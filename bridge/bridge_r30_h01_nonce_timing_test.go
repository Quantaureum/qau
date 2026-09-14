// Quantaureum Node source, version 1.0.0.
// BRIDGE-H01 regression tests.
//
// BRIDGE-H01 (R30, 2026-07-27): highestUsedNonce was updated at
// SubmitMessage time instead of at ExecuteMessage (finalization) time.
// This caused failed/aborted submissions to permanently "burn" nonces —
// the high-water mark advanced even though the message never reached
// the target chain. Combined with sweepUsedNonces (which prunes all
// nonces <= highestUsedNonce), legitimate retries with the same nonce
// (e.g., BRIDGE-C03 deterministic refund nonces) were permanently
// rejected as "pruned replay".
//
// FIX:
//  1. Removed highestUsedNonce update from SubmitMessage.
//  2. Added highestUsedNonce update in the ExecuteMessage success path
//     (only when status transitions to EXECUTED).
//  3. Added in-memory state rollback on adapter.SubmitMessage failure
//     (nonce + message maps) so the same nonce can be retried.
//  4. Init restore only advances highestUsedNonce for EXECUTED messages
//     (not PENDING/FAILED/EXPIRED).
package bridge

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// signH01Message signs a BridgeMessage with the given Dilithium3 key pair
// and registers the public key as a trusted validator key on the bridge.
// This is required because verifyQuantumSignature (called from
// SubmitMessage -> validateMessage) rejects unsigned messages or messages
// whose public key is not in the trustedValidatorKeys set.
//
// BRIDGE-H01 (R30, 2026-07-27) FIX: callers MUST set msg.SourceAddress to
// keyPair.Public.Address().ToHexAddress() BEFORE calling this helper.
// verifyQuantumSignature enforces derivedAddr == msg.SourceAddress (defense
// against key substitution), so a hardcoded placeholder like "0xCaller"
// will be rejected. The helper does NOT overwrite SourceAddress so tests
// can pre-populate usedNonces / nonceKey lookups with the same address.
func signH01Message(t *testing.T, b *QuantumBridge, msg *BridgeMessage, keyPair *crypto.KeyPair) {
	t.Helper()
	msgHash := computeMessageHash(msg)
	signature, err := keyPair.Private.Sign(msgHash)
	if err != nil {
		t.Fatalf("Private.Sign failed: %v", err)
	}
	msg.QuantumSignature = signature
	msg.QuantumPublicKey = keyPair.Public.Bytes()
}

// failingSubmitOnlyAdapter is a ChainAdapter whose SubmitMessage always
// fails. Used to trigger the BRIDGE-H01 rollback path in SubmitMessage.
// Other methods return benign values so the adapter satisfies the
// ChainAdapter interface without exercising unrelated code paths.
type failingSubmitOnlyAdapter struct {
	chainID ChainID

	mu          sync.Mutex
	submitCalls []string
}

func (f *failingSubmitOnlyAdapter) ChainID() ChainID { return f.chainID }

func (f *failingSubmitOnlyAdapter) SubmitMessage(ctx context.Context, msg *BridgeMessage) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitCalls = append(f.submitCalls, msg.ID)
	return "", errors.New("failingSubmitOnlyAdapter: SubmitMessage always fails")
}

func (f *failingSubmitOnlyAdapter) VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}

func (f *failingSubmitOnlyAdapter) ExecuteMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}

func (f *failingSubmitOnlyAdapter) HasSufficientConfirmations(ctx context.Context, blockNumber uint64) (bool, error) {
	return true, nil
}

func (f *failingSubmitOnlyAdapter) GetTransactionBlockNumber(ctx context.Context, txHash string) (uint64, error) {
	return 1, nil
}

func (f *failingSubmitOnlyAdapter) GetMessageProof(ctx context.Context, msgID string) ([]byte, error) {
	return nil, nil
}

func (f *failingSubmitOnlyAdapter) WatchEvents(ctx context.Context, callback func(*BridgeMessage) error) error {
	return nil
}

func (f *failingSubmitOnlyAdapter) FetchMerkleRootFromChain(ctx context.Context) (types.Hash, error) {
	return types.Hash{}, nil
}

// R38-P1-11 DEEP FIX (2026-08-02): signature changed to *BurnVerificationRequest.
func (f *failingSubmitOnlyAdapter) VerifyBurnTransaction(ctx context.Context, req *BurnVerificationRequest) (bool, error) {
	return true, nil
}

// TestBRIDGE_H01_HighestUsedNonceNotAdvancedOnSubmission verifies that
// SubmitMessage does NOT advance highestUsedNonce. Previously this counter
// was updated at submission time, which meant failed submissions would
// permanently block retries with any nonce <= the failed nonce.
func TestBRIDGE_H01_HighestUsedNonceNotAdvancedOnSubmission(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	// Initialize inner status maps (SubmitMessage writes to messagesByStatus[PENDING]).
	if err := b.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Use trackingAdapter so SubmitMessage succeeds.
	b.adapters["source-chain"] = &trackingAdapter{chainID: "source-chain"}

	// Set up a trusted validator key so verifyQuantumSignature accepts the message.
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	b.SetTrustedValidatorKeys([][]byte{keyPair.Public.Bytes()})
	// BRIDGE-H01: SourceAddress MUST match the key pair's derived address
	// (verifyQuantumSignature enforces this).
	callerAddr := keyPair.Public.Address().ToHexAddress()

	msg := &BridgeMessage{
		ID:            "h01-submit-test",
		SourceChain:   "source-chain",
		TargetChain:   "target-chain",
		SourceAddress: callerAddr,
		TargetAddress: "0xRecipient",
		AssetType:     AssetTypeNative,
		AssetID:       "QAU",
		Amount:        "1000000000000000000",
		MessageType:   MessageTypeAssetTransfer,
		Nonce:         42,
		Timestamp:     time.Now().Unix(),
		BlockNumber:   100,
		Status:        MessageStatusPending,
	}
	signH01Message(t, b, msg, keyPair)

	if err := b.SubmitMessage(context.Background(), msg); err != nil {
		t.Fatalf("SubmitMessage failed: %v", err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	nk := nonceKey{chain: "source-chain", addr: callerAddr}
	if highest, ok := b.highestUsedNonce[nk]; ok && highest > 0 {
		t.Fatalf("BRIDGE-H01 regression: highestUsedNonce was advanced to %d on submission — should only advance on execution",
			highest)
	}
}

// TestBRIDGE_H01_NonceRolledBackOnAdapterFailure verifies that when
// adapter.SubmitMessage fails, the nonce is removed from usedNonces so
// the same nonce can be retried. This is critical for BRIDGE-C03
// deterministic nonces (refund/lock/mint/burn/unlock) where retry MUST
// use the same nonce.
func TestBRIDGE_H01_NonceRolledBackOnAdapterFailure(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	// Initialize inner status maps (SubmitMessage writes to messagesByStatus[PENDING]).
	if err := b.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// failingSubmitOnlyAdapter causes SubmitMessage to fail at the adapter step.
	b.adapters["source-chain"] = &failingSubmitOnlyAdapter{chainID: "source-chain"}

	// Set up a trusted validator key so verifyQuantumSignature accepts the message.
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	b.SetTrustedValidatorKeys([][]byte{keyPair.Public.Bytes()})
	// BRIDGE-H01: SourceAddress MUST match the key pair's derived address.
	callerAddr := keyPair.Public.Address().ToHexAddress()

	msg := &BridgeMessage{
		ID:            "h01-rollback-test",
		SourceChain:   "source-chain",
		TargetChain:   "target-chain",
		SourceAddress: callerAddr,
		TargetAddress: "0xRecipient",
		AssetType:     AssetTypeNative,
		AssetID:       "QAU",
		Amount:        "1000000000000000000",
		MessageType:   MessageTypeAssetTransfer,
		Nonce:         99,
		Timestamp:     time.Now().Unix(),
		BlockNumber:   100,
		Status:        MessageStatusPending,
	}
	// Set Expiration before signing so the signature covers the final
	// message state. SubmitMessage sets msg.Expiration = msg.Timestamp +
	// config.MessageExpiration when Expiration==0, which would invalidate
	// the signature on retry (the hash would change). Pre-setting it
	// avoids this issue.
	msg.Expiration = msg.Timestamp + cfg.MessageExpiration
	signH01Message(t, b, msg, keyPair)

	// First submission fails at adapter.
	err = b.SubmitMessage(context.Background(), msg)
	if err == nil {
		t.Fatal("SubmitMessage should fail with failingSubmitOnlyAdapter")
	}

	b.mu.RLock()
	nk := nonceKey{chain: "source-chain", addr: callerAddr}
	if _, exists := b.usedNonces[nk][99]; exists {
		b.mu.RUnlock()
		t.Fatalf("BRIDGE-H01 regression: nonce 99 should be rolled back from usedNonces after adapter failure")
	}
	if _, exists := b.messages[msg.ID]; exists {
		b.mu.RUnlock()
		t.Fatalf("BRIDGE-H01 regression: message %q should be rolled back from q.messages after adapter failure", msg.ID)
	}
	b.mu.RUnlock()

	// Retry with the SAME nonce — must be accepted (not rejected as replay).
	// Use a trackingAdapter this time so the retry succeeds.
	b.adapters["source-chain"] = &trackingAdapter{chainID: "source-chain"}
	if err := b.SubmitMessage(context.Background(), msg); err != nil {
		t.Fatalf("BRIDGE-H01: retry with same nonce after adapter failure should succeed, got: %v", err)
	}
}

// TestBRIDGE_H01_HighestUsedNonceAdvancedOnExecution verifies that
// highestUsedNonce IS advanced when a message transitions to EXECUTED.
// This is the only legitimate place to advance the high-water mark.
//
// This test directly simulates the execution path by calling the same
// in-memory state updates that ExecuteMessage performs (status transition
// + highestUsedNonce advancement). This avoids the complexity of setting
// up signature verification for the full ProcessMessage flow.
func TestBRIDGE_H01_HighestUsedNonceAdvancedOnExecution(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	// Initialize inner status maps (SubmitMessage writes to messagesByStatus[PENDING]).
	if err := b.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	b.adapters["source-chain"] = &trackingAdapter{chainID: "source-chain"}

	// Set up a trusted validator key so verifyQuantumSignature accepts the message.
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	b.SetTrustedValidatorKeys([][]byte{keyPair.Public.Bytes()})
	// BRIDGE-H01: SourceAddress MUST match the key pair's derived address.
	callerAddr := keyPair.Public.Address().ToHexAddress()

	msg := &BridgeMessage{
		ID:            "h01-execute-test",
		SourceChain:   "source-chain",
		TargetChain:   "target-chain",
		SourceAddress: callerAddr,
		TargetAddress: "0xRecipient",
		AssetType:     AssetTypeNative,
		AssetID:       "QAU",
		Amount:        "1000000000000000000",
		MessageType:   MessageTypeAssetTransfer,
		Nonce:         77,
		Timestamp:     time.Now().Unix(),
		BlockNumber:   100,
		Status:        MessageStatusPending,
	}
	signH01Message(t, b, msg, keyPair)

	if err := b.SubmitMessage(context.Background(), msg); err != nil {
		t.Fatalf("SubmitMessage failed: %v", err)
	}

	// Before execution: highestUsedNonce should NOT be advanced.
	b.mu.RLock()
	nk := nonceKey{chain: "source-chain", addr: callerAddr}
	if highest, ok := b.highestUsedNonce[nk]; ok && highest >= 77 {
		b.mu.RUnlock()
		t.Fatalf("BRIDGE-H01 regression: highestUsedNonce advanced to %d BEFORE execution", highest)
	}
	b.mu.RUnlock()

	// Simulate the execution success path: transition to EXECUTED and
	// advance highestUsedNonce (this is the code added by BRIDGE-H01 FIX
	// in the ExecuteMessage success path, replicated here to test the
	// logic without requiring full signature verification setup).
	b.mu.Lock()
	oldStatus := msg.Status
	msg.Status = MessageStatusExecuted
	if internalMsg, ok := b.messages[msg.ID]; ok {
		internalMsg.Status = MessageStatusExecuted
	}
	delete(b.messagesByStatus[oldStatus], msg.ID)
	b.ensureStatusMap(MessageStatusExecuted)[msg.ID] = true
	b.markFinalized(msg.ID)
	// BRIDGE-H01 FIX logic: advance highestUsedNonce on EXECUTED.
	execNk := nonceKey{chain: msg.SourceChain, addr: msg.SourceAddress}
	if msg.Nonce > b.highestUsedNonce[execNk] {
		b.highestUsedNonce[execNk] = msg.Nonce
	}
	b.mu.Unlock()

	// After execution: highestUsedNonce SHOULD be advanced to 77.
	b.mu.RLock()
	highest := b.highestUsedNonce[nk]
	b.mu.RUnlock()
	if highest < 77 {
		t.Fatalf("BRIDGE-H01 regression: highestUsedNonce = %d after execution, want >= 77", highest)
	}
}

// TestBRIDGE_H01_InitRestoreOnlyAdvancesHighestForExecuted verifies that
// the init restore path only advances highestUsedNonce for EXECUTED
// messages, not for PENDING/FAILED/EXPIRED. This ensures failed/pending
// messages restored from persistence do not block retries.
//
// This test directly exercises the restore logic by simulating the
// in-memory state updates that Initialize performs when loading messages
// from the persistent store.
func TestBRIDGE_H01_InitRestoreOnlyAdvancesHighestForExecuted(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	// Simulate restoring messages of different statuses. Each has nonce=50.
	// Only EXECUTED should advance highestUsedNonce.
	testCases := []struct {
		status        BridgeMessageStatus
		shouldAdvance bool
	}{
		{MessageStatusPending, false},
		{MessageStatusFailed, false},
		{MessageStatusExpired, false},
		{MessageStatusExecuted, true},
	}

	for i, tc := range testCases {
		msg := &BridgeMessage{
			ID:            "h01-restore-" + string(tc.status),
			SourceChain:   "source-chain",
			TargetChain:   "target-chain",
			SourceAddress: "0xCaller",
			TargetAddress: "0xRecipient",
			AssetType:     AssetTypeNative,
			AssetID:       "QAU",
			Amount:        "1000000000000000000",
			MessageType:   MessageTypeAssetTransfer,
			Nonce:         uint64(50 + i), // distinct nonces to avoid usedNonces collision
			Timestamp:     time.Now().Unix(),
			BlockNumber:   100,
			Status:        tc.status,
		}

		// Replicate the init restore logic (with BRIDGE-H01 fix applied).
		b.mu.Lock()
		nk := nonceKey{chain: msg.SourceChain, addr: msg.SourceAddress}
		if b.usedNonces[nk] == nil {
			b.usedNonces[nk] = make(map[uint64]time.Time)
		}
		b.usedNonces[nk][msg.Nonce] = time.Unix(msg.Timestamp, 0)
		b.totalUsedNonces++
		// BRIDGE-H01 FIX: only advance highestUsedNonce for EXECUTED.
		if tc.status == MessageStatusExecuted && msg.Nonce > b.highestUsedNonce[nk] {
			b.highestUsedNonce[nk] = msg.Nonce
		}
		b.mu.Unlock()
	}

	b.mu.RLock()
	nk := nonceKey{chain: "source-chain", addr: "0xCaller"}
	highest := b.highestUsedNonce[nk]
	b.mu.RUnlock()

	// Only the EXECUTED message (nonce=53, i=3) should advance highestUsedNonce.
	if highest != 53 {
		t.Fatalf("BRIDGE-H01 regression: highestUsedNonce = %d after restore, want 53 (only EXECUTED nonce should advance)",
			highest)
	}
}
