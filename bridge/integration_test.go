// Quantaureum Node source, version 1.0.0.
//go:build integration

package bridge

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func setupTestBridge(t *testing.T) (*QuantumBridge, *crypto.KeyPair) {
	t.Helper()

	userKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	adapterPub, adapterPriv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("mode3.GenerateKey: %v", err)
	}

	cfg := DefaultBridgeConfig()
	cfg.NodeURLs = map[ChainID]string{
		"quantaureum": "http://localhost:8545",
		"ethereum":    "http://localhost:8546",
	}
	cfg.BridgeContractAddresses = map[ChainID]string{
		"quantaureum": "0xBridgeQau",
		"ethereum":    "0xBridgeEth",
	}
	cfg.ConfirmationsRequired = 0
	cfg.InitializerAddress = "0xInitializer"

	bridge := NewQuantumBridge(cfg).(*QuantumBridge)

	ctx := context.Background()
	if err := bridge.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	qauAdapter := bridge.adapters["quantaureum"].(*QuantaureumChainAdapter)
	if err := qauAdapter.SetGovernanceAddress("0xGovQau", "0xInitializer"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}
	// BRIDGE-P0-01 FIX (R31, 2026-07-27): SetValidatorKeys now requires
	// caller authentication — pass the governance address as caller.
	if err := qauAdapter.SetValidatorKeys(adapterPub, adapterPriv, testProposalID, "0xGovQau"); err != nil {
		t.Fatalf("SetValidatorKeys: %v", err)
	}

	ethAdapter := bridge.adapters["ethereum"].(*ExternalChainAdapter)
	if err := ethAdapter.SetGovernanceAddress("0xGovEth", "0xInitializer"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}
	// BRIDGE-P0-01 FIX (R31, 2026-07-27): SetRelayerKeys now requires
	// caller authentication — pass the governance address as caller.
	if err := ethAdapter.SetRelayerKeys(adapterPub, adapterPriv, testProposalID, "0xGovEth"); err != nil {
		t.Fatalf("SetRelayerKeys: %v", err)
	}

	// P0-1 BRDG-01 FIX: Inject the user's key as a trusted validator key so
	// that verifyQuantumSignature accepts messages signed by signBridgeMessage.
	// Without this, SubmitMessage fails with "no trusted validator keys configured".
	bridge.SetTrustedValidatorKeys([][]byte{userKeyPair.Public.Bytes()})

	return bridge, userKeyPair
}

func signBridgeMessage(t *testing.T, keyPair *crypto.KeyPair, msg *BridgeMessage) {
	t.Helper()

	msg.SourceAddress = keyPair.Public.Address().ToHexAddress()
	msgHash := computeMessageHash(msg)
	signature, err := keyPair.Private.Sign(msgHash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	msg.QuantumSignature = signature
	msg.QuantumPublicKey = keyPair.Public.Bytes()
}

func createTestMessage(id string, nonce uint64, sourceChain, targetChain ChainID) *BridgeMessage {
	return &BridgeMessage{
		ID:            id,
		SourceChain:   sourceChain,
		TargetChain:   targetChain,
		TargetAddress: "0xRecipient123",
		AssetType:     AssetTypeNative,
		AssetID:       "QAU",
		Amount:        "1000000000000000000",
		MessageType:   MessageTypeAssetTransfer,
		Nonce:         nonce,
		Timestamp:     time.Now().Unix(),
		BlockNumber:   100,
		Status:        MessageStatusPending,
	}
}

// setMerkleProofBatch builds shared Merkle trees per source chain, sets the
// committed root on BOTH the source and target adapters, and generates
// individual proofs for each message.
//
// P2-2 FIX (2026-07-14): The CRIT-01 security fix made Merkle proofs mandatory
// for ProcessMessage → VerifyMessage. Three subtleties must be handled:
//   - bridge.VerifyMessage calls q.adapters[msg.SourceChain].VerifyMessage,
//     so the committed root must be set on the SOURCE adapter.
//   - adapter.ExecuteMessage (called by ProcessMessage after verification)
//     calls VerifyMessage AGAIN on the TARGET adapter, so the committed root
//     must ALSO be set on the TARGET adapter.
//   - For multiple messages from the same source chain, a SHARED Merkle tree
//     is needed because each SetCommittedRoot call overwrites the previous
//     root. Individual proofs are generated from the shared tree.
//
// NOTE: When messages have different (source, target) pairs that map to the
// same adapter, the last SetCommittedRoot wins. Callers must process messages
// one at a time (calling setMerkleProofBatch before each ProcessMessage) in
// that case.
func setMerkleProofBatch(t *testing.T, bridge *QuantumBridge, msgs ...*BridgeMessage) {
	t.Helper()
	if len(msgs) == 0 {
		return
	}

	// Group messages by source chain — each source adapter gets one root.
	bySource := make(map[ChainID][]*BridgeMessage)
	for _, msg := range msgs {
		bySource[msg.SourceChain] = append(bySource[msg.SourceChain], msg)
	}

	for sourceChain, groupMsgs := range bySource {
		// BRDG-R5-05 (2026-07-16): Build the shared Merkle tree from the full
		// *BridgeMessage list (NewMerkleTreeFromMessages) so leaves bind the
		// payload, not just the ID. The legacy NewMerkleTree(msgIDs) path
		// produces leaves that verifyMessageInclusion now rejects by design.
		tree, err := NewMerkleTreeFromMessages(groupMsgs)
		if err != nil {
			t.Fatalf("NewMerkleTreeFromMessages: %v", err)
		}
		root := tree.Root()

		// Collect the set of adapters that need this root: the SOURCE adapter
		// (for bridge.VerifyMessage) plus each message's TARGET adapter (for
		// ExecuteMessage → VerifyMessage).
		adaptersToSet := make(map[ChainID]bool)
		adaptersToSet[sourceChain] = true
		for _, msg := range groupMsgs {
			adaptersToSet[msg.TargetChain] = true
		}

		for chainID := range adaptersToSet {
			adapter, ok := bridge.adapters[chainID]
			if !ok {
				t.Fatalf("adapter not found: %s", chainID)
			}
			switch a := adapter.(type) {
			case *QuantaureumChainAdapter:
				if err := a.SetCommittedRoot(root, a.GetGovernanceAddress()); err != nil {
					t.Fatalf("SetCommittedRoot (quantaureum): %v", err)
				}
			case *ExternalChainAdapter:
				if err := a.SetCommittedRoot(root, a.GetGovernanceAddress()); err != nil {
					t.Fatalf("SetCommittedRoot (ethereum): %v", err)
				}
			default:
				t.Fatalf("unknown adapter type: %T", a)
			}
		}

		// Generate individual proofs from the shared tree.
		// BRDG-R5-05 (2026-07-16): leaves are payload-bound
		// (hashLeafMessage(msg)), so proofs must be generated against the
		// same hash — not hashLeaf([]byte(msg.ID)).
		for _, msg := range groupMsgs {
			leafHash := hashLeafMessage(msg)
			proof, err := tree.GenerateProof(leafHash)
			if err != nil {
				t.Fatalf("GenerateProof for %s: %v", msg.ID, err)
			}
			msg.Proof = EncodeMerkleProof(proof)
		}
	}
}

func TestBridgeIntegration_Lifecycle(t *testing.T) {
	bridge, _ := setupTestBridge(t)
	ctx := context.Background()

	if err := bridge.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if err := bridge.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestBridgeIntegration_RejectsForgedKey verifies that a message signed with
// a key NOT in the trusted validator key set is rejected at SubmitMessage time.
//
// P0-1 BRDG-01 FIX (2026-07-13): Before the fix, verifyQuantumSignature
// accepted any self-signed key pair (only checking derived address == source
// address), allowing anyone to forge cross-chain messages. Now the message's
// QuantumPublicKey must match a configured trusted key via ConstantTimeCompare.
func TestBridgeIntegration_RejectsForgedKey(t *testing.T) {
	bridge, _ := setupTestBridge(t)
	ctx := context.Background()

	// Generate a forged key pair that is NOT in the trusted set.
	forgedKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (forged): %v", err)
	}

	msg := createTestMessage("forged-msg-1", 999, "quantaureum", "ethereum")
	signBridgeMessage(t, forgedKeyPair, msg)

	// SubmitMessage must reject the forged key.
	err = bridge.SubmitMessage(ctx, msg)
	if err == nil {
		t.Fatal("expected SubmitMessage to reject forged key, but it succeeded")
	}
	// Verify the error mentions trusted validator key mismatch.
	if !strings.Contains(err.Error(), "trusted validator key") {
		t.Fatalf("expected error about trusted validator key, got: %v", err)
	}
	t.Log("✅ Forged key correctly rejected at SubmitMessage")
}

// TestBridgeIntegration_RejectsWhenNoTrustedKeysConfigured verifies the
// fail-closed behavior: when no trusted validator keys are configured, all
// messages are rejected.
func TestBridgeIntegration_RejectsWhenNoTrustedKeysConfigured(t *testing.T) {
	bridge, keyPair := setupTestBridge(t)
	ctx := context.Background()

	// Clear trusted keys to simulate unconfigured state.
	bridge.SetTrustedValidatorKeys(nil)

	msg := createTestMessage("no-trusted-keys-msg-1", 998, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msg)

	err := bridge.SubmitMessage(ctx, msg)
	if err == nil {
		t.Fatal("expected SubmitMessage to fail when no trusted keys configured, but it succeeded")
	}
	if !strings.Contains(err.Error(), "no trusted validator keys configured") {
		t.Fatalf("expected error about no trusted keys, got: %v", err)
	}
	t.Log("✅ Fail-closed correctly rejects all messages when no trusted keys configured")
}

func TestBridgeIntegration_MessageFullLifecycle(t *testing.T) {
	bridge, keyPair := setupTestBridge(t)
	ctx := context.Background()

	msg := createTestMessage("lifecycle-msg-1", 1, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msg)

	if err := bridge.SubmitMessage(ctx, msg); err != nil {
		t.Fatalf("SubmitMessage: %v", err)
	}

	if msg.Status != MessageStatusPending {
		t.Fatalf("expected PENDING after submit, got %s", msg.Status)
	}

	retrieved, err := bridge.GetMessage(ctx, msg.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if retrieved.ID != msg.ID {
		t.Errorf("retrieved ID mismatch: %s != %s", retrieved.ID, msg.ID)
	}
	if retrieved.Status != MessageStatusPending {
		t.Errorf("retrieved status mismatch: %s != PENDING", retrieved.Status)
	}

	pendingMsgs, err := bridge.GetMessagesByStatus(ctx, MessageStatusPending)
	if err != nil {
		t.Fatalf("GetMessagesByStatus PENDING: %v", err)
	}
	if len(pendingMsgs) != 1 {
		t.Fatalf("expected 1 pending message, got %d", len(pendingMsgs))
	}

	qauMsgs, err := bridge.GetMessagesByChain(ctx, "quantaureum", true)
	if err != nil {
		t.Fatalf("GetMessagesByChain source: %v", err)
	}
	if len(qauMsgs) != 1 {
		t.Fatalf("expected 1 message from quantaureum, got %d", len(qauMsgs))
	}

	ethMsgs, err := bridge.GetMessagesByChain(ctx, "ethereum", false)
	if err != nil {
		t.Fatalf("GetMessagesByChain target: %v", err)
	}
	if len(ethMsgs) != 1 {
		t.Fatalf("expected 1 message to ethereum, got %d", len(ethMsgs))
	}

	// P2-2 FIX: Set Merkle proof before ProcessMessage (CRIT-01 requires it).
	setMerkleProofBatch(t, bridge, msg)

	if err := bridge.ProcessMessage(ctx, msg); err != nil {
		t.Fatalf("ProcessMessage: %v", err)
	}

	if msg.Status != MessageStatusExecuted {
		t.Fatalf("expected EXECUTED after process, got %s", msg.Status)
	}

	executedMsgs, err := bridge.GetMessagesByStatus(ctx, MessageStatusExecuted)
	if err != nil {
		t.Fatalf("GetMessagesByStatus EXECUTED: %v", err)
	}
	if len(executedMsgs) != 1 {
		t.Fatalf("expected 1 executed message, got %d", len(executedMsgs))
	}

	pendingMsgs2, _ := bridge.GetMessagesByStatus(ctx, MessageStatusPending)
	if len(pendingMsgs2) != 0 {
		t.Errorf("expected 0 pending messages after process, got %d", len(pendingMsgs2))
	}
}

func TestBridgeIntegration_NonceReplayProtection(t *testing.T) {
	bridge, keyPair := setupTestBridge(t)
	ctx := context.Background()

	msg1 := createTestMessage("nonce-msg-1", 42, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msg1)

	if err := bridge.SubmitMessage(ctx, msg1); err != nil {
		t.Fatalf("SubmitMessage first: %v", err)
	}

	msg2 := createTestMessage("nonce-msg-2", 42, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msg2)

	err := bridge.SubmitMessage(ctx, msg2)
	if err == nil {
		t.Fatal("expected error for replayed nonce")
	}
}

func TestBridgeIntegration_MessageIDDuplication(t *testing.T) {
	bridge, keyPair := setupTestBridge(t)
	ctx := context.Background()

	msg1 := createTestMessage("dup-id-msg", 1, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msg1)

	if err := bridge.SubmitMessage(ctx, msg1); err != nil {
		t.Fatalf("SubmitMessage first: %v", err)
	}

	msg2 := createTestMessage("dup-id-msg", 2, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msg2)

	err := bridge.SubmitMessage(ctx, msg2)
	if err == nil {
		t.Fatal("expected error for duplicate message ID")
	}
}

func TestBridgeIntegration_FinalizedMessageReplay(t *testing.T) {
	bridge, keyPair := setupTestBridge(t)
	ctx := context.Background()

	msg := createTestMessage("finalized-msg-1", 1, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msg)

	if err := bridge.SubmitMessage(ctx, msg); err != nil {
		t.Fatalf("SubmitMessage: %v", err)
	}

	// P2-2 FIX: Set Merkle proof before ProcessMessage (CRIT-01 requires it).
	setMerkleProofBatch(t, bridge, msg)

	if err := bridge.ProcessMessage(ctx, msg); err != nil {
		t.Fatalf("ProcessMessage: %v", err)
	}

	if msg.Status != MessageStatusExecuted {
		t.Fatalf("expected EXECUTED, got %s", msg.Status)
	}

	replayMsg := createTestMessage("finalized-msg-1", 100, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, replayMsg)

	err := bridge.SubmitMessage(ctx, replayMsg)
	if err == nil {
		t.Fatal("expected error for replaying finalized message ID")
	}
}

func TestBridgeIntegration_MessageExpiration(t *testing.T) {
	bridge, keyPair := setupTestBridge(t)
	ctx := context.Background()

	msg := createTestMessage("expired-msg-1", 1, "quantaureum", "ethereum")
	// P2-2 FIX: Set Expiration BEFORE signing — computeMessageHash includes
	// Expiration, so changing it after signing invalidates the signature.
	msg.Expiration = time.Now().Unix() - 1
	signBridgeMessage(t, keyPair, msg)

	if err := bridge.SubmitMessage(ctx, msg); err != nil {
		t.Fatalf("SubmitMessage: %v", err)
	}

	err := bridge.ProcessMessage(ctx, msg)
	if err == nil {
		t.Fatal("expected error for expired message")
	}

	if msg.Status != MessageStatusExpired {
		t.Errorf("expected EXPIRED, got %s", msg.Status)
	}
}

func TestBridgeIntegration_AssetLockLifecycle(t *testing.T) {
	bridge, _ := setupTestBridge(t)
	ctx := context.Background()

	alm := NewAssetLockManager(bridge, types.Address{})

	owner := types.Address{1, 2, 3}
	recipient := types.Address{4, 5, 6}
	tokenAddr := types.Address{10}

	lockID := GenerateLockID("quantaureum", owner, 0)

	lock := &AssetLock{
		ID:           lockID,
		SourceChain:  "quantaureum",
		TargetChain:  "ethereum",
		AssetType:    AssetTypeQAU,
		TokenAddress: tokenAddr,
		Amount:       big.NewInt(1000000000000000000),
		Owner:        owner,
		Recipient:    recipient,
	}

	// R41-BRIDGE-03: LockAsset now requires a verifiable OwnerAuth. Mint a
	// fresh Dilithium3 keypair whose address is derived via
	// canonicalLockMessage. Recipient / TokenAddress / Amount / SourceChain
	// / TargetChain / AssetType are already set above; signLockForOwnerAuth
	// will reset lock.Owner to the freshly-generated key's derived address
	// and populate lock.OwnerAuth. The lockID stays unchanged (OwnerAuth
	// does not cover lockID) so the GetLock lookup below still works.
	signLockForOwnerAuth(t, lock)

	if err := alm.LockAsset(ctx, lock); err != nil {
		t.Fatalf("LockAsset: %v", err)
	}

	retrievedLock, exists := alm.GetLock(lockID)
	if !exists {
		t.Fatal("lock not found after LockAsset")
	}
	// AUDIT (2026 security review) BRDG-09: LockAsset now leaves the lock in Pending
	// status; ConfirmLock must be called with the source-chain block number
	// before the lock is promoted to Locked. Test bridge uses
	// ConfirmationsRequired=0 so any block number is accepted.
	if retrievedLock.Status != LockStatusPending {
		t.Fatalf("expected PENDING after LockAsset, got %d", retrievedLock.Status)
	}

	if err := alm.ConfirmLock(ctx, lockID, 100); err != nil {
		t.Fatalf("ConfirmLock: %v", err)
	}

	retrievedLock, _ = alm.GetLock(lockID)
	if retrievedLock.Status != LockStatusLocked {
		t.Fatalf("expected LOCKED after ConfirmLock, got %d", retrievedLock.Status)
	}

	if err := alm.MintAsset(ctx, lockID); err != nil {
		t.Fatalf("MintAsset: %v", err)
	}

	retrievedLock, _ = alm.GetLock(lockID)
	if retrievedLock.Status != LockStatusMinted {
		t.Fatalf("expected MINTED, got %d", retrievedLock.Status)
	}

	if err := alm.BurnAsset(ctx, lockID); err != nil {
		t.Fatalf("BurnAsset: %v", err)
	}

	retrievedLock, _ = alm.GetLock(lockID)
	if retrievedLock.Status != LockStatusBurned {
		t.Fatalf("expected BURNED, got %d", retrievedLock.Status)
	}

	if err := alm.UnlockAsset(ctx, lockID, 100); err != nil {
		t.Fatalf("UnlockAsset: %v", err)
	}

	retrievedLock, _ = alm.GetLock(lockID)
	if retrievedLock.Status != LockStatusUnlocked {
		t.Fatalf("expected UNLOCKED, got %d", retrievedLock.Status)
	}

	ownerLocks := alm.GetLocksByOwner(owner)
	if len(ownerLocks) != 1 {
		t.Fatalf("expected 1 lock for owner, got %d", len(ownerLocks))
	}
}

func TestBridgeIntegration_MultiChainRouting(t *testing.T) {
	bridge, keyPair := setupTestBridge(t)
	ctx := context.Background()

	msgQauToEth := createTestMessage("qau-eth-msg-1", 1, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msgQauToEth)

	if err := bridge.SubmitMessage(ctx, msgQauToEth); err != nil {
		t.Fatalf("SubmitMessage QAU->ETH: %v", err)
	}

	msgEthToQau := createTestMessage("eth-qau-msg-1", 2, "ethereum", "quantaureum")
	signBridgeMessage(t, keyPair, msgEthToQau)

	if err := bridge.SubmitMessage(ctx, msgEthToQau); err != nil {
		t.Fatalf("SubmitMessage ETH->QAU: %v", err)
	}

	qauSourceMsgs, err := bridge.GetMessagesByChain(ctx, "quantaureum", true)
	if err != nil {
		t.Fatalf("GetMessagesByChain quantaureum source: %v", err)
	}
	if len(qauSourceMsgs) != 1 {
		t.Fatalf("expected 1 message from quantaureum, got %d", len(qauSourceMsgs))
	}

	ethSourceMsgs, err := bridge.GetMessagesByChain(ctx, "ethereum", true)
	if err != nil {
		t.Fatalf("GetMessagesByChain ethereum source: %v", err)
	}
	if len(ethSourceMsgs) != 1 {
		t.Fatalf("expected 1 message from ethereum, got %d", len(ethSourceMsgs))
	}

	// P2-2 FIX: Set Merkle proof before each ProcessMessage (CRIT-01 requires it).
	// The two messages have different (source, target) pairs that share the same
	// two adapters, so they must be set + processed one at a time — otherwise
	// the second setMerkleProofBatch would overwrite the root that the first
	// message still needs during ExecuteMessage.
	setMerkleProofBatch(t, bridge, msgQauToEth)
	if err := bridge.ProcessMessage(ctx, msgQauToEth); err != nil {
		t.Fatalf("ProcessMessage QAU->ETH: %v", err)
	}
	if msgQauToEth.Status != MessageStatusExecuted {
		t.Fatalf("expected EXECUTED for QAU->ETH, got %s", msgQauToEth.Status)
	}

	setMerkleProofBatch(t, bridge, msgEthToQau)
	if err := bridge.ProcessMessage(ctx, msgEthToQau); err != nil {
		t.Fatalf("ProcessMessage ETH->QAU: %v", err)
	}
	if msgEthToQau.Status != MessageStatusExecuted {
		t.Fatalf("expected EXECUTED for ETH->QAU, got %s", msgEthToQau.Status)
	}
}

func TestBridgeIntegration_ValidatorQuorum(t *testing.T) {
	bridge, _ := setupTestBridge(t)
	relayerCfg := DefaultRelayerConfig()
	relayer := NewMessageRelayer(relayerCfg, bridge)

	// P0-2 FIX (2026-07-13): NewValidatorNetwork panics when verifier is nil
	// (NewSignatureAggregator panics on nil verifier + non-nil validatorSet).
	// Use mockVerifier to allow all signatures in this unit-level test.
	vn := mustNewValidatorNetwork(t, 2, relayer, &mockVerifier{allowAll: true}, "governance")

	v1 := &BridgeValidator{Address: types.Address{1}, Stake: big.NewInt(1000), Active: true, PublicKey: []byte{1}}
	v2 := &BridgeValidator{Address: types.Address{2}, Stake: big.NewInt(2000), Active: true, PublicKey: []byte{2}}
	v3 := &BridgeValidator{Address: types.Address{3}, Stake: big.NewInt(3000), Active: true, PublicKey: []byte{3}}

	if err := vn.AddValidator("governance", v1); err != nil {
		t.Fatalf("AddValidator v1: %v", err)
	}
	if err := vn.AddValidator("governance", v2); err != nil {
		t.Fatalf("AddValidator v2: %v", err)
	}
	if err := vn.AddValidator("governance", v3); err != nil {
		t.Fatalf("AddValidator v3: %v", err)
	}

	activeValidators := vn.GetValidatorSet().GetActiveValidators()
	if len(activeValidators) != 3 {
		t.Fatalf("expected 3 active validators, got %d", len(activeValidators))
	}

	sa := vn.GetSignatureAggregator()
	if sa.HasQuorum("msg-1") {
		t.Fatal("should not have quorum with 0 signatures")
	}

	if err := vn.SignMessage("msg-1", []byte("hash1"), types.Address{1}, []byte("sig1")); err != nil {
		t.Fatalf("SignMessage v1: %v", err)
	}

	if err := vn.SignMessage("msg-1", []byte("hash1"), types.Address{2}, []byte("sig2")); err != nil {
		t.Fatalf("SignMessage v2: %v", err)
	}

	if sa.GetSignatureCount("msg-1") != 0 {
		t.Log("signatures were cleared after reaching quorum (expected behavior)")
	}

	totalStake := vn.GetValidatorSet().GetTotalStake()
	expectedStake := big.NewInt(6000)
	if totalStake.Cmp(expectedStake) != 0 {
		t.Fatalf("expected total stake %d, got %d", expectedStake, totalStake)
	}

	validators := vn.GetValidatorSet().GetActiveValidators()
	for _, v := range validators {
		if v.Address.Equal(types.Address{1}) || v.Address.Equal(types.Address{2}) {
			if v.SignedCount != 1 {
				t.Errorf("validator %s: expected SignedCount=1, got %d", v.Address.ToHexAddress(), v.SignedCount)
			}
		}
	}
}

// mockVerifySuccessAdapter wraps a ChainAdapter and always returns (true, nil)
// for VerifyMessage. Used in quorum-rejection tests to bypass adapter-level
// signature verification and reach the quorum check in ProcessMessage.
type mockVerifySuccessAdapter struct {
	ChainAdapter
}

func (m *mockVerifySuccessAdapter) VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}

// TestBridgeIntegration_ProcessMessageRejectsWithoutQuorum verifies DoD ③:
// when a ValidatorNetwork is configured, ProcessMessage rejects messages
// that have not reached M-of-N quorum.
//
// P0-2 BRDG-03 FIX (2026-07-13): Without this check, a single relayer could
// execute arbitrary cross-chain messages without validator approval.
func TestBridgeIntegration_ProcessMessageRejectsWithoutQuorum(t *testing.T) {
	b, keyPair := setupTestBridge(t)
	ctx := context.Background()

	// Create a ValidatorNetwork with threshold=2 (requires 2 signatures).
	// Use mockVerifier{allowAll: true} so SignMessage works with dummy sigs.
	vn := mustNewValidatorNetwork(t, 2, nil, &mockVerifier{allowAll: true}, "")
	b.SetValidatorNetwork(vn)

	// Replace the source adapter with a mock that always passes VerifyMessage.
	// This is necessary because the adapter's VerifyMessage checks the message
	// signature against the adapter's trusted key (adapterPub), but the message
	// is signed with userKeyPair. Without the mock, ProcessMessage would fail
	// at VerifyMessage before reaching the quorum check.
	realAdapter := b.adapters["quantaureum"]
	b.adapters["quantaureum"] = &mockVerifySuccessAdapter{ChainAdapter: realAdapter}

	// Submit a message (passes bridge-level verifyQuantumSignature because
	// setupTestBridge injected userKeyPair.Public as a trusted key).
	msg := createTestMessage("no-quorum-msg-1", 777, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msg)

	if err := b.SubmitMessage(ctx, msg); err != nil {
		t.Fatalf("SubmitMessage: %v", err)
	}

	// ProcessMessage must reject the message because no validator has signed it
	// (quorum not reached: 0 signatures < threshold 2).
	err := b.ProcessMessage(ctx, msg)
	if err == nil {
		t.Fatal("expected ProcessMessage to reject message without quorum, but it succeeded")
	}
	if !strings.Contains(err.Error(), "insufficient validator signatures") {
		t.Fatalf("expected error about insufficient validator signatures, got: %v", err)
	}
	t.Log("✅ ProcessMessage correctly rejects message without quorum")
}

// TestBridgeIntegration_R4BRDG04_QuorumBypassRegression verifies audit finding
// R4-BRDG-04: when ProcessMessage rejects a message for insufficient quorum,
// the message MUST remain in PENDING status (not transition to VERIFIED).
//
// Before the fix, the PENDING → VERIFIED transition happened BEFORE the quorum
// check. A failed-quorum message was therefore in VERIFIED status, and the
// processMessagesLoop retry path then called ExecuteMessage directly —
// bypassing quorum entirely. This is a regression test for that bypass.
//
// AUDIT R4-BRDG-04 (2026-07-15)
func TestBridgeIntegration_R4BRDG04_QuorumBypassRegression(t *testing.T) {
	b, keyPair := setupTestBridge(t)
	ctx := context.Background()

	vn := mustNewValidatorNetwork(t, 2, nil, &mockVerifier{allowAll: true}, "")
	b.SetValidatorNetwork(vn)

	realAdapter := b.adapters["quantaureum"]
	b.adapters["quantaureum"] = &mockVerifySuccessAdapter{ChainAdapter: realAdapter}

	msg := createTestMessage("r4-brdg04-msg-1", 999, "quantaureum", "ethereum")
	signBridgeMessage(t, keyPair, msg)

	if err := b.SubmitMessage(ctx, msg); err != nil {
		t.Fatalf("SubmitMessage: %v", err)
	}

	// ProcessMessage must fail (no validator signatures).
	err := b.ProcessMessage(ctx, msg)
	if err == nil {
		t.Fatal("expected ProcessMessage to reject message without quorum")
	}

	// R4-BRDG-04 regression check: message MUST stay PENDING (not VERIFIED).
	// Before the fix, it would be VERIFIED — enabling the retry-loop bypass.
	if msg.Status != MessageStatusPending {
		t.Errorf("R4-BRDG-04 regression: message status = %s, want PENDING (quorum check must run BEFORE VERIFIED transition)",
			msg.Status)
	}

	// Internal message state must also reflect PENDING.
	if internalMsg, ok := b.messages[msg.ID]; ok && internalMsg.Status != MessageStatusPending {
		t.Errorf("R4-BRDG-04 regression: internal message status = %s, want PENDING",
			internalMsg.Status)
	}

	t.Log("✅ R4-BRDG-04: message stays PENDING when quorum fails (no VERIFIED bypass)")
}

func TestBridgeIntegration_ConcurrentProcessing(t *testing.T) {
	bridge, keyPair := setupTestBridge(t)
	ctx := context.Background()

	const numMessages = 5
	msgs := make([]*BridgeMessage, numMessages)

	for i := 0; i < numMessages; i++ {
		msgs[i] = createTestMessage(
			fmt.Sprintf("concurrent-msg-%d", i),
			uint64(i+1),
			"quantaureum",
			"ethereum",
		)
		signBridgeMessage(t, keyPair, msgs[i])

		if err := bridge.SubmitMessage(ctx, msgs[i]); err != nil {
			t.Fatalf("SubmitMessage %d: %v", i, err)
		}
	}
	// P2-2 FIX: Set Merkle proofs after all messages are submitted. All share
	// the same source chain ("quantaureum"), so a single shared Merkle tree
	// is built and one root is committed to the quantaureum adapter.
	setMerkleProofBatch(t, bridge, msgs...)

	var wg sync.WaitGroup
	errCh := make(chan error, numMessages)

	for i := 0; i < numMessages; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := bridge.ProcessMessage(ctx, msgs[idx]); err != nil {
				errCh <- fmt.Errorf("ProcessMessage %d: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent processing error: %v", err)
	}

	for i, msg := range msgs {
		if msg.Status != MessageStatusExecuted {
			t.Errorf("message %d: expected EXECUTED, got %s", i, msg.Status)
		}
	}

	executedMsgs, err := bridge.GetMessagesByStatus(ctx, MessageStatusExecuted)
	if err != nil {
		t.Fatalf("GetMessagesByStatus EXECUTED: %v", err)
	}
	if len(executedMsgs) != numMessages {
		t.Fatalf("expected %d executed messages, got %d", numMessages, len(executedMsgs))
	}
}
