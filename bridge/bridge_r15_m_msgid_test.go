// Quantaureum Node source, version 1.0.0.
// Package bridge — BRIDGE-R15-M regression tests for unpredictable message IDs.
//
// AUDIT (2026 security review) BRIDGE-R15-M: Bridge message IDs were previously
// predictable because the client supplied the lock ID via the API, and
// derived message IDs ("<lockID>-mint", "<lockID>-burn", etc.) inherited
// that predictability. The fix generates a cryptographically random
// 16-byte lock ID (128 bits of entropy) when the caller does not provide
// one, making derived message IDs unpredictable.
package bridge

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// signLockForOwnerAuth generates a fresh Dilithium3 keypair, sets lock.Owner
// to the derived address, and signs the canonical lock message so the lock
// passes the R41-BRIDGE-03 OwnerAuth gate. Returns nothing; mutates lock
// in place. Recipient / TokenAddress / Amount / SourceChain / TargetChain
// / AssetType MUST be set on lock before calling.
func signLockForOwnerAuth(t *testing.T, lock *AssetLock) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	lock.Owner = kp.Public.Address()
	msg, err := canonicalLockMessage(lock)
	if err != nil {
		t.Fatalf("canonicalLockMessage: %v", err)
	}
	sig, err := kp.Private.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	lock.OwnerAuth = &OwnerAuth{
		PublicKey: kp.Public.Bytes(),
		Signature: sig,
	}
}

// TestBRIDGE_R15_M_EmptyIDGeneratesRandom verifies that LockAsset generates
// a random lock ID when the caller provides an empty ID. The generated ID
// must be non-empty, start with "lock-", and be different across calls.
func TestBRIDGE_R15_M_EmptyIDGeneratesRandom(t *testing.T) {
	alm := setupAssetLockManagerForR15M(t)

	recipient := types.BytesToAddress([]byte{0x02})
	tokenAddr := types.BytesToAddress([]byte{0x03})

	lock1 := &AssetLock{
		// ID intentionally empty — LockAsset should generate one.
		Recipient:    recipient,
		TokenAddress: tokenAddr,
		Amount:       big.NewInt(100),
		SourceChain:  "source-chain",
		TargetChain:  "target-chain",
		AssetType:    AssetTypeQRC20,
	}
	signLockForOwnerAuth(t, lock1) // R41-BRIDGE-03: owner + signature
	if err := alm.LockAsset(context.Background(), lock1); err != nil {
		t.Fatalf("LockAsset failed: %v", err)
	}
	if lock1.ID == "" {
		t.Fatal("LockAsset should have generated a non-empty ID")
	}
	if !strings.HasPrefix(lock1.ID, "lock-") {
		t.Errorf("expected generated ID to start with 'lock-', got %q", lock1.ID)
	}
	t.Logf("Generated lock ID: %s", lock1.ID)

	// Second call with empty ID should generate a DIFFERENT ID.
	lock2 := &AssetLock{
		Recipient:    recipient,
		TokenAddress: tokenAddr,
		Amount:       big.NewInt(200),
		SourceChain:  "source-chain",
		TargetChain:  "target-chain",
		AssetType:    AssetTypeQRC20,
	}
	signLockForOwnerAuth(t, lock2) // R41-BRIDGE-03: owner + signature
	if err := alm.LockAsset(context.Background(), lock2); err != nil {
		t.Fatalf("LockAsset second call failed: %v", err)
	}
	if lock1.ID == lock2.ID {
		t.Errorf("expected different random IDs, both got %q — random generation may be broken", lock1.ID)
	}
	t.Logf("Second lock ID: %s", lock2.ID)
}

// TestBRIDGE_R15_M_ProvidedIDPreserved verifies that when the caller
// provides an explicit ID, LockAsset preserves it (backward compatibility).
func TestBRIDGE_R15_M_ProvidedIDPreserved(t *testing.T) {
	alm := setupAssetLockManagerForR15M(t)

	recipient := types.BytesToAddress([]byte{0x02})
	tokenAddr := types.BytesToAddress([]byte{0x03})

	lock := &AssetLock{
		ID:           "my-custom-lock-id",
		Recipient:    recipient,
		TokenAddress: tokenAddr,
		Amount:       big.NewInt(100),
		SourceChain:  "source-chain",
		TargetChain:  "target-chain",
		AssetType:    AssetTypeQRC20,
	}
	signLockForOwnerAuth(t, lock) // R41-BRIDGE-03: owner + signature
	if err := alm.LockAsset(context.Background(), lock); err != nil {
		t.Fatalf("LockAsset failed: %v", err)
	}
	if lock.ID != "my-custom-lock-id" {
		t.Errorf("expected custom ID to be preserved, got %q", lock.ID)
	}
}

// setupAssetLockManagerForR15M creates a minimal AssetLockManager for
// BRIDGE-R15-M tests. It uses NewQuantumBridge so the logger and other
// internal fields are properly initialized (avoids nil-pointer panics
// in LockAsset which logs structured fields after submission).
func setupAssetLockManagerForR15M(t *testing.T) *AssetLockManager {
	t.Helper()
	bridge := NewQuantumBridge(nil).(*QuantumBridge)
	bridge.adapters["source-chain"] = &mockAdapterR15M{}
	bridge.adapters["target-chain"] = &mockAdapterR15M{}

	alm := &AssetLockManager{
		bridge:        bridge,
		locks:         make(map[string]*AssetLock),
		locksByOwner:  make(map[types.Address][]string),
		locksByStatus: make(map[LockStatus]map[string]bool),
	}
	return alm
}

// mockAdapterR15M is a minimal ChainAdapter that accepts any message.
// All interface methods are stubbed so the mock satisfies ChainAdapter
// without forcing the test to exercise unrelated functionality.
type mockAdapterR15M struct{}

func (m *mockAdapterR15M) ChainID() ChainID { return "source-chain" }
func (m *mockAdapterR15M) SubmitMessage(ctx context.Context, msg *BridgeMessage) (string, error) {
	return "mock-tx-hash", nil
}
func (m *mockAdapterR15M) VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}
func (m *mockAdapterR15M) ExecuteMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}
func (m *mockAdapterR15M) HasSufficientConfirmations(ctx context.Context, blockNumber uint64) (bool, error) {
	return true, nil
}
func (m *mockAdapterR15M) GetTransactionBlockNumber(ctx context.Context, txHash string) (uint64, error) {
	return 1, nil
}
func (m *mockAdapterR15M) GetMessageProof(ctx context.Context, msgID string) ([]byte, error) {
	return nil, nil
}
func (m *mockAdapterR15M) WatchEvents(ctx context.Context, callback func(*BridgeMessage) error) error {
	return nil
}
func (m *mockAdapterR15M) FetchMerkleRootFromChain(ctx context.Context) (types.Hash, error) {
	return types.Hash{}, nil
}

// R38-P1-11 DEEP FIX (2026-08-02): signature changed to *BurnVerificationRequest.
func (m *mockAdapterR15M) VerifyBurnTransaction(ctx context.Context, req *BurnVerificationRequest) (bool, error) {
	return true, nil
}
