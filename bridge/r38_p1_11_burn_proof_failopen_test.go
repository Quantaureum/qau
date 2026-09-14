// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
//
// R38-P1-11 (2026-08-01) regression tests: RefundFailedLockWithBurnProof
// must fail-closed at every layer of on-chain burn verification.
//
// The vulnerability (audit R38-P1-11): the original implementation of
// RefundFailedLockWithBurnProof in bridge/asset_lock.go wrapped the burn
// verification in `if bridge != nil { adapter, err := bridge.GetAdapter(...);
// if err == nil && adapter != nil { verified, err := adapter.VerifyBurnTransaction(...) } }`.
// This is fail-OPEN: when bridge==nil / adapter==nil / GetAdapter returned an
// error, the entire on-chain verification was SILENTLY SKIPPED, and the refund
// proceeded. A compromised operator (or a misconfigured bridge) could supply a
// FORGED TxHash to release the source-chain refund while the target-chain
// wrapped asset stayed in circulation — a double-spend.
//
// The fix (surgical, fail-closed only): every layer must succeed explicitly.
// bridge==nil → error. GetAdapter err → error. adapter==nil → error.
// VerifyBurnTransaction err → error. verified==false → error. Only when
// verified==true does the refund proceed.
//
// NOTE: This surgical fix addresses the fail-OPEN control-flow bug only.
// Full field-level verification (burn calldata, Burn event, real token,
// beneficiary, amount, finality) requires the ChainAdapter interface
// signature extension + 5 mock adapter updates — a separate follow-up task.
//
// These tests pin the fail-closed behavior:
//  1. bridge==nil → refund rejected (not silently allowed).
//  2. adapter not registered for proof.ChainID → refund rejected.
//  3. registered adapter but VerifyBurnTransaction returns false → rejected.
//  4. registered adapter but VerifyBurnTransaction returns error → rejected.
//  5. (happy path) VerifyBurnTransaction returns true → refund proceeds
//     past the verification gate (may still fail downstream at SubmitMessage
//     without trusted validator keys — that is acceptable and proves the
//     verification gate opened, NOT that the whole refund succeeded).
package bridge

import (
	"context"
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// r38P1_11Adapter is a minimal, fully controlled ChainAdapter stub. Only
// VerifyBurnTransaction is meaningful for these tests; the other methods
// mirror the no-op defaults of mockChainAdapter so the stub satisfies the
// ChainAdapter interface without weakening production adapters.
type r38P1_11Adapter struct {
	chainID ChainID
	// burnVerified controls the (bool) return of VerifyBurnTransaction.
	burnVerified bool
	// burnErr controls the (error) return of VerifyBurnTransaction.
	burnErr error
	// burnCalls counts invocations of VerifyBurnTransaction, so tests can
	// assert that the verification gate was actually reached (vs. silently
	// short-circuited by the old fail-open code path).
	burnCalls int
}

func (m *r38P1_11Adapter) ChainID() ChainID { return m.chainID }

func (m *r38P1_11Adapter) SubmitMessage(ctx context.Context, msg *BridgeMessage) (string, error) {
	return "", nil
}

func (m *r38P1_11Adapter) VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}

func (m *r38P1_11Adapter) ExecuteMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}

func (m *r38P1_11Adapter) HasSufficientConfirmations(ctx context.Context, blockNumber uint64) (bool, error) {
	return true, nil
}

func (m *r38P1_11Adapter) GetTransactionBlockNumber(ctx context.Context, txHash string) (uint64, error) {
	return 0, nil
}

func (m *r38P1_11Adapter) GetMessageProof(ctx context.Context, msgID string) ([]byte, error) {
	return nil, nil
}

func (m *r38P1_11Adapter) WatchEvents(ctx context.Context, callback func(*BridgeMessage) error) error {
	return nil
}

func (m *r38P1_11Adapter) FetchMerkleRootFromChain(ctx context.Context) (types.Hash, error) {
	return types.Hash{}, nil
}

// R38-P1-11 DEEP FIX (2026-08-02): ChainAdapter.VerifyBurnTransaction
// signature changed to accept *BurnVerificationRequest. The surgical
// fail-closed test asserts the call count + verified flag + returned
// error regardless of the request body, so we ignore req fields here.
func (m *r38P1_11Adapter) VerifyBurnTransaction(ctx context.Context, req *BurnVerificationRequest) (bool, error) {
	m.burnCalls++
	return m.burnVerified, m.burnErr
}

// r38P1_11AuditTag is the prefix every R38-P1-11 fail-closed error must
// carry. Tests assert on this prefix to prove the rejection came from the
// surgical fix (not from some unrelated downstream check).
const r38P1_11AuditTag = "R38-P1-11"

// r38P1_11Setup builds an AssetLockManager backed by a QuantumBridge whose
// adapter map contains exactly the supplied adapter for the lock's target
// chain (and a working source-chain adapter for SubmitMessage downstream).
// Returns the adapter so the test can mutate burnVerified/burnErr after
// construction. The lock is a Minted-then-failed lock so the burn-proof gate
// is the layer under test.
func r38P1_11Setup(t *testing.T, targetAdapter *r38P1_11Adapter) (*AssetLockManager, *r38P1_11Adapter) {
	t.Helper()
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	// Source adapter uses trackingAdapter (SubmitMessage is exercised only
	// on the happy path; burn verification gate is what these tests target).
	b.adapters["source-chain"] = &trackingAdapter{chainID: "source-chain"}
	if targetAdapter != nil {
		b.adapters["target-chain"] = targetAdapter
	}
	alm := NewAssetLockManager(b, types.Address{})

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	insertFailedLock(alm, "r38-lock", "source-chain", "target-chain",
		"burn submit failed: simulated (was Minted)")
	return alm, targetAdapter
}

// r38P1_11MakeProof builds the structurally-valid burn proof that matches the
// r38P1_11Setup lock (target-chain, amount 1000). The structural gate must
// pass so the test reaches the on-chain verification layer under test.
func r38P1_11MakeProof() *BurnProof {
	return &BurnProof{
		TxHash:  "0xr38burntx",
		ChainID: "target-chain",
		Amount:  bigNewInt(1000),
	}
}

// TestR38P1_11_RefundFailsClosed_WhenBridgeNotConfigured pins the fail-closed
// behavior when alm.bridge == nil. The old code's `if bridge != nil` guard
// silently skipped verification in this case (fail-open).
func TestR38P1_11_RefundFailsClosed_WhenBridgeNotConfigured(t *testing.T) {
	// Construct an AssetLockManager whose bridge is intentionally nil.
	alm := NewAssetLockManager(nil, types.Address{})
	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})
	insertFailedLock(alm, "r38-nil-bridge", "source-chain", "target-chain",
		"burn submit failed: simulated (was Minted)")

	proof := &BurnProof{
		TxHash:  "0xr38burntx",
		ChainID: "target-chain",
		Amount:  bigNewInt(1000),
	}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "r38-nil-bridge", op, proof)
	if err == nil {
		t.Fatal("R38-P1-11: refund must be REJECTED when bridge is nil (fail-closed), but refund succeeded")
	}
	if !containsStr(err.Error(), r38P1_11AuditTag) {
		t.Fatalf("R38-P1-11: rejection should carry audit tag %q, got: %v", r38P1_11AuditTag, err)
	}
	if !containsStr(err.Error(), "bridge not configured") {
		t.Fatalf("R38-P1-11: error should mention bridge not configured, got: %v", err)
	}

	// Lock must remain Failed — refund did NOT proceed.
	updated, ok := alm.GetLock("r38-nil-bridge")
	if !ok || updated.Status != LockStatusFailed {
		t.Fatalf("lock should remain Failed after fail-closed rejection, ok=%v status=%d", ok, updated.Status)
	}
	if updated.BurnProof != nil {
		t.Fatal("BurnProof must NOT be attached when bridge==nil rejected the refund")
	}
}

// TestR38P1_11_RefundFailsClosed_WhenAdapterNotRegisteredForChain pins the
// fail-closed behavior when GetAdapter returns an error for proof.ChainID
// (no adapter registered for that chain). The old code's
// `if err == nil && adapter != nil` silently skipped verification.
func TestR38P1_11_RefundFailsClosed_WhenAdapterNotRegisteredForChain(t *testing.T) {
	// Bridge exists but has NO adapter for proof.ChainID.
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	b.adapters["source-chain"] = &trackingAdapter{chainID: "source-chain"}
	// NOTE: "target-chain" deliberately NOT registered.
	alm := NewAssetLockManager(b, types.Address{})
	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})
	insertFailedLock(alm, "r38-no-adapter", "source-chain", "target-chain",
		"burn submit failed: simulated (was Minted)")

	proof := r38P1_11MakeProof() // ChainID = "target-chain" (not registered)

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "r38-no-adapter", op, proof)
	if err == nil {
		t.Fatal("R38-P1-11: refund must be REJECTED when adapter not registered for chain (fail-closed)")
	}
	if !containsStr(err.Error(), r38P1_11AuditTag) {
		t.Fatalf("R38-P1-11: rejection should carry audit tag %q, got: %v", r38P1_11AuditTag, err)
	}
	if !containsStr(err.Error(), "no adapter registered") {
		t.Fatalf("R38-P1-11: error should mention no adapter registered, got: %v", err)
	}

	// Lock must remain Failed.
	updated, _ := alm.GetLock("r38-no-adapter")
	if updated.Status != LockStatusFailed {
		t.Fatalf("lock should remain Failed, got %d", updated.Status)
	}
	if updated.BurnProof != nil {
		t.Fatal("BurnProof must NOT be attached when adapter-not-registered rejected the refund")
	}
}

// TestR38P1_11_RefundFailsClosed_WhenVerifyBurnReturnsFalse pins the
// fail-closed behavior when the registered adapter's VerifyBurnTransaction
// returns (false, nil) — i.e., the tx is NOT a valid burn. The old code
// returned an error here too, but only *inside* the `if err == nil &&
// adapter != nil` guard; this test ensures the gate is reached AND the
// rejection now carries the R38-P1-11 audit trail.
func TestR38P1_11_RefundFailsClosed_WhenVerifyBurnReturnsFalse(t *testing.T) {
	adapter := &r38P1_11Adapter{
		chainID:      "target-chain",
		burnVerified: false, // tx is NOT a valid burn
		burnErr:      nil,
	}
	alm, _ := r38P1_11Setup(t, adapter)

	proof := r38P1_11MakeProof()
	op := types.Address{0xAA}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "r38-lock", op, proof)
	if err == nil {
		t.Fatal("R38-P1-11: refund must be REJECTED when VerifyBurnTransaction returns false")
	}
	if !containsStr(err.Error(), r38P1_11AuditTag) {
		t.Fatalf("R38-P1-11: rejection should carry audit tag %q, got: %v", r38P1_11AuditTag, err)
	}
	if !containsStr(err.Error(), "burn verification returned false") {
		t.Fatalf("R38-P1-11: error should mention burn verification returned false, got: %v", err)
	}
	// The verification gate MUST have been reached (proving the gate is
	// active, not silently short-circuited).
	if adapter.burnCalls == 0 {
		t.Fatal("R38-P1-11: VerifyBurnTransaction was never called — the gate was not reached (fail-open regression)")
	}

	// Lock must remain Failed.
	updated, _ := alm.GetLock("r38-lock")
	if updated.Status != LockStatusFailed {
		t.Fatalf("lock should remain Failed, got %d", updated.Status)
	}
	if updated.BurnProof != nil {
		t.Fatal("BurnProof must NOT be attached when verification returned false")
	}
}

// TestR38P1_11_RefundFailsClosed_WhenVerifyBurnReturnsError pins the
// fail-closed behavior when the registered adapter's VerifyBurnTransaction
// returns (_, error) — e.g., RPC unreachable, receipt parse error. The old
// code returned an error here, but only *inside* the `if err == nil &&
// adapter != nil` guard; this test ensures the gate is reached AND the
// rejection carries the R38-P1-11 audit trail wrapping the underlying err.
func TestR38P1_11_RefundFailsClosed_WhenVerifyBurnReturnsError(t *testing.T) {
	underlying := errors.New("simulated RPC unreachable")
	adapter := &r38P1_11Adapter{
		chainID:      "target-chain",
		burnVerified: false,
		burnErr:      underlying,
	}
	alm, _ := r38P1_11Setup(t, adapter)

	proof := r38P1_11MakeProof()
	op := types.Address{0xAA}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "r38-lock", op, proof)
	if err == nil {
		t.Fatal("R38-P1-11: refund must be REJECTED when VerifyBurnTransaction returns an error")
	}
	if !containsStr(err.Error(), r38P1_11AuditTag) {
		t.Fatalf("R38-P1-11: rejection should carry audit tag %q, got: %v", r38P1_11AuditTag, err)
	}
	if !containsStr(err.Error(), "burn verification error") {
		t.Fatalf("R38-P1-11: error should mention burn verification error, got: %v", err)
	}
	if !containsStr(err.Error(), underlying.Error()) {
		t.Fatalf("R38-P1-11: error should wrap the underlying adapter error %q, got: %v", underlying.Error(), err)
	}
	if adapter.burnCalls == 0 {
		t.Fatal("R38-P1-11: VerifyBurnTransaction was never called — the gate was not reached (fail-open regression)")
	}

	// Lock must remain Failed.
	updated, _ := alm.GetLock("r38-lock")
	if updated.Status != LockStatusFailed {
		t.Fatalf("lock should remain Failed, got %d", updated.Status)
	}
	if updated.BurnProof != nil {
		t.Fatal("BurnProof must NOT be attached when verification returned an error")
	}
}

// TestR38P1_11_RefundAccepts_WhenVerifyBurnReturnsTrue is the happy-path
// control for the fail-closed tests above: when VerifyBurnTransaction
// returns (true, nil), the verification gate OPENS and the refund proceeds
// to the downstream steps (proof attachment + SubmitMessage). The refund
// MAY still fail downstream at SubmitMessage (no trusted validator keys in
// test), but the key assertion is that the error is NOT an R38-P1-11
// verification rejection — proving the gate opened, not that the whole
// refund succeeded.
func TestR38P1_11_RefundAccepts_WhenVerifyBurnReturnsTrue(t *testing.T) {
	adapter := &r38P1_11Adapter{
		chainID:      "target-chain",
		burnVerified: true, // valid burn — gate must open
		burnErr:      nil,
	}
	alm, _ := r38P1_11Setup(t, adapter)

	proof := r38P1_11MakeProof()
	op := types.Address{0xAA}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "r38-lock", op, proof)
	// The verification gate MUST have been reached and opened.
	if adapter.burnCalls == 0 {
		t.Fatal("R38-P1-11: VerifyBurnTransaction must be called when bridge+adapter are configured")
	}
	if adapter.burnCalls > 1 {
		t.Fatalf("R38-P1-11: VerifyBurnTransaction should be called exactly once, got %d", adapter.burnCalls)
	}

	if err != nil {
		// Downstream SubmitMessage failure is acceptable in tests without
		// trusted validator keys — but it must NOT be an R38-P1-11
		// verification rejection (those would indicate the gate closed,
		// i.e. fail-closed on the happy path = regression).
		if containsStr(err.Error(), r38P1_11AuditTag) {
			t.Fatalf("R38-P1-11 regression: happy-path returned true but refund was rejected by the verification gate: %v", err)
		}
		t.Logf("refund proceeded past verification gate and failed downstream (expected without trusted keys): %v", err)
	}

	// Critical assertion: the burn proof MUST have been attached to the
	// lock. This proves the verification gate OPENED (the surgical fix's
	// contract: only verified==true proceeds to proof attachment).
	updated, ok := alm.GetLock("r38-lock")
	if !ok {
		t.Fatal("lock should still exist after refund attempt")
	}
	if updated.BurnProof == nil {
		t.Fatal("R38-P1-11: BurnProof must be attached after verification gate opened (only verified==true proceeds)")
	}
	if updated.BurnProof.TxHash != proof.TxHash {
		t.Errorf("BurnProof.TxHash mismatch: got %s, want %s", updated.BurnProof.TxHash, proof.TxHash)
	}
	// If the whole refund chain succeeded, the lock is Refunded; otherwise
	// it stays Failed (atomic — no partial corruption).
	if err == nil {
		if updated.Status != LockStatusRefunded {
			t.Fatalf("lock should be Refunded after successful refund, got %d", updated.Status)
		}
	} else {
		if updated.Status != LockStatusFailed {
			t.Fatalf("lock should remain Failed after downstream SubmitMessage failure, got %d", updated.Status)
		}
	}
}
