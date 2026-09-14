// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
//
// BRIDGE-H06 (R30, 2026-07-27) regression tests: Minted-status lock refund
// requires a burn proof to prevent double-spend.
//
// The vulnerability: When a lock reached Minted status on the target chain
// (wrapped asset was minted) and then failed at a later step (e.g.,
// BurnAsset failure), refunding the source-chain lock WITHOUT burning the
// target-chain wrapped asset creates a double-spend:
//   - User has the wrapped asset on target chain (minted).
//   - User gets the original asset back on source chain (refunded).
//   - Total supply is inflated by `lock.Amount`.
//
// The original code only logged a warning but did NOT block the refund.
// The fix:
//  1. refundFailedLockInternal now REJECTS refunds of Minted-status locks
//     when lock.BurnProof == nil (fail-closed).
//  2. New RefundFailedLockWithBurnProof API allows operators to supply a
//     burn proof (target-chain burn tx hash + chain ID + amount) that
//     matches the lock. The proof is validated and attached to the lock
//     before the refund proceeds.
//
// These tests verify:
//  1. Minted-status lock rejected without burn proof (core fix).
//  2. Minted-status lock allowed with valid burn proof.
//  3. Burn proof with mismatched ChainID rejected.
//  4. Burn proof with mismatched Amount rejected.
//  5. Burn proof with empty TxHash rejected.
//  6. Non-Minted lock still refundable without burn proof (no regression).
//  7. RefundFailedLockWithBurnProof requires operator authorization.
//  8. RefundFailedLockWithBurnProof fails closed when no operators set.
//  9. Idempotent retry with same burn proof succeeds.
//
// 10. Different burn proof on retry rejected (no proof swapping).
// 11. Legacy/internal path (timeout watcher) cannot auto-refund Minted locks.
package bridge

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// insertFailedLockWithMintedReason inserts a Failed lock whose FailedReason
// contains "Minted", simulating a lock that reached Minted status and then
// failed at a later step (e.g., BurnAsset failure). This triggers the
// BRIDGE-H06 burn-proof requirement.
func insertFailedLockWithMintedReason(alm *AssetLockManager, id string, source, target ChainID) *AssetLock {
	return insertFailedLock(alm, id, source, target,
		"burn submit failed: simulated (was Minted)")
}

// TestBRIDGE_H06_MintedStatusLockRejectedWithoutBurnProof verifies the
// core BRIDGE-H06 fix: a refund of a Minted-status lock is REJECTED when
// no burn proof is supplied. Previously the code only logged a warning but
// still processed the refund — creating a double-spend risk.
func TestBRIDGE_H06_MintedStatusLockRejectedWithoutBurnProof(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	insertFailedLockWithMintedReason(alm, "lock-h06-no-proof", "source-chain", "target-chain")

	// Authorized operator, but NO burn proof — refund must be rejected.
	err := alm.RefundFailedLockAuthorized(context.Background(), "lock-h06-no-proof", op)
	if err == nil {
		t.Fatal("BRIDGE-H06 regression: refund of Minted-status lock without burn proof should be rejected")
	}
	if !containsStr(err.Error(), "Minted status") && !containsStr(err.Error(), "burn proof") {
		t.Fatalf("BRIDGE-H06: error should mention Minted status / burn proof, got: %v", err)
	}

	// Lock must remain in Failed status (refund did not proceed).
	lock, ok := alm.GetLock("lock-h06-no-proof")
	if !ok || lock.Status != LockStatusFailed {
		t.Fatalf("lock should remain Failed after rejected refund, got ok=%v status=%d", ok, lock.Status)
	}
	if lock.BurnProof != nil {
		t.Fatal("BurnProof should not be set on a lock that was never refunded with a proof")
	}
}

// TestBRIDGE_H06_MintedStatusLockAllowedWithBurnProof verifies that an
// authorized operator supplying a valid burn proof passes the BRIDGE-H06
// burn-proof validation. The refund may still fail downstream at
// bridge.SubmitMessage (which fails-closed in tests without trusted
// validator keys), but the key assertion is that the error is NOT about
// Minted/burn-proof — i.e., validation passed and the burn proof was
// attached to the lock. This proves the operator API works end-to-end.
func TestBRIDGE_H06_MintedStatusLockAllowedWithBurnProof(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	lock := insertFailedLockWithMintedReason(alm, "lock-h06-with-proof", "source-chain", "target-chain")

	burnProof := &BurnProof{
		TxHash:  "0xburntxhash123",
		ChainID: lock.TargetChain,              // must match
		Amount:  new(big.Int).Set(lock.Amount), // must match
	}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-with-proof", op, burnProof)
	// The refund MAY fail at bridge.SubmitMessage (fail-closed without
	// trusted validator keys) — that's expected and proves the burn-proof
	// validation passed. The error must NOT mention "Minted status" or
	// "burn proof" (those would indicate validation rejection).
	if err != nil {
		if containsStr(err.Error(), "Minted status") || containsStr(err.Error(), "burn proof") {
			t.Fatalf("BRIDGE-H06: burn proof validation should have passed, but got validation error: %v", err)
		}
		// SubmitMessage failure is acceptable — burn proof validation passed.
		t.Logf("refund failed at SubmitMessage (expected without trusted keys): %v", err)
	}

	// Critical assertion: the burn proof MUST have been attached to the
	// lock, regardless of whether SubmitMessage succeeded. This proves the
	// operator API correctly validated and stored the proof.
	updated, ok := alm.GetLock("lock-h06-with-proof")
	if !ok {
		t.Fatal("lock should still exist after refund attempt")
	}
	if updated.BurnProof == nil {
		t.Fatal("BRIDGE-H06: BurnProof should be attached to lock after passing validation (audit trail)")
	}
	if updated.BurnProof.TxHash != burnProof.TxHash {
		t.Errorf("BurnProof.TxHash mismatch: got %s, want %s", updated.BurnProof.TxHash, burnProof.TxHash)
	}
	if updated.BurnProof.ChainID != burnProof.ChainID {
		t.Errorf("BurnProof.ChainID mismatch: got %s, want %s", updated.BurnProof.ChainID, burnProof.ChainID)
	}
	if updated.BurnProof.Amount.Cmp(burnProof.Amount) != 0 {
		t.Errorf("BurnProof.Amount mismatch: got %s, want %s", updated.BurnProof.Amount.String(), burnProof.Amount.String())
	}

	// If SubmitMessage succeeded, the lock must have transitioned to Refunded.
	if err == nil {
		if updated.Status != LockStatusRefunded {
			t.Fatalf("lock status should be Refunded after successful refund, got %d", updated.Status)
		}
	} else {
		// If SubmitMessage failed, the lock must remain in Failed (atomic —
		// no partial state corruption).
		if updated.Status != LockStatusFailed {
			t.Fatalf("lock should remain Failed after SubmitMessage failure, got %d", updated.Status)
		}
	}
}

// TestBRIDGE_H06_MintedStatusLockRejectsMismatchedChainID verifies that
// a burn proof whose ChainID does NOT match lock.TargetChain is rejected.
// This prevents an operator from burning an asset on the wrong chain and
// using that proof to release the source-chain lock.
func TestBRIDGE_H06_MintedStatusLockRejectsMismatchedChainID(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	lock := insertFailedLockWithMintedReason(alm, "lock-h06-wrong-chain", "source-chain", "target-chain")

	// Use a chain that IS registered as an adapter (so the R38-P1-11
	// fail-closed on-chain burn verification gate passes and execution
	// proceeds to the lock-level ChainID mismatch check), but does NOT
	// match lock.TargetChain="target-chain". "source-chain" is registered
	// by setupBridgeWithAdapters and its trackingAdapter returns
	// verified=true, so the mismatch is still detected at the lock-level
	// ChainID check below — which is what this test pins.
	wrongChain := ChainID("source-chain")
	burnProof := &BurnProof{
		TxHash:  "0xburntxhash456",
		ChainID: wrongChain, // does NOT match lock.TargetChain
		Amount:  new(big.Int).Set(lock.Amount),
	}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-wrong-chain", op, burnProof)
	if err == nil {
		t.Fatal("refund with mismatched ChainID burn proof should be rejected")
	}
	if !containsStr(err.Error(), "ChainID") {
		t.Fatalf("error should mention ChainID mismatch, got: %v", err)
	}

	// Lock must remain Failed.
	updated, _ := alm.GetLock("lock-h06-wrong-chain")
	if updated.Status != LockStatusFailed {
		t.Fatalf("lock should remain Failed, got %d", updated.Status)
	}
}

// TestBRIDGE_H06_MintedStatusLockRejectsMismatchedAmount verifies that
// a burn proof whose Amount does NOT match lock.Amount is rejected.
// Partial burns are not allowed — the entire wrapped asset must be burned
// to prevent partial double-spend.
func TestBRIDGE_H06_MintedStatusLockRejectsMismatchedAmount(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	lock := insertFailedLockWithMintedReason(alm, "lock-h06-wrong-amount", "source-chain", "target-chain")

	burnProof := &BurnProof{
		TxHash:  "0xburntxhash789",
		ChainID: lock.TargetChain,
		Amount:  big.NewInt(999), // does NOT match lock.Amount (1000)
	}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-wrong-amount", op, burnProof)
	if err == nil {
		t.Fatal("refund with mismatched amount burn proof should be rejected")
	}
	if !containsStr(err.Error(), "amount") {
		t.Fatalf("error should mention amount mismatch, got: %v", err)
	}
}

// TestBRIDGE_H06_MintedStatusLockRejectsEmptyTxHash verifies that a burn
// proof with an empty TxHash is rejected. The TxHash is the on-chain
// evidence of the burn — without it, there's no proof at all.
func TestBRIDGE_H06_MintedStatusLockRejectsEmptyTxHash(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	lock := insertFailedLockWithMintedReason(alm, "lock-h06-empty-txhash", "source-chain", "target-chain")

	burnProof := &BurnProof{
		TxHash:  "", // empty
		ChainID: lock.TargetChain,
		Amount:  new(big.Int).Set(lock.Amount),
	}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-empty-txhash", op, burnProof)
	if err == nil {
		t.Fatal("refund with empty TxHash burn proof should be rejected")
	}
	if !containsStr(err.Error(), "TxHash") {
		t.Fatalf("error should mention TxHash, got: %v", err)
	}
}

// TestBRIDGE_H06_NonMintedLockAllowedWithoutBurnProof verifies that
// non-Minted locks (e.g., failed at Locked status) can still be refunded
// WITHOUT a burn proof. This is a regression guard: the BRIDGE-H06 fix
// must not over-block legitimate refunds of locks that never reached
// Minted status (no wrapped asset was minted → no double-spend risk).
func TestBRIDGE_H06_NonMintedLockAllowedWithoutBurnProof(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	// FailedReason does NOT contain "Minted" — was Locked at failure time.
	insertFailedLock(alm, "lock-h06-locked", "source-chain", "target-chain",
		"mint submit failed: simulated (was Locked)")

	err := alm.RefundFailedLockAuthorized(context.Background(), "lock-h06-locked", op)
	// Should NOT be rejected for burn proof reasons. It may fail at
	// bridge.SubmitMessage (no trusted keys), but that's a different
	// error. The key assertion: no "Minted" or "burn proof" in the error.
	if err != nil {
		if containsStr(err.Error(), "Minted status") || containsStr(err.Error(), "burn proof") {
			t.Fatalf("BRIDGE-H06 regression: non-Minted lock should NOT require burn proof, got: %v", err)
		}
	}
}

// TestBRIDGE_H06_WithBurnProofRequiresAuthorization verifies that
// RefundFailedLockWithBurnProof enforces operator authorization even
// when a valid burn proof is supplied. An unauthorized caller must be
// rejected before the burn proof is even examined.
func TestBRIDGE_H06_WithBurnProofRequiresAuthorization(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	attacker := types.Address{0xBB}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	lock := insertFailedLockWithMintedReason(alm, "lock-h06-auth", "source-chain", "target-chain")

	burnProof := &BurnProof{
		TxHash:  "0xburntxhash-auth",
		ChainID: lock.TargetChain,
		Amount:  new(big.Int).Set(lock.Amount),
	}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-auth", attacker, burnProof)
	if !errors.Is(err, ErrUnauthorizedOperator) {
		t.Fatalf("expected ErrUnauthorizedOperator for non-operator caller, got %v", err)
	}

	// Burn proof must NOT have been attached (auth rejected before mutation).
	updated, _ := alm.GetLock("lock-h06-auth")
	if updated.BurnProof != nil {
		t.Fatal("BurnProof must not be set when authorization was rejected")
	}
}

// TestBRIDGE_H06_WithBurnProofFailsClosedWhenNoOperators verifies the
// fail-closed behavior: when no operators are configured, even a caller
// supplying a valid burn proof is rejected.
func TestBRIDGE_H06_WithBurnProofFailsClosedWhenNoOperators(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	// Deliberately do NOT call SetAuthorizedOperators.
	lock := insertFailedLockWithMintedReason(alm, "lock-h06-fc", "source-chain", "target-chain")

	burnProof := &BurnProof{
		TxHash:  "0xburntxhash-fc",
		ChainID: lock.TargetChain,
		Amount:  new(big.Int).Set(lock.Amount),
	}

	caller := types.Address{0x01}
	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-fc", caller, burnProof)
	if !errors.Is(err, ErrUnauthorizedOperator) {
		t.Fatalf("expected ErrUnauthorizedOperator when no operators configured, got %v", err)
	}
}

// TestBRIDGE_H06_IdempotentRetryWithSameBurnProof verifies that retrying
// RefundFailedLockWithBurnProof with the SAME burn proof is accepted.
// This handles the case where a first attempt fails transiently (e.g.,
// network error or SubmitMessage failure) and the operator retries with
// the same proof. The second call must NOT be rejected as a proof
// mismatch (idempotent retry).
func TestBRIDGE_H06_IdempotentRetryWithSameBurnProof(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	lock := insertFailedLockWithMintedReason(alm, "lock-h06-retry", "source-chain", "target-chain")

	burnProof := &BurnProof{
		TxHash:  "0xburntxhash-retry",
		ChainID: lock.TargetChain,
		Amount:  new(big.Int).Set(lock.Amount),
	}

	// First call: may succeed (transition to Refunded) or fail at
	// SubmitMessage (fail-closed without trusted validator keys). Either
	// way, the burn proof should be attached.
	firstErr := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-retry", op, burnProof)
	if firstErr != nil {
		if containsStr(firstErr.Error(), "Minted status") || containsStr(firstErr.Error(), "burn proof is required") {
			t.Fatalf("first refund should pass burn proof validation, got: %v", firstErr)
		}
		t.Logf("first refund failed at SubmitMessage (expected without trusted keys): %v", firstErr)
	}

	// Verify the burn proof was attached after the first call.
	afterFirst, _ := alm.GetLock("lock-h06-retry")
	if afterFirst.BurnProof == nil {
		t.Fatal("BurnProof should be attached after first call (validation passed)")
	}

	// If the first call succeeded, the lock is now Refunded — a second
	// call will fail at the status check (only Failed locks can be
	// refunded). This is correct behavior.
	if firstErr == nil {
		if afterFirst.Status != LockStatusRefunded {
			t.Fatalf("lock should be Refunded after successful first call, got %d", afterFirst.Status)
		}
		// Second call must fail at the status check, NOT at burn proof
		// validation. The error should mention "not failed", not "mismatch".
		secondErr := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-retry", op, burnProof)
		if secondErr == nil {
			t.Fatal("second refund on a Refunded lock should fail (no double-refund)")
		}
		if containsStr(secondErr.Error(), "mismatch") {
			t.Fatalf("second call should fail at status check, not proof mismatch: %v", secondErr)
		}
		return
	}

	// First call failed at SubmitMessage → lock is still Failed. The
	// second call with the SAME burn proof must NOT be rejected as a
	// proof mismatch (idempotent retry). It may fail again at
	// SubmitMessage, but that's a different error.
	secondErr := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-retry", op, burnProof)
	if secondErr == nil {
		// Second call succeeded — lock should be Refunded now.
		afterSecond, _ := alm.GetLock("lock-h06-retry")
		if afterSecond.Status != LockStatusRefunded {
			t.Fatalf("lock should be Refunded after successful retry, got %d", afterSecond.Status)
		}
		return
	}
	// Second call failed — must NOT be a proof mismatch (same proof is
	// idempotent). It should be a SubmitMessage failure.
	if containsStr(secondErr.Error(), "mismatch") {
		t.Fatalf("BRIDGE-H06: idempotent retry with same burn proof should NOT be rejected as mismatch: %v", secondErr)
	}
	t.Logf("second refund failed at SubmitMessage (expected without trusted keys): %v", secondErr)

	// Lock must still be in Failed status with burn proof attached.
	afterSecond, _ := alm.GetLock("lock-h06-retry")
	if afterSecond.Status != LockStatusFailed {
		t.Fatalf("lock should remain Failed after failed retry, got %d", afterSecond.Status)
	}
	if afterSecond.BurnProof == nil || afterSecond.BurnProof.TxHash != burnProof.TxHash {
		t.Fatal("burn proof must remain attached after idempotent retry")
	}
}

// TestBRIDGE_H06_DifferentBurnProofOnRetryRejected verifies that if a
// burn proof was already attached to a lock (e.g., from a previous
// successful validation), a subsequent attempt with a DIFFERENT burn
// proof is rejected. This prevents an operator from swapping proofs
// after the fact (e.g., to launder a fake burn).
//
// NOTE: In practice, once a lock is Refunded, the status check blocks
// further refunds. This test simulates the scenario where the first
// attempt FAILED (e.g., SubmitMessage error) and the lock is still in
// Failed status with a proof already attached — the operator must then
// retry with the SAME proof, not a different one.
func TestBRIDGE_H06_DifferentBurnProofOnRetryRejected(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	lock := insertFailedLockWithMintedReason(alm, "lock-h06-swap", "source-chain", "target-chain")

	// Manually attach a burn proof (simulating a previous attempt that
	// validated the proof but failed at SubmitMessage).
	lock.BurnProof = &BurnProof{
		TxHash:  "0xburntxhash-original",
		ChainID: lock.TargetChain,
		Amount:  new(big.Int).Set(lock.Amount),
	}

	// Attempt to refund with a DIFFERENT burn proof (different TxHash).
	differentProof := &BurnProof{
		TxHash:  "0xburntxhash-forged", // different!
		ChainID: lock.TargetChain,
		Amount:  new(big.Int).Set(lock.Amount),
	}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-swap", op, differentProof)
	if err == nil {
		t.Fatal("BRIDGE-H06: refund with different burn proof on retry should be rejected")
	}
	if !containsStr(err.Error(), "mismatch") {
		t.Fatalf("error should mention proof mismatch, got: %v", err)
	}

	// Original burn proof must still be intact (not overwritten).
	updated, _ := alm.GetLock("lock-h06-swap")
	if updated.BurnProof.TxHash != "0xburntxhash-original" {
		t.Errorf("original burn proof must not be overwritten, got TxHash=%s", updated.BurnProof.TxHash)
	}
}

// TestBRIDGE_H06_LegacyInternalPathCannotAutoRefundMintedLocks verifies
// that the internal/legacy refund path (used by the timeout watcher and
// HandlePendingMessageEviction) CANNOT auto-refund Minted-status locks.
// The timeout watcher does not supply a burn proof, so it must NOT
// silently refund a Minted-status lock — that would re-introduce the
// double-spend vulnerability.
//
// This is the key defense: even if an attacker manages to trigger the
// timeout watcher on a Minted-status lock (e.g., by delaying the burn
// step past 24h), the watcher's refund attempt is REJECTED.
func TestBRIDGE_H06_LegacyInternalPathCannotAutoRefundMintedLocks(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	insertFailedLockWithMintedReason(alm, "lock-h06-internal", "source-chain", "target-chain")

	// refundFailedLockLegacy is the path used by the timeout watcher.
	err := alm.refundFailedLockLegacy(context.Background(), "lock-h06-internal")
	if err == nil {
		t.Fatal("BRIDGE-H06 regression: internal/legacy path must NOT auto-refund Minted-status locks without burn proof")
	}
	if !containsStr(err.Error(), "Minted status") && !containsStr(err.Error(), "burn proof") {
		t.Fatalf("error should mention Minted status / burn proof, got: %v", err)
	}

	// Lock must remain Failed.
	updated, _ := alm.GetLock("lock-h06-internal")
	if updated.Status != LockStatusFailed {
		t.Fatalf("lock should remain Failed, got %d", updated.Status)
	}
}

// TestBRIDGE_H06_NilBurnProofRejected verifies that explicitly passing
// nil as the burn proof to RefundFailedLockWithBurnProof is rejected
// with a clear error message.
func TestBRIDGE_H06_NilBurnProofRejected(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	insertFailedLockWithMintedReason(alm, "lock-h06-nil", "source-chain", "target-chain")

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-nil", op, nil)
	if err == nil {
		t.Fatal("refund with nil burn proof should be rejected")
	}
	if !containsStr(err.Error(), "burn proof is required") {
		t.Fatalf("error should mention burn proof is required, got: %v", err)
	}
}

// TestBRIDGE_H06_ZeroAmountBurnProofRejected verifies that a burn proof
// with a zero or negative amount is rejected at the structural validation
// stage, before any lock lookup.
func TestBRIDGE_H06_ZeroAmountBurnProofRejected(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	lock := insertFailedLockWithMintedReason(alm, "lock-h06-zero-amt", "source-chain", "target-chain")

	burnProof := &BurnProof{
		TxHash:  "0xburntxhash-zero",
		ChainID: lock.TargetChain,
		Amount:  big.NewInt(0), // zero amount
	}

	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-h06-zero-amt", op, burnProof)
	if err == nil {
		t.Fatal("refund with zero amount burn proof should be rejected")
	}
	if !containsStr(err.Error(), "amount") {
		t.Fatalf("error should mention amount, got: %v", err)
	}
}

// containsStr is a small helper to avoid pulling in strings package for the
// test file. Returns true if substr appears in s.
func containsStr(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
