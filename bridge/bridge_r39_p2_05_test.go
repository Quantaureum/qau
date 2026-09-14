// Quantaureum Node source, version 1.0.0.
package bridge

// R39-P2-05 (2026-08-02) regression tests for the bridge's per-message
// maximum transfer amount upper bound on the unlock paths.
//
// Audit finding: the bridge/asset_lock.go unlock-proof path
// lacked an amount-range check — the lock-side bridge.go path did check the upper
// bound (line ~2525), but the unlock paths (UnlockAsset +
// RefundFailedLockWithBurnProof) only checked Sign() > 0, not the
// per-message upper bound. The fix centralizes the upper bound as a
// single package-level constant (maxTransferAmountStr) and enforces
// it on all three paths (lock / unlock / refund-with-burn-proof), so
// failure of any single upstream check doesn't bypass the global
// upper bound.
//
// Tests in this file pin three guarantees:
//   1. UnlockAsset refuses when lock.Amount > maxTransferAmount.
//   2. RefundFailedLockWithBurnProof refuses when proof.Amount >
//      maxTransferAmount.
//   3. The maxTransferAmountStr constant matches the documented upper
//      bound (1e27 base units) — if anyone reorders the constants or
//      accidentally changes the value, the test catches it.

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// ── Test 1: UnlockAsset refuses when lock.Amount > maxTransferAmount. ──

// TestR39_P2_05_UnlockAsset_RefusesInflatedAmount pins the audit's
// primary contract: when a lock's Amount exceeds the protocol-wide
// upper bound (maxTransferAmountStr = 1e27), UnlockAsset MUST refuse
// to release the funds — fail-closed. Without this check, a
// hypothetical bug in LockAsset that lets lock.Amount exceed
// maxTransferAmount (e.g., a refactor that drops bridge.go:2525's
// upper-bound check) would silently release / refund the inflated
// amount out of the bridge's locked-asset reserve.
//
// Fixture: insert a Burned-status lock with Amount = 1e27 + 1 (one
// unit over the bound). Call UnlockAsset. Must fail with the
// "R39-P2-05" marker in the error string.
func TestR39_P2_05_UnlockAsset_RefusesInflatedAmount(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	b.adapters["source-chain"] = &trackingAdapter{chainID: "source-chain"}
	b.adapters["target-chain"] = &trackingAdapter{chainID: "target-chain"}

	alm := NewAssetLockManager(b, types.Address{})

	// Construct an inflated amount exactly 1 unit over the bound.
	var upperBound big.Int
	upperBound.SetString(maxTransferAmountStr, 10)
	inflated := new(big.Int).Add(&upperBound, big.NewInt(1))

	// Insert a Burned-status lock with the inflated amount directly
	// (simulating an upstream bug that bypassed bridge.go:2525).
	lock := &AssetLock{
		ID:           "lock-inflated-unlock",
		SourceChain:  "source-chain",
		TargetChain:  "target-chain",
		AssetType:    AssetTypeQRC20,
		TokenAddress: types.Address{0x11},
		Amount:       inflated,
		Owner:        types.Address{0xAA},
		Recipient:    types.Address{0xBB},
		Status:       LockStatusBurned,
		LockTxHash:   "0xmocktxhash",
		BurnTxHash:   "0xmockburnhash",
		CreatedAt:    time.Now().Unix(),
		LockedAt:     time.Now().Unix(),
		BurnedAt:     time.Now().Unix(),
	}
	alm.mu.Lock()
	alm.locks[lock.ID] = lock
	alm.locksByOwner[lock.Owner] = append(alm.locksByOwner[lock.Owner], lock.ID)
	if alm.locksByStatus[LockStatusBurned] == nil {
		alm.locksByStatus[LockStatusBurned] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusBurned][lock.ID] = true
	alm.mu.Unlock()

	// UnlockAsset: should refuse BEFORE the burn-confirmation check
	// because the upper-bound check is at line ~757 (just after the
	// nil/zero check), while the burn-confirmation check is at line
	// ~731 — wait, actually the burn-confirmation check is BEFORE the
	// amount checks. Let me re-read.
	//
	// Actually:
	//   line 731: burnBlockNumber==0 fail-closed
	//   line 738: HasSufficientConfirmations verification
	//   line 753: lock.Amount nil/zero check
	//   line 757 (R39-P2-05 new): upper bound check ← we hit this
	//
	// So we MUST pass a non-zero burnBlockNumber AND the target adapter
	// MUST confirm successfully. The trackingAdapter returns true for
	// HasSufficientConfirmations (see bridge_r13_h01_pause_resume_test.go:62).
	err := alm.UnlockAsset(context.Background(), lock.ID, 1)
	if err == nil {
		t.Fatalf("R39-P2-05: UnlockAsset MUST refuse when lock.Amount > maxTransferAmount (fail-closed); got nil error — the audit's unlock-path upper-bound check is missing or wrong")
	}
	if !strings.Contains(err.Error(), "R39-P2-05") {
		t.Fatalf("R39-P2-05: UnlockAsset refused (good) but the error MUST carry the R39-P2-05 marker for log aggregator grep — got: %v", err)
	}

	// Lock MUST remain in Burned status — fail-closed must NOT mutate
	// state. (The markLockFailed path is only triggered at line ~786
	// after SubmitMessage fails, which we never reach because the
	// upper-bound check fails first.)
	got, ok := alm.GetLock(lock.ID)
	if !ok {
		t.Fatalf("R39-P2-05: lock vanished after fail-closed refusal — protocol accounting corruption")
	}
	if got.Status != LockStatusBurned {
		t.Fatalf("R39-P2-05: lock status mutated from Burned to %d after fail-closed refusal — fail-closed path must NOT mutate state, only return error", got.Status)
	}
}

// ── Test 2: RefundFailedLockWithBurnProof refuses inflated proof.Amount. ──

// TestR39_P2_05_RefundFailedLockWithBurnProof_RefusesInflatedAmount
// pins the second unlock proof path: when proof.Amount exceeds the
// upper bound, the refund MUST be refused — fail-closed.
//
// Fixture: insert a Failed-status lock, authorize an operator, and
// call RefundFailedLockWithBurnProof with a proof whose Amount exceeds
// the bound. The refund MUST fail with the R39-P2-05 marker before
// any refund message is submitted.
func TestR39_P2_05_RefundFailedLockWithBurnProof_RefusesInflatedAmount(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	b.adapters["source-chain"] = &trackingAdapter{chainID: "source-chain"}
	b.adapters["target-chain"] = &trackingAdapter{chainID: "target-chain"}

	alm := NewAssetLockManager(b, types.Address{})

	// Authorize an operator so we get past the auth check at line ~1345.
	operator := types.Address{0x0F, 0xF0}
	alm.mu.Lock()
	if alm.authorizedOperators == nil {
		alm.authorizedOperators = make(map[types.Address]bool)
	}
	alm.authorizedOperators[operator] = true
	alm.mu.Unlock()

	// Insert a Failed-status lock with a normal (non-inflated) amount.
	normalAmount := big.NewInt(1000)
	insertFailedLock(alm, "lock-inflated-refund", "source-chain", "target-chain", "simulated")
	alm.mu.Lock()
	lk := alm.locks["lock-inflated-refund"]
	if lk != nil {
		lk.Amount = normalAmount
		lk.TargetChain = "target-chain"
	}
	alm.mu.Unlock()

	// Construct a proof whose Amount exceeds the upper bound. The
	// strict equality check at line ~1435 would normally catch a
	// mismatch, but our upper-bound check at line ~1383 fires FIRST
	// (before the lock equality check), so we never even reach the
	// equality comparison.
	var upperBound big.Int
	upperBound.SetString(maxTransferAmountStr, 10)
	inflatedProof := new(big.Int).Add(&upperBound, big.NewInt(1))

	proof := &BurnProof{
		TxHash:  "0xinflated-burn",
		ChainID: "target-chain",
		Amount:  inflatedProof,
	}
	err := alm.RefundFailedLockWithBurnProof(context.Background(), "lock-inflated-refund", operator, proof)
	if err == nil {
		t.Fatalf("R39-P2-05: RefundFailedLockWithBurnProof MUST refuse when proof.Amount > maxTransferAmount (fail-closed); got nil error — the audit's refund-path upper-bound check is missing or wrong")
	}
	if !strings.Contains(err.Error(), "R39-P2-05") {
		t.Fatalf("R39-P2-05: RefundFailedLockWithBurnProof refused (good) but the error MUST carry the R39-P2-05 marker for log aggregator grep — got: %v", err)
	}

	// Lock MUST remain in Failed status — fail-closed must NOT mutate
	// state. RefundFailedLockWithBurnProof only mutates state after
	// the upper-bound check and the on-chain verification pass, neither
	// of which we hit.
	got, ok := alm.GetLock("lock-inflated-refund")
	if !ok {
		t.Fatalf("R39-P2-05: lock vanished after fail-closed refusal — protocol accounting corruption")
	}
	if got.Status != LockStatusFailed {
		t.Fatalf("R39-P2-05: lock status mutated from Failed to %d after fail-closed refusal — fail-closed path must NOT mutate state", got.Status)
	}
}

// ── Test 3: maxTransferAmountStr constant matches the documented upper bound. ──

// TestR39_P2_05_MaxTransferConstantStable pins the protocol-wide
// upper-bound constant. If a future refactor accidentally changes
// the constant (e.g., typos "1000000000000000000000000000" →
// "100000000000000000000000000" with one fewer zero), the test
// catches it before a malformed bound silently weakens or breaks
// the bridge.
//
// The value is 1e27 base units (a 1 followed by 27 zeros), as
// documented in the bridge.go:2525 comment. We assert the literal
// has exactly 27 zero digits and parses back to 1e27.
func TestR39_P2_05_MaxTransferConstantStable(t *testing.T) {
	if maxTransferAmountStr != "1000000000000000000000000000" {
		t.Fatalf("R39-P2-05: maxTransferAmountStr must be 1e27 (a 1 followed by 27 zeros); got %q — a future refactor accidentally weakened or broke the protocol-wide upper bound", maxTransferAmountStr)
	}
	var v big.Int
	_, ok := v.SetString(maxTransferAmountStr, 10)
	if !ok {
		t.Fatalf("R39-P2-05: maxTransferAmountStr %q is not a valid base-10 integer — the constant is malformed", maxTransferAmountStr)
	}
	if v.Cmp(big.NewInt(0)) <= 0 {
		t.Fatalf("R39-P2-05: maxTransferAmountStr must be positive; got %s — a malformed constant would bypass the upper-bound check (any positive amount > 0 would pass)", v.String())
	}
	// Sanity: assert v == 1e27 by computing 10^27 and comparing.
	want := new(big.Int).Exp(big.NewInt(10), big.NewInt(27), nil)
	if v.Cmp(want) != 0 {
		t.Fatalf("R39-P2-05: maxTransferAmountStr must equal 10^27 = 1e27; got %s, want %s — the constant drifted from the documented upper bound", v.String(), want.String())
	}
}
