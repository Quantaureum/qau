// Quantaureum Node source, version 1.0.0.
// ECON-R15-H01 regression tests (2026-07-22).
//
// Audit concern: "verify pool.TotalCommission is deducted correctly, preventing an operator
// from claiming commission twice" — verify that ClaimCommission correctly deducts
// pool.TotalCommission so the operator cannot repeatedly claim the same
// commission.
//
// The fix (R13-CRIT-004, already applied) resets pool.TotalCommission to 0
// at line 721 of liquid_staking.go after copying it to the local
// `commission` variable. These tests verify the double-claim scenario
// explicitly: a second claim immediately after the first must return 0
// and must not credit the operator again.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestECON_R15_H01_DoubleClaimReturnsZero verifies that after claiming
// commission once, a second claim (with no new rewards distributed in
// between) returns 0 and does not credit the operator again. This is
// the core double-claim prevention required by ECON-R15-H01.
func TestECON_R15_H01_DoubleClaimReturnsZero(t *testing.T) {
	lsm, pool, operator := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	// Setup: delegator stakes 1000, operator funds 1000, distribute 100
	// reward → commission = 5 QAU (5%).
	lsm.Deposit(delegator, StakeAsset, big.NewInt(1000))
	if _, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000)); err != nil {
		t.Fatalf("StakeLiquid failed: %v", err)
	}
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(100)); err != nil {
		t.Fatalf("DistributeRewards failed: %v", err)
	}

	// First claim: should return 5 and credit operator.
	first, err := lsm.ClaimCommission(pool.ID, operator)
	if err != nil {
		t.Fatalf("first ClaimCommission failed: %v", err)
	}
	if first.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("expected first claim=5, got %s", first)
	}
	balAfterFirst := lsm.GetUserTokenBalance(operator, StakeAsset)

	// Second claim immediately after: should return 0 (TotalCommission
	// was reset to 0 by the first claim) and NOT credit the operator.
	second, err := lsm.ClaimCommission(pool.ID, operator)
	if err != nil {
		t.Fatalf("second ClaimCommission failed: %v", err)
	}
	if second.Sign() != 0 {
		t.Errorf("ECON-R15-H01 REGRESSION: expected second claim=0 (TotalCommission "+
			"should be reset), got %s — operator could repeatedly claim the same commission",
			second)
	}
	balAfterSecond := lsm.GetUserTokenBalance(operator, StakeAsset)
	if balAfterSecond.Cmp(balAfterFirst) != 0 {
		t.Errorf("ECON-R15-H01 REGRESSION: operator balance changed after empty second "+
			"claim (before=%s, after=%s) — double-claim credited the operator twice",
			balAfterFirst, balAfterSecond)
	}
}

// TestECON_R15_H01_ClaimAfterNewRewards verifies that after claiming
// commission once, distributing NEW rewards accrues NEW commission that
// can be claimed again. This confirms the reset is not permanent — the
// operator can claim legitimately accrued commission in subsequent epochs.
func TestECON_R15_H01_ClaimAfterNewRewards(t *testing.T) {
	lsm, pool, operator := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	lsm.Deposit(delegator, StakeAsset, big.NewInt(1000))
	if _, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000)); err != nil {
		t.Fatalf("StakeLiquid failed: %v", err)
	}
	lsm.Deposit(operator, StakeAsset, big.NewInt(2000))

	// First epoch: distribute 100 → commission 5.
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(100)); err != nil {
		t.Fatalf("first DistributeRewards failed: %v", err)
	}
	first, err := lsm.ClaimCommission(pool.ID, operator)
	if err != nil {
		t.Fatalf("first ClaimCommission failed: %v", err)
	}
	if first.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("expected first claim=5, got %s", first)
	}

	// Second epoch: distribute another 100 → commission 5 again.
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(100)); err != nil {
		t.Fatalf("second DistributeRewards failed: %v", err)
	}
	second, err := lsm.ClaimCommission(pool.ID, operator)
	if err != nil {
		t.Fatalf("second ClaimCommission failed: %v", err)
	}
	if second.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("expected second claim=5 (new commission from new rewards), got %s — "+
			"TotalCommission reset should not prevent claiming newly accrued commission",
			second)
	}
}

// TestECON_R15_H01_TotalCommissionResetToZero verifies that
// pool.TotalCommission is exactly 0 after a claim, not just "small"
// or "negative". This catches subtle bugs where SetInt64(0) is skipped
// or where the pointer is reassigned instead of mutating in place.
func TestECON_R15_H01_TotalCommissionResetToZero(t *testing.T) {
	lsm, pool, operator := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	lsm.Deposit(delegator, StakeAsset, big.NewInt(1000))
	if _, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000)); err != nil {
		t.Fatalf("StakeLiquid failed: %v", err)
	}
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(100)); err != nil {
		t.Fatalf("DistributeRewards failed: %v", err)
	}

	// Verify pre-condition: TotalCommission > 0.
	pending, err := lsm.GetPendingCommission(pool.ID)
	if err != nil {
		t.Fatalf("GetPendingCommission failed: %v", err)
	}
	if pending.Sign() <= 0 {
		t.Fatalf("precondition: expected pending commission > 0, got %s", pending)
	}

	// Claim.
	if _, err := lsm.ClaimCommission(pool.ID, operator); err != nil {
		t.Fatalf("ClaimCommission failed: %v", err)
	}

	// Verify post-condition: TotalCommission == 0 exactly.
	pendingAfter, _ := lsm.GetPendingCommission(pool.ID)
	if pendingAfter.Sign() != 0 {
		t.Errorf("ECON-R15-H01 REGRESSION: expected TotalCommission=0 after claim, "+
			"got %s — operator could claim the residual on a subsequent call",
			pendingAfter)
	}
}
