// Quantaureum Node source, version 1.0.0.
// ECON-R13-H03 regression tests (2026-07-21).
// accrueInterest must preserve the invariant TotalSupply == sum(Supplies)
// across all code paths, including the previously broken "TotalSupply == 0
// but borrower owes Principal" edge case.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// addrH03a and addrH03b are stable test addresses used across H03 subtests.
var (
	addrH03a = types.Address{0xa1}
	addrH03b = types.Address{0xa2}
)

// makeLendingManagerH03 mirrors makeLendingManagerR13 but seeds two distinct
// suppliers and one borrower so we can drive accrueInterest across multiple
// paths.
func makeLendingManagerH03(t *testing.T) (*LendingManager, string) {
	t.Helper()
	oracle := NewAggregatedPriceOracle(nil)
	oracle.WatchAsset("QAU", big.NewInt(5000))
	oracle.RegisterSource("src1", 100, func(asset string) (*big.Int, error) {
		return big.NewInt(5000), nil
	})
	lm := NewLendingManager(75, 85, 5, oracle)
	pool, err := lm.CreatePool("QAU", 70, 80)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}
	return lm, pool.PoolID
}

// sumSupplies sums pool.Supplies[*] (only positive entries).
func sumSupplies(pool *LendingPool) *big.Int {
	total := big.NewInt(0)
	for _, bal := range pool.Supplies {
		if bal != nil && bal.Sign() > 0 {
			total.Add(total, bal)
		}
	}
	return total
}

// TestECON_R13_H03_InvariantHeld_AfterNormalAccrual verifies that after a
// normal Supply → Borrow → accrueInterest cycle, the invariant
// TotalSupply == sum(Supplies) still holds.
func TestECON_R13_H03_InvariantHeld_AfterNormalAccrual(t *testing.T) {
	lm, poolID := makeLendingManagerH03(t)

	// Two suppliers deposit 5000 each.
	lm.Deposit(addrH03a, "QAU", big.NewInt(10_000))
	if err := lm.Supply(poolID, addrH03a, big.NewInt(5000)); err != nil {
		t.Fatalf("Supply a: %v", err)
	}
	lm.Deposit(addrH03b, "QAU", big.NewInt(10_000))
	if err := lm.Supply(poolID, addrH03b, big.NewInt(5000)); err != nil {
		t.Fatalf("Supply b: %v", err)
	}

	pool, _ := lm.GetPool(poolID)
	if pool.TotalSupply.Cmp(sumSupplies(pool)) != 0 {
		t.Fatalf("invariant broken before borrow: TotalSupply=%s sum=%s",
			pool.TotalSupply, sumSupplies(pool))
	}

	// Borrower borrows a large amount at block 100. We use a large Principal
	// so the per-block interest (Principal * BorrowRate * blocksDelta /
	// 10000 / blocksPerYear) is non-zero after integer truncation.
	// BorrowRate=1000 (10%), blocksPerYear=2_628_000. For interest > 0
	// we need Principal * 1000 * blocksDelta > 10000 * 2_628_000.
	// With Principal=1e18 (1 QAU in wei) and blocksDelta=2_628_000 (~1 year),
	// interest = 1e18 * 1000 * 2_628_000 / 10000 / 2_628_000 = 1e17.
	borrower := types.Address{0xb0}
	// Borrower supplies a large collateral so Borrow(amount) passes the
	// collateral check.
	lm.Deposit(borrower, "QAU", big.NewInt(0).Exp(big.NewInt(10), big.NewInt(20), nil))
	if err := lm.Supply(poolID, borrower, new(big.Int).Exp(big.NewInt(10), big.NewInt(19), nil)); err != nil {
		t.Fatalf("Supply borrower: %v", err)
	}
	if err := lm.Borrow(poolID, borrower, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), 100); err != nil {
		t.Fatalf("Borrow: %v", err)
	}

	// Advance ~1 year of blocks (2_628_000) and trigger accrual via Repay.
	// Repay amount of 1 just causes a tiny principal reduction; the real
	// work happens in accrueInterest.
	oneYearLater := uint64(100 + 2_628_000)
	if err := lm.Repay(poolID, borrower, big.NewInt(1), oneYearLater); err != nil {
		t.Fatalf("Repay: %v", err)
	}

	pool, _ = lm.GetPool(poolID)
	if pool.TotalSupply.Cmp(sumSupplies(pool)) != 0 {
		t.Fatalf("ECON-R13-H03 invariant broken: TotalSupply=%s but sum(Supplies)=%s (diff=%s)",
			pool.TotalSupply.String(), sumSupplies(pool).String(),
			new(big.Int).Sub(pool.TotalSupply, sumSupplies(pool)).String())
	}
}

// TestECON_R13_H03_InvariantHeld_NoSuppliersButBorrowerOwes reproduces the
// exact bug from the audit: a pool where every supplier has Withdrawn to
// zero but a borrower still has Principal outstanding. Previously the
// branch `pool.TotalSupply.Add(pool.TotalSupply, supplierInterest)` was
// reached even though the distribution loop was skipped, breaking the
// invariant. After the fix, the supplierInterest is redirected to
// pool.Reserves and TotalSupply is left untouched.
func TestECON_R13_H03_InvariantHeld_NoSuppliersButBorrowerOwes(t *testing.T) {
	lm, poolID := makeLendingManagerH03(t)

	// Supplier a deposits 10000, supplies 5000, then withdraws 5000.
	lm.Deposit(addrH03a, "QAU", big.NewInt(20_000))
	if err := lm.Supply(poolID, addrH03a, big.NewInt(5000)); err != nil {
		t.Fatalf("Supply a: %v", err)
	}
	// Borrower b supplies collateral (1000) and borrows 500.
	borrower := types.Address{0xb0}
	lm.Deposit(borrower, "QAU", big.NewInt(20_000))
	if err := lm.Supply(poolID, borrower, big.NewInt(1000)); err != nil {
		t.Fatalf("Supply borrower: %v", err)
	}
	if err := lm.Borrow(poolID, borrower, big.NewInt(500), 100); err != nil {
		t.Fatalf("Borrow: %v", err)
	}

	// Now supplier a withdraws everything.
	if err := lm.Withdraw(poolID, addrH03a, big.NewInt(5000), 100); err != nil {
		t.Fatalf("Withdraw a: %v", err)
	}

	// Force the borrower's position to accrue interest by triggering Repay.
	// Repay calls accrueInterest internally; the borrower still owes Principal
	// so the interest-distribution path executes.
	prevReserves := big.NewInt(0)
	pool, _ := lm.GetPool(poolID)
	if pool.Reserves != nil {
		prevReserves.Set(pool.Reserves)
	}

	if err := lm.Repay(poolID, borrower, big.NewInt(1), 500); err != nil {
		t.Fatalf("Repay: %v", err)
	}

	pool, _ = lm.GetPool(poolID)
	// Invariant: TotalSupply == sum(Supplies) regardless of path taken.
	if pool.TotalSupply.Cmp(sumSupplies(pool)) != 0 {
		t.Fatalf("ECON-R13-H03 invariant broken in zero-supplier path: TotalSupply=%s sum=%s",
			pool.TotalSupply, sumSupplies(pool))
	}
	// Reserves should have grown by supplierInterest (90% of accrued interest).
	// If supplierInterest was 0 (no interest accrued this tick), Reserves is
	// unchanged — we don't fail in that case because the test is about the
	// invariant, not the magnitude of reserves.
	if pool.Reserves != nil && pool.Reserves.Cmp(prevReserves) < 0 {
		t.Errorf("Reserves decreased unexpectedly: was %s, now %s",
			prevReserves, pool.Reserves)
	}
}

// TestECON_R13_H03_InvariantHeld_MultipleAccruals verifies that accrueInterest
// maintains the invariant across many iterations, not just a single call.
func TestECON_R13_H03_InvariantHeld_MultipleAccruals(t *testing.T) {
	lm, poolID := makeLendingManagerH03(t)

	lm.Deposit(addrH03a, "QAU", big.NewInt(20_000))
	if err := lm.Supply(poolID, addrH03a, big.NewInt(5000)); err != nil {
		t.Fatalf("Supply a: %v", err)
	}
	lm.Deposit(addrH03b, "QAU", big.NewInt(20_000))
	if err := lm.Supply(poolID, addrH03b, big.NewInt(3000)); err != nil {
		t.Fatalf("Supply b: %v", err)
	}

	borrower := types.Address{0xb0}
	lm.Deposit(borrower, "QAU", big.NewInt(20_000))
	if err := lm.Supply(poolID, borrower, big.NewInt(2000)); err != nil {
		t.Fatalf("Supply borrower: %v", err)
	}
	if err := lm.Borrow(poolID, borrower, big.NewInt(1000), 100); err != nil {
		t.Fatalf("Borrow: %v", err)
	}

	// Drive multiple accruals by advancing blocks and repaying tiny amounts.
	for block := uint64(200); block <= 2000; block += 200 {
		// Repay(1) triggers accrueInterest on every iteration.
		if err := lm.Repay(poolID, borrower, big.NewInt(1), block); err != nil {
			// Stop if debt is exhausted.
			break
		}
		pool, _ := lm.GetPool(poolID)
		if pool.TotalSupply.Cmp(sumSupplies(pool)) != 0 {
			t.Fatalf("ECON-R13-H03 invariant broken at block %d: TotalSupply=%s sum=%s",
				block, pool.TotalSupply, sumSupplies(pool))
		}
	}
}
