// Quantaureum Node source, version 1.0.0.
// ECON-R13-CRIT-002 regression tests (2026-07-21).
// Lending Supply/Withdraw/Borrow/Repay must actually move real user funds.
package economics

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// makeLendingManagerR13 creates a LendingManager with a working price oracle.
func makeLendingManagerR13(t *testing.T) (*LendingManager, string) {
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

// addr2R13 is a stable test address used across CRIT-002 subtests.
var addr2R13 = types.Address{0x10}

// TestECON_R13_CRIT_002_Supply_DebitsUserBalance verifies that Supply
// actually debits the supplied amount from the user's balance.
func TestECON_R13_CRIT_002_Supply_DebitsUserBalance(t *testing.T) {
	lm, poolID := makeLendingManagerR13(t)

	// Deposit 10000 QAU, then Supply 1000.
	lm.Deposit(addr2R13, "QAU", big.NewInt(10_000))
	if err := lm.Supply(poolID, addr2R13, big.NewInt(1000)); err != nil {
		t.Fatalf("Supply failed: %v", err)
	}

	// User balance should be 9000 (10000 - 1000).
	bal := lm.GetUserTokenBalance(addr2R13, "QAU")
	if bal.Cmp(big.NewInt(9000)) != 0 {
		t.Errorf("expected QAU balance 9000 after Supply, got %s", bal)
	}

	// Pool.TotalSupply should be 1000.
	pool, _ := lm.GetPool(poolID)
	if pool.TotalSupply.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("expected TotalSupply=1000, got %s", pool.TotalSupply)
	}
}

// TestECON_R13_CRIT_002_Supply_RejectsInsufficientBalance verifies that
// Supply rejects when the user has insufficient balance.
func TestECON_R13_CRIT_002_Supply_RejectsInsufficientBalance(t *testing.T) {
	lm, poolID := makeLendingManagerR13(t)

	// No Deposit — user has 0 balance.
	err := lm.Supply(poolID, addr2R13, big.NewInt(1000))
	if err == nil {
		t.Fatal("expected error for zero-balance Supply")
	}
	if !strings.Contains(err.Error(), "insufficient user balance") {
		t.Errorf("expected 'insufficient user balance', got: %v", err)
	}

	// Pool state must remain unmutated.
	pool, _ := lm.GetPool(poolID)
	if pool.TotalSupply.Sign() != 0 {
		t.Errorf("TotalSupply mutated after rejected Supply: %s",
			pool.TotalSupply)
	}
}

// TestECON_R13_CRIT_002_Withdraw_CreditsUserBalance verifies that Withdraw
// actually credits the withdrawn amount to the user's balance.
func TestECON_R13_CRIT_002_Withdraw_CreditsUserBalance(t *testing.T) {
	lm, poolID := makeLendingManagerR13(t)

	// Deposit 10000 QAU, Supply 10000, then Withdraw 3000.
	lm.Deposit(addr2R13, "QAU", big.NewInt(10_000))
	if err := lm.Supply(poolID, addr2R13, big.NewInt(10_000)); err != nil {
		t.Fatalf("Supply failed: %v", err)
	}
	// Balance after Supply = 0 (deposited 10000, supplied 10000).
	balBefore := lm.GetUserTokenBalance(addr2R13, "QAU")
	if balBefore.Sign() != 0 {
		t.Fatalf("expected 0 balance after Supply, got %s", balBefore)
	}

	if err := lm.Withdraw(poolID, addr2R13, big.NewInt(3000), 1); err != nil {
		t.Fatalf("Withdraw failed: %v", err)
	}
	// Balance after Withdraw = 3000.
	balAfter := lm.GetUserTokenBalance(addr2R13, "QAU")
	if balAfter.Cmp(big.NewInt(3000)) != 0 {
		t.Errorf("expected QAU balance 3000 after Withdraw, got %s", balAfter)
	}

	// Pool.TotalSupply should be 7000.
	pool, _ := lm.GetPool(poolID)
	if pool.TotalSupply.Cmp(big.NewInt(7000)) != 0 {
		t.Errorf("expected TotalSupply=7000, got %s", pool.TotalSupply)
	}
}

// TestECON_R13_CRIT_002_Borrow_CreditsUserBalance verifies that Borrow
// actually credits the borrowed principal to the user's balance.
func TestECON_R13_CRIT_002_Borrow_CreditsUserBalance(t *testing.T) {
	lm, poolID := makeLendingManagerR13(t)

	// addr2 deposits 1_000_000 QAU (so they can Supply as collateral).
	lm.Deposit(addr2R13, "QAU", big.NewInt(1_000_000))
	if err := lm.Supply(poolID, addr2R13, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("Supply failed: %v", err)
	}
	// Balance after Supply = 0.
	balBefore := lm.GetUserTokenBalance(addr2R13, "QAU")
	if balBefore.Sign() != 0 {
		t.Fatalf("expected 0 balance after Supply, got %s", balBefore)
	}

	// Borrow 100000 QAU (well within collateral limits).
	if err := lm.Borrow(poolID, addr2R13, big.NewInt(100_000), 1); err != nil {
		t.Fatalf("Borrow failed: %v", err)
	}
	// Balance after Borrow = 100000.
	balAfter := lm.GetUserTokenBalance(addr2R13, "QAU")
	if balAfter.Cmp(big.NewInt(100_000)) != 0 {
		t.Errorf("expected QAU balance 100000 after Borrow, got %s", balAfter)
	}

	// Pool.TotalBorrowed should be 100000.
	pool, _ := lm.GetPool(poolID)
	if pool.TotalBorrowed.Cmp(big.NewInt(100_000)) != 0 {
		t.Errorf("expected TotalBorrowed=100000, got %s", pool.TotalBorrowed)
	}
}

// TestECON_R13_CRIT_002_Repay_DebitsUserBalance verifies that Repay actually
// debits the repaid amount from the user's balance.
func TestECON_R13_CRIT_002_Repay_DebitsUserBalance(t *testing.T) {
	lm, poolID := makeLendingManagerR13(t)

	// Setup: deposit, supply collateral, borrow.
	lm.Deposit(addr2R13, "QAU", big.NewInt(1_000_000))
	lm.Supply(poolID, addr2R13, big.NewInt(1_000_000))
	if err := lm.Borrow(poolID, addr2R13, big.NewInt(100_000), 1); err != nil {
		t.Fatalf("Borrow failed: %v", err)
	}
	// Balance after Borrow = 100000.
	balBefore := lm.GetUserTokenBalance(addr2R13, "QAU")
	if balBefore.Cmp(big.NewInt(100_000)) != 0 {
		t.Fatalf("expected 100000 balance after Borrow, got %s", balBefore)
	}

	// Repay 50000 QAU. Repay at block 1 (no interest accrual).
	if err := lm.Repay(poolID, addr2R13, big.NewInt(50_000), 1); err != nil {
		t.Fatalf("Repay failed: %v", err)
	}
	// Balance after Repay = 100000 - 50000 = 50000.
	balAfter := lm.GetUserTokenBalance(addr2R13, "QAU")
	if balAfter.Cmp(big.NewInt(50_000)) != 0 {
		t.Errorf("expected QAU balance 50000 after Repay, got %s", balAfter)
	}

	// Pool.TotalBorrowed should be 50000.
	pool, _ := lm.GetPool(poolID)
	if pool.TotalBorrowed.Cmp(big.NewInt(50_000)) != 0 {
		t.Errorf("expected TotalBorrowed=50000, got %s", pool.TotalBorrowed)
	}
}

// TestECON_R13_CRIT_002_Repay_RejectsInsufficientBalance verifies that Repay
// rejects when the user has insufficient balance to repay.
func TestECON_R13_CRIT_002_Repay_RejectsInsufficientBalance(t *testing.T) {
	lm, poolID := makeLendingManagerR13(t)

	// Setup: deposit, supply, borrow.
	lm.Deposit(addr2R13, "QAU", big.NewInt(1_000_000))
	lm.Supply(poolID, addr2R13, big.NewInt(1_000_000))
	lm.Borrow(poolID, addr2R13, big.NewInt(100_000), 1)
	// Balance = 100000.

	// Try to Repay 200000 (more than balance).
	err := lm.Repay(poolID, addr2R13, big.NewInt(200_000), 1)
	if err == nil {
		t.Fatal("expected error for Repay exceeding balance")
	}
	if !strings.Contains(err.Error(), "insufficient user balance") {
		t.Errorf("expected 'insufficient user balance', got: %v", err)
	}

	// Verify pool state not mutated.
	pool, _ := lm.GetPool(poolID)
	if pool.TotalBorrowed.Cmp(big.NewInt(100_000)) != 0 {
		t.Errorf("TotalBorrowed mutated after rejected Repay: %s",
			pool.TotalBorrowed)
	}
}

// TestECON_R13_CRIT_002_Liquidate_MovesFundsToLiquidator verifies that
// Liquidate actually: (1) debits the liquidator for the debt covered, and
// (2) credits the seized collateral to the liquidator.
func TestECON_R13_CRIT_002_Liquidate_MovesFundsToLiquidator(t *testing.T) {
	oracle := NewAggregatedPriceOracle(nil)
	// Two assets with price 1 each: QAU (collateral) and USDC (debt).
	// Keeping prices equal avoids any cross-asset valuation confusion.
	oracle.WatchAsset("QAU", big.NewInt(1))
	oracle.WatchAsset("USDC", big.NewInt(1))
	oracle.RegisterSource("src1", 100, func(asset string) (*big.Int, error) {
		return big.NewInt(1), nil
	})
	lm := NewLendingManager(75, 85, 5, oracle)

	// Pool A: QAU collateral. Use percentages (75%, 85%) not bps.
	poolA, err := lm.CreatePool("QAU", 75, 85)
	if err != nil {
		t.Fatalf("CreatePool QAU failed: %v", err)
	}
	// Pool B: USDC debt.
	poolB, err := lm.CreatePool("USDC", 75, 85)
	if err != nil {
		t.Fatalf("CreatePool USDC failed: %v", err)
	}

	// Borrower deposits 1_000_000 QAU and supplies as collateral.
	// collateral @ 75% = 1_000_000 * 1 * 0.75 = 750_000 USD
	borrower := types.Address{0xB0, 0x0B}
	lm.Deposit(borrower, "QAU", big.NewInt(1_000_000))
	if err := lm.Supply(poolA.PoolID, borrower, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("borrower Supply QAU failed: %v", err)
	}

	// Liquidator deposits 1_500_000 USDC and supplies 750_000 to poolB so
	// the pool has enough liquidity. The remaining 750_000 stays as free
	// balance to cover the debt during liquidation.
	liquidator := types.Address{0x11, 0xD0}
	lm.Deposit(liquidator, "USDC", big.NewInt(1_500_000))
	if err := lm.Supply(poolB.PoolID, liquidator, big.NewInt(750_000)); err != nil {
		t.Fatalf("liquidator Supply USDC failed: %v", err)
	}

	// Borrower borrows 700_000 USDC (< 750_000 collateral cap).
	if err := lm.Borrow(poolB.PoolID, borrower, big.NewInt(700_000), 1); err != nil {
		t.Fatalf("Borrow failed: %v", err)
	}
	borrowerUSDC := lm.GetUserTokenBalance(borrower, "USDC")
	if borrowerUSDC.Cmp(big.NewInt(700_000)) != 0 {
		t.Fatalf("expected borrower USDC=700000, got %s", borrowerUSDC)
	}

	// Liquidator's free USDC balance (after supplying 750_000) = 750_000.
	liquidatorUSDCBefore := lm.GetUserTokenBalance(liquidator, "USDC")
	if liquidatorUSDCBefore.Cmp(big.NewInt(750_000)) != 0 {
		t.Fatalf("expected liquidator free USDC=750000, got %s", liquidatorUSDCBefore)
	}
	liquidatorQAUBefore := lm.GetUserTokenBalance(liquidator, "QAU")
	if liquidatorQAUBefore.Sign() != 0 {
		t.Fatalf("expected liquidator QAU=0 before liquidation, got %s", liquidatorQAUBefore)
	}

	// Make the position undercollateralized by reducing the borrower's
	// QAU supply in poolA. At price 1, collateral @ 85% must be < 700_000
	// debt, i.e. supply < 823_530. We reduce to 800_000 so collateral
	// = 800_000 * 0.85 = 680_000 < 700_000 → liquidatable.
	//
	// We bypass the oracle price-drop path (which would trip the circuit
	// breaker on > 30% deviation) and instead trim the supply directly.
	// This isolates the test to Liquidate's fund-movement logic, not oracle
	// behavior.
	lm.mu.Lock()
	lm.pools[poolA.PoolID].Supplies[borrower] = big.NewInt(800_000)
	// Recompute TotalSupply to keep utilization consistent.
	supplySum := big.NewInt(0)
	for _, s := range lm.pools[poolA.PoolID].Supplies {
		if s != nil {
			supplySum.Add(supplySum, s)
		}
	}
	lm.pools[poolA.PoolID].TotalSupply = supplySum
	lm.mu.Unlock()

	// Liquidate: liquidator requests to cover 500_000 USDC of debt.
	// R37 P2-ECON-03: the close-factor cap limits a single liquidation to
	// 50% of total debt (700_000), so only 350_000 is actually covered.
	if err := lm.Liquidate(poolB.PoolID, liquidator, borrower, big.NewInt(500_000), 2); err != nil {
		t.Fatalf("Liquidate failed: %v", err)
	}

	// Liquidator's USDC balance should decrease by the capped 350_000.
	liquidatorUSDCAfter := lm.GetUserTokenBalance(liquidator, "USDC")
	deltaUSDC := new(big.Int).Sub(liquidatorUSDCBefore, liquidatorUSDCAfter)
	if deltaUSDC.Cmp(big.NewInt(350_000)) != 0 {
		t.Errorf("expected liquidator to pay 350000 USDC (close-factor cap), delta=%s (before=%s after=%s)",
			deltaUSDC, liquidatorUSDCBefore, liquidatorUSDCAfter)
	}

	// Liquidator should have received QAU (seized collateral).
	liquidatorQAUAfter := lm.GetUserTokenBalance(liquidator, "QAU")
	if liquidatorQAUAfter.Sign() <= 0 {
		t.Errorf("expected liquidator to receive QAU collateral, got %s", liquidatorQAUAfter)
	}
}
