// Quantaureum Node source, version 1.0.0.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestECON_R12_001_Swap_RejectsInsufficientUserBalance verifies that Swap
// now rejects the call when the user has not deposited enough tokenIn.
// This is the core R11-leftover fix: previously Swap did not check any user
// balance at all and just updated pool reserves.
func TestECON_R12_001_Swap_RejectsInsufficientUserBalance(t *testing.T) {
	lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
	user := types.Address{0xAA}

	// Create pool with initial reserves (simulating LPs already provided liquidity).
	pool, err := lpm.CreatePool("QAU", "USDC", 30)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}
	pool.ReserveA = big.NewInt(1_000_000)
	pool.ReserveB = big.NewInt(2_000_000)

	// User has NOT deposited anything.
	_, err = lpm.Swap("QAU-USDC", user, "QAU", big.NewInt(100), big.NewInt(0))
	if err == nil {
		t.Errorf("expected error when user has no balance, got nil — Swap must check user balance (ECON-R12-001)")
	}
}

// TestECON_R12_001_Swap_MovesUserFunds verifies that Swap actually debits
// amountIn from the user's tokenIn balance and credits amountOut to the
// user's tokenOut balance. This is the critical fix.
func TestECON_R12_001_Swap_MovesUserFunds(t *testing.T) {
	lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
	user := types.Address{0xBB}

	pool, err := lpm.CreatePool("QAU", "USDC", 30) // 0.3% fee
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}
	pool.ReserveA = big.NewInt(1_000_000)
	pool.ReserveB = big.NewInt(2_000_000)

	// Deposit 1000 QAU for the user.
	if _, err := lpm.Deposit(user, "QAU", big.NewInt(1000)); err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}

	// Swap 100 QAU -> ? USDC
	amountIn := big.NewInt(100)
	balBefore := lpm.GetUserTokenBalance(user, "QAU")
	amountOut, err := lpm.Swap("QAU-USDC", user, "QAU", amountIn, big.NewInt(0))
	if err != nil {
		t.Fatalf("Swap failed: %v", err)
	}
	if amountOut.Sign() <= 0 {
		t.Fatalf("expected positive amountOut, got %s", amountOut.String())
	}

	// Verify user's QAU balance was debited by amountIn.
	balAfter := lpm.GetUserTokenBalance(user, "QAU")
	wantDelta := new(big.Int).Neg(amountIn)
	gotDelta := new(big.Int).Sub(balAfter, balBefore)
	if gotDelta.Cmp(wantDelta) != 0 {
		t.Errorf("user QAU balance delta: want %s, got %s (before=%s after=%s)",
			wantDelta.String(), gotDelta.String(), balBefore.String(), balAfter.String())
	}

	// Verify user's USDC balance was credited by amountOut.
	usdcBal := lpm.GetUserTokenBalance(user, "USDC")
	if usdcBal.Cmp(amountOut) != 0 {
		t.Errorf("user USDC balance: want %s, got %s", amountOut.String(), usdcBal.String())
	}
}

// TestECON_R12_001_Swap_AccruesFee verifies that the fee portion of amountIn
// is accrued into pool.AccumulatedFeeA/B (not into the reserves).
func TestECON_R12_001_Swap_AccruesFee(t *testing.T) {
	lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
	user := types.Address{0xCC}

	pool, err := lpm.CreatePool("QAU", "USDC", 30) // 0.3% fee = 30 bps
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}
	pool.ReserveA = big.NewInt(1_000_000)
	pool.ReserveB = big.NewInt(2_000_000)

	amountIn := big.NewInt(1000)
	if _, err := lpm.Deposit(user, "QAU", amountIn); err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}

	expectedFee := new(big.Int).Mul(amountIn, big.NewInt(30))
	expectedFee.Div(expectedFee, big.NewInt(10000)) // 30 / 10000 = 0.3% = 3

	if _, err := lpm.Swap("QAU-USDC", user, "QAU", amountIn, big.NewInt(0)); err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	if pool.AccumulatedFeeA.Cmp(expectedFee) != 0 {
		t.Errorf("AccumulatedFeeA: want %s, got %s", expectedFee.String(), pool.AccumulatedFeeA.String())
	}
}

// TestECON_R12_001_Swap_PerUserReentrancyProtection verifies that a reentrant
// Swap call from the same user is rejected. The first Swap holds the
// activeUsers lock for the duration of the call.
func TestECON_R12_001_Swap_PerUserReentrancyProtection(t *testing.T) {
	lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
	user := types.Address{0xDD}

	pool, err := lpm.CreatePool("QAU", "USDC", 30)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}
	pool.ReserveA = big.NewInt(1_000_000)
	pool.ReserveB = big.NewInt(2_000_000)
	if _, err := lpm.Deposit(user, "QAU", big.NewInt(1000)); err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}

	// Simulate re-entry by pre-marking the user as active.
	lpm.activeUsers[user] = true
	defer delete(lpm.activeUsers, user)

	_, err = lpm.Swap("QAU-USDC", user, "QAU", big.NewInt(100), big.NewInt(0))
	if err == nil {
		t.Errorf("expected reentrant call to be rejected, got nil")
	}
}

// TestECON_R12_001_Deposit_And_Withdraw verifies the new balance primitives.
func TestECON_R12_001_Deposit_And_Withdraw(t *testing.T) {
	lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
	user := types.Address{0xEE}

	// Initial balance is 0.
	if bal := lpm.GetUserTokenBalance(user, "QAU"); bal.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("expected 0 balance, got %s", bal.String())
	}

	// Deposit 500.
	bal, err := lpm.Deposit(user, "QAU", big.NewInt(500))
	if err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}
	if bal.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("after deposit: want 500, got %s", bal.String())
	}

	// Withdraw 200.
	bal, err = lpm.Withdraw(user, "QAU", big.NewInt(200))
	if err != nil {
		t.Fatalf("Withdraw failed: %v", err)
	}
	if bal.Cmp(big.NewInt(300)) != 0 {
		t.Errorf("after withdraw: want 300, got %s", bal.String())
	}

	// Overdraw should fail.
	_, err = lpm.Withdraw(user, "QAU", big.NewInt(1000))
	if err == nil {
		t.Errorf("expected error on overdraw, got nil")
	}
}

// TestECON_R12_001_Swap_Atomicity_NoPartialMutationOnFailure verifies that
// when a swap is rejected (insufficient user balance), pool reserves and
// user balance are NOT mutated.
func TestECON_R12_001_Swap_Atomicity_NoPartialMutationOnFailure(t *testing.T) {
	lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
	user := types.Address{0xFF}

	pool, err := lpm.CreatePool("QAU", "USDC", 30)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}
	pool.ReserveA = big.NewInt(1_000_000)
	pool.ReserveB = big.NewInt(2_000_000)

	reserveABefore := new(big.Int).Set(pool.ReserveA)
	reserveBBefore := new(big.Int).Set(pool.ReserveB)

	// User has 50 QAU but tries to swap 100 — should fail with no state change.
	if _, err := lpm.Deposit(user, "QAU", big.NewInt(50)); err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}
	balBefore := lpm.GetUserTokenBalance(user, "QAU")

	_, err = lpm.Swap("QAU-USDC", user, "QAU", big.NewInt(100), big.NewInt(0))
	if err == nil {
		t.Fatal("expected error for insufficient balance")
	}

	// Pool reserves unchanged.
	if pool.ReserveA.Cmp(reserveABefore) != 0 {
		t.Errorf("ReserveA mutated on failure: want %s, got %s", reserveABefore.String(), pool.ReserveA.String())
	}
	if pool.ReserveB.Cmp(reserveBBefore) != 0 {
		t.Errorf("ReserveB mutated on failure: want %s, got %s", reserveBBefore.String(), pool.ReserveB.String())
	}
	// User balance unchanged.
	if balAfter := lpm.GetUserTokenBalance(user, "QAU"); balAfter.Cmp(balBefore) != 0 {
		t.Errorf("user balance mutated on failure: want %s, got %s", balBefore.String(), balAfter.String())
	}
}
