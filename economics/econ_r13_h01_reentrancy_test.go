// Quantaureum Node source, version 1.0.0.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ---------------------------------------------------------------------------
// ECON-R13-H01: Deposit/Withdraw per-user reentrancy protection
// ---------------------------------------------------------------------------
//
// Audit finding (R13 High): LiquidityPoolManager.Deposit/Withdraw and
// LendingManager.Deposit directly operate on userTokenBalances but lacked
// the activeUsers/activeBorrowers reentrancy guard that Swap/AddLiquidity/
// Supply/Withdraw/Borrow/Repay/Liquidate already enforce. A malicious token
// with transfer hooks (or a reentrant precompile) could re-enter Deposit/
// Withdraw mid-execution to double-credit or double-debit the same balance.
//
// Fix: added the same `if activeUsers[user] { reject }` + set + defer-delete
// pattern that Swap/AddLiquidity use. These tests lock in the new guard.

// TestECON_R13_H01_LPM_Deposit_RejectsReentrantCall verifies that when the
// user is already marked active (simulating a token-hook callback mid-
// execution), LiquidityPoolManager.Deposit rejects the reentrant call.
func TestECON_R13_H01_LPM_Deposit_RejectsReentrantCall(t *testing.T) {
	lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
	user := types.Address{0xE0}

	// Simulate a reentrant call by pre-marking the user as active.
	lpm.activeUsers[user] = true

	_, err := lpm.Deposit(user, "QAU", big.NewInt(100))
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify balance was NOT credited (state unchanged on rejection).
	if bal := lpm.GetUserTokenBalance(user, "QAU"); bal.Sign() != 0 {
		t.Errorf("Deposit credited balance on reentrant rejection: got %s, expected 0", bal.String())
	}
}

// TestECON_R13_H01_LPM_Withdraw_RejectsReentrantCall verifies that when the
// user is already marked active, LiquidityPoolManager.Withdraw rejects the
// reentrant call. The user must have a non-zero balance first so that the
// only reason for rejection is the reentrancy guard (not "insufficient
// balance").
func TestECON_R13_H01_LPM_Withdraw_RejectsReentrantCall(t *testing.T) {
	lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
	user := types.Address{0xE1}

	// Give the user a balance to withdraw from (normal Deposit, not reentrant).
	if _, err := lpm.Deposit(user, "QAU", big.NewInt(500)); err != nil {
		t.Fatalf("setup Deposit failed: %v", err)
	}
	balBefore := lpm.GetUserTokenBalance(user, "QAU")

	// Simulate reentrant call.
	lpm.activeUsers[user] = true

	_, err := lpm.Withdraw(user, "QAU", big.NewInt(100))
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify balance was NOT debited (state unchanged on rejection).
	if bal := lpm.GetUserTokenBalance(user, "QAU"); bal.Cmp(balBefore) != 0 {
		t.Errorf("Withdraw debited balance on reentrant rejection: before=%s after=%s",
			balBefore.String(), bal.String())
	}
}

// TestECON_R13_H01_LM_Deposit_RejectsReentrantCall verifies that when the
// user is already marked active (simulating a token-hook callback mid-
// execution), LendingManager.Deposit rejects the reentrant call.
func TestECON_R13_H01_LM_Deposit_RejectsReentrantCall(t *testing.T) {
	oracle := NewAggregatedPriceOracle(nil)
	lm := NewLendingManager(50, 75, 10, oracle)
	user := types.Address{0xE2}

	// Simulate a reentrant call by pre-marking the user as active.
	lm.activeBorrowers[user] = true

	_, err := lm.Deposit(user, "QAU", big.NewInt(100))
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify balance was NOT credited (state unchanged on rejection).
	if bal := lm.GetUserTokenBalance(user, "QAU"); bal.Sign() != 0 {
		t.Errorf("LendingManager.Deposit credited balance on reentrant rejection: got %s, expected 0", bal.String())
	}
}

// TestECON_R13_H01_NormalDepositWithdrawUnaffected verifies that the
// reentrancy guard does not block normal (non-reentrant) Deposit/Withdraw
// sequences. This is a regression guard.
func TestECON_R13_H01_NormalDepositWithdrawUnaffected(t *testing.T) {
	t.Run("LPM", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
		user := types.Address{0xE3}

		// Normal Deposit.
		bal, err := lpm.Deposit(user, "QAU", big.NewInt(500))
		if err != nil {
			t.Fatalf("Deposit failed: %v", err)
		}
		if bal.Cmp(big.NewInt(500)) != 0 {
			t.Errorf("expected balance 500 after deposit, got %s", bal.String())
		}

		// Normal Withdraw (no reentrancy in flight).
		bal, err = lpm.Withdraw(user, "QAU", big.NewInt(200))
		if err != nil {
			t.Fatalf("Withdraw failed: %v", err)
		}
		if bal.Cmp(big.NewInt(300)) != 0 {
			t.Errorf("expected balance 300 after withdraw, got %s", bal.String())
		}

		// activeUsers must be clean after each op returns (defer-delete).
		if lpm.activeUsers[user] {
			t.Errorf("activeUsers not cleared after Deposit/Withdraw returned")
		}
	})

	t.Run("LendingManager", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		lm := NewLendingManager(50, 75, 10, oracle)
		user := types.Address{0xE4}

		// Normal Deposit.
		bal, err := lm.Deposit(user, "QAU", big.NewInt(500))
		if err != nil {
			t.Fatalf("Deposit failed: %v", err)
		}
		if bal.Cmp(big.NewInt(500)) != 0 {
			t.Errorf("expected balance 500 after deposit, got %s", bal.String())
		}

		// activeBorrowers must be clean after Deposit returns.
		if lm.activeBorrowers[user] {
			t.Errorf("activeBorrowers not cleared after LendingManager.Deposit returned")
		}
	})
}

// TestECON_R13_H01_SequentialDepositWithdrawAllowed verifies that two
// sequential (non-overlapping) calls by the same user are allowed — only
// truly reentrant (in-flight) calls are rejected. This guards against an
// over-aggressive fix that might permanently blacklist a user after one
// Deposit.
func TestECON_R13_H01_SequentialDepositWithdrawAllowed(t *testing.T) {
	lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
	user := types.Address{0xE5}

	// First Deposit.
	if _, err := lpm.Deposit(user, "QAU", big.NewInt(100)); err != nil {
		t.Fatalf("first Deposit failed: %v", err)
	}
	// Second Deposit (sequential, not reentrant).
	if _, err := lpm.Deposit(user, "QAU", big.NewInt(100)); err != nil {
		t.Fatalf("second Deposit failed: %v", err)
	}
	// Withdraw.
	if _, err := lpm.Withdraw(user, "QAU", big.NewInt(50)); err != nil {
		t.Fatalf("Withdraw failed: %v", err)
	}
	// Final balance should be 100 + 100 - 50 = 150.
	if bal := lpm.GetUserTokenBalance(user, "QAU"); bal.Cmp(big.NewInt(150)) != 0 {
		t.Errorf("expected final balance 150, got %s", bal.String())
	}
}
