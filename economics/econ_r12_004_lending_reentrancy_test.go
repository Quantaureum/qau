// Quantaureum Node source, version 1.0.0.
// Package economics — ECON-R12-004 tests.
//
// Verifies the fix for the audit finding:
//
//	LendingManager.Supply/Withdraw lacked per-user reentrancy protection (Borrow/Repay had it)
//
// Before the fix, Borrow/Repay/Liquidate already had a per-user reentrancy
// guard via activeBorrowers (ECON-R11-003), but Supply and Withdraw did NOT.
// A malicious ERC777-style token hook or flash-loan callback firing during
// the state-mutation window could re-enter Supply (double-counting a single
// deposit) or Withdraw (double-spending pool liquidity before the first
// call's balance updates land).
//
// After the fix, all four state-mutating entry points (Supply, Withdraw,
// Borrow, Repay) uniformly reject reentrant calls for the same user.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// newR12_004LendingManager creates a LendingManager with an AggregatedPriceOracle
// watching QAU and a single QAU pool seeded with sufficient supply.
// ECON-R13-CRIT-002: also deposits sufficient QAU balance for the test user
// so Supply/Borrow/Repay can debit real balances.
func newR12_004LendingManager(t *testing.T) (*LendingManager, string) {
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

// r12_004DepositQAU is a convenience helper that deposits QAU into the user's
// lending balance sheet. Required because Supply/Repay now debit real balances
// (ECON-R13-CRIT-002).
func r12_004DepositQAU(t *testing.T, lm *LendingManager, user types.Address, amount *big.Int) {
	t.Helper()
	if _, err := lm.Deposit(user, "QAU", amount); err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}
}

// TestECON_R12_004_Supply_RejectsReentrantCall verifies that when the user is
// already marked active (simulating a callback mid-Supply), Supply rejects
// the reentrant call instead of double-counting the deposit.
func TestECON_R12_004_Supply_RejectsReentrantCall(t *testing.T) {
	lm, poolID := newR12_004LendingManager(t)
	user := types.Address{0x42}

	// ECON-R13-CRIT-002: Supply now debits real user balance.
	r12_004DepositQAU(t, lm, user, big.NewInt(1000))

	// Seed an initial supply so we can compare TotalSupply before/after.
	if err := lm.Supply(poolID, user, big.NewInt(1000)); err != nil {
		t.Fatalf("seed Supply failed: %v", err)
	}

	pool, _ := lm.GetPool(poolID)
	totalSupplyBefore := new(big.Int).Set(pool.TotalSupply)
	userSupplyBefore := new(big.Int).Set(pool.Supplies[user])

	// Simulate a reentrant call by pre-marking the user as active.
	lm.activeBorrowers[user] = true

	err := lm.Supply(poolID, user, big.NewInt(500))
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify state was NOT mutated on rejection.
	if pool.TotalSupply.Cmp(totalSupplyBefore) != 0 {
		t.Errorf("TotalSupply changed on reentrant rejection: before=%s after=%s",
			totalSupplyBefore.String(), pool.TotalSupply.String())
	}
	if pool.Supplies[user].Cmp(userSupplyBefore) != 0 {
		t.Errorf("user supply changed on reentrant rejection: before=%s after=%s",
			userSupplyBefore.String(), pool.Supplies[user].String())
	}
}

// TestECON_R12_004_Withdraw_RejectsReentrantCall verifies that when the user
// is already marked active (simulating a callback mid-Withdraw), Withdraw
// rejects the reentrant call instead of double-spending pool liquidity.
func TestECON_R12_004_Withdraw_RejectsReentrantCall(t *testing.T) {
	lm, poolID := newR12_004LendingManager(t)
	user := types.Address{0x42}

	// ECON-R13-CRIT-002: Supply now debits real user balance.
	r12_004DepositQAU(t, lm, user, big.NewInt(10000))

	// Seed supply large enough to withdraw multiple times.
	if err := lm.Supply(poolID, user, big.NewInt(10000)); err != nil {
		t.Fatalf("seed Supply failed: %v", err)
	}

	pool, _ := lm.GetPool(poolID)
	totalSupplyBefore := new(big.Int).Set(pool.TotalSupply)
	userSupplyBefore := new(big.Int).Set(pool.Supplies[user])

	// Simulate a reentrant call by pre-marking the user as active.
	lm.activeBorrowers[user] = true

	err := lm.Withdraw(poolID, user, big.NewInt(500), 1)
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify state was NOT mutated on rejection.
	if pool.TotalSupply.Cmp(totalSupplyBefore) != 0 {
		t.Errorf("TotalSupply changed on reentrant rejection: before=%s after=%s",
			totalSupplyBefore.String(), pool.TotalSupply.String())
	}
	if pool.Supplies[user].Cmp(userSupplyBefore) != 0 {
		t.Errorf("user supply changed on reentrant rejection: before=%s after=%s",
			userSupplyBefore.String(), pool.Supplies[user].String())
	}
}

// TestECON_R12_004_Supply_AllowsConsecutiveCalls verifies that the guard is
// cleared after a successful Supply, so a subsequent Supply from the same
// user succeeds (i.e. the fix does not break the normal use case).
func TestECON_R12_004_Supply_AllowsConsecutiveCalls(t *testing.T) {
	lm, poolID := newR12_004LendingManager(t)
	user := types.Address{0x55}

	// ECON-R13-CRIT-002: Supply now debits real user balance.
	r12_004DepositQAU(t, lm, user, big.NewInt(1000))

	if err := lm.Supply(poolID, user, big.NewInt(500)); err != nil {
		t.Fatalf("first Supply failed: %v", err)
	}
	if err := lm.Supply(poolID, user, big.NewInt(500)); err != nil {
		t.Fatalf("second Supply failed (guard should have been cleared): %v", err)
	}

	pool, _ := lm.GetPool(poolID)
	if pool.Supplies[user].Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("expected user supply = 1000, got %s", pool.Supplies[user].String())
	}

	// Verify the guard was cleared.
	if lm.activeBorrowers[user] {
		t.Error("activeBorrowers[user] should be false after Supply completed")
	}
}

// TestECON_R12_004_Withdraw_AllowsConsecutiveCalls verifies that the guard
// is cleared after a successful Withdraw, so a subsequent Withdraw from the
// same user succeeds.
func TestECON_R12_004_Withdraw_AllowsConsecutiveCalls(t *testing.T) {
	lm, poolID := newR12_004LendingManager(t)
	user := types.Address{0x56}

	// ECON-R13-CRIT-002: Supply now debits real user balance.
	r12_004DepositQAU(t, lm, user, big.NewInt(1000))

	if err := lm.Supply(poolID, user, big.NewInt(1000)); err != nil {
		t.Fatalf("seed Supply failed: %v", err)
	}
	if err := lm.Withdraw(poolID, user, big.NewInt(300), 1); err != nil {
		t.Fatalf("first Withdraw failed: %v", err)
	}
	if err := lm.Withdraw(poolID, user, big.NewInt(300), 1); err != nil {
		t.Fatalf("second Withdraw failed (guard should have been cleared): %v", err)
	}

	pool, _ := lm.GetPool(poolID)
	if pool.Supplies[user].Cmp(big.NewInt(400)) != 0 {
		t.Errorf("expected user supply = 400 after two 300 withdrawals, got %s",
			pool.Supplies[user].String())
	}

	// Verify the guard was cleared.
	if lm.activeBorrowers[user] {
		t.Error("activeBorrowers[user] should be false after Withdraw completed")
	}
}

// TestECON_R12_004_CrossMethod_ReentryBlocked verifies that a reentrant call
// from one method (e.g. Supply) to another (e.g. Borrow) for the SAME user
// is also blocked. The activeBorrowers guard is shared across all four
// entry points, so any combination of reentrant calls must be rejected.
func TestECON_R12_004_CrossMethod_ReentryBlocked(t *testing.T) {
	lm, poolID := newR12_004LendingManager(t)
	user := types.Address{0x77}

	// ECON-R13-CRIT-002: Supply now debits real user balance.
	r12_004DepositQAU(t, lm, user, big.NewInt(10000))

	// Seed initial supply so Borrow is otherwise valid.
	if err := lm.Supply(poolID, user, big.NewInt(10000)); err != nil {
		t.Fatalf("seed Supply failed: %v", err)
	}

	// Simulate a reentrant Supply -> Borrow call path by pre-marking the
	// user as active (as if Supply were mid-execution).
	lm.activeBorrowers[user] = true

	// Borrow for the same user must be rejected.
	err := lm.Borrow(poolID, user, big.NewInt(100), 1)
	if !isReentrantErr(err) {
		t.Fatalf("Borrow during in-progress Supply should have been rejected as reentrant, got %v", err)
	}

	// Repay for the same user must also be rejected.
	err = lm.Repay(poolID, user, big.NewInt(50), 1)
	if !isReentrantErr(err) {
		t.Fatalf("Repay during in-progress Supply should have been rejected as reentrant, got %v", err)
	}
}

// TestECON_R12_004_DifferentUsers_NotBlocked verifies that the per-user
// guard does NOT block concurrent operations from different users.
func TestECON_R12_004_DifferentUsers_NotBlocked(t *testing.T) {
	lm, poolID := newR12_004LendingManager(t)
	userA := types.Address{0xAA}
	userB := types.Address{0xBB}

	// ECON-R13-CRIT-002: Supply now debits real user balance.
	r12_004DepositQAU(t, lm, userB, big.NewInt(500))

	// Pre-mark userA as active (simulating an in-progress Supply).
	lm.activeBorrowers[userA] = true

	// userB's Supply must still succeed (different user, different key).
	err := lm.Supply(poolID, userB, big.NewInt(500))
	if err != nil {
		t.Fatalf("userB Supply should not be blocked by userA's in-progress operation, got %v", err)
	}

	// userA's own Supply must be rejected.
	err = lm.Supply(poolID, userA, big.NewInt(500))
	if !isReentrantErr(err) {
		t.Fatalf("userA Supply during in-progress operation should have been rejected, got %v", err)
	}
}
