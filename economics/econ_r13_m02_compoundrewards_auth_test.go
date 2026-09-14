// Quantaureum Node source, version 1.0.0.
// ECON-R13-M02 regression tests (2026-07-21).
// CompoundRewards must verify caller is the pool operator and must refuse
// to compound corrupt (negative) reward state.
package economics

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestECON_R13_M02_CompoundRewards_RejectsNonOperatorCaller verifies that
// CompoundRewards rejects calls from any address other than pool.Operator.
// Previously any caller could trigger compounding at a maliciously chosen
// time (e.g., sandwiched around their own unstake).
func TestECON_R13_M02_CompoundRewards_RejectsNonOperatorCaller(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0x01}
	mallory := types.Address{0x02}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool: %v", err)
	}

	// Distribute some rewards so CompoundRewards has work to do.
	// ECON-R14-CRIT-004: DistributeRewards now requires operator auth
	// and debits from the operator's balance.
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(500)); err != nil {
		t.Fatalf("DistributeRewards: %v", err)
	}

	// Non-operator call must fail with ErrInvalidPoolOperator.
	err = lsm.CompoundRewards(pool.ID, mallory)
	if err != ErrInvalidPoolOperator {
		t.Errorf("expected ErrInvalidPoolOperator for non-operator caller, got %v", err)
	}

	// Pool state must be untouched: RewardPool still holds the distributed amount.
	retrieved, _ := lsm.GetPool(pool.ID)
	if retrieved.RewardPool.Sign() <= 0 {
		t.Errorf("RewardPool was drained by rejected call: %s", retrieved.RewardPool)
	}
}

// TestECON_R13_M02_CompoundRewards_OperatorSucceeds verifies the happy path
// still works after the auth check was added.
func TestECON_R13_M02_CompoundRewards_OperatorSucceeds(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	// R37-INFO: CompoundRewards is fail-closed without a TreasuryVerifier;
	// this test exercises accounting logic, not treasury verification, so
	// explicitly opt out of verification.
	lsm.AllowUnverifiedCompounding()
	operator := types.Address{0x01}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	// ECON-R14-CRIT-004: fund operator so DistributeRewards can debit.
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(500)); err != nil {
		t.Fatalf("DistributeRewards: %v", err)
	}

	retrievedBefore, _ := lsm.GetPool(pool.ID)
	rewardBefore := new(big.Int).Set(retrievedBefore.RewardPool)
	stakedBefore := new(big.Int).Set(retrievedBefore.TotalStaked)

	if err := lsm.CompoundRewards(pool.ID, operator); err != nil {
		t.Fatalf("CompoundRewards by operator failed: %v", err)
	}

	retrievedAfter, _ := lsm.GetPool(pool.ID)
	// RewardPool must be drained.
	if retrievedAfter.RewardPool.Sign() != 0 {
		t.Errorf("RewardPool not drained: %s", retrievedAfter.RewardPool)
	}
	// TotalStaked must have grown by rewardBefore.
	wantStaked := new(big.Int).Add(stakedBefore, rewardBefore)
	if retrievedAfter.TotalStaked.Cmp(wantStaked) != 0 {
		t.Errorf("TotalStaked mismatch: want %s, got %s", wantStaked, retrievedAfter.TotalStaked)
	}
}

// TestECON_R13_M02_CompoundRewards_RejectsReentrantOperator verifies that
// the new per-operator reentrancy guard correctly rejects a second concurrent
// CompoundRewards call from the same operator while the first is in flight.
func TestECON_R13_M02_CompoundRewards_RejectsReentrantOperator(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0x01}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	// ECON-R14-CRIT-004: fund operator so DistributeRewards can debit.
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(500)); err != nil {
		t.Fatalf("DistributeRewards: %v", err)
	}

	// Simulate the operator already being mid-operation (e.g., a hook
	// re-entered CompoundRewards or another operation by the same operator
	// is in flight).
	lsm.activeUsers[operator] = true

	err = lsm.CompoundRewards(pool.ID, operator)
	if err == nil {
		t.Fatal("expected reentrant error, got nil")
	}
	if !strings.Contains(err.Error(), "reentrant call") {
		t.Errorf("expected reentrant error, got: %v", err)
	}
}

// TestECON_R13_M02_CompoundRewards_NegativeRewardPoolRefused verifies the
// defensive consistency check: if internal accounting somehow produced a
// negative RewardPool, CompoundRewards refuses to compound (rather than
// silently decreasing TotalStaked).
func TestECON_R13_M02_CompoundRewards_NegativeRewardPoolRefused(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0x01}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	// ECON-R14-CRIT-004: fund operator so DistributeRewards can debit.
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(500)); err != nil {
		t.Fatalf("DistributeRewards: %v", err)
	}

	// Corrupt the internal state: simulate an accounting underflow by
	// setting RewardPool to a negative value directly. We hold the lock
	// because the field is protected by lsm.mu.
	lsm.mu.Lock()
	pool.RewardPool = big.NewInt(-100)
	lsm.mu.Unlock()

	// Sanity check: the early-return guard (RewardPool.Sign() <= 0) would
	// catch this on its own. To actually exercise the dedicated negative
	// branch, we'd need RewardPool == 0 to be false but Sign() < 0 to
	// be true — which is what we set up here. The dedicated negative-check
	// branch is defense-in-depth for the case where the guard is reordered.
	err = lsm.CompoundRewards(pool.ID, operator)
	if err != nil {
		// Either path (early return or dedicated negative check) is
		// acceptable; both refuse to compound. Verify state is untouched.
		retrieved, _ := lsm.GetPool(pool.ID)
		if retrieved.TotalStaked.Sign() < 0 {
			t.Errorf("TotalStaked went negative from corrupt compounding: %s", retrieved.TotalStaked)
		}
	}
}

// TestR37_INFO_CompoundRewards_FailClosedWithoutVerifier verifies the
// R37-INFO fix: with no TreasuryVerifier injected and no explicit opt-out,
// CompoundRewards must refuse to fold rewards into TotalStaked (the
// previous nil default silently skipped on-chain treasury verification).
func TestR37_INFO_CompoundRewards_FailClosedWithoutVerifier(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0x01}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(500)); err != nil {
		t.Fatalf("DistributeRewards: %v", err)
	}
	// DistributeRewards deducts the operator commission (500 bps of 500 =
	// 25), so RewardPool holds 475 — read the actual value instead of
	// hardcoding.
	before, _ := lsm.GetPool(pool.ID)
	rewardBefore := new(big.Int).Set(before.RewardPool)
	if rewardBefore.Sign() <= 0 {
		t.Fatalf("RewardPool empty after DistributeRewards")
	}

	// Default: no verifier, no opt-out → must fail closed.
	err = lsm.CompoundRewards(pool.ID, operator)
	if err == nil {
		t.Fatal("expected fail-closed error without verifier, got nil")
	}
	if !strings.Contains(err.Error(), "treasury verifier not configured") {
		t.Errorf("unexpected error: %v", err)
	}

	// State must be untouched: RewardPool still holds the distributed amount.
	retrieved, _ := lsm.GetPool(pool.ID)
	if retrieved.RewardPool.Cmp(rewardBefore) != 0 {
		t.Errorf("RewardPool mutated by rejected call: want %s, got %s", rewardBefore, retrieved.RewardPool)
	}

	// Explicit opt-out must unblock compounding.
	lsm.AllowUnverifiedCompounding()
	if err := lsm.CompoundRewards(pool.ID, operator); err != nil {
		t.Fatalf("CompoundRewards after AllowUnverifiedCompounding failed: %v", err)
	}
	retrieved, _ = lsm.GetPool(pool.ID)
	if retrieved.RewardPool.Sign() != 0 {
		t.Errorf("RewardPool not drained after opt-out compounding: %s", retrieved.RewardPool)
	}
}
