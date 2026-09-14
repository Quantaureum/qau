// Quantaureum Node source, version 1.0.0.
package economics

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// isReentrantErr returns true if the error message indicates a reentrant-call
// rejection from the ECON-R12-002/003 per-user (or per-pool) reentrancy guard.
func isReentrantErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "reentrant call")
}

// ---------------------------------------------------------------------------
// ECON-R12-003: LiquidStakingManager reentrancy protection
// ---------------------------------------------------------------------------

// TestECON_R12_003_CreatePool_RejectsReentrantCall verifies that when the
// operator is already marked active (simulating a callback mid-execution),
// CreatePool rejects the reentrant call instead of registering a duplicate.
func TestECON_R12_003_CreatePool_RejectsReentrantCall(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0xAB}

	// Simulate a reentrant call by pre-marking the operator as active.
	lsm.activeUsers[operator] = true

	_, err := lsm.CreatePool(operator, "Evil Pool", 500)
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify no pool was actually created (state unchanged on rejection).
	if len(lsm.pools) != 0 {
		t.Errorf("expected 0 pools after reentrant rejection, got %d", len(lsm.pools))
	}
}

// TestECON_R12_003_StakeLiquid_RejectsReentrantCall verifies that when the
// delegator is already marked active, StakeLiquid rejects the reentrant call.
func TestECON_R12_003_StakeLiquid_RejectsReentrantCall(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0x01}
	delegator := types.Address{0xCD}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}

	// Snapshot state before reentrant attempt.
	totalStakedBefore := new(big.Int).Set(pool.TotalStaked)

	// Simulate reentrant call.
	lsm.activeUsers[delegator] = true

	_, err = lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000))
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify state was not mutated.
	if pool.TotalStaked.Cmp(totalStakedBefore) != 0 {
		t.Errorf("TotalStaked changed on reentrant rejection: before=%s after=%s",
			totalStakedBefore.String(), pool.TotalStaked.String())
	}
}

// TestECON_R12_003_UnstakeLiquid_RejectsReentrantCall verifies that when the
// delegator is already marked active, UnstakeLiquid rejects the reentrant call.
func TestECON_R12_003_UnstakeLiquid_RejectsReentrantCall(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0x01}
	delegator := types.Address{0xCD}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}

	// Stake first so we have something to unstake.
	// ECON-R13-CRIT-004: StakeLiquid now debits real user balance.
	lsm.Deposit(delegator, StakeAsset, big.NewInt(1000))
	if _, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000)); err != nil {
		t.Fatalf("StakeLiquid setup failed: %v", err)
	}

	tokenBefore := lsm.liquidTokens[delegator][pool.ID]
	amountBefore := new(big.Int).Set(tokenBefore.Amount)

	// Simulate reentrant call.
	lsm.activeUsers[delegator] = true

	_, err = lsm.UnstakeLiquid(pool.ID, delegator, big.NewInt(100))
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify state was not mutated.
	if tokenBefore.Amount.Cmp(amountBefore) != 0 {
		t.Errorf("token amount changed on reentrant rejection: before=%s after=%s",
			amountBefore.String(), tokenBefore.Amount.String())
	}
}

// TestECON_R12_003_DistributeRewards_RejectsReentrantCall verifies that when
// the pool is already marked active, DistributeRewards rejects the reentrant
// call (pool-level guard since the function takes no user parameter).
func TestECON_R12_003_DistributeRewards_RejectsReentrantCall(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0x01}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}

	rewardPoolBefore := new(big.Int).Set(pool.RewardPool)

	// Simulate reentrant call at the pool level.
	lsm.activePools[pool.ID] = true

	err = lsm.DistributeRewards(pool.ID, operator, big.NewInt(500))
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify state was not mutated.
	if pool.RewardPool.Cmp(rewardPoolBefore) != 0 {
		t.Errorf("RewardPool changed on reentrant rejection: before=%s after=%s",
			rewardPoolBefore.String(), pool.RewardPool.String())
	}
}

// TestECON_R12_003_CompoundRewards_RejectsReentrantCall verifies that when
// the pool is already marked active, CompoundRewards rejects the reentrant
// call (pool-level guard).
func TestECON_R12_003_CompoundRewards_RejectsReentrantCall(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0x01}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}

	// Distribute some rewards so CompoundRewards has work to do.
	// ECON-R14-CRIT-004: fund operator so DistributeRewards can debit.
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(500)); err != nil {
		t.Fatalf("DistributeRewards setup failed: %v", err)
	}

	totalStakedBefore := new(big.Int).Set(pool.TotalStaked)

	// Simulate reentrant call at the pool level.
	lsm.activePools[pool.ID] = true

	// ECON-R13-M02: CompoundRewards now requires operator authorization.
	err = lsm.CompoundRewards(pool.ID, operator)
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify state was not mutated.
	if pool.TotalStaked.Cmp(totalStakedBefore) != 0 {
		t.Errorf("TotalStaked changed on reentrant rejection: before=%s after=%s",
			totalStakedBefore.String(), pool.TotalStaked.String())
	}
}

// TestECON_R12_003_ClaimCommission_RejectsReentrantCall verifies that when
// the operator is already marked active, ClaimCommission rejects the
// reentrant call, preventing double-claim of accumulated commission.
func TestECON_R12_003_ClaimCommission_RejectsReentrantCall(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0x01}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}

	// Build up some commission via DistributeRewards.
	// ECON-R14-CRIT-004: fund operator so DistributeRewards can debit.
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(1000)); err != nil {
		t.Fatalf("DistributeRewards setup failed: %v", err)
	}

	commissionBefore := new(big.Int).Set(pool.TotalCommission)

	// Simulate reentrant call.
	lsm.activeUsers[operator] = true

	_, err = lsm.ClaimCommission(pool.ID, operator)
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}

	// Verify commission was NOT drained.
	if pool.TotalCommission.Cmp(commissionBefore) != 0 {
		t.Errorf("TotalCommission changed on reentrant rejection: before=%s after=%s",
			commissionBefore.String(), pool.TotalCommission.String())
	}
}

// TestECON_R12_003_ActiveUsers_CleanupAfterSuccess verifies that the
// activeUsers/activePools markers are correctly cleaned up after a
// successful operation, so subsequent calls from the same user/pool succeed.
func TestECON_R12_003_ActiveUsers_CleanupAfterSuccess(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	// R37-INFO: CompoundRewards is fail-closed without a TreasuryVerifier;
	// this test exercises reentrancy-marker cleanup, not treasury
	// verification, so explicitly opt out of verification.
	lsm.AllowUnverifiedCompounding()
	operator := types.Address{0x01}
	delegator := types.Address{0x02}

	pool, err := lsm.CreatePool(operator, "Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}

	// StakeLiquid should succeed and clean up the activeUsers marker.
	// ECON-R13-CRIT-004: StakeLiquid now debits real user balance.
	lsm.Deposit(delegator, StakeAsset, big.NewInt(200))
	if _, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(100)); err != nil {
		t.Fatalf("first StakeLiquid failed: %v", err)
	}
	if lsm.activeUsers[delegator] {
		t.Errorf("activeUsers[delegator] not cleaned up after successful StakeLiquid")
	}

	// Second StakeLiquid from the same delegator should also succeed
	// (proves the marker was cleaned up).
	if _, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(100)); err != nil {
		t.Fatalf("second StakeLiquid failed (cleanup broken): %v", err)
	}

	// DistributeRewards should clean up activePools.
	// ECON-R14-CRIT-004: fund operator so DistributeRewards can debit.
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(500)); err != nil {
		t.Fatalf("DistributeRewards failed: %v", err)
	}
	if lsm.activePools[pool.ID] {
		t.Errorf("activePools[poolID] not cleaned up after successful DistributeRewards")
	}

	// CompoundRewards should clean up activePools.
	// ECON-R13-M02: CompoundRewards now requires operator authorization.
	if err := lsm.CompoundRewards(pool.ID, operator); err != nil {
		t.Fatalf("CompoundRewards failed: %v", err)
	}
	if lsm.activePools[pool.ID] {
		t.Errorf("activePools[poolID] not cleaned up after successful CompoundRewards")
	}

	// ClaimCommission should clean up activeUsers.
	if _, err := lsm.ClaimCommission(pool.ID, operator); err != nil {
		t.Fatalf("ClaimCommission failed: %v", err)
	}
	if lsm.activeUsers[operator] {
		t.Errorf("activeUsers[operator] not cleaned up after successful ClaimCommission")
	}
}

// TestECON_R12_003_ActiveMarkers_NotLeftAfterFailure verifies that the
// activeUsers/activePools markers are cleaned up even when the operation
// fails for a non-reentrancy reason (e.g., invalid params, pool not found).
// This prevents a stuck marker from permanently blocking the user.
func TestECON_R12_003_ActiveMarkers_NotLeftAfterFailure(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	delegator := types.Address{0x02}

	// StakeLiquid on a non-existent pool should fail, but still clean up.
	_, err := lsm.StakeLiquid("nonexistent", delegator, big.NewInt(100))
	if err == nil {
		t.Fatal("expected error for non-existent pool")
	}
	if lsm.activeUsers[delegator] {
		t.Errorf("activeUsers[delegator] not cleaned up after failed StakeLiquid")
	}

	// StakeLiquid with non-positive amount should fail, but still clean up.
	if _, err := lsm.StakeLiquid("nonexistent", delegator, big.NewInt(0)); err == nil {
		t.Fatal("expected error for zero amount")
	}
	if lsm.activeUsers[delegator] {
		t.Errorf("activeUsers[delegator] not cleaned up after zero-amount StakeLiquid")
	}

	// DistributeRewards on non-existent pool should fail, but still clean up.
	if err := lsm.DistributeRewards("nonexistent", types.Address{0x01}, big.NewInt(100)); err == nil {
		t.Fatal("expected error for non-existent pool")
	}
	if lsm.activePools["nonexistent"] {
		t.Errorf("activePools not cleaned up after failed DistributeRewards")
	}
}

// ---------------------------------------------------------------------------
// ECON-R12-002: YieldFarmingManager reentrancy protection
// ---------------------------------------------------------------------------

// setupYFMForReentrancy creates a YieldFarmingManager with a farm so we can
// test the reentrancy guards on Stake/Unstake/Harvest.
func setupYFMForReentrancy(t *testing.T) (*YieldFarmingManager, string, types.Address) {
	t.Helper()
	yfm := NewYieldFarmingManager(big.NewInt(1_000_000_000_000_000_000)) // 1e18 reward per block
	farm, err := yfm.CreateFarm("Test Farm", "LP-QAU", "QAU", big.NewInt(1_000_000_000_000_000_000), 1, types.Address{})
	if err != nil {
		t.Fatalf("CreateFarm failed: %v", err)
	}
	user := types.Address{0xEE}
	// ECON-R14-CRIT-001: Stake now debits the user's LP token balance,
	// so we must credit it first via DepositTokens. Some tests call
	// Stake multiple times (e.g. cleanup test calls it twice with 100),
	// so deposit enough headroom.
	if err := yfm.DepositTokens(user, "LP-QAU", big.NewInt(1000)); err != nil {
		t.Fatalf("DepositTokens failed: %v", err)
	}
	return yfm, farm.FarmID, user
}

// TestECON_R12_002_Stake_RejectsReentrantCall verifies that when the user is
// already marked active, Stake rejects the reentrant call.
func TestECON_R12_002_Stake_RejectsReentrantCall(t *testing.T) {
	yfm, farmID, user := setupYFMForReentrancy(t)

	// Simulate reentrant call.
	yfm.activeUsers[user] = true

	err := yfm.Stake(farmID, user, big.NewInt(100))
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}
}

// TestECON_R12_002_Unstake_RejectsReentrantCall verifies that when the user
// is already marked active, Unstake rejects the reentrant call.
func TestECON_R12_002_Unstake_RejectsReentrantCall(t *testing.T) {
	yfm, farmID, user := setupYFMForReentrancy(t)

	// Stake first so we have something to unstake.
	if err := yfm.Stake(farmID, user, big.NewInt(100)); err != nil {
		t.Fatalf("Stake setup failed: %v", err)
	}

	// Simulate reentrant call.
	yfm.activeUsers[user] = true

	_, err := yfm.Unstake(farmID, user, big.NewInt(50))
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}
}

// TestECON_R12_002_Harvest_RejectsReentrantCall verifies that when the user
// is already marked active, Harvest rejects the reentrant call, preventing
// double-claim of rewards.
func TestECON_R12_002_Harvest_RejectsReentrantCall(t *testing.T) {
	yfm, farmID, user := setupYFMForReentrancy(t)

	// Stake first so we have something to harvest.
	if err := yfm.Stake(farmID, user, big.NewInt(100)); err != nil {
		t.Fatalf("Stake setup failed: %v", err)
	}

	// Simulate reentrant call.
	yfm.activeUsers[user] = true

	_, err := yfm.Harvest(farmID, user)
	if !isReentrantErr(err) {
		t.Fatalf("expected reentrant error, got %v", err)
	}
}

// TestECON_R12_002_ActiveUsers_CleanupAfterSuccess verifies that the
// activeUsers marker is correctly cleaned up after successful Stake/Unstake/
// Harvest, so subsequent operations from the same user succeed.
func TestECON_R12_002_ActiveUsers_CleanupAfterSuccess(t *testing.T) {
	yfm, farmID, user := setupYFMForReentrancy(t)

	// Stake should succeed and clean up.
	if err := yfm.Stake(farmID, user, big.NewInt(100)); err != nil {
		t.Fatalf("Stake failed: %v", err)
	}
	if yfm.activeUsers[user] {
		t.Errorf("activeUsers[user] not cleaned up after successful Stake")
	}

	// Second Stake from the same user should also succeed (proves cleanup).
	if err := yfm.Stake(farmID, user, big.NewInt(100)); err != nil {
		t.Fatalf("second Stake failed (cleanup broken): %v", err)
	}

	// Unstake should succeed and clean up.
	if _, err := yfm.Unstake(farmID, user, big.NewInt(50)); err != nil {
		t.Fatalf("Unstake failed: %v", err)
	}
	if yfm.activeUsers[user] {
		t.Errorf("activeUsers[user] not cleaned up after successful Unstake")
	}
}

// TestECON_R12_002_ActiveUsers_NotLeftAfterFailure verifies that the marker
// is cleaned up even when an operation fails for a non-reentrancy reason.
func TestECON_R12_002_ActiveUsers_NotLeftAfterFailure(t *testing.T) {
	yfm, farmID, user := setupYFMForReentrancy(t)

	// Stake with zero amount should fail, but still clean up.
	if err := yfm.Stake(farmID, user, big.NewInt(0)); err == nil {
		t.Fatal("expected error for zero amount")
	}
	if yfm.activeUsers[user] {
		t.Errorf("activeUsers[user] not cleaned up after failed Stake")
	}

	// Unstake with no stake should fail, but still clean up.
	if _, err := yfm.Unstake(farmID, user, big.NewInt(50)); err == nil {
		t.Fatal("expected error for unstake with no stake")
	}
	if yfm.activeUsers[user] {
		t.Errorf("activeUsers[user] not cleaned up after failed Unstake")
	}
}
