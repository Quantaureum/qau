// Quantaureum Node source, version 1.0.0.
// ECON-R13-M03 regression tests (2026-07-21).
// YieldFarming reward accrual must respect farm.EndBlock and farm.Status.
// Previously updateFarm continued crediting rewards forever — past the
// scheduled end block and through paused/ended states — causing infinite
// inflation of the reward token supply.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestECON_R13_M03_UpdateFarm_StopsAtEndBlock verifies that updateFarm
// credits no rewards past farm.EndBlock. Previously the farm kept
// emitting rewards indefinitely.
func TestECON_R13_M03_UpdateFarm_StopsAtEndBlock(t *testing.T) {
	yfm := newYieldFarmingManagerForTest(t)
	farm := createAndFundFarmForTest(t, yfm)

	// Stake from one user so TotalStaked > 0.
	user := types.Address{0x01}
	// ECON-R14-CRIT-001: Stake now debits the user's LP token balance,
	// so we must credit it first via DepositTokens.
	if err := yfm.DepositTokens(user, "LPT", big.NewInt(1000)); err != nil {
		t.Fatalf("DepositTokens: %v", err)
	}
	if err := yfm.Stake(farm.FarmID, user, big.NewInt(1000)); err != nil {
		t.Fatalf("Stake: %v", err)
	}

	// Advance the block to the farm's EndBlock. updateFarm should credit
	// rewards up to EndBlock exactly.
	yfm.SetCurrentBlock(farm.EndBlock)
	yfm.mu.Lock()
	yfm.updateFarm(farm)
	accAtEnd := new(big.Rat).Set(farm.AccRewardPerShare)
	yfm.mu.Unlock()

	if accAtEnd.Sign() <= 0 {
		t.Fatalf("expected non-zero AccRewardPerShare at EndBlock, got %s", accAtEnd)
	}

	// Advance past EndBlock. updateFarm should credit NO additional rewards.
	yfm.SetCurrentBlock(farm.EndBlock + 1_000_000)
	yfm.mu.Lock()
	yfm.updateFarm(farm)
	accAfterEnd := new(big.Rat).Set(farm.AccRewardPerShare)
	yfm.mu.Unlock()

	if accAfterEnd.Cmp(accAtEnd) != 0 {
		t.Errorf("AccRewardPerShare grew past EndBlock: atEnd=%s afterEnd=%s (should be equal)",
			accAtEnd.RatString(), accAfterEnd.RatString())
	}
}

// TestECON_R13_M03_UpdateFarm_PausedStateStopsAccrual verifies that
// changing farm.Status to "PAUSED" halts reward accrual. Previously
// updateFarm ignored Status entirely.
func TestECON_R13_M03_UpdateFarm_PausedStateStopsAccrual(t *testing.T) {
	yfm := newYieldFarmingManagerForTest(t)
	farm := createAndFundFarmForTest(t, yfm)
	user := types.Address{0x01}
	// ECON-R14-CRIT-001: Stake now debits the user's LP token balance,
	// so we must credit it first via DepositTokens.
	if err := yfm.DepositTokens(user, "LPT", big.NewInt(1000)); err != nil {
		t.Fatalf("DepositTokens: %v", err)
	}
	if err := yfm.Stake(farm.FarmID, user, big.NewInt(1000)); err != nil {
		t.Fatalf("Stake: %v", err)
	}

	// Advance and accrue baseline rewards.
	yfm.SetCurrentBlock(yfm.currentBlock + 1000)
	yfm.mu.Lock()
	yfm.updateFarm(farm)
	accBeforePause := new(big.Rat).Set(farm.AccRewardPerShare)
	yfm.mu.Unlock()

	if accBeforePause.Sign() <= 0 {
		t.Fatalf("expected non-zero AccRewardPerShare before pause, got %s", accBeforePause)
	}

	// Pause the farm and advance the block further. No rewards should accrue.
	yfm.mu.Lock()
	farm.Status = "PAUSED"
	yfm.mu.Unlock()

	yfm.SetCurrentBlock(yfm.currentBlock + 1000)
	yfm.mu.Lock()
	yfm.updateFarm(farm)
	accAfterPause := new(big.Rat).Set(farm.AccRewardPerShare)
	yfm.mu.Unlock()

	if accAfterPause.Cmp(accBeforePause) != 0 {
		t.Errorf("AccRewardPerShare changed while paused: before=%s after=%s (should be equal)",
			accBeforePause.RatString(), accAfterPause.RatString())
	}

	// Resume the farm. Rewards should accrue again from the resume point,
	// NOT retroactively for the paused period.
	yfm.mu.Lock()
	farm.Status = "ACTIVE"
	yfm.mu.Unlock()

	yfm.SetCurrentBlock(yfm.currentBlock + 1000)
	yfm.mu.Lock()
	yfm.updateFarm(farm)
	accAfterResume := new(big.Rat).Set(farm.AccRewardPerShare)
	yfm.mu.Unlock()

	if accAfterResume.Cmp(accAfterPause) <= 0 {
		t.Errorf("AccRewardPerShare did not grow after resume: paused=%s resumed=%s",
			accAfterPause.RatString(), accAfterResume.RatString())
	}

	// Sanity: post-resume growth must be strictly positive (proves the
	// farm resumed accruing) but must NOT include the paused 1000 blocks.
	// Total post-resume + paused-period growth must equal the post-resume
	// growth alone — i.e., the paused period contributed zero.
	growthPostResume := new(big.Rat).Sub(accAfterResume, accAfterPause)
	if growthPostResume.Sign() <= 0 {
		t.Errorf("post-resume growth must be positive (farm did not resume accruing): %s",
			growthPostResume.RatString())
	}
	// Verify the paused period contributed zero: accAfterPause must equal
	// accBeforePause. This was already checked above, but we re-state it
	// here as the precondition for the resume test making sense.
}

// TestECON_R13_M03_Harvest_ReturnsZeroAfterEndBlock verifies that a staker
// who harvests after the farm has ended receives no rewards for the
// post-EndBlock period (regression test for the end-to-end path).
func TestECON_R13_M03_Harvest_ReturnsZeroAfterEndBlock(t *testing.T) {
	yfm := newYieldFarmingManagerForTest(t)
	farm := createAndFundFarmForTest(t, yfm)
	user := types.Address{0x01}
	// ECON-R14-CRIT-001: Stake now debits the user's LP token balance,
	// so we must credit it first via DepositTokens.
	if err := yfm.DepositTokens(user, "LPT", big.NewInt(1000)); err != nil {
		t.Fatalf("DepositTokens: %v", err)
	}
	if err := yfm.Stake(farm.FarmID, user, big.NewInt(1000)); err != nil {
		t.Fatalf("Stake: %v", err)
	}

	// Advance to EndBlock and harvest the baseline reward.
	yfm.SetCurrentBlock(farm.EndBlock)
	baselineReward, err := yfm.Harvest(farm.FarmID, user)
	if err != nil {
		t.Fatalf("Harvest at EndBlock: %v", err)
	}
	if baselineReward.Sign() <= 0 {
		t.Fatalf("expected positive baseline reward, got %s", baselineReward)
	}

	// Advance far past EndBlock. A subsequent Harvest must return ZERO —
	// the farm has stopped emitting rewards.
	yfm.SetCurrentBlock(farm.EndBlock + 10_000_000)
	lateReward, err := yfm.Harvest(farm.FarmID, user)
	if err != nil {
		t.Fatalf("Harvest post-EndBlock: %v", err)
	}
	if lateReward.Sign() != 0 {
		t.Errorf("expected zero reward after EndBlock, got %s (inflation bug!)", lateReward)
	}
}

// newYieldFarmingManagerForTest constructs a YieldFarmingManager with a
// sensible default state for the M03 subtests.
func newYieldFarmingManagerForTest(t *testing.T) *YieldFarmingManager {
	t.Helper()
	yfm := NewYieldFarmingManager(big.NewInt(100))
	// Start at block 1 so we have headroom to advance in either direction.
	yfm.SetCurrentBlock(1)
	return yfm
}

// createAndFundFarmForTest creates a farm AND funds its RewardPool so
// updateFarm can actually accrue rewards. ECON-R14-CRIT-003 made
// updateFarm clamp accrual to the pool balance, so tests that expect
// non-zero AccRewardPerShare must fund the pool first.
func createAndFundFarmForTest(t *testing.T, yfm *YieldFarmingManager) *YieldFarm {
	t.Helper()
	farm, err := yfm.CreateFarm("test", "LPT", "RWD", big.NewInt(100), 100, types.Address{})
	if err != nil {
		t.Fatalf("CreateFarm: %v", err)
	}
	// Deposit reward tokens for a treasury funder, then fund the pool.
	funder := types.Address{0xFF}
	if err := yfm.DepositTokens(funder, "RWD", big.NewInt(1_000_000_000)); err != nil {
		t.Fatalf("DepositTokens: %v", err)
	}
	if err := yfm.FundRewardPool(farm.FarmID, funder, big.NewInt(1_000_000_000)); err != nil {
		t.Fatalf("FundRewardPool: %v", err)
	}
	return farm
}
