// Quantaureum Node source, version 1.0.0.
// R37-P1-ECON-01 regression test (2026-07-30).
// YieldFarm double deduction: updateFarm deducted RewardPool at accrual AND
// Harvest/Unstake deducted it again at payout — the pool drained at 2x
// speed, and once empty, updateFarm silently stopped accruing while
// LastRewardBlock still advanced (rewards permanently lost).
// Fix: accrual moves funds RewardPool -> ReservedRewards (liability);
// payouts draw from ReservedRewards.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR37_P1_ECON_01_NoDoubleDeduction verifies the fund conservation
// invariant: RewardPool + ReservedRewards + paidOut == totalFunded, at every
// step of the accrue/payout cycle.
func TestR37_P1_ECON_01_NoDoubleDeduction(t *testing.T) {
	yfm := newYieldFarmingManagerForTest(t)

	funded := big.NewInt(1_000_000)
	farm, err := yfm.CreateFarm("test", "LPT", "RWD", big.NewInt(100), 100, types.Address{})
	if err != nil {
		t.Fatalf("CreateFarm: %v", err)
	}
	funder := types.Address{0xFF}
	if err := yfm.DepositTokens(funder, "RWD", funded); err != nil {
		t.Fatalf("DepositTokens: %v", err)
	}
	if err := yfm.FundRewardPool(farm.FarmID, funder, funded); err != nil {
		t.Fatalf("FundRewardPool: %v", err)
	}

	user := types.Address{0x01}
	if err := yfm.DepositTokens(user, "LPT", big.NewInt(1000)); err != nil {
		t.Fatalf("DepositTokens LPT: %v", err)
	}
	if err := yfm.Stake(farm.FarmID, user, big.NewInt(1000)); err != nil {
		t.Fatalf("Stake: %v", err)
	}

	// Advance 100 blocks and accrue. reward = 100/block * 100 blocks * 100/100 = 10000.
	yfm.SetCurrentBlock(101)
	yfm.mu.Lock()
	yfm.updateFarm(farm)
	poolAfterAccrual := new(big.Int).Set(farm.RewardPool)
	reservedAfterAccrual := new(big.Int).Set(farm.ReservedRewards)
	yfm.mu.Unlock()

	// After accrual: pool + reserved must equal funded (nothing lost, nothing minted).
	sum := new(big.Int).Add(poolAfterAccrual, reservedAfterAccrual)
	if sum.Cmp(funded) != 0 {
		t.Fatalf("conservation violated after accrual: pool=%s reserved=%s sum=%s funded=%s",
			poolAfterAccrual, reservedAfterAccrual, sum, funded)
	}
	if reservedAfterAccrual.Sign() <= 0 {
		t.Fatalf("expected non-zero ReservedRewards after accrual, got %s", reservedAfterAccrual)
	}

	// Harvest. The payout must come from ReservedRewards, NOT RewardPool.
	paid, err := yfm.Harvest(farm.FarmID, user)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	if paid.Sign() <= 0 {
		t.Fatalf("expected non-zero harvest, got %s", paid)
	}

	yfm.mu.RLock()
	poolAfterPayout := new(big.Int).Set(farm.RewardPool)
	reservedAfterPayout := new(big.Int).Set(farm.ReservedRewards)
	yfm.mu.RUnlock()

	// RewardPool must be UNCHANGED by the payout (the old bug deducted it again).
	if poolAfterPayout.Cmp(poolAfterAccrual) != 0 {
		t.Errorf("RewardPool changed during payout (double deduction!): before=%s after=%s",
			poolAfterAccrual, poolAfterPayout)
	}
	// Conservation: pool + reserved + paid == funded.
	total := new(big.Int).Add(poolAfterPayout, reservedAfterPayout)
	total.Add(total, paid)
	if total.Cmp(funded) != 0 {
		t.Errorf("conservation violated after payout: pool=%s reserved=%s paid=%s total=%s funded=%s",
			poolAfterPayout, reservedAfterPayout, paid, total, funded)
	}
	// ReservedRewards must have decreased by exactly the paid amount.
	expectedReserved := new(big.Int).Sub(reservedAfterAccrual, paid)
	if reservedAfterPayout.Cmp(expectedReserved) != 0 {
		t.Errorf("ReservedRewards after payout = %s, want %s (accrued %s - paid %s)",
			reservedAfterPayout, expectedReserved, reservedAfterAccrual, paid)
	}
	// User's reward-token balance must equal the paid amount.
	bal := yfm.GetUserTokenBalance(user, "RWD")
	if bal.Cmp(paid) != 0 {
		t.Errorf("user RWD balance = %s, want paid %s", bal, paid)
	}
}

// TestR37_P1_ECON_01_RemainingPoolStillAccrues verifies the scenario from
// the audit report: after half the funding is accrued and paid out, the
// REMAINING pool must still fund future accrual (previously the pool was
// drained 2x and accrual silently stopped).
func TestR37_P1_ECON_01_RemainingPoolStillAccrues(t *testing.T) {
	yfm := newYieldFarmingManagerForTest(t)

	// Fund exactly 20000: two rounds of 100-block accrual at 100/block.
	funded := big.NewInt(20_000)
	farm, err := yfm.CreateFarm("test", "LPT", "RWD", big.NewInt(100), 100, types.Address{})
	if err != nil {
		t.Fatalf("CreateFarm: %v", err)
	}
	funder := types.Address{0xFF}
	if err := yfm.DepositTokens(funder, "RWD", funded); err != nil {
		t.Fatalf("DepositTokens: %v", err)
	}
	if err := yfm.FundRewardPool(farm.FarmID, funder, funded); err != nil {
		t.Fatalf("FundRewardPool: %v", err)
	}

	user := types.Address{0x01}
	if err := yfm.DepositTokens(user, "LPT", big.NewInt(1000)); err != nil {
		t.Fatalf("DepositTokens LPT: %v", err)
	}
	if err := yfm.Stake(farm.FarmID, user, big.NewInt(1000)); err != nil {
		t.Fatalf("Stake: %v", err)
	}

	// Round 1: 100 blocks -> accrue 10000, harvest it.
	yfm.SetCurrentBlock(101)
	paid1, err := yfm.Harvest(farm.FarmID, user)
	if err != nil {
		t.Fatalf("Harvest round 1: %v", err)
	}
	if paid1.Cmp(big.NewInt(10_000)) != 0 {
		t.Fatalf("round 1 paid = %s, want 10000", paid1)
	}

	// Round 2: another 100 blocks. Under the old double-deduction bug the
	// pool was already empty (20000 - 10000 accrual - 10000 payout = 0) and
	// accrual silently stopped. Now the remaining 10000 in RewardPool must
	// fund a second identical round.
	yfm.SetCurrentBlock(201)
	paid2, err := yfm.Harvest(farm.FarmID, user)
	if err != nil {
		t.Fatalf("Harvest round 2: %v", err)
	}
	if paid2.Cmp(big.NewInt(10_000)) != 0 {
		t.Fatalf("round 2 paid = %s, want 10000 (pool must still fund accrual after first payout)", paid2)
	}

	// Total paid == total funded; pool and reserved both zero.
	yfm.mu.RLock()
	poolEnd := new(big.Int).Set(farm.RewardPool)
	reservedEnd := new(big.Int).Set(farm.ReservedRewards)
	yfm.mu.RUnlock()
	if poolEnd.Sign() != 0 || reservedEnd.Sign() != 0 {
		t.Errorf("end state: pool=%s reserved=%s, want both 0", poolEnd, reservedEnd)
	}
	total := new(big.Int).Add(paid1, paid2)
	if total.Cmp(funded) != 0 {
		t.Errorf("total paid = %s, want funded %s (nothing lost, nothing minted)", total, funded)
	}
}
