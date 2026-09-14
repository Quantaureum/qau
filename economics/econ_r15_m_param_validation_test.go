// Quantaureum Node source, version 1.0.0.
package economics

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestECON_R15_M_LendingManager_ClampsInvalidPercentages verifies that
// NewLendingManager clamps CollateralFactor, LiquidationThreshold, and
// LiquidationPenalty to [0, 100] and enforces threshold >= factor.
// Without this, a liquidationPenalty of 1000 (1000%) would let a liquidator
// seize 11x the debt value in collateral.
func TestECON_R15_M_LendingManager_ClampsInvalidPercentages(t *testing.T) {
	// nil oracle is fine — NewLendingManager falls back to DefaultPriceOracle.
	// We're only testing parameter clamping, not oracle functionality.
	// liquidationPenalty > 100 → must be clamped to 5 (default)
	lm := NewLendingManager(75, 85, 1000, nil)
	if lm.liquidationPenalty > 100 {
		t.Errorf("ECON-R15-M REGRESSION: liquidationPenalty %d not clamped (still > 100)", lm.liquidationPenalty)
	}
	// collateralFactor > 100 → must be clamped to 75 (default)
	lm2 := NewLendingManager(200, 85, 5, nil)
	if lm2.defaultCollateralFactor > 100 {
		t.Errorf("ECON-R15-M REGRESSION: collateralFactor %d not clamped (still > 100)", lm2.defaultCollateralFactor)
	}
	// liquidationThreshold > 100 → must be clamped to 85 (default)
	lm3 := NewLendingManager(75, 200, 5, nil)
	if lm3.defaultLiquidationThreshold > 100 {
		t.Errorf("ECON-R15-M REGRESSION: liquidationThreshold %d not clamped (still > 100)", lm3.defaultLiquidationThreshold)
	}
	// threshold < factor → threshold must be clamped up to factor
	lm4 := NewLendingManager(80, 50, 5, nil)
	if lm4.defaultLiquidationThreshold < lm4.defaultCollateralFactor {
		t.Errorf("ECON-R15-M REGRESSION: threshold %d < factor %d (not clamped)", lm4.defaultLiquidationThreshold, lm4.defaultCollateralFactor)
	}
}

// TestECON_R15_M_CreatePool_RejectsInvalidPercentages verifies that
// CreatePool rejects CollateralFactor or LiquidationThreshold > 100.
func TestECON_R15_M_CreatePool_RejectsInvalidPercentages(t *testing.T) {
	lm := NewLendingManager(75, 85, 5, nil)
	// collateralFactor > 100 (with threshold >= factor to isolate the > 100
	// check from the threshold < factor check) → must be rejected
	_, err := lm.CreatePool("QAU", 200, 200)
	if err == nil || !strings.Contains(err.Error(), "exceeds 100") {
		t.Errorf("ECON-R15-M REGRESSION: expected rejection for collateralFactor=200, got %v", err)
	}
	// liquidationThreshold > 100 (with threshold >= factor) → must be rejected
	_, err = lm.CreatePool("QAU2", 75, 200)
	if err == nil || !strings.Contains(err.Error(), "exceeds 100") {
		t.Errorf("ECON-R15-M REGRESSION: expected rejection for liquidationThreshold=200, got %v", err)
	}
	// valid values → must succeed
	_, err = lm.CreatePool("VALID", 75, 85)
	if err != nil {
		t.Errorf("ECON-R15-M REGRESSION: valid pool creation failed: %v", err)
	}
}

// TestECON_R15_M_YieldFarming_NilRewardPerBlock verifies that
// NewYieldFarmingManager handles nil rewardPerBlock without panicking.
func TestECON_R15_M_YieldFarming_NilRewardPerBlock(t *testing.T) {
	// nil rewardPerBlock → must default to 0, not panic
	yfm := NewYieldFarmingManager(nil)
	if yfm == nil {
		t.Fatal("ECON-R15-M REGRESSION: NewYieldFarmingManager returned nil")
	}
	if yfm.rewardPerBlock == nil || yfm.rewardPerBlock.Sign() != 0 {
		t.Errorf("ECON-R15-M REGRESSION: nil rewardPerBlock not defaulted to 0, got %v", yfm.rewardPerBlock)
	}
	// negative rewardPerBlock → must be clamped to 0
	yfm2 := NewYieldFarmingManager(big.NewInt(-100))
	if yfm2.rewardPerBlock == nil || yfm2.rewardPerBlock.Sign() != 0 {
		t.Errorf("ECON-R15-M REGRESSION: negative rewardPerBlock not clamped to 0, got %v", yfm2.rewardPerBlock)
	}
}

// TestECON_R15_M_LiquidStaking_CommissionBounds verifies that
// LiquidStakingManager.CreatePool enforces StakingConfig.MinCommission /
// MaxCommission bounds, not just the loose 10000 bps cap.
func TestECON_R15_M_LiquidStaking_CommissionBounds(t *testing.T) {
	cfg := DefaultStakingConfig() // MinCommission=100 (1%), MaxCommission=1500 (15%)
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{1}

	// commissionRate below MinCommission (50 < 100) → must be rejected
	_, err := lsm.CreatePool(operator, "low commission pool", 50)
	if err == nil || !strings.Contains(err.Error(), "below config min") {
		t.Errorf("ECON-R15-M REGRESSION: expected rejection for commissionRate=50 (below min 100), got %v", err)
	}

	// commissionRate above MaxCommission (2000 > 1500) → must be rejected
	lsm2 := NewLiquidStakingManager(cfg, sm)
	_, err = lsm2.CreatePool(operator, "high commission pool", 2000)
	if err == nil || !strings.Contains(err.Error(), "exceeds config max") {
		t.Errorf("ECON-R15-M REGRESSION: expected rejection for commissionRate=2000 (above max 1500), got %v", err)
	}

	// commissionRate within bounds (500 = 5%) → must succeed
	lsm3 := NewLiquidStakingManager(cfg, sm)
	_, err = lsm3.CreatePool(operator, "valid pool", 500)
	if err != nil {
		t.Errorf("ECON-R15-M REGRESSION: valid commissionRate=500 rejected: %v", err)
	}
}
