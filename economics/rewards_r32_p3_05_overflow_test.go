// Quantaureum Node source, version 1.0.0.
// Package economics — R32-P3-05 regression tests.
//
// AUDIT (2026) R32-P3-05: economics reward computation lacked overflow/upper-bound checks.
// big.Int itself does not overflow, but attacker-controlled inputs
// (totalSupply, RewardPerBlock, Multiplier) could produce huge intermediate
// values, causing memory bloat / DoS in downstream multiplications.
//
// The fix adds:
//  1. maxBlockReward cap (10^30 wei = 10^12 QAU) in rewards.go
//  2. CalculateInflationReward clamps totalSupply input and final result
//  3. DistributeRewardAmount rejects totalReward > maxBlockReward
//  4. CreateFarm validates multiplier <= MaxFarmMultiplier (1000000 = 10000x)
//  5. CreateFarm validates rewardPerBlock <= maxBlockReward
//
// These tests verify each defense layer.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR32_P3_05_CalculateInflationReward_ClampsHugeTotalSupply verifies that
// CalculateInflationReward clamps the input totalSupply when it is
// astronomically large (10^100). Without the clamp, the multiplication
// (totalSupply * InflationRate) would produce a huge big.Int, and the
// downstream DistributeRewardAmount multiplications would allocate gigabytes.
func TestR32_P3_05_CalculateInflationReward_ClampsHugeTotalSupply(t *testing.T) {
	rc, err := NewRewardCalculator(nil)
	if err != nil {
		t.Fatalf("NewRewardCalculator failed: %v", err)
	}

	// 10^100 — astronomically larger than any real total supply (20M QAU = 2×10^25)
	hugeSupply := new(big.Int).Exp(big.NewInt(10), big.NewInt(100), nil)
	reward := rc.CalculateInflationReward(hugeSupply)

	if reward == nil {
		t.Fatal("CalculateInflationReward returned nil")
	}
	// The reward must not exceed maxBlockReward (10^30).
	if reward.Cmp(maxBlockReward) > 0 {
		t.Fatalf("R32-P3-05 NOT FIXED: CalculateInflationReward returned %s for huge totalSupply, "+
			"expected <= %s (maxBlockReward)", reward.String(), maxBlockReward.String())
	}
	// The input clamp caps totalSupply at 10^30, so the reward equals:
	//   10^30 * 500 / 10000 / 2628000 = 5*10^28 / 2628000 ≈ 1.9*10^22
	// This is well below maxBlockReward because the division by BlocksPerYear
	// reduces it. The key assertion is that the reward does NOT reflect the
	// original 10^100 input — it reflects the clamped 10^30 input.
	expectedFromClamped := new(big.Int).Set(maxBlockReward) // cappedSupply = 10^30
	expectedFromClamped.Mul(expectedFromClamped, big.NewInt(500))
	expectedFromClamped.Div(expectedFromClamped, big.NewInt(10000))
	expectedFromClamped.Div(expectedFromClamped, new(big.Int).SetUint64(2628000))
	if reward.Cmp(expectedFromClamped) != 0 {
		t.Fatalf("R32-P3-05 NOT FIXED: reward %s does not match clamped calculation %s — "+
			"input totalSupply was not clamped to maxBlockReward",
			reward.String(), expectedFromClamped.String())
	}
	// Sanity: reward must be much smaller than the unclamped would be.
	// Unclamped: 10^100 * 500 / 10000 / 2628000 ≈ 1.9 * 10^92 (astronomical)
	if reward.BitLen() > 100 {
		t.Fatalf("R32-P3-05 NOT FIXED: reward bit length %d suggests input was not clamped "+
			"(expected ~74 bits for 1.9*10^22)", reward.BitLen())
	}
}

// TestR32_P3_05_CalculateInflationReward_NormalSupplyUnaffected verifies that
// normal total supply values (20M QAU = 2×10^25 wei) produce rewards below
// the cap and are not affected by the clamp.
func TestR32_P3_05_CalculateInflationReward_NormalSupplyUnaffected(t *testing.T) {
	rc, err := NewRewardCalculator(nil)
	if err != nil {
		t.Fatalf("NewRewardCalculator failed: %v", err)
	}

	// 20M QAU = 2×10^25 wei (the real total supply)
	normalSupply := new(big.Int).Exp(big.NewInt(10), big.NewInt(25), nil)
	normalSupply.Mul(normalSupply, big.NewInt(2))
	reward := rc.CalculateInflationReward(normalSupply)

	if reward == nil || reward.Sign() <= 0 {
		t.Fatalf("CalculateInflationReward returned non-positive reward: %v", reward)
	}
	// Reward should be well below the cap.
	if reward.Cmp(maxBlockReward) > 0 {
		t.Fatalf("Normal supply reward %s exceeds cap %s — clamp logic is broken",
			reward.String(), maxBlockReward.String())
	}

	// Verify the math: reward = supply * rate / 10000 / blocksPerYear
	// = 10^26 * 500 / 10000 / 2628000 = 10^26 * 0.05 / 2628000 ≈ 1.9 * 10^18
	// which is about 1.9 QAU per block — reasonable.
	expected := new(big.Int).Mul(normalSupply, big.NewInt(500))
	expected.Div(expected, big.NewInt(10000))
	expected.Div(expected, big.NewInt(2628000))
	if reward.Cmp(expected) != 0 {
		t.Fatalf("Expected reward %s, got %s — clamp should not affect normal values",
			expected.String(), reward.String())
	}
}

// TestR32_P3_05_CalculateInflationReward_ZeroSupplyReturnsZero verifies that
// zero/nil total supply returns zero reward (existing behavior preserved).
func TestR32_P3_05_CalculateInflationReward_ZeroSupplyReturnsZero(t *testing.T) {
	rc, err := NewRewardCalculator(nil)
	if err != nil {
		t.Fatalf("NewRewardCalculator failed: %v", err)
	}

	if r := rc.CalculateInflationReward(nil); r.Sign() != 0 {
		t.Fatalf("nil totalSupply should return 0, got %s", r.String())
	}
	if r := rc.CalculateInflationReward(big.NewInt(0)); r.Sign() != 0 {
		t.Fatalf("zero totalSupply should return 0, got %s", r.String())
	}
	if r := rc.CalculateInflationReward(big.NewInt(-1)); r.Sign() != 0 {
		t.Fatalf("negative totalSupply should return 0, got %s", r.String())
	}
}

// TestR32_P3_05_DistributeRewardAmount_RejectsHugeReward verifies that
// DistributeRewardAmount rejects totalReward exceeding maxBlockReward,
// preventing memory DoS from downstream multiplications.
func TestR32_P3_05_DistributeRewardAmount_RejectsHugeReward(t *testing.T) {
	rc, err := NewRewardCalculator(nil)
	if err != nil {
		t.Fatalf("NewRewardCalculator failed: %v", err)
	}
	rd, err := NewRewardDistributor(rc, 1000) // 10% proposer share
	if err != nil {
		t.Fatalf("NewRewardDistributor failed: %v", err)
	}

	// 10^100 — astronomically large reward
	hugeReward := new(big.Int).Exp(big.NewInt(10), big.NewInt(100), nil)
	validators := map[types.Address]*big.Int{
		{1}: big.NewInt(1000),
		{2}: big.NewInt(2000),
	}

	_, err = rd.DistributeRewardAmount(hugeReward, types.Address{1}, validators)
	if err == nil {
		t.Fatal("R32-P3-05 NOT FIXED: DistributeRewardAmount accepted a huge totalReward " +
			"exceeding maxBlockReward — should return ErrRewardExceedsSanityCap")
	}
}

// TestR32_P3_05_DistributeRewardAmount_NormalRewardUnaffected verifies that
// normal reward values pass through DistributeRewardAmount without error.
func TestR32_P3_05_DistributeRewardAmount_NormalRewardUnaffected(t *testing.T) {
	rc, err := NewRewardCalculator(nil)
	if err != nil {
		t.Fatalf("NewRewardCalculator failed: %v", err)
	}
	rd, err := NewRewardDistributor(rc, 1000) // 10% proposer share
	if err != nil {
		t.Fatalf("NewRewardDistributor failed: %v", err)
	}

	// 100 QAU = 10^20 wei — well below the cap
	normalReward := new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)
	validators := map[types.Address]*big.Int{
		{1}: big.NewInt(1000),
		{2}: big.NewInt(2000),
	}

	dist, err := rd.DistributeRewardAmount(normalReward, types.Address{1}, validators)
	if err != nil {
		t.Fatalf("Normal reward should be accepted, got error: %v", err)
	}
	if dist == nil {
		t.Fatal("Distribution should not be nil for valid reward")
	}
}

// TestR32_P3_05_CreateFarm_RejectsHugeMultiplier verifies that CreateFarm
// rejects multiplier values exceeding MaxFarmMultiplier (1000000 = 10000x).
func TestR32_P3_05_CreateFarm_RejectsHugeMultiplier(t *testing.T) {
	yfm := NewYieldFarmingManager(big.NewInt(1e18))

	// Multiplier = MaxFarmMultiplier + 1 — exceeds the cap
	_, err := yfm.CreateFarm(
		"test-farm",
		"TEST-LP",
		"QAU",
		big.NewInt(1e18),
		MaxFarmMultiplier+1,
		types.Address{1},
	)
	if err == nil {
		t.Fatal("R32-P3-05 NOT FIXED: CreateFarm accepted multiplier > MaxFarmMultiplier — " +
			"should reject to prevent reward calculation memory DoS")
	}
}

// TestR32_P3_05_CreateFarm_RejectsHugeRewardPerBlock verifies that CreateFarm
// rejects rewardPerBlock values exceeding maxBlockReward.
func TestR32_P3_05_CreateFarm_RejectsHugeRewardPerBlock(t *testing.T) {
	yfm := NewYieldFarmingManager(big.NewInt(1e18))

	// 10^100 — astronomically large reward per block
	hugeRewardPerBlock := new(big.Int).Exp(big.NewInt(10), big.NewInt(100), nil)
	_, err := yfm.CreateFarm(
		"test-farm",
		"TEST-LP",
		"QAU",
		hugeRewardPerBlock,
		100, // 1x multiplier (legitimate)
		types.Address{1},
	)
	if err == nil {
		t.Fatal("R32-P3-05 NOT FIXED: CreateFarm accepted rewardPerBlock > maxBlockReward — " +
			"should reject to prevent reward calculation memory DoS")
	}
}

// TestR32_P3_05_CreateFarm_RejectsNegativeRewardPerBlock verifies that
// CreateFarm rejects nil/negative rewardPerBlock.
func TestR32_P3_05_CreateFarm_RejectsNegativeRewardPerBlock(t *testing.T) {
	yfm := NewYieldFarmingManager(big.NewInt(1e18))

	// nil rewardPerBlock
	_, err := yfm.CreateFarm("test-farm-nil", "TEST-LP", "QAU", nil, 100, types.Address{1})
	if err == nil {
		t.Fatal("CreateFarm should reject nil rewardPerBlock")
	}

	// negative rewardPerBlock
	negativeReward := big.NewInt(-1)
	_, err = yfm.CreateFarm("test-farm-neg", "TEST-LP", "QAU", negativeReward, 100, types.Address{1})
	if err == nil {
		t.Fatal("CreateFarm should reject negative rewardPerBlock")
	}
}

// TestR32_P3_05_CreateFarm_AcceptsValidMultiplier verifies that CreateFarm
// accepts multiplier values within the valid range (including the cap).
func TestR32_P3_05_CreateFarm_AcceptsValidMultiplier(t *testing.T) {
	yfm := NewYieldFarmingManager(big.NewInt(1e18))

	// MaxFarmMultiplier (the cap) — should be accepted (boundary check)
	farm, err := yfm.CreateFarm(
		"test-farm-max-mult",
		"TEST-LP-MAX",
		"QAU",
		big.NewInt(1e18),
		MaxFarmMultiplier,
		types.Address{1},
	)
	if err != nil {
		t.Fatalf("CreateFarm should accept multiplier == MaxFarmMultiplier, got: %v", err)
	}
	if farm.Multiplier != MaxFarmMultiplier {
		t.Fatalf("Expected multiplier %d, got %d", MaxFarmMultiplier, farm.Multiplier)
	}
}

// TestR32_P3_05_CreateFarm_AcceptsZeroRewardPerBlock verifies that
// CreateFarm accepts zero rewardPerBlock (used for farms that are created
// inactive and later funded via FundRewardPool).
func TestR32_P3_05_CreateFarm_AcceptsZeroRewardPerBlock(t *testing.T) {
	yfm := NewYieldFarmingManager(big.NewInt(1e18))

	farm, err := yfm.CreateFarm(
		"test-farm-zero",
		"TEST-LP-ZERO",
		"QAU",
		big.NewInt(0), // zero is valid (farm starts empty, funded later)
		100,
		types.Address{1},
	)
	if err != nil {
		t.Fatalf("CreateFarm should accept zero rewardPerBlock, got: %v", err)
	}
	if farm == nil {
		t.Fatal("Farm should not be nil")
	}
}

// TestR32_P3_05_MaxBlockReward_Value verifies that maxBlockReward is set to
// 10^30 (matching maxGasPrice). This is a sanity check to ensure the constant
// is not accidentally changed.
func TestR32_P3_05_MaxBlockReward_Value(t *testing.T) {
	expected := new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)
	if maxBlockReward.Cmp(expected) != 0 {
		t.Fatalf("maxBlockReward = %s, expected 10^30 = %s",
			maxBlockReward.String(), expected.String())
	}
	// maxBlockReward should equal maxGasPrice for consistency.
	if maxBlockReward.Cmp(maxGasPrice) != 0 {
		t.Fatalf("maxBlockReward %s != maxGasPrice %s — should match for consistency",
			maxBlockReward.String(), maxGasPrice.String())
	}
}
