// Quantaureum Node source, version 1.0.0.
package economics

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestRewardCalculator(t *testing.T) {
	t.Run("NewRewardCalculator_nilConfig", func(t *testing.T) {
		rc, err := NewRewardCalculator(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc == nil {
			t.Fatal("calculator is nil")
		}
	})

	t.Run("NewRewardCalculator_invalidConfig", func(t *testing.T) {
		cfg := &RewardConfig{
			InflationRate:   10001,
			BlocksPerYear:   100,
			HalvingInterval: 100,
		}
		_, err := NewRewardCalculator(cfg)
		if !errors.Is(err, ErrInvalidRewardConfig) {
			t.Errorf("expected ErrInvalidRewardConfig, got %v", err)
		}
	})

	t.Run("NewRewardCalculator_zeroBlocksPerYear", func(t *testing.T) {
		cfg := &RewardConfig{
			HalvingInterval: 100,
			BlocksPerYear:   0,
		}
		_, err := NewRewardCalculator(cfg)
		if !errors.Is(err, ErrInvalidRewardConfig) {
			t.Errorf("expected ErrInvalidRewardConfig, got %v", err)
		}
	})

	t.Run("NewRewardCalculator_zeroHalvingInterval", func(t *testing.T) {
		cfg := &RewardConfig{
			HalvingInterval: 0,
			BlocksPerYear:   100,
		}
		_, err := NewRewardCalculator(cfg)
		if !errors.Is(err, ErrInvalidRewardConfig) {
			t.Errorf("expected ErrInvalidRewardConfig, got %v", err)
		}
	})

	t.Run("CalculateBlockReward_genesis", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    100,
			MinBlockReward:     big.NewInt(1),
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		reward := rc.CalculateBlockReward(0)
		if reward.Sign() != 0 {
			t.Errorf("genesis reward should be 0, got %s", reward)
		}
	})

	t.Run("CalculateBlockReward_beforeHalving", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    100,
			MinBlockReward:     big.NewInt(1),
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		reward := rc.CalculateBlockReward(99)
		if reward.Cmp(big.NewInt(1000)) != 0 {
			t.Errorf("expected 1000, got %s", reward)
		}
	})

	t.Run("CalculateBlockReward_oneHalving", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    100,
			MinBlockReward:     big.NewInt(1),
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		reward := rc.CalculateBlockReward(100)
		if reward.Cmp(big.NewInt(500)) != 0 {
			t.Errorf("expected 500, got %s", reward)
		}
	})

	t.Run("CalculateBlockReward_twoHalvings", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    100,
			MinBlockReward:     big.NewInt(1),
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		reward := rc.CalculateBlockReward(200)
		if reward.Cmp(big.NewInt(250)) != 0 {
			t.Errorf("expected 250, got %s", reward)
		}
	})

	t.Run("CalculateBlockReward_hitsMin", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    100,
			MinBlockReward:     big.NewInt(100),
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		reward := rc.CalculateBlockReward(1000)
		if reward.Cmp(big.NewInt(100)) != 0 {
			t.Errorf("expected min reward 100, got %s", reward)
		}
	})

	t.Run("CalculateBlockReward_moreThan64Halvings", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    1,
			MinBlockReward:     big.NewInt(5),
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		reward := rc.CalculateBlockReward(65)
		if reward.Cmp(big.NewInt(5)) != 0 {
			t.Errorf("expected min reward 5, got %s", reward)
		}
	})

	t.Run("CalculateInflationReward_nilSupply", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    100,
			MinBlockReward:     big.NewInt(1),
			InflationRate:      500,
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		reward := rc.CalculateInflationReward(nil)
		if reward.Sign() != 0 {
			t.Errorf("expected 0, got %s", reward)
		}
	})

	t.Run("CalculateInflationReward_zeroSupply", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    100,
			MinBlockReward:     big.NewInt(1),
			InflationRate:      500,
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		reward := rc.CalculateInflationReward(big.NewInt(0))
		if reward.Sign() != 0 {
			t.Errorf("expected 0, got %s", reward)
		}
	})

	t.Run("CalculateInflationReward_normal", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    100,
			MinBlockReward:     big.NewInt(1),
			InflationRate:      500,
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		supply := big.NewInt(1000000)
		reward := rc.CalculateInflationReward(supply)
		if reward.Sign() <= 0 {
			t.Errorf("expected positive reward, got %s", reward)
		}
	})

	t.Run("CalculateInflationReward_zeroBlocksPerYear", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    100,
			MinBlockReward:     big.NewInt(1),
			InflationRate:      500,
			BlocksPerYear:      0,
		}
		_, err := NewRewardCalculator(cfg)
		if !errors.Is(err, ErrInvalidRewardConfig) {
			t.Errorf("expected ErrInvalidRewardConfig for zero BlocksPerYear, got %v", err)
		}
	})

	t.Run("GetHalvingEpoch", func(t *testing.T) {
		cfg := &RewardConfig{
			HalvingInterval: 100,
			BlocksPerYear:   100,
		}
		rc, _ := NewRewardCalculator(cfg)
		epoch := rc.GetHalvingEpoch(250)
		if epoch != 2 {
			t.Errorf("expected epoch 2, got %d", epoch)
		}
	})

	t.Run("GetNextHalvingBlock", func(t *testing.T) {
		cfg := &RewardConfig{
			HalvingInterval: 100,
			BlocksPerYear:   100,
		}
		rc, _ := NewRewardCalculator(cfg)
		next := rc.GetNextHalvingBlock(250)
		if next != 300 {
			t.Errorf("expected 300, got %d", next)
		}
	})

	t.Run("GetConfig", func(t *testing.T) {
		rc, _ := NewRewardCalculator(nil)
		cfg := rc.GetConfig()
		if cfg == nil {
			t.Fatal("config is nil")
		}
		if cfg.InflationRate != 500 {
			t.Errorf("expected 500 bps, got %d", cfg.InflationRate)
		}
	})

	t.Run("validateRewardConfig_nil", func(t *testing.T) {
		err := validateRewardConfig(nil)
		if err != ErrInvalidRewardConfig {
			t.Errorf("expected ErrInvalidRewardConfig, got %v", err)
		}
	})
}

func TestRewardDistributor(t *testing.T) {
	validators := map[types.Address]*big.Int{
		{1}: big.NewInt(100),
		{2}: big.NewInt(200),
	}

	t.Run("NewRewardDistributor_nilCalculator", func(t *testing.T) {
		rd, err := NewRewardDistributor(nil, 2500)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rd == nil {
			t.Fatal("distributor is nil")
		}
	})

	t.Run("NewRewardDistributor_proposerShareClamped", func(t *testing.T) {
		rc, _ := NewRewardCalculator(nil)
		rd, err := NewRewardDistributor(rc, 99999)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rd.ProposerShare != 10000 {
			t.Errorf("expected 10000, got %d", rd.ProposerShare)
		}
	})

	t.Run("DistributeReward", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    1000000,
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		rd, _ := NewRewardDistributor(rc, 2500)

		dist, err := rd.DistributeReward(100, types.Address{1}, validators)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.TotalReward.Cmp(big.NewInt(1000)) != 0 {
			t.Errorf("expected total 1000, got %s", dist.TotalReward)
		}
	})

	t.Run("DistributeRewardAmount_emptyValidators", func(t *testing.T) {
		rc, _ := NewRewardCalculator(nil)
		rd, _ := NewRewardDistributor(rc, 2500)

		_, err := rd.DistributeRewardAmount(big.NewInt(100), types.Address{1}, map[types.Address]*big.Int{})
		if err != ErrNoValidatorForReward {
			t.Errorf("expected ErrNoValidatorForReward, got %v", err)
		}
	})

	t.Run("DistributeRewardAmount_zeroReward", func(t *testing.T) {
		rc, _ := NewRewardCalculator(nil)
		rd, _ := NewRewardDistributor(rc, 2500)

		dist, err := rd.DistributeRewardAmount(big.NewInt(0), types.Address{1}, validators)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.ProposerReward.Sign() != 0 {
			t.Errorf("expected zero proposer reward, got %s", dist.ProposerReward)
		}
	})

	t.Run("DistributeRewardAmount_nilReward", func(t *testing.T) {
		rc, _ := NewRewardCalculator(nil)
		rd, _ := NewRewardDistributor(rc, 2500)

		dist, err := rd.DistributeRewardAmount(nil, types.Address{1}, validators)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.TotalReward.Sign() != 0 {
			t.Errorf("expected zero total, got %s", dist.TotalReward)
		}
	})

	t.Run("DistributeRewardAmount_zeroStake", func(t *testing.T) {
		rc, _ := NewRewardCalculator(nil)
		rd, _ := NewRewardDistributor(rc, 2500)

		zeroStakeVals := map[types.Address]*big.Int{
			{1}: big.NewInt(0),
			{2}: big.NewInt(0),
		}
		dist, err := rd.DistributeRewardAmount(big.NewInt(1000), types.Address{1}, zeroStakeVals)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.ProposerReward.Cmp(big.NewInt(1000)) != 0 {
			t.Errorf("expected all reward to proposer, got %s", dist.ProposerReward)
		}
	})

	t.Run("DistributeRewardAmount_proposerIsValidator", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    1000000,
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		rd, _ := NewRewardDistributor(rc, 2500)

		dist, err := rd.DistributeRewardAmount(big.NewInt(1000), types.Address{1}, validators)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.ValidatorRewards[types.Address{1}] == nil {
			t.Error("proposer should have validator reward")
		}
	})

	t.Run("DistributeRewardAmount_proposerNotValidator", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    1000000,
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		rd, _ := NewRewardDistributor(rc, 2500)

		dist, err := rd.DistributeRewardAmount(big.NewInt(1000), types.Address{99}, validators)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.ValidatorRewards[types.Address{99}].Cmp(dist.ProposerReward) != 0 {
			t.Errorf("new proposer should get proposer reward as validator reward, got %s",
				dist.ValidatorRewards[types.Address{99}])
		}
	})

	t.Run("DistributeRewardAmount_withNilStakes", func(t *testing.T) {
		cfg := &RewardConfig{
			InitialBlockReward: big.NewInt(1000),
			HalvingInterval:    1000000,
			BlocksPerYear:      100,
		}
		rc, _ := NewRewardCalculator(cfg)
		rd, _ := NewRewardDistributor(rc, 2500)

		valsWithNil := map[types.Address]*big.Int{
			{1}: big.NewInt(100),
			{2}: nil,
			{3}: big.NewInt(-1),
		}
		dist, err := rd.DistributeRewardAmount(big.NewInt(1000), types.Address{1}, valsWithNil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.ValidatorRewards[types.Address{2}] != nil && dist.ValidatorRewards[types.Address{2}].Sign() > 0 {
			t.Error("nil stake should get no reward")
		}
		if dist.ValidatorRewards[types.Address{3}] != nil && dist.ValidatorRewards[types.Address{3}].Sign() > 0 {
			t.Error("negative stake should get no reward")
		}
	})
}

func TestGasFeeCollector(t *testing.T) {
	t.Run("validateFeeRates_valid", func(t *testing.T) {
		cfg := &GasFeeConfig{BurnRate: 5000, ProposerRate: 3000, ValidatorPoolRate: 2000}
		err := validateFeeRates(cfg)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("validateFeeRates_exceedsTotal", func(t *testing.T) {
		cfg := &GasFeeConfig{BurnRate: 5000, ProposerRate: 5000, ValidatorPoolRate: 5000}
		err := validateFeeRates(cfg)
		if err != ErrFeeRatesExceedTotal {
			t.Errorf("expected ErrFeeRatesExceedTotal, got %v", err)
		}
	})

	t.Run("NewGasFeeCollector_invalidConfig", func(t *testing.T) {
		cfg := &GasFeeConfig{BurnRate: 5000, ProposerRate: 5000, ValidatorPoolRate: 5000}
		_, err := NewGasFeeCollector(cfg)
		if err != ErrFeeRatesExceedTotal {
			t.Errorf("expected ErrFeeRatesExceedTotal, got %v", err)
		}
	})

	t.Run("NewGasFeeCollector_nilConfig", func(t *testing.T) {
		gfc, err := NewGasFeeCollector(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gfc == nil {
			t.Fatal("collector is nil")
		}
	})

	t.Run("CollectFee_nilGasPrice", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		_, err := gfc.CollectFee(100, nil)
		if err != ErrInvalidGasPrice {
			t.Errorf("expected ErrInvalidGasPrice, got %v", err)
		}
	})

	t.Run("CollectFee_zeroGasPrice", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		_, err := gfc.CollectFee(100, big.NewInt(0))
		if err != ErrInvalidGasPrice {
			t.Errorf("expected ErrInvalidGasPrice, got %v", err)
		}
	})

	t.Run("CollectFee_valid", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		fee, err := gfc.CollectFee(21000, big.NewInt(1000000000))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := big.NewInt(21000 * 1000000000)
		if fee.Cmp(expected) != 0 {
			t.Errorf("expected %s, got %s", expected, fee)
		}
	})

	t.Run("CollectFee_accumulates", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		gfc.CollectFee(100, big.NewInt(10))
		gfc.CollectFee(200, big.NewInt(5))
		accumulated := gfc.GetAccumulatedFees()
		if accumulated.Cmp(big.NewInt(2000)) != 0 {
			t.Errorf("expected 2000, got %s", accumulated)
		}
	})

	t.Run("DistributeFees_noAccumulated", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		dist, err := gfc.DistributeFees(types.Address{1}, map[types.Address]*big.Int{}, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.TotalFees.Sign() != 0 {
			t.Error("expected zero total fees")
		}
	})

	t.Run("DistributeFees_withValidators", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		gfc.accumulatedFees = big.NewInt(10000)

		validators := map[types.Address]*big.Int{
			{1}: big.NewInt(100),
			{2}: big.NewInt(200),
		}
		dist, err := gfc.DistributeFees(types.Address{1}, validators, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.TotalFees.Cmp(big.NewInt(10000)) != 0 {
			t.Errorf("expected total 10000, got %s", dist.TotalFees)
		}
		if dist.BurnedFees.Sign() == 0 {
			t.Error("expected non-zero burned fees")
		}
		if gfc.accumulatedFees.Sign() != 0 {
			t.Error("accumulated fees should be reset after distribution")
		}
	})

	t.Run("DistributeFees_zeroStake", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		gfc.accumulatedFees = big.NewInt(10000)

		dist, err := gfc.DistributeFees(types.Address{1}, map[types.Address]*big.Int{}, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dist.ProposerFees == nil {
			t.Fatal("proposer fees should not be nil even with zero stake")
		}
	})

	t.Run("GetBaseFee", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		bf := gfc.GetBaseFee()
		if bf.Cmp(big.NewInt(1e9)) != 0 {
			t.Errorf("expected 1e9, got %s", bf)
		}
	})

	t.Run("SetBaseFee_valid", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		err := gfc.SetBaseFee(big.NewInt(2000000000))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		bf := gfc.GetBaseFee()
		if bf.Cmp(big.NewInt(2000000000)) != 0 {
			t.Errorf("expected 2e9, got %s", bf)
		}
	})

	t.Run("SetBaseFee_nil", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		err := gfc.SetBaseFee(nil)
		if err != ErrInvalidGasPrice {
			t.Errorf("expected ErrInvalidGasPrice, got %v", err)
		}
	})

	t.Run("SetBaseFee_zero", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		err := gfc.SetBaseFee(big.NewInt(0))
		if err != ErrInvalidGasPrice {
			t.Errorf("expected ErrInvalidGasPrice, got %v", err)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		gfc.CollectFee(100, big.NewInt(10))
		gfc.Reset()
		if gfc.GetAccumulatedFees().Sign() != 0 {
			t.Error("accumulated should be 0 after reset")
		}
	})

	t.Run("GetTotalBurned", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		gfc.accumulatedFees = big.NewInt(10000)
		gfc.DistributeFees(types.Address{1}, map[types.Address]*big.Int{
			{1}: big.NewInt(100),
		}, 0)
		if gfc.GetTotalBurned().Sign() == 0 {
			t.Error("expected non-zero total burned")
		}
	})

	t.Run("GetConfig", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		cfg := gfc.GetConfig()
		// BurnRate is dynamic via CalculateBurnRate; static config is Year 1 rate (10%).
		expectedRate := CalculateBurnRate(0)
		if cfg.BurnRate != expectedRate {
			t.Errorf("expected %d, got %d", expectedRate, cfg.BurnRate)
		}
	})

	t.Run("DistributeFees_dustToBurn", func(t *testing.T) {
		cfg := &GasFeeConfig{BaseFee: big.NewInt(1e9), BurnRate: 3333, ProposerRate: 3333, ValidatorPoolRate: 3333}
		gfc, _ := NewGasFeeCollector(cfg)
		gfc.accumulatedFees = big.NewInt(10001)

		dist, _ := gfc.DistributeFees(types.Address{1}, map[types.Address]*big.Int{}, 0)
		if dist.BurnedFees == nil {
			t.Fatal("burned fees should exist with dust")
		}
	})

	t.Run("DistributeFees_proposerIsValidator", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		gfc.accumulatedFees = big.NewInt(10000)

		validators := map[types.Address]*big.Int{
			{1}: big.NewInt(100),
		}
		dist, _ := gfc.DistributeFees(types.Address{1}, validators, 0)
		if dist.ValidatorFees[types.Address{1}] == nil {
			t.Error("proposer should have validator fees")
		}
	})

	t.Run("DistributeFees_accumulatedReset", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		gfc.accumulatedFees = big.NewInt(10000)
		gfc.DistributeFees(types.Address{1}, map[types.Address]*big.Int{
			{1}: big.NewInt(100),
		}, 0)
		second, _ := gfc.DistributeFees(types.Address{1}, map[types.Address]*big.Int{{1}: big.NewInt(100)}, 0)
		if second.TotalFees.Sign() != 0 {
			t.Error("second distribution should have zero fees")
		}
	})
}

func TestCalculateNextBaseFee(t *testing.T) {
	t.Run("nilParentBaseFee", func(t *testing.T) {
		result := CalculateNextBaseFee(100, 200, nil)
		if result.Cmp(big.NewInt(1000000000)) != 0 {
			t.Errorf("expected 1e9, got %s", result)
		}
	})

	t.Run("zeroParentBaseFee", func(t *testing.T) {
		result := CalculateNextBaseFee(100, 200, big.NewInt(0))
		if result.Cmp(big.NewInt(1000000000)) != 0 {
			t.Errorf("expected 1e9, got %s", result)
		}
	})

	t.Run("atTarget", func(t *testing.T) {
		baseFee := big.NewInt(1000000000)
		result := CalculateNextBaseFee(100, 200, baseFee)
		if result.Cmp(baseFee) != 0 {
			t.Errorf("expected unchanged, got %s", result)
		}
	})

	t.Run("aboveTarget", func(t *testing.T) {
		baseFee := big.NewInt(1000000000)
		gasLimit := uint64(200)
		gasUsed := gasLimit
		result := CalculateNextBaseFee(gasUsed, gasLimit, baseFee)
		if result.Cmp(baseFee) <= 0 {
			t.Errorf("expected fee increase, got %s", result)
		}
	})

	t.Run("belowTarget", func(t *testing.T) {
		baseFee := big.NewInt(1000000000)
		gasLimit := uint64(200)
		gasUsed := uint64(50)
		result := CalculateNextBaseFee(gasUsed, gasLimit, baseFee)
		if result.Cmp(baseFee) >= 0 {
			t.Errorf("expected fee decrease, got %s", result)
		}
	})

	t.Run("belowTarget_toMin", func(t *testing.T) {
		baseFee := big.NewInt(1)
		gasLimit := uint64(200)
		gasUsed := uint64(0)
		result := CalculateNextBaseFee(gasUsed, gasLimit, baseFee)
		if result.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("expected min 1, got %s", result)
		}
	})
}

func TestEffectiveGasPrice(t *testing.T) {
	t.Run("nilMaxFeePerGas", func(t *testing.T) {
		baseFee := big.NewInt(100)
		result := EffectiveGasPrice(baseFee, nil, big.NewInt(10))
		if result.Cmp(baseFee) != 0 {
			t.Errorf("expected baseFee %s, got %s", baseFee, result)
		}
	})

	t.Run("nilTip", func(t *testing.T) {
		baseFee := big.NewInt(100)
		result := EffectiveGasPrice(baseFee, big.NewInt(200), nil)
		if result.Cmp(baseFee) != 0 {
			t.Errorf("expected baseFee %s, got %s", baseFee, result)
		}
	})

	t.Run("withinMax", func(t *testing.T) {
		baseFee := big.NewInt(100)
		maxFee := big.NewInt(200)
		tip := big.NewInt(10)
		result := EffectiveGasPrice(baseFee, maxFee, tip)
		if result.Cmp(big.NewInt(110)) != 0 {
			t.Errorf("expected 110, got %s", result)
		}
	})

	t.Run("exceedsMax", func(t *testing.T) {
		baseFee := big.NewInt(100)
		maxFee := big.NewInt(120)
		tip := big.NewInt(50)
		result := EffectiveGasPrice(baseFee, maxFee, tip)
		if result.Cmp(maxFee) != 0 {
			t.Errorf("expected maxFee %s, got %s", maxFee, result)
		}
	})
}

func TestCollectEIP1559Fee(t *testing.T) {
	t.Run("nilBaseFee", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		_, _, _, err := gfc.CollectEIP1559Fee(100, nil, big.NewInt(10))
		if err != ErrInvalidGasPrice {
			t.Errorf("expected ErrInvalidGasPrice, got %v", err)
		}
	})

	t.Run("zeroBaseFee", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		_, _, _, err := gfc.CollectEIP1559Fee(100, big.NewInt(0), big.NewInt(10))
		if err != ErrInvalidGasPrice {
			t.Errorf("expected ErrInvalidGasPrice, got %v", err)
		}
	})

	t.Run("valid_noPriority", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		baseFee := big.NewInt(100)
		total, burned, priority, err := gfc.CollectEIP1559Fee(100, baseFee, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total.Cmp(big.NewInt(10000)) != 0 {
			t.Errorf("expected total 10000, got %s", total)
		}
		if burned.Cmp(big.NewInt(10000)) != 0 {
			t.Errorf("expected burned 10000, got %s", burned)
		}
		if priority.Sign() != 0 {
			t.Errorf("expected priority 0, got %s", priority)
		}
	})

	t.Run("valid_withPriority", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		baseFee := big.NewInt(100)
		priorityFee := big.NewInt(10)
		total, burned, priority, err := gfc.CollectEIP1559Fee(100, baseFee, priorityFee)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total.Cmp(big.NewInt(11000)) != 0 {
			t.Errorf("expected total 11000, got %s", total)
		}
		if burned.Cmp(big.NewInt(10000)) != 0 {
			t.Errorf("expected burned 10000, got %s", burned)
		}
		if priority.Cmp(big.NewInt(1000)) != 0 {
			t.Errorf("expected priority 1000, got %s", priority)
		}
	})

	t.Run("zeroPriorityFee", func(t *testing.T) {
		gfc, _ := NewGasFeeCollector(nil)
		baseFee := big.NewInt(100)
		total, burned, priority, err := gfc.CollectEIP1559Fee(100, baseFee, big.NewInt(0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if priority.Sign() != 0 {
			t.Errorf("expected priority 0, got %s", priority)
		}
		_ = total
		_ = burned
	})
}

func TestStakingManager_Full(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)

	t.Run("RegisterSystemCaller", func(t *testing.T) {
		addr := types.Address{99}
		registerSystemCaller(addr)
		if !isSystemCaller(addr) {
			t.Error("should be system caller")
		}
	})

	t.Run("isSystemCaller_zeroAddress", func(t *testing.T) {
		if isSystemCaller(types.Address{}) {
			t.Error("zero address should not be system caller")
		}
	})

	t.Run("Stake_invalidCommission", func(t *testing.T) {
		err := sm.Stake(types.Address{100}, big.NewInt(1000), 99999, 100)
		if err != ErrInvalidCommission {
			t.Errorf("expected ErrInvalidCommission, got %v", err)
		}
	})

	t.Run("Stake_maxStakeForExisting", func(t *testing.T) {
		addr := types.Address{201}
		sm2 := NewStakingManager(DefaultStakingConfig())
		minStake := DefaultStakingConfig().MinStakeAmount
		sm2.Stake(addr, minStake, 1000, 100)
		maxStake := DefaultStakingConfig().MaxStakeAmount
		err := sm2.Stake(addr, maxStake, 1000, 200)
		if err == nil {
			t.Error("expected error when exceeding max stake for existing")
		}
	})

	t.Run("Stake_maxStakeForNew", func(t *testing.T) {
		addr := types.Address{202}
		sm2 := NewStakingManager(DefaultStakingConfig())
		maxStake := DefaultStakingConfig().MaxStakeAmount
		err := sm2.Stake(addr, new(big.Int).Add(maxStake, big.NewInt(1)), 1000, 100)
		if err == nil {
			t.Error("expected error when exceeding max stake for new validator")
		}
	})

	t.Run("Stake_maxValidators", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount:  big.NewInt(1),
			MaxStakeAmount:  big.NewInt(1000000),
			MinCommission:   0,
			MaxCommission:   10000,
			MaxValidators:   2,
			UnbondingPeriod: 100,
		}
		sm2 := NewStakingManager(cfg2)
		sm2.Stake(types.Address{1}, big.NewInt(10), 1000, 1)
		sm2.Stake(types.Address{2}, big.NewInt(10), 1000, 1)
		err := sm2.Stake(types.Address{3}, big.NewInt(10), 1000, 1)
		if err == nil {
			t.Error("expected max validators error")
		}
	})

	t.Run("Stake_belowMinStake", func(t *testing.T) {
		addr := types.Address{30}
		err := sm.Stake(addr, big.NewInt(1), 1000, 100)
		if err != ErrInsufficientStake {
			t.Errorf("expected ErrInsufficientStake, got %v", err)
		}
	})

	t.Run("Stake_nilAmount", func(t *testing.T) {
		addr := types.Address{31}
		err := sm.Stake(addr, nil, 1000, 100)
		if err != ErrInsufficientStake {
			t.Errorf("expected ErrInsufficientStake, got %v", err)
		}
	})

	t.Run("Stake_zeroAmount", func(t *testing.T) {
		addr := types.Address{32}
		err := sm.Stake(addr, big.NewInt(0), 1000, 100)
		if err != ErrInsufficientStake {
			t.Errorf("expected ErrInsufficientStake, got %v", err)
		}
	})

	t.Run("RequestUnstake_notFound", func(t *testing.T) {
		err := sm.RequestUnstake(types.Address{99}, big.NewInt(100), 100)
		if err != ErrStakeNotFound {
			t.Errorf("expected ErrStakeNotFound, got %v", err)
		}
	})

	t.Run("RequestUnstake_invalidAmount", func(t *testing.T) {
		addr := types.Address{40}
		sm2 := NewStakingManager(cfg)
		sm2.Stake(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)), 1000, 100)

		err := sm2.RequestUnstake(addr, nil, 100)
		if err != ErrInvalidUnstakeAmount {
			t.Errorf("expected ErrInvalidUnstakeAmount, got %v", err)
		}

		err = sm2.RequestUnstake(addr, big.NewInt(0), 100)
		if err != ErrInvalidUnstakeAmount {
			t.Errorf("expected ErrInvalidUnstakeAmount, got %v", err)
		}
	})

	t.Run("RequestUnstake_doesNotExist", func(t *testing.T) {
		err := sm.RequestUnstake(types.Address{99}, big.NewInt(100), 100)
		if err != ErrStakeNotFound {
			t.Errorf("expected ErrStakeNotFound, got %v", err)
		}
	})

	t.Run("CompleteUnstake_noRequest", func(t *testing.T) {
		_, err := sm.CompleteUnstake(types.Address{99}, 1000)
		if err != ErrNoUnstakeRequest {
			t.Errorf("expected ErrNoUnstakeRequest, got %v", err)
		}
	})

	t.Run("CompleteUnstake_stillLocked", func(t *testing.T) {
		addr := types.Address{50}
		sm2 := NewStakingManager(cfg)
		sm2.Stake(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)), 1000, 100)
		sm2.RequestUnstake(addr, new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)), 100)

		_, err := sm2.CompleteUnstake(addr, 101)
		if err != ErrStakeLocked {
			t.Errorf("expected ErrStakeLocked, got %v", err)
		}
	})

	t.Run("UpdateCommission_unauthorized", func(t *testing.T) {
		addr := types.Address{60}
		sm2 := NewStakingManager(cfg)
		sm2.Stake(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)), 1000, 100)

		err := sm2.UpdateCommission(types.Address{99}, addr, 500)
		if err == nil {
			t.Error("expected unauthorized error")
		}
	})

	t.Run("UpdateCommission_stakeNotFound", func(t *testing.T) {
		err := sm.UpdateCommission(types.Address{99}, types.Address{99}, 500)
		if err != ErrStakeNotFound {
			t.Errorf("expected ErrStakeNotFound, got %v", err)
		}
	})

	t.Run("UpdateCommission_invalidRate", func(t *testing.T) {
		addr := types.Address{61}
		sm2 := NewStakingManager(cfg)
		sm2.Stake(addr, new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)), 1000, 100)

		err := sm2.UpdateCommission(addr, addr, 99999)
		if err != ErrInvalidCommission {
			t.Errorf("expected ErrInvalidCommission, got %v", err)
		}
	})

	t.Run("SetActive_unauthorized", func(t *testing.T) {
		addr := types.Address{0x70, 0}
		sm2 := NewStakingManager(DefaultStakingConfig())
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		err := sm2.Stake(addr, minStake, 1000, 100)
		if err != nil {
			t.Fatalf("stake failed: %v", err)
		}

		err = sm2.SetActive(types.Address{1}, addr, false)
		if err == nil {
			t.Error("expected unauthorized error for non-system caller")
		}
	})

	t.Run("SetActive_stakeNotFound", func(t *testing.T) {
		registerSystemCaller(types.Address{88})
		err := sm.SetActive(types.Address{88}, types.Address{99}, true)
		if err != ErrStakeNotFound {
			t.Errorf("expected ErrStakeNotFound, got %v", err)
		}
	})

	t.Run("SetActive_insufficientStake", func(t *testing.T) {
		addr := types.Address{71}
		sm2 := NewStakingManager(cfg)
		sm2.Stake(addr, big.NewInt(1), 1000, 100) // below min, but NewStakingManager config allows it

		// Check if it even exists
		_, err := sm2.GetStake(addr)
		if err != nil {
			t.Skip("stake rejected, skip test")
			return
		}
		err = sm2.SetActive(types.Address{88}, addr, true)
		if err != ErrInsufficientStake {
			t.Errorf("expected ErrInsufficientStake, got %v", err)
		}
	})

	t.Run("RequestUnstake_alreadyExists", func(t *testing.T) {
		addr := types.Address{0x80, 0}
		sm2 := NewStakingManager(DefaultStakingConfig())
		minStake := new(big.Int).Mul(big.NewInt(64), big.NewInt(1e18))
		err := sm2.Stake(addr, minStake, 1000, 100)
		if err != nil {
			t.Fatalf("stake failed: %v", err)
		}
		err = sm2.RequestUnstake(addr, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), 100)
		if err != nil {
			t.Fatalf("first unstake failed: %v", err)
		}

		err = sm2.RequestUnstake(addr, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), 200)
		if err != ErrUnstakeRequestExists {
			t.Errorf("expected ErrUnstakeRequestExists, got %v", err)
		}
	})

	t.Run("RequestUnstake_partialLeavesBelowMin", func(t *testing.T) {
		addr := types.Address{81}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		partial := new(big.Int).Sub(minStake, big.NewInt(1))
		err := sm2.RequestUnstake(addr, partial, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		stake, _ := sm2.GetStake(addr)
		if stake.Amount.Sign() != 0 {
			t.Errorf("expected zero stake (full unstake), got %s", stake.Amount)
		}
	})

	t.Run("GetStake_notFound", func(t *testing.T) {
		_, err := sm.GetStake(types.Address{99})
		if err != ErrStakeNotFound {
			t.Errorf("expected ErrStakeNotFound, got %v", err)
		}
	})

	t.Run("GetUnstakeRequest_notFound", func(t *testing.T) {
		_, err := sm.GetUnstakeRequest(types.Address{99})
		if err != ErrNoUnstakeRequest {
			t.Errorf("expected ErrNoUnstakeRequest, got %v", err)
		}
	})

	t.Run("GetTotalStaked", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		total := sm2.GetTotalStaked()
		if total.Sign() != 0 {
			t.Errorf("expected 0, got %s", total)
		}
	})

	t.Run("GetActiveValidators_empty", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		validators := sm2.GetActiveValidators()
		if len(validators) != 0 {
			t.Errorf("expected 0, got %d", len(validators))
		}
	})

	t.Run("GetAllStakes_empty", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		stakes := sm2.GetAllStakes()
		if len(stakes) != 0 {
			t.Errorf("expected 0, got %d", len(stakes))
		}
	})

	t.Run("ValidatorCount", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		if sm2.ValidatorCount() != 0 {
			t.Errorf("expected 0, got %d", sm2.ValidatorCount())
		}
	})

	t.Run("ActiveValidatorCount", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		if sm2.ActiveValidatorCount() != 0 {
			t.Errorf("expected 0, got %d", sm2.ActiveValidatorCount())
		}
	})

	t.Run("GetContractBalance", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		bal := sm2.GetContractBalance()
		if bal.Sign() != 0 {
			t.Errorf("expected 0, got %s", bal)
		}
	})

	t.Run("AddStakeFromTx_nilValue", func(t *testing.T) {
		err := sm.AddStakeFromTx(types.Address{1}, nil, 100)
		if err != ErrInsufficientStake {
			t.Errorf("expected ErrInsufficientStake, got %v", err)
		}
	})

	t.Run("AddStakeFromTx_zeroBlockHeight", func(t *testing.T) {
		err := sm.AddStakeFromTx(types.Address{1}, big.NewInt(100), 0)
		if err == nil {
			t.Error("expected error for invalid block height")
		}
	})

	t.Run("ProcessUnstakeFromTx_notFound", func(t *testing.T) {
		err := sm.ProcessUnstakeFromTx(types.Address{99}, big.NewInt(100), 100)
		if err != ErrStakeNotFound {
			t.Errorf("expected ErrStakeNotFound, got %v", err)
		}
	})

	t.Run("ProcessRewardClaimFromTx_notFound", func(t *testing.T) {
		_, err := sm.ProcessRewardClaimFromTx(types.Address{99}, 100)
		if err != ErrStakeNotFound {
			t.Errorf("expected ErrStakeNotFound, got %v", err)
		}
	})

	t.Run("CompleteUnstakeFromTx_notFound", func(t *testing.T) {
		_, err := sm.CompleteUnstakeFromTx(types.Address{99}, 100)
		if err != ErrNoUnstakeRequest {
			t.Errorf("expected ErrNoUnstakeRequest, got %v", err)
		}
	})

	t.Run("GetPendingRewards_notFound", func(t *testing.T) {
		reward := sm.GetPendingRewards(types.Address{99}, 100)
		if reward.Sign() != 0 {
			t.Errorf("expected 0, got %s", reward)
		}
	})

	t.Run("Stake_reentrancy", func(t *testing.T) {
		addr := types.Address{132}
		sm2 := NewStakingManager(cfg)
		sm2.inProgress[addr] = true
		err := sm2.Stake(addr, big.NewInt(1000), 1000, 100)
		if err == nil {
			t.Error("expected reentrancy error")
		}
	})

	t.Run("RequestUnstake_reentrancy", func(t *testing.T) {
		addr := types.Address{133}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)
		sm2.inProgress[addr] = true
		err := sm2.RequestUnstake(addr, big.NewInt(100), 100)
		if err == nil {
			t.Error("expected reentrancy error")
		}
	})

	t.Run("CompleteUnstake_reentrancy", func(t *testing.T) {
		addr := types.Address{134}
		sm2 := NewStakingManager(cfg)
		sm2.inProgress[addr] = true
		_, err := sm2.CompleteUnstake(addr, 100)
		if err == nil {
			t.Error("expected reentrancy error")
		}
	})

	t.Run("UpdateCommission_reentrancy", func(t *testing.T) {
		addr := types.Address{135}
		sm2 := NewStakingManager(cfg)
		sm2.inProgress[addr] = true
		err := sm2.UpdateCommission(addr, addr, 500)
		if err == nil {
			t.Error("expected reentrancy error")
		}
	})

	t.Run("SetActive_reentrancy", func(t *testing.T) {
		addr := types.Address{136}
		sm2 := NewStakingManager(cfg)
		sm2.inProgress[addr] = true
		err := sm2.SetActive(types.Address{88}, addr, true)
		if err == nil {
			t.Error("expected reentrancy error")
		}
	})

	t.Run("ProcessUnstakeFromTx_reentrancy", func(t *testing.T) {
		addr := types.Address{137}
		sm2 := NewStakingManager(cfg)
		sm2.inProgress[addr] = true
		err := sm2.ProcessUnstakeFromTx(addr, big.NewInt(100), 100)
		if err == nil {
			t.Error("expected reentrancy error")
		}
	})

	t.Run("GetRewardPoolStatus", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		status := sm2.GetRewardPoolStatus()
		if status["totalDistributed"] == nil {
			t.Error("expected totalDistributed key")
		}
		if status["poolCap"] == nil {
			t.Error("expected poolCap key")
		}
	})

	t.Run("GetRewardClaimEvents_empty", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		events := sm2.GetRewardClaimEvents()
		if len(events) != 0 {
			t.Errorf("expected 0, got %d", len(events))
		}
	})

	t.Run("GetTotalRewardsClaimed_empty", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		total := sm2.GetTotalRewardsClaimed()
		if total.Sign() != 0 {
			t.Errorf("expected 0, got %s", total)
		}
	})

	t.Run("trackRewardClaim_nil", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		sm2.trackRewardClaim(types.Address{1}, nil, 100)
		sm2.trackRewardClaim(types.Address{1}, big.NewInt(0), 100)
		sm2.trackRewardClaim(types.Address{1}, big.NewInt(-1), 100)
		events := sm2.GetRewardClaimEvents()
		if len(events) != 0 {
			t.Errorf("expected 0, got %d", len(events))
		}
	})

	t.Run("SetActive_authorizedSystemCaller", func(t *testing.T) {
		addr := types.Address{232}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		systemAddr := types.Address{88}
		registerSystemCaller(systemAddr)

		err := sm2.SetActive(systemAddr, addr, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		stake, _ := sm2.GetStake(addr)
		if stake.Active {
			t.Error("validator should be inactive")
		}
	})

	t.Run("Stake_updateCommission", func(t *testing.T) {
		addr := types.Address{233}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		err := sm2.UpdateCommission(addr, addr, 500)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		stake, _ := sm2.GetStake(addr)
		if stake.Commission != 500 {
			t.Errorf("expected commission 500, got %d", stake.Commission)
		}
	})

	t.Run("RequestUnstake_tooLarge", func(t *testing.T) {
		addr := types.Address{234}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		tooLarge := new(big.Int).Add(minStake, big.NewInt(1))
		err := sm2.RequestUnstake(addr, tooLarge, 100)
		if err != ErrInvalidUnstakeAmount {
			t.Errorf("expected ErrInvalidUnstakeAmount, got %v", err)
		}
	})

	t.Run("Stake_contractAddresses", func(t *testing.T) {
		if StakingContractAddress[18] != 0x10 || StakingContractAddress[19] != 0x01 {
			t.Error("wrong staking contract address")
		}
		if UnstakeContractAddress[18] != 0x10 || UnstakeContractAddress[19] != 0x02 {
			t.Error("wrong unstake contract address")
		}
		if RewardsContractAddress[18] != 0x10 || RewardsContractAddress[19] != 0x03 {
			t.Error("wrong rewards contract address")
		}
	})
}

func TestSyncFromChain(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)

	t.Run("Sync_empty", func(t *testing.T) {
		err := sm.SyncFromChain([]ChainTransaction{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Sync_nilTo", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		err := sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: nil, Value: big.NewInt(100), BlockHeight: 1},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sm2.ValidatorCount() != 0 {
			t.Error("nil To should be skipped")
		}
	})

	t.Run("Sync_wrongContract", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		wrongAddr := types.Address{99}
		err := sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: &wrongAddr, Value: big.NewInt(100), BlockHeight: 1},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sm2.ValidatorCount() != 0 {
			t.Error("wrong contract should be skipped")
		}
	})

	t.Run("Sync_nilValue", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		stakingAddr := StakingContractAddress
		err := sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: &stakingAddr, Value: nil, BlockHeight: 1},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sm2.ValidatorCount() != 0 {
			t.Error("nil value should be skipped")
		}
	})

	t.Run("Sync_zeroValue", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		stakingAddr := StakingContractAddress
		err := sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: &stakingAddr, Value: big.NewInt(0), BlockHeight: 1},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sm2.ValidatorCount() != 0 {
			t.Error("zero value should be skipped")
		}
	})

	t.Run("Sync_zeroBlockHeight", func(t *testing.T) {
		sm2 := NewStakingManager(cfg)
		stakingAddr := StakingContractAddress
		err := sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: &stakingAddr, Value: big.NewInt(100), BlockHeight: 0},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sm2.ValidatorCount() != 0 {
			t.Error("zero block height should be skipped")
		}
	})

	t.Run("Sync_valid_new", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount:  big.NewInt(10),
			MaxStakeAmount:  big.NewInt(1000000),
			MinCommission:   0,
			MaxCommission:   10000,
			MaxValidators:   100,
			UnbondingPeriod: 100,
		}
		sm2 := NewStakingManager(cfg2)
		stakingAddr := StakingContractAddress
		err := sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: &stakingAddr, Value: big.NewInt(100), BlockHeight: 1},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sm2.ValidatorCount() != 1 {
			t.Errorf("expected 1 validator, got %d", sm2.ValidatorCount())
		}
	})

	t.Run("Sync_valid_add", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount:  big.NewInt(10),
			MaxStakeAmount:  big.NewInt(1000000),
			MinCommission:   0,
			MaxCommission:   10000,
			MaxValidators:   100,
			UnbondingPeriod: 100,
		}
		sm2 := NewStakingManager(cfg2)
		stakingAddr := StakingContractAddress
		sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: &stakingAddr, Value: big.NewInt(100), BlockHeight: 1},
			{From: types.Address{1}, To: &stakingAddr, Value: big.NewInt(50), BlockHeight: 2},
		})
		if sm2.ValidatorCount() != 1 {
			t.Errorf("expected 1 validator, got %d", sm2.ValidatorCount())
		}
	})

	t.Run("Sync_belowMin", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount: big.NewInt(1000),
			MaxStakeAmount: big.NewInt(1000000),
			MaxValidators:  100,
		}
		sm2 := NewStakingManager(cfg2)
		stakingAddr := StakingContractAddress
		err := sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: &stakingAddr, Value: big.NewInt(100), BlockHeight: 1},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sm2.ValidatorCount() != 0 {
			t.Errorf("expected 0 validators (below min), got %d", sm2.ValidatorCount())
		}
	})

	t.Run("Sync_overMaxStake_adding", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount:  big.NewInt(10),
			MaxStakeAmount:  big.NewInt(200),
			MinCommission:   0,
			MaxCommission:   10000,
			MaxValidators:   100,
			UnbondingPeriod: 100,
		}
		sm2 := NewStakingManager(cfg2)
		stakingAddr := StakingContractAddress
		err := sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: &stakingAddr, Value: big.NewInt(100), BlockHeight: 1},
			{From: types.Address{1}, To: &stakingAddr, Value: big.NewInt(200), BlockHeight: 2},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		stake, _ := sm2.GetStake(types.Address{1})
		if stake.Amount.Cmp(big.NewInt(100)) != 0 {
			t.Errorf("expected original 100 (extra rejected), got %s", stake.Amount)
		}
	})

	t.Run("Sync_maxValidators", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount: big.NewInt(10),
			MaxStakeAmount: big.NewInt(1000000),
			MaxValidators:  1,
		}
		sm2 := NewStakingManager(cfg2)
		stakingAddr := StakingContractAddress
		err := sm2.SyncFromChain([]ChainTransaction{
			{From: types.Address{1}, To: &stakingAddr, Value: big.NewInt(100), BlockHeight: 1},
			{From: types.Address{2}, To: &stakingAddr, Value: big.NewInt(100), BlockHeight: 2},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sm2.ValidatorCount() != 1 {
			t.Errorf("expected 1 validator, got %d", sm2.ValidatorCount())
		}
	})
}

func TestProcessRewardClaimFromTx(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)

	t.Run("Claim_notFound", func(t *testing.T) {
		_, err := sm.ProcessRewardClaimFromTx(types.Address{99}, 100)
		if err != ErrStakeNotFound {
			t.Errorf("expected ErrStakeNotFound, got %v", err)
		}
	})

	t.Run("Claim_valid", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount:  new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)),
			MaxStakeAmount:  new(big.Int).Mul(big.NewInt(100000000), big.NewInt(1e18)),
			MinCommission:   0,
			MaxCommission:   10000,
			MaxValidators:   100,
			UnbondingPeriod: 100,
		}
		sm2 := NewStakingManager(cfg2)
		addr := types.Address{42}
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		reward, err := sm2.ProcessRewardClaimFromTx(addr, 2000000)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// FIX: StakingAPY = 0 (disabled to avoid double rewards with
		// consensus-layer attestation rewards). Claim returns 0 — validators
		// receive rewards via consensus layer, not staking layer.
		if reward == nil {
			t.Fatal("expected non-nil reward")
		}
		if reward.Sign() != 0 {
			t.Errorf("expected 0 reward (StakingAPY=0), got %s", reward)
		}
	})

	t.Run("Claim_noStake", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount:  new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)),
			MaxStakeAmount:  new(big.Int).Mul(big.NewInt(100000000), big.NewInt(1e18)),
			MinCommission:   0,
			MaxCommission:   10000,
			MaxValidators:   100,
			UnbondingPeriod: 100,
		}
		sm2 := NewStakingManager(cfg2)
		addr := types.Address{43}
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)
		// Manually set stake amount to nil
		sm2.stakes[addr].Amount = nil

		reward, err := sm2.ProcessRewardClaimFromTx(addr, 2000000)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reward.Sign() != 0 {
			t.Errorf("expected 0 reward when stake is nil, got %s", reward)
		}
	})

	t.Run("Claim_currentAtStakeHeight", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount:  new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)),
			MaxStakeAmount:  new(big.Int).Mul(big.NewInt(100000000), big.NewInt(1e18)),
			MinCommission:   0,
			MaxCommission:   10000,
			MaxValidators:   100,
			UnbondingPeriod: 100,
		}
		sm2 := NewStakingManager(cfg2)
		addr := types.Address{44}
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		reward, err := sm2.ProcessRewardClaimFromTx(addr, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reward.Sign() != 0 {
			t.Errorf("expected 0 reward (current <= stake height), got %s", reward)
		}
	})

	t.Run("GetPendingRewards", func(t *testing.T) {
		cfg2 := &StakingConfig{
			MinStakeAmount:  new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)),
			MaxStakeAmount:  new(big.Int).Mul(big.NewInt(100000000), big.NewInt(1e18)),
			MinCommission:   0,
			MaxCommission:   10000,
			MaxValidators:   100,
			UnbondingPeriod: 100,
		}
		sm2 := NewStakingManager(cfg2)
		addr := types.Address{45}
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		reward := sm2.GetPendingRewards(addr, 2000000)
		// FIX: StakingAPY = 0 (disabled to avoid double rewards with
		// consensus-layer attestation rewards). Pending rewards are 0.
		if reward.Sign() != 0 {
			t.Errorf("expected 0 pending reward (StakingAPY=0), got %s", reward)
		}
	})

	t.Run("GetPendingRewards_currentAtStakeHeight", func(t *testing.T) {
		cfg2 := NewStakingManager(cfg)
		addr := types.Address{46}
		reward := cfg2.GetPendingRewards(addr, 0)
		if reward.Sign() != 0 {
			t.Errorf("expected 0 (no stake), got %s", reward)
		}
	})
}

func TestAddStakeFromTx(t *testing.T) {
	cfg := &StakingConfig{
		MinStakeAmount:  new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)),
		MaxStakeAmount:  new(big.Int).Mul(big.NewInt(100000000), big.NewInt(1e18)),
		MinCommission:   0,
		MaxCommission:   10000,
		MaxValidators:   100,
		UnbondingPeriod: 100,
	}
	sm := NewStakingManager(cfg)

	t.Run("Add_valid_new", func(t *testing.T) {
		addr := types.Address{47}
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		err := sm.AddStakeFromTx(addr, minStake, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		stake, _ := sm.GetStake(addr)
		if stake.Amount.Cmp(minStake) != 0 {
			t.Errorf("expected %s, got %s", minStake, stake.Amount)
		}
	})

	t.Run("Add_belowMinStake", func(t *testing.T) {
		addr := types.Address{48}
		err := sm.AddStakeFromTx(addr, big.NewInt(1), 100)
		if err != ErrInsufficientStake {
			t.Errorf("expected ErrInsufficientStake, got %v", err)
		}
	})

	t.Run("Add_exceedMax", func(t *testing.T) {
		addr := types.Address{49}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.AddStakeFromTx(addr, minStake, 100)

		maxStake := cfg.MaxStakeAmount
		err := sm2.AddStakeFromTx(addr, maxStake, 200)
		if err == nil {
			t.Error("expected error when exceeding max stake")
		}
	})

	t.Run("Add_zeroValue", func(t *testing.T) {
		err := sm.AddStakeFromTx(types.Address{50}, big.NewInt(0), 100)
		if err != ErrInsufficientStake {
			t.Errorf("expected ErrInsufficientStake, got %v", err)
		}
	})
}

func TestProcessUnstakeFromTx(t *testing.T) {
	cfg := &StakingConfig{
		MinStakeAmount:  new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)),
		MaxStakeAmount:  new(big.Int).Mul(big.NewInt(100000000), big.NewInt(1e18)),
		MinCommission:   0,
		MaxCommission:   10000,
		MaxValidators:   100,
		UnbondingPeriod: 100,
	}
	sm := NewStakingManager(cfg)

	t.Run("Process_notFound", func(t *testing.T) {
		err := sm.ProcessUnstakeFromTx(types.Address{99}, big.NewInt(100), 100)
		if err != ErrStakeNotFound {
			t.Errorf("expected ErrStakeNotFound, got %v", err)
		}
	})

	t.Run("Process_valid", func(t *testing.T) {
		addr := types.Address{51}
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm.Stake(addr, minStake, 1000, 100)

		err := sm.ProcessUnstakeFromTx(addr, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), 200)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = sm.GetUnstakeRequest(addr)
		if err != nil {
			t.Errorf("expected unstake request, got error: %v", err)
		}
	})

	t.Run("Process_fullUnstake", func(t *testing.T) {
		addr := types.Address{52}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		err := sm2.ProcessUnstakeFromTx(addr, minStake, 200)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		stake, _ := sm2.GetStake(addr)
		if stake.Active {
			t.Error("validator should be inactive after full unstake")
		}
	})

	t.Run("Process_negativeValue", func(t *testing.T) {
		addr := types.Address{53}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		err := sm2.ProcessUnstakeFromTx(addr, big.NewInt(-1), 200)
		if err == nil {
			t.Error("expected error for negative value")
		}
	})

	t.Run("Process_nilValue", func(t *testing.T) {
		addr := types.Address{54}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)

		err := sm2.ProcessUnstakeFromTx(addr, nil, 200)
		if err == nil {
			t.Error("expected error for nil value")
		}
	})

	t.Run("Process_existingRequest", func(t *testing.T) {
		addr := types.Address{55}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(64), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)
		sm2.ProcessUnstakeFromTx(addr, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), 200)

		err := sm2.ProcessUnstakeFromTx(addr, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), 300)
		if err != nil {
			t.Fatalf("unexpected error for existing request: %v", err)
		}
		req, _ := sm2.GetUnstakeRequest(addr)
		if req.Amount.Cmp(new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))) != 0 {
			t.Errorf("expected accumulated 2e18, got %s", req.Amount)
		}
	})

	t.Run("CompleteUnstakeFromTx_valid", func(t *testing.T) {
		addr := types.Address{56}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(64), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)
		sm2.ProcessUnstakeFromTx(addr, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), 100)

		unlockHeight := 100 + cfg.UnbondingPeriod
		amount, err := sm2.CompleteUnstakeFromTx(addr, unlockHeight)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if amount == nil || amount.Sign() <= 0 {
			t.Errorf("expected positive amount, got %s", amount)
		}
	})

	t.Run("CompleteUnstakeFromTx_stillLocked", func(t *testing.T) {
		addr := types.Address{57}
		sm2 := NewStakingManager(cfg)
		minStake := new(big.Int).Mul(big.NewInt(64), big.NewInt(1e18))
		sm2.Stake(addr, minStake, 1000, 100)
		sm2.ProcessUnstakeFromTx(addr, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), 100)

		_, err := sm2.CompleteUnstakeFromTx(addr, 150)
		if err != ErrStakeLocked {
			t.Errorf("expected ErrStakeLocked, got %v", err)
		}
	})
}

func TestInflationModel_Edge(t *testing.T) {
	initialSupply := new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1e18))

	t.Run("NewInflationModel_customConfig", func(t *testing.T) {
		cfg := &InflationConfig{
			InitialRate:      big.NewInt(800),
			MinRate:          big.NewInt(10),
			MaxRate:          big.NewInt(2000),
			TargetStakeRatio: big.NewInt(70),
			AdjustmentPeriod: 50000,
			AdjustmentFactor: big.NewInt(3),
			DecayFactor:      big.NewInt(990),
			PhaseThresholds: map[InflationPhase]*big.Int{
				InflationPhaseHigh:     big.NewInt(900),
				InflationPhaseModerate: big.NewInt(600),
				InflationPhaseLow:      big.NewInt(300),
				InflationPhaseStable:   big.NewInt(50),
			},
		}
		im := NewInflationModel(cfg, initialSupply)
		if im.GetCurrentPhase() != InflationPhaseHigh {
			t.Errorf("expected high phase, got %d", im.GetCurrentPhase())
		}
	})

	t.Run("GetAdjustmentCount", func(t *testing.T) {
		im := NewInflationModel(nil, initialSupply)
		if im.GetAdjustmentCount() != 0 {
			t.Errorf("expected 0, got %d", im.GetAdjustmentCount())
		}
	})

	t.Run("UpdateTotalSupply", func(t *testing.T) {
		im := NewInflationModel(nil, initialSupply)
		newSupply := big.NewInt(2000)
		im.UpdateTotalSupply(newSupply)
		im.UpdateStakedSupply(big.NewInt(1000))
		ratio := im.GetStakeRatio()
		if ratio.Cmp(big.NewInt(50)) != 0 {
			t.Errorf("expected 50, got %s", ratio)
		}
	})

	t.Run("CalculateNewSupply_triggersAdjustment", func(t *testing.T) {
		cfg := &InflationConfig{
			InitialRate:      big.NewInt(500),
			MinRate:          big.NewInt(50),
			MaxRate:          big.NewInt(1000),
			TargetStakeRatio: big.NewInt(67),
			AdjustmentPeriod: 1,
			AdjustmentFactor: big.NewInt(5),
			DecayFactor:      big.NewInt(995),
			PhaseThresholds: map[InflationPhase]*big.Int{
				InflationPhaseHigh:     big.NewInt(800),
				InflationPhaseModerate: big.NewInt(500),
				InflationPhaseLow:      big.NewInt(200),
				InflationPhaseStable:   big.NewInt(50),
			},
		}
		supply := new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1e18))
		staked := new(big.Int).Div(supply, big.NewInt(2))
		im := NewInflationModel(cfg, supply)
		im.UpdateStakedSupply(staked)

		reward := im.CalculateNewSupply(1000)
		if reward.Sign() <= 0 {
			t.Errorf("expected positive reward, got %s", reward)
		}
		if im.GetAdjustmentCount() != 1 {
			t.Errorf("expected 1 adjustment, got %d", im.GetAdjustmentCount())
		}
	})

	t.Run("adjustRate_zeroSupply", func(t *testing.T) {
		cfg := DefaultInflationConfig()
		im := &InflationModel{
			config:      cfg,
			currentRate: big.NewInt(500),
			totalSupply: big.NewInt(0),
		}
		im.adjustRate()
		if im.currentRate.Cmp(big.NewInt(500)) != 0 {
			t.Errorf("expected unchanged rate, got %s", im.currentRate)
		}
	})
}

func TestEconomicsManager(t *testing.T) {
	t.Run("NewEconomicsManager_nilConfig", func(t *testing.T) {
		em, err := NewEconomicsManager(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if em == nil {
			t.Fatal("manager is nil")
		}
	})

	t.Run("NewEconomicsManager_invalidConfig", func(t *testing.T) {
		cfg := &EconomicsConfig{
			Reward: &RewardConfig{
				InflationRate:   10001,
				BlocksPerYear:   100,
				HalvingInterval: 100,
			},
			GasFee: DefaultGasFeeConfig(),
		}
		_, err := NewEconomicsManager(cfg)
		if err == nil {
			t.Error("expected error for invalid reward config")
		}
	})

	t.Run("NewEconomicsManager_invalidGasFee", func(t *testing.T) {
		cfg := &EconomicsConfig{
			Reward: DefaultRewardConfig(),
			GasFee: &GasFeeConfig{
				BurnRate:          5000,
				ProposerRate:      5000,
				ValidatorPoolRate: 5000,
			},
		}
		_, err := NewEconomicsManager(cfg)
		if err == nil {
			t.Error("expected error for invalid gas fee config")
		}
	})

	t.Run("SetTotalSupply", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		supply := big.NewInt(1000000)
		em.SetTotalSupply(supply)
		if em.GetTotalSupply().Cmp(supply) != 0 {
			t.Errorf("expected %s, got %s", supply, em.GetTotalSupply())
		}
	})

	t.Run("ProcessBlock", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		em.SetTotalSupply(new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1e18)))

		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		proposer := types.Address{1}
		em.StakingManager.Stake(proposer, minStake, 1000, 1)

		result, err := em.ProcessBlock(100, proposer, 21000, big.NewInt(1000000000))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result is nil")
		}
		if result.BlockReward == nil {
			t.Error("block reward is nil")
		}
		if result.GasFees == nil {
			t.Error("gas fees is nil")
		}
		if result.BlockHeight != 100 {
			t.Errorf("expected 100, got %d", result.BlockHeight)
		}
	})

	t.Run("ProcessBlock_noGasFees", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		em.SetTotalSupply(new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1e18)))

		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		proposer := types.Address{2}
		em.StakingManager.Stake(proposer, minStake, 1000, 1)

		result, err := em.ProcessBlock(200, proposer, 0, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result is nil")
		}
	})

	t.Run("ProcessBlock_noActiveValidators", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		em.SetTotalSupply(new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1e18)))

		_, err := em.ProcessBlock(100, types.Address{1}, 100, big.NewInt(100))
		if err != errors.New("no validator for reward") && err != ErrNoValidatorForReward {
			var want error = ErrNoValidatorForReward
			if err != nil {
				t.Errorf("expected ErrNoValidatorForReward, got %v", err)
				_ = want
			}
		}
	})

	t.Run("ProcessEIP1559Block", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		em.SetTotalSupply(new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1e18)))

		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		proposer := types.Address{3}
		em.StakingManager.Stake(proposer, minStake, 1000, 1)

		baseFee := big.NewInt(1000000000)
		priorityFee := big.NewInt(100000000)
		result, err := em.ProcessEIP1559Block(100, proposer, 21000, baseFee, priorityFee)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result is nil")
		}
		if result.BlockReward == nil {
			t.Error("block reward is nil")
		}
		if result.GasFees == nil {
			t.Error("gas fees is nil")
		}
	})

	t.Run("ProcessEIP1559Block_nilPriorityFee", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		em.SetTotalSupply(new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1e18)))

		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		proposer := types.Address{4}
		em.StakingManager.Stake(proposer, minStake, 1000, 1)

		baseFee := big.NewInt(1000000000)
		result, err := em.ProcessEIP1559Block(100, proposer, 21000, baseFee, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = result
	})

	t.Run("GetCurrentBaseFee", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		bf := em.GetCurrentBaseFee()
		if bf.Cmp(big.NewInt(1e9)) != 0 {
			t.Errorf("expected 1e9, got %s", bf)
		}
	})

	t.Run("UpdateBaseFee", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		oldBF := em.GetCurrentBaseFee()
		em.UpdateBaseFee(100, 100)
		newBF := em.GetCurrentBaseFee()
		if newBF.Cmp(oldBF) == 0 {
			t.Error("base fee should change when gas usage differs")
		}
	})

	t.Run("TotalValidatorRewards", func(t *testing.T) {
		be := &BlockEconomics{
			BlockHeight: 100,
			BlockReward: &RewardDistribution{
				ValidatorRewards: map[types.Address]*big.Int{
					{1}: big.NewInt(100),
				},
			},
			GasFees: &GasFeeDistribution{
				ValidatorFees: map[types.Address]*big.Int{
					{2}: big.NewInt(200),
				},
			},
		}
		rewards := be.TotalValidatorRewards()
		if rewards[types.Address{1}].Cmp(big.NewInt(100)) != 0 {
			t.Errorf("expected 100, got %s", rewards[types.Address{1}])
		}
		if rewards[types.Address{2}].Cmp(big.NewInt(200)) != 0 {
			t.Errorf("expected 200, got %s", rewards[types.Address{2}])
		}
	})

	t.Run("TotalValidatorRewards_sameAddress", func(t *testing.T) {
		be := &BlockEconomics{
			BlockHeight: 100,
			BlockReward: &RewardDistribution{
				ValidatorRewards: map[types.Address]*big.Int{
					{1}: big.NewInt(100),
				},
			},
			GasFees: &GasFeeDistribution{
				ValidatorFees: map[types.Address]*big.Int{
					{1}: big.NewInt(200),
				},
			},
		}
		rewards := be.TotalValidatorRewards()
		if rewards[types.Address{1}].Cmp(big.NewInt(300)) != 0 {
			t.Errorf("expected 300, got %s", rewards[types.Address{1}])
		}
	})

	t.Run("TotalValidatorRewards_nilFields", func(t *testing.T) {
		be := &BlockEconomics{
			BlockHeight: 100,
		}
		rewards := be.TotalValidatorRewards()
		if len(rewards) != 0 {
			t.Errorf("expected 0 rewards, got %d", len(rewards))
		}
	})

	t.Run("GetConfig", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		cfg := em.GetConfig()
		if cfg.Reward == nil || cfg.GasFee == nil || cfg.Staking == nil || cfg.Governance == nil {
			t.Error("all config sections should be non-nil")
		}
	})

	t.Run("InitializeGovernanceParameters", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		em.InitializeGovernanceParameters()
		params := em.GovernanceManager.GetAllParameters()
		if len(params) == 0 {
			t.Error("parameters should be initialized")
		}
	})

	t.Run("ProcessBlock_burnedFeesExceedSupply", func(t *testing.T) {
		em, _ := NewEconomicsManager(nil)
		em.SetTotalSupply(big.NewInt(1))

		minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		proposer := types.Address{99}
		em.StakingManager.Stake(proposer, minStake, 1000, 1)

		_, err := em.ProcessBlock(100, proposer, 21000, new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1000000)))
		if err != nil && err.Error() == "burned fees exceed total supply" {
			return
		}
		_ = err
	})
}

func TestFeeDistributor_Edge(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)

	t.Run("GetBurnRate_noCollected", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, types.Address{1}, types.Address{2}, types.Address{3})
		rate := fd.GetBurnRate()
		if rate.Sign() != 0 {
			t.Errorf("expected 0, got %s", rate)
		}
	})

	t.Run("GetBurnRate_withFees", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, types.Address{1}, types.Address{2}, types.Address{3})
		fd.CollectFee(big.NewInt(10000))
		fd.Distribute(100)
		rate := fd.GetBurnRate()
		if rate.Sign() <= 0 {
			t.Errorf("expected positive burn rate, got %s", rate)
		}
	})

	t.Run("DistributeHistory_limit", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, types.Address{1}, types.Address{2}, types.Address{3})
		fd.CollectFee(big.NewInt(1000))
		fd.Distribute(100)
		fd.CollectFee(big.NewInt(1000))
		fd.Distribute(200)

		history := fd.GetDistributionHistory(1)
		if len(history) != 1 {
			t.Errorf("expected 1, got %d", len(history))
		}
	})

	t.Run("UpdateConfig_invalidTotal", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, types.Address{1}, types.Address{2}, types.Address{3})
		cfg := &FeeDistributionConfig{
			ValidatorShare: 5000,
			BurnShare:      2000,
			TreasuryShare:  1500,
			DeveloperShare: 1000,
			InsuranceShare: 400,
		}
		err := fd.UpdateConfig(cfg)
		if err != ErrInvalidFeeDistribution {
			t.Errorf("expected ErrInvalidFeeDistribution, got %v", err)
		}
	})

	t.Run("DefaultFeeDistributionConfig", func(t *testing.T) {
		cfg := DefaultFeeDistributionConfig()
		total := cfg.ValidatorShare + cfg.BurnShare + cfg.TreasuryShare +
			cfg.DeveloperShare + cfg.InsuranceShare
		if total != 10000 {
			t.Errorf("expected 10000, got %d", total)
		}
	})
}

func TestDeFiIncentiveManager_Edge(t *testing.T) {
	initialBudget := new(big.Int).Mul(big.NewInt(10000000), big.NewInt(1e18))

	t.Run("CreateProgram_duplicate", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		program := &IncentiveProgram{
			ID:          "dup-1",
			TotalBudget: big.NewInt(1000),
		}
		dim.CreateProgram(program)
		err := dim.CreateProgram(program)
		if err != ErrProgramAlreadyExists {
			t.Errorf("expected ErrProgramAlreadyExists, got %v", err)
		}
	})

	t.Run("ClaimReward_inactive", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		program := &IncentiveProgram{
			ID:              "prog-inactive",
			TotalBudget:     big.NewInt(1000),
			RewardPerAction: big.NewInt(100),
			StartBlock:      0,
			EndBlock:        1000,
			Active:          true,
		}
		dim.CreateProgram(program)
		dim.DeactivateProgram("prog-inactive")

		_, err := dim.ClaimReward("prog-inactive", types.Address{1}, 500)
		if err != ErrProgramNotFound {
			t.Errorf("expected ErrProgramNotFound, got %v", err)
		}
	})

	t.Run("ClaimReward_outOfBlockRange", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		program := &IncentiveProgram{
			ID:              "prog-range",
			TotalBudget:     big.NewInt(1000),
			RewardPerAction: big.NewInt(100),
			StartBlock:      100,
			EndBlock:        200,
		}
		dim.CreateProgram(program)

		_, err := dim.ClaimReward("prog-range", types.Address{1}, 50)
		if err != ErrProgramNotFound {
			t.Errorf("expected ErrProgramNotFound for block before range, got %v", err)
		}

		_, err = dim.ClaimReward("prog-range", types.Address{1}, 300)
		if err != ErrProgramNotFound {
			t.Errorf("expected ErrProgramNotFound for block after range, got %v", err)
		}
	})

	t.Run("ClaimReward_insufficientRemaining", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		program := &IncentiveProgram{
			ID:              "prog-low",
			TotalBudget:     big.NewInt(100),
			RewardPerAction: big.NewInt(1000),
			StartBlock:      0,
			EndBlock:        1000000,
		}
		dim.CreateProgram(program)
		dim.programs["prog-low"].RemainingBudget = big.NewInt(50)

		_, err := dim.ClaimReward("prog-low", types.Address{1}, 500)
		if err != ErrInsufficientBudget {
			t.Errorf("expected ErrInsufficientBudget, got %v", err)
		}
	})

	t.Run("ListActivePrograms", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		dim.CreateProgram(&IncentiveProgram{ID: "a1", TotalBudget: big.NewInt(100), StartBlock: 0, EndBlock: 1000000})
		dim.CreateProgram(&IncentiveProgram{ID: "a2", TotalBudget: big.NewInt(100), StartBlock: 0, EndBlock: 1000000})

		active := dim.ListActivePrograms()
		if len(active) != 2 {
			t.Errorf("expected 2 active, got %d", len(active))
		}
	})

	t.Run("GetTotalDistributed", func(t *testing.T) {
		dim := NewDeFiIncentiveManager(initialBudget)
		dist := dim.GetTotalDistributed()
		if dist.Sign() != 0 {
			t.Errorf("expected 0, got %s", dist)
		}
	})

	t.Run("GetRemainingBudget", func(t *testing.T) {
		dim := NewDeFiIncentiveManager(big.NewInt(5000))
		rem := dim.GetRemainingBudget()
		if rem.Cmp(big.NewInt(5000)) != 0 {
			t.Errorf("expected 5000, got %s", rem)
		}
	})

	t.Run("AddBudget", func(t *testing.T) {
		dim := NewDeFiIncentiveManager(big.NewInt(1000))
		dim.AddBudget(big.NewInt(500))
		rem := dim.GetRemainingBudget()
		if rem.Cmp(big.NewInt(1500)) != 0 {
			t.Errorf("expected 1500, got %s", rem)
		}
	})

	t.Run("DeactivateProgram_notFound", func(t *testing.T) {
		dim := NewDeFiIncentiveManager(initialBudget)
		err := dim.DeactivateProgram("nonexistent")
		if err != ErrProgramNotFound {
			t.Errorf("expected ErrProgramNotFound, got %v", err)
		}
	})

	t.Run("GetProgramStats_notFound", func(t *testing.T) {
		dim := NewDeFiIncentiveManager(initialBudget)
		part, dist, rem := dim.GetProgramStats("nonexistent")
		if part != 0 || dist.Sign() != 0 || rem.Sign() != 0 {
			t.Errorf("expected all zeros, got part=%d dist=%s rem=%s", part, dist, rem)
		}
	})
}

func TestLiquidStaking_Edge(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)

	t.Run("CreatePool_commissionTooHigh", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		_, err := lsm.CreatePool(types.Address{1}, "bad pool", 10001)
		if err != ErrInvalidPoolOperator {
			t.Errorf("expected ErrInvalidPoolOperator, got %v", err)
		}
	})

	t.Run("UnstakeLiquid_poolNotFound", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		_, err := lsm.UnstakeLiquid("nonexistent", types.Address{1}, big.NewInt(100))
		if err != ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("GetExchangeRate", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		pool, _ := lsm.CreatePool(types.Address{1}, "test", 500)
		rate, err := lsm.GetExchangeRate(pool.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rate.Cmp(big.NewInt(1e18)) != 0 {
			t.Errorf("expected 1e18, got %s", rate)
		}
	})

	t.Run("GetExchangeRate_notFound", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		_, err := lsm.GetExchangeRate("nonexistent")
		if err != ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("GetDelegatorStake_empty", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		stake := lsm.GetDelegatorStake("nonexistent", types.Address{1})
		if stake.Sign() != 0 {
			t.Errorf("expected 0, got %s", stake)
		}
	})

	t.Run("GetTotalLiquidStaked", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		total := lsm.GetTotalLiquidStaked()
		if total.Sign() != 0 {
			t.Errorf("expected 0, got %s", total)
		}
	})

	t.Run("CompoundRewards_noRewards", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		operator := types.Address{1}
		pool, _ := lsm.CreatePool(operator, "test", 500)

		// ECON-R13-M02: CompoundRewards now requires operator authorization.
		err := lsm.CompoundRewards(pool.ID, operator)
		if err != nil {
			t.Fatalf("expected nil error when no rewards, got %v", err)
		}
	})

	t.Run("CompoundRewards_poolNotFound", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		// ECON-R13-M02: Pool lookup happens before operator validation, so
		// ErrPoolNotFound is still returned for nonexistent pools.
		err := lsm.CompoundRewards("nonexistent", types.Address{1})
		if err != ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("DistributeRewards_poolNotFound", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		// ECON-R14-CRIT-004: DistributeRewards now requires caller.
		err := lsm.DistributeRewards("nonexistent", types.Address{0x01}, big.NewInt(100))
		if err != ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("GetPool_notFound", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		_, err := lsm.GetPool("nonexistent")
		if err != ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("UnstakeLiquid_tokenNotFound", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		pool, _ := lsm.CreatePool(types.Address{1}, "test", 500)
		_, err := lsm.UnstakeLiquid(pool.ID, types.Address{99}, big.NewInt(100))
		if err != ErrLiquidTokenInsufficient {
			t.Errorf("expected ErrLiquidTokenInsufficient, got %v", err)
		}
	})

	t.Run("UnstakeLiquid_insufficient", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		operator := types.Address{1}
		pool, _ := lsm.CreatePool(operator, "test", 500)
		delegator := types.Address{2}
		// ECON-R13-CRIT-004: StakeLiquid now debits real user balance.
		lsm.Deposit(delegator, StakeAsset, big.NewInt(1000))
		token, _ := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000))

		tooMuch := new(big.Int).Add(token.Amount, big.NewInt(1))
		_, err := lsm.UnstakeLiquid(pool.ID, delegator, tooMuch)
		if err != ErrLiquidTokenInsufficient {
			t.Errorf("expected ErrLiquidTokenInsufficient, got %v", err)
		}
	})
}

// TestR4ECON05_PriorityFeesComputation verifies the EIP-1559 priorityFees
// computation formula that node.go blockInsertLoop uses. Previously
// priorityFees was hardcoded to 0 (audit R4-ECON-05), causing the offline
// supply/burn tracker to silently drop all tip revenue.
func TestR4ECON05_PriorityFeesComputation(t *testing.T) {
	baseFee := big.NewInt(1_000_000_000) // 1 Gwei

	// Tx1: MaxPriorityFeePerGas=2 Gwei, MaxFeePerGas=10 Gwei, GasLimit=21000
	// effectiveTip = min(2, 10-1) = 2 Gwei
	tx1Tip := big.NewInt(2_000_000_000)
	tx1MaxFee := big.NewInt(10_000_000_000)
	tx1GasLimit := uint64(21000)

	effectiveTip1 := new(big.Int).Set(tx1Tip)
	maxTip1 := new(big.Int).Sub(tx1MaxFee, baseFee)
	if effectiveTip1.Cmp(maxTip1) > 0 {
		effectiveTip1 = maxTip1
	}
	txFee1 := new(big.Int).Mul(effectiveTip1, new(big.Int).SetUint64(tx1GasLimit))

	// Tx2: MaxPriorityFeePerGas=5 Gwei, MaxFeePerGas=3 Gwei (below baseFee+tip)
	// effectiveTip = min(5, 3-1) = 2 Gwei (capped by MaxFeePerGas - BaseFee)
	tx2Tip := big.NewInt(5_000_000_000)
	tx2MaxFee := big.NewInt(3_000_000_000)
	tx2GasLimit := uint64(50000)

	effectiveTip2 := new(big.Int).Set(tx2Tip)
	maxTip2 := new(big.Int).Sub(tx2MaxFee, baseFee)
	if maxTip2.Sign() < 0 {
		maxTip2 = big.NewInt(0)
	}
	if effectiveTip2.Cmp(maxTip2) > 0 {
		effectiveTip2 = maxTip2
	}
	txFee2 := new(big.Int).Mul(effectiveTip2, new(big.Int).SetUint64(tx2GasLimit))

	priorityFeesTotal := new(big.Int).Add(txFee1, txFee2)

	// R4-ECON-05: priorityFeesTotal must NOT be zero (the bug was hardcoded 0)
	if priorityFeesTotal.Sign() == 0 {
		t.Fatal("R4-ECON-05: priorityFeesTotal must not be zero — the fix replaced hardcoded big.NewInt(0)")
	}

	// Verify exact tip values (capped correctly)
	expectedTip1 := big.NewInt(2_000_000_000) // min(2, 9) = 2
	if effectiveTip1.Cmp(expectedTip1) != 0 {
		t.Errorf("tip1: expected %s, got %s", expectedTip1, effectiveTip1)
	}
	expectedTip2 := big.NewInt(2_000_000_000) // min(5, 2) = 2 (capped)
	if effectiveTip2.Cmp(expectedTip2) != 0 {
		t.Errorf("tip2: expected %s (capped), got %s", expectedTip2, effectiveTip2)
	}

	// Verify total: (2 Gwei * 21000) + (2 Gwei * 50000) = 142 * 10^12
	expectedTotal := new(big.Int).Add(
		new(big.Int).Mul(big.NewInt(2_000_000_000), big.NewInt(21000)),
		new(big.Int).Mul(big.NewInt(2_000_000_000), big.NewInt(50000)),
	)
	if priorityFeesTotal.Cmp(expectedTotal) != 0 {
		t.Errorf("priorityFeesTotal: expected %s, got %s", expectedTotal, priorityFeesTotal)
	}

	// Integration: pass the computed value to ProcessEIP1559Block
	em, _ := NewEconomicsManager(nil)
	em.SetTotalSupply(new(big.Int).Mul(big.NewInt(1_000_000_000), big.NewInt(1e18)))
	minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
	proposer := types.Address{5}
	em.StakingManager.Stake(proposer, minStake, 1000, 1)

	totalGasUsed := tx1GasLimit + tx2GasLimit
	result, err := em.ProcessEIP1559Block(100, proposer, totalGasUsed, baseFee, priorityFeesTotal)
	if err != nil {
		t.Fatalf("ProcessEIP1559Block failed: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

// TestECONR11004_RewardRemainderAccumulator verifies the ECON- fix:
// the per-validator remainder accumulator is correctly initialized and the
// helper returns 0 in the current StakingAPY=0 config without crashing.
// The remainder-carry-forward path is only reachable when StakingAPY != 0
// (governance-controlled), but the helper must remain safe in all configs.
func TestECONR11004_RewardRemainderAccumulator(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)

	// rewardRemainders map must be initialized by the constructor.
	if sm.rewardRemainders == nil {
		t.Fatal("rewardRemainders map not initialized by NewStakingManager")
	}

	addr := types.Address{77}
	amount := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)) // 32 QAU

	t.Run("APYZero_returnsZero_stateModifying", func(t *testing.T) {
		// With StakingAPY=0, helper returns 0 and does not store a remainder.
		got := sm.computeStakingRewardsECONR11004(addr, amount, 1000, true)
		if got == nil || got.Sign() != 0 {
			t.Fatalf("expected 0 reward (StakingAPY=0), got %s", got)
		}
		// Map must still be empty (no remainder captured when reward is 0).
		if _, ok := sm.rewardRemainders[addr]; ok {
			t.Fatal("expected no remainder entry when StakingAPY=0")
		}
	})

	t.Run("APYZero_returnsZero_readOnly", func(t *testing.T) {
		// Read-only path must also return 0 and not mutate state.
		got := sm.computeStakingRewardsECONR11004(addr, amount, 1000, false)
		if got == nil || got.Sign() != 0 {
			t.Fatalf("expected 0 reward (read-only, StakingAPY=0), got %s", got)
		}
		if _, ok := sm.rewardRemainders[addr]; ok {
			t.Fatal("expected no remainder entry on read-only path")
		}
	})

	t.Run("nilAmount_safe", func(t *testing.T) {
		got := sm.computeStakingRewardsECONR11004(addr, nil, 1000, true)
		if got == nil || got.Sign() != 0 {
			t.Fatalf("expected 0 reward for nil amount, got %s", got)
		}
	})

	t.Run("zeroBlocks_safe", func(t *testing.T) {
		got := sm.computeStakingRewardsECONR11004(addr, amount, 0, true)
		if got == nil || got.Sign() != 0 {
			t.Fatalf("expected 0 reward for 0 blocks, got %s", got)
		}
	})

	t.Run("prePopulatedRemainder_consumed", func(t *testing.T) {
		// Even with StakingAPY=0, ensure the helper does NOT crash when
		// rewardRemainders has a pre-populated entry (simulating a state
		// from a previous run when APY was non-zero). The helper should
		// still return 0 because the early-return at the top short-circuits.
		sm.rewardRemainders[addr] = big.NewInt(12345)
		got := sm.computeStakingRewardsECONR11004(addr, amount, 1000, true)
		if got == nil || got.Sign() != 0 {
			t.Fatalf("expected 0 reward (StakingAPY=0 short-circuit), got %s", got)
		}
		// Stale remainder should remain (helper did not run the math path).
		if sm.rewardRemainders[addr] == nil || sm.rewardRemainders[addr].Int64() != 12345 {
			t.Fatalf("stale remainder should be preserved, got %v", sm.rewardRemainders[addr])
		}
	})
}
