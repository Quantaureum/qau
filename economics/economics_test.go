// Quantaureum Node source, version 1.0.0.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestLiquidStakingManager(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)

	t.Run("NewLiquidStakingManager", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		if lsm == nil {
			t.Fatal("NewLiquidStakingManager returned nil")
		}
	})

	t.Run("CreatePool", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		operator := types.Address{1}
		pool, err := lsm.CreatePool(operator, "Test Pool", 500)
		if err != nil {
			t.Fatalf("CreatePool failed: %v", err)
		}
		if pool.ID == "" {
			t.Error("pool ID is empty")
		}
		if pool.CommissionRate != 500 {
			t.Errorf("expected commission 500, got %d", pool.CommissionRate)
		}
	})

	t.Run("StakeLiquid", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		operator := types.Address{1}
		pool, _ := lsm.CreatePool(operator, "Test Pool", 500)
		delegator := types.Address{2}
		amount := big.NewInt(1000)

		// ECON-R13-CRIT-004: StakeLiquid now debits real user balance.
		lsm.Deposit(delegator, StakeAsset, amount)
		token, err := lsm.StakeLiquid(pool.ID, delegator, amount)
		if err != nil {
			t.Fatalf("StakeLiquid failed: %v", err)
		}
		if token.Amount.Sign() <= 0 {
			t.Error("token amount should be positive")
		}

		stake := lsm.GetDelegatorStake(pool.ID, delegator)
		if stake.Cmp(amount) != 0 {
			t.Errorf("expected stake %s, got %s", amount, stake)
		}
	})

	t.Run("StakeLiquid pool not found", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		_, err := lsm.StakeLiquid("nonexistent", types.Address{1}, big.NewInt(100))
		if err != ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("UnstakeLiquid", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		operator := types.Address{1}
		pool, _ := lsm.CreatePool(operator, "Test Pool", 500)
		delegator := types.Address{2}
		amount := big.NewInt(1000)

		// ECON-R13-CRIT-004: StakeLiquid now debits real user balance.
		lsm.Deposit(delegator, StakeAsset, amount)
		token, _ := lsm.StakeLiquid(pool.ID, delegator, amount)
		returned, err := lsm.UnstakeLiquid(pool.ID, delegator, token.Amount)
		if err != nil {
			t.Fatalf("UnstakeLiquid failed: %v", err)
		}
		if returned.Cmp(amount) != 0 {
			t.Errorf("expected returned %s, got %s", amount, returned)
		}
	})

	t.Run("DistributeRewards", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		operator := types.Address{1}
		pool, _ := lsm.CreatePool(operator, "Test Pool", 500)
		delegator := types.Address{2}
		// ECON-R13-CRIT-004: StakeLiquid now debits real user balance.
		lsm.Deposit(delegator, StakeAsset, big.NewInt(1000))
		lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000))
		// ECON-R14-CRIT-004: DistributeRewards now requires operator auth
		// and debits from the operator's balance.
		lsm.Deposit(operator, StakeAsset, big.NewInt(1000))

		reward := big.NewInt(100)
		err := lsm.DistributeRewards(pool.ID, operator, reward)
		if err != nil {
			t.Fatalf("DistributeRewards failed: %v", err)
		}

		retrieved, _ := lsm.GetPool(pool.ID)
		if retrieved.RewardPool.Sign() <= 0 {
			t.Error("reward pool should have rewards after distribution")
		}
	})

	t.Run("CompoundRewards", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		// R37-INFO: CompoundRewards is fail-closed without a
		// TreasuryVerifier; explicitly opt out for this accounting test.
		lsm.AllowUnverifiedCompounding()
		operator := types.Address{1}
		pool, _ := lsm.CreatePool(operator, "Test Pool", 500)
		delegator := types.Address{2}
		// ECON-R13-CRIT-004: StakeLiquid now debits real user balance.
		lsm.Deposit(delegator, StakeAsset, big.NewInt(1000))
		lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000))
		// ECON-R14-CRIT-004: fund operator so DistributeRewards can debit.
		lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
		lsm.DistributeRewards(pool.ID, operator, big.NewInt(100))

		// ECON-R13-M02: CompoundRewards now requires operator authorization.
		err := lsm.CompoundRewards(pool.ID, operator)
		if err != nil {
			t.Fatalf("CompoundRewards failed: %v", err)
		}

		retrieved, _ := lsm.GetPool(pool.ID)
		if retrieved.RewardPool.Sign() != 0 {
			t.Error("reward pool should be empty after compounding")
		}
	})

	t.Run("ListActivePools", func(t *testing.T) {
		lsm := NewLiquidStakingManager(cfg, sm)
		lsm.CreatePool(types.Address{1}, "Pool 1", 500)
		lsm.CreatePool(types.Address{2}, "Pool 2", 300)

		pools := lsm.ListActivePools()
		if len(pools) != 2 {
			t.Errorf("expected 2 pools, got %d", len(pools))
		}
	})
}

func TestInflationModel(t *testing.T) {
	initialSupply := new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(1e18))

	t.Run("NewInflationModel", func(t *testing.T) {
		im := NewInflationModel(nil, initialSupply)
		if im == nil {
			t.Fatal("NewInflationModel returned nil")
		}
		if im.GetCurrentPhase() != InflationPhaseHigh {
			t.Errorf("expected high phase, got %d", im.GetCurrentPhase())
		}
	})

	t.Run("GetCurrentRate", func(t *testing.T) {
		im := NewInflationModel(nil, initialSupply)
		rate := im.GetCurrentRate()
		if rate.Cmp(big.NewInt(500)) != 0 {
			t.Errorf("expected rate 500, got %s", rate)
		}
	})

	t.Run("CalculateNewSupply", func(t *testing.T) {
		im := NewInflationModel(nil, initialSupply)
		supply := im.CalculateNewSupply(0)
		if supply.Sign() <= 0 {
			t.Error("new supply should be positive")
		}
	})

	t.Run("UpdateStakedSupply", func(t *testing.T) {
		im := NewInflationModel(nil, initialSupply)
		staked := new(big.Int).Mul(big.NewInt(500000000), big.NewInt(1e18))
		im.UpdateStakedSupply(staked)

		ratio := im.GetStakeRatio()
		if ratio.Cmp(big.NewInt(50)) != 0 {
			t.Errorf("expected stake ratio 50%%, got %s", ratio)
		}
	})

	t.Run("PredictRate", func(t *testing.T) {
		im := NewInflationModel(nil, initialSupply)
		predicted := im.PredictRate(1000000)
		if predicted.Cmp(im.GetCurrentRate()) >= 0 {
			t.Error("predicted rate should be lower due to decay")
		}
	})

	t.Run("Rate never below minimum", func(t *testing.T) {
		im := NewInflationModel(nil, initialSupply)
		predicted := im.PredictRate(100000000)
		minRate := big.NewInt(50)
		if predicted.Cmp(minRate) < 0 {
			t.Errorf("predicted rate %s below minimum %s", predicted, minRate)
		}
	})
}

func TestFeeDistributor(t *testing.T) {
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	treasury := types.Address{1}
	developer := types.Address{2}
	insurance := types.Address{3}

	t.Run("NewFeeDistributor", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, treasury, developer, insurance)
		if fd == nil {
			t.Fatal("NewFeeDistributor returned nil")
		}
	})

	t.Run("CollectFee", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, treasury, developer, insurance)
		amount := big.NewInt(1000000)
		fd.CollectFee(amount)

		pool := fd.GetPool()
		if pool.TotalCollected.Cmp(amount) != 0 {
			t.Errorf("expected total collected %s, got %s", amount, pool.TotalCollected)
		}
	})

	t.Run("Distribute", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, treasury, developer, insurance)
		fd.CollectFee(big.NewInt(1000000))

		record, err := fd.Distribute(100)
		if err != nil {
			t.Fatalf("Distribute failed: %v", err)
		}
		if record == nil {
			t.Fatal("record is nil")
		}

		pool := fd.GetPool()
		if pool.ValidatorPool.Sign() != 0 {
			t.Error("validator pool should be empty after distribution")
		}
	})

	t.Run("Distribute too soon", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, treasury, developer, insurance)
		fd.CollectFee(big.NewInt(1000000))
		fd.Distribute(100)

		record, _ := fd.Distribute(101)
		if record != nil {
			t.Error("should not distribute before interval")
		}
	})

	t.Run("GetDistributionHistory", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, treasury, developer, insurance)
		fd.CollectFee(big.NewInt(1000000))
		fd.Distribute(100)

		history := fd.GetDistributionHistory(10)
		if len(history) != 1 {
			t.Errorf("expected 1 record, got %d", len(history))
		}
	})

	t.Run("UpdateConfig", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, treasury, developer, insurance)
		newCfg := &FeeDistributionConfig{
			ValidatorShare:       5000,
			BurnShare:            2000,
			TreasuryShare:        1500,
			DeveloperShare:       1000,
			InsuranceShare:       500,
			DistributionInterval: 100, // R34-005: must be > 0
		}
		err := fd.UpdateConfig(newCfg)
		if err != nil {
			t.Fatalf("UpdateConfig failed: %v", err)
		}
	})

	t.Run("UpdateConfig invalid total", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, treasury, developer, insurance)
		newCfg := &FeeDistributionConfig{
			ValidatorShare: 5000,
			BurnShare:      2000,
			TreasuryShare:  1500,
			DeveloperShare: 1000,
			InsuranceShare: 100,
		}
		err := fd.UpdateConfig(newCfg)
		if err != ErrInvalidFeeDistribution {
			t.Errorf("expected ErrInvalidFeeDistribution, got %v", err)
		}
	})

	t.Run("UpdateConfig invalid interval", func(t *testing.T) {
		fd := NewFeeDistributor(nil, sm, treasury, developer, insurance)
		newCfg := &FeeDistributionConfig{
			ValidatorShare:       5000,
			BurnShare:            2000,
			TreasuryShare:        1500,
			DeveloperShare:       1000,
			InsuranceShare:       500,
			DistributionInterval: 0, // R34-005: must be > 0
		}
		err := fd.UpdateConfig(newCfg)
		if err == nil {
			t.Error("expected error for zero distribution interval, got nil")
		}
	})
}

func TestDeFiIncentiveManager(t *testing.T) {
	initialBudget := new(big.Int).Mul(big.NewInt(10000000), big.NewInt(1e18))

	t.Run("NewDeFiIncentiveManager", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		if dim == nil {
			t.Fatal("NewDeFiIncentiveManager returned nil")
		}
	})

	t.Run("CreateProgram", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		program := &IncentiveProgram{
			ID:              "prog-1",
			Name:            "Liquidity Mining",
			Type:            IncentiveTypeLiquidityProvision,
			TotalBudget:     new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18)),
			RewardPerAction: new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)),
			StartBlock:      0,
			EndBlock:        1000000,
		}

		err := dim.CreateProgram(program)
		if err != nil {
			t.Fatalf("CreateProgram failed: %v", err)
		}

		retrieved, exists := dim.GetProgram("prog-1")
		if !exists {
			t.Fatal("program not found")
		}
		if !retrieved.Active {
			t.Error("program should be active")
		}
	})

	t.Run("CreateProgram insufficient budget", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(big.NewInt(100))
		program := &IncentiveProgram{
			ID:          "prog-2",
			TotalBudget: big.NewInt(1000),
		}
		err := dim.CreateProgram(program)
		if err != ErrInsufficientBudget {
			t.Errorf("expected ErrInsufficientBudget, got %v", err)
		}
	})

	t.Run("ClaimReward", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		program := &IncentiveProgram{
			ID:              "prog-3",
			Name:            "Trading Rewards",
			Type:            IncentiveTypeTradingVolume,
			TotalBudget:     new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18)),
			RewardPerAction: new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)),
			StartBlock:      0,
			EndBlock:        1000000,
		}
		dim.CreateProgram(program)

		claimant := types.Address{1}
		claim, err := dim.ClaimReward("prog-3", claimant, 500)
		if err != nil {
			t.Fatalf("ClaimReward failed: %v", err)
		}
		if claim.Amount.Cmp(program.RewardPerAction) != 0 {
			t.Errorf("expected reward %s, got %s", program.RewardPerAction, claim.Amount)
		}
	})

	t.Run("ClaimReward program not found", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		_, err := dim.ClaimReward("nonexistent", types.Address{1}, 500)
		if err != ErrProgramNotFound {
			t.Errorf("expected ErrProgramNotFound, got %v", err)
		}
	})

	t.Run("DeactivateProgram", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		program := &IncentiveProgram{
			ID:          "prog-4",
			TotalBudget: big.NewInt(1000),
			StartBlock:  0,
			EndBlock:    1000000,
		}
		dim.CreateProgram(program)

		err := dim.DeactivateProgram("prog-4")
		if err != nil {
			t.Fatalf("DeactivateProgram failed: %v", err)
		}

		retrieved, _ := dim.GetProgram("prog-4")
		if retrieved.Active {
			t.Error("program should be inactive")
		}
	})

	t.Run("GetClaimsByUser", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		program := &IncentiveProgram{
			ID:              "prog-5",
			TotalBudget:     big.NewInt(10000),
			RewardPerAction: big.NewInt(100),
			StartBlock:      0,
			EndBlock:        1000000,
		}
		dim.CreateProgram(program)

		claimant := types.Address{1}
		claimant2 := types.Address{2}
		dim.ClaimReward("prog-5", claimant, 100)
		dim.ClaimReward("prog-5", claimant2, 200)

		claims := dim.GetClaimsByUser(claimant)
		if len(claims) != 1 {
			t.Errorf("expected 1 claim for claimant, got %d", len(claims))
		}
		claims2 := dim.GetClaimsByUser(claimant2)
		if len(claims2) != 1 {
			t.Errorf("expected 1 claim for claimant2, got %d", len(claims2))
		}
	})

	t.Run("GetProgramStats", func(t *testing.T) {
		dim := newTestDeFiIncentiveManager(initialBudget)
		program := &IncentiveProgram{
			ID:              "prog-6",
			TotalBudget:     big.NewInt(10000),
			RewardPerAction: big.NewInt(100),
			StartBlock:      0,
			EndBlock:        1000000,
		}
		dim.CreateProgram(program)

		dim.ClaimReward("prog-6", types.Address{1}, 100)
		dim.ClaimReward("prog-6", types.Address{2}, 200)

		participants, distributed, remaining := dim.GetProgramStats("prog-6")
		if participants != 2 {
			t.Errorf("expected 2 participants, got %d", participants)
		}
		if distributed.Cmp(big.NewInt(200)) != 0 {
			t.Errorf("expected distributed 200, got %s", distributed)
		}
		if remaining.Cmp(big.NewInt(9800)) != 0 {
			t.Errorf("expected remaining 9800, got %s", remaining)
		}
	})
}
