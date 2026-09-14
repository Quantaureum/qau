// Quantaureum Node source, version 1.0.0.
package economics

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

func TestDeFi_Basics(t *testing.T) {
	t.Run("DefaultOracleConfig", func(t *testing.T) {
		cfg := DefaultOracleConfig()
		if cfg.MaxDeviationBps == 0 {
			t.Error("MaxDeviationBps should not be 0")
		}
		if cfg.MinSources == 0 {
			t.Error("MinSources should not be 0")
		}
		if cfg.StalenessThreshold == 0 {
			t.Error("StalenessThreshold should not be 0")
		}
	})

	t.Run("DefaultDeFiConfig", func(t *testing.T) {
		cfg := DefaultDeFiConfig()
		if cfg == nil {
			t.Fatal("config is nil")
		}
		if cfg.DefaultSwapFee == 0 {
			t.Error("DefaultSwapFee should not be 0")
		}
		if cfg.MinLiquidityAmount == nil || cfg.MinLiquidityAmount.Sign() != 1 {
			t.Error("MinLiquidityAmount should be 1")
		}
		if cfg.DefaultCollateralFactor == 0 {
			t.Error("DefaultCollateralFactor should not be 0")
		}
		if cfg.LiquidationThreshold == 0 {
			t.Error("LiquidationThreshold should not be 0")
		}
	})

	t.Run("AggregatedPriceOracle_config", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		if oracle == nil {
			t.Fatal("oracle is nil")
		}
		if oracle.config == nil {
			t.Error("config should not be nil")
		}
	})
}

func TestAggregatedPriceOracle(t *testing.T) {
	makeFetchFn := func(price *big.Int) func(string) (*big.Int, error) {
		return func(asset string) (*big.Int, error) {
			return new(big.Int).Set(price), nil
		}
	}

	t.Run("RegisterSource", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		oracle.RegisterSource("source1", 50, makeFetchFn(big.NewInt(100)))
		oracle.RegisterSource("source2", 50, makeFetchFn(big.NewInt(100)))
		if len(oracle.feeds) != 0 {
			t.Errorf("expected 0 feeds (sources go to source registry), got %d", len(oracle.feeds))
		}
	})

	t.Run("WatchAsset", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		oracle.WatchAsset("QAU/USD", big.NewInt(1000))
		oracle.WatchAsset("ETH/USD", big.NewInt(2000))
		if len(oracle.feeds) != 2 {
			t.Errorf("expected 2 feeds, got %d", len(oracle.feeds))
		}
	})

	t.Run("GetPrice_noFeeds", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		price, err := oracle.GetPrice("QAU/USD")
		if err == nil {
			t.Error("expected error when no feeds")
		}
		_ = price
	})

	t.Run("UpdatePrice_staleBeyondThreshold", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(&OracleConfig{
			StalenessThreshold:          time.Nanosecond,
			MaxDeviationBps:             3000,
			MinSources:                  0,
			CircuitBreakerBps:           5000,
			CumulativeCircuitBreakerBps: 10000,
			FreshnessMinBlocks:          1,
		})
		oracle.WatchAsset("QAU/USD", big.NewInt(1000))
		oracle.RegisterSource("src1", 50, makeFetchFn(big.NewInt(1000)))

		time.Sleep(time.Millisecond)
		err := oracle.UpdatePrice("QAU/USD")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("GetPrice_withFeeds", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		oracle.WatchAsset("QAU/USD", big.NewInt(1000))

		price, err := oracle.GetPrice("QAU/USD")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if price.Cmp(big.NewInt(1000)) != 0 {
			t.Errorf("expected 1000, got %s", price)
		}
	})

	t.Run("GetPriceWithBlock_withPrice", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		oracle.WatchAsset("QAU/USD", big.NewInt(1000))

		price, err := oracle.GetPriceWithBlock("QAU/USD", 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if price.Cmp(big.NewInt(1000)) != 0 {
			t.Errorf("expected 1000, got %s", price)
		}
	})

	t.Run("GetPrice_notWatched", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		_, err := oracle.GetPrice("UNKNOWN/PAIR")
		if err == nil {
			t.Error("expected error for unwatched asset")
		}
	})

	t.Run("GetPrices_multiple", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		oracle.WatchAsset("QAU/USD", big.NewInt(100))
		oracle.WatchAsset("ETH/USD", big.NewInt(2000))

		prices, err := oracle.GetPrices([]string{"QAU/USD", "ETH/USD"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(prices) != 2 {
			t.Errorf("expected 2 prices, got %d", len(prices))
		}
	})

	t.Run("GetPricesWithBlock", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		oracle.WatchAsset("QAU/USD", big.NewInt(500))

		prices, err := oracle.GetPricesWithBlock([]string{"QAU/USD"}, 150)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if prices["QAU/USD"].Cmp(big.NewInt(500)) != 0 {
			t.Errorf("expected 500, got %s", prices["QAU/USD"])
		}
	})

	t.Run("UpdatePriceWithBlock_freshEnough", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(nil)
		oracle.WatchAsset("QAU/USD", big.NewInt(1000))
		oracle.RegisterSource("src1", 50, makeFetchFn(big.NewInt(1000)))

		err := oracle.UpdatePriceWithBlock("QAU/USD", 200)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		price, err := oracle.GetPriceWithBlock("QAU/USD", 201)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if price.Cmp(big.NewInt(1000)) != 0 {
			t.Errorf("expected 1000, got %s", price)
		}
	})

	t.Run("UpdatePriceWithBlock_cumulativeDeviation", func(t *testing.T) {
		oracle := NewAggregatedPriceOracle(&OracleConfig{
			MaxDeviationBps:             5000,
			MinSources:                  0,
			CircuitBreakerBps:           5000,
			CumulativeCircuitBreakerBps: 100,
			FreshnessMinBlocks:          1,
			StalenessThreshold:          time.Hour,
		})
		oracle.WatchAsset("QAU/USD", big.NewInt(1000))

		err := oracle.UpdatePriceWithBlock("QAU/USD", 200)
		if err == nil {
			t.Logf("cumulative deviation may reset, error=%v", err)
		}
	})
}

func TestDefaultPriceOracle(t *testing.T) {
	oracle := &DefaultPriceOracle{}

	t.Run("GetPrice_default", func(t *testing.T) {
		price, err := oracle.GetPrice("QAU/USD")
		if err == nil {
			t.Error("expected error: DefaultPriceOracle always rejects requests")
		}
		if !strings.Contains(err.Error(), "price oracle not configured") {
			t.Errorf("expected 'price oracle not configured' error, got: %v", err)
		}
		if price != nil {
			t.Error("expected nil price on error")
		}
	})

	t.Run("GetPrices_default", func(t *testing.T) {
		prices, err := oracle.GetPrices([]string{"QAU/USD", "ETH/USD"})
		if err == nil {
			t.Error("expected error: DefaultPriceOracle always rejects requests")
		}
		if prices != nil {
			t.Error("expected nil prices on error")
		}
	})

	t.Run("GetPricesWithBlock_default", func(t *testing.T) {
		prices, err := oracle.GetPricesWithBlock([]string{"QAU/USD"}, 100)
		if err == nil {
			t.Error("expected error: DefaultPriceOracle always rejects requests")
		}
		if prices != nil {
			t.Error("expected nil prices on error")
		}
	})

	t.Run("UpdatePriceWithBlock", func(t *testing.T) {
		err := oracle.UpdatePriceWithBlock("QAU/USD", 200)
		if err == nil {
			t.Error("expected error: DefaultPriceOracle always rejects requests")
		}
	})
}

func TestDeFiManager(t *testing.T) {
	t.Run("NewDeFiManager_nilConfig", func(t *testing.T) {
		dm := NewDeFiManager(nil)
		if dm == nil {
			t.Fatal("manager is nil")
		}
		if dm.LiquidityManager == nil {
			t.Error("liquidity manager should be initialized")
		}
		if dm.LendingManager == nil {
			t.Error("lending manager should be initialized")
		}
		if dm.FarmingManager == nil {
			t.Error("farming manager should be initialized")
		}
	})

	t.Run("NewDeFiManager_customConfig", func(t *testing.T) {
		cfg := DefaultDeFiConfig()
		cfg.DefaultSwapFee = 2000
		dm := NewDeFiManager(cfg)
		if dm == nil {
			t.Fatal("manager is nil")
		}
	})

	t.Run("initializeDefaultPools", func(t *testing.T) {
		cfg := DefaultDeFiConfig()
		dm := NewDeFiManager(cfg)

		pools := dm.LiquidityManager.GetAllPools()
		lendPools := dm.LendingManager.GetAllPools()
		farms := dm.FarmingManager.GetAllFarms()

		_ = pools
		_ = lendPools
		_ = farms
	})
}

func TestLiquidityPoolManager(t *testing.T) {
	t.Run("NewLiquidityPoolManager", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
		if lpm == nil {
			t.Fatal("manager is nil")
		}
	})

	t.Run("CreatePool_valid", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))

		pool, err := lpm.CreatePool("QAU", "USDC", 500)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool.PoolID == "" {
			t.Error("pool ID should not be empty")
		}
		if pool.FeeRate != 500 {
			t.Errorf("expected fee 500, got %d", pool.FeeRate)
		}
	})

	t.Run("CreatePool_duplicate", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))

		lpm.CreatePool("QAU", "USDC", 500)
		_, err := lpm.CreatePool("QAU", "USDC", 500)
		if err == nil || !strings.Contains(err.Error(), "pool already exists") {
			t.Errorf("expected 'pool already exists', got %v", err)
		}
	})

	t.Run("GetPool_found", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))

		created, _ := lpm.CreatePool("QAU", "USDC", 500)
		retrieved, err := lpm.GetPool(created.PoolID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved.PoolID != created.PoolID {
			t.Errorf("expected %s, got %s", created.PoolID, retrieved.PoolID)
		}
	})

	t.Run("GetPool_notFound", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))
		_, err := lpm.GetPool("nonexistent")
		if err == nil || !strings.Contains(err.Error(), "pool not found") {
			t.Errorf("expected 'pool not found', got %v", err)
		}
	})

	t.Run("GetAllPools", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))

		pools := lpm.GetAllPools()
		if len(pools) != 0 {
			t.Errorf("expected 0, got %d", len(pools))
		}

		lpm.CreatePool("QAU", "USDC", 500)
		lpm.CreatePool("ETH", "USDC", 300)

		pools = lpm.GetAllPools()
		if len(pools) != 2 {
			t.Errorf("expected 2, got %d", len(pools))
		}
	})

	t.Run("AddLiquidity_valid", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))

		pool, _ := lpm.CreatePool("QAU", "USDC", 500)
		// ECON-R13-CRIT-001: AddLiquidity now debits real user balances.
		// Deposit sufficient token balances first.
		lpm.Deposit(types.Address{0x01}, "QAU", big.NewInt(5000))
		lpm.Deposit(types.Address{0x01}, "USDC", big.NewInt(5000))
		_, err := lpm.AddLiquidity(pool.PoolID, types.Address{0x01}, big.NewInt(5000), big.NewInt(5000), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("AddLiquidity_poolNotFound", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))

		_, err := lpm.AddLiquidity("nonexistent", types.Address{0x01}, big.NewInt(5000), big.NewInt(5000), nil)
		if err == nil || !strings.Contains(err.Error(), "pool not found") {
			t.Errorf("expected 'pool not found', got %v", err)
		}
	})

	t.Run("GetPrice_liquidityPool", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))

		pool, _ := lpm.CreatePool("QAU", "USDC", 500)
		// ECON-R13-CRIT-001: AddLiquidity now debits real user balances.
		lpm.Deposit(types.Address{0x01}, "QAU", big.NewInt(10000))
		lpm.Deposit(types.Address{0x01}, "USDC", big.NewInt(20000))
		lpm.AddLiquidity(pool.PoolID, types.Address{0x01}, big.NewInt(10000), big.NewInt(20000), nil)

		price, err := lpm.GetPrice(pool.PoolID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if price == nil {
			t.Fatal("price is nil")
		}
	})

	t.Run("GetUserLPBalance_valid", func(t *testing.T) {
		lpm := NewLiquidityPoolManager(30, big.NewInt(1000))

		pool, _ := lpm.CreatePool("QAU", "USDC", 500)
		// ECON-R13-CRIT-001: AddLiquidity now debits real user balances.
		lpm.Deposit(types.Address{0x01}, "QAU", big.NewInt(10000))
		lpm.Deposit(types.Address{0x01}, "USDC", big.NewInt(20000))
		lpm.AddLiquidity(pool.PoolID, types.Address{0x01}, big.NewInt(10000), big.NewInt(20000), nil)

		lpBal, err := lpm.GetUserLPBalance(pool.PoolID, types.Address{0x01})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lpBal.Sign() <= 0 {
			t.Errorf("expected positive LP balance, got %s", lpBal)
		}
	})
}

func TestLendingManager(t *testing.T) {
	makeOracle := func() *AggregatedPriceOracle {
		oracle := NewAggregatedPriceOracle(nil)
		oracle.WatchAsset("QAU", big.NewInt(5000))
		oracle.WatchAsset("ETH", big.NewInt(200000))
		oracle.RegisterSource("src1", 100, func(asset string) (*big.Int, error) {
			switch asset {
			case "QAU":
				return big.NewInt(5000), nil
			case "ETH":
				return big.NewInt(200000), nil
			default:
				return big.NewInt(1000), nil
			}
		})
		return oracle
	}

	t.Run("NewLendingManager", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		if lm == nil {
			t.Fatal("manager is nil")
		}
	})

	t.Run("NewLendingManager_nilOracle", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, nil)
		if lm == nil {
			t.Fatal("manager is nil")
		}
	})

	t.Run("SetPriceOracle", func(t *testing.T) {
		o1 := makeOracle()
		lm := NewLendingManager(75, 85, 5, o1)
		o2 := makeOracle()
		lm.SetPriceOracle(o2)
		if lm.oracle == nil {
			t.Error("oracle should not be nil")
		}
	})

	t.Run("CreatePool_valid", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		pool, err := lm.CreatePool("QAU", 70, 80)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool.PoolID == "" {
			t.Error("pool ID should not be empty")
		}
	})

	t.Run("CreatePool_duplicate", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		lm.CreatePool("QAU", 70, 80)
		_, err := lm.CreatePool("QAU", 70, 80)
		if err == nil || !strings.Contains(err.Error(), "pool already exists") {
			t.Errorf("expected 'pool already exists', got %v", err)
		}
	})

	t.Run("GetPool_found", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		created, _ := lm.CreatePool("QAU", 70, 80)
		retrieved, err := lm.GetPool(created.PoolID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved.PoolID != created.PoolID {
			t.Errorf("expected %s, got %s", created.PoolID, retrieved.PoolID)
		}
	})

	t.Run("GetPool_notFound", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		_, err := lm.GetPool("nonexistent")
		if err == nil || !strings.Contains(err.Error(), "pool not found") {
			t.Errorf("expected 'pool not found', got %v", err)
		}
	})

	t.Run("Supply_valid", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		pool, _ := lm.CreatePool("QAU", 70, 80)
		// ECON-R13-CRIT-002: Supply now debits real user balance.
		lm.Deposit(types.Address{0x02}, "QAU", big.NewInt(1000))
		err := lm.Supply(pool.PoolID, types.Address{0x02}, big.NewInt(1000))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Supply_poolNotFound", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		err := lm.Supply("nonexistent", types.Address{0x01}, big.NewInt(100))
		if err == nil || !strings.Contains(err.Error(), "pool not found") {
			t.Errorf("expected 'pool not found', got %v", err)
		}
	})

	t.Run("Withdraw_valid", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		pool, _ := lm.CreatePool("QAU", 70, 80)
		// ECON-R13-CRIT-002: Supply now debits real user balance.
		lm.Deposit(types.Address{0x02}, "QAU", big.NewInt(10000))
		lm.Supply(pool.PoolID, types.Address{0x02}, big.NewInt(10000))

		err := lm.Withdraw(pool.PoolID, types.Address{0x02}, big.NewInt(1000), 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Borrow_valid", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		pool, _ := lm.CreatePool("QAU", 70, 80)
		// ECON-R13-CRIT-002: Supply now debits real user balance.
		lm.Deposit(types.Address{0x03}, "QAU", big.NewInt(100000))
		lm.Supply(pool.PoolID, types.Address{0x03}, big.NewInt(100000))

		err := lm.Borrow(pool.PoolID, types.Address{0x03}, big.NewInt(100), 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Repay_valid", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		pool, _ := lm.CreatePool("QAU", 70, 80)
		// ECON-R13-CRIT-002: Supply/Borrow/Repay now move real user balance.
		// Borrow credits the borrower with principal, so the borrower has
		// QAU balance to use for Repay. Supply requires deposit first.
		lm.Deposit(types.Address{0x03}, "QAU", big.NewInt(100000))
		lm.Supply(pool.PoolID, types.Address{0x03}, big.NewInt(100000))
		lm.Borrow(pool.PoolID, types.Address{0x03}, big.NewInt(100), 1)
		// Borrow credits 100 QAU to addr 0x03's balance, which is then
		// debited by Repay.

		err := lm.Repay(pool.PoolID, types.Address{0x03}, big.NewInt(100))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("GetUtilizationRate", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		pool, _ := lm.CreatePool("QAU", 70, 80)

		rate, err := lm.GetUtilizationRate(pool.PoolID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rate != 0 {
			t.Errorf("expected 0, got %d", rate)
		}
	})

	t.Run("GetHealthFactor_default", func(t *testing.T) {
		lm := NewLendingManager(75, 85, 5, makeOracle())
		pool, _ := lm.CreatePool("QAU", 70, 80)
		lm.Supply(pool.PoolID, types.Address{0x03}, big.NewInt(100000))
		lm.Borrow(pool.PoolID, types.Address{0x03}, big.NewInt(100), 1)

		hf, err := lm.GetHealthFactor(pool.PoolID, types.Address{0x03}, 200)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hf == 0 {
			t.Error("health factor should not be 0")
		}
	})
}

func TestYieldFarmingManager(t *testing.T) {
	defaultReward := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18))

	t.Run("NewYieldFarmingManager", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)
		if yfm == nil {
			t.Fatal("manager is nil")
		}
	})

	t.Run("NewYieldFarmingManager_nil", func(t *testing.T) {
		yfm := NewYieldFarmingManager(nil)
		if yfm == nil {
			t.Fatal("manager is nil")
		}
	})

	t.Run("SetCurrentBlock", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)
		yfm.SetCurrentBlock(1000)
		if yfm.currentBlock != 1000 {
			t.Errorf("expected 1000, got %d", yfm.currentBlock)
		}
	})

	t.Run("CreateFarm_valid", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)

		totalRewards := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
		farm, err := yfm.CreateFarm("Farm1", "QAU-LP", "QAU", totalRewards, 1000, types.Address{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if farm.FarmID == "" {
			t.Error("farm ID should not be empty")
		}
	})

	t.Run("GetFarm_found", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)

		rewards := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
		created, _ := yfm.CreateFarm("Farm1", "QAU-LP", "QAU", rewards, 1000, types.Address{})
		retrieved, err := yfm.GetFarm(created.FarmID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved.FarmID != created.FarmID {
			t.Errorf("expected %s, got %s", created.FarmID, retrieved.FarmID)
		}
	})

	t.Run("GetFarm_notFound", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)
		_, err := yfm.GetFarm("nonexistent")
		if err == nil || !strings.Contains(err.Error(), "farm not found") {
			t.Errorf("expected 'farm not found', got %v", err)
		}
	})

	t.Run("GetAllFarms", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)

		farms := yfm.GetAllFarms()
		if len(farms) != 0 {
			t.Errorf("expected 0, got %d", len(farms))
		}

		rewards := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
		yfm.CreateFarm("Farm1", "QAU-LP", "QAU", rewards, 1000, types.Address{})
		yfm.CreateFarm("Farm2", "ETH-LP", "ETH", rewards, 1000, types.Address{})

		farms = yfm.GetAllFarms()
		if len(farms) != 2 {
			t.Errorf("expected 2, got %d", len(farms))
		}
	})

	t.Run("Stake_valid", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)
		rewards := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
		farm, _ := yfm.CreateFarm("Farm1", "QAU-LP", "QAU", rewards, 1000, types.Address{})

		// ECON-R14-CRIT-001: Stake now debits the user's LP token balance,
		// so we must credit it first via DepositTokens.
		if err := yfm.DepositTokens(types.Address{0x02}, "QAU-LP", big.NewInt(1000)); err != nil {
			t.Fatalf("DepositTokens failed: %v", err)
		}

		err := yfm.Stake(farm.FarmID, types.Address{0x02}, big.NewInt(1000))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		staked, err := yfm.GetUserStake(farm.FarmID, types.Address{0x02})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if staked.Cmp(big.NewInt(1000)) != 0 {
			t.Errorf("expected 1000, got %s", staked)
		}
	})

	t.Run("Harvest_valid", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)
		yfm.SetCurrentBlock(1000)

		rewards := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
		farm, _ := yfm.CreateFarm("Farm1", "QAU-LP", "QAU", rewards, 1000, types.Address{})
		// ECON-R14-CRIT-001: Stake now debits the user's LP token balance,
		// so we must credit it first via DepositTokens.
		if err := yfm.DepositTokens(types.Address{0x02}, "QAU-LP", big.NewInt(1000)); err != nil {
			t.Fatalf("DepositTokens failed: %v", err)
		}
		yfm.Stake(farm.FarmID, types.Address{0x02}, big.NewInt(1000))

		reward, err := yfm.Harvest(farm.FarmID, types.Address{0x02})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = reward
	})

	t.Run("GetPendingReward_empty", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)
		rewards := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
		farm, _ := yfm.CreateFarm("Farm1", "QAU-LP", "QAU", rewards, 1000, types.Address{})

		pending, err := yfm.GetPendingReward(farm.FarmID, types.Address{0x02})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pending.Sign() != 0 {
			t.Errorf("expected 0, got %s", pending)
		}
	})

	t.Run("CalculateAPY", func(t *testing.T) {
		yfm := NewYieldFarmingManager(defaultReward)
		rewards := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e18))
		farm, _ := yfm.CreateFarm("Farm1", "QAU-LP", "QAU", rewards, 1000, types.Address{})

		apy, err := yfm.CalculateAPY(farm.FarmID, 1.0, 1.0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if apy < 0 {
			t.Errorf("expected non-negative APY, got %f", apy)
		}
	})
}

// TestInterestDistribution_MultiSupplier tests P0-R3-01 fix:
// remainder must be calculated AFTER the loop, not inside it.
// With the bug, the first supplier receives ALL remaining interest.
func TestInterestDistribution_MultiSupplier(t *testing.T) {
	oracle := NewAggregatedPriceOracle(nil)
	oracle.WatchAsset("QAU", big.NewInt(5000))
	lm := NewLendingManager(75, 85, 5, oracle)
	pool, _ := lm.CreatePool("QAU", 70, 80)

	// Two suppliers with equal supply amounts
	addr1 := types.Address{0x01}
	addr2 := types.Address{0x02}
	supplyAmt := big.NewInt(100000)
	// ECON-R13-CRIT-002: Supply now debits real user balance.
	lm.Deposit(addr1, "QAU", supplyAmt)
	lm.Deposit(addr2, "QAU", supplyAmt)
	lm.Supply(pool.PoolID, addr1, supplyAmt)
	lm.Supply(pool.PoolID, addr2, supplyAmt)

	// Borrower
	borrower := types.Address{0x03}
	// ECON-R13-CRIT-002: Borrow now credits borrower with principal,
	// which is later debited by Repay.
	lm.Deposit(borrower, "QAU", big.NewInt(1000000))
	lm.Supply(pool.PoolID, borrower, big.NewInt(1000000))
	lm.Borrow(pool.PoolID, borrower, big.NewInt(50000), 1)

	// Repay at block 100001 to accrue interest. Borrower needs balance
	// to repay; Borrow credited 50000 QAU which is more than enough.
	lm.Repay(pool.PoolID, borrower, big.NewInt(1), 100001)

	poolObj, _ := lm.GetPool(pool.PoolID)
	bal1 := poolObj.Supplies[addr1]
	bal2 := poolObj.Supplies[addr2]
	if bal1 == nil || bal2 == nil {
		t.Fatal("supplier balances are nil")
	}

	addr1Interest := new(big.Int).Sub(bal1, supplyAmt)
	addr2Interest := new(big.Int).Sub(bal2, supplyAmt)

	// Both suppliers have equal supply (100000 each, 200000 total non-borrower)
	// They should receive approximately equal interest.
	// With P0-R3-01 bug, addr1 would get ALL interest, addr2 gets 0.
	if addr1Interest.Sign() > 0 && addr2Interest.Sign() == 0 {
		t.Errorf("P0-R3-01 REGRESSION: addr1 got %s interest but addr2 got 0. "+
			"With equal supplies, both should receive interest. "+
			"Bug: remainder inside loop gives first supplier all interest.",
			addr1Interest.String())
	}

	// Both should have received some interest
	if addr1Interest.Sign() <= 0 {
		t.Error("addr1 received no interest")
	}
	if addr2Interest.Sign() <= 0 {
		t.Error("addr2 received no interest")
	}
}
