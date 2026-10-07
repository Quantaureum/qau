// Quantaureum Node source, version 1.0.0.
// DeFi Module - Liquidity Pools, Lending, and Yield Farming
package economics

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
)

var logger = logging.Global()

// audit-fix NEW-17: maximum pool/farm counts to prevent memory exhaustion.
const (
	MaxLiquidityPools = 10000
	MaxLendingPools   = 10000
	MaxYieldFarms     = 10000

	// R32-P3-05 FIX (2026-07-28): cap farm.Multiplier to prevent reward
	// calculation memory DoS. Multiplier is in basis points (100 = 1x),
	// so 1000000 = 10000x — far above any legitimate farming incentive.
	// Without this cap, a malicious farm creator could set
	// Multiplier = math.MaxUint64, causing reward.Mul(reward, multiplier)
	// in updateFarmRewards to allocate huge big.Int values.
	MaxFarmMultiplier = uint64(1000000)

	// R14-LOW: cap the number of distinct suppliers per lending pool. Each
	// call to accrueInterest iterates ALL suppliers to distribute yield
	// (defi.go:2359-2381). Without a cap, an attacker can create thousands
	// of dust accounts (1 wei each) and then trigger accrueInterest via
	// Borrow/Repay/Liquidate, causing O(N) work per call and O(N*M) per
	// block (N suppliers × M borrowers). 4096 is generous for legitimate
	// use (real lending pools rarely exceed a few hundred suppliers) while
	// bounding the worst-case iteration cost.
	MaxSuppliersPerLendingPool = 4096
)

// getBlockHeight extracts block height from variadic parameter.
// N1 FIX (2026-07-06 R2): Returns 0 if no block height provided (backward compat).
func getBlockHeight(blockHeight []uint64) uint64 {
	if len(blockHeight) > 0 {
		return blockHeight[0]
	}
	return 0
}

//	Default per-pool maximum total supply for lending pools (20M QAU
//
// with 18 decimals). Prevents unbounded supply growth in a single lending pool.
// Can be overridden per-instance via SetMaxTotalSupply.
var DefaultMaxLendingSupply = new(big.Int).Mul(
	big.NewInt(20_000_000),
	new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
)

//	Default global maximum total supply across ALL lending pools
//
// (500M QAU with 18 decimals). Prevents unbounded aggregate supply growth.
// Can be overridden per-instance via SetGlobalMaxSupply.
var DefaultGlobalMaxLendingSupply = new(big.Int).Mul(
	big.NewInt(500_000_000),
	new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
)

//	MINIMUM_LIQUIDITY is the minimum residual liquidity that must remain
//
// in a liquidity pool after removing liquidity. Prevents a pool from being
// completely drained, which would cause division-by-zero and price manipulation.
const MINIMUM_LIQUIDITY = 1000

// PriceOracle defines the interface for asset price feeds
// audit-fix CRIT-DEFI: Price oracle required for safe collateral/borrow valuation
type PriceOracle interface {
	// GetPrice returns the price of an asset in terms of a base currency (e.g., USD)
	// Returns price in smallest unit (e.g., wei for ETH) or 0 if unavailable
	GetPrice(asset string) (*big.Int, error)
	// GetPrices returns prices for multiple assets
	GetPrices(assets []string) (map[string]*big.Int, error)
	// GetPricesWithBlock returns prices for multiple assets with block-based freshness check.
	// audit-fix R63-CRIT-DeFi: block-aware price fetching for DeFi operations.
	GetPricesWithBlock(assets []string, blockHeight uint64) (map[string]*big.Int, error)
	// UpdatePriceWithBlock updates the price and records the block height.
	// audit-fix R63-CRIT-DeFi: block-aware price updates for oracle feeds.
	UpdatePriceWithBlock(asset string, blockHeight uint64) error
}

// AggregatedPriceOracle implements a Chainlink-style aggregated price feed.
// It combines multiple price sources with staleness detection, deviation bounds,
// and circuit breaker logic for production safety.
type AggregatedPriceOracle struct {
	mu      sync.RWMutex
	feeds   map[string]*priceFeed
	config  *OracleConfig
	sources []priceSource
}

type OracleConfig struct {
	StalenessThreshold          time.Duration
	MaxDeviationBps             uint64
	MinSources                  int
	CircuitBreakerBps           uint64
	CumulativeCircuitBreakerBps uint64 // R68-FUND-1 FIX: cumulative deviation threshold
	FreshnessMinBlocks          uint64 // Minimum blocks since price update before use in DeFi ops
}

// R68-FUND-1 [HIGH] FIX: Add cumulative price deviation tracking to prevent
// gradual multi-update oracle manipulation. The previous per-update circuit
// breaker (3000 bps) could be bypassed by splitting a large price move into
// multiple smaller updates, each individually under the threshold but
// cumulatively devastating (e.g., 10 updates of 2900 bps each = 29x amplification).
// The cumulative circuit breaker tracks total drift since the last reset and
// triggers when total cumulative deviation exceeds CumulativeCircuitBreakerBps.
type priceFeed struct {
	asset           string
	sources         []priceSource
	lastPrice       *big.Int
	lastUpdated     time.Time
	lastBlockHeight uint64 // Block height at which price was last updated
	circuitOpen     bool
	// R68-FUND-1 FIX: Cumulative deviation tracking
	cumulativeDeviationBps uint64   // Accumulated bps deviation since last reset
	cumulativeResetPrice   *big.Int // Reference price at last cumulative reset
}

type priceSource struct {
	name    string
	fetchFn func(asset string) (*big.Int, error)
	weight  uint64
}

func DefaultOracleConfig() *OracleConfig {
	return &OracleConfig{
		StalenessThreshold: 1 * time.Hour,
		MaxDeviationBps:    500,
		MinSources:         1,
		CircuitBreakerBps:  3000,
		// R68-FUND-1 FIX: Cumulative breaker triggers at 2x per-update threshold (6000 bps).
		// A manipulator would need to exceed 6000 bps total drift before the cumulative
		// breaker fires, making multi-update split attacks impractical.
		// Value chosen: 2x per-update (6000 bps = 60%) — a large but safe gap that
		// prevents gradual accumulation while tolerating legitimate multi-source averaging.
		CumulativeCircuitBreakerBps: 6000,
		// audit-fix R63-CRIT-DeFi: Require prices to be at least 1 block old.
		// This prevents same-block price manipulation via flash loans in DeFi ops.
		FreshnessMinBlocks: 1,
	}
}

func NewAggregatedPriceOracle(config *OracleConfig) *AggregatedPriceOracle {
	if config == nil {
		config = DefaultOracleConfig()
	}
	return &AggregatedPriceOracle{
		feeds:  make(map[string]*priceFeed),
		config: config,
	}
}

func (o *AggregatedPriceOracle) RegisterSource(name string, weight uint64, fetchFn func(asset string) (*big.Int, error)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	source := priceSource{name: name, fetchFn: fetchFn, weight: weight}
	o.sources = append(o.sources, source)
	// R47-CS-04 NOTE: priceSource is a value struct, so append copies it.
	// The fetchFn is a shared function reference, which is intentional
	// (same fetcher for all feeds). No aliasing issue.
	for _, feed := range o.feeds {
		feed.sources = append(feed.sources, source)
	}
}

func (o *AggregatedPriceOracle) WatchAsset(asset string, initialPrice *big.Int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, exists := o.feeds[asset]; !exists {
		if initialPrice == nil || initialPrice.Sign() <= 0 {
			initialPrice = big.NewInt(1)
		}
		sources := make([]priceSource, len(o.sources))
		copy(sources, o.sources)
		o.feeds[asset] = &priceFeed{
			asset:           asset,
			sources:         sources,
			lastPrice:       initialPrice,
			lastUpdated:     time.Now(), // Off-chain oracle: wall-clock time is correct for freshness checks
			lastBlockHeight: 0,
		}
	}
}

func (o *AggregatedPriceOracle) GetPrice(asset string) (*big.Int, error) {
	return o.GetPriceWithBlock(asset, 0)
}

// GetPriceWithBlock returns the price for an asset, optionally verifying it is
// at least config.FreshnessMinBlocks old relative to the provided blockHeight.
//
// SECURITY FIX (R63-CRIT-DeFi): Prevents same-block price manipulation via flash
// loans. An attacker could manipulate oracle prices within a single block, then
// use those manipulated prices to borrow or trigger liquidations. By requiring
// prices to be at least FreshnessMinBlocks old, this forces manipulation to
// persist across at least one block, dramatically raising the cost of attack.
func (o *AggregatedPriceOracle) GetPriceWithBlock(asset string, blockHeight uint64) (*big.Int, error) {
	// R37-FIX P2-ECON-02 (2026-07-30): Hold RLock for the entire read.
	// Previously the lock was released right after fetching the feed pointer,
	// then feed.circuitOpen/lastUpdated/lastBlockHeight/lastPrice were read
	// without synchronization while UpdatePriceWithBlock mutates them under
	// the write lock — a torn-read data race (e.g. a half-updated lastPrice
	// pointer observed together with a stale lastBlockHeight).
	o.mu.RLock()
	defer o.mu.RUnlock()

	feed, exists := o.feeds[asset]
	if !exists {
		return nil, fmt.Errorf("no price feed for asset %s", asset)
	}

	if feed.circuitOpen {
		return nil, fmt.Errorf("circuit breaker open for asset %s", asset)
	}

	if time.Since(feed.lastUpdated) > o.config.StalenessThreshold {
		return nil, fmt.Errorf("stale price for asset %s (last updated %v ago)", asset, time.Since(feed.lastUpdated))
	}

	// audit-fix R63-CRIT-DeFi: block-based freshness check
	// Reject prices that are too recent relative to the current block.
	// This forces price manipulation to persist for at least FreshnessMinBlocks,
	// preventing same-block flash-loan oracle manipulation in DeFi operations.
	if o.config.FreshnessMinBlocks > 0 && blockHeight > 0 {
		if feed.lastBlockHeight == 0 {
			// Price has never been updated with a block height; use time-based check only
		} else if blockHeight < feed.lastBlockHeight+o.config.FreshnessMinBlocks {
			return nil, fmt.Errorf("price for asset %s is too recent: updated at block %d, current block %d, minimum age %d blocks",
				asset, feed.lastBlockHeight, blockHeight, o.config.FreshnessMinBlocks)
		}
	}

	if feed.lastPrice == nil || feed.lastPrice.Sign() <= 0 {
		return nil, fmt.Errorf("invalid price for asset %s", asset)
	}

	return new(big.Int).Set(feed.lastPrice), nil
}

func (o *AggregatedPriceOracle) GetPrices(assets []string) (map[string]*big.Int, error) {
	return o.GetPricesWithBlock(assets, 0)
}

// GetPricesWithBlock returns prices for multiple assets with block-based freshness check.
func (o *AggregatedPriceOracle) GetPricesWithBlock(assets []string, blockHeight uint64) (map[string]*big.Int, error) {
	prices := make(map[string]*big.Int)
	for _, asset := range assets {
		price, err := o.GetPriceWithBlock(asset, blockHeight)
		if err != nil {
			return nil, err
		}
		prices[asset] = price
	}
	return prices, nil
}

// UpdatePriceWithBlock fetches fresh price data for an asset from all registered
// sources and records the given block height. Callers should pass the block height
// from the transaction that triggered the price update.
// audit-fix R63-CRIT-DeFi: block height recording enables the freshness check.
func (o *AggregatedPriceOracle) UpdatePriceWithBlock(asset string, blockHeight uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	feed, exists := o.feeds[asset]
	if !exists {
		return fmt.Errorf("no price feed for asset %s", asset)
	}

	if len(feed.sources) == 0 {
		return fmt.Errorf("no sources for asset %s", asset)
	}

	type pricedResult struct {
		price  *big.Int
		weight uint64
		err    error
	}

	results := make([]pricedResult, 0, len(feed.sources))
	var totalWeight uint64

	for _, src := range feed.sources {
		p, err := src.fetchFn(asset)
		if err != nil {
			results = append(results, pricedResult{err: err})
			continue
		}
		if p == nil || p.Sign() <= 0 {
			results = append(results, pricedResult{err: fmt.Errorf("invalid price from %s", src.name)})
			continue
		}
		results = append(results, pricedResult{price: p, weight: src.weight})
		totalWeight += src.weight
	}

	validCount := 0
	for _, r := range results {
		if r.err == nil {
			validCount++
		}
	}

	if validCount < o.config.MinSources {
		return fmt.Errorf("insufficient valid sources for %s: %d < %d", asset, validCount, o.config.MinSources)
	}

	// audit-fix H-DEFI: guard against totalWeight == 0 which would cause
	// division-by-zero panic in the weighted average calculation.
	if totalWeight == 0 {
		return fmt.Errorf("total source weight is zero for %s: all sources have zero weight", asset)
	}

	if validCount > 0 {
		var weightedSum big.Int
		for _, r := range results {
			if r.err == nil {
				var contribution big.Int
				contribution.Mul(r.price, big.NewInt(int64(r.weight))) // #nosec G115 -- weight is always non-negative
				weightedSum.Add(&weightedSum, &contribution)
			}
		}
		newPrice := new(big.Int).Div(&weightedSum, big.NewInt(int64(totalWeight))) //nolint:gosec,G115

		if feed.lastPrice != nil && feed.lastPrice.Sign() > 0 {
			deviation := calculateDeviation(feed.lastPrice, newPrice)
			if deviation > o.config.CircuitBreakerBps {
				feed.circuitOpen = true
				return fmt.Errorf("circuit breaker triggered for %s: deviation %d bps > %d bps", asset, deviation, o.config.CircuitBreakerBps)
			}

			// R68-FUND-1 FIX: Cumulative deviation tracking to prevent gradual manipulation.
			// Initialize cumulative reset price on first update, or reset if cumulative exceeded.
			if feed.cumulativeResetPrice == nil || feed.cumulativeDeviationBps == 0 {
				feed.cumulativeResetPrice = new(big.Int).Set(feed.lastPrice)
				feed.cumulativeDeviationBps = 0
			}
			feed.cumulativeDeviationBps += deviation
			if feed.cumulativeDeviationBps > o.config.CumulativeCircuitBreakerBps {
				feed.circuitOpen = true
				return fmt.Errorf("cumulative circuit breaker triggered for %s: cumulative deviation %d bps > %d bps", asset, feed.cumulativeDeviationBps, o.config.CumulativeCircuitBreakerBps)
			}
		} else {
			// First price update: initialize cumulative tracking baseline.
			feed.cumulativeResetPrice = new(big.Int).Set(newPrice)
			feed.cumulativeDeviationBps = 0
		}

		feed.lastPrice = newPrice
		feed.lastUpdated = time.Now() // Off-chain oracle: wall-clock time is correct for freshness checks
		// audit-fix R63-CRIT-DeFi: record block height for price freshness enforcement
		feed.lastBlockHeight = blockHeight
	}

	return nil
}

// UpdatePrice delegates to UpdatePriceWithBlock with no block height recorded.
// Exists for callers that do not track block height; such updates will not satisfy
// the block-based freshness check in DeFi operations.
// audit-fix R63-CRIT-DeFi: kept for backward compat; prefer UpdatePriceWithBlock.
func (o *AggregatedPriceOracle) UpdatePrice(asset string) error {
	return o.UpdatePriceWithBlock(asset, 0)
}

func calculateDeviation(old, newVal *big.Int) uint64 {
	if old.Sign() == 0 {
		return 0
	}
	diff := new(big.Int).Sub(newVal, old)
	diff.Abs(diff)
	scaled := new(big.Int).Mul(diff, big.NewInt(10000))
	bps := new(big.Int).Div(scaled, old)
	return bps.Uint64()
}

// Deprecated: DefaultPriceOracle is disabled and must not be used. It exists
// solely for backward compatibility and all methods return errors. Provide a
// real PriceOracle implementation (e.g. AggregatedPriceOracle) instead.
//
//	This type is retained to avoid breaking callers but is disabled.
//
// DefaultPriceOracle is kept for backward compatibility but always returns an error.
// R58-N2 [HIGH] FIX: processEnv("QAU_ENV") always returned "", so the production
// check never triggered. DefaultPriceOracle silently returned 1e18 for all assets,
// allowing borrowing with no real oracle in production — an unlimited-collateral attack.
// The fix: always return an error so callers are forced to provide a real oracle.
// SECURITY (audit P4-9): DefaultPriceOracle is used as default but all methods return errors.
// This is intentional fail-closed behavior for production safety.
type DefaultPriceOracle struct{}

func (o *DefaultPriceOracle) GetPrice(asset string) (*big.Int, error) {
	return nil, fmt.Errorf("price oracle not configured: DefaultPriceOracle cannot be used; " +
		"provide a real PriceOracle implementation (e.g. AggregatedPriceOracle) to LendingManager")
}

func (o *DefaultPriceOracle) GetPrices(assets []string) (map[string]*big.Int, error) {
	return nil, fmt.Errorf("price oracle not configured: DefaultPriceOracle cannot be used; " +
		"provide a real PriceOracle implementation (e.g. AggregatedPriceOracle) to LendingManager")
}

func (o *DefaultPriceOracle) GetPricesWithBlock(assets []string, blockHeight uint64) (map[string]*big.Int, error) {
	return nil, fmt.Errorf("price oracle not configured: DefaultPriceOracle cannot be used; " +
		"provide a real PriceOracle implementation (e.g. AggregatedPriceOracle) to LendingManager")
}

func (o *DefaultPriceOracle) UpdatePriceWithBlock(asset string, blockHeight uint64) error {
	return fmt.Errorf("price oracle not configured: DefaultPriceOracle cannot be used; " +
		"provide a real PriceOracle implementation (e.g. AggregatedPriceOracle) to LendingManager")
}

// ============================================================================
// DeFi Manager - Main Entry Point
// ============================================================================

// DeFiManager manages all DeFi operations
type DeFiManager struct {
	// Sub-managers
	LiquidityManager *LiquidityPoolManager
	LendingManager   *LendingManager
	FarmingManager   *YieldFarmingManager

	// Configuration
	config *DeFiConfig
}

// DeFiConfig holds DeFi configuration
type DeFiConfig struct {
	// Liquidity pool settings
	DefaultSwapFee     uint64 // basis points (30 = 0.3%)
	MinLiquidityAmount *big.Int

	// Lending settings
	DefaultCollateralFactor uint64 // percentage (75 = 75%)
	LiquidationThreshold    uint64 // percentage (85 = 85%)
	LiquidationPenalty      uint64 // percentage (5 = 5%)

	// Farming settings
	RewardPerBlock *big.Int
}

// DefaultDeFiConfig returns default DeFi configuration
func DefaultDeFiConfig() *DeFiConfig {
	return &DeFiConfig{
		DefaultSwapFee:          30, // 0.3%
		MinLiquidityAmount:      big.NewInt(1000),
		DefaultCollateralFactor: 75,
		LiquidationThreshold:    85,
		LiquidationPenalty:      5,
		RewardPerBlock:          new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)), // 10 QAU per block
	}
}

// NewDeFiManager creates a new DeFi manager
func NewDeFiManager(config *DeFiConfig) *DeFiManager {
	if config == nil {
		config = DefaultDeFiConfig()
	}

	dm := &DeFiManager{
		config:           config,
		LiquidityManager: NewLiquidityPoolManager(config.DefaultSwapFee, config.MinLiquidityAmount),
		LendingManager:   NewLendingManager(config.DefaultCollateralFactor, config.LiquidationThreshold, config.LiquidationPenalty, nil),
		FarmingManager:   NewYieldFarmingManager(config.RewardPerBlock),
	}

	// Initialize default pools
	dm.initializeDefaultPools()

	return dm
}

// initializeDefaultPools creates default DeFi pools
func (dm *DeFiManager) initializeDefaultPools() {
	type poolDef struct {
		a, b string
		fee  uint64
	}
	for _, p := range []poolDef{
		{"QAU", "USDT", 30}, {"QAU", "ETH", 30}, {"QAU", "BTC", 50},
		{"USDT", "ETH", 30}, {"QAU", "USDC", 30}, {"ETH", "BTC", 50},
	} {
		if _, err := dm.LiquidityManager.CreatePool(p.a, p.b, p.fee); err != nil {
			logger.Warnf("WARN: failed to create default liquidity pool pair=%s err=%v", p.a+"/"+p.b, err) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		}
	}
	type lendDef struct {
		asset       string
		ltv, thresh uint64
	}
	for _, p := range []lendDef{
		{"QAU", 75, 85}, {"USDT", 85, 90}, {"ETH", 80, 88}, {"BTC", 80, 88}, {"USDC", 85, 90},
	} {
		if _, err := dm.LendingManager.CreatePool(p.asset, p.ltv, p.thresh); err != nil {
			logger.Warnf("WARN: failed to create default lending pool asset=%s err=%v", p.asset, err) //nolint:errcheck
		}
	}
	type farmDef struct {
		name, lp, reward string
		rate             *big.Int
		blocks           uint64
	}
	for _, f := range []farmDef{
		{"QAU-USDT Farm", "QAU-USDT-LP", "QAU", new(big.Int).Mul(big.NewInt(20), big.NewInt(1e18)), 200},
		{"QAU-ETH Farm", "QAU-ETH-LP", "QAU", new(big.Int).Mul(big.NewInt(30), big.NewInt(1e18)), 300},
		{"USDT-ETH Farm", "USDT-ETH-LP", "QAU", new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)), 100},
		{"QAU-BTC Farm", "QAU-BTC-LP", "QAU", new(big.Int).Mul(big.NewInt(40), big.NewInt(1e18)), 400},
	} {
		if _, err := dm.FarmingManager.CreateFarm(f.name, f.lp, f.reward, f.rate, f.blocks, types.Address{}); err != nil {
			logger.Warnf("WARN: failed to create default farm name=%s err=%v", f.name, err) //nolint:errcheck
		}
	}
}

// ============================================================================
// Liquidity Pool Manager
// ============================================================================

// LiquidityPool represents an AMM liquidity pool
type LiquidityPool struct {
	PoolID         string
	TokenA         string
	TokenB         string
	ReserveA       *big.Int
	ReserveB       *big.Int
	TotalLiquidity *big.Int
	FeeRate        uint64 // basis points
	CreatedAt      time.Time

	// LP token balances per user
	LPBalances map[types.Address]*big.Int

	// ECON- (2026-07-20): accumulated swap fees per token.
	// The fee portion of each swap is accrued here (NOT added to ReserveA/B)
	// and can be claimed by LPs pro-rata via RemoveLiquidity. Previously the
	// fee was implicitly captured by the constant-product formula (reserves
	// grew but LPs had no way to withdraw the fee portion), and worse, the
	// missing fund-transfer logic meant reserves were updated without any
	// corresponding token movement, allowing arbitrary price manipulation.
	AccumulatedFeeA *big.Int
	AccumulatedFeeB *big.Int
}

// LiquidityPoolManager manages liquidity pools
type LiquidityPoolManager struct {
	mu    sync.RWMutex
	pools map[string]*LiquidityPool

	defaultFeeRate     uint64
	minLiquidityAmount *big.Int

	// ECON- (2026-07-20): per-user reentrancy protection.
	// activeUsers tracks addresses currently executing a mutating DeFi op
	// (AddLiquidity/RemoveLiquidity/Swap). If a reentrant call arrives for
	// the same user, we reject it — matching staking.go's inProgress pattern.
	// This prevents a malicious contract from re-entering AddLiquidity mid-
	// execution to double-count LP tokens or drain pool reserves.
	activeUsers map[types.Address]bool

	// ECON- (2026-07-20): per-user token balances.
	// Each user has a balance per token symbol (e.g. "QAU", "USDC").
	// Swap() subtracts amountIn from the caller's tokenIn balance and
	// adds amountOut to the caller's tokenOut balance. Users must deposit
	// tokens via Deposit() before they can swap.
	// This closes the critical R11-leftover hole where Swap() updated pool
	// reserves without any corresponding fund movement, allowing anyone to
	// manipulate the AMM price at no cost.
	userTokenBalances map[types.Address]map[string]*big.Int
}

// NewLiquidityPoolManager creates a new liquidity pool manager
func NewLiquidityPoolManager(defaultFeeRate uint64, minLiquidity *big.Int) *LiquidityPoolManager {
	return &LiquidityPoolManager{
		pools:              make(map[string]*LiquidityPool),
		defaultFeeRate:     defaultFeeRate,
		minLiquidityAmount: minLiquidity,
		activeUsers:        make(map[types.Address]bool),
		userTokenBalances:  make(map[types.Address]map[string]*big.Int),
	}
}

// CreatePool creates a new liquidity pool
// N1 FIX (2026-07-06 R2): Accept optional blockHeight for deterministic CreatedAt.
func (lpm *LiquidityPoolManager) CreatePool(tokenA, tokenB string, feeRate uint64, blockHeight ...uint64) (*LiquidityPool, error) {
	lpm.mu.Lock()
	defer lpm.mu.Unlock()

	// audit-fix  validate feeRate is below 10000 basis points (100%).
	// Without this check, Swap() computes 10000 - feeRate which underflows
	// for uint64, producing a negative int64 via big.NewInt and corrupting
	// the swap amount calculation.
	if feeRate >= 10000 {
		return nil, errors.New("fee rate must be less than 10000 basis points")
	}

	poolID := tokenA + "-" + tokenB
	if _, exists := lpm.pools[poolID]; exists {
		return nil, errors.New("pool already exists")
	}

	// audit-fix NEW-17: enforce maximum pool count to prevent memory exhaustion
	if len(lpm.pools) >= MaxLiquidityPools {
		return nil, errors.New("maximum liquidity pool count reached")
	}

	pool := &LiquidityPool{
		PoolID:          poolID,
		TokenA:          tokenA,
		TokenB:          tokenB,
		ReserveA:        big.NewInt(0),
		ReserveB:        big.NewInt(0),
		TotalLiquidity:  big.NewInt(0),
		FeeRate:         feeRate,
		CreatedAt:       time.Unix(int64(getBlockHeight(blockHeight)), 0), // N1 FIX: deterministic
		AccumulatedFeeA: big.NewInt(0),
		AccumulatedFeeB: big.NewInt(0),
		LPBalances:      make(map[types.Address]*big.Int),
	}

	lpm.pools[poolID] = pool
	return pool, nil
}

// GetPool returns a deep copy of a pool by ID.
// audit-fix R3-M8: returns a copy to prevent data races when callers
// read big.Int fields outside the lock while concurrent writes occur.
func (lpm *LiquidityPoolManager) GetPool(poolID string) (*LiquidityPool, error) {
	lpm.mu.RLock()
	defer lpm.mu.RUnlock()

	pool, exists := lpm.pools[poolID]
	if !exists {
		return nil, errors.New("pool not found")
	}
	return pool.deepCopy(), nil
}

// GetAllPools returns deep copies of all liquidity pools.
// audit-fix R3-M8: returns copies to prevent data races.
func (lpm *LiquidityPoolManager) GetAllPools() []*LiquidityPool {
	lpm.mu.RLock()
	defer lpm.mu.RUnlock()

	pools := make([]*LiquidityPool, 0, len(lpm.pools))
	for _, pool := range lpm.pools {
		pools = append(pools, pool.deepCopy())
	}
	return pools
}

// deepCopy returns a deep copy of the LiquidityPool with all big.Int fields copied.
// audit-fix R3-M8: prevents data races when callers access pool data outside the lock.
// ECON-R13-CRIT-001 (2026-07-21): also copy AccumulatedFeeA/B so callers can
// verify fee distribution via GetPool().
func (p *LiquidityPool) deepCopy() *LiquidityPool {
	cp := &LiquidityPool{
		PoolID:         p.PoolID,
		TokenA:         p.TokenA,
		TokenB:         p.TokenB,
		ReserveA:       new(big.Int).Set(p.ReserveA),
		ReserveB:       new(big.Int).Set(p.ReserveB),
		TotalLiquidity: new(big.Int).Set(p.TotalLiquidity),
		FeeRate:        p.FeeRate,
		CreatedAt:      p.CreatedAt,
		LPBalances:     make(map[types.Address]*big.Int, len(p.LPBalances)),
	}
	for addr, bal := range p.LPBalances {
		cp.LPBalances[addr] = new(big.Int).Set(bal)
	}
	// ECON-R13-CRIT-001: copy accumulated fees (defensive — fields are
	// non-nil after CreatePool, but be safe against future struct changes).
	if p.AccumulatedFeeA != nil {
		cp.AccumulatedFeeA = new(big.Int).Set(p.AccumulatedFeeA)
	} else {
		cp.AccumulatedFeeA = big.NewInt(0)
	}
	if p.AccumulatedFeeB != nil {
		cp.AccumulatedFeeB = new(big.Int).Set(p.AccumulatedFeeB)
	} else {
		cp.AccumulatedFeeB = big.NewInt(0)
	}
	return cp
}

// AddLiquidity adds liquidity to a pool.
//
// R14-LOW (2026-07-21): Added minLPTokens parameter for slippage protection,
// mirroring Swap's minAmountOut. If minLPTokens is nil or <= 0, slippage
// checking is skipped (backward compat for existing callers). If > 0, the
// transaction is rejected when the computed LP token amount falls below
// minLPTokens — protecting the user from front-running/MEV where the pool
// ratio changes between submission and execution.
func (lpm *LiquidityPoolManager) AddLiquidity(poolID string, user types.Address, amountA, amountB *big.Int, minLPTokens *big.Int) (*big.Int, error) {
	lpm.mu.Lock()
	defer lpm.mu.Unlock()

	// ECON- per-user reentrancy protection.
	if lpm.activeUsers[user] {
		return nil, errors.New("reentrant call: user already has an in-progress DeFi operation")
	}
	lpm.activeUsers[user] = true
	defer delete(lpm.activeUsers, user)

	pool, exists := lpm.pools[poolID]
	if !exists {
		return nil, errors.New("pool not found")
	}

	if amountA == nil || amountB == nil {
		return nil, errors.New("amounts must not be nil")
	}
	if amountA.Sign() <= 0 || amountB.Sign() <= 0 {
		return nil, errors.New("amounts must be positive")
	}

	var lpTokens *big.Int
	// ECON-DEFI-01 FIX (deep-audit 2026-07-12): the first-LP branch previously
	// added the locked minimum liquidity to pool.TotalLiquidity BEFORE the final
	// minLiquidityAmount check below. If that check then failed, the pool was
	// left with TotalLiquidity=1000 and zero reserves — the inconsistent state
	// that bricks every future AddLiquidity (and CreatePool refuses to recreate
	// it). Defer ALL pool mutation until every validation has passed.
	lockMinLiquidity := false

	if pool.TotalLiquidity.Sign() == 0 {
		// First liquidity provider
		// SECURITY (audit P2-): Lock minimum liquidity (1000 wei) to zero
		// address to prevent donation attack. Attackers can front-run the first
		// LP by directly sending tokens to the pool, then burn the initial LP tokens
		// to steal subsequent LP deposits.
		lpTokens = new(big.Int).Sqrt(new(big.Int).Mul(amountA, amountB))
		minLiquidity := big.NewInt(1000)
		if lpTokens.Cmp(minLiquidity) <= 0 {
			return nil, errors.New("insufficient first liquidity: minted tokens must exceed 1000 (minimum liquidity lock)")
		}
		// Permanently lock minimum liquidity to zero address — applied below,
		// only after the minLiquidityAmount check passes.
		lpTokens.Sub(lpTokens, minLiquidity)
		lockMinLiquidity = true
	} else {
		// audit-fix H-DEFI: guard against division by zero.
		// If TotalLiquidity > 0 but a reserve is 0, the pool is in an
		// inconsistent state (e.g., all of one side was drained via Swap).
		// Reject the operation rather than panicking.
		if pool.ReserveA.Sign() == 0 || pool.ReserveB.Sign() == 0 {
			return nil, errors.New("pool reserves are in inconsistent state: zero reserve with non-zero liquidity")
		}

		// Calculate LP tokens based on existing ratio
		lpFromA := new(big.Int).Mul(amountA, pool.TotalLiquidity)
		lpFromA.Div(lpFromA, pool.ReserveA)

		lpFromB := new(big.Int).Mul(amountB, pool.TotalLiquidity)
		lpFromB.Div(lpFromB, pool.ReserveB)

		// Use minimum to prevent manipulation
		if lpFromA.Cmp(lpFromB) < 0 {
			lpTokens = lpFromA
		} else {
			lpTokens = lpFromB
		}
	}

	if lpTokens.Cmp(lpm.minLiquidityAmount) < 0 {
		return nil, errors.New("liquidity amount too small")
	}

	// R14-LOW (2026-07-21): Slippage protection. If the caller specified a
	// minimum LP token amount, reject when the actual computed amount falls
	// below it. This protects against front-running/MEV where the pool ratio
	// changes between submission and execution, leaving the user with fewer
	// LP tokens than expected. nil or non-positive minLPTokens skips the
	// check for backward compatibility.
	if minLPTokens != nil && minLPTokens.Sign() > 0 && lpTokens.Cmp(minLPTokens) < 0 {
		return nil, fmt.Errorf("slippage exceeded: minted %s LP tokens < minimum %s",
			lpTokens.String(), minLPTokens.String())
	}

	// ECON-R13-CRIT-001 (2026-07-21) FIX: verify the user has enough token
	// balances BEFORE mutating pool state. Previously AddLiquidity updated
	// reserves but never debited the user — equivalent to zero-cost LP
	// minting. An attacker could mint LP tokens without depositing any
	// token, then RemoveLiquidity (now also fixed) would actually pay out
	// real tokens. Mirror Swap()'s balance verification pattern.
	userBalA := lpm.getUserBalanceLocked(user, pool.TokenA)
	if userBalA.Cmp(amountA) < 0 {
		return nil, fmt.Errorf("insufficient user balance: have %s %s, need %s",
			userBalA.String(), pool.TokenA, amountA.String())
	}
	userBalB := lpm.getUserBalanceLocked(user, pool.TokenB)
	if userBalB.Cmp(amountB) < 0 {
		return nil, fmt.Errorf("insufficient user balance: have %s %s, need %s",
			userBalB.String(), pool.TokenB, amountB.String())
	}

	// All validations passed — now it is safe to mutate pool state.
	if lockMinLiquidity {
		pool.TotalLiquidity.Add(pool.TotalLiquidity, big.NewInt(1000))
	}

	// Update pool reserves
	pool.ReserveA.Add(pool.ReserveA, amountA)
	pool.ReserveB.Add(pool.ReserveB, amountB)
	pool.TotalLiquidity.Add(pool.TotalLiquidity, lpTokens)

	// Update user LP balance
	if pool.LPBalances[user] == nil {
		pool.LPBalances[user] = big.NewInt(0)
	}
	pool.LPBalances[user].Add(pool.LPBalances[user], lpTokens)

	// ECON-R13-CRIT-001 FIX: actually debit the deposited tokens from the
	// user's balance sheet. Without this, the user receives LP tokens for
	// free and can later burn them to drain real tokens from the pool.
	lpm.subUserBalanceLocked(user, pool.TokenA, amountA)
	lpm.subUserBalanceLocked(user, pool.TokenB, amountB)

	// ECON-R13-L02 (2026-07-21): Log price ratio for auditability.
	// AddLiquidity should NOT change the price ratio (amounts must be
	// proportional to existing reserves). Logging the pre/post ratio
	// makes it easy to detect bugs or manipulation attempts that break
	// this invariant.
	log.Printf("addLiquidity: pool=%s user=%x amountA=%s amountB=%s lpTokens=%s newReserveA=%s newReserveB=%s priceRatio=%s/%s",
		poolID, user[:min(8, len(user))], amountA.String(), amountB.String(),
		lpTokens.String(), pool.ReserveA.String(), pool.ReserveB.String(),
		pool.ReserveA.String(), pool.ReserveB.String())

	return lpTokens, nil
}

// RemoveLiquidity removes liquidity from a pool
func (lpm *LiquidityPoolManager) RemoveLiquidity(poolID string, user types.Address, lpAmount *big.Int) (*big.Int, *big.Int, error) {
	lpm.mu.Lock()
	defer lpm.mu.Unlock()

	// ECON- per-user reentrancy protection.
	if lpm.activeUsers[user] {
		return nil, nil, errors.New("reentrant call: user already has an in-progress DeFi operation")
	}
	lpm.activeUsers[user] = true
	defer delete(lpm.activeUsers, user)

	pool, exists := lpm.pools[poolID]
	if !exists {
		return nil, nil, errors.New("pool not found")
	}

	// audit-fix NEW-9: reject non-positive amounts to prevent balance inflation
	// via big.Int.Sub with negative values
	if lpAmount.Sign() <= 0 {
		return nil, nil, errors.New("LP amount must be positive")
	}

	// audit-fix H-DEFI: guard against division by zero in RemoveLiquidity
	if pool.TotalLiquidity.Sign() == 0 {
		return nil, nil, errors.New("pool has no liquidity to remove")
	}

	userBalance := pool.LPBalances[user]
	if userBalance == nil || userBalance.Cmp(lpAmount) < 0 {
		return nil, nil, errors.New("insufficient LP balance")
	}

	// Calculate token amounts to return
	amountA := new(big.Int).Mul(lpAmount, pool.ReserveA)
	amountA.Div(amountA, pool.TotalLiquidity)

	amountB := new(big.Int).Mul(lpAmount, pool.ReserveB)
	amountB.Div(amountB, pool.TotalLiquidity)

	// FIX: prevent completely draining the pool. After removal, the
	// pool's TotalLiquidity must remain >= MINIMUM_LIQUIDITY to avoid
	// division-by-zero in subsequent swaps and to prevent price manipulation
	// via dust-sized pools.
	remainingLiquidity := new(big.Int).Sub(pool.TotalLiquidity, lpAmount)
	if remainingLiquidity.Cmp(big.NewInt(MINIMUM_LIQUIDITY)) < 0 {
		return nil, nil, fmt.Errorf("removal would leave pool below minimum liquidity %d", MINIMUM_LIQUIDITY)
	}

	// ECON-R13-CRIT-001 (2026-07-21) FIX: distribute the LP's pro-rata
	// share of accumulated fees BEFORE removing liquidity. This must be
	// computed against the CURRENT TotalLiquidity (before we subtract
	// lpAmount), otherwise we would divide by the wrong denominator and
	// the math would not match the LP's true share.
	var feeShareA, feeShareB *big.Int
	if pool.AccumulatedFeeA.Sign() > 0 {
		feeShareA = new(big.Int).Mul(lpAmount, pool.AccumulatedFeeA)
		feeShareA.Div(feeShareA, pool.TotalLiquidity)
	} else {
		feeShareA = big.NewInt(0)
	}
	if pool.AccumulatedFeeB.Sign() > 0 {
		feeShareB = new(big.Int).Mul(lpAmount, pool.AccumulatedFeeB)
		feeShareB.Div(feeShareB, pool.TotalLiquidity)
	} else {
		feeShareB = big.NewInt(0)
	}

	// Update pool reserves
	// ECON-R14-H04 (2026-07-21) FIX: underflow defense. Mathematically
	// amountA = lpAmount * ReserveA / TotalLiquidity, and since lpAmount <=
	// TotalLiquidity (enforced by the LP balance check above), amountA should
	// always be <= ReserveA. But big.Int.Sub silently produces negative
	// values on underflow instead of wrapping like uint256 — any upstream
	// accounting bug (e.g. fee distribution inflating amountA, or a previous
	// Sub leaving ReserveA negative) would propagate undetected and corrupt
	// the pool's price forever. Defense-in-depth: validate the subtraction
	// result is non-negative; if it isn't, fail loudly so the operator can
	// investigate instead of silently poisoning the pool.
	pool.ReserveA.Sub(pool.ReserveA, amountA)
	if pool.ReserveA.Sign() < 0 {
		// Restore the value to avoid leaving the pool in a corrupted state
		// for the next call (this transaction should still revert upstream
		// via the returned error).
		pool.ReserveA.Add(pool.ReserveA, amountA)
		return nil, nil, fmt.Errorf("ECON-R14-H04: ReserveA underflow (amountA=%s > reserve=%s)", amountA, new(big.Int).Add(pool.ReserveA, amountA))
	}
	pool.ReserveB.Sub(pool.ReserveB, amountB)
	if pool.ReserveB.Sign() < 0 {
		pool.ReserveB.Add(pool.ReserveB, amountB)
		// Also restore ReserveA since we already committed that change.
		pool.ReserveA.Add(pool.ReserveA, amountA)
		return nil, nil, fmt.Errorf("ECON-R14-H04: ReserveB underflow (amountB=%s > reserve=%s)", amountB, new(big.Int).Add(pool.ReserveB, amountB))
	}
	pool.TotalLiquidity.Sub(pool.TotalLiquidity, lpAmount)
	if pool.TotalLiquidity.Sign() < 0 {
		// Defensive: remainingLiquidity check above should prevent this,
		// but if it somehow happens we must not leave a negative TL.
		pool.TotalLiquidity.Add(pool.TotalLiquidity, lpAmount)
		pool.ReserveA.Add(pool.ReserveA, amountA)
		pool.ReserveB.Add(pool.ReserveB, amountB)
		return nil, nil, fmt.Errorf("ECON-R14-H04: TotalLiquidity underflow (lpAmount=%s > TL=%s)", lpAmount, new(big.Int).Add(pool.TotalLiquidity, lpAmount))
	}

	// Subtract distributed fees from pool's accumulated fee buckets.
	pool.AccumulatedFeeA.Sub(pool.AccumulatedFeeA, feeShareA)
	if pool.AccumulatedFeeA.Sign() < 0 {
		// Defensive: rounding may leave a tiny negative remainder; clamp to 0.
		pool.AccumulatedFeeA.Set(big.NewInt(0))
	}
	pool.AccumulatedFeeB.Sub(pool.AccumulatedFeeB, feeShareB)
	if pool.AccumulatedFeeB.Sign() < 0 {
		pool.AccumulatedFeeB.Set(big.NewInt(0))
	}

	// Update user LP balance
	pool.LPBalances[user].Sub(pool.LPBalances[user], lpAmount)

	// ECON-R13-CRIT-001 FIX: actually credit the returned tokens (plus the
	// LP's pro-rata share of accumulated fees) to the user's balance sheet.
	// Without this, the user's LP tokens were burned but no tokens were
	// returned — equivalent to stealing the LP's deposits.
	totalA := new(big.Int).Add(amountA, feeShareA)
	totalB := new(big.Int).Add(amountB, feeShareB)
	lpm.addUserBalanceLocked(user, pool.TokenA, totalA)
	lpm.addUserBalanceLocked(user, pool.TokenB, totalB)

	// ECON-R13-L02 (2026-07-21): Log price ratio for auditability.
	// RemoveLiquidity should NOT change the price ratio (proportional
	// removal). Logging the pre/post ratio makes invariant violations
	// visible in logs.
	log.Printf("removeLiquidity: pool=%s user=%x lpAmount=%s amountA=%s amountB=%s feeShareA=%s feeShareB=%s newReserveA=%s newReserveB=%s priceRatio=%s/%s",
		poolID, user[:min(8, len(user))], lpAmount.String(),
		amountA.String(), amountB.String(),
		feeShareA.String(), feeShareB.String(),
		pool.ReserveA.String(), pool.ReserveB.String(),
		pool.ReserveA.String(), pool.ReserveB.String())

	return amountA, amountB, nil
}

// Deposit credits a user's token balance in the LiquidityPoolManager.
// ECON- (2026-07-20): Swap now requires users to have a sufficient
// per-user token balance to draw amountIn from. Deposit is the credit path;
// it is called by the node's execution layer when tokens are moved into the
// DeFi subsystem (typically via a precompile call or RPC handler that has
// already verified the on-chain token transfer).
//
// Returns the new balance after deposit.
func (lpm *LiquidityPoolManager) Deposit(user types.Address, token string, amount *big.Int) (*big.Int, error) {
	if amount == nil || amount.Sign() <= 0 {
		return nil, errors.New("deposit amount must be positive")
	}
	if token == "" {
		return nil, errors.New("token symbol must not be empty")
	}
	lpm.mu.Lock()
	defer lpm.mu.Unlock()

	// ECON-R13-H01 (2026-07-21) FIX: per-user reentrancy protection.
	// Deposit directly credits the user's token balance. Without this guard,
	// a malicious token with transfer hooks (or a reentrant precompile) could
	// re-enter Deposit during the credit step and double-spend the same
	// amount — the inner call sees the already-credited balance and adds
	// again. AddLiquidity and Swap already have this protection; Deposit was
	// missing it, leaving an inconsistent reentrancy posture across the
	// DeFi subsystem. See Swap's ECON- note for the original pattern.
	if lpm.activeUsers[user] {
		return nil, errors.New("reentrant call: user already has an in-progress DeFi operation")
	}
	lpm.activeUsers[user] = true
	defer delete(lpm.activeUsers, user)

	if lpm.userTokenBalances == nil {
		lpm.userTokenBalances = make(map[types.Address]map[string]*big.Int)
	}
	tokens, ok := lpm.userTokenBalances[user]
	if !ok {
		tokens = make(map[string]*big.Int)
		lpm.userTokenBalances[user] = tokens
	}
	cur := tokens[token]
	if cur == nil {
		cur = big.NewInt(0)
	}
	cur.Add(cur, amount)
	tokens[token] = cur
	// ECON-R13-L01 (2026-07-21): Emit event log for auditability.
	// Other DeFi operations (addLiquidity/swap/lendingSupply) already emit
	// log entries; Deposit was missing this, making it impossible to trace
	// deposit activity from logs alone.
	log.Printf("deposit: user=%x token=%s amount=%s newBalance=%s",
		user, token, amount.String(), cur.String())
	return new(big.Int).Set(cur), nil
}

// Withdraw debits a user's token balance in the LiquidityPoolManager.
// Returns an error if the user has insufficient balance.
// ECON- (2026-07-20): paired with Deposit; used by the execution layer
// when a user withdraws tokens from the DeFi subsystem back to their account.
func (lpm *LiquidityPoolManager) Withdraw(user types.Address, token string, amount *big.Int) (*big.Int, error) {
	if amount == nil || amount.Sign() <= 0 {
		return nil, errors.New("withdraw amount must be positive")
	}
	if token == "" {
		return nil, errors.New("token symbol must not be empty")
	}
	lpm.mu.Lock()
	defer lpm.mu.Unlock()

	// ECON-R13-H01 (2026-07-21) FIX: per-user reentrancy protection.
	// Withdraw debits the user's token balance. Without this guard, a
	// malicious token with transfer hooks could re-enter Withdraw during
	// the debit step and withdraw the same funds twice — the inner call
	// sees the not-yet-debited balance and approves a second withdrawal
	// before the outer call's debit commits. AddLiquidity and Swap already
	// have this protection; Withdraw was missing it, leaving an inconsistent
	// reentrancy posture across the DeFi subsystem.
	if lpm.activeUsers[user] {
		return nil, errors.New("reentrant call: user already has an in-progress DeFi operation")
	}
	lpm.activeUsers[user] = true
	defer delete(lpm.activeUsers, user)

	tokens, ok := lpm.userTokenBalances[user]
	if !ok {
		return nil, errors.New("insufficient balance: user has no deposited tokens")
	}
	cur := tokens[token]
	if cur == nil || cur.Cmp(amount) < 0 {
		return nil, errors.New("insufficient balance")
	}
	cur.Sub(cur, amount)
	tokens[token] = cur
	// ECON-R13-L01 (2026-07-21): Emit event log for auditability.
	log.Printf("withdraw: user=%x token=%s amount=%s newBalance=%s",
		user, token, amount.String(), cur.String())
	return new(big.Int).Set(cur), nil
}

// GetUserTokenBalance returns the user's currently-deposited balance for the
// given token. Returns 0 if the user has no balance entry. Read-only.
// ECON- (2026-07-20): exposed for tests and RPC balance queries.
func (lpm *LiquidityPoolManager) GetUserTokenBalance(user types.Address, token string) *big.Int {
	lpm.mu.RLock()
	defer lpm.mu.RUnlock()
	tokens, ok := lpm.userTokenBalances[user]
	if !ok {
		return big.NewInt(0)
	}
	cur := tokens[token]
	if cur == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(cur)
}

// Swap performs a token swap.
// audit-fix  added minAmountOut parameter for slippage protection.
// Without this, swaps are vulnerable to sandwich/front-running attacks
// by malicious block producers who reorder transactions to extract value.
//
// ECON- (2026-07-20) FIX: previously Swap only updated pool reserves
// without any corresponding fund movement, allowing anyone to manipulate
// the AMM price at no cost. Now Swap requires a `user` parameter and
// enforces the invariant:
//
//	userTokenBalances[user][tokenIn]  -= amountIn
//	userTokenBalances[user][tokenOut] += amountOut
//	pool.ReserveIn  += amountIn
//	pool.ReserveOut -= amountOut
//	pool.AccumulatedFeeIn += feePortion(amountIn)
//
// If the user has insufficient tokenIn balance, the swap is rejected before
// any state mutation. Per-user reentrancy protection (activeUsers) is also
// enforced.
//
// Returns the amountOut credited to the user's tokenOut balance.
func (lpm *LiquidityPoolManager) Swap(poolID string, user types.Address, tokenIn string, amountIn *big.Int, minAmountOut *big.Int) (*big.Int, error) {
	lpm.mu.Lock()
	defer lpm.mu.Unlock()

	// ECON- per-user reentrancy protection.
	if lpm.activeUsers[user] {
		return nil, errors.New("reentrant call: user already has an in-progress DeFi operation")
	}
	lpm.activeUsers[user] = true
	defer delete(lpm.activeUsers, user)

	pool, exists := lpm.pools[poolID]
	if !exists {
		return nil, errors.New("pool not found")
	}

	if amountIn == nil || amountIn.Sign() <= 0 {
		return nil, errors.New("amount must be positive")
	}

	var reserveIn, reserveOut *big.Int
	var tokenOut string
	if tokenIn == pool.TokenA {
		reserveIn = pool.ReserveA
		reserveOut = pool.ReserveB
		tokenOut = pool.TokenB
	} else if tokenIn == pool.TokenB {
		reserveIn = pool.ReserveB
		reserveOut = pool.ReserveA
		tokenOut = pool.TokenA
	} else {
		return nil, errors.New("invalid token")
	}

	// audit-fix  prevent swap on empty reserves (drains entire pool when reserveIn == 0)
	if reserveIn.Sign() <= 0 || reserveOut.Sign() <= 0 {
		return nil, errors.New("insufficient liquidity in pool")
	}

	// ECON- verify the user has enough tokenIn balance BEFORE computing
	// the swap output. This is the critical missing check — previously Swap did
	// not debit any user balance at all.
	userBalIn := lpm.getUserBalanceLocked(user, tokenIn)
	if userBalIn.Cmp(amountIn) < 0 {
		return nil, fmt.Errorf("insufficient user balance: have %s %s, need %s",
			userBalIn.String(), tokenIn, amountIn.String())
	}

	// Calculate output using constant product formula: x * y = k
	// amountOut = reserveOut * amountIn * (10000 - fee) / (reserveIn * 10000 + amountIn * (10000 - fee))
	if pool.FeeRate > 10000 {
		return nil, errors.New("invalid fee rate: must not exceed 10000 basis points")
	}

	feeMultiplier := big.NewInt(int64(10000 - pool.FeeRate)) //nolint:gosec,G115
	amountInWithFee := new(big.Int).Mul(amountIn, feeMultiplier)

	numerator := new(big.Int).Mul(reserveOut, amountInWithFee)
	denominator := new(big.Int).Mul(reserveIn, big.NewInt(10000))
	denominator.Add(denominator, amountInWithFee)

	amountOut := new(big.Int).Div(numerator, denominator)

	if amountOut.Sign() <= 0 {
		return nil, errors.New("insufficient output amount")
	}

	// audit-fix  enforce minimum output amount (slippage protection)
	if minAmountOut != nil && minAmountOut.Sign() > 0 && amountOut.Cmp(minAmountOut) < 0 {
		return nil, errors.New("output amount below minimum (slippage exceeded)")
	}

	// audit-fix NEW-18: defense-in-depth check to prevent reserve underflow.
	// The constant-product formula guarantees amountOut < reserveOut, but an
	// explicit guard protects against edge-case arithmetic errors.
	if amountOut.Cmp(reserveOut) >= 0 {
		return nil, errors.New("output exceeds available reserves")
	}

	// ECON- compute the fee portion of amountIn for accrual.
	// feePortion = amountIn * FeeRate / 10000
	// The remainder (amountIn - feePortion) is what actually enters the pool
	// reserves. This matches the AMM convention where the input amount used
	// in the constant-product formula is the post-fee amount.
	feePortion := new(big.Int).Mul(amountIn, big.NewInt(int64(pool.FeeRate))) //nolint:gosec,G115
	feePortion.Div(feePortion, big.NewInt(10000))
	amountInNet := new(big.Int).Sub(amountIn, feePortion)

	// Update reserves — only the post-fee amount enters the pool.
	if tokenIn == pool.TokenA {
		newReserveA := new(big.Int).Add(pool.ReserveA, amountInNet)
		newReserveB := new(big.Int).Sub(pool.ReserveB, amountOut)
		if newReserveB.Sign() < 0 {
			return nil, errors.New("reserve underflow: output exceeds available reserves")
		}
		pool.ReserveA = newReserveA
		pool.ReserveB = newReserveB
		// Accrue the fee portion into the pool's accumulated fees (claimable by LPs).
		pool.AccumulatedFeeA.Add(pool.AccumulatedFeeA, feePortion)
	} else {
		newReserveB := new(big.Int).Add(pool.ReserveB, amountInNet)
		newReserveA := new(big.Int).Sub(pool.ReserveA, amountOut)
		if newReserveA.Sign() < 0 {
			return nil, errors.New("reserve underflow: output exceeds available reserves")
		}
		pool.ReserveB = newReserveB
		pool.ReserveA = newReserveA
		pool.AccumulatedFeeB.Add(pool.AccumulatedFeeB, feePortion)
	}

	// ECON- actually move funds on the user balance sheet.
	// SubBalance(user, tokenIn, amountIn) — debit the full amountIn
	// (fee portion is taken by the pool; the user pays it).
	lpm.subUserBalanceLocked(user, tokenIn, amountIn)
	// AddBalance(user, tokenOut, amountOut) — credit amountOut to the user.
	lpm.addUserBalanceLocked(user, tokenOut, amountOut)

	// SECURITY (audit P3-): Log price change after swap for audit trail.
	// The pool's implicit price (ReserveA/ReserveB) has changed after the swap.
	// While there's no separate PriceOracle field, this log provides visibility
	// into price impact for monitoring and audit purposes.
	log.Printf("swap: pool=%s user=%x tokenIn=%s amountIn=%s amountOut=%s fee=%s newReserveA=%s newReserveB=%s",
		poolID, user[:min(8, len(user))], tokenIn, amountIn.String(), amountOut.String(),
		feePortion.String(), pool.ReserveA.String(), pool.ReserveB.String())

	return amountOut, nil
}

// getUserBalanceLocked returns the user's balance for a token. Caller MUST
// hold lpm.mu (read or write). ECON- (2026-07-20).
func (lpm *LiquidityPoolManager) getUserBalanceLocked(user types.Address, token string) *big.Int {
	if lpm.userTokenBalances == nil {
		return big.NewInt(0)
	}
	tokens, ok := lpm.userTokenBalances[user]
	if !ok {
		return big.NewInt(0)
	}
	cur := tokens[token]
	if cur == nil {
		return big.NewInt(0)
	}
	return cur
}

// subUserBalanceLocked debits amount from user's token balance. Caller MUST
// hold lpm.mu write lock and MUST have verified the balance is sufficient.
// ECON- (2026-07-20).
func (lpm *LiquidityPoolManager) subUserBalanceLocked(user types.Address, token string, amount *big.Int) {
	if lpm.userTokenBalances == nil {
		lpm.userTokenBalances = make(map[types.Address]map[string]*big.Int)
	}
	tokens, ok := lpm.userTokenBalances[user]
	if !ok {
		tokens = make(map[string]*big.Int)
		lpm.userTokenBalances[user] = tokens
	}
	cur := tokens[token]
	if cur == nil {
		cur = big.NewInt(0)
	}
	cur.Sub(cur, amount)
	tokens[token] = cur
}

// addUserBalanceLocked credits amount to user's token balance. Caller MUST
// hold lpm.mu write lock. ECON- (2026-07-20).
func (lpm *LiquidityPoolManager) addUserBalanceLocked(user types.Address, token string, amount *big.Int) {
	if lpm.userTokenBalances == nil {
		lpm.userTokenBalances = make(map[types.Address]map[string]*big.Int)
	}
	tokens, ok := lpm.userTokenBalances[user]
	if !ok {
		tokens = make(map[string]*big.Int)
		lpm.userTokenBalances[user] = tokens
	}
	cur := tokens[token]
	if cur == nil {
		cur = big.NewInt(0)
	}
	cur.Add(cur, amount)
	tokens[token] = cur
}

// GetPrice returns the current price of tokenA in terms of tokenB.
// R58-N1 [MEDIUM] FIX: Changed return type to *big.Rat for exact rational arithmetic.
// Previously used *big.Float which loses sub-unit precision for large reserves
// (e.g., 1_000_000_000_000_000_005 / 1_000_000_000_000_000_000 would round to 1.0).
// big.Rat preserves full precision by storing numerator and denominator separately.
func (lpm *LiquidityPoolManager) GetPrice(poolID string) (*big.Rat, error) {
	lpm.mu.RLock()
	defer lpm.mu.RUnlock()

	pool, exists := lpm.pools[poolID]
	if !exists {
		return nil, errors.New("pool not found")
	}

	if pool.ReserveA.Sign() == 0 {
		return nil, errors.New("no liquidity")
	}

	priceA := new(big.Rat).SetInt(pool.ReserveB)
	priceB := new(big.Rat).SetInt(pool.ReserveA)
	return new(big.Rat).Quo(priceA, priceB), nil
}

// GetUserLPBalance returns user's LP token balance for a pool
func (lpm *LiquidityPoolManager) GetUserLPBalance(poolID string, user types.Address) (*big.Int, error) {
	lpm.mu.RLock()
	defer lpm.mu.RUnlock()

	pool, exists := lpm.pools[poolID]
	if !exists {
		return nil, errors.New("pool not found")
	}

	balance := pool.LPBalances[user]
	if balance == nil {
		return big.NewInt(0), nil
	}
	return new(big.Int).Set(balance), nil
}

// ============================================================================
// Lending Manager
// ============================================================================

// LendingPool represents a lending/borrowing pool
type LendingPool struct {
	PoolID               string
	Asset                string
	TotalSupply          *big.Int
	TotalBorrowed        *big.Int
	Reserves             *big.Int
	SupplyRate           uint64 // basis points per year
	BorrowRate           uint64 // basis points per year
	CollateralFactor     uint64 // percentage
	LiquidationThreshold uint64 // percentage
	CreatedAt            time.Time

	// User positions
	Supplies map[types.Address]*big.Int
	Borrows  map[types.Address]*BorrowPosition
}

// BorrowPosition represents a user's borrow position
type BorrowPosition struct {
	Principal   *big.Int
	Interest    *big.Int
	LastUpdated time.Time // Kept for API backward compat; not used for interest calc
	// audit-fix  use block height instead of wall-clock time for interest accrual.
	// Wall-clock time differs across nodes, causing state divergence.
	LastUpdatedBlock uint64
}

// LendingManager manages lending pools
type LendingManager struct {
	mu    sync.RWMutex
	pools map[string]*LendingPool

	defaultCollateralFactor     uint64
	defaultLiquidationThreshold uint64
	liquidationPenalty          uint64

	// R37-FIX P2-ECON-03 (2026-07-30): close factor caps the fraction of a
	// position's total debt that a single Liquidate call may repay. Without
	// it, a mildly underwater position could be 100% liquidated in one shot
	// and the borrower's entire collateral seized (debt + penalty). Aave /
	// Compound convention is 50%. Clamped to [1, 100]; default 50.
	closeFactor uint64

	//  per-pool maximum total supply cap. Defaults to
	// DefaultMaxLendingSupply. A nil value means no cap (backward compat).
	maxTotalSupply *big.Int

	//  global maximum total supply across ALL lending pools.
	// Limits the sum of all pools' TotalSupply. Defaults to 500M QAU.
	// A nil value means no global cap (backward compat).
	globalMaxTotalSupply *big.Int

	// audit-fix CRIT-DEFI: Price oracle for asset valuation
	oracle PriceOracle

	// ECON- (2026-07-20): per-user reentrancy protection for
	// Borrow/Repay/Liquidate. Mirrors LiquidityPoolManager.activeUsers.
	// Set before pool mutation, cleared via defer on return.
	activeBorrowers map[types.Address]bool

	// ECON-R13-CRIT-002 (2026-07-21): per-user token balance sheet for the
	// lending subsystem. Supply/Repay must debit from here; Withdraw/Borrow
	// must credit to here. Without this, lending operations are purely
	// internal accounting with no actual fund movement — equivalent to
	// uncollateralized borrowing and infinite withdraw.
	// Keyed by user -> asset symbol -> balance.
	userTokenBalances map[types.Address]map[string]*big.Int
}

// NewLendingManager creates a new lending manager
func NewLendingManager(collateralFactor, liquidationThreshold, liquidationPenalty uint64, oracle PriceOracle) *LendingManager {
	// ECON-R15-M (2026-07-22): Clamp percentages to [0, 100] and enforce
	// threshold >= factor. Without this, a liquidationPenalty of 1000 (1000%)
	// would let a liquidator seize 11x the debt value in collateral, and a
	// collateralFactor > 100 would allow borrowing more than the collateral
	// value (permanently undercollateralized pool).
	if collateralFactor > 100 {
		collateralFactor = 75 // default
	}
	if liquidationThreshold > 100 {
		liquidationThreshold = 85 // default
	}
	if liquidationPenalty > 100 {
		liquidationPenalty = 5 // default
	}
	if liquidationThreshold < collateralFactor {
		liquidationThreshold = collateralFactor
	}

	if oracle == nil {
		// FIX: Log warning when no price oracle is provided. The
		// DefaultPriceOracle is fail-closed (all operations return errors),
		// so lending functionality is completely disabled until a real oracle
		// is set via SetPriceOracle(). This is safe but non-functional.
		log.Printf("WARNING: NewLendingManager created without a price oracle; lending operations will fail until SetPriceOracle() is called")
		oracle = &DefaultPriceOracle{}
	}
	return &LendingManager{
		pools:                       make(map[string]*LendingPool),
		defaultCollateralFactor:     collateralFactor,
		defaultLiquidationThreshold: liquidationThreshold,
		liquidationPenalty:          liquidationPenalty,
		closeFactor:                 50,
		maxTotalSupply:              new(big.Int).Set(DefaultMaxLendingSupply),
		globalMaxTotalSupply:        new(big.Int).Set(DefaultGlobalMaxLendingSupply),
		oracle:                      oracle,
		activeBorrowers:             make(map[types.Address]bool),
	}
}

// SetCloseFactor sets the liquidation close factor (percentage of total debt
// a single liquidation may cover). R37 P2-ECON-03: values are clamped to
// [1, 100]; the default is 50 (Aave/Compound convention).
func (lm *LendingManager) SetCloseFactor(cf uint64) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	if cf == 0 || cf > 100 {
		cf = 50
	}
	lm.closeFactor = cf
}

// SetMaxTotalSupply sets the per-pool maximum total supply cap.
//
//	allows operators to configure a custom cap. Pass nil to disable.
func (lm *LendingManager) SetMaxTotalSupply(cap *big.Int) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.maxTotalSupply = cap
}

// SetGlobalMaxSupply sets the global maximum total supply cap across all pools.
//
//	allows operators to configure a custom aggregate cap. Pass nil to disable.
func (lm *LendingManager) SetGlobalMaxSupply(cap *big.Int) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.globalMaxTotalSupply = cap
}

// GetPoolReserves returns the current protocol reserves for a lending pool.
// Reserves accumulate at 10% of borrower interest and are protocol-owned.
// Returns a copy to prevent callers from mutating internal state.
func (lm *LendingManager) GetPoolReserves(poolID string) (*big.Int, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	pool, exists := lm.pools[poolID]
	if !exists {
		return nil, errors.New("pool not found")
	}
	return new(big.Int).Set(pool.Reserves), nil
}

// WithdrawReserves withdraws protocol reserves from a lending pool to the
// specified recipient. Reserves are the protocol's 10% cut of borrower
// interest; prior to ECON-R14-H01 there was no extraction path, so reserves
// accumulated as permanently locked capital.
//
// Security properties:
//   - amount must be positive.
//   - Cannot withdraw more than pool.Reserves (underflow protection).
//   - Checks available liquidity (TotalSupply - TotalBorrowed) to avoid
//     pulling cash the pool needs for supplier withdrawals / new borrows.
//   - Uses the per-user reentrancy guard to prevent recursive calls.
//   - Credits recipient via addUserBalanceLocked; the recipient then uses
//     the normal lending-exit path to extract tokens to their wallet.
//
// NOTE: Authorisation (e.g. governance-only) is the caller's responsibility
// and is enforced at the RPC/handler layer, matching the existing pattern
// for SetMaxTotalSupply / SetGlobalMaxSupply / SetPriceOracle admin methods.
func (lm *LendingManager) WithdrawReserves(poolID string, recipient types.Address, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}
	if recipient == (types.Address{}) {
		return errors.New("recipient must not be zero address")
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.activeBorrowers[recipient] {
		return errors.New("reentrant call: recipient already has an in-progress lending operation")
	}
	lm.activeBorrowers[recipient] = true
	defer delete(lm.activeBorrowers, recipient)

	pool, exists := lm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	// ECON-R14-H01 FIX: underflow protection — cannot withdraw more
	// reserves than have been accumulated.
	if pool.Reserves.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient reserves: have %s, requested %s",
			pool.Reserves.String(), amount.String())
	}

	// ECON-R14-H01 FIX: liquidity check — ensure the pool has enough
	// free cash to cover the withdrawal. Uses the same formula
	// (TotalSupply - TotalBorrowed) as Withdraw / Borrow so that
	// reserves withdrawal cannot push suppliers / borrowers into an
	// "insufficient liquidity" state unexpectedly.
	available := new(big.Int).Sub(pool.TotalSupply, pool.TotalBorrowed)
	if available.Cmp(amount) < 0 {
		return errors.New("insufficient liquidity for reserve withdrawal")
	}

	pool.Reserves.Sub(pool.Reserves, amount)

	lm.addUserBalanceLocked(recipient, pool.Asset, amount)

	log.Printf("lendingWithdrawReserves: pool=%s recipient=%x asset=%s amount=%s newReserves=%s",
		poolID, recipient[:min(8, len(recipient))], pool.Asset, amount.String(),
		pool.Reserves.String())

	return nil
}

// SetPriceOracle sets the price oracle for asset valuation
func (lm *LendingManager) SetPriceOracle(oracle PriceOracle) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.oracle = oracle
}

// Deposit credits a user's token balance in the LendingManager.
// ECON-R13-CRIT-002 (2026-07-21): Lending operations (Supply/Repay) now
// require actual fund movement. Deposit is the credit path — it is called
// by the node's execution layer when tokens are moved into the lending
// subsystem (typically via a precompile call or RPC handler that has
// already verified the on-chain token transfer).
//
// Returns the new balance after deposit.
func (lm *LendingManager) Deposit(user types.Address, token string, amount *big.Int) (*big.Int, error) {
	if amount == nil || amount.Sign() <= 0 {
		return nil, errors.New("deposit amount must be positive")
	}
	if token == "" {
		return nil, errors.New("token symbol must not be empty")
	}
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// ECON-R13-H01 (2026-07-21) FIX: per-user reentrancy protection.
	// Mirrors the activeBorrowers guard in Supply/Withdraw/Borrow/Repay/
	// Liquidate. Deposit directly credits userTokenBalances; a reentrant
	// call from a token hook could double-credit the same deposit before
	// the outer call returns.
	if lm.activeBorrowers[user] {
		return nil, errors.New("reentrant call: user already has an in-progress lending operation")
	}
	lm.activeBorrowers[user] = true
	defer delete(lm.activeBorrowers, user)

	if lm.userTokenBalances == nil {
		lm.userTokenBalances = make(map[types.Address]map[string]*big.Int)
	}
	tokens, ok := lm.userTokenBalances[user]
	if !ok {
		tokens = make(map[string]*big.Int)
		lm.userTokenBalances[user] = tokens
	}
	cur := tokens[token]
	if cur == nil {
		cur = big.NewInt(0)
	}
	cur.Add(cur, amount)
	tokens[token] = cur
	return new(big.Int).Set(cur), nil
}

// getUserBalanceLocked returns the user's balance for a token. Caller MUST
// hold lm.mu (read or write). ECON-R13-CRIT-002 (2026-07-21).
func (lm *LendingManager) getUserBalanceLocked(user types.Address, token string) *big.Int {
	if lm.userTokenBalances == nil {
		return big.NewInt(0)
	}
	tokens, ok := lm.userTokenBalances[user]
	if !ok {
		return big.NewInt(0)
	}
	cur := tokens[token]
	if cur == nil {
		return big.NewInt(0)
	}
	return cur
}

// subUserBalanceLocked debits amount from user's token balance. Caller MUST
// hold lm.mu write lock and MUST have verified the balance is sufficient.
// ECON-R13-CRIT-002 (2026-07-21).
func (lm *LendingManager) subUserBalanceLocked(user types.Address, token string, amount *big.Int) {
	if lm.userTokenBalances == nil {
		lm.userTokenBalances = make(map[types.Address]map[string]*big.Int)
	}
	tokens, ok := lm.userTokenBalances[user]
	if !ok {
		tokens = make(map[string]*big.Int)
		lm.userTokenBalances[user] = tokens
	}
	cur := tokens[token]
	if cur == nil {
		cur = big.NewInt(0)
	}
	cur.Sub(cur, amount)
	tokens[token] = cur
}

// addUserBalanceLocked credits amount to user's token balance. Caller MUST
// hold lm.mu write lock. ECON-R13-CRIT-002 (2026-07-21).
func (lm *LendingManager) addUserBalanceLocked(user types.Address, token string, amount *big.Int) {
	if lm.userTokenBalances == nil {
		lm.userTokenBalances = make(map[types.Address]map[string]*big.Int)
	}
	tokens, ok := lm.userTokenBalances[user]
	if !ok {
		tokens = make(map[string]*big.Int)
		lm.userTokenBalances[user] = tokens
	}
	cur := tokens[token]
	if cur == nil {
		cur = big.NewInt(0)
	}
	cur.Add(cur, amount)
	tokens[token] = cur
}

// GetUserTokenBalance returns the user's currently-deposited balance for the
// given token in the lending subsystem. Returns 0 if the user has no balance
// entry. Read-only. ECON-R13-CRIT-002 (2026-07-21).
func (lm *LendingManager) GetUserTokenBalance(user types.Address, token string) *big.Int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	tokens, ok := lm.userTokenBalances[user]
	if !ok {
		return big.NewInt(0)
	}
	cur := tokens[token]
	if cur == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(cur)
}

// CreatePool creates a new lending pool
// audit-fix S2-1 [MEDIUM]: validate liquidation_threshold >= collateral_factor.
// Without this, a pool could be created where liquidationThreshold < collateralFactor,
// meaning liquidation would only trigger AFTER the borrower has already exceeded their
// borrow limit — leaving insufficient collateral to cover the debt and making all
// loans structurally undercollateralized.
// N1 FIX (2026-07-06 R2): Accept optional blockHeight for deterministic CreatedAt.
func (lm *LendingManager) CreatePool(asset string, collateralFactor, liquidationThreshold uint64, blockHeight ...uint64) (*LendingPool, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	poolID := "LEND-" + asset
	if _, exists := lm.pools[poolID]; exists {
		return nil, errors.New("pool already exists")
	}

	// ECON-R15-M (2026-07-22): Reject percentages > 100. CreatePool uses
	// per-pool parameters (not the manager defaults), so clamping in
	// NewLendingManager does not protect CreatePool. A collateralFactor or
	// liquidationThreshold > 100 would allow borrowing more than the
	// collateral value (permanently undercollateralized pool).
	if collateralFactor > 100 {
		return nil, fmt.Errorf("collateralFactor %d exceeds 100", collateralFactor)
	}
	if liquidationThreshold > 100 {
		return nil, fmt.Errorf("liquidationThreshold %d exceeds 100", liquidationThreshold)
	}

	// audit-fix S2-1 [MEDIUM]: CRITICAL INVARIANT — liquidation threshold must be at least
	// as large as the collateral factor, otherwise the pool is permanently undercollateralized.
	// collateralFactor = max borrowable % of collateral value
	// liquidationThreshold = collateral value used for liquidation health checks
	// If liquidation_threshold < collateral_factor, a borrower can be underwater (debt > borrow limit)
	// without triggering liquidation, because the health check uses liquidation_threshold.
	if liquidationThreshold < collateralFactor {
		return nil, fmt.Errorf("liquidation_threshold (%d%%) must be >= collateral_factor (%d%%): pool would be permanently undercollateralized",
			liquidationThreshold, collateralFactor)
	}

	// audit-fix NEW-17: enforce maximum pool count to prevent memory exhaustion
	if len(lm.pools) >= MaxLendingPools {
		return nil, errors.New("maximum lending pool count reached")
	}

	pool := &LendingPool{
		PoolID:               poolID,
		Asset:                asset,
		TotalSupply:          big.NewInt(0),
		TotalBorrowed:        big.NewInt(0),
		Reserves:             big.NewInt(0),
		SupplyRate:           500,  // 5% APY default
		BorrowRate:           1000, // 10% APY default
		CollateralFactor:     collateralFactor,
		LiquidationThreshold: liquidationThreshold,
		CreatedAt:            time.Unix(int64(getBlockHeight(blockHeight)), 0), // N1 FIX: deterministic
		Supplies:             make(map[types.Address]*big.Int),
		Borrows:              make(map[types.Address]*BorrowPosition),
	}

	lm.pools[poolID] = pool
	return pool, nil
}

// GetPool returns a deep copy of a lending pool by ID.
// audit-fix R3-M3: returns a copy to prevent data races when callers
// access big.Int fields outside the lock.
func (lm *LendingManager) GetPool(poolID string) (*LendingPool, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	pool, exists := lm.pools[poolID]
	if !exists {
		return nil, errors.New("pool not found")
	}
	return pool.deepCopy(), nil
}

// GetAllPools returns deep copies of all lending pools.
// audit-fix R3-M3: returns copies to prevent data races.
func (lm *LendingManager) GetAllPools() []*LendingPool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	pools := make([]*LendingPool, 0, len(lm.pools))
	for _, pool := range lm.pools {
		pools = append(pools, pool.deepCopy())
	}
	return pools
}

// deepCopy returns a deep copy of the LendingPool with all big.Int fields and maps copied.
// audit-fix R3-M3: prevents data races when callers access pool data outside the lock.
func (p *LendingPool) deepCopy() *LendingPool {
	var reserves *big.Int
	if p.Reserves != nil {
		reserves = new(big.Int).Set(p.Reserves)
	} else {
		reserves = big.NewInt(0)
	}
	cp := &LendingPool{
		PoolID:               p.PoolID,
		Asset:                p.Asset,
		TotalSupply:          new(big.Int).Set(p.TotalSupply),
		TotalBorrowed:        new(big.Int).Set(p.TotalBorrowed),
		Reserves:             reserves,
		SupplyRate:           p.SupplyRate,
		BorrowRate:           p.BorrowRate,
		CollateralFactor:     p.CollateralFactor,
		LiquidationThreshold: p.LiquidationThreshold,
		CreatedAt:            p.CreatedAt,
		Supplies:             make(map[types.Address]*big.Int, len(p.Supplies)),
		Borrows:              make(map[types.Address]*BorrowPosition, len(p.Borrows)),
	}
	for addr, bal := range p.Supplies {
		cp.Supplies[addr] = new(big.Int).Set(bal)
	}
	for addr, pos := range p.Borrows {
		cp.Borrows[addr] = &BorrowPosition{
			Principal:        new(big.Int).Set(pos.Principal),
			Interest:         new(big.Int).Set(pos.Interest),
			LastUpdated:      pos.LastUpdated,
			LastUpdatedBlock: pos.LastUpdatedBlock,
		}
	}
	return cp
}

// Supply adds assets to a lending pool
func (lm *LendingManager) Supply(poolID string, user types.Address, amount *big.Int) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// ECON- (2026-07-20): per-user reentrancy guard.
	// Borrow/Repay/Liquidate already had this protection (ECON-),
	// but Supply/Withdraw did not — a malicious ERC777-style hook or a
	// flash-loan callback could re-enter Supply mid-execution to double-
	// count a single deposit (pool.TotalSupply incremented twice while
	// the user's actual balance only moved once). Mirror the activeBorrowers
	// guard here so all four state-mutating entry points are uniformly
	// protected against reentry for the same user.
	if lm.activeBorrowers[user] {
		return errors.New("reentrant call: user already has an in-progress lending operation")
	}
	lm.activeBorrowers[user] = true
	defer delete(lm.activeBorrowers, user)

	pool, exists := lm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}

	// FIX: enforce per-pool maximum total supply cap to prevent
	// unbounded supply growth. If maxTotalSupply is nil, the cap is disabled
	// (backward compatibility).
	if lm.maxTotalSupply != nil {
		newTotal := new(big.Int).Add(pool.TotalSupply, amount)
		if newTotal.Cmp(lm.maxTotalSupply) > 0 {
			return fmt.Errorf("supply exceeds pool max total supply cap: new total %s > cap %s", newTotal.String(), lm.maxTotalSupply.String())
		}
	}

	// R14-LOW: enforce per-pool supplier count cap to prevent accrueInterest
	// DoS. accrueInterest iterates ALL suppliers to distribute yield, so an
	// attacker creating many dust accounts would make every Borrow/Repay/
	// Liquidate call O(N). Reject new suppliers (not existing ones topping
	// up) once the cap is reached.
	if pool.Supplies[user] == nil && len(pool.Supplies) >= MaxSuppliersPerLendingPool {
		return fmt.Errorf("lending pool %s has reached max supplier cap %d (accrueInterest DoS defense)",
			poolID, MaxSuppliersPerLendingPool)
	}

	// FIX: enforce global maximum total supply cap across ALL pools.
	// Sum every pool's TotalSupply plus the new amount and compare against
	// globalMaxTotalSupply. If nil, the global cap is disabled.
	if lm.globalMaxTotalSupply != nil {
		grandTotal := new(big.Int)
		for _, p := range lm.pools {
			grandTotal.Add(grandTotal, p.TotalSupply)
		}
		grandTotal.Add(grandTotal, amount)
		if grandTotal.Cmp(lm.globalMaxTotalSupply) > 0 {
			return fmt.Errorf("supply exceeds global max total supply cap: grand total %s > cap %s", grandTotal.String(), lm.globalMaxTotalSupply.String())
		}
	}

	// ECON-R13-CRIT-002 (2026-07-21) FIX: verify the user has enough of
	// pool.Asset balance BEFORE mutating pool state. Previously Supply
	// increased pool.TotalSupply without debiting the user — equivalent
	// to zero-cost deposit, which combined with zero-cost Borrow let
	// attackers drain the pool. Mirror the Supply/Borrow balance check
	// pattern used in LiquidityPoolManager.
	userBal := lm.getUserBalanceLocked(user, pool.Asset)
	if userBal.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient user balance: have %s %s, need %s",
			userBal.String(), pool.Asset, amount.String())
	}

	// Update pool total supply
	pool.TotalSupply.Add(pool.TotalSupply, amount)

	// Update user supply
	if pool.Supplies[user] == nil {
		pool.Supplies[user] = big.NewInt(0)
	}
	pool.Supplies[user].Add(pool.Supplies[user], amount)

	// ECON-R13-CRIT-002 FIX: actually debit the supplied tokens from the
	// user's balance sheet.
	lm.subUserBalanceLocked(user, pool.Asset, amount)

	// Update interest rates based on utilization
	lm.updateRates(pool)

	log.Printf("lendingSupply: pool=%s user=%x asset=%s amount=%s newTotalSupply=%s newUserSupply=%s",
		poolID, user[:min(8, len(user))], pool.Asset, amount.String(),
		pool.TotalSupply.String(), pool.Supplies[user].String())

	return nil
}

// Withdraw removes assets from a lending pool.
// audit-fix: accepts blockHeight for block-aware price oracle (prevents
// same-block flash-loan oracle manipulation), matching Borrow/Liquidate.
func (lm *LendingManager) Withdraw(poolID string, user types.Address, amount *big.Int, blockHeight ...uint64) error {
	// R37-P3-41 FIX (2026-07-31): blockHeight is REQUIRED for flash-loan
	// oracle protection (FreshnessMinBlocks), matching Borrow/Liquidate.
	// When omitted, the price freshness check is skipped and an attacker
	// can manipulate the oracle in the same block and immediately withdraw
	// against the manipulated price.
	if len(blockHeight) == 0 {
		return errors.New("blockHeight is required for price freshness check")
	}
	currentBlock := blockHeight[0]

	lm.mu.Lock()
	defer lm.mu.Unlock()

	// ECON- (2026-07-20): per-user reentrancy guard.
	// Mirrors the guard in Supply/Borrow/Repay/Liquidate. A reentrant
	// Withdraw could be triggered by a token hook firing during the
	// state-mutation window, allowing a second Withdraw to observe
	// stale TotalSupply / Supplies[user] values and double-spend the
	// pool's liquidity before the first call's balance updates land.
	if lm.activeBorrowers[user] {
		return errors.New("reentrant call: user already has an in-progress lending operation")
	}
	lm.activeBorrowers[user] = true
	defer delete(lm.activeBorrowers, user)

	pool, exists := lm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	// audit-fix NEW-10: reject non-positive amounts to prevent supply inflation
	// via big.Int.Sub with negative values
	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}

	userSupply := pool.Supplies[user]
	if userSupply == nil || userSupply.Cmp(amount) < 0 {
		return errors.New("insufficient supply balance")
	}

	// Check available liquidity
	available := new(big.Int).Sub(pool.TotalSupply, pool.TotalBorrowed)
	if available.Cmp(amount) < 0 {
		return errors.New("insufficient liquidity")
	}

	// Update pool total supply
	pool.TotalSupply.Sub(pool.TotalSupply, amount)

	// Update user supply
	pool.Supplies[user].Sub(pool.Supplies[user], amount)

	// audit-fix H-WITHDRAW-1: check health factor after withdrawal.
	// Without this, a user can withdraw collateral until their position
	// becomes undercollateralized, with no borrow-time check catching it
	// until the next Borrow call.
	hasBorrow := false
	for _, p := range lm.pools {
		if b, ok := p.Borrows[user]; ok && b != nil && b.Principal != nil && b.Principal.Sign() > 0 {
			hasBorrow = true
			break
		}
	}
	if hasBorrow {
		assetTypes := make(map[string]bool)
		for _, p := range lm.pools {
			assetTypes[p.Asset] = true
		}
		assets := make([]string, 0, len(assetTypes))
		for asset := range assetTypes {
			assets = append(assets, asset)
		}
		// R37-P3-41 FIX (2026-07-31): currentBlock was already extracted at
		// the top of Withdraw (mandatory). Reuse it here instead of re-reading
		// from the variadic parameter.
		// audit-fix: use block-aware oracle method to enforce price freshness.
		// This prevents same-block flash-loan oracle manipulation.
		prices, err := lm.oracle.GetPricesWithBlock(assets, currentBlock)
		if err != nil {
			pool.TotalSupply.Add(pool.TotalSupply, amount)
			pool.Supplies[user].Add(pool.Supplies[user], amount)
			return fmt.Errorf("failed to get prices for health check: %w", err)
		}

		for _, p := range lm.pools {
			if b, ok := p.Borrows[user]; ok && b != nil && b.Principal != nil && b.Principal.Sign() > 0 {
				lm.accrueInterest(p, user, currentBlock)
			}
		}

		totalCollateralValue := big.NewInt(0)
		totalDebtValue := big.NewInt(0)
		for _, p := range lm.pools {
			price, hasPrice := prices[p.Asset]
			if !hasPrice || price == nil || price.Sign() <= 0 {
				continue
			}
			if supply, ok := p.Supplies[user]; ok && supply != nil && supply.Sign() > 0 {
				contribution := new(big.Int).Mul(supply, big.NewInt(int64(p.LiquidationThreshold)))
				contribution.Div(contribution, big.NewInt(100))
				contribution.Mul(contribution, price)
				totalCollateralValue.Add(totalCollateralValue, contribution)
			}
			if borrow, ok := p.Borrows[user]; ok && borrow != nil && borrow.Principal != nil {
				debtAmount := new(big.Int).Set(borrow.Principal)
				if borrow.Interest != nil && borrow.Interest.Sign() > 0 {
					debtAmount.Add(debtAmount, borrow.Interest)
				}
				if debtAmount.Sign() > 0 {
					debtValue := new(big.Int).Mul(debtAmount, price)
					totalDebtValue.Add(totalDebtValue, debtValue)
				}
			}
		}

		if totalDebtValue.Sign() > 0 && totalCollateralValue.Cmp(totalDebtValue) < 0 {
			pool.TotalSupply.Add(pool.TotalSupply, amount)
			pool.Supplies[user].Add(pool.Supplies[user], amount)
			return errors.New("withdrawal would make position undercollateralized")
		}
	}

	// Update interest rates
	lm.updateRates(pool)

	// ECON-R13-CRIT-002 (2026-07-21) FIX: actually credit the withdrawn
	// tokens to the user's balance sheet. Previously Withdraw reduced
	// pool.TotalSupply and Supplies[user] but returned no tokens —
	// equivalent to stealing the user's deposit.
	lm.addUserBalanceLocked(user, pool.Asset, amount)

	log.Printf("lendingWithdraw: pool=%s user=%x asset=%s amount=%s newTotalSupply=%s newUserSupply=%s",
		poolID, user[:min(8, len(user))], pool.Asset, amount.String(),
		pool.TotalSupply.String(), pool.Supplies[user].String())

	return nil
}

// Borrow borrows assets from a lending pool.
// audit-fix  accepts blockHeight for deterministic interest accrual.
// N1 FIX (2026-07-06 R2): Accept optional blockTimestamp to replace time.Now()
// for LastUpdated field, ensuring consensus determinism.
func (lm *LendingManager) Borrow(poolID string, user types.Address, amount *big.Int, blockHeight ...uint64) error {
	// R37-P3-41 FIX (2026-07-31): blockHeight is REQUIRED for flash-loan
	// oracle protection (FreshnessMinBlocks). When omitted, the price
	// freshness check is skipped because the oracle sees blockHeight==0
	// and falls back to time-based staleness only — an attacker can
	// manipulate the oracle in the same block and immediately borrow
	// against the manipulated price. Reject the call when blockHeight
	// is not provided to enforce defense-in-depth.
	if len(blockHeight) == 0 {
		return errors.New("blockHeight is required for price freshness check")
	}
	currentBlock := blockHeight[0]

	lm.mu.Lock()
	defer lm.mu.Unlock()

	// ECON- per-user reentrancy guard. Prevents a malicious Borrow
	// implementation from re-entering via callbacks during state mutation.
	if lm.activeBorrowers[user] {
		return errors.New("reentrant call: user already has an in-progress lending operation")
	}
	lm.activeBorrowers[user] = true
	defer delete(lm.activeBorrowers, user)

	pool, exists := lm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}

	// Check available liquidity
	available := new(big.Int).Sub(pool.TotalSupply, pool.TotalBorrowed)
	if available.Cmp(amount) < 0 {
		return errors.New("insufficient liquidity")
	}

	// audit-fix CRIT-DEFI: use price oracle for proper asset valuation
	// Collect all asset types involved
	assetTypes := make(map[string]bool)
	for _, p := range lm.pools {
		assetTypes[p.Asset] = true
	}
	assets := make([]string, 0, len(assetTypes))
	for asset := range assetTypes {
		assets = append(assets, asset)
	}

	// audit-fix R63-CRIT-DeFi: use block-aware oracle method to enforce price
	// freshness. This prevents same-block flash-loan oracle manipulation.
	prices, err := lm.oracle.GetPricesWithBlock(assets, currentBlock)
	if err != nil {
		return fmt.Errorf("failed to get prices from oracle: %w", err)
	}

	// audit-fix H-DEFI-3: accrue interest on ALL existing borrows before checking
	// collateralization. Previously, Borrow only read borrow.Principal + borrow.Interest
	// without calling accrueInterest first, so any interest accrued since the last
	// update was invisible to the health check. This allowed users to borrow more
	// than their collateral supports, because the debt was understated.
	for _, p := range lm.pools {
		if borrow, ok := p.Borrows[user]; ok && borrow != nil && borrow.Principal != nil && borrow.Principal.Sign() > 0 {
			lm.accrueInterest(p, user, currentBlock)
		}
	}

	// audit-fix CRIT-6: cross-pool collateral check with price adjustment.
	// The original check only looked at the user's supply in *this* pool, allowing
	// an attacker to supply in pool A and then borrow uncollateralised in pool B.
	// We now aggregate collateral value and total borrow across ALL pools with price adjustment.
	totalCollateralValue := big.NewInt(0)
	totalBorrowValue := big.NewInt(0)

	for _, p := range lm.pools {
		// Get collateral value with price adjustment
		if supply, ok := p.Supplies[user]; ok && supply != nil && supply.Sign() > 0 {
			// collateral contribution = supply * collateralFactor / 100
			contribution := new(big.Int).Mul(supply, big.NewInt(int64(p.CollateralFactor))) // #nosec G115 -- CollateralFactor is percentage 0-100
			contribution.Div(contribution, big.NewInt(100))
			// Multiply by asset price to get USD value
			if price, ok := prices[p.Asset]; ok {
				contribution.Mul(contribution, price)
				totalCollateralValue.Add(totalCollateralValue, contribution)
			}
		}
		// Get debt value with price adjustment
		if borrow, ok := p.Borrows[user]; ok && borrow != nil && borrow.Principal != nil {
			debtAmount := new(big.Int).Set(borrow.Principal)
			if borrow.Interest != nil && borrow.Interest.Sign() > 0 {
				debtAmount.Add(debtAmount, borrow.Interest)
			}
			// Multiply by asset price to get USD value
			if price, ok := prices[p.Asset]; ok {
				debtAmount.Mul(debtAmount, price)
				totalBorrowValue.Add(totalBorrowValue, debtAmount)
			}
		}
	}

	poolPrice, poolPriceOk := prices[pool.Asset]
	if !poolPriceOk || poolPrice == nil || poolPrice.Sign() <= 0 {
		return fmt.Errorf("no valid price for asset %s", pool.Asset)
	}

	newBorrowValue := new(big.Int).Mul(amount, poolPrice)
	newTotalBorrow := new(big.Int).Add(totalBorrowValue, newBorrowValue)
	if newTotalBorrow.Cmp(totalCollateralValue) > 0 {
		return errors.New("insufficient collateral")
	}

	// Update pool total borrowed
	pool.TotalBorrowed.Add(pool.TotalBorrowed, amount)

	// Update user borrow position
	if pool.Borrows[user] == nil {
		pool.Borrows[user] = &BorrowPosition{
			Principal:        big.NewInt(0),
			Interest:         big.NewInt(0),
			LastUpdated:      time.Unix(int64(currentBlock), 0), // N1 FIX: deterministic — use block as time
			LastUpdatedBlock: currentBlock,
		}
	}
	pool.Borrows[user].Principal.Add(pool.Borrows[user].Principal, amount)
	// N1 FIX: Use deterministic block-based time instead of wall-clock time.
	pool.Borrows[user].LastUpdated = time.Unix(int64(currentBlock), 0)
	if currentBlock > 0 {
		pool.Borrows[user].LastUpdatedBlock = currentBlock
	}

	// Update interest rates
	lm.updateRates(pool)

	// ECON-R13-CRIT-002 (2026-07-21) FIX: actually credit the borrowed
	// tokens to the user's balance sheet. Previously Borrow increased
	// pool.TotalBorrowed and the user's debt but never transferred any
	// tokens — equivalent to uncollateralized borrowing with no payout.
	// The borrower must receive the loan principal so they can use it.
	lm.addUserBalanceLocked(user, pool.Asset, amount)

	log.Printf("lendingBorrow: pool=%s user=%x asset=%s amount=%s newTotalBorrowed=%s newPrincipal=%s",
		poolID, user[:min(8, len(user))], pool.Asset, amount.String(),
		pool.TotalBorrowed.String(), pool.Borrows[user].Principal.String())

	return nil
}

// Repay repays borrowed assets.
// audit-fix  accepts blockHeight for deterministic interest accrual.
func (lm *LendingManager) Repay(poolID string, user types.Address, amount *big.Int, blockHeight ...uint64) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// ECON- per-user reentrancy guard. Prevents callbacks during
	// repayment from re-entering Borrow/Repay/Liquidate for the same user.
	if lm.activeBorrowers[user] {
		return errors.New("reentrant call: user already has an in-progress lending operation")
	}
	lm.activeBorrowers[user] = true
	defer delete(lm.activeBorrowers, user)

	pool, exists := lm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	// audit-fix NEW-11: reject non-positive amounts to prevent interest inflation
	// via big.Int.Sub with negative values
	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}

	borrow := pool.Borrows[user]
	if borrow == nil || borrow.Principal.Sign() == 0 {
		return errors.New("no borrow position")
	}

	// Calculate accrued interest
	currentBlock := uint64(0)
	if len(blockHeight) > 0 {
		currentBlock = blockHeight[0]
	}
	lm.accrueInterest(pool, user, currentBlock)

	totalOwed := new(big.Int).Add(borrow.Principal, borrow.Interest)

	// ECON-R13-CRIT-002 (2026-07-21) FIX: verify the user has enough of
	// pool.Asset balance BEFORE mutating borrow state. Previously Repay
	// reduced borrow.Principal/Interest without debiting the user —
	// equivalent to cost-free debt repayment, which combined with
	// zero-cost Borrow let attackers take infinite loans and repay them
	// without ever putting up collateral.
	//
	// The check uses the REQUESTED amount (not the clamped amount) so a
	// user with insufficient balance cannot trigger any state mutation
	// even when the requested amount exceeds totalOwed. Callers that
	// want to repay exactly the debt should query totalOwed first.
	userBal := lm.getUserBalanceLocked(user, pool.Asset)
	if userBal.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient user balance for repay: have %s %s, need %s",
			userBal.String(), pool.Asset, amount.String())
	}

	if amount.Cmp(totalOwed) > 0 {
		amount = totalOwed
	}

	// Pay interest first, then principal
	if amount.Cmp(borrow.Interest) <= 0 {
		borrow.Interest.Sub(borrow.Interest, amount)
	} else {
		remaining := new(big.Int).Sub(amount, borrow.Interest)
		borrow.Interest.SetInt64(0)
		// ECON-R14-H02 (2026-07-21) defensive: clamp remaining to
		// borrow.Principal so a corrupted/out-of-sync TotalBorrowed
		// can never produce a negative principal or TotalBorrowed
		// (big.Int.Sub wraps to a huge positive value on underflow,
		// which would catastrophically break utilization/liquidity
		// math). Under normal operation remaining <= Principal because
		// amount was clamped to totalOwed = Principal + Interest.
		if remaining.Cmp(borrow.Principal) > 0 {
			remaining.Set(borrow.Principal)
		}
		borrow.Principal.Sub(borrow.Principal, remaining)
		if pool.TotalBorrowed.Cmp(remaining) >= 0 {
			pool.TotalBorrowed.Sub(pool.TotalBorrowed, remaining)
		} else {
			// Out-of-sync — reset to zero rather than wrapping negative.
			pool.TotalBorrowed.SetInt64(0)
		}
	}

	// N1 FIX: Use deterministic block-based time instead of wall-clock time.
	borrow.LastUpdated = time.Unix(int64(currentBlock), 0)
	if currentBlock > 0 {
		borrow.LastUpdatedBlock = currentBlock
	}

	// Update interest rates
	lm.updateRates(pool)

	// ECON-R13-CRIT-002 FIX: actually debit the repaid tokens from the
	// user's balance sheet. Without this, the borrower could repay debt
	// without spending any tokens.
	lm.subUserBalanceLocked(user, pool.Asset, amount)

	log.Printf("lendingRepay: pool=%s user=%x asset=%s amount=%s newPrincipal=%s newInterest=%s",
		poolID, user[:min(8, len(user))], pool.Asset, amount.String(),
		borrow.Principal.String(), borrow.Interest.String())

	return nil
}

// GetUserPosition returns user's lending position
func (lm *LendingManager) GetUserPosition(poolID string, user types.Address) (supplied, borrowed, interest *big.Int, err error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	pool, exists := lm.pools[poolID]
	if !exists {
		return nil, nil, nil, errors.New("pool not found")
	}

	supplied = big.NewInt(0)
	if pool.Supplies[user] != nil {
		supplied = new(big.Int).Set(pool.Supplies[user])
	}

	borrowed = big.NewInt(0)
	interest = big.NewInt(0)
	if pool.Borrows[user] != nil {
		borrowed = new(big.Int).Set(pool.Borrows[user].Principal)
		interest = new(big.Int).Set(pool.Borrows[user].Interest)
	}

	return supplied, borrowed, interest, nil
}

// updateRates updates interest rates based on utilization
func (lm *LendingManager) updateRates(pool *LendingPool) {
	if pool.TotalSupply.Sign() == 0 {
		pool.SupplyRate = 0
		pool.BorrowRate = 500 // 5% base rate
		return
	}

	// Utilization = TotalBorrowed / TotalSupply
	utilization := new(big.Int).Mul(pool.TotalBorrowed, big.NewInt(10000))
	utilization.Div(utilization, pool.TotalSupply)
	utilizationPct := utilization.Uint64()

	// Interest rate model: base rate + utilization * slope
	// Borrow rate: 5% + utilization * 15%
	pool.BorrowRate = 500 + (utilizationPct * 15 / 100)

	// Supply rate: borrow rate * utilization * (1 - reserve factor)
	// Reserve factor = 10%
	pool.SupplyRate = pool.BorrowRate * utilizationPct * 90 / 10000 / 100
}

// accrueInterest calculates and adds accrued interest.
// audit-fix  uses block height for deterministic accrual across nodes.
// Falls back to wall-clock time if blockHeight is 0 (backward compat).
// audit-fix HIGH: wall-clock fallback can cause non-deterministic results between nodes.
// For production, all accruals should use block height.
func (lm *LendingManager) accrueInterest(pool *LendingPool, user types.Address, currentBlock uint64) {
	borrow := pool.Borrows[user]
	if borrow == nil || borrow.Principal.Sign() == 0 {
		return
	}

	var blocksDelta uint64
	blocksPerYear := uint64(2628000)

	if currentBlock > 0 && borrow.LastUpdatedBlock > 0 && currentBlock > borrow.LastUpdatedBlock {
		blocksDelta = currentBlock - borrow.LastUpdatedBlock
	} else {
		// F1-1 CRITICAL FIX: Always update LastUpdatedBlock even when we can't
		// compute blocksDelta. This prevents infinite interest-free borrowing
		// where a borrower could call accrueInterest repeatedly with the same
		// currentBlock and never advance LastUpdatedBlock, accruing zero interest.
		borrow.LastUpdatedBlock = currentBlock
		return
	}

	if blocksDelta == 0 || pool.BorrowRate == 0 {
		// F1-1 CRITICAL FIX: Always update LastUpdatedBlock even when no interest
		// accrues. This ensures the next call has a fresh reference point.
		borrow.LastUpdatedBlock = currentBlock
		return
	}

	interest := new(big.Int).Mul(borrow.Principal, big.NewInt(int64(pool.BorrowRate))) // #nosec G115 -- BorrowRate is percentage
	interest.Mul(interest, new(big.Int).SetUint64(blocksDelta))
	interest.Div(interest, big.NewInt(10000))
	interest.Div(interest, new(big.Int).SetUint64(blocksPerYear))

	borrow.Interest.Add(borrow.Interest, interest)

	// R37-P3-40 FIX (2026-07-31): Add accrued interest to pool.TotalBorrowed.
	// Previously, only borrow.Interest was updated but pool.TotalBorrowed
	// remained unchanged, causing TotalBorrowed to under-report the actual
	// total debt by the amount of all accrued interest. This led to:
	//   - utilization rate being systematically under-stated
	//   - liquidity checks (TotalSupply - TotalBorrowed) over-estimating
	//     available liquidity, allowing withdrawals/borrows that should fail
	//   - supply rate calculations based on a too-small borrowed base
	pool.TotalBorrowed.Add(pool.TotalBorrowed, interest)

	// audit-fix H-SUPPLY-1: distribute interest to suppliers.
	// Previously, borrower interest was only added to borrowPos.Interest
	// but never made available to suppliers. The pool.SupplyRate was
	// calculated but never applied. Now, each time interest accrues for
	// a borrower, the same amount is added to pool.TotalSupply so that
	// suppliers earn yield proportional to their share of the pool.
	// Reserve factor (10%) is retained by the protocol; 90% goes to suppliers.
	supplierInterest := new(big.Int).Mul(interest, big.NewInt(90))
	supplierInterest.Div(supplierInterest, big.NewInt(100))
	reserveAmount := new(big.Int).Sub(interest, supplierInterest)
	if reserveAmount.Sign() > 0 {
		if pool.Reserves == nil {
			pool.Reserves = big.NewInt(0)
		}
		pool.Reserves.Add(pool.Reserves, reserveAmount)
	}
	if supplierInterest.Sign() > 0 {
		// audit-fix: distribute interest to individual suppliers proportionally.
		// Previously, supplierInterest was only added to TotalSupply, leaving
		// individual supplier balances stale. Suppliers could never withdraw
		// their accrued yield. Now distribute by supply share before updating TotalSupply.
		// SECURITY (audit P0-): Distribute interest with remainder tracking
		// to prevent dust attack. Previously, integer division truncation caused
		// each supplier's share to be rounded down, and the accumulated remainder
		// was lost. Attackers could create many dust accounts (1 wei each) to make
		// all shares truncate to 0, then steal the accumulated interest.
		// Fix: Track the remainder and add it to the first supplier.
		//
		// SECURITY (audit P0-): Previous fix placed remainder calculation
		// INSIDE the loop, causing the first supplier to receive ALL remaining
		// interest (not just the truncation remainder). Now the remainder is
		// calculated AFTER the loop completes. Also, suppliers are sorted by
		// address for deterministic iteration order (prevents node state divergence).
		//
		// ECON-R13-H03 (2026-07-21) FIX: The previous code unconditionally
		// executed `pool.TotalSupply.Add(pool.TotalSupply, supplierInterest)`
		// AFTER the `if pool.TotalSupply.Sign() > 0` block. When TotalSupply
		// was 0 (a rare but reachable state — e.g., a pool where every
		// supplier has Withdrawn to zero but a borrower still owes Principal),
		// the supplier distribution loop was skipped (no suppliers to pay),
		// yet TotalSupply was still incremented by supplierInterest. This
		// violated the invariant TotalSupply == sum(Supplies), causing
		// TotalSupply to drift permanently upward while no supplier owned
		// the phantom balance. Downstream Withdraw/interest-rate math then
		// produced wrong results for every subsequent call.
		//
		// Fix: Only update TotalSupply when we actually distributed to at
		// least one supplier. When there are no suppliers (TotalSupply == 0
		// or no positive Supplies entries), the interest is redirected to
		// the protocol reserve — this is the safest bookkeeping choice
		// because the borrower still owes the interest, but the protocol
		// (not a phantom supplier) accounts for the unattributable yield.
		distributed := big.NewInt(0)
		if pool.TotalSupply.Sign() > 0 {
			// Sort suppliers by address for deterministic iteration order
			suppliers := make([]types.Address, 0, len(pool.Supplies))
			for addr := range pool.Supplies {
				if pool.Supplies[addr].Sign() > 0 {
					suppliers = append(suppliers, addr)
				}
			}
			sort.Slice(suppliers, func(i, j int) bool {
				return bytes.Compare(suppliers[i][:], suppliers[j][:]) < 0
			})
			// Phase 1: Distribute proportional shares
			for _, addr := range suppliers {
				supply := pool.Supplies[addr]
				share := new(big.Int).Mul(supplierInterest, supply)
				share.Div(share, pool.TotalSupply)
				pool.Supplies[addr].Add(pool.Supplies[addr], share)
				distributed.Add(distributed, share)
			}
			// Phase 2: Give the true remainder to the first supplier
			remainder := new(big.Int).Sub(supplierInterest, distributed)
			if remainder.Sign() > 0 && len(suppliers) > 0 {
				pool.Supplies[suppliers[0]].Add(pool.Supplies[suppliers[0]], remainder)
				distributed.Add(distributed, remainder)
			}
			// Invariant preserved: sum(Supplies) increased by `distributed`,
			// which equals supplierInterest (after remainder accounting).
			// Update TotalSupply by the same amount so they stay in sync.
			pool.TotalSupply.Add(pool.TotalSupply, distributed)
		} else {
			// ECON-R13-H03: No suppliers to receive the yield — redirect to
			// protocol reserve so the borrower's debt accounting stays
			// consistent with the pool's liability accounting. Without this,
			// the borrower would owe interest that nobody is owed TO,
			// creating an accounting black hole.
			if pool.Reserves == nil {
				pool.Reserves = big.NewInt(0)
			}
			pool.Reserves.Add(pool.Reserves, supplierInterest)
		}
	}

	borrow.LastUpdatedBlock = currentBlock
}

// Liquidate liquidates an undercollateralized borrow position.
// The liquidator repays 'debtToCover' of the borrow and receives
// 'debtToCover * (100 + liquidationPenalty) / 100' of collateral.
// audit-fix CRIT-LIQ: implement missing liquidation function.
// audit-fix CRIT-LIQ-2: cross-pool liquidation - position health is checked
// across ALL pools (matching Borrow's cross-pool collateral check), but
// collateral is seized from the specified pool first, then other pools if needed.
// R47-CS-08 NOTE: The lock is held for the entire liquidation to ensure
// atomicity of cross-pool collateral seizure. Releasing the lock mid-operation
// would allow concurrent modifications to borrower positions, potentially
// causing double-spend or inconsistent state. Lock contention is acceptable
// because liquidations are rare events.
func (lm *LendingManager) Liquidate(poolID string, liquidator, borrower types.Address, debtToCover *big.Int, blockHeight ...uint64) error {
	// R37-P3-41 FIX (2026-07-31): blockHeight is REQUIRED for flash-loan
	// oracle protection (FreshnessMinBlocks), matching Borrow/Withdraw.
	// When omitted, the price freshness check is skipped and an attacker
	// can manipulate the oracle in the same block and immediately liquidate
	// against the manipulated price.
	if len(blockHeight) == 0 {
		return errors.New("blockHeight is required for price freshness check")
	}
	currentBlock := blockHeight[0]

	lm.mu.Lock()
	defer lm.mu.Unlock()

	// ECON- per-user reentrancy guard for both liquidator and
	// borrower. Liquidation touches both accounts' state; if either is
	// already mid-operation, refuse to avoid state corruption.
	if lm.activeBorrowers[liquidator] {
		return errors.New("reentrant call: liquidator already has an in-progress lending operation")
	}
	if lm.activeBorrowers[borrower] {
		return errors.New("reentrant call: borrower already has an in-progress lending operation")
	}
	lm.activeBorrowers[liquidator] = true
	lm.activeBorrowers[borrower] = true
	defer func() {
		delete(lm.activeBorrowers, liquidator)
		delete(lm.activeBorrowers, borrower)
	}()

	pool, exists := lm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	if debtToCover.Sign() <= 0 {
		return errors.New("debt to cover must be positive")
	}

	// R37-P3-41 FIX (2026-07-31): currentBlock was already extracted at
	// the top of Liquidate (mandatory). Reuse it here instead of re-reading
	// from the variadic parameter.

	borrowPos := pool.Borrows[borrower]
	if borrowPos == nil || borrowPos.Principal.Sign() == 0 {
		return errors.New("no borrow position")
	}

	for _, p := range lm.pools {
		if b, ok := p.Borrows[borrower]; ok && b != nil && b.Principal != nil && b.Principal.Sign() > 0 {
			lm.accrueInterest(p, borrower, currentBlock)
		}
	}

	assetTypes := make(map[string]bool)
	for _, p := range lm.pools {
		assetTypes[p.Asset] = true
	}
	assets := make([]string, 0, len(assetTypes))
	for asset := range assetTypes {
		assets = append(assets, asset)
	}

	prices, err := lm.oracle.GetPricesWithBlock(assets, currentBlock)
	if err != nil {
		return fmt.Errorf("failed to get prices from oracle: %w", err)
	}

	// Calculate total debt across ALL pools (with price adjustment)
	totalDebtValue := big.NewInt(0)
	for _, p := range lm.pools {
		if borrow, ok := p.Borrows[borrower]; ok && borrow != nil {
			debtAmount := big.NewInt(0)
			if borrow.Principal != nil {
				debtAmount.Add(debtAmount, borrow.Principal)
			}
			if borrow.Interest != nil && borrow.Interest.Sign() > 0 {
				debtAmount.Add(debtAmount, borrow.Interest)
			}
			// Multiply by asset price
			if price, ok := prices[p.Asset]; ok {
				debtValue := new(big.Int).Mul(debtAmount, price)
				totalDebtValue.Add(totalDebtValue, debtValue)
			}
		}
	}

	// Calculate total collateral value across pools (with price adjustment)
	// audit-fix CRITICAL: use LiquidationThreshold instead of CollateralFactor.
	// CollateralFactor determines max borrowable amount, but LiquidationThreshold
	// determines the effective collateral value for liquidation checks.
	// Formula: effectiveCollateral = supply * liquidationThreshold / 100
	totalCollateralValue := big.NewInt(0)
	for _, p := range lm.pools {
		if supply, ok := p.Supplies[borrower]; ok && supply != nil && supply.Sign() > 0 {
			collateralAmount := new(big.Int).Mul(supply, big.NewInt(int64(p.LiquidationThreshold))) // #nosec G115 -- LiquidationThreshold is percentage
			collateralAmount.Div(collateralAmount, big.NewInt(100))
			// Multiply by asset price
			if price, ok := prices[p.Asset]; ok {
				collateralValue := new(big.Int).Mul(collateralAmount, price)
				totalCollateralValue.Add(totalCollateralValue, collateralValue)
			}
		}
	}

	if totalDebtValue.Sign() == 0 {
		return errors.New("position has no debt")
	}

	// Check if position is actually undercollateralized using price-adjusted values
	// healthFactor = totalCollateralValue / totalDebtValue
	// Position is liquidatable when healthFactor < 1
	if totalCollateralValue.Cmp(totalDebtValue) >= 0 {
		return errors.New("position is not undercollateralized")
	}

	// Calculate actual debt to cover (cap at total debt)
	actualDebt := debtToCover
	liqPoolPrice, liqPoolPriceOk := prices[pool.Asset]
	if !liqPoolPriceOk || liqPoolPrice == nil || liqPoolPrice.Sign() <= 0 {
		return fmt.Errorf("no valid price for asset %s in liquidation", pool.Asset)
	}
	debtValue := new(big.Int).Mul(actualDebt, liqPoolPrice)
	if debtValue.Cmp(totalDebtValue) > 0 {
		actualDebt = new(big.Int).Div(totalDebtValue, liqPoolPrice)
		debtValue = totalDebtValue
	}

	// R39-P2-04 (2026-08-02) FIX (defi Liquidation actualDebt boundary):
	// audit finding — "Liquidation's actualDebt boundary only had a fixed
	// path, not the master-ledger verified standard." The master-ledger invariant is
	// that actualDebt (the amount the liquidator pays in pool.Asset and
	// the amount subtracted from borrowPos.Interest+Principal at line
	// 2804-2820) MUST be capped to what the CURRENT pool's borrow
	// position can actually absorb. Without this cap, a multi-pool
	// borrower (debt in pool A AND pool B) calling Liquidate(pool=A,
	// debtToCover=huge) had `actualDebt` capped only to the cross-pool
	// totalDebtValue at line 2646 — but the line 2804 repayment path
	// only subtracts from pool A's borrowPos. The liquidator pays the
	// full cross-pool `actualDebt` in pool.Asset tokens, while pool B's
	// debt remains untouched → protocol silently gains the difference
	// (liquidator paid X, pool A debt reduced by Y, pool B debt
	// unchanged; X−Y tokens vanish from the accounting ledger).
	//
	// The fix caps `actualDebt` to the current pool's borrow position
	// debt (Principal + Interest) AS DENOMINATED IN pool.Asset TOKEN
	// UNITS — not the cross-pool value. This is the strict master-ledger
	// invariant: actualDebt cannot exceed what `borrowPos` can be
	// reduced by. We compute currentPoolDebtTokenNative = borrowPos.
	// Interest + borrowPos.Principal; if actualDebt > that, cap and
	// recompute debtValue accordingly. The close-factor cap at line
	// 2660 already further restricts actualDebt, so we expose a
	// TIGHTER upper bound here; the close-factor math operates on
	// `debtValue` (line 2658) which we keep consistent.
	//
	// We also assert the post-cap actualDebt equals the in-protocol
	// amount the liquidator will be debited (line 2839), so the
	// the protocol-lateral "master" value is consistent end-to-end.
	currentPoolDebtNative := new(big.Int)
	if borrowPos.Principal != nil {
		currentPoolDebtNative.Add(currentPoolDebtNative, borrowPos.Principal)
	}
	if borrowPos.Interest != nil && borrowPos.Interest.Sign() > 0 {
		currentPoolDebtNative.Add(currentPoolDebtNative, borrowPos.Interest)
	}
	if currentPoolDebtNative.Sign() <= 0 {
		// Defensive: line 2566 already rejects Principal.Sign()==0,
		// but a future refactor that loosens that check would let
		// actualDebt flow into the repayment path with nothing to
		// subtract from. Refuse explicitly so the audit's "master-ledger
		// verified" standard holds regardless of upstream changes.
		return errors.New("R39-P2-04: current pool borrow position has zero debt; refusing to liquidate against an empty position")
	}
	if actualDebt.Cmp(currentPoolDebtNative) > 0 {
		// Cap actualDebt to the current pool's borrow position debt.
		// Without this, the protocol-ledger invariant breaks (see
		// the audit finding above).
		actualDebt = new(big.Int).Set(currentPoolDebtNative)
		debtValue = new(big.Int).Mul(actualDebt, liqPoolPrice)
	}

	// R37-FIX P2-ECON-03 (2026-07-30): close-factor cap. A single liquidation
	// may not repay more than closeFactor % of the total debt. This prevents
	// a mildly underwater position from being fully liquidated in one call,
	// matching the Aave / Compound borrower-protection convention.
	closeFactor := lm.closeFactor
	if closeFactor == 0 {
		closeFactor = 50 // defensive fallback
	}
	maxCloseValue := new(big.Int).Mul(totalDebtValue, big.NewInt(int64(closeFactor)))
	maxCloseValue.Div(maxCloseValue, big.NewInt(100))
	if debtValue.Cmp(maxCloseValue) > 0 {
		actualDebt = new(big.Int).Div(maxCloseValue, liqPoolPrice)
		debtValue = maxCloseValue
	}

	// Calculate collateral reward VALUE (in USD/base currency units).
	// collateralRewardValue = debtValue * (100 + penalty) / 100
	penalty := lm.liquidationPenalty
	if penalty == 0 {
		penalty = 5
	}
	//  int64(100+penalty) is safe — penalty is a small uint32 (default 5),
	// so 100+penalty max is ~105, far below int64 max. No overflow possible.
	collateralRewardValue := new(big.Int).Mul(debtValue, big.NewInt(int64(100+penalty))) //nolint:gosec,G115
	collateralRewardValue.Div(collateralRewardValue, big.NewInt(100))

	// ECON-R13-CRIT-002 (2026-07-21) FIX: verify the liquidator has enough
	// pool.Asset balance to repay debtToCover BEFORE any state mutation.
	// Liquidation requires the liquidator to pay actualDebt in pool.Asset
	// tokens. Without this check, the liquidator could liquidate positions
	// for free.
	liquidatorBal := lm.getUserBalanceLocked(liquidator, pool.Asset)
	if liquidatorBal.Cmp(actualDebt) < 0 {
		return fmt.Errorf("insufficient liquidator balance: have %s %s, need %s to cover debt",
			liquidatorBal.String(), pool.Asset, actualDebt.String())
	}

	// Collect collateral from pools (primary pool first, then others).
	// audit-fix H-DEFI-1: Convert collateralNeededValue to each pool's asset units
	// using the price oracle. Previously, collateralNeeded was in the primary pool's
	// raw token units, but when seizing from other pools with different-priced assets,
	// the same raw amount has a different USD value, causing incorrect seizure amounts.
	collateralNeededValue := new(big.Int).Set(collateralRewardValue)
	liquidatedCollateralValue := big.NewInt(0)
	// ECON-R13-CRIT-003 (2026-07-21): track per-asset seized amounts so we
	// can credit them to the liquidator after the loop completes. Without
	// this, seized collateral was deleted from the borrower but never
	// transferred to anyone — it just vanished.
	seizedByAsset := make(map[string]*big.Int)

	// Seize from primary pool first
	primaryCollateral := pool.Supplies[borrower]
	if primaryCollateral != nil && primaryCollateral.Sign() > 0 {
		primaryPrice := prices[pool.Asset]
		if primaryPrice != nil && primaryPrice.Sign() > 0 {
			primaryCollateralValue := new(big.Int).Mul(primaryCollateral, primaryPrice)
			seizeValue := collateralNeededValue
			if seizeValue.Cmp(primaryCollateralValue) > 0 {
				seizeValue = new(big.Int).Set(primaryCollateralValue)
			}
			if seizeValue.Sign() > 0 {
				// Convert seize value back to token amount: seizeTokens = seizeValue / price
				seizeTokens := new(big.Int).Div(seizeValue, primaryPrice)
				if seizeTokens.Sign() > 0 {
					if seizeTokens.Cmp(primaryCollateral) > 0 {
						seizeTokens = new(big.Int).Set(primaryCollateral)
					}
					pool.Supplies[borrower].Sub(pool.Supplies[borrower], seizeTokens)
					// audit-fix H-DEFI-2: update TotalSupply when seizing collateral
					pool.TotalSupply.Sub(pool.TotalSupply, seizeTokens)
					if pool.Supplies[borrower].Sign() == 0 {
						delete(pool.Supplies, borrower)
					}
					actualSeizeValue := new(big.Int).Mul(seizeTokens, primaryPrice)
					liquidatedCollateralValue.Add(liquidatedCollateralValue, actualSeizeValue)
					collateralNeededValue.Sub(collateralNeededValue, actualSeizeValue)
					// ECON-R13-CRIT-003: track for liquidator credit.
					if existing, ok := seizedByAsset[pool.Asset]; ok {
						existing.Add(existing, seizeTokens)
					} else {
						seizedByAsset[pool.Asset] = new(big.Int).Set(seizeTokens)
					}
				}
			}
		}
	}

	// If more collateral needed, seize from other pools with price conversion
	if collateralNeededValue.Sign() > 0 {
		for _, p := range lm.pools {
			if p == pool || collateralNeededValue.Sign() <= 0 {
				continue
			}
			otherCollateral := p.Supplies[borrower]
			if otherCollateral == nil || otherCollateral.Sign() <= 0 {
				continue
			}
			otherPrice := prices[p.Asset]
			if otherPrice == nil || otherPrice.Sign() <= 0 {
				continue
			}
			otherCollateralValue := new(big.Int).Mul(otherCollateral, otherPrice)
			seizeValue := collateralNeededValue
			if seizeValue.Cmp(otherCollateralValue) > 0 {
				seizeValue = new(big.Int).Set(otherCollateralValue)
			}
			if seizeValue.Sign() > 0 {
				seizeTokens := new(big.Int).Div(seizeValue, otherPrice)
				if seizeTokens.Sign() > 0 {
					if seizeTokens.Cmp(otherCollateral) > 0 {
						seizeTokens = new(big.Int).Set(otherCollateral)
					}
					p.Supplies[borrower].Sub(p.Supplies[borrower], seizeTokens)
					// audit-fix H-DEFI-2: update TotalSupply when seizing collateral
					p.TotalSupply.Sub(p.TotalSupply, seizeTokens)
					if p.Supplies[borrower].Sign() == 0 {
						delete(p.Supplies, borrower)
					}
					actualSeizeValue := new(big.Int).Mul(seizeTokens, otherPrice)
					liquidatedCollateralValue.Add(liquidatedCollateralValue, actualSeizeValue)
					collateralNeededValue.Sub(collateralNeededValue, actualSeizeValue)
					// ECON-R13-CRIT-003: track for liquidator credit.
					if existing, ok := seizedByAsset[p.Asset]; ok {
						existing.Add(existing, seizeTokens)
					} else {
						seizedByAsset[p.Asset] = new(big.Int).Set(seizeTokens)
					}
				}
			}
		}
	}

	if liquidatedCollateralValue.Sign() == 0 {
		return errors.New("no collateral to liquidate")
	}

	// Proportionally reduce debt repayment if collateral was insufficient
	if liquidatedCollateralValue.Cmp(collateralRewardValue) < 0 {
		actualDebtValue := new(big.Int).Mul(liquidatedCollateralValue, big.NewInt(100))
		actualDebtValue.Div(actualDebtValue, big.NewInt(int64(100+penalty))) //nolint:gosec,G115
		actualDebt = new(big.Int).Div(actualDebtValue, liqPoolPrice)
		// R37-P3-39 FIX (2026-07-31): Do NOT force actualDebt to 1 wei when
		// it rounds to 0. The previous code (`actualDebt = big.NewInt(1)`)
		// allowed a liquidator to pay 1 wei of debt and seize ALL residual
		// collateral when the position was deeply underwater (collateral value
		// was too small to cover even 1 wei of debt after the liquidation
		// penalty). This is an effective 100% gift of residual collateral to
		// the liquidator at the expense of suppliers. When actualDebt rounds
		// to 0, the position is not economically liquidatable — reject it.
		if actualDebt.Sign() == 0 {
			return errors.New("liquidation not economically viable: collateral insufficient to cover minimum debt after penalty")
		}
	}

	// Execute liquidation: reduce borrower's debt
	if actualDebt.Cmp(borrowPos.Interest) <= 0 {
		borrowPos.Interest.Sub(borrowPos.Interest, actualDebt)
	} else {
		remaining := new(big.Int).Sub(actualDebt, borrowPos.Interest)
		borrowPos.Interest.SetInt64(0)
		// ECON-R14-H02 (2026-07-21) defensive: same clamp as Repay to
		// prevent big.Int underflow if TotalBorrowed drifts out of sync.
		if remaining.Cmp(borrowPos.Principal) > 0 {
			remaining.Set(borrowPos.Principal)
		}
		borrowPos.Principal.Sub(borrowPos.Principal, remaining)
		if pool.TotalBorrowed.Cmp(remaining) >= 0 {
			pool.TotalBorrowed.Sub(pool.TotalBorrowed, remaining)
		} else {
			pool.TotalBorrowed.SetInt64(0)
		}
	}

	// Update interest rates for affected pools
	lm.updateRates(pool)
	for _, p := range lm.pools {
		if p != pool {
			lm.updateRates(p)
		}
	}

	// ECON-R13-CRIT-003 (2026-07-21) FIX: actually move funds between
	// liquidator and lending subsystem. Previously the comment said "this
	// is where token transfers to the liquidator would occur" — but no
	// transfer ever happened. The liquidator paid nothing and received
	// nothing, while the borrower's collateral was deleted (vanished).
	// Now: (1) debit actualDebt in pool.Asset from the liquidator (they
	// are paying off the borrower's debt), and (2) credit all seized
	// collateral tokens to the liquidator across each asset.
	lm.subUserBalanceLocked(liquidator, pool.Asset, actualDebt)
	for asset, seizedAmount := range seizedByAsset {
		if seizedAmount.Sign() > 0 {
			lm.addUserBalanceLocked(liquidator, asset, seizedAmount)
		}
	}

	log.Printf("lendingLiquidate: pool=%s liquidator=%x borrower=%x debtCovered=%s penalty=%d%% collateralValue=%s seizedAssets=%d",
		poolID, liquidator[:min(8, len(liquidator))], borrower[:min(8, len(borrower))],
		actualDebt.String(), penalty, liquidatedCollateralValue.String(), len(seizedByAsset))

	return nil
}

// GetHealthFactor returns the health factor of a borrow position.
// Returns value < 1.0 if undercollateralized, >= 1.0 if healthy.
// audit-fix CRIT-LIQ-2: uses cross-pool calculation to match Liquidate behavior.
// audit-fix R63-CRIT-DeFi: accepts blockHeight to enforce price freshness.
func (lm *LendingManager) GetHealthFactor(poolID string, borrower types.Address, blockHeight uint64) (float64, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	// audit-fix M-DEFI-4: collect all asset types and fetch prices from oracle.
	// Previously, GetHealthFactor added raw token amounts from different pools
	// together without price conversion. If a user supplied 1 ETH (worth $2000)
	// in pool A and borrowed 1000 USDC in pool B, the health factor was
	// computed as 1/1000 = 0.001 instead of the correct 2000*0.85/1000 = 1.7.
	// This made cross-pool positions appear far less healthy than they actually
	// are, causing premature liquidations.
	assetTypes := make(map[string]bool)
	for _, p := range lm.pools {
		assetTypes[p.Asset] = true
	}
	assets := make([]string, 0, len(assetTypes))
	for asset := range assetTypes {
		assets = append(assets, asset)
	}
	// audit-fix R63-CRIT-DeFi: use block-aware price fetching for health check.
	// Prevents health factor manipulation via same-block price updates.
	prices, err := lm.oracle.GetPricesWithBlock(assets, blockHeight)
	if err != nil {
		return 0, fmt.Errorf("failed to get prices from oracle: %w", err)
	}

	// If poolID is specified, only calculate for that pool
	if poolID != "" {
		pool, exists := lm.pools[poolID]
		if !exists {
			return 0, errors.New("pool not found")
		}
		return lm.calculatePoolHealthFactorWithPrices(pool, borrower, prices)
	}

	totalDebtValue := big.NewInt(0)
	totalCollateralValue := big.NewInt(0)

	for _, p := range lm.pools {
		price, hasPrice := prices[p.Asset]
		// N4 FIX (2026-07-06 R2): When an asset has no valid price, fail-closed
		// by treating its debt at maximum severity instead of silently skipping.
		// This prevents oracle manipulation from hiding debt to avoid liquidation.
		if !hasPrice || price == nil || price.Sign() <= 0 {
			// If the user has debt in this asset but no price, treat as
			// undercollateralized by counting the debt at a very high notional price.
			if borrow, ok := p.Borrows[borrower]; ok && borrow != nil {
				debtAmount := big.NewInt(0)
				if borrow.Principal != nil {
					debtAmount.Set(borrow.Principal)
				}
				if borrow.Interest != nil && borrow.Interest.Sign() > 0 {
					debtAmount.Add(debtAmount, borrow.Interest)
				}
				if debtAmount.Sign() > 0 {
					// Use a very large price to ensure this debt is not ignored.
					// This makes the health factor 0 (undercollateralized),
					// triggering liquidation rather than hiding the debt.
					penaltyPrice := new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil)
					debtValue := new(big.Int).Mul(debtAmount, penaltyPrice)
					totalDebtValue.Add(totalDebtValue, debtValue)
				}
			}
			continue
		}
		if borrow, ok := p.Borrows[borrower]; ok && borrow != nil {
			debtAmount := big.NewInt(0)
			if borrow.Principal != nil {
				debtAmount.Set(borrow.Principal)
			}
			if borrow.Interest != nil && borrow.Interest.Sign() > 0 {
				debtAmount.Add(debtAmount, borrow.Interest)
			}
			if debtAmount.Sign() > 0 {
				debtValue := new(big.Int).Mul(debtAmount, price)
				totalDebtValue.Add(totalDebtValue, debtValue)
			}
		}
		if supply, ok := p.Supplies[borrower]; ok && supply != nil && supply.Sign() > 0 {
			contribution := new(big.Int).Mul(supply, big.NewInt(int64(p.LiquidationThreshold))) // #nosec G115 -- LiquidationThreshold is percentage
			contribution.Div(contribution, big.NewInt(100))
			contribution.Mul(contribution, price)
			totalCollateralValue.Add(totalCollateralValue, contribution)
		}
	}

	if totalDebtValue.Sign() == 0 {
		return 1.0, nil
	}

	if totalCollateralValue.Sign() == 0 {
		return 0.0, nil
	}

	// F1-5 MEDIUM FIX: Use big.Rat for precise rational arithmetic instead of big.Float.
	// Using float64 for financial health factor calculations causes precision loss:
	// collateralFloat.Quo() -> Float64 loses sub-unit precision. For a health factor,
	// precision loss could mask an undercollateralized position or cause incorrect
	// liquidation decisions. big.Rat maintains exact fractions indefinitely.
	collateralRat := new(big.Rat).SetInt(totalCollateralValue)
	debtRat := new(big.Rat).SetInt(totalDebtValue)
	healthRat := new(big.Rat).Quo(collateralRat, debtRat)
	healthFactor, _ := healthRat.Float64()
	return healthFactor, nil
}

// calculatePoolHealthFactorWithPrices calculates health factor for a single pool
// using price oracle for proper asset valuation.
// audit-fix M-DEFI-4: accepts pre-fetched prices to avoid redundant oracle calls.
func (lm *LendingManager) calculatePoolHealthFactorWithPrices(pool *LendingPool, borrower types.Address, prices map[string]*big.Int) (float64, error) {
	price, hasPrice := prices[pool.Asset]
	if !hasPrice || price == nil || price.Sign() <= 0 {
		return 0, fmt.Errorf("no price available for asset %s", pool.Asset)
	}

	totalDebtValue := big.NewInt(0)
	totalCollateralValue := big.NewInt(0)

	if borrow, ok := pool.Borrows[borrower]; ok && borrow != nil {
		debtAmount := big.NewInt(0)
		if borrow.Principal != nil {
			debtAmount.Set(borrow.Principal)
		}
		if borrow.Interest != nil && borrow.Interest.Sign() > 0 {
			debtAmount.Add(debtAmount, borrow.Interest)
		}
		if debtAmount.Sign() > 0 {
			totalDebtValue.Mul(debtAmount, price)
		}
	}

	if supply, ok := pool.Supplies[borrower]; ok && supply != nil && supply.Sign() > 0 {
		contribution := new(big.Int).Mul(supply, big.NewInt(int64(pool.LiquidationThreshold))) // #nosec G115 -- LiquidationThreshold is percentage
		contribution.Div(contribution, big.NewInt(100))
		contribution.Mul(contribution, price)
		totalCollateralValue.Add(totalCollateralValue, contribution)
	}

	if totalDebtValue.Sign() == 0 {
		return 1.0, nil
	}

	if totalCollateralValue.Sign() == 0 {
		return 0.0, nil
	}

	// F1-5 MEDIUM FIX: Use big.Rat for precise rational arithmetic instead of big.Float.
	// Using float64 for financial health factor calculations causes precision loss:
	// collateralFloat.Quo() -> Float64 loses sub-unit precision. For a health factor,
	// precision loss could mask an undercollateralized position or cause incorrect
	// liquidation decisions. big.Rat maintains exact fractions indefinitely.
	collateralRat := new(big.Rat).SetInt(totalCollateralValue)
	debtRat := new(big.Rat).SetInt(totalDebtValue)
	healthRat := new(big.Rat).Quo(collateralRat, debtRat)
	healthFactor, _ := healthRat.Float64()
	return healthFactor, nil
}

// GetUtilizationRate returns the utilization rate of a pool
func (lm *LendingManager) GetUtilizationRate(poolID string) (uint64, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	pool, exists := lm.pools[poolID]
	if !exists {
		return 0, errors.New("pool not found")
	}

	if pool.TotalSupply.Sign() == 0 {
		return 0, nil
	}

	utilization := new(big.Int).Mul(pool.TotalBorrowed, big.NewInt(100))
	utilization.Div(utilization, pool.TotalSupply)
	return utilization.Uint64(), nil
}

// ============================================================================
// Yield Farming Manager
// ============================================================================

// YieldFarm represents a yield farming pool
type YieldFarm struct {
	FarmID         string
	Name           string
	LPToken        string
	RewardToken    string
	TotalStaked    *big.Int
	RewardPerBlock *big.Int
	Multiplier     uint64 // basis points (100 = 1x, 200 = 2x)
	StartBlock     uint64
	EndBlock       uint64
	Status         string // ACTIVE, ENDED, PAUSED
	CreatedAt      time.Time

	// User stakes
	Stakes map[types.Address]*FarmStake

	// Accumulated rewards per share (exact rational, no scaling needed)
	// R58-N7 [LOW] FIX: Use *big.Rat instead of *big.Int with 1e12 scaling.
	// big.Int division truncates when TotalStaked is large and reward is small,
	// causing AccRewardPerShare to stagnate at zero — small stakers lose rewards.
	// big.Rat preserves fractional precision exactly, eliminating the scaling hack.
	AccRewardPerShare *big.Rat
	LastRewardBlock   uint64

	// ECON-R14-CRIT-003 (2026-07-21): Reward pool tracks the actual reward
	// tokens deposited into the farm that have NOT yet been accrued to
	// stakers. updateFarm MUST debit from here when accrual is added to
	// AccRewardPerShare, moving the funds into ReservedRewards.
	RewardPool *big.Int

	// R37-P1-ECON-01 (2026-07-30): ReservedRewards is the liability account
	// holding rewards already accrued to stakers (via updateFarm) but not
	// yet paid out. Harvest/Unstake pay out from HERE — not from
	// RewardPool. Previously updateFarm deducted RewardPool at accrual AND
	// Harvest/Unstake deducted it again at payout (double deduction): the
	// pool drained at 2x speed, and once empty, updateFarm silently stopped
	// accruing while LastRewardBlock still advanced — users' rewards were
	// permanently lost. Invariant: RewardPool + ReservedRewards + paidOut
	// == total funded via FundRewardPool.
	ReservedRewards *big.Int
}

// FarmStake represents a user's stake in a farm
type FarmStake struct {
	Amount         *big.Int
	RewardDebt     *big.Rat // exact rational; updated to stake.Amount * AccRewardPerShare on deposit/claim
	PendingRewards *big.Int // accumulated rewards between stake/unstake operations
	StartBlock     uint64
}

// YieldFarmingManager manages yield farms
type YieldFarmingManager struct {
	mu    sync.RWMutex
	farms map[string]*YieldFarm

	rewardPerBlock *big.Int
	currentBlock   uint64

	// ECON- (2026-07-20): per-user reentrancy protection.
	// Tracks addresses currently executing a mutating farming op
	// (Stake/Unstake/Harvest). Matches the activeUsers pattern in
	// LiquidityPoolManager. Prevents a malicious contract from re-entering
	// Harvest mid-execution to double-claim rewards, or re-entering
	// Unstake to withdraw the same stake twice.
	activeUsers map[types.Address]bool

	// ECON-R14-CRIT-001/002/003 (2026-07-21): per-user token balance sheet
	// for the yield-farming subsystem. Stake MUST debit LP tokens from here;
	// Unstake MUST credit LP tokens back; Harvest MUST credit reward tokens.
	// Without this, farming is purely internal accounting with no actual
	// fund movement — equivalent to staking without LP and harvesting
	// without reward transfer. Keyed by user -> token symbol -> balance.
	userTokenBalances map[types.Address]map[string]*big.Int

	// R14-MED (2026-07-21): CreateFarm authorization. When non-zero,
	// only farmCreatorAddr may call CreateFarm. When zero (default),
	// CreateFarm is unrestricted (backward-compat for existing
	// initializers that do not configure an authorized creator).
	// Operators SHOULD call SetFarmCreator during node startup to
	// lock down farm creation.
	farmCreatorAddr types.Address
}

// SetFarmCreator authorizes a single address to create new yield farms.
// R14-MED (2026-07-21): Without this, any caller can create farms with
// arbitrary parameters (multiplier, rewardPerBlock) — combined with
// ECON-R14-CRIT-003 (rewards minted from thin air), an unauthorized
// farm creator could siphon inflated rewards. SetFarmCreator is
// one-time-settable: once a non-zero address is configured, it cannot
// be changed (prevents an attacker who momentarily obtains the admin
// key from permanently redirecting authorization to a different addr).
func (yfm *YieldFarmingManager) SetFarmCreator(addr types.Address) error {
	yfm.mu.Lock()
	defer yfm.mu.Unlock()
	if yfm.farmCreatorAddr != (types.Address{}) {
		return errors.New("farm creator already set; cannot be changed after initialization")
	}
	if addr == (types.Address{}) {
		return errors.New("farm creator address cannot be zero address")
	}
	yfm.farmCreatorAddr = addr
	return nil
}

// NewYieldFarmingManager creates a new yield farming manager
func NewYieldFarmingManager(rewardPerBlock *big.Int) *YieldFarmingManager {
	// ECON-R15-M (2026-07-22): Default nil to 0 and clamp negative to 0.
	// A nil rewardPerBlock would cause nil-pointer dereferences in reward
	// calculations; a negative rewardPerBlock would drain the reward pool
	// on every distribution, allowing an operator to silently destroy
	// stakers' pending rewards.
	if rewardPerBlock == nil {
		rewardPerBlock = big.NewInt(0)
	} else if rewardPerBlock.Sign() < 0 {
		rewardPerBlock = big.NewInt(0)
	}
	return &YieldFarmingManager{
		farms:             make(map[string]*YieldFarm),
		rewardPerBlock:    rewardPerBlock,
		currentBlock:      1,
		activeUsers:       make(map[types.Address]bool),
		userTokenBalances: make(map[types.Address]map[string]*big.Int),
	}
}

// ECON-R14-CRIT-001/002/003 (2026-07-21): per-user token balance helpers
// for the yield-farming subsystem. Mirror the LendingManager pattern. Callers
// MUST hold yfm.mu write lock (or RLock for the getter).
func (yfm *YieldFarmingManager) getUserBalanceLocked(user types.Address, token string) *big.Int {
	if yfm.userTokenBalances == nil {
		return big.NewInt(0)
	}
	tokens, ok := yfm.userTokenBalances[user]
	if !ok {
		return big.NewInt(0)
	}
	cur := tokens[token]
	if cur == nil {
		return big.NewInt(0)
	}
	return cur
}

func (yfm *YieldFarmingManager) subUserBalanceLocked(user types.Address, token string, amount *big.Int) {
	if yfm.userTokenBalances == nil {
		yfm.userTokenBalances = make(map[types.Address]map[string]*big.Int)
	}
	tokens, ok := yfm.userTokenBalances[user]
	if !ok {
		tokens = make(map[string]*big.Int)
		yfm.userTokenBalances[user] = tokens
	}
	cur := tokens[token]
	if cur == nil {
		cur = big.NewInt(0)
	}
	cur.Sub(cur, amount)
	tokens[token] = cur
}

func (yfm *YieldFarmingManager) addUserBalanceLocked(user types.Address, token string, amount *big.Int) {
	if yfm.userTokenBalances == nil {
		yfm.userTokenBalances = make(map[types.Address]map[string]*big.Int)
	}
	tokens, ok := yfm.userTokenBalances[user]
	if !ok {
		tokens = make(map[string]*big.Int)
		yfm.userTokenBalances[user] = tokens
	}
	cur := tokens[token]
	if cur == nil {
		cur = big.NewInt(0)
	}
	cur.Add(cur, amount)
	tokens[token] = cur
}

// GetUserTokenBalance returns the user's currently-deposited balance for the
// given token in the yield-farming subsystem. Read-only.
// ECON-R14-CRIT-001/002/003 (2026-07-21).
func (yfm *YieldFarmingManager) GetUserTokenBalance(user types.Address, token string) *big.Int {
	yfm.mu.RLock()
	defer yfm.mu.RUnlock()
	tokens, ok := yfm.userTokenBalances[user]
	if !ok {
		return big.NewInt(0)
	}
	cur := tokens[token]
	if cur == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(cur)
}

// DepositTokens credits tokens to a user's farming-subsystem balance sheet.
// Required so users can deposit LP tokens before staking and so governance
// can fund a farm's reward pool (when token == farm.RewardToken and a
// corresponding FundRewardPool call follows).
// ECON-R14-CRIT-001/002/003 (2026-07-21).
func (yfm *YieldFarmingManager) DepositTokens(user types.Address, token string, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}
	yfm.mu.Lock()
	defer yfm.mu.Unlock()
	yfm.addUserBalanceLocked(user, token, amount)
	return nil
}

// FundRewardPool deposits reward tokens into a farm's reward pool. The
// caller MUST have already credited the same amount to the farming subsystem
// via DepositTokens (or be the governance/treasury account with sufficient
// balance). The amount is debited from the funder's balance sheet and added
// to farm.RewardPool so updateFarm can debit against it.
// ECON-R14-CRIT-003 (2026-07-21).
func (yfm *YieldFarmingManager) FundRewardPool(farmID string, funder types.Address, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}
	yfm.mu.Lock()
	defer yfm.mu.Unlock()
	farm, exists := yfm.farms[farmID]
	if !exists {
		return errors.New("farm not found")
	}
	bal := yfm.getUserBalanceLocked(funder, farm.RewardToken)
	if bal.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient reward-token balance: have %s, need %s",
			bal.String(), amount.String())
	}
	yfm.subUserBalanceLocked(funder, farm.RewardToken, amount)
	if farm.RewardPool == nil {
		farm.RewardPool = big.NewInt(0)
	}
	farm.RewardPool.Add(farm.RewardPool, amount)
	return nil
}

// SetCurrentBlock updates the current block number
func (yfm *YieldFarmingManager) SetCurrentBlock(block uint64) {
	yfm.mu.Lock()
	defer yfm.mu.Unlock()
	yfm.currentBlock = block
}

// CreateFarm creates a new yield farm
// N1 FIX (2026-07-06 R2): CreatedAt uses currentBlock for determinism.
//
// R14-MED (2026-07-21): Added caller parameter + authorization check.
// When yfm.farmCreatorAddr is set (non-zero), only that address may
// create farms. When farmCreatorAddr is the zero address (default,
// backward-compat), authorization is skipped — operators SHOULD call
// SetFarmCreator during node startup to lock this down.
func (yfm *YieldFarmingManager) CreateFarm(name, lpToken, rewardToken string, rewardPerBlock *big.Int, multiplier uint64, caller types.Address) (*YieldFarm, error) {
	yfm.mu.Lock()
	defer yfm.mu.Unlock()

	// R14-MED: Authorization check. Skip only when farmCreatorAddr is
	// unset (zero) to preserve backward compatibility with initializers
	// that have not yet been updated to configure an authorized creator.
	if yfm.farmCreatorAddr != (types.Address{}) {
		if caller != yfm.farmCreatorAddr {
			return nil, errors.New("unauthorized: caller is not the authorized farm creator")
		}
	}

	farmID := "FARM-" + lpToken
	if _, exists := yfm.farms[farmID]; exists {
		return nil, errors.New("farm already exists")
	}

	// audit-fix NEW-17: enforce maximum farm count to prevent memory exhaustion
	if len(yfm.farms) >= MaxYieldFarms {
		return nil, errors.New("maximum yield farm count reached")
	}

	// R32-P3-05 FIX (2026-07-28): validate multiplier and rewardPerBlock to
	// prevent reward calculation memory DoS. Without these caps, a malicious
	// farm creator could set Multiplier = math.MaxUint64 or a huge
	// RewardPerBlock, causing updateFarmRewards/calculatePendingReward to
	// allocate huge big.Int values (reward = RewardPerBlock * blocks *
	// Multiplier), consuming gigabytes of memory per farm update.
	if multiplier > MaxFarmMultiplier {
		return nil, fmt.Errorf("farm multiplier %d exceeds maximum %d (basis points: 100=1x, %d=10000x)",
			multiplier, MaxFarmMultiplier, MaxFarmMultiplier)
	}
	if rewardPerBlock == nil || rewardPerBlock.Sign() < 0 {
		return nil, errors.New("rewardPerBlock must be non-negative")
	}
	if rewardPerBlock.Sign() > 0 && rewardPerBlock.Cmp(maxBlockReward) > 0 {
		return nil, fmt.Errorf("rewardPerBlock %s exceeds maximum allowed %s",
			rewardPerBlock.String(), maxBlockReward.String())
	}

	farm := &YieldFarm{
		FarmID:            farmID,
		Name:              name,
		LPToken:           lpToken,
		RewardToken:       rewardToken,
		TotalStaked:       big.NewInt(0),
		RewardPerBlock:    rewardPerBlock,
		Multiplier:        multiplier,
		StartBlock:        yfm.currentBlock,
		EndBlock:          yfm.currentBlock + 2500000, // ~1 year at 12s blocks
		Status:            "ACTIVE",
		CreatedAt:         time.Unix(int64(yfm.currentBlock), 0), // N1 FIX: deterministic
		Stakes:            make(map[types.Address]*FarmStake),
		AccRewardPerShare: new(big.Rat), // R58-N7 fix: exact rational, no 1e12 scaling
		LastRewardBlock:   yfm.currentBlock,
		RewardPool:        big.NewInt(0), // ECON-R14-CRIT-003: starts empty, funded via FundRewardPool
	}

	yfm.farms[farmID] = farm
	return farm, nil
}

// GetFarm returns a deep copy of a farm by ID.
// audit-fix R3-M3: returns a copy to prevent data races.
func (yfm *YieldFarmingManager) GetFarm(farmID string) (*YieldFarm, error) {
	yfm.mu.RLock()
	defer yfm.mu.RUnlock()

	farm, exists := yfm.farms[farmID]
	if !exists {
		return nil, errors.New("farm not found")
	}
	return farm.deepCopy(), nil
}

// GetAllFarms returns deep copies of all yield farms.
// audit-fix R3-M3: returns copies to prevent data races.
func (yfm *YieldFarmingManager) GetAllFarms() []*YieldFarm {
	yfm.mu.RLock()
	defer yfm.mu.RUnlock()

	farms := make([]*YieldFarm, 0, len(yfm.farms))
	for _, farm := range yfm.farms {
		farms = append(farms, farm.deepCopy())
	}
	return farms
}

// deepCopy returns a deep copy of the YieldFarm with all big.Int fields and maps copied.
// audit-fix R3-M3: prevents data races when callers access farm data outside the lock.
func (f *YieldFarm) deepCopy() *YieldFarm {
	cp := &YieldFarm{
		FarmID:            f.FarmID,
		Name:              f.Name,
		LPToken:           f.LPToken,
		RewardToken:       f.RewardToken,
		TotalStaked:       new(big.Int).Set(f.TotalStaked),
		RewardPerBlock:    new(big.Int).Set(f.RewardPerBlock),
		Multiplier:        f.Multiplier,
		StartBlock:        f.StartBlock,
		EndBlock:          f.EndBlock,
		Status:            f.Status,
		CreatedAt:         f.CreatedAt,
		Stakes:            make(map[types.Address]*FarmStake, len(f.Stakes)),
		AccRewardPerShare: new(big.Rat).Set(f.AccRewardPerShare), // R58-N7 fix: *big.Rat
		LastRewardBlock:   f.LastRewardBlock,
	}
	if f.RewardPool != nil {
		cp.RewardPool = new(big.Int).Set(f.RewardPool)
	}
	if f.ReservedRewards != nil {
		cp.ReservedRewards = new(big.Int).Set(f.ReservedRewards)
	}
	for addr, stake := range f.Stakes {
		cp.Stakes[addr] = &FarmStake{
			Amount:         new(big.Int).Set(stake.Amount),
			RewardDebt:     new(big.Rat).Set(stake.RewardDebt), // R58-N7 fix: *big.Rat
			PendingRewards: new(big.Int).Set(stake.PendingRewards),
			StartBlock:     stake.StartBlock,
		}
	}
	return cp
}

// Stake stakes LP tokens in a farm
func (yfm *YieldFarmingManager) Stake(farmID string, user types.Address, amount *big.Int) error {
	yfm.mu.Lock()
	defer yfm.mu.Unlock()

	// ECON- per-user reentrancy protection.
	if yfm.activeUsers[user] {
		return errors.New("reentrant call: user already has an in-progress farming operation")
	}
	yfm.activeUsers[user] = true
	defer delete(yfm.activeUsers, user)

	farm, exists := yfm.farms[farmID]
	if !exists {
		return errors.New("farm not found")
	}

	if farm.Status != "ACTIVE" {
		return errors.New("farm is not active")
	}

	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}

	// ECON-R14-CRIT-001 (2026-07-21) FIX: actually debit LP tokens from the
	// user's balance sheet. Previously Stake only updated farm.Stakes and
	// farm.TotalStaked without removing LP tokens from the user — allowing
	// anyone to stake without owning LP and infinitely farm rewards.
	lpBal := yfm.getUserBalanceLocked(user, farm.LPToken)
	if lpBal.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient LP token balance: have %s, need %s",
			lpBal.String(), amount.String())
	}

	// Update farm rewards
	yfm.updateFarm(farm)

	// If user has existing stake, harvest pending rewards first
	if stake := farm.Stakes[user]; stake != nil && stake.Amount.Sign() > 0 {
		pending := yfm.calculatePendingReward(farm, stake)
		stake.PendingRewards.Add(stake.PendingRewards, pending)
	}

	// Update or create user stake
	if farm.Stakes[user] == nil {
		farm.Stakes[user] = &FarmStake{
			Amount:         big.NewInt(0),
			RewardDebt:     new(big.Rat), // R58-N7 fix: exact rational, no 1e12 scaling
			PendingRewards: big.NewInt(0),
			StartBlock:     yfm.currentBlock,
		}
	}

	farm.Stakes[user].Amount.Add(farm.Stakes[user].Amount, amount)
	farm.TotalStaked.Add(farm.TotalStaked, amount)

	// ECON-R14-CRIT-001: debit LP tokens from user balance sheet.
	yfm.subUserBalanceLocked(user, farm.LPToken, amount)

	// Update reward debt: rewardDebt = stake.Amount * AccRewardPerShare (exact rational)
	// R58-N7 fix: removed 1e12 scaling — big.Rat preserves fractional precision
	farm.Stakes[user].RewardDebt = new(big.Rat).SetInt(farm.Stakes[user].Amount)
	farm.Stakes[user].RewardDebt.Mul(farm.Stakes[user].RewardDebt, farm.AccRewardPerShare)

	// R14-LOW: audit log for stake operation. Matches the pattern used by
	// LendingManager.Supply (lendingSupply: ...). Critical for post-incident
	// forensics since Stake moves LP tokens out of the user's balance into
	// the farm — a missing log made it impossible to reconstruct who staked
	// what when investigating ECON-R14-CRIT-001 (free-stake exploit).
	log.Printf("yieldStake: farm=%s user=%x lpToken=%s amount=%s newStake=%s newTotalStaked=%s",
		farmID, user[:min(8, len(user))], farm.LPToken, amount.String(),
		farm.Stakes[user].Amount.String(), farm.TotalStaked.String())

	return nil
}

// Unstake removes LP tokens from a farm
func (yfm *YieldFarmingManager) Unstake(farmID string, user types.Address, amount *big.Int) (*big.Int, error) {
	yfm.mu.Lock()
	defer yfm.mu.Unlock()

	// ECON- per-user reentrancy protection.
	if yfm.activeUsers[user] {
		return nil, errors.New("reentrant call: user already has an in-progress farming operation")
	}
	yfm.activeUsers[user] = true
	defer delete(yfm.activeUsers, user)

	farm, exists := yfm.farms[farmID]
	if !exists {
		return nil, errors.New("farm not found")
	}

	// audit-fix NEW-12: reject non-positive amounts to prevent stake inflation
	// via big.Int.Sub with negative values
	if amount.Sign() <= 0 {
		return nil, errors.New("amount must be positive")
	}

	stake := farm.Stakes[user]
	if stake == nil || stake.Amount.Cmp(amount) < 0 {
		return nil, errors.New("insufficient stake")
	}

	// Update farm rewards
	yfm.updateFarm(farm)

	// Calculate pending rewards
	pending := yfm.calculatePendingReward(farm, stake)
	totalRewards := new(big.Int).Add(pending, stake.PendingRewards)
	stake.PendingRewards.SetInt64(0)

	// Update stake
	stake.Amount.Sub(stake.Amount, amount)
	farm.TotalStaked.Sub(farm.TotalStaked, amount)

	// Update reward debt: rewardDebt = stake.Amount * AccRewardPerShare (exact rational)
	// R58-N7 fix: removed 1e12 scaling — big.Rat preserves fractional precision
	stake.RewardDebt = new(big.Rat).SetInt(stake.Amount)
	stake.RewardDebt.Mul(stake.RewardDebt, farm.AccRewardPerShare)

	// ECON-R14-CRIT-002 (2026-07-21) FIX: actually move funds.
	//   (1) Return the unstaked LP tokens to the user's balance sheet.
	//   (2) Credit the harvested reward tokens to the user's balance sheet,
	//       debiting from farm.ReservedRewards (R37-P1-ECON-01: accrued
	//       rewards are moved there by updateFarm; the clamp below is
	//       defensive — accrued rewards are always fully backed).
	yfm.addUserBalanceLocked(user, farm.LPToken, amount)
	if totalRewards.Sign() > 0 {
		if farm.ReservedRewards == nil {
			farm.ReservedRewards = big.NewInt(0)
		}
		credit := totalRewards
		if farm.ReservedRewards.Cmp(credit) < 0 {
			// Defensive: should be unreachable since accrued rewards are
			// reserved 1:1 at accrual time. Credit what we can rather than
			// minting unbacked tokens.
			credit = new(big.Int).Set(farm.ReservedRewards)
		}
		if credit.Sign() > 0 {
			yfm.addUserBalanceLocked(user, farm.RewardToken, credit)
			farm.ReservedRewards.Sub(farm.ReservedRewards, credit)
		}
	}

	// R14-LOW: audit log for unstake operation. Matches the pattern used by
	// LendingManager.Withdraw. Critical for post-incident forensics since
	// Unstake returns LP tokens + rewards to the user — without a log it was
	// impossible to trace fund flows during ECON-R14-CRIT-002 investigation
	// (Unstake that didn't actually transfer funds).
	reservedForLog := farm.ReservedRewards
	if reservedForLog == nil {
		reservedForLog = big.NewInt(0)
	}
	log.Printf("yieldUnstake: farm=%s user=%x lpToken=%s amount=%s rewards=%s newStake=%s newTotalStaked=%s rewardPool=%s reservedRewards=%s",
		farmID, user[:min(8, len(user))], farm.LPToken, amount.String(),
		totalRewards.String(), stake.Amount.String(), farm.TotalStaked.String(), farm.RewardPool.String(), reservedForLog.String())

	return totalRewards, nil
}

// Harvest claims pending rewards without unstaking
func (yfm *YieldFarmingManager) Harvest(farmID string, user types.Address) (*big.Int, error) {
	yfm.mu.Lock()
	defer yfm.mu.Unlock()

	// ECON- per-user reentrancy protection.
	if yfm.activeUsers[user] {
		return nil, errors.New("reentrant call: user already has an in-progress farming operation")
	}
	yfm.activeUsers[user] = true
	defer delete(yfm.activeUsers, user)

	farm, exists := yfm.farms[farmID]
	if !exists {
		return nil, errors.New("farm not found")
	}

	stake := farm.Stakes[user]
	if stake == nil || stake.Amount.Sign() == 0 {
		return nil, errors.New("no stake found")
	}

	// Update farm rewards
	yfm.updateFarm(farm)

	// Calculate pending rewards
	pending := yfm.calculatePendingReward(farm, stake)
	totalRewards := new(big.Int).Add(pending, stake.PendingRewards)
	stake.PendingRewards.SetInt64(0)

	// Update reward debt: rewardDebt = stake.Amount * AccRewardPerShare (exact rational)
	// R58-N7 fix: removed 1e12 scaling — big.Rat preserves fractional precision
	stake.RewardDebt = new(big.Rat).SetInt(stake.Amount)
	stake.RewardDebt.Mul(stake.RewardDebt, farm.AccRewardPerShare)

	// ECON-R14-CRIT-002 (2026-07-21) FIX: actually credit reward tokens to
	// the user's balance sheet, debiting from farm.ReservedRewards
	// (R37-P1-ECON-01: updateFarm moves accrued rewards there; previously
	// this deducted RewardPool a second time — double deduction).
	if totalRewards.Sign() > 0 {
		if farm.ReservedRewards == nil {
			farm.ReservedRewards = big.NewInt(0)
		}
		credit := totalRewards
		if farm.ReservedRewards.Cmp(credit) < 0 {
			// Defensive: should be unreachable since accrued rewards are
			// reserved 1:1 at accrual time.
			credit = new(big.Int).Set(farm.ReservedRewards)
		}
		if credit.Sign() > 0 {
			yfm.addUserBalanceLocked(user, farm.RewardToken, credit)
			farm.ReservedRewards.Sub(farm.ReservedRewards, credit)
		}
	}

	return totalRewards, nil
}

// GetPendingReward returns pending rewards for a user
func (yfm *YieldFarmingManager) GetPendingReward(farmID string, user types.Address) (*big.Int, error) {
	yfm.mu.RLock()
	defer yfm.mu.RUnlock()

	farm, exists := yfm.farms[farmID]
	if !exists {
		return nil, errors.New("farm not found")
	}

	stake := farm.Stakes[user]
	if stake == nil {
		return big.NewInt(0), nil
	}

	// Calculate accumulated reward per share up to current block
	// R58-N7 fix: use big.Rat for exact fractional precision — no 1e12 scaling needed
	accRewardPerShare := new(big.Rat).Set(farm.AccRewardPerShare)
	if yfm.currentBlock > farm.LastRewardBlock && farm.TotalStaked.Sign() > 0 {
		blocks := yfm.currentBlock - farm.LastRewardBlock
		// audit-fix M-8: use SetUint64 to prevent int64 truncation of large block counts
		reward := new(big.Int).Mul(farm.RewardPerBlock, new(big.Int).SetUint64(blocks))
		reward.Mul(reward, new(big.Int).SetUint64(farm.Multiplier))
		reward.Div(reward, big.NewInt(100))

		// rewardPerShare = reward / TotalStaked as exact rational (no integer truncation)
		rewardPerShare := new(big.Rat).SetInt(reward)
		rewardPerShare.Quo(rewardPerShare, new(big.Rat).SetInt(farm.TotalStaked))
		accRewardPerShare.Add(accRewardPerShare, rewardPerShare)
	}

	// pending = stake.Amount * accRewardPerShare - stake.RewardDebt (exact rational)
	pending := new(big.Rat).SetInt(stake.Amount)
	pending.Mul(pending, accRewardPerShare)
	pending.Sub(pending, stake.RewardDebt)
	if pending.Sign() < 0 {
		return new(big.Int).Set(stake.PendingRewards), nil
	}
	// Convert rational to integer (floor truncation; unavoidable for token counts)
	num := pending.Num()
	den := pending.Denom()
	if num.Cmp(den) < 0 {
		return new(big.Int).Set(stake.PendingRewards), nil
	}
	currentPending := new(big.Int).Div(num, den)
	return new(big.Int).Add(currentPending, stake.PendingRewards), nil
}

// GetUserStake returns user's stake in a farm
func (yfm *YieldFarmingManager) GetUserStake(farmID string, user types.Address) (*big.Int, error) {
	yfm.mu.RLock()
	defer yfm.mu.RUnlock()

	farm, exists := yfm.farms[farmID]
	if !exists {
		return nil, errors.New("farm not found")
	}

	stake := farm.Stakes[user]
	if stake == nil {
		return big.NewInt(0), nil
	}

	return new(big.Int).Set(stake.Amount), nil
}

// updateFarm updates the accumulated rewards for a farm.
//
// ECON-R13-M03 (2026-07-21) FIX: Previously updateFarm had no terminal-state
// checks. Three serious problems resulted:
//
//  1. Reward accrual continued past farm.EndBlock. The farm was supposed
//     to stop emitting rewards after its scheduled end block (~1 year),
//     but updateFarm happily computed rewards for blocks beyond EndBlock,
//     causing infinite minting of reward tokens indefinitely.
//
//  2. Reward accrual continued while farm.Status was PAUSED or ENDED.
//     A paused farm should stop emitting rewards until it is resumed,
//     but updateFarm ignored the Status field entirely. This let
//     governance actions (pause a farm after a vulnerability is found)
//     fail to actually halt reward accrual.
//
//  3. Combined with the lack of a reward-token treasury debit (rewards
//     are accounted but never debited from a finite pool), an attacker
//     who staked once and never unstaked would receive infinite rewards
//     forever — even after the farm was supposed to have ended.
//
// Fix: updateFarm now performs three guard checks before accruing:
//   - Status must be "ACTIVE" (matches the field docstring's contract)
//   - yfm.currentBlock must not exceed farm.EndBlock (terminal cutoff)
//   - yfm.currentBlock must be > farm.LastRewardBlock (no-op idempotence)
//
// When the farm has ended (currentBlock > EndBlock or Status != ACTIVE),
// we still advance LastRewardBlock to currentBlock so a subsequent
// status change (resume) does not retroactively credit rewards for the
// paused period. This mirrors the TotalStaked==0 branch's behavior.
func (yfm *YieldFarmingManager) updateFarm(farm *YieldFarm) {
	if yfm.currentBlock <= farm.LastRewardBlock {
		return
	}

	// ECON-R13-M03: respect farm lifecycle state. A paused/ended farm
	// stops accruing rewards. We still advance LastRewardBlock so the
	// skipped blocks are not retroactively credited if the farm is later
	// resumed (the resume should be a clean slate from this point).
	if farm.Status != "ACTIVE" {
		farm.LastRewardBlock = yfm.currentBlock
		return
	}

	// ECON-R13-M03: clamp the accrual cutoff at EndBlock. If currentBlock
	// is past EndBlock, we only credit rewards up to EndBlock (the
	// terminal cutoff), then advance LastRewardBlock to currentBlock so
	// future updateFarm calls are no-ops until the farm's EndBlock is
	// explicitly extended by governance.
	effectiveBlock := yfm.currentBlock
	if farm.EndBlock > 0 && yfm.currentBlock > farm.EndBlock {
		// If LastRewardBlock is already past EndBlock, there is nothing
		// more to accrue — just advance the cursor.
		if farm.LastRewardBlock >= farm.EndBlock {
			farm.LastRewardBlock = yfm.currentBlock
			return
		}
		effectiveBlock = farm.EndBlock
	}

	if farm.TotalStaked.Sign() == 0 {
		farm.LastRewardBlock = yfm.currentBlock
		return
	}

	blocks := effectiveBlock - farm.LastRewardBlock
	if blocks == 0 {
		// Defensive: effectiveBlock == LastRewardBlock after clamping.
		farm.LastRewardBlock = yfm.currentBlock
		return
	}
	// audit-fix M-8: use SetUint64 to prevent int64 truncation of large block counts
	reward := new(big.Int).Mul(farm.RewardPerBlock, new(big.Int).SetUint64(blocks))
	reward.Mul(reward, new(big.Int).SetUint64(farm.Multiplier))
	reward.Div(reward, big.NewInt(100))

	// ECON-R14-CRIT-003 (2026-07-21) FIX: do not accrue rewards the farm
	// cannot actually pay. Previously `reward` was added to
	// AccRewardPerShare unconditionally, minting reward tokens out of thin
	// air — infinite inflation. Now clamp the accrued reward to whatever
	// the RewardPool can cover. If the pool is empty/exhausted, no accrual
	// happens this call (LastRewardBlock still advances so we don't
	// retroactively credit when the pool is later topped up).
	if farm.RewardPool == nil {
		farm.RewardPool = big.NewInt(0)
	}
	effectiveReward := reward
	if farm.RewardPool.Cmp(effectiveReward) < 0 {
		if farm.RewardPool.Sign() <= 0 {
			// Pool exhausted — no rewards to accrue this round.
			farm.LastRewardBlock = yfm.currentBlock
			return
		}
		effectiveReward = new(big.Int).Set(farm.RewardPool)
	}
	// R37-P1-ECON-01 FIX (2026-07-30): move the accrued amount from the
	// funding account (RewardPool) into the liability account
	// (ReservedRewards). Payouts (Harvest/Unstake) draw from
	// ReservedRewards — previously they deducted RewardPool a SECOND time,
	// draining it at 2x speed and silently killing accrual once empty.
	farm.RewardPool.Sub(farm.RewardPool, effectiveReward)
	if farm.ReservedRewards == nil {
		farm.ReservedRewards = big.NewInt(0)
	}
	farm.ReservedRewards.Add(farm.ReservedRewards, effectiveReward)

	// R58-N7 fix: rewardPerShare = reward / TotalStaked as exact rational
	// The old big.Int approach with 1e12 scaling truncated to zero when TotalStaked
	// was large (e.g., millions of LP tokens), causing AccRewardPerShare to stagnate
	// and denying small stakers their proportional share of newly minted rewards.
	rewardPerShare := new(big.Rat).SetInt(effectiveReward)
	rewardPerShare.Quo(rewardPerShare, new(big.Rat).SetInt(farm.TotalStaked))

	farm.AccRewardPerShare.Add(farm.AccRewardPerShare, rewardPerShare)
	// Advance LastRewardBlock to currentBlock (not effectiveBlock) so the
	// post-EndBlock gap is not re-credited on the next call.
	farm.LastRewardBlock = yfm.currentBlock
}

// calculatePendingReward calculates pending reward for a stake.
// R58-N7 [LOW] FIX: Use big.Rat for pending reward arithmetic (no 1e12 scaling).
// The old big.Int approach with 1e12 scaling caused truncation when TotalStaked
// was large — rewardPerShare = reward * 1e12 / TotalStaked could truncate to 0,
// stalling AccRewardPerShare and denying small stakers their fair rewards.
// big.Rat preserves exact fractional shares throughout.
func (yfm *YieldFarmingManager) calculatePendingReward(farm *YieldFarm, stake *FarmStake) *big.Int {
	// pending = stake.Amount * AccRewardPerShare - stake.RewardDebt (exact rational)
	pending := new(big.Rat).SetInt(stake.Amount)
	pending.Mul(pending, farm.AccRewardPerShare)
	pending.Sub(pending, stake.RewardDebt)
	// Floor at zero to prevent negative rewards from rounding drift (R10-L3)
	if pending.Sign() < 0 {
		return big.NewInt(0)
	}
	// Convert exact rational to integer (floor — truncates fractional QAU, unavoidable)
	num := pending.Num()
	den := pending.Denom()
	if num.Cmp(den) < 0 {
		return big.NewInt(0)
	}
	return new(big.Int).Div(num, den)
}

// CalculateAPY calculates the APY for a farm
// R58-N1 [MEDIUM] FIX: Use big.Float with 1024-bit precision for intermediate
// calculations instead of the default 53-bit precision. Default float64 precision
// causes rounding errors for large TotalStaked or RewardPerBlock values, which
// can make APY calculations significantly off (e.g., 1.00% instead of 1.01%).
func (yfm *YieldFarmingManager) CalculateAPY(farmID string, lpTokenPrice, rewardTokenPrice float64) (float64, error) {
	yfm.mu.RLock()
	defer yfm.mu.RUnlock()

	farm, exists := yfm.farms[farmID]
	if !exists {
		return 0, errors.New("farm not found")
	}

	if farm.TotalStaked.Sign() == 0 {
		return 0, nil
	}

	// Use 1024-bit precision to avoid rounding errors for large token amounts.
	// Default float64 precision (53 bits ≈ 16 decimal digits) can lose significant
	// figures when TotalStaked or RewardPerBlock are on the order of billions.
	prec := 1024

	// Annual rewards in tokens: rewardPerBlock * blocksPerYear * multiplier / 100
	blocksPerYearF := new(big.Float).SetPrec(uint(prec)).SetInt( //nolint:gosec,G115
		new(big.Int).SetUint64(365 * 24 * 60 * 60 / 12))

	annualRewardsTokensF := new(big.Float).SetPrec(uint(prec)). //nolint:gosec,G115
									SetInt(farm.RewardPerBlock)
	annualRewardsTokensF.Mul(annualRewardsTokensF, blocksPerYearF)
	annualRewardsTokensF.Mul(annualRewardsTokensF,
		new(big.Float).SetPrec(uint(prec)). //nolint:gosec,G115
							SetInt(new(big.Int).SetUint64(farm.Multiplier)))
	annualRewardsTokensF.Quo(annualRewardsTokensF,
		new(big.Float).SetPrec(uint(prec)).SetInt(big.NewInt(100))) //nolint:gosec,G115

	// Annual rewards in USD: tokens * rewardTokenPrice / 1e18
	rewardTokenPriceF := new(big.Float).SetPrec(uint(prec)).SetFloat64(rewardTokenPrice) //nolint:gosec,G115
	oneE18F := new(big.Float).SetPrec(uint(prec)).SetInt(big.NewInt(1e18))               //nolint:gosec,G115
	annualRewardsUSDF := new(big.Float).Mul(annualRewardsTokensF, rewardTokenPriceF)
	annualRewardsUSDF.Quo(annualRewardsUSDF, oneE18F)

	// Total staked in USD: totalStaked * lpTokenPrice / 1e18
	totalStakedF := new(big.Float).SetPrec(uint(prec)).SetInt(farm.TotalStaked)  //nolint:gosec,G115
	lpTokenPriceF := new(big.Float).SetPrec(uint(prec)).SetFloat64(lpTokenPrice) //nolint:gosec,G115
	totalStakedUSDF := new(big.Float).Mul(totalStakedF, lpTokenPriceF)
	totalStakedUSDF.Quo(totalStakedUSDF, oneE18F)

	totalStakedUSD, _ := totalStakedUSDF.Float64()
	if totalStakedUSD == 0 {
		return 0, nil
	}

	// APY = (Annual Rewards / Total Staked) * 100
	annualRewardsUSD, _ := annualRewardsUSDF.Float64()
	apy := (annualRewardsUSD / totalStakedUSD) * 100

	return apy, nil
}
