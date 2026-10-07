// Quantaureum Node source, version 1.0.0.
package economics

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
)

// FIX: ErrInvalidFeeDistribution is returned when the fee distribution
// configuration is invalid (e.g., shares don't sum to 10000). Previously
// UpdateConfig returned ErrInvalidLockPeriod, which is a staking-related
// error and semantically incorrect for fee distribution validation.
var ErrInvalidFeeDistribution = errors.New("invalid fee distribution configuration")

// R47-CS-01: Distinguishable sentinel errors for Distribute() skip paths.
var (
	ErrDistributionSkippedReorg        = errors.New("distribution skipped: block height <= last distribution (reorg)")
	ErrDistributionIntervalNotElapsed  = errors.New("distribution skipped: interval not elapsed")
	ErrDistributionNothingToDistribute = errors.New("distribution skipped: all pools are zero")
)

type FeeDistributionConfig struct {
	ValidatorShare       uint32
	BurnShare            uint32
	TreasuryShare        uint32
	DeveloperShare       uint32
	InsuranceShare       uint32
	DistributionInterval uint64
}

func DefaultFeeDistributionConfig() *FeeDistributionConfig {
	return &FeeDistributionConfig{
		ValidatorShare:       6000,
		BurnShare:            1500,
		TreasuryShare:        1000,
		DeveloperShare:       1000,
		InsuranceShare:       500,
		DistributionInterval: 100,
	}
}

type FeePool struct {
	ValidatorPool    *big.Int
	BurnPool         *big.Int
	TreasuryPool     *big.Int
	DeveloperPool    *big.Int
	InsurancePool    *big.Int
	TotalCollected   *big.Int
	TotalDistributed *big.Int
	TotalBurned      *big.Int
	LastDistribution uint64
}

type FeeDistributor struct {
	mu                  sync.RWMutex
	config              *FeeDistributionConfig
	pool                *FeePool
	stakingManager      *StakingManager
	treasuryAddress     types.Address
	developerAddress    types.Address
	insuranceAddress    types.Address
	distributionHistory []DistributionRecord
	//  tracks the total number of distribution records that have been
	// silently dropped due to history truncation (max 1000 entries).
	truncatedRecordsCount uint64
}

type DistributionRecord struct {
	BlockHeight     uint64
	Timestamp       int64
	ValidatorAmount *big.Int
	BurnAmount      *big.Int
	TreasuryAmount  *big.Int
	DeveloperAmount *big.Int
	InsuranceAmount *big.Int
}

func NewFeeDistributor(
	config *FeeDistributionConfig,
	stakingManager *StakingManager,
	treasury types.Address,
	developer types.Address,
	insurance types.Address,
) *FeeDistributor {
	if config == nil {
		config = DefaultFeeDistributionConfig()
	}

	// FIX: Validate that share percentages sum to exactly 10000 (100%).
	// Without this, fees could be silently lost or over-distributed.
	// R38-P4 FIX: Also validate each share is within [0, 10000] to prevent
	// uint32 overflow in the sum (5 * 0xFFFFFFFF could wrap to 10000).
	const maxShare = uint32(10000)
	if config.ValidatorShare > maxShare || config.BurnShare > maxShare ||
		config.TreasuryShare > maxShare || config.DeveloperShare > maxShare ||
		config.InsuranceShare > maxShare {
		logging.Error("FeeDistributor: individual share exceeds maximum", map[string]any{
			"maxShare":       maxShare,
			"validatorShare": config.ValidatorShare,
			"burnShare":      config.BurnShare,
			"treasuryShare":  config.TreasuryShare,
		})
		return nil
	}
	totalShares := config.ValidatorShare + config.BurnShare + config.TreasuryShare +
		config.DeveloperShare + config.InsuranceShare
	if totalShares != 10000 {
		logging.Error("FeeDistributor: share percentages do not sum to 10000",
			map[string]any{
				"validatorShare": config.ValidatorShare,
				"burnShare":      config.BurnShare,
				"treasuryShare":  config.TreasuryShare,
				"developerShare": config.DeveloperShare,
				"insuranceShare": config.InsuranceShare,
				"totalShares":    totalShares,
				"expected":       10000,
			})
		// Fall back to default config to prevent silent fee loss
		config = DefaultFeeDistributionConfig()
	}

	// FIX: Validate DistributionInterval in the constructor, not just
	// in UpdateConfig. A value of 0 would cause distribution every block,
	// wasting gas and creating unnecessary state writes.
	if config.DistributionInterval == 0 {
		logging.Error("FeeDistributor: DistributionInterval is 0, falling back to default",
			map[string]any{"module": "economics/fee_distribution"})
		config = DefaultFeeDistributionConfig()
	}

	return &FeeDistributor{
		config:           config,
		stakingManager:   stakingManager,
		treasuryAddress:  treasury,
		developerAddress: developer,
		insuranceAddress: insurance,
		pool: &FeePool{
			ValidatorPool:    new(big.Int),
			BurnPool:         new(big.Int),
			TreasuryPool:     new(big.Int),
			DeveloperPool:    new(big.Int),
			InsurancePool:    new(big.Int),
			TotalCollected:   new(big.Int),
			TotalDistributed: new(big.Int),
			TotalBurned:      new(big.Int),
		},
	}
}

// SECURITY FIX (audit P3-02): Added nil and non-positive check to prevent panic
// when amount is nil and to skip meaningless zero/negative fee collection.
//
// P3-E4 AUDIT NOTE (integer overflow): Go's math/big.Int is ARBITRARY
// PRECISION, so true integer overflow is structurally impossible for the Mul
// and Add operations below — the values simply grow to accommodate the result.
// The realistic concern is therefore not overflow but SHARE-PERCENT
// MISCONFIGURATION: if the five share percentages (ValidatorShare+BurnShare+
// TreasuryShare+DeveloperShare+InsuranceShare) summed to > 10000, the
// allocated shares would exceed `amount`. The defensive check below rejects
// that case so pools can never be credited more than was collected.
func (fd *FeeDistributor) CollectFee(amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}

	fd.mu.Lock()
	defer fd.mu.Unlock()

	validatorShare := new(big.Int).Mul(amount, big.NewInt(int64(fd.config.ValidatorShare)))
	validatorShare.Div(validatorShare, big.NewInt(10000))

	burnShare := new(big.Int).Mul(amount, big.NewInt(int64(fd.config.BurnShare)))
	burnShare.Div(burnShare, big.NewInt(10000))

	treasuryShare := new(big.Int).Mul(amount, big.NewInt(int64(fd.config.TreasuryShare)))
	treasuryShare.Div(treasuryShare, big.NewInt(10000))

	developerShare := new(big.Int).Mul(amount, big.NewInt(int64(fd.config.DeveloperShare)))
	developerShare.Div(developerShare, big.NewInt(10000))

	insuranceShare := new(big.Int).Mul(amount, big.NewInt(int64(fd.config.InsuranceShare)))
	insuranceShare.Div(insuranceShare, big.NewInt(10000))

	// P3-E4 FIX: Defense-in-depth — verify the sum of allocated shares does
	// not exceed the collected amount (would indicate misconfigured shares
	// summing to > 100%). big.Int cannot overflow, so this is a consistency
	// guard, not an arithmetic-overflow guard. On misconfiguration we skip
	// crediting this fee rather than corrupting the pools.
	allocated := new(big.Int).Add(validatorShare, burnShare)
	allocated.Add(allocated, treasuryShare)
	allocated.Add(allocated, developerShare)
	allocated.Add(allocated, insuranceShare)
	if allocated.Cmp(amount) > 0 {
		return
	}

	// R30-P3 FIX: Track dust from integer division and add to validator pool.
	// Integer division (Div) truncates, so the sum of shares may be less than
	// the original amount. Without this fix, the dust is silently lost.
	// Adding it to the validator pool ensures total distributed == total collected.
	dust := new(big.Int).Sub(amount, allocated)
	if dust.Sign() > 0 {
		validatorShare.Add(validatorShare, dust)
	}

	fd.pool.ValidatorPool.Add(fd.pool.ValidatorPool, validatorShare)
	fd.pool.BurnPool.Add(fd.pool.BurnPool, burnShare)
	fd.pool.TreasuryPool.Add(fd.pool.TreasuryPool, treasuryShare)
	fd.pool.DeveloperPool.Add(fd.pool.DeveloperPool, developerShare)
	fd.pool.InsurancePool.Add(fd.pool.InsurancePool, insuranceShare)
	fd.pool.TotalCollected.Add(fd.pool.TotalCollected, amount)
}

// Distribute distributes accumulated fees to their respective pools and returns
// a DistributionRecord describing the split. It is called periodically based on
// DistributionInterval.
//
// R31-P4-4 NOTE: This method performs ACCOUNTING ONLY — it moves amounts from
// the per-category pools (ValidatorPool, TreasuryPool, etc.) into the
// DistributionRecord and zeroes the pools. It does NOT execute actual on-chain
// state transitions (SetBalance transfers to treasury/developer/insurance
// addresses, or burning). The caller (EconomicsManager.ProcessBlock) is
// responsible for reading the returned DistributionRecord and executing the
// actual balance transfers via StateDB. This separation exists because
// FeeDistributor does not have direct access to StateDB.
func (fd *FeeDistributor) Distribute(blockHeight uint64) (*DistributionRecord, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	// SECURITY FIX (audit P3-03 + L-4): Prevent uint64 underflow when blockHeight <=
	// LastDistribution (e.g., during reorg or same-block call). Without this check,
	// the subtraction would wrap to a huge number, bypassing the interval check and
	// triggering an unexpected distribution.
	if blockHeight <= fd.pool.LastDistribution {
		fd.pool.LastDistribution = blockHeight
		// R47-CS-01 FIX: Return distinguishable sentinel errors instead of
		// nil,nil so callers can differentiate skip reasons.
		return nil, ErrDistributionSkippedReorg
	}
	blocksSinceLast := blockHeight - fd.pool.LastDistribution
	if blocksSinceLast < fd.config.DistributionInterval {
		return nil, ErrDistributionIntervalNotElapsed
	}

	// R46-CS-01 FIX: Return an error when there is nothing to distribute
	// (all pools are zero). Previously this returned a record with all-zero
	// amounts, making it impossible for callers to distinguish "no interval
	// yet" from "nothing to distribute".
	totalPooled := new(big.Int)
	totalPooled.Add(fd.pool.ValidatorPool, fd.pool.TreasuryPool)
	totalPooled.Add(totalPooled, fd.pool.DeveloperPool)
	totalPooled.Add(totalPooled, fd.pool.InsurancePool)
	totalPooled.Add(totalPooled, fd.pool.BurnPool)
	if totalPooled.Sign() == 0 {
		fd.pool.LastDistribution = blockHeight
		return nil, ErrDistributionNothingToDistribute
	}

	record := &DistributionRecord{
		BlockHeight: blockHeight,
		// R41-CS-003 FIX: Use blockHeight as timestamp instead of time.Now()
		// to ensure determinism across nodes. Different nodes processing the
		// same block must produce identical distribution records.
		Timestamp:       int64(blockHeight),
		ValidatorAmount: new(big.Int).Set(fd.pool.ValidatorPool),
		BurnAmount:      new(big.Int).Set(fd.pool.BurnPool),
		TreasuryAmount:  new(big.Int).Set(fd.pool.TreasuryPool),
		DeveloperAmount: new(big.Int).Set(fd.pool.DeveloperPool),
		InsuranceAmount: new(big.Int).Set(fd.pool.InsurancePool),
	}

	// R32-P5-3 FIX: Include BurnPool in TotalDistributed so that
	// TotalDistributed == TotalCollected after all pools are distributed.
	// Burn is a distribution destination (to null address), not a loss.
	// R46-CS-01: totalPooled was already computed above for the zero check;
	// reuse it directly (pools haven't been zeroed yet).
	fd.pool.TotalDistributed.Add(fd.pool.TotalDistributed, totalPooled)

	fd.pool.TotalBurned.Add(fd.pool.TotalBurned, fd.pool.BurnPool)

	fd.pool.ValidatorPool.SetInt64(0)
	fd.pool.BurnPool.SetInt64(0)
	fd.pool.TreasuryPool.SetInt64(0)
	fd.pool.DeveloperPool.SetInt64(0)
	fd.pool.InsurancePool.SetInt64(0)

	fd.pool.LastDistribution = blockHeight
	fd.distributionHistory = append(fd.distributionHistory, *record)

	if len(fd.distributionHistory) > 1000 {
		truncated := len(fd.distributionHistory) - 1000
		fd.truncatedRecordsCount += uint64(truncated) //nolint:gosec
		// FIX: Warn when distribution history is truncated so records
		// are not silently lost. The counter tracks cumulative truncation.
		logging.Warn("FeeDistributor: distribution history truncated, oldest records lost",
			map[string]any{
				"truncatedNow":   truncated,
				"totalTruncated": fd.truncatedRecordsCount,
				"maxHistoryLen":  1000,
			})
		fd.distributionHistory = fd.distributionHistory[len(fd.distributionHistory)-1000:]
	}

	return record, nil
}

func (fd *FeeDistributor) GetPool() *FeePool {
	fd.mu.RLock()
	defer fd.mu.RUnlock()

	return &FeePool{
		ValidatorPool:    new(big.Int).Set(fd.pool.ValidatorPool),
		BurnPool:         new(big.Int).Set(fd.pool.BurnPool),
		TreasuryPool:     new(big.Int).Set(fd.pool.TreasuryPool),
		DeveloperPool:    new(big.Int).Set(fd.pool.DeveloperPool),
		InsurancePool:    new(big.Int).Set(fd.pool.InsurancePool),
		TotalCollected:   new(big.Int).Set(fd.pool.TotalCollected),
		TotalDistributed: new(big.Int).Set(fd.pool.TotalDistributed),
		TotalBurned:      new(big.Int).Set(fd.pool.TotalBurned),
	}
}

func (fd *FeeDistributor) GetDistributionHistory(limit int) []DistributionRecord {
	fd.mu.RLock()
	defer fd.mu.RUnlock()

	history := fd.distributionHistory
	if limit > 0 && limit < len(history) {
		history = history[len(history)-limit:]
	}

	result := make([]DistributionRecord, len(history))
	copy(result, history)
	return result
}

func (fd *FeeDistributor) GetBurnRate() *big.Int {
	fd.mu.RLock()
	defer fd.mu.RUnlock()

	if fd.pool.TotalCollected.Sign() <= 0 {
		return big.NewInt(0)
	}

	rate := new(big.Int).Mul(fd.pool.TotalBurned, big.NewInt(10000))
	rate.Div(rate, fd.pool.TotalCollected)
	return rate
}

// GetConfig returns a copy of the fee distribution configuration.
func (fd *FeeDistributor) GetConfig() *FeeDistributionConfig {
	fd.mu.RLock()
	defer fd.mu.RUnlock()
	return &FeeDistributionConfig{
		ValidatorShare:       fd.config.ValidatorShare,
		BurnShare:            fd.config.BurnShare,
		TreasuryShare:        fd.config.TreasuryShare,
		DeveloperShare:       fd.config.DeveloperShare,
		InsuranceShare:       fd.config.InsuranceShare,
		DistributionInterval: fd.config.DistributionInterval,
	}
}

func (fd *FeeDistributor) UpdateConfig(config *FeeDistributionConfig) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	// R38-P4 FIX: Validate each share range before summing.
	const maxShare = uint32(10000)
	if config.ValidatorShare > maxShare || config.BurnShare > maxShare ||
		config.TreasuryShare > maxShare || config.DeveloperShare > maxShare ||
		config.InsuranceShare > maxShare {
		return fmt.Errorf("%w: individual share exceeds maximum %d", ErrInvalidFeeDistribution, maxShare)
	}
	total := config.ValidatorShare + config.BurnShare + config.TreasuryShare +
		config.DeveloperShare + config.InsuranceShare

	if total != 10000 {
		return ErrInvalidFeeDistribution
	}

	// FIX: Validate DistributionInterval to prevent 0 value.
	// A value of 0 causes distribution to trigger every block (blocksSinceLast < 0
	// is always false for uint64), leading to excessive gas consumption and
	// state churn. Enforce a minimum of 1.
	if config.DistributionInterval == 0 {
		return errors.New("distribution interval must be > 0")
	}

	fd.config = config
	return nil
}

// ApplyDistributionToState calls Distribute() and, if a distribution is due,
// applies the resulting balance transfers to the provided StateModifier.
//
// FIX: Previously, ProcessBlock called Distribute() but discarded the
// returned DistributionRecord — fees were tracked in memory ("ghost accounting")
// but never credited to treasury/developer/insurance addresses on-chain.
// This method bridges the gap: it performs the actual SetBalance/AddBalance
// calls so that treasury, developer, and insurance addresses receive their
// allocated funds, the proposer receives the validator share, and the burn
// portion is destroyed (by not crediting it to anyone).
//
// This method is intended to be called during block PRODUCTION (in buildBlock),
// before the state root is computed, so that all nodes agree on the post-
// distribution state root. ProcessBlock (called in blockInsertLoop for all
// nodes) only calls CollectFee() for accounting — it no longer calls
// Distribute().
//
//	AUDIT NOTE: Call chain documentation — this function is called from:
//	 - node/block_producer.go:1717 (during block production, before state root)
//	 - NOT from economics.ProcessBlock (which only accumulates fees via CollectFee)
//
// This separation is intentional:
//  1. ProcessBlock accumulates fees in-memory (consensus-safe, can be non-fatal)
//  2. ApplyDistributionToState performs state mutation (must succeed before
//     state root computation to ensure all nodes agree on post-distribution state)
//
// The proposerAddr parameter receives the validator share directly, while
// treasury/developer/insurance shares go to their respective configured addresses.
func (fd *FeeDistributor) ApplyDistributionToState(
	state StateModifier,
	blockHeight uint64,
	proposerAddr types.Address,
) (*DistributionRecord, error) {
	record, err := fd.Distribute(blockHeight)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, nil
	}

	// Credit validator share to the block proposer.
	if record.ValidatorAmount != nil && record.ValidatorAmount.Sign() > 0 {
		if err := state.AddBalance(proposerAddr, record.ValidatorAmount); err != nil {
			logging.Error("FeeDistributor: failed to credit validator share",
				map[string]any{
					"proposer": proposerAddr.String(),
					"amount":   record.ValidatorAmount.String(),
					"block":    blockHeight,
					"error":    err.Error(),
				})
			return record, err
		}
	}

	// Credit treasury share.
	if record.TreasuryAmount != nil && record.TreasuryAmount.Sign() > 0 {
		if err := state.AddBalance(fd.treasuryAddress, record.TreasuryAmount); err != nil {
			logging.Error("FeeDistributor: failed to credit treasury share",
				map[string]any{
					"treasury": fd.treasuryAddress.String(),
					"amount":   record.TreasuryAmount.String(),
					"block":    blockHeight,
					"error":    err.Error(),
				})
			return record, err
		}
	}

	// Credit developer share.
	if record.DeveloperAmount != nil && record.DeveloperAmount.Sign() > 0 {
		if err := state.AddBalance(fd.developerAddress, record.DeveloperAmount); err != nil {
			logging.Error("FeeDistributor: failed to credit developer share",
				map[string]any{
					"developer": fd.developerAddress.String(),
					"amount":    record.DeveloperAmount.String(),
					"block":     blockHeight,
					"error":     err.Error(),
				})
			return record, err
		}
	}

	// Credit insurance share.
	if record.InsuranceAmount != nil && record.InsuranceAmount.Sign() > 0 {
		if err := state.AddBalance(fd.insuranceAddress, record.InsuranceAmount); err != nil {
			logging.Error("FeeDistributor: failed to credit insurance share",
				map[string]any{
					"insurance": fd.insuranceAddress.String(),
					"amount":    record.InsuranceAmount.String(),
					"block":     blockHeight,
					"error":     err.Error(),
				})
			return record, err
		}
	}

	// Burn portion: fees were already deducted from senders during tx
	// execution. By not crediting the burn amount to any address, the
	// total supply is effectively reduced — this is the burn mechanism.

	logging.Info("FeeDistributor: distribution applied on-chain",
		map[string]any{
			"block":           blockHeight,
			"validatorAmount": record.ValidatorAmount.String(),
			"burnAmount":      record.BurnAmount.String(),
			"treasuryAmount":  record.TreasuryAmount.String(),
			"developerAmount": record.DeveloperAmount.String(),
			"insuranceAmount": record.InsuranceAmount.String(),
			"proposer":        proposerAddr.String(),
		})

	return record, nil
}
