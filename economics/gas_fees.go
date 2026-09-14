// Quantaureum Node source, version 1.0.0.
// Package economics implements the economic model for the Quantaureum blockchain.
// This file implements gas fee collection and distribution.
package economics

import (
	"errors"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/types"
)

// Gas fee related errors
var (
	ErrInvalidGasPrice     = errors.New("invalid gas price")
	ErrInvalidGasUsed      = errors.New("invalid gas used")
	ErrInvalidFeeRecipient = errors.New("invalid fee recipient")
	ErrNoFeesToDistribute  = errors.New("no fees to distribute")
	// R40-M11 FIX: Error returned when fee rate basis points exceed 100%.
	ErrFeeRatesExceedTotal = errors.New("sum of BurnRate + ProposerRate + ValidatorPoolRate exceeds 10000 basis points")
)

// L12-030 [P3]: DistributeFees rejects a zero proposer address; crediting proposerFees
// to the zero address would lock funds in a non-existent account.
var ErrZeroProposerAddress = errors.New("proposer address is the zero address")

// GasFeeConfig defines the gas fee distribution configuration
type GasFeeConfig struct {
	// BaseFee is the minimum gas price (in wei)
	BaseFee *big.Int

	// BurnRate is the percentage of fees to burn (basis points, e.g., 5000 = 50%)
	BurnRate uint32

	// ProposerRate is the percentage of remaining fees going to proposer (basis points)
	ProposerRate uint32

	// ValidatorPoolRate is the percentage going to validator pool (basis points)
	// The remainder after burn and proposer goes to validators
	ValidatorPoolRate uint32
}

// maxBasisPoints is the maximum total fee allocation (100% = 10000 basis points).
// R40-M11 FIX: Used to validate that BurnRate + ProposerRate + ValidatorPoolRate
// never exceeds 100%, which would cause accounting errors (more fees distributed
// than collected).
const maxBasisPoints = 10000

// validateFeeRates checks that the sum of fee rates does not exceed 10000 basis points (100%).
// R40-M11 FIX: Prevents accounting errors where more fees are distributed than collected.
func validateFeeRates(config *GasFeeConfig) error {
	total := uint64(config.BurnRate) + uint64(config.ProposerRate) + uint64(config.ValidatorPoolRate)
	if total > maxBasisPoints {
		return ErrFeeRatesExceedTotal
	}
	return nil
}

// DefaultGasFeeConfig returns the default gas fee configuration
// BurnRate is dynamic based on block height (see CalculateBurnRate).
// The static value here is the Year 1 rate (10%).
func DefaultGasFeeConfig() *GasFeeConfig {
	return &GasFeeConfig{
		BaseFee:           big.NewInt(1e9),
		BurnRate:          1000, // Year 1: 10% (dynamic via CalculateBurnRate)
		ProposerRate:      3000,
		ValidatorPoolRate: 2000,
	}
}

// BlocksPerYearGas is the estimated number of blocks per year for gas burn rate
// schedule (12-second blocks: 365 * 24 * 3600 / 12 = 2,628,000).
const BlocksPerYearGas = 2628000

// CalculateBurnRate returns the burn rate (basis points) for the given block height.
// Follows a 3-year step-up schedule:
//
//	Year 1 (0 – 2,628,000):          10% (1000 bps)
//	Year 2 (2,628,000 – 5,256,000):  20% (2000 bps)
//	Year 3 (5,256,000 – 7,884,000):  35% (3500 bps)
//	Year 4+ (7,884,000+):            50% (5000 bps) — final rate
//
// This mirrors Ethereum's fixed 100% base fee burn but with a gradual ramp to
// avoid penalizing early adopters when transaction volume is still low.
func CalculateBurnRate(blockHeight uint64) uint32 {
	switch {
	case blockHeight < BlocksPerYearGas:
		return 1000 // 10%
	case blockHeight < 2*BlocksPerYearGas:
		return 2000 // 20%
	case blockHeight < 3*BlocksPerYearGas:
		return 3500 // 35%
	default:
		return 5000 // 50% (final)
	}
}

// GasFeeCollector collects and distributes gas fees
type GasFeeCollector struct {
	config *GasFeeConfig
	mu     sync.RWMutex

	// Accumulated fees for the current block
	accumulatedFees *big.Int
	// Total burned fees
	totalBurned *big.Int

	// AUDIT (2026) ECON-05 FIX: Actual EIP-1559 base-fee burn accumulated
	// for the current block. The executor burns gasUsed*baseFee on-chain (100%
	// of the base fee). Previously, DistributeFees computed burnedFees as
	// totalFees * burnRate% (10%-50%), which undercounted the real burn and
	// caused em.totalSupply to drift upward. Now CollectEIP1559Fee accumulates
	// the true burn here, and DistributeFees uses it when available.
	accumulatedBurn *big.Int
}

// NewGasFeeCollector creates a new gas fee collector
// R40-M11 FIX: Validates that fee rates do not exceed 10000 basis points.
func NewGasFeeCollector(config *GasFeeConfig) (*GasFeeCollector, error) {
	if config == nil {
		config = DefaultGasFeeConfig()
	}
	// R40-M11 FIX: Reject configurations where fee rates exceed 100%.
	if err := validateFeeRates(config); err != nil {
		return nil, err
	}
	return &GasFeeCollector{
		config:          config,
		accumulatedFees: big.NewInt(0),
		totalBurned:     big.NewInt(0),
		accumulatedBurn: big.NewInt(0), // AUDIT (2026) ECON-05
	}, nil
}

// CollectFee collects gas fee from a transaction
func (gfc *GasFeeCollector) CollectFee(gasUsed uint64, gasPrice *big.Int) (*big.Int, error) {
	gfc.mu.Lock()
	defer gfc.mu.Unlock()

	if gasPrice == nil || gasPrice.Sign() <= 0 {
		return nil, ErrInvalidGasPrice
	}

	// Calculate fee = gasUsed * gasPrice
	// audit-fix R8-3: use SetUint64 to avoid int64 overflow for large gasUsed values
	fee := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), gasPrice)
	gfc.accumulatedFees.Add(gfc.accumulatedFees, fee)

	return fee, nil
}

// GasFeeDistribution represents how gas fees are distributed
type GasFeeDistribution struct {
	// TotalFees is the total fees collected
	TotalFees *big.Int
	// BurnedFees is the amount burned
	BurnedFees *big.Int
	// ProposerFees is the amount going to the block proposer
	ProposerFees *big.Int
	// ValidatorFees maps validator addresses to their fee share
	ValidatorFees map[types.Address]*big.Int
}

// DistributeFees distributes accumulated fees among validators
// blockHeight is used to calculate the dynamic burn rate (see CalculateBurnRate).
func (gfc *GasFeeCollector) DistributeFees(
	proposer types.Address,
	validators map[types.Address]*big.Int,
	blockHeight uint64,
) (*GasFeeDistribution, error) {
	gfc.mu.Lock()
	defer gfc.mu.Unlock()

	// L12-030 [P3]: reject the zero address as proposer. A zero proposer would credit
	// proposerFees to the zero-address key (types.Address{}), locking funds in a
	// non-existent account. The zero address is never a valid block proposer.
	if proposer == (types.Address{}) {
		return nil, ErrZeroProposerAddress
	}

	if gfc.accumulatedFees.Sign() == 0 {
		return &GasFeeDistribution{
			TotalFees:     big.NewInt(0),
			BurnedFees:    big.NewInt(0),
			ProposerFees:  big.NewInt(0),
			ValidatorFees: make(map[types.Address]*big.Int),
		}, nil
	}

	totalFees := new(big.Int).Set(gfc.accumulatedFees)
	distribution := &GasFeeDistribution{
		TotalFees:     totalFees,
		ValidatorFees: make(map[types.Address]*big.Int),
	}

	// AUDIT (2026) ECON-05 FIX: Use the actual EIP-1559 base-fee burn
	// (accumulatedBurn = sum of gasUsed*baseFee from CollectEIP1559Fee) when
	// available. This matches the on-chain burn performed by the executor.
	// When accumulatedBurn is zero (legacy CollectFee path or test-only
	// accumulatedFees injection), fall back to the burnRate% estimate.
	var burnedFees *big.Int
	if gfc.accumulatedBurn.Sign() > 0 {
		burnedFees = new(big.Int).Set(gfc.accumulatedBurn)
	} else {
		// Legacy fallback: burnRate% of totalFees (non-EIP-1559 path)
		burnRate := CalculateBurnRate(blockHeight)
		burnedFees = new(big.Int).Mul(totalFees, big.NewInt(int64(burnRate))) //nolint:gosec,G115
		burnedFees.Div(burnedFees, big.NewInt(10000))
	}
	distribution.BurnedFees = burnedFees
	gfc.totalBurned.Add(gfc.totalBurned, burnedFees)

	// Remaining after burn (defensive: cap burnedFees at totalFees to prevent
	// negative remaining in case of accumulation discrepancy)
	remaining := new(big.Int).Sub(totalFees, burnedFees)
	if remaining.Sign() < 0 {
		remaining.SetInt64(0)
	}

	// Calculate proposer's share
	proposerFees := new(big.Int).Mul(remaining, big.NewInt(int64(gfc.config.ProposerRate)))
	proposerFees.Div(proposerFees, big.NewInt(10000))
	distribution.ProposerFees = proposerFees

	// Validator pool share
	validatorPool := new(big.Int).Mul(remaining, big.NewInt(int64(gfc.config.ValidatorPoolRate)))
	validatorPool.Div(validatorPool, big.NewInt(10000))

	// audit-fix M-6: assign truncation dust to burn pool so all fees are accounted for.
	// dust = remaining - proposerFees - validatorPool (rounding remainder from integer division)
	dust := new(big.Int).Sub(remaining, proposerFees)
	dust.Sub(dust, validatorPool)
	if dust.Sign() > 0 {
		distribution.BurnedFees.Add(distribution.BurnedFees, dust)
		gfc.totalBurned.Add(gfc.totalBurned, dust)
	}

	// Calculate total stake
	totalStake := big.NewInt(0)
	for _, stake := range validators {
		if stake != nil && stake.Sign() > 0 {
			totalStake.Add(totalStake, stake)
		}
	}

	// Distribute to validators proportionally
	if totalStake.Sign() > 0 {
		for addr, stake := range validators {
			if stake == nil || stake.Sign() <= 0 {
				continue
			}
			// fee = validatorPool * stake / totalStake
			fee := new(big.Int).Mul(validatorPool, stake)
			fee.Div(fee, totalStake)
			distribution.ValidatorFees[addr] = fee
		}
	}

	// Add proposer fees to their validator fees if they're a validator
	if existingFee, exists := distribution.ValidatorFees[proposer]; exists {
		distribution.ValidatorFees[proposer] = new(big.Int).Add(existingFee, proposerFees)
	} else {
		distribution.ValidatorFees[proposer] = proposerFees
	}

	// Reset accumulated fees
	gfc.accumulatedFees = big.NewInt(0)
	// AUDIT (2026) ECON-05: Reset accumulated burn alongside fees.
	gfc.accumulatedBurn = big.NewInt(0)

	return distribution, nil
}

// GetAccumulatedFees returns the current accumulated fees
func (gfc *GasFeeCollector) GetAccumulatedFees() *big.Int {
	gfc.mu.RLock()
	defer gfc.mu.RUnlock()
	return new(big.Int).Set(gfc.accumulatedFees)
}

// GetTotalBurned returns the total burned fees
func (gfc *GasFeeCollector) GetTotalBurned() *big.Int {
	gfc.mu.RLock()
	defer gfc.mu.RUnlock()
	return new(big.Int).Set(gfc.totalBurned)
}

// GetBaseFee returns the current base fee
func (gfc *GasFeeCollector) GetBaseFee() *big.Int {
	gfc.mu.RLock()
	defer gfc.mu.RUnlock()
	return new(big.Int).Set(gfc.config.BaseFee)
}

// SetBaseFee updates the base fee (for dynamic fee adjustment)
func (gfc *GasFeeCollector) SetBaseFee(baseFee *big.Int) error {
	if baseFee == nil || baseFee.Sign() <= 0 {
		return ErrInvalidGasPrice
	}

	gfc.mu.Lock()
	defer gfc.mu.Unlock()
	gfc.config.BaseFee = new(big.Int).Set(baseFee)
	return nil
}

// GetConfig returns a copy of the gas fee configuration
func (gfc *GasFeeCollector) GetConfig() *GasFeeConfig {
	gfc.mu.RLock()
	defer gfc.mu.RUnlock()

	return &GasFeeConfig{
		BaseFee:           new(big.Int).Set(gfc.config.BaseFee),
		BurnRate:          gfc.config.BurnRate,
		ProposerRate:      gfc.config.ProposerRate,
		ValidatorPoolRate: gfc.config.ValidatorPoolRate,
	}
}

// Reset resets the accumulated fees (for testing or new block)
func (gfc *GasFeeCollector) Reset() {
	gfc.mu.Lock()
	defer gfc.mu.Unlock()
	gfc.accumulatedFees = big.NewInt(0)
}

// CalculateNextBaseFee computes the base fee for the next block per EIP-1559 rules.
// parentGasUsed: total gas used in the parent block
// parentGasLimit: gas limit of the parent block
// parentBaseFee: base fee of the parent block
// Returns the new base fee for the current block.
func CalculateNextBaseFee(parentGasUsed, parentGasLimit uint64, parentBaseFee *big.Int) *big.Int {
	if parentBaseFee == nil || parentBaseFee.Sign() <= 0 {
		return big.NewInt(1000000000)
	}

	gasTarget := parentGasLimit / 2

	// ECON-GF-01 FIX (deep-audit 2026-07-12): a parent gas limit of 0 or 1 yields
	// gasTarget==0; the excess-branch below then divides by gasTarget, and
	// big.Int division by zero panics — halting the node. With no meaningful
	// target the fee cannot be adjusted, so return it unchanged.
	if gasTarget == 0 {
		return new(big.Int).Set(parentBaseFee)
	}

	if parentGasUsed == gasTarget {
		return new(big.Int).Set(parentBaseFee)
	}

	var delta *big.Int
	if parentGasUsed > gasTarget {
		excess := parentGasUsed - gasTarget
		delta = new(big.Int).Mul(parentBaseFee, new(big.Int).SetUint64(excess))
		delta.Div(delta, new(big.Int).SetUint64(gasTarget))
		delta.Div(delta, big.NewInt(8))
		return new(big.Int).Add(parentBaseFee, delta)
	}

	shortfall := gasTarget - parentGasUsed
	delta = new(big.Int).Mul(parentBaseFee, new(big.Int).SetUint64(shortfall))
	delta.Div(delta, new(big.Int).SetUint64(gasTarget))
	delta.Div(delta, big.NewInt(8))
	result := new(big.Int).Sub(parentBaseFee, delta)
	// P3-E3 FIX (floor check, already enforced — documented here): The
	// subtraction above is the ONLY path that can drive the fee toward zero.
	// This guard ensures the function NEVER returns 0 (or negative): if the
	// computed decrease would take the fee to <= 0, we clamp to 1 wei. The
	// other return paths (nil/<=0 input → 1e9; equal gas → copy of >0
	// parentBaseFee; excess gas → parentBaseFee+delta which is >0) are all
	// already >= 1, so the floor is guaranteed on every path.
	if result.Sign() <= 0 {
		return big.NewInt(1)
	}
	return result
}

// EffectiveGasPrice returns the effective gas price for an EIP-1559 transaction.
// effective_gas_price = min(maxFeePerGas, baseFee + maxPriorityFeePerGas)
func EffectiveGasPrice(baseFee, maxFeePerGas, maxPriorityFeePerGas *big.Int) *big.Int {
	// L6-028 SECURITY FIX: Guard against nil baseFee which would cause a panic
	// in Add(). Treat nil baseFee as 0.
	fee := baseFee
	if fee == nil {
		fee = big.NewInt(0)
	}
	if maxFeePerGas == nil {
		return new(big.Int).Set(fee)
	}
	tip := maxPriorityFeePerGas
	if tip == nil {
		tip = big.NewInt(0)
	}
	total := new(big.Int).Add(fee, tip)
	if total.Cmp(maxFeePerGas) > 0 {
		return new(big.Int).Set(maxFeePerGas)
	}
	return total
}

// CollectEIP1559Fee collects gas fees for an EIP-1559 dynamic fee transaction.
// Returns (totalFee, burnedFee, priorityFee).
func (gfc *GasFeeCollector) CollectEIP1559Fee(gasUsed uint64, baseFee, maxPriorityFeePerGas *big.Int) (*big.Int, *big.Int, *big.Int, error) {
	gfc.mu.Lock()
	defer gfc.mu.Unlock()

	if baseFee == nil || baseFee.Sign() <= 0 {
		return nil, nil, nil, ErrInvalidGasPrice
	}

	gasUsedBig := new(big.Int).SetUint64(gasUsed)
	totalFee := new(big.Int).Mul(gasUsedBig, baseFee)

	priorityFee := big.NewInt(0)
	if maxPriorityFeePerGas != nil && maxPriorityFeePerGas.Sign() > 0 {
		priorityFee = new(big.Int).Mul(gasUsedBig, maxPriorityFeePerGas)
		totalFee.Add(totalFee, priorityFee)
	}

	burnedFee := new(big.Int).Mul(gasUsedBig, baseFee)

	gfc.accumulatedFees.Add(gfc.accumulatedFees, totalFee)
	// AUDIT (2026) ECON-05 FIX: Accumulate the actual EIP-1559 base-fee
	// burn (gasUsed * baseFee) so DistributeFees can use the real on-chain
	// burn amount instead of the inaccurate totalFees * burnRate% estimate.
	// This does NOT add to totalBurned directly — DistributeFees will move
	// accumulatedBurn into totalBurned during distribution.
	gfc.accumulatedBurn.Add(gfc.accumulatedBurn, burnedFee)

	return totalFee, burnedFee, priorityFee, nil
}
