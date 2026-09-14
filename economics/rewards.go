// Quantaureum Node source, version 1.0.0.
// Package economics implements the economic model for the Quantaureum blockchain.
// This includes block rewards, gas fee distribution, staking, and governance parameters.
package economics

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/types"
)

// Reward-related errors
var (
	ErrInvalidBlockHeight   = errors.New("invalid block height")
	ErrInvalidRewardAmount  = errors.New("invalid reward amount")
	ErrRewardAlreadyClaimed = errors.New("reward already claimed")
	ErrNoValidatorForReward = errors.New("no validator for reward")

	// audit-fix HIGH ECONOMICS: overflow and reward validation errors
	ErrInvalidRewardConfig = errors.New("invalid reward config: overflow or validation error")
	ErrRewardExceedsTotal  = errors.New("distributed rewards exceed total reward pool")

	// R32-P3-05 FIX (2026-07-28): reward calculation result exceeds sanity cap.
	// Returned (after clamping) when a maliciously large totalSupply or
	// config would produce a reward so large that subsequent big.Int
	// multiplications (in DistributeRewardAmount) cause memory bloat / DoS.
	ErrRewardExceedsSanityCap = errors.New("reward exceeds sanity cap")
)

// maxBlockReward is the upper bound for any single block reward calculation.
// R32-P3-05 FIX (2026-07-28): big.Int itself does not overflow, but an
// attacker-controlled totalSupply (e.g., 10^100 from a bug or 51% attack)
// would produce equally huge reward values, and the downstream
// multiplications in DistributeRewardAmount (totalReward * ProposerShare,
// validatorPool * stake) would allocate gigabytes of memory per block.
// 10^30 base units = 10^12 QAU, well above the 20M QAU total supply (2×10^25 wei).
// Matches maxGasPrice for consistency.
var maxBlockReward = new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)

// RewardConfig defines the block reward configuration
type RewardConfig struct {
	// InitialBlockReward is the initial reward per block (in wei)
	InitialBlockReward *big.Int

	// HalvingInterval is the number of blocks between reward halvings
	HalvingInterval uint64

	// MinBlockReward is the minimum reward per block (floor)
	MinBlockReward *big.Int

	// InflationRate is the annual inflation rate in basis points (e.g., 500 = 5%)
	InflationRate uint32

	// BlocksPerYear is the estimated number of blocks per year
	BlocksPerYear uint64
}

// validateRewardConfig validates the reward configuration for overflow and bounds.
// audit-fix HIGH ECONOMICS: validates config values to prevent overflow in calculations.
func validateRewardConfig(config *RewardConfig) error {
	if config == nil {
		return ErrInvalidRewardConfig
	}
	// InflationRate is in basis points (0-10000 = 0-100%)
	if config.InflationRate > 10000 {
		return ErrInvalidRewardConfig
	}
	// BlocksPerYear must be positive for division
	if config.BlocksPerYear == 0 {
		return ErrInvalidRewardConfig
	}
	// HalvingInterval must be positive for division
	if config.HalvingInterval == 0 {
		return ErrInvalidRewardConfig
	}
	return nil
}

// DefaultRewardConfig returns the default reward configuration
func DefaultRewardConfig() *RewardConfig {
	return &RewardConfig{
		// Initial reward: 0 QAU per block (rewards come from inflation, not new issuance)
		InitialBlockReward: big.NewInt(0),
		// audit-fix  use 12-second slots consistent with consensus layer.
		// Halving every 4 years at 12s blocks = 4 * 365 * 24 * 60 * 60 / 12 = 10,512,000
		HalvingInterval: 4 * 365 * 24 * 60 * 60 / 12, // 10,512,000 blocks
		// Minimum reward: 0 QAU per block
		MinBlockReward: big.NewInt(0),
		// 5% initial annual inflation rate (500 bps). Adaptively adjusted by
		// InflationModel based on stake ratio, targeting ~67% of total supply.
		InflationRate: 500,
		// audit-fix  12-second blocks => 2,628,000 blocks/year
		BlocksPerYear: 365 * 24 * 60 * 60 / 12, // 2,628,000
	}
}

// RewardCalculator calculates block rewards based on the inflation curve
type RewardCalculator struct {
	config *RewardConfig
	mu     sync.RWMutex
}

// NewRewardCalculator creates a new reward calculator.
// R58-C-NEW-1 [CRITICAL] FIX: Returns error when config is invalid, preventing
// division-by-zero panics in CalculateInflationReward and CalculateBlockReward.
func NewRewardCalculator(config *RewardConfig) (*RewardCalculator, error) {
	if config == nil {
		config = DefaultRewardConfig()
	}
	if err := validateRewardConfig(config); err != nil {
		return nil, fmt.Errorf("reward calculator: %w", err)
	}
	return &RewardCalculator{
		config: config,
	}, nil
}

// CalculateBlockReward calculates the block reward for a given block height
// The reward follows a halving schedule similar to Bitcoin
func (rc *RewardCalculator) CalculateBlockReward(blockHeight uint64) *big.Int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	if blockHeight == 0 {
		// Genesis block has no reward
		return big.NewInt(0)
	}

	// Calculate the number of halvings that have occurred
	halvings := blockHeight / rc.config.HalvingInterval

	// audit-fix M-9: cap halvings at 64 to prevent DoS.
	// 2^64 halvings would reduce any realistic reward to zero.
	if halvings > 64 {
		return new(big.Int).Set(rc.config.MinBlockReward)
	}

	// Calculate reward with halving
	reward := new(big.Int).Set(rc.config.InitialBlockReward)

	// Apply halvings (reward = initial / 2^halvings)
	for i := uint64(0); i < halvings; i++ {
		reward.Div(reward, big.NewInt(2))
		// Check if we've hit the minimum
		if reward.Cmp(rc.config.MinBlockReward) < 0 {
			return new(big.Int).Set(rc.config.MinBlockReward)
		}
	}

	return reward
}

// CalculateInflationReward calculates the reward based on annual inflation rate
// This is an alternative reward model based on total supply
func (rc *RewardCalculator) CalculateInflationReward(totalSupply *big.Int) *big.Int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	if totalSupply == nil || totalSupply.Sign() <= 0 {
		return big.NewInt(0)
	}

	// R32-P3-05 FIX (2026-07-28): cap totalSupply input to prevent memory DoS.
	// If totalSupply exceeds maxBlockReward, the multiplication
	// (totalSupply * InflationRate) would allocate a huge big.Int even before
	// the division. Clamp to the cap so the result is bounded.
	// In practice totalSupply is ~2×10^25 wei (20M QAU), well below 10^30.
	cappedSupply := totalSupply
	if totalSupply.Cmp(maxBlockReward) > 0 {
		cappedSupply = maxBlockReward
	}

	// Annual inflation = totalSupply * inflationRate / 10000
	// FIX: int64(rc.config.InflationRate) is safe — InflationRate is
	// uint32 basis points (e.g., 200 = 2%), far below int64 max (9.2e18).
	// Use named constant instead of magic 10000 for consistency with
	// consensus.BasisPointsDenominator.
	const basisPointsDenominator = 10000
	annualInflation := new(big.Int).Mul(cappedSupply, big.NewInt(int64(rc.config.InflationRate))) //nolint:gosec,G115
	annualInflation.Div(annualInflation, big.NewInt(basisPointsDenominator))

	// Per-block reward = annualInflation / blocksPerYear
	// audit-fix L-6: use SetUint64 to prevent int64 truncation of BlocksPerYear
	// CRITICAL: prevent division by zero if BlocksPerYear is not configured
	if rc.config.BlocksPerYear == 0 {
		return big.NewInt(0)
	}
	blockReward := new(big.Int).Div(annualInflation, new(big.Int).SetUint64(rc.config.BlocksPerYear))

	// R32-P3-05 FIX (2026-07-28): defense-in-depth — clamp the final result
	// to maxBlockReward. This catches any edge case where the division
	// produces an unexpectedly large value (e.g., BlocksPerYear=1 in a
	// misconfigured test genesis).
	if blockReward.Cmp(maxBlockReward) > 0 {
		return new(big.Int).Set(maxBlockReward)
	}

	return blockReward
}

// SetInflationRate updates the inflation rate used by CalculateInflationReward.
// This is called by EconomicsManager to sync the InflationModel's adaptive rate.
func (rc *RewardCalculator) SetInflationRate(rate uint32) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.config.InflationRate = rate
}

// GetHalvingEpoch returns the current halving epoch for a block height
func (rc *RewardCalculator) GetHalvingEpoch(blockHeight uint64) uint64 {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	return blockHeight / rc.config.HalvingInterval
}

// GetNextHalvingBlock returns the block height of the next halving
func (rc *RewardCalculator) GetNextHalvingBlock(blockHeight uint64) uint64 {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	currentEpoch := blockHeight / rc.config.HalvingInterval
	return (currentEpoch + 1) * rc.config.HalvingInterval
}

// GetConfig returns a copy of the reward configuration
func (rc *RewardCalculator) GetConfig() *RewardConfig {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	return &RewardConfig{
		InitialBlockReward: new(big.Int).Set(rc.config.InitialBlockReward),
		HalvingInterval:    rc.config.HalvingInterval,
		MinBlockReward:     new(big.Int).Set(rc.config.MinBlockReward),
		InflationRate:      rc.config.InflationRate,
		BlocksPerYear:      rc.config.BlocksPerYear,
	}
}

// RewardDistribution represents how a block reward is distributed
type RewardDistribution struct {
	// ProposerReward is the reward for the block proposer
	ProposerReward *big.Int
	// ValidatorRewards maps validator addresses to their rewards
	ValidatorRewards map[types.Address]*big.Int
	// TotalReward is the total reward distributed
	TotalReward *big.Int
}

// RewardDistributor handles the distribution of block rewards
type RewardDistributor struct {
	calculator *RewardCalculator
	// ProposerShare is the percentage of reward going to proposer (basis points)
	ProposerShare uint32
	mu            sync.RWMutex
}

// NewRewardDistributor creates a new reward distributor.
// R58-C-NEW-1 cascade fix: now returns error since NewRewardCalculator can fail
// on invalid config, preventing silent default initialization.
func NewRewardDistributor(calculator *RewardCalculator, proposerShare uint32) (*RewardDistributor, error) {
	if calculator == nil {
		var err error
		calculator, err = NewRewardCalculator(nil)
		if err != nil {
			return nil, fmt.Errorf("reward distributor: %w", err)
		}
	}
	if proposerShare > 10000 {
		proposerShare = 10000
	}
	return &RewardDistributor{
		calculator:    calculator,
		ProposerShare: proposerShare,
	}, nil
}

// DistributeReward distributes the block reward among validators
// proposer: the block proposer address
// validators: map of validator addresses to their stake weights
func (rd *RewardDistributor) DistributeReward(
	blockHeight uint64,
	proposer types.Address,
	validators map[types.Address]*big.Int,
) (*RewardDistribution, error) {
	totalReward := rd.calculator.CalculateBlockReward(blockHeight)
	return rd.DistributeRewardAmount(totalReward, proposer, validators)
}

// DistributeRewardAmount distributes a pre-calculated reward amount among validators.
// audit-fix  this method accepts totalReward directly so callers (e.g. ProcessBlock)
// do not need to temporarily mutate RewardCalculator.config, which caused a data race.
func (rd *RewardDistributor) DistributeRewardAmount(
	totalReward *big.Int,
	proposer types.Address,
	validators map[types.Address]*big.Int,
) (*RewardDistribution, error) {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	if len(validators) == 0 {
		return nil, ErrNoValidatorForReward
	}

	// R32-P3-05 FIX (2026-07-28): defense-in-depth — reject excessively large
	// totalReward before multiplications. big.Int doesn't overflow, but a
	// huge totalReward (e.g., 10^100) would cause the downstream Mul calls
	// (totalReward * ProposerShare, validatorPool * stake) to allocate
	// gigabytes of memory, enabling memory DoS. The cap matches
	// CalculateInflationReward's output cap, so legitimate rewards pass.
	if totalReward != nil && totalReward.Sign() > 0 && totalReward.Cmp(maxBlockReward) > 0 {
		return nil, fmt.Errorf("%w: totalReward %s exceeds maxBlockReward %s",
			ErrRewardExceedsSanityCap, totalReward.String(), maxBlockReward.String())
	}

	if totalReward == nil || totalReward.Sign() == 0 {
		return &RewardDistribution{
			ProposerReward:   big.NewInt(0),
			ValidatorRewards: make(map[types.Address]*big.Int),
			TotalReward:      big.NewInt(0),
		}, nil
	}

	distribution := &RewardDistribution{
		ValidatorRewards: make(map[types.Address]*big.Int),
		TotalReward:      new(big.Int).Set(totalReward),
	}

	// Calculate proposer's share.
	//  NOTE (P3): All reward math uses *big.Int integer arithmetic (no
	// floats) to avoid rounding/precision loss on wei-denominated values.
	// Division truncates toward zero (floor for positive values), so the sum of
	// distributed rewards can be at most a few wei less than the input
	// totalReward due to integer rounding.
	// R35-P3-ECON-1 FIX (2026-07-29): Previously the rounding remainder was
	// silently discarded (not minted), causing long-term supply drift. Now the
	// remainder is routed to the proposer as the reward sink, so the sum of
	// distributed rewards exactly equals totalReward.
	proposerReward := new(big.Int).Mul(totalReward, big.NewInt(int64(rd.ProposerShare)))
	proposerReward.Div(proposerReward, big.NewInt(10000))
	distribution.ProposerReward = proposerReward

	// Remaining reward for validators
	validatorPool := new(big.Int).Sub(totalReward, proposerReward)

	// Calculate total stake
	totalStake := big.NewInt(0)
	for _, stake := range validators {
		if stake != nil && stake.Sign() > 0 {
			totalStake.Add(totalStake, stake)
		}
	}

	if totalStake.Sign() == 0 {
		// No stake, give all to proposer
		distribution.ProposerReward = totalReward
		return distribution, nil
	}

	// Distribute to validators proportionally and track the distributed sum
	// so the integer-division remainder can be routed to the proposer instead
	// of being discarded.
	distributedToValidators := big.NewInt(0)
	for addr, stake := range validators {
		if stake == nil || stake.Sign() <= 0 {
			continue
		}
		// reward = validatorPool * stake / totalStake
		reward := new(big.Int).Mul(validatorPool, stake)
		reward.Div(reward, totalStake)
		distribution.ValidatorRewards[addr] = reward
		distributedToValidators.Add(distributedToValidators, reward)
	}

	// R35-P3-ECON-1 FIX: route the integer-division remainder to the proposer
	// (reward sink) instead of discarding it. This keeps the sum of
	// ProposerReward + all ValidatorRewards exactly equal to totalReward,
	// preventing long-term supply drift from accumulated dust.
	remainder := new(big.Int).Sub(validatorPool, distributedToValidators)
	if remainder.Sign() > 0 {
		proposerReward.Add(proposerReward, remainder)
	}

	// Add proposer reward to their validator reward if they're a validator
	if existingReward, exists := distribution.ValidatorRewards[proposer]; exists {
		distribution.ValidatorRewards[proposer] = new(big.Int).Add(existingReward, proposerReward)
	} else {
		distribution.ValidatorRewards[proposer] = proposerReward
	}

	return distribution, nil
}
