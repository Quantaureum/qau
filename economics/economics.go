// Quantaureum Node source, version 1.0.0.
// Package economics implements the economic model for the Quantaureum blockchain.
// This file provides the unified economics manager that coordinates all economic components.
package economics

import (
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/types"
)

// maxGasPrice is the upper bound for gas price / base fee values to prevent
// big.Int memory bloat from maliciously large inputs. 10^30 base units.
// L12-018 FIX.
var maxGasPrice = new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)

// StateModifier is the interface for applying balance transitions to the
// chain state. It is satisfied by *state.StateDB. Defined here to avoid a
// circular dependency between the economics and qaudb/state packages.
// FIX: FeeDistributor uses this to execute actual on-chain balance
// transfers (previously fees were tracked in memory only —"ghost accounting").
type StateModifier interface {
	AddBalance(addr types.Address, amount *big.Int) error
	SubBalance(addr types.Address, amount *big.Int) error
	GetBalance(addr types.Address) *big.Int
	SetBalance(addr types.Address, balance *big.Int)
}

// EconomicsConfig contains all economic configuration
type EconomicsConfig struct {
	Reward     *RewardConfig
	GasFee     *GasFeeConfig
	Staking    *StakingConfig
	Governance *GovernanceConfig
}

// DefaultEconomicsConfig returns the default economics configuration.
//
//	NOTE (P3): testnet vs mainnet configuration differences.
//
// This returns the SHARED defaults used by all networks. Network-specific
// overrides are applied by the node bootstrap (see node/ package) based on
// ChainID:
//   - mainnet (1668): production reward/staking/governance parameters, no
//     inflation (InitialBlockReward=0), strict MinStake.
//   - testnet  (1669): same parameters as mainnet but lower MinStake and
//     shorter VotingPeriod/ExecutionDelay to allow faster governance testing.
//   - devnet   (1333): relaxed limits (low MinStake, short unbonding) and
//     dev-mode flags for local development.
//
// When introducing a network-specific tweak, add it in the bootstrap path so
// DefaultEconomicsConfig stays the single source of shared defaults.
func DefaultEconomicsConfig() *EconomicsConfig {
	return &EconomicsConfig{
		Reward:     DefaultRewardConfig(),
		GasFee:     DefaultGasFeeConfig(),
		Staking:    DefaultStakingConfig(),
		Governance: DefaultGovernanceConfig(),
	}
}

// EconomicsManager coordinates all economic components
type EconomicsManager struct {
	config *EconomicsConfig
	mu     sync.RWMutex

	// Component managers
	RewardCalculator  *RewardCalculator
	RewardDistributor *RewardDistributor
	GasFeeCollector   *GasFeeCollector
	StakingManager    *StakingManager
	GovernanceManager *GovernanceManager

	// FIX: FeeDistributor is now connected to EconomicsManager.
	// It is optional —when nil, ProcessBlock uses GasFeeCollector.DistributeFees.
	// When set (via SetFeeDistributor), it provides multi-party fee splitting
	// (validators/treasury/developer/insurance/burn).
	FeeDistributor *FeeDistributor

	// Total supply tracking
	totalSupply *big.Int

	// inflation is the InflationModel whose totalSupply must stay in sync with
	// em.totalSupply. It is optional; when set, ProcessBlock syncs the
	// authoritative em.totalSupply back into it to prevent drift.
	//
	// I22-004 NOTE: There is a design-level potential for brief inconsistency.
	// em.totalSupply is modified under em.mu, then synced into InflationModel
	// (which has its own lock) within the same critical section. A concurrent
	// reader of InflationModel.totalSupply that does not go through
	// EconomicsManager may observe a stale value for the duration between the
	// em.totalSupply mutation and the em.inflation.SetTotalSupply() call.
	// In practice this window is negligible because both operations occur under
	// em.mu. The authoritative source of truth is always em.totalSupply
	// (accessed via GetTotalSupply()). InflationModel.totalSupply should be
	// treated as a read-only mirror, not an independent tracker.
	inflation *InflationModel
}

// NewEconomicsManager creates a new economics manager
// R40-M11 FIX: Returns error if gas fee config has invalid fee rates.
func NewEconomicsManager(config *EconomicsConfig) (*EconomicsManager, error) {
	if config == nil {
		config = DefaultEconomicsConfig()
	}

	rewardCalc, err := NewRewardCalculator(config.Reward)
	if err != nil {
		return nil, fmt.Errorf("invalid reward config: %w", err)
	}

	gasFeeCollector, err := NewGasFeeCollector(config.GasFee)
	if err != nil {
		return nil, fmt.Errorf("invalid gas fee config: %w", err)
	}

	rewardDist, err := NewRewardDistributor(rewardCalc, 2500)
	if err != nil {
		return nil, fmt.Errorf("invalid reward distributor: %w", err)
	}

	em := &EconomicsManager{
		config:            config,
		RewardCalculator:  rewardCalc,
		RewardDistributor: rewardDist,
		GasFeeCollector:   gasFeeCollector,
		StakingManager:    NewStakingManager(config.Staking),
		GovernanceManager: NewGovernanceManager(config.Governance),
		totalSupply:       big.NewInt(0),
	}

	// FIX: Warn if totalSupply is 0 at construction. totalSupply must
	// be set via SetTotalSupply() after genesis allocation is loaded. A zero
	// totalSupply means inflation reward calculations will produce 0 rewards
	// until SetTotalSupply is called.
	if em.totalSupply.Sign() == 0 {
		log.Printf("WARNING: EconomicsManager created with totalSupply=0; " +
			"call SetTotalSupply() with the genesis allocation before processing blocks " +
			"to ensure correct inflation reward calculations")
	}

	return em, nil
}

// SetTotalSupply sets the total supply for inflation calculations
func (em *EconomicsManager) SetTotalSupply(supply *big.Int) {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.totalSupply = new(big.Int).Set(supply)
}

// GetTotalSupply returns the current total supply
func (em *EconomicsManager) GetTotalSupply() *big.Int {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return new(big.Int).Set(em.totalSupply)
}

// SetInflationModel wires an InflationModel into the EconomicsManager so that
// em.totalSupply (authoritative) is synced back into the model after every
// block, preventing the two independent totalSupply trackers from drifting.
func (em *EconomicsManager) SetInflationModel(im *InflationModel) {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.inflation = im
}

// SetFeeDistributor wires a FeeDistributor into the EconomicsManager.
// FIX: FeeDistributor was defined but never accessible from EconomicsManager.
// When set, callers can use it for multi-party fee distribution. When nil,
// ProcessBlock falls back to GasFeeCollector.DistributeFees.
func (em *EconomicsManager) SetFeeDistributor(fd *FeeDistributor) {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.FeeDistributor = fd
}

// GetFeeDistributor returns the connected FeeDistributor, or nil if not set.
func (em *EconomicsManager) GetFeeDistributor() *FeeDistributor {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.FeeDistributor
}

// ProcessBlock processes economic operations for a new block
func (em *EconomicsManager) ProcessBlock(
	blockHeight uint64,
	proposer types.Address,
	gasUsed uint64,
	gasPrice *big.Int,
) (*BlockEconomics, error) {
	// L12-018 FIX: reject excessively large gasPrice to prevent big.Int memory bloat.
	if gasPrice != nil && gasPrice.Sign() > 0 && gasPrice.Cmp(maxGasPrice) > 0 {
		return nil, fmt.Errorf("gasPrice %s exceeds maximum allowed value", gasPrice.String())
	}

	result := &BlockEconomics{
		BlockHeight: blockHeight,
		Proposer:    proposer,
	}

	// FIX: Narrow em.mu lock scope. GasFeeCollector, FeeDistributor,
	// and StakingManager each have their own internal mutexes, so em.mu only
	// needs to protect em.totalSupply and em.inflation. Previously em.mu was
	// held via defer for the entire function, blocking concurrent readers
	// (GetTotalSupply, GetStakingStats, etc.) during external computations.
	//
	// R47-CS-02 FIX: Move GetActiveValidators inside em.mu to ensure
	// consistency with totalSupply. Previously, validators were acquired
	// outside the lock, creating a TOCTOU window where the validator set
	// could change between acquisition and use.
	em.mu.Lock()
	defer em.mu.Unlock()

	validators := em.StakingManager.GetActiveValidators()
	totalSupply := new(big.Int).Set(em.totalSupply)

	// Sync InflationModel's adaptive rate to RewardCalculator before computing rewards.
	// The InflationModel auto-adjusts based on stake ratio, targeting ~67% of total supply.
	// This connection ensures block rewards reflect the current adaptive inflation rate
	// rather than the static default (500 bps = 5%).
	if em.inflation != nil {
		currentRate := em.inflation.GetCurrentRate()
		if currentRate != nil && currentRate.IsInt64() {
			rateInt64 := currentRate.Int64()
			// R44-CS-003 FIX: Log when the inflation rate is silently
			// discarded due to overflow or non-Int64 representation.
			if rateInt64 < 0 || rateInt64 > 0xFFFFFFFF {
				log.Printf("[WARN] economics: inflation rate %s overflows uint32, using previous rate", currentRate.String())
			} else {
				em.RewardCalculator.SetInflationRate(uint32(rateInt64))
			}
		} else if currentRate != nil {
			log.Printf("[WARN] economics: inflation rate %s is not representable as int64, using previous rate", currentRate.String())
		}
	}

	inflationReward := em.RewardCalculator.CalculateInflationReward(totalSupply)

	rewardDist, err := em.RewardDistributor.DistributeRewardAmount(inflationReward, proposer, validators)
	if err != nil {
		return nil, err
	}
	result.BlockReward = rewardDist

	if gasUsed > 0 && gasPrice != nil && gasPrice.Sign() > 0 {
		// FIX: Return the fee-collection error instead of silently
		// ignoring it. Include gasUsed/gasPrice/blockHeight/proposer for diagnosis.
		// AUDIT (2026) HIGH-12 (ECON-01): Keep CollectFee for accounting/
		// metrics via GasFeeCollector.DistributeFees below, but do NOT route to
		// FeeDistributor — the executor already credits the coinbase. Routing to
		// FeeDistributor caused a double-payment (unbacked inflation).
		if _, err := em.GasFeeCollector.CollectFee(gasUsed, gasPrice); err != nil {
			return nil, fmt.Errorf("failed to collect gas fee (gasUsed=%d, gasPrice=%s, block=%d, proposer=%x): %w",
				gasUsed, gasPrice.String(), blockHeight, proposer, err)
		}
	}

	feeDist, err := em.GasFeeCollector.DistributeFees(proposer, validators, blockHeight)
	if err != nil {
		return nil, err
	}
	result.GasFees = feeDist

	// FIX: Lock already held from the beginning of ProcessBlock.
	// No need to re-acquire here.

	if rewardDist.TotalReward != nil && rewardDist.TotalReward.Sign() > 0 {
		em.totalSupply.Add(em.totalSupply, rewardDist.TotalReward)
	}
	if feeDist.BurnedFees != nil {
		if em.totalSupply.Cmp(feeDist.BurnedFees) < 0 {
			return nil, fmt.Errorf("burned fees exceed total supply")
		}
		em.totalSupply.Sub(em.totalSupply, feeDist.BurnedFees)
		// L11-015 FIX: defense-in-depth check —ensure total supply did not
		// go negative after the burn subtraction.
		if em.totalSupply.Sign() < 0 {
			return nil, fmt.Errorf("total supply became negative after burning fees")
		}
	}

	// L12-003 FIX: sync the authoritative em.totalSupply back into the
	// InflationModel so the two independent totalSupply trackers never drift.
	if em.inflation != nil {
		em.inflation.SetTotalSupply(em.totalSupply)
	}

	return result, nil
}

// ProcessEIP1559Block processes economic operations for a block with EIP-1559 fees.
func (em *EconomicsManager) ProcessEIP1559Block(
	blockHeight uint64,
	proposer types.Address,
	gasUsed uint64,
	baseFee *big.Int,
	priorityFees *big.Int,
) (*BlockEconomics, error) {
	// L12-018 FIX: reject excessively large baseFee/priorityFees to prevent
	// big.Int memory bloat.
	if baseFee != nil && baseFee.Sign() > 0 && baseFee.Cmp(maxGasPrice) > 0 {
		return nil, fmt.Errorf("baseFee exceeds maximum allowed value")
	}
	if priorityFees != nil && priorityFees.Sign() > 0 && priorityFees.Cmp(maxGasPrice) > 0 {
		return nil, fmt.Errorf("priorityFees exceeds maximum allowed value")
	}

	// R44-CS-002 FIX: Move validators acquisition inside em.mu to prevent
	// TOCTOU. Previously validators was fetched before em.mu.Lock(), while
	// totalSupply was fetched after. If the validator set changed between
	// the two snapshots, reward distribution would use inconsistent data.
	// FIX: Hold em.mu for the entire ProcessEIP1559Block to prevent
	// TOCTOU, matching the  fix applied to ProcessBlock.
	em.mu.Lock()
	defer em.mu.Unlock()
	validators := em.StakingManager.GetActiveValidators()
	totalSupply := new(big.Int).Set(em.totalSupply)

	result := &BlockEconomics{
		BlockHeight: blockHeight,
		Proposer:    proposer,
	}

	// Sync InflationModel's adaptive rate to RewardCalculator before computing rewards.
	if em.inflation != nil {
		currentRate := em.inflation.GetCurrentRate()
		if currentRate != nil && currentRate.IsInt64() {
			rateInt64 := currentRate.Int64()
			// R44-CS-003 FIX: Log when the inflation rate is silently discarded.
			if rateInt64 < 0 || rateInt64 > 0xFFFFFFFF {
				log.Printf("[WARN] economics: inflation rate %s overflows uint32 (EIP1559), using previous rate", currentRate.String())
			} else {
				em.RewardCalculator.SetInflationRate(uint32(rateInt64))
			}
		} else if currentRate != nil {
			log.Printf("[WARN] economics: inflation rate %s is not representable as int64 (EIP1559), using previous rate", currentRate.String())
		}
	}

	inflationReward := em.RewardCalculator.CalculateInflationReward(totalSupply)

	rewardDist, err := em.RewardDistributor.DistributeRewardAmount(inflationReward, proposer, validators)
	if err != nil {
		return nil, err
	}
	result.BlockReward = rewardDist

	if gasUsed > 0 && baseFee != nil && baseFee.Sign() > 0 {
		tip := priorityFees
		if tip == nil {
			tip = big.NewInt(0)
		}
		// FIX: Return the fee-collection error instead of silently ignoring it.
		collectedFee, _, _, err := em.GasFeeCollector.CollectEIP1559Fee(gasUsed, baseFee, tip)
		if err != nil {
			return nil, fmt.Errorf("failed to collect EIP-1559 gas fee (gasUsed=%d, block=%d): %w",
				gasUsed, blockHeight, err)
		}
		// FIX: Route collected fees through FeeDistributor when available,
		// matching ProcessBlock's behavior (line 260-261). Previously EIP-1559
		// fees bypassed FeeDistributor entirely, missing multi-party splitting.
		if em.FeeDistributor != nil && collectedFee != nil && collectedFee.Sign() > 0 {
			em.FeeDistributor.CollectFee(collectedFee)
		}
	}

	feeDist, err := em.GasFeeCollector.DistributeFees(proposer, validators, blockHeight)
	if err != nil {
		return nil, err
	}
	result.GasFees = feeDist

	// FIX: Lock already held from the beginning of ProcessEIP1559Block.
	// No need to re-acquire here.

	if rewardDist.TotalReward != nil {
		em.totalSupply.Add(em.totalSupply, rewardDist.TotalReward)
	}
	if feeDist.BurnedFees != nil {
		if em.totalSupply.Cmp(feeDist.BurnedFees) < 0 {
			return nil, fmt.Errorf("burned fees exceed total supply")
		}
		em.totalSupply.Sub(em.totalSupply, feeDist.BurnedFees)
		// L11-015 FIX: defense-in-depth check —ensure total supply did not
		// go negative after the burn subtraction.
		if em.totalSupply.Sign() < 0 {
			return nil, fmt.Errorf("total supply became negative after burning fees")
		}
	}

	// L12-003 FIX: sync the authoritative em.totalSupply back into the
	// InflationModel so the two independent totalSupply trackers never drift.
	if em.inflation != nil {
		em.inflation.SetTotalSupply(em.totalSupply)
	}

	return result, nil
}

// GetCurrentBaseFee returns the current base fee for EIP-1559 transactions.
func (em *EconomicsManager) GetCurrentBaseFee() *big.Int {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return new(big.Int).Set(em.GasFeeCollector.GetBaseFee())
}

// UpdateBaseFee updates the base fee for the next block based on parent block's gas usage.
func (em *EconomicsManager) UpdateBaseFee(parentGasUsed, parentGasLimit uint64) {
	em.mu.Lock()
	defer em.mu.Unlock()
	currentBaseFee := em.GasFeeCollector.GetBaseFee()
	newBaseFee := CalculateNextBaseFee(parentGasUsed, parentGasLimit, currentBaseFee)
	em.GasFeeCollector.SetBaseFee(newBaseFee)
}

// BlockEconomics contains the economic results for a block
type BlockEconomics struct {
	BlockHeight uint64
	Proposer    types.Address
	BlockReward *RewardDistribution
	GasFees     *GasFeeDistribution
}

// TotalValidatorRewards returns the total rewards for all validators
func (be *BlockEconomics) TotalValidatorRewards() map[types.Address]*big.Int {
	rewards := make(map[types.Address]*big.Int)

	// Add block rewards
	if be.BlockReward != nil {
		for addr, reward := range be.BlockReward.ValidatorRewards {
			if _, exists := rewards[addr]; !exists {
				rewards[addr] = big.NewInt(0)
			}
			rewards[addr].Add(rewards[addr], reward)
		}
	}

	// Add gas fees
	if be.GasFees != nil {
		for addr, fee := range be.GasFees.ValidatorFees {
			if _, exists := rewards[addr]; !exists {
				rewards[addr] = big.NewInt(0)
			}
			rewards[addr].Add(rewards[addr], fee)
		}
	}

	return rewards
}

// GetConfig returns a copy of the economics configuration
func (em *EconomicsManager) GetConfig() *EconomicsConfig {
	em.mu.RLock()
	defer em.mu.RUnlock()

	return &EconomicsConfig{
		Reward:     em.RewardCalculator.GetConfig(),
		GasFee:     em.GasFeeCollector.GetConfig(),
		Staking:    em.StakingManager.GetConfig(),
		Governance: em.GovernanceManager.GetConfig(),
	}
}

// InitializeGovernanceParameters initializes the governance parameters
func (em *EconomicsManager) InitializeGovernanceParameters() {
	params := map[string]string{
		"block_reward_initial": em.config.Reward.InitialBlockReward.String(),
		"block_reward_min":     em.config.Reward.MinBlockReward.String(),
		"halving_interval":     big.NewInt(int64(em.config.Reward.HalvingInterval)).String(), // #nosec G115 -- config value always non-negative
		"inflation_rate":       big.NewInt(int64(em.config.Reward.InflationRate)).String(),   // #nosec G115 -- config value always non-negative
		"gas_base_fee":         em.config.GasFee.BaseFee.String(),
		"gas_burn_rate":        big.NewInt(int64(em.config.GasFee.BurnRate)).String(), // #nosec G115 -- config value always non-negative
		"min_stake":            em.config.Staking.MinStakeAmount.String(),
		"max_stake":            em.config.Staking.MaxStakeAmount.String(),
		"unbonding_period":     big.NewInt(int64(em.config.Staking.UnbondingPeriod)).String(),    // #nosec G115 -- config value always non-negative
		"max_validators":       big.NewInt(int64(em.config.Staking.MaxValidators)).String(),      // #nosec G115 -- config value always non-negative
		"voting_period":        big.NewInt(int64(em.config.Governance.VotingPeriod)).String(),    // #nosec G115 -- config value always non-negative
		"quorum_threshold":     big.NewInt(int64(em.config.Governance.QuorumThreshold)).String(), // #nosec G115 -- config value always non-negative
		"pass_threshold":       big.NewInt(int64(em.config.Governance.PassThreshold)).String(),   // #nosec G115 -- config value always non-negative
		"proposal_deposit":     em.config.Governance.ProposalDeposit.String(),
	}
	em.GovernanceManager.InitializeParameters(params)
}
