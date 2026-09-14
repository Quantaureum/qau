// Quantaureum Node source, version 1.0.0.
package economics

import (
	"math/big"
	"sort"
	"sync"
)

type InflationPhase uint8

const (
	InflationPhaseHigh     InflationPhase = 0
	InflationPhaseModerate InflationPhase = 1
	InflationPhaseLow      InflationPhase = 2
	InflationPhaseStable   InflationPhase = 3
)

// DefaultBlocksPerYear is the estimated number of blocks produced per year,
// assuming a 12-second block time: 365 * 24 * 60 * 60 / 12 = 2,628,000.
// L20-005 FIX: Extracted from a hardcoded magic number in CalculateNewSupply
// for clarity and maintainability. This value must match the BlocksPerYear
// used in staking.go and rewards.go; changing it affects block reward
// calculations across the entire economics module.
const DefaultBlocksPerYear = 2628000

type InflationConfig struct {
	InitialRate      *big.Int
	MinRate          *big.Int
	MaxRate          *big.Int
	TargetStakeRatio *big.Int
	AdjustmentPeriod uint64
	AdjustmentFactor *big.Int
	DecayFactor      *big.Int
	PhaseThresholds  map[InflationPhase]*big.Int
}

func DefaultInflationConfig() *InflationConfig {
	return &InflationConfig{
		InitialRate:      big.NewInt(500),
		MinRate:          big.NewInt(50),
		MaxRate:          big.NewInt(1000),
		TargetStakeRatio: big.NewInt(67),
		AdjustmentPeriod: 100000,
		AdjustmentFactor: big.NewInt(5),
		DecayFactor:      big.NewInt(995),
		PhaseThresholds: map[InflationPhase]*big.Int{
			InflationPhaseHigh:     big.NewInt(800),
			InflationPhaseModerate: big.NewInt(500),
			InflationPhaseLow:      big.NewInt(200),
			InflationPhaseStable:   big.NewInt(50),
		},
	}
}

type InflationModel struct {
	mu              sync.RWMutex
	config          *InflationConfig
	currentRate     *big.Int
	currentPhase    InflationPhase
	totalSupply     *big.Int
	stakedSupply    *big.Int
	lastAdjustment  uint64
	adjustmentCount uint64
}

// NewInflationModel creates a new inflation model seeded with the given
// initialSupply. The economics module is network-agnostic: the same inflation
// config (DefaultInflationConfig) and the same reward formula are used for
// every network. Only the initialSupply input differs, and it is derived by
// the caller (node) by summing the genesis allocations.
//
//	[P2] NOTE (testnet vs mainnet supply consistency): The genesis
//
// allocations intentionally differ by network, so initialSupply -- and
// therefore the absolute per-block reward -- differs as well:
//   - mainnet (ChainID 1668): 20,000,000 QAU  (genesis allocation)
//   - devnet  (ChainID 1333): 20,000,000 QAU  (genesis allocation, dev distribution)
//   - testnet (ChainID 1669):    ~128,000 QAU  (validator stakes only, no tokenomics)
//
// This is by design: testnet exists for consensus/protocol testing and does not
// replicate mainnet's full token distribution, so its absolute block rewards are
// roughly 780x smaller. The inflation RATE mechanics (rate bounds, phase decay,
// stake-ratio adjustment) are identical across networks; only the absolute reward
// amounts scale with supply. No code change is required here -- this is documented
// so testnet<->mainnet reward comparisons are not mistaken for a calculation bug.
// If testnet reward parity with mainnet is ever desired, update
// genesis/testnet.json to include the full tokenomics allocation.
func NewInflationModel(config *InflationConfig, initialSupply *big.Int) *InflationModel {
	if config == nil {
		config = DefaultInflationConfig()
	}

	return &InflationModel{
		config:       config,
		currentRate:  new(big.Int).Set(config.InitialRate),
		currentPhase: InflationPhaseHigh,
		totalSupply:  new(big.Int).Set(initialSupply),
		stakedSupply: new(big.Int),
	}
}

func (im *InflationModel) GetCurrentRate() *big.Int {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return new(big.Int).Set(im.currentRate)
}

func (im *InflationModel) GetCurrentPhase() InflationPhase {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.currentPhase
}

func (im *InflationModel) CalculateNewSupply(blockHeight uint64) *big.Int {
	im.mu.Lock()
	defer im.mu.Unlock()

	if blockHeight-im.lastAdjustment >= im.config.AdjustmentPeriod {
		im.adjustRate()
		im.lastAdjustment = blockHeight
		im.adjustmentCount++
	}

	annualRate := new(big.Int).Set(im.currentRate)
	// L20-005 FIX: use named constant instead of hardcoded magic number.
	blocksPerYear := big.NewInt(DefaultBlocksPerYear)
	blockReward := new(big.Int).Mul(im.totalSupply, annualRate)
	blockReward.Div(blockReward, big.NewInt(10000))
	blockReward.Div(blockReward, blocksPerYear)

	// QAU economic model: Genesis allocation of 20,000,000 QAU (20M), then unlimited
	// on-demand supply via QPOS inflation. There is NO maximum supply cap.
	// Block rewards are minted based on the inflation rate (currentRate)
	// and total staked supply, adjusting dynamically to maintain target
	// stake ratio. This is by design - QAU uses an elastic supply model.

	// R35-P3-ECON-8 NOTE (2026-07-29): InflationModel and StakingManager's
	// rewardPoolCap are DISCONNECTED. rewardPoolCap (20M QAU in staking.go)
	// only caps STAKING-layer rewards distributed via ProcessRewardClaimFromTx;
	// it does NOT cap inflation-layer block rewards minted here and distributed
	// via RewardDistributor.DistributeRewardAmount. EconomicsManager.ProcessBlock
	// mints inflation rewards and increments em.totalSupply without checking
	// any cap. This is acceptable because:
	//   1. QAU has an elastic supply model with no hard cap (by design).
	//   2. The inflation rate is adaptively bounded by [MinRate, MaxRate]
	//      (currently [50, 1000] bps = [0.5%, 10%]).
	//   3. StakingAPY=0 (staking-layer rewards disabled), so rewardPoolCap
	//      only gates legacy PendingRewards payouts, not new minting.
	// TODO: if a hard monetary cap is ever required, add a rewardPoolCap
	// field to InflationConfig and clamp blockReward here so inflation
	// respects the cap. This requires coordinating with StakingManager's
	// rewardPoolCap to avoid double-capping.

	// FIX: CalculateNewSupply is now a pure calculation — it returns the
	// newly minted block reward WITHOUT mutating im.totalSupply. The caller is
	// responsible for updating totalSupply separately (e.g. via SetTotalSupply /
	// UpdateTotalSupply). Previously this method mutated totalSupply as a hidden
	// side effect, which was surprising for a "Calculate" function (unlike the pure
	// CalculateInflationReward) and could double-count supply when the caller also
	// updated totalSupply.
	return blockReward
}

func (im *InflationModel) adjustRate() {
	if im.totalSupply.Sign() <= 0 {
		return
	}

	stakeRatio := im.calculateStakeRatio()

	// SECURITY FIX (L14-024): Validate stakedRatio is in [0, 100] (i.e., [0%, 100%]).
	// A negative stakedSupply or a stakedSupply exceeding totalSupply would produce
	// an invalid ratio, causing the inflation rate adjustment to behave erratically.
	// The ratio is stored as a percentage (0-100), so the valid range is [0, 100].
	if stakeRatio.Sign() < 0 || stakeRatio.Cmp(big.NewInt(100)) > 0 {
		return
	}

	targetRatio := im.config.TargetStakeRatio
	deviation := new(big.Int).Sub(stakeRatio, targetRatio)

	adjustment := new(big.Int).Mul(deviation, im.config.AdjustmentFactor)
	adjustment.Div(adjustment, big.NewInt(100))

	newRate := new(big.Int).Sub(im.currentRate, adjustment)

	// R46-CS-03 FIX: Explicitly clamp negative rates to MinRate before the
	// MinRate comparison. If MinRate is misconfigured to a negative value,
	// a negative newRate would propagate. This guard ensures non-negative.
	if newRate.Sign() < 0 {
		newRate.SetInt64(0)
	}
	if newRate.Cmp(im.config.MinRate) < 0 {
		newRate.Set(im.config.MinRate)
	}
	if newRate.Cmp(im.config.MaxRate) > 0 {
		newRate.Set(im.config.MaxRate)
	}

	decayedRate := new(big.Int).Mul(newRate, im.config.DecayFactor)
	decayedRate.Div(decayedRate, big.NewInt(1000))

	im.currentRate.Set(decayedRate)
	im.updatePhase()
}

func (im *InflationModel) calculateStakeRatio() *big.Int {
	if im.totalSupply.Sign() <= 0 {
		return big.NewInt(0)
	}

	ratio := new(big.Int).Mul(im.stakedSupply, big.NewInt(100))
	ratio.Div(ratio, im.totalSupply)
	return ratio
}

func (im *InflationModel) updatePhase() {
	rate := im.currentRate

	phases := make([]InflationPhase, 0, len(im.config.PhaseThresholds))
	for phase := range im.config.PhaseThresholds {
		phases = append(phases, phase)
	}
	sort.Slice(phases, func(i, j int) bool {
		return phases[i] < phases[j]
	})

	for _, phase := range phases {
		threshold := im.config.PhaseThresholds[phase]
		if rate.Cmp(threshold) >= 0 {
			im.currentPhase = phase
			return
		}
	}
	im.currentPhase = InflationPhaseStable
}

func (im *InflationModel) UpdateStakedSupply(staked *big.Int) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.stakedSupply.Set(staked)
}

func (im *InflationModel) UpdateTotalSupply(supply *big.Int) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.totalSupply.Set(supply)
}

// SetTotalSupply sets the total supply. It is used to sync the EconomicsManager's
// authoritative totalSupply back into the InflationModel so the two do not drift.
func (im *InflationModel) SetTotalSupply(ts *big.Int) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.totalSupply.Set(ts)
}

func (im *InflationModel) GetStakeRatio() *big.Int {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.calculateStakeRatio()
}

func (im *InflationModel) GetAdjustmentCount() uint64 {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.adjustmentCount
}

// GetTotalSupply returns the current tracked total supply.
func (im *InflationModel) GetTotalSupply() *big.Int {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return new(big.Int).Set(im.totalSupply)
}

// GetStakedSupply returns the current tracked staked supply.
func (im *InflationModel) GetStakedSupply() *big.Int {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return new(big.Int).Set(im.stakedSupply)
}

func (im *InflationModel) PredictRate(blocksAhead uint64) *big.Int {
	im.mu.RLock()
	defer im.mu.RUnlock()

	// L-4 FIX: Document the limitation of this prediction.
	// NOTE: This prediction is an UPPER BOUND estimate. It only applies the
	// decay factor (DecayFactor) and the MinRate floor. It does NOT account
	// for the stake-ratio adjustment that adjustRate() performs based on
	// (stakedSupply / totalSupply) deviation from TargetStakeRatio.
	// The actual future rate may be lower than this prediction if the stake
	// ratio rises above the target (which would trigger a downward adjustment).
	// Conversely, if the stake ratio falls below the target, the actual rate
	// could be higher. Callers requiring an accurate forecast must simulate
	// the full adjustRate() logic including stake-ratio feedback.
	predictedRate := new(big.Int).Set(im.currentRate)
	adjustments := blocksAhead / im.config.AdjustmentPeriod

	for i := uint64(0); i < adjustments && i < 100; i++ {
		decayedRate := new(big.Int).Mul(predictedRate, im.config.DecayFactor)
		decayedRate.Div(decayedRate, big.NewInt(1000))

		if decayedRate.Cmp(im.config.MinRate) < 0 {
			decayedRate.Set(im.config.MinRate)
		}
		predictedRate.Set(decayedRate)
	}

	return predictedRate
}
