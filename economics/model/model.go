// Quantaureum Node source, version 1.0.0.
// Package model provides a deterministic, side-effect-free economic model of
// QAU issuance, fee burn and net supply evolution.
//
// The package exists so that monetary-policy parameters can be evaluated
// offline — in unit tests, in the econsim CLI (cmd/econsim) and in design
// review — without booting a node or touching consensus state.
//
// # Layering
//
// This package sits at L3 (economics) and deliberately imports nothing from
// consensus (L5). It re-implements the base-reward arithmetic rather than
// calling into consensus, which would be a reverse dependency. To guarantee
// the two never drift, consensus/econ_model_parity_test.go asserts bit-exact
// equality between BaseRewardWei here and QPOS.CalculateBaseReward there.
//
// # Determinism
//
// All token arithmetic uses math/big integers with the same truncation order
// as the consensus implementation. float64 appears only in reporting helpers
// (APY, ratios) and never on a path that produces a token amount.
package model

import (
	"errors"
	"fmt"
	"math/big"
)

// Unit scale constants. QAU uses 18 decimals; the reward formula operates in
// gwei (1e9 wei) to mirror Ethereum's consensus layer, which is where the
// BaseRewardFactor calibration originates.
const (
	// WeiPerGwei is the wei-to-gwei divisor used by the reward formula.
	WeiPerGwei = 1_000_000_000
	// WeiPerQAU is the wei value of one whole QAU (18 decimals).
	WeiPerQAU = 1e18
)

// Reward-structure variants.
//
// The distinction matters because the live chain and the Ethereum
// specification disagree, and the whole point of this model is to quantify
// that gap.
type ProposerMode int

const (
	// ProposerPerSlotFullReward reproduces the CURRENT mainnet behavior
	// (consensus/epoch_rewards_census.go): every slot whose block was
	// attested credits its proposer one FULL base reward. With N validators
	// and 32 slots per epoch this makes the proposer share 32/(N+32) of all
	// issuance — 84% at N=6 — and couples total issuance to N.
	ProposerPerSlotFullReward ProposerMode = iota

	// ProposerWeightedSplit reproduces the ETHEREUM Altair specification:
	// total issuance for an epoch is the sum of every validator's base reward,
	// and that total is divided by fixed weights — PROPOSER_WEIGHT/
	// WEIGHT_DENOMINATOR (8/64) to proposers, the remainder to attesters.
	// Total issuance becomes independent of the validator count.
	//
	// Note this is NOT "attester total / 8". Altair's process_attestation
	// derives the proposer cut as attester_total * PW/(WD-PW) = attester/7,
	// which is the same thing as 8/64 of the grand total. The pre-EM-2
	// consensus constant ProposerRewardQuotient = 8 was a phase0-era name for
	// a different quantity and must not be reused verbatim (it has since been
	// deleted in favor of ProposerWeight/WeightDenominator).
	ProposerWeightedSplit
)

// Params is a complete, self-contained monetary-policy parameter set.
//
// The zero value is not usable; construct via MainnetParams,
// PreEM2MainnetParams, EthereumAltairParams or a named preset, then override
// fields.
type Params struct {
	// BaseRewardFactor is Ethereum's BASE_REWARD_FACTOR (F). Live chain: 2.
	// Ethereum Altair: 64.
	BaseRewardFactor int64

	// BaseRewardsPerEpoch is the trailing divisor of the base-reward formula.
	// Ethereum phase0 used BASE_REWARDS_PER_EPOCH = 4; Altair folded it into
	// the weight table and effectively uses 1. The live chain still carries
	// the phase0 divisor of 4.
	BaseRewardsPerEpoch int64

	// ProposerWeight and WeightDenominator define the proposer's cut of total
	// issuance in ProposerWeightedSplit mode. Ethereum Altair uses
	// PROPOSER_WEIGHT = 8 and WEIGHT_DENOMINATOR = 64, i.e. 12.5%.
	ProposerWeight    int64
	WeightDenominator int64

	// AttestationsPerEpoch is how many base rewards a single validator earns
	// per epoch for attesting. The live chain pays exactly 1 (enforced by the
	// CONS-R8-001 dedup). Before that fix it effectively paid up to
	// SlotsPerEpoch, which is what the pre-EM-2 BaseRewardFactor=2 calibration
	// claim assumed (see PreEM2MainnetParams).
	AttestationsPerEpoch int64

	// SlotsPerEpoch and EpochsPerYear describe chain timing.
	// Live mainnet: 32 slots x 12 s = 384 s per epoch => 82,125 epochs/year.
	SlotsPerEpoch int64
	EpochsPerYear int64

	// Proposer selects the reward-distribution structure.
	Proposer ProposerMode
}

// Validate reports whether p can be used for a computation.
func (p Params) Validate() error {
	switch {
	case p.BaseRewardFactor <= 0:
		return errors.New("model: BaseRewardFactor must be > 0")
	case p.BaseRewardsPerEpoch <= 0:
		return errors.New("model: BaseRewardsPerEpoch must be > 0")
	case p.AttestationsPerEpoch <= 0:
		return errors.New("model: AttestationsPerEpoch must be > 0")
	case p.SlotsPerEpoch <= 0:
		return errors.New("model: SlotsPerEpoch must be > 0")
	case p.EpochsPerYear <= 0:
		return errors.New("model: EpochsPerYear must be > 0")
	case p.Proposer == ProposerWeightedSplit && p.WeightDenominator <= 0:
		return errors.New("model: WeightDenominator must be > 0 in weighted-split mode")
	case p.Proposer == ProposerWeightedSplit && (p.ProposerWeight <= 0 || p.ProposerWeight >= p.WeightDenominator):
		return errors.New("model: ProposerWeight must be in (0, WeightDenominator)")
	}
	return nil
}

// MainnetParams returns the parameter set that reproduces the behavior running
// on QAU mainnet (chainId 1668) under EM-2.
//
// Reference: consensus/block.go (BaseRewardFactor=31, BaseRewardsPerEpoch=1,
// ProposerWeight=8, WeightDenominator=64) and
// consensus/epoch_rewards_census.go (attester keeps 56/64 of its base reward,
// 8/64 accrues to a pool distributed across proposed slots).
//
// consensus/econ_model_parity_test.go asserts these values equal the constants
// actually compiled into consensus, so this function cannot silently drift.
func MainnetParams() Params {
	return Params{
		BaseRewardFactor:     31,
		BaseRewardsPerEpoch:  1,
		ProposerWeight:       8,
		WeightDenominator:    64,
		AttestationsPerEpoch: 1,
		SlotsPerEpoch:        32,
		EpochsPerYear:        82_125,
		Proposer:             ProposerWeightedSplit,
	}
}

// PreEM2MainnetParams returns the parameter set mainnet ran BEFORE the EM-2
// issuance reform (i.e. up to and including release r105).
//
// Kept because it is the only way to reproduce the historically observed
// 1.9e16 wei/epoch, which is the anchor that exposed a 1000x unit misreading
// in the first draft of the economic model. Do not use it to describe the
// current chain.
//
// Reference at that time: BaseRewardFactor=2, a single combined divisor of 4,
// one attester reward per validator per epoch, and one FULL base reward per
// proposed slot (which gave proposers 32/(N+32) of all issuance).
func PreEM2MainnetParams() Params {
	return Params{
		BaseRewardFactor:     2,
		BaseRewardsPerEpoch:  4,
		ProposerWeight:       8, // declared as ProposerRewardQuotient but unused then
		WeightDenominator:    64,
		AttestationsPerEpoch: 1,
		SlotsPerEpoch:        32,
		EpochsPerYear:        82_125,
		Proposer:             ProposerPerSlotFullReward,
	}
}

// LegacyPreDedupParams returns the parameter set that the stale
// BaseRewardFactor=2 calibration comment assumed: one base reward per
// validator per SLOT. Retained so the econsim CLI can demonstrate that the
// CONS-R8-001 dedup fix cut issuance by SlotsPerEpoch without recalibrating F.
func LegacyPreDedupParams() Params {
	p := PreEM2MainnetParams()
	p.AttestationsPerEpoch = p.SlotsPerEpoch
	return p
}

// EthereumAltairParams returns Ethereum's post-Altair monetary parameters,
// unchanged. Used as a ground-truth fixture: fed 30M ETH of stake it must
// reproduce the ~3% APR observed on the beacon chain.
func EthereumAltairParams() Params {
	return Params{
		BaseRewardFactor:     64,
		BaseRewardsPerEpoch:  1, // Altair folded phase0's /4 into the weight table
		ProposerWeight:       8,
		WeightDenominator:    64,
		AttestationsPerEpoch: 1,
		SlotsPerEpoch:        32,
		EpochsPerYear:        82_125,
		Proposer:             ProposerWeightedSplit,
	}
}

// BaseRewardWei returns the per-epoch base reward for a validator holding
// stakeWei out of totalStakeWei, in wei.
//
// The arithmetic mirrors consensus/epoch.go:CalculateBaseReward exactly,
// including the order of truncations:
//
//	stakeGwei  = stakeWei / 1e9                      (truncating)
//	totalGwei  = totalStakeWei / 1e9                 (truncating)
//	rewardGwei = stakeGwei * F / (isqrt(totalGwei) * D)   (single division)
//	reward     = rewardGwei * 1e9
//
// Reproducing the truncation order matters: two sequential divisions would
// yield a smaller result than one combined division whenever the intermediate
// remainder is nonzero (see the CONS-006 / R46-CS-05 notes in consensus).
func BaseRewardWei(stakeWei, totalStakeWei *big.Int, p Params) *big.Int {
	if stakeWei == nil || totalStakeWei == nil {
		return big.NewInt(0)
	}
	if stakeWei.Sign() <= 0 || totalStakeWei.Sign() <= 0 {
		return big.NewInt(0)
	}

	gwei := big.NewInt(WeiPerGwei)
	stakeGwei := new(big.Int).Div(stakeWei, gwei)
	totalGwei := new(big.Int).Div(totalStakeWei, gwei)
	if totalGwei.Sign() == 0 {
		return big.NewInt(0)
	}

	sqrtTotal := new(big.Int).Sqrt(totalGwei)
	if sqrtTotal.Sign() == 0 {
		sqrtTotal = big.NewInt(1)
	}

	rewardGwei := new(big.Int).Mul(stakeGwei, big.NewInt(p.BaseRewardFactor))
	divisor := new(big.Int).Mul(sqrtTotal, big.NewInt(p.BaseRewardsPerEpoch))
	rewardGwei.Div(rewardGwei, divisor)

	return rewardGwei.Mul(rewardGwei, gwei)
}

// Issuance is the per-epoch issuance decomposition, all amounts in wei.
type Issuance struct {
	Attester *big.Int
	Proposer *big.Int
	Total    *big.Int
}

// ProposerShare returns the proposer fraction of total issuance.
// Returns 0 when total issuance is zero.
func (i Issuance) ProposerShare() float64 {
	if i.Total == nil || i.Total.Sign() == 0 {
		return 0
	}
	return ratio(i.Proposer, i.Total)
}

// EpochIssuance computes issuance for one epoch given the per-validator
// stakes, in wei.
//
// In ProposerPerSlotFullReward mode the proposer component is SlotsPerEpoch
// full base rewards. The model charges the MEAN base reward per slot, which is
// exact when all stakes are equal (the mainnet case: 6 x 6,000 QAU) and a
// close approximation otherwise. Callers needing per-slot fidelity under
// unequal stakes must supply a proposer schedule, which is out of scope for a
// monetary-policy model.
//
// In ProposerWeightedSplit mode total issuance is the sum of base rewards and
// the proposer cut is carved OUT of that total, so issuance does not grow when
// the proposer share is raised.
func EpochIssuance(stakesWei []*big.Int, p Params) (Issuance, error) {
	zero := Issuance{Attester: big.NewInt(0), Proposer: big.NewInt(0), Total: big.NewInt(0)}
	if err := p.Validate(); err != nil {
		return zero, err
	}
	if len(stakesWei) == 0 {
		return zero, nil
	}

	total := big.NewInt(0)
	for _, s := range stakesWei {
		if s == nil || s.Sign() < 0 {
			return zero, errors.New("model: stake must be non-nil and non-negative")
		}
		total.Add(total, s)
	}
	if total.Sign() == 0 {
		return zero, nil
	}

	// Attester component: AttestationsPerEpoch base rewards per validator.
	attester := big.NewInt(0)
	baseSum := big.NewInt(0) // sum of single base rewards, used for the mean
	for _, s := range stakesWei {
		b := BaseRewardWei(s, total, p)
		baseSum.Add(baseSum, b)
		attester.Add(attester, new(big.Int).Mul(b, big.NewInt(p.AttestationsPerEpoch)))
	}

	switch p.Proposer {
	case ProposerWeightedSplit:
		// Total issuance is the base-reward sum; weights only split it.
		totalIssuance := attester
		proposer := new(big.Int).Mul(totalIssuance, big.NewInt(p.ProposerWeight))
		proposer.Div(proposer, big.NewInt(p.WeightDenominator))
		return Issuance{
			Attester: new(big.Int).Sub(totalIssuance, proposer),
			Proposer: proposer,
			Total:    totalIssuance,
		}, nil

	case ProposerPerSlotFullReward:
		meanBase := new(big.Int).Div(baseSum, big.NewInt(int64(len(stakesWei))))
		proposer := new(big.Int).Mul(meanBase, big.NewInt(p.SlotsPerEpoch))
		return Issuance{
			Attester: attester,
			Proposer: proposer,
			Total:    new(big.Int).Add(attester, proposer),
		}, nil

	default:
		return zero, fmt.Errorf("model: unknown ProposerMode %d", p.Proposer)
	}
}

// UniformStakes builds a slice of n equal stakes of stakeEachWei.
func UniformStakes(n int, stakeEachWei *big.Int) []*big.Int {
	if n <= 0 || stakeEachWei == nil {
		return nil
	}
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = new(big.Int).Set(stakeEachWei)
	}
	return out
}

// AnnualIssuanceWei scales one epoch of issuance to a year.
func AnnualIssuanceWei(epochIssuance *big.Int, p Params) *big.Int {
	if epochIssuance == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Mul(epochIssuance, big.NewInt(p.EpochsPerYear))
}

// StakingAPY returns annual issuance divided by total stake, as a fraction
// (0.05 == 5%). Reporting helper only; never feeds a token amount.
func StakingAPY(annualIssuanceWei, totalStakeWei *big.Int) float64 {
	return ratio(annualIssuanceWei, totalStakeWei)
}

// FeeModel describes on-chain fee activity for burn accounting.
//
// Under the strict-Ethereum design the base fee is burned in full and the
// priority fee (tip) goes to the proposer, so only the base fee affects net
// supply. Tips are recorded because they matter to validator revenue.
type FeeModel struct {
	TxPerDay    int64 // transactions per day
	GasPerTx    int64 // mean gas per transaction (21,000 for a bare transfer)
	BaseFeeGwei int64 // base fee per gas, in gwei; burned in full
	TipGwei     int64 // priority fee per gas, in gwei; paid to the proposer
}

// DailyBurnWei returns the wei permanently removed from supply per day.
func (f FeeModel) DailyBurnWei() *big.Int {
	return feeWei(f.TxPerDay, f.GasPerTx, f.BaseFeeGwei)
}

// DailyTipWei returns the wei per day transferred to proposers as tips.
// Tips are a transfer, not issuance, so they do not change total supply.
func (f FeeModel) DailyTipWei() *big.Int {
	return feeWei(f.TxPerDay, f.GasPerTx, f.TipGwei)
}

// AnnualBurnWei returns the wei permanently removed from supply per year.
func (f FeeModel) AnnualBurnWei() *big.Int {
	return new(big.Int).Mul(f.DailyBurnWei(), big.NewInt(365))
}

func feeWei(txPerDay, gasPerTx, priceGwei int64) *big.Int {
	if txPerDay <= 0 || gasPerTx <= 0 || priceGwei <= 0 {
		return big.NewInt(0)
	}
	gas := new(big.Int).Mul(big.NewInt(txPerDay), big.NewInt(gasPerTx))
	wei := new(big.Int).Mul(gas, big.NewInt(priceGwei))
	return wei.Mul(wei, big.NewInt(WeiPerGwei))
}

// ratio computes a/b as a float64 for reporting. Returns 0 when b is zero.
func ratio(a, b *big.Int) float64 {
	if a == nil || b == nil || b.Sign() == 0 {
		return 0
	}
	q := new(big.Float).Quo(new(big.Float).SetInt(a), new(big.Float).SetInt(b))
	f, _ := q.Float64()
	return f
}

// QAU converts wei to whole QAU as a float64, for reporting only.
func QAU(wei *big.Int) float64 {
	if wei == nil {
		return 0
	}
	q := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(WeiPerQAU))
	f, _ := q.Float64()
	return f
}

// WeiFromQAU converts a whole number of QAU to wei exactly.
func WeiFromQAU(qau int64) *big.Int {
	w := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	return w.Mul(w, big.NewInt(qau))
}

// ---------------------------------------------------------------------------
// Per-validator attribution
// ---------------------------------------------------------------------------

// Attribution is one epoch's issuance decomposed the way a consensus
// implementation must actually pay it: per validator, with integer truncation
// applied at each validator rather than once at the pool level.
//
// Why this exists separately from Issuance: EpochIssuance answers the monetary
// question ("how much does the protocol emit this epoch"), and it is free to
// divide the pool once. A consensus implementation cannot do that — it credits
// individual balances, so it must truncate per validator. The two therefore
// disagree by a small dust amount, and the difference has to be a documented,
// bounded quantity instead of a surprise discovered during implementation.
//
// DustWei is exactly that bound: pool total minus everything actually credited.
type Attribution struct {
	// AttesterWei[i] is what validator i receives for attesting, index-aligned
	// with the stakes passed to EpochIssuanceAttributed.
	AttesterWei []*big.Int
	// ProposerPoolWei is the total to be split among the epoch's proposers.
	// How it is split across slots is a consensus concern, not a monetary one.
	ProposerPoolWei *big.Int
	// PoolTotalWei is the sum of base rewards, i.e. what EpochIssuance reports
	// as Total in ProposerWeightedSplit mode.
	PoolTotalWei *big.Int
	// CreditedWei is the sum of AttesterWei plus ProposerPoolWei.
	CreditedWei *big.Int
	// DustWei is PoolTotalWei - CreditedWei: emission lost to per-validator
	// truncation and therefore never created.
	//
	// On this chain it is exactly ZERO, and that is a property worth stating
	// rather than a coincidence to rely on blindly: base rewards are produced in
	// gwei granularity (BaseRewardWei multiplies back up by 1e9), and 64 divides
	// 1e9 evenly (1e9 = 2^9 x 1953125), so splitting a gwei-granular amount by
	// x/64 leaves no remainder. A consensus port can therefore be bit-exact with
	// this package instead of merely close.
	//
	// If WeightDenominator is ever changed to a value that does not divide 1e9,
	// dust becomes non-zero but stays strictly below WeightDenominator wei per
	// validator (one remainder per truncation, two truncations per validator).
	DustWei *big.Int
}

// EpochIssuanceAttributed decomposes ProposerWeightedSplit issuance per
// validator, mirroring Altair: each validator's base reward is split into its
// own attester share ((WD-PW)/WD) and a contribution to the proposer pool
// (PW/WD), both truncated at the validator.
//
// This is the shape a consensus port must implement to stay bit-comparable with
// this package; see consensus/econ_model_parity_test.go.
//
// Returns an error in ProposerPerSlotFullReward mode: the live per-slot rule has
// no per-validator attester attribution to speak of, and pretending otherwise
// would invite a wrong port.
func EpochIssuanceAttributed(stakesWei []*big.Int, p Params) (Attribution, error) {
	var out Attribution
	if err := p.Validate(); err != nil {
		return out, err
	}
	if p.Proposer != ProposerWeightedSplit {
		return out, errors.New("model: EpochIssuanceAttributed requires ProposerWeightedSplit")
	}

	total := big.NewInt(0)
	for _, s := range stakesWei {
		if s == nil || s.Sign() < 0 {
			return out, errors.New("model: stake must be non-nil and non-negative")
		}
		total.Add(total, s)
	}

	out.AttesterWei = make([]*big.Int, len(stakesWei))
	out.ProposerPoolWei = big.NewInt(0)
	out.PoolTotalWei = big.NewInt(0)
	out.CreditedWei = big.NewInt(0)

	pw := big.NewInt(p.ProposerWeight)
	wd := big.NewInt(p.WeightDenominator)

	for i, s := range stakesWei {
		base := BaseRewardWei(s, total, p)
		out.PoolTotalWei.Add(out.PoolTotalWei, base)

		toProposer := new(big.Int).Mul(base, pw)
		toProposer.Div(toProposer, wd)

		toSelf := new(big.Int).Mul(base, new(big.Int).Sub(wd, pw))
		toSelf.Div(toSelf, wd)

		out.AttesterWei[i] = toSelf
		out.ProposerPoolWei.Add(out.ProposerPoolWei, toProposer)
		out.CreditedWei.Add(out.CreditedWei, toSelf)
	}

	out.CreditedWei.Add(out.CreditedWei, out.ProposerPoolWei)
	out.DustWei = new(big.Int).Sub(out.PoolTotalWei, out.CreditedWei)
	return out, nil
}

// ProposerShare returns the proposer pool as a fraction of the pool total.
func (a Attribution) ProposerShare() float64 {
	if a.PoolTotalWei == nil || a.PoolTotalWei.Sign() == 0 {
		return 0
	}
	return ratio(a.ProposerPoolWei, a.PoolTotalWei)
}
