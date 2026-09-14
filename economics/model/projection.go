// Quantaureum Node source, version 1.0.0.
package model

import (
	"errors"
	"math"
	"math/big"

	"github.com/quantaureum/qau/params"
)

// FeeMarket models the EIP-1559 base fee as a function of demand rather than
// taking it as a fixed nominal input.
//
// Why this exists: a constant gwei base fee multiplied by a compounding
// transaction count manufactures deflation that cannot happen. Two hard facts
// bound the real thing, and this type encodes exactly those two and nothing
// more:
//
//  1. Below the gas target the 1559 controller lowers the base fee every block
//     (-12.5% max per block), so a chain that is not full sits at the floor.
//     On this chain the floor is params.MinGasPrice (1 gwei): the txpool will
//     not accept anything cheaper, so the base fee cannot settle below it.
//  2. Above the gas target throughput is capped by the block gas limit. Extra
//     demand does not burn more gas; it queues or gets priced out. So annual
//     burn can never exceed blocksPerYear * gasLimit * baseFee.
//
// What is NOT modeled: the price at which congestion clears. Once demand
// exceeds the target, the base fee is whatever rations capacity, and that
// depends on users' fiat willingness to pay — outside this model. The caller
// must supply it via CongestionBaseFeeGwei, and it is reported as the
// assumption it is.
type FeeMarket struct {
	// GasTargetPerBlock is the 1559 target (BlockGasLimit / ElasticityMultiplier).
	GasTargetPerBlock int64
	// GasLimitPerBlock hard-caps gas actually consumed per block.
	GasLimitPerBlock int64
	// BlocksPerYear is SlotsPerEpoch * EpochsPerYear.
	BlocksPerYear int64
	// MinBaseFeeGwei is the floor the controller decays to on an under-full chain.
	MinBaseFeeGwei int64
	// CongestionBaseFeeGwei is the assumed clearing base fee once demand meets
	// or exceeds the target. Ignored while the chain is under target.
	CongestionBaseFeeGwei int64
}

// MainnetFeeMarket returns the fee market implied by the live chain constants
// (params.BlockGasLimit, params.ElasticityMultiplier, params.MinGasPrice) and
// the timing in p. congestionBaseFeeGwei is the caller's assumption for the
// saturated regime; values below the floor are raised to the floor.
// audit-remediation: reviewed 2026-09-11 — int64 arithmetic here operates on
// small protocol constants (BlockGasLimit, ElasticityMultiplier, SlotsPerEpoch
// are single-digit to low-thousands values); overflow would require inputs
// ~1e18× larger than any realistic parameter set, and Validate() bounds them.
func MainnetFeeMarket(p Params, congestionBaseFeeGwei int64) FeeMarket {
	floor := int64(params.MinGasPrice / WeiPerGwei)
	if floor < 1 {
		floor = 1
	}
	if congestionBaseFeeGwei < floor {
		congestionBaseFeeGwei = floor
	}
	return FeeMarket{
		// audit-remediation: reviewed 2026-09-11 — protocol constants only
		// (BlockGasLimit 20M, ElasticityMultiplier 2, SlotsPerEpoch 12,
		// EpochsPerYear ≤ 52_560): products stay ≤ ~1e9, far below int64 max.
		GasTargetPerBlock:     params.BlockGasLimit / params.ElasticityMultiplier,
		GasLimitPerBlock:      params.BlockGasLimit,
		BlocksPerYear:         p.SlotsPerEpoch * p.EpochsPerYear,
		MinBaseFeeGwei:        floor,
		CongestionBaseFeeGwei: congestionBaseFeeGwei,
	}
}

// BurnAtDemand returns the annual burn, the base fee that regime implies, and
// utilization against the gas target (1.0 == exactly at target).
func (m FeeMarket) BurnAtDemand(txPerDay, gasPerTx int64) (*big.Int, int64, float64) {
	if txPerDay <= 0 || gasPerTx <= 0 || m.BlocksPerYear <= 0 || m.GasTargetPerBlock <= 0 {
		return big.NewInt(0), m.MinBaseFeeGwei, 0
	}

	demandGas := new(big.Int).Mul(big.NewInt(txPerDay), big.NewInt(gasPerTx))
	demandGas.Mul(demandGas, big.NewInt(365))
	targetGas := new(big.Int).Mul(big.NewInt(m.BlocksPerYear), big.NewInt(m.GasTargetPerBlock))
	util := ratio(demandGas, targetGas)

	gasBurned := demandGas
	baseFee := m.MinBaseFeeGwei
	if util >= 1 {
		baseFee = m.CongestionBaseFeeGwei
		limitGas := new(big.Int).Mul(big.NewInt(m.BlocksPerYear), big.NewInt(m.GasLimitPerBlock))
		if gasBurned.Cmp(limitGas) > 0 {
			gasBurned = limitGas
		}
	}

	burn := new(big.Int).Mul(gasBurned, big.NewInt(baseFee))
	burn.Mul(burn, big.NewInt(WeiPerGwei))
	return burn, baseFee, util
}

// VestingTranche is one linear-release allocation held by a LinearVesting
// contract. Tokens inside a tranche are already issued (they are part of the
// genesis 20M) but are neither liquid nor stakeable until released, so they
// constrain how large total stake can realistically become in early years.
//
// Release follows the deployed LinearVesting semantics (see R40.G): value
// accrues linearly from the deployment timestamp over DurationYears, and
// nothing is claimable before CliffYears have elapsed.
type VestingTranche struct {
	Name          string
	TotalWei      *big.Int
	CliffYears    float64
	DurationYears float64
}

// LockedAtWei returns the still-locked portion of the tranche at year t.
func (v VestingTranche) LockedAtWei(t float64) *big.Int {
	if v.TotalWei == nil {
		return big.NewInt(0)
	}
	if t < v.CliffYears || v.DurationYears <= 0 {
		return new(big.Int).Set(v.TotalWei)
	}
	if t >= v.DurationYears {
		return big.NewInt(0)
	}
	// locked = total * (duration - t) / duration, computed in integer wei with
	// a 1e9 fixed-point scale so the result stays deterministic.
	const scale = 1_000_000_000
	remaining := int64(math.Round((v.DurationYears - t) / v.DurationYears * scale))
	if remaining <= 0 {
		return big.NewInt(0)
	}
	locked := new(big.Int).Mul(v.TotalWei, big.NewInt(remaining))
	return locked.Div(locked, big.NewInt(scale))
}

// MainnetVesting returns the six LinearVesting tranches deployed on mainnet
// (R40-DEPLOY, 15,000,000 QAU total).
func MainnetVesting() []VestingTranche {
	return []VestingTranche{
		{Name: "Team", TotalWei: WeiFromQAU(4_000_000), CliffYears: 1, DurationYears: 4},
		{Name: "StakingIncentive", TotalWei: WeiFromQAU(4_000_000), CliffYears: 0, DurationYears: 5},
		{Name: "DevFund", TotalWei: WeiFromQAU(2_000_000), CliffYears: 1, DurationYears: 4},
		{Name: "Ecosystem", TotalWei: WeiFromQAU(2_000_000), CliffYears: 0, DurationYears: 4},
		{Name: "Foundation", TotalWei: WeiFromQAU(2_000_000), CliffYears: 1, DurationYears: 4},
		{Name: "Security", TotalWei: WeiFromQAU(1_000_000), CliffYears: 0, DurationYears: 3},
	}
}

// Scenario is a fully specified multi-year simulation input.
type Scenario struct {
	// Params is the monetary policy under test.
	Params Params

	// Years is the simulation horizon.
	Years int

	// InitialSupplyWei is total supply at t=0 (mainnet genesis: 20,000,000 QAU).
	InitialSupplyWei *big.Int

	// Vesting lists allocations that are issued but locked. Pass nil to treat
	// the entire supply as liquid.
	Vesting []VestingTranche

	// StakeRatioOfFloat is the fraction of the LIQUID (unlocked) supply that
	// is staked. Staking against locked vesting balances is not possible on
	// chain, so this ratio is deliberately taken against float rather than
	// against total supply.
	StakeRatioOfFloat float64

	// StakePerValidatorWei sets the implied validator count
	// (stake / stakePerValidator). Mainnet minimum is 6,000 QAU.
	StakePerValidatorWei *big.Int

	// MinValidators floors the implied validator count. Mainnet runs 6.
	MinValidators int

	// Fees describes year-1 fee activity in nominal terms.
	//
	// Caution: a fixed nominal BaseFeeGwei combined with FeeGrowthPerYear
	// compounds into an artificial deflationary spiral over long horizons,
	// because real fee markets price gas against fiat value rather than token
	// count — as supply shrinks and the token appreciates, the gwei base fee
	// falls. For horizons beyond roughly five years prefer
	// BurnAsFractionOfSupply.
	Fees FeeModel

	// FeeGrowthPerYear multiplies transaction volume each year
	// (0.5 == +50%/year). Applied to TxPerDay only, and ignored when
	// BurnAsFractionOfSupply is set.
	FeeGrowthPerYear float64

	// BurnAsFractionOfSupply, when greater than zero, replaces the nominal fee
	// calculation with an annual burn of supply * fraction. This is the
	// standard way to reason about EIP-1559 in the long run ("burn runs at X%
	// of supply per year") and is immune to the nominal-price artifact
	// described above.
	BurnAsFractionOfSupply float64

	// Fee1559, when non-nil, derives the base fee from demand versus the gas
	// target instead of trusting Fees.BaseFeeGwei — see FeeMarket. Ignored when
	// BurnAsFractionOfSupply is set.
	Fee1559 *FeeMarket
}

// YearRow is one simulated year.
type YearRow struct {
	Year        int
	Validators  int
	SupplyWei   *big.Int // total supply at END of year
	FloatWei    *big.Int // liquid (unlocked) supply during the year
	StakeWei    *big.Int
	IssuanceWei *big.Int // gross issuance during the year
	BurnWei     *big.Int // base fee burned during the year
	TipWei      *big.Int // tips paid to proposers (transfer, not issuance)
	NetWei      *big.Int // issuance - burn (can be negative)

	StakingAPY        float64  // gross issuance / stake
	GrossInflation    float64  // gross issuance / supply at start of year
	NetInflation      float64  // net / supply at start of year
	ValidatorRevWei   *big.Int // issuance + tips, per validator
	SecurityBudgetWei *big.Int // issuance + tips (total paid for security)

	// BaseFeeGwei and Utilization are populated only in the Fee1559 regime:
	// the base fee the demand level implies, and demand over the gas target.
	BaseFeeGwei int64
	Utilization float64
}

// Run executes the scenario and returns one row per year.
//
// The model is intentionally coarse-grained at the year level: issuance is
// computed from the year's stake level and multiplied by EpochsPerYear, rather
// than iterating 82,125 epochs. Because issuance is a pure function of stake
// and stake is held constant within a year, the two are equivalent up to
// intra-year compounding, which is immaterial at these rates.
func (s Scenario) Run() ([]YearRow, error) {
	if err := s.Params.Validate(); err != nil {
		return nil, err
	}
	if s.Years <= 0 {
		return nil, errors.New("model: Years must be > 0")
	}
	if s.InitialSupplyWei == nil || s.InitialSupplyWei.Sign() <= 0 {
		return nil, errors.New("model: InitialSupplyWei must be > 0")
	}
	if s.StakePerValidatorWei == nil || s.StakePerValidatorWei.Sign() <= 0 {
		return nil, errors.New("model: StakePerValidatorWei must be > 0")
	}
	if s.StakeRatioOfFloat < 0 || s.StakeRatioOfFloat > 1 {
		return nil, errors.New("model: StakeRatioOfFloat must be in [0,1]")
	}

	supply := new(big.Int).Set(s.InitialSupplyWei)
	rows := make([]YearRow, 0, s.Years)
	txPerDay := float64(s.Fees.TxPerDay)

	for y := 1; y <= s.Years; y++ {
		t := float64(y - 1)

		locked := big.NewInt(0)
		for _, v := range s.Vesting {
			locked.Add(locked, v.LockedAtWei(t))
		}
		float0 := new(big.Int).Sub(supply, locked)
		if float0.Sign() < 0 {
			float0 = big.NewInt(0)
		}

		stake := scaleWei(float0, s.StakeRatioOfFloat)
		validators := 0
		if stake.Sign() > 0 {
			validators = int(new(big.Int).Div(stake, s.StakePerValidatorWei).Int64())
		}
		if validators < s.MinValidators {
			validators = s.MinValidators
		}
		if validators < 1 {
			validators = 1
		}
		// Snap stake to the validator grid so issuance and per-validator
		// revenue stay mutually consistent.
		stake = new(big.Int).Mul(s.StakePerValidatorWei, big.NewInt(int64(validators)))

		iss, err := EpochIssuance(UniformStakes(validators, s.StakePerValidatorWei), s.Params)
		if err != nil {
			return nil, err
		}
		annualIssuance := AnnualIssuanceWei(iss.Total, s.Params)

		fees := s.Fees
		fees.TxPerDay = int64(txPerDay)
		var annualBurn *big.Int
		var baseFeeGwei int64
		var utilization float64
		switch {
		case s.BurnAsFractionOfSupply > 0:
			annualBurn = scaleWei(supply, s.BurnAsFractionOfSupply)
		case s.Fee1559 != nil:
			annualBurn, baseFeeGwei, utilization = s.Fee1559.BurnAtDemand(fees.TxPerDay, fees.GasPerTx)
		default:
			annualBurn = fees.AnnualBurnWei()
		}
		// Fees are paid out of liquid balances, so a year cannot burn more than
		// the float. Without this clamp an aggressive usage assumption drives
		// supply negative and every downstream ratio becomes meaningless.
		if annualBurn.Cmp(float0) > 0 {
			annualBurn = new(big.Int).Set(float0)
		}
		annualTip := new(big.Int).Mul(fees.DailyTipWei(), big.NewInt(365))

		net := new(big.Int).Sub(annualIssuance, annualBurn)
		startSupply := new(big.Int).Set(supply)
		supply = new(big.Int).Add(supply, net)
		if supply.Sign() < 0 {
			supply = big.NewInt(0)
		}

		securityBudget := new(big.Int).Add(annualIssuance, annualTip)
		perValidator := new(big.Int).Div(securityBudget, big.NewInt(int64(validators)))

		rows = append(rows, YearRow{
			Year:              y,
			Validators:        validators,
			SupplyWei:         new(big.Int).Set(supply),
			FloatWei:          float0,
			StakeWei:          stake,
			IssuanceWei:       annualIssuance,
			BurnWei:           annualBurn,
			TipWei:            annualTip,
			NetWei:            net,
			StakingAPY:        StakingAPY(annualIssuance, stake),
			GrossInflation:    ratio(annualIssuance, startSupply),
			NetInflation:      ratio(net, startSupply),
			ValidatorRevWei:   perValidator,
			SecurityBudgetWei: securityBudget,
			BaseFeeGwei:       baseFeeGwei,
			Utilization:       utilization,
		})

		txPerDay *= 1 + s.FeeGrowthPerYear
	}
	return rows, nil
}

// scaleWei multiplies a wei amount by a float fraction using a 1e9
// fixed-point intermediate, keeping the result an exact integer.
func scaleWei(v *big.Int, f float64) *big.Int {
	if v == nil || f <= 0 {
		return big.NewInt(0)
	}
	const scale = 1_000_000_000
	num := int64(math.Round(f * scale))
	if num <= 0 {
		return big.NewInt(0)
	}
	out := new(big.Int).Mul(v, big.NewInt(num))
	return out.Div(out, big.NewInt(scale))
}

// SolveBaseRewardFactor finds the smallest BaseRewardFactor that achieves at
// least targetAPY at the given total stake, holding all other parameters
// fixed. Returns an error when no factor in [1, maxFactor] suffices.
//
// Search is a binary search over F, valid because issuance is monotonically
// non-decreasing in F.
// audit-remediation: reviewed 2026-09-11 — division operands are validated
// Sign() > 0 at function entry; the mid computation cannot overflow because
// maxFactor is bounded (≤ 1e6 default, explicit input otherwise) and lo/high
// are derived from it. big.Int paths (EpochIssuance) do the heavy math.
func SolveBaseRewardFactor(p Params, totalStakeWei, stakePerValidatorWei *big.Int, targetAPY float64, maxFactor int64) (int64, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	if totalStakeWei == nil || totalStakeWei.Sign() <= 0 {
		return 0, errors.New("model: totalStakeWei must be > 0")
	}
	if stakePerValidatorWei == nil || stakePerValidatorWei.Sign() <= 0 {
		return 0, errors.New("model: stakePerValidatorWei must be > 0")
	}
	if targetAPY <= 0 {
		return 0, errors.New("model: targetAPY must be > 0")
	}
	if maxFactor <= 0 {
		maxFactor = 1_000_000
	}

	n := int(new(big.Int).Div(totalStakeWei, stakePerValidatorWei).Int64())
	if n < 1 {
		n = 1
	}
	stakes := UniformStakes(n, stakePerValidatorWei)
	actualStake := new(big.Int).Mul(stakePerValidatorWei, big.NewInt(int64(n)))

	apyAt := func(f int64) (float64, error) {
		q := p
		q.BaseRewardFactor = f
		iss, err := EpochIssuance(stakes, q)
		if err != nil {
			return 0, err
		}
		return StakingAPY(AnnualIssuanceWei(iss.Total, q), actualStake), nil
	}

	hi, err := apyAt(maxFactor)
	if err != nil {
		return 0, err
	}
	if hi < targetAPY {
		return 0, errors.New("model: targetAPY unreachable within maxFactor")
	}

	lo, high := int64(1), maxFactor
	for lo < high {
		// Division-by-zero safety: high > lo is the loop invariant, so the
		// divisor (high-lo) is strictly positive — guarded by this check.
		// (high-lo)/2 ≤ maxFactor/2 ≤ 5e5: no int64 overflow either.
		span := high - lo
		if span == 0 {
			break // unreachable given lo < high; defensive
		}
		mid := lo + span/2
		a, err := apyAt(mid)
		if err != nil {
			return 0, err
		}
		if a < targetAPY {
			lo = mid + 1
		} else {
			high = mid
		}
	}
	return lo, nil
}

// BreakEvenBurn reports the fee activity required for net-zero supply change,
// i.e. annual burn == annual issuance.
type BreakEvenBurn struct {
	AnnualIssuanceWei  *big.Int
	DailyBurnNeededWei *big.Int
	// TxPerDayNeeded is the daily transaction count that closes the gap at the
	// supplied gas-per-tx and base-fee assumptions.
	TxPerDayNeeded float64
}

// SolveBreakEvenBurn computes the burn required to offset issuance at a given
// stake level and fee configuration.
func SolveBreakEvenBurn(p Params, totalStakeWei, stakePerValidatorWei *big.Int, gasPerTx, baseFeeGwei int64) (BreakEvenBurn, error) {
	var out BreakEvenBurn
	if err := p.Validate(); err != nil {
		return out, err
	}
	if gasPerTx <= 0 || baseFeeGwei <= 0 {
		return out, errors.New("model: gasPerTx and baseFeeGwei must be > 0")
	}
	n := int(new(big.Int).Div(totalStakeWei, stakePerValidatorWei).Int64())
	if n < 1 {
		n = 1
	}
	iss, err := EpochIssuance(UniformStakes(n, stakePerValidatorWei), p)
	if err != nil {
		return out, err
	}
	annual := AnnualIssuanceWei(iss.Total, p)
	daily := new(big.Int).Div(annual, big.NewInt(365))

	weiPerTx := new(big.Int).Mul(big.NewInt(gasPerTx), big.NewInt(baseFeeGwei))
	weiPerTx.Mul(weiPerTx, big.NewInt(WeiPerGwei))

	out.AnnualIssuanceWei = annual
	out.DailyBurnNeededWei = daily
	out.TxPerDayNeeded = ratio(daily, weiPerTx)
	return out, nil
}
