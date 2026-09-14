// Quantaureum Node source, version 1.0.0.
package model

import (
	"math"
	"math/big"
	"testing"
)

// approx asserts got is within tol (relative) of want.
func approx(t *testing.T, label string, got, want, tol float64) {
	t.Helper()
	if want == 0 {
		if math.Abs(got) > tol {
			t.Fatalf("%s: got %g, want ~0 (tol %g)", label, got, tol)
		}
		return
	}
	rel := math.Abs(got-want) / math.Abs(want)
	if rel > tol {
		t.Fatalf("%s: got %g, want %g (rel err %.4f > tol %g)", label, got, want, rel, tol)
	}
}

// TestEthereumGroundTruth pins the model against a value that can be checked
// against the real beacon chain: at ~30M ETH staked, Altair parameters yield
// roughly 3% staking APR and roughly 0.76% gross inflation on a 120M supply.
//
// If this test fails, the base-reward arithmetic is wrong in a way that would
// invalidate every QAU projection produced by this package.
func TestEthereumGroundTruth(t *testing.T) {
	p := EthereumAltairParams()
	const validators = 937_500 // 30M ETH / 32 ETH
	stakeEach := WeiFromQAU(32)

	iss, err := EpochIssuance(UniformStakes(validators, stakeEach), p)
	if err != nil {
		t.Fatal(err)
	}
	total := new(big.Int).Mul(stakeEach, big.NewInt(validators))
	annual := AnnualIssuanceWei(iss.Total, p)
	apr := StakingAPY(annual, total)

	t.Logf("ETH: staked=%.0f, annual issuance=%.0f ETH, APR=%.3f%%, proposer share=%.2f%%",
		QAU(total), QAU(annual), apr*100, iss.ProposerShare()*100)

	// Altair parameters at 30M ETH staked yield 3.035% APR. Pinned tightly on
	// purpose: this value is the anchor for the whole F=31 argument, and the
	// original 10% tolerance around a 0.032 guess was loose enough to hide a
	// 0.5-point error, which then got quoted in the design doc as if computed.
	// Keep the band narrow so the doc can cite this number verbatim.
	//
	// For context, the observed beacon-chain APR at that stake level is ~3.0-3.3%;
	// the spread comes from real-world participation and MEV, neither of which
	// this pure-issuance model includes.
	approx(t, "ETH staking APR", apr, 0.03035, 0.01)

	// Gross inflation against a 120M ETH supply.
	approx(t, "ETH gross inflation", ratio(annual, WeiFromQAU(120_000_000)), 0.00759, 0.01)

	// Ethereum's proposer weight is exactly 8/64 = 12.5% of total issuance.
	approx(t, "ETH proposer share", iss.ProposerShare(), 0.125, 0.001)
}

// TestPreEM2ReproducesObservedIssuance pins the model against the value
// actually observed on QAU mainnet at release r105, BEFORE the EM-2 issuance
// reform: 6 validators x 6,000 QAU
// produce 1.9e16 wei of epoch rewards, which the block producer logs as
// "total=19000000000000000 qau-wei".
//
// This is the anchor that proved the 100x/1000x unit confusion in the first
// draft of the economic model: 1.9e16 wei is 0.019 QAU, not 19 QAU.
func TestPreEM2ReproducesObservedIssuance(t *testing.T) {
	p := PreEM2MainnetParams()
	stakes := UniformStakes(6, WeiFromQAU(6_000))

	iss, err := EpochIssuance(stakes, p)
	if err != nil {
		t.Fatal(err)
	}

	wantWei := new(big.Int).SetUint64(19_000_000_000_000_000) // 1.9e16 wei
	if iss.Total.Cmp(wantWei) != 0 {
		t.Fatalf("epoch issuance: got %s wei, want %s wei", iss.Total, wantWei)
	}

	total := WeiFromQAU(36_000)
	annual := AnnualIssuanceWei(iss.Total, p)
	apy := StakingAPY(annual, total)

	t.Logf("live: %.6f QAU/epoch, %.1f QAU/year, APY=%.3f%%, proposer share=%.1f%%",
		QAU(iss.Total), QAU(annual), apy*100, iss.ProposerShare()*100)

	approx(t, "live annual issuance QAU", QAU(annual), 1560.375, 0.001)
	approx(t, "live APY", apy, 0.04334, 0.01)

	// The defect this model exists to quantify: proposers capture 84% of all
	// issuance at N=6, versus Ethereum's 12.5%.
	approx(t, "live proposer share", iss.ProposerShare(), 0.842, 0.01)
}

// TestStaleCalibrationComment demonstrates that the pre-EM-2 BaseRewardFactor=2
// calibration claim ("~9.8% APR at 6 validators x 30,000 QAU") was only
// reachable under the pre-CONS-R8-001 semantics of one attester reward per SLOT,
// and then only counting the attester component. The dedup fix cut the attester
// component by SlotsPerEpoch without recalibrating F.
//
// The claim now survives only as a HISTORY note in consensus/block.go; this test
// keeps the arithmetic behind it verifiable rather than folklore.
func TestStaleCalibrationComment(t *testing.T) {
	// The comment's stated configuration: 6 validators x 30,000 QAU.
	stakes := UniformStakes(6, WeiFromQAU(30_000))
	total := WeiFromQAU(180_000)

	legacy := LegacyPreDedupParams()
	issLegacy, err := EpochIssuance(stakes, legacy)
	if err != nil {
		t.Fatal(err)
	}
	// The comment's 9.8% is the ATTESTER component alone under per-slot pay.
	aprLegacyAtt := StakingAPY(AnnualIssuanceWei(issLegacy.Attester, legacy), total)

	live := PreEM2MainnetParams()
	issLive, err := EpochIssuance(stakes, live)
	if err != nil {
		t.Fatal(err)
	}
	aprLiveAtt := StakingAPY(AnnualIssuanceWei(issLive.Attester, live), total)
	aprLiveTotal := StakingAPY(AnnualIssuanceWei(issLive.Total, live), total)

	t.Logf("stale comment config: pre-dedup attester APR=%.2f%%, post-dedup attester APR=%.3f%% (%.0fx cut); post-dedup total APR=%.2f%%",
		aprLegacyAtt*100, aprLiveAtt*100, aprLegacyAtt/aprLiveAtt, aprLiveTotal*100)

	// Pre-dedup attester-only reproduces the documented ~9.8%.
	approx(t, "pre-dedup attester APR", aprLegacyAtt, 0.098, 0.02)

	// The dedup fix cut it by exactly SlotsPerEpoch.
	approx(t, "dedup cut factor", aprLegacyAtt/aprLiveAtt, float64(live.SlotsPerEpoch), 0.001)
}

// TestIssuanceIndependentOfValidatorCount asserts the central structural
// property of the Ethereum-style reward split: with a fixed total stake,
// total issuance must not depend on how many validators that stake is spread
// across. The live per-slot proposer rule violates this; the quotient rule
// does not.
func TestIssuanceIndependentOfValidatorCount(t *testing.T) {
	totalStake := WeiFromQAU(6_000_000)

	measure := func(p Params, n int) *big.Int {
		each := new(big.Int).Div(totalStake, big.NewInt(int64(n)))
		iss, err := EpochIssuance(UniformStakes(n, each), p)
		if err != nil {
			t.Fatal(err)
		}
		return iss.Total
	}

	eth := EthereumAltairParams()
	a, b := measure(eth, 100), measure(eth, 1000)
	drift := math.Abs(QAU(a)-QAU(b)) / QAU(a)
	if drift > 0.001 {
		t.Fatalf("weighted-split mode: issuance drifted %.4f between N=100 and N=1000 (%s vs %s)", drift, a, b)
	}

	// The live rule must instead shrink total issuance as N grows, because the
	// 32 per-slot proposer rewards are each proportional to the (falling) mean
	// individual stake.
	live := PreEM2MainnetParams()
	prev := measure(live, 6)
	for _, n := range []int{20, 100, 1000} {
		cur := measure(live, n)
		if cur.Cmp(prev) >= 0 {
			t.Fatalf("live mode issuance did not fall at N=%d (%s >= %s)", n, cur, prev)
		}
		prev = cur
	}
	ratio6to1000 := QAU(measure(live, 6)) / QAU(measure(live, 1000))
	t.Logf("live mode issuance at fixed 6M stake: N=6 is %.2fx N=1000", ratio6to1000)
	if ratio6to1000 < 1.5 {
		t.Fatalf("expected strong N-dependence, got %.2fx", ratio6to1000)
	}
}

// TestAPYScalesAsInverseSqrt asserts APY halves when stake quadruples, the
// anti-concentration property inherited from Ethereum.
func TestAPYScalesAsInverseSqrt(t *testing.T) {
	p := EthereumAltairParams()
	each := WeiFromQAU(6_000)

	apyAt := func(n int) float64 {
		iss, err := EpochIssuance(UniformStakes(n, each), p)
		if err != nil {
			t.Fatal(err)
		}
		total := new(big.Int).Mul(each, big.NewInt(int64(n)))
		return StakingAPY(AnnualIssuanceWei(iss.Total, p), total)
	}

	a1 := apyAt(100)
	a4 := apyAt(400)
	approx(t, "APY(4S) vs APY(S)/2", a4, a1/2, 0.01)
}

func TestSolveBaseRewardFactor(t *testing.T) {
	p := EthereumAltairParams()
	target := 0.05
	stake := WeiFromQAU(4_000_000)
	each := WeiFromQAU(6_000)

	f, err := SolveBaseRewardFactor(p, stake, each, target, 100_000)
	if err != nil {
		t.Fatal(err)
	}

	q := p
	q.BaseRewardFactor = f
	iss, err := EpochIssuance(UniformStakes(666, each), q)
	if err != nil {
		t.Fatal(err)
	}
	got := StakingAPY(AnnualIssuanceWei(iss.Total, q), new(big.Int).Mul(each, big.NewInt(666)))

	t.Logf("solved F=%d for target APY %.1f%% at 4M staked -> actual %.3f%%", f, target*100, got*100)
	if got < target {
		t.Fatalf("solved F=%d yields APY %.4f below target %.4f", f, got, target)
	}
	// The smallest sufficient F must be tight: F-1 must undershoot.
	q.BaseRewardFactor = f - 1
	issLow, err := EpochIssuance(UniformStakes(666, each), q)
	if err != nil {
		t.Fatal(err)
	}
	if StakingAPY(AnnualIssuanceWei(issLow.Total, q), new(big.Int).Mul(each, big.NewInt(666))) >= target {
		t.Fatalf("F=%d is not minimal", f)
	}
}

func TestVestingRelease(t *testing.T) {
	tr := VestingTranche{Name: "Team", TotalWei: WeiFromQAU(4_000_000), CliffYears: 1, DurationYears: 4}

	if got := QAU(tr.LockedAtWei(0)); got != 4_000_000 {
		t.Fatalf("t=0 locked: got %.0f, want 4000000", got)
	}
	// Before the cliff nothing is claimable, so the full amount stays locked.
	if got := QAU(tr.LockedAtWei(0.9)); got != 4_000_000 {
		t.Fatalf("t=0.9 locked: got %.0f, want 4000000", got)
	}
	// At t=2 of a 4-year schedule, half remains locked.
	approx(t, "t=2 locked", QAU(tr.LockedAtWei(2)), 2_000_000, 0.001)
	if got := QAU(tr.LockedAtWei(4)); got != 0 {
		t.Fatalf("t=4 locked: got %.0f, want 0", got)
	}

	total := big.NewInt(0)
	for _, v := range MainnetVesting() {
		total.Add(total, v.TotalWei)
	}
	if QAU(total) != 15_000_000 {
		t.Fatalf("mainnet vesting total: got %.0f, want 15000000", QAU(total))
	}
}

// TestFloatConstrainsEarlyStake documents that with 15M of the 20M genesis
// supply locked in vesting contracts, the reachable stake in year 1 is bounded
// by the ~5M float — so any design anchored on "6M staked" is unreachable
// until vesting unlocks.
func TestFloatConstrainsEarlyStake(t *testing.T) {
	s := Scenario{
		Params:               EthereumAltairParams(),
		Years:                6,
		InitialSupplyWei:     WeiFromQAU(20_000_000),
		Vesting:              MainnetVesting(),
		StakeRatioOfFloat:    0.35,
		StakePerValidatorWei: WeiFromQAU(6_000),
		MinValidators:        6,
	}
	rows, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}

	y1 := rows[0]
	t.Logf("Y1: float=%.0f QAU, stake=%.0f QAU, validators=%d, APY=%.2f%%",
		QAU(y1.FloatWei), QAU(y1.StakeWei), y1.Validators, y1.StakingAPY*100)

	if QAU(y1.FloatWei) > 6_000_000 {
		t.Fatalf("year-1 float %.0f exceeds expected ~5M", QAU(y1.FloatWei))
	}
	// Float must grow as vesting releases.
	if rows[len(rows)-1].FloatWei.Cmp(y1.FloatWei) <= 0 {
		t.Fatal("float did not grow across the horizon")
	}
}

func TestScenarioNetSupplyCanDeflate(t *testing.T) {
	s := Scenario{
		Params:               EthereumAltairParams(),
		Years:                3,
		InitialSupplyWei:     WeiFromQAU(20_000_000),
		StakeRatioOfFloat:    0.30,
		StakePerValidatorWei: WeiFromQAU(6_000),
		MinValidators:        6,
		// Usage heavy enough to out-burn issuance but still physically payable.
		Fees:             FeeModel{TxPerDay: 200_000, GasPerTx: 21_000, BaseFeeGwei: 500, TipGwei: 50},
		FeeGrowthPerYear: 0,
	}
	rows, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.SupplyWei.Sign() < 0 {
			t.Fatalf("Y%d: supply went negative (%s)", r.Year, r.SupplyWei)
		}
	}
	last := rows[len(rows)-1]
	t.Logf("heavy usage: issuance=%.0f, burn=%.0f, net=%.0f QAU/yr, net inflation=%.3f%%",
		QAU(last.IssuanceWei), QAU(last.BurnWei), QAU(last.NetWei), last.NetInflation*100)
	if last.NetWei.Sign() >= 0 {
		t.Fatalf("expected net deflation, got net=%s wei", last.NetWei)
	}
	if last.SupplyWei.Cmp(s.InitialSupplyWei) >= 0 {
		t.Fatal("supply did not shrink under net deflation")
	}
}

func TestSolveBreakEvenBurn(t *testing.T) {
	p := EthereumAltairParams()
	be, err := SolveBreakEvenBurn(p, WeiFromQAU(4_000_000), WeiFromQAU(6_000), 21_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("break-even at 4M staked, baseFee=1 gwei: %.0f QAU/day burn, %.0f tx/day",
		QAU(be.DailyBurnNeededWei), be.TxPerDayNeeded)
	if be.TxPerDayNeeded < 1e6 {
		t.Fatalf("expected an implausibly large tx/day at 1 gwei, got %.0f", be.TxPerDayNeeded)
	}
}

func TestParamsValidate(t *testing.T) {
	cases := map[string]Params{
		"zero factor":  {BaseRewardsPerEpoch: 1, AttestationsPerEpoch: 1, SlotsPerEpoch: 32, EpochsPerYear: 82125},
		"zero divisor": {BaseRewardFactor: 64, AttestationsPerEpoch: 1, SlotsPerEpoch: 32, EpochsPerYear: 82125},
		"zero epochs":  {BaseRewardFactor: 64, BaseRewardsPerEpoch: 1, AttestationsPerEpoch: 1, SlotsPerEpoch: 32},
		"zero weight denominator": {BaseRewardFactor: 64, BaseRewardsPerEpoch: 1, AttestationsPerEpoch: 1,
			SlotsPerEpoch: 32, EpochsPerYear: 82125, Proposer: ProposerWeightedSplit},
		"proposer weight >= denominator": {BaseRewardFactor: 64, BaseRewardsPerEpoch: 1, AttestationsPerEpoch: 1,
			SlotsPerEpoch: 32, EpochsPerYear: 82125, Proposer: ProposerWeightedSplit,
			ProposerWeight: 64, WeightDenominator: 64},
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	if err := EthereumAltairParams().Validate(); err != nil {
		t.Errorf("EthereumAltairParams must validate: %v", err)
	}
	if err := MainnetParams().Validate(); err != nil {
		t.Errorf("MainnetParams must validate: %v", err)
	}
	if err := PreEM2MainnetParams().Validate(); err != nil {
		t.Errorf("PreEM2MainnetParams must validate: %v", err)
	}
}

func TestEpochIssuanceEdgeCases(t *testing.T) {
	p := EthereumAltairParams()

	iss, err := EpochIssuance(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	if iss.Total.Sign() != 0 {
		t.Fatal("empty validator set must issue zero")
	}

	iss, err = EpochIssuance([]*big.Int{big.NewInt(0)}, p)
	if err != nil {
		t.Fatal(err)
	}
	if iss.Total.Sign() != 0 {
		t.Fatal("zero stake must issue zero")
	}

	if _, err := EpochIssuance([]*big.Int{nil}, p); err == nil {
		t.Fatal("nil stake must error")
	}

	// Sub-gwei stake truncates to zero reward rather than panicking.
	if got := BaseRewardWei(big.NewInt(1), big.NewInt(1), p); got.Sign() != 0 {
		t.Fatalf("sub-gwei stake: got %s, want 0", got)
	}
}

// TestBurnAsFractionOfSupply exercises the long-horizon burn mode and asserts
// it avoids the nominal-price artifact: with burn expressed as a share of
// supply, the system converges instead of spiraling.
func TestBurnAsFractionOfSupply(t *testing.T) {
	base := Scenario{
		Params:               EthereumAltairParams(),
		Years:                40,
		InitialSupplyWei:     WeiFromQAU(20_000_000),
		Vesting:              MainnetVesting(),
		StakeRatioOfFloat:    0.35,
		StakePerValidatorWei: WeiFromQAU(6_000),
		MinValidators:        6,
	}

	// Burn share below gross inflation: supply still grows, but slower.
	low := base
	low.BurnAsFractionOfSupply = 0.01
	lowRows, err := low.Run()
	if err != nil {
		t.Fatal(err)
	}

	// Burn share above gross inflation: supply shrinks without collapsing.
	high := base
	high.BurnAsFractionOfSupply = 0.03
	highRows, err := high.Run()
	if err != nil {
		t.Fatal(err)
	}

	lowLast := lowRows[len(lowRows)-1]
	highLast := highRows[len(highRows)-1]
	t.Logf("burn 1%%/yr -> supply %.0f QAU after 40y; burn 3%%/yr -> %.0f QAU",
		QAU(lowLast.SupplyWei), QAU(highLast.SupplyWei))

	if lowLast.SupplyWei.Cmp(highLast.SupplyWei) <= 0 {
		t.Fatal("higher burn share must yield lower terminal supply")
	}
	// The 3% case must remain a going concern, not collapse to dust.
	if QAU(highLast.SupplyWei) < 1_000_000 {
		t.Fatalf("3%% burn collapsed supply to %.0f QAU; model is unstable", QAU(highLast.SupplyWei))
	}
	for _, r := range highRows {
		if r.SupplyWei.Sign() < 0 {
			t.Fatalf("Y%d supply negative", r.Year)
		}
	}
}

// TestFeeMarketFloorBelowTarget is the regression for the modeling flaw found
// on 2026-08-31: a fixed nominal base fee of 300 gwei combined with +40%/yr
// volume growth burned 69% of the supply over 12 years. That cannot happen —
// at 50,000 tx/day the chain runs at ~1% of its gas target, and EIP-1559 lowers
// the base fee every under-full block until it reaches the floor.
//
// With the endogenous fee market the same inputs must leave the base fee at the
// floor and the supply GROWING, because issuance dwarfs a floor-priced burn.
func TestFeeMarketFloorBelowTarget(t *testing.T) {
	p := EthereumAltairParams()
	p.BaseRewardFactor = 31
	fm := MainnetFeeMarket(p, 300)

	burn, baseFee, util := fm.BurnAtDemand(50_000, 21_000)
	t.Logf("50k tx/day: util=%.4f baseFee=%d gwei burn=%.2f QAU/yr", util, baseFee, QAU(burn))

	if util >= 1 {
		t.Fatalf("50k tx/day should be far below the gas target, got util=%g", util)
	}
	if baseFee != fm.MinBaseFeeGwei {
		t.Fatalf("under-target base fee: got %d gwei, want floor %d gwei", baseFee, fm.MinBaseFeeGwei)
	}
	// demand gas * 1 gwei = 50000*21000*365 gas = 383.25e9 gas -> 383.25 QAU.
	approx(t, "floor burn QAU/yr", QAU(burn), 383.25, 0.01)

	sc := Scenario{
		Params:               p,
		Years:                12,
		InitialSupplyWei:     WeiFromQAU(20_000_000),
		Vesting:              MainnetVesting(),
		StakeRatioOfFloat:    0.35,
		StakePerValidatorWei: WeiFromQAU(6_000),
		MinValidators:        6,
		Fees:                 FeeModel{TxPerDay: 50_000, GasPerTx: 21_000},
		FeeGrowthPerYear:     0.4,
		Fee1559:              &fm,
	}
	rows, err := sc.Run()
	if err != nil {
		t.Fatal(err)
	}
	last := rows[len(rows)-1]
	t.Logf("after 12y: supply %.0f QAU, terminal util %.4f, baseFee %d gwei",
		QAU(last.SupplyWei), last.Utilization, last.BaseFeeGwei)

	if last.SupplyWei.Cmp(WeiFromQAU(20_000_000)) <= 0 {
		t.Fatalf("supply must grow when burn is floor-priced; got %.0f QAU", QAU(last.SupplyWei))
	}
	for _, r := range rows {
		if r.BaseFeeGwei != fm.MinBaseFeeGwei {
			t.Fatalf("Y%d base fee %d gwei: demand never reaches the target, must stay at floor", r.Year, r.BaseFeeGwei)
		}
	}
}

// TestFeeMarketCapsBurnAtBlockLimit asserts the second hard bound: once demand
// exceeds the gas target the chain is saturated, so burned gas is capped by the
// block gas limit no matter how much demand is posited.
func TestFeeMarketCapsBurnAtBlockLimit(t *testing.T) {
	p := EthereumAltairParams()
	fm := MainnetFeeMarket(p, 300)

	// Absurd demand: 200M tx/day is ~39x the gas target.
	burn, baseFee, util := fm.BurnAtDemand(200_000_000, 21_000)
	if util <= 1 {
		t.Fatalf("expected saturation, got util=%g", util)
	}
	if baseFee != fm.CongestionBaseFeeGwei {
		t.Fatalf("saturated base fee: got %d gwei, want congestion assumption %d gwei", baseFee, fm.CongestionBaseFeeGwei)
	}

	// Cap = blocksPerYear * gasLimit * baseFee.
	capWei := new(big.Int).Mul(big.NewInt(fm.BlocksPerYear), big.NewInt(fm.GasLimitPerBlock))
	capWei.Mul(capWei, big.NewInt(baseFee))
	capWei.Mul(capWei, big.NewInt(WeiPerGwei))
	if burn.Cmp(capWei) != 0 {
		t.Fatalf("burn %s wei must equal the block-limit cap %s wei", burn, capWei)
	}
	t.Logf("saturated: util=%.1f baseFee=%d gwei burn=%.0f QAU/yr (block-limit capped)", util, baseFee, QAU(burn))

	// Ten times the demand must not burn ten times the gas.
	burn10, _, _ := fm.BurnAtDemand(2_000_000_000, 21_000)
	if burn10.Cmp(burn) != 0 {
		t.Fatal("burn must be capacity-bound, not demand-bound, once saturated")
	}
}

// TestFeeMarketFloorIsChainMinimum pins the floor to the chain's own minimum
// gas price: the txpool rejects anything cheaper, so the base fee cannot settle
// below it regardless of how empty blocks are.
func TestFeeMarketFloorIsChainMinimum(t *testing.T) {
	fm := MainnetFeeMarket(EthereumAltairParams(), 0)
	if fm.MinBaseFeeGwei != 1 {
		t.Fatalf("floor: got %d gwei, want 1 gwei (params.MinGasPrice)", fm.MinBaseFeeGwei)
	}
	// A congestion assumption below the floor is meaningless; it must be raised.
	if fm.CongestionBaseFeeGwei != fm.MinBaseFeeGwei {
		t.Fatalf("congestion base fee below floor must clamp to floor, got %d", fm.CongestionBaseFeeGwei)
	}
	if fm.GasTargetPerBlock*2 != fm.GasLimitPerBlock {
		t.Fatalf("target*elasticity must equal limit: %d vs %d", fm.GasTargetPerBlock*2, fm.GasLimitPerBlock)
	}
	if fm.BlocksPerYear != 32*82_125 {
		t.Fatalf("blocks/yr: got %d, want %d", fm.BlocksPerYear, 32*82_125)
	}
}

// TestAttributionDustIsBounded pins the only quantity that can make a consensus
// port disagree with this model: per-validator truncation.
//
// Result: dust is exactly ZERO on this chain, because base rewards are
// gwei-granular and 64 divides 1e9 evenly. That makes a bit-exact consensus
// port possible rather than merely close. The bound assertion is kept as a
// safety net for the day WeightDenominator changes to a value that does not
// divide 1e9.
func TestAttributionDustIsBounded(t *testing.T) {
	p := EthereumAltairParams()
	p.BaseRewardFactor = 31

	if WeiPerGwei%p.WeightDenominator != 0 {
		t.Fatalf("precondition changed: WeightDenominator %d no longer divides %d — dust is no longer zero, update the port and the doc",
			p.WeightDenominator, WeiPerGwei)
	}

	for _, n := range []int{6, 100, 666, 3_333} {
		stakes := UniformStakes(n, WeiFromQAU(6_000))
		attr, err := EpochIssuanceAttributed(stakes, p)
		if err != nil {
			t.Fatal(err)
		}

		if attr.DustWei.Sign() != 0 {
			t.Fatalf("n=%d: dust %s wei, want exactly 0 (gwei-granular rewards split by /64)", n, attr.DustWei)
		}
		maxDust := new(big.Int).Mul(big.NewInt(p.WeightDenominator), big.NewInt(int64(n)))
		if attr.DustWei.Cmp(maxDust) >= 0 {
			t.Fatalf("n=%d: dust %s wei exceeds the %s wei bound", n, attr.DustWei, maxDust)
		}

		// The pool total must equal what EpochIssuance reports, so the two
		// entry points cannot drift.
		iss, err := EpochIssuance(stakes, p)
		if err != nil {
			t.Fatal(err)
		}
		if iss.Total.Cmp(attr.PoolTotalWei) != 0 {
			t.Fatalf("n=%d: pool total %s != EpochIssuance total %s", n, attr.PoolTotalWei, iss.Total)
		}

		// Proposer share must stay at the weight, independent of validator count.
		approx(t, "attributed proposer share", attr.ProposerShare(), 0.125, 0.001)

		t.Logf("n=%-5d pool=%s wei  dust=%s wei (bound %s)  proposer=%.4f%%",
			n, attr.PoolTotalWei, attr.DustWei, maxDust, attr.ProposerShare()*100)
	}
}

// TestAttributionRejectsPerSlotMode guards the port: the live per-slot proposer
// rule has no per-validator attester attribution, so asking for one is a
// programming error rather than something to approximate.
func TestAttributionRejectsPerSlotMode(t *testing.T) {
	if _, err := EpochIssuanceAttributed(UniformStakes(6, WeiFromQAU(6_000)), PreEM2MainnetParams()); err == nil {
		t.Fatal("expected an error for ProposerPerSlotFullReward mode")
	}
}

// TestAttributionUnequalStakes checks the attribution holds when stakes differ,
// which is the case the pool-level model explicitly does not promise to handle
// for the per-slot mode.
func TestAttributionUnequalStakes(t *testing.T) {
	p := EthereumAltairParams()
	p.BaseRewardFactor = 31

	stakes := []*big.Int{
		WeiFromQAU(6_000),
		WeiFromQAU(12_000),
		WeiFromQAU(30_000),
		WeiFromQAU(100_000),
		WeiFromQAU(6_000),
		WeiFromQAU(6_000),
	}
	attr, err := EpochIssuanceAttributed(stakes, p)
	if err != nil {
		t.Fatal(err)
	}

	// A bigger stake must never earn less than a smaller one.
	if attr.AttesterWei[1].Cmp(attr.AttesterWei[0]) <= 0 {
		t.Fatal("12,000 QAU must out-earn 6,000 QAU")
	}
	if attr.AttesterWei[3].Cmp(attr.AttesterWei[2]) <= 0 {
		t.Fatal("100,000 QAU must out-earn 30,000 QAU")
	}
	// Equal stakes must earn exactly equally — no index-dependent favoritism.
	if attr.AttesterWei[0].Cmp(attr.AttesterWei[4]) != 0 || attr.AttesterWei[0].Cmp(attr.AttesterWei[5]) != 0 {
		t.Fatal("equal stakes must receive equal attester rewards")
	}
	approx(t, "unequal-stake proposer share", attr.ProposerShare(), 0.125, 0.001)
	t.Logf("unequal stakes: pool=%s wei dust=%s wei", attr.PoolTotalWei, attr.DustWei)
}
