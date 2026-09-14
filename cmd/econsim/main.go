// Quantaureum Node source, version 1.0.0.
// Command econsim evaluates QAU monetary-policy parameters offline.
//
// It is a calculator, not a node: nothing it prints touches chain state. The
// arithmetic comes from economics/model, which is pinned bit-exact to the
// consensus base-reward implementation by consensus/econ_model_parity_test.go.
//
// Subcommands:
//
//	current    compute issuance with current mainnet parameters
//	compare    compare mainnet parameters with strict-Ethereum parameters
//	table      issuance and APY across stake levels
//	project    multi-year supply projection including fee burn
//	solve      find the BaseRewardFactor that hits a target APY
//	breakeven  fee activity required for net-zero supply change
//
// Examples:
//
//	econsim current
//	econsim compare
//	econsim table -preset eth -f 64
//	econsim project -years 20 -stake-ratio 0.35 -tx-per-day 100000 -basefee 300
//	econsim solve -apy 0.05 -at 4000000
//	econsim breakeven -at 4000000 -basefee 300
package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/quantaureum/qau/economics/model"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "current":
		err = cmdCurrent(args)
	case "compare":
		err = cmdCompare(args)
	case "table":
		err = cmdTable(args)
	case "project":
		err = cmdProject(args)
	case "solve":
		err = cmdSolve(args)
	case "breakeven":
		err = cmdBreakEven(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "econsim: unknown subcommand %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "econsim: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `econsim - QAU monetary policy calculator

usage: econsim <subcommand> [flags]

subcommands:
  current    compute issuance with current mainnet parameters
  compare    compare mainnet parameters with strict-Ethereum parameters
  table      issuance and APY across stake levels
  project    multi-year supply projection including fee burn
  solve      find the BaseRewardFactor that hits a target APY
  breakeven  fee activity required for net-zero supply change

run "econsim <subcommand> -h" for flags
`)
}

// preset resolves a named parameter preset.
func preset(name string) (model.Params, error) {
	switch strings.ToLower(name) {
	case "live", "mainnet", "em2":
		return model.MainnetParams(), nil
	case "eth", "ethereum", "altair":
		return model.EthereumAltairParams(), nil
	case "pre-em2", "preem2", "r105":
		return model.PreEM2MainnetParams(), nil
	case "legacy", "predup", "pre-dedup":
		return model.LegacyPreDedupParams(), nil
	default:
		return model.Params{}, fmt.Errorf("unknown preset %q (want mainnet|eth|pre-em2|legacy)", name)
	}
}

// commonFlags registers the parameter flags shared by most subcommands.
type commonFlags struct {
	preset       *string
	factor       *int64
	perValidator *int64
}

func addCommonFlags(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		preset:       fs.String("preset", "eth", "parameter preset: mainnet|eth|pre-em2|legacy"),
		factor:       fs.Int64("f", 0, "override BaseRewardFactor (0 = preset default)"),
		perValidator: fs.Int64("stake-per-validator", 6_000, "stake per validator, in whole QAU"),
	}
}

func (c commonFlags) params() (model.Params, error) {
	p, err := preset(*c.preset)
	if err != nil {
		return p, err
	}
	if *c.factor > 0 {
		p.BaseRewardFactor = *c.factor
	}
	return p, p.Validate()
}

func (c commonFlags) stakeEach() *big.Int {
	return model.WeiFromQAU(*c.perValidator)
}

func newTab() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
}

// newKV returns a left-aligned writer for label/value pairs.
func newKV() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func cmdCurrent(args []string) error {
	fs := flag.NewFlagSet("current", flag.ExitOnError)
	validators := fs.Int("validators", 6, "validator count")
	stakeEach := fs.Int64("stake-per-validator", 6_000, "stake per validator, in whole QAU")
	if err := fs.Parse(args); err != nil {
		return err
	}

	p := model.MainnetParams()
	each := model.WeiFromQAU(*stakeEach)
	stakes := model.UniformStakes(*validators, each)
	iss, err := model.EpochIssuance(stakes, p)
	if err != nil {
		return err
	}
	total := new(big.Int).Mul(each, big.NewInt(int64(*validators)))
	annual := model.AnnualIssuanceWei(iss.Total, p)

	fmt.Printf("mainnet parameters, EM-2 (BaseRewardFactor=%d, divisor=%d, %d attestation(s)/epoch, proposer weight %d/%d)\n\n",
		p.BaseRewardFactor, p.BaseRewardsPerEpoch, p.AttestationsPerEpoch,
		p.ProposerWeight, p.WeightDenominator)

	w := newKV()
	fmt.Fprintf(w, "validators\t%d\t\n", *validators)
	fmt.Fprintf(w, "total stake\t%.0f QAU\t\n", model.QAU(total))
	fmt.Fprintf(w, "issuance / epoch\t%.6f QAU\t\n", model.QAU(iss.Total))
	fmt.Fprintf(w, "issuance / epoch (wei)\t%s\t\n", iss.Total)
	fmt.Fprintf(w, "issuance / year\t%.1f QAU\t\n", model.QAU(annual))
	fmt.Fprintf(w, "staking APY\t%.3f%%\t\n", model.StakingAPY(annual, total)*100)
	fmt.Fprintf(w, "per validator / year\t%.1f QAU\t\n", model.QAU(annual)/float64(*validators))
	fmt.Fprintf(w, "attester share\t%.1f%%\t\n", (1-iss.ProposerShare())*100)
	fmt.Fprintf(w, "proposer share\t%.1f%%\t\n", iss.ProposerShare()*100)
	return w.Flush()
}

func cmdCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	factor := fs.Int64("f", 31, "BaseRewardFactor for the EM-2 column (31 = mainnet; 64 = Ethereum's own value)")
	stakeEach := fs.Int64("stake-per-validator", 6_000, "stake per validator, in whole QAU")
	if err := fs.Parse(args); err != nil {
		return err
	}

	each := model.WeiFromQAU(*stakeEach)
	live := model.PreEM2MainnetParams()
	eth := model.EthereumAltairParams()
	eth.BaseRewardFactor = *factor

	counts := []int{6, 20, 100, 500, 1_000, 3_000}

	fmt.Printf("pre-EM-2 (F=%d, /%d, per-slot proposer)  vs  EM-2/Ethereum (F=%d, /%d, %d/%d proposer weight)\n\n",
		live.BaseRewardFactor, live.BaseRewardsPerEpoch,
		eth.BaseRewardFactor, eth.BaseRewardsPerEpoch, eth.ProposerWeight, eth.WeightDenominator)

	w := newTab()
	fmt.Fprintln(w, "validators\tstake QAU\tpreEM2 APY\tEM2 APY\tpreEM2 prop%\tEM2 prop%\tpreEM2 QAU/yr\tEM2 QAU/yr\t")
	for _, n := range counts {
		stakes := model.UniformStakes(n, each)
		total := new(big.Int).Mul(each, big.NewInt(int64(n)))

		iLive, err := model.EpochIssuance(stakes, live)
		if err != nil {
			return err
		}
		iEth, err := model.EpochIssuance(stakes, eth)
		if err != nil {
			return err
		}
		aLive := model.AnnualIssuanceWei(iLive.Total, live)
		aEth := model.AnnualIssuanceWei(iEth.Total, eth)

		fmt.Fprintf(w, "%d\t%.0f\t%.3f%%\t%.3f%%\t%.1f%%\t%.1f%%\t%.0f\t%.0f\t\n",
			n, model.QAU(total),
			model.StakingAPY(aLive, total)*100, model.StakingAPY(aEth, total)*100,
			iLive.ProposerShare()*100, iEth.ProposerShare()*100,
			model.QAU(aLive), model.QAU(aEth))
	}
	return w.Flush()
}

func cmdTable(args []string) error {
	fs := flag.NewFlagSet("table", flag.ExitOnError)
	c := addCommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := c.params()
	if err != nil {
		return err
	}
	each := c.stakeEach()

	levels := []int64{36_000, 120_000, 600_000, 1_000_000, 4_000_000,
		10_000_000, 20_000_000, 40_000_000, 60_000_000, 100_000_000}

	fmt.Printf("preset=%s F=%d divisor=%d proposer=%d/%d\n\n",
		*c.preset, p.BaseRewardFactor, p.BaseRewardsPerEpoch, p.ProposerWeight, p.WeightDenominator)

	w := newTab()
	fmt.Fprintln(w, "stake QAU\tvalidators\tQAU/epoch\tQAU/year\tAPY\tper validator/yr\t")
	for _, s := range levels {
		n := s / *c.perValidator
		if n < 1 {
			n = 1
		}
		stakes := model.UniformStakes(int(n), each)
		total := new(big.Int).Mul(each, big.NewInt(n))
		iss, err := model.EpochIssuance(stakes, p)
		if err != nil {
			return err
		}
		annual := model.AnnualIssuanceWei(iss.Total, p)
		fmt.Fprintf(w, "%.0f\t%d\t%.4f\t%.0f\t%.3f%%\t%.0f\t\n",
			model.QAU(total), n, model.QAU(iss.Total), model.QAU(annual),
			model.StakingAPY(annual, total)*100, model.QAU(annual)/float64(n))
	}
	return w.Flush()
}

func cmdProject(args []string) error {
	fs := flag.NewFlagSet("project", flag.ExitOnError)
	c := addCommonFlags(fs)
	years := fs.Int("years", 20, "projection horizon in years")
	supply := fs.Int64("supply", 20_000_000, "initial total supply, in whole QAU")
	stakeRatio := fs.Float64("stake-ratio", 0.35, "fraction of LIQUID supply that is staked")
	noVesting := fs.Bool("no-vesting", false, "treat all supply as liquid (ignore the 15M vesting lock)")
	txPerDay := fs.Int64("tx-per-day", 0, "transactions per day in year 1")
	gasPerTx := fs.Int64("gas-per-tx", 21_000, "mean gas per transaction")
	baseFee := fs.Int64("basefee", 0, "base fee per gas in gwei (burned in full)")
	tip := fs.Int64("tip", 0, "priority fee per gas in gwei (paid to proposer)")
	growth := fs.Float64("growth", 0, "annual transaction volume growth (0.5 = +50%/yr)")
	burnShare := fs.Float64("burn-share", 0, "annual burn as a fraction of supply (0.02 = 2%/yr); overrides nominal fee flags")
	feeMarket := fs.Bool("fee-market", false, "derive base fee from demand vs gas target (EIP-1559) instead of trusting -basefee")
	congestion := fs.Int64("congestion-basefee", 100, "assumed clearing base fee in gwei once demand reaches the gas target (-fee-market only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := c.params()
	if err != nil {
		return err
	}

	sc := model.Scenario{
		Params:               p,
		Years:                *years,
		InitialSupplyWei:     model.WeiFromQAU(*supply),
		StakeRatioOfFloat:    *stakeRatio,
		StakePerValidatorWei: c.stakeEach(),
		MinValidators:        6,
		Fees: model.FeeModel{
			TxPerDay:    *txPerDay,
			GasPerTx:    *gasPerTx,
			BaseFeeGwei: *baseFee,
			TipGwei:     *tip,
		},
		FeeGrowthPerYear:       *growth,
		BurnAsFractionOfSupply: *burnShare,
	}
	if !*noVesting {
		sc.Vesting = model.MainnetVesting()
	}
	if *feeMarket {
		fm := model.MainnetFeeMarket(p, *congestion)
		sc.Fee1559 = &fm
	}

	rows, err := sc.Run()
	if err != nil {
		return err
	}

	fmt.Printf("preset=%s F=%d  stake-ratio=%.0f%% of float  vesting=%v  ", *c.preset, p.BaseRewardFactor, *stakeRatio*100, !*noVesting)
	if *burnShare > 0 {
		fmt.Printf("burn=%.2f%% of supply/yr\n\n", *burnShare*100)
	} else if *feeMarket {
		fm := model.MainnetFeeMarket(p, *congestion)
		fmt.Printf("tx/day(Y1)=%d growth=%.0f%% fee-market=1559\n", *txPerDay, *growth*100)
		fmt.Printf("  gas target %d/block, limit %d/block, %d blocks/yr; floor %d gwei, congestion assumption %d gwei\n\n",
			fm.GasTargetPerBlock, fm.GasLimitPerBlock, fm.BlocksPerYear, fm.MinBaseFeeGwei, fm.CongestionBaseFeeGwei)
	} else {
		fmt.Printf("tx/day(Y1)=%d basefee=%d gwei growth=%.0f%%\n", *txPerDay, *baseFee, *growth*100)
		// A fixed nominal base fee has no EIP-1559 feedback: on the real chain
		// the base fee tracks block fullness and is repriced against fiat, so it
		// falls as the token appreciates. Compounding a constant gwei price for
		// many years therefore manufactures deflation that cannot occur. Say so
		// rather than letting the reader trust the tail of the table.
		if *baseFee > 0 && (*years > 5 || *growth > 0) {
			fmt.Printf("CAUTION: nominal base fee is exogenous here (no 1559 fullness feedback, no fiat repricing).\n" +
				"         Prefer -fee-market (endogenous) or -burn-share for long horizons.\n")
		}
		fmt.Println()
	}

	w := newTab()
	if *feeMarket {
		fmt.Fprintln(w, "year\tsupply\tstake\tvals\tissuance\tburn\tnet\tAPY\tnet infl\tbasefee\tutil\t")
		for _, r := range rows {
			fmt.Fprintf(w, "%d\t%.0f\t%.0f\t%d\t%.0f\t%.0f\t%.0f\t%.2f%%\t%.3f%%\t%d gwei\t%.4f\t\n",
				r.Year, model.QAU(r.SupplyWei), model.QAU(r.StakeWei), r.Validators,
				model.QAU(r.IssuanceWei), model.QAU(r.BurnWei), model.QAU(r.NetWei),
				r.StakingAPY*100, r.NetInflation*100, r.BaseFeeGwei, r.Utilization)
		}
	} else {
		fmt.Fprintln(w, "year\tsupply\tfloat\tstake\tvals\tissuance\tburn\tnet\tAPY\tgross infl\tnet infl\tQAU/val/yr\t")
		for _, r := range rows {
			fmt.Fprintf(w, "%d\t%.0f\t%.0f\t%.0f\t%d\t%.0f\t%.0f\t%.0f\t%.2f%%\t%.3f%%\t%.3f%%\t%.0f\t\n",
				r.Year, model.QAU(r.SupplyWei), model.QAU(r.FloatWei), model.QAU(r.StakeWei), r.Validators,
				model.QAU(r.IssuanceWei), model.QAU(r.BurnWei), model.QAU(r.NetWei),
				r.StakingAPY*100, r.GrossInflation*100, r.NetInflation*100,
				model.QAU(r.ValidatorRevWei))
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	last := rows[len(rows)-1]
	fmt.Printf("\nafter %d years: supply %.0f QAU (%+.0f vs start), cumulative issuance drives %.2f%% total growth\n",
		*years, model.QAU(last.SupplyWei),
		model.QAU(last.SupplyWei)-float64(*supply),
		(model.QAU(last.SupplyWei)/float64(*supply)-1)*100)
	return nil
}

func cmdSolve(args []string) error {
	fs := flag.NewFlagSet("solve", flag.ExitOnError)
	c := addCommonFlags(fs)
	apy := fs.Float64("apy", 0.05, "target staking APY as a fraction (0.05 = 5%)")
	at := fs.Int64("at", 4_000_000, "total stake at which the target applies, in whole QAU")
	maxF := fs.Int64("max-f", 1_000_000, "search ceiling for BaseRewardFactor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := c.params()
	if err != nil {
		return err
	}

	f, err := model.SolveBaseRewardFactor(p, model.WeiFromQAU(*at), c.stakeEach(), *apy, *maxF)
	if err != nil {
		return err
	}

	p.BaseRewardFactor = f
	n := *at / *c.perValidator
	if n < 1 {
		n = 1
	}
	stakes := model.UniformStakes(int(n), c.stakeEach())
	total := new(big.Int).Mul(c.stakeEach(), big.NewInt(n))
	iss, err := model.EpochIssuance(stakes, p)
	if err != nil {
		return err
	}
	annual := model.AnnualIssuanceWei(iss.Total, p)

	fmt.Printf("preset=%s  target APY %.2f%% at %d QAU staked\n\n", *c.preset, *apy*100, *at)
	w := newKV()
	fmt.Fprintf(w, "BaseRewardFactor\t%d\t\n", f)
	fmt.Fprintf(w, "resulting APY\t%.4f%%\t\n", model.StakingAPY(annual, total)*100)
	fmt.Fprintf(w, "annual issuance\t%.0f QAU\t\n", model.QAU(annual))
	fmt.Fprintf(w, "issuance / epoch\t%.4f QAU\t\n", model.QAU(iss.Total))
	return w.Flush()
}

func cmdBreakEven(args []string) error {
	fs := flag.NewFlagSet("breakeven", flag.ExitOnError)
	c := addCommonFlags(fs)
	at := fs.Int64("at", 4_000_000, "total stake, in whole QAU")
	gasPerTx := fs.Int64("gas-per-tx", 21_000, "mean gas per transaction")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := c.params()
	if err != nil {
		return err
	}

	fmt.Printf("preset=%s F=%d  stake=%d QAU  gas/tx=%d\n\n", *c.preset, p.BaseRewardFactor, *at, *gasPerTx)
	w := newTab()
	fmt.Fprintln(w, "baseFee (gwei)\tQAU burned/tx\ttx/day for net zero\t")
	for _, fee := range []int64{1, 10, 50, 100, 300, 1_000, 5_000} {
		be, err := model.SolveBreakEvenBurn(p, model.WeiFromQAU(*at), c.stakeEach(), *gasPerTx, fee)
		if err != nil {
			return err
		}
		perTx := float64(*gasPerTx) * float64(fee) / 1e9
		fmt.Fprintf(w, "%d\t%.6f\t%.0f\t\n", fee, perTx, be.TxPerDayNeeded)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	be, err := model.SolveBreakEvenBurn(p, model.WeiFromQAU(*at), c.stakeEach(), *gasPerTx, 1)
	if err != nil {
		return err
	}
	fmt.Printf("\nannual issuance to offset: %.0f QAU (%.1f QAU/day)\n",
		model.QAU(be.AnnualIssuanceWei), model.QAU(be.DailyBurnNeededWei))
	return nil
}
