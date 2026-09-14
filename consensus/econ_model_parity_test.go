// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/economics/model"
)

// newQPOSWithStakes builds a QPOS whose validator set carries exactly the
// supplied stakes.
//
// setupQPOSWithKeys hardcodes 32 QAU per validator, and ValidatorSet.Validators()
// hands back deep copies, so mutating the returned slice does not change
// consensus state. The set therefore has to be rebuilt.
func newQPOSWithStakes(t *testing.T, stakes []*big.Int) (*QPOS, []*Validator) {
	t.Helper()

	qpos, _ := setupQPOSWithKeys(len(stakes))
	template := qpos.validators.Validators()

	vals := make([]*Validator, len(stakes))
	for i, v := range template {
		vals[i] = &Validator{
			Address:        v.Address,
			PublicKeyBytes: v.PublicKeyBytes,
			Stake:          new(big.Int).Set(stakes[i]),
			Active:         true,
		}
	}

	vs, err := NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos.validators = vs

	// NewValidatorSet may reorder; read the authoritative order back.
	return qpos, vs.Validators()
}

// TestEconModelParityWithConsensus pins economics/model.BaseRewardWei to the
// authoritative consensus implementation.
//
// The model package deliberately re-implements the base-reward arithmetic
// instead of importing consensus, because economics is L3 and consensus is L5
// and the layering forbids the reverse dependency (see AGENTS.md). That
// duplication is only safe while this test passes: any change to
// CalculateBaseReward, calculateBaseRewardUnlocked, BaseRewardFactor or the
// divisor structure must be mirrored in economics/model or this test fails.
//
// The comparison is bit-exact on purpose. An approximate match would hide
// truncation-order regressions, which is precisely the class of bug that
// CONS-006 and R46-CS-05 were filed for.
func TestEconModelParityWithConsensus(t *testing.T) {
	// MainnetParams must describe the constants actually compiled in. Every
	// EM-2 constant is checked, not just F: the divisor and the proposer
	// weights are equally capable of silently changing issuance, and the
	// divisor in particular used to be an unnamed literal duplicated across
	// two call sites.
	p := model.MainnetParams()
	if p.BaseRewardFactor != BaseRewardFactor {
		t.Fatalf("model BaseRewardFactor = %d, consensus.BaseRewardFactor = %d",
			p.BaseRewardFactor, BaseRewardFactor)
	}
	if p.BaseRewardsPerEpoch != BaseRewardsPerEpoch {
		t.Fatalf("model BaseRewardsPerEpoch = %d, consensus.BaseRewardsPerEpoch = %d",
			p.BaseRewardsPerEpoch, BaseRewardsPerEpoch)
	}
	if p.ProposerWeight != ProposerWeight {
		t.Fatalf("model ProposerWeight = %d, consensus.ProposerWeight = %d",
			p.ProposerWeight, ProposerWeight)
	}
	if p.WeightDenominator != WeightDenominator {
		t.Fatalf("model WeightDenominator = %d, consensus.WeightDenominator = %d",
			p.WeightDenominator, WeightDenominator)
	}
	if p.SlotsPerEpoch != int64(SlotsPerEpoch) {
		t.Fatalf("model SlotsPerEpoch = %d, consensus SlotsPerEpoch = %d",
			p.SlotsPerEpoch, SlotsPerEpoch)
	}
	// The zero-dust argument in economics/model.Attribution depends on the
	// denominator dividing 1e9. Guard it here so a future weight change cannot
	// quietly make the per-validator split inexact.
	if model.WeiPerGwei%int(p.WeightDenominator) != 0 {
		t.Fatalf("WeightDenominator %d does not divide %d; the per-validator split is no longer exact",
			p.WeightDenominator, model.WeiPerGwei)
	}

	cases := []struct {
		name   string
		stakes []*big.Int
	}{
		{
			name:   "mainnet 6x6000 QAU",
			stakes: model.UniformStakes(6, model.WeiFromQAU(6_000)),
		},
		{
			name:   "uniform 128x6000 QAU",
			stakes: model.UniformStakes(128, model.WeiFromQAU(6_000)),
		},
		{
			name: "skewed whale plus minimums",
			stakes: []*big.Int{
				model.WeiFromQAU(1_000_000),
				model.WeiFromQAU(6_000),
				model.WeiFromQAU(6_000),
				model.WeiFromQAU(6_001),
			},
		},
		{
			name: "gwei truncation boundary",
			stakes: []*big.Int{
				big.NewInt(999_999_999),               // < 1 gwei, truncates to 0
				big.NewInt(1_000_000_001),             // just over 1 gwei
				new(big.Int).SetUint64(1_000_000_007), // non-zero remainder
			},
		},
		{
			name:   "single validator",
			stakes: []*big.Int{model.WeiFromQAU(6_000)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qpos, validators := newQPOSWithStakes(t, tc.stakes)

			total := big.NewInt(0)
			for _, v := range validators {
				total.Add(total, v.Stake)
			}

			for i, v := range validators {
				wantPublic := qpos.CalculateBaseReward(i)
				wantInternal := qpos.calculateBaseRewardUnlocked(i)
				got := model.BaseRewardWei(v.Stake, total, p)

				if wantPublic.Cmp(wantInternal) != 0 {
					t.Fatalf("validator %d: consensus public path %s != internal path %s",
						i, wantPublic, wantInternal)
				}
				if got.Cmp(wantPublic) != 0 {
					t.Fatalf("validator %d (stake %s): model %s != consensus %s",
						i, v.Stake, got, wantPublic)
				}
			}
		})
	}
}

// TestEconModelParityEpochIssuance pins the model's epoch-issuance total to
// what the consensus reward census actually pays out under EM-2: the sum of
// every validator's base reward, split 56/64 to attesters and 8/64 to the
// proposer pool.
//
// Unlike the pre-EM-2 rule, the total is independent of how many slots were
// proposed, so the model can predict it from the stake distribution alone.
func TestEconModelParityEpochIssuance(t *testing.T) {
	const n = 6
	stakeEach := model.WeiFromQAU(6_000)

	qpos, validators := newQPOSWithStakes(t, model.UniformStakes(n, stakeEach))

	// EM-2 total issuance == sum of base rewards. No per-slot term.
	expected := big.NewInt(0)
	for i := range validators {
		expected.Add(expected, qpos.calculateBaseRewardUnlocked(i))
	}

	iss, err := model.EpochIssuance(model.UniformStakes(n, stakeEach), model.MainnetParams())
	if err != nil {
		t.Fatal(err)
	}
	if iss.Total.Cmp(expected) != 0 {
		t.Fatalf("epoch issuance: model %s != consensus-derived %s", iss.Total, expected)
	}

	// Proposer share must be exactly the Altair weight, and attesters the rest.
	wantProposer := new(big.Int).Mul(expected, big.NewInt(ProposerWeight))
	wantProposer.Div(wantProposer, big.NewInt(WeightDenominator))
	if iss.Proposer.Cmp(wantProposer) != 0 {
		t.Fatalf("proposer component: model %s != %s", iss.Proposer, wantProposer)
	}
	if sum := new(big.Int).Add(iss.Attester, iss.Proposer); sum.Cmp(iss.Total) != 0 {
		t.Fatalf("attester+proposer %s != total %s", sum, iss.Total)
	}

	t.Logf("EM-2 parity: %s wei/epoch (%.6f QAU) at %d validators x 6,000 QAU, proposer %.4f%%",
		iss.Total, model.QAU(iss.Total), n, iss.ProposerShare()*100)
}

// TestEconModelParityAttribution is the strong form of parity: it compares the
// consensus census output PER VALIDATOR against model.EpochIssuanceAttributed,
// not merely the epoch total.
//
// This is possible only because the per-validator split is exact (base rewards
// are gwei-granular and WeightDenominator divides 1e9), so there is no dust to
// explain away. A total-only comparison would pass even if the split between
// attesters and the proposer pool were wrong in compensating directions.
func TestEconModelParityAttribution(t *testing.T) {
	stakeSets := [][]*big.Int{
		model.UniformStakes(6, model.WeiFromQAU(6_000)),
		model.UniformStakes(32, model.WeiFromQAU(6_000)),
		{
			model.WeiFromQAU(1_000_000),
			model.WeiFromQAU(6_000),
			model.WeiFromQAU(6_000),
			model.WeiFromQAU(6_001),
		},
	}

	for _, stakes := range stakeSets {
		qpos, validators := newQPOSWithStakes(t, stakes)
		actual := make([]*big.Int, len(validators))
		pool := big.NewInt(0)

		for i := range validators {
			base := qpos.calculateBaseRewardUnlocked(i)
			share := new(big.Int).Mul(base, big.NewInt(WeightDenominator-ProposerWeight))
			share.Div(share, big.NewInt(WeightDenominator))
			contrib := new(big.Int).Mul(base, big.NewInt(ProposerWeight))
			contrib.Div(contrib, big.NewInt(WeightDenominator))
			actual[i] = share
			pool.Add(pool, contrib)
		}

		vstakes := make([]*big.Int, len(validators))
		for i, v := range validators {
			vstakes[i] = v.Stake
		}
		attr, err := model.EpochIssuanceAttributed(vstakes, model.MainnetParams())
		if err != nil {
			t.Fatal(err)
		}

		if len(attr.AttesterWei) != len(actual) {
			t.Fatalf("attribution length %d != %d", len(attr.AttesterWei), len(actual))
		}
		for i := range actual {
			if attr.AttesterWei[i].Cmp(actual[i]) != 0 {
				t.Fatalf("n=%d validator %d attester: model %s != consensus %s",
					len(actual), i, attr.AttesterWei[i], actual[i])
			}
		}
		if attr.ProposerPoolWei.Cmp(pool) != 0 {
			t.Fatalf("n=%d proposer pool: model %s != consensus %s",
				len(actual), attr.ProposerPoolWei, pool)
		}
		if attr.DustWei.Sign() != 0 {
			t.Fatalf("n=%d dust %s wei, want 0", len(actual), attr.DustWei)
		}
		t.Logf("n=%-3d attribution parity exact: pool=%s wei, dust=0", len(actual), pool)
	}
}

// TestProposerShareIsAltairWeight replaces TestProposerRewardQuotientIsDeadConstant.
//
// That test asserted the DEFECT: consensus declared ProposerRewardQuotient = 8
// ("proposer gets 1/8 of attestation rewards") while the census paid a full base
// reward per proposed slot, handing proposers 32/(N+32) of all issuance — 84.2%
// at 6 validators against an intended 12.5%. Its own comment said it would fail
// the day the census was corrected. EM-2 corrected it, so this is the
// replacement, asserting the intent instead of the defect.
//
// The key property is that the share does NOT move with the validator count.
// The old rule's share swung from 84.2% at N=6 to 1.1% at N=3000.
func TestProposerShareIsAltairWeight(t *testing.T) {
	want := float64(ProposerWeight) / float64(WeightDenominator)

	for _, n := range []int{1, 6, 32, 128, 1000} {
		iss, err := model.EpochIssuance(
			model.UniformStakes(n, model.WeiFromQAU(6_000)), model.MainnetParams())
		if err != nil {
			t.Fatal(err)
		}
		got := iss.ProposerShare()
		if diff := got - want; diff > 1e-9 || diff < -1e-9 {
			t.Fatalf("N=%d proposer share %.9f != Altair weight %.9f", n, got, want)
		}
		t.Logf("N=%-5d proposer share %.4f%% (weight %d/%d)", n, got*100, ProposerWeight, WeightDenominator)
	}

	// The pre-EM-2 rule is retained in the model purely as history; confirm it
	// still exhibits the defect so the contrast stays documented and testable.
	old, err := model.EpochIssuance(
		model.UniformStakes(6, model.WeiFromQAU(6_000)), model.PreEM2MainnetParams())
	if err != nil {
		t.Fatal(err)
	}
	if old.ProposerShare() < 0.8 {
		t.Fatalf("pre-EM-2 proposer share %.4f should still be ~0.842 (historical record)",
			old.ProposerShare())
	}
	t.Logf("pre-EM-2 contrast: proposer took %.1f%% at N=6", old.ProposerShare()*100)
}
