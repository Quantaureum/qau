package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestEB_ProposerDistributionAcrossCutover drives the REAL live proposer
// selection path (GetProposerForSlot → weightedProposerEnabled →
// buildWeightedEpochTableLocked → consensusWeight) and verifies that, in the
// weighted regime, proposer draws follow EFFECTIVE balance (whales capped at
// 2048), not raw stake.
//
// Setup: two "whale" validators at 6000 QAU + four small at 100 QAU, cutover
// at epoch 0 (weighted+effective-balance regime active from the start).
//
// Under RAW stake the four small validators would draw a combined
//
//	4*100 / (2*6000 + 4*100) = 400/12400 = 3.2%
//
// of slots. Under EFFECTIVE balance the whales are capped 6000→2048, so the
// small validators draw a combined
//
//	4*100 / (2*2048 + 4*100) = 400/4496 = 8.9%
//
// i.e. their share nearly triples. Over many epochs the observed small-share
// must land close to the effective-balance prediction and clearly above the
// raw-stake prediction — proving the cap reshapes the live proposer path.
func TestEB_ProposerDistributionAcrossCutover(t *testing.T) {
	stakes := []int64{6000, 6000, 100, 100, 100, 100}
	q := ebNewQPOS(t, stakes, 0) // effective-balance regime active from epoch 0

	idxByAddr := make(map[types.Address]int)
	for i := 0; i < q.validators.Size(); i++ {
		idxByAddr[q.validators.GetValidatorByIndex(i).Address] = i
	}

	const epochs = 40 // 40 * 32 = 1280 slot draws — enough to stabilize
	wins := make(map[int]int)
	total := 0
	for epoch := uint64(0); epoch < epochs; epoch++ {
		base := epoch * SlotsPerEpoch
		for slot := base; slot < base+SlotsPerEpoch; slot++ {
			p, err := q.GetProposerForSlot(slot)
			if err != nil {
				continue
			}
			wins[idxByAddr[p.Address]]++
			total++
		}
	}
	if total == 0 {
		t.Fatal("no proposer draws recorded")
	}

	smallWins := wins[2] + wins[3] + wins[4] + wins[5]
	smallShare := float64(smallWins) / float64(total)

	const rawPrediction = 400.0 / 12400.0 // 0.0323 — if raw stake were used
	const effPrediction = 400.0 / 4496.0  // 0.0890 — effective balance (cap 2048)

	t.Logf("whale0=%d whale1=%d small(sum)=%d total=%d",
		wins[0], wins[1], smallWins, total)
	t.Logf("small share observed=%.4f | raw-stake predicts=%.4f | effective-balance predicts=%.4f",
		smallShare, rawPrediction, effPrediction)

	// The observed small-share must be much closer to the effective-balance
	// prediction than to the raw-stake prediction. Midpoint = 0.0607.
	midpoint := (rawPrediction + effPrediction) / 2
	if smallShare <= midpoint {
		t.Fatalf("small share %.4f is not consistent with effective-balance capping "+
			"(expected ~%.4f, raw-stake would give ~%.4f)",
			smallShare, effPrediction, rawPrediction)
	}

	// The two whales (both 6000, both capped to 2048) must draw roughly
	// equally — neither should dominate the other by more than ~35%.
	hi, lo := wins[0], wins[1]
	if hi < lo {
		hi, lo = lo, hi
	}
	if lo == 0 || float64(hi)/float64(lo) > 1.35 {
		t.Fatalf("equal-stake whales drew too unevenly: %d vs %d", wins[0], wins[1])
	}
}
