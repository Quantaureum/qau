// Quantaureum Node source, version 1.0.0.
package node

import (
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/quantaureum/qau/types"
)

// D1 committee sampler tests: the pinned-row domain (n <= 7) must produce the
// whole roster bit-identically to the pre-sampler rule; above it the sampler
// must deterministically return a 7-entry stake-weighted sample of the captured
// roster, and missing stakes/seeds must fail closed instead of guessing.

func tdilithium3TestRosterAt(t *testing.T, epoch uint64, n int, stakes []int64, seed types.Hash, seedSet bool) *tdilithium3DKGEpochRoster {
	t.Helper()
	_, entries := tdilithium3DKGRosterTestValidators(t, n)
	for i := range entries {
		entries[i].Stake = big.NewInt(stakes[i%len(stakes)])
	}
	return &tdilithium3DKGEpochRoster{Epoch: epoch, Entries: entries, SampleSeed: seed, SampleSeedSet: seedSet}
}


func TestTDilithium3DKGCommitteeSelection(t *testing.T) {
	seed := tdilithium3DKGRosterTestHash(0x7A)

	t.Run("within the pinned row the whole roster is the committee", func(t *testing.T) {
		for _, n := range []int{6, 7} {
			roster := tdilithium3TestRosterAt(t, 9, n, []int64{33}, seed, true)
			selection, err := tdilithium3DKGCommitteeSelection(roster)
			if err != nil {
				t.Fatalf("n=%d selection: %v", n, err)
			}
			if len(selection) != n {
				t.Fatalf("n=%d: selection has %d members", n, len(selection))
			}
			for i, index := range selection {
				if index != i {
					t.Fatalf("n=%d: selection[%d]=%d, want identity", n, i, index)
				}
			}
			if _, err := tdilithium3DKGCommitteeForSelectedRoster(roster, selection); err != nil {
				t.Fatalf("n=%d committee: %v", n, err)
			}
			// Continuity: seeds must not matter inside the pinned row —
			// an unset record yields the identical committee.
			roster.SampleSeedSet = false
			again, err := tdilithium3DKGCommitteeSelection(roster)
			if err != nil || !reflect.DeepEqual(again, selection) {
				t.Fatalf("n=%d: unset seed changed the committee path: %v", n, err)
			}
		}
	})

	t.Run("oversized rosters take a deterministic 7-entry sample", func(t *testing.T) {
		stakes := []int64{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
		roster := tdilithium3TestRosterAt(t, 12, 10, stakes, seed, true)
		first, err := tdilithium3DKGCommitteeSelection(roster)
		if err != nil {
			t.Fatalf("selection: %v", err)
		}
		if len(first) != tdilithium3DKGCommitteeSampleTarget {
			t.Fatalf("sample has %d members, want %d", len(first), tdilithium3DKGCommitteeSampleTarget)
		}
		// Deterministic: same inputs, same output.
		again, err := tdilithium3DKGCommitteeSelection(roster)
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatalf("sample is not deterministic: %v vs %v (%v)", first, again, err)
		}
		// Distinct and sorted (canonical order), in range.
		seen := map[int]bool{}
		for i, index := range first {
			if seen[index] || index < 0 || index >= 10 {
				t.Fatalf("selection index %d invalid", index)
			}
			seen[index] = true
			if i > 0 && first[i-1] > index {
				t.Fatal("selection is not in ascending roster order")
			}
		}
		// Committee shape: 7 participants, threshold 5.
		committee, err := tdilithium3DKGCommitteeForSelectedRoster(roster, first)
		if err != nil {
			t.Fatalf("committee: %v", err)
		}
		if len(committee.Participants) != 7 || committee.Threshold != 5 {
			t.Fatalf("committee = %d participants, t=%d; want 7/5", len(committee.Participants), committee.Threshold)
		}
		// Bindings map participant ids to the selected entries positionally.
		bindings, err := tdilithium3DKGRosterBindings(roster, committee)
		if err != nil {
			t.Fatalf("bindings: %v", err)
		}
		for position, binding := range bindings {
			if binding.ParticipantID != uint32(position)+1 {
				t.Fatalf("binding position mismatch at %d", position)
			}
			var wantAddress types.Address = roster.Entries[first[position]].Address
			if types.Address(binding.ValidatorAddress) != wantAddress {
				t.Fatalf("binding %d bound to the wrong entry", position)
			}
		}
		// A different seed must sample a different committee with
		// overwhelming probability (100 candidate seeds all differing would
		// be a distribution red flag; require at least one change over 8).
		variants := 0
		for round := 0; round < 8; round++ {
			other := tdilithium3DKGRosterTestHash(byte(0x50 + round))
			alt, err := tdilithium3DKGCommitteeSelection(tdilithium3TestRosterAt(t, 12, 10, stakes, other, true))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(alt, first) {
				variants++
			}
		}
		if variants == 0 {
			t.Fatal("8 distinct seeds produced identical committees — the seed is not driving the sample")
		}
	})

	t.Run("seed weighting favors larger stakes measurably", func(t *testing.T) {
		// One dominant staker among many small ones; over many seeds the
		// dominant address must appear in far more than its uniform share
		// (7/10 * 64 ≈ 44.8 baseline appearances; weight 8:1:1... expect >>44).
		n := 10
		stakes := make([]int64, n)
		for i := range stakes {
			stakes[i] = 1
		}
		// entry 3 (canonical roster order) is the whale.
		stakes[3] = 56 // 56 of 68 total → ~82% inclusion mass share
		guard := tdilithium3TestRosterAt(t, 5, n, stakes, seed, true)
		dominant := guard.Entries[3].Address
		appearances := 0
		for round := 0; round < 64; round++ {
			roundSeed := tdilithium3DKGRosterTestHash(byte(round + 1))
			sel, err := tdilithium3DKGCommitteeSelection(tdilithium3TestRosterAt(t, 5, n, stakes, roundSeed, true))
			if err != nil {
				t.Fatal(err)
			}
			for _, index := range sel {
				if guard.Entries[index].Address == dominant {
					appearances++
					break
				}
			}
		}
		if appearances < 46 {
			t.Fatalf("dominant staker appeared in %d/64 samples, below the weighted baseline", appearances)
		}
	})

	t.Run("fail closed without a recorded seed or stakes", func(t *testing.T) {
		roster := tdilithium3TestRosterAt(t, 12, 10, []int64{33}, types.Hash{}, false)
		if _, err := tdilithium3DKGCommitteeSelection(roster); !errors.Is(err, errTDilithium3DKGSamplingUnavailable) {
			t.Fatalf("n=10 without a seed sampled: %v", err)
		}
		weird := tdilithium3TestRosterAt(t, 12, 10, []int64{33}, seed, true)
		weird.Entries[4].Stake = nil
		if _, err := tdilithium3DKGCommitteeSelection(weird); !errors.Is(err, errTDilithium3DKGSamplingUnavailable) {
			t.Fatalf("n=10 with a stakeless entry sampled: %v", err)
		}
		zero := tdilithium3TestRosterAt(t, 12, 10, []int64{33}, seed, true)
		zero.Entries[4].Stake = big.NewInt(0)
		if _, err := tdilithium3DKGCommitteeSelection(zero); !errors.Is(err, errTDilithium3DKGSamplingUnavailable) {
			t.Fatalf("n=10 with a zero-stake entry sampled: %v", err)
		}
	})
}
