// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// R102-WEIGHTED-PROPOSER / R103-COMMITTEE-PARTITION regression tests
// (2026-08-30). Each test contracts a "fails without the fix" property:
// before R102 there was no stake weighting at all (a 90%-stake validator
// drew slots exactly as often as a 1%-stake one), and before R103 a
// 200-validator epoch attested with at most 4096 sampling slots, breaking
// finality solvability beyond n≈6144.

// r102NewQPOS builds a QPOS over n validators with individually weighted
// stakes (QAU * 1e18) and genesis-root entropy for the epoch-0/1 seed domain.
func r102NewQPOS(t *testing.T, qauStakes []int64, cutover uint64) *QPOS {
	t.Helper()
	vals := make([]*Validator, len(qauStakes))
	for i, s := range qauStakes {
		vals[i] = &Validator{
			Address: types.Address{byte(i + 1)},
			Stake:   new(big.Int).Mul(big.NewInt(s), big.NewInt(1e18)),
			Active:  true,
		}
	}
	vs, err := NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	q, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	if err := SetGenesisTime(1788110700); err != nil {
		t.Fatalf("SetGenesisTime: %v", err)
	}
	q.SetGenesisRoot(types.Hash{0x42})
	q.SetWeightedProposerCutover(cutover)
	return q
}

// TestR102_WeightedDominance: with the weighted regime active, a validator
// holding 1_000_000/1_000_003 of total stake must win every slot draw of
// epochs 0-1 (64 independent draws); the pre-R102 uniform shuffle would have
// given it ~25% on a 4-validator set.
func TestR102_WeightedDominance(t *testing.T) {
	q := r102NewQPOS(t, []int64{1000000, 1, 1, 1}, 0)
	heavy := q.validators.GetValidatorByIndex(0)
	for epochS := uint64(0); epochS < 2; epochS++ {
		base := epochS * SlotsPerEpoch
		for slot := base; slot < base+SlotsPerEpoch; slot++ {
			p, err := q.GetProposerForSlot(slot)
			if err != nil {
				t.Fatalf("slot %d: %v", slot, err)
			}
			if p.Address != heavy.Address {
				t.Fatalf("slot %d: heavyweight validator skipped (got %x)", slot, p.Address[:4])
			}
		}
	}
}

// TestR102_DeterminismAcrossInstances: two independent QPOS instances with
// identical state must derive byte-identical proposer schedules (this is the
// no-fork property of the weighted regime).
func TestR102_DeterminismAcrossInstances(t *testing.T) {
	stakes := []int64{6000, 4000, 9000, 2500, 1000, 7000}
	a := r102NewQPOS(t, stakes, 0)
	b := r102NewQPOS(t, stakes, 0)
	for slot := uint64(0); slot < 2*SlotsPerEpoch; slot++ {
		pa, errA := a.GetProposerForSlot(slot)
		pb, errB := b.GetProposerForSlot(slot)
		if (errA != nil) != (errB != nil) {
			t.Fatalf("slot %d: error asymmetry %v vs %v", slot, errA, errB)
		}
		if pa != nil && pa.Address != pb.Address {
			t.Fatalf("slot %d: divergent proposers %x vs %x", slot, pa.Address[:4], pb.Address[:4])
		}
	}
}

// TestR102_CensusMatchesElected: the census-committed proposer index
// (getProposerIndexForSlotUnlocked, embedded on-chain for rewards) must equal
// the index of the elected proposer from GetProposerForSlot in the weighted
// regime — otherwise rewards would be paid to a different validator than the
// one the network verifies as proposer.
func TestR102_CensusMatchesElected(t *testing.T) {
	q := r102NewQPOS(t, []int64{9000, 3000, 1500, 800, 600, 400}, 0)
	for slot := uint64(0); slot < SlotsPerEpoch; slot++ {
		p, err := q.GetProposerForSlot(slot)
		if err != nil {
			t.Fatalf("slot %d: %v", slot, err)
		}
		idx := q.GetProposerIndexForSlot(slot)
		want := q.validators.GetValidatorIndex(p.Address)
		if idx != want {
			t.Fatalf("slot %d: census proposer index %d != elected index %d", slot, idx, want)
		}
	}
}

// TestR102_LegacyBelowCutover: slots BELOW the cutover epoch must stay on the
// legacy uniform shuffle byte-for-byte (direct comparison against the legacy
// shuffle computation internals).
func TestR102_LegacyBelowCutover(t *testing.T) {
	q := r102NewQPOS(t, []int64{9000, 100, 100, 100}, 5) // cutover at epoch 5
	// epoch 0 slot 7: legacy expects shuffle[7 % n]'s validator (no slash/inactive).
	expectShuffled := q.computeShuffleForEpoch(0, 4)
	wantIdx := expectShuffled[7%len(expectShuffled)]
	p, err := q.GetProposerForSlot(7)
	if err != nil {
		t.Fatalf("GetProposerForSlot(7): %v", err)
	}
	gotIdx := q.validators.GetValidatorIndex(p.Address)
	if gotIdx != wantIdx {
		t.Fatalf("pre-cutover proposer diverged from legacy shuffle: got %d want %d", gotIdx, wantIdx)
	}
}

// TestR103_PartitionCoversAll: in the partitioned regime (epoch >= cutover,
// n > 96), every validator must be in EXACTLY ONE slot committee per epoch,
// each committee must meet the BFT floor, and the locked (attestation-gate)
// path must agree membership-for-membership with the public path.
func TestR103_PartitionCoversAll(t *testing.T) {
	const n = 200
	stakes := make([]int64, n)
	for i := range stakes {
		stakes[i] = 6000 + int64(i) // arbitrary non-uniform stake vector
	}
	q := r102NewQPOS(t, stakes, 0)

	seen := make(map[string]int) // address → membership count
	for slot := uint64(0); slot < SlotsPerEpoch; slot++ {
		pub, err := q.GetCommitteeForSlot(slot)
		if err != nil {
			t.Fatalf("slot %d: %v", slot, err)
		}
		if len(pub) < 3 {
			t.Fatalf("slot %d: committee size %d below BFT floor", slot, len(pub))
		}
		// Locked path must agree exactly (it gates ProcessAttestation).
		q.mu.Lock()
		internal, err := q.getCommitteeForSlotLocked(slot)
		q.mu.Unlock()
		if err != nil {
			t.Fatalf("slot %d locked: %v", slot, err)
		}
		if len(internal) != len(pub) {
			t.Fatalf("slot %d: locked size %d != public size %d", slot, len(internal), len(pub))
		}
		setInternal := make(map[string]bool, len(internal))
		for _, v := range internal {
			setInternal[string(v.Address[:])] = true
		}
		for _, v := range pub {
			if !setInternal[string(v.Address[:])] {
				t.Fatalf("slot %d: locked path missing member %x", slot, v.Address[:4])
			}
			seen[string(v.Address[:])]++
		}
	}
	if len(seen) != n {
		t.Fatalf("partition coverage: %d/%d validators attested this epoch", len(seen), n)
	}
	for addr, c := range seen {
		if c != 1 {
			t.Fatalf("validator %x appears %d times (must be exactly 1)", addr[:4], c)
		}
	}
}

// TestR103_DisabledBelowCutover: without the cutover the legacy sampling
// regime must remain — committee sizes follow the legacy formula and
// full-epoch coverage is NOT guaranteed (sampling overlap allowed).
func TestR103_DisabledBelowCutover(t *testing.T) {
	const n = 200
	stakes := make([]int64, n)
	for i := range stakes {
		stakes[i] = 6000
	}
	q := r102NewQPOS(t, stakes, ^uint64(0)) // MaxUint64 = feature off

	// Legacy formula: vpc = clamp(n/32, 3, 128) = 6 for n=200.
	pub, err := q.GetCommitteeForSlot(3)
	if err != nil {
		t.Fatalf("GetCommitteeForSlot: %v", err)
	}
	if len(pub) != 6 {
		t.Fatalf("legacy sampling size: got %d, want 6", len(pub))
	}
}
