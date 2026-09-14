// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// buildCensusTestQPOS returns a QPOS with 6 active validators and no
// attestations. It is used to verify the on-chain anchored reward census
// (CNS-EPH-001): rewards must be identical whether computed from local P2P
// attestations (ProcessEpochRewards) or the on-chain census
// (ComputeEpochRewardsFromCensus).
func buildCensusTestQPOS(t *testing.T) *QPOS {
	t.Helper()
	stake := new(big.Int).Mul(big.NewInt(33000), big.NewInt(1_000_000_000_000_000_000)) // 33,000 QAU
	validators := make([]*Validator, 6)
	for i := 0; i < 6; i++ {
		validators[i] = &Validator{
			Address:        types.Address{byte(i + 1)},
			Stake:          new(big.Int).Set(stake),
			Active:         true,
			PublicKeyBytes: []byte{0xAA, 0xBB, byte(i + 1)},
		}
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	q, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	return q
}

// makeCensusSet builds a deterministic attestation census for the given epoch.
// Each validator attests exactly one distinct slot within the epoch.
func makeCensusSet(epoch uint64) []*Attestation {
	start := EpochStartSlot(epoch)
	var atts []*Attestation
	for vi := 0; vi < 6; vi++ {
		slot := start + uint64(vi)
		atts = append(atts, &Attestation{
			Slot:            slot,
			BeaconBlockRoot: types.Hash{byte(vi + 1)},
			Source:          AttestationCheckpoint{Epoch: epoch - 1, Root: types.Hash{0x11}},
			Target:          AttestationCheckpoint{Epoch: epoch, Root: types.Hash{0x22}},
			ValidatorIndex:  vi,
			Signature:       []byte{0xDE, 0xAD, byte(vi + 1)},
			KeyVersion:      1,
		})
	}
	return atts
}

// TestAttestationCensusRoundTrip verifies the block-header census wire format
// survives a serialize/deserialize round trip without losing any field that
// the reward computation depends on.
func TestAttestationCensusRoundTrip(t *testing.T) {
	const epoch = uint64(3)
	atts := makeCensusSet(epoch)

	serialized := SerializeAttestationCensus(atts, nil)
	if len(serialized) == 0 {
		t.Fatal("SerializeAttestationCensus returned empty payload for non-empty set")
	}

	got, _, err := DeserializeAttestationCensus(serialized)
	if err != nil {
		t.Fatalf("DeserializeAttestationCensus failed: %v", err)
	}
	if len(got) != len(atts) {
		t.Fatalf("round trip count mismatch: got %d want %d", len(got), len(atts))
	}

	for i, want := range atts {
		g := got[i]
		if g.Slot != want.Slot {
			t.Errorf("att %d slot: got %d want %d", i, g.Slot, want.Slot)
		}
		if g.BeaconBlockRoot != want.BeaconBlockRoot {
			t.Errorf("att %d root: got %x want %x", i, g.BeaconBlockRoot, want.BeaconBlockRoot)
		}
		if g.Source.Epoch != want.Source.Epoch || g.Target.Epoch != want.Target.Epoch {
			t.Errorf("att %d checkpoint epochs: got %d/%d want %d/%d",
				i, g.Source.Epoch, g.Target.Epoch, want.Source.Epoch, want.Target.Epoch)
		}
		if g.ValidatorIndex != want.ValidatorIndex {
			t.Errorf("att %d validator index: got %d want %d", i, g.ValidatorIndex, want.ValidatorIndex)
		}
		if string(g.Signature) != string(want.Signature) {
			t.Errorf("att %d signature mismatch", i)
		}
	}
}

// TestCensusRewardsMatchLocal is the core CNS-EPH-001 guarantee: for the SAME
// attestation set, the local P2P path (ProcessEpochRewards) and the on-chain
// census path (ComputeEpochRewardsFromCensus) must produce IDENTICAL rewards.
// Both delegate to computeEpochRewardsUnlocked, so this is a regression guard
// against future divergence between the two entry points that would re-fork
// the chain over epoch rewards.
func TestCensusRewardsMatchLocal(t *testing.T) {
	const epoch = uint64(3)
	q := buildCensusTestQPOS(t)
	atts := makeCensusSet(epoch)

	// Inject the same attestation set into the local (P2P) store.
	for _, a := range atts {
		q.attestations[a.Slot] = append(q.attestations[a.Slot], a)
	}

	local := q.ProcessEpochRewards(epoch)
	census := q.ComputeEpochRewardsFromCensus(epoch, atts, nil)

	if local == nil || census == nil {
		t.Fatalf("nil rewards: local=%v census=%v", local, census)
	}

	if local.TotalRewards.Cmp(census.TotalRewards) != 0 {
		t.Errorf("TotalRewards mismatch: local=%s census=%s", local.TotalRewards, census.TotalRewards)
	}
	if local.TotalPenalties.Cmp(census.TotalPenalties) != 0 {
		t.Errorf("TotalPenalties mismatch: local=%s census=%s", local.TotalPenalties, census.TotalPenalties)
	}
	if local.TotalStake.Cmp(census.TotalStake) != 0 {
		t.Errorf("TotalStake mismatch: local=%s census=%s", local.TotalStake, census.TotalStake)
	}
	if local.ParticipatingStake.Cmp(census.ParticipatingStake) != 0 {
		t.Errorf("ParticipatingStake mismatch: local=%s census=%s", local.ParticipatingStake, census.ParticipatingStake)
	}

	// Per-validator rewards must match exactly.
	for idx, lv := range local.AttesterRewards {
		cv := census.AttesterRewards[idx]
		if cv == nil || lv.Cmp(cv) != 0 {
			t.Errorf("attester reward validator %d mismatch: local=%v census=%v", idx, lv, cv)
		}
	}
	for idx, lv := range local.ProposerRewards {
		cv := census.ProposerRewards[idx]
		if cv == nil || lv.Cmp(cv) != 0 {
			t.Errorf("proposer reward validator %d mismatch: local=%v census=%v", idx, lv, cv)
		}
	}
	for idx, lv := range local.Penalties {
		cv := census.Penalties[idx]
		if cv == nil || lv.Cmp(cv) != 0 {
			t.Errorf("penalty validator %d mismatch: local=%v census=%v", idx, lv, cv)
		}
	}

	// Both must actually reward the participating validators (non-zero) so the
	// test is meaningful rather than trivially zero.
	if census.TotalRewards.Sign() == 0 {
		t.Fatal("expected non-zero rewards from 6 participating validators")
	}
}

// TestCensusRewardsDeterministic verifies that recomputing the reward from the
// same on-chain census is deterministic — the property the syncer relies on to
// reproduce the proposer's state root exactly.
func TestCensusRewardsDeterministic(t *testing.T) {
	const epoch = uint64(4)
	q := buildCensusTestQPOS(t)
	atts := makeCensusSet(epoch)

	serialized := SerializeAttestationCensus(atts, nil)
	first := q.ComputeEpochRewardsFromCensus(epoch, atts, nil)

	// Simulate a second node deserializing the census from the block header.
	atts2, _, err := DeserializeAttestationCensus(serialized)
	if err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	q2 := buildCensusTestQPOS(t)
	second := q2.ComputeEpochRewardsFromCensus(epoch, atts2, nil)

	if first.TotalRewards.Cmp(second.TotalRewards) != 0 {
		t.Errorf("determinism violated: node1=%s node2=%s",
			first.TotalRewards, second.TotalRewards)
	}
	if first.TotalPenalties.Cmp(second.TotalPenalties) != 0 {
		t.Errorf("penalty determinism violated: node1=%s node2=%s",
			first.TotalPenalties, second.TotalPenalties)
	}
}

// TestCensusAnchorsPathDependence proves the census is what anchors the result:
// a DIFFERENT attestation set yields a DIFFERENT reward. This is why the old
// path-dependent (P2P-gossip) computation forked the chain — different nodes
// saw different attestation sets — and why anchoring the census on-chain fixes it.
func TestCensusAnchorsPathDependence(t *testing.T) {
	const epoch = uint64(2)
	q := buildCensusTestQPOS(t)

	full := makeCensusSet(epoch) // all 6 validators attest
	partial := full[:3]          // only 3 validators attest (a node that missed gossip)

	local := q.ComputeEpochRewardsFromCensus(epoch, full, nil)
	partialPath := q.ComputeEpochRewardsFromCensus(epoch, partial, nil)

	if local.TotalRewards.Cmp(partialPath.TotalRewards) == 0 {
		t.Fatalf("expected different rewards for different attestation sets, both=%s",
			local.TotalRewards)
	}
}

// TestCensusMalformedRejected verifies DeserializeAttestationCensus fails
// closed on truncated / inconsistent payloads instead of panicking.
func TestCensusMalformedRejected(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00, 0x00},                         // too short for count
		{0x00, 0x00, 0x00, 0x05},             // claims 5 attestations but no data
		{0x00, 0x00, 0x00, 0x01, 0x01, 0x02}, // attestation truncated mid-fields
	}
	for i, c := range cases {
		if _, _, err := DeserializeAttestationCensus(c); err == nil {
			t.Errorf("case %d: expected error for malformed census, got nil", i)
		}
	}
	// Empty census is valid (no rewards) — must not error.
	if _, _, err := DeserializeAttestationCensus(nil); err != nil {
		t.Errorf("nil census should be treated as empty, got err: %v", err)
	}
	if _, _, err := DeserializeAttestationCensus(SerializeAttestationCensus(nil, nil)); err != nil {
		t.Errorf("serialized empty census should deserialize cleanly, got err: %v", err)
	}
}

// propMapForCensus derives the committed proposer table for makeCensusSet's
// deterministic attestations: validator i attests slot (start+i).
func propMapForCensus(epoch uint64) map[uint64]int {
	start := EpochStartSlot(epoch)
	m := make(map[uint64]int)
	for vi := 0; vi < 6; vi++ {
		m[start+uint64(vi)] = vi
	}
	return m
}

// TestCensusProposerRoundTrip verifies the R59 committed-proposer table
// survives a serialize/deserialize round trip.
func TestCensusProposerRoundTrip(t *testing.T) {
	const epoch = uint64(3)
	atts := makeCensusSet(epoch)
	proposers := propMapForCensus(epoch)

	serialized := SerializeAttestationCensus(atts, proposers)
	_, got, err := DeserializeAttestationCensus(serialized)
	if err != nil {
		t.Fatalf("DeserializeAttestationCensus failed: %v", err)
	}
	if len(got) != len(proposers) {
		t.Fatalf("proposer table count mismatch: got %d want %d", len(got), len(proposers))
	}
	for slot, wantIdx := range proposers {
		if gotIdx, ok := got[slot]; !ok || gotIdx != wantIdx {
			t.Errorf("slot %d proposer: got %d want %d (present=%v)", slot, gotIdx, wantIdx, ok)
		}
	}
}

// TestCensusProposerOverridesLocalAccumulator is the core R59 guarantee: even
// when two nodes have DIFFERENT local VRF-accumulator/shuffle state (the
// residual fork source), using the COMMITTED proposer table from the census
// forces them to produce IDENTICAL proposer rewards. This mimics Ethereum's
// block.proposer_index — the recipient is committed, never re-derived.
func TestCensusProposerOverridesLocalAccumulator(t *testing.T) {
	const epoch = uint64(3)
	atts := makeCensusSet(epoch)
	proposers := propMapForCensus(epoch)

	// Node A: pristine QPOS (accumulator may be absent → keccak fallback).
	qA := buildCensusTestQPOS(t)
	// Node B: corrupt/different local accumulator → a different shuffle would
	// pick a different proposer for the same slot if it were derived locally.
	qB := buildCensusTestQPOS(t)
	for e := uint64(0); e <= epoch; e++ {
		qA.AccumulateVRFOutput(e, types.Hash{0xAA})
		qB.AccumulateVRFOutput(e, types.Hash{0xBB})
	}
	qA.SetEpochVRFAccumulator(epoch-2, types.Hash{0x01})
	qB.SetEpochVRFAccumulator(epoch-2, types.Hash{0x02})

	ra := qA.ComputeEpochRewardsFromCensus(epoch, atts, proposers)
	rb := qB.ComputeEpochRewardsFromCensus(epoch, atts, proposers)

	if ra.TotalRewards.Cmp(rb.TotalRewards) != 0 {
		t.Fatalf("R59 determinism violated: different local VRF state changed rewards: A=%s B=%s",
			ra.TotalRewards, rb.TotalRewards)
	}
	if len(ra.ProposerRewards) != len(rb.ProposerRewards) {
		t.Fatalf("R59 proposer map size mismatch: A=%d B=%d",
			len(ra.ProposerRewards), len(rb.ProposerRewards))
	}
	for idx, av := range ra.ProposerRewards {
		bv, ok := rb.ProposerRewards[idx]
		if !ok || av.Cmp(bv) != 0 {
			t.Errorf("R59 proposer reward validator %d mismatch: A=%v B=%v (present=%v)", idx, av, bv, ok)
		}
	}

	// Sanity: the census path must actually credit the committed proposers
	// (non-zero), otherwise the test is vacuous.
	start := EpochStartSlot(epoch)
	if _, ok := ra.ProposerRewards[proposers[start]]; !ok {
		t.Fatal("expected proposer reward for committed proposer index")
	}
}

// buildEM2TestQPOS builds the mainnet validator configuration (6 x 6,000 QAU)
// so reward assertions can be compared against the published EM-2 numbers in
// docs/economic-model.md.
func buildEM2TestQPOS(t *testing.T) *QPOS {
	t.Helper()
	stake := new(big.Int).Mul(big.NewInt(6_000), big.NewInt(1_000_000_000_000_000_000))
	validators := make([]*Validator, 6)
	for i := 0; i < 6; i++ {
		validators[i] = &Validator{
			Address:        types.Address{byte(i + 1)},
			Stake:          new(big.Int).Set(stake),
			Active:         true,
			PublicKeyBytes: []byte{0xAA, 0xBB, byte(i + 1)},
		}
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	q, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	return q
}

// TestEM2CensusIssuesPublishedAmounts is the end-to-end check that the reward
// census actually pays what the economic model publishes. Unit-testing the
// arithmetic in isolation is not enough: the split has to survive the real
// census code path, including the two-pass proposer-pool distribution.
//
// Expected values (docs/economic-model.md §5, F=31 row at 36,000 QAU staked):
//
//	epoch issuance   0.186 QAU  = 186,000,000,000,000,000 wei
//	attester share   87.5%
//	proposer share   12.5%
func TestEM2CensusIssuesPublishedAmounts(t *testing.T) {
	const epoch = uint64(3)
	q := buildEM2TestQPOS(t)
	atts := makeCensusSet(epoch)

	rewards := q.ComputeEpochRewardsFromCensus(epoch, atts, nil)
	if rewards == nil {
		t.Fatal("nil rewards")
	}

	wantTotal := new(big.Int).SetUint64(186_000_000_000_000_000)
	if rewards.TotalRewards.Cmp(wantTotal) != 0 {
		t.Fatalf("epoch issuance = %s wei, want %s wei (0.186 QAU)",
			rewards.TotalRewards, wantTotal)
	}

	attesterSum := big.NewInt(0)
	for _, v := range rewards.AttesterRewards {
		attesterSum.Add(attesterSum, v)
	}
	proposerSum := big.NewInt(0)
	for _, v := range rewards.ProposerRewards {
		proposerSum.Add(proposerSum, v)
	}

	// Nothing may leak: the two components must reconstruct the total exactly.
	if sum := new(big.Int).Add(attesterSum, proposerSum); sum.Cmp(rewards.TotalRewards) != 0 {
		t.Fatalf("attester %s + proposer %s = %s != total %s",
			attesterSum, proposerSum, sum, rewards.TotalRewards)
	}

	wantProposer := new(big.Int).Mul(wantTotal, big.NewInt(ProposerWeight))
	wantProposer.Div(wantProposer, big.NewInt(WeightDenominator))
	if proposerSum.Cmp(wantProposer) != 0 {
		t.Fatalf("proposer total = %s wei, want %s wei (%d/%d of issuance)",
			proposerSum, wantProposer, ProposerWeight, WeightDenominator)
	}

	wantAttester := new(big.Int).Sub(wantTotal, wantProposer)
	if attesterSum.Cmp(wantAttester) != 0 {
		t.Fatalf("attester total = %s wei, want %s wei", attesterSum, wantAttester)
	}

	t.Logf("EM-2 census: total=%s wei, attester=%s (87.5%%), proposer=%s (12.5%%)",
		rewards.TotalRewards, attesterSum, proposerSum)
}

// TestEM2IssuanceIndependentOfProposedSlotCount pins the property EM-2 exists
// to create: total issuance is a function of the stake distribution alone, not
// of how many slots happened to be proposed.
//
// Under the pre-EM-2 rule each proposed-and-attested slot minted one FULL extra
// base reward, so an epoch with 6 proposed slots issued strictly more than one
// with 1 proposed slot. Now the proposer pool is a fixed 8/64 of the total and
// only its DISTRIBUTION changes.
//
// The two scenarios hold the attester set constant (all 6 validators attest in
// both) and vary only how many distinct slots carry those attestations.
func TestEM2IssuanceIndependentOfProposedSlotCount(t *testing.T) {
	const epoch = uint64(3)
	start := EpochStartSlot(epoch)

	// Scenario A: 6 validators on 6 distinct slots -> 6 credited slots.
	spread := makeCensusSet(epoch)

	// Scenario B: the same 6 validators all attesting ONE slot -> 1 credited slot.
	concentrated := make([]*Attestation, 0, 6)
	for vi := 0; vi < 6; vi++ {
		concentrated = append(concentrated, &Attestation{
			Slot:            start,
			BeaconBlockRoot: types.Hash{byte(vi + 1)},
			Source:          AttestationCheckpoint{Epoch: epoch - 1, Root: types.Hash{0x11}},
			Target:          AttestationCheckpoint{Epoch: epoch, Root: types.Hash{0x22}},
			ValidatorIndex:  vi,
			Signature:       []byte{0xDE, 0xAD, byte(vi + 1)},
			KeyVersion:      1,
		})
	}

	qa := buildEM2TestQPOS(t)
	ra := qa.ComputeEpochRewardsFromCensus(epoch, spread, nil)
	qb := buildEM2TestQPOS(t)
	rb := qb.ComputeEpochRewardsFromCensus(epoch, concentrated, nil)

	if ra == nil || rb == nil {
		t.Fatal("nil rewards")
	}
	if ra.TotalRewards.Cmp(rb.TotalRewards) != 0 {
		t.Fatalf("issuance depends on proposed-slot count: 6 slots = %s, 1 slot = %s",
			ra.TotalRewards, rb.TotalRewards)
	}

	// The pool is the same size in both; only its split differs.
	poolA, poolB := big.NewInt(0), big.NewInt(0)
	for _, v := range ra.ProposerRewards {
		poolA.Add(poolA, v)
	}
	for _, v := range rb.ProposerRewards {
		poolB.Add(poolB, v)
	}
	if poolA.Cmp(poolB) != 0 {
		t.Fatalf("proposer pool differs: 6 slots = %s, 1 slot = %s", poolA, poolB)
	}

	t.Logf("issuance decoupled from slot count: total=%s, pool=%s in both scenarios",
		ra.TotalRewards, poolA)
}
