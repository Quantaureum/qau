// Quantaureum Node source, version 1.0.0.
package consensus

// M4-F4 regression: the epoch reward derivation must be a pure function of
// the on-chain census and the validator MEMBERSHIP — never of the node's
// validator insertion order.
//
// The census indices are positions in a validator slice. Two nodes holding
// the same membership in different orders (live-append vs restart-sorted) must
// either derive identical rewards (canonical order active) or identically
// WRONG ones is not acceptable — the legacy behavior is order-dependent, which
// is exactly the M4 state-root divergence this file's gate fixes.

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/quantaureum/qau/types"
)

var (
	m4f4V1 = types.Address{0x01}
	m4f4V2 = types.Address{0x02}
	m4f4V3 = types.Address{0x03}

	wei = big.NewInt(1_000_000_000_000_000_000)
)

func m4f4_validator(addr types.Address, stake int64) *Validator {
	return &Validator{Address: addr, Stake: new(big.Int).Mul(big.NewInt(stake), wei), Active: true}
}

// m4f4_qposWithOrder builds a QPOS whose validator slice is exactly the given
// order. NewValidatorSet sorts its input, so the live (insertion) order is
// built by appending post-genesis stakers via AddValidator — the same path the
// live staking flow uses.
func m4f4_qposWithOrder(t *testing.T, order []*Validator) *QPOS {
	t.Helper()
	vs, err := NewValidatorSet([]*Validator{order[0]})
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	for _, v := range order[1:] {
		if !vs.AddValidator(v.Address, v.Stake) {
			t.Fatalf("AddValidator(%x) rejected", v.Address[0])
		}
	}
	q, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	return q
}

// m4f4_partialCensus returns a census in which only validator indices 0 and 1
// attested (index 2 missed the epoch) and index 0 proposed the only attested
// slot. Partial participation is what makes the index→validator resolution
// observable: the missed validator — and its inactivity penalty — lands on a
// different address under each insertion order.
func m4f4_partialCensus() ([]*Attestation, map[uint64]int) {
	atts := []*Attestation{
		{Slot: 32, BeaconBlockRoot: types.Hash{0x01},
			Source:         AttestationCheckpoint{Epoch: 0, Root: types.Hash{0x11}},
			Target:         AttestationCheckpoint{Epoch: 1, Root: types.Hash{0x22}},
			ValidatorIndex: 0, Signature: []byte{0xDE, 0xAD, 0x01}, KeyVersion: 1},
		{Slot: 33, BeaconBlockRoot: types.Hash{0x02},
			Source:         AttestationCheckpoint{Epoch: 0, Root: types.Hash{0x11}},
			Target:         AttestationCheckpoint{Epoch: 1, Root: types.Hash{0x22}},
			ValidatorIndex: 1, Signature: []byte{0xDE, 0xAD, 0x02}, KeyVersion: 1},
	}
	return atts, map[uint64]int{32: 0}
}

// TestM4F4_LegacyDerivationIsOrderDependent documents the defect: under the
// legacy (live-order) translation, the SAME census yields DIFFERENT rewards on
// nodes whose validator sets hold the same membership in different orders.
func TestM4F4_LegacyDerivationIsOrderDependent(t *testing.T) {
	SetEpochRewardsCanonicalOrderActivation(0)
	defer SetEpochRewardsCanonicalOrderActivation(0)

	live := m4f4_qposWithOrder(t, []*Validator{
		m4f4_validator(m4f4V2, 2000), m4f4_validator(m4f4V3, 1000), m4f4_validator(m4f4V1, 3000),
	})
	sorted := m4f4_qposWithOrder(t, []*Validator{
		m4f4_validator(m4f4V1, 3000), m4f4_validator(m4f4V2, 2000), m4f4_validator(m4f4V3, 1000),
	})

	atts, proposers := m4f4_partialCensus()
	rLive := live.ComputeEpochRewardsFromCensus(1, atts, proposers)
	rSorted := sorted.ComputeEpochRewardsFromCensus(1, atts, proposers)

	if reflect.DeepEqual(rLive.AttesterRewards, rSorted.AttesterRewards) &&
		reflect.DeepEqual(rLive.Penalties, rSorted.Penalties) {
		t.Fatal("fixture broken: legacy derivation no longer depends on the validator insertion order")
	}
}

// TestM4F4_CanonicalDerivationIsOrderIndependent pins the fix: with the
// canonical order active, both insertion orders derive byte-identical reward
// maps from the same census — the state root no longer depends on the node's
// insertion history.
func TestM4F4_CanonicalDerivationIsOrderIndependent(t *testing.T) {
	SetEpochRewardsCanonicalOrderActivation(1)
	defer SetEpochRewardsCanonicalOrderActivation(0)

	live := m4f4_qposWithOrder(t, []*Validator{
		m4f4_validator(m4f4V2, 2000), m4f4_validator(m4f4V3, 1000), m4f4_validator(m4f4V1, 3000),
	})
	sorted := m4f4_qposWithOrder(t, []*Validator{
		m4f4_validator(m4f4V1, 3000), m4f4_validator(m4f4V2, 2000), m4f4_validator(m4f4V3, 1000),
	})

	atts, proposers := m4f4_partialCensus()
	rLive := live.ComputeEpochRewardsFromCensus(1, atts, proposers)
	rSorted := sorted.ComputeEpochRewardsFromCensus(1, atts, proposers)

	if !reflect.DeepEqual(rLive.AttesterRewards, rSorted.AttesterRewards) {
		t.Fatalf("attester rewards diverge across insertion orders: live=%v sorted=%v",
			rLive.AttesterRewards, rSorted.AttesterRewards)
	}
	if !reflect.DeepEqual(rLive.ProposerRewards, rSorted.ProposerRewards) {
		t.Fatalf("proposer rewards diverge across insertion orders: live=%v sorted=%v",
			rLive.ProposerRewards, rSorted.ProposerRewards)
	}
	if !reflect.DeepEqual(rLive.Penalties, rSorted.Penalties) {
		t.Fatalf("penalties diverge across insertion orders: live=%v sorted=%v",
			rLive.Penalties, rSorted.Penalties)
	}
	if rLive.TotalRewards.Cmp(rSorted.TotalRewards) != 0 ||
		rLive.TotalPenalties.Cmp(rSorted.TotalPenalties) != 0 {
		t.Fatalf("totals diverge across insertion orders: live=(%s,%s) sorted=(%s,%s)",
			rLive.TotalRewards, rLive.TotalPenalties, rSorted.TotalRewards, rSorted.TotalPenalties)
	}

	// The canonical resolution is the address-sorted one: index 0 must be V1,
	// and the missed validator (index 2) must be V3 regardless of the
	// insertion order used to build the set.
	if _, ok := rSorted.Penalties[2]; !ok {
		t.Fatalf("expected the inactivity penalty on canonical index 2 (V3), got %v", rSorted.Penalties)
	}
	if _, ok := rSorted.Penalties[1]; ok {
		t.Fatalf("canonical index 1 (V2) attested and must not be penalized, got %v", rSorted.Penalties)
	}
}

// TestM4F4_SortValidatorsByAddressIsDeterministicAndNonMutating pins the
// shared comparator: sorting is by address bytes, and the input slice is
// never reordered in place.
func TestM4F4_SortValidatorsByAddressIsDeterministicAndNonMutating(t *testing.T) {
	in := []*Validator{
		m4f4_validator(m4f4V3, 1000),
		m4f4_validator(m4f4V1, 3000),
		m4f4_validator(m4f4V2, 2000),
	}
	before := make([]types.Address, 0, len(in))
	for _, v := range in {
		before = append(before, v.Address)
	}

	out := SortValidatorsByAddress(in)
	if out[0].Address != m4f4V1 || out[1].Address != m4f4V2 || out[2].Address != m4f4V3 {
		t.Fatalf("sort order = %x %x %x, want 01 02 03", out[0].Address, out[1].Address, out[2].Address)
	}
	for i, v := range in {
		if v.Address != before[i] {
			t.Fatalf("input slice mutated at %d: %x, want %x", i, v.Address, before[i])
		}
	}
}
