// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

// M4-F4 regression: the canonical epoch-reward index order is opt-in.
//
// Legacy translation (activation 0, the default) must stay byte-for-byte
// identical: the crediting loops index the live validator slice exactly as
// they did before the switch existed.

func m4f4ResetActivation(t *testing.T) {
	t.Helper()
	SetEpochRewardsCanonicalOrderActivation(0)
	t.Cleanup(func() { SetEpochRewardsCanonicalOrderActivation(0) })
}

// m4f4UnsortedSet returns validators whose insertion order is deliberately
// NOT address-sorted, mimicking a live node that appended a post-genesis
// staker at the tail.
func m4f4UnsortedSet() []*consensus.Validator {
	return []*consensus.Validator{
		{Address: types.Address{0x03}, Stake: big.NewInt(6000), Active: true},
		{Address: types.Address{0x01}, Stake: big.NewInt(6000), Active: true},
		{Address: types.Address{0x02}, Stake: big.NewInt(6000), Active: true},
	}
}

func m4f4AddrOrder(vList []*consensus.Validator) []byte {
	out := make([]byte, 0, len(vList))
	for _, v := range vList {
		out = append(out, v.Address[0])
	}
	return out
}

func TestM4F4_ActivationZeroKeepsLegacyOrder(t *testing.T) {
	m4f4ResetActivation(t)

	vList := m4f4UnsortedSet()
	got := epochRewardTargets(vList, 12345)

	if epochRewardsUseCanonicalOrder(12345) {
		t.Fatalf("activation 0 must never use the canonical order")
	}
	if len(got) != len(vList) {
		t.Fatalf("len(got)=%d, want %d", len(got), len(vList))
	}
	for i := range vList {
		if got[i] != vList[i] {
			t.Fatalf("index %d reordered: got address %x, want %x", i, got[i].Address, vList[i].Address)
		}
	}
	if order := m4f4AddrOrder(got); order[0] != 0x03 || order[1] != 0x01 || order[2] != 0x02 {
		t.Fatalf("legacy order changed: got %v, want [3 1 2]", order)
	}
}

func TestM4F4_ActivationEpochBoundary(t *testing.T) {
	m4f4ResetActivation(t)
	SetEpochRewardsCanonicalOrderActivation(100)
	t.Cleanup(func() { SetEpochRewardsCanonicalOrderActivation(0) })

	epochs := []struct {
		epoch     uint64
		canonical bool
	}{
		{epoch: 99, canonical: false},
		{epoch: 100, canonical: true},
		{epoch: 101, canonical: true},
	}
	for _, tc := range epochs {
		if got := epochRewardsUseCanonicalOrder(tc.epoch); got != tc.canonical {
			t.Fatalf("epoch %d: canonical=%v, want %v", tc.epoch, got, tc.canonical)
		}
		vList := m4f4UnsortedSet()
		targets := epochRewardTargets(vList, tc.epoch)
		order := m4f4AddrOrder(targets)
		if tc.canonical {
			if order[0] != 0x01 || order[1] != 0x02 || order[2] != 0x03 {
				t.Fatalf("epoch %d: canonical order %v, want [1 2 3]", tc.epoch, order)
			}
			continue
		}
		if order[0] != 0x03 || order[1] != 0x01 || order[2] != 0x02 {
			t.Fatalf("epoch %d: legacy order %v, want [3 1 2]", tc.epoch, order)
		}
		if targets[0] != vList[0] {
			t.Fatalf("epoch %d: legacy path must not copy or reorder the live slice", tc.epoch)
		}
	}
}

func TestM4F4_CanonicalOrderDoesNotMutateLiveSet(t *testing.T) {
	m4f4ResetActivation(t)
	SetEpochRewardsCanonicalOrderActivation(1)
	t.Cleanup(func() { SetEpochRewardsCanonicalOrderActivation(0) })

	vList := m4f4UnsortedSet()
	before := m4f4AddrOrder(vList)

	targets := epochRewardTargets(vList, 1)
	if order := m4f4AddrOrder(targets); order[0] != 0x01 || order[1] != 0x02 || order[2] != 0x03 {
		t.Fatalf("canonical order %v, want [1 2 3]", order)
	}
	if after := m4f4AddrOrder(vList); string(after) != string(before) {
		t.Fatalf("live validator order mutated: before %v, after %v", before, after)
	}
}
