// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// R87-VSET-ORDER regression tests.
//
// GetActiveValidators() returns map[types.Address]*big.Int. syncQPOSValidators
// FromStaking used to iterate it directly, so the append order of staked
// validators into the QPOS ValidatorSet — and therefore their consensus
// indices — depended on Go map layout, which changes on every process start.
// Epoch rewards credit rewards.AttesterRewards[idx] to validators[idx], so a
// node that restarted with a different layout would credit the same census
// indices to different addresses: permanent state-root divergence (the R87-M4
// failure class).
//
// These tests pin the ordering: bytesLess-ascending, independent of insertion
// order, and usable as the stable key for consensus-index assignment.

func TestR87VSetOrder_SortedStakerAddrsIsAscending(t *testing.T) {
	stakers := map[types.Address]*big.Int{
		types.BytesToAddress([]byte{0xff, 0x01}): big.NewInt(1),
		types.BytesToAddress([]byte{0x00, 0x02}): big.NewInt(2),
		types.BytesToAddress([]byte{0x80, 0x80}): big.NewInt(3),
		types.BytesToAddress([]byte{0x00, 0x01}): big.NewInt(4),
		types.BytesToAddress([]byte{0x7f, 0xff}): big.NewInt(5),
	}
	addrs := sortedStakerAddrs(stakers)
	if len(addrs) != len(stakers) {
		t.Fatalf("got %d addrs, want %d", len(addrs), len(stakers))
	}
	for i := 1; i < len(addrs); i++ {
		if !bytesLess(addrs[i-1][:], addrs[i][:]) {
			t.Errorf("addrs[%d]=%x is not strictly less than addrs[%d]=%x — "+
				"ordering must be bytesLess-ascending so consensus indices are "+
				"identical on every node", i-1, addrs[i-1][:4], i, addrs[i][:4])
		}
	}
}

func TestR87VSetOrder_BytesLessEdgeCases(t *testing.T) {
	if !bytesLess([]byte{0x00}, []byte{0x01}) {
		t.Error("0x00 must sort before 0x01")
	}
	if bytesLess([]byte{0x01}, []byte{0x00}) {
		t.Error("0x01 must not sort before 0x00")
	}
	if !bytesLess([]byte{0x00, 0x01}, []byte{0x01, 0x00}) {
		t.Error("first byte dominates")
	}
	if bytesLess([]byte{0x01}, []byte{0x01}) {
		t.Error("equal slices must not be less")
	}
	// addresses are fixed-size so length differences don't arise; prefix rule
	// still pinned for safety
	if !bytesLess([]byte{0x01}, []byte{0x01, 0x00}) {
		t.Error("prefix must sort before its extension")
	}
}

// TestR87VSetOrder_MapInsertionOrderDoesNotLeak runs the same logical map
// through different construction sequences. Go randomizes iteration order, so
// the ONLY way this test can be stable is if sortedStakerAddrs truly sorts.
func TestR87VSetOrder_MapInsertionOrderDoesNotLeak(t *testing.T) {
	base := []types.Address{
		types.BytesToAddress([]byte{0x10}),
		types.BytesToAddress([]byte{0x20}),
		types.BytesToAddress([]byte{0x30}),
		types.BytesToAddress([]byte{0x40}),
	}
	want := sortedStakerAddrs(func() map[types.Address]*big.Int {
		m := map[types.Address]*big.Int{}
		for _, a := range base {
			m[a] = big.NewInt(1)
		}
		return m
	}())

	// Every permutation of insertion order must produce the identical slice.
	perms := [][]int{{0, 1, 2, 3}, {3, 2, 1, 0}, {1, 0, 3, 2}, {2, 3, 0, 1}}
	for _, p := range perms {
		m := map[types.Address]*big.Int{}
		for _, i := range p {
			m[base[i]] = big.NewInt(1)
		}
		got := sortedStakerAddrs(m)
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("insertion order %v leaked into output: got [%d]=%x want %x — "+
					"consensus indices would differ across node restarts",
					p, i, got[i][:4], want[i][:4])
			}
		}
	}
}
