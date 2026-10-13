// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
)

// slotChain builds a canonical chain from the slots of its blocks, one per
// height, and returns the walk function the guard uses plus the head height.
func slotChain(slots ...uint64) (uint64, func(uint64) (uint64, bool)) {
	return uint64(len(slots) - 1), func(height uint64) (uint64, bool) {
		if height >= uint64(len(slots)) {
			return 0, false
		}
		return slots[height], true
	}
}

func slotOfEpoch(epoch, offset uint64) uint64 { return epoch*consensus.SlotsPerEpoch + offset }

// The guard is relaxed only for an epoch in which the canonical chain has no
// block, wherever the head is.
func TestChainHasNoBlockInEpoch(t *testing.T) {
	// A chain that ran through epoch 7 and stalled.
	stalled := []uint64{0, slotOfEpoch(5, 3), slotOfEpoch(6, 9), slotOfEpoch(7, 1), slotOfEpoch(7, 30)}
	// The same chain restarted in epoch 10: epochs 8 and 9 are empty and the
	// restarted chain has produced three blocks.
	restarted := append(append([]uint64(nil), stalled...), slotOfEpoch(10, 2), slotOfEpoch(10, 3), slotOfEpoch(10, 4))
	// A chain with one empty epoch in the middle (epoch 6).
	gap := []uint64{0, slotOfEpoch(5, 3), slotOfEpoch(7, 9), slotOfEpoch(8, 1)}

	tests := []struct {
		name  string
		slots []uint64
		epoch uint64
		want  bool
	}{
		{"the head's own epoch holds a block", stalled, 7, false},
		{"the epoch before the head holds a block", stalled, 6, false},
		{"first epoch after a stall", stalled, 8, true},
		{"later epoch of a stall", stalled, 9, true},
		{"far after a stall", stalled, 40, true},
		// After the restart the head is in epoch 10, yet epochs 8 and 9 are still empty:
		// the exemption must hold for the slots of epochs 10 and 11 (E-2 = 8, 9).
		{"restarted chain, epoch 8 still empty", restarted, 8, true},
		{"restarted chain, epoch 9 still empty", restarted, 9, true},
		{"restarted chain, epoch 10 now has blocks", restarted, 10, false},
		{"restarted chain, old epoch with blocks", restarted, 7, false},
		{"one empty epoch mid-chain", gap, 6, true},
		{"epochs around the gap hold blocks", gap, 5, false},
		{"epochs around the gap hold blocks (after)", gap, 7, false},
		{"genesis epoch", stalled, 0, false},
	}
	for _, test := range tests {
		head, slotAt := slotChain(test.slots...)
		if got := chainHasNoBlockInEpoch(head, slotAt, test.epoch); got != test.want {
			t.Errorf("%s: chainHasNoBlockInEpoch(epoch %d) = %v, want %v", test.name, test.epoch, got, test.want)
		}
	}
}

// An unreadable block or a walk longer than the limit decides nothing, so the
// guard stays in force.
func TestChainHasNoBlockInEpochIsConservative(t *testing.T) {
	head, slotAt := slotChain(0, slotOfEpoch(7, 1))
	if chainHasNoBlockInEpoch(head+3, slotAt, 8) {
		t.Fatal("a head the store cannot read was treated as proof of an empty epoch")
	}
	broken := func(height uint64) (uint64, bool) {
		if height == 2 {
			return 0, false
		}
		return slotOfEpoch(20, height), true
	}
	if chainHasNoBlockInEpoch(5, broken, 8) {
		t.Fatal("a missing block in the middle of the walk was treated as proof of an empty epoch")
	}
	// Every block above the epoch: the walk runs out before it finds one below.
	long := func(height uint64) (uint64, bool) { return slotOfEpoch(100+height, 0), true }
	if chainHasNoBlockInEpoch(10*coldStartChainWalkLimit, long, 8) {
		t.Fatal("a walk past the limit was treated as proof of an empty epoch")
	}
}
