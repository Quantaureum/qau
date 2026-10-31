// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R30 F21 (2026-10-30) — the irreversible boundary for a reorg is the finalized
// checkpoint BLOCK's slot, not the finalized epoch's boundary slot.
//
// The checkpoint of epoch E is the highest canonical block at or below
// E*SlotsPerEpoch (R42-P3), so when the boundary slot was skipped the checkpoint
// sits strictly below it and every block between the two is NOT final. Comparing
// against the boundary slot refused reorgs that only replaced those blocks. On a
// chain with skipped slots that band sits immediately above the head, so the
// refusal could leave the node on a branch its peers had legitimately abandoned.

// newF21QPOS returns a QPOS whose epoch 1 is finalized with its checkpoint at
// slot 30 (the epoch boundary slot 32 carried no block).
func newF21QPOS(t *testing.T, checkpoint types.Hash) *QPOS {
	t.Helper()
	q, err := NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	q.mu.Lock()
	q.slotBlockRoots[30] = checkpoint
	q.slotBlockRoots[33] = types.Hash{0x33} // abandoned, above the checkpoint
	q.slotBlockRoots[36] = types.Hash{0x36} // abandoned, the replaced head
	q.finalizedEpoch = 1
	q.finalizedRoot = checkpoint
	q.mu.Unlock()
	return q
}

func TestR30F21_CheckpointSlotIsTheBlockSlot(t *testing.T) {
	checkpoint := types.Hash{0xC1}
	q := newF21QPOS(t, checkpoint)

	slot, ok := q.FinalizedCheckpointSlot()
	if !ok {
		t.Fatal("finalized epoch 1 must expose a checkpoint slot")
	}
	if slot != 30 {
		t.Fatalf("checkpoint slot = %d, want 30 (the checkpoint block's slot, not the epoch boundary 32)", slot)
	}
	// The boundary slot is still reported by FinalityFloorSlot: it answers a
	// different question ("how far can the store be rolled back").
	if floor, ok := q.FinalityFloorSlot(); !ok || floor != 32 {
		t.Fatalf("floor slot = %d (ok=%v), want 32", floor, ok)
	}
}

func TestR30F21_CheckpointSlotFallsBackToTheBoundary(t *testing.T) {
	q, err := NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	if _, ok := q.FinalizedCheckpointSlot(); ok {
		t.Fatal("a fresh QPOS must not report a checkpoint slot")
	}

	// No slot root matches this finalized root (pruned / never recorded), so the
	// boundary slot must be used: refusing a legal reorg costs liveness, while
	// accepting an illegal one breaks finality.
	q.AdoptHeaderFinality(0, 1, types.Hash{0xAA})
	slot, ok := q.FinalizedCheckpointSlot()
	if !ok {
		t.Fatal("finalized epoch 1 must expose a checkpoint slot")
	}
	if want := uint64(SlotsPerEpoch); slot != want {
		t.Fatalf("checkpoint slot = %d, want the conservative boundary %d", slot, want)
	}
}

func TestR30F21_ReorgAboveTheCheckpointIsAccepted(t *testing.T) {
	checkpoint := types.Hash{0xC1}
	q := newF21QPOS(t, checkpoint)

	roots := map[uint64]types.Hash{35: {0x35}, 40: {0x40}}
	bounds := ReanchorBounds{
		AncestorSlot:     30,
		AncestorKnown:    true,
		AncestorHash:     checkpoint,
		ReplacedHeadSlot: 36,
	}
	if !q.ReanchorSlotRootsBounded(roots, nil, bounds) {
		t.Fatal("a reorg whose abandoned range [31,36] starts ABOVE the finalized checkpoint (slot 30) must be accepted; refusing it strands the node on a branch its peers abandoned")
	}

	if root, ok := q.GetSlotBlockRoot(30); !ok || root != checkpoint {
		t.Fatalf("finalized checkpoint root at slot 30 = %x (ok=%v), want it preserved", root, ok)
	}
	if _, ok := q.GetSlotBlockRoot(33); ok {
		t.Fatal("the abandoned slot root at 33 survived the reorg")
	}
	if root, ok := q.GetSlotBlockRoot(35); !ok || root != (types.Hash{0x35}) {
		t.Fatalf("re-anchored slot root 35 = %x (ok=%v), want 0x35", root, ok)
	}
	if root, ok := q.GetSlotBlockRoot(40); !ok || root != (types.Hash{0x40}) {
		t.Fatalf("re-anchored slot root 40 = %x (ok=%v), want 0x40", root, ok)
	}
}

func TestR30F21_ReorgThroughTheCheckpointIsRefused(t *testing.T) {
	checkpoint := types.Hash{0xC1}
	q := newF21QPOS(t, checkpoint)

	roots := map[uint64]types.Hash{35: {0x35}}
	bounds := ReanchorBounds{
		AncestorSlot:     29,
		AncestorKnown:    true,
		AncestorHash:     types.Hash{0x29},
		ReplacedHeadSlot: 36,
	}
	if q.ReanchorSlotRootsBounded(roots, nil, bounds) {
		t.Fatal("a reorg whose abandoned range [30,36] contains the finalized checkpoint block (slot 30) must be refused")
	}
	if root, ok := q.GetSlotBlockRoot(30); !ok || root != checkpoint {
		t.Fatalf("checkpoint root at slot 30 = %x (ok=%v), want it untouched after a refusal", root, ok)
	}
	if root, ok := q.GetSlotBlockRoot(33); !ok || root != (types.Hash{0x33}) {
		t.Fatalf("a refused reorg must not touch any slot root: 33 = %x (ok=%v)", root, ok)
	}
}

func TestR30F21_UnknownCheckpointRootStaysConservative(t *testing.T) {
	q, err := NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	q.AdoptHeaderFinality(0, 1, types.Hash{0xAA}) // root cannot be located in the slot map

	// cleanMin = 32 <= boundary 32: refused, because the checkpoint block could
	// be anywhere at or below the boundary.
	if q.ReanchorSlotRootsBounded(nil, nil, ReanchorBounds{
		AncestorSlot:     31,
		AncestorKnown:    true,
		AncestorHash:     types.Hash{0x31},
		ReplacedHeadSlot: 40,
	}) {
		t.Fatal("with an unlocatable checkpoint root the boundary slot must be the limit")
	}
	// cleanMin = 33 > boundary 32: accepted.
	if !q.ReanchorSlotRootsBounded(nil, nil, ReanchorBounds{
		AncestorSlot:     32,
		AncestorKnown:    true,
		AncestorHash:     types.Hash{0x32},
		ReplacedHeadSlot: 40,
	}) {
		t.Fatal("a reorg starting above the boundary slot must still be accepted")
	}
}
