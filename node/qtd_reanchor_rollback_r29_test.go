// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R29 (2026-10-30) — node-layer coverage for the eighth independent re-review
// finding N8: the consensus tests fed ReanchorSlotRootsBounded by hand, so the
// derivation the node actually performs (common ancestor, empty roots on a
// pure rollback, ancestor hash, implied epoch checkpoints) was untested, and
// the B1 shape (empty roots) had no caller-level test at all.

// r29BuildChain stores a linear chain with the given slots (heights 0..n-1)
// and returns the blocks together with their hashes.
func r29BuildChain(t *testing.T, bs *block.BlockStore, slots ...uint64) ([]*encoding.Block, []types.Hash) {
	t.Helper()
	blocks := make([]*encoding.Block, 0, len(slots))
	hashes := make([]types.Hash, 0, len(slots))
	parent := types.Hash{}
	for i, slot := range slots {
		blk := &encoding.Block{Header: &encoding.BlockHeader{
			Height:     uint64(i),
			Slot:       slot,
			Epoch:      consensus.SlotToEpoch(slot),
			ParentHash: parent,
		}}
		if err := bs.PutBlock(blk); err != nil {
			t.Fatalf("PutBlock(slot %d): %v", slot, err)
		}
		h := block.ComputeBlockHash(blk)
		blocks = append(blocks, blk)
		hashes = append(hashes, h)
		parent = h
	}
	return blocks, hashes
}

// TestR29_NodePureRollbackCleansAbandonedRange drives the B1 shape through the
// real caller: the head rolls back to a common ancestor, so the new chain
// contributes no re-anchored slot and the roots map is empty. The abandoned
// range (ancestor, old head] must still be cleaned, and the epoch checkpoint
// the rollback removed must be re-derived from the ancestor.
func TestR29_NodePureRollbackCleansAbandonedRange(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks, hashes := r29BuildChain(t, bs, 0, 30, 35, 40)

	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	qpos.SetSlotBlockRoot(31, types.Hash{0x31})
	qpos.SetSlotBlockRoot(35, hashes[2])
	qpos.SetSlotBlockRoot(40, hashes[3])
	qpos.SetEpochBlockRoot(1, hashes[2])

	n := &Node{blockStore: bs, currentBlock: blocks[3]}
	if !n.commitHeadSwitchLocked("test", blocks[1], hashes[1], blocks[3], hashes[3], qpos) {
		t.Fatal("a rollback above finality must be accepted")
	}

	for _, slot := range []uint64{31, 35, 40} {
		if root, known := qpos.GetSlotBlockRoot(slot); known {
			t.Fatalf("slot %d kept the abandoned root %s after a pure rollback (B1)", slot, root.String())
		}
	}
	if root, known := qpos.GetEpochBlockRoot(1); !known || root != hashes[1] {
		t.Fatalf("epoch 1 checkpoint = %s (known=%v), want the common ancestor %s (N7)",
			root.String(), known, hashes[1].String())
	}
}

// TestR29_NodeRejectedRollbackLeavesRootsUntouched pins the reporting contract
// the caller relies on (N3): a rollback that reaches finalized history is
// refused (commitHeadSwitchLocked returns false) and no root or checkpoint was
// touched, so the caller knows not to treat the block as canonical either.
func TestR29_NodeRejectedRollbackLeavesRootsUntouched(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks, hashes := r29BuildChain(t, bs, 0, 30, 35, 40)

	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	boundaryRoot := types.Hash{0xA1}
	// Adopt a finalized epoch through the public API (the QPOS internals are
	// unexported): epoch 1 is finalized, so its boundary slot 32 is immutable.
	qpos.AdoptHeaderFinality(0, 1, types.Hash{0xA0})
	if got := qpos.GetFinalizedEpoch(); got != 1 {
		t.Fatalf("precondition: finalized epoch = %d, want 1", got)
	}
	qpos.SetSlotBlockRoot(32, boundaryRoot)
	qpos.SetSlotBlockRoot(35, hashes[2])
	qpos.SetSlotBlockRoot(40, hashes[3])

	n := &Node{blockStore: bs, currentBlock: blocks[3]}
	if n.commitHeadSwitchLocked("test", blocks[1], hashes[1], blocks[3], hashes[3], qpos) {
		t.Fatal("a rollback reaching finalized history must be refused (N1/N3)")
	}
	if root, known := qpos.GetSlotBlockRoot(32); !known || root != boundaryRoot {
		t.Fatalf("the finalized boundary slot root was rewritten: known=%v root=%s", known, root.String())
	}
	if root, known := qpos.GetSlotBlockRoot(35); !known || root != hashes[2] {
		t.Fatalf("a refused rollback partially applied: slot 35 = %s (known=%v)", root.String(), known)
	}
}
