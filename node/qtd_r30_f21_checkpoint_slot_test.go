// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R30 F21 (2026-10-30) — the node-side finality guards must compare against the
// finalized checkpoint BLOCK's slot, not the finalized epoch's boundary slot.
//
// With skipped slots the checkpoint sits below the boundary, and the band
// between the two is still reorgable. Guarding against the boundary slot refused
// head switches and store rollbacks that only touched that band, so a node could
// be stranded on a branch its peers had legitimately abandoned.

// r30F21QPOS finalizes epoch 1 with its checkpoint at slot 30 (the boundary slot
// 32 carried no block), so the checkpoint block is hash of slot 30.
func r30F21QPOS(t *testing.T, checkpoint types.Hash) *consensus.QPOS {
	t.Helper()
	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	// Record the canonical root first so the checkpoint slot is derivable, then
	// adopt it as the finalized checkpoint.
	qpos.SetSlotBlockRoot(30, checkpoint)
	qpos.AdoptHeaderFinality(0, 1, checkpoint)
	if got := qpos.GetFinalizedEpoch(); got != 1 {
		t.Fatalf("precondition: finalized epoch = %d, want 1", got)
	}
	if slot, ok := qpos.FinalizedCheckpointSlot(); !ok || slot != 30 {
		t.Fatalf("precondition: checkpoint slot = (%d, %v), want (30, true)", slot, ok)
	}
	return qpos
}

// TestR30F21_HeadSwitchAboveTheCheckpointIsAdopted pins the fork-choice side: a
// reorg whose abandoned range starts above the checkpoint block is legal even
// though it starts below the epoch boundary slot.
func TestR30F21_HeadSwitchAboveTheCheckpointIsAdopted(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	// heights 0..4, slots 0/30/35/40/45
	blocks, hashes := r29BuildChain(t, bs, 0, 30, 35, 40, 45)
	qpos := r30F21QPOS(t, hashes[1]) // checkpoint block = slot 30
	qpos.SetSlotBlockRoot(35, hashes[2])
	qpos.SetSlotBlockRoot(40, hashes[3])
	qpos.SetSlotBlockRoot(45, hashes[4])

	n := &Node{blockStore: bs, currentBlock: blocks[4]} // head at slot 45

	// Roll back to the checkpoint block itself: the abandoned range [31,45] lies
	// entirely above the finalized checkpoint (slot 30), so it must be adopted.
	if !n.commitHeadSwitchLocked("test", blocks[1], hashes[1], blocks[4], hashes[4], qpos) {
		t.Fatal("a reorg that only replaces blocks above the finalized checkpoint must be adopted")
	}
	if n.currentBlock != blocks[1] {
		t.Fatal("an adopted head switch must commit n.currentBlock")
	}
	if got, ok := qpos.GetSlotBlockRoot(30); !ok || got != hashes[1] {
		t.Fatalf("the finalized checkpoint root must survive: slot 30 = %x (present=%v)", got[:8], ok)
	}
	if got, ok := qpos.GetSlotBlockRoot(35); ok {
		t.Fatalf("the abandoned branch's slot root must be dropped: slot 35 = %x", got[:8])
	}
}

// TestR30F21_HeadSwitchThroughTheCheckpointIsRefused is the companion: a reorg
// whose abandoned range contains the checkpoint block is still refused, even
// though the same reorg is above the epoch boundary's block-free band.
func TestR30F21_HeadSwitchThroughTheCheckpointIsRefused(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks, hashes := r29BuildChain(t, bs, 0, 30, 35, 40, 45)
	qpos := r30F21QPOS(t, hashes[1])
	qpos.SetSlotBlockRoot(35, hashes[2])
	qpos.SetSlotBlockRoot(40, hashes[3])

	n := &Node{blockStore: bs, currentBlock: blocks[4]}

	// The new chain's common ancestor is genesis (slot 0), so the abandoned
	// range [1,45] contains the checkpoint block at slot 30.
	if n.commitHeadSwitchLocked("test", blocks[0], hashes[0], blocks[4], hashes[4], qpos) {
		t.Fatal("a reorg that replaces the finalized checkpoint block must be refused")
	}
	if n.currentBlock != blocks[4] {
		t.Fatal("a refused head switch must leave n.currentBlock untouched")
	}
	if got, ok := qpos.GetSlotBlockRoot(30); !ok || got != hashes[1] {
		t.Fatalf("a refused head switch must not touch the checkpoint root: slot 30 = %x (present=%v)", got[:8], ok)
	}
}

// TestR30F21_StoreRollbackUsesTheCheckpointSlot pins the syncer guard: deleting
// blocks whose slots sit above the checkpoint block is legal, deleting the
// checkpoint block itself is not.
func TestR30F21_StoreRollbackUsesTheCheckpointSlot(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	_, hashes := r29BuildChain(t, bs, 0, 30, 31, 33, 40) // heights 0..4
	qpos := r30F21QPOS(t, hashes[1])

	s := &Syncer{blockStore: bs, qpos: qpos}

	// From height 3 (slot 33): above the checkpoint (slot 30) → allowed, even
	// though it is below the epoch boundary slot 32.
	if blocked, slot := s.rollbackBelowFinality(3); blocked {
		t.Fatalf("a rollback starting at slot 33 (above the checkpoint at slot %d) must be allowed", slot)
	}
	// From height 2 (slot 31): still above the checkpoint → allowed.
	if blocked, slot := s.rollbackBelowFinality(2); blocked {
		t.Fatalf("a rollback starting at slot 31 (above the checkpoint at slot %d) must be allowed", slot)
	}
	// From height 1 (slot 30 = the checkpoint block) → refused.
	if blocked, _ := s.rollbackBelowFinality(1); !blocked {
		t.Fatal("a rollback that would delete the finalized checkpoint block must be refused")
	}
	// A rollback point whose block cannot be read stays fail-closed.
	if blocked, _ := s.rollbackBelowFinality(99); !blocked {
		t.Fatal("an unreadable rollback point must be refused")
	}
}
