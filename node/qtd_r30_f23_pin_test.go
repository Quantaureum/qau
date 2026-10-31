// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R30 F23 (2026-10-30) — a restarted node must keep comparing reorgs against the
// finalized checkpoint BLOCK's slot.
//
// QPOS.slotBlockRoots is in-memory state: it starts empty and is rebuilt from
// live imports, which resume at the head, so a restored checkpoint never
// appears in it. The slot is therefore resolved from the block store once, at
// startup, and pinned in the QPOS (keyed by the checkpoint root so it
// invalidates itself when finality advances).

// r30F23PersistStore builds heights 0..3 at slots 0/30/31/33 and records
// justified == finalized epoch 1 with the checkpoint block at slot 30 — the
// boundary slot 32 carried no block, so the two candidate boundaries differ.
func r30F23PersistStore(t *testing.T) (*block.BlockStore, []types.Hash) {
	t.Helper()
	bs := block.NewBlockStore(db.NewMemDB())
	_, hashes := r29BuildChain(t, bs, 0, 30, 31, 33)
	if err := bs.PutFinalityState(1, 1, hashes[1], hashes[1]); err != nil {
		t.Fatalf("PutFinalityState: %v", err)
	}
	return bs, hashes
}

// TestR30F23_RestartedNodePinsTheCheckpointSlot pins the wiring: the restored
// checkpoint resolves to slot 30, not to the epoch boundary slot 32.
func TestR30F23_RestartedNodePinsTheCheckpointSlot(t *testing.T) {
	bs, hashes := r30F23PersistStore(t)

	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	if err := configureQPOSFinalityPersistence(qpos, bs); err != nil {
		t.Fatalf("configureQPOSFinalityPersistence: %v", err)
	}
	if got := qpos.GetFinalizedEpoch(); got != 1 {
		t.Fatalf("precondition: finalized epoch = %d, want 1", got)
	}
	if slot, ok := qpos.FinalizedCheckpointSlot(); !ok || slot != 30 {
		t.Fatalf("restarted checkpoint slot = (%d, %v), want (30, true): slot 32 is only an upper bound", slot, ok)
	}
	// The store's own answer must agree with the pin.
	if h, gerr := bs.GetBlockHash(1); gerr != nil || h != hashes[1] {
		t.Fatalf("precondition: the checkpoint block must be canonical at height 1")
	}

	// A rollback that keeps the checkpoint block is legal, and the old
	// boundary-slot fallback would have refused it (slot 30 < 32).
	s := &Syncer{blockStore: bs, qpos: qpos}
	if blocked, slot := s.rollbackBelowFinality(2); blocked {
		t.Fatalf("a rollback keeping the checkpoint block (slot %d) must be allowed after a restart", slot)
	}
	// Deleting the checkpoint block itself stays refused.
	if blocked, _ := s.rollbackBelowFinality(1); !blocked {
		t.Fatal("a rollback deleting the checkpoint block must be refused")
	}
}

// TestR30F23_UnresolvableCheckpointKeepsTheFallback pins the conservative half:
// when the checkpoint block cannot be resolved, nothing is pinned and the
// boundary slot decides — over-strict, never unsafe.
func TestR30F23_UnresolvableCheckpointKeepsTheFallback(t *testing.T) {
	// The checkpoint root names a block the store does not hold (pruned, or a
	// chain this node never imported): its slot is unknown.
	fresh := block.NewBlockStore(db.NewMemDB())
	r29BuildChain(t, fresh, 0, 30, 31, 33)
	if err := fresh.PutFinalityState(1, 1, types.Hash{0x01}, types.Hash{0x01}); err != nil {
		t.Fatalf("PutFinalityState(fresh): %v", err)
	}
	qpos2, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	if err := configureQPOSFinalityPersistence(qpos2, fresh); err != nil {
		t.Fatalf("configureQPOSFinalityPersistence(fresh): %v", err)
	}
	if slot, ok := qpos2.FinalizedCheckpointSlot(); !ok || slot != consensus.SlotsPerEpoch {
		t.Fatalf("unresolvable checkpoint slot = (%d, %v), want the boundary slot %d", slot, ok, uint64(consensus.SlotsPerEpoch))
	}
}

// TestR30F23_PinSurvivesPruning pins the within-run half: pruning drops the
// checkpoint's own slot root once the window moves past it, and the pin is what
// keeps the boundary exact afterwards.
func TestR30F23_PinSurvivesPruning(t *testing.T) {
	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	checkpoint := types.Hash{0xB7}
	// Finalize epoch 3 (boundary slot 96) with its checkpoint block at slot 60.
	qpos.SetSlotBlockRoot(60, checkpoint)
	qpos.AdoptHeaderFinality(2, 3, checkpoint)
	if slot, ok := qpos.FinalizedCheckpointSlot(); !ok || slot != 60 {
		t.Fatalf("checkpoint slot = (%d, %v), want (60, true)", slot, ok)
	}
	// Fill the window past its threshold; the cutoff (start of epoch 2 = slot
	// 64) then deletes the checkpoint's own entry.
	for s := uint64(40); s < 160; s++ {
		qpos.SetSlotBlockRoot(s, types.Hash{byte(s)})
	}
	if root, ok := qpos.GetSlotBlockRoot(60); ok && root == checkpoint {
		t.Fatal("precondition: pruning must have dropped the checkpoint's slot root")
	}
	if slot, ok := qpos.FinalizedCheckpointSlot(); !ok || slot != 60 {
		t.Fatalf("checkpoint slot after pruning = (%d, %v), want the pinned (60, true)", slot, ok)
	}

	// Finality advancing to a checkpoint with no recorded slot falls back to
	// the new epoch's boundary: the stale pin must not answer for it.
	qpos.AdoptHeaderFinality(3, 4, types.Hash{0xD4})
	if slot, ok := qpos.FinalizedCheckpointSlot(); !ok || slot != 4*consensus.SlotsPerEpoch {
		t.Fatalf("checkpoint slot after finality moved = (%d, %v), want the boundary slot %d", slot, ok, uint64(4*consensus.SlotsPerEpoch))
	}
}
