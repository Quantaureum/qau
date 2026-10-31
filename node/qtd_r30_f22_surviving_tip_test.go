// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R30 F22 (2026-10-30) — the store-rollback guard must judge the block that
// SURVIVES a rollback, not the first block it deletes.
//
// Heights are contiguous but slots are not: a rollback can start at a block
// whose slot sits above the finalized checkpoint while the block that survives
// sits below it. Reading the first deleted block then lets the truncation and
// the state rewind through, and fork choice refuses the head switch afterwards
// — a store truncated below its own head, with nothing left to reconcile it.

// r30F22QPOS finalizes epoch 1 (boundary slot 32) with its checkpoint block at
// slot 30, i.e. the boundary slot carried no block.
func r30F22QPOS(t *testing.T) *consensus.QPOS {
	t.Helper()
	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	checkpoint := types.Hash{0xCC}
	qpos.AdoptHeaderFinality(0, 1, checkpoint)
	if !qpos.SetFinalizedCheckpointSlot(checkpoint, 30) {
		t.Fatal("precondition: the checkpoint slot 30 must be pinnable")
	}
	if slot, ok := qpos.FinalizedCheckpointSlot(); !ok || slot != 30 {
		t.Fatalf("precondition: checkpoint slot = (%d, %v), want (30, true)", slot, ok)
	}
	return qpos
}

// TestR30F22_StoreRollbackJudgesTheSurvivingTip pins the crossing shape: the
// first deleted block (slot 40) is above the checkpoint (slot 30) and the block
// that survives (slot 28) is below it. The rollback abandons the checkpoint
// block, so it must be refused — the old criterion only looked at slot 40 and
// passed.
func TestR30F22_StoreRollbackJudgesTheSurvivingTip(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	// heights 0..4 at slots 0/28/40/45/50.
	r29BuildChain(t, bs, 0, 28, 40, 45, 50)

	s := &Syncer{blockStore: bs, qpos: r30F22QPOS(t)}

	// from height 2: survives with height 1 (slot 28 < 30) → the checkpoint
	// block would be deleted.
	touches, checkpointSlot, proven := s.rollbackTouchesFinality(2)
	if !touches || !proven || checkpointSlot != 30 {
		t.Fatalf("rollback from height 2: touches=%v proven=%v slot=%d, want touches=true proven=true slot=30",
			touches, proven, checkpointSlot)
	}
	if blocked, _ := s.rollbackBelowFinality(2); !blocked {
		t.Fatal("a rollback whose surviving tip sits below the checkpoint must be refused")
	}

	// from height 3: survives with height 2 (slot 40 ≥ 30) → legal.
	if blocked, _ := s.rollbackBelowFinality(3); blocked {
		t.Fatal("a rollback whose surviving tip is above the checkpoint must be allowed")
	}

	// from height 1: survives with genesis (slot 0) → refused.
	if blocked, _ := s.rollbackBelowFinality(1); !blocked {
		t.Fatal("a rollback that would delete every block above genesis must be refused")
	}
}

// TestR30F22_FragmentedTruncationSeparatesUnprovenFromFinality pins the other
// half (auditor finding W1): "the survivor's slot cannot be established" is not
// the same claim as "this reaches finalized history". The repair must stay off
// in both cases, but only the second may stop production — declaring the first
// one a finality violation made the R53 self-repair permanently dead for the
// very stores it exists for.
func TestR30F22_FragmentedTruncationSeparatesUnprovenFromFinality(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	// heights 0..3 at slots 0/10/40/45.
	r29BuildChain(t, bs, 0, 10, 40, 45)
	finality := NewSyncer(nil, bs, nil, nil, 1669)
	finality.SetQPOS(r30QPOSWithFinality(t)) // boundary slot 32

	// Survivor unreadable (no block at height 9): leave the store alone, but do
	// not claim finalized history is at stake.
	n := &Node{blockStore: bs, syncer: finality, stateTrust: newStateTrust()}
	truncated, refused, err := n.truncateFragmentedChain(9, 10)
	if err != nil || !refused || truncated != 0 {
		t.Fatalf("unprovable truncation: truncated=%d refused=%v err=%v, want 0/true/nil", truncated, refused, err)
	}
	if !n.stateTrust.ok() {
		t.Fatal("an unprovable truncation must not break state trust")
	}
	if latest, gerr := bs.GetLatestHeight(); gerr != nil || latest != 3 {
		t.Fatalf("an unprovable truncation must leave the store untouched: latest=%d err=%v", latest, gerr)
	}

	// Survivor above the checkpoint (height 2, slot 40): the repair runs.
	survivor := &Node{blockStore: bs, syncer: finality, stateTrust: newStateTrust()}
	truncated, refused, err = survivor.truncateFragmentedChain(2, 3)
	if err != nil || refused || truncated != 1 {
		t.Fatalf("legal truncation: truncated=%d refused=%v err=%v, want 1/false/nil", truncated, refused, err)
	}
	if latest, gerr := bs.GetLatestHeight(); gerr != nil || latest != 2 {
		t.Fatalf("the legal truncation must delete the orphan above height 2: latest=%d err=%v", latest, gerr)
	}

	// Survivor below the checkpoint (height 1, slot 10): finalized history.
	bs2 := block.NewBlockStore(db.NewMemDB())
	r29BuildChain(t, bs2, 0, 10, 20, 40)
	f2 := NewSyncer(nil, bs2, nil, nil, 1669)
	f2.SetQPOS(r30QPOSWithFinality(t))
	finalized := &Node{blockStore: bs2, syncer: f2, stateTrust: newStateTrust()}
	if _, refused, err := finalized.truncateFragmentedChain(1, 3); err != nil || !refused {
		t.Fatalf("a truncation reaching finalized history must be refused (refused=%v err=%v)", refused, err)
	}
	if finalized.stateTrust.ok() {
		t.Fatal("a truncation reaching finalized history must break state trust")
	}
	if latest, gerr := bs2.GetLatestHeight(); gerr != nil || latest != 3 {
		t.Fatalf("a refused truncation must leave the store untouched: latest=%d err=%v", latest, gerr)
	}
}
