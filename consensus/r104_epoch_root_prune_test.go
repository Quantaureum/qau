// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R104-EPOCHROOT-PRUNE-JUSTIFIED regression tests.
//
// Root cause: setEpochBlockRootLocked's prune used `pruneCutoff = epoch` (the
// freshly written, newest epoch) whenever finalizedEpoch stayed 0, and the
// wall-clock fallback referenced the never-updated field q.currentEpoch
// (dead). With the R101 backfill having written roots 61..64, the very next
// live SetEpochBlockRoot(65) deleted 64 — the SOURCE epoch of every vote
// created thereafter — so ProcessAttestation hard-rejected all votes and
// justification could never advance again.
//
// Contract: the prune MUST never remove the justified checkpoint epoch (nor
// its immediate predecessor, which in-flight votes may still reference).

// TestR104_PruneKeepsJustifiedCheckpoint: with finalized=0 and justified=J,
// writing a newer epoch root must NOT evict J (nor J-1).
func TestR104_PruneKeepsJustifiedCheckpoint(t *testing.T) {
	q, _ := setupQPOSWithKeys(4)

	q.mu.Lock()
	q.justifiedEpoch = 64
	q.finalizedEpoch = 0 // possible while finality has not yet caught up
	q.mu.Unlock()

	// R101-style backfill window, then live writes continuing past it.
	for e := uint64(61); e <= 80; e++ {
		q.SetEpochBlockRoot(e, types.Hash{byte(e)})
	}

	if !q.HasEpochRoot(64) {
		t.Fatal("justified checkpoint root was pruned")
	}
	if !q.HasEpochRoot(63) {
		t.Fatal("justified-1 root pruned (in-flight votes with source=63 would die)")
	}
}

// TestR104_PruneAfterJustifyAdvances: once justification advances past epoch
// J, roots ≤ J-2 MAY be pruned (memory stays bounded).
func TestR104_PruneAfterJustifyAdvances(t *testing.T) {
	q, _ := setupQPOSWithKeys(4)

	q.mu.Lock()
	q.justifiedEpoch = 70
	q.finalizedEpoch = 68
	q.mu.Unlock()

	for e := uint64(60); e <= 90; e++ {
		q.SetEpochBlockRoot(e, types.Hash{byte(e)})
	}

	if !q.HasEpochRoot(69) {
		t.Fatal("justified-1 root must survive prune")
	}
	// Old epochs before the justified guard window may be pruned; assert at
	// least one old entry is gone so the prune still bounds growth.
	if q.HasEpochRoot(60) && q.HasEpochRoot(61) && q.HasEpochRoot(62) {
		t.Fatal("prune never removed pre-justified roots — memory would grow unbounded")
	}
}
