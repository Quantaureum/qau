// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R25 (2026-10-30) — regression tests for the two new defects the R24
// independent re-review found in the persisted-classification work.

// TestR25_PersistCanonicalStateNeverDowngradesToUnknown pins the R25 fix for
// N1: a stale SealRootUnknown write (an asynchronous finalizer that observed
// the root as absent at threshold-completion) must not clobber a definite
// classification a faster path already persisted. Without the guard, after
// QPOS prunes the live root a canonical seal degrades to "unknown" and loses
// its final status.
func TestR25_PersistCanonicalStateNeverDowngradesToUnknown(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32) // epoch 1
	hash := types.Hash{0xC1}

	// R32d (2026-10-31, CI failure): the record is INJECTED rather than
	// produced by the real seal pipeline. The pipeline's asynchronous
	// finalizer persists its own classification concurrently, so the explicit
	// writes below raced it — on CI the finalizer's Matches landed after the
	// test's Differs and overwrote it ("no scheduling luck", the R24-05
	// rule this test originally violated). The guard semantics under test
	// live entirely in persistCanonicalState; the injected record exercises
	// them deterministically.
	r23InjectSealRecord(t, qfs, slot, hash)

	// The classification is known (a faster path recorded canonical).
	qfs.persistCanonicalState(slot, hash, SealRootMatches)
	if got := r24SealRecordClassification(t, qfs, slot); got != SealRootMatches {
		t.Fatalf("classification = %s, want matches", got.String())
	}

	// A stale asynchronous Unknown write arrives after a faster path has
	// already recorded the definite classification.
	qfs.persistCanonicalState(slot, hash, SealRootUnknown)
	if got := r24SealRecordClassification(t, qfs, slot); got != SealRootMatches {
		t.Fatalf("stale Unknown downgraded the classification to %s — a canonical seal would lose its final status after root pruning (N1)", got.String())
	}

	// known → known still overwrites: a reorg flipping the block re-says
	// non-canonical even when it was previously known-canonical.
	qfs.persistCanonicalState(slot, hash, SealRootDiffers)
	if got := r24SealRecordClassification(t, qfs, slot); got != SealRootDiffers {
		t.Fatalf("known->known overwrite was refused: classification = %s, want differs", got.String())
	}
}

// TestR25_ReanchorSlotRootsReDrivesQTDSeal pins the R25 fix for N2: a reorg
// that reverts a slot so a sealed block becomes canonical again must re-drive
// the QTD classification (and the epoch marker), not just rewrite
// slotBlockRoots. Before the fix a reverted seal stayed "differs" forever and
// that stale classification survived the next root pruning.
func TestR25_ReanchorSlotRootsReDrivesQTDSeal(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32) // epoch 1
	canonical := types.Hash{0xC1}
	sideBranch := types.Hash{0x5A}

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)

	// A side-branch seal is retained, then the canonical root of the slot
	// lands as a DIFFERENT block: the retained seal is now provably
	// non-canonical (Differs) and the marker does not advance.
	if err := qfs.RequestSeal(slot, sideBranch); err != nil {
		t.Fatalf("bootstrap RequestSeal: %v", err)
	}
	r23CompleteSeal(t, qfs, slot)
	qpos.SetSlotBlockRoot(slot, canonical)
	r23WaitForClassification(t, qfs, slot, SealRootDiffers, "the side-branch seal to be classified differs")

	before := qpos.GetFinalizedEpoch()
	if before != 0 {
		t.Fatalf("precondition: finalizedEpoch = %d, want 0 (a side-branch seal advances nothing)", before)
	}

	// The reorg reverts the slot: its canonical root becomes the sealed block
	// again. ReanchorSlotRoots must re-drive the seal — the marker advances
	// and the classification refreshes to canonical.
	qpos.ReanchorSlotRoots(map[uint64]types.Hash{slot: sideBranch}, nil)

	if got := r24SealRecordClassification(t, qfs, slot); got != SealRootMatches {
		t.Fatalf("after the reorg re-anchored the sealed block, classification = %s, want matches (N2)", got.String())
	}
	if got := qpos.GetFinalizedEpoch(); got != 1 {
		t.Fatalf("after the reorg the marker was not re-driven: finalizedEpoch = %d, want 1 (N2)", got)
	}
	if !qfs.IsBlockFinalized(slot) {
		t.Fatal("the re-anchored canonical seal must be reportable as final (N2)")
	}
}

// TestR25_ReanchorSlotRootsReDrivesNonCanonical is the negative control for
// N2: when the reorg re-anchors a slot to a DIFFERENT block than the retained
// seal, the re-drive must classify it non-canonical and advance no marker.
func TestR25_ReanchorSlotRootsReDrivesNonCanonical(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32)
	sealed := types.Hash{0x5A}
	canonical := types.Hash{0xA5}

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)

	r23InjectSealRecord(t, qfs, slot, sealed)
	markers := r23SnapshotFinalityMarkers(qpos)

	// The reorg re-anchors the slot to a block that is NOT the sealed one.
	qpos.ReanchorSlotRoots(map[uint64]types.Hash{slot: canonical}, nil)

	if got := r24SealRecordClassification(t, qfs, slot); got != SealRootDiffers {
		t.Fatalf("a seal over the reorged-away block must be classified differs: got %s", got.String())
	}
	r23AssertFinalityMarkersUnchanged(t, markers, r23SnapshotFinalityMarkers(qpos), "non-canonical re-anchor")
}

// TestR25_SlotRootZeroCarriesNoInformation pins the R25 fix for N3: a
// recorded all-zero slot root is "no information" in BOTH the reporting layer
// and the marker-advance path — never "differs".
func TestR25_SlotRootZeroCarriesNoInformation(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32) // epoch 1
	hash := types.Hash{0xC1}

	// Record an explicit ZERO root for the slot (the value, not absence).
	qpos.mu.Lock()
	qpos.slotBlockRoots[slot] = types.Hash{}
	qpos.mu.Unlock()

	r23InjectSealRecord(t, qfs, slot, hash)

	// The reporting layer must agree with advanceQPOSFinalityForSeal: a zero
	// root is no information, so the state is Unknown (not Differs) and the
	// read is not flagged as raced (R26 added the second return value).
	if got, raced := qfs.sealRootState(slot, hash); got != SealRootUnknown || raced {
		t.Fatalf("a recorded zero slot root must be no-information: sealRootState = %s, want unknown (N3)", got.String())
	}
	// The marker-advance path treats it the same way: nothing advances.
	state := qfs.advanceQPOSFinalityForSeal(slot, hash)
	if state != SealRootUnknown {
		t.Fatalf("advanceQPOSFinalityForSeal on a zero root = %s, want unknown", state.String())
	}
	if got := qpos.GetFinalizedEpoch(); got != 0 {
		t.Fatalf("a zero slot root advanced finalizedEpoch to %d — it must advance nothing", got)
	}
}

// TestR31_FinalizedCheckpointSlotMidEpochDegradation pins the DOCUMENTED
// limit of the checkpoint-slot pin (round-11 finding): the pin model can only
// express checkpoints at or below the finalized epoch's boundary slot. A QTD
// seal that advances finality to a MID-EPOCH block — the normal shape on a
// chain with skipped boundary slots, where the epoch root is never recorded —
// still degrades to the boundary fallback, by design. The direction
// under-protects the instant-final block (fail-safe for liveness, never
// over-refuses), matching the F21 boundary-fallback model.
func TestR31_FinalizedCheckpointSlotMidEpochDegradation(t *testing.T) {
	qpos, err := NewQPOS(makeSlotPruneTestValidatorSet(3))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	defer qpos.Stop()

	var midEpoch, boundary types.Hash
	midEpoch[0] = 0x21 // slot 33 — epoch 1, above the boundary
	boundary[0] = 0x20 // slot 32 — the epoch boundary itself

	// A QTD seal advanced finality to the mid-epoch block.
	qpos.mu.Lock()
	qpos.finalizedEpoch = 1
	qpos.finalizedRoot = midEpoch
	qpos.slotBlockRoots[33] = midEpoch
	qpos.pinFinalizedCheckpointSlotLocked()
	qpos.mu.Unlock()

	if slot, ok := qpos.FinalizedCheckpointSlot(); !ok || slot != 32 {
		t.Fatalf("a mid-epoch finalized root must degrade to the boundary slot: got (%d, %v), want (32, true)", slot, ok)
	}

	// The positive case: a finalized root ON the boundary pins exactly.
	qpos.mu.Lock()
	qpos.finalizedRoot = boundary
	qpos.slotBlockRoots[32] = boundary
	qpos.pinFinalizedCheckpointSlotLocked()
	qpos.mu.Unlock()

	if slot, ok := qpos.FinalizedCheckpointSlot(); !ok || slot != 32 {
		t.Fatalf("a boundary-slot finalized root must pin exactly: got (%d, %v), want (32, true)", slot, ok)
	}
}
