// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R27 (2026-10-30) — regression tests for the two remaining findings of the
// R26 independent re-review: N1 (a head rollback leaves roots above the new
// head behind) and N2 (the zero-root normalisation was not applied at every
// read entry point).

// TestR27_HeadRollbackInvalidatesSlotsAboveNewHead pins N1: when the head moves
// BACKWARDS, the roots recorded for the slots the new head no longer reaches
// belong to the abandoned chain. They must be dropped together with their seal
// classifications, otherwise a seal over a reorged-away block keeps a live
// canonical root and the RPC keeps reporting it as final.
func TestR27_HeadRollbackInvalidatesSlotsAboveNewHead(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const sealedSlot = uint64(40) // epoch 1
	const aboveSlot = uint64(41)
	sealed := types.Hash{0xE1}

	qpos.SetSlotBlockRoot(sealedSlot, sealed)
	qpos.SetSlotBlockRoot(aboveSlot, types.Hash{0xE2})
	r23InjectSealRecord(t, qfs, sealedSlot, sealed)
	qfs.persistCanonicalState(sealedSlot, sealed, SealRootMatches)
	if !qfs.IsBlockFinalized(sealedSlot) {
		t.Fatal("precondition: the seal over the live canonical root must be final")
	}

	// The head rolls back to slot 39: the replaced head was slot 41.
	qpos.ReanchorSlotRootsWithStaleAbove(map[uint64]types.Hash{39: {0x39}}, nil, aboveSlot)

	if root, known := qpos.GetSlotBlockRoot(sealedSlot); known {
		t.Fatalf("slot %d kept a root %s from the abandoned chain (N1)", sealedSlot, root.String())
	}
	if root, known := qpos.GetSlotBlockRoot(aboveSlot); known {
		t.Fatalf("slot %d kept a root %s from the abandoned chain (N1)", aboveSlot, root.String())
	}
	if got := r24SealRecordClassification(t, qfs, sealedSlot); got == SealRootMatches {
		t.Fatal("a seal over a rolled-back block still claims to be canonical (N1)")
	}
	if qfs.IsBlockFinalized(sealedSlot) {
		t.Fatal("a rolled-back block is still reported as final (N1)")
	}
}

// TestR27_ForwardReorgKeepsLaterSlots is the negative control for N1: a normal
// forward reorg must not drop roots above its own range — those are future
// slots recorded by concurrent imports.
func TestR27_ForwardReorgKeepsLaterSlots(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	const futureSlot = uint64(50)
	future := types.Hash{0xF5}

	qpos.SetSlotBlockRoot(futureSlot, future)

	// Forward reorg: new head slot 41, replaced head slot 40.
	qpos.ReanchorSlotRootsWithStaleAbove(map[uint64]types.Hash{41: {0x41}}, nil, 40)

	if root, known := qpos.GetSlotBlockRoot(futureSlot); !known || root != future {
		t.Fatalf("a forward reorg dropped a root above its range: known=%v root=%s", known, root.String())
	}
}

// TestR27_StaleEpochCheckpointDoesNotConfirmSeal pins the second half of N1:
// after a rollback, an epoch checkpoint recorded for an epoch ABOVE the new head
// describes the abandoned chain. If it survives, the checkpoint fallback in
// sealRootState still confirms a seal over a reorged-away block even though its
// slot root is gone.
func TestR27_StaleEpochCheckpointDoesNotConfirmSeal(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32) // first slot of epoch 1 — also the epoch checkpoint
	sealed := types.Hash{0xA1}

	qpos.SetSlotBlockRoot(slot, sealed)
	qpos.SetEpochBlockRoot(1, sealed)
	r23InjectSealRecord(t, qfs, slot, sealed)
	qfs.persistCanonicalState(slot, sealed, SealRootMatches)
	if !qfs.IsBlockFinalized(slot) {
		t.Fatal("precondition: the checkpoint-backed seal must be final")
	}

	// Rollback to slot 10 (epoch 0): epoch 1 has no canonical block at all.
	qpos.ReanchorSlotRootsWithStaleAbove(map[uint64]types.Hash{10: {0x0A}}, nil, slot)

	if root, known := qpos.GetEpochBlockRoot(1); known {
		t.Fatalf("epoch 1 kept the abandoned chain's checkpoint %s (N1)", root.String())
	}
	status, record := qfs.GetSlotSealDetails(slot)
	if record == nil {
		t.Fatal("the threshold-agreement record must survive")
	}
	if status.RootState != SealRootUnknown {
		t.Fatalf("canonical state = %s, want unknown — a stale checkpoint must not confirm the seal (N1)", status.RootState.String())
	}
	if qfs.IsBlockFinalized(slot) {
		t.Fatal("the epoch-checkpoint fallback still confirmed a rolled-back block as final (N1)")
	}
}

// TestR27_ZeroRootIsNotKnownAtTheAccessor pins N2: the all-zero placeholder is
// reported as "not known" by the read entry point, so every consumer — seal
// driver, announcement path, block producer, reporting layer — reaches the same
// verdict without each one re-implementing the check.
func TestR27_ZeroRootIsNotKnownAtTheAccessor(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	const slot = uint64(32)

	qpos.mu.Lock()
	qpos.slotBlockRoots[slot] = types.Hash{}
	qpos.mu.Unlock()

	if root, known := qpos.GetSlotBlockRoot(slot); known || root != (types.Hash{}) {
		t.Fatalf("a recorded zero root is still reported as known (root=%s) (N2)", root.String())
	}
}

// TestR27_ZeroRootFallsBackToCheckpoint pins the consistency this round adds:
// with a zero slot root the marker-advance path now consults the epoch
// checkpoint exactly like the reporting layer does, instead of dead-ending at
// "no information".
func TestR27_ZeroRootFallsBackToCheckpoint(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32) // epoch 1
	sealed := types.Hash{0xB2}

	qpos.mu.Lock()
	qpos.slotBlockRoots[slot] = types.Hash{}
	qpos.mu.Unlock()

	if state := qfs.advanceQPOSFinalityForSeal(slot, sealed); state != SealRootUnknown {
		t.Fatalf("without a checkpoint a zero root must advance nothing: got %s", state.String())
	}

	qpos.SetEpochBlockRoot(1, sealed)
	if state := qfs.advanceQPOSFinalityForSeal(slot, sealed); state != SealRootMatches {
		t.Fatalf("a zero slot root must fall back to the matching checkpoint: got %s", state.String())
	}
	if got, raced := qfs.sealRootState(slot, sealed); got != SealRootMatches || raced {
		t.Fatalf("the reporting layer disagrees with the marker path: sealRootState = %s (raced=%v)", got.String(), raced)
	}
}
