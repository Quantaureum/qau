// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R26 (2026-10-30) — regression tests for the four findings of the R25
// independent re-review. D1/D2/D3/D4 are keyed to that review.

// TestR26_ReorgDeletedRootDropsPersistedMatch pins the fix for D1: when an
// accepted reorg REMOVES the root of a slot whose seal was classified
// canonical, the persisted "matches" classification must not survive. Without
// the reset the public RPCs kept answering canonicalState="matches" and
// isFinalized=true (with the reorged-away block hash) for as long as the
// record lived — the exact over-report R23 set out to remove.
func TestR26_ReorgDeletedRootDropsPersistedMatch(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(40) // epoch 1 (slots 32..63)
	sealed := types.Hash{0xE1}

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)
	qpos.SetSlotBlockRoot(slot, sealed)
	if err := qfs.RequestSeal(slot, sealed); err != nil {
		t.Fatalf("RequestSeal: %v", err)
	}
	r23CompleteSeal(t, qfs, slot)

	// Precondition: the seal is canonical and reported as final. The
	// classification is written by the asynchronous finalizer, so wait for it
	// instead of racing the scheduler.
	r23WaitForClassification(t, qfs, slot, SealRootMatches, "the canonical seal to be classified")
	if !qfs.IsBlockFinalized(slot) {
		t.Fatal("precondition: a canonical seal must be reported as final")
	}

	// The reorg covers slots 39..41 but has NO block for slot 40: the sealed
	// block leaves the canonical chain and its per-slot root is deleted.
	qpos.ReanchorSlotRoots(map[uint64]types.Hash{
		slot - 1: {0x39},
		slot + 1: {0x41},
	}, nil)

	if got := r24SealRecordClassification(t, qfs, slot); got == SealRootMatches {
		t.Fatal("a seal whose slot root the reorg deleted still claims to be canonical (D1)")
	}
	if qfs.IsBlockFinalized(slot) {
		t.Fatal("a reorged-away block is still reported as final — the RPC would publish it with isFinalized=true (D1)")
	}
	status, record := qfs.GetSlotSealDetails(slot)
	if record == nil {
		t.Fatal("the threshold-agreement record must survive the invalidation")
	}
	if status.RootState != SealRootUnknown {
		t.Fatalf("canonical state after the reorg = %s, want unknown", status.RootState.String())
	}
}

// TestR26_ReorgDeletionLeavesOtherSealsAlone is the negative control for D1:
// the deletion hook only resets the classification of a record that attests
// the root being removed. A record attesting a DIFFERENT block (already
// classified "differs") is a fact the reorg did not change.
func TestR26_ReorgDeletionLeavesOtherSealsAlone(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(40)
	sealed := types.Hash{0xE7}
	dropped := types.Hash{0xD1}

	qpos.mu.Lock()
	qpos.slotBlockRoots[slot] = dropped
	qpos.mu.Unlock()

	r23InjectSealRecord(t, qfs, slot, sealed)
	qfs.persistCanonicalState(slot, sealed, SealRootDiffers)

	qpos.ReanchorSlotRoots(map[uint64]types.Hash{
		slot - 1: {0x39},
		slot + 1: {0x41},
	}, nil)

	if got := r24SealRecordClassification(t, qfs, slot); got != SealRootDiffers {
		t.Fatalf("classification = %s, want differs untouched (the dropped root attested another block)", got.String())
	}
	if qfs.IsBlockFinalized(slot) {
		t.Fatal("a non-canonical seal must never become final")
	}
}

// TestR26_ZeroRootDoesNotRejectSealRequest pins the admission half of D2: a
// recorded all-zero slot root is "no information" (R25/N3), so it must not act
// as a hard "not canonical" verdict that wedges the slot forever.
func TestR26_ZeroRootDoesNotRejectSealRequest(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32)
	hash := types.Hash{0xC1}

	qpos.mu.Lock()
	qpos.slotBlockRoots[slot] = types.Hash{}
	qpos.mu.Unlock()

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)

	if err := qfs.RequestSeal(slot, hash); err != nil {
		t.Fatalf("a zero slot root must not reject the seal request (D2): %v", err)
	}
}

// TestR26_ZeroRootDoesNotFreezeDiffers is the reconcile half of D2: a zero
// root must not be persisted as proof of non-canonicality.
func TestR26_ZeroRootDoesNotFreezeDiffers(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32)
	sealed := types.Hash{0xC1}

	r23InjectSealRecord(t, qfs, slot, sealed)
	qfs.persistCanonicalState(slot, sealed, SealRootMatches)

	qfs.reconcileCanonicalSeal(slot, types.Hash{})

	if got := r24SealRecordClassification(t, qfs, slot); got != SealRootMatches {
		t.Fatalf("a zero root overwrote the classification to %s — it carries no information (D2)", got.String())
	}
}

// TestR26_SnapshotConsensusFinalizedMatchesStrictAccessor pins D4: the
// consensus boolean published with the status snapshot must agree with the
// strict accessor for the same state (they are now the same computation).
func TestR26_SnapshotConsensusFinalizedMatchesStrictAccessor(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32) // epoch 1
	hash := types.Hash{0xC1}

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)
	qpos.SetSlotBlockRoot(slot, hash)
	if err := qfs.RequestSeal(slot, hash); err != nil {
		t.Fatalf("RequestSeal: %v", err)
	}
	r23CompleteSeal(t, qfs, slot)
	r23WaitForClassification(t, qfs, slot, SealRootMatches, "the canonical seal to be classified")
	// Re-drive through the root-arrival path (idempotent) so the marker state
	// under test does not depend on how far the asynchronous finalizer got.
	qfs.reconcileCanonicalSeal(slot, hash)

	status := qfs.GetSlotSealStatus(slot)
	if status.ConsensusFinalized != qfs.IsSealConsensusFinalized(slot) {
		t.Fatalf("snapshot consensusSealFinalized = %v, strict accessor = %v — the two surfaces disagree (D4)",
			status.ConsensusFinalized, qfs.IsSealConsensusFinalized(slot))
	}
	if !status.ConsensusFinalized {
		t.Fatal("the marker reached epoch 1 through this canonical seal; consensusSealFinalized must be true")
	}
}

// TestR26_PersistedFallbackNeverReplacesARacedRead pins the D3 decision as a
// pure function. A canonical-head switch between the two root reads cannot be
// reproduced on demand, so the decision itself is what gets pinned here.
func TestR26_PersistedFallbackNeverReplacesARacedRead(t *testing.T) {
	cases := []struct {
		name      string
		live      SealRootState
		raced     bool
		persisted SealRootState
		want      SealRootState
	}{
		{"live match wins", SealRootMatches, false, SealRootDiffers, SealRootMatches},
		{"live differs wins", SealRootDiffers, false, SealRootMatches, SealRootDiffers},
		{"missing root falls back (R24 pruning)", SealRootUnknown, false, SealRootMatches, SealRootMatches},
		{"raced read never falls back to matches (D3)", SealRootUnknown, true, SealRootMatches, SealRootUnknown},
		{"raced read never falls back to differs", SealRootUnknown, true, SealRootDiffers, SealRootUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := applyPersistedFallback(tc.live, tc.raced, tc.persisted); got != tc.want {
				t.Fatalf("applyPersistedFallback(%s, raced=%v, %s) = %s, want %s",
					tc.live.String(), tc.raced, tc.persisted.String(), got.String(), tc.want.String())
			}
		})
	}
}

// TestR26_StatusWithoutQPOSKeepsTheRecordedAgreement pins the `qfs.qpos == nil`
// contract that D4's refactor had to preserve: with no QPOS there is no marker
// to cross-check, so EpochFinal stays false while the consensus-layer answer
// remains the recorded agreement.
func TestR26_StatusWithoutQPOSKeepsTheRecordedAgreement(t *testing.T) {
	const slot = uint64(32)
	qfs := &QTDFinalityState{
		instantFinalizedSlots: map[uint64]*InstantFinalityRecord{
			slot: {Slot: slot, BlockHash: types.Hash{0xC2}},
		},
	}

	status, record := qfs.GetSlotSealDetails(slot)
	if record == nil || !status.SealRecorded {
		t.Fatal("the injected record must be reported")
	}
	if status.EpochFinal {
		t.Fatal("without a QPOS there is no marker to report as final")
	}
	if !status.ConsensusFinalized {
		t.Fatal("without a QPOS the recorded agreement is the consensus-layer answer (D4)")
	}
	if status.IsFinalized() {
		t.Fatal("the canonical binding is unknown, so the block must not be reported as final")
	}
}
