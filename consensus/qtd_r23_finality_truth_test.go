// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// R23 (2026-10-29) — finality truthfulness and seal liveness.
//
// The R23 audit found that the finality surface collapsed three independent
// facts into one boolean:
//
//	(a) a threshold seal agreement is RECORDED for a slot,
//	(b) the sealed block is the CANONICAL block of that slot,
//	(c) the QPOS consensus finality marker has reached the slot's EPOCH.
//
// A quorum seal over a side-branch block therefore used to be reported as
// "finalized" together with that fork block's hash (R23-01), and the retained
// agreement was invisible in the seal-status RPC (R23-02).
//
// The tests below pin:
//
//   - the three-state truth surface (matches / differs / unknown) and the
//     honest block-level finality answer derived from it,
//   - the liveness re-drive: a seal that completed BEFORE the canonical root
//     landed must advance the finality markers once the root arrives (R23-05),
//   - the re-seal path: a provably non-canonical agreement must not wedge the
//     canonical block of its slot forever (R23-04),
//   - the fail-closed rule: a non-canonical seal advances NO finality marker
//     (not just finalizedRoot).
//
// Slots are chosen across epoch boundaries on purpose: SlotToEpoch(slot) is
// slot/32, so every slot below 32 lives in epoch 0 — the epoch whose
// "finalized" marker is indistinguishable from "nothing has been finalized
// yet". A marker assertion is only meaningful at epoch >= 1.
// ─────────────────────────────────────────────────────────────────────────────

// r23AssignExecutive installs the executive chamber for the given epoch and
// completes its DKG, so RequestSeal accepts the slot.
func r23AssignExecutive(t *testing.T, coordinator *ThreeChambersCoordinator, epoch uint64) {
	t.Helper()
	if err := coordinator.AssignExecutive([]int{0, 1, 2}, epoch); err != nil {
		t.Fatalf("AssignExecutive(epoch=%d): %v", epoch, err)
	}
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	if err := executive.SetMembers([]int{0, 1, 2}, epoch); err != nil {
		t.Fatalf("SetMembers(epoch=%d): %v", epoch, err)
	}
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete: %v", err)
	}
}

// r23CompleteSeal submits the two partial signatures that reach the 2/3
// weight quorum of a 3-validator set (total 3000, required 2000).
func r23CompleteSeal(t *testing.T, qfs *QTDFinalityState, slot uint64) {
	t.Helper()
	if err := qfs.SubmitPartialSeal(0, slot, []byte("r23-partial-seal-0-min16bytes")); err != nil {
		t.Fatalf("SubmitPartialSeal(0, %d): %v", slot, err)
	}
	if err := qfs.SubmitPartialSeal(1, slot, []byte("r23-partial-seal-1-min16bytes")); err != nil {
		t.Fatalf("SubmitPartialSeal(1, %d): %v", slot, err)
	}
}

// r23WaitFor polls a condition until it holds or the timeout expires.
func r23WaitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", what)
	}
}

// r23FinalityMarkers is a snapshot of the four QPOS finality markers
// (R24, 2026-10-29 — auditor finding X06).
type r23FinalityMarkers struct {
	finalizedEpoch uint64
	finalizedRoot  types.Hash
	justifiedEpoch uint64
	justifiedRoot  types.Hash
}

func r23SnapshotFinalityMarkers(qpos *QPOS) r23FinalityMarkers {
	qpos.mu.RLock()
	defer qpos.mu.RUnlock()
	return r23FinalityMarkers{
		finalizedEpoch: qpos.finalizedEpoch,
		finalizedRoot:  qpos.finalizedRoot,
		justifiedEpoch: qpos.justifiedEpoch,
		justifiedRoot:  qpos.justifiedRoot,
	}
}

// r23AssertFinalityMarkersUnchanged asserts that the QPOS finality markers
// did not move between the two snapshots.
//
// R24 (2026-10-29) FIX (auditor finding X06): the previous helper compared
// the markers against ABSOLUTE values (epoch 0, zero hash), which is coupled
// to a fixture whose genesis root is unnamed. A fixture that registers a
// genesis root (SetGenesisRoot) starts with a non-zero finalizedRoot, and
// the absolute assertion would fire on legitimate state. The comparison is
// now before/after — it asserts the seal's EFFECT, not the fixture's
// starting point.
func r23AssertFinalityMarkersUnchanged(t *testing.T, before, after r23FinalityMarkers, what string) {
	t.Helper()
	if after.finalizedEpoch != before.finalizedEpoch {
		t.Fatalf("%s: finalizedEpoch moved %d -> %d", what, before.finalizedEpoch, after.finalizedEpoch)
	}
	if after.justifiedEpoch != before.justifiedEpoch {
		t.Fatalf("%s: justifiedEpoch moved %d -> %d", what, before.justifiedEpoch, after.justifiedEpoch)
	}
	if after.finalizedRoot != before.finalizedRoot {
		t.Fatalf("%s: finalizedRoot moved %s -> %s", what, before.finalizedRoot.String(), after.finalizedRoot.String())
	}
	if after.justifiedRoot != before.justifiedRoot {
		t.Fatalf("%s: justifiedRoot moved %s -> %s", what, before.justifiedRoot.String(), after.justifiedRoot.String())
	}
}

// r23WaitForClassification waits until the slot's PERSISTED canonical
// classification equals the wanted state (R24, 2026-10-29 — auditor finding
// X05).
//
// The production finalizer runs in a goroutine launched by the seal
// pipeline. persistCanonicalState is the LAST effect that runs on the
// non-matching paths, so the persisted classification is the deterministic
// "the asynchronous finalizer has finished" signal: a marker assertion made
// without waiting for it passed or failed by scheduling luck.
//
// Only Matches and Differs are observable this way — Unknown is the zero
// value of SealRootState, so "still zero" cannot be distinguished from "not
// yet run". The negative tests below all wait for Differs.
func r23WaitForClassification(t *testing.T, qfs *QTDFinalityState, slot uint64, want SealRootState, what string) {
	t.Helper()
	r23WaitFor(t, what, 5*time.Second, func() bool {
		rec := qfs.GetFinalityRecord(slot)
		return rec != nil && rec.CanonicalState == want
	})
}

// TestR23_SealStatus_ThreeStates pins the three independent finality facts
// for every combination of (record present, canonical root known).
func TestR23_SealStatus_ThreeStates(t *testing.T) {
	t.Run("no record", func(t *testing.T) {
		qpos, _, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()

		status := qfs.GetSlotSealStatus(32)
		if status.SealRecorded {
			t.Fatal("no seal was requested: SealRecorded must be false")
		}
		if status.RootState != SealRootUnknown {
			t.Fatalf("RootState = %s, want unknown", status.RootState.String())
		}
		if status.IsFinalized() {
			t.Fatal("a slot without a seal must never be reported as finalized")
		}
		if qfs.IsBlockFinalized(32) {
			t.Fatal("IsBlockFinalized must be false without a seal")
		}
		if qfs.IsCanonicalSeal(32) {
			t.Fatal("IsCanonicalSeal must be false without a seal")
		}
	})

	t.Run("canonical seal", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		blockHash := types.Hash{0xC1}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		qpos.SetSlotBlockRoot(slot, blockHash)
		if err := qfs.RequestSeal(slot, blockHash); err != nil {
			t.Fatalf("RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)

		status := qfs.GetSlotSealStatus(slot)
		if !status.SealRecorded {
			t.Fatal("SealRecorded must be true after the threshold completed")
		}
		if status.RootState != SealRootMatches {
			t.Fatalf("RootState = %s, want matches", status.RootState.String())
		}
		if !status.IsFinalized() {
			t.Fatal("a canonical seal must be reported as finalized")
		}
		if !qfs.IsBlockFinalized(slot) {
			t.Fatal("IsBlockFinalized must be true for a canonical seal")
		}
		if !qfs.IsCanonicalSeal(slot) {
			t.Fatal("IsCanonicalSeal must be true for a canonical seal")
		}
	})

	t.Run("retained side-branch seal", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(64)
		sideBranch := types.Hash{0x5A}
		canonical := types.Hash{0xA5}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		markers := r23SnapshotFinalityMarkers(qpos)
		// The seal is requested before the canonical root is known — the
		// bootstrap case RequestSeal explicitly allows.
		if err := qfs.RequestSeal(slot, sideBranch); err != nil {
			t.Fatalf("bootstrap RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)

		// The canonical chain later publishes a DIFFERENT root for the slot.
		qpos.SetSlotBlockRoot(slot, canonical)

		status := qfs.GetSlotSealStatus(slot)
		if !status.SealRecorded {
			t.Fatal("the threshold agreement must survive a non-canonical seal (R4-CORE-04)")
		}
		if status.RootState != SealRootDiffers {
			t.Fatalf("RootState = %s, want differs", status.RootState.String())
		}
		if status.IsFinalized() {
			t.Fatal("a provably non-canonical seal must never be reported as finalized")
		}
		if qfs.IsBlockFinalized(slot) {
			t.Fatal("IsBlockFinalized must be false for a non-canonical seal")
		}
		if qfs.IsCanonicalSeal(slot) {
			t.Fatal("IsCanonicalSeal must be false for a non-canonical seal")
		}
		// The asynchronous finalizer must have finished classifying the seal
		// before the marker assertion is made (R24: no scheduling luck).
		r23WaitForClassification(t, qfs, slot, SealRootDiffers, "the finalizer to classify the side-branch seal")
		// A non-canonical agreement advances no finality marker at all.
		r23AssertFinalityMarkersUnchanged(t, markers, r23SnapshotFinalityMarkers(qpos), "side-branch seal")
	})

	t.Run("seal with unknown canonical root", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		blockHash := types.Hash{0x3C}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		if err := qfs.RequestSeal(slot, blockHash); err != nil {
			t.Fatalf("bootstrap RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)

		status := qfs.GetSlotSealStatus(slot)
		if !status.SealRecorded {
			t.Fatal("SealRecorded must be true after the threshold completed")
		}
		if status.RootState != SealRootUnknown {
			t.Fatalf("RootState = %s, want unknown", status.RootState.String())
		}
		if status.EpochFinal {
			t.Fatal("the QPOS epoch marker has not reached this epoch yet")
		}
		if status.IsFinalized() {
			t.Fatal("an unconfirmed seal must not be reported as finalized")
		}
		if qfs.IsBlockFinalized(slot) {
			t.Fatal("IsBlockFinalized must be false while the canonical root is unknown")
		}
	})
}

// r23InjectSealRecord stores a seal agreement for a slot WITHOUT launching the
// asynchronous finalizer.
//
// The production finalizer is launched as a goroutine by the seal pipeline, so
// a test that races it cannot tell "the re-drive advanced the finality state"
// apart from "the asynchronous finalizer happened to run after the canonical
// root landed". Injecting the record keeps the re-drive test deterministic:
// the only actor that can advance the finality state is the re-drive itself.
//
// The record's CONTENT is what the re-drive reads (slot, block hash, epoch),
// so the injected record is equivalent to a completed seal for this purpose.
func r23InjectSealRecord(t *testing.T, qfs *QTDFinalityState, slot uint64, blockHash types.Hash) {
	t.Helper()
	qfs.mu.Lock()
	qfs.instantFinalizedSlots[slot] = &InstantFinalityRecord{
		Slot:      slot,
		BlockHash: blockHash,
		SealedAt:  time.Unix(int64(slot), 0),
		Sealers:   []int{0, 1},
		Epoch:     SlotToEpoch(slot),
	}
	qfs.mu.Unlock()
}

// TestR23_ReconcileCanonicalSeal_AdvancesFinalityWhenRootLandsLate pins the
// R23-05 liveness fix: the asynchronous finalizer runs ONCE, when the
// threshold completes. A seal that completed before the canonical root was
// imported was recorded but never advanced the QPOS finality state, and
// nothing re-ran it — the slot silently lost its instant finality.
func TestR23_ReconcileCanonicalSeal_AdvancesFinalityWhenRootLandsLate(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32)
	blockHash := types.Hash{0x7B}

	// The agreement exists; no canonical root is known yet, so nothing has
	// advanced the finality state.
	r23InjectSealRecord(t, qfs, slot, blockHash)
	if got := qpos.GetFinalizedEpoch(); got != 0 {
		t.Fatalf("finalizedEpoch = %d, want 0 (no canonical root known yet)", got)
	}

	// The canonical root lands → the seal is re-driven.
	qpos.SetSlotBlockRoot(slot, blockHash)
	r23WaitFor(t, "finality advance after the canonical root landed", 5*time.Second, func() bool {
		return qpos.GetFinalizedEpoch() == 1
	})

	if got := qpos.GetJustifiedEpoch(); got != 1 {
		t.Fatalf("justifiedEpoch = %d, want 1", got)
	}
	if got := qpos.GetFinalizedRoot(); got != blockHash {
		t.Fatalf("finalizedRoot = %s, want %s", got.String(), blockHash.String())
	}
	qpos.mu.RLock()
	justifiedRoot := qpos.justifiedRoot
	qpos.mu.RUnlock()
	if justifiedRoot != blockHash {
		t.Fatalf("justifiedRoot = %s, want %s", justifiedRoot.String(), blockHash.String())
	}
	if !qfs.IsBlockFinalized(slot) {
		t.Fatal("the reconciled seal must be reported as finalized")
	}
	if !qfs.IsCanonicalSeal(slot) {
		t.Fatal("the reconciled seal must be reported as canonical")
	}
}

// TestR23_SealCompletedBeforeRootImport_EventuallyFinalizes is the end-to-end
// counterpart of the re-drive test: the whole production pipeline (seal
// request → threshold completion → block import) must end with the slot
// reported as finalized, whichever of the two finalization paths (the
// asynchronous finalizer or the re-drive) wins the race.
func TestR23_SealCompletedBeforeRootImport_EventuallyFinalizes(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32)
	blockHash := types.Hash{0x7B}

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)
	// No canonical root yet: the seal is requested and completes before the
	// block is imported.
	if err := qfs.RequestSeal(slot, blockHash); err != nil {
		t.Fatalf("bootstrap RequestSeal: %v", err)
	}
	r23CompleteSeal(t, qfs, slot)

	if rec := qfs.GetFinalityRecord(slot); rec == nil {
		t.Fatal("the threshold agreement must be recorded")
	}

	// The canonical root lands (the block is imported).
	qpos.SetSlotBlockRoot(slot, blockHash)

	r23WaitFor(t, "the slot to become final", 5*time.Second, func() bool {
		return qfs.IsBlockFinalized(slot)
	})
	if got := qpos.GetFinalizedEpoch(); got != 1 {
		t.Fatalf("finalizedEpoch = %d, want 1", got)
	}
}

// TestR23_ReconcileCanonicalSeal_IgnoresForeignRoot is the negative control
// for the re-drive: a retained agreement over a DIFFERENT block must not
// advance any finality marker when the canonical root lands.
func TestR23_ReconcileCanonicalSeal_IgnoresForeignRoot(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32)
	sideBranch := types.Hash{0x5A}
	canonical := types.Hash{0xA5}

	r23InjectSealRecord(t, qfs, slot, sideBranch)

	markers := r23SnapshotFinalityMarkers(qpos)
	// The canonical root lands and differs from the sealed hash: the re-drive
	// must find no agreement for THIS block and advance nothing.
	qpos.SetSlotBlockRoot(slot, canonical)

	status := qfs.GetSlotSealStatus(slot)
	if status.RootState != SealRootDiffers {
		t.Fatalf("RootState = %s, want differs", status.RootState.String())
	}
	r23AssertFinalityMarkersUnchanged(t, markers, r23SnapshotFinalityMarkers(qpos), "re-drive over a foreign root")
}

// TestR23_NonCanonicalSeal_AdvancesNoFinalityMarker pins the strong form of
// the R4-CORE-04 rule: a quorum seal over a side-branch block advances
// NEITHER the finalized nor the justified epoch, and writes NEITHER root.
//
// The scenario is the one the R4-CORE-04 defense-in-depth covers: the seal
// was requested while the canonical root was unknown, and the canonical chain
// published a different root before the threshold completed.
func TestR23_NonCanonicalSeal_AdvancesNoFinalityMarker(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32)
	sideBranch := types.Hash{0x5A}
	canonical := types.Hash{0xA5}

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)
	markers := r23SnapshotFinalityMarkers(qpos)
	if err := qfs.RequestSeal(slot, sideBranch); err != nil {
		t.Fatalf("bootstrap RequestSeal: %v", err)
	}
	// The canonical root lands BEFORE the threshold completes, and it differs.
	qpos.SetSlotBlockRoot(slot, canonical)
	r23CompleteSeal(t, qfs, slot)

	// The agreement is recorded — the threshold proof survives (R4-CORE-04).
	if rec := qfs.GetFinalityRecord(slot); rec == nil {
		t.Fatal("the threshold agreement must be recorded")
	} else if rec.BlockHash != sideBranch {
		t.Fatalf("record.BlockHash = %s, want %s", rec.BlockHash.String(), sideBranch.String())
	}

	// The asynchronous finalizer must have finished classifying the seal
	// before the marker assertion is made (R24: no scheduling luck).
	r23WaitForClassification(t, qfs, slot, SealRootDiffers, "the finalizer to classify the side-branch seal")

	// …but no finality marker moved.
	r23AssertFinalityMarkersUnchanged(t, markers, r23SnapshotFinalityMarkers(qpos), "side-branch seal")

	status := qfs.GetSlotSealStatus(slot)
	if status.RootState != SealRootDiffers {
		t.Fatalf("RootState = %s, want differs", status.RootState.String())
	}
	if status.IsFinalized() {
		t.Fatal("a provably non-canonical seal must never be reported as finalized")
	}
}

// TestR23_NonCanonicalSeal_NoMarkerMove_WithNamedGenesisRoot is the fixture
// variant the snapshot-based marker assertion requires (R24, 2026-10-29 —
// auditor finding X06): the same side-branch scenario, but the fixture
// registers a genesis root, so finalizedRoot starts NON-zero. The absolute
// "markers are zero" assertion the previous helper used would have fired on
// this fixture's legitimate starting state.
//
// The scenario also pins that the epoch-checkpoint positive-evidence rule
// cannot be abused: the named root belongs to epoch 0, and the sealed slot
// lives in epoch 1, so the checkpoint provides no evidence for it either way.
func TestR23_NonCanonicalSeal_NoMarkerMove_WithNamedGenesisRoot(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32) // epoch 1 — a marker assertion is only meaningful here
	sideBranch := types.Hash{0x5A}
	canonical := types.Hash{0xA5}
	genesis := types.Hash{0xE0}

	qpos.SetGenesisRoot(genesis)
	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)
	markers := r23SnapshotFinalityMarkers(qpos)
	if markers.finalizedRoot != (types.Hash{}) {
		t.Fatalf("fixture precondition: finalizedRoot = %s, want the zero hash before any seal", markers.finalizedRoot.String())
	}

	if err := qfs.RequestSeal(slot, sideBranch); err != nil {
		t.Fatalf("bootstrap RequestSeal: %v", err)
	}
	r23CompleteSeal(t, qfs, slot)
	qpos.SetSlotBlockRoot(slot, canonical)

	r23WaitForClassification(t, qfs, slot, SealRootDiffers, "the finalizer to classify the side-branch seal")
	r23AssertFinalityMarkersUnchanged(t, markers, r23SnapshotFinalityMarkers(qpos), "side-branch seal with a named genesis root")

	status := qfs.GetSlotSealStatus(slot)
	if status.RootState != SealRootDiffers || status.IsFinalized() {
		t.Fatalf("RootState = %s, finalized = %t; want differs / false", status.RootState.String(), status.IsFinalized())
	}
}

// TestR23_RequestSeal_ReSealsOverProvablyNonCanonicalRecord pins the R23-04
// liveness fix: a retained agreement over a side-branch block must not wedge
// the canonical block of that slot forever.
//
// Before R23, RequestSeal refused every slot that already had a record
// ("slot already finalized"), so the canonical block of a forked slot could
// never obtain a seal of its own — instant finality was silently lost.
func TestR23_RequestSeal_ReSealsOverProvablyNonCanonicalRecord(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32)
	sideBranch := types.Hash{0x5A}
	canonical := types.Hash{0xA5}

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)
	if err := qfs.RequestSeal(slot, sideBranch); err != nil {
		t.Fatalf("bootstrap RequestSeal: %v", err)
	}
	r23CompleteSeal(t, qfs, slot)

	// The canonical chain publishes a different root for the slot.
	qpos.SetSlotBlockRoot(slot, canonical)

	rec := qfs.GetFinalityRecord(slot)
	if rec == nil || rec.BlockHash != sideBranch {
		t.Fatal("the stale agreement must be present before the re-seal request")
	}

	// Re-sealing the CANONICAL block must now be allowed.
	if err := qfs.RequestSeal(slot, canonical); err != nil {
		t.Fatalf("RequestSeal over a provably non-canonical record must be allowed: %v", err)
	}

	// The stale agreement must NOT be deleted by the request — it is the
	// threshold-agreement proof, and it is only replaced when the canonical
	// seal actually completes.
	rec = qfs.GetFinalityRecord(slot)
	if rec == nil {
		t.Fatal("the stale agreement must survive the re-seal request")
	}
	if rec.BlockHash != sideBranch {
		t.Fatalf("record.BlockHash = %s, want the stale %s", rec.BlockHash.String(), sideBranch.String())
	}

	pending := qfs.GetPendingSeal(slot)
	if pending == nil {
		t.Fatal("a pending seal for the canonical block must exist")
	}
	if pending.BlockHash != canonical {
		t.Fatalf("pending.BlockHash = %s, want the canonical %s", pending.BlockHash.String(), canonical.String())
	}

	// The truth surface keeps reporting both facts at once.
	status := qfs.GetSlotSealStatus(slot)
	if !status.SealRecorded {
		t.Fatal("SealRecorded must stay true while the re-seal is pending")
	}
	if status.RootState != SealRootDiffers {
		t.Fatalf("RootState = %s, want differs", status.RootState.String())
	}
	if status.IsFinalized() {
		t.Fatal("the stale agreement must not be reported as finalized")
	}
}

// TestR23_RequestSeal_StillRefusesCanonicalAndUnknownRecords is the negative
// control for the re-seal path: only a PROVABLY non-canonical record may be
// re-sealed. A record over the canonical block, and a record whose canonical
// root is still unknown, are both refused.
func TestR23_RequestSeal_StillRefusesCanonicalAndUnknownRecords(t *testing.T) {
	t.Run("canonical record is refused", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		blockHash := types.Hash{0xC1}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		qpos.SetSlotBlockRoot(slot, blockHash)
		if err := qfs.RequestSeal(slot, blockHash); err != nil {
			t.Fatalf("RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)

		err := qfs.RequestSeal(slot, blockHash)
		if err == nil {
			t.Fatal("re-sealing an already canonical slot must be refused")
		}
		if !strings.Contains(err.Error(), "already finalized") {
			t.Fatalf("error = %v, want an 'already finalized' refusal", err)
		}
	})

	t.Run("record with unknown root is refused", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(64)
		blockHash := types.Hash{0x3C}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		if err := qfs.RequestSeal(slot, blockHash); err != nil {
			t.Fatalf("bootstrap RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)

		// The canonical root is still unknown, so the record may well be the
		// canonical one — the request must be refused, not silently re-sealed.
		err := qfs.RequestSeal(slot, blockHash)
		if err == nil {
			t.Fatal("re-sealing a slot whose canonical root is unknown must be refused")
		}
		if !strings.Contains(err.Error(), "already finalized") {
			t.Fatalf("error = %v, want an 'already finalized' refusal", err)
		}
	})
}
