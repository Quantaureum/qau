// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// R24 (2026-10-29) — the canonical classification survives the pruning of the
// per-slot root, and the published finality facts stay fail-closed.
//
// The R23 independent review (findings X01–X11) found that the R23 truth
// surface still had four holes:
//
//   - the canonical classification lived ONLY in the live per-slot root map,
//     which QPOS prunes after ~3 epochs — a pruned side-branch seal fell back
//     to the epoch marker's verdict and was re-reported as final (X02), while
//     a pruned canonical seal lost its "final" status;
//   - the epoch-0 shortcut in the strict RPC accessor skipped the epoch
//     cross-check exactly where the ambiguity bites (X09);
//   - the executive seal counter was not bumped by the re-drive, and nothing
//     stopped the two paths from counting one completion twice (X10);
//   - a stale seal announcement could never replace a provably non-canonical
//     record, so nodes disagreed about the same slot forever (X04).
//
// The tests below pin the fixed behavior. All seal slots are >= 32 (epoch 1)
// except the epoch-0 strictness test, which needs the ambiguity on purpose.
// ─────────────────────────────────────────────────────────────────────────────

// r24SealRecordClassification returns the PERSISTED canonical classification
// of a slot's seal record (zero record → the zero state).
func r24SealRecordClassification(t *testing.T, qfs *QTDFinalityState, slot uint64) SealRootState {
	t.Helper()
	rec := qfs.GetFinalityRecord(slot)
	if rec == nil {
		return SealRootUnknown
	}
	return rec.CanonicalState
}

// r24PruneSlotRoot simulates the QPOS pruning of a slot's canonical root: the
// per-slot map keeps only a few epochs, while seal records live for 10 000
// slots. Deleting the entry here is exactly what the prune loop does.
func r24PruneSlotRoot(t *testing.T, qpos *QPOS, slot uint64) {
	t.Helper()
	qpos.mu.Lock()
	delete(qpos.slotBlockRoots, slot)
	qpos.mu.Unlock()
}

// r24SealCount reads the executive chamber's seal counter.
func r24SealCount(t *testing.T, coordinator *ThreeChambersCoordinator) uint64 {
	t.Helper()
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	count, ok := executive.Stats()["sealCount"].(uint64)
	if !ok {
		t.Fatalf("sealCount is %T, want uint64", executive.Stats()["sealCount"])
	}
	return count
}

// TestR24_CanonicalClassificationSurvivesRootPruning pins the R24 storage
// rule: the canonical classification is persisted ON the seal record, so a
// canonical seal stays reportable as final after QPOS prunes the slot's
// canonical root.
//
// Before R24 the classification was re-derived from the live root only; once
// the root was pruned, a canonical seal degraded to "unknown" and lost its
// finality in the reporting layer.
func TestR24_CanonicalClassificationSurvivesRootPruning(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32) // epoch 1
	blockHash := types.Hash{0xC1}

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)
	qpos.SetSlotBlockRoot(slot, blockHash)
	if err := qfs.RequestSeal(slot, blockHash); err != nil {
		t.Fatalf("RequestSeal: %v", err)
	}
	r23CompleteSeal(t, qfs, slot)

	// The asynchronous finalizer must have persisted the classification
	// before the root is pruned (deterministic: no scheduling luck).
	r23WaitForClassification(t, qfs, slot, SealRootMatches, "the finalizer to classify the canonical seal")
	if !qfs.IsBlockFinalized(slot) {
		t.Fatal("precondition: the canonical seal is final while the root is live")
	}

	r24PruneSlotRoot(t, qpos, slot)

	status := qfs.GetSlotSealStatus(slot)
	if status.RootState != SealRootMatches {
		t.Fatalf("after pruning: RootState = %s, want matches (persisted classification)", status.RootState.String())
	}
	if !status.IsFinalized() {
		t.Fatal("after pruning: a canonical seal must stay final")
	}
	if !qfs.IsBlockFinalized(slot) {
		t.Fatal("after pruning: IsBlockFinalized must stay true")
	}
	if !qfs.IsCanonicalSeal(slot) {
		t.Fatal("after pruning: IsCanonicalSeal must stay true")
	}
	if got := r24SealRecordClassification(t, qfs, slot); got != SealRootMatches {
		t.Fatalf("persisted classification = %s, want matches", got.String())
	}
}

// TestR24_SideBranchClassificationSurvivesRootPruning is the negative control
// for the persisted classification (auditor finding X02): a retained
// side-branch seal must STAY provably non-final after the slot root is
// pruned. The R22-era fallback (unknown root → the epoch marker's verdict)
// re-reported exactly these seals as final once the root was gone.
func TestR24_SideBranchClassificationSurvivesRootPruning(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32) // epoch 1
	sideBranch := types.Hash{0x5A}
	canonical := types.Hash{0xA5}

	r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
	approveSlot(coordinator, slot)
	markers := r23SnapshotFinalityMarkers(qpos)
	if err := qfs.RequestSeal(slot, sideBranch); err != nil {
		t.Fatalf("bootstrap RequestSeal: %v", err)
	}
	r23CompleteSeal(t, qfs, slot)
	qpos.SetSlotBlockRoot(slot, canonical)

	r23WaitForClassification(t, qfs, slot, SealRootDiffers, "the finalizer to classify the side-branch seal")

	r24PruneSlotRoot(t, qpos, slot)

	status := qfs.GetSlotSealStatus(slot)
	if status.RootState != SealRootDiffers {
		t.Fatalf("after pruning: RootState = %s, want differs (persisted classification)", status.RootState.String())
	}
	if status.IsFinalized() || qfs.IsBlockFinalized(slot) {
		t.Fatal("after pruning: a provably non-canonical seal must never be reported as final")
	}
	r23AssertFinalityMarkersUnchanged(t, markers, r23SnapshotFinalityMarkers(qpos), "side-branch seal across pruning")
}

// TestR24_EpochCheckpointIsPositiveEvidenceOnly pins the R24 canonicality
// notion shared by the reporting layer and the marker-advancement path: the
// epoch checkpoint root is POSITIVE evidence only.
//
// Both subtests invoke the finalizer body SYNCHRONOUSLY: the "unknown"
// classification has no observable side effect, so a goroutine-based test
// could neither wait for it nor distinguish it from not having run.
func TestR24_EpochCheckpointIsPositiveEvidenceOnly(t *testing.T) {
	t.Run("checkpoint matches the seal", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(33) // epoch 1, not the boundary slot
		blockHash := types.Hash{0xE1}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		// The epoch checkpoint IS the sealed block (the block happens to be
		// the epoch boundary) and the slot's own root is not recorded.
		qpos.SetEpochBlockRoot(SlotToEpoch(slot), blockHash)
		if err := qfs.RequestSeal(slot, blockHash); err != nil {
			t.Fatalf("bootstrap RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)

		// Run the finalizer body synchronously (the production pipeline
		// launches it as a goroutine; same function, deterministic timing).
		qfs.completeSealLockedFinalize(slot, blockHash)

		if got := qpos.GetFinalizedEpoch(); got != SlotToEpoch(slot) {
			t.Fatalf("finalizedEpoch = %d, want %d (checkpoint evidence advances the markers)", got, SlotToEpoch(slot))
		}
		if !qfs.IsBlockFinalized(slot) {
			t.Fatal("a seal whose epoch checkpoint IS the sealed block must be final")
		}
	})

	t.Run("checkpoint differs says nothing", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(33)
		blockHash := types.Hash{0xE1}
		otherBlock := types.Hash{0xE2}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		markers := r23SnapshotFinalityMarkers(qpos)
		// A checkpoint over a DIFFERENT block proves nothing about the sealed
		// block: they are different blocks. The state must stay unknown —
		// never "differs" — and no marker may move.
		qpos.SetEpochBlockRoot(SlotToEpoch(slot), otherBlock)
		if err := qfs.RequestSeal(slot, blockHash); err != nil {
			t.Fatalf("bootstrap RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)

		qfs.completeSealLockedFinalize(slot, blockHash)

		status := qfs.GetSlotSealStatus(slot)
		if status.RootState != SealRootUnknown {
			t.Fatalf("RootState = %s, want unknown (a differing checkpoint is not negative evidence)", status.RootState.String())
		}
		if status.IsFinalized() || qfs.IsBlockFinalized(slot) {
			t.Fatal("an unclassifiable seal must not be reported as final")
		}
		r23AssertFinalityMarkersUnchanged(t, markers, r23SnapshotFinalityMarkers(qpos), "seal under a differing checkpoint")
	})
}

// TestR24_IsSealConsensusFinalized_StrictAcrossAllEpochs pins the strict
// epoch cross-check of the published RPC field (auditor finding X09): the
// check is performed for EVERY epoch, and epoch 0 counts as finalized only
// when a named finalized root exists — the same convention the ordinary
// finalizer uses for the genesis epoch.
func TestR24_IsSealConsensusFinalized_StrictAcrossAllEpochs(t *testing.T) {
	t.Run("epoch 0 without a named root is refused", func(t *testing.T) {
		qpos, _, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(5) // epoch 0 — the case the R24 revision skipped

		r23InjectSealRecord(t, qfs, slot, types.Hash{0x50})

		if qfs.IsSealConsensusFinalized(slot) {
			t.Fatal("an epoch-0 seal must not be reported as consensus-finalized while no finalized root is named")
		}
	})

	t.Run("epoch 0 with a named root is accepted", func(t *testing.T) {
		qpos, _, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(5)

		r23InjectSealRecord(t, qfs, slot, types.Hash{0x50})
		qpos.SetGenesisRoot(types.Hash{0xE0})
		if !qpos.ReanchorFinalityToGenesis() {
			t.Fatal("ReanchorFinalityToGenesis failed: the genesis root was registered")
		}

		if !qfs.IsSealConsensusFinalized(slot) {
			t.Fatal("an epoch-0 seal must be reported as consensus-finalized once the restored checkpoint names epoch 0's root")
		}
	})

	t.Run("marker behind is refused", func(t *testing.T) {
		qpos, _, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(64) // epoch 2

		r23InjectSealRecord(t, qfs, slot, types.Hash{0x64})

		if qfs.IsSealConsensusFinalized(slot) {
			t.Fatal("a seal in an epoch the marker has not reached must not be consensus-finalized")
		}
	})

	t.Run("marker caught up is accepted", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32) // epoch 1
		blockHash := types.Hash{0xC1}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		qpos.SetSlotBlockRoot(slot, blockHash)
		if err := qfs.RequestSeal(slot, blockHash); err != nil {
			t.Fatalf("RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)
		r23WaitFor(t, "the marker to reach epoch 1", 5*time.Second, func() bool {
			return qpos.GetFinalizedEpoch() >= 1
		})

		if !qfs.IsSealConsensusFinalized(slot) {
			t.Fatal("a seal whose epoch marker has caught up must be consensus-finalized")
		}
	})
}

// TestR24_SealCounterCountedExactlyOnce pins the seal-counter rule (auditor
// finding X10): a completion is counted at most once per record, whichever
// path (the asynchronous finalizer or the root-arrival re-drive) observes it,
// and a record replaced by a NEW seal counts again.
func TestR24_SealCounterCountedExactlyOnce(t *testing.T) {
	t.Run("re-drive does not double-count", func(t *testing.T) {
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

		// The asynchronous finalizer counts the completion.
		r23WaitFor(t, "the seal to be counted once", 5*time.Second, func() bool {
			return r24SealCount(t, coordinator) == 1
		})

		// The re-drive (the slot root "landing" again) must not count it a
		// second time.
		qfs.reconcileCanonicalSeal(slot, blockHash)
		qfs.reconcileCanonicalSeal(slot, blockHash)
		if got := r24SealCount(t, coordinator); got != 1 {
			t.Fatalf("sealCount = %d after two re-drives, want 1", got)
		}
	})

	t.Run("root-arrival re-drive counts once", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		blockHash := types.Hash{0xC2}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		// The agreement completes while no canonical root is known: the
		// asynchronous finalizer cannot classify it, so nothing is counted.
		if err := qfs.RequestSeal(slot, blockHash); err != nil {
			t.Fatalf("bootstrap RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)
		if got := r24SealCount(t, coordinator); got != 0 {
			t.Fatalf("sealCount = %d before the root landed, want 0", got)
		}

		// The root lands: the re-drive classifies the seal, advances the
		// markers and counts the completion EXACTLY once (auditor finding
		// X10: the re-drive used to skip the counter entirely).
		qpos.SetSlotBlockRoot(slot, blockHash)
		r23WaitFor(t, "the re-drive to count the seal", 5*time.Second, func() bool {
			return r24SealCount(t, coordinator) == 1
		})
		qfs.reconcileCanonicalSeal(slot, blockHash)
		if got := r24SealCount(t, coordinator); got != 1 {
			t.Fatalf("sealCount = %d after a repeated re-drive, want 1", got)
		}
	})

	t.Run("replaced record counts again", func(t *testing.T) {
		qpos, coordinator, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		sideBranch := types.Hash{0x5A}
		canonical := types.Hash{0xA5}

		r23AssignExecutive(t, coordinator, SlotToEpoch(slot))
		approveSlot(coordinator, slot)
		// A provably non-canonical seal is never counted.
		if err := qfs.RequestSeal(slot, sideBranch); err != nil {
			t.Fatalf("bootstrap RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)
		qpos.SetSlotBlockRoot(slot, canonical)
		r23WaitForClassification(t, qfs, slot, SealRootDiffers, "the side-branch seal to be classified")
		if got := r24SealCount(t, coordinator); got != 0 {
			t.Fatalf("sealCount = %d for a side-branch seal, want 0", got)
		}

		// The canonical re-seal replaces the record and counts on its own.
		if err := qfs.RequestSeal(slot, canonical); err != nil {
			t.Fatalf("re-seal RequestSeal: %v", err)
		}
		r23CompleteSeal(t, qfs, slot)
		r23WaitFor(t, "the replacement seal to be counted", 5*time.Second, func() bool {
			return r24SealCount(t, coordinator) == 1
		})
	})
}

// TestR24_ReceiveSealAnnouncement_ReplacesStaleNonCanonicalRecord pins the
// announcement replacement rule (auditor finding X04): a peer that re-sealed
// the canonical block after a provably non-canonical seal must be able to
// make this node accept the canonical seal. The stale record is replaced ONLY
// when the local canonical root proves the stored one non-canonical.
func TestR24_ReceiveSealAnnouncement_ReplacesStaleNonCanonicalRecord(t *testing.T) {
	const validSig = "mock-aggregated-qtd-threshold-signature"

	t.Run("stale record is replaced by the canonical seal", func(t *testing.T) {
		qpos, _, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		sideBranch := types.Hash{0x5A}
		canonical := types.Hash{0xA5}

		// The side-branch agreement is stored while no canonical root is known.
		if !qfs.ReceiveSealAnnouncement(slot, sideBranch, []byte(validSig), []int{0, 1}) {
			t.Fatal("the side-branch announcement was rejected while the root was unknown")
		}
		// The canonical root lands and differs: the stored record is provably
		// non-canonical.
		qpos.SetSlotBlockRoot(slot, canonical)

		if !qfs.ReceiveSealAnnouncement(slot, canonical, []byte(validSig), []int{0, 1}) {
			t.Fatal("the canonical announcement was rejected")
		}
		rec := qfs.GetFinalityRecord(slot)
		if rec == nil || rec.BlockHash != canonical {
			t.Fatalf("record.BlockHash = %v, want the canonical %s — the stale record was not replaced", rec, canonical.String())
		}
		if rec.CanonicalState != SealRootMatches {
			t.Fatalf("record.CanonicalState = %s, want matches", rec.CanonicalState.String())
		}
		if !qfs.IsBlockFinalized(slot) {
			t.Fatal("the replaced canonical seal must be reportable as final")
		}
	})

	t.Run("stale record is kept without proof", func(t *testing.T) {
		qpos, _, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		first := types.Hash{0x5A}
		second := types.Hash{0xA5}

		// Two DIFFERENT agreements, and the canonical root stays unknown:
		// nothing proves the stored record non-canonical, so it is kept and
		// the new announcement is ignored (accepted as a no-op).
		if !qfs.ReceiveSealAnnouncement(slot, first, []byte(validSig), []int{0, 1}) {
			t.Fatal("the first announcement was rejected while the root was unknown")
		}
		if !qfs.ReceiveSealAnnouncement(slot, second, []byte(validSig), []int{0, 1}) {
			t.Fatal("the second announcement must be answered true (kept, no-op)")
		}
		rec := qfs.GetFinalityRecord(slot)
		if rec == nil || rec.BlockHash != first {
			t.Fatalf("record.BlockHash = %v, want the FIRST agreement %s — an unproven announcement must not replace it", rec, first.String())
		}
	})

	t.Run("announcement over a known different root is rejected", func(t *testing.T) {
		qpos, _, _ := setupStardustWithQTD(t, 3)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		canonical := types.Hash{0xA5}
		fork := types.Hash{0xF0}

		qpos.SetSlotBlockRoot(slot, canonical)
		if qfs.ReceiveSealAnnouncement(slot, fork, []byte(validSig), []int{0, 1}) {
			t.Fatal("an announcement over a known non-canonical block must be rejected (R4-CORE-04)")
		}
		if rec := qfs.GetFinalityRecord(slot); rec != nil {
			t.Fatalf("a rejected announcement must not store a record, got one for %s", rec.BlockHash.String())
		}
	})
}

// TestR24_SealAlreadyCovers pins the node-driver gate (auditor finding X03):
// the drivers skip a slot only when the retained agreement covers THIS block
// or is provably canonical — never merely because a record exists.
func TestR24_SealAlreadyCovers(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()
	const slot = uint64(32)
	sideBranch := types.Hash{0x5A}
	canonical := types.Hash{0xA5}
	other := types.Hash{0x0B}

	if qfs.SealAlreadyCovers(slot, sideBranch) {
		t.Fatal("without a record the gate must be open")
	}

	// A record over the requested block: closed.
	r23InjectSealRecord(t, qfs, slot, sideBranch)
	if !qfs.SealAlreadyCovers(slot, sideBranch) {
		t.Fatal("a record covering the requested block must close the gate")
	}

	// A record over a DIFFERENT block while the root is unknown: open — the
	// requested block may be the canonical one that still needs its seal.
	if qfs.SealAlreadyCovers(slot, canonical) {
		t.Fatal("an unproven record for a different block must not close the gate")
	}

	// The root lands and matches the record: the agreement is canonical — a
	// drive for any other block is pointless.
	qpos.SetSlotBlockRoot(slot, sideBranch)
	if !qfs.SealAlreadyCovers(slot, canonical) {
		t.Fatal("a provably canonical agreement must close the gate for a different block")
	}

	// The root moves to the OTHER block: the retained agreement becomes
	// provably non-canonical and the gate opens for EVERY block — the
	// canonical one needs its seal, and any other would be refused later by
	// the canonical-binding check, not by this gate.
	qpos.SetSlotBlockRoot(slot, canonical)
	if qfs.SealAlreadyCovers(slot, canonical) {
		t.Fatal("a provably non-canonical agreement must not close the gate for the canonical block")
	}
	if qfs.SealAlreadyCovers(slot, other) {
		t.Fatal("a provably non-canonical agreement must not close the gate for any block")
	}
}

// TestR24_ExecutiveStats_ConcurrentWithRecordSeal pins the R24-15 fix: Stats()
// (the chamber-status RPC path) must be safe to call concurrently with
// RecordSeal() (the seal-completion path).
//
// The pre-fix Stats() took sc.mu.RLock and then called DKGDuration(), which
// re-acquired the same RWMutex — a recursive RLock. Go's RWMutex is not
// reentrant under writer contention: once RecordSeal's write lock was queued
// between the two acquisitions, the inner RLock waited for the writer and the
// writer waited for the outer RLock, deadlocking both goroutines forever (the
// R24 determinism battery caught a 28-minute stuck pair). This test hammers
// the exact interleaving; with the recursive form restored it deadlocks and
// the deadline fires.
func TestR24_ExecutiveStats_ConcurrentWithRecordSeal(t *testing.T) {
	sc := NewExecutiveChamber(3, 2)
	if err := sc.SetMembers([]int{0, 1, 2}, 1); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	if err := sc.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50_000; i++ {
			sc.RecordSeal(true)
		}
	}()

	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-done:
			// The writer finished without deadlocking a single Stats poll.
			stats := sc.Stats()
			if stats["sealCount"].(uint64) != 50_000 {
				t.Fatalf("sealCount = %v, want 50000", stats["sealCount"])
			}
			return
		case <-deadline:
			t.Fatal("Stats()/RecordSeal() deadlocked — the recursive RLock is back")
		default:
			_ = sc.Stats()
		}
	}
}
