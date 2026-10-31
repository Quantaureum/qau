// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R28 (2026-10-30) — regression tests for the three nits of the R27 independent
// re-review: R27-O1 (a reorg dropped the justified epoch's checkpoint), R27-O3
// (the lower bound of the cleaned range was the first re-anchored slot instead
// of the common ancestor, leaving roots of skipped slots behind) and the epoch
// checkpoint staleness those two share.

// TestR28_SkippedSlotsBelowNewChainAreDropped pins R27-O3 together with the
// epoch-checkpoint half: the new chain skipped slot 32 (no canonical block
// there at all), so both the abandoned slot root AND the epoch checkpoint that
// named that block are stale. Without the ancestor lower bound the slot root
// survives — it is not in roots and lies below the old [min,max] range — and
// the checkpoint fallback keeps confirming the seal.
func TestR28_SkippedSlotsBelowNewChainAreDropped(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()

	const abandonedSlot = uint64(32) // epoch 1 boundary, skipped by the new chain
	abandoned := types.Hash{0xC3}
	ancestorRoot := types.Hash{0x30} // canonical block at the common ancestor (slot 30)

	qpos.SetSlotBlockRoot(abandonedSlot, abandoned)
	qpos.SetEpochBlockRoot(1, abandoned)
	r23InjectSealRecord(t, qfs, abandonedSlot, abandoned)
	qfs.persistCanonicalState(abandonedSlot, abandoned, SealRootMatches)
	if !qfs.IsBlockFinalized(abandonedSlot) {
		t.Fatal("precondition: the checkpoint-backed seal must be final")
	}

	// New chain: ancestor at slot 30, first re-anchored block at slot 33.
	qpos.ReanchorSlotRootsBounded(
		map[uint64]types.Hash{33: {0x33}},
		nil,
		ReanchorBounds{
			AncestorSlot:     30,
			AncestorKnown:    true,
			ReplacedHeadSlot: 33,
			EpochRoots:       map[uint64]types.Hash{1: ancestorRoot},
		},
	)

	if root, known := qpos.GetSlotBlockRoot(abandonedSlot); known {
		t.Fatalf("slot %d kept the abandoned root %s although the new chain skipped it (R27-O3)",
			abandonedSlot, root.String())
	}
	if root, known := qpos.GetEpochBlockRoot(1); !known || root != ancestorRoot {
		t.Fatalf("epoch 1 checkpoint = %s (known=%v), want the new chain's ancestor root %s",
			root.String(), known, ancestorRoot.String())
	}
	status, record := qfs.GetSlotSealDetails(abandonedSlot)
	if record == nil {
		t.Fatal("the threshold-agreement record must survive")
	}
	if status.RootState != SealRootUnknown {
		t.Fatalf("canonical state = %s, want unknown — the abandoned chain's checkpoint still confirms the seal (R27-O1)",
			status.RootState.String())
	}
	if qfs.IsBlockFinalized(abandonedSlot) {
		t.Fatal("a block the new chain does not contain is still reported as final (R27-O3)")
	}
}

// TestR28_UnknownAncestorKeepsPrefix is the negative control for the lower
// bound: when the caller could not locate the common ancestor (deep reorg,
// chain still syncing) the slots below its first re-anchored block are NOT
// known to be abandoned, so they must be left alone. Wiping them would drop
// canonical history on the strength of a guess.
func TestR28_UnknownAncestorKeepsPrefix(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	const keptSlot = uint64(32)
	kept := types.Hash{0xC4}
	checkpoint := types.Hash{0xC5}

	qpos.SetSlotBlockRoot(keptSlot, kept)
	qpos.SetEpochBlockRoot(1, checkpoint)

	qpos.ReanchorSlotRootsBounded(
		map[uint64]types.Hash{33: {0x33}},
		nil,
		ReanchorBounds{
			AncestorSlot:     30,
			AncestorKnown:    false, // ancestor NOT observed
			ReplacedHeadSlot: 33,
			EpochRoots:       map[uint64]types.Hash{1: {0xC6}},
		},
	)

	if root, known := qpos.GetSlotBlockRoot(keptSlot); !known || root != kept {
		t.Fatalf("an unobserved ancestor wiped slot %d: known=%v root=%s", keptSlot, known, root.String())
	}
	if root, known := qpos.GetEpochBlockRoot(1); !known || root != checkpoint {
		t.Fatalf("an unobserved ancestor rewrote the epoch 1 checkpoint: known=%v root=%s", known, root.String())
	}
}

// TestR28_JustifiedCheckpointSurvivesRollback pins R27-O1: the justified
// checkpoint is a consensus anchor. Attestations carry Source.Epoch =
// justifiedEpoch and ProcessAttestation fail-closes when its canonical root is
// missing (CONS-003), so a reorg-driven cleanup must never drop it — doing so
// stalls finality permanently.
func TestR28_JustifiedCheckpointSurvivesRollback(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	justifiedRoot := types.Hash{0xD1}
	qpos.SetEpochBlockRoot(1, justifiedRoot)
	qpos.mu.Lock()
	qpos.justifiedEpoch = 1
	qpos.justifiedRoot = justifiedRoot
	qpos.mu.Unlock()

	qpos.ReanchorSlotRootsBounded(
		map[uint64]types.Hash{33: {0x33}},
		nil,
		ReanchorBounds{
			AncestorSlot:     30, // the abandoned range [31,33] reaches epoch 1
			AncestorKnown:    true,
			ReplacedHeadSlot: 33,
			EpochRoots:       map[uint64]types.Hash{1: {0xD2}},
		},
	)

	if root, known := qpos.GetEpochBlockRoot(1); !known || root != justifiedRoot {
		t.Fatalf("the reorg dropped or rewrote the justified epoch 1 checkpoint: known=%v root=%s (R27-O1)",
			known, root.String())
	}
}

// TestR28_ForwardReorgKeepsInnerEpochCheckpoint pins the write gate: a reorg
// that starts ABOVE an epoch boundary cannot change that epoch's checkpoint
// (a checkpoint depends only on blocks up to its own boundary slot), so the
// derived value from the re-anchored segment — a mid-epoch block — must not be
// written over it.
func TestR28_ForwardReorgKeepsInnerEpochCheckpoint(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	epochStart := types.Hash{0xE1}
	qpos.SetEpochBlockRoot(1, epochStart)

	// Slots 41..45 are replaced; the epoch 1 boundary (slot 32) is untouched.
	qpos.ReanchorSlotRootsBounded(
		map[uint64]types.Hash{41: {0x41}, 45: {0x45}},
		nil,
		ReanchorBounds{
			AncestorSlot:     40,
			AncestorKnown:    true,
			ReplacedHeadSlot: 45,
			EpochRoots:       map[uint64]types.Hash{1: {0xE9}},
		},
	)

	if root, known := qpos.GetEpochBlockRoot(1); !known || root != epochStart {
		t.Fatalf("epoch 1 checkpoint = %s (known=%v), want the untouched epoch-start root %s",
			root.String(), known, epochStart.String())
	}
}

// TestR28_PrunedRootSealInAbandonedRangeIsInvalidated pins the generalisation of
// the R26 per-slot reset: a seal whose slot root is UNKNOWN (pruned long before
// the reorg) cannot be re-classified from a live root, so GetSlotSealDetails
// falls back to the persisted classification. If that persisted "matches"
// survives a reorg that abandoned its slot, the RPCs keep reporting a
// reorged-away block as final — the exact defect class R23-R27 kept unearthing.
func TestR28_PrunedRootSealInAbandonedRangeIsInvalidated(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()

	const slot = uint64(20) // epoch 0, per-slot root already pruned
	sealed := types.Hash{0xB7}
	r23InjectSealRecord(t, qfs, slot, sealed)
	qfs.persistCanonicalState(slot, sealed, SealRootMatches)
	if _, known := qpos.GetSlotBlockRoot(slot); known {
		t.Fatal("precondition: slot 20 must have no live root")
	}
	if !qfs.IsBlockFinalized(slot) {
		t.Fatal("precondition: the persisted classification must survive pruning (R24)")
	}

	// Head rolls back from slot 40 to slot 10; the common ancestor is slot 5,
	// so slots [6,40] are abandoned and slot 20 is inside that range.
	qpos.ReanchorSlotRootsBounded(
		map[uint64]types.Hash{10: {0x0A}},
		nil,
		ReanchorBounds{
			AncestorSlot:     5,
			AncestorKnown:    true,
			ReplacedHeadSlot: 40,
		},
	)

	if got := r24SealRecordClassification(t, qfs, slot); got != SealRootUnknown {
		t.Fatalf("persisted classification = %s, want unknown — the slot is in the abandoned range", got.String())
	}
	if qfs.IsBlockFinalized(slot) {
		t.Fatal("a seal over a block the reorg abandoned is still reported as final")
	}
}

// TestR28_LegacyWrappersKeepConservativeBounds locks the compatibility contract:
// the entry points that cannot observe the ancestor or the epoch checkpoints
// must keep the pre-R28 conservative behavior (clean the re-anchored range
// only) instead of deleting state on an assumption they cannot verify.
func TestR28_LegacyWrappersKeepConservativeBounds(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	const belowSlot = uint64(32)
	below := types.Hash{0xF1}
	checkpoint := types.Hash{0xF2}
	qpos.SetSlotBlockRoot(belowSlot, below)
	qpos.SetEpochBlockRoot(1, checkpoint)

	qpos.ReanchorSlotRoots(map[uint64]types.Hash{33: {0x33}}, nil)

	if root, known := qpos.GetSlotBlockRoot(belowSlot); !known || root != below {
		t.Fatalf("ReanchorSlotRoots wiped slot %d without knowing it was abandoned: known=%v root=%s",
			belowSlot, known, root.String())
	}
	if root, known := qpos.GetEpochBlockRoot(1); !known || root != checkpoint {
		t.Fatalf("ReanchorSlotRoots dropped the epoch 1 checkpoint: known=%v root=%s", known, root.String())
	}
}

// TestR28_ForkBelowFinalityIsRejected guards the interaction the lower bound
// introduces: the finalized-history check must look at the START of the
// abandoned range, not at the first re-anchored slot. When the common ancestor
// sits BELOW the finalized boundary and the new chain skips back above it, the
// reorg still rewrites finalized history — accepting it would delete finalized
// slot roots, which no reorg may do.
func TestR28_ForkBelowFinalityIsRejected(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	finalizedRoot := types.Hash{0xA0}
	finalizedSlotRoot := types.Hash{0xA1}
	qpos.mu.Lock()
	qpos.finalizedEpoch = 1 // finalized epoch 1 starts at slot 32
	qpos.finalizedRoot = finalizedRoot
	qpos.slotBlockRoots[31] = finalizedSlotRoot
	qpos.mu.Unlock()

	// Ancestor at slot 20 (below finality), first re-anchored block at 33.
	qpos.ReanchorSlotRootsBounded(
		map[uint64]types.Hash{33: {0x33}},
		nil,
		ReanchorBounds{
			AncestorSlot:     20,
			AncestorKnown:    true,
			ReplacedHeadSlot: 40,
		},
	)

	if root, known := qpos.GetSlotBlockRoot(31); !known || root != finalizedSlotRoot {
		t.Fatalf("a reorg forking below finality removed the finalized slot root: known=%v root=%s", known, root.String())
	}
	if root, known := qpos.GetSlotBlockRoot(33); known {
		t.Fatalf("a reorg forking below finality was partially applied (slot 33 = %s)", root.String())
	}
}
