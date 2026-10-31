// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R29 (2026-10-30) — regression tests for the seventh independent re-review:
// B1 (a pure head rollback left the whole abandoned range untouched because
// its roots map was empty), N1 (the finalized guard let a range starting ON the
// finalized boundary through), N7 (an epoch with no new-chain block lost its
// checkpoint instead of falling back to the common ancestor) and N8 (none of
// the above was covered by a test).

// TestR29_PureRollbackCleansAbandonedRange pins B1. A head rollback makes the
// new head the COMMON ANCESTOR, so the new chain contributes no re-anchored
// slot at all and the caller passes an empty roots map. The abandoned range is
// still (ancestor, replaced head]: every slot root in it attests a block the
// rollback removed. Skipping the whole cleanup left those roots live, so the
// seals kept classifying as canonical and the RPCs kept reporting deleted
// blocks as final — and a later linear extension never revisits them.
func TestR29_PureRollbackCleansAbandonedRange(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)
	qfs := qpos.GetQTDFinality()

	const (
		ancestorSlot = uint64(30)
		sealedSlot   = uint64(35)
	)
	sealed := types.Hash{0xB5}

	// The abandoned chain recorded roots at 31..40; the seal at 35 covers the
	// block that is canonical on that (now abandoned) chain.
	qpos.SetSlotBlockRoot(31, types.Hash{0x31})
	qpos.SetSlotBlockRoot(35, sealed)
	qpos.SetSlotBlockRoot(40, types.Hash{0x40})
	r23InjectSealRecord(t, qfs, sealedSlot, sealed)
	qfs.persistCanonicalState(sealedSlot, sealed, SealRootMatches)
	if !qfs.IsBlockFinalized(sealedSlot) {
		t.Fatal("precondition: the live root must confirm the seal before the rollback")
	}

	// The node rolls its head back to slot 30; nothing above the ancestor is
	// on the new chain, so roots is empty.
	accepted := qpos.ReanchorSlotRootsBounded(nil, nil, ReanchorBounds{
		AncestorSlot:     ancestorSlot,
		AncestorKnown:    true,
		AncestorHash:     types.Hash{0x30},
		ReplacedHeadSlot: 40,
	})
	if !accepted {
		t.Fatal("a rollback above finality must be accepted")
	}

	for _, slot := range []uint64{31, 35, 40} {
		if root, known := qpos.GetSlotBlockRoot(slot); known {
			t.Fatalf("slot %d kept the abandoned root %s after a pure rollback (B1)", slot, root.String())
		}
	}
	if got := r24SealRecordClassification(t, qfs, sealedSlot); got != SealRootUnknown {
		t.Fatalf("persisted classification = %s, want unknown — the slot is in the abandoned range",
			got.String())
	}
	if qfs.IsBlockFinalized(sealedSlot) {
		t.Fatal("a seal over a block the rollback removed is still reported as final (B1)")
	}
	if record := qfs.GetFinalityRecord(sealedSlot); record == nil {
		t.Fatal("the threshold-agreement record itself must survive the invalidation")
	}
}

// TestR29_PureRollbackDerivesCheckpointFromAncestor pins N7: an epoch the
// abandoned range reaches but the new chain has no block in still has a
// determined checkpoint — every canonical block up to its boundary is at or
// below the common ancestor, so the checkpoint IS that ancestor (R42-P3).
// Dropping it made ProcessAttestation fail-closed (CONS-003) for every vote
// whose Source.Epoch fell in the epoch, and nothing re-created it because the
// checkpoint is only re-recorded when the new chain reaches a boundary slot.
func TestR29_PureRollbackDerivesCheckpointFromAncestor(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	ancestor := types.Hash{0x30}
	abandoned := types.Hash{0x32}
	genesis := types.Hash{0x01}

	qpos.SetEpochBlockRoot(0, genesis)
	qpos.SetEpochBlockRoot(1, abandoned) // the abandoned chain's slot-32 block

	qpos.ReanchorSlotRootsBounded(nil, nil, ReanchorBounds{
		AncestorSlot:     30,
		AncestorKnown:    true,
		AncestorHash:     ancestor,
		ReplacedHeadSlot: 40,
	})

	if root, known := qpos.GetEpochBlockRoot(1); !known || root != ancestor {
		t.Fatalf("epoch 1 checkpoint = %s (known=%v), want the common ancestor %s (N7)",
			root.String(), known, ancestor.String())
	}
	if root, known := qpos.GetEpochBlockRoot(0); !known || root != genesis {
		t.Fatalf("the rollback touched epoch 0: known=%v root=%s", known, root.String())
	}
}

// TestR29_PureRollbackKeepsJustifiedCheckpoint extends the R27-O1 protection to
// the new ancestor fallback: the justified checkpoint is a consensus anchor
// (attestations carry Source.Epoch = justifiedEpoch and CONS-003 fail-closes
// when its root is missing), so it must not be rewritten by the derivation
// either.
func TestR29_PureRollbackKeepsJustifiedCheckpoint(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	justified := types.Hash{0xD1}
	qpos.SetEpochBlockRoot(1, justified)
	qpos.mu.Lock()
	qpos.justifiedEpoch = 1
	qpos.justifiedRoot = justified
	qpos.mu.Unlock()

	qpos.ReanchorSlotRootsBounded(nil, nil, ReanchorBounds{
		AncestorSlot:     30,
		AncestorKnown:    true,
		AncestorHash:     types.Hash{0x30},
		ReplacedHeadSlot: 40,
	})

	if root, known := qpos.GetEpochBlockRoot(1); !known || root != justified {
		t.Fatalf("the ancestor fallback rewrote the justified epoch 1 checkpoint: known=%v root=%s",
			known, root.String())
	}
}

// TestR29_RollbackToFinalizedBoundaryIsRejected pins N1. The block on the
// finalized epoch's boundary slot IS that epoch's checkpoint root (R42-P3), so
// a range starting exactly on the boundary replaces or drops finalized
// history. The guard is inclusive, and the rejection is reported to the caller
// so it can skip its own writes to the same slots (N3).
func TestR29_RollbackToFinalizedBoundaryIsRejected(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	finalizedRoot := types.Hash{0xA0}
	boundarySlotRoot := types.Hash{0xA1}
	qpos.mu.Lock()
	qpos.finalizedEpoch = 1 // finalized epoch 1 starts at slot 32
	qpos.finalizedRoot = finalizedRoot
	qpos.slotBlockRoots[32] = boundarySlotRoot
	qpos.mu.Unlock()

	accepted := qpos.ReanchorSlotRootsBounded(nil, nil, ReanchorBounds{
		AncestorSlot:     31, // range [32,45] starts exactly on the boundary
		AncestorKnown:    true,
		AncestorHash:     types.Hash{0x31},
		ReplacedHeadSlot: 45,
	})

	if accepted {
		t.Fatal("a rollback whose abandoned range starts on the finalized boundary must be rejected (N1)")
	}
	if root, known := qpos.GetSlotBlockRoot(32); !known || root != boundarySlotRoot {
		t.Fatalf("the finalized boundary slot root was rewritten: known=%v root=%s (N1)",
			known, root.String())
	}
}

// TestR29_PureRollbackWithoutAncestorIsConservative is the negative control for
// the new empty-roots range: without an observed common ancestor the abandoned
// range is unknown, and wiping slots on the strength of a guess would drop
// canonical history. The call must be a no-op that is still reported as
// accepted (nothing was refused, nothing was touched).
func TestR29_PureRollbackWithoutAncestorIsConservative(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	const keptSlot = uint64(35)
	kept := types.Hash{0xC5}
	qpos.SetSlotBlockRoot(keptSlot, kept)

	accepted := qpos.ReanchorSlotRootsBounded(nil, nil, ReanchorBounds{
		AncestorKnown:    false,
		ReplacedHeadSlot: 40,
	})
	if !accepted {
		t.Fatal("an unobservable ancestor is not a refusal")
	}
	if root, known := qpos.GetSlotBlockRoot(keptSlot); !known || root != kept {
		t.Fatalf("an unobserved ancestor wiped slot %d: known=%v root=%s", keptSlot, known, root.String())
	}
}

// TestR29_EmptyRangeIsANoOp locks the last degenerate shape: an empty roots map
// whose bounds describe no range (the replaced head is not above the ancestor)
// must return without touching anything.
func TestR29_EmptyRangeIsANoOp(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 3)

	const keptSlot = uint64(20)
	kept := types.Hash{0xC9}
	qpos.SetSlotBlockRoot(keptSlot, kept)

	if accepted := qpos.ReanchorSlotRootsBounded(nil, nil, ReanchorBounds{
		AncestorSlot:     40,
		AncestorKnown:    true,
		AncestorHash:     types.Hash{0x40},
		ReplacedHeadSlot: 40,
	}); !accepted {
		t.Fatal("a range with no slots above the ancestor is not a refusal")
	}
	if root, known := qpos.GetSlotBlockRoot(keptSlot); !known || root != kept {
		t.Fatalf("an empty range wiped slot %d: known=%v root=%s", keptSlot, known, root.String())
	}
}
