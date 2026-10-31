// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R30 F24 (2026-10-30) — the abandoned range of a reorg must be bounded from
// BOTH ends before it is used.
//
// The ancestor walk is limited to maxReorgDepth slots. When it cannot find the
// common ancestor, planSlotReanchor degrades to "the abandoned range is the
// window I walked", which understates the real range: the finality check then
// answers about a range that starts too high, and the cleanup leaves every slot
// root below the window anchored to the abandoned branch. Two callers can do
// better and must say so — the operator rollback knows the block it moves the
// head to, and that block IS the ancestor (R30 F24 / auditor finding S1). A
// caller that cannot bound the range is refused instead of half-applying it.

// TestR30F24_DeepRollbackCleansTheWholeAbandonedRange pins the hint: a rollback
// deeper than the ancestor window still cleans every abandoned slot root.
func TestR30F24_DeepRollbackCleansTheWholeAbandonedRange(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	slots := make([]uint64, 0, 130)
	for s := uint64(0); s < 130; s++ {
		slots = append(slots, s)
	}
	blocks, hashes := r29BuildChain(t, bs, slots...)

	qpos := r30QPOSWithFinality(t) // finalized epoch 1, boundary slot 32
	// Record the roots of the tail only: the window stays below the pruning
	// threshold, so every abandoned root is still there to be cleaned.
	for slot := uint64(40); slot < 130; slot++ {
		qpos.SetSlotBlockRoot(slot, hashes[slot])
	}
	n := &Node{
		blockStore:    bs,
		currentBlock:  blocks[129],
		stateTrust:    newStateTrust(),
		blockProducer: &BlockProducer{qpos: qpos},
	}

	// The planner cannot reach the ancestor (70 heights below the walk window),
	// which is exactly the shape that used to leave slots 10..59 dirty.
	if p := planSlotReanchor(bs, blocks[59], hashes[59], blocks[129], hashes[129]); p != nil && p.bounds.AncestorKnown {
		t.Fatalf("precondition: the plain walk must not find the ancestor, got slot %d", p.bounds.AncestorSlot)
	}

	deleted, err := newForkRecoveryBackend(n).RollbackToFork(60)
	if err != nil {
		t.Fatalf("a legal deep rollback must succeed: %v", err)
	}
	if deleted != 70 {
		t.Fatalf("deleted %d blocks, want 70", deleted)
	}
	if n.currentBlock == nil || n.currentBlock.Header.Height != 59 {
		t.Fatalf("the head must move to height 59, got %+v", n.currentBlock)
	}
	if latest, gerr := bs.GetLatestHeight(); gerr != nil || latest != 59 {
		t.Fatalf("store latest = %d (err=%v), want 59", latest, gerr)
	}
	// Every abandoned slot root is gone, including the ones below the ancestor
	// window, and the surviving head's root is kept.
	for slot := uint64(60); slot < 130; slot++ {
		if root, ok := qpos.GetSlotBlockRoot(slot); ok && root != (types.Hash{}) {
			t.Fatalf("abandoned slot root %d must be cleaned, got %x", slot, root[:8])
		}
	}
	if root, ok := qpos.GetSlotBlockRoot(59); !ok || root != hashes[59] {
		t.Fatal("the surviving head's slot root must be kept")
	}
}

// TestR30F24_UnboundedPlanIsRefused pins the fail-closed half: a head switch
// whose ancestor cannot be located (and cannot be hinted) is not partially
// applied — the head stays where it is.
func TestR30F24_UnboundedPlanIsRefused(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	r29BuildChain(t, bs, 0) // genesis only

	// Neither the replaced head nor the new head's parent is in the store, so
	// no ancestor can be proven either way.
	oldHead := &encoding.Block{Header: &encoding.BlockHeader{Height: 100, Slot: 100, ParentHash: types.Hash{0xEE}}}
	oldHash := block.ComputeBlockHash(oldHead.Header)
	newHead := &encoding.Block{Header: &encoding.BlockHeader{Height: 101, Slot: 101, ParentHash: types.Hash{0xEF}}}
	newHash := block.ComputeBlockHash(newHead.Header)

	if p := planSlotReanchor(bs, newHead, newHash, oldHead, oldHash); p == nil || p.bounds.AncestorKnown {
		t.Fatalf("precondition: the plan must be unbounded, got %+v", p)
	}

	qpos := r30QPOSWithFinality(t)
	n := &Node{blockStore: bs, currentBlock: oldHead}
	if n.commitHeadSwitchLocked("r30F24", newHead, newHash, oldHead, oldHash, qpos) {
		t.Fatal("a head switch whose abandoned range cannot be bounded must be refused")
	}
	if n.currentBlock != oldHead {
		t.Fatal("a refused head switch must leave n.currentBlock untouched")
	}

	// Without a QPOS nothing is irreversible, so the same switch is the
	// pre-R30 unconditional adoption — the refusal must not spread to nodes
	// that track no finality.
	if !n.commitHeadSwitchLocked("r30F24", newHead, newHash, oldHead, oldHash, nil) {
		t.Fatal("without a QPOS no head switch may be refused")
	}
	if n.currentBlock != newHead {
		t.Fatal("an accepted head switch must commit n.currentBlock")
	}
}
