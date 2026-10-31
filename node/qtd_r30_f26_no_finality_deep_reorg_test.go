// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R30 F26 (2026-10-30) — refusing an un-bounded reorg is only sound while
// something is finalized.
//
// F24 refuses a head switch whose common ancestor cannot be located, because
// the plan then understates the abandoned range. That argument depends on there
// being irreversible history to protect: with no finalized checkpoint block the
// QPOS guard would accept the very same range, so the refusal only freezes the
// head on a branch the network has left — the liveness failure F21 removed on
// the other side. A chain that has not finalized yet (any chain younger than the
// finality lag, and every dev chain) is exactly that case.

// r30F26UnboundedPlans returns a head switch whose common ancestor is in
// neither the store nor the new head's walk window.
func r30F26UnboundedPlans(t *testing.T) (*block.BlockStore, *encoding.Block, types.Hash, *encoding.Block, types.Hash) {
	t.Helper()
	bs := block.NewBlockStore(db.NewMemDB())
	r29BuildChain(t, bs, 0) // genesis only
	oldHead := &encoding.Block{Header: &encoding.BlockHeader{Height: 100, Slot: 100, ParentHash: types.Hash{0xEE}}}
	oldHash := block.ComputeBlockHash(oldHead.Header)
	newHead := &encoding.Block{Header: &encoding.BlockHeader{Height: 101, Slot: 101, ParentHash: types.Hash{0xEF}}}
	newHash := block.ComputeBlockHash(newHead.Header)
	if p := planSlotReanchor(bs, newHead, newHash, oldHead, oldHash); p == nil || p.bounds.AncestorKnown {
		t.Fatalf("precondition: the plan must be unbounded, got %+v", p)
	}
	return bs, oldHead, oldHash, newHead, newHash
}

// TestR30F26_UnboundedPlanIsAppliedWithoutFinality pins the fix: a node that has
// finalized nothing follows the network instead of freezing its head.
func TestR30F26_UnboundedPlanIsAppliedWithoutFinality(t *testing.T) {
	bs, oldHead, oldHash, newHead, newHash := r30F26UnboundedPlans(t)

	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	if slot, finalized := qpos.FinalizedCheckpointSlot(); finalized {
		t.Fatalf("precondition: a fresh QPOS has no finalized checkpoint, got slot %d", slot)
	}

	n := &Node{blockStore: bs, currentBlock: oldHead}
	if !n.commitHeadSwitchLocked("r30F26", newHead, newHash, oldHead, oldHash, qpos) {
		t.Fatal("with nothing finalized an un-bounded head switch must be adopted, not refused")
	}
	if n.currentBlock != newHead {
		t.Fatal("an accepted head switch must commit n.currentBlock")
	}
}

// TestR30F26_GenesisCheckpointDoesNotBlock pins the boundary of the rule: a
// checkpoint pinned at slot 0 (the genesis bootstrap) protects nothing above it,
// and ReanchorConflictsWithFinality cannot refuse any range at all, so the
// refusal must not apply either.
func TestR30F26_GenesisCheckpointDoesNotBlock(t *testing.T) {
	bs, oldHead, oldHash, newHead, newHash := r30F26UnboundedPlans(t)

	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	genesis := types.Hash{0x6E}
	if err := qpos.RestoreFinalityState(0, 0, genesis, genesis); err != nil {
		t.Fatalf("RestoreFinalityState: %v", err)
	}
	if slot, finalized := qpos.FinalizedCheckpointSlot(); !finalized || slot != 0 {
		t.Fatalf("precondition: the restored checkpoint must sit at slot 0, got (%d, %v)", slot, finalized)
	}
	// The guard itself accepts every range against a slot-0 checkpoint, which is
	// what makes refusing on the caller side redundant rather than safe.
	if consensus.ReanchorConflictsWithFinality(map[uint64]types.Hash{101: newHash}, consensus.ReanchorBounds{
		ReplacedHeadSlot: newHead.Header.Slot,
	}, 0) {
		t.Fatal("precondition: no abandoned range can reach a checkpoint at slot 0")
	}

	n := &Node{blockStore: bs, currentBlock: oldHead}
	if !n.commitHeadSwitchLocked("r30F26", newHead, newHash, oldHead, oldHash, qpos) {
		t.Fatal("a genesis-only checkpoint must not block a head switch")
	}
}

// TestR30F26_RealCheckpointStillRefuses pins that the F24 refusal is intact for
// the case it was written for.
func TestR30F26_RealCheckpointStillRefuses(t *testing.T) {
	bs, oldHead, oldHash, newHead, newHash := r30F26UnboundedPlans(t)

	qpos := r30QPOSWithFinality(t)
	n := &Node{blockStore: bs, currentBlock: oldHead}
	if n.commitHeadSwitchLocked("r30F26", newHead, newHash, oldHead, oldHash, qpos) {
		t.Fatal("an un-bounded range must stay refused while a checkpoint at slot > 0 is final")
	}
	if n.currentBlock != oldHead {
		t.Fatal("a refused head switch must leave n.currentBlock untouched")
	}
}
