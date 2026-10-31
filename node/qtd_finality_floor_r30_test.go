// Quantaureum Node source, version 1.0.0.
package node

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// R30 (2026-10-30) — the fork choice used to commit the head and only then ask
// the QPOS whether the reorg rewrote finalized history. These tests pin the two
// halves of the fix: commitHeadSwitchLocked (the QPOS decides while the head is
// still the old one, so a refusal leaves no trace) and the store-rollback guard
// (so the syncer cannot delete finalized blocks and rewind state below the
// floor).

// r30QPOSWithFinality returns a QPOS that has finalized epoch 1, i.e. a finality
// floor at slot SlotsPerEpoch (= every block at or below slot 32 is
// irreversible).
func r30QPOSWithFinality(t *testing.T) *consensus.QPOS {
	t.Helper()
	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.AdoptHeaderFinality(0, 1, types.Hash{0xA0})
	if got := qpos.GetFinalizedEpoch(); got != 1 {
		t.Fatalf("precondition: finalized epoch = %d, want 1", got)
	}
	if floor, ok := qpos.FinalityFloorSlot(); !ok || floor != consensus.SlotsPerEpoch {
		t.Fatalf("precondition: finality floor = (%d, %v), want (%d, true)", floor, ok, uint64(consensus.SlotsPerEpoch))
	}
	return qpos
}

// TestR30_CommitRefusesForkBelowFinality pins the property both head-switch call
// sites rely on: the switch is refused while the head is still the old one, so
// every canonical-head side effect (slot roots, adopted finality, VRF
// accumulator, staking, events — all gated on shouldSwitch) is skipped and the
// QPOS keeps the finalized branch's canonical roots.
func TestR30_CommitRefusesForkBelowFinality(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks, hashes := r29BuildChain(t, bs, 0, 30, 35, 40, 45)
	qpos := r30QPOSWithFinality(t)

	// The current canonical branch's slot roots, as the QPOS would hold them.
	qpos.SetSlotBlockRoot(35, hashes[2])
	qpos.SetSlotBlockRoot(40, hashes[3])
	qpos.SetSlotBlockRoot(45, hashes[4])

	n := &Node{blockStore: bs, currentBlock: blocks[4]} // head at slot 45

	// Rollback to slot 30 abandons [31,40], which contains the finalized
	// boundary slot 32 — the head must stay where it is and nothing may be
	// re-anchored.
	if n.commitHeadSwitchLocked("test", blocks[1], hashes[1], blocks[4], hashes[4], qpos) {
		t.Fatal("a fork below the finality floor must be refused")
	}
	if n.currentBlock != blocks[4] {
		t.Fatal("a refused head switch must leave n.currentBlock untouched")
	}
	if got, ok := qpos.GetSlotBlockRoot(35); !ok || got != hashes[2] {
		t.Fatalf("a refused head switch must not rewrite canonical slot roots: slot 35 = %x (present=%v), want %x", got[:8], ok, hashes[2][:8])
	}
	if got, ok := qpos.GetSlotBlockRoot(40); !ok || got != hashes[3] {
		t.Fatalf("a refused head switch must not drop canonical slot roots: slot 40 = %x (present=%v), want %x", got[:8], ok, hashes[3][:8])
	}

	// Rollback to slot 35 abandons [36,45], entirely above the floor: adopted,
	// and the abandoned slot roots are cleaned up.
	if !n.commitHeadSwitchLocked("test", blocks[2], hashes[2], blocks[4], hashes[4], qpos) {
		t.Fatal("a reorg strictly above the finality floor must be adopted")
	}
	if n.currentBlock != blocks[2] {
		t.Fatal("an adopted head switch must commit n.currentBlock")
	}
	if got, ok := qpos.GetSlotBlockRoot(35); !ok || got != hashes[2] {
		t.Fatalf("the common ancestor's slot root must survive the reorg: slot 35 = %x (present=%v)", got[:8], ok)
	}
	if got, ok := qpos.GetSlotBlockRoot(40); ok {
		t.Fatalf("the abandoned branch's slot root must be dropped: slot 40 = %x", got[:8])
	}

	// Linear extension: adopted, nothing to re-anchor.
	n.currentBlock = blocks[3]
	if !n.commitHeadSwitchLocked("test", blocks[4], hashes[4], blocks[3], hashes[3], qpos) {
		t.Fatal("a linear extension must be adopted")
	}

	// No block producer / no finality state: nothing is irreversible, so the
	// same below-floor fork is legal (this is the pre-R30 behavior for nodes
	// that do not track finality).
	n.currentBlock = blocks[4]
	if !n.commitHeadSwitchLocked("test", blocks[1], hashes[1], blocks[4], hashes[4], nil) {
		t.Fatal("without a QPOS no head switch may be refused")
	}
}

// TestR30_SyncerRefusesRollbackBelowFinality checks the store-level guard: the
// syncer deletes blocks at/above the rollback height and rewinds stateDB to it,
// so a rollback whose SURVIVING tip sits below the finalized checkpoint would
// destroy finalized history. The surviving tip is what decides (R30 F22): a
// rollback keeps block(from-1) as the head, and every canonical block above the
// checkpoint stays abandoned — so height 2 keeps the block at slot 30, which is
// below the checkpoint default (the epoch boundary slot 32).
func TestR30_SyncerRefusesRollbackBelowFinality(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	// heights 0..3, slots 0/30/35/40
	r29BuildChain(t, bs, 0, 30, 35, 40)

	s := NewSyncer(nil, bs, nil, nil, 1669)

	// No finality yet: nothing is irreversible.
	if blocked, _ := s.rollbackBelowFinality(1); blocked {
		t.Fatal("without local finality no rollback may be refused")
	}

	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.AdoptHeaderFinality(0, 1, types.Hash{0xA0})
	if got := qpos.GetFinalizedEpoch(); got != 1 {
		t.Fatalf("precondition: finalized epoch = %d, want 1", got)
	}
	s.SetQPOS(qpos)

	// height 1 would survive with genesis (slot 0) at the tip → deleting it
	// rewrites finalized history.
	if blocked, floor := s.rollbackBelowFinality(1); !blocked || floor != 32 {
		t.Fatalf("rollback to height 1: blocked=%v floor=%d, want blocked=true floor=32", blocked, floor)
	}
	// height 2 would survive with the block at slot 30, still below the
	// checkpoint at slot 32 → refused.
	if blocked, _ := s.rollbackBelowFinality(2); !blocked {
		t.Fatal("a rollback whose surviving tip is below the finalized checkpoint must be refused")
	}
	// height 3 would survive with the block at slot 35, above the checkpoint →
	// history above finality may be reorged.
	if blocked, _ := s.rollbackBelowFinality(3); blocked {
		t.Fatal("rollback to height 3 (surviving tip at slot 35) is above the floor and must be allowed")
	}
	// Unknown surviving tip: fail-closed rather than guess.
	if blocked, _ := s.rollbackBelowFinality(99); !blocked {
		t.Fatal("an unprovable rollback point must be refused (fail-closed)")
	}
}

// TestR30_FragmentedChainTruncationRefusedBelowFinality pins the startup repair
// path (R53). Deleting the orphaned blocks above a ParentHash gap is a normal
// repair, but it must not reach into the finalized prefix: the checkpoint was
// already restored from disk by then, so those blocks back a finality claim this
// node cannot withdraw.
func TestR30_FragmentedChainTruncationRefusedBelowFinality(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	// heights 0..3 at slots 0/10/20/40; truncating from height 2 deletes the
	// block at slot 20, which is below the floor (slot 32).
	r29BuildChain(t, bs, 0, 10, 20, 40)

	finality := NewSyncer(nil, bs, nil, nil, 1669)
	finality.SetQPOS(r30QPOSWithFinality(t))
	n := &Node{blockStore: bs, syncer: finality}

	if truncated, refused, err := n.truncateFragmentedChain(1, 3); err != nil || !refused || truncated != 0 {
		t.Fatalf("a truncation reaching finalized history must be refused (truncated=%d refused=%v err=%v)", truncated, refused, err)
	}
	if latest, err := bs.GetLatestHeight(); err != nil || latest != 3 {
		t.Fatalf("a refused truncation must leave the store untouched: latest=%d err=%v, want 3", latest, err)
	}

	// Without finality state nothing is irreversible, so the same repair runs
	// and removes the orphaned blocks.
	plain := &Node{blockStore: bs, syncer: NewSyncer(nil, bs, nil, nil, 1669)}
	truncated, refused, err := plain.truncateFragmentedChain(1, 3)
	if err != nil || refused || truncated != 2 {
		t.Fatalf("without finality the repair must truncate 2 blocks (truncated=%d refused=%v err=%v)", truncated, refused, err)
	}
	if latest, err := bs.GetLatestHeight(); err != nil || latest != 1 {
		t.Fatalf("after the truncation the store must end at height 1: latest=%d err=%v", latest, err)
	}
}

// TestR30_HistoryExpiryRefusedOnRealStore pins F4. Block-history pruning cannot
// coexist with the store's continuity model (FindContinuousTip scans upward from
// height 1) nor with a restored finality checkpoint, so every entry point
// refuses and the store keeps its blocks — including genesis, which the adapter
// used to report as the "oldest releasable" height.
func TestR30_HistoryExpiryRefusedOnRealStore(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	r29BuildChain(t, bs, 0, 10, 20, 30) // heights 0..3
	adapter := &blockStoreReaderAdapter{blockStore: bs}

	if got := adapter.GetOldestHeight(); got != 1 {
		t.Fatalf("GetOldestHeight() = %d, want 1: the genesis block is never releasable", got)
	}

	// A retention of 1 block makes a live expirer want to delete [1, 2] — the
	// range that would strand genesis and break continuity.
	cfg := DefaultHistoryExpirationConfig()
	cfg.Enabled = true
	cfg.RetentionBlocks = 1
	he := NewHistoryExpirer(cfg, adapter)
	defer he.Stop()

	if err := he.Start(); !errors.Is(err, ErrHistoryExpiryUnsupported) {
		t.Fatalf("Start() = %v, want ErrHistoryExpiryUnsupported", err)
	}
	if _, err := he.ForcePrune(); !errors.Is(err, ErrHistoryExpiryUnsupported) {
		t.Fatalf("ForcePrune() = %v, want ErrHistoryExpiryUnsupported", err)
	}

	for height := uint64(0); height <= 3; height++ {
		if _, err := bs.GetBlockByHeight(height); err != nil {
			t.Fatalf("block at height %d must survive a refused expiry: %v", height, err)
		}
	}
	if latest, err := bs.GetLatestHeight(); err != nil || latest != 3 {
		t.Fatalf("store must be untouched: latest=%d err=%v, want 3", latest, err)
	}
}

// TestR30_PersistedFinalityMustBeBackedByStore pins F5. A restored checkpoint
// that claims an epoch beyond the local head can never be repaired from disk
// (the ratchet only moves forward), so it would pin the finality floor above
// every block this node holds and block each future rollback and re-sync. It
// must be refused loudly at startup instead, i.e. local state stops being
// trusted so this node does not produce from a view it cannot reconcile.
func TestR30_PersistedFinalityMustBeBackedByStore(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	r29BuildChain(t, bs, 0, 10)    // heights 0..1, head slot 10 is still epoch 0
	head := r30QPOSWithFinality(t) // finalized epoch 1, i.e. floor slot 32

	if ok, detail := persistedFinalityFitsStore(head, bs); ok {
		t.Fatalf("a checkpoint ahead of the local head must be rejected, got ok with detail %q", detail)
	}
	n := &Node{stateTrust: newStateTrust()}
	if n.checkPersistedFinalityBacking(head, bs) {
		t.Fatal("checkPersistedFinalityBacking must report the mismatch")
	}
	if n.stateTrust.ok() {
		t.Fatal("an unbacked checkpoint must break state trust so the node stops producing")
	}

	// An empty store cannot back any checkpoint either.
	empty := block.NewBlockStore(db.NewMemDB())
	if ok, _ := persistedFinalityFitsStore(head, empty); ok {
		t.Fatal("an empty store must not be considered backing for a checkpoint")
	}

	// A checkpoint inside the local chain is accepted and changes nothing.
	deeper := block.NewBlockStore(db.NewMemDB())
	r29BuildChain(t, deeper, 0, 10, 40) // head slot 40 is epoch 1
	plain := &Node{stateTrust: newStateTrust()}
	if !plain.checkPersistedFinalityBacking(head, deeper) {
		t.Fatal("a checkpoint at the local head epoch must be accepted")
	}
	if !plain.stateTrust.ok() {
		t.Fatal("a backed checkpoint must not break state trust")
	}
}

// TestR30_ConflictReloadGoesThroughForkChoice pins F6. When a produced block
// loses its height to a block already in the store, the node adopts the stored
// block — but that block was written by the syncer BEFORE fork choice decided, so
// adopting it unconditionally would bypass a refusal and skip the slot-root
// re-anchoring. The reload must ask fork choice just like every other head
// switch, and must not extend a head the store does not hold when refused.
func TestR30_ConflictReloadGoesThroughForkChoice(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	_, hashes := r29BuildChain(t, bs, 0) // genesis at height 0, slot 0
	genesisHash := hashes[0]

	// The store's canonical block at height 1, and the block this producer built
	// for the same height on the same parent (a different slot, so accepting it
	// would be a reorg rather than a duplicate).
	canonical := &encoding.Block{Header: &encoding.BlockHeader{
		Height: 1, Slot: 40, Epoch: consensus.SlotToEpoch(40), ParentHash: genesisHash,
	}}
	if err := bs.PutBlock(canonical); err != nil {
		t.Fatalf("PutBlock(canonical): %v", err)
	}
	canonicalHash := block.ComputeBlockHash(canonical.Header)
	produced := &encoding.Block{Header: &encoding.BlockHeader{
		Height: 1, Slot: 41, Epoch: consensus.SlotToEpoch(41), ParentHash: genesisHash,
	}}

	// Floor at slot 32: adopting the stored block would abandon slots 1..41, so it
	// must be refused and production must stop (the head is not in the store).
	withFinality := &Node{
		blockStore:    bs,
		currentBlock:  produced,
		stateTrust:    newStateTrust(),
		blockProducer: &BlockProducer{qpos: r30QPOSWithFinality(t)},
	}
	if withFinality.reloadConflictHeadLocked(1, produced) {
		t.Fatal("adopting a stored block whose reorg rewrites finalized history must be refused")
	}
	if withFinality.currentBlock != produced {
		t.Fatal("a refused reload must keep the produced block as the head")
	}
	if withFinality.stateTrust.ok() {
		t.Fatal("a refused reload must break state trust: the head is no longer in the store")
	}

	// Without finality state the same reload is a supported equal-height head swap,
	// and the QPOS must learn the new canonical slot root.
	plainQPOS, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	plain := &Node{
		blockStore:    bs,
		currentBlock:  produced,
		stateTrust:    newStateTrust(),
		blockProducer: &BlockProducer{qpos: plainQPOS},
	}
	if !plain.reloadConflictHeadLocked(1, produced) {
		t.Fatal("without finality the reload must be accepted")
	}
	if plain.currentBlock == nil || block.ComputeBlockHash(plain.currentBlock.Header) != canonicalHash {
		t.Fatal("an accepted reload must move the head to the store's canonical block")
	}
	if root, ok := plainQPOS.GetSlotBlockRoot(40); !ok || root != canonicalHash {
		t.Fatal("an accepted reload must re-anchor the new head's slot root")
	}
}

// TestR30_ConflictReloadDetectsDivergedState pins F10. tryProduceBlock commits
// its built state before postCommitBlock stores the block, so when the store
// reports a conflict at the same height, the head moves to a block this node
// never executed while local state still describes the block it built. When the
// two state roots differ the producer must lose state trust (production stops,
// chain following continues) — otherwise it seals the next block on state the
// canonical parent never produced and forks itself off.
func TestR30_ConflictReloadDetectsDivergedState(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	_, hashes := r29BuildChain(t, bs, 0)
	genesisHash := hashes[0]

	canonical := &encoding.Block{Header: &encoding.BlockHeader{
		Height: 1, Slot: 40, Epoch: consensus.SlotToEpoch(40), ParentHash: genesisHash,
		StateRoot: types.Hash{0xC1},
	}}
	if err := bs.PutBlock(canonical); err != nil {
		t.Fatalf("PutBlock(canonical): %v", err)
	}
	produced := &encoding.Block{Header: &encoding.BlockHeader{
		Height: 1, Slot: 41, Epoch: consensus.SlotToEpoch(41), ParentHash: genesisHash,
		StateRoot: types.Hash{0xC2},
	}}

	newNode := func(head *encoding.Block) *Node {
		t.Helper()
		qpos, err := consensus.NewQPOS(nil)
		if err != nil {
			t.Fatalf("NewQPOS: %v", err)
		}
		return &Node{
			blockStore:    bs,
			currentBlock:  head,
			stateDB:       state.NewStateDB(db.NewMemDB()),
			stateTrust:    newStateTrust(),
			blockProducer: &BlockProducer{qpos: qpos},
			// The syncer's baseline claims the produced height was verified.
			syncer: &Syncer{startHeight: 1, stateVerifiedHeight: 1},
		}
	}

	n := newNode(produced)
	if !n.reloadConflictHeadLocked(1, produced) {
		t.Fatal("the reload itself must be accepted (the store is canonical)")
	}
	if n.IsStateTrusted() {
		t.Fatal("a reload onto a block with a different state root must break state trust")
	}
	// The state baseline must drop with the trust: the canonical block at that
	// height was never executed, so a rebuild must start from its parent.
	if got := n.syncer.StateVerifiedHeight(); got >= 1 {
		t.Fatalf("stateVerifiedHeight = %d after the divergence, want it lowered below the discarded height", got)
	}

	// Same state root: the applied state describes the new head too, so the
	// race is benign and production must keep going.
	produced.Header.StateRoot = canonical.Header.StateRoot
	benign := newNode(produced)
	if !benign.reloadConflictHeadLocked(1, produced) {
		t.Fatal("the reload itself must be accepted (the store is canonical)")
	}
	if !benign.IsStateTrusted() {
		t.Fatal("identical state roots must not break state trust")
	}
	if got := benign.syncer.StateVerifiedHeight(); got != 1 {
		t.Fatalf("stateVerifiedHeight = %d after a benign reload, want 1 (unchanged)", got)
	}
}

// TestR30_DebugRollbackMovesHeadAndCleansRoots pins F7. The operator rollback RPC
// truncates the store, but it used to leave the head pointing at a block it had
// just deleted and every abandoned slot root anchored to a deleted block — so the
// RPCs kept reporting those blocks as canonical (and final). The head must move to
// the truncation point and fork choice must clean the abandoned range.
func TestR30_DebugRollbackMovesHeadAndCleansRoots(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks, hashes := r29BuildChain(t, bs, 0, 40, 45) // heights 0..2

	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.SetSlotBlockRoot(40, hashes[1])
	qpos.SetSlotBlockRoot(45, hashes[2])

	n := &Node{
		blockStore:    bs,
		currentBlock:  blocks[2],
		stateTrust:    newStateTrust(),
		blockProducer: &BlockProducer{qpos: qpos},
	}

	if _, err := newForkRecoveryBackend(n).RollbackToFork(2); err != nil {
		t.Fatalf("RollbackToFork: %v", err)
	}
	if n.currentBlock == nil || n.currentBlock.Header.Height != 1 {
		t.Fatalf("the head must move to the truncation point: got %+v, want height 1", n.currentBlock)
	}
	if block.ComputeBlockHash(n.currentBlock.Header) != hashes[1] {
		t.Fatal("the head must be the block at the truncation point")
	}
	if root, ok := qpos.GetSlotBlockRoot(45); ok && root != (types.Hash{}) {
		t.Fatalf("the abandoned slot root 45 must be cleaned, got %x", root[:8])
	}
	if root, ok := qpos.GetSlotBlockRoot(40); !ok || root != hashes[1] {
		t.Fatal("the surviving head's slot root must be kept")
	}
}

// TestR30_UnbackedHeaderCannotPoisonTheFloor pins the adoption guard (R30 F8).
//
// AdoptHeaderFinality is a ratchet: it takes any epoch larger than the local
// one and never lowers it, and the adopted finalized epoch becomes the finality
// floor. A stored header claiming FinalizedEpoch = 1<<40 would therefore pin the
// floor above every block this chain will ever produce and freeze every reorg
// and rollback for good. core.BlockValidator now rejects such headers at
// import, so this guard covers the data already on disk (blocks stored before
// the rule, or a corrupted store): the seed must adopt nothing rather than the
// claim, leaving the floor where the last valid block put it.
func TestR30_UnbackedHeaderCannotPoisonTheFloor(t *testing.T) {
	n, _ := newReplayTestNode(t, 5, 1)

	newQPOS := func() *consensus.QPOS {
		t.Helper()
		qpos, err := consensus.NewQPOS(nil)
		if err != nil {
			t.Fatalf("NewQPOS: %v", err)
		}
		return qpos
	}

	// Slot 40 sits in epoch 1, so epochs beyond 1 are unbacked here.
	poisoned := &encoding.BlockHeader{Height: 2, Slot: 40, Epoch: 1, JustifiedEpoch: 1 << 40, FinalizedEpoch: 1 << 40}
	qpos := newQPOS()
	if n.adoptHeaderFinality(qpos, poisoned, block.ComputeBlockHash(poisoned)) {
		t.Fatal("an unbacked checkpoint claim must not be adopted")
	}
	if got := qpos.GetFinalizedEpoch(); got != 0 {
		t.Fatalf("finalized epoch = %d, want 0 (nothing adopted)", got)
	}
	if floor, ok := qpos.FinalityFloorSlot(); ok {
		t.Fatalf("the floor must stay unset, got slot %d", floor)
	}

	// The same shape with a backed claim must still work, otherwise the guard
	// would be indistinguishable from breaking the R106 catch-up fix.
	backed := &encoding.BlockHeader{Height: 3, Slot: 70, Epoch: 2, JustifiedEpoch: 2, FinalizedEpoch: 1}
	qpos = newQPOS()
	if !n.adoptHeaderFinality(qpos, backed, block.ComputeBlockHash(backed)) {
		t.Fatal("a backed checkpoint claim must be adopted")
	}
	if got := qpos.GetFinalizedEpoch(); got != 1 {
		t.Fatalf("finalized epoch = %d, want 1", got)
	}
	if floor, ok := qpos.FinalityFloorSlot(); !ok || floor != consensus.SlotsPerEpoch {
		t.Fatalf("finality floor = (%d, %v), want (%d, true)", floor, ok, uint64(consensus.SlotsPerEpoch))
	}
}

// TestR30F14_DebugRollbackMovesTheHeadBeforeTruncating pins the ordering the
// operator rollback needs (R30 F14). Fork choice derives the abandoned range by
// walking the OLD head's ancestry; if the store is truncated first, that walk
// cannot find the ancestor and the plan degrades to "the abandoned range starts
// up to 64 slots below the new head", which always reaches below the finality
// floor. The switch was then refused and the refusal was only logged: the RPC
// returned success with a truncated store, a rewound state and a head pointing
// at a block that no longer exists.
func TestR30F14_DebugRollbackMovesTheHeadBeforeTruncating(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks, hashes := r29BuildChain(t, bs, 0, 40, 45, 50) // heights 0..3

	qpos := r30QPOSWithFinality(t) // floor at slot 32
	for i, b := range blocks {
		qpos.SetSlotBlockRoot(b.Header.Slot, hashes[i])
	}
	n := &Node{
		blockStore:    bs,
		currentBlock:  blocks[3],
		stateTrust:    newStateTrust(),
		blockProducer: &BlockProducer{qpos: qpos},
	}

	// Roll back to height 2: heights 2 and 3 are dropped, the surviving tip is
	// block 1 at slot 40 (above the floor, so this is a legal rollback).
	deleted, err := newForkRecoveryBackend(n).RollbackToFork(2)
	if err != nil {
		t.Fatalf("a legal rollback must succeed, got: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted %d blocks, want 2", deleted)
	}
	if n.currentBlock == nil || n.currentBlock.Header.Height != 1 {
		t.Fatalf("the head must move to the truncation point, got %+v", n.currentBlock)
	}
	if block.ComputeBlockHash(n.currentBlock.Header) != hashes[1] {
		t.Fatal("the head must be the block at the truncation point")
	}
	if _, gerr := bs.GetBlockByHeight(2); gerr == nil {
		t.Fatal("the store must be truncated at and above the rollback height")
	}
	if root, ok := qpos.GetSlotBlockRoot(50); ok && root != (types.Hash{}) {
		t.Fatalf("the abandoned slot root 50 must be cleaned, got %x", root[:8])
	}
	if root, ok := qpos.GetSlotBlockRoot(40); !ok || root != hashes[1] {
		t.Fatal("the surviving head's slot root must be kept")
	}
}

// TestR30F14_RollbackBelowTheFinalityFloorChangesNothing pins the fail-closed
// half: when the surviving tip would sit below the floor, the finalized blocks
// above it would be deleted. The call must then abort BEFORE touching anything —
// a half-applied rollback (truncated store, rewound state, head on a deleted
// block) is exactly what the RPC used to report as success.
func TestR30F14_RollbackBelowTheFinalityFloorChangesNothing(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks, _ := r29BuildChain(t, bs, 0, 10, 40, 45) // heights 0..3, block 1 is below the floor

	n := &Node{
		blockStore:    bs,
		currentBlock:  blocks[3],
		stateTrust:    newStateTrust(),
		blockProducer: &BlockProducer{qpos: r30QPOSWithFinality(t)}, // floor at slot 32
	}

	deleted, err := newForkRecoveryBackend(n).RollbackToFork(2)
	if err == nil {
		t.Fatal("a rollback that would delete finalized blocks must be refused")
	}
	if deleted != 0 {
		t.Fatalf("a refused rollback must delete nothing, got %d", deleted)
	}
	if _, gerr := bs.GetBlockByHeight(3); gerr != nil {
		t.Fatal("a refused rollback must leave the store intact")
	}
	if n.currentBlock != blocks[3] {
		t.Fatal("a refused rollback must not move the head")
	}
}

// TestR30F15_TruncatedStoreStillMovesTheHead pins the ancestor hint (R30 F15).
// After a syncer truncation the old head and its parents are gone, so the usual
// ancestor walk fails and the plan understates the abandoned range as "the
// newest 64 slots", which reaches below the finality floor — the head could
// never follow the re-imported chain and stayed on a deleted block until a
// restart. The block the new head descends from is still in the store, and that
// block is the ancestor.
func TestR30F15_TruncatedStoreStillMovesTheHead(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	// A chain long enough that the ancestor walk covers a full window: on a real
	// chain the walked segment always spans maxReorgDepth slots, so its lowest
	// slot is far below the floor even when the surviving tip is well above it.
	slots := make([]uint64, 0, 62)
	for s := uint64(0); s <= 61; s++ {
		slots = append(slots, s)
	}
	blocks, hashes := r29BuildChain(t, bs, slots...)
	head := blocks[len(blocks)-1]      // height 61, slot 61
	headHash := hashes[len(hashes)-1]  // the abandoned head's hash
	surviving := blocks[len(blocks)-2] // height 60, slot 60 — dropped by the truncation

	qpos := r30QPOSWithFinality(t) // floor at slot 32
	qpos.SetSlotBlockRoot(surviving.Header.Slot-1, hashes[len(hashes)-3])
	n := &Node{
		blockStore:    bs,
		currentBlock:  head,
		stateTrust:    newStateTrust(),
		blockProducer: &BlockProducer{qpos: qpos},
	}

	// The truncation already happened (as a syncer rollback does), so neither the
	// head nor its parent is readable any more.
	if _, err := bs.DeleteBlocksFromHeight(surviving.Header.Height); err != nil {
		t.Fatalf("DeleteBlocksFromHeight: %v", err)
	}

	// Peers re-send the block at the truncation height on top of the surviving
	// tip (a different slot, so this really is a replacement branch and not the
	// block the truncation removed); ProcessBlock stores it before the head
	// switch.
	reimported := &encoding.Block{Header: &encoding.BlockHeader{
		Height:     surviving.Header.Height,
		Slot:       surviving.Header.Slot + 2,
		Epoch:      consensus.SlotToEpoch(surviving.Header.Slot + 2),
		ParentHash: hashes[len(hashes)-3],
	}}
	if err := bs.PutBlock(reimported); err != nil {
		t.Fatalf("PutBlock(reimported): %v", err)
	}
	reimportedHash := block.ComputeBlockHash(reimported.Header)

	hint, ok := truncationAncestorHint(bs, reimported)
	if !ok || hint.slot != surviving.Header.Slot-1 {
		t.Fatalf("truncation hint = (%+v, %v), want the surviving tip at slot %d", hint, ok, surviving.Header.Slot-1)
	}
	if p := planSlotReanchor(bs, reimported, reimportedHash, head, headHash); p != nil && p.bounds.AncestorKnown {
		t.Fatalf("precondition: the truncated store must defeat the plain walk, got ancestor %d", p.bounds.AncestorSlot)
	}

	if !n.commitHeadSwitchLocked("r30F15", reimported, reimportedHash, head, headHash, qpos) {
		t.Fatal("a head switch after a store truncation must be accepted: the surviving tip is above the floor and is still stored")
	}
	if n.currentBlock != reimported {
		t.Fatal("the head must follow the re-imported block")
	}
	if root, ok := qpos.GetSlotBlockRoot(surviving.Header.Slot - 1); !ok || root != hashes[len(hashes)-3] {
		t.Fatal("the surviving tip's slot root must be kept")
	}
}

// TestR30F17_RollbackAboveTheHeadChangesNothing pins F17. The debug rollback
// is an operator "go back to this height" call, but the store can hold blocks
// above the head (the head lags the store during sync). Asking for a fork
// height above the head then is not a rollback: the head would move FORWARD and
// the store would be truncated above it, leaving a head that the state rollback
// cannot follow (state never moves forward) — the same three-way mismatch the
// rollback path exists to prevent. Nothing may change.
func TestR30F17_RollbackAboveTheHeadChangesNothing(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks, hashes := r29BuildChain(t, bs, 0, 40, 45, 50) // heights 0..3

	n := &Node{
		blockStore:    bs,
		currentBlock:  blocks[1], // head lags the store on purpose (heights 2 and 3 exist)
		stateTrust:    newStateTrust(),
		blockProducer: &BlockProducer{qpos: r30QPOSWithFinality(t)},
	}

	deleted, err := newForkRecoveryBackend(n).RollbackToFork(3)
	if err == nil {
		t.Fatal("a rollback whose target tip is above the current head must be refused")
	}
	if deleted != 0 {
		t.Fatalf("a refused rollback must delete nothing, got %d", deleted)
	}
	if n.currentBlock != blocks[1] {
		t.Fatal("a refused rollback must not move the head (forward or backward)")
	}
	if got, gerr := bs.GetBlockByHeight(3); gerr != nil || block.ComputeBlockHash(got.Header) != hashes[3] {
		t.Fatal("a refused rollback must leave the store intact")
	}
}

// TestR30F18_ReimportedTipAtTheSameHeightStillMovesTheHead pins the last gap
// in the truncation handling (R30 F18). The ancestor hint is consulted only
// when the store has stopped holding the old head, and the natural test for
// that is "reading the old head's height fails". A one-block reorg at the tip
// refills that very height with the replacement before the head switch, so the
// height read SUCCEEDS while the block it returns is a different block — the
// hint was then skipped and the degraded plan (abandoned range starts at the
// newest walked slot) reached below the floor, freezing the head on a block the
// store had already replaced. "Missing" must mean "the store no longer returns
// this block", not "the height is empty".
func TestR30F18_ReimportedTipAtTheSameHeightStillMovesTheHead(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	slots := make([]uint64, 0, 62)
	for s := uint64(0); s <= 61; s++ {
		slots = append(slots, s)
	}
	blocks, hashes := r29BuildChain(t, bs, slots...)
	head := blocks[len(blocks)-1]      // height 61, slot 61
	headHash := hashes[len(hashes)-1]  // hash the truncation removes
	surviving := blocks[len(blocks)-2] // height 60, slot 60 — also dropped

	qpos := r30QPOSWithFinality(t) // floor at slot 32
	qpos.SetSlotBlockRoot(surviving.Header.Slot-1, hashes[len(hashes)-3])
	n := &Node{
		blockStore:    bs,
		currentBlock:  head,
		stateTrust:    newStateTrust(),
		blockProducer: &BlockProducer{qpos: qpos},
	}

	// Two blocks are truncated, so the old-chain walk cannot even reach the old
	// head's parent — but the replacement branch refills BOTH heights.
	if _, err := bs.DeleteBlocksFromHeight(surviving.Header.Height); err != nil {
		t.Fatalf("DeleteBlocksFromHeight: %v", err)
	}
	anchor := hashes[len(hashes)-3]
	branch := make([]*encoding.Block, 0, 2)
	for i, slot := range []uint64{surviving.Header.Slot + 1, head.Header.Slot + 1} {
		blk := &encoding.Block{Header: &encoding.BlockHeader{
			Height:     surviving.Header.Height + uint64(i),
			Slot:       slot,
			Epoch:      consensus.SlotToEpoch(slot),
			ParentHash: anchor,
		}}
		if err := bs.PutBlock(blk); err != nil {
			t.Fatalf("PutBlock(branch %d): %v", i, err)
		}
		anchor = block.ComputeBlockHash(blk.Header)
		branch = append(branch, blk)
	}
	newHead := branch[len(branch)-1]
	newHeadHash := anchor

	// The store DOES return a block at the old head's height — just not the old
	// head. "Missing" has to mean that, or this switch is vetoed and the head
	// stays on a block the store already replaced.
	if !n.commitHeadSwitchLocked("r30F18", newHead, newHeadHash, head, headHash, qpos) {
		t.Fatal("a reorg that replaced the tip at the same height must still move the head: the surviving tip is stored and above the floor")
	}
	if n.currentBlock != newHead {
		t.Fatal("the head must follow the replacement block")
	}
	if root, ok := qpos.GetSlotBlockRoot(surviving.Header.Slot - 1); !ok || root != hashes[len(hashes)-3] {
		t.Fatal("the surviving tip's slot root must be kept")
	}
}

// TestR30F16_DroppedBlockCannotAnchorASlotRoot pins F16. Every block the
// syncer applies is replayed into the QPOS snapshot, and that snapshot IS the
// canonical root set: slotBlockRoots decides which attestations count as votes
// for the canonical chain, and epochBlockRoots resolves checkpoint lookups. A
// block that the store no longer holds at its height (truncated by a rollback,
// or never stored) must therefore not be replayed — otherwise a dropped block
// keeps a canonical-looking slot root until fork choice happens to clean the
// range, and a rebuild pass running across a rollback resurrects roots that the
// cleanup has already removed.
func TestR30F16_DroppedBlockCannotAnchorASlotRoot(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks, hashes := r29BuildChain(t, bs, 0, 40, 45) // heights 0..2

	newSyncer := func(qpos *consensus.QPOS) *Syncer {
		t.Helper()
		return &Syncer{
			blockStore: bs,
			stateDB:    state.NewStateDB(db.NewMemDB()),
			qpos:       qpos,
		}
	}
	newQPOS := func() *consensus.QPOS {
		t.Helper()
		qpos, err := consensus.NewQPOS(nil)
		if err != nil {
			t.Fatalf("NewQPOS: %v", err)
		}
		return qpos
	}

	// A stored block IS the canonical block at its height, so its root is
	// recorded (the reconstruction contract R38-P1-08 relies on).
	storedQPOS := newQPOS()
	if err := newSyncer(storedQPOS).applyBlock(blocks[1]); err != nil {
		t.Fatalf("applyBlock(stored): %v", err)
	}
	if root, ok := storedQPOS.GetSlotBlockRoot(40); !ok || root != hashes[1] {
		t.Fatal("a stored canonical block must be replayed into the snapshot")
	}

	// The tip is truncated out of the store; a stale apply of that block must
	// not recreate its slot root on any QPOS.
	if _, err := bs.DeleteBlocksFromHeight(2); err != nil {
		t.Fatalf("DeleteBlocksFromHeight: %v", err)
	}
	truncatedQPOS := newQPOS()
	if err := newSyncer(truncatedQPOS).applyBlock(blocks[2]); err != nil {
		t.Fatalf("applyBlock(truncated): %v", err)
	}
	if truncatedQPOS.HasAppliedBlockHeader(hashes[2]) {
		t.Fatal("a block the store no longer holds must not be replayed into the QPOS snapshot")
	}
	if root, ok := truncatedQPOS.GetSlotBlockRoot(45); ok && root != (types.Hash{}) {
		t.Fatalf("a block the store no longer holds must not anchor slot 45, got %x", root[:8])
	}
}
