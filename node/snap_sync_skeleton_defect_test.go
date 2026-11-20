// Quantaureum Node source, version 1.0.0.
// Package node — regression tests for the snap-sync skeleton defect observed
// on a mainnet RPC node (task-snap-sync-skeleton-defect.md, 2026-11-19).
//
// Three failure modes are pinned here:
//
//  1. The R62-SNAP-ADVANCE pivot install must not downgrade an already-stored
//     canonical block to a header-only body (PutBlock's same-hash re-index
//     used to rewrite the stored block data, stripping its transactions).
//  2. A fresh/post-restart node whose state rollback fails with
//     state.ErrRollbackHistoryUnavailable must not re-run the fork-acceptance
//     dance at the same fork height forever (the mainnet 42-cycle OOM loop).
//  3. The skeleton header map must not retain entries below the block tip
//     forever (unbounded growth on mainnet-scale syncs).
package node

import (
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// snapDefect_chainWithTx stores genesis + count blocks, each carrying one
// transaction, directly into the block store (bypassing ProcessBlock so the
// test controls exactly what is canonical). Returns the stored blocks.
func snapDefect_chainWithTx(t *testing.T, s *Syncer, bs *block.BlockStore, count int) []*encoding.Block {
	t.Helper()
	parent := r38p1_08_seedGenesis(t, s, bs)
	blocks := make([]*encoding.Block, 0, count)
	prev := parent
	for i := 1; i <= count; i++ {
		hdr := r38p1_08_makeValidChildHeader(prev)
		hdr.Signature = make([]byte, 3293)
		hdr.StateRoot = types.Hash{0xAA}
		hdr.ReceiptRoot = types.Hash{0xBB}
		tx := &encoding.Transaction{
			Type:     encoding.TxTypeTransfer,
			From:     types.BytesToAddress([]byte{0x11, 0x22}),
			Nonce:    uint64(i),
			Value:    big.NewInt(int64(i)),
			GasLimit: 21000,
			GasPrice: big.NewInt(1),
			ChainID:  1333,
		}
		blk := &encoding.Block{Header: hdr, Transactions: []*encoding.Transaction{tx}}
		if err := bs.PutBlock(blk); err != nil {
			t.Fatalf("seed block %d: PutBlock failed: %v", i, err)
		}
		blocks = append(blocks, blk)
		prev = hdr
	}
	return blocks
}

// TestSnapSkeletonDefect_PivotInstallKeepsStoredBlockBody pins the pivot
// install fix: when the canonical pivot block was already persisted by the
// concurrent block-sync path, completeSnapSync must NOT rewrite it with the
// header-only pivot (which stripped the stored transactions and left
// body-less canonical blocks in the store — the observed store pollution).
// The state-root verification itself is covered elsewhere; here the block
// validator is nil'd out so the test isolates the pivot-install branch.
func TestSnapSkeletonDefect_PivotInstallKeepsStoredBlockBody(t *testing.T) {
	s, bs, _ := r38p1_08_newSyncerWithStore(t)
	blocks := snapDefect_chainWithTx(t, s, bs, 2)

	s.mu.Lock()
	s.blockValidator = nil
	s.snapSyncing = true
	s.snapTargetBlock = 2
	s.snapTargetHeader = blocks[1].Header
	s.currentHeight = 0
	s.mu.Unlock()

	s.completeSnapSync()

	s.mu.RLock()
	advanced := s.currentHeight
	completed := s.snapSyncCompleted
	s.mu.RUnlock()
	if advanced != 2 {
		t.Fatalf("currentHeight = %d, want 2 (snap advance)", advanced)
	}
	if !completed {
		t.Fatal("snapSyncCompleted = false, want true")
	}
	stored, err := bs.GetBlockByHeight(2)
	if err != nil || stored == nil {
		t.Fatalf("pivot block unreadable after snap: %v", err)
	}
	if len(stored.Transactions) != 1 {
		t.Fatalf("pivot block body was stripped by the pivot install: %d transactions remain, want 1 — "+
			"the header-only pivot must not overwrite a stored canonical block", len(stored.Transactions))
	}
}

// TestSnapSkeletonDefect_PivotInstallStillInstallsWhenAbsent proves the fix
// did not break the original R62 path: with the pivot block NOT yet in the
// store, completeSnapSync still installs the header-only pivot and advances
// the tip (the next block's ParentHash lookup depends on it).
func TestSnapSkeletonDefect_PivotInstallStillInstallsWhenAbsent(t *testing.T) {
	s, bs, _ := r38p1_08_newSyncerWithStore(t)
	blocks := snapDefect_chainWithTx(t, s, bs, 2)

	// Drop the stored blocks above genesis: the pivot is now absent.
	if _, err := bs.DeleteBlocksFromHeight(1); err != nil {
		t.Fatalf("DeleteBlocksFromHeight: %v", err)
	}

	s.mu.Lock()
	s.blockValidator = nil
	s.snapSyncing = true
	s.snapTargetBlock = 2
	s.snapTargetHeader = blocks[1].Header
	s.currentHeight = 0
	s.mu.Unlock()

	s.completeSnapSync()

	s.mu.RLock()
	advanced := s.currentHeight
	s.mu.RUnlock()
	if advanced != 2 {
		t.Fatalf("currentHeight = %d, want 2 (pivot install)", advanced)
	}
	stored, err := bs.GetBlockByHeight(2)
	if err != nil || stored == nil {
		t.Fatalf("installed pivot block unreadable: %v", err)
	}
	if len(stored.Transactions) != 0 {
		t.Fatalf("installed pivot should be the header-only carrier, got %d transactions", len(stored.Transactions))
	}
}

// TestSnapSkeletonDefect_ForkRollbackNoStateLoopsAreBounded pins the
// fresh-node loop breaker.
//
// The mainnet loop worked like this: a fork was detected and accepted at
// height H → the store segment from H was deleted → the peer blocks were
// re-requested and re-stored (each re-store advanced currentHeight and
// refreshed the stall timers) → the fork at H was detected again → accepted
// again → ... 42 cycles in 30 minutes, ending in an OOM kill. The node-level
// rollback failed every cycle with ErrRollbackHistoryUnavailable (fresh
// node — no in-memory before-images).
//
// With the fix, the acceptance dance may run only twice per fork height
// while the state rollback keeps failing; past that the fork block is
// dropped without touching the store.
func TestSnapSkeletonDefect_ForkRollbackNoStateLoopsAreBounded(t *testing.T) {
	s, bs, _ := r38p1_08_newSyncerWithStore(t)
	blocks := snapDefect_chainWithTx(t, s, bs, 5)

	// Sync mode, tip at 5 — the fresh-node mid-sync state.
	s.mu.Lock()
	s.currentHeight = 5
	s.syncing = true
	s.mu.Unlock()
	atomic.StoreInt32(&s.syncActive, 1)

	// A competing block at height 6 whose parent is NOT our block 5.
	fork := r38p1_08_makeValidChildHeader(blocks[4].Header)
	fork.ParentHash = types.Hash{0xEE}
	fork.Signature = make([]byte, 3293)
	fork.StateRoot = types.Hash{0xAA}
	fork.ReceiptRoot = types.Hash{0xBB}
	forkBlk := &encoding.Block{Header: fork, Transactions: nil}

	rollbackCalls := 0
	s.SetOnForkRollback(func(forkHeight uint64) {
		rollbackCalls++
		// The node-level callback path: state cannot be rolled back (no
		// in-memory before-images on a fresh node) — record it exactly like
		// the production callback does on ErrRollbackHistoryUnavailable.
		s.noteForkStateRollbackUnavailable(forkHeight)
	})

	// reStoreTip re-stores block 5, mirroring the re-request fulfillment
	// that follows every acceptance in the production loop.
	reStoreTip := func() {
		if err := bs.PutBlock(&encoding.Block{Header: blocks[4].Header, Transactions: blocks[4].Transactions}); err != nil {
			t.Fatalf("re-store block 5: %v", err)
		}
		s.mu.Lock()
		s.currentHeight = 5
		s.mu.Unlock()
	}

	deliver := func() {
		// Errors other than ErrForkDetected (e.g. ErrParentNotFound while the
		// fork point is temporarily absent) are part of the cycle; only the
		// rollback count and the final store state are load-bearing here.
		_ = s.ProcessBlock(forkBlk)
	}

	// Cycle 1: tip re-stored, three detections (peerCount floor = 3) →
	// first acceptance → rollback to 5 → store truncated again.
	reStoreTip()
	for i := 0; i < 3; i++ {
		deliver()
	}
	if rollbackCalls != 1 {
		t.Fatalf("rollbackCalls = %d after cycle 1, want 1 (fork should have been accepted once)", rollbackCalls)
	}

	// Cycle 2: same as cycle 1 — the second (and, with the fix, last) dance.
	reStoreTip()
	for i := 0; i < 3; i++ {
		deliver()
	}
	if rollbackCalls != 2 {
		t.Fatalf("rollbackCalls = %d after cycle 2, want 2 (the dance must be bounded to two cycles)", rollbackCalls)
	}

	// Cycle 3: the dance is now exhausted. Re-store the tip and deliver the
	// fork block repeatedly — the store must stay intact and the rollback
	// must not run again.
	reStoreTip()
	tipBefore, err := bs.GetBlockByHeight(5)
	if err != nil || tipBefore == nil {
		t.Fatalf("block 5 missing before cycle 3: %v", err)
	}
	for i := 0; i < 10; i++ {
		deliver()
	}
	if rollbackCalls != 2 {
		t.Fatalf("rollbackCalls = %d after cycle 3, want 2 — the dance must not run again once exhausted", rollbackCalls)
	}
	tipAfter, err := bs.GetBlockByHeight(5)
	if err != nil || tipAfter == nil {
		t.Fatal("block 5 was deleted by the exhausted fork path — the escape path must not truncate the store")
	}
	if tipAfter.Header.Height != tipBefore.Header.Height {
		t.Fatal("canonical tip changed during the exhausted fork path")
	}
}

// TestSnapSkeletonDefect_ForkRollbackNormalPathUnaffected proves the loop
// breaker does not interfere with a healthy fork recovery: with no recorded
// rollback failures, the fork is still accepted after peerCount detections.
func TestSnapSkeletonDefect_ForkRollbackNormalPathUnaffected(t *testing.T) {
	s, bs, _ := r38p1_08_newSyncerWithStore(t)
	blocks := snapDefect_chainWithTx(t, s, bs, 5)

	s.mu.Lock()
	s.currentHeight = 5
	s.syncing = true
	s.mu.Unlock()
	atomic.StoreInt32(&s.syncActive, 1)

	fork := r38p1_08_makeValidChildHeader(blocks[4].Header)
	fork.ParentHash = types.Hash{0xEE}
	fork.Signature = make([]byte, 3293)
	fork.StateRoot = types.Hash{0xAA}
	fork.ReceiptRoot = types.Hash{0xBB}
	forkBlk := &encoding.Block{Header: fork, Transactions: nil}

	rollbackCalls := 0
	s.SetOnForkRollback(func(forkHeight uint64) {
		rollbackCalls++
	})

	for i := 0; i < 3; i++ {
		_ = s.ProcessBlock(forkBlk)
	}
	if rollbackCalls != 1 {
		t.Fatalf("rollbackCalls = %d, want 1 — the normal fork acceptance must still run", rollbackCalls)
	}
	if got := s.CurrentHeight(); got != 4 {
		t.Fatalf("currentHeight = %d, want 4 (rolled back to forkPoint-1)", got)
	}
}

// TestSnapSkeletonDefect_SkeletonHeadersPrunedBelowTip pins the skeleton map
// bound: entries below the block tip are dead weight and must be pruned,
// entries at or above the tip must survive (the pivot lookup needs them).
func TestSnapSkeletonDefect_SkeletonHeadersPrunedBelowTip(t *testing.T) {
	s, _, _ := r38p1_08_newSyncerWithStore(t)

	s.mu.Lock()
	for h := uint64(0); h < 10; h++ {
		s.skeletonHeaders[h] = r38p1_08_makeValidParentHeader()
	}
	s.currentHeight = 5
	s.pruneSkeletonHeadersLocked()
	kept := len(s.skeletonHeaders)
	s.mu.Unlock()

	if kept != 5 {
		t.Fatalf("skeletonHeaders length = %d after prune, want 5 (heights 5..9)", kept)
	}
	s.mu.RLock()
	_, belowExists := s.skeletonHeaders[4]
	_, atTipExists := s.skeletonHeaders[5]
	s.mu.RUnlock()
	if belowExists {
		t.Fatal("skeleton header below the tip survived the prune")
	}
	if !atTipExists {
		t.Fatal("skeleton header at the tip was incorrectly pruned")
	}
}

// snapDefect_newBufferedNode builds a minimal Node whose sync buffer is
// wired to the given syncer/block store, mirroring the field setup
// blockProcessingLoop/blockInsertLoop rely on. takeNextBlock only touches
// the sync-buffer accounting fields, the syncer and the block store, so a
// zero-value Node with those set is a faithful harness.
func snapDefect_newBufferedNode(s *Syncer, bs *block.BlockStore) *Node {
	n := &Node{
		syncer:          s,
		blockStore:      bs,
		syncBuf:         make([]*encoding.Block, 0, 8),
		syncBufSet:      make(map[string]struct{}),
		syncBufByHeight: make(map[uint64][]int),
		maxSyncBufBytes: 256 << 20,
	}
	return n
}

// snapDefect_enqueue adds a block to the node's sync buffer exactly the way
// blockProcessingLoop does (append + dedup set + height index + byte count).
func snapDefect_enqueue(t *testing.T, n *Node, blk *encoding.Block) {
	t.Helper()
	n.syncBufMu.Lock()
	defer n.syncBufMu.Unlock()
	h := block.ComputeBlockHash(blk.Header)
	n.syncBuf = append(n.syncBuf, blk)
	n.syncBufSet[string(h[:])] = struct{}{}
	n.syncBufByHeight[blk.Header.Height] = append(n.syncBufByHeight[blk.Header.Height], len(n.syncBuf)-1)
	n.syncBufBytes += int64(encoding.ApproxBlockBytes(blk))
}

// snapDefect_forkBlock builds a block at parent.Height+1 whose ParentHash
// deliberately does NOT match the stored parent — the fork-acceptance
// fallback's trigger shape.
func snapDefect_forkBlock(parent *encoding.BlockHeader) *encoding.Block {
	hdr := r38p1_08_makeValidChildHeader(parent)
	hdr.ParentHash = types.Hash{0xEE}
	hdr.Signature = make([]byte, 3293)
	hdr.StateRoot = types.Hash{0xAA}
	hdr.ReceiptRoot = types.Hash{0xBB}
	return &encoding.Block{Header: hdr, Transactions: nil}
}

// TestSnapSyncWaitForPivot_TakeNextBlockHoldsForkFallback pins the residual
// mainnet-wedge fix: while a snap sync is waiting for its pivot install, the
// buffered far-ahead blocks must NOT be fed through the fork-acceptance
// fallback. Every acceptance on a fresh node hits the M4-F3 no-rollback
// refusal and the next delivery wave re-arms the counters at a new height —
// an unbounded loop. takeNextBlock must return nil (wait for the pivot) and
// leave the buffer and the store untouched; after the pivot (snapSyncing
// cleared) the previous behavior resumes.
func TestSnapSyncWaitForPivot_TakeNextBlockHoldsForkFallback(t *testing.T) {
	s, bs, _ := r38p1_08_newSyncerWithStore(t)
	blocks := snapDefect_chainWithTx(t, s, bs, 5)

	s.mu.Lock()
	s.currentHeight = 5
	s.snapSyncing = true // snap session waiting for its pivot
	s.mu.Unlock()

	n := snapDefect_newBufferedNode(s, bs)
	// A fork block at the tip+1 (mismatched parent) and a far-ahead child of
	// it — neither chains onto the store, exactly the wedge's buffer shape.
	snapDefect_enqueue(t, n, snapDefect_forkBlock(blocks[4].Header))
	farHdr := r38p1_08_makeValidChildHeader(snapDefect_forkBlock(blocks[4].Header).Header)
	farHdr.Signature = make([]byte, 3293)
	farHdr.StateRoot = types.Hash{0xAA}
	farHdr.ReceiptRoot = types.Hash{0xBB}
	snapDefect_enqueue(t, n, &encoding.Block{Header: farHdr, Transactions: nil})

	// Drain repeatedly, as blockInsertLoop would across delivery waves: the
	// processor must never enter the fork-acceptance path while waiting for
	// the pivot (this is the mainnet wedge: every wave re-armed the dance at
	// a new fork height).
	rollbackCalls := 0
	s.SetOnForkRollback(func(forkHeight uint64) { rollbackCalls++ })
	for i := 0; i < 50; i++ {
		if got := n.takeNextBlock(); got != nil {
			t.Fatalf("drain %d: takeNextBlock returned a block while snap-syncing — the fork-acceptance fallback must be held until the pivot installs (got height %d)", i+1, got.Header.Height)
		}
	}
	if rollbackCalls != 0 {
		t.Fatalf("OnForkRollback fired %d times during the snap wait — fork-acceptance must not run while waiting for the pivot", rollbackCalls)
	}
	n.syncBufMu.Lock()
	buffered := len(n.syncBuf)
	n.syncBufMu.Unlock()
	if buffered != 2 {
		t.Fatalf("syncBuf length = %d after takeNextBlock, want 2 — the anti-deadlock clear must not run while waiting for the pivot", buffered)
	}
	if blk, err := bs.GetBlockByHeight(5); err != nil || blk == nil {
		t.Fatalf("canonical block 5 missing after takeNextBlock: %v — the wait path must not truncate the store", err)
	}

	// Pivot installed (or session failed closed): snapSyncing clears and the
	// previous behavior resumes — the fallback hands out the fork block so
	// the normal fork-resolution machinery can act on it.
	s.mu.Lock()
	s.snapSyncing = false
	s.mu.Unlock()
	got := n.takeNextBlock()
	if got == nil {
		t.Fatal("takeNextBlock returned nil after snapSyncing cleared — the fallback must resume")
	}
	if got.Header.Height != 6 {
		t.Fatalf("takeNextBlock returned height %d, want 6 (the fork block at currentH+1)", got.Header.Height)
	}
}

// TestSnapSyncWaitForPivot_FastPathStillProgresses proves the wait guard does
// not hold back verifiably chained blocks: a buffered block at currentH+1
// whose parent IS in the store is still handed out during the snap wait (the
// fast path runs before the guard), so ordinary catch-up progress is kept.
func TestSnapSyncWaitForPivot_FastPathStillProgresses(t *testing.T) {
	s, bs, _ := r38p1_08_newSyncerWithStore(t)
	blocks := snapDefect_chainWithTx(t, s, bs, 5)

	s.mu.Lock()
	s.currentHeight = 5
	s.snapSyncing = true
	s.mu.Unlock()

	n := snapDefect_newBufferedNode(s, bs)
	real6 := r38p1_08_makeValidChildHeader(blocks[4].Header)
	real6.Signature = make([]byte, 3293)
	real6.StateRoot = types.Hash{0xAA}
	real6.ReceiptRoot = types.Hash{0xBB}
	snapDefect_enqueue(t, n, &encoding.Block{Header: real6, Transactions: nil})

	got := n.takeNextBlock()
	if got == nil {
		t.Fatal("takeNextBlock returned nil for a block that chains onto the stored tip — the fast path must run before the snap-wait guard")
	}
	if got.Header.Height != 6 {
		t.Fatalf("takeNextBlock returned height %d, want 6", got.Header.Height)
	}
}
