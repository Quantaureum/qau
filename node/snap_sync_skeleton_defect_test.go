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
