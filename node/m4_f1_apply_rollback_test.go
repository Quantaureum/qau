// M4-F1 regression: a strict state-root mismatch must undo BOTH the block
// this call inserted and the state transition it committed. Before the fix
// the block stayed in the canonical store and the state stayed at the failed
// height, so every retry of the same height re-executed on diverged state —
// the M4 amplification chain (thousands of mismatches at a single height).
package node

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// m4f1_buildMismatchBlock builds a height=1 child of the seeded genesis whose
// header state root cannot match after execution (same fixture shape as the
// R38-P1-08 tests). Returns the block and its hash.
func m4f1_buildMismatchBlock(t *testing.T, s *Syncer, bs *block.BlockStore) (*encoding.Block, types.Hash) {
	t.Helper()
	parent := r38p1_08_seedGenesis(t, s, bs)
	child := r38p1_08_makeValidChildHeader(parent)
	child.Signature = make([]byte, 3293)
	child.StateRoot = types.Hash{0xAA}
	child.ReceiptRoot = types.Hash{0xBB}
	blk := &encoding.Block{Header: child, Transactions: nil}
	return blk, block.ComputeBlockHash(child)
}

// TestM4F1_MismatchRollsBackStoreAndState asserts "store and state both do
// not advance" and that a same-height retry does not accumulate the state
// change (no double accounting).
func TestM4F1_MismatchRollsBackStoreAndState(t *testing.T) {
	s, bs, _ := r38p1_08_newSyncerWithStore(t)
	blk, blkHash := m4f1_buildMismatchBlock(t, s, bs)

	addr := types.Address{0x77}
	baseline := big.NewInt(1000)
	s.stateDB.SetBalance(addr, new(big.Int).Set(baseline))
	if _, err := s.stateDB.CommitWithBlock(0); err != nil {
		t.Fatalf("baseline commit failed: %v", err)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		// The empty test block has no transaction side effects, so stage the
		// mutation the block's execution would have made. This is what gives
		// the commit a before-image to roll back.
		s.stateDB.AddBalance(addr, big.NewInt(100))

		err := s.ProcessBlock(blk)
		if err == nil {
			t.Fatalf("attempt %d: expected a state-root mismatch, got nil", attempt)
		}
		if !errors.Is(err, ErrStateRootMismatch) {
			t.Fatalf("attempt %d: expected ErrStateRootMismatch, got %v", attempt, err)
		}

		if got := s.stateDB.GetBalance(addr); got.Cmp(baseline) != 0 {
			t.Fatalf("attempt %d: balance = %s, want %s — the failed apply was not rolled back",
				attempt, got, baseline)
		}
		if got := s.stateDB.LastCommittedHeight(); got != 0 {
			t.Fatalf("attempt %d: state advanced to height %d, want 0", attempt, got)
		}
		if exists, _ := bs.HasBlock(blkHash); exists {
			t.Fatalf("attempt %d: failed block stayed in the canonical store", attempt)
		}
		if got := s.currentHeight; got != 0 {
			t.Fatalf("attempt %d: syncer currentHeight advanced to %d, want 0", attempt, got)
		}
	}
}

// TestM4F1_RollbackFailureBreaksStateTrust covers the case where the rollback
// itself cannot run (the failed commit left no in-memory undo history). The
// syncer must report a hard state-trust break instead of silently pretending
// the height is sane.
func TestM4F1_RollbackFailureBreaksStateTrust(t *testing.T) {
	s, bs, _ := r38p1_08_newSyncerWithStore(t)
	blk, _ := m4f1_buildMismatchBlock(t, s, bs)

	addr := types.Address{0x78}
	s.stateDB.SetBalance(addr, big.NewInt(500))
	if _, err := s.stateDB.CommitWithBlock(0); err != nil {
		t.Fatalf("baseline commit failed: %v", err)
	}

	fatalCalled := false
	var fatalDetail string
	s.SetOnStateFatal(func(detail string) {
		fatalCalled = true
		fatalDetail = detail
	})

	// Attempt 1: dirty state gives the commit a before-image, so the rollback
	// succeeds and the block is removed.
	s.stateDB.AddBalance(addr, big.NewInt(50))
	if err := s.ProcessBlock(blk); err == nil {
		t.Fatal("attempt 1: expected a state-root mismatch, got nil")
	} else if !errors.Is(err, ErrStateRootMismatch) {
		t.Fatalf("attempt 1: expected ErrStateRootMismatch, got %v", err)
	}

	// Attempt 2: nothing is dirty, so the commit records height 1 without any
	// undo history. RollbackToHeight(1) must fail (M4-F3 guard).
	err := s.ProcessBlock(blk)
	if err == nil {
		t.Fatal("attempt 2: expected a hard rollback failure, got nil")
	}
	if !errors.Is(err, ErrStateRollbackAfterApply) {
		t.Fatalf("attempt 2: expected ErrStateRollbackAfterApply, got %v", err)
	}
	if !fatalCalled || fatalDetail == "" {
		t.Fatal("M4-F1: a failed rollback must report a hard state-trust break to the node")
	}
}
