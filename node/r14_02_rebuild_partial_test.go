package node

import (
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// seedGapBlock stores a header at height h WITHOUT chaining to h-1. Used to
// build a range that has a hole in it (the missing height is never seeded).
func seedGapBlock(t *testing.T, bs *block.BlockStore, h uint64, stateRoot, parent types.Hash) {
	t.Helper()
	hdr := &encoding.BlockHeader{
		Version:    1,
		Height:     h,
		Epoch:      h / 32,
		Slot:       h,
		StateRoot:  stateRoot,
		ParentHash: parent,
	}
	if err := bs.PutBlockWithIndex(&encoding.Block{Header: hdr}); err != nil {
		t.Fatalf("seed gap block %d: %v", h, err)
	}
}

// R14-02 regression (2026-10-27): rebuildRange counted per-block fetch/apply
// failures in `failed` and then never looked at the counter. A range with a
// hole fell through to the final state-root comparison, and because the local
// state was missing those blocks' transitions the roots never matched — so the
// R63-STATE-ROOT-TRUST branch set s.stateVerifiedHeight = toHeight and returned
// true. That froze a state that had never been rebuilt: every later rebuild
// skipped the range as "already verified", and the node kept producing on top
// of the incomplete state.
//
// A partial rebuild must fail closed: report failure, leave the verified height
// alone, and let the caller retry the range.
func TestRebuildRange_PartialApplyMustNotMarkVerified(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	stateDB := state.NewStateDB()

	// Heights 2..3 with height 2 deliberately absent from the store.
	putBlock(t, bs, 1, types.Hash{0xAA})
	seedGapBlock(t, bs, 3, types.Hash{0xCC}, types.Hash{0xDE})

	s := NewSyncer(nil, bs, stateDB, nil, 1668)
	defer s.Stop()

	ok := s.rebuildRange(2, 3)
	if ok {
		t.Fatal("rebuildRange must report failure when a block in the range could not be fetched")
	}

	s.mu.RLock()
	verified := s.stateVerifiedHeight
	s.mu.RUnlock()
	if verified != 0 {
		t.Fatalf("a partial rebuild must NOT advance the verified height; got %d, want 0", verified)
	}
}

// Same partial rebuild, but a verified baseline already sat ABOVE the rebuild
// start. The clamp must pull it back to just below the range so no consumer
// treats the incomplete range as proven.
func TestRebuildRange_PartialApplyClampsStaleVerifiedHeight(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	stateDB := state.NewStateDB()

	putBlock(t, bs, 1, types.Hash{0xAA})
	seedGapBlock(t, bs, 3, types.Hash{0xCC}, types.Hash{0xDE})

	s := NewSyncer(nil, bs, stateDB, nil, 1668)
	defer s.Stop()

	s.mu.Lock()
	s.stateVerifiedHeight = 9 // stale proof that covers the hole
	s.mu.Unlock()

	if ok := s.rebuildRange(2, 3); ok {
		t.Fatal("rebuildRange must report failure on a range with a missing block")
	}

	s.mu.RLock()
	verified := s.stateVerifiedHeight
	s.mu.RUnlock()
	if verified != 1 {
		t.Fatalf("stale verified height must clamp to fromHeight-1 (1), got %d", verified)
	}
}

// Negative control: a COMPLETE range must still rebuild and mark verified, so
// the fail-closed guard cannot be satisfied by simply never succeeding.
func TestRebuildRange_CompleteRangeStillMarksVerified(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	stateDB := state.NewStateDB()

	putBlock(t, bs, 1, types.Hash{0xAA})
	putBlock(t, bs, 2, types.Hash{0xBB})

	s := NewSyncer(nil, bs, stateDB, nil, 1668)
	defer s.Stop()

	if ok := s.rebuildRange(1, 2); !ok {
		t.Fatal("a complete range must rebuild successfully")
	}

	s.mu.RLock()
	verified := s.stateVerifiedHeight
	s.mu.RUnlock()
	if verified != 2 {
		t.Fatalf("complete rebuild must mark verified=toHeight (2), got %d", verified)
	}
}
