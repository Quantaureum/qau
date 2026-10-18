package node

import (
	"sync/atomic"
	"testing"

	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// R114-UNTRUSTED-BASE: reproduces the mainnet incident family
// (2026-10-15..18, six production lockouts). A rebuild whose baseline was lifted
// by trusting unverified persisted lch must NOT engage the R63 canonical-trust
// path on a final root mismatch: R63 marks the range verified, freezes the
// poisoned state, and R87 locks production forever. It must instead refuse,
// force full sync, and drop the verified baseline.
func TestRebuildRange_UntrustedBaseMismatchForcesFullSync(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	stateDB := state.NewStateDB()

	// Seed a chain of two blocks whose headers commit to a state root that
	// the (empty) local stateDB will NOT reproduce — the mismatch condition.
	putBlock(t, bs, 1, types.Hash{0xAA})
	putBlock(t, bs, 2, types.Hash{0xBB})

	s := NewSyncer(nil, bs, stateDB, nil, 1668)
	defer s.Stop()

	// Simulate the R87-M4-RESTART lift: baseline trusted from persisted lch.
	s.rebuildBaseUntrusted = true
	if atomic.LoadInt32(&s.fullSyncMode) == 1 {
		t.Fatal("precondition: full sync off")
	}

	ok := s.rebuildRange(1, 2)
	if ok {
		t.Fatal("rebuildRange must REFUSE (return false) on mismatch over an untrusted base")
	}
	if atomic.LoadInt32(&s.fullSyncMode) != 1 {
		t.Fatal("mismatch on untrusted base must force full sync mode")
	}
	if s.rebuildBaseUntrusted {
		t.Fatal("flag must be consumed by the refusal path")
	}
	s.mu.RLock()
	verified := s.stateVerifiedHeight
	s.mu.RUnlock()
	if verified != 0 {
		t.Fatalf("verified baseline must be dropped to 0 on refusal, got %d", verified)
	}
}

// Same mismatch WITHOUT the untrusted flag must keep the R63 trust path: verified
// advances to toHeight and the rebuild reports success. Guards against
// over-tightening.
func TestRebuildRange_TrustedBaseMismatchKeepsR63(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	stateDB := state.NewStateDB()

	putBlock(t, bs, 1, types.Hash{0xCC})
	putBlock(t, bs, 2, types.Hash{0xDD})

	s := NewSyncer(nil, bs, stateDB, nil, 1668)
	defer s.Stop()

	s.rebuildBaseUntrusted = false // trusted base: plain R63 territory

	ok := s.rebuildRange(1, 2)
	if !ok {
		t.Fatal("R63 canonical-trust path must still succeed on a trusted-base mismatch")
	}
	s.mu.RLock()
	verified := s.stateVerifiedHeight
	s.mu.RUnlock()
	if verified != 2 {
		t.Fatalf("R63 must mark verified=toHeight (2), got %d", verified)
	}
	if atomic.LoadInt32(&s.fullSyncMode) == 1 {
		t.Fatal("R63 path must not force full sync")
	}
}

// putBlock stores a minimal canonical block at height h with the given StateRoot.
func putBlock(t *testing.T, bs *block.BlockStore, h uint64, stateRoot types.Hash) {
	t.Helper()
	hdr := &encoding.BlockHeader{
		Version:   1,
		Height:    h,
		Epoch:     h / 32,
		Slot:      h,
		StateRoot: stateRoot,
	}
	if h > 1 {
		hdr.ParentHash = block.ComputeHeaderHash(blockHeader(t, bs, h-1))
	}
	blk := &encoding.Block{Header: hdr, Transactions: nil}
	if err := bs.PutBlockWithIndex(blk); err != nil {
		t.Fatalf("seed block %d: %v", h, err)
	}
}

// blockHeader re-reads the stored header at h (parent hash chaining).
func blockHeader(t *testing.T, bs *block.BlockStore, h uint64) *encoding.BlockHeader {
	t.Helper()
	blk, err := bs.GetBlockByHeight(h)
	if err != nil || blk == nil {
		t.Fatalf("read seeded block %d: %v", h, err)
	}
	return blk.Header
}
