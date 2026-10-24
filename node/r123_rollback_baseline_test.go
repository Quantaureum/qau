// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// R123-ROLLBACK-EATS-BASELINE (2026-10-24): RollbackToHeight(H) is
// >=-INCLUSIVE — it restores the post-(H-1) state and rewinds lch to H-1
// (see its own doc comment in state_db.go). rebuildState's explicit
// "stateDB lch ahead of verified baseline" rollback called
// RollbackToHeight(baseline) but then re-applied from baseline+1 — so the
// baseline block's own state effects were undone and NEVER re-applied.
//
// Empty baselines hide the bug (no state effects). An epoch-BOUNDARY baseline
// block loses its census-derived rewards forever: a production RPC node hit
// exactly this shape (frozen state-root mismatch immediately after a rescue
// rollback onto a boundary block; wrong balances until a state transplant).
//
// The sequence below reproduces that exact shape against a real Syncer:
// boundary block H carries a census that credits validator 0; block H+1 is
// committed to state but not yet verified (the live-ahead-of-verified tip
// condition); the rescue rebuildState then runs.
func TestRebuildState_RollbackMustNotEatBaselineEffects(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	stateDB := state.NewStateDB()

	// One validator with genesis-scale stake so census rewards are non-zero.
	valAddr := types.Address{}
	valAddr[0] = 0x60
	stake, ok := new(big.Int).SetString("6000000000000000000000", 10)
	if !ok {
		t.Fatal("stake literal")
	}
	val := &consensus.Validator{
		Address: valAddr,
		Stake:   stake,
		Active:  true,
	}

	vs, err := consensus.NewValidatorSet([]*consensus.Validator{val})
	if err != nil {
		t.Fatalf("validator set: %v", err)
	}
	qpos, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("qpos: %v", err)
	}

	// Block 1: epoch-boundary block (slot 64 = epoch 2 start, prevEpoch 1)
	// with a census that attests validator 0 for a prev-epoch slot.
	prevSlot := uint64(33) // inside epoch 1 (slots 32..63)
	census := consensus.SerializeAttestationCensus(
		[]*consensus.Attestation{{
			Slot:           prevSlot,
			ValidatorIndex: 0,
		}},
		map[uint64]int{prevSlot: 0},
	)
	if len(census) == 0 {
		t.Fatal("census must serialize non-empty")
	}

	putBlockCensus(t, bs, 1, 64, census, types.Hash{0x01})
	putBlockCensus(t, bs, 2, 65, nil, types.Hash{0x02})

	s := NewSyncer(nil, bs, stateDB, nil, 1668)
	defer s.Stop()
	s.SetQPOS(qpos)

	// Live processing of the boundary block: census rewards credited to
	// validator 0, lch=1, beforeImages[1] populated (dirty accounts).
	blk1, err := bs.GetBlockByHeight(1)
	if err != nil || blk1 == nil {
		t.Fatalf("read block 1: %v", err)
	}
	if err := s.applyBlockInternal(blk1, true); err != nil {
		t.Fatalf("apply block 1: %v", err)
	}
	balanceAfterBoundary := stateDB.GetBalance(valAddr)
	if balanceAfterBoundary.Sign() <= 0 {
		t.Fatalf("precondition: boundary census must credit validator 0, got %s", balanceAfterBoundary)
	}

	// Verified advances to 1 (the block was live-verified)...
	s.mu.Lock()
	s.stateVerifiedHeight = 1
	s.currentHeight = 2
	s.mu.Unlock()

	// ...then the next (empty) block commits to state BEFORE verification
	// catches up — the tip condition the R115B rescue rebuild targets.
	blk2, err := bs.GetBlockByHeight(2)
	if err != nil || blk2 == nil {
		t.Fatalf("read block 2: %v", err)
	}
	if err := s.applyBlockInternal(blk2, true); err != nil {
		t.Fatalf("apply block 2: %v", err)
	}
	if stateDB.LastCommittedHeight() != 2 {
		t.Fatalf("precondition: lch must be 2, got %d", stateDB.LastCommittedHeight())
	}

	// The rescue rebuild: verified=1, lch=2 → baseline=1 → explicit
	// RollbackToHeight(1) → re-apply. The baseline block's census rewards
	// MUST survive this cycle.
	s.rebuildState(1, 2)

	after := stateDB.GetBalance(valAddr)
	if after.Cmp(balanceAfterBoundary) != 0 {
		t.Fatalf("R123-ROLLBACK-EATS-BASELINE: rescue rebuild lost the boundary block's effects: "+
			"balance before=%s after=%s (delta=%s) — RollbackToHeight(baseline) is >=-inclusive, "+
			"the re-apply range must include the baseline block itself",
			balanceAfterBoundary, after, new(big.Int).Sub(balanceAfterBoundary, after))
	}
}

// putBlockCensus stores a canonical block at height h with the given slot and
// census bytes (variant of the r114 harness's putBlock for boundary blocks).
func putBlockCensus(t *testing.T, bs *block.BlockStore, h, slot uint64, census []byte, stateRoot types.Hash) {
	t.Helper()
	hdr := &encoding.BlockHeader{
		Version:      1,
		Height:       h,
		Epoch:        slot / consensus.SlotsPerEpoch,
		Slot:         slot,
		StateRoot:    stateRoot,
		Attestations: census,
	}
	if h > 1 {
		parent := blockHeader(t, bs, h-1)
		hdr.ParentHash = block.ComputeHeaderHash(parent)
	}
	blk := &encoding.Block{Header: hdr, Transactions: nil}
	if err := bs.PutBlockWithIndex(blk); err != nil {
		t.Fatalf("seed block %d: %v", h, err)
	}
}
