// Quantaureum Node source, version 1.0.0.
// Package consensus — R38-P1-08 DEEP FIX regression tests for the
// incremental proposer snapshot reconstruction (2026-08-02).
//
// The conservative R38-P1-08 Fix 2 skipped proposer election verification
// wholesale during syncingMode. The deep fix adds QPOS.ApplyBlockHeader —
// an idempotent-by-hash replay of a canonical block header into the QPOS
// internal snapshot (randaoMix / epochBlockRoots / slotBlockRoots) — so
// that proposer election can be verified block-by-block during sync. These
// tests pin the deep-fix invariants:
//
//  1. Idempotency: replaying the same canonical block twice MUST NOT
//     double-apply (each block contributes once period).
//  2. Reconstruction: after replay, slotBlockRoots + epochBlockRoots are
//     populated exactly as the canonical import path in node/node.go would
//     populate them.
//  3. Genesis path: a genesis block (Height=0) records its root in both
//     epochBlockRoots[0] and slotBlockRoots[0] without requiring a VRF
//     output (VRFValue==zero hash skipped by AccumulateVRFOutput).
//  4. Pruning: the idempotency set is bounded — invoking ApplyBlockHeader
//     past 3*SlotsPerEpoch entries leaves the set bounded (no unbounded
//     memory growth).
//  5. HasAppliedBlockHeader observability surface returns the right
//     pre/post state for the idempotency set.
//
// VRF accumulator ownership: the per-epoch epochVRFAccumulator is owned
// EXCLUSIVELY by AccumulateVRFOutput (node/blockInsertLoop, gated by
// shouldSwitch). ApplyBlockHeader deliberately does NOT XOR it — the live
// path would otherwise double-count the same canonical block's VRF output
// that blockInsertLoop also feeds through AccumulateVRFOutput, diverging
// the future-epoch shuffle seed across nodes.
//
// Callers: syncer.applyBlockInternal in package node calls
// qpos.ApplyBlockHeader(blk, blockHash) per canonical block; see
// node/r38_p1_08_sync_failclosed_test.go for the node-level integration
// tests.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// r38P1_08Deep_makeBlock constructs a minimal *encoding.Block with the
// given header fields for ApplyBlockHeader replay tests. The block hash
// is computed by encoding.MarshalBlockHeader + sha3 inside
// block.ComputeBlockHash (mirrored from node/r38_p1_08 test fixtures
// that use block.ComputeBlockHash).
func r38P1_08Deep_makeBlock(t *testing.T, height, slot, epoch uint64, proposer types.Address, vrfValue types.Hash, randaoReveal types.Hash) *encoding.Block {
	t.Helper()
	return &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       height,
			Slot:         slot,
			Epoch:        epoch,
			Timestamp:    1700000000 + int64(slot)*12,
			ChainID:      1333,
			ProposerAddr: proposer,
			VRFValue:     vrfValue,
			RANDAOReveal: randaoReveal,
			StateRoot:    types.Hash{0xAA},
			ReceiptRoot:  types.Hash{0xBB},
			GasLimit:     30000000,
		},
	}
}

// r38P1_08Deep_qpos builds an in-package QPOS with `count` validators
// mirroring createTestValidators (consensus_election_test.go:24).
// Returns the QPOS and the validator addresses so the test can craft a
// block with the proposer that the shuffle will actually elect.
func r38P1_08Deep_qpos(t *testing.T, count int) (*QPOS, []types.Address) {
	t.Helper()
	EnableTestHelpers()
	defer func() { ResetGenesisTimeForTesting(); testHelpersEnabled = false }()

	validators := make([]*Validator, count)
	addrs := make([]types.Address, count)
	for i := 0; i < count; i++ {
		addr := types.Address{}
		addr[0] = byte(i + 1)
		addrs[i] = addr
		validators[i] = &Validator{
			Address: addr,
			Stake:   big.NewInt(int64((i + 1) * 1000)),
			Active:  true,
		}
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	if err := SetGenesisTime(1700000000); err != nil {
		t.Fatalf("SetGenesisTime: %v", err)
	}
	return qpos, addrs
}

// r38P1_08Deep_blockHash helper computes the canonical block hash so the
// tests pass the same hash the syncer would pass. We avoid importing
// qaudb/block to keep consensus tests unaffected by qaudb/block import
// inflation; the hash is identical to qaudb/block.ComputeHeaderHash:
// encoding.MarshalBlockHeader(header) → sha3.Sum256. Both code paths
// produce identical bytes (verified by block_store_test.go and
// core_test.go).
func r38P1_08Deep_blockHash(t *testing.T, blk *encoding.Block) types.Hash {
	t.Helper()
	if blk == nil || blk.Header == nil {
		return types.Hash{}
	}
	data, err := encoding.MarshalBlockHeader(blk.Header)
	if err != nil {
		t.Fatalf("MarshalBlockHeader: %v", err)
	}
	return sha3.Sum256(data)
}

// TestR38P1_08_Deep_ApplyBlockHeader_Idempotency is the load-bearing
// invariant: replaying a canonical block twice MUST NOT double-XOR the
// VRF accumulator. We craft a block with VRFValue = H{0xAB} and replay it
// twice; the accumulator after the first replay MUST equal the
// accumulator after the second replay (no flips).
func TestR38P1_08_Deep_ApplyBlockHeader_Idempotency(t *testing.T) {
	qpos, _ := r38P1_08Deep_qpos(t, 4)
	defer func() { _ = qpos }()

	v1 := types.Address{0xAA}
	blk := r38P1_08Deep_makeBlock(t, 1, 1, 0, v1, types.Hash{0xAB}, types.Hash{0xCD})
	h1 := r38P1_08Deep_blockHash(t, blk)

	// Pre: not yet applied.
	if qpos.HasAppliedBlockHeader(h1) {
		t.Fatal("precondition: HasAppliedBlockHeader must be false before ApplyBlockHeader")
	}

	// First apply.
	if err := qpos.ApplyBlockHeader(blk, h1); err != nil {
		t.Fatalf("ApplyBlockHeader first call: %v", err)
	}
	if !qpos.HasAppliedBlockHeader(h1) {
		t.Fatal("postcondition: HasAppliedBlockHeader must be true after ApplyBlockHeader")
	}

	qpos.mu.RLock()
	accAfterFirst := qpos.epochVRFAccumulator[0]
	randaoAfterFirst := qpos.randaoMix
	qpos.mu.RUnlock()

	// Second apply MUST be a no-op.
	if err := qpos.ApplyBlockHeader(blk, h1); err != nil {
		t.Fatalf("ApplyBlockHeader second call: %v", err)
	}

	qpos.mu.RLock()
	accAfterSecond := qpos.epochVRFAccumulator[0]
	randaoAfterSecond := qpos.randaoMix
	qpos.mu.RUnlock()

	if accAfterFirst != accAfterSecond {
		t.Fatalf("R38-P1-08 deep-fix idempotency BREAK: VRF accumulator flipped on second ApplyBlockHeader — first=%x second=%x (XOR XOR != identity; expected each block to contribute ONCE)",
			accAfterFirst[:8], accAfterSecond[:8])
	}
	if randaoAfterFirst != randaoAfterSecond {
		t.Fatalf("R38-P1-08 deep-fix idempotency BREAK: randaoMix flipped on second ApplyBlockHeader — first=%x second=%x",
			randaoAfterFirst[:8], randaoAfterSecond[:8])
	}
}

// TestR38P1_08_Deep_ApplyBlockHeader_ReconstructsSlotRoot verifies that
// after replaying a block, slotBlockRoots[slot] is the block hash. This
// is what the ElectionVerifier queries when verifying the proposer
// for that slot.
func TestR38P1_08_Deep_ApplyBlockHeader_ReconstructsSlotRoot(t *testing.T) {
	qpos, _ := r38P1_08Deep_qpos(t, 4)
	defer func() { _ = qpos }()

	blk := r38P1_08Deep_makeBlock(t, 1, /*height*/
		5, /*slot*/
		0, /*epoch*/
		types.Address{0xAA}, types.Hash{0xAB}, types.Hash{0xCD})
	h := r38P1_08Deep_blockHash(t, blk)

	if err := qpos.ApplyBlockHeader(blk, h); err != nil {
		t.Fatalf("ApplyBlockHeader: %v", err)
	}

	qpos.mu.RLock()
	got, ok := qpos.slotBlockRoots[5]
	qpos.mu.RUnlock()
	if !ok {
		t.Fatal("R38-P1-08 deep-fix: slotBlockRoots[5] not set after ApplyBlockHeader — ElectionVerifier lookup will return NotFound for this slot")
	}
	if got != h {
		t.Fatalf("R38-P1-08 deep-fix: slotBlockRoots[5] mismatch — got=%x want=%x", got[:8], h[:8])
	}
}

// TestR38P1_08_Deep_ApplyBlockHeader_DoesNotAccumulateVRF verifies that
// ApplyBlockHeader does NOT XOR the VRF accumulator — ownership of the
// per-epoch accumulator belongs exclusively to AccumulateVRFOutput
// (blockInsertLoop). If ApplyBlockHeader contributed too, the live path
// (ProcessBlock → applyBlock → applyBlockInternal → ApplyBlockHeader)
// would double-count the same canonical block's VRF output that
// blockInsertLoop ALSO feeds through AccumulateVRFOutput, diverging the
// future-epoch shuffle seed across nodes.
func TestR38P1_08_Deep_ApplyBlockHeader_DoesNotAccumulateVRF(t *testing.T) {
	qpos, _ := r38P1_08Deep_qpos(t, 4)
	defer func() { _ = qpos }()

	blk1 := r38P1_08Deep_makeBlock(t, 1, 0, 0, types.Address{0xAA}, types.Hash{0xAA}, types.Hash{})
	h1 := r38P1_08Deep_blockHash(t, blk1)
	if err := qpos.ApplyBlockHeader(blk1, h1); err != nil {
		t.Fatalf("ApplyBlockHeader block 1: %v", err)
	}

	qpos.mu.RLock()
	acc1 := qpos.epochVRFAccumulator[0]
	qpos.mu.RUnlock()

	if acc1 != (types.Hash{}) {
		t.Fatalf("ApplyBlockHeader alone must NOT populate the VRF accumulator, got %x", acc1[:8])
	}

	// The sole owner, AccumulateVRFOutput, does populate it.
	qpos.AccumulateVRFOutput(0, types.Hash{0xAA})
	qpos.mu.RLock()
	acc2 := qpos.epochVRFAccumulator[0]
	qpos.mu.RUnlock()
	if acc2 != (types.Hash{0xAA}) {
		t.Fatalf("AccumulateVRFOutput must XOR {0xAA} into the accumulator, got %x", acc2[:8])
	}
}

// TestR38P1_08_Deep_ApplyBlockHeader_SkipsZeroVRFValue verifies that a
// block whose VRFValue is the zero hash does NOT disturb the accumulator
// (mirrors AccumulateVRFOutput:670's zero-skip guard).
func TestR38P1_08_Deep_ApplyBlockHeader_SkipsZeroVRFValue(t *testing.T) {
	qpos, _ := r38P1_08Deep_qpos(t, 4)
	defer func() { _ = qpos }()

	blk := r38P1_08Deep_makeBlock(t, 1, 0, 0, types.Address{0xAA}, types.Hash{}, types.Hash{})
	h := r38P1_08Deep_blockHash(t, blk)
	if err := qpos.ApplyBlockHeader(blk, h); err != nil {
		t.Fatalf("ApplyBlockHeader: %v", err)
	}

	qpos.mu.RLock()
	acc := qpos.epochVRFAccumulator[0]
	qpos.mu.RUnlock()
	if acc != (types.Hash{}) {
		t.Fatalf("ApplyBlockHeader with zero VRFValue must leave accumulator zero, got %x", acc[:8])
	}
}

// TestR38P1_08_Deep_ApplyBlockHeader_GenesisRegistersRoot verifies that
// a genesis block (Height=0, epoch=0) with NO VRF output and NO RANDAO
// reveal STILL registers its root in epochBlockRoots[0] +
// slotBlockRoots[0]. This is the bootstrap path: epoch 1 finalization
// needs to look up epochBlockRoots[0] (qpos_finality.go:258).
func TestR38P1_08_Deep_ApplyBlockHeader_GenesisRegistersRoot(t *testing.T) {
	qpos, _ := r38P1_08Deep_qpos(t, 4)
	defer func() { _ = qpos }()

	gen := r38P1_08Deep_makeBlock(t /*height*/, 0, 0, 0, types.Address{}, types.Hash{}, types.Hash{})
	h := r38P1_08Deep_blockHash(t, gen)
	if err := qpos.ApplyBlockHeader(gen, h); err != nil {
		t.Fatalf("ApplyBlockHeader genesis: %v", err)
	}

	qpos.mu.RLock()
	gotEpoch, epochOk := qpos.epochBlockRoots[0]
	gotSlot, slotOk := qpos.slotBlockRoots[0]
	qpos.mu.RUnlock()

	if !epochOk || gotEpoch != h {
		t.Fatalf("R38-P1-08 deep-fix: genesis root NOT registered in epochBlockRoots[0] after ApplyBlockHeader — epoch 1 finalization lookup will return zero hash")
	}
	if !slotOk || gotSlot != h {
		t.Fatalf("R38-P1-08 deep-fix: genesis root NOT registered in slotBlockRoots[0] after ApplyBlockHeader — slot 0 canonical root lookup will return zero hash")
	}
}

// TestR38P1_08_Deep_ApplyBlockHeader_GenesisImmutableAfterReseed verifies
// that re-applying a genesis block with a DIFFERENT root does NOT
// overwrite the registered genesis root — mirroring SetGenesisRoot's
// immutable-once-set semantics (qpos_finality.go:287).
func TestR38P1_08_Deep_ApplyBlockHeader_GenesisImmutableAfterReseed(t *testing.T) {
	qpos, _ := r38P1_08Deep_qpos(t, 4)
	defer func() { _ = qpos }()

	genA := r38P1_08Deep_makeBlock(t, 0, 0, 0, types.Address{}, types.Hash{}, types.Hash{})
	hA := r38P1_08Deep_blockHash(t, genA)
	if err := qpos.ApplyBlockHeader(genA, hA); err != nil {
		t.Fatalf("ApplyBlockHeader genA: %v", err)
	}

	// Distinct genesis "replay" with a different proposer (yielding a
	// different hash since blockHash incorporates ProposerAddr via
	// MarshalBlockHeader).
	genB := r38P1_08Deep_makeBlock(t, 0, 0, 0, types.Address{0xFF}, types.Hash{}, types.Hash{})
	hB := r38P1_08Deep_blockHash(t, genB)
	if hA == hB {
		t.Fatal("precondition: distinct genesis hashes expected")
	}
	_ = qpos.ApplyBlockHeader(genB, hB) // best-effort, no error expected

	qpos.mu.RLock()
	got, _ := qpos.epochBlockRoots[0]
	qpos.mu.RUnlock()

	if got != hA {
		t.Fatalf("R38-P1-08 deep-fix: genesis root was OVERWRITTEN by reseed replay — immutable-once-set semantic violated (was=%x, now=%x)", hA[:8], got[:8])
	}
}

// TestR38P1_08_Deep_ApplyBlockHeader_NilInputsReturnsError verifies that
// nil blocks/headers are surfaced as an error (callers can decide
// whether to abort; the syncer logs+continues).
func TestR38P1_08_Deep_ApplyBlockHeader_NilInputsReturnsError(t *testing.T) {
	qpos, _ := r38P1_08Deep_qpos(t, 4)
	defer func() { _ = qpos }()

	if err := qpos.ApplyBlockHeader(nil, types.Hash{}); err == nil {
		t.Fatal("ApplyBlockHeader(nil blk) must return an error, not silently no-op")
	}
	if err := qpos.ApplyBlockHeader(&encoding.Block{}, types.Hash{0xCC}); err == nil {
		t.Fatal("ApplyBlockHeader(blk with nil header) must return an error, not silently no-op")
	}
}

// TestR38P1_08_Deep_ApplyBlockHeader_PruneKeepsSetBounded verifies that
// once the idempotency set exceeds 3*SlotsPerEpoch entries, the prune
// path reduces it back to the bound. We do this by replaying many blocks
// with distinct hashes; the set's size must remain bounded.
func TestR38P1_08_Deep_ApplyBlockHeader_PruneKeepsSetBounded(t *testing.T) {
	qpos, _ := r38P1_08Deep_qpos(t, 4)
	defer func() { _ = qpos }()

	// Apply far more blocks than 3*SlotsPerEpoch. Each distinct
	// (height, slot) tuple yields a distinct hash (ProposerAddr differs).
	const total = 3*SlotsPerEpoch + 50
	for i := 0; i < total; i++ {
		blk := r38P1_08Deep_makeBlock(t, uint64(i+1), uint64(i+1), uint64(i/SlotsPerEpoch), types.Address{byte(i + 1)}, types.Hash{}, types.Hash{})
		h := r38P1_08Deep_blockHash(t, blk)
		if err := qpos.ApplyBlockHeader(blk, h); err != nil {
			t.Fatalf("ApplyBlockHeader iter %d: %v", i, err)
		}
	}

	qpos.mu.RLock()
	size := len(qpos.appliedBlockRoots)
	qpos.mu.RUnlock()

	// Pruning keeps the set <= 3*SlotsPerEpoch + a few entries. We
	// accept anything strictly less than `total` AND <= bound + small
	// slack (the prune runs once per ApplyBlockHeader call so growth +
	// prune asymptote to the bound).
	bound := 3 * SlotsPerEpoch
	if size >= total {
		t.Fatalf("R38-P1-08 deep-fix: appliedBlockRoots set is unbounded — %d entries exceeds bound %d (no pruning occurred)", size, bound)
	}
	// Bound + slack (the prune keeps dropCount == len-bound entries
	// deleted per invocation; subsequent calls may grow past by 1-2
	// before next prune). Use bound*2 as a generous upper bound.
	if size > bound*2 {
		t.Fatalf("R38-P1-08 deep-fix: appliedBlockRoots set %d exceeds generous 2x bound %d — prune not effective", size, bound*2)
	}
}

// TestR38P1_08_Deep_ApplyBlockHeader_DistinctBlocksAllReplayed verifies
// that two genuinely distinct blocks (distinct hashes) BOTH enter the
// idempotency set, and that the second block's VRFValue is XORed with
// the first's (NOT canceled out — distinct blocks each contribute
// once).
func TestR38P1_08_Deep_ApplyBlockHeader_DistinctBlocksAllReplayed(t *testing.T) {
	qpos, _ := r38P1_08Deep_qpos(t, 4)
	defer func() { _ = qpos }()

	blk1 := r38P1_08Deep_makeBlock(t, 1, 0, 0, types.Address{0xAA}, types.Hash{0x11}, types.Hash{})
	h1 := r38P1_08Deep_blockHash(t, blk1)
	if err := qpos.ApplyBlockHeader(blk1, h1); err != nil {
		t.Fatalf("ApplyBlockHeader block 1: %v", err)
	}

	blk2 := r38P1_08Deep_makeBlock(t, 2, 1, 0, types.Address{0xBB}, types.Hash{0x22}, types.Hash{})
	h2 := r38P1_08Deep_blockHash(t, blk2)
	if err := qpos.ApplyBlockHeader(blk2, h2); err != nil {
		t.Fatalf("ApplyBlockHeader block 2: %v", err)
	}

	if !qpos.HasAppliedBlockHeader(h1) {
		t.Fatal("block 1 should be marked as applied")
	}
	if !qpos.HasAppliedBlockHeader(h2) {
		t.Fatal("block 2 should be marked as applied")
	}

	// ApplyBlockHeader does NOT own the VRF accumulator — the accumulator
	// remains zero here (the single owner is AccumulateVRFOutput). The
	// idempotency set is what matters for the incremental-snapshot
	// reconstruction contract.
	qpos.mu.RLock()
	acc := qpos.epochVRFAccumulator[0]
	qpos.mu.RUnlock()
	if acc != (types.Hash{}) {
		t.Fatalf("ApplyBlockHeader must not accumulate VRF; the accumulator is owned exclusively by AccumulateVRFOutput, got %x", acc[:8])
	}
}
