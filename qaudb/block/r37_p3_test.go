// Quantaureum Node source, version 1.0.0.
package block

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// r37MakeBlock builds a minimal valid block at the given height. seed
// distinguishes blocks at the same height (different VRFValue => different
// hash), which is needed for same-height overwrite scenarios.
func r37MakeBlock(height uint64, parent types.Hash, numTx int, seed byte) *encoding.Block {
	hdr := &encoding.BlockHeader{
		Version:    1,
		Height:     height,
		Timestamp:  int64(1_700_000_000 + height),
		ParentHash: parent,
		ChainID:    1668,
		VRFValue:   types.Hash{seed},
	}
	blk := &encoding.Block{Header: hdr}
	for i := 0; i < numTx; i++ {
		blk.Transactions = append(blk.Transactions, &encoding.Transaction{
			Version:   1,
			Nonce:     uint64(i),
			Value:     big.NewInt(int64(i)),
			GasLimit:  21000,
			GasPrice:  big.NewInt(1),
			ChainID:   1668,
			Signature: []byte{seed, byte(i), 0x01},
		})
	}
	return blk
}

func r37NumberKey(h uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, h)
	return append(numberPrefix, k...)
}

// TestR37_P3_01_PutBlock_IsLatestFromDBNotCache verifies that the isLatest
// decision is based on the authoritative DB latestBlockKey, not the
// in-memory cache. A cold-cache store (nil latestBlock) must not regress
// the chain tip when a lower block is stored.
func TestR37_P3_01_PutBlock_IsLatestFromDBNotCache(t *testing.T) {
	database := db.NewMemDB()
	bs1 := NewBlockStore(database)

	b1 := r37MakeBlock(1, types.Hash{}, 0, 0x01)
	if err := bs1.PutBlock(b1); err != nil {
		t.Fatalf("PutBlock h1: %v", err)
	}
	b5 := r37MakeBlock(5, ComputeBlockHash(b1), 0, 0x05)
	if err := bs1.PutBlock(b5); err != nil {
		t.Fatalf("PutBlock h5: %v", err)
	}

	// Cold-cache store over the same DB: in-memory latestBlock is nil, but
	// the DB latestBlockKey still points at height 5.
	bs2 := NewBlockStore(database)
	b3 := r37MakeBlock(3, ComputeBlockHash(b1), 0, 0x03)
	if err := bs2.PutBlock(b3); err != nil {
		t.Fatalf("PutBlock h3: %v", err)
	}

	latest, err := bs2.GetLatestBlock()
	if err != nil {
		t.Fatalf("GetLatestBlock: %v", err)
	}
	if latest.Header.Height != 5 {
		t.Fatalf("chain tip regressed on cold cache: got height %d, want 5", latest.Header.Height)
	}
}

// TestR37_P3_02_PutBlock_OverwriteTipSameHeight verifies the P3-CHAIN-INTEGRITY
// FIX (2026-08-07): PutBlock MUST refuse to overwrite a canonical block at the
// same height with a different hash. Silent overwriting breaks chain integrity
// (a child's ParentHash would no longer match its stored parent hash, causing
// downstream nodes to detect a false fork and stall forever).
//
// Legitimate reorgs must call DeleteBlocksFromHeight BEFORE PutBlock. This test
// also covers the two non-conflict paths:
//   - Same hash re-index (allowed, no-op)
//   - DeleteBlocksFromHeight + PutBlock (legitimate reorg, allowed)
func TestR37_P3_02_PutBlock_OverwriteTipSameHeight(t *testing.T) {
	bs := NewBlockStore(db.NewMemDB())

	parent := types.Hash{0x09}
	bA := r37MakeBlock(5, parent, 1, 0xAA)
	if err := bs.PutBlock(bA); err != nil {
		t.Fatalf("PutBlock A: %v", err)
	}
	txA := ComputeTransactionHash(bA.Transactions[0])

	// 1. Same height, DIFFERENT block → MUST be rejected as a fork conflict.
	bB := r37MakeBlock(5, parent, 1, 0xBB)
	err := bs.PutBlock(bB)
	if !errors.Is(err, ErrBlockConflict) {
		t.Fatalf("PutBlock B: expected ErrBlockConflict, got %v", err)
	}

	// The existing canonical block (bA) MUST remain the tip.
	latest, err := bs.GetLatestBlock()
	if err != nil {
		t.Fatalf("GetLatestBlock: %v", err)
	}
	if got, want := ComputeBlockHash(latest), ComputeBlockHash(bA); got != want {
		t.Fatalf("canonical block overwritten: latest=%x, want bA %x", got[:8], want[:8])
	}

	// The existing canonical block's tx MUST still resolve (not displaced).
	if _, err := bs.GetTransactionLocation(txA); err != nil {
		t.Fatalf("canonical tx location missing after rejected overwrite: %v", err)
	}
	// The rejected block's tx MUST NOT resolve (block B was never stored).
	txB := ComputeTransactionHash(bB.Transactions[0])
	if _, err := bs.GetTransactionLocation(txB); err == nil {
		t.Fatal("rejected block B tx resolvable — block was stored despite ErrBlockConflict")
	}

	// 2. Same hash re-index (legitimate re-index, MUST succeed as no-op).
	if err := bs.PutBlock(bA); err != nil {
		t.Fatalf("PutBlock A (re-index same hash): %v", err)
	}

	// 3. Legitimate reorg: DeleteBlocksFromHeight + PutBlock MUST succeed.
	// This is the canonical path for fork resolution, not silent overwrite.
	if _, err := bs.DeleteBlocksFromHeight(5); err != nil {
		t.Fatalf("DeleteBlocksFromHeight(5): %v", err)
	}
	if err := bs.PutBlock(bB); err != nil {
		t.Fatalf("PutBlock B after delete (legitimate reorg): %v", err)
	}
	latest, err = bs.GetLatestBlock()
	if err != nil {
		t.Fatalf("GetLatestBlock after reorg: %v", err)
	}
	if got, want := ComputeBlockHash(latest), ComputeBlockHash(bB); got != want {
		t.Fatalf("reorg tip mismatch: latest=%x, want bB %x", got[:8], want[:8])
	}
	// After legitimate reorg, bA's tx MUST be gone, bB's tx MUST resolve.
	if _, err := bs.GetTransactionLocation(txA); err == nil {
		t.Fatal("stale tx location from displaced tip still resolvable after reorg")
	}
	if _, err := bs.GetTransactionLocation(txB); err != nil {
		t.Fatalf("new tip tx location missing after reorg: %v", err)
	}
}

// TestR37_P3_03_SetLatestBlock_RejectsNilHeader verifies that a block with
// a nil Header is rejected without panicking and without polluting the
// in-memory cache / DB latest pointer.
func TestR37_P3_03_SetLatestBlock_RejectsNilHeader(t *testing.T) {
	bs := NewBlockStore(db.NewMemDB())
	b1 := r37MakeBlock(1, types.Hash{}, 0, 0x01)
	if err := bs.PutBlock(b1); err != nil {
		t.Fatalf("PutBlock: %v", err)
	}

	// Must not panic nor pollute the cache.
	bs.SetLatestBlock(&encoding.Block{Header: nil})

	latest, err := bs.GetLatestBlock()
	if err != nil {
		t.Fatalf("GetLatestBlock: %v", err)
	}
	if latest.Header.Height != 1 {
		t.Fatalf("cache polluted by nil-header block: got height %d, want 1", latest.Header.Height)
	}
}

// TestR37_P3_03_FindContinuousTip_CorruptDataNoPanic verifies the nil/corrupt
// header defense in the continuity scan: a corrupt record must stop the
// scan gracefully (tip stays at the last continuous height), not panic.
func TestR37_P3_03_FindContinuousTip_CorruptDataNoPanic(t *testing.T) {
	database := db.NewMemDB()
	bs := NewBlockStore(database)
	b1 := r37MakeBlock(1, types.Hash{}, 0, 0x01)
	if err := bs.PutBlock(b1); err != nil {
		t.Fatalf("PutBlock: %v", err)
	}

	// Inject a corrupt record at height 2: number mapping present, but the
	// header bytes are garbage that fails to decode.
	fakeHash := types.Hash{0x42}
	if err := database.Put(r37NumberKey(2), fakeHash[:]); err != nil {
		t.Fatalf("inject number mapping: %v", err)
	}
	if err := database.Put(append(headerPrefix, fakeHash[:]...), []byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatalf("inject corrupt header: %v", err)
	}

	if tip := bs.FindContinuousTip(); tip != 1 {
		t.Fatalf("FindContinuousTip with corrupt data: got %d, want 1", tip)
	}
}

// TestR37_P3_04_DeleteBlocksFromHeight_PartialFailureKeepsRealTip verifies
// that when deletion fails mid-loop (chain gap), the fixup points
// latestBlockKey at the real continuous tip instead of blindly rolling back
// to fromHeight-1 (which would orphan the surviving higher blocks).
func TestR37_P3_04_DeleteBlocksFromHeight_PartialFailureKeepsRealTip(t *testing.T) {
	database := db.NewMemDB()
	bs := NewBlockStore(database)

	parent := types.Hash{}
	for h := uint64(1); h <= 5; h++ {
		b := r37MakeBlock(h, parent, 0, byte(h))
		if err := bs.PutBlock(b); err != nil {
			t.Fatalf("PutBlock h%d: %v", h, err)
		}
		parent = ComputeBlockHash(b)
	}

	// Remove the height-4 number mapping to force a mid-loop deletion
	// failure (chain gap).
	if err := database.Delete(r37NumberKey(4)); err != nil {
		t.Fatalf("delete number mapping h4: %v", err)
	}

	count, err := bs.DeleteBlocksFromHeight(2)
	if err == nil {
		t.Fatal("expected deletion error for chain gap")
	}
	if count != 1 {
		t.Fatalf("deleted count = %d, want 1 (only h5)", count)
	}

	// The fixup must point latestBlockKey at the real continuous tip (h3),
	// NOT blindly roll back to fromHeight-1 (h1), which would orphan h2-h3.
	latest, lerr := bs.GetLatestBlock()
	if lerr != nil {
		t.Fatalf("GetLatestBlock: %v", lerr)
	}
	if latest.Header.Height != 3 {
		t.Fatalf("tip after partial deletion = %d, want 3 (real continuous tip)", latest.Header.Height)
	}
}

// TestR37_P3_05_DeleteBlock_MissingBlockDataLogs verifies that deleting a
// height whose block data is missing logs a warning (instead of silently
// skipping tx/receipt cleanup) and still removes the number mapping.
func TestR37_P3_05_DeleteBlock_MissingBlockDataLogs(t *testing.T) {
	database := db.NewMemDB()
	bs := NewBlockStore(database)

	fakeHash := types.Hash{0x77}
	if err := database.Put(r37NumberKey(7), fakeHash[:]); err != nil {
		t.Fatalf("inject number mapping: %v", err)
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	if err := bs.DeleteBlockAtHeight(7); err != nil {
		t.Fatalf("DeleteBlockAtHeight: %v", err)
	}
	if !strings.Contains(buf.String(), "block data missing") {
		t.Fatalf("expected missing-data warning in log, got: %q", buf.String())
	}
	// The height mapping must be removed despite the missing block data.
	if _, err := database.Get(r37NumberKey(7)); err == nil {
		t.Fatal("number mapping not cleaned up")
	}
}

// TestR37_P3_12_FindContinuousTip_HeaderOnlyReads verifies that the
// continuity scan reads only header records (not full blocks with
// transactions). Deleting the full block record while keeping the header
// must not affect the scan.
func TestR37_P3_12_FindContinuousTip_HeaderOnlyReads(t *testing.T) {
	database := db.NewMemDB()
	bs := NewBlockStore(database)

	parent := types.Hash{}
	var blocks []*encoding.Block
	for h := uint64(1); h <= 3; h++ {
		b := r37MakeBlock(h, parent, 2, byte(h)) // blocks WITH transactions
		if err := bs.PutBlock(b); err != nil {
			t.Fatalf("PutBlock h%d: %v", h, err)
		}
		parent = ComputeBlockHash(b)
		blocks = append(blocks, b)
	}

	// Delete the full block record at height 2 but keep the header record.
	// With the R37-P3-12 fix the scan must still reach h3 (the old code
	// read full blocks and broke at h2).
	hash2 := ComputeBlockHash(blocks[1])
	if err := database.Delete(append(blockPrefix, hash2[:]...)); err != nil {
		t.Fatalf("delete block data h2: %v", err)
	}
	if tip := bs.FindContinuousTip(); tip != 3 {
		t.Fatalf("FindContinuousTip = %d, want 3 (header-only scan)", tip)
	}
}
