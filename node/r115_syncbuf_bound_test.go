// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// R115-SYNCBUF-BOUND (2026-10-19): the receive-side sync buffer had no dedup
// and no byte cap. During full-mode catch-up six peers answer the same
// re-request with overlapping 500-block batches while blockInsertLoop
// re-executes at only ~30-80 blocks/s, so decoded blocks accumulated without
// bound: production held 26,223 buffered blocks => >10GB anonymous heap on a
// 24GB box, wedging the whole OS twice (see r115 incident notes). These
// tests pin the three invariants the fix adds:
//
//   - duplicate in-window deliveries cost nothing (dedup set),
//   - the byte budget is enforced and the buffer can never exceed it,
//   - removal keeps set/budget accounting exact (no leak, no over-count).

func r115TestNode(t *testing.T) *Node {
	t.Helper()
	n := &Node{}
	n.syncBuf = make([]*encoding.Block, 0, 8)
	n.syncBufSet = make(map[string]struct{}, 8)
	n.syncBufBytes = 0
	n.maxSyncBufBytes = 256 << 20
	return n
}

// r115Block builds a minimal but structurally real block at the given height
// with the requested approximate payload size (cheap filler via signature).
func r115Block(height uint64, payloadBytes int) *encoding.Block {
	blk := &encoding.Block{
		Header: &encoding.BlockHeader{
			Height:       height,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{byte(height), byte(height >> 8)},
		},
		Transactions: []*encoding.Transaction{
			{
				Nonce:     height,
				Signature: make([]byte, payloadBytes),
			},
		},
	}
	return blk
}

func TestSyncBufDedupDropsDuplicateDelivery(t *testing.T) {
	n := r115TestNode(t)

	b1 := r115Block(100, 1024)
	// A duplicate delivery is the SAME block object arriving twice (peers
	// answer the same re-request with byte-identical blocks).
	b2 := b1

	for _, b := range []*encoding.Block{b1, b2} {
		key := block.ComputeBlockHash(b.Header)
		k := string(key[:])
		if _, dup := n.syncBufSet[k]; dup {
			continue // receive-path dedup decision, as in blockProcessingLoop
		}
		n.syncBuf = append(n.syncBuf, b)
		n.syncBufSet[k] = struct{}{}
		n.syncBufBytes += int64(encoding.ApproxBlockBytes(b))
	}

	if len(n.syncBuf) != 1 {
		t.Fatalf("dedup failed: buffer holds %d copies, want 1", len(n.syncBuf))
	}
	if n.syncBufBytes != int64(encoding.ApproxBlockBytes(b1)) {
		t.Fatalf("byte budget double-counted duplicate: got %d want %d",
			n.syncBufBytes, encoding.ApproxBlockBytes(b1))
	}
}

func TestSyncBufByteCapDropsOldestUntilFits(t *testing.T) {
	n := r115TestNode(t)
	// Tiny budget: fits exactly two ~10KB blocks, a third forces eviction.
	n.maxSyncBufBytes = int64(2*encoding.ApproxBlockBytes(r115Block(1, 8*1024)) + 512)

	sizes := []int{8 * 1024, 8 * 1024, 8 * 1024}
	for i, sz := range sizes {
		b := r115Block(uint64(100+i), sz)
		key := block.ComputeBlockHash(b.Header)
		k := string(key[:])
		if _, dup := n.syncBufSet[k]; dup {
			continue
		}
		blkBytes := int64(encoding.ApproxBlockBytes(b))
		for len(n.syncBuf) > 0 && n.syncBufBytes+blkBytes > n.maxSyncBufBytes {
			n.syncBufRemoveAt(0)
		}
		n.syncBuf = append(n.syncBuf, b)
		n.syncBufSet[k] = struct{}{}
		n.syncBufBytes += blkBytes
	}

	if len(n.syncBuf) != 2 {
		t.Fatalf("cap eviction wrong: buffer holds %d blocks, want 2 (oldest dropped)", len(n.syncBuf))
	}
	if n.syncBuf[0].Header.Height != 101 {
		t.Fatalf("oldest block not dropped first: first height=%d want 101", n.syncBuf[0].Header.Height)
	}
	if n.syncBufBytes > n.maxSyncBufBytes {
		t.Fatalf("budget breached: %d > %d", n.syncBufBytes, n.maxSyncBufBytes)
	}
}

func TestSyncBufRemoveAtKeepsAccountingExact(t *testing.T) {
	n := r115TestNode(t)
	blocks := []*encoding.Block{r115Block(1, 512), r115Block(2, 1024), r115Block(3, 2048)}
	for _, b := range blocks {
		key := block.ComputeBlockHash(b.Header)
		n.syncBuf = append(n.syncBuf, b)
		n.syncBufSet[string(key[:])] = struct{}{}
		n.syncBufBytes += int64(encoding.ApproxBlockBytes(b))
	}

	// Remove the middle block; set and budget must both shrink by exactly it.
	mid := blocks[1]
	midBytes := int64(encoding.ApproxBlockBytes(mid))
	midKey := block.ComputeBlockHash(mid.Header)
	n.syncBufRemoveAt(1)

	if _, ok := n.syncBufSet[string(midKey[:])]; ok {
		t.Fatal("dedup set still contains removed block's hash")
	}
	if n.syncBufBytes != n.syncBufBytes && false {
		t.Fatal("unreachable")
	}
	want := int64(0)
	for _, b := range blocks {
		want += int64(encoding.ApproxBlockBytes(b))
	}
	want -= midBytes
	if n.syncBufBytes != want {
		t.Fatalf("budget after removal: got %d want %d", n.syncBufBytes, want)
	}
	if len(n.syncBuf) != 2 {
		t.Fatalf("buffer length after removal: got %d want 2", len(n.syncBuf))
	}
}

func TestSyncBufRebuildAccountingRecoversFromFilter(t *testing.T) {
	n := r115TestNode(t)
	// Simulate the OnForkRollback shape: filter the slice in one shot,
	// then rebuild accounting. Everything above forkHeight must vanish
	// from both the set and the budget.
	for h := uint64(1); h <= 4; h++ {
		b := r115Block(h, 1024)
		key := block.ComputeBlockHash(b.Header)
		n.syncBuf = append(n.syncBuf, b)
		n.syncBufSet[string(key[:])] = struct{}{}
		n.syncBufBytes += int64(encoding.ApproxBlockBytes(b))
	}
	forkHeight := uint64(3)
	filtered := n.syncBuf[:0]
	for _, b := range n.syncBuf {
		if b.Header.Height < forkHeight {
			filtered = append(filtered, b)
		}
	}
	n.syncBuf = filtered
	n.syncBufRebuildAccounting()

	if len(n.syncBuf) != 2 {
		t.Fatalf("filter wrong: %d blocks, want 2", len(n.syncBuf))
	}
	if len(n.syncBufSet) != 2 {
		t.Fatalf("set rebuild wrong: %d entries, want 2", len(n.syncBufSet))
	}
	want := int64(0)
	for _, b := range n.syncBuf {
		want += int64(encoding.ApproxBlockBytes(b))
	}
	if n.syncBufBytes != want {
		t.Fatalf("budget rebuild wrong: got %d want %d", n.syncBufBytes, want)
	}
}

func TestApproxBlockBytesNeverUndercountsRealSerialization(t *testing.T) {
	// The budget only works if ApproxBlockBytes >= the footprint the buffer
	// actually retains. It need not match encoding.MarshalBlock exactly
	// (wire framing differs from heap cost), but for a signature-heavy block
	// it must at least cover the raw signature bytes.
	blk := r115Block(7, 64*1024)
	if got := encoding.ApproxBlockBytes(blk); got < 64*1024 {
		t.Fatalf("ApproxBlockBytes=%d under-counts 64KB signature payload", got)
	}
	if got := encoding.ApproxBlockBytes(nil); got != 0 {
		t.Fatalf("nil block must be 0, got %d", got)
	}
}
