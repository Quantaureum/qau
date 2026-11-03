// Quantaureum Node source, version 1.0.0.
package node

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// newAdapterTestStore builds a memdb-backed block store with a monotonic
// epoch labeling that mirrors production: epochs advance per SLOT while
// heights advance per PRODUCED block, so the epoch→height mapping is NOT
// height/32. Fixture: heights 0-2 carry epoch 0, heights 3-5 epoch 1,
// heights 6-7 epoch 2 (latest height 7).
func newAdapterTestStore(t *testing.T) *block.BlockStore {
	t.Helper()
	bs := block.NewBlockStore(db.NewMemDB())
	put := func(height, epoch uint64, acc byte) {
		blk := &encoding.Block{Header: &encoding.BlockHeader{
			Height:         height,
			Epoch:          epoch,
			VRFAccumulator: types.Hash{acc},
		}}
		if err := bs.PutBlock(blk); err != nil {
			t.Fatalf("PutBlock(h=%d): %v", height, err)
		}
	}
	acc := byte(0x10)
	for h := uint64(0); h <= 2; h++ {
		put(h, 0, acc)
		acc++
	}
	for h := uint64(3); h <= 5; h++ {
		put(h, 1, acc)
		acc++
	}
	for h := uint64(6); h <= 7; h++ {
		put(h, 2, acc)
		acc++
	}
	return bs
}

// TestRandomnessAdapterEpochRandomness verifies the binary-search epoch→
// height mapping: each epoch's randomness comes from the LAST block whose
// Header.Epoch equals the requested epoch.
func TestRandomnessAdapterEpochRandomness(t *testing.T) {
	a := &randomnessSourceAdapter{node: &Node{blockStore: newAdapterTestStore(t)}}

	cases := []struct {
		epoch   uint64
		wantH   uint64
		wantAcc byte
	}{
		{0, 2, 0x12}, // last epoch-0 block: height 2
		{1, 5, 0x15}, // last epoch-1 block: height 5
		{2, 7, 0x17}, // last epoch-2 block: height 7 (chain head)
	}
	for _, tc := range cases {
		rec, err := a.EpochRandomness(tc.epoch)
		if err != nil {
			t.Fatalf("EpochRandomness(%d): %v", tc.epoch, err)
		}
		if rec.BoundaryBlock != tc.wantH {
			t.Errorf("epoch %d: BoundaryBlock = %d, want %d", tc.epoch, rec.BoundaryBlock, tc.wantH)
		}
		if rec.Accumulator != (types.Hash{tc.wantAcc}) {
			t.Errorf("epoch %d: Accumulator = %x, want %02x", tc.epoch, rec.Accumulator[:1], tc.wantAcc)
		}
		if rec.Epoch != tc.epoch {
			t.Errorf("epoch %d: record label = %d", tc.epoch, rec.Epoch)
		}
		if rec.BlockHash == (types.Hash{}) {
			t.Errorf("epoch %d: BlockHash empty", tc.epoch)
		}
	}
}

// TestRandomnessAdapterUnsealedEpoch verifies an epoch beyond the chain head
// (or before any block carries it) fails closed with a descriptive error.
func TestRandomnessAdapterUnsealedEpoch(t *testing.T) {
	a := &randomnessSourceAdapter{node: &Node{blockStore: newAdapterTestStore(t)}}

	_, err := a.EpochRandomness(3)
	if err == nil {
		t.Fatal("epoch 3 is not sealed — expected error")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("error = %v, want unavailability", err)
	}
	// Overflow-range epoch must fail cleanly too.
	if _, err := a.EpochRandomness(^uint64(0)); err == nil {
		t.Error("expected error for overflow-range epoch")
	}
}

// TestRandomnessAdapterEmptyChain verifies fail-closed behavior before the
// chain has any blocks.
func TestRandomnessAdapterEmptyChain(t *testing.T) {
	a := &randomnessSourceAdapter{node: &Node{blockStore: block.NewBlockStore(db.NewMemDB())}}
	if _, err := a.EpochRandomness(0); err == nil {
		t.Fatal("empty chain must error, got nil")
	}
}

// TestRandomnessAdapterNoFinality verifies the finality accessor fails
// closed when the node has no block producer (pre-consensus startup).
func TestRandomnessAdapterNoFinality(t *testing.T) {
	a := &randomnessSourceAdapter{node: &Node{}}
	fe, ok := a.LatestFinalizedEpoch()
	if ok {
		t.Errorf("expected ok=false with nil block producer, got epoch %d", fe)
	}
}
