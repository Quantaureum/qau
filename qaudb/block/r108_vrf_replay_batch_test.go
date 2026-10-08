package block

import (
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R108-VRF-REPLAY-BATCH regression tests (2026-09-25): the R52 startup replay
// visits every canonical block and used to drive one PutVRFAccumulator fsync
// per block. It now buffers the per-epoch values and flushes them through
// PutVRFAccumulatorsBatch. These tests pin the property that matters for that
// swap: the batch API must be observationally identical to the per-epoch API —
// same layout, same zero-value rule, same last-write-wins semantics — so
// LoadVRFAccumulators cannot tell which one wrote the entries.

func TestR108_VRFBatch_SameLayoutAsPerEpochWrites(t *testing.T) {
	entries := []struct {
		epoch uint64
		acc   types.Hash
	}{
		{1621, types.Hash{0xaa}},
		{1622, types.Hash{0xbb}},
		{1623, types.Hash{0xcc}},
	}

	batchStore := NewBlockStore(db.NewMemDB())
	batchInput := make(map[uint64]types.Hash, len(entries))
	for _, e := range entries {
		batchInput[e.epoch] = e.acc
	}
	if err := batchStore.PutVRFAccumulatorsBatch(batchInput); err != nil {
		t.Fatalf("PutVRFAccumulatorsBatch: %v", err)
	}

	perEpochStore := NewBlockStore(db.NewMemDB())
	for _, e := range entries {
		if err := perEpochStore.PutVRFAccumulator(e.epoch, e.acc); err != nil {
			t.Fatalf("PutVRFAccumulator %d: %v", e.epoch, err)
		}
	}

	batchAccs, err := batchStore.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("LoadVRFAccumulators (batch): %v", err)
	}
	perEpochAccs, err := perEpochStore.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("LoadVRFAccumulators (per-epoch): %v", err)
	}
	if len(batchAccs) != len(perEpochAccs) {
		t.Fatalf("batch wrote %d checkpoint(s); per-epoch wrote %d", len(batchAccs), len(perEpochAccs))
	}
	for epoch, want := range perEpochAccs {
		if got := batchAccs[epoch]; got != want {
			t.Fatalf("acc[%d] = %v; want %v", epoch, got, want)
		}
	}
}

func TestR108_VRFBatch_EmptyAndZeroHashAreNoOps(t *testing.T) {
	bs := NewBlockStore(db.NewMemDB())

	if err := bs.PutVRFAccumulatorsBatch(nil); err != nil {
		t.Fatalf("nil map: %v", err)
	}
	if err := bs.PutVRFAccumulatorsBatch(map[uint64]types.Hash{}); err != nil {
		t.Fatalf("empty map: %v", err)
	}
	// A zero accumulator means "not yet populated"; persisting it would surface
	// as a fake checkpoint, exactly as guarded against in the per-epoch API.
	if err := bs.PutVRFAccumulatorsBatch(map[uint64]types.Hash{
		100: {},
		101: {0x01},
	}); err != nil {
		t.Fatalf("zero-hash entry: %v", err)
	}

	accs, err := bs.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("LoadVRFAccumulators: %v", err)
	}
	if len(accs) != 1 {
		t.Fatalf("len(accs) = %d; want 1 (zero hash must be skipped)", len(accs))
	}
	if accs[101] != (types.Hash{0x01}) {
		t.Fatalf("acc[101] = %v; want {0x01}", accs[101])
	}
	if _, ok := accs[100]; ok {
		t.Fatal("acc[100] persisted a zero accumulator")
	}
}

func TestR108_VRFBatch_LastWriteWinsAgainstExistingEntry(t *testing.T) {
	bs := NewBlockStore(db.NewMemDB())

	// The replay map holds the LAST on-chain value of an epoch, so the batch
	// flush must overwrite a stale checkpoint rather than be ignored.
	if err := bs.PutVRFAccumulator(2500, types.Hash{0x11}); err != nil {
		t.Fatalf("PutVRFAccumulator: %v", err)
	}
	if err := bs.PutVRFAccumulatorsBatch(map[uint64]types.Hash{2500: {0x22}}); err != nil {
		t.Fatalf("PutVRFAccumulatorsBatch: %v", err)
	}

	accs, err := bs.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("LoadVRFAccumulators: %v", err)
	}
	if accs[2500] != (types.Hash{0x22}) {
		t.Fatalf("acc[2500] = %v; want {0x22}", accs[2500])
	}
}
