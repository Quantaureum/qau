// Quantaureum Node source, version 1.0.0.
package block

import (
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R58-VRF-PERSIST regression tests (2026-08-18): per-epoch VRF accumulator
// checkpoints must round-trip through the block store and survive a restart,
// so a restarting node recovers the deterministic proposer schedule even if
// the R52 block replay is skipped or interrupted — geth-equivalent guarantee
// that proposer entropy is a recoverable function of the canonical chain.
//
// Without this persistence, a restart that skips or interrupts the R52 block
// replay can leave the epoch VRF accumulator empty. Local proposer selection
// can then diverge from the canonical schedule and cause otherwise valid
// blocks to be rejected as proposer mismatches.

func TestR58_VRFPersist_RoundTrip(t *testing.T) {
	database := db.NewMemDB()
	bs := NewBlockStore(database)

	if err := bs.PutVRFAccumulator(1621, types.Hash{0xaa}); err != nil {
		t.Fatalf("PutVRFAccumulator 1621: %v", err)
	}
	if err := bs.PutVRFAccumulator(1622, types.Hash{0xbb}); err != nil {
		t.Fatalf("PutVRFAccumulator 1622: %v", err)
	}

	accs, err := bs.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("LoadVRFAccumulators: %v", err)
	}
	if len(accs) != 2 {
		t.Fatalf("len(accs) = %d; want 2", len(accs))
	}
	if accs[1621] != (types.Hash{0xaa}) || accs[1622] != (types.Hash{0xbb}) {
		t.Fatalf("accs = {%v %v}; want {aa bb}", accs[1621], accs[1622])
	}
}

func TestR58_VRFPersist_ZeroHashNotStored(t *testing.T) {
	database := db.NewMemDB()
	bs := NewBlockStore(database)

	// A zero accumulator means "not yet populated" — it must not be persisted,
	// otherwise LoadVRFAccumulators would report a fake checkpoint.
	if err := bs.PutVRFAccumulator(100, types.Hash{}); err != nil {
		t.Fatalf("PutVRFAccumulator zero: %v", err)
	}
	accs, err := bs.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("LoadVRFAccumulators: %v", err)
	}
	if len(accs) != 0 {
		t.Fatalf("zero-hash accumulator was persisted; len(accs) = %d; want 0", len(accs))
	}
}

func TestR58_VRFPersist_SurvivesRestart(t *testing.T) {
	database := db.NewMemDB()
	bs1 := NewBlockStore(database)
	if err := bs1.PutVRFAccumulator(2000, types.Hash{0x01}); err != nil {
		t.Fatalf("PutVRFAccumulator: %v", err)
	}

	// Simulate a node restart: new BlockStore over the same underlying DB.
	bs2 := NewBlockStore(database)
	accs, err := bs2.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("LoadVRFAccumulators after restart: %v", err)
	}
	if accs[2000] != (types.Hash{0x01}) {
		t.Fatalf("acc[2000] after restart = %v; want {0x01}", accs[2000])
	}
}
