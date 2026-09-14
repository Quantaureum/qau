// Quantaureum Node source, version 1.0.0.
package block

import (
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// AUDIT-FULL C-3 FIX (2026-08-14): regression tests for the persistent
// sync-unvalidated marker. Symptom being fixed: the marker lived only in
// Syncer's in-memory map, so a node restart between ProcessBlock (sync
// path) and rebuildState silently promoted unvalidated blocks to fully
// validated. These tests verify the durable marker round-trips through
// the database, survives a "restart" (new BlockStore over the same DB),
// and is cleared when re-execution verifies the block.

func TestAuditFull_C3_MarkerRoundTrip(t *testing.T) {
	database := db.NewMemDB()
	bs := NewBlockStore(database)

	h1 := types.Hash{0x01}
	h2 := types.Hash{0x02}

	if err := bs.MarkBlockUnvalidated(h1, 100); err != nil {
		t.Fatalf("MarkBlockUnvalidated h1: %v", err)
	}
	if err := bs.MarkBlockUnvalidated(h2, 101); err != nil {
		t.Fatalf("MarkBlockUnvalidated h2: %v", err)
	}

	// Has must report both markers.
	if ok, err := bs.HasUnvalidatedMarker(h1); err != nil || !ok {
		t.Fatalf("HasUnvalidatedMarker h1 = %v, %v; want true, nil", ok, err)
	}
	if ok, err := bs.HasUnvalidatedMarker(h2); err != nil || !ok {
		t.Fatalf("HasUnvalidatedMarker h2 = %v, %v; want true, nil", ok, err)
	}

	// Load must return both entries with correct heights.
	markers, err := bs.LoadUnvalidatedMarkers()
	if err != nil {
		t.Fatalf("LoadUnvalidatedMarkers: %v", err)
	}
	if len(markers) != 2 {
		t.Fatalf("len(markers) = %d; want 2", len(markers))
	}
	if markers[h1] != 100 || markers[h2] != 101 {
		t.Fatalf("markers = {%v %v}; want {100 101}", markers[h1], markers[h2])
	}

	// Clear h1; only h2 remains.
	if err := bs.ClearBlockUnvalidated(h1); err != nil {
		t.Fatalf("ClearBlockUnvalidated h1: %v", err)
	}
	if ok, _ := bs.HasUnvalidatedMarker(h1); ok {
		t.Fatal("h1 still marked after clear")
	}
	markers, err = bs.LoadUnvalidatedMarkers()
	if err != nil {
		t.Fatalf("LoadUnvalidatedMarkers after clear: %v", err)
	}
	if len(markers) != 1 || markers[h2] != 101 {
		t.Fatalf("markers after clear = %v; want only h2@101", markers)
	}
}

func TestAuditFull_C3_MarkerSurvivesRestart(t *testing.T) {
	database := db.NewMemDB()
	bs1 := NewBlockStore(database)

	h := types.Hash{0xAB}
	if err := bs1.MarkBlockUnvalidated(h, 42); err != nil {
		t.Fatalf("MarkBlockUnvalidated: %v", err)
	}

	// Simulate a node restart: a fresh BlockStore over the same DB.
	bs2 := NewBlockStore(database)
	markers, err := bs2.LoadUnvalidatedMarkers()
	if err != nil {
		t.Fatalf("LoadUnvalidatedMarkers after restart: %v", err)
	}
	if len(markers) != 1 {
		t.Fatalf("len(markers) after restart = %d; want 1", len(markers))
	}
	if markers[h] != 42 {
		t.Fatalf("markers[h] = %d; want 42", markers[h])
	}

	// The restart-side clear must also be visible to a third instance.
	if err := bs2.ClearBlockUnvalidated(h); err != nil {
		t.Fatalf("ClearBlockUnvalidated: %v", err)
	}
	bs3 := NewBlockStore(database)
	if ok, _ := bs3.HasUnvalidatedMarker(h); ok {
		t.Fatal("marker survived a persisted clear")
	}
}

func TestAuditFull_C3_ZeroHashRejected(t *testing.T) {
	bs := NewBlockStore(db.NewMemDB())
	if err := bs.MarkBlockUnvalidated(types.Hash{}, 1); err == nil {
		t.Fatal("MarkBlockUnvalidated(zero hash) = nil; want error")
	}
}
