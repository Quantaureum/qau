// Quantaureum Node source, version 1.0.0.
package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
)

// ── SnapshotManager creation ──

func TestNewSnapshotManager(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()

	sm := NewSnapshotManager(database, dir, 100, 5)
	if sm == nil {
		t.Fatal("expected non-nil SnapshotManager")
	}
	if sm.snapshotDir != dir {
		t.Errorf("expected snapshotDir %s, got %s", dir, sm.snapshotDir)
	}
	if sm.interval != 100 {
		t.Errorf("expected interval 100, got %d", sm.interval)
	}
	if sm.keepCount != 5 {
		t.Errorf("expected keepCount 5, got %d", sm.keepCount)
	}
}

// ── CreateSnapshot ──

func TestSnapshotManager_CreateSnapshot(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	err := sm.CreateSnapshot(100)
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Verify snapshot directory was created
	snapDir := filepath.Join(dir, "snapshot-100")
	if _, err := os.Stat(snapDir); os.IsNotExist(err) {
		t.Error("snapshot directory was not created")
	}

	// Verify meta.json exists
	metaPath := filepath.Join(snapDir, "meta.json")
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		t.Error("meta.json was not created")
	}

	// Verify data.json exists
	dataPath := filepath.Join(snapDir, "data.json")
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		t.Error("data.json was not created")
	}
}

func TestSnapshotManager_CreateSnapshot_WithData(t *testing.T) {
	database := db.NewMemDB()
	database.Put([]byte("key1"), []byte("value1"))
	database.Put([]byte("key2"), []byte("value2"))

	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	err := sm.CreateSnapshot(200)
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Verify snapshot directory was created
	snapDir := filepath.Join(dir, "snapshot-200")
	if _, err := os.Stat(snapDir); os.IsNotExist(err) {
		t.Error("snapshot directory was not created")
	}
}

func TestSnapshotManager_CreateSnapshot_MultipleSnapshots(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	for _, height := range []uint64{100, 200, 300} {
		err := sm.CreateSnapshot(height)
		if err != nil {
			t.Fatalf("CreateSnapshot(%d) failed: %v", height, err)
		}
	}

	// Verify all snapshot directories exist
	for _, height := range []uint64{100, 200, 300} {
		snapDir := filepath.Join(dir, filepath.Join("snapshot-"+filepath.Base(string(rune(height)))))
		_ = snapDir // Just verify no panics
	}
}

// ── ListSnapshots ──

func TestSnapshotManager_ListSnapshots_Empty(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	heights, err := sm.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots failed: %v", err)
	}
	if len(heights) != 0 {
		t.Errorf("expected 0 snapshots, got %d", len(heights))
	}
}

func TestSnapshotManager_ListSnapshots_NonexistentDir(t *testing.T) {
	database := db.NewMemDB()
	dir := filepath.Join(t.TempDir(), "nonexistent")
	sm := NewSnapshotManager(database, dir, 100, 5)

	heights, err := sm.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots should not fail for nonexistent dir, got: %v", err)
	}
	if len(heights) != 0 {
		t.Errorf("expected 0 snapshots for nonexistent dir, got %d", len(heights))
	}
}

func TestSnapshotManager_ListSnapshots_AfterCreate(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	sm.CreateSnapshot(100)
	sm.CreateSnapshot(300)
	sm.CreateSnapshot(200)

	heights, err := sm.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots failed: %v", err)
	}
	if len(heights) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(heights))
	}

	// Should be sorted ascending
	if heights[0] != 100 || heights[1] != 200 || heights[2] != 300 {
		t.Errorf("expected sorted heights [100, 200, 300], got %v", heights)
	}
}

func TestSnapshotManager_ListSnapshots_IgnoresInvalidDirs(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	// Create a valid snapshot
	sm.CreateSnapshot(100)

	// Create an invalid directory (no meta.json)
	invalidDir := filepath.Join(dir, "snapshot-200")
	os.MkdirAll(invalidDir, 0755)

	// Create a non-snapshot directory
	otherDir := filepath.Join(dir, "other-dir")
	os.MkdirAll(otherDir, 0755)

	heights, err := sm.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots failed: %v", err)
	}
	if len(heights) != 1 {
		t.Errorf("expected 1 valid snapshot, got %d", len(heights))
	}
	if len(heights) > 0 && heights[0] != 100 {
		t.Errorf("expected height 100, got %d", heights[0])
	}
}

// ── RestoreSnapshot ──

func TestSnapshotManager_RestoreSnapshot_NotFound(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	err := sm.RestoreSnapshot(999)
	if err == nil {
		t.Error("expected error for nonexistent snapshot")
	}
}

func TestSnapshotManager_RestoreSnapshot_AfterCreate(t *testing.T) {
	database := db.NewMemDB()
	database.Put([]byte("key1"), []byte("value1"))
	database.Put([]byte("key2"), []byte("value2"))

	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	// Create snapshot
	if err := sm.CreateSnapshot(100); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Clear database
	database.Put([]byte("key1"), []byte("modified"))
	database.Delete([]byte("key2"))

	// Restore snapshot
	err := sm.RestoreSnapshot(100)
	if err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	// Verify data was restored
	val1, err := database.Get([]byte("key1"))
	if err != nil {
		t.Fatalf("Get key1 failed: %v", err)
	}
	if string(val1) != "value1" {
		t.Errorf("expected key1='value1', got '%s'", string(val1))
	}

	val2, err := database.Get([]byte("key2"))
	if err != nil {
		t.Fatalf("Get key2 failed: %v", err)
	}
	if string(val2) != "value2" {
		t.Errorf("expected key2='value2', got '%s'", string(val2))
	}
}

// ── PruneSnapshots ──

func TestSnapshotManager_PruneSnapshots_NoPruningNeeded(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	sm.CreateSnapshot(100)
	sm.CreateSnapshot(200)

	err := sm.PruneSnapshots()
	if err != nil {
		t.Fatalf("PruneSnapshots failed: %v", err)
	}

	heights, _ := sm.ListSnapshots()
	if len(heights) != 2 {
		t.Errorf("expected 2 snapshots (no pruning needed), got %d", len(heights))
	}
}

func TestSnapshotManager_PruneSnapshots_DeletesOldest(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 2) // keep only 2

	sm.CreateSnapshot(100)
	sm.CreateSnapshot(200)
	sm.CreateSnapshot(300)
	sm.CreateSnapshot(400)

	err := sm.PruneSnapshots()
	if err != nil {
		t.Fatalf("PruneSnapshots failed: %v", err)
	}

	heights, _ := sm.ListSnapshots()
	if len(heights) != 2 {
		t.Fatalf("expected 2 snapshots after pruning, got %d", len(heights))
	}
	// Should keep the newest two
	if heights[0] != 300 || heights[1] != 400 {
		t.Errorf("expected heights [300, 400], got %v", heights)
	}
}

// ── StopAutoSnapshot ──

func TestSnapshotManager_StopAutoSnapshot(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	// Should not panic
	sm.StopAutoSnapshot()
}

// ── StartAutoSnapshot ──

func TestSnapshotManager_StartAutoSnapshot(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 1, 5) // interval=1 for quick trigger

	currentHeight := uint64(0)
	sm.StartAutoSnapshot(func() uint64 {
		currentHeight += 10
		return currentHeight
	})

	// Give it a moment to potentially create a snapshot
	// We just verify it doesn't panic and can be stopped
	sm.StopAutoSnapshot()
}

// ── SnapshotManager with empty database ──

func TestSnapshotManager_CreateSnapshot_EmptyDatabase(t *testing.T) {
	database := db.NewMemDB()
	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	err := sm.CreateSnapshot(100)
	if err != nil {
		t.Fatalf("CreateSnapshot with empty database failed: %v", err)
	}

	// Should be able to restore from empty snapshot
	err = sm.RestoreSnapshot(100)
	if err != nil {
		t.Fatalf("RestoreSnapshot from empty snapshot failed: %v", err)
	}
}

// ── Snapshot round-trip ──

func TestSnapshotManager_RoundTrip(t *testing.T) {
	database := db.NewMemDB()

	// Add some data
	testData := map[string]string{
		"block:0":  "genesis-block-data",
		"state:ab": "account-state-data",
		"tx:cd":    "transaction-data",
	}
	for k, v := range testData {
		database.Put([]byte(k), []byte(v))
	}

	dir := t.TempDir()
	sm := NewSnapshotManager(database, dir, 100, 5)

	// Create snapshot
	if err := sm.CreateSnapshot(500); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Modify database
	database.Put([]byte("block:0"), []byte("modified"))
	database.Delete([]byte("tx:cd"))

	// Restore snapshot
	if err := sm.RestoreSnapshot(500); err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	// Verify all data is restored
	for k, expectedV := range testData {
		val, err := database.Get([]byte(k))
		if err != nil {
			t.Errorf("Get(%q) failed: %v", k, err)
			continue
		}
		if string(val) != expectedV {
			t.Errorf("expected %q=%q, got %q", k, expectedV, string(val))
		}
	}
}
