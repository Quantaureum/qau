// Quantaureum Node source, version 1.0.0.
package visor

import (
	"testing"
	"time"
)

func TestRollbackTracker_RecordAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewRollbackTracker(tmpDir)

	record := &RollbackRecord{
		Timestamp:   time.Now(),
		FromVersion: "v1.0.0",
		ToVersion:   "v1.1.0",
		Success:     true,
		RolledBack:  false,
	}

	if err := tracker.Record(record); err != nil {
		t.Fatalf("Record() failed: %v", err)
	}

	last, err := tracker.GetLastUpgrade()
	if err != nil {
		t.Fatalf("GetLastUpgrade() failed: %v", err)
	}

	if last.ToVersion != "v1.1.0" {
		t.Errorf("ToVersion = %q, want v1.1.0", last.ToVersion)
	}
	if !last.Success {
		t.Error("Success should be true")
	}
}

func TestRollbackTracker_ShouldAutoRollback_RecentUpgrade(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewRollbackTracker(tmpDir)

	// No records - should not rollback
	if tracker.ShouldAutoRollback(0, false) {
		t.Error("should not rollback with no records")
	}

	// Record a recent successful upgrade
	tracker.Record(&RollbackRecord{
		Timestamp:   time.Now(),
		FromVersion: "v1.0.0",
		ToVersion:   "v1.1.0",
		Success:     true,
		RolledBack:  false,
	})

	// 3+ crashes after upgrade - should rollback
	if !tracker.ShouldAutoRollback(3, false) {
		t.Error("should auto-rollback with 3+ crashes after recent upgrade")
	}

	// Health failing after upgrade - should rollback
	if !tracker.ShouldAutoRollback(0, true) {
		t.Error("should auto-rollback with health failing after recent upgrade")
	}

	// 2 crashes (below threshold) - should not rollback
	if tracker.ShouldAutoRollback(2, false) {
		t.Error("should not auto-rollback with only 2 crashes")
	}
}

func TestRollbackTracker_ShouldAutoRollback_OldUpgrade(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewRollbackTracker(tmpDir)

	// Record an old upgrade (6 minutes ago)
	tracker.Record(&RollbackRecord{
		Timestamp:   time.Now().Add(-6 * time.Minute),
		FromVersion: "v1.0.0",
		ToVersion:   "v1.1.0",
		Success:     true,
		RolledBack:  false,
	})

	// Should not rollback for old upgrade
	if tracker.ShouldAutoRollback(3, false) {
		t.Error("should not auto-rollback for old upgrade")
	}
}

func TestRollbackTracker_MultipleRecords(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewRollbackTracker(tmpDir)

	// Record multiple upgrades, newest first
	for i := 0; i < 5; i++ {
		tracker.Record(&RollbackRecord{
			Timestamp:   time.Now().Add(-time.Duration(i) * time.Minute),
			FromVersion: "v1.0.0",
			ToVersion:   "v1.1.0",
			Success:     true,
			RolledBack:  false,
		})
	}

	last, err := tracker.GetLastUpgrade()
	if err != nil {
		t.Fatalf("GetLastUpgrade() failed: %v", err)
	}

	// Should return the most recent record (within 1 minute of now)
	if time.Since(last.Timestamp) > time.Minute {
		t.Errorf("should return the most recent record, got timestamp %v", last.Timestamp)
	}
}
