// Quantaureum Node source, version 1.0.0.
// Package visor provides rollback tracking for qau-visor upgrades.
package visor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RollbackRecord tracks an upgrade attempt and its outcome.
type RollbackRecord struct {
	Timestamp    time.Time `json:"timestamp"`
	FromVersion  string    `json:"fromVersion"`
	ToVersion    string    `json:"toVersion"`
	Success      bool      `json:"success"`
	RolledBack   bool      `json:"rolledBack"`
	ErrorMessage string    `json:"errorMessage,omitempty"`
}

// RollbackTracker tracks upgrade history for rollback decisions.
type RollbackTracker struct {
	dataDir string
}

// NewRollbackTracker creates a new RollbackTracker.
func NewRollbackTracker(dataDir string) *RollbackTracker {
	return &RollbackTracker{dataDir: dataDir}
}

// Record records an upgrade attempt.
func (rt *RollbackTracker) Record(record *RollbackRecord) error {
	records, err := rt.load()
	if err != nil {
		records = []*RollbackRecord{}
	}

	records = append(records, record)

	// Keep only last 50 records
	if len(records) > 50 {
		records = records[len(records)-50:]
	}

	return rt.save(records)
}

// GetLastUpgrade returns the most recent upgrade record by timestamp.
func (rt *RollbackTracker) GetLastUpgrade() (*RollbackRecord, error) {
	records, err := rt.load()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no upgrade records found")
	}

	// Find the record with the most recent timestamp
	var latest *RollbackRecord
	for _, r := range records {
		if latest == nil || r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}

	return latest, nil
}

// ShouldAutoRollback determines if an automatic rollback should be triggered
// based on recent upgrade history and health check results.
//
// Auto-rollback is triggered when:
// 1. The last upgrade was within the last 5 minutes
// 2. The process has crashed more than 3 times since the upgrade
// 3. Health checks have been failing consistently
func (rt *RollbackTracker) ShouldAutoRollback(crashCount int, healthFailing bool) bool {
	last, err := rt.GetLastUpgrade()
	if err != nil {
		return false
	}

	// Only consider recent upgrades (within 5 minutes)
	if time.Since(last.Timestamp) > 5*time.Minute {
		return false
	}

	// If the upgrade succeeded but the process keeps crashing, rollback
	if last.Success && !last.RolledBack && crashCount >= 3 {
		return true
	}

	// If health checks are failing after a recent upgrade, rollback
	if last.Success && !last.RolledBack && healthFailing {
		return true
	}

	return false
}

func (rt *RollbackTracker) load() ([]*RollbackRecord, error) {
	path := filepath.Join(rt.dataDir, "visor_rollback_history.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var records []*RollbackRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}

	return records, nil
}

func (rt *RollbackTracker) save(records []*RollbackRecord) error {
	path := filepath.Join(rt.dataDir, "visor_rollback_history.json")
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600) // G306: rollback history, owner-only
}
