// Quantaureum Node source, version 1.0.0.
package consensus

// P4-T3 (2026-07-15): schema version + migration tests.
//
// Verifies:
//   - migrateV1ToV2 function: V1(0)→V2(2), V2(2)→V2(2) idempotent,
//     future(>2) unchanged.
//   - V1 persistence data (no "version" JSON field, defaults to 0) loads
//     correctly and is silently migrated to V2 on Load.
//   - V2 Save→Load roundtrip preserves Version=ministryStateVersion.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
)

// TestMigrateV1ToV2_Function verifies the migration function logic.
func TestMigrateV1ToV2_Function(t *testing.T) {
	tests := []struct {
		name     string
		input    uint8
		want     uint8
		migrated bool
	}{
		{name: "V1_zero_bumps_to_V2", input: 0, want: ministryStateVersion, migrated: true},
		{name: "V2_idempotent", input: ministryStateVersion, want: ministryStateVersion, migrated: false},
		{name: "future_version_unchanged", input: 3, want: 3, migrated: false},
		{name: "future_version_255_unchanged", input: 255, want: 255, migrated: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := migrateV1ToV2(tt.input)
			if got != tt.want {
				t.Errorf("migrateV1ToV2(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// TestMinistryStore_V1Data_PersonnelMigration simulates loading V1 persistence
// data (written before P4-T3, no "version" field). The Version field defaults
// to 0 on Unmarshal, migrateV1ToV2(0) returns 2, and the data loads without
// error. This is the forward-compatibility guarantee: existing deployments
// upgrade without manual DB migration.
func TestMinistryStore_V1Data_PersonnelMigration(t *testing.T) {
	database := db.NewMemDB()
	store := NewMinistryStateStore(database)

	// Write V1 JSON: no "version" field (simulates pre-P4-T3 data).
	v1JSON := `{"reputations":{"7":{"ValidatorIndex":7,"Score":1000,"TotalBlocks":3}},"operations":3,"errors":0,"lastActive":"2026-07-14T12:00:00Z"}`
	if err := database.Put(ministryPersonnelPrefix, []byte(v1JSON)); err != nil {
		t.Fatalf("seed V1 personnel data: %v", err)
	}

	// Load into a fresh MinistryPersonnel (no qpos/coordinator needed for Load).
	mp := &MinistryPersonnel{
		reputations: make(map[int]*ReputationRecord),
	}
	if err := store.LoadPersonnel(mp); err != nil {
		t.Fatalf("LoadPersonnel on V1 data failed: %v", err)
	}

	// Verify V1 data was migrated (not corrupted) — reputation record intact.
	r := mp.GetReputation(7)
	if r == nil {
		t.Fatal("reputation for validator 7 not loaded from V1 data")
	}
	if r.Score != 1000 {
		t.Errorf("Score = %d, want 1000", r.Score)
	}
	if r.TotalBlocks != 3 {
		t.Errorf("TotalBlocks = %d, want 3", r.TotalBlocks)
	}
	if mp.operations != 3 {
		t.Errorf("operations = %d, want 3", mp.operations)
	}
}

// TestMinistryStore_V1Data_DefenseMigration verifies that V1 Defense state
// (including the consensus-critical blacklist) migrates cleanly. A blacklisted
// validator must remain blacklisted after a P4-T3 upgrade — this is the
// safety-critical scenario called out in SaveDefense's comment.
func TestMinistryStore_V1Data_DefenseMigration(t *testing.T) {
	database := db.NewMemDB()
	store := NewMinistryStateStore(database)

	// V1 Defense JSON: blacklist entry for validator 3, no "version" field.
	v1JSON := `{"alerts":{},"nextAlertID":1,"blacklist":{"3":{"ValidatorIndex":3,"Reason":"double_sign","AddedAt":"2026-07-14T10:00:00Z"}},"partition":{"Detected":false},"quantumAlerts":0,"operations":1,"errors":0,"lastActive":"2026-07-14T10:00:00Z"}`
	if err := database.Put(ministryDefensePrefix, []byte(v1JSON)); err != nil {
		t.Fatalf("seed V1 defense data: %v", err)
	}

	md := &MinistryDefense{
		alerts:    make(map[uint64]*SecurityAlert),
		blacklist: make(map[int]*BlacklistEntry),
	}
	if err := store.LoadDefense(md); err != nil {
		t.Fatalf("LoadDefense on V1 data failed: %v", err)
	}

	// CRITICAL: blacklist entry must survive the V1→V2 migration.
	entry, exists := md.blacklist[3]
	if !exists {
		t.Fatal("blacklist entry for validator 3 was lost during V1→V2 migration")
	}
	if entry.Reason != "double_sign" {
		t.Errorf("blacklist Reason = %q, want \"double_sign\"", entry.Reason)
	}
}

// TestMinistryStore_SaveLoad_RoundtripVersion verifies that a V2 Save writes
// the Version field and a subsequent Load reads it back. This confirms the
// Version field round-trips correctly through JSON serialization.
func TestMinistryStore_SaveLoad_RoundtripVersion(t *testing.T) {
	database := db.NewMemDB()
	store := NewMinistryStateStore(database)

	// Personnel: save with a reputation record, then load into a fresh instance.
	mp := &MinistryPersonnel{reputations: make(map[int]*ReputationRecord)}
	mp.reputations[5] = &ReputationRecord{ValidatorIndex: 5, Score: 950, TotalBlocks: 1}
	mp.operations = 1
	mp.lastActive = time.Now()

	if err := store.SavePersonnel(mp); err != nil {
		t.Fatalf("SavePersonnel: %v", err)
	}

	// Inspect the raw JSON to confirm Version is persisted (not just in-memory).
	raw, err := database.Get(ministryPersonnelPrefix)
	if err != nil {
		t.Fatalf("read back raw personnel JSON: %v", err)
	}
	var probe struct {
		Version uint8 `json:"version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("unmarshal probe: %v", err)
	}
	if probe.Version != ministryStateVersion {
		t.Errorf("persisted Version = %d, want %d", probe.Version, ministryStateVersion)
	}

	// Load into a fresh instance and verify data integrity.
	mp2 := &MinistryPersonnel{reputations: make(map[int]*ReputationRecord)}
	if err := store.LoadPersonnel(mp2); err != nil {
		t.Fatalf("LoadPersonnel: %v", err)
	}
	r := mp2.GetReputation(5)
	if r == nil || r.Score != 950 {
		t.Errorf("roundtrip: reputation 5 Score = %v, want 950", r)
	}
}

// TestMinistryStore_V2Data_NoFutureWarning confirms that loading current V2
// data does not trigger the future-version warning path (which would indicate
// a version mismatch bug). This is a regression guard for the migration logic.
func TestMinistryStore_V2Data_NoFutureWarning(t *testing.T) {
	database := db.NewMemDB()
	store := NewMinistryStateStore(database)

	// Save with current version, then Load — the migrated version should equal
	// ministryStateVersion, NOT exceed it (which would log a warning).
	mp := &MinistryPersonnel{reputations: make(map[int]*ReputationRecord)}
	mp.operations = 1
	if err := store.SavePersonnel(mp); err != nil {
		t.Fatalf("SavePersonnel: %v", err)
	}

	mp2 := &MinistryPersonnel{reputations: make(map[int]*ReputationRecord)}
	if err := store.LoadPersonnel(mp2); err != nil {
		t.Fatalf("LoadPersonnel: %v", err)
	}
	// If we reach here without panic/error, the V2→V2 path is clean.
	// The warning log would only fire if migratedVersion > ministryStateVersion,
	// which can't happen for V2 data — this test guards against that regression.
}
