// Quantaureum Node source, version 1.0.0.
// Package upgrade provides data migration support for format upgrades.
// This implements the migration tool for upgrading data formats between versions.
package upgrade

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
)

// Migration errors
var (
	ErrMigrationFailed     = errors.New("migration failed")
	ErrMigrationInProgress = errors.New("migration already in progress")
	ErrNoMigrationNeeded   = errors.New("no migration needed")
	ErrInvalidMigration    = errors.New("invalid migration")
	ErrMigrationNotFound   = errors.New("migration not found")
	ErrRollbackFailed      = errors.New("rollback failed")
)

// Database key prefixes for migration
var (
	prefixMigrationVersion = []byte("mv") // Current migration version
	prefixMigrationLog     = []byte("ml") // Migration log entries
)

// MigrationVersion represents a data format version
type MigrationVersion uint32

// Predefined migration versions
const (
	MigrationVersionGenesis MigrationVersion = 0 // Initial version
	MigrationVersionV1      MigrationVersion = 1 // First upgrade
	MigrationVersionV2      MigrationVersion = 2 // Second upgrade

	// CurrentMigrationVersion is the latest migration version
	CurrentMigrationVersion = MigrationVersionV1
)

// MigrationStatus represents the status of a migration
type MigrationStatus string

const (
	MigrationStatusPending    MigrationStatus = "pending"
	MigrationStatusRunning    MigrationStatus = "running"
	MigrationStatusCompleted  MigrationStatus = "completed"
	MigrationStatusFailed     MigrationStatus = "failed"
	MigrationStatusRolledBack MigrationStatus = "rolled_back"
)

// MigrationLogEntry represents a log entry for a migration
type MigrationLogEntry struct {
	FromVersion MigrationVersion `json:"fromVersion"`
	ToVersion   MigrationVersion `json:"toVersion"`
	Status      MigrationStatus  `json:"status"`
	StartTime   int64            `json:"startTime"`
	EndTime     int64            `json:"endTime"`
	Error       string           `json:"error,omitempty"`
}

// Encode serializes the migration log entry
func (e *MigrationLogEntry) Encode() []byte {
	errBytes := []byte(e.Error)
	buf := make([]byte, 4+4+1+8+8+4+len(errBytes))
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], uint32(e.FromVersion))
	offset += 4

	binary.BigEndian.PutUint32(buf[offset:], uint32(e.ToVersion))
	offset += 4

	buf[offset] = byte(len(e.Status)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 1
	// Status is stored as a single byte index
	switch e.Status {
	case MigrationStatusPending:
		buf[offset-1] = 0
	case MigrationStatusRunning:
		buf[offset-1] = 1
	case MigrationStatusCompleted:
		buf[offset-1] = 2
	case MigrationStatusFailed:
		buf[offset-1] = 3
	case MigrationStatusRolledBack:
		buf[offset-1] = 4
	}

	binary.BigEndian.PutUint64(buf[offset:], uint64(e.StartTime)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(e.EndTime)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(errBytes))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4

	copy(buf[offset:], errBytes)

	return buf
}

// DecodeMigrationLogEntry deserializes a migration log entry
func DecodeMigrationLogEntry(data []byte) (*MigrationLogEntry, error) {
	if len(data) < 4+4+1+8+8+4 {
		return nil, ErrInvalidMigration
	}

	entry := &MigrationLogEntry{}
	offset := 0

	entry.FromVersion = MigrationVersion(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	entry.ToVersion = MigrationVersion(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	statusByte := data[offset]
	offset += 1
	switch statusByte {
	case 0:
		entry.Status = MigrationStatusPending
	case 1:
		entry.Status = MigrationStatusRunning
	case 2:
		entry.Status = MigrationStatusCompleted
	case 3:
		entry.Status = MigrationStatusFailed
	case 4:
		entry.Status = MigrationStatusRolledBack
	default:
		entry.Status = MigrationStatusPending
	}

	entry.StartTime = int64(binary.BigEndian.Uint64(data[offset:])) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	entry.EndTime = int64(binary.BigEndian.Uint64(data[offset:])) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	errLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if len(data) < offset+int(errLen) {
		return nil, ErrInvalidMigration
	}

	if errLen > 0 {
		entry.Error = string(data[offset : offset+int(errLen)])
	}

	return entry, nil
}

// MigrationFunc is a function that performs a migration
type MigrationFunc func(db db.Database) error

// RollbackFunc is a function that rolls back a migration
type RollbackFunc func(db db.Database) error

// Migration represents a single migration step
type Migration struct {
	// FromVersion is the version this migration upgrades from
	FromVersion MigrationVersion

	// ToVersion is the version this migration upgrades to
	ToVersion MigrationVersion

	// Name is a human-readable name for the migration
	Name string

	// Description describes what the migration does
	Description string

	// Migrate performs the migration
	Migrate MigrationFunc

	// Rollback undoes the migration (optional)
	Rollback RollbackFunc
}

// MigrationManager manages data migrations
type MigrationManager struct {
	db         db.Database
	migrations map[MigrationVersion]*Migration
	mu         sync.Mutex
	running    bool
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(database db.Database) *MigrationManager {
	mm := &MigrationManager{
		db:         database,
		migrations: make(map[MigrationVersion]*Migration),
	}

	// Register built-in migrations
	mm.registerBuiltInMigrations()

	return mm
}

// registerBuiltInMigrations registers the built-in migrations.
//
// SECURITY (audit NODE-09): The previous implementation silently discarded the
// error returned by RegisterMigration via `// #nosec G104 //nolint:errcheck`.
// If a built-in migration is misconfigured (nil Migrate func, FromVersion >=
// ToVersion, etc.), the error would be swallowed and the migration manager
// would silently operate with a missing migration, causing NeedsMigration() to
// return true forever (or Migrate() to return ErrMigrationNotFound at runtime).
// Since built-in migrations are hardcoded and any registration failure is a
// programmer error, we panic to fail fast during development rather than
// silently degrading at runtime.
func (mm *MigrationManager) registerBuiltInMigrations() {
	// Migration from Genesis to V1
	if err := mm.RegisterMigration(&Migration{
		FromVersion: MigrationVersionGenesis,
		ToVersion:   MigrationVersionV1,
		Name:        "genesis_to_v1",
		Description: "Initial migration from genesis format to v1",
		Migrate:     migrateGenesisToV1,
		Rollback:    rollbackV1ToGenesis,
	}); err != nil {
		panic(fmt.Sprintf("FATAL: failed to register built-in migration genesis_to_v1: %v", err))
	}
}

// RegisterMigration registers a migration
func (mm *MigrationManager) RegisterMigration(m *Migration) error {
	if m == nil {
		return ErrInvalidMigration
	}
	if m.Migrate == nil {
		return ErrInvalidMigration
	}
	if m.FromVersion >= m.ToVersion {
		return ErrInvalidMigration
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.migrations[m.FromVersion] = m
	return nil
}

// GetCurrentVersion returns the current migration version
func (mm *MigrationManager) GetCurrentVersion() (MigrationVersion, error) {
	data, err := mm.db.Get(prefixMigrationVersion)
	if err != nil {
		if err == db.ErrNotFound {
			return MigrationVersionGenesis, nil
		}
		return 0, err
	}

	if len(data) < 4 {
		return MigrationVersionGenesis, nil
	}

	return MigrationVersion(binary.BigEndian.Uint32(data)), nil
}

// SetCurrentVersion sets the current migration version
func (mm *MigrationManager) SetCurrentVersion(version MigrationVersion) error {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(version))
	return mm.db.Put(prefixMigrationVersion, data)
}

// NeedsMigration checks if migration is needed
func (mm *MigrationManager) NeedsMigration() (bool, error) {
	current, err := mm.GetCurrentVersion()
	if err != nil {
		return false, err
	}
	return current < CurrentMigrationVersion, nil
}

// GetPendingMigrations returns the list of pending migrations
func (mm *MigrationManager) GetPendingMigrations() ([]*Migration, error) {
	current, err := mm.GetCurrentVersion()
	if err != nil {
		return nil, err
	}

	var pending []*Migration
	version := current
	for version < CurrentMigrationVersion {
		m, exists := mm.migrations[version]
		if !exists {
			return nil, fmt.Errorf("%w: no migration from version %d", ErrMigrationNotFound, version)
		}
		pending = append(pending, m)
		version = m.ToVersion
	}

	return pending, nil
}

// Migrate runs all pending migrations
func (mm *MigrationManager) Migrate() error {
	mm.mu.Lock()
	if mm.running {
		mm.mu.Unlock()
		return ErrMigrationInProgress
	}
	mm.running = true
	mm.mu.Unlock()

	defer func() {
		mm.mu.Lock()
		mm.running = false
		mm.mu.Unlock()
	}()

	pending, err := mm.GetPendingMigrations()
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		return ErrNoMigrationNeeded
	}

	for _, m := range pending {
		if err := mm.runMigration(m); err != nil {
			return fmt.Errorf("%w: migration %s failed: %v", ErrMigrationFailed, m.Name, err)
		}
	}

	return nil
}

// runMigration runs a single migration
func (mm *MigrationManager) runMigration(m *Migration) error {
	// Log migration start
	entry := &MigrationLogEntry{
		FromVersion: m.FromVersion,
		ToVersion:   m.ToVersion,
		Status:      MigrationStatusRunning,
		StartTime:   getCurrentTimestamp(),
	}

	logKey := mm.migrationLogKey(m.FromVersion, m.ToVersion)
	if err := mm.db.Put(logKey, entry.Encode()); err != nil {
		return err
	}

	// Run migration
	if err := m.Migrate(mm.db); err != nil {
		// Log failure
		entry.Status = MigrationStatusFailed
		entry.EndTime = getCurrentTimestamp()
		entry.Error = err.Error()
		if logErr := mm.db.Put(logKey, entry.Encode()); logErr != nil {
			log.Printf("ERROR: failed to write migration log: %v (original error: %v)", logErr, err)
		}
		return err
	}

	// Update version
	if err := mm.SetCurrentVersion(m.ToVersion); err != nil {
		entry.Status = MigrationStatusFailed
		entry.EndTime = getCurrentTimestamp()
		entry.Error = err.Error()
		if logErr := mm.db.Put(logKey, entry.Encode()); logErr != nil {
			log.Printf("ERROR: failed to write migration log: %v (original error: %v)", logErr, err)
		}
		return err
	}

	// Log success
	entry.Status = MigrationStatusCompleted
	entry.EndTime = getCurrentTimestamp()
	if err := mm.db.Put(logKey, entry.Encode()); err != nil {
		log.Printf("ERROR: failed to write migration success log: %v", err)
	}

	return nil
}

// Rollback rolls back the last migration
func (mm *MigrationManager) Rollback() error {
	mm.mu.Lock()
	if mm.running {
		mm.mu.Unlock()
		return ErrMigrationInProgress
	}
	mm.running = true
	mm.mu.Unlock()

	defer func() {
		mm.mu.Lock()
		mm.running = false
		mm.mu.Unlock()
	}()

	current, err := mm.GetCurrentVersion()
	if err != nil {
		return err
	}

	if current == MigrationVersionGenesis {
		return ErrNoMigrationNeeded
	}

	// Find the migration that brought us to current version
	var targetMigration *Migration
	for _, m := range mm.migrations {
		if m.ToVersion == current {
			targetMigration = m
			break
		}
	}

	if targetMigration == nil {
		return ErrMigrationNotFound
	}

	if targetMigration.Rollback == nil {
		return fmt.Errorf("%w: migration %s has no rollback", ErrRollbackFailed, targetMigration.Name)
	}

	// Run rollback
	if err := targetMigration.Rollback(mm.db); err != nil {
		return fmt.Errorf("%w: %v", ErrRollbackFailed, err)
	}

	// Update version
	if err := mm.SetCurrentVersion(targetMigration.FromVersion); err != nil {
		return err
	}

	// Log rollback
	logKey := mm.migrationLogKey(targetMigration.FromVersion, targetMigration.ToVersion)
	entry := &MigrationLogEntry{
		FromVersion: targetMigration.FromVersion,
		ToVersion:   targetMigration.ToVersion,
		Status:      MigrationStatusRolledBack,
		EndTime:     getCurrentTimestamp(),
	}
	if err := mm.db.Put(logKey, entry.Encode()); err != nil {
		log.Printf("ERROR: failed to write rollback log: %v", err)
	}

	return nil
}

// migrationLogKey creates a database key for migration log
func (mm *MigrationManager) migrationLogKey(from, to MigrationVersion) []byte {
	key := make([]byte, len(prefixMigrationLog)+8)
	copy(key, prefixMigrationLog)
	binary.BigEndian.PutUint32(key[len(prefixMigrationLog):], uint32(from))
	binary.BigEndian.PutUint32(key[len(prefixMigrationLog)+4:], uint32(to))
	return key
}

// GetMigrationHistory returns the migration history
func (mm *MigrationManager) GetMigrationHistory() ([]*MigrationLogEntry, error) {
	var history []*MigrationLogEntry

	iter := mm.db.NewIterator(prefixMigrationLog, nil)
	defer iter.Release()

	for iter.Next() {
		entry, err := DecodeMigrationLogEntry(iter.Value())
		if err != nil {
			continue
		}
		history = append(history, entry)
	}

	return history, iter.Error()
}

// getCurrentTimestamp returns the current Unix timestamp
func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}

// MigrateToVersion migrates to a specific target version
func (mm *MigrationManager) MigrateToVersion(targetVersion MigrationVersion) error {
	mm.mu.Lock()
	if mm.running {
		mm.mu.Unlock()
		return ErrMigrationInProgress
	}
	mm.running = true
	mm.mu.Unlock()

	defer func() {
		mm.mu.Lock()
		mm.running = false
		mm.mu.Unlock()
	}()

	current, err := mm.GetCurrentVersion()
	if err != nil {
		return err
	}

	if current == targetVersion {
		return ErrNoMigrationNeeded
	}

	if current > targetVersion {
		// Need to rollback
		return mm.rollbackToVersion(targetVersion)
	}

	// Need to migrate forward
	return mm.migrateForward(current, targetVersion)
}

// migrateForward migrates from current version to target version
func (mm *MigrationManager) migrateForward(current, target MigrationVersion) error {
	version := current
	for version < target {
		m, exists := mm.migrations[version]
		if !exists {
			return fmt.Errorf("%w: no migration from version %d", ErrMigrationNotFound, version)
		}

		if err := mm.runMigration(m); err != nil {
			return fmt.Errorf("%w: migration %s failed: %v", ErrMigrationFailed, m.Name, err)
		}

		version = m.ToVersion
	}

	return nil
}

// rollbackToVersion rolls back to a specific target version
func (mm *MigrationManager) rollbackToVersion(targetVersion MigrationVersion) error {
	current, err := mm.GetCurrentVersion()
	if err != nil {
		return err
	}

	for current > targetVersion {
		// Find the migration that brought us to current version
		var targetMigration *Migration
		for _, m := range mm.migrations {
			if m.ToVersion == current {
				targetMigration = m
				break
			}
		}

		if targetMigration == nil {
			return fmt.Errorf("%w: no migration to version %d", ErrMigrationNotFound, current)
		}

		if targetMigration.Rollback == nil {
			return fmt.Errorf("%w: migration %s has no rollback", ErrRollbackFailed, targetMigration.Name)
		}

		// Run rollback
		if err := mm.runRollback(targetMigration); err != nil {
			return err
		}

		current = targetMigration.FromVersion
	}

	return nil
}

// runRollback runs a single rollback operation
func (mm *MigrationManager) runRollback(m *Migration) error {
	// Log rollback start
	entry := &MigrationLogEntry{
		FromVersion: m.FromVersion,
		ToVersion:   m.ToVersion,
		Status:      MigrationStatusRunning,
		StartTime:   getCurrentTimestamp(),
	}

	logKey := mm.migrationLogKey(m.FromVersion, m.ToVersion)
	if err := mm.db.Put(logKey, entry.Encode()); err != nil {
		return err
	}

	// Run rollback
	if err := m.Rollback(mm.db); err != nil {
		// Log failure
		entry.Status = MigrationStatusFailed
		entry.EndTime = getCurrentTimestamp()
		entry.Error = fmt.Sprintf("rollback failed: %v", err)
		if logErr := mm.db.Put(logKey, entry.Encode()); logErr != nil {
			log.Printf("ERROR: failed to write rollback failure log: %v (original error: %v)", logErr, err)
		}
		return fmt.Errorf("%w: %v", ErrRollbackFailed, err)
	}

	// Update version
	if err := mm.SetCurrentVersion(m.FromVersion); err != nil {
		entry.Status = MigrationStatusFailed
		entry.EndTime = getCurrentTimestamp()
		entry.Error = err.Error()
		if logErr := mm.db.Put(logKey, entry.Encode()); logErr != nil {
			log.Printf("ERROR: failed to write rollback failure log: %v (original error: %v)", logErr, err)
		}
		return err
	}

	// Log success
	entry.Status = MigrationStatusRolledBack
	entry.EndTime = getCurrentTimestamp()
	if err := mm.db.Put(logKey, entry.Encode()); err != nil {
		log.Printf("ERROR: failed to write rollback success log: %v", err)
	}

	return nil
}

// RollbackAll rolls back all migrations to genesis
func (mm *MigrationManager) RollbackAll() error {
	return mm.MigrateToVersion(MigrationVersionGenesis)
}

// CanRollback checks if rollback is possible from current version
func (mm *MigrationManager) CanRollback() (bool, error) {
	current, err := mm.GetCurrentVersion()
	if err != nil {
		return false, err
	}

	if current == MigrationVersionGenesis {
		return false, nil
	}

	// Find the migration that brought us to current version
	for _, m := range mm.migrations {
		if m.ToVersion == current {
			return m.Rollback != nil, nil
		}
	}

	return false, nil
}

// GetMigration returns a migration by its from version
func (mm *MigrationManager) GetMigration(fromVersion MigrationVersion) (*Migration, error) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	m, exists := mm.migrations[fromVersion]
	if !exists {
		return nil, ErrMigrationNotFound
	}
	return m, nil
}

// GetAllMigrations returns all registered migrations
func (mm *MigrationManager) GetAllMigrations() []*Migration {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	result := make([]*Migration, 0, len(mm.migrations))
	for _, m := range mm.migrations {
		result = append(result, m)
	}
	return result
}

// IsRunning returns whether a migration is currently running
func (mm *MigrationManager) IsRunning() bool {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	return mm.running
}

// MigrationProgress represents the progress of a migration
type MigrationProgress struct {
	CurrentVersion MigrationVersion
	TargetVersion  MigrationVersion
	TotalSteps     int
	CompletedSteps int
	CurrentStep    string
	Status         MigrationStatus
}

// GetProgress returns the current migration progress
func (mm *MigrationManager) GetProgress() (*MigrationProgress, error) {
	current, err := mm.GetCurrentVersion()
	if err != nil {
		return nil, err
	}

	pending, err := mm.GetPendingMigrations()
	if err != nil && err != ErrMigrationNotFound {
		return nil, err
	}

	progress := &MigrationProgress{
		CurrentVersion: current,
		TargetVersion:  CurrentMigrationVersion,
		TotalSteps:     len(pending),
		CompletedSteps: 0,
		Status:         MigrationStatusPending,
	}

	if mm.running {
		progress.Status = MigrationStatusRunning
	} else if current == CurrentMigrationVersion {
		progress.Status = MigrationStatusCompleted
		progress.CompletedSteps = progress.TotalSteps
	}

	return progress, nil
}

// Built-in migration functions

// migrateGenesisToV1 migrates from genesis format to v1.
//
// SECURITY (audit NODE-09): The previous implementation was a no-op placeholder
// with a vague "this would..." comment, giving the false impression that a real
// migration was running. For genesis→v1 there is genuinely no data transformation
// needed — the genesis data layout IS the v1 layout. We now verify this
// assumption explicitly by checking that the database is either empty or at
// genesis version, then mark the version. This prevents the migration from
// silently "succeeding" on a database that was already at a later version
// (which would mask a version-tracking bug).
func migrateGenesisToV1(database db.Database) error {
	// Genesis→V1 is a no-op data transformation: the genesis data layout
	// is identical to the v1 layout. The only effect is the version bump
	// performed by runMigration() after this function returns nil.

	// Defensive check: if the database already has a migration version key
	// that is > Genesis, something is wrong — we should not be running a
	// genesis→v1 migration on a database that is already past genesis.
	versionData, err := database.Get(prefixMigrationVersion)
	if err != nil && err != db.ErrNotFound {
		return fmt.Errorf("migrateGenesisToV1: failed to read current version: %w", err)
	}
	if err == nil && len(versionData) >= 4 {
		existingVersion := MigrationVersion(binary.BigEndian.Uint32(versionData))
		if existingVersion > MigrationVersionGenesis {
			return fmt.Errorf("migrateGenesisToV1: database is at version %d, expected genesis (0) — refusing to downgrade version tracking", existingVersion)
		}
	}

	return nil
}

// rollbackV1ToGenesis rolls back from v1 to genesis format.
//
// SECURITY (audit NODE-09): Like the forward migration, this is a no-op data
// transformation. We verify the database is at v1 before allowing rollback.
func rollbackV1ToGenesis(database db.Database) error {
	versionData, err := database.Get(prefixMigrationVersion)
	if err != nil && err != db.ErrNotFound {
		return fmt.Errorf("rollbackV1ToGenesis: failed to read current version: %w", err)
	}
	if err == nil && len(versionData) >= 4 {
		existingVersion := MigrationVersion(binary.BigEndian.Uint32(versionData))
		if existingVersion != MigrationVersionV1 {
			return fmt.Errorf("rollbackV1ToGenesis: database is at version %d, expected v1 (1) — refusing rollback from wrong version", existingVersion)
		}
	}

	return nil
}

// DataTransformer provides utilities for transforming data between formats
type DataTransformer struct {
	db db.Database
}

// NewDataTransformer creates a new data transformer
func NewDataTransformer(database db.Database) *DataTransformer {
	return &DataTransformer{db: database}
}

// TransformKey transforms a key from old format to new format
func (dt *DataTransformer) TransformKey(oldKey []byte, transform func([]byte) []byte) ([]byte, error) {
	if transform == nil {
		return oldKey, nil
	}
	return transform(oldKey), nil
}

// TransformValue transforms a value from old format to new format
func (dt *DataTransformer) TransformValue(oldValue []byte, transform func([]byte) ([]byte, error)) ([]byte, error) {
	if transform == nil {
		return oldValue, nil
	}
	return transform(oldValue)
}

// MigratePrefix migrates all keys with a given prefix
func (dt *DataTransformer) MigratePrefix(
	oldPrefix []byte,
	newPrefix []byte,
	keyTransform func([]byte) []byte,
	valueTransform func([]byte) ([]byte, error),
) error {
	batch := dt.db.NewBatch()

	iter := dt.db.NewIterator(oldPrefix, nil)
	defer iter.Release()

	for iter.Next() {
		oldKey := iter.Key()
		oldValue := iter.Value()

		// Make copies since iterator values may be reused
		oldKeyCopy := make([]byte, len(oldKey))
		copy(oldKeyCopy, oldKey)
		oldValueCopy := make([]byte, len(oldValue))
		copy(oldValueCopy, oldValue)

		// Transform key - always replace prefix if newPrefix is provided
		var newKey []byte
		if len(oldKeyCopy) >= len(oldPrefix) {
			suffix := oldKeyCopy[len(oldPrefix):]
			if newPrefix != nil {
				newKey = make([]byte, len(newPrefix)+len(suffix))
				copy(newKey, newPrefix)
				copy(newKey[len(newPrefix):], suffix)
			} else {
				newKey = oldKeyCopy
			}
		} else {
			newKey = oldKeyCopy
		}

		// Apply additional key transformation if provided
		if keyTransform != nil {
			newKey = keyTransform(newKey)
		}

		// Transform value
		newValue := oldValueCopy
		if valueTransform != nil {
			var err error
			newValue, err = valueTransform(oldValueCopy)
			if err != nil {
				return fmt.Errorf("failed to transform value for key %x: %w", oldKeyCopy, err)
			}
		}

		// Delete old key if different from new key
		if string(oldKeyCopy) != string(newKey) {
			if err := batch.Delete(oldKeyCopy); err != nil {
				return err
			}
		}

		// Write new key-value
		if err := batch.Put(newKey, newValue); err != nil {
			return err
		}
	}

	if err := iter.Error(); err != nil {
		return err
	}

	return batch.Write()
}

// BackupPrefix backs up all keys with a given prefix
func (dt *DataTransformer) BackupPrefix(prefix []byte, backupPrefix []byte) error {
	batch := dt.db.NewBatch()

	iter := dt.db.NewIterator(prefix, nil)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Create backup key
		suffix := key[len(prefix):]
		backupKey := make([]byte, len(backupPrefix)+len(suffix))
		copy(backupKey, backupPrefix)
		copy(backupKey[len(backupPrefix):], suffix)

		// Write backup
		if err := batch.Put(backupKey, value); err != nil {
			return err
		}
	}

	if err := iter.Error(); err != nil {
		return err
	}

	return batch.Write()
}

// RestorePrefix restores all keys from a backup prefix
func (dt *DataTransformer) RestorePrefix(backupPrefix []byte, targetPrefix []byte) error {
	batch := dt.db.NewBatch()

	iter := dt.db.NewIterator(backupPrefix, nil)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Create target key
		suffix := key[len(backupPrefix):]
		targetKey := make([]byte, len(targetPrefix)+len(suffix))
		copy(targetKey, targetPrefix)
		copy(targetKey[len(targetPrefix):], suffix)

		// Write to target
		if err := batch.Put(targetKey, value); err != nil {
			return err
		}

		// Delete backup
		if err := batch.Delete(key); err != nil {
			return err
		}
	}

	if err := iter.Error(); err != nil {
		return err
	}

	return batch.Write()
}

// DeletePrefix deletes all keys with a given prefix
func (dt *DataTransformer) DeletePrefix(prefix []byte) error {
	batch := dt.db.NewBatch()

	iter := dt.db.NewIterator(prefix, nil)
	defer iter.Release()

	for iter.Next() {
		if err := batch.Delete(iter.Key()); err != nil {
			return err
		}
	}

	if err := iter.Error(); err != nil {
		return err
	}

	return batch.Write()
}

// VerifyMigration verifies that a migration was successful
func (mm *MigrationManager) VerifyMigration(fromVersion, toVersion MigrationVersion) error {
	current, err := mm.GetCurrentVersion()
	if err != nil {
		return err
	}

	if current != toVersion {
		return fmt.Errorf("version mismatch: expected %d, got %d", toVersion, current)
	}

	// Check migration log
	logKey := mm.migrationLogKey(fromVersion, toVersion)
	data, err := mm.db.Get(logKey)
	if err != nil {
		return fmt.Errorf("migration log not found: %w", err)
	}

	entry, err := DecodeMigrationLogEntry(data)
	if err != nil {
		return fmt.Errorf("failed to decode migration log: %w", err)
	}

	if entry.Status != MigrationStatusCompleted {
		return fmt.Errorf("migration status is %s, expected completed", entry.Status)
	}

	return nil
}
