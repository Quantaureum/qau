// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
)

// MinistryStateStore provides persistence for the six governance ministries'
// state using a db.Database backend. It implements a write-through pattern:
// the in-memory maps in each ministry remain the primary data structure for
// reads, and MinistryStateStore persists mutations for crash recovery.
//
// P1-T8 (2026-07-14): Previously, all ministry state was purely in-memory.
// A node restart would lose all state, including the Defense blacklist
// (critical for consensus safety — a blacklisted validator would be
// un-blacklisted on restart). This store ensures that critical state
// survives restarts.
//
// Design:
//   - Each ministry's state is serialized as a single JSON blob under a
//     fixed key. This is simpler than per-entry keys and sufficient for
//     the relatively small state sizes (blacklist, proposals, reputations).
//   - JSON encoding is used (same pattern as shard_store.go) because
//     ministry state is NOT consensus-critical (does not affect stateRoot).
//     The state_db.go prohibition on JSON applies only to consensus state.
//   - A checkpoint key records the last persisted epoch for verification.
type MinistryStateStore struct {
	mu       sync.RWMutex
	database db.Database
}

// Key prefixes for ministry state persistence.
var (
	ministryPersonnelPrefix = []byte("min_per:") // → MinistryPersonnelState (JSON)
	ministryRevenuePrefix   = []byte("min_rev:") // → MinistryRevenueState (JSON)
	ministryJusticePrefix   = []byte("min_jus:") // → MinistryJusticeState (JSON)
	ministryDefensePrefix   = []byte("min_def:") // → MinistryDefenseState (JSON)
	ministryRitesPrefix     = []byte("min_rit:") // → MinistryRitesState (JSON)
	ministryWorksPrefix     = []byte("min_wrk:") // → MinistryWorksState (JSON)
	ministryCheckpointKey   = []byte("min_ckpt") // → 8 bytes (last checkpoint epoch, BE)
)

// ministryStateVersion is the current persistence schema version.
// V1 (Version=0): pre-P4-T3 data, no Version field in JSON (defaults to 0).
// V2 (Version=2): P4-T3 added Version field for forward compatibility.
const ministryStateVersion uint8 = 2

// migrateV1ToV2 upgrades V1 persistence data (Version=0, no Version field
// in JSON) to V2 (Version=2). V1 data was written before P4-T3 added the
// Version field. The migration is a version bump only — no data transformation
// is needed because P4-T3 did not change any field layout.
//
// Returns the migrated version. If currentVersion is already >= 2, it is
// returned unchanged (idempotent). If currentVersion > 2 (future version),
// it is returned unchanged — the caller MUST fail-closed (GOV-R5-04) by
// returning an error, refusing to load state from a newer schema version
// to avoid silent data corruption on downgrade.
func migrateV1ToV2(currentVersion uint8) uint8 {
	if currentVersion == 0 {
		return ministryStateVersion // V1 → V2
	}
	return currentVersion
}

// NewMinistryStateStore creates a new MinistryStateStore backed by the
// given database. The database must be non-nil for production use.
func NewMinistryStateStore(database db.Database) *MinistryStateStore {
	return &MinistryStateStore{database: database}
}

// Database returns the underlying database, or nil if not configured.
func (s *MinistryStateStore) Database() db.Database {
	if s == nil {
		return nil
	}
	return s.database
}

// --- Checkpoint ---

// SaveCheckpoint records the epoch at which the ministry state was last
// persisted. Used on startup to verify that the loaded state is current.
func (s *MinistryStateStore) SaveCheckpoint(epoch uint64) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, epoch)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(ministryCheckpointKey, buf)
}

// LoadCheckpoint returns the last persisted epoch, or 0 if no checkpoint exists.
func (s *MinistryStateStore) LoadCheckpoint() (uint64, error) {
	if s == nil || s.database == nil {
		return 0, ErrStateStoreNotConfigured
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := s.database.Get(ministryCheckpointKey)
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return 0, nil // no checkpoint yet
		}
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	if len(data) < 8 {
		return 0, fmt.Errorf("checkpoint data too short: %d bytes", len(data))
	}
	return binary.BigEndian.Uint64(data[:8]), nil
}

// --- Personnel ---

// personnelState is the serializable form of MinistryPersonnel.
type personnelState struct {
	Version     uint8                     `json:"version"` // P4-T3: schema version
	Reputations map[int]*ReputationRecord `json:"reputations"`
	Operations  uint64                    `json:"operations"`
	Errors      uint64                    `json:"errors"`
	LastActive  time.Time                 `json:"lastActive"`
}

// SavePersonnel persists MinistryPersonnel state.
func (s *MinistryStateStore) SavePersonnel(p *MinistryPersonnel) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if p == nil {
		return nil
	}
	p.mu.RLock()
	state := personnelState{
		Version:     ministryStateVersion,
		Reputations: p.reputations,
		Operations:  p.operations,
		Errors:      p.errors,
		LastActive:  p.lastActive,
	}
	p.mu.RUnlock()
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal personnel state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(ministryPersonnelPrefix, data)
}

// LoadPersonnel restores MinistryPersonnel state from the database.
func (s *MinistryStateStore) LoadPersonnel(p *MinistryPersonnel) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if p == nil {
		return nil
	}
	s.mu.RLock()
	data, err := s.database.Get(ministryPersonnelPrefix)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return nil // no saved state
		}
		return fmt.Errorf("load personnel state: %w", err)
	}
	if len(data) == 0 {
		return nil // no saved state
	}
	var state personnelState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal personnel state: %w", err)
	}
	migratedVersion := migrateV1ToV2(state.Version)
	// GOV-R5-04 (2026-07-17): Fail-closed on future schema versions.
	// Previously this only logged a warning and continued loading, which
	// could silently corrupt state if a newer version wrote incompatible
	// schema. Refuse to load so the operator must upgrade the binary
	// before the state can be read (no silent downgrade).
	if migratedVersion > ministryStateVersion {
		return fmt.Errorf("ministry_store: personnel state has future version %d (current=%d) — refusing to load to avoid schema incompatibility (downgrade not supported)", migratedVersion, ministryStateVersion)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reputations == nil {
		p.reputations = make(map[int]*ReputationRecord)
	}
	for k, v := range state.Reputations {
		p.reputations[k] = v
	}
	p.operations = state.Operations
	p.errors = state.Errors
	p.lastActive = state.LastActive
	return nil
}

// --- Defense ---

// defenseState is the serializable form of MinistryDefense.
type defenseState struct {
	Version       uint8                     `json:"version"` // P4-T3: schema version
	Alerts        map[uint64]*SecurityAlert `json:"alerts"`
	NextAlertID   uint64                    `json:"nextAlertID"`
	Blacklist     map[int]*BlacklistEntry   `json:"blacklist"`
	Partition     PartitionState            `json:"partition"`
	QuantumAlerts uint64                    `json:"quantumAlerts"`
	Operations    uint64                    `json:"operations"`
	Errors        uint64                    `json:"errors"`
	LastActive    time.Time                 `json:"lastActive"`
}

// SaveDefense persists MinistryDefense state.
// CRITICAL: The blacklist must survive restarts — a blacklisted validator
// that becomes un-blacklisted on restart can compromise consensus safety.
func (s *MinistryStateStore) SaveDefense(d *MinistryDefense) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if d == nil {
		return nil
	}
	d.mu.RLock()
	state := defenseState{
		Version:       ministryStateVersion,
		Alerts:        d.alerts,
		NextAlertID:   d.nextAlertID,
		Blacklist:     d.blacklist,
		Partition:     d.partition,
		QuantumAlerts: d.quantumAlerts,
		Operations:    d.operations,
		Errors:        d.errors,
		LastActive:    d.lastActive,
	}
	d.mu.RUnlock()
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal defense state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(ministryDefensePrefix, data)
}

// LoadDefense restores MinistryDefense state from the database.
func (s *MinistryStateStore) LoadDefense(d *MinistryDefense) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if d == nil {
		return nil
	}
	s.mu.RLock()
	data, err := s.database.Get(ministryDefensePrefix)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return nil // no saved state
		}
		return fmt.Errorf("load defense state: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	var state defenseState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal defense state: %w", err)
	}
	migratedVersion := migrateV1ToV2(state.Version)
	// GOV-R5-04 (2026-07-17): Fail-closed on future schema versions.
	if migratedVersion > ministryStateVersion {
		return fmt.Errorf("ministry_store: defense state has future version %d (current=%d) — refusing to load to avoid schema incompatibility (downgrade not supported)", migratedVersion, ministryStateVersion)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.alerts == nil {
		d.alerts = make(map[uint64]*SecurityAlert)
	}
	for k, v := range state.Alerts {
		d.alerts[k] = v
	}
	d.nextAlertID = state.NextAlertID
	if d.blacklist == nil {
		d.blacklist = make(map[int]*BlacklistEntry)
	}
	for k, v := range state.Blacklist {
		d.blacklist[k] = v
	}
	d.partition = state.Partition
	d.quantumAlerts = state.QuantumAlerts
	d.operations = state.Operations
	d.errors = state.Errors
	d.lastActive = state.LastActive
	return nil
}

// --- Revenue ---

// revenueState is the serializable form of MinistryRevenue.
type revenueState struct {
	Version       uint8                                `json:"version"` // P4-T3: schema version
	RewardRecords map[uint64]*RewardDistributionRecord `json:"rewardRecords"`
	SlashRecords  []SlashExecutionRecord               `json:"slashRecords"`
	TotalRewards  string                               `json:"totalRewards"` // big.Int as string
	TotalSlashed  string                               `json:"totalSlashed"` // big.Int as string
	Operations    uint64                               `json:"operations"`
	Errors        uint64                               `json:"errors"`
	LastActive    time.Time                            `json:"lastActive"`
}

// SaveRevenue persists MinistryRevenue state.
func (s *MinistryStateStore) SaveRevenue(r *MinistryRevenue) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if r == nil {
		return nil
	}
	r.mu.RLock()
	state := revenueState{
		Version:       ministryStateVersion,
		RewardRecords: r.rewardRecords,
		SlashRecords:  r.slashRecords,
		Operations:    r.operations,
		Errors:        r.errors,
		LastActive:    r.lastActive,
	}
	if r.totalRewards != nil {
		state.TotalRewards = r.totalRewards.String()
	}
	if r.totalSlashed != nil {
		state.TotalSlashed = r.totalSlashed.String()
	}
	r.mu.RUnlock()
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal revenue state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(ministryRevenuePrefix, data)
}

// LoadRevenue restores MinistryRevenue state from the database.
func (s *MinistryStateStore) LoadRevenue(r *MinistryRevenue) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if r == nil {
		return nil
	}
	s.mu.RLock()
	data, err := s.database.Get(ministryRevenuePrefix)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return nil // no saved state
		}
		return fmt.Errorf("load revenue state: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	var state revenueState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal revenue state: %w", err)
	}
	migratedVersion := migrateV1ToV2(state.Version)
	// GOV-R5-04 (2026-07-17): Fail-closed on future schema versions.
	if migratedVersion > ministryStateVersion {
		return fmt.Errorf("ministry_store: revenue state has future version %d (current=%d) — refusing to load to avoid schema incompatibility (downgrade not supported)", migratedVersion, ministryStateVersion)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rewardRecords == nil {
		r.rewardRecords = make(map[uint64]*RewardDistributionRecord)
	}
	for k, v := range state.RewardRecords {
		r.rewardRecords[k] = v
	}
	r.slashRecords = state.SlashRecords
	if state.TotalRewards != "" {
		r.totalRewards = stringToBigInt(state.TotalRewards)
	}
	if state.TotalSlashed != "" {
		r.totalSlashed = stringToBigInt(state.TotalSlashed)
	}
	r.operations = state.Operations
	r.errors = state.Errors
	r.lastActive = state.LastActive
	return nil
}

// --- Justice ---

// justiceState is the serializable form of MinistryJustice.
type justiceState struct {
	Version    uint8                   `json:"version"` // P4-T3: schema version
	Cases      map[uint64]*DisputeCase `json:"cases"`
	NextCaseID uint64                  `json:"nextCaseID"`
	Operations uint64                  `json:"operations"`
	Errors     uint64                  `json:"errors"`
	LastActive time.Time               `json:"lastActive"`
}

// SaveJustice persists MinistryJustice state.
func (s *MinistryStateStore) SaveJustice(j *MinistryJustice) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if j == nil {
		return nil
	}
	j.mu.RLock()
	state := justiceState{
		Version:    ministryStateVersion,
		Cases:      j.cases,
		NextCaseID: j.nextCaseID,
		Operations: j.operations,
		Errors:     j.errors,
		LastActive: j.lastActive,
	}
	j.mu.RUnlock()
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal justice state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(ministryJusticePrefix, data)
}

// LoadJustice restores MinistryJustice state from the database.
func (s *MinistryStateStore) LoadJustice(j *MinistryJustice) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if j == nil {
		return nil
	}
	s.mu.RLock()
	data, err := s.database.Get(ministryJusticePrefix)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return nil // no saved state
		}
		return fmt.Errorf("load justice state: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	var state justiceState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal justice state: %w", err)
	}
	migratedVersion := migrateV1ToV2(state.Version)
	// GOV-R5-04 (2026-07-17): Fail-closed on future schema versions.
	if migratedVersion > ministryStateVersion {
		return fmt.Errorf("ministry_store: justice state has future version %d (current=%d) — refusing to load to avoid schema incompatibility (downgrade not supported)", migratedVersion, ministryStateVersion)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cases == nil {
		j.cases = make(map[uint64]*DisputeCase)
	}
	for k, v := range state.Cases {
		j.cases[k] = v
	}
	j.nextCaseID = state.NextCaseID
	j.operations = state.Operations
	j.errors = state.Errors
	j.lastActive = state.LastActive
	// GOV-R7-07: recompute oldestCaseID after reload since the field is
	// not persisted (it is a runtime cache derived from the live case
	// set). Scanning is O(N) but happens once per node startup.
	j.oldestCaseID = 0
	if len(j.cases) > 0 {
		oldest := ^uint64(0)
		for id := range j.cases {
			if id < oldest {
				oldest = id
			}
		}
		j.oldestCaseID = oldest
	}
	return nil
}

// --- Rites ---

// ritesState is the serializable form of MinistryRites.
// P1-T6 (2026-07-15): Proposal/vote fields removed — governance proposals are
// handled by economics.GovernanceManager. Only ministry operational counters
// are persisted.
type ritesState struct {
	Version    uint8     `json:"version"` // P4-T3: schema version
	Operations uint64    `json:"operations"`
	Errors     uint64    `json:"errors"`
	LastActive time.Time `json:"lastActive"`
}

// SaveRites persists MinistryRites state.
func (s *MinistryStateStore) SaveRites(r *MinistryRites) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if r == nil {
		return nil
	}
	r.mu.RLock()
	state := ritesState{
		Version:    ministryStateVersion,
		Operations: r.operations,
		Errors:     r.errors,
		LastActive: r.lastActive,
	}
	r.mu.RUnlock()
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal rites state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(ministryRitesPrefix, data)
}

// LoadRites restores MinistryRites state from the database.
func (s *MinistryStateStore) LoadRites(r *MinistryRites) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if r == nil {
		return nil
	}
	s.mu.RLock()
	data, err := s.database.Get(ministryRitesPrefix)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return nil // no saved state
		}
		return fmt.Errorf("load rites state: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	var state ritesState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal rites state: %w", err)
	}
	migratedVersion := migrateV1ToV2(state.Version)
	// GOV-R5-04 (2026-07-17): Fail-closed on future schema versions.
	if migratedVersion > ministryStateVersion {
		return fmt.Errorf("ministry_store: rites state has future version %d (current=%d) — refusing to load to avoid schema incompatibility (downgrade not supported)", migratedVersion, ministryStateVersion)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.operations = state.Operations
	r.errors = state.Errors
	r.lastActive = state.LastActive
	return nil
}

// --- Works ---

// worksState is the serializable form of MinistryWorks.
type worksState struct {
	Version      uint8                    `json:"version"` // P4-T3: schema version
	Shards       map[uint64]*ShardInfo    `json:"shards"`
	Bridges      map[uint64]*BridgeInfo   `json:"bridges"`
	CrossChainTx map[uint64]*CrossChainTx `json:"crossChainTx"`
	NextShardID  uint64                   `json:"nextShardID"`
	NextBridgeID uint64                   `json:"nextBridgeID"`
	NextTxID     uint64                   `json:"nextTxID"`
	Operations   uint64                   `json:"operations"`
	Errors       uint64                   `json:"errors"`
	LastActive   time.Time                `json:"lastActive"`
}

// SaveWorks persists MinistryWorks state.
func (s *MinistryStateStore) SaveWorks(w *MinistryWorks) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if w == nil {
		return nil
	}
	w.mu.RLock()
	state := worksState{
		Version:      ministryStateVersion,
		Shards:       w.shards,
		Bridges:      w.bridges,
		CrossChainTx: w.crossChainTx,
		NextShardID:  w.nextShardID,
		NextBridgeID: w.nextBridgeID,
		NextTxID:     w.nextTxID,
		Operations:   w.operations,
		Errors:       w.errors,
		LastActive:   w.lastActive,
	}
	w.mu.RUnlock()
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal works state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(ministryWorksPrefix, data)
}

// LoadWorks restores MinistryWorks state from the database.
func (s *MinistryStateStore) LoadWorks(w *MinistryWorks) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if w == nil {
		return nil
	}
	s.mu.RLock()
	data, err := s.database.Get(ministryWorksPrefix)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return nil // no saved state
		}
		return fmt.Errorf("load works state: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	var state worksState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal works state: %w", err)
	}
	migratedVersion := migrateV1ToV2(state.Version)
	// GOV-R5-04 (2026-07-17): Fail-closed on future schema versions.
	if migratedVersion > ministryStateVersion {
		return fmt.Errorf("ministry_store: works state has future version %d (current=%d) — refusing to load to avoid schema incompatibility (downgrade not supported)", migratedVersion, ministryStateVersion)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.shards == nil {
		w.shards = make(map[uint64]*ShardInfo)
	}
	for k, v := range state.Shards {
		w.shards[k] = v
	}
	if w.bridges == nil {
		w.bridges = make(map[uint64]*BridgeInfo)
	}
	for k, v := range state.Bridges {
		w.bridges[k] = v
	}
	if w.crossChainTx == nil {
		w.crossChainTx = make(map[uint64]*CrossChainTx)
	}
	for k, v := range state.CrossChainTx {
		w.crossChainTx[k] = v
	}
	w.nextShardID = state.NextShardID
	w.nextBridgeID = state.NextBridgeID
	w.nextTxID = state.NextTxID
	w.operations = state.Operations
	w.errors = state.Errors
	w.lastActive = state.LastActive
	return nil
}

// --- MinistryRegistry integration ---

// SaveAll persists all six ministries' state and records the checkpoint epoch.
// P1-T8 (2026-07-14): Called at epoch boundaries for crash recovery.
// Best-effort: errors are collected but each ministry is attempted regardless
// of prior failures. Returns the first error encountered (if any).
//
// Writes are non-atomic (individual Put calls). This is acceptable because
// ministry state is NOT consensus-critical (does not affect stateRoot).
// The checkpoint epoch records when the last successful save completed,
// allowing LoadAll to verify state freshness on restart.
func (s *MinistryStateStore) SaveAll(registry *MinistryRegistry, epoch uint64) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if registry == nil {
		return nil
	}

	var firstErr error

	if registry.personnel != nil {
		if err := s.SavePersonnel(registry.personnel); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.revenue != nil {
		if err := s.SaveRevenue(registry.revenue); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.justice != nil {
		if err := s.SaveJustice(registry.justice); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.defense != nil {
		if err := s.SaveDefense(registry.defense); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.rites != nil {
		if err := s.SaveRites(registry.rites); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.works != nil {
		if err := s.SaveWorks(registry.works); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Write checkpoint.
	if err := s.SaveCheckpoint(epoch); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// LoadAll restores all six ministries' state from the database.
// P1-T8 (2026-07-14): Called at node startup before consensus starts.
// Returns the checkpoint epoch (0 if no state was saved).
func (s *MinistryStateStore) LoadAll(registry *MinistryRegistry) (uint64, error) {
	if s == nil || s.database == nil {
		return 0, ErrStateStoreNotConfigured
	}
	if registry == nil {
		return 0, nil
	}

	var firstErr error

	if registry.personnel != nil {
		if err := s.LoadPersonnel(registry.personnel); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.revenue != nil {
		if err := s.LoadRevenue(registry.revenue); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.justice != nil {
		if err := s.LoadJustice(registry.justice); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.defense != nil {
		if err := s.LoadDefense(registry.defense); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.rites != nil {
		if err := s.LoadRites(registry.rites); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if registry.works != nil {
		if err := s.LoadWorks(registry.works); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	epoch, err := s.LoadCheckpoint()
	if err != nil && firstErr == nil {
		firstErr = err
	}
	return epoch, firstErr
}

// --- Helpers ---

// stringToBigInt converts a decimal string to *big.Int.
// Returns nil for empty string or invalid input.
func stringToBigInt(s string) *big.Int {
	if s == "" {
		return nil
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil
	}
	return n
}
