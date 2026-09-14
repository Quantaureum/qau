// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

type ThreatLevel uint8

const (
	ThreatNone     ThreatLevel = 0
	ThreatLow      ThreatLevel = 1
	ThreatMedium   ThreatLevel = 2
	ThreatHigh     ThreatLevel = 3
	ThreatCritical ThreatLevel = 4
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatNone:
		return "None"
	case ThreatLow:
		return "Low"
	case ThreatMedium:
		return "Medium"
	case ThreatHigh:
		return "High"
	case ThreatCritical:
		return "Critical"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

type ThreatType uint8

const (
	ThreatTypeNone             ThreatType = 0
	ThreatTypeQuantumAttack    ThreatType = 1
	ThreatTypeNetworkPartition ThreatType = 2
	ThreatTypeDDoS             ThreatType = 3
	ThreatTypeSybilAttack      ThreatType = 4
	ThreatTypeCollusion        ThreatType = 5
	ThreatTypeKeyCompromise    ThreatType = 6
)

func (t ThreatType) String() string {
	switch t {
	case ThreatTypeNone:
		return "None"
	case ThreatTypeQuantumAttack:
		return "QuantumAttack"
	case ThreatTypeNetworkPartition:
		return "NetworkPartition"
	case ThreatTypeDDoS:
		return "DDoS"
	case ThreatTypeSybilAttack:
		return "SybilAttack"
	case ThreatTypeCollusion:
		return "Collusion"
	case ThreatTypeKeyCompromise:
		return "KeyCompromise"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

type SecurityAlert struct {
	ID          uint64
	ThreatType  ThreatType
	Level       ThreatLevel
	Slot        uint64
	Description string
	Validators  []int
	BlockHash   types.Hash
	DetectedAt  time.Time
	Resolved    bool
	ResolvedAt  time.Time
}

type BlacklistEntry struct {
	ValidatorIndex int
	Reason         string
	AddedAt        time.Time
	ExpiresAt      time.Time
	Permanent      bool
}

type PartitionState struct {
	Detected      bool
	DetectedAt    time.Time
	PartitionSize int
	TotalNodes    int
	Resolved      bool
	ResolvedAt    time.Time
}

type MinistryDefense struct {
	mu sync.RWMutex

	qpos        *QPOS
	coordinator *ThreeChambersCoordinator
	registry    *MinistryRegistry

	alerts      map[uint64]*SecurityAlert
	nextAlertID uint64
	maxAlerts   int

	blacklist     map[int]*BlacklistEntry
	partition     PartitionState
	quantumAlerts uint64

	operations uint64
	errors     uint64
	lastActive time.Time
}

func NewMinistryDefense(qpos *QPOS, coordinator *ThreeChambersCoordinator, registry *MinistryRegistry) *MinistryDefense {
	return &MinistryDefense{
		qpos:        qpos,
		coordinator: coordinator,
		registry:    registry,
		alerts:      make(map[uint64]*SecurityAlert),
		nextAlertID: 1,
		maxAlerts:   10000,
		blacklist:   make(map[int]*BlacklistEntry),
		partition:   PartitionState{},
	}
}

func (md *MinistryDefense) DetectQuantumAttack(caller types.Address, slot uint64, evidence string, blockTime ...int64) *SecurityAlert {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can create security alerts.
	if caller == (types.Address{}) || !isSystemCaller(caller) {
		return nil
	}

	md.mu.Lock()
	defer md.mu.Unlock()
	md.operations++
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	md.lastActive = now // NOT consensus-critical: local in-memory tracking only

	alertID := md.nextAlertID
	md.nextAlertID++
	md.quantumAlerts++

	alert := &SecurityAlert{
		ID:          alertID,
		ThreatType:  ThreatTypeQuantumAttack,
		Level:       ThreatCritical,
		Slot:        slot,
		Description: fmt.Sprintf("Potential quantum attack detected at slot %d: %s", slot, evidence),
		DetectedAt:  now,
	}

	md.addAlertLocked(alert)

	// P3-T2 (2026-07-15): Structured audit log for quantum attack detection.
	if md.registry != nil {
		md.registry.logAudit(MinistryIDDefense, "detect_quantum_attack", caller,
			fmt.Sprintf("slot=%d alertID=%d evidence=%s", slot, alertID, evidence),
			"ok", now)
	}

	return alert
}

func (md *MinistryDefense) DetectNetworkPartition(caller types.Address, slot uint64, onlineCount int, totalCount int, blockTime ...int64) *SecurityAlert {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can create security alerts.
	if caller == (types.Address{}) || !isSystemCaller(caller) {
		return nil
	}

	md.mu.Lock()
	defer md.mu.Unlock()
	md.operations++
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	md.lastActive = now

	if totalCount == 0 {
		return nil
	}

	onlineRatio := float64(onlineCount) / float64(totalCount)
	level := ThreatNone
	if onlineRatio < 0.33 {
		level = ThreatCritical
	} else if onlineRatio < 0.5 {
		level = ThreatHigh
	} else if onlineRatio < 0.67 {
		level = ThreatMedium
	}

	if level == ThreatNone {
		return nil
	}

	alertID := md.nextAlertID
	md.nextAlertID++

	md.partition = PartitionState{
		Detected:      true,
		DetectedAt:    now,
		PartitionSize: totalCount - onlineCount,
		TotalNodes:    totalCount,
	}

	alert := &SecurityAlert{
		ID:          alertID,
		ThreatType:  ThreatTypeNetworkPartition,
		Level:       level,
		Slot:        slot,
		Description: fmt.Sprintf("Network partition detected: %d/%d nodes online (%.1f%%)", onlineCount, totalCount, onlineRatio*100),
		DetectedAt:  now,
	}

	md.addAlertLocked(alert)

	// P3-T2 (2026-07-15): Structured audit log for network partition detection.
	if md.registry != nil {
		md.registry.logAudit(MinistryIDDefense, "detect_network_partition", caller,
			fmt.Sprintf("slot=%d online=%d/%d level=%s", slot, onlineCount, totalCount, level),
			"ok", now)
	}

	return alert
}

func (md *MinistryDefense) DetectCollusion(caller types.Address, slot uint64, validators []int, blockTime ...int64) *SecurityAlert {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can create security alerts.
	if caller == (types.Address{}) || !isSystemCaller(caller) {
		return nil
	}

	md.mu.Lock()
	defer md.mu.Unlock()
	md.operations++
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	md.lastActive = now

	alertID := md.nextAlertID
	md.nextAlertID++

	alert := &SecurityAlert{
		ID:          alertID,
		ThreatType:  ThreatTypeCollusion,
		Level:       ThreatHigh,
		Slot:        slot,
		Description: fmt.Sprintf("Potential collusion detected at slot %d involving %d validators", slot, len(validators)),
		Validators:  validators,
		DetectedAt:  now,
	}

	md.addAlertLocked(alert)
	return alert
}

func (md *MinistryDefense) AddToBlacklist(caller types.Address, validatorIndex int, reason string, duration time.Duration, blockTime ...int64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can blacklist validators.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot blacklist validators")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can blacklist validators")
	}

	// SECURITY (audit GOV-R7-03): Range check — reject out-of-range
	// validator indices before mutating the blacklist map. Prevents
	// silent acceptance of negative or oversized indices that could
	// pollute the blacklist and break slashing / CanAttest / CanSeal
	// lookups (which key by validator index). Performed BEFORE md.mu.Lock()
	// to avoid establishing an md.mu → qpos.mu lock ordering.
	if md.qpos == nil {
		return fmt.Errorf("defense: qpos not initialized; cannot validate validator index %d", validatorIndex)
	}
	vs := md.qpos.GetValidatorSet()
	if vs == nil {
		return fmt.Errorf("defense: validator set not initialized; cannot validate validator index %d", validatorIndex)
	}
	validatorCount := vs.Size()
	if validatorIndex < 0 || validatorIndex >= validatorCount {
		return fmt.Errorf("validator index %d out of range (validator set size=%d)", validatorIndex, validatorCount)
	}

	md.mu.Lock()
	defer md.mu.Unlock()
	md.operations++
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	md.lastActive = now

	if _, exists := md.blacklist[validatorIndex]; exists {
		md.errors++
		return fmt.Errorf("validator %d already blacklisted", validatorIndex)
	}

	entry := &BlacklistEntry{
		ValidatorIndex: validatorIndex,
		Reason:         reason,
		AddedAt:        now,
		Permanent:      duration == 0,
	}

	if duration > 0 {
		entry.ExpiresAt = now.Add(duration)
	}

	md.blacklist[validatorIndex] = entry

	// P3-T2 (2026-07-15): Structured audit log for blacklist addition.
	if md.registry != nil {
		md.registry.logAudit(MinistryIDDefense, "blacklist_add", caller,
			fmt.Sprintf("validator=%d reason=%s permanent=%v", validatorIndex, reason, entry.Permanent),
			"ok", now)
	}

	return nil
}

func (md *MinistryDefense) RemoveFromBlacklist(caller types.Address, validatorIndex int, blockTime ...int64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can remove validators from blacklist.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot remove from blacklist")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can remove from blacklist")
	}

	md.mu.Lock()
	defer md.mu.Unlock()
	md.operations++
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	md.lastActive = now

	if _, exists := md.blacklist[validatorIndex]; !exists {
		md.errors++
		return fmt.Errorf("validator %d not in blacklist", validatorIndex)
	}

	delete(md.blacklist, validatorIndex)
	return nil
}

// IsBlacklisted checks whether a validator is currently blacklisted.
//
// P0-T5 (2026-07-14): The optional blockTime parameter makes the expiry
// check deterministic. When blockTime is provided (by the QPOS consensus
// path via the blacklistCheck callback), the expiry comparison uses the
// consensus block time instead of time.Now(). This prevents consensus
// divergence: two honest nodes with slightly different wall clocks will
// agree on whether a validator is blacklisted because they both use the
// same slot-derived deterministic time.
//
// When blockTime is omitted (e.g., RPC queries, tests), time.Now() is
// used as a fallback — this is safe for non-consensus read paths.
func (md *MinistryDefense) IsBlacklisted(validatorIndex int, blockTime ...int64) bool {
	md.mu.RLock()
	defer md.mu.RUnlock()

	entry, exists := md.blacklist[validatorIndex]
	if !exists {
		return false
	}

	if entry.Permanent {
		return true
	}

	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	if now.After(entry.ExpiresAt) {
		return false
	}

	return true
}

func (md *MinistryDefense) GetBlacklist() []BlacklistEntry {
	md.mu.RLock()
	defer md.mu.RUnlock()

	result := make([]BlacklistEntry, 0, len(md.blacklist))
	for _, entry := range md.blacklist {
		result = append(result, BlacklistEntry{
			ValidatorIndex: entry.ValidatorIndex,
			Reason:         entry.Reason,
			AddedAt:        entry.AddedAt,
			ExpiresAt:      entry.ExpiresAt,
			Permanent:      entry.Permanent,
		})
	}
	return result
}

func (md *MinistryDefense) ResolveAlert(caller types.Address, alertID uint64, blockTime ...int64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can resolve alerts.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot resolve alerts")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can resolve alerts")
	}

	md.mu.Lock()
	defer md.mu.Unlock()
	md.operations++
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	md.lastActive = now

	alert, exists := md.alerts[alertID]
	if !exists {
		md.errors++
		return fmt.Errorf("alert %d not found", alertID)
	}

	alert.Resolved = true
	alert.ResolvedAt = now

	if alert.ThreatType == ThreatTypeNetworkPartition {
		md.partition.Resolved = true
		md.partition.ResolvedAt = now
		md.partition.Detected = false
	}

	return nil
}

func (md *MinistryDefense) GetAlert(alertID uint64) *SecurityAlert {
	md.mu.RLock()
	defer md.mu.RUnlock()

	if a, ok := md.alerts[alertID]; ok {
		copy := &SecurityAlert{
			ID:          a.ID,
			ThreatType:  a.ThreatType,
			Level:       a.Level,
			Slot:        a.Slot,
			Description: a.Description,
			Validators:  append([]int(nil), a.Validators...),
			BlockHash:   a.BlockHash,
			DetectedAt:  a.DetectedAt,
			Resolved:    a.Resolved,
			ResolvedAt:  a.ResolvedAt,
		}
		return copy
	}
	return nil
}

func (md *MinistryDefense) GetActiveAlerts() []*SecurityAlert {
	md.mu.RLock()
	defer md.mu.RUnlock()

	result := make([]*SecurityAlert, 0)
	for _, a := range md.alerts {
		if !a.Resolved {
			copy := &SecurityAlert{
				ID:          a.ID,
				ThreatType:  a.ThreatType,
				Level:       a.Level,
				Slot:        a.Slot,
				Description: a.Description,
				Validators:  append([]int(nil), a.Validators...),
				DetectedAt:  a.DetectedAt,
				Resolved:    a.Resolved,
			}
			result = append(result, copy)
		}
	}
	return result
}

func (md *MinistryDefense) GetPartitionState() PartitionState {
	md.mu.RLock()
	defer md.mu.RUnlock()
	return md.partition
}

// CleanupExpiredBlacklist removes expired entries from the blacklist.
//
// P0-T5 (2026-07-14): The optional blockTime parameter makes the expiry
// check deterministic when called from the consensus path.
func (md *MinistryDefense) CleanupExpiredBlacklist(blockTime ...int64) int {
	md.mu.Lock()
	defer md.mu.Unlock()

	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	removed := 0
	for idx, entry := range md.blacklist {
		if !entry.Permanent && now.After(entry.ExpiresAt) {
			delete(md.blacklist, idx)
			removed++
		}
	}
	return removed
}

func (md *MinistryDefense) addAlertLocked(alert *SecurityAlert) {
	if len(md.alerts) >= md.maxAlerts {
		oldestID := uint64(0)
		oldestTime := time.Now() // NOT consensus-critical: local in-memory tracking
		for id, a := range md.alerts {
			if a.DetectedAt.Before(oldestTime) {
				oldestTime = a.DetectedAt
				oldestID = id
			}
		}
		if oldestID > 0 {
			delete(md.alerts, oldestID)
		}
	}
	md.alerts[alert.ID] = alert
}

func (md *MinistryDefense) GetStatus() map[string]any {
	md.mu.RLock()
	defer md.mu.RUnlock()

	activeAlerts := 0
	criticalAlerts := 0
	for _, a := range md.alerts {
		if !a.Resolved {
			activeAlerts++
			if a.Level == ThreatCritical {
				criticalAlerts++
			}
		}
	}

	return map[string]any{
		"ministry":          MinistryIDDefense.String(),
		"displayName":       MinistryIDDefense.DisplayName(),
		"active":            true,
		"operations":        md.operations,
		"errors":            md.errors,
		"lastActive":        md.lastActive,
		"totalAlerts":       len(md.alerts),
		"activeAlerts":      activeAlerts,
		"criticalAlerts":    criticalAlerts,
		"quantumAlerts":     md.quantumAlerts,
		"blacklistSize":     len(md.blacklist),
		"partitionDetected": md.partition.Detected,
	}
}
