// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

type MinistryID uint8

const (
	MinistryIDNone      MinistryID = 0
	MinistryIDPersonnel MinistryID = 1
	MinistryIDRevenue   MinistryID = 2
	MinistryIDJustice   MinistryID = 3
	MinistryIDDefense   MinistryID = 4
	MinistryIDRites     MinistryID = 5
	MinistryIDWorks     MinistryID = 6
)

func (m MinistryID) String() string {
	switch m {
	case MinistryIDNone:
		return "None"
	case MinistryIDPersonnel:
		return "Personnel"
	case MinistryIDRevenue:
		return "Revenue"
	case MinistryIDJustice:
		return "Justice"
	case MinistryIDDefense:
		return "Defense"
	case MinistryIDRites:
		return "Rites"
	case MinistryIDWorks:
		return "Works"
	default:
		return fmt.Sprintf("Unknown(%d)", m)
	}
}

func (m MinistryID) DisplayName() string {
	switch m {
	case MinistryIDNone:
		return "None"
	case MinistryIDPersonnel:
		return "Personnel"
	case MinistryIDRevenue:
		return "Revenue"
	case MinistryIDJustice:
		return "Justice"
	case MinistryIDDefense:
		return "Defense"
	case MinistryIDRites:
		return "Rites"
	case MinistryIDWorks:
		return "Works"
	default:
		return fmt.Sprintf("Unknown(%d)", m)
	}
}

type MinistryStatus struct {
	ID         MinistryID
	Name       string
	Active     bool
	Operations uint64
	Errors     uint64
	LastActive time.Time
}

type MinistryRegistry struct {
	mu sync.RWMutex

	qpos        *QPOS
	coordinator *ThreeChambersCoordinator

	personnel *MinistryPersonnel
	revenue   *MinistryRevenue
	justice   *MinistryJustice
	defense   *MinistryDefense
	rites     *MinistryRites
	works     *MinistryWorks

	// P3-T1 (2026-07-15): Prometheus metrics for the six ministries.
	// Set via SetMetrics; nil when metrics are disabled (e.g., in tests
	// that construct ministries directly without wiring metrics).
	// RefreshMetrics() snapshots each ministry's GetStatus() into the
	// gauges/counters. Safe to leave nil — RefreshMetrics is a no-op.
	metrics *MinistryMetrics

	// P3-T2 (2026-07-15): AuditLogger for structured audit trail of key
	// state changes (slashing, reward distribution, blacklist, dispute
	// resolution). Set via SetAuditLogger; nil when no logger is wired.
	// logAudit is a nil-safe helper.
	audit AuditLogger
}

// AuditLogger records structured audit entries for key ministry state changes.
// P3-T2 (2026-07-15): Implementations write to a durable, append-only audit
// log (e.g., a separate BoltDB bucket, a file, or a remote SIEM). The
// interface is minimal so it can be satisfied by anything from a no-op
// logger to a tamper-evident WORM store.
//
// The fields mirror the classic who/what/when/result audit pattern:
//   - ministry: which of the six ministries performed the action
//   - action:   short verb (e.g., "slash", "distribute_rewards", "blacklist_add")
//   - who:      the authorized caller that triggered the action (system caller)
//   - what:     free-form detail (e.g., "validator=3 reason=DoubleSigning amount=1000")
//   - result:   "ok" on success, or the error string on failure
//   - when:     deterministic block time when known, else time.Now()
type AuditLogger interface {
	LogAudit(ministry MinistryID, action string, who types.Address, what string, result string, when time.Time)
}

// NewMinistryRegistry creates a registry of the six governance ministries.
//
// AUDIT (2026) GOV-08 (Info): The ministry registry is currently only
// instantiated in read-only RPC (GetMinistryStatus) for status reporting.
// It is NOT wired into the node or consensus execution path — all
// state-changing ministry methods are dead code in production. The GOV-03
// authorization checks on all state-changing methods ensure that even when
// the ministries are eventually wired in, unauthorized callers cannot
// mutate state.
func NewMinistryRegistry(qpos *QPOS, coordinator *ThreeChambersCoordinator) *MinistryRegistry {
	mr := &MinistryRegistry{
		qpos:        qpos,
		coordinator: coordinator,
	}
	mr.personnel = NewMinistryPersonnel(qpos, coordinator, mr)
	mr.revenue = NewMinistryRevenue(qpos, coordinator, mr)
	mr.justice = NewMinistryJustice(qpos, coordinator, mr)
	mr.defense = NewMinistryDefense(qpos, coordinator, mr)
	mr.rites = NewMinistryRites(qpos, coordinator, mr)
	mr.works = NewMinistryWorks(qpos, coordinator, mr)

	// P0-T2: Wire Defense ministry blacklist into QPOS consensus checks.
	// CanPropose/CanAttest/CanSeal will reject blacklisted validators.
	if qpos != nil && mr.defense != nil {
		qpos.SetBlacklistCheck(mr.defense.IsBlacklisted)
	}

	// P1-T3 (2026-07-14): Wire MinistryRevenue into SlashingManager so that
	// every slashing event is recorded in the ministry's slashRecords for
	// governance visibility. The SlashingManager must already be set on QPOS
	// (via SetSlashingManager) before NewMinistryRegistry is called.
	if qpos != nil && qpos.slashingManager != nil && mr.revenue != nil {
		qpos.slashingManager.SetMinistryRevenue(mr.revenue)
	}

	// P1-T4 (2026-07-14): Wire MinistryPersonnel into SlashingManager's
	// ValidatorManager so that every validator registration is recorded in
	// the Personnel reputation system for governance visibility.
	if qpos != nil && qpos.slashingManager != nil && qpos.slashingManager.validatorMgr != nil && mr.personnel != nil {
		qpos.slashingManager.validatorMgr.SetMinistryPersonnel(mr.personnel)
	}

	return mr
}

func (mr *MinistryRegistry) Personnel() *MinistryPersonnel {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.personnel
}

func (mr *MinistryRegistry) Revenue() *MinistryRevenue {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.revenue
}

func (mr *MinistryRegistry) Justice() *MinistryJustice {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.justice
}

func (mr *MinistryRegistry) Defense() *MinistryDefense {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.defense
}

func (mr *MinistryRegistry) Rites() *MinistryRites {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.rites
}

func (mr *MinistryRegistry) Works() *MinistryWorks {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.works
}

func (mr *MinistryRegistry) GetStatus() map[string]any {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	return map[string]any{
		"personnel": mr.personnel.GetStatus(),
		"revenue":   mr.revenue.GetStatus(),
		"justice":   mr.justice.GetStatus(),
		"defense":   mr.defense.GetStatus(),
		"rites":     mr.rites.GetStatus(),
		"works":     mr.works.GetStatus(),
	}
}

func (mr *MinistryRegistry) GetMinistryStatus(id MinistryID) *MinistryStatus {
	switch id {
	case MinistryIDPersonnel:
		st := mr.personnel.GetStatus()
		return ministryStatusFromMap(MinistryIDPersonnel, st)
	case MinistryIDRevenue:
		st := mr.revenue.GetStatus()
		return ministryStatusFromMap(MinistryIDRevenue, st)
	case MinistryIDJustice:
		st := mr.justice.GetStatus()
		return ministryStatusFromMap(MinistryIDJustice, st)
	case MinistryIDDefense:
		st := mr.defense.GetStatus()
		return ministryStatusFromMap(MinistryIDDefense, st)
	case MinistryIDRites:
		st := mr.rites.GetStatus()
		return ministryStatusFromMap(MinistryIDRites, st)
	case MinistryIDWorks:
		st := mr.works.GetStatus()
		return ministryStatusFromMap(MinistryIDWorks, st)
	default:
		return nil
	}
}

func ministryStatusFromMap(id MinistryID, m map[string]any) *MinistryStatus {
	st := &MinistryStatus{ID: id, Name: id.DisplayName()}
	if v, ok := m["active"]; ok {
		if b, ok := v.(bool); ok { // CS-02 FIX: comma-ok guard against panic
			st.Active = b
		}
	}
	if v, ok := m["operations"]; ok {
		if n, ok := v.(uint64); ok { // CS-02 FIX: comma-ok guard against panic
			st.Operations = n
		}
	}
	if v, ok := m["errors"]; ok {
		if n, ok := v.(uint64); ok { // CS-02 FIX: comma-ok guard against panic
			st.Errors = n
		}
	}
	if v, ok := m["lastActive"]; ok {
		if t, ok := v.(time.Time); ok {
			st.LastActive = t
		}
	}
	return st
}

// SetMetrics injects a MinistryMetrics instance. P3-T1 (2026-07-15).
// Pass nil to disable metrics (e.g., in tests). After injection, call
// RefreshMetrics() periodically (e.g., at epoch boundaries) to snapshot
// each ministry's GetStatus() output into Prometheus gauges/counters.
func (mr *MinistryRegistry) SetMetrics(m *MinistryMetrics) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.metrics = m
}

// SetAuditLogger injects an AuditLogger. P3-T2 (2026-07-15).
// Pass nil to disable audit logging. After injection, logAudit() calls
// in ministry methods will write structured audit entries.
func (mr *MinistryRegistry) SetAuditLogger(l AuditLogger) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.audit = l
}

// RefreshMetrics snapshots each ministry's GetStatus() output into the
// Prometheus metrics. P3-T1 (2026-07-15).
//
// For gauges (Personnel/Justice/Defense/Works), the current value is set
// directly. For Revenue counters (total_distributed / total_slashed), the
// delta from the previous refresh is computed and added — Prometheus
// counters can only increase, so a decrease in the source total (which
// should never happen in practice) is clamped to 0.
//
// Nil-safe: no-op when metrics == nil.
// Not safe for concurrent calls — intended to be invoked from the node's
// epoch loop (single goroutine).
func (mr *MinistryRegistry) RefreshMetrics() {
	mr.mu.RLock()
	metrics := mr.metrics
	personnel := mr.personnel
	revenue := mr.revenue
	justice := mr.justice
	defense := mr.defense
	works := mr.works
	mr.mu.RUnlock()

	if metrics == nil {
		return
	}

	// Personnel: activeCount, avgReputation
	if personnel != nil {
		st := personnel.GetStatus()
		metrics.SetPersonnelActiveValidators(ministryMapToInt(st["activeCount"]))
		metrics.SetPersonnelAvgReputation(ministryMapToInt(st["avgReputation"]))
	}

	// Revenue: counters via delta from GetFinancialSummary
	if revenue != nil {
		summary := revenue.GetFinancialSummary()
		rewardsStr, _ := summary["totalRewardsDistributed"].(string)
		slashedStr, _ := summary["totalSlashed"].(string)

		rewards := ministryParseBig(rewardsStr)
		slashed := ministryParseBig(slashedStr)

		// Compute deltas (clamp negative to 0). On the first refresh
		// after construction, prev is nil so we only establish the
		// baseline without incrementing the counter.
		if metrics.prevRewards != nil {
			delta := new(big.Int).Sub(rewards, metrics.prevRewards)
			if delta.Sign() > 0 {
				metrics.AddRevenueDistributed(delta)
			}
		}
		if metrics.prevSlashed != nil {
			delta := new(big.Int).Sub(slashed, metrics.prevSlashed)
			if delta.Sign() > 0 {
				metrics.AddRevenueSlashed(delta)
			}
		}
		metrics.prevRewards = rewards
		metrics.prevSlashed = slashed
	}

	// Justice: pending, resolved
	if justice != nil {
		st := justice.GetStatus()
		metrics.SetJusticePendingCases(ministryMapToInt(st["pending"]))
		metrics.SetJusticeResolvedCases(ministryMapToInt(st["resolved"]))
	}

	// Defense: activeAlerts, blacklistSize, criticalAlerts, partitionDetected
	if defense != nil {
		st := defense.GetStatus()
		metrics.SetDefenseActiveAlerts(ministryMapToInt(st["activeAlerts"]))
		metrics.SetDefenseBlacklistSize(ministryMapToInt(st["blacklistSize"]))
		metrics.SetDefenseCriticalAlerts(ministryMapToInt(st["criticalAlerts"]))
		if partitionDetected, ok := st["partitionDetected"].(bool); ok {
			metrics.SetDefensePartitionDetected(partitionDetected)
		}
	}

	// Works: activeShards, pendingTxs
	if works != nil {
		st := works.GetStatus()
		metrics.SetWorksActiveShards(ministryMapToInt(st["activeShards"]))
		metrics.SetWorksPendingTxs(ministryMapToInt(st["pendingTxs"]))
	}
}

// logAudit is a nil-safe helper that records a structured audit entry.
// P3-T2 (2026-07-15). When no AuditLogger is wired (audit == nil), this
// is a no-op. The caller is responsible for composing the "what" detail
// string; the logger implementation handles persistence (file, DB, SIEM).
func (mr *MinistryRegistry) logAudit(ministry MinistryID, action string, who types.Address, what string, result string, when time.Time) {
	mr.mu.RLock()
	audit := mr.audit
	mr.mu.RUnlock()

	if audit == nil {
		return
	}
	audit.LogAudit(ministry, action, who, what, result, when)
}

// ministryMapToInt safely extracts an int from a map[string]any value.
// Returns 0 when the value is missing or not an int.
func ministryMapToInt(v any) int {
	if n, ok := v.(int); ok {
		return n
	}
	return 0
}

// ministryParseBig parses a decimal string into a *big.Int. Returns 0 on
// empty string or parse failure. Used by RefreshMetrics for Revenue totals.
func ministryParseBig(s string) *big.Int {
	if s == "" {
		return big.NewInt(0)
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return big.NewInt(0)
	}
	return n
}
