// Quantaureum Node source, version 1.0.0.
package consensus

// Ministry Metrics — P3-T1 (2026-07-15)
//
// Exposes 10 Prometheus metrics for the six governance ministries, organized
// by ministry (Personnel/Revenue/Justice/Defense/Works). Uses the official
// prometheus/client_golang library via promauto, so metrics auto-register
// with the default Prometheus registry and are exposed through the existing
// /metrics/prometheus endpoint (metrics/server.go).
//
// Naming follows the project convention: namespace="qau", subsystem="ministry".
// Counters use the _total suffix per Prometheus best practices.
//
// Metric → spec mapping:
//   personnel_active_validators   → qau_ministry_personnel_active_validators   (gauge)
//   personnel_avg_reputation     → qau_ministry_personnel_avg_reputation     (gauge)
//   revenue_total_distributed    → qau_ministry_revenue_total_distributed    (counter)
//   revenue_total_slashed        → qau_ministry_revenue_total_slashed        (counter)
//   justice_pending_cases        → qau_ministry_justice_pending_cases        (gauge)
//   justice_resolved_cases       → qau_ministry_justice_resolved_cases      (gauge)
//   defense_active_alerts        → qau_ministry_defense_active_alerts        (gauge)
//   defense_blacklist_size       → qau_ministry_defense_blacklist_size       (gauge)
//   works_active_shards          → qau_ministry_works_active_shards          (gauge)
//   works_pending_txs            → qau_ministry_works_pending_txs            (gauge)
//
// Two additional alert-supporting gauges (P3-T3) are registered alongside
// the spec'd metrics, mirroring the rollup/DA pattern of "spec metrics +
// alert-supporting metrics":
//   defense_critical_alerts     → qau_ministry_defense_critical_alerts      (gauge)
//   defense_partition_detected   → qau_ministry_defense_partition_detected  (gauge)
//
// RefreshModel: metrics are NOT updated inline in ministry methods (that would
// require modifying P0–P2 logic). Instead, MinistryRegistry.RefreshMetrics()
// snapshots each ministry's GetStatus() output into the gauges/counters.
// The node calls RefreshMetrics periodically (e.g., at epoch boundaries).
//
// Counter handling: Prometheus counters can only increase. For the Revenue
// counters (total_distributed / total_slashed), RefreshMetrics computes the
// delta from the previously reported value and calls Add(delta). On the
// first refresh after construction (or after a restart), prevRewards /
// prevSlashed are nil and the counter is left at 0 — this matches standard
// Prometheus counter semantics (counter = increases during this process
// lifetime, not lifetime totals).

import (
	"math/big"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

const (
	ministryMetricsNamespace = "qau"
	ministryMetricsSubsystem = "ministry"
)

// MinistryMetrics holds all Prometheus metrics for the six governance
// ministries. P3-T1 (2026-07-15).
//
// All convenience methods are nil-safe: they early-return when m is nil, so
// callers can invoke them unconditionally even when ministry metrics are
// disabled (e.g., in tests that construct ministries directly).
type MinistryMetrics struct {
	// === Personnel ===
	PersonnelActiveValidators prometheus.Gauge
	PersonnelAvgReputation    prometheus.Gauge

	// === Revenue ===
	// Counters — only increase during this process lifetime. The
	// prevRewards/prevSlashed fields track the last reported big.Int value
	// so RefreshMetrics can compute the delta via Add(delta).
	RevenueTotalDistributed prometheus.Counter
	RevenueTotalSlashed     prometheus.Counter

	// === Justice ===
	JusticePendingCases  prometheus.Gauge
	JusticeResolvedCases prometheus.Gauge

	// === Defense ===
	DefenseActiveAlerts  prometheus.Gauge
	DefenseBlacklistSize prometheus.Gauge
	// Alert-supporting metrics (P3-T3). Mirror the rollup/DA pattern of
	// "spec metrics + alert-supporting metrics".
	DefenseCriticalAlerts    prometheus.Gauge
	DefensePartitionDetected prometheus.Gauge

	// === Works ===
	WorksActiveShards prometheus.Gauge
	WorksPendingTxs   prometheus.Gauge

	// Internal: previous big.Int values for Revenue counters, used to
	// compute counter deltas in RefreshMetrics. Guarded by the metrics
	// struct's own usage (RefreshMetrics is called from a single goroutine
	// in the node's epoch loop; concurrent refresh is not expected).
	prevRewards *big.Int
	prevSlashed *big.Int
}

// NewMinistryMetrics creates and registers all ministry Prometheus metrics
// with the default Prometheus registry. Metrics are automatically exposed
// through promhttp.Handler() (the /metrics/prometheus endpoint in
// metrics/server.go).
//
// NOTE: This function panics if called more than once (promauto registers
// with the global default registry, which rejects duplicates). For testing,
// use NewMinistryMetricsWithRegistry with a fresh prometheus.NewRegistry().
func NewMinistryMetrics() *MinistryMetrics {
	return NewMinistryMetricsWithRegistry(prometheus.DefaultRegisterer)
}

// NewMinistryMetricsWithRegistry creates and registers all ministry
// Prometheus metrics with the given registerer. Pass
// prometheus.DefaultRegisterer for production, or a fresh
// prometheus.NewRegistry() for isolated tests.
func NewMinistryMetricsWithRegistry(reg prometheus.Registerer) *MinistryMetrics {
	factory := promauto.With(reg)

	return &MinistryMetrics{
		PersonnelActiveValidators: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "personnel_active_validators",
			Help:      "Number of active validators tracked by the Personnel ministry (reputation >= default).",
		}),
		PersonnelAvgReputation: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "personnel_avg_reputation",
			Help:      "Average reputation score across all validators tracked by the Personnel ministry.",
		}),

		RevenueTotalDistributed: factory.NewCounter(prometheus.CounterOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "revenue_total_distributed",
			Help:      "Total QAU rewards distributed by the Revenue ministry (counter, process-lifetime increments).",
		}),
		RevenueTotalSlashed: factory.NewCounter(prometheus.CounterOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "revenue_total_slashed",
			Help:      "Total QAU slashed by the Revenue ministry (counter, process-lifetime increments).",
		}),

		JusticePendingCases: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "justice_pending_cases",
			Help:      "Number of pending dispute cases in the Justice ministry.",
		}),
		JusticeResolvedCases: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "justice_resolved_cases",
			Help:      "Number of resolved dispute cases in the Justice ministry.",
		}),

		DefenseActiveAlerts: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "defense_active_alerts",
			Help:      "Number of unresolved security alerts in the Defense ministry.",
		}),
		DefenseBlacklistSize: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "defense_blacklist_size",
			Help:      "Number of validators currently blacklisted by the Defense ministry.",
		}),
		DefenseCriticalAlerts: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "defense_critical_alerts",
			Help:      "Number of unresolved CRITICAL-level alerts in the Defense ministry (alert-supporting, P3-T3).",
		}),
		DefensePartitionDetected: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "defense_partition_detected",
			Help:      "1 when a network partition is currently detected by the Defense ministry, 0 otherwise (alert-supporting, P3-T3).",
		}),

		WorksActiveShards: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "works_active_shards",
			Help:      "Number of active shards tracked by the Works ministry.",
		}),
		WorksPendingTxs: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ministryMetricsNamespace,
			Subsystem: ministryMetricsSubsystem,
			Name:      "works_pending_txs",
			Help:      "Number of pending cross-chain transactions across all active bridges (Works ministry).",
		}),
	}
}

// --- Convenience helpers (nil-safe) ---

// SetPersonnelActiveValidators sets the personnel_active_validators gauge.
func (m *MinistryMetrics) SetPersonnelActiveValidators(n int) {
	if m == nil {
		return
	}
	m.PersonnelActiveValidators.Set(float64(n))
}

// SetPersonnelAvgReputation sets the personnel_avg_reputation gauge.
func (m *MinistryMetrics) SetPersonnelAvgReputation(score int) {
	if m == nil {
		return
	}
	m.PersonnelAvgReputation.Set(float64(score))
}

// AddRevenueDistributed adds delta to the revenue_total_distributed counter.
// Callers must ensure delta >= 0 (Prometheus counters are monotonic).
func (m *MinistryMetrics) AddRevenueDistributed(delta *big.Int) {
	if m == nil || delta == nil || delta.Sign() <= 0 {
		return
	}
	f, _ := delta.Float64()
	m.RevenueTotalDistributed.Add(f)
}

// AddRevenueSlashed adds delta to the revenue_total_slashed counter.
// Callers must ensure delta >= 0 (Prometheus counters are monotonic).
// audit-remediation: reviewed 2026-09-11 — metrics counter only; does not touch validator stake.
func (m *MinistryMetrics) AddRevenueSlashed(delta *big.Int) {
	if m == nil || delta == nil || delta.Sign() <= 0 {
		return
	}
	f, _ := delta.Float64()
	m.RevenueTotalSlashed.Add(f)
}

// SetJusticePendingCases sets the justice_pending_cases gauge.
func (m *MinistryMetrics) SetJusticePendingCases(n int) {
	if m == nil {
		return
	}
	m.JusticePendingCases.Set(float64(n))
}

// SetJusticeResolvedCases sets the justice_resolved_cases gauge.
func (m *MinistryMetrics) SetJusticeResolvedCases(n int) {
	if m == nil {
		return
	}
	m.JusticeResolvedCases.Set(float64(n))
}

// SetDefenseActiveAlerts sets the defense_active_alerts gauge.
func (m *MinistryMetrics) SetDefenseActiveAlerts(n int) {
	if m == nil {
		return
	}
	m.DefenseActiveAlerts.Set(float64(n))
}

// SetDefenseBlacklistSize sets the defense_blacklist_size gauge.
func (m *MinistryMetrics) SetDefenseBlacklistSize(n int) {
	if m == nil {
		return
	}
	m.DefenseBlacklistSize.Set(float64(n))
}

// SetDefenseCriticalAlerts sets the defense_critical_alerts gauge.
func (m *MinistryMetrics) SetDefenseCriticalAlerts(n int) {
	if m == nil {
		return
	}
	m.DefenseCriticalAlerts.Set(float64(n))
}

// SetDefensePartitionDetected sets the defense_partition_detected gauge
// (1=detected, 0=healthy).
func (m *MinistryMetrics) SetDefensePartitionDetected(detected bool) {
	if m == nil {
		return
	}
	if detected {
		m.DefensePartitionDetected.Set(1)
	} else {
		m.DefensePartitionDetected.Set(0)
	}
}

// SetWorksActiveShards sets the works_active_shards gauge.
func (m *MinistryMetrics) SetWorksActiveShards(n int) {
	if m == nil {
		return
	}
	m.WorksActiveShards.Set(float64(n))
}

// SetWorksPendingTxs sets the works_pending_txs gauge.
func (m *MinistryMetrics) SetWorksPendingTxs(n int) {
	if m == nil {
		return
	}
	m.WorksPendingTxs.Set(float64(n))
}

// --- MinistryMetricProvider implementation (P3-T3) ---
//
// These methods read the current Prometheus metric values for the alert
// manager. The metrics package defines the MinistryMetricProvider interface;
// *MinistryMetrics satisfies it without the metrics package needing to import
// consensus (dependency injection via interface).
//
// ministryReadMetricValue extracts the float64 value from a Prometheus
// Metric using the dto.Metric.Write() API. For gauges it returns the
// current value; for counters it returns the cumulative count.
func ministryReadMetricValue(m prometheus.Metric) float64 {
	if m == nil {
		return 0
	}
	pb := &dto.Metric{}
	if err := m.Write(pb); err != nil {
		return 0
	}
	if pb.Gauge != nil {
		return pb.Gauge.GetValue()
	}
	if pb.Counter != nil {
		return pb.Counter.GetValue()
	}
	return 0
}

// CriticalAlertsValue returns the current defense_critical_alerts value.
// Used by the "ministry_quantum_attack_detected" alert rule — fires when
// value > 0 (any unresolved critical alert, including quantum attacks).
func (m *MinistryMetrics) CriticalAlertsValue() float64 {
	if m == nil {
		return 0
	}
	return ministryReadMetricValue(m.DefenseCriticalAlerts)
}

// PartitionDetectedValue returns the current defense_partition_detected
// value (1=detected, 0=healthy). Used by the
// "ministry_network_partition_detected" alert rule — fires when value > 0.5.
func (m *MinistryMetrics) PartitionDetectedValue() float64 {
	if m == nil {
		return 0
	}
	return ministryReadMetricValue(m.DefensePartitionDetected)
}

// BlacklistSizeValue returns the current defense_blacklist_size value.
// Used by the "ministry_blacklist_spike" alert rule — fires when > 10.
func (m *MinistryMetrics) BlacklistSizeValue() float64 {
	if m == nil {
		return 0
	}
	return ministryReadMetricValue(m.DefenseBlacklistSize)
}

// PendingCasesValue returns the current justice_pending_cases value.
// Used by the "ministry_pending_cases_backlog" alert rule — fires when > 50.
func (m *MinistryMetrics) PendingCasesValue() float64 {
	if m == nil {
		return 0
	}
	return ministryReadMetricValue(m.JusticePendingCases)
}
