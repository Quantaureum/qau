// Quantaureum Node source, version 1.0.0.
package rollup

// Rollup Metrics — W-P3-1 (2026-07-14)
//
// Exposes 10 Prometheus metrics for L2 rollup monitoring. Uses the official
// prometheus/client_golang library via promauto, so metrics auto-register
// with the default Prometheus registry and are exposed through the existing
// /metrics/prometheus endpoint (metrics/server.go).
//
// Naming follows the project convention: namespace="qau", subsystem="rollup".
// Counters use the _total suffix per Prometheus best practices.
//
// Metric → spec mapping:
//   rollup_status                    → qau_rollup_status              (gauge)
//   rollup_total_batches             → qau_rollup_batches_total       (counter)
//   rollup_total_txs                 → qau_rollup_transactions_total  (counter)
//   rollup_pending_txs               → qau_rollup_pending_transactions(gauge)
//   rollup_batch_build_duration      → qau_rollup_batch_build_duration_seconds    (histogram)
//   rollup_batch_submit_duration     → qau_rollup_batch_submit_duration_seconds   (histogram)
//   rollup_batch_process_duration    → qau_rollup_batch_process_duration_seconds  (histogram)
//   rollup_fraud_proofs_submitted    → qau_rollup_fraud_proofs_submitted_total   (counter)
//   rollup_fraud_proofs_verified     → qau_rollup_fraud_proofs_verified_total    (counter)
//   rollup_l1_anchor_lag             → qau_rollup_l1_anchor_lag       (gauge)

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

const (
	rollupNamespace = "qau"
	rollupSubsystem = "rollup"
)

// RollupMetrics holds all Prometheus metrics for the L2 rollup engine.
// W-P3-1 (2026-07-14)
type RollupMetrics struct {
	// rollup_status: 0=stopped, 1=running, 2=paused, 3=stopping
	Status prometheus.Gauge

	// rollup_total_batches: total batches successfully submitted
	TotalBatches prometheus.Counter

	// rollup_total_txs: total L2 transactions processed across all batches
	TotalTxs prometheus.Counter

	// rollup_pending_txs: current number of pending L2 transactions awaiting batch inclusion
	PendingTxs prometheus.Gauge

	// rollup_batch_build_duration: time to build a batch from pending transactions
	BatchBuildDuration prometheus.Histogram

	// rollup_batch_submit_duration: time to submit a batch (state root update + persistence + L1 anchor)
	BatchSubmitDuration prometheus.Histogram

	// rollup_batch_process_duration: time to execute L2 transactions and compute the post-state root
	BatchProcessDuration prometheus.Histogram

	// rollup_fraud_proofs_submitted: total fraud proofs submitted for verification
	FraudProofsSubmitted prometheus.Counter

	// rollup_fraud_proofs_verified: total fraud proofs that passed verification
	FraudProofsVerified prometheus.Counter

	// rollup_l1_anchor_lag: L1 block lag since the most recent batch anchor (currentHeight - lastAnchorHeight)
	L1AnchorLag prometheus.Gauge

	// W-P3-2 (2026-07-14): Consecutive batch failures — incremented on each
	// Build/Process/Submit error or panic, reset to 0 on success. Used by the
	// "consecutive_batch_failures > 5" alert rule.
	ConsecutiveBatchFailures prometheus.Gauge

	// W-P3-3 (2026-07-14): Total panics recovered in batchLoop + finalizeLoop.
	// Any non-zero value is critical — a panic means the batch/finalize cycle
	// was disrupted, even though the node survived (thanks to recover()).
	BatchLoopPanics prometheus.Counter
}

// NewRollupMetrics creates and registers all rollup Prometheus metrics with
// the default Prometheus registry. Metrics are automatically exposed through
// promhttp.Handler() (the /metrics/prometheus endpoint in metrics/server.go).
//
// NOTE: This function panics if called more than once (promauto registers with
// the global default registry, which rejects duplicates). For testing, use
// NewRollupMetricsWithRegistry with a fresh prometheus.NewRegistry().
func NewRollupMetrics() *RollupMetrics {
	return NewRollupMetricsWithRegistry(prometheus.DefaultRegisterer)
}

// NewRollupMetricsWithRegistry creates and registers all rollup Prometheus
// metrics with the given registerer. Pass prometheus.DefaultRegisterer for
// production, or a fresh prometheus.NewRegistry() for isolated tests.
func NewRollupMetricsWithRegistry(reg prometheus.Registerer) *RollupMetrics {
	factory := promauto.With(reg)

	// Histogram buckets for batch operations (seconds).
	// Rollup batches are lightweight (in-memory state transitions), so the
	// buckets focus on the 1ms–5s range.
	batchDurationBuckets := prometheus.ExponentialBuckets(0.001, 2, 13) // 1ms → ~4s

	return &RollupMetrics{
		Status: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "status",
			Help:      "Rollup engine status: 0=stopped, 1=running, 2=paused, 3=stopping",
		}),

		TotalBatches: factory.NewCounter(prometheus.CounterOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "batches_total",
			Help:      "Total number of batches successfully submitted",
		}),

		TotalTxs: factory.NewCounter(prometheus.CounterOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "transactions_total",
			Help:      "Total number of L2 transactions processed across all batches",
		}),

		PendingTxs: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "pending_transactions",
			Help:      "Current number of pending L2 transactions awaiting batch inclusion",
		}),

		BatchBuildDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "batch_build_duration_seconds",
			Help:      "Time to build a batch from pending transactions",
			Buckets:   batchDurationBuckets,
		}),

		BatchSubmitDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "batch_submit_duration_seconds",
			Help:      "Time to submit a batch (state root update + persistence + L1 anchor)",
			Buckets:   batchDurationBuckets,
		}),

		BatchProcessDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "batch_process_duration_seconds",
			Help:      "Time to execute L2 transactions and compute the post-state root",
			Buckets:   batchDurationBuckets,
		}),

		FraudProofsSubmitted: factory.NewCounter(prometheus.CounterOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "fraud_proofs_submitted_total",
			Help:      "Total number of fraud proofs submitted for verification",
		}),

		FraudProofsVerified: factory.NewCounter(prometheus.CounterOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "fraud_proofs_verified_total",
			Help:      "Total number of fraud proofs that passed verification",
		}),

		L1AnchorLag: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "l1_anchor_lag",
			Help:      "L1 block lag since the most recent batch anchor (currentL1Height - lastAnchorSubmitHeight)",
		}),

		// W-P3-2: Consecutive batch failures gauge.
		ConsecutiveBatchFailures: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "consecutive_batch_failures",
			Help:      "Consecutive batch build/process/submit failures (reset to 0 on success)",
		}),

		// W-P3-3: Total panics recovered in batchLoop + finalizeLoop.
		BatchLoopPanics: factory.NewCounter(prometheus.CounterOpts{
			Namespace: rollupNamespace,
			Subsystem: rollupSubsystem,
			Name:      "batch_loop_panics_total",
			Help:      "Total panics recovered in batchLoop and finalizeLoop (any non-zero value is critical)",
		}),
	}
}

// --- Convenience helpers for the engine ---

// SetStatus updates the rollup_status gauge from a RollupStatus value.
func (m *RollupMetrics) SetStatus(status RollupStatus) {
	if m == nil {
		return
	}
	m.Status.Set(float64(status))
}

// IncBatches increments the total_batches counter by 1.
func (m *RollupMetrics) IncBatches() {
	if m == nil {
		return
	}
	m.TotalBatches.Inc()
}

// AddTxs adds n to the total_txs counter.
func (m *RollupMetrics) AddTxs(n uint64) {
	if m == nil {
		return
	}
	m.TotalTxs.Add(float64(n))
}

// SetPendingTxs sets the pending_txs gauge.
func (m *RollupMetrics) SetPendingTxs(n int) {
	if m == nil {
		return
	}
	m.PendingTxs.Set(float64(n))
}

// ObserveBuildDuration records a batch build duration.
func (m *RollupMetrics) ObserveBuildDuration(d time.Duration) {
	if m == nil {
		return
	}
	m.BatchBuildDuration.Observe(d.Seconds())
}

// ObserveSubmitDuration records a batch submit duration.
func (m *RollupMetrics) ObserveSubmitDuration(d time.Duration) {
	if m == nil {
		return
	}
	m.BatchSubmitDuration.Observe(d.Seconds())
}

// ObserveProcessDuration records a batch process duration.
func (m *RollupMetrics) ObserveProcessDuration(d time.Duration) {
	if m == nil {
		return
	}
	m.BatchProcessDuration.Observe(d.Seconds())
}

// IncFraudProofSubmitted increments the fraud_proofs_submitted counter.
func (m *RollupMetrics) IncFraudProofSubmitted() {
	if m == nil {
		return
	}
	m.FraudProofsSubmitted.Inc()
}

// IncFraudProofVerified increments the fraud_proofs_verified counter.
func (m *RollupMetrics) IncFraudProofVerified() {
	if m == nil {
		return
	}
	m.FraudProofsVerified.Inc()
}

// SetL1AnchorLag sets the l1_anchor_lag gauge (L1 blocks since last anchor).
func (m *RollupMetrics) SetL1AnchorLag(lag uint64) {
	if m == nil {
		return
	}
	m.L1AnchorLag.Set(float64(lag))
}

// SetConsecutiveBatchFailures sets the consecutive_batch_failures gauge.
// W-P3-2 (2026-07-14): Called by the engine on each batch success (reset to 0)
// or failure (increment). The alert rule fires when this exceeds 5.
func (m *RollupMetrics) SetConsecutiveBatchFailures(n uint64) {
	if m == nil {
		return
	}
	m.ConsecutiveBatchFailures.Set(float64(n))
}

// IncBatchLoopPanic increments the batch_loop_panics_total counter.
// W-P3-3 (2026-07-14): Called from recover() blocks in tryBuildAndSubmitBatch
// and tryFinalizeBatches. Any non-zero value triggers a critical alert.
func (m *RollupMetrics) IncBatchLoopPanic() {
	if m == nil {
		return
	}
	m.BatchLoopPanics.Inc()
}

// --- RollupMetricProvider implementation (W-P3-2) ---
//
// These methods read the current Prometheus metric values for the alert
// manager. The metrics package defines the RollupMetricProvider interface;
// *RollupMetrics satisfies it without the metrics package needing to import
// rollup (dependency injection via interface).
//
// readMetricValue extracts the float64 value from a Prometheus Metric using
// the dto.Metric.Write() API. For gauges it returns the current value; for
// counters it returns the cumulative count.

func readMetricValue(m prometheus.Metric) float64 {
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

// StatusValue returns the current rollup_status value (0=stopped, 1=running).
func (m *RollupMetrics) StatusValue() float64 {
	if m == nil {
		return 0
	}
	return readMetricValue(m.Status)
}

// PendingTxsValue returns the current pending_transactions count.
func (m *RollupMetrics) PendingTxsValue() float64 {
	if m == nil {
		return 0
	}
	return readMetricValue(m.PendingTxs)
}

// L1AnchorLagValue returns the current L1 anchor lag (L1 blocks since last anchor).
func (m *RollupMetrics) L1AnchorLagValue() float64 {
	if m == nil {
		return 0
	}
	return readMetricValue(m.L1AnchorLag)
}

// FraudProofsSubmittedValue returns the cumulative fraud_proofs_submitted_total.
func (m *RollupMetrics) FraudProofsSubmittedValue() float64 {
	if m == nil {
		return 0
	}
	return readMetricValue(m.FraudProofsSubmitted)
}

// ConsecutiveBatchFailuresValue returns the current consecutive failure count.
func (m *RollupMetrics) ConsecutiveBatchFailuresValue() float64 {
	if m == nil {
		return 0
	}
	return readMetricValue(m.ConsecutiveBatchFailures)
}

// BatchLoopPanicsValue returns the cumulative batch_loop_panics_total.
func (m *RollupMetrics) BatchLoopPanicsValue() float64 {
	if m == nil {
		return 0
	}
	return readMetricValue(m.BatchLoopPanics)
}
