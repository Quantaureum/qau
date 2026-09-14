// Quantaureum Node source, version 1.0.0.
package consensus

// Shard Metrics — P3-1 (2026-07-15)
//
// Exposes 8 Prometheus metrics for shard subsystem monitoring. Uses the
// official prometheus/client_golang library via promauto, so metrics
// auto-register with the default Prometheus registry and are exposed through
// the existing /metrics/prometheus endpoint (metrics/server.go).
//
// Naming follows the project convention: namespace="qau", subsystem="shard".
// Counters use the _total suffix per Prometheus best practices.
//
// Metric → spec mapping:
//   shard_count                          → qau_shard_count                              (gauge)
//   shard_block_height                   → qau_shard_block_height                       (gauge, labels: shard_id)
//   shard_cross_shard_messages_total     → qau_shard_cross_shard_messages_total         (counter)
//   shard_pending_messages               → qau_shard_pending_messages                   (gauge, labels: shard_id)
//   shard_finalization_delay_seconds     → qau_shard_finalization_delay_seconds         (histogram)
//   shard_p2p_messages_total             → qau_shard_p2p_messages_total                 (counter, labels: type)
//   shard_validator_count                → qau_shard_validator_count                    (gauge, labels: shard_id)
//   shard_commitment_lag                 → qau_shard_commitment_lag                     (gauge, labels: shard_id)
//
// All helper methods are nil-safe: callers can invoke them unconditionally
// even when shard metrics are disabled (e.g., QAU_ENABLE_SHARDING != "1").

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

const (
	shardMetricsNamespace = "qau"
	shardMetricsSubsystem = "shard"
)

// ShardMetrics holds all Prometheus metrics for the shard subsystem.
// P3-1 (2026-07-15).
//
// All fields are nil-safe: the convenience methods (SetShardCount,
// IncCrossShardMessages, etc.) early-return when m is nil, so callers can
// invoke them unconditionally even when sharding is disabled.
type ShardMetrics struct {
	// shard_count: number of active shards. Updated by the metrics refresh
	// loop in node.go (or directly by ShardManager mutations).
	ShardCount prometheus.Gauge

	// shard_block_height: latest block height per shard. Labeled by shard_id.
	// Updated after each successful ProposeBlock / ReceiveBlock.
	BlockHeight *prometheus.GaugeVec

	// shard_cross_shard_messages_total: cumulative count of cross-shard
	// messages submitted. Incremented by SubmitCrossShardMessage.
	CrossShardMessages prometheus.Counter

	// shard_pending_messages: current number of pending (un-relayed)
	// cross-shard messages per shard. Labeled by shard_id.
	PendingMessages *prometheus.GaugeVec

	// shard_finalization_delay_seconds: time from block proposal to
	// finalization (FinalizeBlock). Observed by the block producer.
	FinalizationDelay prometheus.Histogram

	// shard_p2p_messages_total: cumulative count of P2P messages by type.
	// Labeled by message type: "block", "attestation", "cross_msg".
	// Incremented by ShardBlockProducer on each incoming P2P message.
	P2PMessages *prometheus.CounterVec

	// shard_validator_count: number of validators assigned to each shard.
	// Labeled by shard_id. Updated when validators are assigned/reassigned.
	ValidatorCount *prometheus.GaugeVec

	// shard_commitment_lag: difference between the current main-chain slot
	// and the latest committed shard slot (currentSlot - lastCommittedSlot).
	// Labeled by shard_id. High values indicate the shard is falling behind
	// on committing to the main chain.
	CommitmentLag *prometheus.GaugeVec
}

// NewShardMetrics creates and registers all shard Prometheus metrics with
// the default Prometheus registry. Metrics are automatically exposed through
// promhttp.Handler() (the /metrics/prometheus endpoint in metrics/server.go).
//
// NOTE: This function panics if called more than once (promauto registers with
// the global default registry, which rejects duplicates). For testing, use
// NewShardMetricsWithRegistry with a fresh prometheus.NewRegistry().
func NewShardMetrics() *ShardMetrics {
	return NewShardMetricsWithRegistry(prometheus.DefaultRegisterer)
}

// NewShardMetricsWithRegistry creates and registers all shard Prometheus
// metrics with the given registerer. Pass prometheus.DefaultRegisterer for
// production, or a fresh prometheus.NewRegistry() for isolated tests.
func NewShardMetricsWithRegistry(reg prometheus.Registerer) *ShardMetrics {
	factory := promauto.With(reg)

	// Histogram buckets for finalization delay (seconds).
	// Shard finalization requires 2/3 validator attestations, which typically
	// completes within 1-2 slots (12-24s). Buckets span 10ms to ~40s.
	finalizationBuckets := prometheus.ExponentialBuckets(0.01, 2, 13) // 10ms → ~40s

	return &ShardMetrics{
		ShardCount: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: shardMetricsNamespace,
			Subsystem: shardMetricsSubsystem,
			Name:      "count",
			Help:      "Number of active shards currently tracked by the ShardManager",
		}),

		BlockHeight: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: shardMetricsNamespace,
			Subsystem: shardMetricsSubsystem,
			Name:      "block_height",
			Help:      "Latest block height for each shard",
		}, []string{"shard_id"}),

		CrossShardMessages: factory.NewCounter(prometheus.CounterOpts{
			Namespace: shardMetricsNamespace,
			Subsystem: shardMetricsSubsystem,
			Name:      "cross_shard_messages_total",
			Help:      "Total number of cross-shard messages submitted across all shards",
		}),

		PendingMessages: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: shardMetricsNamespace,
			Subsystem: shardMetricsSubsystem,
			Name:      "pending_messages",
			Help:      "Current number of pending (un-relayed) cross-shard messages per shard",
		}, []string{"shard_id"}),

		FinalizationDelay: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: shardMetricsNamespace,
			Subsystem: shardMetricsSubsystem,
			Name:      "finalization_delay_seconds",
			Help:      "Time from block proposal to finalization (after 2/3 quorum)",
			Buckets:   finalizationBuckets,
		}),

		P2PMessages: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: shardMetricsNamespace,
			Subsystem: shardMetricsSubsystem,
			Name:      "p2p_messages_total",
			Help:      "Total shard P2P messages received, by type (block, attestation, cross_msg)",
		}, []string{"type"}),

		ValidatorCount: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: shardMetricsNamespace,
			Subsystem: shardMetricsSubsystem,
			Name:      "validator_count",
			Help:      "Number of validators assigned to each shard",
		}, []string{"shard_id"}),

		CommitmentLag: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: shardMetricsNamespace,
			Subsystem: shardMetricsSubsystem,
			Name:      "commitment_lag",
			Help:      "Difference between current main-chain slot and latest committed shard slot (high values indicate the shard is falling behind)",
		}, []string{"shard_id"}),
	}
}

// --- Convenience helpers (nil-safe) ---
//
// All helpers early-return when m is nil so callers can invoke them
// unconditionally even when sharding is disabled.

// SetShardCount sets the shard_count gauge to the given number of active shards.
func (m *ShardMetrics) SetShardCount(count int) {
	if m == nil {
		return
	}
	m.ShardCount.Set(float64(count))
}

// SetBlockHeight sets the block_height gauge for a specific shard.
func (m *ShardMetrics) SetBlockHeight(shardID uint64, height uint64) {
	if m == nil {
		return
	}
	m.BlockHeight.WithLabelValues(shardIDLabel(shardID)).Set(float64(height))
}

// IncCrossShardMessages increments the cross_shard_messages_total counter by 1.
func (m *ShardMetrics) IncCrossShardMessages() {
	if m == nil {
		return
	}
	m.CrossShardMessages.Inc()
}

// SetPendingMessages sets the pending_messages gauge for a specific shard.
func (m *ShardMetrics) SetPendingMessages(shardID uint64, count int) {
	if m == nil {
		return
	}
	m.PendingMessages.WithLabelValues(shardIDLabel(shardID)).Set(float64(count))
}

// ObserveFinalizationDelay records a finalization delay observation.
func (m *ShardMetrics) ObserveFinalizationDelay(d time.Duration) {
	if m == nil {
		return
	}
	m.FinalizationDelay.Observe(d.Seconds())
}

// IncP2PMessages increments the p2p_messages_total counter for the given
// message type. Valid types: "block", "attestation", "cross_msg".
func (m *ShardMetrics) IncP2PMessages(msgType string) {
	if m == nil {
		return
	}
	m.P2PMessages.WithLabelValues(msgType).Inc()
}

// SetValidatorCount sets the validator_count gauge for a specific shard.
func (m *ShardMetrics) SetValidatorCount(shardID uint64, count int) {
	if m == nil {
		return
	}
	m.ValidatorCount.WithLabelValues(shardIDLabel(shardID)).Set(float64(count))
}

// SetCommitmentLag sets the commitment_lag gauge for a specific shard.
// A high lag means the shard has not committed to the main chain recently.
func (m *ShardMetrics) SetCommitmentLag(shardID uint64, lag uint64) {
	if m == nil {
		return
	}
	m.CommitmentLag.WithLabelValues(shardIDLabel(shardID)).Set(float64(lag))
}

// --- ShardMetricProvider implementation (for alert manager) ---
//
// These methods read the current Prometheus metric values for the alert
// manager. The metrics package may define a ShardMetricProvider interface;
// *ShardMetrics satisfies it without the metrics package needing to import
// consensus (dependency injection via interface).

// shardReadMetricValue extracts the float64 value from a Prometheus Metric.
// For gauges it returns the current value; for counters it returns the
// cumulative count. Returns 0 on nil metric or write error.
func shardReadMetricValue(m prometheus.Metric) float64 {
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

// ShardCountValue returns the current shard_count value.
func (m *ShardMetrics) ShardCountValue() float64 {
	if m == nil {
		return 0
	}
	return shardReadMetricValue(m.ShardCount)
}

// CrossShardMessagesValue returns the cumulative cross_shard_messages_total.
func (m *ShardMetrics) CrossShardMessagesValue() float64 {
	if m == nil {
		return 0
	}
	return shardReadMetricValue(m.CrossShardMessages)
}

// shardIDLabel converts a shardID uint64 to its string label representation.
// Uses decimal formatting for human-readability in Prometheus queries.
func shardIDLabel(shardID uint64) string {
	return strconv.FormatUint(shardID, 10)
}
