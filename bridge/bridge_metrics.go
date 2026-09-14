// Quantaureum Node source, version 1.0.0.
// Package bridge implements the Quantaureum Cross-Chain Bridge protocol.
// bridge_metrics.go defines Prometheus metrics for bridge observability.
//
// P3-1 (2026-07-14): Exposes 5 categories of metrics:
//   - Message counts by status and chain
//   - Arbitration signature counts
//   - Relayer task counts
//   - Adapter RPC latency
//   - Merkle root update counts
//
// All metrics are registered exactly once with the default Prometheus
// registry via a package-level sync.Once singleton. They are automatically
// exposed at /metrics/prometheus alongside other node metrics. No manual
// wiring in node.go is required.
//
// The singleton pattern is necessary because promauto registers on the
// process-global default registry: calling NewBridgeMetrics() more than
// once (e.g., across multiple tests that each construct a QuantumBridge)
// would otherwise panic with "duplicate metrics collector registration".
package bridge

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

const (
	metricsNamespace = "qau"
	metricsSubsystem = "bridge"
)

// metricsOnce ensures the singleton BridgeMetrics is constructed and
// registered exactly once across the lifetime of the process.
var (
	metricsOnce   sync.Once
	sharedMetrics *BridgeMetrics
)

// BridgeMetrics holds Prometheus metrics for the cross-chain bridge.
// All fields are safe for concurrent use (prometheus counters/gauges/histograms
// are internally synchronized). A nil *BridgeMetrics is safe — all helper
// methods check for nil before recording.
type BridgeMetrics struct {
	// Message counts
	MessagesSubmittedTotal *prometheus.CounterVec // labels: source_chain, target_chain
	MessagesByStatus       *prometheus.GaugeVec   // labels: status — current snapshot

	// Arbitration
	ArbitrationSignaturesTotal prometheus.Counter // total signatures collected
	ArbitrationQuorumThreshold prometheus.Gauge   // current BFT threshold

	// Relayer
	RelayerTasksTotal *prometheus.CounterVec // labels: action (submit, relay, retry, failed)

	// Adapter RPC
	AdapterRPCLatencySeconds *prometheus.HistogramVec // labels: chain, method

	// Merkle roots
	MerkleRootUpdatesTotal prometheus.Counter

	// P3-2: Alert-supporting metrics
	// EventSignatureCount tracks the number of registered bridge event
	// signatures per adapter chain. An empty allowlist (count == 0) with
	// bootstrapMode disabled means ALL cross-chain events are rejected.
	EventSignatureCount *prometheus.GaugeVec // labels: chain
	// BootstrapMode tracks whether an adapter is in bootstrap mode (1 = enabled,
	// 0 = disabled). Bootstrap mode should only be enabled temporarily during
	// initial setup; if it stays enabled >1h, that indicates a misconfiguration.
	BootstrapMode *prometheus.GaugeVec // labels: chain

	// P3-2 (2026-07-15): Alert-rule supporting gauges.
	// LastMessageProcessedAt is the Unix timestamp of the most recently
	// processed bridge message. The alert rule fires when (now - last) > 300s.
	// Zero means no message has ever been processed (cold start).
	LastMessageProcessedAt prometheus.Gauge
	// ActiveValidators is the current count of active validators in the
	// bridge ValidatorSet. The alert rule fires when active < threshold.
	ActiveValidators prometheus.Gauge
	// L1AnchorLag is the number of L1 blocks elapsed since the last Merkle
	// root anchor was committed. The alert rule fires when lag > 20.
	L1AnchorLag prometheus.Gauge
	// RelayerConnected is 1 when the relayer is connected to the bridge
	// network, 0 when disconnected. The alert rule fires when value = 1
	// (i.e., disconnected).
	RelayerConnected prometheus.Gauge
}

// NewBridgeMetrics returns the process-wide singleton BridgeMetrics,
// constructing and registering it on the first call. Subsequent calls
// return the same instance — this is required because promauto registers
// on the global default Prometheus registry, and duplicate registrations
// would panic. In production there is exactly one bridge per process.
// In tests, all QuantumBridge instances share the same metrics; tests
// that assert on counter values must capture before/after deltas.
func NewBridgeMetrics() *BridgeMetrics {
	metricsOnce.Do(func() {
		sharedMetrics = &BridgeMetrics{
			MessagesSubmittedTotal: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "messages_submitted_total",
				Help:      "Total cross-chain messages submitted, by source and target chain.",
			}, []string{"source_chain", "target_chain"}),

			MessagesByStatus: promauto.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "messages_by_status",
				Help:      "Current number of bridge messages by status.",
			}, []string{"status"}),

			ArbitrationSignaturesTotal: promauto.NewCounter(prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "arbitration_signatures_total",
				Help:      "Total validator signatures collected for bridge message arbitration.",
			}),

			ArbitrationQuorumThreshold: promauto.NewGauge(prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "arbitration_quorum_threshold",
				Help:      "Current BFT signature threshold for bridge message arbitration.",
			}),

			RelayerTasksTotal: promauto.NewCounterVec(prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "relayer_tasks_total",
				Help:      "Total relayer tasks processed, by action.",
			}, []string{"action"}),

			AdapterRPCLatencySeconds: promauto.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "adapter_rpc_latency_seconds",
				Help:      "Latency of adapter RPC calls to external chains.",
				Buckets:   prometheus.DefBuckets, // 0.005s to 10s
			}, []string{"chain", "method"}),

			MerkleRootUpdatesTotal: promauto.NewCounter(prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "merkle_root_updates_total",
				Help:      "Total Merkle root updates via SetCommittedRoot.",
			}),

			EventSignatureCount: promauto.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "event_signature_count",
				Help:      "Number of registered bridge event signatures per adapter chain. 0 with bootstrap disabled means all cross-chain events are rejected.",
			}, []string{"chain"}),

			BootstrapMode: promauto.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "bootstrap_mode",
				Help:      "Whether the adapter is in bootstrap mode (1=enabled, 0=disabled). Should only be enabled temporarily during initial setup.",
			}, []string{"chain"}),

			LastMessageProcessedAt: promauto.NewGauge(prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "last_message_processed_at",
				Help:      "Unix timestamp of the most recently processed bridge message. 0 means no message has ever been processed.",
			}),

			ActiveValidators: promauto.NewGauge(prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "active_validators",
				Help:      "Current count of active validators in the bridge arbitration ValidatorSet.",
			}),

			L1AnchorLag: promauto.NewGauge(prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "l1_anchor_lag",
				Help:      "Number of L1 blocks elapsed since the last Merkle root anchor was committed.",
			}),

			RelayerConnected: promauto.NewGauge(prometheus.GaugeOpts{
				Namespace: metricsNamespace,
				Subsystem: metricsSubsystem,
				Name:      "relayer_connected",
				Help:      "Whether the bridge relayer is connected (1=connected, 0=disconnected).",
			}),
		}
	})
	return sharedMetrics
}

// --- Bridge-level helpers (called from QuantumBridge methods) ---

// IncMessagesSubmitted increments the submitted message counter for the given
// source→target chain pair.
func (m *BridgeMetrics) IncMessagesSubmitted(sourceChain, targetChain ChainID) {
	if m == nil {
		return
	}
	m.MessagesSubmittedTotal.WithLabelValues(string(sourceChain), string(targetChain)).Inc()
}

// SetStatusCount sets the current count of messages for a given status.
// Called after status transitions in ProcessMessage / VerifyMessage.
func (m *BridgeMetrics) SetStatusCount(status BridgeMessageStatus, count int) {
	if m == nil {
		return
	}
	m.MessagesByStatus.WithLabelValues(string(status)).Set(float64(count))
}

// IncArbitrationSignature increments the total arbitration signature counter.
// Called from ValidatorNetwork.SignMessage.
func (m *BridgeMetrics) IncArbitrationSignature() {
	if m == nil {
		return
	}
	m.ArbitrationSignaturesTotal.Inc()
}

// SetArbitrationQuorum sets the current BFT quorum threshold.
// Called from ValidatorSet.SetThreshold / SyncFromQPOS.
func (m *BridgeMetrics) SetArbitrationQuorum(threshold int) {
	if m == nil {
		return
	}
	m.ArbitrationQuorumThreshold.Set(float64(threshold))
}

// IncRelayerTask increments the relayer task counter for the given action.
// action should be one of: "submit", "relay", "retry", "failed".
func (m *BridgeMetrics) IncRelayerTask(action string) {
	if m == nil {
		return
	}
	m.RelayerTasksTotal.WithLabelValues(action).Inc()
}

// ObserveAdapterRPC records the latency of an adapter RPC call.
// method examples: "getCurrentBlockHeight", "submitMessage", "getTransactionBlockNumber".
func (m *BridgeMetrics) ObserveAdapterRPC(chain ChainID, method string, duration time.Duration) {
	if m == nil {
		return
	}
	m.AdapterRPCLatencySeconds.WithLabelValues(string(chain), method).Observe(duration.Seconds())
}

// IncMerkleRootUpdate increments the Merkle root update counter.
// Called from both adapters' SetCommittedRoot.
func (m *BridgeMetrics) IncMerkleRootUpdate() {
	if m == nil {
		return
	}
	m.MerkleRootUpdatesTotal.Inc()
}

// SetEventSignatureCount sets the number of registered event signatures
// for the given adapter chain. P3-2: used for the "empty event signature
// allowlist" alert.
func (m *BridgeMetrics) SetEventSignatureCount(chain ChainID, count int) {
	if m == nil {
		return
	}
	m.EventSignatureCount.WithLabelValues(string(chain)).Set(float64(count))
}

// SetBootstrapMode records whether an adapter is in bootstrap mode.
// P3-2: used for the "bootstrapMode=true >1h" alert.
func (m *BridgeMetrics) SetBootstrapMode(chain ChainID, enabled bool) {
	if m == nil {
		return
	}
	val := 0.0
	if enabled {
		val = 1.0
	}
	m.BootstrapMode.WithLabelValues(string(chain)).Set(val)
}

// --- P3-2 (2026-07-15): Alert-rule supporting setters ---

// SetLastMessageProcessedAt records the Unix timestamp of the most recently
// processed bridge message. Called from ProcessMessage after a successful
// PENDING → VERIFIED → EXECUTED transition. Zero (the default) means no
// message has ever been processed.
func (m *BridgeMetrics) SetLastMessageProcessedAt(ts int64) {
	if m == nil {
		return
	}
	m.LastMessageProcessedAt.Set(float64(ts))
}

// SetActiveValidators records the current count of active validators in the
// bridge ValidatorSet. Called from ValidatorSet.SyncFromQPOS and
// AddValidator/RemoveValidator. The alert rule fires when active < threshold.
func (m *BridgeMetrics) SetActiveValidators(count int) {
	if m == nil {
		return
	}
	m.ActiveValidators.Set(float64(count))
}

// SetL1AnchorLag records the number of L1 blocks elapsed since the last
// Merkle root anchor was committed. Called from the adapter's
// SetCommittedRoot / FetchMerkleRootFromChain path. The alert rule fires
// when lag > 20.
func (m *BridgeMetrics) SetL1AnchorLag(lag uint64) {
	if m == nil {
		return
	}
	m.L1AnchorLag.Set(float64(lag))
}

// SetRelayerConnected records whether the bridge relayer is connected.
// Called from the relayer's Start/Stop methods. The alert rule fires when
// the relayer is disconnected (value = 0 → disconnected → alert value = 1).
func (m *BridgeMetrics) SetRelayerConnected(connected bool) {
	if m == nil {
		return
	}
	val := 0.0
	if connected {
		val = 1.0
	}
	m.RelayerConnected.Set(val)
}

// --- BridgeMetricProvider implementation (P3-2) ---
//
// These methods read the current Prometheus metric values for the alert
// manager. The metrics package defines the BridgeMetricProvider interface;
// *BridgeMetrics satisfies it without the metrics package needing to import
// bridge (dependency injection via interface).
//
// readMetricValue extracts the float64 value from a Prometheus Metric using
// the dto.Metric.Write() API. For gauges it returns the current value; for
// counters it returns the cumulative count.

func readBridgeMetricValue(m prometheus.Metric) float64 {
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

// MessageProcessingStalledValue returns the number of seconds since the
// last bridge message was processed. Returns 0 on cold start (no message
// ever processed, LastMessageProcessedAt=0) to avoid false positives during
// node startup.
func (m *BridgeMetrics) MessageProcessingStalledValue() float64 {
	if m == nil {
		return 0
	}
	last := readBridgeMetricValue(m.LastMessageProcessedAt)
	if last <= 0 {
		return 0 // cold start — no message ever processed
	}
	now := float64(time.Now().Unix())
	stalled := now - last
	if stalled < 0 {
		return 0 // clock skew — don't alert
	}
	return stalled
}

// FailedMessagesValue returns the current count of bridge messages in the
// FAILED status.
func (m *BridgeMetrics) FailedMessagesValue() float64 {
	if m == nil {
		return 0
	}
	return readBridgeMetricValue(m.MessagesByStatus.WithLabelValues(string(MessageStatusFailed)))
}

// QuorumLostValue returns 1 when active validators cannot reach the
// configured BFT threshold (active < threshold), 0 otherwise. Cold-start
// safe: when threshold=0 (not yet configured), returns 0.
func (m *BridgeMetrics) QuorumLostValue() float64 {
	if m == nil {
		return 0
	}
	threshold := readBridgeMetricValue(m.ArbitrationQuorumThreshold)
	if threshold <= 0 {
		return 0 // threshold not configured yet — cold start
	}
	active := readBridgeMetricValue(m.ActiveValidators)
	if active < threshold {
		return 1 // quorum lost
	}
	return 0
}

// L1AnchorLagValue returns the number of L1 blocks since the last bridge
// Merkle root anchor.
func (m *BridgeMetrics) L1AnchorLagValue() float64 {
	if m == nil {
		return 0
	}
	return readBridgeMetricValue(m.L1AnchorLag)
}

// RelayerDisconnectedValue returns 1 when the relayer is disconnected,
// 0 when connected.
func (m *BridgeMetrics) RelayerDisconnectedValue() float64 {
	if m == nil {
		return 0
	}
	connected := readBridgeMetricValue(m.RelayerConnected)
	if connected < 0.5 {
		return 1 // disconnected
	}
	return 0
}
