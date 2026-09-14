// Quantaureum Node source, version 1.0.0.
// Package metrics provides Prometheus metrics for the Quantaureum node.
//
// Metrics are organized into categories:
//   - Blockchain: block height, block time, transaction count
//   - Consensus (QPOS): proposer status, committee, finality
//   - QTD: threshold signing operations
//   - P2P: peer count, message rates, priority queue stats
//   - System: memory, goroutines, uptime
//
// All metrics follow Prometheus naming conventions:
//   - Namespace: "qau"
//   - Subsystem: category (blockchain, consensus, qtd, p2p, system)
//   - Suffix: unit or type (total, bytes, seconds, info)
package metrics

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

const (
	namespace = "qau"
)

// NodeMetrics holds all Prometheus metrics for the Quantaureum node.
type NodeMetrics struct {
	// === Blockchain ===
	BlockHeight prometheus.Gauge
	BlockTime   prometheus.Histogram
	TxPerBlock  prometheus.Histogram
	BlockSize   prometheus.Gauge

	PendingTxns prometheus.Gauge
	TotalTxns   prometheus.Counter
	GasUsed     prometheus.Histogram
	GasPrice    prometheus.Gauge

	// === Consensus (QPOS) ===
	IsProposer       prometheus.Gauge
	SlotNumber       prometheus.Gauge
	EpochNumber      prometheus.Gauge
	Validators       prometheus.Gauge
	OnlineValidators prometheus.Gauge
	JailedValidators prometheus.Gauge

	// Three-Chamber metrics
	ExecutiveChamberActive prometheus.Gauge // proposer chamber: active proposer
	ReviewChamberSize      prometheus.Gauge // review chamber: attestation committee size
	ReviewChamberVotes     prometheus.Gauge // review chamber: votes received
	SealChamberSigned      prometheus.Gauge // seal chamber: QTD signatures produced

	ProposedBlocks prometheus.Counter
	MissedBlocks   prometheus.Counter
	Attestations   prometheus.Counter
	FinalityDelay  prometheus.Histogram

	// === QTD (threshold signatures) ===
	QTDDKGDuration      prometheus.Histogram
	QTDSignDuration     prometheus.Histogram
	QTDVerifyDuration   prometheus.Histogram
	QTDSignaturesTotal  prometheus.Counter
	QTDSignaturesFailed prometheus.Counter
	QTDKeyRefreshTotal  prometheus.Counter
	// R7-OBS-2 (2026-07-18): DKG failure counter — observed by alert rules
	// in metrics/metrics.go (setupTSSAlertRules) to detect degraded startup
	// performance of the distributed DKG protocol.
	QTDDKGFailedTotal prometheus.Counter
	// R8-OBS-1 (2026-07-18): Simulated DKG invocation counter — increments
	// every time GenerateKeyShares falls back to the trusted-dealer
	// simulation (GenerateDKGDistributedSimulated) because no real P2P
	// DistributedDKGRunner is injected. The alert rule
	// `tss_simulated_dkg_used` fires when this counter > 0, providing
	// defense-in-depth visibility into accidental simulated DKG usage.
	// On mainnet the hard guard in node/config.go Validate() blocks
	// runtime DKG entirely; this counter catches residual risk on
	// testnet/devnet where the simulated path is permitted for testing.
	QTDSimulatedDKGInvocations prometheus.Counter

	// P3-6: QTD finality monitoring metrics.
	FinalityType          prometheus.Gauge // 0=CasperFFG, 1=QTDInstant
	InstantFinalizedCount prometheus.Gauge // Number of blocks finalized via QTD instant finality
	PendingSeals          prometheus.Gauge // Number of pending QTD seal requests

	// === P2P ===
	PeerCount            prometheus.Gauge
	PeerCountIn          prometheus.Gauge
	PeerCountOut         prometheus.Gauge
	MsgReceived          *prometheus.CounterVec
	MsgSent              *prometheus.CounterVec
	MsgDropped           prometheus.Counter
	P2PLatency           prometheus.Histogram
	PriorityQueueSize    prometheus.Gauge
	PriorityQueueDropped prometheus.Counter

	// === RPC ===
	RPCRequestsTotal   *prometheus.CounterVec
	RPCRequestDuration *prometheus.HistogramVec
	RPCErrorsTotal     *prometheus.CounterVec

	// === StateDB ===
	StateDBCacheSize        prometheus.Gauge
	StateDBStorageCacheSize prometheus.Gauge

	// === System ===
	Uptime      prometheus.Gauge
	Goroutines  prometheus.Gauge
	MemoryAlloc prometheus.Gauge
	MemorySys   prometheus.Gauge
	GCPause     prometheus.Histogram
	VersionInfo *prometheus.GaugeVec

	// startTime tracks when the node was started
	startTime time.Time
}

// NewNodeMetrics creates and registers all Prometheus metrics.
func NewNodeMetrics() *NodeMetrics {
	m := &NodeMetrics{
		startTime: time.Now(),

		// === Blockchain ===
		BlockHeight: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "blockchain",
			Name: "block_height",
			Help: "Current block height",
		}),
		BlockTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "blockchain",
			Name:    "block_time_seconds",
			Help:    "Time between consecutive blocks",
			Buckets: prometheus.DefBuckets,
		}),
		TxPerBlock: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "blockchain",
			Name:    "transactions_per_block",
			Help:    "Number of transactions per block",
			Buckets: []float64{0, 1, 5, 10, 50, 100, 500, 1000},
		}),
		BlockSize: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "blockchain",
			Name: "block_size_bytes",
			Help: "Size of the last block in bytes",
		}),
		PendingTxns: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "blockchain",
			Name: "pending_transactions",
			Help: "Number of pending transactions in the mempool",
		}),
		TotalTxns: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "blockchain",
			Name: "transactions_total",
			Help: "Total number of transactions processed",
		}),
		GasUsed: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "blockchain",
			Name:    "gas_used",
			Help:    "Gas used per block",
			Buckets: prometheus.ExponentialBuckets(10000, 2, 10),
		}),
		GasPrice: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "blockchain",
			Name: "gas_price",
			Help: "Current gas price in QAU",
		}),

		// === Consensus ===
		IsProposer: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "is_proposer",
			Help: "Whether this node is the current proposer (1=yes, 0=no)",
		}),
		SlotNumber: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "slot_number",
			Help: "Current slot number",
		}),
		EpochNumber: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "epoch_number",
			Help: "Current epoch number",
		}),
		Validators: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "validators_total",
			Help: "Total number of validators",
		}),
		OnlineValidators: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "validators_online",
			Help: "Number of online validators",
		}),
		JailedValidators: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "validators_jailed",
			Help: "Number of jailed validators",
		}),
		ExecutiveChamberActive: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "executive_chamber_active",
			Help: "Whether the proposer chamber proposer is active (1=yes, 0=no)",
		}),
		ReviewChamberSize: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "review_chamber_size",
			Help: "Current review-chamber attestation committee size",
		}),
		ReviewChamberVotes: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "review_chamber_votes",
			Help: "Review-chamber votes received in current slot",
		}),
		SealChamberSigned: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "seal_chamber_signed",
			Help: "Seal-chamber QTD signatures produced",
		}),
		ProposedBlocks: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "blocks_proposed_total",
			Help: "Total number of blocks proposed by this node",
		}),
		MissedBlocks: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "blocks_missed_total",
			Help: "Total number of blocks missed by this node",
		}),
		Attestations: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name: "attestations_total",
			Help: "Total number of attestations made by this node",
		}),
		FinalityDelay: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "consensus",
			Name:    "finality_delay_seconds",
			Help:    "Time from block creation to finality",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}),

		// === QTD ===
		QTDDKGDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name:    "dkg_duration_seconds",
			Help:    "QTD distributed key generation duration",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}),
		QTDSignDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name:    "sign_duration_seconds",
			Help:    "QTD threshold signing duration",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}),
		QTDVerifyDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name:    "verify_duration_seconds",
			Help:    "QTD signature verification duration",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}),
		QTDSignaturesTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name: "signatures_total",
			Help: "Total QTD signatures produced",
		}),
		QTDSignaturesFailed: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name: "signatures_failed_total",
			Help: "Total QTD signature failures",
		}),
		QTDKeyRefreshTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name: "key_refresh_total",
			Help: "Total QTD key refresh operations",
		}),
		// R7-OBS-2 (2026-07-18): DKG failure counter — see field comment.
		QTDDKGFailedTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name: "dkg_failed_total",
			Help: "Total QTD distributed key generation failures",
		}),
		// R8-OBS-1 (2026-07-18): Simulated DKG invocation counter — see field comment.
		QTDSimulatedDKGInvocations: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name: "simulated_dkg_invocations_total",
			Help: "Total invocations of the simulated (trusted-dealer) DKG path; should be 0 on mainnet",
		}),

		// P3-6: QTD finality monitoring metrics.
		FinalityType: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name: "finality_type",
			Help: "Finality type: 0=CasperFFG, 1=QTDInstant",
		}),
		InstantFinalizedCount: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name: "instant_finalized_count",
			Help: "Number of blocks finalized via QTD instant finality",
		}),
		PendingSeals: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "qtd",
			Name: "pending_seals",
			Help: "Number of pending QTD seal requests",
		}),

		// === P2P ===
		PeerCount: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "p2p",
			Name: "peers_total",
			Help: "Total number of connected peers",
		}),
		PeerCountIn: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "p2p",
			Name: "peers_inbound",
			Help: "Number of inbound peer connections",
		}),
		PeerCountOut: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "p2p",
			Name: "peers_outbound",
			Help: "Number of outbound peer connections",
		}),
		MsgReceived: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace, Subsystem: "p2p",
				Name: "messages_received_total",
				Help: "Total P2P messages received by type",
			},
			[]string{"type"},
		),
		MsgSent: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace, Subsystem: "p2p",
				Name: "messages_sent_total",
				Help: "Total P2P messages sent by type",
			},
			[]string{"type"},
		),
		MsgDropped: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "p2p",
			Name: "messages_dropped_total",
			Help: "Total P2P messages dropped",
		}),
		P2PLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "p2p",
			Name:    "latency_seconds",
			Help:    "P2P message latency",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}),
		PriorityQueueSize: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "p2p",
			Name: "priority_queue_size",
			Help: "Current size of the P2P priority queue",
		}),
		PriorityQueueDropped: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "p2p",
			Name: "priority_queue_dropped_total",
			Help: "Total messages dropped from the priority queue",
		}),

		// === RPC ===
		RPCRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace, Subsystem: "rpc",
				Name: "requests_total",
				Help: "Total RPC requests by method",
			},
			[]string{"method"},
		),
		RPCRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace, Subsystem: "rpc",
				Name:    "request_duration_seconds",
				Help:    "RPC request duration by method",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
			},
			[]string{"method"},
		),
		RPCErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace, Subsystem: "rpc",
				Name: "errors_total",
				Help: "Total RPC errors by method",
			},
			[]string{"method"},
		),

		// === StateDB ===
		StateDBCacheSize: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "statedb",
			Name: "cache_size",
			Help: "Current StateDB account cache size",
		}),
		StateDBStorageCacheSize: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "statedb",
			Name: "storage_cache_size",
			Help: "Current StateDB storage cache size",
		}),

		// === System ===
		Uptime: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "system",
			Name: "uptime_seconds",
			Help: "Node uptime in seconds",
		}),
		Goroutines: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "system",
			Name: "goroutines",
			Help: "Number of goroutines",
		}),
		MemoryAlloc: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "system",
			Name: "memory_alloc_bytes",
			Help: "Allocated memory in bytes",
		}),
		MemorySys: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "system",
			Name: "memory_sys_bytes",
			Help: "System memory in bytes",
		}),
		GCPause: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "system",
			Name:    "gc_pause_seconds",
			Help:    "GC pause duration",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
		}),
		VersionInfo: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace, Subsystem: "system",
				Name: "version_info",
				Help: "Node version information",
			},
			[]string{"version", "git_commit"},
		),
	}

	return m
}

// UpdateSystemMetrics updates runtime/system metrics.
// Should be called periodically (e.g., every 10 seconds).
func (m *NodeMetrics) UpdateSystemMetrics() {
	m.Uptime.Set(time.Since(m.startTime).Seconds())

	m.Goroutines.Set(float64(runtime.NumGoroutine()))

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.MemoryAlloc.Set(float64(memStats.Alloc))
	m.MemorySys.Set(float64(memStats.Sys))
}

// SetVersion sets the version info gauge.
// The value is always 1; the labels carry the actual version info.
func (m *NodeMetrics) SetVersion(version, gitCommit string) {
	m.VersionInfo.WithLabelValues(version, gitCommit).Set(1)
}

// R7-OBS-2 (2026-07-18): TSS DKG startup performance monitoring.
//
// Audit observation (Medium): "The transition to distributed DKG increases
// computational overhead during node startup. Monitoring is recommended to
// ensure node synchronization times remain within acceptable bounds during
// peak load."
//
// The two methods below implement the TSSMetricProvider interface (defined in
// metrics.go) on *NodeMetrics. They expose DKG timing and failure counts to
// the alert manager so operators can detect degraded startup performance.
// Both are nil-safe to keep cold-start and test paths working when metrics
// are not wired.

// DKGDurationP95Value returns the approximate 95th percentile of observed
// DKG durations in seconds. Returns 0 when no DKG has been observed (cold
// start) so the alert rule does not fire on a fresh node.
func (m *NodeMetrics) DKGDurationP95Value() float64 {
	if m == nil {
		return 0
	}
	return readHistogramP95(m.QTDDKGDuration)
}

// DKGFailedCountValue returns the cumulative count of DKG failures.
// Returns 0 when no failures have been recorded.
func (m *NodeMetrics) DKGFailedCountValue() float64 {
	if m == nil {
		return 0
	}
	pb := &dto.Metric{}
	if err := m.QTDDKGFailedTotal.Write(pb); err != nil {
		return 0
	}
	if pb.Counter != nil {
		return pb.Counter.GetValue()
	}
	return 0
}

// SimulatedDKGInvocationsValue returns the cumulative count of simulated
// (trusted-dealer) DKG invocations. Should be 0 on mainnet (hard guard in
// node/config.go Validate() blocks runtime DKG entirely). Non-zero on
// testnet/devnet is expected for testing, but non-zero on mainnet indicates
// a critical configuration bypass.
// R8-OBS-1 (2026-07-18)
func (m *NodeMetrics) SimulatedDKGInvocationsValue() float64 {
	if m == nil {
		return 0
	}
	pb := &dto.Metric{}
	if err := m.QTDSimulatedDKGInvocations.Write(pb); err != nil {
		return 0
	}
	if pb.Counter != nil {
		return pb.Counter.GetValue()
	}
	return 0
}

// readHistogramP95 returns the approximate 95th percentile value from a
// Prometheus histogram. Returns 0 when the histogram has no observations
// (cold start) or when the metric is nil.
//
// The approximation picks the bucket whose cumulative count first reaches
// 95% of the total sample count. When the 95th percentile falls in the
// +Inf bucket, the mean (sum / count) is returned as a fallback.
func readHistogramP95(h prometheus.Histogram) float64 {
	if h == nil {
		return 0
	}
	pb := &dto.Metric{}
	if err := h.(prometheus.Metric).Write(pb); err != nil {
		return 0
	}
	hist := pb.GetHistogram()
	if hist == nil || hist.GetSampleCount() == 0 {
		return 0
	}
	total := hist.GetSampleCount()
	target := uint64(0.95 * float64(total))
	for _, b := range hist.Bucket {
		if b.GetCumulativeCount() >= target {
			return b.GetUpperBound()
		}
	}
	// Target is in the +Inf bucket — use mean as fallback.
	return hist.GetSampleSum() / float64(total)
}
