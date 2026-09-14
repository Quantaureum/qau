// Quantaureum Node source, version 1.0.0.
// Package metrics provides Prometheus metrics for Quantaureum node monitoring.
package metrics

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AlertLevel represents the severity of an alert
type AlertLevel int

// RollupMetricProvider provides read access to rollup metric values for the
// alert manager. The rollup package implements this interface on
// *RollupMetrics; the metrics package consumes it without importing rollup
// (dependency injection via interface).
// W-P3-2 (2026-07-14)
type RollupMetricProvider interface {
	StatusValue() float64                   // 0=stopped, 1=running
	PendingTxsValue() float64               // current pending tx count
	L1AnchorLagValue() float64              // L1 blocks since last anchor
	FraudProofsSubmittedValue() float64     // cumulative fraud proofs submitted
	ConsecutiveBatchFailuresValue() float64 // current consecutive failures
	BatchLoopPanicsValue() float64          // cumulative panics in batchLoop
}

// DAMetricProvider provides read access to DA (Data Availability) metric
// values for the alert manager. The consensus package implements this
// interface on *DAMetrics; the metrics package consumes it without importing
// consensus (dependency injection via interface).
// P3-1/P3-3 (2026-07-15)
type DAMetricProvider interface {
	CommitteeAvailableValue() float64 // 1=available, 0=unavailable
	SamplingConfidenceValue() float64 // 0.0..1.0
	AttestationCountValue() float64   // current attestation count
	BlobStorageSizeValue() float64    // blob storage size in bytes
	VerifierRejectionsValue() float64 // cumulative verifier rejections
	CommitteeSizeValue() float64      // configured committee size (P3-3)
}

// BridgeMetricProvider provides read access to cross-chain bridge metric
// values for the alert manager. The bridge package implements this interface
// on *BridgeMetrics; the metrics package consumes it without importing bridge
// (dependency injection via interface).
// P3-2 (2026-07-15)
type BridgeMetricProvider interface {
	// MessageProcessingStalledValue returns the number of seconds since the
	// last bridge message was processed. The alert rule fires when this
	// exceeds 300 (5 minutes). Returns 0 on cold start (no message ever
	// processed) to avoid false positives during node startup.
	MessageProcessingStalledValue() float64
	// FailedMessagesValue returns the current count of bridge messages in
	// the FAILED status.
	FailedMessagesValue() float64
	// QuorumLostValue returns 1 when active validators cannot reach the
	// configured BFT threshold (active < threshold), 0 otherwise.
	QuorumLostValue() float64
	// L1AnchorLagValue returns the number of L1 blocks since the last bridge
	// Merkle root anchor.
	L1AnchorLagValue() float64
	// RelayerDisconnectedValue returns 1 when the relayer is disconnected,
	// 0 when connected.
	RelayerDisconnectedValue() float64
}

// ThreeChambersMetricProvider provides read access to Three Chambers Finality
// metric values for the alert manager. The consensus package implements this
// interface on *ThreeChambersCoordinator; the metrics package consumes it
// without importing consensus (dependency injection via interface).
// P3-3 (2026-07-15)
type ThreeChambersMetricProvider interface {
	EvidenceQueueLengthValue() float64 // current slashing evidence queue depth
	DKGElapsedSecondsValue() float64   // seconds since DKG started (0 if not running)
}

// MinistryMetricProvider provides read access to Ministry governance metric
// values for the alert manager. The consensus package implements this
// interface on *MinistryMetrics; the metrics package consumes it without
// importing consensus (dependency injection via interface).
// P3-T1/P3-T3 (2026-07-15)
type MinistryMetricProvider interface {
	CriticalAlertsValue() float64    // current Defense critical alert count
	PartitionDetectedValue() float64 // 1 if network partition detected, 0 otherwise
	BlacklistSizeValue() float64     // current Defense blacklist size
	PendingCasesValue() float64      // current Justice pending case count
}

// TSSMetricProvider provides read access to TSS (threshold signature scheme)
// DKG metric values for the alert manager. The metrics package implements
// this interface on *NodeMetrics (see DKGDurationP95Value / DKGFailedCountValue
// methods in node_metrics.go); the alert manager consumes it via dependency
// injection without import cycles.
// R7-OBS-2 (2026-07-18); R8-OBS-1 (2026-07-18) adds SimulatedDKGInvocationsValue.
type TSSMetricProvider interface {
	DKGDurationP95Value() float64 // approximate p95 of DKG duration in seconds
	DKGFailedCountValue() float64 // cumulative DKG failure count
	// SimulatedDKGInvocationsValue returns the cumulative count of
	// simulated (trusted-dealer) DKG invocations. Should be 0 on mainnet.
	SimulatedDKGInvocationsValue() float64
}

const (
	AlertInfo AlertLevel = iota
	AlertWarning
	AlertCritical
)

// BridgeAlertThresholds is the configurable threshold set for the 5
// bridge-related alert rules registered by setupBridgeAlertRules.
//
// AUDIT-FULL ROUND4 2026-08-15 LOW-02 FIX:
// Pre-fix, the bridge alert thresholds (300s stalled / 100 failed
// messages / 0.5 quorum-lost trigger / 20 blocks L1-anchor lag / 0.5
// relayer-disconnected trigger) were inlined as magic numbers in
// setupBridgeAlertRules, with no override path for operators to tune
// alert sensitivity to their own network's noise floor. This struct
// lifts those values to a named, settable, documented config object.
//
// Override path: call m.SetBridgeAlertThresholds(thresholds) BEFORE the
// first m.AlertManager().Check() that should observe the new values
// (typically once at process startup after reading the operator
// config / env vars). The setter re-registers only the bridge rules
// (rules whose Name has the "bridge_" prefix), so non-bridge rules
// (default rollup / DA / ministry / 3-chambers / TSS etc.) are
// untouched. A nil field inside the struct (or a nil thresholds
// pointer) reverts to the matching Default* constant — see
// getBridgeAlertThresholds for the resolution order.
//
// Defaults are kept numerically identical to the pre-fix
// inline-magic-number values so the behavior of a binary that doesn't
// call SetBridgeAlertThresholds remains byte-identical to the previous
// release (regression-safe).
type BridgeAlertThresholds struct {
	// MessageProcessingStalledSeconds: rule fires when
	// BridgeMetricProvider.MessageProcessingStalledValue() returns a
	// value strictly greater than this threshold (in seconds).
	// Default: 300.0 (5 minutes).
	MessageProcessingStalledSeconds float64
	// FailedMessagesBacklog: rule fires when
	// BridgeMetricProvider.FailedMessagesValue() exceeds this count
	// of FAILED bridge messages. Default: 100.0.
	FailedMessagesBacklog float64
	// QuorumLostTrigger: rule fires when
	// BridgeMetricProvider.QuorumLostValue() returns a value
	// strictly greater than this. Operational semantics: the
	// provider returns exactly 1.0 when quorum is lost, exactly
	// 0.0 when intact, so any trigger in (0, 1) fires on the
	// lost state — 0.5 is the conventional midpoint. Default: 0.5.
	QuorumLostTrigger float64
	// L1AnchorLagBlocks: rule fires when
	// BridgeMetricProvider.L1AnchorLagValue() (L1 blocks since
	// the last bridge Merkle-root anchor) exceeds this value.
	// Default: 20.0.
	L1AnchorLagBlocks float64
	// RelayerDisconnectedTrigger: rule fires when
	// BridgeMetricProvider.RelayerDisconnectedValue() returns a
	// value strictly greater than this. Same 0/1 semantics as
	// QuorumLostTrigger. Default: 0.5.
	RelayerDisconnectedTrigger float64
}

// DefaultBridgeAlertThresholds returns the production-default
// bridge alert thresholds. AUDIT-FULL ROUND4 LOW-02: This is the
// SINGLE source of truth for bridge alert defaults — setupBridgeAlertRules
// reads from here, so a future tuning change touches exactly one
// place instead of being scattered across rule registration sites.
func DefaultBridgeAlertThresholds() BridgeAlertThresholds {
	return BridgeAlertThresholds{
		MessageProcessingStalledSeconds: 300.0,
		FailedMessagesBacklog:           100.0,
		QuorumLostTrigger:               0.5,
		L1AnchorLagBlocks:               20.0,
		RelayerDisconnectedTrigger:      0.5,
	}
}

// String returns the string representation of AlertLevel
func (l AlertLevel) String() string {
	switch l {
	case AlertInfo:
		return "info"
	case AlertWarning:
		return "warning"
	case AlertCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Alert represents a triggered alert
type Alert struct {
	Name      string     `json:"name"`
	Level     AlertLevel `json:"level"`
	Message   string     `json:"message"`
	Value     float64    `json:"value"`
	Threshold float64    `json:"threshold"`
	Timestamp time.Time  `json:"timestamp"`
}

// AlertRule defines a threshold-based alert rule
type AlertRule struct {
	Name      string
	MetricFn  func(*Metrics) float64
	Threshold float64
	Level     AlertLevel
	Message   string
	Enabled   bool
}

// AlertManager manages alert rules and triggered alerts
type AlertManager struct {
	rules     []*AlertRule
	alerts    []*Alert
	handlers  []AlertHandler
	mu        sync.RWMutex
	maxAlerts int
}

// AlertHandler is a callback for handling alerts
type AlertHandler func(*Alert)

// NewAlertManager creates a new alert manager
func NewAlertManager() *AlertManager {
	return &AlertManager{
		rules:     make([]*AlertRule, 0),
		alerts:    make([]*Alert, 0),
		handlers:  make([]AlertHandler, 0),
		maxAlerts: 1000,
	}
}

// AddRule adds an alert rule
func (am *AlertManager) AddRule(rule *AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.rules = append(am.rules, rule)
}

// RemoveRulesByNamePrefix removes all alert rules whose Name starts with the
// given prefix. This is used by SetBridgeAlertThresholds to clear bridge rules
// before re-registering them with new thresholds. AUDIT-FULL ROUND4 LOW-02.
func (am *AlertManager) RemoveRulesByNamePrefix(prefix string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	filtered := make([]*AlertRule, 0, len(am.rules))
	for _, r := range am.rules {
		if !strings.HasPrefix(r.Name, prefix) {
			filtered = append(filtered, r)
		}
	}
	am.rules = filtered
}

// AddHandler adds an alert handler
func (am *AlertManager) AddHandler(handler AlertHandler) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.handlers = append(am.handlers, handler)
}

// Check evaluates all rules against current metrics
func (am *AlertManager) Check(m *Metrics) []*Alert {
	am.mu.Lock()

	var triggered []*Alert
	for _, rule := range am.rules {
		if !rule.Enabled {
			continue
		}
		value := rule.MetricFn(m)
		if value > rule.Threshold {
			alert := &Alert{
				Name:      rule.Name,
				Level:     rule.Level,
				Message:   rule.Message,
				Value:     value,
				Threshold: rule.Threshold,
				Timestamp: time.Now(),
			}
			triggered = append(triggered, alert)
			am.alerts = append(am.alerts, alert)
		}
	}

	handlers := make([]AlertHandler, len(am.handlers))
	copy(handlers, am.handlers)

	if len(am.alerts) > am.maxAlerts {
		am.alerts = am.alerts[len(am.alerts)-am.maxAlerts:]
	}

	am.mu.Unlock()

	for _, alert := range triggered {
		alertCopy := alert
		for _, handler := range handlers {
			go handler(alertCopy)
		}
	}

	return triggered
}

// GetAlerts returns recent alerts
func (am *AlertManager) GetAlerts(limit int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if limit <= 0 || limit > len(am.alerts) {
		limit = len(am.alerts)
	}
	start := len(am.alerts) - limit
	if start < 0 {
		start = 0
	}
	result := make([]*Alert, limit)
	copy(result, am.alerts[start:])
	return result
}

// ClearAlerts clears all alerts
func (am *AlertManager) ClearAlerts() {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alerts = am.alerts[:0]
}

// HistogramBucket represents a histogram bucket
type HistogramBucket struct {
	Le    float64 // Upper bound
	Count uint64
}

// Histogram tracks value distributions
type Histogram struct {
	buckets []HistogramBucket
	sum     atomic.Int64
	count   atomic.Uint64
	mu      sync.Mutex
}

// NewHistogram creates a new histogram with the given bucket boundaries
func NewHistogram(boundaries []float64) *Histogram {
	sort.Float64s(boundaries)
	buckets := make([]HistogramBucket, len(boundaries)+1)
	for i, b := range boundaries {
		buckets[i] = HistogramBucket{Le: b}
	}
	buckets[len(boundaries)] = HistogramBucket{Le: 1e18} // +Inf
	return &Histogram{buckets: buckets}
}

// Observe records a value
func (h *Histogram) Observe(value float64) {
	h.mu.Lock()
	for i := range h.buckets {
		if value <= h.buckets[i].Le {
			h.buckets[i].Count++
		}
	}
	h.mu.Unlock()
	h.sum.Add(int64(value * 1000)) // Store as milliseconds for precision
	h.count.Add(1)
}

// Sum returns the sum of all observed values
func (h *Histogram) Sum() float64 {
	return float64(h.sum.Load()) / 1000.0
}

// Count returns the count of observations
func (h *Histogram) Count() uint64 {
	return h.count.Load()
}

// Buckets returns a copy of the buckets
func (h *Histogram) Buckets() []HistogramBucket {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]HistogramBucket, len(h.buckets))
	copy(result, h.buckets)
	return result
}

// TimeSeriesPoint represents a point in a time series
type TimeSeriesPoint struct {
	Timestamp time.Time
	Value     float64
}

// TimeSeries stores time-series data with aggregation
type TimeSeries struct {
	points     []TimeSeriesPoint
	maxPoints  int
	resolution time.Duration
	mu         sync.RWMutex
}

// NewTimeSeries creates a new time series
func NewTimeSeries(maxPoints int, resolution time.Duration) *TimeSeries {
	return &TimeSeries{
		points:     make([]TimeSeriesPoint, 0, maxPoints),
		maxPoints:  maxPoints,
		resolution: resolution,
	}
}

// Add adds a point to the time series
func (ts *TimeSeries) Add(value float64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now().Truncate(ts.resolution)

	// Aggregate if same time bucket
	if len(ts.points) > 0 {
		last := &ts.points[len(ts.points)-1]
		if last.Timestamp.Equal(now) {
			last.Value = (last.Value + value) / 2 // Average
			return
		}
	}

	ts.points = append(ts.points, TimeSeriesPoint{
		Timestamp: now,
		Value:     value,
	})

	// Trim old points
	if len(ts.points) > ts.maxPoints {
		ts.points = ts.points[len(ts.points)-ts.maxPoints:]
	}
}

// GetRange returns points within a time range
func (ts *TimeSeries) GetRange(start, end time.Time) []TimeSeriesPoint {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var result []TimeSeriesPoint
	for _, p := range ts.points {
		if (p.Timestamp.Equal(start) || p.Timestamp.After(start)) &&
			(p.Timestamp.Equal(end) || p.Timestamp.Before(end)) {
			result = append(result, p)
		}
	}
	return result
}

// Average returns the average value over the time series
func (ts *TimeSeries) Average() float64 {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if len(ts.points) == 0 {
		return 0
	}
	var sum float64
	for _, p := range ts.points {
		sum += p.Value
	}
	return sum / float64(len(ts.points))
}

// Last returns the most recent value
func (ts *TimeSeries) Last() float64 {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if len(ts.points) == 0 {
		return 0
	}
	return ts.points[len(ts.points)-1].Value
}

// Metrics holds all node metrics
type Metrics struct {
	// Transaction metrics
	TxProcessed   atomic.Uint64
	TxFailed      atomic.Uint64
	TxPoolSize    atomic.Int64
	TxPoolPending atomic.Int64

	// Block metrics
	BlocksProcessed atomic.Uint64
	BlockHeight     atomic.Uint64
	BlockTime       atomic.Int64 // nanoseconds

	// Consensus metrics
	VotesReceived atomic.Uint64
	VotesSent     atomic.Uint64
	ProposalsMade atomic.Uint64

	// Network metrics
	PeersConnected atomic.Int64
	BytesSent      atomic.Uint64
	BytesReceived  atomic.Uint64
	MessagesIn     atomic.Uint64
	MessagesOut    atomic.Uint64

	// RPC metrics
	RPCRequests     atomic.Uint64
	RPCErrors       atomic.Uint64
	RPCLatencySum   atomic.Int64 // nanoseconds sum
	RPCLatencyCount atomic.Uint64

	// R14-LOW (P2P-LOW-04/05/06): P2P/RPC observability gaps.
	// These fields are populated by the WebSocket server and the P2P host
	// via Set* methods below. They are exposed via the /metrics endpoint so
	// operators can alert on:
	//   - WSDroppedEvents: events lost when a slow subscriber's channel
	//     fills up. A non-zero rate means subscribers are missing block
	//     heads / logs / pending-tx notifications — investigate client
	//     health or buffer sizes.
	//   - WSActiveConnections / WSActiveSubscriptions: gauge of live WS
	//     load. A sudden drop signals a disconnect storm; a steady climb
	//     toward MaxConns signals capacity exhaustion.
	//   - HandshakeFailures: cumulative P2P handshake rejections (rate-
	//     limited / PoW-failed / signature-failed / other). A burst
	//     indicates an attacker probing the P2P layer with malformed
	//     handshakes — pair with perIPLimiter logs for source IP.
	WSDroppedEvents       atomic.Uint64
	WSActiveConnections   atomic.Int64
	WSActiveSubscriptions atomic.Int64
	HandshakeFailures     atomic.Uint64

	// State metrics
	StateSize     atomic.Int64
	AccountCount  atomic.Int64
	ContractCount atomic.Int64

	// Performance metrics
	TPS     atomic.Int64 // transactions per second (x100 for precision)
	Latency atomic.Int64 // average latency in nanoseconds

	// System metrics (updated periodically)
	MemAlloc      atomic.Uint64
	MemSys        atomic.Uint64
	NumGoroutines atomic.Int64
	NumGC         atomic.Uint64

	// Enhanced metrics for Requirements 17.1, 17.2
	// Histograms for latency distribution
	TxLatencyHist  *Histogram // Transaction latency histogram
	BlockTimeHist  *Histogram // Block processing time histogram
	RPCLatencyHist *Histogram // RPC latency histogram

	// Time series for aggregation (Requirements 17.4)
	TPSSeries     *TimeSeries // TPS over time
	LatencySeries *TimeSeries // Latency over time
	MemorySeries  *TimeSeries // Memory usage over time

	// Additional system metrics
	CPUUsage       atomic.Int64 // CPU usage percentage (x100)
	DiskUsage      atomic.Int64 // Disk usage in bytes
	DiskReadBytes  atomic.Uint64
	DiskWriteBytes atomic.Uint64
	HeapObjects    atomic.Uint64
	StackInUse     atomic.Uint64

	// QVM metrics
	QVMExecutions atomic.Uint64
	QVMGasUsed    atomic.Uint64
	QVMErrors     atomic.Uint64

	// Block-STM parallel execution metrics
	STMExecutions         atomic.Uint64
	STMConflicts          atomic.Uint64
	STMRetries            atomic.Uint64
	STMSequentialFallback atomic.Uint64
	STMSpeedup            atomic.Int64 // speedup ratio x100
	STMBatchSize          atomic.Int64 // last batch size

	// Cache metrics
	CacheHits      atomic.Uint64
	CacheMisses    atomic.Uint64
	CacheEvictions atomic.Uint64

	// Consensus detailed metrics
	FinalityTime   atomic.Int64 // Time to finality in nanoseconds
	SlashingEvents atomic.Uint64
	MissedBlocks   atomic.Uint64

	// Alert manager (Requirements 17.3)
	alertManager *AlertManager

	// W-P3-2 (2026-07-14): Rollup metric provider for L2 alert rules.
	// Nil when rollup is not enabled; alert rules check for nil and return 0.
	// Protected by mu (same RWMutex used for labels).
	rollupProvider RollupMetricProvider
	// P3-1 (2026-07-15): DA metric provider for DA alert rules.
	// Nil when DA metrics are not enabled; alert rules check for nil and
	// return 0. Protected by mu.
	daProvider DAMetricProvider
	// P3-2 (2026-07-15): Bridge metric provider for cross-chain bridge
	// alert rules. Nil when the bridge is not enabled; alert rules check
	// for nil and return 0. Protected by mu.
	bridgeProvider BridgeMetricProvider
	// P3-3 (2026-07-15): Three Chambers metric provider for Three Chambers
	// Finality alert rules. Nil when Three Chambers is not enabled; alert
	// rules check for nil and return 0. Protected by mu.
	threeChambersProvider ThreeChambersMetricProvider
	// P3-T1 (2026-07-15): Ministry metric provider for Ministry governance
	// alert rules. Nil when Ministry metrics are not enabled; alert rules
	// check for nil and return 0. Protected by mu.
	ministryProvider MinistryMetricProvider
	// R7-OBS-2 (2026-07-18): TSS metric provider for DKG startup performance
	// alert rules. Nil when TSS metrics are not wired (e.g. tests, cold
	// start before initMetrics); alert rules check for nil and return 0.
	// Protected by mu.
	tssProvider TSSMetricProvider

	// AUDIT-FULL ROUND4 LOW-02: Configurable bridge alert thresholds.
	// When nil (the default), setupBridgeAlertRules reads from
	// DefaultBridgeAlertThresholds(). Set via SetBridgeAlertThresholds.
	// Protected by mu.
	bridgeAlertThresholds *BridgeAlertThresholds

	// Internal
	startTime time.Time
	mu        sync.RWMutex
	labels    map[string]string
}

// New creates a new Metrics instance
func New() *Metrics {
	// Default histogram buckets for latency (in seconds)
	latencyBuckets := []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}
	// Block time buckets (in seconds)
	blockTimeBuckets := []float64{0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 30.0, 60.0}

	m := &Metrics{
		startTime:      time.Now(),
		labels:         make(map[string]string),
		TxLatencyHist:  NewHistogram(latencyBuckets),
		BlockTimeHist:  NewHistogram(blockTimeBuckets),
		RPCLatencyHist: NewHistogram(latencyBuckets),
		TPSSeries:      NewTimeSeries(1440, time.Minute), // 24 hours at 1-minute resolution
		LatencySeries:  NewTimeSeries(1440, time.Minute), // 24 hours at 1-minute resolution
		MemorySeries:   NewTimeSeries(1440, time.Minute), // 24 hours at 1-minute resolution
		alertManager:   NewAlertManager(),
	}

	// Setup default alert rules (Requirements 17.3)
	m.setupDefaultAlertRules()

	return m
}

// setupDefaultAlertRules configures default alert rules
func (m *Metrics) setupDefaultAlertRules() {
	// High memory usage alert
	m.alertManager.AddRule(&AlertRule{
		Name:      "high_memory_usage",
		MetricFn:  func(m *Metrics) float64 { return float64(m.MemAlloc.Load()) / (1024 * 1024 * 1024) }, // GB
		Threshold: 4.0,                                                                                   // 4GB
		Level:     AlertWarning,
		Message:   "Memory usage exceeds 4GB",
		Enabled:   true,
	})

	// Critical memory usage alert
	m.alertManager.AddRule(&AlertRule{
		Name:      "critical_memory_usage",
		MetricFn:  func(m *Metrics) float64 { return float64(m.MemAlloc.Load()) / (1024 * 1024 * 1024) },
		Threshold: 8.0, // 8GB
		Level:     AlertCritical,
		Message:   "Memory usage exceeds 8GB - critical",
		Enabled:   true,
	})

	// Low peer count alert
	m.alertManager.AddRule(&AlertRule{
		Name:      "low_peer_count",
		MetricFn:  func(m *Metrics) float64 { return float64(10 - m.PeersConnected.Load()) }, // Inverted
		Threshold: 7.0,                                                                       // Less than 3 peers
		Level:     AlertWarning,
		Message:   "Connected peers below minimum threshold",
		Enabled:   true,
	})

	// High transaction failure rate
	m.alertManager.AddRule(&AlertRule{
		Name: "high_tx_failure_rate",
		MetricFn: func(m *Metrics) float64 {
			total := m.TxProcessed.Load() + m.TxFailed.Load()
			if total == 0 {
				return 0
			}
			return float64(m.TxFailed.Load()) / float64(total) * 100
		},
		Threshold: 10.0, // 10% failure rate
		Level:     AlertWarning,
		Message:   "Transaction failure rate exceeds 10%",
		Enabled:   true,
	})

	// High RPC error rate
	m.alertManager.AddRule(&AlertRule{
		Name: "high_rpc_error_rate",
		MetricFn: func(m *Metrics) float64 {
			total := m.RPCRequests.Load()
			if total == 0 {
				return 0
			}
			return float64(m.RPCErrors.Load()) / float64(total) * 100
		},
		Threshold: 5.0, // 5% error rate
		Level:     AlertWarning,
		Message:   "RPC error rate exceeds 5%",
		Enabled:   true,
	})

	// High goroutine count
	m.alertManager.AddRule(&AlertRule{
		Name:      "high_goroutine_count",
		MetricFn:  func(m *Metrics) float64 { return float64(m.NumGoroutines.Load()) },
		Threshold: 10000,
		Level:     AlertWarning,
		Message:   "Goroutine count exceeds 10000",
		Enabled:   true,
	})

	// Slow finality
	m.alertManager.AddRule(&AlertRule{
		Name:      "slow_finality",
		MetricFn:  func(m *Metrics) float64 { return float64(m.FinalityTime.Load()) / float64(time.Second) },
		Threshold: 5.0, // 5 seconds
		Level:     AlertWarning,
		Message:   "Block finality time exceeds 5 seconds",
		Enabled:   true,
	})

	// W-P3-2 (2026-07-14): Rollup alert rules. Each MetricFn checks for nil
	// provider and returns 0 (no alert) when rollup is not enabled. This
	// allows the rules to be registered unconditionally at startup.
	m.setupRollupAlertRules()

	// P3-3 (2026-07-15): DA alert rules. Same nil-safe pattern as rollup.
	m.setupDAAlertRules()

	// P3-3 (2026-07-15): Three Chambers Finality alert rules. Same nil-safe pattern.
	m.setupThreeChambersAlertRules()

	// P3-2 (2026-07-15): Bridge alert rules. Same nil-safe pattern.
	m.setupBridgeAlertRules()

	// P3-T3 (2026-07-15): Ministry governance alert rules. Same nil-safe pattern.
	m.setupMinistryAlertRules()

	// R7-OBS-2 (2026-07-18): TSS DKG startup health alert rules.
	m.setupTSSAlertRules()
}

// setupRollupAlertRules registers 6 alert rules for L2 rollup monitoring.
// W-P3-2 (5 rules) + W-P3-3 (1 panic rule).
//
// Rules fire when value > threshold:
//  1. rollup_engine_stopped: status != Running (value = 1 when stopped)
//  2. rollup_consecutive_batch_failures: > 5 consecutive failures
//  3. rollup_l1_anchor_lag_high: > 10 L1 blocks since last anchor
//  4. rollup_fraud_proof_submitted: any fraud proof submitted (threshold 0.5)
//  5. rollup_pending_txs_backlog: > 10000 pending transactions
//  6. rollup_batch_loop_panic: any panic in batchLoop (threshold 0.5)
//
// The MetricFn closures read from m.rollupProvider via a nil-safe helper.
func (m *Metrics) setupRollupAlertRules() {
	// 1. Rollup engine stopped (status != Running)
	m.alertManager.AddRule(&AlertRule{
		Name: "rollup_engine_stopped",
		MetricFn: func(m *Metrics) float64 {
			p := m.getRollupProvider()
			if p == nil {
				return 0
			}
			// Alert when status != 1 (Running). Return 1 when stopped, 0 when running.
			if v := p.StatusValue(); v != float64(1) {
				return 1
			}
			return 0
		},
		Threshold: 0.5,
		Level:     AlertCritical,
		Message:   "Rollup engine is not running (status != Running)",
		Enabled:   true,
	})

	// 2. Consecutive batch failures > 5
	m.alertManager.AddRule(&AlertRule{
		Name: "rollup_consecutive_batch_failures",
		MetricFn: func(m *Metrics) float64 {
			p := m.getRollupProvider()
			if p == nil {
				return 0
			}
			return p.ConsecutiveBatchFailuresValue()
		},
		Threshold: 5.0,
		Level:     AlertWarning,
		Message:   "Rollup consecutive batch failures exceed 5",
		Enabled:   true,
	})

	// 3. L1 anchor lag > 10 L1 blocks
	m.alertManager.AddRule(&AlertRule{
		Name: "rollup_l1_anchor_lag_high",
		MetricFn: func(m *Metrics) float64 {
			p := m.getRollupProvider()
			if p == nil {
				return 0
			}
			return p.L1AnchorLagValue()
		},
		Threshold: 10.0,
		Level:     AlertWarning,
		Message:   "Rollup L1 anchor lag exceeds 10 L1 blocks",
		Enabled:   true,
	})

	// 4. Fraud proof submitted (any — threshold 0.5 so any count >= 1 fires)
	m.alertManager.AddRule(&AlertRule{
		Name: "rollup_fraud_proof_submitted",
		MetricFn: func(m *Metrics) float64 {
			p := m.getRollupProvider()
			if p == nil {
				return 0
			}
			return p.FraudProofsSubmittedValue()
		},
		Threshold: 0.5,
		Level:     AlertWarning,
		Message:   "Rollup fraud proof submitted — investigate immediately",
		Enabled:   true,
	})

	// 5. Pending transactions backlog > 10000
	m.alertManager.AddRule(&AlertRule{
		Name: "rollup_pending_txs_backlog",
		MetricFn: func(m *Metrics) float64 {
			p := m.getRollupProvider()
			if p == nil {
				return 0
			}
			return p.PendingTxsValue()
		},
		Threshold: 10000.0,
		Level:     AlertWarning,
		Message:   "Rollup pending transactions backlog exceeds 10000",
		Enabled:   true,
	})

	// 6. W-P3-3: batchLoop panic (any — threshold 0.5 so any count >= 1 fires)
	m.alertManager.AddRule(&AlertRule{
		Name: "rollup_batch_loop_panic",
		MetricFn: func(m *Metrics) float64 {
			p := m.getRollupProvider()
			if p == nil {
				return 0
			}
			return p.BatchLoopPanicsValue()
		},
		Threshold: 0.5,
		Level:     AlertCritical,
		Message:   "Rollup batchLoop panic recovered — investigate immediately",
		Enabled:   true,
	})
}

// SetRollupMetricProvider injects the rollup metric provider so the alert
// manager can evaluate L2 alert rules. Call this after the rollup engine is
// initialized. Passing nil disables all rollup alert rules (they return 0).
// W-P3-2 (2026-07-14)
func (m *Metrics) SetRollupMetricProvider(p RollupMetricProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollupProvider = p
}

// getRollupProvider returns the current rollup metric provider under a read
// lock. Returns nil if not set (rollup not enabled).
func (m *Metrics) getRollupProvider() RollupMetricProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rollupProvider
}

// setupDAAlertRules registers 5 alert rules for DA (Data Availability)
// committee and danksharding monitoring. P3-3 (2026-07-15).
//
// Rules fire when value > threshold:
//  1. da_committee_unavailable: committee_available < 0.5 (i.e., unavailable)
//     — fires when 1-available > 0.5, so unavailable nodes alert.
//  2. da_sampling_confidence_low: confidence < 0.95
//     — fires when (1-confidence) > 0.05.
//  3. da_blob_storage_large: blob storage > 10 GB
//     — warns of unbounded blob growth (GC misconfigured).
//  4. da_verifier_rejections: any verifier rejection
//     — fires on any non-zero value (could indicate attack or misconfig).
//  5. da_attestation_collection_low: attestation_count / committee_size < 0.66
//     — fires when (1 - rate) > 0.34, i.e., collection rate < 66% (DoD P3-3).
//
// The "DA committee unavailable > 1 epoch" duration is enforced by the
// Prometheus Alertmanager `for:` clause in ops/alerts.yaml (1 epoch ≈ 51min
// at 12s slot time × 256 slots). The Go-side rule here is the instantaneous
// trigger; Alertmanager suppresses flapping below the `for:` duration.
//
// The MetricFn closures read from m.daProvider via a nil-safe helper.
func (m *Metrics) setupDAAlertRules() {
	// 1. DA committee unavailable (critical)
	// Returns 1 when unavailable, 0 when available. Fires at threshold 0.5.
	m.alertManager.AddRule(&AlertRule{
		Name: "da_committee_unavailable",
		MetricFn: func(m *Metrics) float64 {
			p := m.getDAProvider()
			if p == nil {
				return 0
			}
			// Alert when CommitteeAvailableValue() < 0.5 (i.e., unavailable).
			// Invert so the rule fires on unavailable: 1 - available.
			return 1 - p.CommitteeAvailableValue()
		},
		Threshold: 0.5,
		Level:     AlertCritical,
		Message:   "DA committee is unavailable — block production may stall",
		Enabled:   true,
	})

	// 2. Sampling confidence low (warning)
	// Returns (1 - confidence) so the rule fires when confidence < 0.95.
	m.alertManager.AddRule(&AlertRule{
		Name: "da_sampling_confidence_low",
		MetricFn: func(m *Metrics) float64 {
			p := m.getDAProvider()
			if p == nil {
				return 0
			}
			confidence := p.SamplingConfidenceValue()
			// Only alert when confidence has been set (>0 means at least one
			// sampling run completed). Before any sampling, confidence is 0
			// but we don't want to alert on cold start.
			if confidence <= 0 {
				return 0
			}
			return 1 - confidence
		},
		Threshold: 0.05, // fires when (1 - confidence) > 0.05, i.e., confidence < 0.95
		Level:     AlertWarning,
		Message:   "DA sampling confidence below 0.95 — data availability may be degraded",
		Enabled:   true,
	})

	// 3. Blob storage large (warning) — > 10 GB
	m.alertManager.AddRule(&AlertRule{
		Name: "da_blob_storage_large",
		MetricFn: func(m *Metrics) float64 {
			p := m.getDAProvider()
			if p == nil {
				return 0
			}
			// Convert bytes to GB so the threshold is human-readable.
			return p.BlobStorageSizeValue() / (1024 * 1024 * 1024)
		},
		Threshold: 10.0,
		Level:     AlertWarning,
		Message:   "DA blob storage exceeds 10GB — check GC configuration",
		Enabled:   true,
	})

	// 4. Verifier rejections (warning) — any non-zero value
	m.alertManager.AddRule(&AlertRule{
		Name: "da_verifier_rejections",
		MetricFn: func(m *Metrics) float64 {
			p := m.getDAProvider()
			if p == nil {
				return 0
			}
			return p.VerifierRejectionsValue()
		},
		Threshold: 0.5, // fires on any count >= 1
		Level:     AlertWarning,
		Message:   "DA attestation verifier rejected at least one submission — investigate attack or misconfiguration",
		Enabled:   true,
	})

	// 5. Attestation collection rate low (warning) — rate < 0.66.
	// P3-3 DoD: "attestation collection rate < 66%". The collection rate is
	// attestation_count / committee_size. We return (1 - rate) so the rule
	// fires when (1 - rate) > 0.34, i.e., rate < 0.66.
	// Cold-start safe: when committee_size=0 (not yet configured) or
	// attestation_count=0 (no slot processed yet), returns 0 to avoid
	// false positives during node startup.
	m.alertManager.AddRule(&AlertRule{
		Name: "da_attestation_collection_low",
		MetricFn: func(m *Metrics) float64 {
			p := m.getDAProvider()
			if p == nil {
				return 0
			}
			committeeSize := p.CommitteeSizeValue()
			if committeeSize <= 0 {
				return 0 // committee size not configured yet
			}
			attestationCount := p.AttestationCountValue()
			rate := attestationCount / committeeSize
			if rate >= 1 {
				return 0 // cap at 1.0 — more attestations than committee size is healthy
			}
			return 1 - rate
		},
		Threshold: 0.34, // fires when (1 - rate) > 0.34, i.e., rate < 0.66
		Level:     AlertWarning,
		Message:   "DA attestation collection rate below 66% — committee participation degraded",
		Enabled:   true,
	})
}

// SetDAMetricProvider injects the DA metric provider so the alert manager
// can evaluate DA alert rules. Call this after the DankshardingEngine is
// initialized and DAMetrics is created. Passing nil disables all DA alert
// rules (they return 0). P3-1 (2026-07-15)
func (m *Metrics) SetDAMetricProvider(p DAMetricProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.daProvider = p
}

// getDAProvider returns the current DA metric provider under a read lock.
// Returns nil if not set (DA metrics not enabled).
func (m *Metrics) getDAProvider() DAMetricProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.daProvider
}

// setupThreeChambersAlertRules registers 2 alert rules for Three Chambers
// Finality monitoring. P3-3 (2026-07-15).
//
// Rules fire when value > threshold:
//  1. three_chambers_evidence_queue_backlog: evidence queue length > 100
//     — Warning: early backlog detection before the 10000 hard cap (MaxEvidenceQueue).
//     A growing backlog means slashing evidence is not being drained fast
//     enough (SlashingManager may be down or slow).
//  2. three_chambers_dkg_stuck: DKG elapsed > 1800 seconds (30 minutes)
//     — Critical: DKG has made no progress for 30 minutes. The executive
//     chamber cannot activate without a group public key, blocking block
//     finality.
//
// The MetricFn closures read from m.threeChambersProvider via a nil-safe
// helper. When the provider is nil (Three Chambers not enabled), all rules
// return 0 (no alert) — this allows the rules to be registered unconditionally
// at startup without firing on nodes that don't use Three Chambers.
func (m *Metrics) setupThreeChambersAlertRules() {
	// 1. Evidence queue backlog > 100 (warning)
	// Fires when the slashing evidence queue depth exceeds 100 entries. This
	// is an early warning — the hard cap is 10000 (MaxEvidenceQueue), at which
	// point evidence starts being dropped. 100 indicates a backlog that should
	// be investigated before it becomes critical.
	m.alertManager.AddRule(&AlertRule{
		Name: "three_chambers_evidence_queue_backlog",
		MetricFn: func(m *Metrics) float64 {
			p := m.getThreeChambersProvider()
			if p == nil {
				return 0
			}
			return p.EvidenceQueueLengthValue()
		},
		Threshold: 100.0,
		Level:     AlertWarning,
		Message:   "Three Chambers slashing evidence queue backlog exceeds 100 entries — SlashingManager may be slow or down",
		Enabled:   true,
	})

	// 2. DKG stuck > 30 minutes (critical)
	// Fires when the executive chamber's DKG has been running for more than
	// 1800 seconds (30 minutes) without completing. A stuck DKG means the
	// group public key is not available, so the executive chamber cannot
	// activate, which blocks QTD threshold signing and block finality.
	// Cold-start safe: returns 0 when DKG is not running (Idle/Active/Sealing)
	// or when dkgStartTime is zero.
	m.alertManager.AddRule(&AlertRule{
		Name: "three_chambers_dkg_stuck",
		MetricFn: func(m *Metrics) float64 {
			p := m.getThreeChambersProvider()
			if p == nil {
				return 0
			}
			return p.DKGElapsedSecondsValue()
		},
		Threshold: 1800.0, // 30 minutes in seconds
		Level:     AlertCritical,
		Message:   "Three Chambers DKG has been running for over 30 minutes without completion — executive chamber cannot activate, block finality at risk",
		Enabled:   true,
	})
}

// SetThreeChambersMetricProvider injects the Three Chambers metric provider
// so the alert manager can evaluate Three Chambers Finality alert rules.
// Call this after the ThreeChambersCoordinator is initialized. Passing nil
// disables all Three Chambers alert rules (they return 0).
// P3-3 (2026-07-15)
func (m *Metrics) SetThreeChambersMetricProvider(p ThreeChambersMetricProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.threeChambersProvider = p
}

// getThreeChambersProvider returns the current Three Chambers metric provider
// under a read lock. Returns nil if not set (Three Chambers not enabled).
func (m *Metrics) getThreeChambersProvider() ThreeChambersMetricProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.threeChambersProvider
}

// SetMinistryMetricProvider injects the Ministry metric provider so the alert
// manager can evaluate Ministry governance alert rules. Call this after the
// MinistryRegistry is initialized and MinistryMetrics is created. Passing nil
// disables all Ministry alert rules (they return 0). P3-T1 (2026-07-15)
func (m *Metrics) SetMinistryMetricProvider(p MinistryMetricProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ministryProvider = p
}

// getMinistryProvider returns the current Ministry metric provider under a
// read lock. Returns nil if not set (Ministry metrics not enabled).
func (m *Metrics) getMinistryProvider() MinistryMetricProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ministryProvider
}

// SetTSSMetricProvider injects the TSS metric provider so the alert manager
// can evaluate TSS DKG startup health alert rules. Call this after node
// metrics are created and the TSS subsystem is initialized. Passing nil
// disables all TSS alert rules (they return 0). R7-OBS-2 (2026-07-18)
func (m *Metrics) SetTSSMetricProvider(p TSSMetricProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tssProvider = p
}

// getTSSProvider returns the current TSS metric provider under a read lock.
// Returns nil if not set (TSS metrics not wired).
func (m *Metrics) getTSSProvider() TSSMetricProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tssProvider
}

// setupTSSAlertRules registers 3 alert rules for TSS DKG startup health
// monitoring. R7-OBS-2 (2026-07-18); R8-OBS-1 (2026-07-18) adds rule 3.
//
// Audit observation (Medium): "The transition to distributed DKG increases
// computational overhead during node startup. Monitoring is recommended to
// ensure node synchronization times remain within acceptable bounds during
// peak load."
//
// Rules fire when value > threshold:
//  1. tss_dkg_duration_high: DKG p95 duration > 5 seconds
//     — Warning: DKG is taking longer than expected. May indicate CPU
//     contention, large validator sets, or peak-load synchronization
//     stress. Investigate node resource usage during startup.
//  2. tss_dkg_failed_total: any DKG failure (count > 0)
//     — Critical: DKG has failed at least once. The node may be unable to
//     produce threshold signatures for QPOS consensus. Investigate logs
//     for the underlying error (insufficient shares, peer connectivity,
//     threshold misconfiguration, etc.).
//  3. tss_simulated_dkg_used: any simulated DKG invocation (count > 0)
//     — Critical: the simulated (trusted-dealer) DKG path was used. On
//     mainnet this should be impossible (hard guard in node/config.go
//     Validate() blocks runtime DKG). A non-zero value on mainnet
//     indicates a critical configuration bypass. On testnet/devnet
//     this is expected for testing but should be monitored.
//
// The MetricFn closures read from m.tssProvider via a nil-safe helper.
// When the provider is nil (TSS metrics not wired — e.g., test deployments),
// all rules return 0 (no alert).
//
// Cold-start safe: when no DKG has been observed, DKGDurationP95Value
// returns 0 (no alert).
func (m *Metrics) setupTSSAlertRules() {
	// 1. DKG duration high (Warning) — p95 > 5 seconds.
	//
	// The QTDDKGDuration histogram uses ExponentialBuckets(0.001, 2, 10),
	// so the bucket boundaries are roughly 1ms, 2ms, 4ms, ..., 512ms.
	// The 5s threshold sits in the +Inf bucket — p95 will only exceed 5s
	// when a meaningful fraction of DKG runs are slow.
	m.alertManager.AddRule(&AlertRule{
		Name: "tss_dkg_duration_high",
		MetricFn: func(m *Metrics) float64 {
			p := m.getTSSProvider()
			if p == nil {
				return 0
			}
			return p.DKGDurationP95Value()
		},
		Threshold: 5.0, // > 5 seconds
		Level:     AlertWarning,
		Message:   "TSS DKG p95 duration exceeds 5 seconds — investigate node CPU contention or large validator sets during startup",
		Enabled:   true,
	})

	// 2. DKG failure (Critical) — any failure.
	m.alertManager.AddRule(&AlertRule{
		Name: "tss_dkg_failed_total",
		MetricFn: func(m *Metrics) float64 {
			p := m.getTSSProvider()
			if p == nil {
				return 0
			}
			return p.DKGFailedCountValue()
		},
		Threshold: 0.5, // fires when count >= 1
		Level:     AlertCritical,
		Message:   "TSS DKG has failed at least once — node may be unable to produce threshold signatures for QPOS consensus",
		Enabled:   true,
	})

	// 3. Simulated DKG used (Critical) — any invocation.
	// R8-OBS-1 (2026-07-18): defense-in-depth alert. The mainnet hard
	// guard in node/config.go Validate() blocks runtime DKG entirely,
	// so this counter should never increment on mainnet. A non-zero value
	// on mainnet means the hard guard was bypassed — investigate
	// immediately. On testnet/devnet a non-zero value is expected
	// (testing) but should be acknowledged by operators.
	m.alertManager.AddRule(&AlertRule{
		Name: "tss_simulated_dkg_used",
		MetricFn: func(m *Metrics) float64 {
			p := m.getTSSProvider()
			if p == nil {
				return 0
			}
			return p.SimulatedDKGInvocationsValue()
		},
		Threshold: 0.5, // fires when count >= 1
		Level:     AlertCritical,
		Message:   "TSS simulated (trusted-dealer) DKG path was used — on mainnet this indicates a critical configuration bypass; on testnet/devnet this is expected for testing",
		Enabled:   true,
	})
}

// setupBridgeAlertRules registers 5 alert rules for cross-chain bridge
// monitoring. P3-2 (2026-07-15).
//
// Rules fire when value > threshold:
//  1. bridge_message_processing_stopped: seconds since last processed
//     message > 300 (5 minutes). Critical — indicates the processing loop
//     is stalled (adapter RPC down, deadlocked, or panicked).
//  2. bridge_failed_messages_high: FAILED message count > 100. Warning —
//     sustained failures indicate target-chain issues or persistent bugs.
//  3. bridge_validator_quorum_lost: active validators < threshold
//     (value = 1 when quorum cannot be reached). Critical — arbitration
//     cannot finalize any message.
//  4. bridge_l1_anchor_lag_high: L1 blocks since last Merkle root anchor
//     > 20. Warning — root lag means cross-chain messages may be at risk
//     of source-chain reorg.
//  5. bridge_relayer_disconnected: relayer disconnected (value = 1).
//     Critical — without a relayer, no messages can be relayed across
//     chains.
//
// AUDIT-FULL ROUND4 LOW-02 FIX: All thresholds are now read from
// m.getBridgeAlertThresholds() rather than being inlined as magic numbers.
// When no override has been set via SetBridgeAlertThresholds, the defaults
// are byte-identical to the pre-fix values (300, 100, 0.5, 20, 0.5).
//
// The MetricFn closures read from m.bridgeProvider via a nil-safe helper.
// Cold-start safe: when LastMessageProcessedAt=0 (no message ever
// processed), MessageProcessingStalledValue returns 0 to avoid false
// positives during node startup.
func (m *Metrics) setupBridgeAlertRules() {
	t := m.getBridgeAlertThresholds()

	// 1. Message processing stopped (Critical) — stalled for > threshold seconds.
	m.alertManager.AddRule(&AlertRule{
		Name: "bridge_message_processing_stopped",
		MetricFn: func(m *Metrics) float64 {
			p := m.getBridgeProvider()
			if p == nil {
				return 0
			}
			return p.MessageProcessingStalledValue()
		},
		Threshold: t.MessageProcessingStalledSeconds,
		Level:     AlertCritical,
		Message:   "Bridge message processing stalled for > 5 minutes — processing loop may be deadlocked or panicked",
		Enabled:   true,
	})

	// 2. Failed messages backlog (Warning) — > threshold FAILED messages.
	m.alertManager.AddRule(&AlertRule{
		Name: "bridge_failed_messages_high",
		MetricFn: func(m *Metrics) float64 {
			p := m.getBridgeProvider()
			if p == nil {
				return 0
			}
			return p.FailedMessagesValue()
		},
		Threshold: t.FailedMessagesBacklog,
		Level:     AlertWarning,
		Message:   "Bridge FAILED message count exceeds 100 — investigate target-chain issues or persistent failures",
		Enabled:   true,
	})

	// 3. Validator quorum lost (Critical) — active < threshold.
	// Returns 1 when quorum cannot be reached, 0 otherwise.
	m.alertManager.AddRule(&AlertRule{
		Name: "bridge_validator_quorum_lost",
		MetricFn: func(m *Metrics) float64 {
			p := m.getBridgeProvider()
			if p == nil {
				return 0
			}
			return p.QuorumLostValue()
		},
		Threshold: t.QuorumLostTrigger,
		Level:     AlertCritical,
		Message:   "Bridge arbitration quorum lost — active validators below BFT threshold, message finalization blocked",
		Enabled:   true,
	})

	// 4. L1 anchor lag high (Warning) — > threshold L1 blocks since last anchor.
	m.alertManager.AddRule(&AlertRule{
		Name: "bridge_l1_anchor_lag_high",
		MetricFn: func(m *Metrics) float64 {
			p := m.getBridgeProvider()
			if p == nil {
				return 0
			}
			return p.L1AnchorLagValue()
		},
		Threshold: t.L1AnchorLagBlocks,
		Level:     AlertWarning,
		Message:   "Bridge L1 anchor lag exceeds 20 blocks — Merkle root may be stale, reorg risk elevated",
		Enabled:   true,
	})

	// 5. Relayer disconnected (Critical).
	// Returns 1 when disconnected, 0 when connected.
	m.alertManager.AddRule(&AlertRule{
		Name: "bridge_relayer_disconnected",
		MetricFn: func(m *Metrics) float64 {
			p := m.getBridgeProvider()
			if p == nil {
				return 0
			}
			return p.RelayerDisconnectedValue()
		},
		Threshold: t.RelayerDisconnectedTrigger,
		Level:     AlertCritical,
		Message:   "Bridge relayer disconnected — no cross-chain messages can be relayed",
		Enabled:   true,
	})
}

// SetBridgeMetricProvider injects the bridge metric provider so the alert
// manager can evaluate bridge alert rules. Call this after the bridge is
// initialized and BridgeMetrics is created. Passing nil disables all bridge
// alert rules (they return 0). P3-2 (2026-07-15)
func (m *Metrics) SetBridgeMetricProvider(p BridgeMetricProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bridgeProvider = p
}

// getBridgeAlertThresholds returns the configured bridge alert thresholds, or
// DefaultBridgeAlertThresholds() when no override has been set via
// SetBridgeAlertThresholds. AUDIT-FULL ROUND4 LOW-02 FIX.
func (m *Metrics) getBridgeAlertThresholds() BridgeAlertThresholds {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.bridgeAlertThresholds != nil {
		return *m.bridgeAlertThresholds
	}
	return DefaultBridgeAlertThresholds()
}

// SetBridgeAlertThresholds sets the configurable bridge alert thresholds.
// Pass nil to revert to DefaultBridgeAlertThresholds(). This method removes
// all existing bridge alert rules (rules whose Name starts with "bridge_")
// and re-registers them with the new thresholds, so non-bridge rules are
// untouched. Call this BEFORE the first m.AlertManager().Check() that should
// observe the new values (typically at process startup after reading operator
// config / env vars). AUDIT-FULL ROUND4 LOW-02 FIX.
func (m *Metrics) SetBridgeAlertThresholds(thresholds *BridgeAlertThresholds) {
	m.mu.Lock()
	m.bridgeAlertThresholds = thresholds
	m.mu.Unlock()
	// Clear existing bridge rules and re-register with new thresholds.
	m.alertManager.RemoveRulesByNamePrefix("bridge_")
	m.setupBridgeAlertRules()
}

// getBridgeProvider returns the current bridge metric provider under a read
// lock. Returns nil if not set (bridge not enabled).
func (m *Metrics) getBridgeProvider() BridgeMetricProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bridgeProvider
}

// setupMinistryAlertRules registers 4 alert rules for Ministry governance
// monitoring. P3-T3 (2026-07-15).
//
// Rules fire when value > threshold:
//  1. ministry_quantum_attack_detected: Defense critical alerts > 0
//     — Critical: an unresolved quantum-level threat (quantum attack,
//     critical network partition) has been detected. Immediate operator
//     action required (inspect Defense ministry alerts, potentially
//     halt the chain).
//  2. ministry_network_partition_detected: partition flag > 0.5
//     — Critical: the Defense ministry has flagged an active network
//     partition. Consensus may be degraded or split.
//  3. ministry_blacklist_spike: Defense blacklist size > 10
//     — Warning: an unusually large number of validators are blacklisted.
//     Could indicate a coordinated attack, mass slashing event, or
//     misconfigured defense rules.
//  4. ministry_pending_cases_backlog: Justice pending cases > 50
//     — Warning: dispute resolution is falling behind. Pending cases
//     accumulating without resolution may delay slashing or exoneration.
//
// The MetricFn closures read from m.ministryProvider via a nil-safe helper.
// When the provider is nil (Ministry metrics not enabled), all rules return 0
// (no alert) — this allows the rules to be registered unconditionally at
// startup without firing on nodes that don't use Ministry governance.
func (m *Metrics) setupMinistryAlertRules() {
	// 1. Quantum attack / critical threat detected (Critical).
	m.alertManager.AddRule(&AlertRule{
		Name: "ministry_quantum_attack_detected",
		MetricFn: func(m *Metrics) float64 {
			p := m.getMinistryProvider()
			if p == nil {
				return 0
			}
			return p.CriticalAlertsValue()
		},
		Threshold: 0.5, // fires when value >= 1 (any critical alert)
		Level:     AlertCritical,
		Message:   "Ministry Defense: unresolved CRITICAL-level security alert detected (possible quantum attack) — inspect alerts and consider chain halt",
		Enabled:   true,
	})

	// 2. Network partition detected (Critical).
	m.alertManager.AddRule(&AlertRule{
		Name: "ministry_network_partition_detected",
		MetricFn: func(m *Metrics) float64 {
			p := m.getMinistryProvider()
			if p == nil {
				return 0
			}
			return p.PartitionDetectedValue()
		},
		Threshold: 0.5, // fires when value=1 (partition detected)
		Level:     AlertCritical,
		Message:   "Ministry Defense: network partition detected — consensus may be degraded or split, verify validator connectivity",
		Enabled:   true,
	})

	// 3. Blacklist spike (Warning) — > 10 blacklisted validators.
	m.alertManager.AddRule(&AlertRule{
		Name: "ministry_blacklist_spike",
		MetricFn: func(m *Metrics) float64 {
			p := m.getMinistryProvider()
			if p == nil {
				return 0
			}
			return p.BlacklistSizeValue()
		},
		Threshold: 10.0,
		Level:     AlertWarning,
		Message:   "Ministry Defense: blacklist size exceeds 10 validators — investigate possible coordinated attack or mass slashing event",
		Enabled:   true,
	})

	// 4. Pending cases backlog (Warning) — > 50 pending disputes.
	m.alertManager.AddRule(&AlertRule{
		Name: "ministry_pending_cases_backlog",
		MetricFn: func(m *Metrics) float64 {
			p := m.getMinistryProvider()
			if p == nil {
				return 0
			}
			return p.PendingCasesValue()
		},
		Threshold: 50.0,
		Level:     AlertWarning,
		Message:   "Ministry Justice: pending dispute cases exceed 50 — dispute resolution may be falling behind, slashing/exoneration delays expected",
		Enabled:   true,
	})
}

// SetLabel sets a label for metrics
func (m *Metrics) SetLabel(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.labels[key] = value
}

// GetLabel gets a label value
func (m *Metrics) GetLabel(key string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.labels[key]
}

// UpdateSystemMetrics updates system-level metrics
func (m *Metrics) UpdateSystemMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	m.MemAlloc.Store(memStats.Alloc)
	m.MemSys.Store(memStats.Sys)
	m.NumGoroutines.Store(int64(runtime.NumGoroutine()))
	m.NumGC.Store(uint64(memStats.NumGC))
	m.HeapObjects.Store(memStats.HeapObjects)
	m.StackInUse.Store(memStats.StackInuse)

	// Update memory time series
	if m.MemorySeries != nil {
		m.MemorySeries.Add(float64(memStats.Alloc) / (1024 * 1024)) // MB
	}
}

// RecordTxProcessed records a processed transaction
func (m *Metrics) RecordTxProcessed() {
	m.TxProcessed.Add(1)
}

// RecordTxFailed records a failed transaction
func (m *Metrics) RecordTxFailed() {
	m.TxFailed.Add(1)
}

// RecordBlockProcessed records a processed block
func (m *Metrics) RecordBlockProcessed(height uint64, blockTime time.Duration) {
	m.BlocksProcessed.Add(1)
	m.BlockHeight.Store(height)
	m.BlockTime.Store(int64(blockTime))

	// Record in histogram
	if m.BlockTimeHist != nil {
		m.BlockTimeHist.Observe(blockTime.Seconds())
	}
}

// RecordTxLatency records transaction processing latency
func (m *Metrics) RecordTxLatency(latency time.Duration) {
	if m.TxLatencyHist != nil {
		m.TxLatencyHist.Observe(latency.Seconds())
	}
	if m.LatencySeries != nil {
		m.LatencySeries.Add(float64(latency.Milliseconds()))
	}
	m.Latency.Store(int64(latency))
}

// RecordQVMExecution records a QVM execution
func (m *Metrics) RecordQVMExecution(gasUsed uint64, err error) {
	m.QVMExecutions.Add(1)
	m.QVMGasUsed.Add(gasUsed)
	if err != nil {
		m.QVMErrors.Add(1)
	}
}

// RecordCacheAccess records a cache access
func (m *Metrics) RecordCacheAccess(hit bool) {
	if hit {
		m.CacheHits.Add(1)
	} else {
		m.CacheMisses.Add(1)
	}
}

// RecordCacheEviction records a cache eviction
func (m *Metrics) RecordCacheEviction() {
	m.CacheEvictions.Add(1)
}

// RecordFinality records block finality time
func (m *Metrics) RecordFinality(duration time.Duration) {
	m.FinalityTime.Store(int64(duration))
}

// RecordSlashing records a slashing event
func (m *Metrics) RecordSlashing() {
	m.SlashingEvents.Add(1)
}

// RecordMissedBlock records a missed block
func (m *Metrics) RecordMissedBlock() {
	m.MissedBlocks.Add(1)
}

// RecordDiskIO records disk I/O
func (m *Metrics) RecordDiskIO(readBytes, writeBytes uint64) {
	m.DiskReadBytes.Add(readBytes)
	m.DiskWriteBytes.Add(writeBytes)
}

// SetDiskUsage sets the disk usage
func (m *Metrics) SetDiskUsage(bytes int64) {
	m.DiskUsage.Store(bytes)
}

// SetCPUUsage sets the CPU usage percentage
func (m *Metrics) SetCPUUsage(percent float64) {
	m.CPUUsage.Store(int64(percent * 100))
}

// GetCPUUsage returns the CPU usage percentage
func (m *Metrics) GetCPUUsage() float64 {
	return float64(m.CPUUsage.Load()) / 100.0
}

// GetCacheHitRate returns the cache hit rate
func (m *Metrics) GetCacheHitRate() float64 {
	hits := m.CacheHits.Load()
	misses := m.CacheMisses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

func (m *Metrics) GetSTMConflictRate() float64 {
	executions := m.STMExecutions.Load()
	conflicts := m.STMConflicts.Load()
	if executions == 0 {
		return 0
	}
	return float64(conflicts) / float64(executions)
}

func (m *Metrics) RecordSTMExecution(batchSize int, conflicts, retries int, sequentialFallback bool, speedup float64) {
	m.STMExecutions.Add(1)
	m.STMConflicts.Add(uint64(conflicts))
	m.STMRetries.Add(uint64(retries))
	if sequentialFallback {
		m.STMSequentialFallback.Add(1)
	}
	m.STMSpeedup.Store(int64(speedup * 100))
	m.STMBatchSize.Store(int64(batchSize))
}

// RecordRPCRequest records an RPC request
func (m *Metrics) RecordRPCRequest(latency time.Duration, err error) {
	m.RPCRequests.Add(1)
	m.RPCLatencySum.Add(int64(latency))
	m.RPCLatencyCount.Add(1)
	if err != nil {
		m.RPCErrors.Add(1)
	}
	// Record in histogram
	if m.RPCLatencyHist != nil {
		m.RPCLatencyHist.Observe(latency.Seconds())
	}
}

// RecordNetworkMessage records a network message
func (m *Metrics) RecordNetworkMessage(incoming bool, size int) {
	if incoming {
		m.MessagesIn.Add(1)
		m.BytesReceived.Add(uint64(size)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	} else {
		m.MessagesOut.Add(1)
		m.BytesSent.Add(uint64(size)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	}
}

// SetPeersConnected sets the number of connected peers
func (m *Metrics) SetPeersConnected(count int) {
	m.PeersConnected.Store(int64(count))
}

// R14-LOW (P2P-LOW-04/05/06): Setters for the new P2P/RPC observability
// metrics. These are called by the WebSocket server (WSDroppedEvents,
// WSActiveConnections, WSActiveSubscriptions) and the P2P host
// (HandshakeFailures) so the values are reflected in /metrics output.

// AddWSDroppedEvent increments the WS dropped-event counter. Called by the
// WebSocket server's Notify* methods when a subscriber's channel is full.
func (m *Metrics) AddWSDroppedEvent() {
	m.WSDroppedEvents.Add(1)
}

// SetWSActiveConnections sets the current WebSocket connection count.
func (m *Metrics) SetWSActiveConnections(count int) {
	m.WSActiveConnections.Store(int64(count))
}

// SetWSActiveSubscriptions sets the current WebSocket subscription count.
func (m *Metrics) SetWSActiveSubscriptions(count int) {
	m.WSActiveSubscriptions.Store(int64(count))
}

// AddHandshakeFailure increments the P2P handshake failure counter.
// Called by the P2P host when an inbound handshake is rejected for any
// reason (rate-limit, PoW exhaustion, signature failure, etc.).
func (m *Metrics) AddHandshakeFailure() {
	m.HandshakeFailures.Add(1)
}

// SetTxPoolSize sets the transaction pool size
func (m *Metrics) SetTxPoolSize(size int) {
	m.TxPoolSize.Store(int64(size))
}

// SetTxPoolPending sets the pending transaction count
func (m *Metrics) SetTxPoolPending(count int) {
	m.TxPoolPending.Store(int64(count))
}

// SetStateMetrics sets state-related metrics
func (m *Metrics) SetStateMetrics(size, accounts, contracts int64) {
	m.StateSize.Store(size)
	m.AccountCount.Store(accounts)
	m.ContractCount.Store(contracts)
}

// CalculateTPS calculates transactions per second
func (m *Metrics) CalculateTPS(txCount uint64, duration time.Duration) {
	if duration > 0 {
		tps := float64(txCount) / duration.Seconds()
		m.TPS.Store(int64(tps * 100)) // Store as x100 for precision

		// Record to time series for aggregation
		if m.TPSSeries != nil {
			m.TPSSeries.Add(tps)
		}
	}
}

// GetTPS returns the current TPS
func (m *Metrics) GetTPS() float64 {
	return float64(m.TPS.Load()) / 100.0
}

// GetAverageRPCLatency returns the average RPC latency
func (m *Metrics) GetAverageRPCLatency() time.Duration {
	count := m.RPCLatencyCount.Load()
	if count == 0 {
		return 0
	}
	return time.Duration(m.RPCLatencySum.Load() / int64(count)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

// Uptime returns the node uptime
func (m *Metrics) Uptime() time.Duration {
	return time.Since(m.startTime)
}

// AlertManager returns the alert manager
func (m *Metrics) AlertManager() *AlertManager {
	return m.alertManager
}

// CheckAlerts evaluates all alert rules
func (m *Metrics) CheckAlerts() []*Alert {
	if m.alertManager == nil {
		return nil
	}
	return m.alertManager.Check(m)
}

// GetAverageTPS returns the average TPS over the time series
func (m *Metrics) GetAverageTPS() float64 {
	if m.TPSSeries == nil {
		return m.GetTPS()
	}
	return m.TPSSeries.Average()
}

// GetAverageLatency returns the average latency over the time series
func (m *Metrics) GetAverageLatency() time.Duration {
	if m.LatencySeries == nil {
		return time.Duration(m.Latency.Load())
	}
	return time.Duration(m.LatencySeries.Average()) * time.Millisecond
}

// GetAverageMemory returns the average memory usage in MB
func (m *Metrics) GetAverageMemory() float64 {
	if m.MemorySeries == nil {
		return float64(m.MemAlloc.Load()) / (1024 * 1024)
	}
	return m.MemorySeries.Average()
}

// PrometheusHandler returns an HTTP handler for Prometheus metrics
// audit-fix CRITICAL: the original handler had no authentication, allowing anyone
// to access sensitive node metrics. Now requires valid token via Authorization header.
// Usage: curl -H "Authorization: Bearer <token>" http://localhost:9150/metrics
func (m *Metrics) PrometheusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// audit-fix CRITICAL: require authentication via token
		if !m.validateMetricsToken(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		m.UpdateSystemMetrics()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		m.writePrometheusMetrics(w)
	})
}

// validateMetricsToken validates the Authorization header for metrics endpoint.
// Returns true if valid token is present, false otherwise.
func (m *Metrics) validateMetricsToken(r *http.Request) bool {
	// Check for Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	// Expect "Bearer <token>" format
	const bearerPrefix = "Bearer "
	if len(authHeader) <= len(bearerPrefix) {
		return false
	}
	if authHeader[:len(bearerPrefix)] != bearerPrefix {
		return false
	}
	token := authHeader[len(bearerPrefix):]

	// Validate token - must be configured via QAU_METRICS_TOKEN environment variable.
	// If not set, all metrics requests are rejected (secure default).
	expectedToken := m.getMetricsToken()
	if expectedToken == "" {
		// If no token configured, reject all requests (secure default)
		return false
	}

	// Use constant-time comparison to prevent timing attacks
	return m.constantTimeCompare(token, expectedToken)
}

// getMetricsToken returns the configured metrics token from environment or empty string
// SECURITY FIX: Now actually reads from environment variable instead of always returning empty string
func (m *Metrics) getMetricsToken() string {
	return os.Getenv("QAU_METRICS_TOKEN")
}

// constantTimeCompare performs constant-time string comparison to prevent timing attacks.
// audit-fix L-6: delegate to crypto/subtle.ConstantTimeCompare instead of a
// hand-rolled implementation. The standard library version is audited and
// avoids subtle bugs (e.g. the previous version iterated byte-by-byte but
// returned early on length mismatch, which is fine for secrecy but redundant
// with the well-tested stdlib).
func (m *Metrics) constantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// writePrometheusMetrics writes metrics in Prometheus format
func (m *Metrics) writePrometheusMetrics(w http.ResponseWriter) {
	// Get labels string
	m.mu.RLock()
	labels := m.formatLabels()
	m.mu.RUnlock()

	// Transaction metrics
	fmt.Fprintf(w, "# HELP qau_tx_processed_total Total number of processed transactions\n")
	fmt.Fprintf(w, "# TYPE qau_tx_processed_total counter\n")
	fmt.Fprintf(w, "qau_tx_processed_total%s %d\n", labels, m.TxProcessed.Load())

	fmt.Fprintf(w, "# HELP qau_tx_failed_total Total number of failed transactions\n")
	fmt.Fprintf(w, "# TYPE qau_tx_failed_total counter\n")
	fmt.Fprintf(w, "qau_tx_failed_total%s %d\n", labels, m.TxFailed.Load())

	fmt.Fprintf(w, "# HELP qau_tx_pool_size Current transaction pool size\n")
	fmt.Fprintf(w, "# TYPE qau_tx_pool_size gauge\n")
	fmt.Fprintf(w, "qau_tx_pool_size%s %d\n", labels, m.TxPoolSize.Load())

	fmt.Fprintf(w, "# HELP qau_tx_pool_pending Current pending transactions\n")
	fmt.Fprintf(w, "# TYPE qau_tx_pool_pending gauge\n")
	fmt.Fprintf(w, "qau_tx_pool_pending%s %d\n", labels, m.TxPoolPending.Load())

	// Transaction latency histogram
	m.writeHistogram(w, "qau_tx_latency_seconds", "Transaction processing latency in seconds", m.TxLatencyHist, labels)

	// Block metrics
	fmt.Fprintf(w, "# HELP qau_blocks_processed_total Total number of processed blocks\n")
	fmt.Fprintf(w, "# TYPE qau_blocks_processed_total counter\n")
	fmt.Fprintf(w, "qau_blocks_processed_total%s %d\n", labels, m.BlocksProcessed.Load())

	fmt.Fprintf(w, "# HELP qau_block_height Current block height\n")
	fmt.Fprintf(w, "# TYPE qau_block_height gauge\n")
	fmt.Fprintf(w, "qau_block_height%s %d\n", labels, m.BlockHeight.Load())

	fmt.Fprintf(w, "# HELP qau_block_time_seconds Last block processing time in seconds\n")
	fmt.Fprintf(w, "# TYPE qau_block_time_seconds gauge\n")
	fmt.Fprintf(w, "qau_block_time_seconds%s %.6f\n", labels, float64(m.BlockTime.Load())/1e9)

	// Block time histogram
	m.writeHistogram(w, "qau_block_time_histogram_seconds", "Block processing time distribution", m.BlockTimeHist, labels)

	// Consensus metrics
	fmt.Fprintf(w, "# HELP qau_votes_received_total Total votes received\n")
	fmt.Fprintf(w, "# TYPE qau_votes_received_total counter\n")
	fmt.Fprintf(w, "qau_votes_received_total%s %d\n", labels, m.VotesReceived.Load())

	fmt.Fprintf(w, "# HELP qau_votes_sent_total Total votes sent\n")
	fmt.Fprintf(w, "# TYPE qau_votes_sent_total counter\n")
	fmt.Fprintf(w, "qau_votes_sent_total%s %d\n", labels, m.VotesSent.Load())

	fmt.Fprintf(w, "# HELP qau_proposals_made_total Total proposals made\n")
	fmt.Fprintf(w, "# TYPE qau_proposals_made_total counter\n")
	fmt.Fprintf(w, "qau_proposals_made_total%s %d\n", labels, m.ProposalsMade.Load())

	fmt.Fprintf(w, "# HELP qau_finality_time_seconds Time to block finality in seconds\n")
	fmt.Fprintf(w, "# TYPE qau_finality_time_seconds gauge\n")
	fmt.Fprintf(w, "qau_finality_time_seconds%s %.6f\n", labels, float64(m.FinalityTime.Load())/1e9)

	fmt.Fprintf(w, "# HELP qau_slashing_events_total Total slashing events\n")
	fmt.Fprintf(w, "# TYPE qau_slashing_events_total counter\n")
	fmt.Fprintf(w, "qau_slashing_events_total%s %d\n", labels, m.SlashingEvents.Load())

	fmt.Fprintf(w, "# HELP qau_missed_blocks_total Total missed blocks\n")
	fmt.Fprintf(w, "# TYPE qau_missed_blocks_total counter\n")
	fmt.Fprintf(w, "qau_missed_blocks_total%s %d\n", labels, m.MissedBlocks.Load())

	// Network metrics
	fmt.Fprintf(w, "# HELP qau_peers_connected Current number of connected peers\n")
	fmt.Fprintf(w, "# TYPE qau_peers_connected gauge\n")
	fmt.Fprintf(w, "qau_peers_connected%s %d\n", labels, m.PeersConnected.Load())

	fmt.Fprintf(w, "# HELP qau_bytes_sent_total Total bytes sent\n")
	fmt.Fprintf(w, "# TYPE qau_bytes_sent_total counter\n")
	fmt.Fprintf(w, "qau_bytes_sent_total%s %d\n", labels, m.BytesSent.Load())

	fmt.Fprintf(w, "# HELP qau_bytes_received_total Total bytes received\n")
	fmt.Fprintf(w, "# TYPE qau_bytes_received_total counter\n")
	fmt.Fprintf(w, "qau_bytes_received_total%s %d\n", labels, m.BytesReceived.Load())

	fmt.Fprintf(w, "# HELP qau_messages_in_total Total messages received\n")
	fmt.Fprintf(w, "# TYPE qau_messages_in_total counter\n")
	fmt.Fprintf(w, "qau_messages_in_total%s %d\n", labels, m.MessagesIn.Load())

	fmt.Fprintf(w, "# HELP qau_messages_out_total Total messages sent\n")
	fmt.Fprintf(w, "# TYPE qau_messages_out_total counter\n")
	fmt.Fprintf(w, "qau_messages_out_total%s %d\n", labels, m.MessagesOut.Load())

	// RPC metrics
	fmt.Fprintf(w, "# HELP qau_rpc_requests_total Total RPC requests\n")
	fmt.Fprintf(w, "# TYPE qau_rpc_requests_total counter\n")
	fmt.Fprintf(w, "qau_rpc_requests_total%s %d\n", labels, m.RPCRequests.Load())

	fmt.Fprintf(w, "# HELP qau_rpc_errors_total Total RPC errors\n")
	fmt.Fprintf(w, "# TYPE qau_rpc_errors_total counter\n")
	fmt.Fprintf(w, "qau_rpc_errors_total%s %d\n", labels, m.RPCErrors.Load())

	// R14-LOW (P2P-LOW-04/05/06): P2P/RPC observability metrics.
	fmt.Fprintf(w, "# HELP qau_ws_dropped_events_total Total WebSocket events dropped because a subscriber's channel was full\n")
	fmt.Fprintf(w, "# TYPE qau_ws_dropped_events_total counter\n")
	fmt.Fprintf(w, "qau_ws_dropped_events_total%s %d\n", labels, m.WSDroppedEvents.Load())

	fmt.Fprintf(w, "# HELP qau_ws_active_connections Current number of active WebSocket connections\n")
	fmt.Fprintf(w, "# TYPE qau_ws_active_connections gauge\n")
	fmt.Fprintf(w, "qau_ws_active_connections%s %d\n", labels, m.WSActiveConnections.Load())

	fmt.Fprintf(w, "# HELP qau_ws_active_subscriptions Current number of active WebSocket subscriptions\n")
	fmt.Fprintf(w, "# TYPE qau_ws_active_subscriptions gauge\n")
	fmt.Fprintf(w, "qau_ws_active_subscriptions%s %d\n", labels, m.WSActiveSubscriptions.Load())

	fmt.Fprintf(w, "# HELP qau_p2p_handshake_failures_total Total P2P handshake failures (rate-limit, PoW, signature, other)\n")
	fmt.Fprintf(w, "# TYPE qau_p2p_handshake_failures_total counter\n")
	fmt.Fprintf(w, "qau_p2p_handshake_failures_total%s %d\n", labels, m.HandshakeFailures.Load())

	avgLatency := m.GetAverageRPCLatency()
	fmt.Fprintf(w, "# HELP qau_rpc_latency_seconds Average RPC latency in seconds\n")
	fmt.Fprintf(w, "# TYPE qau_rpc_latency_seconds gauge\n")
	fmt.Fprintf(w, "qau_rpc_latency_seconds%s %.6f\n", labels, avgLatency.Seconds())

	// RPC latency histogram
	m.writeHistogram(w, "qau_rpc_latency_histogram_seconds", "RPC latency distribution", m.RPCLatencyHist, labels)

	// State metrics
	fmt.Fprintf(w, "# HELP qau_state_size_bytes State database size in bytes\n")
	fmt.Fprintf(w, "# TYPE qau_state_size_bytes gauge\n")
	fmt.Fprintf(w, "qau_state_size_bytes%s %d\n", labels, m.StateSize.Load())

	fmt.Fprintf(w, "# HELP qau_account_count Total number of accounts\n")
	fmt.Fprintf(w, "# TYPE qau_account_count gauge\n")
	fmt.Fprintf(w, "qau_account_count%s %d\n", labels, m.AccountCount.Load())

	fmt.Fprintf(w, "# HELP qau_contract_count Total number of contracts\n")
	fmt.Fprintf(w, "# TYPE qau_contract_count gauge\n")
	fmt.Fprintf(w, "qau_contract_count%s %d\n", labels, m.ContractCount.Load())

	// Performance metrics
	fmt.Fprintf(w, "# HELP qau_tps Current transactions per second\n")
	fmt.Fprintf(w, "# TYPE qau_tps gauge\n")
	fmt.Fprintf(w, "qau_tps%s %.2f\n", labels, m.GetTPS())

	fmt.Fprintf(w, "# HELP qau_tps_average Average transactions per second\n")
	fmt.Fprintf(w, "# TYPE qau_tps_average gauge\n")
	fmt.Fprintf(w, "qau_tps_average%s %.2f\n", labels, m.GetAverageTPS())

	fmt.Fprintf(w, "# HELP qau_latency_average_seconds Average transaction latency\n")
	fmt.Fprintf(w, "# TYPE qau_latency_average_seconds gauge\n")
	fmt.Fprintf(w, "qau_latency_average_seconds%s %.6f\n", labels, m.GetAverageLatency().Seconds())

	// System metrics
	fmt.Fprintf(w, "# HELP qau_memory_alloc_bytes Allocated memory in bytes\n")
	fmt.Fprintf(w, "# TYPE qau_memory_alloc_bytes gauge\n")
	fmt.Fprintf(w, "qau_memory_alloc_bytes%s %d\n", labels, m.MemAlloc.Load())

	fmt.Fprintf(w, "# HELP qau_memory_sys_bytes System memory in bytes\n")
	fmt.Fprintf(w, "# TYPE qau_memory_sys_bytes gauge\n")
	fmt.Fprintf(w, "qau_memory_sys_bytes%s %d\n", labels, m.MemSys.Load())

	fmt.Fprintf(w, "# HELP qau_memory_average_mb Average memory usage in MB\n")
	fmt.Fprintf(w, "# TYPE qau_memory_average_mb gauge\n")
	fmt.Fprintf(w, "qau_memory_average_mb%s %.2f\n", labels, m.GetAverageMemory())

	fmt.Fprintf(w, "# HELP qau_heap_objects Current heap objects\n")
	fmt.Fprintf(w, "# TYPE qau_heap_objects gauge\n")
	fmt.Fprintf(w, "qau_heap_objects%s %d\n", labels, m.HeapObjects.Load())

	fmt.Fprintf(w, "# HELP qau_stack_inuse_bytes Stack memory in use\n")
	fmt.Fprintf(w, "# TYPE qau_stack_inuse_bytes gauge\n")
	fmt.Fprintf(w, "qau_stack_inuse_bytes%s %d\n", labels, m.StackInUse.Load())

	fmt.Fprintf(w, "# HELP qau_goroutines Current number of goroutines\n")
	fmt.Fprintf(w, "# TYPE qau_goroutines gauge\n")
	fmt.Fprintf(w, "qau_goroutines%s %d\n", labels, m.NumGoroutines.Load())

	fmt.Fprintf(w, "# HELP qau_gc_runs_total Total number of GC runs\n")
	fmt.Fprintf(w, "# TYPE qau_gc_runs_total counter\n")
	fmt.Fprintf(w, "qau_gc_runs_total%s %d\n", labels, m.NumGC.Load())

	fmt.Fprintf(w, "# HELP qau_cpu_usage_percent CPU usage percentage\n")
	fmt.Fprintf(w, "# TYPE qau_cpu_usage_percent gauge\n")
	fmt.Fprintf(w, "qau_cpu_usage_percent%s %.2f\n", labels, m.GetCPUUsage())

	// Disk metrics
	fmt.Fprintf(w, "# HELP qau_disk_usage_bytes Disk usage in bytes\n")
	fmt.Fprintf(w, "# TYPE qau_disk_usage_bytes gauge\n")
	fmt.Fprintf(w, "qau_disk_usage_bytes%s %d\n", labels, m.DiskUsage.Load())

	fmt.Fprintf(w, "# HELP qau_disk_read_bytes_total Total disk read bytes\n")
	fmt.Fprintf(w, "# TYPE qau_disk_read_bytes_total counter\n")
	fmt.Fprintf(w, "qau_disk_read_bytes_total%s %d\n", labels, m.DiskReadBytes.Load())

	fmt.Fprintf(w, "# HELP qau_disk_write_bytes_total Total disk write bytes\n")
	fmt.Fprintf(w, "# TYPE qau_disk_write_bytes_total counter\n")
	fmt.Fprintf(w, "qau_disk_write_bytes_total%s %d\n", labels, m.DiskWriteBytes.Load())

	// QVM metrics
	fmt.Fprintf(w, "# HELP qau_qvm_executions_total Total QVM executions\n")
	fmt.Fprintf(w, "# TYPE qau_qvm_executions_total counter\n")
	fmt.Fprintf(w, "qau_qvm_executions_total%s %d\n", labels, m.QVMExecutions.Load())

	fmt.Fprintf(w, "# HELP qau_qvm_gas_used_total Total QVM gas used\n")
	fmt.Fprintf(w, "# TYPE qau_qvm_gas_used_total counter\n")
	fmt.Fprintf(w, "qau_qvm_gas_used_total%s %d\n", labels, m.QVMGasUsed.Load())

	fmt.Fprintf(w, "# HELP qau_qvm_errors_total Total QVM errors\n")
	fmt.Fprintf(w, "# TYPE qau_qvm_errors_total counter\n")
	fmt.Fprintf(w, "qau_qvm_errors_total%s %d\n", labels, m.QVMErrors.Load())

	// Block-STM parallel execution metrics
	fmt.Fprintf(w, "# HELP qau_stm_executions_total Total Block-STM parallel executions\n")
	fmt.Fprintf(w, "# TYPE qau_stm_executions_total counter\n")
	fmt.Fprintf(w, "qau_stm_executions_total%s %d\n", labels, m.STMExecutions.Load())

	fmt.Fprintf(w, "# HELP qau_stm_conflicts_total Total Block-STM conflicts detected\n")
	fmt.Fprintf(w, "# TYPE qau_stm_conflicts_total counter\n")
	fmt.Fprintf(w, "qau_stm_conflicts_total%s %d\n", labels, m.STMConflicts.Load())

	fmt.Fprintf(w, "# HELP qau_stm_retries_total Total Block-STM retries\n")
	fmt.Fprintf(w, "# TYPE qau_stm_retries_total counter\n")
	fmt.Fprintf(w, "qau_stm_retries_total%s %d\n", labels, m.STMRetries.Load())

	fmt.Fprintf(w, "# HELP qau_stm_sequential_fallback_total Total Block-STM sequential fallbacks\n")
	fmt.Fprintf(w, "# TYPE qau_stm_sequential_fallback_total counter\n")
	fmt.Fprintf(w, "qau_stm_sequential_fallback_total%s %d\n", labels, m.STMSequentialFallback.Load())

	fmt.Fprintf(w, "# HELP qau_stm_speedup_ratio Current Block-STM speedup ratio\n")
	fmt.Fprintf(w, "# TYPE qau_stm_speedup_ratio gauge\n")
	fmt.Fprintf(w, "qau_stm_speedup_ratio%s %.2f\n", labels, float64(m.STMSpeedup.Load())/100.0)

	fmt.Fprintf(w, "# HELP qau_stm_batch_size Last Block-STM batch size\n")
	fmt.Fprintf(w, "# TYPE qau_stm_batch_size gauge\n")
	fmt.Fprintf(w, "qau_stm_batch_size%s %d\n", labels, m.STMBatchSize.Load())

	fmt.Fprintf(w, "# HELP qau_stm_conflict_rate Block-STM conflict rate\n")
	fmt.Fprintf(w, "# TYPE qau_stm_conflict_rate gauge\n")
	fmt.Fprintf(w, "qau_stm_conflict_rate%s %.4f\n", labels, m.GetSTMConflictRate())

	// Cache metrics
	fmt.Fprintf(w, "# HELP qau_cache_hits_total Total cache hits\n")
	fmt.Fprintf(w, "# TYPE qau_cache_hits_total counter\n")
	fmt.Fprintf(w, "qau_cache_hits_total%s %d\n", labels, m.CacheHits.Load())

	fmt.Fprintf(w, "# HELP qau_cache_misses_total Total cache misses\n")
	fmt.Fprintf(w, "# TYPE qau_cache_misses_total counter\n")
	fmt.Fprintf(w, "qau_cache_misses_total%s %d\n", labels, m.CacheMisses.Load())

	fmt.Fprintf(w, "# HELP qau_cache_evictions_total Total cache evictions\n")
	fmt.Fprintf(w, "# TYPE qau_cache_evictions_total counter\n")
	fmt.Fprintf(w, "qau_cache_evictions_total%s %d\n", labels, m.CacheEvictions.Load())

	fmt.Fprintf(w, "# HELP qau_cache_hit_rate Cache hit rate percentage\n")
	fmt.Fprintf(w, "# TYPE qau_cache_hit_rate gauge\n")
	fmt.Fprintf(w, "qau_cache_hit_rate%s %.2f\n", labels, m.GetCacheHitRate())

	fmt.Fprintf(w, "# HELP qau_uptime_seconds Node uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE qau_uptime_seconds gauge\n")
	fmt.Fprintf(w, "qau_uptime_seconds%s %.2f\n", labels, m.Uptime().Seconds())

	// Alert metrics
	if m.alertManager != nil {
		alerts := m.alertManager.GetAlerts(100)
		fmt.Fprintf(w, "# HELP qau_alerts_total Total alerts triggered\n")
		fmt.Fprintf(w, "# TYPE qau_alerts_total gauge\n")
		fmt.Fprintf(w, "qau_alerts_total%s %d\n", labels, len(alerts))
	}
}

// writeHistogram writes a histogram in Prometheus format
func (m *Metrics) writeHistogram(w http.ResponseWriter, name, help string, h *Histogram, labels string) {
	if h == nil {
		return
	}

	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)

	buckets := h.Buckets()
	for _, b := range buckets {
		if b.Le >= 1e18 {
			fmt.Fprintf(w, "%s_bucket%s{le=\"+Inf\"} %d\n", name, labels, b.Count)
		} else {
			fmt.Fprintf(w, "%s_bucket%s{le=\"%.3f\"} %d\n", name, labels, b.Le, b.Count)
		}
	}
	fmt.Fprintf(w, "%s_sum%s %.6f\n", name, labels, h.Sum())
	fmt.Fprintf(w, "%s_count%s %d\n", name, labels, h.Count())
}

// formatLabels formats labels for Prometheus output
// CRITICAL FIX: Escape special characters in label values to prevent Prometheus injection attacks.
// Without escaping, attackers could inject fake metrics through malicious label values.
func (m *Metrics) formatLabels() string {
	if len(m.labels) == 0 {
		return ""
	}

	result := "{"
	first := true
	for k, v := range m.labels {
		if !first {
			result += ","
		}
		// Escape special characters in label value to prevent injection
		escapedValue := escapeLabelValue(v)
		result += fmt.Sprintf(`%s="%s"`, k, escapedValue)
		first = false
	}
	result += "}"
	return result
}

// escapeLabelValue escapes special characters in Prometheus label values.
// Special characters: " (double quote), \ (backslash), \n (newline)
func escapeLabelValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

// Snapshot returns a snapshot of all metrics
func (m *Metrics) Snapshot() map[string]any {
	m.UpdateSystemMetrics()
	return map[string]any{
		// Transaction metrics
		"tx_processed":    m.TxProcessed.Load(),
		"tx_failed":       m.TxFailed.Load(),
		"tx_pool_size":    m.TxPoolSize.Load(),
		"tx_pool_pending": m.TxPoolPending.Load(),
		// Block metrics
		"blocks_processed": m.BlocksProcessed.Load(),
		"block_height":     m.BlockHeight.Load(),
		"block_time_ns":    m.BlockTime.Load(),
		// Consensus metrics
		"votes_received":   m.VotesReceived.Load(),
		"votes_sent":       m.VotesSent.Load(),
		"proposals_made":   m.ProposalsMade.Load(),
		"finality_time_ns": m.FinalityTime.Load(),
		"slashing_events":  m.SlashingEvents.Load(),
		"missed_blocks":    m.MissedBlocks.Load(),
		// Network metrics
		"peers_connected": m.PeersConnected.Load(),
		"bytes_sent":      m.BytesSent.Load(),
		"bytes_received":  m.BytesReceived.Load(),
		"messages_in":     m.MessagesIn.Load(),
		"messages_out":    m.MessagesOut.Load(),
		// RPC metrics
		"rpc_requests":    m.RPCRequests.Load(),
		"rpc_errors":      m.RPCErrors.Load(),
		"rpc_latency_avg": m.GetAverageRPCLatency().Nanoseconds(),
		// R14-LOW (P2P-LOW-04/05/06): P2P/RPC observability metrics.
		"ws_dropped_events":       m.WSDroppedEvents.Load(),
		"ws_active_connections":   m.WSActiveConnections.Load(),
		"ws_active_subscriptions": m.WSActiveSubscriptions.Load(),
		"p2p_handshake_failures":  m.HandshakeFailures.Load(),
		// State metrics
		"state_size":     m.StateSize.Load(),
		"account_count":  m.AccountCount.Load(),
		"contract_count": m.ContractCount.Load(),
		// Performance metrics
		"tps":            m.GetTPS(),
		"tps_average":    m.GetAverageTPS(),
		"latency_avg_ms": m.GetAverageLatency().Milliseconds(),
		// System metrics
		"mem_alloc":      m.MemAlloc.Load(),
		"mem_sys":        m.MemSys.Load(),
		"mem_average_mb": m.GetAverageMemory(),
		"heap_objects":   m.HeapObjects.Load(),
		"stack_inuse":    m.StackInUse.Load(),
		"goroutines":     m.NumGoroutines.Load(),
		"gc_runs":        m.NumGC.Load(),
		"cpu_usage":      m.GetCPUUsage(),
		// Disk metrics
		"disk_usage":       m.DiskUsage.Load(),
		"disk_read_bytes":  m.DiskReadBytes.Load(),
		"disk_write_bytes": m.DiskWriteBytes.Load(),
		// QVM metrics
		"qvm_executions": m.QVMExecutions.Load(),
		"qvm_gas_used":   m.QVMGasUsed.Load(),
		"qvm_errors":     m.QVMErrors.Load(),
		// Cache metrics
		"cache_hits":      m.CacheHits.Load(),
		"cache_misses":    m.CacheMisses.Load(),
		"cache_evictions": m.CacheEvictions.Load(),
		"cache_hit_rate":  m.GetCacheHitRate(),
		// Uptime
		"uptime_seconds": m.Uptime().Seconds(),
	}
}

// Global metrics instance
var globalMetrics *Metrics
var globalMetricsOnce sync.Once

// Global returns the global metrics instance
func Global() *Metrics {
	globalMetricsOnce.Do(func() {
		globalMetrics = New()
	})
	return globalMetrics
}
