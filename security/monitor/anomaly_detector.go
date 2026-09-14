// Quantaureum Node source, version 1.0.0.
// Package monitor provides real-time security monitoring and anomaly detection.
// This module detects suspicious patterns that may indicate attacks.
package monitor

import (
	"math"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

// AnomalyType represents different types of detected anomalies
type AnomalyType string

const (
	// Transaction anomalies
	AnomalyHighTxVolume    AnomalyType = "HIGH_TX_VOLUME"
	AnomalyLargeTxValue    AnomalyType = "LARGE_TX_VALUE"
	AnomalyRapidNonceInc   AnomalyType = "RAPID_NONCE_INCREMENT"
	AnomalyUnusualGasPrice AnomalyType = "UNUSUAL_GAS_PRICE"
	AnomalyContractBomb    AnomalyType = "CONTRACT_BOMB"

	// Network anomalies
	AnomalyPeerFlood      AnomalyType = "PEER_FLOOD"
	AnomalyMessageSpam    AnomalyType = "MESSAGE_SPAM"
	AnomalyEclipseAttempt AnomalyType = "ECLIPSE_ATTEMPT"
	AnomalySybilPattern   AnomalyType = "SYBIL_PATTERN"

	// Consensus anomalies
	AnomalyForkDetected AnomalyType = "FORK_DETECTED"
	AnomalyReorgAttempt AnomalyType = "REORG_ATTEMPT"
	AnomalyDoubleVote   AnomalyType = "DOUBLE_VOTE"
	AnomalyMissedBlocks AnomalyType = "MISSED_BLOCKS"

	// State anomalies
	AnomalyStateCorruption AnomalyType = "STATE_CORRUPTION"
	AnomalyBalanceAnomaly  AnomalyType = "BALANCE_ANOMALY"
)

// Severity levels for anomalies
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// Anomaly represents a detected security anomaly
type Anomaly struct {
	Type        AnomalyType
	Severity    Severity
	Timestamp   time.Time
	Description string
	Source      string
	Details     map[string]any
	Resolved    bool
}

// AnomalyHandler is called when an anomaly is detected
type AnomalyHandler func(*Anomaly)

// ThresholdConfig holds configurable thresholds for anomaly detection
type ThresholdConfig struct {
	// Transaction thresholds
	MaxTxPerSecond       int
	MaxTxValueWei        string // In wei as string for large numbers
	MaxNonceJump         uint64
	GasPriceStdDevFactor float64

	// Network thresholds
	MaxNewPeersPerMinute int
	MaxMessagesPerSecond int
	MaxSameSubnetPeers   int

	// Consensus thresholds
	MaxReorgDepth   int
	MaxMissedBlocks int

	// Time windows
	TxVolumeWindow  time.Duration
	PeerFloodWindow time.Duration
}

// DefaultThresholdConfig returns default threshold configuration
func DefaultThresholdConfig() *ThresholdConfig {
	return &ThresholdConfig{
		MaxTxPerSecond:       1000,
		MaxTxValueWei:        "1000000000000000000000000", // 1M tokens
		MaxNonceJump:         10,
		GasPriceStdDevFactor: 3.0,
		MaxNewPeersPerMinute: 50,
		MaxMessagesPerSecond: 1000,
		MaxSameSubnetPeers:   5,
		MaxReorgDepth:        6,
		MaxMissedBlocks:      50,
		TxVolumeWindow:       time.Minute,
		PeerFloodWindow:      time.Minute,
	}
}

// AnomalyDetector monitors for security anomalies
type AnomalyDetector struct {
	mu sync.RWMutex

	config   *ThresholdConfig
	handlers []AnomalyHandler

	// Transaction monitoring
	txCounts  map[types.Address]*txCounter
	recentTxs []time.Time
	gasPrices []uint64

	// Network monitoring
	newPeerTimes []time.Time
	msgCounts    map[string]*msgCounter
	subnetCounts map[string]int

	// Consensus monitoring
	lastBlockHeight uint64
	missedBlocks    map[types.Address]int

	// Anomaly history
	anomalies    []*Anomaly
	maxAnomalies int

	// Running state
	running bool
	stopCh  chan struct{}

	// audit-fix R4-L12: semaphore to limit concurrent handler goroutines
	handlerSem chan struct{}
}

type txCounter struct {
	count     int
	lastNonce uint64
	lastTime  time.Time
}

type msgCounter struct {
	count    int
	lastTime time.Time
}

// MaxConcurrentHandlers limits concurrent handler goroutines to prevent resource exhaustion
const MaxConcurrentHandlers = 16

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(config *ThresholdConfig) *AnomalyDetector {
	if config == nil {
		config = DefaultThresholdConfig()
	}

	return &AnomalyDetector{
		config:       config,
		handlers:     make([]AnomalyHandler, 0),
		txCounts:     make(map[types.Address]*txCounter),
		recentTxs:    make([]time.Time, 0),
		gasPrices:    make([]uint64, 0, 1000),
		newPeerTimes: make([]time.Time, 0),
		msgCounts:    make(map[string]*msgCounter),
		subnetCounts: make(map[string]int),
		missedBlocks: make(map[types.Address]int),
		anomalies:    make([]*Anomaly, 0),
		maxAnomalies: 10000,
		stopCh:       make(chan struct{}),
		handlerSem:   make(chan struct{}, MaxConcurrentHandlers), // audit-fix R4-L12
	}
}

// RegisterHandler registers a handler for anomaly notifications
func (ad *AnomalyDetector) RegisterHandler(handler AnomalyHandler) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.handlers = append(ad.handlers, handler)
}

// Start starts the anomaly detector
func (ad *AnomalyDetector) Start() {
	ad.mu.Lock()
	if ad.running {
		ad.mu.Unlock()
		return
	}
	ad.running = true
	ad.mu.Unlock()

	go ad.cleanupLoop()
}

// Stop stops the anomaly detector
func (ad *AnomalyDetector) Stop() {
	ad.mu.Lock()
	if !ad.running {
		ad.mu.Unlock()
		return
	}
	ad.running = false
	ad.mu.Unlock()

	close(ad.stopCh)
}

// RecordTransaction records a transaction for monitoring
func (ad *AnomalyDetector) RecordTransaction(from types.Address, nonce, gasPrice, value uint64) {
	now := time.Now()

	// Phase 1: short lock to update state and capture local data needed for anomaly checks.
	var fireRapidNonce bool
	var prevNonce, newNonce, jump uint64
	ad.mu.Lock()
	ad.recentTxs = append(ad.recentTxs, now)
	counter, exists := ad.txCounts[from]
	if !exists {
		counter = &txCounter{lastTime: now}
		ad.txCounts[from] = counter
	}
	if exists && nonce > counter.lastNonce+ad.config.MaxNonceJump {
		fireRapidNonce = true
		prevNonce = counter.lastNonce
		newNonce = nonce
		jump = nonce - counter.lastNonce
	}
	counter.count++
	counter.lastNonce = nonce
	counter.lastTime = now
	ad.gasPrices = append(ad.gasPrices, gasPrice)
	if len(ad.gasPrices) > 1000 {
		ad.gasPrices = ad.gasPrices[1:]
	}
	ad.mu.Unlock()

	// Phase 2: stateless anomaly checks (each takes its own lock internally).
	if fireRapidNonce {
		ad.reportAnomaly(&Anomaly{
			Type:        AnomalyRapidNonceInc,
			Severity:    SeverityMedium,
			Timestamp:   now,
			Description: "Rapid nonce increment detected",
			Source:      from.String(),
			Details: map[string]any{
				"previous_nonce": prevNonce,
				"new_nonce":      newNonce,
				"jump":           jump,
			},
		})
	}

	ad.checkTxVolume()

	// Phase 3: gas price anomaly check (takes its own lock internally).
	ad.checkGasPriceAnomaly(gasPrice)
}

// RecordNewPeer records a new peer connection
func (ad *AnomalyDetector) RecordNewPeer(peerID, subnet string) {
	now := time.Now()

	// Phase 1: short lock to update state and capture local data needed for anomaly checks.
	var fireSybil bool
	var sybilCount int
	ad.mu.Lock()
	ad.newPeerTimes = append(ad.newPeerTimes, now)
	ad.subnetCounts[subnet]++
	if ad.subnetCounts[subnet] > ad.config.MaxSameSubnetPeers {
		fireSybil = true
		sybilCount = ad.subnetCounts[subnet]
	}
	ad.mu.Unlock()

	// Phase 2: stateless anomaly checks (each takes its own lock internally).
	ad.checkPeerFlood()

	if fireSybil {
		ad.reportAnomaly(&Anomaly{
			Type:        AnomalySybilPattern,
			Severity:    SeverityHigh,
			Timestamp:   now,
			Description: "Too many peers from same subnet",
			Source:      subnet,
			Details: map[string]any{
				"subnet":    subnet,
				"count":     sybilCount,
				"threshold": ad.config.MaxSameSubnetPeers,
			},
		})
	}
}

// RecordMessage records a P2P message
func (ad *AnomalyDetector) RecordMessage(peerID string, msgType uint8) {
	now := time.Now()

	// Phase 1: short lock to update state and capture local data needed for anomaly checks.
	var fireSpam bool
	var msgCount int
	ad.mu.Lock()
	counter, exists := ad.msgCounts[peerID]
	if !exists {
		counter = &msgCounter{lastTime: now}
		ad.msgCounts[peerID] = counter
	}
	// Reset counter if window passed
	if now.Sub(counter.lastTime) > time.Second {
		counter.count = 0
		counter.lastTime = now
	}
	counter.count++
	if counter.count > ad.config.MaxMessagesPerSecond {
		fireSpam = true
		msgCount = counter.count
	}
	ad.mu.Unlock()

	// Phase 2: stateless anomaly report (takes its own lock internally).
	if fireSpam {
		ad.reportAnomaly(&Anomaly{
			Type:        AnomalyMessageSpam,
			Severity:    SeverityMedium,
			Timestamp:   now,
			Description: "Message spam detected from peer",
			Source:      peerID,
			Details: map[string]any{
				"peer_id":   peerID,
				"msg_count": msgCount,
				"threshold": ad.config.MaxMessagesPerSecond,
			},
		})
	}
}

// RecordBlockProduced records a new block
func (ad *AnomalyDetector) RecordBlockProduced(height uint64, producer types.Address) {
	now := time.Now()

	// Phase 1: short lock to update state and capture local data needed for anomaly checks.
	var fireReorg bool
	var depth uint64
	var prevHeight uint64
	ad.mu.Lock()
	if height <= ad.lastBlockHeight {
		depth = ad.lastBlockHeight - height + 1
		if int(depth) > ad.config.MaxReorgDepth { //nolint:gosec,G115
			fireReorg = true
			prevHeight = ad.lastBlockHeight
		}
	}
	ad.lastBlockHeight = height
	ad.missedBlocks[producer] = 0
	ad.mu.Unlock()

	// Phase 2: stateless anomaly report (takes its own lock internally).
	if fireReorg {
		ad.reportAnomaly(&Anomaly{
			Type:        AnomalyReorgAttempt,
			Severity:    SeverityCritical,
			Timestamp:   now,
			Description: "Deep chain reorganization detected",
			Source:      producer.String(),
			Details: map[string]any{
				"reorg_depth":    depth,
				"current_height": prevHeight,
				"new_height":     height,
			},
		})
	}
}

// RecordMissedBlock records a missed block
func (ad *AnomalyDetector) RecordMissedBlock(validator types.Address) {
	now := time.Now()

	// Phase 1: short lock to update state and capture local data needed for anomaly checks.
	var fireMissed bool
	var missedCount int
	ad.mu.Lock()
	ad.missedBlocks[validator]++
	if ad.missedBlocks[validator] > ad.config.MaxMissedBlocks {
		fireMissed = true
		missedCount = ad.missedBlocks[validator]
	}
	ad.mu.Unlock()

	// Phase 2: stateless anomaly report (takes its own lock internally).
	if fireMissed {
		ad.reportAnomaly(&Anomaly{
			Type:        AnomalyMissedBlocks,
			Severity:    SeverityHigh,
			Timestamp:   now,
			Description: "Validator missing too many blocks",
			Source:      validator.String(),
			Details: map[string]any{
				"validator":     validator.String(),
				"missed_blocks": missedCount,
				"threshold":     ad.config.MaxMissedBlocks,
			},
		})
	}
}

// RecordDoubleVote records a double vote detection
func (ad *AnomalyDetector) RecordDoubleVote(validator types.Address, height uint64) {
	now := time.Now()

	// No shared state to update beyond the anomaly log; reportAnomaly takes its own lock.
	ad.reportAnomaly(&Anomaly{
		Type:        AnomalyDoubleVote,
		Severity:    SeverityCritical,
		Timestamp:   now,
		Description: "Double vote detected",
		Source:      validator.String(),
		Details: map[string]any{
			"validator": validator.String(),
			"height":    height,
		},
	})
}

// checkTxVolume checks for high transaction volume
func (ad *AnomalyDetector) checkTxVolume() {
	now := time.Now()

	// Phase 1: short lock to prune old entries and capture the rate threshold decision.
	var fire bool
	var rate float64
	ad.mu.Lock()
	cutoff := now.Add(-ad.config.TxVolumeWindow)
	validTxs := make([]time.Time, 0)
	for _, t := range ad.recentTxs {
		if t.After(cutoff) {
			validTxs = append(validTxs, t)
		}
	}
	ad.recentTxs = validTxs
	windowSeconds := ad.config.TxVolumeWindow.Seconds()
	rate = float64(len(ad.recentTxs)) / windowSeconds
	if rate > float64(ad.config.MaxTxPerSecond) {
		fire = true
	}
	ad.mu.Unlock()

	// Phase 2: stateless anomaly report (takes its own lock internally).
	if fire {
		ad.reportAnomaly(&Anomaly{
			Type:        AnomalyHighTxVolume,
			Severity:    SeverityHigh,
			Timestamp:   now,
			Description: "High transaction volume detected",
			Details: map[string]any{
				"tx_per_second": rate,
				"threshold":     ad.config.MaxTxPerSecond,
			},
		})
	}
}

// checkPeerFlood checks for peer connection flood
func (ad *AnomalyDetector) checkPeerFlood() {
	now := time.Now()

	// Phase 1: short lock to prune old entries and capture the threshold decision.
	var fire bool
	var newPeerCount int
	ad.mu.Lock()
	cutoff := now.Add(-ad.config.PeerFloodWindow)
	validTimes := make([]time.Time, 0)
	for _, t := range ad.newPeerTimes {
		if t.After(cutoff) {
			validTimes = append(validTimes, t)
		}
	}
	ad.newPeerTimes = validTimes
	newPeerCount = len(ad.newPeerTimes)
	if newPeerCount > ad.config.MaxNewPeersPerMinute {
		fire = true
	}
	ad.mu.Unlock()

	// Phase 2: stateless anomaly report (takes its own lock internally).
	if fire {
		ad.reportAnomaly(&Anomaly{
			Type:        AnomalyPeerFlood,
			Severity:    SeverityHigh,
			Timestamp:   now,
			Description: "Peer connection flood detected",
			Details: map[string]any{
				"new_peers": newPeerCount,
				"threshold": ad.config.MaxNewPeersPerMinute,
				"window":    ad.config.PeerFloodWindow.String(),
			},
		})
	}
}

// checkGasPriceAnomaly checks for unusual gas prices
func (ad *AnomalyDetector) checkGasPriceAnomaly(gasPrice uint64) {
	// Phase 1: short lock to read the gas price window and compute the decision.
	var fire bool
	var mean, stdDev float64
	ad.mu.Lock()
	if len(ad.gasPrices) < 100 {
		ad.mu.Unlock()
		return // Need enough data
	}

	var sum, sumSq float64
	for _, p := range ad.gasPrices {
		sum += float64(p)
		sumSq += float64(p) * float64(p)
	}
	n := float64(len(ad.gasPrices))
	mean = sum / n
	variance := (sumSq / n) - (mean * mean)
	stdDev = 0.0
	if variance > 0 {
		// audit-fix R5-M1: use proper sqrt instead of raw variance
		stdDev = math.Sqrt(variance)
	}

	// Check if current price is anomalous
	deviation := float64(gasPrice) - mean
	if deviation < 0 {
		deviation = -deviation
	}
	if stdDev > 0 && deviation > stdDev*ad.config.GasPriceStdDevFactor {
		fire = true
	}
	ad.mu.Unlock()

	// Phase 2: stateless anomaly report (takes its own lock internally).
	if fire {
		ad.reportAnomaly(&Anomaly{
			Type:        AnomalyUnusualGasPrice,
			Severity:    SeverityLow,
			Timestamp:   time.Now(),
			Description: "Unusual gas price detected",
			Details: map[string]any{
				"gas_price": gasPrice,
				"mean":      mean,
				"std_dev":   stdDev,
			},
		})
	}
}

// reportAnomaly reports an anomaly to all handlers
// audit-fix R4-L12: use bounded semaphore to limit concurrent handler goroutines
// audit-fix R-fix: acquire ad.mu here (not by the caller) to make this method self-sufficient
// and safe to call without the caller already holding the lock. Captures a snapshot of handlers
// so handler goroutines are launched after the lock is released.
func (ad *AnomalyDetector) reportAnomaly(anomaly *Anomaly) {
	// Phase 1: short lock to append the anomaly and snapshot the current handlers.
	ad.mu.Lock()
	ad.anomalies = append(ad.anomalies, anomaly)
	if len(ad.anomalies) > ad.maxAnomalies {
		ad.anomalies = ad.anomalies[1:]
	}
	handlers := make([]AnomalyHandler, len(ad.handlers))
	copy(handlers, ad.handlers)
	ad.mu.Unlock()

	// Phase 2: notify handlers (in goroutine with bounded concurrency to avoid resource exhaustion).
	for _, handler := range handlers {
		h := handler // capture for goroutine
		go func() {
			// Acquire semaphore (non-blocking select with default drops if at capacity)
			select {
			case ad.handlerSem <- struct{}{}:
				defer func() { <-ad.handlerSem }()
				h(anomaly)
			default:
				// At capacity, drop this notification to prevent goroutine leak
			}
		}()
	}
}

// GetRecentAnomalies returns recent anomalies
func (ad *AnomalyDetector) GetRecentAnomalies(limit int) []*Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	if limit <= 0 || limit > len(ad.anomalies) {
		limit = len(ad.anomalies)
	}

	result := make([]*Anomaly, limit)
	copy(result, ad.anomalies[len(ad.anomalies)-limit:])
	return result
}

// GetAnomalyCount returns count of anomalies by type
func (ad *AnomalyDetector) GetAnomalyCount() map[AnomalyType]int {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	counts := make(map[AnomalyType]int)
	for _, a := range ad.anomalies {
		counts[a.Type]++
	}
	return counts
}

// cleanupLoop periodically cleans up old data
func (ad *AnomalyDetector) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ad.stopCh:
			return
		case <-ticker.C:
			ad.cleanup()
		}
	}
}

// cleanup removes old monitoring data
func (ad *AnomalyDetector) cleanup() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()

	// Clean up old tx counters
	for addr, counter := range ad.txCounts {
		if now.Sub(counter.lastTime) > time.Hour {
			delete(ad.txCounts, addr)
		}
	}

	// Clean up old message counters
	for peer, counter := range ad.msgCounts {
		if now.Sub(counter.lastTime) > time.Minute {
			delete(ad.msgCounts, peer)
		}
	}
}
