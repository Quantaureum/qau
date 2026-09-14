// Quantaureum Node source, version 1.0.0.
// Package audit provides extended security event logging capabilities.
// This file extends the base audit functionality with security-specific events.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/types"
)

// SecurityEventType represents security-specific event types
// These extend the base EventType with more granular security events
type SecurityEventType string

const (
	// Authentication security events
	SecEventAuthSuccess     SecurityEventType = "SEC_AUTH_SUCCESS"
	SecEventAuthFailure     SecurityEventType = "SEC_AUTH_FAILURE"
	SecEventAccountLocked   SecurityEventType = "SEC_ACCOUNT_LOCKED"
	SecEventAccountUnlocked SecurityEventType = "SEC_ACCOUNT_UNLOCKED"

	// Transaction security events
	SecEventTxInvalidSig     SecurityEventType = "SEC_TX_INVALID_SIGNATURE"
	SecEventTxDoubleSpend    SecurityEventType = "SEC_TX_DOUBLE_SPEND_ATTEMPT"
	SecEventTxFrontRunDetect SecurityEventType = "SEC_TX_FRONTRUN_DETECTED"
	SecEventTxReplayAttack   SecurityEventType = "SEC_TX_REPLAY_ATTACK"

	// Consensus security events
	SecEventDoubleSign        SecurityEventType = "SEC_CONSENSUS_DOUBLE_SIGN"
	SecEventSlashing          SecurityEventType = "SEC_CONSENSUS_SLASHING"
	SecEventValidatorJailed   SecurityEventType = "SEC_CONSENSUS_VALIDATOR_JAILED"
	SecEventValidatorUnjailed SecurityEventType = "SEC_CONSENSUS_VALIDATOR_UNJAILED"
	SecEventForkDetected      SecurityEventType = "SEC_CONSENSUS_FORK_DETECTED"
	SecEventLongRangeAttack   SecurityEventType = "SEC_CONSENSUS_LONG_RANGE_ATTACK"

	// Network security events
	SecEventSybilDetected SecurityEventType = "SEC_NETWORK_SYBIL_DETECTED"
	SecEventDDoSDetected  SecurityEventType = "SEC_NETWORK_DDOS_DETECTED"
	SecEventEclipseAttack SecurityEventType = "SEC_NETWORK_ECLIPSE_ATTACK"
	SecEventPeerBanned    SecurityEventType = "SEC_NETWORK_PEER_BANNED"

	// Cryptographic security events
	SecEventSignatureVerified SecurityEventType = "SEC_CRYPTO_SIG_VERIFIED"
	SecEventSignatureFailed   SecurityEventType = "SEC_CRYPTO_SIG_FAILED"
	SecEventKeyCompromised    SecurityEventType = "SEC_CRYPTO_KEY_COMPROMISED"
	SecEventWeakKey           SecurityEventType = "SEC_CRYPTO_WEAK_KEY"

	// State security events
	SecEventStateCorruption   SecurityEventType = "SEC_STATE_CORRUPTION_DETECTED"
	SecEventStateRollback     SecurityEventType = "SEC_STATE_ROLLBACK"
	SecEventMerkleProofFailed SecurityEventType = "SEC_STATE_MERKLE_PROOF_FAILED"

	// Access control security events
	SecEventUnauthorizedAccess  SecurityEventType = "SEC_ACCESS_UNAUTHORIZED"
	SecEventPrivilegeEscalation SecurityEventType = "SEC_ACCESS_PRIVILEGE_ESCALATION"
	SecEventBruteForceDetected  SecurityEventType = "SEC_ACCESS_BRUTE_FORCE"
)

// SecurityEvent represents a security-specific event with extended fields
type SecurityEvent struct {
	// Unique event ID
	ID string `json:"id"`
	// Event type
	Type SecurityEventType `json:"type"`
	// Severity level (uses base Severity type)
	Severity Severity `json:"severity"`
	// Timestamp in RFC3339Nano format
	Timestamp string `json:"timestamp"`
	// Unix timestamp for sorting
	UnixTimestamp int64 `json:"unix_timestamp"`
	// Source module
	Module string `json:"module"`
	// Event message
	Message string `json:"message"`
	// Related address (if applicable)
	Address *types.Address `json:"address,omitempty"`
	// Related transaction hash (if applicable)
	TxHash *types.Hash `json:"tx_hash,omitempty"`
	// Related block height (if applicable)
	BlockHeight *uint64 `json:"block_height,omitempty"`
	// Peer ID (if applicable)
	PeerID string `json:"peer_id,omitempty"`
	// IP address (if applicable)
	IPAddress string `json:"ip_address,omitempty"`
	// Additional context
	Context map[string]any `json:"context,omitempty"`
	// Threat level (0-10)
	ThreatLevel int `json:"threat_level,omitempty"`
	// Recommended action
	RecommendedAction string `json:"recommended_action,omitempty"`
}

// SecurityLoggerConfig holds configuration for the security logger
type SecurityLoggerConfig struct {
	// Output file path
	FilePath string
	// Maximum file size in bytes before rotation
	MaxFileSize int64
	// Maximum number of backup files
	MaxBackups int
	// Minimum severity to log
	MinSeverity Severity
	// Enable console output
	ConsoleOutput bool
	// Buffer size for async logging
	BufferSize int
	// Alert callback for critical events
	AlertCallback func(*SecurityEvent)
}

// DefaultSecurityLoggerConfig returns default configuration
func DefaultSecurityLoggerConfig() *SecurityLoggerConfig {
	return &SecurityLoggerConfig{
		FilePath:      "logs/security.log",
		MaxFileSize:   100 * 1024 * 1024, // 100MB
		MaxBackups:    10,
		MinSeverity:   SeverityInfo,
		ConsoleOutput: false,
		BufferSize:    1000,
	}
}

// SecurityLogger provides security event logging
type SecurityLogger struct {
	mu sync.Mutex

	config *SecurityLoggerConfig
	file   *os.File
	writer io.Writer

	// Event buffer for async logging
	eventCh chan *SecurityEvent
	done    chan struct{}

	// Event counter for ID generation
	eventCounter uint64

	// Statistics
	stats *SecurityLoggerStats
}

// SecurityLoggerStats holds logging statistics
type SecurityLoggerStats struct {
	mu sync.RWMutex

	TotalEvents      uint64
	EventsByType     map[SecurityEventType]uint64
	EventsBySeverity map[Severity]uint64
	LastEventTime    time.Time
	CriticalCount    uint64
}

// NewSecurityLogger creates a new security logger
func NewSecurityLogger(config *SecurityLoggerConfig) (*SecurityLogger, error) {
	if config == nil {
		config = DefaultSecurityLoggerConfig()
	}

	// Create log directory
	dir := filepath.Dir(config.FilePath)
	// audit-fix R5-H2: security log directory should not be world-readable
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file
	// audit-fix R5-H2: security log files must not be world-readable
	file, err := os.OpenFile(config.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := &SecurityLogger{
		config:  config,
		file:    file,
		writer:  file,
		eventCh: make(chan *SecurityEvent, config.BufferSize),
		done:    make(chan struct{}),
		stats: &SecurityLoggerStats{
			EventsByType:     make(map[SecurityEventType]uint64),
			EventsBySeverity: make(map[Severity]uint64),
		},
	}

	// Start async writer
	go logger.writeLoop()

	return logger, nil
}

// Log logs a security event
func (l *SecurityLogger) Log(event *SecurityEvent) {
	// Check severity threshold
	if !l.shouldLog(event.Severity) {
		return
	}

	// Set timestamp if not set
	if event.Timestamp == "" {
		now := time.Now().UTC()
		event.Timestamp = now.Format(time.RFC3339Nano)
		event.UnixTimestamp = now.UnixNano()
	}

	// Generate event ID
	l.mu.Lock()
	l.eventCounter++
	event.ID = fmt.Sprintf("SEC-%d-%d", event.UnixTimestamp, l.eventCounter)
	l.mu.Unlock()

	// Update statistics
	l.updateStats(event)

	// Call alert callback for critical events
	if event.Severity == SeverityCritical && l.config.AlertCallback != nil {
		go l.config.AlertCallback(event)
	}

	// Send to async writer
	select {
	case l.eventCh <- event:
	default:
		// Buffer full, write synchronously
		l.writeEvent(event)
	}
}

// LogTxSecurityEvent logs a transaction-related security event
func (l *SecurityLogger) LogTxSecurityEvent(
	eventType SecurityEventType,
	severity Severity,
	txHash types.Hash,
	from types.Address,
	message string,
	context map[string]any,
) {
	event := &SecurityEvent{
		Type:     eventType,
		Severity: severity,
		Module:   "txpool",
		Message:  message,
		TxHash:   &txHash,
		Address:  &from,
		Context:  context,
	}
	l.Log(event)
}

// LogConsensusSecurityEvent logs a consensus-related security event
func (l *SecurityLogger) LogConsensusSecurityEvent(
	eventType SecurityEventType,
	severity Severity,
	validator types.Address,
	blockHeight uint64,
	message string,
	context map[string]any,
) {
	event := &SecurityEvent{
		Type:        eventType,
		Severity:    severity,
		Module:      "consensus",
		Message:     message,
		Address:     &validator,
		BlockHeight: &blockHeight,
		Context:     context,
	}
	l.Log(event)
}

// LogNetworkSecurityEvent logs a network-related security event
func (l *SecurityLogger) LogNetworkSecurityEvent(
	eventType SecurityEventType,
	severity Severity,
	peerID string,
	ipAddress string,
	message string,
	threatLevel int,
	context map[string]any,
) {
	event := &SecurityEvent{
		Type:        eventType,
		Severity:    severity,
		Module:      "p2p",
		Message:     message,
		PeerID:      peerID,
		IPAddress:   ipAddress,
		ThreatLevel: threatLevel,
		Context:     context,
	}
	l.Log(event)
}

// shouldLog checks if an event should be logged based on severity
func (l *SecurityLogger) shouldLog(severity Severity) bool {
	severityOrder := map[Severity]int{
		SeverityInfo:     0,
		SeverityWarning:  1,
		SeverityError:    2,
		SeverityCritical: 3,
	}
	return severityOrder[severity] >= severityOrder[l.config.MinSeverity]
}

// writeLoop is the async write loop
func (l *SecurityLogger) writeLoop() {
	for {
		select {
		case event := <-l.eventCh:
			l.writeEvent(event)
		case <-l.done:
			// Drain remaining events
			for {
				select {
				case event := <-l.eventCh:
					l.writeEvent(event)
				default:
					return
				}
			}
		}
	}
}

// writeEvent writes an event to the log
func (l *SecurityLogger) writeEvent(event *SecurityEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check file size and rotate if needed
	l.checkRotation()

	data, err := json.Marshal(event)
	if err != nil {
		// Fallback to simple format
		fmt.Fprintf(l.writer, "[%s] [%s] [%s] %s: %s\n",
			event.Timestamp, event.Severity, event.Type, event.Module, event.Message)
		return
	}
	fmt.Fprintln(l.writer, string(data))

	// Console output if enabled
	if l.config.ConsoleOutput {
		slog.Info(string(data))
	}
}

// checkRotation checks if log rotation is needed
func (l *SecurityLogger) checkRotation() {
	if l.file == nil {
		return
	}

	info, err := l.file.Stat()
	if err != nil {
		return
	}

	if info.Size() >= l.config.MaxFileSize {
		l.rotateLog()
	}
}

// rotateLog rotates the log file
func (l *SecurityLogger) rotateLog() {
	l.file.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck

	// Rotate existing backups
	for i := l.config.MaxBackups - 1; i > 0; i-- {
		oldPath := fmt.Sprintf("%s.%d", l.config.FilePath, i)
		newPath := fmt.Sprintf("%s.%d", l.config.FilePath, i+1)
		os.Rename(oldPath, newPath) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	}

	// Rename current to .1
	os.Rename(l.config.FilePath, l.config.FilePath+".1") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck

	// Remove oldest if exceeds max backups
	oldestPath := fmt.Sprintf("%s.%d", l.config.FilePath, l.config.MaxBackups+1)
	os.Remove(oldestPath) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck

	// Create new file
	// audit-fix R5-H2: security log files must not be world-readable
	file, err := os.OpenFile(l.config.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	l.file = file
	l.writer = file
}

// updateStats updates logging statistics
func (l *SecurityLogger) updateStats(event *SecurityEvent) {
	l.stats.mu.Lock()
	defer l.stats.mu.Unlock()

	l.stats.TotalEvents++
	l.stats.EventsByType[event.Type]++
	l.stats.EventsBySeverity[event.Severity]++
	l.stats.LastEventTime = time.Now()

	if event.Severity == SeverityCritical {
		l.stats.CriticalCount++
	}
}

// GetStats returns current statistics
func (l *SecurityLogger) GetStats() *SecurityLoggerStats {
	l.stats.mu.RLock()
	defer l.stats.mu.RUnlock()

	// Return a copy
	stats := &SecurityLoggerStats{
		TotalEvents:      l.stats.TotalEvents,
		EventsByType:     make(map[SecurityEventType]uint64),
		EventsBySeverity: make(map[Severity]uint64),
		LastEventTime:    l.stats.LastEventTime,
		CriticalCount:    l.stats.CriticalCount,
	}
	for k, v := range l.stats.EventsByType {
		stats.EventsByType[k] = v
	}
	for k, v := range l.stats.EventsBySeverity {
		stats.EventsBySeverity[k] = v
	}
	return stats
}

// Close closes the security logger
func (l *SecurityLogger) Close() error {
	close(l.done)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Global security logger instance
// audit-fix R11-L1: use atomic.Pointer to avoid data race between
// GlobalSecurityLogger() and SetGlobalSecurityLogger() (consistent with audit.go SetGlobal).
var (
	globalSecurityLoggerPtr  atomic.Pointer[SecurityLogger]
	globalSecurityLoggerOnce sync.Once
)

// GlobalSecurityLogger returns the global security logger
func GlobalSecurityLogger() *SecurityLogger {
	if sl := globalSecurityLoggerPtr.Load(); sl != nil {
		return sl
	}
	globalSecurityLoggerOnce.Do(func() {
		sl, err := NewSecurityLogger(nil)
		if err != nil {
			slog.Warn("Failed to create security logger", "error", err)
			return
		}
		globalSecurityLoggerPtr.Store(sl)
	})
	return globalSecurityLoggerPtr.Load()
}

// SetGlobalSecurityLogger sets the global security logger (thread-safe)
func SetGlobalSecurityLogger(logger *SecurityLogger) {
	globalSecurityLoggerPtr.Store(logger)
}
