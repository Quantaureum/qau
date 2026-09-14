// Quantaureum Node source, version 1.0.0.
// Package audit provides audit logging for Quantaureum.
// It records all critical operations for compliance and security auditing.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// EventType represents the type of audit event
type EventType string

const (
	// Authentication events
	EventKeyGenerated EventType = "KEY_GENERATED"
	EventKeyImported  EventType = "KEY_IMPORTED"
	EventKeyExported  EventType = "KEY_EXPORTED"
	EventKeyDeleted   EventType = "KEY_DELETED"
	EventKeyRotated   EventType = "KEY_ROTATED"
	EventKeyAccessed  EventType = "KEY_ACCESSED"

	// Transaction events
	EventTxSubmitted EventType = "TX_SUBMITTED"
	EventTxValidated EventType = "TX_VALIDATED"
	EventTxRejected  EventType = "TX_REJECTED"
	EventTxExecuted  EventType = "TX_EXECUTED"
	EventTxFailed    EventType = "TX_FAILED"

	// Block events
	EventBlockProposed  EventType = "BLOCK_PROPOSED"
	EventBlockValidated EventType = "BLOCK_VALIDATED"
	EventBlockRejected  EventType = "BLOCK_REJECTED"
	EventBlockFinalized EventType = "BLOCK_FINALIZED"

	// Consensus events
	EventVoteSubmitted   EventType = "VOTE_SUBMITTED"
	EventValidatorJoined EventType = "VALIDATOR_JOINED"
	EventValidatorLeft   EventType = "VALIDATOR_LEFT"
	EventSlashingEvent   EventType = "SLASHING_EVENT"

	// Network events
	EventPeerConnected    EventType = "PEER_CONNECTED"
	EventPeerDisconnected EventType = "PEER_DISCONNECTED"
	EventPeerBlacklisted  EventType = "PEER_BLACKLISTED"
	EventMalformedMessage EventType = "MALFORMED_MESSAGE"

	// RPC events
	EventRPCRequest  EventType = "RPC_REQUEST"
	EventRPCResponse EventType = "RPC_RESPONSE"
	EventRPCError    EventType = "RPC_ERROR"

	// System events
	EventNodeStarted    EventType = "NODE_STARTED"
	EventNodeStopped    EventType = "NODE_STOPPED"
	EventConfigChanged  EventType = "CONFIG_CHANGED"
	EventUpgradeApplied EventType = "UPGRADE_APPLIED"

	// Security events
	EventSecurityAlert EventType = "SECURITY_ALERT"
	EventAccessDenied  EventType = "ACCESS_DENIED"
	EventRateLimited   EventType = "RATE_LIMITED"
)

// Severity represents the severity level of an audit event
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityError    Severity = "ERROR"
	SeverityCritical Severity = "CRITICAL"
)

// AuditEvent represents a single audit log entry
type AuditEvent struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	EventType EventType      `json:"event_type"`
	Severity  Severity       `json:"severity"`
	Source    string         `json:"source"`
	Actor     string         `json:"actor,omitempty"`
	Target    string         `json:"target,omitempty"`
	Action    string         `json:"action"`
	Result    string         `json:"result"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	IPAddress string         `json:"ip_address,omitempty"`
	UserAgent string         `json:"user_agent,omitempty"`
}

// AuditLogger provides audit logging functionality
type AuditLogger struct {
	mu       sync.Mutex
	output   io.Writer
	nodeID   string
	enabled  bool
	minLevel Severity

	// Event counter for generating unique IDs
	counter uint64

	// AUDIT-FULL SV-06 FIX (2026-08-15): removed the dead buffer/
	// bufferMax/flushCh fields. Log() writes synchronously via
	// writeEvent, so nothing was ever appended to the buffer; Flush()
	// iterated an always-empty slice. Config.BufferMax is kept as a
	// compatibility no-op for existing configurations.
}

// Config holds audit logger configuration
type Config struct {
	Output    io.Writer
	NodeID    string
	Enabled   bool
	MinLevel  Severity
	BufferMax int
}

// DefaultConfig returns default audit logger configuration
func DefaultConfig() *Config {
	return &Config{
		Output:    os.Stdout,
		NodeID:    "unknown",
		Enabled:   true,
		MinLevel:  SeverityInfo,
		BufferMax: 100,
	}
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(cfg *Config) *AuditLogger {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}
	if cfg.BufferMax <= 0 {
		cfg.BufferMax = 100
	}

	al := &AuditLogger{
		output:   cfg.Output,
		nodeID:   cfg.NodeID,
		enabled:  cfg.Enabled,
		minLevel: cfg.MinLevel,
	}

	return al
}

// SetEnabled enables or disables audit logging
var auditEnabledImmutable = os.Getenv("QAU_AUDIT_IMMUTABLE") == "true"

func (al *AuditLogger) SetEnabled(enabled bool) {
	if auditEnabledImmutable {
		return
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	al.enabled = enabled
}

// IsEnabled returns whether audit logging is enabled
func (al *AuditLogger) IsEnabled() bool {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.enabled
}

// SetMinLevel sets the minimum severity level for logging
func (al *AuditLogger) SetMinLevel(level Severity) {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.minLevel = level
}

// Log logs an audit event
func (al *AuditLogger) Log(event *AuditEvent) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if !al.enabled {
		return nil
	}

	if !al.shouldLog(event.Severity) {
		return nil
	}

	// Set defaults
	if event.ID == "" {
		al.counter++
		event.ID = fmt.Sprintf("%s-%d-%d", al.nodeID, time.Now().UnixNano(), al.counter)
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Source == "" {
		event.Source = al.nodeID
	}

	return al.writeEvent(event)
}

// LogEvent is a convenience method to log an event with common fields
func (al *AuditLogger) LogEvent(eventType EventType, severity Severity, action, result string, details map[string]any) error {
	return al.Log(&AuditEvent{
		EventType: eventType,
		Severity:  severity,
		Action:    action,
		Result:    result,
		Details:   details,
	})
}

// LogKeyOperation logs a key-related operation
func (al *AuditLogger) LogKeyOperation(eventType EventType, keyID, actor, result string, details map[string]any) error {
	return al.Log(&AuditEvent{
		EventType: eventType,
		Severity:  SeverityInfo,
		Actor:     actor,
		Target:    keyID,
		Action:    string(eventType),
		Result:    result,
		Details:   details,
	})
}

// LogTransaction logs a transaction-related event
func (al *AuditLogger) LogTransaction(eventType EventType, txHash, from, to, result string, details map[string]any) error {
	if details == nil {
		details = make(map[string]any)
	}
	details["tx_hash"] = txHash
	details["from"] = from
	details["to"] = to

	return al.Log(&AuditEvent{
		EventType: eventType,
		Severity:  SeverityInfo,
		Actor:     from,
		Target:    txHash,
		Action:    string(eventType),
		Result:    result,
		Details:   details,
	})
}

// LogBlock logs a block-related event
func (al *AuditLogger) LogBlock(eventType EventType, blockHash string, height uint64, proposer, result string, details map[string]any) error {
	if details == nil {
		details = make(map[string]any)
	}
	details["block_hash"] = blockHash
	details["height"] = height
	details["proposer"] = proposer

	return al.Log(&AuditEvent{
		EventType: eventType,
		Severity:  SeverityInfo,
		Actor:     proposer,
		Target:    blockHash,
		Action:    string(eventType),
		Result:    result,
		Details:   details,
	})
}

// LogConsensus logs a consensus-related event
func (al *AuditLogger) LogConsensus(eventType EventType, validator, result string, details map[string]any) error {
	severity := SeverityInfo
	if eventType == EventSlashingEvent {
		severity = SeverityCritical
	}

	return al.Log(&AuditEvent{
		EventType: eventType,
		Severity:  severity,
		Actor:     validator,
		Action:    string(eventType),
		Result:    result,
		Details:   details,
	})
}

// LogNetwork logs a network-related event
func (al *AuditLogger) LogNetwork(eventType EventType, peerID, ipAddress, result string, details map[string]any) error {
	severity := SeverityInfo
	if eventType == EventPeerBlacklisted || eventType == EventMalformedMessage {
		severity = SeverityWarning
	}

	return al.Log(&AuditEvent{
		EventType: eventType,
		Severity:  severity,
		Target:    peerID,
		IPAddress: ipAddress,
		Action:    string(eventType),
		Result:    result,
		Details:   details,
	})
}

// LogRPC logs an RPC-related event
func (al *AuditLogger) LogRPC(eventType EventType, method, requestID, ipAddress, result string, details map[string]any) error {
	if details == nil {
		details = make(map[string]any)
	}
	details["method"] = method

	severity := SeverityInfo
	if eventType == EventRPCError {
		severity = SeverityWarning
	}

	return al.Log(&AuditEvent{
		EventType: eventType,
		Severity:  severity,
		RequestID: requestID,
		IPAddress: ipAddress,
		Action:    method,
		Result:    result,
		Details:   details,
	})
}

// LogSecurity logs a security-related event
func (al *AuditLogger) LogSecurity(eventType EventType, actor, target, result string, details map[string]any) error {
	severity := SeverityWarning
	if eventType == EventSecurityAlert {
		severity = SeverityCritical
	}

	return al.Log(&AuditEvent{
		EventType: eventType,
		Severity:  severity,
		Actor:     actor,
		Target:    target,
		Action:    string(eventType),
		Result:    result,
		Details:   details,
	})
}

// LogSystem logs a system-related event
func (al *AuditLogger) LogSystem(eventType EventType, result string, details map[string]any) error {
	return al.Log(&AuditEvent{
		EventType: eventType,
		Severity:  SeverityInfo,
		Action:    string(eventType),
		Result:    result,
		Details:   details,
	})
}

// shouldLog checks if an event should be logged based on severity
func (al *AuditLogger) shouldLog(severity Severity) bool {
	severityOrder := map[Severity]int{
		SeverityInfo:     0,
		SeverityWarning:  1,
		SeverityError:    2,
		SeverityCritical: 3,
	}

	return severityOrder[severity] >= severityOrder[al.minLevel]
}

// writeEvent writes an event to the output
func (al *AuditLogger) writeEvent(event *AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	_, err = al.output.Write(append(data, '\n'))
	return err
}

// Flush flushes any buffered events.
// AUDIT-FULL SV-06 FIX (2026-08-15): events are written synchronously in
// Log() (there is no buffering path anymore — the old buffer fields were
// dead code), so Flush is a no-op kept for API compatibility.
func (al *AuditLogger) Flush() error {
	return nil
}

// Close closes the audit logger
func (al *AuditLogger) Close() error {
	return al.Flush()
}

// Global audit logger instance
var (
	globalAuditLogger     atomic.Pointer[AuditLogger]
	globalAuditLoggerOnce sync.Once
)

// Global returns the global audit logger instance
func Global() *AuditLogger {
	if al := globalAuditLogger.Load(); al != nil {
		return al
	}
	globalAuditLoggerOnce.Do(func() {
		globalAuditLogger.Store(NewAuditLogger(DefaultConfig()))
	})
	return globalAuditLogger.Load()
}

// SetGlobal sets the global audit logger instance (thread-safe)
func SetGlobal(al *AuditLogger) {
	globalAuditLogger.Store(al)
}

// Package-level convenience functions

// Log logs an audit event using the global logger
func Log(event *AuditEvent) error {
	return Global().Log(event)
}

// LogKeyOperation logs a key operation using the global logger
func LogKeyOperation(eventType EventType, keyID, actor, result string, details map[string]any) error {
	return Global().LogKeyOperation(eventType, keyID, actor, result, details)
}

// LogTransaction logs a transaction using the global logger
func LogTransaction(eventType EventType, txHash, from, to, result string, details map[string]any) error {
	return Global().LogTransaction(eventType, txHash, from, to, result, details)
}

// LogBlock logs a block event using the global logger
func LogBlock(eventType EventType, blockHash string, height uint64, proposer, result string, details map[string]any) error {
	return Global().LogBlock(eventType, blockHash, height, proposer, result, details)
}

// LogConsensus logs a consensus event using the global logger
func LogConsensus(eventType EventType, validator, result string, details map[string]any) error {
	return Global().LogConsensus(eventType, validator, result, details)
}

// LogNetwork logs a network event using the global logger
func LogNetwork(eventType EventType, peerID, ipAddress, result string, details map[string]any) error {
	return Global().LogNetwork(eventType, peerID, ipAddress, result, details)
}

// LogRPC logs an RPC event using the global logger
func LogRPC(eventType EventType, method, requestID, ipAddress, result string, details map[string]any) error {
	return Global().LogRPC(eventType, method, requestID, ipAddress, result, details)
}

// LogSecurity logs a security event using the global logger
func LogSecurity(eventType EventType, actor, target, result string, details map[string]any) error {
	return Global().LogSecurity(eventType, actor, target, result, details)
}

// LogSystem logs a system event using the global logger
func LogSystem(eventType EventType, result string, details map[string]any) error {
	return Global().LogSystem(eventType, result, details)
}
