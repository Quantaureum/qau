// Quantaureum Node source, version 1.0.0.
package audit

import (
	"bytes"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}
	if !cfg.Enabled {
		t.Error("expected enabled by default")
	}
	if cfg.MinLevel != SeverityInfo {
		t.Errorf("expected info level, got %s", cfg.MinLevel)
	}
	if cfg.BufferMax != 100 {
		t.Errorf("expected 100 buffer max, got %d", cfg.BufferMax)
	}
}

func TestNewAuditLogger(t *testing.T) {
	al := NewAuditLogger(nil)
	if al == nil {
		t.Fatal("expected non-nil audit logger")
	}
	if !al.IsEnabled() {
		t.Error("expected enabled by default")
	}
}

func TestNewAuditLogger_WithConfig(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{
		Output:    &buf,
		NodeID:    "test-node",
		Enabled:   true,
		MinLevel:  SeverityWarning,
		BufferMax: 50,
	}
	al := NewAuditLogger(cfg)
	if al == nil {
		t.Fatal("expected non-nil audit logger")
	}
	if !al.IsEnabled() {
		t.Error("expected enabled")
	}
}

func TestSetEnabled(t *testing.T) {
	al := NewAuditLogger(nil)
	al.SetEnabled(false)
	if al.IsEnabled() {
		t.Error("expected disabled")
	}
	al.SetEnabled(true)
	if !al.IsEnabled() {
		t.Error("expected enabled")
	}
}

func TestSetMinLevel(t *testing.T) {
	al := NewAuditLogger(nil)
	al.SetMinLevel(SeverityCritical)
}

func TestLog_Disabled(t *testing.T) {
	al := NewAuditLogger(nil)
	al.SetEnabled(false)

	err := al.LogEvent(EventNodeStarted, SeverityInfo, "node_start", "success", nil)
	if err != nil {
		t.Errorf("expected no error when disabled: %v", err)
	}
}

func TestLog_BelowMinLevel(t *testing.T) {
	al := NewAuditLogger(nil)
	al.SetMinLevel(SeverityError)

	err := al.LogEvent(EventNodeStarted, SeverityInfo, "node_start", "success", nil)
	if err != nil {
		t.Errorf("expected no error: %v", err)
	}
}

func TestLogEvent(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogEvent(EventNodeStarted, SeverityInfo, "node_start", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output in buffer")
	}
}

func TestLogKeyOperation(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogKeyOperation(EventKeyGenerated, "key-001", "admin", "success", map[string]any{
		"algorithm": "Dilithium3",
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestLogTransaction(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogTransaction(EventTxSubmitted, "0xabc123", "QAU...sender", "QAU...receiver", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestLogBlock(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogBlock(EventBlockFinalized, "0xblock123", 1000, "QAU...proposer", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestLogConsensus(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogConsensus(EventVoteSubmitted, "QAU...validator", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestLogConsensus_SlashingEvent(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogConsensus(EventSlashingEvent, "QAU...validator", "slashed", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output for slashing")
	}
}

func TestLogNetwork(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogNetwork(EventPeerConnected, "peer-001", "192.168.1.1", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestLogNetwork_MalformedMessage(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogNetwork(EventMalformedMessage, "peer-bad", "10.0.0.1", "blocked", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output for malformed message")
	}
}

func TestLogRPC(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogRPC(EventRPCRequest, "eth_blockNumber", "req-001", "127.0.0.1", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestLogRPC_Error(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogRPC(EventRPCError, "eth_sendTransaction", "req-002", "127.0.0.1", "insufficient_funds", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output for error")
	}
}

func TestLogSecurity(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogSecurity(EventAccessDenied, "attacker", "admin_api", "blocked", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestLogSecurity_CriticalAlert(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogSecurity(EventSecurityAlert, "system", "consensus", "attack_detected", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output for critical alert")
	}
}

func TestLogSystem(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	err := al.LogSystem(EventNodeStarted, "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestFlush(t *testing.T) {
	al := NewAuditLogger(nil)
	_ = al.LogEvent(EventNodeStarted, SeverityInfo, "node_start", "success", nil)

	err := al.Flush()
	if err != nil {
		t.Errorf("unexpected flush error: %v", err)
	}
}

func TestClose(t *testing.T) {
	al := NewAuditLogger(nil)
	_ = al.LogEvent(EventNodeStarted, SeverityInfo, "node_start", "success", nil)

	err := al.Close()
	if err != nil {
		t.Errorf("unexpected close error: %v", err)
	}
}

func TestGlobal(t *testing.T) {
	g := Global()
	if g == nil {
		t.Fatal("expected non-nil global logger")
	}
	if !g.IsEnabled() {
		t.Error("expected global logger enabled by default")
	}
}

func TestSetGlobal(t *testing.T) {
	original := Global()
	al := NewAuditLogger(nil)
	al.SetEnabled(false)

	SetGlobal(al)
	defer SetGlobal(original)

	g := Global()
	if g.IsEnabled() {
		t.Error("expected disabled after SetGlobal")
	}
}

func TestPackageLevelFunctions(t *testing.T) {
	original := Global()

	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "pkg-test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)
	SetGlobal(al)
	defer SetGlobal(original)

	err := LogKeyOperation(EventKeyImported, "key-002", "user", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = LogTransaction(EventTxExecuted, "0xtx1", "QAU...from", "QAU...to", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = LogBlock(EventBlockProposed, "0xblock2", 2000, "QAU...proposer", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = LogConsensus(EventValidatorJoined, "QAU...validator", "joined", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = LogNetwork(EventPeerDisconnected, "peer-003", "10.0.0.3", "disconnected", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = LogRPC(EventRPCResponse, "eth_gasPrice", "req-003", "127.0.0.1", "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = LogSecurity(EventRateLimited, "client-ip", "rpc", "rate_limited", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = LogSystem(EventNodeStopped, "success", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = Log(&AuditEvent{
		EventType: EventConfigChanged,
		Severity:  SeverityInfo,
		Action:    "config_update",
		Result:    "success",
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("expected output from package-level functions")
	}
}

func TestFullEventLogging(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{Output: &buf, NodeID: "full-test", Enabled: true, MinLevel: SeverityInfo}
	al := NewAuditLogger(cfg)

	event := &AuditEvent{
		EventType: EventKeyRotated,
		Severity:  SeverityInfo,
		Actor:     "admin",
		Target:    "key-003",
		Action:    "key_rotation",
		Result:    "success",
		IPAddress: "192.168.1.100",
		RequestID: "req-full-001",
		Details:   map[string]any{"reason": "scheduled"},
	}

	err := al.Log(event)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}
