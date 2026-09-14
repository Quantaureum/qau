// Quantaureum Node source, version 1.0.0.
package metrics

// P3-2 bridge alert rule tests (2026-07-15)
//
// Verifies that the 5 bridge alert rules are registered, evaluate correctly
// against a BridgeMetricProvider, and fire when thresholds are exceeded.
// Mirrors the rollup_alerts_test.go pattern.
//
// AUDIT-FULL ROUND4 2026-08-15  The threshold values (300, 100, 0.5,
// 20, 0.5) used in this test file are TEST DATA, not production configuration.
// Production thresholds are now configurable via BridgeAlertThresholds and
// SetBridgeAlertThresholds. These test values match the defaults for
// regression coverage. CONFIRMED-IN-PLACE.

import (
	"testing"
)

// fakeBridgeProvider is a test double for BridgeMetricProvider.
type fakeBridgeProvider struct {
	messageStalled      float64
	failedMessages      float64
	quorumLost          float64
	l1AnchorLag         float64
	relayerDisconnected float64
}

func (f *fakeBridgeProvider) MessageProcessingStalledValue() float64 { return f.messageStalled }
func (f *fakeBridgeProvider) FailedMessagesValue() float64           { return f.failedMessages }
func (f *fakeBridgeProvider) QuorumLostValue() float64               { return f.quorumLost }
func (f *fakeBridgeProvider) L1AnchorLagValue() float64              { return f.l1AnchorLag }
func (f *fakeBridgeProvider) RelayerDisconnectedValue() float64      { return f.relayerDisconnected }

// TestBridgeAlertRules_NoProvider verifies that all bridge alert rules
// return 0 (no alert) when no provider is set. This is the default state —
// the bridge is not enabled on every node.
func TestBridgeAlertRules_NoProvider(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	alerts := am.Check(m)
	for _, a := range alerts {
		if isBridgeAlert(a.Name) {
			t.Errorf("bridge alert %q fired without provider (value=%v)", a.Name, a.Value)
		}
	}
}

// TestBridgeAlertRules_RunningHealthy verifies that no bridge alerts fire
// when the bridge is running and all metrics are within thresholds.
func TestBridgeAlertRules_RunningHealthy(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		messageStalled:      10, // 10s since last message — well under 300s
		failedMessages:      5,  // 5 failed — well under 100
		quorumLost:          0,  // quorum intact
		l1AnchorLag:         3,  // 3 blocks lag — well under 20
		relayerDisconnected: 0,  // relayer connected
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if isBridgeAlert(a.Name) {
			t.Errorf("bridge alert %q fired in healthy state (value=%v, threshold=%v)",
				a.Name, a.Value, a.Threshold)
		}
	}
}

// TestBridgeAlertRules_MessageProcessingStopped verifies the > 300s threshold.
func TestBridgeAlertRules_MessageProcessingStopped(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 300s should NOT fire (threshold is > 300, not >= 300)
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		messageStalled: 300,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "bridge_message_processing_stopped" {
			t.Errorf("should not fire at 300 (threshold > 300): value=%v", a.Value)
		}
	}

	// 301s SHOULD fire
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		messageStalled: 301,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "bridge_message_processing_stopped" {
			found = true
			if a.Level != AlertCritical {
				t.Errorf("message_processing_stopped: got level %v, want Critical", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected bridge_message_processing_stopped alert at 301s")
	}
}

// TestBridgeAlertRules_MessageProcessingColdStart verifies that the alert
// does not fire during cold start (LastMessageProcessedAt=0 → stalled=0).
func TestBridgeAlertRules_MessageProcessingColdStart(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	// Cold start: stalled=0 (no message ever processed)
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		messageStalled: 0,
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "bridge_message_processing_stopped" {
			t.Errorf("should not fire during cold start (stalled=0): value=%v", a.Value)
		}
	}
}

// TestBridgeAlertRules_FailedMessagesHigh verifies the > 100 threshold.
func TestBridgeAlertRules_FailedMessagesHigh(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 100 should NOT fire (threshold > 100)
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		failedMessages: 100,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "bridge_failed_messages_high" {
			t.Errorf("should not fire at 100 (threshold > 100): value=%v", a.Value)
		}
	}

	// 101 SHOULD fire
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		failedMessages: 101,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "bridge_failed_messages_high" {
			found = true
			if a.Level != AlertWarning {
				t.Errorf("failed_messages_high: got level %v, want Warning", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected bridge_failed_messages_high alert at 101 failed messages")
	}
}

// TestBridgeAlertRules_QuorumLost verifies the quorum-lost alert fires.
func TestBridgeAlertRules_QuorumLost(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		quorumLost: 1, // quorum lost
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "bridge_validator_quorum_lost" {
			found = true
			if a.Level != AlertCritical {
				t.Errorf("quorum_lost: got level %v, want Critical", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected bridge_validator_quorum_lost alert when quorumLost=1")
	}
}

// TestBridgeAlertRules_QuorumIntact verifies no alert when quorum is intact.
func TestBridgeAlertRules_QuorumIntact(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		quorumLost: 0, // quorum intact
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "bridge_validator_quorum_lost" {
			t.Errorf("should not fire when quorum intact (value=0): value=%v", a.Value)
		}
	}
}

// TestBridgeAlertRules_L1AnchorLagHigh verifies the > 20 blocks threshold.
func TestBridgeAlertRules_L1AnchorLagHigh(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 20 should NOT fire (threshold > 20)
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		l1AnchorLag: 20,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "bridge_l1_anchor_lag_high" {
			t.Errorf("should not fire at 20 (threshold > 20): value=%v", a.Value)
		}
	}

	// 21 SHOULD fire
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		l1AnchorLag: 21,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "bridge_l1_anchor_lag_high" {
			found = true
			if a.Level != AlertWarning {
				t.Errorf("l1_anchor_lag_high: got level %v, want Warning", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected bridge_l1_anchor_lag_high alert at lag=21")
	}
}

// TestBridgeAlertRules_RelayerDisconnected verifies the disconnected alert fires.
func TestBridgeAlertRules_RelayerDisconnected(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		relayerDisconnected: 1, // disconnected
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "bridge_relayer_disconnected" {
			found = true
			if a.Level != AlertCritical {
				t.Errorf("relayer_disconnected: got level %v, want Critical", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected bridge_relayer_disconnected alert when disconnected=1")
	}
}

// TestBridgeAlertRules_RelayerConnected verifies no alert when relayer is connected.
func TestBridgeAlertRules_RelayerConnected(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		relayerDisconnected: 0, // connected
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "bridge_relayer_disconnected" {
			t.Errorf("should not fire when relayer connected (value=0): value=%v", a.Value)
		}
	}
}

// isBridgeAlert returns true if the alert name starts with "bridge_".
func isBridgeAlert(name string) bool {
	return len(name) >= 7 && name[:7] == "bridge_"
}

// TestBridgeAlertThresholds_DefaultValues verifies that the default thresholds
// match the pre-fix magic numbers so existing behavior is preserved when no
// override is set. AUDIT-FULL ROUND4 LOW-02 regression.
func TestBridgeAlertThresholds_DefaultValues(t *testing.T) {
	defaults := DefaultBridgeAlertThresholds()
	if defaults.MessageProcessingStalledSeconds != 300.0 {
		t.Errorf("default MessageProcessingStalledSeconds = %v, want 300.0", defaults.MessageProcessingStalledSeconds)
	}
	if defaults.FailedMessagesBacklog != 100.0 {
		t.Errorf("default FailedMessagesBacklog = %v, want 100.0", defaults.FailedMessagesBacklog)
	}
	if defaults.QuorumLostTrigger != 0.5 {
		t.Errorf("default QuorumLostTrigger = %v, want 0.5", defaults.QuorumLostTrigger)
	}
	if defaults.L1AnchorLagBlocks != 20.0 {
		t.Errorf("default L1AnchorLagBlocks = %v, want 20.0", defaults.L1AnchorLagBlocks)
	}
	if defaults.RelayerDisconnectedTrigger != 0.5 {
		t.Errorf("default RelayerDisconnectedTrigger = %v, want 0.5", defaults.RelayerDisconnectedTrigger)
	}
}

// TestBridgeAlertThresholds_Override verifies that SetBridgeAlertThresholds
// changes the effective thresholds and that the bridge rules fire at the
// overridden boundary rather than the default boundary.
// AUDIT-FULL ROUND4 LOW-02 regression.
func TestBridgeAlertThresholds_Override(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// Override thresholds to non-default values: 500s stalled, 200 failed, 0.1 trigger, 50 blocks, 0.1 trigger.
	override := &BridgeAlertThresholds{
		MessageProcessingStalledSeconds: 500.0,
		FailedMessagesBacklog:           200.0,
		QuorumLostTrigger:               0.1,
		L1AnchorLagBlocks:               50.0,
		RelayerDisconnectedTrigger:      0.1,
	}
	m.SetBridgeAlertThresholds(override)

	// Verify the override was applied by checking the internal state.
	got := m.getBridgeAlertThresholds()
	if got.MessageProcessingStalledSeconds != 500.0 {
		t.Errorf("override MessageProcessingStalledSeconds = %v, want 500.0", got.MessageProcessingStalledSeconds)
	}
	if got.FailedMessagesBacklog != 200.0 {
		t.Errorf("override FailedMessagesBacklog = %v, want 200.0", got.FailedMessagesBacklog)
	}

	// 1. Message processing: 400s should NOT fire (default 300 would fire, but override is 500).
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		messageStalled: 400,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "bridge_message_processing_stopped" {
			t.Errorf("should not fire at 400s with override threshold 500: value=%v", a.Value)
		}
	}

	// 501s SHOULD fire with override threshold 500.
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		messageStalled: 501,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "bridge_message_processing_stopped" {
			found = true
		}
	}
	if !found {
		t.Error("expected bridge_message_processing_stopped alert at 501s with override threshold 500")
	}

	// 2. Failed messages: 150 should NOT fire (default 100 would fire, but override is 200).
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		failedMessages: 150,
	})
	alerts = am.Check(m)
	for _, a := range alerts {
		if a.Name == "bridge_failed_messages_high" {
			t.Errorf("should not fire at 150 with override threshold 200: value=%v", a.Value)
		}
	}

	// 201 SHOULD fire
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		failedMessages: 201,
	})
	alerts = am.Check(m)
	found = false
	for _, a := range alerts {
		if a.Name == "bridge_failed_messages_high" {
			found = true
		}
	}
	if !found {
		t.Error("expected bridge_failed_messages_high alert at 201 with override threshold 200")
	}

	// 3. Quorum lost: override 0.1 — value 0.5 should fire.
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		quorumLost: 0.5,
	})
	alerts = am.Check(m)
	found = false
	for _, a := range alerts {
		if a.Name == "bridge_validator_quorum_lost" {
			found = true
		}
	}
	if !found {
		t.Error("expected bridge_validator_quorum_lost alert at 0.5 with override trigger 0.1")
	}

	// 4. L1 anchor lag: 30 should NOT fire (default 20 would fire, but override is 50).
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		l1AnchorLag: 30,
	})
	alerts = am.Check(m)
	for _, a := range alerts {
		if a.Name == "bridge_l1_anchor_lag_high" {
			t.Errorf("should not fire at 30 with override threshold 50: value=%v", a.Value)
		}
	}

	// 51 SHOULD fire
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		l1AnchorLag: 51,
	})
	alerts = am.Check(m)
	found = false
	for _, a := range alerts {
		if a.Name == "bridge_l1_anchor_lag_high" {
			found = true
		}
	}
	if !found {
		t.Error("expected bridge_l1_anchor_lag_high alert at 51 with override threshold 50")
	}

	// 5. Relayer disconnected: override 0.1 — value 0.5 should fire.
	am.ClearAlerts()
	m.SetBridgeMetricProvider(&fakeBridgeProvider{
		relayerDisconnected: 0.5,
	})
	alerts = am.Check(m)
	found = false
	for _, a := range alerts {
		if a.Name == "bridge_relayer_disconnected" {
			found = true
		}
	}
	if !found {
		t.Error("expected bridge_relayer_disconnected alert at 0.5 with override trigger 0.1")
	}

	// Reset to nil (revert to defaults) and verify defaults are restored.
	m.SetBridgeAlertThresholds(nil)
	got = m.getBridgeAlertThresholds()
	if got.MessageProcessingStalledSeconds != 300.0 {
		t.Errorf("after nil reset, MessageProcessingStalledSeconds = %v, want 300.0", got.MessageProcessingStalledSeconds)
	}
}

// TestBridgeAlertThresholds_DefaultRulesUnaffected verifies that overridden
// bridge alert thresholds do NOT affect non-bridge alert rules (e.g. rollup,
// DA, ministry, default rules). AUDIT-FULL ROUND4 LOW-02 regression.
func TestBridgeAlertThresholds_DefaultRulesUnaffected(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// Count total rules before.
	rulesBefore := len(am.rules)

	// Override bridge thresholds.
	m.SetBridgeAlertThresholds(&BridgeAlertThresholds{
		MessageProcessingStalledSeconds: 999.0,
		FailedMessagesBacklog:           999.0,
		QuorumLostTrigger:               0.001,
		L1AnchorLagBlocks:               999.0,
		RelayerDisconnectedTrigger:      0.001,
	})

	// Count total rules after.
	rulesAfter := len(am.rules)

	// The total rule count should be the same (5 bridge rules removed, 5 re-added).
	if rulesBefore != rulesAfter {
		t.Errorf("rule count changed from %d to %d after SetBridgeAlertThresholds (expected no net change)", rulesBefore, rulesAfter)
	}

	// Verify that non-bridge rules still fire at their original thresholds.
	// Trigger a default high_memory_usage alert (4GB threshold).
	am.ClearAlerts()
	m.MemAlloc.Store(5 * 1024 * 1024 * 1024) // 5GB
	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "high_memory_usage" {
			found = true
		}
	}
	if !found {
		t.Error("high_memory_usage default rule should still fire after bridge threshold override")
	}
}
