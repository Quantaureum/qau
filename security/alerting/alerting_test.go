// Quantaureum Node source, version 1.0.0.
package alerting

import (
	"testing"
	"time"
)

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{SeverityInfo, "INFO"},
		{SeverityWarning, "WARNING"},
		{SeverityError, "ERROR"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.s.String() != tt.want {
				t.Errorf("expected %s, got %s", tt.want, tt.s.String())
			}
		})
	}
}

func TestDefaultAlertConfig(t *testing.T) {
	cfg := DefaultAlertConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.MinSeverity != SeverityWarning {
		t.Errorf("expected Warning, got %s", cfg.MinSeverity)
	}
	if cfg.MaxAlertsPerMinute != 60 {
		t.Errorf("expected 60, got %d", cfg.MaxAlertsPerMinute)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("expected 3, got %d", cfg.MaxRetries)
	}
	if cfg.RetryInterval != time.Second {
		t.Errorf("expected 1s, got %v", cfg.RetryInterval)
	}
}

func TestAlertStruct(t *testing.T) {
	now := time.Now()
	alert := &Alert{
		ID:           "alert-001",
		Type:         "SECURITY",
		Title:        "Test Alert",
		Message:      "Test message",
		Source:       "test",
		Severity:     SeverityError,
		Acknowledged: false,
		Resolved:     false,
		Timestamp:    now,
		Details:      map[string]any{"key": "value"},
	}
	if alert.ID != "alert-001" {
		t.Errorf("expected alert-001, got %s", alert.ID)
	}
	if alert.Severity != SeverityError {
		t.Errorf("expected Error, got %s", alert.Severity)
	}
	if alert.Acknowledged {
		t.Error("expected not acknowledged")
	}
}

func TestNewAlertManager(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	if am == nil {
		t.Fatal("expected non-nil manager")
	}
	if am.maxAlerts != 10000 {
		t.Errorf("expected 10000, got %d", am.maxAlerts)
	}
	if am.running {
		t.Error("expected not running initially")
	}

	alerts := am.GetAlerts(0)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestNewAlertManager_NilConfig(t *testing.T) {
	am := NewAlertManager(nil)
	if am == nil {
		t.Fatal("expected non-nil manager with nil config")
	}
	if am.config == nil {
		t.Fatal("expected default config when nil passed")
	}
}

func TestAlertManager_StartStop(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	am.Start()
	if !am.running {
		t.Error("expected running after start")
	}
	am.Stop()
	if am.running {
		t.Error("expected not running after stop")
	}
}

func TestAlertManager_DoubleStart(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	am.Start()
	am.Start() // Should not panic, just returns
	if !am.running {
		t.Error("expected still running after double start")
	}
	am.Stop()
}

func TestAlertManager_AddChannel(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	ch := &mockChannel{name: "mock", enabled: true}
	am.AddChannel(ch)
}

func TestAlertManager_SendAlert(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	am.Start()
	defer am.Stop()

	ch := &mockChannel{name: "test_channel", enabled: true}
	am.AddChannel(ch)

	alert := &Alert{
		ID:        "a1",
		Type:      "TEST",
		Title:     "Test",
		Message:   "Test alert",
		Severity:  SeverityWarning,
		Timestamp: time.Now(),
	}

	err := am.SendAlert(alert)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(ch.sent) != 1 {
		t.Errorf("expected 1 sent, got %d", len(ch.sent))
	}
}

func TestAlertManager_SendAlert_WhileNotStarted(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	err := am.SendAlert(&Alert{
		ID: "a1", Type: "T", Title: "T", Message: "M", Severity: SeverityInfo, Timestamp: time.Now(),
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAlertManager_SendAlert_BelowMinSeverity(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	am.Start()
	defer am.Stop()

	ch := &mockChannel{name: "ch", enabled: true}
	am.AddChannel(ch)

	alert := &Alert{
		ID:        "a2",
		Type:      "INFO",
		Title:     "Info",
		Message:   "Info alert",
		Severity:  SeverityInfo,
		Timestamp: time.Now(),
	}

	err := am.SendAlert(alert)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(ch.sent) != 0 {
		t.Error("expected 0 sent (below min severity)")
	}
}

func TestAlertManager_SendAlert_RateLimit(t *testing.T) {
	cfg := &AlertConfig{
		MinSeverity:         SeverityInfo,
		MaxAlertsPerMinute:  2,
		DeduplicationWindow: time.Second,
		MaxRetries:          1,
		RetryInterval:       time.Millisecond,
	}
	am := NewAlertManager(cfg)
	am.Start()
	defer am.Stop()

	ch := &mockChannel{name: "ch", enabled: true}
	am.AddChannel(ch)

	for i := 0; i < 3; i++ {
		err := am.SendAlert(&Alert{
			ID: "rate_" + string(rune('0'+i)), Type: "T", Title: "T" + string(rune('0'+i)),
			Message: "M", Severity: SeverityWarning, Timestamp: time.Now(),
		})
		if i >= 2 && err != nil {
			if err.Error() != "rate limit exceeded" {
				t.Errorf("expected rate limit error, got: %v", err)
			}
		}
	}
}

func TestAlertManager_AcknowledgeAlert(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	am.Start()
	defer am.Stop()

	ch := &mockChannel{name: "ch", enabled: true}
	am.AddChannel(ch)

	alert := &Alert{
		ID: "a3", Type: "T", Title: "T", Message: "M", Severity: SeverityCritical, Timestamp: time.Now(),
	}
	am.SendAlert(alert)

	err := am.AcknowledgeAlert("a3")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = am.AcknowledgeAlert("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent")
	}
}

func TestAlertManager_ResolveAlert(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	am.Start()
	defer am.Stop()

	ch := &mockChannel{name: "ch", enabled: true}
	am.AddChannel(ch)

	alert := &Alert{
		ID: "a4", Type: "T", Title: "T", Message: "M", Severity: SeverityWarning, Timestamp: time.Now(),
	}
	am.SendAlert(alert)

	err := am.ResolveAlert("a4")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = am.ResolveAlert("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent")
	}
}

func TestAlertManager_GetAlerts(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	am.Start()
	defer am.Stop()

	ch := &mockChannel{name: "ch", enabled: true}
	am.AddChannel(ch)

	for i := 0; i < 5; i++ {
		am.SendAlert(&Alert{
			ID: "a" + string(rune('0'+i)), Type: "T" + string(rune('0'+i)), Title: "T" + string(rune('0'+i)), Message: "M",
			Severity: SeverityError, Timestamp: time.Now(),
		})
	}

	alerts := am.GetAlerts(0)
	if len(alerts) != 5 {
		t.Errorf("expected 5 alerts, got %d", len(alerts))
	}

	limited := am.GetAlerts(2)
	if len(limited) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(limited))
	}
}

func TestAlertManager_Deduplication(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	am.Start()
	defer am.Stop()

	ch := &mockChannel{name: "ch", enabled: true}
	am.AddChannel(ch)

	alert := &Alert{
		ID: "a6", Type: "T", Title: "T", Message: "M", Severity: SeverityError, Timestamp: time.Now(),
	}

	am.SendAlert(alert)
	am.SendAlert(alert) // Same Type+Source+Title = deduplicated

	if len(ch.sent) != 1 {
		t.Errorf("expected 1 (deduplicated), got %d", len(ch.sent))
	}
}

func TestAlertManager_DisabledChannel(t *testing.T) {
	am := NewAlertManager(DefaultAlertConfig())
	am.Start()
	defer am.Stop()

	ch := &mockChannel{name: "disabled_ch", enabled: false}
	am.AddChannel(ch)

	err := am.SendAlert(&Alert{
		ID: "a7", Type: "T", Title: "T", Message: "M", Severity: SeverityError, Timestamp: time.Now(),
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(ch.sent) != 0 {
		t.Error("expected 0 sent (channel disabled)")
	}
}

type mockChannel struct {
	name    string
	enabled bool
	sent    []*Alert
}

func (m *mockChannel) Name() string    { return m.name }
func (m *mockChannel) IsEnabled() bool { return m.enabled }
func (m *mockChannel) Close() error    { return nil }
func (m *mockChannel) Send(alert *Alert) error {
	m.sent = append(m.sent, alert)
	return nil
}
