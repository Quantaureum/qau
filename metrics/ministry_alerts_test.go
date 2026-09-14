// Quantaureum Node source, version 1.0.0.
package metrics

// P3-T3 ministry alert rule tests (2026-07-15)
//
// Verifies that the 4 ministry alert rules are registered, evaluate
// correctly against a MinistryMetricProvider, and fire when thresholds
// are exceeded.

import (
	"testing"
)

// fakeMinistryProvider is a test double for MinistryMetricProvider.
type fakeMinistryProvider struct {
	criticalAlerts    float64
	partitionDetected float64
	blacklistSize     float64
	pendingCases      float64
}

func (f *fakeMinistryProvider) CriticalAlertsValue() float64    { return f.criticalAlerts }
func (f *fakeMinistryProvider) PartitionDetectedValue() float64 { return f.partitionDetected }
func (f *fakeMinistryProvider) BlacklistSizeValue() float64     { return f.blacklistSize }
func (f *fakeMinistryProvider) PendingCasesValue() float64      { return f.pendingCases }

// TestMinistryAlertRules_NoProvider verifies that all ministry alert rules
// return 0 (no alert) when no provider is set. This is the default state —
// ministry metrics are not enabled on every node.
func TestMinistryAlertRules_NoProvider(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	alerts := am.Check(m)
	for _, a := range alerts {
		if isMinistryAlert(a.Name) {
			t.Errorf("ministry alert %q fired without provider (value=%v)", a.Name, a.Value)
		}
	}
}

// TestMinistryAlertRules_Healthy verifies that no ministry alerts fire
// when all metrics are within thresholds.
func TestMinistryAlertRules_Healthy(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetMinistryMetricProvider(&fakeMinistryProvider{
		criticalAlerts:    0,
		partitionDetected: 0,
		blacklistSize:     3,
		pendingCases:      10,
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if isMinistryAlert(a.Name) {
			t.Errorf("ministry alert %q fired in healthy state (value=%v, threshold=%v)",
				a.Name, a.Value, a.Threshold)
		}
	}
}

// TestMinistryAlertRules_QuantumAttack verifies the critical alerts > 0 rule.
func TestMinistryAlertRules_QuantumAttack(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetMinistryMetricProvider(&fakeMinistryProvider{
		criticalAlerts: 1, // any critical alert
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "ministry_quantum_attack_detected" {
			found = true
			if a.Level != AlertCritical {
				t.Errorf("quantum_attack_detected: got level %v, want Critical", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected ministry_quantum_attack_detected alert when criticalAlerts=1")
	}
}

// TestMinistryAlertRules_NetworkPartition verifies the partition detected rule.
func TestMinistryAlertRules_NetworkPartition(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetMinistryMetricProvider(&fakeMinistryProvider{
		partitionDetected: 1, // partition detected
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "ministry_network_partition_detected" {
			found = true
			if a.Level != AlertCritical {
				t.Errorf("network_partition_detected: got level %v, want Critical", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected ministry_network_partition_detected alert when partitionDetected=1")
	}
}

// TestMinistryAlertRules_BlacklistSpike verifies the > 10 threshold.
func TestMinistryAlertRules_BlacklistSpike(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 10 should NOT fire (threshold is > 10, not >= 10)
	am.ClearAlerts()
	m.SetMinistryMetricProvider(&fakeMinistryProvider{
		blacklistSize: 10,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "ministry_blacklist_spike" {
			t.Errorf("should not fire at 10 (threshold > 10): value=%v", a.Value)
		}
	}

	// 11 SHOULD fire
	am.ClearAlerts()
	m.SetMinistryMetricProvider(&fakeMinistryProvider{
		blacklistSize: 11,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "ministry_blacklist_spike" {
			found = true
			if a.Level != AlertWarning {
				t.Errorf("blacklist_spike: got level %v, want Warning", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected ministry_blacklist_spike alert at blacklistSize=11")
	}
}

// TestMinistryAlertRules_PendingCasesBacklog verifies the > 50 threshold.
func TestMinistryAlertRules_PendingCasesBacklog(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 50 should NOT fire (threshold is > 50, not >= 50)
	am.ClearAlerts()
	m.SetMinistryMetricProvider(&fakeMinistryProvider{
		pendingCases: 50,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "ministry_pending_cases_backlog" {
			t.Errorf("should not fire at 50 (threshold > 50): value=%v", a.Value)
		}
	}

	// 51 SHOULD fire
	am.ClearAlerts()
	m.SetMinistryMetricProvider(&fakeMinistryProvider{
		pendingCases: 51,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "ministry_pending_cases_backlog" {
			found = true
			if a.Level != AlertWarning {
				t.Errorf("pending_cases_backlog: got level %v, want Warning", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected ministry_pending_cases_backlog alert at pendingCases=51")
	}
}

// isMinistryAlert returns true if the alert name starts with "ministry_".
func isMinistryAlert(name string) bool {
	return len(name) >= 9 && name[:9] == "ministry_"
}
