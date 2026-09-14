// Quantaureum Node source, version 1.0.0.
package metrics

// P3-3 Three Chambers Finality alert rule tests (2026-07-15)
//
// Verifies that the 2 Three Chambers alert rules are registered, evaluate
// correctly against a ThreeChambersMetricProvider, and fire when thresholds
// are exceeded.

import (
	"testing"
)

// fakeThreeChambersProvider is a test double for ThreeChambersMetricProvider.
type fakeThreeChambersProvider struct {
	evidenceQueueLength float64
	dkgElapsedSeconds   float64
}

func (f *fakeThreeChambersProvider) EvidenceQueueLengthValue() float64 {
	return f.evidenceQueueLength
}

func (f *fakeThreeChambersProvider) DKGElapsedSecondsValue() float64 {
	return f.dkgElapsedSeconds
}

// TestThreeChambersAlertRules_NoProvider verifies that all Three Chambers
// alert rules return 0 (no alert) when no provider is set. This is the
// default state — Three Chambers may not be enabled on every node.
func TestThreeChambersAlertRules_NoProvider(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	alerts := am.Check(m)
	for _, a := range alerts {
		if isThreeChambersAlert(a.Name) {
			t.Errorf("three chambers alert %q fired without provider (value=%v)", a.Name, a.Value)
		}
	}
}

// TestThreeChambersAlertRules_Healthy verifies that no Three Chambers alerts
// fire when the evidence queue is small and DKG is not running.
func TestThreeChambersAlertRules_Healthy(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetThreeChambersMetricProvider(&fakeThreeChambersProvider{
		evidenceQueueLength: 10, // well below 100 threshold
		dkgElapsedSeconds:   0,  // DKG not running
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if isThreeChambersAlert(a.Name) {
			t.Errorf("three chambers alert %q fired in healthy state (value=%v, threshold=%v)",
				a.Name, a.Value, a.Threshold)
		}
	}
}

// TestThreeChambersAlertRules_EvidenceQueueBacklog verifies the > 100
// threshold for the evidence queue backlog alert.
func TestThreeChambersAlertRules_EvidenceQueueBacklog(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 100 should NOT fire (threshold is > 100, not >= 100)
	am.ClearAlerts()
	m.SetThreeChambersMetricProvider(&fakeThreeChambersProvider{
		evidenceQueueLength: 100,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "three_chambers_evidence_queue_backlog" {
			t.Errorf("should not fire at 100 (threshold > 100): value=%v", a.Value)
		}
	}

	// 101 SHOULD fire
	am.ClearAlerts()
	m.SetThreeChambersMetricProvider(&fakeThreeChambersProvider{
		evidenceQueueLength: 101,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "three_chambers_evidence_queue_backlog" {
			found = true
			if a.Level != AlertWarning {
				t.Errorf("evidence_queue_backlog: got level %v, want Warning", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected three_chambers_evidence_queue_backlog alert at length=101")
	}
}

// TestThreeChambersAlertRules_DKGStuck verifies the > 1800 seconds (30 min)
// threshold for the DKG stuck alert.
func TestThreeChambersAlertRules_DKGStuck(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 1800 should NOT fire (threshold is > 1800, not >= 1800)
	am.ClearAlerts()
	m.SetThreeChambersMetricProvider(&fakeThreeChambersProvider{
		dkgElapsedSeconds: 1800,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "three_chambers_dkg_stuck" {
			t.Errorf("should not fire at 1800 (threshold > 1800): value=%v", a.Value)
		}
	}

	// 1801 SHOULD fire
	am.ClearAlerts()
	m.SetThreeChambersMetricProvider(&fakeThreeChambersProvider{
		dkgElapsedSeconds: 1801,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "three_chambers_dkg_stuck" {
			found = true
			if a.Level != AlertCritical {
				t.Errorf("dkg_stuck: got level %v, want Critical", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected three_chambers_dkg_stuck alert at elapsed=1801")
	}
}

// TestThreeChambersAlertRules_ColdStart verifies that no alerts fire when
// the provider returns 0 for both metrics (cold start: no evidence queued,
// DKG not running).
func TestThreeChambersAlertRules_ColdStart(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetThreeChambersMetricProvider(&fakeThreeChambersProvider{
		evidenceQueueLength: 0,
		dkgElapsedSeconds:   0,
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if isThreeChambersAlert(a.Name) {
			t.Errorf("three chambers alert %q fired on cold start (value=%v)", a.Name, a.Value)
		}
	}
}

// isThreeChambersAlert returns true if the alert name starts with
// "three_chambers_".
func isThreeChambersAlert(name string) bool {
	return len(name) >= 15 && name[:15] == "three_chambers_"
}
