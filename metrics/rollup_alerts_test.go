// Quantaureum Node source, version 1.0.0.
package metrics

// W-P3-2/W-P3-3 alert rule tests (2026-07-14)
//
// Verifies that the 6 rollup alert rules are registered, evaluate correctly
// against a RollupMetricProvider, and fire when thresholds are exceeded.

import (
	"testing"
)

// fakeRollupProvider is a test double for RollupMetricProvider.
type fakeRollupProvider struct {
	status               float64
	pendingTxs           float64
	l1AnchorLag          float64
	fraudProofsSubmitted float64
	consecutiveFailures  float64
	batchLoopPanics      float64
}

func (f *fakeRollupProvider) StatusValue() float64                   { return f.status }
func (f *fakeRollupProvider) PendingTxsValue() float64               { return f.pendingTxs }
func (f *fakeRollupProvider) L1AnchorLagValue() float64              { return f.l1AnchorLag }
func (f *fakeRollupProvider) FraudProofsSubmittedValue() float64     { return f.fraudProofsSubmitted }
func (f *fakeRollupProvider) ConsecutiveBatchFailuresValue() float64 { return f.consecutiveFailures }
func (f *fakeRollupProvider) BatchLoopPanicsValue() float64          { return f.batchLoopPanics }

// TestRollupAlertRules_NoProvider verifies that all rollup alert rules
// return 0 (no alert) when no provider is set. This is the default state —
// rollup is not enabled on every node.
func TestRollupAlertRules_NoProvider(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	alerts := am.Check(m)
	for _, a := range alerts {
		if isRollupAlert(a.Name) {
			t.Errorf("rollup alert %q fired without provider (value=%v)", a.Name, a.Value)
		}
	}
}

// TestRollupAlertRules_RunningHealthy verifies that no rollup alerts fire
// when the engine is running and all metrics are within thresholds.
func TestRollupAlertRules_RunningHealthy(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetRollupMetricProvider(&fakeRollupProvider{
		status:               1, // Running
		pendingTxs:           100,
		l1AnchorLag:          3,
		fraudProofsSubmitted: 0,
		consecutiveFailures:  0,
		batchLoopPanics:      0,
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if isRollupAlert(a.Name) {
			t.Errorf("rollup alert %q fired in healthy state (value=%v, threshold=%v)",
				a.Name, a.Value, a.Threshold)
		}
	}
}

// TestRollupAlertRules_EngineStopped verifies the engine-stopped alert fires.
func TestRollupAlertRules_EngineStopped(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetRollupMetricProvider(&fakeRollupProvider{
		status: 0, // Stopped
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "rollup_engine_stopped" {
			found = true
			if a.Level != AlertCritical {
				t.Errorf("engine_stopped: got level %v, want Critical", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected rollup_engine_stopped alert to fire when status=0")
	}
}

// TestRollupAlertRules_ConsecutiveFailures verifies the > 5 threshold.
func TestRollupAlertRules_ConsecutiveFailures(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 5 failures should NOT fire (threshold is > 5, not >= 5)
	am.ClearAlerts()
	m.SetRollupMetricProvider(&fakeRollupProvider{
		status:              1,
		consecutiveFailures: 5,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "rollup_consecutive_batch_failures" {
			t.Errorf("should not fire at 5 (threshold > 5): value=%v", a.Value)
		}
	}

	// 6 failures SHOULD fire
	am.ClearAlerts()
	m.SetRollupMetricProvider(&fakeRollupProvider{
		status:              1,
		consecutiveFailures: 6,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "rollup_consecutive_batch_failures" {
			found = true
		}
	}
	if !found {
		t.Error("expected rollup_consecutive_batch_failures alert at 6 failures")
	}
}

// TestRollupAlertRules_L1AnchorLag verifies the > 10 L1 blocks threshold.
func TestRollupAlertRules_L1AnchorLag(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 10 should NOT fire (threshold > 10)
	am.ClearAlerts()
	m.SetRollupMetricProvider(&fakeRollupProvider{
		status:      1,
		l1AnchorLag: 10,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "rollup_l1_anchor_lag_high" {
			t.Errorf("should not fire at 10 (threshold > 10): value=%v", a.Value)
		}
	}

	// 11 SHOULD fire
	am.ClearAlerts()
	m.SetRollupMetricProvider(&fakeRollupProvider{
		status:      1,
		l1AnchorLag: 11,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "rollup_l1_anchor_lag_high" {
			found = true
		}
	}
	if !found {
		t.Error("expected rollup_l1_anchor_lag_high alert at lag=11")
	}
}

// TestRollupAlertRules_FraudProofSubmitted verifies any fraud proof fires.
func TestRollupAlertRules_FraudProofSubmitted(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetRollupMetricProvider(&fakeRollupProvider{
		status:               1,
		fraudProofsSubmitted: 1,
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "rollup_fraud_proof_submitted" {
			found = true
		}
	}
	if !found {
		t.Error("expected rollup_fraud_proof_submitted alert when count=1")
	}
}

// TestRollupAlertRules_PendingBacklog verifies the > 10000 threshold.
func TestRollupAlertRules_PendingBacklog(t *testing.T) {
	m := New()
	am := m.AlertManager()

	// 10000 should NOT fire
	am.ClearAlerts()
	m.SetRollupMetricProvider(&fakeRollupProvider{
		status:     1,
		pendingTxs: 10000,
	})
	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "rollup_pending_txs_backlog" {
			t.Errorf("should not fire at 10000 (threshold > 10000): value=%v", a.Value)
		}
	}

	// 10001 SHOULD fire
	am.ClearAlerts()
	m.SetRollupMetricProvider(&fakeRollupProvider{
		status:     1,
		pendingTxs: 10001,
	})
	alerts = am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "rollup_pending_txs_backlog" {
			found = true
		}
	}
	if !found {
		t.Error("expected rollup_pending_txs_backlog alert at 10001 pending")
	}
}

// TestRollupAlertRules_BatchLoopPanic verifies any panic fires a critical alert.
// W-P3-3
func TestRollupAlertRules_BatchLoopPanic(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetRollupMetricProvider(&fakeRollupProvider{
		status:          1,
		batchLoopPanics: 1,
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "rollup_batch_loop_panic" {
			found = true
			if a.Level != AlertCritical {
				t.Errorf("batch_loop_panic: got level %v, want Critical", a.Level)
			}
		}
	}
	if !found {
		t.Error("expected rollup_batch_loop_panic alert when count=1")
	}
}

// isRollupAlert returns true if the alert name starts with "rollup_".
func isRollupAlert(name string) bool {
	return len(name) >= 7 && name[:7] == "rollup_"
}
