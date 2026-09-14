// Quantaureum Node source, version 1.0.0.
// Package bridge tests for adaptive_timeout.go.
//
// R7-OBS-1 (2026-07-18): Verifies AdaptiveRPCTimeout returns the base
// timeout when metrics are nil or healthy, and scales up under degraded
// conditions (high anchor lag, stalled processing).
package bridge

import (
	"testing"
	"time"
)

// TestAdaptiveRPCTimeout_NilMetrics ensures nil-safe behavior: when no
// metrics are wired (e.g., test deployments without Prometheus), the
// helper returns the pre-fix base timeout of 15s. This preserves
// backward compatibility for adapters constructed without metrics.
func TestAdaptiveRPCTimeout_NilMetrics(t *testing.T) {
	var m *BridgeMetrics // nil
	got := m.AdaptiveRPCTimeout()
	if got != adaptiveTimeoutBase {
		t.Fatalf("nil metrics: expected base %v, got %v", adaptiveTimeoutBase, got)
	}
	if got != 15*time.Second {
		t.Fatalf("nil metrics: expected 15s, got %v", got)
	}
}

// TestAdaptiveRPCTimeout_HealthyState verifies that a metrics instance with
// no degraded signals (low anchor lag, recent processing) returns the
// base 15s timeout.
func TestAdaptiveRPCTimeout_HealthyState(t *testing.T) {
	m := NewBridgeMetrics()
	// Healthy: lag below threshold, last processed just now.
	m.L1AnchorLag.Set(5)
	m.LastMessageProcessedAt.Set(float64(time.Now().Unix()))

	got := m.AdaptiveRPCTimeout()
	if got != adaptiveTimeoutBase {
		t.Fatalf("healthy: expected base %v, got %v", adaptiveTimeoutBase, got)
	}
}

// TestAdaptiveRPCTimeout_HighAnchorLag verifies that anchor lag > 20
// triggers the 2.0x multiplier (15s → 30s).
func TestAdaptiveRPCTimeout_HighAnchorLag(t *testing.T) {
	m := NewBridgeMetrics()
	m.L1AnchorLag.Set(adaptiveAnchorLagThreshold + 1) // 21
	m.LastMessageProcessedAt.Set(float64(time.Now().Unix()))

	got := m.AdaptiveRPCTimeout()
	want := time.Duration(float64(adaptiveTimeoutBase) * 2.0)
	if got != want {
		t.Fatalf("high anchor lag: expected %v, got %v", want, got)
	}
}

// TestAdaptiveRPCTimeout_ProcessingStalled verifies that processing
// staleness > 300s triggers the 1.5x multiplier (15s → 22.5s).
func TestAdaptiveRPCTimeout_ProcessingStalled(t *testing.T) {
	m := NewBridgeMetrics()
	m.L1AnchorLag.Set(5) // healthy
	// Set last processed 400s ago (above 300s threshold).
	m.LastMessageProcessedAt.Set(float64(time.Now().Unix() - 400))

	got := m.AdaptiveRPCTimeout()
	want := time.Duration(float64(adaptiveTimeoutBase) * 1.5)
	if got != want {
		t.Fatalf("processing stalled: expected %v, got %v", want, got)
	}
}

// TestAdaptiveRPCTimeout_BothSignalsDegraded verifies that both degraded
// signals compose multiplicatively (15s * 2.0 * 1.5 = 45s).
func TestAdaptiveRPCTimeout_BothSignalsDegraded(t *testing.T) {
	m := NewBridgeMetrics()
	m.L1AnchorLag.Set(adaptiveAnchorLagThreshold + 1) // 21
	m.LastMessageProcessedAt.Set(float64(time.Now().Unix() - 400))

	// P3-BR-05 (2026-08-03): the two degradation signals now combine via
	// max() rather than multiplication. Previously expected want =
	// adaptiveTimeoutBase * 2.0 * 1.5 = 45s, now want = adaptiveTimeoutBase
	// * max(2.0, 1.5) = adaptiveTimeoutBase * 2.0 = 30s. The audit fatigue
	// rationale: stacking the two independent signals multiplicatively
	// implied a compounding degradation that does not actually compound
	// in practice. See adaptive_timeout.go AdaptiveRPCTimeout doc.
	got := m.AdaptiveRPCTimeout()
	want := time.Duration(float64(adaptiveTimeoutBase) * 2.0)
	if got != want {
		t.Fatalf("both degraded: expected %v, got %v", want, got)
	}
}

// TestAdaptiveRPCTimeout_ColdStartNotPenalized verifies that a fresh
// metrics instance (LastMessageProcessedAt == 0, meaning no message ever
// processed) does NOT scale the timeout. This avoids false positives during
// node startup.
//
// Note: BridgeMetrics is a process-wide singleton (sync.Once), so prior
// tests may have set LastMessageProcessedAt to a stale value. We explicitly
// reset it to 0 to simulate cold start.
func TestAdaptiveRPCTimeout_ColdStartNotPenalized(t *testing.T) {
	m := NewBridgeMetrics()
	m.L1AnchorLag.Set(5)            // healthy
	m.LastMessageProcessedAt.Set(0) // cold start: no message ever processed

	got := m.AdaptiveRPCTimeout()
	if got != adaptiveTimeoutBase {
		t.Fatalf("cold start: expected base %v, got %v", adaptiveTimeoutBase, got)
	}
}

// TestAdaptiveRPCTimeout_BoundaryValues verifies the threshold boundaries:
// exactly at threshold should NOT trigger (uses >), just above should trigger.
func TestAdaptiveRPCTimeout_BoundaryValues(t *testing.T) {
	t.Run("anchor lag exactly at threshold", func(t *testing.T) {
		m := NewBridgeMetrics()
		m.L1AnchorLag.Set(adaptiveAnchorLagThreshold) // exactly 20
		m.LastMessageProcessedAt.Set(float64(time.Now().Unix()))
		got := m.AdaptiveRPCTimeout()
		if got != adaptiveTimeoutBase {
			t.Fatalf("at-threshold lag should not scale: expected %v, got %v", adaptiveTimeoutBase, got)
		}
	})

	t.Run("processing stalled exactly at threshold", func(t *testing.T) {
		m := NewBridgeMetrics()
		m.L1AnchorLag.Set(5)
		// Set last processed exactly 300s ago.
		m.LastMessageProcessedAt.Set(float64(time.Now().Unix() - 300))
		got := m.AdaptiveRPCTimeout()
		// MessageProcessingStalledValue uses now - last, which could be
		// slightly above 300 due to test execution time. We allow either
		// base or scaled-by-1.5x here.
		basePlusEpsilon := time.Duration(float64(adaptiveTimeoutBase) * 1.5)
		if got != adaptiveTimeoutBase && got != basePlusEpsilon {
			t.Fatalf("at-threshold stall: expected %v or %v, got %v", adaptiveTimeoutBase, basePlusEpsilon, got)
		}
	})
}

// TestAdaptiveRPCTimeout_RespectsMaxCeiling verifies that even under
// extreme degradation, the timeout never exceeds adaptiveTimeoutMax.
// Since current multipliers cap at 2.0 * 1.5 = 3.0x (45s), this test
// also documents the current ceiling behavior.
func TestAdaptiveRPCTimeout_RespectsMaxCeiling(t *testing.T) {
	m := NewBridgeMetrics()
	// Maximum possible degradation with current signals.
	m.L1AnchorLag.Set(1000)         // extreme
	m.LastMessageProcessedAt.Set(1) // 1970-01-01 → very stale

	got := m.AdaptiveRPCTimeout()
	if got > adaptiveTimeoutMax {
		t.Fatalf("extreme degradation: exceeded max %v, got %v", adaptiveTimeoutMax, got)
	}
	// P3-BR-05 (2026-08-03): the two degradation signals now combine via
	// max() rather than multiplication. Previously expected want =
	// adaptiveTimeoutBase * 2.0 * 1.5 = 45s, now want = adaptiveTimeoutBase
	// * max(2.0, 1.5) = adaptiveTimeoutBase * 2.0 = 30s, well below the
	// 120s ceiling. The audit fatigue rationale: stacking the two
	// independent signals multiplicatively implied a compounding
	// degradation that does not actually compound in practice. See
	// adaptive_timeout.go AdaptiveRPCTimeout doc.
	want := time.Duration(float64(adaptiveTimeoutBase) * 2.0)
	if got != want {
		t.Fatalf("extreme degradation: expected composite %v, got %v", want, got)
	}
}
