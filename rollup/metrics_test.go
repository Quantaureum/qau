// Quantaureum Node source, version 1.0.0.
package rollup

// W-P3-1 metrics tests (2026-07-14)
//
// Verifies that all 10 Prometheus metrics are registered, scrapeable, and
// correctly updated by the engine + fraud prover.
//
// Each test uses a fresh prometheus.Registry to avoid "duplicate collector
// registration" panics (promauto registers with the global registry by
// default; NewRollupMetricsWithRegistry allows injecting a fresh one).

import (
	"math/big"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/quantaureum/qau/types"
)

// expectedRollupMetricNames lists all 12 W-P3-1/W-P3-2/W-P3-3 metric names.
var expectedRollupMetricNames = []string{
	"qau_rollup_status",
	"qau_rollup_batches_total",
	"qau_rollup_transactions_total",
	"qau_rollup_pending_transactions",
	"qau_rollup_batch_build_duration_seconds",
	"qau_rollup_batch_submit_duration_seconds",
	"qau_rollup_batch_process_duration_seconds",
	"qau_rollup_fraud_proofs_submitted_total",
	"qau_rollup_fraud_proofs_verified_total",
	"qau_rollup_l1_anchor_lag",
	"qau_rollup_consecutive_batch_failures", // W-P3-2
	"qau_rollup_batch_loop_panics_total",    // W-P3-3
}

// TestRollupMetrics_AllRegistered verifies all 10 metrics are registered with
// a fresh registry. This is the W-P3-1 DoD: "Prometheus can scrape all 10
// metrics."
func TestRollupMetrics_AllRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewRollupMetricsWithRegistry(reg)

	// Gauge/Counter metrics have exactly 1 series.
	singleSeriesChecks := []struct {
		name string
		c    prometheus.Collector
	}{
		{"qau_rollup_status", m.Status},
		{"qau_rollup_batches_total", m.TotalBatches},
		{"qau_rollup_transactions_total", m.TotalTxs},
		{"qau_rollup_pending_transactions", m.PendingTxs},
		{"qau_rollup_fraud_proofs_submitted_total", m.FraudProofsSubmitted},
		{"qau_rollup_fraud_proofs_verified_total", m.FraudProofsVerified},
		{"qau_rollup_l1_anchor_lag", m.L1AnchorLag},
		{"qau_rollup_consecutive_batch_failures", m.ConsecutiveBatchFailures},
		{"qau_rollup_batch_loop_panics_total", m.BatchLoopPanics},
	}
	for _, c := range singleSeriesChecks {
		if n := testutil.CollectAndCount(c.c); n != 1 {
			t.Errorf("metric %s: expected 1 series, got %d", c.name, n)
		}
	}

	// Histogram metrics have > 0 series (buckets + sum + count).
	histChecks := []struct {
		name string
		c    prometheus.Collector
	}{
		{"qau_rollup_batch_build_duration_seconds", m.BatchBuildDuration},
		{"qau_rollup_batch_submit_duration_seconds", m.BatchSubmitDuration},
		{"qau_rollup_batch_process_duration_seconds", m.BatchProcessDuration},
	}
	for _, c := range histChecks {
		if n := testutil.CollectAndCount(c.c); n == 0 {
			t.Errorf("metric %s: no series registered", c.name)
		}
	}
}

// TestRollupMetrics_HelperMethods verifies the nil-safe helper methods update
// metric values correctly.
func TestRollupMetrics_HelperMethods(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewRollupMetricsWithRegistry(reg)

	// Status (gauge)
	m.SetStatus(RollupStatusRunning)
	if v := testutil.ToFloat64(m.Status); v != float64(RollupStatusRunning) {
		t.Errorf("status: got %v, want %v", v, RollupStatusRunning)
	}
	m.SetStatus(RollupStatusStopped)
	if v := testutil.ToFloat64(m.Status); v != float64(RollupStatusStopped) {
		t.Errorf("status: got %v, want %v", v, RollupStatusStopped)
	}

	// TotalBatches (counter)
	m.IncBatches()
	m.IncBatches()
	if v := testutil.ToFloat64(m.TotalBatches); v != 2 {
		t.Errorf("batches_total: got %v, want 2", v)
	}

	// TotalTxs (counter)
	m.AddTxs(10)
	m.AddTxs(5)
	if v := testutil.ToFloat64(m.TotalTxs); v != 15 {
		t.Errorf("transactions_total: got %v, want 15", v)
	}

	// PendingTxs (gauge)
	m.SetPendingTxs(42)
	if v := testutil.ToFloat64(m.PendingTxs); v != 42 {
		t.Errorf("pending_transactions: got %v, want 42", v)
	}

	// FraudProofsSubmitted (counter)
	m.IncFraudProofSubmitted()
	m.IncFraudProofSubmitted()
	m.IncFraudProofSubmitted()
	if v := testutil.ToFloat64(m.FraudProofsSubmitted); v != 3 {
		t.Errorf("fraud_proofs_submitted_total: got %v, want 3", v)
	}

	// FraudProofsVerified (counter)
	m.IncFraudProofVerified()
	if v := testutil.ToFloat64(m.FraudProofsVerified); v != 1 {
		t.Errorf("fraud_proofs_verified_total: got %v, want 1", v)
	}

	// L1AnchorLag (gauge)
	m.SetL1AnchorLag(7)
	if v := testutil.ToFloat64(m.L1AnchorLag); v != 7 {
		t.Errorf("l1_anchor_lag: got %v, want 7", v)
	}

	// ConsecutiveBatchFailures (gauge) — W-P3-2
	m.SetConsecutiveBatchFailures(3)
	if v := testutil.ToFloat64(m.ConsecutiveBatchFailures); v != 3 {
		t.Errorf("consecutive_batch_failures: got %v, want 3", v)
	}
	m.SetConsecutiveBatchFailures(0) // reset on success
	if v := testutil.ToFloat64(m.ConsecutiveBatchFailures); v != 0 {
		t.Errorf("consecutive_batch_failures after reset: got %v, want 0", v)
	}

	// BatchLoopPanics (counter) — W-P3-3
	m.IncBatchLoopPanic()
	m.IncBatchLoopPanic()
	if v := testutil.ToFloat64(m.BatchLoopPanics); v != 2 {
		t.Errorf("batch_loop_panics_total: got %v, want 2", v)
	}

	// Histograms: observe values and verify they don't panic.
	m.ObserveBuildDuration(1 * time.Millisecond)
	m.ObserveBuildDuration(2 * time.Millisecond)
	m.ObserveSubmitDuration(500 * time.Microsecond)
	m.ObserveProcessDuration(3 * time.Millisecond)
}

// TestRollupMetrics_NilSafe verifies all helper methods are nil-safe.
func TestRollupMetrics_NilSafe(t *testing.T) {
	var m *RollupMetrics // nil

	// None of these should panic.
	m.SetStatus(RollupStatusRunning)
	m.IncBatches()
	m.AddTxs(5)
	m.SetPendingTxs(10)
	m.ObserveBuildDuration(0)
	m.ObserveSubmitDuration(0)
	m.ObserveProcessDuration(0)
	m.IncFraudProofSubmitted()
	m.IncFraudProofVerified()
	m.SetL1AnchorLag(0)
	m.SetConsecutiveBatchFailures(0)
	m.IncBatchLoopPanic()
}

// TestRollupMetrics_ProviderMethods verifies the RollupMetricProvider interface
// methods return correct values for the alert manager.
// W-P3-2 (2026-07-14)
func TestRollupMetrics_ProviderMethods(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewRollupMetricsWithRegistry(reg)

	// Set known values
	m.SetStatus(RollupStatusRunning)
	m.SetPendingTxs(42)
	m.SetL1AnchorLag(15)
	m.IncFraudProofSubmitted()
	m.IncFraudProofSubmitted()
	m.SetConsecutiveBatchFailures(3)
	m.IncBatchLoopPanic()

	// Verify provider methods return the same values
	if v := m.StatusValue(); v != float64(RollupStatusRunning) {
		t.Errorf("StatusValue: got %v, want %v", v, RollupStatusRunning)
	}
	if v := m.PendingTxsValue(); v != 42 {
		t.Errorf("PendingTxsValue: got %v, want 42", v)
	}
	if v := m.L1AnchorLagValue(); v != 15 {
		t.Errorf("L1AnchorLagValue: got %v, want 15", v)
	}
	if v := m.FraudProofsSubmittedValue(); v != 2 {
		t.Errorf("FraudProofsSubmittedValue: got %v, want 2", v)
	}
	if v := m.ConsecutiveBatchFailuresValue(); v != 3 {
		t.Errorf("ConsecutiveBatchFailuresValue: got %v, want 3", v)
	}
	if v := m.BatchLoopPanicsValue(); v != 1 {
		t.Errorf("BatchLoopPanicsValue: got %v, want 1", v)
	}

	// Nil-safe: nil receiver should return 0 for all provider methods
	var nilM *RollupMetrics
	if v := nilM.StatusValue(); v != 0 {
		t.Errorf("nil StatusValue: got %v, want 0", v)
	}
	if v := nilM.PendingTxsValue(); v != 0 {
		t.Errorf("nil PendingTxsValue: got %v, want 0", v)
	}
	if v := nilM.L1AnchorLagValue(); v != 0 {
		t.Errorf("nil L1AnchorLagValue: got %v, want 0", v)
	}
	if v := nilM.FraudProofsSubmittedValue(); v != 0 {
		t.Errorf("nil FraudProofsSubmittedValue: got %v, want 0", v)
	}
	if v := nilM.ConsecutiveBatchFailuresValue(); v != 0 {
		t.Errorf("nil ConsecutiveBatchFailuresValue: got %v, want 0", v)
	}
	if v := nilM.BatchLoopPanicsValue(); v != 0 {
		t.Errorf("nil BatchLoopPanicsValue: got %v, want 0", v)
	}
}

// TestRollupMetrics_EngineIntegration verifies the engine updates metrics
// correctly during Start/Stop and batch processing.
func TestRollupMetrics_EngineIntegration(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond // fast for testing
	cfg.MinTxPerBatch = 1
	cfg.MaxTxPerBatch = 10

	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}

	reg := prometheus.NewRegistry()
	m := NewRollupMetricsWithRegistry(reg)
	engine.SetMetrics(m)

	// Before Start: status should be Stopped (0)
	if v := testutil.ToFloat64(m.Status); v != float64(RollupStatusStopped) {
		t.Errorf("pre-start status: got %v, want %v", v, RollupStatusStopped)
	}

	if err := engine.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// After Start: status should be Running (1)
	if v := testutil.ToFloat64(m.Status); v != float64(RollupStatusRunning) {
		t.Errorf("post-start status: got %v, want %v", v, RollupStatusRunning)
	}

	// Submit a transaction and wait for a batch to be processed.
	engine.SetRequireTxSig(false) // bypass signature verification for testing
	tx := &RollupTransaction{
		From:     types.Address{0x01},
		To:       &types.Address{},
		Value:    big.NewInt(0), // zero-value transfer to avoid balance check failure
		GasLimit: 21000,
		// W-P3-1 FIX: zero gas price so gasCost = 21000 * 0 = 0, allowing the
		// unfunded test account (Balance = 0) to pass the balance check in
		// processBatchLocked. With GasPrice > 0, totalCost > 0 and the tx
		// fails with ErrInvalidStateTransition before any batch is built.
		GasPrice: 0,
		ChainID:  cfg.ChainID,
	}
	if err := engine.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction: %v", err)
	}

	// Wait for at least one batch to be built + submitted.
	// The batchLoop runs every BlockTime (100ms); wait up to 2 seconds.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if testutil.ToFloat64(m.TotalBatches) >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify at least 1 batch was submitted.
	if v := testutil.ToFloat64(m.TotalBatches); v < 1 {
		t.Errorf("batches_total: got %v, want >= 1", v)
	}

	// Verify at least 1 tx was counted.
	if v := testutil.ToFloat64(m.TotalTxs); v < 1 {
		t.Errorf("transactions_total: got %v, want >= 1", v)
	}

	// Verify pending txs gauge was updated (should be 0 after batch processing).
	if v := testutil.ToFloat64(m.PendingTxs); v != 0 {
		t.Errorf("pending_transactions after batch: got %v, want 0", v)
	}

	if err := engine.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// After Stop: status should be Stopped (0)
	if v := testutil.ToFloat64(m.Status); v != float64(RollupStatusStopped) {
		t.Errorf("post-stop status: got %v, want %v", v, RollupStatusStopped)
	}
}

// TestRollupMetrics_ScrapeOutput verifies all 10 metric names appear in a
// Prometheus scrape (Gather) from a fresh registry.
func TestRollupMetrics_ScrapeOutput(t *testing.T) {
	reg := prometheus.NewRegistry()
	_ = NewRollupMetricsWithRegistry(reg)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	found := make(map[string]bool)
	for _, fam := range families {
		found[fam.GetName()] = true
	}

	for _, expected := range expectedRollupMetricNames {
		if !found[expected] {
			t.Errorf("metric %q not found in Prometheus scrape output", expected)
		}
	}
}
