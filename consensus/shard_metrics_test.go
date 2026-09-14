// Quantaureum Node source, version 1.0.0.
package consensus

// Shard metrics tests (P3-1, 2026-07-15)
//
// Verifies that all 8 Prometheus metrics are registered, scrapeable, and
// correctly updated by the nil-safe helper methods. Mirrors the
// rollup/metrics_test.go and da_metrics_test.go patterns.
//
// Each test uses a fresh prometheus.Registry to avoid "duplicate collector
// registration" panics (promauto registers with the global registry by
// default; NewShardMetricsWithRegistry allows injecting a fresh one).

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// expectedShardMetricNames lists all 8 P3-1 metric names.
var expectedShardMetricNames = []string{
	"qau_shard_count",
	"qau_shard_block_height",
	"qau_shard_cross_shard_messages_total",
	"qau_shard_pending_messages",
	"qau_shard_finalization_delay_seconds",
	"qau_shard_p2p_messages_total",
	"qau_shard_validator_count",
	"qau_shard_commitment_lag",
}

// TestShardMetrics_AllRegistered verifies all 8 metrics are registered with
// a fresh registry. This is the P3-1 DoD: "Prometheus can scrape all metrics."
//
// Note: GaugeVec/CounterVec metrics only appear in Gather() output after a
// label combination is materialized via WithLabelValues(). We instantiate
// one sample per labeled metric so Gather() reports them.
func TestShardMetrics_AllRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewShardMetricsWithRegistry(reg)

	// Materialize one label combination per labeled metric so Gather() reports them.
	m.BlockHeight.WithLabelValues("0")
	m.PendingMessages.WithLabelValues("0")
	m.P2PMessages.WithLabelValues("init")
	m.ValidatorCount.WithLabelValues("0")
	m.CommitmentLag.WithLabelValues("0")

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	found := make(map[string]bool)
	for _, fam := range families {
		found[fam.GetName()] = true
	}

	for _, expected := range expectedShardMetricNames {
		if !found[expected] {
			t.Errorf("metric %q not found in Prometheus scrape output", expected)
		}
	}
}

// TestShardMetrics_SingleSeries verifies gauge/counter metrics (no labels)
// have exactly 1 series.
func TestShardMetrics_SingleSeries(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewShardMetricsWithRegistry(reg)

	singleSeriesChecks := []struct {
		name string
		c    prometheus.Collector
	}{
		{"qau_shard_count", m.ShardCount},
		{"qau_shard_cross_shard_messages_total", m.CrossShardMessages},
	}
	for _, c := range singleSeriesChecks {
		if n := testutil.CollectAndCount(c.c); n != 1 {
			t.Errorf("metric %s: expected 1 series, got %d", c.name, n)
		}
	}

	// Histogram should have > 0 series.
	if n := testutil.CollectAndCount(m.FinalizationDelay); n == 0 {
		t.Errorf("metric qau_shard_finalization_delay_seconds: no series registered")
	}
}

// TestShardMetrics_HelperMethods verifies the nil-safe helper methods update
// metric values correctly.
func TestShardMetrics_HelperMethods(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewShardMetricsWithRegistry(reg)

	// ShardCount (gauge)
	m.SetShardCount(3)
	if v := testutil.ToFloat64(m.ShardCount); v != 3 {
		t.Errorf("shard_count: got %v, want 3", v)
	}

	// BlockHeight (gauge with labels)
	m.SetBlockHeight(1, 100)
	m.SetBlockHeight(2, 200)
	if v := testutil.ToFloat64(m.BlockHeight.WithLabelValues("1")); v != 100 {
		t.Errorf("block_height{shard_id=\"1\"}: got %v, want 100", v)
	}
	if v := testutil.ToFloat64(m.BlockHeight.WithLabelValues("2")); v != 200 {
		t.Errorf("block_height{shard_id=\"2\"}: got %v, want 200", v)
	}

	// CrossShardMessages (counter)
	m.IncCrossShardMessages()
	m.IncCrossShardMessages()
	m.IncCrossShardMessages()
	if v := testutil.ToFloat64(m.CrossShardMessages); v != 3 {
		t.Errorf("cross_shard_messages_total: got %v, want 3", v)
	}

	// PendingMessages (gauge with labels)
	m.SetPendingMessages(1, 5)
	m.SetPendingMessages(2, 10)
	if v := testutil.ToFloat64(m.PendingMessages.WithLabelValues("1")); v != 5 {
		t.Errorf("pending_messages{shard_id=\"1\"}: got %v, want 5", v)
	}
	if v := testutil.ToFloat64(m.PendingMessages.WithLabelValues("2")); v != 10 {
		t.Errorf("pending_messages{shard_id=\"2\"}: got %v, want 10", v)
	}

	// P2PMessages (counter with labels)
	m.IncP2PMessages("block")
	m.IncP2PMessages("block")
	m.IncP2PMessages("attestation")
	m.IncP2PMessages("cross_msg")
	if v := testutil.ToFloat64(m.P2PMessages.WithLabelValues("block")); v != 2 {
		t.Errorf("p2p_messages_total{type=\"block\"}: got %v, want 2", v)
	}
	if v := testutil.ToFloat64(m.P2PMessages.WithLabelValues("attestation")); v != 1 {
		t.Errorf("p2p_messages_total{type=\"attestation\"}: got %v, want 1", v)
	}
	if v := testutil.ToFloat64(m.P2PMessages.WithLabelValues("cross_msg")); v != 1 {
		t.Errorf("p2p_messages_total{type=\"cross_msg\"}: got %v, want 1", v)
	}

	// ValidatorCount (gauge with labels)
	m.SetValidatorCount(1, 4)
	m.SetValidatorCount(2, 7)
	if v := testutil.ToFloat64(m.ValidatorCount.WithLabelValues("1")); v != 4 {
		t.Errorf("validator_count{shard_id=\"1\"}: got %v, want 4", v)
	}
	if v := testutil.ToFloat64(m.ValidatorCount.WithLabelValues("2")); v != 7 {
		t.Errorf("validator_count{shard_id=\"2\"}: got %v, want 7", v)
	}

	// CommitmentLag (gauge with labels)
	m.SetCommitmentLag(1, 3)
	m.SetCommitmentLag(2, 0)
	if v := testutil.ToFloat64(m.CommitmentLag.WithLabelValues("1")); v != 3 {
		t.Errorf("commitment_lag{shard_id=\"1\"}: got %v, want 3", v)
	}
	if v := testutil.ToFloat64(m.CommitmentLag.WithLabelValues("2")); v != 0 {
		t.Errorf("commitment_lag{shard_id=\"2\"}: got %v, want 0", v)
	}

	// FinalizationDelay (histogram) — observing values should not panic.
	m.ObserveFinalizationDelay(1 * time.Second)
	m.ObserveFinalizationDelay(2 * time.Second)
	m.ObserveFinalizationDelay(500 * time.Millisecond)
}

// TestShardMetrics_NilSafe verifies all helper methods are nil-safe.
func TestShardMetrics_NilSafe(t *testing.T) {
	var m *ShardMetrics // nil

	// None of these should panic.
	m.SetShardCount(0)
	m.SetBlockHeight(1, 0)
	m.IncCrossShardMessages()
	m.SetPendingMessages(1, 0)
	m.ObserveFinalizationDelay(0)
	m.IncP2PMessages("block")
	m.SetValidatorCount(1, 0)
	m.SetCommitmentLag(1, 0)
}

// TestShardMetrics_ProviderMethods verifies the ShardMetricProvider methods
// return correct values for the alert manager.
func TestShardMetrics_ProviderMethods(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewShardMetricsWithRegistry(reg)

	// Set known values
	m.SetShardCount(5)
	m.IncCrossShardMessages()
	m.IncCrossShardMessages()
	m.IncCrossShardMessages()

	// Verify provider methods return the same values
	if v := m.ShardCountValue(); v != 5 {
		t.Errorf("ShardCountValue: got %v, want 5", v)
	}
	if v := m.CrossShardMessagesValue(); v != 3 {
		t.Errorf("CrossShardMessagesValue: got %v, want 3", v)
	}

	// Nil-safe: nil receiver should return 0 for all provider methods
	var nilM *ShardMetrics
	if v := nilM.ShardCountValue(); v != 0 {
		t.Errorf("nil ShardCountValue: got %v, want 0", v)
	}
	if v := nilM.CrossShardMessagesValue(); v != 0 {
		t.Errorf("nil CrossShardMessagesValue: got %v, want 0", v)
	}
}

// TestShardManager_SetMetrics verifies that SetMetrics + refreshMetricsLocked
// correctly update gauge values when shards are created/activated.
func TestShardManager_SetMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewShardMetricsWithRegistry(reg)

	sm := NewShardManager(nil)
	sm.SetMetrics(m)

	// Initially shard_count should be 0 (no shards).
	if v := testutil.ToFloat64(m.ShardCount); v != 0 {
		t.Errorf("initial shard_count: got %v, want 0", v)
	}

	// Create a shard — should refresh metrics (count still 0 because Initializing).
	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard: %v", err)
	}

	// Set up prerequisites and activate the shard.
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard: %v", err)
	}

	// After activation, shard_count should be 1.
	if v := testutil.ToFloat64(m.ShardCount); v != 1 {
		t.Errorf("post-activate shard_count: got %v, want 1", v)
	}

	// ValidatorCount for shard 1 should be 3.
	if v := testutil.ToFloat64(m.ValidatorCount.WithLabelValues("1")); v != 3 {
		t.Errorf("validator_count{shard_id=\"1\"}: got %v, want 3", v)
	}

	// Deactivate — shard_count should drop to 0.
	if err := sm.DeactivateShard(chain.ShardID()); err != nil {
		t.Fatalf("DeactivateShard: %v", err)
	}
	if v := testutil.ToFloat64(m.ShardCount); v != 0 {
		t.Errorf("post-deactivate shard_count: got %v, want 0", v)
	}
}
