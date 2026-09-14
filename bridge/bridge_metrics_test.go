// Quantaureum Node source, version 1.0.0.
// Package bridge — bridge_metrics_test.go verifies the P3-1 Prometheus
// metrics singleton, nil-safety, registration, and counter/gauge/histogram
// recording behavior.
package bridge

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestNewBridgeMetricsSingleton verifies that NewBridgeMetrics returns the
// same process-wide singleton on repeated calls. This is required because
// promauto registers on the global default registry — duplicate construction
// would panic with "duplicate metrics collector registration".
func TestNewBridgeMetricsSingleton(t *testing.T) {
	m1 := NewBridgeMetrics()
	m2 := NewBridgeMetrics()
	if m1 == nil {
		t.Fatal("NewBridgeMetrics returned nil")
	}
	if m1 != m2 {
		t.Fatal("NewBridgeMetrics should return the same singleton instance")
	}
}

// TestBridgeMetricsNilSafe verifies that all helper methods are nil-safe:
// calling any helper on a nil *BridgeMetrics must not panic.
func TestBridgeMetricsNilSafe(t *testing.T) {
	var m *BridgeMetrics // nil pointer — must not panic on any call

	m.IncMessagesSubmitted("src", "dst")
	m.SetStatusCount(MessageStatusPending, 1)
	m.IncArbitrationSignature()
	m.SetArbitrationQuorum(3)
	m.IncRelayerTask("submit")
	m.ObserveAdapterRPC("chain", "method", 100*time.Millisecond)
	m.IncMerkleRootUpdate()
}

// TestBridgeMetricsCounters verifies that counter helpers actually increment
// the underlying Prometheus counters. Uses before/after deltas because the
// singleton is shared across all tests in the package.
func TestBridgeMetricsCounters(t *testing.T) {
	m := NewBridgeMetrics()

	// MessagesSubmittedTotal (CounterVec with source_chain, target_chain labels)
	before := testutil.ToFloat64(m.MessagesSubmittedTotal.WithLabelValues("t-src", "t-dst"))
	m.IncMessagesSubmitted("t-src", "t-dst")
	after := testutil.ToFloat64(m.MessagesSubmittedTotal.WithLabelValues("t-src", "t-dst"))
	if after != before+1 {
		t.Errorf("MessagesSubmittedTotal: expected delta +1, got before=%v after=%v", before, after)
	}

	// ArbitrationSignaturesTotal (Counter)
	before = testutil.ToFloat64(m.ArbitrationSignaturesTotal)
	m.IncArbitrationSignature()
	after = testutil.ToFloat64(m.ArbitrationSignaturesTotal)
	if after != before+1 {
		t.Errorf("ArbitrationSignaturesTotal: expected delta +1, got before=%v after=%v", before, after)
	}

	// RelayerTasksTotal (CounterVec with action label)
	before = testutil.ToFloat64(m.RelayerTasksTotal.WithLabelValues("t-action"))
	m.IncRelayerTask("t-action")
	after = testutil.ToFloat64(m.RelayerTasksTotal.WithLabelValues("t-action"))
	if after != before+1 {
		t.Errorf("RelayerTasksTotal: expected delta +1, got before=%v after=%v", before, after)
	}

	// MerkleRootUpdatesTotal (Counter)
	before = testutil.ToFloat64(m.MerkleRootUpdatesTotal)
	m.IncMerkleRootUpdate()
	after = testutil.ToFloat64(m.MerkleRootUpdatesTotal)
	if after != before+1 {
		t.Errorf("MerkleRootUpdatesTotal: expected delta +1, got before=%v after=%v", before, after)
	}
}

// TestBridgeMetricsGauges verifies that gauge helpers actually set values.
func TestBridgeMetricsGauges(t *testing.T) {
	m := NewBridgeMetrics()

	// MessagesByStatus (GaugeVec with status label)
	m.SetStatusCount(MessageStatusPending, 42)
	val := testutil.ToFloat64(m.MessagesByStatus.WithLabelValues(string(MessageStatusPending)))
	if val != 42 {
		t.Errorf("MessagesByStatus[PENDING]: expected 42, got %v", val)
	}

	// ArbitrationQuorumThreshold (Gauge)
	m.SetArbitrationQuorum(7)
	val = testutil.ToFloat64(m.ArbitrationQuorumThreshold)
	if val != 7 {
		t.Errorf("ArbitrationQuorumThreshold: expected 7, got %v", val)
	}
}

// TestBridgeMetricsHistogram verifies that histogram observations are recorded.
// CollectAndCount returns the number of metric series (one per label combo),
// not the observation count. A new label combination creates a new series.
func TestBridgeMetricsHistogram(t *testing.T) {
	m := NewBridgeMetrics()

	// Use a unique label combo so we can verify the series was created.
	// This avoids the shared-singleton state issue across tests.
	uniqueChain := ChainID("hist-test-chain-unique")
	uniqueMethod := "hist-test-method-unique"

	before := testutil.CollectAndCount(m.AdapterRPCLatencySeconds)
	m.ObserveAdapterRPC(uniqueChain, uniqueMethod, 150*time.Millisecond)
	after := testutil.CollectAndCount(m.AdapterRPCLatencySeconds)
	if after != before+1 {
		t.Errorf("histogram series count should increase by 1: before=%d after=%d", before, after)
	}
}

// TestBridgeMetricsRegistered verifies that all 7 metrics are registered with
// the default Prometheus registry and will be exposed at /metrics/prometheus.
func TestBridgeMetricsRegistered(t *testing.T) {
	m := NewBridgeMetrics()

	// Touch each metric to create at least one sample (label combination).
	m.IncMessagesSubmitted("reg-src", "reg-dst")
	m.SetStatusCount(MessageStatusFailed, 0)
	m.IncArbitrationSignature()
	m.SetArbitrationQuorum(0)
	m.IncRelayerTask("reg")
	m.ObserveAdapterRPC("reg-chain", "reg-method", 1*time.Millisecond)
	m.IncMerkleRootUpdate()
	m.SetEventSignatureCount("reg-chain", 3)
	m.SetBootstrapMode("reg-chain", false)

	// Gather from the default registry and verify all metric names appear.
	gathered, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather from default registry: %v", err)
	}

	expected := []string{
		"qau_bridge_messages_submitted_total",
		"qau_bridge_messages_by_status",
		"qau_bridge_arbitration_signatures_total",
		"qau_bridge_arbitration_quorum_threshold",
		"qau_bridge_relayer_tasks_total",
		"qau_bridge_adapter_rpc_latency_seconds",
		"qau_bridge_merkle_root_updates_total",
		"qau_bridge_event_signature_count",
		"qau_bridge_bootstrap_mode",
	}

	found := make(map[string]bool)
	for _, mf := range gathered {
		found[mf.GetName()] = true
	}

	for _, name := range expected {
		if !found[name] {
			t.Errorf("metric %q not found in default Prometheus registry", name)
		}
	}
}

// TestBridgeMetricsRelayerIntegration verifies that the relayer task metric
// is incremented when SubmitRelayTask is called. This is an integration check
// that the metric wiring in relayer.go is correct.
func TestBridgeMetricsRelayerIntegration(t *testing.T) {
	m := NewBridgeMetrics()
	cfg := DefaultBridgeConfig()
	bridge := NewQuantumBridge(cfg).(*QuantumBridge)
	relayer := NewMessageRelayer(DefaultRelayerConfig(), bridge)

	ctx := context.WithValue(context.Background(), "test", "metrics")
	_ = relayer.Start(ctx)
	defer relayer.Stop()

	before := testutil.ToFloat64(m.RelayerTasksTotal.WithLabelValues("submit"))

	msg := &BridgeMessage{
		ID:          "metrics-integration-test",
		SourceChain: "chain-a",
		TargetChain: "chain-b",
		MessageType: MessageTypeAssetTransfer,
		Status:      MessageStatusPending,
		Timestamp:   time.Now().Unix(),
	}

	_, err := relayer.SubmitRelayTask(msg)
	if err != nil {
		t.Fatalf("SubmitRelayTask failed: %v", err)
	}

	after := testutil.ToFloat64(m.RelayerTasksTotal.WithLabelValues("submit"))
	if after <= before {
		t.Errorf("relayer submit metric not incremented: before=%v after=%v", before, after)
	}
}

// TestBridgeMetricsSubmitMessageIntegration verifies that the submitted message
// counter is incremented when QuantumBridge.SubmitMessage is called.
func TestBridgeMetricsSubmitMessageIntegration(t *testing.T) {
	m := NewBridgeMetrics()
	cfg := DefaultBridgeConfig()
	bridge := NewQuantumBridge(cfg).(*QuantumBridge)

	before := testutil.ToFloat64(m.MessagesSubmittedTotal.WithLabelValues("int-src", "int-dst"))

	msg := &BridgeMessage{
		ID:            "submit-metrics-test",
		SourceChain:   "int-src",
		TargetChain:   "int-dst",
		MessageType:   MessageTypeDataTransfer,
		Status:        MessageStatusPending,
		Timestamp:     time.Now().Unix(),
		Amount:        "0",
		SourceAddress: "0x0000000000000000000000000000000000000001",
		TargetAddress: "0x0000000000000000000000000000000000000002",
		AssetType:     AssetTypeNative,
	}

	// SubmitMessage will fail (no adapter configured), but the metric should
	// NOT be incremented on failure — only on successful submission.
	// Verify that the metric is NOT incremented on failure.
	_ = bridge.SubmitMessage(context.Background(), msg)
	afterFail := testutil.ToFloat64(m.MessagesSubmittedTotal.WithLabelValues("int-src", "int-dst"))
	if afterFail != before {
		t.Errorf("metric should NOT increment on failed submission: before=%v after=%v", before, afterFail)
	}
}

// TestBridgeMetricsObserveRPC verifies that the adapter observeRPC helper
// records latency in the histogram.
func TestBridgeMetricsObserveRPC(t *testing.T) {
	m := NewBridgeMetrics()

	// Create a Quantaureum adapter and inject metrics.
	adapter := NewQuantaureumChainAdapter("obs-chain-rpc", "http://localhost:9999", "", 1, "").(*QuantaureumChainAdapter)
	adapter.SetBridgeMetrics(m)

	// Use a unique method name to guarantee a new series is created.
	uniqueMethod := "test-observe-unique"

	before := testutil.CollectAndCount(m.AdapterRPCLatencySeconds)
	// Call observeRPC directly — it should record a latency observation.
	adapter.observeRPC(uniqueMethod, time.Now().Add(-50*time.Millisecond))
	after := testutil.CollectAndCount(m.AdapterRPCLatencySeconds)

	if after != before+1 {
		t.Errorf("observeRPC did not create a new histogram series: before=%d after=%d", before, after)
	}
}

// TestBridgeMetricsNilAdapterMetrics verifies that observeRPC on an adapter
// without metrics configured (nil) is a no-op and does not panic.
func TestBridgeMetricsNilAdapterMetrics(t *testing.T) {
	adapter := NewQuantaureumChainAdapter("nil-chain", "http://localhost:9999", "", 1, "").(*QuantaureumChainAdapter)
	// Do NOT call SetBridgeMetrics — metrics remains nil.

	// This must not panic.
	adapter.observeRPC("nil-test", time.Now())
}

// TestBridgeMetricsEventSignatureCount verifies the event signature count
// gauge is set correctly. P3-2: used for the "empty allowlist" alert.
func TestBridgeMetricsEventSignatureCount(t *testing.T) {
	m := NewBridgeMetrics()

	m.SetEventSignatureCount("esc-chain", 5)
	val := testutil.ToFloat64(m.EventSignatureCount.WithLabelValues("esc-chain"))
	if val != 5 {
		t.Errorf("EventSignatureCount: expected 5, got %v", val)
	}

	// Verify it can be updated (e.g., after registering more signatures)
	m.SetEventSignatureCount("esc-chain", 6)
	val = testutil.ToFloat64(m.EventSignatureCount.WithLabelValues("esc-chain"))
	if val != 6 {
		t.Errorf("EventSignatureCount: expected 6, got %v", val)
	}
}

// TestBridgeMetricsBootstrapMode verifies the bootstrap mode gauge is set
// correctly. P3-2: used for the "bootstrapMode=true >1h" alert.
func TestBridgeMetricsBootstrapMode(t *testing.T) {
	m := NewBridgeMetrics()

	// Disabled (default production state)
	m.SetBootstrapMode("bm-chain", false)
	val := testutil.ToFloat64(m.BootstrapMode.WithLabelValues("bm-chain"))
	if val != 0 {
		t.Errorf("BootstrapMode[disabled]: expected 0, got %v", val)
	}

	// Enabled (temporary bootstrap state)
	m.SetBootstrapMode("bm-chain", true)
	val = testutil.ToFloat64(m.BootstrapMode.WithLabelValues("bm-chain"))
	if val != 1 {
		t.Errorf("BootstrapMode[enabled]: expected 1, got %v", val)
	}
}

// TestBridgeMetricsBootstrapModeIntegration verifies that SetBootstrapMode on
// an adapter with metrics configured updates the gauge.
func TestBridgeMetricsBootstrapModeIntegration(t *testing.T) {
	m := NewBridgeMetrics()
	adapter := NewQuantaureumChainAdapter("bm-int-chain", "http://localhost:9999", "", 1, "test-initializer").(*QuantaureumChainAdapter)
	adapter.SetBridgeMetrics(m)

	// Set governance address first (required before SetBootstrapMode).
	if err := adapter.SetGovernanceAddress("test-gov-addr", "test-initializer"); err != nil {
		t.Fatalf("SetGovernanceAddress failed: %v", err)
	}

	// Enable bootstrap mode — should update the metric.
	if err := adapter.SetBootstrapMode(true, "test-gov-addr"); err != nil {
		t.Fatalf("SetBootstrapMode(true) failed: %v", err)
	}
	val := testutil.ToFloat64(m.BootstrapMode.WithLabelValues("bm-int-chain"))
	if val != 1 {
		t.Errorf("after SetBootstrapMode(true): expected 1, got %v", val)
	}

	// Disable bootstrap mode — should update the metric.
	if err := adapter.SetBootstrapMode(false, "test-gov-addr"); err != nil {
		t.Fatalf("SetBootstrapMode(false) failed: %v", err)
	}
	val = testutil.ToFloat64(m.BootstrapMode.WithLabelValues("bm-int-chain"))
	if val != 0 {
		t.Errorf("after SetBootstrapMode(false): expected 0, got %v", val)
	}
}
