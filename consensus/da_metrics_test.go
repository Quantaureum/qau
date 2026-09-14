// Quantaureum Node source, version 1.0.0.
package consensus

// DAMetrics tests (P3-1, 2026-07-15)
//
// Verifies that:
//   1. NewDAMetricsWithRegistry registers all 9 metrics without panic.
//   2. All convenience helpers correctly update metric values.
//   3. All DAMetricProvider Value() methods correctly read back values.
//   4. Nil receiver safety: calling helpers on a nil *DAMetrics does not panic.
//   5. SetDAMetrics on DAAttestationCollector wires up the counters so
//      SubmitAttestation rejections increment the correct counters.

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/quantaureum/qau/encoding"
)

// newTestDAMetrics creates a DAMetrics instance with a fresh registry for
// isolated testing (no "duplicate metric" panic).
func newTestDAMetrics(t *testing.T) *DAMetrics {
	t.Helper()
	return NewDAMetricsWithRegistry(prometheus.NewRegistry())
}

// readGauge reads a Prometheus gauge value for test assertions.
func readGauge(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	pb := &dto.Metric{}
	if err := g.(prometheus.Metric).Write(pb); err != nil {
		t.Fatalf("gauge.Write failed: %v", err)
	}
	if pb.Gauge == nil {
		t.Fatalf("metric is not a gauge")
	}
	return pb.Gauge.GetValue()
}

// readCounter reads a Prometheus counter value for test assertions.
func readCounter(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	pb := &dto.Metric{}
	if err := c.(prometheus.Metric).Write(pb); err != nil {
		t.Fatalf("counter.Write failed: %v", err)
	}
	if pb.Counter == nil {
		t.Fatalf("metric is not a counter")
	}
	return pb.Counter.GetValue()
}

// TestDAMetrics_Registration verifies that all 9 metrics are registered
// without panic and start at their zero values.
func TestDAMetrics_Registration(t *testing.T) {
	m := newTestDAMetrics(t)
	if m == nil {
		t.Fatal("NewDAMetricsWithRegistry returned nil")
	}

	// Gauges should start at 0.
	if v := readGauge(t, m.CommitteeAvailable); v != 0 {
		t.Errorf("CommitteeAvailable initial = %v, want 0", v)
	}
	if v := readGauge(t, m.SamplingConfidence); v != 0 {
		t.Errorf("SamplingConfidence initial = %v, want 0", v)
	}
	if v := readGauge(t, m.AttestationCount); v != 0 {
		t.Errorf("AttestationCount initial = %v, want 0", v)
	}
	if v := readGauge(t, m.BlobStorageSize); v != 0 {
		t.Errorf("BlobStorageSize initial = %v, want 0", v)
	}
	if v := readGauge(t, m.BlobEntries); v != 0 {
		t.Errorf("BlobEntries initial = %v, want 0", v)
	}

	// Counters should start at 0.
	if v := readCounter(t, m.GCCycles); v != 0 {
		t.Errorf("GCCycles initial = %v, want 0", v)
	}
	if v := readCounter(t, m.SamplingFailures); v != 0 {
		t.Errorf("SamplingFailures initial = %v, want 0", v)
	}
	if v := readCounter(t, m.VerifierRejections); v != 0 {
		t.Errorf("VerifierRejections initial = %v, want 0", v)
	}
	if v := readCounter(t, m.AttestationCapRejections); v != 0 {
		t.Errorf("AttestationCapRejections initial = %v, want 0", v)
	}

	// P3-3: CommitteeSize gauge should start at 0.
	if v := readGauge(t, m.CommitteeSize); v != 0 {
		t.Errorf("CommitteeSize initial = %v, want 0", v)
	}
}

// TestDAMetrics_SetCommitteeAvailable verifies the gauge is set to 1 or 0.
func TestDAMetrics_SetCommitteeAvailable(t *testing.T) {
	m := newTestDAMetrics(t)

	m.SetCommitteeAvailable(true)
	if v := readGauge(t, m.CommitteeAvailable); v != 1 {
		t.Errorf("after SetCommitteeAvailable(true) = %v, want 1", v)
	}
	if v := m.CommitteeAvailableValue(); v != 1 {
		t.Errorf("CommitteeAvailableValue() = %v, want 1", v)
	}

	m.SetCommitteeAvailable(false)
	if v := readGauge(t, m.CommitteeAvailable); v != 0 {
		t.Errorf("after SetCommitteeAvailable(false) = %v, want 0", v)
	}
	if v := m.CommitteeAvailableValue(); v != 0 {
		t.Errorf("CommitteeAvailableValue() = %v, want 0", v)
	}
}

// TestDAMetrics_SetSamplingConfidence verifies the confidence gauge.
func TestDAMetrics_SetSamplingConfidence(t *testing.T) {
	m := newTestDAMetrics(t)

	m.SetSamplingConfidence(0.95)
	if v := readGauge(t, m.SamplingConfidence); v != 0.95 {
		t.Errorf("SamplingConfidence = %v, want 0.95", v)
	}
	if v := m.SamplingConfidenceValue(); v != 0.95 {
		t.Errorf("SamplingConfidenceValue() = %v, want 0.95", v)
	}
}

// TestDAMetrics_SetAttestationCount verifies the count gauge.
func TestDAMetrics_SetAttestationCount(t *testing.T) {
	m := newTestDAMetrics(t)

	m.SetAttestationCount(42)
	if v := readGauge(t, m.AttestationCount); v != 42 {
		t.Errorf("AttestationCount = %v, want 42", v)
	}
	if v := m.AttestationCountValue(); v != 42 {
		t.Errorf("AttestationCountValue() = %v, want 42", v)
	}
}

// TestDAMetrics_SetBlobStorageStats verifies both gauges are set from the
// (entryCount, totalSize) tuple.
func TestDAMetrics_SetBlobStorageStats(t *testing.T) {
	m := newTestDAMetrics(t)

	m.SetBlobStorageStats(100, 1024*1024)
	if v := readGauge(t, m.BlobEntries); v != 100 {
		t.Errorf("BlobEntries = %v, want 100", v)
	}
	if v := readGauge(t, m.BlobStorageSize); v != 1024*1024 {
		t.Errorf("BlobStorageSize = %v, want %v", v, 1024*1024)
	}
	if v := m.BlobStorageSizeValue(); v != 1024*1024 {
		t.Errorf("BlobStorageSizeValue() = %v, want %v", v, 1024*1024)
	}
}

// TestDAMetrics_IncCounters verifies all counter increment helpers.
func TestDAMetrics_IncCounters(t *testing.T) {
	m := newTestDAMetrics(t)

	// Increment each counter 3 times.
	for i := 0; i < 3; i++ {
		m.IncGCCycles()
		m.IncSamplingFailures()
		m.IncVerifierRejections()
		m.IncAttestationCapRejections()
	}

	if v := readCounter(t, m.GCCycles); v != 3 {
		t.Errorf("GCCycles = %v, want 3", v)
	}
	if v := readCounter(t, m.SamplingFailures); v != 3 {
		t.Errorf("SamplingFailures = %v, want 3", v)
	}
	if v := readCounter(t, m.VerifierRejections); v != 3 {
		t.Errorf("VerifierRejections = %v, want 3", v)
	}
	if v := readCounter(t, m.AttestationCapRejections); v != 3 {
		t.Errorf("AttestationCapRejections = %v, want 3", v)
	}
	if v := m.VerifierRejectionsValue(); v != 3 {
		t.Errorf("VerifierRejectionsValue() = %v, want 3", v)
	}
}

// TestDAMetrics_NilSafe verifies that calling any helper on a nil
// *DAMetrics does not panic. This is critical because callers invoke these
// methods unconditionally even when DA metrics are disabled.
func TestDAMetrics_NilSafe(t *testing.T) {
	var m *DAMetrics // nil pointer

	// None of these should panic.
	m.SetCommitteeAvailable(true)
	m.SetSamplingConfidence(0.95)
	m.SetAttestationCount(42)
	m.SetBlobStorageStats(100, 1024)
	m.IncGCCycles()
	m.IncSamplingFailures()
	m.IncVerifierRejections()
	m.IncAttestationCapRejections()
	m.SetCommitteeSize(512) // P3-3

	// Value() methods should return 0 on nil receiver.
	if v := m.CommitteeAvailableValue(); v != 0 {
		t.Errorf("nil CommitteeAvailableValue() = %v, want 0", v)
	}
	if v := m.SamplingConfidenceValue(); v != 0 {
		t.Errorf("nil SamplingConfidenceValue() = %v, want 0", v)
	}
	if v := m.AttestationCountValue(); v != 0 {
		t.Errorf("nil AttestationCountValue() = %v, want 0", v)
	}
	if v := m.BlobStorageSizeValue(); v != 0 {
		t.Errorf("nil BlobStorageSizeValue() = %v, want 0", v)
	}
	if v := m.VerifierRejectionsValue(); v != 0 {
		t.Errorf("nil VerifierRejectionsValue() = %v, want 0", v)
	}
	if v := m.CommitteeSizeValue(); v != 0 { // P3-3
		t.Errorf("nil CommitteeSizeValue() = %v, want 0", v)
	}
}

// TestDAMetrics_SetCommitteeSize verifies the committee_size gauge is set
// correctly and readable via CommitteeSizeValue(). P3-3 (2026-07-15).
func TestDAMetrics_SetCommitteeSize(t *testing.T) {
	m := newTestDAMetrics(t)

	m.SetCommitteeSize(512)
	if v := readGauge(t, m.CommitteeSize); v != 512 {
		t.Errorf("after SetCommitteeSize(512) = %v, want 512", v)
	}
	if v := m.CommitteeSizeValue(); v != 512 {
		t.Errorf("CommitteeSizeValue() = %v, want 512", v)
	}

	m.SetCommitteeSize(100)
	if v := m.CommitteeSizeValue(); v != 100 {
		t.Errorf("CommitteeSizeValue() after reset = %v, want 100", v)
	}
}

// TestDAAttestationCollector_SetDAMetrics_VerifierRejection verifies that
// SubmitAttestation increments verifier_rejections_total when the verifier
// rejects an attestation.
func TestDAAttestationCollector_SetDAMetrics_VerifierRejection(t *testing.T) {
	metrics := newTestDAMetrics(t)
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(4)
	// Verifier that always rejects.
	c.SetAttestationVerifier(func(_ *encoding.DASAttestation) error {
		return fmt.Errorf("simulated verification failure")
	})
	c.SetDAMetrics(metrics)

	att := &encoding.DASAttestation{
		Slot:           1,
		ValidatorIndex: 0,
	}
	err := c.SubmitAttestation(att)
	if err == nil {
		t.Fatal("SubmitAttestation should have failed")
	}

	if v := readCounter(t, metrics.VerifierRejections); v != 1 {
		t.Errorf("VerifierRejections = %v, want 1", v)
	}
}

// TestDAAttestationCollector_SetDAMetrics_VerifierNil verifies that
// SubmitAttestation increments verifier_rejections_total when the verifier
// is not configured (fail-closed path).
func TestDAAttestationCollector_SetDAMetrics_VerifierNil(t *testing.T) {
	metrics := newTestDAMetrics(t)
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(4)
	// Intentionally do NOT call SetAttestationVerifier — fail-closed.
	c.SetDAMetrics(metrics)

	att := &encoding.DASAttestation{
		Slot:           1,
		ValidatorIndex: 0,
	}
	err := c.SubmitAttestation(att)
	if err == nil {
		t.Fatal("SubmitAttestation should have failed (verifier not configured)")
	}

	if v := readCounter(t, metrics.VerifierRejections); v != 1 {
		t.Errorf("VerifierRejections = %v, want 1 (fail-closed path)", v)
	}
}

// TestDAAttestationCollector_SetDAMetrics_CapRejection verifies that
// SubmitAttestation increments attestation_cap_rejections_total when the
// per-slot cap is reached.
//
// The cap is min(DAMaxAttestationsPerSlot=512, committeeSize). The cap
// rejection path only fires when committeeSize > DAMaxAttestationsPerSlot
// AND more than 512 unique validators have submitted — otherwise the range
// check (ValidatorIndex < committeeSize) fires first. This test uses
// committeeSize=600 and submits 513 attestations to trigger the cap.
func TestDAAttestationCollector_SetDAMetrics_CapRejection(t *testing.T) {
	metrics := newTestDAMetrics(t)
	c := NewDAAttestationCollector()
	// committeeSize > DAMaxAttestationsPerSlot (512) so the cap is 512,
	// allowing validators 0..599 to pass the range check while the cap
	// rejects the 513th unique submission.
	c.SetCommitteeSize(600)
	c.SetAttestationVerifier(func(_ *encoding.DASAttestation) error {
		return nil // always accept
	})
	c.SetDAMetrics(metrics)

	// Submit 512 attestations (fills the cap of DAMaxAttestationsPerSlot).
	for i := 0; i < DAMaxAttestationsPerSlot; i++ {
		att := &encoding.DASAttestation{
			Slot:           1,
			ValidatorIndex: i,
		}
		if err := c.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation %d failed: %v", i, err)
		}
	}

	// 513th submission from a new validator (index 512, < 600 so passes
	// range check) should be rejected because the cap is full.
	att := &encoding.DASAttestation{
		Slot:           1,
		ValidatorIndex: DAMaxAttestationsPerSlot, // 512
	}
	err := c.SubmitAttestation(att)
	if err == nil {
		t.Fatal("SubmitAttestation should have failed (cap reached)")
	}

	if v := readCounter(t, metrics.AttestationCapRejections); v != 1 {
		t.Errorf("AttestationCapRejections = %v, want 1", v)
	}
}

// TestDAAttestationCollector_NoMetricsNoPanic verifies that SubmitAttestation
// works correctly when metrics are not set (existing tests that don't set
// metrics continue to work — all DAMetrics methods are nil-safe).
func TestDAAttestationCollector_NoMetricsNoPanic(t *testing.T) {
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(4)
	c.SetAttestationVerifier(func(_ *encoding.DASAttestation) error {
		return nil
	})
	// Intentionally do NOT call SetDAMetrics — c.metrics is nil.

	att := &encoding.DASAttestation{
		Slot:           1,
		ValidatorIndex: 0,
	}
	// Should not panic even though c.metrics is nil.
	err := c.SubmitAttestation(att)
	if err != nil {
		t.Fatalf("SubmitAttestation failed: %v", err)
	}

	// Verifier-rejection path also should not panic with nil metrics.
	c2 := NewDAAttestationCollector()
	c2.SetCommitteeSize(4)
	c2.SetAttestationVerifier(func(_ *encoding.DASAttestation) error {
		return fmt.Errorf("rejection")
	})
	// No SetDAMetrics call.
	err = c2.SubmitAttestation(att)
	if err == nil {
		t.Fatal("expected rejection error")
	}
}
