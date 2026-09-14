// Quantaureum Node source, version 1.0.0.
package consensus

// DA Metrics — P3-1 (2026-07-15)
//
// Exposes 9 Prometheus metrics for DA (Data Availability) committee and
// danksharding engine monitoring. Uses the official prometheus/client_golang
// library via promauto, so metrics auto-register with the default Prometheus
// registry and are exposed through the existing /metrics/prometheus endpoint
// (metrics/server.go).
//
// Naming follows the project convention: namespace="qau", subsystem="da".
// Counters use the _total suffix per Prometheus best practices.
//
// Metric → spec mapping:
//   da_committee_available          → qau_da_committee_available           (gauge, 0/1)
//   da_sampling_confidence          → qau_da_sampling_confidence           (gauge, 0..1)
//   da_attestation_count            → qau_da_attestation_count             (gauge)
//   da_blob_storage_size_bytes      → qau_da_blob_storage_size_bytes       (gauge)
//   da_blob_entries                 → qau_da_blob_entries                  (gauge)
//   da_gc_cycles_total              → qau_da_gc_cycles_total               (counter)
//   da_sampling_failures_total      → qau_da_sampling_failures_total       (counter)
//   da_verifier_rejections_total    → qau_da_verifier_rejections_total     (counter)
//   da_attestation_cap_rejections   → qau_da_attestation_cap_rejections_total (counter)
//   da_committee_size               → qau_da_committee_size                 (gauge, P3-3)
//
// DoD (04-da-committee.md P3-1) requires:
//   - DA committee availability           ✅ da_committee_available
//   - sampling confidence                 ✅ da_sampling_confidence
//   - attestation collection count        ✅ da_attestation_count
//   - blob storage size                   ✅ da_blob_storage_size_bytes (+ da_blob_entries)
//   - GC frequency                        ✅ da_gc_cycles_total
// Additional counters (sampling failures, verifier rejections, cap rejections)
// support P3-2 structured logging and P3-3 alert rules.
// P3-3 adds da_committee_size to compute attestation collection rate
// (attestation_count / committee_size) for the da_attestation_collection_low rule.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

const (
	daNamespace = "qau"
	daSubsystem = "da"
)

// DAMetrics holds all Prometheus metrics for the DA committee and
// danksharding engine. P3-1 (2026-07-15).
//
// All fields are nil-safe: the convenience methods (SetCommitteeAvailable,
// IncSamplingFailures, etc.) early-return when m is nil, so callers can
// invoke them unconditionally even when DA metrics are disabled.
type DAMetrics struct {
	// da_committee_available: 1 when IsDACommitteeAvailable()=true, 0 otherwise.
	// Updated by the metrics refresh loop in node.go (like NodeMetrics).
	CommitteeAvailable prometheus.Gauge

	// da_sampling_confidence: most recent DAS sampling confidence (0.0..1.0).
	// Set by DankshardingEngine after each Sample() call.
	SamplingConfidence prometheus.Gauge

	// da_attestation_count: current number of collected attestations for the
	// latest slot. Set by the metrics refresh loop.
	AttestationCount prometheus.Gauge

	// da_blob_storage_size_bytes: total bytes used by the blob storage.
	// Set by the metrics refresh loop from BlobStorage.Stats().
	BlobStorageSize prometheus.Gauge

	// da_blob_entries: number of entries (cells) currently in blob storage.
	// Set by the metrics refresh loop from BlobStorage.Stats().
	BlobEntries prometheus.Gauge

	// da_gc_cycles_total: cumulative blob GC cycles run. Incremented by the
	// BlobGarbageCollector on each tick (P3-1 DoD: "GC frequency").
	GCCycles prometheus.Counter

	// da_sampling_failures_total: cumulative DAS sampling failures. Incremented
	// by DankshardingEngine.VerifyBlockDAAvailability on error.
	SamplingFailures prometheus.Counter

	// da_verifier_rejections_total: cumulative attestations rejected by the
	// verifier (signature/committee membership check). Incremented by
	// DAAttestationCollector.SubmitAttestation when attestationVerifier
	// returns an error.
	VerifierRejections prometheus.Counter

	// da_attestation_cap_rejections_total: cumulative attestations rejected
	// because the per-slot cap was reached. Incremented by
	// DAAttestationCollector.SubmitAttestation when the cap is exceeded.
	AttestationCapRejections prometheus.Counter

	// da_committee_size: configured DA committee size. P3-3 (2026-07-15).
	// Used together with da_attestation_count to compute the attestation
	// collection rate (attestation_count / committee_size) for the
	// da_attestation_collection_low alert rule (fires when rate < 0.66).
	CommitteeSize prometheus.Gauge
}

// NewDAMetrics creates and registers all DA Prometheus metrics with the
// default Prometheus registry. Metrics are automatically exposed through
// promhttp.Handler() (the /metrics/prometheus endpoint in metrics/server.go).
//
// NOTE: This function panics if called more than once (promauto registers
// with the global default registry, which rejects duplicates). For testing,
// use NewDAMetricsWithRegistry with a fresh prometheus.NewRegistry().
func NewDAMetrics() *DAMetrics {
	return NewDAMetricsWithRegistry(prometheus.DefaultRegisterer)
}

// NewDAMetricsWithRegistry creates and registers all DA Prometheus metrics
// with the given registerer. Pass prometheus.DefaultRegisterer for production,
// or a fresh prometheus.NewRegistry() for isolated tests.
func NewDAMetricsWithRegistry(reg prometheus.Registerer) *DAMetrics {
	factory := promauto.With(reg)

	return &DAMetrics{
		CommitteeAvailable: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "committee_available",
			Help:      "DA committee availability: 1 when IsDACommitteeAvailable()=true, 0 otherwise",
		}),

		SamplingConfidence: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "sampling_confidence",
			Help:      "Most recent DAS sampling confidence level (0.0..1.0)",
		}),

		AttestationCount: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "attestation_count",
			Help:      "Current number of collected DA attestations for the latest slot",
		}),

		BlobStorageSize: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "blob_storage_size_bytes",
			Help:      "Total bytes used by blob storage",
		}),

		BlobEntries: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "blob_entries",
			Help:      "Number of entries currently stored in blob storage",
		}),

		GCCycles: factory.NewCounter(prometheus.CounterOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "gc_cycles_total",
			Help:      "Total number of blob garbage collection cycles run",
		}),

		SamplingFailures: factory.NewCounter(prometheus.CounterOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "sampling_failures_total",
			Help:      "Total number of DAS sampling failures",
		}),

		VerifierRejections: factory.NewCounter(prometheus.CounterOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "verifier_rejections_total",
			Help:      "Total DA attestations rejected by the signature/committee verifier",
		}),

		AttestationCapRejections: factory.NewCounter(prometheus.CounterOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "attestation_cap_rejections_total",
			Help:      "Total DA attestations rejected because per-slot cap was reached",
		}),

		CommitteeSize: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: daNamespace,
			Subsystem: daSubsystem,
			Name:      "committee_size",
			Help:      "Configured DA committee size (used to compute attestation collection rate)",
		}),
	}
}

// --- Convenience helpers ---

// SetCommitteeAvailable sets the committee_available gauge (0 or 1).
func (m *DAMetrics) SetCommitteeAvailable(available bool) {
	if m == nil {
		return
	}
	if available {
		m.CommitteeAvailable.Set(1)
	} else {
		m.CommitteeAvailable.Set(0)
	}
}

// SetSamplingConfidence sets the sampling_confidence gauge (0.0..1.0).
func (m *DAMetrics) SetSamplingConfidence(confidence float64) {
	if m == nil {
		return
	}
	m.SamplingConfidence.Set(confidence)
}

// SetAttestationCount sets the attestation_count gauge.
func (m *DAMetrics) SetAttestationCount(count int) {
	if m == nil {
		return
	}
	m.AttestationCount.Set(float64(count))
}

// SetBlobStorageStats sets both blob_storage_size_bytes and blob_entries
// gauges from the (entryCount, totalSize) tuple returned by BlobStorage.Stats().
func (m *DAMetrics) SetBlobStorageStats(entryCount int, totalSize int64) {
	if m == nil {
		return
	}
	m.BlobEntries.Set(float64(entryCount))
	m.BlobStorageSize.Set(float64(totalSize))
}

// IncGCCycles increments the gc_cycles_total counter by 1.
func (m *DAMetrics) IncGCCycles() {
	if m == nil {
		return
	}
	m.GCCycles.Inc()
}

// IncSamplingFailures increments the sampling_failures_total counter by 1.
func (m *DAMetrics) IncSamplingFailures() {
	if m == nil {
		return
	}
	m.SamplingFailures.Inc()
}

// IncVerifierRejections increments the verifier_rejections_total counter by 1.
func (m *DAMetrics) IncVerifierRejections() {
	if m == nil {
		return
	}
	m.VerifierRejections.Inc()
}

// IncAttestationCapRejections increments the attestation_cap_rejections_total
// counter by 1.
func (m *DAMetrics) IncAttestationCapRejections() {
	if m == nil {
		return
	}
	m.AttestationCapRejections.Inc()
}

// SetCommitteeSize sets the committee_size gauge. P3-3 (2026-07-15).
// Used together with attestation_count to compute the attestation collection
// rate for the da_attestation_collection_low alert rule.
func (m *DAMetrics) SetCommitteeSize(size int) {
	if m == nil {
		return
	}
	m.CommitteeSize.Set(float64(size))
}

// --- DAMetricProvider implementation (P3-3) ---
//
// These methods read the current Prometheus metric values for the alert
// manager. The metrics package defines the DAMetricProvider interface;
// *DAMetrics satisfies it without the metrics package needing to import
// consensus (dependency injection via interface).

// daReadMetricValue extracts the float64 value from a Prometheus Metric.
// For gauges it returns the current value; for counters it returns the
// cumulative count. Returns 0 on nil metric or write error.
func daReadMetricValue(m prometheus.Metric) float64 {
	if m == nil {
		return 0
	}
	pb := &dto.Metric{}
	if err := m.Write(pb); err != nil {
		return 0
	}
	if pb.Gauge != nil {
		return pb.Gauge.GetValue()
	}
	if pb.Counter != nil {
		return pb.Counter.GetValue()
	}
	return 0
}

// CommitteeAvailableValue returns the current committee_available value
// (1=available, 0=unavailable). Used by the "da_committee_unavailable" alert
// rule — fires when value < 0.5 (i.e., unavailable).
func (m *DAMetrics) CommitteeAvailableValue() float64 {
	if m == nil {
		return 0
	}
	return daReadMetricValue(m.CommitteeAvailable)
}

// SamplingConfidenceValue returns the current sampling_confidence value
// (0.0..1.0). Used by the "da_sampling_confidence_low" alert rule — fires
// when (1 - confidence) > 0.05, i.e., confidence < 0.95.
func (m *DAMetrics) SamplingConfidenceValue() float64 {
	if m == nil {
		return 0
	}
	return daReadMetricValue(m.SamplingConfidence)
}

// AttestationCountValue returns the current attestation_count value.
func (m *DAMetrics) AttestationCountValue() float64 {
	if m == nil {
		return 0
	}
	return daReadMetricValue(m.AttestationCount)
}

// BlobStorageSizeValue returns the current blob_storage_size_bytes value.
func (m *DAMetrics) BlobStorageSizeValue() float64 {
	if m == nil {
		return 0
	}
	return daReadMetricValue(m.BlobStorageSize)
}

// VerifierRejectionsValue returns the cumulative verifier_rejections_total.
// Used by the "da_verifier_rejections" alert rule — any non-zero value is
// suspicious (could indicate an attack or misconfigured validator).
func (m *DAMetrics) VerifierRejectionsValue() float64 {
	if m == nil {
		return 0
	}
	return daReadMetricValue(m.VerifierRejections)
}

// CommitteeSizeValue returns the configured committee_size. P3-3 (2026-07-15).
// Used by the "da_attestation_collection_low" alert rule to compute the
// attestation collection rate: attestation_count / committee_size. The alert
// fires when (1 - rate) > 0.34, i.e., rate < 0.66.
func (m *DAMetrics) CommitteeSizeValue() float64 {
	if m == nil {
		return 0
	}
	return daReadMetricValue(m.CommitteeSize)
}
