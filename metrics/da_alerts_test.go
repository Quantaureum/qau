// Quantaureum Node source, version 1.0.0.
package metrics

// DA alert rule tests (P3-1/P3-3, 2026-07-15)
//
// Verifies that the 4 DA alert rules are registered, evaluate correctly
// against a DAMetricProvider, and fire when thresholds are exceeded.
// Mirrors the rollup_alerts_test.go pattern.

import (
	"testing"
)

// fakeDAProvider is a test double for DAMetricProvider.
type fakeDAProvider struct {
	committeeAvailable float64
	samplingConfidence float64
	attestationCount   float64
	blobStorageSize    float64
	verifierRejections float64
	committeeSize      float64
}

func (f *fakeDAProvider) CommitteeAvailableValue() float64 { return f.committeeAvailable }
func (f *fakeDAProvider) SamplingConfidenceValue() float64 { return f.samplingConfidence }
func (f *fakeDAProvider) AttestationCountValue() float64   { return f.attestationCount }
func (f *fakeDAProvider) BlobStorageSizeValue() float64    { return f.blobStorageSize }
func (f *fakeDAProvider) VerifierRejectionsValue() float64 { return f.verifierRejections }
func (f *fakeDAProvider) CommitteeSizeValue() float64      { return f.committeeSize }

// isDAAlert returns true if the alert name starts with "da_".
func isDAAlert(name string) bool {
	return len(name) >= 3 && name[:3] == "da_"
}

// TestDAAlertRules_NoProvider verifies that all DA alert rules return 0
// (no alert) when no provider is set. This is the default state — DA
// metrics are not enabled on every node (testnet/devnet may disable DA).
func TestDAAlertRules_NoProvider(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	alerts := am.Check(m)
	for _, a := range alerts {
		if isDAAlert(a.Name) {
			t.Errorf("DA alert %q fired without provider (value=%v)", a.Name, a.Value)
		}
	}
}

// TestDAAlertRules_Healthy verifies that no DA alerts fire when the
// committee is available, sampling confidence is high, blob storage is
// small, and no verifier rejections occurred.
func TestDAAlertRules_Healthy(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 1,    // available
		samplingConfidence: 0.99, // > 0.95
		blobStorageSize:    0,    // small
		verifierRejections: 0,    // none
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if isDAAlert(a.Name) {
			t.Errorf("DA alert %q fired on healthy state (value=%v)", a.Name, a.Value)
		}
	}
}

// TestDAAlertRules_CommitteeUnavailable verifies that da_committee_unavailable
// fires when CommitteeAvailableValue()=0.
func TestDAAlertRules_CommitteeUnavailable(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 0, // unavailable
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "da_committee_unavailable" {
			found = true
			if a.Level != AlertCritical {
				t.Errorf("expected AlertCritical, got %v", a.Level)
			}
		}
	}
	if !found {
		t.Errorf("da_committee_unavailable did not fire when committee unavailable")
	}
}

// TestDAAlertRules_SamplingConfidenceLow verifies that
// da_sampling_confidence_low fires when confidence < 0.95.
func TestDAAlertRules_SamplingConfidenceLow(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 1,
		samplingConfidence: 0.80, // < 0.95
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "da_sampling_confidence_low" {
			found = true
		}
	}
	if !found {
		t.Errorf("da_sampling_confidence_low did not fire when confidence=0.80")
	}
}

// TestDAAlertRules_SamplingConfidenceColdStart verifies that
// da_sampling_confidence_low does NOT fire when confidence=0 (cold start,
// no sampling has run yet).
func TestDAAlertRules_SamplingConfidenceColdStart(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 1,
		samplingConfidence: 0, // cold start
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "da_sampling_confidence_low" {
			t.Errorf("da_sampling_confidence_low fired on cold start (confidence=0)")
		}
	}
}

// TestDAAlertRules_BlobStorageLarge verifies that da_blob_storage_large
// fires when blob storage > 10 GB.
func TestDAAlertRules_BlobStorageLarge(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	// 15 GB in bytes
	fifteenGB := float64(15) * 1024 * 1024 * 1024
	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 1,
		blobStorageSize:    fifteenGB,
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "da_blob_storage_large" {
			found = true
		}
	}
	if !found {
		t.Errorf("da_blob_storage_large did not fire when blob storage=15GB")
	}
}

// TestDAAlertRules_VerifierRejections verifies that da_verifier_rejections
// fires when at least one verifier rejection occurred.
func TestDAAlertRules_VerifierRejections(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 1,
		verifierRejections: 3, // any non-zero
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "da_verifier_rejections" {
			found = true
		}
	}
	if !found {
		t.Errorf("da_verifier_rejections did not fire when count=3")
	}
}

// TestDAAlertRules_AllFire verifies that all 5 DA alerts fire simultaneously
// when every metric crosses its threshold. P3-3 (2026-07-15): includes the
// new da_attestation_collection_low rule.
func TestDAAlertRules_AllFire(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	fifteenGB := float64(15) * 1024 * 1024 * 1024
	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 0,    // unavailable
		samplingConfidence: 0.50, // < 0.95
		blobStorageSize:    fifteenGB,
		verifierRejections: 1,
		committeeSize:      100, // configured
		attestationCount:   30,  // 30/100 = 30% < 66%
	})

	alerts := am.Check(m)
	daAlerts := make(map[string]bool)
	for _, a := range alerts {
		if isDAAlert(a.Name) {
			daAlerts[a.Name] = true
		}
	}

	expected := []string{
		"da_committee_unavailable",
		"da_sampling_confidence_low",
		"da_blob_storage_large",
		"da_verifier_rejections",
		"da_attestation_collection_low",
	}
	for _, name := range expected {
		if !daAlerts[name] {
			t.Errorf("expected alert %q to fire, but it did not", name)
		}
	}
}

// TestDAAlertRules_AttestationCollectionLow verifies that
// da_attestation_collection_low fires when attestation_count / committee_size
// < 0.66. P3-3 DoD: "attestation collection rate < 66%".
func TestDAAlertRules_AttestationCollectionLow(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	// Fault injection: committee=100, attestations=50 → rate=0.50 < 0.66.
	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 1,
		committeeSize:      100,
		attestationCount:   50, // 50% < 66%
	})

	alerts := am.Check(m)
	found := false
	for _, a := range alerts {
		if a.Name == "da_attestation_collection_low" {
			found = true
			if a.Level != AlertWarning {
				t.Errorf("expected AlertWarning, got %v", a.Level)
			}
		}
	}
	if !found {
		t.Errorf("da_attestation_collection_low did not fire when rate=0.50")
	}
}

// TestDAAlertRules_AttestationCollectionHealthy verifies that
// da_attestation_collection_low does NOT fire when rate >= 0.66.
func TestDAAlertRules_AttestationCollectionHealthy(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	// Healthy: committee=100, attestations=80 → rate=0.80 >= 0.66.
	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 1,
		committeeSize:      100,
		attestationCount:   80, // 80% >= 66%
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "da_attestation_collection_low" {
			t.Errorf("da_attestation_collection_low fired on healthy rate=0.80")
		}
	}
}

// TestDAAlertRules_AttestationCollectionColdStart verifies that
// da_attestation_collection_low does NOT fire on cold start (committee_size=0
// or attestation_count=0), avoiding false positives during node startup.
func TestDAAlertRules_AttestationCollectionColdStart(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	// Cold start: committee_size=0 (not yet configured).
	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 1,
		committeeSize:      0,
		attestationCount:   0,
	})

	alerts := am.Check(m)
	for _, a := range alerts {
		if a.Name == "da_attestation_collection_low" {
			t.Errorf("da_attestation_collection_low fired on cold start (committee_size=0)")
		}
	}

	// Reset: committee configured but no attestations yet (first slot pending).
	am.ClearAlerts()
	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 1,
		committeeSize:      100,
		attestationCount:   0, // no slot processed yet
	})

	alerts = am.Check(m)
	for _, a := range alerts {
		if a.Name == "da_attestation_collection_low" {
			// attestation_count=0 with committee_size=100 → rate=0 < 0.66.
			// This SHOULD fire because the committee is configured but no
			// attestations arrived — that's a real problem, not cold start.
			// So we expect it to fire here. This test documents that
			// attestation_count=0 is NOT treated as cold start when
			// committee_size > 0.
		}
	}
	// Verify it DOES fire in this case (committee configured, zero attestations).
	found := false
	for _, a := range alerts {
		if a.Name == "da_attestation_collection_low" {
			found = true
		}
	}
	if !found {
		t.Errorf("da_attestation_collection_low should fire when committee_size=100 but attestation_count=0")
	}
}

// TestSetDAMetricProvider_Nil verifies that setting nil provider disables
// all DA alert rules (they should return 0 after nil is set).
func TestSetDAMetricProvider_Nil(t *testing.T) {
	m := New()
	am := m.AlertManager()
	am.ClearAlerts()

	// Set a provider with bad values, then nil it out.
	fifteenGB := float64(15) * 1024 * 1024 * 1024
	m.SetDAMetricProvider(&fakeDAProvider{
		committeeAvailable: 0,
		samplingConfidence: 0.50,
		blobStorageSize:    fifteenGB,
		verifierRejections: 5,
		committeeSize:      100,
		attestationCount:   30, // 30% < 66%
	})
	m.SetDAMetricProvider(nil)

	alerts := am.Check(m)
	for _, a := range alerts {
		if isDAAlert(a.Name) {
			t.Errorf("DA alert %q fired after nil provider set (value=%v)", a.Name, a.Value)
		}
	}
}
