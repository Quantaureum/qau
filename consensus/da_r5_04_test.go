// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"os"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// DA-R5-04 (2026-07-16): Regression tests for BuildAggregateAttestation's
// commitment-binding enforcement. Previously an attestation could be
// reused across distinct commitment sets sharing commitments[0]; now
// BuildAggregateAttestation verifies each attestation's BlobCommitments
// matches the expected aggregate set, fail-closing on mismatch.
//
// DA-R7-04 (2026-07-17): BlobCommitments is now []encoding.KZGCommitment
// (48 bytes each) instead of []types.Hash (32 bytes). The legacy
// BlobCommitment field is populated from the first 32 bytes of
// commitments[0] via types.BytesToHash(commitments[0][:]).
//
// Test matrix:
//   1. Matching BlobCommitments → aggregate produced
//   2. Mismatched BlobCommitments → nil (fail-closed)
//   3. Mismatched length → nil
//   4. Mismatched order → nil
//   5. Single mismatched attestation among many → nil (poison rejected)
//   6. nil commitments (legacy callers) → aggregate still produced (skipped check)
//   7. attestationCommitmentsMatch unit tests for legacy fallback path

// buildCollectorWithCommitments builds a collector preloaded with N
// attestations for slot 100, each carrying the supplied BlobCommitments.
// The verifier is permissive (signature checks are tested elsewhere).
func buildCollectorWithCommitments(t *testing.T, n int, commitments []encoding.KZGCommitment) *DAAttestationCollector {
	t.Helper()
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(n)
	c.SetAttestationVerifier(func(att *encoding.DASAttestation) error { return nil })
	for i := 0; i < n; i++ {
		att := &encoding.DASAttestation{
			Slot:            100,
			Available:       true,
			ValidatorIndex:  i,
			Signature:       []byte{byte(i), 0xAA, 0xBB},
			SampleCount:     10,
			SuccessCount:    10,
			Confidence:      0.9999,
			BlobCommitments: commitments,
		}
		if len(commitments) > 0 {
			att.BlobCommitment = types.BytesToHash(commitments[0][:])
		}
		if err := c.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation %d failed: %v", i, err)
		}
	}
	return c
}

// TestDA_R5_04_AggregateProducesWhenCommitmentsMatch: happy path — all
// attestations carry the expected BlobCommitments → aggregate produced.
func TestDA_R5_04_AggregateProducesWhenCommitmentsMatch(t *testing.T) {
	commitments := []encoding.KZGCommitment{{0x01}, {0x02}, {0x03}}
	c := buildCollectorWithCommitments(t, 4, commitments)
	agg := c.BuildAggregateAttestation(100, commitments)
	if agg == nil {
		t.Fatal("expected non-nil aggregate when all BlobCommitments match")
	}
	if agg.AvailableCount != 4 {
		t.Errorf("AvailableCount mismatch: %d", agg.AvailableCount)
	}
}

// TestDA_R5_04_AggregateRejectsWhenCommitmentsDiffer: all attestations
// carry a DIFFERENT commitment set → fail-closed → nil aggregate.
func TestDA_R5_04_AggregateRejectsWhenCommitmentsDiffer(t *testing.T) {
	attested := []encoding.KZGCommitment{{0x01}, {0x02}, {0x03}}
	expected := []encoding.KZGCommitment{{0x01}, {0x02}, {0x99}} // differs at [2]
	c := buildCollectorWithCommitments(t, 4, attested)
	agg := c.BuildAggregateAttestation(100, expected)
	if agg != nil {
		t.Fatalf("DA-R5-04: expected nil aggregate when BlobCommitments differ, got non-nil (AvailableCount=%d)", agg.AvailableCount)
	}
}

// TestDA_R5_04_AggregateRejectsWhenLengthDiffers: attestations carry a
// 3-element set, expected is 2-element (same prefix) → fail-closed.
// This proves the length check is enforced.
func TestDA_R5_04_AggregateRejectsWhenLengthDiffers(t *testing.T) {
	attested := []encoding.KZGCommitment{{0x01}, {0x02}, {0x03}}
	expected := []encoding.KZGCommitment{{0x01}, {0x02}} // shorter prefix
	c := buildCollectorWithCommitments(t, 4, attested)
	agg := c.BuildAggregateAttestation(100, expected)
	if agg != nil {
		t.Fatalf("DA-R5-04: expected nil when BlobCommitments length differs, got non-nil")
	}
}

// TestDA_R5_04_AggregateRejectsWhenOrderDiffers: same elements, different
// order → fail-closed. This proves order matters (no commutative surprise).
func TestDA_R5_04_AggregateRejectsWhenOrderDiffers(t *testing.T) {
	attested := []encoding.KZGCommitment{{0x01}, {0x02}, {0x03}}
	expected := []encoding.KZGCommitment{{0x01}, {0x03}, {0x02}} // permuted
	c := buildCollectorWithCommitments(t, 4, attested)
	agg := c.BuildAggregateAttestation(100, expected)
	if agg != nil {
		t.Fatalf("DA-R5-04: expected nil when BlobCommitments order differs, got non-nil")
	}
}

// TestDA_R5_04_AggregateRejectsPoisonedSingleAttestation: one malicious
// attestation among many must fail-close the entire aggregate. This
// proves an attacker cannot poison the aggregate by submitting a single
// mismatched attestation.
func TestDA_R5_04_AggregateRejectsPoisonedSingleAttestation(t *testing.T) {
	good := []encoding.KZGCommitment{{0x01}, {0x02}}
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(5)
	c.SetAttestationVerifier(func(att *encoding.DASAttestation) error { return nil })

	// Submit 4 matching attestations.
	for i := 0; i < 4; i++ {
		att := &encoding.DASAttestation{
			Slot:            100,
			Available:       true,
			ValidatorIndex:  i,
			Signature:       []byte{byte(i)},
			BlobCommitments: good,
			BlobCommitment:  types.BytesToHash(good[0][:]), // DA-R7-04: KZGCommitment[0][:32]
		}
		if err := c.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation %d failed: %v", i, err)
		}
	}

	// Submit 1 poisoned attestation with a different commitment set.
	poisoned := &encoding.DASAttestation{
		Slot:            100,
		Available:       true,
		ValidatorIndex:  4,
		Signature:       []byte{0x04},
		BlobCommitments: []encoding.KZGCommitment{{0x01}, {0x99}}, // differs at [1]
		BlobCommitment:  types.BytesToHash(good[0][:]),            // legacy field matches
	}
	if err := c.SubmitAttestation(poisoned); err != nil {
		t.Fatalf("SubmitAttestation poisoned failed: %v", err)
	}

	agg := c.BuildAggregateAttestation(100, good)
	if agg != nil {
		t.Fatalf("DA-R5-04: expected nil when one poisoned attestation present, got non-nil (AvailableCount=%d)", agg.AvailableCount)
	}
}

// TestDA_R5_04_AggregateAcceptsNilCommitments: legacy callers pass nil
// for commitments (e.g., quorum-only checks via GetAggregateAttestation).
// The binding check is skipped in this case — the caller is responsible
// for re-checking with the real set.
func TestDA_R5_04_AggregateAcceptsNilCommitments(t *testing.T) {
	commitments := []encoding.KZGCommitment{{0x01}}
	c := buildCollectorWithCommitments(t, 4, commitments)
	agg := c.BuildAggregateAttestation(100, nil)
	if agg == nil {
		t.Fatal("expected non-nil aggregate when commitments is nil (skip check)")
	}
}

// TestDA_R5_04_attestationCommitmentsMatch_LegacyFallback: legacy
// attestations (no BlobCommitments trailing block) fall back to comparing
// the single BlobCommitment field against expected[0] (truncated to 32 bytes).
//
// DA-R7-04 (2026-07-17): types.BytesToHash takes the LAST 32 bytes of a
// 48-byte input (bytes 16..47). The test commitment places its distinguishing
// byte at position 20 (within the last 32 bytes) so the derived legacy hash
// is non-zero and the match/mismatch cases are meaningful. The expected
// legacy hash is derived via types.BytesToHash(expected[0][:]) — the SAME
// derivation BuildDAAttestation uses — so the test stays correct regardless
// of which 32 bytes BytesToHash extracts.
func TestDA_R5_04_attestationCommitmentsMatch_LegacyFallback(t *testing.T) {
	// Build a 48-byte commitment with the distinguishing byte at position 20
	// (inside the last 32 bytes that BytesToHash extracts).
	c := encoding.KZGCommitment{}
	c[20] = 0xAB
	expected := []encoding.KZGCommitment{c}
	expectedLegacy := types.BytesToHash(c[:]) // same derivation as BuildDAAttestation

	// Legacy attestation with matching BlobCommitment → match.
	legacyMatch := &encoding.DASAttestation{
		BlobCommitment: expectedLegacy,
		// BlobCommitments intentionally nil
	}
	if !attestationCommitmentsMatch(legacyMatch, expected) {
		t.Error("legacy attestation with matching BlobCommitment should match")
	}

	// Legacy attestation with mismatched BlobCommitment → no match.
	legacyMismatch := &encoding.DASAttestation{
		BlobCommitment: types.Hash{0xCD}, // byte 0 = 0xCD, clearly differs from expectedLegacy
	}
	if attestationCommitmentsMatch(legacyMismatch, expected) {
		t.Error("legacy attestation with mismatched BlobCommitment should NOT match")
	}

	// Legacy attestation with zero BlobCommitment and empty expected → match.
	legacyZero := &encoding.DASAttestation{
		BlobCommitment: types.Hash{},
	}
	if !attestationCommitmentsMatch(legacyZero, nil) {
		t.Error("legacy attestation with zero BlobCommitment and empty expected should match")
	}

	// New-format attestation takes precedence over legacy fallback.
	// BlobCommitment matches expectedLegacy, but BlobCommitments has length 2
	// while expected has length 1 → must NOT match.
	newFmt := &encoding.DASAttestation{
		BlobCommitment:  expectedLegacy,                      // matches legacy field
		BlobCommitments: []encoding.KZGCommitment{c, {0xCD}}, // but full set differs (length 2 vs 1)
	}
	if attestationCommitmentsMatch(newFmt, expected) {
		t.Error("new-format attestation with mismatched BlobCommitments should NOT match even if BlobCommitment matches")
	}
}

// TestDA_R5_04_attestationCommitmentsMatch_NilAttestation: nil attestation
// is treated as non-matching (defensive).
func TestDA_R5_04_attestationCommitmentsMatch_NilAttestation(t *testing.T) {
	if attestationCommitmentsMatch(nil, []encoding.KZGCommitment{{0x01}}) {
		t.Error("nil attestation should not match")
	}
}

// TestDA_R5_04_attestationCommitmentsMatch_EmptyBlobCommitmentsAndNonEmptyExpected:
// an attestation with empty (but non-nil) BlobCommitments vs non-empty
// expected → fall back to legacy single-field check.
//
// DA-R7-04 (2026-07-17): types.BytesToHash takes the LAST 32 bytes of a
// 48-byte input, so the distinguishing byte is placed at position 20
// (within bytes 16..47) and the expected legacy hash is derived via
// types.BytesToHash(c[:]) — matching BuildDAAttestation's derivation.
func TestDA_R5_04_attestationCommitmentsMatch_EmptyBlobCommitmentsAndNonEmptyExpected(t *testing.T) {
	c := encoding.KZGCommitment{}
	c[20] = 0x01
	att := &encoding.DASAttestation{
		BlobCommitment:  types.BytesToHash(c[:]),    // same derivation as BuildDAAttestation
		BlobCommitments: []encoding.KZGCommitment{}, // empty but non-nil
	}
	expected := []encoding.KZGCommitment{c}
	// Empty BlobCommitments slice → fall back to BlobCommitment.
	if !attestationCommitmentsMatch(att, expected) {
		t.Error("empty BlobCommitments should fall back to BlobCommitment check")
	}
}

// TestDA_R7_11_ProductionModeRejectsLegacyAttestation: DA-R7-11 (Low).
// In production mode (QAU_PRODUCTION=1), BuildAggregateAttestation MUST
// refuse to aggregate legacy attestations whose BlobCommitments is empty.
// Legacy attestations only bind to commitments[0] via the 32-byte
// BlobCommitment field, allowing cross-commitment-set reuse when two
// distinct sets share the same first commitment. Mainnet must require
// the full BlobCommitments trailing block.
//
// In dev/test mode (no QAU_PRODUCTION), the legacy fallback remains
// available for backward compatibility with old binaries.
func TestDA_R7_11_ProductionModeRejectsLegacyAttestation(t *testing.T) {
	commitments := []encoding.KZGCommitment{{0x01}, {0x02}, {0x03}}
	legacyBlobCommitment := types.BytesToHash(commitments[0][:])

	// buildMixedCollector builds a collector with 3 new-format attestations
	// (sufficient for IsSufficient when CommitteeSize=4) plus 1 legacy
	// attestation (BlobCommitments=nil). The legacy attestation is the
	// canary: dev mode accepts it (fallback path), production mode rejects it.
	buildMixedCollector := func() *DAAttestationCollector {
		c := NewDAAttestationCollector()
		c.SetCommitteeSize(4)
		c.SetAttestationVerifier(func(att *encoding.DASAttestation) error { return nil })
		// 3 new-format attestations (enough for IsSufficient: ceil(2/3*4)=3).
		for i := 0; i < 3; i++ {
			att := &encoding.DASAttestation{
				Slot:            100,
				Available:       true,
				ValidatorIndex:  i,
				Signature:       []byte{byte(i), 0xAA, 0xBB},
				SampleCount:     10,
				SuccessCount:    10,
				Confidence:      0.9999,
				BlobCommitments: commitments,
				BlobCommitment:  legacyBlobCommitment,
			}
			if err := c.SubmitAttestation(att); err != nil {
				t.Fatalf("SubmitAttestation %d failed: %v", i, err)
			}
		}
		// 1 legacy attestation (BlobCommitments intentionally nil).
		legacyAtt := &encoding.DASAttestation{
			Slot:           100,
			Available:      true,
			ValidatorIndex: 3,
			Signature:      []byte{0x03, 0xAA, 0xBB},
			SampleCount:    10,
			SuccessCount:   10,
			Confidence:     0.9999,
			// BlobCommitments intentionally nil — legacy format
			BlobCommitment: legacyBlobCommitment,
		}
		if err := c.SubmitAttestation(legacyAtt); err != nil {
			t.Fatalf("SubmitAttestation legacy failed: %v", err)
		}
		return c
	}

	// Subtest 1: dev mode — legacy attestation accepted via fallback path.
	// All 4 attestations aggregate; AvailableCount=4 satisfies IsSufficient.
	t.Run("dev_mode_accepts_legacy", func(t *testing.T) {
		orig := os.Getenv("QAU_PRODUCTION")
		os.Unsetenv("QAU_PRODUCTION")
		defer func() {
			if orig == "" {
				os.Unsetenv("QAU_PRODUCTION")
			} else {
				os.Setenv("QAU_PRODUCTION", orig)
			}
		}()

		c := buildMixedCollector()
		agg := c.BuildAggregateAttestation(100, commitments)
		if agg == nil {
			t.Fatal("dev mode: expected non-nil aggregate for legacy attestation (fallback path)")
		}
		if agg.AvailableCount != 4 {
			t.Errorf("AvailableCount mismatch: got %d, want 4", agg.AvailableCount)
		}
	})

	// Subtest 2: production mode — legacy attestation REJECTED.
	// The presence of one legacy attestation causes the entire aggregate
	// to be refused (fail-closed), even though the other 3 are new-format.
	t.Run("production_mode_rejects_legacy", func(t *testing.T) {
		orig := os.Getenv("QAU_PRODUCTION")
		os.Setenv("QAU_PRODUCTION", "1")
		defer func() {
			if orig == "" {
				os.Unsetenv("QAU_PRODUCTION")
			} else {
				os.Setenv("QAU_PRODUCTION", orig)
			}
		}()

		c := buildMixedCollector()
		agg := c.BuildAggregateAttestation(100, commitments)
		if agg != nil {
			t.Fatalf("production mode: expected nil aggregate when legacy attestation present, got non-nil (AvailableCount=%d)", agg.AvailableCount)
		}
	})

	// Subtest 3: production mode — all new-format attestations still
	// accepted. This proves the DA-R7-11 check only rejects the legacy
	// format, not all attestations.
	t.Run("production_mode_accepts_new_format", func(t *testing.T) {
		orig := os.Getenv("QAU_PRODUCTION")
		os.Setenv("QAU_PRODUCTION", "1")
		defer func() {
			if orig == "" {
				os.Unsetenv("QAU_PRODUCTION")
			} else {
				os.Setenv("QAU_PRODUCTION", orig)
			}
		}()

		c2 := buildCollectorWithCommitments(t, 4, commitments)
		agg := c2.BuildAggregateAttestation(100, commitments)
		if agg == nil {
			t.Fatal("production mode: expected non-nil aggregate for new-format attestations")
		}
		if agg.AvailableCount != 4 {
			t.Errorf("AvailableCount mismatch: got %d, want 4", agg.AvailableCount)
		}
	})
}
