// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"encoding/binary"
	"errors"
	"testing"
)

// TestTSS_R5_05_VerifyShare_FailClosedOnMissingVVectorS2 verifies that
// VerifyShare rejects a share whose S2 verification vector is missing,
// rather than logging a warning and skipping S2 verification (the old
// fail-open behavior).
//
// AUDIT (2026) TSS-R5-05 (Medium / ACTIVE):
// A malicious distributor could omit VVectorS2 from a forged share to
// fall back to the unverified S2 path. The S1 Pedersen check alone does
// not constrain S2, and ShareIntegrityCheck only validates length/range,
// not consistency with a commitment. The final Dilithium3 signature
// check catches only the aggregate result, not the specific bad share,
// and only in failure modes that surface at verify time.
//
// Fix: missing VVectorS2 now returns ErrShareVerification (fail-closed),
// completing TODO(N20-003). DKG *always* emits VVectorS2 (see
// GenerateDKGShares/GenerateDKGSharesShamir), so absence indicates
// forgery or corruption.
func TestTSS_R5_05_VerifyShare_FailClosedOnMissingVVectorS2(t *testing.T) {
	shareBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(shareBytes[0:4], 42)
	binary.LittleEndian.PutUint32(shareBytes[4:8], 100)
	binary.LittleEndian.PutUint32(shareBytes[8:12], 250)
	threshold := 2

	vVector, err := generateVerificationVector(shareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector S1 failed: %v", err)
	}

	t0ShareBytes := make([]byte, 8)
	vVectorT0, err := generateVerificationVector(t0ShareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector T0 failed: %v", err)
	}

	// Share has S2ShareBytes but NO VVectorS2 — the fail-open path.
	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  shareBytes,
		S2ShareBytes:  make([]byte, 8),
		T0ShareBytes:  t0ShareBytes,
		// VVectorS2 intentionally omitted
		VVectorT0: vVectorT0,
	}

	err = VerifyShare(share, [][][]byte{vVector}, 1)
	if err == nil {
		t.Fatal("TSS-R5-05: expected error when VVectorS2 is missing, got nil (fail-open regression)")
	}
	if !errors.Is(err, ErrShareVerification) {
		t.Errorf("TSS-R5-05: expected ErrShareVerification, got %v", err)
	}
}

// TestTSS_R5_05_VerifyShare_FailClosedOnMissingVVectorT0 verifies the
// symmetric case: missing VVectorT0 must also be rejected.
func TestTSS_R5_05_VerifyShare_FailClosedOnMissingVVectorT0(t *testing.T) {
	shareBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(shareBytes[0:4], 42)
	binary.LittleEndian.PutUint32(shareBytes[4:8], 100)
	binary.LittleEndian.PutUint32(shareBytes[8:12], 250)
	threshold := 2

	vVector, err := generateVerificationVector(shareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector S1 failed: %v", err)
	}

	s2ShareBytes := make([]byte, 8)
	vVectorS2, err := generateVerificationVector(s2ShareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector S2 failed: %v", err)
	}

	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  shareBytes,
		S2ShareBytes:  s2ShareBytes,
		T0ShareBytes:  make([]byte, 8),
		VVectorS2:     vVectorS2,
		// VVectorT0 intentionally omitted
	}

	err = VerifyShare(share, [][][]byte{vVector}, 1)
	if err == nil {
		t.Fatal("TSS-R5-05: expected error when VVectorT0 is missing, got nil (fail-open regression)")
	}
	if !errors.Is(err, ErrShareVerification) {
		t.Errorf("TSS-R5-05: expected ErrShareVerification, got %v", err)
	}
}

// TestTSS_R5_05_VerifyShare_FailClosedOnMissingBothVVectors verifies that
// a share missing BOTH VVectorS2 and VVectorT0 is rejected (and the S2
// check fires first, matching source order).
func TestTSS_R5_05_VerifyShare_FailClosedOnMissingBothVVectors(t *testing.T) {
	shareBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(shareBytes[0:4], 42)
	binary.LittleEndian.PutUint32(shareBytes[4:8], 100)
	binary.LittleEndian.PutUint32(shareBytes[8:12], 250)
	threshold := 2

	vVector, err := generateVerificationVector(shareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector S1 failed: %v", err)
	}

	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  shareBytes,
		S2ShareBytes:  make([]byte, 8),
		T0ShareBytes:  make([]byte, 8),
		// Both VVectorS2 and VVectorT0 intentionally omitted
	}

	err = VerifyShare(share, [][][]byte{vVector}, 1)
	if err == nil {
		t.Fatal("TSS-R5-05: expected error when both VVectors are missing, got nil")
	}
	if !errors.Is(err, ErrShareVerification) {
		t.Errorf("TSS-R5-05: expected ErrShareVerification, got %v", err)
	}
}

// TestTSS_R5_05_VerifyShare_FailClosedOnTamperedS2Share verifies that a
// share with a present-but-mismatched VVectorS2 is rejected. This is the
// "malicious distributor plants inconsistent S2" scenario from the audit
// report — the previous fail-open path would skip verification entirely
// when VVectorS2 was nil, but a more sophisticated attacker could also
// emit a VVectorS2 that doesn't match the (forged) S2ShareBytes. This
// case was already handled by the existing verifyPedersenCoefficients
// path; we include it here as a companion regression test to confirm
// the S2 verification is actually exercised (not skipped silently).
func TestTSS_R5_05_VerifyShare_FailClosedOnTamperedS2Share(t *testing.T) {
	shareBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(shareBytes[0:4], 42)
	binary.LittleEndian.PutUint32(shareBytes[4:8], 100)
	binary.LittleEndian.PutUint32(shareBytes[8:12], 250)
	threshold := 2

	vVector, err := generateVerificationVector(shareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector S1 failed: %v", err)
	}

	// Generate VVectorS2 for the *correct* S2 share, then tamper the
	// S2ShareBytes so they no longer match the commitments.
	s2ShareBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(s2ShareBytes[0:4], 7)
	binary.LittleEndian.PutUint32(s2ShareBytes[4:8], 11)
	vVectorS2, err := generateVerificationVector(s2ShareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector S2 failed: %v", err)
	}

	t0ShareBytes := make([]byte, 8)
	vVectorT0, err := generateVerificationVector(t0ShareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector T0 failed: %v", err)
	}

	// Tamper: overwrite S2ShareBytes with different values after VVectorS2
	// was generated against the original.
	tamperedS2 := make([]byte, 8)
	binary.LittleEndian.PutUint32(tamperedS2[0:4], 999)
	binary.LittleEndian.PutUint32(tamperedS2[4:8], 999)

	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  shareBytes,
		S2ShareBytes:  tamperedS2,
		T0ShareBytes:  t0ShareBytes,
		VVectorS2:     vVectorS2,
		VVectorT0:     vVectorT0,
	}

	err = VerifyShare(share, [][][]byte{vVector}, 1)
	if err == nil {
		t.Fatal("TSS-R5-05: expected error for tampered S2 share with valid-looking VVectorS2, got nil")
	}
	if !errors.Is(err, ErrShareVerification) {
		t.Errorf("TSS-R5-05: expected ErrShareVerification, got %v", err)
	}
}

// TestTSS_R5_05_VerifyShare_FailClosedOnTamperedT0Share is the T0
// symmetric counterpart of the tampered-S2 test above.
func TestTSS_R5_05_VerifyShare_FailClosedOnTamperedT0Share(t *testing.T) {
	shareBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(shareBytes[0:4], 42)
	binary.LittleEndian.PutUint32(shareBytes[4:8], 100)
	binary.LittleEndian.PutUint32(shareBytes[8:12], 250)
	threshold := 2

	vVector, err := generateVerificationVector(shareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector S1 failed: %v", err)
	}

	s2ShareBytes := make([]byte, 8)
	vVectorS2, err := generateVerificationVector(s2ShareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector S2 failed: %v", err)
	}

	t0ShareBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(t0ShareBytes[0:4], 19)
	binary.LittleEndian.PutUint32(t0ShareBytes[4:8], 23)
	vVectorT0, err := generateVerificationVector(t0ShareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector T0 failed: %v", err)
	}

	tamperedT0 := make([]byte, 8)
	binary.LittleEndian.PutUint32(tamperedT0[0:4], 999)
	binary.LittleEndian.PutUint32(tamperedT0[4:8], 999)

	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  shareBytes,
		S2ShareBytes:  s2ShareBytes,
		T0ShareBytes:  tamperedT0,
		VVectorS2:     vVectorS2,
		VVectorT0:     vVectorT0,
	}

	err = VerifyShare(share, [][][]byte{vVector}, 1)
	if err == nil {
		t.Fatal("TSS-R5-05: expected error for tampered T0 share, got nil")
	}
	if !errors.Is(err, ErrShareVerification) {
		t.Errorf("TSS-R5-05: expected ErrShareVerification, got %v", err)
	}
}

// TestTSS_R5_05_VerifyShare_FullDKGSharesAllPass uses the real DKG path
// (GenerateDKGShares) to produce shares and verifies each one passes
// VerifyShare with no warning-suppressed branch. This is the end-to-end
// smoke test confirming that DKG output is compatible with the
// fail-closed verification.
func TestTSS_R5_05_VerifyShare_FullDKGSharesAllPass(t *testing.T) {
	threshold, total := 2, 3
	pub, shares, err := GenerateDKGShares(threshold, total)
	if err != nil {
		t.Fatalf("GenerateDKGShares failed: %v", err)
	}
	if pub == nil {
		t.Fatal("GenerateDKGShares returned nil pub")
	}

	// Collect each participant's VVector into allVVectors (indexed by
	// participantID-1, matching VerifyShare's indexing convention).
	allVVectors := make([][][]byte, total)
	for i, sh := range shares {
		if len(sh.VVector) == 0 {
			t.Fatalf("share %d has empty VVector (DKG must emit it)", i)
		}
		if len(sh.VVectorS2) == 0 {
			t.Fatalf("share %d has empty VVectorS2 (DKG must emit it)", i)
		}
		if len(sh.VVectorT0) == 0 {
			t.Fatalf("share %d has empty VVectorT0 (DKG must emit it)", i)
		}
		allVVectors[sh.ParticipantID-1] = sh.VVector
	}

	for _, sh := range shares {
		if err := VerifyShare(sh, allVVectors, sh.ParticipantID); err != nil {
			t.Errorf("DKG-produced share %d failed VerifyShare: %v",
				sh.ParticipantID, err)
		}
	}
}
