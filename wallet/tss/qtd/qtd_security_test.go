// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/pedersen"
)

func TestTimingAttackProtection(t *testing.T) {
	prot := &TimingAttackProtection{}

	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{1, 2, 3, 5}

	if !prot.ConstantTimeCompare(a, b) {
		t.Error("should be equal")
	}

	if prot.ConstantTimeCompare(a, c) {
		t.Error("should not be equal")
	}

	if prot.ConstantTimeCompare(a, []byte{1, 2}) {
		t.Error("different lengths should be false")
	}
}

func TestConstantTimeSelect(t *testing.T) {
	prot := &TimingAttackProtection{}

	result := prot.ConstantTimeSelect(1, 100, 200)
	if result != 100 {
		t.Errorf("choice=1: got %d, want 100", result)
	}

	result = prot.ConstantTimeSelect(0, 100, 200)
	if result != 200 {
		t.Errorf("choice=0: got %d, want 200", result)
	}
}

func TestAntiCollusion(t *testing.T) {
	ac := NewAntiCollusion()

	// FIX: updated for the M-2 fix (threshold lowered from 90% to 25%).
	// With a 25% threshold, shares differing by only 1 byte out of 5 (80%
	// match) ARE flagged as collusion. To test the "not collusion" case we
	// need shares with very low byte-level similarity (≤25% match).
	share1 := &QTDShare{
		ParticipantID: 1,
		S1ShareBytes:  []byte{1, 2, 3, 4, 5},
	}
	share2 := &QTDShare{
		ParticipantID: 2,
		S1ShareBytes:  []byte{10, 20, 30, 40, 50}, // 0 matching bytes → not collusion
	}

	if ac.DetectSimilarShares(share1, share2) {
		t.Error("shares with 0% byte match should not be collusion")
	}

	// Shares differing by only 1 byte (80% match) SHOULD be collusion with
	// the stricter 25% threshold.
	similar1 := &QTDShare{
		ParticipantID: 1,
		S1ShareBytes:  []byte{1, 2, 3, 4, 5},
	}
	similar2 := &QTDShare{
		ParticipantID: 2,
		S1ShareBytes:  []byte{1, 2, 3, 4, 6}, // 4/5 = 80% match → collusion
	}

	if !ac.DetectSimilarShares(similar1, similar2) {
		t.Error("shares with 80% byte match should be detected as collusion (25% threshold)")
	}

	identical1 := &QTDShare{
		ParticipantID: 1,
		S1ShareBytes:  []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	}
	identical2 := &QTDShare{
		ParticipantID: 2,
		S1ShareBytes:  []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	}

	if !ac.DetectSimilarShares(identical1, identical2) {
		t.Error("identical shares should be detected as collusion")
	}
}

func TestAntiCollusionTiming(t *testing.T) {
	ac := NewAntiCollusion()

	ac.RecordRoundTiming(1, 1000)
	ac.RecordRoundTiming(2, 1005)

	if !ac.CheckSynchronizedSubmission(1, 2, 100) {
		t.Error("submissions within 5ms should be flagged")
	}

	if ac.CheckSynchronizedSubmission(1, 2, 3) {
		t.Error("submissions 5ms apart should not be flagged with 3ms threshold")
	}

	if ac.CheckSynchronizedSubmission(1, 3, 100) {
		t.Error("missing participant should return false")
	}
}

func TestZKProof(t *testing.T) {
	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  []byte{1, 2, 3},
	}
	message := []byte("test message")

	proof, err := GenerateZKProof(share, message)
	if err != nil {
		t.Fatalf("GenerateZKProof failed: %v", err)
	}

	if proof == nil {
		t.Fatal("proof is nil")
	}

	if !VerifyZKProof(proof, share, message) {
		t.Error("valid proof should verify")
	}

	// Tamper with proof
	proof.C[0] ^= 0xFF
	if VerifyZKProof(proof, share, message) {
		t.Error("tampered proof should not verify")
	}
}

func TestSecurityAudit(t *testing.T) {
	audit := NewSecurityAudit()

	shares := []*QTDShare{
		{ParticipantID: 1, Rho: make([]byte, 32), S1ShareBytes: []byte{1, 2, 3}, S2ShareBytes: []byte{4, 5, 6}, VVector: [][]byte{make([]byte, 32)}},
		{ParticipantID: 2, Rho: make([]byte, 32), S1ShareBytes: []byte{7, 8, 9}, S2ShareBytes: []byte{10, 11, 12}, VVector: [][]byte{make([]byte, 32)}},
	}

	session, _ := NewQTDSession([]byte("test"), []int{1, 2}, 2, map[int]*QTDShare{
		1: shares[0],
		2: shares[1],
	})

	issues := audit.AuditSession(session, shares)
	if len(issues) > 0 {
		t.Errorf("unexpected issues: %v", issues)
	}

	// Test with empty verification vector
	sharesWithEmpty := []*QTDShare{
		{ParticipantID: 1, Rho: make([]byte, 32), S1ShareBytes: []byte{1}, S2ShareBytes: []byte{2}},
	}
	issues = audit.AuditSession(session, sharesWithEmpty)
	if len(issues) == 0 {
		t.Error("should detect empty verification vector")
	}
}

func TestShareProofBundle(t *testing.T) {
	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  []byte{42, 100, 255},
		S2ShareBytes:  []byte{1, 2, 3},
	}
	message := []byte("test message")

	bundle, err := NewShareProofBundle(share, message)
	if err != nil {
		t.Fatalf("NewShareProofBundle failed: %v", err)
	}

	if bundle == nil {
		t.Fatal("bundle is nil")
	}

	if !bundle.VerifyProofBundle(message) {
		t.Error("valid proof bundle should verify")
	}

	// Tamper with commitment hash
	bundle.CommitmentHash[0] ^= 0xFF
	if bundle.VerifyProofBundle(message) {
		t.Error("tampered bundle should not verify")
	}
}

func TestBatchVerifyProofs(t *testing.T) {
	shares := []*QTDShare{
		{ParticipantID: 1, Rho: make([]byte, 32), S1ShareBytes: []byte{1, 2, 3}, S2ShareBytes: []byte{4, 5, 6}},
		{ParticipantID: 2, Rho: make([]byte, 32), S1ShareBytes: []byte{7, 8, 9}, S2ShareBytes: []byte{10, 11, 12}},
	}
	message := []byte("batch test")

	bundles := make([]*ShareProofBundle, len(shares))
	for i, share := range shares {
		bundle, err := NewShareProofBundle(share, message)
		if err != nil {
			t.Fatalf("bundle %d failed: %v", i, err)
		}
		bundles[i] = bundle
	}

	if !BatchVerifyProofs(bundles, message) {
		t.Error("all valid bundles should verify")
	}

	// Tamper with one bundle
	bundles[0].CommitmentHash[0] ^= 0xFF
	if BatchVerifyProofs(bundles, message) {
		t.Error("tampered bundle should cause batch to fail")
	}
}

func TestShareIntegrityCheck(t *testing.T) {
	validS1 := make([]byte, 8)
	binary.LittleEndian.PutUint32(validS1[0:4], 1)
	binary.LittleEndian.PutUint32(validS1[4:8], 2)
	validS2 := make([]byte, 8)
	binary.LittleEndian.PutUint32(validS2[0:4], 3)
	binary.LittleEndian.PutUint32(validS2[4:8], 4)
	validT0 := make([]byte, 8)
	binary.LittleEndian.PutUint32(validT0[0:4], 5)
	binary.LittleEndian.PutUint32(validT0[4:8], 6)
	valid := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  validS1,
		S2ShareBytes:  validS2,
		T0ShareBytes:  validT0,
	}

	if err := ShareIntegrityCheck(valid); err != nil {
		t.Errorf("valid share failed check: %v", err)
	}

	invalid := &QTDShare{
		ParticipantID: 0,
		Rho:           make([]byte, 32),
	}
	if err := ShareIntegrityCheck(invalid); err == nil {
		t.Error("invalid participant ID should fail")
	}

	shortRho := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 16),
	}
	if err := ShareIntegrityCheck(shortRho); err == nil {
		t.Error("short rho should fail")
	}

	emptyS1 := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S2ShareBytes:  make([]byte, 4),
	}
	if err := ShareIntegrityCheck(emptyS1); err == nil {
		t.Error("empty S1 should fail")
	}

	notMultipleOf4 := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  []byte{1, 2, 3},
		S2ShareBytes:  make([]byte, 4),
	}
	if err := ShareIntegrityCheck(notMultipleOf4); err == nil {
		t.Error("S1ShareBytes length not multiple of 4 should fail")
	}

	outOfRangeS1 := make([]byte, 4)
	binary.LittleEndian.PutUint32(outOfRangeS1, uint32(Q))
	outOfRange := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  outOfRangeS1,
		S2ShareBytes:  make([]byte, 4),
	}
	if err := ShareIntegrityCheck(outOfRange); err == nil {
		t.Error("S1ShareBytes >= Q should fail")
	}

	outOfRangeS2 := make([]byte, 4)
	binary.LittleEndian.PutUint32(outOfRangeS2, uint32(Q))
	outOfRangeS2Share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  make([]byte, 4),
		S2ShareBytes:  outOfRangeS2,
	}
	if err := ShareIntegrityCheck(outOfRangeS2Share); err == nil {
		t.Error("S2ShareBytes >= Q should fail")
	}

	// QP-05: T0ShareBytes length not a multiple of 4 should fail.
	notMultipleOf4T0 := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  make([]byte, 4),
		S2ShareBytes:  make([]byte, 4),
		T0ShareBytes:  []byte{1, 2, 3},
	}
	if err := ShareIntegrityCheck(notMultipleOf4T0); err == nil {
		t.Error("T0ShareBytes length not multiple of 4 should fail")
	}

	// QP-05: T0ShareBytes coefficient >= Q should fail.
	outOfRangeT0 := make([]byte, 4)
	binary.LittleEndian.PutUint32(outOfRangeT0, uint32(Q))
	outOfRangeT0Share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  make([]byte, 4),
		S2ShareBytes:  make([]byte, 4),
		T0ShareBytes:  outOfRangeT0,
	}
	if err := ShareIntegrityCheck(outOfRangeT0Share); err == nil {
		t.Error("T0ShareBytes >= Q should fail")
	}
}

func TestSecurelyZeroMemory(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	SecurelyZeroMemory(data)

	for i := range data {
		if data[i] != 0 {
			t.Errorf("data[%d] not zeroed: got %d", i, data[i])
		}
	}
}

func TestGenerateChallengeSeed(t *testing.T) {
	entropy := [][]byte{
		[]byte("entropy1"),
		[]byte("entropy2"),
		[]byte("entropy3"),
	}

	seed, err := GenerateChallengeSeed(entropy)
	if err != nil {
		t.Fatalf("GenerateChallengeSeed failed: %v", err)
	}

	if len(seed) != 32 {
		t.Errorf("seed length: got %d, want 32", len(seed))
	}

	// Empty entropy should fail
	_, err = GenerateChallengeSeed(nil)
	if err == nil {
		t.Error("empty entropy should fail")
	}
}

func TestEncodeDecodeShare(t *testing.T) {
	s1 := make([]byte, 8)
	binary.LittleEndian.PutUint32(s1[0:4], 1)
	binary.LittleEndian.PutUint32(s1[4:8], 2)
	s2 := make([]byte, 8)
	binary.LittleEndian.PutUint32(s2[0:4], 3)
	binary.LittleEndian.PutUint32(s2[4:8], 4)
	t0 := make([]byte, 8)
	binary.LittleEndian.PutUint32(t0[0:4], 5)
	binary.LittleEndian.PutUint32(t0[4:8], 6)
	original := &QTDShare{
		ParticipantID: 42,
		Rho:           make([]byte, 32),
		S1ShareBytes:  s1,
		S2ShareBytes:  s2,
		T0ShareBytes:  t0,
	}
	original.Rho[0] = 0xDE
	original.Rho[31] = 0xAD

	encoded, err := EncodeShareForTransmission(original)
	if err != nil {
		t.Fatalf("EncodeShareForTransmission failed: %v", err)
	}

	decoded, err := DecodeShareFromTransmission(encoded)
	if err != nil {
		t.Fatalf("DecodeShareFromTransmission failed: %v", err)
	}

	if decoded.ParticipantID != original.ParticipantID {
		t.Errorf("participant ID: got %d, want %d", decoded.ParticipantID, original.ParticipantID)
	}

	if !bytesEqual(decoded.Rho, original.Rho) {
		t.Error("rho mismatch")
	}

	if !bytesEqual(decoded.S1ShareBytes, original.S1ShareBytes) {
		t.Error("S1ShareBytes mismatch")
	}

	if !bytesEqual(decoded.S2ShareBytes, original.S2ShareBytes) {
		t.Error("S2ShareBytes mismatch")
	}

	if !bytesEqual(decoded.T0ShareBytes, original.T0ShareBytes) {
		t.Error("T0ShareBytes mismatch")
	}
}

func TestDecodeShareTruncated(t *testing.T) {
	_, err := DecodeShareFromTransmission([]byte{1, 2, 3})
	if err == nil {
		t.Error("truncated data should fail")
	}
}

func TestPedersenVerifier(t *testing.T) {
	v := NewPedersenVerifier()

	// FIX: updated to use the 80-byte format (48-byte commitment +
	// 32-byte random blinding) matching generateVerificationVector.
	// The previous test used participant ID as deterministic blinding, which
	// was the CRITICAL vulnerability fixed in this round.
	gen, err := pedersen.NewGenerator()
	if err != nil {
		t.Fatalf("failed to create pedersen generator: %v", err)
	}

	// S1ShareBytes must be a multiple of 4 for canUsePedersenVerification
	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  []byte{42, 0, 0, 0}, // 4 bytes, little-endian uint32 = 42
	}

	// Generate a random blinding factor (matching generateVerificationVector)
	blinding, err := pedersen.RandomBlinding()
	if err != nil {
		t.Fatalf("failed to generate random blinding: %v", err)
	}

	// Compute the expected Pedersen commitment: C = g^share * h^blinding
	shareVal := new(big.Int).SetUint64(uint64(binary.LittleEndian.Uint32(share.S1ShareBytes[:4])))
	expectedCommit := gen.Commit(shareVal, blinding)
	commitmentBytes := expectedCommit.Bytes()

	if len(commitmentBytes) != 48 {
		t.Fatalf("expected 48-byte commitment, got %d bytes", len(commitmentBytes))
	}

	// Build 80-byte entry: commitment (48) || blinding (32)
	blindingBytes := make([]byte, 32)
	blinding.FillBytes(blindingBytes)

	entry := make([]byte, 80)
	copy(entry[:48], commitmentBytes)
	copy(entry[48:], blindingBytes)

	v.AddVerificationVector(share.ParticipantID, [][]byte{entry})

	if err := v.VerifyShare(share); err != nil {
		t.Errorf("valid share failed verification: %v", err)
	}

	// Wrong vector (32-byte SHA256 hash — should be rejected, not accepted via fallback)
	v2 := NewPedersenVerifier()
	v2.AddVerificationVector(share.ParticipantID, [][]byte{[]byte("wrong-size-vector-entry")})
	if err := v2.VerifyShare(share); err == nil {
		t.Error("wrong verification vector should fail")
	}
}

func TestPedernVerifierInvalidParticipant(t *testing.T) {
	v := NewPedersenVerifier()
	share := &QTDShare{ParticipantID: 1}

	err := v.VerifyShare(share)
	if err == nil {
		t.Error("missing verification vector should fail")
	}
}
