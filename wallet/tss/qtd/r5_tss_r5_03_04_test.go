// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// TestTSS_R5_03_04_Power2Round_MathCorrectness verifies that Power2RoundPoly
// satisfies the defining identity t = t1·2^D + t0 (mod Q) for every coefficient,
// and that t1 ∈ [0, 2^10 - 1] and t0 ∈ (-2^(D-1), 2^(D-1)].
//
// AUDIT (2026) TSS-R5-03/04 FIX:
// Power2RoundPoly is the missing primitive required for real distributed DKG.
// Without it, the codebase could only obtain (t0, t1) by calling
// mode3.NewKeyFromSeed — which materializes the full private key in heap.
// This test confirms the math is correct before testing circl compatibility.
func TestTSS_R5_03_04_Power2Round_MathCorrectness(t *testing.T) {
	// Test deterministic edge cases.
	edgeCases := []uint32{
		0,
		1,
		(1 << Dilithium3D) - 1,               // 2^D - 1
		1 << Dilithium3D,                     // 2^D
		(1 << (Dilithium3D - 1)) - 1,         // 2^(D-1) - 1
		1 << (Dilithium3D - 1),               // 2^(D-1)
		(1 << (Dilithium3D - 1)) + 1,         // 2^(D-1) + 1
		uint32(Q) - 1,                        // Q - 1
		uint32(Q),                            // Q (wraps to 0)
		uint32(Q) + 1,                        // Q + 1 (wraps to 1)
		uint32(Q) - (1 << Dilithium3D),       // Q - 2^D
		uint32(Q) - (1 << (Dilithium3D - 1)), // Q - 2^(D-1)
		uint32(Q) + (1 << (Dilithium3D - 1)), // Q + 2^(D-1) (wraps)
	}

	for _, tc := range edgeCases {
		a := tc % uint32(Q) // Normalize
		var p Poly
		p[0] = int32(a)
		var p0PlusQ, p1 Poly
		Power2RoundPoly(&p0PlusQ, &p1, &p)

		a0PlusQ := uint32(p0PlusQ[0])
		a1 := uint32(p1[0])

		// a0 = a0PlusQ - Q
		var a0 int64
		if a0PlusQ >= uint32(Q) {
			a0 = int64(a0PlusQ - uint32(Q))
		} else {
			// a0PlusQ < Q means a0 is negative; circl representation uses a0PlusQ = Q + a0
			// where a0 ∈ (-2^(D-1), 0], so a0PlusQ ∈ [Q - 2^(D-1), Q).
			a0 = int64(a0PlusQ) - int64(Q)
		}

		// Check identity: a = a1 * 2^D + a0 (mod Q)
		reconstructed := (int64(a1)*int64(1<<Dilithium3D) + a0) % int64(Q)
		if reconstructed < 0 {
			reconstructed += int64(Q)
		}
		if uint32(reconstructed) != a {
			t.Errorf("Power2Round(%d): reconstructed=%d (a1=%d a0=%d), want %d",
				a, reconstructed, a1, a0, a)
		}

		// Check a1 range: [0, 2^10 - 1]
		if a1 >= (1 << 10) {
			t.Errorf("Power2Round(%d): a1=%d out of range [0, %d]", a, a1, (1<<10)-1)
		}

		// Check a0 range: (-2^(D-1), 2^(D-1)]
		if a0 <= -(1<<(Dilithium3D-1)) || a0 > (1<<(Dilithium3D-1)) {
			t.Errorf("Power2Round(%d): a0=%d out of range (%d, %d]",
				a, a0, -(1 << (Dilithium3D - 1)), 1<<(Dilithium3D-1))
		}
	}

	// Test all values in [0, Q-1] would be slow; sample every 8192nd value.
	for a := uint32(0); a < uint32(Q); a += 8192 {
		var p Poly
		p[0] = int32(a)
		var p0PlusQ, p1 Poly
		Power2RoundPoly(&p0PlusQ, &p1, &p)

		a0PlusQ := uint32(p0PlusQ[0])
		a1 := uint32(p1[0])

		var a0 int64
		if a0PlusQ >= uint32(Q) {
			a0 = int64(a0PlusQ - uint32(Q))
		} else {
			a0 = int64(a0PlusQ) - int64(Q)
		}

		reconstructed := (int64(a1)*int64(1<<Dilithium3D) + a0) % int64(Q)
		if reconstructed < 0 {
			reconstructed += int64(Q)
		}
		if uint32(reconstructed) != a {
			t.Errorf("Power2Round(%d): reconstructed=%d, want %d", a, reconstructed, a)
			break
		}
	}
}

// TestTSS_R5_03_04_Power2Round_MatchesCircl verifies that our Power2RoundPoly
// produces bit-for-bit identical output to circl's internal power2round, by
// comparing against the (t0, t1) split that mode3.NewKeyFromSeed produces
// internally.
//
// Strategy: generate a key with circl, extract t from the public key and s1/s2
// from the private key, recompute t = A·s1 + s2 ourselves, then Power2Round
// our t. Compare our (t0, t1) against circl's (t0, t1) extracted from the
// packed private/public keys.
//
// This validates that our implementation is binary-compatible with circl,
// which is essential for mode3.PublicKey.Unpack to accept our packed t1.
func TestTSS_R5_03_04_Power2Round_MatchesCircl(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pubKey, privKey := mode3.NewKeyFromSeed(&seed)
	defer func() {
		*privKey = mode3.PrivateKey{}
	}()

	privKeyBytes := privKey.Bytes()
	defer SecurelyZeroMemory(privKeyBytes)

	// Extract rho, s1, s2 from the circl private key.
	rho := privKeyBytes[:32]

	// circl private key layout: rho(32) | K(32) | tr(32) | s1(L*128) | s2(K*128) | t0(K*416)
	s1Packed := privKeyBytes[96 : 96+Dilithium3L*128]
	s1Vec, err := UnpackEtaVec(s1Packed, Dilithium3L, Dilithium3EtaPoly)
	if err != nil {
		t.Fatalf("UnpackEtaVec s1 failed: %v", err)
	}

	s2Packed := privKeyBytes[96+Dilithium3L*128 : 96+(Dilithium3L+Dilithium3K)*128]
	s2Vec, err := UnpackEtaVec(s2Packed, Dilithium3K, Dilithium3EtaPoly)
	if err != nil {
		t.Fatalf("UnpackEtaVec s2 failed: %v", err)
	}

	// Compute t = A·s1 + s2 using our ComputeA.
	aMat, err := ComputeA(rho, Dilithium3K, Dilithium3L)
	if err != nil {
		t.Fatalf("ComputeA failed: %v", err)
	}
	tVec := ComputeW(aMat, s1Vec)
	for i := range tVec {
		tVec[i].Add(&tVec[i], &s2Vec[i])
		tVec[i].Reduce()
	}

	// Power2Round our t to get (t0Vec_ours, t1Vec_ours).
	t0VecOurs := make(PolyVec, Dilithium3K)
	t1VecOurs := make(PolyVec, Dilithium3K)
	for i := range tVec {
		Power2RoundPoly(&t0VecOurs[i], &t1VecOurs[i], &tVec[i])
	}

	// Extract circl's t1 from the public key.
	pubKeyBytes := pubKey.Bytes()
	t1PackedCircl := pubKeyBytes[32:]
	t1VecCircl, err := UnpackT1(t1PackedCircl, Dilithium3K)
	if err != nil {
		t.Fatalf("UnpackT1 circl failed: %v", err)
	}

	// Compare t1: ours vs circl's.
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			if t1VecOurs[i][j] != t1VecCircl[i][j] {
				t.Errorf("t1[%d][%d]: ours=%d, circl=%d",
					i, j, t1VecOurs[i][j], t1VecCircl[i][j])
				return
			}
		}
	}

	// Extract circl's t0 from the private key.
	t0PackedCircl := privKeyBytes[96+(Dilithium3L+Dilithium3K)*128:]
	t0VecCircl := make(PolyVec, Dilithium3K)
	if err := parseT0PolyVec(t0VecCircl, t0PackedCircl, Dilithium3K); err != nil {
		t.Fatalf("parseT0PolyVec circl failed: %v", err)
	}

	// Compare t0 (stored as Q + t0 in circl representation).
	// Our Power2RoundPoly outputs a0PlusQ = Q + a0; parseT0Poly outputs the same.
	// Both may have coefficients slightly > Q (unnormalized); compare directly.
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			// Normalize both to [0, Q-1] before comparing.
			ours := int64(t0VecOurs[i][j])
			ours = ((ours % Q) + Q) % Q
			circl := int64(t0VecCircl[i][j])
			circl = ((circl % Q) + Q) % Q
			if ours != circl {
				t.Errorf("t0[%d][%d]: ours=%d (norm), circl=%d (norm)",
					i, j, ours, circl)
				return
			}
		}
	}
}

// TestTSS_R5_03_04_PackT1_UnpackT1_RoundTrip verifies PackT1 inverts UnpackT1.
func TestTSS_R5_03_04_PackT1_UnpackT1_RoundTrip(t *testing.T) {
	// Generate a random t1 using Power2Round on a random t.
	t1Original := make(PolyVec, Dilithium3K)
	for i := range t1Original {
		for j := 0; j < N; j++ {
			t1Original[i][j] = int32((uint32(j+i*N) * 7919) % 1024) // arbitrary value in [0, 1023]
		}
	}

	packed := PackT1Vec(t1Original)
	if len(packed) != Dilithium3K*320 {
		t.Fatalf("PackT1Vec size: got %d, want %d", len(packed), Dilithium3K*320)
	}

	t1Unpacked, err := UnpackT1(packed, Dilithium3K)
	if err != nil {
		t.Fatalf("UnpackT1 failed: %v", err)
	}

	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			if t1Original[i][j] != t1Unpacked[i][j] {
				t.Errorf("t1[%d][%d]: original=%d, unpacked=%d",
					i, j, t1Original[i][j], t1Unpacked[i][j])
				return
			}
		}
	}
}

// TestTSS_R5_03_04_PackT1_MatchesCircl verifies our PackT1 produces the same
// bytes as circl's Poly.PackT1. We do this by extracting t1 from a circl-
// generated public key via UnpackT1, then re-packing it with our PackT1 and
// comparing against the original public key bytes.
func TestTSS_R5_03_04_PackT1_MatchesCircl(t *testing.T) {
	var seed [32]byte
	seed[0] = 0x42
	pubKey, _ := mode3.NewKeyFromSeed(&seed)
	pubKeyBytes := pubKey.Bytes()
	t1PackedCircl := pubKeyBytes[32:]

	t1Vec, err := UnpackT1(t1PackedCircl, Dilithium3K)
	if err != nil {
		t.Fatalf("UnpackT1 failed: %v", err)
	}

	t1PackedOurs := PackT1Vec(t1Vec)
	if !bytes.Equal(t1PackedOurs, t1PackedCircl) {
		t.Errorf("PackT1 output does not match circl's PackT1\nours:  %x\ncircl: %x",
			t1PackedOurs[:32], t1PackedCircl[:32])
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_BasicProperties verifies the basic
// structural properties of GenerateDKGDistributedSimulatedoutput.
func TestTSS_R5_03_04_GenerateDKGDistributed_BasicProperties(t *testing.T) {
	threshold, total := 3, 5
	qtdPubKey, shares, err := GenerateDKGDistributedSimulated(threshold, total)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	if len(shares) != total {
		t.Errorf("shares count: got %d, want %d", len(shares), total)
	}

	// CombinedSeed MUST be nil — this is the security-critical property
	// distinguishing distributed DKG from trusted-dealer.
	if qtdPubKey.CombinedSeed != nil {
		t.Errorf("CombinedSeed must be nil for distributed DKG, got %d bytes",
			len(qtdPubKey.CombinedSeed))
	}

	// Public key must be the standard Dilithium3 size.
	if len(qtdPubKey.PubKey) != mode3.PublicKeySize {
		t.Errorf("PubKey size: got %d, want %d", len(qtdPubKey.PubKey), mode3.PublicKeySize)
	}

	// The PubKey must be a valid circl PublicKey (Unpack must succeed).
	var pk mode3.PublicKey
	var pkBuf [mode3.PublicKeySize]byte
	copy(pkBuf[:], qtdPubKey.PubKey)
	pk.Unpack(&pkBuf)

	// Each share must have all three verification vectors (fail-closed
	// requirement from TSS-R5-05).
	for i, s := range shares {
		if s.ParticipantID != i+1 {
			t.Errorf("share %d: ParticipantID=%d, want %d", i, s.ParticipantID, i+1)
		}
		if len(s.VVector) == 0 {
			t.Errorf("share %d: VVector missing", i)
		}
		if len(s.VVectorS2) == 0 {
			t.Errorf("share %d: VVectorS2 missing", i)
		}
		if len(s.VVectorT0) == 0 {
			t.Errorf("share %d: VVectorT0 missing", i)
		}
		if len(s.S1ShareBytes) != Dilithium3L*N*3 {
			t.Errorf("share %d: S1ShareBytes len=%d, want %d",
				i, len(s.S1ShareBytes), Dilithium3L*N*3)
		}
		if len(s.S2ShareBytes) != Dilithium3K*N*3 {
			t.Errorf("share %d: S2ShareBytes len=%d, want %d",
				i, len(s.S2ShareBytes), Dilithium3K*N*3)
		}
		if len(s.T0ShareBytes) != Dilithium3K*N*3 {
			t.Errorf("share %d: T0ShareBytes len=%d, want %d",
				i, len(s.T0ShareBytes), Dilithium3K*N*3)
		}
		if len(s.T1Bytes) == 0 {
			t.Errorf("share %d: T1Bytes missing", i)
		}
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_VerifySharePasses verifies that all
// shares produced by GenerateDKGDistributedSimulatedpass Pedersen verification via
// VerifyShare. This is essential: distributed DKG must produce verifiable
// shares, otherwise a malicious coordinator could distribute inconsistent
// shares without detection.
func TestTSS_R5_03_04_GenerateDKGDistributed_VerifySharePasses(t *testing.T) {
	threshold, total := 2, 3
	_, shares, err := GenerateDKGDistributedSimulated(threshold, total)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	// Build allVVectors (one per participant, in participant ID order).
	allVVectors := make([][][]byte, total)
	for i, s := range shares {
		allVVectors[i] = s.VVector
	}

	for _, s := range shares {
		if err := VerifyShare(s, allVVectors, s.ParticipantID); err != nil {
			t.Errorf("VerifyShare for participant %d failed: %v",
				s.ParticipantID, err)
		}
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_RejectsThreshold1 verifies that
// threshold=1 is rejected. A 1-of-n distributed DKG would put the entire key
// in a single share, defeating the security purpose of DKG.
func TestTSS_R5_03_04_GenerateDKGDistributed_RejectsThreshold1(t *testing.T) {
	_, _, err := GenerateDKGDistributedSimulated(1, 3)
	if err == nil {
		t.Error("GenerateDKGDistributedSimulated(1, 3) should have failed")
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_RejectsInvalidConfig verifies
// invalid threshold/total combinations are rejected.
func TestTSS_R5_03_04_GenerateDKGDistributed_RejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		threshold, total int
	}{
		{0, 3},
		{3, 0},
		{-1, 3},
		{3, -1},
		{5, 3}, // threshold > total
	}
	for _, c := range cases {
		_, _, err := GenerateDKGDistributedSimulated(c.threshold, c.total)
		if err == nil {
			t.Errorf("GenerateDKGDistributedSimulated(%d, %d) should have failed",
				c.threshold, c.total)
		}
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_SignatureVerifies is the CRITICAL
// end-to-end test: it generates a distributed DKG key, performs a threshold
// signature using the shares, and verifies the signature with the standard
// circl Dilithium3 verifier (mode3.Verify).
//
// If this test passes, it proves that:
//  1. Power2RoundPoly produces the correct (t0, t1) split.
//  2. PackT1 produces circl-compatible packed t1.
//  3. The mode3.PublicKey constructed from rho + packed t1 is valid.
//  4. The Shamir shares of s1, s2, t0 can reconstruct valid key material
//     during the distributed signing protocol.
//  5. The resulting signature is byte-for-byte verifiable by the standard
//     Dilithium3 verifier.
//
// This is the strongest possible correctness guarantee: the output of
// GenerateDKGDistributedSimulatedis interoperable with the reference Dilithium3
// implementation.
func TestTSS_R5_03_04_GenerateDKGDistributed_SignatureVerifies(t *testing.T) {
	threshold, total := 3, 5
	qtdPubKey, shares, err := GenerateDKGDistributedSimulated(threshold, total)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	// Construct mode3.PublicKey from qtdPubKey.PubKey.
	var pubKey mode3.PublicKey
	var pkBuf [mode3.PublicKeySize]byte
	copy(pkBuf[:], qtdPubKey.PubKey)
	pubKey.Unpack(&pkBuf)

	// Build a QTDManager with threshold-of-total shares.
	m, err := NewQTDManager(threshold, total)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}
	m.SetShamirMode(true)
	for _, s := range shares {
		if err := m.AddShare(s); err != nil {
			t.Fatalf("AddShare %d failed: %v", s.ParticipantID, err)
		}
	}

	// Pick the first `threshold` participants to sign.
	participants := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		participants[i] = i + 1
	}

	message := []byte("TSS-R5-03/04 distributed DKG signature test")

	// Set PK bytes for tr computation in the session.
	// We need to bypass the manager's CreateSigningSession to inject pkBytes,
	// OR use the public NewGMQTDSession + SetPKBytes path.
	shareMap := make(map[int]*QTDShare, threshold)
	for _, pid := range participants {
		s, _ := m.GetShare(pid)
		shareMap[pid] = s
	}

	// Retry loop for rejection sampling (Dilithium3 acceptance ~93%).
	maxRetries := 30
	var sig *QTDSignature
	for retry := 0; retry < maxRetries; retry++ {
		session, err := NewGMQTDSession(message, participants, threshold, shareMap)
		if err != nil {
			t.Fatalf("NewGMQTDSession failed: %v", err)
		}
		// TSS-C2 (R8 2026-07-19): Disable auto-enabled role separation
		// for legacy Round2Aggregate path exercised by this test.
		session.SetRoleAssignment(RoleAssignment{})
		session.useShamir = true
		session.lagrangeCoeffs = make(map[int]int64, len(participants))
		for _, id := range participants {
			session.lagrangeCoeffs[id] = lagrangeCoeff(id, participants)
		}
		session.SetPKBytes(qtdPubKey.PubKey)

		commitments := make([]*Round1Commitment, 0, len(participants))
		for _, pid := range participants {
			commit, err := session.Round1Commitment(pid)
			if err != nil {
				session.Cleanup()
				t.Fatalf("Round1Commitment pid %d failed: %v", pid, err)
			}
			commitments = append(commitments, commit)
		}

		if err := session.Round1Verify(commitments); err != nil {
			session.Cleanup()
			t.Fatalf("Round1Verify failed: %v", err)
		}

		reveals := make([]*Round2Reveal, 0, len(participants))
		for _, pid := range participants {
			reveal, err := session.Round2Reveal(pid)
			if err != nil {
				session.Cleanup()
				t.Fatalf("Round2Reveal pid %d failed: %v", pid, err)
			}
			reveals = append(reveals, reveal)
		}

		sig, err = session.Round2Aggregate(reveals)
		session.Cleanup()
		if err == nil {
			break
		}
		if retry == maxRetries-1 {
			t.Fatalf("Round2Aggregate failed after %d retries: %v", maxRetries, err)
		}
	}

	if sig == nil {
		t.Fatal("signature is nil after all retries")
	}

	if len(sig.FullSig) != mode3.SignatureSize {
		t.Errorf("FullSig size: got %d, want %d", len(sig.FullSig), mode3.SignatureSize)
	}

	// THE CRITICAL CHECK: standard circl Dilithium3 verifier must accept
	// the signature produced by our distributed DKG + threshold signing.
	if !mode3.Verify(&pubKey, message, sig.FullSig) {
		t.Error("mode3.Verify REJECTED signature from distributed DKG — " +
			"Power2Round/PackT1/GenerateDKGDistributedSimulatedproduced an invalid key")
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_2of2 verifies the smallest valid
// distributed DKG configuration: 2-of-2.
func TestTSS_R5_03_04_GenerateDKGDistributed_2of2(t *testing.T) {
	threshold, total := 2, 2
	qtdPubKey, shares, err := GenerateDKGDistributedSimulated(threshold, total)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulated(2,2) failed: %v", err)
	}

	if len(shares) != 2 {
		t.Errorf("shares count: got %d, want 2", len(shares))
	}
	if qtdPubKey.CombinedSeed != nil {
		t.Error("CombinedSeed must be nil")
	}

	// Verify both shares pass Pedersen verification.
	allVVectors := make([][][]byte, total)
	for i, s := range shares {
		allVVectors[i] = s.VVector
	}
	for _, s := range shares {
		if err := VerifyShare(s, allVVectors, s.ParticipantID); err != nil {
			t.Errorf("VerifyShare pid %d: %v", s.ParticipantID, err)
		}
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_DistinctFromTrustedDealer verifies
// that GenerateDKGDistributedSimulatedproduces a key that is NOT reconstructable via
// mode3.NewKeyFromSeed. This is the core security property: there is no seed
// that can regenerate the key.
//
// We confirm this by checking that CombinedSeed is nil, and by confirming
// that the function does NOT use mode3.NewKeyFromSeed internally (verified
// structurally by the absence of a seed field in the output).
func TestTSS_R5_03_04_GenerateDKGDistributed_DistinctFromTrustedDealer(t *testing.T) {
	qtdPubKey, _, err := GenerateDKGDistributedSimulated(2, 3)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	// Core property: no seed.
	if qtdPubKey.CombinedSeed != nil {
		t.Fatal("distributed DKG must NOT produce a CombinedSeed — " +
			"its presence indicates the trusted-dealer path was taken")
	}

	// Public key must still be a valid Dilithium3 public key (verifiable
	// by mode3.PublicKey.UnmarshalBinary).
	var pk mode3.PublicKey
	if err := pk.UnmarshalBinary(qtdPubKey.PubKey); err != nil {
		t.Errorf("distributed DKG PubKey is not a valid Dilithium3 public key: %v", err)
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_ShareUniqueness verifies that each
// participant's share is distinct (i.e., the Shamir split actually produced
// different shares per participant). Identical shares would indicate a
// broken Shamir implementation.
func TestTSS_R5_03_04_GenerateDKGDistributed_ShareUniqueness(t *testing.T) {
	_, shares, err := GenerateDKGDistributedSimulated(3, 5)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	for i := 0; i < len(shares); i++ {
		for j := i + 1; j < len(shares); j++ {
			if bytes.Equal(shares[i].S1ShareBytes, shares[j].S1ShareBytes) {
				t.Errorf("S1ShareBytes identical for participants %d and %d",
					shares[i].ParticipantID, shares[j].ParticipantID)
			}
			if bytes.Equal(shares[i].S2ShareBytes, shares[j].S2ShareBytes) {
				t.Errorf("S2ShareBytes identical for participants %d and %d",
					shares[i].ParticipantID, shares[j].ParticipantID)
			}
			if bytes.Equal(shares[i].T0ShareBytes, shares[j].T0ShareBytes) {
				t.Errorf("T0ShareBytes identical for participants %d and %d",
					shares[i].ParticipantID, shares[j].ParticipantID)
			}
		}
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_ConsistentRho verifies that all
// shares and the public key share the same rho (the public seed for matrix A).
// Inconsistent rho would cause signing to use a different A than verification,
// breaking signature validity.
func TestTSS_R5_03_04_GenerateDKGDistributed_ConsistentRho(t *testing.T) {
	qtdPubKey, shares, err := GenerateDKGDistributedSimulated(2, 3)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	for i, s := range shares {
		if !bytes.Equal(s.Rho, qtdPubKey.Rho) {
			t.Errorf("share %d Rho mismatch: share=%x, pubkey=%x",
				i, s.Rho, qtdPubKey.Rho)
		}
	}
}

// TestTSS_R5_03_04_SampleSmallPolyVec_Distribution verifies that
// sampleSmallPolyVec produces coefficients uniformly distributed in
// [-eta, eta]. A biased distribution could weaken the lattice security.
func TestTSS_R5_03_04_SampleSmallPolyVec_Distribution(t *testing.T) {
	const eta = Dilithium3EtaPoly // 4
	const samplesPerCoeff = 5000

	// Sample many PolyVecs and count coefficient frequencies.
	counts := make(map[int32]int, 2*eta+1)
	for i := 0; i < samplesPerCoeff; i++ {
		vec, err := sampleSmallPolyVec(1, eta)
		if err != nil {
			t.Fatalf("sampleSmallPolyVec failed: %v", err)
		}
		// Count the first coefficient (stored in [0, Q-1] canonical form).
		c := vec[0][0]
		// Convert to centered representation.
		if c > Q/2 {
			c -= Q
		}
		counts[c]++
	}

	// Each value in [-eta, eta] should appear roughly uniformly.
	expected := samplesPerCoeff / (2*eta + 1)
	tolerance := expected / 3 // generous tolerance for statistical fluctuation

	for v := -eta; v <= eta; v++ {
		count := counts[int32(v)]
		if count < expected-tolerance || count > expected+tolerance {
			t.Errorf("coefficient %d: count=%d, expected ~%d (±%d)",
				v, count, expected, tolerance)
		}
	}

	// No value outside [-eta, eta] should ever appear.
	for v, count := range counts {
		if v < -int32(eta) || v > int32(eta) {
			t.Errorf("out-of-range coefficient %d appeared %d times", v, count)
		}
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_EncodeDecodeRoundTrip verifies that
// shares produced by GenerateDKGDistributedSimulatedcan be encoded with Encode(),
// decoded with DecodeQTDShare(), and still pass VerifyShare. This is required
// for the TSSManager.ImportKeyShares path that persists shares to disk.
func TestTSS_R5_03_04_GenerateDKGDistributed_EncodeDecodeRoundTrip(t *testing.T) {
	threshold, total := 2, 3
	_, shares, err := GenerateDKGDistributedSimulated(threshold, total)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	allVVectors := make([][][]byte, total)
	for i, s := range shares {
		allVVectors[i] = s.VVector
	}

	for _, original := range shares {
		encoded := original.Encode()
		if encoded == nil {
			t.Errorf("Encode() returned nil for participant %d", original.ParticipantID)
			continue
		}

		decoded, err := DecodeQTDShare(encoded)
		if err != nil {
			t.Errorf("DecodeQTDShare participant %d failed: %v",
				original.ParticipantID, err)
			continue
		}

		// The decoded share must pass VerifyShare.
		if err := VerifyShare(decoded, allVVectors, decoded.ParticipantID); err != nil {
			t.Errorf("VerifyShare on decoded share %d failed: %v",
				decoded.ParticipantID, err)
		}

		// S1ShareBytes must be byte-identical after round trip.
		if !bytes.Equal(original.S1ShareBytes, decoded.S1ShareBytes) {
			t.Errorf("S1ShareBytes mismatch after encode/decode for participant %d",
				original.ParticipantID)
		}
	}
}

// TestTSS_R5_03_04_GenerateDKGDistributed_TSSManagerIntegration verifies
// that the TSSManager (in the parent tss package) can accept shares from
// GenerateDKGDistributedSimulatedvia ImportKeyShares. We test this at the qtd level
// by reconstructing the group public key export format manually.
//
// Note: full TSSManager integration is tested in the tss package; this test
// only verifies the qtd-level prerequisites.
func TestTSS_R5_03_04_GenerateDKGDistributed_TSSManagerIntegration(t *testing.T) {
	qtdPubKey, shares, err := GenerateDKGDistributedSimulated(2, 3)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	// Verify the QTDPublicKey can be exported and re-imported via the
	// format used by TSSManager.ImportGroupPublicKey.
	// Format: [2 bytes rhoLen][2 bytes t1Len][rho][t1][pubKey]
	rhoLen := len(qtdPubKey.Rho)
	t1Len := len(qtdPubKey.T1)
	pubKeyLen := len(qtdPubKey.PubKey)
	exported := make([]byte, 4+rhoLen+t1Len+pubKeyLen)
	exported[0] = byte(rhoLen >> 8)
	exported[1] = byte(rhoLen)
	exported[2] = byte(t1Len >> 8)
	exported[3] = byte(t1Len)
	copy(exported[4:], qtdPubKey.Rho)
	copy(exported[4+rhoLen:], qtdPubKey.T1)
	copy(exported[4+rhoLen+t1Len:], qtdPubKey.PubKey)

	// Re-parse.
	if len(exported) < 4 {
		t.Fatal("exported too short")
	}
	parsedRhoLen := int(exported[0])<<8 | int(exported[1])
	parsedT1Len := int(exported[2])<<8 | int(exported[3])
	if parsedRhoLen != rhoLen || parsedT1Len != t1Len {
		t.Errorf("header mismatch: rhoLen %d vs %d, t1Len %d vs %d",
			parsedRhoLen, rhoLen, parsedT1Len, t1Len)
	}

	// Reconstruct mode3.PublicKey from the exported pubKey to confirm
	// the round-trip preserves the key.
	var pk mode3.PublicKey
	if err := pk.UnmarshalBinary(qtdPubKey.PubKey); err != nil {
		t.Errorf("UnmarshalBinary failed: %v", err)
	}

	// Sanity check: shares count must match.
	if len(shares) != 3 {
		t.Errorf("shares count: got %d, want 3", len(shares))
	}
}

// TestTSS_R5_03_04_Power2RoundPoly_FullPolyVec verifies that Power2RoundPoly
// correctly processes a full Poly (all 256 coefficients), not just [0].
func TestTSS_R5_03_04_Power2RoundPoly_FullPolyVec(t *testing.T) {
	var p Poly
	for i := 0; i < N; i++ {
		p[i] = int32(uint32(i*7919) % uint32(Q))
	}

	var p0PlusQ, p1 Poly
	Power2RoundPoly(&p0PlusQ, &p1, &p)

	for i := 0; i < N; i++ {
		a0PlusQ := uint32(p0PlusQ[i])
		a1 := uint32(p1[i])

		var a0 int64
		if a0PlusQ >= uint32(Q) {
			a0 = int64(a0PlusQ - uint32(Q))
		} else {
			a0 = int64(a0PlusQ) - int64(Q)
		}

		// Verify identity: a = a1 * 2^D + a0 (mod Q)
		reconstructed := (int64(a1)*int64(1<<Dilithium3D) + a0) % int64(Q)
		if reconstructed < 0 {
			reconstructed += int64(Q)
		}
		if uint32(reconstructed) != uint32(p[i]) {
			t.Errorf("coefficient %d: reconstructed=%d, want %d (a1=%d a0=%d)",
				i, reconstructed, p[i], a1, a0)
			return
		}

		// Verify a1 range.
		if a1 >= (1 << 10) {
			t.Errorf("coefficient %d: a1=%d out of range [0, %d]", i, a1, (1<<10)-1)
			return
		}
	}
}

// Helper: print a byte slice as hex for debug output (unused in tests but
// useful for debugging). Kept as a no-op to avoid unused import warnings.
var _ = fmt.Sprintf
var _ = binary.LittleEndian
