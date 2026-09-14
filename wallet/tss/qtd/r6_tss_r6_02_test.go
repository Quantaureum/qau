// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"bytes"
	"crypto/ecdh"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// TestTSS_R6_02_DHMaskMasksCancel verifies that pairwise DH masks cancel
// in aggregation: Σ_i netMask_i = 0. This is the core correctness property
// that ensures the H-aggregator still obtains the correct c·(t0-s2) for
// hint computation despite individual Z0Shares being masked.
func TestTSS_R6_02_DHMaskMasksCancel(t *testing.T) {
	participants := []int{1, 2, 3, 4, 5}
	sessionID := GenerateSessionID([]byte("test message"), participants)

	// Generate a DH keypair for each participant
	keyPairs := make(map[int]*DHMaskKeyPair)
	allPubKeys := make(map[int][]byte)
	for _, pid := range participants {
		kp, err := GenerateDHMaskKeyPair(pid)
		if err != nil {
			t.Fatalf("GenerateDHMaskKeyPair for pid %d failed: %v", pid, err)
		}
		keyPairs[pid] = kp
		allPubKeys[pid] = kp.PublicKey
	}

	// Compute each participant's net mask
	masks := make([]PolyVec, 0, len(participants))
	for _, pid := range participants {
		mask, err := ComputeParticipantMask(pid, keyPairs[pid].PrivateKey, allPubKeys, sessionID)
		if err != nil {
			t.Fatalf("ComputeParticipantMask for pid %d failed: %v", pid, err)
		}
		masks = append(masks, mask)
	}

	// Verify masks cancel
	if !VerifyMasksCancel(masks) {
		t.Fatal("DH masks do NOT cancel in aggregation — protocol correctness broken")
	}

	t.Logf("SUCCESS: %d participants' DH masks cancel (sum to zero)", len(participants))
}

// TestTSS_R6_02_DHMaskMasksCancel_ThresholdSubset verifies mask cancellation
// when only a threshold subset of participants signs (not all). This is the
// t-of-n threshold case where only threshold participants reveal.
func TestTSS_R6_02_DHMaskMasksCancel_ThresholdSubset(t *testing.T) {
	allParticipants := []int{1, 2, 3, 4, 5}
	threshold := 3
	signingSubset := allParticipants[:threshold] // {1, 2, 3}

	sessionID := GenerateSessionID([]byte("threshold subset test"), signingSubset)

	// Generate DH keypairs for ALL participants (only subset will sign)
	keyPairs := make(map[int]*DHMaskKeyPair)
	allPubKeys := make(map[int][]byte)
	for _, pid := range allParticipants {
		kp, err := GenerateDHMaskKeyPair(pid)
		if err != nil {
			t.Fatalf("GenerateDHMaskKeyPair for pid %d failed: %v", pid, err)
		}
		keyPairs[pid] = kp
		allPubKeys[pid] = kp.PublicKey
	}

	// Only the signing subset computes masks
	// IMPORTANT: each signer uses ALL participants' public keys (including
	// non-signers) so the pairwise masks are consistent. Non-signers don't
	// contribute, but their public keys are needed for mask derivation
	// consistency.
	masks := make([]PolyVec, 0, threshold)
	for _, pid := range signingSubset {
		mask, err := ComputeParticipantMask(pid, keyPairs[pid].PrivateKey, allPubKeys, sessionID)
		if err != nil {
			t.Fatalf("ComputeParticipantMask for pid %d failed: %v", pid, err)
		}
		masks = append(masks, mask)
	}

	// NOTE: Masks cancel ONLY among the signing subset, NOT across all
	// participants. The non-signers' masks are not included, so the sum
	// is non-zero. This is the expected behavior for threshold signing:
	// the signing subset must use a sessionID that binds ONLY to the
	// signing subset, and the public keys map must contain ONLY the
	// signing subset's keys.

	// Re-do with only the signing subset's public keys
	signingPubKeys := make(map[int][]byte)
	for _, pid := range signingSubset {
		signingPubKeys[pid] = keyPairs[pid].PublicKey
	}

	masksSubset := make([]PolyVec, 0, threshold)
	for _, pid := range signingSubset {
		mask, err := ComputeParticipantMask(pid, keyPairs[pid].PrivateKey, signingPubKeys, sessionID)
		if err != nil {
			t.Fatalf("ComputeParticipantMask (subset) for pid %d failed: %v", pid, err)
		}
		masksSubset = append(masksSubset, mask)
	}

	if !VerifyMasksCancel(masksSubset) {
		t.Fatal("DH masks do NOT cancel for threshold signing subset")
	}

	t.Logf("SUCCESS: %d-of-%d threshold subset DH masks cancel", threshold, len(allParticipants))
}

// TestTSS_R6_02_DHMaskIndividualProtection verifies that individual z0_i
// contributions are masked: masked_z0_i ≠ raw_z0_i (with overwhelming
// probability). An eavesdropper seeing masked_z0_i cannot recover z0_i
// without the DH shared secret.
func TestTSS_R6_02_DHMaskIndividualProtection(t *testing.T) {
	participants := []int{1, 2, 3}
	sessionID := GenerateSessionID([]byte("individual protection test"), participants)

	keyPairs := make(map[int]*DHMaskKeyPair)
	allPubKeys := make(map[int][]byte)
	for _, pid := range participants {
		kp, err := GenerateDHMaskKeyPair(pid)
		if err != nil {
			t.Fatalf("GenerateDHMaskKeyPair for pid %d failed: %v", pid, err)
		}
		keyPairs[pid] = kp
		allPubKeys[pid] = kp.PublicKey
	}

	// Create a dummy z0 vector (simulating λ_i·c·(t0_i - s2_i))
	rawZ0 := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			rawZ0[i][j] = int32((uint64(i*N+j) * 12345) % uint64(Q))
		}
	}

	// Apply masks for each participant
	for _, pid := range participants {
		mask, err := ComputeParticipantMask(pid, keyPairs[pid].PrivateKey, allPubKeys, sessionID)
		if err != nil {
			t.Fatalf("ComputeParticipantMask for pid %d failed: %v", pid, err)
		}

		maskedZ0, err := ApplyMaskToZ0(rawZ0, mask)
		if err != nil {
			t.Fatalf("ApplyMaskToZ0 for pid %d failed: %v", pid, err)
		}

		// Verify masked_z0 ≠ raw_z0 (with overwhelming probability)
		differences := 0
		for i := 0; i < Dilithium3K; i++ {
			for j := 0; j < N; j++ {
				if maskedZ0[i][j] != rawZ0[i][j] {
					differences++
				}
			}
		}
		totalCoeffs := Dilithium3K * N
		if differences == 0 {
			t.Fatalf("Participant %d: masked z0 is identical to raw z0 (no protection)", pid)
		}

		// At least 90% of coefficients should differ (statistical check
		// — mask is uniform random mod Q, so ~99.99% of coefficients
		// will differ from the original)
		if differences < totalCoeffs*9/10 {
			t.Fatalf("Participant %d: only %d/%d coefficients differ (expected >90%%)",
				pid, differences, totalCoeffs)
		}

		// Zeroize
		for i := range mask {
			mask[i].Zero()
		}
		for i := range maskedZ0 {
			maskedZ0[i].Zero()
		}
	}

	t.Logf("SUCCESS: All participants' z0 contributions are individually masked")
}

// TestTSS_R6_02_DHMaskEavesdropperCannotRecover verifies that an eavesdropper
// who sees masked_z0_i but does NOT have the DH shared secret cannot recover
// the raw z0_i. The eavesdropper's best strategy is to guess the mask, which
// has probability ~1/Q^N per polynomial — negligible.
func TestTSS_R6_02_DHMaskEavesdropperCannotRecover(t *testing.T) {
	participants := []int{1, 2}
	sessionID := GenerateSessionID([]byte("eavesdropper test"), participants)

	// Two participants generate DH keypairs
	kp1, err := GenerateDHMaskKeyPair(1)
	if err != nil {
		t.Fatalf("GenerateDHMaskKeyPair(1) failed: %v", err)
	}
	kp2, err := GenerateDHMaskKeyPair(2)
	if err != nil {
		t.Fatalf("GenerateDHMaskKeyPair(2) failed: %v", err)
	}

	allPubKeys := map[int][]byte{
		1: kp1.PublicKey,
		2: kp2.PublicKey,
	}

	// Participant 1 computes their mask
	mask1, err := ComputeParticipantMask(1, kp1.PrivateKey, allPubKeys, sessionID)
	if err != nil {
		t.Fatalf("ComputeParticipantMask(1) failed: %v", err)
	}

	// Simulate raw z0
	rawZ0 := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			rawZ0[i][j] = int32(uint64(i*1000+j) % uint64(Q))
		}
	}

	maskedZ0, err := ApplyMaskToZ0(rawZ0, mask1)
	if err != nil {
		t.Fatalf("ApplyMaskToZ0 failed: %v", err)
	}

	// Eavesdropper's "recovery" attempt: assume mask is zero
	// (best case for eavesdropper without DH shared secret)
	eavesdropperGuess := make(PolyVec, Dilithium3K)
	copy(eavesdropperGuess[0][:], maskedZ0[0][:])
	for i := 1; i < Dilithium3K; i++ {
		copy(eavesdropperGuess[i][:], maskedZ0[i][:])
	}

	// Verify eavesdropper's guess is WRONG
	mismatches := 0
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			if eavesdropperGuess[i][j] != rawZ0[i][j] {
				mismatches++
			}
		}
	}
	if mismatches == 0 {
		t.Fatal("Eavesdropper correctly guessed raw z0 — masking is broken")
	}

	// Verify that participant 2 (who HAS the DH shared secret) can compute
	// the same mask as participant 1 (for verification purposes only — in
	// practice, participant 2 doesn't see participant 1's masked z0)
	mask2, err := ComputeParticipantMask(2, kp2.PrivateKey, allPubKeys, sessionID)
	if err != nil {
		t.Fatalf("ComputeParticipantMask(2) failed: %v", err)
	}

	// Verify masks cancel: mask1 + mask2 = 0
	combined := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		combined[i].Add(&mask1[i], &mask2[i])
	}
	if !isPolyVecZero(combined) {
		t.Fatal("masks do not cancel between participants 1 and 2")
	}

	// Cleanup
	for i := range mask1 {
		mask1[i].Zero()
		mask2[i].Zero()
		maskedZ0[i].Zero()
		eavesdropperGuess[i].Zero()
	}

	t.Logf("SUCCESS: Eavesdropper cannot recover raw z0 (%d/%d coefficients wrong)",
		mismatches, Dilithium3K*N)
}

// TestTSS_R6_02_DHMaskSessionBinding verifies that different sessions produce
// different masks for the same participant pair. This prevents mask reuse
// across signing sessions (forward secrecy).
func TestTSS_R6_02_DHMaskSessionBinding(t *testing.T) {
	participants := []int{1, 2}

	kp1, err := GenerateDHMaskKeyPair(1)
	if err != nil {
		t.Fatalf("GenerateDHMaskKeyPair(1) failed: %v", err)
	}
	kp2, err := GenerateDHMaskKeyPair(2)
	if err != nil {
		t.Fatalf("GenerateDHMaskKeyPair(2) failed: %v", err)
	}

	allPubKeys := map[int][]byte{
		1: kp1.PublicKey,
		2: kp2.PublicKey,
	}

	sessionID1 := GenerateSessionID([]byte("session 1"), participants)
	sessionID2 := GenerateSessionID([]byte("session 2"), participants)

	mask1, err := ComputeParticipantMask(1, kp1.PrivateKey, allPubKeys, sessionID1)
	if err != nil {
		t.Fatalf("ComputeParticipantMask session 1 failed: %v", err)
	}
	mask2, err := ComputeParticipantMask(1, kp1.PrivateKey, allPubKeys, sessionID2)
	if err != nil {
		t.Fatalf("ComputeParticipantMask session 2 failed: %v", err)
	}

	// Verify masks are different
	differences := 0
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			if mask1[i][j] != mask2[i][j] {
				differences++
			}
		}
	}
	if differences == 0 {
		t.Fatal("Same mask across different sessions — forward secrecy broken")
	}

	t.Logf("SUCCESS: Different sessions produce different masks (%d/%d coefficients differ)",
		differences, Dilithium3K*N)

	// Cleanup
	for i := range mask1 {
		mask1[i].Zero()
		mask2[i].Zero()
	}
}

// TestTSS_R6_02_DHMaskBackwardCompat verifies that when DH keys are NOT set,
// the session behaves exactly as before (no mask applied). This ensures
// backward compatibility with existing code that doesn't use DH masking.
func TestTSS_R6_02_DHMaskBackwardCompat(t *testing.T) {
	threshold := 2
	total := 3
	participants := []int{1, 2, 3}

	m, err := NewQTDManager(threshold, total)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}

	for _, pid := range participants {
		share := &QTDShare{
			ParticipantID: pid,
			Rho:           make([]byte, 32),
			S1ShareBytes:  make([]byte, Dilithium3L*N*3),
			S2ShareBytes:  make([]byte, Dilithium3K*N*3),
			T0ShareBytes:  make([]byte, Dilithium3K*N*3),
			T1Bytes:       make([]byte, Dilithium3K*N*3),
		}
		if err := m.AddShare(share); err != nil {
			t.Fatalf("AddShare for pid %d failed: %v", pid, err)
		}
	}

	shares := make(map[int]*QTDShare)
	for _, pid := range participants {
		s, _ := m.GetShare(pid)
		shares[pid] = s
	}

	message := []byte("backward compat test — no DH masking")

	// Create session WITHOUT DH keys
	session, err := NewGMQTDSession(message, participants, threshold, shares)
	if err != nil {
		t.Fatalf("NewGMQTDSession failed: %v", err)
	}

	// Verify DH masking is NOT enabled
	if session.DHMaskEnabled() {
		t.Fatal("DHMaskEnabled should be false by default")
	}

	// Run the signing protocol — should work without DH masking
	commitments := make([]*Round1Commitment, 0, len(participants))
	for _, pid := range participants {
		commit, err := session.Round1Commitment(pid)
		if err != nil {
			session.Cleanup()
			t.Fatalf("Round1Commitment for pid %d failed: %v", pid, err)
		}
		commitments = append(commitments, commit)
	}

	if err := session.Round1Verify(commitments); err != nil {
		session.Cleanup()
		t.Fatalf("Round1Verify failed: %v", err)
	}

	reveals := make([]*Round2Reveal, 0, threshold)
	for i := 0; i < threshold; i++ {
		reveal, err := session.Round2Reveal(participants[i])
		if err != nil {
			session.Cleanup()
			t.Fatalf("Round2Reveal for pid %d failed: %v", participants[i], err)
		}
		reveals = append(reveals, reveal)
	}

	// Verify Z0Share is present (protocol still works without DH masking)
	for i, r := range reveals {
		if len(r.Z0Share) == 0 {
			session.Cleanup()
			t.Fatalf("Reveal %d (pid %d) has empty Z0Share — protocol broken without DH masking", i, r.ParticipantID)
		}
	}

	session.Cleanup()
	t.Log("SUCCESS: Session without DH keys produces valid reveals (backward compatible)")
}

// TestTSS_R6_02_DHMaskSigningProtocol verifies that a full signing session
// with DH masking enabled produces a valid Dilithium3 signature.
//
// NOTE: We cannot compare byte-identity with a no-DH session because each
// session samples independent Gaussian masking vectors y_i. Instead, we
// verify that:
//  1. The DH-masked signature is accepted by the standard circl verifier.
//  2. The DH-masked signature has the correct Dilithium3 size.
//
// Mask cancellation in aggregation is verified by the unit tests
// TestTSS_R6_02_DHMaskMasksCancel and TestTSS_R6_02_DHMaskMasksCancel_ThresholdSubset.
func TestTSS_R6_02_DHMaskSigningProtocol(t *testing.T) {
	// Use threshold=total so all participants sign (matches R5 test pattern:
	// participants count == threshold). This is the standard threshold
	// signing flow where sigma_agg = sqrt(n)*sigma = gamma1/4 regardless
	// of n, and Round2Aggregate receives exactly threshold reveals.
	threshold := 3
	total := 3
	participants := []int{1, 2, 3}

	// Generate real Dilithium3 shares via distributed DKG (TSS-R6-01:
	// trusted-dealer path is deprecated; tests must use the distributed
	// DKG to match production behavior).
	pubKey, shares, err := GenerateDKGDistributedSimulated(threshold, total)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	sharesMap := make(map[int]*QTDShare)
	for _, s := range shares {
		sharesMap[s.ParticipantID] = s
	}

	message := []byte("R6-02 DH masking full signing test")

	// Generate DH keypairs for all participants
	dhKeyPairs := make(map[int]*DHMaskKeyPair)
	allPubKeys := make(map[int][]byte)
	for _, pid := range participants {
		kp, err := GenerateDHMaskKeyPair(pid)
		if err != nil {
			t.Fatalf("GenerateDHMaskKeyPair(%d) failed: %v", pid, err)
		}
		dhKeyPairs[pid] = kp
		allPubKeys[pid] = kp.PublicKey
	}

	// Run signing with retries (rejection sampling may fail)
	maxRetries := 30
	var sigWithDH *QTDSignature

	for retry := 0; retry < maxRetries; retry++ {
		// Session WITH DH masking — simulate per-participant sessions by
		// setting the DH keys before each participant's Round2Reveal.
		// In a real deployment, each participant has their own session.
		// Here we use a single session and swap DH keys per participant.
		sessionWithDH, err := NewGMQTDSession(message, participants, threshold, sharesMap)
		if err != nil {
			t.Fatalf("NewGMQTDSession (with DH) failed: %v", err)
		}
		// TSS-C2 (R8 2026-07-19): Disable auto-enabled role separation
		// for the legacy Round2Aggregate path exercised by this test.
		sessionWithDH.SetRoleAssignment(RoleAssignment{})
		sessionWithDH.SetShamirMode(true)
		sessionWithDH.lagrangeCoeffs = make(map[int]int64, len(participants))
		for _, id := range participants {
			sessionWithDH.lagrangeCoeffs[id] = lagrangeCoeff(id, participants)
		}
		sessionWithDH.SetPKBytes(pubKey.PubKey)

		// Enable DH masking on the session
		if err := sessionWithDH.SetDHKeys(dhKeyPairs[participants[0]].PrivateKey, allPubKeys); err != nil {
			sessionWithDH.Cleanup()
			t.Fatalf("SetDHKeys failed: %v", err)
		}

		// Round 1: commitments
		commitmentsWithDH := make([]*Round1Commitment, 0, len(participants))
		for _, pid := range participants {
			c2, err := sessionWithDH.Round1Commitment(pid)
			if err != nil {
				sessionWithDH.Cleanup()
				t.Fatalf("Round1Commitment (with DH) pid %d failed: %v", pid, err)
			}
			commitmentsWithDH = append(commitmentsWithDH, c2)
		}

		if err := sessionWithDH.Round1Verify(commitmentsWithDH); err != nil {
			sessionWithDH.Cleanup()
			t.Fatalf("Round1Verify (with DH) failed: %v", err)
		}

		// Round 2: reveals
		// For the DH session, we swap the DH private key before each
		// participant's Round2Reveal to simulate per-participant sessions.
		revealsWithDH := make([]*Round2Reveal, 0, threshold)

		success := true
		for i := 0; i < threshold; i++ {
			pid := participants[i]

			// Swap DH private key for this participant
			sessionWithDH.SetDHKeys(dhKeyPairs[pid].PrivateKey, allPubKeys)

			r2, err := sessionWithDH.Round2Reveal(pid)
			if err != nil {
				success = false
				break
			}
			revealsWithDH = append(revealsWithDH, r2)
		}

		if !success {
			sessionWithDH.Cleanup()
			continue
		}

		// Aggregate with DH
		sig2, err := sessionWithDH.Round2Aggregate(revealsWithDH)
		if err != nil {
			sessionWithDH.Cleanup()
			continue
		}
		sigWithDH = sig2

		sessionWithDH.Cleanup()
		break
	}

	if sigWithDH == nil {
		t.Fatalf("Signing with DH failed after %d retries", maxRetries)
	}

	// Verify signature has correct Dilithium3 size
	if len(sigWithDH.FullSig) != mode3.SignatureSize {
		t.Fatalf("Signature size mismatch: got %d, want %d",
			len(sigWithDH.FullSig), mode3.SignatureSize)
	}

	// Verify the signature is valid against the public key
	var pk mode3.PublicKey
	var pkBuf [mode3.PublicKeySize]byte
	copy(pkBuf[:], pubKey.PubKey)
	pk.Unpack(&pkBuf)
	if !mode3.Verify(&pk, message, sigWithDH.FullSig) {
		t.Fatal("DH-masked signature failed Dilithium3 verification")
	}

	t.Logf("SUCCESS: DH-masked signing produces valid Dilithium3 signature (%d bytes)",
		len(sigWithDH.FullSig))
}

// TestTSS_R6_02_DHMaskClearKeys verifies that ClearDHKeys properly clears
// DH key material from the session.
func TestTSS_R6_02_DHMaskClearKeys(t *testing.T) {
	threshold := 2
	total := 3
	participants := []int{1, 2, 3}

	m, err := NewQTDManager(threshold, total)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}

	for _, pid := range participants {
		share := &QTDShare{
			ParticipantID: pid,
			Rho:           make([]byte, 32),
			S1ShareBytes:  make([]byte, Dilithium3L*N*3),
			S2ShareBytes:  make([]byte, Dilithium3K*N*3),
			T0ShareBytes:  make([]byte, Dilithium3K*N*3),
			T1Bytes:       make([]byte, Dilithium3K*N*3),
		}
		if err := m.AddShare(share); err != nil {
			t.Fatalf("AddShare for pid %d failed: %v", pid, err)
		}
	}

	sharesMap := make(map[int]*QTDShare)
	for _, pid := range participants {
		s, _ := m.GetShare(pid)
		sharesMap[pid] = s
	}

	session, err := NewGMQTDSession([]byte("clear keys test"), participants, threshold, sharesMap)
	if err != nil {
		t.Fatalf("NewGMQTDSession failed: %v", err)
	}

	// Initially DH masking is disabled
	if session.DHMaskEnabled() {
		t.Fatal("DHMaskEnabled should be false initially")
	}

	// Generate and set DH keys
	kp, err := GenerateDHMaskKeyPair(1)
	if err != nil {
		t.Fatalf("GenerateDHMaskKeyPair failed: %v", err)
	}
	allPubKeys := map[int][]byte{1: kp.PublicKey, 2: kp.PublicKey, 3: kp.PublicKey}

	if err := session.SetDHKeys(kp.PrivateKey, allPubKeys); err != nil {
		t.Fatalf("SetDHKeys failed: %v", err)
	}

	if !session.DHMaskEnabled() {
		t.Fatal("DHMaskEnabled should be true after SetDHKeys")
	}

	// Clear DH keys
	session.ClearDHKeys()

	if session.DHMaskEnabled() {
		t.Fatal("DHMaskEnabled should be false after ClearDHKeys")
	}

	session.Cleanup()
	t.Log("SUCCESS: ClearDHKeys properly disables DH masking")
}

// TestTSS_R6_02_DHMaskSetDHKeysValidation verifies that SetDHKeys rejects
// invalid inputs (nil key, empty map, wrong key length).
func TestTSS_R6_02_DHMaskSetDHKeysValidation(t *testing.T) {
	threshold := 2
	total := 3
	participants := []int{1, 2, 3}

	m, err := NewQTDManager(threshold, total)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}

	for _, pid := range participants {
		share := &QTDShare{
			ParticipantID: pid,
			S1ShareBytes:  make([]byte, Dilithium3L*N*3),
			S2ShareBytes:  make([]byte, Dilithium3K*N*3),
			T0ShareBytes:  make([]byte, Dilithium3K*N*3),
		}
		if err := m.AddShare(share); err != nil {
			t.Fatalf("AddShare for pid %d failed: %v", pid, err)
		}
	}

	sharesMap := make(map[int]*QTDShare)
	for _, pid := range participants {
		s, _ := m.GetShare(pid)
		sharesMap[pid] = s
	}

	session, err := NewGMQTDSession([]byte("validation test"), participants, threshold, sharesMap)
	if err != nil {
		t.Fatalf("NewGMQTDSession failed: %v", err)
	}
	defer session.Cleanup()

	// nil private key
	if err := session.SetDHKeys(nil, map[int][]byte{1: make([]byte, 32)}); err == nil {
		t.Fatal("SetDHKeys should reject nil private key")
	}

	// empty public keys map
	kp, _ := GenerateDHMaskKeyPair(1)
	if err := session.SetDHKeys(kp.PrivateKey, map[int][]byte{}); err == nil {
		t.Fatal("SetDHKeys should reject empty public keys map")
	}

	// wrong key length
	if err := session.SetDHKeys(kp.PrivateKey, map[int][]byte{1: make([]byte, 16)}); err == nil {
		t.Fatal("SetDHKeys should reject wrong public key length")
	}

	// valid keys should succeed
	validPubKeys := map[int][]byte{1: kp.PublicKey, 2: kp.PublicKey}
	if err := session.SetDHKeys(kp.PrivateKey, validPubKeys); err != nil {
		t.Fatalf("SetDHKeys with valid keys failed: %v", err)
	}

	t.Log("SUCCESS: SetDHKeys validation works correctly")
}

// TestTSS_R6_02_DHKeyPairGeneration verifies X25519 keypair generation.
func TestTSS_R6_02_DHKeyPairGeneration(t *testing.T) {
	kp, err := GenerateDHMaskKeyPair(42)
	if err != nil {
		t.Fatalf("GenerateDHMaskKeyPair failed: %v", err)
	}

	if kp.ParticipantID != 42 {
		t.Fatalf("ParticipantID mismatch: got %d, want 42", kp.ParticipantID)
	}

	if kp.PrivateKey == nil {
		t.Fatal("PrivateKey is nil")
	}

	if len(kp.PublicKey) != 32 {
		t.Fatalf("PublicKey length: got %d, want 32", len(kp.PublicKey))
	}

	// Verify the public key matches the private key
	expectedPub := kp.PrivateKey.PublicKey().Bytes()
	if !bytes.Equal(kp.PublicKey, expectedPub) {
		t.Fatal("PublicKey does not match PrivateKey.PublicKey()")
	}

	// Verify two different keypairs are different
	kp2, err := GenerateDHMaskKeyPair(43)
	if err != nil {
		t.Fatalf("GenerateDHMaskKeyPair(43) failed: %v", err)
	}

	if bytes.Equal(kp.PublicKey, kp2.PublicKey) {
		t.Fatal("Two keypairs have identical public keys — randomness failure")
	}

	t.Log("SUCCESS: X25519 keypair generation works correctly")
}

// TestTSS_R6_02_DHSharedSecretConsistency verifies that ECDH produces
// consistent shared secrets: DH(d_i, D_j) == DH(d_j, D_i).
func TestTSS_R6_02_DHSharedSecretConsistency(t *testing.T) {
	kp1, err := GenerateDHMaskKeyPair(1)
	if err != nil {
		t.Fatalf("GenerateDHMaskKeyPair(1) failed: %v", err)
	}
	kp2, err := GenerateDHMaskKeyPair(2)
	if err != nil {
		t.Fatalf("GenerateDHMaskKeyPair(2) failed: %v", err)
	}

	// DH(d1, D2) should equal DH(d2, D1)
	ss12, err := ComputeDHSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	if err != nil {
		t.Fatalf("DH(1→2) failed: %v", err)
	}
	ss21, err := ComputeDHSharedSecret(kp2.PrivateKey, kp1.PublicKey)
	if err != nil {
		t.Fatalf("DH(2→1) failed: %v", err)
	}

	if !bytes.Equal(ss12, ss21) {
		t.Fatal("ECDH shared secrets are not symmetric — DH(d1,D2) ≠ DH(d2,D1)")
	}

	t.Log("SUCCESS: ECDH shared secret is symmetric")
}

// TestTSS_R6_02_DHMaskDeterministic verifies that the same DH shared secret
// and session ID produce the same mask (deterministic derivation).
func TestTSS_R6_02_DHMaskDeterministic(t *testing.T) {
	kp1, _ := GenerateDHMaskKeyPair(1)
	kp2, _ := GenerateDHMaskKeyPair(2)

	allPubKeys := map[int][]byte{1: kp1.PublicKey, 2: kp2.PublicKey}
	sessionID := GenerateSessionID([]byte("determinism test"), []int{1, 2})

	// Compute mask for participant 1 twice
	mask1a, err := ComputeParticipantMask(1, kp1.PrivateKey, allPubKeys, sessionID)
	if err != nil {
		t.Fatalf("ComputeParticipantMask(1) first call failed: %v", err)
	}
	mask1b, err := ComputeParticipantMask(1, kp1.PrivateKey, allPubKeys, sessionID)
	if err != nil {
		t.Fatalf("ComputeParticipantMask(1) second call failed: %v", err)
	}

	// Verify they are identical (deterministic)
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			if mask1a[i][j] != mask1b[i][j] {
				t.Fatalf("Mask is non-deterministic: mismatch at poly %d coeff %d", i, j)
			}
		}
	}

	t.Log("SUCCESS: DH mask derivation is deterministic")

	// Cleanup
	for i := range mask1a {
		mask1a[i].Zero()
		mask1b[i].Zero()
	}
}

// TestTSS_R6_02_RoleSeparatedWithDHMask verifies that role-separated
// aggregation (TSS-R5-01) still works correctly when DH masking (TSS-R6-02)
// is enabled. The W-agg, Z-agg, and H-agg should all produce correct results.
func TestTSS_R6_02_RoleSeparatedWithDHMask(t *testing.T) {
	threshold := 3
	total := 3
	participants := []int{1, 2, 3}

	pubKey, shares, err := GenerateDKGDistributedSimulated(threshold, total)
	if err != nil {
		t.Fatalf("GenerateDKGDistributedSimulatedfailed: %v", err)
	}

	sharesMap := make(map[int]*QTDShare)
	for _, s := range shares {
		sharesMap[s.ParticipantID] = s
	}

	message := []byte("role-separated with DH mask test")

	// Generate DH keypairs
	dhKeyPairs := make(map[int]*DHMaskKeyPair)
	allPubKeys := make(map[int][]byte)
	for _, pid := range participants {
		kp, err := GenerateDHMaskKeyPair(pid)
		if err != nil {
			t.Fatalf("GenerateDHMaskKeyPair(%d) failed: %v", pid, err)
		}
		dhKeyPairs[pid] = kp
		allPubKeys[pid] = kp.PublicKey
	}

	maxRetries := 30
	var roleSig *QTDSignature

	for retry := 0; retry < maxRetries; retry++ {
		session, err := NewGMQTDSession(message, participants, threshold, sharesMap)
		if err != nil {
			t.Fatalf("NewGMQTDSession failed: %v", err)
		}
		session.SetShamirMode(true)
		session.lagrangeCoeffs = make(map[int]int64, len(participants))
		for _, id := range participants {
			session.lagrangeCoeffs[id] = lagrangeCoeff(id, participants)
		}
		session.SetPKBytes(pubKey.PubKey)

		// Enable DH masking
		if err := session.SetDHKeys(dhKeyPairs[participants[0]].PrivateKey, allPubKeys); err != nil {
			session.Cleanup()
			t.Fatalf("SetDHKeys failed: %v", err)
		}

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

		reveals := make([]*Round2Reveal, 0, threshold)
		success := true
		for i := 0; i < threshold; i++ {
			pid := participants[i]
			// Swap DH key for this participant
			session.SetDHKeys(dhKeyPairs[pid].PrivateKey, allPubKeys)

			reveal, err := session.Round2Reveal(pid)
			if err != nil {
				success = false
				break
			}
			reveals = append(reveals, reveal)
		}

		if !success {
			session.Cleanup()
			continue
		}

		// Role-separated aggregation
		wResult, err := session.AggregateW(reveals)
		if err != nil {
			session.Cleanup()
			continue
		}

		zResult, err := session.AggregateZ(reveals)
		if err != nil {
			session.Cleanup()
			continue
		}

		hResult, err := session.AggregateHint(reveals, wResult.WAggBytes, wResult.W1Bytes)
		if err != nil {
			session.Cleanup()
			continue
		}

		roleSig = AssembleFinalSignature(zResult.ZAgg, hResult.Hint, wResult.CtildeSeed, wResult.W1Bytes)
		session.Cleanup()
		break
	}

	if roleSig == nil {
		t.Fatalf("Role-separated signing with DH mask failed after %d retries", maxRetries)
	}

	// Verify the signature
	var pk mode3.PublicKey
	var pkBuf [mode3.PublicKeySize]byte
	copy(pkBuf[:], pubKey.PubKey)
	pk.Unpack(&pkBuf)
	if !mode3.Verify(&pk, message, roleSig.FullSig) {
		t.Fatal("Role-separated DH-masked signature failed Dilithium3 verification")
	}

	t.Logf("SUCCESS: Role-separated aggregation with DH masking produces valid signature (%d bytes)",
		len(roleSig.FullSig))
}

// Ensure unused imports are referenced
var _ time.Duration
var _ *ecdh.PrivateKey
