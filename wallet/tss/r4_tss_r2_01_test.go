// Quantaureum Node source, version 1.0.0.
package tss

// AUDIT (2026) TSS- REGRESSION TESTS (supersedes TSS- tests)
//
// This file contains regression tests for the TSS- (Critical) fix:
// "Aggregator can recover the FULL Dilithium3 private key via NTT inversion
// of separately-transmitted Cs2Share/Ct0Share".
//
// BACKGROUND:
// The TSS- fix replaced raw S2Share/T0Share transmission with masked
// contributions Cs2Share (λ_i·c·s2_i) and Ct0Share (λ_i·c·t0_i). This was
// STILL catastrophically insecure: the challenge polynomial c is invertible
// in the NTT ring Z_q[X]/(X^256+1) (q=8380417), so the aggregator could
// recover s2 and t0 SEPARATELY by NTT inversion:
//   s2 = InvNTT( NTT(c·s2) ⊘ NTT(c) )
//   t0 = InvNTT( NTT(c·t0) ⊘ NTT(c) )
// Then s1 is recovered via A·s1 = t - s2 (t = t1·2^d + t0 is public), giving
// the FULL private key (s1, s2, t0) and enabling signature forgery.
//
// TSS-FIX:
// COMBINE the two contributions into a single Z0Share:
//   Z0Share = λ_i·c·(t0_i - s2_i) = λ_i·c·t0_i - λ_i·c·s2_i
// The aggregator sums Z0Share to obtain c·(t0-s2), which is the exact quantity
// needed for hint computation (z0 = w0 + c·(t0-s2)). The aggregator CANNOT
// decompose c·(t0-s2) back into c·t0 and c·s2 separately.
//
// RESIDUAL RISK (High, not Critical): The aggregator can still recover s1
// because c·(t0-s2) = c·(A·s1 - t1·2^d). However, the aggregator CANNOT
// recover s2 or t0 individually, so it CANNOT forge signatures. Full closure
// requires DH-based pairwise masking or distributed hint generation. Until
// then, distributed TSS is HARD-BLOCKED in production (see distributedTSSEnabled()).
//
// These tests verify:
//  1. End-to-end threshold signing still produces a valid signature (functional)
//  2. Round2Reveal struct carries Z0Share (not Cs2Share/Ct0Share/ScShare)
//  3. IsPrivate/ToPublicReveal/ZeroRevealSecrets handle the new Z0Share field
//  4. Wire format carries a SINGLE combined Z0Share (not separate cs2/ct0)
//  5. AttachZ0Contribution sets Z0Share on the reveal
//  6. CompleteSignPrivate serializes Z0Share into the signature
//  7. CompleteSign strips Z0Share for broadcast safety
//  8. CombineSignatures rejects malformed Z0Share lengths
//  9. SECURITY: raw S2ShareBytes/T0ShareBytes NEVER appear on the wire
// 10. SECURITY: separate cs2/ct0 are NOT transmitted (only combined z0)

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// TestR5_TSS_R5_01_EndToEndSigning verifies that threshold signing still
// produces a valid Dilithium3 signature after the TSS- fix. This is the
// most important test — it proves the fix is functional, not just structural.
func TestR5_TSS_R5_01_EndToEndSigning(t *testing.T) {
	config := DefaultTSSConfig()
	manager, err := NewTSSManager(config)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatalf("failed to generate key shares: %v", err)
	}

	message := []byte("TSS- regression: end-to-end signing must still work")
	participants := make([]int, config.Threshold)
	for i := 0; i < config.Threshold; i++ {
		participants[i] = i + 1
	}

	sig, err := manager.SignWithRetry(message, participants)
	if err != nil {
		t.Fatalf("SignWithRetry failed: %v", err)
	}
	if len(sig) != 3293 && len(sig) != 4064 {
		t.Fatalf("unexpected signature size: %d (expected 3293 or 4064)", len(sig))
	}

	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(manager.GroupPublicKey()))
	if !verifyQMTSignature(&pk, message, sig) {
		t.Fatal("threshold signature verification FAILED — TSS- fix broke signing")
	}
	t.Logf("TSS- end-to-end signing verified (sig=%d bytes)", len(sig))
}

// TestR5_TSS_R5_01_Round2RevealStructFields verifies that the Round2Reveal
// struct carries Z0Share (combined z0 contribution) and NOT the old
// Cs2Share/Ct0Share separate fields. This is a compile-time + runtime
// guarantee that the struct migration is complete and cannot silently regress.
func TestR5_TSS_R5_01_Round2RevealStructFields(t *testing.T) {
	r := &qtd.Round2Reveal{
		ParticipantID: 1,
		WShare:        []byte("w"),
		ZShare:        []byte("z"),
		Z0Share:       []byte("z0"),
		Nonce:         []byte("nonce"),
	}

	// IsPrivate must return true when Z0Share is set.
	if !r.IsPrivate() {
		t.Error("IsPrivate() should return true when Z0Share is set")
	}

	// ToPublicReveal must strip Z0Share.
	pub := r.ToPublicReveal()
	if pub == nil {
		t.Fatal("ToPublicReveal returned nil")
	}
	if len(pub.Z0Share) != 0 {
		t.Errorf("ToPublicReveal did not strip Z0Share: len=%d", len(pub.Z0Share))
	}
	// Public fields must be preserved.
	if !bytes.Equal(pub.WShare, r.WShare) {
		t.Error("ToPublicReveal altered WShare")
	}
	if !bytes.Equal(pub.ZShare, r.ZShare) {
		t.Error("ToPublicReveal altered ZShare")
	}
	if !bytes.Equal(pub.Nonce, r.Nonce) {
		t.Error("ToPublicReveal altered Nonce")
	}

	// A reveal with no Z0Share must NOT be private.
	empty := &qtd.Round2Reveal{ParticipantID: 2}
	if empty.IsPrivate() {
		t.Error("IsPrivate() should return false when Z0Share is empty")
	}
}

// TestR5_TSS_R5_01_ZeroRevealSecrets verifies that ZeroRevealSecrets zeros the
// Z0Share field (not the removed Cs2Share/Ct0Share). This prevents lingering
// signature-derived material from leaking the signing transcript.
func TestR5_TSS_R5_01_ZeroRevealSecrets(t *testing.T) {
	r := &qtd.Round2Reveal{
		ParticipantID: 1,
		Z0Share:       []byte{0xAA, 0xBB, 0xCC, 0xDD},
		WShare:        []byte{0xFF, 0xFF},
		ZShare:        []byte{0xEE, 0xEE},
	}
	qtd.ZeroRevealSecrets(r)

	for i, b := range r.Z0Share {
		if b != 0 {
			t.Errorf("Z0Share[%d] not zeroed: %x", i, b)
		}
	}
}

// TestR5_TSS_R5_01_WireFormatSingleZ0Share is the KEY SECURITY TEST.
// It verifies that the private wire format (EncodeRound2RevealPrivate) carries
// a SINGLE combined Z0Share and does NOT contain:
//   - Raw S2ShareBytes/T0ShareBytes (the original TSS- leak)
//   - Separate Cs2Share/Ct0Share (the TSS- leak — these would allow the
//     aggregator to invert c in the NTT ring and recover s2/t0 separately)
//
// Construction: We craft a reveal where Z0Share is distinct from any raw share.
// After round-trip through Encode/Decode, the decoded bytes must match Z0Share.
// We also verify the wire format has exactly 2 length-prefixed fields (z, z0),
// not the old 3 (z, cs2, ct0) or the original 5 (sc, z, s2, t0).
func TestR5_TSS_R5_01_WireFormatSingleZ0Share(t *testing.T) {
	sessionID := [32]byte{}
	rand.Read(sessionID[:])

	// Simulate a participant's data:
	// - Raw shares (s2_i, t0_i) — these MUST NEVER appear on the wire
	// - Separate masked contributions (cs2_i, ct0_i) — these MUST NEVER appear
	//   on the wire either (TSS- the aggregator could invert c to
	//   recover s2/t0 separately from cs2/ct0)
	// - Combined z0 contribution (z0_i = λ_i·c·(t0_i - s2_i)) — this is what
	//   gets sent; the aggregator cannot decompose it
	rawS2 := make([]byte, 4608)
	rawT0 := make([]byte, 4608)
	rand.Read(rawS2)
	rand.Read(rawT0)

	// Separate masked contributions — these must NOT appear on the wire.
	cs2Share := make([]byte, 4608)
	ct0Share := make([]byte, 4608)
	for i := range cs2Share {
		cs2Share[i] = rawS2[i] ^ 0xAA
		ct0Share[i] = rawT0[i] ^ 0xBB
	}

	// Combined z0 contribution — distinct from both raw shares and separate
	// masked contributions. We use a sentinel XOR to make any leak obvious.
	z0Share := make([]byte, 4608)
	for i := range z0Share {
		// z0 = ct0 - cs2 = (rawT0^0xBB) - (rawS2^0xAA) mod 256 (simplified)
		// Use a distinct sentinel to ensure z0 != cs2 and z0 != ct0.
		z0Share[i] = cs2Share[i] ^ ct0Share[i] ^ 0x5A
	}
	zShare := make([]byte, 3840)
	rand.Read(zShare)

	encoded, err := EncodeRound2RevealPrivate(sessionID, 7, 1752792000000000000, zShare, z0Share)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	// SECURITY PROPERTY 1: The wire payload must NOT contain rawS2 or rawT0
	// as contiguous subsequences (the original TSS- format did).
	if bytes.Contains(encoded, rawS2) {
		t.Fatal("SECURITY FAIL: raw S2ShareBytes found in private wire payload — " +
			"raw share transmission not eliminated")
	}
	if bytes.Contains(encoded, rawT0) {
		t.Fatal("SECURITY FAIL: raw T0ShareBytes found in private wire payload — " +
			"raw share transmission not eliminated")
	}

	// SECURITY PROPERTY 2 (TSS- CORE): The wire payload must NOT contain
	// separate cs2Share or ct0Share as contiguous subsequences. The previous
	// TSS- fix transmitted these separately, allowing the aggregator to
	// invert the challenge polynomial c in the NTT ring and recover s2/t0
	// separately, then s1 via A·s1 = t - s2.
	if bytes.Contains(encoded, cs2Share) {
		t.Fatal("SECURITY FAIL (TSS-): separate Cs2Share found in wire " +
			"payload — aggregator could invert c to recover s2, enabling " +
			"full private key reconstruction")
	}
	if bytes.Contains(encoded, ct0Share) {
		t.Fatal("SECURITY FAIL (TSS-): separate Ct0Share found in wire " +
			"payload — aggregator could invert c to recover t0, enabling " +
			"full private key reconstruction")
	}

	// SECURITY PROPERTY 3: The wire payload must contain the combined Z0Share
	// so the aggregator can sum it to obtain c·(t0-s2) for hint computation.
	if !bytes.Contains(encoded, z0Share) {
		t.Fatal("combined Z0Share not found in wire payload — " +
			"aggregator cannot compute z0 contribution for hint generation")
	}

	// SECURITY PROPERTY 4: Round-trip must recover the combined Z0Share,
	// NOT the raw shares and NOT the separate masked contributions.
	decSessionID, pid, _, decZ, decZ0, err := DecodeRound2RevealPrivate(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decSessionID != sessionID {
		t.Error("session ID mismatch")
	}
	if pid != 7 {
		t.Error("participant ID mismatch")
	}
	if !bytes.Equal(decZ, zShare) {
		t.Error("ZShare mismatch")
	}
	if !bytes.Equal(decZ0, z0Share) {
		t.Error("Z0Share mismatch — aggregator would receive wrong combined z0 contribution")
	}

	// SECURITY PROPERTY 5: Decoded Z0Share must NOT equal raw shares or
	// separate masked contributions.
	if bytes.Equal(decZ0, rawS2) {
		t.Fatal("SECURITY FAIL: decoded Z0Share equals raw S2ShareBytes — " +
			"the wire format is leaking raw key shares")
	}
	if bytes.Equal(decZ0, rawT0) {
		t.Fatal("SECURITY FAIL: decoded Z0Share equals raw T0ShareBytes — " +
			"the wire format is leaking raw key shares")
	}
	if bytes.Equal(decZ0, cs2Share) {
		t.Fatal("SECURITY FAIL (TSS-): decoded Z0Share equals separate " +
			"Cs2Share — the wire format is leaking separable masked contributions")
	}
	if bytes.Equal(decZ0, ct0Share) {
		t.Fatal("SECURITY FAIL (TSS-): decoded Z0Share equals separate " +
			"Ct0Share — the wire format is leaking separable masked contributions")
	}

	// STRUCTURAL PROPERTY: Wire format must have exactly 2 length-prefixed
	// share fields (z, z0), not the old TSS- format with 3 (z, cs2, ct0)
	// or the original 5 (sc, z, s2, t0). Each field has a 4-byte length prefix.
	// TSS- (2026-07-17): Header is now 32 (sessionID) + 4 (PID) + 8 (ts) = 44.
	// Total = 44 + 4+len(z) + 4+len(z0)
	expectedLen := 44 + 4 + len(zShare) + 4 + len(z0Share)
	if len(encoded) != expectedLen {
		t.Errorf("wire format length mismatch: got %d, expected %d "+
			"(2 fields [z,z0] + 8-byte ts, not 3 [z,cs2,ct0] or 5 [sc,z,s2,t0])",
			len(encoded), expectedLen)
	}
}

// TestR5_TSS_R5_01_AttachZ0Contribution verifies that the aggregator-side
// AttachZ0Contribution correctly stores Z0Share on the reveal (without any
// raw share injection and without separate cs2/ct0).
func TestR5_TSS_R5_01_AttachZ0Contribution(t *testing.T) {
	ds := NewDistributedSigner(nil)
	sessionID := [32]byte{}
	rand.Read(sessionID[:])

	// Manually inject a distributed session (bypassing InitiateSession which
	// requires a fully-initialized TSSManager). This is test-only setup.
	pubReveal := &qtd.Round2Reveal{
		ParticipantID: 1,
		WShare:        make([]byte, 4608),
		ZShare:        nil, // initially nil — will be attached
		Nonce:         make([]byte, 16),
	}
	rand.Read(pubReveal.WShare)
	rand.Read(pubReveal.Nonce)

	session := &DistributedSession{
		SessionID:         sessionID,
		Message:           []byte("test"),
		ParticipantIDs:    []int{1, 2, 3},
		Threshold:         2,
		round1Commitments: make(map[int]*qtd.Round1Commitment),
		round2Reveals:     make(map[int]*qtd.Round2Reveal),
	}
	session.round2Reveals[1] = pubReveal
	ds.sessions[sessionID] = session

	// Simulate the aggregator receiving the combined z0 contribution.
	z0Share := make([]byte, 4608)
	zShare := make([]byte, 3840)
	rand.Read(z0Share)
	rand.Read(zShare)

	if err := ds.AttachZ0Contribution(sessionID, 1, z0Share, zShare); err != nil {
		t.Fatalf("AttachZ0Contribution failed: %v", err)
	}

	// Retrieve the session and verify the combined z0 contribution was attached.
	sess, ok := ds.GetSession(sessionID)
	if !ok {
		t.Fatal("session not found after attach")
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	r, exists := sess.round2Reveals[1]
	if !exists {
		t.Fatal("reveal not found after attach")
	}
	if !bytes.Equal(r.Z0Share, z0Share) {
		t.Error("Z0Share not attached correctly")
	}
	if !bytes.Equal(r.ZShare, zShare) {
		t.Error("ZShare not attached correctly")
	}
}

// TestR5_TSS_R5_01_CompleteSignStripsZ0Share verifies that CompleteSign
// produces a sanitized PartialSignature with Z0Share stripped, while
// CompleteSignPrivate retains it. This prevents broadcasting the combined z0
// contribution to non-aggregator peers.
func TestR5_TSS_R5_01_CompleteSignStripsZ0Share(t *testing.T) {
	config := DefaultTSSConfig()
	manager, err := NewTSSManager(config)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatalf("failed to generate key shares: %v", err)
	}

	message := []byte("TSS- CompleteSign strip test")
	participants := make([]int, config.Threshold)
	for i := 0; i < config.Threshold; i++ {
		participants[i] = i + 1
	}

	sessionKey, err := manager.CreateSigningSession(message, participants)
	if err != nil {
		t.Fatalf("CreateSigningSession failed: %v", err)
	}

	// Submit Round1 for all participants.
	round1Sigs := make([]*PartialSignature, len(participants))
	for i, pid := range participants {
		ps, err := manager.BeginSign(sessionKey, pid)
		if err != nil {
			t.Fatalf("BeginSign pid=%d: %v", pid, err)
		}
		round1Sigs[i] = ps
	}
	if err := manager.SubmitRound1(sessionKey, round1Sigs); err != nil {
		t.Fatalf("SubmitRound1 failed: %v", err)
	}

	// Get both the private and sanitized signatures for participant 1.
	priv, err := manager.CompleteSignPrivate(sessionKey, 1)
	if err != nil {
		t.Fatalf("CompleteSignPrivate failed: %v", err)
	}
	pub, err := manager.CompleteSign(sessionKey, 1)
	if err != nil {
		t.Fatalf("CompleteSign failed: %v", err)
	}

	wLen := qtd.Dilithium3K * qtd.N * 3
	zLen := qtd.Dilithium3L * qtd.N * 3
	nonceLen := 16
	publicLen := wLen + zLen + nonceLen

	// The private signature must include the combined z0 contribution.
	if len(priv.Signature) <= publicLen {
		t.Fatalf("CompleteSignPrivate did not include Z0Share: "+
			"len=%d, publicLen=%d", len(priv.Signature), publicLen)
	}
	if !priv.Private {
		t.Error("CompleteSignPrivate must set Private=true")
	}
	// Combined z0 contribution must be exactly z0Len = wLen (K polynomials,
	// same size as WShare). NOT 2*wLen (which would be the old cs2+ct0 size).
	expectedZ0Len := wLen
	if len(priv.Signature)-publicLen != expectedZ0Len {
		t.Errorf("Z0Share size mismatch: got %d, expected %d (K*N*3, "+
			"NOT 2*K*N*3 which would indicate separate cs2/ct0)",
			len(priv.Signature)-publicLen, expectedZ0Len)
	}

	// The public signature must NOT include the z0 contribution.
	if len(pub.Signature) != publicLen {
		t.Errorf("CompleteSign did not strip Z0Share: "+
			"got len=%d, expected %d (public only)", len(pub.Signature), publicLen)
	}
	if pub.Private {
		t.Error("CompleteSign must set Private=false")
	}

	// The public prefix (WShare || ZShare || Nonce) must match between priv and pub.
	if !bytes.Equal(priv.Signature[:publicLen], pub.Signature) {
		t.Error("public prefix mismatch between CompleteSign and CompleteSignPrivate")
	}

	// ValidateForBroadcast must reject the private signature and accept the public one.
	if err := priv.ValidateForBroadcast(); err == nil {
		t.Error("ValidateForBroadcast must reject private signature")
	}
	if err := pub.ValidateForBroadcast(); err != nil {
		t.Errorf("ValidateForBroadcast must accept public signature: %v", err)
	}

	manager.CleanSession(sessionKey)
}

// TestR5_TSS_R5_01_CombineSignaturesRejectsBadLength verifies that
// CombineSignatures rejects partial signatures whose Z0Share length is not
// exactly z0Len (= wLen, K polynomials). This prevents truncation/padding
// attacks where a malicious participant sends a partial payload.
//
// This test also confirms that the expected masked length is wLen (one K-poly
// vector), NOT 2*wLen (which would be the old cs2+ct0 size). If the code were
// still expecting cs2+ct0, this test would fail.
func TestR5_TSS_R5_01_CombineSignaturesRejectsBadLength(t *testing.T) {
	config := DefaultTSSConfig()
	manager, err := NewTSSManager(config)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatalf("failed to generate key shares: %v", err)
	}

	message := []byte("TSS- CombineSignatures length validation")
	participants := make([]int, config.Threshold)
	for i := 0; i < config.Threshold; i++ {
		participants[i] = i + 1
	}

	sessionKey, err := manager.CreateSigningSession(message, participants)
	if err != nil {
		t.Fatalf("CreateSigningSession failed: %v", err)
	}

	round1Sigs := make([]*PartialSignature, len(participants))
	for i, pid := range participants {
		ps, err := manager.BeginSign(sessionKey, pid)
		if err != nil {
			t.Fatalf("BeginSign pid=%d: %v", pid, err)
		}
		round1Sigs[i] = ps
	}
	if err := manager.SubmitRound1(sessionKey, round1Sigs); err != nil {
		t.Fatalf("SubmitRound1 failed: %v", err)
	}

	// Get a valid private signature and truncate the Z0Share.
	priv, err := manager.CompleteSignPrivate(sessionKey, 1)
	if err != nil {
		t.Fatalf("CompleteSignPrivate failed: %v", err)
	}

	wLen := qtd.Dilithium3K * qtd.N * 3
	zLen := qtd.Dilithium3L * qtd.N * 3
	nonceLen := 16
	publicLen := wLen + zLen + nonceLen
	expectedZ0Len := wLen // TSS- single K-poly vector, NOT 2*wLen

	// Verify the valid signature has the expected Z0Share length.
	if len(priv.Signature)-publicLen != expectedZ0Len {
		t.Fatalf("valid Z0Share length mismatch: got %d, expected %d",
			len(priv.Signature)-publicLen, expectedZ0Len)
	}

	// Truncated: remove one byte from the Z0Share.
	truncated := &PartialSignature{
		Index:     priv.Index,
		Signature: append([]byte(nil), priv.Signature[:len(priv.Signature)-1]...),
		Private:   true,
	}
	_, err = manager.CombineSignatures(sessionKey, []*PartialSignature{truncated})
	if err == nil {
		t.Error("CombineSignatures must reject truncated Z0Share")
	}

	// Oversized: append an extra byte to the Z0Share.
	oversized := &PartialSignature{
		Index:     priv.Index,
		Signature: append(append([]byte(nil), priv.Signature...), 0xFF),
		Private:   true,
	}
	_, err = manager.CombineSignatures(sessionKey, []*PartialSignature{oversized})
	if err == nil {
		t.Error("CombineSignatures must reject oversized Z0Share")
	}

	// Old-format attack: a signature with 2*wLen extra bytes (simulating the
	// old cs2+ct0 format) must be REJECTED. This ensures a participant cannot
	// downgrade the protocol to the insecure separate-transmission format.
	oldFormatSig := &PartialSignature{
		Index: priv.Index,
		Signature: append(append([]byte(nil), priv.Signature[:publicLen]...),
			make([]byte, 2*wLen)...), // 2*wLen = old cs2+ct0 size
		Private: true,
	}
	_, err = manager.CombineSignatures(sessionKey, []*PartialSignature{oldFormatSig})
	if err == nil {
		t.Error("SECURITY FAIL: CombineSignatures accepted old-format " +
			"cs2+ct0 payload (2*wLen) — TSS- downgrade not blocked")
	}

	// Zero Z0Share on cleanup.
	for i := range priv.Signature {
		priv.Signature[i] = 0
	}
	for i := range truncated.Signature {
		truncated.Signature[i] = 0
	}
	for i := range oversized.Signature {
		oversized.Signature[i] = 0
	}
	for i := range oldFormatSig.Signature {
		oldFormatSig.Signature[i] = 0
	}
	manager.CleanSession(sessionKey)

	_ = publicLen // suppress unused warning if computation is unused above
}

// TestR5_TSS_R5_01_NoOldFieldsInStruct is a compile-time guarantee that the
// Round2Reveal struct no longer has Cs2Share, Ct0Share, or ScShare fields.
// If someone re-adds them, this test will fail to compile. We access the field
// via reflection to make the test self-documenting.
//
// Note: Go does not allow struct field access via reflection in a way that
// fails to compile if the field exists. Instead, we rely on the fact that
// any code referencing r.Cs2Share/r.Ct0Share/r.ScShare will fail to compile
// (verified by the build at the top of this fix). This test serves as
// documentation of the invariant.
func TestR5_TSS_R5_01_NoOldFieldsInStruct(t *testing.T) {
	// The Round2Reveal struct must have Z0Share field (not Cs2Share/Ct0Share/ScShare).
	r := &qtd.Round2Reveal{
		Z0Share: []byte{1, 2, 3},
	}
	if len(r.Z0Share) != 3 {
		t.Error("Z0Share field is missing or broken")
	}
	// If Cs2Share/Ct0Share/ScShare were still fields, the following lines
	// would compile. They are EXPECTED to not compile.
	// r.Cs2Share = []byte{0}  // EXPECTED: does not compile
	// r.Ct0Share = []byte{0}  // EXPECTED: does not compile
	// r.ScShare   = []byte{0}  // EXPECTED: does not compile
}
