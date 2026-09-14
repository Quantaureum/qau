// Quantaureum Node source, version 1.0.0.
package tss

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// TestDistributedSigner_EncodeDecodeRound1Commitment tests the wire encoding/decoding
// of Round1 commitments for P2P transmission.
func TestDistributedSigner_EncodeDecodeRound1Commitment(t *testing.T) {
	sessionID := [32]byte{}
	rand.Read(sessionID[:])

	commitment := createTestCommitment(1)
	wShare := make([]byte, 4608)
	rand.Read(wShare)

	encoded, err := EncodeRound1Commitment(sessionID, commitment, wShare)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	expectedMin := 84 + 4 + len(wShare)
	if len(encoded) != expectedMin {
		t.Fatalf("expected %d bytes, got %d", expectedMin, len(encoded))
	}

	decodedSessionID, decodedCommitment, decodedW, err := DecodeRound1Commitment(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decodedSessionID != sessionID {
		t.Error("session ID mismatch")
	}
	if decodedCommitment.ParticipantID != commitment.ParticipantID {
		t.Error("participant ID mismatch")
	}
	if string(decodedCommitment.Commitment) != string(commitment.Commitment) {
		t.Error("commitment mismatch")
	}
	if string(decodedCommitment.Nonce) != string(commitment.Nonce) {
		t.Error("nonce mismatch")
	}
	if string(decodedW) != string(wShare) {
		t.Error("wShare mismatch")
	}
}

// TestDistributedSigner_EncodeDecodeRound2RevealPublic tests the wire encoding/decoding
// of the public part of Round2 reveals.
// R2-HIGH-07: ZShare is NOT in the public encoding (moved to private channel).
func TestDistributedSigner_EncodeDecodeRound2RevealPublic(t *testing.T) {
	sessionID := [32]byte{}
	rand.Read(sessionID[:])

	reveal := createTestReveal(1)

	encoded := EncodeRound2RevealPublic(sessionID, reveal)
	if len(encoded) == 0 {
		t.Fatal("encoded data is empty")
	}

	// R2-HIGH-07: Public encoding no longer includes ZShare.
	// Expected: 32 (sessionID) + 4 (PID) + 4608 (WShare) + 16 (Nonce) = 4660
	wLen := qtd.Dilithium3K * qtd.N * 3
	expectedPub := 32 + 4 + wLen + 16
	if len(encoded) != expectedPub {
		t.Fatalf("expected %d bytes (no ZShare), got %d", expectedPub, len(encoded))
	}

	decodedSessionID, decodedReveal, err := DecodeRound2RevealPublic(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decodedSessionID != sessionID {
		t.Error("session ID mismatch")
	}
	if decodedReveal.ParticipantID != reveal.ParticipantID {
		t.Error("participant ID mismatch")
	}
	// R2-HIGH-07: ZShare must NOT be in the public decode.
	if decodedReveal.ZShare != nil {
		t.Error("ZShare should be nil in public decode (R2-HIGH-07)")
	}
	if string(decodedReveal.WShare) != string(reveal.WShare) {
		t.Error("WShare mismatch")
	}
}

// TestDistributedSigner_EncodeDecodeRound2Private tests the wire encoding/decoding
// of the private ZShare + combined z0 contribution (Z0Share) for encrypted
// P2P transmission.
// R2-HIGH-07: ZShare is now included in the private encoding.
// AUDIT (2026) TSS-FIX (CRITICAL): The wire format carries a SINGLE
// combined Z0Share (λ_i·c·(t0_i - s2_i)) instead of the previously separate
// Cs2Share (λ_i·c·s2_i) and Ct0Share (λ_i·c·t0_i). The old separate
// contributions allowed the aggregator to invert the challenge polynomial c in
// the NTT ring and recover s2 and t0 separately, then s1 via A·s1 = t - s2,
// reconstructing the FULL Dilithium3 private key. The new combined Z0Share
// cannot be decomposed by the aggregator (residual risk: s1 recovery only).
// Raw secret-key shares NEVER traverse the wire.
func TestDistributedSigner_EncodeDecodeRound2Private(t *testing.T) {
	sessionID := [32]byte{}
	rand.Read(sessionID[:])

	zShare := make([]byte, 3840)  // R2-HIGH-07: ZShare now in private channel
	z0Share := make([]byte, 4608) // TSS- K polynomials (combined z0 contribution)
	rand.Read(zShare)
	rand.Read(z0Share)

	// TSS- timestamp added to wire format.
	ts := int64(1752792000000000000)
	encoded, err := EncodeRound2RevealPrivate(sessionID, 2, ts, zShare, z0Share)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	// Format: 32 + 4 + 8 + 4 + len(z) + 4 + len(z0)
	expected := 32 + 4 + 8 + 4 + len(zShare) + 4 + len(z0Share)
	if len(encoded) != expected {
		t.Fatalf("expected %d bytes, got %d", expected, len(encoded))
	}

	decodedSessionID, pid, decTS, decZ, decZ0, err := DecodeRound2RevealPrivate(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decodedSessionID != sessionID {
		t.Error("session ID mismatch")
	}
	if pid != 2 {
		t.Error("participant ID mismatch")
	}
	if decTS != ts {
		t.Errorf("timestamp mismatch: got %d, want %d", decTS, ts)
	}
	if string(decZ) != string(zShare) {
		t.Error("zShare mismatch")
	}
	if string(decZ0) != string(z0Share) {
		t.Error("z0Share mismatch")
	}
}

// ============================================================================
// TSS- (2026-07-17): Round2 private message freshness timestamp tests.
//
// These tests verify the wire format carries an 8-byte Unix-nano timestamp
// between ParticipantID and ZShareLen, and that round-trip preserves it.
// The aggregator-side freshness window + monotonic-increase enforcement is
// tested at the node layer (node package) because it requires the Node's
// round2PrivateLastTS map state.
// ============================================================================

// TestTSS_R5_08_TimestampRoundTrip verifies the timestamp is preserved
// through encode/decode and lives at the correct wire-format offset.
func TestTSS_R5_08_TimestampRoundTrip(t *testing.T) {
	sessionID := [32]byte{}
	rand.Read(sessionID[:])
	zShare := make([]byte, 256)
	z0Share := make([]byte, 512)
	rand.Read(zShare)
	rand.Read(z0Share)

	// Multiple timestamps including edge values.
	testTimestamps := []int64{
		0,
		1,
		1_700_000_000_000_000_000, // realistic Unix-nano
		9_223_372_036_854_775_806, // MaxInt64 - 1
		9_223_372_036_854_775_807, // MaxInt64
		-1,                        // negative (shouldn't happen in production but must round-trip)
	}

	for _, ts := range testTimestamps {
		t.Run(fmt.Sprintf("ts=%d", ts), func(t *testing.T) {
			encoded, err := EncodeRound2RevealPrivate(sessionID, 5, ts, zShare, z0Share)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}
			_, pid, decTS, decZ, decZ0, err := DecodeRound2RevealPrivate(encoded)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if pid != 5 {
				t.Errorf("PID mismatch: got %d, want 5", pid)
			}
			if decTS != ts {
				t.Errorf("timestamp mismatch: got %d, want %d", decTS, ts)
			}
			if !bytesEqual(decZ, zShare) {
				t.Error("zShare mismatch")
			}
			if !bytesEqual(decZ0, z0Share) {
				t.Error("z0Share mismatch")
			}
		})
	}
}

// TestTSS_R5_08_WireFormatOffset verifies the timestamp lives at byte offset
// 36..44 (after SessionID[32] + ParticipantID[4]) and is big-endian. This
// protects against accidental format regressions that break compatibility
// with the aggregator's decoding.
func TestTSS_R5_08_WireFormatOffset(t *testing.T) {
	sessionID := [32]byte{}
	for i := range sessionID {
		sessionID[i] = byte(i)
	}
	zShare := []byte{0xAA, 0xBB, 0xCC}
	z0Share := []byte{0xDD, 0xEE}

	ts := int64(0x0102030405060708)
	encoded, err := EncodeRound2RevealPrivate(sessionID, 0x090A, ts, zShare, z0Share)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	// SessionID at [0,32)
	for i := 0; i < 32; i++ {
		if encoded[i] != byte(i) {
			t.Errorf("sessionID[%d]=%d, want %d", i, encoded[i], byte(i))
		}
	}
	// ParticipantID at [32,36) big-endian.
	if pid := binary.BigEndian.Uint32(encoded[32:36]); pid != 0x090A {
		t.Errorf("PID=%d, want 0x090A", pid)
	}
	// Timestamp at [36,44) big-endian.
	if gotTS := int64(binary.BigEndian.Uint64(encoded[36:44])); gotTS != ts {
		t.Errorf("timestamp=%d, want %d", gotTS, ts)
	}
	// Verify big-endian byte order explicitly.
	if encoded[36] != 0x01 || encoded[43] != 0x08 {
		t.Errorf("timestamp byte order wrong: [0]=%#x [7]=%#x (want 0x01, 0x08)",
			encoded[36], encoded[43])
	}
	// ZShareLen at [44,48).
	if zLen := binary.BigEndian.Uint32(encoded[44:48]); zLen != 3 {
		t.Errorf("zShareLen=%d, want 3", zLen)
	}
}

// TestTSS_R5_08_TruncatedPayloadRejected verifies that payloads missing the
// timestamp field (the old 40-byte-minimum format) are now rejected by the
// 48-byte minimum length check. This prevents downgrade attacks where a
// legacy client omits the timestamp.
func TestTSS_R5_08_TruncatedPayloadRejected(t *testing.T) {
	// Construct a legacy-format payload (40 bytes, no timestamp).
	legacy := make([]byte, 40)
	_, _, _, _, _, err := DecodeRound2RevealPrivate(legacy)
	if err == nil {
		t.Fatal("legacy 40-byte payload accepted — timestamp not enforced")
	}
}

// TestTSS_R5_08_EncodeRejectsOversizedShares verifies the size guards still
// fire with the new timestamp field. The freshness fix must not regress
// existing size-validation defenses.
func TestTSS_R5_08_EncodeRejectsOversizedShares(t *testing.T) {
	sessionID := [32]byte{}

	hugeZ := make([]byte, maxEncodedShareSize+1)
	hugeZ0 := make([]byte, maxEncodedShareSize+1)

	if _, err := EncodeRound2RevealPrivate(sessionID, 1, 0, hugeZ, nil); err == nil {
		t.Error("oversized zShare accepted")
	}
	if _, err := EncodeRound2RevealPrivate(sessionID, 1, 0, nil, hugeZ0); err == nil {
		t.Error("oversized z0Share accepted")
	}
}

// bytesEqual is a small local helper to avoid importing bytes just for this.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDistributedSigner_EncodeDecodeSignature tests the wire encoding/decoding
// of final signatures for broadcast.
func TestDistributedSigner_EncodeDecodeSignature(t *testing.T) {
	sessionID := [32]byte{}
	rand.Read(sessionID[:])

	signature := make([]byte, 3293)
	rand.Read(signature)

	encoded := EncodeSignature(sessionID, signature)
	if len(encoded) != 32+3293 {
		t.Fatalf("expected %d bytes, got %d", 32+3293, len(encoded))
	}

	decodedSessionID, decodedSig, err := DecodeSignature(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decodedSessionID != sessionID {
		t.Error("session ID mismatch")
	}
	if string(decodedSig) != string(signature) {
		t.Error("signature mismatch")
	}
}

// TestDistributedSigner_EncodeSessionInit tests session init encoding.
//
// AUDIT (2026) TSS-FIX: The wire format now carries the FULL
// message bytes (not just sha256(message)). The decoded `message` must equal
// the original message — otherwise participants and the aggregator compute
// different Dilithium3 challenges and distributed signing silently falls back
// to local signing.
//
// TSS-M8 (R8 2026-07-19) EXTENSION: The wire format now carries an 8-byte
// authoritative aggregator timestamp at the end. The decode round-trip must
// preserve it. Legacy payloads without the timestamp must still parse (with
// initiatedAt=0), and malformed trailing lengths must be rejected.
func TestDistributedSigner_EncodeSessionInit(t *testing.T) {
	sessionID := [32]byte{}
	rand.Read(sessionID[:])

	message := []byte("test message for signing")
	participantIDs := []int{1, 2, 3}
	initiatedAt := int64(1752920000000000000) // arbitrary fixed Unix-nano

	encoded := EncodeSessionInit(sessionID, message, participantIDs, initiatedAt)
	// Expected: 32 (sessionID) + 32 (msgHash) + 4 (msgLen) + len(message)
	//           + 4 (count) + 4*3 (IDs) + 8 (TSS-M8 timestamp)
	//         = 32 + 32 + 4 + 24 + 4 + 12 + 8 = 116
	if len(encoded) != 116 {
		t.Fatalf("expected 116 bytes, got %d", len(encoded))
	}

	// Test decode
	decSessionID, decMessage, decIDs, decInitiatedAt, err := DecodeSessionInit(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decSessionID != sessionID {
		t.Error("session ID mismatch")
	}
	// TSS-FIX: The decoded message must be the FULL original message,
	// not the 32-byte hash. This is what allows participants to compute the
	// same Dilithium3 challenge as the aggregator.
	if string(decMessage) != string(message) {
		t.Errorf("message mismatch: expected %q, got %q", message, decMessage)
	}
	if len(decIDs) != 3 {
		t.Fatalf("expected 3 participant IDs, got %d", len(decIDs))
	}
	for i, id := range decIDs {
		if id != participantIDs[i] {
			t.Errorf("participant ID[%d]: expected %d, got %d", i, participantIDs[i], id)
		}
	}
	// TSS-M8: Round-trip the authoritative timestamp.
	if decInitiatedAt != initiatedAt {
		t.Errorf("initiatedAt mismatch: expected %d, got %d", initiatedAt, decInitiatedAt)
	}

	// TSS- Tampered hash should be rejected (constant-time integrity check).
	tampered := append([]byte(nil), encoded...)
	tampered[32] ^= 0xFF // flip a bit in the hash
	if _, _, _, _, err := DecodeSessionInit(tampered); err == nil {
		t.Error("tampered hash should fail integrity check")
	}

	// TSS- Tampered message bytes should be rejected.
	tampered2 := append([]byte(nil), encoded...)
	tampered2[68] ^= 0xFF // flip a bit in the message
	if _, _, _, _, err := DecodeSessionInit(tampered2); err == nil {
		t.Error("tampered message should fail integrity check")
	}

	// TSS- Empty message should round-trip correctly.
	emptyEncoded := EncodeSessionInit(sessionID, []byte{}, participantIDs, initiatedAt)
	_, emptyMsg, _, emptyInitAt, err := DecodeSessionInit(emptyEncoded)
	if err != nil {
		t.Fatalf("empty message decode failed: %v", err)
	}
	if len(emptyMsg) != 0 {
		t.Errorf("expected empty message, got %d bytes", len(emptyMsg))
	}
	if emptyInitAt != initiatedAt {
		t.Errorf("empty-message initiatedAt mismatch: expected %d, got %d", initiatedAt, emptyInitAt)
	}

	// TSS-M8: Zero-initiatedAt encodes as 8 zero bytes (still present in
	// the wire format), and decodes back to 0. Callers treat 0 as "no
	// authoritative timestamp — fall back to local time.Now()".
	zeroEncoded := EncodeSessionInit(sessionID, message, participantIDs, 0)
	_, _, _, zeroInitAt, err := DecodeSessionInit(zeroEncoded)
	if err != nil {
		t.Fatalf("zero initiatedAt decode failed: %v", err)
	}
	if zeroInitAt != 0 {
		t.Errorf("expected zero initiatedAt, got %d", zeroInitAt)
	}

	// TSS-M8 BACKWARD COMPAT: A legacy payload without the trailing 8-byte
	// timestamp (pre-TSS-M8 aggregator) must still parse, returning
	// initiatedAt=0 so the participant falls back to local time.Now().
	legacyEncoded := encoded[:len(encoded)-8] // strip the timestamp
	_, _, _, legacyInitAt, err := DecodeSessionInit(legacyEncoded)
	if err != nil {
		t.Fatalf("legacy payload decode failed: %v", err)
	}
	if legacyInitAt != 0 {
		t.Errorf("legacy payload should yield initiatedAt=0, got %d", legacyInitAt)
	}

	// TSS-M8: A payload with a malformed trailing length (not 0 or 8 bytes)
	// must be rejected rather than silently ignoring trailing junk.
	malformed := append([]byte(nil), legacyEncoded...)
	malformed = append(malformed, 0x01, 0x02, 0x03) // 3 trailing bytes — neither 0 nor 8
	if _, _, _, _, err := DecodeSessionInit(malformed); err == nil {
		t.Error("malformed trailing length should be rejected")
	}
}

// TestQTDSession_SubmitExternalW_GetW tests SubmitExternalW and GetW.
func TestQTDSession_SubmitExternalW_GetW(t *testing.T) {
	shares := map[int]*qtd.QTDShare{
		1: {ParticipantID: 1, S1ShareBytes: make([]byte, 3840)},
	}
	session, err := qtd.NewQTDSession([]byte("test"), []int{1, 2, 3}, 2, shares)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	wBytes := make([]byte, 4608)
	rand.Read(wBytes)

	if err := session.SubmitExternalW(2, wBytes); err != nil {
		t.Fatalf("SubmitExternalW failed: %v", err)
	}

	got := session.GetW(2)
	if got == nil {
		t.Fatal("GetW returned nil")
	}
	if string(got) != string(wBytes) {
		t.Error("W bytes mismatch")
	}

	// GetW for non-existent participant should return nil
	nilW := session.GetW(99)
	if nilW != nil {
		t.Error("expected nil for non-existent participant")
	}
}

// TestQTDSession_InjectExternalShare was REMOVED in TSS- fix.
// AUDIT (2026) TSS-FIX: InjectExternalShare was deleted because
// the aggregator no longer receives raw S2/T0 shares to inject into the
// session. Instead, each participant sends a SINGLE combined z0 contribution
// (Z0Share = λ_i·c·(t0_i - s2_i)) which is attached directly to Round2Reveal
// via AttachZ0Contribution. The aggregator sums these to obtain c·(t0-s2) —
// the exact quantity needed for hint computation. The aggregator CANNOT
// decompose this into c·s2 and c·t0 separately (residual risk: s1 recovery
// only, not full key).

// Helper functions for creating test data

func createTestCommitment(participantID int) *qtd.Round1Commitment {
	commitment := make([]byte, 32)
	nonce := make([]byte, 16)
	rand.Read(commitment)
	rand.Read(nonce)

	return &qtd.Round1Commitment{
		ParticipantID: participantID,
		Commitment:    commitment,
		Nonce:         nonce,
	}
}

func createTestReveal(participantID int) *qtd.Round2Reveal {
	wShare := make([]byte, 4608) // K*N*3
	zShare := make([]byte, 3840) // L*N*3
	nonce := make([]byte, 16)
	rand.Read(wShare)
	rand.Read(zShare)
	rand.Read(nonce)

	return &qtd.Round2Reveal{
		ParticipantID: participantID,
		WShare:        wShare,
		ZShare:        zShare,
		Nonce:         nonce,
	}
}
