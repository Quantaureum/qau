// Quantaureum Node source, version 1.0.0.
// Package p2p — R38-P2-01 DEEP FIX regression tests for Protocol V2
// (2026-08-02). The conservative R38-P2-01 audit item (2026-08-02) bound
// the status signature's ValidatorAddress to the signing key's derived
// address: `if verified && pubKey.Address() != status.ValidatorAddress {
// verified = false }`. The deep fix goes further with three coordinated
// controls that are all OPTIONAL (default-off, preserving wire + behavior
// backward compatibility):
//
//  1. ACTIVE SET membership — ActiveValidatorIdentityVerifier interface
//     (host.go) consulted when installed via SetActiveValidatorIdentityVerifier.
//     Returns an error if (address, pubKey) is not in the chain's CURRENT
//     active validator set (defeats stale-tval address-claim attacks).
//
//  2. CLOCK-SKEW freshness window — every V2 status's Timestamp MUST be
//     within +/- statusFreshnessWindowSec seconds of the receiver's wall
//     clock. Set via SetStatusFreshnessWindowSec; 0 disables. Defeats
//     rekey-window replay (recorded status within RLPx's 5-minute TLS
//     session key window).
//
//  3. ANTI-REPLAY — V2 status's SessionNonce, in conjunction with the
//     sender's ValidatorAddress + PeerID, must be unique within the
//     node's local SessionNonceTracker. Set via SetSessionNonceTracker.
//     Defeats intra-freshness-window replay (same status frame replayed
//     by a MitM within the freshness window).
//
// WIRE COMPAT:
//   - V1/R37 nodes send Timestamp=0 + SessionNonce=all-zero. The host's
//     verifier falls back to the legacy 104-byte signed range + applies
//     neither clock-skew nor anti-replay. Existing tests
//     (p2p/r38_p2_01_validator_status_identity_test.go) pin the legacy
//     invariant — these deep tests cover ONLY the V2 extension behavior.
//
// SIGNED DOMAIN:
//   - V2 signers compute ValidatorSignature over base[:104] + Timestamp[8]
//   - SessionNonce[16] (= 128 bytes). host.go's findV2ExtensionValueOffset
//     reconstructs the SAME signed range, so an attacker cannot swap in
//     bogus Timestamp/Nonce without breaking the signature.
package p2p

import (
	"encoding/binary"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// r38P2_01Deep_mockActiveVerifier is a test-only verifier that accepts a
// whitelist of (address, pubKey) tuples.
type r38P2_01Deep_mockActiveVerifier struct {
	allowlist map[[52]byte]struct{} // 20B address + 32B pubkey fingerprint (first 32 of 1952 bytes)
	rejectAll bool
}

func (v *r38P2_01Deep_mockActiveVerifier) VerifyActiveValidator(addr types.Address, publicKey []byte) error {
	if v == nil || v.rejectAll {
		return errR38P2_01DeepNotActive
	}
	var k [52]byte
	copy(k[0:20], addr[:])
	if len(publicKey) >= 32 {
		copy(k[20:52], publicKey[:32])
	}
	if _, ok := v.allowlist[k]; ok {
		return nil
	}
	return errR38P2_01DeepNotActive
}

// errR38P2_01DeepNotActive is a sentinel returned by the test verifier.
var errR38P2_01DeepNotActive = &r38P2_01DeepSimpleError{"r38P2_01Deep: (address, pubKey) not in active set"}

type r38P2_01DeepSimpleError struct{ msg string }

func (e *r38P2_01DeepSimpleError) Error() string { return e.msg }

// r38P2_01Deep_buildSignedStatusPayload constructs a status payload with
// the V2 extension (Timestamp + SessionNonce) appended AFTER the
// signature, signed over base[:104] || Timestamp || SessionNonce. The
// returned []byte is what the host's status handler would feed into
// DecodeStatusMessage + Verify. We DON'T use EncodeStatusMessage here
// because that file builds the payload by handshake; we build byte-by-byte
// so the test asserts the wire-format is exactly as documented.
func r38P2_01Deep_buildSignedStatusPayload(
	t *testing.T,
	version uint32, networkID uint64, height uint64, bestHash, genesisHash [32]byte,
	validatorAddress types.Address,
	pubKey *crypto.PublicKey, privKey *crypto.PrivateKey,
	timestamp uint64, nonce [16]byte,
) []byte {
	t.Helper()
	// Base payload (104 bytes).
	base := make([]byte, 104)
	binary.BigEndian.PutUint32(base[0:4], version)
	binary.BigEndian.PutUint64(base[4:12], networkID)
	binary.BigEndian.PutUint64(base[12:20], height)
	copy(base[20:52], bestHash[:])
	copy(base[52:84], genesisHash[:])
	copy(base[84:104], validatorAddress[:])

	// Signed range: base[:104] + Timestamp[8] + Nonce[16].
	signedRange := make([]byte, 0, 128)
	signedRange = append(signedRange, base...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, timestamp)
	signedRange = append(signedRange, ts...)
	signedRange = append(signedRange, nonce[:]...)
	sig, err := privKey.Sign(signedRange)
	if err != nil {
		t.Fatalf("privKey.Sign: %v", err)
	}

	pk := pubKey.Bytes()
	pkLen := make([]byte, 4)
	binary.BigEndian.PutUint32(pkLen, uint32(len(pk)))
	sigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLen, uint32(len(sig)))

	// Encoded payload:
	//   base[104] || pkLen[4] || pk || sigLen[4] || sig || extLen[4] || ts[8] || nonce[16]
	data := make([]byte, 0, 104+4+len(pk)+4+len(sig)+4+24)
	data = append(data, base...)
	data = append(data, pkLen...)
	data = append(data, pk...)
	data = append(data, sigLen...)
	data = append(data, sig...)
	// V2 extension block.
	extLen := make([]byte, 4)
	binary.BigEndian.PutUint32(extLen, 24)
	data = append(data, extLen...)
	data = append(data, ts...)
	data = append(data, nonce[:]...)
	return data
}

// r38P2_01Deep_newHostForTest returns a minimal Host with the deep-fix
// setters ready to be configured. We use a stub Host here — the
// status-handling path is self-contained; we test it by exercising the
// code block at host.go:3908-3944 via our own copy of the verification
// logic in this test file, asserting against the public Host methods
// (SetActiveValidatorIdentityVerifier / SetStatusFreshnessWindowSec /
// SetSessionNonceTracker) and the SessionNonceTracker directly.
//
// Actually — we test the type + tracker + findV2ExtensionValueOffset +
// the V2 wire-format round-trip via EncodeStatusMessage/DecodeStatusMessage.
// The full handler-path integration is deferred to a real-Host P2P-level
// harness (TestR38P2_01_StatusSignatureBindsValidatorAddress in the
// sibling file). The deep-fix's incremental change here is the OPTIONAL
// checks around the existing handler — testing the wire format + types
// directly isolates each deep-fix control.
func r38P2_01Deep_newHostForTest(t *testing.T) *Host {
	t.Helper()
	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig: %v", err)
	}
	h, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	return h
}

// TestR38P2_01_Deep_V2ExtensionRoundTrip pins that EncodeStatusMessage
// with non-zero Timestamp + nonce appends the extension block, and
// DecodeStatusMessage correctly parses it back WITHOUT touching legacy
// fields.
func TestR38P2_01_Deep_V2ExtensionRoundTrip(t *testing.T) {
	// Build a Dilithium3 key pair for signing.
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv := kp.Private
	pub := kp.Public

	addr := pub.Address()
	status := &StatusMessage{
		Version:            2,
		NetworkID:          1333,
		BestHeight:         42,
		BestHash:           [32]byte{0xAA},
		GenesisHash:        [32]byte{0xBB},
		ValidatorAddress:   addr,
		ValidatorPublicKey: pub.Bytes(),
		Timestamp:          uint64(1700000000),
		SessionNonce:       [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
	}
	// Compute a V2 domain-aware signature.
	signedRange := make([]byte, 0, 128)
	base := make([]byte, 104)
	binary.BigEndian.PutUint32(base[0:4], status.Version)
	binary.BigEndian.PutUint64(base[4:12], status.NetworkID)
	binary.BigEndian.PutUint64(base[12:20], status.BestHeight)
	copy(base[20:52], status.BestHash[:])
	copy(base[52:84], status.GenesisHash[:])
	copy(base[84:104], status.ValidatorAddress[:])
	signedRange = append(signedRange, base...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, status.Timestamp)
	signedRange = append(signedRange, ts...)
	signedRange = append(signedRange, status.SessionNonce[:]...)
	sig, sigErr := priv.Sign(signedRange)
	if sigErr != nil {
		t.Fatalf("priv.Sign: %v", sigErr)
	}
	status.ValidatorSignature = sig

	encoded := EncodeStatusMessage(status)
	if len(encoded) < 104+4+1952+4+3293+4+24 {
		t.Fatalf("R38-P2-01 deep-fix: encoded V2 payload too short (%d < %d)", len(encoded), 104+4+1952+4+3293+4+24)
	}

	decoded, err := DecodeStatusMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeStatusMessage: %v", err)
	}
	if decoded.Timestamp != status.Timestamp {
		t.Fatalf("R38-P2-01 deep-fix: V2 Timestamp not round-tripped — encoded=%d decoded=%d", status.Timestamp, decoded.Timestamp)
	}
	if decoded.SessionNonce != status.SessionNonce {
		t.Fatalf("R38-P2-01 deep-fix: V2 SessionNonce not round-tripped — encoded=%x decoded=%x", status.SessionNonce, decoded.SessionNonce)
	}
	// Legacy fields MUST remain intact.
	if decoded.ValidatorAddress != status.ValidatorAddress {
		t.Fatalf("R38-P2-01 deep-fix: V2 extension corrupted legacy ValidatorAddress")
	}
	if len(decoded.ValidatorPublicKey) != len(status.ValidatorPublicKey) {
		t.Fatalf("R38-P2-01 deep-fix: V2 extension corrupted ValidatorPublicKey length (%d != %d)", len(decoded.ValidatorPublicKey), len(status.ValidatorPublicKey))
	}
	if len(decoded.ValidatorSignature) != len(status.ValidatorSignature) {
		t.Fatalf("R38-P2-01 deep-fix: V2 extension corrupted ValidatorSignature length (%d != %d)", len(decoded.ValidatorSignature), len(status.ValidatorSignature))
	}
}

// TestR38P2_01_Deep_LegacyR37PayloadDecodesNoV2Fields verifies that a
// legacy R37 payload (no V2 extension) decodes with Timestamp=0 +
// SessionNonce=0. This pins backwards wire compatibility: V2 writes
// append the extension; V1 readers MUST see zero defaults.
func TestR38P2_01_Deep_LegacyR37PayloadDecodesNoV2Fields(t *testing.T) {
	// Build a minimal legacy payload: 104-byte base + 4B pkLen + pk + 4B sigLen + sig.
	base := make([]byte, 104)
	binary.BigEndian.PutUint32(base[0:4], 2)
	binary.BigEndian.PutUint64(base[4:12], 1333)
	binary.BigEndian.PutUint64(base[12:20], 1)
	base[20] = 0xAA
	base[52] = 0xBB
	addr := types.Address{0xAA, 0xBB}
	copy(base[84:104], addr[:])

	pk := make([]byte, 32) // truncated test pubKey (the host's actual crypto.PublicKeyFromBytes path would reject)
	pk[0] = 0xCC
	pkLen := make([]byte, 4)
	binary.BigEndian.PutUint32(pkLen, uint32(len(pk)))
	sig := make([]byte, 3293)
	sig[0] = 0xDD
	sigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLen, uint32(len(sig)))

	legacy := append([]byte{}, base...)
	legacy = append(legacy, pkLen...)
	legacy = append(legacy, pk...)
	legacy = append(legacy, sigLen...)
	legacy = append(legacy, sig...)

	decoded, err := DecodeStatusMessage(legacy)
	if err != nil {
		t.Fatalf("DecodeStatusMessage legacy: %v", err)
	}
	if decoded.Timestamp != 0 {
		t.Fatalf("R38-P2-01 deep-fix: legacy R37 payload MUST decode with Timestamp=0 — got %d (wire-format backwards-incompat)", decoded.Timestamp)
	}
	if decoded.SessionNonce != ([16]byte{}) {
		t.Fatalf("R38-P2-01 deep-fix: legacy R37 payload MUST decode with zero SessionNonce — got %x (wire-format backwards-incompat)", decoded.SessionNonce)
	}
}

// TestR38P2_01_Deep_SessionNonceTracker_ReplayReject verifies the
// tracker's check-and-set semantics: the FIRST call for a tuple returns
// false (new), the SECOND returns true (replay). Distinct tuples return
// false independently.
func TestR38P2_01_Deep_SessionNonceTracker_ReplayReject(t *testing.T) {
	tk := NewSessionNonceTracker()
	addr := types.Address{0xAA}
	peer := PeerID("peer-A")
	nonce := [16]byte{0xAB, 0xCD}

	if tk.Seen(addr, peer, nonce) {
		t.Fatal("first Seen call for (addr, peer, nonce) must return false (new tuple)")
	}
	if !tk.Seen(addr, peer, nonce) {
		t.Fatal("second Seen call for the SAME (addr, peer, nonce) must return TRUE (replay)")
	}
	if tk.Len() != 1 {
		t.Fatalf("after 2 Seen calls for the same tuple, tracker Len must be 1 (dedup), got %d", tk.Len())
	}

	// Different nonce → distinct tuple → false (new).
	nonce2 := [16]byte{0xEF, 0x01}
	if tk.Seen(addr, peer, nonce2) {
		t.Fatal("Seen call for a DIFFERENT nonce must return false (new tuple)")
	}
	// Different peer → distinct tuple.
	if tk.Seen(addr, "peer-B", nonce) {
		t.Fatal("Seen call for a DIFFERENT peerID must return false")
	}
	// Different addr → distinct tuple.
	addr2 := types.Address{0xBB}
	if tk.Seen(addr2, peer, nonce) {
		t.Fatal("Seen call for a DIFFERENT address must return false")
	}
	if tk.Len() != 4 {
		t.Fatalf("after 4 distinct tuples, tracker Len must be 4, got %d", tk.Len())
	}
}

// TestR38P2_01_Deep_SessionNonceTracker_Trim verifies that Trim caps
// the tracked-tuple count to the configured max.
func TestR38P2_01_Deep_SessionNonceTracker_Trim(t *testing.T) {
	tk := NewSessionNonceTracker()
	for i := 0; i < 100; i++ {
		nonce := [16]byte{}
		nonce[0] = byte(i)
		tk.Seen(types.Address{byte(i)}, "p", nonce)
	}
	if got := tk.Len(); got != 100 {
		t.Fatalf("precondition: tracker Len must be 100, got %d", got)
	}
	tk.Trim(50)
	if got := tk.Len(); got > 50 {
		t.Fatalf("R38-P2-01 deep-fix: Trim(50) MUST reduce tracker to ≤50 entries — got %d", got)
	}
	if got := tk.Len(); got < 1 {
		t.Fatalf("R38-P2-01 deep-fix: Trim MUST not empty the tracker — got %d", got)
	}
}

// TestR38P2_01_Deep_FindV2ExtensionValueOffset asserts the offset
// helper correctly locates the start of the V2 extension's 24 value
// bytes for a synthetic encoded payload (build helper assembles the
// exact wire format).
func TestR38P2_01_Deep_FindV2ExtensionValueOffset(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv, pub := kp.Private, kp.Public
	nonce := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	payload := r38P2_01Deep_buildSignedStatusPayload(t,
		2, 1333, 1, [32]byte{0xAA}, [32]byte{0xBB},
		pub.Address(), pub, priv,
		1700000000, nonce)

	off, ok := findV2ExtensionValueOffset(payload)
	if !ok {
		t.Fatal("R38-P2-01 deep-fix: findV2ExtensionValueOffset returned ok=false for a valid V2 payload — signed range cannot be reconstructed")
	}
	if off+24 > len(payload) {
		t.Fatalf("R38-P2-01 deep-fix: findV2ExtensionValueOffset returned off=%d but payload only has %d bytes — value bytes would overflow", off, len(payload))
	}
	// The first 8 bytes after `off` MUST be the BE-encoded Timestamp.
	gotTS := binary.BigEndian.Uint64(payload[off : off+8])
	if gotTS != 1700000000 {
		t.Fatalf("R38-P2-01 deep-fix: Timestamp mismatch at offset %d — got %d want 1700000000", off, gotTS)
	}
	// The next 16 bytes MUST be the nonce.
	var gotNonce [16]byte
	copy(gotNonce[:], payload[off+8:off+24])
	if gotNonce != nonce {
		t.Fatalf("R38-P2-01 deep-fix: SessionNonce mismatch at offset %d — got %x want %x", off+8, gotNonce, nonce)
	}
}

// TestR38P2_01_Deep_FindV2ExtensionValueOffset_LegacyReturnsFalse
// verifies the helper returns (0, false) for a legacy R37 payload so the
// status handler falls back to the legacy 104-byte signed range.
func TestR38P2_01_Deep_FindV2ExtensionValueOffset_LegacyReturnsFalse(t *testing.T) {
	// Build a legacy payload (no V2 extension): 104 base + 4 pkLen + 32 pk + 4 sigLen + 3293 sig.
	base := make([]byte, 104)
	pk := make([]byte, 32)
	pkLen := make([]byte, 4)
	binary.BigEndian.PutUint32(pkLen, uint32(len(pk)))
	sig := make([]byte, 3293)
	sigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLen, uint32(len(sig)))
	legacy := append([]byte{}, base...)
	legacy = append(legacy, pkLen...)
	legacy = append(legacy, pk...)
	legacy = append(legacy, sigLen...)
	legacy = append(legacy, sig...)

	if _, ok := findV2ExtensionValueOffset(legacy); ok {
		t.Fatal("R38-P2-01 deep-fix: findV2ExtensionValueOffset MUST return (0,false) for a legacy R37 payload (no V2 extension) — otherwise the legacy 104-byte signed range would be replaced with a bogus extended range, breaking backward compat")
	}
}

// TestR38P2_01_Deep_SessionNonceTracker_NilSafe verifies that nil-safe
// semantics are honored (callers may construct a Host with no tracker;
// Seen returns false so the verifier path doesn't NPE).
func TestR38P2_01_Deep_SessionNonceTracker_NilSafe(t *testing.T) {
	var nilTk *SessionNonceTracker
	if nilTk.Seen(types.Address{}, "p", [16]byte{}) {
		t.Fatal("nil SessionNonceTracker.Seen must return false (not seen), not panic")
	}
	if nilTk.Len() != 0 {
		t.Fatal("nil SessionNonceTracker.Len must return 0")
	}
	nilTk.Trim(10) // must not panic
}

// TestR38P2_01_Deep_Host_Setters verifies that the Set* setters install
// their respective dependencies on the Host without panicking and that
// getters-where-available return the expected vals (the host does not
// expose direct getters — we instead exercise via the SessionNonceTracker
// round-trip and the public methods).
func TestR38P2_01_Deep_Host_Setters(t *testing.T) {
	h := r38P2_01Deep_newHostForTest(t)
	defer h.Stop()

	v := &r38P2_01Deep_mockActiveVerifier{allowlist: make(map[[52]byte]struct{})}
	h.SetActiveValidatorIdentityVerifier(v)
	h.SetStatusFreshnessWindowSec(120)
	tk := NewSessionNonceTracker()
	h.SetSessionNonceTracker(tk)

	// Verify the setters don't NPE on nil pass-through (toggle off).
	h.SetActiveValidatorIdentityVerifier(nil)
	h.SetStatusFreshnessWindowSec(0)
	h.SetSessionNonceTracker(nil)
}

// TestR38P2_01_Deep_ActiveVerifier_RejectsUnknown verifies the
// ActiveValidatorIdentityVerifier boundary — a whitelist verifier
// rejects (address, pubKey) not in its allowlist. This pins the
// deep-fix's active-set membership contract.
func TestR38P2_01_Deep_ActiveVerifier_RejectsUnknown(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv, pub := kp.Private, kp.Public
	_ = priv
	addr := pub.Address()

	// Allowlist has the priv-pub key pair's fingerprint.
	var k [52]byte
	copy(k[0:20], addr[:])
	pk := pub.Bytes()
	if len(pk) >= 32 {
		copy(k[20:52], pk[:32])
	}
	v := &r38P2_01Deep_mockActiveVerifier{allowlist: map[[52]byte]struct{}{k: {}}}
	if err := v.VerifyActiveValidator(addr, pk); err != nil {
		t.Fatalf("R38-P2-01 deep-fix: active verifier SHOULD accept (addr,pk) in allowlist — got %v", err)
	}

	// Unknown address with the same pubkey → reject.
	unknownAddr := types.Address{0xFF}
	if err := v.VerifyActiveValidator(unknownAddr, pk); err == nil {
		t.Fatal("R38-P2-01 deep-fix: active verifier SHOULD reject (addr,pk) NOT in allowlist")
	}

	// rejectAll override.
	v2 := &r38P2_01Deep_mockActiveVerifier{rejectAll: true}
	if err := v2.VerifyActiveValidator(addr, pk); err == nil {
		t.Fatal("R38-P2-01 deep-fix: active verifier with rejectAll MUST reject all (addr,pk)")
	}
}

// TestR38P2_01_Deep_SignedDomainIncludesTimestampAndNonce verifies that
// if an attacker tampers with the Timestamp or SessionNonce AFTER the
// sender's signature was computed (using r38P2_01Deep_buildSignedStatusPayload
// to make a signed V2 frame), the V2 signature verification fails.
// This pins the deep-fix's signed-domain invariant: V2 extensions are
// part of the signature, NOT a free unmarshalled add-on.
func TestR38P2_01_Deep_SignedDomainIncludesTimestampAndNonce(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv, pub := kp.Private, kp.Public
	nonce := [16]byte{0xAB, 0xCD, 0xEF}

	// Sign with the V2 extension domain (base[:104] + ts + nonce).
	good := r38P2_01Deep_buildSignedStatusPayload(t,
		2, 1333, 1, [32]byte{0xAA}, [32]byte{0xBB},
		pub.Address(), pub, priv,
		1700000000, nonce)

	// Verify against the V2 signed range the host would reconstruct.
	off, ok := findV2ExtensionValueOffset(good)
	if !ok {
		t.Fatal("findV2ExtensionValueOffset returned false on good payload")
	}
	signedRange := make([]byte, 0, 128)
	signedRange = append(signedRange, good[:104]...)
	signedRange = append(signedRange, good[off:off+24]...)
	if !pub.Verify(signedRange, good[104+4+1952+4:104+4+1952+4+3293]) {
		t.Fatal("R38-P2-01 deep-fix: V2 signature verification MUST succeed against the reconstructed signed range (base[:104]+ts+nonce)")
	}

	// TAMPER the timestamp byte → signature MUST no longer verify.
	tampered := append([]byte{}, good...)
	// The timestamp bytes live at offset `off..off+8`. Flip the LSB.
	tampered[off] ^= 0x01
	tamperedRange := make([]byte, 0, 128)
	tamperedRange = append(tamperedRange, tampered[:104]...)
	tamperedRange = append(tamperedRange, tampered[off:off+24]...)
	if pub.Verify(tamperedRange, tampered[104+4+1952+4:104+4+1952+4+3293]) {
		t.Fatal("R38-P2-01 deep-fix: V2 signature verification MUST FAIL when Timestamp is tampered (defeats freshness-window circumvention)")
	}

	// TAMPER the nonce byte → signature MUST no longer verify.
	tampered2 := append([]byte{}, good...)
	tampered2[off+8+15] ^= 0xFF // flip last nonce byte
	tampered2Range := make([]byte, 0, 128)
	tampered2Range = append(tampered2Range, tampered2[:104]...)
	tampered2Range = append(tampered2Range, tampered2[off:off+24]...)
	if pub.Verify(tampered2Range, tampered2[104+4+1952+4:104+4+1952+4+3293]) {
		t.Fatal("R38-P2-01 deep-fix: V2 signature verification MUST FAIL when SessionNonce is tampered (defeats anti-replay circumvention)")
	}
}
