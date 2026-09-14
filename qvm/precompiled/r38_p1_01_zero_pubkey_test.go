// Quantaureum Node source, version 1.0.0.
package precompiled

import (
	"crypto/sha256"
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// TestR38P101_DilithiumVerifyCached_RejectsAllZeroPubKey is the RED-bar
// test for the qvm/precompiled sibling-path hardening at
// qvm/precompiled/contracts.go dilithiumVerifyCached. The QVM precompile
// is a directly attacker-reachable surface — any QVM contract can call the
// Dilithium3 precompile and pass attacker-chosen (pubkey, sig, message).
// The R37 hardening in crypto.Verify covers the caller-facing path, but
// dilithiumVerifyCached called mode3.Verify directly with a `<` length gate
// only, so a QVM contract passing an all-zero 1952-byte pubkey could
// trigger the DKG-uninitialized forgery surface from contract-readable code.
//
// R38-P1-01 added a constant-time crypto.IsZeroPublicKeyBytes rejection
// at the entry of dilithiumVerifyCached (after the cache lookup — so a
// forged zero-pubkey cache miss still has to undergo the gate, and a
// poisoned positive cache entry cannot exist because the gate runs only
// on cache miss and a zero key would never have passed the gate). This
// test passes a 1952-byte all-zero pubkey plus a 3293-byte zero signature
// plus a unique hash and asserts the function returns false (reject) —
// without panicking.
func TestR38P101_DilithiumVerifyCached_RejectsAllZeroPubKey(t *testing.T) {
	zeroPubKey := make([]byte, crypto.Dilithium3PublicKeySize)
	if !crypto.IsZeroPublicKeyBytes(zeroPubKey) {
		t.Fatalf("fixture itself is not recognized as all-zero by crypto.IsZeroPublicKeyBytes — fixture wrong")
	}
	sig := make([]byte, crypto.Dilithium3SignatureSize)
	// Unique hash per invocation so cache miss is guaranteed:
	hash := sha256.Sum256([]byte("R38-P1-01 dilithiumVerifyCached zero-PK test"))

	got := dilithiumVerifyCached(zeroPubKey, sig, hash[:])
	if got {
		t.Fatalf("R38-P1-01 dilithiumVerifyCached gate failed: returned true for an all-zero public key — attacker can forge Dilithium3 verify via QVM contracts")
	}
}

// TestR38P101_DilithiumVerifyCached_RejectsWrongLengthPubKey covers the
// sibling length-hardening. The legacy `<` length gate silently accepted
// too-long keys (passing only the first 1952 bytes to Unpack). R38-P1-01
// changed it to `!=` so any wrong-length key is explicitly rejected
// (returns false), mirroring crypto.PublicKeyFromBytes at crypto/generate.go:768.
func TestR38P101_DilithiumVerifyCached_RejectsWrongLengthPubKey(t *testing.T) {
	sig := make([]byte, crypto.Dilithium3SignatureSize)

	cases := []struct {
		name string
		size int
	}{
		{"too_short_1_byte", 1},
		{"too_short_1951_bytes", crypto.Dilithium3PublicKeySize - 1},
		{"too_long_1953_bytes", crypto.Dilithium3PublicKeySize + 1},
		{"too_long_4000_bytes", 4000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			badKey := make([]byte, c.size)
			for i := range badKey {
				badKey[i] = byte(i % 256)
				if badKey[i] == 0 {
					badKey[i] = 0x7f
				}
			}
			// Unique hash per case so cache lookup is clean:
			hash := sha256.Sum256([]byte(c.name + "wrong-length"))
			got := dilithiumVerifyCached(badKey, sig, hash[:])
			if got {
				t.Fatalf("R38-P1-01 length gate failed for %s: dilithiumVerifyCached returned true for a wrong-length pub key (got %d bytes, expected %d) — legacy `<` gate is still present",
					c.name, c.size, crypto.Dilithium3PublicKeySize)
			}
		})
	}
}

// TestR38P101_DilithiumVerifyCached_RejectsShortNonZeroKey is a sibling
// assertion: a 1-byte non-zero pub key must also be rejected by the `!=`
// length gate (the legacy `<` gate would also have caught this case since
// 1 < 1952, but we add an explicit test so the audit fix's `!=` semantics
// are exercised for the boundary size of 1 byte).
func TestR38P101_DilithiumVerifyCached_RejectsShortNonZeroKey(t *testing.T) {
	shortKey := []byte{0x42} // 1-byte non-zero
	hash := sha256.Sum256([]byte("short-nonzero-test"))
	sig := make([]byte, crypto.Dilithium3SignatureSize)
	got := dilithiumVerifyCached(shortKey, sig, hash[:])
	if got {
		t.Fatalf("R38-P1-01: dilithiumVerifyCached accepted a 1-byte pub key — wrong-length gate missing for the `< 1952` boundary")
	}
}
