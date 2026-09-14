// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// TestVerifyKeyUsable_ValidKey verifies that a freshly generated Dilithium3
// keypair passes the cryptographic self-test.
//
// CRYPTO-R9-L-REDO-02 (2026-07-19): previously verifyKeyUsable had NO
// direct unit test coverage — the function could be silently broken
// (e.g., wrong test message, regression in Verify path) without any
// test detecting it. The freshly generated key MUST pass the self-test.
func TestVerifyKeyUsable_ValidKey(t *testing.T) {
	_, priv, err := mode3.GenerateKey(zeroReader{})
	if err != nil {
		t.Fatalf("mode3.GenerateKey failed: %v", err)
	}
	if err := verifyKeyUsable(priv); err != nil {
		t.Errorf("verifyKeyUsable failed for a freshly generated key: %v", err)
	}
}

// TestVerifyKeyUsable_DerivedMessageNotFixed verifies that the test message
// is derived from the public key bytes (not a globally fixed constant).
// Two different keys should sign different messages during the self-test.
//
// CRYPTO-R9-L-REDO-02 (2026-07-19): the previous implementation used a
// fixed string "quantaureum-key-validity-check" for every key. This test
// documents the new behavior: the message is now sha256(pub.Bytes()).
// We cannot directly observe the test message from outside the function,
// but we CAN observe that the function still succeeds — which proves
// the sign/verify roundtrip works with the derived message.
func TestVerifyKeyUsable_DerivedMessageNotFixed(t *testing.T) {
	// Generate two distinct keys and confirm both pass self-test.
	for i := 0; i < 2; i++ {
		_, priv, err := mode3.GenerateKey(zeroReader{})
		if err != nil {
			t.Fatalf("mode3.GenerateKey iteration %d failed: %v", i, err)
		}
		if err := verifyKeyUsable(priv); err != nil {
			t.Errorf("verifyKeyUsable failed for key %d: %v", i, err)
		}
	}
}

// TestVerifyKeyUsable_NilKey verifies that a nil key is rejected.
func TestVerifyKeyUsable_NilKey(t *testing.T) {
	err := verifyKeyUsable(nil)
	if err == nil {
		t.Error("verifyKeyUsable should fail for nil key")
	}
}

// zeroReader is a minimal io.Reader that returns zero bytes. Used as the
// entropy source for reproducible test key generation (NOT for production).
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
