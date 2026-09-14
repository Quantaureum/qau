// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"strings"
	"testing"
)

// TestCRYPTO_H02_ImportKeyPair_MalformedPublicKey_ReturnsError verifies that
// ImportKeyPair returns an error when the public key bytes are malformed.
//
// CRYPTO-H02 FIX (R29, 2026-07-26): This test exercises the error path where
// PublicKeyFromBytes fails. The fix adds `priv.Zeroize()` before returning so
// the parsed Dilithium3 private key material does not linger in heap memory.
// The zeroize call itself cannot be directly observed from outside the
// function (priv is a local variable), but this regression test ensures the
// error path remains correctly exercised and the zeroize-on-error contract
// is preserved by code inspection.
func TestCRYPTO_H02_ImportKeyPair_MalformedPublicKey_ReturnsError(t *testing.T) {
	// Generate a valid keypair to get a valid private key.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	privBytes := kp.Private.Bytes()
	pubBytes := kp.Public.Bytes()

	// Corrupt the public key bytes (wrong length).
	malformedPub := append([]byte(nil), pubBytes...)
	malformedPub = malformedPub[:len(malformedPub)-1] // truncate by 1 byte

	// ImportKeyPair should fail with a public key error.
	_, err = ImportKeyPair(privBytes, malformedPub)
	if err == nil {
		t.Fatal("ImportKeyPair should fail with malformed public key")
	}
	// The error should be related to the public key (length or parsing).
	// We don't assert the exact message to avoid coupling to implementation.
}

// TestCRYPTO_H02_ImportKeyPair_PublicKeyMismatch_ReturnsError verifies that
// ImportKeyPair returns an error when the provided public key does not match
// the private key.
//
// CRYPTO-H02 FIX (R29, 2026-07-26): This test exercises the error path where
// the derived public key does not match the provided public key. The fix adds
// `priv.Zeroize()` before returning so the parsed private key material does
// not linger in heap memory.
func TestCRYPTO_H02_ImportKeyPair_PublicKeyMismatch_ReturnsError(t *testing.T) {
	// Generate two valid keypairs.
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (1) failed: %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (2) failed: %v", err)
	}

	// ImportKeyPair with kp1's private key but kp2's public key should fail.
	_, err = ImportKeyPair(kp1.Private.Bytes(), kp2.Public.Bytes())
	if err == nil {
		t.Fatal("ImportKeyPair should fail when public key does not match private key")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("expected 'does not match' error, got: %v", err)
	}
}

// TestCRYPTO_H02_ImportKeyPair_ValidKeys_NoError verifies that the happy path
// still works after the CRYPTO-H02 fix (the zeroize calls are only on error
// paths, so the success path must not be affected).
func TestCRYPTO_H02_ImportKeyPair_ValidKeys_NoError(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	imported, err := ImportKeyPair(kp.Private.Bytes(), kp.Public.Bytes())
	if err != nil {
		t.Fatalf("ImportKeyPair with valid keys should succeed: %v", err)
	}
	if imported == nil {
		t.Fatal("ImportKeyPair returned nil KeyPair without error")
	}
	if imported.Private == nil || imported.Public == nil {
		t.Error("Imported KeyPair has nil Private or Public")
	}

	// Verify the imported keys match the originals.
	if !imported.Public.Equal(kp.Public) {
		t.Error("Imported public key does not match original")
	}
}
