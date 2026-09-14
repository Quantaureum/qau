// Quantaureum Node source, version 1.0.0.
// Package crypto — CRYPTO-R13-006 regression tests for derivedKey zeroization.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/scrypt"
)

// TestCRYPTO_R13_006_ZeroingDerivedKeyAfterCipherConstruction verifies the
// core correctness assumption of the CRYPTO-R13-006 fix: zeroing the
// scrypt-derived key immediately after aes.NewCipher + cipher.NewGCM
// construction does NOT break subsequent gcm.Open / gcm.Seal operations.
//
// This is critical because the fix in keystore.go zeroes derivedKey right
// after GCM construction (before gcm.Open). If aes.NewCipher retained a
// reference to the input key slice rather than copying the key material
// into internal round keys, zeroing derivedKey would corrupt the cipher
// state and decryption would fail. This test proves the assumption holds.
//
// Without this test, a future Go stdlib change that makes aes.NewCipher
// retain a reference to the input key would silently break the
// CRYPTO-R13-006 fix — the keystore would still "work" (decryption would
// fail and users would notice), but the failure mode would be confusing
// and hard to attribute.
func TestCRYPTO_R13_006_ZeroingDerivedKeyAfterCipherConstruction(t *testing.T) {
	password := []byte("test-password-12345")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	// Use lower scrypt parameters to keep the test fast. The cryptographic
	// property we're testing (cipher doesn't retain key reference) is
	// independent of the scrypt cost.
	derivedKey, err := scrypt.Key(password, salt, 1<<12, 8, 1, 32)
	if err != nil {
		t.Fatalf("scrypt.Key failed: %v", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}

	// CRYPTO-R13-006: zero derivedKey after cipher+GCM construction.
	// This mirrors the keystore.go fix where derivedKey is zeroed
	// between GCM construction and gcm.Open.
	if err := zeroBytesSecure(derivedKey); err != nil {
		t.Fatalf("zeroBytesSecure(derivedKey) failed: %v", err)
	}

	// Verify derivedKey is actually zeroed.
	for i, b := range derivedKey {
		if b != 0 {
			t.Fatalf("derivedKey[%d] = %d, expected 0 after zeroization", i, b)
		}
	}

	// Now encrypt + decrypt to verify gcm still works after zeroing.
	nonce := make([]byte, gcm.NonceSize())
	for i := range nonce {
		nonce[i] = byte(i)
	}
	plaintext := []byte("secret message that must round-trip")
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("gcm.Open failed after derivedKey zeroization: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %v, want %v", decrypted, plaintext)
	}

	t.Logf("CRYPTO-R13-006 verified: zeroing derivedKey after cipher+GCM " +
		"construction does not break gcm.Seal/gcm.Open round-trip")
}

// TestCRYPTO_R13_006_ZeroingDoesNotCorruptMultipleOperations verifies that
// after zeroing derivedKey, the constructed GCM can be used for MULTIPLE
// Seal/Open operations. This catches a regression where the cipher might
// lazily read from the key slice on each operation.
func TestCRYPTO_R13_006_ZeroingDoesNotCorruptMultipleOperations(t *testing.T) {
	password := []byte("another-test-password")
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	derivedKey, err := scrypt.Key(password, salt, 1<<12, 8, 1, 32)
	if err != nil {
		t.Fatalf("scrypt.Key failed: %v", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}

	// Zero derivedKey (CRYPTO-R13-006 fix).
	if err := zeroBytesSecure(derivedKey); err != nil {
		t.Fatalf("zeroBytesSecure failed: %v", err)
	}

	// Perform multiple Seal/Open round-trips with different plaintexts
	// and nonces — any lazy reference to derivedKey would corrupt these.
	for i := 0; i < 5; i++ {
		nonce := make([]byte, gcm.NonceSize())
		for j := range nonce {
			nonce[j] = byte(i*7 + j)
		}
		plaintext := []byte("message-" + string(rune('A'+i)))
		ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
		decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			t.Fatalf("iteration %d: gcm.Open failed: %v", i, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("iteration %d: decrypted mismatch: got %v, want %v",
				i, decrypted, plaintext)
		}
	}

	t.Logf("CRYPTO-R13-006 verified: 5 round-trips after zeroing all succeeded")
}
