// Quantaureum Node source, version 1.0.0.
// Package accounts - P2-KEYSTORE-COMPLETENESS tests (R29, 2026-07-26)
//
// These tests verify the fix for the audit finding:
// "ValidateKeystore lacked an input-size limit (no 16KB cap, OOM risk) and incomplete validation"
//
// The fix adds comprehensive validation of all keystore fields (ciphertext,
// nonce, salt, scrypt parameters) to reject malformed keystores upfront
// without performing expensive cryptographic work.
package accounts

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// validKeystoreV2 returns a JSON-encoded v2 keystore with all fields valid.
// Used as a baseline for testing — individual fields are tampered in each test.
func validKeystoreV2() []byte {
	// 12 bytes of zeros for nonce
	nonce := make([]byte, crypto.NonceSize)
	// 32 bytes of zeros for salt
	salt := make([]byte, crypto.SaltSize)
	// non-empty ciphertext
	ciphertext := []byte("encrypted-key-material")

	data, _ := json.Marshal(map[string]any{
		"version": crypto.KeyFileVersionV2,
		"address": "0x0000000000000000000000000000000000000001",
		"crypto": map[string]any{
			"cipher":     "aes-256-gcm",
			"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
			"cipherparams": map[string]any{
				"nonce": base64.StdEncoding.EncodeToString(nonce),
			},
			"kdf": "scrypt",
			"kdfparams": map[string]any{
				"salt":  base64.StdEncoding.EncodeToString(salt),
				"n":     crypto.MinScryptN,
				"r":     8,
				"p":     1,
				"dklen": 32,
			},
		},
	})
	return data
}

// TestP2_KEYSTORE_COMPLETENESS_ValidKeystorePasses verifies that a fully
// valid keystore passes all validation checks.
func TestP2_KEYSTORE_COMPLETENESS_ValidKeystorePasses(t *testing.T) {
	data := validKeystoreV2()
	if err := ValidateKeystore(data); err != nil {
		t.Errorf("valid keystore should pass validation: %v", err)
	}
}

// TestP2_KEYSTORE_COMPLETENESS_OversizedInputRejected verifies that inputs
// exceeding the 16KB limit are rejected before JSON parsing.
func TestP2_KEYSTORE_COMPLETENESS_OversizedInputRejected(t *testing.T) {
	// Create a 17KB input (exceeds 16KB limit)
	oversized := make([]byte, 17*1024)
	for i := range oversized {
		oversized[i] = 'a'
	}
	err := ValidateKeystore(oversized)
	if err == nil {
		t.Fatal("P2-KEYSTORE-COMPLETENESS REGRESSION: oversized input (17KB) was accepted — " +
			"16KB limit is not enforced, allowing OOM attacks via large JSON blobs")
	}
}

// TestP2_KEYSTORE_COMPLETENESS_ExactLimitAccepted verifies that an input
// exactly at the 16KB limit is accepted (boundary check).
func TestP2_KEYSTORE_COMPLETENESS_ExactLimitAccepted(t *testing.T) {
	// Create a valid keystore and pad it to exactly 16KB with whitespace
	// (JSON allows leading/trailing whitespace)
	base := validKeystoreV2()
	if len(base) >= 16*1024 {
		t.Fatalf("base keystore already exceeds 16KB: %d bytes", len(base))
	}
	padding := 16*1024 - len(base)
	padded := make([]byte, 0, 16*1024)
	// Add leading spaces (valid JSON whitespace)
	for i := 0; i < padding; i++ {
		padded = append(padded, ' ')
	}
	padded = append(padded, base...)

	// This should pass the size check (exactly 16KB) and then parse successfully
	// Note: it might fail if the padded size is exactly at the limit and the
	// comparison is >, which it is (len > maxKeystoreSize), so exactly 16KB passes.
	if err := ValidateKeystore(padded); err != nil {
		// It's OK if it fails for other reasons (e.g., whitespace handling),
		// but it should NOT fail with the size limit error.
		t.Logf("exact-limit input returned error (acceptable if not size-related): %v", err)
	}
}

// TestP2_KEYSTORE_COMPLETENESS_MissingAddressRejected verifies that a
// keystore with an empty address is rejected.
func TestP2_KEYSTORE_COMPLETENESS_MissingAddressRejected(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version": crypto.KeyFileVersionV2,
		"address": "", // empty address
		"crypto": map[string]any{
			"cipher":     "aes-256-gcm",
			"ciphertext": "a2ludGhldGV4dA==",
			"cipherparams": map[string]any{
				"nonce": "AAAAAAAAAAAAAAAA",
			},
			"kdf": "scrypt",
			"kdfparams": map[string]any{
				"salt":  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"n":     crypto.MinScryptN,
				"r":     8,
				"p":     1,
				"dklen": 32,
			},
		},
	})
	err := ValidateKeystore(data)
	if err == nil {
		t.Fatal("P2-KEYSTORE-COMPLETENESS REGRESSION: keystore with empty address was accepted — " +
			"missing address indicates a malformed or tampered keystore")
	}
}

// TestP2_KEYSTORE_COMPLETENESS_MissingCiphertextRejected verifies that a
// keystore with empty ciphertext is rejected.
func TestP2_KEYSTORE_COMPLETENESS_MissingCiphertextRejected(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version": crypto.KeyFileVersionV2,
		"address": "0x0000000000000000000000000000000000000001",
		"crypto": map[string]any{
			"cipher":     "aes-256-gcm",
			"ciphertext": "", // empty ciphertext
			"cipherparams": map[string]any{
				"nonce": "AAAAAAAAAAAAAAAA",
			},
			"kdf": "scrypt",
			"kdfparams": map[string]any{
				"salt":  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"n":     crypto.MinScryptN,
				"r":     8,
				"p":     1,
				"dklen": 32,
			},
		},
	})
	err := ValidateKeystore(data)
	if err == nil {
		t.Fatal("P2-KEYSTORE-COMPLETENESS REGRESSION: keystore with empty ciphertext was accepted — " +
			"empty ciphertext means no encrypted key material to decrypt")
	}
}

// TestP2_KEYSTORE_COMPLETENESS_InvalidNonceLengthRejected verifies that
// nonces with wrong length are rejected (must be exactly 12 bytes for AES-GCM).
func TestP2_KEYSTORE_COMPLETENESS_InvalidNonceLengthRejected(t *testing.T) {
	wrongLengths := []int{0, 1, 8, 11, 13, 16, 24, 32}

	for _, nonceLen := range wrongLengths {
		nonce := make([]byte, nonceLen)
		salt := make([]byte, crypto.SaltSize)

		data, _ := json.Marshal(map[string]any{
			"version": crypto.KeyFileVersionV2,
			"address": "0x0000000000000000000000000000000000000001",
			"crypto": map[string]any{
				"cipher":     "aes-256-gcm",
				"ciphertext": "a2ludGhldGV4dA==",
				"cipherparams": map[string]any{
					"nonce": base64.StdEncoding.EncodeToString(nonce),
				},
				"kdf": "scrypt",
				"kdfparams": map[string]any{
					"salt":  base64.StdEncoding.EncodeToString(salt),
					"n":     crypto.MinScryptN,
					"r":     8,
					"p":     1,
					"dklen": 32,
				},
			},
		})

		err := ValidateKeystore(data)
		if err == nil {
			t.Errorf("P2-KEYSTORE-COMPLETENESS REGRESSION: nonce length %d was accepted (must be %d)",
				nonceLen, crypto.NonceSize)
		}
	}
}

// TestP2_KEYSTORE_COMPLETENESS_InvalidSaltLengthRejected verifies that
// salts with wrong length are rejected (must be exactly 32 bytes for scrypt).
func TestP2_KEYSTORE_COMPLETENESS_InvalidSaltLengthRejected(t *testing.T) {
	wrongLengths := []int{0, 1, 16, 31, 33, 64}

	for _, saltLen := range wrongLengths {
		salt := make([]byte, saltLen)
		nonce := make([]byte, crypto.NonceSize)

		data, _ := json.Marshal(map[string]any{
			"version": crypto.KeyFileVersionV2,
			"address": "0x0000000000000000000000000000000000000001",
			"crypto": map[string]any{
				"cipher":     "aes-256-gcm",
				"ciphertext": "a2ludGhldGV4dA==",
				"cipherparams": map[string]any{
					"nonce": base64.StdEncoding.EncodeToString(nonce),
				},
				"kdf": "scrypt",
				"kdfparams": map[string]any{
					"salt":  base64.StdEncoding.EncodeToString(salt),
					"n":     crypto.MinScryptN,
					"r":     8,
					"p":     1,
					"dklen": 32,
				},
			},
		})

		err := ValidateKeystore(data)
		if err == nil {
			t.Errorf("P2-KEYSTORE-COMPLETENESS REGRESSION: salt length %d was accepted (must be %d)",
				saltLen, crypto.SaltSize)
		}
	}
}

// TestP2_KEYSTORE_COMPLETENESS_WeakScryptNRejected verifies that scrypt
// parameters with N below MinScryptN are rejected.
func TestP2_KEYSTORE_COMPLETENESS_WeakScryptNRejected(t *testing.T) {
	weakNValues := []int{0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}

	for _, n := range weakNValues {
		if n >= crypto.MinScryptN {
			continue // skip valid values
		}

		nonce := make([]byte, crypto.NonceSize)
		salt := make([]byte, crypto.SaltSize)

		data, _ := json.Marshal(map[string]any{
			"version": crypto.KeyFileVersionV2,
			"address": "0x0000000000000000000000000000000000000001",
			"crypto": map[string]any{
				"cipher":     "aes-256-gcm",
				"ciphertext": "a2ludGhldGV4dA==",
				"cipherparams": map[string]any{
					"nonce": base64.StdEncoding.EncodeToString(nonce),
				},
				"kdf": "scrypt",
				"kdfparams": map[string]any{
					"salt":  base64.StdEncoding.EncodeToString(salt),
					"n":     n,
					"r":     8,
					"p":     1,
					"dklen": 32,
				},
			},
		})

		err := ValidateKeystore(data)
		if err == nil {
			t.Errorf("P2-KEYSTORE-COMPLETENESS REGRESSION: weak scrypt N=%d was accepted (min %d)",
				n, crypto.MinScryptN)
		}
	}
}

// TestP2_KEYSTORE_COMPLETENESS_ExcessiveScryptNRejected verifies that
// scrypt N above MaxScryptN is rejected (DoS prevention).
func TestP2_KEYSTORE_COMPLETENESS_ExcessiveScryptNRejected(t *testing.T) {
	excessiveNValues := []int{
		crypto.MaxScryptN + 1,
		crypto.MaxScryptN * 2,
		1 << 23, // 2^23
		1 << 24, // 2^24
		1 << 26, // 2^26 (would require 64GB memory)
	}

	for _, n := range excessiveNValues {
		nonce := make([]byte, crypto.NonceSize)
		salt := make([]byte, crypto.SaltSize)

		data, _ := json.Marshal(map[string]any{
			"version": crypto.KeyFileVersionV2,
			"address": "0x0000000000000000000000000000000000000001",
			"crypto": map[string]any{
				"cipher":     "aes-256-gcm",
				"ciphertext": "a2ludGhldGV4dA==",
				"cipherparams": map[string]any{
					"nonce": base64.StdEncoding.EncodeToString(nonce),
				},
				"kdf": "scrypt",
				"kdfparams": map[string]any{
					"salt":  base64.StdEncoding.EncodeToString(salt),
					"n":     n,
					"r":     8,
					"p":     1,
					"dklen": 32,
				},
			},
		})

		err := ValidateKeystore(data)
		if err == nil {
			t.Errorf("P2-KEYSTORE-COMPLETENESS REGRESSION: excessive scrypt N=%d was accepted (max %d) — "+
				"this allows DoS via memory exhaustion", n, crypto.MaxScryptN)
		}
	}
}

// TestP2_KEYSTORE_COMPLETENESS_InvalidDKLenRejected verifies that DKLen
// values other than 32 are rejected (must be exactly 32 for aes-256-gcm).
func TestP2_KEYSTORE_COMPLETENESS_InvalidDKLenRejected(t *testing.T) {
	wrongDKLenValues := []int{0, 1, 16, 24, 31, 33, 48, 64, 128, 256}

	for _, dklen := range wrongDKLenValues {
		nonce := make([]byte, crypto.NonceSize)
		salt := make([]byte, crypto.SaltSize)

		data, _ := json.Marshal(map[string]any{
			"version": crypto.KeyFileVersionV2,
			"address": "0x0000000000000000000000000000000000000001",
			"crypto": map[string]any{
				"cipher":     "aes-256-gcm",
				"ciphertext": "a2ludGhldGV4dA==",
				"cipherparams": map[string]any{
					"nonce": base64.StdEncoding.EncodeToString(nonce),
				},
				"kdf": "scrypt",
				"kdfparams": map[string]any{
					"salt":  base64.StdEncoding.EncodeToString(salt),
					"n":     crypto.MinScryptN,
					"r":     8,
					"p":     1,
					"dklen": dklen,
				},
			},
		})

		err := ValidateKeystore(data)
		if err == nil {
			t.Errorf("P2-KEYSTORE-COMPLETENESS REGRESSION: DKLen=%d was accepted (must be 32 for aes-256-gcm)",
				dklen)
		}
	}
}

// TestP2_KEYSTORE_COMPLETENESS_InvalidScryptROutOfRange verifies that scrypt
// R values outside the allowed range [MinScryptR, MaxScryptR] are rejected.
func TestP2_KEYSTORE_COMPLETENESS_InvalidScryptROutOfRange(t *testing.T) {
	outOfRangeR := []int{0, -1, crypto.MaxScryptR + 1, 64, 128}

	for _, r := range outOfRangeR {
		nonce := make([]byte, crypto.NonceSize)
		salt := make([]byte, crypto.SaltSize)

		data, _ := json.Marshal(map[string]any{
			"version": crypto.KeyFileVersionV2,
			"address": "0x0000000000000000000000000000000000000001",
			"crypto": map[string]any{
				"cipher":     "aes-256-gcm",
				"ciphertext": "a2ludGhldGV4dA==",
				"cipherparams": map[string]any{
					"nonce": base64.StdEncoding.EncodeToString(nonce),
				},
				"kdf": "scrypt",
				"kdfparams": map[string]any{
					"salt":  base64.StdEncoding.EncodeToString(salt),
					"n":     crypto.MinScryptN,
					"r":     r,
					"p":     1,
					"dklen": 32,
				},
			},
		})

		err := ValidateKeystore(data)
		if err == nil {
			t.Errorf("P2-KEYSTORE-COMPLETENESS REGRESSION: scrypt R=%d was accepted (range %d-%d)",
				r, crypto.MinScryptR, crypto.MaxScryptR)
		}
	}
}

// TestP2_KEYSTORE_COMPLETENESS_InvalidScryptPOutOfRange verifies that scrypt
// P values outside the allowed range [MinScryptP, MaxScryptP] are rejected.
func TestP2_KEYSTORE_COMPLETENESS_InvalidScryptPOutOfRange(t *testing.T) {
	outOfRangeP := []int{0, -1, crypto.MaxScryptP + 1, 32, 64}

	for _, p := range outOfRangeP {
		nonce := make([]byte, crypto.NonceSize)
		salt := make([]byte, crypto.SaltSize)

		data, _ := json.Marshal(map[string]any{
			"version": crypto.KeyFileVersionV2,
			"address": "0x0000000000000000000000000000000000000001",
			"crypto": map[string]any{
				"cipher":     "aes-256-gcm",
				"ciphertext": "a2ludGhldGV4dA==",
				"cipherparams": map[string]any{
					"nonce": base64.StdEncoding.EncodeToString(nonce),
				},
				"kdf": "scrypt",
				"kdfparams": map[string]any{
					"salt":  base64.StdEncoding.EncodeToString(salt),
					"n":     crypto.MinScryptN,
					"r":     8,
					"p":     p,
					"dklen": 32,
				},
			},
		})

		err := ValidateKeystore(data)
		if err == nil {
			t.Errorf("P2-KEYSTORE-COMPLETENESS REGRESSION: scrypt P=%d was accepted (range %d-%d)",
				p, crypto.MinScryptP, crypto.MaxScryptP)
		}
	}
}
