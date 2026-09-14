// Quantaureum Node source, version 1.0.0.
// Package crypto provides cryptographic primitives for the Quantaureum blockchain.
// This file contains unit tests for the Kyber-768 post-quantum key exchange implementation.
package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// TestKyber_GenerateKeyPair tests the GenerateKyberKeyPair function
func TestKyber_GenerateKeyPair(t *testing.T) {
	t.Parallel()

	t.Run("Happy path key generation", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}
		if kp == nil {
			t.Fatal("GenerateKyberKeyPair() returned nil KeyPair")
		}
		if kp.Private == nil {
			t.Fatal("GenerateKyberKeyPair() returned nil Private key")
		}
		if kp.Public == nil {
			t.Fatal("GenerateKyberKeyPair() returned nil Public key")
		}

		// Verify the private key can derive its public key
		derivedPub, err := kp.Private.PublicKey()
		if err != nil {
			t.Fatalf("PrivateKey.PublicKey() failed: %v", err)
		}
		if derivedPub == nil {
			t.Fatal("PrivateKey.PublicKey() returned nil")
		}
		// Verify the derived public key matches the original
		if !kp.Public.Equal(derivedPub) {
			t.Fatal("Derived public key does not match original public key")
		}
	})

	t.Run("Multiple key generations produce different keys", func(t *testing.T) {
		kp1, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}
		kp2, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}
		// Two different key pairs should not be equal
		if kp1.Private.Equal(kp2.Private) {
			t.Fatal("Two different key pairs have equal private keys")
		}
		if kp1.Public.Equal(kp2.Public) {
			t.Fatal("Two different key pairs have equal public keys")
		}
	})
}

// TestKyber_Exchange tests the Exchange method for key exchange
func TestKyber_Exchange(t *testing.T) {
	t.Parallel()

	t.Run("Valid key exchange between two parties", func(t *testing.T) {
		// Generate key pairs for both parties
		aliceKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed for Alice: %v", err)
		}
		bobKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed for Bob: %v", err)
		}

		// Alice encapsulates using Bob's public key
		aliceSharedKey, ciphertext, err := aliceKP.Private.Exchange(bobKP.Public)
		if err != nil {
			t.Fatalf("Alice Exchange() failed: %v", err)
		}
		if aliceSharedKey == nil {
			t.Fatal("Alice Exchange() returned nil shared key")
		}
		if len(aliceSharedKey) != KyberSharedKeySize {
			t.Fatalf("Alice shared key wrong size: got %d, want %d", len(aliceSharedKey), KyberSharedKeySize)
		}
		if ciphertext == nil {
			t.Fatal("Alice Exchange() returned nil ciphertext")
		}
		if len(ciphertext) != KyberCiphertextSize {
			t.Fatalf("Ciphertext wrong size: got %d, want %d", len(ciphertext), KyberCiphertextSize)
		}

		// Bob decapsulates using his private key and the ciphertext
		bobSharedKey, err := bobKP.Private.Decapsulate(ciphertext)
		if err != nil {
			t.Fatalf("Bob Decapsulate() failed: %v", err)
		}
		if bobSharedKey == nil {
			t.Fatal("Bob Decapsulate() returned nil shared key")
		}

		// Both should derive the same shared key
		if !bytes.Equal(aliceSharedKey, bobSharedKey) {
			t.Fatal("Shared keys do not match between Alice and Bob")
		}
	})

	t.Run("Verify shared secret consistency between initiator and responder", func(t *testing.T) {
		// Multiple round trips to ensure consistency
		for i := 0; i < 5; i++ {
			aliceKP, err := GenerateKyberKeyPair()
			if err != nil {
				t.Fatalf("GenerateKyberKeyPair() failed for Alice: %v", err)
			}
			bobKP, err := GenerateKyberKeyPair()
			if err != nil {
				t.Fatalf("GenerateKyberKeyPair() failed for Bob: %v", err)
			}

			aliceSharedKey, ciphertext, err := aliceKP.Private.Exchange(bobKP.Public)
			if err != nil {
				t.Fatalf("Alice Exchange() failed: %v", err)
			}

			bobSharedKey, err := bobKP.Private.Decapsulate(ciphertext)
			if err != nil {
				t.Fatalf("Bob Decapsulate() failed: %v", err)
			}

			if !bytes.Equal(aliceSharedKey, bobSharedKey) {
				t.Fatalf("Iteration %d: Shared keys do not match", i)
			}
		}
	})

	t.Run("Exchange with nil recipient public key", func(t *testing.T) {
		aliceKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		_, _, err = aliceKP.Private.Exchange(nil)
		if err == nil {
			t.Fatal("Exchange(nil) did not return error")
		}
	})
}

// TestKyber_Decapsulate tests the Decapsulate method
func TestKyber_Decapsulate(t *testing.T) {
	t.Parallel()

	t.Run("Kyber private key decapsulates correctly", func(t *testing.T) {
		aliceKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}
		bobKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		// Alice encapsulates
		aliceSharedKey, ciphertext, err := aliceKP.Private.Exchange(bobKP.Public)
		if err != nil {
			t.Fatalf("Exchange() failed: %v", err)
		}

		// Bob decapsulates
		bobSharedKey, err := bobKP.Private.Decapsulate(ciphertext)
		if err != nil {
			t.Fatalf("Decapsulate() failed: %v", err)
		}

		// Keys should match
		if !bytes.Equal(aliceSharedKey, bobSharedKey) {
			t.Fatal("Decapsulated key does not match encapsulated key")
		}
	})

	t.Run("Decapsulate with nil ciphertext", func(t *testing.T) {
		bobKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		_, err = bobKP.Private.Decapsulate(nil)
		if err == nil {
			t.Fatal("Decapsulate(nil) did not return error")
		}
	})

	t.Run("Decapsulate with wrong length ciphertext", func(t *testing.T) {
		bobKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		wrongLenCiphertext := make([]byte, KyberCiphertextSize-1)
		if _, err := rand.Read(wrongLenCiphertext); err != nil {
			t.Fatalf("Failed to generate random ciphertext: %v", err)
		}

		_, err = bobKP.Private.Decapsulate(wrongLenCiphertext)
		if err == nil {
			t.Fatal("Decapsulate(wrong length) did not return error")
		}
	})

	t.Run("Decapsulate with tampered ciphertext", func(t *testing.T) {
		aliceKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}
		bobKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		// Alice encapsulates
		aliceShared, ciphertext, err := aliceKP.Private.Exchange(bobKP.Public)
		if err != nil {
			t.Fatalf("Exchange() failed: %v", err)
		}

		// Tamper with the ciphertext
		tamperedCiphertext := make([]byte, len(ciphertext))
		copy(tamperedCiphertext, ciphertext)
		tamperedCiphertext[0] ^= 0xFF

		// Bob tries to decapsulate tampered ciphertext
		bobShared, err := bobKP.Private.Decapsulate(tamperedCiphertext)
		if err != nil {
			t.Fatalf("Decapsulate(tampered) returned error: %v", err)
		}

		// Should produce a different key (not the same as Alice's)
		if bytes.Equal(aliceShared, bobShared) {
			t.Fatal("Tampered ciphertext produced same shared key")
		}
	})
}

// TestKyber_KeySerialization tests key serialization and deserialization
func TestKyber_KeySerialization(t *testing.T) {
	t.Parallel()

	t.Run("KyberPrivateKeyFromBytes and KyberPublicKeyFromBytes roundtrip", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		// Get private key bytes
		privBytes, err := kp.Private.Bytes()
		if err != nil {
			t.Fatalf("PrivateKey.Bytes() failed: %v", err)
		}
		if privBytes == nil {
			t.Fatal("PrivateKey.Bytes() returned nil")
		}
		if len(privBytes) != KyberPrivateKeySize {
			t.Fatalf("PrivateKey.Bytes() returned wrong size: got %d, want %d", len(privBytes), KyberPrivateKeySize)
		}

		// Reconstruct from bytes
		priv2, err := KyberPrivateKeyFromBytes(privBytes)
		if err != nil {
			t.Fatalf("KyberPrivateKeyFromBytes() failed: %v", err)
		}
		if priv2 == nil {
			t.Fatal("KyberPrivateKeyFromBytes() returned nil")
		}

		// Verify they are equal
		if !kp.Private.Equal(priv2) {
			t.Fatal("Reconstructed private key does not match original")
		}

		// Get public key bytes
		pubBytes, err := kp.Public.Bytes()
		if err != nil {
			t.Fatalf("PublicKey.Bytes() failed: %v", err)
		}
		if pubBytes == nil {
			t.Fatal("PublicKey.Bytes() returned nil")
		}
		if len(pubBytes) != KyberPublicKeySize {
			t.Fatalf("PublicKey.Bytes() returned wrong size: got %d, want %d", len(pubBytes), KyberPublicKeySize)
		}

		// Reconstruct public key from bytes
		pub2, err := KyberPublicKeyFromBytes(pubBytes)
		if err != nil {
			t.Fatalf("KyberPublicKeyFromBytes() failed: %v", err)
		}
		if pub2 == nil {
			t.Fatal("KyberPublicKeyFromBytes() returned nil")
		}

		// Verify they are equal
		if !kp.Public.Equal(pub2) {
			t.Fatal("Reconstructed public key does not match original")
		}

		// Verify key exchange still works with reconstructed keys
		aliceKP, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		aliceShared, ciphertext, err := aliceKP.Private.Exchange(pub2)
		if err != nil {
			t.Fatalf("Exchange() with reconstructed key failed: %v", err)
		}

		bobShared, err := priv2.Decapsulate(ciphertext)
		if err != nil {
			t.Fatalf("Decapsulate() with reconstructed key failed: %v", err)
		}

		if !bytes.Equal(aliceShared, bobShared) {
			t.Fatal("Reconstructed keys failed to produce matching shared secret")
		}
	})

	t.Run("Invalid length bytes for KyberPrivateKeyFromBytes", func(t *testing.T) {
		invalidBytes := make([]byte, KyberPrivateKeySize-1)
		if _, err := rand.Read(invalidBytes); err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}
		_, err := KyberPrivateKeyFromBytes(invalidBytes)
		if err == nil {
			t.Fatalf("KyberPrivateKeyFromBytes() did not return error for length %d", len(invalidBytes))
		}
	})

	t.Run("Invalid length bytes for KyberPublicKeyFromBytes", func(t *testing.T) {
		invalidBytes := make([]byte, KyberPublicKeySize-1)
		if _, err := rand.Read(invalidBytes); err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}
		_, err := KyberPublicKeyFromBytes(invalidBytes)
		if err == nil {
			t.Fatalf("KyberPublicKeyFromBytes() did not return error for length %d", len(invalidBytes))
		}
	})
}

// TestKyber_Equal tests the Equal method for Kyber keys
func TestKyber_Equal(t *testing.T) {
	t.Parallel()

	t.Run("Two identical keys are equal", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		// Private key equal to itself
		if !kp.Private.Equal(kp.Private) {
			t.Fatal("PrivateKey.Equal() returned false for identical keys")
		}

		// Public key equal to itself
		if !kp.Public.Equal(kp.Public) {
			t.Fatal("PublicKey.Equal() returned false for identical keys")
		}
	})

	t.Run("Two different keys are not equal", func(t *testing.T) {
		kp1, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}
		kp2, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		// Different private keys are not equal
		if kp1.Private.Equal(kp2.Private) {
			t.Fatal("Different private keys are reported as equal")
		}

		// Different public keys are not equal
		if kp1.Public.Equal(kp2.Public) {
			t.Fatal("Different public keys are reported as equal")
		}
	})

	t.Run("Nil keys handled correctly", func(t *testing.T) {
		var nilPriv *KyberPrivateKey
		var nilPub *KyberPublicKey

		// Nil private key compared to nil
		if !nilPriv.Equal(nil) {
			t.Fatal("Nil KyberPrivateKey.Equal(nil) returned false")
		}

		// Nil public key compared to nil
		if !nilPub.Equal(nil) {
			t.Fatal("Nil KyberPublicKey.Equal(nil) returned false")
		}

		// Real key compared to nil
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}
		if kp.Private.Equal(nil) {
			t.Fatal("Real KyberPrivateKey.Equal(nil) returned true")
		}
		if kp.Public.Equal(nil) {
			t.Fatal("Real KyberPublicKey.Equal(nil) returned true")
		}
	})
}

// TestKyber_Destroy tests the Destroy method
func TestKyber_Destroy(t *testing.T) {
	t.Parallel()

	t.Run("Verify destroy doesn't panic", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		// Destroy should not panic
		err = kp.Private.Destroy()
		if err != nil {
			t.Fatalf("Destroy() returned error: %v", err)
		}
	})

	t.Run("Post-destroy operations handled correctly", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		// Destroy the private key
		err = kp.Private.Destroy()
		if err != nil {
			t.Fatalf("Destroy() failed: %v", err)
		}

		// Bytes() should return error after destroy
		_, err = kp.Private.Bytes()
		if err == nil {
			t.Fatal("Bytes() did not return error after destroy")
		}

		// PublicKey() should return error after destroy
		_, err = kp.Private.PublicKey()
		if err == nil {
			t.Fatal("PublicKey() did not return error after destroy")
		}

		// Exchange() should return error after destroy
		kp2, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}
		_, _, err = kp.Private.Exchange(kp2.Public)
		if err == nil {
			t.Fatal("Exchange() did not return error after destroy")
		}
	})

	t.Run("Destroy nil key doesn't panic", func(t *testing.T) {
		var nilKey *KyberPrivateKey
		err := nilKey.Destroy()
		if err != nil {
			t.Fatalf("Destroy(nil) returned error: %v", err)
		}
	})
}

// TestKyber_PublicKey tests the PublicKey derivation method
func TestKyber_PublicKey(t *testing.T) {
	t.Parallel()

	t.Run("PrivateKey.PublicKey returns correct type", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		pub, err := kp.Private.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey() failed: %v", err)
		}
		if pub == nil {
			t.Fatal("PublicKey() returned nil")
		}

		// Verify it returns the same public key as the key pair
		if !kp.Public.Equal(pub) {
			t.Fatal("PrivateKey.PublicKey() does not match KeyPair.Public")
		}
	})

	t.Run("Nil PrivateKey.PublicKey returns error", func(t *testing.T) {
		var nilPriv *KyberPrivateKey
		pub, err := nilPriv.PublicKey()
		if err == nil {
			t.Fatal("Nil PrivateKey.PublicKey() did not return error")
		}
		if pub != nil {
			t.Fatal("Nil PrivateKey.PublicKey() returned non-nil public key")
		}
	})
}

// TestKyber_Bytes tests the Bytes method for Kyber keys
func TestKyber_Bytes(t *testing.T) {
	t.Parallel()

	t.Run("PrivateKey.Bytes returns correct size", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		privBytes, err := kp.Private.Bytes()
		if err != nil {
			t.Fatalf("Bytes() failed: %v", err)
		}
		if len(privBytes) != KyberPrivateKeySize {
			t.Fatalf("Bytes() returned wrong size: got %d, want %d", len(privBytes), KyberPrivateKeySize)
		}
	})

	t.Run("PublicKey.Bytes returns correct size", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		pubBytes, err := kp.Public.Bytes()
		if err != nil {
			t.Fatalf("Bytes() failed: %v", err)
		}
		if len(pubBytes) != KyberPublicKeySize {
			t.Fatalf("Bytes() returned wrong size: got %d, want %d", len(pubBytes), KyberPublicKeySize)
		}
	})

	t.Run("Nil PrivateKey.Bytes returns error", func(t *testing.T) {
		var nilPriv *KyberPrivateKey
		_, err := nilPriv.Bytes()
		if err == nil {
			t.Fatal("Nil Bytes() did not return error")
		}
	})

	t.Run("Nil PublicKey.Bytes returns error", func(t *testing.T) {
		var nilPub *KyberPublicKey
		_, err := nilPub.Bytes()
		if err == nil {
			t.Fatal("Nil Bytes() did not return error")
		}
	})
}

func TestKyber_Zeroize(t *testing.T) {
	t.Run("Zeroize valid key", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}

		err = kp.Private.Zeroize()
		if err != nil {
			t.Fatalf("Zeroize() failed: %v", err)
		}

		_, err = kp.Private.Bytes()
		if err == nil {
			t.Fatal("Bytes() did not return error after Zeroize")
		}
	})

	t.Run("Zeroize nil key", func(t *testing.T) {
		var nilKey *KyberPrivateKey
		err := nilKey.Zeroize()
		if err != nil {
			t.Fatalf("Zeroize(nil) returned error: %v", err)
		}
	})

	t.Run("Zeroize already zeroized key", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
		}
		_ = kp.Private.Zeroize()
		err = kp.Private.Zeroize()
		if err != nil {
			t.Fatalf("second Zeroize() should not error: %v", err)
		}
	})
}

func TestKyber_Destroy_Twice(t *testing.T) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
	}
	_ = kp.Private.Destroy()
	err = kp.Private.Destroy()
	if err != nil {
		t.Fatalf("second Destroy() should not error: %v", err)
	}
}

// TestKyber_Destroy_PairedPublicKeyIntact verifies CRY-R3-01 fix:
// Destroy() must zero the secret scalar (sk) and rejection key (z) but
// MUST NOT corrupt the paired standalone PublicKey, whose internal
// *cpapke.PublicKey is shared (same pointer) with PrivateKey.pk.
// Before the fix, zeroInternalKeyState recursed into pk and zeroed the
// public key's polynomial coefficients, breaking Encapsulate/Bytes/Equal.
func TestKyber_Destroy_PairedPublicKeyIntact(t *testing.T) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
	}

	// Snapshot the public key bytes BEFORE destroying the private key.
	pubBytesBefore, err := kp.Public.Bytes()
	if err != nil {
		t.Fatalf("Public.Bytes() before Destroy failed: %v", err)
	}

	// Destroy the private key — must not touch the paired public key.
	if err := kp.Private.Destroy(); err != nil {
		t.Fatalf("Destroy() failed: %v", err)
	}

	// The paired public key bytes must be IDENTICAL after Destroy.
	pubBytesAfter, err := kp.Public.Bytes()
	if err != nil {
		t.Fatalf("Public.Bytes() after Destroy failed: %v (CRY-R3-01: paired pk corrupted)", err)
	}
	if !bytes.Equal(pubBytesBefore, pubBytesAfter) {
		t.Fatal("CRY-R3-01: paired PublicKey bytes changed after PrivateKey.Destroy() — shared pk was zeroed")
	}

	// Encapsulate using the paired public key must still succeed and produce
	// a non-empty ciphertext + shared secret.
	ct, ss, err := kyber768.Scheme().Encapsulate(kp.Public.key)
	if err != nil {
		t.Fatalf("Encapsulate() after Destroy failed: %v (CRY-R3-01: paired pk corrupted)", err)
	}
	if len(ct) == 0 || len(ss) == 0 {
		t.Fatal("CRY-R3-01: Encapsulate() returned empty ct/ss after Destroy — paired pk corrupted")
	}

	// Equal against a fresh copy of the same public key must still hold.
	pubCopy, err := KyberPublicKeyFromBytes(pubBytesBefore)
	if err != nil {
		t.Fatalf("KyberPublicKeyFromBytes failed: %v", err)
	}
	if !kp.Public.Equal(pubCopy) {
		t.Fatal("CRY-R3-01: paired PublicKey.Equal() failed after Destroy — shared pk was zeroed")
	}
}

// TestKyber_Zeroize_PairedPublicKeyIntact verifies the same CRY-R3-01
// invariant for the Zeroize() path (which also calls zeroInternalKeyState).
func TestKyber_Zeroize_PairedPublicKeyIntact(t *testing.T) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair() failed: %v", err)
	}

	pubBytesBefore, err := kp.Public.Bytes()
	if err != nil {
		t.Fatalf("Public.Bytes() before Zeroize failed: %v", err)
	}

	if err := kp.Private.Zeroize(); err != nil {
		t.Fatalf("Zeroize() failed: %v", err)
	}

	pubBytesAfter, err := kp.Public.Bytes()
	if err != nil {
		t.Fatalf("Public.Bytes() after Zeroize failed: %v (CRY-R3-01: paired pk corrupted)", err)
	}
	if !bytes.Equal(pubBytesBefore, pubBytesAfter) {
		t.Fatal("CRY-R3-01: paired PublicKey bytes changed after PrivateKey.Zeroize() — shared pk was zeroed")
	}

	// Encapsulate must still work on the intact paired public key.
	ct, ss, err := kyber768.Scheme().Encapsulate(kp.Public.key)
	if err != nil {
		t.Fatalf("Encapsulate() after Zeroize failed: %v (CRY-R3-01: paired pk corrupted)", err)
	}
	if len(ct) == 0 || len(ss) == 0 {
		t.Fatal("CRY-R3-01: Encapsulate() returned empty ct/ss after Zeroize — paired pk corrupted")
	}
}

func TestKyber_FromBytes_Nil(t *testing.T) {
	_, err := KyberPrivateKeyFromBytes(nil)
	if err == nil {
		t.Fatal("KyberPrivateKeyFromBytes(nil) should error")
	}
	_, err = KyberPublicKeyFromBytes(nil)
	if err == nil {
		t.Fatal("KyberPublicKeyFromBytes(nil) should error")
	}
}

func TestKyber_FromBytes_CorrectLengthMalformed(t *testing.T) {
	kp, _ := GenerateKyberKeyPair()
	validBytes, _ := kp.Private.Bytes()

	// Flip bits in valid bytes to create malformed data
	malformed := make([]byte, KyberPrivateKeySize)
	copy(malformed, validBytes)
	malformed[0] ^= 0xFF
	malformed[len(malformed)-1] ^= 0xFF
	_, err := KyberPrivateKeyFromBytes(malformed)
	// With enough corruption, should fail
	if err == nil {
		t.Log("malformed Kyber-768 key bytes still parsed (statistically possible)")
	}

	malformedPub := make([]byte, KyberPublicKeySize)
	for i := range malformedPub {
		malformedPub[i] = 0xFF
	}
	_, err = KyberPublicKeyFromBytes(malformedPub)
	if err == nil {
		t.Log("all-FF kyber public key parsed successfully")
	}
}

func TestKyber_Exchange_NilSelf(t *testing.T) {
	var nilPriv *KyberPrivateKey
	_, _, err := nilPriv.Exchange(&KyberPublicKey{})
	if err == nil {
		t.Fatal("Exchange on nil private key should error")
	}
}

func TestKyber_Decapsulate_NilSelf(t *testing.T) {
	var nilPriv *KyberPrivateKey
	_, err := nilPriv.Decapsulate(make([]byte, KyberCiphertextSize))
	if err == nil {
		t.Fatal("Decapsulate on nil private key should error")
	}
}

func TestKyber_Equal_Destroyed(t *testing.T) {
	kp1, _ := GenerateKyberKeyPair()
	kp2, _ := GenerateKyberKeyPair()
	_ = kp1.Private.Destroy()
	// Destroy sets k.key=nil, so k.key==nil && other.key!=nil → false
	if kp1.Private.Equal(kp2.Private) {
		t.Error("destroyed key should not equal non-destroyed")
	}
	// Compare destroyed to destroyed
	_ = kp2.Private.Destroy()
	// Both have key==nil, must also be non-nil pointers
	if kp1.Private.Equal(kp2.Private) {
		t.Log("two destroyed keys are equal (both key fields are nil)")
	}
}

func TestKyber_Bytes_Destroyed(t *testing.T) {
	kp, _ := GenerateKyberKeyPair()
	_ = kp.Private.Zeroize()
	_, err := kp.Private.Bytes()
	if err == nil {
		t.Fatal("Bytes() should error after Zeroize")
	}
}

func TestKyber_PublicKey_Destroyed(t *testing.T) {
	kp, _ := GenerateKyberKeyPair()
	_ = kp.Private.Destroy()
	_, err := kp.Private.PublicKey()
	if err == nil {
		t.Fatal("PublicKey() should error after Destroy")
	}
}

func TestKyber_Exchange_Destroyed(t *testing.T) {
	kp, _ := GenerateKyberKeyPair()
	kp2, _ := GenerateKyberKeyPair()
	_ = kp.Private.Destroy()
	_, _, err := kp.Private.Exchange(kp2.Public)
	if err == nil {
		t.Fatal("Exchange() should error after Destroy")
	}
}

func TestKyber_Decapsulate_Destroyed(t *testing.T) {
	kp, _ := GenerateKyberKeyPair()
	ct := make([]byte, KyberCiphertextSize)
	_ = kp.Private.Destroy()
	_, err := kp.Private.Decapsulate(ct)
	if err == nil {
		t.Fatal("Decapsulate() should error after Destroy")
	}
}

func TestPrivateKey_PublicKeyBytes(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pubKeyBytes := kp.Private.PublicKeyBytes()
	if pubKeyBytes == nil {
		t.Fatal("PublicKeyBytes returned nil")
	}
	if len(pubKeyBytes) != Dilithium3PublicKeySize {
		t.Errorf("expected %d bytes, got %d", Dilithium3PublicKeySize, len(pubKeyBytes))
	}

	pubFromPriv := kp.Private.PublicKey()
	pubBytes := pubFromPriv.Bytes()
	if !bytes.Equal(pubKeyBytes, pubBytes) {
		t.Error("PublicKeyBytes should match PublicKey().Bytes()")
	}
}

// TestKyber_GetKyberScheme tests the GetKyberScheme function
func TestKyber_GetKyberScheme(t *testing.T) {
	t.Parallel()

	t.Run("GetKyberScheme returns non-nil scheme", func(t *testing.T) {
		scheme := GetKyberScheme()
		if scheme == nil {
			t.Fatal("GetKyberScheme() returned nil")
		}
	})

	t.Run("GetKyberScheme returns consistent scheme", func(t *testing.T) {
		scheme1 := GetKyberScheme()
		scheme2 := GetKyberScheme()
		if scheme1 != scheme2 {
			t.Fatal("GetKyberScheme() returned different schemes")
		}
	})
}
