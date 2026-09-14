// Quantaureum Node source, version 1.0.0.
// Package crypto provides cryptographic primitives for the Quantaureum blockchain.
// This file contains unit tests for the Dilithium3 post-quantum signature implementation.
package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestDilithium_GenerateKeyPair tests the GenerateKeyPair function
func TestDilithium_GenerateKeyPair(t *testing.T) {
	t.Parallel()

	t.Run("Happy path key generation", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}
		if kp == nil {
			t.Fatal("GenerateKeyPair() returned nil KeyPair")
		}
		if kp.Private == nil {
			t.Fatal("GenerateKeyPair() returned nil Private key")
		}
		if kp.Public == nil {
			t.Fatal("GenerateKeyPair() returned nil Public key")
		}
		// Verify the private key can derive its public key
		derivedPub := kp.Private.PublicKey()
		if derivedPub == nil {
			t.Fatal("PrivateKey.PublicKey() returned nil")
		}
		// Verify the derived public key matches the original
		if !kp.Public.Equal(derivedPub) {
			t.Fatal("Derived public key does not match original public key")
		}
	})

	t.Run("Multiple key generations produce different keys", func(t *testing.T) {
		kp1, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}
		kp2, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
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

// TestDilithium_Sign tests the Sign function
func TestDilithium_Sign(t *testing.T) {
	t.Parallel()

	t.Run("Sign message and verify signature", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		message := []byte("test message for signing")
		sig, err := Sign(kp.Private, message)
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		if sig == nil {
			t.Fatal("Sign() returned nil signature")
		}
		if len(sig) != Dilithium3SignatureSize {
			t.Fatalf("Sign() returned signature of wrong size: got %d, want %d", len(sig), Dilithium3SignatureSize)
		}

		// Verify the signature
		valid := Verify(kp.Public, message, sig)
		if !valid {
			t.Fatal("Verify() returned false for valid signature")
		}
	})

	t.Run("Sign with nil private key", func(t *testing.T) {
		message := []byte("test message")
		_, err := Sign(nil, message)
		if err == nil {
			t.Fatal("Sign(nil) did not return error")
		}
	})

	t.Run("Empty message signing", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		emptyMessage := []byte{}
		sig, err := Sign(kp.Private, emptyMessage)
		if err != nil {
			t.Fatalf("Sign() failed for empty message: %v", err)
		}
		if sig == nil {
			t.Fatal("Sign() returned nil signature for empty message")
		}

		// Verify empty message signature
		valid := Verify(kp.Public, emptyMessage, sig)
		if !valid {
			t.Fatal("Verify() returned false for valid empty message signature")
		}
	})

	t.Run("Large message signing", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		// Create a large message (1MB)
		largeMessage := make([]byte, 1024*1024)
		if _, err := rand.Read(largeMessage); err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}

		sig, err := Sign(kp.Private, largeMessage)
		if err != nil {
			t.Fatalf("Sign() failed for large message: %v", err)
		}

		valid := Verify(kp.Public, largeMessage, sig)
		if !valid {
			t.Fatal("Verify() returned false for valid large message signature")
		}
	})
}

// TestDilithium_Verify tests the Verify function
func TestDilithium_Verify(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	message := []byte("test message for verification")
	sig, err := Sign(kp.Private, message)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	t.Run("Verify valid signature", func(t *testing.T) {
		valid := Verify(kp.Public, message, sig)
		if !valid {
			t.Fatal("Verify() returned false for valid signature")
		}
	})

	t.Run("Verify with nil public key returns false", func(t *testing.T) {
		valid := Verify(nil, message, sig)
		if valid {
			t.Fatal("Verify(nil) returned true, expected false")
		}
	})

	t.Run("Verify with tampered message returns false", func(t *testing.T) {
		tamperedMessage := []byte("tampered message")
		valid := Verify(kp.Public, tamperedMessage, sig)
		if valid {
			t.Fatal("Verify() returned true for tampered message")
		}
	})

	t.Run("Verify with wrong public key returns false", func(t *testing.T) {
		kp2, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}
		valid := Verify(kp2.Public, message, sig)
		if valid {
			t.Fatal("Verify() returned true for signature with wrong public key")
		}
	})

	t.Run("Verify with malformed signature returns false", func(t *testing.T) {
		malformedSig := make([]byte, Dilithium3SignatureSize)
		if _, err := rand.Read(malformedSig); err != nil {
			t.Fatalf("Failed to generate malformed signature: %v", err)
		}
		valid := Verify(kp.Public, message, malformedSig)
		if valid {
			t.Fatal("Verify() returned true for malformed signature")
		}
	})

	t.Run("Verify with wrong length signature returns false", func(t *testing.T) {
		wrongLenSig := make([]byte, Dilithium3SignatureSize-1)
		if _, err := rand.Read(wrongLenSig); err != nil {
			t.Fatalf("Failed to generate wrong-length signature: %v", err)
		}
		valid := Verify(kp.Public, message, wrongLenSig)
		if valid {
			t.Fatal("Verify() returned true for wrong-length signature")
		}
	})

	t.Run("Verify with empty signature returns false", func(t *testing.T) {
		valid := Verify(kp.Public, message, []byte{})
		if valid {
			t.Fatal("Verify() returned true for empty signature")
		}
	})

	t.Run("Verify with nil signature returns false", func(t *testing.T) {
		valid := Verify(kp.Public, message, nil)
		if valid {
			t.Fatal("Verify() returned true for nil signature")
		}
	})
}

// TestDilithium_KeySerialization tests key serialization and deserialization
func TestDilithium_KeySerialization(t *testing.T) {
	t.Parallel()

	t.Run("PrivateKey Bytes and PrivateKeyFromBytes roundtrip", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		// Get bytes
		privBytes := kp.Private.Bytes()
		if privBytes == nil {
			t.Fatal("PrivateKey.Bytes() returned nil")
		}
		if len(privBytes) != Dilithium3PrivateKeySize {
			t.Fatalf("PrivateKey.Bytes() returned wrong size: got %d, want %d", len(privBytes), Dilithium3PrivateKeySize)
		}

		// Reconstruct from bytes
		priv2, err := PrivateKeyFromBytes(privBytes)
		if err != nil {
			t.Fatalf("PrivateKeyFromBytes() failed: %v", err)
		}
		if priv2 == nil {
			t.Fatal("PrivateKeyFromBytes() returned nil")
		}

		// Verify they are equal
		if !kp.Private.Equal(priv2) {
			t.Fatal("Reconstructed private key does not match original")
		}

		// Verify they produce the same signatures
		message := []byte("test message")
		sig1, _ := Sign(kp.Private, message)
		sig2, _ := Sign(priv2, message)
		if !bytes.Equal(sig1, sig2) {
			t.Fatal("Reconstructed key produces different signatures")
		}
	})

	t.Run("PublicKey Bytes and PublicKeyFromBytes roundtrip", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		// Get bytes
		pubBytes := kp.Public.Bytes()
		if pubBytes == nil {
			t.Fatal("PublicKey.Bytes() returned nil")
		}
		if len(pubBytes) != Dilithium3PublicKeySize {
			t.Fatalf("PublicKey.Bytes() returned wrong size: got %d, want %d", len(pubBytes), Dilithium3PublicKeySize)
		}

		// Reconstruct from bytes
		pub2, err := PublicKeyFromBytes(pubBytes)
		if err != nil {
			t.Fatalf("PublicKeyFromBytes() failed: %v", err)
		}
		if pub2 == nil {
			t.Fatal("PublicKeyFromBytes() returned nil")
		}

		// Verify they are equal
		if !kp.Public.Equal(pub2) {
			t.Fatal("Reconstructed public key does not match original")
		}

		// Verify signature verification works with reconstructed key
		message := []byte("test message")
		sig, _ := Sign(kp.Private, message)
		if !Verify(pub2, message, sig) {
			t.Fatal("Reconstructed key failed to verify signature")
		}
	})

	t.Run("Invalid length bytes for PrivateKeyFromBytes", func(t *testing.T) {
		invalidBytes := make([]byte, Dilithium3PrivateKeySize-1)
		if _, err := rand.Read(invalidBytes); err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}
		_, err := PrivateKeyFromBytes(invalidBytes)
		if err == nil {
			t.Fatalf("PrivateKeyFromBytes() did not return error for length %d", len(invalidBytes))
		}
	})

	t.Run("Invalid length bytes for PublicKeyFromBytes", func(t *testing.T) {
		invalidBytes := make([]byte, Dilithium3PublicKeySize-1)
		if _, err := rand.Read(invalidBytes); err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}
		_, err := PublicKeyFromBytes(invalidBytes)
		if err == nil {
			t.Fatalf("PublicKeyFromBytes() did not return error for length %d", len(invalidBytes))
		}
	})
}

// TestDilithium_Equal tests the Equal method for public and private keys
func TestDilithium_Equal(t *testing.T) {
	t.Parallel()

	t.Run("Two identical keys are equal", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
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
		kp1, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}
		kp2, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
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

	t.Run("Nil comparison handled correctly", func(t *testing.T) {
		var nilPriv *PrivateKey
		var nilPub *PublicKey

		// Nil private key compared to nil
		if !nilPriv.Equal(nil) {
			t.Fatal("Nil PrivateKey.Equal(nil) returned false")
		}

		// Nil public key compared to nil
		if !nilPub.Equal(nil) {
			t.Fatal("Nil PublicKey.Equal(nil) returned false")
		}

		// Real key compared to nil
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}
		if kp.Private.Equal(nil) {
			t.Fatal("Real PrivateKey.Equal(nil) returned true")
		}
		if kp.Public.Equal(nil) {
			t.Fatal("Real PublicKey.Equal(nil) returned true")
		}
	})
}

// TestDilithium_ExportImport tests the ExportKeyPair and ImportKeyPair functions
func TestDilithium_ExportImport(t *testing.T) {
	t.Parallel()

	t.Run("ExportKeyPair and ImportKeyPair roundtrip", func(t *testing.T) {
		kp1, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		// Export
		privBytes, pubBytes, err := ExportKeyPair(kp1)
		if err != nil {
			t.Fatalf("ExportKeyPair() failed: %v", err)
		}
		if privBytes == nil || pubBytes == nil {
			t.Fatal("ExportKeyPair() returned nil bytes")
		}

		// Import
		kp2, err := ImportKeyPair(privBytes, pubBytes)
		if err != nil {
			t.Fatalf("ImportKeyPair() failed: %v", err)
		}
		if kp2 == nil {
			t.Fatal("ImportKeyPair() returned nil KeyPair")
		}

		// Verify the imported keys match
		if !kp1.Private.Equal(kp2.Private) {
			t.Fatal("Imported private key does not match original")
		}
		if !kp1.Public.Equal(kp2.Public) {
			t.Fatal("Imported public key does not match original")
		}

		// Verify signing and verification works
		message := []byte("test message for export/import")
		sig1, _ := Sign(kp1.Private, message)
		sig2, _ := Sign(kp2.Private, message)
		if !bytes.Equal(sig1, sig2) {
			t.Fatal("Imported key produces different signatures")
		}
	})

	t.Run("Import with corrupted private key data - import succeeds but key is invalid", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		privBytes, pubBytes, err := ExportKeyPair(kp)
		if err != nil {
			t.Fatalf("ExportKeyPair() failed: %v", err)
		}

		// Corrupt the private key bytes
		corruptedPriv := make([]byte, len(privBytes))
		copy(corruptedPriv, privBytes)
		corruptedPriv[0] ^= 0xFF

		// R26-Crypto-C2 FIX: Import now validates cryptographic key material,
		// so corrupted keys are correctly rejected
		kp2, err := ImportKeyPair(corruptedPriv, pubBytes)
		if err == nil {
			t.Fatal("ImportKeyPair() should reject corrupted private key")
		}
		// Verify it's the expected error
		if kp2 != nil {
			t.Fatal("ImportKeyPair() should return nil keypair on error")
		}
	})

	t.Run("Import with corrupted public key data - import succeeds but key is invalid", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		privBytes, pubBytes, err := ExportKeyPair(kp)
		if err != nil {
			t.Fatalf("ExportKeyPair() failed: %v", err)
		}

		// Corrupt the public key bytes
		corruptedPub := make([]byte, len(pubBytes))
		copy(corruptedPub, pubBytes)
		corruptedPub[0] ^= 0xFF

		// R26-Crypto-C2 FIX: Import now validates that derived public key matches,
		// so corrupted public keys are correctly rejected
		kp2, err := ImportKeyPair(privBytes, corruptedPub)
		if err == nil {
			t.Fatal("ImportKeyPair() should reject when public key doesn't match private key")
		}
		// Verify it's the expected error
		if kp2 != nil {
			t.Fatal("ImportKeyPair() should return nil keypair on error")
		}
	})
}

// TestDilithium_Address tests the Address derivation from public keys
func TestDilithium_Address(t *testing.T) {
	t.Parallel()

	t.Run("PrivateKey.PublicKey returns correct type", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		pub := kp.Private.PublicKey()
		if pub == nil {
			t.Fatal("PublicKey() returned nil")
		}

		// Verify it returns the same public key as the key pair
		if !kp.Public.Equal(pub) {
			t.Fatal("PrivateKey.PublicKey() does not match KeyPair.Public")
		}
	})

	t.Run("PublicKey.Address derivation is consistent", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}

		addr1 := kp.Public.Address()
		addr2 := kp.Public.Address()

		// Same public key should produce same address
		if addr1 != addr2 {
			t.Fatal("Same public key produced different addresses")
		}

		// Different key pairs should produce different addresses
		kp2, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() failed: %v", err)
		}
		addr3 := kp2.Public.Address()
		if addr1 == addr3 {
			t.Fatal("Different public keys produced same address")
		}
	})

	t.Run("Nil PrivateKey.PublicKey returns nil", func(t *testing.T) {
		var nilPriv *PrivateKey
		pub := nilPriv.PublicKey()
		if pub != nil {
			t.Fatal("Nil PrivateKey.PublicKey() should return nil")
		}
	})

	t.Run("Nil PublicKey.Address returns empty address", func(t *testing.T) {
		var nilPub *PublicKey
		addr := nilPub.Address()
		if !addr.IsEmpty() {
			t.Fatal("Nil PublicKey.Address() should return empty address")
		}
	})
}

// TestDilithium_Bytes_NilKey tests Bytes method with nil keys
func TestDilithium_Bytes_NilKey(t *testing.T) {
	t.Parallel()

	t.Run("Nil PrivateKey.Bytes returns nil", func(t *testing.T) {
		var nilPriv *PrivateKey
		bytes := nilPriv.Bytes()
		if bytes != nil {
			t.Fatalf("Expected nil, got %v", bytes)
		}
	})

	t.Run("Nil PublicKey.Bytes returns nil", func(t *testing.T) {
		var nilPub *PublicKey
		bytes := nilPub.Bytes()
		if bytes != nil {
			t.Fatalf("Expected nil, got %v", bytes)
		}
	})
}
