// Quantaureum Node source, version 1.0.0.
package visor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func TestVerifyBinary_ValidSignature(t *testing.T) {
	// Generate a test key pair
	pubKey, privKey, err := mode3.GenerateKey(nil)
	if err != nil {
		t.Skipf("Dilithium3 key generation failed: %v", err)
	}

	// Create a test binary
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "qaud")
	binaryData := []byte("fake qaud binary content for testing")
	if err := os.WriteFile(binaryPath, binaryData, 0755); err != nil {
		t.Fatal(err)
	}

	// Sign the binary
	hash := sha256.Sum256(binaryData)
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privKey, hash[:], sig)
	sigPath := binaryPath + ".sig"
	if err := os.WriteFile(sigPath, sig, 0644); err != nil {
		t.Fatal(err)
	}

	// Verify
	pubKeyBytes := make([]byte, mode3.PublicKeySize)
	pubKey.Pack((*[mode3.PublicKeySize]byte)(pubKeyBytes))
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	if err := VerifyBinary(binaryPath, sigPath, pubKeyHex); err != nil {
		t.Errorf("VerifyBinary() failed with valid signature: %v", err)
	}
}

func TestVerifyBinary_TamperedBinary(t *testing.T) {
	// Generate a test key pair
	pubKey, privKey, err := mode3.GenerateKey(nil)
	if err != nil {
		t.Skipf("Dilithium3 key generation failed: %v", err)
	}

	// Create and sign a binary
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "qaud")
	binaryData := []byte("original binary content")
	if err := os.WriteFile(binaryPath, binaryData, 0755); err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256(binaryData)
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privKey, hash[:], sig)
	sigPath := binaryPath + ".sig"
	if err := os.WriteFile(sigPath, sig, 0644); err != nil {
		t.Fatal(err)
	}

	// Tamper with the binary
	if err := os.WriteFile(binaryPath, []byte("TAMPERED binary content"), 0755); err != nil {
		t.Fatal(err)
	}

	// Verify should fail
	pubKeyBytes := make([]byte, mode3.PublicKeySize)
	pubKey.Pack((*[mode3.PublicKeySize]byte)(pubKeyBytes))
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	if err := VerifyBinary(binaryPath, sigPath, pubKeyHex); err == nil {
		t.Error("VerifyBinary() should fail for tampered binary")
	}
}

func TestVerifyBinary_WrongPublicKey(t *testing.T) {
	// Generate two key pairs
	_, privKey, err := mode3.GenerateKey(nil)
	if err != nil {
		t.Skipf("Dilithium3 key generation failed: %v", err)
	}
	wrongPubKey, _, err := mode3.GenerateKey(nil)
	if err != nil {
		t.Skipf("Dilithium3 key generation failed: %v", err)
	}

	// Create and sign with the first key
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "qaud")
	binaryData := []byte("binary content")
	if err := os.WriteFile(binaryPath, binaryData, 0755); err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256(binaryData)
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privKey, hash[:], sig)
	sigPath := binaryPath + ".sig"
	if err := os.WriteFile(sigPath, sig, 0644); err != nil {
		t.Fatal(err)
	}

	// Verify with wrong public key should fail
	wrongPubKeyBytes := make([]byte, mode3.PublicKeySize)
	wrongPubKey.Pack((*[mode3.PublicKeySize]byte)(wrongPubKeyBytes))
	wrongPubKeyHex := hex.EncodeToString(wrongPubKeyBytes)

	if err := VerifyBinary(binaryPath, sigPath, wrongPubKeyHex); err == nil {
		t.Error("VerifyBinary() should fail with wrong public key")
	}
}

func TestVerifyBinary_MissingSignature(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "qaud")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := VerifyBinary(binaryPath, "/nonexistent.sig", "00"); err == nil {
		t.Error("VerifyBinary() should fail with missing signature file")
	}
}

func TestComputeBinaryHash(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "qaud")
	binaryData := []byte("test binary content")
	if err := os.WriteFile(binaryPath, binaryData, 0755); err != nil {
		t.Fatal(err)
	}

	hash, err := ComputeBinaryHash(binaryPath)
	if err != nil {
		t.Fatalf("ComputeBinaryHash() failed: %v", err)
	}

	// Verify hash is correct
	expected := sha256.Sum256(binaryData)
	expectedHex := hex.EncodeToString(expected[:])
	if hash != expectedHex {
		t.Errorf("hash = %q, want %q", hash, expectedHex)
	}
}

func TestSignBinary(t *testing.T) {
	// Generate a test key pair
	pubKey, privKey, err := mode3.GenerateKey(nil)
	if err != nil {
		t.Skipf("Dilithium3 key generation failed: %v", err)
	}

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "qaud")
	sigPath := filepath.Join(tmpDir, "qaud.sig")
	binaryData := []byte("test binary for signing")
	if err := os.WriteFile(binaryPath, binaryData, 0755); err != nil {
		t.Fatal(err)
	}

	privKeyBytes := make([]byte, mode3.PrivateKeySize)
	privKey.Pack((*[mode3.PrivateKeySize]byte)(privKeyBytes))
	privKeyHex := hex.EncodeToString(privKeyBytes)

	if err := SignBinary(binaryPath, sigPath, privKeyHex); err != nil {
		t.Fatalf("SignBinary() failed: %v", err)
	}

	// Verify the signature
	pubKeyBytes := make([]byte, mode3.PublicKeySize)
	pubKey.Pack((*[mode3.PublicKeySize]byte)(pubKeyBytes))
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	if err := VerifyBinary(binaryPath, sigPath, pubKeyHex); err != nil {
		t.Errorf("VerifyBinary() failed after SignBinary(): %v", err)
	}
}
