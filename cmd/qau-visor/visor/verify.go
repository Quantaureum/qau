// Quantaureum Node source, version 1.0.0.
// Package visor provides Dilithium3 binary signature verification for qau-visor.
//
// Unlike Hyperliquid's Visor which uses GPG signatures, qau-visor uses
// Dilithium3 signatures to stay consistent with Quantaureum's post-quantum
// cryptography. This ensures that only officially signed qaud binaries
// can be installed and upgraded.
package visor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
)

// VerifyBinary verifies a qaud binary's Dilithium3 signature.
//
// The verification process:
//  1. Read the binary file
//  2. Compute SHA-256 hash of the binary
//  3. Verify the Dilithium3 signature against the hash using the public key
//
// Returns nil if verification succeeds, or an error describing why it failed.
func VerifyBinary(binaryPath string, signaturePath string, publicKeyHex string) error {
	// Read binary
	binaryData, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to read binary: %w", err)
	}

	// Read signature
	sigData, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	if len(sigData) != mode3.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, expected %d",
			len(sigData), mode3.SignatureSize)
	}

	// Decode public key
	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(pubKeyBytes) != mode3.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, expected %d",
			len(pubKeyBytes), mode3.PublicKeySize)
	}

	// R38-P1-01 FIX (2026-08-01): Defense-in-depth — reject all-zero
	// public keys before Unpack + mode3.Verify, mirroring the canonical
	// hardening at crypto/verify.go:73 + crypto/generate.go:773.
	// Binaries are always signed by a real Dilithium3 key, so this gate
	// never fires in production. But if a configuration mistake / disk
	// corruption produced an all-zero pubkey hex, mode3.Verify might
	// accept a forged zero signature — fail-closed here eliminates that.
	if crypto.IsZeroPublicKeyBytes(pubKeyBytes) {
		return fmt.Errorf("invalid public key: all zeros (unconfigured or tampered)")
	}

	// Compute SHA-256 hash of the binary (message to verify)
	hash := sha256.Sum256(binaryData)

	// Unpack public key
	var pubKey mode3.PublicKey
	pubKey.Unpack((*[mode3.PublicKeySize]byte)(pubKeyBytes))

	// Verify Dilithium3 signature
	if !mode3.Verify(&pubKey, hash[:], sigData) {
		return fmt.Errorf("Dilithium3 signature verification FAILED - binary may be tampered")
	}

	return nil
}

// SignBinary creates a Dilithium3 signature for a qaud binary.
// This is used by the release process, not by visor itself.
//
// The signing process:
//  1. Read the binary file
//  2. Compute SHA-256 hash of the binary
//  3. Sign the hash with the Dilithium3 private key
//  4. Write the signature to the output path
func SignBinary(binaryPath string, signaturePath string, privateKeyHex string) error {
	// Read binary
	binaryData, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to read binary: %w", err)
	}

	// Decode private key
	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privKeyBytes) != mode3.PrivateKeySize {
		return fmt.Errorf("invalid private key size: got %d, expected %d",
			len(privKeyBytes), mode3.PrivateKeySize)
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(binaryData)

	// Unpack private key and sign
	var privKey mode3.PrivateKey
	privKey.Unpack((*[mode3.PrivateKeySize]byte)(privKeyBytes))

	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&privKey, hash[:], sig)

	// Write signature
	if err := os.WriteFile(signaturePath, sig, 0600); err != nil { // G306: signature, owner-only
		return fmt.Errorf("failed to write signature: %w", err)
	}

	return nil
}

// ComputeBinaryHash computes the SHA-256 hash of a binary file.
// Useful for verifying file integrity independently of signatures.
func ComputeBinaryHash(binaryPath string) (string, error) {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to read binary: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
