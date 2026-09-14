// Quantaureum Go SDK source, version 1.0.0.
// Package accounts provides Dilithium3 quantum-resistant signing functionality.
package accounts

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
)

// SignMessage signs a message using the account's Dilithium3 private key.
// Returns a 3293-byte Dilithium3 signature.
func (a *Account) SignMessage(message []byte) ([]byte, error) {
	if a == nil || a.privateKey == nil {
		return nil, errors.ErrInvalidPrivateKey
	}

	hash := hashMessage(message)
	return signHash(a.privateKey, hash)
}

// SignMessageHash signs a pre-hashed message (32 bytes) without adding any prefix.
// Returns a 3293-byte Dilithium3 signature.
func (a *Account) SignMessageHash(hash []byte) ([]byte, error) {
	if a == nil || a.privateKey == nil {
		return nil, errors.ErrInvalidPrivateKey
	}

	if len(hash) != 32 {
		return nil, fmt.Errorf("%w: hash must be 32 bytes", errors.ErrInvalidSignature)
	}

	return signHash(a.privateKey, hash)
}

// hashMessage creates the signed message hash.
// The message is prefixed with "\x19Quantaureum Signed Message:\n" + len(message).
func hashMessage(message []byte) []byte {
	prefix := fmt.Sprintf("\x19Quantaureum Signed Message:\n%d", len(message))
	return keccak256(append([]byte(prefix), message...))
}

// signHash signs a 32-byte hash with the Dilithium3 private key.
func signHash(privateKey *mode3.PrivateKey, hash []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.ErrInvalidPrivateKey
	}

	signature := make([]byte, SignatureSize)
	mode3.SignTo(privateKey, hash, signature)
	return signature, nil
}

// VerifySignature verifies that a Dilithium3 signature was created by the given address.
//
// IMPORTANT: Dilithium3 does not support public key recovery from signatures.
// Address-only verification requires the full public key. Use
// VerifySignatureWithPublicKey instead for actual cryptographic verification.
//
// Deprecated: This function cannot perform real verification with only an address.
// Always use VerifySignatureWithPublicKey for security-critical signature checks.
func VerifySignature(address common.Address, message []byte, signature []byte) bool {
	// Dilithium3 (post-quantum) does not support public key recovery from
	// signatures or addresses. Without the full 1952-byte public key,
	// cryptographic verification is impossible. Return false to prevent
	// callers from falsely assuming a signature is valid.
	_ = address
	_ = message
	_ = signature
	return false
}

// VerifySignatureWithPublicKey verifies a Dilithium3 signature using a public key.
func VerifySignatureWithPublicKey(publicKey []byte, message []byte, signature []byte) bool {
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize {
		return false
	}

	var pubKey mode3.PublicKey
	pubKey.Unpack((*[PublicKeySize]byte)(publicKey))

	hash := hashMessage(message)
	return mode3.Verify(&pubKey, hash, signature)
}

// VerifySignatureHashWithPublicKey verifies a Dilithium3 signature against a pre-hashed message.
func VerifySignatureHashWithPublicKey(publicKey []byte, hash []byte, signature []byte) bool {
	if len(publicKey) != PublicKeySize || len(signature) != SignatureSize || len(hash) != 32 {
		return false
	}

	var pubKey mode3.PublicKey
	pubKey.Unpack((*[PublicKeySize]byte)(publicKey))

	return mode3.Verify(&pubKey, hash, signature)
}
