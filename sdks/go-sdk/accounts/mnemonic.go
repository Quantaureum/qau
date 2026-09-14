// Quantaureum Go SDK source, version 1.0.0.
// Package accounts provides mnemonic-based account generation for Quantaureum.
// Uses Dilithium3 post-quantum cryptographic keys.
package accounts

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"
)

const (
	// DefaultDerivationPath is the standard BIP-44 derivation path for Quantaureum
	// m/44'/1668'/0'/0/0 - coin type 1668 is registered for Quantaureum (SLIP-44)
	DefaultDerivationPath = "m/44'/1668'/0'/0/0"

	// QuantaureumCoinType is the SLIP-44 registered coin type for Quantaureum
	// This MUST match the Wallet implementation (quantum-hd-keyring.ts)
	// Version: v1.1 - Synchronized with Wallet
	QuantaureumCoinType = 1668
)

// validateDerivationPath validates the BIP-44 derivation path
// Ensures coin type is 1668 for Quantaureum to prevent cross-chain key leakage
func validateDerivationPath(path string) error {
	// Basic format validation (m/purpose'/coin'/account'/change/index)
	if !strings.HasPrefix(path, "m/44'/") {
		return fmt.Errorf("invalid derivation path: must start with m/44' for BIP-44, got: %s", path)
	}

	// Parse path components
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return fmt.Errorf("invalid derivation path: must have at least m/purpose'/coin'/account', got: %s", path)
	}

	// Validate coin type (parts[2] should be "1668'")
	coinTypeStr := strings.TrimSuffix(parts[2], "'")
	coinType, err := parseUint32(coinTypeStr)
	if err != nil {
		return fmt.Errorf("invalid coin type in derivation path: %s", parts[2])
	}

	// audit-fix L6-013: Range validation for SLIP-44 coin type.
	// Valid coin types are in [1, 0x7FFFFFFF] (hardened range). This catches
	// malformed paths or overflowed parseUint32 results before the exact-match
	// check below. Note: the crypto/ package itself contains no HD derivation
	// code; this validation lives in the SDK accounts package.
	if coinType == 0 || coinType > 0x7FFFFFFF {
		return fmt.Errorf("invalid coin type %d: must be in [1, %d]", coinType, 0x7FFFFFFF)
	}

	// CRITICAL FIX: Validate coin type matches Quantaureum (1668)
	// Prevents derivation of keys for other chains which could leak private key material
	if coinType != QuantaureumCoinType {
		return fmt.Errorf(
			"invalid coin type: expected %d (Quantaureum), got %d. "+
				"Using wrong coin type may compromise security by deriving keys for unintended chains",
			QuantaureumCoinType, coinType,
		)
	}

	return nil
}

// parseUint32 parses a string to uint32
func parseUint32(s string) (uint32, error) {
	var result uint32
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

// GenerateMnemonic generates a new random mnemonic phrase.
// The bitSize should be 128 (12 words), 160 (15 words), 192 (18 words),
// 224 (21 words), or 256 (24 words).
func GenerateMnemonic(bitSize int) (string, error) {
	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	return mnemonic, nil
}

// GenerateMnemonic12 generates a new 12-word mnemonic phrase.
func GenerateMnemonic12() (string, error) {
	return GenerateMnemonic(128)
}

// GenerateMnemonic24 generates a new 24-word mnemonic phrase.
func GenerateMnemonic24() (string, error) {
	return GenerateMnemonic(256)
}

// ValidateMnemonic checks if a mnemonic phrase is valid.
func ValidateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

// NewAccountFromMnemonic creates a Dilithium3 account from a mnemonic phrase.
func NewAccountFromMnemonic(mnemonic string) (*Account, error) {
	return NewAccountFromMnemonicWithPath(mnemonic, DefaultDerivationPath)
}

// NewAccountFromMnemonicWithPath creates a Dilithium3 account from a mnemonic phrase
// using a custom derivation path.
func NewAccountFromMnemonicWithPath(mnemonic string, path string) (*Account, error) {
	mnemonic = strings.TrimSpace(mnemonic)
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.ErrInvalidMnemonic
	}

	// CRITICAL FIX: Validate derivation path before using it
	// Ensures coin type is 1668 for Quantaureum, preventing cross-chain key leakage
	if err := validateDerivationPath(path); err != nil {
		return nil, err
	}

	// COMPATIBILITY FIX: Pass raw mnemonic bytes (not BIP39 seed) to HKDF
	// to match the TypeScript wallet implementation
	privateKey, err := deriveDilithiumKeyFromMnemonic([]byte(mnemonic), path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %w", err)
	}

	account := NewAccountFromPrivateKey(privateKey)
	account.mnemonic = []byte(mnemonic)
	account.ZeroizeMnemonic() // Zero immediately after key derivation

	return account, nil
}

// NewAccountFromMnemonicWithPassword creates a Dilithium3 account with a password.
func NewAccountFromMnemonicWithPassword(mnemonic string, password string) (*Account, error) {
	return NewAccountFromMnemonicWithPathAndPassword(mnemonic, DefaultDerivationPath, password)
}

// NewAccountFromMnemonicWithPathAndPassword creates a Dilithium3 account with path and password.
// AUDIT 2026-07-12 KEYS-04: Previously this function used bip39.NewSeed (PBKDF2)
// while NewAccountFromMnemonicWithPath used raw mnemonic bytes. Even with an
// empty password, the two constructors derived DIFFERENT keys from the same
// mnemonic, causing users to "recover" to different addresses and lose access
// to funds. Fix: both constructors now use the same raw-mnemonic-bytes HKDF
// derivation. When password is non-empty, it is mixed into the HKDF salt,
// so the derivation is distinct from the no-password path but still
// consistent across calls. When password is empty, the derivation is
// IDENTICAL to NewAccountFromMnemonicWithPath, preventing cross-constructor
// address divergence.
func NewAccountFromMnemonicWithPathAndPassword(mnemonic string, path string, password string) (*Account, error) {
	mnemonic = strings.TrimSpace(mnemonic)
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.ErrInvalidMnemonic
	}

	// CRITICAL FIX: Validate derivation path before using it
	// Ensures coin type is 1668 for Quantaureum, preventing cross-chain key leakage
	if err := validateDerivationPath(path); err != nil {
		return nil, err
	}

	// KEYS-04 FIX: Use raw mnemonic bytes with password mixed into HKDF salt.
	// When password is empty, this produces the same key as NewAccountFromMnemonicWithPath.
	privateKey, err := deriveDilithiumKeyFromMnemonicWithPassword([]byte(mnemonic), path, password)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %w", err)
	}

	account := NewAccountFromPrivateKey(privateKey)
	account.mnemonic = []byte(mnemonic)
	account.ZeroizeMnemonic() // Zero immediately after key derivation

	return account, nil
}

// deriveDilithiumKey derives a Dilithium3 key from a seed using HKDF-SHA256.
// COMPATIBILITY FIX: This now uses HKDF-SHA256 to match the TypeScript wallet implementation.
// Both implementations use: hkdf(sha256, mnemonic+path, salt='quantaureum-dilithium3', info='dilithium3-seed-v1')
// This ensures the same mnemonic produces the same address in both wallet and Go SDK.
func deriveDilithiumKey(seed []byte, path string) (*mode3.PrivateKey, error) {
	keyMaterial, err := deriveKeyMaterialHKDF(seed, path, "")
	if err != nil {
		return nil, fmt.Errorf("failed to derive key material: %w", err)
	}
	reader := &deterministicReader{data: keyMaterial, pos: 0}

	_, priv, err := mode3.GenerateKey(reader)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// deriveDilithiumKeyFromMnemonic derives a Dilithium3 key directly from mnemonic bytes.
// This matches the TypeScript wallet's generateKeyPairFromMnemonicBytes() implementation:
//
//	ikm = length-prefixed(mnemonic) + length-prefixed(path)
//	HKDF-SHA256(ikm, salt="quantaureum-dilithium3", info="dilithium3-seed-v1")
func deriveDilithiumKeyFromMnemonic(mnemonicBytes []byte, path string) (*mode3.PrivateKey, error) {
	keyMaterial, err := deriveKeyMaterialHKDF(mnemonicBytes, path, "")
	if err != nil {
		return nil, fmt.Errorf("failed to derive key material: %w", err)
	}
	reader := &deterministicReader{data: keyMaterial, pos: 0}

	_, priv, err := mode3.GenerateKey(reader)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// deriveDilithiumKeyFromMnemonicWithPassword derives a Dilithium3 key from
// mnemonic bytes with an optional password mixed into the HKDF salt.
// AUDIT 2026-07-12 KEYS-04: When password is empty, the salt is the same as
// deriveDilithiumKeyFromMnemonic, producing the IDENTICAL key. This ensures
// NewAccountFromMnemonic and NewAccountFromMnemonicWithPassword(mnemonic, "")
// derive the same address. When password is non-empty, it is appended to the
// salt, producing a distinct but deterministic key.
func deriveDilithiumKeyFromMnemonicWithPassword(mnemonicBytes []byte, path string, password string) (*mode3.PrivateKey, error) {
	keyMaterial, err := deriveKeyMaterialHKDF(mnemonicBytes, path, password)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key material: %w", err)
	}
	reader := &deterministicReader{data: keyMaterial, pos: 0}

	_, priv, err := mode3.GenerateKey(reader)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// deriveKeyMaterialHKDF creates deterministic key material using HKDF-SHA256.
// This matches the TypeScript wallet's mnemonicToSeedFromBytes() implementation:
//
//	ikm = length-prefixed(mnemonic) + length-prefixed(path)
//	salt = "quantaureum-dilithium3" [+ password if non-empty]  (KEYS-04)
//	info = "dilithium3-seed-v1"
//
// AUDIT 2026-07-12 KEYS-04: The password parameter is mixed into the HKDF
// salt. When empty, the salt is just "quantaureum-dilithium3", matching the
// no-password derivation exactly. When non-empty, the salt becomes
// "quantaureum-dilithium3" + password, producing a distinct key.
func deriveKeyMaterialHKDF(seed []byte, path string, password string) ([]byte, error) {
	// Build IKM: [4-byte seed length LE] || seed || [4-byte path length LE] || path
	// This matches the TypeScript length-prefixed domain separation
	seedLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(seedLen, uint32(len(seed)))
	pathBytes := []byte(path)
	pathLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(pathLen, uint32(len(pathBytes)))

	ikm := make([]byte, 0, len(seedLen)+len(seed)+len(pathLen)+len(pathBytes))
	ikm = append(ikm, seedLen...)
	ikm = append(ikm, seed...)
	ikm = append(ikm, pathLen...)
	ikm = append(ikm, pathBytes...)

	// KEYS-04: Mix password into salt. Empty password = same salt as no-password path.
	salt := []byte("quantaureum-dilithium3")
	if password != "" {
		salt = append(salt, []byte(password)...)
	}
	info := []byte("dilithium3-seed-v1")

	// Use HKDF-SHA256 extract-then-expand, matching the TypeScript implementation
	reader := hkdf.New(sha256.New, ikm, salt, info)

	// AUDIT 2026-07-12 KEYS-03: HKDF-SHA256 maximum output length is
	// 255 * HashLen = 255 * 32 = 8160 bytes (RFC 5869 §2.3). The previous
	// code requested 8192 bytes, which exceeds this limit, causing
	// io.ReadFull to ALWAYS fail with io.ErrUnexpectedEOF. This made
	// NewAccountFromMnemonic* 100% non-functional (fail-closed) — mnemonic
	// recovery was completely broken. Fix: request exactly 8160 bytes
	// (the RFC maximum), which is more than enough for Dilithium3 key
	// generation (mode3.GenerateKey consumes far less than 8160 bytes of
	// randomness).
	keyMaterial := make([]byte, 8160)
	if _, err := io.ReadFull(reader, keyMaterial); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	// Zeroize IKM after use
	for i := range ikm {
		ikm[i] = 0
	}

	return keyMaterial, nil
}

// deterministicReader provides deterministic randomness from pre-computed data.
type deterministicReader struct {
	data []byte
	pos  int
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// MnemonicToSeed converts a mnemonic phrase to a seed.
func MnemonicToSeed(mnemonic string, password string) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.ErrInvalidMnemonic
	}
	return bip39.NewSeed(mnemonic, password), nil
}
