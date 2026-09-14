// Quantaureum Go SDK source, version 1.0.0.
// Package utils provides utility functions for the Quantaureum Go SDK.
package utils

import (
	"context"
	"math/big"
	"strings"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
)

// ValidateAddress validates an address string and returns a ValidationError if invalid.
func ValidateAddress(field string, addr string) error {
	if addr == "" {
		return errors.NewValidationError(field, "address cannot be empty")
	}
	if !IsValidAddress(addr) {
		return errors.NewValidationError(field, "invalid address format")
	}
	return nil
}

// ValidateAddressNotEmpty validates that a common.Address is not empty.
func ValidateAddressNotEmpty(field string, addr common.Address) error {
	if addr.IsEmpty() {
		return errors.NewValidationError(field, "address cannot be empty")
	}
	return nil
}

// ValidateHash validates a hash string and returns a ValidationError if invalid.
func ValidateHash(field string, hash string) error {
	if hash == "" {
		return errors.NewValidationError(field, "hash cannot be empty")
	}
	hash = Remove0xPrefix(hash)
	if len(hash) != 64 {
		return errors.NewValidationError(field, "hash must be 32 bytes (64 hex characters)")
	}
	if !IsValidHex(hash) {
		return errors.NewValidationError(field, "invalid hash format")
	}
	return nil
}

// ValidateHashNotEmpty validates that a common.Hash is not empty.
func ValidateHashNotEmpty(field string, hash common.Hash) error {
	if hash.IsEmpty() {
		return errors.NewValidationError(field, "hash cannot be empty")
	}
	return nil
}

// ValidateHexString validates a hex string and returns a ValidationError if invalid.
func ValidateHexString(field string, hex string) error {
	if hex == "" {
		return nil // Empty hex is valid
	}
	if !IsValidHex(hex) {
		return errors.NewValidationError(field, "invalid hex string")
	}
	return nil
}

// ValidatePrivateKey validates a private key hex string.
// audit-fix GO-CRIT-1: Quantaureum uses Dilithium3 post-quantum signatures,
// which have 4000-byte private keys (not 32-byte ECDSA keys). The old code
// rejected all valid Dilithium3 private keys because it only accepted 32 bytes.
// Now we accept both 32-byte ECDSA (legacy) and 4000-byte Dilithium3 keys.
func ValidatePrivateKey(field string, key string) error {
	if key == "" {
		return errors.NewValidationError(field, "private key cannot be empty")
	}
	keyBytes, err := HexToBytes(key)
	if err != nil {
		return errors.NewValidationErrorWithCause(field, "invalid private key format", err)
	}
	if len(keyBytes) != 32 && len(keyBytes) != Dilithium3PrivateKeySize {
		return errors.NewValidationError(field,
			"private key must be 32 bytes (ECDSA) or 4000 bytes (Dilithium3)")
	}
	return nil
}

// ValidatePrivateKeyBytes validates private key bytes.
// audit-fix GO-CRIT-1: Accept both 32-byte ECDSA and 4000-byte Dilithium3 keys.
func ValidatePrivateKeyBytes(field string, key []byte) error {
	if key == nil {
		return errors.NewValidationError(field, "private key cannot be nil")
	}
	if len(key) != 32 && len(key) != Dilithium3PrivateKeySize {
		return errors.NewValidationError(field,
			"private key must be 32 bytes (ECDSA) or 4000 bytes (Dilithium3)")
	}
	return nil
}

// Dilithium3 key sizes per NIST FIPS 204 (Dilithium3 parameter set)
const (
	Dilithium3PrivateKeySize = 4000
	Dilithium3PublicKeySize  = 1952
	Dilithium3SignatureSize  = 3293
)

// ValidateMnemonic validates a mnemonic phrase.
func ValidateMnemonic(field string, mnemonic string) error {
	if mnemonic == "" {
		return errors.NewValidationError(field, "mnemonic cannot be empty")
	}
	words := strings.Fields(mnemonic)
	wordCount := len(words)
	// Valid word counts: 12, 15, 18, 21, 24
	if wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24 {
		return errors.NewValidationError(field, "mnemonic must have 12, 15, 18, 21, or 24 words")
	}
	return nil
}

// ValidateDerivationPath validates a BIP-32 derivation path.
func ValidateDerivationPath(field string, path string) error {
	if path == "" {
		return errors.NewValidationError(field, "derivation path cannot be empty")
	}
	if !strings.HasPrefix(path, "m/") && path != "m" {
		return errors.NewValidationError(field, "derivation path must start with 'm/'")
	}
	return nil
}

// ValidateBigInt validates a *big.Int is not nil.
func ValidateBigInt(field string, value *big.Int) error {
	if value == nil {
		return errors.NewValidationError(field, "value cannot be nil")
	}
	return nil
}

// ValidateBigIntPositive validates a *big.Int is not nil and is positive.
func ValidateBigIntPositive(field string, value *big.Int) error {
	if value == nil {
		return errors.NewValidationError(field, "value cannot be nil")
	}
	if value.Sign() < 0 {
		return errors.NewValidationError(field, "value must be non-negative")
	}
	return nil
}

// ValidateContext validates that a context is not nil.
func ValidateContext(ctx context.Context) error {
	if ctx == nil {
		return errors.NewValidationError("ctx", "context cannot be nil")
	}
	return nil
}

// ValidateNotNil validates that a pointer is not nil.
func ValidateNotNil(field string, value any) error {
	if value == nil {
		return errors.NewValidationError(field, "value cannot be nil")
	}
	return nil
}

// ValidateBytes validates that a byte slice is not nil.
func ValidateBytes(field string, data []byte) error {
	if data == nil {
		return errors.NewValidationError(field, "data cannot be nil")
	}
	return nil
}

// ValidateBytesNotEmpty validates that a byte slice is not nil and not empty.
func ValidateBytesNotEmpty(field string, data []byte) error {
	if data == nil {
		return errors.NewValidationError(field, "data cannot be nil")
	}
	if len(data) == 0 {
		return errors.NewValidationError(field, "data cannot be empty")
	}
	return nil
}

// ValidateStringNotEmpty validates that a string is not empty.
func ValidateStringNotEmpty(field string, value string) error {
	if value == "" {
		return errors.NewValidationError(field, "value cannot be empty")
	}
	return nil
}

// ValidateURL validates a URL string.
func ValidateURL(field string, url string) error {
	if url == "" {
		return errors.NewValidationError(field, "URL cannot be empty")
	}
	// Basic URL validation - must have a scheme
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "ws://") && !strings.HasPrefix(url, "wss://") {
		return errors.NewValidationError(field, "URL must have a valid scheme (http, https, ws, wss)")
	}
	return nil
}

// ValidateGasLimit validates a gas limit value.
func ValidateGasLimit(field string, gas uint64) error {
	if gas == 0 {
		return errors.NewValidationError(field, "gas limit cannot be zero")
	}
	return nil
}

// ValidateChainID validates a chain ID.
func ValidateChainID(field string, chainID *big.Int) error {
	if chainID == nil {
		return errors.NewValidationError(field, "chain ID cannot be nil")
	}
	if chainID.Sign() <= 0 {
		return errors.NewValidationError(field, "chain ID must be positive")
	}
	return nil
}

// ValidateDecimals validates decimal places for unit conversion.
func ValidateDecimals(field string, decimals int) error {
	if decimals < 0 {
		return errors.NewValidationError(field, "decimals cannot be negative")
	}
	if decimals > 77 { // Max for uint256
		return errors.NewValidationError(field, "decimals too large")
	}
	return nil
}

// ValidateABIMethod validates an ABI method name.
func ValidateABIMethod(field string, method string) error {
	if method == "" {
		return errors.NewValidationError(field, "method name cannot be empty")
	}
	return nil
}
