// Quantaureum Node source, version 1.0.0.
// Package types provides core data types for the Quantaureum blockchain.
package types

import (
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"

	logging "github.com/quantaureum/qau/log"
)

const (
	// AddressLength is the expected length of an address in bytes
	AddressLength = 20

	// AddressPrefix is the prefix for all Quantaureum addresses
	AddressPrefix = "QAU"

	// HashLength is the expected length of a hash in bytes
	HashLength = 32
)

var (
	// ErrInvalidAddress is returned when an address is invalid
	ErrInvalidAddress = errors.New("invalid address")

	// ErrInvalidAddressLength is returned when address length is wrong
	ErrInvalidAddressLength = errors.New("invalid address length")

	// ErrInvalidAddressPrefix is returned when address prefix is wrong
	ErrInvalidAddressPrefix = errors.New("invalid address prefix")

	// base32Encoding is the encoding used for address strings (no padding)
	base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// Address represents a 20-byte Quantaureum address
type Address [AddressLength]byte

// Hash represents a 32-byte hash
type Hash [HashLength]byte

// BytesToAddress converts bytes to Address, truncating or padding as needed
func BytesToAddress(b []byte) Address {
	var addr Address
	if len(b) > AddressLength {
		b = b[len(b)-AddressLength:]
	}
	copy(addr[AddressLength-len(b):], b)
	return addr
}

// BytesToAddressStrict returns an error if b is not exactly AddressLength bytes.
// M-01 FIX (R8 2026-07-19): BytesToAddress silently truncates long inputs and
// zero-pads short inputs, masking upstream bugs that pass wrong-length data
// (e.g. feeding a 32-byte hash into a 20-byte address slot). The strict
// variant is required on cryptography-sensitive paths where an address derived
// from wrong-length input would be a valid-looking but completely wrong address.
// The legacy BytesToAddress is retained for non-security-sensitive tooling.
func BytesToAddressStrict(b []byte) (Address, error) {
	if len(b) != AddressLength {
		return Address{}, ErrInvalidAddressLength
	}
	var addr Address
	copy(addr[:], b)
	return addr, nil
}

// Bytes returns the address as a byte slice
func (a Address) Bytes() []byte {
	return a[:]
}

// String returns the QAU-prefixed base32 representation of the address
func (a Address) String() string {
	return AddressPrefix + base32Encoding.EncodeToString(a[:])
}

// IsEmpty returns true if the address is all zeros
func (a Address) IsEmpty() bool {
	// audit-fix L4-001: constant-time comparison to prevent timing side-channel.
	// Accumulate OR of all bytes instead of early-return on first non-zero byte.
	var acc byte
	for _, b := range a {
		acc |= b
	}
	return acc == 0
}

// ParseAddress parses a QAU-prefixed address string
func ParseAddress(s string) (Address, error) {
	var addr Address

	if s == "" {
		return addr, ErrInvalidAddress
	}

	if !strings.HasPrefix(s, AddressPrefix) {
		return addr, ErrInvalidAddressPrefix
	}

	// Remove prefix
	encoded := s[len(AddressPrefix):]
	if encoded == "" {
		return addr, ErrInvalidAddress
	}

	// Decode base32
	decoded, err := base32Encoding.DecodeString(encoded)
	if err != nil {
		return addr, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}

	if len(decoded) != AddressLength {
		return addr, ErrInvalidAddressLength
	}

	copy(addr[:], decoded)
	return addr, nil
}

// AddressFromPublicKey derives an address from a public key using SHA3-256
// The address is the last 20 bytes of SHA3-256(publicKey)
//
// =============================================================================
// SHARED INTERFACE WARNING - DO NOT MODIFY WITHOUT SYNCING WITH WALLET
// =============================================================================
// This function implements SHARED ADDRESS DERIVATION with Quantaureum Wallet
// (app/scripts/lib/quantum-crypto/dilithium3.ts deriveAddress).
// The address derivation algorithm MUST be identical on both sides.
//
// Algorithm:
//  1. Compute SHA3-256(publicKey)
//  2. Take last 20 bytes (bytes 12-31 of the 32-byte hash)
//  3. Return as Address type (20 bytes)
//
// Wallet implementation: the quantaureum-wallet repo
//
//	deriveAddress() method
//
// =============================================================================
// ErrInvalidPublicKeySize is returned when a public key is not the expected
// Dilithium3 size (1952 bytes). H-01 (R8 2026-07-19 FIX): previously,
// AddressFromPublicKey silently returned an empty Address on invalid input,
// which callers could not distinguish from a valid (but zero) derivation.
// This made it impossible to reject malformed public keys at API boundaries
// and led to silently-accepted invalid transactions whose From field was
// the zero Address. Callers that can propagate errors MUST use
// AddressFromPublicKeyE and surface the error to the caller.
var ErrInvalidPublicKeySize = errors.New("invalid public key size: expected 1952 bytes (Dilithium3)")

// AddressFromPublicKeyE derives an address from a public key and returns an
// error if the public key is invalid (wrong size). H-01 (R8 2026-07-19 FIX):
// this is the preferred API for callers that can propagate errors. Use this
// in deserialization, signature verification, and RPC input paths so that
// malformed public keys are rejected explicitly rather than silently mapped
// to the zero Address.
//
// SHARED INTERFACE WARNING - MUST SYNC WITH WALLET
// Wallet: the quantaureum-wallet repo
// Algorithm: SHA3-256(publicKey), take last 20 bytes (bytes 12-31 of 32-byte hash)
// Version: v1.1 - Both Wallet and Core use identical algorithm with runtime validation
// Note: Wallet supports optional ethereumCompatible mode for EIP-55 checksum encoding,
// but the base address derivation is IDENTICAL (pure SHA3-256).
func AddressFromPublicKeyE(pubKey []byte) (Address, error) {
	// CRITICAL FIX: Runtime public key size validation (1952 bytes for Dilithium3)
	// Prevents address derivation from malformed keys that could lead to collision attacks
	// This check MUST match the Wallet's dilithium3.ts deriveAddress validation
	if len(pubKey) != QuantumPublicKeySize {
		// R41-CR-002 FIX: Do not log actual key length — only log a fixed
		// message to avoid leaking key format information to attackers.
		logging.Global().Warn("AddressFromPublicKeyE: rejected invalid public key size")
		return Address{}, ErrInvalidPublicKeySize
	}
	hash := sha3.Sum256(pubKey)
	return BytesToAddress(hash[HashLength-AddressLength:]), nil
}

// AddressFromPublicKey derives an address from a public key. It is a
// backwards-compatible wrapper around AddressFromPublicKeyE: on invalid
// input it logs a warning and returns the zero Address (preserving the
// previous behavior). NEW CODE SHOULD PREFER AddressFromPublicKeyE so
// that malformed keys are rejected at API boundaries instead of being
// silently mapped to the zero Address.
//
// H-01 (R8 2026-07-19 FIX): This function is retained for existing callers
// that cannot propagate an error (e.g. Sender()). It logs a warning on
// invalid input but still returns zero Address. Do not use in new code
// paths that handle untrusted input — use AddressFromPublicKeyE.
func AddressFromPublicKey(pubKey []byte) Address {
	addr, err := AddressFromPublicKeyE(pubKey)
	if err != nil {
		return Address{}
	}
	return addr
}

// ParseHexAddress parses an Ethereum-style 0x-prefixed hex address
// This is provided for migration compatibility - should be removed after full migration
func ParseHexAddress(s string) (Address, error) {
	var addr Address

	if len(s) == 0 {
		return addr, ErrInvalidAddress
	}

	// Remove 0x prefix if present
	hexStr := s
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		hexStr = s[2:]
	}

	// Must be 40 hex characters (20 bytes)
	if len(hexStr) != 40 {
		return addr, ErrInvalidAddressLength
	}

	// Decode hex
	decoded, err := hexDecode(hexStr)
	if err != nil {
		return addr, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}

	copy(addr[:], decoded)
	return addr, nil
}

// ParseAddressWithFallback parses an address (supports both QAU and 0x formats)
// Returns address or error
func ParseAddressWithFallback(s string) (Address, error) {
	addr, err := ParseAddress(s)
	if err == nil {
		return addr, nil
	}

	// Try hex format
	addr, err = ParseHexAddress(s)
	if err != nil {
		return Address{}, fmt.Errorf("invalid address %q: %w", s, err)
	}
	return addr, nil
}

// ToHexAddress converts a QAU address to Ethereum-style hex format
// This is for backward compatibility during migration
func (a Address) ToHexAddress() string {
	return fmt.Sprintf("0x%x", a[:])
}

// Equal returns true if two addresses are equal.
// L18-023 FIX: Use constant-time comparison to prevent timing side-channels.
// Although Go's == on fixed-size arrays typically compiles to memequal
// (which is constant-time), we delegate to ConstantTimeEqual for an
// explicit, auditable guarantee.
func (a Address) Equal(other Address) bool {
	return a.ConstantTimeEqual(other)
}

// ConstantTimeEqual returns true if two addresses are equal using constant-time
// comparison. Use this in security-sensitive contexts (e.g., authorization checks)
// to prevent timing side-channels.
// audit-fix L-1: constant-time address comparison for security contexts.
func (a Address) ConstantTimeEqual(other Address) bool {
	return subtle.ConstantTimeCompare(a[:], other[:]) == 1
}

// IsValid returns true if the address is not zero address
func (a Address) IsValid() bool {
	return !a.IsEmpty()
}

// ShortString returns a shortened string representation (first 8 chars)
func (a Address) ShortString() string {
	str := a.String()
	if len(str) > 8 {
		return str[:8] + "..."
	}
	return str
}

// hexDecode decodes a hex string to bytes (internal helper)
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("hex string has odd length")
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		result[i/2] = byte(b)
	}
	return result, nil
}

// BytesToHash converts bytes to Hash
func BytesToHash(b []byte) Hash {
	var h Hash
	if len(b) > HashLength {
		b = b[len(b)-HashLength:]
	}
	copy(h[HashLength-len(b):], b)
	return h
}

// ErrInvalidHashLength is returned when a hash is not exactly HashLength bytes.
// M-01 FIX (R8 2026-07-19): companion to BytesToHashStrict.
var ErrInvalidHashLength = errors.New("invalid hash length")

// BytesToHashStrict returns an error if b is not exactly HashLength bytes.
// M-01 FIX (R8 2026-07-19): mirrors BytesToAddressStrict — the legacy
// BytesToHash silently truncates/pads, which masks bugs in callers that pass
// wrong-length input. Use the strict variant on any path where a wrong-length
// hash would be a security-relevant confusion (e.g. block hashes, tx hashes
// in consensus-critical comparisons).
func BytesToHashStrict(b []byte) (Hash, error) {
	if len(b) != HashLength {
		return Hash{}, ErrInvalidHashLength
	}
	var h Hash
	copy(h[:], b)
	return h, nil
}

// Bytes returns the hash as a byte slice
func (h Hash) Bytes() []byte {
	return h[:]
}

// String returns the hex representation of the hash
func (h Hash) String() string {
	return fmt.Sprintf("%x", h[:])
}

// IsEmpty returns true if the hash is all zeros
func (h Hash) IsEmpty() bool {
	// audit-fix L4-001: constant-time comparison to prevent timing side-channel.
	var acc byte
	for _, b := range h {
		acc |= b
	}
	return acc == 0
}

// ConstantTimeEqual returns true if two hashes are equal using constant-time
// comparison.
//
// CRYPTO-R13-008 (2026-07-21) FIX: Go's == on [N]byte arrays compiles to a
// runtime memequal call that short-circuits on the first differing byte.
// Although the runtime memequal is often branchless on common architectures,
// the Go spec does NOT guarantee constant-time behavior for array ==. For
// hashes that may be unannounced at the time Equal() is invoked (e.g., a
// ParentHash / StateRoot that a peer is still validating before broadcast),
// use this method to obtain a cryptographic constant-time guarantee. This
// mirrors the Address.ConstantTimeEqual pattern established in audit-fix L-1.
func (h Hash) ConstantTimeEqual(other Hash) bool {
	return subtle.ConstantTimeCompare(h[:], other[:]) == 1
}

// Keccak256Hash computes the Keccak256 hash of data and returns it as a Hash
func Keccak256Hash(data []byte) Hash {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	var h Hash
	copy(h[:], hash.Sum(nil))
	return h
}
