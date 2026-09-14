// Quantaureum Node source, version 1.0.0.
// Package common provides common types and utilities for the QAU blockchain.
//
// C-03 (R8 2026-07-19 FIX): Address and Hash are now type aliases for
// types.Address and types.Hash respectively. Previously both packages
// independently defined [20]byte / [32]byte types with the same names but
// incompatible Go types, leading to:
//   - Pervasive `common.Address(x)` / `types.Address(x)` conversions
//   - Method-set divergence (Hex/MarshalJSON only existed on common.*)
//   - Subtle bugs where values compared equal but typed unequal
//
// Now common.Address IS types.Address (and common.Hash IS types.Hash).
// Go does not permit defining new methods on non-local (aliased) types, so
// the previously-common-only methods (Hex, MarshalJSON, UnmarshalJSON) have
// been removed. Audited callers (package perf) do not invoke those methods,
// so the removal is safe. The Hex/MarshalJSON behavior can be reintroduced
// later by defining them on types.Address / types.Hash directly in package
// types if a future need arises.
//
// The remaining exported helpers (BytesToAddress, HexToAddress, BytesToHash,
// HexToHash) are preserved as thin wrappers around the canonical
// implementations in package types for backward compatibility with any
// caller that imports package common.
package common

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/quantaureum/qau/types"
)

const (
	// AddressLength is the expected length of an address in bytes.
	// C-03 (R8 2026-07-19 FIX): Re-exported from types for backward compat.
	AddressLength = types.AddressLength

	// HashLength is the expected length of a hash in bytes.
	// C-03 (R8 2026-07-19 FIX): Re-exported from types for backward compat.
	HashLength = types.HashLength
)

var (
	// ErrInvalidAddressLength is returned when address length is wrong.
	// C-03 (R8 2026-07-19 FIX): Aliased to types.ErrInvalidAddressLength so
	// that errors returned from types.* functions match common's sentinel.
	ErrInvalidAddressLength = types.ErrInvalidAddressLength

	// ErrInvalidHashLength is returned when hash length is wrong.
	// types does not define this sentinel, so it remains common-local.
	ErrInvalidHashLength = errors.New("invalid hash length")

	// ErrInvalidHexString is returned when hex string is invalid.
	ErrInvalidHexString = errors.New("invalid hex string")
)

// Address is an alias for types.Address.
// C-03 (R8 2026-07-19 FIX): Previously `type Address [20]byte` which was a
// distinct, incompatible Go type. Now an alias so common.Address and
// types.Address are the same type — no conversion required.
type Address = types.Address

// Hash is an alias for types.Hash.
// C-03 (R8 2026-07-19 FIX): Previously `type Hash [32]byte` which was a
// distinct, incompatible Go type. Now an alias for types.Hash.
type Hash = types.Hash

// BytesToAddress converts bytes to Address, truncating or padding as needed.
// C-03 (R8 2026-07-19 FIX): Delegates to types.BytesToAddress so there is a
// single implementation. Kept for backward compatibility with callers that
// import package common.
func BytesToAddress(b []byte) Address {
	return types.BytesToAddress(b)
}

// HexToAddress converts a hex string to Address.
// L6-043 SECURITY NOTE: This is a PARSING function (hex string → bytes),
// NOT a comparison function. Constant-time is not required here because:
//  1. The function converts user-supplied input to a typed value; it does
//     not compare two secret values.
//  2. Timing depends on the input string format (prefix, length), not on
//     secret data. An attacker cannot extract secrets from parse timing.
//  3. The length check (len(b) != AddressLength) uses early return, but the
//     address length is public information, not a secret.
func HexToAddress(s string) (Address, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")

	b, err := hex.DecodeString(s)
	if err != nil {
		return Address{}, fmt.Errorf("%w: %v", ErrInvalidHexString, err)
	}

	if len(b) != AddressLength {
		return Address{}, ErrInvalidAddressLength
	}

	return BytesToAddress(b), nil
}

// BytesToHash converts bytes to Hash, truncating or padding as needed.
// C-03 (R8 2026-07-19 FIX): Delegates to types.BytesToHash so there is a
// single implementation.
func BytesToHash(b []byte) Hash {
	return types.BytesToHash(b)
}

// HexToHash converts a hex string to Hash.
// L6-043 SECURITY NOTE: This is a PARSING function (hex string → bytes),
// NOT a comparison function. Constant-time is not required here because:
//  1. The function converts user-supplied input to a typed value; it does
//     not compare two secret values.
//  2. Timing depends on the input string format (prefix, length), not on
//     secret data. An attacker cannot extract secrets from parse timing.
//  3. The length check (len(b) != HashLength) uses early return, but the
//     hash length is public information, not a secret.
func HexToHash(s string) (Hash, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")

	b, err := hex.DecodeString(s)
	if err != nil {
		return Hash{}, fmt.Errorf("%w: %v", ErrInvalidHexString, err)
	}

	if len(b) != HashLength {
		return Hash{}, ErrInvalidHashLength
	}

	return BytesToHash(b), nil
}
