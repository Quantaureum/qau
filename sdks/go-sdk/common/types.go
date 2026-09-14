// Quantaureum Go SDK source, version 1.0.0.
// Package common provides common types used throughout the Quantaureum Go SDK.
package common

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	// AddressLength is the expected length of an address in bytes
	AddressLength = 20
	// HashLength is the expected length of a hash in bytes
	HashLength = 32
)

// Address represents a 20-byte Ethereum-style address.
type Address [AddressLength]byte

// Hash represents a 32-byte Keccak256 hash.
type Hash [HashLength]byte

// BytesToAddress converts a byte slice to an Address.
// If the slice is longer than AddressLength, it takes the last AddressLength bytes.
// If shorter, it pads with zeros on the left.
func BytesToAddress(b []byte) Address {
	var a Address
	if len(b) > AddressLength {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
	return a
}

// HexToAddress converts a hex string to an Address.
// The hex string may optionally have a "0x" prefix.
func HexToAddress(s string) Address {
	return BytesToAddress(fromHex(s))
}

// Bytes returns the byte slice representation of the address.
func (a Address) Bytes() []byte {
	return a[:]
}

// Hex returns the hex string representation of the address with 0x prefix.
func (a Address) Hex() string {
	return "0x" + hex.EncodeToString(a[:])
}

// String implements fmt.Stringer, returns the hex representation.
func (a Address) String() string {
	return a.Hex()
}

// Format implements fmt.Formatter for custom formatting.
func (a Address) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%s", a.Hex())
}

// SetBytes sets the address to the value of b.
// If b is larger than AddressLength, b will be cropped from the left.
func (a *Address) SetBytes(b []byte) {
	if len(b) > AddressLength {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// BytesToHash converts a byte slice to a Hash.
// If the slice is longer than HashLength, it takes the last HashLength bytes.
// If shorter, it pads with zeros on the left.
func BytesToHash(b []byte) Hash {
	var h Hash
	if len(b) > HashLength {
		b = b[len(b)-HashLength:]
	}
	copy(h[HashLength-len(b):], b)
	return h
}

// HexToHash converts a hex string to a Hash.
// The hex string may optionally have a "0x" prefix.
func HexToHash(s string) Hash {
	return BytesToHash(fromHex(s))
}

// Bytes returns the byte slice representation of the hash.
func (h Hash) Bytes() []byte {
	return h[:]
}

// Hex returns the hex string representation of the hash with 0x prefix.
func (h Hash) Hex() string {
	return "0x" + hex.EncodeToString(h[:])
}

// String implements fmt.Stringer, returns the hex representation.
func (h Hash) String() string {
	return h.Hex()
}

// Format implements fmt.Formatter for custom formatting.
func (h Hash) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%s", h.Hex())
}

// SetBytes sets the hash to the value of b.
// If b is larger than HashLength, b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > HashLength {
		b = b[len(b)-HashLength:]
	}
	copy(h[HashLength-len(b):], b)
}

// fromHex converts a hex string to bytes, handling the optional 0x prefix.
func fromHex(s string) []byte {
	if has0xPrefix(s) {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, _ := hex.DecodeString(s)
	return b
}

// has0xPrefix checks if a string has the 0x prefix.
func has0xPrefix(s string) bool {
	return len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
}

// EmptyAddress returns an empty (zero) address.
func EmptyAddress() Address {
	return Address{}
}

// EmptyHash returns an empty (zero) hash.
func EmptyHash() Hash {
	return Hash{}
}

// IsEmpty returns true if the address is empty (all zeros).
func (a Address) IsEmpty() bool {
	return a == Address{}
}

// IsEmpty returns true if the hash is empty (all zeros).
func (h Hash) IsEmpty() bool {
	return h == Hash{}
}

// Big converts an address to a big.Int.
func (a Address) Big() *big.Int {
	return new(big.Int).SetBytes(a[:])
}

// Big converts a hash to a big.Int.
func (h Hash) Big() *big.Int {
	return new(big.Int).SetBytes(h[:])
}
