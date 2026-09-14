// Quantaureum Go SDK source, version 1.0.0.
package utils

import (
	"strings"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
)

// IsValidAddress checks if a string is a valid Ethereum-style address.
// A valid address is a 40-character hex string (with optional 0x prefix).
func IsValidAddress(s string) bool {
	s = Remove0xPrefix(s)

	// Must be exactly 40 hex characters
	if len(s) != 40 {
		return false
	}

	// All characters must be valid hex
	for _, c := range s {
		if !isHexChar(c) {
			return false
		}
	}

	return true
}

// ChecksumAddress returns the EIP-55 checksummed version of an address.
// The input can be a hex string (with or without 0x prefix) or a common.Address.
func ChecksumAddress(addr string) string {
	addr = strings.ToLower(Remove0xPrefix(addr))

	if len(addr) != 40 {
		return ""
	}

	// Hash the lowercase address
	hash := Keccak256([]byte(addr))

	result := make([]byte, 40)
	for i := 0; i < 40; i++ {
		c := addr[i]
		// Get the corresponding nibble from the hash
		hashByte := hash[i/2]
		var hashNibble byte
		if i%2 == 0 {
			hashNibble = hashByte >> 4
		} else {
			hashNibble = hashByte & 0x0f
		}

		// If the hash nibble is >= 8, uppercase the character
		if c >= 'a' && c <= 'f' && hashNibble >= 8 {
			result[i] = c - 32 // Convert to uppercase
		} else {
			result[i] = c
		}
	}

	return "0x" + string(result)
}

// ChecksumAddressFromBytes returns the EIP-55 checksummed address from a byte slice.
func ChecksumAddressFromBytes(b []byte) string {
	addr := common.BytesToAddress(b)
	return ChecksumAddress(addr.Hex())
}

// IsChecksumAddress checks if an address has valid EIP-55 checksum.
func IsChecksumAddress(addr string) bool {
	if !IsValidAddress(addr) {
		return false
	}
	return ChecksumAddress(addr) == addr
}

// AddressFromHex converts a hex string to a common.Address.
// Returns the zero address if the input is invalid.
func AddressFromHex(s string) common.Address {
	return common.HexToAddress(s)
}
