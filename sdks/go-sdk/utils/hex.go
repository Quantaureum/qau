// Quantaureum Go SDK source, version 1.0.0.
// Package utils provides utility functions for the Quantaureum Go SDK.
package utils

import (
	"encoding/hex"
	"strings"

	"github.com/quantaureum/qau/sdks/go-sdk/errors"
)

// BytesToHex converts a byte slice to a hex string with 0x prefix.
func BytesToHex(b []byte) string {
	if b == nil {
		return "0x"
	}
	return "0x" + hex.EncodeToString(b)
}

// HexToBytes converts a hex string to a byte slice.
// The hex string may optionally have a "0x" prefix.
// Returns an error if the hex string is invalid.
func HexToBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")

	if len(s) == 0 {
		return []byte{}, nil
	}

	// Pad with leading zero if odd length
	if len(s)%2 == 1 {
		s = "0" + s
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.ErrInvalidHex
	}
	return b, nil
}

// Has0xPrefix checks if a string has the 0x or 0X prefix.
func Has0xPrefix(s string) bool {
	return len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
}

// Add0xPrefix adds the 0x prefix to a hex string if not already present.
func Add0xPrefix(s string) string {
	if Has0xPrefix(s) {
		return s
	}
	return "0x" + s
}

// Remove0xPrefix removes the 0x or 0X prefix from a hex string if present.
func Remove0xPrefix(s string) string {
	if Has0xPrefix(s) {
		return s[2:]
	}
	return s
}

// IsValidHex checks if a string is a valid hex string (with optional 0x prefix).
func IsValidHex(s string) bool {
	s = Remove0xPrefix(s)
	if len(s) == 0 {
		return true
	}
	for _, c := range s {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

// isHexChar checks if a rune is a valid hex character.
func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
