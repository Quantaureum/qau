// Quantaureum Node source, version 1.0.0.
// Package hexutil provides hex encoding/decoding utilities with 0x prefix support.
package hexutil

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const (
	// hexPrefix is the standard hex prefix
	hexPrefix = "0x"
)

var (
	// ErrEmptyString is returned when input is empty
	ErrEmptyString = errors.New("empty hex string")

	// ErrMissingPrefix is returned when 0x prefix is missing
	ErrMissingPrefix = errors.New("hex string without 0x prefix")

	// ErrOddLength is returned when hex string has odd length
	ErrOddLength = errors.New("hex string has odd length")

	// ErrInvalidHex is returned when hex string contains invalid characters
	ErrInvalidHex = errors.New("invalid hex string")

	// ErrLeadingZero is returned when big integer has leading zeros
	ErrLeadingZero = errors.New("hex number with leading zero digits")

	// ErrEmptyNumber is returned when number is empty (0x)
	ErrEmptyNumber = errors.New("hex string \"0x\"")

	// ErrBig256Range is returned when big integer exceeds 256 bits
	ErrBig256Range = errors.New("hex number > 256 bits")
)

// Encode encodes bytes as a hex string with 0x prefix
func Encode(b []byte) string {
	if len(b) == 0 {
		return hexPrefix
	}
	return hexPrefix + hex.EncodeToString(b)
}

// Decode decodes a hex string with 0x prefix to bytes
func Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, ErrEmptyString
	}
	if !has0xPrefix(s) {
		return nil, ErrMissingPrefix
	}
	s = s[2:]
	if len(s) == 0 {
		return []byte{}, nil
	}
	if len(s)%2 != 0 {
		return nil, ErrOddLength
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHex, err)
	}
	return b, nil
}

// DecodeBytes decodes a hex string with 0x prefix to bytes
func DecodeBytes(s string) ([]byte, error) {
	return Decode(s)
}

// EncodeBig encodes a big integer as a hex string with 0x prefix
// The sign of the integer is ignored
func EncodeBig(i *big.Int) string {
	if i == nil {
		return "0x0"
	}
	if i.Sign() == 0 {
		return "0x0"
	}
	// Use absolute value
	abs := new(big.Int).Abs(i)
	return hexPrefix + abs.Text(16)
}

// DecodeBig decodes a hex string with 0x prefix to a big integer
func DecodeBig(s string) (*big.Int, error) {
	if s == "" {
		return nil, ErrEmptyString
	}
	if !has0xPrefix(s) {
		return nil, ErrMissingPrefix
	}
	s = s[2:]
	if len(s) == 0 {
		return nil, ErrEmptyNumber
	}
	// Check for leading zeros (except for "0" itself)
	if len(s) > 1 && s[0] == '0' {
		return nil, ErrLeadingZero
	}

	i, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, ErrInvalidHex
	}

	// Check 256-bit limit
	if i.BitLen() > 256 {
		return nil, ErrBig256Range
	}

	return i, nil
}

// DecodeBigInt decodes a hex string with 0x prefix to a big integer
func DecodeBigInt(s string) (*big.Int, error) {
	return DecodeBig(s)
}

// EncodeUint64 encodes a uint64 as a hex string with 0x prefix
func EncodeUint64(i uint64) string {
	if i == 0 {
		return "0x0"
	}
	return fmt.Sprintf("0x%x", i)
}

// DecodeUint64 decodes a hex string with 0x prefix to uint64
func DecodeUint64(s string) (uint64, error) {
	if s == "" {
		return 0, ErrEmptyString
	}
	if !has0xPrefix(s) {
		return 0, ErrMissingPrefix
	}
	s = s[2:]
	if len(s) == 0 {
		return 0, ErrEmptyNumber
	}
	// Check for leading zeros
	if len(s) > 1 && s[0] == '0' {
		return 0, ErrLeadingZero
	}

	// L14-026/L15-024 FIX: Use strconv.ParseUint instead of fmt.Sscanf for
	// constant-time hex parsing (Sscanf uses reflection and format string parsing).
	i, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidHex, err)
	}
	return i, nil
}

// has0xPrefix checks if string has 0x or 0X prefix
func has0xPrefix(s string) bool {
	return len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
}

// IsHex checks if a string is a valid hex string with 0x prefix
func IsHex(s string) bool {
	if !has0xPrefix(s) {
		return false
	}
	s = s[2:]
	if len(s) == 0 {
		return true
	}
	for _, c := range s {
		if !isHexChar(byte(c)) { // #nosec G115 -- single byte extraction
			return false
		}
	}
	return true
}

// isHexChar checks if a byte is a valid hex character
func isHexChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// DecodeNoPrefix decodes a hex string without requiring 0x prefix
func DecodeNoPrefix(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")

	if len(s) == 0 {
		return []byte{}, nil
	}
	if len(s)%2 != 0 {
		return nil, ErrOddLength
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHex, err)
	}
	return b, nil
}
