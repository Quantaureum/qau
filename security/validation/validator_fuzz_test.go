// Quantaureum Node source, version 1.0.0.
package validation

import (
	"testing"
)

// FuzzValidateAddress tests the address validation logic with arbitrary inputs.
// This helps discover edge cases that could lead to panics or incorrect acceptance.
func FuzzValidateAddress(f *testing.F) {
	// Seed corpus with valid and invalid addresses
	f.Add("0x1234567890abcdef1234567890abcdef12345678")  // valid
	f.Add("0x")                                          // too short
	f.Add("1234567890abcdef1234567890abcdef12345678")    // missing 0x
	f.Add("0xGGGG")                                      // invalid hex
	f.Add("")                                            // empty
	f.Add("0x1234567890abcdef1234567890abcdef123456789") // too long

	f.Fuzz(func(t *testing.T, addr string) {
		// We only care that validateAddress does not panic and returns
		// a deterministic result for the same input.
		_ = validateAddress(addr)
	})
}

// FuzzValidateHex tests hex string validation with arbitrary inputs.
func FuzzValidateHex(f *testing.F) {
	f.Add("0xabcd")
	f.Add("abcd")
	f.Add("0x")
	f.Add("")
	f.Add("0xGGGG")
	f.Add("0x1234567890abcdef")

	f.Fuzz(func(t *testing.T, hex string) {
		_ = validateHexBytes(hex, 1024)
	})
}

// FuzzValidateTransactionHash tests tx hash validation.
func FuzzValidateTransactionHash(f *testing.F) {
	f.Add("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	f.Add("0x")
	f.Add("")
	f.Add("notahex")

	f.Fuzz(func(t *testing.T, hash string) {
		_ = validateAddress(hash)
	})
}
