// Quantaureum Go SDK source, version 1.0.0.
package utils

import (
	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"golang.org/x/crypto/sha3"
)

// Keccak256 calculates the Keccak-256 hash of the input data.
// Returns a 32-byte hash.
func Keccak256(data ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, d := range data {
		hasher.Write(d)
	}
	return hasher.Sum(nil)
}

// Keccak256Hash calculates the Keccak-256 hash and returns it as a common.Hash.
func Keccak256Hash(data ...[]byte) common.Hash {
	return common.BytesToHash(Keccak256(data...))
}

// Keccak256Hex calculates the Keccak-256 hash and returns it as a hex string with 0x prefix.
func Keccak256Hex(data ...[]byte) string {
	return BytesToHex(Keccak256(data...))
}
