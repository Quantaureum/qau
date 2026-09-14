// Quantaureum Node source, version 1.0.0.
// Package blake2b provides BLAKE2b hash functions.
// BLAKE2b is a cryptographic hash function faster than MD5, SHA-1, SHA-2, and SHA-3,
// yet is at least as secure as the latest standard SHA-3.
package blake2b

import (
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
)

const (
	// Size256 is the size of a BLAKE2b-256 hash in bytes
	Size256 = 32

	// Size512 is the size of a BLAKE2b-512 hash in bytes
	Size512 = 64

	// BlockSize is the block size of BLAKE2b in bytes
	BlockSize = 128
)

// Sum256 returns the BLAKE2b-256 hash of the data
func Sum256(data []byte) [Size256]byte {
	return blake2b.Sum256(data)
}

// Sum512 returns the BLAKE2b-512 hash of the data
func Sum512(data []byte) [Size512]byte {
	return blake2b.Sum512(data)
}

// New256 returns a new hash.Hash computing the BLAKE2b-256 checksum
func New256() (hash.Hash, error) {
	return blake2b.New256(nil)
}

// New512 returns a new hash.Hash computing the BLAKE2b-512 checksum
func New512() (hash.Hash, error) {
	return blake2b.New512(nil)
}

// NewWithKey returns a new hash.Hash computing the BLAKE2b-256 checksum with a key (MAC mode)
func NewWithKey(key []byte) (hash.Hash, error) {
	return blake2b.New256(key)
}

// Sum256Slice returns the BLAKE2b-256 hash of the data as a slice
func Sum256Slice(data []byte) []byte {
	h := Sum256(data)
	return h[:]
}

// Sum512Slice returns the BLAKE2b-512 hash of the data as a slice
func Sum512Slice(data []byte) []byte {
	h := Sum512(data)
	return h[:]
}

// Hash256 computes BLAKE2b-256 hash of multiple data chunks
// audit-fix L-1: propagate error from New256 instead of silently ignoring
func Hash256(data ...[]byte) ([Size256]byte, error) {
	h, err := New256()
	if err != nil {
		return [Size256]byte{}, fmt.Errorf("blake2b: failed to create Hash256: %w", err)
	}
	for _, d := range data {
		h.Write(d)
	}
	var result [Size256]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

// Hash512 computes BLAKE2b-512 hash of multiple data chunks
// audit-fix L-1: propagate error from New512 instead of silently ignoring
func Hash512(data ...[]byte) ([Size512]byte, error) {
	h, err := New512()
	if err != nil {
		return [Size512]byte{}, fmt.Errorf("blake2b: failed to create Hash512: %w", err)
	}
	for _, d := range data {
		h.Write(d)
	}
	var result [Size512]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}
