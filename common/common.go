// Quantaureum Node source, version 1.0.0.
// Package common provides common types and utilities for the QAU blockchain.
//
// This package contains fundamental types and utility functions used throughout
// the QAU blockchain implementation. It includes core types like Address and Hash,
// as well as subpackages for hex encoding, safe math operations, and LRU caching.
//
// # Core Types
//
// The package provides two fundamental types:
//
//   - Address: A 20-byte type representing blockchain addresses
//   - Hash: A 32-byte type representing cryptographic hashes
//
// Both types support hex encoding/decoding with 0x prefix and JSON serialization.
//
// # Address Usage
//
// Create an address from hex string:
//
//	addr, err := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(addr.Hex()) // 0x1234567890abcdef1234567890abcdef12345678
//
// Create an address from bytes:
//
//	addr := common.BytesToAddress(someBytes)
//
// # Hash Usage
//
// Create a hash from hex string:
//
//	hash, err := common.HexToHash("0x...")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Subpackages
//
// The common package includes several subpackages:
//
//   - hexutil: Hex encoding/decoding utilities with 0x prefix support
//   - math: Safe big integer arithmetic with overflow detection
//   - lru: Generic LRU cache implementation
//
// # Hexutil Subpackage
//
// The hexutil subpackage provides hex encoding/decoding:
//
//	import "github.com/quantaureum/qau/common/hexutil"
//
//	// Encode bytes to hex
//	hex := hexutil.Encode([]byte{0x01, 0x02, 0x03})
//	// hex = "0x010203"
//
//	// Decode hex to bytes
//	bytes, err := hexutil.Decode("0x010203")
//
//	// Encode/decode big integers
//	bigHex := hexutil.EncodeBig(big.NewInt(255))
//	// bigHex = "0xff"
//
// # Math Subpackage
//
// The math subpackage provides safe arithmetic operations:
//
//	import "github.com/quantaureum/qau/common/math"
//
//	// Safe addition with overflow detection
//	result, ok := math.SafeAdd(a, b)
//	if !ok {
//	    log.Println("overflow detected")
//	}
//
//	// Safe multiplication
//	result, ok := math.SafeMul(a, b)
//
// # LRU Subpackage
//
// The lru subpackage provides a generic LRU cache:
//
//	import "github.com/quantaureum/qau/common/lru"
//
//	// Create a cache with max 100 items
//	cache := lru.New[string, int](100)
//
//	// Add items
//	cache.Put("key1", 42)
//
//	// Get items
//	value, found := cache.Get("key1")
package common

// Version information
const (
	// PackageVersion is the version of the common package
	PackageVersion = "1.0.0"
)

// Exported types from types.go:
// - Address (20-byte blockchain address)
// - Hash (32-byte cryptographic hash)
// - BytesToAddress
// - HexToAddress
// - BytesToHash
// - HexToHash

// Exported constants from types.go:
// - AddressLength (20)
// - HashLength (32)

// Exported errors from types.go:
// - ErrInvalidAddressLength
// - ErrInvalidHashLength
// - ErrInvalidHexString

// Subpackages:
// - github.com/quantaureum/qau/common/hexutil
// - github.com/quantaureum/qau/common/math
// - github.com/quantaureum/qau/common/lru
