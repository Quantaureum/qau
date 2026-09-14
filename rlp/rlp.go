// Quantaureum Node source, version 1.0.0.
// Package rlp implements the RLP (Recursive Length Prefix) serialization format.
//
// RLP is the main encoding method used to serialize objects in Ethereum and QAU.
// The purpose of RLP is to encode arbitrarily nested arrays of binary data,
// providing a canonical serialization format for blockchain data structures.
//
// # RLP Encoding Rules
//
// RLP encoding is defined as follows:
//   - For a single byte whose value is in the [0x00, 0x7f] range, that byte is its own RLP encoding.
//   - If a string is 0-55 bytes long, the RLP encoding consists of a single byte with value 0x80
//     plus the length of the string followed by the string.
//   - If a string is more than 55 bytes long, the RLP encoding consists of a single byte with value
//     0xb7 plus the length in bytes of the length of the string in binary form, followed by the
//     length of the string, followed by the string.
//   - If the total payload of a list is 0-55 bytes long, the RLP encoding consists of a single byte
//     with value 0xc0 plus the length of the list followed by the concatenation of the RLP encodings
//     of the items.
//   - If the total payload of a list is more than 55 bytes long, the RLP encoding consists of a
//     single byte with value 0xf7 plus the length in bytes of the length of the payload in binary
//     form, followed by the length of the payload, followed by the concatenation of the RLP encodings
//     of the items.
//
// # Basic Usage
//
// Encoding a value:
//
//	type Transaction struct {
//	    Nonce    uint64
//	    GasPrice *big.Int
//	    To       []byte
//	    Value    *big.Int
//	    Data     []byte
//	}
//
//	tx := Transaction{Nonce: 1, GasPrice: big.NewInt(1000)}
//	encoded, err := rlp.EncodeToBytes(tx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Decoding a value:
//
//	var decoded Transaction
//	err := rlp.DecodeBytes(encoded, &decoded)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Supported Types
//
// The RLP package supports encoding and decoding of:
//   - Basic types: bool, uint, uint8-uint64, string, []byte
//   - Big integers: *big.Int
//   - Slices and arrays of supported types
//   - Structs with exported fields of supported types
//   - Nested structures
//
// # Custom Encoding
//
// Types can implement the Encoder interface for custom encoding:
//
//	type Encoder interface {
//	    EncodeRLP(w io.Writer) error
//	}
//
// Types can implement the Decoder interface for custom decoding:
//
//	type Decoder interface {
//	    DecodeRLP(s *Stream) error
//	}
//
// # Stream Decoding
//
// For more control over decoding, use the Stream type:
//
//	stream := rlp.NewStream(reader, 0)
//	value, err := stream.Uint64()
//
// # Error Handling
//
// The package defines several error types for invalid input:
//   - ErrExpectedString: Expected a string but got a list
//   - ErrExpectedList: Expected a list but got a string
//   - ErrCanonicalSize: Non-canonical size encoding
//   - ErrValueTooLarge: Value exceeds maximum size
//   - ErrMoreThanOneValue: Input contains multiple values
package rlp

// Version information
const (
	// PackageVersion is the version of the rlp package
	PackageVersion = "1.0.0"
)

// Exported functions from encode.go:
// - Encode(val any) ([]byte, error)
// - EncodeToBytes(val any) ([]byte, error)
// - EncodeToWriter(w io.Writer, val any) error

// Exported functions from decode.go:
// - Decode(data []byte, val any) error
// - DecodeBytes(data []byte, val any) error
// - NewStream(r io.Reader, inputLimit uint64) *Stream

// Exported interfaces:
// - Encoder: Custom encoding interface
// - Decoder: Custom decoding interface

// Exported types:
// - Stream: Streaming decoder for RLP data

// Exported errors:
// - ErrExpectedString
// - ErrExpectedList
// - ErrCanonicalSize
// - ErrValueTooLarge
// - ErrMoreThanOneValue
