// Quantaureum Node source, version 1.0.0.
// Package rlp implements the RLP (Recursive Length Prefix) serialization format.
// RLP is the main encoding method used to serialize objects in Ethereum.
package rlp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
)

var (
	// ErrNegativeBigInt is returned when trying to encode a negative big.Int
	ErrNegativeBigInt = errors.New("rlp: cannot encode negative big.Int")
	// ErrUnsupportedType is returned when trying to encode an unsupported type
	ErrUnsupportedType = errors.New("rlp: unsupported type")
)

// Encoder is implemented by types that require custom RLP encoding rules.
type Encoder interface {
	EncodeRLP(w io.Writer) error
}

// Encode writes the RLP encoding of val to w.
func Encode(w io.Writer, val any) error {
	b, err := EncodeToBytes(val)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// EncodeToBytes returns the RLP encoding of val.
func EncodeToBytes(val any) ([]byte, error) {
	return encodeValue(reflect.ValueOf(val))
}

// EncodeToReader returns a reader from which the RLP encoding of val can be read.
func EncodeToReader(val any) (size int, r io.Reader, err error) {
	b, err := EncodeToBytes(val)
	if err != nil {
		return 0, nil, err
	}
	return len(b), bytes.NewReader(b), nil
}

func encodeValue(val reflect.Value) ([]byte, error) {
	// Handle invalid value
	if !val.IsValid() {
		return []byte{0x80}, nil // empty string
	}

	// Handle pointer and interface types
	for val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return []byte{0x80}, nil // empty string
		}
		val = val.Elem()
	}

	// Check for Encoder interface
	if val.CanAddr() {
		if enc, ok := val.Addr().Interface().(Encoder); ok {
			var buf bytes.Buffer
			if err := enc.EncodeRLP(&buf); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		}
	}
	if val.CanInterface() {
		if enc, ok := val.Interface().(Encoder); ok {
			var buf bytes.Buffer
			if err := enc.EncodeRLP(&buf); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		}
	}

	switch val.Kind() {
	case reflect.Bool:
		return encodeBool(val.Bool()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return encodeInt(val.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return encodeUint(val.Uint()), nil
	case reflect.String:
		return encodeString(val.String()), nil
	case reflect.Slice:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			return encodeBytes(val.Bytes()), nil
		}
		return encodeSlice(val)
	case reflect.Array:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			// Byte array - encode as string
			b := make([]byte, val.Len())
			for i := 0; i < val.Len(); i++ {
				b[i] = byte(val.Index(i).Uint()) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
			}
			return encodeBytes(b), nil
		}
		return encodeArray(val)
	case reflect.Struct:
		// Check for big.Int
		if val.Type() == reflect.TypeOf(big.Int{}) {
			return encodeBigInt(val.Addr().Interface().(*big.Int)) //nolint:errcheck
		}
		return encodeStruct(val)
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedType, val.Type())
	}
}

func encodeBool(b bool) []byte {
	if b {
		return []byte{0x01}
	}
	return []byte{0x80}
}

func encodeInt(i int64) ([]byte, error) {
	if i < 0 {
		return nil, fmt.Errorf("rlp: cannot encode negative integer: %d", i)
	}
	return encodeUint(uint64(i)), nil
}

func encodeUint(i uint64) []byte {
	if i == 0 {
		return []byte{0x80}
	}
	if i < 128 {
		return []byte{byte(i)}
	}
	// Encode as big-endian bytes
	b := make([]byte, 8)
	size := putint(b, i)
	return encodeBytes(b[:size])
}

func encodeString(s string) []byte {
	return encodeBytes([]byte(s))
}

func encodeBytes(b []byte) []byte {
	if len(b) == 0 {
		return []byte{0x80}
	}
	if len(b) == 1 && b[0] < 128 {
		return []byte{b[0]}
	}
	return append(encodeStringHeader(len(b)), b...)
}

func encodeStringHeader(size int) []byte {
	if size < 56 {
		return []byte{0x80 + byte(size)} // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	}
	sizeBytes := putintBytes(uint64(size))
	return append([]byte{0xB7 + byte(len(sizeBytes))}, sizeBytes...) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

func encodeBigInt(i *big.Int) ([]byte, error) {
	if i == nil || i.Sign() == 0 {
		return []byte{0x80}, nil
	}
	if i.Sign() < 0 {
		return nil, ErrNegativeBigInt
	}
	return encodeBytes(i.Bytes()), nil
}

func encodeSlice(val reflect.Value) ([]byte, error) {
	return encodeList(val.Len(), func(i int) ([]byte, error) {
		return encodeValue(val.Index(i))
	})
}

func encodeArray(val reflect.Value) ([]byte, error) {
	return encodeList(val.Len(), func(i int) ([]byte, error) {
		return encodeValue(val.Index(i))
	})
}

func encodeStruct(val reflect.Value) ([]byte, error) {
	t := val.Type()
	var fields []int
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).PkgPath == "" { // exported field
			fields = append(fields, i)
		}
	}

	return encodeList(len(fields), func(idx int) ([]byte, error) {
		return encodeValue(val.Field(fields[idx]))
	})
}

func encodeList(length int, encodeElement func(int) ([]byte, error)) ([]byte, error) {
	// Encode all elements first
	var content []byte
	for i := 0; i < length; i++ {
		elem, err := encodeElement(i)
		if err != nil {
			return nil, err
		}
		content = append(content, elem...)
	}

	// Add list header
	return append(encodeListHeader(len(content)), content...), nil
}

func encodeListHeader(size int) []byte {
	if size < 56 {
		return []byte{0xC0 + byte(size)} // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	}
	sizeBytes := putintBytes(uint64(size))
	return append([]byte{0xF7 + byte(len(sizeBytes))}, sizeBytes...) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

// putint writes i to the beginning of b in big endian byte order,
// using the least number of bytes needed to represent i.
func putint(b []byte, i uint64) (size int) {
	switch {
	case i < (1 << 8):
		b[0] = byte(i)
		return 1
	case i < (1 << 16):
		b[0] = byte(i >> 8)
		b[1] = byte(i) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		return 2
	case i < (1 << 24):
		b[0] = byte(i >> 16)
		b[1] = byte(i >> 8) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[2] = byte(i)      // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		return 3
	case i < (1 << 32):
		b[0] = byte(i >> 24)
		b[1] = byte(i >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[2] = byte(i >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[3] = byte(i)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		return 4
	case i < (1 << 40):
		b[0] = byte(i >> 32)
		b[1] = byte(i >> 24) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[2] = byte(i >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[3] = byte(i >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[4] = byte(i)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		return 5
	case i < (1 << 48):
		b[0] = byte(i >> 40)
		b[1] = byte(i >> 32) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[2] = byte(i >> 24) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[3] = byte(i >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[4] = byte(i >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[5] = byte(i)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		return 6
	case i < (1 << 56):
		b[0] = byte(i >> 48)
		b[1] = byte(i >> 40) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[2] = byte(i >> 32) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[3] = byte(i >> 24) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[4] = byte(i >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[5] = byte(i >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[6] = byte(i)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		return 7
	default:
		b[0] = byte(i >> 56)
		b[1] = byte(i >> 48) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[2] = byte(i >> 40) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[3] = byte(i >> 32) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[4] = byte(i >> 24) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[5] = byte(i >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[6] = byte(i >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		b[7] = byte(i)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		return 8
	}
}

func putintBytes(i uint64) []byte {
	b := make([]byte, 8)
	size := putint(b, i)
	return b[:size]
}

func intsize(i uint64) int {
	switch {
	case i < (1 << 8):
		return 1
	case i < (1 << 16):
		return 2
	case i < (1 << 24):
		return 3
	case i < (1 << 32):
		return 4
	case i < (1 << 40):
		return 5
	case i < (1 << 48):
		return 6
	case i < (1 << 56):
		return 7
	default:
		return 8
	}
}

func headsize(size uint64) int {
	if size < 56 {
		return 1
	}
	return 1 + intsize(size)
}

// ListSize returns the encoded size of an RLP list with the given content size.
func ListSize(contentSize uint64) uint64 {
	// Safe: headsize returns small values (1-9)
	return uint64(headsize(contentSize)) + contentSize // #nosec G115 - headsize returns small positive int
}

// StringSize returns the encoded size of a string.
func StringSize(b []byte) uint64 {
	switch {
	case len(b) == 0:
		return 1
	case len(b) == 1 && b[0] < 128:
		return 1
	case len(b) < 56:
		// Safe: len(b) < 56, so 1 + len(b) < 57, fits in uint64
		return uint64(1 + len(b)) // #nosec G115 - len(b) is bounded
	default:
		// Safe: len(b) is always non-negative, intsize returns small values
		return uint64(1 + intsize(uint64(len(b))) + len(b)) // #nosec G115 - len is non-negative
	}
}

// IntSize returns the encoded size of an unsigned integer.
func IntSize(i uint64) int {
	if i < 128 {
		return 1
	}
	return 1 + intsize(i)
}
