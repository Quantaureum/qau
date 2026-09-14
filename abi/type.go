// Quantaureum Node source, version 1.0.0.
// Package abi implements the Ethereum ABI (Application Binary Interface) encoding and decoding.
package abi

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// Type enumerations for ABI types
const (
	IntTy byte = iota
	UintTy
	BoolTy
	StringTy
	SliceTy
	ArrayTy
	TupleTy
	AddressTy
	FixedBytesTy
	BytesTy
	HashTy
	FixedPointTy
	FunctionTy
)

// Type represents an ABI type with its properties
type Type struct {
	Elem *Type // For slices and arrays
	Size int   // Size in bits for int/uint, or length for fixed bytes/arrays
	T    byte  // Type enumeration

	stringKind string // String representation of the type

	// For tuple types
	TupleRawName  string
	TupleElems    []*Type
	TupleRawNames []string
}

// ABI type errors
var (
	ErrInvalidType       = errors.New("invalid type")
	ErrInvalidArraySize  = errors.New("invalid array size")
	ErrUnsupportedType   = errors.New("unsupported type")
	ErrInvalidTypeFormat = errors.New("invalid type format")
)

// NewType creates a new Type from a type string
func NewType(t string, internalType string, components []ArgumentMarshaling) (Type, error) {
	return newTypeWithDepth(t, internalType, components, 0)
}

// maxABITypeDepth bounds NewType recursion. ABI-03 FIX (deep-audit 2026-07-12):
// an untrusted ABI type string with deeply nested array suffixes ("uint" + many
// "[]") or nested tuple components could otherwise recurse until the goroutine
// stack overflows and the process crashes.
const maxABITypeDepth = 64

func newTypeWithDepth(t string, internalType string, components []ArgumentMarshaling, depth int) (Type, error) {
	if depth > maxABITypeDepth {
		return Type{}, fmt.Errorf("ABI type nesting too deep (> %d)", maxABITypeDepth)
	}
	// Handle array types
	if strings.HasSuffix(t, "[]") {
		// Dynamic array
		elemType, err := newTypeWithDepth(strings.TrimSuffix(t, "[]"), internalType, components, depth+1)
		if err != nil {
			return Type{}, err
		}
		return Type{
			Elem:       &elemType,
			T:          SliceTy,
			stringKind: t,
		}, nil
	}

	// Handle fixed-size arrays
	if idx := strings.LastIndex(t, "["); idx != -1 && strings.HasSuffix(t, "]") {
		sizeStr := t[idx+1 : len(t)-1]
		if sizeStr != "" {
			size, err := strconv.Atoi(sizeStr)
			if err != nil {
				return Type{}, fmt.Errorf("%w: %v", ErrInvalidArraySize, err)
			}
			if size <= 0 {
				return Type{}, ErrInvalidArraySize
			}
			elemType, err := newTypeWithDepth(t[:idx], internalType, components, depth+1)
			if err != nil {
				return Type{}, err
			}
			return Type{
				Elem:       &elemType,
				Size:       size,
				T:          ArrayTy,
				stringKind: t,
			}, nil
		}
	}

	// Handle tuple types
	if t == "tuple" {
		if len(components) == 0 {
			return Type{
				T:          TupleTy,
				stringKind: t,
			}, nil
		}
		elems := make([]*Type, len(components))
		names := make([]string, len(components))
		for i, comp := range components {
			elemType, err := newTypeWithDepth(comp.Type, comp.InternalType, comp.Components, depth+1)
			if err != nil {
				return Type{}, err
			}
			elems[i] = &elemType
			names[i] = comp.Name
		}
		return Type{
			T:             TupleTy,
			TupleElems:    elems,
			TupleRawNames: names,
			TupleRawName:  internalType,
			stringKind:    t,
		}, nil
	}

	// Parse basic types
	return parseBasicType(t)
}

// parseBasicType parses basic ABI types (int, uint, bool, address, bytes, string)
func parseBasicType(t string) (Type, error) {
	switch {
	case t == "bool":
		return Type{T: BoolTy, stringKind: t}, nil

	case t == "address":
		return Type{T: AddressTy, Size: 20, stringKind: t}, nil

	case t == "string":
		return Type{T: StringTy, stringKind: t}, nil

	case t == "bytes":
		return Type{T: BytesTy, stringKind: t}, nil

	case strings.HasPrefix(t, "bytes"):
		// Fixed bytes (bytes1 to bytes32)
		sizeStr := strings.TrimPrefix(t, "bytes")
		size, err := strconv.Atoi(sizeStr)
		if err != nil {
			return Type{}, fmt.Errorf("%w: invalid bytes size", ErrInvalidType)
		}
		if size < 1 || size > 32 {
			return Type{}, fmt.Errorf("%w: bytes size must be 1-32", ErrInvalidType)
		}
		return Type{T: FixedBytesTy, Size: size, stringKind: t}, nil

	case strings.HasPrefix(t, "uint"):
		sizeStr := strings.TrimPrefix(t, "uint")
		if sizeStr == "" {
			return Type{T: UintTy, Size: 256, stringKind: "uint256"}, nil
		}
		size, err := strconv.Atoi(sizeStr)
		if err != nil {
			return Type{}, fmt.Errorf("%w: invalid uint size", ErrInvalidType)
		}
		if size < 8 || size > 256 || size%8 != 0 {
			return Type{}, fmt.Errorf("%w: uint size must be 8-256 and multiple of 8", ErrInvalidType)
		}
		return Type{T: UintTy, Size: size, stringKind: t}, nil

	case strings.HasPrefix(t, "int"):
		sizeStr := strings.TrimPrefix(t, "int")
		if sizeStr == "" {
			return Type{T: IntTy, Size: 256, stringKind: "int256"}, nil
		}
		size, err := strconv.Atoi(sizeStr)
		if err != nil {
			return Type{}, fmt.Errorf("%w: invalid int size", ErrInvalidType)
		}
		if size < 8 || size > 256 || size%8 != 0 {
			return Type{}, fmt.Errorf("%w: int size must be 8-256 and multiple of 8", ErrInvalidType)
		}
		return Type{T: IntTy, Size: size, stringKind: t}, nil

	case t == "function":
		return Type{T: FunctionTy, Size: 24, stringKind: t}, nil

	default:
		return Type{}, fmt.Errorf("%w: %s", ErrUnsupportedType, t)
	}
}

// String returns the string representation of the type
func (t Type) String() string {
	return t.stringKind
}

// IsDynamic returns true if the type is dynamically sized
func (t Type) IsDynamic() bool {
	switch t.T {
	case StringTy, BytesTy, SliceTy:
		return true
	case ArrayTy:
		return t.Elem.IsDynamic()
	case TupleTy:
		for _, elem := range t.TupleElems {
			if elem.IsDynamic() {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// GetSize returns the size of the type in bytes for static types
// Returns 32 for dynamic types (pointer size)
func (t Type) GetSize() int {
	switch t.T {
	case IntTy, UintTy, BoolTy, AddressTy, FixedBytesTy, FunctionTy, HashTy:
		return 32 // All basic types are padded to 32 bytes
	case ArrayTy:
		if t.Elem.IsDynamic() {
			return 32 // Dynamic elements use pointer
		}
		return t.Size * t.Elem.GetSize()
	case TupleTy:
		size := 0
		for _, elem := range t.TupleElems {
			if elem.IsDynamic() {
				size += 32 // Pointer
			} else {
				size += elem.GetSize()
			}
		}
		return size
	default:
		return 32 // Dynamic types use pointer
	}
}

// RequireLength returns the required length for encoding
func (t Type) RequireLength() int {
	switch t.T {
	case SliceTy:
		return 32 // Length prefix
	case ArrayTy:
		return t.Size * t.Elem.RequireLength()
	case TupleTy:
		total := 0
		for _, elem := range t.TupleElems {
			total += elem.RequireLength()
		}
		return total
	default:
		return 32
	}
}

// ArgumentMarshaling is used for JSON marshaling of ABI arguments
type ArgumentMarshaling struct {
	Name         string               `json:"name"`
	Type         string               `json:"type"`
	InternalType string               `json:"internalType,omitempty"`
	Components   []ArgumentMarshaling `json:"components,omitempty"`
	Indexed      bool                 `json:"indexed,omitempty"`
}

// pack packs a value according to the type
func (t Type) pack(value any) ([]byte, error) {
	switch t.T {
	case UintTy:
		return packNum(value, t.Size, false)
	case IntTy:
		return packNum(value, t.Size, true)
	case BoolTy:
		return packBool(value)
	case AddressTy:
		return packAddress(value)
	case BytesTy:
		return packBytes(value)
	case StringTy:
		return packString(value)
	case FixedBytesTy:
		return packFixedBytes(value, t.Size)
	case SliceTy:
		return packSlice(value, t.Elem)
	case ArrayTy:
		return packArray(value, t.Elem, t.Size)
	case TupleTy:
		return packTuple(value, t.TupleElems)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedType, t.String())
	}
}

// unpack unpacks data according to the type
func (t Type) unpack(data []byte, offset int, ds *decodeState) (any, int, error) {
	switch t.T {
	case UintTy:
		return unpackNum(data, offset, t.Size, false)
	case IntTy:
		return unpackNum(data, offset, t.Size, true)
	case BoolTy:
		return unpackBool(data, offset)
	case AddressTy:
		return unpackAddress(data, offset)
	case BytesTy:
		return unpackBytes(data, offset, ds)
	case StringTy:
		return unpackString(data, offset, ds)
	case FixedBytesTy:
		return unpackFixedBytes(data, offset, t.Size, ds)
	case SliceTy:
		return unpackSlice(data, offset, t.Elem, ds)
	case ArrayTy:
		return unpackArray(data, offset, t.Elem, t.Size, ds)
	case TupleTy:
		return unpackTuple(data, offset, t.TupleElems, ds)
	default:
		return nil, 0, fmt.Errorf("%w: %s", ErrUnsupportedType, t.String())
	}
}

// Packing helper functions

func packNum(value any, size int, signed bool) ([]byte, error) {
	var bi *big.Int
	switch v := value.(type) {
	case *big.Int:
		bi = v
	case int64:
		bi = big.NewInt(v)
	case uint64:
		bi = new(big.Int).SetUint64(v)
	case int:
		bi = big.NewInt(int64(v))
	case uint:
		bi = new(big.Int).SetUint64(uint64(v))
	case int32:
		bi = big.NewInt(int64(v))
	case uint32:
		bi = new(big.Int).SetUint64(uint64(v))
	case int16:
		bi = big.NewInt(int64(v))
	case uint16:
		bi = new(big.Int).SetUint64(uint64(v))
	case int8:
		bi = big.NewInt(int64(v))
	case uint8:
		bi = new(big.Int).SetUint64(uint64(v))
	default:
		return nil, fmt.Errorf("cannot pack %T as number", value)
	}

	// Pad to 32 bytes
	result := make([]byte, 32)
	if signed && bi.Sign() < 0 {
		// Two's complement for negative numbers
		// Fill with 0xFF
		for i := range result {
			result[i] = 0xFF
		}
		// For negative numbers, we need to handle two's complement
		twosComp := new(big.Int).Add(bi, new(big.Int).Lsh(big.NewInt(1), uint(size))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		bytes := twosComp.Bytes()
		copy(result[32-len(bytes):], bytes)
	} else {
		bytes := bi.Bytes()
		copy(result[32-len(bytes):], bytes)
	}
	return result, nil
}

func packBool(value any) ([]byte, error) {
	b, ok := value.(bool)
	if !ok {
		return nil, fmt.Errorf("cannot pack %T as bool", value)
	}
	result := make([]byte, 32)
	if b {
		result[31] = 1
	}
	return result, nil
}

func packAddress(value any) ([]byte, error) {
	result := make([]byte, 32)
	switch v := value.(type) {
	case [20]byte:
		copy(result[12:], v[:])
	case []byte:
		if len(v) != 20 {
			return nil, fmt.Errorf("address must be 20 bytes, got %d", len(v))
		}
		copy(result[12:], v)
	case string:
		// Handle hex string
		addr := strings.TrimPrefix(v, "0x")
		if len(addr) != 40 {
			return nil, fmt.Errorf("invalid address string length")
		}
		bytes, err := hexDecode(addr)
		if err != nil {
			return nil, err
		}
		copy(result[12:], bytes)
	default:
		return nil, fmt.Errorf("cannot pack %T as address", value)
	}
	return result, nil
}

func packBytes(value any) ([]byte, error) {
	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return nil, fmt.Errorf("cannot pack %T as bytes", value)
	}

	// Length prefix + padded data
	length := len(data)
	paddedLen := ((length + 31) / 32) * 32
	result := make([]byte, 32+paddedLen)

	// Write length
	lengthBig := big.NewInt(int64(length))
	lengthBytes := lengthBig.Bytes()
	copy(result[32-len(lengthBytes):32], lengthBytes)

	// Write data
	copy(result[32:], data)
	return result, nil
}

func packString(value any) ([]byte, error) {
	s, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("cannot pack %T as string", value)
	}
	return packBytes([]byte(s))
}

func packFixedBytes(value any, size int) ([]byte, error) {
	result := make([]byte, 32)
	switch v := value.(type) {
	case []byte:
		if len(v) > size {
			return nil, fmt.Errorf("bytes too long: got %d, max %d", len(v), size)
		}
		copy(result[:], v)
	case [32]byte:
		copy(result[:], v[:size])
	default:
		return nil, fmt.Errorf("cannot pack %T as fixed bytes", value)
	}
	return result, nil
}

func packSlice(value any, elemType *Type) ([]byte, error) {
	// Get slice length and elements
	slice, err := toSlice(value)
	if err != nil {
		return nil, err
	}

	length := len(slice)

	// Pack length
	lengthBytes := make([]byte, 32)
	lengthBig := big.NewInt(int64(length))
	lb := lengthBig.Bytes()
	copy(lengthBytes[32-len(lb):], lb)

	// Pack elements
	elemData, err := packElements(slice, elemType)
	if err != nil {
		return nil, err
	}

	return append(lengthBytes, elemData...), nil
}

func packArray(value any, elemType *Type, size int) ([]byte, error) {
	slice, err := toSlice(value)
	if err != nil {
		return nil, err
	}

	if len(slice) != size {
		return nil, fmt.Errorf("array size mismatch: expected %d, got %d", size, len(slice))
	}

	return packElements(slice, elemType)
}

func packElements(slice []any, elemType *Type) ([]byte, error) {
	if elemType.IsDynamic() {
		// Dynamic elements: offsets + data
		var offsets []byte
		var data []byte
		baseOffset := len(slice) * 32

		for _, elem := range slice {
			// Write offset
			offsetBytes := make([]byte, 32)
			offset := big.NewInt(int64(baseOffset + len(data)))
			if offset.Cmp(maxABIOffset) > 0 {
				return nil, fmt.Errorf("ABI offset overflow: %s", offset.String())
			}
			ob := offset.Bytes()
			copy(offsetBytes[32-len(ob):], ob)
			offsets = append(offsets, offsetBytes...)

			// Pack element
			elemData, err := elemType.pack(elem)
			if err != nil {
				return nil, err
			}
			data = append(data, elemData...)
		}
		return append(offsets, data...), nil
	}

	// Static elements: just concatenate
	var result []byte
	for _, elem := range slice {
		elemData, err := elemType.pack(elem)
		if err != nil {
			return nil, err
		}
		result = append(result, elemData...)
	}
	return result, nil
}

func packTuple(value any, elems []*Type) ([]byte, error) {
	values, err := toSlice(value)
	if err != nil {
		return nil, err
	}

	if len(values) != len(elems) {
		return nil, fmt.Errorf("tuple size mismatch: expected %d, got %d", len(elems), len(values))
	}

	// Calculate head size
	headSize := 0
	for _, elem := range elems {
		if elem.IsDynamic() {
			headSize += 32 // Offset pointer
		} else {
			headSize += elem.GetSize()
		}
	}

	var head []byte
	var tail []byte

	for i, elem := range elems {
		if elem.IsDynamic() {
			// Write offset
			offsetBytes := make([]byte, 32)
			offset := big.NewInt(int64(headSize + len(tail)))
			if offset.Cmp(maxABIOffset) > 0 {
				return nil, fmt.Errorf("ABI offset overflow: %s", offset.String())
			}
			ob := offset.Bytes()
			copy(offsetBytes[32-len(ob):], ob)
			head = append(head, offsetBytes...)

			// Pack to tail
			data, err := elem.pack(values[i])
			if err != nil {
				return nil, err
			}
			tail = append(tail, data...)
		} else {
			// Pack directly to head
			data, err := elem.pack(values[i])
			if err != nil {
				return nil, err
			}
			head = append(head, data...)
		}
	}

	return append(head, tail...), nil
}

// Unpacking helper functions

func unpackNum(data []byte, offset int, size int, signed bool) (any, int, error) {
	if offset+32 > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for number at offset %d", offset)
	}

	bytes := data[offset : offset+32]
	bi := new(big.Int).SetBytes(bytes)

	if signed {
		// Check if negative (high bit set in the 256-bit representation)
		if bytes[0]&0x80 != 0 {
			// Two's complement: subtract 2^256 to get the negative value
			maxVal := new(big.Int).Lsh(big.NewInt(1), 256)
			bi.Sub(bi, maxVal)
		}
	}

	return bi, 32, nil
}

func unpackBool(data []byte, offset int) (any, int, error) {
	if offset+32 > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for bool at offset %d", offset)
	}

	// Check last byte
	return data[offset+31] != 0, 32, nil
}

func unpackAddress(data []byte, offset int) (any, int, error) {
	if offset+32 > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for address at offset %d", offset)
	}

	var addr [20]byte
	copy(addr[:], data[offset+12:offset+32])
	return addr, 32, nil
}

func unpackBytes(data []byte, offset int, ds *decodeState) (any, int, error) {
	if offset+32 > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for bytes length at offset %d", offset)
	}

	// Read length
	// audit-fix R4-M1: validate length fits in int and is non-negative to prevent panic on make()
	lengthBig := new(big.Int).SetBytes(data[offset : offset+32])
	if !lengthBig.IsInt64() || lengthBig.Int64() < 0 || lengthBig.Int64() > math.MaxInt32 {
		return nil, 0, fmt.Errorf("bytes length overflow: %s", lengthBig.String())
	}
	length := int(lengthBig.Int64())

	if offset+32+length > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for bytes content")
	}

	// SECURITY (audit DATA-03): Charge allocation against the total decode
	// memory budget. Overlapping offsets would cause the same bytes to be
	// allocated multiple times, exhausting the budget and failing the decode.
	if err := ds.alloc(length); err != nil {
		return nil, 0, err
	}

	result := make([]byte, length)
	copy(result, data[offset+32:offset+32+length])

	// Calculate total consumed (length word + padded data)
	paddedLen := ((length + 31) / 32) * 32
	return result, 32 + paddedLen, nil
}

func unpackString(data []byte, offset int, ds *decodeState) (any, int, error) {
	bytes, consumed, err := unpackBytes(data, offset, ds)
	if err != nil {
		return nil, 0, err
	}
	return string(bytes.([]byte)), consumed, nil //nolint:errcheck
}

func unpackFixedBytes(data []byte, offset int, size int, ds *decodeState) (any, int, error) {
	if offset+32 > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for fixed bytes at offset %d", offset)
	}

	// SECURITY (audit DATA-03): Charge allocation against the budget.
	if err := ds.alloc(size); err != nil {
		return nil, 0, err
	}

	result := make([]byte, size)
	copy(result, data[offset:offset+size])
	return result, 32, nil
}

func unpackSlice(data []byte, offset int, elemType *Type, ds *decodeState) (any, int, error) {
	if offset+32 > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for slice length at offset %d", offset)
	}

	// Read length
	// audit-fix R4-M1: validate length fits in int and is non-negative to prevent panic on make()
	lengthBig := new(big.Int).SetBytes(data[offset : offset+32])
	if !lengthBig.IsInt64() || lengthBig.Int64() < 0 || lengthBig.Int64() > math.MaxInt32 {
		return nil, 0, fmt.Errorf("slice length overflow: %s", lengthBig.String())
	}
	length := int(lengthBig.Int64())

	// ABI-01 FIX (deep-audit 2026-07-12): bound length by the remaining
	// decodable capacity before allocating. Each element consumes at least 32
	// bytes (a dynamic element's head offset, or a static element's minimum
	// encoding), so a length larger than remaining/32 cannot be real. The old
	// code allocated make([]any, length) for any length up to MaxInt32 (~34GB)
	// from a crafted length prefix — OOM. unpackBytes already does this check.
	if remaining := len(data) - (offset + 32); length > remaining/32 {
		return nil, 0, fmt.Errorf("slice length %d exceeds available data (%d bytes)", length, remaining)
	}

	// SECURITY (audit DATA-03): Charge the result slice allocation and check
	// element count before allocating. Overlapping offsets in nested dynamic
	// types would cause the same data to be decoded multiple times, and each
	// decode would charge against this budget.
	if err := ds.alloc(length * 16); err != nil { // 16 bytes ≈ sizeof(any) on 64-bit
		return nil, 0, err
	}
	if err := ds.elem(); err != nil { // charge for the slice itself
		return nil, 0, err
	}

	// Unpack elements
	result := make([]any, length)
	currentOffset := offset + 32

	if elemType.IsDynamic() {
		// audit-fix R10-1: validate offsets before use to prevent negative index panic.
		offsets := make([]int, length)
		for i := 0; i < length; i++ {
			o, err := safeABIOffset(data, currentOffset)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid slice element %d offset: %w", i, err)
			}
			offsets[i] = o
			currentOffset += 32
		}

		// Unpack elements at offsets
		for i := 0; i < length; i++ {
			elemOffset := offset + 32 + offsets[i]
			elem, _, err := elemType.unpack(data, elemOffset, ds)
			if err != nil {
				return nil, 0, err
			}
			result[i] = elem
		}
	} else {
		// Static elements
		for i := 0; i < length; i++ {
			if err := ds.elem(); err != nil {
				return nil, 0, err
			}
			elem, consumed, err := elemType.unpack(data, currentOffset, ds)
			if err != nil {
				return nil, 0, err
			}
			result[i] = elem
			currentOffset += consumed
		}
	}

	return result, currentOffset - offset, nil
}

func unpackArray(data []byte, offset int, elemType *Type, size int, ds *decodeState) (any, int, error) {
	// ABI-02 FIX (deep-audit 2026-07-12): bound size by the remaining decodable
	// capacity before allocating. size comes from the ABI type string (e.g.
	// uint256[999999999]); an untrusted ABI could otherwise force a multi-GB
	// make([]any, size). Each element consumes at least 32 bytes.
	if size < 0 {
		return nil, 0, fmt.Errorf("invalid negative array size %d", size)
	}
	if offset < 0 || offset > len(data) {
		return nil, 0, fmt.Errorf("array offset %d out of range", offset)
	}
	if remaining := len(data) - offset; size > remaining/32 {
		return nil, 0, fmt.Errorf("array size %d exceeds available data (%d bytes)", size, remaining)
	}

	// SECURITY (audit DATA-03): Charge the result array allocation and element
	// count against the decode budget.
	if err := ds.alloc(size * 16); err != nil { // 16 bytes ≈ sizeof(any) on 64-bit
		return nil, 0, err
	}
	if err := ds.elem(); err != nil { // charge for the array itself
		return nil, 0, err
	}

	result := make([]any, size)
	currentOffset := offset

	if elemType.IsDynamic() {
		// audit-fix R10-1: validate offsets before use to prevent negative index panic.
		offsets := make([]int, size)
		for i := 0; i < size; i++ {
			o, err := safeABIOffset(data, currentOffset)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid array element %d offset: %w", i, err)
			}
			offsets[i] = o
			currentOffset += 32
		}

		// Unpack elements at offsets
		for i := 0; i < size; i++ {
			elemOffset := offset + offsets[i]
			elem, _, err := elemType.unpack(data, elemOffset, ds)
			if err != nil {
				return nil, 0, err
			}
			result[i] = elem
		}
	} else {
		// Static elements
		for i := 0; i < size; i++ {
			if err := ds.elem(); err != nil {
				return nil, 0, err
			}
			elem, consumed, err := elemType.unpack(data, currentOffset, ds)
			if err != nil {
				return nil, 0, err
			}
			result[i] = elem
			currentOffset += consumed
		}
	}

	return result, currentOffset - offset, nil
}

func unpackTuple(data []byte, offset int, elems []*Type, ds *decodeState) (any, int, error) {
	// SECURITY (audit DATA-03): Charge the result tuple allocation.
	if err := ds.alloc(len(elems) * 16); err != nil { // 16 bytes ≈ sizeof(any) on 64-bit
		return nil, 0, err
	}
	if err := ds.elem(); err != nil { // charge for the tuple itself
		return nil, 0, err
	}

	result := make([]any, len(elems))
	currentOffset := offset

	// First pass: read static values and offsets for dynamic values
	// audit-fix R10-1: validate offsets before use to prevent negative index panic.
	dynamicOffsets := make([]int, len(elems))
	for i, elem := range elems {
		if elem.IsDynamic() {
			o, err := safeABIOffset(data, currentOffset)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid tuple element %d offset: %w", i, err)
			}
			dynamicOffsets[i] = o
			currentOffset += 32
		} else {
			val, consumed, err := elem.unpack(data, currentOffset, ds)
			if err != nil {
				return nil, 0, err
			}
			result[i] = val
			currentOffset += consumed
		}
	}

	// Second pass: read dynamic values
	for i, elem := range elems {
		if elem.IsDynamic() {
			elemOffset := offset + dynamicOffsets[i]
			val, _, err := elem.unpack(data, elemOffset, ds)
			if err != nil {
				return nil, 0, err
			}
			result[i] = val
		}
	}

	return result, currentOffset - offset, nil
}

// Helper functions

func toSlice(value any) ([]any, error) {
	switch v := value.(type) {
	case []any:
		return v, nil
	case []string:
		result := make([]any, len(v))
		for i, s := range v {
			result[i] = s
		}
		return result, nil
	case [][]byte:
		result := make([]any, len(v))
		for i, b := range v {
			result[i] = b
		}
		return result, nil
	case []*big.Int:
		result := make([]any, len(v))
		for i, b := range v {
			result[i] = b
		}
		return result, nil
	case []uint64:
		result := make([]any, len(v))
		for i, n := range v {
			result[i] = n
		}
		return result, nil
	case []int64:
		result := make([]any, len(v))
		for i, n := range v {
			result[i] = n
		}
		return result, nil
	case []bool:
		result := make([]any, len(v))
		for i, b := range v {
			result[i] = b
		}
		return result, nil
	case [][20]byte:
		result := make([]any, len(v))
		for i, a := range v {
			result[i] = a
		}
		return result, nil
	default:
		return nil, fmt.Errorf("cannot convert %T to slice", value)
	}
}

// audit-fix R10-1: safeABIOffset extracts a uint256 ABI offset, validates it is
// representable as a non-negative int, and is within data bounds. Without this,
// a crafted 256-bit value > MaxInt64 wraps to a negative int via Int64(),
// causing a panic on negative slice index.
func safeABIOffset(data []byte, pos int) (int, error) {
	if pos+32 > len(data) {
		return 0, fmt.Errorf("insufficient data for ABI offset at position %d", pos)
	}
	offBig := new(big.Int).SetBytes(data[pos : pos+32])
	if !offBig.IsInt64() || offBig.Sign() < 0 {
		return 0, fmt.Errorf("ABI offset overflow: %s", offBig.String())
	}
	o := int(offBig.Int64())
	if o > len(data) {
		return 0, fmt.Errorf("ABI offset %d exceeds data length %d", o, len(data))
	}
	return o, nil
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex string has odd length")
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		result[i/2] = byte(b)
	}
	return result, nil
}
