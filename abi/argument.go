// Quantaureum Node source, version 1.0.0.
package abi

// L14-041 SECURITY NOTE: Type conversion in ABI encoding/decoding must
// be performed carefully to prevent integer overflow and truncation.
// When converting between Go types (e.g., uint64 to *big.Int), the
// conversion must check that the source value fits within the target
// type's range. ABI decoding from untrusted input must validate all
// length prefixes and offset values to prevent out-of-bounds reads.
// The ABI specification uses 256-bit integers as the native word size,
// which exceeds Go's uint64 -- always use *big.Int for ABI integer types.

import (
	"fmt"
	"math/big"
	"reflect"
)

// Argument represents a single ABI argument
type Argument struct {
	Name    string
	Type    Type
	Indexed bool // For event arguments
}

// maxABIOffset is the maximum allowed offset in ABI encoding.
// L12-035 FIX: Prevents offset overflow in Pack/packElements/packTuple.
var maxABIOffset = big.NewInt(1 << 32)

// SECURITY (audit DATA-03): Total decode budget to prevent "decode bomb" from
// overlapping offsets or deeply nested dynamic types. When multiple dynamic
// arguments point to the same region (overlap), the same bytes are decoded
// multiple times. With nested dynamic types (e.g. bytes[][][]), this creates
// exponential work from a small input. The budget caps total allocated bytes
// and total decoded elements across one Unpack call, causing the decode to
// fail before resources are exhausted.
const (
	// maxABIDecodeMemory is the total allocation budget for a single Unpack
	// call. 32 MB matches the rlp package's maxTotalDecodeMemory.
	maxABIDecodeMemory = 32 * 1024 * 1024
	// maxABIDecodeElements caps the total number of elements decoded across
	// all nested slices/arrays/tuples. Prevents excessive element creation
	// from crafted nested payloads.
	maxABIDecodeElements = 1 << 20 // 1M elements
)

// decodeState tracks resource consumption during a single Unpack call.
// SECURITY (audit DATA-03): Without this, overlapping dynamic offsets or
// deeply nested dynamic types can cause exponential decode work (decode bomb).
type decodeState struct {
	totalAllocated int // cumulative bytes allocated across all unpack calls
	totalElements  int // cumulative elements decoded across all nested types
}

// alloc charges n bytes against the memory budget. Returns an error if the
// budget would be exceeded.
func (ds *decodeState) alloc(n int) error {
	if n < 0 {
		return fmt.Errorf("ABI decode: negative allocation %d", n)
	}
	if ds.totalAllocated+n > maxABIDecodeMemory {
		return fmt.Errorf("ABI decode memory budget exceeded: %d > %d", ds.totalAllocated+n, maxABIDecodeMemory)
	}
	ds.totalAllocated += n
	return nil
}

// elem charges one decoded element against the element count limit.
func (ds *decodeState) elem() error {
	ds.totalElements++
	if ds.totalElements > maxABIDecodeElements {
		return fmt.Errorf("ABI decode element count exceeded: %d > %d", ds.totalElements, maxABIDecodeElements)
	}
	return nil
}

// Arguments is a slice of Argument
type Arguments []Argument

// Pack packs the given values according to the argument types
func (args Arguments) Pack(values ...any) ([]byte, error) {
	if len(values) != len(args) {
		return nil, fmt.Errorf("argument count mismatch: expected %d, got %d", len(args), len(values))
	}

	// Calculate head size (static parts + offsets for dynamic parts)
	headSize := 0
	for _, arg := range args {
		if arg.Type.IsDynamic() {
			headSize += 32 // Offset pointer
		} else {
			headSize += arg.Type.GetSize()
		}
	}

	var head []byte
	var tail []byte

	for i, arg := range args {
		if arg.Type.IsDynamic() {
			// Write offset to head
			offsetBytes := make([]byte, 32)
			offset := big.NewInt(int64(headSize + len(tail)))
			if offset.Cmp(maxABIOffset) > 0 {
				return nil, fmt.Errorf("ABI offset overflow: %s", offset.String())
			}
			ob := offset.Bytes()
			copy(offsetBytes[32-len(ob):], ob)
			head = append(head, offsetBytes...)

			// Pack value to tail
			packed, err := arg.Type.pack(values[i])
			if err != nil {
				return nil, fmt.Errorf("failed to pack argument %d (%s): %w", i, arg.Name, err)
			}
			tail = append(tail, packed...)
		} else {
			// Pack directly to head
			packed, err := arg.Type.pack(values[i])
			if err != nil {
				return nil, fmt.Errorf("failed to pack argument %d (%s): %w", i, arg.Name, err)
			}
			head = append(head, packed...)
		}
	}

	return append(head, tail...), nil
}

// Unpack unpacks the given data according to the argument types
func (args Arguments) Unpack(data []byte) ([]any, error) {
	if len(data) == 0 {
		if len(args) == 0 {
			return []any{}, nil
		}
		return nil, fmt.Errorf("empty data for %d arguments", len(args))
	}

	// SECURITY (audit DATA-03): Track total decode resources to prevent
	// "decode bomb" from overlapping offsets or nested dynamic types.
	ds := &decodeState{}

	result := make([]any, len(args))
	offset := 0

	// First pass: read static values and offsets for dynamic values
	// audit-fix R10-1: validate offsets before use to prevent negative index panic.
	dynamicOffsets := make([]int, len(args))
	for i, arg := range args {
		if arg.Type.IsDynamic() {
			o, err := safeABIOffset(data, offset)
			if err != nil {
				return nil, fmt.Errorf("invalid argument %d offset: %w", i, err)
			}
			dynamicOffsets[i] = o
			offset += 32
		} else {
			val, consumed, err := arg.Type.unpack(data, offset, ds)
			if err != nil {
				return nil, fmt.Errorf("failed to unpack argument %d (%s): %w", i, arg.Name, err)
			}
			result[i] = val
			offset += consumed
		}
	}

	// Second pass: read dynamic values
	for i, arg := range args {
		if arg.Type.IsDynamic() {
			val, _, err := arg.Type.unpack(data, dynamicOffsets[i], ds)
			if err != nil {
				return nil, fmt.Errorf("failed to unpack dynamic argument %d (%s): %w", i, arg.Name, err)
			}
			result[i] = val
		}
	}

	return result, nil
}

// UnpackIntoInterface unpacks data into the provided interface
func (args Arguments) UnpackIntoInterface(v any, data []byte) error {
	values, err := args.Unpack(data)
	if err != nil {
		return err
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return fmt.Errorf("v must be a pointer")
	}
	rv = rv.Elem()

	switch rv.Kind() {
	case reflect.Struct:
		return args.unpackIntoStruct(rv, values)
	case reflect.Slice:
		return args.unpackIntoSlice(rv, values)
	case reflect.Interface:
		rv.Set(reflect.ValueOf(values))
		return nil
	default:
		if len(values) == 1 {
			return setSingleValue(rv, values[0])
		}
		return fmt.Errorf("cannot unpack %d values into %s", len(values), rv.Kind())
	}
}

func (args Arguments) unpackIntoStruct(rv reflect.Value, values []any) error {
	if rv.NumField() < len(values) {
		return fmt.Errorf("struct has %d fields, but %d values to unpack", rv.NumField(), len(values))
	}

	for i, val := range values {
		field := rv.Field(i)
		if !field.CanSet() {
			continue
		}
		if err := setSingleValue(field, val); err != nil {
			return fmt.Errorf("failed to set field %d: %w", i, err)
		}
	}
	return nil
}

func (args Arguments) unpackIntoSlice(rv reflect.Value, values []any) error {
	if rv.Cap() < len(values) {
		rv.Set(reflect.MakeSlice(rv.Type(), len(values), len(values)))
	} else {
		rv.SetLen(len(values))
	}

	for i, val := range values {
		if err := setSingleValue(rv.Index(i), val); err != nil {
			return fmt.Errorf("failed to set element %d: %w", i, err)
		}
	}
	return nil
}

func setSingleValue(rv reflect.Value, val any) error {
	if val == nil {
		return nil
	}

	valRv := reflect.ValueOf(val)

	// Handle *big.Int specially
	if bi, ok := val.(*big.Int); ok {
		switch rv.Kind() {
		case reflect.Ptr:
			if rv.Type() == reflect.TypeOf((*big.Int)(nil)) {
				rv.Set(reflect.ValueOf(bi))
				return nil
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			// L11-037 (P3): Guard against silent overflow when narrowing a
			// *big.Int to a fixed-size signed integer. bi.Int64() returns only
			// the low 64 bits when the value exceeds int64 range, and SetInt on
			// a narrower type (int8/16/32) would silently wrap. Reject values
			// that do not fit instead of producing a corrupted result.
			if !bi.IsInt64() {
				return fmt.Errorf("value %s overflows int64", bi.String())
			}
			v := bi.Int64()
			if rv.OverflowInt(v) {
				return fmt.Errorf("value %s overflows %s", bi.String(), rv.Kind())
			}
			rv.SetInt(v)
			return nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			// L12-022 FIX: Guard against silent overflow when narrowing a
			// *big.Int to a fixed-size unsigned integer. bi.Uint64() panics
			// or returns undefined values when the value exceeds uint64 range.
			if !bi.IsUint64() {
				return fmt.Errorf("value %s overflows uint64", bi.String())
			}
			v := bi.Uint64()
			if rv.OverflowUint(v) {
				return fmt.Errorf("value %s overflows %s", bi.String(), rv.Kind())
			}
			rv.SetUint(v)
			return nil
		case reflect.Interface:
			rv.Set(reflect.ValueOf(bi))
			return nil
		}
	}

	// Handle []any for tuples/arrays
	if slice, ok := val.([]any); ok {
		switch rv.Kind() {
		case reflect.Slice:
			return setSliceValue(rv, slice)
		case reflect.Array:
			return setArrayValue(rv, slice)
		case reflect.Struct:
			return setStructValue(rv, slice)
		case reflect.Interface:
			rv.Set(reflect.ValueOf(slice))
			return nil
		}
	}

	// Handle [20]byte for addresses
	if addr, ok := val.([20]byte); ok {
		switch rv.Kind() {
		case reflect.Array:
			if rv.Len() == 20 && rv.Type().Elem().Kind() == reflect.Uint8 {
				for i := 0; i < 20; i++ {
					rv.Index(i).SetUint(uint64(addr[i]))
				}
				return nil
			}
		case reflect.Slice:
			rv.SetBytes(addr[:])
			return nil
		case reflect.Interface:
			rv.Set(reflect.ValueOf(addr))
			return nil
		}
	}

	// Handle []byte
	if bytes, ok := val.([]byte); ok {
		switch rv.Kind() {
		case reflect.Slice:
			if rv.Type().Elem().Kind() == reflect.Uint8 {
				rv.SetBytes(bytes)
				return nil
			}
		case reflect.Array:
			if rv.Type().Elem().Kind() == reflect.Uint8 {
				for i := 0; i < len(bytes) && i < rv.Len(); i++ {
					rv.Index(i).SetUint(uint64(bytes[i]))
				}
				return nil
			}
		case reflect.Interface:
			rv.Set(reflect.ValueOf(bytes))
			return nil
		}
	}

	// Handle string
	if s, ok := val.(string); ok {
		switch rv.Kind() {
		case reflect.String:
			rv.SetString(s)
			return nil
		case reflect.Interface:
			rv.Set(reflect.ValueOf(s))
			return nil
		}
	}

	// Handle bool
	if b, ok := val.(bool); ok {
		switch rv.Kind() {
		case reflect.Bool:
			rv.SetBool(b)
			return nil
		case reflect.Interface:
			rv.Set(reflect.ValueOf(b))
			return nil
		}
	}

	// Try direct assignment if types are compatible
	if valRv.Type().AssignableTo(rv.Type()) {
		rv.Set(valRv)
		return nil
	}

	// Try conversion
	if valRv.Type().ConvertibleTo(rv.Type()) {
		rv.Set(valRv.Convert(rv.Type()))
		return nil
	}

	return fmt.Errorf("cannot assign %T to %s", val, rv.Type())
}

func setSliceValue(rv reflect.Value, slice []any) error {
	elemType := rv.Type().Elem()
	newSlice := reflect.MakeSlice(rv.Type(), len(slice), len(slice))
	for i, elem := range slice {
		elemRv := reflect.New(elemType).Elem()
		if err := setSingleValue(elemRv, elem); err != nil {
			return err
		}
		newSlice.Index(i).Set(elemRv)
	}
	rv.Set(newSlice)
	return nil
}

func setArrayValue(rv reflect.Value, slice []any) error {
	if rv.Len() != len(slice) {
		return fmt.Errorf("array length mismatch: expected %d, got %d", rv.Len(), len(slice))
	}
	for i, elem := range slice {
		if err := setSingleValue(rv.Index(i), elem); err != nil {
			return err
		}
	}
	return nil
}

func setStructValue(rv reflect.Value, slice []any) error {
	if rv.NumField() < len(slice) {
		return fmt.Errorf("struct has %d fields, but %d values", rv.NumField(), len(slice))
	}
	for i, elem := range slice {
		field := rv.Field(i)
		if !field.CanSet() {
			continue
		}
		if err := setSingleValue(field, elem); err != nil {
			return err
		}
	}
	return nil
}

// NonIndexed returns arguments that are not indexed (for event data)
func (args Arguments) NonIndexed() Arguments {
	var result Arguments
	for _, arg := range args {
		if !arg.Indexed {
			result = append(result, arg)
		}
	}
	return result
}

// Indexed returns arguments that are indexed (for event topics)
func (args Arguments) Indexed() Arguments {
	var result Arguments
	for _, arg := range args {
		if arg.Indexed {
			result = append(result, arg)
		}
	}
	return result
}
