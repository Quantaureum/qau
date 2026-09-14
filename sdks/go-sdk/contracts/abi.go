// Quantaureum Go SDK source, version 1.0.0.
// Package contracts provides smart contract interaction functionality for the Quantaureum Go SDK.
package contracts

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
	"github.com/quantaureum/qau/sdks/go-sdk/utils"
)

// Type represents an ABI type.
type Type struct {
	Elem *Type  // For arrays and slices
	Size int    // For fixed-size arrays and fixed bytes
	T    string // Type name (e.g., "uint256", "address", "bytes32")
}

// Argument represents a function argument or return value.
type Argument struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Indexed bool   `json:"indexed,omitempty"` // For event parameters
}

// Method represents a contract method (function).
type Method struct {
	Name            string     `json:"name"`
	Type            string     `json:"type"` // "function", "constructor", "fallback", "receive"
	Inputs          []Argument `json:"inputs"`
	Outputs         []Argument `json:"outputs,omitempty"`
	StateMutability string     `json:"stateMutability,omitempty"` // "pure", "view", "nonpayable", "payable"
	Constant        bool       `json:"constant,omitempty"`        // Deprecated, use stateMutability
	Payable         bool       `json:"payable,omitempty"`         // Deprecated, use stateMutability
}

// Event represents a contract event.
type Event struct {
	Name      string     `json:"name"`
	Type      string     `json:"type"` // Always "event"
	Inputs    []Argument `json:"inputs"`
	Anonymous bool       `json:"anonymous,omitempty"`
}

// ABI represents a contract's Application Binary Interface.
type ABI struct {
	Constructor Method
	Methods     map[string]Method
	Events      map[string]Event
	Fallback    *Method
	Receive     *Method
}

// JSON parses an ABI from a JSON string.
func JSON(reader string) (ABI, error) {
	return ParseABI([]byte(reader))
}

// ParseABI parses an ABI from JSON bytes.
func ParseABI(data []byte) (ABI, error) {
	var fields []struct {
		Type            string     `json:"type"`
		Name            string     `json:"name"`
		Inputs          []Argument `json:"inputs"`
		Outputs         []Argument `json:"outputs"`
		StateMutability string     `json:"stateMutability"`
		Constant        bool       `json:"constant"`
		Payable         bool       `json:"payable"`
		Anonymous       bool       `json:"anonymous"`
	}

	if err := json.Unmarshal(data, &fields); err != nil {
		return ABI{}, fmt.Errorf("failed to parse ABI JSON: %w", err)
	}

	abi := ABI{
		Methods: make(map[string]Method),
		Events:  make(map[string]Event),
	}

	for _, field := range fields {
		switch field.Type {
		case "constructor":
			abi.Constructor = Method{
				Type:            "constructor",
				Inputs:          field.Inputs,
				StateMutability: field.StateMutability,
				Payable:         field.Payable,
			}
		case "function", "":
			method := Method{
				Name:            field.Name,
				Type:            "function",
				Inputs:          field.Inputs,
				Outputs:         field.Outputs,
				StateMutability: field.StateMutability,
				Constant:        field.Constant,
				Payable:         field.Payable,
			}
			abi.Methods[field.Name] = method
		case "event":
			event := Event{
				Name:      field.Name,
				Type:      "event",
				Inputs:    field.Inputs,
				Anonymous: field.Anonymous,
			}
			abi.Events[field.Name] = event
		case "fallback":
			fallback := Method{
				Type:            "fallback",
				StateMutability: field.StateMutability,
				Payable:         field.Payable,
			}
			abi.Fallback = &fallback
		case "receive":
			receive := Method{
				Type:            "receive",
				StateMutability: "payable",
			}
			abi.Receive = &receive
		}
	}

	return abi, nil
}

// Pack encodes the method call with the given arguments.
// Returns the ABI-encoded data including the 4-byte method selector.
func (abi *ABI) Pack(name string, args ...any) ([]byte, error) {
	method, ok := abi.Methods[name]
	if !ok {
		return nil, errors.NewValidationError("name", fmt.Sprintf("method %s not found", name))
	}

	if len(args) != len(method.Inputs) {
		return nil, errors.NewValidationError("args", fmt.Sprintf("expected %d arguments, got %d", len(method.Inputs), len(args)))
	}

	// Calculate method selector (first 4 bytes of keccak256(signature))
	selector := methodSelector(method)

	// Encode arguments
	encoded, err := encodeArguments(method.Inputs, args)
	if err != nil {
		return nil, fmt.Errorf("failed to encode arguments: %w", err)
	}

	return append(selector, encoded...), nil
}

// PackConstructor encodes the constructor call with the given arguments.
func (abi *ABI) PackConstructor(args ...any) ([]byte, error) {
	if len(args) != len(abi.Constructor.Inputs) {
		return nil, errors.NewValidationError("args", fmt.Sprintf("expected %d arguments, got %d", len(abi.Constructor.Inputs), len(args)))
	}

	return encodeArguments(abi.Constructor.Inputs, args)
}

// Unpack decodes the output data from a method call.
func (abi *ABI) Unpack(name string, data []byte) ([]any, error) {
	method, ok := abi.Methods[name]
	if !ok {
		return nil, errors.NewValidationError("name", fmt.Sprintf("method %s not found", name))
	}

	return decodeArguments(method.Outputs, data)
}

// UnpackIntoInterface decodes the output data into the provided interface.
func (abi *ABI) UnpackIntoInterface(v any, name string, data []byte) error {
	results, err := abi.Unpack(name, data)
	if err != nil {
		return err
	}

	if len(results) == 0 {
		return nil
	}

	// Handle single return value
	if len(results) == 1 {
		return setInterfaceValue(v, results[0])
	}

	// Handle multiple return values (expects a struct or slice)
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return errors.NewValidationError("v", "must be a pointer")
	}
	rv = rv.Elem()

	switch rv.Kind() {
	case reflect.Struct:
		for i := 0; i < rv.NumField() && i < len(results); i++ {
			if rv.Field(i).CanSet() {
				if err := setReflectValue(rv.Field(i), results[i]); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		rv.Set(reflect.ValueOf(results))
	default:
		return errors.NewValidationError("v", "must be a pointer to struct or slice for multiple return values")
	}

	return nil
}

// methodSelector calculates the 4-byte method selector.
func methodSelector(method Method) []byte {
	sig := methodSignature(method)
	hash := utils.Keccak256([]byte(sig))
	return hash[:4]
}

// methodSignature returns the canonical method signature.
func methodSignature(method Method) string {
	types := make([]string, len(method.Inputs))
	for i, input := range method.Inputs {
		types[i] = canonicalType(input.Type)
	}
	return fmt.Sprintf("%s(%s)", method.Name, strings.Join(types, ","))
}

// EventID returns the topic hash for an event.
func (abi *ABI) EventID(name string) (common.Hash, error) {
	event, ok := abi.Events[name]
	if !ok {
		return common.Hash{}, errors.NewValidationError("name", fmt.Sprintf("event %s not found", name))
	}

	sig := eventSignature(event)
	return utils.Keccak256Hash([]byte(sig)), nil
}

// eventSignature returns the canonical event signature.
func eventSignature(event Event) string {
	types := make([]string, len(event.Inputs))
	for i, input := range event.Inputs {
		types[i] = canonicalType(input.Type)
	}
	return fmt.Sprintf("%s(%s)", event.Name, strings.Join(types, ","))
}

// canonicalType returns the canonical type name for ABI encoding.
func canonicalType(t string) string {
	// Handle aliases
	switch t {
	case "int":
		return "int256"
	case "uint":
		return "uint256"
	case "fixed":
		return "fixed128x18"
	case "ufixed":
		return "ufixed128x18"
	}
	return t
}

// encodeArguments encodes a list of arguments according to ABI specification.
func encodeArguments(inputs []Argument, args []any) ([]byte, error) {
	if len(inputs) != len(args) {
		return nil, fmt.Errorf("argument count mismatch: expected %d, got %d", len(inputs), len(args))
	}

	// Calculate head and tail sections
	var heads [][]byte
	var tails [][]byte
	headOffset := len(inputs) * 32 // Each head element is 32 bytes

	for i, input := range inputs {
		encoded, isDynamic, err := encodeValue(input.Type, args[i])
		if err != nil {
			return nil, fmt.Errorf("failed to encode argument %d (%s): %w", i, input.Name, err)
		}

		if isDynamic {
			// For dynamic types, head contains offset to tail
			offset := headOffset
			for _, tail := range tails {
				offset += len(tail)
			}
			heads = append(heads, padLeft(big.NewInt(int64(offset)).Bytes(), 32))
			tails = append(tails, encoded)
		} else {
			// For static types, head contains the value directly
			heads = append(heads, encoded)
		}
	}

	// Concatenate heads and tails
	var result []byte
	for _, head := range heads {
		result = append(result, head...)
	}
	for _, tail := range tails {
		result = append(result, tail...)
	}

	return result, nil
}

// encodeValue encodes a single value according to its ABI type.
// Returns the encoded bytes and whether the type is dynamic.
func encodeValue(typeName string, value any) ([]byte, bool, error) {
	// Handle array types
	if strings.HasSuffix(typeName, "[]") {
		baseType := strings.TrimSuffix(typeName, "[]")
		return encodeDynamicArray(baseType, value)
	}

	// Handle fixed-size array types
	if idx := strings.Index(typeName, "["); idx != -1 {
		return encodeFixedArray(typeName, value)
	}

	// Handle basic types
	switch {
	case strings.HasPrefix(typeName, "uint"):
		return encodeUint(typeName, value)
	case strings.HasPrefix(typeName, "int"):
		return encodeInt(typeName, value)
	case typeName == "address":
		return encodeAddress(value)
	case typeName == "bool":
		return encodeBool(value)
	case typeName == "bytes":
		return encodeDynamicBytes(value)
	case strings.HasPrefix(typeName, "bytes"):
		return encodeFixedBytes(typeName, value)
	case typeName == "string":
		return encodeString(value)
	case typeName == "tuple":
		return nil, false, fmt.Errorf("tuple encoding not yet supported")
	default:
		return nil, false, fmt.Errorf("unsupported type: %s", typeName)
	}
}

// encodeUint encodes an unsigned integer.
func encodeUint(typeName string, value any) ([]byte, bool, error) {
	var bigVal *big.Int

	switch v := value.(type) {
	case *big.Int:
		bigVal = v
	case int:
		bigVal = big.NewInt(int64(v))
	case int64:
		bigVal = big.NewInt(v)
	case uint:
		bigVal = new(big.Int).SetUint64(uint64(v))
	case uint64:
		bigVal = new(big.Int).SetUint64(v)
	case uint32:
		bigVal = new(big.Int).SetUint64(uint64(v))
	case uint16:
		bigVal = new(big.Int).SetUint64(uint64(v))
	case uint8:
		bigVal = new(big.Int).SetUint64(uint64(v))
	default:
		return nil, false, fmt.Errorf("cannot encode %T as %s", value, typeName)
	}

	if bigVal.Sign() < 0 {
		return nil, false, fmt.Errorf("cannot encode negative value as unsigned integer")
	}

	return padLeft(bigVal.Bytes(), 32), false, nil
}

// encodeInt encodes a signed integer.
func encodeInt(typeName string, value any) ([]byte, bool, error) {
	var bigVal *big.Int

	switch v := value.(type) {
	case *big.Int:
		bigVal = v
	case int:
		bigVal = big.NewInt(int64(v))
	case int64:
		bigVal = big.NewInt(v)
	case int32:
		bigVal = big.NewInt(int64(v))
	case int16:
		bigVal = big.NewInt(int64(v))
	case int8:
		bigVal = big.NewInt(int64(v))
	case uint:
		bigVal = new(big.Int).SetUint64(uint64(v))
	case uint64:
		bigVal = new(big.Int).SetUint64(v)
	default:
		return nil, false, fmt.Errorf("cannot encode %T as %s", value, typeName)
	}

	// Two's complement for negative numbers
	if bigVal.Sign() < 0 {
		// Create two's complement representation
		bytes := bigVal.Bytes()
		result := make([]byte, 32)
		for i := range result {
			result[i] = 0xff
		}
		copy(result[32-len(bytes):], bytes)
		return result, false, nil
	}

	return padLeft(bigVal.Bytes(), 32), false, nil
}

// encodeAddress encodes an address.
func encodeAddress(value any) ([]byte, bool, error) {
	var addr common.Address

	switch v := value.(type) {
	case common.Address:
		addr = v
	case *common.Address:
		if v == nil {
			return padLeft(nil, 32), false, nil
		}
		addr = *v
	case string:
		addr = common.HexToAddress(v)
	case []byte:
		if len(v) != 20 {
			return nil, false, fmt.Errorf("invalid address length: %d", len(v))
		}
		copy(addr[:], v)
	default:
		return nil, false, fmt.Errorf("cannot encode %T as address", value)
	}

	return padLeft(addr.Bytes(), 32), false, nil
}

// encodeBool encodes a boolean.
func encodeBool(value any) ([]byte, bool, error) {
	var b bool

	switch v := value.(type) {
	case bool:
		b = v
	default:
		return nil, false, fmt.Errorf("cannot encode %T as bool", value)
	}

	result := make([]byte, 32)
	if b {
		result[31] = 1
	}
	return result, false, nil
}

// encodeDynamicBytes encodes dynamic bytes.
func encodeDynamicBytes(value any) ([]byte, bool, error) {
	var data []byte

	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return nil, false, fmt.Errorf("cannot encode %T as bytes", value)
	}

	// Length prefix + padded data
	length := padLeft(big.NewInt(int64(len(data))).Bytes(), 32)
	paddedData := padRight(data, ((len(data)+31)/32)*32)

	return append(length, paddedData...), true, nil
}

// encodeFixedBytes encodes fixed-size bytes (bytes1 to bytes32).
func encodeFixedBytes(typeName string, value any) ([]byte, bool, error) {
	// Parse size from type name (e.g., "bytes32" -> 32)
	var size int
	_, err := fmt.Sscanf(typeName, "bytes%d", &size)
	if err != nil || size < 1 || size > 32 {
		return nil, false, fmt.Errorf("invalid fixed bytes type: %s", typeName)
	}

	var data []byte

	switch v := value.(type) {
	case []byte:
		data = v
	case [32]byte:
		data = v[:]
	case common.Hash:
		data = v.Bytes()
	case string:
		// Handle hex strings
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			data, err = hexToBytes(v)
			if err != nil {
				return nil, false, err
			}
		} else {
			data = []byte(v)
		}
	default:
		return nil, false, fmt.Errorf("cannot encode %T as %s", value, typeName)
	}

	if len(data) > size {
		return nil, false, fmt.Errorf("data too long for %s: %d bytes", typeName, len(data))
	}

	return padRight(data, 32), false, nil
}

// encodeString encodes a string.
func encodeString(value any) ([]byte, bool, error) {
	var str string

	switch v := value.(type) {
	case string:
		str = v
	case []byte:
		str = string(v)
	default:
		return nil, false, fmt.Errorf("cannot encode %T as string", value)
	}

	return encodeDynamicBytes([]byte(str))
}

// encodeDynamicArray encodes a dynamic array.
func encodeDynamicArray(baseType string, value any) ([]byte, bool, error) {
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false, fmt.Errorf("cannot encode %T as array", value)
	}

	length := rv.Len()

	// Encode length
	result := padLeft(big.NewInt(int64(length)).Bytes(), 32)

	// Encode elements
	elements, err := encodeArrayElements(baseType, rv)
	if err != nil {
		return nil, false, err
	}

	return append(result, elements...), true, nil
}

// encodeFixedArray encodes a fixed-size array.
func encodeFixedArray(typeName string, value any) ([]byte, bool, error) {
	// Parse base type and size (e.g., "uint256[3]" -> "uint256", 3)
	idx := strings.Index(typeName, "[")
	baseType := typeName[:idx]
	sizeStr := typeName[idx+1 : len(typeName)-1]

	var size int
	_, err := fmt.Sscanf(sizeStr, "%d", &size)
	if err != nil {
		return nil, false, fmt.Errorf("invalid array size: %s", sizeStr)
	}

	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false, fmt.Errorf("cannot encode %T as array", value)
	}

	if rv.Len() != size {
		return nil, false, fmt.Errorf("array size mismatch: expected %d, got %d", size, rv.Len())
	}

	// Check if base type is dynamic
	isDynamic := isDynamicType(baseType)

	elements, err := encodeArrayElements(baseType, rv)
	if err != nil {
		return nil, false, err
	}

	return elements, isDynamic, nil
}

// encodeArrayElements encodes array elements.
func encodeArrayElements(baseType string, rv reflect.Value) ([]byte, error) {
	isDynamic := isDynamicType(baseType)

	if !isDynamic {
		// Static elements: concatenate directly
		var result []byte
		for i := 0; i < rv.Len(); i++ {
			encoded, _, err := encodeValue(baseType, rv.Index(i).Interface())
			if err != nil {
				return nil, fmt.Errorf("failed to encode element %d: %w", i, err)
			}
			result = append(result, encoded...)
		}
		return result, nil
	}

	// Dynamic elements: use head/tail encoding
	var heads [][]byte
	var tails [][]byte
	headOffset := rv.Len() * 32

	for i := 0; i < rv.Len(); i++ {
		encoded, _, err := encodeValue(baseType, rv.Index(i).Interface())
		if err != nil {
			return nil, fmt.Errorf("failed to encode element %d: %w", i, err)
		}

		offset := headOffset
		for _, tail := range tails {
			offset += len(tail)
		}
		heads = append(heads, padLeft(big.NewInt(int64(offset)).Bytes(), 32))
		tails = append(tails, encoded)
	}

	var result []byte
	for _, head := range heads {
		result = append(result, head...)
	}
	for _, tail := range tails {
		result = append(result, tail...)
	}

	return result, nil
}

// isDynamicType returns true if the type is dynamic (variable length).
func isDynamicType(typeName string) bool {
	if typeName == "bytes" || typeName == "string" {
		return true
	}
	if strings.HasSuffix(typeName, "[]") {
		return true
	}
	return false
}

// decodeArguments decodes ABI-encoded data according to the output types.
func decodeArguments(outputs []Argument, data []byte) ([]any, error) {
	if len(outputs) == 0 {
		return nil, nil
	}

	results := make([]any, len(outputs))
	offset := 0

	for i, output := range outputs {
		value, bytesRead, err := decodeValue(output.Type, data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to decode output %d (%s): %w", i, output.Name, err)
		}
		results[i] = value

		// For static types, advance by 32 bytes
		// For dynamic types, we read the offset from head, actual data is in tail
		if isDynamicType(output.Type) {
			offset += 32 // Just the offset pointer
		} else {
			offset += bytesRead
		}
	}

	return results, nil
}

// decodeValue decodes a single value from ABI-encoded data.
// Returns the decoded value and the number of bytes consumed from the head.
func decodeValue(typeName string, data []byte, offset int) (any, int, error) {
	if offset+32 > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for decoding at offset %d", offset)
	}

	// Handle array types
	if strings.HasSuffix(typeName, "[]") {
		baseType := strings.TrimSuffix(typeName, "[]")
		return decodeDynamicArray(baseType, data, offset)
	}

	// Handle fixed-size array types
	if idx := strings.Index(typeName, "["); idx != -1 {
		return decodeFixedArray(typeName, data, offset)
	}

	// Handle basic types
	switch {
	case strings.HasPrefix(typeName, "uint"):
		return decodeUint(typeName, data, offset)
	case strings.HasPrefix(typeName, "int"):
		return decodeInt(typeName, data, offset)
	case typeName == "address":
		return decodeAddress(data, offset)
	case typeName == "bool":
		return decodeBool(data, offset)
	case typeName == "bytes":
		return decodeDynamicBytes(data, offset)
	case strings.HasPrefix(typeName, "bytes"):
		return decodeFixedBytes(typeName, data, offset)
	case typeName == "string":
		return decodeString(data, offset)
	default:
		return nil, 0, fmt.Errorf("unsupported type: %s", typeName)
	}
}

// decodeUint decodes an unsigned integer.
func decodeUint(typeName string, data []byte, offset int) (*big.Int, int, error) {
	word := data[offset : offset+32]
	return new(big.Int).SetBytes(word), 32, nil
}

// decodeInt decodes a signed integer.
func decodeInt(typeName string, data []byte, offset int) (*big.Int, int, error) {
	word := data[offset : offset+32]
	result := new(big.Int).SetBytes(word)

	// Check if negative (high bit set)
	if word[0]&0x80 != 0 {
		// Two's complement: subtract 2^256
		maxUint256 := new(big.Int).Lsh(big.NewInt(1), 256)
		result.Sub(result, maxUint256)
	}

	return result, 32, nil
}

// decodeAddress decodes an address.
func decodeAddress(data []byte, offset int) (common.Address, int, error) {
	word := data[offset : offset+32]
	return common.BytesToAddress(word[12:32]), 32, nil
}

// decodeBool decodes a boolean.
func decodeBool(data []byte, offset int) (bool, int, error) {
	word := data[offset : offset+32]
	return word[31] != 0, 32, nil
}

// decodeDynamicBytes decodes dynamic bytes.
func decodeDynamicBytes(data []byte, offset int) ([]byte, int, error) {
	// Read offset to actual data
	dataOffset := new(big.Int).SetBytes(data[offset : offset+32]).Uint64()

	if int(dataOffset)+32 > len(data) {
		return nil, 0, fmt.Errorf("invalid dynamic bytes offset")
	}

	// Read length
	length := new(big.Int).SetBytes(data[dataOffset : dataOffset+32]).Uint64()

	if int(dataOffset)+32+int(length) > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for dynamic bytes")
	}

	// Read data
	result := make([]byte, length)
	copy(result, data[dataOffset+32:dataOffset+32+length])

	return result, 32, nil
}

// decodeFixedBytes decodes fixed-size bytes.
func decodeFixedBytes(typeName string, data []byte, offset int) ([]byte, int, error) {
	var size int
	_, err := fmt.Sscanf(typeName, "bytes%d", &size)
	if err != nil || size < 1 || size > 32 {
		return nil, 0, fmt.Errorf("invalid fixed bytes type: %s", typeName)
	}

	word := data[offset : offset+32]
	result := make([]byte, size)
	copy(result, word[:size])

	return result, 32, nil
}

// decodeString decodes a string.
func decodeString(data []byte, offset int) (string, int, error) {
	bytes, bytesRead, err := decodeDynamicBytes(data, offset)
	if err != nil {
		return "", 0, err
	}
	return string(bytes), bytesRead, nil
}

// decodeDynamicArray decodes a dynamic array.
func decodeDynamicArray(baseType string, data []byte, offset int) ([]any, int, error) {
	// Read offset to actual data
	dataOffset := new(big.Int).SetBytes(data[offset : offset+32]).Uint64()

	if int(dataOffset)+32 > len(data) {
		return nil, 0, fmt.Errorf("invalid dynamic array offset")
	}

	// Read length
	length := new(big.Int).SetBytes(data[dataOffset : dataOffset+32]).Uint64()

	// Decode elements
	results := make([]any, length)
	elemOffset := int(dataOffset) + 32

	for i := uint64(0); i < length; i++ {
		value, bytesRead, err := decodeValue(baseType, data, elemOffset)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to decode array element %d: %w", i, err)
		}
		results[i] = value

		if isDynamicType(baseType) {
			elemOffset += 32
		} else {
			elemOffset += bytesRead
		}
	}

	return results, 32, nil
}

// decodeFixedArray decodes a fixed-size array.
func decodeFixedArray(typeName string, data []byte, offset int) ([]any, int, error) {
	idx := strings.Index(typeName, "[")
	baseType := typeName[:idx]
	sizeStr := typeName[idx+1 : len(typeName)-1]

	var size int
	_, err := fmt.Sscanf(sizeStr, "%d", &size)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid array size: %s", sizeStr)
	}

	results := make([]any, size)
	elemOffset := offset
	totalBytesRead := 0

	for i := 0; i < size; i++ {
		value, bytesRead, err := decodeValue(baseType, data, elemOffset)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to decode array element %d: %w", i, err)
		}
		results[i] = value
		elemOffset += bytesRead
		totalBytesRead += bytesRead
	}

	return results, totalBytesRead, nil
}

// Helper functions

// padLeft pads data with zeros on the left to reach the target length.
func padLeft(data []byte, size int) []byte {
	if len(data) >= size {
		return data
	}
	result := make([]byte, size)
	copy(result[size-len(data):], data)
	return result
}

// padRight pads data with zeros on the right to reach the target length.
func padRight(data []byte, size int) []byte {
	if len(data) >= size {
		return data[:size]
	}
	result := make([]byte, size)
	copy(result, data)
	return result
}

// hexToBytes converts a hex string to bytes.
func hexToBytes(s string) ([]byte, error) {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(result); i++ {
		_, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &result[i])
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// setInterfaceValue sets the value of an interface pointer.
func setInterfaceValue(v any, value any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return errors.NewValidationError("v", "must be a pointer")
	}
	return setReflectValue(rv.Elem(), value)
}

// setReflectValue sets a reflect.Value from an interface value.
func setReflectValue(rv reflect.Value, value any) error {
	if !rv.CanSet() {
		return errors.NewValidationError("v", "cannot set value")
	}

	srcVal := reflect.ValueOf(value)

	// Handle type conversions
	if srcVal.Type().AssignableTo(rv.Type()) {
		rv.Set(srcVal)
		return nil
	}

	// Handle *big.Int to various integer types
	if bigInt, ok := value.(*big.Int); ok {
		switch rv.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			rv.SetUint(bigInt.Uint64())
			return nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			rv.SetInt(bigInt.Int64())
			return nil
		}
	}

	// Try to convert
	if srcVal.Type().ConvertibleTo(rv.Type()) {
		rv.Set(srcVal.Convert(rv.Type()))
		return nil
	}

	return fmt.Errorf("cannot assign %T to %s", value, rv.Type())
}

// MethodByID returns the method matching the given selector (first 4 bytes of call data).
func (abi *ABI) MethodByID(id []byte) (*Method, error) {
	if len(id) < 4 {
		return nil, errors.NewValidationError("id", "selector must be at least 4 bytes")
	}

	selector := id[:4]
	for name, method := range abi.Methods {
		methodSel := methodSelector(method)
		if bytesEqual(selector, methodSel) {
			m := abi.Methods[name]
			return &m, nil
		}
	}

	return nil, errors.NewValidationError("id", "method not found for selector")
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// UnpackEvent decodes event data.
func (abi *ABI) UnpackEvent(name string, data []byte, topics []common.Hash) ([]any, error) {
	event, ok := abi.Events[name]
	if !ok {
		return nil, errors.NewValidationError("name", fmt.Sprintf("event %s not found", name))
	}

	// Separate indexed and non-indexed inputs
	var indexedInputs []Argument
	var nonIndexedInputs []Argument
	for _, input := range event.Inputs {
		if input.Indexed {
			indexedInputs = append(indexedInputs, input)
		} else {
			nonIndexedInputs = append(nonIndexedInputs, input)
		}
	}

	results := make([]any, len(event.Inputs))

	// Decode indexed parameters from topics
	topicIdx := 1 // Skip first topic (event signature)
	if event.Anonymous {
		topicIdx = 0
	}

	for i, input := range event.Inputs {
		if input.Indexed {
			if topicIdx >= len(topics) {
				return nil, fmt.Errorf("missing topic for indexed parameter %s", input.Name)
			}
			// Indexed parameters are stored directly in topics (32 bytes)
			value, _, err := decodeValue(input.Type, topics[topicIdx].Bytes(), 0)
			if err != nil {
				// For dynamic types, the topic contains the hash, not the value
				results[i] = topics[topicIdx]
			} else {
				results[i] = value
			}
			topicIdx++
		}
	}

	// Decode non-indexed parameters from data
	if len(nonIndexedInputs) > 0 && len(data) > 0 {
		nonIndexedResults, err := decodeArguments(nonIndexedInputs, data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode non-indexed parameters: %w", err)
		}

		nonIndexedIdx := 0
		for i, input := range event.Inputs {
			if !input.Indexed {
				results[i] = nonIndexedResults[nonIndexedIdx]
				nonIndexedIdx++
			}
		}
	}

	return results, nil
}
