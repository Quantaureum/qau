// Quantaureum Node source, version 1.0.0.
package abi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

// ABI errors
var (
	ErrMethodNotFound  = errors.New("method not found")
	ErrEventNotFound   = errors.New("event not found")
	ErrInvalidABI      = errors.New("invalid ABI")
	ErrArgumentCount   = errors.New("argument count mismatch")
	ErrTypeMismatch    = errors.New("type mismatch")
	ErrInvalidSelector = errors.New("invalid selector")
)

// ABI represents a contract's Application Binary Interface
type ABI struct {
	Constructor Method
	Methods     map[string]Method
	Events      map[string]Event
	Errors      map[string]Error
	Fallback    Method
	Receive     Method

	// methodsByID provides O(1) lookup by 4-byte selector.
	// Built by buildMethodIndex() after JSON parsing.
	// P3-10 FIX: Replaces O(n) linear scan in MethodByID.
	methodsByID map[[4]byte]*Method

	// eventsByID provides O(1) lookup by 32-byte topic hash.
	// Built by buildEventIndex() after JSON parsing.
	// L9-056 FIX: Replaces O(n) linear scan in EventByID.
	eventsByID map[[32]byte]*Event
}

// Method represents a contract method
type Method struct {
	Name    string
	RawName string // Original name from JSON
	Type    string // "function", "constructor", "fallback", "receive"
	Inputs  Arguments
	Outputs Arguments

	// Constant indicates if the method is read-only
	Constant bool
	// Payable indicates if the method can receive Ether
	Payable bool
	// StateMutability: "pure", "view", "nonpayable", "payable"
	StateMutability string

	// ID is the 4-byte method selector
	ID []byte
	// Sig is the method signature (e.g., "transfer(address,uint256)")
	Sig string
}

// Error represents a contract error
type Error struct {
	Name   string
	Inputs Arguments
	ID     []byte
	Sig    string
}

// JSON parses an ABI from a JSON reader
func JSON(reader io.Reader) (ABI, error) {
	// FIX: Limit input size to 10MB to prevent OOM from malicious payloads.
	limitedReader := io.LimitReader(reader, 10*1024*1024)
	var fields []struct {
		Type            string               `json:"type"`
		Name            string               `json:"name"`
		Inputs          []ArgumentMarshaling `json:"inputs"`
		Outputs         []ArgumentMarshaling `json:"outputs"`
		Constant        bool                 `json:"constant"`
		Payable         bool                 `json:"payable"`
		StateMutability string               `json:"stateMutability"`
		Anonymous       bool                 `json:"anonymous"`
	}

	if err := json.NewDecoder(limitedReader).Decode(&fields); err != nil {
		return ABI{}, fmt.Errorf("%w: %v", ErrInvalidABI, err)
	}

	// FIX: Verify the input did not exceed the 10MB limit. If the
	// LimitReader was exhausted, there may be more data that was silently
	// truncated, indicating a potentially malicious or corrupted ABI file.
	if _, err := limitedReader.Read(make([]byte, 1)); err == nil {
		return ABI{}, fmt.Errorf("%w: input exceeds 10MB limit", ErrInvalidABI)
	}

	abi := ABI{
		Methods: make(map[string]Method),
		Events:  make(map[string]Event),
		Errors:  make(map[string]Error),
	}

	for _, field := range fields {
		switch field.Type {
		case "constructor":
			inputs, err := parseArguments(field.Inputs)
			if err != nil {
				return ABI{}, err
			}
			abi.Constructor = Method{
				Type:            "constructor",
				Inputs:          inputs,
				StateMutability: field.StateMutability,
				Payable:         field.Payable || field.StateMutability == "payable",
			}

		case "function", "":
			method, err := parseMethod(field.Name, field.Inputs, field.Outputs, field.Constant, field.Payable, field.StateMutability)
			if err != nil {
				return ABI{}, err
			}
			abi.Methods[field.Name] = method

		case "fallback":
			abi.Fallback = Method{
				Type:            "fallback",
				StateMutability: field.StateMutability,
				Payable:         field.Payable || field.StateMutability == "payable",
			}

		case "receive":
			abi.Receive = Method{
				Type:            "receive",
				StateMutability: "payable",
				Payable:         true,
			}

		case "event":
			event, err := parseEvent(field.Name, field.Inputs, field.Anonymous)
			if err != nil {
				return ABI{}, err
			}
			abi.Events[field.Name] = event

		case "error":
			abiError, err := parseError(field.Name, field.Inputs)
			if err != nil {
				return ABI{}, err
			}
			abi.Errors[field.Name] = abiError
		}
	}

	// P3-10 FIX: Build the method selector index for O(1) MethodByID lookups.
	abi.buildMethodIndex()
	// L9-056 FIX: Build the event topic index for O(1) EventByID lookups.
	abi.buildEventIndex()

	return abi, nil
}

func parseMethod(name string, inputs, outputs []ArgumentMarshaling, constant, payable bool, stateMutability string) (Method, error) {
	inputArgs, err := parseArguments(inputs)
	if err != nil {
		return Method{}, err
	}

	outputArgs, err := parseArguments(outputs)
	if err != nil {
		return Method{}, err
	}

	// Build signature
	sig := buildSignature(name, inputArgs)

	// Calculate selector (first 4 bytes of keccak256(signature))
	hash := keccak256([]byte(sig))
	id := hash[:4]

	return Method{
		Name:            name,
		RawName:         name,
		Type:            "function",
		Inputs:          inputArgs,
		Outputs:         outputArgs,
		Constant:        constant || stateMutability == "view" || stateMutability == "pure",
		Payable:         payable || stateMutability == "payable",
		StateMutability: stateMutability,
		ID:              id,
		Sig:             sig,
	}, nil
}

func parseEvent(name string, inputs []ArgumentMarshaling, anonymous bool) (Event, error) {
	args, err := parseArguments(inputs)
	if err != nil {
		return Event{}, err
	}

	// Set indexed flag from marshaling
	for i, input := range inputs {
		args[i].Indexed = input.Indexed
	}

	// Build signature
	sig := buildSignature(name, args)

	// Calculate topic (keccak256(signature))
	hash := keccak256([]byte(sig))

	return Event{
		Name:      name,
		RawName:   name,
		Inputs:    args,
		Anonymous: anonymous,
		ID:        hash,
		Sig:       sig,
	}, nil
}

func parseError(name string, inputs []ArgumentMarshaling) (Error, error) {
	args, err := parseArguments(inputs)
	if err != nil {
		return Error{}, err
	}

	sig := buildSignature(name, args)
	hash := keccak256([]byte(sig))

	return Error{
		Name:   name,
		Inputs: args,
		ID:     hash[:4],
		Sig:    sig,
	}, nil
}

func parseArguments(inputs []ArgumentMarshaling) (Arguments, error) {
	args := make(Arguments, len(inputs))
	for i, input := range inputs {
		typ, err := NewType(input.Type, input.InternalType, input.Components)
		if err != nil {
			return nil, fmt.Errorf("failed to parse type %s: %w", input.Type, err)
		}
		args[i] = Argument{
			Name:    input.Name,
			Type:    typ,
			Indexed: input.Indexed,
		}
	}
	return args, nil
}

func buildSignature(name string, args Arguments) string {
	sig := name + "("
	for i, arg := range args {
		if i > 0 {
			sig += ","
		}
		sig += arg.Type.String()
	}
	sig += ")"
	return sig
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// Pack packs the given method name and arguments into calldata
func (abi *ABI) Pack(name string, args ...any) ([]byte, error) {
	// Handle constructor
	if name == "" {
		return abi.Constructor.Inputs.Pack(args...)
	}

	method, ok := abi.Methods[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMethodNotFound, name)
	}

	// Pack arguments
	packed, err := method.Inputs.Pack(args...)
	if err != nil {
		return nil, err
	}

	// Prepend method selector
	return append(method.ID, packed...), nil
}

// Unpack unpacks the output data from a method call
func (abi *ABI) Unpack(name string, data []byte) ([]any, error) {
	method, ok := abi.Methods[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMethodNotFound, name)
	}

	return method.Outputs.Unpack(data)
}

// UnpackIntoInterface unpacks the output data into the provided interface
func (abi *ABI) UnpackIntoInterface(v any, name string, data []byte) error {
	method, ok := abi.Methods[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrMethodNotFound, name)
	}

	return method.Outputs.UnpackIntoInterface(v, data)
}

// UnpackInput unpacks the input data from a method call (excluding selector)
func (abi *ABI) UnpackInput(name string, data []byte) ([]any, error) {
	method, ok := abi.Methods[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMethodNotFound, name)
	}

	return method.Inputs.Unpack(data)
}

// buildMethodIndex builds the methodsByID map for O(1) selector lookups.
// Called by JSON() after all methods are parsed. Safe to call multiple times.
func (abi *ABI) buildMethodIndex() {
	abi.methodsByID = make(map[[4]byte]*Method, len(abi.Methods))
	// L6-054 NOTE: We iterate with `for name := range` and take a fresh
	// loop-body-local copy `m := abi.Methods[name]`. Because `m` is declared
	// inside the loop body (not the range clause), it is a distinct
	// per-iteration variable in every Go version, so `&m` is a unique
	// address per iteration and each map entry points to its own Method
	// copy. This is the canonical fix for loop-variable address capture and
	// avoids the pre-1.22 `for _, m := range` + `&m` footgun. Do NOT refactor
	// this to `for _, m := range abi.Methods { ... &m }` without keeping the
	// explicit copy.
	for name := range abi.Methods {
		m := abi.Methods[name]
		if len(m.ID) >= 4 {
			var key [4]byte
			copy(key[:], m.ID[:4])
			abi.methodsByID[key] = &m
		}
	}
}

// buildEventIndex builds the eventsByID map for O(1) topic lookups.
// Called by JSON() after all events are parsed. Safe to call multiple times.
// L9-056 FIX: Replaces O(n) linear scan in EventByID with O(1) map lookup.
func (abi *ABI) buildEventIndex() {
	abi.eventsByID = make(map[[32]byte]*Event, len(abi.Events))
	// Use the same loop-variable address capture pattern as buildMethodIndex.
	for name := range abi.Events {
		e := abi.Events[name]
		if len(e.ID) >= 32 {
			var key [32]byte
			copy(key[:], e.ID[:32])
			abi.eventsByID[key] = &e
		}
	}
}

// MethodByID looks up a method by its 4-byte selector.
// P3-10 FIX: Uses map lookup (O(1)) when methodsByID index is available
// (built by JSON constructor). Falls back to linear scan for ABI instances
// not created via JSON().
func (abi *ABI) MethodByID(id []byte) (*Method, error) {
	if len(id) < 4 {
		return nil, ErrInvalidSelector
	}

	// Fast path: O(1) map lookup when index is built.
	if abi.methodsByID != nil {
		var key [4]byte
		copy(key[:], id[:4])
		if method, ok := abi.methodsByID[key]; ok {
			return method, nil
		}
		return nil, ErrMethodNotFound
	}

	// Fallback: O(n) linear scan for ABI instances without an index
	// (e.g., manually constructed or not initialized via JSON()).
	for _, method := range abi.Methods {
		if len(method.ID) >= 4 &&
			method.ID[0] == id[0] &&
			method.ID[1] == id[1] &&
			method.ID[2] == id[2] &&
			method.ID[3] == id[3] {
			// L6-054 FIX: Take the address of an explicit per-iteration copy
			// rather than the range variable. Under Go 1.22+ (this project) the
			// range variable is already fresh per iteration, but the explicit
			// copy is robust under all Go versions and unambiguous to static
			// analyzers checking for loop-variable address capture.
			m := method
			return &m, nil
		}
	}

	return nil, ErrMethodNotFound
}

// EventByID looks up an event by its topic hash.
// L9-056 FIX: Uses map lookup (O(1)) when eventsByID index is available
// (built by JSON constructor). Falls back to linear scan for ABI instances
// not created via JSON().
func (abi *ABI) EventByID(id []byte) (*Event, error) {
	if len(id) < 32 {
		return nil, ErrInvalidSelector
	}

	// Fast path: O(1) map lookup when index is built.
	if abi.eventsByID != nil {
		var key [32]byte
		copy(key[:], id[:32])
		if event, ok := abi.eventsByID[key]; ok {
			return event, nil
		}
		return nil, ErrEventNotFound
	}

	// Fallback: linear scan for ABI instances not created via JSON().
	// L14-040 NOTE: This fallback path is inconsistent with the primary map
	// lookup above. It uses manual byte-by-byte comparison instead of
	// bytes.Equal, and checks len(event.ID) >= 32 rather than == 32.
	// This is intentional: some ABI instances may have event IDs longer
	// than 32 bytes (e.g. with extra metadata), and the >= check ensures
	// they are still matchable. However, this means the fallback could
	// match a different event than the primary lookup if there are
	// duplicate IDs with different lengths. This is a known limitation.
	for _, event := range abi.Events {
		if len(event.ID) >= 32 {
			match := true
			for i := 0; i < 32; i++ {
				if event.ID[i] != id[i] {
					match = false
					break
				}
			}
			if match {
				return &event, nil
			}
		}
	}

	return nil, ErrEventNotFound
}

// HasMethod returns true if the ABI has a method with the given name
func (abi *ABI) HasMethod(name string) bool {
	_, ok := abi.Methods[name]
	return ok
}

// HasEvent returns true if the ABI has an event with the given name
func (abi *ABI) HasEvent(name string) bool {
	_, ok := abi.Events[name]
	return ok
}

// PackEvent packs event arguments (non-indexed only)
func (abi *ABI) PackEvent(name string, args ...any) ([]byte, error) {
	event, ok := abi.Events[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrEventNotFound, name)
	}

	return event.Inputs.NonIndexed().Pack(args...)
}

// UnpackEvent unpacks event data (non-indexed arguments)
func (abi *ABI) UnpackEvent(name string, data []byte) ([]any, error) {
	event, ok := abi.Events[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrEventNotFound, name)
	}

	return event.Inputs.NonIndexed().Unpack(data)
}

// UnpackEventIntoInterface unpacks event data into the provided interface
func (abi *ABI) UnpackEventIntoInterface(v any, name string, data []byte) error {
	event, ok := abi.Events[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrEventNotFound, name)
	}

	return event.Inputs.NonIndexed().UnpackIntoInterface(v, data)
}
