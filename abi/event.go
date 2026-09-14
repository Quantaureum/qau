// Quantaureum Node source, version 1.0.0.
package abi

import (
	"fmt"
	"math/big"
)

// Event represents a contract event
type Event struct {
	Name      string
	RawName   string // Original name from JSON
	Inputs    Arguments
	Anonymous bool

	// ID is the 32-byte topic hash (keccak256 of signature)
	ID []byte
	// Sig is the event signature (e.g., "Transfer(address,address,uint256)")
	Sig string
}

// EventLog represents a decoded event log
type EventLog struct {
	Name   string
	Topics [][]byte
	Data   []byte
}

// UnpackLog unpacks an event log into the provided interface
func (e *Event) UnpackLog(log EventLog, v any) error {
	// Unpack non-indexed arguments from data
	nonIndexed := e.Inputs.NonIndexed()
	if len(log.Data) > 0 {
		if err := nonIndexed.UnpackIntoInterface(v, log.Data); err != nil {
			return fmt.Errorf("failed to unpack non-indexed arguments: %w", err)
		}
	}
	return nil
}

// ParseTopics parses indexed arguments from event topics
func (e *Event) ParseTopics(topics [][]byte) ([]any, error) {
	indexed := e.Inputs.Indexed()

	// Skip first topic (event signature) for non-anonymous events
	topicOffset := 0
	if !e.Anonymous {
		topicOffset = 1
	}

	if len(topics)-topicOffset < len(indexed) {
		return nil, fmt.Errorf("not enough topics: expected %d, got %d", len(indexed), len(topics)-topicOffset)
	}

	result := make([]any, len(indexed))
	for i, arg := range indexed {
		topicData := topics[topicOffset+i]
		val, err := parseIndexedTopic(topicData, arg.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to parse topic %d: %w", i, err)
		}
		result[i] = val
	}

	return result, nil
}

// parseIndexedTopic parses a single indexed topic value
func parseIndexedTopic(topic []byte, typ Type) (any, error) {
	if len(topic) != 32 {
		return nil, fmt.Errorf("topic must be 32 bytes, got %d", len(topic))
	}

	switch typ.T {
	case UintTy:
		return new(big.Int).SetBytes(topic), nil

	case IntTy:
		bi := new(big.Int).SetBytes(topic)
		// Check if negative (high bit set)
		if topic[0]&0x80 != 0 {
			// audit-fix R10-2: ABI always pads to 32 bytes (256 bits), so two's
			// complement must use 2^256, not 2^typ.Size. Previously, e.g. int8(-1)
			// (encoded as all FF bytes) would decode as ~2^256 instead of -1.
			maxVal := new(big.Int).Lsh(big.NewInt(1), 256)
			bi.Sub(bi, maxVal)
		}
		return bi, nil

	case BoolTy:
		return topic[31] != 0, nil

	case AddressTy:
		var addr [20]byte
		copy(addr[:], topic[12:32])
		return addr, nil

	case FixedBytesTy:
		result := make([]byte, typ.Size)
		copy(result, topic[:typ.Size])
		return result, nil

	case BytesTy, StringTy, SliceTy, ArrayTy, TupleTy:
		// Dynamic types are hashed, return the hash
		result := make([]byte, 32)
		copy(result, topic)
		return result, nil

	default:
		return nil, fmt.Errorf("unsupported indexed type: %s", typ.String())
	}
}

// UnpackEventData unpacks the non-indexed event data
func (e *Event) UnpackEventData(data []byte) ([]any, error) {
	return e.Inputs.NonIndexed().Unpack(data)
}

// UnpackEventDataIntoInterface unpacks event data into the provided interface
func (e *Event) UnpackEventDataIntoInterface(v any, data []byte) error {
	return e.Inputs.NonIndexed().UnpackIntoInterface(v, data)
}

// GetIndexedArguments returns the indexed arguments
func (e *Event) GetIndexedArguments() Arguments {
	return e.Inputs.Indexed()
}

// GetNonIndexedArguments returns the non-indexed arguments
func (e *Event) GetNonIndexedArguments() Arguments {
	return e.Inputs.NonIndexed()
}

// MatchTopic checks if the given topic matches this event's signature
func (e *Event) MatchTopic(topic []byte) bool {
	if e.Anonymous {
		return true // Anonymous events don't have signature topic
	}
	if len(topic) != 32 || len(e.ID) != 32 {
		return false
	}
	for i := 0; i < 32; i++ {
		if topic[i] != e.ID[i] {
			return false
		}
	}
	return true
}

// DecodeLog decodes a complete event log (topics + data)
func (e *Event) DecodeLog(topics [][]byte, data []byte) (map[string]any, error) {
	result := make(map[string]any)

	// Parse indexed topics
	indexed := e.Inputs.Indexed()
	topicOffset := 0
	if !e.Anonymous {
		topicOffset = 1
	}

	for i, arg := range indexed {
		if topicOffset+i >= len(topics) {
			return nil, fmt.Errorf("missing topic for indexed argument %s", arg.Name)
		}
		val, err := parseIndexedTopic(topics[topicOffset+i], arg.Type)
		if err != nil {
			return nil, err
		}
		if arg.Name != "" {
			result[arg.Name] = val
		} else {
			result[fmt.Sprintf("arg%d", i)] = val
		}
	}

	// Parse non-indexed data
	nonIndexed := e.Inputs.NonIndexed()
	if len(data) > 0 && len(nonIndexed) > 0 {
		values, err := nonIndexed.Unpack(data)
		if err != nil {
			return nil, err
		}
		for i, arg := range nonIndexed {
			if arg.Name != "" {
				result[arg.Name] = values[i]
			} else {
				result[fmt.Sprintf("data%d", i)] = values[i]
			}
		}
	}

	return result, nil
}
