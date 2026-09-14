// Quantaureum Node source, version 1.0.0.
// Package validation provides P2P message validation for Quantaureum.
package validation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/quantaureum/qau/p2p"
)

// P2P validation errors
var (
	ErrInvalidMsgType    = errors.New("invalid message type")
	ErrMsgTooLarge       = errors.New("message too large")
	ErrMsgTooSmall       = errors.New("message too small")
	ErrInvalidChecksum   = errors.New("invalid checksum")
	ErrMalformedMessage  = errors.New("malformed message")
	ErrInvalidPayload    = errors.New("invalid payload")
	ErrInvalidBlockData  = errors.New("invalid block data")
	ErrInvalidTxData     = errors.New("invalid transaction data")
	ErrInvalidVoteData   = errors.New("invalid vote data")
	ErrInvalidStatusData = errors.New("invalid status data")
)

// P2P message constants
const (
	MsgHeaderSize = 9                // 1 byte type + 4 bytes length + 4 bytes checksum
	MaxMsgSize    = 10 * 1024 * 1024 // 10 MB
	MinMsgSize    = MsgHeaderSize

	// audit-fix R5-F21: local cap for request hash counts
	MaxRequestHashes = 256
)

// P2PValidator validates P2P messages
type P2PValidator struct {
	mu    sync.RWMutex
	stats P2PValidationStats
}

// P2PValidationStats tracks P2P validation statistics
type P2PValidationStats struct {
	TotalMessages     uint64
	ValidMessages     uint64
	InvalidMessages   uint64
	MalformedMessages uint64
	OversizedMessages uint64
	ChecksumFailures  uint64
}

// NewP2PValidator creates a new P2P validator
func NewP2PValidator() *P2PValidator {
	return &P2PValidator{}
}

// Stats returns the validation statistics
func (v *P2PValidator) Stats() P2PValidationStats {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.stats
}

// ValidateMessage validates a raw P2P message
func (v *P2PValidator) ValidateMessage(data []byte) *ValidationResult {
	v.mu.Lock()
	v.stats.TotalMessages++
	v.mu.Unlock()

	result := v.validateMessageInternal(data)

	v.mu.Lock()
	if result.Valid {
		v.stats.ValidMessages++
	} else {
		v.stats.InvalidMessages++
		if errors.Is(result.Error, ErrMalformedMessage) {
			v.stats.MalformedMessages++
		}
		if errors.Is(result.Error, ErrMsgTooLarge) {
			v.stats.OversizedMessages++
		}
		if errors.Is(result.Error, ErrInvalidChecksum) {
			v.stats.ChecksumFailures++
		}
	}
	v.mu.Unlock()

	return result
}

func (v *P2PValidator) validateMessageInternal(data []byte) *ValidationResult {
	// Check minimum size
	if len(data) < MinMsgSize {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMsgTooSmall,
			Field:   "message",
			Details: fmt.Sprintf("message size %d is less than minimum %d", len(data), MinMsgSize),
		}
	}

	// Parse header
	msgType := data[0]
	length := binary.BigEndian.Uint32(data[1:5])
	checksum := binary.BigEndian.Uint32(data[5:9])

	// Validate message type
	if !isValidMsgType(msgType) {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidMsgType,
			Field:   "type",
			Details: fmt.Sprintf("unknown message type: %d", msgType),
		}
	}

	// Validate length
	if length > MaxMsgSize {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMsgTooLarge,
			Field:   "length",
			Details: fmt.Sprintf("payload length %d exceeds maximum %d", length, MaxMsgSize),
		}
	}

	// Check if we have enough data
	expectedSize := MsgHeaderSize + int(length)
	if len(data) < expectedSize {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMalformedMessage,
			Field:   "message",
			Details: fmt.Sprintf("expected %d bytes, got %d", expectedSize, len(data)),
		}
	}

	// Extract payload
	payload := data[MsgHeaderSize : MsgHeaderSize+length]

	// Verify checksum
	calculatedChecksum := crc32Checksum(payload)
	if calculatedChecksum != checksum {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidChecksum,
			Field:   "checksum",
			Details: fmt.Sprintf("expected %08x, got %08x", calculatedChecksum, checksum),
		}
	}

	// Validate payload based on message type
	return v.validatePayload(msgType, payload)
}

func (v *P2PValidator) validatePayload(msgType uint8, payload []byte) *ValidationResult {
	switch msgType {
	case p2p.MsgTypeBlock:
		return v.validateBlockPayload(payload)
	case p2p.MsgTypeTransaction:
		return v.validateTransactionPayload(payload)
	case p2p.MsgTypeVote:
		return v.validateVotePayload(payload)
	case p2p.MsgTypeBlockReq:
		return v.validateBlockRequestPayload(payload)
	case p2p.MsgTypeBlockResp:
		return v.validateBlockResponsePayload(payload)
	case p2p.MsgTypeTxReq:
		return v.validateTxRequestPayload(payload)
	case p2p.MsgTypeTxResp:
		return v.validateTxResponsePayload(payload)
	case p2p.MsgTypeStatus:
		return v.validateStatusPayload(payload)
	case p2p.MsgTypePing, p2p.MsgTypePong:
		// Ping/pong can have any payload
		return &ValidationResult{Valid: true}
	// audit-fix R5-F20: handle all QPOS consensus and extended message types
	case p2p.MsgTypeChallenge, p2p.MsgTypeChallengeResponse:
		// Challenge-response: must have non-empty payload
		if len(payload) == 0 {
			return &ValidationResult{Valid: false, Error: ErrInvalidPayload, Field: "payload", Details: "empty challenge payload"}
		}
		return &ValidationResult{Valid: true}
	case p2p.MsgTypeBatch:
		// Batch must have at least 4 bytes for message count
		if len(payload) < 4 {
			return &ValidationResult{Valid: false, Error: ErrMalformedMessage, Field: "payload", Details: "batch payload too small"}
		}
		return &ValidationResult{Valid: true}
	case p2p.MsgTypeAttestation, p2p.MsgTypeAggregateAttest:
		// Attestation: must have non-empty payload with minimum size for slot+committee data
		if len(payload) < 16 {
			return &ValidationResult{Valid: false, Error: ErrInvalidPayload, Field: "payload", Details: "attestation payload too small"}
		}
		return &ValidationResult{Valid: true}
	case p2p.MsgTypeProposerSlashing, p2p.MsgTypeAttesterSlashing:
		// Slashing evidence: must have non-empty payload
		if len(payload) == 0 {
			return &ValidationResult{Valid: false, Error: ErrInvalidPayload, Field: "payload", Details: "empty slashing payload"}
		}
		return &ValidationResult{Valid: true}
	case p2p.MsgTypeExpert:
		// Expert network messages: must have non-empty payload
		if len(payload) == 0 {
			return &ValidationResult{Valid: false, Error: ErrInvalidPayload, Field: "payload", Details: "empty expert payload"}
		}
		return &ValidationResult{Valid: true}
	default:
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidMsgType,
			Field:   "type",
			Details: fmt.Sprintf("unhandled message type: %d", msgType),
		}
	}
}

func (v *P2PValidator) validateBlockPayload(payload []byte) *ValidationResult {
	if len(payload) == 0 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidBlockData,
			Field:   "payload",
			Details: "empty block payload",
		}
	}

	// Basic structure validation - block should have at least header
	// Minimum block header size is approximately 200 bytes
	if len(payload) < 100 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidBlockData,
			Field:   "payload",
			Details: "block payload too small",
		}
	}

	return &ValidationResult{Valid: true}
}

// validateTransactionPayload validates the format of a transaction payload in P2P messages.
// This is P2P message format validation only, checking minimum size requirements.
// Full transaction validation including nonce monotonicity is enforced at txpool admission.
// nonce monotonicity enforced at txpool admission
// replay attack protection: chain ID is validated at txpool admission and block validation
func (v *P2PValidator) validateTransactionPayload(payload []byte) *ValidationResult {
	if len(payload) == 0 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidTxData,
			Field:   "payload",
			Details: "empty transaction payload",
		}
	}

	// Minimum transaction size (version + type + nonce + chainID + addresses + signature)
	// Note: Chain ID validation for replay attack protection is performed at txpool admission
	if len(payload) < 50 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidTxData,
			Field:   "payload",
			Details: "transaction payload too small",
		}
	}

	return &ValidationResult{Valid: true}
}

func (v *P2PValidator) validateVotePayload(payload []byte) *ValidationResult {
	if len(payload) == 0 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidVoteData,
			Field:   "payload",
			Details: "empty vote payload",
		}
	}

	// Vote should contain: block hash (32) + height (8) + validator address (20) + signature
	if len(payload) < 60 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidVoteData,
			Field:   "payload",
			Details: "vote payload too small",
		}
	}

	return &ValidationResult{Valid: true}
}

func (v *P2PValidator) validateBlockRequestPayload(payload []byte) *ValidationResult {
	// Block request: from_height (8) + to_height (8) + hash_count (4) + hashes
	if len(payload) < 20 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMalformedMessage,
			Field:   "payload",
			Details: "block request payload too small",
		}
	}

	hashCount := binary.BigEndian.Uint32(payload[16:20])
	// audit-fix R5-F21: bound hash count to prevent excessive allocation
	if hashCount > MaxRequestHashes {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMalformedMessage,
			Field:   "payload",
			Details: fmt.Sprintf("block request hash count %d exceeds maximum %d", hashCount, MaxRequestHashes),
		}
	}
	expectedSize := 20 + int(hashCount)*32
	if len(payload) < expectedSize {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMalformedMessage,
			Field:   "payload",
			Details: fmt.Sprintf("expected %d bytes for %d hashes, got %d", expectedSize, hashCount, len(payload)),
		}
	}

	return &ValidationResult{Valid: true}
}

func (v *P2PValidator) validateBlockResponsePayload(payload []byte) *ValidationResult {
	// Block response can be empty (no blocks found)
	return &ValidationResult{Valid: true}
}

// validateTxRequestPayload validates the format of a transaction request message.
// This is P2P message format validation only, not transaction content validation.
// nonce monotonicity enforced at txpool admission, not in P2P message validation
// replay attack protection: chain ID validation is performed at txpool admission
func (v *P2PValidator) validateTxRequestPayload(payload []byte) *ValidationResult {
	// Transaction request: hash_count (4) + hashes
	if len(payload) < 4 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMalformedMessage,
			Field:   "payload",
			Details: "tx request payload too small",
		}
	}

	hashCount := binary.BigEndian.Uint32(payload[0:4])
	// audit-fix R5-F21: bound hash count to prevent excessive allocation
	if hashCount > MaxRequestHashes {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMalformedMessage,
			Field:   "payload",
			Details: fmt.Sprintf("tx request hash count %d exceeds maximum %d", hashCount, MaxRequestHashes),
		}
	}
	expectedSize := 4 + int(hashCount)*32
	if len(payload) < expectedSize {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMalformedMessage,
			Field:   "payload",
			Details: fmt.Sprintf("expected %d bytes for %d hashes, got %d", expectedSize, hashCount, len(payload)),
		}
	}

	return &ValidationResult{Valid: true}
}

// validateTxResponsePayload validates the format of a transaction response message.
// This is P2P message format validation only, not transaction content validation.
// nonce monotonicity enforced at txpool admission, not in P2P message validation
// replay attack protection: chain ID validation is performed at txpool admission
func (v *P2PValidator) validateTxResponsePayload(payload []byte) *ValidationResult {
	// Transaction response can be empty (no transactions found)
	return &ValidationResult{Valid: true}
}

func (v *P2PValidator) validateStatusPayload(payload []byte) *ValidationResult {
	// Status: version (4) + network_id (8) + best_height (8) + best_hash (32) + genesis_hash (32)
	if len(payload) < 84 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidStatusData,
			Field:   "payload",
			Details: fmt.Sprintf("status payload too small: expected 84 bytes, got %d", len(payload)),
		}
	}

	return &ValidationResult{Valid: true}
}

// audit-fix R5-F20: accept all defined message types, not just 1-10
func isValidMsgType(msgType uint8) bool {
	switch {
	case msgType >= p2p.MsgTypeBlock && msgType <= p2p.MsgTypeBatch:
		return true // types 1-13
	case msgType >= p2p.MsgTypeAttestation && msgType <= p2p.MsgTypeAttesterSlashing:
		return true // types 20-23
	case msgType == p2p.MsgTypeExpert:
		return true // type 30
	default:
		return false
	}
}

// crc32Checksum calculates CRC32 checksum
func crc32Checksum(data []byte) uint32 {
	var crc uint32 = 0xFFFFFFFF
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// ValidateAndDecodeMessage validates and decodes a P2P message
func (v *P2PValidator) ValidateAndDecodeMessage(data []byte) (msgType uint8, payload []byte, err error) {
	result := v.ValidateMessage(data)
	if !result.Valid {
		return 0, nil, result.Error
	}

	msgType = data[0]
	length := binary.BigEndian.Uint32(data[1:5])
	payload = data[MsgHeaderSize : MsgHeaderSize+length]

	return msgType, payload, nil
}
