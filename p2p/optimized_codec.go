// Quantaureum Node source, version 1.0.0.
// Package p2p provides optimized peer-to-peer networking for the Quantaureum blockchain.
// This file implements an optimized codec for efficient message serialization and deserialization.
// **Feature: optimized-network-protocol, Requirements 12.1, 12.2, 13.2, 13.3**
package p2p

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// OptimizedCodec provides an optimized encoding/decoding implementation for P2P messages
// with reduced overhead and improved performance compared to the default implementation.
type OptimizedCodec struct {
	// audit-fix R7-6: mutex protects writeBuffer/readBuffer from concurrent access.
	// The global optimizedCodec singleton may be called from multiple goroutines.
	mu sync.Mutex
	// Reusable buffers for encoding/decoding to reduce allocations
	writeBuffer []byte
	readBuffer  []byte
}

// NewOptimizedCodec creates a new OptimizedCodec instance
func NewOptimizedCodec() *OptimizedCodec {
	return &OptimizedCodec{
		writeBuffer: make([]byte, 0, 64*1024), // 64KB initial capacity
		readBuffer:  make([]byte, 0, 64*1024), // 64KB initial capacity
	}
}

// OptimizedMessageHeader represents the optimized message header structure
// Format: [flags(1)] [type(1)] [length(3)] [timestamp(4)]
// Total size: 9 bytes (same as original, but more efficient layout)
type OptimizedMessageHeader struct {
	Flags     uint8  // Compression, encryption flags
	MsgType   uint8  // Message type
	Length    uint32 // Payload length (3 bytes, max ~16MB)
	Timestamp uint32 // Unix timestamp in seconds (4 bytes)
}

// EncodeOptimizedMessage encodes a message using the optimized format
func (c *OptimizedCodec) EncodeOptimizedMessage(msgType uint8, payload []byte, timestamp time.Time) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(payload) > MaxMsgSize {
		return nil, ErrMsgTooLarge
	}

	// Compress payload if needed
	processedPayload, compressed, err := msgCompressor.CompressIfNeeded(payload)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// Build header
	header := OptimizedMessageHeader{
		MsgType:   msgType,
		Length:    uint32(len(processedPayload)), // #nosec G115 -- length is always non-negative
		Timestamp: uint32(timestamp.Unix()),      // #nosec G115 -- value bounded by protocol constraints
	}

	if compressed {
		header.Flags |= MsgFlagCompressed
	}

	// Calculate checksum on processed payload
	checksum := crc32Checksum(processedPayload)

	// Build message: header (9) + payload + checksum (4)
	msgSize := 9 + len(processedPayload) + 4
	if cap(c.writeBuffer) < msgSize {
		c.writeBuffer = make([]byte, msgSize)
	} else {
		c.writeBuffer = c.writeBuffer[:msgSize]
	}

	offset := 0

	// Write flags and type
	c.writeBuffer[offset] = header.Flags
	offset++
	c.writeBuffer[offset] = header.MsgType
	offset++

	// Write length using 3 bytes (0-16,777,215)
	if header.Length > 0xFFFFFF {
		return nil, ErrMsgTooLarge
	}
	c.writeBuffer[offset] = byte(header.Length >> 16)
	c.writeBuffer[offset+1] = byte(header.Length >> 8) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	c.writeBuffer[offset+2] = byte(header.Length)      // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 3

	// Write timestamp (4 bytes)
	binary.BigEndian.PutUint32(c.writeBuffer[offset:offset+4], header.Timestamp)
	offset += 4

	// Write payload
	copy(c.writeBuffer[offset:offset+len(processedPayload)], processedPayload)
	offset += len(processedPayload)

	// Write checksum (4 bytes)
	binary.BigEndian.PutUint32(c.writeBuffer[offset:offset+4], checksum)

	// Return a copy to avoid buffer reuse issues
	result := make([]byte, msgSize)
	copy(result, c.writeBuffer)
	return result, nil
}

// DecodeOptimizedMessage decodes a message using the optimized format
func (c *OptimizedCodec) DecodeOptimizedMessage(data []byte) (*Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(data) < 13 { // Header (9) + minimum checksum (4)
		return nil, ErrMalformedMessage
	}

	offset := 0

	// Read flags and type
	flags := data[offset]
	offset++
	msgType := data[offset]
	offset++

	// Read length using 3 bytes
	length := uint32(data[offset])<<16 | uint32(data[offset+1])<<8 | uint32(data[offset+2])
	offset += 3

	// Read timestamp
	timestamp := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Verify total length
	if offset+int(length)+4 > len(data) {
		return nil, ErrMalformedMessage
	}

	// Read payload
	processedPayload := data[offset : offset+int(length)]
	offset += int(length)

	// Read and verify checksum
	checksum := binary.BigEndian.Uint32(data[offset : offset+4])
	if crc32Checksum(processedPayload) != checksum {
		return nil, ErrInvalidChecksum
	}

	// Check if compressed
	isCompressed := (flags & MsgFlagCompressed) != 0

	// Decompress if needed
	payload, err := msgCompressor.DecompressIfNeeded(processedPayload, isCompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress message: %w", err)
	}

	return &Message{
		Type:      msgType,
		Payload:   payload,
		Timestamp: time.Unix(int64(timestamp), 0),
	}, nil
}

// EncodeOptimizedBatchMessage encodes a batch of messages using an optimized format.
//
// R33 P2P-03 FIX (2026-07-28): Added batch-level timestamp, per-message
// compression flag, and CRC32 checksum to match the single-message format's
// integrity guarantees. Previously the batch format had no checksum (allowing
// silent data corruption), no compression flag (making decompression
// impossible), and used time.Now() on decode (losing the original timestamp).
//
// Batch format:
//
//	[count(2)] [timestamp(4)] [msg1_len(2)] [msg1_type(1)] [msg1_flags(1)] [msg1_payload] ... [crc32(4)]
//
// The CRC32 covers everything from timestamp through the last payload.
func (c *OptimizedCodec) EncodeOptimizedBatchMessage(messages []*Message) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(messages) == 0 {
		return nil, ErrMalformedMessage
	}

	// Precompute total size for batch header
	// Batch format: [count(2)] [timestamp(4)] [msg1_len(2)] [msg1_type(1)] [msg1_flags(1)] [msg1_payload] ... [crc32(4)]
	totalSize := 2 + 4 // count (2) + timestamp (4)

	// Calculate total size and compress messages
	compressedMsgs := make([][]byte, len(messages))
	msgTypes := make([]uint8, len(messages))
	msgFlags := make([]uint8, len(messages))
	msgLengths := make([]uint16, len(messages))

	for i, msg := range messages {
		// Compress payload if needed
		processedPayload, compressed, err := msgCompressor.CompressIfNeeded(msg.Payload)
		if err != nil {
			return nil, fmt.Errorf("compression failed for message %d: %w", i, err)
		}

		compressedMsgs[i] = processedPayload
		msgTypes[i] = msg.Type
		if compressed {
			msgFlags[i] = MsgFlagCompressed
		}
		// audit-fix NEW-23: check uint16 overflow before narrowing
		if len(processedPayload) > 0xFFFF {
			return nil, fmt.Errorf("message %d payload size %d exceeds uint16 max", i, len(processedPayload))
		}
		msgLengths[i] = uint16(len(processedPayload))  // #nosec G115 - overflow checked above
		totalSize += 2 + 1 + 1 + len(processedPayload) // len(2) + type(1) + flags(1) + payload
	}

	totalSize += 4 // CRC32 (4 bytes)

	// Build batch
	if cap(c.writeBuffer) < totalSize {
		c.writeBuffer = make([]byte, totalSize)
	} else {
		c.writeBuffer = c.writeBuffer[:totalSize]
	}

	offset := 0

	// Write message count (2 bytes)
	binary.BigEndian.PutUint16(c.writeBuffer[offset:offset+2], uint16(len(messages))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 2

	// Write batch timestamp (4 bytes)
	batchTimestamp := uint32(time.Now().Unix()) // #nosec G115 -- bounded by protocol constraints
	binary.BigEndian.PutUint32(c.writeBuffer[offset:offset+4], batchTimestamp)
	offset += 4

	// Write messages
	for i := range messages {
		// Write message length (2 bytes)
		binary.BigEndian.PutUint16(c.writeBuffer[offset:offset+2], msgLengths[i])
		offset += 2

		// Write message type (1 byte)
		c.writeBuffer[offset] = msgTypes[i]
		offset += 1

		// Write message flags (1 byte) — R33 P2P-03 FIX
		c.writeBuffer[offset] = msgFlags[i]
		offset += 1

		// Write payload
		copy(c.writeBuffer[offset:offset+int(msgLengths[i])], compressedMsgs[i])
		offset += int(msgLengths[i])
	}

	// Write CRC32 (4 bytes) — covers timestamp through last payload — R33 P2P-03 FIX
	crcStart := 2 // after count
	crcEnd := offset
	checksum := crc32Checksum(c.writeBuffer[crcStart:crcEnd])
	binary.BigEndian.PutUint32(c.writeBuffer[offset:offset+4], checksum)

	// Return a copy to avoid buffer reuse issues
	result := make([]byte, totalSize)
	copy(result, c.writeBuffer)
	return result, nil
}

// DecodeOptimizedBatchMessage decodes a batch of messages using the optimized format.
//
// R33 P2P-03 FIX (2026-07-28): Added CRC32 verification, per-message
// compression flag handling, and batch-level timestamp reading.
func (c *OptimizedCodec) DecodeOptimizedBatchMessage(data []byte) ([]*Message, error) {
	// Minimum: count(2) + timestamp(4) + crc32(4) = 10
	if len(data) < 10 {
		return nil, ErrMalformedMessage
	}

	// Read message count
	msgCount := binary.BigEndian.Uint16(data[:2])
	if msgCount == 0 {
		return nil, ErrMalformedMessage
	}
	// SECURITY (audit DATA-07): Cap message count to MaxBatchMessages (1000),
	// matching the cap in DecodeBatchMessage (message.go). Without this, a
	// 2-byte input forces a 524KB pre-allocation (65535 * 8 bytes on 64-bit).
	if msgCount > MaxBatchMessages {
		return nil, ErrMalformedMessage
	}

	// Read batch timestamp (4 bytes) — R33 P2P-03 FIX
	batchTimestamp := binary.BigEndian.Uint32(data[2:6])
	batchTime := time.Unix(int64(batchTimestamp), 0) // #nosec G115 -- bounded by protocol constraints

	offset := 6 // after count(2) + timestamp(4)

	messages := make([]*Message, 0, msgCount)

	for i := uint16(0); i < msgCount; i++ {
		// Check if we have enough data for message header: len(2) + type(1) + flags(1) = 4
		if offset+4 > len(data) {
			return nil, ErrMalformedMessage
		}

		// Read message length (2 bytes)
		msgLen := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// Read message type (1 byte)
		msgType := data[offset] // #nosec G602 -- offset bounded by `offset+4 > len(data)` check above
		offset += 1

		// Read message flags (1 byte) — R33 P2P-03 FIX
		msgFlags := data[offset] // #nosec G602 -- offset bounded by `offset+4 > len(data)` check above
		offset += 1

		// Check if we have enough data for payload (plus 4 for trailing CRC32)
		if offset+int(msgLen)+4 > len(data) {
			return nil, ErrMalformedMessage
		}

		// Read payload
		processedPayload := data[offset : offset+int(msgLen)]
		offset += int(msgLen)

		// Decompress if needed — R33 P2P-03 FIX
		isCompressed := (msgFlags & MsgFlagCompressed) != 0
		payload, err := msgCompressor.DecompressIfNeeded(processedPayload, isCompressed)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress batch message %d: %w", i, err)
		}

		// Create message with batch timestamp — R33 P2P-03 FIX (was time.Now())
		messages = append(messages, &Message{
			Type:      msgType,
			Payload:   payload,
			Timestamp: batchTime,
		})
	}

	// Verify CRC32 — R33 P2P-03 FIX
	// CRC covers from timestamp (offset 2) through the last payload (offset).
	if offset+4 > len(data) {
		return nil, ErrMalformedMessage
	}
	expectedCRC := binary.BigEndian.Uint32(data[offset : offset+4])
	actualCRC := crc32Checksum(data[2:offset]) // #nosec G602 -- offset bounded by loop+payload checks
	if expectedCRC != actualCRC {
		return nil, ErrInvalidChecksum
	}

	return messages, nil
}

// OptimizedStatusMessage provides an optimized format for status messages
// Reduces redundant fields and uses variable-length encoding
func (c *OptimizedCodec) EncodeOptimizedStatusMessage(status *StatusMessage) []byte {
	// Format: [version(1)] [network_id(2)] [best_height(8)] [best_hash(32)] [genesis_hash(32)]
	// Total: 1+2+8+32+32 = 75 bytes (down from 84 bytes)
	data := make([]byte, 75)
	offset := 0

	// Version (1 byte, max 255)
	// audit-fix NEW-23: check uint32→byte overflow before narrowing
	if status.Version > 0xFF {
		data[offset] = 0xFF // saturate to max; callers should use standard codec for version > 255
	} else {
		data[offset] = byte(status.Version) // #nosec G115 - overflow checked above
	}
	offset++

	// NetworkID (2 bytes, max 65535)
	// audit-fix NEW-23: check uint64→uint16 overflow before narrowing
	if status.NetworkID > 0xFFFF {
		binary.BigEndian.PutUint16(data[offset:offset+2], 0xFFFF) // saturate; callers should use standard codec
	} else {
		binary.BigEndian.PutUint16(data[offset:offset+2], uint16(status.NetworkID)) // #nosec G115 - overflow checked above
	}
	offset += 2

	// BestHeight (4 bytes)
	binary.BigEndian.PutUint64(data[offset:offset+8], status.BestHeight)
	offset += 8

	// BestHash (32 bytes)
	copy(data[offset:offset+32], status.BestHash[:])
	offset += 32

	// GenesisHash (32 bytes)
	copy(data[offset:offset+32], status.GenesisHash[:])

	return data
}

// DecodeOptimizedStatusMessage decodes an optimized status message
func (c *OptimizedCodec) DecodeOptimizedStatusMessage(data []byte) (*StatusMessage, error) {
	if len(data) < 75 {
		return nil, ErrMalformedMessage
	}

	offset := 0
	status := &StatusMessage{}

	// Version (1 byte)
	status.Version = uint32(data[offset])
	offset++

	// NetworkID (2 bytes)
	status.NetworkID = uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// BestHeight (4 bytes)
	status.BestHeight = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	// BestHash (32 bytes)
	copy(status.BestHash[:], data[offset:offset+32])
	offset += 32

	// GenesisHash (32 bytes)
	copy(status.GenesisHash[:], data[offset:offset+32])

	return status, nil
}
