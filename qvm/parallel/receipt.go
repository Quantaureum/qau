// Quantaureum Node source, version 1.0.0.
// Package parallel implements Block-STM parallel transaction execution.
package parallel

import (
	"encoding/binary"
	"errors"

	"github.com/quantaureum/qau/types"
)

// Maximum limits for deserialization to prevent OOM from malicious input.
const (
	MaxReceiptLogs = 10000   // Maximum number of logs per receipt
	MaxLogTopics   = 8       // Maximum number of topics per log (LOG4 = 4 topics + margin)
	MaxLogDataSize = 1 << 20 // Maximum data size per log (1 MB)
	MaxErrorLen    = 1 << 16 // Maximum error string length (64 KB)
)

// Serialization errors
var (
	ErrInvalidReceiptData = errors.New("invalid receipt data")
	ErrInvalidLogData     = errors.New("invalid log data")
	ErrReceiptTooLarge    = errors.New("receipt exceeds maximum allowed size")
	// QV-06 FIX: Return an error when the serialized data contains trailing
	// bytes after a valid receipt, which would indicate corruption or a
	// format mismatch.
	ErrTrailingReceiptData = errors.New("trailing data after receipt")
)

// MarshalReceipt serializes a Receipt to bytes.
func MarshalReceipt(r *Receipt) ([]byte, error) {
	if r == nil {
		return nil, ErrInvalidReceiptData
	}

	// Calculate total size
	size := 32 + 8 + 8 + 8   // TxHash + TxIndex + Status + GasUsed
	size += 4 + len(r.Error) // Error length + Error string
	size += 4                // Logs count

	for _, log := range r.Logs {
		size += 20                     // Address
		size += 4 + len(log.Topics)*32 // Topics count + Topics
		size += 4 + len(log.Data)      // Data length + Data
	}

	buf := make([]byte, size)
	offset := 0

	// TxHash (32 bytes)
	copy(buf[offset:], r.TxHash[:])
	offset += 32

	// TxIndex (8 bytes, int64)
	binary.BigEndian.PutUint64(buf[offset:], uint64(r.TxIndex)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	// Status (8 bytes)
	binary.BigEndian.PutUint64(buf[offset:], r.Status)
	offset += 8

	// GasUsed (8 bytes)
	binary.BigEndian.PutUint64(buf[offset:], r.GasUsed)
	offset += 8

	// Error (4 bytes length + string)
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(r.Error))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4
	copy(buf[offset:], r.Error)
	offset += len(r.Error)

	// Logs count (4 bytes)
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(r.Logs))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4

	// Logs
	for _, log := range r.Logs {
		// Address (20 bytes)
		copy(buf[offset:], log.Address[:])
		offset += 20

		// Topics count (4 bytes)
		binary.BigEndian.PutUint32(buf[offset:], uint32(len(log.Topics))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		offset += 4

		// Topics (32 bytes each)
		for _, topic := range log.Topics {
			copy(buf[offset:], topic[:])
			offset += 32
		}

		// Data length (4 bytes) + Data
		binary.BigEndian.PutUint32(buf[offset:], uint32(len(log.Data))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		offset += 4
		copy(buf[offset:], log.Data)
		offset += len(log.Data)
	}

	return buf, nil
}

// UnmarshalReceipt deserializes a Receipt from bytes.
func UnmarshalReceipt(data []byte) (*Receipt, error) {
	if len(data) < 32+8+8+8+4+4 { // Minimum size
		return nil, ErrInvalidReceiptData
	}

	r := &Receipt{}
	offset := 0

	// TxHash (32 bytes)
	copy(r.TxHash[:], data[offset:offset+32])
	offset += 32

	// TxIndex (8 bytes)
	r.TxIndex = int(binary.BigEndian.Uint64(data[offset:])) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	// Status (8 bytes)
	r.Status = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// GasUsed (8 bytes)
	r.GasUsed = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Error length (4 bytes)
	if offset+4 > len(data) {
		return nil, ErrInvalidReceiptData
	}
	errorLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if errorLen > MaxErrorLen {
		return nil, ErrReceiptTooLarge
	}

	// Error string
	if offset+int(errorLen) > len(data) {
		return nil, ErrInvalidReceiptData
	}
	r.Error = string(data[offset : offset+int(errorLen)])
	offset += int(errorLen)

	// Logs count (4 bytes)
	if offset+4 > len(data) {
		return nil, ErrInvalidReceiptData
	}
	logsCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if logsCount > MaxReceiptLogs {
		return nil, ErrReceiptTooLarge
	}

	// Logs
	r.Logs = make([]*Log, logsCount)
	for i := uint32(0); i < logsCount; i++ {
		log := &Log{}

		// Address (20 bytes)
		if offset+20 > len(data) {
			return nil, ErrInvalidLogData
		}
		copy(log.Address[:], data[offset:offset+20])
		offset += 20

		// Topics count (4 bytes)
		if offset+4 > len(data) {
			return nil, ErrInvalidLogData
		}
		topicsCount := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		if topicsCount > MaxLogTopics {
			return nil, ErrReceiptTooLarge
		}

		// Topics (32 bytes each)
		log.Topics = make([]types.Hash, topicsCount)
		for j := uint32(0); j < topicsCount; j++ {
			if offset+32 > len(data) {
				return nil, ErrInvalidLogData
			}
			copy(log.Topics[j][:], data[offset:offset+32])
			offset += 32
		}

		// Data length (4 bytes)
		if offset+4 > len(data) {
			return nil, ErrInvalidLogData
		}
		dataLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		if dataLen > MaxLogDataSize {
			return nil, ErrReceiptTooLarge
		}

		// Data
		if offset+int(dataLen) > len(data) {
			return nil, ErrInvalidLogData
		}
		log.Data = make([]byte, dataLen)
		copy(log.Data, data[offset:offset+int(dataLen)])
		offset += int(dataLen)

		r.Logs[i] = log
	}

	// QV-06 FIX: Ensure all bytes in the input were consumed. Trailing bytes
	// indicate corruption or a format mismatch and should not be silently
	// ignored.
	if offset != len(data) {
		return nil, ErrTrailingReceiptData
	}

	return r, nil
}

// Equal compares two Receipts for equality.
func (r *Receipt) Equal(other *Receipt) bool {
	if r == nil || other == nil {
		return r == other
	}

	if r.TxHash != other.TxHash {
		return false
	}
	if r.TxIndex != other.TxIndex {
		return false
	}
	if r.Status != other.Status {
		return false
	}
	if r.GasUsed != other.GasUsed {
		return false
	}
	if r.Error != other.Error {
		return false
	}
	if len(r.Logs) != len(other.Logs) {
		return false
	}

	for i, log := range r.Logs {
		otherLog := other.Logs[i]
		if log.Address != otherLog.Address {
			return false
		}
		if len(log.Topics) != len(otherLog.Topics) {
			return false
		}
		for j, topic := range log.Topics {
			if topic != otherLog.Topics[j] {
				return false
			}
		}
		if len(log.Data) != len(otherLog.Data) {
			return false
		}
		for j, b := range log.Data {
			if b != otherLog.Data[j] {
				return false
			}
		}
	}

	return true
}
