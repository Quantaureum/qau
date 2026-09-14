// Quantaureum Node source, version 1.0.0.
// Package encoding provides serialization and deserialization for Quantaureum blockchain data structures.
// This file implements receipt (de)serialization for R35-P0-09 persistent receipt storage.
package encoding

import (
	"fmt"

	"github.com/quantaureum/qau/types"
)

// Receipt field tags (protobuf-compatible wire format).
const (
	fieldReceiptTxHash      = 1
	fieldReceiptBlockHash   = 2
	fieldReceiptBlockNumber = 3
	fieldReceiptTxIndex     = 4
	fieldReceiptStatus      = 5
	fieldReceiptGasUsed     = 6
	fieldReceiptLogs        = 7
	fieldReceiptError       = 8

	fieldLogAddress = 1
	fieldLogTopics  = 2
	fieldLogData    = 3
)

// MarshalReceipt serializes a StoredReceipt to bytes using the same
// protobuf-compatible wire format as the rest of the encoding package.
//
// R35-P0-09 FIX: deterministic binary encoding (not JSON) so all nodes
// produce identical bytes for the same receipt.
func MarshalReceipt(r *StoredReceipt) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil receipt", ErrInvalidData)
	}
	w := NewWriteBuffer()

	// Field 1: TxHash (32 bytes)
	w.EncodeBytesField(fieldReceiptTxHash, r.TxHash[:])

	// Field 2: BlockHash (32 bytes)
	w.EncodeBytesField(fieldReceiptBlockHash, r.BlockHash[:])

	// Field 3: BlockNumber (uint64, varint)
	w.EncodeUint64Field(fieldReceiptBlockNumber, r.BlockNumber)

	// Field 4: TxIndex (uint32, varint)
	w.EncodeUint64Field(fieldReceiptTxIndex, uint64(r.TxIndex))

	// Field 5: Status (uint64, varint)
	w.EncodeUint64Field(fieldReceiptStatus, r.Status)

	// Field 6: GasUsed (uint64, varint)
	w.EncodeUint64Field(fieldReceiptGasUsed, r.GasUsed)

	// Field 7: Logs (repeated embedded message)
	for _, log := range r.Logs {
		if log == nil {
			continue
		}
		logData, err := marshalLog(log)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal log: %w", err)
		}
		w.EncodeBytesField(fieldReceiptLogs, logData)
	}

	// Field 8: Error (string)
	if r.Error != "" {
		w.EncodeBytesField(fieldReceiptError, []byte(r.Error))
	}

	return w.Bytes(), nil
}

func marshalLog(log *StoredLog) ([]byte, error) {
	w := NewWriteBuffer()
	// Field 1: Address (32 bytes)
	w.EncodeBytesField(fieldLogAddress, log.Address[:])
	// Field 2: Topics (repeated 32-byte fixed)
	for _, topic := range log.Topics {
		w.EncodeBytesField(fieldLogTopics, topic[:])
	}
	// Field 3: Data (bytes)
	if len(log.Data) > 0 {
		w.EncodeBytesField(fieldLogData, log.Data)
	}
	return w.Bytes(), nil
}

// UnmarshalReceipt deserializes a StoredReceipt from bytes.
func UnmarshalReceipt(data []byte) (*StoredReceipt, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrEmptyData)
	}
	r := &StoredReceipt{}
	buf := NewBuffer(data)

	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
		}

		switch fieldNum {
		case fieldReceiptTxHash:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for TxHash", ErrMalformedMessage)
			}
			b, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: TxHash: %v", ErrMalformedMessage, err)
			}
			if len(b) != 32 {
				return nil, fmt.Errorf("%w: TxHash length %d != 32", ErrMalformedMessage, len(b))
			}
			copy(r.TxHash[:], b)

		case fieldReceiptBlockHash:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for BlockHash", ErrMalformedMessage)
			}
			b, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: BlockHash: %v", ErrMalformedMessage, err)
			}
			if len(b) != 32 {
				return nil, fmt.Errorf("%w: BlockHash length %d != 32", ErrMalformedMessage, len(b))
			}
			copy(r.BlockHash[:], b)

		case fieldReceiptBlockNumber:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for BlockNumber", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: BlockNumber: %v", ErrMalformedMessage, err)
			}
			r.BlockNumber = v

		case fieldReceiptTxIndex:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for TxIndex", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: TxIndex: %v", ErrMalformedMessage, err)
			}
			if v > 0xFFFFFFFF {
				return nil, fmt.Errorf("%w: TxIndex overflow: %d", ErrMalformedMessage, v)
			}
			r.TxIndex = uint32(v) //nolint:gosec,G115

		case fieldReceiptStatus:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for Status", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: Status: %v", ErrMalformedMessage, err)
			}
			r.Status = v

		case fieldReceiptGasUsed:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for GasUsed", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: GasUsed: %v", ErrMalformedMessage, err)
			}
			r.GasUsed = v

		case fieldReceiptLogs:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for Log", ErrMalformedMessage)
			}
			logData, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: Log: %v", ErrMalformedMessage, err)
			}
			log, err := unmarshalLog(logData)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal log: %w", err)
			}
			r.Logs = append(r.Logs, log)

		case fieldReceiptError:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for Error", ErrMalformedMessage)
			}
			b, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: Error: %v", ErrMalformedMessage, err)
			}
			r.Error = string(b)

		default:
			if err := buf.Skip(wireType); err != nil {
				return nil, fmt.Errorf("%w: skip: %v", ErrMalformedMessage, err)
			}
		}
	}

	return r, nil
}

func unmarshalLog(data []byte) (*StoredLog, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty log data", ErrEmptyData)
	}
	log := &StoredLog{}
	buf := NewBuffer(data)

	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
		}

		switch fieldNum {
		case fieldLogAddress:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for Address", ErrMalformedMessage)
			}
			b, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: Address: %v", ErrMalformedMessage, err)
			}
			if len(b) != 32 {
				return nil, fmt.Errorf("%w: Address length %d != 32", ErrMalformedMessage, len(b))
			}
			copy(log.Address[:], b)

		case fieldLogTopics:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for Topic", ErrMalformedMessage)
			}
			b, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: Topic: %v", ErrMalformedMessage, err)
			}
			if len(b) != 32 {
				return nil, fmt.Errorf("%w: Topic length %d != 32", ErrMalformedMessage, len(b))
			}
			var topic types.Hash
			copy(topic[:], b)
			log.Topics = append(log.Topics, topic)

		case fieldLogData:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for Data", ErrMalformedMessage)
			}
			b, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: Data: %v", ErrMalformedMessage, err)
			}
			// Defensive copy: buffer contents may be reused.
			log.Data = append([]byte(nil), b...)

		default:
			if err := buf.Skip(wireType); err != nil {
				return nil, fmt.Errorf("%w: skip: %v", ErrMalformedMessage, err)
			}
		}
	}

	return log, nil
}
