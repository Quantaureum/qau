// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Block field numbers (protobuf compatible)
const (
	fieldBlockHeader       = 1
	fieldBlockTransactions = 2
)

// MarshalBlock serializes a Block to bytes
func MarshalBlock(b *Block) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: nil block", ErrInvalidData)
	}

	buf := NewWriteBuffer()

	// Field 1: header (embedded message)
	if b.Header != nil {
		headerData, err := MarshalBlockHeader(b.Header)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal header: %w", err)
		}
		buf.EncodeBytesField(fieldBlockHeader, headerData)
	}

	// Field 2: transactions (repeated embedded message)
	for _, tx := range b.Transactions {
		txData, err := MarshalTransaction(tx)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal transaction: %w", err)
		}
		buf.EncodeBytesField(fieldBlockTransactions, txData)
	}

	return buf.Bytes(), nil
}

// Block deserialization limits to prevent memory exhaustion attacks
const (
	// audit-fix CRITICAL: prevent memory exhaustion from unbounded transaction count
	maxTxPerBlock = 10000
	// Maximum size of a single transaction in bytes (1MB)
	maxTxSizeBytes = 1024 * 1024
	// L18-036 FIX: Maximum total block size in bytes (10MB).
	// Prevents memory exhaustion from oversized block data before
	// transaction-level limits are evaluated. Gas limit (20M) at
	// ~16 gas/byte allows ~1.25MB blocks; 10MB gives ample headroom.
	maxBlockSizeBytes = 10 * 1024 * 1024
)

// UnmarshalBlock deserializes a Block from bytes
func UnmarshalBlock(data []byte) (*Block, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrEmptyData)
	}
	// L18-036 FIX: Reject oversized block data to prevent memory exhaustion.
	if len(data) > maxBlockSizeBytes {
		return nil, fmt.Errorf("%w: block size %d exceeds maximum %d", ErrMalformedMessage, len(data), maxBlockSizeBytes)
	}

	buf := NewBuffer(data)
	b := &Block{
		Transactions: make([]*Transaction, 0, 256), // Pre-allocate with reasonable capacity
	}

	// audit-fix CRITICAL: track total transactions to enforce limit
	txCount := 0

	// L19-001 FIX: Track seen fields to detect duplicate non-repeatable fields.
	// fieldBlockTransactions is repeatable (appends to slice), all other
	// fields are non-repeatable and must not appear more than once.
	seenFields := make(map[int]bool)

	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
		}

		// L19-001 FIX: Reject duplicate non-repeatable fields.
		// fieldBlockTransactions legitimately appears multiple times (one per tx).
		if fieldNum != fieldBlockTransactions {
			if seenFields[fieldNum] {
				return nil, fmt.Errorf("%w: duplicate field %d in block", ErrMalformedMessage, fieldNum)
			}
			seenFields[fieldNum] = true
		}

		switch fieldNum {
		case fieldBlockHeader:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for header", ErrMalformedMessage)
			}
			headerData, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			header, err := UnmarshalBlockHeader(headerData)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal header: %w", err)
			}
			b.Header = header

		case fieldBlockTransactions:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for transaction", ErrMalformedMessage)
			}
			txData, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// audit-fix CRITICAL: enforce transaction size limit
			if len(txData) > maxTxSizeBytes {
				return nil, fmt.Errorf("%w: transaction size %d exceeds maximum %d", ErrMalformedMessage, len(txData), maxTxSizeBytes)
			}
			// audit-fix CRITICAL: enforce transaction count limit
			txCount++
			if txCount > maxTxPerBlock {
				return nil, fmt.Errorf("%w: transaction count %d exceeds maximum %d", ErrMalformedMessage, txCount, maxTxPerBlock)
			}
			tx, err := UnmarshalTransaction(txData)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal transaction: %w", err)
			}
			b.Transactions = append(b.Transactions, tx)

		default:
			// Skip unknown fields
			if err := buf.Skip(wireType); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
		}
	}

	// ENC-R11-002 (2026-07-20) FIX: Reject blocks with no header field.
	// Without this check, a peer could send a block containing only
	// transactions (or only unknown fields) and the consumer would receive
	// a *Block with Header == nil — every downstream caller dereferences
	// b.Header (e.g. block_validator.go, adapters.go, RPC handlers) and
	// would panic on nil access. Defense-in-depth: validate at the
	// deserialization boundary so callers can rely on b.Header != nil.
	if b.Header == nil {
		return nil, fmt.Errorf("%w: block missing header field", ErrMalformedMessage)
	}

	return b, nil
}

// MarshalBlockCompact serializes a Block using a compact binary format
// Format: [headerLen(4)] [header] [txCount(4)] [tx1Len(4)] [tx1] [tx2Len(4)] [tx2] ...
func MarshalBlockCompact(b *Block) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: nil block", ErrInvalidData)
	}

	// Marshal header
	headerData, err := MarshalBlockHeader(b.Header)
	if err != nil {
		return nil, err
	}

	// Calculate total size
	totalSize := 4 + len(headerData) + 4 // headerLen + header + txCount
	txDataList := make([][]byte, len(b.Transactions))
	for i, tx := range b.Transactions {
		txData, err := MarshalTransaction(tx)
		if err != nil {
			return nil, err
		}
		txDataList[i] = txData
		totalSize += 4 + len(txData) // txLen + tx
	}

	// Build result
	result := make([]byte, totalSize)
	offset := 0

	// Write header length and header
	// Safe: header data length is bounded by block size limits
	if len(headerData) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: header data too large", ErrInvalidData)
	}
	binary.BigEndian.PutUint32(result[offset:], uint32(len(headerData))) // #nosec G115 - overflow checked above
	offset += 4
	copy(result[offset:], headerData)
	offset += len(headerData)

	// Write transaction count
	if len(b.Transactions) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: too many transactions", ErrInvalidData)
	}
	binary.BigEndian.PutUint32(result[offset:], uint32(len(b.Transactions))) // #nosec G115 - overflow checked above
	offset += 4

	// Write transactions
	for _, txData := range txDataList {
		if len(txData) > math.MaxUint32 {
			return nil, fmt.Errorf("%w: transaction data too large", ErrInvalidData)
		}
		binary.BigEndian.PutUint32(result[offset:], uint32(len(txData))) // #nosec G115 - overflow checked above
		offset += 4
		copy(result[offset:], txData)
		offset += len(txData)
	}

	return result, nil
}

// UnmarshalBlockCompact deserializes a Block from compact binary format
func UnmarshalBlockCompact(data []byte) (*Block, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("%w: data too short", ErrEmptyData)
	}
	// ENC-R11-003 (2026-07-20) FIX: Apply the same maxBlockSizeBytes cap as
	// UnmarshalBlock. The compact format is also accepted from peers, so an
	// attacker could otherwise submit a multi-MB blob and force the node to
	// walk it byte-by-byte before any per-transaction limit kicks in.
	if len(data) > maxBlockSizeBytes {
		return nil, fmt.Errorf("%w: compact block size %d exceeds maximum %d", ErrMalformedMessage, len(data), maxBlockSizeBytes)
	}

	offset := 0

	// Read header length and header
	headerLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// L18-013/L19-005 FIX: Use uint64 for bounds check to prevent int overflow
	// on 32-bit platforms where uint32 values near MaxUint32 would overflow
	// int32 when cast to int, bypassing the length check and causing OOB access.
	if uint64(headerLen) > uint64(len(data))-uint64(offset) {
		return nil, fmt.Errorf("%w: header length exceeds data", ErrMalformedMessage)
	}
	// ENC-R11-003 (2026-07-20) FIX: Per-field size cap mirrors UnmarshalBlock's
	// implicit header budget. A header alone >1MB is malformed.
	if headerLen > maxTxSizeBytes {
		return nil, fmt.Errorf("%w: header length %d exceeds maximum %d", ErrMalformedMessage, headerLen, maxTxSizeBytes)
	}
	headerEnd := offset + int(headerLen) // safe: headerLen <= len(data)-offset

	header, err := UnmarshalBlockHeader(data[offset:headerEnd])
	if err != nil {
		return nil, err
	}
	offset = headerEnd

	// Read transaction count
	if offset+4 > len(data) {
		return nil, fmt.Errorf("%w: missing transaction count", ErrMalformedMessage)
	}
	// L12-033 [P3] NOTE: txCount is uint32 (wire format uses 4-byte big-endian) but
	// make()'s capacity parameter and slice indexing expect int. On 32-bit platforms a
	// uint32 near math.MaxUint32 would overflow int32 (producing a negative/zero capacity),
	// potentially causing a panic in make(). The maxTxPerBlock=10000 cap below mitigates this
	// in practice, but the wire type (uint32) and the in-memory type (int) intentionally differ.
	txCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Cap txCount to prevent excessive allocation from untrusted data
	if txCount > maxTxPerBlock {
		return nil, fmt.Errorf("%w: transaction count %d exceeds maximum %d", ErrMalformedMessage, txCount, maxTxPerBlock)
	}

	// Read transactions
	transactions := make([]*Transaction, 0, txCount)
	for i := uint32(0); i < txCount; i++ {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("%w: missing transaction length", ErrMalformedMessage)
		}
		txLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		// L18-013/L19-005 FIX: Use uint64 for bounds check (same as headerLen).
		if uint64(txLen) > uint64(len(data))-uint64(offset) {
			return nil, fmt.Errorf("%w: transaction length exceeds data", ErrMalformedMessage)
		}
		// ENC-R11-003 (2026-07-20) FIX: Apply per-transaction size cap same
		// as UnmarshalBlock — without this an attacker could pack a single
		// oversized transaction that fits within maxBlockSizeBytes but exceeds
		// maxTxSizeBytes, bypassing per-element validation.
		if txLen > maxTxSizeBytes {
			return nil, fmt.Errorf("%w: compact transaction size %d exceeds maximum %d", ErrMalformedMessage, txLen, maxTxSizeBytes)
		}
		txEnd := offset + int(txLen) // safe: txLen <= len(data)-offset

		tx, err := UnmarshalTransaction(data[offset:txEnd])
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
		offset = txEnd
	}

	return &Block{
		Header:       header,
		Transactions: transactions,
	}, nil
}

// Equal returns true if two Blocks are equal
func (b *Block) Equal(other *Block) bool {
	if b == nil || other == nil {
		return b == other
	}

	if !b.Header.Equal(other.Header) {
		return false
	}

	if len(b.Transactions) != len(other.Transactions) {
		return false
	}

	for i := range b.Transactions {
		if !b.Transactions[i].Equal(other.Transactions[i]) {
			return false
		}
	}

	return true
}

// Validate validates the Block
func (b *Block) Validate() error {
	if b == nil {
		return fmt.Errorf("%w: nil block", ErrInvalidData)
	}

	if b.Header == nil {
		return fmt.Errorf("%w: nil header", ErrInvalidData)
	}

	if err := b.Header.Validate(); err != nil {
		return err
	}

	for i, tx := range b.Transactions {
		if err := tx.Validate(); err != nil {
			return fmt.Errorf("transaction %d: %w", i, err)
		}
	}

	return nil
}
