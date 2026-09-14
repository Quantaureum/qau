// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"errors"
	"fmt"
	"math"

	"github.com/quantaureum/qau/types"
)

var (
	// ErrUnexpectedEOF is returned when data ends unexpectedly
	ErrUnexpectedEOF = errors.New("unexpected end of data")

	// ErrVarintOverflow is returned when a varint is too large
	ErrVarintOverflow = errors.New("varint overflow")

	// ErrInvalidWireType is returned when wire type is invalid
	ErrInvalidWireType = errors.New("invalid wire type")

	// ErrBytesLengthOverflow is returned when bytes length is too large
	ErrBytesLengthOverflow = errors.New("bytes length overflow")

	// ErrTrailingData is returned when there is unexpected trailing data
	ErrTrailingData = errors.New("trailing data after message")
)

// ValidateBlockHeaderData validates raw bytes as a BlockHeader without fully deserializing
// Returns an error if the data is malformed
func ValidateBlockHeaderData(data []byte) error {
	if len(data) == 0 {
		return ErrEmptyData
	}

	buf := NewBuffer(data)
	seenFields := make(map[int]bool)

	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return fmt.Errorf("%w: failed to decode tag: %v", ErrMalformedMessage, err)
		}

		// Validate field number is in expected range
		if fieldNum < 1 || fieldNum > 25 {
			// Unknown field - skip it but don't fail
			if err := buf.Skip(wireType); err != nil {
				return fmt.Errorf("%w: failed to skip unknown field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			continue
		}

		// Check for duplicate fields (protobuf allows this but we don't)
		if seenFields[fieldNum] {
			return fmt.Errorf("%w: duplicate field %d", ErrMalformedMessage, fieldNum)
		}
		seenFields[fieldNum] = true

		// Validate wire type for each field
		switch fieldNum {
		case fieldHeaderVersion, fieldHeaderHeight, fieldHeaderTimestamp:
			if wireType != WireVarint {
				return fmt.Errorf("%w: field %d expected varint, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			if _, err := buf.DecodeVarint(); err != nil {
				return fmt.Errorf("%w: failed to decode varint for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}

		case fieldHeaderParentHash, fieldHeaderStateRoot, fieldHeaderTxRoot, fieldHeaderReceiptRoot, fieldHeaderVRFValue:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) != types.HashLength {
				return fmt.Errorf("%w: field %d expected %d bytes, got %d", ErrInvalidHash, fieldNum, types.HashLength, len(data))
			}

		case fieldHeaderProposerAddr:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) != types.AddressLength {
				return fmt.Errorf("%w: field %d expected %d bytes, got %d", ErrInvalidAddress, fieldNum, types.AddressLength, len(data))
			}

		case fieldHeaderVRFProof, fieldHeaderSignature:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			if _, err := buf.DecodeBytes(); err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
		}
	}

	return nil
}

// isValidTransactionField returns true if the field number is a known transaction field.
// L9-035 FIX: Extended to include EIP-1559/4844 (14-18), multisig (20-23), and privacy (30-36) fields.
func isValidTransactionField(fieldNum int) bool {
	switch fieldNum {
	case 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13: // standard fields
		return true
	case 14, 15, 16, 17, 18: // EIP-1559/4844 fields
		return true
	case 20, 21, 22, 23: // multisig fields
		return true
	case 30, 31, 32, 33, 34, 35, 36: // privacy fields
		return true
	default:
		return false
	}
}

// ValidateTransactionData validates raw bytes as a Transaction without fully deserializing
// Returns an error if the data is malformed
func ValidateTransactionData(data []byte) error {
	if len(data) == 0 {
		return ErrEmptyData
	}

	buf := NewBuffer(data)
	seenFields := make(map[int]bool)

	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return fmt.Errorf("%w: failed to decode tag: %v", ErrMalformedMessage, err)
		}

		// L9-035 FIX: Validate field number is in expected range.
		// Known transaction fields: 1-13 (standard), 14-18 (EIP-1559/4844),
		// 20-23 (multisig), 30-36 (privacy). Fields 19, 24-29 are reserved/gaps.
		if !isValidTransactionField(fieldNum) {
			// Unknown field - skip it but don't fail
			if err := buf.Skip(wireType); err != nil {
				return fmt.Errorf("%w: failed to skip unknown field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			continue
		}

		// Check for duplicate fields
		if seenFields[fieldNum] {
			return fmt.Errorf("%w: duplicate field %d", ErrMalformedMessage, fieldNum)
		}
		seenFields[fieldNum] = true

		// Validate wire type for each field
		switch fieldNum {
		case fieldTxVersion, fieldTxType, fieldTxNonce, fieldTxGasLimit:
			if wireType != WireVarint {
				return fmt.Errorf("%w: field %d expected varint, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return fmt.Errorf("%w: failed to decode varint for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			// Safe conversion: validate transaction type with overflow check
			if fieldNum == fieldTxType {
				if v > math.MaxUint8 {
					return fmt.Errorf("%w: type value %d exceeds valid range", ErrMalformedMessage, v)
				}
				if !TxType(v).IsValid() {
					return fmt.Errorf("%w: %d", ErrInvalidTxType, v)
				}
			}

		// R40-M6 FIX: Validate ChainID field — must be varint and non-zero.
		// Previously ValidateTransactionData did not check for ChainID at all,
		// allowing malformed or replay-vulnerable transactions to pass validation.
		case fieldTxChainID:
			if wireType != WireVarint {
				return fmt.Errorf("%w: field %d (chain_id) expected varint, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return fmt.Errorf("%w: failed to decode varint for field %d (chain_id): %v", ErrMalformedMessage, fieldNum, err)
			}
			if v == 0 {
				return fmt.Errorf("%w: chain_id is zero — replay protection requires a valid chain ID", ErrMalformedMessage)
			}

		case fieldTxFrom, fieldTxTo:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) != types.AddressLength {
				return fmt.Errorf("%w: field %d expected %d bytes, got %d", ErrInvalidAddress, fieldNum, types.AddressLength, len(data))
			}

		case fieldTxValue, fieldTxGasPrice:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 32 {
				return fmt.Errorf("%w: field %d exceeds 32-byte limit (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxData:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 1024*1024 {
				return fmt.Errorf("%w: field %d exceeds 1MB limit (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxSignature:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 3293 {
				return fmt.Errorf("%w: field %d exceeds Dilithium3 signature size limit (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxPublicKey:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			// L16-005 FIX: Validate PublicKey size. Dilithium3 public key is
			// exactly 1952 bytes. Reject oversized keys to prevent abuse.
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 1952 {
				return fmt.Errorf("%w: field %d exceeds Dilithium3 public key size limit 1952 (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxLegacyHash:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			// L16-022 FIX: Add size check for legacy hash.
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) != types.HashLength {
				return fmt.Errorf("%w: field %d expected %d bytes (hash), got %d", ErrMalformedMessage, fieldNum, types.HashLength, len(data))
			}

		// L9-035 FIX: Validate EIP-1559/4844 fields
		case fieldTxMaxFee, fieldTxPriorityFee, fieldTxMaxFeePerBlobGas:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 32 {
				return fmt.Errorf("%w: field %d exceeds 32-byte limit (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxBlobVersionedHashes:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) != types.HashLength {
				return fmt.Errorf("%w: field %d expected %d bytes (hash), got %d", ErrMalformedMessage, fieldNum, types.HashLength, len(data))
			}

		case fieldTxBlobGasUsed:
			if wireType != WireVarint {
				return fmt.Errorf("%w: field %d expected varint, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			if _, err := buf.DecodeVarint(); err != nil {
				return fmt.Errorf("%w: failed to decode varint for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}

		// L9-035 FIX: Validate multisig fields
		case fieldTxMultiSigSignatures:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 3293 {
				return fmt.Errorf("%w: field %d exceeds Dilithium3 signature size limit (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxMultiSigSignerBitmap:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			// L16-022 FIX: Add size check for signer bitmap.
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 128 {
				return fmt.Errorf("%w: field %d exceeds signer bitmap limit 128 (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxMultiSigRequiredSigs, fieldTxMultiSigTotalSigners:
			if wireType != WireVarint {
				return fmt.Errorf("%w: field %d expected varint, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			if _, err := buf.DecodeVarint(); err != nil {
				return fmt.Errorf("%w: failed to decode varint for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}

		// L9-035 FIX: Validate privacy fields
		case fieldTxPrivacyEphemeralPubKey:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			// L16-022 FIX: Add size check for ephemeral public key.
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 2400 {
				return fmt.Errorf("%w: field %d exceeds ephemeral pub key limit 2400 (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxPrivacyStealthAddrHash:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) != types.HashLength {
				return fmt.Errorf("%w: field %d expected %d bytes (hash), got %d", ErrMalformedMessage, fieldNum, types.HashLength, len(data))
			}

		case fieldTxPrivacyCommitments, fieldTxPrivacyEncryptedAmounts, fieldTxPrivacyRangeProofs:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			// L16-022 FIX: Add size check for privacy commitments/amounts/proofs.
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 1024*1024 {
				return fmt.Errorf("%w: field %d exceeds 1MB limit (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxPrivacyBalanceProof:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			// L16-022 FIX: Add size check for balance proof.
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) > 65536 {
				return fmt.Errorf("%w: field %d exceeds balance proof limit 65536 (got %d)", ErrMalformedMessage, fieldNum, len(data))
			}

		case fieldTxPrivacyNullifier:
			if wireType != WireBytes {
				return fmt.Errorf("%w: field %d expected bytes, got wire type %d", ErrMalformedMessage, fieldNum, wireType)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return fmt.Errorf("%w: failed to decode bytes for field %d: %v", ErrMalformedMessage, fieldNum, err)
			}
			if len(data) != types.HashLength {
				return fmt.Errorf("%w: field %d expected %d bytes (hash), got %d", ErrMalformedMessage, fieldNum, types.HashLength, len(data))
			}
		}
	}

	// R40-M6 FIX: Ensure ChainID field was present in the transaction data.
	// A missing ChainID leaves the transaction unbound to any chain, which is
	// equivalent to ChainID=0 and breaks cross-chain replay protection.
	if !seenFields[fieldTxChainID] {
		return fmt.Errorf("%w: missing required chain_id field — replay protection requires a valid chain ID", ErrMalformedMessage)
	}

	return nil
}

// IsMalformed checks if the data is malformed (cannot be parsed as a valid protobuf message)
func IsMalformed(data []byte) bool {
	if len(data) == 0 {
		return true
	}

	buf := NewBuffer(data)

	for buf.Remaining() > 0 {
		_, wireType, err := buf.DecodeTag()
		if err != nil {
			return true
		}

		// Check for invalid wire type
		if wireType < 0 || wireType > 5 || wireType == 3 || wireType == 4 {
			return true
		}

		if err := buf.Skip(wireType); err != nil {
			return true
		}
	}

	return false
}

// ValidateAndUnmarshalBlockHeader validates and unmarshals a BlockHeader in one pass
func ValidateAndUnmarshalBlockHeader(data []byte) (*BlockHeader, error) {
	if err := ValidateBlockHeaderData(data); err != nil {
		return nil, err
	}
	return UnmarshalBlockHeader(data)
}

// ValidateAndUnmarshalTransaction validates and unmarshals a Transaction in one pass
func ValidateAndUnmarshalTransaction(data []byte) (*Transaction, error) {
	if err := ValidateTransactionData(data); err != nil {
		return nil, err
	}
	return UnmarshalTransaction(data)
}
