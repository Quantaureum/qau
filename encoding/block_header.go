// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"fmt"
	"math"
	"math/big"

	"github.com/quantaureum/qau/types"
)

// BlockHeader field numbers (protobuf compatible)
const (
	fieldHeaderVersion      = 1
	fieldHeaderHeight       = 2
	fieldHeaderTimestamp    = 3
	fieldHeaderParentHash   = 4
	fieldHeaderStateRoot    = 5
	fieldHeaderTxRoot       = 6
	fieldHeaderReceiptRoot  = 7
	fieldHeaderProposerAddr = 8
	fieldHeaderVRFProof     = 9
	fieldHeaderVRFValue     = 10
	fieldHeaderSignature    = 11
	// QPOS consensus fields
	fieldHeaderSlot           = 12
	fieldHeaderEpoch          = 13
	fieldHeaderRANDAOReveal   = 14
	fieldHeaderAttestations   = 15
	fieldHeaderJustifiedEpoch = 16
	fieldHeaderFinalizedEpoch = 17
	// audit-fix H-1: chain ID for cross-chain replay protection
	fieldHeaderChainID           = 18
	fieldHeaderBaseFee           = 19 // EIP-1559: base fee per gas
	fieldHeaderGasUsed           = 20 // EIP-1559: total gas used in block
	fieldHeaderGasLimit          = 21 // Gas limit for this block
	fieldHeaderSyncCommitteeSig  = 22 // Aggregated sync committee signature
	fieldHeaderSyncCommitteeBits = 23 // Sync committee participation bitfield
	fieldHeaderExcessBlobGas     = 24 // EIP-4844: excess blob gas
	fieldHeaderBlobGasUsed       = 25 // EIP-4844: blob gas used in this block
	fieldHeaderDAAttestation     = 26 // Danksharding: aggregated DA attestation
	fieldHeaderDABlobCommitments = 27 // Danksharding: serialized blob KZG commitments
	// audit-fix L5-001: KeyVersion for key rotation safety
	fieldHeaderKeyVersion = 28 // Signing key version for rotation-safe validation
	// audit-fix L5-002: Stardust Consensus fields
	fieldHeaderQTDSignature          = 29 // Executive Chamber QTD threshold signature
	fieldHeaderReviewAttestationRoot = 30 // Review Chamber Merkle root of attestation votes
	fieldHeaderExecutiveSealers      = 31 // Executive Chamber committee member indices
	fieldHeaderFinalityType          = 32 // 0=CasperFFG, 1=QTDInstant
	// R54-ACC (2026-08-07): per-epoch VRF accumulator carried ON-CHAIN so
	// proposer election is a deterministic function of verified headers,
	// eliminating path-dependent local-state divergence (the chain-fork root cause).
	fieldHeaderVRFAccumulator = 33 // per-epoch VRF accumulator at block production time
)

// MarshalBlockHeader serializes a BlockHeader to bytes using protobuf wire format
func MarshalBlockHeader(h *BlockHeader) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: nil header", ErrInvalidData)
	}

	buf := NewWriteBuffer()

	// Field 1: version (uint32)
	buf.EncodeUint32Field(fieldHeaderVersion, h.Version)

	// Field 2: height (uint64)
	buf.EncodeUint64Field(fieldHeaderHeight, h.Height)

	// Field 3: timestamp (int64)
	buf.EncodeInt64Field(fieldHeaderTimestamp, h.Timestamp)

	// Field 4: parent_hash (bytes)
	buf.EncodeBytesField(fieldHeaderParentHash, h.ParentHash[:])

	// Field 5: state_root (bytes)
	buf.EncodeBytesField(fieldHeaderStateRoot, h.StateRoot[:])

	// Field 6: tx_root (bytes)
	buf.EncodeBytesField(fieldHeaderTxRoot, h.TxRoot[:])

	// Field 7: receipt_root (bytes)
	buf.EncodeBytesField(fieldHeaderReceiptRoot, h.ReceiptRoot[:])

	// Field 8: proposer_addr (bytes)
	buf.EncodeBytesField(fieldHeaderProposerAddr, h.ProposerAddr[:])

	// Field 9: vrf_proof (bytes)
	buf.EncodeBytesField(fieldHeaderVRFProof, h.VRFProof)

	// Field 10: vrf_value (bytes)
	buf.EncodeBytesField(fieldHeaderVRFValue, h.VRFValue[:])

	// Field 11: signature (bytes)
	buf.EncodeBytesField(fieldHeaderSignature, h.Signature)

	// QPOS consensus fields
	// Field 12: slot (uint64)
	if h.Slot > 0 {
		buf.EncodeUint64Field(fieldHeaderSlot, h.Slot)
	}

	// Field 13: epoch (uint64)
	if h.Epoch > 0 {
		buf.EncodeUint64Field(fieldHeaderEpoch, h.Epoch)
	}

	// Field 14: randao_reveal (bytes)
	if h.RANDAOReveal != (types.Hash{}) {
		buf.EncodeBytesField(fieldHeaderRANDAOReveal, h.RANDAOReveal[:])
	}

	// Field 15: attestations (bytes)
	if len(h.Attestations) > 0 {
		buf.EncodeBytesField(fieldHeaderAttestations, h.Attestations)
	}

	// Field 16: justified_epoch (uint64)
	if h.JustifiedEpoch > 0 {
		buf.EncodeUint64Field(fieldHeaderJustifiedEpoch, h.JustifiedEpoch)
	}

	// Field 17: finalized_epoch (uint64)
	if h.FinalizedEpoch > 0 {
		buf.EncodeUint64Field(fieldHeaderFinalizedEpoch, h.FinalizedEpoch)
	}

	// R40-M5 FIX: Use EncodeUint64FieldAlways to ensure ChainID is always present
	// in the wire format, even when zero. EncodeUint64Field silently skips zero
	// values per protobuf convention, which broke the original "always encode" intent.
	buf.EncodeUint64FieldAlways(fieldHeaderChainID, h.ChainID)

	if h.BaseFee != nil && h.BaseFee.Sign() > 0 {
		buf.EncodeBytesField(fieldHeaderBaseFee, h.BaseFee.Bytes())
	}

	if h.GasUsed > 0 {
		buf.EncodeUint64Field(fieldHeaderGasUsed, h.GasUsed)
	}

	if h.GasLimit > 0 {
		buf.EncodeUint64Field(fieldHeaderGasLimit, h.GasLimit)
	}

	if h.ExcessBlobGas > 0 {
		buf.EncodeUint64Field(fieldHeaderExcessBlobGas, h.ExcessBlobGas)
	}

	if h.BlobGasUsed > 0 {
		buf.EncodeUint64Field(fieldHeaderBlobGasUsed, h.BlobGasUsed)
	}

	if len(h.SyncCommitteeSig) > 0 {
		buf.EncodeBytesField(fieldHeaderSyncCommitteeSig, h.SyncCommitteeSig)
	}

	if len(h.SyncCommitteeBits) > 0 {
		buf.EncodeBytesField(fieldHeaderSyncCommitteeBits, h.SyncCommitteeBits)
	}

	if len(h.DAAttestation) > 0 {
		buf.EncodeBytesField(fieldHeaderDAAttestation, h.DAAttestation)
	}

	if len(h.DABlobCommitments) > 0 {
		buf.EncodeBytesField(fieldHeaderDABlobCommitments, h.DABlobCommitments)
	}

	// audit-fix L5-001: KeyVersion must always be serialized for key rotation safety.
	// Without this, blocks signed with different key versions have the same hash,
	// making key rotation security mechanism completely ineffective.
	buf.EncodeUint64FieldAlways(fieldHeaderKeyVersion, h.KeyVersion)

	// audit-fix L5-002: Stardust Consensus fields must be serialized.
	// Without these, QTD instant finality data is lost and block hashes
	// don't reflect QTD signatures, allowing replay of old blocks.
	if len(h.QTDSignature) > 0 {
		buf.EncodeBytesField(fieldHeaderQTDSignature, h.QTDSignature)
	}

	if h.ReviewAttestationRoot != (types.Hash{}) {
		buf.EncodeBytesField(fieldHeaderReviewAttestationRoot, h.ReviewAttestationRoot[:])
	}

	if len(h.ExecutiveSealers) > 0 {
		buf.EncodeBytesField(fieldHeaderExecutiveSealers, h.ExecutiveSealers)
	}

	// FinalityType: always encode (small uint, 0=CasperFFG default)
	buf.EncodeUint32Field(fieldHeaderFinalityType, uint32(h.FinalityType))

	// R54-ACC: per-epoch VRF accumulator (bytes). Always encode so the
	// on-chain value participates in the block hash and is verifiable.
	if h.VRFAccumulator != (types.Hash{}) {
		buf.EncodeBytesField(fieldHeaderVRFAccumulator, h.VRFAccumulator[:])
	}

	return buf.Bytes(), nil
}

// UnmarshalBlockHeader deserializes a BlockHeader from bytes
func UnmarshalBlockHeader(data []byte) (*BlockHeader, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrEmptyData)
	}

	buf := NewBuffer(data)
	h := &BlockHeader{}

	// L19-001/L19-002 FIX: Track seen fields to detect duplicate fields.
	// All BlockHeader fields are non-repeatable (single-value), so any
	// duplicate field indicates a malformed or malicious message that
	// could be used for field overwriting / malleability attacks.
	seenFields := make(map[int]bool)

	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
		}

		// L19-001/L19-002 FIX: Reject duplicate fields.
		// All BlockHeader fields are non-repeatable.
		if seenFields[fieldNum] {
			return nil, fmt.Errorf("%w: duplicate field %d in block header", ErrMalformedMessage, fieldNum)
		}
		seenFields[fieldNum] = true

		switch fieldNum {
		case fieldHeaderVersion:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for version", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// Safe conversion: check for uint32 overflow
			if v > math.MaxUint32 {
				return nil, fmt.Errorf("%w: version value %d exceeds uint32 max", ErrMalformedMessage, v)
			}
			h.Version = uint32(v)

		case fieldHeaderHeight:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for height", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.Height = v

		case fieldHeaderTimestamp:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for timestamp", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// Safe conversion: check for int64 overflow
			if v > math.MaxInt64 {
				return nil, fmt.Errorf("%w: timestamp value %d exceeds int64 max", ErrMalformedMessage, v)
			}
			h.Timestamp = int64(v)

		case fieldHeaderParentHash:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for parent_hash", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.HashLength {
				return nil, fmt.Errorf("%w: parent_hash must be %d bytes, got %d", ErrInvalidHash, types.HashLength, len(data))
			}
			copy(h.ParentHash[:], data)

		case fieldHeaderStateRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for state_root", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.HashLength {
				return nil, fmt.Errorf("%w: state_root must be %d bytes, got %d", ErrInvalidHash, types.HashLength, len(data))
			}
			copy(h.StateRoot[:], data)

		case fieldHeaderTxRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for tx_root", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.HashLength {
				return nil, fmt.Errorf("%w: tx_root must be %d bytes, got %d", ErrInvalidHash, types.HashLength, len(data))
			}
			copy(h.TxRoot[:], data)

		case fieldHeaderReceiptRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for receipt_root", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.HashLength {
				return nil, fmt.Errorf("%w: receipt_root must be %d bytes, got %d", ErrInvalidHash, types.HashLength, len(data))
			}
			copy(h.ReceiptRoot[:], data)

		case fieldHeaderProposerAddr:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for proposer_addr", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.AddressLength {
				return nil, fmt.Errorf("%w: proposer_addr must be %d bytes, got %d", ErrInvalidAddress, types.AddressLength, len(data))
			}
			copy(h.ProposerAddr[:], data)

		case fieldHeaderVRFProof:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for vrf_proof", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.VRFProof = data

		case fieldHeaderVRFValue:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for vrf_value", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.HashLength {
				return nil, fmt.Errorf("%w: vrf_value must be %d bytes, got %d", ErrInvalidHash, types.HashLength, len(data))
			}
			copy(h.VRFValue[:], data)

		case fieldHeaderSignature:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for signature", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.Signature = data

		// QPOS consensus fields
		case fieldHeaderSlot:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for slot", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.Slot = v

		case fieldHeaderEpoch:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for epoch", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.Epoch = v

		case fieldHeaderRANDAOReveal:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for randao_reveal", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.HashLength {
				return nil, fmt.Errorf("%w: randao_reveal must be %d bytes, got %d", ErrInvalidHash, types.HashLength, len(data))
			}
			copy(h.RANDAOReveal[:], data)

		case fieldHeaderAttestations:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for attestations", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.Attestations = data

		case fieldHeaderJustifiedEpoch:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for justified_epoch", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.JustifiedEpoch = v

		case fieldHeaderFinalizedEpoch:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for finalized_epoch", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.FinalizedEpoch = v

		// audit-fix H-1: chain_id for cross-chain replay protection
		case fieldHeaderChainID:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for chain_id", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.ChainID = v

		case fieldHeaderBaseFee:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for base_fee", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L9-038 FIX: Limit BaseFee to 32 bytes to prevent unbounded
			// big.Int allocation from malicious or malformed input.
			if len(data) > 32 {
				return nil, fmt.Errorf("%w: base_fee exceeds 32-byte limit (got %d)", ErrMalformedMessage, len(data))
			}
			h.BaseFee = new(big.Int).SetBytes(data)

		case fieldHeaderGasUsed:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for gas_used", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.GasUsed = v

		case fieldHeaderGasLimit:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for gas_limit", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.GasLimit = v

		case fieldHeaderSyncCommitteeSig:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for sync_committee_sig", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.SyncCommitteeSig = data

		case fieldHeaderSyncCommitteeBits:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for sync_committee_bits", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.SyncCommitteeBits = data

		case fieldHeaderExcessBlobGas:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for excess_blob_gas", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.ExcessBlobGas = v

		case fieldHeaderBlobGasUsed:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for blob_gas_used", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.BlobGasUsed = v

		case fieldHeaderDAAttestation:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for da_attestation", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.DAAttestation = data

		case fieldHeaderDABlobCommitments:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for da_blob_commitments", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.DABlobCommitments = data

		case fieldHeaderKeyVersion:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for key_version", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.KeyVersion = v

		case fieldHeaderQTDSignature:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for qtd_signature", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.QTDSignature = data

		case fieldHeaderReviewAttestationRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for review_attestation_root", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.HashLength {
				return nil, fmt.Errorf("%w: review_attestation_root must be %d bytes, got %d", ErrInvalidHash, types.HashLength, len(data))
			}
			copy(h.ReviewAttestationRoot[:], data)

		case fieldHeaderExecutiveSealers:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for executive_sealers", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			h.ExecutiveSealers = data

		case fieldHeaderFinalityType:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for finality_type", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if v > 255 {
				return nil, fmt.Errorf("%w: finality_type value %d exceeds uint8 max", ErrMalformedMessage, v)
			}
			h.FinalityType = uint8(v)

		case fieldHeaderVRFAccumulator:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for vrf_accumulator", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.HashLength {
				return nil, fmt.Errorf("%w: vrf_accumulator must be %d bytes, got %d", ErrInvalidHash, types.HashLength, len(data))
			}
			copy(h.VRFAccumulator[:], data)

		default:
			// Skip unknown fields
			if err := buf.Skip(wireType); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
		}
	}

	return h, nil
}
