// Quantaureum Node source, version 1.0.0.
// Package encoding provides serialization for Quantaureum data structures.
// This file implements Attestation serialization for QPOS consensus.
package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/quantaureum/qau/types"
)

// Attestation field numbers
const (
	fieldAttSlot            = 1
	fieldAttBeaconBlockRoot = 2
	fieldAttSourceEpoch     = 3
	fieldAttSourceRoot      = 4
	fieldAttTargetEpoch     = 5
	fieldAttTargetRoot      = 6
	fieldAttValidatorIndex  = 7
	fieldAttSignature       = 8
)

// Attestation represents a validator's vote for a block in QPOS
type Attestation struct {
	Slot            uint64     // Slot being attested
	BeaconBlockRoot types.Hash // Block hash being voted for
	SourceEpoch     uint64     // Last justified epoch
	SourceRoot      types.Hash // Last justified block root
	TargetEpoch     uint64     // Current epoch
	TargetRoot      types.Hash // Current epoch block root
	ValidatorIndex  uint32     // Index of attesting validator
	Signature       []byte     // Dilithium3 signature
}

// MarshalAttestation serializes an Attestation to bytes
func MarshalAttestation(att *Attestation) ([]byte, error) {
	if att == nil {
		return nil, fmt.Errorf("%w: nil attestation", ErrInvalidData)
	}

	buf := NewWriteBuffer()

	// Field 1: slot
	buf.EncodeUint64Field(fieldAttSlot, att.Slot)

	// Field 2: beacon block root
	buf.EncodeBytesField(fieldAttBeaconBlockRoot, att.BeaconBlockRoot[:])

	// Field 3: source epoch
	buf.EncodeUint64Field(fieldAttSourceEpoch, att.SourceEpoch)

	// Field 4: source root
	buf.EncodeBytesField(fieldAttSourceRoot, att.SourceRoot[:])

	// Field 5: target epoch
	buf.EncodeUint64Field(fieldAttTargetEpoch, att.TargetEpoch)

	// Field 6: target root
	buf.EncodeBytesField(fieldAttTargetRoot, att.TargetRoot[:])

	// Field 7: validator index
	buf.EncodeUint32Field(fieldAttValidatorIndex, att.ValidatorIndex)

	// Field 8: signature
	if len(att.Signature) > 0 {
		buf.EncodeBytesField(fieldAttSignature, att.Signature)
	}

	return buf.Bytes(), nil
}

// UnmarshalAttestation deserializes an Attestation from bytes
func UnmarshalAttestation(data []byte) (*Attestation, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrEmptyData)
	}

	buf := NewBuffer(data)
	att := &Attestation{}

	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
		}

		switch fieldNum {
		case fieldAttSlot:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for slot", ErrMalformedMessage)
			}
			att.Slot, err = buf.DecodeVarint()
			if err != nil {
				return nil, err
			}

		case fieldAttBeaconBlockRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for beacon block root", ErrMalformedMessage)
			}
			rootBytes, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(rootBytes) != types.HashLength {
				return nil, fmt.Errorf("%w: beacon block root must be %d bytes, got %d", ErrMalformedMessage, types.HashLength, len(rootBytes))
			}
			copy(att.BeaconBlockRoot[:], rootBytes)

		case fieldAttSourceEpoch:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for source epoch", ErrMalformedMessage)
			}
			att.SourceEpoch, err = buf.DecodeVarint()
			if err != nil {
				return nil, err
			}

		case fieldAttSourceRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for source root", ErrMalformedMessage)
			}
			rootBytes, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(rootBytes) != types.HashLength {
				return nil, fmt.Errorf("%w: source root must be %d bytes, got %d", ErrMalformedMessage, types.HashLength, len(rootBytes))
			}
			copy(att.SourceRoot[:], rootBytes)

		case fieldAttTargetEpoch:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for target epoch", ErrMalformedMessage)
			}
			att.TargetEpoch, err = buf.DecodeVarint()
			if err != nil {
				return nil, err
			}

		case fieldAttTargetRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for target root", ErrMalformedMessage)
			}
			rootBytes, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(rootBytes) != types.HashLength {
				return nil, fmt.Errorf("%w: target root must be %d bytes, got %d", ErrMalformedMessage, types.HashLength, len(rootBytes))
			}
			copy(att.TargetRoot[:], rootBytes)

		case fieldAttValidatorIndex:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for validator index", ErrMalformedMessage)
			}
			idx, err := buf.DecodeVarint()
			if err != nil {
				return nil, err
			}
			// audit-fix R7-2: check for uint32 overflow before truncation
			if idx > math.MaxUint32 {
				return nil, fmt.Errorf("%w: validator index %d exceeds uint32 max", ErrMalformedMessage, idx)
			}
			att.ValidatorIndex = uint32(idx) // #nosec G115 - overflow checked above

		case fieldAttSignature:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for signature", ErrMalformedMessage)
			}
			att.Signature, err = buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			// L14-016 FIX: Limit Signature to Dilithium3 size (3293 bytes).
			if len(att.Signature) > 3293 {
				return nil, fmt.Errorf("%w: signature exceeds 3293 bytes (got %d)", ErrMalformedMessage, len(att.Signature))
			}

		default:
			if err := buf.Skip(wireType); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
		}
	}

	return att, nil
}

// AggregatedAttestation represents multiple attestations aggregated together.
// Phase 3 optimization: AggregatedSignature contains a single QTD threshold signature
// (3293 bytes) when QTD is active. AggregationBits is Snappy-compressed.
type AggregatedAttestation struct {
	Slot                uint64     // Slot being attested
	BeaconBlockRoot     types.Hash // Block hash being voted for
	SourceEpoch         uint64     // Last justified epoch
	SourceRoot          types.Hash // Last justified block root
	TargetEpoch         uint64     // Current epoch
	TargetRoot          types.Hash // Current epoch block root
	AggregationBits     []byte     // Bitmap of participating validators (Snappy compressed)
	AggregatedSignature []byte     // QTD threshold aggregated signature (Phase 3)
	Signature           []byte     // Individual signature (fallback when QTD not available)
}

// AggregatedAttestation field numbers
const (
	fieldAggAttSlot                = 1
	fieldAggAttBeaconBlockRoot     = 2
	fieldAggAttSourceEpoch         = 3
	fieldAggAttSourceRoot          = 4
	fieldAggAttTargetEpoch         = 5
	fieldAggAttTargetRoot          = 6
	fieldAggAttAggregationBits     = 7
	fieldAggAttSignature           = 8
	fieldAggAttAggregatedSignature = 9 // Phase 3: QTD aggregated signature
)

// MarshalAggregatedAttestation serializes an AggregatedAttestation
func MarshalAggregatedAttestation(att *AggregatedAttestation) ([]byte, error) {
	if att == nil {
		return nil, fmt.Errorf("%w: nil aggregated attestation", ErrInvalidData)
	}

	buf := NewWriteBuffer()

	buf.EncodeUint64Field(fieldAggAttSlot, att.Slot)
	buf.EncodeBytesField(fieldAggAttBeaconBlockRoot, att.BeaconBlockRoot[:])
	buf.EncodeUint64Field(fieldAggAttSourceEpoch, att.SourceEpoch)
	buf.EncodeBytesField(fieldAggAttSourceRoot, att.SourceRoot[:])
	buf.EncodeUint64Field(fieldAggAttTargetEpoch, att.TargetEpoch)
	buf.EncodeBytesField(fieldAggAttTargetRoot, att.TargetRoot[:])
	buf.EncodeBytesField(fieldAggAttAggregationBits, att.AggregationBits)
	if len(att.AggregatedSignature) > 0 {
		buf.EncodeBytesField(fieldAggAttAggregatedSignature, att.AggregatedSignature)
	}
	if len(att.Signature) > 0 {
		buf.EncodeBytesField(fieldAggAttSignature, att.Signature)
	}

	return buf.Bytes(), nil
}

// UnmarshalAggregatedAttestation deserializes an AggregatedAttestation
func UnmarshalAggregatedAttestation(data []byte) (*AggregatedAttestation, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrEmptyData)
	}

	buf := NewBuffer(data)
	att := &AggregatedAttestation{}

	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
		}

		switch fieldNum {
		case fieldAggAttSlot:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type", ErrMalformedMessage)
			}
			att.Slot, err = buf.DecodeVarint()
			if err != nil {
				return nil, err
			}

		case fieldAggAttBeaconBlockRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type", ErrMalformedMessage)
			}
			rootBytes, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(rootBytes) != types.HashLength {
				return nil, fmt.Errorf("%w: beacon block root must be %d bytes, got %d", ErrMalformedMessage, types.HashLength, len(rootBytes))
			}
			copy(att.BeaconBlockRoot[:], rootBytes)

		case fieldAggAttSourceEpoch:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type", ErrMalformedMessage)
			}
			att.SourceEpoch, err = buf.DecodeVarint()
			if err != nil {
				return nil, err
			}

		case fieldAggAttSourceRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type", ErrMalformedMessage)
			}
			rootBytes, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(rootBytes) != types.HashLength {
				return nil, fmt.Errorf("%w: source root must be %d bytes, got %d", ErrMalformedMessage, types.HashLength, len(rootBytes))
			}
			copy(att.SourceRoot[:], rootBytes)

		case fieldAggAttTargetEpoch:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type", ErrMalformedMessage)
			}
			att.TargetEpoch, err = buf.DecodeVarint()
			if err != nil {
				return nil, err
			}

		case fieldAggAttTargetRoot:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type", ErrMalformedMessage)
			}
			rootBytes, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(rootBytes) != types.HashLength {
				return nil, fmt.Errorf("%w: target root must be %d bytes, got %d", ErrMalformedMessage, types.HashLength, len(rootBytes))
			}
			copy(att.TargetRoot[:], rootBytes)

		case fieldAggAttAggregationBits:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type", ErrMalformedMessage)
			}
			att.AggregationBits, err = buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			// SECURITY (audit DATA-07): Cap AggregationBits to prevent decode bomb.
			// Snappy-compressed bitmap of participating validators; 4096 bytes
			// supports up to ~32768 validators even uncompressed.
			if len(att.AggregationBits) > 4096 {
				return nil, fmt.Errorf("%w: aggregation bits exceed 4096 bytes (got %d)", ErrMalformedMessage, len(att.AggregationBits))
			}

		case fieldAggAttSignature:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type", ErrMalformedMessage)
			}
			att.Signature, err = buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			// SECURITY (audit DATA-07): Cap individual signature to Dilithium3 size.
			if len(att.Signature) > 3293 {
				return nil, fmt.Errorf("%w: signature exceeds 3293 bytes (got %d)", ErrMalformedMessage, len(att.Signature))
			}

		case fieldAggAttAggregatedSignature:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type", ErrMalformedMessage)
			}
			att.AggregatedSignature, err = buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			// SECURITY (audit DATA-07): Cap aggregated signature. When QTD is
			// active this is a single Dilithium3 threshold signature (3293 bytes).
			// Allow up to 1MB for transitional/fallback aggregated multi-sig.
			if len(att.AggregatedSignature) > 1*1024*1024 {
				return nil, fmt.Errorf("%w: aggregated signature exceeds 1MB (got %d)", ErrMalformedMessage, len(att.AggregatedSignature))
			}

		default:
			if err := buf.Skip(wireType); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
		}
	}

	return att, nil
}

// MarshalAttestationCompact serializes an Attestation using compact binary format
// Format: slot(8) + blockRoot(32) + sourceEpoch(8) + sourceRoot(32) + targetEpoch(8) + targetRoot(32) + validatorIdx(4) + sigLen(2) + sig
func MarshalAttestationCompact(att *Attestation) ([]byte, error) {
	if att == nil {
		return nil, fmt.Errorf("%w: nil attestation", ErrInvalidData)
	}

	sigLen := len(att.Signature)
	// audit-fix NEW-23: check uint16 overflow before narrowing
	if sigLen > math.MaxUint16 {
		return nil, errors.New("signature length exceeds uint16 max")
	}
	totalLen := 8 + 32 + 8 + 32 + 8 + 32 + 4 + 2 + sigLen
	data := make([]byte, totalLen)

	offset := 0
	binary.BigEndian.PutUint64(data[offset:], att.Slot)
	offset += 8

	copy(data[offset:], att.BeaconBlockRoot[:])
	offset += 32

	binary.BigEndian.PutUint64(data[offset:], att.SourceEpoch)
	offset += 8

	copy(data[offset:], att.SourceRoot[:])
	offset += 32

	binary.BigEndian.PutUint64(data[offset:], att.TargetEpoch)
	offset += 8

	copy(data[offset:], att.TargetRoot[:])
	offset += 32

	binary.BigEndian.PutUint32(data[offset:], att.ValidatorIndex)
	offset += 4

	binary.BigEndian.PutUint16(data[offset:], uint16(sigLen)) // #nosec G115 - overflow checked above
	offset += 2

	copy(data[offset:], att.Signature)

	return data, nil
}

// UnmarshalAttestationCompact deserializes an Attestation from compact binary format
func UnmarshalAttestationCompact(data []byte) (*Attestation, error) {
	minLen := 8 + 32 + 8 + 32 + 8 + 32 + 4 + 2 // Without signature
	if len(data) < minLen {
		return nil, fmt.Errorf("%w: data too short", ErrEmptyData)
	}

	att := &Attestation{}
	offset := 0

	att.Slot = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	copy(att.BeaconBlockRoot[:], data[offset:offset+32])
	offset += 32

	att.SourceEpoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	copy(att.SourceRoot[:], data[offset:offset+32])
	offset += 32

	att.TargetEpoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	copy(att.TargetRoot[:], data[offset:offset+32])
	offset += 32

	att.ValidatorIndex = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	sigLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if len(data) < offset+int(sigLen) {
		return nil, fmt.Errorf("%w: signature length exceeds data", ErrMalformedMessage)
	}

	att.Signature = make([]byte, sigLen)
	copy(att.Signature, data[offset:offset+int(sigLen)])

	return att, nil
}
