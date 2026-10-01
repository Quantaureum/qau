// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const (
	localShareMagic   = "QTMSHR01"
	localShareVersion = uint16(1)
)

// MarshalBinary encodes one local share for encrypted node-local persistence.
func (share *LocalShare) MarshalBinary() ([]byte, error) {
	if share == nil {
		return nil, ErrInvalidLocalShare
	}
	if share.zeroized {
		return nil, ErrLocalShareZeroized
	}
	if err := share.ValidateIdentity(share.key, share.committee, share.participant); err != nil {
		return nil, err
	}
	if err := validateShareMaterial(share.material); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, localShareEncodedSize(len(share.key.PublicKey), len(share.committee.Participants)))
	encoded = append(encoded, localShareMagic...)
	encoded = binary.BigEndian.AppendUint16(encoded, localShareVersion)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(share.key.Algorithm))
	encoded = binary.BigEndian.AppendUint64(encoded, share.key.Generation)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(share.key.PublicKey)))
	encoded = append(encoded, share.key.PublicKey...)
	encoded = binary.BigEndian.AppendUint64(encoded, share.committee.Version)
	encoded = binary.BigEndian.AppendUint32(encoded, share.committee.Threshold)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(share.committee.Participants)))
	for _, participantID := range share.committee.Participants {
		encoded = binary.BigEndian.AppendUint32(encoded, participantID)
	}
	encoded = binary.BigEndian.AppendUint32(encoded, share.participant)
	encoded = appendShareMaterialEncoding(encoded, share.material)
	commitment := share.Commitment()
	encoded = append(encoded, commitment[:]...)
	return encoded, nil
}

// UnmarshalLocalShare decodes and validates one exact local-share encoding.
func UnmarshalLocalShare(encoded []byte) (*LocalShare, error) {
	minimumSize := localShareEncodedSize(StandardParameters().PublicKeySize, int(protocol.TMLDSAV1ParticipantCount))
	if len(encoded) != minimumSize || !bytes.Equal(encoded[:len(localShareMagic)], []byte(localShareMagic)) {
		return nil, ErrInvalidLocalShare
	}
	offset := len(localShareMagic)
	if binary.BigEndian.Uint16(encoded[offset:offset+2]) != localShareVersion {
		return nil, ErrInvalidLocalShare
	}
	offset += 2
	algorithm := qcrypto.SignatureAlgorithm(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	generation := binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	publicKeyLength := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if algorithm != qcrypto.SignatureAlgorithmMLDSA65 || publicKeyLength != StandardParameters().PublicKeySize {
		return nil, ErrInvalidLocalShare
	}
	publicKey := append([]byte(nil), encoded[offset:offset+publicKeyLength]...)
	offset += publicKeyLength
	committeeVersion := binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	threshold := binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	participantCount := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if participantCount != int(protocol.TMLDSAV1ParticipantCount) {
		return nil, ErrInvalidLocalShare
	}
	participants := make([]uint32, participantCount)
	for index := range participants {
		participants[index] = binary.BigEndian.Uint32(encoded[offset : offset+4])
		offset += 4
	}
	participantID := binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	material, err := decodeShareMaterial(encoded[offset : offset+shareMaterialEncodedSize])
	if err != nil {
		return nil, ErrInvalidLocalShare
	}
	offset += shareMaterialEncodedSize
	var commitment [32]byte
	copy(commitment[:], encoded[offset:offset+32])
	share, err := NewLocalShare(
		protocol.ThresholdKeyID{
			Algorithm:  algorithm,
			Generation: generation,
			PublicKey:  publicKey,
		},
		protocol.CommitteeID{
			Version:      committeeVersion,
			Threshold:    threshold,
			Participants: participants,
		},
		participantID,
		material,
	)
	if err != nil {
		return nil, err
	}
	want := share.Commitment()
	if subtle.ConstantTimeCompare(want[:], commitment[:]) != 1 {
		share.Zeroize()
		return nil, ErrShareCommitmentMismatch
	}
	return share, nil
}

func localShareEncodedSize(publicKeySize, participantCount int) int {
	return len(localShareMagic) + 2 + 2 + 8 + 4 + publicKeySize + 8 + 4 + 4 + participantCount*4 + 4 + shareMaterialEncodedSize + 32
}
