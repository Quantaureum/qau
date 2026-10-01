// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const (
	reshareContributionMagic       = "QTMRSH01"
	reshareContributionVersion     = uint16(1)
	shareMaterialPolynomialCount   = 17
	shareMaterialEncodedSize       = shareMaterialPolynomialCount * Degree * 4
	reshareContributionEncodedSize = 8 + 2 + 32 + 32 + 32 + 4*4 + 4 + 4 + shareMaterialEncodedSize + 32
)

// EncodeReshareContribution returns recipient plaintext that must be encrypted
// before persistence or transport.
func EncodeReshareContribution(contribution ReshareContribution) ([]byte, error) {
	if err := contribution.validate(
		contribution.key,
		contribution.oldCommittee,
		contribution.newCommittee,
		contribution.selectedDealers,
		contribution.recipientID,
	); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, reshareContributionEncodedSize)
	encoded = append(encoded, reshareContributionMagic...)
	encoded = binary.BigEndian.AppendUint16(encoded, reshareContributionVersion)
	keyDigest, _ := contribution.key.CanonicalDigest()
	oldDigest, _ := contribution.oldCommittee.CanonicalDigest()
	newDigest, _ := contribution.newCommittee.CanonicalDigest()
	encoded = append(encoded, keyDigest[:]...)
	encoded = append(encoded, oldDigest[:]...)
	encoded = append(encoded, newDigest[:]...)
	for _, dealerID := range contribution.selectedDealers {
		encoded = binary.BigEndian.AppendUint32(encoded, dealerID)
	}
	encoded = binary.BigEndian.AppendUint32(encoded, contribution.dealerID)
	encoded = binary.BigEndian.AppendUint32(encoded, contribution.recipientID)
	encoded = appendShareMaterialEncoding(encoded, contribution.material)
	encoded = append(encoded, contribution.commitment[:]...)
	return encoded, nil
}

// DecodeReshareContribution validates exact metadata and canonical share bytes.
func DecodeReshareContribution(
	encoded []byte,
	key protocol.ThresholdKeyID,
	oldCommittee protocol.CommitteeID,
	newCommittee protocol.CommitteeID,
	selectedDealers []uint32,
	expectedDealerID uint32,
	expectedRecipientID uint32,
) (ReshareContribution, error) {
	if len(encoded) != reshareContributionEncodedSize ||
		!bytes.Equal(encoded[:len(reshareContributionMagic)], []byte(reshareContributionMagic)) {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	offset := len(reshareContributionMagic)
	version := binary.BigEndian.Uint16(encoded[offset : offset+2])
	offset += 2
	if version != reshareContributionVersion {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	keyDigest, err := key.CanonicalDigest()
	if err != nil || subtle.ConstantTimeCompare(keyDigest[:], encoded[offset:offset+32]) != 1 {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	offset += 32
	oldDigest, err := oldCommittee.CanonicalDigest()
	if err != nil || subtle.ConstantTimeCompare(oldDigest[:], encoded[offset:offset+32]) != 1 {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	offset += 32
	newDigest, err := newCommittee.CanonicalDigest()
	if err != nil || subtle.ConstantTimeCompare(newDigest[:], encoded[offset:offset+32]) != 1 {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	offset += 32
	if len(selectedDealers) != int(protocol.TMLDSAV1Threshold) {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	decodedDealers := make([]uint32, len(selectedDealers))
	for index := range decodedDealers {
		decodedDealers[index] = binary.BigEndian.Uint32(encoded[offset : offset+4])
		offset += 4
	}
	if !equalParticipants(selectedDealers, decodedDealers) {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	dealerID := binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	recipientID := binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	if dealerID != expectedDealerID || recipientID != expectedRecipientID {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	material, err := decodeShareMaterial(encoded[offset : offset+shareMaterialEncodedSize])
	if err != nil {
		return ReshareContribution{}, err
	}
	offset += shareMaterialEncodedSize
	contribution := ReshareContribution{
		key:             key.Clone(),
		oldCommittee:    oldCommittee.Clone(),
		newCommittee:    newCommittee.Clone(),
		selectedDealers: append([]uint32(nil), selectedDealers...),
		dealerID:        dealerID,
		recipientID:     recipientID,
		material:        material,
	}
	copy(contribution.commitment[:], encoded[offset:offset+32])
	if err := contribution.validate(key, oldCommittee, newCommittee, selectedDealers, recipientID); err != nil {
		return ReshareContribution{}, err
	}
	return contribution, nil
}

func appendShareMaterialEncoding(encoded []byte, material ShareMaterial) []byte {
	appendVector := func(polynomials []Poly) {
		for polynomialIndex := range polynomials {
			for _, coefficient := range polynomials[polynomialIndex] {
				encoded = binary.BigEndian.AppendUint32(encoded, uint32(coefficient))
			}
		}
	}
	appendVector(material.S1[:])
	appendVector(material.S2[:])
	appendVector(material.T0[:])
	return encoded
}

func decodeShareMaterial(encoded []byte) (ShareMaterial, error) {
	if len(encoded) != shareMaterialEncodedSize {
		return ShareMaterial{}, ErrInvalidReshareContribution
	}
	var material ShareMaterial
	offset := 0
	decodeVector := func(polynomials []Poly) error {
		for polynomialIndex := range polynomials {
			for coefficientIndex := range polynomials[polynomialIndex] {
				coefficient := int32(binary.BigEndian.Uint32(encoded[offset : offset+4]))
				offset += 4
				if !isCanonicalCoefficient(coefficient) {
					return ErrInvalidReshareContribution
				}
				polynomials[polynomialIndex][coefficientIndex] = coefficient
			}
		}
		return nil
	}
	if err := decodeVector(material.S1[:]); err != nil {
		return ShareMaterial{}, err
	}
	if err := decodeVector(material.S2[:]); err != nil {
		return ShareMaterial{}, err
	}
	if err := decodeVector(material.T0[:]); err != nil {
		return ShareMaterial{}, err
	}
	return material, nil
}
