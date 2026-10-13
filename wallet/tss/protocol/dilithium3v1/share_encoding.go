// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const (
	localShareMagic       = "QTD3SH02"
	legacyLocalShareMagic = "QTD3SH01"
	// localShareVersion is the share-encoding version of a share that never
	// went through a rotation. Version 3 added the 32-bit fold multiplicity
	// ahead of each component's secret vectors so R77-rotated shares
	// round-trip their norm history.
	localShareVersion       = uint16(3)
	legacyLocalShareVersion = uint16(2)
	// rotatedLocalShareVersion is the encoding of a rotated share: version 3
	// plus one flags byte after rho. Only rotated shares use it, so a fresh
	// share (every offline-ceremony share among them) keeps its version-3
	// bytes and stays readable by nodes that predate the flag.
	rotatedLocalShareVersion = uint16(4)
	// localShareFlagRotated is the only defined flags bit.
	localShareFlagRotated    = byte(1)
	shareDigestSize          = 32
	componentMetadataSize    = 2 + 1 + 32 + 4
	componentSecretPolyCount = L + K
)

var (
	ErrInvalidLocalShareEncoding    = errors.New("invalid Dilithium3 v1 local share encoding")
	ErrUnsupportedLocalShareVersion = errors.New("unsupported Dilithium3 v1 local share version")
	ErrShareDigestMismatch          = errors.New("Dilithium3 v1 local share digest mismatch")
)

// MarshalBinary encodes one local share for encrypted node-local persistence.
func (share *LocalShare) MarshalBinary() ([]byte, error) {
	if err := share.Validate(); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, localShareEncodedSize(share))
	encoded = append(encoded, localShareMagic...)
	if share.Rotated {
		encoded = binary.BigEndian.AppendUint16(encoded, rotatedLocalShareVersion)
	} else {
		encoded = binary.BigEndian.AppendUint16(encoded, localShareVersion)
	}
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(share.Protocol))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(share.Key.Algorithm))
	encoded = binary.BigEndian.AppendUint64(encoded, share.Key.Generation)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(share.Key.PublicKey)))
	encoded = append(encoded, share.Key.PublicKey...)
	encoded = binary.BigEndian.AppendUint64(encoded, share.Committee.Version)
	encoded = binary.BigEndian.AppendUint32(encoded, share.Committee.Threshold)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(share.Committee.Participants)))
	for _, participantID := range share.Committee.Participants {
		encoded = binary.BigEndian.AppendUint32(encoded, participantID)
	}
	encoded = binary.BigEndian.AppendUint32(encoded, share.ParticipantID)
	encoded = append(encoded, share.ParticipantPosition)
	encoded = binary.BigEndian.AppendUint64(encoded, share.ActivationEpoch)
	encoded = append(encoded, share.TranscriptDigest[:]...)
	encoded = append(encoded, share.Rho[:]...)
	if share.Rotated {
		encoded = append(encoded, localShareFlagRotated)
	}
	for _, component := range share.Components {
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(component.GroupMask))
		encoded = append(encoded, component.DealerPosition)
		encoded = append(encoded, component.ContributionDigest[:]...)
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(componentMultiplicity(component)))
		var err error
		encoded, err = appendVectorL(encoded, component.S1)
		if err != nil {
			return nil, err
		}
		encoded, err = appendVectorK(encoded, component.S2)
		if err != nil {
			return nil, err
		}
	}
	digest := sha3.Sum256(encoded)
	encoded = append(encoded, digest[:]...)
	return encoded, nil
}

// UnmarshalLocalShare validates the entire encoding before returning secret data.
func UnmarshalLocalShare(encoded []byte) (*LocalShare, error) {
	if len(encoded) < len(localShareMagic) {
		return nil, ErrInvalidLocalShareEncoding
	}
	if bytes.Equal(encoded[:len(legacyLocalShareMagic)], []byte(legacyLocalShareMagic)) {
		return nil, ErrUnsupportedLocalShareVersion
	}
	if !bytes.Equal(encoded[:len(localShareMagic)], []byte(localShareMagic)) {
		return nil, ErrInvalidLocalShareEncoding
	}
	// Every fixed field is length-checked before it is read, so a truncated
	// encoding is an error, never a panic.
	if len(encoded) < len(localShareMagic)+shareDigestSize {
		return nil, ErrInvalidLocalShareEncoding
	}
	payload := encoded[:len(encoded)-shareDigestSize]
	wantDigest := sha3.Sum256(payload)
	if subtle.ConstantTimeCompare(wantDigest[:], encoded[len(payload):]) != 1 {
		return nil, ErrShareDigestMismatch
	}
	offset := len(localShareMagic)
	// version, protocol, algorithm, generation, and the public-key length.
	if offset+2+2+2+8+4 > len(payload) {
		return nil, ErrInvalidLocalShareEncoding
	}
	version := binary.BigEndian.Uint16(encoded[offset : offset+2])
	if version != localShareVersion && version != legacyLocalShareVersion && version != rotatedLocalShareVersion {
		return nil, ErrUnsupportedLocalShareVersion
	}
	legacyVersionTwo := version == legacyLocalShareVersion
	offset += 2
	thresholdProtocol := protocol.ThresholdProtocol(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	algorithm := qcrypto.SignatureAlgorithm(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	generation := binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	publicKeyLength := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if publicKeyLength != mode3PublicKeySize || offset+publicKeyLength > len(payload) {
		return nil, ErrInvalidLocalShareEncoding
	}
	publicKey := append([]byte(nil), encoded[offset:offset+publicKeyLength]...)
	offset += publicKeyLength
	// committee version, threshold, and the participant count.
	if offset+8+4+4 > len(payload) {
		return nil, ErrInvalidLocalShareEncoding
	}
	committeeVersion := binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	threshold := binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	participantCount := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if participantCount < MinCommitteeParticipants || participantCount > MaxCommitteeParticipants {
		return nil, ErrInvalidLocalShareEncoding
	}
	// participants, participant ID and position, activation epoch, transcript
	// digest, and rho.
	if offset+4*participantCount+4+1+8+32+32 > len(payload) {
		return nil, ErrInvalidLocalShareEncoding
	}
	participants := make([]uint32, participantCount)
	for index := range participants {
		participants[index] = binary.BigEndian.Uint32(encoded[offset : offset+4])
		offset += 4
	}
	participantID := binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	participantPosition := encoded[offset]
	offset++
	activationEpoch := binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	var transcriptDigest [32]byte
	copy(transcriptDigest[:], encoded[offset:offset+32])
	offset += 32
	var rho [32]byte
	copy(rho[:], encoded[offset:offset+32])
	offset += 32
	// A rotated share's flags byte must be exactly the rotation flag: the
	// encoding stays canonical, one byte string per share.
	rotated := version == rotatedLocalShareVersion
	if rotated {
		if offset+1 > len(payload) || encoded[offset] != localShareFlagRotated {
			return nil, ErrInvalidLocalShareEncoding
		}
		offset++
	}
	share := &LocalShare{
		Protocol:            thresholdProtocol,
		Key:                 protocol.ThresholdKeyID{Algorithm: algorithm, Generation: generation, PublicKey: publicKey},
		Committee:           protocol.CommitteeID{Version: committeeVersion, Threshold: threshold, Participants: participants},
		ParticipantID:       participantID,
		ParticipantPosition: participantPosition,
		ActivationEpoch:     activationEpoch,
		TranscriptDigest:    transcriptDigest,
		Rho:                 rho,
		Rotated:             rotated,
	}
	groups, err := GroupsForPositionN(participantPosition, participantCount)
	if err != nil {
		return nil, ErrInvalidLocalShareEncoding
	}
	share.Components = make([]RSSComponent, len(groups))
	for index := range share.Components {
		component := &share.Components[index]
		// group mask, dealer position, contribution digest, and (from
		// version 3) the multiplicity.
		header := 2 + 1 + 32
		if !legacyVersionTwo {
			header += 4
		}
		if offset+header > len(payload) {
			share.Zeroize()
			return nil, ErrInvalidLocalShareEncoding
		}
		component.GroupMask = RSSGroupMask(binary.BigEndian.Uint16(encoded[offset : offset+2]))
		offset += 2
		component.DealerPosition = encoded[offset]
		offset++
		copy(component.ContributionDigest[:], encoded[offset:offset+32])
		offset += 32
		if legacyVersionTwo {
			component.Multiplicity = 1
		} else {
			component.Multiplicity = binary.BigEndian.Uint32(encoded[offset : offset+4])
			offset += 4
			if component.Multiplicity == 0 {
				share.Zeroize()
				return nil, ErrInvalidLocalShareEncoding
			}
		}
		var err error
		component.S1, offset, err = decodeVectorL(encoded, offset)
		if err != nil {
			share.Zeroize()
			return nil, ErrInvalidLocalShareEncoding
		}
		component.S2, offset, err = decodeVectorK(encoded, offset)
		if err != nil {
			share.Zeroize()
			return nil, ErrInvalidLocalShareEncoding
		}
	}
	if offset != len(payload) {
		share.Zeroize()
		return nil, ErrInvalidLocalShareEncoding
	}
	if err := share.Validate(); err != nil {
		share.Zeroize()
		return nil, err
	}
	return share, nil
}

const mode3PublicKeySize = 1952

func localShareEncodedSize(share *LocalShare) int {
	participants := len(share.Committee.Participants)
	metadataSize := 8 + 2 + 2 + 2 + 8 + 4 + mode3PublicKeySize + 8 + 4 + 4 + participants*4 + 4 + 1 + 8 + 32 + 32
	if share.Rotated {
		metadataSize++
	}
	componentSize := componentMetadataSize + componentSecretPolyCount*PolyEncodedSize
	return metadataSize + len(share.Components)*componentSize + shareDigestSize
}

func appendVectorL(destination []byte, vector VectorL) ([]byte, error) {
	for _, polynomial := range vector {
		encoded, err := EncodePoly(polynomial)
		if err != nil {
			return nil, err
		}
		destination = append(destination, encoded[:]...)
	}
	return destination, nil
}

func appendVectorK(destination []byte, vector VectorK) ([]byte, error) {
	for _, polynomial := range vector {
		encoded, err := EncodePoly(polynomial)
		if err != nil {
			return nil, err
		}
		destination = append(destination, encoded[:]...)
	}
	return destination, nil
}

func decodeVectorL(encoded []byte, offset int) (VectorL, int, error) {
	var vector VectorL
	if offset < 0 || offset+L*PolyEncodedSize > len(encoded) {
		return VectorL{}, offset, ErrInvalidLocalShareEncoding
	}
	for index := range vector {
		polynomial, err := DecodePoly(encoded[offset : offset+PolyEncodedSize])
		if err != nil {
			return VectorL{}, offset, err
		}
		vector[index] = polynomial
		offset += PolyEncodedSize
	}
	return vector, offset, nil
}

func decodeVectorK(encoded []byte, offset int) (VectorK, int, error) {
	var vector VectorK
	if offset < 0 || offset+K*PolyEncodedSize > len(encoded) {
		return VectorK{}, offset, ErrInvalidLocalShareEncoding
	}
	for index := range vector {
		polynomial, err := DecodePoly(encoded[offset : offset+PolyEncodedSize])
		if err != nil {
			return VectorK{}, offset, err
		}
		vector[index] = polynomial
		offset += PolyEncodedSize
	}
	return vector, offset, nil
}
