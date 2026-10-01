// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

var ErrInvalidReshareActivationCertificate = errors.New("invalid TMLDSA v1 reshare activation certificate")

// ReshareActivationAcknowledgement binds one participant's durable candidate
// to the common reshare transcript and target epoch.
type ReshareActivationAcknowledgement struct {
	SessionID         [32]byte
	ActivationEpoch   uint64
	Key               protocol.ThresholdKeyID
	OldCommittee      protocol.CommitteeID
	NewCommittee      protocol.CommitteeID
	TranscriptDigest  [32]byte
	ParticipantID     uint32
	CandidateDigest   [32]byte
	IdentitySignature []byte
}

// SigningBytes returns the canonical identity-signed acknowledgement bytes.
func (acknowledgement ReshareActivationAcknowledgement) SigningBytes() ([]byte, error) {
	if err := acknowledgement.validateUnsigned(); err != nil {
		return nil, err
	}
	keyDigest, _ := acknowledgement.Key.CanonicalDigest()
	oldDigest, _ := acknowledgement.OldCommittee.CanonicalDigest()
	newDigest, _ := acknowledgement.NewCommittee.CanonicalDigest()
	encoded := make([]byte, 0, 32+8+32*5+4)
	encoded = append(encoded, []byte("QAU-TMLDSA65-V1-RESHARE-ACTIVATION-ACK")...)
	encoded = append(encoded, acknowledgement.SessionID[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, acknowledgement.ActivationEpoch)
	encoded = append(encoded, keyDigest[:]...)
	encoded = append(encoded, oldDigest[:]...)
	encoded = append(encoded, newDigest[:]...)
	encoded = append(encoded, acknowledgement.TranscriptDigest[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, acknowledgement.ParticipantID)
	encoded = append(encoded, acknowledgement.CandidateDigest[:]...)
	return encoded, nil
}

func (acknowledgement ReshareActivationAcknowledgement) validateUnsigned() error {
	if acknowledgement.SessionID == ([32]byte{}) || acknowledgement.ActivationEpoch == 0 ||
		acknowledgement.TranscriptDigest == ([32]byte{}) || acknowledgement.ParticipantID == 0 ||
		acknowledgement.CandidateDigest == ([32]byte{}) {
		return ErrInvalidReshareActivationCertificate
	}
	if err := acknowledgement.Key.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReshareActivationCertificate, err)
	}
	if err := DefaultProfile().ValidateTransition(acknowledgement.OldCommittee, acknowledgement.NewCommittee); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReshareActivationCertificate, err)
	}
	if !committeeContains(acknowledgement.NewCommittee, acknowledgement.ParticipantID) {
		return ErrInvalidReshareActivationCertificate
	}
	return nil
}

// Verify validates this acknowledgement's identity signature.
func (acknowledgement ReshareActivationAcknowledgement) Verify(verifier ReshareIdentityVerifier) error {
	if verifier == nil || len(acknowledgement.IdentitySignature) == 0 ||
		len(acknowledgement.IdentitySignature) > protocol.MaxThresholdIdentitySignature {
		return ErrInvalidReshareActivationCertificate
	}
	message, err := acknowledgement.SigningBytes()
	if err != nil || !verifier(acknowledgement.ParticipantID, message, acknowledgement.IdentitySignature) {
		return ErrInvalidReshareActivationCertificate
	}
	return nil
}

// CanonicalDigest returns the stable digest including the identity signature.
func (acknowledgement ReshareActivationAcknowledgement) CanonicalDigest() ([32]byte, error) {
	message, err := acknowledgement.SigningBytes()
	if err != nil || len(acknowledgement.IdentitySignature) == 0 ||
		len(acknowledgement.IdentitySignature) > protocol.MaxThresholdIdentitySignature {
		return [32]byte{}, ErrInvalidReshareActivationCertificate
	}
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-SIGNED-ACTIVATION-ACK"))
	_, _ = digest.Write(message)
	_, _ = digest.Write(acknowledgement.IdentitySignature)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

// ReshareActivationCertificate contains exactly one acknowledgement from each
// member of the new six-participant committee.
type ReshareActivationCertificate struct {
	Acknowledgements []ReshareActivationAcknowledgement
}

// ReshareIdentityVerifier verifies a participant's long-term identity signature.
type ReshareIdentityVerifier func(participantID uint32, message, signature []byte) bool

// Verify validates all bindings and all six identity signatures.
func (certificate ReshareActivationCertificate) Verify(verifier ReshareIdentityVerifier) error {
	if verifier == nil {
		return ErrInvalidReshareActivationCertificate
	}
	if err := certificate.validateStructure(); err != nil {
		return err
	}
	for _, acknowledgement := range certificate.Acknowledgements {
		if err := acknowledgement.Verify(verifier); err != nil {
			return err
		}
	}
	return nil
}

func (certificate ReshareActivationCertificate) validateStructure() error {
	if len(certificate.Acknowledgements) != int(protocol.TMLDSAV1ParticipantCount) {
		return ErrInvalidReshareActivationCertificate
	}
	first := certificate.Acknowledgements[0]
	if err := first.validateUnsigned(); err != nil {
		return err
	}
	if len(first.IdentitySignature) == 0 || len(first.IdentitySignature) > protocol.MaxThresholdIdentitySignature {
		return ErrInvalidReshareActivationCertificate
	}
	for index, acknowledgement := range certificate.Acknowledgements {
		if err := acknowledgement.validateUnsigned(); err != nil {
			return err
		}
		if acknowledgement.ParticipantID != first.NewCommittee.Participants[index] ||
			acknowledgement.SessionID != first.SessionID ||
			acknowledgement.ActivationEpoch != first.ActivationEpoch ||
			acknowledgement.TranscriptDigest != first.TranscriptDigest ||
			!sameThresholdKey(acknowledgement.Key, first.Key) ||
			!sameCommittee(acknowledgement.OldCommittee, first.OldCommittee) ||
			!sameCommittee(acknowledgement.NewCommittee, first.NewCommittee) ||
			len(acknowledgement.IdentitySignature) == 0 ||
			len(acknowledgement.IdentitySignature) > protocol.MaxThresholdIdentitySignature {
			return ErrInvalidReshareActivationCertificate
		}
	}
	return nil
}

// CanonicalDigest returns the stable public digest of a structurally valid certificate.
func (certificate ReshareActivationCertificate) CanonicalDigest() ([32]byte, error) {
	if err := certificate.validateStructure(); err != nil {
		return [32]byte{}, err
	}
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-ACTIVATION-CERTIFICATE"))
	for _, acknowledgement := range certificate.Acknowledgements {
		message, _ := acknowledgement.SigningBytes()
		_, _ = digest.Write(message)
		_, _ = digest.Write(acknowledgement.IdentitySignature)
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

// Digest verifies every signature before returning the canonical digest.
func (certificate ReshareActivationCertificate) Digest(verifier ReshareIdentityVerifier) ([32]byte, error) {
	if err := certificate.Verify(verifier); err != nil {
		return [32]byte{}, err
	}
	return certificate.CanonicalDigest()
}

func sameThresholdKey(left, right protocol.ThresholdKeyID) bool {
	return left.Algorithm == right.Algorithm && left.Generation == right.Generation &&
		bytes.Equal(left.PublicKey, right.PublicKey)
}

func sameCommittee(left, right protocol.CommitteeID) bool {
	if left.Version != right.Version || left.Threshold != right.Threshold ||
		len(left.Participants) != len(right.Participants) {
		return false
	}
	for index := range left.Participants {
		if left.Participants[index] != right.Participants[index] {
			return false
		}
	}
	return true
}
