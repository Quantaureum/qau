// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const (
	dkgActivationAcknowledgementDomain = "QAU-TDILITHIUM3-V1-DKG-ACTIVATION-ACK"
	dkgActivationCertificateDomain     = "QAU-TDILITHIUM3-V1-DKG-ACTIVATION-CERTIFICATE"
)

var ErrInvalidDKGActivationCertificate = errors.New("invalid Dilithium3 v1 DKG activation certificate")

type DKGActivationAcknowledgement struct {
	SessionDigest     [32]byte
	ActivationEpoch   uint64
	Key               protocol.ThresholdKeyID
	Committee         protocol.CommitteeID
	TranscriptDigest  [32]byte
	ParticipantID     uint32
	CandidateDigest   [32]byte
	IdentitySignature []byte
}

type DKGActivationCertificate struct {
	Acknowledgements []DKGActivationAcknowledgement
}

type DKGIdentityVerifier func(participantID uint32, message, signature []byte) bool

func (acknowledgement DKGActivationAcknowledgement) SigningBytes() ([]byte, error) {
	if err := acknowledgement.validateUnsigned(); err != nil {
		return nil, err
	}
	keyDigest, err := acknowledgement.Key.CanonicalDigest()
	if err != nil {
		return nil, fmt.Errorf("%w: key digest: %v", ErrInvalidDKGActivationCertificate, err)
	}
	committeeDigest, err := acknowledgement.Committee.CanonicalDigest()
	if err != nil {
		return nil, fmt.Errorf("%w: committee digest: %v", ErrInvalidDKGActivationCertificate, err)
	}
	encoded := make([]byte, 0, len(dkgActivationAcknowledgementDomain)+32*5+8+4)
	encoded = append(encoded, dkgActivationAcknowledgementDomain...)
	encoded = append(encoded, acknowledgement.SessionDigest[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, acknowledgement.ActivationEpoch)
	encoded = append(encoded, keyDigest[:]...)
	encoded = append(encoded, committeeDigest[:]...)
	encoded = append(encoded, acknowledgement.TranscriptDigest[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, acknowledgement.ParticipantID)
	encoded = append(encoded, acknowledgement.CandidateDigest[:]...)
	return encoded, nil
}

func (acknowledgement DKGActivationAcknowledgement) validateUnsigned() error {
	if acknowledgement.SessionDigest == ([32]byte{}) || acknowledgement.ActivationEpoch == 0 ||
		acknowledgement.TranscriptDigest == ([32]byte{}) || acknowledgement.ParticipantID == 0 ||
		acknowledgement.CandidateDigest == ([32]byte{}) ||
		acknowledgement.Key.Algorithm != qcrypto.SignatureAlgorithmDilithium3Legacy {
		return ErrInvalidDKGActivationCertificate
	}
	if err := acknowledgement.Key.Validate(); err != nil {
		return fmt.Errorf("%w: key: %v", ErrInvalidDKGActivationCertificate, err)
	}
	if err := protocol.ValidateDilithium3V1Committee(acknowledgement.Committee); err != nil {
		return fmt.Errorf("%w: committee: %v", ErrInvalidDKGActivationCertificate, err)
	}
	for _, participantID := range acknowledgement.Committee.Participants {
		if participantID == acknowledgement.ParticipantID {
			return nil
		}
	}
	return ErrInvalidDKGActivationCertificate
}

func (acknowledgement DKGActivationAcknowledgement) Verify(verifier DKGIdentityVerifier) error {
	if verifier == nil || len(acknowledgement.IdentitySignature) == 0 ||
		len(acknowledgement.IdentitySignature) > protocol.MaxThresholdIdentitySignature {
		return ErrInvalidDKGActivationCertificate
	}
	message, err := acknowledgement.SigningBytes()
	if err != nil || !verifier(acknowledgement.ParticipantID, message, acknowledgement.IdentitySignature) {
		return ErrInvalidDKGActivationCertificate
	}
	return nil
}

func (certificate DKGActivationCertificate) Verify(verifier DKGIdentityVerifier) error {
	if verifier == nil {
		return ErrInvalidDKGActivationCertificate
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

func (certificate DKGActivationCertificate) VerifyCandidate(share *LocalShare, sessionDigest [32]byte, verifier DKGIdentityVerifier) error {
	if sessionDigest == ([32]byte{}) || share == nil || share.Validate() != nil {
		return ErrInvalidDKGActivationCertificate
	}
	if err := certificate.Verify(verifier); err != nil {
		return err
	}
	acknowledgement := certificate.Acknowledgements[share.ParticipantPosition]
	shareKeyDigest, err := share.Key.CanonicalDigest()
	if err != nil {
		return ErrInvalidDKGActivationCertificate
	}
	certificateKeyDigest, err := acknowledgement.Key.CanonicalDigest()
	if err != nil {
		return ErrInvalidDKGActivationCertificate
	}
	shareCommitteeDigest, err := share.Committee.CanonicalDigest()
	if err != nil {
		return ErrInvalidDKGActivationCertificate
	}
	certificateCommitteeDigest, err := acknowledgement.Committee.CanonicalDigest()
	if err != nil || acknowledgement.SessionDigest != sessionDigest ||
		acknowledgement.ParticipantID != share.ParticipantID ||
		acknowledgement.ActivationEpoch != share.ActivationEpoch ||
		acknowledgement.TranscriptDigest != share.TranscriptDigest ||
		certificateKeyDigest != shareKeyDigest || certificateCommitteeDigest != shareCommitteeDigest {
		return ErrInvalidDKGActivationCertificate
	}
	encoded, err := share.MarshalBinary()
	if err != nil {
		return ErrInvalidDKGActivationCertificate
	}
	defer clear(encoded)
	if sha3.Sum256(encoded) != acknowledgement.CandidateDigest {
		return ErrInvalidDKGActivationCertificate
	}
	return nil
}

func (certificate DKGActivationCertificate) validateStructure() error {
	if len(certificate.Acknowledgements) == 0 {
		return ErrInvalidDKGActivationCertificate
	}
	first := certificate.Acknowledgements[0]
	// The acknowledgement set must cover the certificate's whole committee
	// (R76: the family size, not the legacy six).
	if int(first.Committee.Threshold) == 0 ||
		len(certificate.Acknowledgements) != len(first.Committee.Participants) {
		return ErrInvalidDKGActivationCertificate
	}
	if err := first.validateUnsigned(); err != nil {
		return err
	}
	firstKeyDigest, err := first.Key.CanonicalDigest()
	if err != nil {
		return ErrInvalidDKGActivationCertificate
	}
	firstCommitteeDigest, err := first.Committee.CanonicalDigest()
	if err != nil {
		return ErrInvalidDKGActivationCertificate
	}
	for index, acknowledgement := range certificate.Acknowledgements {
		if err := acknowledgement.validateUnsigned(); err != nil {
			return err
		}
		keyDigest, keyErr := acknowledgement.Key.CanonicalDigest()
		committeeDigest, committeeErr := acknowledgement.Committee.CanonicalDigest()
		if keyErr != nil || committeeErr != nil ||
			acknowledgement.ParticipantID != first.Committee.Participants[index] ||
			acknowledgement.SessionDigest != first.SessionDigest ||
			acknowledgement.ActivationEpoch != first.ActivationEpoch ||
			acknowledgement.TranscriptDigest != first.TranscriptDigest ||
			keyDigest != firstKeyDigest || committeeDigest != firstCommitteeDigest ||
			len(acknowledgement.IdentitySignature) == 0 ||
			len(acknowledgement.IdentitySignature) > protocol.MaxThresholdIdentitySignature {
			return ErrInvalidDKGActivationCertificate
		}
	}
	return nil
}

func (certificate DKGActivationCertificate) CanonicalDigest() ([32]byte, error) {
	if err := certificate.validateStructure(); err != nil {
		return [32]byte{}, err
	}
	hash := sha3.New256()
	_, _ = hash.Write([]byte(dkgActivationCertificateDomain))
	for _, acknowledgement := range certificate.Acknowledgements {
		message, err := acknowledgement.SigningBytes()
		if err != nil {
			return [32]byte{}, err
		}
		_, _ = hash.Write(message)
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(acknowledgement.IdentitySignature)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(acknowledgement.IdentitySignature)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}
