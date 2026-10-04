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
	if verifier == nil {
		return fmt.Errorf("%w: no identity verifier", ErrInvalidDKGActivationCertificate)
	}
	if len(acknowledgement.IdentitySignature) == 0 ||
		len(acknowledgement.IdentitySignature) > protocol.MaxThresholdIdentitySignature {
		return fmt.Errorf("%w: identity signature length %d", ErrInvalidDKGActivationCertificate, len(acknowledgement.IdentitySignature))
	}
	message, err := acknowledgement.SigningBytes()
	if err != nil {
		return fmt.Errorf("%w: signing bytes: %v", ErrInvalidDKGActivationCertificate, err)
	}
	if !verifier(acknowledgement.ParticipantID, message, acknowledgement.IdentitySignature) {
		return fmt.Errorf("%w: identity signature does not verify for participant %d", ErrInvalidDKGActivationCertificate, acknowledgement.ParticipantID)
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
	if sessionDigest == ([32]byte{}) {
		return fmt.Errorf("%w: empty session digest", ErrInvalidDKGActivationCertificate)
	}
	if share == nil || share.Validate() != nil {
		return fmt.Errorf("%w: local share invalid", ErrInvalidDKGActivationCertificate)
	}
	if err := certificate.Verify(verifier); err != nil {
		return err
	}
	if int(share.ParticipantPosition) >= len(certificate.Acknowledgements) {
		return fmt.Errorf("%w: share position %d outside %d acknowledgements",
			ErrInvalidDKGActivationCertificate, share.ParticipantPosition, len(certificate.Acknowledgements))
	}
	acknowledgement := certificate.Acknowledgements[share.ParticipantPosition]
	shareKeyDigest, err := share.Key.CanonicalDigest()
	if err != nil {
		return fmt.Errorf("%w: share key digest: %v", ErrInvalidDKGActivationCertificate, err)
	}
	certificateKeyDigest, err := acknowledgement.Key.CanonicalDigest()
	if err != nil {
		return fmt.Errorf("%w: certificate key digest: %v", ErrInvalidDKGActivationCertificate, err)
	}
	shareCommitteeDigest, err := share.Committee.CanonicalDigest()
	if err != nil {
		return fmt.Errorf("%w: share committee digest: %v", ErrInvalidDKGActivationCertificate, err)
	}
	certificateCommitteeDigest, err := acknowledgement.Committee.CanonicalDigest()
	if err != nil {
		return fmt.Errorf("%w: certificate committee digest: %v", ErrInvalidDKGActivationCertificate, err)
	}
	switch {
	case acknowledgement.SessionDigest != sessionDigest:
		return fmt.Errorf("%w: acknowledgement session %x != %x",
			ErrInvalidDKGActivationCertificate, acknowledgement.SessionDigest[:8], sessionDigest[:8])
	case acknowledgement.ParticipantID != share.ParticipantID:
		return fmt.Errorf("%w: acknowledgement participant %d != share participant %d",
			ErrInvalidDKGActivationCertificate, acknowledgement.ParticipantID, share.ParticipantID)
	case acknowledgement.ActivationEpoch != share.ActivationEpoch:
		return fmt.Errorf("%w: acknowledgement epoch %d != share epoch %d",
			ErrInvalidDKGActivationCertificate, acknowledgement.ActivationEpoch, share.ActivationEpoch)
	case acknowledgement.TranscriptDigest != share.TranscriptDigest:
		return fmt.Errorf("%w: acknowledgement transcript %x != share transcript %x",
			ErrInvalidDKGActivationCertificate, acknowledgement.TranscriptDigest[:8], share.TranscriptDigest[:8])
	case certificateKeyDigest != shareKeyDigest:
		return fmt.Errorf("%w: certificate key digest differs from the share's", ErrInvalidDKGActivationCertificate)
	case certificateCommitteeDigest != shareCommitteeDigest:
		return fmt.Errorf("%w: certificate committee digest differs from the share's", ErrInvalidDKGActivationCertificate)
	}
	encoded, err := share.MarshalBinary()
	if err != nil {
		return fmt.Errorf("%w: share encoding: %v", ErrInvalidDKGActivationCertificate, err)
	}
	defer clear(encoded)
	if digest := sha3.Sum256(encoded); digest != acknowledgement.CandidateDigest {
		return fmt.Errorf("%w: candidate digest %x != acknowledgement's %x",
			ErrInvalidDKGActivationCertificate, digest[:8], acknowledgement.CandidateDigest[:8])
	}
	return nil
}

func (certificate DKGActivationCertificate) validateStructure() error {
	if len(certificate.Acknowledgements) == 0 {
		return fmt.Errorf("%w: no acknowledgements", ErrInvalidDKGActivationCertificate)
	}
	first := certificate.Acknowledgements[0]
	// The acknowledgement set must cover the certificate's whole committee
	// (R76: the family size, not the legacy six).
	if int(first.Committee.Threshold) == 0 {
		return fmt.Errorf("%w: zero committee threshold", ErrInvalidDKGActivationCertificate)
	}
	if len(certificate.Acknowledgements) != len(first.Committee.Participants) {
		return fmt.Errorf("%w: %d acknowledgements for %d committee participants",
			ErrInvalidDKGActivationCertificate, len(certificate.Acknowledgements), len(first.Committee.Participants))
	}
	if err := first.validateUnsigned(); err != nil {
		return err
	}
	firstKeyDigest, err := first.Key.CanonicalDigest()
	if err != nil {
		return fmt.Errorf("%w: key digest: %v", ErrInvalidDKGActivationCertificate, err)
	}
	firstCommitteeDigest, err := first.Committee.CanonicalDigest()
	if err != nil {
		return fmt.Errorf("%w: committee digest: %v", ErrInvalidDKGActivationCertificate, err)
	}
	for index, acknowledgement := range certificate.Acknowledgements {
		if err := acknowledgement.validateUnsigned(); err != nil {
			return fmt.Errorf("%w: acknowledgement %d: %v", ErrInvalidDKGActivationCertificate, index, err)
		}
		keyDigest, keyErr := acknowledgement.Key.CanonicalDigest()
		committeeDigest, committeeErr := acknowledgement.Committee.CanonicalDigest()
		switch {
		case keyErr != nil || committeeErr != nil:
			return fmt.Errorf("%w: acknowledgement %d digests: %v / %v", ErrInvalidDKGActivationCertificate, index, keyErr, committeeErr)
		case acknowledgement.ParticipantID != first.Committee.Participants[index]:
			return fmt.Errorf("%w: acknowledgement %d has participant %d, want %d",
				ErrInvalidDKGActivationCertificate, index, acknowledgement.ParticipantID, first.Committee.Participants[index])
		case acknowledgement.SessionDigest != first.SessionDigest:
			return fmt.Errorf("%w: acknowledgement %d session %x != %x",
				ErrInvalidDKGActivationCertificate, index, acknowledgement.SessionDigest[:8], first.SessionDigest[:8])
		case acknowledgement.ActivationEpoch != first.ActivationEpoch:
			return fmt.Errorf("%w: acknowledgement %d activation epoch %d != %d",
				ErrInvalidDKGActivationCertificate, index, acknowledgement.ActivationEpoch, first.ActivationEpoch)
		case acknowledgement.TranscriptDigest != first.TranscriptDigest:
			return fmt.Errorf("%w: acknowledgement %d transcript %x != %x",
				ErrInvalidDKGActivationCertificate, index, acknowledgement.TranscriptDigest[:8], first.TranscriptDigest[:8])
		case keyDigest != firstKeyDigest:
			return fmt.Errorf("%w: acknowledgement %d key digest differs", ErrInvalidDKGActivationCertificate, index)
		case committeeDigest != firstCommitteeDigest:
			return fmt.Errorf("%w: acknowledgement %d committee digest differs", ErrInvalidDKGActivationCertificate, index)
		case len(acknowledgement.IdentitySignature) == 0:
			return fmt.Errorf("%w: acknowledgement %d has no identity signature", ErrInvalidDKGActivationCertificate, index)
		case len(acknowledgement.IdentitySignature) > protocol.MaxThresholdIdentitySignature:
			return fmt.Errorf("%w: acknowledgement %d identity signature oversized (%d)", ErrInvalidDKGActivationCertificate, index, len(acknowledgement.IdentitySignature))
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
