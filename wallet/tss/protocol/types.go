// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"

	qcrypto "github.com/quantaureum/qau/crypto"
)

var (
	ErrInvalidThresholdKey = errors.New("invalid threshold key")
	ErrInvalidCommittee    = errors.New("invalid threshold committee")
	ErrInvalidProtocol     = errors.New("invalid threshold protocol")
)

// ThresholdProtocol identifies the distributed protocol that owns DKG,
// reshare, preprocessing, and signing state. It is independent from the final
// signature encoding selected by SignatureAlgorithm.
type ThresholdProtocol uint16

const (
	ThresholdProtocolUnknown ThresholdProtocol = iota
	ThresholdProtocolDilithium3V1
	ThresholdProtocolMLDSA65ExperimentalV1
	ThresholdProtocolLegacyUnsafe
)

// Supported reports whether the binary recognizes the threshold protocol.
func (thresholdProtocol ThresholdProtocol) Supported() bool {
	switch thresholdProtocol {
	case ThresholdProtocolDilithium3V1, ThresholdProtocolMLDSA65ExperimentalV1, ThresholdProtocolLegacyUnsafe:
		return true
	default:
		return false
	}
}

// String returns the stable protocol label used by logs and persistence paths.
func (thresholdProtocol ThresholdProtocol) String() string {
	switch thresholdProtocol {
	case ThresholdProtocolDilithium3V1:
		return "qau-tdilithium3-v1"
	case ThresholdProtocolMLDSA65ExperimentalV1:
		return "qau-tmldsa65-experimental-v1"
	case ThresholdProtocolLegacyUnsafe:
		return "qau-threshold-legacy-unsafe"
	default:
		return "unknown"
	}
}

// ValidateAlgorithm rejects protocol and final-signature algorithm mismatch.
func (thresholdProtocol ThresholdProtocol) ValidateAlgorithm(algorithm qcrypto.SignatureAlgorithm) error {
	if thresholdProtocol == ThresholdProtocolLegacyUnsafe {
		if algorithm != qcrypto.SignatureAlgorithmDilithium3Legacy {
			return fmt.Errorf("%w: protocol %s requires %s, got %s", ErrInvalidProtocol, thresholdProtocol, qcrypto.SignatureAlgorithmDilithium3Legacy, algorithm)
		}
		return nil
	}
	profile, err := thresholdProtocol.Profile()
	if err != nil {
		return err
	}
	if profile.Algorithm != algorithm {
		return fmt.Errorf(
			"%w: protocol %s requires %s, got %s",
			ErrInvalidProtocol,
			thresholdProtocol,
			profile.Algorithm,
			algorithm,
		)
	}
	return nil
}

// ThresholdKeyID identifies one algorithm-specific group key generation.
type ThresholdKeyID struct {
	Algorithm  qcrypto.SignatureAlgorithm
	Generation uint64
	PublicKey  []byte
}

// Validate rejects ambiguous or unusable group-key identities.
func (key ThresholdKeyID) Validate() error {
	if !key.Algorithm.Supported() {
		return fmt.Errorf("%w: unsupported algorithm %d", ErrInvalidThresholdKey, key.Algorithm)
	}
	if key.Generation == 0 {
		return fmt.Errorf("%w: zero generation", ErrInvalidThresholdKey)
	}
	if len(key.PublicKey) != key.Algorithm.PublicKeySize() {
		return fmt.Errorf("%w: wrong public key length", ErrInvalidThresholdKey)
	}
	if qcrypto.IsZeroPublicKeyBytes(key.PublicKey) {
		return fmt.Errorf("%w: zero public key", ErrInvalidThresholdKey)
	}
	return nil
}

// Clone returns an identity that does not alias the original public-key bytes.
func (key ThresholdKeyID) Clone() ThresholdKeyID {
	key.PublicKey = append([]byte(nil), key.PublicKey...)
	return key
}

// CanonicalDigest returns the stable digest used in protocol transcripts.
func (key ThresholdKeyID) CanonicalDigest() ([32]byte, error) {
	if err := key.Validate(); err != nil {
		return [32]byte{}, err
	}
	encoded := make([]byte, 0, 23+len(key.PublicKey))
	encoded = append(encoded, []byte("QAU-THRESHOLD-KEY-V1")...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(key.Algorithm))
	encoded = binary.BigEndian.AppendUint64(encoded, key.Generation)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(key.PublicKey)))
	encoded = append(encoded, key.PublicKey...)
	return sha3.Sum256(encoded), nil
}

// CommitteeID identifies one ordered threshold committee generation.
type CommitteeID struct {
	Version      uint64
	Threshold    uint32
	Participants []uint32
}

// Validate requires a strictly increasing non-zero participant list.
func (committee CommitteeID) Validate() error {
	if committee.Version == 0 {
		return fmt.Errorf("%w: zero version", ErrInvalidCommittee)
	}
	if len(committee.Participants) < 2 {
		return fmt.Errorf("%w: fewer than two participants", ErrInvalidCommittee)
	}
	if committee.Threshold < 2 || int(committee.Threshold) > len(committee.Participants) {
		return fmt.Errorf("%w: threshold outside participant range", ErrInvalidCommittee)
	}
	var previous uint32
	for index, participant := range committee.Participants {
		if participant == 0 {
			return fmt.Errorf("%w: zero participant", ErrInvalidCommittee)
		}
		if index > 0 && participant <= previous {
			return fmt.Errorf("%w: participants must be strictly increasing", ErrInvalidCommittee)
		}
		previous = participant
	}
	return nil
}

// Clone returns an identity that does not alias the participant slice.
func (committee CommitteeID) Clone() CommitteeID {
	committee.Participants = append([]uint32(nil), committee.Participants...)
	return committee
}

// CanonicalDigest returns the stable digest used in protocol transcripts.
func (committee CommitteeID) CanonicalDigest() ([32]byte, error) {
	if err := committee.Validate(); err != nil {
		return [32]byte{}, err
	}
	encoded := make([]byte, 0, 32+4*len(committee.Participants))
	encoded = append(encoded, []byte("QAU-THRESHOLD-COMMITTEE-V1")...)
	encoded = binary.BigEndian.AppendUint64(encoded, committee.Version)
	encoded = binary.BigEndian.AppendUint32(encoded, committee.Threshold)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(committee.Participants)))
	for _, participant := range committee.Participants {
		encoded = binary.BigEndian.AppendUint32(encoded, participant)
	}
	return sha3.Sum256(encoded), nil
}

// SigningDomain separates threshold signatures used by different subsystems.
type SigningDomain uint16

const (
	SigningDomainUnknown SigningDomain = iota
	SigningDomainBlock
	SigningDomainVote
	SigningDomainFinality
)
