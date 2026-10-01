// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"errors"
	"fmt"
	"math"

	qcrypto "github.com/quantaureum/qau/crypto"
)

const (
	ThresholdV1ParticipantCount uint32 = 6
	ThresholdV1Threshold        uint32 = 4
	ThresholdV1MaxCorrupt       uint32 = 2

	TMLDSAV1ParticipantCount = ThresholdV1ParticipantCount
	TMLDSAV1Threshold        = ThresholdV1Threshold
	TMLDSAV1MaxCorrupt       = ThresholdV1MaxCorrupt
)

var (
	ErrInvalidThresholdProfile    = errors.New("invalid threshold protocol profile")
	ErrInvalidThresholdTransition = errors.New("invalid threshold committee transition")
	ErrInvalidTMLDSAV1Profile     = errors.New("invalid TMLDSA v1 profile")
	ErrInvalidTMLDSAV1Transition  = errors.New("invalid TMLDSA v1 committee transition")
)

// ThresholdProtocolProfile defines one immutable protocol and algorithm pair.
type ThresholdProtocolProfile struct {
	Protocol     ThresholdProtocol
	Algorithm    qcrypto.SignatureAlgorithm
	Participants uint32
	Threshold    uint32
	MaxCorrupt   uint32
}

// Dilithium3V1Profile returns the fixed legacy mode3 threshold profile.
func Dilithium3V1Profile() ThresholdProtocolProfile {
	return ThresholdProtocolProfile{
		Protocol:     ThresholdProtocolDilithium3V1,
		Algorithm:    qcrypto.SignatureAlgorithmDilithium3Legacy,
		Participants: ThresholdV1ParticipantCount,
		Threshold:    ThresholdV1Threshold,
		MaxCorrupt:   ThresholdV1MaxCorrupt,
	}
}

// MLDSA65ExperimentalV1Profile returns the existing experimental profile.
func MLDSA65ExperimentalV1Profile() ThresholdProtocolProfile {
	return ThresholdProtocolProfile{
		Protocol:     ThresholdProtocolMLDSA65ExperimentalV1,
		Algorithm:    qcrypto.SignatureAlgorithmMLDSA65,
		Participants: ThresholdV1ParticipantCount,
		Threshold:    ThresholdV1Threshold,
		MaxCorrupt:   ThresholdV1MaxCorrupt,
	}
}

// Profile returns the immutable profile for a recognized protocol.
func (thresholdProtocol ThresholdProtocol) Profile() (ThresholdProtocolProfile, error) {
	switch thresholdProtocol {
	case ThresholdProtocolDilithium3V1:
		return Dilithium3V1Profile(), nil
	case ThresholdProtocolMLDSA65ExperimentalV1:
		return MLDSA65ExperimentalV1Profile(), nil
	default:
		return ThresholdProtocolProfile{}, fmt.Errorf("%w: %d", ErrInvalidProtocol, thresholdProtocol)
	}
}

// Validate rejects malformed or inconsistent fixed-profile values.
func (profile ThresholdProtocolProfile) Validate() error {
	if !profile.Protocol.Supported() {
		return fmt.Errorf("%w: unsupported protocol", ErrInvalidThresholdProfile)
	}
	if err := profile.Protocol.ValidateAlgorithm(profile.Algorithm); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidThresholdProfile, err)
	}
	if profile.Participants != ThresholdV1ParticipantCount ||
		profile.Threshold != ThresholdV1Threshold ||
		profile.MaxCorrupt != ThresholdV1MaxCorrupt {
		return fmt.Errorf("%w: unsupported dimensions", ErrInvalidThresholdProfile)
	}
	return nil
}

// ValidateCommittee requires the fixed four-of-six committee.
func (profile ThresholdProtocolProfile) ValidateCommittee(committee CommitteeID) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if err := committee.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidThresholdProfile, err)
	}
	if len(committee.Participants) != int(profile.Participants) {
		return fmt.Errorf("%w: participant count %d, want %d", ErrInvalidThresholdProfile, len(committee.Participants), profile.Participants)
	}
	if committee.Threshold != profile.Threshold {
		return fmt.Errorf("%w: threshold %d, want %d", ErrInvalidThresholdProfile, committee.Threshold, profile.Threshold)
	}
	return nil
}

// ValidateTransition requires consecutive versions and matching fixed profiles.
func (profile ThresholdProtocolProfile) ValidateTransition(oldCommittee, newCommittee CommitteeID) error {
	if err := profile.ValidateCommittee(oldCommittee); err != nil {
		return err
	}
	if err := profile.ValidateCommittee(newCommittee); err != nil {
		return err
	}
	if oldCommittee.Version == math.MaxUint64 || newCommittee.Version != oldCommittee.Version+1 {
		return fmt.Errorf("%w: version %d must follow %d", ErrInvalidThresholdTransition, newCommittee.Version, oldCommittee.Version)
	}
	return nil
}

// TMLDSAV1Profile defines the fixed active-committee security profile.
type TMLDSAV1Profile struct{}

// DefaultTMLDSAV1Profile returns the protocol v1 profile.
func DefaultTMLDSAV1Profile() TMLDSAV1Profile {
	return TMLDSAV1Profile{}
}

// ValidateCommittee requires the fixed four-of-six active committee.
func (TMLDSAV1Profile) ValidateCommittee(committee CommitteeID) error {
	if err := MLDSA65ExperimentalV1Profile().ValidateCommittee(committee); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTMLDSAV1Profile, err)
	}
	return nil
}

// ValidateTransition requires consecutive versions and valid old and new committees.
func (profile TMLDSAV1Profile) ValidateTransition(oldCommittee, newCommittee CommitteeID) error {
	if err := MLDSA65ExperimentalV1Profile().ValidateTransition(oldCommittee, newCommittee); err != nil {
		if errors.Is(err, ErrInvalidThresholdTransition) {
			return fmt.Errorf("%w: %v", ErrInvalidTMLDSAV1Transition, err)
		}
		return fmt.Errorf("%w: %v", ErrInvalidTMLDSAV1Profile, err)
	}
	return nil
}
