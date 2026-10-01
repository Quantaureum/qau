// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"errors"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
)

func TestThresholdProtocolProfiles(t *testing.T) {
	tests := []struct {
		name      string
		profile   ThresholdProtocolProfile
		protocol  ThresholdProtocol
		algorithm qcrypto.SignatureAlgorithm
	}{
		{
			name:      "dilithium3 v1",
			profile:   Dilithium3V1Profile(),
			protocol:  ThresholdProtocolDilithium3V1,
			algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy,
		},
		{
			name:      "mldsa65 experimental v1",
			profile:   MLDSA65ExperimentalV1Profile(),
			protocol:  ThresholdProtocolMLDSA65ExperimentalV1,
			algorithm: qcrypto.SignatureAlgorithmMLDSA65,
		},
	}

	committee := CommitteeID{
		Version:      1,
		Threshold:    4,
		Participants: []uint32{1, 2, 3, 4, 5, 6},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.profile.Protocol != test.protocol || test.profile.Algorithm != test.algorithm {
				t.Fatalf("profile identity = (%v, %v), want (%v, %v)", test.profile.Protocol, test.profile.Algorithm, test.protocol, test.algorithm)
			}
			if test.profile.Participants != 6 || test.profile.Threshold != 4 || test.profile.MaxCorrupt != 2 {
				t.Fatalf("unexpected fixed profile: %#v", test.profile)
			}
			if err := test.profile.ValidateCommittee(committee); err != nil {
				t.Fatalf("ValidateCommittee: %v", err)
			}
		})
	}
}

func TestThresholdProtocolRejectsAlgorithmMismatch(t *testing.T) {
	tests := []struct {
		name      string
		protocol  ThresholdProtocol
		algorithm qcrypto.SignatureAlgorithm
	}{
		{name: "unknown protocol", protocol: ThresholdProtocolUnknown, algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy},
		{name: "dilithium protocol with mldsa", protocol: ThresholdProtocolDilithium3V1, algorithm: qcrypto.SignatureAlgorithmMLDSA65},
		{name: "mldsa protocol with dilithium", protocol: ThresholdProtocolMLDSA65ExperimentalV1, algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.protocol.ValidateAlgorithm(test.algorithm); err == nil {
				t.Fatal("protocol and algorithm mismatch accepted")
			}
		})
	}
}

func TestTMLDSAV1ProfileValidateCommittee(t *testing.T) {
	profile := DefaultTMLDSAV1Profile()
	valid := CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}}
	if err := profile.ValidateCommittee(valid); err != nil {
		t.Fatalf("valid 4-of-6 committee rejected: %v", err)
	}

	tests := []struct {
		name      string
		committee CommitteeID
	}{
		{name: "five participants", committee: CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5}}},
		{name: "late joiner appended to active committee", committee: CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6, 7}}},
		{name: "wrong threshold", committee: CommitteeID{Version: 1, Threshold: 3, Participants: []uint32{1, 2, 3, 4, 5, 6}}},
		{name: "duplicate participant", committee: CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 5}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := profile.ValidateCommittee(test.committee); !errors.Is(err, ErrInvalidTMLDSAV1Profile) {
				t.Fatalf("ValidateCommittee() error = %v, want %v", err, ErrInvalidTMLDSAV1Profile)
			}
		})
	}
}

func TestTMLDSAV1ProfileValidateTransition(t *testing.T) {
	profile := DefaultTMLDSAV1Profile()
	oldCommittee := CommitteeID{Version: 7, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}}
	newCommittee := CommitteeID{Version: 8, Threshold: 4, Participants: []uint32{3, 4, 5, 6, 7, 8}}
	if err := profile.ValidateTransition(oldCommittee, newCommittee); err != nil {
		t.Fatalf("valid six-to-six rotation rejected: %v", err)
	}

	unchangedVersion := newCommittee
	unchangedVersion.Version = oldCommittee.Version
	if err := profile.ValidateTransition(oldCommittee, unchangedVersion); !errors.Is(err, ErrInvalidTMLDSAV1Transition) {
		t.Fatalf("same-version transition error = %v, want %v", err, ErrInvalidTMLDSAV1Transition)
	}

	skippedVersion := newCommittee
	skippedVersion.Version = oldCommittee.Version + 2
	if err := profile.ValidateTransition(oldCommittee, skippedVersion); !errors.Is(err, ErrInvalidTMLDSAV1Transition) {
		t.Fatalf("skipped-version transition error = %v, want %v", err, ErrInvalidTMLDSAV1Transition)
	}

	lateJoinWithoutRotation := newCommittee
	lateJoinWithoutRotation.Participants = []uint32{1, 2, 3, 4, 5, 6, 7}
	if err := profile.ValidateTransition(oldCommittee, lateJoinWithoutRotation); !errors.Is(err, ErrInvalidTMLDSAV1Profile) {
		t.Fatalf("seven-member transition error = %v, want %v", err, ErrInvalidTMLDSAV1Profile)
	}
}
