// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"fmt"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

var (
	ErrInvalidLocalShare  = errors.New("invalid Dilithium3 v1 local share")
	ErrLocalShareZeroized = errors.New("Dilithium3 v1 local share is zeroized")
)

// RSSComponent is one replicated secret component held by three participants.
//
// Multiplicity counts the fresh group contributions folded into the
// component: newly dealt components carry 1; every R77 fold adds the
// source's multiplicity to the target's. It bounds the signing protocol's
// per-signer partial norm (a member's partial is the sum of mult(G)
// |-eta|-bounded base contributions across the groups allocated to it), so
// sign.go and the executor scale their bound by the multiplicity sum rather
// than the raw group count. The value follows deterministically from the
// rotation history (committee versions), so it is byte-identical across
// honest members and discloses nothing the rotation plan does not already
// publish.
type RSSComponent struct {
	GroupMask          RSSGroupMask
	DealerPosition     uint8
	ContributionDigest [32]byte
	Multiplicity       uint32
	S1                 VectorL
	S2                 VectorK
}

// componentMultiplicity returns the floor of an unsigned multiplicity: a
// never-dealt component has no defined contribution count only if it was
// decoded from the pre-multiplicity share encoding, which treated every
// group as a single fresh contribution.
func componentMultiplicity(component RSSComponent) int {
	if component.Multiplicity == 0 {
		return 1
	}
	return int(component.Multiplicity)
}

// LocalShare binds one participant's RSS components to one key generation.
// The component count is binomial(C-1, g-1) for the session's committee size
// C (ten for the six-member profile).
type LocalShare struct {
	Protocol            protocol.ThresholdProtocol
	Key                 protocol.ThresholdKeyID
	Committee           protocol.CommitteeID
	ParticipantID       uint32
	ParticipantPosition uint8
	ActivationEpoch     uint64
	TranscriptDigest    [32]byte
	Rho                 [32]byte
	Components          []RSSComponent
	zeroized            bool
}

// Validate rejects identity substitution and malformed RSS component state.
func (share *LocalShare) Validate() error {
	if share == nil {
		return ErrInvalidLocalShare
	}
	if share.zeroized {
		return ErrLocalShareZeroized
	}
	if share.Protocol != protocol.ThresholdProtocolDilithium3V1 {
		return fmt.Errorf("%w: wrong protocol", ErrInvalidLocalShare)
	}
	if share.Key.Algorithm != qcrypto.SignatureAlgorithmDilithium3Legacy {
		return fmt.Errorf("%w: wrong algorithm", ErrInvalidLocalShare)
	}
	if err := share.Key.Validate(); err != nil {
		return fmt.Errorf("%w: key: %v", ErrInvalidLocalShare, err)
	}
	if err := protocol.ValidateDilithium3V1Committee(share.Committee); err != nil {
		return fmt.Errorf("%w: committee: %v", ErrInvalidLocalShare, err)
	}
	participants := len(share.Committee.Participants)
	position, found := committeePosition(share.Committee, share.ParticipantID)
	if !found {
		return fmt.Errorf("%w: participant %d is not in committee", ErrInvalidLocalShare, share.ParticipantID)
	}
	if share.ParticipantPosition != position {
		return fmt.Errorf("%w: participant position %d does not match committee position %d", ErrInvalidLocalShare, share.ParticipantPosition, position)
	}
	if share.ActivationEpoch == 0 {
		return fmt.Errorf("%w: zero activation epoch", ErrInvalidLocalShare)
	}
	if share.TranscriptDigest == ([32]byte{}) {
		return fmt.Errorf("%w: zero transcript digest", ErrInvalidLocalShare)
	}
	expectedGroups, err := GroupsForPositionN(position, participants)
	if err != nil {
		return fmt.Errorf("%w: participant groups: %v", ErrInvalidLocalShare, err)
	}
	if len(share.Components) != len(expectedGroups) {
		return fmt.Errorf("%w: component count %d, want %d", ErrInvalidLocalShare, len(share.Components), len(expectedGroups))
	}
	for index, component := range share.Components {
		if component.GroupMask != expectedGroups[index] {
			return fmt.Errorf("%w: component %d has group %06b, want %06b", ErrInvalidLocalShare, index, component.GroupMask, expectedGroups[index])
		}
		if int(component.DealerPosition) >= participants || !component.GroupMask.Contains(component.DealerPosition) {
			return fmt.Errorf("%w: component %d dealer %d is outside group", ErrInvalidLocalShare, index, component.DealerPosition)
		}
		if component.ContributionDigest == ([32]byte{}) {
			return fmt.Errorf("%w: component %d has zero contribution digest", ErrInvalidLocalShare, index)
		}
		if component.Multiplicity == 0 {
			return fmt.Errorf("%w: component %d has zero fold multiplicity", ErrInvalidLocalShare, index)
		}
		if err := validateVectorL(fmt.Sprintf("components[%d].s1", index), component.S1); err != nil {
			return err
		}
		if err := validateVectorK(fmt.Sprintf("components[%d].s2", index), component.S2); err != nil {
			return err
		}
	}
	return nil
}

// Clone returns an independent copy of public metadata and secret components.
func (share *LocalShare) Clone() *LocalShare {
	if share == nil {
		return nil
	}
	clone := *share
	clone.Key = share.Key.Clone()
	clone.Committee = share.Committee.Clone()
	clone.Components = append([]RSSComponent(nil), share.Components...)
	return &clone
}

// Zeroize clears all component secret vectors and permanently retires this value.
func (share *LocalShare) Zeroize() {
	if share == nil {
		return
	}
	for index := range share.Components {
		share.Components[index].S1 = VectorL{}
		share.Components[index].S2 = VectorK{}
	}
	share.zeroized = true
}

// IsZeroized reports whether the secret vectors have been retired.
func (share *LocalShare) IsZeroized() bool {
	return share == nil || share.zeroized
}

// CommitteePositionOf exports participant-position lookup for node-side
// ceremony drivers (rotation plans consume positions rather than IDs).
func CommitteePositionOf(committee protocol.CommitteeID, participantID uint32) (uint8, bool) {
	return committeePosition(committee, participantID)
}

func committeePosition(committee protocol.CommitteeID, participantID uint32) (uint8, bool) {
	if participantID == 0 {
		return 0, false
	}
	for index, candidate := range committee.Participants {
		if candidate == participantID {
			return uint8(index), true
		}
	}
	return 0, false
}

func validateVectorL(name string, vector VectorL) error {
	for vectorIndex := range vector {
		if err := validateSharePoly(name, vectorIndex, vector[vectorIndex]); err != nil {
			return err
		}
	}
	return nil
}

func validateVectorK(name string, vector VectorK) error {
	for vectorIndex := range vector {
		if err := validateSharePoly(name, vectorIndex, vector[vectorIndex]); err != nil {
			return err
		}
	}
	return nil
}

func validateSharePoly(name string, vectorIndex int, polynomial Poly) error {
	for coefficientIndex, coefficient := range polynomial {
		if !isCanonicalCoefficient(coefficient) {
			return fmt.Errorf("%w: %s[%d][%d] is non-canonical", ErrInvalidLocalShare, name, vectorIndex, coefficientIndex)
		}
	}
	return nil
}
