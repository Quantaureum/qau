// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	groupSeedMessageMagic              = "QTD3GS01"
	groupSeedMessageVersion     uint16 = 1
	groupSeedMessageDomain             = "QAU-TDILITHIUM3-V1-GROUP-SEED"
	groupSeedCommitmentDomain          = "QAU-TDILITHIUM3-V1-GROUP-SEED-COMMITMENT"
	groupAcknowledgementMagic          = "QTD3GA01"
	groupAcknowledgementVersion        = uint16(1)
	groupAcknowledgementDomain         = "QAU-TDILITHIUM3-V1-GROUP-ACK"
)

var (
	ErrInvalidGroupSeedMessage             = errors.New("invalid Dilithium3 v1 group seed message")
	ErrInvalidGroupSeedMessageEncoding     = errors.New("invalid Dilithium3 v1 group seed message encoding")
	ErrGroupSeedMessageDigestMismatch      = errors.New("Dilithium3 v1 group seed message digest mismatch")
	ErrInvalidGroupAcknowledgement         = errors.New("invalid Dilithium3 v1 group acknowledgement")
	ErrInvalidGroupAcknowledgementEncoding = errors.New("invalid Dilithium3 v1 group acknowledgement encoding")
	ErrGroupAcknowledgementDigestMismatch  = errors.New("Dilithium3 v1 group acknowledgement digest mismatch")
	ErrDuplicateGroupAcknowledgement       = errors.New("duplicate Dilithium3 v1 group acknowledgement")
	ErrConflictingPublicContribution       = errors.New("conflicting Dilithium3 v1 public contribution")
	ErrConflictingGroupSeed                = errors.New("conflicting Dilithium3 v1 group seed")
	ErrDuplicateGroupSeedMessage           = errors.New("duplicate Dilithium3 v1 group seed message")
	ErrGroupContributionFinalized          = errors.New("Dilithium3 v1 group contribution is finalized")
	ErrDKGSessionAbort                     = errors.New("Dilithium3 v1 DKG session must abort")
)

// GroupSeedMessage carries one private seed to one group recipient.
type GroupSeedMessage struct {
	SessionDigest     [32]byte
	CommitteeDigest   [32]byte
	GroupMask         RSSGroupMask
	LeaderPosition    uint8
	RecipientPosition uint8
	Attempt           uint8
	Seed              [32]byte
}

// Validate enforces one canonical leader, recipient, and fresh seed.
func (message GroupSeedMessage) Validate() error {
	if message.SessionDigest == ([32]byte{}) || message.CommitteeDigest == ([32]byte{}) {
		return fmt.Errorf("%w: zero context digest", ErrInvalidGroupSeedMessage)
	}
	if err := message.GroupMask.Validate(); err != nil {
		return fmt.Errorf("%w: group: %v", ErrInvalidGroupSeedMessage, err)
	}
	leader, err := message.GroupMask.Leader(message.Attempt)
	if err != nil || leader != message.LeaderPosition {
		return fmt.Errorf("%w: wrong leader for attempt", ErrInvalidGroupSeedMessage)
	}
	if !message.GroupMask.Contains(message.RecipientPosition) || message.RecipientPosition == message.LeaderPosition {
		return fmt.Errorf("%w: invalid recipient", ErrInvalidGroupSeedMessage)
	}
	if message.Seed == ([32]byte{}) {
		return fmt.Errorf("%w: zero seed", ErrInvalidGroupSeedMessage)
	}
	return nil
}

// ValidateFor binds a private message to the receiver's expected context.
func (message GroupSeedMessage) ValidateFor(sessionDigest, committeeDigest [32]byte, group RSSGroupMask, recipientPosition uint8) error {
	if err := message.Validate(); err != nil {
		return err
	}
	if message.SessionDigest != sessionDigest || message.CommitteeDigest != committeeDigest || message.GroupMask != group || message.RecipientPosition != recipientPosition {
		return fmt.Errorf("%w: context mismatch", ErrInvalidGroupSeedMessage)
	}
	return nil
}

// Digest returns the acknowledgement digest for this recipient-specific message.
func (message GroupSeedMessage) Digest() ([32]byte, error) {
	payload, err := message.canonicalPayload()
	if err != nil {
		return [32]byte{}, err
	}
	encoded := append([]byte(groupSeedMessageDomain), payload...)
	return sha3.Sum256(encoded), nil
}

// SeedCommitmentDigest binds the shared seed without revealing the recipient.
func (message GroupSeedMessage) SeedCommitmentDigest() ([32]byte, error) {
	if err := message.Validate(); err != nil {
		return [32]byte{}, err
	}
	encoded := make([]byte, 0, len(groupSeedCommitmentDomain)+32+32+1+1+1+32)
	encoded = append(encoded, groupSeedCommitmentDomain...)
	encoded = append(encoded, message.SessionDigest[:]...)
	encoded = append(encoded, message.CommitteeDigest[:]...)
	encoded = append(encoded, byte(message.GroupMask), message.LeaderPosition, message.Attempt)
	encoded = append(encoded, message.Seed[:]...)
	return sha3.Sum256(encoded), nil
}

// MarshalBinary encodes one private group seed message.
func (message GroupSeedMessage) MarshalBinary() ([]byte, error) {
	payload, err := message.canonicalPayload()
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, groupSeedMessageEncodedSize())
	encoded = append(encoded, groupSeedMessageMagic...)
	encoded = binary.BigEndian.AppendUint16(encoded, groupSeedMessageVersion)
	encoded = append(encoded, payload...)
	digest := sha3.Sum256(encoded)
	encoded = append(encoded, digest[:]...)
	return encoded, nil
}

// UnmarshalGroupSeedMessage decodes and validates a private group seed message.
func UnmarshalGroupSeedMessage(encoded []byte) (GroupSeedMessage, error) {
	if len(encoded) != groupSeedMessageEncodedSize() || !bytes.Equal(encoded[:8], []byte(groupSeedMessageMagic)) {
		return GroupSeedMessage{}, ErrInvalidGroupSeedMessageEncoding
	}
	payloadEnd := len(encoded) - 32
	digest := sha3.Sum256(encoded[:payloadEnd])
	if subtle.ConstantTimeCompare(digest[:], encoded[payloadEnd:]) != 1 {
		return GroupSeedMessage{}, ErrGroupSeedMessageDigestMismatch
	}
	if binary.BigEndian.Uint16(encoded[8:10]) != groupSeedMessageVersion {
		return GroupSeedMessage{}, ErrInvalidGroupSeedMessageEncoding
	}
	offset := 10
	var message GroupSeedMessage
	copy(message.SessionDigest[:], encoded[offset:offset+32])
	offset += 32
	copy(message.CommitteeDigest[:], encoded[offset:offset+32])
	offset += 32
	message.GroupMask = RSSGroupMask(encoded[offset])
	offset++
	message.LeaderPosition = encoded[offset]
	offset++
	message.RecipientPosition = encoded[offset]
	offset++
	message.Attempt = encoded[offset]
	offset++
	copy(message.Seed[:], encoded[offset:offset+32])
	if err := message.Validate(); err != nil {
		return GroupSeedMessage{}, err
	}
	return message, nil
}

func (message GroupSeedMessage) canonicalPayload() ([]byte, error) {
	if err := message.Validate(); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, 100)
	payload = append(payload, message.SessionDigest[:]...)
	payload = append(payload, message.CommitteeDigest[:]...)
	payload = append(payload, byte(message.GroupMask), message.LeaderPosition, message.RecipientPosition, message.Attempt)
	payload = append(payload, message.Seed[:]...)
	return payload, nil
}

func groupSeedMessageEncodedSize() int { return 8 + 2 + 100 + 32 }

// ContributionAcknowledgement reports one member's agreed public contribution digest.
type ContributionAcknowledgement struct {
	SessionDigest        [32]byte
	CommitteeDigest      [32]byte
	GroupMask            RSSGroupMask
	LeaderPosition       uint8
	ParticipantPosition  uint8
	Attempt              uint8
	SeedCommitmentDigest [32]byte
	SeedMessageDigest    [32]byte
	ContributionDigest   [32]byte
}

// Validate enforces acknowledgement identity and non-zero digests.
func (acknowledgement ContributionAcknowledgement) Validate() error {
	if acknowledgement.SessionDigest == ([32]byte{}) || acknowledgement.CommitteeDigest == ([32]byte{}) {
		return fmt.Errorf("%w: zero context digest", ErrInvalidGroupAcknowledgement)
	}
	if err := acknowledgement.GroupMask.Validate(); err != nil {
		return fmt.Errorf("%w: group: %v", ErrInvalidGroupAcknowledgement, err)
	}
	leader, err := acknowledgement.GroupMask.Leader(acknowledgement.Attempt)
	if err != nil || leader != acknowledgement.LeaderPosition {
		return fmt.Errorf("%w: wrong leader for attempt", ErrInvalidGroupAcknowledgement)
	}
	if !acknowledgement.GroupMask.Contains(acknowledgement.ParticipantPosition) {
		return fmt.Errorf("%w: participant outside group", ErrInvalidGroupAcknowledgement)
	}
	if acknowledgement.SeedCommitmentDigest == ([32]byte{}) || acknowledgement.SeedMessageDigest == ([32]byte{}) || acknowledgement.ContributionDigest == ([32]byte{}) {
		return fmt.Errorf("%w: zero acknowledgement digest", ErrInvalidGroupAcknowledgement)
	}
	return nil
}

// Digest returns the canonical public acknowledgement digest.
func (acknowledgement ContributionAcknowledgement) Digest() ([32]byte, error) {
	payload, err := acknowledgement.canonicalPayload()
	if err != nil {
		return [32]byte{}, err
	}
	encoded := append([]byte(groupAcknowledgementDomain), payload...)
	return sha3.Sum256(encoded), nil
}

// MarshalBinary encodes one public acknowledgement.
func (acknowledgement ContributionAcknowledgement) MarshalBinary() ([]byte, error) {
	payload, err := acknowledgement.canonicalPayload()
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, groupAcknowledgementEncodedSize())
	encoded = append(encoded, groupAcknowledgementMagic...)
	encoded = binary.BigEndian.AppendUint16(encoded, groupAcknowledgementVersion)
	encoded = append(encoded, payload...)
	digest := sha3.Sum256(encoded)
	encoded = append(encoded, digest[:]...)
	return encoded, nil
}

// UnmarshalContributionAcknowledgement decodes one public acknowledgement.
func UnmarshalContributionAcknowledgement(encoded []byte) (ContributionAcknowledgement, error) {
	if len(encoded) != groupAcknowledgementEncodedSize() || !bytes.Equal(encoded[:8], []byte(groupAcknowledgementMagic)) {
		return ContributionAcknowledgement{}, ErrInvalidGroupAcknowledgementEncoding
	}
	payloadEnd := len(encoded) - 32
	digest := sha3.Sum256(encoded[:payloadEnd])
	if subtle.ConstantTimeCompare(digest[:], encoded[payloadEnd:]) != 1 {
		return ContributionAcknowledgement{}, ErrGroupAcknowledgementDigestMismatch
	}
	if binary.BigEndian.Uint16(encoded[8:10]) != groupAcknowledgementVersion {
		return ContributionAcknowledgement{}, ErrInvalidGroupAcknowledgementEncoding
	}
	offset := 10
	var acknowledgement ContributionAcknowledgement
	copy(acknowledgement.SessionDigest[:], encoded[offset:offset+32])
	offset += 32
	copy(acknowledgement.CommitteeDigest[:], encoded[offset:offset+32])
	offset += 32
	acknowledgement.GroupMask = RSSGroupMask(encoded[offset])
	offset++
	acknowledgement.LeaderPosition = encoded[offset]
	offset++
	acknowledgement.ParticipantPosition = encoded[offset]
	offset++
	acknowledgement.Attempt = encoded[offset]
	offset++
	copy(acknowledgement.SeedCommitmentDigest[:], encoded[offset:offset+32])
	offset += 32
	copy(acknowledgement.SeedMessageDigest[:], encoded[offset:offset+32])
	offset += 32
	copy(acknowledgement.ContributionDigest[:], encoded[offset:offset+32])
	if err := acknowledgement.Validate(); err != nil {
		return ContributionAcknowledgement{}, err
	}
	return acknowledgement, nil
}

func (acknowledgement ContributionAcknowledgement) canonicalPayload() ([]byte, error) {
	if err := acknowledgement.Validate(); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, 164)
	payload = append(payload, acknowledgement.SessionDigest[:]...)
	payload = append(payload, acknowledgement.CommitteeDigest[:]...)
	payload = append(payload, byte(acknowledgement.GroupMask), acknowledgement.LeaderPosition, acknowledgement.ParticipantPosition, acknowledgement.Attempt)
	payload = append(payload, acknowledgement.SeedCommitmentDigest[:]...)
	payload = append(payload, acknowledgement.SeedMessageDigest[:]...)
	payload = append(payload, acknowledgement.ContributionDigest[:]...)
	return payload, nil
}

func groupAcknowledgementEncodedSize() int { return 8 + 2 + 164 + 32 }

// GroupAcknowledgementSet rejects duplicates and contribution equivocation.
type GroupAcknowledgementSet struct {
	sessionDigest        [32]byte
	committeeDigest      [32]byte
	groupMask            RSSGroupMask
	leaderPosition       uint8
	attempt              uint8
	seedCommitmentDigest [32]byte
	contributionDigest   [32]byte
	seen                 [6]bool
	count                uint8
}

// NewGroupAcknowledgementSet creates the exact context for three group acknowledgements.
func NewGroupAcknowledgementSet(message GroupSeedMessage, contributionDigest [32]byte) (*GroupAcknowledgementSet, error) {
	if err := message.Validate(); err != nil {
		return nil, ErrInvalidGroupAcknowledgement
	}
	seedCommitmentDigest, err := message.SeedCommitmentDigest()
	if err != nil {
		return nil, err
	}
	return NewGroupAcknowledgementSetFromContext(message.SessionDigest, message.CommitteeDigest, message.GroupMask, message.LeaderPosition, message.Attempt, seedCommitmentDigest, contributionDigest)
}

// NewGroupAcknowledgementSetFromContext rebuilds the same acknowledgement
// context from public fields only. Participants outside a group never receive
// its private seed, so they cannot call NewGroupAcknowledgementSet; they learn
// the shared seed commitment digest from the signed acknowledgements
// themselves. The contribution digest still has to match, so a group that
// equivocates on t_U cannot collect three acknowledgements.
func NewGroupAcknowledgementSetFromContext(
	sessionDigest, committeeDigest [32]byte,
	group RSSGroupMask,
	leaderPosition, attempt uint8,
	seedCommitmentDigest, contributionDigest [32]byte,
) (*GroupAcknowledgementSet, error) {
	if sessionDigest == ([32]byte{}) || committeeDigest == ([32]byte{}) || seedCommitmentDigest == ([32]byte{}) || contributionDigest == ([32]byte{}) {
		return nil, ErrInvalidGroupAcknowledgement
	}
	if err := group.Validate(); err != nil {
		return nil, ErrInvalidGroupAcknowledgement
	}
	leader, err := group.Leader(attempt)
	if err != nil || leader != leaderPosition {
		return nil, ErrInvalidGroupAcknowledgement
	}
	return &GroupAcknowledgementSet{sessionDigest: sessionDigest, committeeDigest: committeeDigest, groupMask: group, leaderPosition: leaderPosition, attempt: attempt, seedCommitmentDigest: seedCommitmentDigest, contributionDigest: contributionDigest}, nil
}

// Add records one unique matching group acknowledgement.
func (set *GroupAcknowledgementSet) Add(acknowledgement ContributionAcknowledgement) error {
	if set == nil {
		return ErrInvalidGroupAcknowledgement
	}
	if err := acknowledgement.Validate(); err != nil {
		return err
	}
	if acknowledgement.SessionDigest != set.sessionDigest || acknowledgement.CommitteeDigest != set.committeeDigest || acknowledgement.GroupMask != set.groupMask || acknowledgement.LeaderPosition != set.leaderPosition || acknowledgement.Attempt != set.attempt || acknowledgement.SeedCommitmentDigest != set.seedCommitmentDigest {
		return fmt.Errorf("%w: context mismatch", ErrInvalidGroupAcknowledgement)
	}
	if acknowledgement.ContributionDigest != set.contributionDigest {
		return ErrConflictingPublicContribution
	}
	if set.seen[acknowledgement.ParticipantPosition] {
		return ErrDuplicateGroupAcknowledgement
	}
	set.seen[acknowledgement.ParticipantPosition] = true
	set.count++
	return nil
}

// Complete reports whether all three group members acknowledged one contribution.
func (set *GroupAcknowledgementSet) Complete() bool { return set != nil && set.count == 3 }

// GroupAttemptState tracks one group's monotonic leader replacement state.
type GroupAttemptState struct {
	SessionDigest        [32]byte
	CommitteeDigest      [32]byte
	GroupMask            RSSGroupMask
	Attempt              uint8
	LeaderPosition       uint8
	SeedMessageDigest    [32]byte
	ContributionDigest   [32]byte
	ContributionAccepted bool
	Aborted              bool
}

// NewGroupAttemptState starts at the lowest-position group leader.
func NewGroupAttemptState(sessionDigest, committeeDigest [32]byte, group RSSGroupMask) (*GroupAttemptState, error) {
	if sessionDigest == ([32]byte{}) || committeeDigest == ([32]byte{}) || group.Validate() != nil {
		return nil, ErrInvalidGroupSeedMessage
	}
	leader, _ := group.Leader(0)
	return &GroupAttemptState{SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group, LeaderPosition: leader}, nil
}

// AcceptSeed durably binds one fresh recipient-specific seed message to the attempt.
func (state *GroupAttemptState) AcceptSeed(message GroupSeedMessage) error {
	if state == nil || state.Aborted {
		return ErrDKGSessionAbort
	}
	if state.ContributionAccepted {
		return ErrGroupContributionFinalized
	}
	if err := message.Validate(); err != nil {
		return err
	}
	if message.SessionDigest != state.SessionDigest || message.CommitteeDigest != state.CommitteeDigest || message.GroupMask != state.GroupMask || message.Attempt != state.Attempt || message.LeaderPosition != state.LeaderPosition {
		return fmt.Errorf("%w: attempt context mismatch", ErrInvalidGroupSeedMessage)
	}
	digest, err := message.Digest()
	if err != nil {
		return err
	}
	if state.SeedMessageDigest != ([32]byte{}) {
		if state.SeedMessageDigest != digest {
			return ErrConflictingGroupSeed
		}
		return ErrDuplicateGroupSeedMessage
	}
	state.SeedMessageDigest = digest
	return nil
}

// MarkContributionAccepted prevents any later leader replacement.
func (state *GroupAttemptState) MarkContributionAccepted(digest [32]byte) error {
	if state == nil || state.Aborted || state.SeedMessageDigest == ([32]byte{}) || digest == ([32]byte{}) {
		return ErrInvalidGroupAcknowledgement
	}
	state.ContributionDigest = digest
	state.ContributionAccepted = true
	return nil
}
