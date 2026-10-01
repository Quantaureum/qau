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
	complaintMagic          = "QTD3CP01"
	complaintVersion uint16 = 1
)

var (
	ErrInvalidComplaint         = errors.New("invalid Dilithium3 v1 complaint")
	ErrInvalidComplaintEncoding = errors.New("invalid Dilithium3 v1 complaint encoding")
	ErrComplaintDigestMismatch  = errors.New("Dilithium3 v1 complaint digest mismatch")
)

// ComplaintReason identifies one reviewable DKG failure class.
type ComplaintReason uint8

const (
	ComplaintReasonUnknown ComplaintReason = iota
	ComplaintReasonMissingSeed
	ComplaintReasonInvalidSeedEnvelope
	ComplaintReasonConflictingSeeds
	ComplaintReasonInvalidComponent
	ComplaintReasonContributionDigestMismatch
	ComplaintReasonPublishedContributionMismatch
	ComplaintReasonStaleContext
)

// ComplaintEvidence binds evidence to one exact group attempt.
//
// Admissibility policy: a complaint may replace a group leader only when its
// evidence is attributable to the accused dealer. Validate and ApplyComplaint
// are structural only — they hold no committee keys and no dealer envelope, so
// they cannot tell a genuine dealer message from a MessageDigest the complainant
// fabricated itself. A complaint without attributable evidence is therefore
// refused, including the bare "the leader never sent a seed" claim, which by
// construction leaves no signed envelope to show. An unattributable claim must
// never advance an attempt, so a stalled leader fails closed instead of letting
// one member burn the attempt. See the design document, section "Complaints and
// Leader Replacement". Wiring leader replacement into a driver requires this
// struct to carry the dealer's signed envelope plus a signature check against
// the committee roster (qcrypto.VerifySignatureForAlgorithm) before a complaint
// is accepted as admissible.
type ComplaintEvidence struct {
	SessionDigest   [32]byte
	CommitteeDigest [32]byte
	GroupMask       RSSGroupMask
	LeaderPosition  uint8
	Attempt         uint8
	MessageDigest   [32]byte
	RevealedSeed    [32]byte
}

// Complaint requests leader replacement for one failed group attempt.
type Complaint struct {
	SessionDigest       [32]byte
	CommitteeDigest     [32]byte
	GroupMask           RSSGroupMask
	LeaderPosition      uint8
	ComplainantPosition uint8
	Attempt             uint8
	Reason              ComplaintReason
	Evidence            ComplaintEvidence
}

// Validate rejects structurally false, unrelated, or seed-leaking complaint
// records. It is not an admissibility check: it cannot prove that the evidence
// is attributable to the accused dealer, so a structurally valid complaint still
// needs signature verification before it may replace a leader.
func (complaint Complaint) Validate() error {
	if complaint.SessionDigest == ([32]byte{}) || complaint.CommitteeDigest == ([32]byte{}) {
		return fmt.Errorf("%w: zero context digest", ErrInvalidComplaint)
	}
	if err := complaint.GroupMask.Validate(); err != nil {
		return fmt.Errorf("%w: group: %v", ErrInvalidComplaint, err)
	}
	leader, err := complaint.GroupMask.Leader(complaint.Attempt)
	if err != nil || leader != complaint.LeaderPosition {
		return fmt.Errorf("%w: wrong leader for attempt", ErrInvalidComplaint)
	}
	if !complaint.GroupMask.Contains(complaint.ComplainantPosition) || complaint.ComplainantPosition == complaint.LeaderPosition {
		return fmt.Errorf("%w: invalid complainant", ErrInvalidComplaint)
	}
	if complaint.Reason < ComplaintReasonMissingSeed || complaint.Reason > ComplaintReasonStaleContext {
		return fmt.Errorf("%w: unknown reason", ErrInvalidComplaint)
	}
	evidence := complaint.Evidence
	if evidence.SessionDigest != complaint.SessionDigest || evidence.CommitteeDigest != complaint.CommitteeDigest || evidence.GroupMask != complaint.GroupMask || evidence.LeaderPosition != complaint.LeaderPosition || evidence.Attempt != complaint.Attempt {
		return fmt.Errorf("%w: unrelated evidence", ErrInvalidComplaint)
	}
	if evidence.MessageDigest == ([32]byte{}) {
		return fmt.Errorf("%w: zero evidence digest", ErrInvalidComplaint)
	}
	revealsSeed := complaint.Reason == ComplaintReasonConflictingSeeds || complaint.Reason == ComplaintReasonInvalidComponent
	if revealsSeed != (evidence.RevealedSeed != ([32]byte{})) {
		return fmt.Errorf("%w: invalid seed disclosure", ErrInvalidComplaint)
	}
	return nil
}

// MarshalBinary encodes one fixed-size public complaint.
func (complaint Complaint) MarshalBinary() ([]byte, error) {
	if err := complaint.Validate(); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, complaintEncodedSize())
	encoded = append(encoded, complaintMagic...)
	encoded = binary.BigEndian.AppendUint16(encoded, complaintVersion)
	encoded = append(encoded, complaint.SessionDigest[:]...)
	encoded = append(encoded, complaint.CommitteeDigest[:]...)
	encoded = append(encoded, byte(complaint.GroupMask), complaint.LeaderPosition, complaint.ComplainantPosition, complaint.Attempt, byte(complaint.Reason))
	encoded = append(encoded, complaint.Evidence.SessionDigest[:]...)
	encoded = append(encoded, complaint.Evidence.CommitteeDigest[:]...)
	encoded = append(encoded, byte(complaint.Evidence.GroupMask), complaint.Evidence.LeaderPosition, complaint.Evidence.Attempt)
	encoded = append(encoded, complaint.Evidence.MessageDigest[:]...)
	encoded = append(encoded, complaint.Evidence.RevealedSeed[:]...)
	digest := sha3.Sum256(encoded)
	encoded = append(encoded, digest[:]...)
	return encoded, nil
}

// UnmarshalComplaint decodes and validates one fixed-size public complaint.
func UnmarshalComplaint(encoded []byte) (Complaint, error) {
	if len(encoded) != complaintEncodedSize() || !bytes.Equal(encoded[:8], []byte(complaintMagic)) {
		return Complaint{}, ErrInvalidComplaintEncoding
	}
	payloadEnd := len(encoded) - 32
	digest := sha3.Sum256(encoded[:payloadEnd])
	if subtle.ConstantTimeCompare(digest[:], encoded[payloadEnd:]) != 1 {
		return Complaint{}, ErrComplaintDigestMismatch
	}
	if binary.BigEndian.Uint16(encoded[8:10]) != complaintVersion {
		return Complaint{}, ErrInvalidComplaintEncoding
	}
	offset := 10
	var complaint Complaint
	copy(complaint.SessionDigest[:], encoded[offset:offset+32])
	offset += 32
	copy(complaint.CommitteeDigest[:], encoded[offset:offset+32])
	offset += 32
	complaint.GroupMask = RSSGroupMask(encoded[offset])
	offset++
	complaint.LeaderPosition = encoded[offset]
	offset++
	complaint.ComplainantPosition = encoded[offset]
	offset++
	complaint.Attempt = encoded[offset]
	offset++
	complaint.Reason = ComplaintReason(encoded[offset])
	offset++
	copy(complaint.Evidence.SessionDigest[:], encoded[offset:offset+32])
	offset += 32
	copy(complaint.Evidence.CommitteeDigest[:], encoded[offset:offset+32])
	offset += 32
	complaint.Evidence.GroupMask = RSSGroupMask(encoded[offset])
	offset++
	complaint.Evidence.LeaderPosition = encoded[offset]
	offset++
	complaint.Evidence.Attempt = encoded[offset]
	offset++
	copy(complaint.Evidence.MessageDigest[:], encoded[offset:offset+32])
	offset += 32
	copy(complaint.Evidence.RevealedSeed[:], encoded[offset:offset+32])
	if err := complaint.Validate(); err != nil {
		return Complaint{}, err
	}
	return complaint, nil
}

func complaintEncodedSize() int { return 8 + 2 + 32 + 32 + 5 + 32 + 32 + 3 + 32 + 32 + 32 }

// ApplyComplaint burns the current seed and advances to the next group leader.
// It may only be called with a complaint whose evidence has already been verified
// as attributable to the accused dealer; structural validation alone is not
// enough (see ComplaintEvidence). No production caller exists yet: the group
// driver refuses unattributable complaints and fails a stalled leader closed.
func (state *GroupAttemptState) ApplyComplaint(complaint Complaint) error {
	if state == nil || state.Aborted {
		return ErrDKGSessionAbort
	}
	if state.ContributionAccepted {
		return ErrGroupContributionFinalized
	}
	if err := complaint.Validate(); err != nil {
		return err
	}
	if complaint.SessionDigest != state.SessionDigest || complaint.CommitteeDigest != state.CommitteeDigest || complaint.GroupMask != state.GroupMask || complaint.Attempt != state.Attempt || complaint.LeaderPosition != state.LeaderPosition {
		return fmt.Errorf("%w: state context mismatch", ErrInvalidComplaint)
	}
	state.SeedMessageDigest = [32]byte{}
	state.ContributionDigest = [32]byte{}
	if state.Attempt == 2 {
		state.Aborted = true
		return ErrDKGSessionAbort
	}
	state.Attempt++
	state.LeaderPosition, _ = state.GroupMask.Leader(state.Attempt)
	return nil
}
