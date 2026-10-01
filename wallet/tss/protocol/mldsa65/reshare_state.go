// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"bytes"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const (
	ReshareConsistencyRounds         uint32 = 8
	ReshareConsistencyChecksPerRound uint32 = 3
	reshareDealerWitnessNamespace    uint32 = 1 << 31

	reshareConsistencyStateMagic   = "QTMLDSA-RESHARE-CONSISTENCY-1"
	reshareConsistencyStateVersion = 1
	maxReshareConsistencyStateSize = 4 << 20
)

// ReshareDealerWitnessID returns the logical sender ID used for the dealer's
// old-share witness in the constant-link consistency check.
func ReshareDealerWitnessID(dealerID uint32) uint32 {
	if dealerID == 0 || dealerID&reshareDealerWitnessNamespace != 0 {
		return 0
	}
	return reshareDealerWitnessNamespace | dealerID
}

var (
	ErrInvalidReshareState     = errors.New("invalid TMLDSA v1 reshare consistency state")
	ErrReshareStateTransition  = errors.New("invalid TMLDSA v1 reshare state transition")
	ErrReshareStateRollback    = errors.New("TMLDSA v1 reshare state rollback or fork")
	ErrReshareEquivocation     = errors.New("TMLDSA v1 reshare equivocation")
	ErrReshareNonZeroSyndrome  = errors.New("TMLDSA v1 reshare non-zero syndrome")
	ErrReshareTranscriptFailed = errors.New("TMLDSA v1 reshare transcript failed")
)

// ReshareConsistencyPhase is the durable network transcript phase.
type ReshareConsistencyPhase uint8

const (
	ReshareConsistencyPhaseUnknown ReshareConsistencyPhase = iota
	ReshareConsistencyPhaseContributionAgreement
	ReshareConsistencyPhaseNonceCommitment
	ReshareConsistencyPhaseNonceReveal
	ReshareConsistencyPhaseTermCommitment
	ReshareConsistencyPhaseTermReveal
	ReshareConsistencyPhaseVerified
	ReshareConsistencyPhaseAborted
)

// ReshareAbortReason identifies why a transcript became permanently unusable.
type ReshareAbortReason uint8

const (
	ReshareAbortReasonUnknown ReshareAbortReason = iota
	ReshareAbortReasonEquivocation
	ReshareAbortReasonTranscriptMismatch
	ReshareAbortReasonInvalidReveal
	ReshareAbortReasonNonZeroSyndrome
	ReshareAbortReasonTimeout
	ReshareAbortReasonPersistence
)

// ReshareAbortEvidence is the public, signable description of one abort.
type ReshareAbortEvidence struct {
	Reason       ReshareAbortReason `json:"reason"`
	OffenderID   uint32             `json:"offender_id"`
	Round        uint32             `json:"round"`
	CheckID      uint32             `json:"check_id"`
	DetailDigest [32]byte           `json:"detail_digest"`
}

type reshareConsistencyEventKind uint8

const (
	reshareConsistencyEventUnknown reshareConsistencyEventKind = iota
	reshareConsistencyEventAgreement
	reshareConsistencyEventNonceCommitment
	reshareConsistencyEventNonceReveal
	reshareConsistencyEventTermCommitment
	reshareConsistencyEventTermReveal
	reshareConsistencyEventAbort
)

type reshareConsistencyEvent struct {
	Kind     reshareConsistencyEventKind `json:"kind"`
	SenderID uint32                      `json:"sender_id,omitempty"`
	Value    [32]byte                    `json:"value,omitempty"`
	Term     int32                       `json:"term,omitempty"`
	Salt     [32]byte                    `json:"salt,omitempty"`
	Abort    ReshareAbortEvidence        `json:"abort,omitempty"`
}

type reshareRecipientCommitment struct {
	RecipientID uint32   `json:"recipient_id"`
	Commitment  [32]byte `json:"commitment"`
}

type reshareConsistencyEncoding struct {
	Version                 int                          `json:"version"`
	SessionID               [32]byte                     `json:"session_id"`
	Key                     protocol.ThresholdKeyID      `json:"key"`
	OldCommittee            protocol.CommitteeID         `json:"old_committee"`
	NewCommittee            protocol.CommitteeID         `json:"new_committee"`
	SelectedDealers         []uint32                     `json:"selected_dealers"`
	DealerID                uint32                       `json:"dealer_id"`
	ContributionCommitments []reshareRecipientCommitment `json:"contribution_commitments"`
	Events                  []reshareConsistencyEvent    `json:"events"`
	Phase                   ReshareConsistencyPhase      `json:"phase"`
	Round                   uint32                       `json:"round"`
	CheckID                 uint32                       `json:"check_id"`
	TranscriptDigest        [32]byte                     `json:"transcript_digest"`
}

// ReshareConsistencyCoordinator enforces one dealer's globally ordered checks.
type ReshareConsistencyCoordinator struct {
	sessionID               [32]byte
	key                     protocol.ThresholdKeyID
	oldCommittee            protocol.CommitteeID
	newCommittee            protocol.CommitteeID
	selectedDealers         []uint32
	dealerID                uint32
	contributionCommitments map[uint32][32]byte
	contributionSetDigest   [32]byte
	agreements              map[uint32][32]byte
	nonceCommitments        map[uint32][32]byte
	nonceReveals            map[uint32][32]byte
	termCommitments         map[uint32][32]byte
	termReveals             map[uint32]ReshareMaskedTermReveal
	challengeSeed           [32]byte
	phase                   ReshareConsistencyPhase
	round                   uint32
	checkID                 uint32
	events                  []reshareConsistencyEvent
	transcriptDigest        [32]byte
	abortEvidence           ReshareAbortEvidence
	hasAbortEvidence        bool
}

// NewReshareConsistencyCoordinator creates one dealer-bound transcript.
func NewReshareConsistencyCoordinator(
	sessionID [32]byte,
	key protocol.ThresholdKeyID,
	oldCommittee protocol.CommitteeID,
	newCommittee protocol.CommitteeID,
	selectedDealers []uint32,
	dealerID uint32,
	contributionCommitments map[uint32][32]byte,
) (*ReshareConsistencyCoordinator, error) {
	if sessionID == ([32]byte{}) || key.Algorithm != qcrypto.SignatureAlgorithmMLDSA65 {
		return nil, ErrInvalidReshareState
	}
	if err := key.Validate(); err != nil {
		return nil, ErrInvalidReshareState
	}
	if err := DefaultProfile().ValidateTransition(oldCommittee, newCommittee); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidReshareState, err)
	}
	if err := validateSelectedDealers(oldCommittee, selectedDealers); err != nil ||
		!containsParticipant(selectedDealers, dealerID) ||
		!validResharePhysicalParticipants(oldCommittee.Participants) ||
		!validResharePhysicalParticipants(newCommittee.Participants) {
		return nil, ErrInvalidReshareState
	}
	if len(contributionCommitments) != len(newCommittee.Participants) {
		return nil, ErrInvalidReshareState
	}
	commitments := make(map[uint32][32]byte, len(contributionCommitments))
	for _, recipientID := range newCommittee.Participants {
		commitment, ok := contributionCommitments[recipientID]
		if !ok || commitment == ([32]byte{}) {
			return nil, ErrInvalidReshareState
		}
		commitments[recipientID] = commitment
	}
	coordinator := &ReshareConsistencyCoordinator{
		sessionID:               sessionID,
		key:                     key.Clone(),
		oldCommittee:            oldCommittee.Clone(),
		newCommittee:            newCommittee.Clone(),
		selectedDealers:         append([]uint32(nil), selectedDealers...),
		dealerID:                dealerID,
		contributionCommitments: commitments,
		agreements:              make(map[uint32][32]byte, len(newCommittee.Participants)),
		nonceCommitments:        make(map[uint32][32]byte, len(newCommittee.Participants)),
		nonceReveals:            make(map[uint32][32]byte, len(newCommittee.Participants)),
		termCommitments:         make(map[uint32][32]byte, len(newCommittee.Participants)),
		termReveals:             make(map[uint32]ReshareMaskedTermReveal, len(newCommittee.Participants)),
		phase:                   ReshareConsistencyPhaseContributionAgreement,
	}
	coordinator.contributionSetDigest = coordinator.computeContributionSetDigest()
	coordinator.transcriptDigest = coordinator.computeInitialTranscriptDigest()
	return coordinator, nil
}

// Phase returns the current durable phase.
func (coordinator *ReshareConsistencyCoordinator) Phase() ReshareConsistencyPhase {
	if coordinator == nil {
		return ReshareConsistencyPhaseUnknown
	}
	return coordinator.phase
}

// CurrentCheck returns the currently active projection round and check.
func (coordinator *ReshareConsistencyCoordinator) CurrentCheck() (uint32, uint32) {
	if coordinator == nil {
		return 0, 0
	}
	return coordinator.round, coordinator.checkID
}

// ContributionSetDigest is the value every recipient must acknowledge.
func (coordinator *ReshareConsistencyCoordinator) ContributionSetDigest() [32]byte {
	if coordinator == nil {
		return [32]byte{}
	}
	return coordinator.contributionSetDigest
}

// ValidateContributionCommitment binds installation to the agreed recipient payload.
func (coordinator *ReshareConsistencyCoordinator) ValidateContributionCommitment(
	recipientID uint32,
	commitment [32]byte,
) error {
	if coordinator == nil || commitment == ([32]byte{}) {
		return ErrInvalidReshareState
	}
	want, ok := coordinator.contributionCommitments[recipientID]
	if !ok || subtle.ConstantTimeCompare(want[:], commitment[:]) != 1 {
		return ErrInvalidReshareState
	}
	return nil
}

// SessionIdentity returns the public storage-routing identity.
func (coordinator *ReshareConsistencyCoordinator) SessionIdentity() ([32]byte, uint32, error) {
	if coordinator == nil || coordinator.sessionID == ([32]byte{}) || coordinator.dealerID == 0 {
		return [32]byte{}, 0, ErrInvalidReshareState
	}
	return coordinator.sessionID, coordinator.dealerID, nil
}

// ValidateIdentity rejects any runner request that does not exactly match the
// durable coordinator generation and participant sets.
func (coordinator *ReshareConsistencyCoordinator) ValidateIdentity(
	sessionID [32]byte,
	key protocol.ThresholdKeyID,
	oldCommittee protocol.CommitteeID,
	newCommittee protocol.CommitteeID,
	selectedDealers []uint32,
	dealerID uint32,
) error {
	if coordinator == nil || coordinator.sessionID != sessionID || coordinator.dealerID != dealerID ||
		!sameThresholdKey(coordinator.key, key) ||
		!sameCommittee(coordinator.oldCommittee, oldCommittee) ||
		!sameCommittee(coordinator.newCommittee, newCommittee) ||
		len(coordinator.selectedDealers) != len(selectedDealers) {
		return ErrInvalidReshareState
	}
	for index := range selectedDealers {
		if coordinator.selectedDealers[index] != selectedDealers[index] {
			return ErrInvalidReshareState
		}
	}
	return nil
}

// ChallengeSeed returns the public projection seed after nonce reveal.
func (coordinator *ReshareConsistencyCoordinator) ChallengeSeed() [32]byte {
	if coordinator == nil {
		return [32]byte{}
	}
	return coordinator.challengeSeed
}

// TranscriptDigest returns the hash-chain head for durable replay binding.
func (coordinator *ReshareConsistencyCoordinator) TranscriptDigest() [32]byte {
	if coordinator == nil {
		return [32]byte{}
	}
	return coordinator.transcriptDigest
}

// TranscriptDigestAt returns the hash-chain head after an exact event prefix.
func (coordinator *ReshareConsistencyCoordinator) TranscriptDigestAt(eventCount uint64) ([32]byte, error) {
	if coordinator == nil || eventCount > uint64(len(coordinator.events)) {
		return [32]byte{}, ErrInvalidReshareState
	}
	digest := coordinator.computeInitialTranscriptDigest()
	for index := uint64(0); index < eventCount; index++ {
		digest = advanceReshareConsistencyDigest(digest, coordinator.events[index])
	}
	return digest, nil
}

// EventCount returns the number of accepted durable transcript events.
func (coordinator *ReshareConsistencyCoordinator) EventCount() uint64 {
	if coordinator == nil {
		return 0
	}
	return uint64(len(coordinator.events))
}

// ValidateExtension requires the current state to preserve the exact prior event prefix.
func (coordinator *ReshareConsistencyCoordinator) ValidateExtension(previous *ReshareConsistencyCoordinator) error {
	if coordinator == nil || previous == nil ||
		coordinator.computeInitialTranscriptDigest() != previous.computeInitialTranscriptDigest() ||
		len(coordinator.events) < len(previous.events) {
		return ErrReshareStateRollback
	}
	for index := range previous.events {
		if coordinator.events[index] != previous.events[index] {
			return ErrReshareStateRollback
		}
	}
	if len(coordinator.events) == len(previous.events) &&
		coordinator.transcriptDigest != previous.transcriptDigest {
		return ErrReshareStateRollback
	}
	return nil
}

// AbortEvidence returns the terminal evidence when the transcript aborted.
func (coordinator *ReshareConsistencyCoordinator) AbortEvidence() (ReshareAbortEvidence, bool) {
	if coordinator == nil || !coordinator.hasAbortEvidence {
		return ReshareAbortEvidence{}, false
	}
	return coordinator.abortEvidence, true
}

// RecordContributionAgreement requires all six recipients to acknowledge one view.
func (coordinator *ReshareConsistencyCoordinator) RecordContributionAgreement(
	participantID uint32,
	digest [32]byte,
) error {
	return coordinator.recordContributionAgreement(participantID, digest, true)
}

func (coordinator *ReshareConsistencyCoordinator) recordContributionAgreement(
	participantID uint32,
	digest [32]byte,
	record bool,
) error {
	if err := coordinator.requirePhase(ReshareConsistencyPhaseContributionAgreement); err != nil {
		return err
	}
	if !committeeContains(coordinator.newCommittee, participantID) || digest == ([32]byte{}) {
		return ErrInvalidReshareState
	}
	if existing, ok := coordinator.agreements[participantID]; ok {
		if subtle.ConstantTimeCompare(existing[:], digest[:]) == 1 {
			return nil
		}
		return coordinator.abortEquivocation(participantID, existing, digest, record)
	}
	if subtle.ConstantTimeCompare(coordinator.contributionSetDigest[:], digest[:]) != 1 {
		evidence := ReshareAbortEvidence{
			Reason:       ReshareAbortReasonTranscriptMismatch,
			OffenderID:   participantID,
			DetailDigest: digestPair(coordinator.contributionSetDigest, digest),
		}
		coordinator.abort(evidence, record)
		return ErrReshareTranscriptFailed
	}
	coordinator.agreements[participantID] = digest
	coordinator.acceptEvent(reshareConsistencyEvent{Kind: reshareConsistencyEventAgreement, SenderID: participantID, Value: digest}, record)
	if len(coordinator.agreements) == len(coordinator.newCommittee.Participants) {
		coordinator.phase = ReshareConsistencyPhaseNonceCommitment
	}
	return nil
}

// RecordNonceCommitment records one fixed nonce view before any reveal.
func (coordinator *ReshareConsistencyCoordinator) RecordNonceCommitment(
	participantID uint32,
	commitment [32]byte,
) error {
	return coordinator.recordNonceCommitment(participantID, commitment, true)
}

func (coordinator *ReshareConsistencyCoordinator) recordNonceCommitment(
	participantID uint32,
	commitment [32]byte,
	record bool,
) error {
	if err := coordinator.requirePhase(ReshareConsistencyPhaseNonceCommitment); err != nil {
		return err
	}
	if !committeeContains(coordinator.newCommittee, participantID) || commitment == ([32]byte{}) {
		return ErrInvalidReshareState
	}
	if existing, ok := coordinator.nonceCommitments[participantID]; ok {
		if subtle.ConstantTimeCompare(existing[:], commitment[:]) == 1 {
			return nil
		}
		return coordinator.abortEquivocation(participantID, existing, commitment, record)
	}
	coordinator.nonceCommitments[participantID] = commitment
	coordinator.acceptEvent(reshareConsistencyEvent{Kind: reshareConsistencyEventNonceCommitment, SenderID: participantID, Value: commitment}, record)
	if len(coordinator.nonceCommitments) == len(coordinator.newCommittee.Participants) {
		coordinator.phase = ReshareConsistencyPhaseNonceReveal
	}
	return nil
}

// RecordNonceReveal validates one reveal against the globally fixed commitments.
func (coordinator *ReshareConsistencyCoordinator) RecordNonceReveal(
	participantID uint32,
	nonce [32]byte,
) error {
	return coordinator.recordNonceReveal(participantID, nonce, true)
}

func (coordinator *ReshareConsistencyCoordinator) recordNonceReveal(
	participantID uint32,
	nonce [32]byte,
	record bool,
) error {
	if err := coordinator.requirePhase(ReshareConsistencyPhaseNonceReveal); err != nil {
		return err
	}
	if !committeeContains(coordinator.newCommittee, participantID) || nonce == ([32]byte{}) {
		return ErrInvalidReshareState
	}
	if existing, ok := coordinator.nonceReveals[participantID]; ok {
		if subtle.ConstantTimeCompare(existing[:], nonce[:]) == 1 {
			return nil
		}
		return coordinator.abortEquivocation(participantID, existing, nonce, record)
	}
	want := CommitReshareConsistencyNonce(coordinator.sessionID, coordinator.dealerID, participantID, nonce)
	commitment := coordinator.nonceCommitments[participantID]
	if subtle.ConstantTimeCompare(want[:], commitment[:]) != 1 {
		evidence := ReshareAbortEvidence{
			Reason:       ReshareAbortReasonInvalidReveal,
			OffenderID:   participantID,
			DetailDigest: digestPair(commitment, want),
		}
		coordinator.abort(evidence, record)
		return ErrInvalidReshareConsistencyNonce
	}
	coordinator.nonceReveals[participantID] = nonce
	coordinator.acceptEvent(reshareConsistencyEvent{Kind: reshareConsistencyEventNonceReveal, SenderID: participantID, Value: nonce}, record)
	if len(coordinator.nonceReveals) != len(coordinator.newCommittee.Participants) {
		return nil
	}
	combined, err := RevealReshareConsistencyNonce(
		coordinator.sessionID,
		coordinator.dealerID,
		coordinator.newCommittee.Participants,
		coordinator.nonceCommitments,
		coordinator.nonceReveals,
	)
	if err != nil {
		coordinator.abort(ReshareAbortEvidence{Reason: ReshareAbortReasonInvalidReveal}, record)
		return err
	}
	coordinator.challengeSeed = coordinator.deriveChallengeSeed(combined)
	coordinator.phase = ReshareConsistencyPhaseTermCommitment
	return nil
}

// RecordMaskedTermCommitment records one sender's current check commitment.
func (coordinator *ReshareConsistencyCoordinator) RecordMaskedTermCommitment(
	participantID uint32,
	commitment [32]byte,
) error {
	return coordinator.recordMaskedTermCommitment(participantID, commitment, true)
}

func (coordinator *ReshareConsistencyCoordinator) recordMaskedTermCommitment(
	participantID uint32,
	commitment [32]byte,
	record bool,
) error {
	if err := coordinator.requirePhase(ReshareConsistencyPhaseTermCommitment); err != nil {
		return err
	}
	expectedSenders := coordinator.currentTermSenders()
	if !containsParticipant(expectedSenders, participantID) || commitment == ([32]byte{}) {
		return ErrInvalidReshareState
	}
	if existing, ok := coordinator.termCommitments[participantID]; ok {
		if subtle.ConstantTimeCompare(existing[:], commitment[:]) == 1 {
			return nil
		}
		return coordinator.abortEquivocation(participantID, existing, commitment, record)
	}
	coordinator.termCommitments[participantID] = commitment
	coordinator.acceptEvent(reshareConsistencyEvent{Kind: reshareConsistencyEventTermCommitment, SenderID: participantID, Value: commitment}, record)
	if len(coordinator.termCommitments) == len(expectedSenders) {
		coordinator.phase = ReshareConsistencyPhaseTermReveal
	}
	return nil
}

// RecordMaskedTermReveal validates one current check reveal.
func (coordinator *ReshareConsistencyCoordinator) RecordMaskedTermReveal(reveal ReshareMaskedTermReveal) error {
	return coordinator.recordMaskedTermReveal(reveal, true)
}

func (coordinator *ReshareConsistencyCoordinator) recordMaskedTermReveal(
	reveal ReshareMaskedTermReveal,
	record bool,
) error {
	if err := coordinator.requirePhase(ReshareConsistencyPhaseTermReveal); err != nil {
		return err
	}
	expectedSenders := coordinator.currentTermSenders()
	if !containsParticipant(expectedSenders, reveal.SenderID) {
		return ErrInvalidReshareState
	}
	if existing, ok := coordinator.termReveals[reveal.SenderID]; ok {
		if existing.Term == reveal.Term && subtle.ConstantTimeCompare(existing.Salt[:], reveal.Salt[:]) == 1 {
			return nil
		}
		return coordinator.abortEquivocation(
			reveal.SenderID,
			digestTermReveal(existing),
			digestTermReveal(reveal),
			record,
		)
	}
	commitment := coordinator.termCommitments[reveal.SenderID]
	if err := VerifyReshareMaskedTerm(
		commitment,
		coordinator.sessionID,
		coordinator.dealerID,
		coordinator.round,
		coordinator.checkID,
		reveal.SenderID,
		reveal.Term,
		reveal.Salt,
	); err != nil {
		evidence := ReshareAbortEvidence{
			Reason:       ReshareAbortReasonInvalidReveal,
			OffenderID:   reveal.SenderID,
			Round:        coordinator.round,
			CheckID:      coordinator.checkID,
			DetailDigest: digestTermReveal(reveal),
		}
		coordinator.abort(evidence, record)
		return err
	}
	coordinator.termReveals[reveal.SenderID] = reveal
	coordinator.acceptEvent(reshareConsistencyEvent{
		Kind:     reshareConsistencyEventTermReveal,
		SenderID: reveal.SenderID,
		Term:     reveal.Term,
		Salt:     reveal.Salt,
	}, record)
	if len(coordinator.termReveals) != len(expectedSenders) {
		return nil
	}
	syndrome, err := VerifyAndAggregateReshareMaskedTerms(
		coordinator.sessionID,
		coordinator.dealerID,
		coordinator.round,
		coordinator.checkID,
		expectedSenders,
		coordinator.termCommitments,
		coordinator.termReveals,
	)
	if err != nil {
		coordinator.abort(ReshareAbortEvidence{Reason: ReshareAbortReasonInvalidReveal}, record)
		return err
	}
	if syndrome != 0 {
		evidence := ReshareAbortEvidence{
			Reason:       ReshareAbortReasonNonZeroSyndrome,
			Round:        coordinator.round,
			CheckID:      coordinator.checkID,
			DetailDigest: digestSyndrome(syndrome),
		}
		coordinator.abort(evidence, record)
		return ErrReshareNonZeroSyndrome
	}
	coordinator.termCommitments = make(map[uint32][32]byte, len(coordinator.newCommittee.Participants)+1)
	coordinator.termReveals = make(map[uint32]ReshareMaskedTermReveal, len(coordinator.newCommittee.Participants)+1)
	coordinator.checkID++
	if coordinator.checkID == ReshareConsistencyChecksPerRound {
		coordinator.checkID = 0
		coordinator.round++
	}
	if coordinator.round == ReshareConsistencyRounds {
		coordinator.phase = ReshareConsistencyPhaseVerified
		return nil
	}
	coordinator.phase = ReshareConsistencyPhaseTermCommitment
	return nil
}

func (coordinator *ReshareConsistencyCoordinator) currentTermSenders() []uint32 {
	senders := append([]uint32(nil), coordinator.newCommittee.Participants...)
	if coordinator.checkID == ReshareConsistencyChecksPerRound-1 {
		senders = append(senders, ReshareDealerWitnessID(coordinator.dealerID))
	}
	return senders
}

func validResharePhysicalParticipants(participants []uint32) bool {
	for _, participantID := range participants {
		if participantID == 0 || participantID&reshareDealerWitnessNamespace != 0 {
			return false
		}
	}
	return true
}

// AbortTimeout permanently closes a committed transcript after its deadline.
func (coordinator *ReshareConsistencyCoordinator) AbortTimeout(detailDigest [32]byte) error {
	if coordinator == nil || coordinator.phase == ReshareConsistencyPhaseVerified || coordinator.phase == ReshareConsistencyPhaseAborted {
		return ErrReshareStateTransition
	}
	coordinator.abort(ReshareAbortEvidence{
		Reason:       ReshareAbortReasonTimeout,
		Round:        coordinator.round,
		CheckID:      coordinator.checkID,
		DetailDigest: detailDigest,
	}, true)
	return nil
}

// MarshalBinary encodes the full ordered public transcript for encrypted storage.
func (coordinator *ReshareConsistencyCoordinator) MarshalBinary() ([]byte, error) {
	if coordinator == nil {
		return nil, ErrInvalidReshareState
	}
	commitments := make([]reshareRecipientCommitment, 0, len(coordinator.newCommittee.Participants))
	for _, recipientID := range coordinator.newCommittee.Participants {
		commitments = append(commitments, reshareRecipientCommitment{
			RecipientID: recipientID,
			Commitment:  coordinator.contributionCommitments[recipientID],
		})
	}
	encoded, err := json.Marshal(reshareConsistencyEncoding{
		Version:                 reshareConsistencyStateVersion,
		SessionID:               coordinator.sessionID,
		Key:                     coordinator.key.Clone(),
		OldCommittee:            coordinator.oldCommittee.Clone(),
		NewCommittee:            coordinator.newCommittee.Clone(),
		SelectedDealers:         append([]uint32(nil), coordinator.selectedDealers...),
		DealerID:                coordinator.dealerID,
		ContributionCommitments: commitments,
		Events:                  append([]reshareConsistencyEvent(nil), coordinator.events...),
		Phase:                   coordinator.phase,
		Round:                   coordinator.round,
		CheckID:                 coordinator.checkID,
		TranscriptDigest:        coordinator.transcriptDigest,
	})
	if err != nil {
		return nil, err
	}
	if len(encoded)+len(reshareConsistencyStateMagic) > maxReshareConsistencyStateSize {
		return nil, ErrInvalidReshareState
	}
	return append([]byte(reshareConsistencyStateMagic), encoded...), nil
}

// UnmarshalReshareConsistencyCoordinator validates and replays a durable transcript.
func UnmarshalReshareConsistencyCoordinator(encoded []byte) (*ReshareConsistencyCoordinator, error) {
	if len(encoded) > maxReshareConsistencyStateSize || !bytes.HasPrefix(encoded, []byte(reshareConsistencyStateMagic)) {
		return nil, ErrInvalidReshareState
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded[len(reshareConsistencyStateMagic):]))
	decoder.DisallowUnknownFields()
	var state reshareConsistencyEncoding
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	if state.Version != reshareConsistencyStateVersion || len(state.ContributionCommitments) != len(state.NewCommittee.Participants) {
		return nil, ErrInvalidReshareState
	}
	commitments := make(map[uint32][32]byte, len(state.ContributionCommitments))
	for _, entry := range state.ContributionCommitments {
		if _, duplicate := commitments[entry.RecipientID]; duplicate {
			return nil, ErrInvalidReshareState
		}
		commitments[entry.RecipientID] = entry.Commitment
	}
	coordinator, err := NewReshareConsistencyCoordinator(
		state.SessionID,
		state.Key,
		state.OldCommittee,
		state.NewCommittee,
		state.SelectedDealers,
		state.DealerID,
		commitments,
	)
	if err != nil {
		return nil, err
	}
	for _, event := range state.Events {
		if err := coordinator.replayEvent(event); err != nil {
			return nil, err
		}
		coordinator.acceptEvent(event, true)
	}
	if coordinator.phase != state.Phase || coordinator.round != state.Round || coordinator.checkID != state.CheckID ||
		subtle.ConstantTimeCompare(coordinator.transcriptDigest[:], state.TranscriptDigest[:]) != 1 {
		return nil, ErrInvalidReshareState
	}
	return coordinator, nil
}

func (coordinator *ReshareConsistencyCoordinator) replayEvent(event reshareConsistencyEvent) error {
	switch event.Kind {
	case reshareConsistencyEventAgreement:
		return coordinator.recordContributionAgreement(event.SenderID, event.Value, false)
	case reshareConsistencyEventNonceCommitment:
		return coordinator.recordNonceCommitment(event.SenderID, event.Value, false)
	case reshareConsistencyEventNonceReveal:
		return coordinator.recordNonceReveal(event.SenderID, event.Value, false)
	case reshareConsistencyEventTermCommitment:
		return coordinator.recordMaskedTermCommitment(event.SenderID, event.Value, false)
	case reshareConsistencyEventTermReveal:
		err := coordinator.recordMaskedTermReveal(ReshareMaskedTermReveal{
			SenderID: event.SenderID,
			Term:     event.Term,
			Salt:     event.Salt,
		}, false)
		if errors.Is(err, ErrReshareNonZeroSyndrome) {
			return nil
		}
		return err
	case reshareConsistencyEventAbort:
		if coordinator.phase == ReshareConsistencyPhaseAborted {
			if coordinator.abortEvidence != event.Abort {
				return ErrInvalidReshareState
			}
			return nil
		}
		coordinator.abort(event.Abort, false)
		return nil
	default:
		return ErrInvalidReshareState
	}
}

func (coordinator *ReshareConsistencyCoordinator) requirePhase(phase ReshareConsistencyPhase) error {
	if coordinator == nil || coordinator.phase != phase {
		return ErrReshareStateTransition
	}
	return nil
}

func (coordinator *ReshareConsistencyCoordinator) abortEquivocation(
	offenderID uint32,
	previous [32]byte,
	conflicting [32]byte,
	record bool,
) error {
	coordinator.abort(ReshareAbortEvidence{
		Reason:       ReshareAbortReasonEquivocation,
		OffenderID:   offenderID,
		Round:        coordinator.round,
		CheckID:      coordinator.checkID,
		DetailDigest: digestPair(previous, conflicting),
	}, record)
	return ErrReshareEquivocation
}

func (coordinator *ReshareConsistencyCoordinator) abort(evidence ReshareAbortEvidence, record bool) {
	coordinator.phase = ReshareConsistencyPhaseAborted
	coordinator.abortEvidence = evidence
	coordinator.hasAbortEvidence = true
	coordinator.acceptEvent(reshareConsistencyEvent{Kind: reshareConsistencyEventAbort, Abort: evidence}, record)
}

func (coordinator *ReshareConsistencyCoordinator) acceptEvent(event reshareConsistencyEvent, record bool) {
	if !record {
		return
	}
	coordinator.events = append(coordinator.events, event)
	coordinator.transcriptDigest = advanceReshareConsistencyDigest(coordinator.transcriptDigest, event)
}

func advanceReshareConsistencyDigest(previous [32]byte, event reshareConsistencyEvent) [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-EVENT"))
	_, _ = digest.Write(previous[:])
	writeReshareConsistencyEvent(digest, event)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func (coordinator *ReshareConsistencyCoordinator) computeContributionSetDigest() [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-CONTRIBUTION-SET"))
	coordinator.writeTranscriptIdentity(digest)
	for _, recipientID := range coordinator.newCommittee.Participants {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], recipientID)
		_, _ = digest.Write(encoded[:])
		commitment := coordinator.contributionCommitments[recipientID]
		_, _ = digest.Write(commitment[:])
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func (coordinator *ReshareConsistencyCoordinator) computeInitialTranscriptDigest() [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-TRANSCRIPT"))
	coordinator.writeTranscriptIdentity(digest)
	_, _ = digest.Write(coordinator.contributionSetDigest[:])
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func (coordinator *ReshareConsistencyCoordinator) deriveChallengeSeed(nonce [32]byte) [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-CONSISTENCY"))
	_, _ = digest.Write(coordinator.sessionID[:])
	_, _ = digest.Write(nonce[:])
	keyDigest, _ := coordinator.key.CanonicalDigest()
	oldDigest, _ := coordinator.oldCommittee.CanonicalDigest()
	newDigest, _ := coordinator.newCommittee.CanonicalDigest()
	_, _ = digest.Write(keyDigest[:])
	_, _ = digest.Write(oldDigest[:])
	_, _ = digest.Write(newDigest[:])
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], coordinator.dealerID)
	_, _ = digest.Write(encoded[:])
	for _, recipientID := range coordinator.newCommittee.Participants {
		binary.BigEndian.PutUint32(encoded[:], recipientID)
		_, _ = digest.Write(encoded[:])
		commitment := coordinator.contributionCommitments[recipientID]
		_, _ = digest.Write(commitment[:])
	}
	var seed [32]byte
	copy(seed[:], digest.Sum(nil))
	return seed
}

func (coordinator *ReshareConsistencyCoordinator) writeTranscriptIdentity(writer io.Writer) {
	_, _ = writer.Write(coordinator.sessionID[:])
	keyDigest, _ := coordinator.key.CanonicalDigest()
	oldDigest, _ := coordinator.oldCommittee.CanonicalDigest()
	newDigest, _ := coordinator.newCommittee.CanonicalDigest()
	_, _ = writer.Write(keyDigest[:])
	_, _ = writer.Write(oldDigest[:])
	_, _ = writer.Write(newDigest[:])
	var encoded [4]byte
	for _, dealerID := range coordinator.selectedDealers {
		binary.BigEndian.PutUint32(encoded[:], dealerID)
		_, _ = writer.Write(encoded[:])
	}
	binary.BigEndian.PutUint32(encoded[:], coordinator.dealerID)
	_, _ = writer.Write(encoded[:])
}

func writeReshareConsistencyEvent(writer io.Writer, event reshareConsistencyEvent) {
	_, _ = writer.Write([]byte{byte(event.Kind)})
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], event.SenderID)
	_, _ = writer.Write(encoded[:])
	_, _ = writer.Write(event.Value[:])
	binary.BigEndian.PutUint32(encoded[:], uint32(event.Term))
	_, _ = writer.Write(encoded[:])
	_, _ = writer.Write(event.Salt[:])
	_, _ = writer.Write([]byte{byte(event.Abort.Reason)})
	binary.BigEndian.PutUint32(encoded[:], event.Abort.OffenderID)
	_, _ = writer.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], event.Abort.Round)
	_, _ = writer.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], event.Abort.CheckID)
	_, _ = writer.Write(encoded[:])
	_, _ = writer.Write(event.Abort.DetailDigest[:])
}

func digestPair(left, right [32]byte) [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-CONFLICT"))
	_, _ = digest.Write(left[:])
	_, _ = digest.Write(right[:])
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func digestTermReveal(reveal ReshareMaskedTermReveal) [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-TERM-REVEAL"))
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], reveal.SenderID)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], uint32(reveal.Term))
	_, _ = digest.Write(encoded[:])
	_, _ = digest.Write(reveal.Salt[:])
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func digestSyndrome(syndrome int32) [32]byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(syndrome))
	return sha3.Sum256(append([]byte("QAU-TMLDSA65-V1-RESHARE-SYNDROME"), encoded[:]...))
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrInvalidReshareState
		}
		return err
	}
	return nil
}
