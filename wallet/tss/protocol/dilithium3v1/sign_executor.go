// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// This file is the in-process executor driver of the reviewed four-of-six
// Dilithium3 v1 signing construction (signing-executor design note, Slice 1).
// Four signer instances exchange the four public round messages of the
// construction through the wallet-side message layer and the session gate:
//
//	round 1  commit      the digest of the signer's MLWE share w_i
//	round 2  reveal      w_i itself, opened against the round-1 digest
//	round 3a acceptance  the signer's per-party rejection bit
//	round 3b response    z_i^(1), only for a slot every signer accepted
//
// Every signer recomputes w = sum_i w_i, w1, and the challenge locally, tests
// its own per-party rejection predicate locally, and releases its response
// part only when its own bit and every observed bit are true. The combine runs
// on published values only, and every signer produces the same packed
// signature. A rejected slot publishes no response part from any signer.
//
// The sender identity of an envelope is the transport's claim; a networked
// deployment authenticates it at the p2p layer (design note, Slice 4), and the
// gate re-checks it against the session policy. The driver itself trusts
// nothing about the routing: messages may arrive reordered, duplicated,
// dropped, replayed, or forged, and every deviation is either refused before
// delivery or aborts the slot with a bounded reason code.
//
// Every signer holds its own durable journal and its own one-time record, binds
// the slot's committed randomness into them before its first message leaves,
// and consumes them on every path that does not end in a signature: a local
// rejection, a failed combine check, a slot-level abort, or a silence (design
// note, Slice 3). A restart can therefore never resume or reuse a slot.
//
// Like sign.go and sign_randomness.go this driver is a correctness, leakage,
// and differential-testing reference and never a production path: nothing here
// is exported, and it holds all four shares in one process, which is also how
// it reconstructs the per-signer partial secrets the local rejection test
// consumes. A deployment samples each signer's randomness inside its own
// process (design note, Open Obligations item 1), which is also why the four
// ball points are caller-supplied here.

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

var (
	// errSigningExecutorMismatch reports an inconsistent transcript: a reveal
	// that does not open the round-1 commitment of its sender.
	errSigningExecutorMismatch = errors.New("inconsistent Dilithium3 v1 signing executor transcript")

	// errSigningExecutorCombine reports a slot that every signer accepted but
	// whose published values failed a public combine check.
	errSigningExecutorCombine = errors.New("failed Dilithium3 v1 signing executor combine check")

	// errSigningExecutorSilence reports a participant whose message of this
	// slot never arrived.
	errSigningExecutorSilence = errors.New("silent participant in the Dilithium3 v1 signing executor")
)

// signingExecutorAbort is the bounded abort of one slot: a reason code, the
// attributable evidence, and a short detail. It never carries a secret-derived
// value, and its reason maps onto the sentinel of its class.
type signingExecutorAbort struct {
	reason   SigningExecutorReason
	evidence Evidence
	detail   string
}

func (abort *signingExecutorAbort) Error() string {
	if abort == nil {
		return "<nil>"
	}
	if abort.evidence.ParticipantID != 0 {
		return fmt.Sprintf(
			"Dilithium3 v1 signing executor aborted: %s: signer %d: %s",
			abort.reason, abort.evidence.ParticipantID, abort.detail,
		)
	}
	return fmt.Sprintf("Dilithium3 v1 signing executor aborted: %s: %s", abort.reason, abort.detail)
}

// Unwrap maps the bounded reason onto the sentinel of its class.
func (abort *signingExecutorAbort) Unwrap() error {
	if abort == nil {
		return nil
	}
	switch abort.reason {
	case SigningExecutorReasonUnauthorized:
		return ErrSigningExecutorUnauthorized
	case SigningExecutorReasonConflict:
		return ErrSigningExecutorConflict
	case SigningExecutorReasonCommitmentMismatch:
		return errSigningExecutorMismatch
	case SigningExecutorReasonLocalRejection:
		return errSigningRejected
	case SigningExecutorReasonCombineCheck:
		return errSigningExecutorCombine
	case SigningExecutorReasonSilence:
		return errSigningExecutorSilence
	default:
		return nil
	}
}

// fatal reports whether the abort ends the slot. An unauthorized message is a
// delivery the coordinator should never have made; it is refused without
// ending an otherwise healthy slot, so network noise cannot kill a signing.
// Every other abort is sticky.
func (abort *signingExecutorAbort) fatal() bool {
	return abort != nil && abort.reason != SigningExecutorReasonUnauthorized
}

// signingExecutorReasonOf returns the bounded reason carried by an error.
func signingExecutorReasonOf(err error) (SigningExecutorReason, bool) {
	var abort *signingExecutorAbort
	if !errors.As(err, &abort) {
		return SigningExecutorReasonUnknown, false
	}
	return abort.reason, true
}

// signingExecutorKindName names one executor message kind for abort details.
func signingExecutorKindName(kind uint16) string {
	switch kind {
	case SigningExecutorKindCommit:
		return "commit"
	case SigningExecutorKindReveal:
		return "reveal"
	case SigningExecutorKindAcceptance:
		return "acceptance"
	case SigningExecutorKindResponse:
		return "response"
	default:
		return fmt.Sprintf("kind %d", kind)
	}
}

// signingExecutorEnvelope is one routed executor message: the sender identity,
// the message kind, and the canonical payload. The slot is decoded from the
// payload, so a forged envelope cannot disagree with its own encoding.
type signingExecutorEnvelope struct {
	Sender  uint32
	Kind    uint16
	Payload []byte
}

// signingExecutorSlotMaterial is one active signer's local material for one
// slot: its ball randomness, its durable signing journal, and its one-time
// preprocessing record. The journal lives across the whole request; the record
// is consumed by exactly one slot and binds that slot's committed randomness.
type signingExecutorSlotMaterial struct {
	randomness *signingRandomness
	journal    *SigningJournal
	record     *PreprocessingRecord
}

// signingExecutorPreparedDomain and signingExecutorResponsePartDomain separate
// this signer's durable payloads from the reference driver's and from each
// other.
const (
	signingExecutorPreparedDomain     = "QAU-TDILITHIUM3-V1-SIGNING-EXECUTOR-PREPARED"
	signingExecutorResponsePartDomain = "QAU-TDILITHIUM3-V1-SIGNING-EXECUTOR-RESPONSE-PART"
)

// signingExecutorPreparedDigest binds this signer's slot binding, its rounded
// randomness expansion, and the public commitment of its one-time record into
// the durable prepared payload. It is persisted before any message leaves the
// signer, so a restart can prove that this slot's randomness is consumed.
func signingExecutorPreparedDigest(
	sessionID [32]byte,
	participantID uint32,
	slot uint16,
	recordCommitment [32]byte,
	randomness *signingRandomness,
) ([32]byte, error) {
	buffer := make([]byte, 0, len(signingExecutorPreparedDomain)+32+4+2+32+(L+K)*PolyEncodedSize)
	buffer = append(buffer, signingExecutorPreparedDomain...)
	buffer = append(buffer, sessionID[:]...)
	buffer = binary.BigEndian.AppendUint32(buffer, participantID)
	buffer = binary.BigEndian.AppendUint16(buffer, slot)
	buffer = append(buffer, recordCommitment[:]...)
	for row := range randomness.first {
		encoded, err := EncodePoly(randomness.first[row])
		if err != nil {
			return [32]byte{}, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
		}
		buffer = append(buffer, encoded[:]...)
	}
	for row := range randomness.second {
		encoded, err := EncodePoly(randomness.second[row])
		if err != nil {
			return [32]byte{}, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
		}
		buffer = append(buffer, encoded[:]...)
	}
	return sha3.Sum256(buffer), nil
}

// signingExecutorResponsePartDigest binds the response part that leaves one
// signer, so the durable responded state records exactly what was released.
func signingExecutorResponsePartDigest(
	sessionID [32]byte,
	participantID uint32,
	slot uint16,
	part [L]SignedPoly,
) ([32]byte, error) {
	buffer := make([]byte, 0, len(signingExecutorResponsePartDomain)+32+4+2+L*ZEncodedSize)
	buffer = append(buffer, signingExecutorResponsePartDomain...)
	buffer = append(buffer, sessionID[:]...)
	buffer = binary.BigEndian.AppendUint32(buffer, participantID)
	buffer = binary.BigEndian.AppendUint16(buffer, slot)
	for row := range part {
		encoded, err := EncodeZ(part[row])
		if err != nil {
			return [32]byte{}, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
		}
		buffer = append(buffer, encoded[:]...)
	}
	return sha3.Sum256(buffer), nil
}

// signingExecutorSigner is one in-process signer instance. It holds its own
// ball randomness and its own partial secret, its own inbox gate, and the
// public values it received; nothing else. Every per-signer slice is sized by
// the pinned committee row's threshold (4 or 5 for R76b).
type signingExecutorSigner struct {
	lock sync.Mutex

	gate          *SigningExecutorGate
	position      int
	slot          uint16
	sessionID     [32]byte
	participantID uint32
	identities    []uint32
	fullMask      uint8
	params        SigningParameters

	randomness    *signingRandomness
	partialFirst  VectorL
	partialSecond VectorK

	journal *SigningJournal
	record  *PreprocessingRecord

	rho            [32]byte
	representative [64]byte
	key            protocol.ThresholdKeyID
	message        []byte

	contribution VectorK

	commits         [][32]byte
	commitsSeen     uint8
	reveals         []VectorK
	revealsSeen     uint8
	digestsChecked  uint8
	acceptances     []bool
	acceptancesSeen uint8
	parts           [][L]SignedPoly
	partsSeen       uint8

	accepted   bool
	w          VectorK
	highBits   VectorK
	seed       [CTildeSize]byte
	challenge  Poly
	shiftFirst [L]SignedPoly

	started        bool
	revealSent     bool
	acceptanceSent bool
	responseSent   bool

	rejected  bool
	burned    bool
	signature []byte

	outbound []signingExecutorEnvelope
}

// start persists this signer's one-time binding and queues the round-1 commit:
// the slot's committed randomness is bound into the durable prepared state, and
// the one-time record is committed to exactly this session, before any message
// leaves the signer.
func (signer *signingExecutorSigner) start() error {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	if signer.started {
		return fmt.Errorf("%w: signer %d started twice", errInvalidSigningAttempt, signer.participantID)
	}
	signer.started = true
	if signer.record.State() != PreprocessingAvailable {
		return signer.failLocked(fmt.Errorf(
			"%w: signer %d record is %v, want available",
			errInvalidSigningAttempt, signer.participantID, signer.record.State(),
		))
	}
	prepared, err := signingExecutorPreparedDigest(
		signer.sessionID, signer.participantID, signer.slot,
		signer.record.CoordinatorView().Commitment, signer.randomness,
	)
	if err != nil {
		return signer.failLocked(fmt.Errorf(
			"%w: signer %d prepared: %v", errInvalidSigningAttempt, signer.participantID, err,
		))
	}
	if _, err := signer.journal.Advance(signer.sessionID, protocol.SingleUsePrepared, prepared[:]); err != nil {
		return signer.failLocked(fmt.Errorf(
			"%w: signer %d prepared: %v", errInvalidSigningState, signer.participantID, err,
		))
	}
	if err := signer.record.Commit(signer.sessionID); err != nil {
		return signer.failLocked(fmt.Errorf(
			"%w: signer %d record commit: %v", errInvalidSigningAttempt, signer.participantID, err,
		))
	}
	contribution, err := ComputePublicVector(signer.rho, signer.randomness.first, signer.randomness.second)
	if err != nil {
		return signer.failLocked(fmt.Errorf("%w: signer %d share: %v", errInvalidSigningAttempt, signer.participantID, err))
	}
	digest, err := signingCommitmentDigest(signer.sessionID, signer.participantID, signer.slot, contribution)
	if err != nil {
		return signer.failLocked(fmt.Errorf("%w: signer %d commitment: %v", errInvalidSigningAttempt, signer.participantID, err))
	}
	payload, err := EncodeSigningExecutorCommit(signer.slot, digest)
	if err != nil {
		return signer.failLocked(fmt.Errorf("%w: signer %d commit: %v", errInvalidSigningAttempt, signer.participantID, err))
	}
	if _, err := signer.journal.Advance(signer.sessionID, protocol.SingleUseCommitted, digest[:]); err != nil {
		return signer.failLocked(fmt.Errorf(
			"%w: signer %d committed: %v", errInvalidSigningState, signer.participantID, err,
		))
	}
	signer.contribution = contribution
	signer.commits[signer.position] = digest
	signer.commitsSeen |= 1 << signer.position
	signer.outbound = append(signer.outbound, signingExecutorEnvelope{
		Sender: signer.participantID, Kind: SigningExecutorKindCommit, Payload: payload,
	})
	return nil
}

// drain returns and clears every queued outbound message of this signer.
func (signer *signingExecutorSigner) drain() []signingExecutorEnvelope {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	queued := signer.outbound
	signer.outbound = nil
	return queued
}

// deliver checks and applies one message routed by the coordinator. A nil
// error means the message was applied or was an idempotent retransmission;
// every other result is a refused or aborting message.
func (signer *signingExecutorSigner) deliver(envelope signingExecutorEnvelope) error {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	if !signer.started {
		return fmt.Errorf("%w: signer %d received before start", errInvalidSigningAttempt, signer.participantID)
	}
	if signer.rejected || signer.burned || signer.signature != nil {
		// The slot is over for this signer; nothing can revive it, and nothing
		// it observes from here on can publish anything.
		return nil
	}
	var (
		slot       uint16
		commit     [32]byte
		reveal     VectorK
		acceptance bool
		part       [L]SignedPoly
	)
	switch envelope.Kind {
	case SigningExecutorKindCommit:
		decodedSlot, digest, err := DecodeSigningExecutorCommit(envelope.Payload)
		if err != nil {
			return signer.refuseLocked(envelope.Sender, fmt.Sprintf("malformed commit: %v", err))
		}
		slot, commit = decodedSlot, digest
	case SigningExecutorKindReveal:
		decodedSlot, contribution, err := DecodeSigningExecutorReveal(envelope.Payload)
		if err != nil {
			return signer.refuseLocked(envelope.Sender, fmt.Sprintf("malformed reveal: %v", err))
		}
		slot, reveal = decodedSlot, contribution
	case SigningExecutorKindAcceptance:
		decodedSlot, bit, err := DecodeSigningExecutorAcceptance(envelope.Payload)
		if err != nil {
			return signer.refuseLocked(envelope.Sender, fmt.Sprintf("malformed acceptance: %v", err))
		}
		slot, acceptance = decodedSlot, bit
	case SigningExecutorKindResponse:
		decodedSlot, decodedPart, err := DecodeSigningExecutorResponse(envelope.Payload)
		if err != nil {
			return signer.refuseLocked(envelope.Sender, fmt.Sprintf("malformed response: %v", err))
		}
		slot, part = decodedSlot, decodedPart
	default:
		return signer.refuseLocked(envelope.Sender, fmt.Sprintf("unknown kind %d", envelope.Kind))
	}
	if slot != signer.slot {
		return signer.refuseLocked(envelope.Sender, fmt.Sprintf("message for slot %d in slot %d", slot, signer.slot))
	}
	admission, evidence, err := signer.gate.Observe(envelope.Sender, slot, envelope.Kind, envelope.Payload)
	if err != nil {
		if errors.Is(err, ErrSigningExecutorUnauthorized) {
			return signer.refuseLocked(envelope.Sender, err.Error())
		}
		if errors.Is(err, ErrSigningExecutorConflict) {
			return &signingExecutorAbort{
				reason:   SigningExecutorReasonConflict,
				evidence: evidence,
				detail:   fmt.Sprintf("conflicting %s payload", signingExecutorKindName(envelope.Kind)),
			}
		}
		return fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	if admission == SigningExecutorAdmissionDuplicate {
		return nil
	}
	index := signer.indexOf(envelope.Sender)
	if index < 0 {
		// The gate already refuses every sender outside the policy.
		return fmt.Errorf("%w: sender %d outside the session policy", errInvalidSigningAttempt, envelope.Sender)
	}
	bit := uint8(1) << index
	switch envelope.Kind {
	case SigningExecutorKindCommit:
		signer.commits[index] = commit
		signer.commitsSeen |= bit
	case SigningExecutorKindReveal:
		signer.reveals[index] = reveal
		signer.revealsSeen |= bit
	case SigningExecutorKindAcceptance:
		signer.acceptances[index] = acceptance
		signer.acceptancesSeen |= bit
	case SigningExecutorKindResponse:
		signer.parts[index] = part
		signer.partsSeen |= bit
	}
	return signer.advanceLocked()
}

// refuseLocked rejects a message the session policy does not admit. The slot
// continues; the refusal itself is the attributable evidence.
func (signer *signingExecutorSigner) refuseLocked(sender uint32, detail string) error {
	return &signingExecutorAbort{
		reason:   SigningExecutorReasonUnauthorized,
		evidence: Evidence{ParticipantID: sender},
		detail:   detail,
	}
}

// indexOf maps one active participant identity to its position in the session.
func (signer *signingExecutorSigner) indexOf(sender uint32) int {
	for index, identity := range signer.identities {
		if identity == sender {
			return index
		}
	}
	return -1
}

// advanceLocked runs every round transition whose inputs are complete. It is
// idempotent: each transition is guarded by its own emission flag, so a
// duplicate delivery or a reordered one changes nothing.
func (signer *signingExecutorSigner) advanceLocked() error {
	for {
		changed := false
		if err := signer.checkDigestsLocked(); err != nil {
			return err
		}
		if signer.commitsSeen == signer.fullMask && !signer.revealSent {
			payload, err := EncodeSigningExecutorReveal(signer.slot, signer.contribution)
			if err != nil {
				return fmt.Errorf("%w: signer %d reveal: %v", errInvalidSigningAttempt, signer.participantID, err)
			}
			signer.revealSent = true
			signer.reveals[signer.position] = signer.contribution
			signer.revealsSeen |= 1 << signer.position
			signer.outbound = append(signer.outbound, signingExecutorEnvelope{
				Sender: signer.participantID, Kind: SigningExecutorKindReveal, Payload: payload,
			})
			changed = true
		}
		if signer.digestsChecked == signer.fullMask && !signer.acceptanceSent {
			if err := signer.computeChallengeLocked(); err != nil {
				return err
			}
			payload, err := EncodeSigningExecutorAcceptance(signer.slot, signer.accepted)
			if err != nil {
				return fmt.Errorf("%w: signer %d acceptance: %v", errInvalidSigningAttempt, signer.participantID, err)
			}
			signer.acceptanceSent = true
			signer.acceptances[signer.position] = signer.accepted
			signer.acceptancesSeen |= 1 << signer.position
			signer.outbound = append(signer.outbound, signingExecutorEnvelope{
				Sender: signer.participantID, Kind: SigningExecutorKindAcceptance, Payload: payload,
			})
			changed = true
		}
		if signer.acceptanceSent && signer.acceptancesSeen == signer.fullMask && !signer.rejected && !signer.responseSent {
			if !signer.allAcceptedLocked() {
				// Some signer rejected the slot, so this signer must not release
				// its response part, whatever the coordinator still delivers: it
				// consumes its one-time material instead.
				signer.rejected = true
				if err := signer.burnLocked(); err != nil {
					return err
				}
			} else {
				part := signingResponsePart(signer.randomness, signer.shiftFirst)
				payload, err := EncodeSigningExecutorResponse(signer.slot, part)
				if err != nil {
					return signer.failLocked(fmt.Errorf(
						"%w: signer %d response: %v", errInvalidSigningAttempt, signer.participantID, err,
					))
				}
				digest, err := signingExecutorResponsePartDigest(signer.sessionID, signer.participantID, signer.slot, part)
				if err != nil {
					return signer.failLocked(fmt.Errorf(
						"%w: signer %d response: %v", errInvalidSigningAttempt, signer.participantID, err,
					))
				}
				if err := signer.record.MarkResponseReleased(); err != nil {
					return signer.failLocked(fmt.Errorf(
						"%w: signer %d response release: %v", errInvalidSigningAttempt, signer.participantID, err,
					))
				}
				if _, err := signer.journal.Advance(signer.sessionID, protocol.SingleUseResponded, digest[:]); err != nil {
					return signer.failLocked(fmt.Errorf(
						"%w: signer %d responded: %v", errInvalidSigningState, signer.participantID, err,
					))
				}
				signer.responseSent = true
				signer.parts[signer.position] = part
				signer.partsSeen |= 1 << signer.position
				signer.outbound = append(signer.outbound, signingExecutorEnvelope{
					Sender: signer.participantID, Kind: SigningExecutorKindResponse, Payload: payload,
				})
				changed = true
			}
		}
		if !signer.rejected && signer.partsSeen == signer.fullMask && signer.signature == nil && signer.allAcceptedLocked() {
			var z [L]SignedPoly
			for index := range signer.parts {
				for row := 0; row < L; row++ {
					for coefficient := 0; coefficient < N; coefficient++ {
						z[row][coefficient] += signer.parts[index][row][coefficient]
					}
				}
			}
			signature, predicate, err := signingExecutorCombine(
				signer.key, signer.message, signer.w, signer.highBits, signer.seed, z,
			)
			if err != nil {
				return signer.failLocked(fmt.Errorf("%w: signer %d combine: %v", errInvalidSigningAttempt, signer.participantID, err))
			}
			if predicate != "" {
				abort := &signingExecutorAbort{
					reason: SigningExecutorReasonCombineCheck,
					detail: predicate,
				}
				if err := signer.burnLocked(); err != nil {
					return err
				}
				return abort
			}
			if _, err := signer.journal.Advance(signer.sessionID, protocol.SingleUseFinalized, signature); err != nil {
				return signer.failLocked(fmt.Errorf(
					"%w: signer %d finalized: %v", errInvalidSigningState, signer.participantID, err,
				))
			}
			signer.signature = signature
		}
		if !changed {
			return nil
		}
	}
}

// burnLocked consumes this signer's one-time material: the record burns and
// the journal entry reaches its terminal burned state, so the slot's randomness
// can never be reused. It is idempotent, does nothing once the signer
// finalized, and reports only a failure to reach the durable burned state.
func (signer *signingExecutorSigner) burnLocked() error {
	if signer.burned || signer.signature != nil {
		return nil
	}
	signer.burned = true
	_ = signer.record.RejectOpening(errSigningRejected)
	if _, err := signer.journal.Advance(signer.sessionID, protocol.SingleUseBurned, nil); err != nil {
		return fmt.Errorf(
			"%w: signer %d burning the signing journal: %v", errInvalidSigningState, signer.participantID, err,
		)
	}
	return nil
}

// failLocked burns the signer's one-time material and returns the cause, or the
// burn failure when the journal cannot reach the burned state.
func (signer *signingExecutorSigner) failLocked(cause error) error {
	if err := signer.burnLocked(); err != nil {
		return err
	}
	return cause
}

// burn consumes the signer's one-time material on a slot-level abort.
func (signer *signingExecutorSigner) burn() error {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	return signer.burnLocked()
}

// checkDigestsLocked opens every (commit, reveal) pair that is now complete and
// aborts on the first reveal that does not match its commitment.
func (signer *signingExecutorSigner) checkDigestsLocked() error {
	for index := range signer.identities {
		bit := uint8(1) << index
		if signer.commitsSeen&bit == 0 || signer.revealsSeen&bit == 0 || signer.digestsChecked&bit != 0 {
			continue
		}
		digest, err := signingCommitmentDigest(
			signer.sessionID, signer.identities[index], signer.slot, signer.reveals[index],
		)
		if err != nil {
			return fmt.Errorf("%w: signer %d transcript: %v", errInvalidSigningAttempt, signer.participantID, err)
		}
		signer.digestsChecked |= bit
		if digest != signer.commits[index] {
			return &signingExecutorAbort{
				reason:   SigningExecutorReasonCommitmentMismatch,
				evidence: Evidence{ParticipantID: signer.identities[index], Digest: digest},
				detail:   "reveal does not open the round-1 commitment",
			}
		}
	}
	return nil
}

// computeChallengeLocked aggregates the four revealed shares, derives the mode3
// challenge, and evaluates this signer's own rejection predicate. Only this
// signer's own partial secret feeds the test.
func (signer *signingExecutorSigner) computeChallengeLocked() error {
	var w VectorK
	for index := range signer.reveals {
		for row := 0; row < K; row++ {
			w[row] = Add(w[row], signer.reveals[index][row])
		}
	}
	var highBits VectorK
	for row := 0; row < K; row++ {
		highBits[row] = HighBits(w[row])
	}
	public, err := EncodePublicHighBits(highBits)
	if err != nil {
		return fmt.Errorf("%w: signer %d high bits: %v", errInvalidSigningAttempt, signer.participantID, err)
	}
	seed, err := signingChallengeSeed(signer.representative, public)
	if err != nil {
		return fmt.Errorf("%w: signer %d challenge seed: %v", errInvalidSigningAttempt, signer.participantID, err)
	}
	challenge, err := DeriveMode3Challenge(seed)
	if err != nil {
		return fmt.Errorf("%w: signer %d challenge: %v", errInvalidSigningAttempt, signer.participantID, err)
	}
	shiftFirst, shiftSecond := signingExecutorChallengeShift(signer.partialFirst, signer.partialSecond, challenge)
	passes, err := signingRejectionTest(signer.randomness, shiftFirst, shiftSecond, signer.params.Radius)
	if err != nil {
		return fmt.Errorf("%w: signer %d rejection test: %v", errInvalidSigningAttempt, signer.participantID, err)
	}
	signer.w = w
	signer.highBits = highBits
	signer.seed = seed
	signer.challenge = challenge
	signer.shiftFirst = shiftFirst
	signer.accepted = passes
	return nil
}

// allAcceptedLocked reports whether every acceptance bit of the slot is in and
// true, which is the only condition under which a response may be released.
func (signer *signingExecutorSigner) allAcceptedLocked() bool {
	if signer.acceptancesSeen != signer.fullMask {
		return false
	}
	for _, accepted := range signer.acceptances {
		if !accepted {
			return false
		}
	}
	return true
}

// missingLocked reports the earliest input this signer still needs: the
// message kind and the participant that owes it.
func (signer *signingExecutorSigner) missingLocked() (uint16, uint32, bool) {
	if signer.rejected || signer.burned || signer.signature != nil {
		return 0, 0, false
	}
	if signer.commitsSeen != signer.fullMask {
		return SigningExecutorKindCommit, signer.identities[firstMissing(signer.commitsSeen, len(signer.identities))], true
	}
	if signer.revealsSeen != signer.fullMask {
		return SigningExecutorKindReveal, signer.identities[firstMissing(signer.revealsSeen, len(signer.identities))], true
	}
	if signer.acceptancesSeen != signer.fullMask {
		return SigningExecutorKindAcceptance, signer.identities[firstMissing(signer.acceptancesSeen, len(signer.identities))], true
	}
	if signer.partsSeen != 0xF {
		return SigningExecutorKindResponse, signer.identities[firstMissing(signer.partsSeen, len(signer.identities))], true
	}
	return 0, 0, false
}

// firstMissing returns the lowest position absent from a non-full bit mask.
func firstMissing(mask uint8, count int) int {
	for index := 0; index < count; index++ {
		if mask&(1<<index) == 0 {
			return index
		}
	}
	return -1
}

// signingExecutorSession drives one slot of one signing request across the t
// in-process signer instances of the pinned committee row.
type signingExecutorSession struct {
	policy  SigningExecutorPolicy
	slot    uint16
	signers []*signingExecutorSigner

	started bool
	aborted *signingExecutorAbort
}

// newSigningExecutorSession validates the slot binding and returns a session
// whose signers hold only their own material. The material is caller-supplied
// because the in-process reference drives all t signers; a deployment samples
// each ball point and binds each one-time record inside its own signer
// process. The committee size comes from the active shares and must have a
// pinned signing row (R76b).
func newSigningExecutorSession(
	request protocol.SignRequest,
	activeShares []*LocalShare,
	slot uint16,
	material []signingExecutorSlotMaterial,
) (*signingExecutorSession, error) {
	if slot == 0 || slot > signingExecutorSlotLimit {
		return nil, fmt.Errorf(
			"%w: slot %d outside [1, %d]", errInvalidSigningAttempt, slot, signingExecutorSlotLimit,
		)
	}
	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	if len(activeShares) == 0 {
		return nil, fmt.Errorf("%w: no active shares", errInvalidSigningAttempt)
	}
	participants := len(activeShares[0].Committee.Participants)
	params, err := SigningParametersForParticipants(participants)
	if err != nil {
		return nil, ErrUnsupportedSigningCommitteeSize
	}
	threshold := params.Threshold
	if len(activeShares) != threshold {
		return nil, fmt.Errorf("%w: %d active shares, want %d", errInvalidSigningAttempt, len(activeShares), threshold)
	}
	if len(material) != threshold {
		return nil, fmt.Errorf("%w: %d material sets, want %d", errInvalidSigningAttempt, len(material), threshold)
	}
	participantIDs := make([]uint32, threshold)
	positions := make([]uint8, threshold)
	activeMask := uint16(0)
	for index, share := range activeShares {
		if share == nil || share.Validate() != nil {
			return nil, fmt.Errorf("%w: active share %d is invalid", errInvalidSigningAttempt, index)
		}
		if len(share.Committee.Participants) != participants {
			return nil, fmt.Errorf("%w: active share %d committee size mismatch", errInvalidSigningAttempt, index)
		}
		participantIDs[index] = share.ParticipantID
		positions[index] = share.ParticipantPosition
		if index > 0 && (participantIDs[index-1] >= participantIDs[index] || positions[index-1] >= positions[index]) {
			return nil, fmt.Errorf("%w: active shares are not in canonical order", errInvalidSigningAttempt)
		}
		activeMask |= 1 << share.ParticipantPosition
	}
	signerIDs := append([]uint32(nil), participantIDs...)
	sessionID, err := Dilithium3SigningSessionID(request, signerIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	for index, share := range activeShares {
		shareSession, err := Dilithium3SigningSessionForShare(request, share, signerIDs)
		if err != nil || shareSession != sessionID {
			return nil, fmt.Errorf("%w: active share %d does not match the request", errInvalidSigningAttempt, index)
		}
	}
	allocation, err := AllocateRSSGroupsFor(activeMask, participants)
	if err != nil {
		return nil, fmt.Errorf("%w: active set %012b: %v", errInvalidSigningAttempt, activeMask, err)
	}
	var rho [32]byte
	copy(rho[:], request.Key.PublicKey[:32])
	for index, share := range activeShares {
		if share.Rho != rho {
			return nil, fmt.Errorf("%w: active share %d rho does not match the key", errInvalidSigningAttempt, index)
		}
	}
	for index := range material {
		if material[index].journal == nil || material[index].record == nil {
			return nil, fmt.Errorf("%w: signer %d material is incomplete", errInvalidSigningAttempt, index)
		}
		if err := validateSigningRandomness(material[index].randomness, params); err != nil {
			return nil, fmt.Errorf("%w: randomness %d: %v", errInvalidSigningAttempt, index, err)
		}
	}
	partialFirst, partialSecond, err := reconstructPartialSecrets(activeShares, participants, allocation)
	if err != nil {
		return nil, err
	}
	representative, err := signingMessageRepresentative(request.Key, request.Message)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	fullMask := uint8(1<<threshold) - 1
	policy := SigningExecutorPolicy{SessionID: sessionID, Signers: append([]uint32(nil), participantIDs...)}
	session := &signingExecutorSession{policy: policy, slot: slot, signers: make([]*signingExecutorSigner, threshold)}
	for index := range activeShares {
		gate, err := NewSigningExecutorGate(policy)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
		}
		session.signers[index] = &signingExecutorSigner{
			gate:           gate,
			position:       index,
			slot:           slot,
			sessionID:      sessionID,
			participantID:  participantIDs[index],
			identities:     participantIDs,
			fullMask:       fullMask,
			params:         params,
			randomness:     material[index].randomness,
			partialFirst:   partialFirst[index],
			partialSecond:  partialSecond[index],
			journal:        material[index].journal,
			record:         material[index].record,
			rho:            rho,
			representative: representative,
			key:            request.Key.Clone(),
			message:        append([]byte(nil), request.Message...),
			commits:        make([][32]byte, threshold),
			reveals:        make([]VectorK, threshold),
			acceptances:    make([]bool, threshold),
			parts:          make([][L]SignedPoly, threshold),
		}
	}
	return session, nil
}

// start queues each signer's round-1 commit.
func (session *signingExecutorSession) start() error {
	if session == nil {
		return errInvalidSigningAttempt
	}
	if session.started {
		return fmt.Errorf("%w: session started twice", errInvalidSigningState)
	}
	session.started = true
	for _, signer := range session.signers {
		if err := signer.start(); err != nil {
			if burnErr := session.burn(); burnErr != nil {
				return fmt.Errorf("%w (burn: %v)", err, burnErr)
			}
			return err
		}
	}
	return nil
}

// drain returns and clears every queued outbound message of the session, in
// signer order.
func (session *signingExecutorSession) drain() []signingExecutorEnvelope {
	if session == nil {
		return nil
	}
	var queued []signingExecutorEnvelope
	for _, signer := range session.signers {
		queued = append(queued, signer.drain()...)
	}
	return queued
}

// deliverTo routes one message to one receiver. A nil error means the message
// was applied or was an idempotent retransmission. An unauthorized message is
// refused without ending the slot; every other failure ends it, consumes every
// remaining one-time material of the session, and is sticky for the whole
// session.
func (session *signingExecutorSession) deliverTo(target int, envelope signingExecutorEnvelope) error {
	if session == nil {
		return errInvalidSigningAttempt
	}
	if session.aborted != nil {
		return session.aborted
	}
	if !session.started {
		return fmt.Errorf("%w: session not started", errInvalidSigningState)
	}
	if target < 0 || target >= len(session.signers) {
		return fmt.Errorf("%w: receiver %d", errInvalidSigningAttempt, target)
	}
	err := session.signers[target].deliver(envelope)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrSigningExecutorUnauthorized) {
		return err
	}
	var abort *signingExecutorAbort
	if errors.As(err, &abort) && abort.fatal() {
		session.aborted = abort
	}
	if burnErr := session.burn(); burnErr != nil {
		return fmt.Errorf("%w (burn: %v)", err, burnErr)
	}
	return err
}

// burn consumes the one-time material of every signer that has not finalized: a
// slot that ends in an abort, a rejection, or a silence never leaves a live
// record or an unfinished journal entry behind. It is idempotent.
func (session *signingExecutorSession) burn() error {
	var failure error
	for _, signer := range session.signers {
		if err := signer.burn(); err != nil && failure == nil {
			failure = err
		}
	}
	return failure
}

// finish closes the slot once the coordinator can deliver nothing more: it
// reports the signature, the first legitimate rejection, or the silent
// participant that starves the slot. Every outcome but a signature consumes the
// remaining one-time material of the slot. Reason codes are bounded: a
// rejection is a normal outcome, a silence names the missing message and its
// sender, and every delivered message was already checked when it was
// delivered.
func (session *signingExecutorSession) finish() ([]byte, error) {
	if session == nil || !session.started {
		return nil, fmt.Errorf("%w: session not started", errInvalidSigningState)
	}
	if session.aborted != nil {
		return nil, session.aborted
	}
	for _, signer := range session.signers {
		if signer.isRejected() {
			abort := &signingExecutorAbort{
				reason:   SigningExecutorReasonLocalRejection,
				evidence: Evidence{ParticipantID: signer.participantID},
				detail:   "local rejection",
			}
			if err := session.burn(); err != nil {
				return nil, fmt.Errorf("%w (burn: %v)", abort, err)
			}
			return nil, abort
		}
	}
	for _, signer := range session.signers {
		if kind, sender, missing := signer.missing(); missing {
			abort := &signingExecutorAbort{
				reason:   SigningExecutorReasonSilence,
				evidence: Evidence{ParticipantID: sender},
				detail:   fmt.Sprintf("missing %s", signingExecutorKindName(kind)),
			}
			if err := session.burn(); err != nil {
				return nil, fmt.Errorf("%w (burn: %v)", abort, err)
			}
			return nil, abort
		}
	}
	var signature []byte
	for _, signer := range session.signers {
		current := signer.result()
		if current == nil {
			return nil, fmt.Errorf(
				"%w: signer %d has no signature and no missing input", errInvalidSigningState, signer.participantID,
			)
		}
		if signature == nil {
			signature = current
			continue
		}
		if !bytes.Equal(signature, current) {
			return nil, fmt.Errorf("%w: signers produced different signatures", errInvalidSigningState)
		}
	}
	return signature, nil
}

// hasStarted reports whether this signer has persisted its one-time binding.
func (signer *signingExecutorSigner) hasStarted() bool {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	return signer.started
}

// isBurned reports whether this signer consumed its one-time material without a
// signature.
func (signer *signingExecutorSigner) isBurned() bool {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	return signer.burned
}

// isRejected reports whether this signer observed a rejection bit and stopped.
func (signer *signingExecutorSigner) isRejected() bool {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	return signer.rejected
}

// missing reports the earliest input this signer still needs.
func (signer *signingExecutorSigner) missing() (uint16, uint32, bool) {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	return signer.missingLocked()
}

// result returns this signer's signature, or nil when it has no complete one.
func (signer *signingExecutorSigner) result() []byte {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	return signer.signature
}

// signingExecutorChallengeShift computes the centered coefficients of
// c * partial for one signer's own partial secret. It is the per-signer form of
// the reference driver's inline shift; Slice 2 pins the two against each other
// by differential testing.
func signingExecutorChallengeShift(
	partialFirst VectorL,
	partialSecond VectorK,
	challenge Poly,
) ([L]SignedPoly, [K]SignedPoly) {
	challengeNTT := ForwardNTT(challenge)
	var shiftFirst [L]SignedPoly
	var shiftSecond [K]SignedPoly
	for row := 0; row < L; row++ {
		product := InverseNTT(pointwiseMultiply(challengeNTT, ForwardNTT(partialFirst[row])))
		for index := 0; index < N; index++ {
			shiftFirst[row][index] = CenteredCoefficient(product[index])
		}
	}
	for row := 0; row < K; row++ {
		product := InverseNTT(pointwiseMultiply(challengeNTT, ForwardNTT(partialSecond[row])))
		for index := 0; index < N; index++ {
			shiftSecond[row][index] = CenteredCoefficient(product[index])
		}
	}
	return shiftFirst, shiftSecond
}

// signingExecutorCombine runs the three public combine checks over published
// values only and assembles the packed signature. A failed predicate is
// returned by name; the error return is reserved for malformed inputs and
// internal failures. The checks mirror the reference driver's finalize step,
// and Slice 2 pins them against it by differential testing.
func signingExecutorCombine(
	key protocol.ThresholdKeyID,
	message []byte,
	w VectorK,
	highBits VectorK,
	seed [CTildeSize]byte,
	z [L]SignedPoly,
) ([]byte, string, error) {
	// Public check 1: ||z||inf < Gamma1 - Beta, the verifier's own bound.
	for row := 0; row < L; row++ {
		for index := 0; index < N; index++ {
			value := int64(z[row][index])
			if value >= Gamma1-Beta || value <= -(Gamma1-Beta) {
				return nil, "aggregate z bound", nil
			}
		}
	}
	var rho [32]byte
	copy(rho[:], key.PublicKey[:32])
	var normalized VectorL
	for row := 0; row < L; row++ {
		for index := 0; index < N; index++ {
			normalized[row][index] = Normalize(z[row][index])
		}
	}
	commitment, err := ComputePublicVector(rho, normalized, VectorK{})
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	challenge, err := DeriveMode3Challenge(seed)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	t1, err := decodeMode3T1(key.PublicKey[32:])
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	var hints HintVector
	weight := 0
	for row := 0; row < K; row++ {
		shifted := MultiplyPolynomials(challenge, ScalarMul(t1[row], 1<<D))
		verificationInput := Sub(commitment[row], shifted)
		// Public check 2: ||delta||inf <= Gamma2, the hint's precondition.
		delta := Sub(w[row], verificationInput)
		for index := 0; index < N; index++ {
			value := CenteredCoefficient(delta[index])
			if value > Gamma2 || value < -Gamma2 {
				return nil, "combine delta bound", nil
			}
		}
		high := HighBits(verificationInput)
		for index := 0; index < N; index++ {
			if high[index] != highBits[row][index] {
				hints[row][index] = 1
				weight++
			}
		}
		corrected, err := UseHint(verificationInput, hints[row])
		if err != nil {
			return nil, "", fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
		}
		if corrected != highBits[row] {
			return nil, "UseHint does not reproduce the committed w1", nil
		}
	}
	// Public check 3: the hint weight is at most Omega.
	if weight > Omega {
		return nil, "hint weight", nil
	}
	parts := SignatureParts{Challenge: seed, Z: z, Hints: hints}
	signature, err := AssembleVerifiedMode3Signature(key, message, parts)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	return signature, "", nil
}
