// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// The exported per-signer surface of the signing executor (design note,
// Slice 4). A node drives one party per active signer: the party holds exactly
// one LocalShare, samples its own per-slot ball randomness inside its own
// process, and drives its own durable journal and one-time record. It emits
// the four canonical round payloads of the message layer and consumes its
// peers' payloads through the same gate the in-process executor uses; the node
// transport owns the envelope, the sequence numbers, and the routing.
//
// A party derives its partial secret locally, from its own share and the
// allocation of its position -- the local form of the reference reconstruction
// -- and never sees another signer's material. The in-process drivers of
// sign.go and sign_executor.go hold all four shares and therefore stay
// references: they must never be the object a node drives, and the differential
// tests pin this surface against them byte for byte.
//
// Every deviation the gate or the round logic detects surfaces as a bounded
// outcome: an unauthorized message is refused without ending a healthy slot,
// and every other failure ends the slot, consumes this party's one-time
// material, and is sticky.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"slices"
	"sync"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// SigningExecutorPartyConfig binds one signer's slot. The request is the base
// request of the signing; the party binds the slot index into its attempt nonce
// the way the slot schedule does, so every active signer of the slot derives
// the same session from the same base request.
type SigningExecutorPartyConfig struct {
	// Request is the base signing request, unbound to any slot.
	Request protocol.SignRequest

	// Share is this signer's own local share. The party derives its partial
	// secret from it and never accepts another signer's share.
	Share *LocalShare

	// Signers are the four active signer identities in ascending order.
	Signers [4]uint32

	// Slot is the one-based slot index of the schedule.
	Slot uint16

	// Journal is this signer's durable signing journal, which lives across the
	// whole request.
	Journal *SigningJournal

	// Record is this signer's one-time preprocessing record for this slot. It
	// is committed to exactly this session and consumed by every path that
	// does not end in a signature.
	Record *PreprocessingRecord

	// Entropy is the signer's own randomness source. It must be cryptographic
	// in production (crypto/rand.Reader): the source draws this slot's ball
	// point inside the signer's process, and the point never leaves it.
	Entropy io.Reader
}

// SigningExecutorRoundMessage is one queued round message of a party: the
// wallet-side message kind and its canonical payload. The node transport wraps
// it into the threshold envelope with the sender identity and the sequence
// number, and the slot index travels inside the payload.
type SigningExecutorRoundMessage struct {
	Kind    uint16
	Payload []byte
}

// SigningExecutorOutcome is the exported, bounded view of one executor error.
// Fatal reports whether the error ends the slot; an unauthorized refusal is
// the only non-fatal outcome, so network noise cannot kill a healthy signing.
// A caller that cannot obtain a bounded outcome must treat the error as
// terminal.
type SigningExecutorOutcome struct {
	Reason   SigningExecutorReason
	Evidence Evidence
	Fatal    bool
}

// SigningExecutorOutcomeOf extracts the bounded outcome of an executor error.
// The boolean reports whether the error is a bounded executor outcome at all.
func SigningExecutorOutcomeOf(err error) (SigningExecutorOutcome, bool) {
	var abort *signingExecutorAbort
	if !errors.As(err, &abort) {
		return SigningExecutorOutcome{}, false
	}
	return SigningExecutorOutcome{
		Reason:   abort.reason,
		Evidence: abort.evidence,
		Fatal:    abort.fatal(),
	}, true
}

// SigningExecutorParty is one active signer of one slot. It owns the round
// logic, the gate checks, and the single-use lifecycle of its own material; the
// node transport owns the envelope and the routing.
type SigningExecutorParty struct {
	lock      sync.Mutex
	signer    *signingExecutorSigner
	sessionID [32]byte
	aborted   *signingExecutorAbort
}

// NewSigningExecutorParty samples this signer's per-slot ball point from the
// config's entropy source and returns the party of one slot. The sampling
// happens inside the signer's own process (design note, Open Obligations
// item 1); the point is never serialized and never returned.
func NewSigningExecutorParty(config SigningExecutorPartyConfig) (*SigningExecutorParty, error) {
	point, err := sampleSigningExecutorPartyRandomness(config.Entropy)
	if err != nil {
		return nil, err
	}
	return newSigningExecutorParty(config, point)
}

// sampleSigningExecutorPartyRandomness draws one uniform ball point from the
// caller's source: eight bytes seed the deterministic stream the sampler
// consumes. A production caller passes a cryptographic source, so the seed is
// unpredictable; the stream itself is deterministic given the seed.
func sampleSigningExecutorPartyRandomness(entropy io.Reader) (*signingRandomness, error) {
	if entropy == nil {
		return nil, fmt.Errorf("%w: missing entropy source", ErrInvalidSigningRandomness)
	}
	var seed [8]byte
	if _, err := io.ReadFull(entropy, seed[:]); err != nil {
		return nil, fmt.Errorf("%w: entropy: %v", ErrInvalidSigningRandomness, err)
	}
	point, err := sampleSigningRandomness(rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seed[:])))))
	if err != nil {
		return nil, err
	}
	return point, nil
}

// newSigningExecutorParty validates the binding and assembles the party around
// one signer instance. The ball point is supplied here so the differential
// tests can drive one party and the in-process references on byte-identical
// inputs; NewSigningExecutorParty samples it from the config's entropy source.
func newSigningExecutorParty(
	config SigningExecutorPartyConfig,
	point *signingRandomness,
) (*SigningExecutorParty, error) {
	if config.Slot == 0 || config.Slot > signingExecutorSlotLimit {
		return nil, fmt.Errorf(
			"%w: slot %d outside [1, %d]", errInvalidSigningAttempt, config.Slot, signingExecutorSlotLimit,
		)
	}
	if config.Journal == nil || config.Record == nil {
		return nil, fmt.Errorf("%w: missing journal or preprocessing record", errInvalidSigningAttempt)
	}
	if err := config.Request.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	if err := config.Share.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	if err := validateSigningRandomness(point); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	slotRequest := signingExecutorSlotRequest(config.Request, config.Slot)
	sessionID, err := Dilithium3SigningSessionForShare(slotRequest, config.Share, config.Signers[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	policy := SigningExecutorPolicy{SessionID: sessionID, Signers: config.Signers}
	gate, err := NewSigningExecutorGate(policy)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	position := slices.Index(config.Signers[:], config.Share.ParticipantID)
	if position < 0 {
		return nil, fmt.Errorf(
			"%w: share of participant %d is not an active signer", errInvalidSigningAttempt, config.Share.ParticipantID,
		)
	}
	activeMask := uint8(0)
	for _, identity := range config.Signers {
		signerPosition, found := committeePosition(config.Share.Committee, identity)
		if !found {
			return nil, fmt.Errorf("%w: signer %d is outside the committee", errInvalidSigningAttempt, identity)
		}
		activeMask |= 1 << signerPosition
	}
	allocation, err := AllocateRSSGroups(activeMask)
	if err != nil {
		return nil, fmt.Errorf("%w: active set %06b: %v", errInvalidSigningAttempt, activeMask, err)
	}
	var rho [32]byte
	copy(rho[:], slotRequest.Key.PublicKey[:32])
	if config.Share.Rho != rho {
		return nil, fmt.Errorf("%w: local share rho does not match the key", errInvalidSigningAttempt)
	}
	partialFirst, partialSecond := localPartialSecrets(config.Share, allocation)
	owned := 0
	for _, owner := range allocation {
		if owner == config.Share.ParticipantPosition {
			owned++
		}
	}
	bound := owned * RSSComponentEta
	for row := 0; row < L; row++ {
		if err := validatePartialBound("s1", position, row, partialFirst[row], bound); err != nil {
			return nil, err
		}
	}
	for row := 0; row < K; row++ {
		if err := validatePartialBound("s2", position, row, partialSecond[row], bound); err != nil {
			return nil, err
		}
	}
	representative, err := signingMessageRepresentative(slotRequest.Key, slotRequest.Message)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	return &SigningExecutorParty{
		sessionID: sessionID,
		signer: &signingExecutorSigner{
			gate:           gate,
			position:       position,
			slot:           config.Slot,
			sessionID:      sessionID,
			participantID:  config.Share.ParticipantID,
			identities:     config.Signers,
			randomness:     point,
			partialFirst:   partialFirst,
			partialSecond:  partialSecond,
			journal:        config.Journal,
			record:         config.Record,
			rho:            rho,
			representative: representative,
			key:            slotRequest.Key.Clone(),
			message:        append([]byte(nil), slotRequest.Message...),
		},
	}, nil
}

// SessionID returns the signing session this party is bound to. The node builds
// the envelope context from it, so no second derivation can disagree.
func (party *SigningExecutorParty) SessionID() [32]byte {
	if party == nil {
		return [32]byte{}
	}
	return party.sessionID
}

// Start persists this party's one-time binding -- the journal prepared and
// committed entries and the record bound to this session -- and queues its
// round-1 commit. No message leaves the party before the binding is durable.
func (party *SigningExecutorParty) Start() error {
	if party == nil {
		return errInvalidSigningAttempt
	}
	party.lock.Lock()
	defer party.lock.Unlock()
	if party.aborted != nil {
		return party.aborted
	}
	return party.signer.start()
}

// Drain returns and clears every queued round message of this party. The
// transport wraps each one into its envelope and routes it to the other three
// signers.
func (party *SigningExecutorParty) Drain() []SigningExecutorRoundMessage {
	if party == nil {
		return nil
	}
	queued := party.signer.drain()
	if len(queued) == 0 {
		return nil
	}
	messages := make([]SigningExecutorRoundMessage, 0, len(queued))
	for _, envelope := range queued {
		messages = append(messages, SigningExecutorRoundMessage{Kind: envelope.Kind, Payload: envelope.Payload})
	}
	return messages
}

// Deliver applies one inbound round message after the transport has checked its
// envelope and its identity signature. A nil error means the message was
// applied or was an idempotent retransmission; an unauthorized refusal ends
// nothing, and every other failure ends the slot, consumes this party's
// one-time material, and is sticky.
func (party *SigningExecutorParty) Deliver(sender uint32, kind uint16, payload []byte) error {
	if party == nil {
		return errInvalidSigningAttempt
	}
	party.lock.Lock()
	defer party.lock.Unlock()
	if party.aborted != nil {
		return party.aborted
	}
	err := party.signer.deliver(signingExecutorEnvelope{Sender: sender, Kind: kind, Payload: payload})
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrSigningExecutorUnauthorized) {
		return err
	}
	var abort *signingExecutorAbort
	if errors.As(err, &abort) && abort.fatal() {
		party.aborted = abort
	}
	if burnErr := party.signer.burn(); burnErr != nil {
		return fmt.Errorf("%w (burn: %v)", err, burnErr)
	}
	return err
}

// NewSigningExecutorRecord mints one fresh one-time record for one slot from
// the caller's entropy source. The revised construction needs no offline
// supply (design note, R57): the record is the slot's single-use binding token,
// so its identifier, its opaque handle, and its public commitment are all drawn
// here, and a production caller passes a cryptographic source (crypto/rand).
// The record is consumed by the slot's party: committed to exactly one session
// in Start and burned on every path that does not end in a signature.
func NewSigningExecutorRecord(participantID uint32, entropy io.Reader) (*PreprocessingRecord, error) {
	if participantID == 0 {
		return nil, fmt.Errorf("%w: zero participant", ErrInvalidPreprocessing)
	}
	if entropy == nil {
		return nil, fmt.Errorf("%w: missing entropy source", ErrInvalidPreprocessing)
	}
	var material [3][32]byte
	for index := range material {
		if _, err := io.ReadFull(entropy, material[index][:]); err != nil {
			return nil, fmt.Errorf("%w: entropy: %v", ErrInvalidPreprocessing, err)
		}
	}
	record, err := NewPreprocessingRecord(
		PreprocessingID(material[0]), participantID, SecretHandle(material[1]), material[2],
	)
	if err != nil {
		return nil, err
	}
	return record, nil
}

// Done reports whether this party's slot reached a terminal state: a completed
// signature, a legitimate rejection, a burned outcome, or a reported abort. A
// done slot publishes nothing further, so the node driver closes it with
// Finish instead of waiting for its deadline.
func (party *SigningExecutorParty) Done() bool {
	if party == nil {
		return true
	}
	party.lock.Lock()
	defer party.lock.Unlock()
	if party.aborted != nil || party.signer.result() != nil {
		return true
	}
	return party.signer.isBurned() || party.signer.isRejected()
}

// Filtered reports whether this party's slot ended in a legitimate filter
// outcome -- a local rejection or a failed public combine check -- rather than
// a hard abort. It is meaningful once Done reports true and Finish failed: the
// schedule answers a filter by starting the next candidate slot, and every
// other failure ends the request.
func (party *SigningExecutorParty) Filtered() bool {
	if party == nil {
		return false
	}
	party.lock.Lock()
	defer party.lock.Unlock()
	if party.aborted == nil {
		return false
	}
	switch party.aborted.reason {
	case SigningExecutorReasonLocalRejection, SigningExecutorReasonCombineCheck:
		return true
	default:
		return false
	}
}

// Finish closes this party's slot: it reports the signature, or the first
// legitimate rejection or the missing input that starves the slot. Every
// outcome but a signature consumes the one-time material, and every abort is
// sticky.
func (party *SigningExecutorParty) Finish() ([]byte, error) {
	if party == nil {
		return nil, errInvalidSigningAttempt
	}
	party.lock.Lock()
	defer party.lock.Unlock()
	if party.aborted != nil {
		return nil, party.aborted
	}
	if !party.signer.hasStarted() {
		return nil, fmt.Errorf("%w: party not started", errInvalidSigningState)
	}
	if party.signer.isRejected() {
		abort := &signingExecutorAbort{
			reason:   SigningExecutorReasonLocalRejection,
			evidence: Evidence{ParticipantID: party.signer.participantID},
			detail:   "local rejection",
		}
		party.aborted = abort
		if err := party.signer.burn(); err != nil {
			return nil, fmt.Errorf("%w (burn: %v)", abort, err)
		}
		return nil, abort
	}
	if kind, sender, missing := party.signer.missing(); missing {
		abort := &signingExecutorAbort{
			reason:   SigningExecutorReasonSilence,
			evidence: Evidence{ParticipantID: sender},
			detail:   fmt.Sprintf("missing %s", signingExecutorKindName(kind)),
		}
		party.aborted = abort
		if err := party.signer.burn(); err != nil {
			return nil, fmt.Errorf("%w (burn: %v)", abort, err)
		}
		return nil, abort
	}
	signature := party.signer.result()
	if signature == nil {
		return nil, fmt.Errorf(
			"%w: party %d has no signature and no missing input",
			errInvalidSigningState, party.signer.participantID,
		)
	}
	return signature, nil
}
