// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Session-scoped admissibility for the signing executor (design note,
// Slice 1). The gate mirrors the DKG inbox pattern -- a per-session identity
// snapshot, an admissibility check before delivery, and a replay table -- with
// one deliberate simplification: every kind of the revised construction is a
// broadcast inside the active set, so the recipient-position check of the DKG
// inbox reduces to "the sender is an active signer of this session".
//
// The gate holds no secret and no payload: it keeps one payload digest per
// (sender, slot, kind) replay key, so an identical retransmission is
// idempotent and a conflicting one is attributable evidence.

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrInvalidSigningExecutorGate reports a malformed policy.
	ErrInvalidSigningExecutorGate = errors.New("invalid Dilithium3 v1 signing executor gate")

	// ErrSigningExecutorUnauthorized reports a message whose sender, slot, or
	// kind is outside the session policy.
	ErrSigningExecutorUnauthorized = errors.New("unauthorized Dilithium3 v1 signing executor message")

	// ErrSigningExecutorConflict reports a second, different payload for one
	// replay key: the sender equivocated.
	ErrSigningExecutorConflict = errors.New("conflicting Dilithium3 v1 signing executor message")
)

// signingExecutorSlotLimit bounds the slot index. The pinned schedule uses
// fewer slots per request; anything beyond this bound is malformed.
const signingExecutorSlotLimit = 1 << 12

// SigningExecutorReason is the bounded abort reason of one slot. A local
// rejection and a failed combine check are normal outcomes; the others are
// attributable deviations.
type SigningExecutorReason uint8

const (
	SigningExecutorReasonUnknown SigningExecutorReason = iota
	SigningExecutorReasonUnauthorized
	SigningExecutorReasonConflict
	SigningExecutorReasonCommitmentMismatch
	SigningExecutorReasonLocalRejection
	SigningExecutorReasonCombineCheck
	SigningExecutorReasonSilence
)

func (reason SigningExecutorReason) String() string {
	switch reason {
	case SigningExecutorReasonUnauthorized:
		return "unauthorized"
	case SigningExecutorReasonConflict:
		return "conflict"
	case SigningExecutorReasonCommitmentMismatch:
		return "commitment mismatch"
	case SigningExecutorReasonLocalRejection:
		return "local rejection"
	case SigningExecutorReasonCombineCheck:
		return "combine check"
	case SigningExecutorReasonSilence:
		return "silence"
	default:
		return "unknown"
	}
}

// SigningExecutorAdmission is the outcome of the admissibility gate.
type SigningExecutorAdmission uint8

const (
	SigningExecutorAdmissionUnknown SigningExecutorAdmission = iota

	// SigningExecutorAdmissionFresh is the first delivery of a message: the
	// caller applies it.
	SigningExecutorAdmissionFresh

	// SigningExecutorAdmissionDuplicate is an identical retransmission: the
	// caller skips it, because applying it twice would duplicate a reveal.
	SigningExecutorAdmissionDuplicate
)

// SigningExecutorPolicy is the per-session admissibility snapshot: the session
// identifier and the active signer identities in canonical ascending order.
// Since R76b the signer count is the pinned row threshold (4 or 5) instead of
// a fixed four.
type SigningExecutorPolicy struct {
	SessionID [32]byte
	Signers   []uint32
}

// Validate rejects a policy that does not describe a strictly ascending,
// non-zero signer identity list that matches a pinned committee row.
func (policy SigningExecutorPolicy) Validate() error {
	if policy.SessionID == ([32]byte{}) {
		return fmt.Errorf("%w: zero session", ErrInvalidSigningExecutorGate)
	}
	if _, err := SigningParametersForThresholdCount(len(policy.Signers)); err != nil {
		return err
	}
	for index, signer := range policy.Signers {
		if signer == 0 {
			return fmt.Errorf("%w: zero signer at position %d", ErrInvalidSigningExecutorGate, index)
		}
		if index > 0 && policy.Signers[index-1] >= signer {
			return fmt.Errorf("%w: signers are not strictly ascending", ErrInvalidSigningExecutorGate)
		}
	}
	return nil
}

// activeSigner reports whether the identity is one of the four signers.
func (policy SigningExecutorPolicy) activeSigner(sender uint32) bool {
	for _, signer := range policy.Signers {
		if signer == sender {
			return true
		}
	}
	return false
}

// signingExecutorReplayKey identifies one logical message of one slot.
type signingExecutorReplayKey struct {
	Sender uint32
	Slot   uint16
	Kind   uint16
}

// SigningExecutorGate authorizes and de-duplicates incoming executor payloads
// before any of them is applied.
type SigningExecutorGate struct {
	mu     sync.Mutex
	policy SigningExecutorPolicy
	seen   map[signingExecutorReplayKey][32]byte
}

// NewSigningExecutorGate returns a gate bound to one session policy.
func NewSigningExecutorGate(policy SigningExecutorPolicy) (*SigningExecutorGate, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &SigningExecutorGate{
		policy: policy,
		seen:   make(map[signingExecutorReplayKey][32]byte),
	}, nil
}

// Policy returns the immutable session policy.
func (gate *SigningExecutorGate) Policy() SigningExecutorPolicy {
	if gate == nil {
		return SigningExecutorPolicy{}
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.policy
}

// Observe checks one incoming payload against the policy and the replay table.
// It returns the admission and, for a conflict, attributable evidence that
// carries the sender and the digest of the first payload for that key.
func (gate *SigningExecutorGate) Observe(
	sender uint32,
	slot uint16,
	kind uint16,
	payload []byte,
) (SigningExecutorAdmission, Evidence, error) {
	if gate == nil {
		return SigningExecutorAdmissionUnknown, Evidence{}, fmt.Errorf(
			"%w: missing gate", ErrInvalidSigningExecutorGate,
		)
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if slot == 0 || slot > signingExecutorSlotLimit {
		return SigningExecutorAdmissionUnknown, Evidence{}, fmt.Errorf(
			"%w: slot %d outside [1, %d]", ErrSigningExecutorUnauthorized, slot, signingExecutorSlotLimit,
		)
	}
	switch kind {
	case SigningExecutorKindCommit, SigningExecutorKindReveal,
		SigningExecutorKindAcceptance, SigningExecutorKindResponse:
	default:
		return SigningExecutorAdmissionUnknown, Evidence{}, fmt.Errorf(
			"%w: kind %d", ErrSigningExecutorUnauthorized, kind,
		)
	}
	if !gate.policy.activeSigner(sender) {
		return SigningExecutorAdmissionUnknown, Evidence{}, fmt.Errorf(
			"%w: signer %d is not active", ErrSigningExecutorUnauthorized, sender,
		)
	}
	if len(payload) == 0 {
		return SigningExecutorAdmissionUnknown, Evidence{}, fmt.Errorf(
			"%w: empty payload", ErrSigningExecutorUnauthorized,
		)
	}
	digest := sha3.Sum256(payload)
	key := signingExecutorReplayKey{Sender: sender, Slot: slot, Kind: kind}
	previous, found := gate.seen[key]
	if !found {
		gate.seen[key] = digest
		return SigningExecutorAdmissionFresh, Evidence{}, nil
	}
	if previous == digest {
		return SigningExecutorAdmissionDuplicate, Evidence{ParticipantID: sender, Digest: previous}, nil
	}
	return SigningExecutorAdmissionUnknown, Evidence{ParticipantID: sender, Digest: previous}, fmt.Errorf(
		"%w: signer %d sent two payloads for slot %d kind %d", ErrSigningExecutorConflict, sender, slot, kind,
	)
}

// Received returns how many distinct messages of the session passed the gate.
func (gate *SigningExecutorGate) Received() int {
	if gate == nil {
		return 0
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return len(gate.seen)
}
