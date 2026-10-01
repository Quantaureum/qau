// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// This file is the in-process reference driver of the four-of-six Dilithium3
// v1 signing state machine, revised by R57 to the reviewed construction. Each
// active signer samples its own ball randomness, publishes the MLWE commitment
// share w_i = A*(nu*x1) + x2 after the round-1 commitment, applies the
// per-party rejection test locally, and the accepted slot publishes the
// aggregate response z^(1) = sum_i z_i^(1). The combine recomputes w, w1,
// delta = w - (A*z^(1) - 2^D*c*t1), and the hint from public values only, runs
// the three public checks, and the unmodified verifier accepts the packed
// 3293-byte mode3 signature. There is no distributed carry, no bit
// decomposition, and no global norm circuit on this path.
//
// Like sign_randomness.go this driver is a correctness, leakage, and cost
// reference and never a production path. The networked executor, the secure
// sampler placement, and the side-channel review remain open obligations of
// the design note, so no exported production entry point exists yet. The
// driver holds all four active shares and all four randomness points in one
// process, which is also why it can reconstruct the partial secrets the
// reference rejection test consumes.

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const (
	// signingAttemptDomain separates the attempt binding digest from every other
	// transcript in the protocol.
	signingAttemptDomain = "QAU-TDILITHIUM3-V1-SIGNING-ATTEMPT"

	// signingPreparedDomain, signingCommitmentDomain, and signingResponseDomain
	// separate the three journal payloads from each other and from the attempt
	// binding.
	signingPreparedDomain   = "QAU-TDILITHIUM3-V1-SIGNING-PREPARED"
	signingCommitmentDomain = "QAU-TDILITHIUM3-V1-SIGNING-COMMITMENT"
	signingResponseDomain   = "QAU-TDILITHIUM3-V1-SIGNING-RESPONSE"
)

var (
	// errInvalidSigningAttempt reports malformed attempt input: a missing
	// journal or record, an invalid request, share, or randomness, or a
	// malformed partial secret.
	errInvalidSigningAttempt = errors.New("invalid Dilithium3 v1 signing attempt")

	// errInvalidSigningState reports a round called out of order. A call in a
	// live attempt burns it; a terminal attempt only reports the error.
	errInvalidSigningState = errors.New("invalid Dilithium3 v1 signing state transition")

	// errSigningRejected reports a legitimate rejection: a local rejection or a
	// failed public combine check of this slot. Nothing derived from a secret
	// is opened and the attempt burns.
	errSigningRejected = errors.New("Dilithium3 v1 signing attempt rejected")

	// errSigningInconsistent reports that the public reconstruction no longer
	// matches the committed transcript, which must never produce a signature.
	errSigningInconsistent = errors.New("inconsistent Dilithium3 v1 signing transcript")
)

// signingState is the monotonic lifecycle of one attempt. Challenged is the
// wallet-level view of the round-2 opening; the single-use journal does not
// distinguish it because nothing durable changes until the response.
type signingState uint8

const (
	signingStateUnknown signingState = iota
	signingStateCreated
	signingStatePrepared
	signingStateCommitted
	signingStateChallenged
	signingStateResponded
	signingStateFinalized
	signingStateBurned
)

func (state signingState) String() string {
	switch state {
	case signingStateCreated:
		return "created"
	case signingStatePrepared:
		return "prepared"
	case signingStateCommitted:
		return "committed"
	case signingStateChallenged:
		return "challenged"
	case signingStateResponded:
		return "responded"
	case signingStateFinalized:
		return "finalized"
	case signingStateBurned:
		return "burned"
	default:
		return "unknown"
	}
}

// signingCommitment is the round-1 public transcript: the session identity and
// the digest of the four committed MLWE shares w_i. It carries no randomness
// and no partial value.
type signingCommitment struct {
	SessionID  [32]byte
	Commitment [32]byte
}

// signingChallenge is the round-2 public transcript: w1, which the verifier
// recomputes, and the challenge derived from it. It carries no randomness and
// no second-half value.
type signingChallenge struct {
	SessionID [32]byte
	HighBits  PublicHighBits
	Challenge [CTildeSize]byte
}

// signingResponse is the round-3 public transcript: the aggregate response,
// which is a component of the released signature, and its journal digest. The
// aggregate is opened only after every signer accepted the slot; no individual
// response part is exposed by this reference transcript.
type signingResponse struct {
	SessionID      [32]byte
	Z              [L]SignedPoly
	ResponseDigest [32]byte
}

// signingAttempt drives one slot of one signing request over the reference
// engine. It holds the round data as unexported state; the only values it ever
// returns are the three public round transcripts and the final signature.
type signingAttempt struct {
	lock    sync.Mutex
	journal *SigningJournal
	record  *PreprocessingRecord

	request       protocol.SignRequest
	key           protocol.ThresholdKeyID
	sessionID     [32]byte
	bindingDigest [32]byte
	randomness    [4]*signingRandomness

	// Reference dealer model: each active signer's partial secret from its five
	// assigned components, and the public values the combine needs.
	partialFirst   [4]VectorL
	partialSecond  [4]VectorK
	t1             VectorK
	representative [64]byte

	state signingState

	contributions  [4]VectorK
	w              VectorK
	challengeValue Poly
	challengeSeed  [CTildeSize]byte
	highBits       VectorK
	z              [L]SignedPoly
	responseDigest [32]byte
	signature      []byte
}

// newSigningAttempt validates the round-0 binding and returns an attempt in the
// created state. Nothing is persisted and nothing is released until prepare.
//
// The four randomness points are supplied by the caller because the in-process
// reference drives all four signers; a networked deployment samples each point
// inside its own signer process, which is open obligation 1 of the design note.
func newSigningAttempt(
	journal *SigningJournal,
	record *PreprocessingRecord,
	request protocol.SignRequest,
	activeShares []*LocalShare,
	coordinatorID uint32,
	randomness [4]*signingRandomness,
) (*signingAttempt, error) {
	if journal == nil || record == nil {
		return nil, fmt.Errorf("%w: missing journal or preprocessing record", errInvalidSigningAttempt)
	}
	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	if coordinatorID == 0 {
		return nil, fmt.Errorf("%w: zero coordinator identity", errInvalidSigningAttempt)
	}
	if len(activeShares) != 4 {
		return nil, fmt.Errorf("%w: %d active shares, want 4", errInvalidSigningAttempt, len(activeShares))
	}
	var participantIDs [4]uint32
	var positions [4]uint8
	activeMask := uint8(0)
	for index, share := range activeShares {
		if share == nil || share.Validate() != nil {
			return nil, fmt.Errorf("%w: active share %d is invalid", errInvalidSigningAttempt, index)
		}
		participantIDs[index] = share.ParticipantID
		positions[index] = share.ParticipantPosition
		if index > 0 && (participantIDs[index-1] >= participantIDs[index] || positions[index-1] >= positions[index]) {
			return nil, fmt.Errorf("%w: active shares are not in canonical order", errInvalidSigningAttempt)
		}
		activeMask |= 1 << share.ParticipantPosition
	}
	signerIDs := participantIDs[:]
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
	allocation, err := AllocateRSSGroups(activeMask)
	if err != nil {
		return nil, fmt.Errorf("%w: active set %06b: %v", errInvalidSigningAttempt, activeMask, err)
	}
	var rho [32]byte
	copy(rho[:], request.Key.PublicKey[:32])
	for index, share := range activeShares {
		if share.Rho != rho {
			return nil, fmt.Errorf("%w: active share %d rho does not match the key", errInvalidSigningAttempt, index)
		}
	}
	t1, err := decodeMode3T1(request.Key.PublicKey[32:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	for index := range randomness {
		if err := validateSigningRandomness(randomness[index]); err != nil {
			return nil, fmt.Errorf("%w: randomness %d: %v", errInvalidSigningAttempt, index, err)
		}
	}
	partialFirst, partialSecond, err := reconstructPartialSecrets(activeShares, allocation)
	if err != nil {
		return nil, err
	}
	representative, err := signingMessageRepresentative(request.Key, request.Message)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	bindingDigest, err := signingBindingDigest(request, participantIDs, coordinatorID, allocation, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	return &signingAttempt{
		journal:        journal,
		record:         record,
		request:        request,
		key:            request.Key.Clone(),
		sessionID:      sessionID,
		bindingDigest:  bindingDigest,
		randomness:     randomness,
		partialFirst:   partialFirst,
		partialSecond:  partialSecond,
		t1:             t1,
		representative: representative,
		state:          signingStateCreated,
	}, nil
}

// prepare persists the local randomness and the preprocessing commitment in the
// signing journal before any commitment is released, then binds the one-time
// record to exactly this session.
func (attempt *signingAttempt) prepare() error {
	if attempt == nil {
		return errInvalidSigningAttempt
	}
	attempt.lock.Lock()
	defer attempt.lock.Unlock()
	if err := attempt.requireStateLocked(signingStateCreated, "prepare"); err != nil {
		return err
	}
	if attempt.record.State() != PreprocessingAvailable {
		return attempt.burnLocked(fmt.Errorf(
			"%w: preprocessing record is %v, want available", errInvalidSigningAttempt, attempt.record.State(),
		))
	}
	view := attempt.record.CoordinatorView()
	prepared, err := signingPreparedDigest(attempt.bindingDigest, view.Commitment, attempt.randomness)
	if err != nil {
		return fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	if _, err := attempt.journal.Advance(attempt.sessionID, protocol.SingleUsePrepared, prepared[:]); err != nil {
		return fmt.Errorf("%w: %v", errInvalidSigningState, err)
	}
	if err := attempt.record.Commit(attempt.sessionID); err != nil {
		return attempt.burnLocked(fmt.Errorf("%w: preprocessing commit: %v", errInvalidSigningAttempt, err))
	}
	attempt.state = signingStatePrepared
	return nil
}

// commit releases the round-1 commitment: the digest of the four committed
// MLWE shares w_i with the attempt binding. It carries no randomness and no
// partial value, so a rushing signer gains nothing from it.
func (attempt *signingAttempt) commit() (signingCommitment, error) {
	if attempt == nil {
		return signingCommitment{}, errInvalidSigningAttempt
	}
	attempt.lock.Lock()
	defer attempt.lock.Unlock()
	if err := attempt.requireStateLocked(signingStatePrepared, "commit"); err != nil {
		return signingCommitment{}, err
	}
	var rho [32]byte
	copy(rho[:], attempt.key.PublicKey[:32])
	buffer := make([]byte, 0, 32+len(attempt.randomness)*K*PolyEncodedSize)
	buffer = append(buffer, signingCommitmentDomain...)
	buffer = append(buffer, attempt.bindingDigest[:]...)
	for index := range attempt.randomness {
		contribution, err := ComputePublicVector(
			rho, attempt.randomness[index].first, attempt.randomness[index].second,
		)
		if err != nil {
			return signingCommitment{}, attempt.burnLocked(fmt.Errorf("%w: %v", errInvalidSigningAttempt, err))
		}
		attempt.contributions[index] = contribution
		for row := range contribution {
			encoded, err := EncodePoly(contribution[row])
			if err != nil {
				return signingCommitment{}, attempt.burnLocked(fmt.Errorf("%w: %v", errInvalidSigningAttempt, err))
			}
			buffer = append(buffer, encoded[:]...)
		}
	}
	commitment := sha3.Sum256(buffer)
	if _, err := attempt.journal.Advance(attempt.sessionID, protocol.SingleUseCommitted, commitment[:]); err != nil {
		return signingCommitment{}, fmt.Errorf("%w: %v", errInvalidSigningState, err)
	}
	attempt.state = signingStateCommitted
	return signingCommitment{SessionID: attempt.sessionID, Commitment: commitment}, nil
}

// challenge runs round 2: every signer reveals w_i, anyone aggregates
// w = sum_i w_i, and the challenge follows from the message representative and
// the encoded high bits, exactly as in native mode3.
func (attempt *signingAttempt) challenge() (signingChallenge, error) {
	if attempt == nil {
		return signingChallenge{}, errInvalidSigningAttempt
	}
	attempt.lock.Lock()
	defer attempt.lock.Unlock()
	if err := attempt.requireStateLocked(signingStateCommitted, "challenge"); err != nil {
		return signingChallenge{}, err
	}
	var w VectorK
	for index := range attempt.contributions {
		for row := 0; row < K; row++ {
			w[row] = Add(w[row], attempt.contributions[index][row])
		}
	}
	var highBits VectorK
	for row := 0; row < K; row++ {
		highBits[row] = HighBits(w[row])
	}
	public, err := EncodePublicHighBits(highBits)
	if err != nil {
		return signingChallenge{}, attempt.burnLocked(fmt.Errorf("%w: %v", errInvalidSigningAttempt, err))
	}
	seed, err := signingChallengeSeed(attempt.representative, public)
	if err != nil {
		return signingChallenge{}, attempt.burnLocked(fmt.Errorf("%w: %v", errInvalidSigningAttempt, err))
	}
	challengeValue, err := DeriveMode3Challenge(seed)
	if err != nil {
		return signingChallenge{}, attempt.burnLocked(fmt.Errorf("%w: %v", errInvalidSigningAttempt, err))
	}
	attempt.w = w
	attempt.challengeValue = challengeValue
	attempt.challengeSeed = seed
	attempt.highBits = highBits
	attempt.state = signingStateChallenged
	return signingChallenge{SessionID: attempt.sessionID, HighBits: public, Challenge: seed}, nil
}

// respond runs round 3: every signer computes its own challenge shift, applies
// the per-party rejection test, and an accepted slot publishes the aggregate
// response only. A rejected slot burns the attempt and opens nothing else.
func (attempt *signingAttempt) respond() (signingResponse, error) {
	if attempt == nil {
		return signingResponse{}, errInvalidSigningAttempt
	}
	attempt.lock.Lock()
	defer attempt.lock.Unlock()
	if err := attempt.requireStateLocked(signingStateChallenged, "respond"); err != nil {
		return signingResponse{}, err
	}
	challengeNTT := ForwardNTT(attempt.challengeValue)
	var shiftFirst [4][L]SignedPoly
	var shiftSecond [4][K]SignedPoly
	for index := range attempt.randomness {
		for row := 0; row < L; row++ {
			product := InverseNTT(pointwiseMultiply(challengeNTT, ForwardNTT(attempt.partialFirst[index][row])))
			for coefficient := 0; coefficient < N; coefficient++ {
				shiftFirst[index][row][coefficient] = CenteredCoefficient(product[coefficient])
			}
		}
		for row := 0; row < K; row++ {
			product := InverseNTT(pointwiseMultiply(challengeNTT, ForwardNTT(attempt.partialSecond[index][row])))
			for coefficient := 0; coefficient < N; coefficient++ {
				shiftSecond[index][row][coefficient] = CenteredCoefficient(product[coefficient])
			}
		}
	}
	// The per-party rejection is local: every signer must accept this slot.
	for index := range attempt.randomness {
		passes, err := signingRejectionTest(attempt.randomness[index], shiftFirst[index], shiftSecond[index])
		if err != nil {
			return signingResponse{}, attempt.burnLocked(fmt.Errorf("%w: %v", errInvalidSigningAttempt, err))
		}
		if !passes {
			return signingResponse{}, attempt.rejectLocked("local rejection")
		}
	}
	// Accepted slot: the aggregate response is public, the individual parts are not.
	var aggregate [L]SignedPoly
	for index := range attempt.randomness {
		part := signingResponsePart(attempt.randomness[index], shiftFirst[index])
		for row := 0; row < L; row++ {
			for coefficient := 0; coefficient < N; coefficient++ {
				aggregate[row][coefficient] += part[row][coefficient]
			}
		}
	}
	// The aggregate response must stay mode3-encodable for the durable payload,
	// so the combine's z-bound check runs here as well; a slot beyond the bound
	// is rejected like any other and the attempt burns.
	for row := 0; row < L; row++ {
		for coefficient := 0; coefficient < N; coefficient++ {
			value := int64(aggregate[row][coefficient])
			if value >= Gamma1-Beta || value <= -(Gamma1-Beta) {
				return signingResponse{}, attempt.rejectLocked("aggregate z bound")
			}
		}
	}
	if err := attempt.record.MarkResponseReleased(); err != nil {
		return signingResponse{}, attempt.burnLocked(fmt.Errorf("%w: %v", errInvalidSigningAttempt, err))
	}
	digest, err := signingResponseDigest(attempt.bindingDigest, aggregate)
	if err != nil {
		return signingResponse{}, attempt.burnLocked(fmt.Errorf("%w: %v", errInvalidSigningAttempt, err))
	}
	if _, err := attempt.journal.Advance(attempt.sessionID, protocol.SingleUseResponded, digest[:]); err != nil {
		return signingResponse{}, fmt.Errorf("%w: %v", errInvalidSigningState, err)
	}
	attempt.z = aggregate
	attempt.responseDigest = digest
	attempt.state = signingStateResponded
	return signingResponse{SessionID: attempt.sessionID, Z: aggregate, ResponseDigest: digest}, nil
}

// finalize runs round 4: the combine checks run on public values only, the
// hints are derived from delta = w - (A*z^(1) - 2^D*c*t1), and the signature is
// assembled and released only after the unmodified verifier accepted it.
func (attempt *signingAttempt) finalize() ([]byte, error) {
	if attempt == nil {
		return nil, errInvalidSigningAttempt
	}
	attempt.lock.Lock()
	defer attempt.lock.Unlock()
	if err := attempt.requireStateLocked(signingStateResponded, "finalize"); err != nil {
		return nil, err
	}
	// Public check 1: ||z^(1)||inf < Gamma1 - Beta, the verifier's own bound.
	for row := 0; row < L; row++ {
		for index := 0; index < N; index++ {
			value := int64(attempt.z[row][index])
			if value >= Gamma1-Beta || value <= -(Gamma1-Beta) {
				return nil, attempt.rejectLocked("aggregate z bound")
			}
		}
	}
	var rho [32]byte
	copy(rho[:], attempt.key.PublicKey[:32])
	var normalized VectorL
	for row := 0; row < L; row++ {
		for index := 0; index < N; index++ {
			normalized[row][index] = Normalize(attempt.z[row][index])
		}
	}
	commitment, err := ComputePublicVector(rho, normalized, VectorK{})
	if err != nil {
		return nil, attempt.burnLocked(fmt.Errorf("%w: %v", errInvalidSigningAttempt, err))
	}
	var hints HintVector
	weight := 0
	for row := 0; row < K; row++ {
		shifted := MultiplyPolynomials(attempt.challengeValue, ScalarMul(attempt.t1[row], 1<<D))
		verificationInput := Sub(commitment[row], shifted)
		// Public check 2: ||delta||inf <= Gamma2, the hint's precondition.
		deltaPoly := Sub(attempt.w[row], verificationInput)
		for index := 0; index < N; index++ {
			delta := CenteredCoefficient(deltaPoly[index])
			if delta > Gamma2 || delta < -Gamma2 {
				return nil, attempt.rejectLocked("combine delta bound")
			}
		}
		high := HighBits(verificationInput)
		for index := 0; index < N; index++ {
			if high[index] != attempt.highBits[row][index] {
				hints[row][index] = 1
				weight++
			}
		}
		corrected, err := UseHint(verificationInput, hints[row])
		if err != nil {
			return nil, attempt.burnLocked(fmt.Errorf("%w: %v", errSigningInconsistent, err))
		}
		if corrected != attempt.highBits[row] {
			return nil, attempt.burnLocked(fmt.Errorf(
				"%w: UseHint does not reproduce the committed w1", errSigningInconsistent,
			))
		}
	}
	// Public check 3: the hint weight is at most Omega.
	if weight > Omega {
		return nil, attempt.rejectLocked("hint weight")
	}
	parts := SignatureParts{Challenge: attempt.challengeSeed, Z: attempt.z, Hints: hints}
	signature, err := AssembleVerifiedMode3Signature(attempt.key, attempt.request.Message, parts)
	if err != nil {
		return nil, attempt.burnLocked(fmt.Errorf("%w: %v", errSigningInconsistent, err))
	}
	if _, err := attempt.journal.Advance(attempt.sessionID, protocol.SingleUseFinalized, signature); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningState, err)
	}
	attempt.signature = signature
	attempt.state = signingStateFinalized
	return signature, nil
}

// requireStateLocked enforces the round order. A call in a live attempt is a
// protocol violation and burns it; a terminal attempt only reports the error.
func (attempt *signingAttempt) requireStateLocked(expected signingState, operation string) error {
	if attempt.state == expected {
		return nil
	}
	return attempt.burnLocked(fmt.Errorf(
		"%w: cannot %s in state %s, want %s", errInvalidSigningState, operation, attempt.state, expected,
	))
}

// burnLocked moves a live attempt to its terminal burned state: the one-time
// record and the journal both burn, so no randomness or partial value can ever
// be reused after a rejection, an abort, or a protocol violation.
func (attempt *signingAttempt) burnLocked(cause error) error {
	if attempt.state == signingStateBurned || attempt.state == signingStateFinalized {
		return cause
	}
	if attempt.record.State() != PreprocessingBurned {
		cause = attempt.record.RejectOpening(cause)
	}
	if _, err := attempt.journal.Advance(attempt.sessionID, protocol.SingleUseBurned, nil); err != nil {
		return fmt.Errorf("%w: burning the signing journal: %v", cause, err)
	}
	attempt.state = signingStateBurned
	return cause
}

// rejectLocked burns the attempt after a legitimate rejection. The reason names
// only the predicate that rejected; no secret-derived value is published.
func (attempt *signingAttempt) rejectLocked(predicate string) error {
	return attempt.burnLocked(fmt.Errorf("%w: %s predicate", errSigningRejected, predicate))
}

// reconstructPartialSecrets sums every three-member component into the partial
// secret of the active position that owns it, and requires the three copies of
// each component to agree. The reference driver holds all active shares in one
// process; no production path may reconstruct either a partial secret or the
// aggregate secret this way.
func reconstructPartialSecrets(activeShares []*LocalShare, allocation [20]uint8) ([4]VectorL, [4]VectorK, error) {
	var partialFirst [4]VectorL
	var partialSecond [4]VectorK
	var activeIndex [6]int
	for position := range activeIndex {
		activeIndex[position] = -1
	}
	for index, share := range activeShares {
		activeIndex[share.ParticipantPosition] = index
	}
	groups := CanonicalRSSGroups()
	if len(groups) != len(allocation) {
		return [4]VectorL{}, [4]VectorK{}, fmt.Errorf(
			"%w: %d groups against %d allocations", errInvalidSigningAttempt, len(groups), len(allocation),
		)
	}
	var owners [20]int
	var owned [4]int
	for groupIndex := range allocation {
		owner := activeIndex[allocation[groupIndex]]
		if owner < 0 {
			return [4]VectorL{}, [4]VectorK{}, fmt.Errorf(
				"%w: group %06b is allocated to inactive position %d",
				errInvalidSigningAttempt, groups[groupIndex], allocation[groupIndex],
			)
		}
		owners[groupIndex] = owner
		owned[owner]++
	}
	for groupIndex, group := range groups {
		var reference *RSSComponent
		for _, share := range activeShares {
			for index := range share.Components {
				component := &share.Components[index]
				if component.GroupMask != group {
					continue
				}
				if reference == nil {
					reference = component
					continue
				}
				if *component != *reference {
					return [4]VectorL{}, [4]VectorK{}, fmt.Errorf(
						"%w: group %06b components disagree", errInvalidSigningAttempt, group,
					)
				}
			}
		}
		if reference == nil {
			return [4]VectorL{}, [4]VectorK{}, fmt.Errorf(
				"%w: group %06b has no active holder", errInvalidSigningAttempt, group,
			)
		}
		owner := owners[groupIndex]
		for row := 0; row < L; row++ {
			partialFirst[owner][row] = Add(partialFirst[owner][row], reference.S1[row])
		}
		for row := 0; row < K; row++ {
			partialSecond[owner][row] = Add(partialSecond[owner][row], reference.S2[row])
		}
	}
	for position := 0; position < 4; position++ {
		bound := owned[position] * RSSComponentEta
		for row := 0; row < L; row++ {
			if err := validatePartialBound("s1", position, row, partialFirst[position][row], bound); err != nil {
				return [4]VectorL{}, [4]VectorK{}, err
			}
		}
		for row := 0; row < K; row++ {
			if err := validatePartialBound("s2", position, row, partialSecond[position][row], bound); err != nil {
				return [4]VectorL{}, [4]VectorK{}, err
			}
		}
	}
	// Every partial must be reproducible from the owning signer's own
	// components: that is how a networked signer derives it, without ever
	// seeing another signer's material.
	for index, share := range activeShares {
		localFirst, localSecond := localPartialSecrets(share, allocation)
		if localFirst != partialFirst[index] || localSecond != partialSecond[index] {
			return [4]VectorL{}, [4]VectorK{}, fmt.Errorf(
				"%w: signer %d partial secret is not reproducible from its own components",
				errInvalidSigningAttempt, share.ParticipantID,
			)
		}
	}
	return partialFirst, partialSecond, nil
}

// localPartialSecrets sums the components one single signer holds for the
// groups allocated to its position. It is the local-only form of the reference
// reconstruction: a networked signer derives its partial secret from its own
// share, and its owned groups are exactly the allocation entries naming its
// position, each of which contains it (rss_topology.go).
func localPartialSecrets(share *LocalShare, allocation [20]uint8) (VectorL, VectorK) {
	var first VectorL
	var second VectorK
	if share == nil {
		return first, second
	}
	groups := CanonicalRSSGroups()
	for groupIndex, group := range groups {
		if groupIndex >= len(allocation) || allocation[groupIndex] != share.ParticipantPosition {
			continue
		}
		for componentIndex := range share.Components {
			component := &share.Components[componentIndex]
			if component.GroupMask != group {
				continue
			}
			for row := 0; row < L; row++ {
				first[row] = Add(first[row], component.S1[row])
			}
			for row := 0; row < K; row++ {
				second[row] = Add(second[row], component.S2[row])
			}
		}
	}
	return first, second
}

// validatePartialBound requires one partial-secret coefficient to stay inside
// the bound its owned component count implies.
func validatePartialBound(name string, position, row int, polynomial Poly, bound int) error {
	for index := 0; index < N; index++ {
		value := int64(CenteredCoefficient(polynomial[index]))
		if value < int64(-bound) || value > int64(bound) {
			return fmt.Errorf(
				"%w: partial %s[%d][%d][%d] = %d outside the bound %d",
				errInvalidSigningAttempt, name, position, row, index, value, bound,
			)
		}
	}
	return nil
}

// signingBindingDigest is the digest of every value a signing transition is
// bound to: chain, protocol, algorithm, generation, key, committee, epoch,
// slot, domain, message, attempt nonce, the four signers, the coordinator, the
// group allocation, and the session identifier.
func signingBindingDigest(
	request protocol.SignRequest,
	participantIDs [4]uint32,
	coordinatorID uint32,
	allocation [20]uint8,
	sessionID [32]byte,
) ([32]byte, error) {
	keyDigest, err := request.Key.CanonicalDigest()
	if err != nil {
		return [32]byte{}, err
	}
	committeeDigest, err := request.Committee.CanonicalDigest()
	if err != nil {
		return [32]byte{}, err
	}
	messageDigest := sha3.Sum256(request.Message)
	encoded := make([]byte, 0, 256)
	encoded = append(encoded, signingAttemptDomain...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(request.Protocol))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(request.Key.Algorithm))
	encoded = binary.BigEndian.AppendUint64(encoded, request.Key.Generation)
	encoded = append(encoded, keyDigest[:]...)
	encoded = append(encoded, committeeDigest[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, request.ChainID)
	encoded = binary.BigEndian.AppendUint64(encoded, request.Epoch)
	encoded = binary.BigEndian.AppendUint64(encoded, request.Slot)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(request.Domain))
	encoded = append(encoded, messageDigest[:]...)
	encoded = append(encoded, request.AttemptNonce[:]...)
	for _, participantID := range participantIDs {
		encoded = binary.BigEndian.AppendUint32(encoded, participantID)
	}
	encoded = binary.BigEndian.AppendUint32(encoded, coordinatorID)
	encoded = append(encoded, allocation[:]...)
	encoded = append(encoded, sessionID[:]...)
	return sha3.Sum256(encoded), nil
}

// signingMessageRepresentative computes the mode3 transcript
// tr = SHAKE256(pk)[0:32] and mu = SHAKE256(tr || message)[0:64].
func signingMessageRepresentative(key protocol.ThresholdKeyID, message []byte) ([64]byte, error) {
	shake := sha3.NewSHAKE256()
	if _, err := shake.Write(key.PublicKey); err != nil {
		return [64]byte{}, err
	}
	var transcript [TRSize]byte
	if _, err := io.ReadFull(shake, transcript[:]); err != nil {
		return [64]byte{}, err
	}
	shake.Reset()
	_, _ = shake.Write(transcript[:])
	_, _ = shake.Write(message)
	var representative [64]byte
	if _, err := io.ReadFull(shake, representative[:]); err != nil {
		return [64]byte{}, err
	}
	return representative, nil
}

// signingChallengeSeed computes c_tilde = SHAKE256(mu || EncodeHighBits(w1)).
func signingChallengeSeed(representative [64]byte, high PublicHighBits) ([CTildeSize]byte, error) {
	shake := sha3.NewSHAKE256()
	_, _ = shake.Write(representative[:])
	for row := range high.Encoded {
		_, _ = shake.Write(high.Encoded[row][:])
	}
	var seed [CTildeSize]byte
	if _, err := io.ReadFull(shake, seed[:]); err != nil {
		return [CTildeSize]byte{}, err
	}
	return seed, nil
}

// signingPreparedDigest binds the attempt, the preprocessing commitment, and
// the four rounded randomness expansions into the durable prepared payload.
func signingPreparedDigest(
	bindingDigest, recordCommitment [32]byte,
	randomness [4]*signingRandomness,
) ([32]byte, error) {
	buffer := make([]byte, 0, 64+len(randomness)*(L+K)*PolyEncodedSize)
	buffer = append(buffer, signingPreparedDomain...)
	buffer = append(buffer, bindingDigest[:]...)
	buffer = append(buffer, recordCommitment[:]...)
	for _, point := range randomness {
		for row := range point.first {
			encoded, err := EncodePoly(point.first[row])
			if err != nil {
				return [32]byte{}, err
			}
			buffer = append(buffer, encoded[:]...)
		}
		for row := range point.second {
			encoded, err := EncodePoly(point.second[row])
			if err != nil {
				return [32]byte{}, err
			}
			buffer = append(buffer, encoded[:]...)
		}
	}
	return sha3.Sum256(buffer), nil
}

// signingResponseDigest binds the attempt and the aggregate response into the
// durable responded payload. The response is public once the journal records
// it, because it is a component of the released signature.
func signingResponseDigest(bindingDigest [32]byte, aggregate [L]SignedPoly) ([32]byte, error) {
	buffer := make([]byte, 0, 64+L*ZEncodedSize)
	buffer = append(buffer, signingResponseDomain...)
	buffer = append(buffer, bindingDigest[:]...)
	for row := range aggregate {
		encoded, err := EncodeZ(aggregate[row])
		if err != nil {
			return [32]byte{}, err
		}
		buffer = append(buffer, encoded[:]...)
	}
	return sha3.Sum256(buffer), nil
}
