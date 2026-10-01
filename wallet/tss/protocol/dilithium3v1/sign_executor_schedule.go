// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// This file is the slot schedule of the in-process signing executor (design
// note, Slice 2). One signing request runs up to SigningParallelSlots candidate
// slots, each slot being one session with its own committed randomness and its
// own request nonce, until one slot produces the signature. A slot that ends in
// a local rejection or a failed public combine check is a normal filter outcome
// and the schedule moves on to the next candidate; any other abort ends the
// request. The candidates run sequentially here; a networked deployment may
// submit them concurrently, but the schedule and its per-slot counts are
// unchanged.
//
// Like the rest of the executor this is an unexported reference layer: the node
// wiring slice owns the exported entry point and the network transport. Each
// candidate carries the four signers' one-time records over the request-long
// journals, and every candidate that does not end in a signature burns them
// (design note, Slice 3).

import (
	"errors"
	"fmt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// errSigningExecutorScheduleExhausted reports a request whose candidate slots
// all failed their filters: the caller retries with a new request and fresh
// randomness, never with the same slot material.
var errSigningExecutorScheduleExhausted = errors.New("Dilithium3 v1 signing executor schedule exhausted")

// signingExecutorSlotRequest returns the slot's request: the base request with
// the first two attempt-nonce bytes bound to the one-based slot index, the
// reference driver's own convention. The nonce is bound into the signing
// session identifier, so every slot is its own session.
func signingExecutorSlotRequest(request protocol.SignRequest, slot uint16) protocol.SignRequest {
	slotRequest := request.Clone()
	slotRequest.AttemptNonce[0] = byte(slot)
	slotRequest.AttemptNonce[1] = byte(slot >> 8)
	return slotRequest
}

// signingExecutorSlotOutcome records one candidate slot: whether it produced
// the signature, the bounded reason of a filtered slot, and how many messages
// the four signers emitted in it.
type signingExecutorSlotOutcome struct {
	Slot     uint16
	Accepted bool
	Reason   SigningExecutorReason
	Emitted  int
}

// signingExecutorCandidate is one candidate slot's one-time material: the four
// ball points and the four one-time records. The journals live across the whole
// request, one per signer; each record is consumed by at most one candidate.
type signingExecutorCandidate struct {
	randomness [4]*signingRandomness
	records    [4]*PreprocessingRecord
}

// signingExecutorSchedule drives one signing request across its candidate
// slots.
type signingExecutorSchedule struct {
	request    protocol.SignRequest
	active     []*LocalShare
	journals   [4]*SigningJournal
	candidates []signingExecutorCandidate
}

// signingExecutorCandidateMaterial assembles one candidate's per-signer session
// material out of the request-long journals and the candidate's own records.
func signingExecutorCandidateMaterial(
	journals [4]*SigningJournal,
	candidate signingExecutorCandidate,
) [4]signingExecutorSlotMaterial {
	var material [4]signingExecutorSlotMaterial
	for index := range material {
		material[index] = signingExecutorSlotMaterial{
			randomness: candidate.randomness[index],
			journal:    journals[index],
			record:     candidate.records[index],
		}
	}
	return material
}

// newSigningExecutorSchedule validates the request, the active set, the
// journals, and the candidate material, and returns the schedule. The material
// is caller-supplied for the same reason as in the session constructor: a
// deployment samples each ball point and binds each one-time record inside its
// own signer process.
func newSigningExecutorSchedule(
	request protocol.SignRequest,
	activeShares []*LocalShare,
	journals [4]*SigningJournal,
	candidates []signingExecutorCandidate,
) (*signingExecutorSchedule, error) {
	if len(candidates) == 0 || len(candidates) > SigningParallelSlots {
		return nil, fmt.Errorf(
			"%w: %d candidate slots, want [1, %d]", errInvalidSigningAttempt, len(candidates), SigningParallelSlots,
		)
	}
	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSigningAttempt, err)
	}
	for index := range journals {
		if journals[index] == nil {
			return nil, fmt.Errorf("%w: signer %d journal is missing", errInvalidSigningAttempt, index)
		}
	}
	// The first slot validates the whole binding; every later slot differs only
	// in the attempt nonce, which the session constructor derives again.
	if _, err := newSigningExecutorSession(
		signingExecutorSlotRequest(request, 1), activeShares, 1,
		signingExecutorCandidateMaterial(journals, candidates[0]),
	); err != nil {
		return nil, err
	}
	return &signingExecutorSchedule{
		request:    request.Clone(),
		active:     append([]*LocalShare(nil), activeShares...),
		journals:   journals,
		candidates: candidates,
	}, nil
}

// run drives the candidate slots in order and returns the signature together
// with every slot outcome up to and including the accepted one. A request whose
// candidates all filter out reports errSigningExecutorScheduleExhausted with
// all of the outcomes.
func (schedule *signingExecutorSchedule) run() ([]byte, []signingExecutorSlotOutcome, error) {
	if schedule == nil {
		return nil, nil, errInvalidSigningAttempt
	}
	outcomes := make([]signingExecutorSlotOutcome, 0, len(schedule.candidates))
	for index := range schedule.candidates {
		slot := uint16(index + 1)
		signature, _, emitted, err := schedule.runSlot(slot)
		if err == nil {
			outcomes = append(outcomes, signingExecutorSlotOutcome{Slot: slot, Accepted: true, Emitted: emitted})
			return signature, outcomes, nil
		}
		reason, bounded := signingExecutorReasonOf(err)
		if !bounded || (reason != SigningExecutorReasonLocalRejection && reason != SigningExecutorReasonCombineCheck) {
			return nil, outcomes, err
		}
		outcomes = append(outcomes, signingExecutorSlotOutcome{Slot: slot, Reason: reason, Emitted: emitted})
	}
	return nil, outcomes, fmt.Errorf(
		"%w: %d candidate slots all filtered", errSigningExecutorScheduleExhausted, len(outcomes),
	)
}

// runSlot drives one candidate slot with honest broadcast routing and reports
// the signature, the session, and the message count.
func (schedule *signingExecutorSchedule) runSlot(slot uint16) ([]byte, *signingExecutorSession, int, error) {
	if slot == 0 || int(slot) > len(schedule.candidates) {
		return nil, nil, 0, fmt.Errorf(
			"%w: slot %d outside the schedule", errInvalidSigningAttempt, slot,
		)
	}
	session, err := newSigningExecutorSession(
		signingExecutorSlotRequest(schedule.request, slot), schedule.active, slot,
		signingExecutorCandidateMaterial(schedule.journals, schedule.candidates[slot-1]),
	)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := session.start(); err != nil {
		return nil, session, 0, err
	}
	signature, emitted, err := signingExecutorPump(session)
	return signature, session, emitted, err
}

// signingExecutorPump carries every message of one session to the other three
// receivers until the signers are quiescent, and reports the signature and the
// number of messages the four signers emitted. It is the honest coordinator of
// the in-process schedule; the adversarial harness drives the same session API
// with its own routing.
func signingExecutorPump(session *signingExecutorSession) ([]byte, int, error) {
	emitted := 0
	for {
		batch := session.drain()
		if len(batch) == 0 {
			break
		}
		emitted += len(batch)
		for _, envelope := range batch {
			for target, identity := range session.policy.Signers {
				if identity == envelope.Sender {
					continue
				}
				if err := session.deliverTo(target, envelope); err != nil {
					return nil, emitted, err
				}
			}
		}
	}
	signature, err := session.finish()
	return signature, emitted, err
}
