// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Tests of the slot schedule (design note, Slice 2): every published value of a
// slot is differentially tested against the reference driver on identical slot
// inputs, the per-slot message counts and byte sizes of the executor layer are
// pinned, and the two schedule outcomes -- an accepted slot after filtered
// candidates, and an exhausted request -- are pinned with deterministic
// request labels.

import (
	"bytes"
	"errors"
	"math"
	"math/rand"
	"testing"
)

// signingExecutorTestReferenceShift returns the reference driver's challenge
// shift for one active position, from the attempt's own stored material: the
// per-position wiring is what the differential test checks, while the reference
// driver's own aggregate response is the independent anchor.
func signingExecutorTestReferenceShift(
	t *testing.T,
	attempt *signingAttempt,
	index int,
) ([L]SignedPoly, [K]SignedPoly) {
	t.Helper()
	return signingExecutorChallengeShift(
		attempt.partialFirst[index], attempt.partialSecond[index], attempt.challengeValue,
	)
}

// TestSigningExecutorScheduleDifferentialValues requires every value the
// schedule's slots publish to match the reference driver on the same slot
// inputs: each reveal w_i, each acceptance bit, each response part z_i^(1), the
// aggregate w, w1, and challenge, and the exact 3293-byte signature. The summed
// response parts must also reproduce the reference driver's own aggregate
// response, which it computes on an independent path.
func TestSigningExecutorScheduleDifferentialValues(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	const mask = uint8(0x0F)
	request := fixture.requestFor([]byte(signingExecutorTestMessage))
	active := fixture.activeShares(t, mask)
	source := rand.New(rand.NewSource(0x5EED))
	const slots = 6
	var randomness [][4]*signingRandomness
	for slot := 1; slot <= slots; slot++ {
		randomness = append(randomness, signingTestAttemptRandomness(t, source))
	}
	// The harness sessions and the schedule interpret the same slot inputs on
	// independent journals, so their one-time sessions never collide.
	journals := signingExecutorTestJournals(t)
	scheduleJournals := signingExecutorTestJournals(t)
	candidates := make([]signingExecutorCandidate, 0, slots)
	for slot := 1; slot <= slots; slot++ {
		candidates = append(candidates, signingExecutorCandidate{
			randomness: randomness[slot-1],
			records:    signingExecutorTestRecords(t, slot),
		})
	}
	schedule, err := newSigningExecutorSchedule(request, active, scheduleJournals, candidates)
	if err != nil {
		t.Fatalf("newSigningExecutorSchedule(): %v", err)
	}
	accepted := 0
	for slot := 1; slot <= slots; slot++ {
		slotRequest := signingExecutorSlotRequest(request, uint16(slot))
		attempt, referenceAccepted := signingExecutorTestReference(
			t, journal, slotRequest, active, uint16(slot), randomness[slot-1],
		)
		session, err := newSigningExecutorSession(
			slotRequest, active, uint16(slot), signingExecutorTestMaterial(t, slot, randomness[slot-1], journals),
		)
		if err != nil {
			t.Fatalf("slot %d: newSigningExecutorSession(): %v", slot, err)
		}
		if err := session.start(); err != nil {
			t.Fatalf("slot %d: start(): %v", slot, err)
		}
		run := signingExecutorTestDrive(t, session, signingExecutorTestCleanRoute(session))
		for _, deliveryErr := range run.errors {
			// A combine check that fails on the last response delivery is a
			// legitimate filter outcome of the slot, not a routing fault.
			reason, bounded := signingExecutorReasonOf(deliveryErr)
			if !bounded || reason != SigningExecutorReasonCombineCheck {
				t.Fatalf("slot %d: honest run returned %v", slot, deliveryErr)
			}
		}
		signature, err := session.finish()
		scheduleSignature, _, emitted, scheduleErr := schedule.runSlot(uint16(slot))
		if referenceAccepted != (scheduleErr == nil) {
			t.Fatalf("slot %d: the schedule and the reference disagree on the decision: %v", slot, scheduleErr)
		}
		recorded := 0
		for _, envelopes := range run.outbound {
			recorded += len(envelopes)
		}
		if emitted != recorded {
			t.Fatalf("slot %d: schedule counted %d messages, the harness recorded %d", slot, emitted, recorded)
		}
		var (
			bits     [4]bool
			parts    [4][L]SignedPoly
			partsSum [L]SignedPoly
		)
		for index, signer := range session.signers {
			envelopes := run.outbound[signer.participantID]
			if len(envelopes) != 3 && len(envelopes) != 4 {
				t.Fatalf("slot %d signer %d published %d messages, want 3 or 4", slot, signer.participantID, len(envelopes))
			}
			if envelopes[0].Kind != SigningExecutorKindCommit ||
				envelopes[1].Kind != SigningExecutorKindReveal ||
				envelopes[2].Kind != SigningExecutorKindAcceptance {
				t.Fatalf("slot %d signer %d published an unexpected message sequence", slot, signer.participantID)
			}
			revealSlot, contribution, err := DecodeSigningExecutorReveal(envelopes[1].Payload)
			if err != nil || revealSlot != uint16(slot) {
				t.Fatalf("slot %d signer %d reveal: slot=%d err=%v", slot, signer.participantID, revealSlot, err)
			}
			if contribution != attempt.contributions[index] {
				t.Fatalf("slot %d signer %d reveal differs from the reference share", slot, signer.participantID)
			}
			_, bit, err := DecodeSigningExecutorAcceptance(envelopes[2].Payload)
			if err != nil {
				t.Fatalf("slot %d signer %d acceptance: %v", slot, signer.participantID, err)
			}
			bits[index] = bit
			shiftFirst, shiftSecond := signingExecutorTestReferenceShift(t, attempt, index)
			wantBit, err := signingRejectionTest(attempt.randomness[index], shiftFirst, shiftSecond)
			if err != nil {
				t.Fatalf("slot %d signer %d reference rejection test: %v", slot, signer.participantID, err)
			}
			if bit != wantBit {
				t.Fatalf("slot %d signer %d acceptance bit %v, want %v", slot, signer.participantID, bit, wantBit)
			}
			if len(envelopes) == 4 {
				responseSlot, part, err := DecodeSigningExecutorResponse(envelopes[3].Payload)
				if err != nil || responseSlot != uint16(slot) {
					t.Fatalf("slot %d signer %d response: slot=%d err=%v", slot, signer.participantID, responseSlot, err)
				}
				if wantPart := signingResponsePart(attempt.randomness[index], shiftFirst); part != wantPart {
					t.Fatalf("slot %d signer %d response part differs from the reference", slot, signer.participantID)
				}
				parts[index] = part
			}
		}
		// A response part is released only when every acceptance bit is true, so
		// the published bit vector decides the message count of the slot.
		responses := bits[0] && bits[1] && bits[2] && bits[3]
		for index, signer := range session.signers {
			wantCount := 3
			if responses {
				wantCount = 4
			}
			if len(run.outbound[signer.participantID]) != wantCount {
				t.Fatalf("slot %d signer %d published %d messages, want %d", slot, signer.participantID, len(run.outbound[signer.participantID]), wantCount)
			}
			if !responses {
				continue
			}
			for row := 0; row < L; row++ {
				for coefficient := 0; coefficient < N; coefficient++ {
					partsSum[row][coefficient] += parts[index][row][coefficient]
				}
			}
		}
		if responses && partsSum != attempt.z {
			t.Fatalf("slot %d: summed response parts differ from the reference aggregate", slot)
		}
		if !referenceAccepted {
			if !errors.Is(scheduleErr, errSigningRejected) && !errors.Is(scheduleErr, errSigningExecutorCombine) {
				t.Fatalf("slot %d: filtered slot aborted with %v", slot, scheduleErr)
			}
			continue
		}
		accepted++
		if !bytes.Equal(signature, attempt.signature) {
			t.Fatalf("slot %d: session signature differs from the reference driver", slot)
		}
		if !bytes.Equal(scheduleSignature, attempt.signature) {
			t.Fatalf("slot %d: schedule signature differs from the reference driver", slot)
		}
		for _, signer := range session.signers {
			if signer.w != attempt.w {
				t.Fatalf("slot %d: aggregate w differs from the reference", slot)
			}
			if signer.highBits != attempt.highBits {
				t.Fatalf("slot %d: w1 differs from the reference", slot)
			}
			if signer.seed != attempt.challengeSeed {
				t.Fatalf("slot %d: challenge differs from the reference", slot)
			}
		}
	}
	if accepted == 0 {
		t.Fatal("the deterministic slot inputs covered no accepted slot")
	}
}

// signingExecutorTestSchedule builds one deterministic J-slot schedule for a
// request label: the per-slot randomness comes from one stream, the way the
// reference rejection loop draws it, and the request nonce carries the label.
func signingExecutorTestSchedule(
	t *testing.T,
	fixture *signingTestFixture,
	label int64,
) *signingExecutorSchedule {
	t.Helper()
	request := fixture.requestFor([]byte(signingExecutorTestMessage))
	request.AttemptNonce[2] = byte(label)
	request.AttemptNonce[3] = byte(label >> 8)
	active := fixture.activeShares(t, 0x0F)
	journals := signingExecutorTestJournals(t)
	source := rand.New(rand.NewSource(label))
	candidates := make([]signingExecutorCandidate, 0, SigningParallelSlots)
	for slot := 1; slot <= SigningParallelSlots; slot++ {
		candidates = append(candidates, signingExecutorCandidate{
			randomness: signingTestAttemptRandomness(t, source),
			records:    signingExecutorTestRecords(t, slot),
		})
	}
	schedule, err := newSigningExecutorSchedule(request, active, journals, candidates)
	if err != nil {
		t.Fatalf("label %d: newSigningExecutorSchedule(): %v", label, err)
	}
	return schedule
}

// TestSigningExecutorScheduleCounts pins the executor layer's message counts
// and byte sizes per slot, the J-slot request probability, and the two schedule
// outcomes: an accepted slot after filtered candidates, and an exhausted
// request.
func TestSigningExecutorScheduleCounts(t *testing.T) {
	filteredBytes := signingExecutorCommitEncodedSize + signingExecutorRevealEncodedSize +
		signingExecutorAcceptanceEncodedSize
	if filteredBytes != 4671 {
		t.Fatalf("filtered slot bytes per signer = %d, want 4671", filteredBytes)
	}
	acceptedBytes := filteredBytes + signingExecutorResponseEncodedSize
	if acceptedBytes != 7881 {
		t.Fatalf("accepted slot bytes per signer = %d, want 7881", acceptedBytes)
	}
	if SigningParallelSlots != 11 {
		t.Fatalf("parallel slots = %d, want 11", SigningParallelSlots)
	}
	perSlot := math.Pow(2, -SigningRandomnessExponent)
	if success := 1 - math.Pow(1-perSlot, SigningParallelSlots); success < 0.5 {
		t.Fatalf("J-slot success probability %.4f is below 1/2", success)
	}

	fixture := signingTestFixtureFor(t)
	var acceptedOutcomes []signingExecutorSlotOutcome
	for label := int64(1); label <= 8 && acceptedOutcomes == nil; label++ {
		signature, outcomes, err := signingExecutorTestSchedule(t, fixture, label).run()
		if err != nil {
			continue
		}
		if len(signature) != 3293 {
			t.Fatalf("label %d: signature length %d, want 3293", label, len(signature))
		}
		acceptedOutcomes = outcomes
	}
	if acceptedOutcomes == nil {
		t.Fatal("no accepted schedule in 8 deterministic candidates")
	}
	for index, outcome := range acceptedOutcomes {
		if index == len(acceptedOutcomes)-1 {
			if !outcome.Accepted || outcome.Emitted != 16 {
				t.Fatalf("accepted slot %d: accepted=%v emitted=%d, want accepted with 16 messages", outcome.Slot, outcome.Accepted, outcome.Emitted)
			}
			continue
		}
		if outcome.Accepted {
			t.Fatal("an accepted slot preceded the final schedule outcome")
		}
		switch outcome.Reason {
		case SigningExecutorReasonLocalRejection:
			if outcome.Emitted != 12 {
				t.Fatalf("local-rejected slot %d emitted %d messages, want 12", outcome.Slot, outcome.Emitted)
			}
		case SigningExecutorReasonCombineCheck:
			// Every local test passed, so every signer published a response part
			// before the public combine checks filtered the slot.
			if outcome.Emitted != 16 {
				t.Fatalf("combine-filtered slot %d emitted %d messages, want 16", outcome.Slot, outcome.Emitted)
			}
		default:
			t.Fatalf("filtered slot %d: reason %s", outcome.Slot, outcome.Reason)
		}
	}

	exhausted := false
	for label := int64(0x100); label <= 0x110 && !exhausted; label++ {
		_, outcomes, err := signingExecutorTestSchedule(t, fixture, label).run()
		if !errors.Is(err, errSigningExecutorScheduleExhausted) {
			continue
		}
		exhausted = true
		if len(outcomes) != SigningParallelSlots {
			t.Fatalf("exhausted request reported %d outcomes, want %d", len(outcomes), SigningParallelSlots)
		}
		for _, outcome := range outcomes {
			if outcome.Accepted {
				t.Fatalf("exhausted slot %d: accepted", outcome.Slot)
			}
			wantEmitted := 12
			if outcome.Reason == SigningExecutorReasonCombineCheck {
				wantEmitted = 16
			} else if outcome.Reason != SigningExecutorReasonLocalRejection {
				t.Fatalf("exhausted slot %d: reason %s", outcome.Slot, outcome.Reason)
			}
			if outcome.Emitted != wantEmitted {
				t.Fatalf("exhausted slot %d: emitted=%d, want %d", outcome.Slot, outcome.Emitted, wantEmitted)
			}
		}
	}
	if !exhausted {
		t.Fatal("no exhausted request in 17 deterministic candidates")
	}
}

// TestSigningExecutorScheduleRejectsMalformedInput requires the schedule to
// refuse an empty candidate list, more candidates than the schedule bounds, and
// a malformed slot probe.
func TestSigningExecutorScheduleRejectsMalformedInput(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	request := fixture.requestFor([]byte(signingExecutorTestMessage))
	active := fixture.activeShares(t, 0x0F)
	randomness := signingTestRandomnessFor(t, 0x71)
	journals := signingExecutorTestJournals(t)
	candidate := signingExecutorCandidate{randomness: randomness, records: signingExecutorTestRecords(t, 1)}
	if _, err := newSigningExecutorSchedule(request, active, journals, nil); !errors.Is(err, errInvalidSigningAttempt) {
		t.Fatalf("empty candidates: error = %v", err)
	}
	tooMany := make([]signingExecutorCandidate, SigningParallelSlots+1)
	for index := range tooMany {
		tooMany[index] = candidate
	}
	if _, err := newSigningExecutorSchedule(request, active, journals, tooMany); !errors.Is(err, errInvalidSigningAttempt) {
		t.Fatalf("too many candidates: error = %v", err)
	}
	missingJournal := journals
	missingJournal[1] = nil
	if _, err := newSigningExecutorSchedule(
		request, active, missingJournal, []signingExecutorCandidate{candidate},
	); !errors.Is(err, errInvalidSigningAttempt) {
		t.Fatalf("missing journal: error = %v", err)
	}
	schedule, err := newSigningExecutorSchedule(request, active, journals, []signingExecutorCandidate{candidate})
	if err != nil {
		t.Fatalf("newSigningExecutorSchedule(): %v", err)
	}
	if _, _, _, err := schedule.runSlot(0); !errors.Is(err, errInvalidSigningAttempt) {
		t.Fatalf("zero slot probe: error = %v", err)
	}
	if _, _, _, err := schedule.runSlot(2); !errors.Is(err, errInvalidSigningAttempt) {
		t.Fatalf("out-of-range slot probe: error = %v", err)
	}
	if _, err := newSigningExecutorSchedule(
		request, active[:3], journals, []signingExecutorCandidate{candidate},
	); !errors.Is(err, errInvalidSigningAttempt) {
		t.Fatalf("three shares: error = %v", err)
	}
}
