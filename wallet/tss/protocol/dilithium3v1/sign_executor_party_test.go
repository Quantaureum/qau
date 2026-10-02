// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Tests of the exported per-signer party surface (design note, Slice 4): a
// party built from one share must behave byte for byte like the in-process
// executor session -- and therefore like the reference driver the session is
// pinned against -- on identical slot inputs, must refuse unauthorized network
// noise without ending a healthy slot, and must consume its one-time material
// on every outcome that is not a signature.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// signingExecutorPartyTestIdentities returns the four active identities in
// canonical order.
func signingExecutorPartyTestIdentities(active []*LocalShare) []uint32 {
	identities := make([]uint32, len(active))
	for index, share := range active {
		identities[index] = share.ParticipantID
	}
	return identities
}

// signingExecutorPartyTestConfig returns the config of one party with the given
// per-signer material.
func signingExecutorPartyTestConfig(
	fixture *signingTestFixture,
	active []*LocalShare,
	index int,
	slot uint16,
	journal *SigningJournal,
	record *PreprocessingRecord,
) SigningExecutorPartyConfig {
	return SigningExecutorPartyConfig{
		Request: signingExecutorTestRequest(fixture, slot),
		Share:   active[index],
		Signers: signingExecutorPartyTestIdentities(active),
		Slot:    slot,
		Journal: journal,
		Record:  record,
	}
}

// signingExecutorPartyTestParties builds the four parties of one slot from the
// caller's journals and records, with the ball points pinned so the run can be
// compared against the in-process references byte for byte.
func signingExecutorPartyTestParties(
	t *testing.T,
	fixture *signingTestFixture,
	mask uint8,
	slot uint16,
	randomness []*signingRandomness,
	journals []*SigningJournal,
	records []*PreprocessingRecord,
) []*SigningExecutorParty {
	t.Helper()
	active := fixture.activeShares(t, mask)
	params, err := SigningParametersForParticipants(len(fixture.shares[0].Committee.Participants))
	if err != nil {
		t.Fatal(err)
	}
	parties := make([]*SigningExecutorParty, len(active))
	for index := range parties {
		party, err := newSigningExecutorParty(
			signingExecutorPartyTestConfig(fixture, active, index, slot, journals[index], records[index]),
			params,
			randomness[index],
		)
		if err != nil {
			t.Fatalf("slot %d signer %d: newSigningExecutorParty(): %v", slot, index, err)
		}
		parties[index] = party
	}
	return parties
}

// signingExecutorPartyTestRecord is one emitted round message in comparison
// form.
type signingExecutorPartyTestRecord struct {
	kind    uint16
	payload []byte
}

// signingExecutorPartyTestPump broadcasts every queued message of every party
// to the other three until the parties are quiescent. A party whose delivery
// returned a fatal outcome is skipped from then on, mirroring the in-process
// harness, whose drive stops at the first fatal delivery. It returns every
// emitted message by sender and every delivery failure.
func signingExecutorPartyTestPump(
	t *testing.T,
	parties []*SigningExecutorParty,
	identities []uint32,
) (map[uint32][]signingExecutorPartyTestRecord, []error) {
	t.Helper()
	emitted := make(map[uint32][]signingExecutorPartyTestRecord)
	var failures []error
	stopped := make([]bool, len(parties))
	for {
		batches := make([][]SigningExecutorRoundMessage, len(parties))
		quiet := true
		for index := range parties {
			batches[index] = parties[index].Drain()
			if len(batches[index]) > 0 {
				quiet = false
			}
		}
		if quiet {
			return emitted, failures
		}
		for source := range parties {
			for _, message := range batches[source] {
				emitted[identities[source]] = append(emitted[identities[source]], signingExecutorPartyTestRecord{
					kind:    message.Kind,
					payload: message.Payload,
				})
				for target := range parties {
					if target == source || stopped[target] {
						continue
					}
					err := parties[target].Deliver(identities[source], message.Kind, message.Payload)
					if err == nil {
						continue
					}
					failures = append(failures, err)
					if outcome, ok := SigningExecutorOutcomeOf(err); ok && outcome.Fatal {
						stopped[target] = true
					}
				}
			}
		}
	}
}

// signingExecutorPartyTestCount returns how many messages of one kind one
// sender emitted.
func signingExecutorPartyTestCount(
	emitted map[uint32][]signingExecutorPartyTestRecord,
	sender uint32,
	kind uint16,
) int {
	count := 0
	for _, record := range emitted[sender] {
		if record.kind == kind {
			count++
		}
	}
	return count
}

// signingExecutorPartyTestCompare requires the party run to have emitted
// exactly the session's messages: the same senders, the same kinds, and the
// same payloads in the same per-sender order.
func signingExecutorPartyTestCompare(
	t *testing.T,
	slot int,
	run *signingExecutorTestRun,
	emitted map[uint32][]signingExecutorPartyTestRecord,
	identities []uint32,
) {
	t.Helper()
	if len(run.outbound) != len(emitted) {
		t.Fatalf("slot %d: parties emitted for %d senders, session for %d", slot, len(emitted), len(run.outbound))
	}
	for _, sender := range identities {
		want := run.outbound[sender]
		got := emitted[sender]
		if len(want) != len(got) {
			t.Fatalf("slot %d sender %d: parties emitted %d messages, session %d", slot, sender, len(got), len(want))
		}
		for index := range want {
			if want[index].Kind != got[index].kind || !bytes.Equal(want[index].Payload, got[index].payload) {
				t.Fatalf("slot %d sender %d message %d: payload differs from the session", slot, sender, index)
			}
		}
	}
}

// TestSigningExecutorPartyMatchesInProcessExecutor drives the four exported
// parties of one slot and the in-process executor session over identical slot
// inputs -- the same request, shares, and ball points, with separate journals
// and records because both are single-use -- and requires byte-identical
// emissions per sender, the same outcome class, and, for an accepted slot, the
// same 3293-byte signature as the reference driver.
func TestSigningExecutorPartyMatchesInProcessExecutor(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	const mask = uint8(0x0F)
	active := fixture.activeShares(t, mask)
	identities := signingExecutorPartyTestIdentities(active)
	referenceJournal := signingTestJournal(t)
	sessionJournals := signingExecutorTestJournals(t)
	partyJournals := signingExecutorTestJournals(t)
	accepted := 0
	rejected := 0
	for slot := 1; slot <= 24 && (accepted == 0 || rejected == 0); slot++ {
		slotIndex := uint16(slot)
		randomness := signingExecutorTestRandomness(t, int64(0xE700+slot*73))
		request := signingExecutorTestRequest(fixture, slotIndex)
		attempt, referenceAccepted := signingExecutorTestReference(
			t, referenceJournal, request, active, slotIndex, randomness,
		)

		session, err := newSigningExecutorSession(
			request, active, slotIndex, signingExecutorTestMaterial(t, slot, randomness, sessionJournals),
		)
		if err != nil {
			t.Fatalf("slot %d: newSigningExecutorSession(): %v", slot, err)
		}
		if err := session.start(); err != nil {
			t.Fatalf("slot %d: session start(): %v", slot, err)
		}
		sessionRun := signingExecutorTestDrive(t, session, signingExecutorTestCleanRoute(session))
		sessionSignature, sessionErr := session.finish()

		records := signingExecutorTestRecords(t, slot)
		parties := signingExecutorPartyTestParties(t, fixture, mask, slotIndex, randomness, partyJournals, records)
		for index, party := range parties {
			if err := party.Start(); err != nil {
				t.Fatalf("slot %d signer %d: party Start(): %v", slot, index, err)
			}
			if got := party.SessionID(); got != session.policy.SessionID {
				t.Fatalf("slot %d signer %d: session %x, want %x", slot, index, got, session.policy.SessionID)
			}
		}
		emitted, failures := signingExecutorPartyTestPump(t, parties, identities)
		for _, failure := range failures {
			// A combine check that fails on the last response delivery is a
			// legitimate filter outcome of the slot, not a routing fault.
			outcome, ok := SigningExecutorOutcomeOf(failure)
			if !ok || outcome.Reason != SigningExecutorReasonCombineCheck {
				t.Fatalf("slot %d: honest party routing returned %v", slot, failure)
			}
		}
		for index, party := range parties {
			signature, err := party.Finish()
			if referenceAccepted {
				if err != nil {
					t.Fatalf("slot %d signer %d: accepted by the reference but aborted: %v", slot, index, err)
				}
				if !bytes.Equal(signature, attempt.signature) {
					t.Fatalf("slot %d signer %d: signature differs from the reference driver", slot, index)
				}
				if !bytes.Equal(signature, sessionSignature) {
					t.Fatalf("slot %d signer %d: signature differs from the in-process session", slot, index)
				}
				continue
			}
			if err == nil {
				t.Fatalf("slot %d signer %d: rejected by the reference but produced a signature", slot, index)
			}
			outcome, ok := SigningExecutorOutcomeOf(err)
			if !ok {
				t.Fatalf("slot %d signer %d: rejected slot aborted with %v", slot, index, err)
			}
			sessionOutcome, ok := SigningExecutorOutcomeOf(sessionErr)
			if !ok || sessionOutcome.Reason != outcome.Reason {
				t.Fatalf("slot %d signer %d: party reason %s, session reason %v", slot, index, outcome.Reason, sessionErr)
			}
			switch outcome.Reason {
			case SigningExecutorReasonLocalRejection:
				// A locally rejected slot publishes no response part at all.
				if got := signingExecutorPartyTestCount(emitted, identities[index], SigningExecutorKindResponse); got != 0 {
					t.Fatalf("slot %d signer %d: rejected slot emitted %d response parts", slot, index, got)
				}
			case SigningExecutorReasonCombineCheck:
				// Every signer accepted locally, so every response part was
				// published before the public combine checks filtered the slot.
				if got := signingExecutorPartyTestCount(emitted, identities[index], SigningExecutorKindResponse); got != 1 {
					t.Fatalf("slot %d signer %d: combine-filtered slot emitted %d response parts, want 1", slot, index, got)
				}
			default:
				t.Fatalf("slot %d signer %d: rejected slot aborted with %s", slot, index, outcome.Reason)
			}
		}
		signingExecutorPartyTestCompare(t, slot, sessionRun, emitted, identities)
		if referenceAccepted {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("covered %d accepted and %d rejected slots; both classes are required", accepted, rejected)
	}
}

// signingExecutorPartyTestAcceptedSlot scans deterministic slots until the
// reference driver accepts one.
func signingExecutorPartyTestAcceptedSlot(
	t *testing.T,
	fixture *signingTestFixture,
	active []*LocalShare,
) (uint16, []*signingRandomness) {
	t.Helper()
	journal := signingTestJournal(t)
	for slot := 1; slot <= 128; slot++ {
		randomness := signingExecutorTestRandomness(t, int64(0xA100+slot*59))
		if _, accepted := signingExecutorTestReference(
			t, journal, signingExecutorTestRequest(fixture, uint16(slot)), active, uint16(slot), randomness,
		); accepted {
			return uint16(slot), randomness
		}
	}
	t.Fatal("no accepted slot in 128 deterministic candidates")
	return 0, nil
}

// TestSigningExecutorPartyRefusesUnauthorizedNoise requires refused
// unauthorized messages to leave a healthy slot running: a forged sender and a
// malformed payload of an active sender are both bounded, non-fatal refusals,
// and the slot still completes with the reference signature.
func TestSigningExecutorPartyRefusesUnauthorizedNoise(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	const mask = uint8(0x0F)
	active := fixture.activeShares(t, mask)
	identities := signingExecutorPartyTestIdentities(active)
	slot, randomness := signingExecutorPartyTestAcceptedSlot(t, fixture, active)
	attempt, accepted := signingExecutorTestReference(
		t, signingTestJournal(t), signingExecutorTestRequest(fixture, slot), active, slot, randomness,
	)
	if !accepted {
		t.Fatalf("slot %d: the reference driver rejects the scanned accepted slot", slot)
	}
	journals := signingExecutorTestJournals(t)
	records := signingExecutorTestRecords(t, int(slot))
	parties := signingExecutorPartyTestParties(t, fixture, mask, slot, randomness, journals, records)
	for index, party := range parties {
		if err := party.Start(); err != nil {
			t.Fatalf("signer %d: Start(): %v", index, err)
		}
	}

	// A committee member outside the active set is a forged sender.
	foreign := fixture.shares[4].ParticipantID
	payload, err := EncodeSigningExecutorCommit(slot, [32]byte{0x11})
	if err != nil {
		t.Fatalf("EncodeSigningExecutorCommit(): %v", err)
	}
	outcome, ok := SigningExecutorOutcomeOf(parties[1].Deliver(foreign, SigningExecutorKindCommit, payload))
	if !ok || outcome.Reason != SigningExecutorReasonUnauthorized || outcome.Fatal {
		t.Fatalf("forged sender: outcome %+v, ok=%v", outcome, ok)
	}
	if outcome.Evidence.ParticipantID != foreign {
		t.Fatalf("forged sender: evidence names %d, want %d", outcome.Evidence.ParticipantID, foreign)
	}
	// A malformed payload from an active sender is refused before the gate, so
	// it cannot claim the sender's replay key.
	outcome, ok = SigningExecutorOutcomeOf(parties[2].Deliver(identities[0], SigningExecutorKindReveal, []byte("junk")))
	if !ok || outcome.Reason != SigningExecutorReasonUnauthorized || outcome.Fatal {
		t.Fatalf("malformed payload: outcome %+v, ok=%v", outcome, ok)
	}

	_, failures := signingExecutorPartyTestPump(t, parties, identities)
	if len(failures) != 0 {
		t.Fatalf("healthy slot returned delivery failures: %v", failures)
	}
	for index, party := range parties {
		signature, err := party.Finish()
		if err != nil {
			t.Fatalf("signer %d: Finish(): %v", index, err)
		}
		if !bytes.Equal(signature, attempt.signature) {
			t.Fatalf("signer %d: signature differs from the reference driver", index)
		}
	}
}

// TestSigningExecutorPartySingleUseIsTerminal requires the party's durable
// lifecycle to end in a terminal state on both outcome classes: finalized for
// an accepted slot and burned for a rejected one, with the one-time record
// consumed in both cases. A consumed record then refuses a second slot even
// with a fresh journal, and a finished session entry refuses a replay even with
// a fresh record.
func TestSigningExecutorPartySingleUseIsTerminal(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	const mask = uint8(0x0F)
	active := fixture.activeShares(t, mask)
	identities := signingExecutorPartyTestIdentities(active)
	journals := signingExecutorTestJournals(t)
	accepted := 0
	rejected := 0
	for slot := 1; slot <= 24 && (accepted == 0 || rejected == 0); slot++ {
		slotIndex := uint16(slot)
		randomness := signingExecutorTestRandomness(t, int64(0xDD00+slot*41))
		records := signingExecutorTestRecords(t, slot)
		parties := signingExecutorPartyTestParties(t, fixture, mask, slotIndex, randomness, journals, records)
		for index, party := range parties {
			if err := party.Start(); err != nil {
				t.Fatalf("slot %d signer %d: Start(): %v", slot, index, err)
			}
		}
		_, _ = signingExecutorPartyTestPump(t, parties, identities)
		signature, err := parties[0].Finish()
		wantState := protocol.SingleUseBurned
		if err == nil {
			if len(signature) != 3293 {
				t.Fatalf("slot %d: signature length %d, want 3293", slot, len(signature))
			}
			accepted++
			wantState = protocol.SingleUseFinalized
		} else {
			outcome, ok := SigningExecutorOutcomeOf(err)
			if !ok || (outcome.Reason != SigningExecutorReasonLocalRejection &&
				outcome.Reason != SigningExecutorReasonCombineCheck) {
				t.Fatalf("slot %d: rejected slot aborted with %v", slot, err)
			}
			rejected++
		}
		for index, party := range parties {
			entry, found, readErr := journals[index].Read(party.SessionID())
			if readErr != nil || !found {
				t.Fatalf("slot %d signer %d: journal read: found=%v err=%v", slot, index, found, readErr)
			}
			if entry.State != wantState {
				t.Fatalf("slot %d signer %d: journal state %d, want %d", slot, index, entry.State, wantState)
			}
			if state := records[index].State(); state != PreprocessingBurned {
				t.Fatalf("slot %d signer %d: record state %d, want burned", slot, index, state)
			}
			if index == 0 {
				continue
			}
			other, otherErr := party.Finish()
			if (otherErr == nil) != (err == nil) {
				t.Fatalf("slot %d signer %d: outcome class %v, want %v", slot, index, otherErr, err)
			}
			if otherErr == nil && !bytes.Equal(other, signature) {
				t.Fatalf("slot %d signer %d: signature differs from signer 0", slot, index)
			}
		}
		params, pErr := SigningParametersForParticipants(len(active[0].Committee.Participants))
		if pErr != nil {
			t.Fatal(pErr)
		}
		reuse, err := newSigningExecutorParty(
			signingExecutorPartyTestConfig(fixture, active, 0, slotIndex, signingTestJournal(t), records[0]),
			params,
			randomness[0],
		)
		if err != nil {
			t.Fatalf("slot %d: reuse party construction: %v", slot, err)
		}
		if err := reuse.Start(); !errors.Is(err, errInvalidSigningAttempt) {
			t.Fatalf("slot %d: record reuse: error = %v, want %v", slot, err, errInvalidSigningAttempt)
		}
		if state := records[0].State(); state != PreprocessingBurned {
			t.Fatalf("slot %d: record state %d after the reuse attempt, want burned", slot, state)
		}
		freshRecords := signingExecutorTestRecords(t, slot)
		replay, err := newSigningExecutorParty(
			signingExecutorPartyTestConfig(fixture, active, 0, slotIndex, journals[0], freshRecords[0]),
			params,
			randomness[0],
		)
		if err != nil {
			t.Fatalf("slot %d: replay party construction: %v", slot, err)
		}
		if err := replay.Start(); !errors.Is(err, errInvalidSigningState) {
			t.Fatalf("slot %d: session replay: error = %v, want %v", slot, err, errInvalidSigningState)
		}
		if state := freshRecords[0].State(); state != PreprocessingBurned {
			t.Fatalf("slot %d: a refused replay must burn the fresh record, state %d", slot, state)
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("covered %d accepted and %d rejected slots; both classes are required", accepted, rejected)
	}
}

// TestSigningExecutorPartyDoneMarksTerminalSlots requires Done to stay false
// while a slot can still progress and to become true once the slot reached a
// terminal state: a completed signature, a rejection, or a starvation burn.
func TestSigningExecutorPartyDoneMarksTerminalSlots(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	const mask = uint8(0x0F)
	active := fixture.activeShares(t, mask)
	identities := signingExecutorPartyTestIdentities(active)
	journals := signingExecutorTestJournals(t)

	// A started slot with nothing delivered can still progress.
	slot, randomness := signingExecutorPartyTestAcceptedSlot(t, fixture, active)
	records := signingExecutorTestRecords(t, int(slot))
	parties := signingExecutorPartyTestParties(t, fixture, mask, slot, randomness, journals, records)
	for index, party := range parties {
		if err := party.Start(); err != nil {
			t.Fatalf("signer %d: Start(): %v", index, err)
		}
		if party.Done() {
			t.Fatalf("signer %d: empty slot reported done", index)
		}
	}
	_, _ = signingExecutorPartyTestPump(t, parties, identities)
	for index, party := range parties {
		if !party.Done() {
			t.Fatalf("signer %d: completed slot is not done", index)
		}
		signature, err := party.Finish()
		if err != nil || len(signature) != 3293 {
			t.Fatalf("signer %d: Finish() = %d bytes, %v", index, len(signature), err)
		}
	}

	// A rejected slot is terminal for every signer as well.
	rejectedSlot, rejectedRandomness := signingExecutorTestRejectingSlot(t, fixture)
	rejectedParties := signingExecutorPartyTestParties(
		t, fixture, mask, rejectedSlot, rejectedRandomness, journals, signingExecutorTestRecords(t, int(rejectedSlot)),
	)
	for index, party := range rejectedParties {
		if err := party.Start(); err != nil {
			t.Fatalf("rejected slot signer %d: Start(): %v", index, err)
		}
	}
	_, _ = signingExecutorPartyTestPump(t, rejectedParties, identities)
	for index, party := range rejectedParties {
		if !party.Done() {
			t.Fatalf("rejected slot signer %d: slot is not done", index)
		}
	}

	// A starved slot is not done until Finish consumes its material. It gets a
	// fresh journal: the slot index is deterministic, so its session would
	// otherwise collide with the completed run's journal entry.
	freshSlot, freshRandomness := signingExecutorPartyTestAcceptedSlot(t, fixture, active)
	starved := signingExecutorPartyTestParties(
		t, fixture, mask, freshSlot, freshRandomness, signingExecutorTestJournals(t),
		signingExecutorTestRecords(t, int(freshSlot)),
	)[0]
	if err := starved.Start(); err != nil {
		t.Fatalf("starved slot: Start(): %v", err)
	}
	if starved.Done() {
		t.Fatal("starved slot reported done before Finish")
	}
	if _, err := starved.Finish(); err == nil {
		t.Fatal("starved slot produced a signature")
	}
	if !starved.Done() {
		t.Fatal("starved slot is not terminal after Finish")
	}
}

// TestNewSigningExecutorRecordMintsOneTimeRecords requires the minted record to
// carry the caller's participant and fresh, non-zero metadata drawn from the
// entropy source, and to follow the one-time lifecycle: committed to exactly
// one session and then burned.
func TestNewSigningExecutorRecordMintsOneTimeRecords(t *testing.T) {
	material := make([]byte, 3*32*2)
	for index := range material {
		material[index] = byte(index + 1)
	}
	reader := bytes.NewReader(material)
	first, err := NewSigningExecutorRecord(5, reader)
	if err != nil {
		t.Fatalf("NewSigningExecutorRecord(): %v", err)
	}
	second, err := NewSigningExecutorRecord(5, reader)
	if err != nil {
		t.Fatalf("NewSigningExecutorRecord(): %v", err)
	}
	firstView := first.CoordinatorView()
	secondView := second.CoordinatorView()
	if firstView.ParticipantID != 5 || secondView.ParticipantID != 5 {
		t.Fatalf("participants %d and %d, want 5", firstView.ParticipantID, secondView.ParticipantID)
	}
	if firstView.RecordID == (PreprocessingID{}) || firstView.Commitment == ([32]byte{}) {
		t.Fatal("minted record carries zero metadata")
	}
	if firstView.RecordID == secondView.RecordID || firstView.Commitment == secondView.Commitment {
		t.Fatal("two mints reused record metadata")
	}
	if state := first.State(); state != PreprocessingAvailable {
		t.Fatalf("minted record state %d, want available", state)
	}
	if err := first.Commit([32]byte{0x11}); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	if err := first.MarkResponseReleased(); err != nil {
		t.Fatalf("MarkResponseReleased(): %v", err)
	}
	if state := first.State(); state != PreprocessingBurned {
		t.Fatalf("record state %d after release, want burned", state)
	}
	if _, err := NewSigningExecutorRecord(0, bytes.NewReader(material)); !errors.Is(err, ErrInvalidPreprocessing) {
		t.Fatalf("zero participant: error = %v", err)
	}
	if _, err := NewSigningExecutorRecord(5, nil); !errors.Is(err, ErrInvalidPreprocessing) {
		t.Fatalf("missing entropy: error = %v", err)
	}
	if _, err := NewSigningExecutorRecord(5, bytes.NewReader(material[:10])); !errors.Is(err, ErrInvalidPreprocessing) {
		t.Fatalf("short entropy: error = %v", err)
	}
}

// TestSigningExecutorPartyFilteredClassifiesSlotOutcomes requires Filtered to
// report the two legitimate filter classes and nothing else: an accepted slot
// and a starved slot are not filtered, a rejected slot is.
func TestSigningExecutorPartyFilteredClassifiesSlotOutcomes(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	const mask = uint8(0x0F)
	active := fixture.activeShares(t, mask)
	identities := signingExecutorPartyTestIdentities(active)
	journals := signingExecutorTestJournals(t)

	slot, randomness := signingExecutorPartyTestAcceptedSlot(t, fixture, active)
	parties := signingExecutorPartyTestParties(
		t, fixture, mask, slot, randomness, journals, signingExecutorTestRecords(t, int(slot)),
	)
	for index, party := range parties {
		if err := party.Start(); err != nil {
			t.Fatalf("signer %d: Start(): %v", index, err)
		}
	}
	_, _ = signingExecutorPartyTestPump(t, parties, identities)
	for index, party := range parties {
		signature, err := party.Finish()
		if err != nil || len(signature) != 3293 {
			t.Fatalf("signer %d: Finish() = %d bytes, %v", index, len(signature), err)
		}
		if party.Filtered() {
			t.Fatalf("signer %d: an accepted slot reported a filter", index)
		}
	}

	rejectedSlot, rejectedRandomness := signingExecutorTestRejectingSlot(t, fixture)
	rejected := signingExecutorPartyTestParties(
		t, fixture, mask, rejectedSlot, rejectedRandomness, journals, signingExecutorTestRecords(t, int(rejectedSlot)),
	)
	for index, party := range rejected {
		if err := party.Start(); err != nil {
			t.Fatalf("rejected slot signer %d: Start(): %v", index, err)
		}
	}
	_, _ = signingExecutorPartyTestPump(t, rejected, identities)
	for index, party := range rejected {
		if _, err := party.Finish(); err == nil {
			t.Fatalf("rejected slot signer %d produced a signature", index)
		}
		if !party.Filtered() {
			t.Fatalf("rejected slot signer %d did not report a filter", index)
		}
	}

	starved := signingExecutorPartyTestParties(
		t, fixture, mask, slot, randomness, signingExecutorTestJournals(t), signingExecutorTestRecords(t, int(slot)),
	)[0]
	if err := starved.Start(); err != nil {
		t.Fatalf("starved slot: Start(): %v", err)
	}
	if _, err := starved.Finish(); err == nil {
		t.Fatal("starved slot produced a signature")
	}
	if starved.Filtered() {
		t.Fatal("a starved slot reported a filter")
	}
}

// TestSigningExecutorPartyRejectsInvalidBindings requires malformed party input
// to be rejected before any message is produced.
func TestSigningExecutorPartyRejectsInvalidBindings(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	active := fixture.activeShares(t, 0x0F)
	identities := signingExecutorPartyTestIdentities(active)
	point := signingExecutorTestRandomness(t, 0x91)[0]
	params, paramsErr := SigningParametersForParticipants(6)
	if paramsErr != nil {
		t.Fatal(paramsErr)
	}
	base := signingExecutorPartyTestConfig(fixture, active, 0, 1, signingTestJournal(t), signingExecutorTestRecords(t, 1)[0])
	cases := []struct {
		name   string
		mutate func(*SigningExecutorPartyConfig)
	}{
		{name: "zero slot", mutate: func(config *SigningExecutorPartyConfig) { config.Slot = 0 }},
		{name: "slot above the limit", mutate: func(config *SigningExecutorPartyConfig) {
			config.Slot = signingExecutorSlotLimit + 1
		}},
		{name: "missing journal", mutate: func(config *SigningExecutorPartyConfig) { config.Journal = nil }},
		{name: "missing record", mutate: func(config *SigningExecutorPartyConfig) { config.Record = nil }},
		{name: "missing share", mutate: func(config *SigningExecutorPartyConfig) { config.Share = nil }},
		{name: "share outside the active set", mutate: func(config *SigningExecutorPartyConfig) {
			config.Share = fixture.shares[4]
		}},
		{name: "signers not ascending", mutate: func(config *SigningExecutorPartyConfig) {
			config.Signers = []uint32{identities[1], identities[0], identities[2], identities[3]}
		}},
		{name: "signer outside the committee", mutate: func(config *SigningExecutorPartyConfig) {
			config.Signers = []uint32{identities[0], identities[1], identities[2], identities[3] + 1000}
		}},
		{name: "foreign key", mutate: func(config *SigningExecutorPartyConfig) {
			config.Request = signingExecutorTestForeignKeyRequest(fixture)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := base
			testCase.mutate(&config)
			if _, err := newSigningExecutorParty(config, params, point); !errors.Is(err, errInvalidSigningAttempt) {
				t.Fatalf("error = %v, want %v", err, errInvalidSigningAttempt)
			}
		})
	}
	// The exported constructor requires a randomness source of its own.
	if _, err := NewSigningExecutorParty(base); !errors.Is(err, ErrInvalidSigningRandomness) {
		t.Fatalf("missing entropy: error = %v, want %v", err, ErrInvalidSigningRandomness)
	}
}

// TestSigningExecutorPartySamplesItsOwnRandomness requires the exported
// constructor to draw the slot's ball point from the caller's entropy source
// inside the party: identical sources produce identical round-1 payloads, and
// the party's session identifier is the one the request and the active set
// define.
func TestSigningExecutorPartySamplesItsOwnRandomness(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	active := fixture.activeShares(t, 0x0F)
	identities := signingExecutorPartyTestIdentities(active)
	sessionID, err := Dilithium3SigningSessionID(signingExecutorTestRequest(fixture, 1), identities[:])
	if err != nil {
		t.Fatalf("Dilithium3SigningSessionID(): %v", err)
	}
	entropy := []byte{0x5A, 0x11, 0xC3, 0x07, 0x9E, 0x42, 0x6D, 0xF0}
	var payloads [][]byte
	for round := 0; round < 2; round++ {
		config := signingExecutorPartyTestConfig(
			fixture, active, 0, 1, signingTestJournal(t), signingExecutorTestRecords(t, 1)[0],
		)
		config.Entropy = bytes.NewReader(entropy)
		party, err := NewSigningExecutorParty(config)
		if err != nil {
			t.Fatalf("round %d: NewSigningExecutorParty(): %v", round, err)
		}
		if got := party.SessionID(); got != sessionID {
			t.Fatalf("round %d: session %x, want %x", round, got, sessionID)
		}
		if err := party.Start(); err != nil {
			t.Fatalf("round %d: Start(): %v", round, err)
		}
		messages := party.Drain()
		if len(messages) != 1 || messages[0].Kind != SigningExecutorKindCommit {
			t.Fatalf("round %d: drained %d messages, want one commit", round, len(messages))
		}
		slot, _, err := DecodeSigningExecutorCommit(messages[0].Payload)
		if err != nil || slot != 1 {
			t.Fatalf("round %d: commit payload slot %d err %v, want slot 1", round, slot, err)
		}
		payloads = append(payloads, messages[0].Payload)
	}
	if !bytes.Equal(payloads[0], payloads[1]) {
		t.Fatal("identical entropy sources produced different commit payloads")
	}
}
