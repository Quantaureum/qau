// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Tests of the in-process executor driver (design note, Slice 1): the honest
// run is differentially tested against the reference driver of sign.go, and an
// adversarial router injects one deviation class per case: reordering,
// duplication, dropping, replaying, forging, and equivocation. Every injected
// deviation either completes with the baseline signature or aborts with a
// bounded reason code and the responsible participant.

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// signingExecutorTestMessage is the deterministic message every executor test
// slot signs.
const signingExecutorTestMessage = "QAU-TDILITHIUM3-V1-SIGNING-EXECUTOR-INTEROP"

// signingExecutorTestRequest binds one slot's deterministic request.
func signingExecutorTestRequest(fixture *signingTestFixture, slot uint16) protocol.SignRequest {
	request := fixture.requestFor([]byte(signingExecutorTestMessage))
	request.AttemptNonce[0] = byte(slot)
	request.AttemptNonce[1] = byte(slot >> 8)
	return request
}

// signingExecutorTestForeignKeyRequest returns the slot request with a foreign
// key generation, which no active share can match.
func signingExecutorTestForeignKeyRequest(fixture *signingTestFixture) protocol.SignRequest {
	request := signingExecutorTestRequest(fixture, 1)
	request.Key.Generation += 1
	return request
}

// signingExecutorTestRandomness draws four ball points from a deterministic
// source derived from the case label.
func signingExecutorTestRandomness(t *testing.T, label int64) []*signingRandomness {
	t.Helper()
	return signingTestAttemptRandomness(t, rand.New(rand.NewSource(label)))
}

// signingExecutorTestJournals opens one signing journal per active position,
// the way four signer processes would each keep their own.
func signingExecutorTestJournals(t *testing.T) []*SigningJournal {
	t.Helper()
	directory := t.TempDir()
	journals := make([]*SigningJournal, 4)
	for index := range journals {
		journals[index] = signingTestJournalAt(t, filepath.Join(directory, fmt.Sprintf("signer-%d", index)))
	}
	return journals
}

// signingExecutorTestRecords returns fresh one-time records of one slot, the
// pinned C=6 threshold count of them. The metadata is test scaffolding;
// production records come from the preprocessing layer.
func signingExecutorTestRecords(t *testing.T, slot int) []*PreprocessingRecord {
	t.Helper()
	return signingExecutorTestRecordsFor(t, slot, signingTestParameters(t).Threshold)
}

// signingExecutorTestRecordsFor is signingExecutorTestRecords with an explicit
// signer count, for the family-row tests.
func signingExecutorTestRecordsFor(t *testing.T, slot, signers int) []*PreprocessingRecord {
	t.Helper()
	records := make([]*PreprocessingRecord, signers)
	for index := range records {
		records[index] = mpcTestRecord(t, byte(0x30+((slot-1)%24)*4+index))
	}
	return records
}

// signingExecutorTestMaterial returns one slot's per-signer material over the
// given journals, with fresh one-time records.
func signingExecutorTestMaterial(
	t *testing.T,
	slot int,
	randomness []*signingRandomness,
	journals []*SigningJournal,
) []signingExecutorSlotMaterial {
	t.Helper()
	records := signingExecutorTestRecordsFor(t, slot, len(randomness))
	material := make([]signingExecutorSlotMaterial, len(randomness))
	for index := range material {
		material[index] = signingExecutorSlotMaterial{
			randomness: randomness[index],
			journal:    journals[index],
			record:     records[index],
		}
	}
	return material
}

// signingExecutorTestSession builds one slot session over the given journals,
// with fresh one-time records for the slot.
func signingExecutorTestSession(
	t *testing.T,
	fixture *signingTestFixture,
	mask uint8,
	slot uint16,
	randomness []*signingRandomness,
	journals []*SigningJournal,
) *signingExecutorSession {
	t.Helper()
	active := fixture.activeShares(t, mask)
	request := signingExecutorTestRequest(fixture, slot)
	session, err := newSigningExecutorSession(
		request, active, slot, signingExecutorTestMaterial(t, int(slot), randomness, journals),
	)
	if err != nil {
		t.Fatalf("slot %d: newSigningExecutorSession(): %v", slot, err)
	}
	return session
}

// signingExecutorTestReference runs one reference attempt on exactly the given
// slot inputs and reports its decision, so the executor can be compared against
// it on identical inputs.
func signingExecutorTestReference(
	t *testing.T,
	journal *SigningJournal,
	request protocol.SignRequest,
	active []*LocalShare,
	slot uint16,
	randomness []*signingRandomness,
) (*signingAttempt, bool) {
	t.Helper()
	attempt, err := newSigningAttempt(
		journal, signingTestAttemptRecord(t, int(slot)), request, active, signingTestCoordinator, randomness,
	)
	if err != nil {
		t.Fatalf("slot %d: newSigningAttempt(): %v", slot, err)
	}
	if err := attempt.prepare(); err != nil {
		t.Fatalf("slot %d: prepare(): %v", slot, err)
	}
	if _, err := attempt.commit(); err != nil {
		t.Fatalf("slot %d: commit(): %v", slot, err)
	}
	if _, err := attempt.challenge(); err != nil {
		t.Fatalf("slot %d: challenge(): %v", slot, err)
	}
	if _, err := attempt.respond(); err != nil {
		if !errors.Is(err, errSigningRejected) {
			t.Fatalf("slot %d: respond(): %v", slot, err)
		}
		return attempt, false
	}
	if _, err := attempt.finalize(); err != nil {
		if !errors.Is(err, errSigningRejected) {
			t.Fatalf("slot %d: finalize(): %v", slot, err)
		}
		return attempt, false
	}
	return attempt, true
}

// signingExecutorTestDelivery is one routed message for one receiver.
type signingExecutorTestDelivery struct {
	target   int
	envelope signingExecutorEnvelope
}

// signingExecutorTestRoute resolves one drained batch into deliveries.
type signingExecutorTestRoute func(batchIndex int, batch []signingExecutorEnvelope) []signingExecutorTestDelivery

// signingExecutorTestBroadcast expands a batch into one delivery per receiver
// other than the sender: every kind of the construction is a broadcast inside
// the active set.
func signingExecutorTestBroadcast(ids []uint32, batch []signingExecutorEnvelope) []signingExecutorTestDelivery {
	var deliveries []signingExecutorTestDelivery
	for _, envelope := range batch {
		for target, identity := range ids {
			if identity == envelope.Sender {
				continue
			}
			deliveries = append(deliveries, signingExecutorTestDelivery{target: target, envelope: envelope})
		}
	}
	return deliveries
}

// signingExecutorTestRun records one harness run: every rejection a receiver
// returned and every message the signers emitted.
type signingExecutorTestRun struct {
	errors   []error
	outbound map[uint32][]signingExecutorEnvelope
}

// emitted returns every recorded outbound message of one kind.
func (run *signingExecutorTestRun) emitted(kind uint16) []signingExecutorEnvelope {
	var emitted []signingExecutorEnvelope
	for _, envelopes := range run.outbound {
		for _, envelope := range envelopes {
			if envelope.Kind == kind {
				emitted = append(emitted, envelope)
			}
		}
	}
	return emitted
}

// signingExecutorTestDrive pumps one session until no signer has anything to
// send, stopping early when a fatal abort ends the slot.
func signingExecutorTestDrive(
	t *testing.T,
	session *signingExecutorSession,
	route signingExecutorTestRoute,
) *signingExecutorTestRun {
	t.Helper()
	run := &signingExecutorTestRun{outbound: make(map[uint32][]signingExecutorEnvelope)}
	for batchIndex := 0; ; batchIndex++ {
		batch := session.drain()
		if len(batch) == 0 {
			return run
		}
		for _, envelope := range batch {
			run.outbound[envelope.Sender] = append(run.outbound[envelope.Sender], envelope)
		}
		for _, delivery := range route(batchIndex, batch) {
			err := session.deliverTo(delivery.target, delivery.envelope)
			if err == nil {
				continue
			}
			run.errors = append(run.errors, err)
			var abort *signingExecutorAbort
			if errors.As(err, &abort) && abort.fatal() {
				return run
			}
		}
	}
}

// signingExecutorTestAbort extracts the bounded abort from an outcome.
func signingExecutorTestAbort(t *testing.T, err error) *signingExecutorAbort {
	t.Helper()
	var abort *signingExecutorAbort
	if !errors.As(err, &abort) {
		t.Fatalf("error %v is not a bounded executor abort", err)
	}
	return abort
}

// signingExecutorTestCleanRoute broadcasts every batch to the other receivers.
func signingExecutorTestCleanRoute(session *signingExecutorSession) signingExecutorTestRoute {
	ids := session.policy.Signers
	return func(_ int, batch []signingExecutorEnvelope) []signingExecutorTestDelivery {
		return signingExecutorTestBroadcast(ids, batch)
	}
}

// signingExecutorTestReverseRoute delivers every batch in reverse order, so
// receivers must buffer out-of-order round messages.
func signingExecutorTestReverseRoute(session *signingExecutorSession) signingExecutorTestRoute {
	ids := session.policy.Signers
	return func(_ int, batch []signingExecutorEnvelope) []signingExecutorTestDelivery {
		deliveries := signingExecutorTestBroadcast(ids, batch)
		for left, right := 0, len(deliveries)-1; left < right; left, right = left+1, right-1 {
			deliveries[left], deliveries[right] = deliveries[right], deliveries[left]
		}
		return deliveries
	}
}

// signingExecutorTestDuplicateRoute delivers every message twice, exercising
// the idempotent retransmission path of the gate.
func signingExecutorTestDuplicateRoute(session *signingExecutorSession) signingExecutorTestRoute {
	ids := session.policy.Signers
	return func(_ int, batch []signingExecutorEnvelope) []signingExecutorTestDelivery {
		var deliveries []signingExecutorTestDelivery
		for _, delivery := range signingExecutorTestBroadcast(ids, batch) {
			deliveries = append(deliveries, delivery, delivery)
		}
		return deliveries
	}
}

// signingExecutorTestDropRoute drops one sender's messages of one kind for
// every receiver.
func signingExecutorTestDropRoute(
	session *signingExecutorSession,
	senderIndex int,
	kind uint16,
) signingExecutorTestRoute {
	ids := session.policy.Signers
	return func(_ int, batch []signingExecutorEnvelope) []signingExecutorTestDelivery {
		var kept []signingExecutorEnvelope
		for _, envelope := range batch {
			if envelope.Sender == ids[senderIndex] && envelope.Kind == kind {
				continue
			}
			kept = append(kept, envelope)
		}
		return signingExecutorTestBroadcast(ids, kept)
	}
}

// signingExecutorTestTamperRoute replaces one sender's payload of one kind
// before it is routed.
func signingExecutorTestTamperRoute(
	session *signingExecutorSession,
	senderIndex int,
	kind uint16,
	mutate func([]byte) []byte,
) signingExecutorTestRoute {
	ids := session.policy.Signers
	return func(_ int, batch []signingExecutorEnvelope) []signingExecutorTestDelivery {
		var routed []signingExecutorEnvelope
		for _, envelope := range batch {
			if envelope.Sender == ids[senderIndex] && envelope.Kind == kind {
				envelope = signingExecutorEnvelope{
					Sender:  envelope.Sender,
					Kind:    envelope.Kind,
					Payload: mutate(envelope.Payload),
				}
			}
			routed = append(routed, envelope)
		}
		return signingExecutorTestBroadcast(ids, routed)
	}
}

// signingExecutorTestTamperReveal flips one coefficient of a reveal, so it no
// longer opens the sender's round-1 commitment.
func signingExecutorTestTamperReveal(t *testing.T, payload []byte) []byte {
	t.Helper()
	slot, contribution, err := DecodeSigningExecutorReveal(payload)
	if err != nil {
		t.Fatalf("DecodeSigningExecutorReveal(): %v", err)
	}
	contribution[0][0] = Normalize(contribution[0][0] + 1)
	encoded, err := EncodeSigningExecutorReveal(slot, contribution)
	if err != nil {
		t.Fatalf("EncodeSigningExecutorReveal(): %v", err)
	}
	return encoded
}

// signingExecutorTestTamperResponse displaces two response polynomials far
// enough that the public combine checks must reject the slot.
func signingExecutorTestTamperResponse(t *testing.T, payload []byte) []byte {
	t.Helper()
	slot, part, err := DecodeSigningExecutorResponse(payload)
	if err != nil {
		t.Fatalf("DecodeSigningExecutorResponse(): %v", err)
	}
	for row := 0; row < 2; row++ {
		for index := 0; index < N; index++ {
			value := part[row][index] + Gamma1/2
			if value > Gamma1 {
				value = Gamma1
			}
			if value <= -Gamma1 {
				value = -Gamma1 + 1
			}
			part[row][index] = value
		}
	}
	encoded, err := EncodeSigningExecutorResponse(slot, part)
	if err != nil {
		t.Fatalf("EncodeSigningExecutorResponse(): %v", err)
	}
	return encoded
}

// signingExecutorTestBaseline scans deterministic slots on one active set until
// the executor accepts one, and returns its signature, slot, and randomness.
func signingExecutorTestBaseline(
	t *testing.T,
	fixture *signingTestFixture,
) ([]byte, uint16, []*signingRandomness) {
	t.Helper()
	const mask = uint8(0x0F)
	journals := signingExecutorTestJournals(t)
	for slot := 1; slot <= 128; slot++ {
		randomness := signingExecutorTestRandomness(t, int64(0xB000+slot*97))
		session := signingExecutorTestSession(t, fixture, mask, uint16(slot), randomness, journals)
		if err := session.start(); err != nil {
			t.Fatalf("slot %d: start(): %v", slot, err)
		}
		signingExecutorTestDrive(t, session, signingExecutorTestCleanRoute(session))
		signature, err := session.finish()
		if err == nil {
			return signature, uint16(slot), randomness
		}
	}
	t.Fatal("no accepted slot in 128 deterministic candidates")
	return nil, 0, []*signingRandomness{}
}

// TestSigningExecutorHonestRunMatchesReference drives the executor and the
// reference driver on exactly the same slot inputs and requires the same
// decision and, for an accepted slot, the same published values and the same
// 3293-byte signature. A rejected slot must publish no response part from any
// signer and must end in the local-rejection reason.
func TestSigningExecutorHonestRunMatchesReference(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	journals := signingExecutorTestJournals(t)
	accepted := 0
	rejected := 0
	for _, mask := range []uint8{0x0F, 0x3C, 0x33} {
		for slot := 1; slot <= 5; slot++ {
			randomness := signingExecutorTestRandomness(t, int64(0x5E00+slot*131+int(mask)*7))
			request := signingExecutorTestRequest(fixture, uint16(slot))
			active := fixture.activeShares(t, mask)
			attempt, referenceAccepted := signingExecutorTestReference(
				t, journal, request, active, uint16(slot), randomness,
			)
			session, err := newSigningExecutorSession(
				request, active, uint16(slot), signingExecutorTestMaterial(t, slot, randomness, journals),
			)
			if err != nil {
				t.Fatalf("slot %d mask %06b: newSigningExecutorSession(): %v", slot, mask, err)
			}
			if err := session.start(); err != nil {
				t.Fatalf("slot %d mask %06b: start(): %v", slot, mask, err)
			}
			run := signingExecutorTestDrive(t, session, signingExecutorTestCleanRoute(session))
			for _, deliveryErr := range run.errors {
				// A combine check that fails on the last response delivery is a
				// legitimate filter outcome of the slot, not a routing fault.
				reason, bounded := signingExecutorReasonOf(deliveryErr)
				if !bounded || reason != SigningExecutorReasonCombineCheck {
					t.Fatalf("slot %d mask %06b: honest run returned %v", slot, mask, deliveryErr)
				}
			}
			signature, err := session.finish()
			if referenceAccepted {
				accepted++
				if err != nil {
					t.Fatalf("slot %d mask %06b: accepted by the reference but aborted: %v", slot, mask, err)
				}
				if !bytes.Equal(signature, attempt.signature) {
					t.Fatalf("slot %d mask %06b: signature differs from the reference driver", slot, mask)
				}
				for index, signer := range session.signers {
					if signer.contribution != attempt.contributions[index] {
						t.Fatalf("slot %d mask %06b: signer %d share differs from the reference", slot, mask, index)
					}
					if signer.w != attempt.w {
						t.Fatalf("slot %d mask %06b: aggregate w differs from the reference", slot, mask)
					}
					if signer.highBits != attempt.highBits {
						t.Fatalf("slot %d mask %06b: w1 differs from the reference", slot, mask)
					}
					if signer.seed != attempt.challengeSeed {
						t.Fatalf("slot %d mask %06b: challenge differs from the reference", slot, mask)
					}
				}
				continue
			}
			rejected++
			abort := signingExecutorTestAbort(t, err)
			switch abort.reason {
			case SigningExecutorReasonLocalRejection:
				// A locally rejected slot publishes no response part at all.
				for _, envelope := range run.emitted(SigningExecutorKindResponse) {
					t.Fatalf("slot %d mask %06b: rejected slot emitted a response from signer %d", slot, mask, envelope.Sender)
				}
			case SigningExecutorReasonCombineCheck:
				// Every signer accepted locally, so every response part was
				// published before the public combine checks filtered the slot.
				if got := len(run.emitted(SigningExecutorKindResponse)); got != 4 {
					t.Fatalf("slot %d mask %06b: combine-filtered slot emitted %d response parts, want 4", slot, mask, got)
				}
			default:
				t.Fatalf("slot %d mask %06b: rejected slot aborted with %s", slot, mask, abort.reason)
			}
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("covered %d accepted and %d rejected slots; both classes are required", accepted, rejected)
	}
}

// TestSigningExecutorAdversarialRouting injects one deviation class per subtest
// into the routing of an otherwise honest accepted slot: every case either
// completes with the baseline signature or aborts with the expected bounded
// reason and attribution.
func TestSigningExecutorAdversarialRouting(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	baseline, slot, randomness := signingExecutorTestBaseline(t, fixture)
	newSession := func(t *testing.T) *signingExecutorSession {
		t.Helper()
		journals := signingExecutorTestJournals(t)
		session := signingExecutorTestSession(t, fixture, 0x0F, slot, randomness, journals)
		if err := session.start(); err != nil {
			t.Fatalf("start(): %v", err)
		}
		return session
	}

	t.Run("clean", func(t *testing.T) {
		session := newSession(t)
		run := signingExecutorTestDrive(t, session, signingExecutorTestCleanRoute(session))
		if len(run.errors) != 0 {
			t.Fatalf("clean run returned errors: %v", run.errors)
		}
		signature, err := session.finish()
		if err != nil {
			t.Fatalf("clean run aborted: %v", err)
		}
		if !bytes.Equal(signature, baseline) {
			t.Fatal("clean run differs from the baseline signature")
		}
	})

	t.Run("reordered deliveries", func(t *testing.T) {
		session := newSession(t)
		run := signingExecutorTestDrive(t, session, signingExecutorTestReverseRoute(session))
		if len(run.errors) != 0 {
			t.Fatalf("reordered run returned errors: %v", run.errors)
		}
		signature, err := session.finish()
		if err != nil {
			t.Fatalf("reordered run aborted: %v", err)
		}
		if !bytes.Equal(signature, baseline) {
			t.Fatal("reordered run differs from the baseline signature")
		}
	})

	t.Run("duplicated deliveries", func(t *testing.T) {
		session := newSession(t)
		run := signingExecutorTestDrive(t, session, signingExecutorTestDuplicateRoute(session))
		if len(run.errors) != 0 {
			t.Fatalf("duplicated run returned errors: %v", run.errors)
		}
		signature, err := session.finish()
		if err != nil {
			t.Fatalf("duplicated run aborted: %v", err)
		}
		if !bytes.Equal(signature, baseline) {
			t.Fatal("duplicated run differs from the baseline signature")
		}
	})

	for _, dropped := range []struct {
		kind uint16
		name string
	}{
		{kind: SigningExecutorKindCommit, name: "commit"},
		{kind: SigningExecutorKindReveal, name: "reveal"},
		{kind: SigningExecutorKindAcceptance, name: "acceptance"},
		{kind: SigningExecutorKindResponse, name: "response"},
	} {
		t.Run("dropped "+dropped.name, func(t *testing.T) {
			session := newSession(t)
			signingExecutorTestDrive(t, session, signingExecutorTestDropRoute(session, 1, dropped.kind))
			_, err := session.finish()
			abort := signingExecutorTestAbort(t, err)
			if abort.reason != SigningExecutorReasonSilence {
				t.Fatalf("dropped %s aborted with %s, want silence", dropped.name, abort.reason)
			}
			if abort.evidence.ParticipantID != session.policy.Signers[1] {
				t.Fatalf("dropped %s blamed signer %d, want %d", dropped.name, abort.evidence.ParticipantID, session.policy.Signers[1])
			}
			if abort.detail != "missing "+dropped.name {
				t.Fatalf("dropped %s detail %q", dropped.name, abort.detail)
			}
		})
	}

	t.Run("replayed foreign-slot message", func(t *testing.T) {
		session := newSession(t)
		injection, err := EncodeSigningExecutorCommit(slot+1, [32]byte{0xEE})
		if err != nil {
			t.Fatalf("EncodeSigningExecutorCommit(): %v", err)
		}
		route := func(batchIndex int, batch []signingExecutorEnvelope) []signingExecutorTestDelivery {
			deliveries := signingExecutorTestBroadcast(session.policy.Signers, batch)
			if batchIndex == 0 {
				for target := range session.signers {
					if target == 2 {
						continue
					}
					deliveries = append(deliveries, signingExecutorTestDelivery{
						target: target,
						envelope: signingExecutorEnvelope{
							Sender: session.policy.Signers[2], Kind: SigningExecutorKindCommit, Payload: injection,
						},
					})
				}
			}
			return deliveries
		}
		run := signingExecutorTestDrive(t, session, route)
		if len(run.errors) != 3 {
			t.Fatalf("replay produced %d errors, want 3: %v", len(run.errors), run.errors)
		}
		for _, err := range run.errors {
			reason, ok := signingExecutorReasonOf(err)
			if !ok || reason != SigningExecutorReasonUnauthorized {
				t.Fatalf("replay was not refused as unauthorized: %v", err)
			}
		}
		signature, err := session.finish()
		if err != nil {
			t.Fatalf("the slot did not survive a refused replay: %v", err)
		}
		if !bytes.Equal(signature, baseline) {
			t.Fatal("the replayed slot differs from the baseline signature")
		}
	})

	t.Run("forged reveal", func(t *testing.T) {
		session := newSession(t)
		route := signingExecutorTestTamperRoute(session, 1, SigningExecutorKindReveal, func(payload []byte) []byte {
			return signingExecutorTestTamperReveal(t, payload)
		})
		run := signingExecutorTestDrive(t, session, route)
		if len(run.errors) == 0 {
			t.Fatal("the forged reveal was not detected")
		}
		_, err := session.finish()
		abort := signingExecutorTestAbort(t, err)
		if abort.reason != SigningExecutorReasonCommitmentMismatch {
			t.Fatalf("forged reveal aborted with %s, want commitment mismatch", abort.reason)
		}
		if abort.evidence.ParticipantID != session.policy.Signers[1] {
			t.Fatalf("forged reveal blamed signer %d, want %d", abort.evidence.ParticipantID, session.policy.Signers[1])
		}
		if !errors.Is(err, errSigningExecutorMismatch) {
			t.Fatalf("forged reveal error %v does not map onto the mismatch sentinel", err)
		}
	})

	t.Run("forged response", func(t *testing.T) {
		session := newSession(t)
		route := signingExecutorTestTamperRoute(session, 1, SigningExecutorKindResponse, func(payload []byte) []byte {
			return signingExecutorTestTamperResponse(t, payload)
		})
		run := signingExecutorTestDrive(t, session, route)
		if len(run.errors) == 0 {
			t.Fatal("the forged response was not detected")
		}
		_, err := session.finish()
		abort := signingExecutorTestAbort(t, err)
		if abort.reason != SigningExecutorReasonCombineCheck {
			t.Fatalf("forged response aborted with %s, want combine check", abort.reason)
		}
		if abort.detail == "" {
			t.Fatal("forged response abort carries no failed predicate")
		}
		if !errors.Is(err, errSigningExecutorCombine) {
			t.Fatalf("forged response error %v does not map onto the combine sentinel", err)
		}
	})

	t.Run("equivocating reveal", func(t *testing.T) {
		session := newSession(t)
		route := func(_ int, batch []signingExecutorEnvelope) []signingExecutorTestDelivery {
			deliveries := signingExecutorTestBroadcast(session.policy.Signers, batch)
			for _, envelope := range batch {
				if envelope.Sender != session.policy.Signers[1] || envelope.Kind != SigningExecutorKindReveal {
					continue
				}
				tampered := signingExecutorTestTamperReveal(t, envelope.Payload)
				deliveries = append(deliveries, signingExecutorTestDelivery{
					target: 0,
					envelope: signingExecutorEnvelope{
						Sender: envelope.Sender, Kind: envelope.Kind, Payload: tampered,
					},
				})
			}
			return deliveries
		}
		run := signingExecutorTestDrive(t, session, route)
		if len(run.errors) == 0 {
			t.Fatal("the equivocating reveal was not detected")
		}
		_, err := session.finish()
		abort := signingExecutorTestAbort(t, err)
		if abort.reason != SigningExecutorReasonConflict {
			t.Fatalf("equivocation aborted with %s, want conflict", abort.reason)
		}
		if abort.evidence.ParticipantID != session.policy.Signers[1] {
			t.Fatalf("equivocation blamed signer %d, want %d", abort.evidence.ParticipantID, session.policy.Signers[1])
		}
		if !errors.Is(err, ErrSigningExecutorConflict) {
			t.Fatalf("equivocation error %v does not map onto the conflict sentinel", err)
		}
	})
}

// TestSigningExecutorCorruptSignersCannotExtractRejectedResponse simulates two
// corrupt signers plus a malicious coordinator against a slot whose honest
// signer rejects: the corrupt acceptance bits are forged to true and response
// parts are injected, and no honest signer may publish a response, combine, or
// sign the rejected slot.
func TestSigningExecutorCorruptSignersCannotExtractRejectedResponse(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	slot, randomness := signingExecutorTestRejectingSlot(t, fixture)
	journals := signingExecutorTestJournals(t)
	session := signingExecutorTestSession(t, fixture, 0x0F, slot, randomness, journals)
	if err := session.start(); err != nil {
		t.Fatalf("start(): %v", err)
	}
	if session.signers[0].accepted {
		t.Fatal("the negative test requires signer 0 to reject the slot")
	}
	ids := session.policy.Signers
	// A corrupt signer computes its response part regardless of its own bit;
	// only the payload has to be carried by the coordinator.
	challenge := signingExecutorTestChallenge(t, session)
	forgedParts := make(map[uint32][]byte, 2)
	for _, index := range []int{1, 2} {
		shiftFirst, _ := signingExecutorChallengeShift(
			session.signers[index].partialFirst, session.signers[index].partialSecond, challenge,
		)
		part := signingResponsePart(session.signers[index].randomness, shiftFirst)
		payload, err := EncodeSigningExecutorResponse(slot, part)
		if err != nil {
			t.Fatalf("EncodeSigningExecutorResponse(): %v", err)
		}
		forgedParts[ids[index]] = payload
	}
	forgedAcceptance, err := EncodeSigningExecutorAcceptance(slot, true)
	if err != nil {
		t.Fatalf("EncodeSigningExecutorAcceptance(): %v", err)
	}
	corrupt := map[uint32]bool{ids[1]: true, ids[2]: true}
	route := func(_ int, batch []signingExecutorEnvelope) []signingExecutorTestDelivery {
		var deliveries []signingExecutorTestDelivery
		for _, envelope := range batch {
			if corrupt[envelope.Sender] {
				if envelope.Kind == SigningExecutorKindAcceptance {
					envelope = signingExecutorEnvelope{
						Sender: envelope.Sender, Kind: envelope.Kind, Payload: forgedAcceptance,
					}
				}
				if envelope.Kind == SigningExecutorKindResponse {
					continue
				}
			}
			for target, identity := range ids {
				if identity == envelope.Sender {
					continue
				}
				deliveries = append(deliveries, signingExecutorTestDelivery{target: target, envelope: envelope})
			}
			if corrupt[envelope.Sender] && envelope.Kind == SigningExecutorKindAcceptance {
				for target, identity := range ids {
					if identity == envelope.Sender {
						continue
					}
					deliveries = append(deliveries, signingExecutorTestDelivery{
						target: target,
						envelope: signingExecutorEnvelope{
							Sender: envelope.Sender, Kind: SigningExecutorKindResponse,
							Payload: forgedParts[envelope.Sender],
						},
					})
				}
			}
		}
		return deliveries
	}
	run := signingExecutorTestDrive(t, session, route)
	if len(run.errors) != 0 {
		t.Fatalf("corrupt routing produced delivery errors: %v", run.errors)
	}
	for _, index := range []int{0, 3} {
		envelopes := run.outbound[ids[index]]
		for _, envelope := range envelopes {
			if envelope.Kind == SigningExecutorKindResponse {
				t.Fatalf("honest signer %d published a response for a rejected slot", ids[index])
			}
		}
		if len(envelopes) != 3 {
			t.Fatalf("honest signer %d published %d messages, want commit, reveal, and acceptance", ids[index], len(envelopes))
		}
		if envelopes[0].Kind != SigningExecutorKindCommit || envelopes[1].Kind != SigningExecutorKindReveal ||
			envelopes[2].Kind != SigningExecutorKindAcceptance {
			t.Fatalf("honest signer %d published an unexpected message sequence", ids[index])
		}
	}
	_, accepted, err := DecodeSigningExecutorAcceptance(run.outbound[ids[0]][2].Payload)
	if err != nil {
		t.Fatalf("DecodeSigningExecutorAcceptance(): %v", err)
	}
	if accepted {
		t.Fatalf("honest signer %d published an accepting bit for a slot it rejected", ids[0])
	}
	_, err = session.finish()
	abort := signingExecutorTestAbort(t, err)
	if abort.reason != SigningExecutorReasonLocalRejection {
		t.Fatalf("corrupt routing ended with %s, want local rejection", abort.reason)
	}
	if abort.evidence.ParticipantID != ids[0] {
		t.Fatalf("corrupt routing blamed signer %d, want %d", abort.evidence.ParticipantID, ids[0])
	}
	if session.signers[0].signature != nil || session.signers[3].signature != nil {
		t.Fatal("the rejected slot produced a signature")
	}
}

// signingExecutorTestRejectingSlot scans deterministic slots until the executor
// rejects one with signer 0's own bit false, the negative-test precondition.
func signingExecutorTestRejectingSlot(t *testing.T, fixture *signingTestFixture) (uint16, []*signingRandomness) {
	t.Helper()
	journals := signingExecutorTestJournals(t)
	for candidate := 1; candidate <= 128; candidate++ {
		randomness := signingExecutorTestRandomness(t, int64(0xC000+candidate*53))
		session := signingExecutorTestSession(t, fixture, 0x0F, uint16(candidate), randomness, journals)
		if err := session.start(); err != nil {
			t.Fatalf("slot %d: start(): %v", candidate, err)
		}
		signingExecutorTestDrive(t, session, signingExecutorTestCleanRoute(session))
		if _, err := session.finish(); err == nil {
			continue
		}
		if session.signers[0].rejected && !session.signers[0].accepted {
			return uint16(candidate), randomness
		}
	}
	t.Fatal("no rejected slot with signer 0 rejecting in 128 candidates")
	return 0, []*signingRandomness{}
}

// signingExecutorTestChallenge recomputes the public challenge from the four
// shares the signers committed at start.
func signingExecutorTestChallenge(t *testing.T, session *signingExecutorSession) Poly {
	t.Helper()
	var w VectorK
	for _, signer := range session.signers {
		for row := 0; row < K; row++ {
			w[row] = Add(w[row], signer.contribution[row])
		}
	}
	var highBits VectorK
	for row := 0; row < K; row++ {
		highBits[row] = HighBits(w[row])
	}
	public, err := EncodePublicHighBits(highBits)
	if err != nil {
		t.Fatalf("EncodePublicHighBits(): %v", err)
	}
	seed, err := signingChallengeSeed(session.signers[0].representative, public)
	if err != nil {
		t.Fatalf("signingChallengeSeed(): %v", err)
	}
	challenge, err := DeriveMode3Challenge(seed)
	if err != nil {
		t.Fatalf("DeriveMode3Challenge(): %v", err)
	}
	return challenge
}

// TestSigningExecutorSessionRejectsInvalidBindings requires malformed session
// input to be rejected before any message is produced.
func TestSigningExecutorSessionRejectsInvalidBindings(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	randomness := signingExecutorTestRandomness(t, 0x71)
	request := signingExecutorTestRequest(fixture, 1)
	active := fixture.activeShares(t, 0x0F)
	journals := signingExecutorTestJournals(t)
	material := signingExecutorTestMaterial(t, 1, randomness, journals)
	missingRandomness := material
	missingRandomness[0] = signingExecutorSlotMaterial{journal: journals[0], record: material[0].record}
	missingJournal := material
	missingJournal[2] = signingExecutorSlotMaterial{randomness: randomness[2], record: material[2].record}
	missingRecord := material
	missingRecord[3] = signingExecutorSlotMaterial{randomness: randomness[3], journal: journals[3]}
	cases := []struct {
		name     string
		request  protocol.SignRequest
		shares   []*LocalShare
		slot     uint16
		material []signingExecutorSlotMaterial
	}{
		{
			name: "three shares", request: request, shares: active[:3],
			slot: 1, material: material,
		},
		{
			name: "zero slot", request: request, shares: active,
			slot: 0, material: material,
		},
		{
			name: "missing randomness", request: request, shares: active,
			slot: 1, material: missingRandomness,
		},
		{
			name: "missing journal", request: request, shares: active,
			slot: 1, material: missingJournal,
		},
		{
			name: "missing record", request: request, shares: active,
			slot: 1, material: missingRecord,
		},
		{
			name: "foreign key", request: signingExecutorTestForeignKeyRequest(fixture), shares: active,
			slot: 1, material: material,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := newSigningExecutorSession(
				testCase.request, testCase.shares, testCase.slot, testCase.material,
			); !errors.Is(err, errInvalidSigningAttempt) {
				t.Fatalf("error = %v, want %v", err, errInvalidSigningAttempt)
			}
		})
	}
}
