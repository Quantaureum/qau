// Quantaureum Node source, version 1.0.0.
package node

// Tests of the node-side signing request schedule: a filtered slot advances to
// the next candidate, an exhausted request reports every candidate outcome, and
// any other failure ends the request with that slot's own outcome. The
// production factory's happy path needs a real DKG share, so it is exercised by
// the development-network integration; these tests drive the policy through
// scripted slots and cover the factory's validation paths.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3SigningScheduleTestMessage is the canned signature the scripted
// accepted slot reports.
const tdilithium3SigningScheduleTestMessage = "QAU-TDILITHIUM3-V1-SIGNING-SCHEDULE-TEST"

// tdilithium3SigningScheduleTestRequest returns a structurally valid request
// that is cryptographically inert: the scripted slots never sign with it.
func tdilithium3SigningScheduleTestRequest() protocol.SignRequest {
	publicKey := make([]byte, qcrypto.SignatureAlgorithmDilithium3Legacy.PublicKeySize())
	publicKey[0] = 0x51
	return protocol.SignRequest{
		Protocol: protocol.ThresholdProtocolDilithium3V1,
		Key: protocol.ThresholdKeyID{
			Algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, Generation: 7, PublicKey: publicKey,
		},
		Committee: protocol.CommitteeID{
			Version: 1, Threshold: protocol.ThresholdV1Threshold, Participants: []uint32{1, 2, 3, 4, 5, 6},
		},
		ChainID: 1669, Epoch: 1, Slot: 64, Domain: protocol.SigningDomainFinality,
		Message: []byte(tdilithium3SigningScheduleTestMessage), AttemptNonce: [32]byte{0xA1, 0x02},
	}
}

// tdilithium3SigningScheduleTestJournal opens a temporary signing journal.
func tdilithium3SigningScheduleTestJournal(t *testing.T) *dilithium3v1.SigningJournal {
	t.Helper()
	journal, err := dilithium3v1.OpenSigningJournal(filepath.Join(t.TempDir(), "signing-journal.db"))
	if err != nil {
		t.Fatalf("OpenSigningJournal(): %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

// tdilithium3SigningScheduleTestScript scripts one factory: the slot that
// accepts (zero means none), the slots that filter, the slots that end in a
// silence, and the slot that fails hard. Every other slot starves at its
// deadline.
type tdilithium3SigningScheduleTestScript struct {
	acceptAt uint16
	filter   map[uint16]bool
	silence  map[uint16]bool
	failAt   uint16
}

// tdilithium3SigningScheduleTestFactory builds the scripted factory and a
// pointer to the slots it built, so a test can assert each slot's lifecycle.
func tdilithium3SigningScheduleTestFactory(
	t *testing.T,
	script tdilithium3SigningScheduleTestScript,
) (tdilithium3SigningSlotFactory, *[]*tdilithium3SigningSlotTestSlot) {
	t.Helper()
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	payloads := tdilithium3SigningSlotTestPayloads(t)
	signature := []byte(tdilithium3SigningScheduleTestMessage)
	built := &[]*tdilithium3SigningSlotTestSlot{}
	silent := func(uint8, []byte) error { return nil }
	factory := func(slot uint16) (
		tdilithium3SigningSlot, *tdilithium3SigningTransport, *tdilithium3SigningInbox, error,
	) {
		slotContext := fixture.context
		slotContext.SessionID = [32]byte{0x77, byte(slot)}
		inbox, err := newTDilithium3SigningInboxFromIdentitySnapshot(slotContext, fixture.identities)
		if err != nil {
			return nil, nil, nil, err
		}
		transport, err := newTDilithium3SigningTransport(
			slotContext, fixture.context.Signers[0], fixture.signers[fixture.context.Signers[0]], silent,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		stub := newTDilithium3SigningSlotTestSlot(payloads, signature)
		switch {
		case script.acceptAt != 0 && slot == script.acceptAt:
			stub.scriptAccepted()
		case script.failAt != 0 && slot == script.failAt:
			stub.scriptFinish(errSigningSlotTestDelivery, false)
		case script.filter[slot]:
			stub.scriptFinish(errSigningSlotTestStarved, true)
		case script.silence[slot]:
			stub.scriptFinish(
				fmt.Errorf("%w: signer 9: scripted silence", dilithium3v1.ErrSigningExecutorSilence), false,
			)
		}
		*built = append(*built, stub)
		return stub, transport, inbox, nil
	}
	return factory, built
}

// TestTDilithium3SigningScheduleAdvancesPastFilteredSlots requires a request to
// return the signature of a candidate that accepts while its siblings filter.
// The candidates run concurrently (the networked deployment the reference
// schedule sanctions), so every candidate is built up front and the accepted
// one wins the race; the filtered siblings' outcomes are best effort, but the
// accepted outcome and the signature are not.
func TestTDilithium3SigningScheduleAdvancesPastFilteredSlots(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	factory, built := tdilithium3SigningScheduleTestFactory(t, tdilithium3SigningScheduleTestScript{
		acceptAt: 3, filter: map[uint16]bool{1: true, 2: true},
	})
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	schedule, err := newTDilithium3SigningRequestSchedule(node, factory, 3, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	signature, outcomes, err := schedule.run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if string(signature) != tdilithium3SigningScheduleTestMessage {
		t.Fatalf("signature %q", signature)
	}
	var accepted *tdilithium3SigningRequestOutcome
	for index := range outcomes {
		if outcomes[index].Accepted {
			accepted = &outcomes[index]
		}
	}
	if accepted == nil || accepted.Slot != 3 {
		t.Fatalf("accepted outcome %+v, want slot 3", accepted)
	}
	if len(*built) != 3 {
		t.Fatalf("%d candidates built, want 3 (all submitted concurrently)", len(*built))
	}
}

// TestTDilithium3SigningScheduleSuccessBeatsHardFailure requires a candidate's
// valid signature to win even when a sibling candidate fails hard: the
// candidates are independent sessions, so one signer's fatal abort in one slot
// cannot suppress a completed signature in another. This is the liveness gain
// of the concurrent schedule over the serial one, which aborted on the first
// hard failure.
func TestTDilithium3SigningScheduleSuccessBeatsHardFailure(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	factory, built := tdilithium3SigningScheduleTestFactory(t, tdilithium3SigningScheduleTestScript{
		acceptAt: 2, failAt: 1,
	})
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	schedule, err := newTDilithium3SigningRequestSchedule(node, factory, 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	signature, _, err := schedule.run(ctx)
	if err != nil {
		t.Fatalf("a sibling hard failure suppressed a valid signature: %v", err)
	}
	if string(signature) != tdilithium3SigningScheduleTestMessage {
		t.Fatalf("signature %q", signature)
	}
	if len(*built) != 2 {
		t.Fatalf("%d candidates built, want 2", len(*built))
	}
}

// TestTDilithium3SigningScheduleExhaustsCandidates requires a request whose
// candidates all filter to report exhaustion with every outcome.
func TestTDilithium3SigningScheduleExhaustsCandidates(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	factory, built := tdilithium3SigningScheduleTestFactory(t, tdilithium3SigningScheduleTestScript{
		filter: map[uint16]bool{1: true, 2: true, 3: true},
	})
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	schedule, err := newTDilithium3SigningRequestSchedule(node, factory, 3, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, outcomes, err := schedule.run(ctx)
	if !errors.Is(err, errTDilithium3SigningRequestExhausted) {
		t.Fatalf("error = %v, want %v", err, errTDilithium3SigningRequestExhausted)
	}
	if len(outcomes) != 3 {
		t.Fatalf("%d outcomes, want 3", len(outcomes))
	}
	for index, stub := range *built {
		if !stub.wasBurned() {
			t.Fatalf("candidate %d left its material live", index+1)
		}
	}
}

// TestTDilithium3SigningScheduleSilenceExhaustsLikeAFilter requires silence --
// a candidate starved of a participant's message, the retry-class outcome the
// executor pins (ErrSigningExecutorSilence) -- to exhaust the request alongside
// the legitimate filters instead of surfacing as the request's hard error, so
// the seal path retries the attempt with fresh material. A genuine local fault
// still wins over exhaustion (TestTDilithium3SigningScheduleEndsOnHardFailure).
func TestTDilithium3SigningScheduleSilenceExhaustsLikeAFilter(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	factory, built := tdilithium3SigningScheduleTestFactory(t, tdilithium3SigningScheduleTestScript{
		filter:  map[uint16]bool{1: true},
		silence: map[uint16]bool{2: true, 3: true},
	})
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	schedule, err := newTDilithium3SigningRequestSchedule(node, factory, 3, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, outcomes, err := schedule.run(ctx)
	if !errors.Is(err, errTDilithium3SigningRequestExhausted) {
		t.Fatalf("error = %v, want %v (silence is retry-class, not a hard failure)", err, errTDilithium3SigningRequestExhausted)
	}
	if len(outcomes) != 3 {
		t.Fatalf("%d outcomes, want 3", len(outcomes))
	}
	for index, stub := range *built {
		if !stub.wasBurned() {
			t.Fatalf("candidate %d left its material live", index+1)
		}
	}
}

// TestTDilithium3SigningScheduleEndsOnHardFailure requires a request with no
// accepting candidate to surface a hard (non-filter) failure rather than a bare
// exhaustion: the candidates run concurrently, and when none signs the first
// hard failure is the request's error.
func TestTDilithium3SigningScheduleEndsOnHardFailure(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	factory, built := tdilithium3SigningScheduleTestFactory(t, tdilithium3SigningScheduleTestScript{
		filter: map[uint16]bool{1: true}, failAt: 2,
	})
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	schedule, err := newTDilithium3SigningRequestSchedule(node, factory, 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	signature, outcomes, err := schedule.run(ctx)
	if signature != nil || !errors.Is(err, errSigningSlotTestDelivery) {
		t.Fatalf("signature %q, error %v", signature, err)
	}
	for _, outcome := range outcomes {
		if outcome.Accepted {
			t.Fatalf("outcomes %+v, no candidate should have accepted", outcomes)
		}
	}
	if len(*built) != 2 {
		t.Fatalf("%d candidates built, want 2", len(*built))
	}
	for index, stub := range *built {
		if !stub.wasBurned() {
			t.Fatalf("candidate %d left its material live", index+1)
		}
	}
}

// TestTDilithium3SigningScheduleDeadlineEndsTheRequest requires candidates that
// never converge to end the request at their deadline, each consuming its
// material. The concurrent schedule submits every candidate up front, so all
// are built and all are burned when the deadline lapses with no signature.
func TestTDilithium3SigningScheduleDeadlineEndsTheRequest(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	factory, built := tdilithium3SigningScheduleTestFactory(t, tdilithium3SigningScheduleTestScript{})
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	schedule, err := newTDilithium3SigningRequestSchedule(node, factory, 2, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, outcomes, err := schedule.run(ctx)
	if err == nil {
		t.Fatal("a starved request produced a signature")
	}
	for _, outcome := range outcomes {
		if outcome.Accepted {
			t.Fatalf("outcomes %+v, want none accepted", outcomes)
		}
	}
	if len(*built) != 2 {
		t.Fatalf("%d candidates built, want 2", len(*built))
	}
	for index, stub := range *built {
		if !stub.wasBurned() {
			t.Fatalf("candidate %d left its material live", index+1)
		}
	}
}

// TestTDilithium3SigningScheduleRejectsInvalidShapes requires malformed schedule
// input and malformed request config to be refused before any slot starts.
func TestTDilithium3SigningScheduleRejectsInvalidShapes(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	factory, _ := tdilithium3SigningScheduleTestFactory(t, tdilithium3SigningScheduleTestScript{})
	if _, err := newTDilithium3SigningRequestSchedule(nil, factory, 1, time.Second); err == nil {
		t.Fatal("missing node accepted")
	}
	if _, err := newTDilithium3SigningRequestSchedule(node, nil, 1, time.Second); err == nil {
		t.Fatal("missing factory accepted")
	}
	if _, err := newTDilithium3SigningRequestSchedule(node, factory, 0, time.Second); err == nil {
		t.Fatal("zero candidates accepted")
	}
	if _, err := newTDilithium3SigningRequestSchedule(
		node, factory, dilithium3v1.SigningMaxParallelSlots+1, time.Second,
	); err == nil {
		t.Fatal("too many candidates accepted")
	}
	if _, err := newTDilithium3SigningRequestSchedule(node, factory, 1, 0); err == nil {
		t.Fatal("zero slot timeout accepted")
	}
	if schedule, err := newTDilithium3SigningRequestSchedule(node, factory, 2, time.Second); err != nil {
		t.Fatalf("valid schedule refused: %v", err)
	} else if schedule.slots != 2 {
		t.Fatalf("schedule slots %d, want 2", schedule.slots)
	}

	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	base := func() tdilithium3SigningPartyConfig {
		return tdilithium3SigningPartyConfig{
			Request:    tdilithium3SigningScheduleTestRequest(),
			Share:      &dilithium3v1.LocalShare{ParticipantID: fixture.context.Signers[0]},
			Signers:    fixture.context.Signers,
			Journal:    tdilithium3SigningScheduleTestJournal(t),
			Identities: fixture.identities,
			Sign:       fixture.signers[fixture.context.Signers[0]],
			Broadcast:  func(uint8, []byte) error { return nil },
			Entropy:    bytes.NewReader(make([]byte, 3*32*(dilithium3v1.SigningParallelSlots+1))),
		}
	}
	cases := []struct {
		name   string
		mutate func(*tdilithium3SigningPartyConfig)
	}{
		{name: "zero request", mutate: func(config *tdilithium3SigningPartyConfig) {
			config.Request = protocol.SignRequest{}
		}},
		{name: "missing journal", mutate: func(config *tdilithium3SigningPartyConfig) { config.Journal = nil }},
		{name: "missing signer callback", mutate: func(config *tdilithium3SigningPartyConfig) { config.Sign = nil }},
		{name: "missing broadcast", mutate: func(config *tdilithium3SigningPartyConfig) { config.Broadcast = nil }},
		{name: "missing entropy", mutate: func(config *tdilithium3SigningPartyConfig) { config.Entropy = nil }},
		{name: "signers not ascending", mutate: func(config *tdilithium3SigningPartyConfig) {
			config.Signers = []uint32{config.Signers[1], config.Signers[0], config.Signers[2], config.Signers[3]}
		}},
		{name: "missing identity", mutate: func(config *tdilithium3SigningPartyConfig) {
			delete(config.Identities, config.Signers[3])
		}},
		{name: "missing share", mutate: func(config *tdilithium3SigningPartyConfig) { config.Share = nil }},
		{name: "share outside the active set", mutate: func(config *tdilithium3SigningPartyConfig) {
			config.Share = &dilithium3v1.LocalShare{ParticipantID: 99}
		}},
		{name: "share without material", mutate: func(*tdilithium3SigningPartyConfig) {}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := base()
			testCase.mutate(&config)
			if _, err := newTDilithium3SigningSchedule(node, config); err == nil {
				t.Fatal("malformed request config accepted")
			}
		})
	}
}
