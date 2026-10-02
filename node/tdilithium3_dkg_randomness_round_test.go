// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGRandomnessRoundSixIndependentNodes(t *testing.T) {
	runners, _ := testTDilithium3DKGRunners(t)
	var publicKeys [6]*mode3.PublicKey
	var privateKeys [6]*mode3.PrivateKey
	var contributions [6][32]byte
	for position, runner := range runners {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY DKG identity %d", position))
		publicKeys[position], privateKeys[position] = mode3.NewKeyFromSeed(&seed)
		contributions[position] = runner.record.LocalRandomness
	}
	var inboxes [6]*tdilithium3DKGInbox
	var rounds [6]*tdilithium3DKGRandomnessRound
	for position, runner := range runners {
		inbox, err := newTDilithium3DKGInbox(runner.session, uint8(position), func(senderID uint32, message, signature []byte) bool {
			position, found := tdilithium3DKGCommitteePosition(runner.session.Committee, senderID)
			return found && mode3.Verify(publicKeys[position], message, signature)
		}, func(peer p2p.PeerID) (uint32, bool) {
			for sender := range runners {
				if peer == p2p.PeerID(fmt.Sprintf("peer-%d", sender)) {
					return runner.session.Committee.Participants[sender], true
				}
			}
			return 0, false
		})
		if err != nil {
			t.Fatal(err)
		}
		inboxes[position] = inbox
		rounds[position], err = newTDilithium3DKGRandomnessRound(runner)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := rounds[0].outbound(func([]byte) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("reveal before durable commitments accepted")
	}
	for sender := len(runners) - 1; sender >= 0; sender-- {
		sign := func(message []byte) ([]byte, error) {
			signature := make([]byte, mode3.SignatureSize)
			mode3.SignTo(privateKeys[sender], message, signature)
			return signature, nil
		}
		packet, err := rounds[sender].outboundCommitment(sign)
		if err != nil {
			t.Fatal(err)
		}
		message := p2p.PeerMessage{Type: p2p.MsgTypeTDilithium3DKGRandomnessCommitment, From: p2p.PeerID(fmt.Sprintf("peer-%d", sender)), Payload: packet}
		for position := range runners {
			if position == sender {
				continue
			}
			if err := inboxes[position].accept(message); err != nil {
				t.Fatal(err)
			}
			if ready, err := rounds[position].observe(<-inboxes[position].messages); err != nil || ready {
				t.Fatalf("commitment round prematurely revealed: %v", err)
			}
		}
	}
	for position, runner := range runners {
		if !runner.record.CommitmentsPersisted {
			t.Fatalf("node %d has no durable commitments", position)
		}
		restarted, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
			Session: runner.session, ParticipantPosition: uint8(position), BasePath: runner.basePath,
			Password: runner.password, Entropy: bytes.NewReader(bytes.Repeat([]byte{7}, 32)),
		})
		if err != nil {
			t.Fatal(err)
		}
		runners[position] = restarted
		rounds[position], err = newTDilithium3DKGRandomnessRound(restarted)
		if err != nil {
			t.Fatal(err)
		}
	}
	for sender := len(runners) - 1; sender >= 0; sender-- {
		sign := func(message []byte) ([]byte, error) {
			signature := make([]byte, mode3.SignatureSize)
			mode3.SignTo(privateKeys[sender], message, signature)
			return signature, nil
		}
		packet, err := rounds[sender].outbound(sign)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rounds[sender].outbound(nil); err == nil {
			t.Fatal("unsigned outbound accepted")
		}
		message := p2p.PeerMessage{Type: p2p.MsgTypeTDilithium3DKGRandomness, From: p2p.PeerID(fmt.Sprintf("peer-%d", sender)), Payload: packet}
		for position := range runners {
			if position == sender {
				continue
			}
			if err := inboxes[position].accept(message); err != nil {
				t.Fatal(err)
			}
			ready, err := rounds[position].observe(<-inboxes[position].messages)
			if err != nil {
				t.Fatal(err)
			}
			if ready != (rounds[position].receivedCount() == 6) {
				t.Fatalf("position %d ready too early", position)
			}
		}
	}
	wantGlobal, wantRho, err := dilithium3v1.DeriveDKGRandomness(runners[0].session, contributions[:])
	if err != nil {
		t.Fatal(err)
	}
	for position, runner := range runners {
		if runner.record.Stage != tdilithium3DKGStageRandomnessComplete || runner.record.GlobalRandomness != wantGlobal || runner.record.Rho != wantRho {
			t.Fatalf("node %d did not persist the same derived randomness", position)
		}
		restarted, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
			Session: runner.session, ParticipantPosition: uint8(position), BasePath: runner.basePath,
			Password: runner.password, Entropy: bytes.NewReader(bytes.Repeat([]byte{7}, 32)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if restarted.record.GlobalRandomness != wantGlobal || restarted.record.Rho != wantRho {
			t.Fatal("restart lost completed randomness")
		}
	}
}

func TestTDilithium3DKGRandomnessRoundRejectsConflictsAndFailedPersistence(t *testing.T) {
	runners, _ := testTDilithium3DKGRunners(t)
	round, err := newTDilithium3DKGRandomnessRound(runners[0])
	if err != nil {
		t.Fatal(err)
	}
	if ready, err := round.observe(testTDilithium3VerifiedRandomness(runners[0], 1, [32]byte{1})); err != nil || ready || round.receivedCount() != 1 {
		t.Fatalf("early reveal was not buffered safely: ready %v error %v", ready, err)
	}
	if _, err := round.outbound(func([]byte) ([]byte, error) { return make([]byte, mode3.SignatureSize), nil }); err == nil {
		t.Fatal("outbound reveal before durable commitments accepted")
	}
	testTDilithium3PersistCommitments(t, round, runners[0])
	for position := uint8(1); position < 5; position++ {
		if ready, err := round.observe(testTDilithium3VerifiedRandomness(runners[0], position, [32]byte{position})); err != nil || ready {
			t.Fatalf("partial round incorrectly completed: %v", err)
		}
	}
	if _, err := round.observe(testTDilithium3VerifiedRandomness(runners[0], 1, [32]byte{99})); err == nil {
		t.Fatal("conflicting contribution accepted")
	}
	if _, err := round.observe(testTDilithium3VerifiedRandomness(runners[0], 0, [32]byte{99})); err == nil {
		t.Fatal("forged local contribution accepted")
	}
	if _, err := round.observe(testTDilithium3VerifiedRandomness(runners[0], 5, [32]byte{})); err == nil {
		t.Fatal("zero contribution accepted")
	}
	unexpectedSequence := testTDilithium3VerifiedRandomness(runners[0], 5, [32]byte{5})
	unexpectedSequence.Sequence = 2
	if _, err := round.observe(unexpectedSequence); err == nil {
		t.Fatal("unexpected randomness sequence accepted")
	}
	journalPath := runners[0].journal.path
	original, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	last := testTDilithium3VerifiedRandomness(runners[0], 5, [32]byte{5})
	if _, err := round.observe(last); err == nil {
		t.Fatal("journal failure was ignored")
	}
	if runners[0].record.Stage != tdilithium3DKGStagePrepared {
		t.Fatal("failed journal write advanced in-memory state")
	}
	if err := os.WriteFile(journalPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if ready, err := round.observe(last); err != nil || !ready {
		t.Fatalf("retry failed after journal restoration: ready %v error %v", ready, err)
	}
	if _, err := round.observe(last); err == nil {
		t.Fatal("completed round accepted another contribution")
	}
}

func TestTDilithium3DKGRandomnessRoundEarlyRevealSurvivesReplaySuppression(t *testing.T) {
	runners, _ := testTDilithium3DKGRunners(t)
	runner := runners[0]
	round, err := newTDilithium3DKGRandomnessRound(runner)
	if err != nil {
		t.Fatal(err)
	}
	var seed [mode3.SeedSize]byte
	copy(seed[:], "DEVNET ONLY early DKG reveal")
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	senderID := runner.session.Committee.Participants[1]
	inbox, err := newTDilithium3DKGInbox(runner.session, 0,
		func(id uint32, message, signature []byte) bool {
			return id == senderID && mode3.Verify(publicKey, message, signature)
		},
		func(peer p2p.PeerID) (uint32, bool) { return senderID, peer == "peer-1" },
	)
	if err != nil {
		t.Fatal(err)
	}
	value := [32]byte{1}
	sign := func(message []byte) ([]byte, error) {
		signature := make([]byte, mode3.SignatureSize)
		mode3.SignTo(privateKey, message, signature)
		return signature, nil
	}
	reveal, err := encodeTDilithium3DKGSignedEnvelope(runner.session, p2p.MsgTypeTDilithium3DKGRandomness, 1, 1, value[:], sign)
	if err != nil {
		t.Fatal(err)
	}
	wire := p2p.PeerMessage{From: "peer-1", Type: p2p.MsgTypeTDilithium3DKGRandomness, Payload: reveal}
	if err := inbox.accept(wire); err != nil {
		t.Fatal(err)
	}
	if ready, err := round.observe(<-inbox.messages); err != nil || ready || round.receivedCount() != 1 {
		t.Fatalf("early reveal prematurely completed: %v", err)
	}
	for position := uint8(1); position < 6; position++ {
		if _, err := round.observe(testTDilithium3VerifiedCommitment(t, runner, position, [32]byte{position})); err != nil {
			t.Fatal(err)
		}
	}
	if round.receivedCount() != 2 || !runner.record.CommitmentsPersisted {
		t.Fatal("buffered reveal was not applied after durable commitments")
	}
	if err := inbox.accept(wire); err != nil || len(inbox.messages) != 0 {
		t.Fatalf("duplicate reveal delivered twice: %v", err)
	}
	for position := uint8(2); position < 6; position++ {
		ready, err := round.observe(testTDilithium3VerifiedRandomness(runner, position, [32]byte{position}))
		if err != nil || ready != (position == 5) {
			t.Fatalf("round stalled after early reveal: ready %v error %v", ready, err)
		}
	}
}

func TestTDilithium3DKGRandomnessRoundConcurrentDelivery(t *testing.T) {
	runners, _ := testTDilithium3DKGRunners(t)
	round, err := newTDilithium3DKGRandomnessRound(runners[0])
	if err != nil {
		t.Fatal(err)
	}
	testTDilithium3PersistCommitments(t, round, runners[0])
	var workers sync.WaitGroup
	for position := uint8(1); position < 6; position++ {
		workers.Add(1)
		go func(position uint8) {
			defer workers.Done()
			_, err := round.observe(testTDilithium3VerifiedRandomness(runners[0], position, [32]byte{position}))
			if err != nil {
				t.Errorf("delivery %d failed: %v", position, err)
			}
		}(position)
	}
	workers.Wait()
	if round.receivedCount() != 6 || runners[0].record.Stage != tdilithium3DKGStageRandomnessComplete {
		t.Fatal("concurrent delivery failed to commit exactly one complete round")
	}
}

func TestTDilithium3DKGRandomnessRoundRestartBeforeCommit(t *testing.T) {
	runners, _ := testTDilithium3DKGRunners(t)
	initial := runners[0]
	round, err := newTDilithium3DKGRandomnessRound(initial)
	if err != nil {
		t.Fatal(err)
	}
	for position := uint8(1); position < 4; position++ {
		if ready, err := round.observe(testTDilithium3VerifiedCommitment(t, initial, position, [32]byte{position})); err != nil || ready {
			t.Fatalf("incomplete round advanced before crash: %v", err)
		}
	}
	restarted, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
		Session: initial.session.Clone(), ParticipantPosition: initial.participantPosition,
		BasePath: initial.basePath, Password: initial.password,
		Entropy: bytes.NewReader(bytes.Repeat([]byte{99}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.record.Stage != tdilithium3DKGStagePrepared || restarted.record.LocalRandomness != initial.record.LocalRandomness {
		t.Fatal("restart changed the persisted local contribution")
	}
	resumed, err := newTDilithium3DKGRandomnessRound(restarted)
	if err != nil {
		t.Fatal(err)
	}
	testTDilithium3PersistCommitments(t, resumed, restarted)
	for position := uint8(1); position < 6; position++ {
		ready, err := resumed.observe(testTDilithium3VerifiedRandomness(restarted, position, [32]byte{position}))
		if err != nil {
			t.Fatal(err)
		}
		if ready != (position == 5) {
			t.Fatalf("position %d completed at wrong time", position)
		}
	}
	if restarted.record.Stage != tdilithium3DKGStageRandomnessComplete {
		t.Fatal("replayed remote contributions did not complete durable round")
	}
}

func testTDilithium3VerifiedCommitment(t *testing.T, runner *tdilithium3DKGRunner, position uint8, value [32]byte) tdilithium3DKGVerifiedMessage {
	t.Helper()
	commitment, err := dilithium3v1.DKGRandomnessCommitment(runner.session, position, value)
	if err != nil {
		t.Fatal(err)
	}
	return tdilithium3DKGVerifiedMessage{Type: p2p.MsgTypeTDilithium3DKGRandomnessCommitment, SenderID: runner.session.Committee.Participants[position], Sequence: 1, Payload: commitment[:]}
}

func testTDilithium3PersistCommitments(t *testing.T, round *tdilithium3DKGRandomnessRound, runner *tdilithium3DKGRunner) {
	t.Helper()
	for position := uint8(1); position < 6; position++ {
		if ready, err := round.observe(testTDilithium3VerifiedCommitment(t, runner, position, [32]byte{position})); err != nil || ready {
			t.Fatalf("commitment phase position %d: ready %v error %v", position, ready, err)
		}
	}
	if !runner.record.CommitmentsPersisted {
		t.Fatal("commitments were not persisted")
	}
}

func testTDilithium3VerifiedRandomness(runner *tdilithium3DKGRunner, position uint8, payload [32]byte) tdilithium3DKGVerifiedMessage {
	return tdilithium3DKGVerifiedMessage{Type: p2p.MsgTypeTDilithium3DKGRandomness, SenderID: runner.session.Committee.Participants[position], Sequence: 1, Payload: payload[:]}
}
