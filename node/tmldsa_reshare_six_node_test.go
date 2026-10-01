// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareSixNodeCrashSafeActivation(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", "1")
	useFastTMLDSAPersistenceCrypto(t)

	key, oldCommittee, _, selectedDealers := testTMLDSAActivationIdentity(t)
	newCommittee := protocol.CommitteeID{
		Version:      oldCommittee.Version + 1,
		Threshold:    protocol.TMLDSAV1Threshold,
		Participants: append([]uint32(nil), oldCommittee.Participants...),
	}
	request := tmldsaReshareRunRequest{
		SessionID:       [32]byte{0xd1},
		ActivationEpoch: 72,
		Key:             key,
		OldCommittee:    oldCommittee,
		NewCommittee:    newCommittee,
		SelectedDealers: selectedDealers,
	}
	if err := request.validate(); err != nil {
		t.Fatal(err)
	}

	nodes := make(map[uint32]*Node, len(newCommittee.Participants))
	oldShares := make(map[uint32]*protocolmldsa65.LocalShare, len(selectedDealers))
	for _, participantID := range newCommittee.Participants {
		nodes[participantID] = testTMLDSAJournalNode(t)
	}
	for _, dealerID := range selectedDealers {
		share, err := protocolmldsa65.NewLocalShare(
			key,
			oldCommittee,
			dealerID,
			protocolmldsa65.ShareMaterial{},
		)
		if err != nil {
			t.Fatal(err)
		}
		oldShares[dealerID] = share
		defer share.Zeroize()
	}

	broadcast := func(message tmldsaReshareControlMessage) {
		t.Helper()
		for _, participantID := range newCommittee.Participants {
			if err := nodes[participantID].applyTMLDSAReshareControlMessage(message); err != nil {
				t.Fatalf("apply %s from %d to %d: %v", message.Kind, message.SenderID, participantID, err)
			}
		}
	}

	for _, dealerID := range selectedDealers {
		privateMessages, control, err := nodes[dealerID].prepareTMLDSAReshareDealerMessages(
			request,
			dealerID,
			oldShares[dealerID],
			bytes.NewReader(bytes.Repeat([]byte{byte(dealerID), 0xd2}, 100000)),
		)
		if err != nil {
			t.Fatalf("prepare dealer %d: %v", dealerID, err)
		}
		if len(privateMessages) != int(protocol.TMLDSAV1ParticipantCount) {
			t.Fatalf("dealer %d private message count = %d", dealerID, len(privateMessages))
		}
		for _, privateMessage := range privateMessages {
			recipientNode := nodes[privateMessage.RecipientID]
			if recipientNode == nil {
				t.Fatalf("unknown recipient %d", privateMessage.RecipientID)
			}
			if err := recipientNode.persistTMLDSAInboundResharePayload(tmldsaInboundReshareSet{
				SessionID:           request.SessionID,
				KeyGeneration:       request.Key.Generation,
				OldCommitteeVersion: request.OldCommittee.Version,
				NewCommitteeVersion: request.NewCommittee.Version,
				RecipientID:         privateMessage.RecipientID,
			}, dealerID, privateMessage.Payload); err != nil {
				t.Fatalf("deliver dealer %d to recipient %d: %v", dealerID, privateMessage.RecipientID, err)
			}
		}
		broadcast(control)
	}

	for _, dealerID := range selectedDealers {
		driveTMLDSASixNodeDealer(t, nodes, oldShares[dealerID], request, dealerID)
	}

	publicKeys := make(map[uint32][]byte, len(newCommittee.Participants))
	privateKeys := make(map[uint32]*qcrypto.PrivateKey, len(newCommittee.Participants))
	for _, participantID := range newCommittee.Participants {
		keyPair, err := qcrypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[participantID] = keyPair.Public.Bytes()
		privateKeys[participantID] = keyPair.Private
		share, err := nodes[participantID].prepareTMLDSAReshareActivation(
			request.SessionID,
			request.ActivationEpoch,
			request.Key,
			request.OldCommittee,
			request.NewCommittee,
			request.SelectedDealers,
			participantID,
		)
		if err != nil {
			t.Fatalf("prepare activation for %d: %v", participantID, err)
		}
		share.Zeroize()
	}
	verifier := func(participantID uint32, message, signature []byte) bool {
		publicKey, err := qcrypto.PublicKeyFromBytes(publicKeys[participantID])
		return err == nil && qcrypto.Verify(publicKey, message, signature)
	}
	for _, participantID := range newCommittee.Participants {
		candidateDigest, transcriptDigest, err := nodes[participantID].tmldsaReshareActivationEvidence(
			request.SessionID,
			participantID,
		)
		if err != nil {
			t.Fatal(err)
		}
		acknowledgement := protocolmldsa65.ReshareActivationAcknowledgement{
			SessionID:        request.SessionID,
			ActivationEpoch:  request.ActivationEpoch,
			Key:              request.Key.Clone(),
			OldCommittee:     request.OldCommittee.Clone(),
			NewCommittee:     request.NewCommittee.Clone(),
			TranscriptDigest: transcriptDigest,
			ParticipantID:    participantID,
			CandidateDigest:  candidateDigest,
		}
		message, err := acknowledgement.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		acknowledgement.IdentitySignature, err = privateKeys[participantID].Sign(message)
		if err != nil {
			t.Fatal(err)
		}
		for _, recipientID := range newCommittee.Participants {
			if _, err := nodes[recipientID].persistTMLDSAReshareActivationAcknowledgement(
				acknowledgement,
				verifier,
			); err != nil {
				t.Fatalf("deliver activation acknowledgement %d to %d: %v", participantID, recipientID, err)
			}
		}
	}

	for _, participantID := range newCommittee.Participants {
		restarted := &Node{config: nodes[participantID].config}
		nodes[participantID] = restarted
		if _, err := restarted.activateTMLDSAReshare(
			request.SessionID,
			request.ActivationEpoch-1,
			request.Key,
			request.NewCommittee,
			participantID,
		); err == nil {
			t.Fatalf("participant %d activated before epoch", participantID)
		}
		activated, err := restarted.activateTMLDSAReshare(
			request.SessionID,
			request.ActivationEpoch,
			request.Key,
			request.NewCommittee,
			participantID,
		)
		if err != nil {
			t.Fatalf("activate participant %d: %v", participantID, err)
		}
		activated.Zeroize()
		active, found, err := restarted.loadActiveTMLDSAShare()
		if err != nil || !found {
			t.Fatalf("load active participant %d: found=%v err=%v", participantID, found, err)
		}
		if err := active.ValidateIdentity(request.Key, request.NewCommittee, participantID); err != nil {
			t.Fatalf("active participant %d identity: %v", participantID, err)
		}
		active.Zeroize()
	}
}

func driveTMLDSASixNodeDealer(
	t *testing.T,
	nodes map[uint32]*Node,
	oldShare *protocolmldsa65.LocalShare,
	request tmldsaReshareRunRequest,
	dealerID uint32,
) {
	t.Helper()
	participants := request.NewCommittee.Participants
	coordinator, found, err := nodes[participants[0]].loadTMLDSAReshareConsistencyState(request.SessionID, dealerID)
	if err != nil || !found {
		t.Fatalf("load dealer %d state: found=%v err=%v", dealerID, found, err)
	}
	for step := 0; step < 256; step++ {
		if coordinator.Phase() == protocolmldsa65.ReshareConsistencyPhaseVerified {
			for _, participantID := range participants {
				if err := nodes[participantID].persistTMLDSAReshareConsistencyState(coordinator); err != nil {
					t.Fatalf("persist verified dealer %d state for participant %d: %v", dealerID, participantID, err)
				}
				peer, peerFound, peerErr := nodes[participantID].loadTMLDSAReshareConsistencyState(request.SessionID, dealerID)
				if peerErr != nil || !peerFound || peer.Phase() != protocolmldsa65.ReshareConsistencyPhaseVerified {
					t.Fatalf("dealer %d participant %d did not restore verified state: found=%v phase=%v err=%v", dealerID, participantID, peerFound, peer.Phase(), peerErr)
				}
			}
			return
		}

		var messages []tmldsaReshareControlMessage
		phase := coordinator.Phase()
		for _, participantID := range participants {
			participantNode := nodes[participantID]
			var generated []tmldsaReshareControlMessage
			switch phase {
			case protocolmldsa65.ReshareConsistencyPhaseContributionAgreement,
				protocolmldsa65.ReshareConsistencyPhaseNonceCommitment,
				protocolmldsa65.ReshareConsistencyPhaseNonceReveal:
				generated, err = participantNode.nextTMLDSAReshareParticipantMessagesWithCoordinator(
					request,
					coordinator,
					dealerID,
					participantID,
					bytes.NewReader(bytes.Repeat([]byte{byte(step), byte(participantID), 0xd3}, 128)),
				)
			case protocolmldsa65.ReshareConsistencyPhaseTermCommitment,
				protocolmldsa65.ReshareConsistencyPhaseTermReveal:
				var dealerShare *protocolmldsa65.LocalShare
				if participantID == dealerID {
					dealerShare = oldShare
				}
				generated, err = participantNode.nextTMLDSAReshareTermMessagesWithMask(
					request,
					coordinator,
					dealerID,
					participantID,
					bytes.NewReader(bytes.Repeat([]byte{byte(step), byte(participantID), 0xd4}, 128)),
					testTMLDSAReshareMask,
					dealerShare,
				)
			default:
				t.Fatalf("unexpected dealer %d phase %v", dealerID, phase)
			}
			if err != nil {
				t.Fatalf("dealer %d participant %d phase %v: %v", dealerID, participantID, phase, err)
			}

			if dealerID == request.SelectedDealers[0] && participantID == participants[2] &&
				(phase == protocolmldsa65.ReshareConsistencyPhaseNonceCommitment ||
					phase == protocolmldsa65.ReshareConsistencyPhaseTermCommitment) {
				restarted := &Node{config: participantNode.config}
				var replayed []tmldsaReshareControlMessage
				if phase == protocolmldsa65.ReshareConsistencyPhaseNonceCommitment {
					replayed, err = restarted.nextTMLDSAReshareParticipantMessagesWithCoordinator(
						request,
						coordinator,
						dealerID,
						participantID,
						bytes.NewReader(bytes.Repeat([]byte{0xee}, 128)),
					)
				} else {
					replayed, err = restarted.nextTMLDSAReshareTermMessagesWithMask(
						request,
						coordinator,
						dealerID,
						participantID,
						bytes.NewReader(bytes.Repeat([]byte{0xef}, 128)),
						testTMLDSAReshareMask,
						nil,
					)
				}
				if err != nil || !reflect.DeepEqual(generated, replayed) {
					t.Fatalf("phase %v restart changed output: err=%v before=%+v after=%+v", phase, err, generated, replayed)
				}
				nodes[participantID] = restarted
			}
			messages = append(messages, generated...)
		}
		if len(messages) == 0 {
			t.Fatalf("dealer %d phase %v produced no messages", dealerID, phase)
		}
		for _, message := range messages {
			if err := applyTMLDSAReshareControlTransition(coordinator, message); err != nil {
				t.Fatalf("apply dealer %d %s from %d: %v", dealerID, message.Kind, message.SenderID, err)
			}
		}
	}
	t.Fatalf("dealer %d did not finish consistency checks", dealerID)
}

func testTMLDSAReshareMask(localTermSenderID, _ uint32, peerTermSenderID uint32) (int32, error) {
	if localTermSenderID == 0 || peerTermSenderID == 0 || localTermSenderID == peerTermSenderID {
		return 0, fmt.Errorf("invalid test pairwise term")
	}
	left, right := localTermSenderID, peerTermSenderID
	if left > right {
		left, right = right, left
	}
	magnitude := int32((uint64(left)*65537+uint64(right)*257)%1000000 + 1)
	if localTermSenderID < peerTermSenderID {
		return magnitude, nil
	}
	return -magnitude, nil
}

func useFastTMLDSAPersistenceCrypto(t *testing.T) {
	t.Helper()
	previousEncrypt := tmldsaEncryptPersistenceBlob
	previousDecrypt := tmldsaDecryptPersistenceBlob
	tmldsaEncryptPersistenceBlob = func(plaintext, password []byte) ([]byte, error) {
		if len(plaintext) == 0 || len(password) == 0 {
			return nil, fmt.Errorf("invalid fast persistence input")
		}
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(plaintext)
		encoded := append([]byte("QTMLDSA-TEST-PERSIST-1"), mac.Sum(nil)...)
		return append(encoded, plaintext...), nil
	}
	tmldsaDecryptPersistenceBlob = func(encoded, password []byte) ([]byte, error) {
		const header = "QTMLDSA-TEST-PERSIST-1"
		if len(password) == 0 || len(encoded) < len(header)+sha256.Size || string(encoded[:len(header)]) != header {
			return nil, fmt.Errorf("invalid fast persistence encoding")
		}
		wantMAC := encoded[len(header) : len(header)+sha256.Size]
		plaintext := encoded[len(header)+sha256.Size:]
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(plaintext)
		if !hmac.Equal(wantMAC, mac.Sum(nil)) {
			return nil, fmt.Errorf("invalid fast persistence authentication")
		}
		return append([]byte(nil), plaintext...), nil
	}
	t.Cleanup(func() {
		tmldsaEncryptPersistenceBlob = previousEncrypt
		tmldsaDecryptPersistenceBlob = previousDecrypt
	})
}
