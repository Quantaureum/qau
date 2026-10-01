// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha3"
	"testing"

	circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareActivationInstallsOnlyAfterVerifiedDurableEpoch(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", "1")
	node := testTMLDSAJournalNode(t)
	key, oldCommittee, newCommittee, selectedDealers := testTMLDSAActivationIdentity(t)
	const recipientID uint32 = 9
	const activationEpoch uint64 = 44
	var sessionID [32]byte
	sessionID[0] = 0x94

	inbound := tmldsaInboundReshareSet{
		SessionID:           sessionID,
		KeyGeneration:       key.Generation,
		OldCommitteeVersion: oldCommittee.Version,
		NewCommitteeVersion: newCommittee.Version,
		RecipientID:         recipientID,
		Payloads:            make(map[uint32][]byte, len(selectedDealers)),
	}
	for _, dealerID := range selectedDealers {
		oldShare, err := protocolmldsa65.NewLocalShare(
			key,
			oldCommittee,
			dealerID,
			protocolmldsa65.ShareMaterial{},
		)
		if err != nil {
			t.Fatal(err)
		}
		entropy := bytes.NewReader(bytes.Repeat([]byte{byte(dealerID), 0x02, 0x03, 0x04}, 100000))
		plan, err := protocolmldsa65.NewReshareDealerPlan(
			oldShare,
			oldCommittee,
			newCommittee,
			selectedDealers,
			entropy,
		)
		if err != nil {
			t.Fatal(err)
		}
		commitments := make(map[uint32][32]byte, len(newCommittee.Participants))
		for _, targetID := range newCommittee.Participants {
			contribution, err := plan.Contribution(targetID)
			if err != nil {
				t.Fatal(err)
			}
			commitment, err := contribution.Commitment()
			if err != nil {
				t.Fatal(err)
			}
			commitments[targetID] = commitment
			if targetID == recipientID {
				payload, err := protocolmldsa65.EncodeReshareContribution(contribution)
				if err != nil {
					t.Fatal(err)
				}
				inbound.Payloads[dealerID] = payload
				if err := node.persistTMLDSAInboundResharePayload(inbound, dealerID, payload); err != nil {
					t.Fatal(err)
				}
			}
		}
		coordinator, err := protocolmldsa65.NewReshareConsistencyCoordinator(
			sessionID,
			key,
			oldCommittee,
			newCommittee,
			selectedDealers,
			dealerID,
			commitments,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
			t.Fatal(err)
		}
		completeTMLDSAConsistencyTranscript(t, coordinator, sessionID, dealerID, newCommittee.Participants)
		if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
			t.Fatal(err)
		}
	}

	prepared, err := node.prepareTMLDSAReshareActivation(
		sessionID,
		activationEpoch,
		key,
		oldCommittee,
		newCommittee,
		selectedDealers,
		recipientID,
	)
	if err != nil {
		t.Fatalf("prepare activation: %v", err)
	}
	if err := prepared.ValidateIdentity(key, newCommittee, recipientID); err != nil {
		t.Fatalf("prepared share identity: %v", err)
	}
	if _, found, err := node.loadActiveTMLDSAShare(); err != nil || found {
		t.Fatalf("prepared share became active early: found=%v err=%v", found, err)
	}
	if _, err := node.activateTMLDSAReshare(sessionID, activationEpoch, key, newCommittee, recipientID); err == nil {
		t.Fatal("reshare activated without a six-party activation certificate")
	}
	certificate, verifier := testTMLDSAReshareActivationCertificate(
		t,
		node,
		sessionID,
		activationEpoch,
		key,
		oldCommittee,
		newCommittee,
		recipientID,
	)
	if err := node.persistTMLDSAReshareActivationCertificate(certificate, verifier); err != nil {
		t.Fatalf("persist activation certificate: %v", err)
	}
	if _, err := node.activateTMLDSAReshare(sessionID, activationEpoch-1, key, newCommittee, recipientID); err == nil {
		t.Fatal("wrong epoch activated the candidate")
	}
	activated, err := node.activateTMLDSAReshare(sessionID, activationEpoch, key, newCommittee, recipientID)
	if err != nil {
		t.Fatalf("activate reshare: %v", err)
	}
	if activated.Commitment() != prepared.Commitment() {
		t.Fatal("activated share differs from prepared share")
	}

	restarted := &Node{config: node.config}
	loaded, found, err := restarted.loadActiveTMLDSAShare()
	if err != nil {
		t.Fatalf("restart active load: %v", err)
	}
	if !found || loaded.Commitment() != activated.Commitment() {
		t.Fatal("active share did not survive restart")
	}
	epochRequest, found, err := restarted.activeTMLDSAReshareRunRequest(
		activationEpoch+1,
		[]int{7, 8, 9, 10, 11, 12},
		[]int{13, 14, 15, 16, 17, 18},
		4,
	)
	if err != nil || !found {
		t.Fatalf("active v1 reshare request: found=%v err=%v", found, err)
	}
	if epochRequest.Key.Generation != key.Generation || epochRequest.OldCommittee.Version != newCommittee.Version {
		t.Fatal("active v1 reshare request used the wrong generation")
	}
}

func testTMLDSAReshareActivationCertificate(
	t *testing.T,
	node *Node,
	sessionID [32]byte,
	activationEpoch uint64,
	key protocol.ThresholdKeyID,
	oldCommittee protocol.CommitteeID,
	newCommittee protocol.CommitteeID,
	localParticipantID uint32,
) (protocolmldsa65.ReshareActivationCertificate, protocolmldsa65.ReshareIdentityVerifier) {
	t.Helper()
	candidateDigest, transcriptDigest, err := node.tmldsaReshareActivationEvidence(sessionID, localParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	publicKeys := make(map[uint32][]byte, len(newCommittee.Participants))
	acknowledgements := make([]protocolmldsa65.ReshareActivationAcknowledgement, 0, len(newCommittee.Participants))
	for _, participantID := range newCommittee.Participants {
		keyPair, err := qcrypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[participantID] = keyPair.Public.Bytes()
		participantCandidateDigest := sha3.Sum256([]byte{byte(participantID), 0xa5})
		if participantID == localParticipantID {
			participantCandidateDigest = candidateDigest
		}
		acknowledgement := protocolmldsa65.ReshareActivationAcknowledgement{
			SessionID:        sessionID,
			ActivationEpoch:  activationEpoch,
			Key:              key,
			OldCommittee:     oldCommittee,
			NewCommittee:     newCommittee,
			TranscriptDigest: transcriptDigest,
			ParticipantID:    participantID,
			CandidateDigest:  participantCandidateDigest,
		}
		message, err := acknowledgement.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		acknowledgement.IdentitySignature, err = keyPair.Private.Sign(message)
		if err != nil {
			t.Fatal(err)
		}
		acknowledgements = append(acknowledgements, acknowledgement)
	}
	verifier := func(participantID uint32, message, signature []byte) bool {
		publicKey, err := qcrypto.PublicKeyFromBytes(publicKeys[participantID])
		return err == nil && qcrypto.Verify(publicKey, message, signature)
	}
	return protocolmldsa65.ReshareActivationCertificate{Acknowledgements: acknowledgements}, verifier
}

func completeTMLDSAConsistencyTranscript(
	t *testing.T,
	coordinator *protocolmldsa65.ReshareConsistencyCoordinator,
	sessionID [32]byte,
	dealerID uint32,
	participants []uint32,
) {
	t.Helper()
	agreement := coordinator.ContributionSetDigest()
	for _, participantID := range participants {
		if err := coordinator.RecordContributionAgreement(participantID, agreement); err != nil {
			t.Fatal(err)
		}
	}
	nonces := make(map[uint32][32]byte, len(participants))
	for _, participantID := range participants {
		nonce := sha3.Sum256([]byte{byte(dealerID), byte(participantID), 0x37})
		nonces[participantID] = nonce
		commitment := protocolmldsa65.CommitReshareConsistencyNonce(sessionID, dealerID, participantID, nonce)
		if err := coordinator.RecordNonceCommitment(participantID, commitment); err != nil {
			t.Fatal(err)
		}
	}
	for _, participantID := range participants {
		if err := coordinator.RecordNonceReveal(participantID, nonces[participantID]); err != nil {
			t.Fatal(err)
		}
	}
	for round := uint32(0); round < protocolmldsa65.ReshareConsistencyRounds; round++ {
		for checkID := uint32(0); checkID < protocolmldsa65.ReshareConsistencyChecksPerRound; checkID++ {
			senders := append([]uint32(nil), participants...)
			if checkID == protocolmldsa65.ReshareConsistencyChecksPerRound-1 {
				senders = append(senders, protocolmldsa65.ReshareDealerWitnessID(dealerID))
			}
			reveals := make(map[uint32]protocolmldsa65.ReshareMaskedTermReveal, len(senders))
			for _, senderID := range senders {
				salt := sha3.Sum256([]byte{byte(dealerID), byte(round), byte(checkID), byte(senderID), 0x81})
				commitment, err := protocolmldsa65.CommitReshareMaskedTerm(
					sessionID,
					dealerID,
					round,
					checkID,
					senderID,
					0,
					salt,
				)
				if err != nil {
					t.Fatal(err)
				}
				reveals[senderID] = protocolmldsa65.ReshareMaskedTermReveal{SenderID: senderID, Salt: salt}
				if err := coordinator.RecordMaskedTermCommitment(senderID, commitment); err != nil {
					t.Fatal(err)
				}
			}
			for _, senderID := range senders {
				if err := coordinator.RecordMaskedTermReveal(reveals[senderID]); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if coordinator.Phase() != protocolmldsa65.ReshareConsistencyPhaseVerified {
		t.Fatalf("consistency phase = %v", coordinator.Phase())
	}
}

func testTMLDSAActivationIdentity(t *testing.T) (
	protocol.ThresholdKeyID,
	protocol.CommitteeID,
	protocol.CommitteeID,
	[]uint32,
) {
	t.Helper()
	var seed [circlmldsa65.SeedSize]byte
	seed[0] = 0x62
	publicKey, _ := circlmldsa65.NewKeyFromSeed(&seed)
	return protocol.ThresholdKeyID{
			Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
			Generation: 12,
			PublicKey:  publicKey.Bytes(),
		}, protocol.CommitteeID{
			Version:      31,
			Threshold:    4,
			Participants: []uint32{1, 2, 3, 4, 5, 6},
		}, protocol.CommitteeID{
			Version:      32,
			Threshold:    4,
			Participants: []uint32{7, 8, 9, 10, 11, 12},
		}, []uint32{1, 2, 3, 4}
}
