// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"testing"

	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareParticipantDriverResumesAgreementAndNonce(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", "1")
	node := testTMLDSAJournalNode(t)
	key, oldCommittee, newCommittee, selectedDealers := testTMLDSAActivationIdentity(t)
	request := tmldsaReshareRunRequest{
		SessionID:       [32]byte{0x61},
		ActivationEpoch: 60,
		Key:             key,
		OldCommittee:    oldCommittee,
		NewCommittee:    newCommittee,
		SelectedDealers: selectedDealers,
	}
	oldShare, err := protocolmldsa65.NewLocalShare(key, oldCommittee, 1, protocolmldsa65.ShareMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := protocolmldsa65.NewReshareDealerPlan(
		oldShare,
		oldCommittee,
		newCommittee,
		selectedDealers,
		bytes.NewReader(bytes.Repeat([]byte{0x62}, 100000)),
	)
	if err != nil {
		t.Fatal(err)
	}
	commitments := make(map[uint32][32]byte, len(newCommittee.Participants))
	var localPayload []byte
	for _, recipientID := range newCommittee.Participants {
		contribution, err := plan.Contribution(recipientID)
		if err != nil {
			t.Fatal(err)
		}
		commitments[recipientID], err = contribution.Commitment()
		if err != nil {
			t.Fatal(err)
		}
		if recipientID == 7 {
			localPayload, err = protocolmldsa65.EncodeReshareContribution(contribution)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	coordinator, err := protocolmldsa65.NewReshareConsistencyCoordinator(
		request.SessionID,
		key,
		oldCommittee,
		newCommittee,
		selectedDealers,
		1,
		commitments,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatal(err)
	}
	if err := node.persistTMLDSAInboundResharePayload(tmldsaInboundReshareSet{
		SessionID:           request.SessionID,
		KeyGeneration:       key.Generation,
		OldCommitteeVersion: oldCommittee.Version,
		NewCommitteeVersion: newCommittee.Version,
		RecipientID:         7,
	}, 1, localPayload); err != nil {
		t.Fatal(err)
	}

	messages, err := node.nextTMLDSAReshareParticipantMessages(
		request,
		1,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0x63}, 128)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].Kind != tmldsaReshareControlAgreement {
		t.Fatalf("agreement messages = %+v", messages)
	}
	if err := node.applyTMLDSAReshareControlMessage(messages[0]); err != nil {
		t.Fatal(err)
	}

	coordinator, _, err = node.loadTMLDSAReshareConsistencyState(request.SessionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	agreement := coordinator.ContributionSetDigest()
	for _, participantID := range []uint32{8, 9, 10, 11, 12} {
		if err := coordinator.RecordContributionAgreement(participantID, agreement); err != nil {
			t.Fatal(err)
		}
	}
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatal(err)
	}

	first, err := node.nextTMLDSAReshareParticipantMessages(
		request,
		1,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0x64}, 128)),
	)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Node{config: node.config}
	second, err := restarted.nextTMLDSAReshareParticipantMessages(
		request,
		1,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0x65}, 128)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(second) != 1 || first[0].Kind != tmldsaReshareControlNonceCommitment ||
		first[0].Value != second[0].Value {
		t.Fatalf("nonce commitments differ: first=%+v second=%+v", first, second)
	}
	if err := node.applyTMLDSAReshareControlMessage(first[0]); err != nil {
		t.Fatal(err)
	}
	coordinator, _, err = node.loadTMLDSAReshareConsistencyState(request.SessionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	peerNonces := make(map[uint32][32]byte, 5)
	for _, participantID := range []uint32{8, 9, 10, 11, 12} {
		nonce := [32]byte{byte(participantID), 0x69}
		peerNonces[participantID] = nonce
		if err := coordinator.RecordNonceCommitment(
			participantID,
			protocolmldsa65.CommitReshareConsistencyNonce(request.SessionID, 1, participantID, nonce),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatal(err)
	}
	localReveal, err := node.nextTMLDSAReshareParticipantMessages(
		request,
		1,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0x6a}, 128)),
	)
	if err != nil || len(localReveal) != 1 || localReveal[0].Kind != tmldsaReshareControlNonceReveal {
		t.Fatalf("local nonce reveal=%+v err=%v", localReveal, err)
	}
	if err := node.applyTMLDSAReshareControlMessage(localReveal[0]); err != nil {
		t.Fatal(err)
	}
	coordinator, _, err = node.loadTMLDSAReshareConsistencyState(request.SessionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, participantID := range []uint32{8, 9, 10, 11, 12} {
		if err := coordinator.RecordNonceReveal(participantID, peerNonces[participantID]); err != nil {
			t.Fatal(err)
		}
	}
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatal(err)
	}
	termCommitment, err := node.nextTMLDSAReshareTermMessagesWithMask(
		request,
		coordinator,
		1,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0x6b}, 128)),
		func(uint32, uint32, uint32) (int32, error) { return 0, nil },
		nil,
	)
	if err != nil || len(termCommitment) != 1 || termCommitment[0].Kind != tmldsaReshareControlTermCommitment {
		t.Fatalf("term commitment=%+v err=%v", termCommitment, err)
	}
	if err := node.applyTMLDSAReshareControlMessage(termCommitment[0]); err != nil {
		t.Fatal(err)
	}
	coordinator, _, err = node.loadTMLDSAReshareConsistencyState(request.SessionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, participantID := range []uint32{8, 9, 10, 11, 12} {
		salt := [32]byte{byte(participantID), 0x6c}
		commitment, err := protocolmldsa65.CommitReshareMaskedTerm(
			request.SessionID,
			1,
			0,
			0,
			participantID,
			0,
			salt,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := coordinator.RecordMaskedTermCommitment(participantID, commitment); err != nil {
			t.Fatal(err)
		}
	}
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatal(err)
	}
	termReveal, err := node.nextTMLDSAReshareTermMessagesWithMask(
		request,
		coordinator,
		1,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0x6d}, 128)),
		func(uint32, uint32, uint32) (int32, error) { return 0, nil },
		nil,
	)
	if err != nil || len(termReveal) != 1 || termReveal[0].Kind != tmldsaReshareControlTermReveal ||
		termReveal[0].TermSenderID != 7 {
		t.Fatalf("term reveal=%+v err=%v", termReveal, err)
	}
}

func TestTMLDSAReshareDealerPreparationResumesDurablePayloads(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", "1")
	node := testTMLDSAJournalNode(t)
	key, oldCommittee, newCommittee, selectedDealers := testTMLDSAActivationIdentity(t)
	request := tmldsaReshareRunRequest{
		SessionID:       [32]byte{0x6e},
		ActivationEpoch: 62,
		Key:             key,
		OldCommittee:    oldCommittee,
		NewCommittee:    newCommittee,
		SelectedDealers: selectedDealers,
	}
	oldShare, err := protocolmldsa65.NewLocalShare(key, oldCommittee, 1, protocolmldsa65.ShareMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	firstPrivate, firstControl, err := node.prepareTMLDSAReshareDealerMessages(
		request,
		1,
		oldShare,
		bytes.NewReader(bytes.Repeat([]byte{0x6f}, 100000)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPrivate) != 6 || firstControl.Kind != tmldsaReshareControlContributionSet {
		t.Fatalf("dealer preparation private=%d control=%+v", len(firstPrivate), firstControl)
	}
	restarted := &Node{config: node.config}
	secondPrivate, secondControl, err := restarted.prepareTMLDSAReshareDealerMessages(
		request,
		1,
		oldShare,
		bytes.NewReader(bytes.Repeat([]byte{0x70}, 100000)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPrivate) != len(firstPrivate) || secondControl.ContributionHeads[0] != firstControl.ContributionHeads[0] {
		t.Fatal("restart changed durable dealer contribution set")
	}
	for index := range firstPrivate {
		if !bytes.Equal(firstPrivate[index].Payload, secondPrivate[index].Payload) {
			t.Fatalf("restart changed recipient %d payload", firstPrivate[index].RecipientID)
		}
	}
}
