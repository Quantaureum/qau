// Quantaureum Node source, version 1.0.0.
package node

import (
	"crypto/sha3"
	"testing"

	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareControlSeparatesPhysicalAndLogicalTermSenders(t *testing.T) {
	witnessID := protocolmldsa65.ReshareDealerWitnessID(1)
	tests := []struct {
		name    string
		message tmldsaReshareControlMessage
		wantErr bool
	}{
		{
			name: "recipient term",
			message: tmldsaReshareControlMessage{
				Protocol:     tmldsaReshareControlProtocol,
				Kind:         tmldsaReshareControlTermCommitment,
				SessionID:    [32]byte{0x71},
				DealerID:     1,
				SenderID:     7,
				TermSenderID: 7,
				Value:        [32]byte{0x72},
			},
		},
		{
			name: "dealer witness",
			message: tmldsaReshareControlMessage{
				Protocol:     tmldsaReshareControlProtocol,
				Kind:         tmldsaReshareControlTermCommitment,
				SessionID:    [32]byte{0x71},
				DealerID:     1,
				SenderID:     1,
				TermSenderID: witnessID,
				Value:        [32]byte{0x72},
			},
		},
		{
			name: "recipient impersonates witness",
			message: tmldsaReshareControlMessage{
				Protocol:     tmldsaReshareControlProtocol,
				Kind:         tmldsaReshareControlTermCommitment,
				SessionID:    [32]byte{0x71},
				DealerID:     1,
				SenderID:     7,
				TermSenderID: witnessID,
				Value:        [32]byte{0x72},
			},
			wantErr: true,
		},
		{
			name: "recipient impersonates peer",
			message: tmldsaReshareControlMessage{
				Protocol:     tmldsaReshareControlProtocol,
				Kind:         tmldsaReshareControlTermReveal,
				SessionID:    [32]byte{0x71},
				DealerID:     1,
				SenderID:     7,
				TermSenderID: 8,
				Salt:         [32]byte{0x73},
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.message.validate()
			if test.wantErr && err == nil {
				t.Fatal("message validation succeeded")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("message validation failed: %v", err)
			}
		})
	}
}

func TestTMLDSAReshareControlBindsAbortEvidenceReporter(t *testing.T) {
	key, oldCommittee, newCommittee, _ := testTMLDSAActivationIdentity(t)
	evidence := protocolmldsa65.SignedReshareAbortEvidence{
		SessionID:         [32]byte{0x75},
		Key:               key,
		OldCommittee:      oldCommittee,
		NewCommittee:      newCommittee,
		DealerID:          1,
		ReporterID:        7,
		IdentitySignature: []byte{0x76},
		Evidence: protocolmldsa65.ReshareAbortEvidence{
			Reason:       protocolmldsa65.ReshareAbortReasonTimeout,
			Round:        1,
			CheckID:      2,
			DetailDigest: [32]byte{0x77},
		},
	}
	message := tmldsaReshareControlMessage{
		Protocol:      tmldsaReshareControlProtocol,
		Kind:          tmldsaReshareControlAbortEvidence,
		SessionID:     evidence.SessionID,
		DealerID:      evidence.DealerID,
		SenderID:      evidence.ReporterID,
		AbortEvidence: &evidence,
	}
	if err := message.validate(); err != nil {
		t.Fatalf("valid abort evidence rejected: %v", err)
	}
	message.SenderID++
	if err := message.validate(); err == nil {
		t.Fatal("abort evidence reporter impersonation accepted")
	}
}

func TestTMLDSAReshareControlBindsActivationAcknowledgementSender(t *testing.T) {
	key, oldCommittee, newCommittee, _ := testTMLDSAActivationIdentity(t)
	acknowledgement := protocolmldsa65.ReshareActivationAcknowledgement{
		SessionID:         [32]byte{0x78},
		ActivationEpoch:   52,
		Key:               key,
		OldCommittee:      oldCommittee,
		NewCommittee:      newCommittee,
		TranscriptDigest:  [32]byte{0x79},
		ParticipantID:     7,
		CandidateDigest:   [32]byte{0x7a},
		IdentitySignature: []byte{0x7b},
	}
	message := tmldsaReshareControlMessage{
		Protocol:      tmldsaReshareControlProtocol,
		Kind:          tmldsaReshareControlActivationAck,
		SessionID:     acknowledgement.SessionID,
		DealerID:      1,
		SenderID:      acknowledgement.ParticipantID,
		ActivationAck: &acknowledgement,
	}
	if err := message.validate(); err != nil {
		t.Fatalf("valid activation acknowledgement rejected: %v", err)
	}
	message.SenderID++
	if err := message.validate(); err == nil {
		t.Fatal("activation acknowledgement sender impersonation accepted")
	}
}

func TestTMLDSAReshareControlAppliesOnlyThroughDurableState(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", "1")
	node := testTMLDSAJournalNode(t)
	key, oldCommittee, newCommittee, selectedDealers := testTMLDSAActivationIdentity(t)
	commitments := make([]tmldsaReshareControlCommitment, 0, len(newCommittee.Participants))
	for _, participantID := range newCommittee.Participants {
		commitments = append(commitments, tmldsaReshareControlCommitment{
			RecipientID: participantID,
			Commitment:  sha3.Sum256([]byte{byte(participantID), 0xa7}),
		})
	}
	message := tmldsaReshareControlMessage{
		Protocol:          tmldsaReshareControlProtocol,
		Kind:              tmldsaReshareControlContributionSet,
		SessionID:         [32]byte{0x51},
		Key:               key,
		OldCommittee:      oldCommittee,
		NewCommittee:      newCommittee,
		SelectedDealers:   selectedDealers,
		DealerID:          1,
		SenderID:          1,
		ContributionHeads: commitments,
	}
	encoded, err := encodeTMLDSAReshareControlMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeTMLDSAReshareControlMessage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.applyTMLDSAReshareControlMessage(decoded); err != nil {
		t.Fatalf("apply contribution set: %v", err)
	}
	state, found, err := node.loadTMLDSAReshareConsistencyState(message.SessionID, message.DealerID)
	if err != nil || !found {
		t.Fatalf("load contribution state: found=%v err=%v", found, err)
	}
	agreement := state.ContributionSetDigest()
	if err := node.applyTMLDSAReshareControlMessage(tmldsaReshareControlMessage{
		Protocol:  tmldsaReshareControlProtocol,
		Kind:      tmldsaReshareControlAgreement,
		SessionID: message.SessionID,
		DealerID:  message.DealerID,
		SenderID:  7,
		Value:     agreement,
	}); err != nil {
		t.Fatalf("apply agreement: %v", err)
	}
	restored, found, err := node.loadTMLDSAReshareConsistencyState(message.SessionID, message.DealerID)
	if err != nil || !found || restored.EventCount() != 1 {
		t.Fatalf("agreement was not durable: found=%v events=%d err=%v", found, restored.EventCount(), err)
	}
}
