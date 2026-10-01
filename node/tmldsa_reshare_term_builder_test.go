// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"testing"

	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareTermBuilderIncludesRecipientAndDealerWitnessMasks(t *testing.T) {
	key, oldCommittee, newCommittee, selectedDealers := testTMLDSAActivationIdentity(t)
	request := tmldsaReshareRunRequest{
		SessionID:       [32]byte{0x66},
		ActivationEpoch: 61,
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
		bytes.NewReader(bytes.Repeat([]byte{0x67}, 100000)),
	)
	if err != nil {
		t.Fatal(err)
	}
	contribution, err := plan.Contribution(7)
	if err != nil {
		t.Fatal(err)
	}
	seed := [32]byte{0x68}
	var recipientPeers []uint32
	recipientTerm, err := computeTMLDSAReshareRecipientTerm(
		request,
		1,
		7,
		0,
		2,
		seed,
		contribution,
		func(localTermSenderID, peerParticipantID, peerTermSenderID uint32) (int32, error) {
			recipientPeers = append(recipientPeers, peerTermSenderID)
			return 0, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := contribution.LinearProjection(seed, 0)
	if err != nil {
		t.Fatal(err)
	}
	coefficients, err := protocolmldsa65.ReshareConstantCheckCoefficients(newCommittee.Participants)
	if err != nil {
		t.Fatal(err)
	}
	wantRecipient := protocolmldsa65.MaskedLinearTerm(projection, coefficients[0], 0)
	if recipientTerm != wantRecipient || len(recipientPeers) != 6 ||
		recipientPeers[len(recipientPeers)-1] != protocolmldsa65.ReshareDealerWitnessID(1) {
		t.Fatalf("recipient term=%d peers=%v", recipientTerm, recipientPeers)
	}

	var witnessPeers []uint32
	witnessTerm, err := computeTMLDSAReshareDealerWitnessTerm(
		request,
		1,
		0,
		seed,
		oldShare,
		func(localTermSenderID, peerParticipantID, peerTermSenderID uint32) (int32, error) {
			witnessPeers = append(witnessPeers, peerTermSenderID)
			return 0, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	oldProjection, err := oldShare.LinearProjection(seed, 0)
	if err != nil {
		t.Fatal(err)
	}
	witnessCoefficient, err := protocolmldsa65.ReshareDealerConstantCheckCoefficient(1, selectedDealers)
	if err != nil {
		t.Fatal(err)
	}
	wantWitness := protocolmldsa65.MaskedLinearTerm(oldProjection, witnessCoefficient, 0)
	if witnessTerm != wantWitness || len(witnessPeers) != 6 {
		t.Fatalf("witness term=%d peers=%v", witnessTerm, witnessPeers)
	}
}
