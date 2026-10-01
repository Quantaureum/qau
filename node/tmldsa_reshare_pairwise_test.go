// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAResharePairwiseBindingSeparatesPhysicalAndLogicalSenders(t *testing.T) {
	witnessID := protocolmldsa65.ReshareDealerWitnessID(2)
	tests := []struct {
		name               string
		localParticipantID uint32
		localTermSenderID  uint32
		peerParticipantID  uint32
		peerTermSenderID   uint32
		wantErr            bool
	}{
		{name: "recipient pair", localParticipantID: 7, localTermSenderID: 7, peerParticipantID: 8, peerTermSenderID: 8},
		{name: "local dealer witness", localParticipantID: 2, localTermSenderID: witnessID, peerParticipantID: 7, peerTermSenderID: 7},
		{name: "peer dealer witness", localParticipantID: 7, localTermSenderID: 7, peerParticipantID: 2, peerTermSenderID: witnessID},
		{name: "nondealer witness", localParticipantID: 3, localTermSenderID: witnessID, peerParticipantID: 7, peerTermSenderID: 7, wantErr: true},
		{name: "recipient impersonation", localParticipantID: 7, localTermSenderID: 8, peerParticipantID: 9, peerTermSenderID: 9, wantErr: true},
		{name: "self physical edge", localParticipantID: 2, localTermSenderID: 2, peerParticipantID: 2, peerTermSenderID: witnessID, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateTMLDSAResharePairwiseBinding(
				2,
				test.localParticipantID,
				test.localTermSenderID,
				test.peerParticipantID,
				test.peerTermSenderID,
			)
			if test.wantErr && err == nil {
				t.Fatal("pairwise binding validation succeeded")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("pairwise binding validation failed: %v", err)
			}
		})
	}
}

func TestTMLDSAResharePairwiseMaskUsesAuthenticatedPQSession(t *testing.T) {
	addressA := types.Address{0x71}
	addressB := types.Address{0x72}
	exchangeA, err := consensus.NewValidatorKeyExchange(addressA)
	if err != nil {
		t.Fatal(err)
	}
	exchangeB, err := consensus.NewValidatorKeyExchange(addressB)
	if err != nil {
		t.Fatal(err)
	}
	publicA, err := exchangeA.LocalKyberPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	publicB, err := exchangeB.LocalKyberPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := exchangeA.RegisterKyberKey(addressB, publicB); err != nil {
		t.Fatal(err)
	}
	if err := exchangeB.RegisterKyberKey(addressA, publicA); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := exchangeA.InitiateSession(addressB)
	if err != nil {
		t.Fatal(err)
	}
	if err := exchangeB.CompleteSession(addressA, ciphertext); err != nil {
		t.Fatal(err)
	}

	sessionID := [32]byte{0x83}
	maskA, err := deriveTMLDSAResharePairwiseMask(
		exchangeA,
		addressB,
		sessionID,
		2,
		3,
		1,
		7,
		8,
	)
	if err != nil {
		t.Fatal(err)
	}
	maskB, err := deriveTMLDSAResharePairwiseMask(
		exchangeB,
		addressA,
		sessionID,
		2,
		3,
		1,
		8,
		7,
	)
	if err != nil {
		t.Fatal(err)
	}
	if maskA == 0 || maskA != -maskB {
		t.Fatalf("pairwise masks do not cancel: %d + %d", maskA, maskB)
	}
}
