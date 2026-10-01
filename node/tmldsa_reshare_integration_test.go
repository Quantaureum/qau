// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"testing"

	circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareContributionJournalIntegration(t *testing.T) {
	var seed [circlmldsa65.SeedSize]byte
	seed[0] = 0x51
	publicKey, _ := circlmldsa65.NewKeyFromSeed(&seed)
	key := protocol.ThresholdKeyID{
		Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
		Generation: 6,
		PublicKey:  publicKey.Bytes(),
	}
	oldCommittee := protocol.CommitteeID{Version: 13, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}}
	newCommittee := protocol.CommitteeID{Version: 14, Threshold: 4, Participants: []uint32{7, 8, 9, 10, 11, 12}}
	selectedDealers := []uint32{1, 2, 3, 4}
	oldShare, err := protocolmldsa65.NewLocalShare(
		key,
		oldCommittee,
		1,
		protocolmldsa65.ShareMaterial{},
	)
	if err != nil {
		t.Fatalf("NewLocalShare(): %v", err)
	}
	plan, err := protocolmldsa65.NewReshareDealerPlan(
		oldShare,
		oldCommittee,
		newCommittee,
		selectedDealers,
		bytes.NewReader(bytes.Repeat([]byte{0x37, 0x91, 0x42, 0xe5}, 100000)),
	)
	if err != nil {
		t.Fatalf("NewReshareDealerPlan(): %v", err)
	}

	var sessionID [32]byte
	sessionID[0] = 0xb5
	outbound := tmldsaOutboundReshareSet{
		SessionID:           sessionID,
		KeyGeneration:       key.Generation,
		OldCommitteeVersion: oldCommittee.Version,
		NewCommitteeVersion: newCommittee.Version,
		DealerID:            1,
		Payloads:            make(map[uint32][]byte, len(newCommittee.Participants)),
	}
	for _, recipientID := range newCommittee.Participants {
		contribution, err := plan.Contribution(recipientID)
		if err != nil {
			t.Fatalf("Contribution(%d): %v", recipientID, err)
		}
		payload, err := protocolmldsa65.EncodeReshareContribution(contribution)
		if err != nil {
			t.Fatalf("EncodeReshareContribution(%d): %v", recipientID, err)
		}
		outbound.Payloads[recipientID] = payload
	}

	node := testTMLDSAJournalNode(t)
	if err := node.persistTMLDSAOutboundReshareSet(outbound); err != nil {
		t.Fatalf("persist outbound set: %v", err)
	}
	loaded, found, err := node.loadTMLDSAOutboundReshareSet(sessionID, 1, newCommittee.Participants)
	if err != nil {
		t.Fatalf("load outbound set: %v", err)
	}
	if !found {
		t.Fatal("outbound set not found")
	}
	for _, recipientID := range newCommittee.Participants {
		if _, err := protocolmldsa65.DecodeReshareContribution(
			loaded.Payloads[recipientID],
			key,
			oldCommittee,
			newCommittee,
			selectedDealers,
			1,
			recipientID,
		); err != nil {
			t.Fatalf("DecodeReshareContribution(%d): %v", recipientID, err)
		}
	}
}
