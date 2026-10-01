// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareActivationAcknowledgementsAssembleCertificate(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	key, oldCommittee, newCommittee, _ := testTMLDSAActivationIdentity(t)
	publicKeys := make(map[uint32][]byte, len(newCommittee.Participants))
	privateKeys := make(map[uint32]*qcrypto.PrivateKey, len(newCommittee.Participants))
	for _, participantID := range newCommittee.Participants {
		keyPair, err := qcrypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[participantID] = keyPair.Public.Bytes()
		privateKeys[participantID] = keyPair.Private
	}
	verifier := func(participantID uint32, message, signature []byte) bool {
		publicKey, err := qcrypto.PublicKeyFromBytes(publicKeys[participantID])
		return err == nil && qcrypto.Verify(publicKey, message, signature)
	}
	var complete bool
	for index, participantID := range newCommittee.Participants {
		acknowledgement := protocolmldsa65.ReshareActivationAcknowledgement{
			SessionID:        [32]byte{0xc1},
			ActivationEpoch:  51,
			Key:              key,
			OldCommittee:     oldCommittee,
			NewCommittee:     newCommittee,
			TranscriptDigest: [32]byte{0xc2},
			ParticipantID:    participantID,
			CandidateDigest:  [32]byte{byte(participantID), 0xc3},
		}
		message, err := acknowledgement.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		acknowledgement.IdentitySignature, err = privateKeys[participantID].Sign(message)
		if err != nil {
			t.Fatal(err)
		}
		complete, err = node.persistTMLDSAReshareActivationAcknowledgement(acknowledgement, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if complete != (index == len(newCommittee.Participants)-1) {
			t.Fatalf("complete after acknowledgement %d = %v", index, complete)
		}
	}
	record, found, err := node.loadTMLDSAReshareActivationCertificate([32]byte{0xc1})
	if err != nil || !found {
		t.Fatalf("load certificate: found=%v err=%v", found, err)
	}
	if err := record.Certificate.Verify(verifier); err != nil {
		t.Fatalf("assembled certificate: %v", err)
	}
}
