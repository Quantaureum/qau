// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
)

func TestReshareActivationCertificateRequiresSixSignedMatchingAcknowledgements(t *testing.T) {
	key, oldCommittee := testShareIdentity(t)
	newCommittee := oldCommittee.Clone()
	newCommittee.Version++
	newCommittee.Participants = []uint32{7, 8, 9, 10, 11, 12}
	publicKeys := make(map[uint32][]byte, len(newCommittee.Participants))
	acknowledgements := make([]ReshareActivationAcknowledgement, 0, len(newCommittee.Participants))
	for _, participantID := range newCommittee.Participants {
		keyPair, err := qcrypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[participantID] = keyPair.Public.Bytes()
		acknowledgement := ReshareActivationAcknowledgement{
			SessionID:        [32]byte{0x91},
			ActivationEpoch:  42,
			Key:              key,
			OldCommittee:     oldCommittee,
			NewCommittee:     newCommittee,
			TranscriptDigest: [32]byte{0x92},
			ParticipantID:    participantID,
			CandidateDigest:  [32]byte{byte(participantID), 0x93},
		}
		message, err := acknowledgement.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		acknowledgement.IdentitySignature, err = keyPair.Private.Sign(message)
		if err != nil {
			t.Fatal(err)
		}
		if err := acknowledgement.Verify(func(gotParticipantID uint32, gotMessage, signature []byte) bool {
			return gotParticipantID == participantID && qcrypto.Verify(keyPair.Public, gotMessage, signature)
		}); err != nil {
			t.Fatalf("acknowledgement Verify(): %v", err)
		}
		if digest, err := acknowledgement.CanonicalDigest(); err != nil || digest == ([32]byte{}) {
			t.Fatalf("acknowledgement CanonicalDigest(): digest=%x err=%v", digest, err)
		}
		acknowledgements = append(acknowledgements, acknowledgement)
	}
	certificate := ReshareActivationCertificate{Acknowledgements: acknowledgements}
	verifier := func(participantID uint32, message, signature []byte) bool {
		publicKey, err := qcrypto.PublicKeyFromBytes(publicKeys[participantID])
		return err == nil && qcrypto.Verify(publicKey, message, signature)
	}
	if err := certificate.Verify(verifier); err != nil {
		t.Fatalf("Verify(): %v", err)
	}

	missing := certificate
	missing.Acknowledgements = append([]ReshareActivationAcknowledgement(nil), acknowledgements[:5]...)
	if err := missing.Verify(verifier); err == nil {
		t.Fatal("certificate without all six acknowledgements verified")
	}

	mismatched := certificate
	mismatched.Acknowledgements = append([]ReshareActivationAcknowledgement(nil), acknowledgements...)
	mismatched.Acknowledgements[5].ActivationEpoch++
	if err := mismatched.Verify(verifier); err == nil {
		t.Fatal("certificate with mismatched epoch verified")
	}

	tampered := certificate
	tampered.Acknowledgements = append([]ReshareActivationAcknowledgement(nil), acknowledgements...)
	tampered.Acknowledgements[0].TranscriptDigest[0] ^= 1
	if err := tampered.Verify(verifier); err == nil {
		t.Fatal("certificate with tampered transcript verified")
	}
}
