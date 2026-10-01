// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func TestDKGActivationCertificateRequiresSixIdentitySignatures(t *testing.T) {
	certificate, verifier, signers := testDKGActivationCertificate(t)
	if err := certificate.Verify(verifier); err != nil {
		t.Fatalf("valid certificate: %v", err)
	}
	first, err := certificate.CanonicalDigest()
	if err != nil || first == ([32]byte{}) {
		t.Fatalf("certificate digest: %v", err)
	}
	second, err := certificate.CanonicalDigest()
	if err != nil || first != second {
		t.Fatal("certificate digest is not deterministic")
	}
	if err := certificate.Verify(nil); !errors.Is(err, ErrInvalidDKGActivationCertificate) {
		t.Fatalf("nil verifier: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*DKGActivationCertificate)
		resign bool
	}{
		{name: "missing member", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements = value.Acknowledgements[:5] }},
		{name: "duplicate member", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements[5] = value.Acknowledgements[4] }},
		{name: "out of order", mutate: func(value *DKGActivationCertificate) {
			value.Acknowledgements[1], value.Acknowledgements[2] = value.Acknowledgements[2], value.Acknowledgements[1]
		}},
		{name: "foreign session", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements[2].SessionDigest[0] ^= 1 }, resign: true},
		{name: "foreign transcript", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements[2].TranscriptDigest[0] ^= 1 }, resign: true},
		{name: "different epoch", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements[2].ActivationEpoch++ }, resign: true},
		{name: "different generation", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements[2].Key.Generation++ }, resign: true},
		{name: "different committee", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements[2].Committee.Version++ }, resign: true},
		{name: "changed candidate digest", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements[2].CandidateDigest[0] ^= 1 }},
		{name: "changed identity signature", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements[2].IdentitySignature[0] ^= 1 }},
		{name: "missing identity signature", mutate: func(value *DKGActivationCertificate) { value.Acknowledgements[2].IdentitySignature = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := DKGActivationCertificate{Acknowledgements: make([]DKGActivationAcknowledgement, 6)}
			for index, acknowledgement := range certificate.Acknowledgements {
				acknowledgement.Key = acknowledgement.Key.Clone()
				acknowledgement.Committee = acknowledgement.Committee.Clone()
				acknowledgement.IdentitySignature = append([]byte(nil), acknowledgement.IdentitySignature...)
				changed.Acknowledgements[index] = acknowledgement
			}
			test.mutate(&changed)
			if test.resign {
				acknowledgement := &changed.Acknowledgements[2]
				message, err := acknowledgement.SigningBytes()
				if err != nil {
					t.Fatal(err)
				}
				mode3.SignTo(signers[acknowledgement.ParticipantID], message, acknowledgement.IdentitySignature)
			}
			if err := changed.Verify(verifier); !errors.Is(err, ErrInvalidDKGActivationCertificate) {
				t.Fatalf("malformed certificate error = %v", err)
			}
		})
	}
}

func TestDKGActivationCertificateBindsLocalCandidate(t *testing.T) {
	certificate, verifier, signers := testDKGActivationCertificate(t)
	acknowledgement := &certificate.Acknowledgements[2]
	share := testLocalShare(t)
	share.Key = acknowledgement.Key.Clone()
	share.Committee = acknowledgement.Committee.Clone()
	share.ParticipantID = acknowledgement.ParticipantID
	share.ActivationEpoch = acknowledgement.ActivationEpoch
	share.TranscriptDigest = acknowledgement.TranscriptDigest
	encoded, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	acknowledgement.CandidateDigest = sha3.Sum256(encoded)
	clear(encoded)
	message, err := acknowledgement.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	mode3.SignTo(signers[acknowledgement.ParticipantID], message, acknowledgement.IdentitySignature)
	if err := certificate.VerifyCandidate(share, acknowledgement.SessionDigest, verifier); err != nil {
		t.Fatalf("matching local candidate: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*LocalShare, *[32]byte)
	}{
		{name: "different session", mutate: func(_ *LocalShare, session *[32]byte) { session[0] ^= 1 }},
		{name: "different epoch", mutate: func(candidate *LocalShare, _ *[32]byte) { candidate.ActivationEpoch++ }},
		{name: "different committee", mutate: func(candidate *LocalShare, _ *[32]byte) { candidate.Committee.Version++ }},
		{name: "different key generation", mutate: func(candidate *LocalShare, _ *[32]byte) { candidate.Key.Generation++ }},
		{name: "different participant", mutate: func(candidate *LocalShare, _ *[32]byte) { candidate.ParticipantID++ }},
		{name: "different RSS component", mutate: func(candidate *LocalShare, _ *[32]byte) { candidate.Components[0].S1[0][0]++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := share.Clone()
			session := acknowledgement.SessionDigest
			test.mutate(changed, &session)
			if err := certificate.VerifyCandidate(changed, session, verifier); !errors.Is(err, ErrInvalidDKGActivationCertificate) {
				t.Fatalf("changed candidate error = %v", err)
			}
		})
	}
}

func testDKGActivationCertificate(t *testing.T) (DKGActivationCertificate, DKGIdentityVerifier, map[uint32]*mode3.PrivateKey) {
	t.Helper()
	session := testDKGSession()
	sessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	key := testLocalShare(t).Key
	key.Generation = session.KeyGeneration
	publicKeys := make(map[uint32]*mode3.PublicKey, 6)
	privateKeys := make(map[uint32]*mode3.PrivateKey, 6)
	certificate := DKGActivationCertificate{Acknowledgements: make([]DKGActivationAcknowledgement, 6)}
	for index, participantID := range session.Committee.Participants {
		publicKey, privateKey, err := mode3.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[participantID] = publicKey
		privateKeys[participantID] = privateKey
		acknowledgement := DKGActivationAcknowledgement{
			SessionDigest:     sessionDigest,
			ActivationEpoch:   session.ActivationEpoch,
			Key:               key.Clone(),
			Committee:         session.Committee.Clone(),
			TranscriptDigest:  [32]byte{1, 2, 3},
			ParticipantID:     participantID,
			CandidateDigest:   sha3.Sum256([]byte{byte(participantID), 1}),
			IdentitySignature: make([]byte, mode3.SignatureSize),
		}
		message, err := acknowledgement.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		mode3.SignTo(privateKey, message, acknowledgement.IdentitySignature)
		certificate.Acknowledgements[index] = acknowledgement
	}
	verifier := func(participantID uint32, message, signature []byte) bool {
		publicKey := publicKeys[participantID]
		return publicKey != nil && mode3.Verify(publicKey, message, signature)
	}
	return certificate, verifier, privateKeys
}
