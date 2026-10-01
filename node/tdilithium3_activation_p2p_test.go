// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGSignedActivationReceipts(t *testing.T) {
	runners, transport := testTDilithium3DKGRunners(t)
	results, err := runTDilithium3DKGCluster(context.Background(), runners, transport, tdilithium3DKGFaultPlan{})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroTDilithium3DKGResults(&results)
	session := runners[0].session
	keys := make(map[uint32]*mode3.PublicKey, len(runners))
	packets := make([][]byte, len(runners))
	for position := range runners {
		publicKey, privateKey, err := mode3.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[session.Committee.Participants[position]] = publicKey
		sign := func(message []byte) ([]byte, error) {
			signature := make([]byte, mode3.SignatureSize)
			mode3.SignTo(privateKey, message, signature)
			return signature, nil
		}
		packets[len(runners)-1-position], err = encodeTDilithium3DKGActivationEnvelope(session, results[position].Share, sign)
		if err != nil {
			t.Fatal(err)
		}
	}
	verifier := dilithium3v1.DKGIdentityVerifier(func(participantID uint32, message, signature []byte) bool {
		publicKey := keys[participantID]
		return publicKey != nil && mode3.Verify(publicKey, message, signature)
	})
	certificate, err := assembleTDilithium3DKGActivationCertificate(session, results[0].PublicKey, results[0].TranscriptDigest, packets, verifier)
	if err != nil {
		t.Fatal(err)
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for position, runner := range runners {
		if err := runner.shareStore.ActivateCandidate(certificate, sessionDigest, session.ActivationEpoch, verifier, runner.password); err != nil {
			t.Fatalf("participant %d activation: %v", position, err)
		}
		loaded, err := newThresholdShareStore(runner.basePath).LoadActiveAtEpoch(session.ActivationEpoch, verifier, runner.password)
		if err != nil {
			t.Fatalf("participant %d restart: %v", position, err)
		}
		if loaded.ParticipantID != session.Committee.Participants[position] {
			t.Fatal("activated wrong participant")
		}
		loaded.Zeroize()
		if err := p2p.ValidateTDilithium3DKGEnvelope(p2p.MsgTypeTDilithium3DKGActivation, packets[position]); err != nil {
			t.Fatalf("P2P rejected signed activation: %v", err)
		}
	}
	if _, err := assembleTDilithium3DKGActivationCertificate(session, results[0].PublicKey, results[0].TranscriptDigest, packets[:5], verifier); err == nil {
		t.Fatal("five receipts activated six-party committee")
	}
	duplicate := append([][]byte(nil), packets...)
	duplicate[0] = packets[1]
	if _, err := assembleTDilithium3DKGActivationCertificate(session, results[0].PublicKey, results[0].TranscriptDigest, duplicate, verifier); err == nil {
		t.Fatal("duplicate signer accepted")
	}
	forged := append([][]byte(nil), packets...)
	envelope, err := protocol.DecodeEnvelope(forged[0])
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload[33] ^= 1
	forged[0], err = protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assembleTDilithium3DKGActivationCertificate(session, results[0].PublicKey, results[0].TranscriptDigest, forged, verifier); err == nil {
		t.Fatal("tampered candidate digest accepted")
	}
	other := session.Clone()
	other.Nonce[0] ^= 1
	if _, err := assembleTDilithium3DKGActivationCertificate(other, results[0].PublicKey, results[0].TranscriptDigest, packets, verifier); err == nil {
		t.Fatal("foreign session accepted")
	}
}
