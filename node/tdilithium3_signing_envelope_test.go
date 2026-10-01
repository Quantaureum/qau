// Quantaureum Node source, version 1.0.0.
package node

// Tests of the node-side signing executor envelope layer: the outbound builder
// signs exactly the p2p-validated binding, and the inbound verifier rejects
// every message that is not bound to the signing context and its sender.

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3SigningTestContext returns one signing execution binding.
func tdilithium3SigningTestContext() tdilithium3SigningContext {
	return tdilithium3SigningContext{
		SessionID:        [32]byte{0x51, 0x55},
		KeyGeneration:    7,
		CommitteeVersion: 2,
		Signers:          [4]uint32{3, 5, 8, 13},
	}
}

// tdilithium3SigningTestPayload returns a canonical round payload of one kind.
func tdilithium3SigningTestPayload(t *testing.T, messageType uint8) []byte {
	t.Helper()
	var (
		payload []byte
		err     error
	)
	switch messageType {
	case p2p.MsgTypeTDilithium3SigningCommit:
		payload, err = dilithium3v1.EncodeSigningExecutorCommit(1, [32]byte{0x51})
	case p2p.MsgTypeTDilithium3SigningReveal:
		payload, err = dilithium3v1.EncodeSigningExecutorReveal(1, dilithium3v1.VectorK{})
	case p2p.MsgTypeTDilithium3SigningAcceptance:
		payload, err = dilithium3v1.EncodeSigningExecutorAcceptance(1, true)
	case p2p.MsgTypeTDilithium3SigningResponse:
		payload, err = dilithium3v1.EncodeSigningExecutorResponse(1, [5]dilithium3v1.SignedPoly{})
	default:
		t.Fatalf("unsupported signing message type %d", messageType)
	}
	if err != nil {
		t.Fatalf("encoding signing payload for %d: %v", messageType, err)
	}
	return payload
}

// tdilithium3SigningTestIdentity returns a deterministic DEVNET ONLY identity
// key pair and the verifier bound to one participant identity.
func tdilithium3SigningTestIdentity(
	t *testing.T,
	participantID uint32,
) (func([]byte) ([]byte, error), tdilithium3SigningIdentityVerifier) {
	t.Helper()
	var seed [mode3.SeedSize]byte
	copy(seed[:], []byte("DEVNET ONLY signing envelope fixture"))
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	sign := func(message []byte) ([]byte, error) {
		signature := make([]byte, mode3.SignatureSize)
		mode3.SignTo(privateKey, message, signature)
		return signature, nil
	}
	verifier := func(senderID uint32, signingBytes, signature []byte) bool {
		return senderID == participantID && mode3.Verify(publicKey, signingBytes, signature)
	}
	return sign, verifier
}

// TestTDilithium3SigningEnvelopeRoundTrip requires every signing round kind to
// survive the signed outbound and the verified inbound with its payload and
// binding intact.
func TestTDilithium3SigningEnvelopeRoundTrip(t *testing.T) {
	context := tdilithium3SigningTestContext()
	sign, verifier := tdilithium3SigningTestIdentity(t, 5)
	for _, messageType := range []uint8{
		p2p.MsgTypeTDilithium3SigningCommit,
		p2p.MsgTypeTDilithium3SigningReveal,
		p2p.MsgTypeTDilithium3SigningAcceptance,
		p2p.MsgTypeTDilithium3SigningResponse,
	} {
		payload := tdilithium3SigningTestPayload(t, messageType)
		encoded, err := encodeTDilithium3SigningEnvelope(context, messageType, 5, 3, payload, sign)
		if err != nil {
			t.Fatalf("kind %d: encode: %v", messageType, err)
		}
		envelope, err := protocol.DecodeEnvelope(encoded)
		if err != nil {
			t.Fatalf("kind %d: decode: %v", messageType, err)
		}
		if envelope.SenderID != 5 || envelope.Sequence != 3 ||
			envelope.KeyGeneration != context.KeyGeneration ||
			envelope.CommitteeVersion != context.CommitteeVersion ||
			envelope.SessionID != context.SessionID {
			t.Fatalf("kind %d: envelope binding drifted", messageType)
		}
		decoded, err := validateTDilithium3SigningInbound(messageType, encoded, context, verifier)
		if err != nil {
			t.Fatalf("kind %d: inbound: %v", messageType, err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("kind %d: inbound payload differs", messageType)
		}
	}
}

// TestTDilithium3SigningEnvelopeRejections requires the outbound builder and
// the inbound verifier to reject every envelope that is not canonically bound
// to the context and its sender.
func TestTDilithium3SigningEnvelopeRejections(t *testing.T) {
	context := tdilithium3SigningTestContext()
	sign, verifier := tdilithium3SigningTestIdentity(t, 5)
	kind := p2p.MsgTypeTDilithium3SigningCommit
	payload := tdilithium3SigningTestPayload(t, kind)
	valid, err := encodeTDilithium3SigningEnvelope(context, kind, 5, 3, payload, sign)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if _, err := encodeTDilithium3SigningEnvelope(context, kind, 4, 3, payload, sign); err == nil {
		t.Fatal("sender outside the active set accepted")
	}
	if _, err := encodeTDilithium3SigningEnvelope(context, kind, 5, 0, payload, sign); err == nil {
		t.Fatal("zero sequence accepted")
	}
	if _, err := encodeTDilithium3SigningEnvelope(context, kind, 5, 3, payload, nil); err == nil {
		t.Fatal("missing signer accepted")
	}
	if _, err := encodeTDilithium3SigningEnvelope(context, kind, 5, 3, []byte("garbage"), sign); err == nil {
		t.Fatal("non-canonical payload accepted")
	}
	if _, err := encodeTDilithium3SigningEnvelope(context, 101, 5, 3, payload, sign); err == nil {
		t.Fatal("unknown message type accepted")
	}
	if _, err := encodeTDilithium3SigningEnvelope(context, kind, 5, 3, payload, func([]byte) ([]byte, error) {
		return []byte{1}, nil
	}); err == nil {
		t.Fatal("wrong-size identity signature accepted")
	}
	badContexts := []tdilithium3SigningContext{
		{KeyGeneration: 1, CommitteeVersion: 1, Signers: context.Signers},
		{SessionID: context.SessionID, CommitteeVersion: 1, Signers: context.Signers},
		{SessionID: context.SessionID, KeyGeneration: 1, Signers: context.Signers},
		{SessionID: context.SessionID, KeyGeneration: 1, CommitteeVersion: 1},
		{SessionID: context.SessionID, KeyGeneration: 1, CommitteeVersion: 1, Signers: [4]uint32{3, 3, 8, 13}},
	}
	for index, badContext := range badContexts {
		if _, err := encodeTDilithium3SigningEnvelope(badContext, kind, 5, 3, payload, sign); err == nil {
			t.Fatalf("malformed context %d accepted", index)
		}
	}

	if _, err := validateTDilithium3SigningInbound(kind, valid, context, nil); err == nil {
		t.Fatal("missing verifier accepted")
	}
	if _, err := validateTDilithium3SigningInbound(p2p.MsgTypeTDilithium3SigningReveal, valid, context, verifier); err == nil {
		t.Fatal("message type mismatch accepted")
	}
	envelope, err := protocol.DecodeEnvelope(valid)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := envelope
	unsigned.IdentitySignature = make([]byte, mode3.SignatureSize)
	encoded, err := protocol.EncodeEnvelope(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateTDilithium3SigningInbound(kind, encoded, context, verifier); err == nil {
		t.Fatal("unsigned envelope accepted")
	}
	tampered := envelope
	tampered.IdentitySignature = append([]byte(nil), envelope.IdentitySignature...)
	tampered.IdentitySignature[0] ^= 1
	encoded, err = protocol.EncodeEnvelope(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateTDilithium3SigningInbound(kind, encoded, context, verifier); err == nil {
		t.Fatal("tampered identity signature accepted")
	}
	foreign := context
	foreign.SessionID = [32]byte{0x99}
	if _, err := validateTDilithium3SigningInbound(kind, valid, foreign, verifier); err == nil {
		t.Fatal("foreign session accepted")
	}
	outsider := envelope
	outsider.SenderID = 42
	encoded, err = protocol.EncodeEnvelope(outsider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateTDilithium3SigningInbound(kind, encoded, context, verifier); err == nil {
		t.Fatal("sender outside the active set accepted")
	}
	tamperedPayload := envelope
	tamperedPayload.Payload = append([]byte(nil), envelope.Payload...)
	tamperedPayload.Payload[8] = 0
	tamperedPayload.Payload[9] = 0
	encoded, err = protocol.EncodeEnvelope(tamperedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateTDilithium3SigningInbound(kind, encoded, context, verifier); err == nil {
		t.Fatal("zero-slot payload accepted")
	}
}
