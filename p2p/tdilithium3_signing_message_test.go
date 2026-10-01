// Quantaureum Node source, version 1.0.0.
package p2p

// Tests of the Dilithium3 v1 signing executor P2P kinds: the four round
// messages validate inside the shared threshold envelope, have a TSS route, and
// are exempt from content-hash dedup exactly like the DKG family.

import (
	"errors"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// signingExecutorTestKinds returns the four signing executor message types.
func signingExecutorTestKinds() []uint8 {
	return []uint8{
		MsgTypeTDilithium3SigningCommit,
		MsgTypeTDilithium3SigningReveal,
		MsgTypeTDilithium3SigningAcceptance,
		MsgTypeTDilithium3SigningResponse,
	}
}

// signingExecutorTestPayload returns a canonical round payload of one signing
// executor kind.
func signingExecutorTestPayload(t *testing.T, messageType uint8) []byte {
	t.Helper()
	var (
		payload []byte
		err     error
	)
	switch messageType {
	case MsgTypeTDilithium3SigningCommit:
		payload, err = dilithium3v1.EncodeSigningExecutorCommit(1, [32]byte{0x51})
	case MsgTypeTDilithium3SigningReveal:
		payload, err = dilithium3v1.EncodeSigningExecutorReveal(1, dilithium3v1.VectorK{})
	case MsgTypeTDilithium3SigningAcceptance:
		payload, err = dilithium3v1.EncodeSigningExecutorAcceptance(1, true)
	case MsgTypeTDilithium3SigningResponse:
		payload, err = dilithium3v1.EncodeSigningExecutorResponse(1, [5]dilithium3v1.SignedPoly{})
	default:
		t.Fatalf("unsupported signing executor message type %d", messageType)
	}
	if err != nil {
		t.Fatalf("encoding signing executor payload for %d: %v", messageType, err)
	}
	return payload
}

// TestTDilithium3SigningMessageKindsValidateAndRoute requires every signing
// executor kind to pass format validation and to have a TSS route.
func TestTDilithium3SigningMessageKindsValidateAndRoute(t *testing.T) {
	host := &Host{protocolRegistry: NewProtocolRegistry(), tssCh: make(chan PeerMessage, 4)}
	host.registerProtocols()
	for _, messageType := range signingExecutorTestKinds() {
		payload := testTDilithium3Envelope(t, messageType, signingExecutorTestPayload(t, messageType))
		message := &Message{Type: messageType, From: PeerID("validator-101"), Payload: payload}
		if err := ValidateMessage(message); err != nil {
			t.Fatalf("message type %d rejected: %v", messageType, err)
		}
		if err := host.protocolRegistry.RouteMessage(message); err != nil {
			t.Fatalf("message type %d has no TSS route: %v", messageType, err)
		}
	}
}

// TestTDilithium3SigningEnvelopeRejections requires the validator to pin the
// envelope context, the message type, the identity signature size, and the
// canonical payload of the round.
func TestTDilithium3SigningEnvelopeRejections(t *testing.T) {
	kind := MsgTypeTDilithium3SigningCommit
	valid := testTDilithium3Envelope(t, kind, signingExecutorTestPayload(t, kind))
	if err := ValidateTDilithium3SigningEnvelope(kind, valid); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	wrongProtocol := protocol.ThresholdEnvelope{
		ProtocolVersion:   protocol.ThresholdProtocolVersionV1,
		Protocol:          protocol.ThresholdProtocolMLDSA65ExperimentalV1,
		Algorithm:         qcrypto.SignatureAlgorithmMLDSA65,
		MessageType:       uint16(kind),
		KeyGeneration:     1,
		CommitteeVersion:  1,
		SessionID:         [32]byte{1},
		SenderID:          101,
		Sequence:          1,
		Payload:           signingExecutorTestPayload(t, kind),
		IdentitySignature: []byte{1},
	}
	encoded, err := protocol.EncodeEnvelope(wrongProtocol)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTDilithium3SigningEnvelope(kind, encoded); err == nil {
		t.Fatal("wrong threshold protocol accepted")
	}

	// A payload of another round behind the same message type, and a message
	// type that does not match the envelope, are both rejected.
	crossed := testTDilithium3Envelope(t, kind, signingExecutorTestPayload(t, MsgTypeTDilithium3SigningReveal))
	if err := ValidateTDilithium3SigningEnvelope(kind, crossed); err == nil {
		t.Fatal("cross-kind payload accepted")
	}
	if err := ValidateTDilithium3SigningEnvelope(MsgTypeTDilithium3SigningReveal, valid); err == nil {
		t.Fatal("envelope message type mismatch accepted")
	}

	envelope, err := protocol.DecodeEnvelope(valid)
	if err != nil {
		t.Fatal(err)
	}
	envelope.IdentitySignature = []byte{1}
	short, err := protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTDilithium3SigningEnvelope(kind, short); err == nil {
		t.Fatal("short identity signature accepted")
	}

	// The round payload carries a one-based slot; a zero slot is malformed.
	zeroSlotPayload := signingExecutorTestPayload(t, kind)
	zeroSlotPayload[8] = 0
	zeroSlotPayload[9] = 0
	zeroSlot := testTDilithium3Envelope(t, kind, zeroSlotPayload)
	if err := ValidateTDilithium3SigningEnvelope(kind, zeroSlot); err == nil {
		t.Fatal("zero slot payload accepted")
	}

	for _, size := range []int{0, protocol.MaxThresholdEnvelopePayload + 1} {
		if err := ValidateTDilithium3SigningEnvelope(kind, make([]byte, size)); err == nil {
			t.Fatalf("invalid envelope size %d accepted", size)
		}
	}
}

// TestTDilithium3SigningMessagesAreExemptFromContentHashDedup requires an
// identical retransmission of a signing round message to survive the duplicate
// window, while a type outside the exemption lists still trips it.
func TestTDilithium3SigningMessagesAreExemptFromContentHashDedup(t *testing.T) {
	validator := NewMessageValidator()
	for _, messageType := range signingExecutorTestKinds() {
		payload := testTDilithium3Envelope(t, messageType, signingExecutorTestPayload(t, messageType))
		message := &Message{Type: messageType, From: PeerID("validator-101"), Payload: payload}
		for attempt := 1; attempt <= 2; attempt++ {
			if err := validator.ValidateMessage(message); err != nil {
				t.Fatalf("message type %d retransmission %d rejected: %v", messageType, attempt, err)
			}
		}
	}
	expert := &Message{Type: MsgTypeExpert, From: PeerID("validator-101"), Payload: []byte{1}}
	if err := validator.ValidateMessage(expert); err != nil {
		t.Fatalf("first expert message rejected: %v", err)
	}
	if err := validator.ValidateMessage(expert); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("second expert message = %v, want %v", err, ErrDuplicateMessage)
	}
}
