// Quantaureum Node source, version 1.0.0.
package node

// Tests of the node-side signing executor transport: fresh messages consume
// strictly increasing sequences, retransmissions reuse the exact envelope
// bytes, and a second payload for a kind of the same slot is refused.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3SigningTransportTestBroadcast is one captured broadcast.
type tdilithium3SigningTransportTestBroadcast struct {
	messageType uint8
	payload     []byte
}

// TestTDilithium3SigningTransportSequencesAndRetransmissions requires every
// round kind to go out under the sender's next sequence with a verifiable
// binding, requires a retransmission to reuse the exact bytes without consuming
// a sequence, and requires a second payload for a kind of the same slot to be
// refused.
func TestTDilithium3SigningTransportSequencesAndRetransmissions(t *testing.T) {
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	var broadcasts []tdilithium3SigningTransportTestBroadcast
	transport, err := newTDilithium3SigningTransport(
		fixture.context, 1, fixture.signers[1],
		func(messageType uint8, payload []byte) error {
			broadcasts = append(broadcasts, tdilithium3SigningTransportTestBroadcast{
				messageType: messageType, payload: append([]byte(nil), payload...),
			})
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	kinds := []uint16{
		dilithium3v1.SigningExecutorKindCommit,
		dilithium3v1.SigningExecutorKindReveal,
		dilithium3v1.SigningExecutorKindAcceptance,
		dilithium3v1.SigningExecutorKindResponse,
	}
	for index, kind := range kinds {
		messageType, _ := tdilithium3SigningWireKind(kind)
		payload := tdilithium3SigningTestPayload(t, messageType)
		if err := transport.Send(kind, payload); err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
		if len(broadcasts) != index+1 {
			t.Fatalf("kind %d: %d broadcasts", kind, len(broadcasts))
		}
		captured := broadcasts[index]
		if captured.messageType != messageType {
			t.Fatalf("kind %d: broadcast type %d, want %d", kind, captured.messageType, messageType)
		}
		envelope, err := protocol.DecodeEnvelope(captured.payload)
		if err != nil {
			t.Fatalf("kind %d: decode: %v", kind, err)
		}
		if envelope.SenderID != 1 || envelope.Sequence != uint32(index+1) ||
			envelope.SessionID != fixture.context.SessionID {
			t.Fatalf("kind %d: envelope binding drifted: %+v", kind, envelope)
		}
		decoded, err := validateTDilithium3SigningInbound(
			messageType, captured.payload, fixture.context,
			func(senderID uint32, message, signature []byte) bool {
				return verifyTDilithium3SigningTestIdentity(t, fixture, senderID, message, signature)
			},
		)
		if err != nil {
			t.Fatalf("kind %d: inbound: %v", kind, err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("kind %d: inbound payload differs", kind)
		}
	}
	if transport.Sequence() != uint32(len(kinds)) {
		t.Fatalf("sequence %d, want %d", transport.Sequence(), len(kinds))
	}
	if err := transport.Send(kinds[0], tdilithium3SigningTestPayload(t, p2p.MsgTypeTDilithium3SigningCommit)); err == nil {
		t.Fatal("second payload for a sent kind accepted")
	}
	if err := transport.Resend(kinds[1]); err != nil {
		t.Fatalf("resend: %v", err)
	}
	if len(broadcasts) != len(kinds)+1 || !bytes.Equal(broadcasts[len(kinds)].payload, broadcasts[1].payload) {
		t.Fatal("retransmission did not reuse the exact envelope bytes")
	}
	if transport.Sequence() != uint32(len(kinds)) {
		t.Fatal("retransmission consumed a sequence")
	}
	if err := transport.Resend(0); err == nil {
		t.Fatal("unknown round kind accepted")
	}
	if err := transport.Send(0, nil); err == nil {
		t.Fatal("unknown round kind accepted")
	}
	if err := transport.Send(dilithium3v1.SigningExecutorKindCommit, []byte("garbage")); err == nil {
		t.Fatal("non-canonical payload accepted")
	}
}

// TestTDilithium3SigningTransportFailedBroadcastKeepsTheEnvelope requires a
// failed broadcast to leave a byte-identical retransmission instead of a second
// envelope with a new sequence.
func TestTDilithium3SigningTransportFailedBroadcastKeepsTheEnvelope(t *testing.T) {
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	var broadcasts []tdilithium3SigningTransportTestBroadcast
	failNext := false
	transport, err := newTDilithium3SigningTransport(
		fixture.context, 1, fixture.signers[1],
		func(messageType uint8, payload []byte) error {
			broadcasts = append(broadcasts, tdilithium3SigningTransportTestBroadcast{
				messageType: messageType, payload: append([]byte(nil), payload...),
			})
			if failNext {
				failNext = false
				return errSigningTransportTestBroadcast
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	commit := tdilithium3SigningTestPayload(t, p2p.MsgTypeTDilithium3SigningCommit)
	failNext = true
	if err := transport.Send(dilithium3v1.SigningExecutorKindCommit, commit); err != errSigningTransportTestBroadcast {
		t.Fatalf("failed broadcast: %v", err)
	}
	if err := transport.Resend(dilithium3v1.SigningExecutorKindCommit); err != nil {
		t.Fatalf("resend after a failed broadcast: %v", err)
	}
	if len(broadcasts) != 2 || !bytes.Equal(broadcasts[0].payload, broadcasts[1].payload) {
		t.Fatal("retransmission after a failed broadcast differs")
	}
	if transport.Sequence() != 1 {
		t.Fatalf("sequence %d after a failed broadcast, want 1", transport.Sequence())
	}
	reveal := tdilithium3SigningTestPayload(t, p2p.MsgTypeTDilithium3SigningReveal)
	if err := transport.Send(dilithium3v1.SigningExecutorKindReveal, reveal); err != nil {
		t.Fatalf("send after a failed broadcast: %v", err)
	}
	envelope, err := protocol.DecodeEnvelope(broadcasts[2].payload)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Sequence != 2 {
		t.Fatalf("second fresh sequence %d, want 2", envelope.Sequence)
	}
}

// TestTDilithium3SigningTransportRejectsInvalidBindings requires malformed
// transport input to be refused before any message is produced.
func TestTDilithium3SigningTransportRejectsInvalidBindings(t *testing.T) {
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	broadcast := func(uint8, []byte) error { return nil }
	if _, err := newTDilithium3SigningTransport(fixture.context, 1, nil, broadcast); err == nil {
		t.Fatal("missing identity signer accepted")
	}
	if _, err := newTDilithium3SigningTransport(fixture.context, 1, fixture.signers[1], nil); err == nil {
		t.Fatal("missing broadcast accepted")
	}
	if _, err := newTDilithium3SigningTransport(fixture.context, 2, fixture.signers[1], broadcast); err == nil {
		t.Fatal("sender outside the active set accepted")
	}
	badContext := fixture.context
	badContext.SessionID = [32]byte{}
	if _, err := newTDilithium3SigningTransport(badContext, 1, fixture.signers[1], broadcast); err == nil {
		t.Fatal("malformed context accepted")
	}
}

// errSigningTransportTestBroadcast is the injected broadcast failure.
var errSigningTransportTestBroadcast = errors.New("injected broadcast failure")
