// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

type reshareDeliveryPeer struct {
	send func(p2p.PeerID, uint8, []byte) error
}

func (peer *reshareDeliveryPeer) SendTSSToPeer(id p2p.PeerID, kind uint8, payload []byte) error {
	return peer.send(id, kind, payload)
}

func TestReshareDeliveryRetriesUntilAuthenticatedAcknowledgement(t *testing.T) {
	var transport *P2PReshareTransport
	attempts := 0
	peer := &reshareDeliveryPeer{send: func(_ p2p.PeerID, _ uint8, payload []byte) error {
		attempts++
		if attempts == 1 {
			return errors.New("recipient offline")
		}
		var message reshareWireMessage
		if err := json.Unmarshal(payload, &message); err != nil {
			t.Fatal(err)
		}
		if attempts == 2 {
			return nil
		}
		if message.Contribution.S1SubShare[0] != 7 {
			t.Fatal("retry changed private contribution")
		}
		if message.Attempt != uint32(attempts) {
			t.Fatal("retry reused replay identity")
		}
		transport.Acknowledge(&reshareWireMessage{SessionID: message.SessionID, FromParticipant: 4, ToParticipant: 1, Acknowledgement: true})
		return nil
	}}
	transport = NewP2PReshareTransport(peer, 1, []byte("session"))
	transport.retryInterval = time.Millisecond
	transport.SetPeerResolver(func(int) (p2p.PeerID, bool) { return "recipient", true })
	message := &reshareWireMessage{SessionID: []byte("session"), FromParticipant: 1, ToParticipant: 4,
		Contribution: &qtd.SubShare{FromParticipant: 1, ToParticipant: 4, S1SubShare: []byte{7}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := transport.Deliver(ctx, []*reshareWireMessage{message}); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("got %d attempts", attempts)
	}
}

func TestReshareDeliveryRejectsWrongSessionAcknowledgement(t *testing.T) {
	var transport *P2PReshareTransport
	peer := &reshareDeliveryPeer{send: func(_ p2p.PeerID, _ uint8, _ []byte) error {
		transport.Acknowledge(&reshareWireMessage{SessionID: []byte("old"), FromParticipant: 4, ToParticipant: 1, Acknowledgement: true})
		transport.Acknowledge(&reshareWireMessage{SessionID: []byte("session"), FromParticipant: 5, ToParticipant: 1, Acknowledgement: true})
		return nil
	}}
	transport = NewP2PReshareTransport(peer, 1, []byte("session"))
	transport.retryInterval = time.Millisecond
	transport.SetPeerResolver(func(int) (p2p.PeerID, bool) { return "recipient", true })
	message := &reshareWireMessage{SessionID: []byte("session"), FromParticipant: 1, ToParticipant: 4,
		Contribution: &qtd.SubShare{FromParticipant: 1, ToParticipant: 4}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := transport.Deliver(ctx, []*reshareWireMessage{message}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected bounded timeout, got %v", err)
	}
}

func TestReshareBufferDeduplicatesRetriesAndRejectsConflicts(t *testing.T) {
	node := &Node{}
	message := &reshareWireMessage{SessionID: []byte("session"), FromParticipant: 1, ToParticipant: 4,
		Contribution: &qtd.SubShare{FromParticipant: 1, ToParticipant: 4, S1SubShare: []byte{7}}}
	if !node.bufferReshareMessage(message) {
		t.Fatal("first contribution rejected")
	}
	size := node.resharePendingBytes
	retry := *message
	retry.Attempt = 2
	if !node.bufferReshareMessage(&retry) {
		t.Fatal("identical retry rejected")
	}
	if node.resharePendingBytes != size || len(node.resharePending["session"]) != 1 {
		t.Fatal("retry exhausted buffer capacity")
	}
	retry.Contribution = &qtd.SubShare{FromParticipant: 1, ToParticipant: 4, S1SubShare: []byte{8}}
	if node.bufferReshareMessage(&retry) {
		t.Fatal("conflicting retry accepted")
	}
	transport := NewP2PReshareTransport(nil, 4, []byte("session"))
	node.attachReshareTransport(transport)
	if node.resharePendingBytes != 0 || len(node.resharePending) != 0 {
		t.Fatal("attached session remained buffered")
	}
	if !transport.Ingest(message) || transport.Ingest(&retry) {
		t.Fatal("active transport mishandled duplicate contributions")
	}
	foreign := *message
	foreign.SessionID = []byte("another-session")
	if transport.Ingest(&foreign) {
		t.Fatal("accepted a foreign session")
	}
}

func TestReshareAcknowledgementRequiresAuthenticatedPeer(t *testing.T) {
	transport := NewP2PReshareTransport(nil, 1, make([]byte, 32))
	transport.acknowledged[4] = false
	node := &Node{reshareTransport: transport}
	payload, err := json.Marshal(&reshareWireMessage{SessionID: make([]byte, 32), FromParticipant: 4, ToParticipant: 1, Acknowledgement: true})
	if err != nil {
		t.Fatal(err)
	}
	node.handleTSSDKGReshare(p2p.PeerMessage{From: "unknown", Payload: payload})
	if transport.acknowledged[4] {
		t.Fatal("unauthenticated peer acknowledged a private share")
	}
}

func TestReshareTransportRejectsTypedNilHost(t *testing.T) {
	var host *p2p.Host
	transport := NewP2PReshareTransport(host, 1, []byte("session"))
	transport.SetPeerResolver(func(int) (p2p.PeerID, bool) { return "recipient", true })
	message := &reshareWireMessage{SessionID: []byte("session"), FromParticipant: 1, ToParticipant: 4,
		Contribution: &qtd.SubShare{FromParticipant: 1, ToParticipant: 4}}
	if err := transport.Send(message); err == nil {
		t.Fatal("missing host accepted")
	}
}
