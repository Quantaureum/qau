// Quantaureum Node source, version 1.0.0.
package p2p

// Tests of the Dilithium3 v1 proposal signing trigger wire layer (TSS-R3-B-1
// P2): the fixed-width payload bounds at the raw-frame validator, and the
// protocol routing that delivers the trigger to the TSS subscriber. The
// trigger is NOT a threshold envelope, so it must reach the node layer's
// handler before the session-id-keyed envelope routing.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// triggerPayloadOf builds one trigger payload of the requested length: the
// base layout (epoch | slot | bound | attempt) padded with extension bytes
// when the caller asks for a longer one.
func triggerPayloadOf(length int) []byte {
	payload := make([]byte, length)
	if length >= 56 {
		binary.BigEndian.PutUint64(payload[0:8], 7)
		binary.BigEndian.PutUint64(payload[8:16], 64)
		for i := 16; i < 48; i++ {
			payload[i] = byte(0x30 + i)
		}
		binary.BigEndian.PutUint64(payload[48:56], 2)
	}
	return payload
}

// TestTDilithium3ProposalTriggerRawValidation mirrors the seal request's raw
// validation test: the frame validator admits the base payload (56 bytes) and
// the extension headroom (up to 96), and refuses anything outside the bound.
func TestTDilithium3ProposalTriggerRawValidation(t *testing.T) {
	validator := NewMessageValidator()
	raw := make([]byte, MsgHeaderSize+56)
	raw[0] = MsgTypeTDilithium3ProposalTrigger
	binary.BigEndian.PutUint32(raw[1:5], 56)
	if err := validator.ValidateRawMessage(raw); err != nil {
		t.Fatalf("valid proposal trigger rejected: %v", err)
	}
	payloadValidator := validator.validators[MsgTypeTDilithium3ProposalTrigger]
	if payloadValidator == nil {
		t.Fatal("proposal trigger has no registered payload validator")
	}
	for _, length := range []int{56, 96} {
		if err := payloadValidator.Validate(triggerPayloadOf(length)); err != nil {
			t.Fatalf("trigger length %d rejected: %v", length, err)
		}
	}
	for _, length := range []int{0, 55, 97, 4096} {
		if err := payloadValidator.Validate(triggerPayloadOf(length)); err == nil {
			t.Fatalf("invalid trigger length %d accepted", length)
		}
	}
	// The raw-frame validator enforces the upper bound only (the seal request
	// validator's shape: declared size > max is refused before routing; the
	// lower bound is the payload validator's contract above).
	for _, length := range []int{97, 4096} {
		raw := make([]byte, MsgHeaderSize+length)
		raw[0] = MsgTypeTDilithium3ProposalTrigger
		binary.BigEndian.PutUint32(raw[1:5], uint32(length))
		if err := validator.ValidateRawMessage(raw); err == nil {
			t.Fatalf("raw frame declaring length %d accepted", length)
		}
	}
}

// TestTDilithium3ProposalTriggerRoutesToTSSSubscriber requires the trigger to
// be routed by the TSS protocol registration to the TSS subscriber channel,
// so the node layer's handler receives it. Without the protocol registration
// the frame would die at RouteMessage before any handler runs.
func TestTDilithium3ProposalTriggerRoutesToTSSSubscriber(t *testing.T) {
	host := &Host{protocolRegistry: NewProtocolRegistry(), tssCh: make(chan PeerMessage, 1)}
	host.registerProtocols()
	payload := triggerPayloadOf(56)
	message := &Message{Type: MsgTypeTDilithium3ProposalTrigger, From: PeerID("trigger-proposer"), Payload: payload}
	if err := ValidateMessage(message); err != nil {
		t.Fatalf("proposal trigger rejected by message validation: %v", err)
	}
	if err := host.protocolRegistry.RouteMessage(message); err != nil {
		t.Fatalf("proposal trigger has no protocol route: %v", err)
	}
	select {
	case received := <-host.SubscribeTSS():
		if received.Type != message.Type || received.From != message.From || !bytes.Equal(received.Payload, payload) {
			t.Fatal("proposal trigger envelope changed during routing")
		}
	default:
		t.Fatal("proposal trigger did not reach the TSS subscriber")
	}
	// The trigger is exempt from content-hash dedup (retransmission
	// idempotency): two identical frames must both pass message validation.
	if err := ValidateMessage(message); err != nil {
		t.Fatalf("identical retransmission rejected by message validation: %v", err)
	}
}
