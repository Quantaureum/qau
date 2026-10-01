// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"bytes"
	"testing"
)

func TestTSSKeyExchangeRoutesToSubscriber(t *testing.T) {
	host := &Host{protocolRegistry: NewProtocolRegistry(), tssCh: make(chan PeerMessage, 1)}
	host.registerProtocols()
	payload := bytes.Repeat([]byte{0x42}, 1184+4000)
	message := &Message{Type: MsgTypeTSSKeyExchange, From: PeerID("test-validator"), Payload: payload}
	if err := ValidateMessage(message); err != nil {
		t.Fatalf("key exchange rejected by message validation: %v", err)
	}
	if err := host.protocolRegistry.RouteMessage(message); err != nil {
		t.Fatalf("key exchange has no protocol route: %v", err)
	}
	select {
	case received := <-host.SubscribeTSS():
		if received.Type != message.Type || received.From != message.From || !bytes.Equal(received.Payload, payload) {
			t.Fatal("key exchange envelope changed during routing")
		}
	default:
		t.Fatal("key exchange did not reach the TSS subscriber")
	}
	for _, length := range []int{0, 35, 20*1024 + 1} {
		if err := ValidateMessage(&Message{Type: MsgTypeTSSKeyExchange, Payload: make([]byte, length)}); err == nil {
			t.Fatalf("key exchange accepted invalid length %d", length)
		}
	}
}
