// Quantaureum Node source, version 1.0.0.
package rpc

// Tests for the "newRandomness" WebSocket subscription type: whitelist
// acceptance, rejection of unknown types, and end-to-end delivery of
// NotifyEpochRandomness payloads through the broadcast loop.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestWSRandomnessSubscribeAccepted(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	conn := &WSConn{conn: &bufferConn{}, sendCh: make(chan []byte, wsSendQueueSize)}
	req := &Request{JSONRPC: JSONRPCVersion, Method: "eth_subscribe", ID: json.RawMessage(`1`)}
	req.Params = json.RawMessage(`["newRandomness"]`)

	resp := ws.handleSubscribe(conn, req)
	if resp.Error != nil {
		t.Fatalf("newRandomness subscription rejected: %v", resp.Error)
	}
	ws.mu.Lock()
	count := 0
	for _, sub := range ws.subscriptions {
		if sub.Type == SubTypeRandomness {
			count++
		}
	}
	ws.mu.Unlock()
	if count != 1 {
		t.Errorf("registered %d newRandomness subscriptions, want 1", count)
	}
}

func TestWSRandomnessSubscribeUnknownTypeRejected(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	conn := &WSConn{conn: &bufferConn{}, sendCh: make(chan []byte, wsSendQueueSize)}
	req := &Request{JSONRPC: JSONRPCVersion, Method: "eth_subscribe", ID: json.RawMessage(`1`)}
	req.Params = json.RawMessage(`["newRandomnessV2"]`)

	resp := ws.handleSubscribe(conn, req)
	if resp.Error == nil {
		t.Fatal("unknown subscription type must be rejected")
	}
}

func TestWSRandomnessNotifyDeliversPayload(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	conn := &WSConn{conn: &bufferConn{}, sendCh: make(chan []byte, wsSendQueueSize)}
	sub := &Subscription{ID: "sub-rand", Type: SubTypeRandomness, Conn: conn}
	ws.mu.Lock()
	ws.subscriptions["sub-rand"] = sub
	ws.mu.Unlock()

	// Notify goes through randomnessCh → broadcastEvents → sendCh. The
	// broadcast loop is already running (started by NewWebSocketServer).
	ws.NotifyEpochRandomness(42, "0xaabb", "0xccdd", 42*32+31)

	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case msg := <-conn.sendCh:
			text := string(msg)
			if !strings.Contains(text, "sub-rand") {
				t.Fatalf("notification missing subscription ID: %s", text)
			}
			for _, want := range []string{`"epoch":42`, "0xaabb", "0xccdd", `"finalized":true`} {
				if !strings.Contains(text, want) {
					t.Errorf("notification payload missing %s: %s", want, text)
				}
			}
			return
		case <-time.After(time.Until(deadline)):
			t.Fatal("timed out waiting for newRandomness notification")
		}
	}
}
