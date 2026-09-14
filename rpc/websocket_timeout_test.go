// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"net"
	"testing"
	"time"
)

// TestR4API01_WriteMessage_WriteTimeoutPreventsBlocking verifies that
// writeMessage enforces a write deadline (WSWriteTimeout), so a slow/stopped
// reader does not block the broadcast goroutine indefinitely (head-of-line
// blocking DoS).
//
// Without the fix, writeMessage would block forever on a slow reader's
// Write(), preventing ALL other subscribers from receiving events. With the
// fix, the write times out after WSWriteTimeout and the connection is cleaned
// up by the caller.
//
// AUDIT (2026) R4-API-01
func TestR4API01_WriteMessage_WriteTimeoutPreventsBlocking(t *testing.T) {
	// net.Pipe creates a synchronous, in-memory connection. Write blocks
	// until the other side reads. By not reading from the other end, we
	// simulate a stopped subscriber whose TCP receive buffer is full.
	serverEnd, clientEnd := net.Pipe()
	defer serverEnd.Close()
	defer clientEnd.Close()

	wsConn := &WSConn{
		conn:    serverEnd,
		pongSem: make(chan struct{}, 1),
	}
	ws := &WebSocketServer{}

	// Call writeMessage in a goroutine. It should block because no one is
	// reading from clientEnd, but it should timeout after WSWriteTimeout
	// (not block forever).
	done := make(chan error, 1)
	go func() {
		done <- ws.writeMessage(wsConn, []byte(`{"jsonrpc":"2.0","method":"eth_subscription"}`))
	}()

	select {
	case err := <-done:
		// The write should have timed out (returned an error), not blocked
		// forever.
		if err == nil {
			t.Error("expected writeMessage to return a timeout error for slow reader, got nil")
		}
		t.Logf("=== R4-API-01: writeMessage correctly timed out for slow reader: %v ===", err)
	case <-time.After(WSWriteTimeout + 5*time.Second):
		t.Fatal("writeMessage blocked beyond WSWriteTimeout — head-of-line blocking DoS not fixed")
	}
}
