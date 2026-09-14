// Quantaureum Node source, version 1.0.0.
package rpc

// AUDIT-FULL H-6 (2026-08-14) regression tests.
//
// Bug: broadcastToSubscribers performed blocking writeMessage calls from
// the single broadcastEvents goroutine. With WSWriteTimeout = 10s, ONE
// slow/stalled subscriber stalled the loop for up to 10 seconds, delaying
// event delivery to every other subscriber (head-of-line blocking).
//
// Fix: each WSConn has a buffered sendCh drained by a dedicated writer
// goroutine. broadcastToSubscribers now enqueues with a non-blocking send;
// a full queue drops the event for THAT subscriber only (metric + log).
//
// Tests:
//  1. A subscriber whose queue is full causes a drop (counter increments)
//     but does NOT prevent delivery to another subscriber, and the
//     broadcast call returns promptly (no 10s stall).
//  2. The enqueued message is a valid notification JSON containing the
//     subscriber's subscription ID (writer-goroutine contract).

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

// bufferConn is a minimal net.Conn that records written bytes.
type bufferConn struct {
	bytes.Buffer
}

func (b *bufferConn) Read(p []byte) (int, error)  { return 0, nil }
func (b *bufferConn) Write(p []byte) (int, error) { return b.Buffer.Write(p) }
func (b *bufferConn) Close() error                { return nil }
func (b *bufferConn) LocalAddr() net.Addr         { return nil }
func (b *bufferConn) RemoteAddr() net.Addr        { return nil }
func (b *bufferConn) SetDeadline(t time.Time) error {
	return nil
}
func (b *bufferConn) SetReadDeadline(t time.Time) error  { return nil }
func (b *bufferConn) SetWriteDeadline(t time.Time) error { return nil }

func TestAuditFullH6_SlowSubscriberDoesNotBlockOthers(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	good := &WSConn{conn: &bufferConn{}, sendCh: make(chan []byte, wsSendQueueSize)}
	slow := &WSConn{conn: &bufferConn{}, sendCh: make(chan []byte, wsSendQueueSize)}

	// Simulate the slow subscriber: its queue is already full because its
	// writer goroutine is stalled.
	for i := 0; i < wsSendQueueSize; i++ {
		slow.sendCh <- []byte("stale")
	}

	ws.mu.Lock()
	ws.subscriptions["sub-good"] = &Subscription{
		ID: "sub-good", Type: SubTypeNewHeads, Conn: good,
	}
	ws.subscriptions["sub-slow"] = &Subscription{
		ID: "sub-slow", Type: SubTypeNewHeads, Conn: slow,
	}
	ws.mu.Unlock()

	dropsBefore := ws.droppedEvents.Load()

	start := time.Now()
	ws.broadcastToSubscribers(SubTypeNewHeads, map[string]any{"number": "0x10"})
	elapsed := time.Since(start)

	// The broadcast must return promptly — the pre-H-6 code would have
	// blocked on the slow subscriber's socket write for up to
	// WSWriteTimeout (10s).
	if elapsed > 2*time.Second {
		t.Fatalf("AUDIT-FULL H-6 NOT FIXED: broadcast took %v (head-of-line blocking)", elapsed)
	}

	// The good subscriber must have the event queued.
	select {
	case msg := <-good.sendCh:
		if !strings.Contains(string(msg), "sub-good") {
			t.Errorf("queued message missing subscription ID: %s", msg)
		}
	default:
		t.Fatal("AUDIT-FULL H-6 NOT FIXED: good subscriber did not receive the event")
	}

	// The slow subscriber's queue must still be full of stale entries
	// (no room was made), and a drop must have been counted.
	if ws.droppedEvents.Load() <= dropsBefore {
		t.Error("AUDIT-FULL H-6 NOT FIXED: drop for slow subscriber was not accounted")
	}

	// Cleanup the filled queue so Stop/goroutines don't leak.
	for len(slow.sendCh) > 0 {
		<-slow.sendCh
	}
}

func TestAuditFullH6_EnqueuedMessageWrittenByWriterContract(t *testing.T) {
	ws := NewWebSocketServer(nil)
	defer ws.Stop()

	conn := &bufferConn{}
	good := &WSConn{conn: conn, sendCh: make(chan []byte, wsSendQueueSize)}

	ws.mu.Lock()
	ws.subscriptions["sub-good"] = &Subscription{
		ID: "sub-good", Type: SubTypeLogs, Conn: good,
	}
	ws.mu.Unlock()

	ws.broadcastToSubscribers(SubTypeLogs, map[string]any{
		"address": "0xdeadbeef",
		"topics":  []string{},
	})

	var msg []byte
	select {
	case msg = <-good.sendCh:
	default:
		t.Fatal("expected a queued notification")
	}

	// Emulate the per-connection writer goroutine: drain sendCh via
	// writeMessage and verify a well-formed notification was produced.
	if err := ws.writeMessage(good, msg); err != nil {
		t.Fatalf("writeMessage failed: %v", err)
	}
	out := conn.String()
	for _, want := range []string{"eth_subscription", "sub-good", "0xdeadbeef"} {
		if !strings.Contains(out, want) {
			t.Errorf("written frame missing %q: %s", want, out)
		}
	}
}
