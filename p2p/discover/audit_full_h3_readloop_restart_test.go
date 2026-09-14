// Quantaureum Node source, version 1.0.0.
package discover

// AUDIT-FULL H-3 (2026-08-14) regression tests.
//
// Bug: UDPTransport.readLoop's recover() logged the panic and then let
// the goroutine exit permanently. A single malformed packet (or any bug
// triggering a panic in the read path) silently disabled node discovery
// for the rest of the process lifetime.
//
// Fix: readLoop is now a supervisor loop that restarts readLoopOnce
// (with a 1s backoff) after each panic, until the transport is closed.
//
// These tests inject panics via readLoopOnceHook and verify:
//  1. The loop restarts after consecutive panics (3rd invocation happens).
//  2. After the panics, the transport still delivers packets to
//     packetCh — i.e. discovery keeps working.

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p/enode"
)

func TestAuditFullH3_ReadLoopRestartsAfterPanic(t *testing.T) {
	localID, _ := enode.GenerateID()
	localNode := enode.NewNode(localID, net.ParseIP("127.0.0.1"), 30303, 30303)

	// Install the panic hook BEFORE starting the read loop (avoids a
	// data race on the package-level hook).
	var invocations atomic.Int32
	readLoopOnceHook = func() {
		if invocations.Add(1) <= 2 {
			panic("AUDIT-FULL H-3 injected test panic")
		}
	}
	defer func() { readLoopOnceHook = nil }()

	// Build the transport manually so ONLY readLoop runs (no handleLoop
	// competing for packetCh) — this lets the test observe deliveries.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	transport := &UDPTransport{
		conn:      conn,
		localNode: localNode,
		packetCh:  make(chan *udpPacket, 256),
		pending:   make(map[uint32]*pendingRequest),
		ctx:       ctx,
		cancel:    cancel,
	}
	transport.wg.Add(1)
	go transport.readLoop()
	defer transport.Close()

	// Wait for the supervisor to restart the loop past both injected
	// panics: the 3rd invocation of readLoopOnce proves 2 restarts.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if invocations.Load() >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := invocations.Load(); got < 3 {
		t.Fatalf("AUDIT-FULL H-3 NOT FIXED: readLoop did not restart after panics (invocations=%d, want >= 3)", got)
	}

	// Discovery must still work after the panics: send a datagram to the
	// transport's socket and expect it to be drained into packetCh.
	laddr := conn.LocalAddr().(*net.UDPAddr)
	client, err := net.DialUDP("udp", nil, laddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer client.Close()

	payload := make([]byte, 128) // arbitrary garbage
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	select {
	case pkt := <-transport.packetCh:
		if len(pkt.data) != len(payload) {
			t.Errorf("received %d bytes, want %d", len(pkt.data), len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AUDIT-FULL H-3 NOT FIXED: transport stopped receiving packets after readLoop panics")
	}
}

func TestAuditFullH3_ReadLoopExitsOnClose(t *testing.T) {
	// The supervisor must not outlive Close(): wg.Wait() in Close() must
	// return even though the readLoop goroutine now loops forever.
	localID, _ := enode.GenerateID()
	localNode := enode.NewNode(localID, net.ParseIP("127.0.0.1"), 30303, 30303)

	tab := newTestTable()
	defer tab.Close()

	transport, err := NewUDPTransport(context.Background(), localNode, tab, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		transport.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("AUDIT-FULL H-3 regression: Close() hung — readLoop supervisor ignores ctx cancellation")
	}
}
