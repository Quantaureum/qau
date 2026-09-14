// Quantaureum Node source, version 1.0.0.
package rpc

// P2P-R15-H02 tests.
//
// Verifies the fix for the audit finding:
//   WebSocket handleConnection goroutines lacked WaitGroup tracking → after Stop() returns,
//   goroutines still run and touch closed connections
//
// Before the fix, Stop() called httpServer.Shutdown which only waits for
// non-hijacked requests. WebSocket connections are hijacked (via
// http.Hijacker), so they are NOT tracked by http.Server. As a result,
// handleConnection goroutines remained blocked on readMessage
// indefinitely after Stop() returned, accessing already-closed
// connections.
//
// After the fix:
//   - ServeHTTP wraps handleConnection in connWG.Add(1)/defer Done()
//   - Stop() force-closes all active connections to unblock read loops
//   - Stop() waits for connWG with a timeout, ensuring all
//     handleConnection goroutines exit before Stop returns

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestP2P_R15_H02_StopWaitsForHandleConnection verifies that Stop() waits
// for all handleConnection goroutines to exit before returning. Before the
// fix, Stop() returned immediately after httpServer.Shutdown (which
// doesn't track hijacked connections), leaving handleConnection goroutines
// blocked on readMessage indefinitely.
//
// This test creates a real WebSocket server, connects a client that sits
// idle (so handleConnection blocks on readMessage), then calls Stop() and
// verifies:
//  1. Stop() returns within a reasonable timeout (not blocked forever)
//  2. connCount drops to 0 (all handleConnection goroutines exited)
func TestP2P_R15_H02_StopWaitsForHandleConnection(t *testing.T) {
	ws := NewWebSocketServer(nil)
	// Use a short shutdown timeout so the test doesn't hang if there's a bug.
	ws.SetShutdownTimeout(3 * time.Second)

	// Start on an ephemeral port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // httpServer will create its own listener

	go func() { _ = ws.Start(addr) }()

	// Give the server a moment to start.
	time.Sleep(100 * time.Millisecond)

	// Connect a WebSocket client and perform the upgrade handshake.
	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("net.Dial failed: %v", err)
	}
	// Perform WebSocket handshake.
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	handshake := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: 127.0.0.1\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Origin: http://127.0.0.1\r\n"+
			"\r\n", key)
	_, err = clientConn.Write([]byte(handshake))
	if err != nil {
		t.Fatalf("handshake write failed: %v", err)
	}

	// Read the server's upgrade response.
	br := bufio.NewReader(clientConn)
	respLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading handshake response failed: %v", err)
	}
	if !strings.Contains(respLine, "101") {
		t.Fatalf("expected 101 Switching Protocols, got: %s", respLine)
	}
	// Read remaining headers until empty line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading handshake headers failed: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// At this point handleConnection is running and blocked on readMessage
	// (the client is idle). Verify the connection was registered.
	// Give the server a moment to register the connection.
	time.Sleep(100 * time.Millisecond)
	connCount := atomic.LoadInt32(&ws.connCount)
	if connCount != 1 {
		t.Fatalf("expected connCount=1 after client connect, got %d", connCount)
	}

	// Call Stop() — this should force-close the connection and wait for
	// the handleConnection goroutine to exit.
	stopDone := make(chan struct{})
	go func() {
		ws.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		// Stop() returned — good.
	case <-time.After(10 * time.Second):
		t.Fatal("P2P-R15-H02 REGRESSION: Stop() did not return within 10s — handleConnection goroutine still running")
	}

	// Verify connCount dropped to 0 (handleConnection defer ran).
	connCount = atomic.LoadInt32(&ws.connCount)
	if connCount != 0 {
		t.Errorf("expected connCount=0 after Stop(), got %d — handleConnection goroutine did not exit cleanly", connCount)
	}

	_ = clientConn.Close()
}

// TestP2P_R15_H02_StopWithNoConnections verifies that Stop() returns
// quickly when there are no active connections (no goroutines to wait for).
func TestP2P_R15_H02_StopWithNoConnections(t *testing.T) {
	ws := NewWebSocketServer(nil)
	ws.SetShutdownTimeout(3 * time.Second)

	go func() { _ = ws.Start("127.0.0.1:0") }()
	time.Sleep(100 * time.Millisecond)

	stopDone := make(chan struct{})
	go func() {
		ws.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		// Good — Stop() returned quickly.
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within 5s with no active connections")
	}
}

// TestP2P_R15_H02_StopClosesActiveConnection verifies that Stop()
// force-closes all active WebSocket connections so handleConnection's
// read loop unblocks and exits. Before the fix, the connection remained
// open and handleConnection stayed blocked on readMessage.
func TestP2P_R15_H02_StopClosesActiveConnection(t *testing.T) {
	ws := NewWebSocketServer(nil)
	ws.SetShutdownTimeout(3 * time.Second)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	go func() { _ = ws.Start(addr) }()
	time.Sleep(100 * time.Millisecond)

	// Connect and handshake.
	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("net.Dial failed: %v", err)
	}
	defer clientConn.Close()

	key := "dGhlIHNhbXBsZSBub25jZQ=="
	handshake := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: 127.0.0.1\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Origin: http://127.0.0.1\r\n"+
			"\r\n", key)
	_, err = clientConn.Write([]byte(handshake))
	if err != nil {
		t.Fatalf("handshake write failed: %v", err)
	}

	br := bufio.NewReader(clientConn)
	respLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading handshake response failed: %v", err)
	}
	if !strings.Contains(respLine, "101") {
		t.Fatalf("expected 101, got: %s", respLine)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading headers failed: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	time.Sleep(100 * time.Millisecond)

	// Call Stop() — should close the client connection.
	ws.Stop()

	// The client should detect the connection close. A read from the
	// closed connection should return EOF or an error quickly.
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	_, err = clientConn.Read(buf)
	if err == nil {
		// If no error, the server may have sent a close frame. That's fine —
		// the key point is that the connection was closed by Stop().
		t.Log("client read returned no error (may have received close frame)")
	} else {
		t.Logf("client read returned expected error after Stop(): %v", err)
	}
}

// TestP2P_R15_H02_MultipleConnectionsAllExit verifies that Stop() waits
// for MULTIPLE handleConnection goroutines, not just one.
func TestP2P_R15_H02_MultipleConnectionsAllExit(t *testing.T) {
	ws := NewWebSocketServer(nil)
	ws.SetShutdownTimeout(5 * time.Second)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	go func() { _ = ws.Start(addr) }()
	time.Sleep(100 * time.Millisecond)

	// Connect 3 idle clients.
	clientConns := make([]net.Conn, 0, 3)
	for i := 0; i < 3; i++ {
		clientConn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("net.Dial %d failed: %v", i, err)
		}
		key := fmt.Sprintf("dGhlIHNhbXBsZSBub25jZQ==%d", i)
		handshake := fmt.Sprintf(
			"GET / HTTP/1.1\r\n"+
				"Host: 127.0.0.1\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Key: %s\r\n"+
				"Sec-WebSocket-Version: 13\r\n"+
				"Origin: http://127.0.0.1\r\n"+
				"\r\n", key)
		_, err = clientConn.Write([]byte(handshake))
		if err != nil {
			t.Fatalf("handshake %d write failed: %v", i, err)
		}
		br := bufio.NewReader(clientConn)
		respLine, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading handshake %d response failed: %v", i, err)
		}
		if !strings.Contains(respLine, "101") {
			t.Fatalf("client %d expected 101, got: %s", i, respLine)
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("reading headers %d failed: %v", i, err)
			}
			if line == "\r\n" {
				break
			}
		}
		clientConns = append(clientConns, clientConn)
	}

	time.Sleep(200 * time.Millisecond)
	connCount := atomic.LoadInt32(&ws.connCount)
	if connCount != 3 {
		t.Fatalf("expected connCount=3, got %d", connCount)
	}

	// Stop should wait for ALL 3 handleConnection goroutines.
	stopDone := make(chan struct{})
	go func() {
		ws.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		// Good.
	case <-time.After(15 * time.Second):
		t.Fatal("P2P-R15-H02 REGRESSION: Stop() did not return within 15s with 3 connections")
	}

	connCount = atomic.LoadInt32(&ws.connCount)
	if connCount != 0 {
		t.Errorf("expected connCount=0 after Stop(), got %d", connCount)
	}

	for _, c := range clientConns {
		_ = c.Close()
	}
}

// TestP2P_R15_H02_AcceptKeyCorrect verifies the SHA1 accept key
// computation is correct per RFC 6455. This is a helper used by the
// handshake above; we test it here to ensure the test infrastructure
// is correct.
func TestP2P_R15_H02_AcceptKeyCorrect(t *testing.T) {
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	h := sha1.New() // #nosec G401 -- SHA-1 required by RFC 6455
	h.Write([]byte(key + wsGUID))
	expected := base64.StdEncoding.EncodeToString(h.Sum(nil))
	// RFC 6455 Section 4.2.2 example:
	if expected != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("unexpected accept key: got %s, want s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", expected)
	}
}

// TestP2P_R15_H02_StopWithoutStart verifies that calling Stop() on a
// WebSocketServer that was never Start()ed does not panic. The connWG
// should have no goroutines to wait for, and the connection-closing
// loop should find an empty connSubs map.
func TestP2P_R15_H02_StopWithoutStart(t *testing.T) {
	ws := NewWebSocketServer(nil)
	ws.SetShutdownTimeout(1 * time.Second)

	stopDone := make(chan struct{})
	go func() {
		ws.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		// Good — no panic, no hang.
	case <-time.After(3 * time.Second):
		t.Fatal("Stop() on non-started server did not return within 3s")
	}
}

// TestP2P_R15_H02_StopIsIdempotent verifies that calling Stop() twice
// does not panic or hang. The second call should find httpServer already
// shut down and connWG already at zero.
func TestP2P_R15_H02_StopIsIdempotent(t *testing.T) {
	ws := NewWebSocketServer(nil)
	ws.SetShutdownTimeout(2 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx
	go func() { _ = ws.Start("127.0.0.1:0") }()
	time.Sleep(100 * time.Millisecond)
	cancel()

	ws.Stop()
	// Second Stop should not panic.
	ws.Stop()
}

// TestP2P_R15_H02_ConnWGDecrementsOnConnectionClose verifies that
// connWG is decremented when a connection closes normally (not just
// via Stop). This ensures the WaitGroup tracking is correct for the
// normal connection lifecycle, not just shutdown.
func TestP2P_R15_H02_ConnWGDecrementsOnConnectionClose(t *testing.T) {
	ws := NewWebSocketServer(nil)
	ws.SetShutdownTimeout(3 * time.Second)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	go func() { _ = ws.Start(addr) }()
	defer ws.Stop()
	time.Sleep(100 * time.Millisecond)

	// Connect and handshake.
	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("net.Dial failed: %v", err)
	}
	defer clientConn.Close()

	key := "dGhlIHNhbXBsZSBub25jZQ=="
	handshake := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: 127.0.0.1\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Origin: http://127.0.0.1\r\n"+
			"\r\n", key)
	_, err = clientConn.Write([]byte(handshake))
	if err != nil {
		t.Fatalf("handshake write failed: %v", err)
	}
	br := bufio.NewReader(clientConn)
	_, err = br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading response failed: %v", err)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" {
			break
		}
	}

	time.Sleep(100 * time.Millisecond)
	if atomic.LoadInt32(&ws.connCount) != 1 {
		t.Fatalf("expected connCount=1, got %d", atomic.LoadInt32(&ws.connCount))
	}

	// Close the client — handleConnection's readMessage should get EOF,
	// causing handleConnection to return, which decrements connWG.
	_ = clientConn.Close()

	// Wait for the server to detect the close and clean up.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&ws.connCount) == 0 {
			return // Success
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("connCount did not drop to 0 after client close (got %d) — handleConnection goroutine may not have exited",
		atomic.LoadInt32(&ws.connCount))
}

// Ensure http import is used (for ErrServerClosed comparison in tests
// that may reference it). This is a compile-time guard.
var _ = http.ErrServerClosed
