// Quantaureum Node source, version 1.0.0.
package discover

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p/enode"
)

// TestP2_HandlePingAuth_PingDoesNotMarkVerified verifies that receiving a PING
// does NOT mark the sender as verified. This is the core fix for
// P2-HANDLEPING-AUTH: previously, any unsigned PING (even spoofed) granted
// FINDNODE qualification, enabling ~16× reflection amplification attacks.
//
// P2-HANDLEPING-AUTH FIX (R29, 2026-07-26): handlePing no longer calls
// markVerified. Verification is now only granted in handlePong, after WE
// send a PING and receive a matching PONG (proving bidirectional reachability).
func TestP2_HandlePingAuth_PingDoesNotMarkVerified(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &UDPTransport{
		conn:    conn,
		table:   nil,
		pending: make(map[uint32]*pendingRequest),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Create a PING payload with a node ID
	var nodeID enode.ID
	nodeID[0] = 0x42
	payload := make([]byte, 4+32)
	binary.BigEndian.PutUint32(payload[:4], 11111)
	copy(payload[4:], nodeID[:])

	from := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345}

	// Call handlePing
	transport.handlePing(from, payload)

	// Give the verification PING goroutine time to start (it will fail because
	// 192.0.2.1 is not reachable, but we need to ensure it doesn't mark the
	// IP as verified)
	time.Sleep(100 * time.Millisecond)

	// CRITICAL: The sender must NOT be verified just from sending a PING.
	// Previously, handlePing called markVerified immediately, granting
	// FINDNODE qualification to any IP that sent a PING (even spoofed).
	if transport.isVerified(from.IP.String()) {
		t.Fatal("P2-HANDLEPING-AUTH REGRESSION: handlePing marked the sender " +
			"as verified just from receiving a PING. This allows an attacker " +
			"to spoof a PING from a victim's IP and immediately gain " +
			"FINDNODE qualification, enabling ~16× reflection amplification.")
	}
}

// TestP2_HandlePingAuth_PongMarksVerified verifies that handlePong marks the
// sender as verified when the PONG matches a pending PING that WE initiated.
// This is the new verification path: only a completed PING→PONG exchange
// (initiated by us) grants FINDNODE qualification.
func TestP2_HandlePingAuth_PongMarksVerified(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &UDPTransport{
		conn:          conn,
		table:         nil,
		pending:       make(map[uint32]*pendingRequest),
		ctx:           ctx,
		cancel:        cancel,
		verifiedPeers: make(map[string]time.Time),
	}

	from := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 12345}
	reqID := uint32(99999)

	// Register a pending PING (simulating that WE initiated a PING to this
	// address). This is what Ping() does internally via registerPending.
	transport.pendingMu.Lock()
	transport.pending[reqID] = &pendingRequest{
		callback:     func(result any, err error) {}, // no-op callback
		expectedAddr: from,
	}
	transport.pendingMu.Unlock()

	// Verify the IP is NOT verified before the PONG
	if transport.isVerified(from.IP.String()) {
		t.Fatal("IP should not be verified before PONG is received")
	}

	// Create a PONG payload matching the pending PING
	var nodeID enode.ID
	nodeID[0] = 0x99
	pongPayload := make([]byte, 4+32)
	binary.BigEndian.PutUint32(pongPayload[:4], reqID)
	copy(pongPayload[4:], nodeID[:])

	// Call handlePong — this should mark the IP as verified
	transport.handlePong(from, pongPayload)

	// CRITICAL: After receiving a PONG matching our PING, the IP MUST be
	// verified. This is the endpoint proof — we sent a PING and they
	// responded, proving they can receive packets at this address.
	if !transport.isVerified(from.IP.String()) {
		t.Fatal("P2-HANDLEPING-AUTH REGRESSION: handlePong did NOT mark the " +
			"sender as verified after receiving a PONG matching our PING. " +
			"This breaks the legitimate verification flow — peers who " +
			"complete a PING/PONG exchange should be granted FINDNODE " +
			"qualification.")
	}
}

// TestP2_HandlePingAuth_PongFromWrongAddressNotVerified verifies that a PONG
// from a different address than expected does NOT mark that address as verified.
// This prevents an attacker from sending a PONG from address B to get address B
// verified when we sent the PING to address A.
func TestP2_HandlePingAuth_PongFromWrongAddressNotVerified(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &UDPTransport{
		conn:          conn,
		table:         nil,
		pending:       make(map[uint32]*pendingRequest),
		ctx:           ctx,
		cancel:        cancel,
		verifiedPeers: make(map[string]time.Time),
	}

	expectedAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 12345}
	wrongAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.4"), Port: 9999}
	reqID := uint32(88888)

	// Register a pending PING to expectedAddr
	transport.pendingMu.Lock()
	transport.pending[reqID] = &pendingRequest{
		callback:     func(result any, err error) {},
		expectedAddr: expectedAddr,
	}
	transport.pendingMu.Unlock()

	// Create a PONG payload matching the reqID, but from a DIFFERENT address
	var nodeID enode.ID
	nodeID[0] = 0x88
	pongPayload := make([]byte, 4+32)
	binary.BigEndian.PutUint32(pongPayload[:4], reqID)
	copy(pongPayload[4:], nodeID[:])

	// Call handlePong from the WRONG address
	transport.handlePong(wrongAddr, pongPayload)

	// Neither address should be verified — the PONG came from a different
	// address than the one we sent the PING to.
	if transport.isVerified(expectedAddr.IP.String()) {
		t.Error("P2-HANDLEPING-AUTH REGRESSION: expectedAddr was marked as " +
			"verified even though the PONG came from a different address")
	}
	if transport.isVerified(wrongAddr.IP.String()) {
		t.Error("P2-HANDLEPING-AUTH REGRESSION: wrongAddr was marked as " +
			"verified — an attacker can send a PONG from an arbitrary address " +
			"to get that address verified, bypassing the endpoint proof")
	}
}

// TestP2_HandlePingAuth_UnsolicitedPongNotVerified verifies that an unsolicited
// PONG (one with no matching pending PING) does NOT mark the sender as verified.
// This prevents an attacker from sending unsolicited PONGs to gain verification.
func TestP2_HandlePingAuth_UnsolicitedPongNotVerified(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &UDPTransport{
		conn:          conn,
		table:         nil,
		pending:       make(map[uint32]*pendingRequest),
		ctx:           ctx,
		cancel:        cancel,
		verifiedPeers: make(map[string]time.Time),
	}

	from := &net.UDPAddr{IP: net.ParseIP("192.0.2.5"), Port: 12345}

	// Create a PONG payload with a reqID that has NO matching pending PING
	var nodeID enode.ID
	nodeID[0] = 0x77
	pongPayload := make([]byte, 4+32)
	binary.BigEndian.PutUint32(pongPayload[:4], 77777) // no matching pending
	copy(pongPayload[4:], nodeID[:])

	// Call handlePong — this is an unsolicited PONG
	transport.handlePong(from, pongPayload)

	// The IP must NOT be verified — there was no matching pending PING,
	// meaning we never sent a PING to this address.
	if transport.isVerified(from.IP.String()) {
		t.Fatal("P2-HANDLEPING-AUTH REGRESSION: unsolicited PONG (no matching " +
			"pending PING) marked the sender as verified. This allows an " +
			"attacker to send unsolicited PONGs to gain FINDNODE qualification " +
			"without completing a PING/PONG exchange.")
	}
}

// TestP2_HandlePingAuth_FullExchangeMarksVerified is an end-to-end test that
// verifies the full PING/PONG exchange flow: two transports exchange PINGs,
// and after the exchange completes, both sides are verified.
//
// This test uses real UDP connections to verify the fix works in practice:
//   - Transport A sends PING to Transport B
//   - Transport B receives PING, sends PONG, and sends verification PING to A
//   - Transport A receives PONG (matching its PING) → marks B as verified
//   - Transport B receives PONG (matching its verification PING) → marks A as verified
//   - Both sides are now verified
func TestP2_HandlePingAuth_FullExchangeMarksVerified(t *testing.T) {
	// Create two UDP transports
	connA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP A failed: %v", err)
	}
	defer connA.Close()

	connB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP B failed: %v", err)
	}
	defer connB.Close()

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()

	// Create key pairs for node IDs
	// We use fixed node IDs for deterministic testing
	var idA, idB enode.ID
	idA[0] = 0xAA
	idB[0] = 0xBB

	nodeA := enode.NewNode(idA, connA.LocalAddr().(*net.UDPAddr).IP, connA.LocalAddr().(*net.UDPAddr).Port, connA.LocalAddr().(*net.UDPAddr).Port)
	nodeB := enode.NewNode(idB, connB.LocalAddr().(*net.UDPAddr).IP, connB.LocalAddr().(*net.UDPAddr).Port, connB.LocalAddr().(*net.UDPAddr).Port)

	transportA := &UDPTransport{
		conn:          connA,
		table:         nil,
		pending:       make(map[uint32]*pendingRequest),
		ctx:           ctxA,
		cancel:        cancelA,
		verifiedPeers: make(map[string]time.Time),
		localNode:     nodeA,
	}

	transportB := &UDPTransport{
		conn:          connB,
		table:         nil,
		pending:       make(map[uint32]*pendingRequest),
		ctx:           ctxB,
		cancel:        cancelB,
		verifiedPeers: make(map[string]time.Time),
		localNode:     nodeB,
	}

	// Start packet handling goroutines for both transports
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		transportA.handleLoopTest()
	}()
	go func() {
		defer wg.Done()
		transportB.handleLoopTest()
	}()

	// Transport A initiates a PING to Transport B
	go func() {
		_ = transportA.Ping(nodeB)
	}()

	// Wait for the exchange to complete
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	aVerified := false
	bVerified := false

	for !aVerified || !bVerified {
		select {
		case <-deadline:
			// Cancel the goroutines
			cancelA()
			cancelB()
			wg.Wait()
			t.Fatalf("P2-HANDLEPING-AUTH: exchange did not complete within timeout. "+
				"A verified: %v, B verified: %v", aVerified, bVerified)
		case <-ticker.C:
			// Check if B is verified on A's side (A sent PING, got PONG)
			if !aVerified {
				bIP := connB.LocalAddr().(*net.UDPAddr).IP.String()
				if transportA.isVerified(bIP) {
					aVerified = true
				}
			}
			// Check if A is verified on B's side (B sent verification PING, got PONG)
			if !bVerified {
				aIP := connA.LocalAddr().(*net.UDPAddr).IP.String()
				if transportB.isVerified(aIP) {
					bVerified = true
				}
			}
		}
	}

	// Both sides should be verified after the full exchange
	cancelA()
	cancelB()
	wg.Wait()

	if !aVerified {
		t.Error("P2-HANDLEPING-AUTH: Transport A did not verify Transport B " +
			"after PING/PONG exchange")
	}
	if !bVerified {
		t.Error("P2-HANDLEPING-AUTH: Transport B did not verify Transport A " +
			"after verification PING/PONG exchange")
	}
}

// handleLoopTest is a test helper that reads and dispatches UDP packets.
// It exits when the transport's context is canceled.
func (t *UDPTransport) handleLoopTest() {
	buf := make([]byte, 1280)
	for {
		if t.ctx.Err() != nil {
			return
		}
		t.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, from, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			if t.ctx.Err() != nil {
				return
			}
			continue // timeout or other error
		}
		if n < 1 {
			continue
		}
		packetType := buf[0]
		payload := make([]byte, n-1)
		copy(payload, buf[1:n])

		fromAddr := &net.UDPAddr{IP: from.IP, Port: from.Port}

		switch packetType {
		case 1:
			t.handlePing(fromAddr, payload)
		case 2:
			t.handlePong(fromAddr, payload)
		case 3:
			t.handleFindNode(fromAddr, payload)
		case 4:
			t.handleNeighbors(fromAddr, payload)
		}
	}
}
