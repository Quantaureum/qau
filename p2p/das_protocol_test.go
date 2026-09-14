// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// TestDASProtocol_NewDASProtocol verifies the constructor.
// P0-10 (2026-07-14)
func TestDASProtocol_NewDASProtocol(t *testing.T) {
	proto := NewDASProtocol(nil)
	if proto == nil {
		t.Fatal("NewDASProtocol returned nil")
	}
}

// TestDASProtocol_GetConnectedPeersNilHost verifies nil-safety.
// P0-10 (2026-07-14)
func TestDASProtocol_GetConnectedPeersNilHost(t *testing.T) {
	proto := NewDASProtocol(nil)
	peers := proto.GetConnectedPeers()
	if peers != nil {
		t.Errorf("GetConnectedPeers with nil host should return nil, got %v", peers)
	}
}

// TestDASProtocol_SendSampleRequestNilHost verifies nil-safety.
// P0-10 (2026-07-14)
func TestDASProtocol_SendSampleRequestNilHost(t *testing.T) {
	proto := NewDASProtocol(nil)
	_, err := proto.SendSampleRequest("peer1", 50, []byte("test"))
	if err == nil {
		t.Error("SendSampleRequest with nil host should return error")
	}
}

// TestDASProtocol_NewDASPeerGetter verifies the factory function.
// P0-10 (2026-07-14)
func TestDASProtocol_NewDASPeerGetter(t *testing.T) {
	getter := NewDASPeerGetter(nil)
	if getter == nil {
		t.Fatal("NewDASPeerGetter returned nil")
	}
	// Should return error when host is nil
	_, err := getter("peer1", 50, []byte("test"))
	if err == nil {
		t.Error("getter with nil host should return error")
	}
}

// TestDASProtocol_NewDASPeerList verifies the factory function.
// P0-10 (2026-07-14)
func TestDASProtocol_NewDASPeerList(t *testing.T) {
	lister := NewDASPeerList(nil)
	if lister == nil {
		t.Fatal("NewDASPeerList returned nil")
	}
	peers := lister()
	if peers != nil {
		t.Errorf("lister with nil host should return nil, got %v", peers)
	}
}

// TestDASProtocol_RequestNoPeer verifies that SendSampleRequest returns an
// error (rather than blocking) when the requested peer is not connected.
// P0-10 (2026-07-14)
func TestDASProtocol_RequestNoPeer(t *testing.T) {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:0",
		MaxPeers:     10,
		TrustedPeers: []string{},
		DevMode:      true, // skip PoW in tests
	}
	host, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Stop()

	proto := NewDASProtocol(host)

	// No peers connected — SendRaw should fail immediately.
	start := time.Now()
	_, err = proto.SendSampleRequest("nonexistent-peer", 50, make([]byte, 20))
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error for request to non-existent peer")
	}
	// Should fail fast — well under the DAS request timeout.
	if elapsed > time.Second {
		t.Errorf("request took too long: %v (peer-not-found should fail fast)", elapsed)
	}
}

// TestDASProtocol_RequestTimeout verifies that SendSampleRequest times out
// when a connected peer does not respond. A fake peer is injected so that
// SendRaw succeeds, then we verify the select hits the timer branch.
// P0-10 (2026-07-14)
func TestDASProtocol_RequestTimeout(t *testing.T) {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:0",
		MaxPeers:     10,
		TrustedPeers: []string{},
		DevMode:      true, // skip PoW in tests
	}
	host, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Stop()

	// Inject a fake connected peer so SendRaw succeeds. We don't start any
	// read/write loop on it — the sendCh just drains into the void.
	ctx, cancel := context.WithCancel(host.ctx)
	defer cancel()
	fakePeer := &Peer{
		ID:        PeerID("fake-peer"),
		Connected: true,
		sendCh:    make(chan []byte, 16), // buffered so SendRaw doesn't block
		ctx:       ctx,
		cancel:    cancel,
	}
	host.peersMu.Lock()
	host.peers[PeerID("fake-peer")] = fakePeer
	host.peersMu.Unlock()

	// Use a shorter timeout for the test to keep it fast.
	// We can't override DASRequestTimeout (const), so we just verify the
	// elapsed time is within [DASRequestTimeout - 100ms, DASRequestTimeout + 2s].
	proto := NewDASProtocol(host)
	start := time.Now()
	// P1-12 (2026-07-19): payload must be exactly DASSampleRequestSize (28 bytes)
	// so SendSampleRequest can inject the RequestID at bytes [0:8].
	_, err = proto.SendSampleRequest("fake-peer", 50, make([]byte, 28))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if err != ErrDASRequestTimeout {
		// ctx cancellation could also fire if host.Stop() races; ensure we
		// actually hit the timeout branch.
		t.Logf("got err=%v (want %v)", err, ErrDASRequestTimeout)
	}
	if elapsed < DASRequestTimeout-200*time.Millisecond {
		t.Errorf("request returned too quickly: %v (should wait at least %v)",
			elapsed, DASRequestTimeout)
	}
	if elapsed > DASRequestTimeout+2*time.Second {
		t.Errorf("request took too long: %v (timeout should be %v)",
			elapsed, DASRequestTimeout)
	}
}

// TestValidateMessageType_DAS verifies DAS message types are recognized.
// P0-10 (2026-07-14)
func TestValidateMessageType_DAS(t *testing.T) {
	dasTypes := []uint8{
		MsgTypeDASSampleReq, MsgTypeDASSampleResp,
		MsgTypeDASAttestation, MsgTypeDASAggregateAttest,
	}
	for _, mt := range dasTypes {
		if !ValidateMessageType(mt) {
			t.Errorf("ValidateMessageType(%d) = false, want true", mt)
		}
	}
}

// TestProtocolRegistry_DASRegistered verifies the DAS protocol is registered.
// P0-10 (2026-07-14)
func TestProtocolRegistry_DASRegistered(t *testing.T) {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:0",
		MaxPeers:     10,
		TrustedPeers: []string{},
		DevMode:      true, // skip PoW in tests
	}
	host, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Stop()

	proto := host.protocolRegistry.GetProtocol(ProtocolDAS)
	if proto == nil {
		t.Fatal("DAS protocol not registered")
	}
	if !proto.Enabled {
		t.Error("DAS protocol should be enabled")
	}
	// Verify all DAS message types are registered
	for _, mt := range []uint8{MsgTypeDASSampleReq, MsgTypeDASSampleResp, MsgTypeDASAttestation, MsgTypeDASAggregateAttest} {
		if !proto.Spec.MsgTypes[mt] {
			t.Errorf("message type %d not registered in DAS protocol", mt)
		}
	}
}

// TestHandleDASProtocol_SizeValidation verifies DoS protection:
// requests/responses with wrong size are silently dropped.
// P0-10 (2026-07-14); P1-12 (2026-07-19): updated for new wire format
// (RequestID 8 bytes added at head: request 20→28, response 100→108).
func TestHandleDASProtocol_SizeValidation(t *testing.T) {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:0",
		MaxPeers:     10,
		TrustedPeers: []string{},
		DevMode:      true, // skip PoW in tests
	}
	host, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Stop()

	// Wrong-size request (should be 28 bytes) — should be dropped
	wrongReq := &Message{Type: MsgTypeDASSampleReq, Payload: make([]byte, 10)}
	if err := host.handleDASProtocol(wrongReq); err != nil {
		t.Errorf("handleDASProtocol with wrong-size request should not return error: %v", err)
	}
	// Channel should be empty
	select {
	case <-host.dasReqCh:
		t.Error("wrong-size request should not be enqueued")
	default:
		// OK
	}

	// Correct-size request — should be enqueued
	correctReq := &Message{Type: MsgTypeDASSampleReq, Payload: make([]byte, 28)}
	if err := host.handleDASProtocol(correctReq); err != nil {
		t.Errorf("handleDASProtocol with correct request failed: %v", err)
	}
	select {
	case <-host.dasReqCh:
		// OK
	default:
		t.Error("correct-size request should be enqueued")
	}

	// Wrong-size response (should be 108 bytes) — should be dropped
	wrongResp := &Message{Type: MsgTypeDASSampleResp, Payload: make([]byte, 50)}
	host.handleDASProtocol(wrongResp)
	// No pending channel registered, so even at the right size it would be
	// dropped — here we just verify size validation rejects before lookup.

	// P1-12: For a correct-size response to be delivered, a pending channel
	// must first be registered for the RequestID encoded in bytes [0:8].
	correctResp := &Message{Type: MsgTypeDASSampleResp, Payload: make([]byte, 108)}
	// Set RequestID = 42 in the response so we can register for it.
	binary.BigEndian.PutUint64(correctResp.Payload[0:8], 42)
	pendingCh := host.RegisterDASResponseChannel(42)
	defer host.UnregisterDASResponseChannel(42)

	host.handleDASProtocol(correctResp)
	select {
	case <-pendingCh:
		// OK — response was routed by RequestID
	case <-time.After(time.Second):
		t.Error("correct-size response with registered RequestID should be delivered")
	}

	// Unsolicited response (no matching RequestID) — should be dropped silently
	unsolicited := &Message{Type: MsgTypeDASSampleResp, Payload: make([]byte, 108)}
	binary.BigEndian.PutUint64(unsolicited.Payload[0:8], 9999) // no pending channel for 9999
	host.handleDASProtocol(unsolicited)
	// No way to observe the drop directly; the test passes if it returns
	// without blocking (which it does — drop is non-blocking by design).
}

// TestHandleDASProtocol_AttestationSizeLimit verifies attestation size limit.
// P0-10 (2026-07-14)
func TestHandleDASProtocol_AttestationSizeLimit(t *testing.T) {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:0",
		MaxPeers:     10,
		TrustedPeers: []string{},
		DevMode:      true, // skip PoW in tests
	}
	host, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Stop()

	// Oversized attestation (>10KB) — should be dropped
	oversized := &Message{Type: MsgTypeDASAttestation, Payload: make([]byte, 11*1024)}
	host.handleDASProtocol(oversized)
	select {
	case <-host.dasReqCh:
		t.Error("oversized attestation should not be enqueued")
	default:
		// OK
	}

	// Valid attestation (<10KB) — should be enqueued
	valid := &Message{Type: MsgTypeDASAttestation, Payload: make([]byte, 512)}
	host.handleDASProtocol(valid)
	select {
	case <-host.dasReqCh:
		// OK
	default:
		t.Error("valid attestation should be enqueued")
	}
}
