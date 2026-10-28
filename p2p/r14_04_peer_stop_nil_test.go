package p2p

import (
	"context"
	"testing"
	"time"
)

// R14-04 regression (2026-10-27): handleInboundConnection reserves a slot in
// h.peers with a PLACEHOLDER Peer{ID, Addr, Connected, Direction} while the
// handshake is in flight — that placeholder has no ctx and no cancel. Both
// teardown loops that walk the whole table (Stop and
// disconnectAllPeersForCertRotation) called peer.cancel() unconditionally, so a
// shutdown or certificate rotation that overlapped an in-flight inbound
// handshake hit a nil func call: an unrecoverable panic. Worse, both loops hold
// h.peersMu while iterating, so the panic left the peer mutex locked forever and
// every later peer operation deadlocked.
func TestR14_04_PeerStopIsNilSafe(t *testing.T) {
	// Placeholder entry exactly as handleInboundConnection builds it.
	placeholder := &Peer{
		ID:        placeholderPeerPrefix + "203.0.113.9:4242",
		Addr:      "203.0.113.9:4242",
		Connected: false,
		Direction: DirInbound,
	}
	if placeholder.cancel != nil {
		t.Fatal("precondition: a placeholder carries no cancel func")
	}
	placeholder.stop() // must be a no-op, not a panic

	// A nil receiver must also be tolerated by callers that raced a delete.
	var nilPeer *Peer
	nilPeer.stop()

	// A real peer's cancel must still fire.
	ctx, cancel := context.WithCancel(context.Background())
	real := &Peer{ID: "real", cancel: cancel}
	real.stop()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("real peer cancel must still run")
	}
}

// Host.Stop walks h.peers; a placeholder left behind by an in-flight handshake
// must not panic the shutdown path.
func TestR14_04_HostStopToleratesPlaceholderPeer(t *testing.T) {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:0",
		MaxPeers:     10,
		TrustedPeers: []string{},
		DevMode:      true, // skip PoW in tests
	}
	h, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}

	// Exactly what handleInboundConnection reserves mid-handshake.
	pid := PeerID(placeholderPeerPrefix + "203.0.113.9:4242")
	h.peersMu.Lock()
	h.peers[pid] = &Peer{
		ID:        pid,
		Addr:      "203.0.113.9:4242",
		Connected: false,
		Direction: DirInbound,
	}
	h.peersMu.Unlock()

	// Stop is synchronous: a panic here fails the test, and a deadlock trips
	// the package test timeout.
	if err := h.Stop(); err != nil {
		t.Fatalf("Stop on a host holding a placeholder peer returned: %v", err)
	}
}

// Certificate rotation clears the whole table; the same placeholder must not
// panic it (this path also runs in the rotation goroutine, where a panic takes
// down the node's background work).
func TestR14_04_CertRotationTeardownToleratesPlaceholderPeer(t *testing.T) {
	scorer := NewPeerScorer()
	defer scorer.Stop()

	h := &Host{
		peerScorer: scorer,
		peers: map[PeerID]*Peer{
			// Addr deliberately empty: this test is about the nil cancel, not
			// about the re-dial goroutine (a real addr would open a socket).
			placeholderPeerPrefix + "203.0.113.9:4242": {
				ID:        placeholderPeerPrefix + "203.0.113.9:4242",
				Connected: false,
				Direction: DirInbound,
			},
		},
	}

	h.disconnectAllPeersForCertRotation()

	if n := len(h.peers); n != 0 {
		t.Fatalf("peer table must be cleared after rotation teardown, %d remain", n)
	}
}
