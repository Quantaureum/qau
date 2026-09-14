// Quantaureum Node source, version 1.0.0.
package node

import (
	"net"
	"testing"
)

// =============================================================================
// P2P-R13-CRIT-004 (2026-07-21) tests: P2P startup-order TOCTOU fix
//
// The fix splits the previous initP2P() (which created AND started the host
// in one call) into two methods:
//   - initP2P()         — creates the host, does NOT call Start()
//   - startP2P()        — calls p2pHost.Start()
//
// The Node.Start() ordering is now:
//   initP2P() → ... → startServices() → initP2PSignatureVerifier() → startP2P()
//
// This eliminates the multi-second TOCTOU window where the host was accepting
// connections while payloadVerifier was nil (signature verification silently
// skipped / fail-open).
// =============================================================================

// TestP2P_R13_CRIT_004_InitP2P_DoesNotStartHost verifies that initP2P()
// creates the host but does NOT call p2pHost.Start(). We prove this by
// binding the same listen address after initP2P() — if the host had started,
// the second bind would fail with "address already in use".
func TestP2P_R13_CRIT_004_InitP2P_DoesNotStartHost(t *testing.T) {
	// Find an available port, then release it so initP2P can bind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("precondition: find available port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &Config{
		Name:       "test-r13-crit004-init-does-not-start",
		DataDir:    t.TempDir(),
		ListenAddr: addr,
		MaxPeers:   1,
		EnableDHT:  false,
		DevMode:    true,
		NetworkID:  DevnetNetworkID,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	if err := n.initP2P(); err != nil {
		t.Fatalf("initP2P failed: %v", err)
	}
	if n.p2pHost == nil {
		t.Fatal("expected p2pHost to be non-nil after initP2P")
	}

	// CRITICAL ASSERTION: after initP2P(), the listen address must still be
	// bindable — proving initP2P() did NOT call p2pHost.Start() (which would
	// have bound the address and prevented this second bind).
	probe, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("P2P-R13-CRIT-004: listen addr %s was already bound after initP2P() — initP2P() must not call Start() (TOCTOU window): %v", addr, err)
	}
	probe.Close()

	// Now start the host via startP2P() — this SHOULD bind the address.
	if err := n.startP2P(); err != nil {
		t.Fatalf("startP2P failed: %v", err)
	}

	// After startP2P(), the address must be bound — proving startP2P() did
	// call p2pHost.Start().
	probe2, err := net.Listen("tcp", addr)
	if err == nil {
		probe2.Close()
		t.Errorf("P2P-R13-CRIT-004: listen addr %s was NOT bound after startP2P() — startP2P() must call Start()", addr)
	}

	_ = n.p2pHost.Stop()
}

// TestP2P_R13_CRIT_004_StartP2P_NilHostIsNoOp verifies that startP2P() is
// a safe no-op when p2pHost is nil (e.g., SyncOnlyMode or P2P disabled).
func TestP2P_R13_CRIT_004_StartP2P_NilHostIsNoOp(t *testing.T) {
	cfg := &Config{Name: "test-r13-crit004-nil-host", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	if n.p2pHost != nil {
		t.Fatal("test precondition: expected nil p2pHost")
	}

	// Must not panic; must return nil.
	if err := n.startP2P(); err != nil {
		t.Errorf("startP2P with nil p2pHost should be a no-op, got error: %v", err)
	}
}

// TestP2P_R13_CRIT_004_FullStartOrder verifies the full start order:
// initP2P → initP2PSignatureVerifier → startP2P succeeds end-to-end.
// This is a smoke test that exercises the split lifecycle in the same
// sequence as Node.Start().
func TestP2P_R13_CRIT_004_FullStartOrder(t *testing.T) {
	cfg := &Config{
		Name:       "test-r13-crit004-full-order",
		DataDir:    t.TempDir(),
		ListenAddr: "127.0.0.1:0",
		MaxPeers:   1,
		EnableDHT:  false,
		DevMode:    true,
		NetworkID:  DevnetNetworkID,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	// Step 1: initP2P — creates host, does not start it.
	if err := n.initP2P(); err != nil {
		t.Fatalf("initP2P failed: %v", err)
	}

	// Step 2: initP2PSignatureVerifier — wires verifier (host still not started,
	// so no connections can arrive yet — no TOCTOU window).
	// Must not panic. With DevMode=true and no blockProducer yet, the verifier
	// callbacks will fail-closed (ErrSignatureInvalid) — that's the correct
	// startup behavior. The important thing is that the verifier is wired
	// BEFORE the host starts accepting connections.
	n.initP2PSignatureVerifier()

	// Step 3: startP2P — NOW the host starts accepting connections, with
	// the verifier already in place.
	if err := n.startP2P(); err != nil {
		t.Fatalf("startP2P failed: %v", err)
	}

	// Verify the host is actually running by checking that it has a listener.
	// We can't read h.listener directly, but EnodeURL() requires the host
	// to be initialized — and Stop() must not panic after Start().
	enode := n.p2pHost.EnodeURL()
	if enode == "" {
		t.Error("expected non-empty enode URL after startP2P")
	}

	_ = n.p2pHost.Stop()
}
