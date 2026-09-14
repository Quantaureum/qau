// Quantaureum Node source, version 1.0.0.
// Package p2p — R37-P3-18 regression tests.
//
// R37-P3-18 (2026-07-31): validatorPeerMap had (a) no cleanup when a peer
// disconnected, so validator→PeerID mappings lingered and directed TSS
// point-to-point messages (SendTSSToValidator) could be routed to a dead
// peer, and (b) no size cap, so a buggy/compromised caller could grow the
// map without bound.
//
// The fix:
//  1. Peer.disconnectCleanup (the once-guarded funnel reached by every
//     disconnect path) now calls removeValidatorMappingsForPeer(p.ID).
//  2. RegisterValidatorPeer enforces MaxValidatorPeerEntries (10000);
//     re-registration of an existing address is always allowed.
//
// These tests verify:
//  1. Disconnecting a peer removes exactly its validator mappings and
//     leaves other peers' mappings intact.
//  2. The map is capped at MaxValidatorPeerEntries; new addresses are
//     rejected at capacity while existing addresses can still update.
package p2p

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR37_P3_18_ValidatorPeerMap_DisconnectCleanup verifies that running the
// per-peer disconnect cleanup removes all validator mappings pointing to the
// disconnected peer, and only those.
func TestR37_P3_18_ValidatorPeerMap_DisconnectCleanup(t *testing.T) {
	host, err := NewHost(&Config{
		ListenAddr: "127.0.0.1:0",
		MaxPeers:   10,
		NetworkID:  1333,
	})
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Stop()

	addrA1 := types.BytesToAddress([]byte{0xA1})
	addrA2 := types.BytesToAddress([]byte{0xA2})
	addrB1 := types.BytesToAddress([]byte{0xB1})

	// Two validators on peer-A, one on peer-B.
	// AUDIT-FULL H-2: tests use the trusted internal registration path
	// (the exported one is capability-gated now).
	host.registerValidatorPeer(addrA1, "peer-A")
	host.registerValidatorPeer(addrA2, "peer-A")
	host.registerValidatorPeer(addrB1, "peer-B")

	// Simulate peer-A's disconnect cleanup (the once-guarded funnel used by
	// readLoop/writeLoop defers, Disconnect and disconnectPeer).
	p := &Peer{ID: "peer-A", Addr: "127.0.0.1:1234"}
	p.disconnectCleanup(host)

	if _, ok := host.GetPeerIDForValidator(addrA1); ok {
		t.Error("R37-P3-18 NOT FIXED: mapping addrA1->peer-A survived peer-A disconnect")
	}
	if _, ok := host.GetPeerIDForValidator(addrA2); ok {
		t.Error("R37-P3-18 NOT FIXED: mapping addrA2->peer-A survived peer-A disconnect")
	}
	pid, ok := host.GetPeerIDForValidator(addrB1)
	if !ok || pid != "peer-B" {
		t.Errorf("mapping addrB1->peer-B should be unaffected, got pid=%q ok=%v", pid, ok)
	}

	// Cleanup must be idempotent-safe for a peer with no mappings.
	pB := &Peer{ID: "peer-B", Addr: "127.0.0.1:1235"}
	pB.disconnectCleanup(host)
	if _, ok := host.GetPeerIDForValidator(addrB1); ok {
		t.Error("mapping addrB1->peer-B should be removed after peer-B disconnect")
	}
}

// TestR37_P3_18_ValidatorPeerMap_SizeCap verifies that RegisterValidatorPeer
// enforces MaxValidatorPeerEntries: new addresses are rejected at capacity,
// while existing addresses may still be re-registered (PeerID update).
func TestR37_P3_18_ValidatorPeerMap_SizeCap(t *testing.T) {
	// Minimal host: only the map is needed for RegisterValidatorPeer.
	h := &Host{validatorPeerMap: make(map[types.Address]PeerID)}

	addrAt := func(i int) types.Address {
		var a types.Address
		binary.BigEndian.PutUint64(a[12:], uint64(i))
		return a
	}

	// Fill the map to capacity.
	for i := 0; i < MaxValidatorPeerEntries; i++ {
		h.registerValidatorPeer(addrAt(i), PeerID(fmt.Sprintf("peer-%d", i)))
	}
	if got := len(h.validatorPeerMap); got != MaxValidatorPeerEntries {
		t.Fatalf("map size = %d, want %d", got, MaxValidatorPeerEntries)
	}

	// A NEW address beyond capacity must be rejected.
	overflowAddr := addrAt(MaxValidatorPeerEntries)
	h.registerValidatorPeer(overflowAddr, "peer-overflow")
	if got := len(h.validatorPeerMap); got != MaxValidatorPeerEntries {
		t.Errorf("R37-P3-18 NOT FIXED: map grew past cap to %d entries", got)
	}
	if _, ok := h.GetPeerIDForValidator(overflowAddr); ok {
		t.Error("R37-P3-18 NOT FIXED: overflow address was registered despite cap")
	}

	// Re-registering an EXISTING address must still update its PeerID.
	existing := addrAt(0)
	h.registerValidatorPeer(existing, "peer-updated")
	pid, ok := h.GetPeerIDForValidator(existing)
	if !ok || pid != "peer-updated" {
		t.Errorf("existing address re-registration failed, got pid=%q ok=%v", pid, ok)
	}
}
