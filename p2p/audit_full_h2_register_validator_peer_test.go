// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// AUDIT-FULL H-2 FIX (2026-08-14): regression tests for the capability-gated
// RegisterValidatorPeer.
//
// Symptom being fixed: the exported RegisterValidatorPeer had no caller
// authentication — any internal module or compromised code path holding the
// Host could install an arbitrary (address, peerID) mapping and hijack
// directed TSS message routing. Now the exported entry point is denied by
// default; only the Host's verified status path (internal
// registerValidatorPeer) or the node layer after an explicit
// AuthorizeValidatorRegistration can write mappings.

func TestAuditFull_H2_ExportedRegisterDeniedByDefault(t *testing.T) {
	h := &Host{validatorPeerMap: make(map[types.Address]PeerID)}
	addr := types.BytesToAddress([]byte{0xC2})

	h.RegisterValidatorPeer(addr, "attacker-peer")

	if _, ok := h.GetPeerIDForValidator(addr); ok {
		t.Fatal("AUDIT-FULL H-2: unauthorized RegisterValidatorPeer call mutated the validator peer map")
	}
}

func TestAuditFull_H2_AuthorizedRegisterWorks(t *testing.T) {
	h := &Host{validatorPeerMap: make(map[types.Address]PeerID)}
	addr := types.BytesToAddress([]byte{0xA2})

	h.AuthorizeValidatorRegistration()
	h.RegisterValidatorPeer(addr, "node-registered-peer")

	pid, ok := h.GetPeerIDForValidator(addr)
	if !ok || pid != "node-registered-peer" {
		t.Fatalf("AUDIT-FULL H-2: authorized registration failed, got pid=%q ok=%v", pid, ok)
	}
}

func TestAuditFull_H2_InternalTrustedPathUnaffected(t *testing.T) {
	h := &Host{validatorPeerMap: make(map[types.Address]PeerID)}
	addr := types.BytesToAddress([]byte{0xB3})

	// The verified status handler's path must work WITHOUT the capability.
	h.registerValidatorPeer(addr, "verified-status-peer")

	pid, ok := h.GetPeerIDForValidator(addr)
	if !ok || pid != "verified-status-peer" {
		t.Fatalf("AUDIT-FULL H-2: internal trusted registration path broken, got pid=%q ok=%v", pid, ok)
	}
}
