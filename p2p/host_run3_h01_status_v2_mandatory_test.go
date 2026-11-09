// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
//
// AUDIT run-3 H-01 / run-13 qau.p2p/status-replay-validator-map-hijack
// regression tests: with the Protocol V2 receiver controls wired
// (freshness window + session-nonce tracker), a SIGNED status frame can
// only register the Address→PeerID mapping when it carries a fresh V2
// extension. V1-shaped frames (no timestamp, no nonce) are rejected —
// previously they skipped every replay/freshness check, so any captured
// legacy signature could be replayed forever to hijack TSS routing.
package p2p

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// h01HostForTest returns a real Host with the V2 receiver controls wired
// the same way node.initP2P does.
func h01HostForTest(t *testing.T) *Host {
	t.Helper()
	h := r38P2_01Deep_newHostForTest(t)
	h.SetStatusFreshnessWindowSec(120)
	h.SetSessionNonceTracker(NewSessionNonceTracker())
	return h
}

// TestH01_V1ShapedSignedStatusCannotRegisterMapping pins the core fix:
// a validly signed V1 frame (signature over base[:104] only, no V2
// extension) must NOT register the mapping while the freshness window is
// configured.
func TestH01_V1ShapedSignedStatusCannotRegisterMapping(t *testing.T) {
	honestKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := honestKey.Public.Address()

	encoded, _, err := encodeSignedStatusForTest(honestKey.Private, honestKey.Public.Bytes(), addr)
	if err != nil {
		t.Fatalf("encodeSignedStatusForTest: %v", err)
	}

	h := h01HostForTest(t)
	if err := h.handleBaseProtocol(&Message{Type: MsgTypeStatus, From: PeerID("victim-peer"), Payload: encoded}); err != nil {
		t.Fatalf("handleBaseProtocol: %v", err)
	}

	if pid, ok := h.GetPeerIDForValidator(addr); ok {
		t.Fatalf("H01 regression: V1-shaped signed status registered the mapping (to %q) — replay protection bypassed", pid)
	}
}

// TestH01_LegacyConfigKeepsV1Behavior documents the semantics boundary:
// with NO window and NO tracker wired (pre-H01 receivers), the V1-shaped
// frame still registers. This keeps the change strictly opt-in per
// receiver configuration.
func TestH01_LegacyConfigKeepsV1Behavior(t *testing.T) {
	honestKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := honestKey.Public.Address()

	encoded, _, err := encodeSignedStatusForTest(honestKey.Private, honestKey.Public.Bytes(), addr)
	if err != nil {
		t.Fatalf("encodeSignedStatusForTest: %v", err)
	}

	h := r38P2_01Deep_newHostForTest(t) // no window, no tracker
	if err := h.handleBaseProtocol(&Message{Type: MsgTypeStatus, From: PeerID("victim-peer"), Payload: encoded}); err != nil {
		t.Fatalf("handleBaseProtocol: %v", err)
	}

	if _, ok := h.GetPeerIDForValidator(addr); !ok {
		t.Fatal("legacy receiver (no V2 controls wired) must keep registering V1-shaped frames")
	}
}

// TestH01_V2StatusRegistersMapping pins the happy path: a fresh V2 frame
// signed over the extended domain registers the mapping for the honest
// peer.
func TestH01_V2StatusRegistersMapping(t *testing.T) {
	honestKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := honestKey.Public.Address()

	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	encoded := r38P2_01Deep_buildSignedStatusPayload(
		t, 1, 1668, 42, [32]byte{0xBB}, [32]byte{0x47},
		addr, honestKey.Public, honestKey.Private,
		uint64(time.Now().Unix()), nonce,
	)

	h := h01HostForTest(t)
	if err := h.handleBaseProtocol(&Message{Type: MsgTypeStatus, From: PeerID("victim-peer"), Payload: encoded}); err != nil {
		t.Fatalf("handleBaseProtocol: %v", err)
	}

	pid, ok := h.GetPeerIDForValidator(addr)
	if !ok || pid != PeerID("victim-peer") {
		t.Fatalf("H01 regression: fresh V2 status must register the mapping, got pid=%q ok=%v", pid, ok)
	}
}

// TestH01_V2ReplayFromDifferentPeerRejected pins the cross-peer replay
// fix: capturing the victim's V2 frame and replaying it from the
// attacker's peer identity must not re-point the mapping.
func TestH01_V2ReplayFromDifferentPeerRejected(t *testing.T) {
	honestKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := honestKey.Public.Address()

	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}
	encoded := r38P2_01Deep_buildSignedStatusPayload(
		t, 1, 1668, 42, [32]byte{0xBB}, [32]byte{0x47},
		addr, honestKey.Public, honestKey.Private,
		uint64(time.Now().Unix()), nonce,
	)

	h := h01HostForTest(t)

	// Honest delivery registers the mapping.
	if err := h.handleBaseProtocol(&Message{Type: MsgTypeStatus, From: PeerID("victim-peer"), Payload: encoded}); err != nil {
		t.Fatalf("handleBaseProtocol(honest): %v", err)
	}

	// Captured-frame replay from the attacker's peer identity.
	if err := h.handleBaseProtocol(&Message{Type: MsgTypeStatus, From: PeerID("attacker-peer"), Payload: encoded}); err != nil {
		t.Fatalf("handleBaseProtocol(replay): %v", err)
	}

	pid, ok := h.GetPeerIDForValidator(addr)
	if !ok || pid != PeerID("victim-peer") {
		t.Fatalf("H01 regression: cross-peer replay re-pointed the mapping to %q", pid)
	}
}
