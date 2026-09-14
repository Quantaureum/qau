// Quantaureum Node source, version 1.0.0.
// Package p2p — R37-P3-19 regression tests.
//
// R37-P3-19 (2026-07-31): Host.Stop() stopped the rate limiters, blacklist,
// penalty manager and gossipsub router, but never stopped the Broadcaster
// (cleanupCache goroutine, broadcast.go) or the PeerScorer
// (backgroundCleanup goroutine, peer_score.go). Both goroutines outlived
// Host.Stop(), leaking on shutdown and on every test host.
//
// The fix: Host.Stop() now calls broadcaster.Stop() and peerScorer.Stop()
// (both sync.Once-guarded, nil-checked).
//
// These tests verify:
//  1. After Host.Stop(), both components' stop channels are closed.
//  2. Host.Stop() remains idempotent (second call must not panic).
package p2p

import (
	"testing"
)

// TestR37_P3_19_Stop_StopsBroadcasterAndPeerScorer verifies that Host.Stop
// terminates the Broadcaster and PeerScorer background goroutines.
func TestR37_P3_19_Stop_StopsBroadcasterAndPeerScorer(t *testing.T) {
	host, err := NewHost(&Config{
		ListenAddr: "127.0.0.1:0",
		MaxPeers:   10,
		NetworkID:  1333,
	})
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}

	if host.broadcaster == nil {
		t.Fatal("broadcaster should be initialized by NewHost")
	}
	if host.peerScorer == nil {
		t.Fatal("peerScorer should be initialized by NewHost")
	}

	if err := host.Stop(); err != nil {
		t.Fatalf("host.Stop failed: %v", err)
	}

	// stopCh closed => the background goroutine's select observes it and
	// returns. Both Stop() implementations only close stopCh.
	select {
	case <-host.broadcaster.stopCh:
	default:
		t.Error("R37-P3-19 NOT FIXED: broadcaster.stopCh not closed after Host.Stop " +
			"(cleanupCache goroutine leaked)")
	}
	select {
	case <-host.peerScorer.stopCh:
	default:
		t.Error("R37-P3-19 NOT FIXED: peerScorer.stopCh not closed after Host.Stop " +
			"(backgroundCleanup goroutine leaked)")
	}
}

// TestR37_P3_19_Stop_Idempotent verifies that calling Host.Stop twice does
// not panic now that broadcaster/peerScorer stops participate in shutdown.
func TestR37_P3_19_Stop_Idempotent(t *testing.T) {
	host, err := NewHost(&Config{
		ListenAddr: "127.0.0.1:0",
		MaxPeers:   10,
		NetworkID:  1333,
	})
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}

	if err := host.Stop(); err != nil {
		t.Fatalf("first host.Stop failed: %v", err)
	}
	// Second Stop: h.closed short-circuits, but even the component Stop
	// calls are sync.Once-guarded, so this must never panic.
	if err := host.Stop(); err != nil {
		t.Fatalf("second host.Stop failed: %v", err)
	}
}
