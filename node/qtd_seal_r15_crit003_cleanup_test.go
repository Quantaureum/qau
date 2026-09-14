// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p"
)

// P2P-R15-CRIT-003 (2026-07-22): qtdPeerRate map must be bounded by
// maxSize and clean up stale entries via TTL. Without this, the map grows
// unbounded on long-running nodes.

func TestP2P_R15_CRIT_003_CleanupRemovesStaleEntries(t *testing.T) {
	n := &Node{}
	n.ensureQTDSealLimiter()

	// Add 3 peers, 2 stale (lastSeen > 1h ago) and 1 fresh.
	now := time.Now()
	staleTime := now.Add(-2 * time.Hour)

	n.qtdPeerRtMu.Lock()
	n.qtdPeerRate["stale1"] = &qtdPeerRateInfo{windowStart: staleTime, count: 1, lastSeen: staleTime}
	n.qtdPeerRate["stale2"] = &qtdPeerRateInfo{windowStart: staleTime, count: 1, lastSeen: staleTime}
	n.qtdPeerRate["fresh1"] = &qtdPeerRateInfo{windowStart: now, count: 1, lastSeen: now}
	n.qtdPeerRtMu.Unlock()

	removed := n.CleanupQTDPeerRate()
	if removed != 2 {
		t.Errorf("expected 2 stale entries removed, got %d", removed)
	}
	if n.GetQTDPeerRateCount() != 1 {
		t.Errorf("expected 1 remaining entry, got %d", n.GetQTDPeerRateCount())
	}
}

func TestP2P_R15_CRIT_003_CleanupKeepsFreshEntries(t *testing.T) {
	n := &Node{}
	n.ensureQTDSealLimiter()

	now := time.Now()
	recent := now.Add(-30 * time.Minute) // < 1h TTL

	n.qtdPeerRtMu.Lock()
	n.qtdPeerRate["recent1"] = &qtdPeerRateInfo{windowStart: recent, count: 1, lastSeen: recent}
	n.qtdPeerRate["recent2"] = &qtdPeerRateInfo{windowStart: now, count: 1, lastSeen: now}
	n.qtdPeerRtMu.Unlock()

	removed := n.CleanupQTDPeerRate()
	if removed != 0 {
		t.Errorf("expected 0 entries removed (all fresh), got %d", removed)
	}
	if n.GetQTDPeerRateCount() != 2 {
		t.Errorf("expected 2 remaining entries, got %d", n.GetQTDPeerRateCount())
	}
}

func TestP2P_R15_CRIT_003_MaxSizeTriggersCleanup(t *testing.T) {
	// Verify that when the map reaches qtdPeerRateMaxSize, adding a new
	// peer triggers cleanup of stale entries.
	n := &Node{}
	n.ensureQTDSealLimiter()

	now := time.Now()
	staleTime := now.Add(-2 * time.Hour)

	// Fill map with stale entries up to maxSize.
	n.qtdPeerRtMu.Lock()
	for i := 0; i < qtdPeerRateMaxSize; i++ {
		peer := p2p.PeerID("stale-" + string(rune(i)))
		n.qtdPeerRate[peer] = &qtdPeerRateInfo{windowStart: staleTime, count: 1, lastSeen: staleTime}
	}
	n.qtdPeerRtMu.Unlock()

	if n.GetQTDPeerRateCount() != qtdPeerRateMaxSize {
		t.Fatalf("expected %d entries before trigger, got %d", qtdPeerRateMaxSize, n.GetQTDPeerRateCount())
	}

	// Adding a new peer should trigger cleanup (all stale entries removed).
	n.allowQTDSealFromPeer("new-peer")

	remaining := n.GetQTDPeerRateCount()
	if remaining != 1 {
		t.Errorf("expected 1 entry (new-peer) after cleanup, got %d", remaining)
	}
}

func TestP2P_R15_CRIT_003_LastSeenUpdatedOnAccess(t *testing.T) {
	// Verify that allowQTDSealFromPeer updates lastSeen so active peers
	// are not cleaned up.
	n := &Node{}
	n.ensureQTDSealLimiter()

	// First call — creates entry.
	n.allowQTDSealFromPeer("active-peer")
	if n.GetQTDPeerRateCount() != 1 {
		t.Fatalf("expected 1 entry, got %d", n.GetQTDPeerRateCount())
	}

	// Manually set lastSeen to old time to simulate inactivity.
	n.qtdPeerRtMu.Lock()
	n.qtdPeerRate["active-peer"].lastSeen = time.Now().Add(-2 * time.Hour)
	n.qtdPeerRtMu.Unlock()

	// Call allowQTDSealFromPeer again — should update lastSeen to now.
	n.allowQTDSealFromPeer("active-peer")

	// Now cleanup should NOT remove the entry (lastSeen was just updated).
	removed := n.CleanupQTDPeerRate()
	if removed != 0 {
		t.Errorf("active peer should not be cleaned up, removed=%d", removed)
	}
}
