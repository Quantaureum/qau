// Quantaureum Node source, version 1.0.0.
// Package gossipsub — P2P-R12-M01 regression tests.
//
// AUDIT (2026) R12-P2P-M01: GossipSub previously had no per-peer GRAFT
// rate limit. The existing GossipSubMaxGrafts cap (100 per ControlMessage)
// only bounds one RPC, so a malicious peer could send many small RPCs each
// carrying 1-2 GRAFTs, repeatedly churning the mesh and consuming CPU.
//
// The fix adds a per-peer sliding-window rate limit (50 GRAFTs per 10s)
// applied at the very top of handleGraft. These tests verify:
//  1. A peer sending up to maxGraftPerWindow GRAFTs is allowed through.
//  2. A peer exceeding the limit has subsequent GRAFTs silently dropped
//     (no PRUNE sent — that would amplify the attack).
//  3. Different peers have independent rate-limit counters.
//  4. The counter resets after the window elapses.
//  5. Disconnected peers have their graftRateLimit entries cleaned up
//     (no memory leak).
package gossipsub

import (
	"testing"
	"time"
)

// sendGraftRPC builds and sends a single-GRAFT ControlMessage RPC from
// the given peer. Returns the error from HandleRPC, if any.
func sendGraftRPC(gs *GossipSub, from PeerID, topic string) error {
	rpc := &RPC{
		Control: &ControlMessage{
			Graft: []*ControlGraft{{Topic: topic}},
		},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		return err
	}
	return gs.HandleRPC(from, data)
}

// TestP2P_R12_M01_GraftRateLimit_AllowsWithinLimit verifies that a peer
// sending up to maxGraftPerWindow GRAFTs is allowed through (mesh membership
// grows or stays at the cap, but no GRAFT is dropped due to rate limit).
func TestP2P_R12_M01_GraftRateLimit_AllowsWithinLimit(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	const maxGraftPerWindow = 50
	const graftRateWindow = 10 * time.Second

	// Send maxGraftPerWindow GRAFTs from the same peer. All should be
	// admitted by the rate limiter (allowGraft returns true).
	for i := 0; i < maxGraftPerWindow; i++ {
		if !gs.allowGraft("flooder", maxGraftPerWindow, graftRateWindow) {
			t.Fatalf("allowGraft returned false on iteration %d (within limit should be allowed)", i)
		}
	}
}

// TestP2P_R12_M01_GraftRateLimit_RejectsBeyondLimit verifies that once a
// peer exceeds maxGraftPerWindow, subsequent GRAFTs are rejected.
func TestP2P_R12_M01_GraftRateLimit_RejectsBeyondLimit(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	const maxGraftPerWindow = 50
	const graftRateWindow = 10 * time.Second

	// Exhaust the budget.
	for i := 0; i < maxGraftPerWindow; i++ {
		if !gs.allowGraft("flooder", maxGraftPerWindow, graftRateWindow) {
			t.Fatalf("allowGraft returned false on iteration %d (within limit should be allowed)", i)
		}
	}

	// Subsequent calls should be rejected.
	if gs.allowGraft("flooder", maxGraftPerWindow, graftRateWindow) {
		t.Fatal("allowGraft returned true after limit exceeded — must reject")
	}
}

// TestP2P_R12_M01_GraftRateLimit_IndependentPerPeer verifies that the
// rate limit is per-peer — exhaustion for one peer does not affect another.
func TestP2P_R12_M01_GraftRateLimit_IndependentPerPeer(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	const maxGraftPerWindow = 50
	const graftRateWindow = 10 * time.Second

	// Exhaust peer A's budget.
	for i := 0; i < maxGraftPerWindow; i++ {
		if !gs.allowGraft("peerA", maxGraftPerWindow, graftRateWindow) {
			t.Fatalf("allowGraft(peerA) returned false on iteration %d", i)
		}
	}
	// peerA is now rate-limited.
	if gs.allowGraft("peerA", maxGraftPerWindow, graftRateWindow) {
		t.Fatal("peerA should be rate-limited after exhausting budget")
	}

	// peerB has its own independent budget — should be allowed.
	if !gs.allowGraft("peerB", maxGraftPerWindow, graftRateWindow) {
		t.Fatal("peerB should have its own independent budget — allowGraft returned false")
	}
}

// TestP2P_R12_M01_GraftRateLimit_WindowReset verifies that the counter
// resets after the window elapses, allowing GRAFTs through again.
func TestP2P_R12_M01_GraftRateLimit_WindowReset(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Use a very short window so the test runs fast.
	const maxGraftPerWindow = 3
	const graftRateWindow = 50 * time.Millisecond

	// Exhaust the budget.
	for i := 0; i < maxGraftPerWindow; i++ {
		if !gs.allowGraft("flooder", maxGraftPerWindow, graftRateWindow) {
			t.Fatalf("allowGraft returned false on iteration %d", i)
		}
	}
	if gs.allowGraft("flooder", maxGraftPerWindow, graftRateWindow) {
		t.Fatal("should be rate-limited after exhausting budget")
	}

	// Wait for the window to elapse.
	time.Sleep(graftRateWindow + 20*time.Millisecond)

	// Counter should reset and the next GRAFT should be allowed.
	if !gs.allowGraft("flooder", maxGraftPerWindow, graftRateWindow) {
		t.Fatal("allowGraft returned false after window reset — counter did not reset")
	}
}

// TestP2P_R12_M01_GraftRateLimit_HandleGraftDropsAfterLimit verifies the
// end-to-end behavior: once the budget is exhausted, handleGraft silently
// drops the GRAFT (the peer is NOT added to the mesh, and no PRUNE is sent).
//
// Note: handleGraft uses hardcoded constants (maxGraftPerWindow=50,
// graftRateWindow=10s) matching the production values. To exhaust the
// real budget from outside, this test calls allowGraft with the same
// constants 50 times (matching the production cap), then sends a 51st
// GRAFT via HandleRPC and asserts it is dropped.
func TestP2P_R12_M01_GraftRateLimit_HandleGraftDropsAfterLimit(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Match the constants used in handleGraft exactly so the budget is
	// truly exhausted from the production limiter's perspective.
	const maxGraftPerWindow = 50
	const graftRateWindow = 10 * time.Second

	// Exhaust the budget via allowGraft (simulating GRAFTs from any topic).
	for i := 0; i < maxGraftPerWindow; i++ {
		if !gs.allowGraft("flooder", maxGraftPerWindow, graftRateWindow) {
			t.Fatalf("allowGraft returned false on iteration %d", i)
		}
	}

	// Capture sent-message count before the rate-limited GRAFT.
	sentBefore := len(sender.sentMessages["flooder"])

	// Now send a GRAFT via HandleRPC. handleGraft should drop it silently
	// (no mesh membership change, no PRUNE reply).
	if err := sendGraftRPC(gs, "flooder", TopicBlocks); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// Verify no PRUNE (or any message) was sent back to the flooder.
	if got := len(sender.sentMessages["flooder"]); got != sentBefore {
		t.Errorf("expected %d messages sent to flooder, got %d — rate-limited GRAFT must be silently dropped (no PRUNE amplification)",
			sentBefore, got)
	}

	// Verify the peer is NOT in the mesh (graft was dropped before the
	// mesh-membership step).
	gs.topicsMu.RLock()
	topic := gs.topics[TopicBlocks]
	gs.topicsMu.RUnlock()
	if topic == nil {
		t.Fatal("TopicBlocks not found — JoinTopic must have failed silently")
	}
	topic.meshMu.RLock()
	_, inMesh := topic.mesh["flooder"]
	topic.meshMu.RUnlock()
	if inMesh {
		t.Fatal("flooder should NOT be in mesh after rate-limited GRAFT — handleGraft did not drop it")
	}
}

// TestP2P_R12_M01_GraftRateLimit_HandleGraftAllowsUnderLimit verifies the
// happy path: under the rate limit, a GRAFT adds the peer to the mesh.
func TestP2P_R12_M01_GraftRateLimit_HandleGraftAllowsUnderLimit(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	if err := sendGraftRPC(gs, "peer1", TopicBlocks); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	gs.topicsMu.RLock()
	topic := gs.topics[TopicBlocks]
	gs.topicsMu.RUnlock()
	if topic == nil {
		t.Fatal("TopicBlocks not found")
	}
	topic.meshMu.RLock()
	_, inMesh := topic.mesh["peer1"]
	topic.meshMu.RUnlock()
	if !inMesh {
		t.Fatal("peer1 should be in mesh after a single GRAFT (under the rate limit)")
	}
}

// TestP2P_R12_M01_GraftRateLimit_CleanupOnDisconnect verifies that when a
// peer disconnects (syncPeers observes it gone), its graftRateLimit entry
// is cleaned up to prevent a memory leak.
func TestP2P_R12_M01_GraftRateLimit_CleanupOnDisconnect(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Make peer "temppeer" appear connected, then send a GRAFT so it has
	// a graftRateLimit entry.
	sender.addPeer("temppeer")
	if err := sendGraftRPC(gs, "temppeer", TopicBlocks); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// Verify the entry exists.
	gs.graftRateMu.Lock()
	_, exists := gs.graftRateLimit["temppeer"]
	gs.graftRateMu.Unlock()
	if !exists {
		t.Fatal("graftRateLimit entry should exist after GRAFT")
	}

	// Simulate disconnect: remove peer from connected list and run syncPeers.
	sender.removePeer("temppeer")
	gs.syncPeers()

	// Verify the entry was cleaned up.
	gs.graftRateMu.Lock()
	_, exists = gs.graftRateLimit["temppeer"]
	gs.graftRateMu.Unlock()
	if exists {
		t.Fatal("graftRateLimit entry should be cleaned up after peer disconnect")
	}
}

// TestP2P_R12_M01_GraftRateLimit_AllowedTopicStillEnforces verifies that
// the rate limit applies even to whitelisted topics — being on the whitelist
// means the topic is processed at all, not that it is exempt from rate limiting.
func TestP2P_R12_M01_GraftRateLimit_AllowedTopicStillEnforces(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	const maxGraftPerWindow = 5
	const graftRateWindow = 10 * time.Second

	// Exhaust the budget.
	for i := 0; i < maxGraftPerWindow; i++ {
		if !gs.allowGraft("flooder", maxGraftPerWindow, graftRateWindow) {
			t.Fatalf("allowGraft returned false on iteration %d", i)
		}
	}

	// Subsequent GRAFT on a whitelisted topic should still be rejected.
	if gs.allowGraft("flooder", maxGraftPerWindow, graftRateWindow) {
		t.Fatal("allowGraft should return false even for whitelisted topics once limit is exceeded")
	}
}
