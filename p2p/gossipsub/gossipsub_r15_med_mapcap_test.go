// Quantaureum Node source, version 1.0.0.
// Package gossipsub — R15-MED regression tests for rate-limiter map bounding.
//
// AUDIT (2026) R15-MED (P2P-R15-M): The iwantRateLimit and
// graftRateLimit maps are swept every heartbeat by sweepStaleRateTrackers,
// but a burst of sybil peers connecting within one heartbeat window could
// grow either map beyond the P2P host's max-peer limit before the sweep
// runs. The fix adds a defensive hard cap (10000 entries) with immediate
// stale eviction when the threshold is reached. Fail-closed: if the map is
// still at cap after eviction (all entries fresh), reject the new entry
// rather than allowing growth.
//
// These tests verify:
//  1. The graftRateLimit map cannot grow beyond maxGraftTrackerEntries.
//  2. When the cap is reached, stale entries are evicted to make room.
//  3. When all entries are fresh and the cap is reached, new entries are
//     rejected (fail-closed) rather than allowing unbounded growth.
package gossipsub

import (
	"testing"
	"time"
)

// TestP2P_R15_M_GraftRateLimitMapBoundedStaleEviction verifies that when
// the graftRateLimit map reaches the hard cap, stale entries are evicted
// to make room for the new entry. This is the primary defense against
// sybil-burst memory exhaustion.
//
// Note: allowGraft's cap check uses cutoff = time.Now() - window. An entry
// is evictable only if its windowEnd < cutoff, i.e. windowEnd < now - window.
// Since entries are normally created with windowEnd = now + window, they
// become evictable only after 2*window has elapsed. To test the eviction
// path deterministically without long sleeps, we pre-populate the map with
// explicitly stale entries (windowEnd far in the past) and then call
// allowGraft to verify the cap + eviction logic.
func TestP2P_R15_M_GraftRateLimitMapBoundedStaleEviction(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	const maxPerWindow = 50
	const window = 10 * time.Second

	// Pre-populate graftRateLimit with maxGraftTrackerEntries stale entries.
	// We use a windowEnd far in the past so they are eligible for eviction
	// under any reasonable cutoff.
	const maxGraftTrackerEntries = 10000
	staleTime := time.Now().Add(-30 * time.Second)
	gs.graftRateMu.Lock()
	for i := 0; i < maxGraftTrackerEntries; i++ {
		peer := string(rune(i))
		gs.graftRateLimit[peer] = &graftRateTracker{
			count:     0,
			windowEnd: staleTime,
		}
	}
	gs.graftRateMu.Unlock()

	// allowGraft from a new peer should trigger stale eviction and admit
	// the new entry. If the cap logic is broken, this would either
	// return false (regression) or grow the map unboundedly.
	allowed := gs.allowGraft("newpeer", maxPerWindow, window)
	if !allowed {
		t.Fatal("allowGraft(newpeer) should succeed after stale eviction — cap must not block when stale entries can be evicted")
	}

	gs.graftRateMu.Lock()
	_, exists := gs.graftRateLimit["newpeer"]
	size := len(gs.graftRateLimit)
	gs.graftRateMu.Unlock()
	if !exists {
		t.Fatal("newpeer entry should exist in graftRateLimit after allowGraft returned true")
	}
	if size > maxGraftTrackerEntries {
		t.Errorf("graftRateLimit size %d exceeds cap %d — stale eviction did not work", size, maxGraftTrackerEntries)
	}
}

// TestP2P_R15_M_GraftRateLimitMapBoundedFailClosed verifies that when the
// cap is reached AND all entries are fresh (cannot be evicted), new entries
// are rejected (fail-closed) rather than allowing the map to grow.
func TestP2P_R15_M_GraftRateLimitMapBoundedFailClosed(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Use a long window so entries stay fresh.
	const maxPerWindow = 50
	const window = 10 * time.Second

	// Fill the map with maxGraftTrackerEntries fresh peers.
	const maxGraftTrackerEntries = 10000
	for i := 0; i < maxGraftTrackerEntries; i++ {
		peer := string(rune(i))
		gs.allowGraft(peer, maxPerWindow, window)
	}

	// Verify we hit the cap.
	gs.graftRateMu.Lock()
	sizeBefore := len(gs.graftRateLimit)
	gs.graftRateMu.Unlock()
	if sizeBefore != maxGraftTrackerEntries {
		t.Fatalf("expected map size %d, got %d", maxGraftTrackerEntries, sizeBefore)
	}

	// Add one more peer — all entries are fresh, so no eviction can occur.
	// allowGraft must return false (fail-closed) to prevent growth.
	allowed := gs.allowGraft("newpeer", maxPerWindow, window)
	if allowed {
		t.Fatal("allowGraft(newpeer) should return false (fail-closed) when cap is reached and no stale entries can be evicted")
	}

	// Verify the map size did not grow.
	gs.graftRateMu.Lock()
	sizeAfter := len(gs.graftRateLimit)
	gs.graftRateMu.Unlock()
	if sizeAfter > maxGraftTrackerEntries {
		t.Errorf("graftRateLimit size %d exceeds cap %d — fail-closed did not prevent growth", sizeAfter, maxGraftTrackerEntries)
	}
}

// TestP2P_R15_M_IWANTRateLimitMapBoundedStaleEviction verifies that when
// the iwantRateLimit map reaches the hard cap, stale entries are evicted
// to make room for the new entry. This is the primary defense against
// sybil-burst memory exhaustion for the IWANT path.
//
// Note: handleIWant uses internal hardcoded constants for the rate window
// (iwantRateWindow = 10s). To test stale eviction, we must wait for the
// window to elapse. To keep the test fast, we instead directly manipulate
// the iwantRateLimit map with stale entries, then call handleIWant to
// verify the cap + eviction logic.
func TestP2P_R15_M_IWANTRateLimitMapBoundedStaleEviction(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Pre-populate iwantRateLimit with maxIWANTTrackerEntries stale entries.
	// We use a windowEnd in the past so they are eligible for eviction.
	const maxIWANTTrackerEntries = 10000
	staleTime := time.Now().Add(-30 * time.Second)
	gs.iwantRateMu.Lock()
	for i := 0; i < maxIWANTTrackerEntries; i++ {
		peer := string(rune(i))
		gs.iwantRateLimit[peer] = &iwantRateTracker{
			count:     0,
			windowEnd: staleTime,
		}
	}
	gs.iwantRateMu.Unlock()

	// Build an IWANT control message from a new peer.
	rpc := &RPC{
		Control: &ControlMessage{
			IWant: []*ControlIWant{{MessageIDs: []MessageID{{0x01}}}},
		},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}

	// HandleRPC from a new peer should trigger stale eviction and admit
	// the new entry. If the cap logic is broken, this would either
	// silently drop the message (regression) or grow the map unboundedly.
	if err := gs.HandleRPC("newpeer", data); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// Verify the map size did not grow beyond the cap.
	gs.iwantRateMu.Lock()
	size := len(gs.iwantRateLimit)
	_, newPeerExists := gs.iwantRateLimit["newpeer"]
	gs.iwantRateMu.Unlock()
	if size > maxIWANTTrackerEntries {
		t.Errorf("iwantRateLimit size %d exceeds cap %d — stale eviction did not work", size, maxIWANTTrackerEntries)
	}
	if !newPeerExists {
		// The new peer's entry should have been admitted after eviction.
		// If it's not there, the cap check rejected it even though stale
		// entries were evictable — that's a bug.
		t.Error("newpeer entry should exist in iwantRateLimit after stale eviction admitted the new IWANT")
	}
}

// TestP2P_R15_M_IWANTRateLimitMapBoundedFailClosed verifies that when the
// iwantRateLimit cap is reached AND all entries are fresh, the new IWANT
// is silently dropped (fail-closed) rather than allowing the map to grow.
func TestP2P_R15_M_IWANTRateLimitMapBoundedFailClosed(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	if _, err := gs.JoinTopic(TopicBlocks, func(*Message) {}); err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Pre-populate iwantRateLimit with maxIWANTTrackerEntries fresh entries.
	const maxIWANTTrackerEntries = 10000
	freshTime := time.Now().Add(30 * time.Second)
	gs.iwantRateMu.Lock()
	for i := 0; i < maxIWANTTrackerEntries; i++ {
		peer := string(rune(i))
		gs.iwantRateLimit[peer] = &iwantRateTracker{
			count:     0,
			windowEnd: freshTime,
		}
	}
	gs.iwantRateMu.Unlock()

	// Build an IWANT control message from a new peer.
	rpc := &RPC{
		Control: &ControlMessage{
			IWant: []*ControlIWant{{MessageIDs: []MessageID{{0x01}}}},
		},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}

	// HandleRPC from a new peer — all entries are fresh, so no eviction
	// can occur. handleIWant must silently drop the message (fail-closed)
	// to prevent unbounded growth.
	if err := gs.HandleRPC("newpeer", data); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// Verify the map size did not grow beyond the cap.
	gs.iwantRateMu.Lock()
	size := len(gs.iwantRateLimit)
	_, newPeerExists := gs.iwantRateLimit["newpeer"]
	gs.iwantRateMu.Unlock()
	if size > maxIWANTTrackerEntries {
		t.Errorf("iwantRateLimit size %d exceeds cap %d — fail-closed did not prevent growth", size, maxIWANTTrackerEntries)
	}
	if newPeerExists {
		t.Error("newpeer entry should NOT exist in iwantRateLimit when cap is reached and no stale entries can be evicted (fail-closed)")
	}
}
