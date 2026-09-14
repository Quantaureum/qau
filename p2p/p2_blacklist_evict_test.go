// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
	"time"
)

// TestP2_BLACKLIST_EVICT_PreservesLongBansUnderPressure verifies that when the
// blacklist is at capacity and a new entry is added, the eviction logic
// prefers to evict entries CLOSEST to expiration (short remaining ban time)
// rather than entries with the LONGEST remaining ban time.
//
// P2-BLACKLIST-EVICT FIX (R29, 2026-07-26): Previously, the eviction loop
// used Go's randomized map iteration order, which could evict a
// recently-added long ban (e.g., 1-hour ban applied 1 second ago) to make
// room for a new entry — defeating the purpose of the long ban. The fix
// sorts non-permanent entries by expiration time (ascending) and evicts
// from the closest-to-expiration first.
//
// This test creates a blacklist at capacity with two types of entries:
//   - "short" bans: expire in 5 seconds (close to expiration)
//   - "long" bans: expire in 1 hour (far from expiration)
//
// Then adds one more entry to trigger eviction, and verifies that ONLY
// short bans were evicted (long bans preserved).
func TestP2_BLACKLIST_EVICT_PreservesLongBansUnderPressure(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	// Set a small maxSize to make the test fast and deterministic.
	bl.maxSize = 10

	now := time.Now()

	// Fill the blacklist to capacity with a mix of short and long bans.
	// We add 5 short bans (expire in 5s) and 5 long bans (expire in 1h).
	// Total = 10 = maxSize (at capacity).
	for i := 0; i < 5; i++ {
		peer := PeerID("short-ban-")
		peer = peer + PeerID(rune('A'+i))
		bl.mu.Lock()
		bl.peers[peer] = &blacklistEntry{
			reason:    "short ban",
			expiresAt: now.Add(5 * time.Second),
			permanent: false,
		}
		bl.mu.Unlock()
	}
	for i := 0; i < 5; i++ {
		peer := PeerID("long-ban-")
		peer = peer + PeerID(rune('A'+i))
		bl.mu.Lock()
		bl.peers[peer] = &blacklistEntry{
			reason:    "long ban",
			expiresAt: now.Add(1 * time.Hour),
			permanent: false,
		}
		bl.mu.Unlock()
	}

	// Verify we're at capacity.
	bl.mu.Lock()
	initialSize := len(bl.peers)
	bl.mu.Unlock()
	if initialSize != 10 {
		t.Fatalf("initial size = %d, want 10 (at capacity)", initialSize)
	}

	// Add one more entry to trigger eviction.
	// This should evict the SHORT bans (closest to expiration) first.
	newPeer := PeerID("new-peer-triggering-eviction")
	bl.Add(newPeer, "new violation")

	// Verify the new entry was added.
	if !bl.IsBlacklisted(newPeer) {
		t.Fatal("new peer was not added to blacklist")
	}

	// Verify that ALL long bans were preserved.
	// Under the OLD (buggy) eviction, some long bans might have been evicted
	// because the eviction used randomized map iteration order.
	for i := 0; i < 5; i++ {
		peer := PeerID("long-ban-")
		peer = peer + PeerID(rune('A'+i))
		if !bl.IsBlacklisted(peer) {
			t.Errorf("P2-BLACKLIST-EVICT REGRESSION: long ban %q was evicted "+
				"even though it has ~1 hour remaining. The eviction should "+
				"prefer entries closest to expiration (short bans with ~5s "+
				"remaining), not long bans. Under the old randomized eviction, "+
				"this long ban could be evicted to make room for the new entry, "+
				"defeating the purpose of the 1-hour ban.", peer)
		}
	}

	// Verify that at least some short bans were evicted (to make room).
	// The target is 90% of maxSize = 9, so we need to evict at least 2 entries
	// to go from 10+1=11 down to 9. Both evicted entries should be short bans.
	shortBansRemaining := 0
	for i := 0; i < 5; i++ {
		peer := PeerID("short-ban-")
		peer = peer + PeerID(rune('A'+i))
		if bl.IsBlacklisted(peer) {
			shortBansRemaining++
		}
	}
	if shortBansRemaining >= 5 {
		t.Errorf("P2-BLACKLIST-EVICT: no short bans were evicted (all 5 remain) "+
			"— the eviction should have preferred short bans (5s remaining) "+
			"over long bans (1h remaining). shortBansRemaining=%d", shortBansRemaining)
	}
}

// TestP2_BLACKLIST_EVICT_EvictsClosestToExpirationFirst verifies the core
// eviction ordering: when multiple non-permanent entries exist, the ones
// CLOSEST to expiration are evicted first.
//
// This is a more granular test than the one above — it uses entries with
// 3 different expiration times and verifies the exact eviction order.
//
// Test fix (R29, 2026-07-26): The original test had two bugs:
//  1. Peer ID mismatch: setup used rune('A'+i) with i=0..5, so 1m entries
//     were "1mC"/"1mD" and 1h entries were "1hE"/"1hF", but verification
//     checked "1mA"/"1mB" and "1hA"/"1hB" (which never existed) — false
//     positives reported as "evicted".
//  2. Timing-dependent: 1s TTL could expire before Add() ran, causing
//     evictExpiredLocked to remove them instead of the eviction logic —
//     the test would pass for the wrong reason.
//
// Fix: use explicit peer names (no rune arithmetic) and safer TTLs
// (30s/5m/1h) that won't expire during the test but still have clear
// ordering for eviction preference.
func TestP2_BLACKLIST_EVICT_EvictsClosestToExpirationFirst(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	bl.maxSize = 6

	now := time.Now()

	// Add 2 entries expiring in 30s (closest to expiration, but won't
	// expire during the test).
	// Add 2 entries expiring in 5m (medium).
	// Add 2 entries expiring in 1h (farthest from expiration).
	// Total = 6 = maxSize (at capacity).
	entries := []struct {
		peerID PeerID
		ttl    time.Duration
	}{
		{PeerID("short-A"), 30 * time.Second},
		{PeerID("short-B"), 30 * time.Second},
		{PeerID("med-A"), 5 * time.Minute},
		{PeerID("med-B"), 5 * time.Minute},
		{PeerID("long-A"), 1 * time.Hour},
		{PeerID("long-B"), 1 * time.Hour},
	}

	for _, e := range entries {
		bl.mu.Lock()
		bl.peers[e.peerID] = &blacklistEntry{
			reason:    "test",
			expiresAt: now.Add(e.ttl),
			permanent: false,
		}
		bl.mu.Unlock()
	}

	// Add one more entry to trigger eviction.
	// Target is 90% of 6 = 5 (floor(6*9/10)=5).
	// So we need to evict at least 2 entries (from 6+1=7 down to 5).
	// The 2 evicted entries should be the "short" entries (closest to expiration).
	newPeer := PeerID("trigger-eviction")
	bl.Add(newPeer, "new")

	// Verify the "short" entries were evicted (closest to expiration).
	for _, p := range []PeerID{PeerID("short-A"), PeerID("short-B")} {
		if bl.IsBlacklisted(p) {
			t.Errorf("P2-BLACKLIST-EVICT REGRESSION: entry %q (30s remaining) "+
				"was NOT evicted — it should have been evicted first because "+
				"it is closest to expiration. The eviction should prefer "+
				"entries with the least remaining ban time.", p)
		}
	}

	// Verify the "med" and "long" entries were preserved.
	for _, p := range []PeerID{PeerID("med-A"), PeerID("med-B")} {
		if !bl.IsBlacklisted(p) {
			t.Errorf("P2-BLACKLIST-EVICT REGRESSION: entry %q (5m remaining) "+
				"was evicted — it should have been preserved because there "+
				"were entries with less remaining ban time (30s) that should "+
				"have been evicted first.", p)
		}
	}
	for _, p := range []PeerID{PeerID("long-A"), PeerID("long-B")} {
		if !bl.IsBlacklisted(p) {
			t.Errorf("P2-BLACKLIST-EVICT REGRESSION: entry %q (1h remaining) "+
				"was evicted — it should have been preserved because there "+
				"were entries with less remaining ban time (30s) that should "+
				"have been evicted first.", p)
		}
	}
}

// TestP2_BLACKLIST_EVICT_PreservesPermanentEntries verifies that permanent
// entries are NEVER evicted, even under high pressure.
//
// This was already the behavior before the P2-BLACKLIST-EVICT fix (the old
// code skipped permanent entries in the eviction loop), but we test it here
// to ensure the new sort-based eviction logic also preserves this invariant.
func TestP2_BLACKLIST_EVICT_PreservesPermanentEntries(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	bl.maxSize = 5

	// Add 3 permanent entries.
	for i := 0; i < 3; i++ {
		peer := PeerID("permanent-")
		peer = peer + PeerID(rune('A'+i))
		bl.mu.Lock()
		bl.peers[peer] = &blacklistEntry{
			reason:    "permanent ban",
			expiresAt: time.Time{}, // zero value for permanent
			permanent: true,
		}
		bl.mu.Unlock()
	}

	// Add 2 non-permanent entries (expiring in 1 hour).
	now := time.Now()
	for i := 0; i < 2; i++ {
		peer := PeerID("temp-")
		peer = peer + PeerID(rune('A'+i))
		bl.mu.Lock()
		bl.peers[peer] = &blacklistEntry{
			reason:    "temp ban",
			expiresAt: now.Add(1 * time.Hour),
			permanent: false,
		}
		bl.mu.Unlock()
	}

	// Add one more entry to trigger eviction.
	// The 2 temp entries should be evicted (target = 90% of 5 = 4).
	// The 3 permanent entries should be preserved.
	newPeer := PeerID("trigger-eviction")
	bl.Add(newPeer, "new")

	// Verify permanent entries are still present.
	for i := 0; i < 3; i++ {
		peer := PeerID("permanent-")
		peer = peer + PeerID(rune('A'+i))
		if !bl.IsBlacklisted(peer) {
			t.Errorf("P2-BLACKLIST-EVICT REGRESSION: permanent entry %q was "+
				"evicted — permanent entries must NEVER be evicted, even under "+
				"high pressure.", peer)
		}
	}
}

// TestP2_BLACKLIST_EVICT_IPMapSamePolicy verifies that the IP/subnet maps
// use the same expiration-time-based eviction policy as the peer map.
//
// P2-BLACKLIST-EVICT FIX (R29, 2026-07-26): The fix was applied to both
// evictIfNeededLocked (peer map) and evictStringMapLocked (IP/subnet maps).
// This test verifies the IP map behaves the same way.
func TestP2_BLACKLIST_EVICT_IPMapSamePolicy(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	bl.maxSize = 6

	now := time.Now()

	// Fill the IP map to capacity with a mix of short and long bans.
	bl.mu.Lock()
	for i := 0; i < 3; i++ {
		ipKey := "10.0.0." + string(rune('1'+i))
		bl.ips[ipKey] = &blacklistEntry{
			reason:    "short IP ban",
			expiresAt: now.Add(5 * time.Second),
			permanent: false,
		}
	}
	for i := 0; i < 3; i++ {
		ipKey := "10.0.1." + string(rune('1'+i))
		bl.ips[ipKey] = &blacklistEntry{
			reason:    "long IP ban",
			expiresAt: now.Add(1 * time.Hour),
			permanent: false,
		}
	}
	bl.mu.Unlock()

	// Verify we're at capacity in the IP map.
	bl.mu.Lock()
	initialIPCount := len(bl.ips)
	bl.mu.Unlock()
	if initialIPCount != 6 {
		t.Fatalf("initial IP count = %d, want 6 (at capacity)", initialIPCount)
	}

	// Trigger eviction by calling evictStringMapLocked with a full map.
	// We add one more IP entry to trigger the eviction.
	bl.mu.Lock()
	// First, fill to capacity + 1 to trigger eviction.
	bl.ips["10.0.2.1"] = &blacklistEntry{
		reason:    "trigger",
		expiresAt: now.Add(30 * time.Minute),
		permanent: false,
	}
	// Now call evictStringMapLocked to enforce the bound.
	bl.evictStringMapLocked(bl.ips)

	// Verify short IP bans were evicted (closest to expiration).
	for i := 0; i < 3; i++ {
		ipKey := "10.0.0." + string(rune('1'+i))
		if _, exists := bl.ips[ipKey]; exists {
			t.Errorf("P2-BLACKLIST-EVICT REGRESSION: short IP ban %q (5s remaining) "+
				"was NOT evicted — it should have been evicted first because "+
				"it is closest to expiration.", ipKey)
		}
	}

	// Verify long IP bans were preserved.
	for i := 0; i < 3; i++ {
		ipKey := "10.0.1." + string(rune('1'+i))
		if _, exists := bl.ips[ipKey]; !exists {
			t.Errorf("P2-BLACKLIST-EVICT REGRESSION: long IP ban %q (1h remaining) "+
				"was evicted — it should have been preserved because there were "+
				"entries with less remaining ban time (5s) that should have been "+
				"evicted first.", ipKey)
		}
	}
	bl.mu.Unlock()
}
