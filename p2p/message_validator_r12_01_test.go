package p2p

// R12-01 regression tests (twelfth-round audit).
//
// The IsDuplicate seenMessages eviction previously removed ONE entry per full
// map scan while holding seenMessagesMu, looping from maxSeenMessages down to
// 90% of it. That is O(cap * evict) work in a single call — a remote peer could
// drive the map to the cap by flooding distinct payloads (IsDuplicate runs
// before format validation) and stall ValidateMessage for every peer. The fix
// mirrors the proven lastMessages sweep: prune every entry past the 30s dedup
// window in one pass, and only if STILL at capacity sort once and batch-drop
// the oldest 10%.
//
// These tests pin the observable correctness of that change and give a
// deterministic negative-control signal: with an all-expired map at capacity,
// the bounded sweep must purge every expired entry, whereas the old one-by-one
// loop would leave ~90% of them behind.

import (
	"fmt"
	"testing"
	"time"
)

// seedSeen fills v.seenMessages with n distinct hashes stamped at ageOffset
// relative to now, bypassing IsDuplicate so the test controls timestamps.
func seedSeen(v *MessageValidator, n int, ageOffset time.Duration) {
	v.seenMessagesMu.Lock()
	defer v.seenMessagesMu.Unlock()
	stamp := time.Now().Add(ageOffset)
	for i := 0; i < n; i++ {
		v.seenMessages[fmt.Sprintf("seed-%d", i)] = stamp
	}
}

// TestR12_01_IsDuplicate_PurgesExpiredOnOverflow proves the bounded sweep drops
// every entry past the dedup window in a single overflow insertion. On the old
// one-by-one loop, only ~10% (down to the 90% floor) would be removed, leaving
// expired hashes occupying the dedup budget.
func TestR12_01_IsDuplicate_PurgesExpiredOnOverflow(t *testing.T) {
	v := NewMessageValidator()
	cap := 100
	v.maxSeenMessages = cap

	// Fill to capacity with long-expired entries (60s old > 30s dedup window).
	seedSeen(v, cap, -60*time.Second)

	// One fresh insertion crosses the cap and triggers eviction.
	if v.IsDuplicate("overflow-fresh") {
		t.Fatal("a never-seen hash must not be flagged duplicate")
	}

	v.seenMessagesMu.Lock()
	size := len(v.seenMessages)
	remainingExpired := 0
	for _, ts := range v.seenMessages {
		if time.Since(ts) >= 30*time.Second {
			remainingExpired++
		}
	}
	v.seenMessagesMu.Unlock()

	// The bounded sweep must have purged every expired entry, leaving only the
	// fresh one we just inserted. The old loop would report ~90 here.
	if remainingExpired != 0 {
		t.Fatalf("expired dedup entries lingered: %d still past the 30s window (map size %d); the eviction must purge all expired in one pass", remainingExpired, size)
	}
	if size > cap {
		t.Fatalf("seenMessages exceeded cap after overflow: size %d > cap %d", size, cap)
	}
}

// TestR12_01_IsDuplicate_BoundsMapWhenAllFresh proves that when nothing is
// expired (worst-case flood of recent distinct payloads) the sweep still keeps
// the map at or below capacity and retains the newest entry — bounding the
// eviction to a single sort+batch instead of a quadratic scan loop.
func TestR12_01_IsDuplicate_BoundsMapWhenAllFresh(t *testing.T) {
	v := NewMessageValidator()
	cap := 100
	v.maxSeenMessages = cap

	// Fill to capacity with fresh (0s age) entries — none eligible for the
	// expired prune pass, so the sort+batch path is exercised.
	seedSeen(v, cap, 0)

	newest := "flood-latest"
	if v.IsDuplicate(newest) {
		t.Fatal("fresh hash must not be flagged duplicate on first sight")
	}

	v.seenMessagesMu.Lock()
	size := len(v.seenMessages)
	_, hasNewest := v.seenMessages[newest]
	v.seenMessagesMu.Unlock()

	if size > cap {
		t.Fatalf("seenMessages not bounded under all-fresh flood: size %d > cap %d", size, cap)
	}
	if !hasNewest {
		t.Fatal("the just-inserted hash must survive eviction (newest is never evicted)")
	}
	// A single overflow evicts one batch (cap/10), so the map settles just under
	// capacity rather than growing. Boundedness is the invariant under test.
	if size < (cap*9)/10 {
		t.Fatalf("expected a bounded batch evict near the cap, size collapsed to %d (cap %d)", size, cap)
	}
}

// TestR12_01_IsDuplicate_StillDedupsWithinWindow proves the change preserves the
// replay-dedup behavior it exists for: a hash seen moments ago is flagged.
func TestR12_01_IsDuplicate_StillDedupsWithinWindow(t *testing.T) {
	v := NewMessageValidator()
	h := "same-tx-hash"
	if v.IsDuplicate(h) {
		t.Fatal("first sighting must not be duplicate")
	}
	if !v.IsDuplicate(h) {
		t.Fatal("second sighting within the 30s window must be flagged duplicate")
	}
}

// TestR12_01_IsDuplicate_ExpiredEntryNotTreatedAsDuplicate proves the dedup
// window is real: an entry older than 30s no longer suppresses a re-arrival, so
// a legitimately re-broadcast message is not permanently blocked.
func TestR12_01_IsDuplicate_ExpiredEntryNotTreatedAsDuplicate(t *testing.T) {
	v := NewMessageValidator()
	h := "rebroadcast"
	seedSeen(v, 0, 0) // no-op, ensures map initialized
	v.seenMessagesMu.Lock()
	v.seenMessages[h] = time.Now().Add(-45 * time.Second)
	v.seenMessagesMu.Unlock()

	if v.IsDuplicate(h) {
		t.Fatal("a hash past the 30s dedup window must not be flagged duplicate")
	}
}
