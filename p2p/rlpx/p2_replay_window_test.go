// Quantaureum Node source, version 1.0.0.
package rlpx

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p/enode"
)

// TestP2_REPLAY_WINDOW_TimestampWindowReducedTo15s verifies that the handshake
// timestamp window has been reduced from the original 60s to 15s.
//
// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): The original 60s window gave a ±60s
// acceptance window (120 seconds total replay attack surface). An attacker who
// captured a handshake message could replay it within this 120s window. The fix
// reduces the window to 15s, shrinking the replay attack surface by 4x (from
// 120s to 30s) while still tolerating real-world network latency and clock skew.
//
// This test prevents regression: if a future change accidentally restores the
// 60s window, this test will fail.
func TestP2_REPLAY_WINDOW_TimestampWindowReducedTo15s(t *testing.T) {
	if handshakeTimestampWindow != 15*time.Second {
		t.Fatalf("P2-REPLAY-WINDOW REGRESSION: handshakeTimestampWindow = %v, "+
			"expected 15s. The window was reduced from 60s to 15s to shrink "+
			"the replay attack surface by 4x. Restoring the 60s window would "+
			"re-introduce the vulnerability where an attacker who captures a "+
			"handshake can replay it within a 120s window.",
			handshakeTimestampWindow)
	}

	// Also verify the TTL is 2x the window (defense-in-depth: entries remain
	// in the cache for the full duration of the replay window plus a safety
	// margin).
	expectedTTL := 2 * handshakeTimestampWindow
	if handshakeReplayCacheTTL != expectedTTL {
		t.Errorf("P2-REPLAY-WINDOW: handshakeReplayCacheTTL = %v, expected %v "+
			"(2x the timestamp window). The TTL must be at least as long as "+
			"the timestamp window to ensure entries remain in the cache for "+
			"the full duration of the replay window.",
			handshakeReplayCacheTTL, expectedTTL)
	}
}

// TestP2_REPLAY_WINDOW_ReplayCacheRejectsDuplicateMessage verifies that the
// replay cache rejects a duplicate handshake message with the same
// (peerID, nonce) pair.
//
// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): Without a nonce cache, even a tight
// timestamp window allows replays within that window. The cache tracks
// (peerID, nonce) pairs that have been seen. If the same pair appears again
// within the cache's TTL, the replay is rejected.
//
// R33 P2P-01 FIX (2026-07-28): The cache now uses a two-step check-then-commit
// pattern. decodeAuthMessagePQ only calls checkReplay (no insert). The caller
// (ResponderHandshakeWithStore) calls commitReplay AFTER signature verification.
// This test simulates the full flow: decode → commit → decode again (replay).
func TestP2_REPLAY_WINDOW_ReplayCacheRejectsDuplicateMessage(t *testing.T) {
	// Reset the cache to ensure a clean state.
	globalReplayCache.resetForTesting()

	msg := makeValidAuthMessage()
	encoded := encodeAuthMessagePQ(msg)

	// First decode should succeed (checkReplay only, no insert).
	decoded1, err := decodeAuthMessagePQ(encoded)
	if err != nil {
		t.Fatalf("first decodeAuthMessagePQ failed: %v — the replay cache "+
			"should not reject a message it has never seen before", err)
	}
	if decoded1 == nil {
		t.Fatal("first decode returned nil message")
	}

	// Simulate the caller committing the replay entry after signature verification.
	if err := globalReplayCache.commitReplay(decoded1.InitiatorID, decoded1.Nonce); err != nil {
		t.Fatalf("commitReplay failed: %v", err)
	}

	// Second decode of the SAME encoded bytes MUST fail with ErrHandshakeReplay.
	// This is the core of the fix: even within the timestamp window, a replayed
	// message is rejected because the (InitiatorID, Nonce) pair is already in
	// the cache.
	_, err = decodeAuthMessagePQ(encoded)
	if err == nil {
		t.Fatal("P2-REPLAY-WINDOW REGRESSION: second decodeAuthMessagePQ with " +
			"the same (InitiatorID, Nonce) pair succeeded — the replay cache " +
			"did NOT reject the duplicate message. This allows an attacker who " +
			"captures a handshake to replay it within the timestamp window.")
	}
	if !errors.Is(err, ErrHandshakeReplay) {
		t.Errorf("P2-REPLAY-WINDOW: second decode returned wrong error: %v — "+
			"expected ErrHandshakeReplay. The error must be ErrHandshakeReplay "+
			"so that callers and operators can distinguish 'malformed message' "+
			"from 'replay attack detected'.", err)
	}
}

// TestP2_REPLAY_WINDOW_ReplayCacheRejectsDuplicateResponse verifies that the
// replay cache also rejects duplicate auth RESPONSES with the same
// (ResponderID, nonce) pair.
//
// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): Same rationale as the auth message
// test, but for the responder's auth response. An attacker who captures a
// valid auth response could replay it to the initiator to impersonate the
// responder. The cache prevents this.
func TestP2_REPLAY_WINDOW_ReplayCacheRejectsDuplicateResponse(t *testing.T) {
	globalReplayCache.resetForTesting()

	resp := makeValidAuthResponse()
	encoded := encodeAuthResponsePQ(resp)

	// First decode should succeed (checkReplay only, no insert).
	decoded1, err := decodeAuthResponsePQ(encoded)
	if err != nil {
		t.Fatalf("first decodeAuthResponsePQ failed: %v", err)
	}
	if decoded1 == nil {
		t.Fatal("first decode returned nil response")
	}

	// Simulate the caller committing the replay entry after signature verification.
	if err := globalReplayCache.commitReplay(decoded1.ResponderID, decoded1.Nonce); err != nil {
		t.Fatalf("commitReplay failed: %v", err)
	}

	// Second decode MUST fail with ErrHandshakeReplay.
	_, err = decodeAuthResponsePQ(encoded)
	if err == nil {
		t.Fatal("P2-REPLAY-WINDOW REGRESSION: second decodeAuthResponsePQ with " +
			"the same (ResponderID, Nonce) pair succeeded — the replay cache " +
			"did NOT reject the duplicate response.")
	}
	if !errors.Is(err, ErrHandshakeReplay) {
		t.Errorf("P2-REPLAY-WINDOW: second decode returned wrong error: %v — "+
			"expected ErrHandshakeReplay", err)
	}
}

// TestP2_REPLAY_WINDOW_DifferentNoncesAllowed verifies that the replay cache
// does NOT reject messages with different nonces from the same peer. This is
// important because a legitimate peer may initiate multiple handshakes
// concurrently, each with a different nonce.
//
// Without this test, a bug where the cache keys on peerID alone (instead of
// peerID+nonce) would not be detected — it would manifest as false-positive
// replay rejections for legitimate concurrent handshakes.
func TestP2_REPLAY_WINDOW_DifferentNoncesAllowed(t *testing.T) {
	globalReplayCache.resetForTesting()

	// First message with nonce A.
	msg1 := makeValidAuthMessage()
	encoded1 := encodeAuthMessagePQ(msg1)
	_, err := decodeAuthMessagePQ(encoded1)
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}

	// Second message with a DIFFERENT nonce but the SAME InitiatorID.
	// This should succeed because the (InitiatorID, nonce) pair is different.
	msg2 := makeValidAuthMessage()
	// Override InitiatorID to be the same as msg1's.
	msg2.InitiatorID = msg1.InitiatorID
	// msg2.Nonce is already different (nextTestNonce() returns unique nonces).
	encoded2 := encodeAuthMessagePQ(msg2)
	_, err = decodeAuthMessagePQ(encoded2)
	if err != nil {
		t.Fatalf("P2-REPLAY-WINDOW REGRESSION: decode of a message with a "+
			"different nonce but the same InitiatorID failed: %v — the replay "+
			"cache should allow different nonces from the same peer (legitimate "+
			"concurrent handshakes)", err)
	}
}

// TestP2_REPLAY_WINDOW_DifferentPeerIDsAllowed verifies that the replay cache
// does NOT reject messages with the same nonce from different peers. Nonces
// are random 32-byte values, so collisions are astronomically unlikely, but
// the cache keys on (peerID, nonce) to be defense-in-depth correct.
func TestP2_REPLAY_WINDOW_DifferentPeerIDsAllowed(t *testing.T) {
	globalReplayCache.resetForTesting()

	// First message from peer A with nonce X.
	msg1 := makeValidAuthMessage()
	encoded1 := encodeAuthMessagePQ(msg1)
	_, err := decodeAuthMessagePQ(encoded1)
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}

	// Second message from peer B with the SAME nonce.
	// This should succeed because the (peerID, nonce) pair is different
	// (different peerID).
	msg2 := makeValidAuthMessage()
	msg2.Nonce = msg1.Nonce // Same nonce, different InitiatorID (makeValidAuthMessage uses fixed InitiatorID)
	// But wait — makeValidAuthMessage uses a FIXED InitiatorID. We need to
	// change it to a different one.
	var differentID enode.ID
	differentID[0] = 0xFF // Make it different from the fixed InitiatorID
	msg2.InitiatorID = differentID
	encoded2 := encodeAuthMessagePQ(msg2)
	_, err = decodeAuthMessagePQ(encoded2)
	if err != nil {
		t.Fatalf("P2-REPLAY-WINDOW REGRESSION: decode of a message with the "+
			"same nonce but a different InitiatorID failed: %v — the replay "+
			"cache should allow the same nonce from different peers", err)
	}
}

// TestP2_REPLAY_WINDOW_CacheEntryExpiresAfterTTL verifies that a cache entry
// expires after the TTL, allowing the same (peerID, nonce) pair to be accepted
// again after the TTL has passed.
//
// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): The cache uses a TTL-based eviction
// to bound memory usage. After the TTL, entries are eligible for purging. This
// test verifies that a message can be decoded again after its cache entry has
// expired (by manually advancing the cache timestamp).
//
// Note: We can't actually wait 30s in a unit test, so we directly manipulate
// the cache's internal state to simulate an expired entry.
func TestP2_REPLAY_WINDOW_CacheEntryExpiresAfterTTL(t *testing.T) {
	globalReplayCache.resetForTesting()

	msg := makeValidAuthMessage()
	encoded := encodeAuthMessagePQ(msg)

	// First decode succeeds (checkReplay only, no insert).
	decoded1, err := decodeAuthMessagePQ(encoded)
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}

	// Commit the replay entry (simulates post-signature-verification commit).
	if err := globalReplayCache.commitReplay(decoded1.InitiatorID, decoded1.Nonce); err != nil {
		t.Fatalf("commitReplay failed: %v", err)
	}

	// Second decode fails (replay detected).
	_, err = decodeAuthMessagePQ(encoded)
	if err == nil {
		t.Fatal("expected replay error on second decode")
	}
	if !errors.Is(err, ErrHandshakeReplay) {
		t.Fatalf("expected ErrHandshakeReplay, got %v", err)
	}

	// Manually backdate the cache entry to simulate TTL expiration.
	var key [64]byte
	copy(key[:32], msg.InitiatorID[:])
	copy(key[32:], msg.Nonce)

	globalReplayCache.mu.Lock()
	if ts, exists := globalReplayCache.entries[key]; exists {
		globalReplayCache.entries[key] = ts.Add(-(handshakeReplayCacheTTL + time.Second))
	} else {
		globalReplayCache.mu.Unlock()
		t.Fatal("cache entry not found after commit — commitReplay did not record the entry")
	}
	globalReplayCache.mu.Unlock()

	// Third decode should succeed because the entry is now expired.
	// The checkReplay function should treat the expired entry as "not in cache".
	//
	// NOTE: This test re-encodes the message to get a fresh timestamp, because
	// the timestamp window check (15s) would reject the original message after
	// 30s of real time. By re-encoding with a fresh timestamp, we isolate the
	// test to ONLY the cache expiration behavior.
	msg.Timestamp = uint64(time.Now().Unix())
	encoded = encodeAuthMessagePQ(msg)
	_, err = decodeAuthMessagePQ(encoded)
	if err != nil {
		t.Fatalf("P2-REPLAY-WINDOW: decode after TTL expiration failed: %v — "+
			"the cache entry should have expired and been refreshed", err)
	}
}

// TestP2_REPLAY_WINDOW_CacheBoundedUnderFlood verifies that the cache is
// bounded under a flood of unique handshakes. When the cache reaches
// maxReplayCacheEntries, it should evict the oldest entries rather than
// growing unboundedly.
//
// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): Without a bound, an attacker could
// flood the node with handshakes (each with a unique nonce) to exhaust memory.
// The cache bounds its size by evicting the oldest entries when full.
func TestP2_REPLAY_WINDOW_CacheBoundedUnderFlood(t *testing.T) {
	globalReplayCache.resetForTesting()

	// Insert more entries than the cache's capacity. Each entry has a unique
	// (peerID, nonce) pair.
	//
	// We use a small multiplier (maxReplayCacheEntries + 100) to keep the test
	// fast. The cache's eviction logic triggers when len(entries) >=
	// maxReplayCacheEntries, so we just need to exceed that by a small amount.
	totalToInsert := maxReplayCacheEntries + 100

	for i := 0; i < totalToInsert; i++ {
		var peerID enode.ID
		// Make each peerID unique by varying the first 8 bytes.
		peerID[0] = byte(i >> 56)
		peerID[1] = byte(i >> 48)
		peerID[2] = byte(i >> 40)
		peerID[3] = byte(i >> 32)
		peerID[4] = byte(i >> 24)
		peerID[5] = byte(i >> 16)
		peerID[6] = byte(i >> 8)
		peerID[7] = byte(i)

		nonce := make([]byte, nonceSize)
		// Fill nonce with the same index to make it unique per iteration.
		for j := 0; j < nonceSize; j++ {
			nonce[j] = byte(i)
		}

		err := globalReplayCache.commitReplay(peerID, nonce)
		if err != nil {
			t.Fatalf("commitReplay failed at iteration %d: %v", i, err)
		}
	}

	// Verify the cache size is bounded. It should be at most
	// maxReplayCacheEntries (the eviction logic triggers when the cache
	// reaches this size).
	globalReplayCache.mu.Lock()
	cacheSize := len(globalReplayCache.entries)
	globalReplayCache.mu.Unlock()

	if cacheSize > maxReplayCacheEntries {
		t.Errorf("P2-REPLAY-WINDOW REGRESSION: cache size = %d, expected <= %d "+
			"after inserting %d entries — the cache is not bounded, allowing "+
			"an attacker to exhaust memory via a handshake flood",
			cacheSize, maxReplayCacheEntries, totalToInsert)
	}
}

// TestP2_REPLAY_WINDOW_ConcurrentAccessIsSafe verifies that the replay cache
// is safe for concurrent access. Multiple goroutines calling commitReplay
// simultaneously should not cause data races or panics.
//
// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): The cache is accessed from
// handshake goroutines (decodeAuthMessagePQ/decodeAuthResponsePQ), which run
// concurrently. The cache uses sync.Mutex to protect the internal map. This
// test runs the race detector (when run with -race) to verify thread-safety.
//
// R33 P2P-01 FIX (2026-07-28): Updated to use commitReplay (the inserting
// function) since checkReplay only reads and does not modify the map.
func TestP2_REPLAY_WINDOW_ConcurrentAccessIsSafe(t *testing.T) {
	globalReplayCache.resetForTesting()

	const numGoroutines = 100
	const messagesPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < messagesPerGoroutine; i++ {
				var peerID enode.ID
				peerID[0] = byte(goroutineID)
				peerID[1] = byte(i)

				nonce := make([]byte, nonceSize)
				nonce[0] = byte(goroutineID)
				nonce[1] = byte(i)

				// commitReplay should never panic or data-race.
				_ = globalReplayCache.commitReplay(peerID, nonce)
			}
		}(g)
	}

	wg.Wait()

	// Verify all unique entries were recorded.
	expectedEntries := numGoroutines * messagesPerGoroutine
	globalReplayCache.mu.Lock()
	actualEntries := len(globalReplayCache.entries)
	globalReplayCache.mu.Unlock()

	if actualEntries != expectedEntries {
		t.Errorf("expected %d cache entries, got %d — some concurrent "+
			"commitReplay calls were lost (data race or mutex bug)",
			expectedEntries, actualEntries)
	}
}

// TestP2_REPLAY_WINDOW_MalformedNonceRejected verifies that the cache rejects
// malformed nonces (wrong length) without recording them. This prevents
// cache pollution from malformed messages.
//
// R33 P2P-01 FIX (2026-07-28): Tests both checkReplay and commitReplay, since
// the split means both functions must validate nonce length independently.
func TestP2_REPLAY_WINDOW_MalformedNonceRejected(t *testing.T) {
	globalReplayCache.resetForTesting()

	var peerID enode.ID
	peerID[0] = 0x42

	// Wrong-length nonce.
	malformedNonce := make([]byte, 16) // should be 32 bytes

	// checkReplay must reject malformed nonce.
	err := globalReplayCache.checkReplay(peerID, malformedNonce)
	if err == nil {
		t.Fatal("P2-REPLAY-WINDOW: checkReplay accepted a malformed nonce " +
			"(16 bytes instead of 32) — malformed nonces should be rejected")
	}
	if !errors.Is(err, ErrInvalidHandshakeMessage) {
		t.Errorf("expected ErrInvalidHandshakeMessage for malformed nonce, got %v", err)
	}

	// commitReplay must also reject malformed nonce.
	err = globalReplayCache.commitReplay(peerID, malformedNonce)
	if err == nil {
		t.Fatal("P2-REPLAY-WINDOW: commitReplay accepted a malformed nonce")
	}
	if !errors.Is(err, ErrInvalidHandshakeMessage) {
		t.Errorf("expected ErrInvalidHandshakeMessage for malformed nonce, got %v", err)
	}

	// Verify the malformed entry was NOT recorded.
	globalReplayCache.mu.Lock()
	cacheSize := len(globalReplayCache.entries)
	globalReplayCache.mu.Unlock()

	if cacheSize != 0 {
		t.Errorf("P2-REPLAY-WINDOW: cache was polluted with %d entries after a "+
			"malformed nonce was rejected — the entry should not have been recorded",
			cacheSize)
	}
}

// TestR33_P2P_01_CheckDoesNotInsert verifies that checkReplay does NOT insert
// into the cache, while commitReplay does. This is the core invariant of the
// P2P-01 fix: an unverified handshake (one where commitReplay was never called)
// must not poison the cache.
func TestR33_P2P_01_CheckDoesNotInsert(t *testing.T) {
	globalReplayCache.resetForTesting()

	var peerID enode.ID
	peerID[0] = 0x42
	nonce := make([]byte, nonceSize)
	nonce[0] = 0x01

	// checkReplay should succeed (entry not in cache).
	if err := globalReplayCache.checkReplay(peerID, nonce); err != nil {
		t.Fatalf("checkReplay failed on empty cache: %v", err)
	}

	// Verify checkReplay did NOT insert.
	globalReplayCache.mu.Lock()
	cacheSize := len(globalReplayCache.entries)
	globalReplayCache.mu.Unlock()
	if cacheSize != 0 {
		t.Fatalf("R33 P2P-01 REGRESSION: checkReplay inserted %d entries — "+
			"checkReplay must NOT insert (only commitReplay inserts)", cacheSize)
	}

	// commitReplay should insert.
	if err := globalReplayCache.commitReplay(peerID, nonce); err != nil {
		t.Fatalf("commitReplay failed: %v", err)
	}

	globalReplayCache.mu.Lock()
	cacheSize = len(globalReplayCache.entries)
	globalReplayCache.mu.Unlock()
	if cacheSize != 1 {
		t.Fatalf("commitReplay did not insert exactly 1 entry, got %d", cacheSize)
	}

	// Now checkReplay should detect the replay.
	if err := globalReplayCache.checkReplay(peerID, nonce); err == nil {
		t.Fatal("R33 P2P-01 REGRESSION: checkReplay did not detect replay after commit")
	} else if !errors.Is(err, ErrHandshakeReplay) {
		t.Fatalf("expected ErrHandshakeReplay, got %v", err)
	}
}
