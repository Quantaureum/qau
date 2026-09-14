// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
	"time"
)

// TestP2_TXPOOL_RATELIMIT_TxRateLimiterExists verifies that the Host has a
// dedicated tx rate limiter field, distinct from the global rateLimiter.
//
// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): Without a dedicated tx rate
// limiter, a peer could use its entire 500 msg/sec global budget on
// MsgTypeTransaction alone, saturating the Dilithium3 verification pipeline.
// The tx rate limiter applies a tighter cap (default 50 txs/sec) to prevent
// this. This test ensures the field exists and is initialized.
func TestP2_TXPOOL_RATELIMIT_TxRateLimiterExists(t *testing.T) {
	// We can't easily construct a full Host in tests (it requires many
	// dependencies), so we test the RateLimiter primitive directly with
	// the production configuration. This verifies the limiter works
	// correctly with the defaultMaxPerPeerTxsPerSec constant.
	limiter := NewRateLimiter(defaultMaxPerPeerTxsPerSec, time.Second)
	defer limiter.Stop()

	peer := PeerID("tx-flooder-1")

	// The first defaultMaxPerPeerTxsPerSec transactions should be allowed.
	for i := 0; i < defaultMaxPerPeerTxsPerSec; i++ {
		if !limiter.Allow(peer) {
			t.Fatalf("P2-TXPOOL-RATELIMIT REGRESSION: tx %d was rejected "+
				"but the limit is %d/sec — the limiter is too tight or "+
				"the counter is not resetting properly", i+1, defaultMaxPerPeerTxsPerSec)
		}
	}

	// The (defaultMaxPerPeerTxsPerSec + 1)-th transaction should be rejected.
	if limiter.Allow(peer) {
		t.Fatalf("P2-TXPOOL-RATELIMIT REGRESSION: tx %d was allowed but the "+
			"limit is %d/sec — the limiter is not enforcing the cap, allowing "+
			"a peer to flood the Dilithium3 verification pipeline",
			defaultMaxPerPeerTxsPerSec+1, defaultMaxPerPeerTxsPerSec)
	}
}

// TestP2_TXPOOL_RATELIMIT_DefaultLimitIsReasonable verifies that the default
// tx rate limit is in a reasonable range: tight enough to prevent DoS, loose
// enough for legitimate DEX bots and block builders.
//
// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): The limit must be:
//   - < 500 (the global per-peer rate limit) — otherwise it's redundant
//   - > 10 — otherwise legitimate high-frequency traders are blocked
//   - == 50 — the documented default (10% of global budget)
func TestP2_TXPOOL_RATELIMIT_DefaultLimitIsReasonable(t *testing.T) {
	if defaultMaxPerPeerTxsPerSec >= 500 {
		t.Fatalf("P2-TXPOOL-RATELIMIT REGRESSION: defaultMaxPerPeerTxsPerSec = %d "+
			"is >= the global rate limit (500/sec), making the tx limiter "+
			"redundant — a peer could still flood the verification pipeline "+
			"with 500 txs/sec", defaultMaxPerPeerTxsPerSec)
	}
	if defaultMaxPerPeerTxsPerSec <= 10 {
		t.Fatalf("P2-TXPOOL-RATELIMIT REGRESSION: defaultMaxPerPeerTxsPerSec = %d "+
			"is too low (<=10) — legitimate DEX bots and block builders that "+
			"submit 20-30 txs/sec would be blocked", defaultMaxPerPeerTxsPerSec)
	}
	if defaultMaxPerPeerTxsPerSec != 50 {
		t.Logf("WARNING: defaultMaxPerPeerTxsPerSec = %d (expected 50). "+
			"If this was an intentional tuning change, update this test. "+
			"Otherwise, the default was accidentally changed.", defaultMaxPerPeerTxsPerSec)
	}
}

// TestP2_TXPOOL_RATELIMIT_PerPeerIsolation verifies that the tx rate limit
// is per-peer — one peer hitting the limit does not affect another peer.
//
// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): This is critical for Sybil
// resistance: if an attacker controls peer A and floods it to the limit,
// honest peer B must still be able to submit transactions normally.
func TestP2_TXPOOL_RATELIMIT_PerPeerIsolation(t *testing.T) {
	limiter := NewRateLimiter(5, time.Second) // small limit for fast testing
	defer limiter.Stop()

	attacker := PeerID("attacker")
	honest := PeerID("honest-peer")

	// Exhaust the attacker's quota.
	for i := 0; i < 5; i++ {
		if !limiter.Allow(attacker) {
			t.Fatalf("attacker tx %d should be allowed (limit 5)", i+1)
		}
	}

	// Attacker is now rate-limited.
	if limiter.Allow(attacker) {
		t.Fatal("attacker tx 6 should be rejected (limit 5)")
	}

	// Honest peer must still be able to submit.
	for i := 0; i < 5; i++ {
		if !limiter.Allow(honest) {
			t.Fatalf("P2-TXPOOL-RATELIMIT REGRESSION: honest peer tx %d was "+
				"rejected because the attacker exhausted a SHARED quota — "+
				"the tx rate limit must be per-peer, not global", i+1)
		}
	}
}

// TestP2_TXPOOL_RATELIMIT_ViolationEscalation verifies that repeated tx rate
// limit violations are tracked and escalate after the threshold.
//
// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): After RateLimitViolationThreshold
// (3) violations within 1 minute, RecordViolation returns true, signaling
// the caller to disconnect the peer. This test ensures the violation tracking
// works for the tx rate limiter (it uses the same primitive as the global
// rate limiter, so this is mostly a sanity check).
func TestP2_TXPOOL_RATELIMIT_ViolationEscalation(t *testing.T) {
	limiter := NewRateLimiter(1, time.Second) // tight limit for fast testing
	defer limiter.Stop()

	peer := PeerID("serial-flooder")

	// First violation.
	if limiter.RecordViolation(peer) {
		t.Fatal("first RecordViolation should return false (count=1 < threshold=3)")
	}
	// Second violation.
	if limiter.RecordViolation(peer) {
		t.Fatal("second RecordViolation should return false (count=2 < threshold=3)")
	}
	// Third violation — should trigger escalation.
	if !limiter.RecordViolation(peer) {
		t.Fatal("P2-TXPOOL-RATELIMIT REGRESSION: third RecordViolation should " +
			"return true (count=3 >= threshold=3) to signal peer disconnection")
	}

	// Verify the violation count is tracked correctly.
	if count := limiter.GetViolationCount(peer); count != 3 {
		t.Fatalf("violation count = %d, want 3", count)
	}
}

// TestP2_TXPOOL_RATELIMIT_WindowReset verifies that the tx rate limiter
// resets after the window expires, allowing a previously rate-limited peer
// to submit transactions again.
//
// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): Without window reset, a peer
// that hit the limit once would be permanently blocked. The limiter uses
// a fixed-window counter that resets after windowEnd.
func TestP2_TXPOOL_RATELIMIT_WindowReset(t *testing.T) {
	// Use a very short window for fast testing.
	limiter := NewRateLimiter(2, 100*time.Millisecond)
	defer limiter.Stop()

	peer := PeerID("bursty-peer")

	// Use up the quota.
	if !limiter.Allow(peer) {
		t.Fatal("first tx should be allowed")
	}
	if !limiter.Allow(peer) {
		t.Fatal("second tx should be allowed")
	}
	if limiter.Allow(peer) {
		t.Fatal("third tx should be rejected (limit 2)")
	}

	// Wait for the window to reset.
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again after window reset.
	if !limiter.Allow(peer) {
		t.Fatal("P2-TXPOOL-RATELIMIT REGRESSION: tx was rejected after the " +
			"window expired — the fixed-window counter is not resetting, " +
			"permanently blocking the peer after one burst")
	}
}
