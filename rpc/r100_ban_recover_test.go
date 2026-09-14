// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// R100-BAN-NORECOVER regression tests.
//
// A burst of requests can trip the per-IP limiter. Once the configured ban
// expires, the client must return to the same clean state as a never-banned
// client.
//
// The 1-hour ban itself is intended behavior. The defect is that a banned IP
// never returns to a clean state:
//
//	entry.violations++                                    (ratelimit.go:387)
//	if entry.violations >= ViolationsBeforeBan {           (:388)
//	    entry.bannedUntil = now.Add(BanDuration)           (:389)
//	}
//
// violations is reset in exactly one place — UnbanIP (:502) — which has ZERO
// production callers. So once an IP has accumulated ViolationsBeforeBan (10)
// violations, that counter stays at or above the threshold for the lifetime of
// the process. After the ban expires, the very NEXT single token shortfall
// re-arms a full 1-hour ban immediately, with no further burst of abuse needed.
//
// Effect: without the fix, the first offense is effectively permanent. A client that legitimately bursts once
// per hour is banned forever. Behind NAT, a CDN, or any shared egress IP, one
// misbehaving client permanently denies service to every other user sharing that
// address — and getClientIPWithTrust means a spoofed X-Forwarded-For through a
// trusted proxy lets an attacker choose whose address gets poisoned.
//
// Note on what was NOT the mechanism: an earlier reading of this code assumed
// each rejected request re-extended the ban, making it self-perpetuating. That
// is wrong — the ban check at :263 returns before reaching :387, so retries
// during a ban do not increment violations. The real defect is narrower and had
// to be verified rather than assumed.
//
// FIX: when a ban expires, clear it and reset the violation counter, so the
// client resumes with a clean slate exactly as a never-banned client would.

// r100Config builds a limiter whose PER-IP bucket starves before the global
// one. This ordering matters and is easy to get wrong: Allow() checks the ban,
// then the GLOBAL bucket, then the per-IP bucket (ratelimit.go:278-291), and
// BurstSize is the capacity of BOTH buckets. Firing requests back-to-back
// therefore drains the global bucket first and returns ErrRateLimitExceeded
// without ever reaching the per-IP violation counter — the first version of
// this test did exactly that and observed violations stuck at 0, which looked
// like the ban path being dead code.
//
// The fix is to pace the requests: GlobalRateLimit refills at 1000/s (1 per ms)
// while PerIPRateLimit is set to 1/s, so a 3 ms gap tops the global bucket back
// up while the per-IP bucket stays empty. That is also what real traffic looks
// like — a client hammering one node, not a single instantaneous burst.
func r100Config() *RateLimitConfig {
	cfg := DefaultRateLimitConfig()
	cfg.GlobalRateLimit = 1000
	cfg.PerIPRateLimit = 1
	cfg.BurstSize = 3
	cfg.ViolationsBeforeBan = 2
	cfg.BanDuration = 60 * time.Millisecond
	return cfg
}

func r100Limiter(t *testing.T) *RateLimiter {
	t.Helper()
	rl := NewRateLimiter(r100Config())
	t.Cleanup(rl.Stop)
	return rl
}

func r100Req(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = ip + ":40000"
	return r
}

// r100DriveUntilBanned paces requests so the per-IP bucket (not the global one)
// is the binding constraint, and reports whether a ban was armed.
func r100DriveUntilBanned(t *testing.T, rl *RateLimiter, ip string) bool {
	t.Helper()
	for range 30 {
		_ = rl.Allow(r100Req(ip), "eth_blockNumber")
		if r100IsBanned(rl, ip) {
			return true
		}
		time.Sleep(3 * time.Millisecond)
	}
	return false
}

// TestR100_BanExpiryResetsViolationCounter is the core regression: after a ban
// lapses, the client must be treated as clean, not as one violation away from
// another ban.
//
// Fails without the fix: the post-expiry burst is banned again immediately
// because violations is still >= ViolationsBeforeBan from the first offense.
func TestR100_BanExpiryResetsViolationCounter(t *testing.T) {
	rl := r100Limiter(t)
	const ip = "203.0.113.7"

	if !r100DriveUntilBanned(t, rl, ip) {
		t.Fatal("setup failed: client was never banned")
	}
	if got := r100Violations(rl, ip); got < 2 {
		t.Fatalf("setup failed: violations = %d, expected >= ViolationsBeforeBan", got)
	}

	// Let the ban lapse, then make ONE request. The per-IP bucket is still
	// empty, so this request legitimately records a violation — that part is
	// correct and must stay.
	time.Sleep(140 * time.Millisecond)
	_ = rl.Allow(r100Req(ip), "eth_blockNumber")

	// THE DECISIVE ASSERTION. That single post-expiry shortfall must NOT be
	// enough to re-arm a ban. Before the fix the counter still held the first
	// offense's total, so violations went 2 -> 3 >= ViolationsBeforeBan and a
	// fresh full ban was armed instantly: the first offense became a life
	// sentence, and on a shared egress IP (NAT / CDN) it took every other user
	// sharing that address down with it.
	if r100IsBanned(rl, ip) {
		t.Errorf("a single token shortfall after the ban expired re-armed a full ban "+
			"(violations=%d). The counter is only ever reset by UnbanIP, which has zero "+
			"production callers, so once banned an IP never returns to a clean state "+
			"(R100-BAN-NORECOVER)", r100Violations(rl, ip))
	}
	// The counter must have started over: exactly this one fresh violation.
	if got := r100Violations(rl, ip); got != 1 {
		t.Errorf("violations = %d after ban expiry + one shortfall, want 1 (counter reset to 0, "+
			"then this request's own violation)", got)
	}
}

// TestR100_ExpiredBanIsClearedNotJustIgnored pins the observable state, not only
// the behavior: an expired ban must be actively cleared so operators reading
// GetStats()/BannedIPs are not shown phantom bans, and so the eviction logic at
// :350 (which refuses to evict entries it believes are banned) can reclaim the
// slot.
func TestR100_ExpiredBanIsClearedNotJustIgnored(t *testing.T) {
	rl := r100Limiter(t)
	const ip = "203.0.113.8"

	if !r100DriveUntilBanned(t, rl, ip) {
		t.Fatal("setup failed: client was never banned")
	}

	time.Sleep(140 * time.Millisecond)

	// One request after expiry must clear the stale ban state. That same
	// request then records its own violation (the bucket is still empty), which
	// is correct — but it must not re-arm the ban.
	_ = rl.Allow(r100Req(ip), "eth_blockNumber")

	if r100BannedUntilSet(rl, ip) {
		t.Error("bannedUntil is still set after the ban expired and a request was served — " +
			"stale ban state inflates GetStats().BannedIPs and blocks entry eviction at " +
			"the MaxTrackedIPs cap, whose fallback is to fail closed (ratelimit.go:350) " +
			"(R100-BAN-NORECOVER)")
	}
	if got := r100Violations(rl, ip); got > 1 {
		t.Errorf("violations = %d after ban expiry, want <= 1 — a lapsed ban must leave the "+
			"client in the same state as one that was never banned, carrying at most the "+
			"violation from the request that observed the expiry", got)
	}
}

// TestR100_ActiveBanStillRefuses guards the security property: the fix must not
// weaken an in-force ban.
func TestR100_ActiveBanStillRefuses(t *testing.T) {
	cfg := r100Config()
	cfg.BanDuration = 10 * time.Second // long enough to stay active
	rl := NewRateLimiter(cfg)
	t.Cleanup(rl.Stop)
	const ip = "203.0.113.9"

	if !r100DriveUntilBanned(t, rl, ip) {
		t.Fatal("setup failed: client was never banned")
	}

	// Even after the token buckets would have refilled, an active ban refuses.
	time.Sleep(60 * time.Millisecond)
	if err := rl.Allow(r100Req(ip), "eth_blockNumber"); err == nil {
		t.Error("an ACTIVE ban must still refuse requests; the R100 reset may only apply " +
			"once bannedUntil is in the past")
	}
	if !r100IsBanned(rl, ip) {
		t.Error("an active ban must not be cleared by the expiry-reset path")
	}
}

// ── test helper: read state directly from the shard ───────────────────────

func r100Violations(rl *RateLimiter, ip string) int {
	shardIdx := rl.shardIndex(ip)
	rl.ipShardsMu[shardIdx].Lock()
	defer rl.ipShardsMu[shardIdx].Unlock()
	if e, ok := rl.ipShards[shardIdx][ip]; ok {
		return e.violations
	}
	return -1
}

func r100IsBanned(rl *RateLimiter, ip string) bool {
	shardIdx := rl.shardIndex(ip)
	rl.ipShardsMu[shardIdx].Lock()
	defer rl.ipShardsMu[shardIdx].Unlock()
	if e, ok := rl.ipShards[shardIdx][ip]; ok {
		return time.Now().Before(e.bannedUntil)
	}
	return false
}

func r100BannedUntilSet(rl *RateLimiter, ip string) bool {
	shardIdx := rl.shardIndex(ip)
	rl.ipShardsMu[shardIdx].Lock()
	defer rl.ipShardsMu[shardIdx].Unlock()
	if e, ok := rl.ipShards[shardIdx][ip]; ok {
		return !e.bannedUntil.IsZero()
	}
	return false
}

// TestR100_ExpiryRuleTruthTable pins the decision rule in isolation.
func TestR100_ExpiryRuleTruthTable(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		s    banState
		want bool
		why  string
	}{
		{"never banned", banState{}, false, "zero bannedUntil means no ban to clear"},
		{"active ban", banState{bannedUntil: now.Add(time.Minute), violations: 12}, false,
			"an in-force ban must keep refusing; clearing it would weaken the limiter"},
		{"lapsed ban", banState{bannedUntil: now.Add(-time.Minute), violations: 12}, true,
			"expired ban must leave no trace, or the first offense becomes permanent"},
		{"lapsed exactly now", banState{bannedUntil: now, violations: 10}, true,
			"boundary: bannedUntil == now is expired, matching the Before() check at :263"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expiredBanShouldReset(tc.s, now); got != tc.want {
				t.Errorf("expiredBanShouldReset = %v, want %v\nreason: %s", got, tc.want, tc.why)
			}
		})
	}
}
