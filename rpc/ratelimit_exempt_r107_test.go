// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// R107-LOCAL-FANOUT (2026-09-04)
//
// Regression tests for the per-IP rate-limit exemption. Background: a validator
// that also hosts the block explorer front-end sends every explorer RPC call
// from 127.0.0.1, so one page view (which fans out into hundreds of
// eth_getBlockByNumber calls) empties the shared per-IP bucket. Ten such empties
// banned 127.0.0.1 for an hour and only a process restart cleared it, taking the
// whole explorer to zero.
//
// The exemption must:
//   - bypass the per-IP bucket and the ban for listed IPs / CIDRs,
//   - keep applying the global and per-method limits (an exempt caller must not
//     be able to monopolise the node),
//   - never exempt anybody by default,
//   - refuse an all-zero prefix (which would exempt the entire internet),
//   - follow config hot-reload.
//
// Test-shaping note: all three buckets (global, per-IP, per-method) use
// BurstSize as their capacity and differ only in refill rate. To isolate one
// bucket, the tests keep BurstSize comfortably large and starve exactly one
// refill rate, rather than shrinking BurstSize (which would throttle all three
// at once and make the assertion meaningless).

const (
	// r107UnlimitedRate makes a bucket effectively unbounded *given the pacing in
	// r107Drain*. Rate alone is not enough: every bucket caps at BurstSize and
	// only refills when the clock advances, so a tight loop can never draw more
	// than BurstSize tokens per clock tick no matter how high the rate is (this
	// bites hardest on Windows, whose timer granularity is coarse). r107Drain
	// therefore paces itself — see below.
	r107UnlimitedRate = 1000000
	r107Burst         = 50
	// Requests per pause, kept below r107Burst so a fast bucket never runs dry.
	r107Chunk  = 25
	r107Pause  = 2 * time.Millisecond
	r107Rounds = 12
	// Total requests per drain: enough to exhaust a slow (1 req/s) bucket many
	// times over while a fast bucket keeps up.
	r107Attempts = r107Chunk * r107Rounds
)

func r107Request(remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = remoteAddr
	return r
}

// r107Drain consumes n requests and returns how many were allowed. It pauses
// every r107Chunk requests so buckets configured with r107UnlimitedRate get a
// chance to refill (a token bucket's throughput is bounded by BurstSize per
// clock tick, not by its nominal rate), while a bucket configured at 1 req/s
// gains only microtokens across the whole run and stays empty.
func r107Drain(rl *RateLimiter, remoteAddr, method string, n int) int {
	allowed := 0
	for i := 0; i < n; i++ {
		if i > 0 && i%r107Chunk == 0 {
			time.Sleep(r107Pause)
		}
		if err := rl.Allow(r107Request(remoteAddr), method); err == nil {
			allowed++
		}
	}
	return allowed
}

// r107Config returns a config whose only slow bucket is the per-IP one.
func r107Config(exempt ...string) *RateLimitConfig {
	cfg := DefaultRateLimitConfig()
	cfg.GlobalRateLimit = r107UnlimitedRate
	cfg.PerIPRateLimit = 1 // 1 req/s: dries up immediately in a tight loop
	cfg.BurstSize = r107Burst
	cfg.PerMethodRateLimit = nil
	cfg.ViolationsBeforeBan = 2
	cfg.BanDuration = time.Hour
	if len(exempt) > 0 {
		cfg.ExemptIPs = exempt
	}
	return cfg
}

func TestR107_ExemptIP_BypassesPerIPLimitAndBan(t *testing.T) {
	rl := NewRateLimiter(r107Config("127.0.0.1"))

	// Far more requests than the per-IP bucket, and enough violations to ban.
	const attempts = r107Attempts
	if allowed := r107Drain(rl, "127.0.0.1:54321", "eth_blockNumber", attempts); allowed != attempts {
		t.Fatalf("exempt IP must never be throttled: allowed %d/%d", allowed, attempts)
	}
	if rl.IsBanned("127.0.0.1") {
		t.Fatal("exempt IP must never be banned")
	}
}

func TestR107_NonExemptIP_StillLimitedAndBanned(t *testing.T) {
	rl := NewRateLimiter(r107Config("127.0.0.1"))

	const attempts = r107Attempts
	allowed := r107Drain(rl, "203.0.113.7:1234", "eth_blockNumber", attempts)
	if allowed > r107Burst+5 { // small tolerance for refill during the loop
		t.Fatalf("non-exempt IP was not throttled: allowed %d/%d", allowed, attempts)
	}
	if !rl.IsBanned("203.0.113.7") {
		t.Fatal("non-exempt IP should be banned after repeated violations")
	}
}

func TestR107_ExemptIP_StillSubjectToGlobalLimit(t *testing.T) {
	// The global limit is the backstop that makes the exemption safe.
	cfg := r107Config("127.0.0.1")
	cfg.GlobalRateLimit = 1 // now the global bucket is the slow one
	rl := NewRateLimiter(cfg)

	const attempts = r107Attempts
	if allowed := r107Drain(rl, "127.0.0.1:9999", "eth_blockNumber", attempts); allowed > r107Burst+5 {
		t.Fatalf("global limit must still bound an exempt caller: allowed %d/%d", allowed, attempts)
	}
}

func TestR107_ExemptIP_StillSubjectToMethodLimit(t *testing.T) {
	cfg := r107Config("127.0.0.1")
	cfg.PerIPRateLimit = r107UnlimitedRate // isolate the per-method bucket
	cfg.PerMethodRateLimit = map[string]int{"eth_call": 1}
	rl := NewRateLimiter(cfg)

	const attempts = r107Attempts
	if allowed := r107Drain(rl, "127.0.0.1:9999", "eth_call", attempts); allowed > r107Burst+5 {
		t.Fatalf("per-method limit must still apply to an exempt caller: allowed %d/%d", allowed, attempts)
	}
	// A method without its own limit stays unthrottled, proving the previous
	// assertion measured the method bucket and not some other limit.
	if allowed := r107Drain(rl, "127.0.0.1:9999", "eth_blockNumber", attempts); allowed != attempts {
		t.Fatalf("unlimited method must not be throttled: allowed %d/%d", allowed, attempts)
	}
}

func TestR107_ExemptCIDRMatching(t *testing.T) {
	rl := NewRateLimiter(r107Config("10.1.0.0/16", "::1"))

	const attempts = r107Attempts
	if allowed := r107Drain(rl, "10.1.2.3:1000", "eth_blockNumber", attempts); allowed != attempts {
		t.Fatalf("IP inside exempt CIDR must not be throttled: allowed %d/%d", allowed, attempts)
	}
	if allowed := r107Drain(rl, "[::1]:1000", "eth_blockNumber", attempts); allowed != attempts {
		t.Fatalf("exempt IPv6 loopback must not be throttled: allowed %d/%d", allowed, attempts)
	}
	if allowed := r107Drain(rl, "10.2.2.3:1000", "eth_blockNumber", attempts); allowed > r107Burst+5 {
		t.Fatalf("IP outside exempt CIDR must stay throttled: allowed %d/%d", allowed, attempts)
	}
}

func TestR107_NoExemptionByDefault(t *testing.T) {
	if got := DefaultRateLimitConfig().ExemptIPs; len(got) != 0 {
		t.Fatalf("defaults must not exempt anybody, got %v", got)
	}
	// Loopback must be throttled like any other address when not configured:
	// on a proxied deployment all public traffic arrives from 127.0.0.1.
	rl := NewRateLimiter(r107Config())
	const attempts = r107Attempts
	if allowed := r107Drain(rl, "127.0.0.1:1234", "eth_blockNumber", attempts); allowed > r107Burst+5 {
		t.Fatalf("loopback must not be exempt by default: allowed %d/%d", allowed, attempts)
	}
}

func TestR107_OverBroadOrMalformedExemptEntriesIgnored(t *testing.T) {
	rl := NewRateLimiter(r107Config("0.0.0.0/0", "::/0", "not-an-ip", "", "0.0.0.0"))

	const attempts = r107Attempts
	if allowed := r107Drain(rl, "198.51.100.9:1234", "eth_blockNumber", attempts); allowed > r107Burst+5 {
		t.Fatalf("an all-zero prefix must not exempt anybody: allowed %d/%d", allowed, attempts)
	}
}

func TestR107_UpdateConfigRefreshesExemptions(t *testing.T) {
	rl := NewRateLimiter(r107Config())

	const attempts = r107Attempts
	if allowed := r107Drain(rl, "127.0.0.1:1234", "eth_blockNumber", attempts); allowed > r107Burst+5 {
		t.Fatalf("precondition: loopback should be limited, allowed %d", allowed)
	}

	// Hot-reload adds the exemption; the ban/violation state accumulated above
	// must no longer matter (this is the operational escape hatch: raise limits
	// or exempt the local service without restarting the validator).
	rl.UpdateConfig(r107Config("127.0.0.1"))
	if allowed := r107Drain(rl, "127.0.0.1:1234", "eth_blockNumber", attempts); allowed != attempts {
		t.Fatalf("exemption must take effect after UpdateConfig: allowed %d/%d", allowed, attempts)
	}

	// Removing it again restores throttling.
	rl.UpdateConfig(r107Config())
	if allowed := r107Drain(rl, "127.0.0.1:1234", "eth_blockNumber", attempts); allowed >= attempts {
		t.Fatalf("removing the exemption must restore throttling: allowed %d/%d", allowed, attempts)
	}
}
