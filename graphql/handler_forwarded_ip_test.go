// Quantaureum Node source, version 1.0.0.
package graphql

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// AUDIT run-3 qau.graphql/loopback-forwarded-ip-rate-limit-bypass regression
// test. A loopback peer could previously send a different X-Real-IP /
// X-Forwarded-For per request and land in a fresh rate-limit bucket each time.
// Forwarded headers must only be honored when the direct peer is explicitly
// configured as a trusted proxy.
func TestServeHTTP_ForwardedIPIgnoredWithoutTrustedProxy(t *testing.T) {
	cfg := DefaultHandlerConfig()
	cfg.RateLimitRequests = 1
	cfg.RateLimitWindow = time.Minute
	h := NewHandler(&Resolver{}, cfg)

	do := func(xRealIP string) int {
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ chainId }"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Real-IP", xRealIP)
		req.RemoteAddr = "127.0.0.1:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do("198.51.100.1"); code != http.StatusUnauthorized {
		t.Fatalf("first request = %d, want 401", code)
	}
	// Same direct peer, spoofed different client IP: must share the bucket.
	if code := do("198.51.100.2"); code != http.StatusTooManyRequests {
		t.Fatalf("spoofed X-Real-IP bypassed the rate limit: second request = %d, want 429", code)
	}
}

func newForwardedRequest(remoteAddr, xRealIP, xff string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ chainId }"}`))
	req.Header.Set("Content-Type", "application/json")
	if xRealIP != "" {
		req.Header.Set("X-Real-IP", xRealIP)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	req.RemoteAddr = remoteAddr
	return req
}

func TestClientIPWithTrust_NoWhitelistUsesDirectPeer(t *testing.T) {
	req := newForwardedRequest("203.0.113.9:4444", "198.51.100.1", "")
	if got := clientIPWithTrust(req, nil); got != "203.0.113.9" {
		t.Fatalf("got %q, want direct peer 203.0.113.9", got)
	}
}

func TestClientIPWithTrust_TrustedProxyHonorsXRealIP(t *testing.T) {
	req := newForwardedRequest("127.0.0.1:4444", "198.51.100.7", "")
	if got := clientIPWithTrust(req, []string{"127.0.0.1"}); got != "198.51.100.7" {
		t.Fatalf("got %q, want forwarded 198.51.100.7", got)
	}
}

func TestClientIPWithTrust_TrustedProxyHonorsRightmostXFFEntry(t *testing.T) {
	req := newForwardedRequest("127.0.0.1:4444", "", "198.51.100.8, 10.0.0.2")
	if got := clientIPWithTrust(req, []string{"127.0.0.1"}); got != "10.0.0.2" {
		t.Fatalf("got %q, want rightmost XFF entry 10.0.0.2", got)
	}
}

// AUDIT node/graphql-clientip-spoof FIX: a client-supplied leftmost XFF entry
// is attacker-controlled (proxies append). The rate-limit identity must come
// from the rightmost untrusted hop, not from whatever the client prepended.
func TestClientIPWithTrust_LeftmostXFFSpoofIgnored(t *testing.T) {
	req := newForwardedRequest("127.0.0.1:4444", "", "1.2.3.4, 198.51.100.8")
	if got := clientIPWithTrust(req, []string{"127.0.0.1"}); got != "198.51.100.8" {
		t.Fatalf("spoofed leftmost XFF entry used as identity: got %q, want 198.51.100.8", got)
	}
	// Rotating the spoofed leftmost value must not change the identity.
	req = newForwardedRequest("127.0.0.1:4444", "", "9.9.9.9, 198.51.100.8")
	if got := clientIPWithTrust(req, []string{"127.0.0.1"}); got != "198.51.100.8" {
		t.Fatalf("rotating spoofed XFF entry changed identity: got %q, want 198.51.100.8", got)
	}
}

// Trusted proxy hops inside the XFF chain are skipped while walking left.
func TestClientIPWithTrust_SkipsTrustedXFFHops(t *testing.T) {
	req := newForwardedRequest("127.0.0.1:4444", "", "198.51.100.8, 10.0.0.2")
	if got := clientIPWithTrust(req, []string{"127.0.0.1", "10.0.0.0/8"}); got != "198.51.100.8" {
		t.Fatalf("got %q, want 198.51.100.8 (trusted hop 10.0.0.2 skipped)", got)
	}
}

// Malformed forwarding values must never become the rate-limit identity.
func TestClientIPWithTrust_RejectsMalformedHeaders(t *testing.T) {
	req := newForwardedRequest("127.0.0.1:4444", "not-an-ip", "garbage, 198.51.100.8")
	if got := clientIPWithTrust(req, []string{"127.0.0.1"}); got != "198.51.100.8" {
		t.Fatalf("got %q, want valid rightmost XFF entry 198.51.100.8", got)
	}
	req = newForwardedRequest("127.0.0.1:4444", "not-an-ip", "garbage")
	if got := clientIPWithTrust(req, []string{"127.0.0.1"}); got != "127.0.0.1" {
		t.Fatalf("malformed X-Real-IP/XFF used as identity: got %q, want direct peer 127.0.0.1", got)
	}
}

func TestClientIPWithTrust_CIDRMatch(t *testing.T) {
	req := newForwardedRequest("10.1.2.3:4444", "198.51.100.9", "")
	if got := clientIPWithTrust(req, []string{"10.0.0.0/8"}); got != "198.51.100.9" {
		t.Fatalf("got %q, want forwarded 198.51.100.9", got)
	}
	if got := clientIPWithTrust(req, []string{"192.168.0.0/16"}); got != "10.1.2.3" {
		t.Fatalf("got %q, want direct peer 10.1.2.3", got)
	}
}

func TestClientIPWithTrust_OverBroadCIDRRejected(t *testing.T) {
	req := newForwardedRequest("203.0.113.9:4444", "198.51.100.10", "")
	if got := clientIPWithTrust(req, []string{"0.0.0.0/0"}); got != "203.0.113.9" {
		t.Fatalf("got %q, want direct peer (0.0.0.0/0 must not be trusted)", got)
	}
}

// With an explicit trusted proxy, rotating forwarded IPs is legitimate: each
// distinct client IP gets its own bucket.
func TestServeHTTP_TrustedProxySeparatesClientBuckets(t *testing.T) {
	cfg := DefaultHandlerConfig()
	cfg.TrustedProxies = []string{"127.0.0.1"}
	cfg.RateLimitRequests = 1
	cfg.RateLimitWindow = time.Minute
	h := NewHandler(&Resolver{}, cfg)

	do := func(xRealIP string) int {
		req := newForwardedRequest("127.0.0.1:5555", xRealIP, "")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := do("198.51.100.1"); code != http.StatusUnauthorized {
		t.Fatalf("first client request = %d, want 401", code)
	}
	if code := do("198.51.100.2"); code != http.StatusUnauthorized {
		t.Fatalf("second client request = %d, want 401 (separate bucket)", code)
	}
	if code := do("198.51.100.1"); code != http.StatusTooManyRequests {
		t.Fatalf("repeated client request = %d, want 429", code)
	}
}
