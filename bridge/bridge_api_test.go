// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBRDG_R7_04_RateLimitAndBan verifies the per-IP rate limiter + auth-failure
// ban added in BRDG-R7-04. The fix closes the brute-force / DoS vector where an
// attacker could hit /bridge/message/* at >1000 req/s with arbitrary API keys.
func TestBRDG_R7_04_RateLimitAndBan(t *testing.T) {
	// Build an API with a known key. We don't start the HTTP server; we
	// invoke the authenticated handler directly via httptest.
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := NewBridgeAPI(qb, nil, nil, nil, "correct-key")
	// Wire a trivial handler through authenticate so we can observe decisions.
	h := api.authenticate(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	// --- Part 1: wrong key accumulates failures → ban after apiMaxFailures ---
	ip := "10.0.0.1"
	for i := 0; i < apiMaxFailures; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/bridge/status", nil)
		req.RemoteAddr = ip + ":1234"
		req.Header.Set("X-API-Key", "wrong-key")
		rr := httptest.NewRecorder()
		h(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, rr.Code)
		}
	}
	// At this point the IP should be banned. The next request — even with the
	// correct key — must be rejected with 429 (ban takes precedence over auth).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bridge/status", nil)
	req.RemoteAddr = ip + ":1234"
	req.Header.Set("X-API-Key", "correct-key")
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: expected 429 (banned), got %d", apiMaxFailures, rr.Code)
	}

	// --- Part 2: a different IP is unaffected (per-IP, not global) ---
	ip2 := "10.0.0.2"
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/bridge/status", nil)
	req2.RemoteAddr = ip2 + ":5678"
	req2.Header.Set("X-API-Key", "correct-key")
	rr2 := httptest.NewRecorder()
	h(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("different IP with correct key: expected 200, got %d (ban should be per-IP)", rr2.Code)
	}

	// --- Part 3: correct key on a fresh IP passes the rate limiter ---
	// (We already proved this in Part 2, but also confirm a second request
	// from the same fresh IP succeeds while within the burst budget.)
	rr3 := httptest.NewRecorder()
	h(rr3, req2)
	if rr3.Code != http.StatusOK {
		t.Fatalf("second request from fresh IP: expected 200, got %d", rr3.Code)
	}
}

// TestBRDG_R7_04_ClientIP verifies the clientIP method correctly extracts the
// origin IP from X-Forwarded-For (when behind Caddy / a trusted reverse proxy
// with TrustProxy=true) and falls back to RemoteAddr on direct exposure
// (TrustProxy=false).
//
// R43-BRIDGE-XFF-01 FIX (2026-08-03): clientIP is now a method on
// BridgeAPI. X-Forwarded-For is honored ONLY when TrustProxy==true. The
// original test cases (direct / xff-single / xff-multi / no-port) are
// preserved; we now run them under TWO TrustProxy modes:
//   - TrustProxy=true  → XFF honored (matches the original test semantics).
//   - TrustProxy=false → XFF ignored, RemoteAddr peer returned.
func TestBRDG_R7_04_ClientIP(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	cases := []struct {
		name       string
		xff        string
		remote     string
		trustProxy bool
		want       string
	}{
		// TrustProxy == true: XFF honored (original test cases).
		{"trust_direct", "", "203.0.113.5:5678", true, "203.0.113.5"},
		{"trust_xff_single", "198.51.100.7", "10.0.0.1:99", true, "198.51.100.7"},
		{"trust_xff_multi", "198.51.100.7, 10.0.0.1, 192.0.2.9", "10.0.0.1:99", true, "198.51.100.7"},
		{"trust_no_port", "", "203.0.113.5", true, "203.0.113.5"},
		// TrustProxy == false: XFF ignored, RemoteAddr peer returned.
		// R43-BRIDGE-XFF-01: spoofable XFF must NOT bypass rate limit on
		// direct exposure.
		{"notrust_direct", "", "203.0.113.5:5678", false, "203.0.113.5"},
		{"notrust_xff_ignored", "198.51.100.7", "10.0.0.1:99", false, "10.0.0.1"},
		{"notrust_xff_multi_ignored", "198.51.100.7, 10.0.0.1, 192.0.2.9", "10.0.0.1:99", false, "10.0.0.1"},
		{"notrust_no_port", "", "203.0.113.5", false, "203.0.113.5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := NewBridgeAPI(qb, nil, nil, nil, "test-key")
			api.SetTrustProxy(c.trustProxy)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = c.remote
			if c.xff != "" {
				req.Header.Set("X-Forwarded-For", c.xff)
			}
			got := api.clientIP(req)
			if got != c.want {
				t.Errorf("clientIP(trustProxy=%v) = %q, want %q", c.trustProxy, got, c.want)
			}
		})
	}
}

// TestBRDG_R7_04_SetTrustProxy verifies SetTrustProxy is thread-safe and
// the trustProxy field flips correctly. R43-BRIDGE-XFF-01 FIX.
func TestBRDG_R7_04_SetTrustProxy(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := NewBridgeAPI(qb, nil, nil, nil, "test-key")

	// Default is false (direct-exposure safe).
	api.mu.RLock()
	got := api.TrustProxy
	api.mu.RUnlock()
	if got {
		t.Fatalf("default TrustProxy: got true, want false")
	}

	api.SetTrustProxy(true)
	api.mu.RLock()
	got = api.TrustProxy
	api.mu.RUnlock()
	if !got {
		t.Fatalf("after SetTrustProxy(true): got false, want true")
	}

	api.SetTrustProxy(false)
	api.mu.RLock()
	got = api.TrustProxy
	api.mu.RUnlock()
	if got {
		t.Fatalf("after SetTrustProxy(false): got true, want false")
	}
}
