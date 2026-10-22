// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// F-15 review follow-up (2026-10-21): pin the checkOrigin decision table.
// The no-origins fallback must key off the TCP peer address (r.RemoteAddr),
// never the forgeable Host header; the configured-origins branch keeps exact
// string matching and the rejectMissingOrigin gate.

func newTestWSServer(origins []string, rejectMissing bool) *WebSocketServer {
	ws := NewWebSocketServer(nil)
	ws.allowedOrigins = origins
	ws.rejectMissingOrigin = rejectMissing
	return ws
}

func originReq(remoteAddr, host, origin string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	r.RemoteAddr = remoteAddr
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestCheckOriginNoOriginsConfigured(t *testing.T) {
	ws := newTestWSServer(nil, true)

	tests := []struct {
		name    string
		remote  string
		host    string
		origin  string
		allowed bool
	}{
		// F-15 core property: the localhost decision comes from the TCP
		// peer, never the (forgeable) Host header.
		{"originless loopback IPv4", "127.0.0.1:52001", "localhost:8545", "", true},
		{"originless loopback IPv6", "[::1]:52002", "localhost:8545", "", true},
		{"originless remote with forged localhost Host", "203.0.113.9:52003", "localhost:8545", "", false},
		{"originless remote with plain Host", "203.0.113.9:52004", "node.example:8545", "", false},
		// Browser paths: Origin decides, Host is irrelevant.
		{"browser localhost origin from remote peer", "203.0.113.9:52005", "node.example", "http://localhost:3000", true},
		{"browser localhost origin from loopback", "127.0.0.1:52006", "whatever", "https://127.0.0.1:8443", true},
		{"browser external origin rejected", "127.0.0.1:52007", "whatever", "https://evil.example", false},
		{"malformed Origin rejected", "127.0.0.1:52008", "localhost", "http://localhost:0:bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ws.checkOrigin(originReq(tt.remote, tt.host, tt.origin)); got != tt.allowed {
				t.Fatalf("checkOrigin(remote=%s host=%s origin=%q) = %v, want %v",
					tt.remote, tt.host, tt.origin, got, tt.allowed)
			}
		})
	}
}

func TestCheckOriginConfiguredOrigins(t *testing.T) {
	// Exact-match policy with a configured list: no localhost fallback.
	ws := newTestWSServer([]string{"https://app.example", "https://admin.example"}, true)

	tests := []struct {
		name    string
		remote  string
		origin  string
		allowed bool
	}{
		{"exact match", "203.0.113.9:1", "https://app.example", true},
		{"second entry", "203.0.113.9:2", "https://admin.example", true},
		{"scheme mismatch rejected", "203.0.113.9:3", "http://app.example", false},
		{"prefix not enough", "203.0.113.9:4", "https://app.example.evil.io", false},
		{"case-sensitive", "203.0.113.9:5", "https://APP.example", false},
		{"missing Origin rejected by default", "203.0.113.9:6", "", false},
		{"localhost origin NOT special-cased", "203.0.113.9:7", "http://localhost:3000", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ws.checkOrigin(originReq(tt.remote, "node.example", tt.origin)); got != tt.allowed {
				t.Fatalf("checkOrigin(origin=%q) = %v, want %v", tt.origin, got, tt.allowed)
			}
		})
	}

	// rejectMissingOrigin=false relaxes ONLY the missing-Origin case.
	ws.rejectMissingOrigin = false
	if !ws.checkOrigin(originReq("203.0.113.9:8", "node.example", "")) {
		t.Fatal("rejectMissingOrigin=false: missing Origin should be accepted")
	}
	if ws.checkOrigin(originReq("203.0.113.9:9", "node.example", "https://unknown.example")) {
		t.Fatal("rejectMissingOrigin=false: unknown Origin must still be rejected")
	}

	// Wildcard accepts any Origin.
	wild := newTestWSServer([]string{"*"}, true)
	if !wild.checkOrigin(originReq("203.0.113.9:10", "node.example", "https://anything.example")) {
		t.Fatal("wildcard origin rejected")
	}
}
