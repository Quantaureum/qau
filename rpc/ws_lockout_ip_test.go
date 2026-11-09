// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"net"
	"testing"
)

// AUDIT node/rpc-ws-lockout-port-key regression (ported from node 8245a07).
//
// The WebSocket dispatch path stored conn.RemoteAddr().String() ("IP:port") in
// contextKeyClientIP. authenticateFromContext then rebuilt RemoteAddr with
// net.JoinHostPort(clientIP, "0"), producing "IP:port:0" — not a valid
// host:port pair — so http.Request-based attribution fell back to the whole
// string. Because the port is unique per connection, every reconnect landed in
// a fresh brute-force lockout bucket, letting an attacker reset failed-auth
// counters indefinitely.
func TestWSClientIP_StripsPortSoLockoutKeyIsStable(t *testing.T) {
	if got := wsClientIP("203.0.113.7:51234"); got != "203.0.113.7" {
		t.Fatalf("wsClientIP stripped wrong value: got %q, want 203.0.113.7", got)
	}
	// Two connections from the same host must map to the same lockout key.
	a := wsClientIP("203.0.113.7:51234")
	b := wsClientIP("203.0.113.7:60000")
	if a != b {
		t.Fatalf("same host different ports produced different lockout keys: %q vs %q", a, b)
	}
	// IPv6 literals keep their brackets once a port is appended again.
	if got := wsClientIP("[2001:db8::1]:51234"); got != "2001:db8::1" {
		t.Fatalf("wsClientIP on IPv6: got %q, want 2001:db8::1", got)
	}
	// The value must survive the authenticateFromContext round-trip.
	host, _, err := net.SplitHostPort(net.JoinHostPort(a, "0"))
	if err != nil || host != a {
		t.Fatalf("JoinHostPort(%q) is not round-trippable: host=%q err=%v", a, host, err)
	}
}

// Pins the pre-fix defect shape: an "IP:port" context value round-trips
// through net.JoinHostPort into a BRACKETED address whose host still contains
// the port, so the port-bearing string becomes the attribution key and differs
// per connection.
func TestWSClientIP_UntrimmedValueKeepsPortInKey(t *testing.T) {
	remoteAddr := net.JoinHostPort("203.0.113.7:51234", "0") // what server.go built pre-fix
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		t.Fatalf("unexpected split failure for %q: %v", remoteAddr, err)
	}
	if host != "203.0.113.7:51234" {
		t.Fatalf("pre-fix key shape changed: got %q, want 203.0.113.7:51234", host)
	}
	other, _, err := net.SplitHostPort(net.JoinHostPort("203.0.113.7:60000", "0"))
	if err != nil {
		t.Fatalf("unexpected split failure: %v", err)
	}
	if host == other {
		t.Fatalf("pre-fix keys should be per-connection, got identical %q", host)
	}
}
