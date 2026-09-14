// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
)

// TestR4API02_isNonLoopbackAddr verifies that isNonLoopbackAddr correctly
// distinguishes loopback addresses (which are safe to disable auth on) from
// non-loopback addresses (which require auth).
//
// AUDIT (2026) R4-API-02: The previous security net used a fragile
// hardcoded string comparison that only matched three exact strings:
//
//	"127.0.0.1:8545", "localhost:8545", ":8545"
//
// It failed to recognize other loopback forms (127.0.0.2, 127.1.2.3, [::1])
// and incorrectly treated ":8545" (binds to 0.0.0.0 = all interfaces) as
// loopback. This test verifies the robust isNonLoopbackAddr() replacement.
func TestR4API02_isNonLoopbackAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool // true = non-loopback (remote), false = loopback (local)
	}{
		// Loopback IPv4 forms — should return false (local).
		{"loopback 127.0.0.1 with port", "127.0.0.1:8545", false},
		{"loopback 127.0.0.1 no port", "127.0.0.1", false},
		{"loopback 127.0.0.2 (full /8 range)", "127.0.0.2:8545", false},
		{"loopback 127.1.2.3 (full /8 range)", "127.1.2.3:8545", false},
		{"localhost with port", "localhost:8545", false},
		{"localhost no port", "localhost", false},

		// Loopback IPv6 forms — should return false (local).
		{"loopback IPv6 [::1]", "[::1]:8545", false},
		{"loopback IPv6 ::1 no brackets", "::1", false},

		// Empty/disabled — should return false (no listener at all).
		{"empty string", "", false},

		// Non-loopback IPv4 forms — should return true (remote).
		{"0.0.0.0 binds all interfaces", "0.0.0.0:8545", true},
		{":8545 binds all interfaces (no host)", ":8545", true},
		{"non-loopback 192.168.1.1", "192.168.1.1:8545", true},
		{"non-loopback 10.0.0.1", "10.0.0.1:8545", true},
		{"non-loopback 198.51.100.10", "198.51.100.10:8545", true},

		// Non-loopback IPv6 forms — should return true (remote).
		{"IPv6 [::] binds all interfaces", "[::]:8545", true},
		{"IPv6 non-loopback [2001:db8::1]", "[2001:db8::1]:8545", true},

		// Hostnames — should return true (could resolve to anything).
		{"hostname rpc.example.com", "rpc.example.com:8545", true},
		{"hostname node.local", "node.local:8546", true},

		// Whitespace handling.
		{"loopback with leading space", "  127.0.0.1:8545", false},
		{"loopback with trailing space", "127.0.0.1:8545  ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNonLoopbackAddr(tt.addr)
			if got != tt.want {
				t.Errorf("isNonLoopbackAddr(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// TestR4API02_SecurityNet_WSNonLoopbackForcesAuth verifies that the
// R4-API-02 fix makes isNonLoopbackAddr catch the WS address case that
// the old hardcoded string comparison missed.
//
// Before the fix: if RPCAddr="127.0.0.1:8545" and WSAddr="0.0.0.0:8546",
// the old check only looked at RPCAddr and concluded "not remote" → auth
// could be disabled, exposing admin_* methods over WS without auth.
//
// After the fix: isNonLoopbackAddr(WSAddr) returns true for "0.0.0.0:8546",
// so the security net forces auth on.
func TestR4API02_SecurityNet_WSNonLoopbackForcesAuth(t *testing.T) {
	// Simulate the vulnerable configuration: RPC on loopback, WS on all interfaces.
	rpcAddr := "127.0.0.1:8545"
	wsAddr := "0.0.0.0:8546"

	// Old check (hardcoded string comparison) — only looks at RPCAddr.
	oldRpcIsRemote := rpcAddr != "127.0.0.1:8545" && rpcAddr != "localhost:8545" && rpcAddr != ":8545"
	if oldRpcIsRemote {
		t.Fatalf("old check should say RPC is local for %q", rpcAddr)
	}

	// New check: also inspects WSAddr.
	newRpcIsRemote := isNonLoopbackAddr(rpcAddr)
	if !newRpcIsRemote && isNonLoopbackAddr(wsAddr) {
		newRpcIsRemote = true
	}
	if !newRpcIsRemote {
		t.Fatal("R4-API-02 REGRESSION: new security net failed to detect WS bound to 0.0.0.0 — auth would NOT be forced on, reproducing the vulnerability")
	}
	t.Logf("=== R4-API-02: new security net correctly detected WS=%s as non-loopback (rpcIsRemote=true) ===", wsAddr)
}

// TestR4API02_SecurityNet_GraphQLNonLoopbackForcesAuth verifies that the
// R4-API-02 fix catches the GraphQL address case.
//
// Before the fix: the GraphQL address (QAU_GRAPHQL_ADDR env var) was
// completely ignored by the security net. Setting QAU_GRAPHQL_ADDR=0.0.0.0:8547
// while keeping RPCAddr=127.0.0.1:8545 would NOT trigger auth enforcement.
//
// After the fix: isNonLoopbackAddr("0.0.0.0:8547") returns true, so auth
// is forced on.
func TestR4API02_SecurityNet_GraphQLNonLoopbackForcesAuth(t *testing.T) {
	rpcAddr := "127.0.0.1:8545"
	graphqlAddr := "0.0.0.0:8547"

	// New check: also inspects GraphQL address.
	rpcIsRemote := isNonLoopbackAddr(rpcAddr)
	if !rpcIsRemote && isNonLoopbackAddr(graphqlAddr) {
		rpcIsRemote = true
	}
	if !rpcIsRemote {
		t.Fatal("R4-API-02 REGRESSION: security net failed to detect GraphQL bound to 0.0.0.0 — auth would NOT be forced on")
	}
	t.Logf("=== R4-API-02: security net correctly detected GraphQL=%s as non-loopback ===", graphqlAddr)
}

// TestR4API02_SecurityNet_AllLoopbackNoForce verifies that when ALL
// listener addresses are loopback, the security net does NOT trigger
// (auth can remain disabled as configured). This is the non-regression
// case: the fix must not break the legitimate localhost-only deployment.
func TestR4API02_SecurityNet_AllLoopbackNoForce(t *testing.T) {
	rpcAddr := "127.0.0.1:8545"
	wsAddr := "127.0.0.1:8546"

	rpcIsRemote := isNonLoopbackAddr(rpcAddr)
	if !rpcIsRemote && isNonLoopbackAddr(wsAddr) {
		rpcIsRemote = true
	}
	if rpcIsRemote {
		t.Fatal("R4-API-02 REGRESSION: security net triggered for all-loopback config — would force auth on localhost-only deployment, breaking legitimate use")
	}
	t.Logf("=== R4-API-02: security net correctly identified all-loopback config (rpcIsRemote=false) ===")
}
