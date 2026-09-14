// Quantaureum Node source, version 1.0.0.
package node

import (
	"strings"
	"testing"
)

// R90-PROXY-IP regression tests.
//
// Without resolveRPCTrustedProxies wired into the auth manager and rate
// limiter, a node behind a TLS-terminating reverse proxy attributes every
// request to the proxy's own loopback address: per-IP rate limiting degrades
// into one shared bucket for all wallet users and one attacker's auth failures
// lock out everybody. These tests pin the policy that decides which proxies may
// supply X-Forwarded-For.

func TestR90_ResolveRPCTrustedProxies_EmptyTrustsNothing(t *testing.T) {
	got, err := resolveRPCTrustedProxies(nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil (trust nothing) for empty input, got %v", got)
	}

	// Whitespace-only entries must not create a phantom policy either: a
	// non-empty slice would flip rpc.getClientIPWithTrust into X-Forwarded-For
	// parsing mode for requests from unlisted peers.
	got, err = resolveRPCTrustedProxies([]string{"", "   "}, "  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for whitespace-only input, got %v", got)
	}
}

func TestR90_ResolveRPCTrustedProxies_ParsesIPsAndCIDRs(t *testing.T) {
	got, err := resolveRPCTrustedProxies(
		[]string{"127.0.0.1", " ::1 ", "10.0.0.0/8", "fd00::/8"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"127.0.0.1", "::1", "10.0.0.0/8", "fd00::/8"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: got %q want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestR90_ResolveRPCTrustedProxies_EnvOverridesConfigAndDedupes(t *testing.T) {
	// The env var replaces the configured list outright (same contract as
	// QAU_RPC_USER_ALLOWLIST) so an operator can fix a bad config without
	// editing the file.
	got, err := resolveRPCTrustedProxies([]string{"10.1.2.3"}, "127.0.0.1, 127.0.0.1 ,::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"127.0.0.1", "::1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v (env must replace config and dedupe)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestR90_ResolveRPCTrustedProxies_RejectsOverBroadAndMalformed(t *testing.T) {
	cases := []struct {
		name    string
		entry   string
		wantSub string
	}{
		// Trusting the whole internet lets any caller spoof X-Forwarded-For
		// and bypass per-IP rate limiting entirely.
		{"ipv4 default route", "0.0.0.0/0", "over-broad"},
		{"ipv6 default route", "::/0", "over-broad"},
		{"unspecified ipv4", "0.0.0.0", "unspecified"},
		{"unspecified ipv6", "::", "unspecified"},
		// Malformed input must fail closed at startup rather than be dropped:
		// a silent drop reintroduces the collapsed-IP behavior this setting
		// exists to fix, with no signal to the operator.
		{"not an ip", "caddy", "invalid IP"},
		{"bad cidr", "10.0.0.0/99", "invalid CIDR"},
		{"host:port instead of ip", "127.0.0.1:2019", "invalid IP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveRPCTrustedProxies([]string{tc.entry}, "")
			if err == nil {
				t.Fatalf("expected an error for %q, got %v", tc.entry, got)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantSub)
			}
			if got != nil {
				t.Fatalf("expected nil result alongside error, got %v", got)
			}
		})
	}
}

func TestR90_ResolveRPCTrustedProxies_RejectsBadEntryFromEnv(t *testing.T) {
	// The env path must validate too — it is the one an operator edits under
	// time pressure during an incident.
	if _, err := resolveRPCTrustedProxies(nil, "127.0.0.1,0.0.0.0/0"); err == nil {
		t.Fatal("expected the over-broad env entry to be rejected")
	}
}

func TestR90_ResolveRPCTrustedProxies_AcceptsSingleHostCIDR(t *testing.T) {
	// /32 and /128 are the tightest useful form (one specific proxy) and must
	// not be mistaken for an over-broad mask.
	for _, entry := range []string{"127.0.0.1/32", "::1/128"} {
		got, err := resolveRPCTrustedProxies([]string{entry}, "")
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", entry, err)
		}
		if len(got) != 1 || got[0] != entry {
			t.Fatalf("%s: got %v", entry, got)
		}
	}
}

func TestR90_NewRPCAuthConfig_CarriesProxiesAndKeepsDefaults(t *testing.T) {
	proxies := []string{"127.0.0.1"}
	cfg := newRPCAuthConfig(proxies)
	if cfg == nil {
		t.Fatal("nil auth config")
	}
	if len(cfg.TrustedProxies) != 1 || cfg.TrustedProxies[0] != "127.0.0.1" {
		t.Fatalf("trusted proxies not applied: %v", cfg.TrustedProxies)
	}
	// The proxy policy must be additive: rpc.NewAuthManager(nil) would have
	// used DefaultAuthConfig, so replacing it must not drop auth itself or the
	// public-method allowlist that keeps wallets working.
	if !cfg.Enabled {
		t.Fatal("auth must stay enabled")
	}
	if len(cfg.PublicMethods) == 0 {
		t.Fatal("public method allowlist must be preserved")
	}

	// Nil policy (no proxy in front) must stay nil rather than become a
	// zero-length non-nil slice: rpc.getClientIPWithTrust branches on len()==0,
	// but a caller inspecting the config should see the same "trust nothing".
	if got := newRPCAuthConfig(nil).TrustedProxies; len(got) != 0 {
		t.Fatalf("expected no trusted proxies, got %v", got)
	}
}

func TestR90_NewRPCRateLimitConfig_CarriesProxiesAndKeepsDefaults(t *testing.T) {
	// R107: newRPCRateLimitConfig now also overlays the node's configurable
	// limits; an empty Config must therefore still yield the rpc defaults.
	cfg := newRPCRateLimitConfig(&Config{}, []string{"10.0.0.0/8"})
	if cfg == nil {
		t.Fatal("nil rate limit config")
	}
	if len(cfg.TrustedProxies) != 1 || cfg.TrustedProxies[0] != "10.0.0.0/8" {
		t.Fatalf("trusted proxies not applied: %v", cfg.TrustedProxies)
	}
	if !cfg.Enabled {
		t.Fatal("rate limiting must stay enabled")
	}
	if cfg.PerIPRateLimit <= 0 || cfg.GlobalRateLimit <= 0 {
		t.Fatalf("default limits must be preserved (perIP=%d global=%d)",
			cfg.PerIPRateLimit, cfg.GlobalRateLimit)
	}
}
