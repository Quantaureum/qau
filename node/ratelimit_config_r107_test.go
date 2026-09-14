// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/rpc"
)

// R107-LOCAL-FANOUT (2026-09-04)
//
// The node used to expose only requestsPerSecond (the *global* RPC limit) in
// config.json. The per-IP bucket, its burst, the violation threshold and the ban
// duration were hardcoded in rpc.DefaultRateLimitConfig(), so an operator whose
// co-located service (the explorer front-end on 127.0.0.1) kept tripping the
// per-IP ban had no lever short of patching the binary — and clearing an active
// ban required restarting the validator.
//
// These tests pin the config plumbing: startup and hot-reload must both honour
// the new fields, unset fields must keep the safe defaults, and a malformed or
// over-broad exemption must be rejected loudly instead of silently ignored.

func TestR107_BuildRateLimitConfig_UnsetFieldsKeepDefaults(t *testing.T) {
	defaults := rpc.DefaultRateLimitConfig()
	got := buildRateLimitConfig(&Config{})

	if got.GlobalRateLimit != defaults.GlobalRateLimit {
		t.Errorf("GlobalRateLimit = %d, want default %d", got.GlobalRateLimit, defaults.GlobalRateLimit)
	}
	if got.PerIPRateLimit != defaults.PerIPRateLimit {
		t.Errorf("PerIPRateLimit = %d, want default %d", got.PerIPRateLimit, defaults.PerIPRateLimit)
	}
	if got.BurstSize != defaults.BurstSize {
		t.Errorf("BurstSize = %d, want default %d", got.BurstSize, defaults.BurstSize)
	}
	if got.ViolationsBeforeBan != defaults.ViolationsBeforeBan {
		t.Errorf("ViolationsBeforeBan = %d, want default %d", got.ViolationsBeforeBan, defaults.ViolationsBeforeBan)
	}
	if got.BanDuration != defaults.BanDuration {
		t.Errorf("BanDuration = %v, want default %v", got.BanDuration, defaults.BanDuration)
	}
	if len(got.ExemptIPs) != 0 {
		t.Errorf("ExemptIPs = %v, want empty (exemptions must be opt-in)", got.ExemptIPs)
	}
	if !got.Enabled {
		t.Error("rate limiting must stay enabled")
	}
}

func TestR107_BuildRateLimitConfig_AppliesConfiguredValues(t *testing.T) {
	cfg := &Config{
		RequestsPerSecond:            2000,
		PerIPRequestsPerSecond:       400,
		RateLimitBurstSize:           800,
		RateLimitViolationsBeforeBan: 50,
		RateLimitBanDurationSeconds:  120,
		RateLimitExemptIPs:           []string{"127.0.0.1", "::1"},
	}
	got := buildRateLimitConfig(cfg)

	if got.GlobalRateLimit != 2000 {
		t.Errorf("GlobalRateLimit = %d, want 2000", got.GlobalRateLimit)
	}
	if got.PerIPRateLimit != 400 {
		t.Errorf("PerIPRateLimit = %d, want 400", got.PerIPRateLimit)
	}
	if got.BurstSize != 800 {
		t.Errorf("BurstSize = %d, want 800", got.BurstSize)
	}
	if got.ViolationsBeforeBan != 50 {
		t.Errorf("ViolationsBeforeBan = %d, want 50", got.ViolationsBeforeBan)
	}
	if got.BanDuration != 2*time.Minute {
		t.Errorf("BanDuration = %v, want 2m", got.BanDuration)
	}
	if len(got.ExemptIPs) != 2 || got.ExemptIPs[0] != "127.0.0.1" || got.ExemptIPs[1] != "::1" {
		t.Errorf("ExemptIPs = %v, want [127.0.0.1 ::1]", got.ExemptIPs)
	}

	// The slice must be copied: mutating the node config afterwards must not
	// reach into the limiter's live config.
	cfg.RateLimitExemptIPs[0] = "10.0.0.1"
	if got.ExemptIPs[0] != "127.0.0.1" {
		t.Error("ExemptIPs must be a defensive copy of the node config slice")
	}
}

func TestR107_BuildRateLimitConfig_IgnoresNonPositiveValues(t *testing.T) {
	defaults := rpc.DefaultRateLimitConfig()
	// A typo (negative) must not disable limiting; it falls back to defaults.
	got := buildRateLimitConfig(&Config{
		PerIPRequestsPerSecond:       -1,
		RateLimitBurstSize:           -10,
		RateLimitViolationsBeforeBan: -5,
		RateLimitBanDurationSeconds:  -60,
	})

	if got.PerIPRateLimit != defaults.PerIPRateLimit {
		t.Errorf("negative PerIPRequestsPerSecond must be ignored, got %d", got.PerIPRateLimit)
	}
	if got.BurstSize != defaults.BurstSize {
		t.Errorf("negative RateLimitBurstSize must be ignored, got %d", got.BurstSize)
	}
	if got.ViolationsBeforeBan != defaults.ViolationsBeforeBan {
		t.Errorf("negative RateLimitViolationsBeforeBan must be ignored, got %d", got.ViolationsBeforeBan)
	}
	if got.BanDuration != defaults.BanDuration {
		t.Errorf("negative RateLimitBanDurationSeconds must be ignored, got %v", got.BanDuration)
	}
}

// The startup path is what regressed before: config.json values were only read
// by the hot-reload path, so a fresh boot silently used the defaults.
func TestR107_NewRPCRateLimitConfig_HonoursNodeConfigAtStartup(t *testing.T) {
	cfg := &Config{
		PerIPRequestsPerSecond: 500,
		RateLimitExemptIPs:     []string{"127.0.0.1"},
	}
	got := newRPCRateLimitConfig(cfg, []string{"10.0.0.0/8"})

	if got.PerIPRateLimit != 500 {
		t.Errorf("startup PerIPRateLimit = %d, want 500", got.PerIPRateLimit)
	}
	if len(got.ExemptIPs) != 1 || got.ExemptIPs[0] != "127.0.0.1" {
		t.Errorf("startup ExemptIPs = %v, want [127.0.0.1]", got.ExemptIPs)
	}
	// The trusted-proxy policy must survive the overlay.
	if len(got.TrustedProxies) != 1 || got.TrustedProxies[0] != "10.0.0.0/8" {
		t.Errorf("TrustedProxies = %v, want [10.0.0.0/8]", got.TrustedProxies)
	}
}

func TestR107_ValidateRateLimitExemptIPs(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		wantErr bool
	}{
		{"empty", nil, false},
		{"loopback v4", []string{"127.0.0.1"}, false},
		{"loopback v6", []string{"::1"}, false},
		{"cidr", []string{"10.1.0.0/16"}, false},
		{"blank entries skipped", []string{"", "  "}, false},
		{"garbage", []string{"not-an-ip"}, true},
		{"unspecified v4", []string{"0.0.0.0"}, true},
		{"all of ipv4", []string{"0.0.0.0/0"}, true},
		{"all of ipv6", []string{"::/0"}, true},
		{"bad cidr", []string{"10.0.0.0/99"}, true},
		{"one bad among good", []string{"127.0.0.1", "nope"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateLimitExemptIPs(tt.entries)
			if tt.wantErr && err == nil {
				t.Fatalf("expected an error for %v", tt.entries)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %v: %v", tt.entries, err)
			}
		})
	}
}

// Hot-reload must notice a change in any of the new fields; otherwise raising a
// limit or adding an exemption would still require the restart this change is
// meant to avoid.
func TestR107_RateLimitFieldsAreHotReloadable(t *testing.T) {
	base := &Config{RequestsPerSecond: 1000}
	tests := []struct {
		name  string
		apply func(c *Config)
	}{
		{"perIP", func(c *Config) { c.PerIPRequestsPerSecond = 300 }},
		{"burst", func(c *Config) { c.RateLimitBurstSize = 300 }},
		{"violations", func(c *Config) { c.RateLimitViolationsBeforeBan = 99 }},
		{"banDuration", func(c *Config) { c.RateLimitBanDurationSeconds = 30 }},
		{"exemptIPs", func(c *Config) { c.RateLimitExemptIPs = []string{"127.0.0.1"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := *base
			tt.apply(&changed)
			if rateLimitConfigUnchanged(base, &changed) {
				t.Fatalf("%s change must be detected by the hot-reload comparison", tt.name)
			}
		})
	}

	same := *base
	if !rateLimitConfigUnchanged(base, &same) {
		t.Fatal("identical configs must be reported as unchanged (avoids pointless limiter churn)")
	}
}

func TestR107_EqualStringSlices(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{nil, []string{}, true},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a"}, []string{"b"}, false},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
	}
	for _, c := range cases {
		if got := equalStringSlices(c.a, c.b); got != c.want {
			t.Errorf("equalStringSlices(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
