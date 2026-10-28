package rpc

import (
	"errors"
	"net/http/httptest"
	"testing"
)

// R14-03 regression (2026-10-27): the GlobalIPWhitelist check used to run
// AFTER the public-method loop, and that loop returns nil on a hit. Every
// method listed in PublicMethods therefore skipped the operator's allowlist
// entirely — an operator who set GlobalIPWhitelist to restrict the RPC to
// their own network still served the whole public surface to the internet.
// The allowlist is global: it must gate public methods too.
func TestValidateRequest_IPWhitelistGatesPublicMethods(t *testing.T) {
	cfg := &AuthConfig{
		Enabled:           true,
		EnableHMAC:        false,
		APIKeys:           make(map[string]*APIKeyInfo),
		GlobalIPWhitelist: []string{"10.0.0.0/8"},
		PublicMethods:     []string{"eth_chainId"},
		APIKeyHeader:      "X-API-Key",
	}
	am := NewAuthManager(cfg)
	defer am.Stop()

	// Off-allowlist caller asking for a PUBLIC method: must be rejected.
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "203.0.113.9:12345"
	if err := am.ValidateRequest(r, "eth_chainId"); !errors.Is(err, ErrIPNotAllowed) {
		t.Fatalf("public method from a non-allowlisted IP must be rejected with ErrIPNotAllowed, got %v", err)
	}

	// On-allowlist caller asking for the same public method: must pass with no key.
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.RemoteAddr = "10.1.2.3:12345"
	if err := am.ValidateRequest(r2, "eth_chainId"); err != nil {
		t.Fatalf("public method from an allowlisted IP must pass, got %v", err)
	}
}

// Without a configured allowlist, public methods must stay key-free (no
// over-tightening from the reorder).
func TestValidateRequest_PublicMethodUnaffectedWithoutWhitelist(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	cfg.GlobalIPWhitelist = nil
	am := NewAuthManager(cfg)
	defer am.Stop()

	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "198.51.100.7:12345"
	if err := am.ValidateRequest(r, "eth_chainId"); err != nil {
		t.Fatalf("public method must stay open when no allowlist is configured, got %v", err)
	}
}

// Non-public methods from a non-allowlisted IP must still be rejected with the
// allowlist error (not the auth-required error) — the allowlist decision comes
// first, so operators see the real reason.
func TestValidateRequest_IPWhitelistStillGatesPrivateMethods(t *testing.T) {
	cfg := &AuthConfig{
		Enabled:           true,
		EnableHMAC:        false,
		APIKeys:           make(map[string]*APIKeyInfo),
		GlobalIPWhitelist: []string{"10.0.0.0/8"},
		PublicMethods:     []string{"eth_chainId"},
		APIKeyHeader:      "X-API-Key",
	}
	am := NewAuthManager(cfg)
	defer am.Stop()

	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "203.0.113.9:12345"
	if err := am.ValidateRequest(r, "admin_nodeInfo"); !errors.Is(err, ErrIPNotAllowed) {
		t.Fatalf("private method from a non-allowlisted IP must be rejected with ErrIPNotAllowed, got %v", err)
	}
}
