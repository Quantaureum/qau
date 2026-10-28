// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// OBS-15-1 regression (2026-10-28): the HTTP batch path had the same shape as
// the WebSocket batch path fixed by R15-01. In rpc/server.go the whole batch
// auth block sits behind `if len(nonPublicMethods) > 0`, so a batch containing
// ONLY public methods skipped it entirely — and with it all three
// GlobalIPWhitelist enforcement points (validateRequest, validateBatchRequest,
// ValidateAdminRequest). Each batch element is then dispatched through
// handleRequest, which authorizes only ADMIN methods, so public methods got
// no check at all.
//
// Consequence: an operator who set GlobalIPWhitelist to restrict the RPC to
// their own network still served the whole public surface over HTTP batch
// requests, while the identical single-request path was correctly rejected.
//
// These tests drive handleHTTP directly (the same entry point ServeHTTP uses).

// newOBS15Server builds a server whose auth manager enforces a global
// allowlist of 10.0.0.0/8.
func newOBS15Server(t *testing.T) (*Server, func()) {
	t.Helper()
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	cfg.GlobalIPWhitelist = []string{"10.0.0.0/8"}
	am := NewAuthManager(cfg)

	srv := NewServer(nil)
	srv.authManager = am
	return srv, am.Stop
}

// postOBS15 sends body as an HTTP JSON-RPC request from the given remote
// address and returns the response body.
func postOBS15(t *testing.T, srv *Server, body, remoteAddr string) string {
	t.Helper()
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	srv.handleHTTP(w, r)
	return w.Body.String()
}

// An all-public HTTP batch from an off-allowlist IP must be rejected by the
// whitelist, not dispatched to method handlers.
func TestOBS15_1_HTTPBatchAllPublicRespectsWhitelist(t *testing.T) {
	srv, stop := newOBS15Server(t)
	defer stop()

	body := `[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber"}]`
	out := postOBS15(t, srv, body, "203.0.113.9:12345")

	if !strings.Contains(out, "IP address not allowed") {
		t.Fatalf("all-public HTTP batch from off-allowlist IP must be whitelist-rejected, got: %s", out)
	}
}

// Negative control: the same batch from an allowlisted IP must still be
// dispatched (the fix must not over-block legitimate traffic).
func TestOBS15_1_HTTPBatchAllowlistedIPStillDispatches(t *testing.T) {
	srv, stop := newOBS15Server(t)
	defer stop()

	body := `[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber"}]`
	out := postOBS15(t, srv, body, "10.1.2.3:12345")

	if strings.Contains(out, "IP address not allowed") {
		t.Fatalf("allowlisted IP must not be whitelist-rejected, got: %s", out)
	}
	if out == "" {
		t.Fatal("allowlisted batch produced no response at all")
	}
	var responses []Response
	if err := json.Unmarshal([]byte(out), &responses); err != nil {
		t.Fatalf("allowlisted batch must produce a JSON array of responses, got: %s", out)
	}
	if len(responses) != 2 {
		t.Fatalf("allowlisted batch must answer both elements, got %d responses", len(responses))
	}
}

// Without a configured allowlist, an all-public batch must keep working
// exactly as before (no over-tightening from the fix).
func TestOBS15_1_HTTPBatchWithoutWhitelistUnaffected(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	cfg.GlobalIPWhitelist = nil
	am := NewAuthManager(cfg)
	defer am.Stop()

	srv := NewServer(nil)
	srv.authManager = am

	body := `[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber"}]`
	out := postOBS15(t, srv, body, "203.0.113.9:12345")

	if strings.Contains(out, "IP address not allowed") {
		t.Fatalf("no allowlist configured — batch must not be IP-rejected, got: %s", out)
	}
	if out == "" {
		t.Fatal("batch produced no response at all")
	}
}

// A mixed batch (public + non-public) from an off-allowlist IP must also be
// rejected — the batch-level API-key check and the whitelist must both hold.
func TestOBS15_1_HTTPMixedBatchOffAllowlistRejected(t *testing.T) {
	srv, stop := newOBS15Server(t)
	defer stop()

	body := `[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"admin_nodeInfo"}]`
	out := postOBS15(t, srv, body, "203.0.113.9:12345")

	if !strings.Contains(out, "IP address not allowed") &&
		!strings.Contains(out, "authentication required") &&
		!strings.Contains(out, "API key") {
		t.Fatalf("mixed batch from off-allowlist IP must be auth-rejected, got: %s", out)
	}
}
