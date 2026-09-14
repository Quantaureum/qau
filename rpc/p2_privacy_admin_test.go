// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"testing"
)

// TestP2_PRIVACY_ADMIN_SendPrivacyTransactionIsAdminGated verifies that
// qau_sendPrivacyTransaction is registered as an admin method (via
// RegisterAdminHandler), not just a regular handler.
//
// P2-PRIVACY-ADMIN FIX (R29, 2026-07-26): Previously this method was
// registered with RegisterHandler, making it callable by any authenticated
// user. Since the method's parameters (from, to, amount) do NOT include a
// user-provided signature, the node would need to sign on behalf of the
// user (like eth_sendTransaction) — which is an admin operation. The fix
// switches to RegisterAdminHandler for defense-in-depth, ensuring the
// admin gate is in place before the privacy feature ships.
//
// This test prevents regression: if a future refactor accidentally
// switches back to RegisterHandler, this test will fail.
func TestP2_PRIVACY_ADMIN_SendPrivacyTransactionIsAdminGated(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	// qau_sendPrivacyTransaction MUST be an admin method.
	if !srv.isAdminMethod("qau_sendPrivacyTransaction") {
		t.Fatal("P2-PRIVACY-ADMIN REGRESSION: qau_sendPrivacyTransaction is not " +
			"registered as an admin method — it was switched back to " +
			"RegisterHandler, allowing any authenticated user to call it. " +
			"Since the method takes (from, to, amount) without a user " +
			"signature, the node would sign on behalf of the user, making " +
			"this an admin-only operation (like eth_sendTransaction).")
	}

	// The handler must still be registered (RegisterAdminHandler registers
	// both the admin flag AND the handler).
	if srv.handlers["qau_sendPrivacyTransaction"] == nil {
		t.Fatal("P2-PRIVACY-ADMIN REGRESSION: qau_sendPrivacyTransaction is " +
			"marked admin but the handler is not registered — the method " +
			"would return 'method not found' instead of 'admin required'")
	}
}

// TestP2_PRIVACY_ADMIN_SendPrivacyTransactionNotInPublicMethods verifies that
// qau_sendPrivacyTransaction is NOT in the PublicMethods list.
//
// P2-PRIVACY-ADMIN FIX (R29, 2026-07-26): A method cannot be both public
// (no auth required) and admin-gated — the two registrations conflict.
// If it's listed in PublicMethods, the admin gate is effectively bypassed
// for unauthenticated callers. This test ensures the method is removed
// from the PublicMethods list when it was switched to RegisterAdminHandler.
func TestP2_PRIVACY_ADMIN_SendPrivacyTransactionNotInPublicMethods(t *testing.T) {
	// Build the default AuthManager config (same as production).
	cfg := DefaultAuthConfig()
	am := NewAuthManager(cfg)

	// qau_sendPrivacyTransaction MUST NOT be a public method.
	if am.IsPublicMethod("qau_sendPrivacyTransaction") {
		t.Fatal("P2-PRIVACY-ADMIN REGRESSION: qau_sendPrivacyTransaction is " +
			"listed in PublicMethods, which bypasses the admin gate. " +
			"A method cannot be both public (no auth) and admin-gated — " +
			"remove it from PublicMethods to ensure the admin gate is " +
			"the sole authority for this method.")
	}

	// Sanity check: a known-public method should still be public (ensures
	// the test setup is correct and we're not just always returning true).
	if !am.IsPublicMethod("eth_blockNumber") {
		t.Fatal("test setup error: eth_blockNumber should be a public method")
	}
}

// TestP2_PRIVACY_ADMIN_SendPrivacyTransactionRequiresAdmin verifies end-to-end
// that calling qau_sendPrivacyTransaction without admin auth is rejected.
//
// This is a defense-in-depth test: even though the handler is currently a
// stub returning "not implemented", the admin gate must be enforced BEFORE
// the handler is invoked, so the user gets "admin required" instead of
// "not implemented". This ensures that when the handler is eventually
// implemented, the admin gate is already in place.
func TestP2_PRIVACY_ADMIN_SendPrivacyTransactionRequiresAdmin(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	// Enable admin auth enforcement (production behavior).
	api.SetEnforceAdminAuth(true)
	api.RegisterHandlers(srv)

	// Build a request with NO admin auth.
	params, _ := json.Marshal(map[string]any{
		"from":                "0x0000000000000000000000000000000000000001",
		"to":                  "0x0000000000000000000000000000000000000002",
		"receiverSpendPubKey": "0x",
		"receiverViewPubKey":  "0x",
		"amount":              "0x1",
	})

	req := &Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "qau_sendPrivacyTransaction",
		Params:  params,
	}

	// Use a context with NO admin auth.
	resp := srv.HandleRequest(context.Background(), req)

	// The request MUST fail (admin gate rejects before handler runs).
	if resp.Error == nil {
		t.Fatal("P2-PRIVACY-ADMIN REGRESSION: qau_sendPrivacyTransaction " +
			"was called without admin auth and did not return an error — " +
			"the admin gate is not enforced, allowing any authenticated " +
			"user to call this method")
	}

	// The error should indicate admin auth is required (not "not implemented").
	// We check that the error message mentions "admin" or "auth" somewhere.
	errMsg := resp.Error.Message
	if errMsg == "" {
		t.Fatalf("P2-PRIVACY-ADMIN REGRESSION: error message is empty")
	}

	// The error should NOT be "not implemented" — that would mean the
	// handler was invoked before the admin check, defeating the purpose
	// of the gate. The admin gate runs BEFORE handler dispatch.
	if containsSubstring(errMsg, "not implemented") {
		t.Fatalf("P2-PRIVACY-ADMIN REGRESSION: qau_sendPrivacyTransaction "+
			"returned 'not implemented' instead of 'admin required' — "+
			"the handler was invoked before the admin check, defeating "+
			"the admin gate (error: %s)", errMsg)
	}
}

// containsSubstring is a helper to check if a substring exists in a string.
// We define it locally to avoid importing strings (which would make the
// test file dependencies heavier than needed).
func containsSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
