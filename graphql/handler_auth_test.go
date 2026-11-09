// Quantaureum Node source, version 1.0.0.
package graphql

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AUDIT run-3 qau.graphql/forced-auth-unwired-fail-closed-independent-model
// regression test: the default handler configuration has no credential and
// AuthDisabled=false, so unauthenticated requests must be rejected. This
// guards the fail-closed property that makes the endpoint safe when the node
// has not wired an API key.
func TestDefaultHandlerConfig_RejectsUnauthenticatedRequests(t *testing.T) {
	h := NewHandler(&Resolver{}, DefaultHandlerConfig())

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ chainId }"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GraphQL request returned %d, want 401", rec.Code)
	}
}

// A configured API key must be required: requests without the header stay 401.
func TestConfiguredAPIKey_RequiresHeader(t *testing.T) {
	cfg := DefaultHandlerConfig()
	cfg.APIKey = "graphql-test-key"
	h := NewHandler(&Resolver{}, cfg)

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ chainId }"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("request without X-API-Key returned %d, want 401", rec.Code)
	}
}
