// Quantaureum Node source, version 1.0.0.
package graphql

// F-11 (2026-10-21): the graphql package previously had no tests. These cover
// the handler's resource limits (query length, complexity, depth, body size),
// input sanitization, and the read-only guarantee of auth-disabled mode.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestHandler(t *testing.T, cfg *HandlerConfig) *Handler {
	t.Helper()
	if cfg == nil {
		cfg = DefaultHandlerConfig()
	}
	if cfg.RateLimitRequests == 0 {
		cfg.RateLimitRequests = 1000
	}
	return NewHandler(nil, cfg)
}

func graphQLPost(t *testing.T, h *Handler, query string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(GraphQLRequest{Query: query})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler_QueryAndBodyLimits(t *testing.T) {
	t.Run("query length", func(t *testing.T) {
		cfg := DefaultHandlerConfig()
		cfg.AuthDisabled = true
		h := newTestHandler(t, cfg)
		rec := graphQLPost(t, h, strings.Repeat("a", DefaultMaxQueryLength+1), nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("body size", func(t *testing.T) {
		cfg := DefaultHandlerConfig()
		cfg.AuthDisabled = true
		cfg.MaxBodySize = 64
		h := newTestHandler(t, cfg)
		rec := graphQLPost(t, h, "{"+strings.Repeat("a", 128)+"}", nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("complexity", func(t *testing.T) {
		h := newTestHandler(t, nil)
		query := "{" + strings.Repeat("a ", 120) + "}"
		if err := h.validateComplexity(query); err != ErrQueryTooComplex {
			t.Fatalf("validateComplexity = %v, want ErrQueryTooComplex", err)
		}
	})

	t.Run("depth", func(t *testing.T) {
		cfg := DefaultHandlerConfig()
		cfg.MaxDepth = 4
		h := newTestHandler(t, cfg)
		query := strings.Repeat("{ ", 6) + "x " + strings.Repeat("} ", 6)
		if err := h.validateComplexity(query); err != ErrQueryTooComplex {
			t.Fatalf("validateComplexity = %v, want ErrQueryTooComplex", err)
		}
	})

	t.Run("within limits", func(t *testing.T) {
		h := newTestHandler(t, nil)
		if err := h.validateComplexity("{ chainId gasPrice }"); err != nil {
			t.Fatalf("simple query rejected: %v", err)
		}
	})
}

func TestSanitizeGraphQLQuery(t *testing.T) {
	bad := []struct {
		name  string
		query string
	}{
		{"null byte", "{ a\x00 }"},
		{"comment", "{ a # comment\n }"},
		{"string literal", `{ a(arg: "x") }`},
		{"unbalanced braces open", "{ a "},
		{"unbalanced braces close", "a }"},
		{"unbalanced parens", "{ a( }"},
		{"excessive whitespace", "{" + strings.Repeat(" ", 200) + "a }"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := sanitizeGraphQLQuery(tc.query); err == nil {
				t.Fatalf("sanitizeGraphQLQuery(%q) accepted an invalid query", tc.query)
			}
		})
	}

	if err := sanitizeGraphQLQuery("{ chainId }"); err != nil {
		t.Fatalf("valid query rejected: %v", err)
	}
}

func TestIsMutationOperation(t *testing.T) {
	cases := map[string]bool{
		"mutation { setValue }":       true,
		" \n\tmutation { setValue } ": true,
		"{ setValue }":                false,
		"query { setValue }":          false,
		"querymutation { x }":         false,
	}
	for query, want := range cases {
		if got := isMutationOperation(query); got != want {
			t.Fatalf("isMutationOperation(%q) = %v, want %v", query, got, want)
		}
	}
}

func TestHandler_AuthDisabledIsReadOnly(t *testing.T) {
	cfg := DefaultHandlerConfig()
	cfg.AuthDisabled = true
	h := newTestHandler(t, cfg)

	rec := graphQLPost(t, h, "mutation { setValue }", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("mutation with AuthDisabled: status = %d, want 401", rec.Code)
	}

	rec = graphQLPost(t, h, "{ unsupportedField }", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("read query with AuthDisabled: status = %d, want 200", rec.Code)
	}
}

func TestHandler_APIKeyAuthentication(t *testing.T) {
	cfg := DefaultHandlerConfig()
	cfg.APIKey = "test-api-key"
	h := newTestHandler(t, cfg)

	if rec := graphQLPost(t, h, "{ unsupportedField }", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request: status = %d, want 401", rec.Code)
	}
	rec := graphQLPost(t, h, "{ unsupportedField }", map[string]string{
		"Authorization": "Bearer test-api-key",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated request: status = %d, want 200", rec.Code)
	}
}

func TestRateLimiter_BoundsRequests(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)
	if !rl.allow("198.51.100.7") {
		t.Fatal("first request should be allowed")
	}
	if !rl.allow("198.51.100.7") {
		t.Fatal("second request should be allowed")
	}
	if rl.allow("198.51.100.7") {
		t.Fatal("third request should be rejected")
	}
	if !rl.allow("198.51.100.8") {
		t.Fatal("a different client must not be affected")
	}
}
