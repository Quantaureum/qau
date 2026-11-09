// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
)

// AUDIT run-3 qau.graphql/forced-auth-unwired-fail-closed-independent-model
// regression tests.
//
// startGraphQLServer used to build the handler from DefaultHandlerConfig()
// alone: no API key, no auth wiring, AuthDisabled=false. On a non-loopback
// listener that made every request fail with 401 and gave the operator no way
// to authenticate. The config builder now wires QAU_GRAPHQL_API_KEY for
// non-loopback listeners and keeps the fail-closed default otherwise.
func newGraphQLTestNode() *Node {
	return &Node{config: &Config{}}
}

func TestGraphQLHandlerConfig_LoopbackDefaults(t *testing.T) {
	t.Setenv("QAU_GRAPHQL_API_KEY", "secret-key")

	cfg := newGraphQLTestNode().graphqlHandlerConfig("127.0.0.1:8547")
	if cfg.APIKey != "" {
		t.Fatalf("loopback listener must not require an API key, got %q", cfg.APIKey)
	}
	if cfg.AuthDisabled {
		t.Fatal("auth-disabled mode must never be the default")
	}
}

func TestGraphQLHandlerConfig_NonLoopbackUsesConfiguredKey(t *testing.T) {
	t.Setenv("QAU_GRAPHQL_API_KEY", "secret-key")

	cfg := newGraphQLTestNode().graphqlHandlerConfig("0.0.0.0:8547")
	if cfg.APIKey != "secret-key" {
		t.Fatalf("non-loopback listener must use QAU_GRAPHQL_API_KEY, got %q", cfg.APIKey)
	}
	if cfg.AuthDisabled {
		t.Fatal("non-loopback listener must never disable authentication")
	}
}

func TestGraphQLHandlerConfig_NonLoopbackWithoutKeyStaysFailClosed(t *testing.T) {
	t.Setenv("QAU_GRAPHQL_API_KEY", "")

	cfg := newGraphQLTestNode().graphqlHandlerConfig("0.0.0.0:8547")
	if cfg.APIKey != "" {
		t.Fatalf("no key configured, unexpected APIKey %q", cfg.APIKey)
	}
	// With no key and AuthDisabled=false, Handler.isAuthenticated returns
	// false for every request: the endpoint stays fail-closed (401).
	if cfg.AuthDisabled {
		t.Fatal("missing API key must fail closed, not open")
	}
}
