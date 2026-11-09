// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"net"
	"testing"
	"time"
)

// AUDIT run-3 qau.config/graphql-flag-ignored regression tests.
//
// The --graphql flag used to be parsed and then ignored: startGraphQLServer
// only honored QAU_GRAPHQL_ADDR=off, so "--graphql=false" left the listener
// running while the operator believed it was off. The flag is now wired:
//   - explicit --graphql=false  -> server not started
//   - flag omitted              -> legacy behavior (server starts unless env off)
//   - explicit --graphql=true   -> server starts
//   - QAU_GRAPHQL_ADDR=off      -> still wins (backwards compatible)

// freeLoopbackAddr reserves then releases a loopback port and returns its
// address, so the test can point QAU_GRAPHQL_ADDR at a port nothing else uses.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a loopback port: %v", err)
	}
	addr := l.Addr().String()
	if cerr := l.Close(); cerr != nil {
		t.Fatalf("failed to release the reserved port: %v", cerr)
	}
	return addr
}

// dialEventually reports whether addr accepts TCP connections within timeout.
func dialEventually(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// stopGraphQLServer shuts the test server down without failing the test on
// timeout (the listener is torn down with the process anyway).
func stopGraphQLServer(t *testing.T, n *Node) {
	t.Helper()
	if n.graphqlServer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = n.graphqlServer.Shutdown(ctx)
}

func TestGraphqlFlagExplicitFalseDoesNotStartServer(t *testing.T) {
	addr := freeLoopbackAddr(t)
	t.Setenv("QAU_GRAPHQL_ADDR", addr)
	t.Setenv("QAU_GRAPHQL_API_KEY", "")

	n := &Node{config: &Config{GraphqlExplicit: true, GraphqlEnabled: false}}
	n.startGraphQLServer()

	if n.graphqlServer != nil {
		stopGraphQLServer(t, n)
		t.Fatal("--graphql=false must not start the GraphQL server")
	}
	if dialEventually(addr, 300*time.Millisecond) {
		t.Fatalf("--graphql=false left something listening on %s", addr)
	}
}

func TestGraphqlFlagOmittedKeepsLegacyStart(t *testing.T) {
	addr := freeLoopbackAddr(t)
	t.Setenv("QAU_GRAPHQL_ADDR", addr)

	n := &Node{config: &Config{}}
	n.startGraphQLServer()
	if n.graphqlServer == nil {
		t.Fatal("omitting --graphql must keep the legacy behavior (GraphQL enabled)")
	}
	defer stopGraphQLServer(t, n)

	if !dialEventually(addr, 2*time.Second) {
		t.Fatalf("GraphQL server was created but never accepted connections on %s", addr)
	}
}

func TestGraphqlFlagExplicitTrueStartsServer(t *testing.T) {
	addr := freeLoopbackAddr(t)
	t.Setenv("QAU_GRAPHQL_ADDR", addr)

	n := &Node{config: &Config{GraphqlExplicit: true, GraphqlEnabled: true}}
	n.startGraphQLServer()
	if n.graphqlServer == nil {
		t.Fatal("--graphql=true must start the GraphQL server")
	}
	defer stopGraphQLServer(t, n)

	if !dialEventually(addr, 2*time.Second) {
		t.Fatalf("GraphQL server did not accept connections on %s", addr)
	}
}

func TestGraphqlEnvOffStillDisables(t *testing.T) {
	t.Setenv("QAU_GRAPHQL_ADDR", "off")

	n := &Node{config: &Config{GraphqlExplicit: true, GraphqlEnabled: true}}
	n.startGraphQLServer()
	if n.graphqlServer != nil {
		stopGraphQLServer(t, n)
		t.Fatal("QAU_GRAPHQL_ADDR=off must still disable the GraphQL server (backwards compatibility)")
	}
}
