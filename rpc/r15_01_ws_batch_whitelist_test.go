// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// R15-01 regression (2026-10-27): the WebSocket batch path marked every
// request as "auth already verified" whenever an auth manager existed —
// `batchAuthCtx != nil` — but batch-level validation short-circuits on an
// empty method list. A batch containing ONLY public methods therefore skipped
// ValidateRequest entirely, including the GlobalIPWhitelist check. That is the
// WS-batch sibling of R14-03: an operator who configured GlobalIPWhitelist
// still served public methods over a WS batch to the whole internet, while the
// identical single-request path correctly rejected them.
//
// The tests drive ws.handleMessage with a fake connection whose RemoteAddr is
// off-allowlist, and assert on the bytes written back to the connection.

// r15FakeAddr is a net.Addr carrying a fixed "host:port" string.
type r15FakeAddr struct{ s string }

func (a r15FakeAddr) Network() string { return "tcp" }
func (a r15FakeAddr) String() string  { return a.s }

// r15MockConn is a minimal net.Conn with a controlled RemoteAddr that records
// everything written to it.
type r15MockConn struct {
	addr string
	mu   sync.Mutex
	buf  bytes.Buffer
}

func (m *r15MockConn) Read(b []byte) (int, error) { return 0, nil }
func (m *r15MockConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.Write(b)
}
func (m *r15MockConn) Close() error                     { return nil }
func (m *r15MockConn) LocalAddr() net.Addr              { return r15FakeAddr{"127.0.0.1:0"} }
func (m *r15MockConn) RemoteAddr() net.Addr             { return r15FakeAddr{m.addr} }
func (m *r15MockConn) SetDeadline(time.Time) error      { return nil }
func (m *r15MockConn) SetReadDeadline(time.Time) error  { return nil }
func (m *r15MockConn) SetWriteDeadline(time.Time) error { return nil }
func (m *r15MockConn) written() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.String()
}

func newR15WSConn(addr string) (*WSConn, *r15MockConn) {
	c := &r15MockConn{addr: addr}
	conn := &WSConn{
		conn:    c,
		reader:  bufio.NewReader(c),
		header:  http.Header{},
		pongSem: make(chan struct{}, 1),
	}
	return conn, c
}

func newR15AuthedFixture(t *testing.T) (*WebSocketServer, func()) {
	t.Helper()
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	cfg.GlobalIPWhitelist = []string{"10.0.0.0/8"}
	am := NewAuthManager(cfg)

	srv := NewServer(nil)
	srv.authManager = am

	ws := NewWebSocketServer(srv)
	return ws, am.Stop
}

// An all-public batch from an off-allowlist IP must be rejected by the
// whitelist, not dispatched to method handlers.
func TestR15_01_WSBatchAllPublicRespectsWhitelist(t *testing.T) {
	ws, stop := newR15AuthedFixture(t)
	defer stop()

	conn, mock := newR15WSConn("203.0.113.9:12345")
	ws.handleMessage(conn, []byte(`[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber"}]`))

	out := mock.written()
	if out == "" {
		t.Fatal("batch produced no response at all — auth rejection missing")
	}
	if !strings.Contains(out, "IP address not allowed") {
		t.Fatalf("all-public batch from off-allowlist IP must be whitelist-rejected, got: %s", out)
	}
}

// Mixed batch: the non-public method fails batch-level auth (no API key), so
// the whole batch must be rejected before any dispatch.
func TestR15_01_WSBatchMixedStillGated(t *testing.T) {
	ws, stop := newR15AuthedFixture(t)
	defer stop()

	conn, mock := newR15WSConn("203.0.113.9:12345")
	ws.handleMessage(conn, []byte(`[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"admin_nodeInfo"}]`))

	out := mock.written()
	if !strings.Contains(out, "authentication required") && !strings.Contains(out, "IP address not allowed") {
		t.Fatalf("mixed batch with a non-public method from off-allowlist IP must be auth-rejected, got: %s", out)
	}
}

// Single public request from an off-allowlist IP must be rejected (R14-03
// path) — guards the batch fix against regressions in the shared gate.
func TestR15_01_WSSinglePublicRespectsWhitelist(t *testing.T) {
	ws, stop := newR15AuthedFixture(t)
	defer stop()

	conn, _ := newR15WSConn("203.0.113.9:12345")
	resp := ws.handleRequestInternal(conn, &Request{JSONRPC: "2.0", ID: 1, Method: "eth_chainId"}, false)
	if resp == nil || resp.Error == nil {
		t.Fatal("single public request from off-allowlist IP must be rejected")
	}
	if !strings.Contains(resp.Error.Message, "IP address not allowed") {
		t.Fatalf("expected IP-whitelist rejection, got: %v", resp.Error.Message)
	}
}

// On-allowlist caller: an all-public batch must reach method dispatch. The
// unregistered method yields method-not-found, NOT an IP rejection — proves
// the fix does not over-block allowlisted traffic.
func TestR15_01_WSBatchAllowlistedIPStillDispatches(t *testing.T) {
	ws, stop := newR15AuthedFixture(t)
	defer stop()

	conn, mock := newR15WSConn("10.1.2.3:12345")
	ws.handleMessage(conn, []byte(`[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}]`))

	out := mock.written()
	if strings.Contains(out, "IP address not allowed") {
		t.Fatalf("allowlisted IP must not be whitelist-rejected, got: %s", out)
	}
	if out == "" {
		t.Fatal("allowlisted batch produced no response")
	}
}
