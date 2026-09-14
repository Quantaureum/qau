// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRPC_R13_H01_RejectsCompressedRequestBody verifies that the HTTP handler
// refuses any non-identity Content-Encoding. Previously the server silently
// passed the body to the JSON parser; if a future middleware were to
// decompress, a small gzip stream could expand to gigabytes and OOM the node.
func TestRPC_R13_H01_RejectsCompressedRequestBody(t *testing.T) {
	srv := NewServer(DefaultConfig())

	cases := []struct {
		name        string
		encoding    string
		wantStatus  int
		shouldAllow bool
	}{
		{"missing header (default identity)", "", 0, true},
		{"explicit identity", "identity", 0, true},
		{"gzip rejected", "gzip", http.StatusUnsupportedMediaType, false},
		{"deflate rejected", "deflate", http.StatusUnsupportedMediaType, false},
		{"br rejected", "br", http.StatusUnsupportedMediaType, false},
		{"zstd rejected", "zstd", http.StatusUnsupportedMediaType, false},
		{"case insensitive gzip", "GZIP", http.StatusUnsupportedMediaType, false},
		{"whitespace padded identity", "  identity  ", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","method":"net_version","id":1}`
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}

			rec := httptest.NewRecorder()
			srv.handleHTTP(rec, req)

			if tc.shouldAllow {
				if rec.Code == http.StatusUnsupportedMediaType {
					t.Fatalf("expected handler to accept Content-Encoding=%q (got 415)", tc.encoding)
				}
			} else {
				if rec.Code != tc.wantStatus {
					t.Fatalf("expected status %d for Content-Encoding=%q, got %d (body=%q)",
						tc.wantStatus, tc.encoding, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

// TestRPC_R13_H02_LimitListenerBoundsConnections verifies the limitListener
// enforces a hard cap on simultaneous connections. We configure an extremely
// small limit (2) so the third concurrent connection blocks until the first
// is closed.
func TestRPC_R13_H02_LimitListenerBoundsConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	limited := newLimitListener(ln, 2)

	// Dial two connections — these occupy both slots.
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer c1.Close()
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer c2.Close()

	ac1, err := limited.Accept()
	if err != nil {
		t.Fatalf("accept 1: %v", err)
	}
	defer ac1.Close()
	ac2, err := limited.Accept()
	if err != nil {
		t.Fatalf("accept 2: %v", err)
	}
	defer ac2.Close()

	// Dial a third connection. The underlying TCP listener has accepted
	// it, but limited.Accept() must block because the semaphore is full.
	c3, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 3: %v", err)
	}
	defer c3.Close()

	acceptErr := make(chan error, 1)
	go func() {
		_, err := limited.Accept()
		acceptErr <- err
	}()

	select {
	case err := <-acceptErr:
		t.Fatalf("limitListener accepted a 3rd connection before a slot was released: %v", err)
	case <-time.After(150 * time.Millisecond):
		// expected: still blocked
	}

	// Close connection #1 — this releases one slot. The blocked Accept
	// should now succeed.
	if err := ac1.Close(); err != nil {
		t.Fatalf("close ac1: %v", err)
	}

	select {
	case err := <-acceptErr:
		if err != nil {
			t.Fatalf("expected Accept to succeed after slot freed, got err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("limitListener did not unblock after a slot was released")
	}
}

// TestRPC_R13_H02_LimitListenerReleasesOnConnClose verifies that closing a
// wrapped connection frees its semaphore slot so subsequent connections are
// accepted (regression test for the limitListenerConn.Close path).
func TestRPC_R13_H02_LimitListenerReleasesOnConnClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	limited := newLimitListener(ln, 1)

	// Acquire the single slot.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer c.Close()

	ac, err := limited.Accept()
	if err != nil {
		t.Fatalf("accept 1: %v", err)
	}

	// Closing the wrapped conn must release the slot.
	if err := ac.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The next dial+accept pair should succeed immediately.
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer c2.Close()

	done := make(chan error, 1)
	go func() {
		_, err := limited.Accept()
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second accept failed after slot release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("slot was not released after wrapped conn Close")
	}
}

// TestRPC_R13_H02_NewLimitListenerZeroOrNegativeReturnsRaw verifies the
// defensive fallback: a non-positive limit returns the raw listener rather
// than deadlocking.
func TestRPC_R13_H02_NewLimitListenerZeroOrNegativeReturnsRaw(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	if got := newLimitListener(ln, 0); got != ln {
		t.Errorf("newLimitListener(n=0) should return raw listener, got %T", got)
	}
	if got := newLimitListener(ln, -1); got != ln {
		t.Errorf("newLimitListener(n=-1) should return raw listener, got %T", got)
	}
}

// TestRPC_R14_CRIT_003_CloseWakesBlockedAccept verifies the deadlock fix:
// when all semaphore slots are occupied (Accept is blocked waiting for a
// slot), calling Close() must unblock Accept so the server can shut down
// gracefully. Before the fix, Close() only closed the underlying listener
// and could NOT interrupt the blocked Accept — the server hung forever.
func TestRPC_R14_CRIT_003_CloseWakesBlockedAccept(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	limited := newLimitListener(ln, 1).(*limitListener)

	// Dial + accept the single slot.
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer c1.Close()
	ac1, err := limited.Accept()
	if err != nil {
		t.Fatalf("accept 1: %v", err)
	}
	defer ac1.Close()

	// Start a second Accept in a goroutine. It must block because the
	// slot is held by ac1.
	acceptDone := make(chan error, 1)
	go func() {
		_, err := limited.Accept()
		acceptDone <- err
	}()

	// Confirm it is actually blocked.
	select {
	case err := <-acceptDone:
		t.Fatalf("Accept returned before Close: %v (expected to block)", err)
	case <-time.After(150 * time.Millisecond):
		// expected: still blocked
	}

	// Close the listener — this must wake up the blocked Accept.
	if err := limited.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-acceptDone:
		if err == nil {
			t.Fatal("expected Accept to return error after Close, got nil")
		}
		// Expected: either the limitListener-closed sentinel or the
		// underlying listener's "use of closed network connection".
	case <-time.After(2 * time.Second):
		t.Fatal("RPC-R14-CRIT-003 REGRESSION: Close did not wake blocked Accept (deadlock)")
	}
}
