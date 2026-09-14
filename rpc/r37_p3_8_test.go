// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestR37_P3_8_SingleRequestPanicRecovered verifies the R37-P3-08 fix: a panic
// inside a handler invoked through the single-request HTTP path must be
// recovered (like the batch path already does), returning a JSON-RPC internal
// error response instead of killing the HTTP handler goroutine and leaving the
// client with a truncated/empty response.
func TestR37_P3_8_SingleRequestPanicRecovered(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("test_panic", func(_ context.Context, _ json.RawMessage) (any, *Error) {
		panic("boom: nil pointer dereference simulation")
	})

	body := `{"jsonrpc":"2.0","method":"test_panic","id":1}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	// Must not panic — handleHTTP should return normally.
	srv.handleHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after recovered panic, got %d", w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response body is not valid JSON-RPC (truncated response?): %v; body=%q", err, w.Body.String())
	}
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error response for panicking handler, got nil error")
	}
	if resp.Error.Code != ErrCodeInternal {
		t.Errorf("expected internal error code %d, got %d", ErrCodeInternal, resp.Error.Code)
	}
}

// TestR37_P3_8_SingleRequestNormalStillWorks guards against the recover
// wrapper breaking the normal single-request path.
func TestR37_P3_8_SingleRequestNormalStillWorks(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("test_ok", func(_ context.Context, _ json.RawMessage) (any, *Error) {
		return "fine", nil
	})

	body := `{"jsonrpc":"2.0","method":"test_ok","id":2}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	srv.handleHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	if resp.Result != "fine" {
		t.Errorf("expected result %q, got %v", "fine", resp.Result)
	}
}
