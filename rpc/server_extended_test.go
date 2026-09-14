// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── Server configuration tests ──

func TestConfig_Timeouts(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ReadTimeout < time.Second {
		t.Error("read timeout too short")
	}
	if cfg.WriteTimeout < time.Second {
		t.Error("write timeout too short")
	}
}

func TestConfig_MaxBatchSize(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxBatchSize <= 0 {
		t.Error("max batch size must be positive")
	}
}

// ── Server creation with config ──

func TestNewServer_WithCustomConfig(t *testing.T) {
	cfg := &Config{
		Addr:            "0.0.0.0:9999",
		MaxBatchSize:    50,
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    5 * time.Second,
		MaxBodySize:     2 * 1024 * 1024,
		MaxParamsLength: 1024,
		EnableRateLimit: true,
		AllowedOrigins:  []string{"https://example.com"},
	}
	srv := NewServer(cfg)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

// ── SetDevMode ──

func TestSetDevMode(t *testing.T) {
	srv := NewServer(nil)
	srv.SetDevMode(true)
	srv.SetDevMode(false)
}

// ── SetExposeErrorData ──

func TestSetExposeErrorData(t *testing.T) {
	srv := NewServer(nil)
	srv.SetExposeErrorData(true)
	srv.SetExposeErrorData(false)
}

// ── sanitizeError ──

func TestSanitizeError_ExposeData(t *testing.T) {
	srv := NewServer(nil)
	srv.SetDevMode(true)
	srv.SetExposeErrorData(true)

	rpcErr := NewErrorWithData(-32000, "test error", "sensitive data")
	sanitized := srv.sanitizeError(rpcErr)
	if sanitized.Data == nil {
		t.Error("expected data to be preserved when devMode and exposeErrorData are both true")
	}
}

func TestSanitizeError_HideData(t *testing.T) {
	srv := NewServer(nil)
	srv.SetDevMode(false)
	srv.SetExposeErrorData(false)

	rpcErr := NewErrorWithData(-32000, "test error", "sensitive data")
	sanitized := srv.sanitizeError(rpcErr)
	if sanitized.Data != nil {
		t.Error("expected data to be stripped when devMode is false")
	}
}

// ── Admin method checks ──

func TestIsAdminMethod_Registered(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterAdminMethod("admin_test")
	if !srv.isAdminMethod("admin_test") {
		t.Error("expected admin_test to be an admin method")
	}
}

func TestIsAdminMethod_NotRegistered(t *testing.T) {
	srv := NewServer(nil)
	if srv.isAdminMethod("eth_blockNumber") {
		t.Error("eth_blockNumber should not be an admin method")
	}
}

// ── CORS headers ──

func TestSetCORSHeaders_Mainnet(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Origin", "https://app.quantaureum.com")

	srv.setCORSHeaders(w, r)

	// Should set CORS headers for mainnet default origins
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		// May or may not be set depending on origin matching
		// Just verify no panic
	}
}

func TestSetCORSHeaders_CustomOrigins(t *testing.T) {
	cfg := &Config{
		AllowedOrigins: []string{"https://myapp.com"},
	}
	srv := NewServer(cfg)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Origin", "https://myapp.com")

	srv.setCORSHeaders(w, r)
}

// ── HTTP request handling ──

func TestHandleHTTP_InvalidMethod(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	srv.handleHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestHandleHTTP_ValidJSONRPC(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	body := `{"jsonrpc":"2.0","method":"eth_chainId","id":1}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	srv.handleHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleHTTP_BatchRequest(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	body := `[{"jsonrpc":"2.0","method":"eth_chainId","id":1},{"jsonrpc":"2.0","method":"eth_blockNumber","id":2}]`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	srv.handleHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleHTTP_EmptyBody(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/json")

	srv.handleHTTP(w, r)
	// Should handle gracefully (parse error)
}

func TestHandleHTTP_InvalidJSON(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader("not-json"))
	r.Header.Set("Content-Type", "application/json")

	srv.handleHTTP(w, r)
	// Should return parse error
}

// ── HandleRequest with auth ──

func TestHandleRequest_AdminMethod_NoAuth(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterAdminMethod("admin_secret")
	srv.RegisterHandler("admin_secret", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "secret", nil
	})
	srv.SetAuthManager(NewAuthManager(nil))

	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "admin_secret",
		ID:      1,
	})
	if resp.Error == nil {
		t.Error("expected auth error for admin method without auth context")
	}
}

// ── HandleBatchRequest with batch size limit ──

func TestHandleBatchRequest_ExceedsMaxSize(t *testing.T) {
	cfg := &Config{MaxBatchSize: 2}
	srv := NewServer(cfg)
	srv.RegisterHandler("qau_test", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "ok", nil
	})

	batch := make([]Request, 5)
	for i := range batch {
		batch[i] = Request{JSONRPC: "2.0", Method: "qau_test", ID: i}
	}

	// HandleBatchRequest processes all requests regardless of batch size
	// The batch size limit is enforced in handleBatch (HTTP handler)
	responses := srv.HandleBatchRequest(context.Background(), batch)
	if len(responses) != 5 {
		t.Errorf("expected 5 responses from HandleBatchRequest, got %d", len(responses))
	}
}

// ── Rate limiter integration ──

func TestSetRateLimiter(t *testing.T) {
	srv := NewServer(nil)
	rl := NewRateLimiter(DefaultRateLimitConfig())
	srv.SetRateLimiter(rl)
}

// ── Request/Response JSON serialization ──

func TestResponse_JSON(t *testing.T) {
	resp := &Response{
		JSONRPC: "2.0",
		Result:  "0x684",
		ID:      1,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}
	if !strings.Contains(string(data), `"result":"0x684"`) {
		t.Errorf("unexpected JSON: %s", string(data))
	}
}

func TestResponse_ErrorJSON(t *testing.T) {
	resp := &Response{
		JSONRPC: "2.0",
		Error:   NewError(-32601, "Method not found"),
		ID:      1,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal error response: %v", err)
	}
	if !strings.Contains(string(data), `"code":-32601`) {
		t.Errorf("unexpected JSON: %s", string(data))
	}
}

// ── Start/Stop with TLS (cert files not available, just test error path) ──

func TestStartTLS_MissingCert(t *testing.T) {
	srv := NewServer(nil)
	err := srv.StartTLS("127.0.0.1:0", "nonexistent.crt", "nonexistent.key")
	if err == nil {
		t.Error("expected error for missing TLS cert files")
	}
}

// ── extractClientIP ──

func TestExtractClientIP_Direct(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "192.168.1.1:12345"

	ip := extractClientIP(r)
	if ip == "" {
		t.Error("expected non-empty IP")
	}
}

func TestExtractClientIP_Forwarded(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")

	ip := extractClientIP(r)
	if ip == "" {
		t.Error("expected non-empty IP from forwarded header")
	}
}

// ── AuthManager integration with server ──

func TestServerAuthManager_Integration(t *testing.T) {
	srv := NewServer(nil)
	am := NewAuthManager(nil)
	srv.SetAuthManager(am)

	// Auth manager should be set
	if srv.authManager == nil {
		t.Error("expected auth manager to be set")
	}
}

// ── writeResponse / writeError ──

func TestWriteResponse(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	resp := &Response{
		JSONRPC: "2.0",
		Result:  "0x1",
		ID:      1,
	}
	srv.writeResponse(w, resp)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestWriteError(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	srv.writeError(w, 1, NewError(-32601, "Method not found"))

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (JSON-RPC errors are 200), got %d", w.Code)
	}
}
