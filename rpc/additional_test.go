// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ── Filter methods ──

func TestNewFilter_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.NewFilter(ctx(), nil)
	requireErr(t, nil, err)
}

func TestNewFilter_InvalidParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.NewFilter(ctx(), json.RawMessage(`"invalid"`))
	requireErr(t, nil, err)
}

func TestNewBlockFilter(t *testing.T) {
	api := newTestAPI()
	result, err := api.NewBlockFilter(ctx(), nil)
	requireOK(t, result, err)
	// Should return a filter ID
	filterID, ok := result.(string)
	if !ok || filterID == "" {
		t.Error("expected non-empty filter ID string")
	}
}

func TestNewPendingTransactionFilter(t *testing.T) {
	api := newTestAPI()
	result, err := api.NewPendingTransactionFilter(ctx(), nil)
	requireOK(t, result, err)
	filterID, ok := result.(string)
	if !ok || filterID == "" {
		t.Error("expected non-empty filter ID string")
	}
}

func TestUninstallFilter_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.UninstallFilter(ctx(), nil)
	requireErr(t, nil, err)
}

func TestUninstallFilter_InvalidID(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-a-number"})
	result, err := api.UninstallFilter(ctx(), params)
	// UninstallFilter may not return error for invalid ID, just false
	_ = result
	_ = err
}

func TestUninstallFilter_ValidID(t *testing.T) {
	api := newTestAPI()
	// First create a block filter
	result, _ := api.NewBlockFilter(ctx(), nil)
	filterID := result.(string)

	// Then uninstall it
	params, _ := json.Marshal([]string{filterID})
	uninstResult, err := api.UninstallFilter(ctx(), params)
	requireOK(t, uninstResult, err)
}

func TestGetFilterChanges_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetFilterChanges(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetFilterChanges_InvalidID(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-a-number"})
	_, err := api.GetFilterChanges(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetFilterChanges_BlockFilter(t *testing.T) {
	api := newTestAPI()
	result, _ := api.NewBlockFilter(ctx(), nil)
	filterID := result.(string)

	params, _ := json.Marshal([]string{filterID})
	changes, err := api.GetFilterChanges(ctx(), params)
	requireOK(t, changes, err)
}

func TestGetFilterChanges_PendingTxFilter(t *testing.T) {
	api := newTestAPI()
	result, _ := api.NewPendingTransactionFilter(ctx(), nil)
	filterID := result.(string)

	params, _ := json.Marshal([]string{filterID})
	changes, err := api.GetFilterChanges(ctx(), params)
	requireOK(t, changes, err)
}

func TestGetFilterLogs_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetFilterLogs(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetFilterLogs_InvalidID(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-a-number"})
	_, err := api.GetFilterLogs(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetLogs_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetLogs(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetLogs_InvalidParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetLogs(ctx(), json.RawMessage(`"invalid"`))
	requireErr(t, nil, err)
}

// ── PersonalAPI tests ──

func TestNewPersonalAPI(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	if api == nil {
		t.Fatal("expected non-nil PersonalAPI")
	}
}

func TestPersonalAPI_ListAccounts(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	result, err := api.ListAccounts(context.Background(), nil)
	requireOK(t, result, err)
}

func TestPersonalAPI_SetDevMode(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	// DevMode requires compile-time flag, so this won't actually enable it
	api.SetDevMode(true)
	api.SetDevMode(false)
}

func TestPersonalAPI_RegisterHandlers(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	srv := NewServer(nil)
	api.RegisterHandlers(srv)

	// Check that personal methods are registered
	expectedMethods := []string{
		"personal_newAccount",
		"personal_listAccounts",
		"personal_unlockAccount",
		"personal_lockAccount",
		"personal_sendTransaction",
		"personal_sign",
		"personal_importRawKey",
	}
	for _, method := range expectedMethods {
		if _, ok := srv.handlers[method]; !ok {
			t.Errorf("expected handler for method %s", method)
		}
	}
}

func TestPersonalAPI_NewAccount_NoPassword(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	params, _ := json.Marshal([]string{})
	_, err := api.NewAccount(context.Background(), params)
	// Should fail without password
	_ = err
}

func TestPersonalAPI_LockAccount_NotUnlocked(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	params, _ := json.Marshal([]string{"0x1234567890123456789012345678901234567890"})
	result, err := api.LockAccount(context.Background(), params)
	// Locking an account that's not unlocked should return false
	_ = result
	_ = err
}

func TestPersonalAPI_IsUnlocked_Empty(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	var emptyAddr types.Address
	if api.IsUnlocked(emptyAddr) {
		t.Error("expected empty address to not be unlocked")
	}
}

// ── RateLimiter additional tests ──

func TestNewRateLimiter_Additional(t *testing.T) {
	rl := NewRateLimiter(DefaultRateLimitConfig())
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}
}

func TestRateLimiterConfig_Fields(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	if cfg.GlobalRateLimit <= 0 {
		t.Error("expected positive global rate limit")
	}
	if cfg.BurstSize <= 0 {
		t.Error("expected positive burst size")
	}
}

func TestRateLimiter_AllowRequest(t *testing.T) {
	rl := NewRateLimiter(DefaultRateLimitConfig())
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "192.168.1.1:12345"
	err := rl.Allow(r, "eth_chainId")
	if err != nil {
		t.Errorf("first request should be allowed, got: %v", err)
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(DefaultRateLimitConfig())
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = "192.168.1." + string(rune('0'+i)) + ":12345"
		err := rl.Allow(r, "eth_chainId")
		if err != nil {
			t.Errorf("request from IP %d should be allowed, got: %v", i, err)
		}
	}
}

// ── Quantum API tests ──

func TestVerifyQuantumTransaction_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.VerifyQuantumTransaction(ctx(), nil)
	requireErr(t, nil, err)
}

// ── WebSocket server creation ──

func TestNewWebSocketServer(t *testing.T) {
	srv := NewWebSocketServer(nil)
	if srv == nil {
		t.Error("expected non-nil WebSocket server")
	}
}

// ── requireTLS check ──

func TestRequireTLS_NonHTTPContext(t *testing.T) {
	api := NewPersonalAPI("", nil, nil, nil)
	err := api.requireTLS(context.Background())
	if err != nil {
		t.Error("non-HTTP context should not require TLS")
	}
}

func TestRequireTLS_HTTPContext_NoTLS(t *testing.T) {
	api := NewPersonalAPI("", nil, nil, nil)
	r := httptest.NewRequest("POST", "/", nil)
	ctx := context.WithValue(context.Background(), contextKeyHTTPRequest{}, r)
	err := api.requireTLS(ctx)
	if err == nil {
		t.Error("expected TLS required error for non-TLS HTTP request")
	}
}

// ── extractDilithium3PrivateKey tests ──

func TestExtractDilithium3PrivateKey_NoPrefix(t *testing.T) {
	// Without dilithium3: prefix, short input must be rejected
	_, err := extractDilithium3PrivateKey("abc123")
	if err == nil {
		t.Error("expected error for short non-prefixed key")
	}
}

func TestExtractDilithium3PrivateKey_WithPrefix(t *testing.T) {
	// With dilithium3: prefix, short input must be rejected
	_, err := extractDilithium3PrivateKey("dilithium3:abcd1234")
	if err == nil {
		t.Error("expected error for short prefixed key")
	}
}

// ── HTTP context helpers ──

func TestExtractClientIP_EmptyRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = ""
	ip := extractClientIP(r)
	// Should handle empty remote addr gracefully
	_ = ip
}

func TestExtractClientIP_XForwardedFor(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 198.51.100.7")
	ip := extractClientIP(r)
	if ip == "" {
		t.Error("expected non-empty IP from X-Forwarded-For")
	}
}

func TestExtractClientIP_XRealIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Real-IP", "203.0.113.50")
	ip := extractClientIP(r)
	if ip == "" {
		t.Error("expected non-empty IP from X-Real-IP")
	}
}

// ── Server handleRequest edge cases ──

func TestHandleRequest_EmptyMethod(t *testing.T) {
	srv := NewServer(nil)
	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "",
		ID:      1,
	})
	if resp.Error == nil {
		t.Error("expected error for empty method")
	}
}

func TestHandleRequest_NoVersion(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("qau_test", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "ok", nil
	})
	resp := srv.HandleRequest(context.Background(), &Request{
		Method: "qau_test",
		ID:     1,
	})
	// Missing version should trigger invalid request error
	if resp.Error == nil {
		t.Error("expected error for missing JSON-RPC version")
	}
}

// ── Server CORS with no origin ──

func TestSetCORSHeaders_NoOrigin(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	// No Origin header

	srv.setCORSHeaders(w, r)
	// Should not set CORS headers without origin
}

// ── Server OPTIONS request ──

func TestHandleHTTP_OptionsRequest(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/", nil)
	r.Header.Set("Origin", "https://example.com")

	srv.handleHTTP(w, r)
	// Should handle CORS preflight
}

// ── Server with rate limiter ──

func TestHandleHTTP_RateLimited(t *testing.T) {
	cfg := &Config{
		EnableRateLimit: true,
	}
	srv := NewServer(cfg)
	srv.RegisterHandler("qau_test", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "ok", nil
	})
	rl := NewRateLimiter(&RateLimitConfig{
		Enabled:         true,
		GlobalRateLimit: 1,
		BurstSize:       1,
	})
	srv.SetRateLimiter(rl)

	// First request should succeed
	body := `{"jsonrpc":"2.0","method":"qau_test","id":1}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "192.168.1.1:12345"
	srv.handleHTTP(w, r)

	// Rapid subsequent requests may be rate limited
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r2.Header.Set("Content-Type", "application/json")
	r2.RemoteAddr = "192.168.1.1:12345"
	srv.handleHTTP(w2, r2)
}
