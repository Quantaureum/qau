// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultAuthConfig(t *testing.T) {
	cfg := DefaultAuthConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if !cfg.EnableHMAC {
		t.Error("HMAC should be enabled by default")
	}
	if len(cfg.PublicMethods) == 0 {
		t.Error("expected some public methods in default config")
	}
}

func TestNewAuthManager_NilConfig(t *testing.T) {
	am := NewAuthManager(nil)
	if am == nil {
		t.Fatal("expected non-nil auth manager")
	}
	defer am.Stop()
}

func TestNewAuthManager_WithConfig(t *testing.T) {
	cfg := &AuthConfig{
		Enabled:       true,
		APIKeys:       make(map[string]*APIKeyInfo),
		EnableHMAC:    true,
		PublicMethods: []string{"eth_chainId", "eth_blockNumber"},
	}
	am := NewAuthManager(cfg)
	if am == nil {
		t.Fatal("expected non-nil auth manager")
	}
	defer am.Stop()
}

// ── GenerateAPIKey tests ──

func TestGenerateAPIKey(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	info, err := am.GenerateAPIKey("test-key", []string{"read"}, 0)
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}
	if info.Key == "" {
		t.Error("expected non-empty key")
	}
	if info.KeyHash == "" {
		t.Error("expected non-empty key hash")
	}
	if info.Name != "test-key" {
		t.Errorf("expected name 'test-key', got '%s'", info.Name)
	}
}

func TestGenerateAPIKey_WithExpiry(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	info, err := am.GenerateAPIKey("expiring-key", []string{"read"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateAPIKey with expiry failed: %v", err)
	}
	if info.ExpiresAt.IsZero() {
		t.Error("expected non-zero expiry time")
	}
}

// ── AddAPIKey / RemoveAPIKey tests ──

func TestAddAPIKey(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	info := &APIKeyInfo{
		Key:         "test-key-123",
		Name:        "added-key",
		Permissions: []string{"read"},
		CreatedAt:   time.Now(),
	}
	am.AddAPIKey(info)

	// Should be retrievable
	keys := am.ListAPIKeys()
	if len(keys) == 0 {
		t.Error("expected at least one API key name")
	}
}

func TestRemoveAPIKey(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	info, _ := am.GenerateAPIKey("to-remove", []string{"read"}, 0)
	am.RemoveAPIKey(info.Key)

	// Key should be removed
	keys := am.ListAPIKeys()
	for _, name := range keys {
		if name == "to-remove" {
			t.Error("key should have been removed")
		}
	}
}

// ── ValidateRequest tests ──

func TestValidateRequest_AuthDisabled(t *testing.T) {
	cfg := &AuthConfig{Enabled: false}
	am := NewAuthManager(cfg)
	defer am.Stop()

	r := httptest.NewRequest("POST", "/", nil)
	err := am.ValidateRequest(r, "eth_chainId")
	if err != nil {
		t.Errorf("expected no error when auth disabled, got: %v", err)
	}
}

func TestValidateRequest_PublicMethod(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	am := NewAuthManager(cfg)
	defer am.Stop()

	r := httptest.NewRequest("POST", "/", nil)
	// Public methods should be accessible without API key
	err := am.ValidateRequest(r, "eth_chainId")
	if err != nil {
		t.Errorf("expected public method to be accessible, got: %v", err)
	}
}

func TestValidateRequest_NonPublicMethod_NoKey(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	cfg.APIKeys = make(map[string]*APIKeyInfo)
	am := NewAuthManager(cfg)
	defer am.Stop()

	r := httptest.NewRequest("POST", "/", nil)
	err := am.ValidateRequest(r, "admin_nodeInfo")
	if err == nil {
		t.Error("expected error for non-public method without API key")
	}
}

func TestValidateRequest_WithAPIKey(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	cfg.EnableHMAC = false // Disable HMAC for simple test
	cfg.APIKeys = make(map[string]*APIKeyInfo)
	cfg.APIKeyHeader = "X-API-Key"
	am := NewAuthManager(cfg)
	defer am.Stop()

	// Generate key with wildcard permission to access any method
	info, _ := am.GenerateAPIKey("test", []string{"*"}, 0)

	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("X-API-Key", info.Key)
	err := am.ValidateRequest(r, "admin_nodeInfo")
	if err != nil {
		t.Errorf("expected valid API key to work, got: %v", err)
	}
}

// ── SetEnabled / IsEnabled tests ──

func TestSetEnabled(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	am.SetEnabled(false)
	if am.IsEnabled() {
		t.Error("expected auth to be disabled")
	}

	am.SetEnabled(true)
	if !am.IsEnabled() {
		t.Error("expected auth to be enabled")
	}
}

// ── GetAPIKeyInfo tests ──

func TestGetAPIKeyInfo(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	info, _ := am.GenerateAPIKey("test", []string{"read"}, 0)
	retrieved := am.GetAPIKeyInfo(info.Key)
	if retrieved == nil {
		t.Error("expected to retrieve API key info")
	}
	if retrieved.Name != "test" {
		t.Errorf("expected name 'test', got '%s'", retrieved.Name)
	}
}

func TestGetAPIKeyInfo_NotFound(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	retrieved := am.GetAPIKeyInfo("nonexistent-key")
	if retrieved != nil {
		t.Error("expected nil for nonexistent key")
	}
}

// ── ListAPIKeys tests ──

func TestListAPIKeys(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	am.GenerateAPIKey("key1", []string{"read"}, 0)
	am.GenerateAPIKey("key2", []string{"write"}, 0)

	keys := am.ListAPIKeys()
	if len(keys) < 2 {
		t.Errorf("expected at least 2 key names, got %d", len(keys))
	}
}

// ── APIKeyInfo fields ──

func TestAPIKeyInfo_Fields(t *testing.T) {
	info := &APIKeyInfo{
		Key:         "test-key",
		KeyHash:     "test-hash",
		Name:        "test",
		Permissions: []string{"read", "write"},
		CreatedAt:   time.Now(),
	}
	if info.Key != "test-key" {
		t.Error("unexpected key value")
	}
	if len(info.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(info.Permissions))
	}
}

// ── Auth with HMAC ──

func TestValidateRequest_HMACEnabled(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	cfg.EnableHMAC = true
	cfg.APIKeys = make(map[string]*APIKeyInfo)
	am := NewAuthManager(cfg)
	defer am.Stop()

	r := httptest.NewRequest("POST", "/", nil)
	// Without HMAC headers, should still work for public methods
	err := am.ValidateRequest(r, "eth_chainId")
	if err != nil {
		t.Errorf("public method should work without HMAC, got: %v", err)
	}
}

// ── IP Whitelist ──

func TestValidateRequest_IPWhitelist(t *testing.T) {
	cfg := &AuthConfig{
		Enabled:           true,
		EnableHMAC:        false,
		APIKeys:           make(map[string]*APIKeyInfo),
		GlobalIPWhitelist: []string{"192.168.1.0/24"},
		PublicMethods:     []string{"eth_chainId"},
		APIKeyHeader:      "X-API-Key",
	}
	am := NewAuthManager(cfg)
	defer am.Stop()

	// Generate key with wildcard permission
	info, _ := am.GenerateAPIKey("test", []string{"*"}, 0)

	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "192.168.1.100:12345"
	r.Header.Set("X-API-Key", info.Key)

	// IP in whitelist + valid API key should be allowed
	err := am.ValidateRequest(r, "admin_nodeInfo")
	if err != nil {
		t.Errorf("IP in whitelist with valid key should be allowed, got: %v", err)
	}
}

// ── Rate limiting per API key ──

func TestAPIKeyRateLimiting(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	cfg.EnableHMAC = false // Disable HMAC for simple test
	cfg.APIKeys = make(map[string]*APIKeyInfo)
	cfg.APIKeyHeader = "X-API-Key"
	am := NewAuthManager(cfg)
	defer am.Stop()

	info := &APIKeyInfo{
		Key:         "rate-limited-key",
		Name:        "limited",
		Permissions: []string{"*"},
		RateLimit:   100, // 100 requests per second
		CreatedAt:   time.Now(),
	}
	am.AddAPIKey(info)

	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("X-API-Key", "rate-limited-key")

	// First few requests should work
	for i := 0; i < 3; i++ {
		err := am.ValidateRequest(r, "admin_nodeInfo")
		if err != nil {
			t.Errorf("request %d should be allowed, got: %v", i, err)
		}
	}
}
