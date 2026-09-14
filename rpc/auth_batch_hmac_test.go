// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// computeBatchHMACSig replicates the HMAC computation in
// verifyBatchHMACWithNonce for testing. The format MUST match:
//
//	mac = HMAC(secret, "BATCHv1" || numMethods(4) || for each: len(4) || method || apiKeyHash || timestamp || nonce || SHA256(body))
//
// R33 RPC-01 FIX (2026-07-28): apiKeyHash is now included to bind the
// signature to the API key identity.
func computeBatchHMACSig(secret []byte, methods []string, apiKeyHash, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("BATCHv1"))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(methods)))
	mac.Write(lenBuf[:])
	for _, m := range methods {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(m)))
		mac.Write(lenBuf[:])
		mac.Write([]byte(m))
	}
	mac.Write([]byte(apiKeyHash))
	mac.Write([]byte(timestamp))
	mac.Write([]byte(nonce))
	bodyHash := sha256.Sum256(body)
	mac.Write(bodyHash[:])
	return hex.EncodeToString(mac.Sum(nil))
}

// computeSingleHMACSig replicates the single-request HMAC in
// verifyHMACWithNonce for cross-format incompatibility testing.
// R33 RPC-01 FIX: apiKeyHash is now included in the computation.
func computeSingleHMACSig(secret []byte, method, apiKeyHash, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(method))
	mac.Write([]byte(apiKeyHash))
	mac.Write([]byte(timestamp))
	mac.Write([]byte(nonce))
	bodyHash := sha256.Sum256(body)
	mac.Write(bodyHash[:])
	return hex.EncodeToString(mac.Sum(nil))
}

// newBatchTestAuthManager builds an AuthManager configured for HMAC testing.
// IMPORTANT: memguard.NewEnclave wipes the caller's secret slice as a
// defense-in-depth measure, so any test that wants to re-compute the HMAC
// locally MUST keep its own copy. We return testSecret (independent of the
// wiped slice passed to SetHMACSecret) so computeBatchHMACSig can sign
// with the same bytes that verifyBatchHMACWithNonce will use.
func newBatchTestAuthManager(t *testing.T) (*AuthManager, []byte, string) {
	t.Helper()
	cfg := &AuthConfig{
		Enabled:       true,
		EnableHMAC:    true,
		APIKeys:       make(map[string]*APIKeyInfo),
		PublicMethods: []string{"eth_chainId", "eth_blockNumber"},
		APIKeyHeader:  "X-API-Key",
	}
	secret := []byte("test-batch-hmac-secret-32-bytes!!")
	// Keep an independent copy: SetHMACSecret → memguard.NewEnclave wipes
	// the original slice to prevent the raw key from lingering in Go-managed
	// memory. Tests that re-compute HMACs need their own pristine copy.
	testSecret := make([]byte, len(secret))
	copy(testSecret, secret)
	cfg.SetHMACSecret(secret)
	am := NewAuthManager(cfg)
	info, err := am.GenerateAPIKey("batch-test", []string{"*"}, 0)
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}
	return am, testSecret, info.Key
}

func TestValidateBatchRequest_CoversAllMethodNames(t *testing.T) {
	am, secret, apiKey := newBatchTestAuthManager(t)
	defer am.Stop()

	methods := []string{"admin_nodeInfo", "admin_peers", "qau_qposStatus"}
	body := []byte(`[{"jsonrpc":"2.0","method":"admin_nodeInfo","id":1},{"jsonrpc":"2.0","method":"admin_peers","id":2},{"jsonrpc":"2.0","method":"qau_qposStatus","id":3}]`)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "batch-nonce-1"

	sig := computeBatchHMACSig(secret, methods, hashAPIKey(apiKey), timestamp, nonce, body)

	r := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	r.Header.Set("X-API-Key", apiKey)
	r.Header.Set("X-Signature", sig)
	r.Header.Set("X-Timestamp", timestamp)
	r.Header.Set("X-Nonce", nonce)

	if err := am.ValidateBatchRequest(r, methods); err != nil {
		t.Fatalf("ValidateBatchRequest with correct HMAC failed: %v", err)
	}
}

func TestValidateBatchRequest_MethodSubstitutionFails(t *testing.T) {
	am, secret, apiKey := newBatchTestAuthManager(t)
	defer am.Stop()

	// Original batch: admin_nodeInfo + admin_peers
	originalMethods := []string{"admin_nodeInfo", "admin_peers"}
	body := []byte(`[{"jsonrpc":"2.0","method":"admin_nodeInfo","id":1},{"jsonrpc":"2.0","method":"admin_peers","id":2}]`)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "batch-nonce-2"

	// Compute HMAC over original methods
	sig := computeBatchHMACSig(secret, originalMethods, hashAPIKey(apiKey), timestamp, nonce, body)

	// Attacker swaps admin_peers → admin_stopNode (passes per-method
	// authorization since the API key has wildcard "*", but HMAC should
	// fail because method names changed).
	swappedMethods := []string{"admin_nodeInfo", "admin_stopNode"}

	r := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	r.Header.Set("X-API-Key", apiKey)
	r.Header.Set("X-Signature", sig)
	r.Header.Set("X-Timestamp", timestamp)
	r.Header.Set("X-Nonce", nonce)

	err := am.ValidateBatchRequest(r, swappedMethods)
	if err == nil {
		t.Fatal("ValidateBatchRequest should fail when method names are swapped")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("expected 'invalid signature' error, got: %v", err)
	}
}

func TestValidateBatchRequest_SingleRequestHMACIncompatible(t *testing.T) {
	am, secret, apiKey := newBatchTestAuthManager(t)
	defer am.Stop()

	// A single-request HMAC (computed with verifyHMACWithNonce format)
	// must NOT validate as a batch HMAC, and vice versa.
	methods := []string{"admin_nodeInfo"}
	body := []byte(`[{"jsonrpc":"2.0","method":"admin_nodeInfo","id":1}]`)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "batch-nonce-3"

	// Compute single-request HMAC (uses raw method, no BATCHv1 prefix)
	singleSig := computeSingleHMACSig(secret, "admin_nodeInfo", hashAPIKey(apiKey), timestamp, nonce, body)

	r := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	r.Header.Set("X-API-Key", apiKey)
	r.Header.Set("X-Signature", singleSig)
	r.Header.Set("X-Timestamp", timestamp)
	r.Header.Set("X-Nonce", nonce)

	// Should fail — batch HMAC has "BATCHv1" prefix that single-request lacks.
	err := am.ValidateBatchRequest(r, methods)
	if err == nil {
		t.Fatal("single-request HMAC should not validate as batch HMAC")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("expected 'invalid signature' error, got: %v", err)
	}
}

func TestValidateBatchRequest_EmptyMethodsNoop(t *testing.T) {
	am, _, _ := newBatchTestAuthManager(t)
	defer am.Stop()

	// Empty methods list should be a no-op (all methods public).
	r := httptest.NewRequest("POST", "/", nil)
	if err := am.ValidateBatchRequest(r, nil); err != nil {
		t.Errorf("ValidateBatchRequest with empty methods should be no-op, got: %v", err)
	}
}

func TestValidateBatchRequest_ReplayFails(t *testing.T) {
	am, secret, apiKey := newBatchTestAuthManager(t)
	defer am.Stop()

	methods := []string{"admin_nodeInfo"}
	body := []byte(`[{"jsonrpc":"2.0","method":"admin_nodeInfo","id":1}]`)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "batch-nonce-replay"

	sig := computeBatchHMACSig(secret, methods, hashAPIKey(apiKey), timestamp, nonce, body)

	// First call — should succeed.
	r1 := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	r1.Header.Set("X-API-Key", apiKey)
	r1.Header.Set("X-Signature", sig)
	r1.Header.Set("X-Timestamp", timestamp)
	r1.Header.Set("X-Nonce", nonce)
	if err := am.ValidateBatchRequest(r1, methods); err != nil {
		t.Fatalf("first ValidateBatchRequest should succeed, got: %v", err)
	}

	// Second call with same nonce — should fail (replay detected).
	r2 := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	r2.Header.Set("X-API-Key", apiKey)
	r2.Header.Set("X-Signature", sig)
	r2.Header.Set("X-Timestamp", timestamp)
	r2.Header.Set("X-Nonce", nonce)
	err := am.ValidateBatchRequest(r2, methods)
	if err == nil {
		t.Fatal("replay with same nonce should fail")
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Errorf("expected replay error, got: %v", err)
	}
}

func TestValidateBatchRequest_PermissionCheck(t *testing.T) {
	// API key authorized only for "eth_*" should NOT be able to call
	// "admin_*" methods even with a valid batch HMAC.
	cfg := &AuthConfig{
		Enabled:       true,
		EnableHMAC:    true,
		APIKeys:       make(map[string]*APIKeyInfo),
		PublicMethods: []string{"eth_chainId"},
		APIKeyHeader:  "X-API-Key",
	}
	secret := []byte("test-batch-perm-secret-32-bytes!")
	// SetHMACSecret wipes the caller's slice via memguard; keep a pristine copy
	// so the test can independently re-compute the HMAC for assertion.
	testSecret := make([]byte, len(secret))
	copy(testSecret, secret)
	cfg.SetHMACSecret(secret)
	am := NewAuthManager(cfg)
	defer am.Stop()

	info, err := am.GenerateAPIKey("perm-test", []string{"eth_*"}, 0)
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}

	// Batch contains an admin method the key is not authorized for.
	methods := []string{"eth_blockNumber", "admin_nodeInfo"}
	body := []byte(`[{"jsonrpc":"2.0","method":"eth_blockNumber","id":1},{"jsonrpc":"2.0","method":"admin_nodeInfo","id":2}]`)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "batch-perm-1"
	sig := computeBatchHMACSig(testSecret, methods, hashAPIKey(info.Key), timestamp, nonce, body)

	r := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	r.Header.Set("X-API-Key", info.Key)
	r.Header.Set("X-Signature", sig)
	r.Header.Set("X-Timestamp", timestamp)
	r.Header.Set("X-Nonce", nonce)

	err = am.ValidateBatchRequest(r, methods)
	if err == nil {
		t.Fatal("ValidateBatchRequest should fail: API key not authorized for admin_*")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("expected 'method not allowed' error, got: %v", err)
	}
}

// TestValidateBatchRequest_BodyReadOnce ensures the request body is
// consumed exactly once and restored for downstream readers (so the
// JSON-RPC handler can still parse it after auth).
func TestValidateBatchRequest_BodyReadOnce(t *testing.T) {
	am, secret, apiKey := newBatchTestAuthManager(t)
	defer am.Stop()

	methods := []string{"admin_nodeInfo"}
	body := []byte(`[{"jsonrpc":"2.0","method":"admin_nodeInfo","id":1}]`)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "batch-body-1"
	sig := computeBatchHMACSig(secret, methods, hashAPIKey(apiKey), timestamp, nonce, body)

	r := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	r.Header.Set("X-API-Key", apiKey)
	r.Header.Set("X-Signature", sig)
	r.Header.Set("X-Timestamp", timestamp)
	r.Header.Set("X-Nonce", nonce)

	if err := am.ValidateBatchRequest(r, methods); err != nil {
		t.Fatalf("ValidateBatchRequest failed: %v", err)
	}

	// Body should be readable downstream (restored by NopCloser+NewBuffer).
	downstream, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("downstream body read failed: %v", err)
	}
	if string(downstream) != string(body) {
		t.Errorf("body mismatch: got %q, want %q", downstream, body)
	}
}

// Suppress unused import warning for net/http (used implicitly via httptest).
var _ = http.Header{}
