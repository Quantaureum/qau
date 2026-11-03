// Quantaureum Node source, version 1.0.0.
package rpc

// End-to-end tests for the admin key management RPC: generate (plaintext
// shown once) → list (plaintext-free) → extend → revoke. Also verifies the
// persistence hook fires on every mutation.

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestAdminKeyAPI(t *testing.T) (*AdminKeyAPI, *AuthManager, *atomic.Int64) {
	t.Helper()
	am := NewAuthManager(DefaultAuthConfig())
	var mutations atomic.Int64
	am.SetPersistenceHook(func() { mutations.Add(1) })
	return NewAdminKeyAPI(am), am, &mutations
}

func TestAdminKeyGenerateListExtendRevoke(t *testing.T) {
	api, am, mutations := newTestAdminKeyAPI(t)
	ctx := context.Background()

	// Generate: plaintext returned exactly once, expiry set.
	gen, rerr := api.Generate(ctx, json.RawMessage(`{"name":"consumer-a","permissions":["qau_randomnessGet"],"days":30}`))
	if rerr != nil {
		t.Fatalf("Generate: %v", rerr)
	}
	genMap := gen.(map[string]any)
	plaintext, _ := genMap["apiKey"].(string)
	keyHash, _ := genMap["keyHash"].(string)
	if plaintext == "" || keyHash == "" {
		t.Fatal("generate response missing apiKey/keyHash")
	}
	if hashAPIKey(plaintext) != keyHash {
		t.Errorf("keyHash %s is not SHA-256 of the returned plaintext key", keyHash)
	}
	if mutations.Load() != 1 {
		t.Errorf("persistence hook fired %d times after generate, want 1", mutations.Load())
	}

	// The stored entry must not contain the plaintext.
	for _, snap := range am.SnapshotAPIKeys() {
		if snap.KeyHash != keyHash {
			continue
		}
		if len(snap.Permissions) != 1 || snap.Permissions[0] != "qau_randomnessGet" {
			t.Errorf("stored permissions = %v", snap.Permissions)
		}
	}

	// List: contains the key hash but NEVER the plaintext.
	list, rerr := api.List(ctx, nil)
	if rerr != nil {
		t.Fatalf("List: %v", rerr)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), plaintext) {
		t.Fatal("list response leaks the plaintext key")
	}
	if !strings.Contains(string(raw), keyHash) {
		t.Error("list response missing the key hash")
	}

	// Extend: pushes expiry out by 30 days from the current expiry.
	before := am.SnapshotAPIKeys()[0].ExpiresAt
	ext, rerr := api.Extend(ctx, json.RawMessage(`{"keyHash":"`+keyHash+`","days":30}`))
	if rerr != nil {
		t.Fatalf("Extend: %v", rerr)
	}
	after := am.SnapshotAPIKeys()[0].ExpiresAt
	if !after.After(before.Add(29 * 24 * time.Hour)) {
		t.Errorf("extend did not move expiry: before=%v after=%v", before, after)
	}
	if _, ok := ext.(map[string]any)["expiresAt"]; !ok {
		t.Error("extend response missing expiresAt")
	}
	if mutations.Load() != 2 {
		t.Errorf("persistence hook fired %d times after extend, want 2", mutations.Load())
	}

	// Revoke by hash: second revoke reports false.
	rev, rerr := api.Revoke(ctx, json.RawMessage(`{"keyHash":"`+keyHash+`"}`))
	if rerr != nil {
		t.Fatalf("Revoke: %v", rerr)
	}
	if rev.(map[string]any)["revoked"] != true {
		t.Error("first revoke should report true")
	}
	rev2, _ := api.Revoke(ctx, json.RawMessage(`{"keyHash":"`+keyHash+`"}`))
	if rev2.(map[string]any)["revoked"] != false {
		t.Error("second revoke should report false")
	}
	if len(am.SnapshotAPIKeys()) != 0 {
		t.Error("registry should be empty after revoke")
	}
	if mutations.Load() != 3 {
		t.Errorf("persistence hook fired %d times after revoke, want 3", mutations.Load())
	}
}

func TestAdminKeyRateLimit(t *testing.T) {
	api, am, mutations := newTestAdminKeyAPI(t)
	ctx := context.Background()

	// QR-41: generate with a paid rate limit — the response advertises it and
	// the stored copy carries it (so validateRequest's token bucket and the
	// persisted registry both see it).
	gen, rerr := api.Generate(ctx, json.RawMessage(`{"name":"paid-tier","rateLimit":240}`))
	if rerr != nil {
		t.Fatalf("Generate(rateLimit=240): %v", rerr)
	}
	genMap := gen.(map[string]any)
	keyHash, _ := genMap["keyHash"].(string)
	if keyHash == "" {
		t.Fatal("generate response missing keyHash")
	}
	if got, _ := genMap["rateLimit"].(int); got != 240 {
		t.Errorf("generate response rateLimit = %v, want 240", genMap["rateLimit"])
	}
	var found bool
	for _, snap := range am.SnapshotAPIKeys() {
		if snap.KeyHash != keyHash {
			continue
		}
		found = true
		if snap.RateLimit != 240 {
			t.Errorf("stored RateLimit = %d, want 240 (QR-41: paid tier must reach the stored copy)", snap.RateLimit)
		}
	}
	if !found {
		t.Fatal("generated key missing from snapshot")
	}
	// Generate + SetAPIKeyRateLimit both count as registry mutations.
	if mutations.Load() != 2 {
		t.Errorf("persistence hook fired %d times (generate + rate limit), want 2", mutations.Load())
	}

	// Omitted rateLimit keeps the key unthrottled and the response field absent.
	gen2, rerr := api.Generate(ctx, json.RawMessage(`{"name":"free-tier"}`))
	if rerr != nil {
		t.Fatalf("Generate(no rateLimit): %v", rerr)
	}
	if _, ok := gen2.(map[string]any)["rateLimit"]; ok {
		t.Error("unthrottled key must not advertise a rateLimit")
	}
	for _, snap := range am.SnapshotAPIKeys() {
		if snap.Name == "free-tier" && snap.RateLimit != 0 {
			t.Errorf("free-tier RateLimit = %d, want 0 (unthrottled)", snap.RateLimit)
		}
	}

	// Unknown keyHash must fail with ErrInvalidAPIKey.
	if err := am.SetAPIKeyRateLimit(strings.Repeat("c", 64), 100); err != ErrInvalidAPIKey {
		t.Errorf("SetAPIKeyRateLimit(unknown hash) = %v, want ErrInvalidAPIKey", err)
	}

	// Re-tiering an existing key updates the stored copy.
	if err := am.SetAPIKeyRateLimit(keyHash, 480); err != nil {
		t.Fatalf("SetAPIKeyRateLimit(re-tier): %v", err)
	}
	for _, snap := range am.SnapshotAPIKeys() {
		if snap.KeyHash == keyHash && snap.RateLimit != 480 {
			t.Errorf("re-tiered RateLimit = %d, want 480", snap.RateLimit)
		}
	}
}

func TestAdminKeyValidation(t *testing.T) {
	api, _, _ := newTestAdminKeyAPI(t)
	ctx := context.Background()

	cases := []struct {
		name   string
		method func() (any, *Error)
	}{
		{"generate missing name", func() (any, *Error) {
			return api.Generate(ctx, json.RawMessage(`{"days":30}`))
		}},
		{"generate days overflow", func() (any, *Error) {
			return api.Generate(ctx, json.RawMessage(`{"name":"x","days":99999}`))
		}},
		{"generate negative days", func() (any, *Error) {
			return api.Generate(ctx, json.RawMessage(`{"name":"x","days":-1}`))
		}},
		{"generate negative rateLimit", func() (any, *Error) {
			return api.Generate(ctx, json.RawMessage(`{"name":"x","rateLimit":-5}`))
		}},
		{"revoke short hash", func() (any, *Error) {
			return api.Revoke(ctx, json.RawMessage(`{"keyHash":"abcd"}`))
		}},
		{"revoke non-hex hash", func() (any, *Error) {
			return api.Revoke(ctx, json.RawMessage(`{"keyHash":"`+strings.Repeat("z", 64)+`"}`))
		}},
		{"extend zero days", func() (any, *Error) {
			return api.Extend(ctx, json.RawMessage(`{"keyHash":"`+strings.Repeat("a", 64)+`","days":0}`))
		}},
		{"extend unknown key", func() (any, *Error) {
			return api.Extend(ctx, json.RawMessage(`{"keyHash":"`+strings.Repeat("b", 64)+`","days":5}`))
		}},
	}
	for _, tc := range cases {
		if _, rerr := tc.method(); rerr == nil || rerr.Code != -32602 && rerr.Code != -32000 {
			t.Errorf("%s: expected -32602/-32000, got %v", tc.name, rerr)
		}
	}
}

func TestAdminKeyMethodsAreAdminGated(t *testing.T) {
	srv := NewServer(nil)
	api, am, _ := newTestAdminKeyAPI(t)
	api.RegisterHandlers(srv)
	for _, method := range []string{"admin_generateAPIKey", "admin_listAPIKeys", "admin_revokeAPIKey", "admin_extendAPIKey"} {
		if _, ok := srv.handlers[method]; !ok {
			t.Errorf("%s handler not registered", method)
		}
		if !srv.isAdminMethod(method) {
			t.Errorf("%s must be an admin method", method)
		}
		// They must NOT be publicly callable without authentication.
		if am.IsPublicMethod(method) {
			t.Errorf("%s must not be in the public allowlist", method)
		}
	}
}
