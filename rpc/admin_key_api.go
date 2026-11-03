// Quantaureum Node source, version 1.0.0.
// Package rpc implements the JSON-RPC 2.0 server for Quantaureum.
// This file provides runtime API-key management over admin-gated RPC
// (admin_generateAPIKey / admin_listAPIKeys / admin_revokeAPIKey /
// admin_extendAPIKey).
//
// Security model:
//   - Every method requires admin authentication (RegisterAdminMethod).
//   - The plaintext key is returned EXACTLY ONCE by admin_generateAPIKey;
//     all listings expose only the SHA-256 hash (AuthManager stores no
//     plaintext — audit-fix M-1 / RPC-002).
//   - Mutations trigger the AuthManager persistence hook so the registry
//     survives node restarts (wired by the node to <dataDir>/apikeys.json).
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AdminKeyAPI exposes runtime API-key management via JSON-RPC. All methods
// are admin-gated; unauthenticated or non-admin callers are rejected by the
// server pipeline before the handler runs.
type AdminKeyAPI struct {
	am *AuthManager
}

// NewAdminKeyAPI creates an AdminKeyAPI over the given AuthManager.
func NewAdminKeyAPI(am *AuthManager) *AdminKeyAPI {
	return &AdminKeyAPI{am: am}
}

// RegisterHandlers registers the admin key management handlers. Each method
// is also registered as an admin method so the server enforces admin
// authentication before dispatch.
func (api *AdminKeyAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("admin_generateAPIKey", api.Generate)
	server.RegisterAdminMethod("admin_generateAPIKey")
	server.RegisterHandler("admin_listAPIKeys", api.List)
	server.RegisterAdminMethod("admin_listAPIKeys")
	server.RegisterHandler("admin_revokeAPIKey", api.Revoke)
	server.RegisterAdminMethod("admin_revokeAPIKey")
	server.RegisterHandler("admin_extendAPIKey", api.Extend)
	server.RegisterAdminMethod("admin_extendAPIKey")
}

// apiKeyBounds bounds admin key durations. The maximum is deliberately
// generous but finite so an admin typo cannot mint a near-permanent key.
const (
	apiKeyMaxDays = 3650 // 10 years
)

// Generate issues a new API key.
// RPC: admin_generateAPIKey (admin-only)
// Params: {"name": "<id>", "permissions": ["method", ...], "days": <uint>,
//
//	       "rateLimit": <req/min>}
//	- permissions: allowed RPC methods; empty/omitted allows all methods.
//	- days: expiry in days (1..3650); omit or 0 for a non-expiring key.
//	- rateLimit: per-key throttle in requests/minute (QR-41: how paid keys
//	  "buy higher rate limits"); omit or 0 for the unthrottled default.
//
// The response carries the plaintext apiKey exactly once — this is the only
// opportunity to hand it to the consumer — plus the effective "rateLimit"
// (omitted when unthrottled, matching admin_listAPIKeys).
func (api *AdminKeyAPI) Generate(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.am == nil {
		return nil, &Error{Code: -32601, Message: "auth manager not available"}
	}
	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
		Days        int      `json:"days"`
		RateLimit   int      `json:"rateLimit"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return nil, &Error{Code: -32602, Message: "invalid params: name is required"}
	}
	if req.Days < 0 || req.Days > apiKeyMaxDays {
		return nil, &Error{Code: -32602, Message: fmt.Sprintf("invalid params: days must be 0..%d", apiKeyMaxDays)}
	}
	if req.RateLimit < 0 {
		return nil, &Error{Code: -32602, Message: "invalid params: rateLimit must be >= 0 (0 = unthrottled)"}
	}
	var expires time.Duration
	if req.Days > 0 {
		expires = time.Duration(req.Days) * 24 * time.Hour
	}
	info, err := api.am.GenerateAPIKey(req.Name, req.Permissions, expires)
	if err != nil {
		return nil, &Error{Code: -32000, Message: "key generation failed: " + err.Error()}
	}
	// QR-41: attach the paid tier's rate limit to the freshly minted key so
	// the per-key token bucket (validateRequest / validateBatchRequest) and
	// the persisted registry both see it.
	if req.RateLimit > 0 {
		if err := api.am.SetAPIKeyRateLimit(info.KeyHash, req.RateLimit); err != nil {
			return nil, &Error{Code: -32000, Message: "rate limit assignment failed: " + err.Error()}
		}
	}
	resp := map[string]any{
		"apiKey":    info.Key, // plaintext: returned exactly once
		"keyHash":   info.KeyHash,
		"name":      info.Name,
		"createdAt": info.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !info.ExpiresAt.IsZero() {
		resp["expiresAt"] = info.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if req.RateLimit > 0 {
		resp["rateLimit"] = req.RateLimit
	}
	return resp, nil
}

// List returns all registered keys, plaintext-free.
// RPC: admin_listAPIKeys (admin-only)
func (api *AdminKeyAPI) List(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.am == nil {
		return nil, &Error{Code: -32601, Message: "auth manager not available"}
	}
	snaps := api.am.SnapshotAPIKeys()
	out := make([]map[string]any, 0, len(snaps))
	for _, s := range snaps {
		entry := map[string]any{
			"keyHash":    s.KeyHash,
			"name":       s.Name,
			"createdAt":  s.CreatedAt.UTC().Format(time.RFC3339),
			"usageCount": s.UsageCount,
		}
		if !s.ExpiresAt.IsZero() {
			entry["expiresAt"] = s.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if len(s.Permissions) > 0 {
			entry["permissions"] = s.Permissions
		}
		if s.RateLimit > 0 {
			entry["rateLimit"] = s.RateLimit
		}
		out = append(out, entry)
	}
	return map[string]any{"keys": out}, nil
}

// Revoke deletes a key by its SHA-256 hash.
// RPC: admin_revokeAPIKey (admin-only)
// Params: {"keyHash": "<64 hex chars>"}
func (api *AdminKeyAPI) Revoke(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.am == nil {
		return nil, &Error{Code: -32601, Message: "auth manager not available"}
	}
	keyHash, rerr := parseKeyHashParam(params)
	if rerr != nil {
		return nil, rerr
	}
	revoked := api.am.RemoveAPIKeyByHash(keyHash)
	return map[string]any{"revoked": revoked}, nil
}

// Extend extends the expiry of a key by days (relative to the current expiry,
// or to now for an expired/unset key).
// RPC: admin_extendAPIKey (admin-only)
// Params: {"keyHash": "<64 hex chars>", "days": <uint>}
func (api *AdminKeyAPI) Extend(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.am == nil {
		return nil, &Error{Code: -32601, Message: "auth manager not available"}
	}
	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		KeyHash string `json:"keyHash"`
		Days    int    `json:"days"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	keyHash, herr := normalizeKeyHash(req.KeyHash)
	if herr != nil {
		return nil, &Error{Code: -32602, Message: herr.Error()}
	}
	if req.Days <= 0 || req.Days > apiKeyMaxDays {
		return nil, &Error{Code: -32602, Message: fmt.Sprintf("invalid params: days must be 1..%d", apiKeyMaxDays)}
	}
	newExpiry, err := api.am.ExtendAPIKey(keyHash, req.Days)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}
	return map[string]any{"expiresAt": newExpiry.UTC().Format(time.RFC3339)}, nil
}

// parseKeyHashParam extracts and validates {"keyHash": "..."} params.
func parseKeyHashParam(params json.RawMessage) (string, *Error) {
	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return "", rerr
	}
	var req struct {
		KeyHash string `json:"keyHash"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return "", &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	keyHash, herr := normalizeKeyHash(req.KeyHash)
	if herr != nil {
		return "", &Error{Code: -32602, Message: herr.Error()}
	}
	return keyHash, nil
}

// normalizeKeyHash validates the key hash form (64 lowercase hex chars).
// Both bare hex and 0x-prefixed hex are accepted — the billing worker carries
// the keyHash from the deposit event as 0x-hex 32 bytes, while
// admin_listAPIKeys reports the bare form.
func normalizeKeyHash(keyHash string) (string, error) {
	keyHash = strings.ToLower(strings.TrimSpace(keyHash))
	keyHash = strings.TrimPrefix(keyHash, "0x")
	if len(keyHash) != 64 {
		return "", fmt.Errorf("keyHash must be 64 hex chars (SHA-256)")
	}
	if _, err := hex.DecodeString(keyHash); err != nil {
		return "", fmt.Errorf("keyHash must be hex: %v", err)
	}
	return keyHash, nil
}
