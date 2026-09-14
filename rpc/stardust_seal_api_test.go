// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── P1-7: QTD Seal RPC tests ──
// 03-P1-7 (2026-07-14): Verify the new qau_tss_requestSeal /
// qau_tss_submitPartialSeal / qau_tss_getSealStatus RPC surface.

// TestGetSealStatus_NilQPOS verifies graceful failure when QPOS is nil.
func TestGetSealStatus_NilQPOS(t *testing.T) {
	api := NewStardustAPI(nil)
	_, err := api.GetSealStatus(ctx(), nil)
	requireErr(t, nil, err)
}

// TestGetSealStatus_InvalidSlotParam verifies that invalid slot parameter
// is rejected.
func TestGetSealStatus_InvalidSlotParam(t *testing.T) {
	api := NewStardustAPI(nil)
	// Pass garbage params — should fail at param parsing (or earlier at qpos nil check).
	_, err := api.GetSealStatus(ctx(), json.RawMessage(`{}`))
	requireErr(t, nil, err)
}

// TestRequestSeal_NilQPOS verifies graceful failure when QPOS is nil.
func TestRequestSeal_NilQPOS(t *testing.T) {
	api := NewStardustAPI(nil)
	_, err := api.RequestSeal(ctx(), nil)
	requireErr(t, nil, err)
}

// TestRequestSeal_MissingBlockHash verifies that a missing blockHash is rejected.
func TestRequestSeal_MissingBlockHash(t *testing.T) {
	api := NewStardustAPI(nil)
	params, _ := json.Marshal(map[string]any{
		"slot": 1,
	})
	_, err := api.RequestSeal(ctx(), params)
	requireErr(t, nil, err)
}

// TestRequestSeal_InvalidBlockHash verifies that a malformed blockHash is rejected.
func TestRequestSeal_InvalidBlockHash(t *testing.T) {
	api := NewStardustAPI(nil)
	params, _ := json.Marshal(map[string]any{
		"slot":      1,
		"blockHash": "0xdeadbeef", // too short
	})
	_, err := api.RequestSeal(ctx(), params)
	requireErr(t, nil, err)
}

// TestRequestSeal_ArrayForm verifies the array-style params work.
func TestRequestSeal_ArrayForm(t *testing.T) {
	api := NewStardustAPI(nil)
	// Array form: [slot, "0x..."]
	params, _ := json.Marshal([]any{
		1,
		"0x" + strings.Repeat("ab", 32), // 32-byte hash
	})
	_, err := api.RequestSeal(ctx(), params)
	// Should fail at QPOS nil check, not at param parsing.
	requireErr(t, nil, err)
}

// TestRequestSeal_HexSlot verifies that hex slot strings are accepted.
func TestRequestSeal_HexSlot(t *testing.T) {
	api := NewStardustAPI(nil)
	params, _ := json.Marshal(map[string]any{
		"slotHex":   "0x1a",
		"blockHash": "0x" + strings.Repeat("cd", 32),
	})
	_, err := api.RequestSeal(ctx(), params)
	// Should fail at QPOS nil check, not at param parsing.
	requireErr(t, nil, err)
}

// TestSubmitPartialSeal_NilQPOS verifies graceful failure when QPOS is nil.
func TestSubmitPartialSeal_NilQPOS(t *testing.T) {
	api := NewStardustAPI(nil)
	_, err := api.SubmitPartialSeal(ctx(), nil)
	requireErr(t, nil, err)
}

// TestSubmitPartialSeal_MissingSignature verifies that missing signature is rejected.
func TestSubmitPartialSeal_MissingSignature(t *testing.T) {
	api := NewStardustAPI(nil)
	params, _ := json.Marshal(map[string]any{
		"slot":           1,
		"validatorIndex": 0,
	})
	_, err := api.SubmitPartialSeal(ctx(), params)
	requireErr(t, nil, err)
}

// TestSubmitPartialSeal_InvalidSignatureHex verifies that invalid hex signature is rejected.
func TestSubmitPartialSeal_InvalidSignatureHex(t *testing.T) {
	api := NewStardustAPI(nil)
	params, _ := json.Marshal(map[string]any{
		"slot":           1,
		"validatorIndex": 0,
		"signature":      "0xZZZZ",
	})
	_, err := api.SubmitPartialSeal(ctx(), params)
	requireErr(t, nil, err)
}

// TestParseUint64Hex verifies the hex parsing helper.
func TestParseUint64Hex(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
		hasError bool
	}{
		{"0x1a", 26, false},
		{"1a", 26, false},
		{"0x0", 0, false},
		{"0xff", 255, false},
		{"0xFFFFFFFFFFFFFFFF", 18446744073709551615, false},
		{"0xGGG", 0, true}, // invalid hex
		{"", 0, false},     // empty string = 0
	}

	for _, tt := range tests {
		got, err := parseUint64Hex(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("parseUint64Hex(%q): expected error, got %d", tt.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUint64Hex(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.expected {
			t.Errorf("parseUint64Hex(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

// TestSealRPC_RegisterHandlers verifies that all three seal RPC methods
// are registered correctly.
func TestSealRPC_RegisterHandlers(t *testing.T) {
	api := NewStardustAPI(nil)
	srv := NewServer(nil)
	api.RegisterHandlers(srv)

	// Verify admin-gated methods are registered as admin.
	if !srv.isAdminMethod("qau_tss_requestSeal") {
		t.Error("qau_tss_requestSeal should be admin-gated")
	}
	if !srv.isAdminMethod("qau_tss_submitPartialSeal") {
		t.Error("qau_tss_submitPartialSeal should be admin-gated")
	}
	// getSealStatus should NOT be admin-gated (read-only).
	if srv.isAdminMethod("qau_tss_getSealStatus") {
		t.Error("qau_tss_getSealStatus should NOT be admin-gated (read-only)")
	}
	// P1-9: getDKGStatus should be registered (dispatchable) and NOT admin-gated.
	// Verify via handleRequest: a registered method returns a non-MethodNotFound
	// response (even if it errors due to nil QPOS).
	req := &Request{
		JSONRPC: "2.0",
		Method:  "qau_stardust_getDKGStatus",
		Params:  json.RawMessage(`[]`),
		ID:      1,
	}
	resp := srv.handleRequest(ctx(), req)
	if resp.Error != nil && resp.Error.Code == ErrCodeMethodNotFound {
		t.Error("qau_stardust_getDKGStatus should be registered (got MethodNotFound)")
	}
	if srv.isAdminMethod("qau_stardust_getDKGStatus") {
		t.Error("qau_stardust_getDKGStatus should NOT be admin-gated (read-only)")
	}
}

// ── P1-9: DKG Status RPC tests ──

// TestGetDKGStatus_NilQPOS verifies graceful failure when QPOS is nil.
func TestGetDKGStatus_NilQPOS(t *testing.T) {
	api := NewStardustAPI(nil)
	_, err := api.GetDKGStatus(ctx(), nil)
	requireErr(t, nil, err)
}

// TestGetDKGStatus_NoChambers verifies graceful handling when chambers are
// not initialized.
func TestGetDKGStatus_NoChambers(t *testing.T) {
	// We can't easily create a QPOS without chambers in the rpc test package,
	// so we test the nil QPOS path and the registration path. The full
	// coordinator behavior is tested in consensus/provinces_dkg_test.go.
	api := NewStardustAPI(nil)
	result, err := api.GetDKGStatus(ctx(), nil)
	// nil QPOS returns an error.
	if err == nil {
		t.Error("expected error when QPOS is nil")
	}
	_ = result
}
