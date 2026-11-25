// Quantaureum Node source, version 1.0.0.
//go:build !no_rpc_sign_tx

package rpc

import (
	"context"
	"encoding/json"
	"testing"
)

// Audit M-07: the five not-yet-wired methods must fail closed with the
// dedicated ErrCodeNotImplemented code and a message that names the method
// and the reason, instead of a generic internal error.
func TestStubMethodsFailClosedWithNotImplemented(t *testing.T) {
	api := &API{}
	ctx := context.Background()
	params := json.RawMessage(`[]`)

	tests := []struct {
		name   string
		method string
		call   func() (any, *Error)
	}{
		{
			name:   "VerifyQuantumTransaction",
			method: "qau_verifyQuantumTransaction",
			call:   func() (any, *Error) { return api.VerifyQuantumTransaction(ctx, params) },
		},
		{
			name:   "SendPrivacyTransaction",
			method: "qau_sendPrivacyTransaction",
			call:   func() (any, *Error) { return api.SendPrivacyTransaction(ctx, params) },
		},
		{
			name:   "ScanPrivacy",
			method: "qau_scanPrivacy",
			call:   func() (any, *Error) { return api.ScanPrivacy(ctx, params) },
		},
		{
			name:   "GetPrivacyBalance",
			method: "qau_getPrivacyBalance",
			call:   func() (any, *Error) { return api.GetPrivacyBalance(ctx, params) },
		},
		{
			name:   "GenerateStealthAddress",
			method: "qau_generateStealthAddress",
			call:   func() (any, *Error) { return api.GenerateStealthAddress(ctx, params) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, rpcErr := tc.call()
			if result != nil {
				t.Fatalf("%s returned a non-nil result %v; must fail closed", tc.method, result)
			}
			if rpcErr == nil {
				t.Fatalf("%s returned nil error; must fail closed with ErrCodeNotImplemented", tc.method)
			}
			if rpcErr.Code != ErrCodeNotImplemented {
				t.Fatalf("%s error code = %d, want %d (ErrCodeNotImplemented)", tc.method, rpcErr.Code, ErrCodeNotImplemented)
			}
			if !containsSubstring(rpcErr.Message, "not implemented") {
				t.Fatalf("%s error message %q must state it is not implemented", tc.method, rpcErr.Message)
			}
			if !containsSubstring(rpcErr.Message, tc.method) {
				t.Fatalf("%s error message %q must name the method", tc.method, rpcErr.Message)
			}
		})
	}
}
