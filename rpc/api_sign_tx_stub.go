// Quantaureum Node source, version 1.0.0.
//go:build no_rpc_sign_tx

// Package rpc provides RPC handling for the Quantaureum blockchain.
// This file is included when building with -tags=no_rpc_sign_tx
// It provides a stub that returns an error for SignQuantumTransaction.
package rpc

import (
	"context"
	"encoding/json"
)

// SignQuantumTransaction is disabled at compile time for security.
// This method accepts a raw private key over RPC and should NEVER be enabled in production.
// Use client-side signing instead.
func (api *API) SignQuantumTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	return nil, NewError(ErrCodeUnauthorized, "qau_signQuantumTransaction is disabled at compile time; use client-side signing")
}
