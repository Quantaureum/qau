// Quantaureum Node source, version 1.0.0.
// Package rpc implements the JSON-RPC 2.0 server for Quantaureum.
// This file provides quantum-cryptography RPC methods (qau_quantum*, qau_qrng*).

package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/quantaureum/qau/qrng"
	"github.com/quantaureum/qau/quantum"
)

// QuantumAPI exposes quantum-cryptography subsystems via JSON-RPC:
//   - MPC ceremony status (qau_quantumGetMPCStatus)
//   - ZKP proof verification (qau_quantumVerifyZKP)
//   - Key rotation status (qau_quantumGetKeyRotationStatus)
//   - Quantum random number generation (qau_qrngGetRandom)
//
// Each subsystem is independently enabled and may be nil. Every method
// returns -32601 when its backing component is not available.
type QuantumAPI struct {
	mpc         *quantum.MPCManager
	zkVerifier  *quantum.ZKVerifier
	keyRotation *quantum.KeyRotationManager
	qrng        *qrng.QRNG
}

// NewQuantumAPI creates a QuantumAPI. Any argument may be nil when the
// corresponding feature is disabled.
func NewQuantumAPI(
	mpc *quantum.MPCManager,
	zkVerifier *quantum.ZKVerifier,
	keyRotation *quantum.KeyRotationManager,
	qrng *qrng.QRNG,
) *QuantumAPI {
	return &QuantumAPI{
		mpc:         mpc,
		zkVerifier:  zkVerifier,
		keyRotation: keyRotation,
		qrng:        qrng,
	}
}

// RegisterHandlers registers all quantum API handlers on the given server.
func (api *QuantumAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("qau_quantumGetMPCStatus", api.GetMPCStatus)
	server.RegisterHandler("qau_quantumVerifyZKP", api.VerifyZKP)
	server.RegisterHandler("qau_quantumGetKeyRotationStatus", api.GetKeyRotationStatus)
	server.RegisterHandler("qau_qrngGetRandom", api.GetRandom)
	// RPC-FIX: Register qau_qrngGetRandom as admin method.
	// Previously this was only removed from PublicMethods but not registered
	// as an admin method, allowing any authenticated user (non-admin) to call
	// it and exhaust the QRNG entropy pool or observe consensus randomness.
	// Admin registration ensures only admin-authorized callers can invoke it.
	server.RegisterAdminMethod("qau_qrngGetRandom")
}

// GetMPCStatus returns the MPC ceremony manager status.
// RPC: qau_quantumGetMPCStatus
func (api *QuantumAPI) GetMPCStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.mpc == nil {
		return nil, &Error{Code: -32601, Message: "MPC manager not available (disabled)"}
	}

	return map[string]any{
		"registeredParties": api.mpc.GetPartyCount(),
		"activeSessions":    api.mpc.GetActiveSessionCount(),
	}, nil
}

// VerifyZKP verifies a zero-knowledge proof.
// RPC: qau_quantumVerifyZKP
// Params: {"proofBytes": "<hex>", "publicInputs": ["<hex>", ...], "circuitId": "<id>"}
func (api *QuantumAPI) VerifyZKP(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.zkVerifier == nil {
		return nil, &Error{Code: -32601, Message: "ZKP verifier not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		ProofBytes   string   `json:"proofBytes"`
		PublicInputs []string `json:"publicInputs"`
		CircuitID    string   `json:"circuitId"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	// RPC-FIX: Bound proof/public-inputs size at the RPC boundary to
	// prevent a single request from triggering memory exhaustion (a 1GB
	// proofBytes or a million-entry publicInputs array would otherwise be
	// decoded before reaching the verifier).
	const (
		maxProofSizeHex       = (1 << 20) * 2 // 1 MiB decoded → 2 MiB hex chars
		maxPublicInputs       = 100
		maxPublicInputSizeHex = 32 * 1024 * 2 // 32 KiB decoded → 64 KiB hex chars
	)
	if len(req.ProofBytes) > maxProofSizeHex {
		return nil, &Error{Code: -32602, Message: "proofBytes too large (max 1MB decoded)"}
	}
	if len(req.PublicInputs) > maxPublicInputs {
		return nil, &Error{Code: -32602, Message: "too many publicInputs (max 100)"}
	}
	for _, input := range req.PublicInputs {
		if len(input) > maxPublicInputSizeHex {
			return nil, &Error{Code: -32602, Message: "publicInput too large (max 32KB decoded each)"}
		}
	}

	proofBytes, err := hex.DecodeString(req.ProofBytes)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid proofBytes hex: " + err.Error()}
	}

	publicInputs := make([][]byte, 0, len(req.PublicInputs))
	for _, input := range req.PublicInputs {
		b, err := hex.DecodeString(input)
		if err != nil {
			return nil, &Error{Code: -32602, Message: "invalid publicInput hex: " + err.Error()}
		}
		publicInputs = append(publicInputs, b)
	}

	proof := &quantum.ZKProof{
		ProofBytes:   proofBytes,
		PublicInputs: publicInputs,
		CircuitID:    req.CircuitID,
	}

	valid, err := api.zkVerifier.VerifyProof(proof)
	if err != nil {
		return map[string]any{
			"valid":     false,
			"circuitId": req.CircuitID,
			"error":     err.Error(),
		}, nil
	}

	return map[string]any{
		"valid":     valid,
		"circuitId": req.CircuitID,
	}, nil
}

// GetKeyRotationStatus returns the validator key rotation manager status.
// RPC: qau_quantumGetKeyRotationStatus
func (api *QuantumAPI) GetKeyRotationStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.keyRotation == nil {
		return nil, &Error{Code: -32601, Message: "key rotation manager not available (disabled)"}
	}

	result := map[string]any{
		"timeUntilNextRotation": api.keyRotation.TimeUntilNextRotation().String(),
	}

	if key, err := api.keyRotation.GetActiveKey(); err == nil && key != nil {
		result["activeKeyId"] = key.ID
		result["algorithm"] = key.Algorithm
		result["version"] = key.Version
		result["createdAt"] = key.CreatedAt
		result["expiresAt"] = key.ExpiresAt
		// FIX: Truncate the public key to avoid exposing the full
		// validator public key via RPC. Only return the first 16 bytes.
		pubKeyHex := hex.EncodeToString(key.PublicKey)
		if len(pubKeyHex) > 32 {
			pubKeyHex = pubKeyHex[:32] + "..."
		}
		result["publicKey"] = "0x" + pubKeyHex
	} else {
		result["activeKeyId"] = ""
	}

	history := api.keyRotation.GetRotationHistory()
	result["rotationCount"] = len(history)

	expired := api.keyRotation.CheckExpiry()
	result["expiredKeys"] = expired

	return result, nil
}

// GetRandom returns quantum-generated random bytes.
// RPC: qau_qrngGetRandom (admin-only — requires authentication)
// Params: {"bytes": <numBytes>}  (optional, default 32, max 64)
//
// AUDIT (2026) API-02: This endpoint is no longer public. It requires
// admin authentication to prevent entropy starvation DoS and to prevent
// correlation/prediction of consensus entropy if the QRNG instance is
// shared. The max bytes per call has been reduced from 1024 to 64 to
// limit entropy drain per authenticated request.
func (api *QuantumAPI) GetRandom(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qrng == nil {
		return nil, &Error{Code: -32601, Message: "QRNG not available (disabled)"}
	}

	numBytes := 32
	if len(params) > 0 && string(params) != "null" {
		if unwrapped, rerr := unwrapParams(params); rerr == nil {
			var req struct {
				Bytes int `json:"bytes"`
			}
			// AUDIT (2026) API-02: Reduced max from 1024 to 64 to limit
			// entropy drain per request.
			if err := json.Unmarshal(unwrapped, &req); err == nil && req.Bytes > 0 && req.Bytes <= 64 {
				numBytes = req.Bytes
			}
		}
	}

	randomBytes, err := api.qrng.Bytes(numBytes)
	if err != nil {
		return nil, &Error{Code: -32000, Message: "QRNG generation failed: " + err.Error()}
	}

	return map[string]any{
		"random":  "0x" + hex.EncodeToString(randomBytes),
		"bytes":   numBytes,
		"healthy": api.qrng.IsHealthy(),
	}, nil
}
