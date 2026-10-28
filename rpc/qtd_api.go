// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/quantaureum/qau/wallet/tss"
)

type TSSAPI struct {
	tssManager *tss.TSSManager
	devMode    bool // SECURITY (audit P0-): sensitive methods restricted to devMode
}

func NewTSSAPI(manager *tss.TSSManager) *TSSAPI {
	return &TSSAPI{tssManager: manager, devMode: false} // devMode defaults to false (secure)
}

// SetDevMode enables devMode for sensitive TSS operations.
// SECURITY (audit P0-): Only enable in devMode (ChainID=1333).
// TSS-FIX: Apply compile-time DEV_MODE_ENABLED gate (mirrors PersonalAPI
// pattern) so that even if an admin calls SetDevMode(true) in a production
// binary, devMode cannot be enabled at runtime. Production builds must be
// compiled with -ldflags "-X github.com/quantaureum/qau/rpc.DEV_MODE_ENABLED=false".
func (api *TSSAPI) SetDevMode(enabled bool) {
	if DEV_MODE_ENABLED != "true" {
		api.devMode = false
		return
	}
	log.Printf("[SECURITY] TSSAPI devMode set to %v", enabled)
	api.devMode = enabled
}

// hashShare returns the SHA3-256 hash of a key share as hex string.
// SECURITY (audit P0-): Return hash instead of raw share bytes to prevent
// private key extraction via RPC.
// R19-F06 (2026-10-28): the salt is a per-call crypto/rand value that is
// RETURNED to the caller alongside the hash. The previous salt was the
// current Unix second — never returned, guessable to within a few
// candidates, and shared by every query in the same second — which made
// shareHash a low-entropy verification oracle for a leaked share rather
// than a commitment, and broke the "audit logs can re-derive" promise
// (the log path salted with a DIFFERENT timestamp than the response).
// A high-entropy returned salt fixes both: re-derivation works, and a
// verifier without the salt learns nothing.
func hashShare(share []byte, salt []byte) string {
	h := sha3.New256()
	_, _ = h.Write(share)
	_, _ = h.Write(salt)
	return hex.EncodeToString(h.Sum(nil))
}

// shareHashSalt returns a fresh 32-byte crypto/rand salt.
func shareHashSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func (api *TSSAPI) RegisterHandlers(server *Server) {
	// R7-C1 FIX: Threshold-signing methods handle secret key material and signing.
	// Every privileged operation MUST be admin-gated. GetShare exposes raw secret
	// shares and should never be reachable over RPC; it remains admin-only and is
	// expected to be removed from the public surface in a follow-up.
	server.RegisterAdminMethod("qau_tss_generateKeyShares")
	// L18-038 FIX: qau_tss_getPublicKey is a read-only query; removed AdminMethod.
	server.RegisterAdminMethod("qau_tss_getShare")
	server.RegisterAdminMethod("qau_tss_signMessage")
	server.RegisterAdminMethod("qau_tss_verifySignature")
	// R31-P3 FIX: qau_tss_status is a read-only status query (like qpos_status).
	// It should NOT require admin authentication — doing so prevents external
	// monitoring tools from checking TSS health without admin credentials.
	server.RegisterHandler("qau_tss_status", api.Status)
	server.RegisterHandler("qau_tss_generateKeyShares", api.GenerateKeyShares)
	server.RegisterHandler("qau_tss_getPublicKey", api.GetPublicKey)
	server.RegisterHandler("qau_tss_getShare", api.GetShare)
	server.RegisterHandler("qau_tss_signMessage", api.SignMessage)
	server.RegisterHandler("qau_tss_verifySignature", api.VerifySignature)
}

func (api *TSSAPI) GenerateKeyShares(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.tssManager == nil {
		return nil, NewError(ErrCodeInternal, "TSS manager not initialized")
	}

	var req struct {
		Threshold   int `json:"threshold"`
		TotalShares int `json:"totalShares"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		var arr []json.RawMessage
		if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 1 {
			if err3 := json.Unmarshal(arr[0], &req); err3 != nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
			}
		} else {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
		}
	}

	// R19-F05 (2026-10-28): the caller-supplied threshold/totalShares used to
	// be validated and then silently DROPPED — GenerateKeyShares() has no
	// parameters and uses the manager's own configuration, so an operator
	// asking for 3-of-5 got whatever the manager was configured with and no
	// signal that the request was a no-op. Refuse explicitly instead.
	if req.Threshold > 0 || req.TotalShares > 0 {
		cfg := tss.TSSConfig{
			Threshold:     req.Threshold,
			TotalShares:   req.TotalShares,
			SecurityLevel: 256,
		}
		if err := cfg.Validate(); err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid config", err.Error())
		}
		if req.Threshold != api.tssManager.Threshold() || req.TotalShares != api.tssManager.TotalShares() {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "config mismatch",
				fmt.Sprintf("threshold/totalShares cannot be set via RPC; the TSS manager is already configured with %d-of-%d — reconfigure the node instead",
					api.tssManager.Threshold(), api.tssManager.TotalShares()))
		}
	}

	shares, err := api.tssManager.GenerateKeyShares()
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "DKG failed", err.Error())
	}

	salt, err := shareHashSalt()
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "salt generation failed", err.Error())
	}
	saltHex := hex.EncodeToString(salt)
	result := make([]map[string]any, len(shares))
	for i, s := range shares {
		result[i] = map[string]any{
			"index":              s.Index,
			"shareHash":          "0x" + hashShare(s.Share, salt),
			"shareHashAlgorithm": "sha3-256",
			"shareHashSalt":      "0x" + saltHex,
			"verificationVector": encodeVerificationVector(s.VerificationVector),
		}
	}

	pubKey := api.tssManager.GroupPublicKey()

	return map[string]any{
		"success":       true,
		"publicKey":     "0x" + hex.EncodeToString(pubKey),
		"threshold":     api.tssManager.Threshold(),
		"totalShares":   api.tssManager.TotalShares(),
		"shareHashSalt": "0x" + saltHex,
		"shares":        result,
	}, nil
}

func (api *TSSAPI) GetPublicKey(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.tssManager == nil {
		return nil, NewError(ErrCodeInternal, "TSS manager not initialized")
	}

	pubKey := api.tssManager.GroupPublicKey()
	if pubKey == nil {
		return nil, NewError(ErrCodeInternal, "no public key available — run qau_tss_generateKeyShares first")
	}

	return map[string]any{
		"publicKey": "0x" + hex.EncodeToString(pubKey),
	}, nil
}

func (api *TSSAPI) GetShare(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.tssManager == nil {
		return nil, NewError(ErrCodeInternal, "TSS manager not initialized")
	}

	var req struct {
		ParticipantID int `json:"participantId"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		var arr []json.RawMessage
		if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 1 {
			if err3 := json.Unmarshal(arr[0], &req); err3 != nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
			}
		} else {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
		}
	}

	// SECURITY (audit P0-): Raw share export restricted to devMode
	if !api.devMode {
		return nil, NewError(ErrCodeUnauthorized, "qau_tss_getShare is only available in devMode (ChainID=1333) — raw share export is disabled in production for security")
	}

	share, err := api.tssManager.GetShare(req.ParticipantID)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeNotFound, "share not found", err.Error())
	}

	// TSS-FIX: Audit-log every successful share export — who (caller
	// identity is enforced by AdminMethod gateway upstream), when, and which
	// participant's share was queried. The share itself is never logged.
	// R19-F06: one salt per call, returned with the response so the audit
	// log and the caller can re-derive the SAME hash.
	salt, err := shareHashSalt()
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "salt generation failed", err.Error())
	}
	shareHash := hashShare(share.Share, salt)
	log.Printf("[SECURITY AUDIT] qau_tss_getShare participantId=%d shareIndex=%d hash=%s salt=%s",
		req.ParticipantID, share.Index, shareHash, hex.EncodeToString(salt))

	return map[string]any{
		"index":              share.Index,
		"shareHash":          "0x" + shareHash,
		"shareHashSalt":      "0x" + hex.EncodeToString(salt),
		"shareHashAlgorithm": "sha3-256",
		"verificationVector": encodeVerificationVector(share.VerificationVector),
	}, nil
}

type signMessageRequest struct {
	Message        string `json:"message"`
	ParticipantIDs []int  `json:"participantIds"`
}

func (api *TSSAPI) SignMessage(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.tssManager == nil {
		return nil, NewError(ErrCodeInternal, "TSS manager not initialized")
	}

	var req signMessageRequest
	if err := json.Unmarshal(params, &req); err != nil {
		var arr []json.RawMessage
		if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 1 {
			if err3 := json.Unmarshal(arr[0], &req); err3 != nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
			}
		} else {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
		}
	}

	if req.Message == "" {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing message", "message is required")
	}
	// RPC-FIX: Cap the message size at the RPC boundary to prevent a
	// single admin-authenticated (or devMode) request from triggering
	// threshold-signing on a multi-megabyte payload, which would burn
	// CPU/memory/network across all participants. Per-key rate limiting
	// cannot mitigate single-request resource exhaustion.
	// Limit applies to the raw request string; a hex-encoded 1MB payload is
	// 2MB of hex chars, so cap at 2MB of string + 2-char "0x" prefix slack.
	const maxSignMessageBytes = 1 << 20 // 1 MiB decoded
	if len(req.Message) > maxSignMessageBytes*2+2 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "message too large",
			"message must be at most 1MB (decoded); hex-encoded input must be at most ~2MB")
	}
	if len(req.ParticipantIDs) == 0 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing participantIds",
			"at least one participant is required")
	}
	// RPC-FIX: Cap the participant IDs array length at the RPC boundary
	// to prevent a single request from triggering explosion of internal
	// iteration/communication overhead in SignWithRetry.
	const maxParticipantIDs = 100
	if len(req.ParticipantIDs) > maxParticipantIDs {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "too many participant IDs",
			fmt.Sprintf("participant IDs must be at most %d", maxParticipantIDs))
	}
	// RPC-FIX: Validate each participant ID is within [0, TotalShares-1]
	// at the RPC boundary to prevent out-of-range access in tssManager.GetShare
	// and to surface a clearer error to the caller.
	total := api.tssManager.TotalShares()
	if total > 0 {
		for _, id := range req.ParticipantIDs {
			if id < 0 || id >= total {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "participant ID out of range",
					fmt.Sprintf("participant ID %d is outside [0, %d]", id, total-1))
			}
		}
	}

	var message []byte
	if strings.HasPrefix(req.Message, "0x") {
		var err error
		message, err = hex.DecodeString(req.Message[2:])
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hex message", err.Error())
		}
	} else {
		message = []byte(req.Message)
	}

	signature, err := api.tssManager.SignWithRetry(message, req.ParticipantIDs)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "threshold signing failed", err.Error())
	}

	return map[string]any{
		"success":          true,
		"signature":        "0x" + hex.EncodeToString(signature),
		"signatureSize":    len(signature),
		"participantCount": len(req.ParticipantIDs),
	}, nil
}

func (api *TSSAPI) VerifySignature(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.tssManager == nil {
		return nil, NewError(ErrCodeInternal, "TSS manager not initialized")
	}

	var req struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		var arr []json.RawMessage
		if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 1 {
			if err3 := json.Unmarshal(arr[0], &req); err3 != nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
			}
		} else {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
		}
	}

	if req.Message == "" || req.Signature == "" {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing required fields",
			"message and signature are required")
	}

	// R32-P2-02 FIX (2026-07-28): Cap signature size at 64 KiB. A legitimate
	// TSS combined signature is far smaller (Dilithium3 = 3293 bytes; the
	// aggregated form is a constant multiple). 64 KiB is a generous upper
	// bound that rejects multi-MB attacker-crafted signatures which would
	// otherwise burn CPU in VerifyCombinedSignature. Mirrors the existing
	// maxSignMessageBytes cap on the sign path (qtd_api.go:234).
	const maxVerifySignatureBytes = 1 << 16 // 64 KiB
	sigTrimmed := strings.TrimPrefix(req.Signature, "0x")
	if len(sigTrimmed) > maxVerifySignatureBytes*2 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "signature too large",
			"signature hex input must be at most 128 KiB (64 KiB decoded)")
	}
	signature, err := hex.DecodeString(sigTrimmed)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid signature hex", err.Error())
	}

	var message []byte
	if strings.HasPrefix(req.Message, "0x") {
		// R32-P2-02: Apply the same 1 MiB cap as the sign path
		// (maxSignMessageBytes at qtd_api.go:234). Previously the verify
		// path skipped this check, allowing a multi-MB message to reach
		// VerifyCombinedSignature.
		const maxVerifyMessageBytes = 1 << 20 // 1 MiB decoded
		msgTrimmed := req.Message[2:]
		if len(msgTrimmed) > maxVerifyMessageBytes*2 {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "message too large",
				"message must be at most 1MB (decoded); hex-encoded input must be at most ~2MB")
		}
		message, err = hex.DecodeString(msgTrimmed)
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hex message", err.Error())
		}
	} else {
		message = []byte(req.Message)
	}

	err = api.tssManager.VerifyCombinedSignature(signature, message)
	if err != nil {
		// RPC-M5 (R8 2026-07-19 FIX): Distinguish "signature is invalid"
		// (the expected negative result of a verification call) from
		// "TSS infrastructure is broken" (e.g. group public key not
		// loaded, public key too short, internal panic). Previously
		// every error was returned as {valid: false, message: err.Error()}
		// with a nil RPC error, conflating the two cases and bypassing
		// the sanitizeError pipeline so internal error details leaked in
		// the response. Monitoring on RPC error rates also could not
		// catch category (b) because the response was HTTP 200.
		//
		// Classification:
		//   - ErrSignatureVerificationFailed: the signature failed
		//     Dilithium3/GM-QTD verification. This is the expected
		//     negative result; return {valid: false} as a successful
		//     RPC response (nil error).
		//   - ErrInsufficientShares (group public key not loaded):
		//     infrastructure error. Return ErrCodeInternal so it flows
		//     through sanitizeError and is visible in monitoring.
		//   - Any other error: treat as infrastructure error.
		if errors.Is(err, tss.ErrSignatureVerificationFailed) {
			return map[string]any{
				"valid": false,
			}, nil
		}
		// Infrastructure error — surface as RPC error so monitoring
		// sees it and sanitizeError strips internal details in
		// production mode.
		return nil, NewErrorWithData(ErrCodeInternal, "TSS verification infrastructure error", err.Error())
	}

	return map[string]any{
		"valid": true,
	}, nil
}

func (api *TSSAPI) Status(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.tssManager == nil {
		return nil, NewError(ErrCodeInternal, "TSS manager not initialized")
	}

	pubKey := api.tssManager.GroupPublicKey()
	hasKey := pubKey != nil

	result := map[string]any{
		"initialized":  hasKey,
		"threshold":    api.tssManager.Threshold(),
		"totalShares":  api.tssManager.TotalShares(),
		"shareCount":   api.tssManager.ShareCount(),
		"hasThreshold": api.tssManager.HasThreshold(),
	}

	if hasKey {
		result["publicKey"] = "0x" + hex.EncodeToString(pubKey)
	}

	return result, nil
}

func encodeVerificationVector(vv [][]byte) []string {
	if vv == nil {
		return nil
	}
	result := make([]string, len(vv))
	for i, v := range vv {
		result[i] = "0x" + hex.EncodeToString(v)
	}
	return result
}
