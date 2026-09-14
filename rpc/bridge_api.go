// Quantaureum Node source, version 1.0.0.
// Package rpc implements the JSON-RPC 2.0 server for Quantaureum.
// This file provides cross-chain bridge RPC methods (qau_bridge*).

package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/quantaureum/qau/bridge"
	"github.com/quantaureum/qau/types"
)

// lockRefunder is the narrow interface required for admin-triggered lock
// refunds. It is satisfied by *bridge.AssetLockManager, and is defined here
// (rather than importing the concrete type) to keep the rpc package
// decoupled from bridge internals.
type lockRefunder interface {
	RefundFailedLockAuthorized(ctx context.Context, lockID string, caller types.Address) error
}

// BridgeAPI exposes cross-chain bridge state via JSON-RPC.
// All methods return -32601 when the bridge is not enabled on this node.
type BridgeAPI struct {
	bridge   bridge.Bridge
	config   *bridge.BridgeConfig
	refunder lockRefunder // nil when bridge asset lock is unavailable
}

// NewBridgeAPI creates a BridgeAPI. The bridge and config arguments may be
// nil when the bridge feature is disabled; every read method handles nil
// safely. The refunder argument enables the admin-only
// qau_bridgeRefundFailedLock method; pass nil to disable it.
func NewBridgeAPI(b bridge.Bridge, cfg *bridge.BridgeConfig, refunder lockRefunder) *BridgeAPI {
	return &BridgeAPI{bridge: b, config: cfg, refunder: refunder}
}

// RegisterHandlers registers all bridge API handlers on the given server.
func (api *BridgeAPI) RegisterHandlers(server *Server) {
	// R12-RPC-001 FIX: Register bridge handlers with appropriate access control.
	// GetPendingTransfers exposes operational/financial data, so register it
	// as an admin method via the server's adminMethodRegistry.
	server.RegisterHandler("qau_bridgeGetStatus", api.GetStatus)
	server.RegisterHandler("qau_bridgeGetPendingTransfers", api.GetPendingTransfers)
	server.RegisterHandler("qau_bridgeGetSupportedChains", api.GetSupportedChains)
	// Mark GetPendingTransfers as admin-only so the server's auth middleware
	// enforces authentication before dispatching.
	server.RegisterAdminMethod("qau_bridgeGetPendingTransfers")

	// R35-P3-BRIDGE-01 FIX (2026-07-30): Expose an admin-only refund RPC so
	// operators can manually release funds stuck in Failed lock status when
	// the automatic relayer cannot complete the refund (e.g. due to a
	// transient adapter outage). This is registered as an admin method
	// and additionally checks operator authorization at the bridge layer.
	if api.refunder != nil {
		server.RegisterHandler("qau_bridgeRefundFailedLock", api.RefundFailedLock)
		server.RegisterAdminMethod("qau_bridgeRefundFailedLock")
	}
}

// GetStatus returns the overall bridge status.
// RPC: qau_bridgeGetStatus
func (api *BridgeAPI) GetStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.bridge == nil {
		return nil, &Error{Code: -32601, Message: "bridge not available (disabled)"}
	}

	pendingCount := 0
	if pending, err := api.bridge.GetMessagesByStatus(ctx, bridge.MessageStatusPending); err == nil {
		pendingCount = len(pending)
	}

	chainCount := 0
	if api.config != nil {
		chainCount = len(api.config.NodeURLs)
	}

	return map[string]any{
		"enabled":         true,
		"pendingMessages": pendingCount,
		"supportedChains": chainCount,
	}, nil
}

// GetPendingTransfers returns all pending cross-chain transfer messages.
// RPC: qau_bridgeGetPendingTransfers
// RPC-FIX: Add pagination (offset, limit) to bound response size and
// prevent a single admin call from materializing the entire pending queue
// (which could be thousands of entries / tens of MB) into memory and the
// JSON response.
func (api *BridgeAPI) GetPendingTransfers(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.bridge == nil {
		return nil, &Error{Code: -32601, Message: "bridge not available (disabled)"}
	}

	// Pagination defaults / caps. Limit is capped at maxBridgePendingLimit to
	// bound single-response size; offset is non-negative.
	const (
		defaultBridgePendingLimit = 50
		maxBridgePendingLimit     = 100
	)
	var req struct {
		Offset int `json:"offset"`
		Limit  int `json:"limit"`
	}
	if len(params) > 0 {
		// R35-P3-RPC-01 FIX (2026-07-30): Previously this used `_ = json.Unmarshal`
		// which silently ignored malformed params (violating the project rule
		// against silent error ignoring). Malformed JSON now logs a warning so
		// operators can detect malformed client requests, while the best-effort
		// fallback to zero values (which sanitizePagination clamps to defaults)
		// is preserved to avoid a hard error on backwards-compatible params.
		if err := json.Unmarshal(params, &req); err != nil {
			log.Printf("[WARN] bridge: malformed pagination params in qau_bridgeGetPendingTransfers: %v", err)
		}
	}

	// P2P-R10-M2 (2026-07-19) FIX: Unified pagination bounds check via
	// sanitizePagination. Previously used inline clamps that missed an
	// upper bound on offset (allowing math.MaxInt64 to reach the slicing
	// path, which on 32-bit builds could overflow `offset + limit`).
	req.Limit, req.Offset = sanitizePagination(req.Limit, req.Offset, defaultBridgePendingLimit, maxBridgePendingLimit)

	messages, err := api.bridge.GetMessagesByStatus(ctx, bridge.MessageStatusPending)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	total := len(messages)
	start := req.Offset
	if start > total {
		start = total
	}
	end := start + req.Limit
	if end > total {
		end = total
	}
	page := messages[start:end]

	result := make([]map[string]any, 0, len(page))
	for _, msg := range page {
		result = append(result, bridgeMessageToMap(msg))
	}
	return map[string]any{
		"transfers": result,
		"total":     total,
		"offset":    start,
		"limit":     req.Limit,
	}, nil
}

// GetSupportedChains returns the list of chain IDs the bridge can relay to.
// RPC: qau_bridgeGetSupportedChains
func (api *BridgeAPI) GetSupportedChains(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.bridge == nil {
		return nil, &Error{Code: -32601, Message: "bridge not available (disabled)"}
	}

	chains := make([]string, 0)
	if api.config != nil {
		for chainID := range api.config.NodeURLs {
			chains = append(chains, string(chainID))
		}
	}
	return map[string]any{
		"chains": chains,
		"count":  len(chains),
	}, nil
}

// RefundFailedLock manually triggers a refund for a lock stuck in Failed
// status. This is an admin-only emergency tool for operators when the
// automatic relayer cannot complete the refund.
// RPC: qau_bridgeRefundFailedLock
//
// Params: {"lockId": "...", "caller": "0x..."}
//
// Security model:
//  1. Registered as AdminMethod → server enforces HMAC auth before dispatch.
//  2. The caller address is parsed from params and passed to the bridge
//     layer, which independently verifies that caller is in the
//     authorizedOperators set (fail-closed when no operators are configured).
//  3. All refund attempts are logged with lockID + caller for audit trail.
func (api *BridgeAPI) RefundFailedLock(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.bridge == nil || api.refunder == nil {
		return nil, &Error{Code: -32601, Message: "bridge refund not available (disabled)"}
	}

	var req struct {
		LockID string `json:"lockId"`
		Caller string `json:"caller"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	if req.LockID == "" {
		return nil, &Error{Code: -32602, Message: "lockId is required"}
	}
	caller, err := types.ParseHexAddress(req.Caller)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid caller address: " + err.Error()}
	}

	// Security audit log: record every refund attempt (success or failure).
	log.Printf("[SECURITY AUDIT] qau_bridgeRefundFailedLock lockId=%s caller=%s",
		req.LockID, caller.ToHexAddress())

	if err := api.refunder.RefundFailedLockAuthorized(ctx, req.LockID, caller); err != nil {
		log.Printf("[SECURITY] qau_bridgeRefundFailedLock FAILED lockId=%s caller=%s err=%v",
			req.LockID, caller.ToHexAddress(), err)
		return nil, &Error{Code: -32000, Message: fmt.Sprintf("refund failed: %v", err)}
	}

	log.Printf("[SECURITY AUDIT] qau_bridgeRefundFailedLock SUCCESS lockId=%s caller=%s",
		req.LockID, caller.ToHexAddress())

	return map[string]any{
		"success": true,
		"lockId":  req.LockID,
	}, nil
}

// bridgeMessageToMap converts a BridgeMessage to a JSON-friendly map.
//
// RPC- DOC: The "amount" field exposes per-message financial data.
// This is acceptable because qau_bridgeGetPendingTransfers is registered as
// an admin-only method (see RegisterHandlers → RegisterAdminMethod), so only
// authenticated admin callers can reach this path. A masked variant is not
// provided because operational triage of pending transfers requires the
// exact amount. If a future compliance regime requires masking for
// non-super-admin roles, wrap this function with a role-based view.
func bridgeMessageToMap(msg *bridge.BridgeMessage) map[string]any {
	if msg == nil {
		return nil
	}
	return map[string]any{
		"id":            msg.ID,
		"sourceChain":   string(msg.SourceChain),
		"targetChain":   string(msg.TargetChain),
		"sourceAddress": msg.SourceAddress,
		"targetAddress": msg.TargetAddress,
		"assetType":     string(msg.AssetType),
		"amount":        msg.Amount,
		"nonce":         msg.Nonce,
		"timestamp":     msg.Timestamp,
		"status":        string(msg.Status),
		"messageType":   string(msg.MessageType),
	}
}
