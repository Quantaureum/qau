// Quantaureum Node source, version 1.0.0.
// Package rpc implements the JSON-RPC 2.0 server for Quantaureum.
// This file provides sharding RPC methods (qau_shard*).
//
// P1-3 (2026-07-14): Exposes the shard subsystem state via 8 read-only RPC
// methods + 1 admin-gated method for submitting cross-shard messages.
// All methods return -32601 when sharding is not enabled on this node.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

// ShardAPI exposes the sharding subsystem via JSON-RPC.
//
// P1-3 (2026-07-14): manager may be nil when sharding is disabled
// (QAU_ENABLE_SHARDING != "1"). Every method handles nil safely by
// returning -32601 "sharding not available".
type ShardAPI struct {
	manager *consensus.ShardManager
}

// NewShardAPI creates a ShardAPI. manager may be nil when sharding is
// disabled; every method handles nil safely.
func NewShardAPI(manager *consensus.ShardManager) *ShardAPI {
	return &ShardAPI{manager: manager}
}

// RegisterHandlers registers all shard API handlers on the given server.
func (api *ShardAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("qau_shardGetShardCount", api.GetShardCount)
	server.RegisterHandler("qau_shardGetActiveShardCount", api.GetActiveShardCount)
	server.RegisterHandler("qau_shardGetShard", api.GetShard)
	server.RegisterHandler("qau_shardGetBlock", api.GetBlock)
	server.RegisterHandler("qau_shardGetCommitment", api.GetCommitment)
	server.RegisterHandler("qau_shardSubmitCrossShardMessage", api.SubmitCrossShardMessage)
	server.RegisterHandler("qau_shardGetReceipt", api.GetReceipt)
	server.RegisterHandler("qau_shardIsReceiptSpent", api.IsReceiptSpent)

	// Admin-gate the state-mutating method.
	server.RegisterAdminMethod("qau_shardSubmitCrossShardMessage")
}

// --- Read-only query methods ---

// GetShardCount returns the total number of shards (active + inactive).
// RPC: qau_shardGetShardCount (read-only, no params)
func (api *ShardAPI) GetShardCount(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.manager == nil {
		return nil, &Error{Code: -32601, Message: "sharding not available (disabled)"}
	}
	return api.manager.GetShardCount(), nil
}

// GetActiveShardCount returns the number of active shards.
// RPC: qau_shardGetActiveShardCount (read-only, no params)
func (api *ShardAPI) GetActiveShardCount(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.manager == nil {
		return nil, &Error{Code: -32601, Message: "sharding not available (disabled)"}
	}
	return api.manager.GetActiveShardCount(), nil
}

// GetShard returns information about a specific shard.
// RPC: qau_shardGetShard (read-only, params: {shardId})
func (api *ShardAPI) GetShard(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.manager == nil {
		return nil, &Error{Code: -32601, Message: "sharding not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		ShardID uint64 `json:"shardId"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	chain, err := api.manager.GetShard(req.ShardID)
	if err != nil {
		return nil, &Error{Code: -32601, Message: err.Error()}
	}

	validators := chain.Validators()
	valHex := make([]string, len(validators))
	for i, v := range validators {
		valHex[i] = "0x" + hex.EncodeToString(v[:])
	}

	assignment, _ := api.manager.GetAssignment(req.ShardID)

	result := map[string]any{
		"shardId":      chain.ShardID(),
		"status":       chain.Status().String(),
		"validators":   valHex,
		"latestHeight": chain.LatestHeight(),
		"epoch":        chain.Epoch(),
	}
	if assignment != nil {
		result["assignmentEpoch"] = assignment.Epoch
	}
	return result, nil
}

// GetBlock returns a shard block by height.
// RPC: qau_shardGetBlock (read-only, params: {shardId, height})
func (api *ShardAPI) GetBlock(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.manager == nil {
		return nil, &Error{Code: -32601, Message: "sharding not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		ShardID uint64 `json:"shardId"`
		Height  uint64 `json:"height"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	chain, err := api.manager.GetShard(req.ShardID)
	if err != nil {
		return nil, &Error{Code: -32601, Message: err.Error()}
	}

	block, err := chain.GetBlock(req.Height)
	if err != nil {
		return nil, &Error{Code: -32601, Message: err.Error()}
	}

	return shardBlockToMap(block), nil
}

// GetCommitment returns the shard commitment for a given block height.
// RPC: qau_shardGetCommitment (read-only, params: {shardId, height})
func (api *ShardAPI) GetCommitment(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.manager == nil {
		return nil, &Error{Code: -32601, Message: "sharding not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		ShardID uint64 `json:"shardId"`
		Height  uint64 `json:"height"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	chain, err := api.manager.GetShard(req.ShardID)
	if err != nil {
		return nil, &Error{Code: -32601, Message: err.Error()}
	}

	commitment, exists := chain.GetCommitment(req.Height)
	if !exists {
		return nil, &Error{Code: -32601, Message: "commitment not found for height"}
	}

	return map[string]any{
		"shardId":    req.ShardID,
		"height":     req.Height,
		"commitment": "0x" + hex.EncodeToString(commitment[:]),
	}, nil
}

// --- Cross-shard message methods ---

// SubmitCrossShardMessage submits a cross-shard message to the source shard.
// RPC: qau_shardSubmitCrossShardMessage (admin-gated, params: message fields)
func (api *ShardAPI) SubmitCrossShardMessage(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.manager == nil {
		return nil, &Error{Code: -32601, Message: "sharding not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		SourceShard uint64 `json:"sourceShard"`
		DestShard   uint64 `json:"destShard"`
		Sender      string `json:"sender"`
		Recipient   string `json:"recipient"`
		Payload     string `json:"payload"`
		Nonce       uint64 `json:"nonce"`
		Timestamp   uint64 `json:"timestamp"`
		Signature   string `json:"signature"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	// Parse hex-encoded fields.
	sender, err := parseHexAddress(req.Sender)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid sender address: " + err.Error()}
	}
	recipient, err := parseHexAddress(req.Recipient)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid recipient address: " + err.Error()}
	}
	payload, err := parseHexBytes(req.Payload)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid payload: " + err.Error()}
	}
	signature, err := parseHexBytes(req.Signature)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid signature: " + err.Error()}
	}

	// RPC-FIX: Reject cross-shard messages with timestamps too far from
	// the current wall-clock. Without this check, an attacker can set
	// msg.Timestamp to a far-future value to bypass any future-window check
	// inside the engine, or to a far-past value to have the message
	// misclassified as expired. ±5 minutes is the same skew used by fraud
	// proof freshness (RPC-) and is tolerant of clock drift across nodes.
	const crossShardMsgMaxSkewSeconds uint64 = 300
	now := uint64(time.Now().Unix())
	if req.Timestamp > now+crossShardMsgMaxSkewSeconds {
		return nil, &Error{Code: -32602, Message: "timestamp too far in the future (must be within ±5 minutes of current time)"}
	}
	if req.Timestamp+crossShardMsgMaxSkewSeconds < now {
		return nil, &Error{Code: -32602, Message: "timestamp too far in the past (must be within ±5 minutes of current time)"}
	}

	chain, err := api.manager.GetShard(req.SourceShard)
	if err != nil {
		return nil, &Error{Code: -32601, Message: err.Error()}
	}

	msg := &consensus.CrossShardMessage{
		SourceShard: req.SourceShard,
		DestShard:   req.DestShard,
		Sender:      sender,
		Recipient:   recipient,
		Payload:     payload,
		Nonce:       req.Nonce,
		Timestamp:   req.Timestamp,
		Signature:   signature,
	}
	// Compute the canonical message ID (same as SubmitCrossShardMessage does internally).
	// HIGH-17: canonical ID is derived from (source, dest, sender, nonce) so a forged
	// ID field cannot bypass the monotonic nonce check.
	msg.ID = consensus.GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)

	if err := chain.SubmitCrossShardMessage(msg); err != nil {
		return nil, &Error{Code: -32603, Message: "submit failed: " + err.Error()}
	}

	return map[string]any{
		"messageId": "0x" + hex.EncodeToString(msg.ID[:]),
		"accepted":  true,
	}, nil
}

// GetReceipt returns a cross-shard receipt by message ID.
// RPC: qau_shardGetReceipt (read-only, params: {shardId, messageId})
func (api *ShardAPI) GetReceipt(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.manager == nil {
		return nil, &Error{Code: -32601, Message: "sharding not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		ShardID   uint64 `json:"shardId"`
		MessageID string `json:"messageId"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	msgID, err := parseHexHash(req.MessageID)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid messageId: " + err.Error()}
	}

	chain, err := api.manager.GetShard(req.ShardID)
	if err != nil {
		return nil, &Error{Code: -32601, Message: err.Error()}
	}

	receipt, err := chain.GetReceipt(msgID)
	if err != nil {
		return nil, &Error{Code: -32601, Message: err.Error()}
	}

	return crossShardReceiptToMap(receipt), nil
}

// IsReceiptSpent checks whether a cross-shard receipt has been spent.
// RPC: qau_shardIsReceiptSpent (read-only, params: {shardId, messageId})
func (api *ShardAPI) IsReceiptSpent(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.manager == nil {
		return nil, &Error{Code: -32601, Message: "sharding not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		ShardID   uint64 `json:"shardId"`
		MessageID string `json:"messageId"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	msgID, err := parseHexHash(req.MessageID)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid messageId: " + err.Error()}
	}

	chain, err := api.manager.GetShard(req.ShardID)
	if err != nil {
		return nil, &Error{Code: -32601, Message: err.Error()}
	}

	return chain.IsReceiptSpent(msgID), nil
}

// --- Helpers ---

// shardBlockToMap converts a ShardBlock to a JSON-serializable map.
func shardBlockToMap(block *consensus.ShardBlock) map[string]any {
	h := block.Header
	result := map[string]any{
		"shardId":       h.ShardID,
		"height":        h.Height,
		"parentHash":    "0x" + hex.EncodeToString(h.ParentHash[:]),
		"stateRoot":     "0x" + hex.EncodeToString(h.StateRoot[:]),
		"txRoot":        "0x" + hex.EncodeToString(h.TxRoot[:]),
		"crossMsgRoot":  "0x" + hex.EncodeToString(h.CrossMsgRoot[:]),
		"timestamp":     h.Timestamp,
		"proposer":      "0x" + hex.EncodeToString(h.Proposer[:]),
		"signature":     "0x" + hex.EncodeToString(h.Signature),
		"finalized":     block.Finalized,
		"txCount":       len(block.Txs),
		"crossMsgCount": len(block.CrossMsgs),
	}
	if len(h.VRFProof) > 0 {
		result["vrfProof"] = "0x" + hex.EncodeToString(h.VRFProof)
	}
	result["vrfOutput"] = "0x" + hex.EncodeToString(h.VRFOutput[:])
	return result
}

// crossShardReceiptToMap converts a CrossShardReceipt to a JSON-serializable map.
func crossShardReceiptToMap(r *consensus.CrossShardReceipt) map[string]any {
	return map[string]any{
		"messageId":   "0x" + hex.EncodeToString(r.MessageID[:]),
		"sourceShard": r.SourceShard,
		"destShard":   r.DestShard,
		"txHash":      "0x" + hex.EncodeToString(r.TxHash[:]),
		"blockHeight": r.BlockHeight,
		"relayed":     r.Relayed,
		"relayedAt":   r.RelayedAt,
		"spent":       r.Spent,
		"spentAt":     r.SpentAt,
	}
}

// parseHexAddress parses a hex-encoded address string (with or without 0x prefix).
// SHRD- (2026-07-17): Strict length check — a valid address is exactly
// 20 bytes. Previously, overlong inputs were silently truncated and short
// inputs were zero-padded, which could cause address/ID confusion or
// misleading success responses. Now returns an error for any length != 20.
func parseHexAddress(s string) (types.Address, error) {
	s = stripHexPrefix(s)
	var addr types.Address
	b, err := hex.DecodeString(s)
	if err != nil {
		return addr, err
	}
	if len(b) != len(addr) {
		return addr, fmt.Errorf("invalid address length: got %d bytes, want %d", len(b), len(addr))
	}
	copy(addr[:], b)
	return addr, nil
}

// parseHexHash parses a hex-encoded hash string (with or without 0x prefix).
// SHRD- (2026-07-17): Strict length check — a valid hash is exactly
// 32 bytes. Previously, overlong inputs were silently truncated and short
// inputs were zero-padded, which could cause address/ID confusion or
// misleading success responses. Now returns an error for any length != 32.
func parseHexHash(s string) (types.Hash, error) {
	s = stripHexPrefix(s)
	var hash types.Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return hash, err
	}
	if len(b) != len(hash) {
		return hash, fmt.Errorf("invalid hash length: got %d bytes, want %d", len(b), len(hash))
	}
	copy(hash[:], b)
	return hash, nil
}
