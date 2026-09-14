// Quantaureum Node source, version 1.0.0.
// Package rpc implements the JSON-RPC 2.0 server for Quantaureum.
// This file provides L2 rollup RPC methods (qau_rollup*).

package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/rollup"
	"github.com/quantaureum/qau/types"
)

// RollupAPI exposes L2 rollup state via JSON-RPC.
// All methods return -32601 when the rollup engine is not enabled.
type RollupAPI struct {
	engine *rollup.RollupEngine
}

// NewRollupAPI creates a RollupAPI. engine may be nil when the rollup
// feature is disabled; every method handles nil safely.
func NewRollupAPI(engine *rollup.RollupEngine) *RollupAPI {
	return &RollupAPI{engine: engine}
}

// RegisterHandlers registers all rollup API handlers on the given server.
func (api *RollupAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("qau_rollupGetStatus", api.GetStatus)
	server.RegisterHandler("qau_rollupGetBatch", api.GetBatch)
	server.RegisterHandler("qau_rollupGetStateRoot", api.GetStateRoot)
	// W-P1-2 FIX (2026-07-13): L2 transaction submission channel. Marked as
	// admin-only because it mutates L2 state (sequencer tx queue). Wallets
	// submit pre-signed L2 transactions via this method.
	server.RegisterHandler("qau_rollupSendRawTransaction", api.SendRawTransaction)
	server.RegisterAdminMethod("qau_rollupSendRawTransaction")
	// W-P1-4 FIX (2026-07-13): L1 anchor query for challengers. Read-only —
	// returns the anchor record (postStateRoot, txDataHash, submitHeight) for
	// a given batch hash, enabling challengers to verify batch integrity.
	server.RegisterHandler("qau_rollupGetAnchor", api.GetAnchor)
	// AUDIT (2026) RLLP-FIX (CRITICAL): Challenger entry point.
	// Accepts a signed fraud proof and forwards it to
	// engine.SubmitFraudProof, which verifies + stores the proof AND
	// immediately transitions the accused batch to Challenged so the
	// finalizeLoop cannot silently finalize it. Admin-only because it
	// mutates L2 batch state (status transition).
	server.RegisterHandler("qau_rollupSubmitFraudProof", api.SubmitFraudProof)
	server.RegisterAdminMethod("qau_rollupSubmitFraudProof")
	// W-P1-6 Phase 3 (2026-07-14): L1↔L2 bridge query methods. All read-only.
	server.RegisterHandler("qau_l1BridgeGetStatus", api.L1BridgeGetStatus)
	server.RegisterHandler("qau_l1BridgeGetLiquidity", api.L1BridgeGetLiquidity)
	server.RegisterHandler("qau_l1BridgeGetDeposit", api.L1BridgeGetDeposit)
	server.RegisterHandler("qau_l1BridgeGetFinalizedStateRoot", api.L1BridgeGetFinalizedStateRoot)
	// W-P1-6 Phase 4 (2026-07-14): On-chain QASM contract deployment + calldata helpers.
	server.RegisterHandler("qau_l1BridgeGetContractBytecode", api.L1BridgeGetContractBytecode)
	server.RegisterHandler("qau_l1BridgeEncodeRecordFinalizedBatch", api.L1BridgeEncodeRecordFinalizedBatch)
}

// GetStatus returns the rollup engine status, statistics, and configuration.
// RPC: qau_rollupGetStatus
func (api *RollupAPI) GetStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}

	status := api.engine.GetStatus()
	totalBatches, totalTxs, uptime := api.engine.GetStats()

	statusStr := "stopped"
	switch status {
	case rollup.RollupStatusRunning:
		statusStr = "running"
	case rollup.RollupStatusPaused:
		statusStr = "paused"
	case rollup.RollupStatusStopping:
		statusStr = "stopping"
	}

	result := map[string]any{
		"status":       statusStr,
		"totalBatches": totalBatches,
		"totalTxs":     totalTxs,
		"uptime":       uptime.String(),
	}

	if bm := api.engine.GetBatchManager(); bm != nil {
		result["pendingTxs"] = bm.PendingTxCount()
	}

	if cfg := api.engine.GetConfig(); cfg != nil {
		result["chainId"] = cfg.ChainID
		result["l1ChainId"] = cfg.L1ChainID
		result["blockTime"] = cfg.BlockTime.String()
	}

	return result, nil
}

// GetBatch returns information about a specific batch by index.
// RPC: qau_rollupGetBatch
// Params: {"index": <batchIndex>}
func (api *RollupAPI) GetBatch(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		Index uint64 `json:"index"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	bm := api.engine.GetBatchManager()
	if bm == nil {
		return nil, &Error{Code: -32601, Message: "batch manager not available"}
	}

	batch, err := bm.GetBatch(req.Index)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	return batchToMap(batch), nil
}

// GetStateRoot returns an L2 state root.
// If batchIndex is provided, returns that batch's post-state root;
// otherwise returns the latest known state root.
// RPC: qau_rollupGetStateRoot
// Params: {"batchIndex": <index>}  (optional)
func (api *RollupAPI) GetStateRoot(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}

	// Try to parse an optional batchIndex parameter.
	hasIndex := false
	var batchIndex uint64
	if len(params) > 0 && string(params) != "null" {
		if unwrapped, rerr := unwrapParams(params); rerr == nil {
			var req struct {
				BatchIndex uint64 `json:"batchIndex"`
			}
			if err := json.Unmarshal(unwrapped, &req); err == nil {
				batchIndex = req.BatchIndex
				hasIndex = true
			}
		}
	}

	if hasIndex {
		sm := api.engine.GetStateManager()
		if sm == nil {
			return nil, &Error{Code: -32601, Message: "state manager not available"}
		}
		root, exists := sm.GetStateRoot(batchIndex)
		if !exists {
			return nil, &Error{Code: -32000, Message: "state root not found for batch index"}
		}
		return map[string]any{
			"batchIndex": batchIndex,
			"stateRoot":  "0x" + hex.EncodeToString(root[:]),
		}, nil
	}

	// No index provided — return the latest state root from the batch manager.
	bm := api.engine.GetBatchManager()
	if bm == nil {
		return nil, &Error{Code: -32601, Message: "batch manager not available"}
	}
	root := bm.GetLastStateRoot()
	return map[string]any{
		"stateRoot": "0x" + hex.EncodeToString(root[:]),
		"latest":    true,
	}, nil
}

// SendRawTransaction submits a pre-signed L2 transaction to the sequencer.
//
// W-P1-2 FIX (2026-07-13): Previously there was no way to submit L2
// transactions via JSON-RPC — the L2 transaction channel was completely
// closed even after verifier injection (W-P1-1). This handler accepts a
// pre-signed L2 transaction and forwards it to engine.SubmitL2Transaction.
//
// RPC: qau_rollupSendRawTransaction (admin-only — mutates L2 state)
//
//	Params: {
//	  "nonce":     <uint64>,
//	  "gasPrice":  <uint64>,
//	  "gasLimit":  <uint64>,
//	  "to":        "0x<hex>",          // recipient address (omit for contract creation)
//	  "value":     "0x<hex>",          // amount in wei (hex string, eth_* convention)
//	  "data":      "0x<hex>",          // calldata (optional)
//	  "from":      "0x<hex>",          // sender address
//	  "chainId":   <uint64>,           // L2 chain ID
//	  "publicKey": "0x<hex>",          // sender's Dilithium3 public key (1952 bytes)
//	  "signature": "0x<hex>"           // Dilithium3 signature over SigningHash()
//	}
//
// Returns: {"txHash": "0x<hex>"}
func (api *RollupAPI) SendRawTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		Nonce     uint64 `json:"nonce"`
		GasPrice  uint64 `json:"gasPrice"`
		GasLimit  uint64 `json:"gasLimit"`
		To        string `json:"to"`
		Value     string `json:"value"`
		Data      string `json:"data"`
		From      string `json:"from"`
		ChainID   uint64 `json:"chainId"`
		PublicKey string `json:"publicKey"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
	}

	// Validate required fields.
	if req.From == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'from' address")
	}
	if req.PublicKey == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'publicKey' (sender Dilithium3 public key required for L2 verification)")
	}
	if req.Signature == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'signature'")
	}

	fromAddr, err := types.ParseHexAddress(req.From)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid 'from' address", err.Error())
	}

	pubKey, perr := decodeHexField(req.PublicKey, "publicKey")
	if perr != nil {
		return nil, perr
	}
	sig, serr := decodeHexField(req.Signature, "signature")
	if serr != nil {
		return nil, serr
	}

	// RLLP-FIX (2026-07-17): Validate Dilithium3 public key and
	// signature lengths immediately after hex decoding, BEFORE constructing
	// the transaction or invoking the sequencer. Previously only
	// SubmitFraudProof had these checks — SendRawTransaction accepted
	// arbitrarily large publicKey/signature payloads, wasting CPU/memory on
	// malformed inputs that would fail signature verification anyway. This
	// also prevents potential panics in crypto.PublicKeyAddressFromBytes
	// when the sequencer validates the transaction.
	if len(pubKey) != crypto.Dilithium3PublicKeySize {
		return nil, NewError(ErrCodeInvalidParams,
			fmt.Sprintf("invalid 'publicKey' length: expected %d bytes (Dilithium3), got %d",
				crypto.Dilithium3PublicKeySize, len(pubKey)))
	}
	if len(sig) != crypto.Dilithium3SignatureSize {
		return nil, NewError(ErrCodeInvalidParams,
			fmt.Sprintf("invalid 'signature' length: expected %d bytes (Dilithium3), got %d",
				crypto.Dilithium3SignatureSize, len(sig)))
	}

	// Build the RollupTransaction.
	tx := &rollup.RollupTransaction{
		Nonce:     req.Nonce,
		GasPrice:  req.GasPrice,
		GasLimit:  req.GasLimit,
		From:      fromAddr,
		ChainID:   req.ChainID,
		Signature: sig,
		PublicKey: pubKey,
	}

	// Optional 'to' (omit for contract creation).
	if req.To != "" && req.To != "0x" {
		toAddr, err := types.ParseHexAddress(req.To)
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid 'to' address", err.Error())
		}
		tx.To = &toAddr
	}

	// Optional 'value' (hex string, like eth_* convention).
	if req.Value != "" && req.Value != "0x" {
		val, ok := new(big.Int).SetString(trim0xRollup(req.Value), 16)
		if !ok {
			return nil, NewError(ErrCodeInvalidParams, "invalid 'value' (expected hex string)")
		}
		tx.Value = val
	}

	// Optional 'data'.
	if req.Data != "" && req.Data != "0x" {
		data, derr := decodeHexField(req.Data, "data")
		if derr != nil {
			return nil, derr
		}
		tx.Data = data
	}

	// Submit to the sequencer (which runs signature verification via the
	// injected verifier from W-P1-1).
	if err := api.engine.SubmitL2Transaction(tx); err != nil {
		return nil, NewError(ErrCodeInternal, fmt.Sprintf("failed to submit L2 transaction: %v", err))
	}

	return map[string]any{
		"txHash": "0x" + hex.EncodeToString(tx.Hash[:]),
		"status": "submitted",
	}, nil
}

// SubmitFraudProof accepts a signed fraud proof from a challenger and submits
// it to the rollup engine. The engine verifies the challenger's signature,
// stores the proof, and immediately transitions the accused batch to
// Challenged so the finalizeLoop cannot finalize it.
//
// AUDIT (2026) RLLP-FIX (CRITICAL): This is the missing challenger
// entry point. Previously there was NO production path to submit a fraud
// proof — the FraudProver.SubmitFraudProof method existed but was never wired
// to an RPC, and even if called directly it did not trigger ChallengeBatch.
// This made the entire optimistic rollup challenge mechanism dead code.
//
// RPC: qau_rollupSubmitFraudProof (admin-only — mutates L2 batch state)
//
//	Params: {
//	  "type":            <uint8>,           // 0=StateTransition, 1=InvalidBatch, 2=DoubleSpend
//	  "batchIndex":      <uint64>,
//	  "challenger":      "0x<hex>",         // challenger address (20 bytes)
//	  "preStateRoot":    "0x<hex>",         // 32 bytes
//	  "postStateRoot":   "0x<hex>",         // 32 bytes
//	  "timestamp":       <int64>,
//	  "challengerSig":   "0x<hex>",         // Dilithium3 signature (3293 bytes)
//	  "challengerPubKey":"0x<hex>",         // Dilithium3 public key (1952 bytes)
//	  "proofData":       "0x<hex>",         // type-specific proof data
//	  "invalidTx": {                        // optional, required for type=0 (StateTransition)
//	    "nonce":     <uint64>,
//	    "gasPrice":  <uint64>,
//	    "gasLimit":  <uint64>,
//	    "to":        "0x<hex>",             // optional
//	    "value":     "0x<hex>",
//	    "data":      "0x<hex>",
//	    "from":      "0x<hex>",
//	    "chainId":   <uint64>,
//	    "publicKey": "0x<hex>",
//	    "signature": "0x<hex>"
//	  }
//	}
//
// Returns: {"status": "challenged", "batchIndex": <uint64>} on success.
func (api *RollupAPI) SubmitFraudProof(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		Type             uint8  `json:"type"`
		BatchIndex       uint64 `json:"batchIndex"`
		Challenger       string `json:"challenger"`
		PreStateRoot     string `json:"preStateRoot"`
		PostStateRoot    string `json:"postStateRoot"`
		Timestamp        int64  `json:"timestamp"`
		ChallengerSig    string `json:"challengerSig"`
		ChallengerPubKey string `json:"challengerPubKey"`
		ProofData        string `json:"proofData"`
		InvalidTx        *struct {
			Nonce     uint64 `json:"nonce"`
			GasPrice  uint64 `json:"gasPrice"`
			GasLimit  uint64 `json:"gasLimit"`
			To        string `json:"to"`
			Value     string `json:"value"`
			Data      string `json:"data"`
			From      string `json:"from"`
			ChainID   uint64 `json:"chainId"`
			PublicKey string `json:"publicKey"`
			Signature string `json:"signature"`
		} `json:"invalidTx"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
	}

	// Validate required fields.
	if req.Challenger == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'challenger' address")
	}
	if req.PreStateRoot == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'preStateRoot'")
	}
	if req.PostStateRoot == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'postStateRoot'")
	}
	if req.ChallengerSig == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'challengerSig'")
	}
	if req.ChallengerPubKey == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'challengerPubKey' (Dilithium3 public key required for challenger verification)")
	}
	if req.Timestamp <= 0 {
		return nil, NewError(ErrCodeInvalidParams, "missing or non-positive 'timestamp'")
	}
	// RPC-FIX: Reject fraud proofs with timestamps too far from the
	// current wall-clock. This prevents replaying a historically valid signed
	// fraud proof (whose Dilithium3 signature binds the timestamp) and forces
	// the engine's own freshness check to be a defense-in-depth backstop.
	const fraudProofMaxSkewSeconds = 300 // ±5 minutes
	now := time.Now().Unix()
	skew := now - req.Timestamp
	if skew < -fraudProofMaxSkewSeconds || skew > fraudProofMaxSkewSeconds {
		return nil, NewError(ErrCodeInvalidParams, "timestamp skew too large (must be within ±5 minutes of current time)")
	}

	// RPC-FIX: Validate that req.Type is a known FraudProofType enum
	// value at the RPC boundary. This surfaces a clearer error to callers
	// than letting an unknown type propagate into the engine's dispatch
	// logic, and prevents proof.Type from being set to an undefined value.
	switch rollup.FraudProofType(req.Type) {
	case rollup.FraudProofTypeStateTransition,
		rollup.FraudProofTypeInvalidBatch,
		rollup.FraudProofTypeDoubleSpend:
		// ok
	default:
		return nil, NewError(ErrCodeInvalidParams,
			fmt.Sprintf("invalid 'type' (must be 0=StateTransition, 1=InvalidBatch, 2=DoubleSpend, got %d)", req.Type))
	}

	challengerAddr, err := types.ParseHexAddress(req.Challenger)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid 'challenger' address", err.Error())
	}

	preRoot, perr := decodeHashField(req.PreStateRoot, "preStateRoot")
	if perr != nil {
		return nil, perr
	}
	postRoot, perr := decodeHashField(req.PostStateRoot, "postStateRoot")
	if perr != nil {
		return nil, perr
	}

	sig, serr := decodeHexField(req.ChallengerSig, "challengerSig")
	if serr != nil {
		return nil, serr
	}
	pubKey, perr := decodeHexField(req.ChallengerPubKey, "challengerPubKey")
	if perr != nil {
		return nil, perr
	}
	proofData, derr := decodeHexField(req.ProofData, "proofData")
	if derr != nil {
		return nil, derr
	}

	// AUDIT (2026) RLLP- defense-in-depth: Validate Dilithium3
	// key/signature lengths at the RPC boundary. Even though the engine's
	// SignatureVerifier would reject malformed keys, this prevents
	// oversized payloads from reaching the verifier (DoS hardening) and
	// catches configuration errors early (fail-closed). Quantaureum uses
	// Dilithium3 exclusively for challenger signatures (no ECDSA fallback).
	if len(pubKey) != crypto.Dilithium3PublicKeySize {
		return nil, NewError(ErrCodeInvalidParams,
			fmt.Sprintf("invalid 'challengerPubKey' length: expected %d bytes (Dilithium3), got %d",
				crypto.Dilithium3PublicKeySize, len(pubKey)))
	}
	if len(sig) != crypto.Dilithium3SignatureSize {
		return nil, NewError(ErrCodeInvalidParams,
			fmt.Sprintf("invalid 'challengerSig' length: expected %d bytes (Dilithium3), got %d",
				crypto.Dilithium3SignatureSize, len(sig)))
	}

	// RPC-FIX: Verify challenger address matches the public key.
	// Without this, an attacker could use their own Dilithium3 key pair but
	// claim a victim's address as the challenger. The signature would verify
	// against the attacker's public key, but the fraud proof's Challenger
	// field would point to the victim — leading to false attribution of
	// challenge responsibility, potential false slashing of the victim, or
	// misdirected challenge rewards.
	derivedAddr := crypto.PublicKeyAddressFromBytes(pubKey)
	if derivedAddr != challengerAddr {
		return nil, NewError(ErrCodeInvalidParams,
			"challenger address does not match the provided public key")
	}

	proof := &rollup.FraudProof{
		Type:             rollup.FraudProofType(req.Type),
		BatchIndex:       req.BatchIndex,
		Challenger:       challengerAddr,
		PreStateRoot:     preRoot,
		PostStateRoot:    postRoot,
		Timestamp:        req.Timestamp,
		ChallengerSig:    sig,
		ChallengerPubKey: pubKey,
		ProofData:        proofData,
	}

	// For StateTransition proofs, the invalid transaction MUST be provided
	// so verifyStateTransitionFraud can re-simulate it.
	if proof.Type == rollup.FraudProofTypeStateTransition {
		if req.InvalidTx == nil {
			return nil, NewError(ErrCodeInvalidParams, "missing 'invalidTx' (required for StateTransition fraud proof)")
		}
		invalidTx, txErr := parseInvalidTx(req.InvalidTx)
		if txErr != nil {
			return nil, txErr
		}
		proof.InvalidTx = invalidTx
	}

	// Forward to the engine's coordinated SubmitFraudProof — this verifies
	// the challenger signature, stores the proof, AND transitions the batch
	// to Challenged atomically (best-effort transition).
	if err := api.engine.SubmitFraudProof(proof); err != nil {
		return nil, NewErrorWithData(ErrCodeInternal,
			fmt.Sprintf("fraud proof rejected: %v", err), err.Error())
	}

	return map[string]any{
		"status":     "challenged",
		"batchIndex": req.BatchIndex,
	}, nil
}

// decodeHashField decodes a 0x-prefixed 32-byte hex string into a types.Hash.
func decodeHashField(s string, fieldName string) (types.Hash, *Error) {
	b, err := hex.DecodeString(trim0xRollup(s))
	if err != nil {
		return types.Hash{}, NewErrorWithData(ErrCodeInvalidParams,
			fmt.Sprintf("invalid '%s' (expected hex string)", fieldName), err.Error())
	}
	if len(b) != types.HashLength {
		return types.Hash{}, NewError(ErrCodeInvalidParams,
			fmt.Sprintf("invalid '%s' (expected %d bytes, got %d)", fieldName, types.HashLength, len(b)))
	}
	var h types.Hash
	copy(h[:], b)
	return h, nil
}

// parseInvalidTx converts the JSON invalidTx object into a RollupTransaction.
func parseInvalidTx(req *struct {
	Nonce     uint64 `json:"nonce"`
	GasPrice  uint64 `json:"gasPrice"`
	GasLimit  uint64 `json:"gasLimit"`
	To        string `json:"to"`
	Value     string `json:"value"`
	Data      string `json:"data"`
	From      string `json:"from"`
	ChainID   uint64 `json:"chainId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}) (*rollup.RollupTransaction, *Error) {
	fromAddr, err := types.ParseHexAddress(req.From)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid invalidTx.from address", err.Error())
	}
	tx := &rollup.RollupTransaction{
		Nonce:    req.Nonce,
		GasPrice: req.GasPrice,
		GasLimit: req.GasLimit,
		From:     fromAddr,
		ChainID:  req.ChainID,
	}
	if req.To != "" && req.To != "0x" {
		toAddr, err := types.ParseHexAddress(req.To)
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid invalidTx.to address", err.Error())
		}
		tx.To = &toAddr
	}
	if req.Value != "" && req.Value != "0x" {
		val, ok := new(big.Int).SetString(trim0xRollup(req.Value), 16)
		if !ok {
			return nil, NewError(ErrCodeInvalidParams, "invalid invalidTx.value (expected hex string)")
		}
		tx.Value = val
	}
	if req.Data != "" && req.Data != "0x" {
		data, derr := decodeHexField(req.Data, "invalidTx.data")
		if derr != nil {
			return nil, derr
		}
		tx.Data = data
	}
	if req.PublicKey != "" {
		pubKey, perr := decodeHexField(req.PublicKey, "invalidTx.publicKey")
		if perr != nil {
			return nil, perr
		}
		// RPC-FIX: Validate Dilithium3 public key length at the RPC
		// boundary for defense-in-depth, consistent with SubmitFraudProof:451.
		if len(pubKey) != crypto.Dilithium3PublicKeySize {
			return nil, NewError(ErrCodeInvalidParams,
				fmt.Sprintf("invalid 'invalidTx.publicKey' length: expected %d bytes (Dilithium3), got %d",
					crypto.Dilithium3PublicKeySize, len(pubKey)))
		}
		tx.PublicKey = pubKey
	}
	if req.Signature != "" {
		sig, serr := decodeHexField(req.Signature, "invalidTx.signature")
		if serr != nil {
			return nil, serr
		}
		// RPC-FIX: Validate Dilithium3 signature length at the RPC
		// boundary for defense-in-depth, consistent with SubmitFraudProof:456.
		if len(sig) != crypto.Dilithium3SignatureSize {
			return nil, NewError(ErrCodeInvalidParams,
				fmt.Sprintf("invalid 'invalidTx.signature' length: expected %d bytes (Dilithium3), got %d",
					crypto.Dilithium3SignatureSize, len(sig)))
		}
		tx.Signature = sig
	}
	return tx, nil
}

// decodeHexField decodes a 0x-prefixed hex string into bytes, returning a
// JSON-RPC error on failure.
//
// R32-P2-02 FIX (2026-07-28): Added 1 MiB decoded-length limit (aligned with
// server.MaxRequestBodySize) to prevent a single hex field from consuming
// excessive memory. Previously this function had no length cap, relying on
// the global MaxParamsLength (64 KiB) for protection.
func decodeHexField(s string, fieldName string) ([]byte, *Error) {
	trimmed := trim0xRollup(s)
	// R32-P2-02: Reject oversized hex inputs before decoding.
	if len(trimmed) > maxParseHexBytesLen {
		return nil, NewErrorWithData(ErrCodeInvalidParams,
			fmt.Sprintf("'%s' too large: %d chars exceeds limit %d", fieldName, len(trimmed), maxParseHexBytesLen), "")
	}
	b, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams,
			fmt.Sprintf("invalid '%s' (expected hex string)", fieldName), err.Error())
	}
	return b, nil
}

// GetAnchor retrieves the L1 anchor record for a given batch hash.
// W-P1-4 FIX (2026-07-13): Enables challengers to verify batch integrity by
// looking up the on-chain anchor (postStateRoot, txDataHash, submitHeight).
//
// RPC: qau_rollupGetAnchor (read-only)
// Params: {"batchHash": "0x<hex>"} or just "0x<hex>" as a string
//
//	Returns: {
//	  "batchHash":       "0x<hex>",
//	  "postStateRoot":   "0x<hex>",
//	  "txDataHash":      "0x<hex>",
//	  "submitHeight":    <uint64>,
//	  "challengeBlocks": <uint64>,
//	  "challengeDeadlineHeight": <uint64>,
//	  "currentHeight":   <uint64>
//	} or {"found": false} if not anchored.
func (api *RollupAPI) GetAnchor(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}

	anchor := api.engine.GetL1Anchor()
	if anchor == nil {
		return map[string]any{
			"enabled": false,
			"message": "L1 anchor not configured",
		}, nil
	}

	// Parse batch hash param (accept both {batchHash: "0x..."} and "0x...").
	var batchHashHex string
	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	// Try object form first.
	var obj struct {
		BatchHash string `json:"batchHash"`
	}
	if err := json.Unmarshal(unwrapped, &obj); err == nil && obj.BatchHash != "" {
		batchHashHex = obj.BatchHash
	} else {
		// Fall back to string form.
		var s string
		if err := json.Unmarshal(unwrapped, &s); err != nil {
			return nil, NewError(ErrCodeInvalidParams, "expected batch hash string or {batchHash: ...}")
		}
		batchHashHex = s
	}
	if batchHashHex == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing batchHash")
	}

	hashBytes, err := hex.DecodeString(trim0xRollup(batchHashHex))
	if err != nil || len(hashBytes) != 32 {
		return nil, NewError(ErrCodeInvalidParams, "invalid batchHash (expected 32-byte hex)")
	}
	var batchHash types.Hash
	copy(batchHash[:], hashBytes)

	record, ok := anchor.GetAnchor(batchHash)
	if !ok {
		return map[string]any{"found": false}, nil
	}

	return map[string]any{
		"found":                   true,
		"batchHash":               "0x" + hex.EncodeToString(record.BatchHash[:]),
		"postStateRoot":           "0x" + hex.EncodeToString(record.PostStateRoot[:]),
		"txDataHash":              "0x" + hex.EncodeToString(record.TxDataHash[:]),
		"submitHeight":            record.SubmitHeight,
		"challengeBlocks":         record.ChallengeBlocks,
		"challengeDeadlineHeight": record.ChallengeDeadlineHeight(),
		"currentHeight":           anchor.GetCurrentHeight(),
	}, nil
}

// trim0xRollup removes the optional 0x/0X prefix from a hex string.
func trim0xRollup(s string) string {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s[2:]
	}
	return s
}

// --- W-P1-6 Phase 3 (2026-07-14): L1↔L2 bridge RPC methods ---

// L1BridgeGetStatus returns the bridge status: bridge address, L1 liquidity,
// and pending withdrawal count.
// RPC: qau_l1BridgeGetStatus (read-only, no params)
func (api *RollupAPI) L1BridgeGetStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}
	l2Bridge := api.engine.GetL2Bridge()
	if l2Bridge == nil {
		return nil, &Error{Code: -32601, Message: "L1↔L2 bridge not configured"}
	}
	l1Bridge := l2Bridge.GetL1Bridge()
	bridgeAddr := l2Bridge.GetBridgeAddress()
	return map[string]any{
		"bridgeAddress":      "0x" + hex.EncodeToString(bridgeAddr[:]),
		"liquidity":          "0x" + l1Bridge.GetLiquidity().Text(16),
		"pendingWithdrawals": len(l2Bridge.GetPendingWithdrawals()),
	}, nil
}

// L1BridgeGetLiquidity returns the total L1 QAU currently locked in the bridge.
// RPC: qau_l1BridgeGetLiquidity (read-only, no params)
// Returns: {"liquidity": "0x<hex>"} — hex-encoded big integer (wei units).
func (api *RollupAPI) L1BridgeGetLiquidity(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}
	l2Bridge := api.engine.GetL2Bridge()
	if l2Bridge == nil {
		return nil, &Error{Code: -32601, Message: "L1↔L2 bridge not configured"}
	}
	l1Bridge := l2Bridge.GetL1Bridge()
	return map[string]any{
		"liquidity": "0x" + l1Bridge.GetLiquidity().Text(16),
	}, nil
}

// L1BridgeGetDeposit returns information about a deposit by its hash.
// RPC: qau_l1BridgeGetDeposit (read-only)
// Params: {"depositHash": "0x<hex>"}
// Returns: deposit details or {"found": false}.
func (api *RollupAPI) L1BridgeGetDeposit(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}
	l2Bridge := api.engine.GetL2Bridge()
	if l2Bridge == nil {
		return nil, &Error{Code: -32601, Message: "L1↔L2 bridge not configured"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		DepositHash string `json:"depositHash"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid params: "+err.Error())
	}
	if req.DepositHash == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'depositHash'")
	}

	hashBytes, err := hex.DecodeString(trim0xRollup(req.DepositHash))
	if err != nil || len(hashBytes) != 32 {
		return nil, NewError(ErrCodeInvalidParams, "invalid depositHash (expected 32-byte hex)")
	}
	var depositHash types.Hash
	copy(depositHash[:], hashBytes)

	l1Bridge := l2Bridge.GetL1Bridge()
	d, ok := l1Bridge.GetDeposit(depositHash)
	if !ok {
		return map[string]any{"found": false}, nil
	}
	return map[string]any{
		"found":     true,
		"hash":      "0x" + hex.EncodeToString(d.Hash[:]),
		"depositor": "0x" + hex.EncodeToString(d.Depositor[:]),
		"amount":    "0x" + d.Amount.Text(16),
		"timestamp": d.Timestamp,
		"minted":    d.Minted,
	}, nil
}

// L1BridgeGetFinalizedStateRoot returns the finalized L2 state root for a
// given batch index. This is the root that Merkle withdrawal proofs are
// verified against.
// RPC: qau_l1BridgeGetFinalizedStateRoot (read-only)
// Params: {"batchIndex": <uint64>}
// Returns: {"found": true, "batchIndex": ..., "stateRoot": "0x..."} or {"found": false}.
func (api *RollupAPI) L1BridgeGetFinalizedStateRoot(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.engine == nil {
		return nil, &Error{Code: -32601, Message: "rollup not available (disabled)"}
	}
	l2Bridge := api.engine.GetL2Bridge()
	if l2Bridge == nil {
		return nil, &Error{Code: -32601, Message: "L1↔L2 bridge not configured"}
	}

	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		BatchIndex uint64 `json:"batchIndex"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid params: "+err.Error())
	}

	l1Bridge := l2Bridge.GetL1Bridge()
	root, ok := l1Bridge.GetFinalizedStateRoot(req.BatchIndex)
	if !ok {
		return map[string]any{"found": false}, nil
	}
	return map[string]any{
		"found":      true,
		"batchIndex": req.BatchIndex,
		"stateRoot":  "0x" + hex.EncodeToString(root[:]),
	}, nil
}

// batchToMap converts a Batch struct to a JSON-friendly map.
func batchToMap(batch *rollup.Batch) map[string]any {
	if batch == nil {
		return nil
	}

	statusStr := "pending"
	switch batch.Status {
	case rollup.BatchStatusSubmitted:
		statusStr = "submitted"
	case rollup.BatchStatusFinalized:
		statusStr = "finalized"
	case rollup.BatchStatusChallenged:
		statusStr = "challenged"
	case rollup.BatchStatusRejected:
		statusStr = "rejected"
	}

	return map[string]any{
		"index":             batch.Index,
		"prevStateRoot":     "0x" + hex.EncodeToString(batch.PrevStateRoot[:]),
		"postStateRoot":     "0x" + hex.EncodeToString(batch.PostStateRoot[:]),
		"txCount":           batch.TxCount,
		"totalGasUsed":      batch.TotalGasUsed,
		"timestamp":         batch.Timestamp,
		"status":            statusStr,
		"batchHash":         "0x" + hex.EncodeToString(batch.BatchHash[:]),
		"submittedAt":       batch.SubmittedAt,
		"finalizedAt":       batch.FinalizedAt,
		"challengeDeadline": batch.ChallengeDeadline,
	}
}

// --- W-P1-6 Phase 4 (2026-07-14): On-chain QASM contract helpers ---

// L1BridgeGetContractBytecode returns the L1Bridge QASM contract deployment
// bytecode. Deploy by sending a transaction with To=nil and Data=bytecode.
// The deployer becomes the contract owner (authorized to call
// recordFinalizedBatch).
//
// RPC: qau_l1BridgeGetContractBytecode (read-only, no params)
// Returns: {"bytecode": "0x<hex>", "bytecodeSize": <int>}
func (api *RollupAPI) L1BridgeGetContractBytecode(ctx context.Context, params json.RawMessage) (any, *Error) {
	// R8-OBS-3 (2026-07-18): L1BridgeBytecode now returns ([]byte, error)
	// instead of panicking on invalid hex. The init-time validation makes
	// this error path theoretically impossible, but we handle it gracefully.
	code, err := rollup.L1BridgeBytecode()
	if err != nil {
		return nil, &Error{Code: -32000, Message: fmt.Sprintf("L1Bridge bytecode decode failed: %v", err)}
	}
	return map[string]any{
		"bytecode":     "0x" + hex.EncodeToString(code),
		"bytecodeSize": len(code),
	}, nil
}

// L1BridgeEncodeRecordFinalizedBatch encodes calldata for the on-chain
// L1Bridge contract's recordFinalizedBatch(uint256, bytes32) function.
// The node operator sends this calldata as a transaction to the deployed
// L1Bridge contract address to sync finalized L2 state roots on-chain.
//
// RPC: qau_l1BridgeEncodeRecordFinalizedBatch (read-only)
// Params: {"batchIndex": <uint64>, "stateRoot": "0x<hex>"}
// Returns: {"calldata": "0x<hex>", "to": "0x<contractAddr>"}
func (api *RollupAPI) L1BridgeEncodeRecordFinalizedBatch(ctx context.Context, params json.RawMessage) (any, *Error) {
	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		BatchIndex uint64 `json:"batchIndex"`
		StateRoot  string `json:"stateRoot"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid params: "+err.Error())
	}
	if req.StateRoot == "" {
		return nil, NewError(ErrCodeInvalidParams, "missing 'stateRoot'")
	}

	rootBytes, err := hex.DecodeString(trim0xRollup(req.StateRoot))
	if err != nil || len(rootBytes) != 32 {
		return nil, NewError(ErrCodeInvalidParams, "invalid stateRoot (expected 32-byte hex)")
	}
	var stateRoot types.Hash
	copy(stateRoot[:], rootBytes)

	calldata := rollup.EncodeRecordFinalizedBatch(req.BatchIndex, stateRoot)

	// Include the contract address if configured.
	contractAddr := "0x"
	if api.engine != nil {
		if cfg := api.engine.GetConfig(); cfg != nil && cfg.L1BridgeContractAddress != (types.Address{}) {
			contractAddr = "0x" + hex.EncodeToString(cfg.L1BridgeContractAddress[:])
		}
	}

	return map[string]any{
		"calldata": "0x" + hex.EncodeToString(calldata),
		"to":       contractAddr,
	}, nil
}
