// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

type StardustAPI struct {
	qpos *consensus.QPOS

	// P1-T1 (2026-07-14): MinistryRegistry singleton. When set, GetMinistryStatus
	// uses this pre-existing instance instead of creating a disposable copy on
	// every call. When nil (backward compat), falls back to on-the-fly creation.
	ministryRegistry *consensus.MinistryRegistry

	// FIX: optional admin allowlist for state-mutating stardust operations.
	// Reserved for future state-mutating stardust RPC methods (e.g. chain/bridge
	// administration); current stardust methods are read-only. When non-empty,
	// only addresses in this set may perform admin-gated operations.
	adminAddrs map[types.Address]bool
}

func NewStardustAPI(qpos *consensus.QPOS) *StardustAPI {
	return &StardustAPI{qpos: qpos}
}

// SetMinistryRegistry injects the node-level MinistryRegistry singleton.
// P1-T1 (2026-07-14): When set, GetMinistryStatus reads from the shared
// instance that is wired into the consensus execution path, rather than
// creating a new disposable registry on every RPC call.
func (api *StardustAPI) SetMinistryRegistry(registry *consensus.MinistryRegistry) {
	api.ministryRegistry = registry
}

// SetAdminAddresses configures the admin allowlist for stardust operations.
// FIX: when non-empty, only these addresses may perform admin-gated
// stardust operations.
func (api *StardustAPI) SetAdminAddresses(addrs []types.Address) {
	api.adminAddrs = make(map[types.Address]bool, len(addrs))
	for _, a := range addrs {
		api.adminAddrs[a] = true
	}
}

// IsAdminAuthorized reports whether the given address is authorized to perform
// admin stardust operations. When no allowlist is configured, all addresses are
// authorized (backward-compatible).
func (api *StardustAPI) IsAdminAuthorized(addr types.Address) bool {
	if len(api.adminAddrs) == 0 {
		return true
	}
	return api.adminAddrs[addr]
}

func (api *StardustAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("qau_stardust_getFinality", api.GetFinality)
	server.RegisterHandler("qau_stardust_getChambers", api.GetChambers)
	server.RegisterHandler("qau_stardust_getMinistryStatus", api.GetMinistryStatus)
	server.RegisterHandler("qau_stardust_verifyFinality", api.VerifyFinality)
	server.RegisterHandler("qau_stardust_getQTDFinalityStatus", api.GetQTDFinalityStatus)
	server.RegisterHandler("qau_stardust_getExecutiveChamber", api.GetExecutiveChamber)
	server.RegisterHandler("qau_stardust_getReviewChamber", api.GetReviewChamber)
	server.RegisterHandler("qau_stardust_getThreeChambersFlow", api.GetThreeChambersFlow)
	// P1-7: QTD seal RPC surface.
	// getSealStatus is read-only (any client).
	// requestSeal/submitPartialSeal are admin-gated consensus-triggering operations.
	server.RegisterHandler("qau_tss_getSealStatus", api.GetSealStatus)
	server.RegisterAdminMethod("qau_tss_requestSeal")
	server.RegisterHandler("qau_tss_requestSeal", api.RequestSeal)
	server.RegisterAdminMethod("qau_tss_submitPartialSeal")
	server.RegisterHandler("qau_tss_submitPartialSeal", api.SubmitPartialSeal)
	// P1-9: DKG status monitoring (read-only).
	server.RegisterHandler("qau_stardust_getDKGStatus", api.GetDKGStatus)
}

func (api *StardustAPI) GetFinality(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	slot, err := parseSlotParam(params)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid slot parameter", err.Error())
	}

	qfs := api.qpos.GetQTDFinality()
	if qfs == nil {
		return map[string]any{
			"slot":            slot,
			"finalityType":    "CasperFFG",
			"isFinalized":     false,
			"instantFinality": false,
		}, nil
	}

	record := qfs.GetFinalityRecord(slot)
	result := map[string]any{
		"slot":              slot,
		"finalityType":      qfs.GetFinalityType().String(),
		"isInstantFinality": qfs.IsInstantFinality(),
	}

	if record != nil {
		result["isFinalized"] = true
		result["blockHash"] = "0x" + hex.EncodeToString(record.BlockHash[:])
		result["qtdSignature"] = "0x" + hex.EncodeToString(record.QTDSignature)
		result["sealers"] = record.Sealers
		result["finalityDelay"] = record.FinalityDelay.String()
		result["sealedAt"] = record.SealedAt.Unix()
	} else {
		result["isFinalized"] = qfs.IsSlotFinalized(slot)
	}

	return result, nil
}

func (api *StardustAPI) GetChambers(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	if !api.qpos.HasChambers() {
		return map[string]any{
			"enabled": false,
			"message": "Three Chambers not initialized",
		}, nil
	}

	coordinator := api.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return map[string]any{
			"enabled": false,
			"message": "Chambers coordinator not available",
		}, nil
	}
	return coordinator.GetChamberStatus(), nil
}

// GetMinistryStatus returns the status of the six governance ministries.
//
// P1-T1 (2026-07-14): When api.ministryRegistry is set (injected by the Node),
// this method reads from the shared singleton that is wired into the consensus
// execution path. When nil (backward compat, e.g., tests), it falls back to
// creating a disposable registry on-the-fly — this fallback path does NOT
// reflect any state changes made via the wired-in singleton.
func (api *StardustAPI) GetMinistryStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	// P1-T1: Use the injected singleton when available.
	if api.ministryRegistry != nil {
		return api.ministryRegistry.GetStatus(), nil
	}

	// Backward-compat fallback: create a disposable registry for read-only
	// status. This path does NOT reflect state from the wired-in singleton.
	coordinator := api.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return map[string]any{
			"enabled": false,
			"message": "Ministry registry not available",
		}, nil
	}

	registry := consensus.NewMinistryRegistry(api.qpos, coordinator)
	return registry.GetStatus(), nil
}

// VerifyFinality verifies the stardust finality status of a (slot, blockHash) pair.
// RPC: qau_stardust_verifyFinality
//
// RPC- DOC: This endpoint ONLY verifies the finality status of the
// (slot, blockHash, qtdSignature) tuple via consensus.VerifyStardustFinality.
// The request does NOT carry a full block header (Height/ParentHash/StateRoot/
// TxRoot/ProposerAddr are not submitted and are not part of the verification
// surface). Callers must NOT treat a "valid": true response as proof that a
// full block with those header fields has been finalized — it only means the
// QTD finality gadget has a valid seal for the given (slot, blockHash). Full
// block integrity must be validated via eth_getBlockByHash + block hash
// comparison by the caller.
func (api *StardustAPI) VerifyFinality(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	var req struct {
		Slot         uint64 `json:"slot"`
		BlockHash    string `json:"blockHash"`
		QTDSignature string `json:"qtdSignature"`
		FinalityType uint8  `json:"finalityType"`
	}
	if err := parseParams(params, &req); err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
	}

	header := &encoding.BlockHeader{
		Slot:         req.Slot,
		FinalityType: req.FinalityType,
	}

	if req.QTDSignature != "" {
		sig, err := hex.DecodeString(trim0xStardust(req.QTDSignature))
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid QTD signature", err.Error())
		}
		header.QTDSignature = sig
	}

	// AUDIT (2026) CORE-05 FIX: Parse and pass the block's own hash
	// (not ParentHash) to VerifyStardustFinality. The QTD seal is over the
	// block's own hash, so verification must use the same hash that was
	// passed to RequestSeal.
	var blockHash types.Hash
	if req.BlockHash != "" {
		hashBytes, err := hex.DecodeString(trim0xStardust(req.BlockHash))
		if err != nil || len(hashBytes) != len(blockHash) {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid blockHash", "expected 32-byte hex hash")
		}
		copy(blockHash[:], hashBytes)
	}

	valid := consensus.VerifyStardustFinality(header, blockHash, api.qpos)

	return map[string]any{
		"slot":         req.Slot,
		"finalityType": req.FinalityType,
		"valid":        valid,
	}, nil
}

func (api *StardustAPI) GetQTDFinalityStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	qfs := api.qpos.GetQTDFinality()
	if qfs == nil {
		return map[string]any{
			"enabled": false,
			"type":    "CasperFFG",
		}, nil
	}

	return qfs.GetQTDFinalityStatus(), nil
}

func (api *StardustAPI) GetExecutiveChamber(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	if !api.qpos.HasChambers() {
		return map[string]any{
			"enabled": false,
		}, nil
	}

	coordinator := api.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return map[string]any{
			"enabled": false,
		}, nil
	}
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		return map[string]any{
			"enabled": false,
		}, nil
	}

	return executive.Stats(), nil
}

func (api *StardustAPI) GetReviewChamber(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	slot, err := parseSlotParam(params)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid slot parameter", err.Error())
	}

	if !api.qpos.HasChambers() {
		return map[string]any{
			"enabled": false,
			"slot":    slot,
		}, nil
	}

	coordinator := api.qpos.GetChambersCoordinator()
	// R36-P3-18 FIX (2026-07-30): Add nil check for coordinator, matching
	// the pattern used by sibling methods (GetThreeChambersStatus line 137,
	// GetExecutiveChamber line 266, GetThreeChambersFlow line 339). Without
	// this check, calling GetReviewChamber before chambers are initialized
	// would nil-deref on coordinator.GetReviewChamber().
	if coordinator == nil {
		return map[string]any{
			"enabled": false,
			"slot":    slot,
		}, nil
	}
	review := coordinator.GetReviewChamber()
	if review == nil {
		return map[string]any{
			"enabled": false,
			"slot":    slot,
		}, nil
	}

	return review.GetReviewStatus(), nil
}

func (api *StardustAPI) GetThreeChambersFlow(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	slot, err := parseSlotParam(params)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid slot parameter", err.Error())
	}

	if !api.qpos.HasChambers() {
		return map[string]any{
			"enabled": false,
			"slot":    slot,
		}, nil
	}

	// GOV- (Info): ThreeChambersFlow is an ephemeral helper with no
	// long-lived instance stored on the coordinator — calling
	// NewThreeChambersFlow here would yield a flow whose lifecycles map is
	// empty, so GetLifecycle would always return nil and the RPC would
	// report "phase: None" even when the slot has actually been proposed,
	// reviewed, sealed and finalized. To return real on-chain state we
	// instead query the coordinator's review chamber (slot result + verdict)
	// and the QPOS proposer schedule directly. Sealers / finality delay
	// remain unavailable through this RPC because they are tracked only on
	// the ephemeral flow; operators needing them should query
	// qau_tss_status / qau_qposStatus instead.
	coordinator := api.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return map[string]any{
			"slot":  slot,
			"phase": "None",
		}, nil
	}

	proposer := -1
	if v, perr := api.qpos.GetProposerForSlot(slot); perr == nil && v != nil {
		if vs := api.qpos.GetValidatorSet(); vs != nil {
			proposer = vs.GetValidatorIndex(v.Address)
		}
	}

	phase := "None"
	reviewVerdict := "Pending"
	if review := coordinator.GetReviewChamber(); review != nil {
		if result := review.GetSlotResult(slot); result != nil {
			reviewVerdict = result.Verdict.String()
			switch result.Verdict {
			case consensus.VerdictPending:
				phase = "Proposed"
			case consensus.VerdictApproved:
				phase = "Reviewed"
			case consensus.VerdictRejected, consensus.VerdictTimeout:
				phase = "Reviewed"
			}
		}
	}

	return map[string]any{
		"slot":          slot,
		"phase":         phase,
		"proposer":      proposer,
		"reviewVerdict": reviewVerdict,
	}, nil
}

func parseSlotParam(params json.RawMessage) (uint64, error) {
	var slot uint64
	if err := json.Unmarshal(params, &slot); err != nil {
		var arr []uint64
		if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 1 {
			return arr[0], nil
		}
		var obj struct {
			Slot uint64 `json:"slot"`
		}
		if err3 := json.Unmarshal(params, &obj); err3 == nil {
			return obj.Slot, nil
		}
		return 0, fmt.Errorf("cannot parse slot from params")
	}
	return slot, nil
}

func parseParams(params json.RawMessage, target any) error {
	if err := json.Unmarshal(params, target); err != nil {
		var arr []json.RawMessage
		if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 1 {
			return json.Unmarshal(arr[0], target)
		}
		return err
	}
	return nil
}

func trim0xStardust(s string) string {
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}

// GetSealStatus returns the QTD seal status for a given slot.
// P1-7: Read-only RPC for querying partial seal collection progress.
// Params: ["slot"] or {"slot": <number>}
func (api *StardustAPI) GetSealStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	qfs := api.qpos.GetQTDFinality()
	if qfs == nil {
		return nil, NewError(ErrCodeInternal, "QTD finality not initialized")
	}

	slot, err := parseSlotParam(params)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid slot parameter")
	}

	finalized := qfs.IsSlotFinalized(slot)
	result := map[string]any{
		"slot":      fmt.Sprintf("0x%x", slot),
		"finalized": finalized,
	}
	if finalized {
		rec := qfs.GetFinalityRecord(slot)
		if rec != nil {
			result["blockHash"] = "0x" + hex.EncodeToString(rec.BlockHash[:])
			result["sealerCount"] = len(rec.Sealers)
			result["sealedAt"] = rec.SealedAt
		}
		return result, nil
	}

	// Not yet finalized — report pending seal progress if any.
	pending := qfs.GetPendingSeal(slot)
	if pending != nil {
		result["pending"] = true
		result["blockHash"] = "0x" + hex.EncodeToString(pending.BlockHash[:])
		result["partialSigCount"] = len(pending.PartialSigs)
		result["requiredCount"] = pending.RequiredCount
		result["completed"] = pending.Completed
		// RPC-FIX: This is a public (non-admin) endpoint, so do NOT
		// expose the concrete sealer index list — that would let any client
		// monitor which executive members are active/inactive and infer QTD
		// threshold progress for targeted attacks. Only expose the count,
		// which is sufficient for liveness monitoring.
		result["sealerCount"] = len(pending.PartialSigs)
	}
	return result, nil
}

// RequestSeal triggers a QTD seal request for a slot.
// P1-7: Admin-gated RPC for externally triggering the QTD joint signing flow.
// This is the entry point for "user-initiated joint signing" (a project highlight:
// users can invoke joint signing).
//
// Params: {"slot": <number>, "blockHash": "0x..."} or
//
//	[<slot>, "0x..."]
//
// Pre-conditions (enforced by qfs.RequestSeal):
//   - Block must be approved by Review Chamber (≥2/3 attestation stake)
//   - Executive Chamber must be active (DKG complete)
//   - No existing pending seal for this slot
//   - Slot not already finalized
func (api *StardustAPI) RequestSeal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	qfs := api.qpos.GetQTDFinality()
	if qfs == nil {
		return nil, NewError(ErrCodeInternal, "QTD finality not initialized")
	}

	var req struct {
		Slot      uint64 `json:"slot"`
		BlockHash string `json:"blockHash"`
		SlotHex   string `json:"slotHex"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		var arr []json.RawMessage
		if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 2 {
			if err3 := json.Unmarshal(arr[0], &req.Slot); err3 != nil {
				// Try hex string form.
				var slotStr string
				if err4 := json.Unmarshal(arr[0], &slotStr); err4 == nil {
					req.SlotHex = slotStr
				} else {
					return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
				}
			}
			if err3 := json.Unmarshal(arr[1], &req.BlockHash); err3 != nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid blockHash", err3.Error())
			}
		} else {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
		}
	}

	// Support hex slot (e.g. "0x1a").
	if req.Slot == 0 && req.SlotHex != "" {
		s, err := parseUint64Hex(req.SlotHex)
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid slotHex", err.Error())
		}
		req.Slot = s
	}

	if req.BlockHash == "" {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing blockHash", "blockHash is required")
	}

	hashBytes, err := hex.DecodeString(trim0xStardust(req.BlockHash))
	if err != nil || len(hashBytes) != 32 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid blockHash",
			"expected 32-byte hex hash (64 hex chars)")
	}
	var blockHash types.Hash
	copy(blockHash[:], hashBytes)

	if err := qfs.RequestSeal(req.Slot, blockHash); err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "request seal failed", err.Error())
	}

	return map[string]any{
		"success":       true,
		"slot":          fmt.Sprintf("0x%x", req.Slot),
		"blockHash":     "0x" + hex.EncodeToString(blockHash[:]),
		"requiredCount": api.getRequiredSealCount(),
	}, nil
}

// SubmitPartialSeal submits a partial seal signature from an executive chamber
// member. P1-7: Admin-gated RPC for external partial seal submission (e.g.
// from wallet clients acting as executive members).
//
// Params: {"slot": <number>, "validatorIndex": <number>, "signature": "0x..."}
//
// Pre-conditions (enforced by qfs.SubmitPartialSeal):
//   - Seal must be pending for this slot (RequestSeal already called)
//   - Validator must be an executive chamber member
//   - Signature must pass format/length validation
//   - Validator must not have already submitted for this slot
func (api *StardustAPI) SubmitPartialSeal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}

	qfs := api.qpos.GetQTDFinality()
	if qfs == nil {
		return nil, NewError(ErrCodeInternal, "QTD finality not initialized")
	}

	var req struct {
		Slot           uint64 `json:"slot"`
		ValidatorIndex int    `json:"validatorIndex"`
		Signature      string `json:"signature"`
		SlotHex        string `json:"slotHex"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
	}

	// Support hex slot.
	if req.Slot == 0 && req.SlotHex != "" {
		s, err := parseUint64Hex(req.SlotHex)
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid slotHex", err.Error())
		}
		req.Slot = s
	}

	if req.Signature == "" {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing signature", "signature is required")
	}

	sigBytes, err := hex.DecodeString(trim0xStardust(req.Signature))
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid signature hex", err.Error())
	}

	// RPC-FIX: Validate Dilithium3 signature length at the RPC boundary
	// for defense-in-depth (DoS hardening), consistent with rollup_api.go:456.
	if len(sigBytes) != crypto.Dilithium3SignatureSize {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid signature length",
			fmt.Sprintf("expected %d bytes (Dilithium3), got %d",
				crypto.Dilithium3SignatureSize, len(sigBytes)))
	}

	if err := qfs.SubmitPartialSeal(req.ValidatorIndex, req.Slot, sigBytes); err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "submit partial seal failed", err.Error())
	}

	// Report post-submission status.
	finalized := qfs.IsSlotFinalized(req.Slot)
	result := map[string]any{
		"success":        true,
		"slot":           fmt.Sprintf("0x%x", req.Slot),
		"validatorIndex": req.ValidatorIndex,
		"finalized":      finalized,
		"signatureSize":  len(sigBytes),
	}
	if pending := qfs.GetPendingSeal(req.Slot); pending != nil {
		result["partialSigCount"] = len(pending.PartialSigs)
		result["requiredCount"] = pending.RequiredCount
	}
	return result, nil
}

// getRequiredSealCount returns the executive chamber threshold, or 0 if not available.
func (api *StardustAPI) getRequiredSealCount() int {
	if !api.qpos.HasChambers() {
		return 0
	}
	coordinator := api.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return 0
	}
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		return 0
	}
	return executive.Threshold()
}

// GetDKGStatus returns the current DKG (Distributed Key Generation) status for
// the executive chamber. P1-9 (2026-07-14): Read-only monitoring endpoint used
// to track whether the executive chamber has completed its DKG round and is
// active for block sealing.
//
// Returns:
//
//	{"available": false, "reason": "..."} — chambers not initialized
//	{"available": true, "state": "Active", "epoch": N, ...} — DKG status
func (api *StardustAPI) GetDKGStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.qpos == nil {
		return nil, NewError(ErrCodeInternal, "QPOS not initialized")
	}
	if !api.qpos.HasChambers() {
		return map[string]any{
			"available": false,
			"reason":    "three chambers not enabled",
		}, nil
	}
	coordinator := api.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return map[string]any{
			"available": false,
			"reason":    "coordinator not initialized",
		}, nil
	}
	return coordinator.GetDKGStatus(), nil
}

// parseUint64Hex parses a hex string (with or without 0x prefix) into uint64.
func parseUint64Hex(s string) (uint64, error) {
	s = trim0xStardust(s)
	var v uint64
	for _, ch := range s {
		var d uint64
		switch {
		case ch >= '0' && ch <= '9':
			d = uint64(ch - '0')
		case ch >= 'a' && ch <= 'f':
			d = uint64(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			d = uint64(ch-'A') + 10
		default:
			return 0, fmt.Errorf("invalid hex char %q", ch)
		}
		v = v*16 + d
	}
	return v, nil
}
