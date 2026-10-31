// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

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

	// R24 (2026-10-29): the status and the record are read as ONE snapshot.
	// The previous revision read them separately (GetFinalityRecord followed
	// by GetSlotSealStatus), so a concurrent seal completion could produce a
	// response whose record and whose status described DIFFERENT moments —
	// e.g. a record for one block next to the classification of another.
	// GetSlotSealDetails returns both from a single lookup.
	//
	// R26 (2026-10-30): the consensus-layer boolean is part of that snapshot
	// too (SlotSealStatus.ConsensusFinalized). It used to be computed by a
	// separate IsSealConsensusFinalized call, which re-read the record and the
	// markers — the last remaining way for one response to mix two moments.
	status, record := qfs.GetSlotSealDetails(slot)
	result := map[string]any{
		"slot":              slot,
		"finalityType":      qfs.GetFinalityType().String(),
		"isInstantFinality": qfs.IsInstantFinality(),
		// R23 (2026-10-29): isFinalized is now the honest BLOCK-level answer
		// — a QTD seal counts as final only when the sealed block is the
		// canonical block of its slot (canonicalState == matches). R24 made
		// this fail-closed: when the canonical root is unknown (or was
		// pruned) the seal is NOT reported final unless a matching
		// classification was persisted with the record.
		//
		// Before R23 this field carried IsSlotFinalized, which cannot tell a
		// canonical seal from a seal over a side-branch block: a quorum seal
		// over a fork block was reported as finalized together with that
		// fork block's hash. The three independent facts are now reported
		// separately so a client can combine them explicitly:
		//   - sealRecorded:      a threshold agreement exists for the slot
		//   - canonical/canonicalState:
		//                        the sealed block IS the slot's canonical root
		//                        ("matches"), provably is NOT ("differs"), or
		//                        the root is not known yet ("unknown")
		//   - epochFinalized:    the QPOS consensus finality marker reached the
		//                        slot's epoch
		//   - consensusSealFinalized: the CONSENSUS-layer view: a seal agreement
		//                        is recorded for the slot AND the QPOS epoch
		//                        marker has caught up to the slot's epoch
		//                        (SlotSealStatus.ConsensusFinalized, read from
		//                        the same snapshot as the fields above).
		//                        It is NOT a statement about the canonical
		//                        block: a side-branch seal never advances the
		//                        marker itself, but the marker can still reach
		//                        its epoch through OTHER slots' canonical
		//                        seals. Use isFinalized for the block-level
		//                        answer.
		"isFinalized":            status.IsFinalized(),
		"sealRecorded":           status.SealRecorded,
		"canonical":              status.RootState == consensus.SealRootMatches,
		"canonicalState":         status.RootState.String(),
		"epochFinalized":         status.EpochFinal,
		"consensusSealFinalized": status.ConsensusFinalized,
	}

	if record != nil {
		// R22: record PRESENCE is not finality. The record is retained as the
		// threshold-agreement proof even when the sealed block is not the
		// canonical root, so the block hash is reported together with the
		// explicit canonical binding above — never as an implicit "finalized".
		result["blockHash"] = "0x" + hex.EncodeToString(record.BlockHash[:])
		result["qtdSignature"] = "0x" + hex.EncodeToString(record.QTDSignature)
		result["sealers"] = record.Sealers
		result["finalityDelay"] = record.FinalityDelay.String()
		result["sealedAt"] = record.SealedAt.Unix()
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

	// R19-F03 (2026-10-28): reject the empty-verification path. FinalityType
	// defaults to 0 when the caller omits the field, and
	// consensus.VerifyStardustFinality returns true immediately for type 0 —
	// so this public endpoint used to answer {"valid": true} for ANY
	// (slot, blockHash) with no signature at all. Require the caller to
	// assert a concrete finality type and to present a signature; type 0 is
	// not a queryable finality level.
	if req.FinalityType == 0 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid finalityType",
			"finalityType must be set (0 is not a verifiable finality level)")
	}
	if req.QTDSignature == "" {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing qtdSignature",
			"a QTD seal signature is required for finality verification")
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

	// R29 (2026-10-30) FIX (auditor finding N6): `valid` answers ONE question —
	// does the presented signature prove a threshold seal over this block? A
	// seal agreement is kept after a reorg (it is the quorum proof), so
	// `valid: true` never meant "this block is final" and clients kept reading
	// it that way. Publish the block-level answer next to it, from the same
	// snapshot the other finality RPCs use, so the two can never be conflated.
	resp := map[string]any{
		"slot":         req.Slot,
		"finalityType": req.FinalityType,
		"valid":        valid,
	}
	if qfs := api.qpos.GetQTDFinality(); qfs != nil {
		status, record := qfs.GetSlotSealDetails(req.Slot)
		sealedThisBlock := record != nil && record.BlockHash == blockHash
		resp["sealRecorded"] = status.SealRecorded
		resp["canonical"] = status.RootState == consensus.SealRootMatches
		resp["canonicalState"] = status.RootState.String()
		resp["epochFinalized"] = status.EpochFinal
		resp["consensusSealFinalized"] = status.ConsensusFinalized
		resp["isFinalized"] = valid && sealedThisBlock && status.IsFinalized()
	}
	return resp, nil
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

	// R23 (2026-10-29): the seal status is now reported as independent facts
	// instead of a single boolean, and the record payload is emitted whenever
	// a record EXISTS — not only when the consensus view says "finalized".
	//
	// Before R23 a retained agreement over a non-canonical block was
	// invisible here (the record branch was gated on `finalized`), and a
	// concurrently pending seal overwrote the `blockHash` / `sealerCount`
	// keys of the record, so a client could not tell which block it was
	// looking at.
	status, rec := qfs.GetSlotSealDetails(slot)
	pending := qfs.GetPendingSeal(slot)
	// R26 (2026-10-30): the consensus boolean comes from the SAME snapshot as
	// the record and the classification (status.ConsensusFinalized).
	return sealStatusResult(slot, status, rec, pending, status.ConsensusFinalized), nil
}

// sealStatusResult assembles the qau_tss_getSealStatus response body from the
// independent finality facts of a slot (R23, 2026-10-29).
//
// It is a pure function of its arguments on purpose: the response SCHEMA is
// part of the public contract, and the states that matter most (a retained
// side-branch seal next to a re-seal in flight) cannot be produced from
// outside the consensus package. Keeping the mapping separate from the
// consensus reads lets the schema be pinned directly by unit tests.
func sealStatusResult(slot uint64, status consensus.SlotSealStatus, rec *consensus.InstantFinalityRecord, pending *consensus.PendingSeal, consensusSealFinalized bool) map[string]any {
	result := map[string]any{
		"slot": slot,
		// finalized: the honest BLOCK-level answer — a seal counts as final
		// only when the sealed block is the canonical block of its slot
		// (canonicalState == matches). R24 made this fail-closed: an unknown
		// (or pruned) canonical root does NOT report the seal as final
		// unless a matching classification was persisted with the record.
		"finalized": status.IsFinalized(),
		// consensusSealFinalized: the CONSENSUS-layer view
		// (SlotSealStatus.ConsensusFinalized) — a seal agreement is recorded for
		// the slot AND the QPOS epoch marker has caught up to the slot's epoch.
		// It says nothing about the canonical block: a side-branch seal never
		// advances the marker itself, but the marker can still reach its epoch
		// through OTHER slots' canonical seals. The block-level answer is
		// "finalized" above. R26 (2026-10-30): this value is computed from the
		// same snapshot as the fields below, not by a second read.
		"consensusSealFinalized": consensusSealFinalized,
		// The three independent facts behind those two booleans.
		"sealRecorded":   status.SealRecorded,
		"canonical":      status.RootState == consensus.SealRootMatches,
		"canonicalState": status.RootState.String(),
		"epochFinalized": status.EpochFinal,
	}

	if rec != nil {
		result["blockHash"] = "0x" + hex.EncodeToString(rec.BlockHash[:])
		result["sealerCount"] = len(rec.Sealers)
		// R24 (2026-10-29): sealedAt is emitted as UNIX SECONDS in BOTH
		// finality RPCs. The previous revision emitted the Go time.Time here
		// (an RFC3339 string) while qau_stardust_getFinality emitted
		// record.SealedAt.Unix() (a number), so the same field had two
		// different JSON types depending on the endpoint a client asked.
		// The numeric form is the one the published getFinality contract
		// documents, so it wins here.
		result["sealedAt"] = rec.SealedAt.Unix()
	}

	if pending != nil {
		result["pending"] = true
		result["partialSigCount"] = len(pending.PartialSigs)
		result["requiredCount"] = pending.RequiredCount
		result["completed"] = pending.Completed
		// RPC-FIX: This is a public (non-admin) endpoint, so do NOT
		// expose the concrete sealer index list — that would let any client
		// monitor which executive members are active/inactive and infer QTD
		// threshold progress for targeted attacks. Only expose the count,
		// which is sufficient for liveness monitoring.
		//
		// R23: a record and a pending seal can coexist — the pending seal is
		// the re-seal of a slot whose previous agreement covered a
		// non-canonical block (R23 liveness fix). The legacy key names stay
		// bound to the RECORD in that case, and the pending seal gets its
		// own keys, so a client can never mistake one for the other.
		if rec == nil {
			result["blockHash"] = "0x" + hex.EncodeToString(pending.BlockHash[:])
			result["sealerCount"] = len(pending.PartialSigs)
		} else {
			result["pendingBlockHash"] = "0x" + hex.EncodeToString(pending.BlockHash[:])
			result["pendingSealerCount"] = len(pending.PartialSigs)
		}
	}
	return result
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
		msg := err.Error()
		// R19-F07 (2026-10-28): an identical repeat request is an idempotent
		// retry, not a server fault — report success with existing=true when
		// the pending seal carries the same blockHash, and a conflict error
		// when the caller is trying to seal a different hash for the slot.
		if strings.Contains(msg, "seal already requested") {
			if pending := qfs.GetPendingSeal(req.Slot); pending != nil && pending.BlockHash == blockHash {
				return map[string]any{
					"success":       true,
					"existing":      true,
					"slot":          req.Slot,
					"blockHash":     "0x" + hex.EncodeToString(blockHash[:]),
					"requiredCount": api.getRequiredSealCount(),
				}, nil
			}
			return nil, NewErrorWithData(ErrCodeInvalidParams, "seal request conflict", msg)
		}
		// R19-F07: the remaining rejections are domain preconditions (slot
		// finalized, chambers not ready, block not approved, non-canonical
		// hash) — operator errors, not node faults. Mapping them to
		// ErrCodeInvalidParams (instead of ErrCodeInternal) lets monitoring
		// distinguish misuse from internal failures.
		return nil, NewErrorWithData(ErrCodeInvalidParams, "request seal rejected", msg)
	}

	return map[string]any{
		"success":       true,
		"slot":          req.Slot,
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

	// R19-F04 (2026-10-28): accept BOTH signature shapes the consensus layer
	// defines, instead of only full Dilithium3 signatures. The previous
	// 3293-byte-only gate made the documented "executive members can invoke
	// joint signing" unusable — a threshold-share holder only holds a share
	// and cannot produce a full 3293-byte independent signature, while
	// SubmitPartialSeal explicitly supports TSS partials (>= 16 bytes, with
	// fail-closed aggregation downstream per R14-MED). Full Dilithium3
	// signatures remain cryptographically verified inside SubmitPartialSeal
	// (over the pending seal's blockHash); TSS partials are length-checked
	// here and at the consensus layer, and can never influence the final
	// aggregated signature (local mode rejects them at aggregation,
	// distributed mode re-signs from scratch).
	const minTSSPartialSigLen = 16
	if len(sigBytes) != crypto.Dilithium3SignatureSize && len(sigBytes) < minTSSPartialSigLen {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid signature length",
			fmt.Sprintf("expected %d bytes (full Dilithium3) or >= %d bytes (TSS partial), got %d",
				crypto.Dilithium3SignatureSize, minTSSPartialSigLen, len(sigBytes)))
	}
	if len(sigBytes) > crypto.Dilithium3SignatureSize {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid signature length",
			fmt.Sprintf("signature exceeds the maximum (%d bytes), got %d",
				crypto.Dilithium3SignatureSize, len(sigBytes)))
	}

	if err := qfs.SubmitPartialSeal(req.ValidatorIndex, req.Slot, sigBytes); err != nil {
		// R19-F07: domain rejections (no pending seal, duplicate, wrong
		// length, not a sealer) are caller errors — map to invalid-params
		// instead of internal so monitoring can tell misuse from faults.
		return nil, NewErrorWithData(ErrCodeInvalidParams, "submit partial seal rejected", err.Error())
	}

	// Report post-submission status.
	//
	// R24 (2026-10-29): the published "finalized" field is the honest
	// BLOCK-level answer — the canonical block of the slot carries a
	// threshold agreement. The previous revision used the consensus-layer
	// accessor, which reports true for ANY recorded agreement (including one
	// over a side-branch block) and for a slot whose epoch marker has not
	// caught up yet. The same field name now means the same thing in every
	// finality RPC (qau_stardust_getFinality, qau_tss_getSealStatus and
	// qau_tss_submitPartialSeal).
	status, _ := qfs.GetSlotSealDetails(req.Slot)
	result := map[string]any{
		"success":        true,
		"slot":           req.Slot,
		"validatorIndex": req.ValidatorIndex,
		"finalized":      status.IsFinalized(),
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
		// R19-F11: detect overflow instead of silently wrapping — a >16-hex-digit
		// value used to wrap modulo 2^64 and address a different slot than
		// the caller typed.
		if v > (^(uint64(0))-d)/16 {
			return 0, fmt.Errorf("hex value overflows uint64")
		}
		v = v*16 + d
	}
	return v, nil
}
