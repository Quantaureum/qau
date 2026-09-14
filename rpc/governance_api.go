// Quantaureum Node source, version 1.0.0.
// Governance RPC API — Proposal submission, voting, and parameter queries
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/types"
)

// GovernanceAPI provides governance RPC methods.
type GovernanceAPI struct {
	gm          *economics.GovernanceManager
	blockReader BlockReader
	chainID     uint64

	nonceMu    sync.Mutex
	usedNonces map[types.Address]map[string]time.Time

	// GOV-R7-08 (Low): nonceTTL is the replay-protection window for
	// confirmed governance nonces. Confirmed nonces older than nonceTTL
	// are eligible for eviction during the per-call cleanup in
	// verifyGovernanceSignature. Defaults to 10 minutes (the previous
	// hardcoded value) and can be overridden via SetNonceTTL for
	// high-latency networks (longer window) or test environments
	// (shorter window) without recompiling.
	nonceTTL time.Duration
}

const maxGovernanceNoncesPerAddress = 10000
const maxGovernanceTrackedAddresses = 100000

// isNoncePending returns true if the nonce timestamp indicates a pending
// reservation (awaiting signature verification).
// L13-020 FIX: Centralizes the time.Time{} zero-value sentinel check
// to prevent future refactoring mistakes. The zero value of time.Time
// (Go year 1, NOT Unix epoch 1970) marks a nonce as "pending"; any
// non-zero value means the nonce is confirmed (signature verified).
// All callers MUST use these helpers instead of bare ts.IsZero() checks.
func isNoncePending(ts time.Time) bool {
	return ts.IsZero()
}

// isNonceConfirmed returns true if the nonce has been confirmed
// (signature verified and timestamp recorded).
func isNonceConfirmed(ts time.Time) bool {
	return !ts.IsZero()
}

// defaultGovernanceNonceTTL is the default replay-protection window for
// confirmed governance nonces. Override per-instance with SetNonceTTL.
const defaultGovernanceNonceTTL = 10 * time.Minute

// NewGovernanceAPI creates a new Governance API.
func NewGovernanceAPI(gm *economics.GovernanceManager, br BlockReader) *GovernanceAPI {
	return &GovernanceAPI{
		gm:          gm,
		blockReader: br,
		usedNonces:  make(map[types.Address]map[string]time.Time),
		nonceTTL:    defaultGovernanceNonceTTL,
	}
}

// SetChainID sets the chain ID used in governance signature messages to prevent
// cross-chain replay of governance signatures.
func (api *GovernanceAPI) SetChainID(id uint64) {
	api.chainID = id
}

// SetNonceTTL overrides the replay-protection window for confirmed governance
// nonces. A longer window tolerates high-latency RPC paths; a shorter window
// tightens the replay window (useful in tests). Must be > 0; passing 0 keeps
// the default to avoid accidentally disabling replay protection.
func (api *GovernanceAPI) SetNonceTTL(ttl time.Duration) {
	if ttl <= 0 {
		ttl = defaultGovernanceNonceTTL
	}
	api.nonceTTL = ttl
}

// R24-018: This method uses a non-standard name. The convention across
// other API structs (API, DebugAPI, ProofAPI, etc.) is RegisterHandlers.
// The original name is retained for backward compatibility; a
// RegisterHandlers alias is defined below.
// RegisterGovernanceHandlers registers all governance API handlers.
func (api *GovernanceAPI) RegisterGovernanceHandlers(server *Server) {
	// Proposal methods (write operations)
	server.RegisterHandler("qau_createProposal", api.CreateProposal)
	server.RegisterHandler("qau_castVote", api.CastVote)
	server.RegisterHandler("qau_finalizeProposal", api.FinalizeProposal)
	server.RegisterHandler("qau_executeProposal", api.ExecuteProposal)

	// SECURITY FIX (P2): Governance write methods accept client-supplied
	// proposer/voter addresses as parameters but did not verify that the
	// caller controls those addresses. Register them as admin methods so
	// admin authentication (API key with admin permission + IP whitelist)
	// is enforced before the handler runs.
	server.RegisterAdminMethod("qau_createProposal")
	server.RegisterAdminMethod("qau_castVote")
	server.RegisterAdminMethod("qau_finalizeProposal")
	server.RegisterAdminMethod("qau_executeProposal")

	// Query methods
	server.RegisterHandler("qau_getProposal", api.GetProposal)
	server.RegisterHandler("qau_getActiveProposals", api.GetActiveProposals)
	server.RegisterHandler("qau_getProposalCount", api.GetProposalCount)
	server.RegisterHandler("qau_getVote", api.GetVote)
	server.RegisterHandler("qau_getGovernanceConfig", api.GetGovernanceConfig)
	server.RegisterHandler("qau_getGovernanceParameters", api.GetGovernanceParameters)
	server.RegisterHandler("qau_getGovernanceParameter", api.GetGovernanceParameter)
}

// RegisterHandlers is an alias for RegisterGovernanceHandlers, following the
// standard naming convention used by other API structs (R24-018).
func (api *GovernanceAPI) RegisterHandlers(server *Server) {
	api.RegisterGovernanceHandlers(server)
}

// currentHeight returns the current block height.
func (api *GovernanceAPI) currentHeight() uint64 {
	if api.blockReader != nil {
		return api.blockReader.GetLatestHeight()
	}
	return 0
}

// unwrapParams extracts the first element from a JSON-RPC params array.
// The RPC framework passes params as [arg0, arg1, ...], so for single-argument
// methods we need to extract arg0.
func unwrapParams(params json.RawMessage) (json.RawMessage, *Error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(params, &arr); err != nil {
		// Maybe it's already an object (not wrapped in array)
		return params, nil
	}
	if len(arr) == 0 {
		return nil, &Error{Code: -32602, Message: "empty params"}
	}
	return arr[0], nil
}

// parseAddress parses a hex address string.
func parseGovAddress(s string) (types.Address, error) {
	return types.ParseHexAddress(s)
}

// verifyGovernanceSignature verifies a Dilithium3 signature for a governance operation.
// CRITICAL C-2 FIX: all state-mutating governance RPC calls require Dilithium3 signature
// verification proving ownership of the address being operated on, with nonce-based
// replay protection.
func (api *GovernanceAPI) verifyGovernanceSignature(method string, userAddr types.Address, nonce, params string, signature, pubKeyHex string) error {
	if signature == "" || pubKeyHex == "" {
		return fmt.Errorf("signature and publicKey are required for state-mutating operations")
	}
	if nonce == "" {
		return fmt.Errorf("nonce is required for replay protection")
	}

	api.nonceMu.Lock()
	if len(api.usedNonces) > maxGovernanceTrackedAddresses {
		api.nonceMu.Unlock()
		return fmt.Errorf("too many tracked addresses (memory limit)")
	}
	if api.usedNonces[userAddr] == nil {
		api.usedNonces[userAddr] = make(map[string]time.Time)
	}
	// GOV-R7-08: nonceTTL is now an instance field (settable via
	// SetNonceTTL) instead of a hardcoded const, allowing operators to
	// adjust the replay-protection window without recompiling.
	nonceTTL := api.nonceTTL
	if nonceTTL <= 0 {
		nonceTTL = defaultGovernanceNonceTTL
	}
	now := time.Now()
	for k, ts := range api.usedNonces[userAddr] {
		// L13-013 FIX: Skip pending (zero-time) nonces in TTL cleanup.
		// Pending nonces await signature verification and must NOT be evicted
		// by a concurrent request's cleanup, which would reopen a TOCTOU
		// window allowing the same nonce to be reused.
		if isNonceConfirmed(ts) && now.Sub(ts) > nonceTTL {
			delete(api.usedNonces[userAddr], k)
		}
	}
	if _, used := api.usedNonces[userAddr][nonce]; used {
		api.nonceMu.Unlock()
		return fmt.Errorf("nonce already used (replay detected)")
	}
	// L13-020 FIX: time.Time{} (zero value) marks this nonce as "pending"
	// (awaiting signature verification). The isNoncePending() helper centralizes
	// this sentinel check. The TTL cleanup above explicitly skips pending nonces
	// via isNonceConfirmed(ts), so pending entries survive concurrent cleanup.
	// This is safe because: (1) cleanup runs BEFORE insertion in this function;
	// (2) isNoncePending/isNonceConfirmed are the ONLY way to check nonce state;
	// (3) the double-check at the second lock (see L19-005 below) re-verifies
	// the pending state before confirming.
	api.usedNonces[userAddr][nonce] = time.Time{}
	api.nonceMu.Unlock()

	sigBytes, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		api.rollbackPendingGovernanceNonce(userAddr, nonce)
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(strings.TrimPrefix(pubKeyHex, "0x"))
	if err != nil {
		api.rollbackPendingGovernanceNonce(userAddr, nonce)
		return fmt.Errorf("invalid publicKey hex: %w", err)
	}

	// L9-040 FIX: Explicit public key length validation (defense-in-depth).
	// crypto.PublicKeyFromBytes checks this internally, but early rejection
	// provides clearer error messages and avoids unnecessary processing.
	if len(pubKeyBytes) != crypto.Dilithium3PublicKeySize {
		api.rollbackPendingGovernanceNonce(userAddr, nonce)
		return fmt.Errorf("invalid public key length: expected %d bytes, got %d", crypto.Dilithium3PublicKeySize, len(pubKeyBytes))
	}

	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		api.rollbackPendingGovernanceNonce(userAddr, nonce)
		return fmt.Errorf("invalid Dilithium3 public key: %w", err)
	}

	derivedAddr := pubKey.Address()
	if derivedAddr != userAddr {
		api.rollbackPendingGovernanceNonce(userAddr, nonce)
		return fmt.Errorf("public key does not match claimed address")
	}

	// L9-007 FIX: Include ChainID and QAU-{method} domain prefix to prevent
	// cross-chain replay and cross-method signature confusion.
	message := []byte(fmt.Sprintf("QAU-%s|%d|%s|%s|%s", method, api.chainID, userAddr.ToHexAddress(), nonce, params))

	if !crypto.Verify(pubKey, message, sigBytes) {
		api.rollbackPendingGovernanceNonce(userAddr, nonce)
		return fmt.Errorf("signature verification failed")
	}

	api.nonceMu.Lock()
	// L13-013 FIX: Re-verify the nonce is still in pending state before
	// confirming. This closes the TOCTOU window between the initial pending
	// reservation (first lock) and this confirmation (second lock).
	// L19-005 FIX: This double-check pattern (reserve -> verify -> confirm)
	// is the standard defense against nonce TOCTOU races. Between the first
	// lock release and this second lock acquire, a concurrent request cannot
	// reuse the nonce (it sees the pending entry and is rejected at line 136),
	// and the TTL cleanup cannot evict it (isNonceConfirmed skips pending).
	if ts, exists := api.usedNonces[userAddr][nonce]; !exists || isNonceConfirmed(ts) {
		api.nonceMu.Unlock()
		return fmt.Errorf("nonce reservation invalid or lost (possible replay)")
	}
	if len(api.usedNonces[userAddr]) >= maxGovernanceNoncesPerAddress {
		type nonceEntry struct {
			nonce string
			ts    time.Time
		}
		entries := make([]nonceEntry, 0, len(api.usedNonces[userAddr]))
		for k, ts := range api.usedNonces[userAddr] {
			entries = append(entries, nonceEntry{k, ts})
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].ts.Before(entries[j].ts)
		})
		for i := 0; i < len(entries)/2; i++ {
			delete(api.usedNonces[userAddr], entries[i].nonce)
		}
	}
	api.usedNonces[userAddr][nonce] = time.Now()
	api.nonceMu.Unlock()

	return nil
}

// rollbackPendingGovernanceNonce removes a pending nonce reservation when verification fails.
func (api *GovernanceAPI) rollbackPendingGovernanceNonce(userAddr types.Address, nonce string) {
	api.nonceMu.Lock()
	defer api.nonceMu.Unlock()
	if nonces, ok := api.usedNonces[userAddr]; ok {
		// L13-020 FIX: Only roll back pending nonces (isNoncePending check).
		// Confirmed nonces must NOT be deleted (they are replay-protected).
		if ts, exists := nonces[nonce]; exists && isNoncePending(ts) {
			delete(nonces, nonce)
		}
	}
}

// CreateProposal creates a new governance proposal.
// CRITICAL C-2 FIX: requires Dilithium3 signature verification.
// Params: {proposer, type, title, description, changes, deposit, nonce, signature, publicKey}
func (api *GovernanceAPI) CreateProposal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		Proposer       string                      `json:"proposer"`
		Type           uint8                       `json:"type"`
		Title          string                      `json:"title"`
		Description    string                      `json:"description"`
		Changes        []economics.ParameterChange `json:"changes"`
		Deposit        string                      `json:"deposit"`
		TotalVotePower string                      `json:"totalVotePower"`
		Nonce          string                      `json:"nonce"`
		Signature      string                      `json:"signature"`
		PublicKey      string                      `json:"publicKey"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	// L10-009: Validate proposal data size to prevent memory exhaustion.
	const maxProposalDataSize = 32 * 1024 // 32KB
	// L18-040 FIX: Limit Changes array length to prevent O(N) loop abuse.
	const maxChanges = 100
	if len(req.Changes) > maxChanges {
		return nil, &Error{Code: -32602, Message: fmt.Sprintf("too many changes: %d (max %d)", len(req.Changes), maxChanges)}
	}
	proposalDataSize := len(req.Title) + len(req.Description)
	for _, c := range req.Changes {
		proposalDataSize += len(c.Parameter) + len(c.OldValue) + len(c.NewValue)
	}
	if proposalDataSize > maxProposalDataSize {
		return nil, &Error{Code: -32602, Message: fmt.Sprintf("proposal data too large: %d bytes (max %d)", proposalDataSize, maxProposalDataSize)}
	}

	proposer, err := parseGovAddress(req.Proposer)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid proposer address: " + err.Error()}
	}

	deposit, ok := new(big.Int).SetString(req.Deposit, 10)
	if !ok {
		deposit = big.NewInt(0)
	}

	// R37-P3-37 FIX (2026-07-31): Include ALL state-mutating parameters in
	// the signed payload, with pipe delimiters to prevent field-collision
	// ambiguity. Previously authParams used string concatenation
	// (Proposer+Title+Deposit) which: (1) allowed collision attacks
	// (e.g. Proposer="0xA"+Title="B" produces the same hash as
	// Proposer="0xAB"+Title=""); (2) omitted Type, Description, and Changes,
	// allowing an attacker to reuse a signature for a proposal with the same
	// Title/Deposit but different (potentially malicious) parameter changes.
	changesJSON, _ := json.Marshal(req.Changes)
	authParams := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s",
		req.Proposer, req.Type, req.Title, req.Description, req.Deposit, req.TotalVotePower, string(changesJSON))
	if verr := api.verifyGovernanceSignature("qau_createProposal", proposer, req.Nonce, authParams, req.Signature, req.PublicKey); verr != nil {
		return nil, &Error{Code: -32603, Message: "signature verification required: " + verr.Error()}
	}

	// L12-004 FIX: snapshot totalVotePower at creation time. If the client
	// does not provide it, totalVotePower is nil (no snapshot; FinalizeProposal
	// falls back to its caller-supplied parameter for backward compatibility).
	totalVotePower, tvpOK := new(big.Int).SetString(req.TotalVotePower, 10)
	if !tvpOK {
		totalVotePower = nil
	}

	// R41-L3ECON-05 (2026-08-03) FIX: parse the on-chain ProposerNonce from
	// req.Nonce (the SAME string that verifyGovernanceSignature already
	// embedded into the Dilithium3 signed message + checked against the
	// in-process usedNonces replay cache). Pairing the on-chain counter
	// with the signed nonce means:
	//   - An attacker cannot bump the on-chain counter without the
	//     proposer's Dilithium3 key (the bumped nonce would not pass
	//     verifyGovernanceSignature's signature check).
	//   - A node restart that loses the in-process `usedNonces` is
	//     still protected by the on-chain strict-monotonic counter
	//     (CreateProposal rejects `proposerNonce <= last recorded`).
	// We require the nonce string to parse strictly as a base-10 unsigned
	// uint64; any other format is a client error (rejected before
	// touching chain state).
	proposerNonce, err := parseStrictNonce(req.Nonce)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "R41-L3ECON-05: invalid nonce: " + err.Error()}
	}

	// R43-GOVSIG-01 (2026-08-03): forward the Dilithium3 signature material
	// into the core economics layer so CreateProposal verifies it AGAIN at
	// the core (defense in depth). The RPC layer's verifyGovernanceSignature
	// already checked the signature against the in-process usedNonces replay
	// cache; the core layer re-checks the signature against the on-chain
	// ProposerNonce state and the pub→addr binding. A caller that bypasses
	// the RPC path (and therefore skips verifyGovernanceSignature) is still
	// blocked at the core because production callers MUST pass a non-nil
	// ProposalSignature. The signed message format is identical on both
	// layers (see economics.GovernanceProposalSignatureMethod + the
	// verifyProposalSignatureLocked doc comment), so a signature accepted
	// by the RPC layer is also accepted by the core layer.
	//
	// req.PublicKey and req.Signature are hex strings (with optional 0x
	// prefix) carried verbatim from the client. We hex-decode them into
	// bytes here; decode failure is a client error (reject before touching
	// chain state). The "0x" prefix is stripped before decoding using
	// strings.TrimPrefix to tolerate both "0x..." and "..." forms.
	pubKeyBytes, derr := hex.DecodeString(strings.TrimPrefix(req.PublicKey, "0x"))
	if derr != nil {
		return nil, &Error{Code: -32602, Message: "R43-GOVSIG-01: malformed publicKey hex: " + derr.Error()}
	}
	sigBytes, derr := hex.DecodeString(strings.TrimPrefix(req.Signature, "0x"))
	if derr != nil {
		return nil, &Error{Code: -32602, Message: "R43-GOVSIG-01: malformed signature hex: " + derr.Error()}
	}
	proposalSig := &economics.ProposalSignature{
		ProposerPubKey: pubKeyBytes,
		ProposerSig:    sigBytes,
		Nonce:          req.Nonce,
		ChainID:        api.chainID,
		TotalVotePower: req.TotalVotePower,
	}

	proposal, err := api.gm.CreateProposal(
		proposer,
		economics.ProposalType(req.Type),
		req.Title,
		req.Description,
		req.Changes,
		deposit,
		api.currentHeight(),
		totalVotePower,
		proposerNonce,
		proposalSig,
	)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	return proposalToMap(proposal), nil
}

// CastVote casts a vote on a proposal.
// CRITICAL C-2 FIX: requires Dilithium3 signature verification.
// Params: {proposalId, voter, option, votePower, nonce, signature, publicKey}
func (api *GovernanceAPI) CastVote(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		ProposalID uint64 `json:"proposalId"`
		Voter      string `json:"voter"`
		Option     uint8  `json:"option"`
		VotePower  string `json:"votePower"`
		Nonce      string `json:"nonce"`
		Signature  string `json:"signature"`
		PublicKey  string `json:"publicKey"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	voter, err := parseGovAddress(req.Voter)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid voter address: " + err.Error()}
	}

	votePower, ok := new(big.Int).SetString(req.VotePower, 10)
	if !ok {
		votePower = big.NewInt(0)
	}

	// R37-P3-37 FIX (2026-07-31): Include VoteOption in the signed payload,
	// with pipe delimiters to prevent field-collision ambiguity. Previously
	// authParams used string concatenation (ProposalID+Voter+VotePower) which:
	// (1) allowed collision attacks (e.g. ProposalID=1+Voter="0xAB" produces
	// the same string as ProposalID=10+Voter="xAB"); (2) omitted Option,
	// allowing an attacker to capture a signed "Yes" vote and replay it as a
	// "No" vote — the signature would still verify because the authParams did
	// not bind the vote option.
	authParams := fmt.Sprintf("%d|%s|%d|%s", req.ProposalID, req.Voter, req.Option, req.VotePower)
	if verr := api.verifyGovernanceSignature("qau_castVote", voter, req.Nonce, authParams, req.Signature, req.PublicKey); verr != nil {
		return nil, &Error{Code: -32603, Message: "signature verification required: " + verr.Error()}
	}

	// SECURITY FIX (L14-020): Validate vote option is one of the allowed values.
	// Without this, an attacker could submit an arbitrary uint8 value that might
	// cause unexpected behavior in the governance vote tallying logic.
	option := economics.VoteOption(req.Option)
	if option != economics.VoteOptionYes && option != economics.VoteOptionNo && option != economics.VoteOptionAbstain {
		return nil, &Error{Code: -32602, Message: fmt.Sprintf("invalid vote option: %d (must be 0=Yes, 1=No, 2=Abstain)", req.Option)}
	}

	err = api.gm.Vote(req.ProposalID, voter, option, votePower, api.currentHeight())
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	return map[string]any{
		"success":    true,
		"proposalId": req.ProposalID,
		"voter":      voter.ToHexAddress(),
		"option":     req.Option,
	}, nil
}

// FinalizeProposal finalizes a proposal after voting ends.
// CRITICAL C-2 FIX: requires Dilithium3 signature verification.
// Params: {proposalId, totalVotePower, caller, nonce, signature, publicKey}
func (api *GovernanceAPI) FinalizeProposal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		ProposalID     uint64 `json:"proposalId"`
		TotalVotePower string `json:"totalVotePower"`
		Caller         string `json:"caller"`
		Nonce          string `json:"nonce"`
		Signature      string `json:"signature"`
		PublicKey      string `json:"publicKey"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	caller, err := parseGovAddress(req.Caller)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid caller address: " + err.Error()}
	}

	totalVotePower, ok := new(big.Int).SetString(req.TotalVotePower, 10)
	if !ok {
		totalVotePower = big.NewInt(0)
	}

	// L9-008 FIX: Bind caller address into the FinalizeProposal signature message
	// and use delimiters to prevent field-collision ambiguity.
	authParams := fmt.Sprintf("%d|%s|%s", req.ProposalID, caller.ToHexAddress(), req.TotalVotePower)
	if verr := api.verifyGovernanceSignature("qau_finalizeProposal", caller, req.Nonce, authParams, req.Signature, req.PublicKey); verr != nil {
		return nil, &Error{Code: -32603, Message: "signature verification required: " + verr.Error()}
	}

	err = api.gm.FinalizeProposal(req.ProposalID, totalVotePower, api.currentHeight())
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	// L10-031: Log the finalization event for audit trail.
	log.Printf("[Governance] Proposal %d finalized by %s, totalVotePower=%s, height=%d",
		req.ProposalID, caller.ToHexAddress(), req.TotalVotePower, api.currentHeight())

	proposal, _ := api.gm.GetProposal(req.ProposalID)
	return map[string]any{
		"success":    true,
		"proposalId": req.ProposalID,
		"status":     proposalStatusString(proposal),
	}, nil
}

// ExecuteProposal executes a passed proposal.
// CRITICAL C-2 FIX: requires Dilithium3 signature verification.
// Params: {proposalId, caller, nonce, signature, publicKey}
func (api *GovernanceAPI) ExecuteProposal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		ProposalID uint64 `json:"proposalId"`
		Caller     string `json:"caller"`
		Nonce      string `json:"nonce"`
		Signature  string `json:"signature"`
		PublicKey  string `json:"publicKey"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	caller, err := parseGovAddress(req.Caller)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid caller address: " + err.Error()}
	}

	authParams := fmt.Sprintf("%d", req.ProposalID)
	if verr := api.verifyGovernanceSignature("qau_executeProposal", caller, req.Nonce, authParams, req.Signature, req.PublicKey); verr != nil {
		return nil, &Error{Code: -32603, Message: "signature verification required: " + verr.Error()}
	}

	err = api.gm.ExecuteProposal(req.ProposalID, api.currentHeight())
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	return map[string]any{
		"success":    true,
		"proposalId": req.ProposalID,
		"status":     "executed",
	}, nil
}

// GetProposal returns proposal details.
// Params: [proposalId]
func (api *GovernanceAPI) GetProposal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		ProposalID uint64 `json:"proposalId"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params"}
	}

	proposal, err := api.gm.GetProposal(req.ProposalID)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	return proposalToMap(proposal), nil
}

// GetActiveProposals returns all active proposals.
func (api *GovernanceAPI) GetActiveProposals(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}

	proposals := api.gm.GetActiveProposals()
	result := make([]map[string]any, 0, len(proposals))
	for _, p := range proposals {
		result = append(result, proposalToMap(p))
	}
	return result, nil
}

// GetProposalCount returns the total number of proposals.
func (api *GovernanceAPI) GetProposalCount(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}
	return api.gm.ProposalCount(), nil
}

// GetVote returns a voter's vote on a proposal.
// Params: {proposalId, voter}
func (api *GovernanceAPI) GetVote(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		ProposalID uint64 `json:"proposalId"`
		Voter      string `json:"voter"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params"}
	}

	voter, err := parseGovAddress(req.Voter)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid voter address"}
	}

	vote, err := api.gm.GetVote(req.ProposalID, voter)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	return map[string]any{
		"proposalId": vote.ProposalID,
		"voter":      vote.Voter.ToHexAddress(),
		"option":     vote.Option,
		"votePower":  vote.VotePower.String(),
		"height":     vote.Height,
	}, nil
}

// GetGovernanceConfig returns the governance configuration.
//
// R40-P2-05 (2026-08-03): the response now surfaces the four `Emergency*`
// fields that economics.GovernanceConfig carries (the R40-P1-06 fix made
// GetConfig() return them, but the RPC layer was still silently dropping
// them — RPC consumers read zero values and fell back to the regular, much
// laxer thresholds, bypassing the emergency pause mechanism). The Emergency*
// keys are camelCased to match the existing key style used elsewhere in this
// response (votingPeriod / quorumThreshold / …).
func (api *GovernanceAPI) GetGovernanceConfig(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}

	cfg := api.gm.GetConfig()
	return map[string]any{
		"votingPeriod":    cfg.VotingPeriod,
		"quorumThreshold": cfg.QuorumThreshold,
		"passThreshold":   cfg.PassThreshold,
		"proposalDeposit": cfg.ProposalDeposit.String(),
		"executionDelay":  cfg.ExecutionDelay,
		// R40-P2-05: surface the Emergency* fields — without these the RPC
		// consumer sees zero values and silently falls back to the regular
		// (laxer) thresholds, bypassing the emergency pause mechanism.
		"emergencyVotingPeriod":    cfg.EmergencyVotingPeriod,
		"emergencyQuorumThreshold": cfg.EmergencyQuorumThreshold,
		"emergencyPassThreshold":   cfg.EmergencyPassThreshold,
		"emergencyExecutionDelay":  cfg.EmergencyExecutionDelay,
	}, nil
}

// GetGovernanceParameters returns all governance parameters.
func (api *GovernanceAPI) GetGovernanceParameters(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}
	return api.gm.GetAllParameters(), nil
}

// GetGovernanceParameter returns a single governance parameter.
// Params: [name]
func (api *GovernanceAPI) GetGovernanceParameter(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.gm == nil {
		return nil, &Error{Code: -32601, Message: "governance not available"}
	}

	// This one uses array format: ["paramName"]
	var arr []string
	if err := json.Unmarshal(params, &arr); err != nil || len(arr) == 0 {
		return nil, &Error{Code: -32602, Message: "invalid params: expected [name]"}
	}

	value, ok := api.gm.GetParameter(arr[0])
	if !ok {
		return nil, &Error{Code: -32000, Message: "parameter not found"}
	}
	return map[string]any{
		"name":  arr[0],
		"value": value,
	}, nil
}

// proposalToMap converts a Proposal to a map for JSON response.
func proposalToMap(p *economics.Proposal) map[string]any {
	if p == nil {
		return nil
	}
	changes := make([]map[string]any, 0, len(p.Changes))
	for _, c := range p.Changes {
		changes = append(changes, map[string]any{
			"parameter": c.Parameter,
			"oldValue":  c.OldValue,
			"newValue":  c.NewValue,
		})
	}
	return map[string]any{
		"id":           p.ID,
		"type":         p.Type,
		"proposer":     p.Proposer.ToHexAddress(),
		"title":        p.Title,
		"description":  p.Description,
		"changes":      changes,
		"status":       proposalStatusString(p),
		"startHeight":  p.StartHeight,
		"endHeight":    p.EndHeight,
		"yesVotes":     p.YesVotes.String(),
		"noVotes":      p.NoVotes.String(),
		"abstainVotes": p.AbstainVotes.String(),
		"deposit":      p.Deposit.String(),
		"createdAt":    p.CreatedAt.Unix(),
		// R41-L3ECON-05: expose the on-chain ProposerNonce so RPC clients
		// can reconstruct a proposer's sequence (forensic auditability)
		// and compute the next nonce to send (proposerNonce > current).
		"proposerNonce": p.ProposerNonce,
	}
}

// parseStrictNonce parses a governance nonce string as a strict base-10
// unsigned 64-bit integer. Used by CreateProposal (R41-L3ECON-05) to feed
// the on-chain ProposerNonce counter from the RPC `nonce` field — the
// same field already embedded into the Dilithium3 signed message by
// verifyGovernanceSignature. Strict semantic rules:
//   - Leading/trailing whitespace rejected (clients must send clean decimals).
//   - Empty string rejected (the CreateProposal counter starts at 0 for
//     first-time proposers, so the smallest accepted on-chain nonce is 1).
//   - Negative sign rejected (uint64 domain).
//   - "+", "0x...", "0o..." prefixes rejected — only ASCII digits 0-9.
//   - Overflow rejected (> uint64 max).
//
// On any failure returns a descriptive error so the RPC handler can
// surface a -32602 "invalid params" back to the client.
func parseStrictNonce(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("nonce string is empty (require a base-10 uint64, minimum 1)")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("nonce string %q contains non-ASCII-digit character %q (require base-10 uint64)", s, r)
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("nonce string %q parse: %w", s, err)
	}
	if n == 0 {
		return 0, fmt.Errorf("nonce 0 rejected — on-chain ProposerNonce must be strictly greater than the last recorded value (first proposal uses nonce 1)")
	}
	return n, nil
}

// proposalStatusString returns the string representation of a proposal's status.
func proposalStatusString(p *economics.Proposal) string {
	if p == nil {
		return "unknown"
	}
	switch p.Status {
	case economics.ProposalStatusPending:
		return "pending"
	case economics.ProposalStatusActive:
		return "active"
	case economics.ProposalStatusPassed:
		return "passed"
	case economics.ProposalStatusRejected:
		return "rejected"
	case economics.ProposalStatusExecuted:
		return "executed"
	case economics.ProposalStatusExpired:
		return "expired"
	default:
		return "unknown"
	}
}
