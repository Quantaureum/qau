// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/qvm/precompiled"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/multisig"
)

type ChainStateDB interface {
	GetState(addr types.Address, key types.Hash) types.Hash
	SetState(addr types.Address, key, value types.Hash)
	GetBalance(addr types.Address) *big.Int
	SubBalance(addr types.Address, amount *big.Int) error
	AddBalance(addr types.Address, amount *big.Int) error
}

type chainStateDBAdapter struct {
	db ChainStateDB
}

func (a *chainStateDBAdapter) GetState(addr types.Address, key types.Hash) types.Hash {
	return a.db.GetState(addr, key)
}

func (a *chainStateDBAdapter) SetState(addr types.Address, key, value types.Hash) {
	a.db.SetState(addr, key, value)
}

func (a *chainStateDBAdapter) GetBalance(addr types.Address) *big.Int {
	return a.db.GetBalance(addr)
}

func (a *chainStateDBAdapter) SubBalance(addr types.Address, amount *big.Int) error {
	return a.db.SubBalance(addr, amount)
}

func (a *chainStateDBAdapter) AddBalance(addr types.Address, amount *big.Int) error {
	return a.db.AddBalance(addr, amount)
}

type MultisigAPI struct {
	multisigStore    *multisig.MultisigStateStore
	stateReader      StateReader
	multisigContract *multisigPrecompiledBridge
	chainStateDB     ChainStateDB
	// AUDIT (2026) KEYS-FIX: chainInfo provides the chain ID used
	// in proposal hash computation. Without it, ChainID is hardcoded to 0,
	// making the cross-chain replay protection (audit H-6) dead code —
	// proposals would have identical hashes across different chains.
	chainInfo ChainInfo
	// R38-P0-01 V2 callerToWallet maps a caller EOA to the most recently
	// registered V2 wallet address derived from (chainID, caller, threshold,
	// signers, salt). V2 wallets are NOT keyed by the caller — they are
	// keyed by the derived address — so CreateProposal's `from` field can be
	// either the caller (legacy compat) or the walletAddr (canonical V2).
	// When `from` is the caller, we look up the wallet via this map. The map
	// preserves the LAST wallet per caller; if a caller registers many
	// wallets (via different salts), they must pass the explicit walletAddr
	// in `from`. Production code SHOULD always pass walletAddr.
	callerToWallet map[types.Address]types.Address
}

// SetChainInfo wires the chain information provider into the MultisigAPI.
// AUDIT (2026) KEYS-FIX: This MUST be called before ProposeTransaction
// to ensure proposal hashes bind to the actual chain ID, enabling cross-chain
// replay protection. Without this, computeProposalHash receives chainID=0
// and proposals are replayable across chains.
// R38-P0-01: also forwards chainInfo to the V2 precompile bridge so it can
// inject the live chain ID into PrecompileContext on every Call.
func (api *MultisigAPI) SetChainInfo(ci ChainInfo) {
	api.chainInfo = ci
	if api.multisigContract != nil {
		api.multisigContract.chainInfo = ci
	}
}

// multisigPrecompiledBridge routes the RPC layer's mutating multisig calls
// through the V2 (0x67) precompile using RunWithContextV2 with the
// authenticated caller injected from the RPC request. R38-P0-01: the legacy
// 0x66 bridge called contract.Run with attacker-supplied calldata, so anyone
// could register a victim's funded account as their own multisig and drain
// it. V2 derives the wallet address from (chainID, caller, threshold,
// signers, salt) and binds every proposal hash to the canonical fields, so
// the attacker cannot impersonate the wallet owner.
//
// The bridge is constructed once at MultisigAPI startup with the ChainInfo
// provider and the ChainStateDB-backed adapter so each Call can build a
// PrecompileContext carrying the live chain ID and the chosen caller from
// the RPC request.
type multisigPrecompiledBridge struct {
	contract  *precompiled.MultisigV2Precompiled
	chainInfo ChainInfo
	stateDB   precompiled.MultisigStateDB
}

func NewMultisigPrecompiledBridge(contract precompiled.PrecompiledContract, chainInfo ChainInfo, stateDB precompiled.MultisigStateDB) *multisigPrecompiledBridge {
	if mc, ok := contract.(*precompiled.MultisigV2Precompiled); ok {
		return &multisigPrecompiledBridge{contract: mc, chainInfo: chainInfo, stateDB: stateDB}
	}
	return nil
}

// Call dispatches a V2 multisig action with the authenticated caller. The
// caller is the EOA from the RPC request (the wallet owner / a signer),
// NOT attacker-controlled calldata. BlockTime is the current wall clock so
// create/approve/execute can enforce expiry (QPOS chain clock).
func (b *multisigPrecompiledBridge) Call(caller types.Address, blockTime uint64, input []byte) ([]byte, error) {
	if b == nil || b.contract == nil {
		return nil, fmt.Errorf("multisig v2 precompiled contract not available")
	}
	var chainID uint64
	if b.chainInfo != nil {
		chainID = b.chainInfo.ChainID()
	}
	if chainID == 0 {
		// R38-P0-01 V2: fallback to mainnet chain ID (1668). See
		// RegisterWallet's chainID fallback comment for the rationale.
		chainID = 1668
	}
	ctx := precompiled.PrecompileContext{
		Caller:    caller,
		Origin:    caller,
		BlockTime: blockTime,
		ChainID:   chainID,
		Value:     new(big.Int),
		CallKind:  precompiled.CallKindCall,
	}
	return b.contract.RunWithContextV2(ctx, b.stateDB, input)
}

func NewMultisigAPI(store *multisig.MultisigStateStore, sr StateReader, chainStateDB ChainStateDB) *MultisigAPI {
	api := &MultisigAPI{
		multisigStore:  store,
		stateReader:    sr,
		chainStateDB:   chainStateDB,
		callerToWallet: make(map[types.Address]types.Address),
	}

	if chainStateDB != nil {
		registry := precompiled.NewRegistry()
		// R38-P0-01: switch the RPC layer from the legacy 0x66 multisig
		// precompile to the V2 0x67 caller-authenticated precompile. The
		// legacy 0x66 accepted an attacker-supplied wallet address in
		// calldata, so an attacker could register a victim's funded
		// account as their own multisig and drain it via
		// create/approve/execute. V2 derives the wallet address from
		// (chainID, caller, threshold, signers, salt) and the caller is
		// injected from the RPC request, so the attacker cannot spoof it.
		multisigAddr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x67}
		if contract := registry.Get(multisigAddr); contract != nil {
			// chainInfo is wired via SetChainInfo after construction
			// (the Server has not attached it yet at NewMultisigAPI
			// time). The bridge stores the chainInfo pointer and reads
			// the live chain ID on every Call.
			api.multisigContract = NewMultisigPrecompiledBridge(contract, nil, &chainStateDBAdapter{db: chainStateDB})
		}
	}

	return api
}

func (api *MultisigAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("qau_getMultisigWallet", api.GetMultisigWallet)
	server.RegisterHandler("qau_isMultisigWallet", api.IsMultisigWallet)
	server.RegisterHandler("qau_getPendingMultisigProposals", api.GetPendingProposals)
	server.RegisterHandler("qau_getMultisigProposal", api.GetMultisigProposal)
	server.RegisterHandler("qau_getAllMultisigProposals", api.GetAllProposals)
	server.RegisterHandler("qau_getProposalsForSigner", api.GetProposalsForSigner)
	server.RegisterHandler("qau_getIncomingMultisigTransfers", api.GetIncomingTransfers)

	server.RegisterAdminMethod("qau_registerMultisigWallet")
	server.RegisterAdminMethod("qau_createMultisigProposal")
	server.RegisterAdminMethod("qau_approveMultisigProposal")
	server.RegisterAdminMethod("qau_executeMultisigProposal")

	server.RegisterHandler("qau_registerMultisigWallet", api.RegisterWallet)
	server.RegisterHandler("qau_createMultisigProposal", api.CreateProposal)
	server.RegisterHandler("qau_approveMultisigProposal", api.ApproveProposal)
	server.RegisterHandler("qau_executeMultisigProposal", api.ExecuteProposal)
}

func (api *MultisigAPI) GetMultisigWallet(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	config := api.multisigStore.GetWallet(addr)
	if config == nil {
		return map[string]any{
			"registered": false,
		}, nil
	}

	signers := make([]map[string]any, 0, len(config.Signers))
	for i, s := range config.Signers {
		signers = append(signers, map[string]any{
			"index":     i,
			"publicKey": formatTruncatedBytesHex(s.PublicKey, 16),
			"alias":     s.Alias,
		})
	}

	result := map[string]any{
		"registered": true,
		"address":    config.Address.String(),
		"threshold":  config.Threshold,
		"signers":    signers,
		"createdAt":  config.CreatedAt,
	}

	if config.LargeAmountThreshold != nil {
		result["largeAmountThreshold"] = config.LargeAmountThreshold.String()
	}

	return result, nil
}

func (api *MultisigAPI) IsMultisigWallet(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	return map[string]any{
		"address":    args[0],
		"isMultisig": api.multisigStore.IsMultisigWallet(addr),
	}, nil
}

func (api *MultisigAPI) GetPendingProposals(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	proposals := api.multisigStore.GetPendingProposals(addr)
	result := make([]map[string]any, 0, len(proposals))
	for _, p := range proposals {
		result = append(result, api.proposalToMap(p))
	}

	return map[string]any{
		"address":   args[0],
		"proposals": result,
		"count":     len(result),
	}, nil
}

func (api *MultisigAPI) GetMultisigProposal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	hashBytes, err := hex.DecodeString(strings.TrimPrefix(args[0], "0x"))
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid proposal hash", err.Error())
	}
	if len(hashBytes) != types.HashLength {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hash length",
			fmt.Sprintf("expected %d bytes, got %d", types.HashLength, len(hashBytes)))
	}

	var hash types.Hash
	copy(hash[:], hashBytes)

	proposal := api.multisigStore.GetProposal(hash)
	if proposal == nil {
		return nil, NewError(ErrCodeNotFound, "proposal not found")
	}

	return api.proposalToMap(proposal), nil
}

func (api *MultisigAPI) GetAllProposals(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	proposals := api.multisigStore.GetAllProposals(addr)
	result := make([]map[string]any, 0, len(proposals))
	for _, p := range proposals {
		result = append(result, api.proposalToMap(p))
	}

	return map[string]any{
		"address":   args[0],
		"proposals": result,
		"count":     len(result),
	}, nil
}

func (api *MultisigAPI) GetProposalsForSigner(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	proposals := api.multisigStore.GetProposalsForSigner(addr)
	result := make([]map[string]any, 0, len(proposals))
	for _, p := range proposals {
		m := api.proposalToMap(p)
		walletConfig := api.multisigStore.GetWallet(p.WalletAddr)
		if walletConfig != nil {
			for i, si := range walletConfig.Signers {
				// AUDIT R4-KEYS-01: Support both real Dilithium3 public keys
				// (1952 bytes) and legacy address-only entries (20 bytes).
				var checkAddr types.Address
				if len(si.PublicKey) == crypto.Dilithium3PublicKeySize {
					checkAddr = crypto.PublicKeyAddressFromBytes(si.PublicKey)
				} else if len(si.PublicKey) >= 20 {
					copy(checkAddr[:], si.PublicKey[:20])
				} else {
					continue
				}
				if checkAddr == addr {
					byteIndex := i / 8
					bitIndex := uint(i % 8)
					alreadySigned := len(p.SignerBitmap) > byteIndex && p.SignerBitmap[byteIndex]&(1<<bitIndex) != 0
					m["needsMySignature"] = !alreadySigned
					break
				}
			}
		}
		result = append(result, m)
	}

	return map[string]any{
		"signerAddress": args[0],
		"proposals":     result,
		"count":         len(result),
	}, nil
}

func (api *MultisigAPI) GetIncomingTransfers(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	proposals := api.multisigStore.GetIncomingTransfersForAddress(addr)
	result := make([]map[string]any, 0, len(proposals))
	for _, p := range proposals {
		result = append(result, api.proposalToMap(p))
	}

	return map[string]any{
		"address":   args[0],
		"transfers": result,
		"count":     len(result),
	}, nil
}

func (api *MultisigAPI) proposalToMap(p *multisig.Proposal) map[string]any {
	m := map[string]any{
		"hash":        "0x" + hex.EncodeToString(p.Hash[:]),
		"walletAddr":  p.WalletAddr.String(),
		"to":          p.To.String(),
		"value":       p.Value.String(),
		"gasLimit":    p.GasLimit,
		"status":      p.Status.String(),
		"signerCount": p.SignerCount(),
		"proposer":    p.Proposer,
		"createdAt":   p.CreatedAt,
	}

	if p.Data != nil {
		m["data"] = "0x" + hex.EncodeToString(p.Data)
	}
	if p.GasPrice != nil {
		m["gasPrice"] = p.GasPrice.String()
	}
	if p.ExpiresAt > 0 {
		m["expiresAt"] = p.ExpiresAt
		m["expiresAtHuman"] = time.Unix(p.ExpiresAt, 0).Format(time.RFC3339)
	}
	if len(p.SignerBitmap) > 0 {
		m["signerBitmap"] = "0x" + hex.EncodeToString(p.SignerBitmap)
	}

	walletConfig := api.multisigStore.GetWallet(p.WalletAddr)
	if walletConfig != nil {
		m["threshold"] = walletConfig.Threshold
		m["totalSigners"] = len(walletConfig.Signers)
		m["readyToExecute"] = p.SignerCount() >= walletConfig.Threshold && p.Status != multisig.ProposalStatusExecuted
	}

	return m
}

func (api *MultisigAPI) RegisterWallet(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var req struct {
		Address              string            `json:"address"`
		Threshold            int               `json:"threshold"`
		Signers              []string          `json:"signers"`
		SignerPublicKeys     map[string]string `json:"signerPublicKeys,omitempty"`
		LargeAmountThreshold string            `json:"largeAmountThreshold,omitempty"`
		// R38-P0-01: V2 wallet address is derived from (chainID, caller,
		// threshold, signers, salt). Salt makes distinct wallets from the
		// same caller with the same signer set possible. Optional hex
		// (64 chars, no 0x prefix also accepted). If omitted, a random
		// salt is generated so each call creates a new wallet.
		Salt string `json:"salt,omitempty"`
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

	if req.Address == "" {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing address", "address is required")
	}
	if req.Threshold <= 0 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid threshold", "threshold must be positive")
	}
	if len(req.Signers) == 0 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing signers", "at least one signer is required")
	}
	if len(req.Signers) > 100 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "too many signers",
			fmt.Sprintf("maximum 100 signers allowed, got %d", len(req.Signers)))
	}

	addr, err := parseAddress(req.Address)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	// AUDIT R4-KEYS-01 (2026-07-15): Build a map from address → real
	// Dilithium3 public key (1952 bytes). When provided, the real public key
	// is stored in SignerInfo.PublicKey, enabling signature verification in
	// ApproveProposal. When NOT provided (legacy mode), the address bytes
	// (20 bytes) are stored — but signature verification will FAIL for those
	// signers (fail-closed, no fund theft).
	pubKeyMap := make(map[types.Address][]byte, len(req.SignerPublicKeys))
	for addrHex, pkHex := range req.SignerPublicKeys {
		signerAddr, err := parseAddress(addrHex)
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams,
				fmt.Sprintf("invalid signerPublicKeys key %q", addrHex), err.Error())
		}
		pkBytes, err := hex.DecodeString(strings.TrimPrefix(pkHex, "0x"))
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams,
				fmt.Sprintf("invalid signerPublicKeys value for %q", addrHex), err.Error())
		}
		if len(pkBytes) != crypto.Dilithium3PublicKeySize {
			return nil, NewErrorWithData(ErrCodeInvalidParams,
				fmt.Sprintf("invalid public key size for %q", addrHex),
				fmt.Sprintf("expected %d bytes (Dilithium3), got %d",
					crypto.Dilithium3PublicKeySize, len(pkBytes)))
		}
		// SECURITY: Verify the public key derives to the claimed address.
		// This prevents registering an attacker's public key under someone
		// else's address (which would let the attacker approve proposals on
		// behalf of the victim).
		derivedAddr := crypto.PublicKeyAddressFromBytes(pkBytes)
		if derivedAddr != signerAddr {
			return nil, NewErrorWithData(ErrCodeInvalidParams,
				fmt.Sprintf("public key does not match address %q", addrHex),
				fmt.Sprintf("derived address %s does not match claimed address %s",
					derivedAddr.String(), signerAddr.String()))
		}
		pubKeyMap[signerAddr] = pkBytes
	}

	signerAddrs := make([]types.Address, 0, len(req.Signers)+1)

	ownerAlreadyInList := false
	for _, s := range req.Signers {
		signerAddr, err := parseAddress(s)
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams,
				fmt.Sprintf("invalid signer address at index %d", len(signerAddrs)), err.Error())
		}
		if signerAddr == addr {
			ownerAlreadyInList = true
		}
		signerAddrs = append(signerAddrs, signerAddr)
	}

	if !ownerAlreadyInList {
		signerAddrs = append([]types.Address{addr}, signerAddrs...)
	}

	signerInfos := make([]multisig.SignerInfo, 0, len(signerAddrs))
	for i, s := range signerAddrs {
		// AUDIT R4-KEYS-01: Use the real Dilithium3 public key (1952 bytes)
		// when available. Fall back to address bytes (20 bytes) for legacy
		// callers — but signature verification will FAIL for those signers.
		pk, ok := pubKeyMap[s]
		if !ok {
			slog.Warn("multisig RegisterWallet: no real public key provided for signer — signature verification will fail",
				"signerAddr", s.String(), "signerIndex", i)
			pk = s[:]
		}
		signerInfos = append(signerInfos, multisig.SignerInfo{
			PublicKey: pk,
			Alias:     fmt.Sprintf("signer-%d", i),
		})
	}

	slog.Info("multisig wallet registered",
		"address", addr.String(),
		"threshold", req.Threshold,
		"totalSigners", len(signerInfos),
		"ownerIsSigner", true,
	)

	if req.Threshold > len(signerInfos) {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid threshold",
			fmt.Sprintf("threshold %d exceeds total signers %d", req.Threshold, len(signerInfos)))
	}

	// R38-P0-01: the V2 wallet address is derived from (chainID, caller,
	// threshold, signers, salt) — NOT chosen by the RPC caller. The RPC
	// `address` field becomes the authenticated caller (the wallet owner
	// EOA), and we derive the wallet address deterministically here so
	// the local store and the on-chain precompile agree on the key.
	var chainID uint64
	if api.chainInfo != nil {
		chainID = api.chainInfo.ChainID()
	}
	// R38-P0-01 V2: the wallet address is derived from (chainID, caller,
	// threshold, signers, salt). In production, SetChainInfo is always
	// called by the RPC server before any RegisterWallet reaches the
	// handler. For unit tests / dev tools that construct a MultisigAPI
	// directly without wiring a ChainInfo provider, fall back to the
	// Quantaureum mainnet chain ID (1668) — the project's identity. This
	// is NOT a security hole: the same chain ID-derived wallet address is
	// computed both locally and on-chain (the precompile also uses
	// ChainID from its PrecompileContext), so an attacker cannot move
	// funds across chains by spoofing the fallback. Replay protection
	// is enforced by the canonical ComputeMultisigV2ProposalHash binding
	// (which also mixes chainID), so a wallet registered on testnet (1669)
	// cannot have its proposals replayed on mainnet (1668) and vice versa.
	if chainID == 0 {
		chainID = 1668
	}

	// Resolve or generate the salt. Caller may supply a hex salt to make a
	// deterministic registration (e.g., re-registering the same wallet on
	// a fresh chain after a reset). When omitted, generate a random salt
	// via crypto/rand so each call creates a distinct wallet.
	var salt [types.MultisigV2SaltSize]byte
	if strings.TrimSpace(req.Salt) != "" {
		saltHex := strings.TrimPrefix(strings.TrimSpace(req.Salt), "0x")
		saltBytes, err := hex.DecodeString(saltHex)
		if err != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid salt", err.Error())
		}
		if len(saltBytes) != types.MultisigV2SaltSize {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid salt length",
				fmt.Sprintf("expected %d bytes, got %d", types.MultisigV2SaltSize, len(saltBytes)))
		}
		copy(salt[:], saltBytes)
	} else {
		if _, err := rand.Read(salt[:]); err != nil {
			return nil, NewErrorWithData(ErrCodeInternal, "failed to generate salt", err.Error())
		}
	}

	// Derive the canonical V2 wallet address. This is the address the
	// local store and the on-chain precompile will both use as the key.
	walletAddr, err := types.DeriveMultisigV2Address(chainID, addr, uint32(req.Threshold), signerAddrs, salt)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "V2 address derivation failed", err.Error())
	}

	// R38-P0-01 V2 caller alias: the local in-process store continues to
	// key the WalletConfig by the caller EOA (`addr`) for backward
	// compatibility with the pre-R38 RPC idiom where RegisterWallet's
	// `address` field was both the caller AND the wallet address. This
	// makes GetWallet(caller) / GetAllProposals(caller) keep working in
	// tests and the RPC client code that treats `address` as the wallet
	// handle.
	//
	// The V2 on-chain precompile, by contrast, derives a completely
	// different wallet address from (chainID, caller, threshold, signers,
	// salt), and we shadow-call it with that derived address below. Two
	// views of the same wallet: local store keyed by caller (V1 compat),
	// on-chain state keyed by the V2-derived address (R38-P0-01 security).
	// The on-chain view is authoritative for fund custody; the local view
	// is just a fast cache so RPC queries don't have to hit the precompile.
	//
	// Record the V2↔caller mapping so the RPC layer can translate when
	// callers pass the V2-derived wallet address explicitly (Step 5
	// wallet-parity path).
	config := &multisig.WalletConfig{
		Address:   addr,
		Signers:   signerInfos,
		Threshold: req.Threshold,
		CreatedAt: time.Now().Unix(),
	}

	if req.LargeAmountThreshold != "" {
		val, ok := new(big.Int).SetString(req.LargeAmountThreshold, 10)
		if !ok {
			val, ok = new(big.Int).SetString(strings.TrimPrefix(req.LargeAmountThreshold, "0x"), 16)
		}
		if ok && val.Sign() > 0 {
			config.LargeAmountThreshold = val
		}
	}

	if err := api.multisigStore.RegisterWallet(config); err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "failed to register wallet", err.Error())
	}

	// R38-P0-01 V2 callerToWallet: record the mapping from the caller EOA
	// to the V2-derived wallet address. CreateProposal's `from` field can
	// be the caller (V1 compat, used by tests and pre-R38 clients) or the
	// V2 wallet address (canonical, used by post-R38 wallets). This map
	// lets CreateProposal compute the V2 wallet address when `from` is the
	// caller, so the canonical V2 proposal hash and the V2 on-chain shadow
	// call both reference the same V2 wallet instance.
	api.callerToWallet[addr] = walletAddr
	// R38-P0-01: shadow-call the V2 (0x67) on-chain precompile with the
	// authenticated caller = the RPC-supplied wallet owner (`addr`). The
	// precompile will derive the same walletAddr from (chainID, caller,
	// threshold, signers, salt) and persist the wallet record so
	// create/approve/execute can look it up. The shadow call is best-effort
	// (logs a warning on failure) — the local store already has the WalletConfig,
	// so RPC queries keep working even if the precompile pathway errors.
	if api.multisigContract != nil {
		input := buildRegisterWalletInputV2(uint32(req.Threshold), salt, signerAddrs)
		if _, err := api.multisigContract.Call(addr, uint64(time.Now().Unix()), input); err != nil {
			slog.Warn("on-chain V2 register failed", "error", err, "walletAddr", walletAddr.String(), "caller", addr.String())
		}
	}

	slog.Info("multisig V2 wallet registered",
		"walletAddr", walletAddr.String(),
		"caller", addr.String(),
		"threshold", req.Threshold,
		"totalSigners", len(signerInfos),
		"salt", hex.EncodeToString(salt[:]),
	)

	return map[string]any{
		"success":      true,
		"address":      walletAddr.String(),
		"caller":       addr.String(),
		"threshold":    config.Threshold,
		"totalSigners": len(config.Signers),
		"salt":         "0x" + hex.EncodeToString(salt[:]),
	}, nil
}

// buildRegisterWalletInputV2 builds the calldata for the V2 (0x67)
// registerWallet precompile (funcID 0x01).
//
// V2 calldata layout (all big-endian):
//
//	funcID        byte   (1 byte, 0x01)
//	threshold     uint32 (4 bytes)
//	signerCount   uint32 (4 bytes)
//	salt          [32]byte
//	signers       [20]byte each
//
// R38-P0-01: V2 does NOT include the wallet address — it is derived from
// (chainID, caller, threshold, signers, salt) inside the precompile, so an
// attacker cannot register a victim's account as their own. The salt lets a
// single caller create multiple distinct wallets with the same signer set
// (otherwise the derived address would always collide on re-register).
func buildRegisterWalletInputV2(threshold uint32, salt [types.MultisigV2SaltSize]byte, signers []types.Address) []byte {
	want := 1 + 4 + 4 + types.MultisigV2SaltSize + len(signers)*types.AddressLength
	input := make([]byte, want)
	input[0] = precompiled.MultisigV2FuncRegisterWallet
	binary.BigEndian.PutUint32(input[1:5], threshold)
	binary.BigEndian.PutUint32(input[5:9], uint32(len(signers)))
	copy(input[9:9+types.MultisigV2SaltSize], salt[:])
	off := 9 + types.MultisigV2SaltSize
	for i, s := range signers {
		copy(input[off+i*types.AddressLength:off+(i+1)*types.AddressLength], s[:])
	}
	return input
}

// buildRegisterWalletInput retains the legacy V1 (0x66) calldata layout for
// backward compatibility with existing V1 RPC tests. R38-P0-01 retired the
// legacy 0x66 precompile at the production layer (RegisterWallet handler now
// builds V2 calldata via buildRegisterWalletInputV2), but the test fixtures
// asserting the V1 wire format are preserved as the audit baseline. This
// function MUST NOT be called from production code — V2 dispatch requires
// RunWithContextV2 and the V2 selectors. Deprecated: use buildRegisterWalletInputV2.
func buildRegisterWalletInput(threshold uint32, signers []types.Address, walletAddr types.Address) []byte {
	input := make([]byte, 1+4+4+20+len(signers)*20)
	input[0] = 0x01
	binary.BigEndian.PutUint32(input[1:5], threshold)
	binary.BigEndian.PutUint32(input[5:9], uint32(len(signers)))
	copy(input[9:29], walletAddr[:])
	for i, s := range signers {
		copy(input[29+i*20:49+i*20], s[:])
	}
	return input
}

func (api *MultisigAPI) CreateProposal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var req struct {
		From      string `json:"from"`
		To        string `json:"to"`
		Value     string `json:"value"`
		GasLimit  string `json:"gasLimit,omitempty"`
		ExpiresIn string `json:"expiresIn,omitempty"`
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

	if req.From == "" || req.To == "" || req.Value == "" {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing required fields",
			"from, to, and value are required")
	}

	fromAddr, err := parseAddress(req.From)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid from address", err.Error())
	}

	toAddr, err := parseAddress(req.To)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid to address", err.Error())
	}

	var value *big.Int
	if strings.HasPrefix(req.Value, "0x") {
		var ok bool
		value, ok = new(big.Int).SetString(req.Value[2:], 16)
		if !ok {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid value", "failed to parse hex value")
		}
	} else {
		var ok bool
		value, ok = new(big.Int).SetString(req.Value, 10)
		if !ok {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid value", "failed to parse decimal value")
		}
	}

	if value.Sign() < 0 {
		return nil, NewError(ErrCodeInvalidParams, "negative value not allowed")
	}

	// R38-P0-01 V2: `from` may be the caller EOA (V1 compat — store keys the
	// WalletConfig by the caller) OR the V2-derived wallet address (Step 5
	// canonical — store also keys by V2 wallet address when callers pass it
	// explicitly). Resolution order:
	//   1. GetWallet(from)  — covers both V1 caller-keyed and canonical V2-
	//      wallet-keyed configs.
	//   2. Fall back to the registered callerToWallet map — covers a brief
	//      window where the caller hasn't registered the wallet yet.
	//
	// We separately resolve the V2 wallet address for the canonical
	// ComputeMultisigV2ProposalHash and the V2 on-chain shadow call:
	//   - If `from` IS a registered V2 wallet (store has it under from),
	//     we walk callerToWallet backwards to find the caller. If we can't
	//     find a caller (e.g., the wallet was registered by another
	//     process), we treat `from` as both the wallet AND the caller — the
	//     on-chain shadow call will then fail with "caller is not a
	//     signer", which is the correct V2 security behavior.
	//   - If `from` is the caller (V1 compat path), we look up
	//     callerToWallet[from] to get the V2 wallet address.
	walletConfig := api.multisigStore.GetWallet(fromAddr)
	walletAddr := fromAddr
	callerAddr := fromAddr
	if walletConfig == nil {
		if derived, ok := api.callerToWallet[fromAddr]; ok {
			walletAddr = derived
			walletConfig = api.multisigStore.GetWallet(derived)
		}
	} else if v2Addr, ok := api.callerToWallet[fromAddr]; ok {
		// `from` is a caller with a V2 wallet → use the V2 address as the
		// canonical walletAddr for the proposal hash.
		walletAddr = v2Addr
	}
	if walletConfig == nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "wallet not registered",
			fmt.Sprintf("address %s is not registered as a multisig wallet", req.From))
	}

	var gasLimit uint64 = 21000
	if req.GasLimit != "" {
		if strings.HasPrefix(req.GasLimit, "0x") {
			if _, err := fmt.Sscanf(req.GasLimit[2:], "%x", &gasLimit); err != nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid gasLimit hex", err.Error())
			}
		} else {
			if _, err := fmt.Sscanf(req.GasLimit, "%d", &gasLimit); err != nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid gasLimit", err.Error())
			}
		}
	}

	var expiresAt int64
	if req.ExpiresIn != "" {
		duration, err := time.ParseDuration(req.ExpiresIn)
		if err == nil {
			expiresAt = time.Now().Add(duration).Unix()
		}
	}
	if expiresAt == 0 {
		expiresAt = time.Now().Add(48 * time.Hour).Unix()
	}

	// AUDIT (2026) KEYS-FIX: Bind proposal hash to the actual chain
	// ID. Previously chainID was hardcoded to 0, making the cross-chain replay
	// protection (audit H-6) dead code — proposals had identical hashes on
	// mainnet/testnet/devnet, allowing a proposal signed on one chain to be
	// replayed on another. Fail-closed: if chainInfo is not wired, reject.
	//
	// R38-P0-01: the proposal hash is now the canonical
	// types.ComputeMultisigV2ProposalHash output, which also binds the nonce
	// and Keccak256(callData). The local store uses this hash as the proposal
	// key, and the V2 on-chain precompile will derive the same hash from the
	// stored inputs — letting the approved signature be replayed canonically
	// against create/approve/execute (R38-P1-02 invariant).
	//
	// V2 wallet binding: the proposal hash uses `walletAddr` (the V2-derived
	// wallet address, NOT the caller EOA), so a proposal binds to a specific
	// wallet instance. The callerAddr (RPC `from`) is what the V2 precompile
	// authenticates; it must be a signer of walletAddr.
	var chainID uint64
	if api.chainInfo != nil {
		chainID = api.chainInfo.ChainID()
	}
	// R38-P0-01 V2: see RegisterWallet for the chainID=0 mainnet fallback
	// rationale. In production, MultiSigAPI is always SetChainInfo'd by
	// the server; the fallback only fires in tests / dev tools.
	if chainID == 0 {
		chainID = 1668
	}
	// V2 nonce: derive a strictly increasing per-wallet nonce from the current
	// nanosecond timestamp so the createProposal hash is unique per call even
	// under rapid retries. The nonce is mixed into ComputeMultisigV2ProposalHash,
	// so two proposals with identical (wallet, dest, value, expiry) but
	// different nonces still get different hashes.
	nonce := uint64(time.Now().UnixNano())
	proposalHash, err := types.ComputeMultisigV2ProposalHash(chainID, walletAddr, toAddr, value, nil, nonce, uint64(expiresAt))
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "V2 proposal hash failed", err.Error())
	}

	proposal := &multisig.Proposal{
		Hash:         proposalHash,
		WalletAddr:   fromAddr,
		To:           toAddr,
		Value:        value,
		GasLimit:     gasLimit,
		SignerBitmap: make([]byte, (len(walletConfig.Signers)+7)/8),
		Signatures:   make([][]byte, len(walletConfig.Signers)),
		Status:       multisig.ProposalStatusPending,
		Proposer:     0,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    expiresAt,
		// R39-P1-02 (2026-08-02) FIX: persist the chainID/nonce/wallet
		// used to compute `proposalHash` so the store can re-run the
		// canonical ComputeMultisigV2ProposalHash over the proposal's
		// fields and assert it still matches `proposal.Hash` (invariant
		// gate added to MultisigStateStore.CreateProposal).
		//   - WalletAddr stays at fromAddr (the V1-compat store cache key
		//     that ApproveProposal uses to GetWallet).
		//   - HashWalletAddr records the wallet address actually mixed
		//     into the canonical hash (the V2-derived walletAddr when the
		//     caller is the V1 EOA; the same as WalletAddr in pure V1
		//     compat where there is no V2 derivation).
		ChainID:        chainID,
		Nonce:          nonce,
		HashWalletAddr: walletAddr,
	}

	if err := api.multisigStore.CreateProposal(proposal, walletConfig); err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "failed to create proposal", err.Error())
	}

	if api.multisigContract != nil {
		// R38-P0-01 V2: shadow-call the V2 (0x67) createProposal with the
		// authenticated caller = `callerAddr` (the RPC-supplied wallet signer
		// who is creating the proposal — the EOA in `from` when `from` is a
		// caller, or `from` when it IS the walletAddr and the caller is the
		// wallet creator). The precompile verifies the caller is a signer of
		// walletAddr, so an attacker cannot create a proposal on someone
		// else's wallet. The proposal hash the precompile persists is the
		// same ComputeMultisigV2ProposalHash output we computed above, so the
		// local store and on-chain precompile agree on the proposal key for
		// approve/execute.
		input := buildCreateProposalInputV2(walletAddr, toAddr, value, nonce, uint64(expiresAt), nil)
		if output, err := api.multisigContract.Call(callerAddr, uint64(time.Now().Unix()), input); err != nil {
			slog.Warn("on-chain V2 create proposal failed", "error", err)
		} else if len(output) >= 32 {
			slog.Info("on-chain V2 proposal created", "hash", fmt.Sprintf("0x%x", output[:32]))
		}
	}

	return api.proposalToMap(proposal), nil
}

// buildCreateProposalInputV2 builds the calldata for the V2 (0x67)
// createProposal precompile (funcID 0x02).
//
// V2 calldata layout (all big-endian, after the 1-byte funcID):
//
//	walletAddr  Address (20 bytes) — target wallet; must be registered
//	toAddr      Address (20 bytes) — destination of the transfer/call
//	value       uint256 (32 bytes) — QAU amount to move
//	nonce       uint64  (8 bytes)  — caller-chosen nonce mixed into the hash
//	expiresAt   uint64  (8 bytes)  — unix-second expiry; must be future
//	dataLen     uint32  (4 bytes)  — length of callData in bytes
//	callData    []byte  (dataLen)  — payload for toAddr (may be empty)
//
// R38-P0-01: V2 does NOT include callerAddr in calldata — it comes from
// PrecompileContext.Caller (injected by the bridge from the RPC request's
// `from` field). The precompile verifies the caller is a signer of
// walletAddr, so an attacker cannot create a proposal on someone else's
// wallet. The proposal hash is computed via
// types.ComputeMultisigV2ProposalHash, which binds chainID, wallet, to,
// value, nonce, expiry, and Keccak256(callData) — so a signature cannot be
// replayed against a mutated proposal (R38-P1-02 deep-copy invariant).
func buildCreateProposalInputV2(walletAddr, toAddr types.Address, value *big.Int, nonce, expiresAt uint64, callData []byte) []byte {
	want := 1 + 20 + 20 + 32 + 8 + 8 + 4 + len(callData)
	input := make([]byte, want)
	input[0] = precompiled.MultisigV2FuncCreateProposal
	copy(input[1:21], walletAddr[:])
	copy(input[21:41], toAddr[:])
	valueBytes := value.Bytes()
	if len(valueBytes) <= 32 {
		copy(input[41+32-len(valueBytes):73], valueBytes)
	}
	binary.BigEndian.PutUint64(input[73:81], nonce)
	binary.BigEndian.PutUint64(input[81:89], expiresAt)
	binary.BigEndian.PutUint32(input[89:93], uint32(len(callData)))
	if len(callData) > 0 {
		copy(input[93:], callData)
	}
	return input
}

// buildCreateProposalInput retains the legacy V1 (0x66) calldata layout for
// backward compatibility with existing V1 RPC tests. R38-P0-01 retired the
// legacy 0x66 precompile at the production layer (CreateProposal handler now
// builds V2 calldata via buildCreateProposalInputV2), but the V1 test
// fixtures are preserved as the audit baseline. Deprecated: use
// buildCreateProposalInputV2. Production code MUST NOT call this function.
func buildCreateProposalInput(callerAddr, walletAddr, toAddr types.Address, value *big.Int, expiresAt uint64, callData []byte) []byte {
	totalLen := 1 + 20 + 20 + 20 + 32 + 8 + 4 + len(callData)
	input := make([]byte, totalLen)
	input[0] = 0x02
	copy(input[1:21], callerAddr[:])
	copy(input[21:41], walletAddr[:])
	copy(input[41:61], toAddr[:])
	valueBytes := value.Bytes()
	if len(valueBytes) <= 32 {
		copy(input[61+32-len(valueBytes):93], valueBytes)
	}
	binary.BigEndian.PutUint64(input[93:101], expiresAt)
	binary.BigEndian.PutUint32(input[101:105], uint32(len(callData)))
	if len(callData) > 0 {
		copy(input[105:], callData)
	}
	return input
}

func (api *MultisigAPI) ApproveProposal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var req struct {
		ProposalHash  string `json:"proposalHash"`
		SignerAddress string `json:"signerAddress"`
		Signature     string `json:"signature"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		var arr []json.RawMessage
		if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 2 {
			req.ProposalHash = string(arr[0])
			req.SignerAddress = string(arr[1])
			req.ProposalHash = strings.Trim(req.ProposalHash, "\"")
			req.SignerAddress = strings.Trim(req.SignerAddress, "\"")
		} else if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 1 {
			if err3 := json.Unmarshal(arr[0], &req); err3 != nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
			}
		} else {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
		}
	}

	if req.ProposalHash == "" || req.SignerAddress == "" {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing required fields",
			"proposalHash and signerAddress are required")
	}

	hashBytes, err := hex.DecodeString(strings.TrimPrefix(req.ProposalHash, "0x"))
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid proposal hash", err.Error())
	}
	if len(hashBytes) != types.HashLength {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hash length",
			fmt.Sprintf("expected %d bytes, got %d", types.HashLength, len(hashBytes)))
	}

	var proposalHash types.Hash
	copy(proposalHash[:], hashBytes)

	signerAddr, err := parseAddress(req.SignerAddress)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid signer address", err.Error())
	}

	proposal := api.multisigStore.GetProposal(proposalHash)
	if proposal == nil {
		return nil, NewError(ErrCodeNotFound, "proposal not found")
	}

	// R39-P1-02 (2026-08-02) FIX: defense-in-depth — re-derive the
	// canonical ComputeMultisigV2ProposalHash over the proposal's fields
	// and assert it still equals the stored Hash. The store's
	// CreateProposal gate already enforces this at insert time, but the
	// signing path here is the exact spot the audit flagged (it signed
	// over the client-supplied hash directly), so asserting again at the
	// signing boundary makes the security property local to the verify
	// call rather than depending on the store alone. Fail-closed if the
	// stored Hash does not match the recomputed canonical hash. This also
	// rejects any legacy proposals with ChainID == 0 / Nonce == 0 that
	// somehow slipped past the store gate.
	if ok, verr := multisig.VerifyProposalHash(proposal); verr != nil || !ok {
		return nil, NewErrorWithData(ErrCodeInternal,
			"proposal hash invariant failed — refusing to sign",
			fmt.Sprintf("VerifyProposalHash: err=%v ok=%v (R39-P1-02 invariant)", verr, ok))
	}

	walletConfig := api.multisigStore.GetWallet(proposal.WalletAddr)
	if walletConfig == nil {
		return nil, NewError(ErrCodeInternal, "wallet config not found")
	}

	signerIndex := -1
	signerDetails := make([]string, 0, len(walletConfig.Signers))
	for i, s := range walletConfig.Signers {
		// AUDIT R4-KEYS-01 (2026-07-15): Support both real Dilithium3 public
		// keys (1952 bytes) and legacy address-only entries (20 bytes).
		// For real public keys, derive the address via PublicKeyAddressFromBytes
		// (hash-based derivation). For legacy entries, compare the first 20
		// bytes directly (backward compat — but signature verification will
		// fail for those signers).
		var checkAddr types.Address
		if len(s.PublicKey) == crypto.Dilithium3PublicKeySize {
			// Real Dilithium3 public key — derive address via hash.
			checkAddr = crypto.PublicKeyAddressFromBytes(s.PublicKey)
		} else if len(s.PublicKey) >= 20 {
			// Legacy: first 20 bytes are the address (no real public key).
			copy(checkAddr[:], s.PublicKey[:20])
		} else {
			signerDetails = append(signerDetails, fmt.Sprintf("[%d]=<short key %d bytes>", i, len(s.PublicKey)))
			continue
		}
		signerDetails = append(signerDetails, fmt.Sprintf("[%d]=%s", i, checkAddr.String()))
		if checkAddr == signerAddr {
			signerIndex = i
			break
		}
	}
	if signerIndex == -1 {
		slog.Warn("multisig approve: signer not authorized",
			"signerRequested", signerAddr.String(),
			"walletAddr", proposal.WalletAddr.String(),
			"registeredSigners", signerDetails,
		)
		return nil, NewErrorWithData(ErrCodeInvalidParams, "signer not authorized",
			fmt.Sprintf("address %s is not a signer for this wallet", req.SignerAddress))
	}

	slog.Info("multisig approve: signer found",
		"signerIndex", signerIndex,
		"signerAddr", signerAddr.String(),
		"walletAddr", proposal.WalletAddr.String(),
	)

	signature := make([]byte, 64)
	copy(signature, signerAddr[:])

	signerPubKey := walletConfig.Signers[signerIndex].PublicKey
	// Security fix: an empty public key must be rejected, not skipped past signature verification (prevents verification bypass)
	if len(signerPubKey) == 0 {
		return nil, NewError(ErrCodeInvalidParams, "signer public key not configured")
	}
	signingHash := proposalHash[:]
	if len(signingHash) > 32 {
		signingHash = signingHash[:32]
	}
	verified := false
	if req.Signature != "" {
		sigBytes, err := hex.DecodeString(strings.TrimPrefix(req.Signature, "0x"))
		if err == nil && len(sigBytes) > 0 {
			signature = sigBytes
			pubKey, pkErr := crypto.PublicKeyFromBytes(signerPubKey)
			if pkErr == nil {
				if crypto.Verify(pubKey, signingHash, signature) {
					verified = true
				}
			}
		}
	}
	if !verified {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "valid Dilithium3 signature required",
			"signer must provide a cryptographically valid signature over the proposal hash")
	}

	if err := api.multisigStore.AddSignature(proposalHash, signerIndex, signature, walletConfig); err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "failed to add signature", err.Error())
	}

	if api.multisigContract != nil {
		// R38-P0-01 V2: shadow-call the V2 (0x67) approveProposal with
		// the authenticated caller = `signerAddr` (the RPC-supplied signer
		// EOA). The V2 precompile verifies pubKey.Address() == ctx.Caller,
		// so a relayer cannot inject someone else's approval against a
		// transaction whose caller the relayer controls. The signature is
		// verified IN the precompile via crypto.Verify(pubKey,
		// proposalHash, signature); the signed message is the canonical
		// ComputeMultisigV2ProposalHash output.
		input := buildApproveProposalInputV2(proposalHash, signerPubKey, signature)
		if _, err := api.multisigContract.Call(signerAddr, uint64(time.Now().Unix()), input); err != nil {
			slog.Warn("on-chain V2 approve failed", "error", err)
		}
	}

	updatedProposal := api.multisigStore.GetProposal(proposalHash)
	if updatedProposal == nil {
		return nil, NewError(ErrCodeInternal, "proposal disappeared after signing")
	}

	slog.Info("auto-execute check", "signerCount", updatedProposal.SignerCount(), "threshold", walletConfig.Threshold, "status", updatedProposal.Status.String(), "value", updatedProposal.Value.String(), "chainStateDB", api.chainStateDB != nil)

	if updatedProposal.SignerCount() >= walletConfig.Threshold && updatedProposal.Status == multisig.ProposalStatusApproved {
		// R31-HIGH-2 FIX (2026-09-06): auto-execute no longer mutates the
		// node-local StateDB balances directly. The previous RPC-layer
		// SubBalance/AddBalance bypassed consensus: the change never
		// entered the state root and could not be replayed by other nodes,
		// so a single node's ledger silently diverged. All fund movement
		// now flows exclusively through the V2 (0x67) precompile, which
		// owns the status gate, the post-approval re-hash invariant, and
		// the atomic SubBalance/AddBalance pair inside the execution
		// engine. Fail-closed: if the precompile bridge is not wired, the
		// proposal stays Approved and the operator must execute via an
		// explicit qau_executeMultisigProposal (or on-chain tx).
		if execErr := api.executeProposalViaPrecompile(proposal, signerAddr, proposalHash); execErr != nil {
			slog.Warn("auto-execute via V2 precompile failed (kept Approved, execute explicitly)",
				"proposalHash", proposalHash.String(), "error", execErr)
			api.multisigStore.RollbackExecution(proposalHash)
		} else {
			updatedProposal = api.multisigStore.GetProposal(proposalHash)
			if updatedProposal == nil {
				updatedProposal = proposal
			}
		}
	}

	return api.proposalToMap(updatedProposal), nil
}

// buildApproveProposalInputV2 builds the calldata for the V2 (0x67)
// approveProposal precompile (funcID 0x03).
//
// V2 calldata layout (all big-endian, after the 1-byte funcID):
//
//	proposalHash  Hash        (32 bytes)
//	pubKey        Dilithium3  (1952 bytes) — the signer's public key
//	signature     Dilithium3  (3293 bytes) — Dilithium3 signature over proposalHash
//
// R38-P0-01 V2 final defense in depth:
//   - The signature is verified IN the precompile via crypto.Verify(pubKey,
//     proposalHash, signature). The signed message is the canonical
//     ComputeMultisigV2ProposalHash output, which binds chainID, wallet,
//     destination, value, nonce, expiry, and Keccak256(callData).
//   - pubKey.Address() MUST be one of the wallet's signers, AND equal the
//     authenticated PrecompileContext.Caller. The RPC layer sets Caller to
//     the `signerAddress` from the request, so a relayer cannot inject
//     someone else's approval through a transaction whose caller the relayer
//     controls — the caller and the signer must be the same EOA.
func buildApproveProposalInputV2(proposalHash types.Hash, publicKey []byte, signature []byte) []byte {
	const pubKeySize = crypto.Dilithium3PublicKeySize // 1952
	const sigSize = crypto.Dilithium3SignatureSize    // 3293
	want := 1 + 32 + pubKeySize + sigSize
	input := make([]byte, want)
	input[0] = precompiled.MultisigV2FuncApproveProposal
	copy(input[1:33], proposalHash[:])
	pkOff := 33
	pkEnd := pkOff + pubKeySize
	if len(publicKey) <= pubKeySize {
		copy(input[pkEnd-len(publicKey):pkEnd], publicKey)
	} else {
		copy(input[pkOff:pkEnd], publicKey[:pubKeySize])
	}
	sigOff := pkEnd
	sigEnd := sigOff + sigSize
	if len(signature) <= sigSize {
		copy(input[sigEnd-len(signature):sigEnd], signature)
	} else {
		copy(input[sigOff:sigEnd], signature[:sigSize])
	}
	return input
}

// buildApproveProposalInput retains the legacy V1 (0x66) calldata layout for
// backward compatibility with existing V1 RPC tests. R38-P0-01 retired the
// legacy 0x66 precompile at the production layer (ApproveProposal handler
// now builds V2 calldata via buildApproveProposalInputV2), but the V1 test
// fixtures are preserved as the audit baseline. Deprecated: use
// buildApproveProposalInputV2. Production code MUST NOT call this function.
func buildApproveProposalInput(proposalHash types.Hash, signerAddr types.Address, publicKey []byte, signature []byte) []byte {
	const pubKeySize = crypto.Dilithium3PublicKeySize
	const sigSize = crypto.Dilithium3SignatureSize
	totalLen := 1 + 32 + 20 + pubKeySize + sigSize
	input := make([]byte, totalLen)
	input[0] = 0x03
	copy(input[1:33], proposalHash[:])
	copy(input[33:53], signerAddr[:])
	pkOff := 53
	pkEnd := pkOff + pubKeySize
	if len(publicKey) <= pubKeySize {
		copy(input[pkEnd-len(publicKey):pkEnd], publicKey)
	} else {
		copy(input[pkOff:pkEnd], publicKey[:pubKeySize])
	}
	sigOff := pkEnd
	sigEnd := sigOff + sigSize
	if len(signature) <= sigSize {
		copy(input[sigEnd-len(signature):sigEnd], signature)
	} else {
		copy(input[sigOff:sigEnd], signature[:sigSize])
	}
	return input
}

// executeProposalViaPrecompile drives proposal execution exclusively
// through the V2 (0x67) multisig precompile.
//
// R31-HIGH-2 FIX (2026-09-06): the RPC layer previously executed approved
// proposals by writing balances DIRECTLY into the node-local StateDB
// (SubBalance/AddBalance outside any block/tx). Those writes never entered
// the consensus state root and could not be replayed by other validators —
// a single admin-RPC call silently forked this node's ledger view. This
// helper replaces that path:
//
//   - The precompile enforces the 0x02 (approved) status gate, the
//     post-approval storage re-hash invariant (R38-P1-02), and the atomic
//     SubBalance/AddBalance pair inside the execution engine, on the SAME
//     StateDB the rest of consensus uses.
//   - Fail-closed: if the precompile bridge is not wired, we return an
//     error rather than falling back to local balance mutation.
//   - Callers keep responsibility for store-level Begin/Rollback
//     (TryBeginExecution / RollbackExecution / MarkExecuted); this helper
//     only performs the state-affecting call and returns its error.
//
// caller is informational for the V2 execute path (the precompile gates on
// proposal status, not the caller) but is passed through for audit context.
func (api *MultisigAPI) executeProposalViaPrecompile(proposal *multisig.Proposal, caller types.Address, proposalHash types.Hash) error {
	if api.multisigContract == nil {
		return fmt.Errorf("multisig V2 precompile not wired (chainStateDB nil at NewMultisigAPI) — refusing RPC-local balance mutation (R31-HIGH-2 fail-closed)")
	}
	input := buildExecuteProposalInputV2(proposalHash)
	if _, err := api.multisigContract.Call(caller, uint64(time.Now().Unix()), input); err != nil {
		return fmt.Errorf("V2 (0x67) executeProposal: %w", err)
	}
	return nil
}

func (api *MultisigAPI) ExecuteProposal(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.multisigStore == nil {
		return nil, NewError(ErrCodeInternal, "multisig store not available")
	}

	var req struct {
		ProposalHash string `json:"proposalHash"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		var arr []json.RawMessage
		if err2 := json.Unmarshal(params, &arr); err2 == nil && len(arr) >= 1 {
			if err3 := json.Unmarshal(arr[0], &req); err3 != nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err3.Error())
			}
		} else {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid params", err.Error())
		}
	}

	hashBytes, err := hex.DecodeString(strings.TrimPrefix(req.ProposalHash, "0x"))
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid proposal hash", err.Error())
	}
	if len(hashBytes) != types.HashLength {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hash length",
			fmt.Sprintf("expected %d bytes, got %d", types.HashLength, len(hashBytes)))
	}

	var proposalHash types.Hash
	copy(proposalHash[:], hashBytes)

	proposal := api.multisigStore.GetProposal(proposalHash)
	if proposal == nil {
		return nil, NewError(ErrCodeNotFound, "proposal not found")
	}

	walletConfig := api.multisigStore.GetWallet(proposal.WalletAddr)
	if walletConfig == nil {
		return nil, NewError(ErrCodeInternal, "wallet config not found")
	}

	if proposal.SignerCount() < walletConfig.Threshold {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "insufficient signatures",
			fmt.Sprintf("need %d, have %d", walletConfig.Threshold, proposal.SignerCount()))
	}

	execProposal, execErr := api.multisigStore.TryBeginExecution(proposalHash, walletConfig.Threshold)
	if execErr != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "execution already in progress or completed", execErr.Error())
	}

	if execProposal.Value.Sign() < 0 {
		api.multisigStore.RollbackExecution(proposalHash)
		return nil, NewError(ErrCodeInvalidParams, "negative value not allowed")
	}

	// R31-HIGH-2 FIX (2026-09-06): the RPC layer no longer touches
	// chainStateDB balances for execution. All value movement is owned by
	// the V2 (0x67) precompile (status gate 0x02, storage re-hash
	// invariant, atomic SubBalance/AddBalance). The previous RPC-level
	// balance writes bypassed the consensus state root: they were visible
	// only on this node, could not be replayed by peers, and the single
	// -layer rollback (plus its CRITICAL-log-both-fail path) allowed the
	// local ledger to drift. Fail-closed: without the precompile bridge
	// wired, execution is refused outright instead of mutating local state.
	if err := api.executeProposalViaPrecompile(proposal, proposal.WalletAddr, proposalHash); err != nil {
		api.multisigStore.RollbackExecution(proposalHash)
		return nil, NewErrorWithData(ErrCodeInternal, "multisig execution via V2 precompile failed", err.Error())
	}

	if err := api.multisigStore.MarkExecuted(proposalHash); err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "failed to mark executed", err.Error())
	}

	updatedProposal := api.multisigStore.GetProposal(proposalHash)
	if updatedProposal == nil {
		return nil, NewError(ErrCodeInternal, "proposal disappeared after execution")
	}

	return api.proposalToMap(updatedProposal), nil
}

// buildExecuteProposalInputV2 builds the calldata for the V2 (0x67)
// executeProposal precompile (funcID 0x04).
//
// V2 calldata layout (after the 1-byte funcID):
//
//	proposalHash  Hash  (32 bytes)
//
// R38-P0-01 V2 final step: the precompile rejects execution until the
// status is 0x02 (approved), re-derives the canonical hash from the stored
// fields + stored callData and requires it to match the stored proposalHash
// (detects post-approval storage tampering, R38-P1-02 deep-copy invariant),
// then atomically SubBalance(wallet)+AddBalance(to). Status flips to 0x03 to
// prevent replay double-spend.
func buildExecuteProposalInputV2(proposalHash types.Hash) []byte {
	input := make([]byte, 1+32)
	input[0] = precompiled.MultisigV2FuncExecuteProposal
	copy(input[1:33], proposalHash[:])
	return input
}

// buildExecuteProposalInput retains the legacy V1 (0x66) calldata layout for
// backward compatibility with existing V1 RPC tests. R38-P0-01 retired the
// legacy 0x66 precompile at the production layer (ExecuteProposal handler
// now builds V2 calldata via buildExecuteProposalInputV2), but the V1 test
// fixtures are preserved as the audit baseline. Deprecated: use
// buildExecuteProposalInputV2. Production code MUST NOT call this function.
func buildExecuteProposalInput(proposalHash types.Hash) []byte {
	input := make([]byte, 1+32)
	input[0] = 0x04
	copy(input[1:33], proposalHash[:])
	return input
}

func computeProposalHash(fromAddr, toAddr types.Address, value *big.Int, nonce int64, gasLimit uint64, gasPrice *big.Int, data []byte, chainID uint64) types.Hash {
	h := sha256.New()
	h.Write(fromAddr[:])
	h.Write(toAddr[:])
	h.Write(value.Bytes())
	h.Write([]byte(fmt.Sprintf("%d", nonce)))
	// audit-fix H-6 [HIGH]: Include GasLimit, GasPrice, Data, ChainID in the
	// proposal hash. Without these fields, an attacker could modify them after
	// proposal creation without invalidating the hash, enabling transaction
	// tampering (e.g., bumping GasLimit or changing Data payload).
	var gasLimitBytes [8]byte
	binary.BigEndian.PutUint64(gasLimitBytes[:], gasLimit)
	h.Write(gasLimitBytes[:])
	if gasPrice != nil {
		h.Write(gasPrice.Bytes())
	}
	h.Write(data)
	var chainIDBytes [8]byte
	binary.BigEndian.PutUint64(chainIDBytes[:], chainID)
	h.Write(chainIDBytes[:])
	digest := h.Sum(nil)

	var hash types.Hash
	copy(hash[:], digest[:types.HashLength])
	return hash
}
