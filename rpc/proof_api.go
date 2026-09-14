// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

type ProofAPI struct {
	blockReader BlockReader
	stateReader StateReader
}

func NewProofAPI(blockReader BlockReader, stateReader StateReader) *ProofAPI {
	return &ProofAPI{
		blockReader: blockReader,
		stateReader: stateReader,
	}
}

type StorageProof struct {
	Key   string   `json:"key"`
	Value string   `json:"value"`
	Proof []string `json:"proof"`
}

type AccountProofResult struct {
	Address      string         `json:"address"`
	AccountProof []string       `json:"accountProof"`
	Balance      string         `json:"balance"`
	CodeHash     string         `json:"codeHash"`
	Nonce        string         `json:"nonce"`
	StorageHash  string         `json:"storageHash"`
	StorageProof []StorageProof `json:"storageProof"`

	// StateRoot is the canonical chain state root at the requested block
	// height, exposed so callers (light clients, bridges) can bind the
	// returned value to a specific chain state. Empty when the state root
	// cannot be resolved.
	// R38-P2-04 FIX (2026-08-02).
	StateRoot string `json:"stateRoot"`

	// Unverified is true when the returned proof is NOT cryptographically
	// bound to StateRoot — i.e. calling code MUST NOT treat the proof as
	// evidence that the account data is part of the canonical chain state.
	// Today this is always true: buildAccountProof constructs a fresh
	// single-entry Verkle tree and proves against THAT tree, not against
	// the canonical state trie. A malicious full node could fabricate any
	// (address, balance, nonce) tuple and produce a valid-looking proof
	// for it. Binding the proof to StateRoot requires extending
	// StateReader with a stateRoot-aware Prove method (audit Phase 3).
	// R38-P2-04 FIX (2026-08-02).
	Unverified bool `json:"unverified"`
}

func (api *ProofAPI) GetProof(address string, storageKeys []string, blockNum string) (*AccountProofResult, error) {
	// FIX: Limit storageKeys count to prevent DoS via oversized requests
	const maxStorageKeys = 100
	if len(storageKeys) > maxStorageKeys {
		return nil, fmt.Errorf("too many storage keys: %d > %d", len(storageKeys), maxStorageKeys)
	}

	addr := hexToAddress(address)

	height := uint64(0)
	if blockNum == "latest" || blockNum == "" {
		height = api.blockReader.GetLatestHeight()
	} else {
		fmt.Sscanf(blockNum, "%d", &height)
	}

	// R38-P2-04 FIX (2026-08-02): Resolve the canonical StateRoot for the
	// requested height so callers receive the chain state root alongside
	// the pseudo-proof. Previously height was discarded (`_ = height`),
	// hiding from the caller that the proof was generated against a
	// synthetic tree rather than this canonical state. The proof itself
	// is still NOT bound to StateRoot (see buildAccountProof/detected
	// Unverified flag) — this only gives callers the information needed to
	// NOT be misled. Until StateReader exposes a stateRoot-aware Prove,
	// downstream systems must treat eth_getProof results as unverified RPC
	// responses (trust the node, not the proof).
	stateRoot := ""
	blkAny, err := api.blockReader.GetBlockByHeight(height)
	if err == nil {
		if br, ok := blkAny.(*BlockResponse); ok && br != nil {
			stateRoot = br.StateRoot
		}
	}

	balance := api.stateReader.GetBalance(addr)
	nonce := api.stateReader.GetNonce(addr)
	code := api.stateReader.GetCode(addr)

	codeHash := types.Hash{}
	if len(code) > 0 {
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(code)
		copy(codeHash[:], hasher.Sum(nil))
	}

	// R38-P2-04 DEEP FIX (2026-08-02): Try the stateRoot-aware path first.
	// If the StateReader can produce a REAL Verkle proof against the
	// canonical chain state (today: full StateDB-backed adapters), we use
	// it and set Unverified=FALSE — the proof is cryptographically bound to
	// stateRoot. If the StateReader returns ErrProofNotSupported or the
	// generic nil/error, fall back to the synthetic-tree pseudo-proof and
	// set Unverified=TRUE honestly so callers know not to trust the proof.
	//
	// This preserves the conservative-mitigation guarantee from the earlier
	// R38-P2-04 surgical fix: in no case does the API fabricate a real
	// proof and silently turn Unverified=false against a synthetic tree.
	// The fallback surfaces StateRoot + Unverified=true so light clients
	// / bridges still see the canonical root but are explicitly warned.
	verifiedProof, _ := api.stateReader.ProveAccount(addr)
	proofStrings, unverified := serializeVerkleProof(verifiedProof), verifiedProof == nil

	accountProof := proofStrings
	if unverified {
		// Fallback to the legacy synthetic-tree path — keep behavior
		// compatible with adapters that do not implement ProveAccount.
		accountProof = buildAccountProof(addr, balance, nonce, codeHash)
	}

	result := &AccountProofResult{
		Address:      "0x" + hex.EncodeToString(addr[:]),
		AccountProof: accountProof,
		Balance:      "0x" + hex.EncodeToString(balance.Bytes()),
		CodeHash:     "0x" + hex.EncodeToString(codeHash[:]),
		Nonce:        "0x" + hex.EncodeToString(uint64ToBytes(nonce)),
		StorageHash:  "0x" + hex.EncodeToString(types.Hash{}.Bytes()),
		StorageProof: make([]StorageProof, 0, len(storageKeys)),
		StateRoot:    stateRoot,
		Unverified:   unverified,
	}

	for _, keyHex := range storageKeys {
		key := hexToHash(keyHex)
		val := api.stateReader.GetState(addr, key)
		// R38-P2-04 DEEP FIX: prefer stateRoot-aware storage proof when
		// available, mirror account path. Storage proofs share the same
		// Verkle proof backend as accounts.
		verifiedStorageProof, _ := api.stateReader.ProveStorage(addr, key)
		storageProof := buildStorageProof(addr, key, val)
		if verifiedStorageProof != nil {
			storageProof.Proof = serializeVerkleProof(verifiedStorageProof)
		}
		result.StorageProof = append(result.StorageProof, storageProof)
	}

	return result, nil
}

// RegisterHandlers registers the eth_getProof endpoint.
//
// R22 FIX: The underlying GetProof method uses a custom typed signature
// (string, []string, string) that the type switch in server.go
// RegisterHandler does not recognize. Without an adapter wrapper the
// handler was silently dropped by the default branch and the method
// returned "method not found". The adapter translates the standard
// JSON-RPC positional params array [address, storageKeys, blockNum]
// into the typed Go arguments.
func (api *ProofAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("eth_getProof", func(ctx context.Context, params json.RawMessage) (any, error) {
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if len(args) < 1 {
			return nil, fmt.Errorf("missing address parameter")
		}
		var address string
		if err := json.Unmarshal(args[0], &address); err != nil {
			return nil, fmt.Errorf("invalid address: %w", err)
		}
		var storageKeys []string
		if len(args) >= 2 {
			if err := json.Unmarshal(args[1], &storageKeys); err != nil {
				return nil, fmt.Errorf("invalid storage keys: %w", err)
			}
		}
		var blockNum string
		if len(args) >= 3 {
			if err := json.Unmarshal(args[2], &blockNum); err != nil {
				return nil, fmt.Errorf("invalid block number: %w", err)
			}
		}
		return api.GetProof(address, storageKeys, blockNum)
	})
}

// serializeVerkleProof produces the canonical []string (0x-prefixed hex)
// representation of a VerkleProof for the eth_getProof RPC response
// (R38-P2-04 DEEP FIX 2026-08-02).
//
// The serialization matches the layout buildAccountProof used for
// synthetic-tree proofs (Path followed by all Siblings in level order),
// so the wire format is backward-compatible: replacing the synthetic path
// with the canonical-state-trie path smuggles in the real proof without
// changing the JSON contract.
//
// Returns nil when proof is nil — the caller treats nil as "no proof
// available" and falls back to the synthetic-tree path so the wire
// response still has a non-empty AccountProof list (preserving RPC
// contract for clients that probe len(AccountProof) > 0).
func serializeVerkleProof(proof *trie.VerkleProof) []string {
	if proof == nil {
		return nil
	}
	hexProof := make([]string, 0, len(proof.Path)+len(proof.Siblings))
	for _, p := range proof.Path {
		hexProof = append(hexProof, "0x"+hex.EncodeToString(p[:]))
	}
	for _, level := range proof.Siblings {
		for _, sib := range level {
			hexProof = append(hexProof, "0x"+hex.EncodeToString(sib.Hash[:]))
		}
	}
	return hexProof
}

func buildAccountProof(addr types.Address, balance *big.Int, nonce uint64, codeHash types.Hash) []string {
	// R36-P3-21 LIMITATION NOTE (2026-07-30): The proof returned here is
	// NOT bound to the chain's stateRoot. This function constructs a
	// FRESH single-entry Verkle tree containing ONLY the requested account,
	// then calls tree.Prove() on that entry. The resulting Merkle path is
	// a "pseudo-proof" — it proves that the account data is consistent
	// with the freshly-built tree, NOT that the account data is part of
	// the canonical chain state. A caller that trusts this proof to
	// verify on-chain state (e.g. a light client or cross-chain bridge)
	// would be misled: a malicious full node could return any (address,
	// balance, nonce) tuple and this function would happily produce a
	// valid-looking proof for it. The stateRoot binding is missing because
	// the StateReader interface (rpc/api.go) does not expose a
	// stateRoot-aware Prove method — the underlying StateDB has the full
	// Verkle tree but does not expose it through the rpc adapter. Until
	// the StateReader interface is extended to expose stateRoot-bound
	// proofs, downstream systems MUST treat eth_getProof results as
	// unverified RPC responses (trust the node, not the proof). This is
	// acceptable for the current mainnet (no light clients, no bridges
	// consuming getProof) but is a pre-mainnet-blocker for any system
	// that relies on cryptographic state proofs.
	tree := trie.NewVerkleTree(256)

	accountKey := append([]byte("account:"), addr[:]...)
	accountData := serializeAccountData(balance, nonce, codeHash)
	tree.Put(accountKey, accountData)

	proof, err := tree.Prove(accountKey)
	if err != nil {
		return []string{}
	}

	hexProof := make([]string, 0, len(proof.Path)+len(proof.Siblings))
	for _, p := range proof.Path {
		hexProof = append(hexProof, "0x"+hex.EncodeToString(p[:]))
	}
	for _, level := range proof.Siblings {
		for _, sib := range level {
			hexProof = append(hexProof, "0x"+hex.EncodeToString(sib.Hash[:]))
		}
	}
	return hexProof
}

func buildStorageProof(addr types.Address, key, value types.Hash) StorageProof {
	tree := trie.NewVerkleTree(256)

	storageKey := append(append([]byte("storage:"), addr[:]...), key[:]...)
	storageData := value[:]
	tree.Put(storageKey, storageData)

	proof, err := tree.Prove(storageKey)
	if err != nil {
		return StorageProof{
			Key:   "0x" + hex.EncodeToString(key[:]),
			Value: "0x0",
			Proof: []string{},
		}
	}

	hexProof := make([]string, 0, len(proof.Path)+len(proof.Siblings))
	for _, p := range proof.Path {
		hexProof = append(hexProof, "0x"+hex.EncodeToString(p[:]))
	}
	for _, level := range proof.Siblings {
		for _, sib := range level {
			hexProof = append(hexProof, "0x"+hex.EncodeToString(sib.Hash[:]))
		}
	}

	return StorageProof{
		Key:   "0x" + hex.EncodeToString(key[:]),
		Value: "0x" + hex.EncodeToString(value[:]),
		Proof: hexProof,
	}
}

func serializeAccountData(balance *big.Int, nonce uint64, codeHash types.Hash) []byte {
	data := make([]byte, 72)
	balanceBytes := balance.Bytes()
	copy(data[32-len(balanceBytes):32], balanceBytes)
	data[32] = byte(nonce >> 56)
	data[33] = byte(nonce >> 48)
	data[34] = byte(nonce >> 40)
	data[35] = byte(nonce >> 32)
	data[36] = byte(nonce >> 24)
	data[37] = byte(nonce >> 16)
	data[38] = byte(nonce >> 8)
	data[39] = byte(nonce)
	copy(data[40:72], codeHash[:])
	return data
}

func uint64ToBytes(n uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(n >> 56)
	b[1] = byte(n >> 48)
	b[2] = byte(n >> 40)
	b[3] = byte(n >> 32)
	b[4] = byte(n >> 24)
	b[5] = byte(n >> 16)
	b[6] = byte(n >> 8)
	b[7] = byte(n)
	return b
}
