// Quantaureum Node source, version 1.0.0.
// Package lightclient provides the light client API for bandwidth-optimized access.
package lightclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/encoding"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/rpc"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// BandwidthStats tracks bandwidth usage for light client connections
type BandwidthStats struct {
	BytesSent        uint64    `json:"bytesSent"`
	BytesReceived    uint64    `json:"bytesReceived"`
	CompressedSent   uint64    `json:"compressedSent"`
	RequestCount     uint64    `json:"requestCount"`
	CompressionRatio float64   `json:"compressionRatio"`
	LastUpdated      time.Time `json:"lastUpdated"`
}

// LightClientAPI provides RPC methods optimized for light clients
type LightClientAPI struct {
	syncer *HeaderSyncer
	prover *SPVProver

	// Bandwidth optimization
	compressionEnabled bool
	compressionLevel   int
	maxResponseSize    int

	// Statistics
	stats   BandwidthStats
	statsMu sync.RWMutex

	// Transaction submission callback
	txSubmitter func(tx *encoding.Transaction) error

	// Balance lookup callback
	balanceLookup func(addr types.Address) (*big.Int, uint64, error)

	// Transaction status lookup
	txStatusLookup func(txHash types.Hash) (*TxStatus, error)
}

// TxStatus represents the status of a transaction
type TxStatus struct {
	Status      string `json:"status"` // "pending", "confirmed", "failed", "unknown"
	BlockHeight uint64 `json:"blockHeight,omitempty"`
	BlockHash   string `json:"blockHash,omitempty"`
	TxIndex     uint32 `json:"txIndex,omitempty"`
	GasUsed     uint64 `json:"gasUsed,omitempty"`
	Error       string `json:"error,omitempty"`
}

// LightClientAPIConfig holds configuration for the light client API
type LightClientAPIConfig struct {
	CompressionEnabled bool
	CompressionLevel   int // 1-9, default 6
	MaxResponseSize    int // Maximum response size in bytes
}

// DefaultLightClientAPIConfig returns default configuration
func DefaultLightClientAPIConfig() *LightClientAPIConfig {
	return &LightClientAPIConfig{
		CompressionEnabled: true,
		CompressionLevel:   6,
		MaxResponseSize:    10 * 1024 * 1024, // 10MB
	}
}

// NewLightClientAPI creates a new light client API
func NewLightClientAPI(syncer *HeaderSyncer, prover *SPVProver) *LightClientAPI {
	return NewLightClientAPIWithConfig(syncer, prover, DefaultLightClientAPIConfig())
}

// NewLightClientAPIWithConfig creates a new light client API with custom configuration
func NewLightClientAPIWithConfig(syncer *HeaderSyncer, prover *SPVProver, cfg *LightClientAPIConfig) *LightClientAPI {
	if cfg == nil {
		cfg = DefaultLightClientAPIConfig()
	}
	return &LightClientAPI{
		syncer:             syncer,
		prover:             prover,
		compressionEnabled: cfg.CompressionEnabled,
		compressionLevel:   cfg.CompressionLevel,
		maxResponseSize:    cfg.MaxResponseSize,
		stats: BandwidthStats{
			LastUpdated: time.Now(),
		},
	}
}

// SetTxSubmitter sets the transaction submission callback
func (api *LightClientAPI) SetTxSubmitter(submitter func(tx *encoding.Transaction) error) {
	api.txSubmitter = submitter
}

// SetBalanceLookup sets the balance lookup callback
func (api *LightClientAPI) SetBalanceLookup(lookup func(addr types.Address) (*big.Int, uint64, error)) {
	api.balanceLookup = lookup
}

// SetTxStatusLookup sets the transaction status lookup callback
func (api *LightClientAPI) SetTxStatusLookup(lookup func(txHash types.Hash) (*TxStatus, error)) {
	api.txStatusLookup = lookup
}

// GetHeaderSyncer returns the header syncer for sync committee bridging.
func (api *LightClientAPI) GetHeaderSyncer() *HeaderSyncer {
	return api.syncer
}

// updateStats updates bandwidth statistics
func (api *LightClientAPI) updateStats(sent, received, compressed uint64) {
	api.statsMu.Lock()
	defer api.statsMu.Unlock()

	atomic.AddUint64(&api.stats.BytesSent, sent)
	atomic.AddUint64(&api.stats.BytesReceived, received)
	atomic.AddUint64(&api.stats.CompressedSent, compressed)
	atomic.AddUint64(&api.stats.RequestCount, 1)

	if api.stats.BytesSent > 0 {
		api.stats.CompressionRatio = float64(api.stats.CompressedSent) / float64(api.stats.BytesSent)
	}
	api.stats.LastUpdated = time.Now()
}

// RegisterHandlers registers all light client API handlers with the RPC server
func (api *LightClientAPI) RegisterHandlers(server *rpc.Server) {
	// Header methods
	server.RegisterHandler("qau_light_getBlockHeader", api.GetBlockHeader)
	server.RegisterHandler("qau_light_getBlockHeaders", api.GetBlockHeaders)
	server.RegisterHandler("qau_light_getCheckpoints", api.GetCheckpoints)
	server.RegisterHandler("qau_light_getLatestHeader", api.GetLatestHeader)

	// SPV Proof methods - Transaction inclusion proofs (Requirements 17.2)
	server.RegisterHandler("qau_light_getTxProof", api.GetTxProof)
	server.RegisterHandler("qau_light_verifyTxProof", api.VerifyTxProof)
	server.RegisterHandler("qau_light_getMultiTxProof", api.GetMultiTxProof)
	server.RegisterHandler("qau_light_getSerializedTxProof", api.GetSerializedTxProof)

	// SPV Proof methods - State proofs (Requirements 17.4)
	server.RegisterHandler("qau_light_getStateProof", api.GetStateProof)
	server.RegisterHandler("qau_light_verifyStateProof", api.VerifyStateProofRPC)
	server.RegisterHandler("qau_light_getMultiStateProof", api.GetMultiStateProof)
	server.RegisterHandler("qau_light_getSerializedStateProof", api.GetSerializedStateProof)

	// Sync methods
	server.RegisterHandler("qau_light_getSyncStatus", api.GetSyncStatus)

	// Dedicated light client endpoints (Requirements 17.5)
	server.RegisterHandler("qau_light_submitTransaction", api.SubmitTransaction)
	server.RegisterHandler("qau_light_getBalance", api.GetBalance)
	server.RegisterHandler("qau_light_getTxStatus", api.GetTxStatus)
	server.RegisterHandler("qau_light_getBandwidthStats", api.GetBandwidthStats)

	// Bandwidth-optimized endpoints
	server.RegisterHandler("qau_light_getCompressedHeaders", api.GetCompressedHeaders)
	server.RegisterHandler("qau_light_getDeltaHeaders", api.GetDeltaHeaders)
	server.RegisterHandler("qau_light_getCompactProof", api.GetCompactProof)
	server.RegisterHandler("qau_light_batchRequest", api.BatchRequest)

	// Sync Committee methods for light client verification
	server.RegisterHandler("qau_light_getSyncCommittee", api.GetSyncCommittee)
	server.RegisterHandler("qau_light_verifySyncCommitteeSig", api.VerifySyncCommitteeSig)
}

// BlockHeaderResponse represents a block header response
type BlockHeaderResponse struct {
	Height      string `json:"height"`
	Hash        string `json:"hash"`
	ParentHash  string `json:"parentHash"`
	StateRoot   string `json:"stateRoot"`
	TxRoot      string `json:"txRoot"`
	ReceiptRoot string `json:"receiptRoot"`
	Timestamp   int64  `json:"timestamp"`
	Proposer    string `json:"proposer"`
}

// headerToResponse converts a block header to a response
func headerToResponse(header *encoding.BlockHeader) *BlockHeaderResponse {
	if header == nil {
		return nil
	}

	hash := computeHeaderHash(header)

	return &BlockHeaderResponse{
		Height:      formatHexUint64(header.Height),
		Hash:        formatHexHash(hash),
		ParentHash:  formatHexHash(header.ParentHash),
		StateRoot:   formatHexHash(header.StateRoot),
		TxRoot:      formatHexHash(header.TxRoot),
		ReceiptRoot: formatHexHash(header.ReceiptRoot),
		Timestamp:   header.Timestamp,
		Proposer:    formatHexAddress(header.ProposerAddr),
	}
}

// GetBlockHeader returns a block header by height or hash
func (api *LightClientAPI) GetBlockHeader(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, rpc.ErrInvalidParams
	}

	blockID, ok := args[0].(string)
	if !ok {
		return nil, rpc.ErrInvalidParams
	}

	var header *encoding.BlockHeader
	var err error

	// Try to parse as height first
	if height, parseErr := parseHexUint64(blockID); parseErr == nil {
		header, err = api.syncer.GetHeaderByHeight(height)
	} else {
		// Try as hash
		hash, parseErr := parseHash(blockID)
		if parseErr != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid block identifier", parseErr.Error())
		}
		header, err = api.syncer.GetHeaderByHash(hash)
	}

	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "header not found")
	}

	return headerToResponse(header), nil
}

// GetBlockHeaders returns a range of block headers
func (api *LightClientAPI) GetBlockHeaders(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, rpc.ErrInvalidParams
	}

	startStr, ok := args[0].(string)
	if !ok {
		return nil, rpc.ErrInvalidParams
	}

	countFloat, ok := args[1].(float64)
	if !ok {
		return nil, rpc.ErrInvalidParams
	}

	startHeight, err := parseHexUint64(startStr)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid start height", err.Error())
	}

	count := uint64(countFloat)
	if count > 1000 {
		count = 1000 // Limit to 1000 headers per request
	}

	headers, err := api.syncer.GetHeaderRange(startHeight, count)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "headers not found")
	}

	responses := make([]*BlockHeaderResponse, len(headers))
	for i, header := range headers {
		responses[i] = headerToResponse(header)
	}

	return responses, nil
}

// GetCheckpoints returns all available checkpoints
func (api *LightClientAPI) GetCheckpoints(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	checkpoints := api.syncer.GetAllCheckpoints()

	responses := make([]map[string]any, len(checkpoints))
	for i, cp := range checkpoints {
		responses[i] = map[string]any{
			"height":    formatHexUint64(cp.Height),
			"hash":      formatHexHash(cp.Hash),
			"stateRoot": formatHexHash(cp.StateRoot),
			"timestamp": cp.Timestamp,
		}
	}

	return responses, nil
}

// GetLatestHeader returns the latest block header
func (api *LightClientAPI) GetLatestHeader(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	height := api.syncer.GetLatestHeight()
	if height == 0 {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "no headers available")
	}

	header, err := api.syncer.GetHeaderByHeight(height)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "header not found")
	}

	return headerToResponse(header), nil
}

// TxProofResponse represents a transaction proof response
type TxProofResponse struct {
	TxHash      string   `json:"txHash"`
	BlockHeight string   `json:"blockHeight"`
	BlockHash   string   `json:"blockHash"`
	TxIndex     uint32   `json:"txIndex"`
	TxRoot      string   `json:"txRoot"`
	Proof       []string `json:"proof"`
	Positions   []byte   `json:"positions"`
}

// GetTxProof returns a transaction inclusion proof
func (api *LightClientAPI) GetTxProof(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, rpc.ErrInvalidParams
	}

	txHash, err := parseHash(args[0])
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid transaction hash", err.Error())
	}

	proof, err := api.prover.GenerateTxInclusionProof(txHash)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "transaction not found")
	}

	blockHash := computeHeaderHash(proof.BlockHeader)

	proofHashes := make([]string, len(proof.MerkleProof))
	for i, h := range proof.MerkleProof {
		proofHashes[i] = formatHexHash(h)
	}

	return &TxProofResponse{
		TxHash:      formatHexHash(proof.TxHash),
		BlockHeight: formatHexUint64(proof.BlockHeader.Height),
		BlockHash:   formatHexHash(blockHash),
		TxIndex:     proof.TxIndex,
		TxRoot:      formatHexHash(proof.BlockHeader.TxRoot),
		Proof:       proofHashes,
		Positions:   proof.ProofPositions,
	}, nil
}

// VerifyTxProof verifies a transaction inclusion proof
func (api *LightClientAPI) VerifyTxProof(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		TxHash    string   `json:"txHash"`
		TxIndex   uint32   `json:"txIndex"`
		TxRoot    string   `json:"txRoot"`
		Proof     []string `json:"proof"`
		Positions []byte   `json:"positions"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	txHash, err := parseHash(args.TxHash)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid transaction hash", err.Error())
	}

	txRoot, err := parseHash(args.TxRoot)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid tx root", err.Error())
	}

	proofHashes := make([]types.Hash, len(args.Proof))
	for i, h := range args.Proof {
		hash, err := parseHash(h)
		if err != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid proof hash", err.Error())
		}
		proofHashes[i] = hash
	}

	valid := VerifyTxInBlock(txHash, args.TxIndex, txRoot, proofHashes, args.Positions)

	return map[string]bool{"valid": valid}, nil
}

// StateProofResponse represents a state proof response
type StateProofResponse struct {
	Address       string                      `json:"address"`
	BlockHeight   string                      `json:"blockHeight,omitempty"`
	StateRoot     string                      `json:"stateRoot,omitempty"`
	Account       *AccountResponse            `json:"account,omitempty"`
	AccountProof  string                      `json:"accountProof,omitempty"`
	StorageProofs map[string]*StorageResponse `json:"storageProofs,omitempty"`
}

// AccountResponse represents account data in a response
type AccountResponse struct {
	Nonce       string `json:"nonce"`
	Balance     string `json:"balance"`
	CodeHash    string `json:"codeHash"`
	StorageRoot string `json:"storageRoot"`
}

// StorageResponse represents storage data in a response
type StorageResponse struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Proof string `json:"proof,omitempty"`
}

// GetStateProof returns a state proof for an account
func (api *LightClientAPI) GetStateProof(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		Address     string   `json:"address"`
		StorageKeys []string `json:"storageKeys,omitempty"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	addr, err := parseAddress(args.Address)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid address", err.Error())
	}

	storageKeys := make([]types.Hash, len(args.StorageKeys))
	for i, k := range args.StorageKeys {
		key, err := parseHash(k)
		if err != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid storage key", err.Error())
		}
		storageKeys[i] = key
	}

	proof, err := api.prover.GenerateStateProof(addr, storageKeys)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "state not found")
	}

	response := &StateProofResponse{
		Address:       formatHexAddress(addr),
		StorageProofs: make(map[string]*StorageResponse),
	}

	if proof.BlockHeader != nil {
		response.BlockHeight = formatHexUint64(proof.BlockHeader.Height)
		response.StateRoot = formatHexHash(proof.BlockHeader.StateRoot)
	}

	if proof.Account != nil {
		response.Account = &AccountResponse{
			Nonce:       formatHexUint64(proof.Account.Nonce),
			Balance:     formatHexBigInt(proof.Account.Balance),
			CodeHash:    formatHexHash(proof.Account.CodeHash),
			StorageRoot: formatHexHash(proof.Account.StorageRoot),
		}
	}

	for key, entry := range proof.StorageProofs {
		response.StorageProofs[formatHexHash(key)] = &StorageResponse{
			Key:   formatHexHash(entry.Key),
			Value: formatHexHash(entry.Value),
		}
	}

	return response, nil
}

// VerifyStateProofRPC verifies a state proof via RPC
func (api *LightClientAPI) VerifyStateProofRPC(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		StateRoot string `json:"stateRoot"`
		Address   string `json:"address"`
		ProofData string `json:"proofData,omitempty"` // hex-encoded serialized proof
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	stateRoot, err := parseHash(args.StateRoot)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid state root", err.Error())
	}

	addr, err := parseAddress(args.Address)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid address", err.Error())
	}

	// If proof data is provided, verify it
	if args.ProofData != "" {
		proofBytes, err := hex.DecodeString(stripHexPrefix(args.ProofData))
		if err != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid proof data", err.Error())
		}

		proof, err := UnmarshalStateProof(proofBytes)
		if err != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid proof format", err.Error())
		}

		if proof.Address != addr {
			return map[string]any{
				"valid":  false,
				"reason": "address mismatch",
			}, nil
		}

		valid := VerifyStateProof(stateRoot, proof)
		return map[string]any{
			"valid": valid,
		}, nil
	}

	// Generate and verify proof on the fly
	proof, err := api.prover.GenerateStateProof(addr, nil)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "state not found")
	}

	valid := VerifyStateProof(stateRoot, proof)
	return map[string]any{
		"valid": valid,
	}, nil
}

// SyncStatusResponse represents sync status
type SyncStatusResponse struct {
	Syncing         bool   `json:"syncing"`
	LatestHeight    string `json:"latestHeight"`
	CheckpointCount int    `json:"checkpointCount"`
}

// GetSyncStatus returns the current sync status
func (api *LightClientAPI) GetSyncStatus(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	return &SyncStatusResponse{
		Syncing:         api.syncer.IsSyncing(),
		LatestHeight:    formatHexUint64(api.syncer.GetLatestHeight()),
		CheckpointCount: len(api.syncer.GetAllCheckpoints()),
	}, nil
}

// GetMultiTxProof returns proofs for multiple transactions
func (api *LightClientAPI) GetMultiTxProof(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		TxHashes []string `json:"txHashes"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	if len(args.TxHashes) == 0 {
		return nil, rpc.NewError(rpc.ErrCodeInvalidParams, "no transaction hashes provided")
	}

	if len(args.TxHashes) > 100 {
		return nil, rpc.NewError(rpc.ErrCodeInvalidParams, "too many transaction hashes (max 100)")
	}

	txHashes := make([]types.Hash, len(args.TxHashes))
	for i, h := range args.TxHashes {
		hash, err := parseHash(h)
		if err != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid transaction hash", err.Error())
		}
		txHashes[i] = hash
	}

	proofs, err := api.prover.GenerateMultiTxProof(txHashes)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "transactions not found")
	}

	responses := make([]*TxProofResponse, len(proofs))
	for i, proof := range proofs {
		blockHash := computeHeaderHash(proof.BlockHeader)
		proofHashes := make([]string, len(proof.MerkleProof))
		for j, h := range proof.MerkleProof {
			proofHashes[j] = formatHexHash(h)
		}

		responses[i] = &TxProofResponse{
			TxHash:      formatHexHash(proof.TxHash),
			BlockHeight: formatHexUint64(proof.BlockHeader.Height),
			BlockHash:   formatHexHash(blockHash),
			TxIndex:     proof.TxIndex,
			TxRoot:      formatHexHash(proof.BlockHeader.TxRoot),
			Proof:       proofHashes,
			Positions:   proof.ProofPositions,
		}
	}

	return responses, nil
}

// GetMultiStateProof returns proofs for multiple accounts
func (api *LightClientAPI) GetMultiStateProof(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		Addresses   []string            `json:"addresses"`
		StorageKeys map[string][]string `json:"storageKeys,omitempty"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	if len(args.Addresses) == 0 {
		return nil, rpc.NewError(rpc.ErrCodeInvalidParams, "no addresses provided")
	}

	if len(args.Addresses) > 50 {
		return nil, rpc.NewError(rpc.ErrCodeInvalidParams, "too many addresses (max 50)")
	}

	addresses := make([]types.Address, len(args.Addresses))
	for i, a := range args.Addresses {
		addr, err := parseAddress(a)
		if err != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid address", err.Error())
		}
		addresses[i] = addr
	}

	storageKeys := make(map[types.Address][]types.Hash)
	for addrStr, keys := range args.StorageKeys {
		addr, err := parseAddress(addrStr)
		if err != nil {
			continue
		}

		hashKeys := make([]types.Hash, len(keys))
		for i, k := range keys {
			key, err := parseHash(k)
			if err != nil {
				continue
			}
			hashKeys[i] = key
		}
		storageKeys[addr] = hashKeys
	}

	proofs, err := api.prover.GenerateMultiStateProof(addresses, storageKeys)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "states not found")
	}

	responses := make([]*StateProofResponse, len(proofs))
	for i, proof := range proofs {
		response := &StateProofResponse{
			Address:       formatHexAddress(proof.Address),
			StorageProofs: make(map[string]*StorageResponse),
		}

		if proof.BlockHeader != nil {
			response.BlockHeight = formatHexUint64(proof.BlockHeader.Height)
			response.StateRoot = formatHexHash(proof.BlockHeader.StateRoot)
		}

		if proof.Account != nil {
			response.Account = &AccountResponse{
				Nonce:       formatHexUint64(proof.Account.Nonce),
				Balance:     formatHexBigInt(proof.Account.Balance),
				CodeHash:    formatHexHash(proof.Account.CodeHash),
				StorageRoot: formatHexHash(proof.Account.StorageRoot),
			}
		}

		for key, entry := range proof.StorageProofs {
			response.StorageProofs[formatHexHash(key)] = &StorageResponse{
				Key:   formatHexHash(entry.Key),
				Value: formatHexHash(entry.Value),
			}
		}

		responses[i] = response
	}

	return responses, nil
}

// GetSerializedTxProof returns a serialized transaction proof for bandwidth optimization
func (api *LightClientAPI) GetSerializedTxProof(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, rpc.ErrInvalidParams
	}

	txHash, err := parseHash(args[0])
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid transaction hash", err.Error())
	}

	proof, err := api.prover.GenerateTxInclusionProof(txHash)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "transaction not found")
	}

	serialized, err := MarshalTxInclusionProof(proof)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeInternal, "failed to serialize proof")
	}

	return map[string]string{
		"proof": "0x" + hex.EncodeToString(serialized),
	}, nil
}

// GetSerializedStateProof returns a serialized state proof for bandwidth optimization
func (api *LightClientAPI) GetSerializedStateProof(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		Address     string   `json:"address"`
		StorageKeys []string `json:"storageKeys,omitempty"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	addr, err := parseAddress(args.Address)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid address", err.Error())
	}

	storageKeys := make([]types.Hash, len(args.StorageKeys))
	for i, k := range args.StorageKeys {
		key, err := parseHash(k)
		if err != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid storage key", err.Error())
		}
		storageKeys[i] = key
	}

	proof, err := api.prover.GenerateStateProof(addr, storageKeys)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "state not found")
	}

	serialized, err := MarshalStateProof(proof)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeInternal, "failed to serialize proof")
	}

	return map[string]string{
		"proof": "0x" + hex.EncodeToString(serialized),
	}, nil
}

// Helper functions

func parseAddress(s string) (types.Address, error) {
	s = stripHexPrefix(s)
	if len(s) != 40 {
		return types.Address{}, ErrInvalidProof
	}
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return types.Address{}, err
	}
	return types.BytesToAddress(bytes), nil
}

func parseHash(s string) (types.Hash, error) {
	s = stripHexPrefix(s)
	if len(s) != 64 {
		return types.Hash{}, ErrInvalidProof
	}
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return types.Hash{}, err
	}
	return types.BytesToHash(bytes), nil
}

func parseHexUint64(s string) (uint64, error) {
	s = stripHexPrefix(s)
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	var result uint64
	for _, b := range bytes {
		result = result<<8 | uint64(b)
	}
	return result, nil
}

func stripHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

func formatHexUint64(n uint64) string {
	return "0x" + hex.EncodeToString([]byte{
		byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), // #nosec G115 -- value range verified by caller
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n), // #nosec G115 -- value range verified by caller
	})
}

func formatHexHash(h types.Hash) string {
	return "0x" + hex.EncodeToString(h[:])
}

func formatHexAddress(a types.Address) string {
	return "0x" + hex.EncodeToString(a[:])
}

func formatHexBigInt(n *big.Int) string {
	if n == nil {
		return "0x0"
	}
	return "0x" + n.Text(16)
}

func computeHeaderHash(header *encoding.BlockHeader) types.Hash {
	if header == nil {
		return types.Hash{}
	}
	data, err := encoding.MarshalBlockHeader(header)
	if err != nil {
		return types.Hash{}
	}
	h := sha3.Sum256(data)
	return types.BytesToHash(h[:])
}

// SubmitTransaction submits a transaction to the network (Requirements 17.5)
func (api *LightClientAPI) SubmitTransaction(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		RawTx string `json:"rawTx"` // hex-encoded serialized transaction
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	if api.txSubmitter == nil {
		return nil, rpc.NewError(rpc.ErrCodeInternal, "transaction submission not available")
	}

	// Decode transaction
	txBytes, err := hex.DecodeString(stripHexPrefix(args.RawTx))
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid transaction encoding", err.Error())
	}

	tx, err := encoding.UnmarshalTransaction(txBytes)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid transaction format", err.Error())
	}

	// Submit transaction
	if err := api.txSubmitter(tx); err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidTx, "transaction submission failed", err.Error())
	}

	// Compute transaction hash
	txHash := computeTxHash(tx)

	api.updateStats(uint64(len(txBytes)), 0, 0)

	return map[string]string{
		"txHash": formatHexHash(txHash),
	}, nil
}

// GetBalance returns the balance of an account (simplified endpoint for light clients)
func (api *LightClientAPI) GetBalance(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, rpc.ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid address", err.Error())
	}

	if api.balanceLookup == nil {
		return nil, rpc.NewError(rpc.ErrCodeInternal, "balance lookup not available")
	}

	balance, nonce, err := api.balanceLookup(addr)
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "account not found")
	}

	return map[string]string{
		"address": formatHexAddress(addr),
		"balance": formatHexBigInt(balance),
		"nonce":   formatHexUint64(nonce),
	}, nil
}

// GetTxStatus returns the status of a transaction
func (api *LightClientAPI) GetTxStatus(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, rpc.ErrInvalidParams
	}

	txHash, err := parseHash(args[0])
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid transaction hash", err.Error())
	}

	if api.txStatusLookup == nil {
		return nil, rpc.NewError(rpc.ErrCodeInternal, "transaction status lookup not available")
	}

	status, err := api.txStatusLookup(txHash)
	if err != nil {
		return &TxStatus{
			Status: "unknown",
		}, nil
	}

	return status, nil
}

// GetBandwidthStats returns bandwidth usage statistics
func (api *LightClientAPI) GetBandwidthStats(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	api.statsMu.RLock()
	defer api.statsMu.RUnlock()

	return &BandwidthStats{
		BytesSent:        atomic.LoadUint64(&api.stats.BytesSent),
		BytesReceived:    atomic.LoadUint64(&api.stats.BytesReceived),
		CompressedSent:   atomic.LoadUint64(&api.stats.CompressedSent),
		RequestCount:     atomic.LoadUint64(&api.stats.RequestCount),
		CompressionRatio: api.stats.CompressionRatio,
		LastUpdated:      api.stats.LastUpdated,
	}, nil
}

// CompressedHeadersResponse represents compressed headers response
type CompressedHeadersResponse struct {
	Headers          string `json:"headers"` // base64-encoded gzip compressed headers
	Count            int    `json:"count"`
	UncompressedSize int    `json:"uncompressedSize"`
	CompressedSize   int    `json:"compressedSize"`
}

// GetCompressedHeaders returns gzip-compressed block headers for bandwidth optimization
func (api *LightClientAPI) GetCompressedHeaders(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		StartHeight string `json:"startHeight"`
		Count       int    `json:"count"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	startHeight, err := parseHexUint64(args.StartHeight)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid start height", err.Error())
	}

	count := args.Count
	if count <= 0 || count > 1000 {
		count = 100 // Default to 100 headers
	}

	headers, err := api.syncer.GetHeaderRange(startHeight, uint64(count)) //nolint:gosec,G115
	if err != nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "headers not found")
	}

	// Serialize headers
	var uncompressed bytes.Buffer
	for _, header := range headers {
		data, err := encoding.MarshalBlockHeader(header)
		if err != nil {
			continue
		}
		// Write length prefix
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(data))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		uncompressed.Write(lenBuf)
		uncompressed.Write(data)
	}

	// Compress
	var compressed bytes.Buffer
	gzWriter, err := gzip.NewWriterLevel(&compressed, api.compressionLevel)
	if err != nil {
		gzWriter = gzip.NewWriter(&compressed)
	}
	// P3-LOG-04 FIX (R30, 2026-07-27): Check gzip Writer Write/Close errors
	// and log via structured logging.Global() so SIEM pipelines can collect
	// compression failures. Previously both errors were silently ignored,
	// masking disk/buffer corruption and producing empty or truncated
	// responses without any operator-visible signal.
	if _, err := gzWriter.Write(uncompressed.Bytes()); err != nil {
		logging.Global().Warn("lightclient: gzip Writer.Write failed during header compression",
			map[string]any{"error": err.Error(), "uncompressedSize": uncompressed.Len()})
	}
	if err := gzWriter.Close(); err != nil {
		logging.Global().Warn("lightclient: gzip Writer.Close failed during header compression",
			map[string]any{"error": err.Error(), "uncompressedSize": uncompressed.Len()})
	}

	api.updateStats(uint64(uncompressed.Len()), 0, uint64(compressed.Len())) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction

	return &CompressedHeadersResponse{
		Headers:          hex.EncodeToString(compressed.Bytes()),
		Count:            len(headers),
		UncompressedSize: uncompressed.Len(),
		CompressedSize:   compressed.Len(),
	}, nil
}

// DeltaHeader represents a delta-encoded header (only changed fields)
type DeltaHeader struct {
	Height         string `json:"height"`
	TimestampDelta int64  `json:"timestampDelta,omitempty"`
	ParentHash     string `json:"parentHash,omitempty"`
	StateRoot      string `json:"stateRoot,omitempty"`
	TxRoot         string `json:"txRoot,omitempty"`
	ReceiptRoot    string `json:"receiptRoot,omitempty"`
	Proposer       string `json:"proposer,omitempty"`
	TxCount        int    `json:"txCount,omitempty"`
}

// DeltaHeadersResponse represents delta-encoded headers response
type DeltaHeadersResponse struct {
	BaseHeader *BlockHeaderResponse `json:"baseHeader"`
	Deltas     []*DeltaHeader       `json:"deltas"`
}

// GetDeltaHeaders returns delta-encoded headers for bandwidth optimization
func (api *LightClientAPI) GetDeltaHeaders(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		StartHeight string `json:"startHeight"`
		Count       int    `json:"count"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	startHeight, err := parseHexUint64(args.StartHeight)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid start height", err.Error())
	}

	count := args.Count
	if count <= 0 || count > 1000 {
		count = 100
	}

	headers, err := api.syncer.GetHeaderRange(startHeight, uint64(count)) //nolint:gosec,G115
	if err != nil || len(headers) == 0 {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "headers not found")
	}

	// First header is the base
	baseHeader := headerToResponse(headers[0])

	// Generate deltas for subsequent headers
	deltas := make([]*DeltaHeader, 0, len(headers)-1)
	var prevTimestamp int64 = headers[0].Timestamp

	for i := 1; i < len(headers); i++ {
		header := headers[i]
		delta := &DeltaHeader{
			Height:         formatHexUint64(header.Height),
			TimestampDelta: header.Timestamp - prevTimestamp,
			StateRoot:      formatHexHash(header.StateRoot),
			TxRoot:         formatHexHash(header.TxRoot),
			ReceiptRoot:    formatHexHash(header.ReceiptRoot),
		}

		// Only include proposer if different from previous
		if i > 0 && header.ProposerAddr != headers[i-1].ProposerAddr {
			delta.Proposer = formatHexAddress(header.ProposerAddr)
		}

		deltas = append(deltas, delta)
		prevTimestamp = header.Timestamp
	}

	return &DeltaHeadersResponse{
		BaseHeader: baseHeader,
		Deltas:     deltas,
	}, nil
}

// CompactProofResponse represents a compact proof response
type CompactProofResponse struct {
	Type         string `json:"type"`  // "tx" or "state"
	Proof        string `json:"proof"` // hex-encoded compact proof
	Size         int    `json:"size"`
	OriginalSize int    `json:"originalSize,omitempty"`
}

// GetCompactProof returns a bandwidth-optimized compact proof
func (api *LightClientAPI) GetCompactProof(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		Type   string   `json:"type"`           // "tx" or "state"
		Target string   `json:"target"`         // txHash or address
		Keys   []string `json:"keys,omitempty"` // storage keys for state proofs
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	switch args.Type {
	case "tx":
		txHash, err := parseHash(args.Target)
		if err != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid transaction hash", err.Error())
		}

		proof, err := api.prover.GenerateTxInclusionProof(txHash)
		if err != nil {
			return nil, rpc.NewError(rpc.ErrCodeNotFound, "transaction not found")
		}

		// Serialize to compact format
		compactProof := serializeCompactTxProof(proof)

		return &CompactProofResponse{
			Type:  "tx",
			Proof: hex.EncodeToString(compactProof),
			Size:  len(compactProof),
		}, nil

	case "state":
		addr, err := parseAddress(args.Target)
		if err != nil {
			return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid address", err.Error())
		}

		storageKeys := make([]types.Hash, len(args.Keys))
		for i, k := range args.Keys {
			key, err := parseHash(k)
			if err != nil {
				continue
			}
			storageKeys[i] = key
		}

		proof, err := api.prover.GenerateStateProof(addr, storageKeys)
		if err != nil {
			return nil, rpc.NewError(rpc.ErrCodeNotFound, "state not found")
		}

		// Serialize to compact format
		compactProof := serializeCompactStateProof(proof)

		return &CompactProofResponse{
			Type:  "state",
			Proof: hex.EncodeToString(compactProof),
			Size:  len(compactProof),
		}, nil

	default:
		return nil, rpc.NewError(rpc.ErrCodeInvalidParams, "invalid proof type, must be 'tx' or 'state'")
	}
}

// BatchRequestItem represents a single request in a batch
type BatchRequestItem struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	ID     any             `json:"id"`
}

// BatchResponseItem represents a single response in a batch
type BatchResponseItem struct {
	ID     any        `json:"id"`
	Result any        `json:"result,omitempty"`
	Error  *rpc.Error `json:"error,omitempty"`
}

// BatchRequest handles multiple light client requests in a single call for bandwidth optimization
func (api *LightClientAPI) BatchRequest(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args struct {
		Requests []BatchRequestItem `json:"requests"`
	}

	if err := json.Unmarshal(params, &args); err != nil {
		return nil, rpc.ErrInvalidParams
	}

	if len(args.Requests) == 0 {
		return nil, rpc.NewError(rpc.ErrCodeInvalidParams, "no requests provided")
	}

	if len(args.Requests) > 50 {
		return nil, rpc.NewError(rpc.ErrCodeInvalidParams, "too many requests (max 50)")
	}

	responses := make([]*BatchResponseItem, len(args.Requests))

	for i, req := range args.Requests {
		result, err := api.handleSingleRequest(ctx, req.Method, req.Params)
		responses[i] = &BatchResponseItem{
			ID:     req.ID,
			Result: result,
			Error:  err,
		}
	}

	return responses, nil
}

// handleSingleRequest handles a single request within a batch
func (api *LightClientAPI) handleSingleRequest(ctx context.Context, method string, params json.RawMessage) (any, *rpc.Error) {
	switch method {
	case "getBlockHeader":
		return api.GetBlockHeader(ctx, params)
	case "getBlockHeaders":
		return api.GetBlockHeaders(ctx, params)
	case "getLatestHeader":
		return api.GetLatestHeader(ctx, params)
	case "getCheckpoints":
		return api.GetCheckpoints(ctx, params)
	case "getTxProof":
		return api.GetTxProof(ctx, params)
	case "getStateProof":
		return api.GetStateProof(ctx, params)
	case "getBalance":
		return api.GetBalance(ctx, params)
	case "getTxStatus":
		return api.GetTxStatus(ctx, params)
	case "getSyncStatus":
		return api.GetSyncStatus(ctx, params)
	default:
		return nil, rpc.NewError(rpc.ErrCodeMethodNotFound, "method not found in batch context")
	}
}

// serializeCompactTxProof creates a compact binary representation of a tx proof
func serializeCompactTxProof(proof *TxInclusionProof) []byte {
	if proof == nil {
		return nil
	}

	// Compact format: [txHash(32)] [height(8)] [txIndex(4)] [proofCount(2)] [proofs...] [positions]
	proofCount := len(proof.MerkleProof)
	size := 32 + 8 + 4 + 2 + (proofCount * 32) + len(proof.ProofPositions)

	buf := make([]byte, size)
	offset := 0

	// TxHash
	copy(buf[offset:offset+32], proof.TxHash[:])
	offset += 32

	// Height
	if proof.BlockHeader != nil {
		binary.BigEndian.PutUint64(buf[offset:offset+8], proof.BlockHeader.Height)
	}
	offset += 8

	// TxIndex
	binary.BigEndian.PutUint32(buf[offset:offset+4], proof.TxIndex)
	offset += 4

	// Proof count
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(proofCount)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 2

	// Merkle proofs
	for _, h := range proof.MerkleProof {
		copy(buf[offset:offset+32], h[:])
		offset += 32
	}

	// Positions
	copy(buf[offset:], proof.ProofPositions)

	return buf
}

// serializeCompactStateProof creates a compact binary representation of a state proof
func serializeCompactStateProof(proof *StateProof) []byte {
	if proof == nil {
		return nil
	}

	// Compact format: [address(20)] [hasAccount(1)] [nonce(8)] [balance(32)] [storageCount(2)] [storageEntries...]
	var buf bytes.Buffer

	// Address
	buf.Write(proof.Address[:])

	// Account data
	if proof.Account != nil {
		buf.WriteByte(1) // hasAccount = true

		// Nonce
		nonceBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(nonceBuf, proof.Account.Nonce)
		buf.Write(nonceBuf)

		// Balance (as 32-byte big-endian)
		balanceBytes := make([]byte, 32)
		if proof.Account.Balance != nil {
			b := proof.Account.Balance.Bytes()
			copy(balanceBytes[32-len(b):], b)
		}
		buf.Write(balanceBytes)
	} else {
		buf.WriteByte(0) // hasAccount = false
	}

	// Storage proofs count
	countBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(countBuf, uint16(len(proof.StorageProofs))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	buf.Write(countBuf)

	// Storage entries
	for key, entry := range proof.StorageProofs {
		buf.Write(key[:])
		buf.Write(entry.Value[:])
	}

	return buf.Bytes()
}

// computeTxHash computes the hash of a transaction
func computeTxHash(tx *encoding.Transaction) types.Hash {
	if tx == nil {
		return types.Hash{}
	}
	data, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return types.Hash{}
	}
	h := sha3.Sum256(data)
	return types.BytesToHash(h[:])
}

// maxDecompressedSize limits the decompressed data size to prevent gzip bombs (100MB)
const maxDecompressedSize = 100 * 1024 * 1024

// DecompressHeaders decompresses gzip-compressed headers
func DecompressHeaders(compressedHex string) ([]*encoding.BlockHeader, error) {
	compressed, err := hex.DecodeString(compressedHex)
	if err != nil {
		return nil, err
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	// Limit decompressed size to prevent gzip bombs
	limitedReader := io.LimitReader(gzReader, maxDecompressedSize+1)
	uncompressed, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	if len(uncompressed) > maxDecompressedSize {
		return nil, errors.New("decompressed data exceeds maximum allowed size")
	}

	var headers []*encoding.BlockHeader
	offset := 0

	for offset < len(uncompressed) {
		if offset+4 > len(uncompressed) {
			break
		}

		length := binary.BigEndian.Uint32(uncompressed[offset : offset+4])
		offset += 4

		if offset+int(length) > len(uncompressed) {
			break
		}

		header, err := encoding.UnmarshalBlockHeader(uncompressed[offset : offset+int(length)])
		if err != nil {
			return nil, err
		}

		headers = append(headers, header)
		offset += int(length)
	}

	return headers, nil
}

// GetSyncCommittee returns the current sync committee info for light clients.
func (api *LightClientAPI) GetSyncCommittee(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	verifier := api.syncer.GetSyncCommitteeVerifier()
	if verifier == nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "sync committee verifier not available")
	}

	committee := verifier.GetCurrentCommittee()
	if committee == nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "sync committee not available")
	}

	pubKeysHex := make([]string, len(committee.ValidatorPubKeys))
	for i, pk := range committee.ValidatorPubKeys {
		pubKeysHex[i] = hex.EncodeToString(pk)
	}

	return map[string]any{
		"period":           committee.Period,
		"validatorCount":   len(committee.ValidatorPubKeys),
		"validatorPubKeys": pubKeysHex,
	}, nil
}

// VerifySyncCommitteeSig verifies a block header's sync committee signature.
func (api *LightClientAPI) VerifySyncCommitteeSig(ctx context.Context, params json.RawMessage) (any, *rpc.Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, rpc.ErrInvalidParams
	}

	headerHex, ok := args[0].(string)
	if !ok {
		return nil, rpc.ErrInvalidParams
	}

	headerBytes, err := hex.DecodeString(headerHex)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid header hex", err.Error())
	}

	header, err := encoding.UnmarshalBlockHeader(headerBytes)
	if err != nil {
		return nil, rpc.NewErrorWithData(rpc.ErrCodeInvalidParams, "invalid block header", err.Error())
	}

	verifier := api.syncer.GetSyncCommitteeVerifier()
	if verifier == nil {
		return nil, rpc.NewError(rpc.ErrCodeNotFound, "sync committee verifier not available")
	}

	if err := verifier.VerifyBlockHeader(header); err != nil {
		return map[string]any{
			"valid": false,
			"error": err.Error(),
		}, nil
	}

	return map[string]any{
		"valid": true,
	}, nil
}
