// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

type BlobAPI struct {
	blockReader BlockReader
	txPool      TxPool
	chainInfo   ChainInfo
}

func NewBlobAPI(blockReader BlockReader, txPool TxPool, chainInfo ChainInfo) *BlobAPI {
	return &BlobAPI{
		blockReader: blockReader,
		txPool:      txPool,
		chainInfo:   chainInfo,
	}
}

func (api *BlobAPI) RegisterHandlers(server *Server) {
	// FIX: Wrap handlers with adapter functions that match the
	// RegisterHandler accepted signature (ctx, json.RawMessage) (any, error).
	// Previously the custom signatures (no params, typed params) silently
	// failed to register, making the methods unreachable.
	server.RegisterHandler("eth_blobBaseFee", func(ctx context.Context, _ json.RawMessage) (any, error) {
		return api.GetBlobBaseFee(ctx)
	})
	server.RegisterHandler("eth_getBlobSidecar", func(ctx context.Context, params json.RawMessage) (any, error) {
		p, rerr := unwrapParams(params)
		if rerr != nil {
			return nil, rerr
		}
		var hashStr string
		if err := json.Unmarshal(p, &hashStr); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		hashBytes, err := hex.DecodeString(cleanHexPrefix(hashStr))
		if err != nil || len(hashBytes) != 32 {
			return nil, fmt.Errorf("invalid transaction hash")
		}
		var txHash types.Hash
		copy(txHash[:], hashBytes)
		return api.GetBlobSidecar(ctx, txHash)
	})
	// R31-P2 FIX (P2-6, 2026-07-28): Quantaureum blob transactions use
	// quantum FRI polynomial commitments (DA-), NOT standard EIP-4844
	// KZG commitments. The eth_ prefix implies KZG semantics, which is
	// misleading. Register qau_sendBlobTransaction as the PRIMARY method
	// (clear Quantaureum-specific namespace), and keep eth_sendBlobTransaction
	// as a backwards-compatibility alias for wallets that expect the EIP-4844
	// method name. Both route to the same FRI-based implementation.
	blobTxHandler := func(ctx context.Context, params json.RawMessage) (any, error) {
		p, rerr := unwrapParams(params)
		if rerr != nil {
			return nil, rerr
		}
		var req SendBlobTxRequest
		if err := json.Unmarshal(p, &req); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		return api.SendBlobTransaction(ctx, req)
	}
	// Primary method: qau_ prefix (Quantaureum-specific, uses FRI commitments)
	server.RegisterHandler("qau_sendBlobTransaction", blobTxHandler)
	server.RegisterAdminMethod("qau_sendBlobTransaction")
	// Compatibility alias: eth_ prefix for wallets expecting EIP-4844 naming.
	// NOTE: Despite the eth_ prefix, commitments use FRI, not KZG.
	server.RegisterHandler("eth_sendBlobTransaction", blobTxHandler)
	// Security fix: eth_sendBlobTransaction is a write operation (submitting to the tx pool);
	// it must be registered as an admin method to enforce auth and prevent unauthorized calls
	server.RegisterAdminMethod("eth_sendBlobTransaction")
}

type BlobBaseFeeResult struct {
	BlobBaseFee   string `json:"blobBaseFee"`
	ExcessBlobGas string `json:"excessBlobGas"`
	BlobGasUsed   string `json:"blobGasUsed"`
	TargetBlobGas string `json:"targetBlobGas"`
}

func (api *BlobAPI) GetBlobBaseFee(ctx context.Context) (*BlobBaseFeeResult, error) {
	// FIX: Check blockReader before use to prevent nil pointer dereference
	if api.blockReader == nil {
		return nil, fmt.Errorf("block reader not available")
	}
	latestHeight := api.blockReader.GetLatestHeight()
	block, err := api.blockReader.GetBlockByHeight(latestHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	type headerGetter interface {
		GetHeader() any
	}
	var excessBlobGas, blobGasUsed uint64
	if hg, ok := block.(headerGetter); ok {
		if h := hg.GetHeader(); h != nil {
			if bh, ok := h.(*encoding.BlockHeader); ok {
				excessBlobGas = bh.ExcessBlobGas
				blobGasUsed = bh.BlobGasUsed
			}
		}
	}

	blobFee := encoding.CalcBlobFee(excessBlobGas)

	return &BlobBaseFeeResult{
		BlobBaseFee:   fmt.Sprintf("0x%x", blobFee),
		ExcessBlobGas: fmt.Sprintf("0x%x", excessBlobGas),
		BlobGasUsed:   fmt.Sprintf("0x%x", blobGasUsed),
		TargetBlobGas: fmt.Sprintf("0x%x", uint64(encoding.TargetBlobsPerBlock)*encoding.BlobGasPerBlob),
	}, nil
}

type BlobSidecarResult struct {
	BlockHash   string   `json:"blockHash"`
	BlockNumber string   `json:"blockNumber"`
	TxIndex     string   `json:"txIndex"`
	TxHash      string   `json:"txHash"`
	Blobs       []string `json:"blobs"`
	Commitments []string `json:"commitments"`
	Proofs      []string `json:"proofs"`
}

func (api *BlobAPI) GetBlobSidecar(ctx context.Context, txHash types.Hash) (*BlobSidecarResult, error) {
	tx, err := api.blockReader.GetTransaction(txHash)
	if err != nil {
		return nil, fmt.Errorf("transaction not found: %w", err)
	}

	blobTx, ok := tx.(*encoding.Transaction)
	if !ok {
		return nil, fmt.Errorf("unexpected transaction type")
	}

	if !blobTx.IsBlobTx() {
		return nil, fmt.Errorf("transaction is not a blob transaction")
	}

	sidecar := blobTx.BlobTxSidecar()
	if sidecar == nil {
		return nil, fmt.Errorf("blob sidecar not available for this transaction")
	}

	result := &BlobSidecarResult{
		TxHash:      hex.EncodeToString(txHash[:]),
		Blobs:       make([]string, len(sidecar.Blobs)),
		Commitments: make([]string, len(sidecar.Commitments)),
		Proofs:      make([]string, len(sidecar.Proofs)),
	}

	for i, blob := range sidecar.Blobs {
		result.Blobs[i] = "0x" + hex.EncodeToString(blob[:])
	}
	for i, c := range sidecar.Commitments {
		result.Commitments[i] = "0x" + hex.EncodeToString(c[:])
	}
	for i, p := range sidecar.Proofs {
		result.Proofs[i] = "0x" + hex.EncodeToString(p[:])
	}

	return result, nil
}

type SendBlobTxRequest struct {
	To               string   `json:"to"`
	Value            string   `json:"value"`
	Gas              string   `json:"gas"`
	MaxFeePerGas     string   `json:"maxFeePerGas"`
	MaxPriorityFee   string   `json:"maxPriorityFeePerGas"`
	MaxFeePerBlobGas string   `json:"maxFeePerBlobGas"`
	Data             string   `json:"data"`
	Blobs            []string `json:"blobs"`
	Commitments      []string `json:"commitments"`
	Proofs           []string `json:"proofs"`
	Signature        string   `json:"signature"`
	PublicKey        string   `json:"publicKey"`
}

func (api *BlobAPI) SendBlobTransaction(ctx context.Context, req SendBlobTxRequest) (types.Hash, error) {
	if len(req.Blobs) == 0 {
		return types.Hash{}, fmt.Errorf("at least one blob is required")
	}
	if len(req.Blobs) > encoding.MaxBlobsPerTransaction {
		return types.Hash{}, fmt.Errorf("too many blobs: %d > %d", len(req.Blobs), encoding.MaxBlobsPerTransaction)
	}

	toAddr := types.Address{}
	if req.To != "" {
		addrBytes, err := hex.DecodeString(cleanHexPrefix(req.To))
		if err != nil || len(addrBytes) != types.AddressLength {
			return types.Hash{}, fmt.Errorf("invalid 'to' address")
		}
		copy(toAddr[:], addrBytes)
	}

	value := new(big.Int)
	if req.Value != "" {
		if _, ok := value.SetString(cleanHexPrefix(req.Value), 16); !ok {
			return types.Hash{}, fmt.Errorf("invalid value")
		}
	}
	if value.Sign() < 0 {
		return types.Hash{}, fmt.Errorf("negative value not allowed")
	}

	gas := uint64(21000)
	if req.Gas != "" {
		if _, err := fmt.Sscanf(cleanHexPrefix(req.Gas), "%x", &gas); err != nil {
			return types.Hash{}, fmt.Errorf("invalid gas: %w", err)
		}
	}
	if gas > 30000000 {
		return types.Hash{}, fmt.Errorf("gas exceeds maximum allowed")
	}

	maxFeePerGas := new(big.Int)
	if req.MaxFeePerGas != "" {
		if _, ok := maxFeePerGas.SetString(cleanHexPrefix(req.MaxFeePerGas), 16); !ok {
			return types.Hash{}, fmt.Errorf("invalid maxFeePerGas")
		}
	}

	maxPriorityFee := new(big.Int)
	if req.MaxPriorityFee != "" {
		if _, ok := maxPriorityFee.SetString(cleanHexPrefix(req.MaxPriorityFee), 16); !ok {
			return types.Hash{}, fmt.Errorf("invalid maxPriorityFeePerGas")
		}
	}

	maxFeePerBlobGas := new(big.Int)
	if req.MaxFeePerBlobGas != "" {
		if _, ok := maxFeePerBlobGas.SetString(cleanHexPrefix(req.MaxFeePerBlobGas), 16); !ok {
			return types.Hash{}, fmt.Errorf("invalid maxFeePerBlobGas")
		}
	}

	var data []byte
	if req.Data != "" {
		var err error
		// R32-P2-02 FIX (2026-07-28): Cap data size to prevent memory DoS.
		trimmed := cleanHexPrefix(req.Data)
		if len(trimmed) > maxParseHexBytesLen {
			return types.Hash{}, fmt.Errorf("data too large: %d chars exceeds limit %d", len(trimmed), maxParseHexBytesLen)
		}
		data, err = hex.DecodeString(trimmed)
		if err != nil {
			return types.Hash{}, fmt.Errorf("invalid data: %w", err)
		}
	}

	sidecar := &encoding.BlobTxSidecar{
		Blobs:       make([]encoding.Blob, len(req.Blobs)),
		Commitments: make([]encoding.KZGCommitment, len(req.Blobs)),
		Proofs:      make([]encoding.KZGProof, len(req.Blobs)),
	}

	for i, blobHex := range req.Blobs {
		blobBytes, err := hex.DecodeString(cleanHexPrefix(blobHex))
		if err != nil || len(blobBytes) != encoding.BlobSize {
			return types.Hash{}, fmt.Errorf("invalid blob at index %d: must be %d bytes", i, encoding.BlobSize)
		}
		copy(sidecar.Blobs[i][:], blobBytes)
	}

	for i, cHex := range req.Commitments {
		cBytes, err := hex.DecodeString(cleanHexPrefix(cHex))
		if err != nil || len(cBytes) != 48 {
			return types.Hash{}, fmt.Errorf("invalid commitment at index %d", i)
		}
		copy(sidecar.Commitments[i][:], cBytes)
	}

	for i, pHex := range req.Proofs {
		pBytes, err := hex.DecodeString(cleanHexPrefix(pHex))
		if err != nil || len(pBytes) != 48 {
			return types.Hash{}, fmt.Errorf("invalid proof at index %d", i)
		}
		copy(sidecar.Proofs[i][:], pBytes)
	}

	if err := sidecar.Validate(); err != nil {
		return types.Hash{}, fmt.Errorf("blob sidecar validation failed: %w", err)
	}

	var sig []byte
	if req.Signature != "" {
		var err error
		sig, err = hex.DecodeString(cleanHexPrefix(req.Signature))
		if err != nil {
			return types.Hash{}, fmt.Errorf("invalid signature: %w", err)
		}
	}

	var pubKey []byte
	if req.PublicKey != "" {
		var err error
		pubKey, err = hex.DecodeString(cleanHexPrefix(req.PublicKey))
		if err != nil {
			return types.Hash{}, fmt.Errorf("invalid publicKey: %w", err)
		}
	}

	chainID := api.chainInfo.NetworkID()

	tx := &encoding.Transaction{
		Version:              1,
		Type:                 encoding.TxTypeBlob,
		Nonce:                0,
		To:                   &toAddr,
		Value:                value,
		GasLimit:             gas,
		GasPrice:             maxFeePerGas,
		Data:                 data,
		Signature:            sig,
		PublicKey:            pubKey,
		ChainID:              chainID,
		MaxFeePerGas:         maxFeePerGas,
		MaxPriorityFeePerGas: maxPriorityFee,
		MaxFeePerBlobGas:     maxFeePerBlobGas,
		BlobVersionedHashes:  sidecar.VersionedHashes(),
		BlobGasUsed:          sidecar.BlobGasUsed(),
		BlobSidecar:          sidecar,
	}

	if err := encoding.ValidateBlobTransaction(tx); err != nil {
		return types.Hash{}, fmt.Errorf("blob transaction validation failed: %w", err)
	}

	// audit fix (CRITICAL): verify the signature exists and submit to the tx pool
	if len(sig) == 0 {
		return types.Hash{}, fmt.Errorf("signature is required")
	}
	tx.Signature = sig
	// FIX: Recover sender address from signature and set From field.
	// Previously From was left as zero address, making it impossible to identify
	// the sender or properly track the transaction origin.
	// RPC-FIX: Use crypto.PublicKeyAddressFromBytes instead of
	// sha3.Sum256(pubKey)[:20]. The previous implementation used a different
	// hash algorithm than the rest of the codebase, allowing an attacker to
	// craft a pubKey whose sha3.Sum256 matches a victim's address while the
	// real Dilithium3 address derivation differs — enabling sender address
	// forgery and audit pollution.
	//
	// DA- (INFO, 2026-07-17): This finding is closed by the RPC-
	// fix above. The current implementation uses
	// crypto.PublicKeyAddressFromBytes → types.AddressFromPublicKey, which
	// applies SHA3-256(pubKey) and takes the last 20 bytes (bytes 12..31).
	// This matches the wallet's dilithium3.ts deriveAddress() algorithm
	// (see types/types.go:130-150 for the shared interface contract). The
	// Ethereum-style keccak256(pubKey)[:20] derivation has been removed.
	// No further code change needed — this comment is the closure artifact.
	if len(pubKey) > 0 && len(sig) > 0 {
		tx.From = crypto.PublicKeyAddressFromBytes(pubKey)
	}
	if api.txPool == nil {
		return types.Hash{}, fmt.Errorf("transaction pool not available")
	}

	txData, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to marshal transaction: %w", err)
	}

	hash, err := api.txPool.AddTransaction(txData)
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to submit transaction: %w", err)
	}
	return hash, nil
}

func cleanHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}
