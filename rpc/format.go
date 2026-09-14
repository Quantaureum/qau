// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"encoding/hex"
	"fmt"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// BlockResponse is the formatted block response for RPC
type BlockResponse struct {
	Number           string `json:"number"`
	Hash             string `json:"hash"`
	ParentHash       string `json:"parentHash"`
	Timestamp        string `json:"timestamp"`
	StateRoot        string `json:"stateRoot"`
	TransactionsRoot string `json:"transactionsRoot"`
	ReceiptsRoot     string `json:"receiptsRoot"`
	Miner            string `json:"miner"`
	GasLimit         string `json:"gasLimit"`
	GasUsed          string `json:"gasUsed"`
	BaseFeePerGas    string `json:"baseFeePerGas,omitempty"`
	Transactions     []any  `json:"transactions"`
}

// TransactionResponse is the formatted transaction response for RPC
type TransactionResponse struct {
	Hash                 string `json:"hash"`
	Nonce                string `json:"nonce"`
	BlockHash            string `json:"blockHash"`
	BlockNumber          string `json:"blockNumber"`
	TransactionIndex     string `json:"transactionIndex"`
	From                 string `json:"from"`
	To                   any    `json:"to"`
	Value                string `json:"value"`
	Gas                  string `json:"gas"`
	GasPrice             string `json:"gasPrice"`
	MaxFeePerGas         string `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas,omitempty"`
	Type                 string `json:"type,omitempty"`
	Input                string `json:"input"`
	PublicKey            string `json:"publicKey,omitempty"`
	Signature            string `json:"signature,omitempty"`
	SignatureType        string `json:"signatureType,omitempty"`
}

// FormatBlock formats a block for RPC response
func FormatBlock(blk *encoding.Block, fullTx bool) *BlockResponse {
	if blk == nil || blk.Header == nil {
		return nil
	}

	// Compute block hash using the canonical hash function (same as block store)
	blockHash := block.ComputeBlockHash(blk.Header)

	resp := &BlockResponse{
		Number:           formatHex(blk.Header.Height),
		Hash:             formatHashHex(blockHash),
		ParentHash:       formatHashHex(blk.Header.ParentHash),
		Timestamp:        formatHex(uint64(blk.Header.Timestamp)), // #nosec G115 -- Timestamp is always non-negative
		StateRoot:        formatHashHex(blk.Header.StateRoot),
		TransactionsRoot: formatHashHex(blk.Header.TxRoot),
		ReceiptsRoot:     formatHashHex(blk.Header.ReceiptRoot),
		Miner:            formatAddressHex(blk.Header.ProposerAddr),
		GasLimit:         formatHex(blk.Header.GasLimit),
		GasUsed:          formatHex(blk.Header.GasUsed),
		Transactions:     make([]any, 0),
	}

	if blk.Header.BaseFee != nil && blk.Header.BaseFee.Sign() > 0 {
		resp.BaseFeePerGas = "0x" + blk.Header.BaseFee.Text(16)
	}

	// Add transactions
	if blk.Transactions != nil {
		for i, tx := range blk.Transactions {
			if fullTx {
				resp.Transactions = append(resp.Transactions, FormatTransaction(tx, blockHash, blk.Header.Height, uint64(i))) //nolint:gosec,G115
			} else {
				resp.Transactions = append(resp.Transactions, formatHashHex(tx.Hash()))
			}
		}
	}

	return resp
}

// FormatTransaction formats a transaction for RPC response
func FormatTransaction(tx *encoding.Transaction, blockHash types.Hash, blockNumber uint64, txIndex uint64) *TransactionResponse {
	if tx == nil {
		return nil
	}

	var toAddr any = nil
	if tx.To != nil {
		toAddr = formatAddressHex(*tx.To)
	}

	value := "0x0"
	if tx.Value != nil {
		value = "0x" + tx.Value.Text(16)
	}

	gasPrice := "0x0"
	if tx.GasPrice != nil {
		gasPrice = "0x" + tx.GasPrice.Text(16)
	}

	txHash := tx.Hash()

	resp := &TransactionResponse{
		Hash:             formatHashHex(txHash),
		Nonce:            formatHex(tx.Nonce),
		BlockHash:        formatHashHex(blockHash),
		BlockNumber:      formatHex(blockNumber),
		TransactionIndex: formatHex(txIndex),
		From:             formatAddressHex(tx.From),
		To:               toAddr,
		Value:            value,
		Gas:              formatHex(tx.GasLimit),
		GasPrice:         gasPrice,
		Input:            formatBytesHex(tx.Data),
	}

	if tx.Type == encoding.TxTypeDynamicFee {
		resp.Type = "0x2"
		if tx.MaxFeePerGas != nil {
			resp.MaxFeePerGas = "0x" + tx.MaxFeePerGas.Text(16)
		}
		if tx.MaxPriorityFeePerGas != nil {
			resp.MaxPriorityFeePerGas = "0x" + tx.MaxPriorityFeePerGas.Text(16)
		}
	} else {
		resp.Type = fmt.Sprintf("0x%x", uint8(tx.Type))
	}

	// Add quantum signature information
	// P2-12 FIX: Truncate signature and public key to prevent leaking full
	// quantum cryptographic material (3293-byte signature, 1952-byte pubkey)
	// in RPC transaction responses.
	if len(tx.PublicKey) > 0 {
		resp.PublicKey = formatTruncatedBytesHex(tx.PublicKey, 10)
	}
	if len(tx.Signature) > 0 {
		resp.Signature = formatTruncatedBytesHex(tx.Signature, 10)
	}

	// Dilithium3 is the only supported signature type
	// LOW-5 FIX: Replace magic numbers (3293, 1952) with the named constants
	// from the crypto package. The magic numbers were brittle: if Dilithium3
	// parameters ever change, the constants in crypto/generate.go would be
	// updated but these literals would silently break signature-type detection.
	if len(tx.Signature) == crypto.Dilithium3SignatureSize && len(tx.PublicKey) == crypto.Dilithium3PublicKeySize {
		resp.SignatureType = "dilithium3"
	}

	return resp
}

// Helper functions
func formatHex(n uint64) string {
	return fmt.Sprintf("0x%x", n)
}

func formatHashHex(h types.Hash) string {
	return "0x" + hex.EncodeToString(h[:])
}

func formatAddressHex(a types.Address) string {
	return "0x" + hex.EncodeToString(a[:])
}

func formatBytesHex(b []byte) string {
	if len(b) == 0 {
		return "0x"
	}
	return "0x" + hex.EncodeToString(b)
}

// formatTruncatedBytesHex returns a hex-encoded string of the first maxBytes
// bytes of b, followed by "..." if the input is longer. This prevents leaking
// full quantum signatures (3293 bytes) or public keys (1952 bytes) in RPC
// responses while still providing enough data for identification/debugging.
// P2-12 FIX: truncate sensitive cryptographic material in transaction responses.
func formatTruncatedBytesHex(b []byte, maxBytes int) string {
	if len(b) == 0 {
		return "0x"
	}
	if len(b) <= maxBytes {
		return "0x" + hex.EncodeToString(b)
	}
	return "0x" + hex.EncodeToString(b[:maxBytes]) + "..."
}
