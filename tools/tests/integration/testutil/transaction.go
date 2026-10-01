// Quantaureum Node source, version 1.0.0.
//go:build integration || e2e || chaos

// Package testutil provides utilities for integration testing.
package testutil

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// TransactionParams represents parameters for creating a transaction.
type TransactionParams struct {
	From     string   `json:"from"`
	To       string   `json:"to,omitempty"`
	Value    *big.Int `json:"value,omitempty"`
	GasLimit uint64   `json:"gas,omitempty"`
	GasPrice *big.Int `json:"gasPrice,omitempty"`
	Data     []byte   `json:"data,omitempty"`
	Nonce    *uint64  `json:"nonce,omitempty"`
}

// TransactionReceipt represents a transaction receipt.
type TransactionReceipt struct {
	TransactionHash string `json:"transactionHash"`
	BlockHash       string `json:"blockHash"`
	BlockNumber     uint64 `json:"blockNumber"`
	GasUsed         uint64 `json:"gasUsed"`
	Status          uint64 `json:"status"`
	ContractAddress string `json:"contractAddress,omitempty"`
}

// BlockInfo represents block information.
type BlockInfo struct {
	Number       uint64   `json:"number"`
	Hash         string   `json:"hash"`
	ParentHash   string   `json:"parentHash"`
	Timestamp    uint64   `json:"timestamp"`
	Transactions []string `json:"transactions"`
	GasUsed      uint64   `json:"gasUsed"`
	GasLimit     uint64   `json:"gasLimit"`
}

// GetNonce gets the nonce for an address.
func (c *NodeClient) GetNonce(ctx context.Context, address string) (uint64, error) {
	result, err := c.Call(ctx, "eth_getTransactionCount", []any{address, "latest"})
	if err != nil {
		return 0, err
	}

	var nonceStr string
	if err := json.Unmarshal(result, &nonceStr); err != nil {
		return 0, fmt.Errorf("failed to unmarshal nonce: %w", err)
	}

	var nonce uint64
	fmt.Sscanf(nonceStr, "0x%x", &nonce)
	return nonce, nil
}

// SendRawTransaction sends a raw signed transaction.
func (c *NodeClient) SendRawTransaction(ctx context.Context, signedTx string) (string, error) {
	result, err := c.Call(ctx, "eth_sendRawTransaction", []any{signedTx})
	if err != nil {
		return "", err
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", fmt.Errorf("failed to unmarshal tx hash: %w", err)
	}

	return txHash, nil
}

// WaitForTransaction waits for a transaction to be mined.
func (c *NodeClient) WaitForTransaction(ctx context.Context, txHash string, timeout time.Duration) (*TransactionReceipt, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		result, err := c.GetTransactionReceipt(ctx, txHash)
		if err == nil && result != nil {
			var receipt TransactionReceipt
			if err := json.Unmarshal(result, &receipt); err == nil && receipt.BlockHash != "" {
				return &receipt, nil
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
			// Retry
		}
	}

	return nil, fmt.Errorf("timeout waiting for transaction %s", txHash)
}

// GetBlockInfo gets detailed block information.
func (c *NodeClient) GetBlockInfo(ctx context.Context, number uint64) (*BlockInfo, error) {
	result, err := c.GetBlock(ctx, number, false)
	if err != nil {
		return nil, err
	}

	var block BlockInfo
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, fmt.Errorf("failed to unmarshal block: %w", err)
	}

	return &block, nil
}

// GetLatestBlockInfo gets the latest block information.
func (c *NodeClient) GetLatestBlockInfo(ctx context.Context) (*BlockInfo, error) {
	blockNum, err := c.GetBlockNumber(ctx)
	if err != nil {
		return nil, err
	}
	return c.GetBlockInfo(ctx, blockNum)
}

// EstimateGas estimates gas for a transaction.
func (c *NodeClient) EstimateGas(ctx context.Context, params *TransactionParams) (uint64, error) {
	callParams := map[string]any{
		"from": params.From,
	}
	if params.To != "" {
		callParams["to"] = params.To
	}
	if params.Value != nil {
		callParams["value"] = fmt.Sprintf("0x%x", params.Value)
	}
	if params.Data != nil {
		callParams["data"] = "0x" + hex.EncodeToString(params.Data)
	}

	result, err := c.Call(ctx, "eth_estimateGas", []any{callParams})
	if err != nil {
		return 0, err
	}

	var gasStr string
	if err := json.Unmarshal(result, &gasStr); err != nil {
		return 0, fmt.Errorf("failed to unmarshal gas estimate: %w", err)
	}

	var gas uint64
	fmt.Sscanf(gasStr, "0x%x", &gas)
	return gas, nil
}

// GetGasPrice gets the current gas price.
func (c *NodeClient) GetGasPrice(ctx context.Context) (*big.Int, error) {
	result, err := c.Call(ctx, "eth_gasPrice", nil)
	if err != nil {
		return nil, err
	}

	var priceStr string
	if err := json.Unmarshal(result, &priceStr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal gas price: %w", err)
	}

	price := new(big.Int)
	price.SetString(priceStr[2:], 16) // Remove "0x" prefix
	return price, nil
}

// GetPendingTransactions gets pending transactions.
func (c *NodeClient) GetPendingTransactions(ctx context.Context) ([]json.RawMessage, error) {
	result, err := c.Call(ctx, "eth_pendingTransactions", nil)
	if err != nil {
		return nil, err
	}

	var txs []json.RawMessage
	if err := json.Unmarshal(result, &txs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pending transactions: %w", err)
	}

	return txs, nil
}

// GetValidators gets the current validator set.
func (c *NodeClient) GetValidators(ctx context.Context) ([]json.RawMessage, error) {
	result, err := c.Call(ctx, "qau_getValidators", nil)
	if err != nil {
		return nil, err
	}

	var validators []json.RawMessage
	if err := json.Unmarshal(result, &validators); err != nil {
		return nil, fmt.Errorf("failed to unmarshal validators: %w", err)
	}

	return validators, nil
}

// GetSyncStatus gets the synchronization status.
func (c *NodeClient) GetSyncStatus(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, "eth_syncing", nil)
}

// IsSyncing checks if the node is syncing.
func (c *NodeClient) IsSyncing(ctx context.Context) (bool, error) {
	result, err := c.GetSyncStatus(ctx)
	if err != nil {
		return false, err
	}

	// If result is "false", node is not syncing
	var syncing bool
	if err := json.Unmarshal(result, &syncing); err == nil {
		return syncing, nil
	}

	// If result is an object, node is syncing
	return true, nil
}
