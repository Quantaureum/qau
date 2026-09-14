// Quantaureum Go SDK source, version 1.0.0.
// Package client provides the RPC client for interacting with Quantaureum nodes.
package client

import (
	"context"
	"fmt"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/types"
)

// TransactionByHash returns the transaction with the given hash.
// The second return value indicates whether the transaction is pending.
// Returns nil, false, nil if the transaction is not found.
func (c *Client) TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, false, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, false, err
	}

	var result rpcTransaction
	if err := c.rpc.Call(ctx, &result, "eth_getTransactionByHash", hash.Hex()); err != nil {
		return nil, false, fmt.Errorf("failed to get transaction by hash: %w", err)
	}

	// Check if transaction exists
	if result.Hash == "" {
		return nil, false, nil
	}

	tx, err := parseTransaction(&result)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse transaction: %w", err)
	}

	// Transaction is pending if blockHash is empty
	isPending := result.BlockHash == "" || result.BlockHash == "0x0000000000000000000000000000000000000000000000000000000000000000"

	return tx, isPending, nil
}

// TransactionReceipt returns the receipt of a transaction by transaction hash.
// Returns nil, nil if the receipt is not found (transaction not yet mined).
func (c *Client) TransactionReceipt(ctx context.Context, hash common.Hash) (*types.Receipt, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result rpcReceipt
	if err := c.rpc.Call(ctx, &result, "eth_getTransactionReceipt", hash.Hex()); err != nil {
		return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	// Check if receipt exists
	if result.TransactionHash == "" {
		return nil, nil
	}

	receipt, err := parseReceipt(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse receipt: %w", err)
	}

	return receipt, nil
}

// TransactionCount returns the number of transactions in a block by block hash.
func (c *Client) TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error) {
	if err := c.validateClientOpen(); err != nil {
		return 0, err
	}
	if err := validateContext(ctx); err != nil {
		return 0, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getBlockTransactionCountByHash", blockHash.Hex()); err != nil {
		return 0, fmt.Errorf("failed to get transaction count: %w", err)
	}

	count, err := hexToUint64(result)
	if err != nil {
		return 0, fmt.Errorf("invalid transaction count: %w", err)
	}

	return uint(count), nil
}

// TransactionInBlock returns a transaction by block hash and index.
func (c *Client) TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result rpcTransaction
	if err := c.rpc.Call(ctx, &result, "eth_getTransactionByBlockHashAndIndex", blockHash.Hex(), fmt.Sprintf("0x%x", index)); err != nil {
		return nil, fmt.Errorf("failed to get transaction in block: %w", err)
	}

	// Check if transaction exists
	if result.Hash == "" {
		return nil, nil
	}

	tx, err := parseTransaction(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse transaction: %w", err)
	}

	return tx, nil
}

// PendingTransactionCount returns the number of pending transactions.
func (c *Client) PendingTransactionCount(ctx context.Context) (uint, error) {
	if err := c.validateClientOpen(); err != nil {
		return 0, err
	}
	if err := validateContext(ctx); err != nil {
		return 0, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getBlockTransactionCountByNumber", "pending"); err != nil {
		return 0, fmt.Errorf("failed to get pending transaction count: %w", err)
	}

	count, err := hexToUint64(result)
	if err != nil {
		return 0, fmt.Errorf("invalid pending transaction count: %w", err)
	}

	return uint(count), nil
}
