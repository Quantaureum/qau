// Quantaureum Go SDK source, version 1.0.0.
// Package client provides the RPC client for interacting with Quantaureum nodes.
package client

import (
	"context"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
)

// BalanceAt returns the balance of the account at the given block number.
// If blockNumber is nil, it returns the balance at the latest block.
func (c *Client) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getBalance", account.Hex(), toBlockNumArg(blockNumber)); err != nil {
		return nil, fmt.Errorf("failed to get balance for %s: %w", account.Hex(), err)
	}

	balance, err := hexToBigInt(result)
	if err != nil {
		return nil, fmt.Errorf("invalid balance response: %w", err)
	}

	return balance, nil
}

// NonceAt returns the nonce of the account at the given block number.
// If blockNumber is nil, it returns the nonce at the latest block.
func (c *Client) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	if err := c.validateClientOpen(); err != nil {
		return 0, err
	}
	if err := validateContext(ctx); err != nil {
		return 0, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getTransactionCount", account.Hex(), toBlockNumArg(blockNumber)); err != nil {
		return 0, fmt.Errorf("failed to get nonce for %s: %w", account.Hex(), err)
	}

	nonce, err := hexToUint64(result)
	if err != nil {
		return 0, fmt.Errorf("invalid nonce response: %w", err)
	}

	return nonce, nil
}

// PendingNonceAt returns the pending nonce of the account.
// This is the nonce that should be used for the next transaction.
func (c *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	if err := c.validateClientOpen(); err != nil {
		return 0, err
	}
	if err := validateContext(ctx); err != nil {
		return 0, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getTransactionCount", account.Hex(), "pending"); err != nil {
		return 0, fmt.Errorf("failed to get pending nonce for %s: %w", account.Hex(), err)
	}

	nonce, err := hexToUint64(result)
	if err != nil {
		return 0, fmt.Errorf("invalid pending nonce response: %w", err)
	}

	return nonce, nil
}

// CodeAt returns the contract code at the given address and block number.
// If blockNumber is nil, it returns the code at the latest block.
// Returns empty bytes for non-contract addresses.
func (c *Client) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getCode", account.Hex(), toBlockNumArg(blockNumber)); err != nil {
		return nil, fmt.Errorf("failed to get code for %s: %w", account.Hex(), err)
	}

	// Empty code is returned as "0x"
	if result == "" || result == "0x" {
		return []byte{}, nil
	}

	code, err := hexToBytes(result)
	if err != nil {
		return nil, fmt.Errorf("invalid code response: %w", err)
	}

	return code, nil
}

// StorageAt returns the value of a storage slot at the given address and block number.
// If blockNumber is nil, it returns the value at the latest block.
func (c *Client) StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getStorageAt", account.Hex(), key.Hex(), toBlockNumArg(blockNumber)); err != nil {
		return nil, fmt.Errorf("failed to get storage for %s at %s: %w", account.Hex(), key.Hex(), err)
	}

	if result == "" || result == "0x" {
		return make([]byte, 32), nil
	}

	value, err := hexToBytes(result)
	if err != nil {
		return nil, fmt.Errorf("invalid storage response: %w", err)
	}

	// Pad to 32 bytes if necessary
	if len(value) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(value):], value)
		return padded, nil
	}

	return value, nil
}

// PendingBalanceAt returns the pending balance of the account.
func (c *Client) PendingBalanceAt(ctx context.Context, account common.Address) (*big.Int, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getBalance", account.Hex(), "pending"); err != nil {
		return nil, fmt.Errorf("failed to get pending balance for %s: %w", account.Hex(), err)
	}

	balance, err := hexToBigInt(result)
	if err != nil {
		return nil, fmt.Errorf("invalid pending balance response: %w", err)
	}

	return balance, nil
}

// PendingCodeAt returns the pending contract code at the given address.
func (c *Client) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getCode", account.Hex(), "pending"); err != nil {
		return nil, fmt.Errorf("failed to get pending code for %s: %w", account.Hex(), err)
	}

	if result == "" || result == "0x" {
		return []byte{}, nil
	}

	code, err := hexToBytes(result)
	if err != nil {
		return nil, fmt.Errorf("invalid pending code response: %w", err)
	}

	return code, nil
}

// PendingStorageAt returns the pending value of a storage slot at the given address.
func (c *Client) PendingStorageAt(ctx context.Context, account common.Address, key common.Hash) ([]byte, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_getStorageAt", account.Hex(), key.Hex(), "pending"); err != nil {
		return nil, fmt.Errorf("failed to get pending storage for %s at %s: %w", account.Hex(), key.Hex(), err)
	}

	if result == "" || result == "0x" {
		return make([]byte, 32), nil
	}

	value, err := hexToBytes(result)
	if err != nil {
		return nil, fmt.Errorf("invalid pending storage response: %w", err)
	}

	// Pad to 32 bytes if necessary
	if len(value) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(value):], value)
		return padded, nil
	}

	return value, nil
}
