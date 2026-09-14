// Quantaureum Go SDK source, version 1.0.0.
// Package client provides the RPC client for interacting with Quantaureum nodes.
package client

import (
	"context"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/types"
)

// BlockNumber returns the current block number.
func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	if err := c.validateClientOpen(); err != nil {
		return 0, err
	}
	if err := validateContext(ctx); err != nil {
		return 0, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_blockNumber"); err != nil {
		return 0, fmt.Errorf("failed to get block number: %w", err)
	}

	blockNum, err := hexToUint64(result)
	if err != nil {
		return 0, fmt.Errorf("invalid block number response: %w", err)
	}

	return blockNum, nil
}

// BlockByNumber returns the block with the given number.
// If number is nil, it returns the latest block.
// Set fullTx to true to include full transaction objects.
func (c *Client) BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error) {
	return c.blockByNumber(ctx, number, true)
}

// BlockByNumberWithTxHashes returns the block with transaction hashes only.
func (c *Client) BlockByNumberWithTxHashes(ctx context.Context, number *big.Int) (*types.Block, error) {
	return c.blockByNumber(ctx, number, false)
}

// blockByNumber is the internal implementation for block by number queries.
func (c *Client) blockByNumber(ctx context.Context, number *big.Int, fullTx bool) (*types.Block, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result rpcBlock
	if err := c.rpc.Call(ctx, &result, "eth_getBlockByNumber", toBlockNumArg(number), fullTx); err != nil {
		return nil, fmt.Errorf("failed to get block by number: %w", err)
	}

	// Check if block exists
	if result.Hash == "" {
		return nil, nil
	}

	block, err := parseBlock(&result, fullTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}

	return block, nil
}

// BlockByHash returns the block with the given hash.
// Set fullTx to true to include full transaction objects.
func (c *Client) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return c.blockByHash(ctx, hash, true)
}

// BlockByHashWithTxHashes returns the block with transaction hashes only.
func (c *Client) BlockByHashWithTxHashes(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return c.blockByHash(ctx, hash, false)
}

// blockByHash is the internal implementation for block by hash queries.
func (c *Client) blockByHash(ctx context.Context, hash common.Hash, fullTx bool) (*types.Block, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result rpcBlock
	if err := c.rpc.Call(ctx, &result, "eth_getBlockByHash", hash.Hex(), fullTx); err != nil {
		return nil, fmt.Errorf("failed to get block by hash: %w", err)
	}

	// Check if block exists
	if result.Hash == "" {
		return nil, nil
	}

	block, err := parseBlock(&result, fullTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}

	return block, nil
}

// HeaderByNumber returns the block header with the given number.
func (c *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.BlockHeader, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result rpcBlock
	if err := c.rpc.Call(ctx, &result, "eth_getBlockByNumber", toBlockNumArg(number), false); err != nil {
		return nil, fmt.Errorf("failed to get header by number: %w", err)
	}

	// Check if block exists
	if result.Hash == "" {
		return nil, nil
	}

	header, err := parseBlockHeader(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	return header, nil
}

// HeaderByHash returns the block header with the given hash.
func (c *Client) HeaderByHash(ctx context.Context, hash common.Hash) (*types.BlockHeader, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result rpcBlock
	if err := c.rpc.Call(ctx, &result, "eth_getBlockByHash", hash.Hex(), false); err != nil {
		return nil, fmt.Errorf("failed to get header by hash: %w", err)
	}

	// Check if block exists
	if result.Hash == "" {
		return nil, nil
	}

	header, err := parseBlockHeader(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	return header, nil
}

// parseBlockHeader converts an rpcBlock to a types.BlockHeader.
func parseBlockHeader(rb *rpcBlock) (*types.BlockHeader, error) {
	header := &types.BlockHeader{}

	// Parse number
	if rb.Number != "" {
		num, err := hexToBigInt(rb.Number)
		if err != nil {
			return nil, fmt.Errorf("invalid block number: %w", err)
		}
		header.Number = num
	}

	// Parse hashes
	header.Hash = common.HexToHash(rb.Hash)
	header.ParentHash = common.HexToHash(rb.ParentHash)
	header.StateRoot = common.HexToHash(rb.StateRoot)
	header.TransactionsRoot = common.HexToHash(rb.TransactionsRoot)
	header.ReceiptsRoot = common.HexToHash(rb.ReceiptsRoot)

	// Parse nonce
	if rb.Nonce != "" {
		nonce, err := hexToUint64(rb.Nonce)
		if err == nil {
			header.Nonce = nonce
		}
	}

	// Parse miner
	header.Miner = common.HexToAddress(rb.Miner)

	// Parse difficulty
	if rb.Difficulty != "" {
		diff, err := hexToBigInt(rb.Difficulty)
		if err == nil {
			header.Difficulty = diff
		}
	}

	// Parse total difficulty
	if rb.TotalDifficulty != "" {
		totalDiff, err := hexToBigInt(rb.TotalDifficulty)
		if err == nil {
			header.TotalDifficulty = totalDiff
		}
	}

	// Parse extra data
	if rb.ExtraData != "" {
		extraData, err := hexToBytes(rb.ExtraData)
		if err == nil {
			header.ExtraData = extraData
		}
	}

	// Parse size
	if rb.Size != "" {
		size, err := hexToUint64(rb.Size)
		if err == nil {
			header.Size = size
		}
	}

	// Parse gas limit
	if rb.GasLimit != "" {
		gasLimit, err := hexToUint64(rb.GasLimit)
		if err == nil {
			header.GasLimit = gasLimit
		}
	}

	// Parse gas used
	if rb.GasUsed != "" {
		gasUsed, err := hexToUint64(rb.GasUsed)
		if err == nil {
			header.GasUsed = gasUsed
		}
	}

	// Parse timestamp
	if rb.Timestamp != "" {
		timestamp, err := hexToUint64(rb.Timestamp)
		if err == nil {
			header.Timestamp = timestamp
		}
	}

	// Parse logs bloom
	if rb.LogsBloom != "" {
		logsBloom, err := hexToBytes(rb.LogsBloom)
		if err == nil {
			header.LogsBloom = logsBloom
		}
	}

	return header, nil
}
