// Quantaureum Go SDK source, version 1.0.0.
// Package client provides the RPC client for interacting with Quantaureum nodes.
package client

import (
	"context"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/sdks/go-sdk/errors"
)

// SuggestGasPrice returns the suggested gas price for a transaction.
func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_gasPrice"); err != nil {
		return nil, fmt.Errorf("failed to get gas price: %w", err)
	}

	gasPrice, err := hexToBigInt(result)
	if err != nil {
		return nil, fmt.Errorf("invalid gas price response: %w", err)
	}

	return gasPrice, nil
}

// EstimateGas estimates the gas needed to execute a transaction.
func (c *Client) EstimateGas(ctx context.Context, msg CallMsg) (uint64, error) {
	if err := c.validateClientOpen(); err != nil {
		return 0, err
	}
	if err := validateContext(ctx); err != nil {
		return 0, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_estimateGas", toCallArg(msg)); err != nil {
		return 0, fmt.Errorf("failed to estimate gas: %w", err)
	}

	gas, err := hexToUint64(result)
	if err != nil {
		return 0, fmt.Errorf("invalid gas estimate response: %w", err)
	}

	return gas, nil
}

// SuggestGasTipCap returns the suggested gas tip cap for EIP-1559 transactions.
func (c *Client) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_maxPriorityFeePerGas"); err != nil {
		// Fallback to a default tip if the method is not supported
		return big.NewInt(1000000000), nil // 1 Gwei default
	}

	tipCap, err := hexToBigInt(result)
	if err != nil {
		return nil, fmt.Errorf("invalid gas tip cap response: %w", err)
	}

	return tipCap, nil
}

// FeeHistory returns the fee history for a range of blocks.
type FeeHistory struct {
	OldestBlock      *big.Int     // Oldest block in the range
	Reward           [][]*big.Int // Reward percentiles for each block
	BaseFee          []*big.Int   // Base fee for each block
	GasUsedRatio     []float64    // Gas used ratio for each block
	BlobBaseFee      []*big.Int   // Blob base fee for each block (EIP-4844)
	BlobGasUsedRatio []float64    // Blob gas used ratio for each block
}

// FeeHistory returns the fee history for a range of blocks.
func (c *Client) FeeHistory(ctx context.Context, blockCount uint64, lastBlock *big.Int, rewardPercentiles []float64) (*FeeHistory, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if blockCount == 0 {
		return nil, errors.NewValidationError("blockCount", "block count cannot be zero")
	}

	var result struct {
		OldestBlock       string     `json:"oldestBlock"`
		Reward            [][]string `json:"reward"`
		BaseFeePerGas     []string   `json:"baseFeePerGas"`
		GasUsedRatio      []float64  `json:"gasUsedRatio"`
		BaseFeePerBlobGas []string   `json:"baseFeePerBlobGas"`
		BlobGasUsedRatio  []float64  `json:"blobGasUsedRatio"`
	}

	if err := c.rpc.Call(ctx, &result, "eth_feeHistory", fmt.Sprintf("0x%x", blockCount), toBlockNumArg(lastBlock), rewardPercentiles); err != nil {
		return nil, fmt.Errorf("failed to get fee history: %w", err)
	}

	history := &FeeHistory{
		GasUsedRatio:     result.GasUsedRatio,
		BlobGasUsedRatio: result.BlobGasUsedRatio,
	}

	// Parse oldest block
	if result.OldestBlock != "" {
		oldestBlock, err := hexToBigInt(result.OldestBlock)
		if err != nil {
			return nil, fmt.Errorf("invalid oldest block: %w", err)
		}
		history.OldestBlock = oldestBlock
	}

	// Parse rewards
	if len(result.Reward) > 0 {
		history.Reward = make([][]*big.Int, len(result.Reward))
		for i, rewards := range result.Reward {
			history.Reward[i] = make([]*big.Int, len(rewards))
			for j, r := range rewards {
				reward, err := hexToBigInt(r)
				if err != nil {
					return nil, fmt.Errorf("invalid reward: %w", err)
				}
				history.Reward[i][j] = reward
			}
		}
	}

	// Parse base fees
	if len(result.BaseFeePerGas) > 0 {
		history.BaseFee = make([]*big.Int, len(result.BaseFeePerGas))
		for i, bf := range result.BaseFeePerGas {
			baseFee, err := hexToBigInt(bf)
			if err != nil {
				return nil, fmt.Errorf("invalid base fee: %w", err)
			}
			history.BaseFee[i] = baseFee
		}
	}

	// Parse blob base fees
	if len(result.BaseFeePerBlobGas) > 0 {
		history.BlobBaseFee = make([]*big.Int, len(result.BaseFeePerBlobGas))
		for i, bf := range result.BaseFeePerBlobGas {
			blobBaseFee, err := hexToBigInt(bf)
			if err != nil {
				return nil, fmt.Errorf("invalid blob base fee: %w", err)
			}
			history.BlobBaseFee[i] = blobBaseFee
		}
	}

	return history, nil
}
