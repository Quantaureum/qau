// Quantaureum Go SDK source, version 1.0.0.
// Package client provides the RPC client for interacting with Quantaureum nodes.
package client

import (
	"context"
	"fmt"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
	"github.com/quantaureum/qau/sdks/go-sdk/types"
)

// SendTransaction sends a signed transaction to the network.
// Returns the transaction hash on success.
func (c *Client) SendTransaction(ctx context.Context, tx *types.Transaction) (common.Hash, error) {
	if err := c.validateClientOpen(); err != nil {
		return common.Hash{}, err
	}
	if err := validateContext(ctx); err != nil {
		return common.Hash{}, err
	}
	if tx == nil {
		return common.Hash{}, errors.NewValidationError("tx", "transaction cannot be nil")
	}

	if !tx.IsSigned() {
		return common.Hash{}, errors.NewValidationError("tx", "transaction must be signed")
	}

	// Encode the transaction to RLP
	data := tx.RLPEncode()
	hexData := fmt.Sprintf("0x%x", data)

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_sendRawTransaction", hexData); err != nil {
		return common.Hash{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	return common.HexToHash(result), nil
}

// Call executes a message call transaction, which is directly executed in the VM
// of the node, but never mined into the blockchain.
func (c *Client) Call(ctx context.Context, msg CallMsg, blockNumber any) ([]byte, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var blockArg string
	switch v := blockNumber.(type) {
	case nil:
		blockArg = "latest"
	case string:
		blockArg = v
	case *any:
		if v == nil {
			blockArg = "latest"
		} else {
			blockArg = fmt.Sprintf("%v", *v)
		}
	default:
		blockArg = fmt.Sprintf("0x%x", blockNumber)
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_call", toCallArg(msg), blockArg); err != nil {
		return nil, fmt.Errorf("failed to execute call: %w", err)
	}

	if result == "" || result == "0x" {
		return []byte{}, nil
	}

	data, err := hexToBytes(result)
	if err != nil {
		return nil, fmt.Errorf("invalid call result: %w", err)
	}

	return data, nil
}

// CallContract is an alias for Call that accepts a block number as *big.Int.
func (c *Client) CallContract(ctx context.Context, msg CallMsg, blockNumber any) ([]byte, error) {
	return c.Call(ctx, msg, blockNumber)
}

// PendingCallContract executes a message call against the pending state.
func (c *Client) PendingCallContract(ctx context.Context, msg CallMsg) ([]byte, error) {
	return c.Call(ctx, msg, "pending")
}

// SendRawTransaction sends a raw signed transaction to the network.
// The data should be the RLP-encoded signed transaction.
func (c *Client) SendRawTransaction(ctx context.Context, data []byte) (common.Hash, error) {
	if err := c.validateClientOpen(); err != nil {
		return common.Hash{}, err
	}
	if err := validateContext(ctx); err != nil {
		return common.Hash{}, err
	}
	if len(data) == 0 {
		return common.Hash{}, errors.NewValidationError("data", "transaction data cannot be empty")
	}

	hexData := fmt.Sprintf("0x%x", data)

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_sendRawTransaction", hexData); err != nil {
		return common.Hash{}, fmt.Errorf("failed to send raw transaction: %w", err)
	}

	return common.HexToHash(result), nil
}

// FilterLogs returns logs matching the given filter query.
func (c *Client) FilterLogs(ctx context.Context, q FilterQuery) ([]*types.Log, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result []rpcLog
	if err := c.rpc.Call(ctx, &result, "eth_getLogs", toFilterArg(q)); err != nil {
		return nil, fmt.Errorf("failed to filter logs: %w", err)
	}

	logs := make([]*types.Log, len(result))
	for i, rl := range result {
		log, err := parseLog(&rl)
		if err != nil {
			return nil, fmt.Errorf("failed to parse log %d: %w", i, err)
		}
		logs[i] = log
	}

	return logs, nil
}

// ChainID returns the chain ID of the connected network.
func (c *Client) ChainID(ctx context.Context) (uint64, error) {
	if err := c.validateClientOpen(); err != nil {
		return 0, err
	}
	if err := validateContext(ctx); err != nil {
		return 0, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "eth_chainId"); err != nil {
		return 0, fmt.Errorf("failed to get chain ID: %w", err)
	}

	chainID, err := hexToUint64(result)
	if err != nil {
		return 0, fmt.Errorf("invalid chain ID response: %w", err)
	}

	return chainID, nil
}

// NetworkID returns the network ID.
func (c *Client) NetworkID(ctx context.Context) (uint64, error) {
	if err := c.validateClientOpen(); err != nil {
		return 0, err
	}
	if err := validateContext(ctx); err != nil {
		return 0, err
	}

	var result string
	if err := c.rpc.Call(ctx, &result, "net_version"); err != nil {
		return 0, fmt.Errorf("failed to get network ID: %w", err)
	}

	// net_version returns a decimal string, not hex
	var networkID uint64
	_, err := fmt.Sscanf(result, "%d", &networkID)
	if err != nil {
		// Try hex format as fallback
		networkID, err = hexToUint64(result)
		if err != nil {
			return 0, fmt.Errorf("invalid network ID response: %w", err)
		}
	}

	return networkID, nil
}

// SyncProgress represents the sync progress of the node.
type SyncProgress struct {
	StartingBlock uint64 // Block number where sync started
	CurrentBlock  uint64 // Current block number being synced
	HighestBlock  uint64 // Highest block number known
	PulledStates  uint64 // Number of state entries pulled
	KnownStates   uint64 // Total number of known state entries
}

// SyncProgress returns the sync progress of the node.
// Returns nil if the node is not syncing.
func (c *Client) SyncProgress(ctx context.Context) (*SyncProgress, error) {
	if err := c.validateClientOpen(); err != nil {
		return nil, err
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}

	var result any
	if err := c.rpc.Call(ctx, &result, "eth_syncing"); err != nil {
		return nil, fmt.Errorf("failed to get sync progress: %w", err)
	}

	// If result is false, node is not syncing
	if syncing, ok := result.(bool); ok && !syncing {
		return nil, nil
	}

	// Parse sync progress
	if progress, ok := result.(map[string]any); ok {
		sp := &SyncProgress{}

		if v, ok := progress["startingBlock"].(string); ok {
			sp.StartingBlock, _ = hexToUint64(v)
		}
		if v, ok := progress["currentBlock"].(string); ok {
			sp.CurrentBlock, _ = hexToUint64(v)
		}
		if v, ok := progress["highestBlock"].(string); ok {
			sp.HighestBlock, _ = hexToUint64(v)
		}
		if v, ok := progress["pulledStates"].(string); ok {
			sp.PulledStates, _ = hexToUint64(v)
		}
		if v, ok := progress["knownStates"].(string); ok {
			sp.KnownStates, _ = hexToUint64(v)
		}

		return sp, nil
	}

	return nil, nil
}
