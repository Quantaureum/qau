// Quantaureum Node source, version 1.0.0.
//go:build integration || e2e || chaos

// Package testutil provides utilities for integration testing.
package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// NodeClient provides a client for interacting with a Quantaureum node.
type NodeClient struct {
	rpcURL    string
	wsURL     string
	healthURL string
	client    *http.Client
}

// NewNodeClient creates a new node client.
func NewNodeClient(rpcURL, wsURL, healthURL string) *NodeClient {
	return &NodeClient{
		rpcURL:    rpcURL,
		wsURL:     wsURL,
		healthURL: healthURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RPCRequest represents a JSON-RPC request.
type RPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
	ID      int    `json:"id"`
}

// RPCResponse represents a JSON-RPC response.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
	ID      int             `json:"id"`
}

// RPCError represents a JSON-RPC error.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
}

// Call makes a JSON-RPC call to the node.
func (c *NodeClient) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	req := RPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp RPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, rpcResp.Error
	}

	return rpcResp.Result, nil
}

// BatchCall makes a batch JSON-RPC call to the node.
func (c *NodeClient) BatchCall(ctx context.Context, requests []RPCRequest) ([]RPCResponse, error) {
	body, err := json.Marshal(requests)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResponses []RPCResponse
	if err := json.Unmarshal(respBody, &rpcResponses); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return rpcResponses, nil
}

// GetBalance gets the balance of an address.
func (c *NodeClient) GetBalance(ctx context.Context, address string) (string, error) {
	result, err := c.Call(ctx, "eth_getBalance", []any{address, "latest"})
	if err != nil {
		return "", err
	}

	var balance string
	if err := json.Unmarshal(result, &balance); err != nil {
		return "", fmt.Errorf("failed to unmarshal balance: %w", err)
	}

	return balance, nil
}

// GetBlockNumber gets the current block number.
func (c *NodeClient) GetBlockNumber(ctx context.Context) (uint64, error) {
	result, err := c.Call(ctx, "eth_blockNumber", nil)
	if err != nil {
		return 0, err
	}

	var blockNum string
	if err := json.Unmarshal(result, &blockNum); err != nil {
		return 0, fmt.Errorf("failed to unmarshal block number: %w", err)
	}

	// Parse hex string
	var num uint64
	fmt.Sscanf(blockNum, "0x%x", &num)
	return num, nil
}

// GetBlock gets a block by number.
func (c *NodeClient) GetBlock(ctx context.Context, number uint64, fullTx bool) (json.RawMessage, error) {
	blockNum := fmt.Sprintf("0x%x", number)
	return c.Call(ctx, "eth_getBlockByNumber", []any{blockNum, fullTx})
}

// GetBlockByHash gets a block by hash.
func (c *NodeClient) GetBlockByHash(ctx context.Context, hash string, fullTx bool) (json.RawMessage, error) {
	return c.Call(ctx, "eth_getBlockByHash", []any{hash, fullTx})
}

// SendTransaction sends a raw transaction.
func (c *NodeClient) SendTransaction(ctx context.Context, txData string) (string, error) {
	result, err := c.Call(ctx, "eth_sendRawTransaction", []any{txData})
	if err != nil {
		return "", err
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", fmt.Errorf("failed to unmarshal tx hash: %w", err)
	}

	return txHash, nil
}

// GetTransactionReceipt gets a transaction receipt.
func (c *NodeClient) GetTransactionReceipt(ctx context.Context, txHash string) (json.RawMessage, error) {
	return c.Call(ctx, "eth_getTransactionReceipt", []any{txHash})
}

// GetPeerCount gets the number of connected peers.
func (c *NodeClient) GetPeerCount(ctx context.Context) (int, error) {
	result, err := c.Call(ctx, "net_peerCount", nil)
	if err != nil {
		return 0, err
	}

	var countStr string
	if err := json.Unmarshal(result, &countStr); err != nil {
		return 0, fmt.Errorf("failed to unmarshal peer count: %w", err)
	}

	var count int
	fmt.Sscanf(countStr, "0x%x", &count)
	return count, nil
}

// GetChainID gets the chain ID.
func (c *NodeClient) GetChainID(ctx context.Context) (uint64, error) {
	result, err := c.Call(ctx, "eth_chainId", nil)
	if err != nil {
		return 0, err
	}

	var chainIDStr string
	if err := json.Unmarshal(result, &chainIDStr); err != nil {
		return 0, fmt.Errorf("failed to unmarshal chain ID: %w", err)
	}

	var chainID uint64
	fmt.Sscanf(chainIDStr, "0x%x", &chainID)
	return chainID, nil
}

// HealthCheck checks if the node is healthy.
func (c *NodeClient) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.healthURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: status %d", resp.StatusCode)
	}

	return nil
}

// ReadinessCheck checks if the node is ready.
func (c *NodeClient) ReadinessCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.healthURL+"/ready", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("readiness check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: status %d", resp.StatusCode)
	}

	return nil
}

// WaitForReady waits for the node to be ready.
func (c *NodeClient) WaitForReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if err := c.ReadinessCheck(ctx); err == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			// Retry
		}
	}

	return fmt.Errorf("timeout waiting for node to be ready")
}
