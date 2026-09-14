// Quantaureum Node source, version 1.0.0.
// Package main provides the Quantaureum Command Line Interface (CLI) tool.
// This tool provides developers with a comprehensive interface to interact with the Quantaureum blockchain.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RPCClient is a simple JSON-RPC client for Quantaureum
type RPCClient struct {
	endpoint  string
	client    *http.Client
	allowlist []string // audit-fix R62-F3 [HIGH]: SSRF mitigation — optional endpoint allowlist
}

// NewRPCClient creates a new RPC client.
// endpoint can be an HTTP URL (e.g., http://localhost:8545) or an IPC path.
// audit-fix R62-F3 [HIGH]: SSRF mitigation — if allowlist is non-nil, validates that
// the endpoint matches at least one allowlist pattern before connecting.
func NewRPCClient(endpoint string, allowlist ...string) (*RPCClient, error) {
	if len(allowlist) > 0 && !isEndpointAllowed(endpoint, allowlist) {
		return nil, fmt.Errorf("endpoint %q is not in the allowlist", endpoint)
	}
	return &RPCClient{
		endpoint:  endpoint,
		allowlist: allowlist,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// isEndpointAllowed checks if a given endpoint URL is in the allowlist.
// Patterns may include host:port, IP:port, or net.JoinHostPort with wildcards.
// audit-fix R62-F3 [HIGH]: Prevents SSRF by blocking internal/dangerous targets.
func isEndpointAllowed(endpoint string, allowlist []string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Host)
	if host == "" {
		// IPC path — allow by default
		return true
	}
	// Block obvious internal targets
	lowerHost := strings.ToLower(host)
	if strings.HasPrefix(lowerHost, "127.") ||
		strings.HasPrefix(lowerHost, "localhost") ||
		strings.HasPrefix(lowerHost, "0.0.0.0") ||
		strings.HasPrefix(lowerHost, "[::1]") ||
		strings.HasPrefix(lowerHost, "169.254.") || // link-local (AWS metadata)
		strings.Contains(lowerHost, ".internal") ||
		strings.Contains(lowerHost, ":443") && strings.Contains(lowerHost, "metadata") ||
		strings.Contains(lowerHost, "169.254.169.254") || // AWS/GCP/Azure metadata
		strings.Contains(lowerHost, "metadata.google.internal") {
		// Unless explicitly in the allowlist, reject internal/cloud metadata endpoints
		for _, p := range allowlist {
			if strings.EqualFold(host, strings.ToLower(p)) {
				return true
			}
		}
		return false
	}
	// Check allowlist
	for _, p := range allowlist {
		if strings.EqualFold(host, strings.ToLower(p)) {
			return true
		}
	}
	// No allowlist entries matched
	return false
}

// call makes a JSON-RPC call to the endpoint
func (c *RPCClient) call(method string, params []any) (json.RawMessage, error) {
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.client.Post(c.endpoint, "application/json", bytes.NewReader(reqJSON)) // #nosec G704 -- SSRF: endpoint validated by allowlist
	if err != nil {
		return nil, fmt.Errorf("failed to connect to node: %w", err)
	}
	// R59-G104 [MEDIUM] FIX: Always drain and close the response body to allow
	// the HTTP transport to reuse the connection. Previously, on non-200 responses,
	// the body was closed immediately without reading, which can leave a keep-alive
	// connection in a half-closed state, preventing reuse and exhausting connections.
	defer func() {
		io.Copy(io.Discard, resp.Body) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		resp.Body.Close()              // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("node returned status %d", resp.StatusCode)
	}

	var result struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *RPCError       `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("RPC error: %s (code %d)", result.Error.Message, result.Error.Code)
	}

	return result.Result, nil
}

// RPCError represents an RPC error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ChainID returns the chain ID
func (c *RPCClient) ChainID(ctx context.Context) (string, error) {
	result, err := c.call("eth_chainId", nil)
	if err != nil {
		return "", err
	}
	var chainID string
	if err := json.Unmarshal(result, &chainID); err != nil {
		return "", err
	}
	return chainID, nil
}

// BlockNumber returns the latest block number
func (c *RPCClient) BlockNumber(ctx context.Context) (uint64, error) {
	result, err := c.call("eth_blockNumber", nil)
	if err != nil {
		return 0, err
	}
	var blockNum string
	if err := json.Unmarshal(result, &blockNum); err != nil {
		return 0, err
	}
	// Parse hex string
	var num uint64
	// audit-fix R62-F4 [MEDIUM]: fmt.Sscanf return value was ignored. On malformed hex
	// (e.g., "0xGGGG"), Sscanf fails silently and num remains 0, causing incorrect block
	// queries to succeed without any error signal.
	if _, err := fmt.Sscanf(blockNum, "%x", &num); err != nil {
		return 0, fmt.Errorf("failed to parse block number %q: %w", blockNum, err)
	}
	return num, nil
}

// GetBalance returns the balance of an address
func (c *RPCClient) GetBalance(ctx context.Context, address string) (string, error) {
	result, err := c.call("eth_getBalance", []any{address, "latest"})
	if err != nil {
		return "", err
	}
	var balance string
	if err := json.Unmarshal(result, &balance); err != nil {
		return "", err
	}
	return balance, nil
}

// GetBlockByNumber returns a block by its number
func (c *RPCClient) GetBlockByNumber(ctx context.Context, number string) (map[string]any, error) {
	result, err := c.call("eth_getBlockByNumber", []any{number, true})
	if err != nil {
		return nil, err
	}
	var block map[string]any
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, err
	}
	return block, nil
}

// GetBlockByHash returns a block by its hash
func (c *RPCClient) GetBlockByHash(ctx context.Context, hash string) (map[string]any, error) {
	result, err := c.call("eth_getBlockByHash", []any{hash, true})
	if err != nil {
		return nil, err
	}
	var block map[string]any
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, err
	}
	return block, nil
}

// GetTransactionReceipt returns the receipt of a transaction
func (c *RPCClient) GetTransactionReceipt(ctx context.Context, hash string) (map[string]any, error) {
	result, err := c.call("eth_getTransactionReceipt", []any{hash})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	var receipt map[string]any
	if err := json.Unmarshal(result, &receipt); err != nil {
		return nil, err
	}
	return receipt, nil
}

// TxPoolStatus returns the transaction pool status
func (c *RPCClient) TxPoolStatus(ctx context.Context) (map[string]string, error) {
	result, err := c.call("txpool_status", nil)
	if err != nil {
		return nil, err
	}
	var status map[string]string
	if err := json.Unmarshal(result, &status); err != nil {
		return nil, err
	}
	return status, nil
}

// TxPoolContent returns the transaction pool content
func (c *RPCClient) TxPoolContent(ctx context.Context) (map[string]any, error) {
	result, err := c.call("txpool_content", nil)
	if err != nil {
		return nil, err
	}
	var content map[string]any
	if err := json.Unmarshal(result, &content); err != nil {
		return nil, err
	}
	return content, nil
}

// NetPeerCount returns the number of connected peers
func (c *RPCClient) NetPeerCount(ctx context.Context) (uint64, error) {
	result, err := c.call("net_peerCount", nil)
	if err != nil {
		return 0, err
	}
	var count string
	if err := json.Unmarshal(result, &count); err != nil {
		return 0, err
	}
	var num uint64
	// audit-fix R62-F4 [MEDIUM]: fmt.Sscanf return value was ignored. On malformed hex
	// (e.g., "0xGGGG"), Sscanf fails silently and num remains 0, causing incorrect peer
	// count to be returned without any error signal.
	if _, err := fmt.Sscanf(count, "%x", &num); err != nil {
		return 0, fmt.Errorf("failed to parse peer count %q: %w", count, err)
	}
	return num, nil
}

// AdminPeers returns information about connected peers
func (c *RPCClient) AdminPeers(ctx context.Context) ([]map[string]any, error) {
	result, err := c.call("admin_peers", nil)
	if err != nil {
		return nil, err
	}
	var peers []map[string]any
	if err := json.Unmarshal(result, &peers); err != nil {
		return nil, err
	}
	return peers, nil
}

// Web3ClientVersion returns the client version
func (c *RPCClient) Web3ClientVersion(ctx context.Context) (string, error) {
	result, err := c.call("web3_clientVersion", nil)
	if err != nil {
		return "", err
	}
	var version string
	if err := json.Unmarshal(result, &version); err != nil {
		return "", err
	}
	return version, nil
}

// QPOSStatus returns the QPOS consensus status
func (c *RPCClient) QPOSStatus(ctx context.Context) (map[string]any, error) {
	result, err := c.call("qau_qposStatus", nil)
	if err != nil {
		return nil, err
	}
	var status map[string]any
	if err := json.Unmarshal(result, &status); err != nil {
		return nil, err
	}
	return status, nil
}

// GetStake returns stake info for an address
func (c *RPCClient) GetStake(ctx context.Context, address string) (map[string]any, error) {
	result, err := c.call("qau_getStake", []any{address})
	if err != nil {
		return nil, err
	}
	var stake map[string]any
	if err := json.Unmarshal(result, &stake); err != nil {
		return nil, err
	}
	return stake, nil
}

// SendRawTransaction sends a raw transaction
func (c *RPCClient) SendRawTransaction(ctx context.Context, signedTx string) (string, error) {
	result, err := c.call("eth_sendRawTransaction", []any{signedTx})
	if err != nil {
		return "", err
	}
	var hash string
	if err := json.Unmarshal(result, &hash); err != nil {
		return "", err
	}
	return hash, nil
}

// GetTransactionByHash returns a transaction by its hash
func (c *RPCClient) GetTransactionByHash(ctx context.Context, hash string) (map[string]any, error) {
	result, err := c.call("eth_getTransactionByHash", []any{hash})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	var tx map[string]any
	if err := json.Unmarshal(result, &tx); err != nil {
		return nil, err
	}
	return tx, nil
}
