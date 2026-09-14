// Quantaureum Go SDK source, version 1.0.0.
// Package client provides the RPC client for interacting with Quantaureum nodes.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/sdks/go-sdk/errors"
)

// jsonRPCVersion is the JSON-RPC version used by the client.
const jsonRPCVersion = "2.0"

// rpcRequest represents a JSON-RPC request.
type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      uint64 `json:"id"`
}

// rpcResponse represents a JSON-RPC response.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError represents a JSON-RPC error.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// maxResponseBytes limits RPC response body size to prevent OOM from a
// malicious or misbehaving node (10 MB).
// audit-fix R9-3
const maxResponseBytes = 10 * 1024 * 1024

// rpcClient handles JSON-RPC communication with the node.
type rpcClient struct {
	url        string
	httpClient *http.Client
	idCounter  uint64
}

// newRPCClient creates a new RPC client.
// audit-fix M-SDK: reject nil httpClient to prevent use of http.DefaultClient
// which has no timeout and can block indefinitely on unresponsive nodes.
func newRPCClient(url string, httpClient *http.Client) *rpcClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &rpcClient{
		url:        url,
		httpClient: httpClient,
		idCounter:  0,
	}
}

// nextID returns the next request ID.
func (c *rpcClient) nextID() uint64 {
	return atomic.AddUint64(&c.idCounter, 1)
}

// Call performs a JSON-RPC call with the given method and parameters.
func (c *rpcClient) Call(ctx context.Context, result any, method string, params ...any) error {
	// Build request
	req := &rpcRequest{
		JSONRPC: jsonRPCVersion,
		Method:  method,
		Params:  params,
		ID:      c.nextID(),
	}

	// Handle nil params
	if req.Params == nil {
		req.Params = []any{}
	}

	// Marshal request
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Execute request
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrConnectionFailed, err)
	}
	defer httpResp.Body.Close()

	// audit-fix R9-3: limit response body size to prevent OOM.
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check HTTP status
	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: status=%d, body=%s", httpResp.StatusCode, string(respBody))
	}

	// Parse response
	var resp rpcResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for RPC error
	if resp.Error != nil {
		return parseRPCError(resp.Error)
	}

	// Unmarshal result if provided
	if result != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return fmt.Errorf("failed to unmarshal result: %w", err)
		}
	}

	return nil
}

// parseRPCError converts an rpcError to an errors.RPCError.
// It also extracts revert reasons from execution reverted errors.
func parseRPCError(e *rpcError) error {
	rpcErr := errors.NewRPCError(e.Code, e.Message, e.Data)

	// Map common error codes to specific errors
	switch e.Code {
	case -32000, -32001, -32002, -32003, -32004, -32005: // Server error range
		if containsString(e.Message, "insufficient funds") {
			return fmt.Errorf("%w: %s", errors.ErrInsufficientFunds, e.Message)
		}
		if containsString(e.Message, "nonce too low") {
			return fmt.Errorf("%w: %s", errors.ErrNonceTooLow, e.Message)
		}
		if containsString(e.Message, "gas too low") || containsString(e.Message, "intrinsic gas") {
			return fmt.Errorf("%w: %s", errors.ErrGasTooLow, e.Message)
		}
		if containsString(e.Message, "execution reverted") || containsString(e.Message, "revert") {
			revertReason := extractRevertReason(e)
			return errors.NewTransactionError("", revertReason, rpcErr)
		}
		if containsString(e.Message, "already known") {
			return fmt.Errorf("%w: %s", errors.ErrTransactionAlreadyKnown, e.Message)
		}
		if containsString(e.Message, "replacement transaction underpriced") {
			return fmt.Errorf("%w: %s", errors.ErrReplacementUnderpriced, e.Message)
		}
	case -32600: // Invalid request
		return errors.NewValidationError("request", e.Message)
	case -32601: // Method not found
		return errors.NewValidationError("method", fmt.Sprintf("method not found: %s", e.Message))
	case -32602: // Invalid params
		return errors.NewValidationError("params", e.Message)
	case -32603: // Internal error
		// Check for revert in internal errors too
		if containsString(e.Message, "execution reverted") || containsString(e.Message, "revert") {
			revertReason := extractRevertReason(e)
			return errors.NewTransactionError("", revertReason, rpcErr)
		}
	}

	return rpcErr
}

// extractRevertReason extracts the revert reason from an RPC error.
// It handles various formats of revert data from different node implementations.
func extractRevertReason(e *rpcError) string {
	// Try to extract from error data
	if e.Data != nil {
		switch data := e.Data.(type) {
		case string:
			// Data might be hex-encoded revert reason
			reason := decodeRevertReason(data)
			if reason != "" {
				return reason
			}
			return data
		case map[string]any:
			// Some nodes return structured data
			if reason, ok := data["reason"].(string); ok {
				return reason
			}
			if message, ok := data["message"].(string); ok {
				return message
			}
			if revertData, ok := data["data"].(string); ok {
				reason := decodeRevertReason(revertData)
				if reason != "" {
					return reason
				}
			}
		}
	}

	// Try to extract from message
	msg := e.Message

	// Look for "execution reverted: <reason>" pattern
	if idx := bytes.Index(bytes.ToLower([]byte(msg)), []byte("execution reverted:")); idx != -1 {
		reason := strings.TrimSpace(msg[idx+19:])
		if reason != "" {
			return reason
		}
	}

	// Look for "revert: <reason>" pattern
	if idx := bytes.Index(bytes.ToLower([]byte(msg)), []byte("revert:")); idx != -1 {
		reason := strings.TrimSpace(msg[idx+7:])
		if reason != "" {
			return reason
		}
	}

	// Look for "reverted with reason string '<reason>'" pattern
	if idx := bytes.Index(bytes.ToLower([]byte(msg)), []byte("reverted with reason string '")); idx != -1 {
		start := idx + 29
		end := strings.Index(msg[start:], "'")
		if end != -1 {
			return msg[start : start+end]
		}
	}

	return "execution reverted"
}

// decodeRevertReason decodes a hex-encoded revert reason.
// The standard format is: 0x08c379a0 + offset + length + string data
func decodeRevertReason(hexData string) string {
	// Remove 0x prefix
	if len(hexData) >= 2 && (hexData[:2] == "0x" || hexData[:2] == "0X") {
		hexData = hexData[2:]
	}

	// Minimum length for Error(string) selector + offset + length
	if len(hexData) < 136 { // 8 + 64 + 64
		return ""
	}

	// Check for Error(string) selector: 0x08c379a0
	if hexData[:8] != "08c379a0" {
		// Check for Panic(uint256) selector: 0x4e487b71
		if hexData[:8] == "4e487b71" && len(hexData) >= 72 {
			// Decode panic code
			panicCode := hexData[8:72]
			return fmt.Sprintf("panic: code %s", panicCode)
		}
		return ""
	}

	// Skip selector (4 bytes = 8 hex chars)
	data := hexData[8:]

	// Read offset (should be 32 = 0x20)
	if len(data) < 64 {
		return ""
	}
	// Skip offset
	data = data[64:]

	// Read length
	if len(data) < 64 {
		return ""
	}
	lengthHex := data[:64]
	length := hexToInt(lengthHex)
	if length == 0 || length > 1024 { // Sanity check
		return ""
	}
	data = data[64:]

	// Read string data
	stringHexLen := int(length) * 2
	if len(data) < stringHexLen {
		return ""
	}
	stringHex := data[:stringHexLen]

	// Decode hex to string
	result := make([]byte, length)
	for i := 0; i < int(length); i++ {
		b := hexToByte(stringHex[i*2 : i*2+2])
		result[i] = b
	}

	return string(result)
}

// hexToInt converts a hex string to uint64.
func hexToInt(hex string) uint64 {
	var result uint64
	for _, c := range hex {
		result *= 16
		switch {
		case c >= '0' && c <= '9':
			result += uint64(c - '0')
		case c >= 'a' && c <= 'f':
			result += uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			result += uint64(c - 'A' + 10)
		}
	}
	return result
}

// hexToByte converts a 2-character hex string to a byte.
func hexToByte(hex string) byte {
	if len(hex) != 2 {
		return 0
	}
	var result byte
	for _, c := range hex {
		result *= 16
		switch {
		case c >= '0' && c <= '9':
			result += byte(c - '0')
		case c >= 'a' && c <= 'f':
			result += byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			result += byte(c - 'A' + 10)
		}
	}
	return result
}

// containsString checks if s contains substr (case-insensitive).
func containsString(s, substr string) bool {
	return bytes.Contains(
		bytes.ToLower([]byte(s)),
		bytes.ToLower([]byte(substr)),
	)
}

// CallRaw performs a JSON-RPC call and returns the raw result.
func (c *rpcClient) CallRaw(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	var result json.RawMessage
	if err := c.Call(ctx, &result, method, params...); err != nil {
		return nil, err
	}
	return result, nil
}

// BatchCall performs multiple JSON-RPC calls in a single request.
type batchRequest struct {
	Method string
	Params []any
	Result any
	Error  error
}

// BatchCall performs multiple JSON-RPC calls in a single HTTP request.
func (c *rpcClient) BatchCall(ctx context.Context, requests []batchRequest) error {
	if len(requests) == 0 {
		return nil
	}

	// Build batch request
	batch := make([]rpcRequest, len(requests))
	for i, req := range requests {
		batch[i] = rpcRequest{
			JSONRPC: jsonRPCVersion,
			Method:  req.Method,
			Params:  req.Params,
			ID:      c.nextID(),
		}
		if batch[i].Params == nil {
			batch[i].Params = []any{}
		}
	}

	// Marshal request
	reqBody, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("failed to marshal batch request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Execute request
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrConnectionFailed, err)
	}
	defer httpResp.Body.Close()

	// audit-fix R9-3: limit response body size to prevent OOM.
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check HTTP status
	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: status=%d, body=%s", httpResp.StatusCode, string(respBody))
	}

	// Parse batch response
	var responses []rpcResponse
	if err := json.Unmarshal(respBody, &responses); err != nil {
		return fmt.Errorf("failed to unmarshal batch response: %w", err)
	}

	// Map responses by ID
	respMap := make(map[uint64]*rpcResponse)
	for i := range responses {
		respMap[responses[i].ID] = &responses[i]
	}

	// Process results
	for i, req := range batch {
		resp, ok := respMap[req.ID]
		if !ok {
			requests[i].Error = fmt.Errorf("missing response for request %d", req.ID)
			continue
		}

		if resp.Error != nil {
			requests[i].Error = parseRPCError(resp.Error)
			continue
		}

		if requests[i].Result != nil && len(resp.Result) > 0 {
			if err := json.Unmarshal(resp.Result, requests[i].Result); err != nil {
				requests[i].Error = fmt.Errorf("failed to unmarshal result: %w", err)
			}
		}
	}

	return nil
}
