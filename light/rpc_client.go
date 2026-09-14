// Quantaureum Node source, version 1.0.0.
package light

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/quantaureum/qau/types"
)

// RPCClient is the RPC client a light node uses to reach a full node
type RPCClient struct {
	baseURL    string
	httpClient *http.Client
}

// RPC error definitions
var (
	ErrRPCRequestFailed = errors.New("RPC request failed")
	ErrRPCResponse      = errors.New("RPC response error")
	ErrEmptyTree        = errors.New("empty Merkle tree")
	ErrInvalidIndex     = errors.New("invalid index")
)

// rpcRequest is a JSON-RPC request
type rpcRequest struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

// rpcResponse is a JSON-RPC response
type rpcResponse struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  any    `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// blockHeaderResult is the header result returned by RPC
type blockHeaderResult struct {
	Height     string `json:"height"`
	ParentHash string `json:"parentHash"`
	StateRoot  string `json:"stateRoot"`
	TxRoot     string `json:"transactionRoot"`
	Timestamp  string `json:"timestamp"`
	Proposer   string `json:"proposer"`
	Signature  string `json:"signature"`
}

// NewRPCClient creates an RPC client
func NewRPCClient(rpcURL string) RPCClient {
	return RPCClient{
		baseURL: strings.TrimRight(rpcURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// call performs a JSON-RPC call
func (c *RPCClient) call(method string, params []any) (any, error) {
	req := rpcRequest{
		Jsonrpc: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPCRequestFailed, err)
	}

	httpReq, err := http.NewRequest("POST", c.baseURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPCRequestFailed, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPCRequestFailed, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPCRequestFailed, err)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPCResponse, err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("%w: [%d] %s", ErrRPCResponse, rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// GetLatestHeight fetches the latest block height
func (c *RPCClient) GetLatestHeight() (uint64, error) {
	result, err := c.call("eth_blockNumber", []any{})
	if err != nil {
		return 0, err
	}

	hexStr, ok := result.(string)
	if !ok {
		return 0, fmt.Errorf("%w: expected a string result", ErrRPCResponse)
	}

	return parseHexUint64(hexStr)
}

// GetBlockHeader fetches the header at the given height
func (c *RPCClient) GetBlockHeader(height uint64) (*BlockHeader, error) {
	hexHeight := fmt.Sprintf("0x%x", height)
	result, err := c.call("eth_getBlockByNumber", []any{hexHeight, false})
	if err != nil {
		return nil, err
	}

	return parseBlockHeader(result)
}

// GetBalance queries an account balance
func (c *RPCClient) GetBalance(addr types.Address) (*big.Int, error) {
	result, err := c.call("eth_getBalance", []any{addr.ToHexAddress(), "latest"})
	if err != nil {
		return nil, err
	}

	hexStr, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("%w: expected a string result", ErrRPCResponse)
	}

	balance := new(big.Int)
	// strip the 0x prefix
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if _, ok := balance.SetString(hexStr, 16); !ok {
		return nil, fmt.Errorf("%w: invalid balance value", ErrRPCResponse)
	}

	return balance, nil
}

// parseHexUint64 parses a hex string into a uint64
func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")

	var v uint64
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= uint64(c-'A') + 10
		default:
			return 0, fmt.Errorf("invalid hex character: %c", c)
		}
	}
	return v, nil
}

// parseBlockHeader parses a header from an RPC response
func parseBlockHeader(result any) (*BlockHeader, error) {
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPCResponse, err)
	}

	var headerResult blockHeaderResult
	if err := json.Unmarshal(resultBytes, &headerResult); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPCResponse, err)
	}

	height, err := parseHexUint64(headerResult.Height)
	if err != nil {
		return nil, fmt.Errorf("failed to parse height: %w", err)
	}

	timestamp, err := parseHexUint64(headerResult.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	parentHash, err := parseHexToHash(headerResult.ParentHash)
	if err != nil {
		return nil, fmt.Errorf("failed to parse parent hash: %w", err)
	}

	stateRoot, err := parseHexToHash(headerResult.StateRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to parse state root: %w", err)
	}

	txRoot, err := parseHexToHash(headerResult.TxRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tx root: %w", err)
	}

	proposer, err := types.ParseAddressWithFallback(headerResult.Proposer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proposer address: %w", err)
	}

	var signature []byte
	if headerResult.Signature != "" {
		sigHex := strings.TrimPrefix(headerResult.Signature, "0x")
		sigBytes, err := hexDecode(sigHex)
		if err == nil {
			signature = sigBytes
		}
	}

	return &BlockHeader{
		Height:     height,
		ParentHash: parentHash,
		StateRoot:  stateRoot,
		TxRoot:     txRoot,
		Timestamp:  int64(timestamp),
		Proposer:   proposer,
		Signature:  signature,
	}, nil
}

// hexDecode decodes a hex string
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, ok := hexVal(s[i])
		if !ok {
			return nil, fmt.Errorf("invalid hex character: %c", s[i])
		}
		lo, ok := hexVal(s[i+1])
		if !ok {
			return nil, fmt.Errorf("invalid hex character: %c", s[i+1])
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

// hexVal returns the value of a hex character
func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// parseHexToHash parses a hex string into a types.Hash
func parseHexToHash(s string) (types.Hash, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	b, err := hexDecode(s)
	if err != nil {
		return types.Hash{}, err
	}
	return types.BytesToHash(b), nil
}
