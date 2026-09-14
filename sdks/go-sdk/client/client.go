// Quantaureum Go SDK source, version 1.0.0.
// Package client provides the RPC client for interacting with Quantaureum nodes.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
	"github.com/quantaureum/qau/sdks/go-sdk/types"
)

// Client represents a connection to a Quantaureum node.
type Client struct {
	rpc    *rpcClient
	url    string
	closed bool
}

// ClientOption is a function that configures a Client.
type ClientOption func(*clientConfig)

// clientConfig holds client configuration options.
type clientConfig struct {
	httpClient *http.Client
	timeout    time.Duration
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *clientConfig) {
		c.httpClient = httpClient
	}
}

// WithTimeout sets the default timeout for requests.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *clientConfig) {
		c.timeout = timeout
	}
}

// ErrClientClosed is returned when operations are attempted on a closed client.
var ErrClientClosed = errors.NewValidationError("client", "client is closed")

// NewClient creates a new client connected to the given URL.
func NewClient(url string, opts ...ClientOption) (*Client, error) {
	if url == "" {
		return nil, errors.NewValidationError("url", "URL cannot be empty")
	}

	// Apply options
	cfg := &clientConfig{
		timeout: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Create HTTP client with timeout if not provided
	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: cfg.timeout,
		}
	}

	return &Client{
		rpc: newRPCClient(url, httpClient),
		url: url,
	}, nil
}

// validateClientOpen checks if the client is open and returns an error if closed.
func (c *Client) validateClientOpen() error {
	if c == nil {
		return errors.NewValidationError("client", "client cannot be nil")
	}
	if c.closed {
		return ErrClientClosed
	}
	return nil
}

// validateContext validates that a context is not nil.
func validateContext(ctx context.Context) error {
	if ctx == nil {
		return errors.NewValidationError("ctx", "context cannot be nil")
	}
	return nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	c.closed = true
	return nil
}

// IsClosed returns true if the client has been closed.
func (c *Client) IsClosed() bool {
	return c.closed
}

// URL returns the URL of the connected node.
func (c *Client) URL() string {
	return c.url
}

// CallMsg represents a message call.
type CallMsg struct {
	From     common.Address  // Sender address (optional for calls)
	To       *common.Address // Recipient address (nil for contract creation)
	Gas      uint64          // Gas limit
	GasPrice *big.Int        // Gas price
	Value    *big.Int        // Value in wei
	Data     []byte          // Call data
}

// FilterQuery represents a filter query for logs.
type FilterQuery struct {
	BlockHash *common.Hash     // Block hash (mutually exclusive with FromBlock/ToBlock)
	FromBlock *big.Int         // Start block (nil = latest)
	ToBlock   *big.Int         // End block (nil = latest)
	Addresses []common.Address // Contract addresses to filter
	Topics    [][]common.Hash  // Topics to filter
}

// Subscription represents an event subscription.
type Subscription interface {
	Unsubscribe()
	Err() <-chan error
}

// toBlockNumArg converts a block number to the RPC argument format.
func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	if number.Sign() < 0 {
		// Negative numbers represent special blocks
		switch number.Int64() {
		case -1:
			return "pending"
		case -2:
			return "latest"
		case -3:
			return "earliest"
		default:
			return "latest"
		}
	}
	return fmt.Sprintf("0x%x", number)
}

// toCallArg converts a CallMsg to the RPC argument format.
func toCallArg(msg CallMsg) any {
	arg := map[string]any{}

	if !msg.From.IsEmpty() {
		arg["from"] = msg.From.Hex()
	}
	if msg.To != nil {
		arg["to"] = msg.To.Hex()
	}
	if msg.Gas != 0 {
		arg["gas"] = fmt.Sprintf("0x%x", msg.Gas)
	}
	if msg.GasPrice != nil && msg.GasPrice.Sign() > 0 {
		arg["gasPrice"] = fmt.Sprintf("0x%x", msg.GasPrice)
	}
	if msg.Value != nil && msg.Value.Sign() > 0 {
		arg["value"] = fmt.Sprintf("0x%x", msg.Value)
	}
	if len(msg.Data) > 0 {
		arg["data"] = fmt.Sprintf("0x%x", msg.Data)
	}

	return arg
}

// toFilterArg converts a FilterQuery to the RPC argument format.
func toFilterArg(q FilterQuery) any {
	arg := map[string]any{}

	if q.BlockHash != nil {
		arg["blockHash"] = q.BlockHash.Hex()
	} else {
		if q.FromBlock != nil {
			arg["fromBlock"] = toBlockNumArg(q.FromBlock)
		}
		if q.ToBlock != nil {
			arg["toBlock"] = toBlockNumArg(q.ToBlock)
		}
	}

	if len(q.Addresses) > 0 {
		addrs := make([]string, len(q.Addresses))
		for i, addr := range q.Addresses {
			addrs[i] = addr.Hex()
		}
		arg["address"] = addrs
	}

	if len(q.Topics) > 0 {
		topics := make([]any, len(q.Topics))
		for i, t := range q.Topics {
			if len(t) == 0 {
				topics[i] = nil
			} else if len(t) == 1 {
				topics[i] = t[0].Hex()
			} else {
				hashes := make([]string, len(t))
				for j, h := range t {
					hashes[j] = h.Hex()
				}
				topics[i] = hashes
			}
		}
		arg["topics"] = topics
	}

	return arg
}

// hexToUint64 converts a hex string to uint64.
func hexToUint64(hex string) (uint64, error) {
	var result uint64
	if len(hex) >= 2 && hex[:2] == "0x" {
		hex = hex[2:]
	}
	_, err := fmt.Sscanf(hex, "%x", &result)
	return result, err
}

// hexToBigInt converts a hex string to *big.Int.
func hexToBigInt(hex string) (*big.Int, error) {
	if len(hex) >= 2 && hex[:2] == "0x" {
		hex = hex[2:]
	}
	if hex == "" || hex == "0" {
		return new(big.Int), nil
	}
	result := new(big.Int)
	_, ok := result.SetString(hex, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex number: %s", hex)
	}
	return result, nil
}

// hexToBytes converts a hex string to bytes.
func hexToBytes(hex string) ([]byte, error) {
	if len(hex) >= 2 && hex[:2] == "0x" {
		hex = hex[2:]
	}
	if len(hex)%2 != 0 {
		hex = "0" + hex
	}
	result := make([]byte, len(hex)/2)
	for i := 0; i < len(result); i++ {
		_, err := fmt.Sscanf(hex[i*2:i*2+2], "%02x", &result[i])
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// rpcBlock represents a block in RPC response format.
type rpcBlock struct {
	Number           string   `json:"number"`
	Hash             string   `json:"hash"`
	ParentHash       string   `json:"parentHash"`
	Nonce            string   `json:"nonce"`
	Miner            string   `json:"miner"`
	Difficulty       string   `json:"difficulty"`
	TotalDifficulty  string   `json:"totalDifficulty"`
	ExtraData        string   `json:"extraData"`
	Size             string   `json:"size"`
	GasLimit         string   `json:"gasLimit"`
	GasUsed          string   `json:"gasUsed"`
	Timestamp        string   `json:"timestamp"`
	Transactions     []any    `json:"transactions"`
	Uncles           []string `json:"uncles"`
	StateRoot        string   `json:"stateRoot"`
	TransactionsRoot string   `json:"transactionsRoot"`
	ReceiptsRoot     string   `json:"receiptsRoot"`
	LogsBloom        string   `json:"logsBloom"`
}

// rpcTransaction represents a transaction in RPC response format.
type rpcTransaction struct {
	Hash             string `json:"hash"`
	Nonce            string `json:"nonce"`
	BlockHash        string `json:"blockHash"`
	BlockNumber      string `json:"blockNumber"`
	TransactionIndex string `json:"transactionIndex"`
	From             string `json:"from"`
	To               string `json:"to"`
	Value            string `json:"value"`
	GasPrice         string `json:"gasPrice"`
	Gas              string `json:"gas"`
	Input            string `json:"input"`
	V                string `json:"v"`
	R                string `json:"r"`
	S                string `json:"s"`
}

// rpcReceipt represents a receipt in RPC response format.
type rpcReceipt struct {
	TransactionHash   string   `json:"transactionHash"`
	TransactionIndex  string   `json:"transactionIndex"`
	BlockHash         string   `json:"blockHash"`
	BlockNumber       string   `json:"blockNumber"`
	From              string   `json:"from"`
	To                string   `json:"to"`
	CumulativeGasUsed string   `json:"cumulativeGasUsed"`
	GasUsed           string   `json:"gasUsed"`
	ContractAddress   string   `json:"contractAddress"`
	Logs              []rpcLog `json:"logs"`
	LogsBloom         string   `json:"logsBloom"`
	Status            string   `json:"status"`
	Type              string   `json:"type"`
}

// rpcLog represents a log in RPC response format.
type rpcLog struct {
	Address          string   `json:"address"`
	Topics           []string `json:"topics"`
	Data             string   `json:"data"`
	BlockNumber      string   `json:"blockNumber"`
	TransactionHash  string   `json:"transactionHash"`
	TransactionIndex string   `json:"transactionIndex"`
	BlockHash        string   `json:"blockHash"`
	LogIndex         string   `json:"logIndex"`
	Removed          bool     `json:"removed"`
}

// parseBlock converts an rpcBlock to a types.Block.
func parseBlock(rb *rpcBlock, fullTx bool) (*types.Block, error) {
	block := &types.Block{}

	// Parse number
	if rb.Number != "" {
		num, err := hexToBigInt(rb.Number)
		if err != nil {
			return nil, fmt.Errorf("invalid block number: %w", err)
		}
		block.Number = num
	}

	// Parse hashes
	block.Hash = common.HexToHash(rb.Hash)
	block.ParentHash = common.HexToHash(rb.ParentHash)
	block.StateRoot = common.HexToHash(rb.StateRoot)
	block.TransactionsRoot = common.HexToHash(rb.TransactionsRoot)
	block.ReceiptsRoot = common.HexToHash(rb.ReceiptsRoot)

	// Parse nonce
	if rb.Nonce != "" {
		nonce, err := hexToUint64(rb.Nonce)
		if err == nil {
			block.Nonce = nonce
		}
	}

	// Parse miner
	block.Miner = common.HexToAddress(rb.Miner)

	// Parse difficulty
	if rb.Difficulty != "" {
		diff, err := hexToBigInt(rb.Difficulty)
		if err == nil {
			block.Difficulty = diff
		}
	}

	// Parse total difficulty
	if rb.TotalDifficulty != "" {
		totalDiff, err := hexToBigInt(rb.TotalDifficulty)
		if err == nil {
			block.TotalDifficulty = totalDiff
		}
	}

	// Parse extra data
	if rb.ExtraData != "" {
		extraData, err := hexToBytes(rb.ExtraData)
		if err == nil {
			block.ExtraData = extraData
		}
	}

	// Parse size
	if rb.Size != "" {
		size, err := hexToUint64(rb.Size)
		if err == nil {
			block.Size = size
		}
	}

	// Parse gas limit
	if rb.GasLimit != "" {
		gasLimit, err := hexToUint64(rb.GasLimit)
		if err == nil {
			block.GasLimit = gasLimit
		}
	}

	// Parse gas used
	if rb.GasUsed != "" {
		gasUsed, err := hexToUint64(rb.GasUsed)
		if err == nil {
			block.GasUsed = gasUsed
		}
	}

	// Parse timestamp
	if rb.Timestamp != "" {
		timestamp, err := hexToUint64(rb.Timestamp)
		if err == nil {
			block.Timestamp = timestamp
		}
	}

	// Parse logs bloom
	if rb.LogsBloom != "" {
		logsBloom, err := hexToBytes(rb.LogsBloom)
		if err == nil {
			block.LogsBloom = logsBloom
		}
	}

	// Parse uncles
	if len(rb.Uncles) > 0 {
		block.Uncles = make([]common.Hash, len(rb.Uncles))
		for i, uncle := range rb.Uncles {
			block.Uncles[i] = common.HexToHash(uncle)
		}
	}

	// Parse transactions
	if fullTx && len(rb.Transactions) > 0 {
		block.Transactions = make([]*types.Transaction, 0, len(rb.Transactions))
		for _, txData := range rb.Transactions {
			// Try to parse as full transaction
			txBytes, err := json.Marshal(txData)
			if err != nil {
				continue
			}
			var rpcTx rpcTransaction
			if err := json.Unmarshal(txBytes, &rpcTx); err != nil {
				continue
			}
			tx, err := parseTransaction(&rpcTx)
			if err != nil {
				continue
			}
			block.Transactions = append(block.Transactions, tx)
		}
	}

	return block, nil
}

// parseTransaction converts an rpcTransaction to a types.Transaction.
func parseTransaction(rt *rpcTransaction) (*types.Transaction, error) {
	tx := &types.Transaction{}

	// Parse nonce
	if rt.Nonce != "" {
		nonce, err := hexToUint64(rt.Nonce)
		if err != nil {
			return nil, fmt.Errorf("invalid nonce: %w", err)
		}
		tx.Nonce = nonce
	}

	// Parse gas price
	if rt.GasPrice != "" {
		gasPrice, err := hexToBigInt(rt.GasPrice)
		if err != nil {
			return nil, fmt.Errorf("invalid gas price: %w", err)
		}
		tx.GasPrice = gasPrice
	}

	// Parse gas
	if rt.Gas != "" {
		gas, err := hexToUint64(rt.Gas)
		if err != nil {
			return nil, fmt.Errorf("invalid gas: %w", err)
		}
		tx.Gas = gas
	}

	// Parse to address
	if rt.To != "" {
		to := common.HexToAddress(rt.To)
		tx.To = &to
	}

	// Parse value
	if rt.Value != "" {
		value, err := hexToBigInt(rt.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid value: %w", err)
		}
		tx.Value = value
	}

	// Parse input data
	if rt.Input != "" {
		data, err := hexToBytes(rt.Input)
		if err != nil {
			return nil, fmt.Errorf("invalid input: %w", err)
		}
		tx.Data = data
	}

	// Parse signature
	if rt.V != "" {
		v, err := hexToBigInt(rt.V)
		if err == nil {
			tx.V = v
		}
	}
	if rt.R != "" {
		r, err := hexToBigInt(rt.R)
		if err == nil {
			tx.R = r
		}
	}
	if rt.S != "" {
		s, err := hexToBigInt(rt.S)
		if err == nil {
			tx.S = s
		}
	}

	return tx, nil
}

// parseReceipt converts an rpcReceipt to a types.Receipt.
func parseReceipt(rr *rpcReceipt) (*types.Receipt, error) {
	receipt := &types.Receipt{}

	// Parse transaction hash
	receipt.TxHash = common.HexToHash(rr.TransactionHash)

	// Parse transaction index
	if rr.TransactionIndex != "" {
		txIndex, err := hexToUint64(rr.TransactionIndex)
		if err == nil {
			receipt.TxIndex = uint(txIndex)
		}
	}

	// Parse block hash
	receipt.BlockHash = common.HexToHash(rr.BlockHash)

	// Parse block number
	if rr.BlockNumber != "" {
		blockNum, err := hexToBigInt(rr.BlockNumber)
		if err == nil {
			receipt.BlockNumber = blockNum
		}
	}

	// Parse from address
	receipt.From = common.HexToAddress(rr.From)

	// Parse to address
	if rr.To != "" {
		to := common.HexToAddress(rr.To)
		receipt.To = &to
	}

	// Parse cumulative gas used
	if rr.CumulativeGasUsed != "" {
		cumGas, err := hexToUint64(rr.CumulativeGasUsed)
		if err == nil {
			receipt.CumulativeGasUsed = cumGas
		}
	}

	// Parse gas used
	if rr.GasUsed != "" {
		gasUsed, err := hexToUint64(rr.GasUsed)
		if err == nil {
			receipt.GasUsed = gasUsed
		}
	}

	// Parse contract address
	if rr.ContractAddress != "" {
		contractAddr := common.HexToAddress(rr.ContractAddress)
		receipt.ContractAddress = &contractAddr
	}

	// Parse logs bloom
	if rr.LogsBloom != "" {
		logsBloom, err := hexToBytes(rr.LogsBloom)
		if err == nil {
			receipt.LogsBloom = logsBloom
		}
	}

	// Parse status
	if rr.Status != "" {
		status, err := hexToUint64(rr.Status)
		if err == nil {
			receipt.Status = status
		}
	}

	// Parse type
	if rr.Type != "" {
		txType, err := hexToUint64(rr.Type)
		if err == nil {
			receipt.Type = uint8(txType)
		}
	}

	// Parse logs
	if len(rr.Logs) > 0 {
		receipt.Logs = make([]*types.Log, len(rr.Logs))
		for i, rl := range rr.Logs {
			log, err := parseLog(&rl)
			if err != nil {
				return nil, fmt.Errorf("failed to parse log %d: %w", i, err)
			}
			receipt.Logs[i] = log
		}
	}

	return receipt, nil
}

// parseLog converts an rpcLog to a types.Log.
func parseLog(rl *rpcLog) (*types.Log, error) {
	log := &types.Log{}

	// Parse address
	log.Address = common.HexToAddress(rl.Address)

	// Parse topics
	if len(rl.Topics) > 0 {
		log.Topics = make([]common.Hash, len(rl.Topics))
		for i, topic := range rl.Topics {
			log.Topics[i] = common.HexToHash(topic)
		}
	}

	// Parse data
	if rl.Data != "" {
		data, err := hexToBytes(rl.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid log data: %w", err)
		}
		log.Data = data
	}

	// Parse block number
	if rl.BlockNumber != "" {
		blockNum, err := hexToUint64(rl.BlockNumber)
		if err == nil {
			log.BlockNumber = blockNum
		}
	}

	// Parse transaction hash
	log.TxHash = common.HexToHash(rl.TransactionHash)

	// Parse transaction index
	if rl.TransactionIndex != "" {
		txIndex, err := hexToUint64(rl.TransactionIndex)
		if err == nil {
			log.TxIndex = uint(txIndex)
		}
	}

	// Parse block hash
	log.BlockHash = common.HexToHash(rl.BlockHash)

	// Parse log index
	if rl.LogIndex != "" {
		logIndex, err := hexToUint64(rl.LogIndex)
		if err == nil {
			log.Index = uint(logIndex)
		}
	}

	// Parse removed
	log.Removed = rl.Removed

	return log, nil
}
