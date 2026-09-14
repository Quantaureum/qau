// Quantaureum Node source, version 1.0.0.
// Package rpc provides advanced RPC methods for block, transaction, and filter operations
package rpc

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

// Filter types
const (
	FilterTypeLog                = "log"
	FilterTypeBlock              = "block"
	FilterTypePendingTransaction = "pendingTransaction"

	// R7-M8 FIX: cap on total live filters to bound memory use against
	// filter-spam DoS. Matches geth's per-connection subscription model.
	maxFiltersTotal = 100 // L14-011: lowered from 10000 to 100 to prevent memory-exhaustion DoS

	// AUDIT (2026) API-04 FIX: per-client filter limit. Previously, the
	// global pool of 100 filters had no per-client scoping — a single client
	// could create 100 filters and starve all other clients. This limit
	// matches MaxSubscriptionsPerConn for WebSocket subscriptions.
	maxFiltersPerClient = 10

	// RP-05 FIX: maximum number of logs eth_getLogs / eth_getFilterLogs may
	// return. A wide block range combined with log-heavy contracts can produce
	// a huge number of entries and exhaust memory. Return an error when the
	// accumulated result count exceeds this cap so callers narrow their filter.
	maxLogsResult = 10000
)

// LogFilter represents a log filter
type LogFilter struct {
	FromBlock string `json:"fromBlock,omitempty"`
	ToBlock   string `json:"toBlock,omitempty"`
	Address   any    `json:"address,omitempty"` // string or []string
	Topics    []any  `json:"topics,omitempty"`  // []string or [][]string
}

// Log represents an event log
type Log struct {
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

// FilterManager manages active filters
// audit-fix R3-M3: added stopCh for graceful shutdown of cleanup goroutine.
type FilterManager struct {
	mu          sync.RWMutex
	filters     map[string]*activeFilter
	blockReader BlockReader
	stopCh      chan struct{}
	stopOnce    sync.Once
}

type activeFilter struct {
	id         string
	filterType string
	created    time.Time
	lastPolled time.Time
	logFilter  *LogFilter
	lastBlock  uint64
	clientID   string // AUDIT (2026) API-04: per-client ownership tracking
	// pendingLogs, pendingTxs, pendingBlocks removed (unused — golangci-lint unused)
}

// Global filter manager (initialized per API instance)
// audit-fix R3-M3: replaced package-global sync.Once with explicit
// constructor and Stop() for proper lifecycle management.
var globalFilterManager *FilterManager
var filterManagerMu sync.Mutex

func getFilterManager(blockReader BlockReader) *FilterManager {
	filterManagerMu.Lock()
	defer filterManagerMu.Unlock()
	if globalFilterManager == nil {
		globalFilterManager = newFilterManager(blockReader)
	}
	return globalFilterManager
}

// StopGlobalFilterManager stops the global filter manager's cleanup goroutine.
// audit-fix R5-L1: must be called during shutdown to prevent goroutine leak.
func StopGlobalFilterManager() {
	filterManagerMu.Lock()
	defer filterManagerMu.Unlock()
	if globalFilterManager != nil {
		globalFilterManager.Stop()
		globalFilterManager = nil
	}
}

// newFilterManager creates a FilterManager and starts its cleanup goroutine.
func newFilterManager(blockReader BlockReader) *FilterManager {
	fm := &FilterManager{
		filters:     make(map[string]*activeFilter),
		blockReader: blockReader,
		stopCh:      make(chan struct{}),
	}
	go fm.cleanupLoop()
	return fm
}

// Stop stops the cleanup goroutine. Safe to call multiple times.
func (fm *FilterManager) Stop() {
	fm.stopOnce.Do(func() {
		close(fm.stopCh)
	})
}

func (fm *FilterManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-fm.stopCh:
			return
		case <-ticker.C:
			fm.cleanup()
		}
	}
}

func (fm *FilterManager) cleanup() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	now := time.Now()
	for id, f := range fm.filters {
		// Remove filters not polled for 5 minutes
		if now.Sub(f.lastPolled) > 5*time.Minute {
			delete(fm.filters, id)
		}
	}
}

// newFilterID generates a cryptographically random filter ID.
// audit-fix WS-L1: replaced predictable atomic counter with crypto/rand
// to prevent attackers from enumerating and probing other users' filters.
func (fm *FilterManager) newFilterID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(cryptorand.Reader, b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	return "0x" + hex.EncodeToString(b), nil
}

// addFilter creates a new filter owned by clientID.
// AUDIT (2026) API-04 FIX: Added per-client filter limit to prevent a
// single client from exhausting the global filter pool.
func (fm *FilterManager) addFilter(filterType string, logFilter *LogFilter, clientID string) (string, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// R7-M8 FIX: cap total live filters to prevent memory-exhaustion DoS via
	// repeated eth_newFilter / eth_newBlockFilter / eth_newPendingTransactionFilter
	// calls within the 5-minute cleanup window.
	if len(fm.filters) >= maxFiltersTotal {
		return "", fmt.Errorf("filter limit reached (%d); uninstall stale filters or wait for cleanup", maxFiltersTotal)
	}

	// AUDIT (2026) API-04 FIX: enforce per-client filter limit.
	// Count existing filters owned by this client.
	clientCount := 0
	for _, f := range fm.filters {
		if f.clientID == clientID {
			clientCount++
		}
	}
	if clientCount >= maxFiltersPerClient {
		return "", fmt.Errorf("per-client filter limit reached (%d); uninstall stale filters before creating new ones", maxFiltersPerClient)
	}

	id, err := fm.newFilterID()
	if err != nil {
		return "", err
	}
	var lastBlock uint64
	if fm.blockReader != nil {
		lastBlock = fm.blockReader.GetLatestHeight()
	}

	fm.filters[id] = &activeFilter{
		id:         id,
		filterType: filterType,
		created:    time.Now(),
		lastPolled: time.Now(),
		logFilter:  logFilter,
		lastBlock:  lastBlock,
		clientID:   clientID,
	}
	return id, nil
}

func (fm *FilterManager) getFilter(id string) *activeFilter {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return fm.filters[id]
}

// removeFilter removes a filter, verifying that the caller (clientID) owns it.
// AUDIT (2026) API-04 FIX: Added ownership check to prevent a client from
// uninstalling another client's filters.
func (fm *FilterManager) removeFilter(id string, clientID string) bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	f, ok := fm.filters[id]
	if !ok {
		return false
	}
	// Ownership check: only the creator can uninstall. An empty clientID on
	// the filter (legacy/unknown origin) allows removal for backward compat.
	if f.clientID != "" && f.clientID != clientID {
		return false
	}
	delete(fm.filters, id)
	return true
}

// GetBlockTransactionCountByHash returns the number of transactions in a block by hash
func (api *API) GetBlockTransactionCountByHash(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	hash, err := parseHash(args[0])
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid hash")
	}

	if api.blockReader == nil {
		return "0x0", nil
	}

	block, err := api.blockReader.GetBlockByHash(hash)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, "block not found")
	}

	// Extract transaction count from block response
	if blockResp, ok := block.(*BlockResponse); ok {
		return formatHexUint64(uint64(len(blockResp.Transactions))), nil
	}

	return "0x0", nil
}

// GetBlockTransactionCountByNumber returns the number of transactions in a block by number
func (api *API) GetBlockTransactionCountByNumber(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	height, err := parseBlockNumber(args[0], api.blockReader)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid block number")
	}

	if api.blockReader == nil {
		return "0x0", nil
	}

	block, err := api.blockReader.GetBlockByHeight(height)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, "block not found")
	}

	if blockResp, ok := block.(*BlockResponse); ok {
		return formatHexUint64(uint64(len(blockResp.Transactions))), nil
	}

	return "0x0", nil
}

// GetTransactionByBlockHashAndIndex returns a transaction by block hash and index
func (api *API) GetTransactionByBlockHashAndIndex(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	hash, err := parseHash(args[0])
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid hash")
	}

	index, err := parseHexToUint64(args[1])
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid index")
	}

	if api.blockReader == nil {
		return nil, NewError(ErrCodeNotFound, "transaction not found")
	}

	block, err := api.blockReader.GetBlockByHash(hash)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, "block not found")
	}

	if blockResp, ok := block.(*BlockResponse); ok {
		if int(index) < len(blockResp.Transactions) { //nolint:gosec,G115
			return blockResp.Transactions[index], nil
		}
	}

	return nil, nil // Return null for non-existent index (Ethereum standard)
}

// GetTransactionByBlockNumberAndIndex returns a transaction by block number and index
func (api *API) GetTransactionByBlockNumberAndIndex(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	height, err := parseBlockNumber(args[0], api.blockReader)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid block number")
	}

	index, err := parseHexToUint64(args[1])
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid index")
	}

	if api.blockReader == nil {
		return nil, NewError(ErrCodeNotFound, "transaction not found")
	}

	block, err := api.blockReader.GetBlockByHeight(height)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, "block not found")
	}

	if blockResp, ok := block.(*BlockResponse); ok {
		if int(index) < len(blockResp.Transactions) { //nolint:gosec,G115
			return blockResp.Transactions[index], nil
		}
	}

	return nil, nil // Return null for non-existent index (Ethereum standard)
}

// Call executes a contract call without creating a transaction
func (api *API) Call(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	callArgs, ok := args[0].(map[string]any)
	if !ok {
		return nil, ErrInvalidParams
	}

	// Parse from address (optional)
	var from types.Address
	if fromStr, ok := callArgs["from"].(string); ok && fromStr != "" {
		parsedFrom, err := parseAddress(fromStr)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid from address")
		}
		from = parsedFrom
	}

	// Parse to address (required for calls)
	toStr, _ := callArgs["to"].(string)
	// R7-M7 FIX: removed log.Printf("[eth_call] toStr=%q", toStr). It logged
	// user-controlled input on every eth_call, enabling log-flooding DoS and
	// potential log-injection. Address validation happens in parseAddress below.
	if toStr == "" {
		// Contract creation - not supported in eth_call, return 0x
		return "0x", nil
	}

	to, err := parseAddress(toStr)
	if err != nil {
		return nil, NewError(ErrCodeInvalidParams, "invalid to address")
	}

	// Parse value (optional)
	value := big.NewInt(0)
	if valueStr, ok := callArgs["value"].(string); ok && valueStr != "" {
		value = new(big.Int)
		valueStr = stripHexPrefix(valueStr)
		if _, ok := value.SetString(valueStr, 16); !ok {
			// Try decimal
			if _, ok := value.SetString(valueStr, 10); !ok {
				return nil, NewError(ErrCodeInvalidParams, "invalid value")
			}
		}
	}

	// Parse data (optional)
	var data []byte
	if dataStr, ok := callArgs["data"].(string); ok && dataStr != "" {
		data, err = parseHexBytes(dataStr)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid data")
		}
	}

	// audit-fix P5-L6: Cap calldata size to prevent DoS via oversized input.
	// Without this, an attacker can send megabytes of calldata that the QVM
	// must process, consuming CPU and memory.
	const maxCallDataSize = 1 << 20 // 1 MB
	if len(data) > maxCallDataSize {
		return nil, NewError(ErrCodeInvalidParams, fmt.Sprintf("call data too large: %d bytes exceeds %d limit", len(data), maxCallDataSize))
	}

	// Check if address has code
	if api.stateReader != nil {
		code := api.stateReader.GetCode(to)
		if len(code) == 0 {
			// Not a contract, return empty
			return "0x", nil
		}
	}

	// Execute contract call if caller is available
	if api.contractCaller != nil {
		// audit-fix P5-L6: Set default gas limit for eth_call to prevent
		// unbounded computation. Users can override via the "gas" param,
		// but it is capped at maxCallGas.
		const maxCallGas uint64 = 50_000_000 // 50M gas
		defaultCallGas := uint64(10_000_000) // 10M gas default
		gasLimit := defaultCallGas
		if gasStr, ok := callArgs["gas"].(string); ok {
			if g, err := parseHexToUint64(gasStr); err == nil && g > 0 {
				gasLimit = g
			}
		}
		if gasLimit > maxCallGas {
			gasLimit = maxCallGas
		}

		req := &ContractCallRequest{
			From:  from,
			To:    to,
			Value: value,
			Data:  data,
			Gas:   gasLimit,
		}

		result, err := api.contractCaller.Call(req)
		if err != nil {
			return nil, NewError(ErrCodeInternal, fmt.Sprintf("contract call failed: %v", err))
		}

		if result.Error != nil {
			// Return 0x on error (Ethereum semantics)
			return "0x", nil
		}

		return formatHexBytes(result.ReturnData), nil
	}

	// Contract caller not available - return error
	return nil, NewError(ErrCodeInternal, "contract call not supported: QVM not available")
}

// clientIDFromContext extracts a client identifier from the request context.
// Uses API key when available (authenticated), falls back to client IP.
// AUDIT (2026) API-04 FIX: Used for per-client filter scoping.
func clientIDFromContext(ctx context.Context) string {
	if apiKey, ok := ctx.Value(contextKeyAPIKey{}).(string); ok && apiKey != "" {
		return "key:" + apiKey
	}
	if ip, ok := ctx.Value(contextKeyClientIP{}).(string); ok && ip != "" {
		return "ip:" + ip
	}
	return "unknown"
}

// NewFilter creates a new log filter
func (api *API) NewFilter(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []LogFilter
	if err := json.Unmarshal(params, &args); err != nil {
		// Try single object
		var filter LogFilter
		if err := json.Unmarshal(params, &filter); err != nil {
			return nil, ErrInvalidParams
		}
		args = []LogFilter{filter}
	}

	if len(args) < 1 {
		return nil, ErrInvalidParams
	}

	fm := getFilterManager(api.blockReader)
	filterID, err := fm.addFilter(FilterTypeLog, &args[0], clientIDFromContext(ctx))
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	return filterID, nil
}

// NewBlockFilter creates a new block filter
func (api *API) NewBlockFilter(ctx context.Context, params json.RawMessage) (any, *Error) {
	fm := getFilterManager(api.blockReader)
	filterID, err := fm.addFilter(FilterTypeBlock, nil, clientIDFromContext(ctx))
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}
	return filterID, nil
}

// NewPendingTransactionFilter creates a new pending transaction filter
func (api *API) NewPendingTransactionFilter(ctx context.Context, params json.RawMessage) (any, *Error) {
	fm := getFilterManager(api.blockReader)
	filterID, err := fm.addFilter(FilterTypePendingTransaction, nil, clientIDFromContext(ctx))
	if err != nil {
		return nil, NewError(ErrCodeInternal, fmt.Sprintf("failed to add filter: %v", err))
	}
	return filterID, nil
}

// UninstallFilter removes a filter
func (api *API) UninstallFilter(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	fm := getFilterManager(api.blockReader)
	return fm.removeFilter(args[0], clientIDFromContext(ctx)), nil
}

// GetFilterChanges returns changes since last poll
func (api *API) GetFilterChanges(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	fm := getFilterManager(api.blockReader)
	// FIX: check filter existence and update lastPolled under a single
	// Lock to prevent TOCTOU race with cleanup goroutine deleting the filter.
	fm.mu.Lock()
	filter, filterExists := fm.filters[args[0]]
	if !filterExists {
		fm.mu.Unlock()
		return nil, NewError(ErrCodeNotFound, "filter not found")
	}
	filter.lastPolled = time.Now()
	fm.mu.Unlock()

	switch filter.filterType {
	case FilterTypeBlock:
		// Return new block hashes since last poll
		return api.getNewBlockHashes(filter)
	case FilterTypePendingTransaction:
		// Return new pending transaction hashes
		return api.getNewPendingTxHashes(filter)
	case FilterTypeLog:
		// Return new logs matching filter
		return api.getNewLogs(filter)
	}

	return []any{}, nil
}

// audit-fix R3-M1: maxFilterBlockRange caps per-poll block scan to prevent DoS
// via stale filters that haven't been polled for a long time.
const maxFilterBlockRange = 1024

func (api *API) getNewBlockHashes(filter *activeFilter) (any, *Error) {
	if api.blockReader == nil {
		return []string{}, nil
	}

	currentHeight := api.blockReader.GetLatestHeight()
	if currentHeight <= filter.lastBlock {
		return []string{}, nil
	}

	// audit-fix R3-M1: cap scan range to prevent DoS from stale filters
	fromHeight := filter.lastBlock + 1
	if currentHeight-fromHeight >= maxFilterBlockRange {
		fromHeight = currentHeight - maxFilterBlockRange + 1
	}

	hashes := make([]string, 0)
	for h := fromHeight; h <= currentHeight; h++ {
		block, err := api.blockReader.GetBlockByHeight(h)
		if err != nil {
			continue
		}
		// MEDIUFIX: Use *BlockResponse type assertion instead of
		// map[string]any. The production BlockReader implementation
		// (blockReaderAdapter.GetBlockByHeight) returns *BlockResponse via
		// rpc.FormatBlock(), not a map. The previous map type assertion
		// always failed, causing eth_getFilterChanges block filters to
		// silently return empty results.
		if blockResp, ok := block.(*BlockResponse); ok {
			if blockResp.Hash != "" {
				hashes = append(hashes, blockResp.Hash)
			}
		} else if blockMap, ok := block.(map[string]any); ok {
			// Fallback for test mocks that return map[string]any
			if hash, ok := blockMap["hash"].(string); ok {
				hashes = append(hashes, hash)
			}
		}
	}

	// R36-P3-17 FIX (2026-07-30): Acquire the FilterManager lock before
	// writing filter.lastBlock. The filter pointer was fetched under the
	// manager's Lock at GetFilterChanges line 562-569, but released before
	// this function runs. Two concurrent GetFilterChanges calls for the
	// same filterID would both read+write filter.lastBlock without
	// synchronization — a data race the race detector would flag. The
	// manager's mu protects the filters map AND (by convention) the
	// per-filter mutable fields like lastBlock and lastPolled. Re-acquire
	// the Lock here for the write.
	fm := getFilterManager(api.blockReader)
	fm.mu.Lock()
	filter.lastBlock = currentHeight
	fm.mu.Unlock()
	return hashes, nil
}

func (api *API) getNewPendingTxHashes(filter *activeFilter) (any, *Error) {
	if api.txPool == nil {
		return []string{}, nil
	}

	// Get current pending transactions
	pending := api.txPool.GetPendingTransactions()
	hashes := make([]string, 0, len(pending))
	for _, tx := range pending {
		if txMap, ok := tx.(map[string]any); ok {
			if hash, ok := txMap["hash"].(string); ok {
				hashes = append(hashes, hash)
			}
		}
	}

	return hashes, nil
}

func (api *API) getNewLogs(filter *activeFilter) (any, *Error) {
	// LOW-6 FIX: Document why this returns an empty slice.
	// TODO(security/rpc-compat): eth_getFilterChanges for log filters should
	// return only the logs generated SINCE the last poll. The current
	// implementation always returns an empty slice, which means clients using
	// polling-based log subscriptions will silently miss every event.
	//
	// A correct implementation requires:
	//   1. A log store that indexes logs by block number (so we can query
	//      "logs in blocks (filter.lastPollBlock, currentBlock]").
	//   2. Storing lastPollBlock on the activeFilter and updating it after
	//      each poll.
	//   3. Applying filter.logFilter (address + topics) to the retrieved logs.
	//
	// Until the log store is available, callers must use eth_getLogs with an
	// explicit block range, or subscribe to logs via websocket newHeads +
	// eth_getLogs per block. Returning an empty slice (rather than an error)
	// preserves backward compatibility with existing clients.
	return []Log{}, nil
}

// GetFilterLogs returns all logs for a filter
func (api *API) GetFilterLogs(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	fm := getFilterManager(api.blockReader)
	filter := fm.getFilter(args[0])
	if filter == nil {
		return nil, NewError(ErrCodeNotFound, "filter not found")
	}

	if filter.filterType != FilterTypeLog {
		return nil, NewError(ErrCodeInvalidParams, "not a log filter")
	}

	// Return logs matching filter criteria
	return api.getLogs(filter.logFilter)
}

// GetLogs returns logs matching filter criteria
func (api *API) GetLogs(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []LogFilter
	if err := json.Unmarshal(params, &args); err != nil {
		var filter LogFilter
		if err := json.Unmarshal(params, &filter); err != nil {
			return nil, ErrInvalidParams
		}
		args = []LogFilter{filter}
	}

	if len(args) < 1 {
		return []Log{}, nil
	}

	return api.getLogs(&args[0])
}

func (api *API) getLogs(filter *LogFilter) (any, *Error) {
	// Parse block range
	var fromBlock, toBlock uint64

	if filter.FromBlock == "" || filter.FromBlock == "latest" {
		if api.blockReader != nil {
			fromBlock = api.blockReader.GetLatestHeight()
		}
	} else if filter.FromBlock == "earliest" {
		fromBlock = 0
	} else {
		var err error
		fromBlock, err = parseHexToUint64(filter.FromBlock)
		if err != nil {
			fromBlock = 0
		}
	}

	if filter.ToBlock == "" || filter.ToBlock == "latest" {
		if api.blockReader != nil {
			toBlock = api.blockReader.GetLatestHeight()
		}
	} else if filter.ToBlock == "earliest" {
		toBlock = 0
	} else {
		var err error
		toBlock, err = parseHexToUint64(filter.ToBlock)
		if err != nil {
			toBlock = fromBlock
		}
	}

	// audit-fix R3-L1: explicit guard for fromBlock > toBlock before unsigned
	// subtraction, which would wrap to ^uint64(0) and mask logic errors.
	// Also limit range to prevent DoS
	if fromBlock > toBlock {
		toBlock = fromBlock
	} else if toBlock-fromBlock > 1000 {
		toBlock = fromBlock + 1000
	}

	if api.blockReader == nil {
		return []Log{}, nil
	}

	// Collect addresses to filter
	addresses := make([]string, 0)
	if filter.Address != nil {
		switch addr := filter.Address.(type) {
		case string:
			if addr != "" {
				addresses = append(addresses, addr)
			}
		case []any:
			for _, a := range addr {
				if s, ok := a.(string); ok {
					addresses = append(addresses, s)
				}
			}
		}
	}

	// Collect topic filters
	topicFilters := make([][]string, 0)
	if len(filter.Topics) > 0 {
		for _, t := range filter.Topics {
			topicFilter := make([]string, 0)
			switch tv := t.(type) {
			case string:
				if tv != "" {
					topicFilter = append(topicFilter, tv)
				}
			case []any:
				for _, ti := range tv {
					if s, ok := ti.(string); ok {
						topicFilter = append(topicFilter, s)
					}
				}
			}
			topicFilters = append(topicFilters, topicFilter)
		}
	}

	var logs []Log
	logIndex := uint64(0)

	// Iterate through blocks and collect logs
	for height := fromBlock; height <= toBlock; height++ {
		block, err := api.blockReader.GetBlockByHeight(height)
		if err != nil {
			continue
		}

		// R36-P2-RPC-02 FIX: Use *BlockResponse type assertion (production
		// path) with a map[string]any fallback (test mocks). The production
		// blockReaderAdapter.GetBlockByHeight returns *BlockResponse via
		// rpc.FormatBlock(), not a map — the previous map-only assertion
		// always failed in production, causing eth_getLogs / eth_getFilterLogs
		// to silently return empty arrays. Same fix as getNewBlockHashes
		// (advanced.go:618-627).
		var blockHash string
		var txs []any
		if blockResp, ok := block.(*BlockResponse); ok {
			blockHash = blockResp.Hash
			txs = blockResp.Transactions
		} else if blockMap, ok := block.(map[string]any); ok {
			blockHash, _ = blockMap["hash"].(string)
			txs, _ = blockMap["transactions"].([]any)
		} else {
			continue
		}
		blockNumber := formatHexUint64(height)

		if txs == nil {
			continue
		}

		for txIndex, tx := range txs {
			var txHash string
			switch t := tx.(type) {
			case string:
				txHash = t
			case map[string]any:
				if h, ok := t["hash"].(string); ok {
					txHash = h
				}
			}

			if txHash == "" {
				continue
			}

			// Get receipt for transaction
			hash, err := parseHash(txHash)
			if err != nil {
				continue
			}

			receipt, err := api.blockReader.GetTransactionReceipt(hash)
			if err != nil || receipt == nil {
				continue
			}

			receiptMap, ok := receipt.(map[string]any)
			if !ok {
				continue
			}

			// Extract logs from receipt
			receiptLogs, ok := receiptMap["logs"].([]any)
			if !ok {
				continue
			}

			for _, rlog := range receiptLogs {
				logMap, ok := rlog.(map[string]any)
				if !ok {
					continue
				}

				// Extract log data
				addr, _ := logMap["address"].(string)
				logData, _ := logMap["data"].(string)
				removed, _ := logMap["removed"].(bool)

				// Filter by address
				if len(addresses) > 0 {
					found := false
					for _, a := range addresses {
						if strings.EqualFold(a, addr) {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}

				// Extract topics
				topicsRaw, _ := logMap["topics"].([]any)
				topics := make([]string, 0, len(topicsRaw))
				for _, t := range topicsRaw {
					if s, ok := t.(string); ok {
						topics = append(topics, s)
					}
				}

				// Filter by topics
				if len(topicFilters) > 0 {
					if !matchesTopicFilters(topics, topicFilters) {
						continue
					}
				}

				// Create log entry
				log := Log{
					Address:          addr,
					Topics:           topics,
					Data:             logData,
					BlockNumber:      blockNumber,
					TransactionHash:  txHash,
					TransactionIndex: formatHexUint64(uint64(txIndex)), //nolint:gosec,G115
					BlockHash:        blockHash,
					LogIndex:         formatHexUint64(logIndex),
					Removed:          removed,
				}
				logs = append(logs, log)
				logIndex++
				// RP-05 FIX: bound the result set to prevent memory exhaustion from
				// log-heavy contracts over a wide block range. Return an error so
				// the caller knows to narrow the filter (block range / address /
				// topics) rather than silently truncating.
				if len(logs) > maxLogsResult {
					return nil, NewError(ErrCodeInvalidParams,
						fmt.Sprintf("log result size exceeds maximum of %d; narrow your block range or filter criteria", maxLogsResult))
				}
			}
		}
	}

	if logs == nil {
		return []Log{}, nil
	}
	return logs, nil
}

// matchesTopicFilters checks if topics match the given topic filters.
// Each filter can be nil (match any) or a specific value.
func matchesTopicFilters(topics []string, filters [][]string) bool {
	for i, filter := range filters {
		if len(filter) == 0 {
			// Empty filter matches anything
			continue
		}
		if i >= len(topics) {
			return false
		}
		found := false
		for _, f := range filter {
			if topics[i] == f {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Helper function
func parseHexToUint64(s string) (uint64, error) {
	s = stripHexPrefix(s)
	if s == "" {
		return 0, nil
	}
	// L-4 FIX: use strconv.ParseUint instead of fmt.Sscanf for portability
	// fmt.Sscanf with %x can overflow on 32-bit systems
	val, err := strconv.ParseUint(s, 16, 64)
	return val, err
}
