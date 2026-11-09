// Quantaureum Node source, version 1.0.0.
// Package rpc provides advanced RPC methods for block, transaction, and filter operations
package rpc

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qvm"
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

	// pollMu serializes polling of this filter and protects lastBlock /
	// lastPendingNonce-type cursors. Without it, two concurrent
	// eth_getFilterChanges calls for the same filter could both read the
	// same cursor, scan the same range, and advance it independently
	// (data race + duplicated / skipped results). The manager's mu only
	// guards the filters map, not per-filter mutable state.
	pollMu sync.Mutex

	// pendingSeen is the set of pending-transaction hashes already reported
	// by this filter. eth_getFilterChanges must be incremental: returning the
	// whole pool on every poll re-delivers transactions the caller has already
	// handled. It is seeded from the pool contents at filter creation so the
	// first poll only reports transactions that arrived afterwards.
	pendingSeen map[string]struct{}

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

// addFilter creates a filter owned by clientID.
// AUDIT (2026) API-04 FIX: Added per-client filter limit to prevent a
// single client from exhausting the global filter pool.
// pendingBaseline carries the pending-tx hashes already in the pool when a
// pending-transaction filter is created (nil for other filter types) so the
// filter reports only later arrivals.
func (fm *FilterManager) addFilter(filterType string, logFilter *LogFilter, clientID string, pendingBaseline []string) (string, error) {
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

	var pendingSeen map[string]struct{}
	if filterType == FilterTypePendingTransaction {
		pendingSeen = make(map[string]struct{}, len(pendingBaseline))
		for _, h := range pendingBaseline {
			pendingSeen[h] = struct{}{}
		}
	}

	fm.filters[id] = &activeFilter{
		id:          id,
		filterType:  filterType,
		created:     time.Now(),
		lastPolled:  time.Now(),
		logFilter:   logFilter,
		lastBlock:   lastBlock,
		clientID:    clientID,
		pendingSeen: pendingSeen,
	}
	return id, nil
}

// getFilter returns the filter if it exists and is visible to clientID.
// AUDIT (2026) FIX: read paths used to skip the ownership check that
// removeFilter enforced, so any client that obtained a filter ID could poll
// it and advance its cursor. Read access now follows the same rule as
// uninstall: the creator sees the filter; filters created without a client
// identity (legacy/unknown origin) stay readable for backward compatibility.
func (fm *FilterManager) getFilter(id string, clientID string) *activeFilter {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	f, ok := fm.filters[id]
	if !ok {
		return nil
	}
	if f.clientID != "" && f.clientID != clientID {
		return nil
	}
	return f
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
		// This node cannot simulate contract deployment in eth_call. Returning
		// "0x" would look like a successful call that returned no data.
		return nil, NewError(ErrCodeExecution,
			"eth_call for contract creation is not supported: deployment simulation is unavailable")
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
			return nil, NewError(ErrCodeExecution, fmt.Sprintf("contract call failed: %v", err))
		}

		if result == nil {
			return nil, NewError(ErrCodeExecution, "contract call returned no result")
		}

		if result.Error != nil {
			// AUDIT FIX: a revert / execution failure must not be reported as a
			// successful call with empty return data.
			return nil, executionRPCError(result)
		}

		return formatHexBytes(result.ReturnData), nil
	}

	// Contract caller not available - return error
	return nil, NewError(ErrCodeExecution, "contract call not supported: QVM not available")
}

// executionRPCError converts a failed contract simulation into a JSON-RPC
// error instead of reporting it as a successful call with empty return data.
// Reverts keep their revert payload in Error.Data (code 3); every other
// execution failure is reported as a user-facing -32000 execution error.
func executionRPCError(result *ContractCallResult) *Error {
	if errors.Is(result.Error, qvm.ErrExecutionReverted) {
		return NewErrorWithData(ErrCodeExecutionReverted, "execution reverted",
			formatHexBytes(result.ReturnData))
	}
	return NewError(ErrCodeExecution,
		fmt.Sprintf("contract execution failed: %v", result.Error))
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
	filterID, err := fm.addFilter(FilterTypeLog, &args[0], clientIDFromContext(ctx), nil)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	return filterID, nil
}

// NewBlockFilter creates a new block filter
func (api *API) NewBlockFilter(ctx context.Context, params json.RawMessage) (any, *Error) {
	fm := getFilterManager(api.blockReader)
	filterID, err := fm.addFilter(FilterTypeBlock, nil, clientIDFromContext(ctx), nil)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}
	return filterID, nil
}

// NewPendingTransactionFilter creates a new pending transaction filter
func (api *API) NewPendingTransactionFilter(ctx context.Context, params json.RawMessage) (any, *Error) {
	var baseline []string
	if api.txPool != nil {
		baseline = pendingTxHashes(api.txPool.GetPendingTransactions())
	}
	fm := getFilterManager(api.blockReader)
	filterID, err := fm.addFilter(FilterTypePendingTransaction, nil, clientIDFromContext(ctx), baseline)
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
	clientID := clientIDFromContext(ctx)
	fm.mu.Lock()
	filter, filterExists := fm.filters[args[0]]
	if !filterExists || (filter.clientID != "" && filter.clientID != clientID) {
		fm.mu.Unlock()
		// Same answer for "does not exist" and "belongs to another client":
		// a foreign client must not be able to probe which IDs are live.
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

// getNewBlockHashes returns the hashes of blocks after the filter's cursor and
// advances the cursor to the last block actually scanned.
//
// AUDIT (2026) FIX:
//   - Reading filter.lastBlock, scanning, and advancing it now happen under the
//     per-filter pollMu (previously the cursor was read without any lock and
//     written under the manager lock, so two concurrent polls raced).
//   - The scan is capped at maxFilterBlockRange blocks PER POLL and the cursor
//     advances only to the last scanned block. The old code jumped straight to
//     head-minus-1024, permanently dropping everything in between.
//   - A block read failure returns an error and leaves the cursor untouched,
//     so the range is retried on the next poll instead of being skipped.
func (api *API) getNewBlockHashes(filter *activeFilter) (any, *Error) {
	if api.blockReader == nil {
		// No silent empty result: the node cannot serve this filter type.
		return nil, NewError(ErrCodeInternal,
			"block filters are not supported: block reader unavailable")
	}

	filter.pollMu.Lock()
	defer filter.pollMu.Unlock()

	latest := api.blockReader.GetLatestHeight()
	if latest < filter.lastBlock {
		// Chain rewound below the cursor (rollback / resync); resume at head.
		filter.lastBlock = latest
	}
	fromHeight := filter.lastBlock + 1
	if fromHeight > latest {
		return []string{}, nil
	}

	toHeight := fromHeight + maxFilterBlockRange - 1
	if toHeight > latest {
		toHeight = latest
	}

	hashes := make([]string, 0, toHeight-fromHeight+1)
	for h := fromHeight; h <= toHeight; h++ {
		block, err := api.blockReader.GetBlockByHeight(h)
		if err != nil {
			// Cursor intentionally not advanced; the batch is retried.
			return nil, NewError(ErrCodeInternal,
				fmt.Sprintf("failed to read block %d for block filter: %v", h, err))
		}
		// Use *BlockResponse type assertion instead of map[string]any. The
		// production BlockReader implementation returns *BlockResponse via
		// rpc.FormatBlock(), not a map.
		var hash string
		if blockResp, ok := block.(*BlockResponse); ok {
			hash = blockResp.Hash
		} else if blockMap, ok := block.(map[string]any); ok {
			// Fallback for test mocks that return map[string]any
			hash, _ = blockMap["hash"].(string)
		}
		if hash == "" {
			// A block without a hash cannot be reported, and skipping it
			// while advancing the cursor would lose it silently.
			return nil, NewError(ErrCodeInternal,
				fmt.Sprintf("block %d has no hash; refusing to skip it", h))
		}
		hashes = append(hashes, hash)
	}

	filter.lastBlock = toHeight
	return hashes, nil
}

// getNewPendingTxHashes returns the pending-transaction hashes that entered
// the pool since the previous poll, and rebases the filter's seen-set.
//
// AUDIT (2026) API-04-adjacent FIX: the previous implementation only accepted
// map[string]any elements, but the production adapter (txPoolAdapter
// .GetPendingTransactions in node/adapters.go) returns *encoding.Transaction,
// so every production poll yielded an empty array. It also returned the whole
// pool on each poll instead of the increment. Both are addressed here:
// pendingTxHashes understands the real element shape, and pendingSeen tracks
// what has already been delivered.
func (api *API) getNewPendingTxHashes(filter *activeFilter) (any, *Error) {
	if api.txPool == nil {
		// No silent empty result: the node cannot serve this filter type.
		return nil, NewError(ErrCodeInternal,
			"pending transaction filters are not supported: tx pool unavailable")
	}

	filter.pollMu.Lock()
	defer filter.pollMu.Unlock()

	hashes := pendingTxHashes(api.txPool.GetPendingTransactions())
	newHashes := make([]string, 0, len(hashes))
	seen := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		seen[h] = struct{}{}
		if _, already := filter.pendingSeen[h]; !already {
			newHashes = append(newHashes, h)
		}
	}

	// Rebase to the current pool: hashes that left the pool must not be
	// remembered forever, and a later re-entry is a new arrival worth reporting.
	filter.pendingSeen = seen

	return newHashes, nil
}

// pendingTxHashes extracts canonical lowercase 0x-prefixed hashes from the
// elements returned by TxPool.GetPendingTransactions. Production returns
// *encoding.Transaction; strings, types.Hash and map[string]any are accepted
// for test doubles and legacy callers. Duplicates are dropped and elements
// whose hash cannot be determined are skipped.
func pendingTxHashes(pending []any) []string {
	out := make([]string, 0, len(pending))
	seen := make(map[string]struct{}, len(pending))
	for _, tx := range pending {
		var hash string
		switch t := tx.(type) {
		case *encoding.Transaction:
			if t != nil {
				if h := t.Hash(); h != (types.Hash{}) {
					hash = "0x" + h.String()
				}
			}
		case encoding.Transaction:
			if h := t.Hash(); h != (types.Hash{}) {
				hash = "0x" + h.String()
			}
		case types.Hash:
			if t != (types.Hash{}) {
				hash = "0x" + t.String()
			}
		case string:
			hash = t
		case map[string]any:
			if h, ok := t["hash"].(string); ok {
				hash = h
			}
		}
		if hash == "" {
			continue
		}
		key := strings.ToLower(hash)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

// getNewLogs returns the logs matching the filter that were produced in the
// blocks after the last poll, and advances the filter's block cursor.
//
// AUDIT (2026) API-04-adjacent FIX (LOW-6): this used to always return an
// empty slice, so clients polling eth_getFilterChanges silently missed every
// event. Logs are now sourced from the same per-block receipt scan used by
// eth_getLogs (getLogsRange): there is no separate log index, but the block
// reader can serve every block and its receipts, which is enough to scan the
// (lastBlock, head] window.
//
// The cursor is advanced ONLY after a successful scan, and only up to the last
// block actually scanned (the batch is capped at maxFilterBlockRange so a stale
// filter cannot force an unbounded scan in one poll). If a block cannot be
// read the RPC returns an error and leaves the cursor untouched, so the same
// window is retried on the next poll instead of being skipped forever.
func (api *API) getNewLogs(filter *activeFilter) (any, *Error) {
	if api.blockReader == nil {
		// No silent empty result: the node cannot serve this filter type.
		return nil, NewError(ErrCodeInternal,
			"log filters are not supported: block reader unavailable")
	}
	if filter.logFilter == nil {
		return nil, NewError(ErrCodeInternal, "log filter has no criteria")
	}

	filter.pollMu.Lock()
	defer filter.pollMu.Unlock()

	latest := api.blockReader.GetLatestHeight()
	if latest < filter.lastBlock {
		// Chain was rewound below our cursor (rollback / resync). Move the
		// cursor back so the next blocks are still reported.
		filter.lastBlock = latest
	}
	fromHeight := filter.lastBlock + 1
	if fromHeight > latest {
		return []Log{}, nil
	}

	toHeight := fromHeight + maxFilterBlockRange - 1
	if toHeight > latest {
		toHeight = latest
	}

	logs, rpcErr := api.getLogsRange(fromHeight, toHeight, filter.logFilter)
	if rpcErr != nil {
		// Cursor intentionally not advanced; the batch is retried next poll.
		return nil, rpcErr
	}

	filter.lastBlock = toHeight
	return logs, nil
}

// GetFilterLogs returns all logs for a filter
func (api *API) GetFilterLogs(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	fm := getFilterManager(api.blockReader)
	filter := fm.getFilter(args[0], clientIDFromContext(ctx))
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

	switch filter.FromBlock {
	case "", "latest":
		if api.blockReader != nil {
			fromBlock = api.blockReader.GetLatestHeight()
		}
	case "earliest":
		fromBlock = 0
	default:
		var err error
		fromBlock, err = parseHexToUint64(filter.FromBlock)
		if err != nil {
			fromBlock = 0
		}
	}

	switch filter.ToBlock {
	case "", "latest":
		if api.blockReader != nil {
			toBlock = api.blockReader.GetLatestHeight()
		}
	case "earliest":
		toBlock = 0
	default:
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

	logs, rpcErr := api.getLogsRange(fromBlock, toBlock, filter)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return logs, nil
}

// getLogsRange scans blocks [fromBlock, toBlock] inclusive and returns the
// logs matching filter (address + topics). Callers are responsible for
// bounding the range before calling.
//
// A failure to read a block is returned as an error rather than skipped:
// silently dropping a block would make an empty result indistinguishable from
// "no events", which is the failure mode this scan exists to avoid.
func (api *API) getLogsRange(fromBlock, toBlock uint64, filter *LogFilter) ([]Log, *Error) {
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
			return nil, NewError(ErrCodeInternal,
				fmt.Sprintf("failed to read block %d while scanning logs: %v", height, err))
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
			case *TransactionResponse:
				// GETLOGS TX-HASH FIX (2026-11-03, found by the vrf-billing
				// e2e): blockReaderAdapter.GetBlockByHeight serves
				// FormatBlock(blk, true) — full tx objects — so production
				// elements are *TransactionResponse. Only the string and
				// map cases were handled here, so every production block
				// yielded txHash=="" and eth_getLogs returned empty forever.
				txHash = t.Hash
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

				// Extract topics.
				// GETLOGS TOPICS FIX (2026-11-03, found by the vrf-billing
				// e2e): receiptFromStored stores topics as []string; the old
				// []any-only assertion failed for every production receipt,
				// silently stripping topics from served logs — topic filters
				// (the entire eth_getLogs use case) then matched nothing.
				// Accept both element shapes.
				var topics []string
				switch tv := logMap["topics"].(type) {
				case []string:
					topics = append(topics, tv...)
				case []any:
					for _, t := range tv {
						if s, ok := t.(string); ok {
							topics = append(topics, s)
						}
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
