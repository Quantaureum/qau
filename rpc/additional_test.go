// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ── Filter methods ──

// cleanupFilter uninstalls the given filter at test cleanup.
//
// The FilterManager is a package-level singleton shared by every test and
// every -count iteration, with a per-client cap of 10 live filters and a
// 5-minute cleanup window. A test that creates a filter without uninstalling
// it therefore breaks every filter test that runs later in the same binary
// (the next addFilter is refused, and a test that ignores the create error
// panics on its type assertion). Every filter-creating test must register
// this cleanup.
func cleanupFilter(t *testing.T, api *API, filterID string) {
	t.Helper()
	t.Cleanup(func() {
		params, _ := json.Marshal([]string{filterID})
		_, _ = api.UninstallFilter(ctx(), params)
	})
}

func TestNewFilter_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.NewFilter(ctx(), nil)
	requireErr(t, nil, err)
}

func TestNewFilter_InvalidParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.NewFilter(ctx(), json.RawMessage(`"invalid"`))
	requireErr(t, nil, err)
}

func TestNewBlockFilter(t *testing.T) {
	api := newTestAPI()
	result, err := api.NewBlockFilter(ctx(), nil)
	requireOK(t, result, err)
	// Should return a filter ID
	filterID, ok := result.(string)
	if !ok || filterID == "" {
		t.Error("expected non-empty filter ID string")
	}
	cleanupFilter(t, api, filterID)
}

func TestNewPendingTransactionFilter(t *testing.T) {
	api := newTestAPI()
	result, err := api.NewPendingTransactionFilter(ctx(), nil)
	requireOK(t, result, err)
	filterID, ok := result.(string)
	if !ok || filterID == "" {
		t.Error("expected non-empty filter ID string")
	}
	cleanupFilter(t, api, filterID)
}

func TestUninstallFilter_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.UninstallFilter(ctx(), nil)
	requireErr(t, nil, err)
}

func TestUninstallFilter_InvalidID(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-a-number"})
	result, err := api.UninstallFilter(ctx(), params)
	// UninstallFilter may not return error for invalid ID, just false
	_ = result
	_ = err
}

func TestUninstallFilter_ValidID(t *testing.T) {
	api := newTestAPI()
	// First create a block filter — the create error must be asserted: a nil
	// result would panic the type assertion below.
	result, err := api.NewBlockFilter(ctx(), nil)
	requireOK(t, result, err)
	filterID := result.(string)

	// Then uninstall it
	params, _ := json.Marshal([]string{filterID})
	uninstResult, err := api.UninstallFilter(ctx(), params)
	requireOK(t, uninstResult, err)
}

func TestGetFilterChanges_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetFilterChanges(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetFilterChanges_InvalidID(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-a-number"})
	_, err := api.GetFilterChanges(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetFilterChanges_BlockFilter(t *testing.T) {
	api := newTestAPI()
	result, err := api.NewBlockFilter(ctx(), nil)
	requireOK(t, result, err)
	filterID := result.(string)
	cleanupFilter(t, api, filterID)

	params, _ := json.Marshal([]string{filterID})
	changes, err := api.GetFilterChanges(ctx(), params)
	requireOK(t, changes, err)
}

func TestGetFilterChanges_PendingTxFilter(t *testing.T) {
	api := newTestAPI()
	result, err := api.NewPendingTransactionFilter(ctx(), nil)
	requireOK(t, result, err)
	filterID := result.(string)
	cleanupFilter(t, api, filterID)

	params, _ := json.Marshal([]string{filterID})
	changes, err := api.GetFilterChanges(ctx(), params)
	requireOK(t, changes, err)
}

func TestGetFilterLogs_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetFilterLogs(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetFilterLogs_InvalidID(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-a-number"})
	_, err := api.GetFilterLogs(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetLogs_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetLogs(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetLogs_InvalidParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetLogs(ctx(), json.RawMessage(`"invalid"`))
	requireErr(t, nil, err)
}

// logScanMockReader serves formatted blocks and receipts so the log-filter
// scan can be exercised end to end (the default mockBlockReader returns nil
// for every read).
type logScanMockReader struct {
	latestHeight uint64
	blocks       map[uint64]*BlockResponse
	receipts     map[types.Hash]map[string]any
}

func (m *logScanMockReader) GetBlockByHash(hash types.Hash) (any, error) { return nil, nil }
func (m *logScanMockReader) GetBlockByHeight(height uint64) (any, error) {
	blk, ok := m.blocks[height]
	if !ok {
		return nil, fmt.Errorf("block %d not found", height)
	}
	return blk, nil
}
func (m *logScanMockReader) GetLatestHeight() uint64                     { return m.latestHeight }
func (m *logScanMockReader) GetTransaction(hash types.Hash) (any, error) { return nil, nil }
func (m *logScanMockReader) GetTransactionReceipt(hash types.Hash) (any, error) {
	if r, ok := m.receipts[hash]; ok {
		return r, nil
	}
	return nil, nil
}
func (m *logScanMockReader) GetBlockByHeightRange(from, to uint64) ([]any, error) { return nil, nil }
func (m *logScanMockReader) GetGasLimit() uint64                                  { return 30_000_000 }

// TestGetFilterChanges_LogFilter_ReturnsNewLogsAndAdvancesCursor is the
// regression test for the silent-empty eth_getFilterChanges log path
// (rpc/advanced.go getNewLogs). Before the fix every poll returned []Log{}.
// It also pins the incremental cursor contract: a second poll with no new
// blocks must return nothing (no duplicate delivery), and a later block must
// be delivered exactly once.
func TestGetFilterChanges_LogFilter_ReturnsNewLogsAndAdvancesCursor(t *testing.T) {
	// The FilterManager is a package singleton that captures the first
	// BlockReader it sees; rebind it to this test's reader.
	StopGlobalFilterManager()
	t.Cleanup(StopGlobalFilterManager)

	contract := "0x1111111111111111111111111111111111111111"
	otherAddr := "0x2222222222222222222222222222222222222222"
	topic := "0x" + strings.Repeat("aa", 32)

	tx6 := types.Hash{0x06}
	tx7 := types.Hash{0x07}
	tx8 := types.Hash{0x08}

	reader := &logScanMockReader{
		latestHeight: 5, // filter is created at height 5
		blocks: map[uint64]*BlockResponse{
			6: {Number: "0x6", Hash: "0xblock6", Transactions: []any{&TransactionResponse{Hash: "0x" + tx6.String()}}},
			7: {Number: "0x7", Hash: "0xblock7", Transactions: []any{&TransactionResponse{Hash: "0x" + tx7.String()}}},
		},
		receipts: map[types.Hash]map[string]any{
			tx6: {"logs": []any{map[string]any{
				"address": contract, "data": "0x01", "topics": []any{topic}, "removed": false,
			}}},
			// Same topic from a different address: must NOT match the
			// address-scoped filter.
			tx7: {"logs": []any{map[string]any{
				"address": otherAddr, "data": "0x02", "topics": []any{topic}, "removed": false,
			}}},
		},
	}

	api := NewAPI(newMockStateReader(), reader, newMockTxPool(), newMockChainInfo(), &mockAccountManager{})

	params, _ := json.Marshal(map[string]any{
		"fromBlock": "latest",
		"address":   contract,
		"topics":    []any{topic},
	})
	created, err := api.NewFilter(ctx(), params)
	requireOK(t, created, err)
	filterID := created.(string)
	cleanupFilter(t, api, filterID)

	// Head advances past the filter's creation height before the first poll.
	reader.latestHeight = 7
	pollParams, _ := json.Marshal([]string{filterID})

	changes, rpcErr := api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	logs, ok := changes.([]Log)
	if !ok {
		t.Fatalf("expected []Log from eth_getFilterChanges, got %T", changes)
	}
	if len(logs) != 1 {
		t.Fatalf("expected exactly 1 matching log, got %d (%+v)", len(logs), logs)
	}
	if logs[0].BlockNumber != "0x6" || logs[0].TransactionHash != "0x"+tx6.String() {
		t.Fatalf("unexpected log identity: %+v", logs[0])
	}

	// Second poll with no new blocks: nothing to deliver, cursor unchanged.
	changes, rpcErr = api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	logs, ok = changes.([]Log)
	if !ok {
		t.Fatalf("expected []Log from eth_getFilterChanges, got %T", changes)
	}
	if len(logs) != 0 {
		t.Fatalf("expected no logs on an unchanged head, got %d (%+v)", len(logs), logs)
	}

	// New head block with a matching log is delivered exactly once.
	reader.latestHeight = 8
	reader.blocks[8] = &BlockResponse{
		Number: "0x8", Hash: "0xblock8", Transactions: []any{&TransactionResponse{Hash: "0x" + tx8.String()}},
	}
	reader.receipts[tx8] = map[string]any{"logs": []any{map[string]any{
		"address": contract, "data": "0x03", "topics": []any{topic}, "removed": false,
	}}}
	changes, rpcErr = api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	logs, ok = changes.([]Log)
	if !ok {
		t.Fatalf("expected []Log from eth_getFilterChanges, got %T", changes)
	}
	if len(logs) != 1 || logs[0].BlockNumber != "0x8" {
		t.Fatalf("expected the block-8 log exactly once, got %d (%+v)", len(logs), logs)
	}
}

// syntheticBlockReader synthesizes a block for any requested height, which
// lets the batch-cap and retry semantics be tested without materializing a
// 1000+ block fixture.
type syntheticBlockReader struct {
	latest uint64
	failAt uint64 // 0 means "never fail"
}

func (m *syntheticBlockReader) GetBlockByHash(hash types.Hash) (any, error) { return nil, nil }
func (m *syntheticBlockReader) GetBlockByHeight(height uint64) (any, error) {
	if m.failAt != 0 && height == m.failAt {
		return nil, fmt.Errorf("synthetic read failure at height %d", height)
	}
	return &BlockResponse{Number: formatHexUint64(height), Hash: fmt.Sprintf("0xblock%d", height)}, nil
}
func (m *syntheticBlockReader) GetLatestHeight() uint64                              { return m.latest }
func (m *syntheticBlockReader) GetTransaction(hash types.Hash) (any, error)          { return nil, nil }
func (m *syntheticBlockReader) GetTransactionReceipt(hash types.Hash) (any, error)   { return nil, nil }
func (m *syntheticBlockReader) GetBlockByHeightRange(from, to uint64) ([]any, error) { return nil, nil }
func (m *syntheticBlockReader) GetGasLimit() uint64                                  { return 30_000_000 }

// blockFilterCursor returns the filter's current block cursor.
func blockFilterCursor(t *testing.T, reader BlockReader, filterID string) uint64 {
	t.Helper()
	fm := getFilterManager(reader)
	fm.mu.RLock()
	filter := fm.filters[filterID]
	fm.mu.RUnlock()
	if filter == nil {
		t.Fatalf("filter %s disappeared", filterID)
	}
	filter.pollMu.Lock()
	defer filter.pollMu.Unlock()
	return filter.lastBlock
}

// TestGetFilterChanges_BlockFilter_ReadFailureKeepsCursor pins the retry
// contract: a block read failure must surface as an RPC error and must NOT
// advance the cursor, or the unread blocks are lost forever.
func TestGetFilterChanges_BlockFilter_ReadFailureKeepsCursor(t *testing.T) {
	StopGlobalFilterManager()
	t.Cleanup(StopGlobalFilterManager)

	reader := &syntheticBlockReader{latest: 5}
	api := NewAPI(newMockStateReader(), reader, newMockTxPool(), newMockChainInfo(), &mockAccountManager{})

	created, err := api.NewBlockFilter(ctx(), nil)
	requireOK(t, created, err)
	filterID := created.(string)
	cleanupFilter(t, api, filterID)
	pollParams, _ := json.Marshal([]string{filterID})

	reader.latest = 7
	reader.failAt = 6
	_, rpcErr := api.GetFilterChanges(ctx(), pollParams)
	if rpcErr == nil {
		t.Fatal("expected an RPC error when a block cannot be read, got success")
	}
	if got := blockFilterCursor(t, reader, filterID); got != 5 {
		t.Fatalf("cursor must stay at 5 after a failed scan, got %d", got)
	}

	// The same window is retried once the read succeeds.
	reader.failAt = 0
	changes, rpcErr := api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	hashes, ok := changes.([]string)
	if !ok {
		t.Fatalf("expected []string from eth_getFilterChanges, got %T", changes)
	}
	if len(hashes) != 2 || hashes[0] != "0xblock6" || hashes[1] != "0xblock7" {
		t.Fatalf("expected blocks 6 and 7 after retry, got %v", hashes)
	}
}

// TestGetFilterChanges_BlockFilter_BatchCapAdvancesWithoutSkipping pins the
// batch semantics for stale filters: at most maxFilterBlockRange blocks per
// poll, and the next poll continues exactly where the previous one stopped
// (the old code jumped to head-minus-1024, dropping the gap).
func TestGetFilterChanges_BlockFilter_BatchCapAdvancesWithoutSkipping(t *testing.T) {
	StopGlobalFilterManager()
	t.Cleanup(StopGlobalFilterManager)

	reader := &syntheticBlockReader{latest: 0}
	api := NewAPI(newMockStateReader(), reader, newMockTxPool(), newMockChainInfo(), &mockAccountManager{})

	created, err := api.NewBlockFilter(ctx(), nil)
	requireOK(t, created, err)
	filterID := created.(string)
	cleanupFilter(t, api, filterID)
	pollParams, _ := json.Marshal([]string{filterID})

	reader.latest = 5000
	changes, rpcErr := api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	hashes, ok := changes.([]string)
	if !ok {
		t.Fatalf("expected []string from eth_getFilterChanges, got %T", changes)
	}
	if len(hashes) != maxFilterBlockRange {
		t.Fatalf("expected exactly %d hashes in one batch, got %d", maxFilterBlockRange, len(hashes))
	}
	if hashes[0] != "0xblock1" || hashes[len(hashes)-1] != fmt.Sprintf("0xblock%d", maxFilterBlockRange) {
		t.Fatalf("first batch must cover blocks 1..%d, got %s..%s",
			maxFilterBlockRange, hashes[0], hashes[len(hashes)-1])
	}
	if got := blockFilterCursor(t, reader, filterID); got != uint64(maxFilterBlockRange) {
		t.Fatalf("cursor must stop at the last scanned block %d, got %d", maxFilterBlockRange, got)
	}

	changes, rpcErr = api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	hashes, ok = changes.([]string)
	if !ok {
		t.Fatalf("expected []string from eth_getFilterChanges, got %T", changes)
	}
	if len(hashes) != maxFilterBlockRange {
		t.Fatalf("expected a full second batch, got %d", len(hashes))
	}
	if hashes[0] != fmt.Sprintf("0xblock%d", maxFilterBlockRange+1) {
		t.Fatalf("second batch must resume at block %d, got %s", maxFilterBlockRange+1, hashes[0])
	}
}

// pendingPoolMock lets a test control what the pool reports as pending.
// The embedded mockTxPool supplies the remaining TxPool methods.
type pendingPoolMock struct {
	mockTxPool
	pending []any
}

func (m *pendingPoolMock) GetPendingTransactions() []any { return m.pending }

func newFilterTestTx(nonce uint64) *encoding.Transaction {
	return &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    nonce,
		Value:    big.NewInt(0),
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}
}

// TestGetFilterChanges_PendingTxFilter_ProductionTypeIncremental is the
// regression test for the pending-transaction filter returning nothing in
// production. The production adapter returns []any of *encoding.Transaction,
// while the old code only accepted map[string]any, so every poll was empty.
// It also pins the incremental contract: each poll returns only hashes that
// entered the pool since the previous poll, and evicted transactions are
// dropped from the seen-set.
func TestGetFilterChanges_PendingTxFilter_ProductionTypeIncremental(t *testing.T) {
	StopGlobalFilterManager()
	t.Cleanup(StopGlobalFilterManager)

	tx1 := newFilterTestTx(1)
	tx2 := newFilterTestTx(2)
	tx3 := newFilterTestTx(3)

	pool := &pendingPoolMock{pending: []any{tx1}}
	api := NewAPI(newMockStateReader(), newMockBlockReader(), pool, newMockChainInfo(), &mockAccountManager{})

	created, err := api.NewPendingTransactionFilter(ctx(), nil)
	requireOK(t, created, err)
	filterID := created.(string)
	cleanupFilter(t, api, filterID)
	pollParams, _ := json.Marshal([]string{filterID})

	// A transaction that arrives after the filter was created must be
	// reported (as a hash string) even though the element is a real
	// *encoding.Transaction, not a map.
	pool.pending = append(pool.pending, tx2)
	changes, rpcErr := api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	hashes, ok := changes.([]string)
	if !ok {
		t.Fatalf("expected []string from eth_getFilterChanges, got %T", changes)
	}
	want2 := "0x" + tx2.Hash().String()
	if len(hashes) != 1 || hashes[0] != want2 {
		t.Fatalf("expected only the new tx %s, got %v", want2, hashes)
	}

	// Polling again with no new arrivals must not replay the pool.
	changes, rpcErr = api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	hashes, ok = changes.([]string)
	if !ok {
		t.Fatalf("expected []string from eth_getFilterChanges, got %T", changes)
	}
	if len(hashes) != 0 {
		t.Fatalf("expected no new hashes on an unchanged pool, got %v", hashes)
	}

	// A third arrival is reported exactly once.
	pool.pending = append(pool.pending, tx3)
	changes, rpcErr = api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	hashes, ok = changes.([]string)
	if !ok {
		t.Fatalf("expected []string from eth_getFilterChanges, got %T", changes)
	}
	want3 := "0x" + tx3.Hash().String()
	if len(hashes) != 1 || hashes[0] != want3 {
		t.Fatalf("expected only the new tx %s, got %v", want3, hashes)
	}

	// An evicted transaction is forgotten; it is not reported again.
	pool.pending = pool.pending[1:]
	changes, rpcErr = api.GetFilterChanges(ctx(), pollParams)
	requireOK(t, changes, rpcErr)
	hashes, ok = changes.([]string)
	if !ok {
		t.Fatalf("expected []string from eth_getFilterChanges, got %T", changes)
	}
	if len(hashes) != 0 {
		t.Fatalf("expected no hashes after eviction, got %v", hashes)
	}
}

// TestFilterOwnership_PollAndReadChecksCaller pins the AUDIT FIX: filter read
// paths (eth_getFilterChanges, eth_getFilterLogs) must enforce the same
// ownership rule as eth_uninstallFilter. Before the fix, any client that knew
// a filter ID could poll it and advance its cursor.
func TestFilterOwnership_PollAndReadChecksCaller(t *testing.T) {
	StopGlobalFilterManager()
	t.Cleanup(StopGlobalFilterManager)

	reader := &syntheticBlockReader{latest: 5}
	api := NewAPI(newMockStateReader(), reader, newMockTxPool(), newMockChainInfo(), &mockAccountManager{})

	ctxA := context.WithValue(ctx(), contextKeyClientIP{}, "10.0.0.1")
	ctxB := context.WithValue(ctx(), contextKeyClientIP{}, "10.0.0.2")

	blockID, err := api.NewBlockFilter(ctxA, nil)
	requireOK(t, blockID, err)
	blockPollParams, _ := json.Marshal([]string{blockID.(string)})

	if _, rpcErr := api.GetFilterChanges(ctxA, blockPollParams); rpcErr != nil {
		t.Fatalf("owner must be able to poll its filter: %v", rpcErr.Message)
	}
	_, rpcErr := api.GetFilterChanges(ctxB, blockPollParams)
	if rpcErr == nil {
		t.Fatal("another client was able to poll a filter it does not own")
	}
	if rpcErr.Code != ErrCodeNotFound {
		t.Fatalf("expected %d for a non-owned filter, got %d", ErrCodeNotFound, rpcErr.Code)
	}

	logParams, _ := json.Marshal(map[string]any{"fromBlock": "latest"})
	logID, err := api.NewFilter(ctxA, logParams)
	requireOK(t, logID, err)
	logReadParams, _ := json.Marshal([]string{logID.(string)})

	if _, rpcErr := api.GetFilterLogs(ctxA, logReadParams); rpcErr != nil {
		t.Fatalf("owner must be able to read its log filter: %v", rpcErr.Message)
	}
	if _, rpcErr := api.GetFilterLogs(ctxB, logReadParams); rpcErr == nil {
		t.Fatal("another client was able to read a log filter it does not own")
	}

	// Uninstall keeps the same boundary.
	if removed, _ := api.UninstallFilter(ctxB, logReadParams); removed == true {
		t.Fatal("another client was able to uninstall a filter it does not own")
	}
	if removed, rpcErr := api.UninstallFilter(ctxA, logReadParams); rpcErr != nil || removed != true {
		t.Fatalf("owner must be able to uninstall its filter, removed=%v err=%v", removed, rpcErr)
	}
}

// ── PersonalAPI tests ──

func TestNewPersonalAPI(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	if api == nil {
		t.Fatal("expected non-nil PersonalAPI")
	}
}

func TestPersonalAPI_ListAccounts(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	result, err := api.ListAccounts(context.Background(), nil)
	requireOK(t, result, err)
}

func TestPersonalAPI_SetDevMode(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	// DevMode requires compile-time flag, so this won't actually enable it
	api.SetDevMode(true)
	api.SetDevMode(false)
}

func TestPersonalAPI_RegisterHandlers(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	srv := NewServer(nil)
	api.RegisterHandlers(srv)

	// Check that personal methods are registered
	expectedMethods := []string{
		"personal_newAccount",
		"personal_listAccounts",
		"personal_unlockAccount",
		"personal_lockAccount",
		"personal_sendTransaction",
		"personal_sign",
		"personal_importRawKey",
	}
	for _, method := range expectedMethods {
		if _, ok := srv.handlers[method]; !ok {
			t.Errorf("expected handler for method %s", method)
		}
	}
}

func TestPersonalAPI_NewAccount_NoPassword(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	params, _ := json.Marshal([]string{})
	_, err := api.NewAccount(context.Background(), params)
	// Should fail without password
	_ = err
}

func TestPersonalAPI_LockAccount_NotUnlocked(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	params, _ := json.Marshal([]string{"0x1234567890123456789012345678901234567890"})
	result, err := api.LockAccount(context.Background(), params)
	// Locking an account that's not unlocked should return false
	_ = result
	_ = err
}

func TestPersonalAPI_IsUnlocked_Empty(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	var emptyAddr types.Address
	if api.IsUnlocked(emptyAddr) {
		t.Error("expected empty address to not be unlocked")
	}
}

// ── RateLimiter additional tests ──

func TestNewRateLimiter_Additional(t *testing.T) {
	rl := NewRateLimiter(DefaultRateLimitConfig())
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}
}

func TestRateLimiterConfig_Fields(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	if cfg.GlobalRateLimit <= 0 {
		t.Error("expected positive global rate limit")
	}
	if cfg.BurstSize <= 0 {
		t.Error("expected positive burst size")
	}
}

func TestRateLimiter_AllowRequest(t *testing.T) {
	rl := NewRateLimiter(DefaultRateLimitConfig())
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "192.168.1.1:12345"
	err := rl.Allow(r, "eth_chainId")
	if err != nil {
		t.Errorf("first request should be allowed, got: %v", err)
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(DefaultRateLimitConfig())
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = "192.168.1." + string(rune('0'+i)) + ":12345"
		err := rl.Allow(r, "eth_chainId")
		if err != nil {
			t.Errorf("request from IP %d should be allowed, got: %v", i, err)
		}
	}
}

// ── Quantum API tests ──

func TestVerifyQuantumTransaction_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.VerifyQuantumTransaction(ctx(), nil)
	requireErr(t, nil, err)
}

// ── WebSocket server creation ──

func TestNewWebSocketServer(t *testing.T) {
	srv := NewWebSocketServer(nil)
	if srv == nil {
		t.Error("expected non-nil WebSocket server")
	}
}

// ── requireTLS check ──

func TestRequireTLS_NonHTTPContext(t *testing.T) {
	api := NewPersonalAPI("", nil, nil, nil)
	err := api.requireTLS(context.Background())
	if err != nil {
		t.Error("non-HTTP context should not require TLS")
	}
}

func TestRequireTLS_HTTPContext_NoTLS(t *testing.T) {
	api := NewPersonalAPI("", nil, nil, nil)
	r := httptest.NewRequest("POST", "/", nil)
	ctx := context.WithValue(context.Background(), contextKeyHTTPRequest{}, r)
	err := api.requireTLS(ctx)
	if err == nil {
		t.Error("expected TLS required error for non-TLS HTTP request")
	}
}

// ── extractDilithium3PrivateKey tests ──

func TestExtractDilithium3PrivateKey_NoPrefix(t *testing.T) {
	// Without dilithium3: prefix, short input must be rejected
	_, err := extractDilithium3PrivateKey("abc123")
	if err == nil {
		t.Error("expected error for short non-prefixed key")
	}
}

func TestExtractDilithium3PrivateKey_WithPrefix(t *testing.T) {
	// With dilithium3: prefix, short input must be rejected
	_, err := extractDilithium3PrivateKey("dilithium3:abcd1234")
	if err == nil {
		t.Error("expected error for short prefixed key")
	}
}

// ── HTTP context helpers ──

func TestExtractClientIP_EmptyRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = ""
	ip := extractClientIP(r)
	// Should handle empty remote addr gracefully
	_ = ip
}

func TestExtractClientIP_XForwardedFor(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 198.51.100.7")
	ip := extractClientIP(r)
	if ip == "" {
		t.Error("expected non-empty IP from X-Forwarded-For")
	}
}

func TestExtractClientIP_XRealIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Real-IP", "203.0.113.50")
	ip := extractClientIP(r)
	if ip == "" {
		t.Error("expected non-empty IP from X-Real-IP")
	}
}

// ── Server handleRequest edge cases ──

func TestHandleRequest_EmptyMethod(t *testing.T) {
	srv := NewServer(nil)
	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "",
		ID:      1,
	})
	if resp.Error == nil {
		t.Error("expected error for empty method")
	}
}

func TestHandleRequest_NoVersion(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("qau_test", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "ok", nil
	})
	resp := srv.HandleRequest(context.Background(), &Request{
		Method: "qau_test",
		ID:     1,
	})
	// Missing version should trigger invalid request error
	if resp.Error == nil {
		t.Error("expected error for missing JSON-RPC version")
	}
}

// ── Server CORS with no origin ──

func TestSetCORSHeaders_NoOrigin(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	// No Origin header

	srv.setCORSHeaders(w, r)
	// Should not set CORS headers without origin
}

// ── Server OPTIONS request ──

func TestHandleHTTP_OptionsRequest(t *testing.T) {
	srv := NewServer(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/", nil)
	r.Header.Set("Origin", "https://example.com")

	srv.handleHTTP(w, r)
	// Should handle CORS preflight
}

// ── Server with rate limiter ──

func TestHandleHTTP_RateLimited(t *testing.T) {
	cfg := &Config{
		EnableRateLimit: true,
	}
	srv := NewServer(cfg)
	srv.RegisterHandler("qau_test", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "ok", nil
	})
	rl := NewRateLimiter(&RateLimitConfig{
		Enabled:         true,
		GlobalRateLimit: 1,
		BurstSize:       1,
	})
	srv.SetRateLimiter(rl)

	// First request should succeed
	body := `{"jsonrpc":"2.0","method":"qau_test","id":1}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "192.168.1.1:12345"
	srv.handleHTTP(w, r)

	// Rapid subsequent requests may be rate limited
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r2.Header.Set("Content-Type", "application/json")
	r2.RemoteAddr = "192.168.1.1:12345"
	srv.handleHTTP(w2, r2)
}
