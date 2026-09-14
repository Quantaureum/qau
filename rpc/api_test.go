// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
)

// ── mock implementations ──

type mockStateReader struct {
	balances map[types.Address]*big.Int
	nonces   map[types.Address]uint64
	codes    map[types.Address][]byte
	storage  map[types.Address]map[types.Hash]types.Hash
}

func newMockStateReader() *mockStateReader {
	return &mockStateReader{
		balances: make(map[types.Address]*big.Int),
		nonces:   make(map[types.Address]uint64),
		codes:    make(map[types.Address][]byte),
		storage:  make(map[types.Address]map[types.Hash]types.Hash),
	}
}

func (m *mockStateReader) GetBalance(addr types.Address) *big.Int {
	if b, ok := m.balances[addr]; ok {
		return new(big.Int).Set(b)
	}
	return big.NewInt(0)
}
func (m *mockStateReader) GetNonce(addr types.Address) uint64 { return m.nonces[addr] }
func (m *mockStateReader) GetCode(addr types.Address) []byte  { return m.codes[addr] }
func (m *mockStateReader) GetState(addr types.Address, key types.Hash) types.Hash {
	if s, ok := m.storage[addr]; ok {
		return s[key]
	}
	return types.Hash{}
}
func (m *mockStateReader) IterateAccounts(fn func(addr types.Address, code []byte, balance *big.Int) bool) {
	for addr, balance := range m.balances {
		if !fn(addr, m.codes[addr], balance) {
			return
		}
	}
}

// R38-P2-04 DEEP FIX (2026-08-02): StateReader interface gained three
// stateRoot-aware proof methods. The mock has no real state trie behind
// it, so all three return the honest "not supported" errors and zero
// StateRoot — the RPC GetProof path falls back to the synthetic-tree
// pseudo-proof and surfaces Unverified=true.
func (m *mockStateReader) StateRoot() types.Hash { return types.Hash{} }
func (m *mockStateReader) ProveAccount(addr types.Address) (*trie.VerkleProof, error) {
	return nil, ErrProofNotSupported
}
func (m *mockStateReader) ProveStorage(addr types.Address, key types.Hash) (*trie.VerkleProof, error) {
	return nil, ErrProofNotSupported
}

type mockBlockReader struct {
	latestHeight uint64
}

func newMockBlockReader() *mockBlockReader {
	return &mockBlockReader{latestHeight: 100}
}

func (m *mockBlockReader) GetBlockByHash(hash types.Hash) (any, error)          { return nil, nil }
func (m *mockBlockReader) GetBlockByHeight(height uint64) (any, error)          { return nil, nil }
func (m *mockBlockReader) GetLatestHeight() uint64                              { return m.latestHeight }
func (m *mockBlockReader) GetTransaction(hash types.Hash) (any, error)          { return nil, nil }
func (m *mockBlockReader) GetTransactionReceipt(hash types.Hash) (any, error)   { return nil, nil }
func (m *mockBlockReader) GetBlockByHeightRange(from, to uint64) ([]any, error) { return nil, nil }
func (m *mockBlockReader) GetGasLimit() uint64                                  { return 30_000_000 }

type mockTxPool struct {
	pendingCount int
	queuedCount  int
}

func newMockTxPool() *mockTxPool                                   { return &mockTxPool{pendingCount: 5, queuedCount: 2} }
func (m *mockTxPool) AddTransaction(tx []byte) (types.Hash, error) { return types.Hash{}, nil }
func (m *mockTxPool) AddVerifiedTransaction(tx *encoding.Transaction) (types.Hash, error) {
	return types.Hash{}, nil
}
func (m *mockTxPool) GetPendingTransactions() []any                            { return nil }
func (m *mockTxPool) GetPendingCount() int                                     { return m.pendingCount }
func (m *mockTxPool) GetQueuedCount() int                                      { return m.queuedCount }
func (m *mockTxPool) GetPendingNonce(addr types.Address) uint64                { return 0 }
func (m *mockTxPool) AddUserOperation(uo *encoding.UserOperation) error        { return nil }
func (m *mockTxPool) GetUserOperation(hash types.Hash) *encoding.UserOperation { return nil }
func (m *mockTxPool) PendingUserOps() []*encoding.UserOperation                { return nil }

type mockChainInfo struct {
	chainID   uint64
	networkID uint64
}

func newMockChainInfo() *mockChainInfo                 { return &mockChainInfo{chainID: 1668, networkID: 1} }
func (m *mockChainInfo) ChainID() uint64               { return m.chainID }
func (m *mockChainInfo) NetworkID() uint64             { return m.networkID }
func (m *mockChainInfo) ProtocolVersion() string       { return "Quantaureum/2.0.0" }
func (m *mockChainInfo) IsSyncing() bool               { return false }
func (m *mockChainInfo) HighestBlock() uint64          { return 100 }
func (m *mockChainInfo) PeerCount() int                { return 10 }
func (m *mockChainInfo) GetPeers() []PeerInfo          { return nil }
func (m *mockChainInfo) GetQPOSStatus() map[string]any { return map[string]any{"epoch": 5} }
func (m *mockChainInfo) GetEnodeURL() string           { return "enode://test@127.0.0.1:30303" }
func (m *mockChainInfo) GetListenAddr() string         { return ":9000" }
func (m *mockChainInfo) GetAdvertisedIP() string       { return "127.0.0.1" }

type mockAccountManager struct{}

func (m *mockAccountManager) SignTransaction(from types.Address, tx any) ([]byte, error) {
	return nil, nil
}
func (m *mockAccountManager) UnlockAccountDirect(addr types.Address, password string) error {
	return nil
}
func (m *mockAccountManager) IsUnlocked(addr types.Address) bool { return true }

// ── helpers ──

func newTestAPI() *API {
	api := NewAPI(
		newMockStateReader(),
		newMockBlockReader(),
		newMockTxPool(),
		newMockChainInfo(),
		&mockAccountManager{},
	)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	return api
}

func mustParseAddress(t *testing.T, s string) types.Address {
	t.Helper()
	addr, err := types.ParseHexAddress(s)
	if err != nil {
		t.Fatalf("bad test address %q: %v", s, err)
	}
	return addr
}

// ctx returns a plain background context (CRV2 removed the trusted-local
// commit-auth bypass along with the HMAC subsystem).
func ctx() context.Context { return context.Background() }

func requireOK(t *testing.T, result any, rpcErr *Error) {
	t.Helper()
	if rpcErr != nil {
		t.Fatalf("unexpected RPC error: %s (code=%d)", rpcErr.Message, rpcErr.Code)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

func requireErr(t *testing.T, result any, rpcErr *Error) {
	t.Helper()
	if rpcErr == nil {
		t.Fatal("expected error, got none")
	}
}

// ── Chain methods ──

func TestChainID(t *testing.T) {
	api := newTestAPI()
	result, err := api.ChainID(ctx(), nil)
	requireOK(t, result, err)
	if result.(string) != "0x684" {
		t.Errorf("expected 0x684, got %v", result)
	}
}

func TestNetworkID(t *testing.T) {
	api := newTestAPI()
	result, err := api.NetworkID(ctx(), nil)
	requireOK(t, result, err)
	if result == nil {
		t.Error("expected non-nil network ID")
	}
}

func TestProtocolVersion(t *testing.T) {
	api := newTestAPI()
	result, err := api.ProtocolVersion(ctx(), nil)
	requireOK(t, result, err)
	if result.(string) != "Quantaureum/2.0.0" {
		t.Errorf("unexpected version: %v", result)
	}
}

func TestBlockNumber(t *testing.T) {
	api := newTestAPI()
	result, err := api.BlockNumber(ctx(), nil)
	requireOK(t, result, err)
	if result.(string) != "0x64" {
		t.Errorf("expected 0x64, got %v", result)
	}
}

func TestSyncing(t *testing.T) {
	api := newTestAPI()
	result, err := api.Syncing(ctx(), nil)
	requireOK(t, result, err)
	if result.(bool) != false {
		t.Errorf("expected false, got %v", result)
	}
}

// ── Account methods ──

func TestGetBalance(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0x1234567890123456789012345678901234567890")
	state := api.stateReader.(*mockStateReader)
	state.balances[addr] = big.NewInt(1_000_000_000_000_000_000)

	params, _ := json.Marshal([]string{addr.ToHexAddress(), "latest"})
	result, err := api.GetBalance(ctx(), params)
	requireOK(t, result, err)
	if result.(string) != "0xde0b6b3a7640000" {
		t.Errorf("unexpected balance: %v", result)
	}
}

func TestGetBalanceZeroAddress(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"0x0000000000000000000000000000000000000000", "latest"})
	result, err := api.GetBalance(ctx(), params)
	requireOK(t, result, err)
	if result.(string) != "0x0" {
		t.Errorf("expected 0x0, got %v", result)
	}
}

func TestGetBalanceInvalidAddress(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-an-address", "latest"})
	_, err := api.GetBalance(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetTransactionCount(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	state := api.stateReader.(*mockStateReader)
	state.nonces[addr] = 42

	params, _ := json.Marshal([]string{addr.ToHexAddress(), "latest"})
	result, err := api.GetTransactionCount(ctx(), params)
	requireOK(t, result, err)
	if result.(string) != "0x2a" {
		t.Errorf("expected 0x2a, got %v", result)
	}
}

func TestGetCode(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	state := api.stateReader.(*mockStateReader)
	state.codes[addr] = []byte{0x60, 0x80, 0x60, 0x40}

	params, _ := json.Marshal([]string{addr.ToHexAddress(), "latest"})
	result, err := api.GetCode(ctx(), params)
	requireOK(t, result, err)
	if result.(string) != "0x60806040" {
		t.Errorf("unexpected code: %v", result)
	}
}

func TestGetStorageAt(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0xdddddddddddddddddddddddddddddddddddddddd")
	state := api.stateReader.(*mockStateReader)
	if state.storage[addr] == nil {
		state.storage[addr] = make(map[types.Hash]types.Hash)
	}
	var key types.Hash
	key[0] = 0x01
	state.storage[addr][key] = types.BytesToHash([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a})

	params, _ := json.Marshal([]string{
		addr.ToHexAddress(),
		"0x0100000000000000000000000000000000000000000000000000000000000000",
		"latest",
	})
	result, err := api.GetStorageAt(ctx(), params)
	requireOK(t, result, err)
	if result.(string) != "0x000000000000000000000000000000000000000000000000000000000000002a" {
		t.Errorf("unexpected storage: %v", result)
	}
}

func TestGetBalanceQuantityTags(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0xcccccccccccccccccccccccccccccccccccccccc")
	state := api.stateReader.(*mockStateReader)
	state.balances[addr] = big.NewInt(0)

	params, _ := json.Marshal([]string{addr.ToHexAddress(), "pending"})
	_, err := api.GetBalance(ctx(), params)
	if err != nil {
		t.Errorf("pending tag failed: %v", err)
	}
}

// ── Net methods ──

func TestNetVersion(t *testing.T) {
	api := newTestAPI()
	result, err := api.NetVersion(ctx(), nil)
	requireOK(t, result, err)
	if result == nil {
		t.Error("expected non-nil net version")
	}
}

func TestNetListening(t *testing.T) {
	api := newTestAPI()
	result, err := api.NetListening(ctx(), nil)
	requireOK(t, result, err)
	if !result.(bool) {
		t.Error("expected listening=true")
	}
}

// ── TxPool ──

func TestTxPoolStatus(t *testing.T) {
	api := newTestAPI()
	result, err := api.TxPoolStatus(ctx(), nil)
	requireOK(t, result, err)
	status, ok := result.(map[string]string)
	if !ok {
		t.Fatalf("expected map[string]string, got %T", result)
	}
	if status["pending"] != "0x5" {
		t.Errorf("expected 0x5 pending, got %v", status["pending"])
	}
	if status["queued"] != "0x2" {
		t.Errorf("expected 0x2 queued, got %v", status["queued"])
	}
}

// ── Web3 methods ──

func TestWeb3ClientVersion(t *testing.T) {
	api := newTestAPI()
	result, err := api.Web3ClientVersion(ctx(), nil)
	requireOK(t, result, err)
	if result.(string) == "" {
		t.Error("expected non-empty client version")
	}
}

func TestWeb3Sha3(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"0x68656c6c6f"})
	result, err := api.Web3Sha3(ctx(), params)
	requireOK(t, result, err)
	if len(result.(string)) != 66 {
		t.Errorf("expected 66-char hash, got %d", len(result.(string)))
	}
}

// ── Block methods ──

func TestGetBlockByNumber(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"0x1", "false"})
	_, err := api.GetBlockByNumber(ctx(), params)
	// nil result is expected with mock — just verify no error
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Message)
	}
}

func TestGetBlockByNumberInvalidHex(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"xyz", "false"})
	_, err := api.GetBlockByNumber(ctx(), params)
	requireErr(t, nil, err)
}

// ── Gas price ──

func TestGasPrice(t *testing.T) {
	api := newTestAPI()
	result, err := api.GasPrice(ctx(), nil)
	requireOK(t, result, err)
	if len(result.(string)) < 4 {
		t.Errorf("unexpected gas price: %v", result)
	}
}

// ── QPOS status ──

func TestQPOSStatus(t *testing.T) {
	api := newTestAPI()
	result, err := api.QPOSStatus(ctx(), nil)
	requireOK(t, result, err)
	status := result.(map[string]any)
	if epoch, ok := status["epoch"].(int); !ok || epoch != 5 {
		t.Errorf("unexpected epoch: %v", epoch)
	}
}

// ── Admin methods ──

func TestAdminNodeInfo(t *testing.T) {
	api := newTestAPI()
	result, err := api.AdminNodeInfo(ctx(), nil)
	requireOK(t, result, err)
	if result == nil {
		t.Fatal("expected non-nil node info")
	}
}

// ── Server ──

func TestServerNewWithNilConfig(t *testing.T) {
	srv := NewServer(nil)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestNewError(t *testing.T) {
	err := NewError(-32601, "Method not found")
	if err.Code != -32601 {
		t.Errorf("expected code -32601, got %d", err.Code)
	}
	if err.Message != "Method not found" {
		t.Errorf("unexpected message: %s", err.Message)
	}
}

func TestErrorImplementsErrorInterface(t *testing.T) {
	e := NewError(-32601, "test error")
	var _ error = e
	if e.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

func TestNewErrorWithData(t *testing.T) {
	err := NewErrorWithData(-32000, "Server error", map[string]string{"detail": "oops"})
	if err.Data == nil {
		t.Error("expected data to be set")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Addr == "" {
		t.Error("expected non-empty listen address")
	}
	if cfg.MaxBatchSize <= 0 {
		t.Error("expected positive max batch size")
	}
}

func TestRegisterHandler(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("qau_testMethod", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "ok", nil
	})
	srv.RegisterHandler("qau_testMethod", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "overwritten", nil
	})
}

func TestRegisterAdminMethod(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterAdminMethod("admin_test")
}

func TestUnregisterHandler(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("qau_tempMethod", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "ok", nil
	})
	srv.UnregisterHandler("qau_tempMethod")
}

// ── HandleRequest / HandleBatchRequest ──

func TestHandleRequestKnownMethod(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	resp := srv.HandleRequest(ctx(), &Request{
		JSONRPC: "2.0",
		Method:  "eth_chainId",
		ID:      1,
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
	if resp.Result.(string) != "0x684" {
		t.Errorf("unexpected result: %v", resp.Result)
	}
}

func TestHandleRequestUnknownMethod(t *testing.T) {
	srv := NewServer(nil)
	resp := srv.HandleRequest(ctx(), &Request{
		JSONRPC: "2.0",
		Method:  "qau_nonexistent",
		ID:      1,
	})
	if resp.Error == nil {
		t.Error("expected error for unknown method")
	}
}

func TestHandleBatchRequest(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	responses := srv.HandleBatchRequest(ctx(), []Request{
		{JSONRPC: "2.0", Method: "eth_chainId", ID: 1},
		{JSONRPC: "2.0", Method: "eth_blockNumber", ID: 2},
	})
	if len(responses) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(responses))
	}
	for i, resp := range responses {
		if resp.Error != nil {
			t.Errorf("batch item %d has error: %s", i, resp.Error.Message)
		}
	}
}

// ── Gas price estimation ──

func TestEstimateGas(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0x1234567890123456789012345678901234567890")
	params, _ := json.Marshal([]map[string]string{{
		"from": addr.ToHexAddress(),
		"to":   "0x0000000000000000000000000000000000000001",
	}})
	result, err := api.EstimateGas(ctx(), params)
	requireOK(t, result, err)
	if result.(string) != "0x5208" {
		t.Errorf("unexpected gas estimate: %v", result)
	}
}

// ── API methods with nil params ──

func TestBlockNumberNilParams(t *testing.T) {
	api := newTestAPI()
	r, e := api.BlockNumber(ctx(), nil)
	requireOK(t, r, e)
}

func TestProtocolVersionNilParams(t *testing.T) {
	api := newTestAPI()
	r, e := api.ProtocolVersion(ctx(), nil)
	requireOK(t, r, e)
}

// ── Auth Manager and Rate Limiter ──

func TestSetAuthManager(t *testing.T) {
	srv := NewServer(nil)
	srv.SetAuthManager(NewAuthManager(nil))
}

// TestEthMethodsAccepted verifies that standard JSON-RPC eth_ methods are now
// served by the production API registration (previously these were rejected).
// Standard EVM methods live under the eth_ namespace; qau_ is reserved for
// Quantaureum-unique methods only.
func TestEthMethodsAccepted(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	for _, method := range []string{
		"eth_chainId", "eth_blockNumber", "eth_gasPrice",
		"eth_getBalance", "eth_call", "eth_estimateGas",
		"eth_sendRawTransaction", "eth_getTransactionByHash",
		"eth_getLogs",
	} {
		resp := srv.handleRequest(context.Background(), &Request{JSONRPC: "2.0", Method: method, ID: 1})
		// These methods must be RECOGNIZED (not method-not-found). Some may
		// return a parameter error for empty params, which is acceptable; the
		// contract under test is purely that the handler is registered.
		if resp.Error != nil && resp.Error.Code == ErrCodeMethodNotFound {
			t.Errorf("%s should be registered, got method-not-found", method)
		}
	}
}

// TestStandardQauMethodsRemoved verifies the hard rename: standard EVM methods
// that previously had a qau_ registration are no longer reachable under qau_.
func TestStandardQauMethodsRemoved(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	for _, method := range []string{
		"qau_chainId", "qau_blockNumber", "qau_getBalance",
		"qau_call", "qau_sendRawTransaction",
	} {
		resp := srv.handleRequest(context.Background(), &Request{JSONRPC: "2.0", Method: method, ID: 1})
		if resp.Error == nil || resp.Error.Code != ErrCodeMethodNotFound {
			t.Errorf("%s should no longer be registered (standard methods moved to eth_), got: %v", method, resp.Error)
		}
	}
}

func TestQauMethodsAccepted(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("eth_blockNumber", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "0x1", nil
	})

	resp := srv.handleRequest(context.Background(), &Request{JSONRPC: "2.0", Method: "eth_blockNumber", ID: 1})

	if resp.Error != nil {
		t.Errorf("eth_blockNumber should be accepted, got error: %v", resp.Error)
	}
}
