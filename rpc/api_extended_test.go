// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ── Additional mock implementations ──

type mockStakingManager struct {
	stakes           map[types.Address]*StakeInfo
	unstakeRequests  map[types.Address]*UnstakeRequest
	totalStaked      *big.Int
	allStakes        []*StakeInfo
	config           *StakingConfig
	validatorCount   int
	activeCount      int
	activeValidators map[types.Address]*big.Int
}

func newMockStakingManager() *mockStakingManager {
	return &mockStakingManager{
		stakes:           make(map[types.Address]*StakeInfo),
		unstakeRequests:  make(map[types.Address]*UnstakeRequest),
		totalStaked:      big.NewInt(0),
		activeValidators: make(map[types.Address]*big.Int),
		config: &StakingConfig{
			MinStakeAmount:  big.NewInt(1000),
			MaxStakeAmount:  big.NewInt(1e18),
			UnbondingPeriod: 86400,
			MaxValidators:   100,
			MinCommission:   0,
			MaxCommission:   100,
		},
	}
}

func (m *mockStakingManager) Stake(addr types.Address, amount *big.Int, commission uint32, blockHeight uint64) error {
	m.stakes[addr] = &StakeInfo{
		Address:     addr,
		Amount:      amount,
		Commission:  commission,
		StakeHeight: blockHeight,
		Active:      true,
	}
	m.totalStaked = new(big.Int).Add(m.totalStaked, amount)
	return nil
}
func (m *mockStakingManager) RequestUnstake(addr types.Address, amount *big.Int, blockHeight uint64) error {
	m.unstakeRequests[addr] = &UnstakeRequest{
		Address:       addr,
		Amount:        amount,
		RequestHeight: blockHeight,
		UnlockHeight:  blockHeight + 86400,
	}
	return nil
}
func (m *mockStakingManager) CompleteUnstake(addr types.Address, currentHeight uint64) (*big.Int, error) {
	return big.NewInt(1000), nil
}
func (m *mockStakingManager) GetStake(addr types.Address) (*StakeInfo, error) {
	if s, ok := m.stakes[addr]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("stake not found for %s", addr.ToHexAddress())
}
func (m *mockStakingManager) GetUnstakeRequest(addr types.Address) (*UnstakeRequest, error) {
	if r, ok := m.unstakeRequests[addr]; ok {
		return r, nil
	}
	return &UnstakeRequest{Address: addr, Amount: big.NewInt(0), UnlockHeight: 100}, nil
}
func (m *mockStakingManager) GetTotalStaked() *big.Int   { return m.totalStaked }
func (m *mockStakingManager) GetAllStakes() []*StakeInfo { return m.allStakes }
func (m *mockStakingManager) GetActiveValidators() map[types.Address]*big.Int {
	return m.activeValidators
}
func (m *mockStakingManager) ValidatorCount() int       { return m.validatorCount }
func (m *mockStakingManager) ActiveValidatorCount() int { return m.activeCount }
func (m *mockStakingManager) GetConfig() *StakingConfig { return m.config }
func (m *mockStakingManager) GetRewardPoolStatus() map[string]any {
	return map[string]any{
		"totalDistributed": big.NewInt(0),
		"poolCap":          big.NewInt(1000000),
		"remaining":        big.NewInt(1000000),
	}
}
func (m *mockStakingManager) GetTotalRewardsClaimed() *big.Int { return big.NewInt(0) }
func (m *mockStakingManager) UpdateCommission(caller, addr types.Address, commission uint32) error {
	if s, ok := m.stakes[addr]; ok {
		s.Commission = commission
		return nil
	}
	return fmt.Errorf("stake not found")
}

func (m *mockStakingManager) SaveState() error {
	return nil
}

type mockContractCaller struct {
	returnData []byte
	gasUsed    uint64
	callErr    error
}

func newMockContractCaller() *mockContractCaller {
	return &mockContractCaller{returnData: []byte{0x01}, gasUsed: 21000}
}

func (m *mockContractCaller) Call(req *ContractCallRequest) (*ContractCallResult, error) {
	if m.callErr != nil {
		return nil, m.callErr
	}
	return &ContractCallResult{ReturnData: m.returnData, GasUsed: m.gasUsed}, nil
}

type mockSnapshotManager struct {
	snapshots map[uint64]map[string]any
}

func newMockSnapshotManager() *mockSnapshotManager {
	return &mockSnapshotManager{snapshots: make(map[uint64]map[string]any)}
}

func (m *mockSnapshotManager) CreateSnapshot(blockHeight uint64) (map[string]any, error) {
	snap := map[string]any{"height": blockHeight, "id": "snap-1"}
	m.snapshots[blockHeight] = snap
	return snap, nil
}

func (m *mockSnapshotManager) RestoreSnapshot(blockHeight uint64) (map[string]any, error) {
	if s, ok := m.snapshots[blockHeight]; ok {
		return s, nil
	}
	return nil, nil
}

// ── Helper: create API with all mocks ──

func newTestAPIFull() *API {
	api := NewAPI(
		newMockStateReader(),
		newMockBlockReader(),
		newMockTxPool(),
		newMockChainInfo(),
		&mockAccountManager{},
	)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	api.SetStakingManager(newMockStakingManager())
	api.SetContractCaller(newMockContractCaller())
	api.SetSnapshotManager(newMockSnapshotManager())
	return api
}

// ── parseAddress tests ──

func TestParseAddress_HexFormat(t *testing.T) {
	addr, err := parseAddress("0x1234567890123456789012345678901234567890")
	if err != nil {
		t.Fatalf("parseAddress failed: %v", err)
	}
	if addr.IsEmpty() {
		t.Error("expected non-empty address")
	}
}

func TestParseAddress_InvalidHex(t *testing.T) {
	_, err := parseAddress("not-an-address")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestParseAddress_ShortHex(t *testing.T) {
	_, err := parseAddress("0x1234")
	if err == nil {
		t.Error("expected error for short hex address")
	}
}

// ── parseHash tests ──

func TestParseHash_Valid(t *testing.T) {
	h, err := parseHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("parseHash failed: %v", err)
	}
	if h == (types.Hash{}) {
		t.Error("expected non-zero hash")
	}
}

func TestParseHash_ShortHash(t *testing.T) {
	h, err := parseHash("0x1")
	if err != nil {
		t.Fatalf("parseHash short hash failed: %v", err)
	}
	// Short hashes should be padded
	if h == (types.Hash{}) {
		t.Error("expected padded hash, got zero")
	}
}

func TestParseHash_InvalidHex(t *testing.T) {
	_, err := parseHash("zzzz")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

// ── parseHexBytes tests ──

func TestParseHexBytes_Valid(t *testing.T) {
	b, err := parseHexBytes("0x60806040")
	if err != nil {
		t.Fatalf("parseHexBytes failed: %v", err)
	}
	if len(b) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(b))
	}
}

func TestParseHexBytes_OddLength(t *testing.T) {
	b, err := parseHexBytes("0xabc")
	if err != nil {
		t.Fatalf("parseHexBytes odd length failed: %v", err)
	}
	if len(b) != 2 {
		t.Errorf("expected 2 bytes, got %d", len(b))
	}
}

func TestParseHexBytes_NoPrefix(t *testing.T) {
	b, err := parseHexBytes("6080")
	if err != nil {
		t.Fatalf("parseHexBytes no prefix failed: %v", err)
	}
	if len(b) != 2 {
		t.Errorf("expected 2 bytes, got %d", len(b))
	}
}

// ── parseBlockNumber tests ──

func TestParseBlockNumber_Latest(t *testing.T) {
	br := newMockBlockReader()
	height, err := parseBlockNumber("latest", br)
	if err != nil {
		t.Fatalf("parseBlockNumber latest failed: %v", err)
	}
	if height != 100 {
		t.Errorf("expected 100, got %d", height)
	}
}

func TestParseBlockNumber_Pending(t *testing.T) {
	br := newMockBlockReader()
	height, err := parseBlockNumber("pending", br)
	if err != nil {
		t.Fatalf("parseBlockNumber pending failed: %v", err)
	}
	if height != 100 {
		t.Errorf("expected 100, got %d", height)
	}
}

func TestParseBlockNumber_Earliest(t *testing.T) {
	height, err := parseBlockNumber("earliest", nil)
	if err != nil {
		t.Fatalf("parseBlockNumber earliest failed: %v", err)
	}
	if height != 0 {
		t.Errorf("expected 0, got %d", height)
	}
}

func TestParseBlockNumber_Hex(t *testing.T) {
	height, err := parseBlockNumber("0xa", nil)
	if err != nil {
		t.Fatalf("parseBlockNumber hex failed: %v", err)
	}
	if height != 10 {
		t.Errorf("expected 10, got %d", height)
	}
}

func TestParseBlockNumber_InvalidHex(t *testing.T) {
	_, err := parseBlockNumber("xyz", nil)
	if err == nil {
		t.Error("expected error for invalid hex block number")
	}
}

func TestParseBlockNumber_NilReader(t *testing.T) {
	height, err := parseBlockNumber("latest", nil)
	if err != nil {
		t.Fatalf("parseBlockNumber latest with nil reader failed: %v", err)
	}
	if height != 0 {
		t.Errorf("expected 0 with nil reader, got %d", height)
	}
}

// ── stripHexPrefix tests ──

func TestStripHexPrefix_WithPrefix(t *testing.T) {
	if s := stripHexPrefix("0xabc"); s != "abc" {
		t.Errorf("expected 'abc', got '%s'", s)
	}
}

func TestStripHexPrefix_UpperCase(t *testing.T) {
	if s := stripHexPrefix("0Xabc"); s != "abc" {
		t.Errorf("expected 'abc', got '%s'", s)
	}
}

func TestStripHexPrefix_NoPrefix(t *testing.T) {
	if s := stripHexPrefix("abc"); s != "abc" {
		t.Errorf("expected 'abc', got '%s'", s)
	}
}

// ── formatHexUint64 tests ──

func TestFormatHexUint64_Zero(t *testing.T) {
	if s := formatHexUint64(0); s != "0x0" {
		t.Errorf("expected '0x0', got '%s'", s)
	}
}

func TestFormatHexUint64_NonZero(t *testing.T) {
	if s := formatHexUint64(255); s != "0xff" {
		t.Errorf("expected '0xff', got '%s'", s)
	}
}

func TestFormatHexUint64_Large(t *testing.T) {
	if s := formatHexUint64(1668); s != "0x684" {
		t.Errorf("expected '0x684', got '%s'", s)
	}
}

// ── SendRawTransaction tests ──

func TestSendRawTransaction_EmptyData(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"0x"})
	_, err := api.SendRawTransaction(ctx(), params)
	requireErr(t, nil, err)
}

func TestSendRawTransaction_InvalidHex(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-hex"})
	_, err := api.SendRawTransaction(ctx(), params)
	requireErr(t, nil, err)
}

func TestSendRawTransaction_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.SendRawTransaction(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetBlockByHash tests ──

func TestGetBlockByHash_InvalidHash(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]any{"not-a-hash", false})
	_, err := api.GetBlockByHash(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetBlockByHash_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetBlockByHash(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetBlockByNumber tests ──

func TestGetBlockByNumber_Latest(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]any{"latest", false})
	_, err := api.GetBlockByNumber(ctx(), params)
	// mock returns nil, no error expected
	if err != nil && err.Code != ErrCodeNotFound {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetBlockByNumber_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetBlockByNumber(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetTransactionByHash tests ──

func TestGetTransactionByHash_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetTransactionByHash(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetTransactionByHash_InvalidHash(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-a-hash"})
	_, err := api.GetTransactionByHash(ctx(), params)
	requireErr(t, nil, err)
}

// ── GetTransactionReceipt tests ──

func TestGetTransactionReceipt_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetTransactionReceipt(ctx(), nil)
	requireErr(t, nil, err)
}

// ── EstimateGas tests ──

func TestEstimateGas_ContractCreation(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0x1234567890123456789012345678901234567890")
	params, _ := json.Marshal([]map[string]string{{
		"from": addr.ToHexAddress(),
		"data": "0x60806040",
	}})
	result, err := api.EstimateGas(ctx(), params)
	requireOK(t, result, err)
	// Contract creation should add 32000 overhead
	gasStr := result.(string)
	if gasStr == "0x0" {
		t.Error("expected non-zero gas for contract creation")
	}
}

func TestEstimateGas_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.EstimateGas(ctx(), nil)
	requireErr(t, nil, err)
}

// ── SendTransaction tests ──

func TestSendTransaction_NoFrom(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]map[string]any{{"to": "0x0000000000000000000000000000000000000001"}})
	_, err := api.SendTransaction(ctx(), params)
	requireErr(t, nil, err)
}

func TestSendTransaction_InvalidFrom(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]map[string]any{{"from": "not-an-address"}})
	_, err := api.SendTransaction(ctx(), params)
	requireErr(t, nil, err)
}

func TestSendTransaction_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.SendTransaction(ctx(), nil)
	requireErr(t, nil, err)
}

// ── Net methods ──

func TestNetPeerCount(t *testing.T) {
	api := newTestAPI()
	result, err := api.NetPeerCount(ctx(), nil)
	requireOK(t, result, err)
}

// ── TxPoolContent ──

func TestTxPoolContent(t *testing.T) {
	api := newTestAPI()
	result, err := api.TxPoolContent(ctx(), nil)
	requireOK(t, result, err)
}

// ── PendingTransactions ──

func TestPendingTransactions(t *testing.T) {
	api := newTestAPI()
	result, err := api.PendingTransactions(ctx(), nil)
	requireOK(t, result, err)
}

// ── Web3Sha3 edge cases ──

func TestWeb3Sha3_InvalidInput(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"not-hex"})
	_, err := api.Web3Sha3(ctx(), params)
	requireErr(t, nil, err)
}

func TestWeb3Sha3_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.Web3Sha3(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetCode edge cases ──

func TestGetCode_NoCode(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0x0000000000000000000000000000000000000000")
	params, _ := json.Marshal([]string{addr.ToHexAddress(), "latest"})
	result, err := api.GetCode(ctx(), params)
	requireOK(t, result, err)
	if result.(string) != "0x" {
		t.Errorf("expected '0x' for no code, got %v", result)
	}
}

func TestGetCode_InvalidAddress(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"bad-address", "latest"})
	_, err := api.GetCode(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetCode_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetCode(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetStorageAt edge cases ──

func TestGetStorageAt_InvalidAddress(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"bad-address", "0x0", "latest"})
	_, err := api.GetStorageAt(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetStorageAt_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetStorageAt(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetTransactionCount edge cases ──

func TestGetTransactionCount_InvalidAddress(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"bad-address", "latest"})
	_, err := api.GetTransactionCount(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetTransactionCount_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetTransactionCount(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetBalance edge cases ──

func TestGetBalance_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetBalance(ctx(), nil)
	requireErr(t, nil, err)
}

// ── SetStakingManager nil check ──

func TestSetStakingManager_Nil(t *testing.T) {
	api := newTestAPI()
	api.SetStakingManager(nil) // should not panic
}

// ── SetContractCaller nil check ──

func TestSetContractCaller_Nil(t *testing.T) {
	api := newTestAPI()
	api.SetContractCaller(nil) // should not panic
}

// ── SetSnapshotManager nil check ──

func TestSetSnapshotManager_Nil(t *testing.T) {
	api := newTestAPI()
	api.SetSnapshotManager(nil) // should not panic
}

// ── SetPrivacyManager nil check ──

func TestSetPrivacyManager_Nil(t *testing.T) {
	api := newTestAPI()
	api.SetPrivacyManager(nil) // should not panic
}

// ── requireStakingManager ──

func TestRequireStakingManager_NotSet(t *testing.T) {
	api := newTestAPI()
	// stakingManager is nil by default
	err := api.requireStakingManager()
	if err == nil {
		t.Error("expected error when staking manager not set")
	}
}

func TestRequireStakingManager_Set(t *testing.T) {
	api := newTestAPIFull()
	err := api.requireStakingManager()
	if err != nil {
		t.Errorf("expected no error when staking manager set, got %v", err)
	}
}

// ── requireTxPool ──

func TestRequireTxPool_Set(t *testing.T) {
	api := newTestAPI()
	err := api.requireTxPool()
	if err != nil {
		t.Errorf("expected no error when tx pool set, got %v", err)
	}
}

// ── Staking methods ──

func TestGetStake_NoStakingManager(t *testing.T) {
	api := newTestAPI() // no staking manager
	params, _ := json.Marshal([]string{"0x1234567890123456789012345678901234567890"})
	_, err := api.GetStake(ctx(), params)
	requireErr(t, nil, err)
}

func TestGetStakingPools_NoStakingManager(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetStakingPools(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetStakingStats_NoStakingManager(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetStakingStats(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetStakingStats_WithManager(t *testing.T) {
	api := newTestAPIFull()
	result, err := api.GetStakingStats(ctx(), nil)
	requireOK(t, result, err)
}

func TestGetPendingRewards_NoStakingManager(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetPendingRewards(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetUnstakeStatus_NoStakingManager(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetUnstakeStatus(ctx(), nil)
	requireErr(t, nil, err)
}

// ── SupportedEntryPoints ──

func TestSupportedEntryPoints(t *testing.T) {
	api := newTestAPI()
	result, err := api.SupportedEntryPoints(ctx(), nil)
	requireOK(t, result, err)
}

// ── CreateSnapshot / RestoreSnapshot ──

func TestCreateSnapshot_NoManager(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"0x1"})
	_, err := api.CreateSnapshot(ctx(), params)
	requireErr(t, nil, err)
}

func TestRestoreSnapshot_NoManager(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]string{"0x1"})
	_, err := api.RestoreSnapshot(ctx(), params)
	requireErr(t, nil, err)
}

func TestCreateSnapshot_WithManager(t *testing.T) {
	api := newTestAPIFull()
	params, _ := json.Marshal([]string{"0x1"})
	result, err := api.CreateSnapshot(ctx(), params)
	requireOK(t, result, err)
}

func TestRestoreSnapshot_WithManager(t *testing.T) {
	api := newTestAPIFull()
	params, _ := json.Marshal([]string{"0x1"})
	result, err := api.RestoreSnapshot(ctx(), params)
	requireOK(t, result, err)
}

// ── QPOSStatus ──

func TestQPOSStatus_NilChainInfo(t *testing.T) {
	api := NewAPI(
		newMockStateReader(),
		newMockBlockReader(),
		newMockTxPool(),
		nil,
		&mockAccountManager{},
	)
	_, err := api.QPOSStatus(ctx(), nil)
	if err != nil {
		t.Errorf("QPOSStatus should handle nil chainInfo, got: %v", err)
	}
}

// ── RegisterHandlers completeness ──

func TestRegisterHandlers_AllMethods(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPIFull()
	api.RegisterHandlers(srv)

	expectedMethods := []string{
		"eth_chainId", "eth_blockNumber",
		"eth_getBalance", "eth_getTransactionCount",
		"eth_getCode", "eth_getStorageAt",
		"eth_sendRawTransaction", "eth_estimateGas",
		"net_version", "net_peerCount", "net_listening",
		"web3_clientVersion", "web3_sha3",
	}

	for _, method := range expectedMethods {
		if _, ok := srv.handlers[method]; !ok {
			t.Errorf("expected handler for method %s", method)
		}
	}
}

// ── HandleRequest with various RPC versions ──

func TestHandleRequest_ValidJSONRPC(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "eth_chainId",
		ID:      42,
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
	if resp.ID != 42 {
		t.Errorf("expected ID 42, got %v", resp.ID)
	}
}

func TestHandleRequest_NilID(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("qau_test", func(ctx context.Context, params json.RawMessage) (any, *Error) {
		return "ok", nil
	})

	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "qau_test",
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
}

// ── Error code constants ──

func TestErrorCodes(t *testing.T) {
	if ErrCodeParse != -32700 {
		t.Errorf("expected ErrCodeParse -32700, got %d", ErrCodeParse)
	}
	if ErrCodeInvalidRequest != -32600 {
		t.Errorf("expected ErrCodeInvalidRequest -32600, got %d", ErrCodeInvalidRequest)
	}
	if ErrCodeMethodNotFound != -32601 {
		t.Errorf("expected ErrCodeMethodNotFound -32601, got %d", ErrCodeMethodNotFound)
	}
	if ErrCodeInvalidParams != -32602 {
		t.Errorf("expected ErrCodeInvalidParams -32602, got %d", ErrCodeInvalidParams)
	}
	if ErrCodeInternal != -32603 {
		t.Errorf("expected ErrCodeInternal -32603, got %d", ErrCodeInternal)
	}
}

// ── parseUint64 ──

func TestParseUint64_Valid(t *testing.T) {
	val, err := parseUint64("0xff")
	if err != nil {
		t.Fatalf("parseUint64 failed: %v", err)
	}
	if val != 255 {
		t.Errorf("expected 255, got %d", val)
	}
}

func TestParseUint64_Zero(t *testing.T) {
	val, err := parseUint64("0x0")
	if err != nil {
		t.Fatalf("parseUint64 failed: %v", err)
	}
	if val != 0 {
		t.Errorf("expected 0, got %d", val)
	}
}

func TestParseUint64_Empty(t *testing.T) {
	val, err := parseUint64("")
	if err != nil {
		t.Fatalf("parseUint64 empty failed: %v", err)
	}
	if val != 0 {
		t.Errorf("expected 0, got %d", val)
	}
}

func TestParseUint64_Invalid(t *testing.T) {
	_, err := parseUint64("zzz")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

// ── parseBigInt ──

func TestParseBigInt_Valid(t *testing.T) {
	val, err := parseBigInt("0xff")
	if err != nil {
		t.Fatalf("parseBigInt failed: %v", err)
	}
	if val.Int64() != 255 {
		t.Errorf("expected 255, got %d", val.Int64())
	}
}

func TestParseBigInt_Empty(t *testing.T) {
	val, err := parseBigInt("")
	if err != nil {
		t.Fatalf("parseBigInt empty failed: %v", err)
	}
	if val.Int64() != 0 {
		t.Errorf("expected 0, got %d", val.Int64())
	}
}

// ── formatHexBig ──

func TestFormatHexBig_Nil(t *testing.T) {
	if s := formatHexBig(nil); s != "0x0" {
		t.Errorf("expected '0x0', got '%s'", s)
	}
}

func TestFormatHexBig_Value(t *testing.T) {
	if s := formatHexBig(big.NewInt(256)); s != "0x100" {
		t.Errorf("expected '0x100', got '%s'", s)
	}
}

// ── GetBlockTransactionCountByHash ──

func TestGetBlockTransactionCountByHash_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetBlockTransactionCountByHash(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetBlockTransactionCountByNumber ──

func TestGetBlockTransactionCountByNumber_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetBlockTransactionCountByNumber(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetTransactionByBlockHashAndIndex ──

func TestGetTransactionByBlockHashAndIndex_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetTransactionByBlockHashAndIndex(ctx(), nil)
	requireErr(t, nil, err)
}

// ── GetTransactionByBlockNumberAndIndex ──

func TestGetTransactionByBlockNumberAndIndex_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetTransactionByBlockNumberAndIndex(ctx(), nil)
	requireErr(t, nil, err)
}

// ── UserOperation methods ──

func TestSendUserOperation_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.SendUserOperation(ctx(), nil)
	requireErr(t, nil, err)
}

func TestEstimateUserOperationGas_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.EstimateUserOperationGas(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetUserOperationByHash_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetUserOperationByHash(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetUserOperationReceipt_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetUserOperationReceipt(ctx(), nil)
	requireErr(t, nil, err)
}
