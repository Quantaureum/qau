// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ── API methods with full parameter paths ──

func TestGetBalance_WithParams(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0x1234567890123456789012345678901234567890")
	params, _ := json.Marshal([]string{addr.ToHexAddress(), "latest"})
	result, err := api.GetBalance(ctx(), params)
	requireOK(t, result, err)
}

func TestGetTransactionCount_Earliest(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0x1234567890123456789012345678901234567890")
	params, _ := json.Marshal([]string{addr.ToHexAddress(), "earliest"})
	result, err := api.GetTransactionCount(ctx(), params)
	requireOK(t, result, err)
}

func TestGetCode_WithCode(t *testing.T) {
	sr := newMockStateReader()
	addr := types.BytesToAddress([]byte{1})
	sr.codes[addr] = []byte{0x60, 0x80}
	api := NewAPI(sr, newMockBlockReader(), newMockTxPool(), newMockChainInfo(), &mockAccountManager{})
	params, _ := json.Marshal([]string{addr.ToHexAddress(), "latest"})
	result, err := api.GetCode(ctx(), params)
	requireOK(t, result, err)
	if result.(string) == "0x" {
		t.Error("expected non-empty code")
	}
}

func TestGetStorageAt_WithValue(t *testing.T) {
	sr := newMockStateReader()
	addr := types.BytesToAddress([]byte{1})
	var key types.Hash
	key[0] = 0x01
	var val types.Hash
	val[31] = 0x42
	sr.storage[addr] = map[types.Hash]types.Hash{key: val}
	api := NewAPI(sr, newMockBlockReader(), newMockTxPool(), newMockChainInfo(), &mockAccountManager{})
	params, _ := json.Marshal([]string{addr.ToHexAddress(), "0x0000000000000000000000000000000000000000000000000000000000000001", "latest"})
	result, err := api.GetStorageAt(ctx(), params)
	requireOK(t, result, err)
}

func TestGetBlockByNumber_Hex(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]any{"0x0", false})
	_, err := api.GetBlockByNumber(ctx(), params)
	_ = err
}

func TestGetBlockByNumber_WithFullTx(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]any{"latest", true})
	_, err := api.GetBlockByNumber(ctx(), params)
	_ = err
}

func TestGetBlockByHash_WithFullTx(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]any{"0x0000000000000000000000000000000000000000000000000000000000000001", true})
	_, err := api.GetBlockByHash(ctx(), params)
	_ = err
}

func TestSendRawTransaction_ValidHex(t *testing.T) {
	api := newTestAPI()
	// Create a minimal hex data that looks like a transaction
	hexData := "0x0101" // minimal valid hex
	params, _ := json.Marshal([]string{hexData})
	_, err := api.SendRawTransaction(ctx(), params)
	_ = err
}

func TestEstimateGas_Transfer(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0x1234567890123456789012345678901234567890")
	params, _ := json.Marshal([]map[string]string{{
		"from":  addr.ToHexAddress(),
		"to":    addr.ToHexAddress(),
		"value": "0x1",
	}})
	result, err := api.EstimateGas(ctx(), params)
	requireOK(t, result, err)
}

func TestEstimateGas_WithData(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0x1234567890123456789012345678901234567890")
	params, _ := json.Marshal([]map[string]string{{
		"from": addr.ToHexAddress(),
		"to":   addr.ToHexAddress(),
		"data": "0x60806040526000",
	}})
	result, err := api.EstimateGas(ctx(), params)
	requireOK(t, result, err)
}

func TestEstimateGas_WithValue(t *testing.T) {
	api := newTestAPI()
	addr := mustParseAddress(t, "0x1234567890123456789012345678901234567890")
	params, _ := json.Marshal([]map[string]string{{
		"from":  addr.ToHexAddress(),
		"to":    addr.ToHexAddress(),
		"value": "0xde0b6b3a7640000", // 1 QAU
	}})
	result, err := api.EstimateGas(ctx(), params)
	requireOK(t, result, err)
}

func TestCall_WithContractCallerFull(t *testing.T) {
	api := newTestAPIFull()
	addr := mustParseAddress(t, "0x1234567890123456789012345678901234567890")
	params, _ := json.Marshal([]map[string]string{{
		"from": addr.ToHexAddress(),
		"to":   addr.ToHexAddress(),
		"data": "0x60806040",
	}})
	result, err := api.Call(ctx(), params)
	requireOK(t, result, err)
}

// ── Staking methods with full parameters ──

func TestStake_NoStakingManager(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]any{
		"0x1234567890123456789012345678901234567890",
		"0xde0b6b3a7640000",
		"0",
		"nonce1",
		"sig1",
		"pubkey1",
	})
	_, err := api.Stake(ctx(), params)
	requireErr(t, nil, err)
}

func TestUnstake_NoStakingManager(t *testing.T) {
	api := newTestAPI()
	params, _ := json.Marshal([]any{
		"0x1234567890123456789012345678901234567890",
		"0xde0b6b3a7640000",
		"nonce1",
		"sig1",
		"pubkey1",
	})
	_, err := api.Unstake(ctx(), params)
	requireErr(t, nil, err)
}

func TestClaimRewards_WithStakingManager(t *testing.T) {
	api := newTestAPIFull()
	params, _ := json.Marshal([]any{
		"0x1234567890123456789012345678901234567890",
		"nonce1",
		"sig1",
		"pubkey1",
	})
	_, err := api.ClaimRewards(ctx(), params)
	_ = err
}

func TestCompoundRewards_WithStakingManager(t *testing.T) {
	api := newTestAPIFull()
	params, _ := json.Marshal([]any{
		"0x1234567890123456789012345678901234567890",
		"nonce1",
		"sig1",
		"pubkey1",
	})
	_, err := api.CompoundRewards(ctx(), params)
	_ = err
}

func TestGetUserStakes_WithStakingManager(t *testing.T) {
	api := newTestAPIFull()
	params, _ := json.Marshal([]string{"0x1234567890123456789012345678901234567890"})
	result, err := api.GetUserStakes(ctx(), params)
	requireOK(t, result, err)
}

func TestGetUnstakeStatus_WithStakingManager(t *testing.T) {
	api := newTestAPIFull()
	params, _ := json.Marshal([]string{"0x1234567890123456789012345678901234567890"})
	result, err := api.GetUnstakeStatus(ctx(), params)
	requireOK(t, result, err)
}

func TestGetPendingRewards_WithStakingManager(t *testing.T) {
	api := newTestAPIFull()
	params, _ := json.Marshal([]string{"0x1234567890123456789012345678901234567890"})
	result, err := api.GetPendingRewards(ctx(), params)
	requireOK(t, result, err)
}

func TestGetContractBalance_WithStakingManager(t *testing.T) {
	api := newTestAPIFull()
	params, _ := json.Marshal([]string{"0x1234567890123456789012345678901234567890"})
	result, err := api.GetContractBalance(ctx(), params)
	requireOK(t, result, err)
}

func TestGetContractList_WithStakingManager(t *testing.T) {
	api := newTestAPIFull()
	params, _ := json.Marshal([]map[string]any{{"limit": 10}})
	result, err := api.GetContractList(ctx(), params)
	requireOK(t, result, err)
}

// ── FormatBlock with various block configurations ──

func TestFormatBlock_GenesisBlock(t *testing.T) {
	proposer := types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	blk := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       0,
			Timestamp:    1700000000,
			ProposerAddr: proposer,
			GasLimit:     30000000,
			GasUsed:      0,
			ChainID:      1668,
			Slot:         0,
			Epoch:        0,
		},
		Transactions: nil,
	}
	result := FormatBlock(blk, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Number != "0x0" {
		t.Errorf("expected number 0x0, got %s", result.Number)
	}
}

func TestFormatBlock_WithAttestations(t *testing.T) {
	proposer := types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	blk := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       10,
			Timestamp:    1700000000,
			ProposerAddr: proposer,
			GasLimit:     30000000,
			Attestations: []byte{0x01, 0x02, 0x03},
		},
	}
	result := FormatBlock(blk, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ── FormatTransaction with various types ──

func TestFormatTransaction_Staking(t *testing.T) {
	from := types.BytesToAddress([]byte{1})
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeStake,
		Nonce:    1,
		From:     from,
		To:       nil,
		Value:    big.NewInt(1000),
		GasLimit: 53000,
		GasPrice: big.NewInt(1e9),
		ChainID:  1668,
	}
	result := FormatTransaction(tx, types.Hash{}, 1, 0)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ── Server handleRequest with various scenarios ──

func TestHandleRequest_WithParams(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	params, _ := json.Marshal([]string{"0x1234567890123456789012345678901234567890", "latest"})
	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "eth_getBalance",
		Params:  params,
		ID:      1,
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
}

func TestHandleRequest_InvalidParams(t *testing.T) {
	srv := NewServer(nil)
	api := newTestAPI()
	api.RegisterHandlers(srv)

	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "eth_getBalance",
		Params:  json.RawMessage(`"invalid"`),
		ID:      1,
	})
	if resp.Error == nil {
		t.Error("expected error for invalid params")
	}
}

// ── AuthManager edge cases ──

func TestAuthManager_ValidateAdminRequest_NoKey(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	r := httptest.NewRequest("POST", "/", nil)
	err := am.ValidateAdminRequest(r, "admin_secret")
	if err == nil {
		t.Error("expected error for admin request without API key")
	}
}

func TestAuthManager_ValidateAdminRequest_WithKey(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.Enabled = true
	cfg.EnableHMAC = false
	cfg.APIKeys = make(map[string]*APIKeyInfo)
	cfg.APIKeyHeader = "X-API-Key"
	am := NewAuthManager(cfg)
	defer am.Stop()

	info, _ := am.GenerateAPIKey("admin-test", []string{"*"}, 0)

	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("X-API-Key", info.Key)
	err := am.ValidateAdminRequest(r, "admin_secret")
	if err != nil {
		t.Errorf("expected admin request with valid key to succeed, got: %v", err)
	}
}

func TestAuthManager_APIKeyUsageCount(t *testing.T) {
	am := NewAuthManager(nil)
	defer am.Stop()

	info, _ := am.GenerateAPIKey("usage-test", []string{"*"}, 0)
	retrieved := am.GetAPIKeyInfo(info.Key)
	if retrieved == nil {
		t.Fatal("expected to retrieve API key info")
	}
	// UsageCount should start at 0
	if retrieved.UsageCount.Load() != 0 {
		t.Errorf("expected UsageCount 0, got %d", retrieved.UsageCount.Load())
	}
}

// ── RateLimiter with high load ──

func TestRateLimiter_HighLoad(t *testing.T) {
	cfg := &RateLimitConfig{
		Enabled:         true,
		GlobalRateLimit: 1000,
		BurstSize:       100,
	}
	rl := NewRateLimiter(cfg)
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = "192.168.1.1:12345"
		err := rl.Allow(r, "eth_chainId")
		if err != nil {
			t.Errorf("request %d should be allowed, got: %v", i, err)
		}
	}
}

// ── PersonalAPI ImportRawKey ──

func TestPersonalAPI_ImportRawKey_NoParams(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	_, err := api.ImportRawKey(context.Background(), nil)
	requireErr(t, nil, err)
}

func TestPersonalAPI_ImportRawKey_InvalidKey(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	params, _ := json.Marshal([]string{"not-a-key", "password"})
	_, err := api.ImportRawKey(context.Background(), params)
	requireErr(t, nil, err)
}

func TestPersonalAPI_UnlockAccount_NoParams(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	_, err := api.UnlockAccount(context.Background(), nil)
	requireErr(t, nil, err)
}

func TestPersonalAPI_Sign_NoParams(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	_, err := api.Sign(context.Background(), nil)
	requireErr(t, nil, err)
}

func TestPersonalAPI_SendTransaction_NoParams(t *testing.T) {
	api := NewPersonalAPI(t.TempDir(), newMockTxPool(), newMockStateReader(), newMockChainInfo())
	_, err := api.SendTransaction(context.Background(), nil)
	requireErr(t, nil, err)
}
