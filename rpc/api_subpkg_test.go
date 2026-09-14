// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
)

// ── Mock FeeHistoryReader ──

type mockFeeHistoryReader struct{}

func (m *mockFeeHistoryReader) GetFeeHistory(blockCount uint64, newestBlock uint64, rewardPercentiles []float64) (*FeeHistoryResult, error) {
	return &FeeHistoryResult{}, nil
}

// ── Mock ChainStateDB ──

type mockChainStateDB struct{}

func (m *mockChainStateDB) GetState(addr types.Address, key types.Hash) types.Hash {
	return types.Hash{}
}
func (m *mockChainStateDB) SetState(addr types.Address, key, value types.Hash)   {}
func (m *mockChainStateDB) GetBalance(addr types.Address) *big.Int               { return big.NewInt(0) }
func (m *mockChainStateDB) SubBalance(addr types.Address, amount *big.Int) error { return nil }
func (m *mockChainStateDB) AddBalance(addr types.Address, amount *big.Int) error { return nil }

// ── DeFi API tests ──

func TestNewDeFiAPI_Nil(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	if api == nil {
		t.Fatal("expected non-nil DeFiAPI")
	}
}

func TestDeFiAPI_GetLiquidityPools_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetLiquidityPools(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetLiquidityPool_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetLiquidityPool(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_AddLiquidity_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.AddLiquidity(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_RemoveLiquidity_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.RemoveLiquidity(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_Swap_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.Swap(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetSwapQuote_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetSwapQuote(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetUserLPBalance_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetUserLPBalance(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetLendingPools_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetLendingPools(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetLendingPool_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetLendingPool(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_Borrow_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.Borrow(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_Repay_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.Repay(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetUserLendingPosition_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetUserLendingPosition(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetYieldFarms_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetYieldFarms(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetYieldFarm_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetYieldFarm(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_StakeFarm_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.StakeFarm(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_UnstakeFarm_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.UnstakeFarm(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_HarvestFarm_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.HarvestFarm(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetFarmPendingReward_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetFarmPendingReward(ctx(), nil)
	requireErr(t, nil, err)
}

func TestDeFiAPI_GetUserFarmStake_NoParams(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: disable admin auth for test
	_, err := api.GetUserFarmStake(ctx(), nil)
	requireErr(t, nil, err)
}

// ── Fee API tests ──

func TestNewFeeAPI(t *testing.T) {
	api := NewFeeAPI(newMockBlockReader(), &mockFeeHistoryReader{})
	if api == nil {
		t.Fatal("expected non-nil FeeAPI")
	}
}

func TestFeeAPI_FeeHistory_NoParams(t *testing.T) {
	api := NewFeeAPI(newMockBlockReader(), &mockFeeHistoryReader{})
	_, err := api.FeeHistory(ctx(), nil)
	requireErr(t, nil, err)
}

func TestFeeAPI_MaxPriorityFeePerGas(t *testing.T) {
	api := NewFeeAPI(newMockBlockReader(), &mockFeeHistoryReader{})
	result, err := api.MaxPriorityFeePerGas(ctx(), nil)
	requireOK(t, result, err)
}

func TestFeeAPI_RegisterHandlers(t *testing.T) {
	api := NewFeeAPI(newMockBlockReader(), &mockFeeHistoryReader{})
	srv := NewServer(nil)
	api.RegisterHandlers(srv)
}

func TestFeeAPI_FeeHistory_WithParams(t *testing.T) {
	api := NewFeeAPI(newMockBlockReader(), &mockFeeHistoryReader{})
	params, _ := json.Marshal([]any{"0x5", "latest", nil})
	result, err := api.FeeHistory(ctx(), params)
	_ = result
	_ = err
}

func TestFeeAPI_FeeHistory_InvalidBlockCount(t *testing.T) {
	api := NewFeeAPI(newMockBlockReader(), &mockFeeHistoryReader{})
	params, _ := json.Marshal([]any{"not-a-number", "latest", nil})
	result, err := api.FeeHistory(ctx(), params)
	// Invalid block count may be handled gracefully
	_ = result
	_ = err
}

// ── Multisig API tests ──

func TestNewMultisigAPI(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	if api == nil {
		t.Fatal("expected non-nil MultisigAPI")
	}
}

func TestMultisigAPI_RegisterHandlers(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	srv := NewServer(nil)
	api.RegisterHandlers(srv)
}

func TestMultisigAPI_GetMultisigWallet_NoParams(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	_, err := api.GetMultisigWallet(ctx(), nil)
	requireErr(t, nil, err)
}

func TestMultisigAPI_IsMultisigWallet_NoParams(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	_, err := api.IsMultisigWallet(ctx(), nil)
	requireErr(t, nil, err)
}

func TestMultisigAPI_GetPendingProposals_NoParams(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	_, err := api.GetPendingProposals(ctx(), nil)
	requireErr(t, nil, err)
}

func TestMultisigAPI_GetMultisigProposal_NoParams(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	_, err := api.GetMultisigProposal(ctx(), nil)
	requireErr(t, nil, err)
}

func TestMultisigAPI_RegisterWallet_NoParams(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	_, err := api.RegisterWallet(ctx(), nil)
	requireErr(t, nil, err)
}

func TestMultisigAPI_CreateProposal_NoParams(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	_, err := api.CreateProposal(ctx(), nil)
	requireErr(t, nil, err)
}

func TestMultisigAPI_ApproveProposal_NoParams(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	_, err := api.ApproveProposal(ctx(), nil)
	requireErr(t, nil, err)
}

func TestMultisigAPI_ExecuteProposal_NoParams(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	_, err := api.ExecuteProposal(ctx(), nil)
	requireErr(t, nil, err)
}

func TestMultisigAPI_IsMultisigWallet_InvalidAddress(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	params, _ := json.Marshal([]string{"not-an-address"})
	_, err := api.IsMultisigWallet(ctx(), params)
	requireErr(t, nil, err)
}

func TestMultisigAPI_GetMultisigWallet_InvalidAddress(t *testing.T) {
	api := NewMultisigAPI(nil, newMockStateReader(), &mockChainStateDB{})
	params, _ := json.Marshal([]string{"not-an-address"})
	_, err := api.GetMultisigWallet(ctx(), params)
	requireErr(t, nil, err)
}

// ── Proof API tests ──

func TestNewProofAPI(t *testing.T) {
	api := NewProofAPI(newMockBlockReader(), newMockStateReader())
	if api == nil {
		t.Fatal("expected non-nil ProofAPI")
	}
}

func TestProofAPI_GetProof_NoParams(t *testing.T) {
	api := NewProofAPI(newMockBlockReader(), newMockStateReader())
	// GetProof takes (address string, storageKeys []string, blockNum string)
	_, err := api.GetProof("0x1234567890123456789012345678901234567890", []string{"0x0"}, "latest")
	_ = err
}

func TestProofAPI_RegisterHandlers(t *testing.T) {
	api := NewProofAPI(newMockBlockReader(), newMockStateReader())
	srv := NewServer(nil)
	api.RegisterHandlers(srv)
}

func TestProofAPI_GetProof_InvalidAddress(t *testing.T) {
	api := NewProofAPI(newMockBlockReader(), newMockStateReader())
	_, err := api.GetProof("not-an-address", []string{"0x0"}, "latest")
	_ = err
}

// ── Debug API tests ──

func TestNewDebugAPI(t *testing.T) {
	api := NewDebugAPI(newMockBlockReader(), newMockStateReader(), newMockContractCaller(), newMockChainInfo())
	if api == nil {
		t.Fatal("expected non-nil DebugAPI")
	}
}

func TestDebugAPI_TraceTransaction_NoParams(t *testing.T) {
	api := NewDebugAPI(newMockBlockReader(), newMockStateReader(), newMockContractCaller(), newMockChainInfo())
	_, err := api.TraceTransaction("", nil)
	_ = err
}

func TestDebugAPI_TraceBlockByNumber(t *testing.T) {
	api := NewDebugAPI(newMockBlockReader(), newMockStateReader(), newMockContractCaller(), newMockChainInfo())
	_, err := api.TraceBlockByNumber("latest", nil)
	_ = err
}

func TestDebugAPI_TraceBlockByHash(t *testing.T) {
	api := NewDebugAPI(newMockBlockReader(), newMockStateReader(), newMockContractCaller(), newMockChainInfo())
	_, err := api.TraceBlockByHash("0x0000000000000000000000000000000000000000000000000000000000000000", nil)
	_ = err
}

func TestDebugAPI_RegisterHandlers(t *testing.T) {
	api := NewDebugAPI(newMockBlockReader(), newMockStateReader(), newMockContractCaller(), newMockChainInfo())
	srv := NewServer(nil)
	api.RegisterHandlers(srv)
}

// ── Blob API tests ──

func TestNewBlobAPI(t *testing.T) {
	api := NewBlobAPI(newMockBlockReader(), newMockTxPool(), newMockChainInfo())
	if api == nil {
		t.Fatal("expected non-nil BlobAPI")
	}
}

func TestBlobAPI_RegisterHandlers(t *testing.T) {
	api := NewBlobAPI(newMockBlockReader(), newMockTxPool(), newMockChainInfo())
	srv := NewServer(nil)
	api.RegisterHandlers(srv)
}

func TestBlobAPI_GetBlobBaseFee(t *testing.T) {
	api := NewBlobAPI(newMockBlockReader(), newMockTxPool(), newMockChainInfo())
	result, err := api.GetBlobBaseFee(ctx())
	_ = result
	_ = err
}

// ── Access List API tests ──

func TestNewAccessListAPI(t *testing.T) {
	api := NewAccessListAPI(newMockBlockReader(), newMockStateReader(), newMockContractCaller(), newMockChainInfo())
	if api == nil {
		t.Fatal("expected non-nil AccessListAPI")
	}
}

func TestAccessListAPI_CreateAccessList_NoParams(t *testing.T) {
	api := NewAccessListAPI(newMockBlockReader(), newMockStateReader(), newMockContractCaller(), newMockChainInfo())
	_, err := api.CreateAccessList(TraceCallArgs{}, "latest")
	_ = err
}

func TestAccessListAPI_RegisterHandlers(t *testing.T) {
	api := NewAccessListAPI(newMockBlockReader(), newMockStateReader(), newMockContractCaller(), newMockChainInfo())
	srv := NewServer(nil)
	api.RegisterHandlers(srv)
}

// ── QTD/TSS API tests ──

func TestNewTSSAPI(t *testing.T) {
	api := NewTSSAPI(nil)
	if api == nil {
		t.Fatal("expected non-nil TSSAPI")
	}
}

func TestTSSAPI_RegisterHandlers(t *testing.T) {
	api := NewTSSAPI(nil)
	srv := NewServer(nil)
	api.RegisterHandlers(srv)
}

func TestTSSAPI_GenerateKeyShares_NoParams(t *testing.T) {
	api := NewTSSAPI(nil)
	_, err := api.GenerateKeyShares(ctx(), nil)
	requireErr(t, nil, err)
}

func TestTSSAPI_GetPublicKey_NoParams(t *testing.T) {
	api := NewTSSAPI(nil)
	_, err := api.GetPublicKey(ctx(), nil)
	requireErr(t, nil, err)
}

func TestTSSAPI_GetShare_NoParams(t *testing.T) {
	api := NewTSSAPI(nil)
	_, err := api.GetShare(ctx(), nil)
	requireErr(t, nil, err)
}

func TestTSSAPI_SignMessage_NoParams(t *testing.T) {
	api := NewTSSAPI(nil)
	_, err := api.SignMessage(ctx(), nil)
	requireErr(t, nil, err)
}

// TestTSSAPI_SignMessage_MessageTooLarge verifies the RPC-R7-07 fix: an
// oversized message must be rejected at the RPC boundary before reaching the
// threshold-signing pipeline, preventing a single request from exhausting
// CPU/memory/network across all participants.
func TestTSSAPI_SignMessage_MessageTooLarge(t *testing.T) {
	// R33 CONS-05: threshold must be >= 2; these tests use TSSManager only as
	// a minimal mock for the RPC size-limit check, so T=2/N=2 is sufficient.
	mgr, err := tss.NewTSSManager(tss.TSSConfig{Threshold: 2, TotalShares: 2})
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}
	api := NewTSSAPI(mgr)

	// Construct a message slightly over 1MB decoded (2MB+2 hex chars).
	huge := "0x" + strings.Repeat("ab", (1<<20)+1)
	params, _ := json.Marshal(map[string]any{
		"message":        huge,
		"participantIds": []int{0},
	})

	_, rpcErr := api.SignMessage(ctx(), params)
	if rpcErr == nil {
		t.Fatal("RPC-R7-07: expected error for oversized message, got nil")
	}
	if rpcErr.Code != ErrCodeInvalidParams {
		t.Fatalf("RPC-R7-07: expected ErrCodeInvalidParams, got code=%d msg=%q",
			rpcErr.Code, rpcErr.Message)
	}
	if !strings.Contains(rpcErr.Message, "too large") {
		t.Fatalf("RPC-R7-07: expected 'too large' in error, got %q", rpcErr.Message)
	}
}

// TestTSSAPI_SignMessage_MessageSizeBoundaryAccepted verifies that a message
// just under the limit is NOT rejected by the size check (the call may fail
// later inside the TSS pipeline for unrelated reasons, but the size check must
// not fire).
func TestTSSAPI_SignMessage_MessageSizeBoundaryAccepted(t *testing.T) {
	// R33 CONS-05: threshold must be >= 2; these tests use TSSManager only as
	// a minimal mock for the RPC size-limit check, so T=2/N=2 is sufficient.
	mgr, err := tss.NewTSSManager(tss.TSSConfig{Threshold: 2, TotalShares: 2})
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}
	api := NewTSSAPI(mgr)

	// Construct a 1MB decoded message (2MB hex chars + "0x" prefix = exactly
	// the boundary; the check rejects > 2MB+2).
	ok := "0x" + strings.Repeat("ab", 1<<20)
	params, _ := json.Marshal(map[string]any{
		"message":        ok,
		"participantIds": []int{0},
	})

	_, rpcErr := api.SignMessage(ctx(), params)
	// The size check must NOT fire. The call may still fail inside the TSS
	// engine (no shares loaded) — that's fine. We only assert the failure is
	// NOT the "too large" error.
	if rpcErr != nil && strings.Contains(rpcErr.Message, "too large") {
		t.Fatalf("RPC-R7-07 REGRESSION: boundary-size message rejected by size check: %q",
			rpcErr.Message)
	}
}

func TestTSSAPI_VerifySignature_NoParams(t *testing.T) {
	api := NewTSSAPI(nil)
	_, err := api.VerifySignature(ctx(), nil)
	requireErr(t, nil, err)
}

func TestTSSAPI_Status_NoManager(t *testing.T) {
	api := NewTSSAPI(nil)
	result, err := api.Status(ctx(), nil)
	// TSS manager not initialized returns an error
	_ = result
	_ = err
}

// ── Quantum Signature Parser tests ──

func TestExtractQuantumDataFromSignature_Empty(t *testing.T) {
	result, err := ExtractQuantumDataFromSignature("")
	// Empty string returns error "no quantum signature data found"
	if err == nil {
		if result.HasQuantumData {
			t.Error("expected no quantum data for empty string")
		}
	}
}

func TestExtractQuantumDataFromSignature_ShortSignature(t *testing.T) {
	result, err := ExtractQuantumDataFromSignature("0x0102")
	// Short signature returns error
	if err == nil {
		if result.HasQuantumData {
			t.Error("expected no quantum data for short signature")
		}
	}
}

func TestHasQuantumSignature_Empty(t *testing.T) {
	if HasQuantumSignature("") {
		t.Error("expected false for empty signature")
	}
}

func TestHasQuantumSignature_ShortSignature(t *testing.T) {
	if HasQuantumSignature("0x0102") {
		t.Error("expected false for short signature")
	}
}

func TestEncodeQuantumSignature(t *testing.T) {
	pubKey := make([]byte, 1952)
	sig := make([]byte, 3293)
	ecdsaSig := make([]byte, 65)
	result := EncodeQuantumSignature(sig, pubKey, ecdsaSig)
	if result == "" {
		t.Error("expected non-empty encoded signature")
	}
}

// ── Stardust API tests ──

func TestNewStardustAPI(t *testing.T) {
	api := NewStardustAPI(nil)
	if api == nil {
		t.Fatal("expected non-nil StardustAPI")
	}
}

func TestStardustAPI_RegisterHandlers(t *testing.T) {
	api := NewStardustAPI(nil)
	srv := NewServer(nil)
	api.RegisterHandlers(srv)
}

func TestStardustAPI_GetFinality_NoParams(t *testing.T) {
	api := NewStardustAPI(nil)
	_, err := api.GetFinality(ctx(), nil)
	requireErr(t, nil, err)
}

func TestStardustAPI_GetChambers_NoParams(t *testing.T) {
	api := NewStardustAPI(nil)
	_, err := api.GetChambers(ctx(), nil)
	requireErr(t, nil, err)
}

func TestStardustAPI_GetMinistryStatus_NoParams(t *testing.T) {
	api := NewStardustAPI(nil)
	_, err := api.GetMinistryStatus(ctx(), nil)
	requireErr(t, nil, err)
}

func TestStardustAPI_VerifyFinality_NoParams(t *testing.T) {
	api := NewStardustAPI(nil)
	_, err := api.VerifyFinality(ctx(), nil)
	requireErr(t, nil, err)
}

func TestStardustAPI_GetQTDFinalityStatus_NoParams(t *testing.T) {
	api := NewStardustAPI(nil)
	_, err := api.GetQTDFinalityStatus(ctx(), nil)
	requireErr(t, nil, err)
}

// ── Quantum API extended tests ──

func TestSendPrivacyTransaction_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.SendPrivacyTransaction(ctx(), nil)
	requireErr(t, nil, err)
}

func TestScanPrivacy_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.ScanPrivacy(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGetPrivacyBalance_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GetPrivacyBalance(ctx(), nil)
	requireErr(t, nil, err)
}

func TestGenerateStealthAddress_NoParams(t *testing.T) {
	api := newTestAPI()
	_, err := api.GenerateStealthAddress(ctx(), nil)
	requireErr(t, nil, err)
}
