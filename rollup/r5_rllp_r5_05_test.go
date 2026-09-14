// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// RLLP-R5-05 (2026-07-16): Regression tests for withdrawal burn semantics
// and buildWithdrawalSMT filtering.
//
// Two bugs were fixed:
//  1. processBatchLocked treated tx.To==bridgeAddress as a normal transfer
//     (crediting the bridge account) instead of burning the value from L2
//     supply. This broke the L2 supply invariant: L1 releases + L2 bridge
//     balance > actual L1-locked assets (double-spend).
//  2. buildWithdrawalSMT included ALL txs with tx.To != nil && Value > 0,
//     polluting the withdrawal tree with ordinary user-to-user transfers.

// TestRLLP_R5_05_WithdrawalBurnsFromL2Supply verifies that when BridgeAddress
// is configured, a withdrawal tx burns value from L2 supply: the sender's
// balance decreases AND the bridge account does NOT get credited.
func TestRLLP_R5_05_WithdrawalBurnsFromL2Supply(t *testing.T) {
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	cfg.BridgeAddress = bridgeAddr

	sm := NewStateManager(cfg)
	user := types.Address{0x42}
	sm.MintBalance(user, big.NewInt(10000))

	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &bridgeAddr,
		Value:    big.NewInt(3000),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	_, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{withdrawalTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// User balance must be reduced by 3000 (gas=0).
	userAcc := sm.GetAccount(user)
	if userAcc == nil {
		t.Fatal("user account not found")
	}
	expectedUser := big.NewInt(10000 - 3000)
	if userAcc.Balance.Cmp(expectedUser) != 0 {
		t.Errorf("user balance: got %s, want %s (burn should deduct from sender)",
			userAcc.Balance.String(), expectedUser.String())
	}

	// Bridge account must NOT be credited — the value is burned.
	bridgeAcc := sm.GetAccount(bridgeAddr)
	if bridgeAcc != nil && bridgeAcc.Balance.Sign() > 0 {
		t.Errorf("bridge account should have ZERO balance (burn semantics), got %s",
			bridgeAcc.Balance.String())
	}
}

// TestRLLP_R5_05_LegacyModeCreditsBridgeAccount verifies that when
// BridgeAddress is NOT configured (zero), the old behavior is preserved:
// withdrawal value is credited to the bridge account as a normal transfer.
// This ensures backward compatibility for development/test setups.
func TestRLLP_R5_05_LegacyModeCreditsBridgeAccount(t *testing.T) {
	cfg := DefaultRollupConfig()
	// BridgeAddress is zero (default) — legacy mode, no burn.

	sm := NewStateManager(cfg)
	user := types.Address{0x42}
	bridgeAddr := types.Address{0xff}
	sm.MintBalance(user, big.NewInt(10000))

	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &bridgeAddr,
		Value:    big.NewInt(3000),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	_, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{withdrawalTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// User balance reduced by 3000.
	userAcc := sm.GetAccount(user)
	if userAcc == nil {
		t.Fatal("user account not found")
	}
	expectedUser := big.NewInt(10000 - 3000)
	if userAcc.Balance.Cmp(expectedUser) != 0 {
		t.Errorf("user balance: got %s, want %s", userAcc.Balance.String(), expectedUser.String())
	}

	// Bridge account IS credited in legacy mode (old behavior).
	bridgeAcc := sm.GetAccount(bridgeAddr)
	if bridgeAcc == nil {
		t.Fatal("bridge account should exist in legacy mode (credited as normal transfer)")
	}
	if bridgeAcc.Balance.Cmp(big.NewInt(3000)) != 0 {
		t.Errorf("bridge balance (legacy): got %s, want 3000 (normal transfer, no burn)",
			bridgeAcc.Balance.String())
	}
}

// TestRLLP_R5_05_L2SupplyInvariant verifies that burning reduces total L2
// supply: sum of all account balances after burn < sum before burn.
func TestRLLP_R5_05_L2SupplyInvariant(t *testing.T) {
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	cfg.BridgeAddress = bridgeAddr

	sm := NewStateManager(cfg)
	user := types.Address{0x42}
	sm.MintBalance(user, big.NewInt(10000))

	// Total supply before = 10000 (only user has funds).
	supplyBefore := big.NewInt(10000)

	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &bridgeAddr,
		Value:    big.NewInt(4000),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	_, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{withdrawalTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Total supply after = 10000 - 4000 = 6000 (4000 burned, not credited).
	userAcc := sm.GetAccount(user)
	bridgeAcc := sm.GetAccount(bridgeAddr)

	supplyAfter := big.NewInt(0)
	if userAcc != nil {
		supplyAfter.Add(supplyAfter, userAcc.Balance)
	}
	if bridgeAcc != nil {
		supplyAfter.Add(supplyAfter, bridgeAcc.Balance)
	}

	expectedSupply := big.NewInt(10000 - 4000)
	if supplyAfter.Cmp(expectedSupply) != 0 {
		t.Errorf("L2 supply after burn: got %s, want %s (supply must shrink by withdrawal amount)",
			supplyAfter.String(), expectedSupply.String())
	}
	if supplyAfter.Cmp(supplyBefore) >= 0 {
		t.Errorf("L2 supply must DECREASE after withdrawal burn: before=%s, after=%s",
			supplyBefore.String(), supplyAfter.String())
	}
}

// TestRLLP_R5_05_BuildWithdrawalSMT_FiltersByBridgeAddress verifies that
// buildWithdrawalSMT only includes txs where tx.To == bridgeAddress, not
// all value transfers. This prevents polluting the withdrawal tree with
// ordinary user-to-user transfers.
func TestRLLP_R5_05_BuildWithdrawalSMT_FiltersByBridgeAddress(t *testing.T) {
	bridgeAddr := types.Address{0xff}
	user1 := types.Address{0x01}
	user2 := types.Address{0x02}
	otherAddr := types.Address{0x03}

	txs := []*RollupTransaction{
		// txIdx 0: withdrawal (user1 → bridge). SHOULD be included.
		{
			From:  user1,
			To:    &bridgeAddr,
			Value: big.NewInt(100),
		},
		// txIdx 1: ordinary transfer (user1 → user2). Should NOT be included.
		{
			From:  user1,
			To:    &user2,
			Value: big.NewInt(50),
		},
		// txIdx 2: ordinary transfer (user2 → otherAddr). Should NOT be included.
		{
			From:  user2,
			To:    &otherAddr,
			Value: big.NewInt(30),
		},
		// txIdx 3: another withdrawal (user2 → bridge). SHOULD be included.
		{
			From:  user2,
			To:    &bridgeAddr,
			Value: big.NewInt(20),
		},
		// txIdx 4: tx with nil To. Should NOT be included.
		{
			From:  user1,
			To:    nil,
			Value: big.NewInt(10),
		},
		// txIdx 5: tx with zero Value to bridge. Should NOT be included.
		{
			From:  user1,
			To:    &bridgeAddr,
			Value: big.NewInt(0),
		},
	}

	smt := buildWithdrawalSMT(txs, bridgeAddr)

	// Only txIdx 0 and txIdx 3 should be in the tree.
	// Verify txIdx 0 (user1 withdrawal) is present: proof verifies AND leaf hash matches.
	key0 := ComputeWithdrawalTreeKey(user1, 0)
	leaf0 := ComputeWithdrawalLeafHash(user1, big.NewInt(100), 0)
	proof0, err := smt.Prove(key0)
	if err != nil {
		t.Fatalf("expected proof for txIdx 0 (user1 withdrawal): %v", err)
	}
	if !VerifyMerkleProof(key0, proof0, smt.Root()) {
		t.Error("txIdx 0 (user1 withdrawal) proof should verify against root")
	}
	if proof0.LeafHash != leaf0 {
		t.Error("txIdx 0 proof leaf hash should match the withdrawal leaf (was inserted)")
	}

	// Verify txIdx 3 (user2 withdrawal) is present.
	key3 := ComputeWithdrawalTreeKey(user2, 3)
	leaf3 := ComputeWithdrawalLeafHash(user2, big.NewInt(20), 3)
	proof3, err := smt.Prove(key3)
	if err != nil {
		t.Fatalf("expected proof for txIdx 3 (user2 withdrawal): %v", err)
	}
	if !VerifyMerkleProof(key3, proof3, smt.Root()) {
		t.Error("txIdx 3 (user2 withdrawal) proof should verify against root")
	}
	if proof3.LeafHash != leaf3 {
		t.Error("txIdx 3 proof leaf hash should match the withdrawal leaf (was inserted)")
	}

	// Verify txIdx 1 (ordinary transfer) is NOT present: leaf hash won't match
	// because the ordinary transfer was never inserted into the withdrawal tree.
	key1 := ComputeWithdrawalTreeKey(user1, 1)
	leaf1 := ComputeWithdrawalLeafHash(user1, big.NewInt(50), 1)
	proof1, err := smt.Prove(key1)
	if err != nil {
		t.Fatalf("Prove should not error even for non-included keys: %v", err)
	}
	if proof1.LeafHash == leaf1 {
		t.Error("txIdx 1 (ordinary transfer) should NOT be in withdrawal tree (leaf hash matches — was incorrectly inserted)")
	}
}

// TestRLLP_R5_05_MixedBatchBurnsOnlyWithdrawals verifies that in a batch with
// both withdrawal and non-withdrawal txs, only withdrawals are burned and
// non-withdrawals are normal transfers.
func TestRLLP_R5_05_MixedBatchBurnsOnlyWithdrawals(t *testing.T) {
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	cfg.BridgeAddress = bridgeAddr

	sm := NewStateManager(cfg)
	user1 := types.Address{0x01}
	user2 := types.Address{0x02}
	otherAddr := types.Address{0x03}

	sm.MintBalance(user1, big.NewInt(10000))
	sm.MintBalance(user2, big.NewInt(5000))

	txs := []*RollupTransaction{
		// txIdx 0: user1 withdraws 2000 to bridge → burn.
		{
			Nonce: 0, GasPrice: 0, GasLimit: 21000,
			From: user1, To: &bridgeAddr, Value: big.NewInt(2000),
			ChainID: cfg.ChainID,
		},
		// txIdx 1: user1 transfers 1000 to user2 → normal transfer.
		{
			Nonce: 1, GasPrice: 0, GasLimit: 21000,
			From: user1, To: &user2, Value: big.NewInt(1000),
			ChainID: cfg.ChainID,
		},
		// txIdx 2: user2 withdraws 500 to bridge → burn.
		{
			Nonce: 0, GasPrice: 0, GasLimit: 21000,
			From: user2, To: &bridgeAddr, Value: big.NewInt(500),
			ChainID: cfg.ChainID,
		},
	}

	prevRoot := sm.computeStateRoot()
	_, _, err := sm.ProcessBatch(0, prevRoot, txs)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// user1: 10000 - 2000 (burn) - 1000 (transfer) = 7000
	user1Acc := sm.GetAccount(user1)
	expectedUser1 := big.NewInt(10000 - 2000 - 1000)
	if user1Acc.Balance.Cmp(expectedUser1) != 0 {
		t.Errorf("user1 balance: got %s, want %s", user1Acc.Balance.String(), expectedUser1.String())
	}

	// user2: 5000 + 1000 (received) - 500 (burn) = 5500
	user2Acc := sm.GetAccount(user2)
	expectedUser2 := big.NewInt(5000 + 1000 - 500)
	if user2Acc.Balance.Cmp(expectedUser2) != 0 {
		t.Errorf("user2 balance: got %s, want %s", user2Acc.Balance.String(), expectedUser2.String())
	}

	// otherAddr: 0 (not involved).
	otherAcc := sm.GetAccount(otherAddr)
	if otherAcc != nil && otherAcc.Balance.Sign() > 0 {
		t.Errorf("otherAddr should have 0 balance, got %s", otherAcc.Balance.String())
	}

	// Bridge account: 0 (burned, not credited).
	bridgeAcc := sm.GetAccount(bridgeAddr)
	if bridgeAcc != nil && bridgeAcc.Balance.Sign() > 0 {
		t.Errorf("bridge account should have 0 balance (both withdrawals burned), got %s",
			bridgeAcc.Balance.String())
	}

	// Total L2 supply: 15000 - 2000 (burn) - 500 (burn) = 12500
	totalSupply := big.NewInt(0)
	totalSupply.Add(totalSupply, user1Acc.Balance)
	totalSupply.Add(totalSupply, user2Acc.Balance)
	if bridgeAcc != nil {
		totalSupply.Add(totalSupply, bridgeAcc.Balance)
	}
	expectedSupply := big.NewInt(15000 - 2000 - 500)
	if totalSupply.Cmp(expectedSupply) != 0 {
		t.Errorf("total L2 supply: got %s, want %s (only withdrawals should reduce supply)",
			totalSupply.String(), expectedSupply.String())
	}
}

// TestRLLP_R5_05_WithdrawalBurnsWithGas verifies that gas is still charged
// when burning withdrawal value. The sender pays value + gas, but only the
// value is burned (gas is consumed as in normal txs).
func TestRLLP_R5_05_WithdrawalBurnsWithGas(t *testing.T) {
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	cfg.BridgeAddress = bridgeAddr

	sm := NewStateManager(cfg)
	user := types.Address{0x42}
	// Fund enough for value + gas: 3000 + (21000 * 2) = 45000, plus margin.
	sm.MintBalance(user, big.NewInt(100000))

	gasPrice := uint64(2)
	gasLimit := uint64(21000)
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), new(big.Int).SetUint64(gasPrice))

	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		From:     user,
		To:       &bridgeAddr,
		Value:    big.NewInt(3000),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	_, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{withdrawalTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// User balance: 100000 - 3000 (burn value) - gasCost.
	userAcc := sm.GetAccount(user)
	expectedUser := new(big.Int).Sub(big.NewInt(100000), big.NewInt(3000))
	expectedUser.Sub(expectedUser, gasCost)
	if userAcc.Balance.Cmp(expectedUser) != 0 {
		t.Errorf("user balance with gas: got %s, want %s (value + gas deducted)",
			userAcc.Balance.String(), expectedUser.String())
	}

	// Bridge account: 0 (value burned, gas not credited to bridge).
	bridgeAcc := sm.GetAccount(bridgeAddr)
	if bridgeAcc != nil && bridgeAcc.Balance.Sign() > 0 {
		t.Errorf("bridge account should have 0 balance (burn), got %s",
			bridgeAcc.Balance.String())
	}
}

// TestRLLP_R5_05_WithdrawalBurnNotTriggeredForZeroBridgeAddress verifies
// that when BridgeAddress is the zero address, no burn occurs. This is the
// safety guard: zero BridgeAddress means "burn disabled" (legacy mode).
func TestRLLP_R5_05_WithdrawalBurnNotTriggeredForZeroBridgeAddress(t *testing.T) {
	cfg := DefaultRollupConfig()
	// BridgeAddress is zero (default).
	sm := NewStateManager(cfg)
	user := types.Address{0x42}
	// Send to the zero address — should NOT trigger burn (normal transfer).
	zeroAddr := types.Address{}

	sm.MintBalance(user, big.NewInt(10000))

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &zeroAddr,
		Value:    big.NewInt(1000),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	_, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// User balance: 10000 - 1000 = 9000 (normal transfer).
	userAcc := sm.GetAccount(user)
	expectedUser := big.NewInt(10000 - 1000)
	if userAcc.Balance.Cmp(expectedUser) != 0 {
		t.Errorf("user balance: got %s, want %s (normal transfer, no burn for zero BridgeAddress)",
			userAcc.Balance.String(), expectedUser.String())
	}

	// Zero address account IS credited (normal transfer).
	zeroAcc := sm.GetAccount(zeroAddr)
	if zeroAcc == nil {
		t.Fatal("zero-address account should exist (normal transfer)")
	}
	if zeroAcc.Balance.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("zero-address balance: got %s, want 1000 (normal transfer, no burn)",
			zeroAcc.Balance.String())
	}
}
