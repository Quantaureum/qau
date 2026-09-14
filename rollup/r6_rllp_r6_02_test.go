// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ── RLLP: withdrawal L2 burn + withdrawal-tree leaf-set closure test ──
//
// Audit quote (AUDIT-FULL-ROUND6-2026-07-17.md RLLP [Low / LATENT]):
//   "withdrawals did not burn + withdrawal-tree leaf-set pollution"
//   file:line: rollup/ withdrawal path
//   fix: withdrawals must burn the corresponding L2 tokens.
//
// Fix status: fixed (2026-07-16), in two layers:
//
//   1. Burn semantics (state_manager.go:336-375 processBatchLocked):
//      when BridgeAddress is configured and tx.To == BridgeAddress, the value is debited from the sender
//      but not credited to the bridge account — effectively burned from L2 supply.
//      This preserves the L2 supply invariant: every L1 release maps 1:1 to an L2 burn,
//      preventing double-spends (tokens accumulated by the bridge on L2 while also released on L1).
//
//   2. Withdrawal-tree leaf set (bridge.go:616-630 buildWithdrawalSMT):
//      only transactions with tx.To == bridgeAddress enter the withdrawal SMT. Previously every
//      tx.To != nil && Value > 0 was inserted, polluting the tree and breaking the
//      1:1 leaf-to-release invariant, risking ordinary transfers being mistaken for withdrawals.
//
// This file explicitly verifies closure:
//   1. after a withdrawal tx the bridge account balance stays 0 (value burned, not credited)
//   2. after a withdrawal tx the sender balance decreases correctly
//   3. ordinary transfers do not appear in the withdrawal tree
//   4. only txs with To == bridgeAddress enter the withdrawal tree
//   5. without a configured BridgeAddress no burn triggers (backward-compatible)

// TestRLLP_R6_02_WithdrawalBurnsL2Supply verifies the core burn semantics:
// after a withdrawal tx (To == BridgeAddress, Value > 0), the bridge account
// on L2 must NOT be credited — the value is burned from L2 supply.
// This is the first half of "withdrawal without burn".
func TestRLLP_R6_02_WithdrawalBurnsL2Supply(t *testing.T) {
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	cfg.BridgeAddress = bridgeAddr // RLLP- enable burn semantics
	sm := NewStateManager(cfg)

	user := types.Address{0x42}
	initialBalance := int64(10000)
	withdrawAmount := int64(300)

	// Fund the user on L2.
	sm.MintBalance(user, big.NewInt(initialBalance))

	// Build withdrawal tx: user → bridgeAddr.
	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0, // gas=0 to isolate burn semantics
		GasLimit: 21000,
		From:     user,
		To:       &bridgeAddr,
		Value:    big.NewInt(withdrawAmount),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	_, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{withdrawalTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Verify sender balance was reduced by the withdrawal amount.
	userAcc := sm.GetAccount(user)
	if userAcc == nil {
		t.Fatal("user account not found after withdrawal")
	}
	expectedUserBalance := big.NewInt(initialBalance - withdrawAmount)
	if userAcc.Balance.Cmp(expectedUserBalance) != 0 {
		t.Errorf("user balance after burn: got %s, want %d ( burn failed)",
			userAcc.Balance.String(), initialBalance-withdrawAmount)
	}

	// Verify bridge account was NOT credited (burn semantics).
	bridgeAcc := sm.GetAccount(bridgeAddr)
	if bridgeAcc != nil && bridgeAcc.Balance.Sign() > 0 {
		t.Errorf("bridge account must NOT be credited under burn semantics, got balance=%s ( NOT FIXED)",
			bridgeAcc.Balance.String())
	}

	t.Logf(" burn semantics OK: user=%s, bridge=<nil/0> (value burned from L2 supply)",
		userAcc.Balance.String())
}

// TestRLLP_R6_02_BurnMaintainsL2SupplyInvariant verifies that the total L2
// supply decreases by exactly the withdrawal amount after a burn. This is
// the security invariant: every L1 release corresponds 1:1 to an L2 burn.
func TestRLLP_R6_02_BurnMaintainsL2SupplyInvariant(t *testing.T) {
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	cfg.BridgeAddress = bridgeAddr
	sm := NewStateManager(cfg)

	user := types.Address{0x42}
	initialBalance := int64(10000)
	withdrawAmount := int64(1500)

	sm.MintBalance(user, big.NewInt(initialBalance))

	// Total L2 supply before = initialBalance.
	supplyBefore := big.NewInt(initialBalance)

	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &bridgeAddr,
		Value:    big.NewInt(withdrawAmount),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	_, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{withdrawalTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Total L2 supply after = (initialBalance - withdrawAmount) + bridge(=0)
	// = initialBalance - withdrawAmount.
	userAcc := sm.GetAccount(user)
	userAfter := new(big.Int).Set(userAcc.Balance)

	bridgeAcc := sm.GetAccount(bridgeAddr)
	bridgeAfter := big.NewInt(0)
	if bridgeAcc != nil {
		bridgeAfter.Set(bridgeAcc.Balance)
	}

	supplyAfter := new(big.Int).Add(userAfter, bridgeAfter)
	expectedSupply := new(big.Int).Sub(supplyBefore, big.NewInt(withdrawAmount))

	if supplyAfter.Cmp(expectedSupply) != 0 {
		t.Errorf("L2 supply invariant violated: before=%s, after=%s, expected=%s (burn did not reduce supply 1:1)",
			supplyBefore.String(), supplyAfter.String(), expectedSupply.String())
	}

	t.Logf(" supply invariant OK: supply %s → %s (burned %d)",
		supplyBefore.String(), supplyAfter.String(), withdrawAmount)
}

// TestRLLP_R6_02_WithdrawalTreeExcludesNonWithdrawalTxs verifies the second
// half of "withdrawal-tree leaf-set pollution". The withdrawal SMT must only contain
// txs where To == bridgeAddress. Ordinary user-to-user transfers must NOT
// pollute the tree.
func TestRLLP_R6_02_WithdrawalTreeExcludesNonWithdrawalTxs(t *testing.T) {
	bridgeAddr := types.Address{0xff}
	user1 := types.Address{0x42}
	user2 := types.Address{0x43}
	recipient := types.Address{0x44}

	// Mixed batch: 1 ordinary transfer + 1 withdrawal.
	ordinaryTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user1,
		To:       &recipient, // NOT the bridge — ordinary transfer
		Value:    big.NewInt(100),
	}
	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user2,
		To:       &bridgeAddr, // withdrawal
		Value:    big.NewInt(500),
	}
	txs := []*RollupTransaction{ordinaryTx, withdrawalTx}

	smt := buildWithdrawalSMT(txs, bridgeAddr)

	// The ordinary transfer must NOT be in the tree.
	ordinaryKey := ComputeWithdrawalTreeKey(user1, 0)
	ordinaryLeaf := ComputeWithdrawalLeafHash(user1, big.NewInt(100), 0)
	leaf, ok := smt.Get(ordinaryKey)
	if ok && leaf == ordinaryLeaf {
		t.Errorf("ordinary transfer (To != bridgeAddr) must NOT be in withdrawal tree ( pollution NOT FIXED)")
	}

	// The withdrawal MUST be in the tree.
	withdrawalKey := ComputeWithdrawalTreeKey(user2, 1) // txIndex=1 (second tx in batch)
	withdrawalLeaf := ComputeWithdrawalLeafHash(user2, big.NewInt(500), 1)
	leaf, ok = smt.Get(withdrawalKey)
	if !ok {
		t.Errorf("withdrawal tx missing from tree")
	} else if leaf != withdrawalLeaf {
		t.Errorf("withdrawal leaf mismatch: got %x, want %x", leaf, withdrawalLeaf)
	}

	t.Logf(" tree pollution OK: ordinary transfer excluded, withdrawal included")
}

// TestRLLP_R6_02_WithdrawalTreeOnlyContainsBridgeTxs verifies that a batch
// with multiple ordinary transfers and zero withdrawals produces an EMPTY
// withdrawal tree (root == empty SMT root). This is the degenerate case of
// the pollution fix: no false positives.
func TestRLLP_R6_02_WithdrawalTreeOnlyContainsBridgeTxs(t *testing.T) {
	bridgeAddr := types.Address{0xff}
	user1 := types.Address{0x42}
	user2 := types.Address{0x43}
	user3 := types.Address{0x44}

	// Batch with only ordinary transfers (no withdrawals).
	txs := []*RollupTransaction{
		{From: user1, To: &user2, Value: big.NewInt(100), GasLimit: 21000, Nonce: 0},
		{From: user2, To: &user3, Value: big.NewInt(50), GasLimit: 21000, Nonce: 0},
		{From: user3, To: &user1, Value: big.NewInt(25), GasLimit: 21000, Nonce: 0},
	}

	smtWithdrawals := buildWithdrawalSMT(txs, bridgeAddr)
	smtEmpty := NewSparseMerkleTree()

	if smtWithdrawals.Root() != smtEmpty.Root() {
		t.Errorf("batch with no withdrawals must produce empty withdrawal tree root; got %x, want %x ( pollution NOT FIXED)",
			smtWithdrawals.Root(), smtEmpty.Root())
	}

	t.Logf(" empty-tree OK: no-withdrawal batch root = %x (matches empty SMT)", smtWithdrawals.Root())
}

// TestRLLP_R6_02_NoBridgeAddressFallsBackToTransfer verifies that when
// BridgeAddress is NOT configured (zero address), withdrawal txs are treated
// as ordinary transfers (value credited to recipient). This is the backward-
// compatibility path — burn semantics only apply when BridgeAddress is set.
func TestRLLP_R6_02_NoBridgeAddressFallsBackToTransfer(t *testing.T) {
	cfg := DefaultRollupConfig()
	// BridgeAddress is zero (default) — burn semantics disabled.
	if cfg.BridgeAddress != (types.Address{}) {
		t.Fatalf("test precondition: default BridgeAddress must be zero")
	}
	sm := NewStateManager(cfg)

	user := types.Address{0x42}
	recipient := types.Address{0x43}
	initialBalance := int64(10000)
	transferAmount := int64(300)

	sm.MintBalance(user, big.NewInt(initialBalance))

	// Tx to recipient (NOT a burn target since BridgeAddress is zero).
	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &recipient,
		Value:    big.NewInt(transferAmount),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	_, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	userAcc := sm.GetAccount(user)
	recipientAcc := sm.GetAccount(recipient)

	expectedUser := big.NewInt(initialBalance - transferAmount)
	if userAcc.Balance.Cmp(expectedUser) != 0 {
		t.Errorf("user balance: got %s, want %s", userAcc.Balance.String(), expectedUser.String())
	}
	if recipientAcc.Balance.Cmp(big.NewInt(transferAmount)) != 0 {
		t.Errorf("recipient must be credited when BridgeAddress is zero, got %s (burn semantics misapplied)",
			recipientAcc.Balance.String())
	}

	t.Logf(" backward-compat OK: BridgeAddress=zero → ordinary transfer (no burn)")
}

// TestRLLP_R6_02_FixedSummary documents the  closure status.
func TestRLLP_R6_02_FixedSummary(t *testing.T) {
	t.Log("=== RLLP- CLOSURE SUMMARY ===")
	t.Log("")
	t.Log("Audit finding (R6): withdrawal without burn + withdrawal-tree leaf-set pollution")
	t.Log("  1. Withdrawal value was credited to bridge account on L2 instead of burned,")
	t.Log("     breaking the 1:1 L2 burn ↔ L1 release invariant (double-spend risk).")
	t.Log("  2. buildWithdrawalSMT included ALL txs with To != nil && Value > 0,")
	t.Log("     polluting the withdrawal tree with ordinary user-to-user transfers.")
	t.Log("")
	t.Log("Fix (RLLP-, 2026-07-16):")
	t.Log("  1. processBatchLocked (state_manager.go:336-375): when BridgeAddress is")
	t.Log("     configured and tx.To == BridgeAddress, value is deducted from sender")
	t.Log("     but NOT credited to bridge account — burned from L2 supply.")
	t.Log("  2. buildWithdrawalSMT (bridge.go:616-630): only txs with To == bridgeAddress")
	t.Log("     are inserted into the withdrawal SMT. Ordinary transfers are excluded.")
	t.Log("")
	t.Log("Security properties verified by this test file:")
	t.Log("  1. Burn: bridge account balance stays 0 after withdrawal (value burned).")
	t.Log("  2. Supply invariant: total L2 supply decreases by exactly withdrawal amount.")
	t.Log("  3. Tree purity: ordinary transfers (To != bridgeAddr) excluded from tree.")
	t.Log("  4. Empty tree: batch with no withdrawals produces empty SMT root.")
	t.Log("  5. Backward compat: BridgeAddress=zero falls back to ordinary transfer.")
	t.Log("")
	t.Log(" status: FIXED (via RLLP-) ✓")
}
