// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// --- W-P1-6 tests (2026-07-13): L1↔L2 bridge ---
// --- Merkle proof upgrade (2026-07-14) ---

// TestMemoryL1Bridge_DepositAndLiquidity verifies that deposits increase
// liquidity and can be retrieved by hash.
func TestMemoryL1Bridge_DepositAndLiquidity(t *testing.T) {
	bridge := NewMemoryL1Bridge()
	depositor := types.Address{0x01}

	// Initial liquidity = 0
	if liq := bridge.GetLiquidity(); liq.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("expected 0 liquidity, got %s", liq.String())
	}

	// Deposit 100
	hash, err := bridge.Deposit(depositor, big.NewInt(100))
	if err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}
	if hash == (types.Hash{}) {
		t.Fatal("deposit hash is zero")
	}

	// Liquidity = 100
	if liq := bridge.GetLiquidity(); liq.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("expected 100 liquidity, got %s", liq.String())
	}

	// Retrieve deposit
	d, ok := bridge.GetDeposit(hash)
	if !ok {
		t.Fatal("deposit not found")
	}
	if d.Depositor != depositor {
		t.Errorf("depositor mismatch: got %x, want %x", d.Depositor, depositor)
	}
	if d.Amount.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("amount mismatch: got %s, want 100", d.Amount.String())
	}
	if d.Minted {
		t.Error("deposit should not be minted yet")
	}

	// Deposit 0 should fail
	if _, err := bridge.Deposit(depositor, big.NewInt(0)); err == nil {
		t.Error("expected error for zero deposit")
	}
}

// TestL2Bridge_ProcessDeposit verifies that ProcessDeposit mints L2 balance
// and is idempotent (double-call returns ErrDepositAlreadyMinted).
func TestL2Bridge_ProcessDeposit(t *testing.T) {
	l1Bridge := NewMemoryL1Bridge()
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	bridgeAddr := types.Address{0xff}

	l2Bridge := NewL2Bridge(l1Bridge, sm, bridgeAddr)
	depositor := types.Address{0x01}

	// Deposit 500 on L1
	depositHash, err := l1Bridge.Deposit(depositor, big.NewInt(500))
	if err != nil {
		t.Fatalf("L1 Deposit failed: %v", err)
	}

	// Before mint, L2 balance = 0
	acc := sm.GetAccount(depositor)
	if acc != nil && acc.Balance.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("expected 0 L2 balance before mint, got %s", acc.Balance.String())
	}

	// Process deposit → mints 500 on L2
	if err := l2Bridge.ProcessDeposit(depositHash); err != nil {
		t.Fatalf("ProcessDeposit failed: %v", err)
	}

	acc = sm.GetAccount(depositor)
	if acc == nil {
		t.Fatal("account not created after mint")
	}
	if acc.Balance.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("expected 500 L2 balance, got %s", acc.Balance.String())
	}

	// Double-mint should fail
	if err := l2Bridge.ProcessDeposit(depositHash); err != ErrDepositAlreadyMinted {
		t.Errorf("expected ErrDepositAlreadyMinted, got %v", err)
	}

	// Non-existent deposit should fail
	if err := l2Bridge.ProcessDeposit(types.Hash{0x99}); err != ErrDepositNotFound {
		t.Errorf("expected ErrDepositNotFound, got %v", err)
	}
}

// setupWithdrawalBatch creates a StateManager with a funded user, processes a
// withdrawal batch via ProcessBatch (so the state root is archived), and
// returns the batch ready for ProcessFinalizedBatch.
//
// This helper is used by all Merkle-proof-based bridge tests to ensure the
// state root is properly archived in stateHistory (required by ProveAccountAtState).
func setupWithdrawalBatch(t *testing.T, userBalance, withdrawAmount int64) (
	*memoryL1Bridge, *StateManager, *L2Bridge, types.Address, *Batch,
) {
	t.Helper()
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	// RLLP-R5-05 (2026-07-16): Set BridgeAddress so processBatchLocked burns
	// withdrawal value from L2 supply instead of crediting the bridge account.
	cfg.BridgeAddress = bridgeAddr
	l1Bridge := NewMemoryL1Bridge().(*memoryL1Bridge)
	sm := NewStateManager(cfg)
	l2Bridge := NewL2Bridge(l1Bridge, sm, bridgeAddr)

	user := types.Address{0x42}

	// Fund L1 bridge with enough liquidity for the withdrawal.
	l1Bridge.Deposit(types.Address{0x99}, big.NewInt(userBalance*2))

	// Fund the user on L2 (simulate a prior deposit mint).
	sm.MintBalance(user, big.NewInt(userBalance))

	// Build withdrawal tx: user → bridgeAddr.
	// GasPrice=0 so gas cost is 0 — these tests verify bridge logic, not gas accounting.
	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &bridgeAddr,
		Value:    big.NewInt(withdrawAmount),
		ChainID:  cfg.ChainID,
	}

	// Process the batch via StateManager → archives state root in stateHistory.
	prevRoot := sm.computeStateRoot()
	postRoot, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{withdrawalTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	batch := &Batch{
		Index:         0,
		PostStateRoot: postRoot,
		Transactions:  []*RollupTransaction{withdrawalTx},
		TxCount:       1,
	}
	batch.BatchHash = types.Hash{0xDE, 0xAD}

	return l1Bridge, sm, l2Bridge, user, batch
}

// TestL2Bridge_ProcessFinalizedBatch verifies that ProcessFinalizedBatch
// detects withdrawal txs (To == bridgeAddr, Value > 0) and releases them on L1
// using a Merkle inclusion proof.
func TestL2Bridge_ProcessFinalizedBatch(t *testing.T) {
	l1Bridge, _, l2Bridge, _, batch := setupWithdrawalBatch(t, 10000, 300)

	// Process the finalized batch
	if err := l2Bridge.ProcessFinalizedBatch(batch); err != nil {
		t.Fatalf("ProcessFinalizedBatch failed: %v", err)
	}

	// L1 liquidity should have decreased by 300
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(20000-300)) != 0 {
		t.Errorf("expected %d L1 liquidity after withdrawal, got %s", 20000-300, liq.String())
	}

	// No pending withdrawals (all processed)
	pending := l2Bridge.GetPendingWithdrawals()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending withdrawals, got %d", len(pending))
	}

	// Double-process should be a no-op (idempotent)
	if err := l2Bridge.ProcessFinalizedBatch(batch); err != nil {
		t.Fatalf("idempotent re-process failed: %v", err)
	}
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(20000-300)) != 0 {
		t.Errorf("expected %d L1 liquidity after idempotent re-process, got %s", 20000-300, liq.String())
	}
}

// TestL2Bridge_NonWithdrawalTxSkipped verifies that txs not addressed to the
// bridge are ignored by ProcessFinalizedBatch.
func TestL2Bridge_NonWithdrawalTxSkipped(t *testing.T) {
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	// RLLP-R5-05 (2026-07-16): Set BridgeAddress for burn semantics.
	cfg.BridgeAddress = bridgeAddr
	l1Bridge := NewMemoryL1Bridge()
	sm := NewStateManager(cfg)
	l2Bridge := NewL2Bridge(l1Bridge, sm, bridgeAddr)

	l1Bridge.Deposit(types.Address{0x02}, big.NewInt(1000))

	// Set up state with a funded user.
	user := types.Address{0x10}
	sm.MintBalance(user, big.NewInt(10000))

	// A regular transfer (To != bridgeAddr) should NOT trigger withdrawal.
	otherAddr := types.Address{0x03}
	regularTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &otherAddr,
		Value:    big.NewInt(500),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	postRoot, _, err := sm.ProcessBatch(1, prevRoot, []*RollupTransaction{regularTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	batch := &Batch{
		Index:         1,
		PostStateRoot: postRoot,
		Transactions:  []*RollupTransaction{regularTx},
		TxCount:       1,
	}
	batch.BatchHash = types.Hash{0x11}

	if err := l2Bridge.ProcessFinalizedBatch(batch); err != nil {
		t.Fatalf("ProcessFinalizedBatch failed: %v", err)
	}

	// L1 liquidity unchanged
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("expected 1000 liquidity (no withdrawal), got %s", liq.String())
	}
}

// TestL2Bridge_RetryPendingWithdrawals verifies that failed withdrawals are
// retried and eventually succeed when L1 liquidity becomes available.
func TestL2Bridge_RetryPendingWithdrawals(t *testing.T) {
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	// RLLP-R5-05 (2026-07-16): Set BridgeAddress for burn semantics.
	cfg.BridgeAddress = bridgeAddr
	l1Bridge := NewMemoryL1Bridge()
	sm := NewStateManager(cfg)
	l2Bridge := NewL2Bridge(l1Bridge, sm, bridgeAddr)

	// No L1 liquidity yet → withdrawal will fail
	user := types.Address{0x02}
	sm.MintBalance(user, big.NewInt(10000))

	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &bridgeAddr,
		Value:    big.NewInt(400),
		ChainID:  cfg.ChainID,
	}

	prevRoot := sm.computeStateRoot()
	postRoot, _, err := sm.ProcessBatch(3, prevRoot, []*RollupTransaction{withdrawalTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	batch := &Batch{
		Index:         3,
		PostStateRoot: postRoot,
		Transactions:  []*RollupTransaction{withdrawalTx},
		TxCount:       1,
	}
	batch.BatchHash = types.Hash{0x22}

	// Process → fails (no L1 liquidity), records as pending
	if err := l2Bridge.ProcessFinalizedBatch(batch); err != nil {
		t.Fatalf("ProcessFinalizedBatch failed: %v", err)
	}
	pending := l2Bridge.GetPendingWithdrawals()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending withdrawal, got %d", len(pending))
	}
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("expected 0 liquidity, got %s", liq.String())
	}

	// Retry → still fails (no liquidity)
	retried := l2Bridge.RetryPendingWithdrawals()
	if retried != 0 {
		t.Errorf("expected 0 retried, got %d", retried)
	}

	// Now fund L1 bridge with 500
	l1Bridge.Deposit(types.Address{0x99}, big.NewInt(500))

	// Retry → succeeds
	retried = l2Bridge.RetryPendingWithdrawals()
	if retried != 1 {
		t.Errorf("expected 1 retried, got %d", retried)
	}
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("expected 100 liquidity (500-400), got %s", liq.String())
	}

	// No more pending
	pending = l2Bridge.GetPendingWithdrawals()
	if len(pending) != 0 {
		t.Errorf("expected 0 pending after retry, got %d", len(pending))
	}
}

// TestL2Bridge_MerkleProofValid verifies that a valid Merkle withdrawal proof
// is accepted by L1Bridge and releases the correct amount.
func TestL2Bridge_MerkleProofValid(t *testing.T) {
	l1Bridge, sm, l2Bridge, user, batch := setupWithdrawalBatch(t, 10000, 500)

	if err := l2Bridge.ProcessFinalizedBatch(batch); err != nil {
		t.Fatalf("ProcessFinalizedBatch failed: %v", err)
	}

	// Verify L1 released the funds.
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(20000-500)) != 0 {
		t.Errorf("expected %d L1 liquidity, got %s", 20000-500, liq.String())
	}

	// Verify the finalized state root was recorded.
	root, ok := l1Bridge.GetFinalizedStateRoot(batch.Index)
	if !ok {
		t.Fatal("finalized state root not recorded")
	}
	if root != batch.PostStateRoot {
		t.Errorf("finalized root mismatch: got %x, want %x", root, batch.PostStateRoot)
	}

	// Verify the user's L2 balance was reduced by the withdrawal amount (gas=0).
	acc := sm.GetAccount(user)
	if acc == nil {
		t.Fatal("user account not found")
	}
	expectedBalance := big.NewInt(10000 - 500) // balance - withdraw (gas=0)
	if acc.Balance.Cmp(expectedBalance) != 0 {
		t.Errorf("user balance: got %s, want %s", acc.Balance.String(), expectedBalance.String())
	}
}

// TestL2Bridge_TamperedMerkleProof verifies that a tampered Merkle proof is
// rejected by L1Bridge.
//
// AUDIT R4-BRDG-02 (2026-07-15): Rewritten to use the dedicated withdrawal
// tree. The old test used the account state SMT (via ProveAccountAtState),
// which did not bind the withdrawal amount — exactly the vulnerability the
// audit identified. The new test builds a dedicated withdrawal SMT, generates
// a valid proof from it, then tampers with: (a) a sibling hash, (b) the
// withdrawal root, (c) the leaf hash, and (d) the calldata amount. All
// tampered variants must be rejected; the valid proof must still be accepted.
func TestL2Bridge_TamperedMerkleProof(t *testing.T) {
	l1Bridge, _, l2Bridge, user, batch := setupWithdrawalBatch(t, 10000, 300)

	// Build the dedicated withdrawal SMT (same logic as ProcessFinalizedBatch).
	// RLLP-R5-05 (2026-07-16): Pass bridge address to filter withdrawals only.
	withdrawalSMT := buildWithdrawalSMT(batch.Transactions, l2Bridge.GetBridgeAddress())
	withdrawalRoot := withdrawalSMT.Root()

	// Record both roots on L1 (mirrors what ProcessFinalizedBatch does).
	l1Bridge.RecordFinalizedBatch(batch.Index, batch.PostStateRoot)
	if err := l1Bridge.RecordWithdrawalRoot(batch.Index, withdrawalRoot); err != nil {
		t.Fatalf("RecordWithdrawalRoot failed: %v", err)
	}

	// Generate a valid proof from the dedicated withdrawal tree.
	treeKey := ComputeWithdrawalTreeKey(user, 0)
	merkleProof, err := withdrawalSMT.Prove(treeKey)
	if err != nil {
		t.Fatalf("withdrawalSMT.Prove failed: %v", err)
	}

	// Tampered proof #1: flip a sibling hash.
	tampered := *merkleProof
	tampered.Siblings = make([]types.Hash, len(merkleProof.Siblings))
	copy(tampered.Siblings, merkleProof.Siblings)
	tampered.Siblings[0] = types.Hash{0xFF}

	proof1 := &MerkleWithdrawalProof{
		WithdrawalRoot: withdrawalRoot,
		Proof:          &tampered,
		TreeKey:        treeKey,
	}
	if err := l1Bridge.ProcessWithdrawal(user, big.NewInt(300), batch.Index, 0, batch.BatchHash, proof1); err == nil {
		t.Error("tampered sibling proof should be rejected")
	}

	// Tampered proof #2: wrong withdrawal root.
	wrongRoot := types.Hash{0x99}
	proof2 := &MerkleWithdrawalProof{
		WithdrawalRoot: wrongRoot,
		Proof:          merkleProof,
		TreeKey:        treeKey,
	}
	if err := l1Bridge.ProcessWithdrawal(user, big.NewInt(300), batch.Index, 0, batch.BatchHash, proof2); err == nil {
		t.Error("proof with wrong withdrawal root should be rejected")
	}

	// Tampered proof #3: tampered leaf hash (does not match reconstructed leaf).
	tamperedLeaf := *merkleProof
	tamperedLeaf.LeafHash = types.Hash{0xAB}
	proof3 := &MerkleWithdrawalProof{
		WithdrawalRoot: withdrawalRoot,
		Proof:          &tamperedLeaf,
		TreeKey:        treeKey,
	}
	if err := l1Bridge.ProcessWithdrawal(user, big.NewInt(300), batch.Index, 0, batch.BatchHash, proof3); err == nil {
		t.Error("proof with tampered leaf hash should be rejected")
	}

	// Tampered proof #4: wrong amount in calldata (does not match committed leaf).
	// The attacker submits amount=999 instead of 300. The bridge reconstructs
	// leaf = SHA256(user || 999 || 0), which won't match the proof's LeafHash
	// (which was computed with amount=300). This is the core of R4-BRDG-02.
	proof4 := &MerkleWithdrawalProof{
		WithdrawalRoot: withdrawalRoot,
		Proof:          merkleProof,
		TreeKey:        treeKey,
	}
	if err := l1Bridge.ProcessWithdrawal(user, big.NewInt(999), batch.Index, 0, batch.BatchHash, proof4); err == nil {
		t.Error("proof with wrong amount should be rejected (audit R4-BRDG-02)")
	}

	// Valid proof should still work.
	validProof := &MerkleWithdrawalProof{
		WithdrawalRoot: withdrawalRoot,
		Proof:          merkleProof,
		TreeKey:        treeKey,
	}
	if err := l1Bridge.ProcessWithdrawal(user, big.NewInt(300), batch.Index, 0, batch.BatchHash, validProof); err != nil {
		t.Errorf("valid proof should be accepted: %v", err)
	}

	// L1 liquidity should have decreased by 300.
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(20000-300)) != 0 {
		t.Errorf("expected %d L1 liquidity, got %s", 20000-300, liq.String())
	}
}

// TestL2Bridge_NilProofRejected verifies that nil proofs are rejected.
func TestL2Bridge_NilProofRejected(t *testing.T) {
	l1Bridge, _, _, user, batch := setupWithdrawalBatch(t, 10000, 300)

	// Record the finalized state root on L1.
	l1Bridge.RecordFinalizedBatch(batch.Index, batch.PostStateRoot)

	// Nil proof.
	err := l1Bridge.ProcessWithdrawal(user, big.NewInt(300), batch.Index, 0, batch.BatchHash, nil)
	if err == nil {
		t.Error("nil proof should be rejected")
	}

	// Nil inner proof.
	err = l1Bridge.ProcessWithdrawal(user, big.NewInt(300), batch.Index, 0, batch.BatchHash, &MerkleWithdrawalProof{})
	if err == nil {
		t.Error("nil inner proof should be rejected")
	}
}

// TestL2Bridge_UnfinalizedBatchRejected verifies that withdrawals for batches
// without a recorded withdrawal root are rejected.
//
// AUDIT R4-BRDG-02 (2026-07-15): Rewritten. The old test relied on the
// finalized state root; the new design requires the dedicated withdrawal tree
// root to be recorded via RecordWithdrawalRoot. Without it, ProcessWithdrawal
// must fail with "no withdrawal root recorded for batch".
func TestL2Bridge_UnfinalizedBatchRejected(t *testing.T) {
	l1Bridge, _, l2Bridge, user, batch := setupWithdrawalBatch(t, 10000, 300)

	// Build a valid withdrawal proof, but DON'T call RecordWithdrawalRoot.
	// RLLP-R5-05 (2026-07-16): Pass bridge address to filter withdrawals only.
	withdrawalSMT := buildWithdrawalSMT(batch.Transactions, l2Bridge.GetBridgeAddress())
	treeKey := ComputeWithdrawalTreeKey(user, 0)
	merkleProof, err := withdrawalSMT.Prove(treeKey)
	if err != nil {
		t.Fatalf("withdrawalSMT.Prove failed: %v", err)
	}

	proof := &MerkleWithdrawalProof{
		WithdrawalRoot: withdrawalSMT.Root(),
		Proof:          merkleProof,
		TreeKey:        treeKey,
	}

	// ProcessWithdrawal should fail because the withdrawal root for this
	// batch was never recorded on L1.
	err = l1Bridge.ProcessWithdrawal(user, big.NewInt(300), batch.Index, 0, batch.BatchHash, proof)
	if err == nil {
		t.Error("withdrawal for unfinalized batch should be rejected")
	}

	// L1 liquidity should be unchanged.
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(20000)) != 0 {
		t.Errorf("expected %d L1 liquidity, got %s", 20000, liq.String())
	}
}

// TestStateManager_MintBurn verifies MintBalance and BurnBalance.
func TestStateManager_MintBurn(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	addr := types.Address{0x01}

	// Mint 1000
	if err := sm.MintBalance(addr, big.NewInt(1000)); err != nil {
		t.Fatalf("MintBalance failed: %v", err)
	}
	acc := sm.GetAccount(addr)
	if acc.Balance.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("expected 1000, got %s", acc.Balance.String())
	}

	// Burn 300
	if err := sm.BurnBalance(addr, big.NewInt(300)); err != nil {
		t.Fatalf("BurnBalance failed: %v", err)
	}
	acc = sm.GetAccount(addr)
	if acc.Balance.Cmp(big.NewInt(700)) != 0 {
		t.Errorf("expected 700, got %s", acc.Balance.String())
	}

	// Burn more than balance → error
	if err := sm.BurnBalance(addr, big.NewInt(1000)); err == nil {
		t.Error("expected error for insufficient balance burn")
	}

	// Mint 0 → error
	if err := sm.MintBalance(addr, big.NewInt(0)); err == nil {
		t.Error("expected error for zero mint")
	}

	// Burn 0 → error
	if err := sm.BurnBalance(addr, big.NewInt(0)); err == nil {
		t.Error("expected error for zero burn")
	}
}

// TestL2Bridge_EndToEndDepositWithdraw is an end-to-end test of the full
// deposit→withdraw cycle with Merkle proofs.
func TestL2Bridge_EndToEndDepositWithdraw(t *testing.T) {
	l1Bridge := NewMemoryL1Bridge()
	cfg := DefaultRollupConfig()
	bridgeAddr := types.Address{0xff}
	// RLLP-R5-05 (2026-07-16): Set BridgeAddress for burn semantics.
	cfg.BridgeAddress = bridgeAddr
	sm := NewStateManager(cfg)
	l2Bridge := NewL2Bridge(l1Bridge, sm, bridgeAddr)

	user := types.Address{0x42}

	// 1. User deposits 10000 QAU on L1
	depositHash, err := l1Bridge.Deposit(user, big.NewInt(10000))
	if err != nil {
		t.Fatalf("L1 deposit failed: %v", err)
	}

	// 2. L2 bridge processes deposit → mints 10000 on L2
	if err := l2Bridge.ProcessDeposit(depositHash); err != nil {
		t.Fatalf("L2 mint failed: %v", err)
	}
	acc := sm.GetAccount(user)
	if acc.Balance.Cmp(big.NewInt(10000)) != 0 {
		t.Fatalf("expected 10000 L2 balance, got %s", acc.Balance.String())
	}

	// L1 liquidity = 10000 (locked by deposit)
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(10000)) != 0 {
		t.Fatalf("expected 10000 L1 liquidity, got %s", liq.String())
	}

	// 3. User withdraws 6000 QAU back to L1 (L2 tx to bridgeAddr)
	withdrawalTx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 0,
		GasLimit: 21000,
		From:     user,
		To:       &bridgeAddr,
		Value:    big.NewInt(6000),
		ChainID:  cfg.ChainID,
	}

	// 4. Process the batch → executes withdrawal, archives state root
	prevRoot := sm.computeStateRoot()
	postRoot, _, err := sm.ProcessBatch(0, prevRoot, []*RollupTransaction{withdrawalTx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	batch := &Batch{
		Index:         0,
		PostStateRoot: postRoot,
		Transactions:  []*RollupTransaction{withdrawalTx},
		TxCount:       1,
	}
	batch.BatchHash = types.Hash{0xDE, 0xAD}

	// 5. Batch finalized → L2Bridge generates Merkle proof, releases 6000 on L1
	if err := l2Bridge.ProcessFinalizedBatch(batch); err != nil {
		t.Fatalf("ProcessFinalizedBatch failed: %v", err)
	}

	// L1 liquidity = 10000 - 6000 = 4000
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(4000)) != 0 {
		t.Errorf("expected 4000 L1 liquidity after withdrawal, got %s", liq.String())
	}

	// 6. Second deposit + second withdrawal (verify no state leakage)
	depositHash2, _ := l1Bridge.Deposit(user, big.NewInt(2000))
	l2Bridge.ProcessDeposit(depositHash2)
	// L2 balance: 10000 - 6000 (withdrawal) + 2000 (2nd deposit) = 6000 (gas=0)
	acc = sm.GetAccount(user)
	expectedL2 := big.NewInt(10000 - 6000 + 2000)
	if acc.Balance.Cmp(expectedL2) != 0 {
		t.Errorf("expected %s L2 balance after 2nd deposit, got %s", expectedL2.String(), acc.Balance.String())
	}
	// L1 liquidity: 4000 + 2000 = 6000
	if liq := l1Bridge.GetLiquidity(); liq.Cmp(big.NewInt(6000)) != 0 {
		t.Errorf("expected 6000 L1 liquidity after 2nd deposit, got %s", liq.String())
	}
}

// --- RLLP-R5-09 tests: deposit L1 finality check ---

// TestRLLP_R5_09_DepositBlockedBeforeFinality verifies that when
// requiredDepositConfirmations is set, ProcessDeposit refuses to mint until
// the deposit's L1 block has enough confirmations.
//
// Regression scenario BEFORE the fix:
//  1. User deposits 1000 QAU on L1 at height H
//  2. L1 reorgs at height H+2, rolling back the deposit
//  3. But L2Bridge.ProcessDeposit already minted 1000 L2 QAU (no finality check)
//  4. Result: 1000 unbacked L2 QAU in circulation
//
// AFTER the fix: ProcessDeposit checks that currentL1Height - deposit.L1Height
// >= requiredDepositConfirmations before minting. If not, returns
// ErrDepositNotFinalized so the caller can retry later.
func TestRLLP_R5_09_DepositBlockedBeforeFinality(t *testing.T) {
	l1Bridge := NewMemoryL1Bridge().(*memoryL1Bridge)
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	bridgeAddr := types.Address{0xff}

	l2Bridge := NewL2Bridge(l1Bridge, sm, bridgeAddr)
	// RLLP-R5-09: Require 10 L1 confirmations before minting.
	l2Bridge.SetRequiredDepositConfirmations(10)
	// Use the L1 bridge itself as the height reader (it implements
	// L1HeightReader via GetCurrentHeight).
	l2Bridge.SetL1HeightReader(l1Bridge)

	depositor := types.Address{0x01}

	// Deposit at L1 height 5.
	l1Bridge.SetHeight(5)
	depositHash, err := l1Bridge.Deposit(depositor, big.NewInt(1000))
	if err != nil {
		t.Fatalf("L1 Deposit failed: %v", err)
	}

	// Verify the deposit recorded L1Height=5.
	d, ok := l1Bridge.GetDeposit(depositHash)
	if !ok {
		t.Fatal("deposit not found")
	}
	if d.L1Height != 5 {
		t.Fatalf("deposit L1Height=%d, want 5", d.L1Height)
	}

	// At L1 height 8 (only 3 confirmations), minting must be blocked.
	l1Bridge.SetHeight(8)
	err = l2Bridge.ProcessDeposit(depositHash)
	if err == nil {
		t.Fatal("RLLP-R5-09 REGRESSION: ProcessDeposit succeeded with only 3 confirmations (need 10)")
	}
	if !errorsIs(err, ErrDepositNotFinalized) {
		t.Errorf("expected ErrDepositNotFinalized, got: %v", err)
	}

	// Verify NO L2 balance was minted.
	acc := sm.GetAccount(depositor)
	if acc != nil && acc.Balance.Sign() > 0 {
		t.Errorf("L2 balance minted before finality: got %s, want 0", acc.Balance.String())
	}

	// At L1 height 15 (10 confirmations: 15-5=10), minting should succeed.
	l1Bridge.SetHeight(15)
	if err := l2Bridge.ProcessDeposit(depositHash); err != nil {
		t.Fatalf("ProcessDeposit should succeed with 10 confirmations: %v", err)
	}

	acc = sm.GetAccount(depositor)
	if acc == nil || acc.Balance.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("expected 1000 L2 balance after finality, got %v", acc)
	}

	// Double-mint should still fail (idempotency preserved).
	if err := l2Bridge.ProcessDeposit(depositHash); err != ErrDepositAlreadyMinted {
		t.Errorf("expected ErrDepositAlreadyMinted on retry, got: %v", err)
	}

	t.Log("✅ RLLP-R5-09: deposit blocked before finality, minted after sufficient confirmations")
}

// TestRLLP_R5_09_FailClosed_NoHeightReader verifies that when finality
// checking is enabled but no L1HeightReader is configured, ProcessDeposit
// fail-closes (refuses to mint) rather than silently allowing the deposit.
func TestRLLP_R5_09_FailClosed_NoHeightReader(t *testing.T) {
	l1Bridge := NewMemoryL1Bridge()
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	bridgeAddr := types.Address{0xff}

	l2Bridge := NewL2Bridge(l1Bridge, sm, bridgeAddr)
	// Enable finality checking but DON'T inject an L1HeightReader.
	l2Bridge.SetRequiredDepositConfirmations(10)

	depositor := types.Address{0x01}
	depositHash, err := l1Bridge.Deposit(depositor, big.NewInt(1000))
	if err != nil {
		t.Fatalf("L1 Deposit failed: %v", err)
	}

	// ProcessDeposit must fail-closed: cannot verify finality without a reader.
	err = l2Bridge.ProcessDeposit(depositHash)
	if err == nil {
		t.Fatal("RLLP-R5-09 REGRESSION: ProcessDeposit succeeded with finality enabled but no L1HeightReader (fail-open)")
	}

	// Verify NO L2 balance was minted.
	acc := sm.GetAccount(depositor)
	if acc != nil && acc.Balance.Sign() > 0 {
		t.Errorf("L2 balance minted despite fail-closed: got %s", acc.Balance.String())
	}

	t.Log("✅ RLLP-R5-09: fail-closed when L1HeightReader is nil")
}

// TestRLLP_R5_09_FailClosed_UnknownL1Height verifies that when a deposit has
// L1Height=0 (unknown L1 inclusion block), ProcessDeposit fail-closes rather
// than assuming the deposit is safe to mint.
func TestRLLP_R5_09_FailClosed_UnknownL1Height(t *testing.T) {
	l1Bridge := NewMemoryL1Bridge().(*memoryL1Bridge)
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	bridgeAddr := types.Address{0xff}

	l2Bridge := NewL2Bridge(l1Bridge, sm, bridgeAddr)
	l2Bridge.SetRequiredDepositConfirmations(10)
	l2Bridge.SetL1HeightReader(l1Bridge)

	// Manually create a deposit with L1Height=0 (simulating a deposit
	// created before the fix was deployed, or a buggy L1Bridge impl).
	depositor := types.Address{0x01}
	amount := big.NewInt(1000)
	zeroHeightDeposit := &Deposit{
		Hash:      computeDepositHash(depositor, amount, 0),
		Depositor: depositor,
		Amount:    new(big.Int).Set(amount),
		Timestamp: time.Now().Unix(),
		L1Height:  0, // unknown
	}
	l1Bridge.mu.Lock()
	l1Bridge.deposits[zeroHeightDeposit.Hash] = zeroHeightDeposit
	l1Bridge.mu.Unlock()

	// Advance L1 height to simulate blocks passing.
	l1Bridge.SetHeight(100)

	// ProcessDeposit must fail-closed: cannot verify finality with L1Height=0.
	err := l2Bridge.ProcessDeposit(zeroHeightDeposit.Hash)
	if err == nil {
		t.Fatal("RLLP-R5-09 REGRESSION: ProcessDeposit succeeded with L1Height=0 (unknown L1 block)")
	}

	// Verify NO L2 balance was minted.
	acc := sm.GetAccount(depositor)
	if acc != nil && acc.Balance.Sign() > 0 {
		t.Errorf("L2 balance minted despite unknown L1Height: got %s", acc.Balance.String())
	}

	t.Log("✅ RLLP-R5-09: fail-closed when deposit.L1Height=0 (unknown)")
}

// TestRLLP_R5_09_BackwardCompatible_DefaultDisabled verifies that when
// requiredDepositConfirmations is 0 (the default), ProcessDeposit skips the
// finality check and mints immediately — preserving backward compatibility
// for dev/test environments.
func TestRLLP_R5_09_BackwardCompatible_DefaultDisabled(t *testing.T) {
	l1Bridge := NewMemoryL1Bridge()
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	bridgeAddr := types.Address{0xff}

	l2Bridge := NewL2Bridge(l1Bridge, sm, bridgeAddr)
	// DON'T call SetRequiredDepositConfirmations — default is 0 (disabled).
	// Also DON'T call SetL1HeightReader — not needed when check is disabled.

	depositor := types.Address{0x01}
	depositHash, err := l1Bridge.Deposit(depositor, big.NewInt(500))
	if err != nil {
		t.Fatalf("L1 Deposit failed: %v", err)
	}

	// ProcessDeposit should succeed immediately (no finality check).
	if err := l2Bridge.ProcessDeposit(depositHash); err != nil {
		t.Fatalf("ProcessDeposit should succeed with default config (no finality check): %v", err)
	}

	acc := sm.GetAccount(depositor)
	if acc == nil || acc.Balance.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("expected 500 L2 balance, got %v", acc)
	}

	t.Log("✅ RLLP-R5-09: backward compatible — finality check disabled by default")
}

// TestRLLP_R5_09_BboltBridge_RestoresCurrentHeight verifies that after a
// restart, bboltL1Bridge reconstructs currentHeight from the max L1Height of
// restored deposits, so new deposits get a correct L1Height.
func TestRLLP_R5_09_BboltBridge_RestoresCurrentHeight(t *testing.T) {
	// Use a temp bbolt DB.
	dir := filepath.Join(t.TempDir(), "rollup-l1bridge")
	db1, err := db.NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}

	// Phase 1: Create deposits at L1 heights 5, 10, 15.
	bridge1, err := NewBboltL1Bridge(db1)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge(1): %v", err)
	}
	mp1 := bridge1.(*bboltL1Bridge).memoryL1Bridge

	mp1.SetHeight(5)
	h1, _ := bridge1.Deposit(types.Address{0x01}, big.NewInt(100))
	mp1.SetHeight(10)
	h2, _ := bridge1.Deposit(types.Address{0x02}, big.NewInt(200))
	mp1.SetHeight(15)
	h3, _ := bridge1.Deposit(types.Address{0x03}, big.NewInt(300))

	// Verify L1Heights were recorded.
	d1, _ := bridge1.GetDeposit(h1)
	d2, _ := bridge1.GetDeposit(h2)
	d3, _ := bridge1.GetDeposit(h3)
	if d1.L1Height != 5 || d2.L1Height != 10 || d3.L1Height != 15 {
		t.Fatalf("L1Heights before restart: d1=%d d2=%d d3=%d (want 5,10,15)",
			d1.L1Height, d2.L1Height, d3.L1Height)
	}

	db1.Close()

	// Phase 2: Reopen DB and verify currentHeight is reconstructed to 15.
	db2, err := db.NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB(2): %v", err)
	}
	defer db2.Close()

	bridge2, err := NewBboltL1Bridge(db2)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge(2): %v", err)
	}
	mp2 := bridge2.(*bboltL1Bridge).memoryL1Bridge

	if mp2.currentHeight != 15 {
		t.Errorf("RLLP-R5-09: currentHeight after restart=%d, want 15 (max deposit L1Height)", mp2.currentHeight)
	}

	// A new deposit after restart should get L1Height >= 15 (the reconstructed
	// currentHeight). This ensures the finality check works correctly for
	// new deposits after a restart.
	h4, _ := bridge2.Deposit(types.Address{0x04}, big.NewInt(400))
	d4, _ := bridge2.GetDeposit(h4)
	if d4.L1Height != 15 {
		t.Errorf("new deposit after restart: L1Height=%d, want 15 (reconstructed currentHeight)", d4.L1Height)
	}

	t.Log("✅ RLLP-R5-09: bboltL1Bridge reconstructs currentHeight from max deposit L1Height after restart")
}

// errorsIs is a wrapper around errors.Is to avoid importing the errors
// package in the test file (which already imports math/big and testing).
// This keeps the test file's imports minimal.
func errorsIs(err error, target error) bool {
	return errors.Is(err, target)
}
