// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// TestBboltL1Bridge_Persistence verifies that deposits, liquidity, and
// finalized state roots survive a simulated restart (re-creation with the
// same database).
// W-P1-6 Phase 3 (2026-07-14)
func TestBboltL1Bridge_Persistence(t *testing.T) {
	database := db.NewMemDB()

	// Phase 1: Create bridge, perform operations, then "crash" (drop reference).
	bridge1, err := NewBboltL1Bridge(database)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge #1 failed: %v", err)
	}

	depositor := types.Address{0x01}
	depHash, err := bridge1.Deposit(depositor, big.NewInt(10000))
	if err != nil {
		t.Fatalf("Deposit failed: %v", err)
	}

	stateRoot := types.Hash{0xAA, 0xBB, 0xCC}
	if err := bridge1.RecordFinalizedBatch(0, stateRoot); err != nil {
		t.Fatalf("RecordFinalizedBatch failed: %v", err)
	}
	if err := bridge1.RecordFinalizedBatch(1, types.Hash{0xDD}); err != nil {
		t.Fatalf("RecordFinalizedBatch(1) failed: %v", err)
	}

	// Verify state before "restart".
	if liq := bridge1.GetLiquidity(); liq.Cmp(big.NewInt(10000)) != 0 {
		t.Fatalf("expected 10000 liquidity, got %s", liq.String())
	}

	// Phase 2: "Restart" — create new bridge with the SAME database.
	bridge2, err := NewBboltL1Bridge(database)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge #2 failed: %v", err)
	}

	// Deposit restored.
	d, ok := bridge2.GetDeposit(depHash)
	if !ok {
		t.Fatal("deposit not restored after restart")
	}
	if d.Depositor != depositor {
		t.Errorf("depositor mismatch: got %x, want %x", d.Depositor, depositor)
	}
	if d.Amount.Cmp(big.NewInt(10000)) != 0 {
		t.Errorf("amount mismatch: got %s, want 10000", d.Amount.String())
	}

	// Liquidity restored.
	if liq := bridge2.GetLiquidity(); liq.Cmp(big.NewInt(10000)) != 0 {
		t.Errorf("expected 10000 liquidity after restart, got %s", liq.String())
	}

	// Finalized roots restored.
	root0, ok := bridge2.GetFinalizedStateRoot(0)
	if !ok {
		t.Fatal("finalized root 0 not restored")
	}
	if root0 != stateRoot {
		t.Errorf("finalized root 0 mismatch: got %x, want %x", root0, stateRoot)
	}
	root1, ok := bridge2.GetFinalizedStateRoot(1)
	if !ok {
		t.Fatal("finalized root 1 not restored")
	}
	if root1 != (types.Hash{0xDD}) {
		t.Errorf("finalized root 1 mismatch: got %x", root1)
	}
}

// TestBboltL1Bridge_WithdrawalPersistence verifies that a processed
// withdrawal survives a simulated restart — calling ProcessWithdrawal again
// after restart returns ErrWithdrawalAlreadyProcessed.
// W-P1-6 Phase 3 (2026-07-14)
//
// AUDIT R4-BRDG-02 (2026-07-15): Rewritten to use the dedicated withdrawal
// tree. Also verifies that the withdrawal root itself is persisted — without
// persistence, a restart would lose the root and all withdrawals for that
// batch would be rejected (denial of service) or, worse, the bridge contract
// might fall back to a less-strict verification path.
func TestBboltL1Bridge_WithdrawalPersistence(t *testing.T) {
	database := db.NewMemDB()

	// Get a valid batch + state root via the standard helper.
	_, _, l2Bridge, user, batch := setupWithdrawalBatch(t, 10000, 500)

	// Create bboltL1Bridge #1 and fund it.
	bridge1, err := NewBboltL1Bridge(database)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge #1 failed: %v", err)
	}
	bridge1.Deposit(types.Address{0x99}, big.NewInt(10000))

	// Record finalized batch + dedicated withdrawal root.
	if err := bridge1.RecordFinalizedBatch(batch.Index, batch.PostStateRoot); err != nil {
		t.Fatalf("RecordFinalizedBatch failed: %v", err)
	}
	// RLLP-R5-05 (2026-07-16): Pass bridge address to filter withdrawals only.
	withdrawalSMT := buildWithdrawalSMT(batch.Transactions, l2Bridge.GetBridgeAddress())
	withdrawalRoot := withdrawalSMT.Root()
	if err := bridge1.RecordWithdrawalRoot(batch.Index, withdrawalRoot); err != nil {
		t.Fatalf("RecordWithdrawalRoot failed: %v", err)
	}
	treeKey := ComputeWithdrawalTreeKey(user, 0)
	merkleProof, err := withdrawalSMT.Prove(treeKey)
	if err != nil {
		t.Fatalf("withdrawalSMT.Prove failed: %v", err)
	}
	proof := &MerkleWithdrawalProof{
		WithdrawalRoot: withdrawalRoot,
		Proof:          merkleProof,
		TreeKey:        treeKey,
	}

	// Process withdrawal — should succeed.
	err = bridge1.ProcessWithdrawal(user, big.NewInt(500), batch.Index, 0, batch.BatchHash, proof)
	if err != nil {
		t.Fatalf("ProcessWithdrawal failed: %v", err)
	}
	// Liquidity: 10000 - 500 = 9500
	if liq := bridge1.GetLiquidity(); liq.Cmp(big.NewInt(9500)) != 0 {
		t.Fatalf("expected 9500 liquidity, got %s", liq.String())
	}

	// "Restart" — create new bridge with same db.
	bridge2, err := NewBboltL1Bridge(database)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge #2 failed: %v", err)
	}

	// Liquidity restored to 9500 (not 10000).
	if liq := bridge2.GetLiquidity(); liq.Cmp(big.NewInt(9500)) != 0 {
		t.Errorf("expected 9500 liquidity after restart, got %s", liq.String())
	}

	// Finalized root restored.
	root, ok := bridge2.GetFinalizedStateRoot(batch.Index)
	if !ok {
		t.Fatal("finalized root not restored")
	}
	if root != batch.PostStateRoot {
		t.Errorf("finalized root mismatch: got %x, want %x", root, batch.PostStateRoot)
	}

	// AUDIT R4-BRDG-02: Withdrawal root restored after restart.
	restoredWR, ok := bridge2.GetWithdrawalRoot(batch.Index)
	if !ok {
		t.Fatal("withdrawal root not restored after restart")
	}
	if restoredWR != withdrawalRoot {
		t.Errorf("withdrawal root mismatch: got %x, want %x", restoredWR, withdrawalRoot)
	}

	// Re-processing the same withdrawal should fail (idempotency preserved).
	err = bridge2.ProcessWithdrawal(user, big.NewInt(500), batch.Index, 0, batch.BatchHash, proof)
	if err != ErrWithdrawalAlreadyProcessed {
		t.Errorf("expected ErrWithdrawalAlreadyProcessed after restart, got %v", err)
	}
}

// TestBboltL1Bridge_NilDB verifies that NewBboltL1Bridge rejects nil database.
func TestBboltL1Bridge_NilDB(t *testing.T) {
	_, err := NewBboltL1Bridge(nil)
	if err == nil {
		t.Error("expected error for nil database")
	}
}

// TestBboltL1Bridge_InterfaceCompliance verifies bboltL1Bridge satisfies the
// full L1Bridge interface (compile-time check).
func TestBboltL1Bridge_InterfaceCompliance(t *testing.T) {
	var _ L1Bridge = (*bboltL1Bridge)(nil)
}
