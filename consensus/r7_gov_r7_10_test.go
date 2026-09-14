// Quantaureum Node source, version 1.0.0.
package consensus

// GOV-R7-10 (2026-07-17) regression tests.
//
// Audit finding (AUDIT-R7-MINISTRY-2026-07-17.md GOV-R7-10 [Medium]):
//   MinistryWorks.CompleteCrossChainTx executed `bridge.PendingTxCount--`
//   without a lower-bound check. PendingTxCount is a uint64; if a duplicate
//   CompleteCrossChainTx call ever reached the decrement (e.g., via internal
//   async retry that bypasses the RPC nonce protection), the counter would
//   underflow to MaxUint64, polluting GetBridgeHealth and capacity checks
//   that depend on PendingTxCount.
//
// Fix:
//   1. Add idempotent handling at the entry — if the tx is already
//      "completed", return nil without decrementing again.
//   2. Add defensive lower-bound check on the decrement:
//        if bridge.PendingTxCount > 0 { bridge.PendingTxCount-- }

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestGOV_R7_10_CompleteCrossChainTx_IdempotentOnRetry verifies that calling
// CompleteCrossChainTx twice on the same tx succeeds both times and does
// NOT underflow PendingTxCount.
func TestGOV_R7_10_CompleteCrossChainTx_IdempotentOnRetry(t *testing.T) {
	_, works := setupMinistryWorks(t)

	bridge, err := works.RegisterBridge(testSystemCaller, "R7-10 test bridge", 1, 3, "100000")
	if err != nil {
		t.Fatalf("RegisterBridge failed: %v", err)
	}

	tx, err := works.RecordCrossChainTx(testSystemCaller, bridge.ID, types.Hash{0xa1}, "100")
	if err != nil {
		t.Fatalf("RecordCrossChainTx failed: %v", err)
	}
	if tx.Status != "pending" {
		t.Fatalf("tx status = %s, want pending", tx.Status)
	}

	// Capture PendingTxCount after recording (should be 1).
	beforeBridge, err := works.GetBridge(bridge.ID)
	if err != nil {
		t.Fatalf("GetBridge failed: %v", err)
	}
	beforeCount := beforeBridge.PendingTxCount
	if beforeCount != 1 {
		t.Fatalf("PendingTxCount after RecordCrossChainTx = %d, want 1", beforeCount)
	}

	// First completion must succeed and decrement PendingTxCount.
	if err := works.CompleteCrossChainTx(testSystemCaller, tx.ID, types.Hash{0xb1}); err != nil {
		t.Fatalf("first CompleteCrossChainTx failed: %v", err)
	}
	afterFirst, _ := works.GetBridge(bridge.ID)
	if afterFirst.PendingTxCount != 0 {
		t.Errorf("PendingTxCount after first completion = %d, want 0", afterFirst.PendingTxCount)
	}

	// Second completion (RPC retry / duplicate) must succeed (idempotent)
	// WITHOUT further decrement (must stay 0, NOT underflow to MaxUint64).
	if err := works.CompleteCrossChainTx(testSystemCaller, tx.ID, types.Hash{0xb1}); err != nil {
		t.Fatalf("second CompleteCrossChainTx (idempotent retry) failed: %v", err)
	}
	afterSecond, _ := works.GetBridge(bridge.ID)
	if afterSecond.PendingTxCount != 0 {
		t.Errorf("PendingTxCount after idempotent retry = %d, want 0 (no underflow)", afterSecond.PendingTxCount)
	}
}

// TestGOV_R7_10_CompleteCrossChainTx_NoUnderflowOnZeroCount verifies that
// even if PendingTxCount is somehow already 0 (e.g., manual state reset),
// decrement does NOT underflow to MaxUint64.
func TestGOV_R7_10_CompleteCrossChainTx_NoUnderflowOnZeroCount(t *testing.T) {
	_, works := setupMinistryWorks(t)

	bridge, err := works.RegisterBridge(testSystemCaller, "R7-10 underflow test", 1, 3, "100000")
	if err != nil {
		t.Fatalf("RegisterBridge failed: %v", err)
	}

	// Manually set PendingTxCount = 0 to simulate the edge case where the
	// counter is already at zero (e.g., misaligned state between tx records
	// and bridge counter). Then record a tx (which increments to 1) and
	// complete it (decrements back to 0). The next completion must stay 0.
	works.mu.Lock()
	if b, ok := works.bridges[bridge.ID]; ok {
		b.PendingTxCount = 0
	}
	works.mu.Unlock()

	tx, err := works.RecordCrossChainTx(testSystemCaller, bridge.ID, types.Hash{0xc1}, "50")
	if err != nil {
		t.Fatalf("RecordCrossChainTx failed: %v", err)
	}

	// Complete — should decrement from 1 to 0.
	if err := works.CompleteCrossChainTx(testSystemCaller, tx.ID, types.Hash{0xd1}); err != nil {
		t.Fatalf("CompleteCrossChainTx failed: %v", err)
	}
	b1, _ := works.GetBridge(bridge.ID)
	if b1.PendingTxCount != 0 {
		t.Errorf("PendingTxCount after completion = %d, want 0", b1.PendingTxCount)
	}

	// Force a second decrement path by manually setting tx back to pending.
	// This simulates a bug or async path that re-triggers completion.
	works.mu.Lock()
	if stored, ok := works.crossChainTx[tx.ID]; ok {
		stored.Status = "pending"
	}
	works.mu.Unlock()

	// Complete again — PendingTxCount is 0, must NOT underflow.
	if err := works.CompleteCrossChainTx(testSystemCaller, tx.ID, types.Hash{0xd1}); err != nil {
		t.Fatalf("second CompleteCrossChainTx failed: %v", err)
	}
	b2, _ := works.GetBridge(bridge.ID)
	if b2.PendingTxCount != 0 {
		t.Errorf("PendingTxCount after second completion = %d, want 0 (no underflow to MaxUint64)", b2.PendingTxCount)
	}
}
