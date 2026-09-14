// Quantaureum Node source, version 1.0.0.
package parallel

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// QVM-R7-04 (High) — ParallelQVM.executeCall's simple-transfer path did not record a WriteSet, breaking conflict detection
//
// Audit quote (AUDIT-R7-QVM-2026-07-17.md QVM-R7-04):
//   "When the target account has no code, executeCall takes the simple-transfer path... result.WriteSet stays the initial empty map"
//   "Exploit: Tx1: A->B 100, Tx2: A->C 100, A has only 100 -> after parallel execution A=-100, minting funds from thin air"
//
// This test verifies:
//   1. after two conflicting simple transfers (A->B, A->C, A has funds for only one) run in parallel,
//      A's balance never goes negative (no funds minted out of thin air).
//   2. validateResults detects the WriteSet conflict and triggers a retry or sequential fallback.
//   3. result.WriteSet is indeed populated on the simple-transfer path (checked via intermediate state).
//
// If this test passes, the "fund-minting risk" described in QVM-R7-04 does not hold:
//   - isolatedStateWrapper.SetBalance calls recordWrite, populating result.WriteSet
//   - validateResults detects the read/write conflict on A's balance
//   - the post-conflict retry or sequential fallback guarantees a correct final state
//
// If this test fails (A's balance is negative), the vulnerability is real and executeTransfer must be fixed
// to fill result.WriteSet explicitly.

// TestQVM_R7_04_SimpleTransferConflictDetection verifies that two conflicting
// simple transfers (A→B and A→C, where A has only enough for one) do NOT
// result in negative balance (inflation). The parallel executor must detect
// the write-set conflict and retry/fall-back to sequential execution.
func TestQVM_R7_04_SimpleTransferConflictDetection(t *testing.T) {
	state := newMinimalMockState()

	// A has 100, B and C have 0
	addrA := types.Address{0xAA}
	addrB := types.Address{0xBB}
	addrC := types.Address{0xCC}
	state.SetBalance(addrA, big.NewInt(100))
	state.SetBalance(addrB, big.NewInt(0))
	state.SetBalance(addrC, big.NewInt(0))

	config := DefaultParallelQVMConfig()
	config.ChainID = 1
	config.NumWorkers = 2
	config.MaxRetries = 3
	config.EnableSpeculativeExecution = true
	pq := NewParallelQVM(config)
	pq.EnableConsensusMode()

	// Two conflicting transfers: A→B 100, A→C 100
	// Both targets have no code → simple transfer path
	calls := []*ContractCall{
		NewContractCall(0, addrB, addrA, nil, 100000, 100),
		NewContractCall(1, addrC, addrA, nil, 100000, 100),
	}

	results, err := pq.Execute(calls, state)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// SECURITY-CRITICAL: A must NOT have negative balance (no inflation).
	balA := state.GetBalance(addrA)
	if balA.Sign() < 0 {
		t.Fatalf("QVM-R7-04 INFLATION: A balance is negative (%s) — conflict detection failed, both transfers applied", balA)
	}

	// A should have 0 (one transfer succeeded) or 100 (both failed).
	// A must NOT be -100 (both succeeded without conflict detection).
	balB := state.GetBalance(addrB)
	balC := state.GetBalance(addrC)
	total := new(big.Int).Add(balA, balB)
	total.Add(total, balC)
	if total.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("QVM-R7-04 INFLATION: total supply changed (A=%s B=%s C=%s, total=%s, expected=100)",
			balA, balB, balC, total)
	}

	t.Logf("QVM-R7-04 OK: A=%s B=%s C=%s (total=100, no inflation)", balA, balB, balC)

	// At least one transfer must have succeeded (A had enough for one).
	// If both failed, that's overly conservative but not a security issue.
	if balB.Sign() == 0 && balC.Sign() == 0 {
		t.Logf("QVM-R7-04 NOTE: both transfers failed (conservative) — not a security issue but may indicate over-retry")
	}
}

// TestQVM_R7_04_SimpleTransferWriteSetPopulated verifies that the simple
// transfer path (no code at target) DOES populate result.WriteSet. This
// directly tests the audit claim that "result.WriteSet stays the initial empty map".
func TestQVM_R7_04_SimpleTransferWriteSetPopulated(t *testing.T) {
	state := newMinimalMockState()

	addrA := types.Address{0xAA}
	addrB := types.Address{0xBB}
	state.SetBalance(addrA, big.NewInt(1000))
	state.SetBalance(addrB, big.NewInt(0))

	config := DefaultParallelQVMConfig()
	config.ChainID = 1
	pq := NewParallelQVM(config)
	pq.EnableConsensusMode()

	calls := []*ContractCall{
		NewContractCall(0, addrB, addrA, nil, 100000, 100),
	}

	results, err := pq.Execute(calls, state)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.Success {
		t.Fatalf("transfer should succeed: %v", r.Error)
	}

	// SECURITY-CRITICAL: result.WriteSet must contain entries for both
	// caller (A) and contract (B) balance keys.
	if r.WriteSet == nil {
		t.Fatal("QVM-R7-04: result.WriteSet is nil — audit claim confirmed, WriteSet not populated")
	}

	// Check caller (A) write
	aWrites, aOk := r.WriteSet[addrA]
	if !aOk {
		t.Fatal("QVM-R7-04: result.WriteSet[addrA] missing — caller balance write not recorded")
	}
	if len(aWrites) == 0 {
		t.Fatal("QVM-R7-04: result.WriteSet[addrA] is empty — caller balance write not recorded")
	}

	// Check contract (B) write
	bWrites, bOk := r.WriteSet[addrB]
	if !bOk {
		t.Fatal("QVM-R7-04: result.WriteSet[addrB] missing — recipient balance write not recorded")
	}
	if len(bWrites) == 0 {
		t.Fatal("QVM-R7-04: result.WriteSet[addrB] is empty — recipient balance write not recorded")
	}

	t.Logf("QVM-R7-04 OK: WriteSet populated (addrA keys=%d, addrB keys=%d)", len(aWrites), len(bWrites))
}

// TestQVM_R7_04_SimpleTransferReadSetPopulated verifies that the simple
// transfer path also populates result.ReadSet (needed for conflict detection).
func TestQVM_R7_04_SimpleTransferReadSetPopulated(t *testing.T) {
	state := newMinimalMockState()

	addrA := types.Address{0xAA}
	addrB := types.Address{0xBB}
	state.SetBalance(addrA, big.NewInt(1000))
	state.SetBalance(addrB, big.NewInt(0))

	config := DefaultParallelQVMConfig()
	config.ChainID = 1
	pq := NewParallelQVM(config)
	pq.EnableConsensusMode()

	calls := []*ContractCall{
		NewContractCall(0, addrB, addrA, nil, 100000, 100),
	}

	results, err := pq.Execute(calls, state)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(results) != 1 || !results[0].Success {
		t.Fatalf("transfer should succeed")
	}

	r := results[0]
	if r.ReadSet == nil {
		t.Fatal("QVM-R7-04: result.ReadSet is nil")
	}

	// Caller (A) balance must be in ReadSet (executeTransfer reads it for balance check).
	aReads, aOk := r.ReadSet[addrA]
	if !aOk || len(aReads) == 0 {
		t.Fatal("QVM-R7-04: result.ReadSet[addrA] missing — caller balance read not recorded")
	}

	t.Logf("QVM-R7-04 OK: ReadSet populated (addrA keys=%d)", len(aReads))
}
