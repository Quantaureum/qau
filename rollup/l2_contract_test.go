// Quantaureum Node source, version 1.0.0.
package rollup

// W-P2-3: L2 contract execution end-to-end tests.
//
// Goal (per the rollup production-readiness plan):
//   Verify that QVM integration allows correct L2 contract calls.
//
// Steps:
//   1. Deploy a simple Counter contract to L2 (manually set code)
//   2. Call `increment()`, verify storage correctly updated
//   3. Verify stateRoot includes storage changes
//
// DoD: L2 contract deployment + call + storage update full chain test passes.
//
// The rollup's QVMExecutor interface only exposes Call (not Create), so
// contract "deployment" is done by pre-setting code on an account via the
// StateDB adapter. This mirrors how the node initializes system contracts.

import (
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// counterBytecode is a simple Counter contract that increments slot 0 by 1
// on every call. No function selector dispatch — any call triggers increment.
//
// Bytecode disassembly:
//
//	PUSH1 0x00   // stack: [0]           — slot key
//	SLOAD        // stack: [value]       — load slot 0
//	PUSH1 0x01   // stack: [value, 1]
//	ADD          // stack: [value+1]
//	PUSH1 0x00   // stack: [value+1, 0]  — slot key for SSTORE
//	SSTORE       // slot[0] = value+1, stack: []
//	STOP
var counterBytecode = []byte{
	0x10, 0x00, // PUSH1 0x00
	0x60,       // SLOAD
	0x10, 0x01, // PUSH1 0x01
	0x20,       // ADD
	0x10, 0x00, // PUSH1 0x00
	0x61, // SSTORE
	0x00, // STOP
}

// setValueBytecode stores the first 32 bytes of calldata to slot 0.
//
// Bytecode disassembly:
//
//	PUSH1 0x00   // stack: [0]           — calldata offset
//	CALLDATALOAD // stack: [calldata[0:32]]
//	PUSH1 0x00   // stack: [calldata[0:32], 0]  — slot key
//	SSTORE       // slot[0] = calldata[0:32]
//	STOP
var setValueBytecode = []byte{
	0x10, 0x00, // PUSH1 0x00
	0x75,       // CALLDATALOAD
	0x10, 0x00, // PUSH1 0x00
	0x61, // SSTORE
	0x00, // STOP
}

// deployContract manually deploys bytecode to a contract address by setting
// Code + CodeHash on the account. This simulates contract deployment without
// needing the QVM Create path (which the rollup's QVMExecutor interface doesn't
// expose).
func deployContract(sm *StateManager, addr types.Address, bytecode []byte) {
	acc := sm.getOrCreateAccount(addr)
	acc.Code = append([]byte(nil), bytecode...)
	h := sha256.Sum256(bytecode)
	acc.CodeHash = types.Hash(h)
}

// --- W-P2-3 Test 1: Counter contract increment ---

// TestL2Contract_CounterIncrement deploys a Counter contract, calls it via a
// rollup batch, and verifies that storage slot 0 was incremented from 0 to 1.
func TestL2Contract_CounterIncrement(t *testing.T) {
	cfg := DefaultRollupConfig()
	executor := qvm.NewExecutor()

	sm := NewStateManager(cfg)
	sm.SetExecutor(executor)

	from := types.Address{10}
	contractAddr := types.Address{20}

	// Fund sender.
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000_000)

	// Deploy Counter contract.
	deployContract(sm, contractAddr, counterBytecode)

	// Verify deployment.
	acc := sm.GetAccount(contractAddr)
	if acc == nil || len(acc.Code) == 0 {
		t.Fatal("contract not deployed")
	}
	if acc.CodeHash == (types.Hash{}) {
		t.Fatal("CodeHash not set")
	}

	preRoot := sm.computeStateRoot()

	// Call increment() — tx with To=contract, empty Data, Value=0.
	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 100000,
		Value:    big.NewInt(0),
		From:     from,
		To:       &contractAddr,
		Data:     nil,
	}

	postRoot, gasUsed, err := sm.ProcessBatch(0, preRoot, []*RollupTransaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if gasUsed == 0 {
		t.Error("expected gasUsed > 0 for contract call")
	}

	// Verify storage slot 0 == 1.
	contractAcc := sm.GetAccount(contractAddr)
	if contractAcc == nil {
		t.Fatal("contract account missing after call")
	}
	slotKey := types.Hash{} // slot 0
	got := contractAcc.Storage[slotKey]
	expected := types.Hash{}
	expected[31] = 1 // big-endian uint256 = 1
	if got != expected {
		t.Fatalf("storage slot 0: got %x, want %x (counter should be 1)", got, expected)
	}

	// Verify stateRoot changed (storage was written).
	if postRoot == preRoot {
		t.Fatal("stateRoot unchanged after contract call — storage update not reflected")
	}
	t.Log("✅ Counter contract increment: storage[0] = 1, stateRoot changed")
}

// --- W-P2-3 Test 2: Multiple increments ---

// TestL2Contract_MultipleIncrements calls increment() 3 times and verifies
// the counter reaches 3.
func TestL2Contract_MultipleIncrements(t *testing.T) {
	cfg := DefaultRollupConfig()
	executor := qvm.NewExecutor()

	sm := NewStateManager(cfg)
	sm.SetExecutor(executor)

	from := types.Address{10}
	contractAddr := types.Address{20}

	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(100_000_000)
	deployContract(sm, contractAddr, counterBytecode)

	preRoot := sm.computeStateRoot()

	for i := 0; i < 3; i++ {
		tx := &RollupTransaction{
			Nonce:    uint64(i),
			GasPrice: 1,
			GasLimit: 100000,
			Value:    big.NewInt(0),
			From:     from,
			To:       &contractAddr,
		}
		postRoot, _, err := sm.ProcessBatch(uint64(i), preRoot, []*RollupTransaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch(%d): %v", i, err)
		}
		preRoot = postRoot
	}

	// Verify storage slot 0 == 3.
	contractAcc := sm.GetAccount(contractAddr)
	slotKey := types.Hash{}
	got := contractAcc.Storage[slotKey]
	expected := types.Hash{}
	expected[31] = 3
	if got != expected {
		t.Fatalf("storage slot 0: got %x, want %x (counter should be 3)", got, expected)
	}
	t.Log("✅ Multiple increments: storage[0] = 3 after 3 calls")
}

// --- W-P2-3 Test 3: SetValue contract with calldata ---

// TestL2Contract_SetValueWithCalldata deploys a contract that reads calldata
// and stores it to slot 0. Verifies that tx.Data is correctly passed to the
// QVM as calldata.
func TestL2Contract_SetValueWithCalldata(t *testing.T) {
	cfg := DefaultRollupConfig()
	executor := qvm.NewExecutor()

	sm := NewStateManager(cfg)
	sm.SetExecutor(executor)

	from := types.Address{10}
	contractAddr := types.Address{20}

	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(100_000_000)
	deployContract(sm, contractAddr, setValueBytecode)

	preRoot := sm.computeStateRoot()

	// Calldata: 32-byte big-endian value 0x4242.
	calldata := make([]byte, 32)
	calldata[30] = 0x42
	calldata[31] = 0x42

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 100000,
		Value:    big.NewInt(0),
		From:     from,
		To:       &contractAddr,
		Data:     calldata,
	}

	_, _, err := sm.ProcessBatch(0, preRoot, []*RollupTransaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	// Verify storage slot 0 == calldata.
	contractAcc := sm.GetAccount(contractAddr)
	slotKey := types.Hash{}
	got := contractAcc.Storage[slotKey]
	expected := types.Hash{}
	copy(expected[:], calldata)
	if got != expected {
		t.Fatalf("storage slot 0: got %x, want %x (should match calldata)", got, expected)
	}
	t.Log("✅ SetValue with calldata: storage[0] matches tx.Data")
}

// --- W-P2-3 Test 4: Contract call without executor falls back to transfer ---

// TestL2Contract_NoExecutorFallsBackToTransfer verifies that when no QVM
// executor is configured, a tx to a contract address is treated as a simple
// transfer (code is ignored). This is the W-P0-2 fallback behavior.
func TestL2Contract_NoExecutorFallsBackToTransfer(t *testing.T) {
	cfg := DefaultRollupConfig()
	// No sm.SetExecutor(...) — executor is nil.

	sm := NewStateManager(cfg)

	from := types.Address{10}
	contractAddr := types.Address{20}

	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000_000)
	deployContract(sm, contractAddr, counterBytecode)

	preRoot := sm.computeStateRoot()

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		From:     from,
		To:       &contractAddr,
	}

	_, _, err := sm.ProcessBatch(0, preRoot, []*RollupTransaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	// Storage should NOT be modified (no executor → no QVM execution).
	contractAcc := sm.GetAccount(contractAddr)
	slotKey := types.Hash{}
	got := contractAcc.Storage[slotKey]
	if got != (types.Hash{}) {
		t.Fatalf("storage slot 0: got %x, want empty (no executor → no storage write)", got)
	}

	// Value transfer should still happen (simple transfer fallback).
	if contractAcc.Balance.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("contract balance: got %s, want 500 (value transfer)", contractAcc.Balance.String())
	}
	t.Log("✅ No executor: contract call falls back to simple transfer (no storage change)")
}

// --- W-P2-3 Test 5: Failed contract call doesn't corrupt state ---

// TestL2Contract_FailedCallNoCorruption verifies that when a contract call
// fails (e.g., out of gas), the state is rolled back and subsequent calls
// work correctly.
func TestL2Contract_FailedCallNoCorruption(t *testing.T) {
	cfg := DefaultRollupConfig()
	executor := qvm.NewExecutor()

	sm := NewStateManager(cfg)
	sm.SetExecutor(executor)

	from := types.Address{10}
	contractAddr := types.Address{20}

	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(100_000_000)
	deployContract(sm, contractAddr, counterBytecode)

	preRoot := sm.computeStateRoot()

	// First call: insufficient gas → should fail but not corrupt state.
	tx1 := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 100, // way too low for SSTORE
		Value:    big.NewInt(0),
		From:     from,
		To:       &contractAddr,
	}

	// ProcessBatch should still succeed (the batch itself is valid; the
	// individual tx fails and its state changes are rolled back).
	_, _, err := sm.ProcessBatch(0, preRoot, []*RollupTransaction{tx1})
	if err != nil {
		// If the batch fails entirely, that's also acceptable — the key
		// requirement is that state is not corrupted.
		t.Logf("ProcessBatch with low-gas tx returned error (acceptable): %v", err)
	}

	// Verify storage slot 0 is still 0 (failed call didn't increment).
	contractAcc := sm.GetAccount(contractAddr)
	slotKey := types.Hash{}
	got := contractAcc.Storage[slotKey]
	if got != (types.Hash{}) {
		t.Fatalf("storage slot 0: got %x, want empty (failed call should not write)", got)
	}

	// Second call with sufficient gas — should succeed and increment to 1.
	preRoot2 := sm.computeStateRoot()
	tx2 := &RollupTransaction{
		Nonce:    1,
		GasPrice: 1,
		GasLimit: 100000,
		Value:    big.NewInt(0),
		From:     from,
		To:       &contractAddr,
	}
	_, _, err = sm.ProcessBatch(1, preRoot2, []*RollupTransaction{tx2})
	if err != nil {
		t.Fatalf("ProcessBatch(1) after failed call: %v", err)
	}

	contractAcc = sm.GetAccount(contractAddr)
	got = contractAcc.Storage[slotKey]
	expected := types.Hash{}
	expected[31] = 1
	if got != expected {
		t.Fatalf("storage slot 0 after successful call: got %x, want %x", got, expected)
	}
	t.Log("✅ Failed call (low gas) did not corrupt state; subsequent call succeeded")
}

// --- W-P2-3 Test 6: Contract call via full RollupEngine E2E ---

// TestL2Contract_EngineE2E deploys a Counter contract and calls it through the
// full RollupEngine pipeline (sequencer → batch → state manager), verifying
// that the QVM is correctly wired in the engine's StateManager.
func TestL2Contract_EngineE2E(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1
	cfg.MaxTxPerBatch = 10

	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}

	// Inject QVM executor.
	executor := qvm.NewExecutor()
	sm := engine.GetStateManager()
	sm.SetExecutor(executor)

	// W-P2-3 focuses on contract execution, not signatures — disable sig check.
	engine.SetRequireTxSig(false)

	// Fund sender.
	from := types.Address{10}
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000_000)

	// Deploy contract.
	contractAddr := types.Address{20}
	deployContract(sm, contractAddr, counterBytecode)

	// Sync BatchManager's lastStateRoot with StateManager (HIGH-11 fix).
	preRoot := sm.computeStateRoot()
	bm := engine.GetBatchManager()
	bm.RestoreMeta(0, preRoot)

	if err := engine.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer engine.Stop()

	// Submit tx to call increment().
	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 100000,
		Value:    big.NewInt(0),
		From:     from,
		To:       &contractAddr,
		ChainID:  cfg.ChainID,
	}
	if err := engine.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction: %v", err)
	}

	// Wait for batch to be built + submitted.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		totalBatches, _, _ := engine.GetStats()
		if totalBatches > 0 {
			// Verify storage was updated.
			contractAcc := sm.GetAccount(contractAddr)
			slotKey := types.Hash{}
			got := contractAcc.Storage[slotKey]
			expected := types.Hash{}
			expected[31] = 1
			if got != expected {
				t.Fatalf("storage slot 0: got %x, want %x (counter should be 1)", got, expected)
			}
			t.Log("✅ Engine E2E: contract call via RollupEngine incremented storage[0] to 1")
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	totalBatches, totalTxs, _ := engine.GetStats()
	t.Errorf("no batch built within 2s (batches=%d, txs=%d)", totalBatches, totalTxs)
}

// --- W-P2-3 Test 7: Contract storage affects stateRoot ---

// TestL2Contract_StorageAffectsStateRoot verifies that two calls to the same
// contract produce DIFFERENT stateRoots (because storage changes), and that
// the stateRoot is deterministic (same sequence of calls → same roots).
func TestL2Contract_StorageAffectsStateRoot(t *testing.T) {
	cfg := DefaultRollupConfig()
	executor := qvm.NewExecutor()

	// Run 1.
	sm1 := NewStateManager(cfg)
	sm1.SetExecutor(executor)
	from := types.Address{10}
	contractAddr := types.Address{20}
	sm1.getOrCreateAccount(from)
	sm1.accountStates[from].Balance = new(big.Int).SetInt64(100_000_000)
	deployContract(sm1, contractAddr, counterBytecode)

	preRoot1 := sm1.computeStateRoot()
	tx1 := &RollupTransaction{
		Nonce: 0, GasPrice: 1, GasLimit: 100000, Value: big.NewInt(0),
		From: from, To: &contractAddr,
	}
	postRoot1, _, _ := sm1.ProcessBatch(0, preRoot1, []*RollupTransaction{tx1})

	tx2 := &RollupTransaction{
		Nonce: 1, GasPrice: 1, GasLimit: 100000, Value: big.NewInt(0),
		From: from, To: &contractAddr,
	}
	postRoot2, _, _ := sm1.ProcessBatch(1, postRoot1, []*RollupTransaction{tx2})

	// Run 2 (same setup, should produce same roots).
	executor2 := qvm.NewExecutor()
	sm2 := NewStateManager(cfg)
	sm2.SetExecutor(executor2)
	sm2.getOrCreateAccount(from)
	sm2.accountStates[from].Balance = new(big.Int).SetInt64(100_000_000)
	deployContract(sm2, contractAddr, counterBytecode)

	preRoot2 := sm2.computeStateRoot()
	if preRoot2 != preRoot1 {
		t.Fatalf("pre-roots differ: %x vs %x (should be deterministic)", preRoot1, preRoot2)
	}

	r1, _, _ := sm2.ProcessBatch(0, preRoot2, []*RollupTransaction{{
		Nonce: 0, GasPrice: 1, GasLimit: 100000, Value: big.NewInt(0),
		From: from, To: &contractAddr,
	}})
	r2, _, _ := sm2.ProcessBatch(1, r1, []*RollupTransaction{{
		Nonce: 1, GasPrice: 1, GasLimit: 100000, Value: big.NewInt(0),
		From: from, To: &contractAddr,
	}})

	if r1 != postRoot1 {
		t.Fatalf("post-root 1 differs: %x vs %x (should be deterministic)", postRoot1, r1)
	}
	if r2 != postRoot2 {
		t.Fatalf("post-root 2 differs: %x vs %x (should be deterministic)", postRoot2, r2)
	}
	if postRoot1 == postRoot2 {
		t.Fatal("post-root 1 == post-root 2 (storage change should produce different roots)")
	}
	t.Log("✅ StateRoot determinism: same call sequence → same roots; different storage → different roots")
}
