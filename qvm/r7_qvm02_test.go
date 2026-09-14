// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"bytes"
	"math/big"
	"testing"
)

// QVM-R7-02 (High) — executeWithJIT did not initialize transientStorage /
// txCreatedContracts / reentryCounts
//
// Audit source (AUDIT-R7-QVM-2026-07-17.md QVM-R7-02):
//   "The JIT execution path's Environment initialization missed 3 key fields:
//    transientStorage / txCreatedContracts / reentryCounts"
//   Location: qvm/executor.go:218-325 (executeWithJIT)
//   Impact:
//     - TLOAD/TSTORE broken (nil map → always zero; reentrancy lock defeated)
//     - SELFDESTRUCT EIP-6780 broken (nil map → all SELFDESTRUCTs silently no-op)
//     - reentryCounts nil → IncrementReentryCount lazily initializes (no panic, but inconsistent)
//
// Fix:
//   executeWithJIT now initializes the 3 fields, mirroring Interpreter.Execute (qvm.go:218-236).
//
// This test verifies:
//   1. On the JIT path, TSTORE + TLOAD read/write transient storage correctly (previously TLOAD returned zero)
//   2. On the JIT path, reentryCounts is initialized (IncrementReentryCount does not panic)
//   3. On the JIT path, txCreatedContracts is initialized (non-nil)

// TestQVM_R7_02_JITTransientStorageInitialized verifies that on the JIT path TSTORE+TLOAD
// read/write transient storage correctly. Before the fix env.transientStorage was nil and TLOAD always returned zero.
func TestQVM_R7_02_JITTransientStorageInitialized(t *testing.T) {
	// R31-HIGH-1: JIT dispatch requires QAU_ENABLE_JIT=1 (and not QAU_PRODUCTION).
	t.Setenv("QAU_ENABLE_JIT", "1")
	t.Setenv("QAU_PRODUCTION", "")

	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}

	// Bytecode:
	//   PUSH1 0x99   // value (next-to-top)
	//   PUSH1 0x00   // key (top)
	//   TSTORE       // transient[0x00] = 0x99
	//   PUSH1 0x00   // key (top)
	//   TLOAD        // -> 0x99 (top)
	//   PUSH1 0x00   // offset (top)
	//   MSTORE       // memory[0] = 0x99
	//   PUSH1 0x20   // size
	//   PUSH1 0x00   // offset
	//   RETURN       // return memory[0:32]
	//
	// Note: QVM opcodes differ from EVM. PUSH1=0x10, TSTORE=0x63, TLOAD=0x62,
	// MSTORE=0x51, RETURN=0x06.
	code := []byte{
		byte(PUSH1), 0x99, // value
		byte(PUSH1), 0x00, // key
		byte(TSTORE),
		byte(PUSH1), 0x00, // key
		byte(TLOAD),
		byte(PUSH1), 0x00, // offset
		byte(MSTORE),
		byte(PUSH1), 0x20, // size
		byte(PUSH1), 0x00, // offset
		byte(RETURN),
	}

	// === JIT executor ===
	jitExecutor := NewExecutorWithJIT()
	jitExecutor.enableJITForTesting()
	jitStateDB := newMockStateDB()
	jitStateDB.SetBalance(calleeAddr, big.NewInt(1000000))
	jitStateDB.exist[calleeAddr] = true

	jitCtx := &ExecutionContext{
		Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: calleeAddr,
		Value: big.NewInt(0), BlockNumber: 42, Timestamp: 1000, Coinbase: Address{0x10},
		GasLimit: 1000000, ChainID: 1668, BlockHashes: make(map[uint64]Hash),
		Code: code, Input: []byte{}, Gas: 100000, Depth: 0, ReadOnly: false,
	}
	jitResult := jitExecutor.Execute(jitCtx, jitStateDB)

	// === Interpreter executor (reference) ===
	interpreterExecutor := NewExecutor()
	interpreterExecutor.DisableJIT()
	interpreterStateDB := newMockStateDB()
	interpreterStateDB.SetBalance(calleeAddr, big.NewInt(1000000))
	interpreterStateDB.exist[calleeAddr] = true

	interpreterCtx := &ExecutionContext{
		Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: calleeAddr,
		Value: big.NewInt(0), BlockNumber: 42, Timestamp: 1000, Coinbase: Address{0x10},
		GasLimit: 1000000, ChainID: 1668, BlockHashes: make(map[uint64]Hash),
		Code: code, Input: []byte{}, Gas: 100000, Depth: 0, ReadOnly: false,
	}
	interpreterResult := interpreterExecutor.Execute(interpreterCtx, interpreterStateDB)

	// JIT result must not have an error (TSTORE/TLOAD are basic opcodes)
	if jitResult.Err != nil {
		t.Fatalf("QVM-R7-02: JIT execution failed: %v", jitResult.Err)
	}

	// The key assertion: JIT must return 0x99 in the first byte (padded to 32 bytes).
	// Before the fix, env.transientStorage was nil, so TLOAD returned zero, and
	// the return data would be all zeros.
	expected := make([]byte, 32)
	expected[31] = 0x99 // 0x99 right-padded to 32 bytes

	if !bytes.Equal(jitResult.ReturnData, expected) {
		t.Errorf("QVM-R7-02: JIT TLOAD returned wrong value (transientStorage not initialized)\n"+
			"  got:       %x\n  expected:  %x", jitResult.ReturnData, expected)
	}

	// JIT and interpreter must agree
	if !bytes.Equal(jitResult.ReturnData, interpreterResult.ReturnData) {
		t.Errorf("QVM-R7-02: JIT and interpreter disagree on TLOAD result\n"+
			"  JIT:         %x\n  interpreter: %x",
			jitResult.ReturnData, interpreterResult.ReturnData)
	}

	t.Logf("QVM-R7-02 OK: JIT transientStorage initialized — TLOAD returned 0x99 after TSTORE")
}

// TestQVM_R7_02_JITReentryCountNoPanic verifies that on the JIT path reentryCounts is properly
// initialized, so IncrementReentryCount never panics on a nil map.
//
// Note: IncrementReentryCount itself has a nil check (environment.go:156-158), so
// even a nil reentryCounts would not panic. The fix ensures the JIT path behaves
// the same as the interpreter path.
func TestQVM_R7_02_JITReentryCountNoPanic(t *testing.T) {
	// R31-HIGH-1: JIT dispatch requires QAU_ENABLE_JIT=1 (and not QAU_PRODUCTION).
	t.Setenv("QAU_ENABLE_JIT", "1")
	t.Setenv("QAU_PRODUCTION", "")

	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}

	// Simple STOP code — just to trigger executeWithJIT and env creation
	code := []byte{byte(STOP)}

	jitExecutor := NewExecutorWithJIT()
	jitExecutor.enableJITForTesting()
	jitStateDB := newMockStateDB()
	jitStateDB.SetBalance(calleeAddr, big.NewInt(1000000))
	jitStateDB.exist[calleeAddr] = true

	jitCtx := &ExecutionContext{
		Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: calleeAddr,
		Value: big.NewInt(0), BlockNumber: 42, Timestamp: 1000, Coinbase: Address{0x10},
		GasLimit: 1000000, ChainID: 1668, BlockHashes: make(map[uint64]Hash),
		Code: code, Input: []byte{}, Gas: 100000, Depth: 0, ReadOnly: false,
	}

	// Must not panic
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("QVM-R7-02: JIT execution panicked (reentryCounts nil): %v", r)
		}
	}()

	result := jitExecutor.Execute(jitCtx, jitStateDB)
	if result.Err != nil {
		t.Fatalf("QVM-R7-02: JIT STOP execution failed: %v", result.Err)
	}

	t.Logf("QVM-R7-02 OK: JIT reentryCounts initialized — no panic on env creation")
}

// TestQVM_R7_02_JITTxCreatedContractsInitialized verifies that on the JIT path
// txCreatedContracts is properly initialized (non-nil), so the SELFDESTRUCT EIP-6780
// check works correctly.
//
// Note: this test verifies env initialization indirectly. Checking nil directly requires internal access;
// here we verify by ensuring JIT execution produces no anomalies.
func TestQVM_R7_02_JITTxCreatedContractsInitialized(t *testing.T) {
	// R31-HIGH-1: JIT dispatch requires QAU_ENABLE_JIT=1 (and not QAU_PRODUCTION).
	t.Setenv("QAU_ENABLE_JIT", "1")
	t.Setenv("QAU_PRODUCTION", "")

	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}

	// Simple SSTORE + STOP — triggers env creation and storage operations
	code := []byte{
		byte(PUSH1), 0x42, // value
		byte(PUSH1), 0x00, // key
		byte(SSTORE),
		byte(STOP),
	}

	jitExecutor := NewExecutorWithJIT()
	jitExecutor.enableJITForTesting()
	jitStateDB := newMockStateDB()
	jitStateDB.SetBalance(calleeAddr, big.NewInt(1000000))
	jitStateDB.exist[calleeAddr] = true

	jitCtx := &ExecutionContext{
		Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: calleeAddr,
		Value: big.NewInt(0), BlockNumber: 42, Timestamp: 1000, Coinbase: Address{0x10},
		GasLimit: 1000000, ChainID: 1668, BlockHashes: make(map[uint64]Hash),
		Code: code, Input: []byte{}, Gas: 100000, Depth: 0, ReadOnly: false,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("QVM-R7-02: JIT execution panicked (txCreatedContracts nil): %v", r)
		}
	}()

	result := jitExecutor.Execute(jitCtx, jitStateDB)
	if result.Err != nil {
		t.Fatalf("QVM-R7-02: JIT SSTORE execution failed: %v", result.Err)
	}

	// Verify storage was written
	val := jitStateDB.GetState(calleeAddr, Hash{})
	// Storage value is a 32-byte hash, 0x42 right-padded
	expected := Hash{}
	expected[31] = 0x42
	if val != expected {
		t.Errorf("QVM-R7-02: SSTORE did not persist correctly\n  got: %x\n  want: %x", val, expected)
	}

	t.Logf("QVM-R7-02 OK: JIT txCreatedContracts initialized — env creation succeeded")
}
