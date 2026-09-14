// Quantaureum Node source, version 1.0.0.
// QVM-R13-MED-002 regression tests.
//
// These tests verify the full EIP-2200 net gas metering implementation in
// opSStore (operations.go) and makeSStoreOp (jit/compiler.go). They cover
// all 8 cases of the (current, new, original) state matrix, ensuring the
// correct gas cost and refund are applied in both the interpreter and JIT
// execution paths.
//
// Test strategy:
//   - For each case, pre-populate mockStateDB.storage (current value) and
//     mockStateDB.committedStorage (original value) at slot 0x00.
//   - Run a single-SSTORE bytecode that writes `new` to slot 0x00.
//   - Assert the interpreter gas usage matches the expected EIP-2200 cost.
//   - For dirty cases (current != original), we set current and original
//     directly via the mock (no need to run a prior SSTORE in the same tx).
//   - JIT is also exercised to verify JIT/interpreter parity.
package qvm

import (
	"math/big"
	"testing"
)

// runEIP2200Case runs a single-SSTORE bytecode with the given current and
// original pre-populated, and returns the gas used by the interpreter.
// The bytecode writes `newValue` to slot 0x00.
//
// NOTE: PUSH1 0xNN pushes 0xNN right-aligned into a 32-byte Word, so the
// resulting Hash has 0xNN at position 31 (LSB). We must pre-populate current
// and original the same way for the equality comparison to work.
func runEIP2200Case(t *testing.T, currentByte byte, hasCurrent bool, originalByte byte, hasOriginal bool, newValue byte) (interpGas, jitGas uint64) {
	t.Helper()
	// R31-HIGH-1: JIT dispatch requires QAU_ENABLE_JIT=1 (and not QAU_PRODUCTION).
	t.Setenv("QAU_ENABLE_JIT", "1")
	t.Setenv("QAU_PRODUCTION", "")
	stateDB := newMockStateDB()
	calleeAddr := Address{0x02}
	stateDB.SetBalance(calleeAddr, big.NewInt(1_000_000))
	stateDB.exist[calleeAddr] = true

	// Pre-populate current (live storage) and original (committed storage).
	// Hash is 32 bytes; the value lives at position 31 (LSB), matching how
	// PUSH1 0xNN fills the Word (right-aligned).
	slot := Hash{}
	if hasCurrent {
		curHash := Hash{}
		curHash[31] = currentByte
		stateDB.storage[calleeAddr] = map[Hash]Hash{slot: curHash}
	}
	if hasOriginal {
		origHash := Hash{}
		origHash[31] = originalByte
		stateDB.committedStorage[calleeAddr] = map[Hash]Hash{slot: origHash}
	}

	// Bytecode: PUSH1 <newValue>, PUSH1 0x00, SSTORE, STOP
	code := []byte{
		byte(PUSH1), newValue,
		byte(PUSH1), 0x00,
		byte(SSTORE),
		byte(STOP),
	}

	ctx := &ExecutionContext{
		Origin:      Address{0x01},
		GasPrice:    big.NewInt(1),
		Caller:      Address{0x01},
		Address:     calleeAddr,
		Value:       big.NewInt(0),
		BlockNumber: 1,
		Timestamp:   100,
		Coinbase:    Address{0x10},
		GasLimit:    1_000_000,
		ChainID:     1668,
		BlockHashes: make(map[uint64]Hash),
		Code:        code,
		Input:       []byte{},
		Gas:         1_000_000,
		Depth:       0,
		ReadOnly:    false,
	}

	// Interpreter run
	interpExecutor := NewExecutor()
	interpExecutor.DisableJIT()
	interpResult := interpExecutor.Execute(ctx, stateDB)
	if interpResult.Err != nil {
		t.Fatalf("interpreter execution failed: %v", interpResult.Err)
	}

	// JIT run on a fresh stateDB (so the dirty-slot setup is identical).
	jitStateDB := newMockStateDB()
	jitStateDB.SetBalance(calleeAddr, big.NewInt(1_000_000))
	jitStateDB.exist[calleeAddr] = true
	if hasCurrent {
		curHash := Hash{}
		curHash[31] = currentByte
		jitStateDB.storage[calleeAddr] = map[Hash]Hash{slot: curHash}
	}
	if hasOriginal {
		origHash := Hash{}
		origHash[31] = originalByte
		jitStateDB.committedStorage[calleeAddr] = map[Hash]Hash{slot: origHash}
	}
	jitExecutor := NewExecutorWithJIT()
	jitExecutor.enableJITForTesting()
	jitCtx := &ExecutionContext{
		Origin:      Address{0x01},
		GasPrice:    big.NewInt(1),
		Caller:      Address{0x01},
		Address:     calleeAddr,
		Value:       big.NewInt(0),
		BlockNumber: 1,
		Timestamp:   100,
		Coinbase:    Address{0x10},
		GasLimit:    1_000_000,
		ChainID:     1668,
		BlockHashes: make(map[uint64]Hash),
		Code:        code,
		Input:       []byte{},
		Gas:         1_000_000,
		Depth:       0,
		ReadOnly:    false,
	}
	jitResult := jitExecutor.Execute(jitCtx, jitStateDB)
	if jitResult.Err != nil {
		t.Fatalf("JIT execution failed: %v", jitResult.Err)
	}

	return interpResult.GasUsed, jitResult.GasUsed
}

// TestQVM_R13_MED_002_Case1_NoChange verifies Case 1 of EIP-2200:
// current == new → cost SLoad (100), no refund.
func TestQVM_R13_MED_002_Case1_NoChange(t *testing.T) {
	// current = 0x11, original = 0x11 (clean), new = 0x11 (same as current)
	interpGas, jitGas := runEIP2200Case(t, 0x11, true, 0x11, true, 0x11)
	// Cold access surcharge (2000) + base warm (100) + storageCost=SLoad (100) = 2200
	// Plus PUSH+PUSH = 6. Total = 2206.
	const expected = 3 + 3 + 2000 + 100 + 100
	if interpGas != expected {
		t.Errorf("interpreter gas = %d, want %d", interpGas, expected)
	}
	if jitGas != interpGas {
		t.Errorf("JIT gas = %d, interpreter = %d (must match)", jitGas, interpGas)
	}
}

// TestQVM_R13_MED_002_Case2_CleanSet verifies Case 2 of EIP-2200:
// clean slot (original=0, current=0), 0 → Y → cost SStoreSet (20000), no refund.
func TestQVM_R13_MED_002_Case2_CleanSet(t *testing.T) {
	// current = 0, original = 0, new = 0x42
	interpGas, jitGas := runEIP2200Case(t, 0, false, 0, false, 0x42)
	// Cold access (2000+100) + SStoreSet (20000) = 22100
	// Plus PUSH+PUSH = 6. Total = 22106.
	const expected = 3 + 3 + 2000 + 100 + 20000
	if interpGas != expected {
		t.Errorf("interpreter gas = %d, want %d", interpGas, expected)
	}
	if jitGas != interpGas {
		t.Errorf("JIT gas = %d, interpreter = %d (must match)", jitGas, interpGas)
	}
}

// TestQVM_R13_MED_002_Case3_CleanClear verifies Case 3 of EIP-2200:
// clean slot (original=X, current=X), X → 0 → cost SStoreReset (2900) + Clear refund (4800).
func TestQVM_R13_MED_002_Case3_CleanClear(t *testing.T) {
	// current = 0x42, original = 0x42, new = 0
	interpGas, jitGas := runEIP2200Case(t, 0x42, true, 0x42, true, 0x00)
	// used = PUSH+PUSH (6) + Cold (2000) + base (100) + SStoreReset (2900) = 5006
	// refund = SStoreClear (4800), but EIP-3529 caps refund at used/5 = 1001.
	// FinalUsed = 5006 - 1001 = 4005.
	used := uint64(3 + 3 + 2000 + 100 + 2900) // 5006
	refund := uint64(4800)
	maxRefund := used / 5 // 1001
	actualRefund := refund
	if actualRefund > maxRefund {
		actualRefund = maxRefund
	}
	expected := used - actualRefund // 4005
	if interpGas != expected {
		t.Errorf("interpreter gas = %d, want %d", interpGas, expected)
	}
	if jitGas != interpGas {
		t.Errorf("JIT gas = %d, interpreter = %d (must match)", jitGas, interpGas)
	}
}

// TestQVM_R13_MED_002_Case4_CleanReset verifies Case 4 of EIP-2200:
// clean slot (original=X, current=X), X → Y → cost SStoreReset (2900), no refund.
func TestQVM_R13_MED_002_Case4_CleanReset(t *testing.T) {
	// current = 0x42, original = 0x42, new = 0x99
	interpGas, jitGas := runEIP2200Case(t, 0x42, true, 0x42, true, 0x99)
	// Cold access (2100) + SStoreReset (2900) = 5000
	// Plus PUSH+PUSH = 6. Total = 5006.
	const expected = 3 + 3 + 2000 + 100 + 2900
	if interpGas != expected {
		t.Errorf("interpreter gas = %d, want %d", interpGas, expected)
	}
	if jitGas != interpGas {
		t.Errorf("JIT gas = %d, interpreter = %d (must match)", jitGas, interpGas)
	}
}

// TestQVM_R13_MED_002_Case5_DirtyClear_OriginalZero verifies Case 5 of EIP-2200:
// dirty slot (original=0, current=X), X → 0 → cost SLoad (100), no refund (EIP-3529).
// This is the core QVM-R13-MED-002 fix case.
func TestQVM_R13_MED_002_Case5_DirtyClear_OriginalZero(t *testing.T) {
	// current = 0x42, original = 0x00 (dirty), new = 0
	interpGas, jitGas := runEIP2200Case(t, 0x42, true, 0, false, 0x00)
	// Cold access (2100) + dirty SLoad (100) = 2200
	// Plus PUSH+PUSH = 6. Total = 2206.
	// No refund (original == 0 per EIP-3529).
	const expected = 3 + 3 + 2000 + 100 + 100
	if interpGas != expected {
		t.Errorf("interpreter gas = %d, want %d (dirty clear must cost SLoad only, no refund per EIP-3529)",
			interpGas, expected)
	}
	if jitGas != interpGas {
		t.Errorf("JIT gas = %d, interpreter = %d (must match)", jitGas, interpGas)
	}
}

// TestQVM_R13_MED_002_Case6_DirtyReset_OriginalZero verifies Case 6 of EIP-2200:
// dirty slot (original=0, current=X), X → Y → cost SLoad (100), no refund.
func TestQVM_R13_MED_002_Case6_DirtyReset_OriginalZero(t *testing.T) {
	// current = 0x42, original = 0x00 (dirty), new = 0x99
	interpGas, jitGas := runEIP2200Case(t, 0x42, true, 0, false, 0x99)
	// Cold access (2100) + dirty SLoad (100) = 2200
	// Plus PUSH+PUSH = 6. Total = 2206.
	const expected = 3 + 3 + 2000 + 100 + 100
	if interpGas != expected {
		t.Errorf("interpreter gas = %d, want %d (dirty reset must cost SLoad only)",
			interpGas, expected)
	}
	if jitGas != interpGas {
		t.Errorf("JIT gas = %d, interpreter = %d (must match)", jitGas, interpGas)
	}
}

// TestQVM_R13_MED_002_Case7_DirtyClear_OriginalNonZero verifies Case 7 of EIP-2200:
// dirty slot (original=Z, current=X), X → 0 → cost SLoad (100) + Clear refund (4800).
// This is the second core QVM-R13-MED-002 fix case.
func TestQVM_R13_MED_002_Case7_DirtyClear_OriginalNonZero(t *testing.T) {
	// current = 0x99, original = 0x42 (dirty, original non-zero), new = 0
	interpGas, jitGas := runEIP2200Case(t, 0x99, true, 0x42, true, 0x00)
	// used = PUSH+PUSH (6) + Cold (2000) + base (100) + dirty SLoad (100) = 2206
	// refund = SStoreClear (4800), but EIP-3529 caps refund at used/5 = 441.
	// FinalUsed = 2206 - 441 = 1765.
	used := uint64(3 + 3 + 2000 + 100 + 100) // 2206
	refund := uint64(4800)
	maxRefund := used / 5 // 441
	actualRefund := refund
	if actualRefund > maxRefund {
		actualRefund = maxRefund
	}
	expected := used - actualRefund // 1765
	if interpGas != expected {
		t.Errorf("interpreter gas = %d, want %d (dirty clear with original!=0: cost SLoad + refund Clear)",
			interpGas, expected)
	}
	if jitGas != interpGas {
		t.Errorf("JIT gas = %d, interpreter = %d (must match)", jitGas, interpGas)
	}
}

// TestQVM_R13_MED_002_Case8_DirtyReset_OriginalNonZero verifies Case 8 of EIP-2200:
// dirty slot (original=Z, current=X), X → Y → cost SLoad (100), no refund.
func TestQVM_R13_MED_002_Case8_DirtyReset_OriginalNonZero(t *testing.T) {
	// current = 0x99, original = 0x42 (dirty, original non-zero), new = 0x55
	interpGas, jitGas := runEIP2200Case(t, 0x99, true, 0x42, true, 0x55)
	// Cold access (2100) + dirty SLoad (100) = 2200
	// Plus PUSH+PUSH = 6. Total = 2206.
	// No refund (still non-zero, original non-zero — net effect: Z → Y, not a clear).
	const expected = 3 + 3 + 2000 + 100 + 100
	if interpGas != expected {
		t.Errorf("interpreter gas = %d, want %d (dirty reset with original!=0: cost SLoad only)",
			interpGas, expected)
	}
	if jitGas != interpGas {
		t.Errorf("JIT gas = %d, interpreter = %d (must match)", jitGas, interpGas)
	}
}

// TestQVM_R13_MED_002_NoCommittedStateReader_Fallback verifies that when the
// StateDB does NOT implement committedStateReader, opSStore conservatively
// uses the legacy 3-state logic (no dirty detection, no refund). This is
// QVM-R7-05's conservative fallback for StateDBs that cannot supply the
// committed value — preserved by QVM-R13-MED-002.
//
// We can't easily test this through the executor because mockStateDB DOES
// implement committedStateReader. Instead, this test documents the expected
// fallback behavior for StateDB implementors.
func TestQVM_R13_MED_002_NoCommittedStateReader_Fallback(t *testing.T) {
	t.Skip("documented behavior: when StateDB does not implement committedStateReader, " +
		"opSStore uses originalKnown=false → conservative 3-state logic with no refund. " +
		"Verified by code inspection of operations.go and jit/compiler.go: " +
		"the `originalKnown && current != original` dirty-detection guard " +
		"short-circuits to false when originalKnown is false.")
}
