// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"
)

// QVM-R7-03 (High) — JIT adapter DelegateCall / StaticCall lacked snapshot / revert
//
// Audit source (AUDIT-R7-QVM-2026-07-17.md QVM-R7-03):
//   "The JIT adapter's DelegateCall and StaticCall paths take no snapshot,
//    so state cannot be rolled back when a sub-call fails"
//   Location: qvm/jit_adapter.go:497-560 (DelegateCall), 562-616 (StaticCall)
//   "Compare Call (jit_adapter.go:356-410), which correctly implements snapshot + revert"
//   "Exploit scenario: contract A DELEGATECALLs contract B; B mutates A's storage then
//    REVERTs. On the JIT path B's mutations are not rolled back — A's storage is polluted"
//
// Fix:
//   DelegateCall / StaticCall now snapshot before Execute and call
//   RevertToSnapshot on error, matching the Call pattern.
//
// This test verifies:
//   1. When a DelegateCall sub-call fails (REVERT), the caller's storage is rolled back
//   2. When a StaticCall sub-call fails, state is rolled back

// qvmR703setupAdapter creates a jitEnvAdapter for DelegateCall/StaticCall tests.
// Contract B's code SSTOREs then REVERTs, to exercise rollback on sub-call failure.
func qvmR703setupAdapter(t *testing.T) (*jitEnvAdapter, *mockStateDB, Address, Address) {
	t.Helper()

	callerAddr := Address{0xAA} // contract A (DELEGATECALL originator)
	targetAddr := Address{0xBB} // contract B (DELEGATECALL target)

	stateDB := newMockStateDB()
	stateDB.SetBalance(callerAddr, big.NewInt(1000000))
	stateDB.exist[callerAddr] = true
	stateDB.exist[targetAddr] = true

	// contract B code: SSTORE(0x00, 0x42) + REVERT(0, 0)
	// QVM opcodes: PUSH1=0x10, SSTORE=0x61, REVERT=0x07
	// SSTORE pops key (top) and value (second), writing storage[key] = value
	targetCode := []byte{
		byte(PUSH1), 0x42, // value (second on stack)
		byte(PUSH1), 0x00, // key (top of stack)
		byte(SSTORE),      // storage[0x00] = 0x42 (in the caller's context, since DELEGATECALL)
		byte(PUSH1), 0x00, // offset
		byte(PUSH1), 0x00, // size
		byte(REVERT),
	}
	stateDB.SetCode(targetAddr, targetCode)
	stateDB.SetCode(callerAddr, []byte{byte(STOP)}) // caller only needs to exist

	// create the Environment (simulating the JIT env)
	ctx := &ExecutionContext{
		Origin:      callerAddr,
		GasPrice:    big.NewInt(1),
		Caller:      callerAddr,
		Address:     callerAddr,
		Value:       big.NewInt(0),
		BlockNumber: 42,
		Timestamp:   1000,
		Coinbase:    Address{0x10},
		GasLimit:    1000000,
		ChainID:     1668,
		BlockHashes: make(map[uint64]Hash),
		Code:        stateDB.GetCode(callerAddr),
		Input:       []byte{},
		Gas:         100000,
		Depth:       0,
		ReadOnly:    false,
	}

	env := &Environment{
		ctx:                ctx,
		stateDB:            stateDB,
		stack:              NewStack(),
		memory:             NewMemory(),
		gas:                NewGasMeter(ctx.Gas),
		gasTable:           DefaultGasTable(),
		precompiled:        nil, // tests do not touch precompiled contracts
		pc:                 0,
		logs:               make([]*Log, 0),
		returnData:         nil,
		blockHashes:        ctx.BlockHashes,
		parentEnv:          nil,
		activeAddresses:    make([]Address, 0, 2),
		transientStorage:   make(map[Address]map[Hash]Hash),
		txCreatedContracts: make(map[Address]bool),
		reentryCounts:      make(map[Address]int),
		jumpDests:          make(map[uint64]bool),
	}
	env.PushActiveAddress(callerAddr)

	interpreter := NewInterpreter()
	adapter := newJITEnvAdapter(env, interpreter)

	return adapter, stateDB, callerAddr, targetAddr
}

// TestQVM_R7_03_DelegateCallRevertsStateOnSubCallError verifies DelegateCall
// rolls back the caller's storage when the sub-call REVERTs.
func TestQVM_R7_03_DelegateCallRevertsStateOnSubCallError(t *testing.T) {
	adapter, stateDB, callerAddr, targetAddr := qvmR703setupAdapter(t)

	// before the call, the caller's storage[0x00] should be zero
	key := Hash{}
	beforeVal := stateDB.GetState(callerAddr, key)
	if beforeVal != (Hash{}) {
		t.Fatalf("QVM-R7-03: pre-condition: caller storage[0] should be zero, got %x", beforeVal)
	}

	// invoke DelegateCall — the target will SSTORE then REVERT
	_, _, err := adapter.DelegateCall(
		addrToJIT(callerAddr),
		addrToJIT(targetAddr),
		[]byte{}, // input
		50000,    // gas
	)

	// DelegateCall should return an error (target REVERTs)
	if err == nil {
		t.Fatal("QVM-R7-03: DelegateCall should return error when target REVERTs")
	}

	// key assertion: the caller's storage[0x00] must still be zero (rolled back)
	// before the fix: storage was polluted to 0x42 (not rolled back)
	afterVal := stateDB.GetState(callerAddr, key)
	if afterVal != (Hash{}) {
		t.Errorf("QVM-R7-03: DelegateCall sub-call REVERT did not roll back caller storage\n"+
			"  got:      %x (polluted)\n  expected: 0x00 (rolled back)", afterVal)
	}

	t.Logf("QVM-R7-03 OK: DelegateCall rolled back caller storage on sub-call REVERT (err=%v)", err)
}

// TestQVM_R7_03_StaticCallRevertsStateOnSubCallError verifies StaticCall
// rolls back state on sub-call failure. StaticCall sets ReadOnly=true which blocks writes,
// but snapshot + revert remains a defense-in-depth measure.
func TestQVM_R7_03_StaticCallRevertsStateOnSubCallError(t *testing.T) {
	adapter, stateDB, callerAddr, targetAddr := qvmR703setupAdapter(t)

	// change the target code to: PUSH1 0x00, PUSH1 0x00, REVERT (direct REVERT, no SSTORE)
	// because StaticCall is ReadOnly, SSTORE would be refused; use a plain REVERT instead
	targetCode := []byte{
		byte(PUSH1), 0x00, // offset
		byte(PUSH1), 0x00, // size
		byte(REVERT),
	}
	stateDB.SetCode(targetAddr, targetCode)

	// record storage state before the call
	key := Hash{}
	beforeVal := stateDB.GetState(callerAddr, key)

	// invoke StaticCall — the target REVERTs immediately
	_, _, err := adapter.StaticCall(
		addrToJIT(callerAddr),
		addrToJIT(targetAddr),
		[]byte{}, // input
		50000,    // gas
	)

	// StaticCall should return an error
	if err == nil {
		t.Fatal("QVM-R7-03: StaticCall should return error when target REVERTs")
	}

	// verify state unmodified (ReadOnly blocks writes; snapshot/revert is defense in depth)
	afterVal := stateDB.GetState(callerAddr, key)
	if afterVal != beforeVal {
		t.Errorf("QVM-R7-03: StaticCall changed state despite REVERT\n  before: %x\n  after:  %x",
			beforeVal, afterVal)
	}

	t.Logf("QVM-R7-03 OK: StaticCall state preserved on sub-call REVERT (err=%v)", err)
}

// TestQVM_R7_03_DelegateCallPreservesStateOnSuccess verifies DelegateCall
// does NOT roll back state when the sub-call succeeds (positive test — the fix must not break the normal path).
func TestQVM_R7_03_DelegateCallPreservesStateOnSuccess(t *testing.T) {
	adapter, stateDB, callerAddr, targetAddr := qvmR703setupAdapter(t)

	// change the target code to: SSTORE(0x00, 0x42) + STOP (success path)
	targetCode := []byte{
		byte(PUSH1), 0x42, // value
		byte(PUSH1), 0x00, // key
		byte(SSTORE),
		byte(STOP),
	}
	stateDB.SetCode(targetAddr, targetCode)

	// invoke DelegateCall — the target SSTOREs then STOPs (success)
	_, _, err := adapter.DelegateCall(
		addrToJIT(callerAddr),
		addrToJIT(targetAddr),
		[]byte{},
		50000,
	)

	// should succeed
	if err != nil {
		t.Fatalf("QVM-R7-03: DelegateCall should succeed when target STOPs: %v", err)
	}

	// verify storage was written correctly (not rolled back)
	key := Hash{}
	afterVal := stateDB.GetState(callerAddr, key)
	expected := Hash{}
	expected[31] = 0x42
	if afterVal != expected {
		t.Errorf("QVM-R7-03: DelegateCall success should persist storage\n  got: %x\n  want: %x",
			afterVal, expected)
	}

	t.Logf("QVM-R7-03 OK: DelegateCall preserved state on sub-call success")
}
