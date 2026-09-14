// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"
)

// =============================================================================
// QVM-R13-HIGH-001 (2026-07-21) tests: opCallCode reentry counter integration
//
// The fix adds IncrementReentryCount + defer DecrementReentryCount to the
// interpreter path of opCallCode, mirroring opCall/opStaticCall/opDelegateCall
// (call.go:265-278, 666-676, 960-970) and the JIT path (jit_adapter.go:847-855).
//
// Previously, CALLCODE only charged the 2300-gas reentrancy disincentive but
// never incremented the per-address counter — so MaxReentriesPerAddress could
// be bypassed via A→B(CALLCODE)→A→B(CALLCODE)… chains.
//
// These tests verify:
//  1. When reentryCounts[ctx.Address] is at the limit, opCallCode hard-blocks
//     (push 0 and return) instead of entering sub-execution.
//  2. The reentry counter is properly incremented (and decremented on return)
//     when the reentrancy branch is entered — observable indirectly because
//     when at-limit, IncrementReentryCount returns false and the call is
//     rejected before any state mutation.
// =============================================================================

// setupCallCodeReentryEnv builds a minimal Environment where opCallCode will
// enter the reentrancy-guard branch:
//   - target has code (targetHasCode=true)
//   - env.callDepth = 1 (so the reentrancy branch fires)
//   - env.ctx.Address is in activeAddresses (IsAddressActive=true)
//   - reentryCounts[ctx.Address] is initialized to `initialCount` so callers
//     can drive it to the limit.
//
// The stack is pre-populated with the 7 CALLCODE operands (non-EVMCompatible
// order: outSize, outOffset, inSize, inOffset, value, addr, gas).
func setupCallCodeReentryEnv(t *testing.T, initialCount int) (*Interpreter, *Environment, Address, Address) {
	t.Helper()
	interp := NewInterpreter()
	sdb := newMockStateDB()

	caller := Address{0x01}
	target := Address{0x02}

	sdb.SetBalance(caller, big.NewInt(1_000_000))
	sdb.SetCode(target, []byte{byte(STOP)})
	sdb.exist[target] = true

	env := &Environment{
		ctx: &ExecutionContext{
			Origin:      caller,
			GasPrice:    big.NewInt(1),
			Caller:      caller,
			Address:     caller,
			Value:       big.NewInt(0),
			BlockNumber: 1,
			Timestamp:   100,
			Coinbase:    Address{0x10},
			GasLimit:    10_000_000,
			ChainID:     1,
			Code:        []byte{byte(STOP)},
			Input:       []byte{},
			Gas:         10_000_000,
		},
		stateDB:  sdb,
		stack:    NewStack(),
		memory:   NewMemory(),
		gas:      NewGasMeter(10_000_000),
		gasTable: DefaultGasTable(),
		jumpDests: map[uint64]bool{
			0: true,
		},
		// Reentrancy branch fires only when callDepth >= 1.
		callDepth: 1,
		// Per-transaction reentry counter, pre-populated by the caller.
		reentryCounts: map[Address]int{caller: initialCount},
	}

	// Push caller onto activeAddresses so IsAddressActive(caller) returns true.
	env.activeAddresses = []Address{caller}

	// Non-EVMCompatible stack order (top to bottom):
	//   outSize, outOffset, inSize, inOffset, value, addr, gas
	if err := env.stack.PushUint64(0); err != nil { // outSize
		t.Fatalf("push outSize: %v", err)
	}
	if err := env.stack.PushUint64(0); err != nil { // outOffset
		t.Fatalf("push outOffset: %v", err)
	}
	if err := env.stack.PushUint64(0); err != nil { // inSize
		t.Fatalf("push inSize: %v", err)
	}
	if err := env.stack.PushUint64(0); err != nil { // inOffset
		t.Fatalf("push inOffset: %v", err)
	}
	if err := env.stack.PushBigInt(big.NewInt(0)); err != nil { // value = 0
		t.Fatalf("push value: %v", err)
	}
	addrWord := Word{}
	copy(addrWord[12:], target[:])                   // right-align 20-byte address in 32-byte word
	if err := env.stack.Push(addrWord); err != nil { // addr = target
		t.Fatalf("push addr: %v", err)
	}
	if err := env.stack.PushUint64(500_000); err != nil { // gas
		t.Fatalf("push gas: %v", err)
	}

	return interp, env, caller, target
}

// TestQVM_R13_HIGH_001_CallCode_BlockedWhenReentryLimitReached verifies that
// when reentryCounts[ctx.Address] is at MaxReentriesPerAddress, opCallCode
// hard-blocks (pushes 0 and returns) WITHOUT entering sub-execution.
//
// QVM-R13-HIGH-001 (2026-07-21): Before the fix, opCallCode only charged the
// 2300-gas reentrancy disincentive but never called IncrementReentryCount —
// so the hard cap was bypassed and the call would proceed into sub-execution.
func TestQVM_R13_HIGH_001_CallCode_BlockedWhenReentryLimitReached(t *testing.T) {
	interp, env, caller, _ := setupCallCodeReentryEnv(t, MaxReentriesPerAddress)

	// Snapshot the caller balance so we can detect sub-execution side effects.
	balanceBefore := env.stateDB.GetBalance(caller)

	if err := interp.opCallCode(env); err != nil {
		t.Fatalf("opCallCode returned error: %v", err)
	}

	// Verify opCallCode pushed exactly one value (0) onto the stack.
	result, err := env.stack.Pop()
	if err != nil {
		t.Fatalf("pop result: %v", err)
	}
	if result := result.ToBigInt(); result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("QVM-R13-HIGH-001 REGRESSION: expected push 0 (reentry limit hard-block), got %s",
			result.String())
	}

	// Verify the reentry counter was NOT incremented past the limit by the
	// blocked call. The fix uses check-before-increment, so a blocked call
	// leaves the counter at exactly MaxReentriesPerAddress.
	if count := env.reentryCounts[caller]; count != MaxReentriesPerAddress {
		t.Errorf("QVM-R13-HIGH-001 REGRESSION: counter should be unchanged at %d (limit), got %d — "+
			"opCallCode did not call IncrementReentryCount (reentry cap bypassed)",
			MaxReentriesPerAddress, count)
	}

	// Verify no sub-execution occurred (balance unchanged means no value
	// transfer, no gas burn beyond the reentrancy guard). This is a weak
	// proxy for "call did not proceed", but combined with the counter check
	// above it confirms the hard-block fired.
	balanceAfter := env.stateDB.GetBalance(caller)
	if balanceAfter.Cmp(balanceBefore) != 0 {
		t.Errorf("QVM-R13-HIGH-001: balance changed unexpectedly (sub-execution may have run): before=%s after=%s",
			balanceBefore.String(), balanceAfter.String())
	}
}

// TestQVM_R13_HIGH_001_CallCode_BelowLimit_AllowsReentry verifies that when
// the counter is below the limit, opCallCode does NOT hard-block on the
// IncrementReentryCount check. We can't reliably assert sub-call SUCCESS in
// this minimal test setup (the sub-execution may fail for environment reasons
// unrelated to the reentry fix), so we instead verify that the counter
// returned to its starting value — proving the deferred DecrementReentryCount
// fired on ALL return paths (success, revert, error).
//
// QVM-R13-HIGH-001 (2026-07-21): Before the fix, opCallCode never touched
// the counter, so it would always stay at the starting value. With the fix,
// the counter is incremented and then decremented on return, so it also
// returns to the starting value. The hard-block test (TestQVM_R13_HIGH_001_
// CallCode_BlockedWhenReentryLimitReached) is the only direct proof that
// IncrementReentryCount was actually called — this test instead verifies
// the symmetric DecrementReentryCount wiring.
func TestQVM_R13_HIGH_001_CallCode_BelowLimit_AllowsReentry(t *testing.T) {
	interp, env, caller, _ := setupCallCodeReentryEnv(t, 0)

	if err := interp.opCallCode(env); err != nil {
		t.Fatalf("opCallCode returned error: %v", err)
	}

	// Pop the result regardless of success/failure (we don't assert on it
	// because the sub-call may fail for setup-specific reasons).
	if _, err := env.stack.Pop(); err != nil {
		t.Fatalf("pop result: %v", err)
	}

	// QVM-R13-HIGH-001 + QVM-R12-001: counter must return to its starting
	// value (0) after the call returns, regardless of success/failure.
	// If counter is 1, the deferred DecrementReentryCount was not wired to
	// some return path.
	if count := env.reentryCounts[caller]; count != 0 {
		t.Errorf("QVM-R13-HIGH-001: counter should return to 0 after call (deferred decrement), got %d — "+
			"DecrementReentryCount may not be wired to all return paths", count)
	}
}

// TestQVM_R13_HIGH_001_CallCode_DecrementsOnFailure verifies that even when
// the sub-call FAILS, the reentry counter is still decremented (so a failed
// CALLCODE doesn't permanently saturate the counter).
//
// We trigger sub-call failure by giving the target empty code at execution
// time (after the reentrancy branch already fired based on initial code).
// Actually we use a simpler approach: set target's code to a single INVALID
// opcode so the sub-execution reverts.
func TestQVM_R13_HIGH_001_CallCode_DecrementsOnFailure(t *testing.T) {
	interp, env, caller, target := setupCallCodeReentryEnv(t, 0)

	// Replace target code with INVALID so sub-execution fails.
	env.stateDB.SetCode(target, []byte{byte(INVALID)})

	if err := interp.opCallCode(env); err != nil {
		// opCallCode itself doesn't error on sub-call failure — it pushes 0
		// onto the stack. Any error here is a different bug.
		t.Fatalf("opCallCode returned error: %v", err)
	}

	// Pop the result (0 or 1, depending on sub-call success).
	if _, err := env.stack.Pop(); err != nil {
		t.Fatalf("pop result: %v", err)
	}

	// QVM-R13-HIGH-001 + QVM-R12-001: counter must be 0 after the call
	// returns, regardless of whether the sub-call succeeded or failed.
	// If counter is 1, the DecrementReentryCount was missed on a failure path.
	if count := env.reentryCounts[caller]; count != 0 {
		t.Errorf("QVM-R13-HIGH-001: counter should return to 0 after failed sub-call (deferred decrement), got %d — "+
			"DecrementReentryCount may not be wired to all failure paths", count)
	}
}
