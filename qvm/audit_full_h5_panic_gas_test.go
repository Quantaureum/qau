// Quantaureum Node source, version 1.0.0.
package qvm

// AUDIT-FULL H-5 (2026-08-14) regression test.
//
// Bug: the interpreter's panic-recovery path computed
// GasUsed = env.gas.Limit() while the JIT path uses ctx.Gas. In production
// the two are equal (NewGasMeter(ctx.Gas)), but they are different sources
// of truth — any frame where the meter limit diverges from ctx.Gas (future
// gas re-parenting, test harnesses, sub-frames) would make a panic consume
// different gas depending on the execution engine → consensus fork.
//
// Fix: interpreter panic path now reads env.ctx.Gas, same as JIT.
//
// Test: build an Environment whose GasMeter limit (999999) deliberately
// differs from ctx.Gas (100000), trigger a panic inside run() via a stateDB
// that panics, and assert result.GasUsed == ctx.Gas.

import (
	"errors"
	"testing"
)

// panickingStateDB embeds a nil StateDB: any method call panics with a nil
// interface dereference, deterministically triggering run()'s recover.
type panickingStateDB struct {
	StateDB
}

func TestAuditFullH5_PanicRecoveryGasUsesCtxGas(t *testing.T) {
	interp := NewInterpreter()

	ctx := &ExecutionContext{
		Code: []byte{
			byte(PUSH20),
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
			byte(BALANCE),
			byte(STOP),
		},
		Gas:     100000, // ctx.Gas — the single source of truth
		Origin:  Address{0x01},
		Caller:  Address{0x01},
		Address: Address{0x02},
	}

	env := &Environment{
		ctx:      ctx,
		stateDB:  panickingStateDB{}, // GetBalance → panic
		stack:    NewStack(),
		memory:   NewMemory(),
		gas:      NewGasMeter(999999), // deliberately != ctx.Gas
		gasTable: DefaultGasTable(),
	}

	result := interp.run(env)
	if result == nil {
		t.Fatal("run returned nil result")
	}
	if result.Err == nil {
		t.Fatal("expected panic-recovery error, got nil")
	}
	if !errors.Is(result.Err, ErrPanicRecovery) {
		t.Fatalf("expected ErrPanicRecovery, got %v", result.Err)
	}
	if result.GasUsed != ctx.Gas {
		t.Errorf("AUDIT-FULL H-5 NOT FIXED: panic recovery GasUsed=%d (gas meter limit), want ctx.Gas=%d", result.GasUsed, ctx.Gas)
	}
}
