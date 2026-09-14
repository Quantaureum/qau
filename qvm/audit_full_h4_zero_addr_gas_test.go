// Quantaureum Node source, version 1.0.0.
package qvm

// AUDIT-FULL H-4 (2026-08-14) regression tests.
//
// Bug: P3-QV-04 made opCall's zero-address rejection gas-aware, but the fix
// was not propagated to opStaticCall, opCallCode, opDelegateCall and
// opAuthCall — those four returned 0 immediately without consuming any gas,
// enabling zero-cost probing of the reserved zero address.
//
// Fix: all five call opcodes now share rejectZeroAddrCall, which charges
// memory-expansion cost plus a base call cost before pushing 0.
//
// These tests execute each of the four previously-unfixed opcodes against
// the zero address and assert:
//  1. The call still pushes 0 (no error, no revert) — behavior preserved.
//  2. Gas IS consumed (GasUsed > 0 beyond the trivial PUSH/MSTORE overhead).
//  3. With a large memory expansion request and insufficient gas, the
//     opcode now fails with out-of-gas instead of returning for free.

import (
	"testing"
)

// runZeroAddrOpcode executes `opcode` against the zero address with the
// given gas limit and returns the execution result.
func runZeroAddrOpcode(t *testing.T, opcode OpCode, gas uint64, withValue bool) *ExecutionResult {
	t.Helper()
	interp := NewInterpreter()
	sdb := newMockStateDB()

	code := []byte{
		byte(PUSH1), 0x20, // retSize
		byte(PUSH1), 0x00, // retOffset
		byte(PUSH1), 0x00, // argsSize
		byte(PUSH1), 0x00, // argsOffset
	}
	if withValue {
		code = append(code, byte(PUSH32),
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // value = 0
	}
	code = append(code,
		byte(PUSH20), // addr = 0x0 (zero address)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		byte(PUSH1), 0xff, // gas requested for subcall
		byte(opcode),
		byte(PUSH1), 0x00,
		byte(MSTORE),
		byte(PUSH1), 0x20,
		byte(PUSH1), 0x00,
		byte(RETURN),
	)

	ctx := &ExecutionContext{
		Code:          code,
		Gas:           gas,
		Origin:        Address{0x01},
		Caller:        Address{0x01},
		Address:       Address{0x02},
		EVMCompatible: true,
	}
	return interp.Execute(ctx, sdb)
}

func TestAuditFullH4_ZeroAddress_ChargesGas_AllOpcodes(t *testing.T) {
	cases := []struct {
		name      string
		opcode    OpCode
		withValue bool
	}{
		{"STATICCALL", STATICCALL, false},
		{"CALLCODE", CALLCODE, true},
		{"DELEGATECALL", DELEGATECALL, false},
		{"AUTHCALL", AUTHCALL, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runZeroAddrOpcode(t, tc.opcode, 100000, tc.withValue)

			if result.Err != nil {
				t.Fatalf("%s to zero address should not error: %v", tc.name, result.Err)
			}
			// Behavior preserved: call fails softly (pushes 0).
			if len(result.ReturnData) != 32 || result.ReturnData[31] != 0 {
				t.Fatalf("%s to zero address should push 0, got returnData=%v", tc.name, result.ReturnData)
			}
			// Gas must be consumed. The surrounding PUSH/MSTORE/RETURN
			// scaffold costs < 100 gas, so anything above that comes from
			// the zero-address rejection path.
			if result.GasUsed <= 100 {
				t.Errorf("AUDIT-FULL H-4 NOT FIXED: %s to zero address consumed only %d gas (zero-cost probing still possible)", tc.name, result.GasUsed)
			}
		})
	}
}

func TestAuditFullH4_ZeroAddress_MemoryExpansionOutOfGas(t *testing.T) {
	// Request a huge retOffset so the zero-address reject path must charge
	// a large memory-expansion cost. With a small gas pool the opcode must
	// fail with out-of-gas instead of returning 0 for free.
	interp := NewInterpreter()
	sdb := newMockStateDB()

	code := []byte{
		byte(PUSH1), 0x20, // retSize
		byte(PUSH4), 0xff, 0xff, 0xff, 0xff, // retOffset = ~4GiB (huge memory request)
		byte(PUSH1), 0x00, // argsSize
		byte(PUSH1), 0x00, // argsOffset
		byte(PUSH20), // addr = 0x0
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		byte(PUSH1), 0xff, // gas
		byte(STATICCALL),
		byte(STOP),
	}

	ctx := &ExecutionContext{
		Code:          code,
		Gas:           5000, // far below the memory expansion cost
		Origin:        Address{0x01},
		Caller:        Address{0x01},
		Address:       Address{0x02},
		EVMCompatible: true,
	}
	result := interp.Execute(ctx, sdb)

	if result.Err == nil {
		t.Fatal("AUDIT-FULL H-4 NOT FIXED: STATICCALL to zero address with unaffordable memory expansion succeeded for free")
	}
}
