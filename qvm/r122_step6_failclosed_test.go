// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"strings"
	"testing"
)

// TestR122Step6EVMFailClosed: R122 Step-6 — EVM bytecode that cannot be
// translated must be REJECTED with an explicit error, never executed
// natively (EVM/QVM arithmetic operand order differs → silent wrong math,
// fund-loss class). See docs/EVM-COMPATIBILITY.md.
func TestR122Step6EVMFailClosed(t *testing.T) {
	executor := NewExecutor()
	stateDB := newMockStateDB()
	caller := Address{0x51}
	stateDB.SetNonce(caller, 1)
	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 10_000_000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}

	// EVM initcode: starts with the Solidity free-memory-pointer preamble
	// (PUSH1 0x80 PUSH1 0x40 MSTORE → 60 80 60 40 52) so IsEVMBytecode
	// detects it, then contains a byte with no EVM→QVM mapping (0xEF is
	// not in evmToQVMOpcodeMap) so TranslateEVMBytecode must fail.
	initCode := []byte{0x60, 0x80, 0x60, 0x40, 0x52, 0xEF, 0x00}

	res, addr := executor.Create(stateDB, caller, initCode, 5_000_000, big.NewInt(0), blockCtx, 0)
	if res == nil || res.Err == nil {
		t.Fatalf("EVM untranslatable initcode must fail-closed, got res=%+v addr=%x", res, addr)
	}
	msg := res.Err.Error()
	if !strings.Contains(msg, "evm translation failed") {
		t.Fatalf("error should carry the fail-closed reason, got: %s", msg)
	}

	// Fail-closed must not leave deployed code behind.
	if code := stateDB.GetCode(addr); len(code) != 0 {
		t.Fatalf("rejected deploy must leave no code, got %x", code)
	}
}

// TestR122Step6EVMRuntimeTranslationFailClosed: when the INIT code executes
// fine but the RETURNED runtime code is untranslatable EVM, the deployment
// must revert (pre-R122 this silently deployed raw EVM bytecode).
func TestR122Step6EVMRuntimeTranslationFailClosed(t *testing.T) {
	executor := NewExecutor()
	stateDB := newMockStateDB()
	caller := Address{0x51}
	stateDB.SetNonce(caller, 1)
	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 10_000_000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}

	// QVM-native initcode (passes IsEVMBytecode == false, no init
	// translation) that RETURNs a chunk of EVM-looking runtime code
	// containing an unmappable opcode. Layout:
	//   PUSH2 <len>      0x11 0x02 <rt_len>
	//   PUSH2 <src=0x40> 0x11 0x02 0x00 0x40     (source already in code)
	//   ... simpler: embed runtime via CODECOPY from the init blob:
	// For a unit-level test, place the "runtime" bytes at code offset 0x40
	// and CODECOPY them to memory, then RETURN them.
	// Opcodes: CODECOPY=0x79, MSTORE-family not needed; RETURN=0x06.
	// CODECOPY stack: dest=top? (QVM: dest=MSTORE-style bottom) — build
	// explicitly: PUSH2 dst(0x00) PUSH2 src(0x40) PUSH2 len CODECOPY
	// then PUSH2 0x00 PUSH2 len RETURN.
	rt := []byte{0x60, 0x80, 0x60, 0x40, 0x52, 0xEF, 0x00} // EVM preamble + unmappable 0xEF
	init := []byte{
		// CODECOPY pops dest(top) offset size — push size FIRST (bottom),
		// then offset, then dest last (matches wqau.qasm constructor usage).
		byte(PUSH2), 0x00, byte(len(rt)), // size (bottom)
		byte(PUSH2), 0x00, 0x40, // code src offset
		byte(PUSH2), 0x00, 0x00, // mem dest (top)
		byte(CODECOPY),
		// RETURN pops offset first (top of stack): push size THEN offset,
		// so offset ends up on top (QVM dest/value convention: value=top).
		byte(PUSH2), 0x00, byte(len(rt)), // size (bottom)
		byte(PUSH2), 0x00, 0x00, // offset (top)
		byte(RETURN),
	}
	// pad to 0x40 with STOPs, then runtime bytes
	for len(init) < 0x40 {
		init = append(init, byte(STOP))
	}
	init = append(init, rt...)

	res, addr := executor.Create(stateDB, caller, init, 5_000_000, big.NewInt(0), blockCtx, 0)
	if res == nil || res.Err == nil {
		t.Fatalf("untranslatable EVM runtime must fail-closed, got res=%+v ret=%x", res, res.ReturnData)
	}
	msg := res.Err.Error()
	if !strings.Contains(msg, "runtime translation failed") && !strings.Contains(msg, "fail-closed") {
		t.Fatalf("error should carry the runtime fail-closed reason, got: %s", msg)
	}
	if code := stateDB.GetCode(addr); len(code) != 0 {
		t.Fatalf("rejected deploy must leave no code, got %x", code)
	}
}
