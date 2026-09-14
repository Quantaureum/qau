// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"
)

// R123 Phase-0 smoke gate: verify the three environment opcodes the stqau contract design depends on
// (SELFBALANCE / NUMBER / TIMESTAMP) behave identically on both execution paths (JIT executor.go and
// the interpreter), returning correct values. This is the R123 plan's stop-loss gate:
// any failure → re-evaluate the D4 (SELFBALANCE accounting) / D6 (NUMBER unlock) design.
//
// The tests reuse the deployment/call patterns already proven in R122 (Create + Call).

// r123EnvEchoContract: echo runtime assembly — hand-assembled QVM bytecode:
//
//	SELFBALANCE / NUMBER / TIMESTAMP each pushed and stored into memory 0x00-0x60, then RETURN
//
// construction: initcode = COPY runtime + RETURN
func r123EnvEchoCode() []byte {
	// runtime:
	//  SELFBALANCE  MSTORE(0x00)   -- stack order: MSTORE offset=top, value=second
	//  NUMBER       MSTORE(0x20)
	//  TIMESTAMP    MSTORE(0x40)
	//  PUSH1 0x60 PUSH1 0x00 RETURN  -- (size, offset) RETURN: offset=top? double-check
	// QVM opcode hex (opcodes.go): SELFBALANCE=0x82 NUMBER=0x80 TIMESTAMP=0x81
	// MSTORE=0x51 PUSH1=0x10 RETURN=0x06
	rt := []byte{
		byte(SELFBALANCE), byte(PUSH1), 0x00, byte(MSTORE),
		byte(NUMBER), byte(PUSH1), 0x20, byte(MSTORE),
		byte(TIMESTAMP), byte(PUSH1), 0x40, byte(MSTORE),
		byte(PUSH1), 0x60, byte(PUSH1), 0x00, byte(RETURN),
	}
	// initcode: PUSH2 len, PUSH2 0x00 (offset), CODECOPY... — simplified: use the
	// same construction as the r122 tests — the CODECOPY pattern is expanded here:
	// PUSH1 rtLen; PUSH1 0x0C (code start after init); PUSH1 0x00; CODECOPY
	// QVM: CODECOPY = 0x79
	init := []byte{
		byte(PUSH1), byte(len(rt)),
		byte(PUSH1), 0x0C, // runtime offset within the initcode (init length)
		byte(PUSH1), 0x00,
		byte(CODECOPY),
		byte(PUSH1), byte(len(rt)),
		byte(PUSH1), 0x00,
		byte(RETURN),
	}
	return append(init, rt...)
}

// TestR123Phase0SelfBalanceNumberTimestamp: give the contract a balance, CALL it, return
// all three values, and assert each.
func TestR123Phase0SelfBalanceNumberTimestamp(t *testing.T) {
	db := newMockStateDB()
	exec := NewExecutor()
	ctx := &BlockContext{BlockNumber: 12345, Timestamp: 1788676000, GasLimit: 20_000_000, ChainID: 1668}

	owner := Address{0x77}
	db.SetBalance(owner, big.NewInt(1_000_000_000))

	// deploy the echo contract
	db.SetNonce(owner, 1)
	res, addr := exec.Create(db, owner, r123EnvEchoCode(), 5_000_000, big.NewInt(0), ctx, 0)
	if res.Err != nil {
		t.Fatalf("deploy: %v", res.Err)
	}
	// endow the contract with 42.5 QAU (425e17)
	wantBal := big.NewInt(425)
	wantBal.Mul(wantBal, big.NewInt(1e17))
	db.SetBalance(addr, wantBal)

	// caller CALLs the contract
	caller := Address{0x88}
	db.SetBalance(caller, big.NewInt(1_000_000))
	callRes := exec.Call(db, caller, addr, nil, 1_000_000, big.NewInt(0), ctx, 0)
	if callRes.Err != nil {
		t.Fatalf("call: %v", callRes.Err)
	}
	if len(callRes.ReturnData) != 0x60 {
		t.Fatalf("return len = %d, want 96", len(callRes.ReturnData))
	}
	gotBal := new(big.Int).SetBytes(callRes.ReturnData[0:32])
	gotNum := new(big.Int).SetBytes(callRes.ReturnData[32:64])
	gotTs := new(big.Int).SetBytes(callRes.ReturnData[64:96])
	if gotBal.Cmp(wantBal) != 0 {
		t.Fatalf("SELFBALANCE = %s, want %s", gotBal, wantBal)
	}
	if gotNum.Uint64() != 12345 {
		t.Fatalf("NUMBER = %d, want 12345", gotNum)
	}
	if gotTs.Int64() != 1788676000 {
		t.Fatalf("TIMESTAMP = %d, want 1788676000", gotTs)
	}
}

// TestR123Phase0EnvOpcodesJITPath: same echo contract, consistency check on the JIT path.
// Production txpool currently uses only the interpreter (qvm.NewExecutor defaults jitEnabled=false;
// enableJITForTesting is only available inside tests); this test defensively guarantees: when the JIT path
// is enabled later, the three environment opcodes stqau depends on keep their semantics.
func TestR123Phase0EnvOpcodesJITPath(t *testing.T) {
	// dual gate: enableJITForTesting only bypasses the EnableJIT() check;
	// the Execute() dispatch point still requires QAU_ENABLE_JIT=1 and non-production mode.
	t.Setenv("QAU_ENABLE_JIT", "1")
	t.Setenv("QAU_PRODUCTION", "")

	db := newMockStateDB()
	exec := NewExecutorWithJIT()
	exec.enableJITForTesting()
	if !exec.IsJITEnabled() {
		t.Fatal("JIT should be enabled for test")
	}
	ctx := &BlockContext{BlockNumber: 777, Timestamp: 1788677111, GasLimit: 20_000_000, ChainID: 1668}

	owner := Address{0x77}
	db.SetBalance(owner, big.NewInt(1_000_000_000))
	db.SetNonce(owner, 1)
	res, addr := exec.Create(db, owner, r123EnvEchoCode(), 5_000_000, big.NewInt(0), ctx, 0)
	if res.Err != nil {
		t.Fatalf("deploy: %v", res.Err)
	}
	wantBal := big.NewInt(9)
	wantBal.Mul(wantBal, big.NewInt(1e18))
	db.SetBalance(addr, wantBal)

	caller := Address{0x88}
	db.SetBalance(caller, big.NewInt(1_000_000))
	callRes := exec.Call(db, caller, addr, nil, 1_000_000, big.NewInt(0), ctx, 0)
	if callRes.Err != nil {
		t.Fatalf("call: %v", callRes.Err)
	}
	if len(callRes.ReturnData) != 0x60 {
		t.Fatalf("return len = %d, want 96", len(callRes.ReturnData))
	}
	gotBal := new(big.Int).SetBytes(callRes.ReturnData[0:32])
	gotNum := new(big.Int).SetBytes(callRes.ReturnData[32:64])
	gotTs := new(big.Int).SetBytes(callRes.ReturnData[64:96])
	if gotBal.Cmp(wantBal) != 0 {
		t.Fatalf("JIT SELFBALANCE = %s, want %s", gotBal, wantBal)
	}
	if gotNum.Uint64() != 777 {
		t.Fatalf("JIT NUMBER = %d, want 777", gotNum)
	}
	if gotTs.Int64() != 1788677111 {
		t.Fatalf("JIT TIMESTAMP = %d, want 1788677111", gotTs)
	}
}
