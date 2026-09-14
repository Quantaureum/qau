// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"
)

// R37-P3-21 regression tests: CREATE/CREATE2 must set the new contract
// account nonce to 1 (EIP-161, matching go-ethereum create()/create2()).

// r37InitCode returns a minimal QVM init code that deploys 32 bytes of
// runtime code (MSTORE 0x42 at 0, RETURN 32 bytes from 0).
func r37InitCode() []byte {
	// QVM opcodes: PUSH1=0x10, MSTORE=0x51, RETURN=0x06
	return []byte{0x10, 0x42, 0x10, 0x00, 0x51, 0x10, 0x20, 0x10, 0x00, 0x06}
}

func r37BlockCtx() *BlockContext {
	return &BlockContext{
		BlockNumber: 1,
		Timestamp:   1780743509,
		GasLimit:    8000000,
		Coinbase:    Address{0x10},
	}
}

func TestR37_P3_21_ExecutorCreateSetsContractNonceToOne(t *testing.T) {
	callerAddr := Address{0x01}
	executor := NewExecutor()
	stateDB := newMockStateDB()
	stateDB.SetBalance(callerAddr, big.NewInt(1000000))
	// TxExecutor increments the sender nonce before calling Create.
	stateDB.SetNonce(callerAddr, 1)

	initCode := r37InitCode()
	result, addr := executor.Create(stateDB, callerAddr, initCode, 1000000, big.NewInt(0), r37BlockCtx(), 0)
	if result.Err != nil {
		t.Fatalf("contract creation failed: %v", result.Err)
	}
	if stateDB.GetCodeSize(addr) == 0 {
		t.Fatal("no code deployed")
	}
	if got := stateDB.GetNonce(addr); got != 1 {
		t.Fatalf("EIP-161: new contract nonce = %d, want 1", got)
	}
}

func TestR37_P3_21_ExecutorCreate2SetsContractNonceToOne(t *testing.T) {
	callerAddr := Address{0x01}
	executor := NewExecutor()
	stateDB := newMockStateDB()
	stateDB.SetBalance(callerAddr, big.NewInt(1000000))
	stateDB.SetNonce(callerAddr, 1)

	initCode := r37InitCode()
	salt := Hash{0x2a}
	result, addr := executor.Create2(stateDB, callerAddr, initCode, salt, 1000000, big.NewInt(0), r37BlockCtx(), 0)
	if result.Err != nil {
		t.Fatalf("contract creation failed: %v", result.Err)
	}
	wantAddr := Create2Address(callerAddr, salt, initCode)
	if addr != wantAddr {
		t.Fatalf("CREATE2 address = %x, want %x", addr, wantAddr)
	}
	if stateDB.GetCodeSize(addr) == 0 {
		t.Fatal("no code deployed")
	}
	if got := stateDB.GetNonce(addr); got != 1 {
		t.Fatalf("EIP-161: new contract nonce = %d, want 1", got)
	}
}

func TestR37_P3_21_InterpreterCreateSetsContractNonceToOne(t *testing.T) {
	creatorAddr := Address{0x02}
	stateDB := newMockStateDB()
	stateDB.SetBalance(creatorAddr, big.NewInt(1000000))

	initCode := r37InitCode()
	// Parent program: store initCode into memory, then CREATE(value=0,
	// offset=22, size=10). MSTORE pops offset(top), value(second); CREATE
	// pops value(top), offset, size.
	var word [32]byte
	copy(word[32-len(initCode):], initCode)
	code := []byte{byte(PUSH32)}
	code = append(code, word[:]...)
	code = append(code,
		byte(PUSH1), 0x00, // MSTORE offset
		byte(MSTORE),
		byte(PUSH1), byte(len(initCode)), // CREATE size
		byte(PUSH1), 0x16, // CREATE offset (32-10=22)
		byte(PUSH1), 0x00, // CREATE value
		byte(CREATE),
		byte(STOP),
	)

	interp := NewInterpreter()
	ctx := &ExecutionContext{
		Origin:      creatorAddr,
		Caller:      creatorAddr,
		Address:     creatorAddr,
		Value:       big.NewInt(0),
		BlockNumber: 1,
		Timestamp:   1780743509,
		GasLimit:    8000000,
		Code:        code,
		Gas:         1000000,
	}
	result := interp.Execute(ctx, stateDB)
	if result.Err != nil {
		t.Fatalf("execution failed: %v", result.Err)
	}

	contractAddr := CreateAddress(creatorAddr, 0)
	if stateDB.GetCodeSize(contractAddr) == 0 {
		t.Fatal("no code deployed via interpreter CREATE")
	}
	if got := stateDB.GetNonce(contractAddr); got != 1 {
		t.Fatalf("EIP-161: new contract nonce = %d, want 1", got)
	}
	if got := stateDB.GetNonce(creatorAddr); got != 1 {
		t.Fatalf("creator nonce = %d, want 1", got)
	}
}
