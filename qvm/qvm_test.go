// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"testing"
)

func TestNewInterpreter(t *testing.T) {
	i := NewInterpreter()
	if i == nil {
		t.Fatal("expected non-nil interpreter")
	}
	if i.gasTable == nil {
		t.Error("expected non-nil gas table")
	}
}

func TestExecute_EmptyCode(t *testing.T) {
	i := NewInterpreter()
	sdb := newMockStateDB()

	ctx := &ExecutionContext{
		Code:  []byte{},
		Gas:   100000,
		Input: []byte{},
	}

	result := i.Execute(ctx, sdb)
	_ = result
}

func TestExecute_SimpleCode(t *testing.T) {
	i := NewInterpreter()
	sdb := newMockStateDB()

	code := []byte{
		byte(PUSH1), 0x2a,
		byte(PUSH1), 0x00,
		byte(SSTORE),
	}

	ctx := &ExecutionContext{
		Code:    code,
		Gas:     100000,
		Input:   []byte{},
		Origin:  Address{0x01},
		Caller:  Address{0x01},
		Address: Address{0x02},
	}

	result := i.Execute(ctx, sdb)
	if result.Err != nil {
		t.Fatalf("simple code execution failed: %v", result.Err)
	}
}

func TestExecute_ReturnData(t *testing.T) {
	i := NewInterpreter()
	sdb := newMockStateDB()

	code := []byte{
		byte(PUSH1), 0x2a,
		byte(PUSH1), 0x00,
		byte(MSTORE),
		byte(PUSH1), 0x20,
		byte(PUSH1), 0x00,
		byte(RETURN),
	}

	ctx := &ExecutionContext{
		Code:    code,
		Gas:     100000,
		Input:   []byte{},
		Origin:  Address{0x01},
		Caller:  Address{0x01},
		Address: Address{0x02},
	}

	result := i.Execute(ctx, sdb)
	if result.Err != nil {
		t.Fatalf("execution failed: %v", result.Err)
	}
	if result.ReturnData == nil {
		t.Fatal("expected return data")
	}
}

func TestExecute_GasConsumption(t *testing.T) {
	i := NewInterpreter()
	sdb := newMockStateDB()

	code := []byte{
		byte(PUSH1), 0x2a,
		byte(PUSH1), 0x00,
		byte(SSTORE),
	}

	ctx := &ExecutionContext{
		Code:    code,
		Gas:     100000,
		Input:   []byte{},
		Origin:  Address{0x01},
		Caller:  Address{0x01},
		Address: Address{0x02},
	}

	result := i.Execute(ctx, sdb)
	if result.Err != nil {
		t.Fatalf("execution failed: %v", result.Err)
	}
	if result.GasUsed == 0 {
		t.Error("expected positive gas usage")
	}
}

func TestExecute_OutOfGas(t *testing.T) {
	i := NewInterpreter()
	sdb := newMockStateDB()

	code := []byte{
		byte(PUSH1), 0x2a,
		byte(PUSH1), 0x00,
		byte(SSTORE),
	}

	ctx := &ExecutionContext{
		Code:    code,
		Gas:     0,
		Input:   []byte{},
		Origin:  Address{0x01},
		Caller:  Address{0x01},
		Address: Address{0x02},
	}

	result := i.Execute(ctx, sdb)
	if result.Err == nil {
		t.Error("expected out-of-gas error with 0 gas")
	}
}

func TestExecute_InvalidOpcode(t *testing.T) {
	i := NewInterpreter()
	sdb := newMockStateDB()

	code := []byte{byte(INVALID)}

	ctx := &ExecutionContext{
		Code:  code,
		Gas:   100000,
		Input: []byte{},
	}

	result := i.Execute(ctx, sdb)
	if result.Err == nil {
		t.Error("expected error for INVALID opcode")
	}
}

func TestExecute_REVERT(t *testing.T) {
	i := NewInterpreter()
	sdb := newMockStateDB()

	code := []byte{
		byte(PUSH1), 0x01,
		byte(PUSH1), 0x00,
		byte(MSTORE),
		byte(PUSH1), 0x01,
		byte(PUSH1), 0x00,
		byte(REVERT),
	}

	ctx := &ExecutionContext{
		Code:    code,
		Gas:     100000,
		Input:   []byte{},
		Origin:  Address{0x01},
		Caller:  Address{0x01},
		Address: Address{0x02},
	}

	result := i.Execute(ctx, sdb)
	if result.Err == nil {
		t.Error("expected revert error")
	}
	if !result.Reverted {
		t.Error("expected Reverted flag to be true")
	}
}

func TestValidateBytecode(t *testing.T) {
	i := NewInterpreter()

	if err := i.ValidateBytecode([]byte{}); err != nil {
		t.Errorf("empty bytecode should be valid: %v", err)
	}

	valid := []byte{
		byte(PUSH1), 0x2a,
		byte(PUSH1), 0x00,
		byte(SSTORE),
	}
	if err := i.ValidateBytecode(valid); err != nil {
		t.Errorf("valid bytecode rejected: %v", err)
	}
}

func TestValidateBytecode_TooLarge(t *testing.T) {
	i := NewInterpreter()
	large := make([]byte, MaxCodeSize+1)
	if err := i.ValidateBytecode(large); err == nil {
		t.Error("expected error for oversized bytecode")
	}
}
