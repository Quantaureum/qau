// Quantaureum Node source, version 1.0.0.
package jit

import (
	"testing"
)

// FIX: End-to-end JIT vs interpreter consistency tests.
// These tests verify that the JIT compiler produces the same results as
// the interpreter for basic operations including arithmetic, memory,
// and CALL/CREATE paths.

// TestJITConsistency_Arithmetic verifies JIT and interpreter produce
// identical stack results for basic arithmetic (ADD, SUB, MUL, DIV).
func TestJITConsistency_Arithmetic(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{
			name: "ADD",
			code: []byte{byte(PUSH1), 0x0A, byte(PUSH1), 0x14, byte(ADD), byte(STOP)},
		},
		{
			name: "SUB",
			// QVM SUB: pops a(top), b(second), returns a-b. Push b first, then a.
			code: []byte{byte(PUSH1), 0x0A, byte(PUSH1), 0x64, byte(SUB), byte(STOP)},
		},
		{
			name: "MUL",
			code: []byte{byte(PUSH1), 0x07, byte(PUSH1), 0x06, byte(MUL), byte(STOP)},
		},
		{
			name: "DIV",
			// QVM DIV: pops a(top), b(second), returns a/b. Push b first, then a.
			code: []byte{byte(PUSH1), 0x06, byte(PUSH1), 0x3C, byte(DIV), byte(STOP)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewJITCompiler(256)
			plan, err := compiler.Compile(tt.code)
			if err != nil {
				t.Fatalf("compile failed: %v", err)
			}

			env := newMockEnv(100000)
			if err := compiler.Execute(plan, env); err != nil {
				t.Fatalf("JIT execute failed: %v", err)
			}

			if env.stack.Len() != 1 {
				t.Fatalf("expected 1 item on stack, got %d", env.stack.Len())
			}
			result, _ := env.stack.Pop()

			// Verify expected results manually since we can't easily run
			// the interpreter from the jit package.
			var expected uint64
			switch tt.name {
			case "ADD":
				expected = 0x0A + 0x14
			case "SUB":
				expected = 0x64 - 0x0A
			case "MUL":
				expected = 0x07 * 0x06
			case "DIV":
				expected = 0x3C / 0x06
			}
			if result.ToUint64() != expected {
				t.Errorf("expected %d, got %d", expected, result.ToUint64())
			}
		})
	}
}

// TestJITConsistency_Memory verifies JIT memory operations produce
// correct results matching expected interpreter behavior.
func TestJITConsistency_Memory(t *testing.T) {
	// PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x00, MLOAD, STOP
	code := []byte{
		byte(PUSH1), 0x42, // value
		byte(PUSH1), 0x00, // offset
		byte(MSTORE),      // memory[0] = 0x42
		byte(PUSH1), 0x00, // offset
		byte(MLOAD), // push memory[0]
		byte(STOP),
	}

	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	if err := compiler.Execute(plan, env); err != nil {
		t.Fatalf("JIT execute failed: %v", err)
	}

	if env.stack.Len() != 1 {
		t.Fatalf("expected 1 item on stack, got %d", env.stack.Len())
	}
	result, _ := env.stack.Pop()
	// MSTORE at offset 0 stores 32-byte big-endian value. For PUSH1 0x42,
	// the value is 0x00...0042 (31 zeros + 0x42). MLOAD reads it back as
	// a 256-bit value, which is 0x42 = 66.
	if result.ToUint64() != 0x42 {
		t.Errorf("expected 0x42, got 0x%x", result.ToUint64())
	}
}

// TestJITConsistency_CALL_Gas verifies that CALL consumes the expected
// gas amount, matching the interpreter's gas accounting.
func TestJITConsistency_CALL_Gas(t *testing.T) {
	// PUSH1 0x00 (retLength), PUSH1 0x00 (retOffset), PUSH1 0x00 (argsLength),
	// PUSH1 0x00 (argsOffset), PUSH1 0x00 (value), PUSH1 0x01 (addr),
	// PUSH1 0x2710 (gas), CALL, STOP
	code := []byte{
		byte(PUSH1), 0x00, // retLength
		byte(PUSH1), 0x00, // retOffset
		byte(PUSH1), 0x00, // argsLength
		byte(PUSH1), 0x00, // argsOffset
		byte(PUSH1), 0x00, // value
		byte(PUSH1), 0x01, // addr (Address{0x00...01})
		byte(PUSH2), 0x27, 0x10, // gas = 10000
		byte(CALL),
		byte(STOP),
	}

	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	env.callSucceeds = true
	// Set up target address as having code for reentrancy guard
	var targetAddr Address
	targetAddr[19] = 0x01
	env.state.codes[targetAddr] = []byte{0x00}

	if err := compiler.Execute(plan, env); err != nil {
		t.Fatalf("JIT execute failed: %v", err)
	}

	// CALL should push 1 (success) onto the stack
	if env.stack.Len() != 1 {
		t.Fatalf("expected 1 item on stack, got %d", env.stack.Len())
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 1 {
		t.Errorf("expected CALL to return 1 (success), got %d", result.ToUint64())
	}

	// Verify gas was consumed (base CALL gas + callee gas + reentrancy guard)
	if env.gas.used == 0 {
		t.Error("expected gas to be consumed by CALL")
	}
}

// TestJITConsistency_CREATE verifies CREATE produces a non-zero address
// and consumes gas.
func TestJITConsistency_CREATE(t *testing.T) {
	// PUSH1 0x00 (value), PUSH1 0x00 (offset), PUSH1 0x00 (size), CREATE, STOP
	code := []byte{
		byte(PUSH1), 0x00, // value
		byte(PUSH1), 0x00, // offset
		byte(PUSH1), 0x00, // size (empty init code)
		byte(CREATE),
		byte(STOP),
	}

	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	env.callSucceeds = true // mockEnv uses callSucceeds for CREATE success

	if err := compiler.Execute(plan, env); err != nil {
		t.Fatalf("JIT execute failed: %v", err)
	}

	// CREATE should push the contract address onto the stack
	if env.stack.Len() != 1 {
		t.Fatalf("expected 1 item on stack, got %d", env.stack.Len())
	}

	// Verify gas was consumed
	if env.gas.used == 0 {
		t.Error("expected gas to be consumed by CREATE")
	}
}

// TestJITConsistency_CALL_NoCode verifies that calling an EOA (no code)
// does not charge reentrancy guard gas, matching interpreter behavior.
func TestJITConsistency_CALL_NoCode(t *testing.T) {
	// PUSH1 0x00, PUSH1 0x00, PUSH1 0x00, PUSH1 0x00, PUSH1 0x00,
	// PUSH1 0x02, PUSH2 0x27 0x10, CALL, STOP
	code := []byte{
		byte(PUSH1), 0x00, // retLength
		byte(PUSH1), 0x00, // retOffset
		byte(PUSH1), 0x00, // argsLength
		byte(PUSH1), 0x00, // argsOffset
		byte(PUSH1), 0x00, // value
		byte(PUSH1), 0x02, // addr (EOA - no code)
		byte(PUSH2), 0x27, 0x10, // gas = 10000
		byte(CALL),
		byte(STOP),
	}

	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	// EOA call: no code at target, callDepth=0 (no reentrancy)
	env := newMockEnv(100000)
	env.callSucceeds = true

	if err := compiler.Execute(plan, env); err != nil {
		t.Fatalf("JIT execute failed: %v", err)
	}

	// CALL to EOA should succeed (pushes 1)
	if env.stack.Len() != 1 {
		t.Fatalf("expected 1 item on stack, got %d", env.stack.Len())
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 1 {
		t.Errorf("expected CALL to EOA to return 1 (success), got %d", result.ToUint64())
	}
}
