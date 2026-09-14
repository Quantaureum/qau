// Quantaureum Node source, version 1.0.0.
// Package qvm — R32-P3-06 regression tests.
//
// AUDIT (2026) R32-P3-06: QVM INVALID opcode error handling was inconsistent.
// Previously CREATE/CREATE2 mapped ALL ValidateDeployedCode failures to
// ErrInvalidOpcode, which was misleading — the actual failure could be:
//   - ErrCodeTooLarge (code size exceeds maximum)
//   - ErrInvalidPushData (truncated push data)
//   - ErrUnknownOpcode (unknown opcode in bytecode)
//   - ErrInvalidJumpTarget (invalid jump destination)
//   - ErrStackImbalance (stack imbalance)
//   - ErrInvalidCodePrefix (code starts with 0xEF, EIP-3541)
//
// The fix:
//  1. Adds ErrInvalidBytecode error type for deployment validation failures
//  2. Adds ValidationResult.FirstError() helper to extract the specific cause
//  3. CREATE/CREATE2 now return ErrInvalidBytecode wrapping the specific error
//
// Runtime INVALID opcode handling (environment.go, operations.go) is already
// correct and unchanged — ErrInvalidOpcode is the right error for runtime
// unknown/invalid opcodes.
package qvm

import (
	"errors"
	"math/big"
	"testing"
)

// TestR32_P3_06_ErrInvalidBytecode_DistinctFromErrInvalidOpcode verifies that
// ErrInvalidBytecode is a distinct error from ErrInvalidOpcode. Previously
// CREATE/CREATE2 used ErrInvalidOpcode for all deployment validation failures,
// making it impossible to distinguish runtime invalid opcodes from deployment
// validation failures.
func TestR32_P3_06_ErrInvalidBytecode_DistinctFromErrInvalidOpcode(t *testing.T) {
	if errors.Is(ErrInvalidBytecode, ErrInvalidOpcode) {
		t.Fatal("ErrInvalidBytecode should NOT be the same as ErrInvalidOpcode — " +
			"deployment validation failures must be distinguishable from runtime invalid opcodes")
	}
	if errors.Is(ErrInvalidOpcode, ErrInvalidBytecode) {
		t.Fatal("ErrInvalidOpcode should NOT be the same as ErrInvalidBytecode")
	}
}

// TestR32_P3_06_Create_DeploymentValidationFailureReturnsErrInvalidBytecode
// verifies that Create returns ErrInvalidBytecode (not ErrInvalidOpcode) when
// the deployed code fails ValidateDeployedCode due to EIP-3541 prefix (0xEF).
func TestR32_P3_06_Create_DeploymentValidationFailureReturnsErrInvalidBytecode(t *testing.T) {
	callerAddr := Address{0x01}
	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 1000000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}

	// initCode that RETURNS code starting with 0xEF (EIP-3541 violation).
	// PUSH1 0xEF + PUSH1 0x00 (offset) + PUSH1 0x01 (size) + RETURN
	// This pushes 0xEF to memory[0], then returns 1 byte from offset 0.
	initCode := []byte{
		byte(PUSH1), 0xEF, // push 0xEF (the forbidden prefix byte)
		byte(PUSH1), 0x00, // push offset=0
		byte(MSTORE8),     // memory[0] = 0xEF
		byte(PUSH1), 0x01, // push size=1
		byte(PUSH1), 0x00, // push offset=0
		byte(RETURN), // return memory[0:1] = [0xEF]
	}

	executor := NewExecutor()
	stateDB := newMockStateDB()
	stateDB.SetBalance(callerAddr, big.NewInt(1000000))
	stateDB.SetNonce(callerAddr, 1)

	result, addr := executor.Create(stateDB, callerAddr, initCode, 100000, big.NewInt(0), blockCtx, 0)

	if result == nil {
		t.Fatal("Create returned nil result")
	}
	if result.Err == nil {
		t.Fatal("R32-P3-06 NOT FIXED: Create succeeded for code starting with 0xEF — " +
			"EIP-3541 violation should fail deployment validation")
	}
	// The error must be ErrInvalidBytecode (wrapping the specific cause),
	// NOT the plain ErrInvalidOpcode used for runtime unknown opcodes.
	if !errors.Is(result.Err, ErrInvalidBytecode) {
		t.Fatalf("R32-P3-06 NOT FIXED: Create returned %v for EIP-3541 violation, "+
			"expected ErrInvalidBytecode (was previously ErrInvalidOpcode)", result.Err)
	}
	// The wrapped error should mention the EIP-3541 prefix issue.
	if !errors.Is(result.Err, ErrInvalidCodePrefix) {
		// The wrapped error should at least mention the prefix issue in its message.
		errStr := result.Err.Error()
		if !contains(errStr, "0xEF") && !contains(errStr, "prefix") {
			t.Fatalf("R32-P3-06: error message %q does not mention 0xEF/prefix — "+
				"should wrap the specific validation error", errStr)
		}
	}
	// Address should be empty on failure.
	if addr != (Address{}) {
		t.Fatalf("Address should be empty on deployment failure, got %x", addr)
	}
}

// TestR32_P3_06_Create2_DeploymentValidationFailureReturnsErrInvalidBytecode
// verifies that Create2 returns ErrInvalidBytecode (not ErrInvalidOpcode) when
// the deployed code fails ValidateDeployedCode due to EIP-3541 prefix (0xEF).
func TestR32_P3_06_Create2_DeploymentValidationFailureReturnsErrInvalidBytecode(t *testing.T) {
	callerAddr := Address{0x01}
	salt := Hash{0x01}
	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 1000000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}

	// initCode that RETURNS code starting with 0xEF (EIP-3541 violation).
	initCode := []byte{
		byte(PUSH1), 0xEF, // push 0xEF (the forbidden prefix byte)
		byte(PUSH1), 0x00, // push offset=0
		byte(MSTORE8),     // memory[0] = 0xEF
		byte(PUSH1), 0x01, // push size=1
		byte(PUSH1), 0x00, // push offset=0
		byte(RETURN), // return memory[0:1] = [0xEF]
	}

	executor := NewExecutor()
	stateDB := newMockStateDB()
	stateDB.SetBalance(callerAddr, big.NewInt(1000000))
	stateDB.SetNonce(callerAddr, 1)

	result, addr := executor.Create2(stateDB, callerAddr, initCode, salt, 100000, big.NewInt(0), blockCtx, 0)

	if result == nil {
		t.Fatal("Create2 returned nil result")
	}
	if result.Err == nil {
		t.Fatal("R32-P3-06 NOT FIXED: Create2 succeeded for code starting with 0xEF — " +
			"EIP-3541 violation should fail deployment validation")
	}
	if !errors.Is(result.Err, ErrInvalidBytecode) {
		t.Fatalf("R32-P3-06 NOT FIXED: Create2 returned %v for EIP-3541 violation, "+
			"expected ErrInvalidBytecode (was previously ErrInvalidOpcode)", result.Err)
	}
	if addr != (Address{}) {
		t.Fatalf("Address should be empty on deployment failure, got %x", addr)
	}
}

// TestR32_P3_06_RuntimeInvalidOpcode_StillReturnsErrInvalidOpcode verifies
// that runtime INVALID opcode execution still returns ErrInvalidOpcode (not
// ErrInvalidBytecode). This confirms the fix only changes the deployment
// validation path, not the runtime execution path.
func TestR32_P3_06_RuntimeInvalidOpcode_StillReturnsErrInvalidOpcode(t *testing.T) {
	// Execute a contract with the INVALID opcode (0x08 in QVM).
	// The interpreter should return ErrInvalidOpcode at runtime.
	code := []byte{byte(INVALID)}

	executor := NewExecutor()
	stateDB := newMockStateDB()
	callerAddr := Address{0x01}
	contractAddr := Address{0x02}
	stateDB.SetCode(contractAddr, code)
	stateDB.SetBalance(callerAddr, big.NewInt(1000000))

	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 1000000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}

	result := executor.Call(stateDB, callerAddr, contractAddr, nil, 1000, big.NewInt(0), blockCtx, 0)
	if result == nil {
		t.Fatal("Executor.Call returned nil result")
	}
	// Runtime INVALID opcode must return ErrInvalidOpcode, NOT ErrInvalidBytecode.
	if result.Err != ErrInvalidOpcode {
		t.Fatalf("R32-P3-06: runtime INVALID opcode returned %v, expected ErrInvalidOpcode "+
			"(runtime path should be unaffected by deployment validation fix)", result.Err)
	}
	if errors.Is(result.Err, ErrInvalidBytecode) {
		t.Fatal("R32-P3-06: runtime INVALID opcode returned ErrInvalidBytecode — " +
			"runtime path should return ErrInvalidOpcode, not ErrInvalidBytecode")
	}
}

// TestR32_P3_06_ValidationResult_FirstError verifies that
// ValidationResult.FirstError() returns the first error for an invalid result
// and nil for a valid result.
func TestR32_P3_06_ValidationResult_FirstError(t *testing.T) {
	// Valid result → nil
	validResult := &ValidationResult{Valid: true}
	if err := validResult.FirstError(); err != nil {
		t.Fatalf("FirstError for valid result should be nil, got %v", err)
	}

	// Nil result → nil
	var nilResult *ValidationResult
	if err := nilResult.FirstError(); err != nil {
		t.Fatalf("FirstError for nil result should be nil, got %v", err)
	}

	// Invalid result with no errors → nil (defensive)
	emptyInvalidResult := &ValidationResult{Valid: false}
	if err := emptyInvalidResult.FirstError(); err != nil {
		t.Fatalf("FirstError for invalid result with no errors should be nil, got %v", err)
	}

	// Invalid result with errors → first error
	invalidResult := &ValidationResult{
		Valid: false,
		Errors: []ValidationError{
			{Offset: 0, OpCode: 0xFF, Message: "unknown opcode"},
			{Offset: 5, OpCode: 0xFE, Message: "another error"},
		},
	}
	firstErr := invalidResult.FirstError()
	if firstErr == nil {
		t.Fatal("FirstError for invalid result with errors should not be nil")
	}
	// Should be the first error (offset 0, opcode 0xFF).
	errStr := firstErr.Error()
	if !contains(errStr, "offset 0") {
		t.Fatalf("FirstError should return the first error (offset 0), got: %s", errStr)
	}
}

// contains is a simple string contains helper (avoids importing strings for
// one function).
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
