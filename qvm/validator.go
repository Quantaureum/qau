// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"errors"
	"fmt"
)

// Validation errors
var (
	ErrCodeTooLarge      = errors.New("code size exceeds maximum")
	ErrInvalidPushData   = errors.New("invalid push data: truncated")
	ErrUnknownOpcode     = errors.New("unknown opcode")
	ErrInvalidJumpTarget = errors.New("invalid jump target")
	ErrStackImbalance    = errors.New("stack imbalance detected")
	ErrInvalidCodePrefix = errors.New("invalid code prefix: code cannot start with 0xEF (EIP-3541)")
)

// ValidationResult contains the result of bytecode validation.
type ValidationResult struct {
	Valid       bool
	Errors      []ValidationError
	JumpDests   map[uint64]bool
	CodeSize    int
	OpcodeCount int
}

// ValidationError represents a single validation error.
type ValidationError struct {
	Offset  uint64
	OpCode  OpCode
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("offset %d: %s (opcode: %s)", e.Offset, e.Message, e.OpCode.String())
}

// FirstError returns the first validation error from the result, or nil if
// the result is valid. R32-P3-06 FIX (2026-07-28): used by executor.go to
// construct a specific ErrInvalidBytecode wrapper instead of the previous
// misleading ErrInvalidOpcode for all deployment validation failures.
func (r *ValidationResult) FirstError() error {
	if r == nil || r.Valid || len(r.Errors) == 0 {
		return nil
	}
	return r.Errors[0]
}

// BytecodeValidator validates QVM bytecode.
type BytecodeValidator struct {
	maxCodeSize  int
	allowUnknown bool // Allow unknown opcodes (they will fail at runtime)
	strictMode   bool // Enable strict validation
}

// NewBytecodeValidator creates a new bytecode validator.
func NewBytecodeValidator() *BytecodeValidator {
	return &BytecodeValidator{
		maxCodeSize:  MaxCodeSize,
		allowUnknown: true,
		strictMode:   false,
	}
}

// WithMaxCodeSize sets the maximum code size.
func (v *BytecodeValidator) WithMaxCodeSize(size int) *BytecodeValidator {
	v.maxCodeSize = size
	return v
}

// WithStrictMode enables strict validation.
func (v *BytecodeValidator) WithStrictMode(strict bool) *BytecodeValidator {
	v.strictMode = strict
	v.allowUnknown = !strict
	return v
}

// Validate validates the given bytecode.
func (v *BytecodeValidator) Validate(code []byte) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Errors:    make([]ValidationError, 0),
		JumpDests: make(map[uint64]bool),
		CodeSize:  len(code),
	}

	// Check code size
	if len(code) > v.maxCodeSize {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Offset:  0,
			Message: fmt.Sprintf("code size %d exceeds maximum %d", len(code), v.maxCodeSize),
		})
		return result
	}

	// First pass: identify jump destinations and validate opcodes
	// SECURITY NOTE: jumpTargets map removed - JUMP/JUMPI targets are runtime-dependent
	// and cannot be statically verified. Only JUMPDEST marking (line 109) is reliable.

	for pc := 0; pc < len(code); {
		op := OpCode(code[pc])
		result.OpcodeCount++

		// Check if opcode is valid
		info, valid := op.GetInfo()
		if !valid {
			if !v.allowUnknown {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Offset:  uint64(pc), // #nosec G115 -- pc is a non-negative int index bounded by len(code)
					OpCode:  op,
					Message: "unknown opcode",
				})
			}
			pc++
			continue
		}

		// Mark jump destinations
		if op == JUMPDEST {
			result.JumpDests[uint64(pc)] = true // #nosec G115 -- pc is a non-negative int index bounded by len(code)
		}

		// Handle PUSH instructions
		if op.IsPush() {
			pushSize := info.ImmediateSize
			if pc+1+pushSize > len(code) {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Offset:  uint64(pc), // #nosec G115 -- pc is a non-negative int index bounded by len(code)
					OpCode:  op,
					Message: fmt.Sprintf("truncated push data: need %d bytes, have %d", pushSize, len(code)-pc-1),
				})
			}
			pc += 1 + pushSize
		} else {
			pc++
		}
	}

	// Second pass (strict mode): validate jump targets
	if v.strictMode {
		for pc := 0; pc < len(code); {
			op := OpCode(code[pc])

			if op == JUMP || op == JUMPI {
				// In strict mode, we can't statically verify all jumps
				// because the target is on the stack at runtime
				// We just note that jumps exist
			}

			if op.IsPush() {
				pc += 1 + op.PushSize()
			} else {
				pc++
			}
		}
	}

	// SECURITY FIX: Removed dead validation code (lines 148-157).
	// The jumpTargets map was created but never populated during the first pass,
	// so this validation was checking an empty map and always passed.
	// Proper jump target validation requires runtime stack analysis (not statically computable).
	// JUMPDEST marking at line 109 remains correct.

	return result
}

// ValidateInitCode validates contract initialization code.
func (v *BytecodeValidator) ValidateInitCode(code []byte) *ValidationResult {
	result := v.Validate(code)

	// Init code has a larger size limit
	if len(code) > MaxInitCodeSize {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Offset:  0,
			Message: fmt.Sprintf("init code size %d exceeds maximum %d", len(code), MaxInitCodeSize),
		})
	}

	return result
}

// ValidateDeployedCode validates deployed contract code.
//
// QVM-004 NOTE: jumpdest integrity (marking all valid JUMPDEST positions and
// validating PUSH argument data) is NOT checked separately here — it is
// already enforced by the v.Validate(code) call on the first line, which runs
// the full BytecodeValidator pass (opcode validity + PUSH data + jumpdest
// analysis). This function is an ADDITIONAL check that layers the EIP-3541
// "no leading 0xEF" policy on top for code that is about to be committed to
// state. Callers in the executor (Create/Create2) invoke this on the FINAL
// deployed runtime code.
func (v *BytecodeValidator) ValidateDeployedCode(code []byte) *ValidationResult {
	result := v.Validate(code)

	// Deployed code must not start with 0xEF (EIP-3541)
	if len(code) > 0 && code[0] == 0xEF {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Offset:  0,
			OpCode:  OpCode(0xEF),
			Message: "deployed code cannot start with 0xEF",
		})
	}

	return result
}

// QuickValidate performs a quick validation check.
// audit-fix CR-3: Added EIP-3541 check to prevent deployment of code starting with 0xEF
func (v *BytecodeValidator) QuickValidate(code []byte) error {
	if len(code) > v.maxCodeSize {
		return ErrCodeTooLarge
	}

	// EIP-3541: deployed code must not start with 0xEF
	// This check was missing in QuickValidate but present in ValidateDeployedCode
	if len(code) > 0 && code[0] == 0xEF {
		return ErrInvalidCodePrefix
	}

	// Quick scan for truncated PUSH data and unknown opcodes
	for pc := 0; pc < len(code); {
		op := OpCode(code[pc])

		if op.IsPush() {
			pushSize := op.PushSize()
			if pc+1+pushSize > len(code) {
				return ErrInvalidPushData
			}
			pc += 1 + pushSize
		} else {
			// FIX: Check for unknown opcodes. An opcode not in the
			// valid opcode table will cause ErrInvalidOpcode at runtime;
			// rejecting it early in QuickValidate prevents deployment of
			// bytecode containing invalid instructions.
			if _, valid := op.GetInfo(); !valid {
				return ErrUnknownOpcode
			}
			pc++
		}
	}

	return nil
}

// Disassemble disassembles bytecode into human-readable format.
func Disassemble(code []byte) []string {
	result := make([]string, 0)

	for pc := 0; pc < len(code); {
		op := OpCode(code[pc])
		info, valid := op.GetInfo()

		if !valid {
			result = append(result, fmt.Sprintf("%04x: UNKNOWN(0x%02x)", pc, op))
			pc++
			continue
		}

		if op.IsPush() {
			pushSize := info.ImmediateSize
			end := pc + 1 + pushSize
			if end > len(code) {
				end = len(code)
			}

			data := code[pc+1 : end]
			result = append(result, fmt.Sprintf("%04x: %s 0x%x", pc, info.Name, data))
			pc = end
		} else {
			result = append(result, fmt.Sprintf("%04x: %s", pc, info.Name))
			pc++
		}
	}

	return result
}

// Assemble assembles simple bytecode from opcodes.
// This is mainly for testing purposes.
func Assemble(ops ...any) []byte {
	result := make([]byte, 0)

	for _, op := range ops {
		switch v := op.(type) {
		case OpCode:
			result = append(result, byte(v))
		case byte:
			result = append(result, v)
		case []byte:
			result = append(result, v...)
		case int:
			result = append(result, byte(v)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		}
	}

	return result
}
