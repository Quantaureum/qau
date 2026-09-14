// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"testing"
)

func TestBytecodeValidator_Validate(t *testing.T) {
	tests := []struct {
		name    string
		code    []byte
		isValid bool
	}{
		{name: "Valid jump destinations pass validation", code: []byte{byte(JUMPDEST), byte(PUSH1), 0x00, byte(JUMP), byte(JUMPDEST)}, isValid: true},
		{name: "Empty code is valid", code: []byte{}, isValid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewBytecodeValidator()
			result := validator.Validate(tt.code)
			if result.Valid != tt.isValid {
				t.Errorf("expected valid=%v, got %v", tt.isValid, result.Valid)
			}
		})
	}
}

func TestBytecodeValidator_QuickValidate(t *testing.T) {
	tests := []struct {
		name    string
		code    []byte
		wantErr error
	}{
		{name: "EIP-3541 prefix check - deployed code cannot start with 0xef", code: []byte{0xEF, 0xfe, 0xfe, 0xfe}, wantErr: ErrInvalidCodePrefix},
		{name: "Valid code passes quick check", code: []byte{byte(STOP)}, wantErr: nil},
		{name: "Empty code passes quick check", code: []byte{}, wantErr: nil},
		{name: "Code too large fails", code: make([]byte, MaxCodeSize+1), wantErr: ErrCodeTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewBytecodeValidator()
			err := validator.QuickValidate(tt.code)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestBytecodeValidator_ValidateInitCode(t *testing.T) {
	tests := []struct {
		name    string
		code    []byte
		isValid bool
	}{
		{name: "Valid init code passes", code: []byte{byte(PUSH1), 0x01, byte(RETURN)}, isValid: true},
		{name: "Empty init code passes", code: []byte{}, isValid: true},
		{name: "Code size exceeds limit fails", code: make([]byte, MaxInitCodeSize+1), isValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewBytecodeValidator()
			result := validator.ValidateInitCode(tt.code)
			if result.Valid != tt.isValid {
				t.Errorf("expected valid=%v, got %v", tt.isValid, result.Valid)
			}
		})
	}
}

func TestBytecodeValidator_ValidateDeployedCode(t *testing.T) {
	tests := []struct {
		name    string
		code    []byte
		isValid bool
	}{
		{name: "Valid deployed code passes", code: []byte{byte(STOP)}, isValid: true},
		{name: "Valid deployed code with JUMPDEST passes", code: []byte{byte(JUMPDEST), byte(PUSH1), 0x00, byte(JUMP), byte(JUMPDEST)}, isValid: true},
		{name: "Code starting with 0xEF fails", code: []byte{0xEF, 0xfe, 0xfe, 0xfe}, isValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewBytecodeValidator()
			result := validator.ValidateDeployedCode(tt.code)
			if result.Valid != tt.isValid {
				t.Errorf("expected valid=%v, got %v", tt.isValid, result.Valid)
			}
		})
	}
}

func TestDisassemble(t *testing.T) {
	tests := []struct {
		name          string
		code          []byte
		expectedLines int
	}{
		{name: "Disassemble simple bytecode", code: []byte{byte(STOP), byte(PUSH1), 0x01, byte(ADD)}, expectedLines: 3},
		{name: "Unknown opcodes handled", code: []byte{0xFF, 0xFE}, expectedLines: 2},
		{name: "Empty bytecode", code: []byte{}, expectedLines: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Disassemble(tt.code)
			if len(result) != tt.expectedLines {
				t.Errorf("expected %d lines, got %d", tt.expectedLines, len(result))
			}
		})
	}
}
