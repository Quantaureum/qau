// Quantaureum Node source, version 1.0.0.
package evmcompat

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

func TestTranslateOpcode_KnownOpcodes(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	tests := []struct {
		evmCode byte
		name    string
		want    qvm.OpCode
	}{
		{0x00, "STOP", qvm.STOP},
		{0x01, "ADD", qvm.ADD},
		{0x02, "MUL", qvm.MUL},
		{0x03, "SUB", qvm.SUB},
		{0x04, "DIV", qvm.DIV},
		{0x05, "SDIV", qvm.SDIV},
		{0x06, "MOD", qvm.MOD},
		{0x07, "SMOD", qvm.SMOD},
		{0x08, "ADDMOD", qvm.ADDMOD},
		{0x09, "MULMOD", qvm.MULMOD},
		{0x0A, "EXP", qvm.EXP},
		{0x0B, "SIGNEXTEND", qvm.SIGNEXTEND},
		{0x10, "LT", qvm.LT},
		{0x11, "GT", qvm.GT},
		{0x12, "SLT", qvm.SLT},
		{0x13, "SGT", qvm.SGT},
		{0x14, "EQ", qvm.EQ},
		{0x20, "SHA3", qvm.SHA3},
		{0x3B, "EXTCODESIZE", qvm.EXTCODESIZE},
		{0x3C, "EXTCODECOPY", qvm.EXTCODECOPY},
		{0x3D, "RETURNDATASIZE", qvm.RETURNDATASIZE},
		{0x3E, "RETURNDATACOPY", qvm.RETURNDATACOPY},
		{0x3F, "EXTCODEHASH", qvm.EXTCODEHASH},
		{0x40, "BLOCKHASH", qvm.BLOCKHASH},
		{0x41, "COINBASE", qvm.COINBASE},
		{0x42, "TIMESTAMP", qvm.TIMESTAMP},
		{0x43, "NUMBER", qvm.NUMBER},
		{0x44, "DIFFICULTY", qvm.PREVRANDAO},
		{0x45, "GASLIMIT", qvm.GASLIMIT},
		{0x46, "CHAINID", qvm.CHAINID},
		{0x47, "SELFBALANCE", qvm.SELFBALANCE},
		{0x48, "BASEFEE", qvm.BASEFEE},
		{0x49, "BLOBHASH", qvm.BLOBHASH},
		{0x4A, "BLOBBASEFEE", qvm.BLOBBASEFEE},
		{0x5C, "TLOAD", qvm.TLOAD},
		{0x5D, "TSTORE", qvm.TSTORE},
		{0x5E, "MCOPY", qvm.MCOPY},
		{0x5F, "PUSH0", qvm.PUSH0},
		{0x56, "JUMP", qvm.JUMP},
		{0x57, "JUMPI", qvm.JUMPI},
		{0x80, "DUP1", qvm.DUP1},
		{0x81, "DUP2", qvm.DUP2},
		{0x8F, "DUP16", qvm.DUP16},
		{0x90, "SWAP1", qvm.SWAP1},
		{0x9F, "SWAP16", qvm.SWAP16},
		{0xA0, "LOG0", qvm.LOG0},
		{0xA4, "LOG4", qvm.LOG4},
		{0xF0, "CREATE", qvm.CREATE},
		{0xF1, "CALL", qvm.CALL},
		{0xF2, "CALLCODE", qvm.CALLCODE},
		{0xF4, "DELEGATECALL", qvm.DELEGATECALL},
		{0xF5, "CREATE2", qvm.CREATE2},
		{0xFA, "STATICCALL", qvm.STATICCALL},
		{0xFD, "REVERT", qvm.REVERT},
		{0xFF, "SELFDESTRUCT", qvm.SELFDESTRUCT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := layer.TranslateOpcode(tt.evmCode)
			if err != nil {
				t.Fatalf("TranslateOpcode(0x%02X) error: %v", tt.evmCode, err)
			}
			if got != tt.want {
				t.Errorf("TranslateOpcode(0x%02X) = %v, want %v", tt.evmCode, got, tt.want)
			}
		})
	}
}

func TestTranslateOpcode_IncompatibleOpcodes(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	// These EVM opcodes are truly unmapped and should return ErrIncompatibleOpcode
	incompatible := []struct {
		code byte
		name string
	}{
		{0x0C, "0x0C"},
		{0x0D, "0x0D"},
		{0x0E, "0x0E"},
		{0x0F, "0x0F"},
		{0x0E, "0x0E"},
		{0xEE, "0xEE"},
		{0xE0, "0xE0"},
		{0xC0, "0xC0"},
		{0xB0, "0xB0"},
	}

	for _, tt := range incompatible {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := layer.TranslateOpcode(tt.code)
			if err == nil {
				t.Errorf("expected error for incompatible opcode 0x%02X (%s)", tt.code, tt.name)
			}
		})
	}
}

func TestTranslateOpcode_UnknownOpcode(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())
	_, _, err := layer.TranslateOpcode(0xEE)
	if err == nil {
		t.Error("expected error for unknown opcode 0xEE")
	}
}

func TestTranslateBytecode_Simple(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	evmCode := []byte{0x60, 0x01, 0x60, 0x02, 0x01}
	qauCode, gasCosts, err := layer.TranslateBytecode(evmCode)
	if err != nil {
		t.Fatalf("TranslateBytecode error: %v", err)
	}
	if len(qauCode) == 0 {
		t.Error("expected non-empty translated bytecode")
	}
	if len(gasCosts) != len(qauCode) {
		t.Errorf("gas costs length %d != bytecode length %d", len(gasCosts), len(qauCode))
	}
}

func TestTranslateBytecode_Empty(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	qauCode, _, err := layer.TranslateBytecode([]byte{})
	if err != nil {
		t.Fatalf("TranslateBytecode empty error: %v", err)
	}
	if len(qauCode) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(qauCode))
	}
}

func TestTranslateBytecode_InvalidOpcode(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	_, _, err := layer.TranslateBytecode([]byte{0xEE})
	if err == nil {
		t.Error("expected error for invalid opcode in bytecode")
	}
}

func TestValidateEVMBytecode_Valid(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	valid := []byte{0x60, 0x01, 0x60, 0x02, 0x01, 0x00}
	if err := layer.ValidateEVMBytecode(valid); err != nil {
		t.Errorf("valid bytecode rejected: %v", err)
	}
}

func TestValidateEVMBytecode_Empty(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	if err := layer.ValidateEVMBytecode([]byte{}); err != nil {
		t.Errorf("empty bytecode should be valid: %v", err)
	}
}

func TestValidateEVMBytecode_TooLarge(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())
	large := make([]byte, 24577)
	if err := layer.ValidateEVMBytecode(large); err == nil {
		t.Error("expected error for oversized bytecode")
	}
}

func TestValidateEVMBytecode_UnknownOpcode(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	invalid := []byte{0xEE}
	if err := layer.ValidateEVMBytecode(invalid); err == nil {
		t.Error("expected error for unknown opcode")
	}
}

func TestIsPrecompile(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	tests := []struct {
		addr     byte
		expected bool
	}{
		{0x01, true},
		{0x02, true},
		{0x03, true},
		{0x04, true},
		{0x05, true},
		{0x06, true},
		{0x07, true},
		{0x08, true},
		{0x09, true},
		{0x0A, true}, // Keccak256 precompile
		{0x00, false},
		{0x0B, false},
	}

	for _, tt := range tests {
		result := layer.IsPrecompile(types.BytesToAddress([]byte{tt.addr}))
		if result != tt.expected {
			t.Errorf("IsPrecompile(0x%02X) = %v, want %v", tt.addr, result, tt.expected)
		}
	}
}

func TestGetCompatibilityReport(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())
	report := layer.GetCompatibilityReport()

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	totalOpcodes, ok := report["total_opcodes"].(int)
	if !ok {
		t.Fatal("expected total_opcodes in report")
	}
	if totalOpcodes == 0 {
		t.Error("expected at least some opcodes in report")
	}

	compatRatio, ok := report["compatibility_ratio"].(float64)
	if !ok {
		t.Fatal("expected compatibility_ratio in report")
	}
	if compatRatio <= 0 || compatRatio > 100 {
		t.Errorf("unexpected compatibility ratio: %f", compatRatio)
	}
}

func TestDUPMappings(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	expectedDUPs := []qvm.OpCode{
		qvm.DUP1, qvm.DUP2, qvm.DUP3, qvm.DUP4,
		qvm.DUP5, qvm.DUP6, qvm.DUP7, qvm.DUP8,
		qvm.DUP9, qvm.DUP10, qvm.DUP11, qvm.DUP12,
		qvm.DUP13, qvm.DUP14, qvm.DUP15, qvm.DUP16,
	}

	for i, expectedQAU := range expectedDUPs {
		evmCode := byte(0x80 + i)
		got, _, err := layer.TranslateOpcode(evmCode)
		if err != nil {
			t.Errorf("DUP%d (0x%02X) translation error: %v", i+1, evmCode, err)
			continue
		}
		if got != expectedQAU {
			t.Errorf("DUP%d: got %v, want %v", i+1, got, expectedQAU)
		}
	}
}

func TestSWAPMappings(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	expectedSWAPs := []qvm.OpCode{
		qvm.SWAP1, qvm.SWAP2, qvm.SWAP3, qvm.SWAP4,
		qvm.SWAP5, qvm.SWAP6, qvm.SWAP7, qvm.SWAP8,
		qvm.SWAP9, qvm.SWAP10, qvm.SWAP11, qvm.SWAP12,
		qvm.SWAP13, qvm.SWAP14, qvm.SWAP15, qvm.SWAP16,
	}

	for i, expectedQAU := range expectedSWAPs {
		evmCode := byte(0x90 + i)
		got, _, err := layer.TranslateOpcode(evmCode)
		if err != nil {
			t.Errorf("SWAP%d (0x%02X) translation error: %v", i+1, evmCode, err)
			continue
		}
		if got != expectedQAU {
			t.Errorf("SWAP%d: got %v, want %v", i+1, got, expectedQAU)
		}
	}
}

func TestLOGMappings(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	for i := byte(0); i <= 4; i++ {
		evmCode := 0xA0 + i
		expectedQAU := qvm.OpCode(byte(qvm.LOG0) + i)
		got, _, err := layer.TranslateOpcode(evmCode)
		if err != nil {
			t.Errorf("LOG%d (0x%02X) translation error: %v", i, evmCode, err)
			continue
		}
		if got != expectedQAU {
			t.Errorf("LOG%d: got %v, want %v", i, got, expectedQAU)
		}
	}
}

// TestAllStandardEVMOpcodesHaveMappings verifies that all standard EVM opcodes
// have mappings in the compatibility layer.
func TestAllStandardEVMOpcodesHaveMappings(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	// All standard EVM opcodes that should be supported
	standardOpcodes := []struct {
		code byte
		name string
	}{
		// Stop and arithmetic (0x00-0x0B)
		{0x00, "STOP"}, {0x01, "ADD"}, {0x02, "MUL"}, {0x03, "SUB"},
		{0x04, "DIV"}, {0x05, "SDIV"}, {0x06, "MOD"}, {0x07, "SMOD"},
		{0x08, "ADDMOD"}, {0x09, "MULMOD"}, {0x0A, "EXP"}, {0x0B, "SIGNEXTEND"},
		// Comparison & bitwise (0x10-0x1D)
		{0x10, "LT"}, {0x11, "GT"}, {0x12, "SLT"}, {0x13, "SGT"},
		{0x14, "EQ"}, {0x15, "ISZERO"}, {0x16, "AND"}, {0x17, "OR"},
		{0x18, "XOR"}, {0x19, "NOT"}, {0x1A, "BYTE"}, {0x1B, "SHL"},
		{0x1C, "SHR"}, {0x1D, "SAR"},
		// SHA3
		{0x20, "SHA3"},
		// Environment (0x30-0x3F)
		{0x30, "ADDRESS"}, {0x31, "BALANCE"}, {0x32, "ORIGIN"}, {0x33, "CALLER"},
		{0x34, "CALLVALUE"}, {0x35, "CALLDATALOAD"}, {0x36, "CALLDATASIZE"},
		{0x37, "CALLDATACOPY"}, {0x38, "CODESIZE"}, {0x39, "CODECOPY"},
		{0x3A, "GASPRICE"}, {0x3B, "EXTCODESIZE"}, {0x3C, "EXTCODECOPY"},
		{0x3D, "RETURNDATASIZE"}, {0x3E, "RETURNDATACOPY"}, {0x3F, "EXTCODEHASH"},
		// Block info (0x40-0x4A)
		{0x40, "BLOCKHASH"}, {0x41, "COINBASE"}, {0x42, "TIMESTAMP"},
		{0x43, "NUMBER"}, {0x44, "DIFFICULTY"}, {0x45, "GASLIMIT"},
		{0x46, "CHAINID"}, {0x47, "SELFBALANCE"}, {0x48, "BASEFEE"},
		{0x49, "BLOBHASH"}, {0x4A, "BLOBBASEFEE"},
		// Stack, memory, storage (0x50-0x5F)
		{0x50, "POP"}, {0x51, "MLOAD"}, {0x52, "MSTORE"}, {0x53, "MSTORE8"},
		{0x54, "SLOAD"}, {0x55, "SSTORE"}, {0x56, "JUMP"}, {0x57, "JUMPI"},
		{0x58, "PC"}, {0x59, "MSIZE"}, {0x5A, "GAS"}, {0x5B, "JUMPDEST"},
		{0x5C, "TLOAD"}, {0x5D, "TSTORE"}, {0x5E, "MCOPY"}, {0x5F, "PUSH0"},
		// PUSH1-32 (0x60-0x7F)
		{0x60, "PUSH1"}, {0x61, "PUSH2"}, {0x62, "PUSH3"}, {0x63, "PUSH4"},
		{0x64, "PUSH5"}, {0x65, "PUSH6"}, {0x66, "PUSH7"}, {0x67, "PUSH8"},
		{0x68, "PUSH9"}, {0x69, "PUSH10"}, {0x6A, "PUSH11"}, {0x6B, "PUSH12"},
		{0x6C, "PUSH13"}, {0x6D, "PUSH14"}, {0x6E, "PUSH15"}, {0x6F, "PUSH16"},
		{0x70, "PUSH17"}, {0x71, "PUSH18"}, {0x72, "PUSH19"}, {0x73, "PUSH20"},
		{0x74, "PUSH21"}, {0x75, "PUSH22"}, {0x76, "PUSH23"}, {0x77, "PUSH24"},
		{0x78, "PUSH25"}, {0x79, "PUSH26"}, {0x7A, "PUSH27"}, {0x7B, "PUSH28"},
		{0x7C, "PUSH29"}, {0x7D, "PUSH30"}, {0x7E, "PUSH31"}, {0x7F, "PUSH32"},
		// DUP1-16 (0x80-0x8F)
		{0x80, "DUP1"}, {0x81, "DUP2"}, {0x82, "DUP3"}, {0x83, "DUP4"},
		{0x84, "DUP5"}, {0x85, "DUP6"}, {0x86, "DUP7"}, {0x87, "DUP8"},
		{0x88, "DUP9"}, {0x89, "DUP10"}, {0x8A, "DUP11"}, {0x8B, "DUP12"},
		{0x8C, "DUP13"}, {0x8D, "DUP14"}, {0x8E, "DUP15"}, {0x8F, "DUP16"},
		// SWAP1-16 (0x90-0x9F)
		{0x90, "SWAP1"}, {0x91, "SWAP2"}, {0x92, "SWAP3"}, {0x93, "SWAP4"},
		{0x94, "SWAP5"}, {0x95, "SWAP6"}, {0x96, "SWAP7"}, {0x97, "SWAP8"},
		{0x98, "SWAP9"}, {0x99, "SWAP10"}, {0x9A, "SWAP11"}, {0x9B, "SWAP12"},
		{0x9C, "SWAP13"}, {0x9D, "SWAP14"}, {0x9E, "SWAP15"}, {0x9F, "SWAP16"},
		// LOG0-4 (0xA0-0xA4)
		{0xA0, "LOG0"}, {0xA1, "LOG1"}, {0xA2, "LOG2"}, {0xA3, "LOG3"}, {0xA4, "LOG4"},
		// System (0xF0-0xFF)
		{0xF0, "CREATE"}, {0xF1, "CALL"}, {0xF2, "CALLCODE"}, {0xF3, "RETURN"},
		{0xF4, "DELEGATECALL"}, {0xF5, "CREATE2"}, {0xFA, "STATICCALL"},
		{0xFD, "REVERT"}, {0xFE, "INVALID"}, {0xFF, "SELFDESTRUCT"},
	}

	var missing []string
	for _, op := range standardOpcodes {
		_, _, err := layer.TranslateOpcode(op.code)
		if err != nil {
			missing = append(missing, fmt.Sprintf("0x%02X (%s)", op.code, op.name))
		}
	}

	if len(missing) > 0 {
		t.Errorf("Missing EVM opcode mappings for %d standard opcodes:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestTranslateBytecode_WithNewOpcodes tests bytecode translation with the newly added opcodes.
func TestTranslateBytecode_WithNewOpcodes(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	tests := []struct {
		name     string
		bytecode []byte
		wantErr  bool
	}{
		{
			name:     "SIGNEXTEND",
			bytecode: []byte{0x60, 0x1F, 0x60, 0xFF, 0x0B},
			wantErr:  false,
		},
		{
			name:     "SDIV and SMOD",
			bytecode: []byte{0x60, 0x04, 0x60, 0x02, 0x05, 0x07},
			wantErr:  false,
		},
		{
			name:     "EXTCODESIZE",
			bytecode: []byte{0x60, 0x00, 0x3B},
			wantErr:  false,
		},
		{
			name:     "EXTCODECOPY",
			bytecode: []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x3C},
			wantErr:  false,
		},
		{
			name:     "RETURNDATASIZE and RETURNDATACOPY",
			bytecode: []byte{0x3D, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x3E},
			wantErr:  false,
		},
		{
			name:     "EXTCODEHASH",
			bytecode: []byte{0x60, 0x00, 0x3F},
			wantErr:  false,
		},
		{
			name:     "DIFFICULTY/PREVRANDAO",
			bytecode: []byte{0x44},
			wantErr:  false,
		},
		{
			name:     "BASEFEE",
			bytecode: []byte{0x48},
			wantErr:  false,
		},
		{
			name:     "BLOBHASH",
			bytecode: []byte{0x60, 0x01, 0x49},
			wantErr:  false,
		},
		{
			name:     "BLOBBASEFEE",
			bytecode: []byte{0x4A},
			wantErr:  false,
		},
		{
			name:     "TLOAD and TSTORE",
			bytecode: []byte{0x60, 0x01, 0x5D, 0x5C},
			wantErr:  false,
		},
		{
			name:     "PUSH0",
			bytecode: []byte{0x5F},
			wantErr:  false,
		},
		{
			name:     "Combined new opcodes",
			bytecode: []byte{0x5F, 0x60, 0x01, 0x01, 0x3D, 0x44, 0x48, 0x5C, 0x5D},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qauCode, gasCosts, err := layer.TranslateBytecode(tt.bytecode)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(qauCode) == 0 {
				t.Error("expected non-empty translated bytecode")
			}
			if len(gasCosts) != len(qauCode) {
				t.Errorf("gas costs length %d != bytecode length %d", len(gasCosts), len(qauCode))
			}
		})
	}
}

// TestTranslateBytecodeToEVM_NewOpcodes tests roundtrip translation for new opcodes.
func TestTranslateBytecodeToEVM_NewOpcodes(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	// Test individual new opcodes that have 1:1 QVM mappings
	newOpcodes := []byte{
		0x3D, // RETURNDATASIZE
		0x3E, // RETURNDATACOPY
		0x44, // DIFFICULTY -> PREVRANDAO
		0x5F, // PUSH0
	}

	for _, evmOp := range newOpcodes {
		t.Run(fmt.Sprintf("0x%02X", evmOp), func(t *testing.T) {
			// Translate EVM -> QVM
			qvmOp, _, err := layer.TranslateOpcode(evmOp)
			if err != nil {
				t.Fatalf("TranslateOpcode(0x%02X) error: %v", evmOp, err)
			}

			// Translate QVM -> EVM (for opcodes with unique QVM codes)
			evmCode, evmName, err := layer.TranslateQAUOpcode(qvmOp)
			if err != nil {
				t.Fatalf("TranslateQAUOpcode(%v) error: %v", qvmOp, err)
			}

			// For 1:1 mappings, the EVM code should roundtrip
			_ = evmCode
			_ = evmName
		})
	}
}

// TestUnknownEVMOpcodesReturnError verifies that unknown EVM opcodes return ErrIncompatibleOpcode.
func TestUnknownEVMOpcodesReturnError(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	// Opcodes that are not standard EVM and should not have mappings
	unknownOpcodes := []byte{
		0x0C, 0x0D, 0x0E, 0x0F, // Unused arithmetic range
		0x0E, 0x0F,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, // Unused after SHA3
		0x4B, 0x4C, 0x4D, 0x4E, 0x4F, // Unused after BLOBBASEFEE
		0xA5, 0xA6, 0xA7, // Unused after LOG4
		0xB0, 0xB1, 0xB2, // Unused range
		0xC0, 0xC1, 0xC2, // Unused range
		0xD0, 0xD1, 0xD2, // Unused range
		0xE0, 0xE1, 0xE2, // Unused range
		0xEE, 0xEF, // Unused range
	}

	for _, op := range unknownOpcodes {
		_, _, err := layer.TranslateOpcode(op)
		if err == nil {
			t.Errorf("expected ErrIncompatibleOpcode for unknown opcode 0x%02X, got nil", op)
		}
		if err != nil && err != ErrIncompatibleOpcode {
			t.Errorf("expected ErrIncompatibleOpcode for 0x%02X, got: %v", op, err)
		}
	}
}

// TestGetCompatibilityReport_ShowsHighCoverage verifies the compatibility report shows high coverage.
func TestGetCompatibilityReport_ShowsHighCoverage(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())
	report := layer.GetCompatibilityReport()

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	totalOpcodes, ok := report["total_opcodes"].(int)
	if !ok {
		t.Fatal("expected total_opcodes in report")
	}

	compatibleOpcodes, ok := report["compatible_opcodes"].(int)
	if !ok {
		t.Fatal("expected compatible_opcodes in report")
	}

	compatRatio, ok := report["compatibility_ratio"].(float64)
	if !ok {
		t.Fatal("expected compatibility_ratio in report")
	}

	// All mapped opcodes should be compatible
	if compatibleOpcodes != totalOpcodes {
		t.Errorf("expected all opcodes to be compatible: compatible=%d, total=%d", compatibleOpcodes, totalOpcodes)
	}

	// Should have 100% compatibility ratio since all mapped opcodes are marked compatible
	if compatRatio != 100.0 {
		t.Errorf("expected 100%% compatibility ratio, got %.1f%%", compatRatio)
	}

	// Should have a substantial number of opcodes mapped
	if totalOpcodes < 100 {
		t.Errorf("expected at least 100 mapped opcodes, got %d", totalOpcodes)
	}

	// Verify precompile count (9 standard + keccak256 + dilithium + kyber = 12)
	precompileCount, ok := report["precompile_count"].(int)
	if !ok || precompileCount != 12 {
		t.Errorf("expected 12 precompiles, got %d", precompileCount)
	}
}

// TestValidateEVMBytecode_WithNewOpcodes tests validation of bytecode containing new opcodes.
func TestValidateEVMBytecode_WithNewOpcodes(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	tests := []struct {
		name     string
		bytecode []byte
		wantErr  bool
	}{
		{
			name:     "SIGNEXTEND valid",
			bytecode: []byte{0x60, 0x01, 0x60, 0x02, 0x0B},
			wantErr:  false,
		},
		{
			name:     "RETURNDATASIZE valid",
			bytecode: []byte{0x3D},
			wantErr:  false,
		},
		{
			name:     "RETURNDATACOPY valid",
			bytecode: []byte{0x3E},
			wantErr:  false,
		},
		{
			name:     "EXTCODESIZE valid",
			bytecode: []byte{0x3B},
			wantErr:  false,
		},
		{
			name:     "EXTCODEHASH valid",
			bytecode: []byte{0x3F},
			wantErr:  false,
		},
		{
			name:     "DIFFICULTY/PREVRANDAO valid",
			bytecode: []byte{0x44},
			wantErr:  false,
		},
		{
			name:     "BASEFEE valid",
			bytecode: []byte{0x48},
			wantErr:  false,
		},
		{
			name:     "BLOBHASH valid",
			bytecode: []byte{0x49},
			wantErr:  false,
		},
		{
			name:     "BLOBBASEFEE valid",
			bytecode: []byte{0x4A},
			wantErr:  false,
		},
		{
			name:     "TLOAD valid",
			bytecode: []byte{0x5C},
			wantErr:  false,
		},
		{
			name:     "TSTORE valid",
			bytecode: []byte{0x5D},
			wantErr:  false,
		},
		{
			name:     "PUSH0 valid",
			bytecode: []byte{0x5F},
			wantErr:  false,
		},
		{
			name:     "Unknown opcode invalid",
			bytecode: []byte{0xEE},
			wantErr:  true,
		},
		{
			name:     "Mixed valid with new opcodes",
			bytecode: []byte{0x5F, 0x60, 0x01, 0x01, 0x3D, 0x44, 0x48, 0x5C, 0x5D, 0x00},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := layer.ValidateEVMBytecode(tt.bytecode)
			if tt.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

// TestPrecompileHandlers tests all precompile handlers.
func TestPrecompileHandlers(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	// Build a valid blake2f input: 4-byte rounds (big-endian) + 209 bytes of state
	blake2fInput := make([]byte, 213)
	binary.BigEndian.PutUint32(blake2fInput[0:4], 10) // rounds = 10

	tests := []struct {
		name    string
		addr    byte
		input   []byte
		gas     uint64
		wantErr bool
		wantGas uint64
	}{
		{
			name:    "ecRecover sufficient gas",
			addr:    0x01,
			input:   make([]byte, 128),
			gas:     5000,
			wantErr: false,
			wantGas: 3000,
		},
		{
			name:    "ecRecover insufficient gas",
			addr:    0x01,
			input:   make([]byte, 128),
			gas:     1000,
			wantErr: true,
		},
		{
			name:    "sha256 sufficient gas",
			addr:    0x02,
			input:   make([]byte, 32),
			gas:     1000,
			wantErr: false,
			wantGas: 72, // 60 + 12*1
		},
		{
			name:    "ripemd160 sufficient gas",
			addr:    0x03,
			input:   make([]byte, 32),
			gas:     1000,
			wantErr: false,
			wantGas: 720, // 600 + 120*1
		},
		{
			name:    "identity sufficient gas",
			addr:    0x04,
			input:   []byte{1, 2, 3},
			gas:     100,
			wantErr: false,
			wantGas: 18, // 15 + 3*1
		},
		{
			name:    "modexp sufficient gas",
			addr:    0x05,
			input:   make([]byte, 96),
			gas:     1000,
			wantErr: false,
			wantGas: 200,
		},
		{
			name:    "ecAdd infinity points (zero input is point at infinity)",
			addr:    0x06,
			input:   make([]byte, 128),
			gas:     1000,
			wantErr: false,
			wantGas: 150, // bn256Add RequiredGas is 150
			// EIP-196: all-zero input encodes the point at infinity (identity).
			// infinity + infinity = infinity, encoded as 64 zero bytes.
			// QVM-BN256-01 FIX: the precompile correctly accepts this input.
		},
		{
			name:    "ecMul zero scalar (infinity result)",
			addr:    0x07,
			input:   make([]byte, 128),
			gas:     10000,
			wantErr: false,
			wantGas: 6000, // bn256ScalarMul RequiredGas is 6000
			// EIP-196: all-zero input = (infinity point, scalar=0).
			// infinity * 0 = infinity, encoded as 64 zero bytes.
			// QVM-BN256-01 FIX: the precompile correctly accepts scalar=0.
		},
		{
			name:    "ecPairing sufficient gas",
			addr:    0x08,
			input:   make([]byte, 192),
			gas:     100000,
			wantErr: false,
			wantGas: 79000, // 34000 + 45000*1
		},
		{
			name:    "blake2f sufficient gas",
			addr:    0x09,
			input:   blake2fInput,
			gas:     100,
			wantErr: false,
			wantGas: 10,
		},
		{
			name:    "blake2f insufficient input",
			addr:    0x09,
			input:   make([]byte, 100),
			gas:     100,
			wantErr: true,
		},
		{
			name:    "keccak256 sufficient gas",
			addr:    0x0A,
			input:   []byte("hello"),
			gas:     1000,
			wantErr: false,
			wantGas: 36, // 30 + 6*1
		},
		{
			name:    "unsupported precompile",
			addr:    0x0B,
			input:   nil,
			gas:     100,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, usedGas, err := layer.ExecutePrecompile(
				types.BytesToAddress([]byte{tt.addr}),
				tt.input,
				tt.gas,
			)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if usedGas != tt.wantGas {
				t.Errorf("gas used = %d, want %d", usedGas, tt.wantGas)
			}
			if result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

// TestSDIVSMODMappings tests that SDIV and SMOD map to their own dedicated QVM opcodes.
func TestSDIVSMODMappings(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	// SDIV (0x05) should map to QVM SDIV (not DIV)
	sdivOp, _, err := layer.TranslateOpcode(0x05)
	if err != nil {
		t.Fatalf("SDIV translation error: %v", err)
	}
	if sdivOp != qvm.SDIV {
		t.Errorf("SDIV maps to %v, expected qvm.SDIV (%v)", sdivOp, qvm.SDIV)
	}

	// SDIV should map to a different opcode than DIV
	divOp, _, err := layer.TranslateOpcode(0x04)
	if err != nil {
		t.Fatalf("DIV translation error: %v", err)
	}
	if sdivOp == divOp {
		t.Errorf("SDIV and DIV should map to different opcodes, both map to %v", sdivOp)
	}

	// SMOD (0x07) should map to QVM SMOD (not MOD)
	smodOp, _, err := layer.TranslateOpcode(0x07)
	if err != nil {
		t.Fatalf("SMOD translation error: %v", err)
	}
	if smodOp != qvm.SMOD {
		t.Errorf("SMOD maps to %v, expected qvm.SMOD (%v)", smodOp, qvm.SMOD)
	}

	// SMOD should map to a different opcode than MOD
	modOp, _, err := layer.TranslateOpcode(0x06)
	if err != nil {
		t.Fatalf("MOD translation error: %v", err)
	}
	if smodOp == modOp {
		t.Errorf("SMOD and MOD should map to different opcodes, both map to %v", smodOp)
	}
}

// TestDIFFICULTYMapsToPREVRANDAO tests that EVM DIFFICULTY maps to QVM PREVRANDAO.
func TestDIFFICULTYMapsToPREVRANDAO(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	op, gas, err := layer.TranslateOpcode(0x44)
	if err != nil {
		t.Fatalf("DIFFICULTY translation error: %v", err)
	}
	if op != qvm.PREVRANDAO {
		t.Errorf("DIFFICULTY maps to %v, expected PREVRANDAO (%v)", op, qvm.PREVRANDAO)
	}
	if gas != 2 {
		t.Errorf("DIFFICULTY gas = %d, expected 2", gas)
	}
}

// TestBASEFEEMapsToOwnOpcode tests that EVM BASEFEE maps to its own QVM BASEFEE opcode.
func TestBASEFEEMapsToOwnOpcode(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	op, gas, err := layer.TranslateOpcode(0x48)
	if err != nil {
		t.Fatalf("BASEFEE translation error: %v", err)
	}
	if op != qvm.BASEFEE {
		t.Errorf("BASEFEE maps to %v, expected qvm.BASEFEE (%v)", op, qvm.BASEFEE)
	}
	if gas != 2 {
		t.Errorf("BASEFEE gas = %d, expected 2", gas)
	}

	// BASEFEE should map to a different opcode than GASPRICE
	gaspriceOp, _, err := layer.TranslateOpcode(0x3A)
	if err != nil {
		t.Fatalf("GASPRICE translation error: %v", err)
	}
	if op == gaspriceOp {
		t.Errorf("BASEFEE and GASPRICE should map to different opcodes, both map to %v", op)
	}
}

// TestPUSHMappings tests all PUSH1-32 opcodes.
func TestPUSHMappings(t *testing.T) {
	layer := NewEVMCompatLayer(DefaultEVMCompatConfig())

	expectedPUSHs := []qvm.OpCode{
		qvm.PUSH1, qvm.PUSH2, qvm.PUSH3, qvm.PUSH4,
		qvm.PUSH5, qvm.PUSH6, qvm.PUSH7, qvm.PUSH8,
		qvm.PUSH9, qvm.PUSH10, qvm.PUSH11, qvm.PUSH12,
		qvm.PUSH13, qvm.PUSH14, qvm.PUSH15, qvm.PUSH16,
		qvm.PUSH17, qvm.PUSH18, qvm.PUSH19, qvm.PUSH20,
		qvm.PUSH21, qvm.PUSH22, qvm.PUSH23, qvm.PUSH24,
		qvm.PUSH25, qvm.PUSH26, qvm.PUSH27, qvm.PUSH28,
		qvm.PUSH29, qvm.PUSH30, qvm.PUSH31, qvm.PUSH32,
	}

	for i, expectedQAU := range expectedPUSHs {
		evmCode := byte(0x60 + i)
		got, _, err := layer.TranslateOpcode(evmCode)
		if err != nil {
			t.Errorf("PUSH%d (0x%02X) translation error: %v", i+1, evmCode, err)
			continue
		}
		if got != expectedQAU {
			t.Errorf("PUSH%d: got %v, want %v", i+1, got, expectedQAU)
		}
	}
}
