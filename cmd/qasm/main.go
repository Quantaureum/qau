// Quantaureum Node source, version 1.0.0.
// Package main implements the QASM assembler for the Quantaureum Virtual Machine.
// QASM is the native assembly language for QVM — it uses QVM's own opcode
// numbering system, NOT the EVM opcode set.
//
// Usage:
//
//	qasm assemble <input.qasm> <output.hex>   # Assemble source to hex bytecode
//	qasm disassemble <input.hex>              # Disassemble hex bytecode to QASM
//	qasm list                                  # List all QVM opcodes
package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/quantaureum/qau/qvm"
)

// opcodeMap maps mnemonic strings to QVM opcodes.
var opcodeMap = map[string]qvm.OpCode{
	// Control Flow
	"STOP": qvm.STOP, "JUMP": qvm.JUMP, "JUMPI": qvm.JUMPI,
	"JUMPDEST": qvm.JUMPDEST, "PC": qvm.PC, "NOP": qvm.NOP,
	"RETURN": qvm.RETURN, "REVERT": qvm.REVERT, "INVALID": qvm.INVALID,

	// Stack Operations
	"PUSH1": qvm.PUSH1, "PUSH2": qvm.PUSH2, "PUSH4": qvm.PUSH4,
	"PUSH8": qvm.PUSH8, "PUSH16": qvm.PUSH16, "PUSH32": qvm.PUSH32,
	"POP":  qvm.POP,
	"DUP1": qvm.DUP1, "DUP2": qvm.DUP2, "DUP3": qvm.DUP3,
	"DUP4": qvm.DUP4, "DUP5": qvm.DUP5, "DUP6": qvm.DUP6,
	"DUP7": qvm.DUP7, "DUP8": qvm.DUP8, "DUP9": qvm.DUP9,
	"DUP10": qvm.DUP10, "DUP11": qvm.DUP11, "DUP12": qvm.DUP12,
	"DUP13": qvm.DUP13, "DUP14": qvm.DUP14, "DUP15": qvm.DUP15,
	"DUP16": qvm.DUP16,
	"SWAP1": qvm.SWAP1, "SWAP2": qvm.SWAP2, "SWAP3": qvm.SWAP3,
	"SWAP4": qvm.SWAP4, "SWAP5": qvm.SWAP5, "SWAP6": qvm.SWAP6,
	"SWAP7": qvm.SWAP7, "SWAP8": qvm.SWAP8, "SWAP9": qvm.SWAP9,
	"SWAP10": qvm.SWAP10, "SWAP11": qvm.SWAP11, "SWAP12": qvm.SWAP12,
	"SWAP13": qvm.SWAP13, "SWAP14": qvm.SWAP14, "SWAP15": qvm.SWAP15,
	"SWAP16": qvm.SWAP16,

	// Arithmetic
	"ADD": qvm.ADD, "SUB": qvm.SUB, "MUL": qvm.MUL, "DIV": qvm.DIV,
	"MOD": qvm.MOD, "ADDMOD": qvm.ADDMOD, "MULMOD": qvm.MULMOD, "EXP": qvm.EXP,

	// Comparison
	"LT": qvm.LT, "GT": qvm.GT, "SLT": qvm.SLT, "SGT": qvm.SGT,
	"EQ": qvm.EQ, "ISZERO": qvm.ISZERO,

	// Bitwise
	"AND": qvm.AND, "OR": qvm.OR, "XOR": qvm.XOR, "NOT": qvm.NOT,
	"SHL": qvm.SHL, "SHR": qvm.SHR, "SAR": qvm.SAR, "BYTE": qvm.BYTE,

	// Memory
	"MLOAD": qvm.MLOAD, "MSTORE": qvm.MSTORE, "MSTORE8": qvm.MSTORE8,
	"MSIZE": qvm.MSIZE, "MCOPY": qvm.MCOPY,

	// Storage
	"SLOAD": qvm.SLOAD, "SSTORE": qvm.SSTORE,

	// Context
	"ADDRESS": qvm.ADDRESS, "BALANCE": qvm.BALANCE, "ORIGIN": qvm.ORIGIN,
	"CALLER": qvm.CALLER, "CALLVALUE": qvm.CALLVALUE,
	"CALLDATALOAD": qvm.CALLDATALOAD, "CALLDATASIZE": qvm.CALLDATASIZE,
	"CALLDATACOPY": qvm.CALLDATACOPY,
	"CODESIZE":     qvm.CODESIZE, "CODECOPY": qvm.CODECOPY,
	"GASPRICE": qvm.GASPRICE, "GASLIMIT": qvm.GASLIMIT, "GAS": qvm.GAS,
	"BLOCKHASH": qvm.BLOCKHASH, "COINBASE": qvm.COINBASE, "TIMESTAMP": qvm.TIMESTAMP,
	"NUMBER": qvm.NUMBER, "CHAINID": qvm.CHAINID, "SELFBALANCE": qvm.SELFBALANCE,

	// Crypto
	"SHA3": qvm.SHA3, "KECCAK256": qvm.KECCAK256,

	// Post-Quantum Crypto
	"KYBER_KEYGEN": qvm.KYBER_KEYGEN, "KYBER_ENCAPS": qvm.KYBER_ENCAPS,
	"KYBER_DECAPS": qvm.KYBER_DECAPS,

	// Call
	"CALL": qvm.CALL, "CALLCODE": qvm.CALLCODE,
	"DELEGATECALL": qvm.DELEGATECALL, "STATICCALL": qvm.STATICCALL,
	"CREATE": qvm.CREATE, "CREATE2": qvm.CREATE2,

	// Return Data
	"RETURNDATASIZE": qvm.RETURNDATASIZE, "RETURNDATACOPY": qvm.RETURNDATACOPY,

	// Log
	"LOG0": qvm.LOG0, "LOG1": qvm.LOG1, "LOG2": qvm.LOG2,
	"LOG3": qvm.LOG3, "LOG4": qvm.LOG4,

	// System
	"SELFDESTRUCT": qvm.SELFDESTRUCT,
}

// Assembler converts QASM source to QVM bytecode.
type Assembler struct {
	labels       map[string]uint64 // label -> offset (absolute in output)
	fixups       []fixup           // pending label references
	output       []byte            // assembled bytecode
	lineno       int               // current line number
	pass         int               // 1 = collect labels, 2 = generate code
	sections     map[string][]byte // .init and .code sections
	curSection   string            // current section name
	codeStartOff int               // byte offset where .code section begins
	strict       bool              // QVM- strict mode upgrades warnings to errors
}

type fixup struct {
	offset   uint64 // byte offset in output where the address goes
	label    string // label to resolve (or start label for difference)
	labelEnd string // if non-empty, resolve as labelEnd - label (difference)
	size     int    // 1, 2, or 4 bytes for the address
	lineno   int    // source line for error reporting
	section  string // which section this fixup is in ("init" or "code")
}

func newAssembler() *Assembler {
	return &Assembler{
		labels:     make(map[string]uint64),
		fixups:     nil,
		output:     nil,
		sections:   make(map[string][]byte),
		curSection: "code", // default section
	}
}

// Assemble converts QASM source text to QVM bytecode.
func (a *Assembler) Assemble(src string) ([]byte, error) {
	lines := strings.Split(src, "\n")

	// Pass 1: collect labels and calculate offsets
	a.pass = 1
	a.output = nil
	a.labels = nil
	a.labels = make(map[string]uint64)
	a.fixups = nil
	for i, line := range lines {
		a.lineno = i + 1
		if err := a.processLine(line); err != nil {
			return nil, fmt.Errorf("line %d: %w", a.lineno, err)
		}
	}

	// Pass 2: generate code with resolved labels
	a.pass = 2
	a.output = nil
	a.fixups = nil
	for i, line := range lines {
		a.lineno = i + 1
		if err := a.processLine(line); err != nil {
			return nil, fmt.Errorf("line %d: %w", a.lineno, err)
		}
	}

	// Resolve fixups
	for _, f := range a.fixups {
		addrStart, ok := a.labels[f.label]
		if !ok {
			return nil, fmt.Errorf("line %d: undefined label '%s'", f.lineno, f.label)
		}
		var val uint64
		if f.labelEnd != "" {
			// Difference expression: @end - @start
			// For size calculations (e.g., runtime_end - runtime_start), use absolute offsets
			// since both labels are in the same section and the difference is the same.
			addrEnd, ok := a.labels[f.labelEnd]
			if !ok {
				return nil, fmt.Errorf("line %d: undefined label '%s'", f.lineno, f.labelEnd)
			}
			if addrEnd < addrStart {
				return nil, fmt.Errorf("line %d: negative label difference (@%s=0x%x < @%s=0x%x)", f.lineno, f.labelEnd, addrEnd, f.label, addrStart)
			}
			val = addrEnd - addrStart
		} else {
			val = addrStart
			// If this fixup is in the .code section and the label is also in .code,
			// adjust the offset to be relative to the start of the .code section.
			// When the runtime code is deployed, PC starts at 0, so jump targets
			// must be relative to the runtime code start, not the full bytecode.
			if f.section == "code" && a.codeStartOff > 0 {
				if val < uint64(a.codeStartOff) {
					return nil, fmt.Errorf("line %d: .code section references label '%s' at offset 0x%x which is before .code start 0x%x", f.lineno, f.label, val, a.codeStartOff)
				}
				val -= uint64(a.codeStartOff)
			}
		}
		switch f.size {
		case 1:
			if val > 0xFF {
				return nil, fmt.Errorf("line %d: value 0x%x too large for 1-byte reference", f.lineno, val)
			}
			a.output[f.offset] = byte(val)
		case 2:
			if val > 0xFFFF {
				return nil, fmt.Errorf("line %d: value 0x%x too large for 2-byte reference", f.lineno, val)
			}
			a.output[f.offset] = byte(val >> 8)
			a.output[f.offset+1] = byte(val)
		case 4:
			a.output[f.offset] = byte(val >> 24)
			a.output[f.offset+1] = byte(val >> 16)
			a.output[f.offset+2] = byte(val >> 8)
			a.output[f.offset+3] = byte(val)
		}
	}

	// FIX: Validate the assembled bytecode before returning.
	// This catches malformed contracts that would silently fail at runtime.
	if err := a.validateOutput(); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	return a.output, nil
}

// validateOutput performs basic validation on the assembled bytecode.
// FIX: Ensures the assembled code is well-formed and won't
// silently fail at runtime due to invalid opcode sequences.
// validateOutput performs basic validation on the assembled bytecode.
// //FIX: Validates PUSH instruction integrity AND
// checks for the function dispatcher pattern at the start of the .code section.
func (a *Assembler) validateOutput() error {
	if len(a.output) == 0 {
		return nil
	}

	// Phase 1: Walk through the code validating PUSH instruction sizes
	i := 0
	for i < len(a.output) {
		op := qvm.OpCode(a.output[i])
		info, ok := op.GetInfo()
		if !ok {
			i++
			continue
		}
		if op.IsPush() && info.ImmediateSize > 0 {
			if i+1+info.ImmediateSize > len(a.output) {
				return fmt.Errorf("truncated PUSH at offset %d: needs %d bytes but only %d remain",
					i, info.ImmediateSize, len(a.output)-i-1)
			}
			i += 1 + info.ImmediateSize
		} else {
			i++
		}
	}

	// Phase 2: FIX - Validate function dispatcher pattern.
	// The .code section (runtime code) should start with a function dispatcher
	// that extracts the 4-byte function selector:
	//   PUSH1 0x00      CALLDATALOAD    PUSH1 0xe0      SHR   PUSH4 0xffffffff  AND
	//   [0x10, 0x00,    0x75,           0x10, 0xe0,     0x45, 0x12, 0xff,0xff,0xff,0xff, 0x40]
	// This is a WARNING, not an error - some contracts (constructors, utilities)
	// may legitimately not need a dispatcher.
	dispatcherPattern := []byte{
		byte(qvm.PUSH1), 0x00, // PUSH1 0x00 (offset)
		byte(qvm.CALLDATALOAD), // CALLDATALOAD
		byte(qvm.PUSH1), 0xe0,  // PUSH1 0xe0 (224 bits = 28 bytes)
		byte(qvm.SHR),                           // SHR
		byte(qvm.PUSH4), 0xff, 0xff, 0xff, 0xff, // PUSH4 0xffffffff
		byte(qvm.AND), // AND
	}

	// Determine where the .code section starts
	codeStart := 0
	if a.codeStartOff > 0 {
		codeStart = a.codeStartOff
	}

	// Only check if there's enough bytes for the dispatcher
	if len(a.output)-codeStart >= len(dispatcherPattern) {
		matches := true
		for j, b := range dispatcherPattern {
			if a.output[codeStart+j] != b {
				matches = false
				break
			}
		}
		if !matches {
			//  Warn about missing dispatcher pattern.
			// This is a warning, not an error, to allow non-standard contracts.
			// QVM-FIX: In strict mode (--strict flag), upgrade this warning
			// to an error to catch developer mistakes early.
			msg := "Runtime code does not start with the standard function dispatcher pattern\n" +
				"(PUSH1 0x00 CALLDATALOAD PUSH1 0xe0 SHR PUSH4 0xffffffff AND).\n" +
				"Contracts without a dispatcher will have all function calls silently fail at runtime.\n" +
				"If this is intentional (e.g., constructor code), this warning can be ignored.\n"
			if a.strict {
				return fmt.Errorf("strict mode: %s", msg)
			}
			fmt.Fprintf(os.Stderr, "WARNING: %s", msg)
		}
	}

	return nil
}

func (a *Assembler) processLine(line string) error {
	// Strip comments
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = line[:idx]
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	// Handle labels
	if strings.HasSuffix(line, ":") {
		label := strings.TrimSuffix(line, ":")
		a.labels[label] = uint64(len(a.output))
		return nil
	}

	// Handle directives
	if strings.HasPrefix(line, ".") {
		return a.processDirective(line)
	}

	// Handle instructions
	return a.processInstruction(line)
}

func (a *Assembler) processDirective(line string) error {
	parts := strings.Fields(line)
	directive := strings.ToUpper(parts[0])

	switch directive {
	case ".INIT":
		a.curSection = "init"
		return nil
	case ".CODE":
		a.curSection = "code"
		a.codeStartOff = len(a.output) // record where .code section begins
		return nil
	case ".BYTE":
		// .byte 0x12 0x34 0x56
		for _, arg := range parts[1:] {
			b, err := parseByte(arg)
			if err != nil {
				return fmt.Errorf(".byte: %w", err)
			}
			a.output = append(a.output, b)
		}
		return nil
	case ".WORD":
		// .word 0x1234 (2 bytes, big-endian)
		for _, arg := range parts[1:] {
			val, err := parseUint(arg, 16)
			if err != nil {
				return fmt.Errorf(".word: %w", err)
			}
			a.output = append(a.output, byte(val>>8), byte(val))
		}
		return nil
	case ".DWORD":
		// .dword 0x12345678 (4 bytes, big-endian)
		for _, arg := range parts[1:] {
			val, err := parseUint(arg, 32)
			if err != nil {
				return fmt.Errorf(".dword: %w", err)
			}
			a.output = append(a.output, byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
		}
		return nil
	case ".QWORD":
		// .qword 0x... (8 bytes, big-endian)
		for _, arg := range parts[1:] {
			val, err := parseUint(arg, 64)
			if err != nil {
				return fmt.Errorf(".qword: %w", err)
			}
			for i := 7; i >= 0; i-- {
				a.output = append(a.output, byte(val>>(i*8)))
			}
		}
		return nil
	case ".HEX":
		// .hex 610140604052 (raw hex bytes)
		if len(parts) < 2 {
			return fmt.Errorf(".hex requires hex data")
		}
		hexStr := strings.Join(parts[1:], "")
		data, err := hex.DecodeString(hexStr)
		if err != nil {
			return fmt.Errorf(".hex: %w", err)
		}
		a.output = append(a.output, data...)
		return nil
	case ".PAD":
		// .pad 32 (fill with zeros)
		if len(parts) < 2 {
			return fmt.Errorf(".pad requires count")
		}
		count, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf(".pad: %w", err)
		}
		// V21-009 FIX: Enforce upper limit to prevent excessive memory allocation
		if count > 65536 {
			return fmt.Errorf(".pad count %d exceeds maximum 65536", count)
		}
		// V21-010 FIX: Reject negative count
		if count < 0 {
			return fmt.Errorf(".pad count must be non-negative, got %d", count)
		}
		for i := 0; i < count; i++ {
			a.output = append(a.output, 0)
		}
		return nil
	default:
		return fmt.Errorf("unknown directive: %s", parts[0])
	}
}

func (a *Assembler) processInstruction(line string) error {
	parts := strings.Fields(line)
	mnemonic := strings.ToUpper(parts[0])

	op, ok := opcodeMap[mnemonic]
	if !ok {
		return fmt.Errorf("unknown mnemonic: %s", parts[0])
	}

	// PUSH instructions have immediate data
	if op.IsPush() {
		a.output = append(a.output, byte(op))
		if len(parts) < 2 {
			return fmt.Errorf("%s requires immediate data", mnemonic)
		}

		immediate := parts[1]
		pushSize := op.PushSize()

		// Check if it's a label reference (e.g., PUSH2 @loop or PUSH2 @end-@start)
		if strings.HasPrefix(immediate, "@") {
			labelStart, labelEnd := parseLabelExpr(immediate[1:])
			if a.pass == 1 {
				// In pass 1, emit placeholder bytes
				for i := 0; i < pushSize; i++ {
					a.output = append(a.output, 0)
				}
			} else {
				// In pass 2, add fixup
				offset := uint64(len(a.output))
				for i := 0; i < pushSize; i++ {
					a.output = append(a.output, 0)
				}
				a.fixups = append(a.fixups, fixup{
					offset:   offset,
					label:    labelStart,
					labelEnd: labelEnd,
					size:     pushSize,
					lineno:   a.lineno,
					section:  a.curSection,
				})
			}
			return nil
		}

		// Parse the immediate value
		data, err := parseImmediate(immediate, pushSize)
		if err != nil {
			return fmt.Errorf("%s: %w", mnemonic, err)
		}
		a.output = append(a.output, data...)
		return nil
	}

	// JUMP and JUMPI with label arguments need a PUSH before the opcode
	if (op == qvm.JUMP || op == qvm.JUMPI) && len(parts) >= 2 && strings.HasPrefix(parts[1], "@") {
		labelName := parts[1][1:] // strip @
		// Emit PUSH2 <label_offset> before the JUMP/JUMPI opcode
		a.output = append(a.output, byte(qvm.PUSH2))
		if a.pass == 1 {
			// In pass 1, emit placeholder bytes for the offset
			a.output = append(a.output, 0, 0)
		} else {
			// In pass 2, add fixup for the label
			offset := uint64(len(a.output))
			a.output = append(a.output, 0, 0) // placeholder
			a.fixups = append(a.fixups, fixup{
				offset:  offset,
				label:   labelName,
				size:    2,
				lineno:  a.lineno,
				section: a.curSection,
			})
		}
		// Now emit the JUMP/JUMPI opcode
		a.output = append(a.output, byte(op))
		return nil
	}

	// All other instructions: just emit the opcode byte
	a.output = append(a.output, byte(op))
	return nil
}

// parseLabelExpr parses a label expression: "label" or "labelEnd-labelStart".
// Returns (startLabel, endLabel). If no difference, endLabel is empty.
func parseLabelExpr(expr string) (string, string) {
	if idx := strings.Index(expr, "-@"); idx >= 0 {
		return expr[idx+2:], expr[:idx] // start=label after -@, end=label before -@
	}
	return expr, ""
}

// parseImmediate parses an immediate value and returns exactly `size` bytes (big-endian).
// Supports arbitrary precision using math/big for PUSH16/PUSH32.
func parseImmediate(s string, size int) ([]byte, error) {
	var val big.Int

	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		hexStr := s[2:]
		if len(hexStr) == 0 {
			return nil, fmt.Errorf("empty hex value")
		}
		_, ok := val.SetString(hexStr, 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex value: %s", s)
		}
	} else {
		_, ok := val.SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("invalid decimal value: %s", s)
		}
	}

	// Check if value fits in `size` bytes
	if val.Sign() >= 0 {
		byteLen := (val.BitLen() + 7) / 8
		if byteLen > size {
			return nil, fmt.Errorf("value too large for %d-byte push (needs %d bytes)", size, byteLen)
		}
	} else {
		// Negative values are encoded as two's complement and must fit in
		// the signed range [-2^(size*8-1), -1].
		var minSigned big.Int
		minSigned.Lsh(big.NewInt(1), uint(size*8-1))
		minSigned.Neg(&minSigned)
		if val.Cmp(&minSigned) < 0 {
			return nil, fmt.Errorf("value too small for %d-byte signed push (min %s)", size, minSigned.String())
		}
	}

	result := make([]byte, size)
	if val.Sign() < 0 {
		// val.Bytes() returns the absolute value, losing the sign. Encode
		// negatives as two's complement: 2^(size*8) + val (val is negative).
		var modulus big.Int
		modulus.Lsh(big.NewInt(1), uint(size*8))
		var twos big.Int
		twos.Add(&val, &modulus)
		bytes := twos.Bytes()
		copy(result[size-len(bytes):], bytes)
	} else {
		bytes := val.Bytes()
		copy(result[size-len(bytes):], bytes)
	}

	return result, nil
}

func parseByte(s string) (byte, error) {
	v, err := parseUint(s, 8)
	if err != nil {
		return 0, err
	}
	return byte(v), nil
}

func parseUint(s string, bitSize int) (uint64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, bitSize)
	}
	return strconv.ParseUint(s, 10, bitSize)
}

// Disassemble converts QVM bytecode to QASM source.
func disassemble(code []byte) string {
	var sb strings.Builder
	i := 0
	for i < len(code) {
		op := qvm.OpCode(code[i])
		info, ok := op.GetInfo()
		if !ok {
			sb.WriteString(fmt.Sprintf("    0x%02x  // UNKNOWN\n", code[i]))
			i++
			continue
		}

		if op.IsPush() && info.ImmediateSize > 0 {
			start := i + 1
			end := start + info.ImmediateSize
			if end > len(code) {
				sb.WriteString(fmt.Sprintf("    %s  // TRUNCATED\n", info.Name))
				break
			}
			imm := code[start:end]
			sb.WriteString(fmt.Sprintf("    %s 0x%s\n", info.Name, hex.EncodeToString(imm)))
			i = end
		} else {
			sb.WriteString(fmt.Sprintf("    %s\n", info.Name))
			i++
		}
	}
	return sb.String()
}

func listOpcodes() {
	fmt.Println("QVM Instruction Set (Quantaureum Virtual Machine)")
	fmt.Println("=" + strings.Repeat("=", 70))
	fmt.Printf("%-14s %-6s %-12s %-8s %-8s %-8s %s\n",
		"MNEMONIC", "OPCODE", "CATEGORY", "STACKPOP", "STACKPUSH", "GASCOST", "IMMEDIATE")
	fmt.Println(strings.Repeat("-", 80))

	// Group by category
	categories := []struct {
		name    string
		opcodes []string
	}{
		{"Control Flow", []string{"STOP", "JUMP", "JUMPI", "JUMPDEST", "PC", "NOP", "RETURN", "REVERT", "INVALID"}},
		{"Stack", []string{"PUSH1", "PUSH2", "PUSH4", "PUSH8", "PUSH16", "PUSH32", "POP",
			"DUP1", "DUP2", "DUP3", "DUP4", "DUP5", "DUP6", "DUP7", "DUP8",
			"DUP9", "DUP10", "DUP11", "DUP12", "DUP13", "DUP14", "DUP15", "DUP16",
			"SWAP1", "SWAP2", "SWAP3", "SWAP4", "SWAP5", "SWAP6", "SWAP7", "SWAP8",
			"SWAP9", "SWAP10", "SWAP11", "SWAP12", "SWAP13", "SWAP14", "SWAP15", "SWAP16"}},
		{"Arithmetic", []string{"ADD", "SUB", "MUL", "DIV", "MOD", "ADDMOD", "MULMOD", "EXP"}},
		{"Comparison", []string{"LT", "GT", "SLT", "SGT", "EQ", "ISZERO"}},
		{"Bitwise", []string{"AND", "OR", "XOR", "NOT", "SHL", "SHR", "SAR", "BYTE"}},
		{"Memory", []string{"MLOAD", "MSTORE", "MSTORE8", "MSIZE", "MCOPY"}},
		{"Storage", []string{"SLOAD", "SSTORE"}},
		{"Context", []string{"ADDRESS", "BALANCE", "ORIGIN", "CALLER", "CALLVALUE",
			"CALLDATALOAD", "CALLDATASIZE", "CALLDATACOPY",
			"CODESIZE", "CODECOPY", "GASPRICE", "GASLIMIT", "GAS",
			"BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER", "CHAINID", "SELFBALANCE"}},
		{"Crypto", []string{"SHA3", "KECCAK256"}},
		{"Post-Quantum", []string{"KYBER_KEYGEN", "KYBER_ENCAPS", "KYBER_DECAPS"}},
		{"Call", []string{"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"}},
		{"Return Data", []string{"RETURNDATASIZE", "RETURNDATACOPY"}},
		{"Log", []string{"LOG0", "LOG1", "LOG2", "LOG3", "LOG4"}},
		{"System", []string{"SELFDESTRUCT"}},
	}

	for _, cat := range categories {
		fmt.Printf("\n[%s]\n", cat.name)
		for _, name := range cat.opcodes {
			op, ok := opcodeMap[name]
			if !ok {
				continue
			}
			info, _ := op.GetInfo()
			immStr := "-"
			if info.ImmediateSize > 0 {
				immStr = fmt.Sprintf("%d bytes", info.ImmediateSize)
			}
			fmt.Printf("  %-12s 0x%02x   %-12s %-8d %-8d %-8d %s\n",
				name, byte(op), cat.name, info.StackPop, info.StackPush, info.GasCost, immStr)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("QASM - Quantaureum Virtual Machine Assembler")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  qasm assemble [--strict] <input.qasm> [output.hex]  Assemble QASM to bytecode")
		fmt.Println("  qasm disassemble <input.hex>             Disassemble bytecode to QASM")
		fmt.Println("  qasm list                                 List all QVM opcodes")
		fmt.Println()
		fmt.Println("QASM uses QVM's native opcode numbering (NOT EVM compatible).")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "assemble", "asm":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qasm assemble [--strict] <input.qasm> [output.hex]")
			os.Exit(1)
		}
		// QVM-FIX: Parse --strict flag (upgrades dispatcher pattern
		// warning to error). Positional args after flag filtering are
		// input.qasm and optional output.hex.
		strictMode := false
		var posArgs []string
		for _, arg := range os.Args[2:] {
			if arg == "--strict" {
				strictMode = true
			} else {
				posArgs = append(posArgs, arg)
			}
		}
		if len(posArgs) < 1 {
			fmt.Println("Usage: qasm assemble [--strict] <input.qasm> [output.hex]")
			os.Exit(1)
		}
		src, err := os.ReadFile(posArgs[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", posArgs[0], err)
			os.Exit(1)
		}

		a := newAssembler()
		a.strict = strictMode
		code, err := a.Assemble(string(src))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Assembly error: %v\n", err)
			os.Exit(1)
		}

		hexOutput := "0x" + hex.EncodeToString(code)

		if len(posArgs) >= 2 {
			//nolint:gosec // G306: assembler bytecode output file; non-sensitive.
			if err := os.WriteFile(posArgs[1], []byte(hexOutput), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", posArgs[1], err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Assembled %d bytes to %s\n", len(code), posArgs[1])
		} else {
			fmt.Println(hexOutput)
		}

	case "disassemble", "dis":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qasm disassemble <hex_bytecode>")
			os.Exit(1)
		}
		hexStr := os.Args[2]
		hexStr = strings.TrimPrefix(hexStr, "0x")
		hexStr = strings.TrimPrefix(hexStr, "0X")
		code, err := hex.DecodeString(hexStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid hex: %v\n", err)
			os.Exit(1)
		}
		// QV-05 FIX: Enforce a maximum input size to prevent excessive memory/CPU
		// usage from very large inputs (e.g. accidental multi-GB hex strings).
		const maxDisasmSize = 10 * 1024 * 1024 // 10 MB
		if len(code) > maxDisasmSize {
			fmt.Fprintf(os.Stderr, "Input too large: %d bytes (max %d bytes)\n", len(code), maxDisasmSize)
			os.Exit(1)
		}
		fmt.Println(disassemble(code))

	case "list", "opcodes":
		listOpcodes()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
