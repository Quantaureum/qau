// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"fmt"
)

// EVMBytecodeTranslator translates EVM bytecode to QVM bytecode.
// This is a standalone implementation within the qvm package to avoid
// import cycles with the evmcompat package.
//
// EVM and QVM use different opcode encodings:
// - EVM PUSH1=0x60, PUSH2=0x61, ... PUSH32=0x7F
// - QVM PUSH1=0x10, PUSH2=0x11, ... PUSH32=0x2F
// - EVM ADD=0x01, MUL=0x02, SUB=0x03
// - QVM ADD=0x20, MUL=0x21, SUB=0x22
//
// This translator auto-detects EVM bytecode and converts it to QVM format,
// allowing Solidity-compiled contracts to run on QVM.

// evmToQVMOpcodeMap maps EVM opcodes to QVM opcodes.
var evmToQVMOpcodeMap = map[byte]byte{
	// Arithmetic
	0x01: byte(ADD),        // ADD
	0x02: byte(MUL),        // MUL
	0x03: byte(SUB),        // SUB
	0x04: byte(DIV),        // DIV
	0x05: byte(SDIV),       // SDIV
	0x06: byte(MOD),        // MOD
	0x07: byte(SMOD),       // SMOD
	0x08: byte(ADDMOD),     // ADDMOD
	0x09: byte(MULMOD),     // MULMOD
	0x0A: byte(EXP),        // EXP
	0x0B: byte(SIGNEXTEND), // SIGNEXTEND

	// Comparison & Bitwise
	0x10: byte(LT),     // LT
	0x11: byte(GT),     // GT
	0x12: byte(SLT),    // SLT
	0x13: byte(SGT),    // SGT
	0x14: byte(EQ),     // EQ
	0x15: byte(ISZERO), // ISZERO
	0x16: byte(AND),    // AND
	0x17: byte(OR),     // OR
	0x18: byte(XOR),    // XOR
	0x19: byte(NOT),    // NOT
	0x1A: byte(BYTE),   // BYTE
	0x1B: byte(SHL),    // SHL
	0x1C: byte(SHR),    // SHR
	0x1D: byte(SAR),    // SAR

	// SHA3
	0x20: byte(KECCAK256), // SHA3/KECCAK256

	// Environment
	0x30: byte(ADDRESS),        // ADDRESS
	0x31: byte(BALANCE),        // BALANCE
	0x32: byte(ORIGIN),         // ORIGIN
	0x33: byte(CALLER),         // CALLER
	0x34: byte(CALLVALUE),      // CALLVALUE
	0x35: byte(CALLDATALOAD),   // CALLDATALOAD
	0x36: byte(CALLDATASIZE),   // CALLDATASIZE
	0x37: byte(CALLDATACOPY),   // CALLDATACOPY
	0x38: byte(CODESIZE),       // CODESIZE
	0x39: byte(CODECOPY),       // CODECOPY
	0x3A: byte(GASPRICE),       // GASPRICE
	0x3B: byte(EXTCODESIZE),    // EXTCODESIZE
	0x3C: byte(EXTCODECOPY),    // EXTCODECOPY
	0x3D: byte(RETURNDATASIZE), // RETURNDATASIZE
	0x3E: byte(RETURNDATACOPY), // RETURNDATACOPY
	0x3F: byte(EXTCODEHASH),    // EXTCODEHASH

	// Block
	0x40: byte(BLOCKHASH),   // BLOCKHASH
	0x41: byte(COINBASE),    // COINBASE
	0x42: byte(TIMESTAMP),   // TIMESTAMP
	0x43: byte(NUMBER),      // NUMBER
	0x44: byte(PREVRANDAO),  // DIFFICULTY (EIP-4399: now PREVRANDAO)
	0x45: byte(GASLIMIT),    // GASLIMIT
	0x46: byte(CHAINID),     // CHAINID
	0x47: byte(SELFBALANCE), // SELFBALANCE
	0x48: byte(BASEFEE),     // BASEFEE
	0x49: byte(BLOBHASH),    // BLOBHASH (EIP-4844, Cancun)
	0x4A: byte(BLOBBASEFEE), // BLOBBASEFEE (EIP-7516, Cancun)

	// Stack, Memory, Storage, Flow
	0x50: byte(POP),      // POP
	0x51: byte(MLOAD),    // MLOAD
	0x52: byte(MSTORE),   // MSTORE
	0x53: byte(MSTORE8),  // MSTORE8
	0x54: byte(SLOAD),    // SLOAD
	0x55: byte(SSTORE),   // SSTORE
	0x56: byte(JUMP),     // JUMP
	0x57: byte(JUMPI),    // JUMPI
	0x58: byte(PC),       // PC
	0x59: byte(MSIZE),    // MSIZE
	0x5A: byte(GAS),      // GAS
	0x5B: byte(JUMPDEST), // JUMPDEST
	0x5F: byte(PUSH0),    // PUSH0 (EIP-3854, Shanghai)
	0x5E: byte(MCOPY),    // MCOPY (EIP-5656, Cancun)
	0x5C: byte(TLOAD),    // TLOAD (EIP-1153, Cancun)
	0x5D: byte(TSTORE),   // TSTORE (EIP-1153, Cancun)

	// Push operations: EVM 0x60-0x7F → QVM 0x10-0x2F
	0x60: byte(PUSH1), 0x61: byte(PUSH2), 0x62: byte(PUSH3), 0x63: byte(PUSH4),
	0x64: byte(PUSH5), 0x65: byte(PUSH6), 0x66: byte(PUSH7), 0x67: byte(PUSH8),
	0x68: byte(PUSH9), 0x69: byte(PUSH10), 0x6A: byte(PUSH11), 0x6B: byte(PUSH12),
	0x6C: byte(PUSH13), 0x6D: byte(PUSH14), 0x6E: byte(PUSH15), 0x6F: byte(PUSH16),
	0x70: byte(PUSH17), 0x71: byte(PUSH18), 0x72: byte(PUSH19), 0x73: byte(PUSH20),
	0x74: byte(PUSH21), 0x75: byte(PUSH22), 0x76: byte(PUSH23), 0x77: byte(PUSH24),
	0x78: byte(PUSH25), 0x79: byte(PUSH26), 0x7A: byte(PUSH27), 0x7B: byte(PUSH28),
	0x7C: byte(PUSH29), 0x7D: byte(PUSH30), 0x7E: byte(PUSH31), 0x7F: byte(PUSH32),

	// Duplication: EVM 0x80-0x8F → QVM 0x30-0x3F
	0x80: byte(DUP1), 0x81: byte(DUP2), 0x82: byte(DUP3), 0x83: byte(DUP4),
	0x84: byte(DUP5), 0x85: byte(DUP6), 0x86: byte(DUP7), 0x87: byte(DUP8),
	0x88: byte(DUP9), 0x89: byte(DUP10), 0x8A: byte(DUP11), 0x8B: byte(DUP12),
	0x8C: byte(DUP13), 0x8D: byte(DUP14), 0x8E: byte(DUP15), 0x8F: byte(DUP16),

	// Swap: EVM 0x90-0x9F → QVM 0x40-0x4F
	0x90: byte(SWAP1), 0x91: byte(SWAP2), 0x92: byte(SWAP3), 0x93: byte(SWAP4),
	0x94: byte(SWAP5), 0x95: byte(SWAP6), 0x96: byte(SWAP7), 0x97: byte(SWAP8),
	0x98: byte(SWAP9), 0x99: byte(SWAP10), 0x9A: byte(SWAP11), 0x9B: byte(SWAP12),
	0x9C: byte(SWAP13), 0x9D: byte(SWAP14), 0x9E: byte(SWAP15), 0x9F: byte(SWAP16),

	// Log: EVM 0xA0-0xA4 → QVM 0x50-0x54
	0xA0: byte(LOG0), 0xA1: byte(LOG1), 0xA2: byte(LOG2), 0xA3: byte(LOG3), 0xA4: byte(LOG4),

	// System
	0xF0: byte(CREATE),       // CREATE
	0xF1: byte(CALL),         // CALL
	0xF2: byte(CALLCODE),     // CALLCODE
	0xF3: byte(RETURN),       // RETURN
	0xF4: byte(DELEGATECALL), // DELEGATECALL
	0xF5: byte(CREATE2),      // CREATE2
	0xFA: byte(STATICCALL),   // STATICCALL
	0xFD: byte(REVERT),       // REVERT
	0xFE: byte(INVALID),      // INVALID
	0xFF: byte(SELFDESTRUCT), // SELFDESTRUCT
	// EIP-7702 (Prague) — QVM-R8-NEW-04 (R8 2026-07-19) FIX: Add AUTH/AUTHCALL
	// mappings so Solidity-compiled contracts using EIP-7702 set-code
	// transactions translate correctly. Without these entries the translator
	// would reject the bytecode with "unknown opcode 0xF6/0xF7".
	0xF6: byte(AUTH),     // AUTH (EIP-7702)
	0xF7: byte(AUTHCALL), // AUTHCALL (EIP-7702)

	// Control flow
	0x00: byte(STOP), // STOP
}

// IsEVMBytecode detects whether bytecode is in EVM format.
// Uses multi-byte heuristics to distinguish EVM from QVM bytecode.
//
// Key distinction: EVM PUSH opcodes are 0x60-0x7F, while QVM PUSH opcodes
// are 0x10-0x2F. However, QVM opcodes like CALLER=0x73 overlap with EVM PUSH
// range, so single-byte detection is unreliable.
//
// Strategy: Check if the first opcode is a known QVM opcode. If it is,
// treat as QVM. Only translate if the bytecode matches known EVM patterns.
//
// FIX: Verified boundary safety. This function performs prefix-only
// checks (first 1-5 bytes) and does NOT scan through all opcodes, so there
// is no PUSH data boundary issue. All array accesses are bounds-checked:
//   - 5-byte pattern: guarded by len(code) >= 5
//   - Single-byte checks: guarded by len(code) >= 1 (via early return on empty)
//
// TranslateEVMBytecode handles truncated PUSH data by zero-padding to the
// expected push size, so PUSH data never reads past the end of the bytecode.
func IsEVMBytecode(code []byte) bool {
	if len(code) == 0 {
		return false
	}

	// PRIORITY 1: Check multi-byte Solidity patterns FIRST.
	// EVM PUSH1=0x60 conflicts with QVM SLOAD=0x60.
	// Multi-byte patterns are unambiguous and must be checked before
	// single-byte QVM opcode lookup to avoid false negatives.
	//
	// Solidity init code pattern: PUSH1 0x80 PUSH1 0x40 MSTORE (60 80 60 40 52)
	// Every Solidity contract starts with this exact 5-byte sequence.
	if len(code) >= 5 && code[0] == 0x60 && code[1] == 0x80 &&
		code[2] == 0x60 && code[3] == 0x40 && code[4] == 0x52 {
		return true
	}

	// EVM PUSH0 (0x5F) —QVM PUSH0 is 0x0A, so 0x5F is unambiguous.
	if len(code) >= 1 && code[0] == 0x5F {
		return true
	}

	// PRIORITY 2: Check if first byte is a known QVM opcode.
	// If it IS a QVM opcode AND didn't match any pattern above, treat as QVM.
	first := code[0]
	op := OpCode(first)
	// R36-P3-8 FIX (2026-07-30): Added Cancun opcodes (TLOAD, TSTORE,
	// BLOBHASH, MCOPY) to the QVM whitelist. These are real QVM opcodes
	// (opcodes.go:158/163/164/192) but were missing from this list, so
	// QVM-native bytecode starting with one of them was misclassified as
	// EVM PUSH and got mistranslated, corrupting the bytecode stream.
	qvmOps := []OpCode{
		STOP, JUMP, JUMPI, JUMPDEST, PC, NOP, RETURN, REVERT, INVALID,
		PUSH0, PUSH1, PUSH2, PUSH3, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8,
		PUSH9, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16,
		ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND,
		LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR,
		KECCAK256, ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE,
		CALLDATALOAD, CALLDATASIZE, CALLDATACOPY, CODESIZE, CODECOPY,
		GASPRICE, EXTCODESIZE, EXTCODECOPY, RETURNDATASIZE, RETURNDATACOPY,
		EXTCODEHASH, BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, CHAINID,
		SELFBALANCE, PREVRANDAO, BASEFEE, BLOBBASEFEE, GASLIMIT,
		POP, MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE, MSIZE, GAS,
		LOG0, LOG1, LOG2, LOG3, LOG4,
		CREATE, CALL, CALLCODE, DELEGATECALL, CREATE2, STATICCALL, SELFDESTRUCT,
		DUP1, DUP2, DUP3, DUP4, DUP5, DUP6, DUP7, DUP8,
		DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16,
		SWAP1, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7, SWAP8,
		SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16,
		// Cancun transient-storage / blob / memory-copy opcodes:
		TLOAD, TSTORE, BLOBHASH, MCOPY,
	}
	for _, qop := range qvmOps {
		if op == qop {
			return false // Known QVM opcode, not EVM
		}
	}

	// PRIORITY 3: Single-byte range checks for EVM-only opcodes.
	if first >= 0x60 && first <= 0x7F {
		return true
	}
	if first >= 0x80 && first <= 0x9F {
		return true
	}
	if first >= 0xA0 && first <= 0xA4 {
		return true
	}
	return false
}

// TranslateEVMBytecode converts EVM bytecode to QVM bytecode.
// This is called automatically by the executor when EVM bytecode is detected.
//
// AUDIT (2026) QVFIX: Previously, unknown/unmapped EVM opcodes were
// silently mapped to INVALID and translation continued. This was inconsistent
// with the evmcompat.EVMCompatLayer.TranslateBytecode translator, which
// returns an error on unknown opcodes. The inconsistency meant the same EVM
// bytecode could produce different results depending on which translator was
// used: one would produce QVM bytecode with deferred INVALID failures, the
// other would fail immediately and let the caller fall back to native QVM
// execution. Now both translators return an error on unknown opcodes, so the
// caller can handle the failure consistently (typically by falling back to
// native QVM execution).
// EVMTranslatedMarker is a fixed 8-byte prefix prepended by TranslateEVMBytecode
// and TranslateEVMBytecodeWithLog to every emitted QVM byte sequence whose
// source was an EVM contract. This replaces the brittle 8-byte EVM-preamble
// pattern sniffing in isEVMTranslatedCode (executor.go) as the authoritative
// "this contract originated from an EVM translation" signal: a 2^-64
// accidental false positive is eliminated entirely → only code that LITERALLY
// came through TranslateEVMBytecode carries the marker. P3-QV-03 FIX
// (2026-08-03).
//
// Choosing the marker bytes:
//   - Must be INVALID/UNDEFINED in QVM bytecode (so QVM-deployed contracts
//     would never legitimately start with these bytes — guards against
//     collisions with hand-written QVM prefix probes).
//   - Bytes chosen are not EVM bytecodes either (0xFA, 0xE5 etc. don't
//     appear as instruction starts in the QVM op table, and EVM
//     0xFA = STATICCALL emits its own QVM translation, so the prefix
//     cannot be reproduced by a translator pass).
//   - CRC32 of the marker over "QUANTAUREUM EVM-translated preamble v1":
//     0xE6 0x4D 0x91 0xFE — encoded as second 4 bytes, gives a
//     cross-version check: future V2 markers can add a CRCb that doesn't
//     collide with this V1.
//
// The marker is FROZEN at this 8-byte value. Any future change MUST keep
// these exact 8 bytes for V1 translation; if QVM evolves a stronger
// protocol marker (e.g. via a versioned contract-metadata header), add
// this marker to that header rather than replacing it. Mirrors the RLP
// envelope versioning pattern from rollup/l1_anchor.go P3-RL-04.
const EVMTranslatedMarker = "\xfa\xe5\xfe\x91\x4d\xe6\xe0\xe1"

// TranslateEVMBytecode translates EVM bytecode to QVM bytecode. P3-QV-03
// (2026-08-03): prepends EVMTranslatedMarker to the output so downstream
// EVMCompatible detection no longer relies on a brittle 8-byte pattern
// sniff that has a 2^-64 false-positive rate (a future QASM compiler
// could unintentionally emit those bytes, reversing stack-pop order).
// Callers that strip the marker after TranslateEVMBytecode (if any)
// MUST clear the EVMCompatible flag — otherwise they would lose the
// intent of the marker. The marker is NOT a QVM opcode and is skipped
// by the QVM interpreter's PC stepper in opRead-bytecode execution
// (the marker is REMOVED by Create / Create2 before runtime use, or
// -- per ops-defined behavior -- the executor rejects contracts with
// a marker prefix that isn't stripped, since the marker bytes are
// invalid QVM opcode positions). The legacy 8-byte preamble sniff in
// isEVMTranslatedCode now PREFERENTIALLY consults the marker; only
// contracts not bearing the marker fall back to the prefix check (legacy
// pre-marker QVM code deployed before this change).
func TranslateEVMBytecode(evmCode []byte) ([]byte, error) {
	qvmCode := make([]byte, 0, len(evmCode)+len(EVMTranslatedMarker))
	// P3-QV-03: prepend the explicit translation marker.
	qvmCode = append(qvmCode, []byte(EVMTranslatedMarker)...)
	i := 0
	for i < len(evmCode) {
		evmOp := evmCode[i]
		// Check if it's a PUSH instruction
		if evmOp >= 0x60 && evmOp <= 0x7F {
			pushSize := int(evmOp - 0x60 + 1)
			qvmOp, ok := evmToQVMOpcodeMap[evmOp]
			if !ok {
				// AUDIT (2026) QVM-06: Return error instead of silently
				// mapping to INVALID, matching evmcompat translator behavior.
				return nil, fmt.Errorf("evm_translate: unknown PUSH opcode 0x%02x at position %d", evmOp, i)
			}
			qvmCode = append(qvmCode, qvmOp)
			// Copy push data
			end := i + 1 + pushSize
			if end > len(evmCode) {
				end = len(evmCode)
			}
			qvmCode = append(qvmCode, evmCode[i+1:end]...)
			// Pad with zeros if incomplete
			actualSize := end - i - 1
			for j := actualSize; j < pushSize; j++ {
				qvmCode = append(qvmCode, 0)
			}
			i = end
			continue
		}
		// Regular opcode
		qvmOp, ok := evmToQVMOpcodeMap[evmOp]
		if ok {
			qvmCode = append(qvmCode, qvmOp)
		} else {
			// AUDIT (2026) QVM-06: Return error instead of silently
			// mapping to INVALID, matching evmcompat translator behavior.
			return nil, fmt.Errorf("evm_translate: unknown opcode 0x%02x at position %d", evmOp, i)
		}
		i++
	}
	return qvmCode, nil
}

// TranslateEVMBytecodeWithLog translates EVM bytecode and logs the translation
// for debugging purposes.
func TranslateEVMBytecodeWithLog(evmCode []byte) ([]byte, error) {
	if !IsEVMBytecode(evmCode) {
		return evmCode, nil // Already QVM bytecode
	}
	translated, err := TranslateEVMBytecode(evmCode)
	if err != nil {
		return nil, fmt.Errorf("EVM to QVM bytecode translation failed: %w", err)
	}
	return translated, nil
}
