// Quantaureum Node source, version 1.0.0.
// Package qvm implements the Quantaureum Virtual Machine (QVM).
// QVM is a stack-based virtual machine designed for smart contract execution.
package qvm

// OpCode represents a QVM instruction opcode.
type OpCode byte

// QVM Instruction Set
// The instruction set is organized into categories:
// - 0x00-0x0F: Control flow
// - 0x10-0x1F: Stack operations
// - 0x20-0x2F: Arithmetic operations
// - 0x30-0x3F: Comparison operations
// - 0x40-0x4F: Bitwise operations
// - 0x50-0x5F: Memory operations
// - 0x60-0x6F: Storage operations
// - 0x70-0x7F: Context operations
// - 0x80-0x8F: Crypto operations
// - 0x90-0x9F: Call operations
// - 0xF0-0xFF: System operations

const (
	// Control Flow (0x00-0x0F)
	STOP       OpCode = 0x00 // Halt execution
	JUMP       OpCode = 0x01 // Unconditional jump
	JUMPI      OpCode = 0x02 // Conditional jump
	JUMPDEST   OpCode = 0x03 // Mark valid jump destination
	PC         OpCode = 0x04 // Get program counter
	NOP        OpCode = 0x05 // No operation
	RETURN     OpCode = 0x06 // Return from execution
	REVERT     OpCode = 0x07 // Revert execution with data
	INVALID    OpCode = 0x08 // Invalid instruction (always fails)
	SIGNEXTEND OpCode = 0x09 // Sign-extend byte k of value x
	PUSH0      OpCode = 0x0A // Push 0 bytes (pushes 0 onto stack, EIP-3854)

	// Stack Operations (0x10-0x1F)
	// P3-V6 AUDIT NOTE (PUSH1-PUSH32 value space): Unlike EVM (where PUSH1..PUSH32
	// occupy the contiguous 0x60..0x7F range), QVM splits PUSH opcodes into TWO
	// non-contiguous ranges because 0x60-0x6F is already used by storage ops:
	//   - Primary range 0x10-0x15: PUSH1,PUSH2,PUSH4,PUSH8,PUSH16,PUSH32 (powers of 2)
	//   - Extended range 0xB0-0xC9: PUSH3,PUSH5..PUSH7,PUSH9..PUSH31 (gap fillers)
	// IsPush()/PushSize() handle BOTH ranges. The split is intentional and
	// documented; any new PUSH variant MUST be registered in opcodeInfoTable
	// AND covered by IsPush/PushSize or it will be treated as a non-PUSH opcode.
	PUSH1  OpCode = 0x10 // Push 1 byte
	PUSH2  OpCode = 0x11 // Push 2 bytes
	PUSH4  OpCode = 0x12 // Push 4 bytes
	PUSH8  OpCode = 0x13 // Push 8 bytes
	PUSH16 OpCode = 0x14 // Push 16 bytes
	PUSH32 OpCode = 0x15 // Push 32 bytes
	POP    OpCode = 0x16 // Pop from stack

	// Extended PUSH operations for EVM compatibility (0xB0-0xC9)
	// These fill the gaps in the PUSH1-32 range to support full EVM bytecode translation.
	PUSH3  OpCode = 0xB0 // Push 3 bytes
	PUSH5  OpCode = 0xB1 // Push 5 bytes
	PUSH6  OpCode = 0xB2 // Push 6 bytes
	PUSH7  OpCode = 0xB3 // Push 7 bytes
	PUSH9  OpCode = 0xB4 // Push 9 bytes
	PUSH10 OpCode = 0xB5 // Push 10 bytes
	PUSH11 OpCode = 0xB6 // Push 11 bytes
	PUSH12 OpCode = 0xB7 // Push 12 bytes
	PUSH13 OpCode = 0xB8 // Push 13 bytes
	PUSH14 OpCode = 0xB9 // Push 14 bytes
	PUSH15 OpCode = 0xBA // Push 15 bytes
	PUSH17 OpCode = 0xBB // Push 17 bytes
	PUSH18 OpCode = 0xBC // Push 18 bytes
	PUSH19 OpCode = 0xBD // Push 19 bytes
	PUSH20 OpCode = 0xBE // Push 20 bytes
	PUSH21 OpCode = 0xBF // Push 21 bytes
	PUSH22 OpCode = 0xC0 // Push 22 bytes
	PUSH23 OpCode = 0xC1 // Push 23 bytes
	PUSH24 OpCode = 0xC2 // Push 24 bytes
	PUSH25 OpCode = 0xC3 // Push 25 bytes
	PUSH26 OpCode = 0xC4 // Push 26 bytes
	PUSH27 OpCode = 0xC5 // Push 27 bytes
	PUSH28 OpCode = 0xC6 // Push 28 bytes
	PUSH29 OpCode = 0xC7 // Push 29 bytes
	PUSH30 OpCode = 0xC8 // Push 30 bytes
	PUSH31 OpCode = 0xC9 // Push 31 bytes
	DUP1   OpCode = 0x17 // Duplicate 1st stack item
	DUP2   OpCode = 0x18 // Duplicate 2nd stack item
	DUP3   OpCode = 0x19 // Duplicate 3rd stack item  // audit-fix R69-QVM-2 [CRITICAL]: DUP3 added (was missing)
	DUP4   OpCode = 0x1A // Duplicate 4th stack item  // audit-fix R69-QVM-2: DUP4 moved from 0x19 to avoid conflict with DUP3
	// audit-fix R69-QVM-2 [CRITICAL]: DUP5-16 added in free range 0xD0-0xDB (0x20-0x26
	// conflict with arithmetic ops ADD=0x20..DIV=0x23). The standard EVM DUP range
	// (0x80-0x8F) is partially occupied by extended context ops (NUMBER, CHAINID,
	// SELFBALANCE at 0x80-0x82) and crypto ops (SHA3..KYBER at 0x88-0x8C).
	DUP5  OpCode = 0xD0 // Duplicate 5th stack item
	DUP6  OpCode = 0xD1 // Duplicate 6th stack item
	DUP7  OpCode = 0xD2 // Duplicate 7th stack item
	DUP8  OpCode = 0xD3 // Duplicate 8th stack item
	DUP9  OpCode = 0xD4 // Duplicate 9th stack item
	DUP10 OpCode = 0xD5 // Duplicate 10th stack item
	DUP11 OpCode = 0xD6 // Duplicate 11th stack item
	DUP12 OpCode = 0xD7 // Duplicate 12th stack item
	DUP13 OpCode = 0xD8 // Duplicate 13th stack item
	DUP14 OpCode = 0xD9 // Duplicate 14th stack item
	DUP15 OpCode = 0xDA // Duplicate 15th stack item
	DUP16 OpCode = 0xDB // Duplicate 16th stack item
	SWAP1 OpCode = 0x1B // Swap 1st and 2nd stack items
	SWAP2 OpCode = 0x1C // Swap 1st and 3rd stack items
	SWAP3 OpCode = 0x1D // Swap 1st and 4th stack items // audit-fix R69-QVM-1 [CRITICAL]: SWAP3 added
	SWAP4 OpCode = 0x1E // Swap 1st and 5th stack items // audit-fix R69-QVM-1: SWAP4 moved from 0x1C
	// audit-fix R69-QVM-1 [CRITICAL]: SWAP5-16 added in free range 0xDC-0xE7 (0x1F-0x27
	// conflict with comparison ops LT=0x30..ISZERO=0x35 at offset 0x10, and arithmetic
	// ops at 0x20-0x29). The standard EVM SWAP range (0x90-0x9F) is partially occupied
	// by Call operations (CALL..CREATE2 at 0x90-0x95).
	SWAP5       OpCode = 0xDC // Swap 1st and 6th stack items
	SWAP6       OpCode = 0xDD // Swap 1st and 7th stack items
	SWAP7       OpCode = 0xDE // Swap 1st and 8th stack items
	SWAP8       OpCode = 0xDF // Swap 1st and 9th stack items
	SWAP9       OpCode = 0xE0 // Swap 1st and 10th stack items
	SWAP10      OpCode = 0xE1 // Swap 1st and 11th stack items
	SWAP11      OpCode = 0xE2 // Swap 1st and 12th stack items
	SWAP12      OpCode = 0xE3 // Swap 1st and 13th stack items
	SWAP13      OpCode = 0xE4 // Swap 1st and 14th stack items
	SWAP14      OpCode = 0xE5 // Swap 1st and 15th stack items
	SWAP15      OpCode = 0xE6 // Swap 1st and 16th stack items
	SWAP16      OpCode = 0xE7 // Swap 1st and 17th stack items
	BLOBBASEFEE OpCode = 0xE8 // Get blob base fee (EIP-7516)

	// Arithmetic Operations (0x20-0x2F)
	ADD    OpCode = 0x20 // Addition
	SUB    OpCode = 0x21 // Subtraction
	MUL    OpCode = 0x22 // Multiplication
	DIV    OpCode = 0x23 // Integer division (unsigned)
	MOD    OpCode = 0x24 // Modulo (unsigned)
	SDIV   OpCode = 0x25 // Signed integer division (EVM 0x05)
	SMOD   OpCode = 0x26 // Signed modulo (EVM 0x07)
	ADDMOD OpCode = 0x27 // (a + b) % N
	MULMOD OpCode = 0x28 // (a * b) % N
	EXP    OpCode = 0x29 // Exponentiation

	// Comparison Operations (0x30-0x3F)
	LT     OpCode = 0x30 // Less than
	GT     OpCode = 0x31 // Greater than
	SLT    OpCode = 0x32 // Signed less than
	SGT    OpCode = 0x33 // Signed greater than
	EQ     OpCode = 0x34 // Equality
	ISZERO OpCode = 0x35 // Is zero

	// Bitwise Operations (0x40-0x4F)
	AND  OpCode = 0x40 // Bitwise AND
	OR   OpCode = 0x41 // Bitwise OR
	XOR  OpCode = 0x42 // Bitwise XOR
	NOT  OpCode = 0x43 // Bitwise NOT
	SHL  OpCode = 0x44 // Shift left
	SHR  OpCode = 0x45 // Logical shift right
	SAR  OpCode = 0x46 // Arithmetic shift right
	BYTE OpCode = 0x47 // Get byte from word

	// Memory Operations (0x50-0x5F)
	MLOAD   OpCode = 0x50 // Load from memory
	MSTORE  OpCode = 0x51 // Store to memory
	MSTORE8 OpCode = 0x52 // Store byte to memory
	MSIZE   OpCode = 0x53 // Get memory size
	MCOPY   OpCode = 0x54 // Copy memory

	// Storage Operations (0x60-0x6F)
	SLOAD  OpCode = 0x60 // Load from storage
	SSTORE OpCode = 0x61 // Store to storage
	TLOAD  OpCode = 0x62 // Load from transient storage (EIP-1153)
	TSTORE OpCode = 0x63 // Store to transient storage (EIP-1153)

	// Context Operations (0x70-0x7F)
	ADDRESS      OpCode = 0x70 // Get current contract address
	BALANCE      OpCode = 0x71 // Get balance of address
	ORIGIN       OpCode = 0x72 // Get transaction origin
	CALLER       OpCode = 0x73 // Get caller address
	CALLVALUE    OpCode = 0x74 // Get call value
	CALLDATALOAD OpCode = 0x75 // Load call data
	CALLDATASIZE OpCode = 0x76 // Get call data size
	CALLDATACOPY OpCode = 0x77 // Copy call data to memory
	CODESIZE     OpCode = 0x78 // Get code size
	CODECOPY     OpCode = 0x79 // Copy code to memory
	GASPRICE     OpCode = 0x7A // Get gas price
	GASLIMIT     OpCode = 0x7B // Get gas limit
	GAS          OpCode = 0x7C // Get remaining gas
	BLOCKHASH    OpCode = 0x7D // Get block hash
	COINBASE     OpCode = 0x7E // Get block proposer
	TIMESTAMP    OpCode = 0x7F // Get block timestamp

	// Extended Context Operations (0x80-0x8F)
	NUMBER      OpCode = 0x80 // Get block number
	CHAINID     OpCode = 0x81 // Get chain ID
	SELFBALANCE OpCode = 0x82 // Get self balance
	EXTCODESIZE OpCode = 0x83 // Get code size of external account
	EXTCODECOPY OpCode = 0x84 // Copy code from external account to memory
	EXTCODEHASH OpCode = 0x85 // Get code hash of external account (EIP-1052)
	PREVRANDAO  OpCode = 0x86 // Get previous RANDAO mix (EIP-4399)
	BLOBHASH    OpCode = 0x87 // Get blob hash at index (EIP-4844)
	BASEFEE     OpCode = 0x8D // Get base fee of current block (EIP-3198)

	// Crypto Operations (0x88-0x8F)
	SHA3      OpCode = 0x88 // SHA3-256 hash
	KECCAK256 OpCode = 0x89 // Keccak-256 hash (alias)
	// Post-Quantum Crypto Operations (0x8A-0x8F)
	KYBER_KEYGEN   OpCode = 0x8A // Generate Kyber-768 key pair
	KYBER_ENCAPS   OpCode = 0x8B // Kyber-768 encapsulate (generate shared key and ciphertext)
	KYBER_DECAPS   OpCode = 0x8C // Kyber-768 decapsulate (extract shared key from ciphertext)
	KYBER_ZERO_KEY OpCode = 0x8E // Zeroize PQC key material from memory (audit P1-02)

	// Call Operations (0x90-0x9F)
	CALL         OpCode = 0x90 // Call another contract
	CALLCODE     OpCode = 0x91 // Call with current storage
	DELEGATECALL OpCode = 0x92 // Delegate call
	STATICCALL   OpCode = 0x93 // Static call (read-only)
	CREATE       OpCode = 0x94 // Create new contract
	CREATE2      OpCode = 0x95 // Create with deterministic address
	AUTH         OpCode = 0x96 // Set authorized address from signature (EIP-7702)
	AUTHCALL     OpCode = 0x97 // Call using authorized address as caller (EIP-7702)

	// Return Data Operations (0x3D-0x3E) — EIP-211 (Byzantium)
	RETURNDATASIZE OpCode = 0x3d // Get size of return data from last call
	RETURNDATACOPY OpCode = 0x3e // Copy return data to memory

	// Log Operations (0xA0-0xAF)
	LOG0 OpCode = 0xA0 // Log with 0 topics
	LOG1 OpCode = 0xA1 // Log with 1 topic
	LOG2 OpCode = 0xA2 // Log with 2 topics
	LOG3 OpCode = 0xA3 // Log with 3 topics
	LOG4 OpCode = 0xA4 // Log with 4 topics

	// System Operations (0xF0-0xFF)
	SELFDESTRUCT OpCode = 0xF0 // Destroy contract
)

// OpCodeInfo contains metadata about an opcode.
type OpCodeInfo struct {
	Name          string // Human-readable name
	StackPop      int    // Number of items popped from stack
	StackPush     int    // Number of items pushed to stack
	GasCost       uint64 // Base gas cost
	ImmediateSize int    // Size of immediate data (for PUSH)
	IsJump        bool   // Is this a jump instruction
	IsTerminal    bool   // Does this terminate execution
}

// R26-049 / R27-013: For SWAPn and DUPn opcodes, the StackPop field represents
// the "minimum stack depth required" (NOT actual items popped). SWAPn needs
// n+1 items on stack (StackPop=n+1); DUPn needs n items (StackPop=n). Neither
// actually removes items — SWAPn swaps in-place, DUPn pushes a copy. The VM
// uses StackPop for underflow pre-check. The overflow check in environment.go
// uses isDupOrSwap() to avoid subtracting StackPop for these opcodes.
//
// isDupOrSwap returns true if the opcode is a DUPn or SWAPn variant.
// DUP: 0x17-0x1A (DUP1-DUP4) and 0xD0-0xDB (DUP5-DUP16)
// SWAP: 0x1B-0x1E (SWAP1-SWAP4) and 0xDC-0xE7 (SWAP5-SWAP16)
func isDupOrSwap(op OpCode) bool {
	switch op {
	case DUP1, DUP2, DUP3, DUP4,
		DUP5, DUP6, DUP7, DUP8, DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16,
		SWAP1, SWAP2, SWAP3, SWAP4,
		SWAP5, SWAP6, SWAP7, SWAP8, SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16:
		return true
	}
	return false
}

// opcodeInfoTable maps opcodes to their metadata.
// Optimized: array-based lookup eliminates map hash overhead on every opcode.
// An empty Name means the slot is unused (invalid opcode).
var opcodeInfoTable [256]OpCodeInfo

func init() {
	// Control Flow
	opcodeInfoTable[STOP] = OpCodeInfo{Name: "STOP", StackPop: 0, StackPush: 0, GasCost: 0, IsTerminal: true}
	opcodeInfoTable[JUMP] = OpCodeInfo{Name: "JUMP", StackPop: 1, StackPush: 0, GasCost: 8, IsJump: true}
	opcodeInfoTable[JUMPI] = OpCodeInfo{Name: "JUMPI", StackPop: 2, StackPush: 0, GasCost: 10, IsJump: true}
	opcodeInfoTable[JUMPDEST] = OpCodeInfo{Name: "JUMPDEST", StackPop: 0, StackPush: 0, GasCost: 1}
	opcodeInfoTable[PC] = OpCodeInfo{Name: "PC", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[NOP] = OpCodeInfo{Name: "NOP", StackPop: 0, StackPush: 0, GasCost: 1}
	opcodeInfoTable[RETURN] = OpCodeInfo{Name: "RETURN", StackPop: 2, StackPush: 0, GasCost: 0, IsTerminal: true}
	opcodeInfoTable[REVERT] = OpCodeInfo{Name: "REVERT", StackPop: 2, StackPush: 0, GasCost: 0, IsTerminal: true}
	opcodeInfoTable[INVALID] = OpCodeInfo{Name: "INVALID", StackPop: 0, StackPush: 0, GasCost: 0, IsTerminal: true}
	opcodeInfoTable[SIGNEXTEND] = OpCodeInfo{Name: "SIGNEXTEND", StackPop: 2, StackPush: 1, GasCost: 5}
	opcodeInfoTable[PUSH0] = OpCodeInfo{Name: "PUSH0", StackPop: 0, StackPush: 1, GasCost: 2}

	// Stack Operations
	opcodeInfoTable[PUSH1] = OpCodeInfo{Name: "PUSH1", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 1}
	opcodeInfoTable[PUSH2] = OpCodeInfo{Name: "PUSH2", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 2}
	opcodeInfoTable[PUSH3] = OpCodeInfo{Name: "PUSH3", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 3}
	opcodeInfoTable[PUSH4] = OpCodeInfo{Name: "PUSH4", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 4}
	opcodeInfoTable[PUSH5] = OpCodeInfo{Name: "PUSH5", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 5}
	opcodeInfoTable[PUSH6] = OpCodeInfo{Name: "PUSH6", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 6}
	opcodeInfoTable[PUSH7] = OpCodeInfo{Name: "PUSH7", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 7}
	opcodeInfoTable[PUSH8] = OpCodeInfo{Name: "PUSH8", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 8}
	opcodeInfoTable[PUSH9] = OpCodeInfo{Name: "PUSH9", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 9}
	opcodeInfoTable[PUSH10] = OpCodeInfo{Name: "PUSH10", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 10}
	opcodeInfoTable[PUSH11] = OpCodeInfo{Name: "PUSH11", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 11}
	opcodeInfoTable[PUSH12] = OpCodeInfo{Name: "PUSH12", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 12}
	opcodeInfoTable[PUSH13] = OpCodeInfo{Name: "PUSH13", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 13}
	opcodeInfoTable[PUSH14] = OpCodeInfo{Name: "PUSH14", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 14}
	opcodeInfoTable[PUSH15] = OpCodeInfo{Name: "PUSH15", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 15}
	opcodeInfoTable[PUSH16] = OpCodeInfo{Name: "PUSH16", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 16}
	opcodeInfoTable[PUSH17] = OpCodeInfo{Name: "PUSH17", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 17}
	opcodeInfoTable[PUSH18] = OpCodeInfo{Name: "PUSH18", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 18}
	opcodeInfoTable[PUSH19] = OpCodeInfo{Name: "PUSH19", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 19}
	opcodeInfoTable[PUSH20] = OpCodeInfo{Name: "PUSH20", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 20}
	opcodeInfoTable[PUSH21] = OpCodeInfo{Name: "PUSH21", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 21}
	opcodeInfoTable[PUSH22] = OpCodeInfo{Name: "PUSH22", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 22}
	opcodeInfoTable[PUSH23] = OpCodeInfo{Name: "PUSH23", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 23}
	opcodeInfoTable[PUSH24] = OpCodeInfo{Name: "PUSH24", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 24}
	opcodeInfoTable[PUSH25] = OpCodeInfo{Name: "PUSH25", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 25}
	opcodeInfoTable[PUSH26] = OpCodeInfo{Name: "PUSH26", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 26}
	opcodeInfoTable[PUSH27] = OpCodeInfo{Name: "PUSH27", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 27}
	opcodeInfoTable[PUSH28] = OpCodeInfo{Name: "PUSH28", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 28}
	opcodeInfoTable[PUSH29] = OpCodeInfo{Name: "PUSH29", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 29}
	opcodeInfoTable[PUSH30] = OpCodeInfo{Name: "PUSH30", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 30}
	opcodeInfoTable[PUSH31] = OpCodeInfo{Name: "PUSH31", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 31}
	opcodeInfoTable[PUSH32] = OpCodeInfo{Name: "PUSH32", StackPop: 0, StackPush: 1, GasCost: 3, ImmediateSize: 32}
	opcodeInfoTable[POP] = OpCodeInfo{Name: "POP", StackPop: 1, StackPush: 0, GasCost: 2}
	opcodeInfoTable[DUP1] = OpCodeInfo{Name: "DUP1", StackPop: 1, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP2] = OpCodeInfo{Name: "DUP2", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP4] = OpCodeInfo{Name: "DUP4", StackPop: 4, StackPush: 1, GasCost: 3}
	opcodeInfoTable[SWAP1] = OpCodeInfo{Name: "SWAP1", StackPop: 2, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP2] = OpCodeInfo{Name: "SWAP2", StackPop: 3, StackPush: 0, GasCost: 3}
	// R27-035: Reorder so SWAP3 is defined before SWAP4 for consistency.
	opcodeInfoTable[SWAP3] = OpCodeInfo{Name: "SWAP3", StackPop: 4, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP4] = OpCodeInfo{Name: "SWAP4", StackPop: 5, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP5] = OpCodeInfo{Name: "SWAP5", StackPop: 6, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP6] = OpCodeInfo{Name: "SWAP6", StackPop: 7, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP7] = OpCodeInfo{Name: "SWAP7", StackPop: 8, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP8] = OpCodeInfo{Name: "SWAP8", StackPop: 9, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP9] = OpCodeInfo{Name: "SWAP9", StackPop: 10, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP10] = OpCodeInfo{Name: "SWAP10", StackPop: 11, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP11] = OpCodeInfo{Name: "SWAP11", StackPop: 12, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP12] = OpCodeInfo{Name: "SWAP12", StackPop: 13, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP13] = OpCodeInfo{Name: "SWAP13", StackPop: 14, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP14] = OpCodeInfo{Name: "SWAP14", StackPop: 15, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP15] = OpCodeInfo{Name: "SWAP15", StackPop: 16, StackPush: 0, GasCost: 3}
	opcodeInfoTable[SWAP16] = OpCodeInfo{Name: "SWAP16", StackPop: 17, StackPush: 0, GasCost: 3}
	opcodeInfoTable[DUP3] = OpCodeInfo{Name: "DUP3", StackPop: 3, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP5] = OpCodeInfo{Name: "DUP5", StackPop: 5, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP6] = OpCodeInfo{Name: "DUP6", StackPop: 6, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP7] = OpCodeInfo{Name: "DUP7", StackPop: 7, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP8] = OpCodeInfo{Name: "DUP8", StackPop: 8, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP9] = OpCodeInfo{Name: "DUP9", StackPop: 9, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP10] = OpCodeInfo{Name: "DUP10", StackPop: 10, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP11] = OpCodeInfo{Name: "DUP11", StackPop: 11, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP12] = OpCodeInfo{Name: "DUP12", StackPop: 12, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP13] = OpCodeInfo{Name: "DUP13", StackPop: 13, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP14] = OpCodeInfo{Name: "DUP14", StackPop: 14, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP15] = OpCodeInfo{Name: "DUP15", StackPop: 15, StackPush: 1, GasCost: 3}
	opcodeInfoTable[DUP16] = OpCodeInfo{Name: "DUP16", StackPop: 16, StackPush: 1, GasCost: 3}

	// Arithmetic Operations
	opcodeInfoTable[ADD] = OpCodeInfo{Name: "ADD", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[SUB] = OpCodeInfo{Name: "SUB", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[MUL] = OpCodeInfo{Name: "MUL", StackPop: 2, StackPush: 1, GasCost: 5}
	opcodeInfoTable[DIV] = OpCodeInfo{Name: "DIV", StackPop: 2, StackPush: 1, GasCost: 5}
	opcodeInfoTable[MOD] = OpCodeInfo{Name: "MOD", StackPop: 2, StackPush: 1, GasCost: 5}
	opcodeInfoTable[SDIV] = OpCodeInfo{Name: "SDIV", StackPop: 2, StackPush: 1, GasCost: 5}
	opcodeInfoTable[SMOD] = OpCodeInfo{Name: "SMOD", StackPop: 2, StackPush: 1, GasCost: 5}
	opcodeInfoTable[ADDMOD] = OpCodeInfo{Name: "ADDMOD", StackPop: 3, StackPush: 1, GasCost: 8}
	opcodeInfoTable[MULMOD] = OpCodeInfo{Name: "MULMOD", StackPop: 3, StackPush: 1, GasCost: 8}
	opcodeInfoTable[EXP] = OpCodeInfo{Name: "EXP", StackPop: 2, StackPush: 1, GasCost: 10}

	// Comparison Operations
	opcodeInfoTable[LT] = OpCodeInfo{Name: "LT", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[GT] = OpCodeInfo{Name: "GT", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[SLT] = OpCodeInfo{Name: "SLT", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[SGT] = OpCodeInfo{Name: "SGT", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[EQ] = OpCodeInfo{Name: "EQ", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[ISZERO] = OpCodeInfo{Name: "ISZERO", StackPop: 1, StackPush: 1, GasCost: 3}

	// Bitwise Operations
	opcodeInfoTable[AND] = OpCodeInfo{Name: "AND", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[OR] = OpCodeInfo{Name: "OR", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[XOR] = OpCodeInfo{Name: "XOR", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[NOT] = OpCodeInfo{Name: "NOT", StackPop: 1, StackPush: 1, GasCost: 3}
	opcodeInfoTable[SHL] = OpCodeInfo{Name: "SHL", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[SHR] = OpCodeInfo{Name: "SHR", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[SAR] = OpCodeInfo{Name: "SAR", StackPop: 2, StackPush: 1, GasCost: 3}
	opcodeInfoTable[BYTE] = OpCodeInfo{Name: "BYTE", StackPop: 2, StackPush: 1, GasCost: 3}

	// Memory Operations
	opcodeInfoTable[MLOAD] = OpCodeInfo{Name: "MLOAD", StackPop: 1, StackPush: 1, GasCost: 3}
	opcodeInfoTable[MSTORE] = OpCodeInfo{Name: "MSTORE", StackPop: 2, StackPush: 0, GasCost: 3}
	opcodeInfoTable[MSTORE8] = OpCodeInfo{Name: "MSTORE8", StackPop: 2, StackPush: 0, GasCost: 3}
	opcodeInfoTable[MSIZE] = OpCodeInfo{Name: "MSIZE", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[MCOPY] = OpCodeInfo{Name: "MCOPY", StackPop: 3, StackPush: 0, GasCost: 3}

	// Storage Operations
	opcodeInfoTable[SLOAD] = OpCodeInfo{Name: "SLOAD", StackPop: 1, StackPush: 1, GasCost: 100}
	opcodeInfoTable[SSTORE] = OpCodeInfo{Name: "SSTORE", StackPop: 2, StackPush: 0, GasCost: 100}
	opcodeInfoTable[TLOAD] = OpCodeInfo{Name: "TLOAD", StackPop: 1, StackPush: 1, GasCost: 100}
	opcodeInfoTable[TSTORE] = OpCodeInfo{Name: "TSTORE", StackPop: 2, StackPush: 0, GasCost: 100}

	// Context Operations
	opcodeInfoTable[ADDRESS] = OpCodeInfo{Name: "ADDRESS", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[BALANCE] = OpCodeInfo{Name: "BALANCE", StackPop: 1, StackPush: 1, GasCost: 100}
	opcodeInfoTable[ORIGIN] = OpCodeInfo{Name: "ORIGIN", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[CALLER] = OpCodeInfo{Name: "CALLER", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[CALLVALUE] = OpCodeInfo{Name: "CALLVALUE", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[CALLDATALOAD] = OpCodeInfo{Name: "CALLDATALOAD", StackPop: 1, StackPush: 1, GasCost: 3}
	opcodeInfoTable[CALLDATASIZE] = OpCodeInfo{Name: "CALLDATASIZE", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[CALLDATACOPY] = OpCodeInfo{Name: "CALLDATACOPY", StackPop: 3, StackPush: 0, GasCost: 3}
	opcodeInfoTable[CODESIZE] = OpCodeInfo{Name: "CODESIZE", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[CODECOPY] = OpCodeInfo{Name: "CODECOPY", StackPop: 3, StackPush: 0, GasCost: 3}
	opcodeInfoTable[GASPRICE] = OpCodeInfo{Name: "GASPRICE", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[GASLIMIT] = OpCodeInfo{Name: "GASLIMIT", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[GAS] = OpCodeInfo{Name: "GAS", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[BLOCKHASH] = OpCodeInfo{Name: "BLOCKHASH", StackPop: 1, StackPush: 1, GasCost: 20}
	opcodeInfoTable[COINBASE] = OpCodeInfo{Name: "COINBASE", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[TIMESTAMP] = OpCodeInfo{Name: "TIMESTAMP", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[NUMBER] = OpCodeInfo{Name: "NUMBER", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[CHAINID] = OpCodeInfo{Name: "CHAINID", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[SELFBALANCE] = OpCodeInfo{Name: "SELFBALANCE", StackPop: 0, StackPush: 1, GasCost: 5}
	opcodeInfoTable[EXTCODESIZE] = OpCodeInfo{Name: "EXTCODESIZE", StackPop: 1, StackPush: 1, GasCost: 100}
	opcodeInfoTable[EXTCODECOPY] = OpCodeInfo{Name: "EXTCODECOPY", StackPop: 4, StackPush: 0, GasCost: 3}
	opcodeInfoTable[EXTCODEHASH] = OpCodeInfo{Name: "EXTCODEHASH", StackPop: 1, StackPush: 1, GasCost: 100}
	opcodeInfoTable[PREVRANDAO] = OpCodeInfo{Name: "PREVRANDAO", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[BLOBHASH] = OpCodeInfo{Name: "BLOBHASH", StackPop: 1, StackPush: 1, GasCost: 2}
	opcodeInfoTable[BASEFEE] = OpCodeInfo{Name: "BASEFEE", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[BLOBBASEFEE] = OpCodeInfo{Name: "BLOBBASEFEE", StackPop: 0, StackPush: 1, GasCost: 2}

	// Crypto Operations
	opcodeInfoTable[SHA3] = OpCodeInfo{Name: "SHA3", StackPop: 2, StackPush: 1, GasCost: 30}
	opcodeInfoTable[KECCAK256] = OpCodeInfo{Name: "KECCAK256", StackPop: 2, StackPush: 1, GasCost: 30}

	// Return Data Operations — EIP-211 (Byzantium)
	opcodeInfoTable[RETURNDATASIZE] = OpCodeInfo{Name: "RETURNDATASIZE", StackPop: 0, StackPush: 1, GasCost: 2}
	opcodeInfoTable[RETURNDATACOPY] = OpCodeInfo{Name: "RETURNDATACOPY", StackPop: 3, StackPush: 0, GasCost: 3}

	// Post-Quantum Crypto Operations
	opcodeInfoTable[KYBER_KEYGEN] = OpCodeInfo{Name: "KYBER_KEYGEN", StackPop: 0, StackPush: 2, GasCost: 50000}
	opcodeInfoTable[KYBER_ENCAPS] = OpCodeInfo{Name: "KYBER_ENCAPS", StackPop: 1, StackPush: 2, GasCost: 25000}
	opcodeInfoTable[KYBER_DECAPS] = OpCodeInfo{Name: "KYBER_DECAPS", StackPop: 2, StackPush: 1, GasCost: 25000}
	opcodeInfoTable[KYBER_ZERO_KEY] = OpCodeInfo{Name: "KYBER_ZERO_KEY", StackPop: 2, StackPush: 0, GasCost: 3}

	// Call Operations
	// FIX: GasCost set to 0 — the full gas cost (base + cold + value + new account)
	// is computed dynamically by CalculateCallGas / GasCreate / GasSelfDestruct inside
	// each opcode handler. Setting a non-zero GasCost here causes double-charging because
	// run() in environment.go consumes GasCost before the handler runs, and the handler
	// then consumes the full cost again.
	opcodeInfoTable[CALL] = OpCodeInfo{Name: "CALL", StackPop: 7, StackPush: 1, GasCost: 0}
	opcodeInfoTable[CALLCODE] = OpCodeInfo{Name: "CALLCODE", StackPop: 7, StackPush: 1, GasCost: 0}
	opcodeInfoTable[DELEGATECALL] = OpCodeInfo{Name: "DELEGATECALL", StackPop: 6, StackPush: 1, GasCost: 0}
	opcodeInfoTable[STATICCALL] = OpCodeInfo{Name: "STATICCALL", StackPop: 6, StackPush: 1, GasCost: 0}
	opcodeInfoTable[CREATE] = OpCodeInfo{Name: "CREATE", StackPop: 3, StackPush: 1, GasCost: 0}
	opcodeInfoTable[CREATE2] = OpCodeInfo{Name: "CREATE2", StackPop: 4, StackPush: 1, GasCost: 0}
	opcodeInfoTable[AUTH] = OpCodeInfo{Name: "AUTH", StackPop: 3, StackPush: 1, GasCost: 0}
	opcodeInfoTable[AUTHCALL] = OpCodeInfo{Name: "AUTHCALL", StackPop: 7, StackPush: 1, GasCost: 0}

	// Log Operations
	opcodeInfoTable[LOG0] = OpCodeInfo{Name: "LOG0", StackPop: 2, StackPush: 0, GasCost: 375}
	opcodeInfoTable[LOG1] = OpCodeInfo{Name: "LOG1", StackPop: 3, StackPush: 0, GasCost: 375}
	opcodeInfoTable[LOG2] = OpCodeInfo{Name: "LOG2", StackPop: 4, StackPush: 0, GasCost: 375}
	opcodeInfoTable[LOG3] = OpCodeInfo{Name: "LOG3", StackPop: 5, StackPush: 0, GasCost: 375}
	opcodeInfoTable[LOG4] = OpCodeInfo{Name: "LOG4", StackPop: 6, StackPush: 0, GasCost: 375}

	// System Operations
	opcodeInfoTable[SELFDESTRUCT] = OpCodeInfo{Name: "SELFDESTRUCT", StackPop: 1, StackPush: 0, GasCost: 0, IsTerminal: true}
}

// GetInfo returns the metadata for an opcode.
func (op OpCode) GetInfo() (OpCodeInfo, bool) {
	info := opcodeInfoTable[op]
	return info, info.Name != ""
}

// String returns the name of the opcode.
func (op OpCode) String() string {
	info := opcodeInfoTable[op]
	if info.Name != "" {
		return info.Name
	}
	return "UNKNOWN"
}

// IsValid returns true if the opcode is valid.
func (op OpCode) IsValid() bool {
	return opcodeInfoTable[op].Name != ""
}

// IsPush returns true if the opcode is a PUSH instruction.
func (op OpCode) IsPush() bool {
	// Standard PUSH range (0x10-0x15)
	if op >= PUSH1 && op <= PUSH32 {
		return true
	}
	// Extended PUSH range for EVM compatibility (0xB0-0xC9)
	if op >= PUSH3 && op <= PUSH31 {
		return true
	}
	return false
}

// PushSize returns the number of bytes to push for PUSH instructions.
func (op OpCode) PushSize() int {
	return opcodeInfoTable[op].ImmediateSize
}
