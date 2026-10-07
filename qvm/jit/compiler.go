// Quantaureum Node source, version 1.0.0.
package jit

import (
	"crypto/sha256"
	"errors"
	"math"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// maxMemoryAlloc limits single memory allocations to prevent OOM attacks.
// EVM memory is word-addressed and gas-metered; this is a defensive ceiling.
const maxMemoryAlloc = 1 << 32 // 4 GiB

// R42-QV-001 FIX: Local safe gas arithmetic helpers, mirroring qvm.SafeMulGas
// and qvm.SafeAddGas. Defined locally to avoid a circular import on qvm.
// Without these, every dynamic-gas multiplication in the JIT path could
// silently overflow to a small value, allowing gas bypass.
var errJITGasOverflow = errors.New("JIT gas overflow")

func safeMulGas(a, b uint64) (uint64, error) {
	if a > 0 && b > math.MaxUint64/a {
		return 0, errJITGasOverflow
	}
	return a * b, nil
}

func safeAddGas(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, errJITGasOverflow
	}
	return a + b, nil
}

// audit-fix P2-1b-4: Dynamic Gas constants (kept consistent with qvm/gas.go). N2 FIX (2026-07-06 R2): Fixed garbled comment.
// These constants are used for dynamic gas calculation during opcode execution; static gas is already deducted in opcodeGasCost. N2 FIX (2026-07-06 R2): Fixed garbled comment.
const (
	gasSHA3Word uint64 = 6  // SHA3 per-word dynamic gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasExpByte  uint64 = 50 // EXP per-byte dynamic gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasCopyWord uint64 = 3  // COPY-class per-word dynamic gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasLogData  uint64 = 8  // LOG per-byte data dynamic gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
)

// audit-fix P2-1b-5: CALL/CREATE dynamic gas constants. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Static GasCall(100) is already deducted in opcodeGasCost; only the extra portion is charged here. N2 FIX (2026-07-06 R2): Fixed garbled comment.
const (
	gasCallCold       uint64 = 2500  // Cold address extra gas: 2600-100 (static already charged 100). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasCallValue      uint64 = 9000  // value transfer gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasCallNewAccount uint64 = 25000 // Transfer-to-new-account gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasCallStipend    uint64 = 2300  // Extra stipend for value transfer (added to subcall gas). N2 FIX (2026-07-06 R2): Fixed garbled comment.
)

// audit-fix P3-1: Memory expansion and storage access dynamic gas constants (kept consistent with qvm/gas.go). N2 FIX (2026-07-06 R2): Fixed garbled comment.
const (
	gasMemoryPerWord   uint64 = 3     // Memory per-word gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasMemoryQuadCoeff uint64 = 512   // Memory quadratic coefficient denominator. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasSLoadCold       uint64 = 2100  // Cold SLOAD total cost. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasSLoadWarm       uint64 = 100   // Warm SLOAD total cost (= static already charged 100). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasSStoreSet       uint64 = 20000 // SSTORE: zero to non-zero. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasSStoreReset     uint64 = 2900  // SSTORE: non-zero to non-zero, or non-zero to zero. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasSStoreClear     uint64 = 4800  // SSTORE clear refund. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasSStoreNoop      uint64 = 100   // SSTORE: value unchanged. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasBalanceCold     uint64 = 2600  // Cold BALANCE total cost. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasBalanceWarm     uint64 = 100   // Warm BALANCE total cost (= static already charged 100). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	gasLogTopic        uint64 = 375   // LOG per-topic gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
)

// memoryExpansionCost calculates the additional gas cost for expanding memory.
// audit-fix P3-1: Equivalent implementation to qvm.MemoryExpansionCost to avoid circular import. N2 FIX (2026-07-06 R2): Fixed garbled comment.
//
//	SYNC NOTE: This implementation MUST stay identical to
//
// qvm.MemoryExpansionCost (qvm/memory.go:336). The JIT package cannot import
// qvm (circular dependency: qvm imports qvm/jit). Any change to either
// implementation MUST be mirrored in the other to prevent consensus
// determinism issues. A consistency test (TestJITInterpreterMemoryGasParity)
// verifies they produce identical results.
func memoryExpansionCost(currentSize, newSize uint64) uint64 {
	if newSize <= currentSize {
		return 0
	}
	// Prevent overflow. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	if newSize > 32*1024*1024 { // 32MB safety ceiling. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		return math.MaxUint64
	}
	currentWords := (currentSize + 31) / 32
	newWords := (newSize + 31) / 32
	// FIX: Check for overflow in quadratic cost calculation.
	//
	// P3-QVM-MEMOVERFLOW FIX (R30, 2026-07-27): Moved the overflow check
	// BEFORE the multiplication. Previously the order was:
	//   currentCost := currentWords * gasMemoryPerWord  // multiply first
	//   if currentWords > math.MaxUint64/currentWords { return max }  // check second
	// The check was for the QUADRATIC term (currentWords*currentWords),
	// not the linear term (currentWords*gasMemoryPerWord). However, the
	// pattern of "multiply then check" is fragile — a future change to
	// gasMemoryPerWord (e.g., to a larger value) could make the linear
	// multiplication overflow BEFORE the check runs, silently wrapping to
	// a small value and bypassing the gas ceiling.
	//
	// Under the current 32MB ceiling: currentWords <= 1M, gasMemoryPerWord=3,
	// so currentWords*gasMemoryPerWord <= 3M — far below uint64 max. The
	// fix is defensive (no behavior change today) but makes the code
	// robust to future parameter changes.
	//
	// The correct order is:
	//   1. Check overflow for linear term (currentWords * gasMemoryPerWord).
	//   2. Compute linear term.
	//   3. Check overflow for quadratic term (currentWords * currentWords).
	//   4. Compute quadratic term.
	//   5. Check overflow for linear + quadratic sum.
	//   6. Compute sum.
	if currentWords > 0 && currentWords > math.MaxUint64/gasMemoryPerWord {
		return math.MaxUint64
	}
	currentCost := currentWords * gasMemoryPerWord
	if currentWords > 0 && currentWords > math.MaxUint64/currentWords {
		return math.MaxUint64
	}
	quadCurrent := (currentWords * currentWords) / gasMemoryQuadCoeff
	if quadCurrent > math.MaxUint64-currentCost {
		return math.MaxUint64
	}
	currentCost += quadCurrent

	if newWords > 0 && newWords > math.MaxUint64/gasMemoryPerWord {
		return math.MaxUint64
	}
	newCost := newWords * gasMemoryPerWord
	if newWords > 0 && newWords > math.MaxUint64/newWords {
		return math.MaxUint64
	}
	quadNew := (newWords * newWords) / gasMemoryQuadCoeff
	if quadNew > math.MaxUint64-newCost {
		return math.MaxUint64
	}
	newCost += quadNew

	if newCost < currentCost {
		return 0
	}
	return newCost - currentCost
}

// chargeMemoryExpansion charges gas for memory expansion from current size to newSize.
// audit-fix P3-1: JIT memory operations must charge memory expansion gas the same as the interpreter. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func chargeMemoryExpansion(env VMEnvironment, newSize uint64) error {
	currentSize := env.Memory().Len()
	cost := memoryExpansionCost(currentSize, newSize)
	if cost > 0 {
		if err := env.Gas().Consume(cost); err != nil {
			return err
		}
	}
	return nil
}

// ErrExecutionReverted is the error returned when a REVERT opcode is executed.
// This mirrors qvm.ErrExecutionReverted to avoid circular imports.
var ErrExecutionReverted = errors.New("execution reverted")

// ErrMemoryOverflow is returned when a memory operation would overflow.
var ErrMemoryOverflow = errors.New("memory overflow")

// ErrWriteProtection is returned when a state-modifying operation is attempted in a read-only context.
var ErrWriteProtection = errors.New("write protection")

type OpCode byte

const (
	STOP     OpCode = 0x00
	JUMP     OpCode = 0x01
	JUMPI    OpCode = 0x02
	JUMPDEST OpCode = 0x03
	PC       OpCode = 0x04
	NOP      OpCode = 0x05
	RETURN   OpCode = 0x06
	REVERT   OpCode = 0x07
	INVALID  OpCode = 0x08
	// audit-fix P2-1b-7: Complete missing opcodes (values consistent with qvm/opcodes.go). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	SIGNEXTEND OpCode = 0x09 // Sign-extend byte k of value x
	PUSH0      OpCode = 0x0A // Push 0 onto stack (EIP-3854)

	PUSH1  OpCode = 0x10
	PUSH2  OpCode = 0x11
	PUSH4  OpCode = 0x12
	PUSH8  OpCode = 0x13
	PUSH16 OpCode = 0x14
	PUSH32 OpCode = 0x15
	POP    OpCode = 0x16

	// Extended PUSH operations for EVM compatibility (0xB0-0xC9)
	PUSH3  OpCode = 0xB0
	PUSH5  OpCode = 0xB1
	PUSH6  OpCode = 0xB2
	PUSH7  OpCode = 0xB3
	PUSH9  OpCode = 0xB4
	PUSH10 OpCode = 0xB5
	PUSH11 OpCode = 0xB6
	PUSH12 OpCode = 0xB7
	PUSH13 OpCode = 0xB8
	PUSH14 OpCode = 0xB9
	PUSH15 OpCode = 0xBA
	PUSH17 OpCode = 0xBB
	PUSH18 OpCode = 0xBC
	PUSH19 OpCode = 0xBD
	PUSH20 OpCode = 0xBE
	PUSH21 OpCode = 0xBF
	PUSH22 OpCode = 0xC0
	PUSH23 OpCode = 0xC1
	PUSH24 OpCode = 0xC2
	PUSH25 OpCode = 0xC3
	PUSH26 OpCode = 0xC4
	PUSH27 OpCode = 0xC5
	PUSH28 OpCode = 0xC6
	PUSH29 OpCode = 0xC7
	PUSH30 OpCode = 0xC8
	PUSH31 OpCode = 0xC9

	DUP1   OpCode = 0x17
	DUP2   OpCode = 0x18
	DUP3   OpCode = 0x19
	DUP4   OpCode = 0x1A
	DUP5   OpCode = 0xD0
	DUP6   OpCode = 0xD1
	DUP7   OpCode = 0xD2
	DUP8   OpCode = 0xD3
	DUP9   OpCode = 0xD4
	DUP10  OpCode = 0xD5
	DUP11  OpCode = 0xD6
	DUP12  OpCode = 0xD7
	DUP13  OpCode = 0xD8
	DUP14  OpCode = 0xD9
	DUP15  OpCode = 0xDA
	DUP16  OpCode = 0xDB
	SWAP1  OpCode = 0x1B
	SWAP2  OpCode = 0x1C
	SWAP3  OpCode = 0x1D
	SWAP4  OpCode = 0x1E
	SWAP5  OpCode = 0xDC
	SWAP6  OpCode = 0xDD
	SWAP7  OpCode = 0xDE
	SWAP8  OpCode = 0xDF
	SWAP9  OpCode = 0xE0
	SWAP10 OpCode = 0xE1
	SWAP11 OpCode = 0xE2
	SWAP12 OpCode = 0xE3
	SWAP13 OpCode = 0xE4
	SWAP14 OpCode = 0xE5
	SWAP15 OpCode = 0xE6
	SWAP16 OpCode = 0xE7

	ADD    OpCode = 0x20
	SUB    OpCode = 0x21
	MUL    OpCode = 0x22
	DIV    OpCode = 0x23
	MOD    OpCode = 0x24
	SDIV   OpCode = 0x25
	SMOD   OpCode = 0x26
	ADDMOD OpCode = 0x27
	MULMOD OpCode = 0x28
	EXP    OpCode = 0x29

	LT     OpCode = 0x30
	GT     OpCode = 0x31
	SLT    OpCode = 0x32
	SGT    OpCode = 0x33
	EQ     OpCode = 0x34
	ISZERO OpCode = 0x35

	AND  OpCode = 0x40
	OR   OpCode = 0x41
	XOR  OpCode = 0x42
	NOT  OpCode = 0x43
	SHL  OpCode = 0x44
	SHR  OpCode = 0x45
	SAR  OpCode = 0x46
	BYTE OpCode = 0x47

	MLOAD   OpCode = 0x50
	MSTORE  OpCode = 0x51
	MSTORE8 OpCode = 0x52
	MSIZE   OpCode = 0x53
	MCOPY   OpCode = 0x54

	SLOAD  OpCode = 0x60
	SSTORE OpCode = 0x61
	// audit-fix P2-1b-7: Transient storage (EIP-1153). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	TLOAD  OpCode = 0x62
	TSTORE OpCode = 0x63

	ADDRESS      OpCode = 0x70
	BALANCE      OpCode = 0x71
	ORIGIN       OpCode = 0x72
	CALLER       OpCode = 0x73
	CALLVALUE    OpCode = 0x74
	CALLDATALOAD OpCode = 0x75
	CALLDATASIZE OpCode = 0x76
	CALLDATACOPY OpCode = 0x77
	CODESIZE     OpCode = 0x78
	CODECOPY     OpCode = 0x79
	GASPRICE     OpCode = 0x7A
	GASLIMIT     OpCode = 0x7B
	GAS          OpCode = 0x7C
	BLOCKHASH    OpCode = 0x7D
	COINBASE     OpCode = 0x7E
	TIMESTAMP    OpCode = 0x7F

	NUMBER      OpCode = 0x80
	CHAINID     OpCode = 0x81
	SELFBALANCE OpCode = 0x82
	// audit-fix P2-1b-7: External account code query (EIP-1052/4399/4844/3198). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	EXTCODESIZE OpCode = 0x83
	EXTCODECOPY OpCode = 0x84
	EXTCODEHASH OpCode = 0x85
	PREVRANDAO  OpCode = 0x86
	BLOBHASH    OpCode = 0x87

	SHA3      OpCode = 0x88
	KECCAK256 OpCode = 0x89

	// audit-fix P2-1b-7: BASEFee (EIP-3198)
	BASEFEE OpCode = 0x8D

	CALL         OpCode = 0x90
	CALLCODE     OpCode = 0x91
	DELEGATECALL OpCode = 0x92
	STATICCALL   OpCode = 0x93
	CREATE       OpCode = 0x94
	CREATE2      OpCode = 0x95
	// audit-fix P2-1b-7: EIP-7702 account abstraction. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	AUTH     OpCode = 0x96
	AUTHCALL OpCode = 0x97

	RETURNDATASIZE OpCode = 0x3d
	RETURNDATACOPY OpCode = 0x3e

	LOG0 OpCode = 0xA0
	LOG1 OpCode = 0xA1
	LOG2 OpCode = 0xA2
	LOG3 OpCode = 0xA3
	LOG4 OpCode = 0xA4

	SELFDESTRUCT OpCode = 0xF0

	// audit-fix P2-1b-7: BLOBBASEFEE (EIP-7516)
	BLOBBASEFEE OpCode = 0xE8

	// Post-Quantum Crypto Operations
	KYBER_KEYGEN   OpCode = 0x8A
	KYBER_ENCAPS   OpCode = 0x8B
	KYBER_DECAPS   OpCode = 0x8C
	KYBER_ZERO_KEY OpCode = 0x8E
)

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

func (op OpCode) PushSize() int {
	switch op {
	case PUSH1:
		return 1
	case PUSH2:
		return 2
	case PUSH3:
		return 3
	case PUSH4:
		return 4
	case PUSH5:
		return 5
	case PUSH6:
		return 6
	case PUSH7:
		return 7
	case PUSH8:
		return 8
	case PUSH9:
		return 9
	case PUSH10:
		return 10
	case PUSH11:
		return 11
	case PUSH12:
		return 12
	case PUSH13:
		return 13
	case PUSH14:
		return 14
	case PUSH15:
		return 15
	case PUSH16:
		return 16
	case PUSH17:
		return 17
	case PUSH18:
		return 18
	case PUSH19:
		return 19
	case PUSH20:
		return 20
	case PUSH21:
		return 21
	case PUSH22:
		return 22
	case PUSH23:
		return 23
	case PUSH24:
		return 24
	case PUSH25:
		return 25
	case PUSH26:
		return 26
	case PUSH27:
		return 27
	case PUSH28:
		return 28
	case PUSH29:
		return 29
	case PUSH30:
		return 30
	case PUSH31:
		return 31
	case PUSH32:
		return 32
	default:
		return 0
	}
}

type Word [32]byte

func NewWord(data []byte) Word {
	var w Word
	if len(data) > 32 {
		data = data[len(data)-32:]
	}
	copy(w[32-len(data):], data)
	return w
}

func NewWordFromUint64(v uint64) Word {
	var w Word
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

func (w Word) ToUint64() uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(w[31-i]) << (8 * i)
	}
	return v
}

func (w Word) ToBigInt() *big.Int {
	return new(big.Int).SetBytes(w[:])
}

func (w Word) IsZero() bool {
	for _, b := range w {
		if b != 0 {
			return false
		}
	}
	return true
}

func (w Word) Bytes() []byte {
	return w[:]
}

type Hash [32]byte
type Address [20]byte

type Log struct {
	Address Address
	Topics  []Hash
	Data    []byte
}

type VMContext interface {
	Origin() Address
	GasPrice() *big.Int
	Caller() Address
	Address() Address
	Value() *big.Int
	BlockNumber() uint64
	Timestamp() int64
	Coinbase() Address
	GasLimit() uint64
	ChainID() uint64
	Code() []byte
	Input() []byte
	Depth() int
	// audit-fix P2-1b-7: Add context methods to support PREVRANDAO/BLOBHASH/BASEFEE/BLOBBASEFEE. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	PrevRandao() Hash
	BlobHashes() []Hash
	BaseFee() uint64
	BlobBaseFee() uint64
}

type VMState interface {
	GetBalance(addr Address) *big.Int
	SetBalance(addr Address, balance *big.Int)
	GetNonce(addr Address) uint64
	SetNonce(addr Address, nonce uint64)
	GetCode(addr Address) []byte
	SetCode(addr Address, code []byte)
	GetCodeHash(addr Address) Hash
	GetCodeSize(addr Address) int
	GetState(addr Address, key Hash) Hash
	SetState(addr Address, key, value Hash)
	Exist(addr Address) bool
	Empty(addr Address) bool
	Snapshot() int
	RevertToSnapshot(id int)
	SelfDestruct(addr Address)
	HasSelfDestructed(addr Address) bool
	AddAddressToAccessList(addr Address)
	AddSlotToAccessList(addr Address, slot Hash)
	AddressInAccessList(addr Address) bool
	SlotInAccessList(addr Address, slot Hash) (bool, bool)
}

// committedStateReader is an optional VMState capability that returns the
// storage value committed at the start of the transaction (i.e. before any
// in-transaction dirty writes). It is used by makeSStoreOp for EIP-3529 gas
// refund calculation. StateDB implementations that cannot supply the
// committed value simply omit this method; makeSStoreOp then falls back to
// the current live value, preserving prior behavior.
//
// R7 P0-4 FIX (QVM-, 2026-07-17): Without this check, the JIT SSTORE
// refund diverged from the interpreter path (which checks original), causing
// a consensus-splitting gasUsed difference when JIT is enabled.
type committedStateReader interface {
	GetCommittedState(addr Address, key Hash) Hash
}

type VMStack interface {
	Push(w Word) error
	Pop() (Word, error)
	PopUint64() (uint64, error)
	PopBigInt() (*big.Int, error)
	PushUint64(v uint64) error
	PushBigInt(v *big.Int) error
	Dup(n int) error
	Swap(n int) error
	Len() int
}

type VMMemory interface {
	Load(offset, size uint64) []byte
	Store(offset uint64, data []byte) error
	Len() uint64
}

type VMGas interface {
	Available() uint64
	Consume(amount uint64) error
	FinalUsed() uint64
	RefundAmount() uint64
	// audit-fix P2-1b-5: Return refunds unused gas (after subcall). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	Return(amount uint64)
	// audit-fix P3-1: Refund adds gas refund (e.g. SSTORE clearing storage). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	Refund(amount uint64)
}

type VMEnvironment interface {
	Stack() VMStack
	Memory() VMMemory
	Gas() VMGas
	Ctx() VMContext
	StateDB() VMState
	Stopped() bool
	SetStopped(v bool)
	GetBlockHash(blockNum uint64) Hash
	AddLog(log *Log)
	SetReturnData(data []byte)
	ReturnData() []byte
	SetReverted(v bool)
	SetErr(err error)
	Err() error
	PC() uint64
	SetPC(pc uint64)
	JumpDests() map[uint64]bool
	// audit-fix P2-1b-9: Add ReadOnly check to prevent state modification in STATICCALL context. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	ReadOnly() bool
	// audit-fix P2-1b-7: Transient storage (EIP-1153) for TLOAD/TSTORE. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	GetTransientState(addr Address, key Hash) Hash
	SetTransientState(addr Address, key, value Hash)

	// Call operations - delegated to the interpreter
	Call(caller Address, addr Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error)
	CallCode(caller Address, addr Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error)
	DelegateCall(caller Address, addr Address, input []byte, gas uint64) ([]byte, uint64, error)
	StaticCall(caller Address, addr Address, input []byte, gas uint64) ([]byte, uint64, error)
	Create(caller Address, input []byte, gas uint64, value *big.Int, salt *Hash) ([]byte, Address, uint64, error)
	LastReturnData() []byte
	SelfDestruct(addr Address)

	// FIX: Expose reentrancy state so the JIT compiler can charge the
	// 2300 reentrancy guard gas BEFORE the 63/64 rule, matching the interpreter
	// path (call.go). Previously the JIT compiler could not check reentrancy at
	// compile time, so the 2300 was charged in jit_adapter.go AFTER the 63/64
	// split, giving the callee slightly more gas than the interpreter.
	IsAddressActive(addr Address) bool
	CallDepth() int
}

type MicroOp func(env VMEnvironment) error

type ExecutionPlan struct {
	CodeHash   [32]byte
	Ops        []MicroOp
	OpPCs      []uint64       // PC value for each op (for JUMP/JUMPI support)
	OpGasCosts []uint64       // pre-computed gas cost for each op
	PCToIdx    map[uint64]int // cached reverse mapping: pc -> op index for JUMP/JUMPI
	JumpDests  map[uint64]int
	CodeLength int
	TotalGas   uint64 // pre-computed total gas for the plan
}

type JITCompiler struct {
	cache *CompilationCache
}

func NewJITCompiler(cacheSize int) *JITCompiler {
	return &JITCompiler{
		cache: NewCompilationCache(cacheSize),
	}
}

func (c *JITCompiler) Cache() *CompilationCache {
	return c.cache
}

func (c *JITCompiler) Compile(code []byte) (*ExecutionPlan, error) {
	codeHash := sha256.Sum256(code)

	if plan, ok := c.cache.Get(codeHash); ok {
		return plan, nil
	}

	plan := c.compileBytecode(code, codeHash)
	c.cache.Put(codeHash, plan)
	return plan, nil
}

// opcodeGasCost returns the static gas cost for a given JIT opcode.
// audit-fix P3-1: These costs must be fully consistent with opcodeInfoTable in qvm/gas.go. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Otherwise JIT and interpreter would consume different gas for the same bytecode, breaking consensus. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func opcodeGasCost(op OpCode) uint64 {
	switch op {
	// GasZero = 0
	case STOP, RETURN, REVERT, SELFDESTRUCT:
		return 0

	// GasJumpDest = 1
	case JUMPDEST:
		return 1

		// NOP = 1 (consistent with interpreter opcodeInfoTable). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case NOP:
		return 1

	// GasBase = 2
	case ADDRESS, CALLER, CALLVALUE, CALLDATASIZE, CODESIZE,
		GASPRICE, GASLIMIT, GAS, COINBASE,
		TIMESTAMP, NUMBER, CHAINID, POP,
		PC, RETURNDATASIZE,
		// audit-fix P2-1b-7: Add GasBase opcodes. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		PUSH0, PREVRANDAO, BLOBHASH, BASEFEE, BLOBBASEFEE:
		return 2

	// GasVeryLow = 3
	case ADD, SUB, LT, GT, SLT, SGT, EQ, ISZERO,
		AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR,
		MLOAD, MSTORE, MSTORE8, MCOPY, RETURNDATACOPY,
		// audit-fix P2-1b-7: EXTCODECOPY = GasVeryLow
		EXTCODECOPY:
		return 3

	// SIGNEXTEND = 5 (consistent with interpreter opcodeInfoTable, not GasVeryLow). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case SIGNEXTEND:
		return 5

	// PUSH1-PUSH32 = GasVeryLow = 3
	case PUSH1, PUSH2, PUSH3, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8,
		PUSH9, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16,
		PUSH17, PUSH18, PUSH19, PUSH20, PUSH21, PUSH22, PUSH23, PUSH24,
		PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH30, PUSH31, PUSH32:
		return 3

	// DUP1-DUP16 = GasVeryLow = 3
	case DUP1, DUP2, DUP3, DUP4, DUP5, DUP6, DUP7, DUP8,
		DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16:
		return 3

	// SWAP1-SWAP16 = GasVeryLow = 3
	case SWAP1, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7, SWAP8,
		SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16:
		return 3

	// GasLow = 5
	case MUL, DIV, MOD,
		// audit-fix P2-1b-7: SDIV/SMOD = GasLow
		SDIV, SMOD,
		// SELFBALANCE = 5 (consistent with interpreter opcodeInfoTable, not GasBase). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		SELFBALANCE:
		return 5

	// GasMid = 8
	case ADDMOD, MULMOD, JUMP:
		return 8

	// JUMPI = 10 (consistent with interpreter opcodeInfoTable, not GasMid=8). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case JUMPI:
		return 10

	// GasHigh = 10
	case EXP:
		return 10

	// BLOCKHASH = 20 (consistent with interpreter opcodeInfoTable, not GasBase=2). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case BLOCKHASH:
		return 20

		// GasSLoad = 100 (static base cost; cold access surcharge is dynamically charged in MicroOp). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case SLOAD,
		// audit-fix P2-1b-7: TLOAD = GasSLoad
		TLOAD:
		return 100

		// GasSStore base = 100 (static base cost; cold access surcharge and storage cost are dynamically charged in MicroOp). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case SSTORE,
		// audit-fix P2-1b-7: TSTORE = GasSStore base
		TSTORE:
		return 100

		// GasCall = 100 (static base cost; cold access surcharge etc. dynamically charged in MicroOp). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case CALL, CALLCODE, DELEGATECALL, STATICCALL,
		// audit-fix P2-1b-7: EXTCODESIZE/EXTCODEHASH/AUTH/AUTHCALL = 100
		EXTCODESIZE, EXTCODEHASH, AUTH, AUTHCALL:
		return 100

		// BALANCE = 100 (static base cost; cold access surcharge dynamically charged in MicroOp). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case BALANCE:
		return 100

		// GasSHA3 = 30 (static base cost; per-word cost dynamically charged in MicroOp). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case SHA3, KECCAK256:
		return 30

		// GasLog = 375 (static base cost; topic and data costs dynamically charged in MicroOp). N2 FIX (2026-07-06 R2): Fixed garbled comment.
	// audit-fix P3-1: Consistent with interpreter; LOG static gas only charges base cost 375. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	// topic(375*count) and data(8*size) are dynamically charged in MicroOp. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case LOG0, LOG1, LOG2, LOG3, LOG4:
		return 375

	// GasCreate / GasCreate2 = 32000
	case CREATE, CREATE2:
		return 32000

	// CALLDATALOAD = GasVeryLow = 3
	case CALLDATALOAD:
		return 3

	// CALLDATACOPY = GasVeryLow + copy cost
	case CALLDATACOPY:
		return 3

	// CODECOPY = GasVeryLow + copy cost
	case CODECOPY:
		return 3

	// MSIZE = GasBase = 2
	case MSIZE:
		return 2

	// ORIGIN = GasBase = 2
	case ORIGIN:
		return 2

	// Post-quantum crypto: high cost
	case KYBER_KEYGEN:
		return 50000
	case KYBER_ENCAPS:
		return 25000
	case KYBER_DECAPS:
		return 25000
	case KYBER_ZERO_KEY:
		return 3

	default:
		return 0
	}
}

func (c *JITCompiler) compileBytecode(code []byte, codeHash [32]byte) *ExecutionPlan {
	plan := &ExecutionPlan{
		CodeHash:   codeHash,
		JumpDests:  make(map[uint64]int),
		CodeLength: len(code),
	}

	jumpDests := analyzeJumpDests(code)
	plan.JumpDests = jumpDests

	taggedOps := make([]taggedOp, 0, len(code)/2)
	opPCs := make([]uint64, 0, len(code)/2)
	opGasCosts := make([]uint64, 0, len(code)/2)
	pc := uint64(0)

	for pc < uint64(len(code)) {
		op := OpCode(code[pc])
		pcVal := pc
		gasCost := opcodeGasCost(op)

		switch {
		case op.IsPush():
			size := op.PushSize()
			start := pc + 1
			end := start + uint64(size)
			if end > uint64(len(code)) {
				end = uint64(len(code))
			}
			data := make([]byte, size)
			copy(data, code[start:end])
			taggedOps = append(taggedOps, taggedOp{op: op, microOp: makePushOp(data), pushData: data})
			opPCs = append(opPCs, pcVal)
			opGasCosts = append(opGasCosts, gasCost)
			pc = end

		case op == JUMPDEST:
			jumpDests[pc] = len(taggedOps)
			taggedOps = append(taggedOps, taggedOp{op: op, microOp: makeNoOp()})
			opPCs = append(opPCs, pcVal)
			opGasCosts = append(opGasCosts, gasCost)
			pc++

		case op == PC:
			taggedOps = append(taggedOps, taggedOp{op: op, microOp: makePCOp(pcVal)})
			opPCs = append(opPCs, pcVal)
			opGasCosts = append(opGasCosts, gasCost)
			pc++

		default:
			microOp := compileOp(op)
			if microOp != nil {
				taggedOps = append(taggedOps, taggedOp{op: op, microOp: microOp})
				opPCs = append(opPCs, pcVal)
				opGasCosts = append(opGasCosts, gasCost)
			}
			pc++
		}
	}

	// Apply peephole optimization with opcode tags
	// audit-fix P2-1b-2: Use the optimized jumpDests, not the pre-optimization old index. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	ops, opPCs, opGasCosts, jumpDestsOptimized := optimizeTaggedOps(taggedOps, opPCs, opGasCosts)

	// Build PCToIdx cache for JUMP/JUMPI resolution (using optimized indices)
	pcToIdx := jumpDestsOptimized

	// Compute total gas
	var totalGas uint64
	for _, g := range opGasCosts {
		totalGas += g
	}

	plan.Ops = ops
	plan.OpPCs = opPCs
	plan.OpGasCosts = opGasCosts
	plan.PCToIdx = pcToIdx
	plan.TotalGas = totalGas
	return plan
}

// L10-029: WARNING - compileOp() is INCOMPLETE. It does not handle all QVM. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// opcodes (e.g., CALL, CALLCODE, DELEGATECALL, STATICCALL, CREATE, CREATE2,
// AUTHCALL, EXTCODESIZE, EXTCODECOPY, EXTCODEHASH, SELFDESTRUCT, LOG*).
// The JIT compiler is disabled by default (jitEnabled=false in Executor).
// Do NOT enable JIT until this function is fully implemented and all
// opcodes are supported. See qvm/executor.go NewExecutor().
//
// R40-P3-03 (2026-08-03) — liveness note: compileOp is NOT dead code. It
// is invoked from `Compile` (this file, compiler.go:858) which is reached
// from the JIT executeWithJIT path enabled via `Executor.enableJITForTesting`
// (qvm/executor.go:155) — which is gated by a deliberately higher barrier
// than production (`QAU_PRODUCTION=1` hard-blocks JIT at executor.go:249).
// The qvm JIT consistency / stress tests (`qvm/jit_consistency_test.go`,
// `qvm/executor_r15_crit001_jit_prod_guard_test.go`, etc.) exercise this
// path, which is why `unused` linter does NOT flag compileOp — there are
// live callers. DO NOT remove this function or mark it `//nolint:unused`;
// instead, finish implementing the missing opcodes when JIT is unblocked.
func compileOp(op OpCode) MicroOp {
	switch op {
	case STOP:
		return makeStopOp()
	case JUMP:
		return makeJumpOp()
	case JUMPI:
		return makeJumpIOp()
	case RETURN:
		return makeReturnOp()
	case REVERT:
		return makeRevertOp()
	case ADD:
		return makeAddOp()
	case SUB:
		return makeSubOp()
	case MUL:
		return makeMulOp()
	case DIV:
		return makeDivOp()
	case MOD:
		return makeModOp()
	case ADDMOD:
		return makeAddModOp()
	case MULMOD:
		return makeMulModOp()
	case EXP:
		return makeExpOp()
	case LT:
		return makeLtOp()
	case GT:
		return makeGtOp()
	case SLT:
		return makeSltOp()
	case SGT:
		return makeSgtOp()
	case EQ:
		return makeEqOp()
	case ISZERO:
		return makeIsZeroOp()
	case AND:
		return makeAndOp()
	case OR:
		return makeOrOp()
	case XOR:
		return makeXorOp()
	case NOT:
		return makeNotOp()
	case SHL:
		return makeShlOp()
	case SHR:
		return makeShrOp()
	case SAR:
		return makeSarOp()
	case BYTE:
		return makeByteOp()
	case POP:
		return makePopOp()
	case DUP1:
		return makeDupOp(1)
	case DUP2:
		return makeDupOp(2)
	case DUP3:
		return makeDupOp(3)
	case DUP4:
		return makeDupOp(4)
	case DUP5:
		return makeDupOp(5)
	case DUP6:
		return makeDupOp(6)
	case DUP7:
		return makeDupOp(7)
	case DUP8:
		return makeDupOp(8)
	case DUP9:
		return makeDupOp(9)
	case DUP10:
		return makeDupOp(10)
	case DUP11:
		return makeDupOp(11)
	case DUP12:
		return makeDupOp(12)
	case DUP13:
		return makeDupOp(13)
	case DUP14:
		return makeDupOp(14)
	case DUP15:
		return makeDupOp(15)
	case DUP16:
		return makeDupOp(16)
	case SWAP1:
		return makeSwapOp(1)
	case SWAP2:
		return makeSwapOp(2)
	case SWAP3:
		return makeSwapOp(3)
	case SWAP4:
		return makeSwapOp(4)
	case SWAP5:
		return makeSwapOp(5)
	case SWAP6:
		return makeSwapOp(6)
	case SWAP7:
		return makeSwapOp(7)
	case SWAP8:
		return makeSwapOp(8)
	case SWAP9:
		return makeSwapOp(9)
	case SWAP10:
		return makeSwapOp(10)
	case SWAP11:
		return makeSwapOp(11)
	case SWAP12:
		return makeSwapOp(12)
	case SWAP13:
		return makeSwapOp(13)
	case SWAP14:
		return makeSwapOp(14)
	case SWAP15:
		return makeSwapOp(15)
	case SWAP16:
		return makeSwapOp(16)
	case MLOAD:
		return makeMLoadOp()
	case MSTORE:
		return makeMStoreOp()
	case MSTORE8:
		return makeMStore8Op()
	case MSIZE:
		return makeMSizeOp()
	case MCOPY:
		return makeMCopyOp()
	case SLOAD:
		return makeSLoadOp()
	case SSTORE:
		return makeSStoreOp()
	case ADDRESS:
		return makeAddressOp()
	case BALANCE:
		return makeBalanceOp()
	case ORIGIN:
		return makeOriginOp()
	case CALLER:
		return makeCallerOp()
	case CALLVALUE:
		return makeCallValueOp()
	case CALLDATALOAD:
		return makeCallDataLoadOp()
	case CALLDATASIZE:
		return makeCallDataSizeOp()
	case CALLDATACOPY:
		return makeCallDataCopyOp()
	case CODESIZE:
		return makeCodeSizeOp()
	case CODECOPY:
		return makeCodeCopyOp()
	case GASPRICE:
		return makeGasPriceOp()
	case GASLIMIT:
		return makeGasLimitOp()
	case GAS:
		return makeGasOp()
	case BLOCKHASH:
		return makeBlockHashOp()
	case COINBASE:
		return makeCoinbaseOp()
	case TIMESTAMP:
		return makeTimestampOp()
	case NUMBER:
		return makeNumberOp()
	case CHAINID:
		return makeChainIDOp()
	case SELFBALANCE:
		return makeSelfBalanceOp()
	case SHA3, KECCAK256:
		return makeSha3Op()
	case RETURNDATASIZE:
		return makeReturnDataSizeOp()
	case RETURNDATACOPY:
		return makeReturnDataCopyOp()
	case CALL:
		return makeCallOp()
	case CALLCODE:
		return makeCallCodeOp()
	case DELEGATECALL:
		return makeDelegateCallOp()
	case STATICCALL:
		return makeStaticCallOp()
	case CREATE:
		return makeCreateOp(false)
	case CREATE2:
		return makeCreateOp(true)
	case KYBER_KEYGEN, KYBER_ENCAPS, KYBER_DECAPS, KYBER_ZERO_KEY:
		return makeKyberOp()
	case SELFDESTRUCT:
		return makeSelfDestructOp()
	case LOG0:
		return makeLogOp(0)
	case LOG1:
		return makeLogOp(1)
	case LOG2:
		return makeLogOp(2)
	case LOG3:
		return makeLogOp(3)
	case LOG4:
		return makeLogOp(4)
	case NOP, JUMPDEST:
		return makeNoOp()
	// audit-fix P2-1b-7: Complete the 15 missing opcodes. N2 FIX (2026-07-06 R2): Fixed garbled comment.
	case PUSH0:
		return makePush0Op()
	case SIGNEXTEND:
		return makeSignExtendOp()
	case SDIV:
		return makeSdivOp()
	case SMOD:
		return makeSmodOp()
	case TLOAD:
		return makeTLoadOp()
	case TSTORE:
		return makeTStoreOp()
	case EXTCODESIZE:
		return makeExtCodeSizeOp()
	case EXTCODECOPY:
		return makeExtCodeCopyOp()
	case EXTCODEHASH:
		return makeExtCodeHashOp()
	case PREVRANDAO:
		return makePrevRandaoOp()
	case BLOBHASH:
		return makeBlobHashOp()
	case BASEFEE:
		return makeBaseFeeOp()
	case BLOBBASEFEE:
		return makeBlobBaseFeeOp()
	case AUTH:
		return makeAuthOp()
	case AUTHCALL:
		return makeAuthCallOp()
	default:
		return makeInvalidOp()
	}
}

func (c *JITCompiler) Execute(plan *ExecutionPlan, env VMEnvironment) error {
	ops := plan.Ops
	gasCosts := plan.OpGasCosts
	pcToIdx := plan.PCToIdx
	n := len(ops)

	for i := 0; i < n; {
		// Use pre-computed per-op gas cost instead of fixed 3
		if gasCosts[i] > 0 {
			if err := env.Gas().Consume(gasCosts[i]); err != nil {
				return err
			}
		}
		// Set the expected PC for this op and record it to detect JUMP/JUMPI changes
		expectedPC := plan.OpPCs[i]
		env.SetPC(expectedPC)
		if err := ops[i](env); err != nil {
			return err
		}
		if env.Stopped() {
			return nil
		}
		// Check if PC was changed by JUMP/JUMPI
		curPC := env.PC()
		if curPC != expectedPC {
			// PC changed - find the corresponding op index using cached mapping. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			if idx, ok := pcToIdx[curPC]; ok {
				i = idx
				continue
			}
			// Invalid jump destination
			return ErrInvalidOpcode
		}
		i++
	}
	return nil
}

// withPC wraps a MicroOp. The PC is stored separately in ExecutionPlan.OpPCs.
func withPC(pc uint64, op MicroOp) MicroOp {
	// PC is tracked via ExecutionPlan.OpPCs, not inside the op itself.
	// The withPC wrapper just returns the op as-is since Execute() handles PC.
	return op
}

func analyzeJumpDests(code []byte) map[uint64]int {
	dests := make(map[uint64]int)
	idx := 0
	for pc := uint64(0); pc < uint64(len(code)); {
		op := OpCode(code[pc])
		if op == JUMPDEST {
			dests[pc] = idx
		}
		if op.IsPush() {
			pc += 1 + uint64(op.PushSize())
		} else {
			pc++
		}
		idx++
	}
	return dests
}

// taggedOp bundles a MicroOp with metadata for peephole optimization.
type taggedOp struct {
	op       OpCode
	microOp  MicroOp
	pushData []byte // only set for PUSH ops
}

func optimizePlan(ops []MicroOp, opPCs []uint64, opGasCosts []uint64) ([]MicroOp, []uint64, []uint64) {
	if len(ops) < 2 {
		return ops, opPCs, opGasCosts
	}

	// We need to reconstruct op tags from the compilation context.
	// Since we don't have the original opcodes here, we use a different approach:
	// The optimization is done in compileBytecode where we have the opcodes.
	// This function now just handles the simple cases that don't need opcode info.
	// The real peephole optimization happens in compileBytecode's optimization loop.

	optimized := make([]MicroOp, 0, len(ops))
	optPCs := make([]uint64, 0, len(ops))
	optGasCosts := make([]uint64, 0, len(ops))

	i := 0
	for i < len(ops) {
		optimized = append(optimized, ops[i])
		optPCs = append(optPCs, opPCs[i])
		optGasCosts = append(optGasCosts, opGasCosts[i])
		i++
	}
	return optimized, optPCs, optGasCosts
}

// optimizeTaggedOps performs peephole optimization on tagged ops.
// It merges PUSH+arithmetic, eliminates PUSH+POP, and removes redundant JUMPDESTs.
// Returns optimized ops, PCs, gas costs, and updated jumpDests map (PC -> new index). N2 FIX (2026-07-06 R2): Fixed garbled comment.
// audit-fix P2-1b-2: Previously PCToIdx still used the old index after optimization, causing JUMP to jump to the wrong position. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func optimizeTaggedOps(taggedOps []taggedOp, opPCs []uint64, opGasCosts []uint64) ([]MicroOp, []uint64, []uint64, map[uint64]int) {
	jumpDestsAfter := make(map[uint64]int)

	if len(taggedOps) < 2 {
		ops := make([]MicroOp, len(taggedOps))
		for i, t := range taggedOps {
			ops[i] = t.microOp
			if t.op == JUMPDEST {
				jumpDestsAfter[opPCs[i]] = i
			}
		}
		return ops, opPCs, opGasCosts, jumpDestsAfter
	}

	optimized := make([]MicroOp, 0, len(taggedOps))
	optPCs := make([]uint64, 0, len(taggedOps))
	optGasCosts := make([]uint64, 0, len(taggedOps))

	i := 0
	for i < len(taggedOps) {
		if i+1 < len(taggedOps) {
			// Pattern 1: PUSH + POP -> eliminate both (no-op). N2 FIX (2026-07-06 R2): Fixed garbled comment.
			// audit-fix P3-1: Even if the operation is eliminated, gas must still be charged to maintain interpreter consistency. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			// The interpreter charges PUSH and POP separately; JIT must also charge. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			if taggedOps[i].op.IsPush() && taggedOps[i+1].op == POP {
				mergedGas := opGasCosts[i] + opGasCosts[i+1]
				optimized = append(optimized, makeNoOpWithGas())
				optPCs = append(optPCs, opPCs[i])
				optGasCosts = append(optGasCosts, mergedGas)
				i += 2
				continue
			}

			// Pattern 2: PUSH + ISZERO -> merged: push 1 if value is zero, else 0. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			if taggedOps[i].op.IsPush() && taggedOps[i+1].op == ISZERO {
				data := taggedOps[i].pushData
				mergedGas := opGasCosts[i] + opGasCosts[i+1]
				merged := makePushIsZeroOp(data)
				optimized = append(optimized, merged)
				optPCs = append(optPCs, opPCs[i])
				optGasCosts = append(optGasCosts, mergedGas)
				i += 2
				continue
			}

			// Pattern 3: PUSH + ADD -> merged: pop one, add constant. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			if taggedOps[i].op.IsPush() && taggedOps[i+1].op == ADD {
				data := taggedOps[i].pushData
				mergedGas := opGasCosts[i] + opGasCosts[i+1]
				merged := makePushAddOp(data)
				optimized = append(optimized, merged)
				optPCs = append(optPCs, opPCs[i])
				optGasCosts = append(optGasCosts, mergedGas)
				i += 2
				continue
			}

			// Pattern 4: PUSH + SUB -> merged: pop one, subtract constant. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			if taggedOps[i].op.IsPush() && taggedOps[i+1].op == SUB {
				data := taggedOps[i].pushData
				mergedGas := opGasCosts[i] + opGasCosts[i+1]
				merged := makePushSubOp(data)
				optimized = append(optimized, merged)
				optPCs = append(optPCs, opPCs[i])
				optGasCosts = append(optGasCosts, mergedGas)
				i += 2
				continue
			}

			// Pattern 5: PUSH + DUP -> merged: push value and duplicate top. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			// This is equivalent to pushing the value twice
			if taggedOps[i].op.IsPush() && (taggedOps[i+1].op >= DUP1 && taggedOps[i+1].op <= DUP16) && taggedOps[i+1].op == DUP1 {
				data := taggedOps[i].pushData
				mergedGas := opGasCosts[i] + opGasCosts[i+1]
				merged := makePushDup1Op(data)
				optimized = append(optimized, merged)
				optPCs = append(optPCs, opPCs[i])
				optGasCosts = append(optGasCosts, mergedGas)
				i += 2
				continue
			}
		}

		// No optimization: keep as-is
		// Record JUMPDEST with its new index in the optimized array
		if taggedOps[i].op == JUMPDEST {
			jumpDestsAfter[opPCs[i]] = len(optimized)
		}
		optimized = append(optimized, taggedOps[i].microOp)
		optPCs = append(optPCs, opPCs[i])
		optGasCosts = append(optGasCosts, opGasCosts[i])
		i++
	}

	return optimized, optPCs, optGasCosts, jumpDestsAfter
}

// makeNoOpWithGas creates a no-op that charges gas but does nothing.
// audit-fix P3-1: Used to retain gas charging after PUSH+POP optimization. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeNoOpWithGas() MicroOp {
	return func(env VMEnvironment) error {
		return nil
	}
}

// makePushIsZeroOp creates a merged PUSH+ISZERO: pushes 1 if value is zero, else 0.
func makePushIsZeroOp(data []byte) MicroOp {
	w := NewWord(data)
	isZero := w.IsZero()
	result := Word{}
	if isZero {
		result[31] = 1
	}
	return func(env VMEnvironment) error {
		return env.Stack().Push(result)
	}
}

// makePushAddOp creates a merged PUSH+ADD: pops one value, adds constant, pushes result.
// Original: PUSH constant -> stack has [..., constant], ADD pops a=constant, b=stack_top, pushes a+b. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Merged: skip the PUSH, just pop b from stack and compute b+constant.
func makePushAddOp(data []byte) MicroOp {
	constant := NewWord(data).ToBigInt()
	return func(env VMEnvironment) error {
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		result := new(big.Int).Add(b, constant)
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

// makePushSubOp creates a merged PUSH+SUB: pops one value, computes constant - value, pushes result.
// QVM SUB semantics: pops a(top), b(second), pushes a - b.
// Original: PUSH constant -> stack has [..., constant], SUB pops a=constant(top), b=stack_val(second), pushes a-b = constant - stack_val. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Merged: skip the PUSH, just pop b from stack and compute constant - b.
func makePushSubOp(data []byte) MicroOp {
	constant := NewWord(data).ToBigInt()
	return func(env VMEnvironment) error {
		// Merged: we skip pushing constant, so just pop the original stack top (b)
		// and compute constant - b (matching QVM SUB: a - b where a=constant)
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		result := new(big.Int).Sub(constant, b)
		if result.Sign() < 0 {
			result.Add(result, bigMaxUint256Plus1)
		}
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

// makePushDup1Op creates a merged PUSH+DUP1: pushes the value twice.
func makePushDup1Op(data []byte) MicroOp {
	w := NewWord(data)
	return func(env VMEnvironment) error {
		if err := env.Stack().Push(w); err != nil {
			return err
		}
		return env.Stack().Push(w)
	}
}

var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
var bigMaxUint256Plus1 = new(big.Int).Lsh(big.NewInt(1), 256)

func makePushOp(data []byte) MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().Push(NewWord(data))
	}
}

func makeStopOp() MicroOp {
	return func(env VMEnvironment) error {
		env.SetStopped(true)
		return nil
	}
}

func makeNoOp() MicroOp {
	return func(env VMEnvironment) error {
		return nil
	}
}

func makePCOp(pc uint64) MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(pc)
	}
}

func makeAddOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		result := new(big.Int).Add(a, b)
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

func makeSubOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		result := new(big.Int).Sub(a, b)
		if result.Sign() < 0 {
			result.Add(result, bigMaxUint256Plus1)
		}
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

func makeMulOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		result := new(big.Int).Mul(a, b)
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

func makeDivOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		var result *big.Int
		if b.Sign() == 0 {
			result = new(big.Int)
		} else {
			result = new(big.Int).Div(a, b)
		}
		return env.Stack().PushBigInt(result)
	}
}

func makeModOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		var result *big.Int
		if b.Sign() == 0 {
			result = new(big.Int)
		} else {
			result = new(big.Int).Mod(a, b)
		}
		return env.Stack().PushBigInt(result)
	}
}

func makeExpOp() MicroOp {
	return func(env VMEnvironment) error {
		base, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		exp, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		// audit-fix P2-1b-4: Dynamic gas = 50 * exponent byte count. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Static gas (10) is already deducted in the Execute loop. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		expBytes := (exp.BitLen() + 7) / 8
		dynamicGas, err := safeMulGas(uint64(expBytes), gasExpByte)
		if err != nil {
			return err
		}
		if err := env.Gas().Consume(dynamicGas); err != nil {
			return err
		}
		result := new(big.Int).Exp(base, exp, bigMaxUint256Plus1)
		return env.Stack().PushBigInt(result)
	}
}

func makeLtOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		if a.Cmp(b) < 0 {
			return env.Stack().PushUint64(1)
		}
		return env.Stack().PushUint64(0)
	}
}

func makeGtOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		if a.Cmp(b) > 0 {
			return env.Stack().PushUint64(1)
		}
		return env.Stack().PushUint64(0)
	}
}

func makeEqOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		b, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		if a == b {
			return env.Stack().PushUint64(1)
		}
		return env.Stack().PushUint64(0)
	}
}

func makeIsZeroOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		if a.IsZero() {
			return env.Stack().PushUint64(1)
		}
		return env.Stack().PushUint64(0)
	}
}

func makeAndOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		result := new(big.Int).And(a, b)
		return env.Stack().PushBigInt(result)
	}
}

func makeOrOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		result := new(big.Int).Or(a, b)
		return env.Stack().PushBigInt(result)
	}
}

func makeXorOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		result := new(big.Int).Xor(a, b)
		return env.Stack().PushBigInt(result)
	}
}

func makeNotOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		result := new(big.Int).Not(a)
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

func makeShlOp() MicroOp {
	return func(env VMEnvironment) error {
		shift, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		value, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		if shift.Cmp(big.NewInt(256)) >= 0 {
			return env.Stack().PushUint64(0)
		}
		result := new(big.Int).Lsh(value, uint(shift.Uint64()))
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

func makeShrOp() MicroOp {
	return func(env VMEnvironment) error {
		shift, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		value, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		if shift.Cmp(big.NewInt(256)) >= 0 {
			return env.Stack().PushUint64(0)
		}
		result := new(big.Int).Rsh(value, uint(shift.Uint64()))
		return env.Stack().PushBigInt(result)
	}
}

func makePopOp() MicroOp {
	return func(env VMEnvironment) error {
		_, err := env.Stack().Pop()
		return err
	}
}

func makeDupOp(n int) MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().Dup(n)
	}
}

func makeSwapOp(n int) MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().Swap(n)
	}
}

func makeMLoadOp() MicroOp {
	return func(env VMEnvironment) error {
		offset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// audit-fix P3-1: Overflow check + memory expansion gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if offset > math.MaxUint64-32 {
			return ErrMemoryOverflow
		}
		if err := chargeMemoryExpansion(env, offset+32); err != nil {
			return err
		}
		data := env.Memory().Load(offset, 32)
		return env.Stack().Push(NewWord(data))
	}
}

func makeMStoreOp() MicroOp {
	return func(env VMEnvironment) error {
		offset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		value, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		// audit-fix P2-1b-3: Overflow check to prevent OOM. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if offset > math.MaxUint64-32 {
			return ErrMemoryOverflow
		}
		// audit-fix P3-1: Memory expansion gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if err := chargeMemoryExpansion(env, offset+32); err != nil {
			return err
		}
		return env.Memory().Store(offset, value.Bytes())
	}
}

func makeMStore8Op() MicroOp {
	return func(env VMEnvironment) error {
		offset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		value, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		// audit-fix P2-1b-3: Overflow check. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if offset > math.MaxUint64-1 {
			return ErrMemoryOverflow
		}
		// audit-fix P3-1: Memory expansion gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if err := chargeMemoryExpansion(env, offset+1); err != nil {
			return err
		}
		return env.Memory().Store(offset, value.Bytes()[31:])
	}
}

func makeSLoadOp() MicroOp {
	return func(env VMEnvironment) error {
		key, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		var k Hash
		copy(k[:], key.Bytes())
		// audit-fix P3-1: Cold access dynamic gas (EIP-2929). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Static already charged gasSLoadWarm=100; cold access needs extra gasSLoadCold-gasSLoadWarm=2000. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		addr := env.Ctx().Address()
		if _, slotOk := env.StateDB().SlotInAccessList(addr, k); !slotOk {
			extraCost := gasSLoadCold - gasSLoadWarm
			if err := env.Gas().Consume(extraCost); err != nil {
				return err
			}
			env.StateDB().AddSlotToAccessList(addr, k)
		}
		value := env.StateDB().GetState(addr, k)
		return env.Stack().Push(NewWord(value[:]))
	}
}

func makeSStoreOp() MicroOp {
	return func(env VMEnvironment) error {
		// audit-fix P2-1b-9: Forbid SSTORE in STATICCALL context. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if env.ReadOnly() {
			return ErrWriteProtection
		}
		key, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		value, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		var k, v Hash
		copy(k[:], key.Bytes())
		copy(v[:], value.Bytes())
		addr := env.Ctx().Address()
		// audit-fix P3-1: Cold access dynamic gas (EIP-2929). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Static already charged gasSLoadWarm=100; cold access needs extra gasSLoadCold-gasSLoadWarm=2000. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if _, slotOk := env.StateDB().SlotInAccessList(addr, k); !slotOk {
			extraCost := gasSLoadCold - gasSLoadWarm
			if err := env.Gas().Consume(extraCost); err != nil {
				return err
			}
			env.StateDB().AddSlotToAccessList(addr, k)
		}
		// audit-fix P3-1: Storage cost (based on value change). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		current := env.StateDB().GetState(addr, k)

		// R7 P0-4 FIX (QVM-, 2026-07-17): EIP-3529 — only refund when
		// genuinely clearing pre-existing storage (original != 0). Clearing a
		// slot created earlier in this same transaction (original == 0) yields
		// no refund. Previously the JIT path only checked `current`, so a
		// SSTORE(slot, X) → SSTORE(slot, 0) sequence within one transaction
		// incorrectly received a 4800-gas refund, diverging from the
		// interpreter path and causing a consensus-splitting gasUsed diff.
		// Matches interpreter opSStore (operations.go).
		//
		// QVM-R13-MED-002 (2026-07-21) FIX: Implement full EIP-2200 net gas
		// metering. When the slot is dirty (current != original), dirty
		// writes cost only SLOAD (100) instead of SSTORE_RESET (2900) — the
		// original transition was already charged when the slot was first
		// modified. This must match the interpreter path (operations.go)
		// exactly to avoid a consensus-splitting gasUsed diff.
		var original Hash
		originalKnown := false
		if cr, ok := env.StateDB().(committedStateReader); ok {
			original = cr.GetCommittedState(addr, k)
			originalKnown = true
		} else {
			original = current
		}

		var storageCost uint64
		if current == v {
			// Case 1: No change.
			storageCost = gasSStoreNoop
		} else if originalKnown && current != original {
			// Dirty slot: already modified earlier in this transaction.
			storageCost = gasSStoreNoop // SLOAD (100)
			// Issue SSTORE_CLEAR refund only when the net effect is a genuine
			// clear (original != 0 and new value == 0). The 0 -> X -> 0 cycle
			// (original == 0) is explicitly excluded by EIP-3529.
			if original != (Hash{}) && v == (Hash{}) {
				env.Gas().Refund(gasSStoreClear)
			}
		} else if current == (Hash{}) {
			// Case 2: Clean slot, 0 -> non-zero (set).
			storageCost = gasSStoreSet
		} else if v == (Hash{}) {
			// Case 3: Clean slot, non-zero -> zero (clear with refund).
			storageCost = gasSStoreReset
			if originalKnown && original != (Hash{}) {
				env.Gas().Refund(gasSStoreClear)
			}
		} else {
			// Case 4: Clean slot, non-zero -> non-zero (reset).
			storageCost = gasSStoreReset
		}
		// The storageCost values (gasSStoreSet=20000, gasSStoreReset=2900, etc.)
		// are the pure storage mutation costs per EIP-2200/EIP-2929. The static
		// gasSLoadWarm=100 is the base access cost; cold access surcharge is added
		// separately above. Do NOT subtract gasSLoadWarm here - that would undercharge. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// cold SSTORE by 100 gas (JIT=22000 vs interpreter=22100).
		if err := env.Gas().Consume(storageCost); err != nil {
			return err
		}
		env.StateDB().SetState(addr, k, v)
		return nil
	}
}

func makeAddressOp() MicroOp {
	return func(env VMEnvironment) error {
		addr := env.Ctx().Address()
		return env.Stack().Push(NewWord(addr[:]))
	}
}

func makeBalanceOp() MicroOp {
	return func(env VMEnvironment) error {
		addrWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		var addr Address
		copy(addr[:], addrWord.Bytes()[12:])
		// audit-fix P3-1: Cold access dynamic gas (EIP-2929). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Static already charged gasBalanceWarm=100; cold access needs extra gasBalanceCold-gasBalanceWarm=2500. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if !env.StateDB().AddressInAccessList(addr) {
			extraCost := gasBalanceCold - gasBalanceWarm
			if err := env.Gas().Consume(extraCost); err != nil {
				return err
			}
			env.StateDB().AddAddressToAccessList(addr)
		}
		balance := env.StateDB().GetBalance(addr)
		return env.Stack().PushBigInt(balance)
	}
}

func makeOriginOp() MicroOp {
	return func(env VMEnvironment) error {
		origin := env.Ctx().Origin()
		return env.Stack().Push(NewWord(origin[:]))
	}
}

func makeCallerOp() MicroOp {
	return func(env VMEnvironment) error {
		caller := env.Ctx().Caller()
		return env.Stack().Push(NewWord(caller[:]))
	}
}

func makeCallValueOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushBigInt(env.Ctx().Value())
	}
}

func makeCallDataLoadOp() MicroOp {
	return func(env VMEnvironment) error {
		offset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		input := env.Ctx().Input()
		data := make([]byte, 32)
		if offset < uint64(len(input)) {
			copy(data, input[offset:])
		}
		return env.Stack().Push(NewWord(data))
	}
}

func makeCallDataSizeOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(uint64(len(env.Ctx().Input())))
	}
}

func makeCallDataCopyOp() MicroOp {
	return func(env VMEnvironment) error {
		memOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		dataOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// audit-fix P2-1b-3: Overflow check to prevent OOM. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > maxMemoryAlloc {
			return ErrMemoryOverflow
		}
		if memOffset > math.MaxUint64-size {
			return ErrMemoryOverflow
		}
		// FIX: Charge memory expansion gas (matching interpreter path).
		// The interpreter charges both memory expansion AND copy word gas;
		// the JIT was only charging copy word gas.
		if err := chargeMemoryExpansion(env, memOffset+size); err != nil {
			return err
		}
		// audit-fix P2-1b-4: Dynamic gas = 3 * ceil(size/32). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Static gas (3) is already deducted in the Execute loop. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		wordCount := (size + 31) / 32
		dynamicGas, err := safeMulGas(wordCount, gasCopyWord)
		if err != nil {
			return err
		}
		if err := env.Gas().Consume(dynamicGas); err != nil {
			return err
		}
		input := env.Ctx().Input()
		data := make([]byte, size)
		if dataOffset < uint64(len(input)) {
			copy(data, input[dataOffset:])
		}
		return env.Memory().Store(memOffset, data)
	}
}

func makeCodeSizeOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(uint64(len(env.Ctx().Code())))
	}
}

func makeCodeCopyOp() MicroOp {
	return func(env VMEnvironment) error {
		memOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		codeOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// audit-fix P2-1b-3: Overflow check to prevent OOM. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > maxMemoryAlloc {
			return ErrMemoryOverflow
		}
		if memOffset > math.MaxUint64-size {
			return ErrMemoryOverflow
		}
		// FIX: Charge memory expansion gas (matching interpreter path).
		if err := chargeMemoryExpansion(env, memOffset+size); err != nil {
			return err
		}
		// audit-fix P2-1b-4: Dynamic gas = 3 * ceil(size/32). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		wordCount := (size + 31) / 32
		dynamicGas, err := safeMulGas(wordCount, gasCopyWord)
		if err != nil {
			return err
		}
		if err := env.Gas().Consume(dynamicGas); err != nil {
			return err
		}
		code := env.Ctx().Code()
		data := make([]byte, size)
		if codeOffset < uint64(len(code)) {
			copy(data, code[codeOffset:])
		}
		return env.Memory().Store(memOffset, data)
	}
}

func makeGasPriceOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushBigInt(env.Ctx().GasPrice())
	}
}

func makeGasOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(env.Gas().Available())
	}
}

func makeBlockHashOp() MicroOp {
	return func(env VMEnvironment) error {
		blockNum, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		hash := env.GetBlockHash(blockNum)
		return env.Stack().Push(NewWord(hash[:]))
	}
}

func makeCoinbaseOp() MicroOp {
	return func(env VMEnvironment) error {
		coinbase := env.Ctx().Coinbase()
		return env.Stack().Push(NewWord(coinbase[:]))
	}
}

func makeTimestampOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(uint64(env.Ctx().Timestamp()))
	}
}

func makeNumberOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(env.Ctx().BlockNumber())
	}
}

func makeChainIDOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(env.Ctx().ChainID())
	}
}

func makeSelfBalanceOp() MicroOp {
	return func(env VMEnvironment) error {
		balance := env.StateDB().GetBalance(env.Ctx().Address())
		return env.Stack().PushBigInt(balance)
	}
}

func makeSha3Op() MicroOp {
	return func(env VMEnvironment) error {
		offset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// audit-fix P2-1b-3: Overflow check to prevent OOM. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > maxMemoryAlloc {
			return ErrMemoryOverflow
		}
		if offset > math.MaxUint64-size {
			return ErrMemoryOverflow
		}
		// audit-fix P3-1: Memory expansion gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > 0 {
			if err := chargeMemoryExpansion(env, offset+size); err != nil {
				return err
			}
		}
		// audit-fix P2-1b-4: Dynamic gas = 6 * ceil(size/32). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Static gas (30) is already deducted in the Execute loop. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		wordCount := (size + 31) / 32
		dynamicGas, err := safeMulGas(wordCount, gasSHA3Word)
		if err != nil {
			return err
		}
		if err := env.Gas().Consume(dynamicGas); err != nil {
			return err
		}
		data := env.Memory().Load(offset, size)
		// audit-fix P2-1b-1: Use Keccak-256 (EVM standard), not SHA-256. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Previously using sha256.Sum256 caused JIT and interpreter to produce different hashes for the same input. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Breaking contract storage key accounting and CREATE2 address calculation. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		h := sha3.NewLegacyKeccak256()
		h.Write(data)
		hash := h.Sum(nil)
		return env.Stack().Push(NewWord(hash))
	}
}

func makeLogOp(topicCount int) MicroOp {
	return func(env VMEnvironment) error {
		// audit-fix P2-1b-9: Forbid LOG in STATICCALL context. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if env.ReadOnly() {
			return ErrWriteProtection
		}
		offset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// audit-fix P3-1: Memory expansion gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > 0 {
			if offset > math.MaxUint64-size {
				return ErrMemoryOverflow
			}
			if err := chargeMemoryExpansion(env, offset+size); err != nil {
				return err
			}
		}
		// audit-fix P3-1: Dynamic gas = topic cost + data cost. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Static gas only includes GasLog(375); topic(375*count) and data(8*size) are dynamically charged here. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		topicGas, err := safeMulGas(uint64(topicCount), gasLogTopic)
		if err != nil {
			return err
		}
		dataGas, err := safeMulGas(size, gasLogData)
		if err != nil {
			return err
		}
		dynamicGas, err := safeAddGas(topicGas, dataGas)
		if err != nil {
			return err
		}
		if dynamicGas > 0 {
			if err := env.Gas().Consume(dynamicGas); err != nil {
				return err
			}
		}
		data := env.Memory().Load(offset, size)

		topics := make([]Hash, topicCount)
		for i := topicCount - 1; i >= 0; i-- {
			t, err := env.Stack().Pop()
			if err != nil {
				return err
			}
			copy(topics[i][:], t.Bytes())
		}

		env.AddLog(&Log{
			Address: env.Ctx().Address(),
			Topics:  topics,
			Data:    data,
		})
		return nil
	}
}

func makeInvalidOp() MicroOp {
	return func(env VMEnvironment) error {
		return ErrInvalidOpcode
	}
}

// --- Control flow operations ---

func makeJumpOp() MicroOp {
	return func(env VMEnvironment) error {
		dest, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// Validate that dest is a valid JUMPDEST
		if !env.JumpDests()[dest] {
			return ErrInvalidOpcode
		}
		env.SetPC(dest)
		return nil
	}
}

func makeJumpIOp() MicroOp {
	return func(env VMEnvironment) error {
		dest, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		cond, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		if !cond.IsZero() {
			// Validate that dest is a valid JUMPDEST
			if !env.JumpDests()[dest] {
				return ErrInvalidOpcode
			}
			env.SetPC(dest)
		}
		return nil
	}
}

func makeReturnOp() MicroOp {
	return func(env VMEnvironment) error {
		offset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// audit-fix P3-1: Memory expansion gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > 0 {
			if offset > math.MaxUint64-size {
				return ErrMemoryOverflow
			}
			if err := chargeMemoryExpansion(env, offset+size); err != nil {
				return err
			}
		}
		data := env.Memory().Load(offset, size)
		env.SetReturnData(data)
		env.SetStopped(true)
		return nil
	}
}

func makeRevertOp() MicroOp {
	return func(env VMEnvironment) error {
		offset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// audit-fix P3-1: Memory expansion gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > 0 {
			if offset > math.MaxUint64-size {
				return ErrMemoryOverflow
			}
			if err := chargeMemoryExpansion(env, offset+size); err != nil {
				return err
			}
		}
		data := env.Memory().Load(offset, size)
		env.SetReturnData(data)
		env.SetReverted(true)
		env.SetStopped(true)
		env.SetErr(ErrExecutionReverted)
		return nil
	}
}

// --- Arithmetic operations ---

func makeAddModOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		n, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		var result *big.Int
		if n.Sign() == 0 {
			result = new(big.Int)
		} else {
			result = new(big.Int).Add(a, b)
			result.Mod(result, n)
		}
		return env.Stack().PushBigInt(result)
	}
}

func makeMulModOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		n, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		var result *big.Int
		if n.Sign() == 0 {
			result = new(big.Int)
		} else {
			result = new(big.Int).Mul(a, b)
			result.Mod(result, n)
		}
		return env.Stack().PushBigInt(result)
	}
}

// --- Signed comparison operations ---

// toSigned converts an unsigned 256-bit integer to a signed one
func toSigned(x *big.Int) *big.Int {
	if x.Bit(255) == 1 {
		result := new(big.Int).Sub(x, bigMaxUint256Plus1)
		return result
	}
	return new(big.Int).Set(x)
}

func makeSltOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		aSigned := toSigned(a)
		bSigned := toSigned(b)
		if aSigned.Cmp(bSigned) < 0 {
			return env.Stack().PushUint64(1)
		}
		return env.Stack().PushUint64(0)
	}
}

func makeSgtOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		aSigned := toSigned(a)
		bSigned := toSigned(b)
		if aSigned.Cmp(bSigned) > 0 {
			return env.Stack().PushUint64(1)
		}
		return env.Stack().PushUint64(0)
	}
}

// --- Bitwise operations ---

func makeSarOp() MicroOp {
	return func(env VMEnvironment) error {
		shift, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		value, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		valueSigned := toSigned(value)
		var result *big.Int
		if shift.Cmp(big.NewInt(256)) >= 0 {
			if valueSigned.Sign() >= 0 {
				result = new(big.Int)
			} else {
				result = big.NewInt(-1)
			}
		} else {
			result = new(big.Int).Rsh(valueSigned, uint(shift.Uint64()))
		}
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

func makeByteOp() MicroOp {
	return func(env VMEnvironment) error {
		index, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		value, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		if index.Cmp(big.NewInt(32)) >= 0 {
			return env.Stack().PushUint64(0)
		}
		idx := int(index.Uint64())
		res := byte(0)
		bytes := value.Bytes()
		padding := 32 - len(bytes)
		if idx >= padding {
			res = bytes[idx-padding]
		}
		return env.Stack().PushUint64(uint64(res))
	}
}

// --- Memory operations ---

func makeMSizeOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(env.Memory().Len())
	}
}

func makeMCopyOp() MicroOp {
	return func(env VMEnvironment) error {
		dest, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		src, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		if size == 0 {
			return nil
		}
		// audit-fix P2-1b-3: Overflow check to prevent OOM. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > maxMemoryAlloc {
			return ErrMemoryOverflow
		}
		if dest > math.MaxUint64-size {
			return ErrMemoryOverflow
		}
		if src > math.MaxUint64-size {
			return ErrMemoryOverflow
		}
		// FIX: Charge memory expansion gas, matching interpreter path
		// (operations_missing.go:313). MCOPY accesses both [dest, dest+size)
		// and [src, src+size), so memory must expand to cover the larger of
		// the two ranges. Previously the JIT only charged copy word gas,
		// undercharging relative to the interpreter and breaking consensus
		// determinism.
		maxEnd := dest + size
		if srcEnd := src + size; srcEnd > maxEnd {
			maxEnd = srcEnd
		}
		if err := chargeMemoryExpansion(env, maxEnd); err != nil {
			return err
		}
		// audit-fix P2-1b-4: Dynamic gas = 3 * ceil(size/32). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// Static gas (3) is already deducted in the Execute loop. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		wordCount := (size + 31) / 32
		dynamicGas, err := safeMulGas(wordCount, gasCopyWord)
		if err != nil {
			return err
		}
		if err := env.Gas().Consume(dynamicGas); err != nil {
			return err
		}
		// Copy data: read from source, write to destination
		data := env.Memory().Load(src, size)
		return env.Memory().Store(dest, data)
	}
}

// --- Context operations ---

func makeGasLimitOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(env.Ctx().GasLimit())
	}
}

// --- Return data operations ---

func makeReturnDataSizeOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(uint64(len(env.LastReturnData())))
	}
}

func makeReturnDataCopyOp() MicroOp {
	return func(env VMEnvironment) error {
		memOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		dataOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// audit-fix P2-1b-3: Overflow check to prevent OOM. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > maxMemoryAlloc {
			return ErrMemoryOverflow
		}
		if memOffset > math.MaxUint64-size {
			return ErrMemoryOverflow
		}
		if dataOffset > math.MaxUint64-size {
			return ErrMemoryOverflow
		}
		// FIX: Charge memory expansion gas (matching interpreter path).
		if err := chargeMemoryExpansion(env, memOffset+size); err != nil {
			return err
		}
		// audit-fix P2-1b-4: Dynamic gas = 3 * ceil(size/32). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		wordCount := (size + 31) / 32
		dynamicGas, err := safeMulGas(wordCount, gasCopyWord)
		if err != nil {
			return err
		}
		if err := env.Gas().Consume(dynamicGas); err != nil {
			return err
		}
		returnData := env.LastReturnData()
		data := make([]byte, size)
		if dataOffset < uint64(len(returnData)) {
			end := dataOffset + size
			if end > uint64(len(returnData)) {
				end = uint64(len(returnData))
			}
			copy(data, returnData[dataOffset:end])
		}
		return env.Memory().Store(memOffset, data)
	}
}

// --- Call operations ---

func makeCallOp() MicroOp {
	return func(env VMEnvironment) error {
		gas, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		addrWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		value, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		inOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		inSize, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		outOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		outSize, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}

		// audit-fix P2-1b-5: Forbid value transfer in STATICCALL context. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		hasValue := value.Sign() > 0
		if env.ReadOnly() && hasValue {
			return ErrWriteProtection
		}

		// audit-fix P2-1b-5: Memory overflow check. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if inSize > 0 && inOffset > math.MaxUint64-inSize {
			return ErrMemoryOverflow
		}
		if outSize > 0 && outOffset > math.MaxUint64-outSize {
			return ErrMemoryOverflow
		}

		// audit-fix P2-1b-5: Balance check (when value transfer). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if hasValue {
			balance := env.StateDB().GetBalance(env.Ctx().Address())
			if balance.Cmp(value) < 0 {
				return env.Stack().PushUint64(0)
			}
		}

		var addr Address
		copy(addr[:], addrWord.Bytes()[12:])

		// FIX: Reject calls to the zero address (0x0), matching the
		// interpreter path (call.go:161-165). The zero address is reserved and
		// must never receive a CALL. Without this check, the JIT path diverges
		// from the interpreter, which is a consensus-determinism risk.
		var zeroAddr Address
		if addr == zeroAddr {
			return env.Stack().PushUint64(0)
		}

		// audit-fix P2-1b-5: Dynamic gas - cold/warm address + value transfer + new account. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		isCold := !env.StateDB().AddressInAccessList(addr)
		dynamicGas := uint64(0)
		if isCold {
			dynamicGas += gasCallCold
		}
		if hasValue {
			dynamicGas += gasCallValue
			if !env.StateDB().Exist(addr) {
				dynamicGas += gasCallNewAccount
			}
		}
		if dynamicGas > 0 {
			if err := env.Gas().Consume(dynamicGas); err != nil {
				return err
			}
		}
		// Add to access list. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		env.StateDB().AddAddressToAccessList(addr)

		// FIX: Charge memory expansion gas for input/output regions.
		// The interpreter path (call.go) charges this BEFORE the 63/64 rule;
		// the JIT path was completely missing this, allowing free memory expansion.
		// FIX: The 63/64 rule must be applied AFTER deducting ALL fixed
		// costs (base call cost + memory expansion). Previously it was applied
		// before memory expansion, giving the callee more gas than it should have.
		var memCost uint64
		if inSize > 0 {
			memCost = memoryExpansionCost(env.Memory().Len(), inOffset+inSize)
		}
		if outSize > 0 {
			outCost := memoryExpansionCost(env.Memory().Len(), outOffset+outSize)
			if outCost > memCost {
				memCost = outCost
			}
		}
		if memCost > 0 {
			if err := env.Gas().Consume(memCost); err != nil {
				return err
			}
		}

		// FIX: Charge reentrancy guard gas (2300) BEFORE the 63/64 rule,
		// matching the interpreter path (call.go lines 220-224). Previously this
		// was done in jit_adapter.go AFTER the 63/64 split, causing the callee to
		// receive slightly more gas than the interpreter would allow.
		// FIX: Add targetHasCode check matching interpreter path (call.go:221-222).
		// EOA calls (target has no code) must not be charged the reentrancy guard gas.
		//  DESIGN NOTE: Calling env.StateDB().GetCode(addr) from within a JIT
		// MicroOp is feasible because MicroOps execute at runtime (not compile time)
		// with full access to the EVMEnv. The GetCode call is O(1) (a map lookup in
		// the StateDB cache) and does not measurably impact JIT execution throughput.
		// This pattern is safe and intentionally mirrors the interpreter's call path.
		targetHasCode := len(env.StateDB().GetCode(addr)) > 0
		if targetHasCode && env.CallDepth() >= 1 && env.IsAddressActive(addr) {
			if err := env.Gas().Consume(2300); err != nil {
				return err
			}
		}

		// audit-fix P2-1b-5: 63/64 gas reservation rule (now applied after memory expansion). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		// FIX: Reentrancy guard gas is now charged above, BEFORE the 63/64
		// rule, matching the interpreter path. The previous NOTE about the timing
		// difference is no longer applicable.
		available := env.Gas().Available()
		maxGas := available - available/64
		if gas > maxGas {
			gas = maxGas
		}
		// Add stipend when value transfer. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if hasValue {
			gas += gasCallStipend
		}

		// FIX: Consume the callee's gas allocation from the caller's
		// gas meter BEFORE calling env.Call(). The 63/64 rule reserves this
		// gas for the callee; without Consume, the callee's gas is "free" and
		// the subsequent Return(gas - gasUsed) incorrectly adds gas back.
		if err := env.Gas().Consume(gas); err != nil {
			return err
		}

		// Read input from memory
		var input []byte
		if inSize > 0 {
			input = env.Memory().Load(inOffset, inSize)
		}

		// Delegate to interpreter via VMEnvironment
		returnData, gasUsed, callErr := env.Call(env.Ctx().Address(), addr, input, gas, value)

		// audit-fix P2-1b-5: Refund unused gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if gasUsed < gas {
			env.Gas().Return(gas - gasUsed)
		}

		// Store return data
		env.SetReturnData(returnData)

		// Copy return data to output memory
		if outSize > 0 && len(returnData) > 0 {
			copySize := outSize
			if uint64(len(returnData)) < copySize {
				copySize = uint64(len(returnData))
			}
			if err := env.Memory().Store(outOffset, returnData[:copySize]); err != nil {
				return err
			}
		}

		if callErr != nil {
			return env.Stack().PushUint64(0)
		}
		return env.Stack().PushUint64(1)
	}
}

func makeCallCodeOp() MicroOp {
	return func(env VMEnvironment) error {
		gas, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		addrWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		value, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		inOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		inSize, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		outOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		outSize, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}

		// audit-fix P2-1b-9: Forbid SSTORE in STATICCALL context. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		hasValue := value.Sign() > 0
		if env.ReadOnly() && hasValue {
			return ErrWriteProtection
		}

		// audit-fix P2-1b-5: Memory overflow check. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if inSize > 0 && inOffset > math.MaxUint64-inSize {
			return ErrMemoryOverflow
		}
		if outSize > 0 && outOffset > math.MaxUint64-outSize {
			return ErrMemoryOverflow
		}

		// audit-fix P2-1b-5: Balance check (when value transfer). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if hasValue {
			balance := env.StateDB().GetBalance(env.Ctx().Address())
			if balance.Cmp(value) < 0 {
				return env.Stack().PushUint64(0)
			}
		}

		var addr Address
		copy(addr[:], addrWord.Bytes()[12:])

		// FIX: Reject calls to the zero address (0x0), matching the
		// interpreter CALL pattern. CALLCODE shares the same address semantics.
		var zeroAddr Address
		if addr == zeroAddr {
			return env.Stack().PushUint64(0)
		}

		// audit-fix P2-1b-5: Dynamic gas - cold/warm address + value transfer + new account. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		isCold := !env.StateDB().AddressInAccessList(addr)
		dynamicGas := uint64(0)
		if isCold {
			dynamicGas += gasCallCold
		}
		if hasValue {
			dynamicGas += gasCallValue
			if !env.StateDB().Exist(addr) {
				dynamicGas += gasCallNewAccount
			}
		}
		if dynamicGas > 0 {
			if err := env.Gas().Consume(dynamicGas); err != nil {
				return err
			}
		}
		env.StateDB().AddAddressToAccessList(addr)

		// /FIX: Charge memory expansion gas before 63/64 rule.
		var memCost uint64
		if inSize > 0 {
			memCost = memoryExpansionCost(env.Memory().Len(), inOffset+inSize)
		}
		if outSize > 0 {
			outCost := memoryExpansionCost(env.Memory().Len(), outOffset+outSize)
			if outCost > memCost {
				memCost = outCost
			}
		}
		if memCost > 0 {
			if err := env.Gas().Consume(memCost); err != nil {
				return err
			}
		}

		// FIX: Charge reentrancy guard gas BEFORE the 63/64 rule.
		// FIX: Add targetHasCode check matching interpreter path.
		// FIX: CALLCODE executes the target's code in the CALLER's
		// storage context (like DELEGATECALL), so the reentrancy check must
		// use env.Ctx().Address() (caller), not addr (target). Previously
		// checked IsAddressActive(addr) which is semantically incorrect for
		// CALLCODE - it would miss reentrancy via the caller's address. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		targetHasCode := len(env.StateDB().GetCode(addr)) > 0
		if targetHasCode && env.CallDepth() >= 1 && env.IsAddressActive(env.Ctx().Address()) {
			if err := env.Gas().Consume(2300); err != nil {
				return err
			}
		}

		// audit-fix P2-1b-5: 63/64 gas reservation rule. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		available := env.Gas().Available()
		maxGas := available - available/64
		if gas > maxGas {
			gas = maxGas
		}
		if hasValue {
			gas += gasCallStipend
		}

		// FIX: Consume callee gas allocation (see CALL for explanation).
		if err := env.Gas().Consume(gas); err != nil {
			return err
		}

		var input []byte
		if inSize > 0 {
			input = env.Memory().Load(inOffset, inSize)
		}

		returnData, gasUsed, callErr := env.CallCode(env.Ctx().Address(), addr, input, gas, value)

		// audit-fix P2-1b-5: Refund unused gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if gasUsed < gas {
			env.Gas().Return(gas - gasUsed)
		}

		env.SetReturnData(returnData)

		if outSize > 0 && len(returnData) > 0 {
			copySize := outSize
			if uint64(len(returnData)) < copySize {
				copySize = uint64(len(returnData))
			}
			if err := env.Memory().Store(outOffset, returnData[:copySize]); err != nil {
				return err
			}
		}

		if callErr != nil {
			return env.Stack().PushUint64(0)
		}
		return env.Stack().PushUint64(1)
	}
}

func makeDelegateCallOp() MicroOp {
	return func(env VMEnvironment) error {
		gas, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		addrWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		inOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		inSize, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		outOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		outSize, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}

		// audit-fix P2-1b-5: Memory overflow check. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if inSize > 0 && inOffset > math.MaxUint64-inSize {
			return ErrMemoryOverflow
		}
		if outSize > 0 && outOffset > math.MaxUint64-outSize {
			return ErrMemoryOverflow
		}

		var addr Address
		copy(addr[:], addrWord.Bytes()[12:])

		// FIX: Reject calls to the zero address (0x0), matching the
		// interpreter DELEGATECALL pattern (call.go:803-807).
		var zeroAddr Address
		if addr == zeroAddr {
			return env.Stack().PushUint64(0)
		}

		// audit-fix P2-1b-5: Dynamic gas - cold/warm address (DELEGATECALL has no value transfer). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		isCold := !env.StateDB().AddressInAccessList(addr)
		if isCold {
			if err := env.Gas().Consume(gasCallCold); err != nil {
				return err
			}
		}
		env.StateDB().AddAddressToAccessList(addr)

		// /FIX: Charge memory expansion gas before 63/64 rule.
		var memCost uint64
		if inSize > 0 {
			memCost = memoryExpansionCost(env.Memory().Len(), inOffset+inSize)
		}
		if outSize > 0 {
			outCost := memoryExpansionCost(env.Memory().Len(), outOffset+outSize)
			if outCost > memCost {
				memCost = outCost
			}
		}
		if memCost > 0 {
			if err := env.Gas().Consume(memCost); err != nil {
				return err
			}
		}

		// FIX: Charge reentrancy guard gas BEFORE the 63/64 rule.
		// DELEGATECALL runs in the caller's storage context, so reentrancy is
		// detected via ctx.Address (the current contract), NOT the target.
		// FIX: Add targetHasCode check matching interpreter path (call.go:848-849).
		targetHasCode := len(env.StateDB().GetCode(addr)) > 0
		if targetHasCode && env.CallDepth() >= 1 && env.IsAddressActive(env.Ctx().Address()) {
			if err := env.Gas().Consume(2300); err != nil {
				return err
			}
		}

		// audit-fix P2-1b-5: 63/64 gas reservation rule. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		available := env.Gas().Available()
		maxGas := available - available/64
		if gas > maxGas {
			gas = maxGas
		}

		// FIX: Consume callee gas allocation (see CALL for explanation).
		if err := env.Gas().Consume(gas); err != nil {
			return err
		}

		var input []byte
		if inSize > 0 {
			input = env.Memory().Load(inOffset, inSize)
		}

		returnData, gasUsed, callErr := env.DelegateCall(env.Ctx().Caller(), addr, input, gas)

		// audit-fix P2-1b-5: Refund unused gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if gasUsed < gas {
			env.Gas().Return(gas - gasUsed)
		}

		env.SetReturnData(returnData)

		if outSize > 0 && len(returnData) > 0 {
			copySize := outSize
			if uint64(len(returnData)) < copySize {
				copySize = uint64(len(returnData))
			}
			if err := env.Memory().Store(outOffset, returnData[:copySize]); err != nil {
				return err
			}
		}

		if callErr != nil {
			return env.Stack().PushUint64(0)
		}
		return env.Stack().PushUint64(1)
	}
}

func makeStaticCallOp() MicroOp {
	return func(env VMEnvironment) error {
		gas, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		addrWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		inOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		inSize, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		outOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		outSize, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}

		// audit-fix P2-1b-5: Memory overflow check. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if inSize > 0 && inOffset > math.MaxUint64-inSize {
			return ErrMemoryOverflow
		}
		if outSize > 0 && outOffset > math.MaxUint64-outSize {
			return ErrMemoryOverflow
		}

		var addr Address
		copy(addr[:], addrWord.Bytes()[12:])

		// FIX: Reject calls to the zero address (0x0), matching the
		// interpreter STATICCALL pattern (call.go:538-542).
		var zeroAddr Address
		if addr == zeroAddr {
			return env.Stack().PushUint64(0)
		}

		// audit-fix P2-1b-5: Dynamic gas - cold/warm address (STATICCALL has no value transfer). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		isCold := !env.StateDB().AddressInAccessList(addr)
		if isCold {
			if err := env.Gas().Consume(gasCallCold); err != nil {
				return err
			}
		}
		env.StateDB().AddAddressToAccessList(addr)

		// /FIX: Charge memory expansion gas before 63/64 rule.
		var memCost uint64
		if inSize > 0 {
			memCost = memoryExpansionCost(env.Memory().Len(), inOffset+inSize)
		}
		if outSize > 0 {
			outCost := memoryExpansionCost(env.Memory().Len(), outOffset+outSize)
			if outCost > memCost {
				memCost = outCost
			}
		}
		if memCost > 0 {
			if err := env.Gas().Consume(memCost); err != nil {
				return err
			}
		}

		// FIX: Charge reentrancy guard gas BEFORE the 63/64 rule.
		// FIX: Add targetHasCode check matching interpreter path.
		targetHasCode := len(env.StateDB().GetCode(addr)) > 0
		if targetHasCode && env.CallDepth() >= 1 && env.IsAddressActive(addr) {
			if err := env.Gas().Consume(2300); err != nil {
				return err
			}
		}

		// audit-fix P2-1b-5: 63/64 gas reservation rule. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		available := env.Gas().Available()
		maxGas := available - available/64
		if gas > maxGas {
			gas = maxGas
		}

		// FIX: Consume callee gas allocation (see CALL for explanation).
		if err := env.Gas().Consume(gas); err != nil {
			return err
		}

		var input []byte
		if inSize > 0 {
			input = env.Memory().Load(inOffset, inSize)
		}

		returnData, gasUsed, callErr := env.StaticCall(env.Ctx().Address(), addr, input, gas)

		// audit-fix P2-1b-5: Refund unused gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if gasUsed < gas {
			env.Gas().Return(gas - gasUsed)
		}

		env.SetReturnData(returnData)

		if outSize > 0 && len(returnData) > 0 {
			copySize := outSize
			if uint64(len(returnData)) < copySize {
				copySize = uint64(len(returnData))
			}
			if err := env.Memory().Store(outOffset, returnData[:copySize]); err != nil {
				return err
			}
		}

		if callErr != nil {
			return env.Stack().PushUint64(0)
		}
		return env.Stack().PushUint64(1)
	}
}

// --- Create operations ---

func makeCreateOp(isCreate2 bool) MicroOp {
	return func(env VMEnvironment) error {
		// audit-fix P2-1b-9: Forbid CREATE in STATICCALL context. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if env.ReadOnly() {
			return ErrWriteProtection
		}
		value, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		offset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}

		var salt *Hash
		if isCreate2 {
			saltWord, err := env.Stack().Pop()
			if err != nil {
				return err
			}
			var s Hash
			copy(s[:], saltWord.Bytes())
			salt = &s
		}

		// audit-fix P2-1b-5: Memory overflow check. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > 0 && offset > math.MaxUint64-size {
			return ErrMemoryOverflow
		}

		// audit-fix P2-1b-5: Balance check (when value transfer). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		hasValue := value.Sign() > 0
		if hasValue {
			balance := env.StateDB().GetBalance(env.Ctx().Address())
			if balance.Cmp(value) < 0 {
				var emptyAddr Address
				return env.Stack().Push(NewWord(emptyAddr[:]))
			}
		}

		// FIX: Removed CREATE2 hash cost charge here. The hash cost is
		// already charged in jitEnvAdapter.Create() (jit_adapter.go:642-654),
		// so charging it here as well results in double charging.
		// The adapter is the correct location because it mirrors the interpreter's
		// opCreateGeneric path and has access to the actual initcode size.

		// /FIX: Charge memory expansion gas before 63/64 rule.
		if size > 0 {
			memCost := memoryExpansionCost(env.Memory().Len(), offset+size)
			if memCost > 0 {
				if err := env.Gas().Consume(memCost); err != nil {
					return err
				}
			}
		}

		// Read init code from memory
		var input []byte
		if size > 0 {
			input = env.Memory().Load(offset, size)
		}

		// audit-fix P2-1b-5: 63/64 gas reservation rule. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		available := env.Gas().Available()
		maxGas := available - available/64
		gas := maxGas

		// FIX: Consume callee gas allocation (see CALL for explanation).
		if err := env.Gas().Consume(gas); err != nil {
			return err
		}

		// Delegate to interpreter via VMEnvironment
		returnData, contractAddr, gasUsed, createErr := env.Create(env.Ctx().Address(), input, gas, value, salt)

		// audit-fix P2-1b-5: Refund unused gas. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if gasUsed < gas {
			env.Gas().Return(gas - gasUsed)
		}

		_ = returnData

		if createErr != nil {
			var emptyAddr Address
			return env.Stack().Push(NewWord(emptyAddr[:]))
		}
		return env.Stack().Push(NewWord(contractAddr[:]))
	}
}

// --- Post-quantum crypto operations ---

func makeKyberOp() MicroOp {
	return func(env VMEnvironment) error {
		// Kyber operations require special handling via the interpreter
		return ErrInvalidOpcode
	}
}

// --- Self-destruct operation ---

func makeSelfDestructOp() MicroOp {
	return func(env VMEnvironment) error {
		// P3-QVM-SELFDESTRUCT FIX (R30, 2026-07-27): The JIT SELFDESTRUCT
		// implementation was severely incomplete — it called env.SelfDestruct()
		// but did NOT:
		//   1. Transfer the contract's balance to the beneficiary (EIP-6780
		//      requires this at end-of-block, not at opcode execution time).
		//   2. Check EIP-6780 (only contracts created in the SAME transaction
		//      can be self-destructed; the JIT impl didn't consult
		//      txCreatedContracts).
		//   3. Charge gas for the operation.
		//   4. Handle shared state (selfDestructCleared, selfDestructBeneficiaries).
		//
		// Running this incomplete implementation would silently corrupt state:
		// the contract would be marked destroyed but its balance would vanish
		// (not transferred), and EIP-6780 would be bypassed. This is a
		// consensus-splitting bug.
		//
		// The JIT is disabled in production by three layers:
		//   1. jitEnabled: false (default off in executor.go)
		//   2. EnableJIT rejected in production mode (QAU_PRODUCTION=1)
		//   3. Execute dispatch point checks
		//
		// But defense-in-depth says: even if JIT is accidentally enabled,
		// SELFDESTRUCT should fail safely rather than execute an incomplete
		// implementation. Return ErrInvalidOpcode so the contract gets a
		// clear revert instead of silent state corruption. The interpreter
		// path (operations_missing.go:opSelfDestruct) has the complete
		// implementation with EIP-6780 semantics, balance transfer, gas
		// charging, and shared-state tracking — and is used in all
		// production code paths.
		//
		// The STATICCALL read-only check and the original env.SelfDestruct()
		// call are intentionally removed: returning ErrInvalidOpcode makes
		// them unreachable, and keeping them would imply the incomplete
		// logic is still active.
		return ErrInvalidOpcode
	}
}

// --- audit-fix P2-1b-7: Complete the 15 missing opcodes ---. N2 FIX (2026-07-06 R2): Fixed garbled comment.

// makePush0Op implements PUSH0 (EIP-3854): push 0 value. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makePush0Op() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(0)
	}
}

// makeSignExtendOp implements SIGNEXTEND: sign-extend the high bits of value. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [k, value] -> [signExtended(value, k)]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeSignExtendOp() MicroOp {
	return func(env VMEnvironment) error {
		kBig, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		value, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		if kBig.Cmp(big.NewInt(31)) >= 0 {
			// k >= 31, no extension needed, return original value. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			return env.Stack().PushBigInt(value)
		}
		k := int(kBig.Uint64())
		// Convert value to 32-byte big-endian. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		var valBytes [32]byte
		value.FillBytes(valBytes[:])
		// Check if the highest bit of the k-th byte is 1 (negative). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		bit := valBytes[31-k] & 0x80
		if bit != 0 {
			// Negative: fill high bits with 0xFF. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			for i := 30 - k; i >= 0; i-- {
				valBytes[i] = 0xFF
			}
		} else {
			// Positive: fill high bits with 0x00. N2 FIX (2026-07-06 R2): Fixed garbled comment.
			for i := 30 - k; i >= 0; i-- {
				valBytes[i] = 0x00
			}
		}
		result := new(big.Int).SetBytes(valBytes[:])
		return env.Stack().PushBigInt(result)
	}
}

// makeSdivOp implements SDIV: signed division. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [a, b] -> [a / b] (signed, truncated toward zero). N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeSdivOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		aSigned := toSigned(a)
		bSigned := toSigned(b)
		var result *big.Int
		if bSigned.Sign() == 0 {
			result = new(big.Int)
		} else {
			result = new(big.Int).Quo(aSigned, bSigned)
		}
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

// makeSmodOp implements SMOD: signed modulo. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [a, b] -> [a % b] (signed, result sign matches a). N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeSmodOp() MicroOp {
	return func(env VMEnvironment) error {
		a, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		b, err := env.Stack().PopBigInt()
		if err != nil {
			return err
		}
		aSigned := toSigned(a)
		bSigned := toSigned(b)
		var result *big.Int
		if bSigned.Sign() == 0 {
			result = new(big.Int)
		} else {
			result = new(big.Int).Rem(aSigned, bSigned)
		}
		result.And(result, maxUint256)
		return env.Stack().PushBigInt(result)
	}
}

// makeTLoadOp implements TLOAD (EIP-1153): read from transient storage. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [key] -> [value]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeTLoadOp() MicroOp {
	return func(env VMEnvironment) error {
		keyWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		var key Hash
		copy(key[:], keyWord.Bytes())
		value := env.GetTransientState(env.Ctx().Address(), key)
		return env.Stack().Push(NewWord(value[:]))
	}
}

// makeTStoreOp implements TSTORE (EIP-1153): write to transient storage. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [key, value] -> []. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeTStoreOp() MicroOp {
	return func(env VMEnvironment) error {
		// audit-fix P2-1b-9: Forbid TSTORE in STATICCALL context. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if env.ReadOnly() {
			return ErrWriteProtection
		}
		keyWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		valueWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		var key, value Hash
		copy(key[:], keyWord.Bytes())
		copy(value[:], valueWord.Bytes())
		env.SetTransientState(env.Ctx().Address(), key, value)
		return nil
	}
}

// makeExtCodeSizeOp implements EXTCODESIZE: get external account code size. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [addr] -> [codeSize]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeExtCodeSizeOp() MicroOp {
	return func(env VMEnvironment) error {
		addrWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		var addr Address
		copy(addr[:], addrWord.Bytes()[12:])
		return env.Stack().PushUint64(uint64(env.StateDB().GetCodeSize(addr)))
	}
}

// makeExtCodeCopyOp implements EXTCODECOPY: copy external account code to memory. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [addr, memOffset, codeOffset, size] -> []. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeExtCodeCopyOp() MicroOp {
	return func(env VMEnvironment) error {
		addrWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		memOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		codeOffset, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		size, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		// audit-fix P2-1b-3: Overflow check to prevent OOM. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if size > maxMemoryAlloc {
			return ErrMemoryOverflow
		}
		if memOffset > math.MaxUint64-size {
			return ErrMemoryOverflow
		}
		// FIX: Charge memory expansion gas (matching interpreter path).
		if err := chargeMemoryExpansion(env, memOffset+size); err != nil {
			return err
		}
		// audit-fix P2-1b-4: Dynamic gas = 3 * ceil(size/32). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		wordCount := (size + 31) / 32
		dynamicGas, err := safeMulGas(wordCount, gasCopyWord)
		if err != nil {
			return err
		}
		if err := env.Gas().Consume(dynamicGas); err != nil {
			return err
		}
		var addr Address
		copy(addr[:], addrWord.Bytes()[12:])
		code := env.StateDB().GetCode(addr)
		// Build data to copy; pad insufficient part with 0. N2 FIX (2026-07-06 R2): Fixed garbled comment.
		data := make([]byte, size)
		if codeOffset < uint64(len(code)) {
			available := uint64(len(code)) - codeOffset
			copySize := size
			if available < copySize {
				copySize = available
			}
			copy(data, code[codeOffset:codeOffset+copySize])
		}
		return env.Memory().Store(memOffset, data)
	}
}

// makeExtCodeHashOp implements EXTCODEHASH (EIP-1052): get external account code hash. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [addr] -> [codeHash]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeExtCodeHashOp() MicroOp {
	return func(env VMEnvironment) error {
		addrWord, err := env.Stack().Pop()
		if err != nil {
			return err
		}
		var addr Address
		copy(addr[:], addrWord.Bytes()[12:])
		// Empty account returns 0; otherwise returns keccak256(code). N2 FIX (2026-07-06 R2): Fixed garbled comment.
		if env.StateDB().Empty(addr) {
			return env.Stack().PushUint64(0)
		}
		hash := env.StateDB().GetCodeHash(addr)
		return env.Stack().Push(NewWord(hash[:]))
	}
}

// makePrevRandaoOp implements PREVRANDAO (EIP-4399): get previous block's RANDAO value. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [] -> [prevRandao]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makePrevRandaoOp() MicroOp {
	return func(env VMEnvironment) error {
		randao := env.Ctx().PrevRandao()
		return env.Stack().Push(NewWord(randao[:]))
	}
}

// makeBlobHashOp implements BLOBHASH (EIP-4844): get blob hash by index. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [index] -> [blobHash]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeBlobHashOp() MicroOp {
	return func(env VMEnvironment) error {
		index, err := env.Stack().PopUint64()
		if err != nil {
			return err
		}
		blobHashes := env.Ctx().BlobHashes()
		if index >= uint64(len(blobHashes)) {
			return env.Stack().PushUint64(0)
		}
		hash := blobHashes[index]
		return env.Stack().Push(NewWord(hash[:]))
	}
}

// makeBaseFeeOp implements BASEFEE (EIP-3198): get current block base fee. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [] -> [baseFee]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeBaseFeeOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(env.Ctx().BaseFee())
	}
}

// makeBlobBaseFeeOp implements BLOBBASEFEE (EIP-7516): get blob base fee. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [] -> [blobBaseFee]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeBlobBaseFeeOp() MicroOp {
	return func(env VMEnvironment) error {
		return env.Stack().PushUint64(env.Ctx().BlobBaseFee())
	}
}

// makeAuthOp implements AUTH (EIP-7702). N2 FIX (2026-07-06 R2): Fixed garbled comment.
// AUTH involves ECDSA signature verification with complex logic; JIT does not support it yet. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Returns ErrInvalidOpcode to trigger fallback to interpreter execution. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [authority, offset, length] -> [success]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeAuthOp() MicroOp {
	return func(env VMEnvironment) error {
		return ErrInvalidOpcode
	}
}

// makeAuthCallOp implements AUTHCALL (EIP-7702). N2 FIX (2026-07-06 R2): Fixed garbled comment.
// AUTHCALL involves authorized address transfer and call with complex logic; JIT does not support it yet. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Returns ErrInvalidOpcode to trigger fallback to interpreter execution. N2 FIX (2026-07-06 R2): Fixed garbled comment.
// Stack order: [gas, addr, value, argsOffset, argsLength, retOffset, retLength] -> [success]. N2 FIX (2026-07-06 R2): Fixed garbled comment.
func makeAuthCallOp() MicroOp {
	return func(env VMEnvironment) error {
		return ErrInvalidOpcode
	}
}

var ErrInvalidOpcode = &vmError{msg: "invalid opcode"}

type vmError struct {
	msg string
}

func (e *vmError) Error() string {
	return e.msg
}
