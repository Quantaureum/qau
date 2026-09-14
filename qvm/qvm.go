// Quantaureum Node source, version 1.0.0.
// Package qvm implements the Quantaureum Virtual Machine.
// QVM is a stack-based virtual machine for executing smart contracts.
package qvm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/qvm/precompiled"
)

// QVM errors
var (
	ErrInvalidOpcode            = errors.New("invalid opcode")
	ErrInvalidJumpDest          = errors.New("invalid jump destination")
	ErrWriteProtection          = errors.New("write protection")
	ErrReturnDataOutOfBounds    = errors.New("return data out of bounds")
	ErrMaxCodeSizeExceeded      = errors.New("max code size exceeded")
	ErrContractAddressCollision = errors.New("contract address collision")
	ErrExecutionReverted        = errors.New("execution reverted")
	ErrDepthExceeded            = errors.New("call depth exceeded")
	ErrInsufficientBalance      = errors.New("insufficient balance")
	ErrInvalidNonce             = errors.New("invalid nonce for contract creation")
	ErrNonceOverflow            = errors.New("nonce overflow")
	// P3-V9: Calling the zero address (0x0) is rejected — it is a reserved
	// address (see L10-020 in call.go). Enforced at both the opcode layer
	// (opCall/opCallCode push 0) and the Executor.Call/CallWithRollback API.
	ErrZeroAddress = errors.New("call to reserved zero address")
	// L6-050: EXP exponent byte length exceeds the 256-bit QVM word size.
	ErrExponentTooLarge = errors.New("qvm: EXP exponent exceeds 256-bit word size")
	// AUDIT (2026) CRIT-03/04: Non-deterministic Kyber KEM opcodes and
	// precompiled contracts are disabled because they use crypto/rand, causing
	// state-root divergence across nodes (each node gets different random output).
	// A single transaction calling these would halt the chain.
	ErrNonDeterministicOpcode = errors.New("qvm: non-deterministic opcode disabled for consensus safety")
	//  EIP-3860 initcode size exceeds the maximum allowed bound.
	ErrInitCodeSizeExceeded = errors.New("init code size exceeds maximum")
	// QVM-R10-C1 (2026-07-19): A panic occurred during Interpreter.run()
	// (e.g., from a malicious contract triggering an array out-of-bounds
	// or nil dereference in an opcode implementation). The recover wraps
	// the entire run loop and converts the panic into this error so the
	// transaction is reverted and the node continues operating.
	ErrPanicRecovery = errors.New("qvm: execution panic recovered")
	// R32-P3-06 FIX (2026-07-28): Unified error for deployed-code validation
	// failures. Previously CREATE/CREATE2 mapped all ValidateDeployedCode
	// failures to ErrInvalidOpcode, which was misleading — the actual cause
	// could be ErrCodeTooLarge, ErrInvalidPushData, ErrUnknownOpcode,
	// ErrInvalidJumpTarget, ErrStackImbalance, or ErrInvalidCodePrefix.
	// ErrInvalidBytecode wraps the specific validation error so callers can
	// distinguish "invalid opcode at runtime" (ErrInvalidOpcode) from
	// "deployed code failed static validation" (ErrInvalidBytecode).
	ErrInvalidBytecode = errors.New("invalid deployed bytecode")
)

// Constants
const (
	MaxCodeSize     = 24576 // Maximum contract code size (24KB)
	MaxCallDepth    = 1024  // Maximum call depth
	MaxInitCodeSize = 49152 // Maximum init code size (48KB)
)

// Address represents a 20-byte account address.
type Address [20]byte

// Hash represents a 32-byte hash.
type Hash [32]byte

// Log represents an event log emitted during execution.
type Log struct {
	Address Address
	Topics  []Hash
	Data    []byte
}

// ExecutionContext contains the context for contract execution.
type ExecutionContext struct {
	// Transaction context
	Origin   Address  // Transaction sender
	GasPrice *big.Int // Gas price

	// Call context
	Caller  Address  // Direct caller
	Address Address  // Current contract address
	Value   *big.Int // Value sent with call

	// Block context
	BlockNumber uint64
	Timestamp   int64
	Coinbase    Address // Block proposer
	GasLimit    uint64  // Block gas limit
	ChainID     uint64
	BlockHashes map[uint64]Hash // Recent block hashes (last 256 blocks) for BLOCKHASH opcode

	// EIP-4399 / EIP-4844 / EIP-7516 context
	PrevRandao  Hash   // Previous RANDAO mix (for PREVRANDAO opcode, replaces DIFFICULTY)
	BlobHashes  []Hash // Blob hashes for current transaction (EIP-4844, for BLOBHASH opcode)
	BlobBaseFee uint64 // Blob base fee (EIP-7516, for BLOBBASEFEE opcode)
	BaseFee     uint64 // Base fee per gas (EIP-3198, for BASEFEE opcode)

	// Code and data
	Code          []byte // Contract bytecode (translated if EVM compatibility is active)
	Input         []byte // Call input data
	OriginalCode  []byte // Original untranslated code (for CODECOPY during contract creation)
	EVMCompatible bool   // true if code was translated from EVM (affects CALL stack order)

	// Execution state
	Gas            uint64       // Available gas
	Depth          int          // Call depth
	ReadOnly       bool         // Static call flag
	SkipValidation bool         // Skip QuickValidate (used for initCode which includes constructor args)
	ParentEnv      *Environment // audit-fix CRIT-REENTRY: pass parent env for reentrancy tracking

	// SECURITY FIX H-9: Abort channel for cancellable execution.
	// When closed, the interpreter's run loop will detect it and terminate
	// early. Used by EstimateGas to cancel goroutines that exceed the timeout.
	// nil means no abort monitoring (normal execution path).
	AbortCh <-chan struct{}
}

// ExecutionResult contains the result of contract execution.
type ExecutionResult struct {
	ReturnData []byte // Return data
	GasUsed    uint64 // Gas consumed
	GasRefund  uint64 // Gas refund
	Logs       []*Log // Event logs
	Err        error  // Execution error (nil = success)
	Reverted   bool   // Was execution reverted
}

// StateDB interface for state access during execution.
type StateDB interface {
	// Account operations
	GetBalance(addr Address) *big.Int
	SetBalance(addr Address, balance *big.Int)
	GetNonce(addr Address) uint64
	SetNonce(addr Address, nonce uint64)

	// Code operations
	GetCode(addr Address) []byte
	SetCode(addr Address, code []byte)
	GetCodeHash(addr Address) Hash
	GetCodeSize(addr Address) int

	// Storage operations
	GetState(addr Address, key Hash) Hash
	SetState(addr Address, key, value Hash)

	// Account existence
	Exist(addr Address) bool
	Empty(addr Address) bool

	// Snapshot and revert
	Snapshot() int
	RevertToSnapshot(id int)

	// Self destruct
	SelfDestruct(addr Address)
	HasSelfDestructed(addr Address) bool

	// Access list (for gas calculation)
	AddAddressToAccessList(addr Address)
	AddSlotToAccessList(addr Address, slot Hash)
	AddressInAccessList(addr Address) bool
	SlotInAccessList(addr Address, slot Hash) (addressOk, slotOk bool)
}

// QVM is the Quantaureum Virtual Machine.
type QVM interface {
	// Execute executes contract code with the given context.
	Execute(ctx *ExecutionContext, stateDB StateDB) *ExecutionResult

	// ValidateBytecode validates contract bytecode.
	ValidateBytecode(code []byte) error

	// EstimateGas estimates the gas required for execution.
	EstimateGas(ctx *ExecutionContext, stateDB StateDB) (uint64, error)
}

// audit-fix R2-L1: maximum entries in jump destination cache to prevent unbounded growth.
const maxJumpDestCacheSize = 4096

// Interpreter executes QVM bytecode.
type Interpreter struct {
	gasTable *GasTable
	// precompiled holds the registry of precompiled contracts used by
	// CALL/STATICCALL/DELEGATECALL/CALLCODE to execute precompiled logic.
	precompiled *precompiled.Registry

	// audit-fix R3-M1: mutex protects jumpDestCache and jumpDestOrder from
	// concurrent access when multiple goroutines call Execute().
	cacheMu sync.Mutex
	// Jump destination analysis cache (bounded)
	jumpDestCache map[Hash]map[uint64]bool
	// audit-fix R2-L1: track insertion order for simple eviction
	jumpDestOrder []Hash

	// R37-INFO FIX (2026-07-31): ecdsaAuthEnabled gates the AUTH/AUTHCALL
	// EIP-7702 authorization path, which verifies a secp256k1 ECDSA
	// signature — a quantum-vulnerable scheme on a quantum-safe (Dilithium3)
	// chain. Default false = fail-closed: opAuth refuses authorization and
	// pushes 0. Enable only for EVM-compatibility testing via
	// EnableECDSAAuth (see Executor.EnableECDSAAuth for the env-var and
	// production guards).
	ecdsaAuthEnabled bool

	// R43-QVM-BYTECODE-01 (2026-08-03): gates whether ValidateBytecode
	// rejects unknown opcodes. Default false (production-hardened): invalid
	// opcodes fail deployment validation, blocking malicious / malformed
	// contracts at deployment instead of letting them pass and fail at
	// runtime (which was the audit's concern — a contract could appear to
	// deploy OK and then maliciously fail-on-execution, or exploit a
	// future added opcode). Set to true via SetDevnetValidation on
	// devnets where EVM-compatibility experimentation tolerates unknown
	// opcodes (e.g. future-EVM opcode probes on a test L2).
	//
	// Backward compatibility: existing Executor + node code paths create
	// Interpreters via NewInterpreter(), which defaults to false
	// (production-hardened). Existing tests that construct an Interpreter
	// directly and expect "unknown opcodes allowed" should call
	// SetDevnetValidation(true) explicitly.
	devnetValidation bool
}

// NewInterpreter creates a new QVM interpreter.
func NewInterpreter() *Interpreter {
	return &Interpreter{
		gasTable:      DefaultGasTable(),
		precompiled:   precompiled.NewRegistry(),
		jumpDestCache: make(map[Hash]map[uint64]bool),
		jumpDestOrder: make([]Hash, 0, maxJumpDestCacheSize),
	}
}

// SetDevnetValidation toggles ValidateBytecode's tolerance of unknown
// opcodes. R43-QVM-BYTECODE-01 (2026-08-03). When true (devnet), unknown
// opcodes are logged + advanced (legacy behavior). When false (default,
// production), ValidateBytecode rejects deployment of bytecode containing
// any unknown opcode. Idempotent.
//
// Callers:
//   - node wiring on chainID == 1333 (devnet) or 1334 (devnet L2) should
//     call SetDevnetValidation(true).
//   - all other chain IDs keep the default (production-hardened).
//
// Not guarded by a mutex: SetDevnetValidation is intended to be called ONCE
// during interpreter construction / node startup, BEFORE the interpreter is
// shared across goroutines. Concurrent toggling during execution is not
// supported (and is a sign of a wiring bug rather than a real use case).
func (i *Interpreter) SetDevnetValidation(devnet bool) {
	i.devnetValidation = devnet
}

// EnableECDSAAuth enables the secp256k1 ECDSA AUTH authorization path.
// R37-INFO (2026-07-31): disabled by default because secp256k1 is
// quantum-vulnerable on a quantum-safe (Dilithium3) chain. Callers should
// prefer the Executor-level gate (Executor.EnableECDSAAuth), which
// enforces env-var and production guards.
func (i *Interpreter) EnableECDSAAuth() {
	i.ecdsaAuthEnabled = true
}

// Execute executes the bytecode in the given context.
func (i *Interpreter) Execute(ctx *ExecutionContext, stateDB StateDB) *ExecutionResult {
	// Create execution environment
	env := &Environment{
		ctx:         ctx,
		stateDB:     stateDB,
		stack:       NewStack(),
		memory:      NewMemory(),
		gas:         NewGasMeter(ctx.Gas),
		gasTable:    i.gasTable,
		precompiled: i.precompiled,
		pc:          0,
		logs:        make([]*Log, 0),
		returnData:  nil,
		blockHashes: ctx.BlockHashes,
		// R34-QVM-P0-001 FIX: Initialize callDepth from ctx.Depth to ensure
		// consistent depth tracking across nested calls. Previously callDepth
		// defaulted to 0 for every new environment, causing depth to reset
		// at each call frame — sub-call environments would see callDepth=0
		// instead of the actual nesting depth, breaking reentrancy checks
		// that rely on callDepth >= 1 for cross-contract call detection.
		callDepth: uint64(ctx.Depth),
		// R40-C-H1 FIX: Set parentEnv so IsAddressActive can traverse the call chain.
		// For top-level tx execution, ctx.ParentEnv is nil (correct — chain starts here).
		// For sub-call execution, ctx.ParentEnv points to the calling environment.
		parentEnv: ctx.ParentEnv,
	}

	// FIX: EIP-1153 transient storage is per-transaction, shared across all calls.
	// FIX: Also propagate txCreatedContracts (EIP-6780) from parent environment.
	if ctx.ParentEnv != nil {
		env.transientStorage = ctx.ParentEnv.transientStorage
		env.txCreatedContracts = ctx.ParentEnv.txCreatedContracts
		// AUDIT (2026) QVM-07: Share reentry counts across call frames.
		env.reentryCounts = ctx.ParentEnv.reentryCounts
	} else {
		env.transientStorage = make(map[Address]map[Hash]Hash)
		// FIX: initialize txCreatedContracts for top-level transactions.
		// Without this, the map is nil and CREATE operations would need to
		// lazily initialize it (which they do at operations_missing.go:1309),
		// but SELFDESTRUCT checks (operations_missing.go:674) treat nil as
		// "no contracts created in this tx" — which is correct but fragile.
		// Initializing here makes the intent explicit and prevents subtle bugs.
		env.txCreatedContracts = make(map[Address]bool)
		// AUDIT (2026) QVM-07: Initialize reentry counter for top-level tx.
		env.reentryCounts = make(map[Address]int)
	}

	// audit-fix CRIT-REENTRY: Initialize and propagate active addresses.
	// Now includes the entry-point contract address to protect against
	// classic DAO-style reentrancy attacks on the caller.
	if ctx.ParentEnv != nil {
		env.activeAddresses = make([]Address, len(ctx.ParentEnv.activeAddresses))
		copy(env.activeAddresses, ctx.ParentEnv.activeAddresses)
	} else {
		// R40-C5 FIX: For top-level calls, push the caller (origin tx sender) into
		// activeAddresses BEFORE pushing the callee. Without this, the caller address
		// is never tracked, so contract B calling back to caller A won't trigger
		// reentrancy detection — enabling classic DAO-style attacks.
		env.activeAddresses = make([]Address, 0, 2)
		if ctx.Caller != ctx.Address {
			env.PushActiveAddress(ctx.Caller)
		}
	}
	env.PushActiveAddress(ctx.Address)
	// No defer Pop here as this is the top-level env being returned

	// Analyze jump destinations
	jumpDests := i.analyzeJumpDests(ctx.Code)
	env.jumpDests = jumpDests

	// R37-P1-QVM-01 FIX (2026-07-30): EIP-1153 transient storage must roll
	// back when a sub-call REVERTs or errors. Sub-call envs SHARE the
	// parent's transientStorage root map (above) and TSTORE writes land
	// directly in it with no journaling, so a reverted sub-call's writes
	// previously survived — poisoning sibling calls and defeating
	// TSTORE-based reentrancy locks (e.g. ReentrancyGuardTransient).
	// Deep-copy the shared map before execution; on failure restore it
	// IN PLACE (clear + repopulate) so every env holding the same
	// reference observes the pre-call state. Reassigning the map pointer
	// would leave ancestor envs holding the dirty object.
	var tsSnapshot map[Address]map[Hash]Hash
	if ctx.ParentEnv != nil && ctx.ParentEnv.transientStorage != nil {
		tsSnapshot = make(map[Address]map[Hash]Hash, len(ctx.ParentEnv.transientStorage))
		for addr, slots := range ctx.ParentEnv.transientStorage {
			inner := make(map[Hash]Hash, len(slots))
			for k, v := range slots {
				inner[k] = v
			}
			tsSnapshot[addr] = inner
		}
	}

	// Execute bytecode
	result := i.run(env)

	if env.tracer != nil {
		env.tracer.CaptureEnd(result.ReturnData, result.GasUsed, result.Err)
	}

	// R37-P1-QVM-01: restore transient storage on ANY failure (execution
	// error or REVERT), mirroring the stateDB RevertToSnapshot the call
	// opcodes perform on the same condition. In-place restore, see above.
	if tsSnapshot != nil && (result.Err != nil || result.Reverted) {
		shared := ctx.ParentEnv.transientStorage
		for addr := range shared {
			delete(shared, addr)
		}
		for addr, slots := range tsSnapshot {
			inner := make(map[Hash]Hash, len(slots))
			for k, v := range slots {
				inner[k] = v
			}
			shared[addr] = inner
		}
	}

	return result
}

// ValidateBytecode validates that the bytecode is well-formed.
func (i *Interpreter) ValidateBytecode(code []byte) error {
	if len(code) > MaxCodeSize {
		return ErrMaxCodeSizeExceeded
	}

	// Validate all opcodes
	for pc := 0; pc < len(code); {
		op := OpCode(code[pc])

		// Check if opcode is valid
		if !op.IsValid() {
			// R43-QVM-BYTECODE-01 (2026-08-03): audit-fix — previously
			// `continue`d silently for ALL deployment calls, letting
			// malicious / malformed contracts pass deployment validation
			// and only fail at runtime. A contract could appear to deploy
			// OK and then maliciously abort execution (e.g. placeholder
			// opcode inserted to bypass static-analysis fraud proofs), or
			// exploit a future-added opcode to break forward compatibility.
			// On production chains (default, devnetValidation=false) we
			// REJECT deployment of bytecode with unknown opcodes; on
			// devnets (devnetValidation=true) we keep the legacy permissive
			// behavior to support EVM-compatibility experiments that probe
			// not-yet-supported opcodes.
			if !i.devnetValidation {
				return fmt.Errorf("%w: unknown opcode 0x%02x at pc %d", ErrInvalidBytecode, byte(op), pc)
			}
			// Devnet permissive path: log + advance (legacy behavior).
			// NOTE: we do not log per-opcode warnings here because a single
			// malicious payload could spam logs; the operator is expected
			// to diagnose via the contract's runtime revert, which will
			// surface the unknown opcode at execution time.
			pc++
			continue
		}

		// Skip immediate data for PUSH instructions
		if op.IsPush() {
			pc += 1 + op.PushSize()
		} else {
			pc++
		}
	}

	return nil
}

// EstimateGas estimates the gas required for execution.
// M-NEW-3 FIX: Added execution timeout to prevent CPU exhaustion from malicious
// contracts that consume excessive computation during gas estimation.
// SECURITY FIX H-9: Use an abort channel to cancel the goroutine on timeout.
// Previously, when the timeout fired, the goroutine continued running
// indefinitely (until gas was exhausted), leaking CPU and memory resources.
// Now the abort channel is closed on timeout, and the run loop checks it
// periodically (every 1024 opcodes) and terminates early.
func (i *Interpreter) EstimateGas(ctx *ExecutionContext, stateDB StateDB) (uint64, error) {
	const MaxSafeGas uint64 = 1<<63 - 1
	const MaxEstimationGas uint64 = 30000000
	const EstimationTimeout = 5 * time.Second // audit-fix MED-2: wall-clock timeout for gas estimation

	estimateCtx := *ctx
	estimateCtx.Gas = MaxSafeGas
	if estimateCtx.Gas > MaxEstimationGas {
		estimateCtx.Gas = MaxEstimationGas
	}

	// SECURITY FIX H-9: Create an abort channel that will be closed on timeout.
	// The run loop checks this channel periodically and terminates early.
	abortCh := make(chan struct{})
	estimateCtx.AbortCh = abortCh

	type estimateResult struct {
		gasUsed uint64
		err     error
	}

	ch := make(chan estimateResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- estimateResult{gasUsed: 0, err: fmt.Errorf("estimateGas goroutine panic: %v", r)}
			}
		}()
		snapshot := stateDB.Snapshot()
		result := i.Execute(&estimateCtx, stateDB)
		stateDB.RevertToSnapshot(snapshot)

		if result.Err != nil && !result.Reverted {
			ch <- estimateResult{gasUsed: 0, err: result.Err}
			return
		}

		buffer := result.GasUsed / 10
		if result.GasUsed > (^uint64(0) - buffer) {
			ch <- estimateResult{gasUsed: ^uint64(0), err: nil}
			return
		}
		ch <- estimateResult{gasUsed: result.GasUsed + buffer, err: nil}
	}()

	select {
	case r := <-ch:
		return r.gasUsed, r.err
	case <-time.After(EstimationTimeout):
		// SECURITY FIX H-9: Close the abort channel to signal the goroutine
		// to terminate. The run loop checks this channel every 1024 opcodes
		// and will exit early, preventing the goroutine from leaking.
		close(abortCh)
		// Wait for the goroutine to finish to ensure proper cleanup.
		// Use a short grace period to avoid blocking too long.
		select {
		case <-ch:
			// Goroutine finished after abort signal
		case <-time.After(500 * time.Millisecond):
			// Goroutine didn't finish within grace period; proceed anyway.
			// The goroutine will eventually finish and send to the buffered
			// channel (size 1), so it won't block forever.
		}
		return 0, errors.New("gas estimation timed out after 5 seconds")
	}
}

// analyzeJumpDests finds all valid jump destinations in the code.
// audit-fix R2-L1: bounded cache with FIFO eviction.
// audit-fix R3-M7: actually populate and look up the cache.
func (i *Interpreter) analyzeJumpDests(code []byte) map[uint64]bool {
	// Compute code hash for cache key
	rawHash := sha256.Sum256(code)
	var codeHash Hash
	copy(codeHash[:], rawHash[:])

	// audit-fix R3-M1: lock protects the shared cache from concurrent Execute() calls.
	i.cacheMu.Lock()
	defer i.cacheMu.Unlock()

	// Cache lookup
	if cached, ok := i.jumpDestCache[codeHash]; ok {
		return cached
	}

	dests := make(map[uint64]bool)

	for pc := 0; pc < len(code); {
		op := OpCode(code[pc])

		if op == JUMPDEST {
			dests[uint64(pc)] = true //nolint:gosec,G115
		}

		// Skip immediate data for PUSH instructions
		if op.IsPush() {
			//  Validate PUSH immediate data is within code boundaries.
			// If the PUSH data extends past the end of the code, the remaining
			// bytes are part of the immediate data and must not be marked as
			// jump destinations. Stop the analysis here.
			nextPC := pc + 1 + op.PushSize()
			if nextPC > len(code) {
				break
			}
			pc = nextPC
		} else {
			pc++
		}
	}

	// Evict oldest entries if cache is full
	if len(i.jumpDestCache) >= maxJumpDestCacheSize {
		// Remove oldest quarter of entries
		evictCount := maxJumpDestCacheSize / 4
		if evictCount > len(i.jumpDestOrder) {
			evictCount = len(i.jumpDestOrder)
		}
		// MED-1 FIX: Copy slice before iteration to prevent race condition
		// If another goroutine accesses jumpDestOrder during the delete loop,
		// it might see partial/modified state. Copy first, then modify atomically.
		toEvict := make([]Hash, evictCount)
		copy(toEvict, i.jumpDestOrder[:evictCount])
		for _, h := range toEvict {
			delete(i.jumpDestCache, h)
		}
		i.jumpDestOrder = i.jumpDestOrder[evictCount:]
	}

	// Insert into cache and track insertion order
	i.jumpDestCache[codeHash] = dests
	i.jumpDestOrder = append(i.jumpDestOrder, codeHash)

	return dests
}
