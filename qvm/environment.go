// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"errors"
	"fmt"
	"log"

	"github.com/quantaureum/qau/qvm/precompiled"
)

// Environment holds the execution state for the interpreter.
type Environment struct {
	ctx      *ExecutionContext
	stateDB  StateDB
	stack    *Stack
	memory   *Memory
	gas      *GasMeter
	gasTable *GasTable
	// precompiled holds the registry of precompiled contracts, used by
	// CALL/STATICCALL/DELEGATECALL/CALLCODE to detect and execute
	// precompiled contract logic directly instead of trying to run
	// empty bytecode (which would succeed with no return data).
	precompiled *precompiled.Registry

	pc         uint64          // Program counter
	jumpDests  map[uint64]bool // Valid jump destinations
	logs       []*Log          // Emitted logs
	returnData []byte          // Return data from last call

	// Execution state
	stopped  bool
	reverted bool
	err      error

	// SECURITY FIX QVM-H3: Reentrancy protection
	// Tracks the current call depth to prevent reentrancy attacks
	callDepth uint64

	activeAddresses []Address // audit-fix CRIT-4: tracks active addresses for cross-contract reentrancy detection

	// R40-C-H1 FIX: Parent environment reference for traversing the call stack.
	// This enables IsAddressActive to check the entire call chain, not just
	// the current environment's activeAddresses. Critical for detecting A→B→A
	// attacks where B's code calls back A (factory pattern CREATE scenario).
	parentEnv *Environment

	// R40-C-H2 FIX: EIP-6780 self-destruct semantics.
	// Tracks contracts created during this transaction. Under EIP-6780 (active post-Shanghai),
	// a contract can only self-destruct if it was created in the same transaction.
	// This map is shared across all environments within a transaction via copying.
	txCreatedContracts map[Address]bool
	// QVM-R10-M2 (2026-07-19) FIX: EIP-6780 same-tx re-creation support.
	// When a contract self-destructs and is then RE-CREATED at the same
	// address within the same tx, the stateDB's HasSelfDestructed flag
	// remains set (stateDB implementations typically don't expose a Clear
	// method). To allow the re-created contract to self-destruct AGAIN
	// (which EIP-6780 permits, since it's a fresh creation), we track the
	// set of addresses whose HasSelfDestructed flag we've logically cleared
	// via re-creation. opSelfDestruct consults this set before applying
	// the HasSelfDestructed early-return no-op. The set is shared across
	// all environments within a transaction (same pattern as
	// txCreatedContracts).
	selfDestructCleared map[Address]bool

	// Self-destruct state
	selfDestructed          bool
	selfDestructBeneficiary Address

	// Block hashes for BLOCKHASH opcode (last 256 blocks)
	blockHashes map[uint64]Hash

	// EIP-1153 transient storage (per-transaction, shared across calls within same tx)
	transientStorage map[Address]map[Hash]Hash

	// AUDIT (2026) QVFIX: Per-transaction reentry counter per address.
	// The 2300 gas penalty is an economic disincentive but not a hard block.
	// This counter caps how many times a single address can be re-entered
	// within one transaction, preventing pathological reentrancy attacks
	// where an attacker is willing to pay the gas cost. Shared across all
	// call frames in the transaction (like transientStorage).
	reentryCounts map[Address]int

	// EIP-7702 authorized address (set by AUTH opcode, used by AUTHCALL)
	// nil means no authorization has been set (AUTH not yet called or failed)
	authorizedAddress *Address

	// SECURITY (audit 2026-06-26, P1-02): Track PQC key memory regions for
	// automatic zeroization at end of execution. Prevents Kyber private keys
	// and shared secrets from persisting in QVM memory after the contract
	// finishes executing, blocking extraction via memory dumps or bugs.
	pqcKeyRegions []memoryRegion

	tracer Tracer
}

// memoryRegion tracks a memory region containing sensitive PQC key material.
// SECURITY (audit 2026-06-26, P1-02): Used by auto-zeroization to clean up
// Kyber private keys and shared secrets from QVM memory after execution.
type memoryRegion struct {
	offset uint64
	size   uint64
}

// audit-fix CRIT-4: Track active contract addresses in the call stack
// to detect cross-contract reentrancy (A→B→A attack pattern).

// IsAddressActive checks if the given address is already in the active call stack.
// R40-C-H1 FIX: Now traverses the full parent environment chain to detect
// cross-contract reentrancy (A→B→A pattern) in factory contract scenarios where
// a contract's constructor creates another contract via CREATE and that contract
// then calls back into the original factory. Without parent chain traversal,
// the re-entry check would only see the immediate environment's activeAddresses.
func (env *Environment) IsAddressActive(addr Address) bool {
	for ; env != nil; env = env.parentEnv {
		for _, active := range env.activeAddresses {
			if active == addr {
				return true
			}
		}
	}
	return false
}

// PushActiveAddress adds an address to the active call stack.
// Returns true if the address was pushed, false if max depth was exceeded.
// R24-C8 FIX: No longer silently skips - returns false to prevent call imbalance.
// Callers must check return value and fail the call if false is returned.
const MaxActiveCallDepth = 1024

// AUDIT (2026) QVFIX: Maximum number of times a single address can
// be re-entered within one transaction before being hard-blocked. The 2300 gas
// penalty remains as the economic disincentive for each reentry; this cap
// prevents pathological cases where an attacker is willing to pay the gas.
//
// AUDIT (2026) R4-QVFIX: Increased from 3 to 10. The original limit
// of 3 was found to harm legitimate composability patterns (router → AMM →
// token → callback → aggregator → ... can easily exceed 3 levels). A limit
// of 10 still caps worst-case reentrancy depth (vs. EVM which has no hard
// count limit — EVM relies solely on gas) while accommodating real-world
// DeFi composability. The limit is also per-transaction configurable via
// SetMaxReentriesPerAddress on the root Environment.
const MaxReentriesPerAddress = 10

func (env *Environment) PushActiveAddress(addr Address) bool {
	if len(env.activeAddresses) >= MaxActiveCallDepth {
		// R24-C8 FIX: Return false instead of silently skipping.
		// This prevents call depth / activeAddresses mismatch that could
		// break reentrancy protection. The caller must fail the call
		// when false is returned.
		return false
	}
	env.activeAddresses = append(env.activeAddresses, addr)
	return true
}

// IncrementReentryCount increments the per-transaction reentry counter for the
// given address and returns true if the address is still within the allowed
// reentry cap, false if the cap has been exceeded (caller should hard-block).
//
// AUDIT (2026) QVFIX: The reentryCounts map is shared across all
// call frames in the transaction (propagated like transientStorage). The root
// environment owns the map; child environments share the same pointer.
//
// QVM- (2026-07-20) FIX: Previously this method ALWAYS incremented
// and then checked `<= MaxReentriesPerAddress`. When the check failed (count
// already at limit), the increment had already pushed count to limit+1,
// permanently saturating the counter. Combined with the missing
// DecrementReentryCount, this meant a single address could be permanently
// DoS'd after MaxReentriesPerAddress reentries. Now we check BEFORE
// incrementing, so a blocked call does not pollute the counter.
func (env *Environment) IncrementReentryCount(addr Address) bool {
	// Traverse to the root environment that owns the reentryCounts map.
	root := env
	for root.parentEnv != nil {
		root = root.parentEnv
	}
	if root.reentryCounts == nil {
		root.reentryCounts = make(map[Address]int)
	}
	// QVM- Check BEFORE incrementing to avoid over-saturating the
	// counter when the call is going to be blocked anyway.
	if root.reentryCounts[addr] >= MaxReentriesPerAddress {
		return false
	}
	root.reentryCounts[addr]++
	return true
}

// DecrementReentryCount decrements the per-transaction reentry counter for
// the given address. This MUST be called when a CALL frame that previously
// called IncrementReentryCount returns (success, revert, or error).
//
// QVM- (2026-07-20) FIX: Previously there was no decrement path —
// once an address was re-entered up to MaxReentriesPerAddress times within
// a transaction, the counter stayed at that value forever, blocking all
// subsequent CALLs to that address for the rest of the transaction. This
// caused permanent DoS within a transaction after legitimate composability.
//
// Safety:
//   - Clamped at 0 (never goes negative) to defend against bugs where
//     Decrement is called without a matching Increment.
//   - Traverses to root environment (same as IncrementReentryCount) so the
//     shared counter is updated correctly.
func (env *Environment) DecrementReentryCount(addr Address) {
	// Traverse to the root environment that owns the reentryCounts map.
	root := env
	for root.parentEnv != nil {
		root = root.parentEnv
	}
	if root.reentryCounts == nil {
		// Map was never initialized — nothing to decrement (defensive).
		return
	}
	if root.reentryCounts[addr] <= 0 {
		// Already at zero (or absent) — delete to keep the map clean.
		// This prevents the map from accumulating zero-count entries.
		delete(root.reentryCounts, addr)
		return
	}
	root.reentryCounts[addr]--
	// If decrement brought the counter to zero, delete the entry to keep
	// the map clean (matches the "already at zero" branch above).
	if root.reentryCounts[addr] == 0 {
		delete(root.reentryCounts, addr)
	}
}

// PopActiveAddress removes the last address from the active call stack.
// R30-P3 FIX: Log warning on empty stack instead of silently returning.
// Silent return could mask bugs in call stack management.
func (env *Environment) PopActiveAddress() {
	if len(env.activeAddresses) > 0 {
		env.activeAddresses = env.activeAddresses[:len(env.activeAddresses)-1]
	} else {
		log.Printf("WARN: PopActiveAddress called on empty activeAddresses stack")
	}
}

func (env *Environment) Stack() *Stack {
	return env.stack
}

func (env *Environment) Memory() *Memory {
	return env.memory
}

func (env *Environment) Gas() *GasMeter {
	return env.gas
}

func (env *Environment) Ctx() *ExecutionContext {
	return env.ctx
}

func (env *Environment) StateDB() StateDB {
	return env.stateDB
}

func (env *Environment) SetTracer(t Tracer) {
	env.tracer = t
}

func (env *Environment) Tracer() Tracer {
	return env.tracer
}

func (env *Environment) Stopped() bool {
	return env.stopped
}

func (env *Environment) SetStopped(v bool) {
	env.stopped = v
}

func (env *Environment) GetBlockHash(blockNum uint64) Hash {
	return env.getBlockHash(blockNum)
}

func (env *Environment) AddLog(log *Log) {
	env.logs = append(env.logs, log)
}

func (env *Environment) SetReturnData(data []byte) {
	env.returnData = data
}

func (env *Environment) ReturnData() []byte {
	return env.returnData
}

func (env *Environment) SetReverted(v bool) {
	env.reverted = v
}

func (env *Environment) SetErr(err error) {
	env.err = err
}

func (env *Environment) Err() error {
	return env.err
}

func (env *Environment) PC() uint64 {
	return env.pc
}

func (env *Environment) SetPC(pc uint64) {
	env.pc = pc
}

func (env *Environment) JumpDests() map[uint64]bool {
	return env.jumpDests
}

func (env *Environment) GasTable() *GasTable {
	return env.gasTable
}

// getBlockHash returns the block hash for a given block number.
// It looks up the hash from the blockHashes map which contains the last 256 blocks.
// Returns zero hash if the block number is not in the accessible range.
func (env *Environment) getBlockHash(blockNum uint64) Hash {
	// BLOCKHASH should only work for the most recent 256 blocks
	currentBlock := env.ctx.BlockNumber
	if blockNum >= currentBlock || currentBlock-blockNum > 256 {
		// Return zero hash for blocks outside the accessible range
		return Hash{}
	}

	// Look up from blockHashes map
	if env.blockHashes != nil {
		if hash, ok := env.blockHashes[blockNum]; ok {
			return hash
		}
	}

	return Hash{}
}

// run executes the bytecode until completion.
//
// QVM-R10-C1 (2026-07-19) FIX: Added outermost defer recover() around the
// entire main execution loop. Previously, a malicious contract could
// trigger a panic (e.g., via an array out-of-bounds, nil dereference,
// or integer overflow in an opcode implementation) that would propagate
// up the stack and crash the entire node — a single malicious
// transaction could DoS the whole network.
//
// The recover converts any such panic into a regular execution error
// (ErrPanicRecovery) so the transaction fails and is reverted, but the
// node continues operating. This matches the defense-in-depth pattern
// used by go-ethereum's EVM interpreter (exec() wraps op execution in
// a recover for the same reason).
//
// Scope: this recover wraps the WHOLE run loop, including opcode
// dispatch, gas accounting, stack management, and memory operations.
// Per-opcode re-panic is unnecessary because any panic from anywhere
// in the call tree is caught here.
func (i *Interpreter) run(env *Environment) (result *ExecutionResult) {
	// QVM-R10-C1: Outermost panic recovery. Captures any panic raised
	// during opcode execution and converts it to an execution error.
	// The deferred function runs AFTER we finish building `result` (the
	// named return value), so we can inspect `result` and replace it
	// with an error result if a panic occurred.
	defer func() {
		if r := recover(); r != nil {
			// Log the panic for forensic/debugging purposes. Include the
			// PC and remaining gas to aid in reproducing the issue.
			log.Printf("ERROR: QVM Interpreter.run panic recovered (pc=%d gas_remaining=%d): %v",
				env.pc, env.gas.Remaining(), r)

			// Zeroize PQC key regions defensively — the normal cleanup
			// path at the end of run() was skipped because of the panic,
			// so sensitive key material might still be in memory.
			// R35-P3 FIX (2026-07-29): Log ZeroRange errors instead of
			// silently discarding them with `_ =`. The normal cleanup path
			// (below) already logs these errors; the panic recovery path
			// must do the same so memory-corruption or region-tracking
			// bugs are not masked during panic-driven exits.
			memSize := env.memory.Size()
			for _, region := range env.pqcKeyRegions {
				if region.size == 0 {
					continue
				}
				end := region.offset + region.size
				if end < region.offset || end > memSize {
					continue
				}
				if err := env.memory.ZeroRange(region.offset, region.size); err != nil {
					log.Printf("WARN: PQC key zeroing failed in panic recovery (offset=%d, size=%d): %v",
						region.offset, region.size, err)
				}
			}
			env.pqcKeyRegions = nil

			// Build a synthetic error result. We mark the execution as
			// reverted so any state changes are rolled back — the
			// caller (Executor) treats Reverted=true as a rollback.
			// Gas accounting: we consume ALL remaining gas on panic,
			// matching the EVM convention for out-of-gas and other
			// fatal execution errors. This also discourages attackers
			// from using panic-triggering contracts for gas griefing.
			//
			// QVM-R14-CRIT-001 (2026-07-21) FIX: Previously this branch
			// computed GasUsed = Limit - Remaining (only used gas),
			// which contradicted both the comment above and the JIT
			// panic-recovery path in executor.go (which sets GasUsed =
			// ctx.Gas, consuming all gas). The divergence meant a
			// panic-triggering transaction produced different GasUsed
			// values (and therefore different receipt roots) depending
			// on whether JIT was active — a consensus fork risk. Now
			// both paths consume the full gas limit on panic.
			//
			// AUDIT-FULL H-5 (2026-08-14): GasUsed now reads
			// env.ctx.Gas directly (as the JIT path does) instead of
			// env.gas.Limit(). In production the two are equal
			// (NewGasMeter(ctx.Gas)), but a GasMeter whose limit was
			// constructed differently (e.g. sub-frames or future gas
			// re-parenting) would silently diverge the two panic paths
			// again. ctx.Gas is the single source of truth.
			result = &ExecutionResult{
				ReturnData: nil,
				GasUsed:    env.ctx.Gas,
				GasRefund:  0,
				Logs:       env.logs,
				Err:        fmt.Errorf("%w: %v", ErrPanicRecovery, r),
				Reverted:   true,
			}
			// R31-P2 FIX (P2-7, 2026-07-28): Sync env state with the result.
			// Previously, only `result` was updated but env.reverted/env.err
			// were left stale (false/nil). Callers that inspect env directly
			// (e.g., opCreateGeneric before the P0-01 fix) would miss the
			// panic and treat the execution as successful, causing state
			// pollution. This is the root cause of P0-01.
			env.reverted = true
			env.err = fmt.Errorf("%w: %v", ErrPanicRecovery, r)
		}
	}()

	code := env.ctx.Code

	// SECURITY FIX H-9: opCounter is used to periodically check the abort channel.
	// Checking every opcode would be too expensive, so we check every 1024 opcodes.
	const abortCheckInterval = 1024
	opCounter := 0

	for !env.stopped && env.pc < uint64(len(code)) {
		// SECURITY FIX H-9: Check abort channel periodically to allow
		// cancellation of long-running executions (e.g., EstimateGas timeout).
		if env.ctx.AbortCh != nil {
			opCounter++
			if opCounter >= abortCheckInterval {
				opCounter = 0
				select {
				case <-env.ctx.AbortCh:
					env.err = errors.New("execution aborted")
					env.stopped = true
				default:
				}
			}
		}
		if env.stopped {
			break
		}

		// Fetch opcode
		op := OpCode(code[env.pc])

		// Get opcode info
		info, valid := op.GetInfo()
		if !valid {
			env.err = ErrInvalidOpcode
			env.stopped = true
			break
		}

		// Check stack requirements
		if env.stack.Len() < info.StackPop {
			env.err = ErrStackUnderflow
			env.stopped = true
			break
		}

		// QVM-STACK-01 FIX (deep-audit 2026-07-12): use strict `>` so the stack
		// may legally reach exactly MaxStackSize (1024), matching the EVM/geth
		// bound (`sLen - pop + push > StackLimit`) and Stack.Push itself, which
		// already permits up to 1024 entries. The previous `>=` was an
		// off-by-one that capped the effective depth at 1023, rejecting valid
		// EVM programs that use the full 1024-slot stack.
		// FIX: For DUPn/SWAPn, StackPop represents min stack depth (not
		// items removed). These opcodes don't pop items, so don't subtract StackPop
		// from the stack size when checking overflow.
		itemsRemoved := info.StackPop
		if isDupOrSwap(op) {
			itemsRemoved = 0
		}
		if env.stack.Len()-itemsRemoved+info.StackPush > MaxStackSize {
			env.err = ErrStackOverflow
			env.stopped = true
			break
		}

		// Consume base gas
		if err := env.gas.Consume(info.GasCost); err != nil {
			env.err = err
			env.stopped = true
			break
		}

		// Execute opcode
		env.pc++
		if err := i.executeOp(env, op); err != nil {
			env.err = err
			env.stopped = true
			break
		}
	}

	// SECURITY (audit 2026-06-26, P1-02): Zeroize all tracked PQC key material
	// from memory after execution completes. This ensures Kyber private keys
	// and shared secrets generated during contract execution do not persist
	// in QVM memory beyond the contract's lifetime, preventing extraction via
	// memory dumps, cold boot attacks, or memory read vulnerabilities.
	// FIX: Log warning instead of silently ignoring ZeroRange errors.
	// Silent ignoring could mask memory corruption or bugs in region tracking.
	// QVM-FIX: Skip regions that fall outside the current memory size
	// to avoid expanding memory after OOG. ZeroRange calls expand() which
	// would force memory growth even when the main loop exited early (e.g.
	// out-of-gas), wasting resources. Only zero regions already in range.
	memSize := env.memory.Size()
	for _, region := range env.pqcKeyRegions {
		if region.size == 0 {
			continue
		}
		end := region.offset + region.size
		if end < region.offset || end > memSize {
			// Region extends beyond current memory; skip to avoid expansion.
			continue
		}
		if err := env.memory.ZeroRange(region.offset, region.size); err != nil {
			log.Printf("WARN: PQC key zeroing failed (offset=%d, size=%d): %v",
				region.offset, region.size, err)
		}
	}
	env.pqcKeyRegions = nil

	// Build result
	result = &ExecutionResult{
		ReturnData: env.returnData,
		// R30-QVFIX: Use FinalUsed() to report net gas after EIP-3529 refunds.
		// FinalUsed() returns g.used - actualRefund where actualRefund = min(g.refund, g.used/5).
		GasUsed:   env.gas.FinalUsed(),
		GasRefund: env.gas.RefundAmount(),
		Logs:      env.logs,
		Err:       env.err,
		Reverted:  env.reverted,
	}

	return result
}

// executeOp executes a single opcode.
func (i *Interpreter) executeOp(env *Environment, op OpCode) error {
	switch op {
	// Control Flow
	case STOP:
		env.stopped = true
		return nil

	case JUMP:
		dest, err := env.stack.PopUint64()
		if err != nil {
			return err
		}
		if !env.jumpDests[dest] {
			return ErrInvalidJumpDest
		}
		env.pc = dest
		return nil

	case JUMPI:
		dest, err := env.stack.PopUint64()
		if err != nil {
			return err
		}
		cond, err := env.stack.Pop()
		if err != nil {
			return err
		}
		if !cond.IsZero() {
			if !env.jumpDests[dest] {
				return ErrInvalidJumpDest
			}
			env.pc = dest
		}
		return nil

	case JUMPDEST:
		// No-op, just a marker
		return nil

	case PC:
		return env.stack.PushUint64(env.pc - 1)

	case NOP:
		return nil

	case RETURN:
		return i.opReturn(env)

	case REVERT:
		return i.opRevert(env)

	case INVALID:
		return ErrInvalidOpcode

	case SIGNEXTEND:
		return i.opSignExtend(env)

	case PUSH0:
		return env.stack.Push(Word{})

	// Stack Operations
	case PUSH1, PUSH2, PUSH3, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8,
		PUSH9, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16,
		PUSH17, PUSH18, PUSH19, PUSH20, PUSH21, PUSH22, PUSH23, PUSH24,
		PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH30, PUSH31, PUSH32:
		return i.opPush(env, op)

	case POP:
		_, err := env.stack.Pop()
		return err

	case DUP1:
		return env.stack.Dup(1)
	case DUP2:
		return env.stack.Dup(2)
	case DUP3:
		return env.stack.Dup(3)
	case DUP4:
		return env.stack.Dup(4)
	// audit-fix R69-QVM-2 [CRITICAL]: Extended DUP opcodes in 0xD0-0xDB range
	case DUP5:
		return env.stack.Dup(5)
	case DUP6:
		return env.stack.Dup(6)
	case DUP7:
		return env.stack.Dup(7)
	case DUP8:
		return env.stack.Dup(8)
	case DUP9:
		return env.stack.Dup(9)
	case DUP10:
		return env.stack.Dup(10)
	case DUP11:
		return env.stack.Dup(11)
	case DUP12:
		return env.stack.Dup(12)
	case DUP13:
		return env.stack.Dup(13)
	case DUP14:
		return env.stack.Dup(14)
	case DUP15:
		return env.stack.Dup(15)
	case DUP16:
		return env.stack.Dup(16)

	case SWAP1:
		return env.stack.Swap(1)
	case SWAP2:
		return env.stack.Swap(2)
	case SWAP3:
		return env.stack.Swap(3)
	case SWAP4:
		return env.stack.Swap(4)
	// audit-fix R69-QVM-1 [CRITICAL]: Extended SWAP opcodes in 0xDC-0xE7 range
	case SWAP5:
		return env.stack.Swap(5)
	case SWAP6:
		return env.stack.Swap(6)
	case SWAP7:
		return env.stack.Swap(7)
	case SWAP8:
		return env.stack.Swap(8)
	case SWAP9:
		return env.stack.Swap(9)
	case SWAP10:
		return env.stack.Swap(10)
	case SWAP11:
		return env.stack.Swap(11)
	case SWAP12:
		return env.stack.Swap(12)
	case SWAP13:
		return env.stack.Swap(13)
	case SWAP14:
		return env.stack.Swap(14)
	case SWAP15:
		return env.stack.Swap(15)
	case SWAP16:
		return env.stack.Swap(16)

	// Arithmetic Operations
	case ADD:
		return i.opAdd(env)
	case SUB:
		return i.opSub(env)
	case MUL:
		return i.opMul(env)
	case DIV:
		return i.opDiv(env)
	case SDIV:
		return i.opSDiv(env)
	case MOD:
		return i.opMod(env)
	case SMOD:
		return i.opSMod(env)
	case ADDMOD:
		return i.opAddMod(env)
	case MULMOD:
		return i.opMulMod(env)
	case EXP:
		return i.opExp(env)

	// Comparison Operations
	case LT:
		return i.opLt(env)
	case GT:
		return i.opGt(env)
	case SLT:
		return i.opSlt(env)
	case SGT:
		return i.opSgt(env)
	case EQ:
		return i.opEq(env)
	case ISZERO:
		return i.opIsZero(env)

	// Bitwise Operations
	case AND:
		return i.opAnd(env)
	case OR:
		return i.opOr(env)
	case XOR:
		return i.opXor(env)
	case NOT:
		return i.opNot(env)
	case SHL:
		return i.opShl(env)
	case SHR:
		return i.opShr(env)
	case SAR:
		return i.opSar(env)
	case BYTE:
		return i.opByte(env)

	// Memory Operations
	case MLOAD:
		return i.opMLoad(env)
	case MSTORE:
		return i.opMStore(env)
	case MSTORE8:
		return i.opMStore8(env)
	case MSIZE:
		return env.stack.PushUint64(env.memory.Size())
	case MCOPY:
		return i.opMCopy(env)

	// Storage Operations
	case SLOAD:
		return i.opSLoad(env)
	case SSTORE:
		return i.opSStore(env)
	case TLOAD:
		return i.opTLoad(env)
	case TSTORE:
		return i.opTStore(env)

	// Context Operations
	case ADDRESS:
		return i.opAddress(env)
	case BALANCE:
		return i.opBalance(env)
	case ORIGIN:
		return i.opOrigin(env)
	case CALLER:
		return i.opCaller(env)
	case CALLVALUE:
		return i.opCallValue(env)
	case CALLDATALOAD:
		return i.opCallDataLoad(env)
	case CALLDATASIZE:
		return env.stack.PushUint64(uint64(len(env.ctx.Input)))
	case RETURNDATASIZE:
		// R40-C-C1 FIX: Return the size of return data from the last call.
		// EIP-211 (Byzantium): required for Solidity CREATE/call return handling.
		return env.stack.PushUint64(uint64(len(env.returnData)))
	case CALLDATACOPY:
		return i.opCallDataCopy(env)
	case RETURNDATACOPY:
		// R40-C-C1 FIX: Copy return data from last call to memory.
		// EIP-211 (Byzantium): required for Solidity CREATE/call return handling.
		return i.opReturnDataCopy(env)
	case CODESIZE:
		return i.opCodeSize(env)
	case CODECOPY:
		return i.opCodeCopy(env)
	case GASPRICE:
		return i.opGasPrice(env)
	case GASLIMIT:
		return i.opGasLimit(env)
	case GAS:
		remaining := env.gas.Remaining()
		return env.stack.PushUint64(remaining)
	case BLOCKHASH:
		return i.opBlockHash(env)
	case COINBASE:
		return i.opCoinbase(env)
	case TIMESTAMP:
		return env.stack.PushUint64(uint64(env.ctx.Timestamp)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	case NUMBER:
		return env.stack.PushUint64(env.ctx.BlockNumber)
	case CHAINID:
		return env.stack.PushUint64(env.ctx.ChainID)
	case SELFBALANCE:
		return i.opSelfBalance(env)
	case EXTCODESIZE:
		return i.opExtCodeSize(env)
	case EXTCODECOPY:
		return i.opExtCodeCopy(env)
	case EXTCODEHASH:
		return i.opExtCodeHash(env)
	case PREVRANDAO:
		return i.opPrevRandao(env)
	case BLOBHASH:
		return i.opBlobHash(env)
	case BASEFEE:
		return i.opBaseFee(env)
	case BLOBBASEFEE:
		return i.opBlobBaseFee(env)

	// Crypto Operations
	case SHA3, KECCAK256:
		return i.opSHA3(env)

	// Post-Quantum Crypto Operations
	case KYBER_KEYGEN:
		return i.opKyberKeyGen(env)
	case KYBER_ENCAPS:
		return i.opKyberEncaps(env)
	case KYBER_DECAPS:
		return i.opKyberDecaps(env)
	case KYBER_ZERO_KEY:
		return i.opKyberZeroKey(env)

	// Call Operations
	case CALL:
		return i.opCall(env)
	case STATICCALL:
		return i.opStaticCall(env)
	case DELEGATECALL:
		return i.opDelegateCall(env)
	case CALLCODE:
		return i.opCallCode(env)
	case CREATE:
		return i.opCreate(env)
	case CREATE2:
		return i.opCreate2(env)
	case AUTH:
		return i.opAuth(env)
	case AUTHCALL:
		return i.opAuthCall(env)
	case SELFDESTRUCT:
		return i.opSelfDestruct(env)

	// Log Operations
	case LOG0:
		return i.opLog0(env)
	case LOG1:
		return i.opLog1(env)
	case LOG2:
		return i.opLog2(env)
	case LOG3:
		return i.opLog3(env)
	case LOG4:
		return i.opLog4(env)

	default:
		return ErrInvalidOpcode
	}
}
