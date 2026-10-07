// Quantaureum Node source, version 1.0.0.
package qvm

// L14-030 SECURITY NOTE: The QVM JIT compiler is DISABLED by default
// (jitEnabled: false). The JIT compilation path (compileOp) is incomplete
// and has not undergone security review. Enabling JIT could introduce
// memory safety vulnerabilities (buffer overflows, arbitrary code
// execution) if the compiled code does not properly validate inputs.
// JIT should remain disabled until a full security audit of the
// compilation pipeline is completed.

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/qvm/jit"
	"github.com/quantaureum/qau/qvm/precompiled"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// audit-fix P2-1b-8: mapJITErr maps JIT errors to qvm package errors,
// ensuring callers can compare error types directly (e.g., result.Err == ErrWriteProtection).
// R2 FIX (2026-07-06): Unified comment language to English for consistency.
func mapJITErr(err error) error {
	if err == nil {
		return nil
	}
	switch err {
	case jit.ErrInvalidOpcode:
		return ErrInvalidOpcode
	case jit.ErrExecutionReverted:
		return ErrExecutionReverted
	case jit.ErrWriteProtection:
		return ErrWriteProtection
	case jit.ErrMemoryOverflow:
		// qvm package has no ErrMemoryOverflow; preserve the original error.
		return err
	default:
		return err
	}
}

// Executor is the main entry point for QVM execution.
type Executor struct {
	interpreter     *Interpreter
	validator       *BytecodeValidator
	gasEstimator    *GasEstimator
	precompiled     *precompiled.Registry
	jitCompiler     *jit.JITCompiler
	jitEnabled      bool
	precompileQueue *jit.PrecompileQueue
}

// NewExecutor creates a new QVM executor.
func NewExecutor() *Executor {
	// QVFIX: JIT compiler is NOT instantiated in production. The JIT
	// compilation path (compileOp) has not undergone a complete security audit
	// and AUTHCALL opcode is still a stub. By setting jitCompiler to nil,
	// the Execute() dispatch check (jitCompiler != nil) ensures JIT can never
	// be triggered even if jitEnabled is somehow set to true.
	// To enable JIT for testing, use NewExecutorWithJIT().
	return &Executor{
		interpreter:     NewInterpreter(),
		validator:       NewBytecodeValidator(),
		gasEstimator:    NewGasEstimator(),
		precompiled:     precompiled.NewRegistry(),
		jitCompiler:     nil, // QVM-001: JIT disabled at construction time
		jitEnabled:      false,
		precompileQueue: nil,
	}
}

// NewExecutorWithJIT creates an executor with JIT compiler instantiated.
// QVFIX: This is only for testing. Production code must use NewExecutor().
func NewExecutorWithJIT() *Executor {
	compiler := jit.NewJITCompiler(256)
	return &Executor{
		interpreter:     NewInterpreter(),
		validator:       NewBytecodeValidator(),
		gasEstimator:    NewGasEstimator(),
		precompiled:     precompiled.NewRegistry(),
		jitCompiler:     compiler,
		jitEnabled:      false,
		precompileQueue: jit.NewPrecompileQueue(compiler, 128),
	}
}

// EnableJIT enables the JIT compiler for contract execution.
// The JIT compiler compiles contract bytecode to MicroOp sequences
// for faster repeated execution, with automatic fallback to the
// interpreter on any compilation or execution error.
//
// QVFIX: JIT is incomplete and has NOT undergone security audit.
// EnableJIT now requires QAU_ENABLE_JIT=1 environment variable to prevent
// accidental enabling. In production (QAU_PRODUCTION=1), JIT is hard-blocked
// regardless of the env var. This method returns an error if JIT cannot be
// safely enabled.
func (e *Executor) EnableJIT() error {
	if os.Getenv("QAU_PRODUCTION") == "1" {
		return fmt.Errorf("JIT compiler cannot be enabled in production mode (QAU_PRODUCTION=1): " +
			"JIT has not undergone security audit")
	}
	if os.Getenv("QAU_ENABLE_JIT") != "1" {
		return fmt.Errorf("JIT compiler requires QAU_ENABLE_JIT=1 environment variable: " +
			"JIT has not undergone security audit and is disabled by default")
	}
	// QVFIX: If jitCompiler is nil (NewExecutor, not NewExecutorWithJIT),
	// JIT cannot be enabled because there's no compiler instance.
	if e.jitCompiler == nil {
		return fmt.Errorf("JIT compiler not instantiated: use NewExecutorWithJIT() for testing")
	}
	e.jitEnabled = true
	return nil
}

// DisableJIT disables the JIT compiler, falling back to the interpreter.
func (e *Executor) DisableJIT() {
	e.jitEnabled = false
}

// EnableECDSAAuth enables the AUTH/AUTHCALL EIP-7702 secp256k1
// authorization path on the interpreter.
//
// R37-INFO FIX (2026-07-31): AUTH verifies a secp256k1 ECDSA signature —
// a quantum-vulnerable scheme on a quantum-safe (Dilithium3) chain. The
// path is disabled by default. Enabling requires QAU_ENABLE_ECDSA_AUTH=1
// and is hard-blocked when QAU_PRODUCTION=1, mirroring the EnableJIT
// gate. Production quantum-safe deployments must NOT enable this; a
// Dilithium-based authorization opcode is the intended replacement.
func (e *Executor) EnableECDSAAuth() error {
	if os.Getenv("QAU_PRODUCTION") == "1" {
		return fmt.Errorf("ECDSA AUTH cannot be enabled in production mode (QAU_PRODUCTION=1): " +
			"quantum-vulnerable secp256k1 authorization path")
	}
	if os.Getenv("QAU_ENABLE_ECDSA_AUTH") != "1" {
		return fmt.Errorf("ECDSA AUTH requires QAU_ENABLE_ECDSA_AUTH=1 environment variable: " +
			"quantum-vulnerable secp256k1 path, disabled by default")
	}
	e.interpreter.EnableECDSAAuth()
	return nil
}

// IsECDSAAuthEnabled returns whether the secp256k1 AUTH path is enabled.
func (e *Executor) IsECDSAAuthEnabled() bool {
	return e.interpreter.ecdsaAuthEnabled
}

// SetDevnetValidation pass-through to the underlying Interpreter.
// R43-QVM-BYTECODE-01 (2026-08-03): node wiring should call this with true
// on devnet chain IDs (1333, 1334) to keep the legacy "unknown opcode is
// tolerated at deployment, fails at runtime" behavior; production chains
// keep the default false (production-hardened: unknown opcodes rejected at
// deployment). See Interpreter.SetDevnetValidation for full semantics.
// Idempotent. Safe to call before or after e.Start().
func (e *Executor) SetDevnetValidation(devnet bool) {
	if e.interpreter != nil {
		e.interpreter.SetDevnetValidation(devnet)
	}
}

// enableJITForTesting bypasses the env-var guard for unit tests.
// QVFIX: This method is intentionally unexported — only tests in
// the qvm package can call it. Production code must use EnableJIT().
func (e *Executor) enableJITForTesting() {
	e.jitEnabled = true
}

// IsJITEnabled returns whether the JIT compiler is enabled.
func (e *Executor) IsJITEnabled() bool {
	return e.jitEnabled
}

func (e *Executor) JITCompiler() *jit.JITCompiler {
	return e.jitCompiler
}

func (e *Executor) JITStats() (hits, misses, compiles uint64, hitRate float64) {
	if e.jitCompiler == nil {
		return 0, 0, 0, 0
	}
	hits, misses, compiles = e.jitCompiler.Cache().Stats()
	hitRate = e.jitCompiler.Cache().HitRate()
	return
}

func (e *Executor) PrecompileQueue() *jit.PrecompileQueue {
	return e.precompileQueue
}

func (e *Executor) StartPrecompileWorker(interval time.Duration) {
	if e.precompileQueue != nil {
		e.precompileQueue.Start(interval)
	}
}

func (e *Executor) StopPrecompileWorker() {
	if e.precompileQueue != nil {
		e.precompileQueue.Stop()
	}
}

func (e *Executor) PrecompileContracts(codes [][]byte) int {
	if e.precompileQueue == nil {
		return 0
	}
	return e.precompileQueue.PrecompileBatch(codes)
}

// Execute executes contract code with the given context.
func (e *Executor) Execute(ctx *ExecutionContext, stateDB StateDB) *ExecutionResult {
	// R48-QV-01 FIX: Validate ctx is non-nil before accessing fields.
	if ctx == nil {
		return &ExecutionResult{
			Err: fmt.Errorf("nil execution context"),
		}
	}
	// Skip QuickValidate for initCode execution (constructor args are not valid QVM instructions).
	// For normal contract calls, QuickValidate catches obviously invalid code early.
	// P3-V7 AUDIT NOTE (SkipValidation is trusted-internal only): SkipValidation
	// bypasses QuickValidate and is set ONLY when executing initCode from the
	// trusted contract-deployment path (see Create/Create2 at lines ~675/~838),
	// where the "code" is constructor bytecode concatenated with ABI-encoded
	// constructor args — the args are not valid opcodes and would fail
	// QuickValidate. It is NEVER set for user-supplied runtime code: runtime
	// calls always go through Execute with SkipValidation=false. Setting this
	// for untrusted code would disable a safety check, so it must remain
	// internal/trusted-only.
	if !ctx.SkipValidation {
		if err := e.validator.QuickValidate(ctx.Code); err != nil {
			return &ExecutionResult{
				Err:     err,
				GasUsed: ctx.Gas,
			}
		}
	}

	// L10-019: Enforce maximum call depth (MaxCallDepth=1024) to prevent
	// stack overflow in recursive contract calls. The CALL opcode handler
	// in call.go also checks env.callDepth before entering Execute.
	if ctx.Depth >= MaxCallDepth {
		return &ExecutionResult{
			Err:     ErrDepthExceeded,
			GasUsed: ctx.Gas,
		}
	}

	if e.jitEnabled && e.jitCompiler != nil && len(ctx.Code) > 0 {
		// P3-QVM-SELFDESTRUCT FIX (R30, 2026-07-27): QVM-R15-CRIT-001
		// defense-in-depth — hard production guard at the Execute() dispatch
		// point. R31-HIGH-1 FIX (2026-09-06): the guard now uses
		// params.JITAllowedEnv() so the dispatch point enforces the SAME
		// double gate as EnableJIT (explicit QAU_ENABLE_JIT=1 opt-in AND
		// non-production). Even if jitEnabled is true (e.g., via
		// enableJITForTesting bypassing EnableJIT's check), a JIT that has
		// not been explicitly opted into — or that runs in production mode
		// (QAU_PRODUCTION=1) — never reaches execution.
		// The JIT SELFDESTRUCT implementation is intentionally reduced to
		// ErrInvalidOpcode (see qvm/jit/compiler.go:makeSelfDestructOp), but
		// defense-in-depth requires blocking the ENTIRE JIT path in production
		// — not just SELFDESTRUCT — because the JIT compiler has other
		// incomplete opcodes and has not been audited for production use.
		// The interpreter path is the only production-safe execution engine.
		if !params.JITAllowedEnv() {
			return &ExecutionResult{
				Err:     fmt.Errorf("QVM-R15-CRIT-001: JIT execution blocked (production mode or missing QAU_ENABLE_JIT=1 opt-in) — use interpreter path"),
				GasUsed: 0,
			}
		}
		return e.executeWithJIT(ctx, stateDB)
	}

	return e.interpreter.Execute(ctx, stateDB)
}

func (e *Executor) executeWithJIT(ctx *ExecutionContext, stateDB StateDB) (result *ExecutionResult) {
	// QVM-R13-CRIT-001 (2026-07-21) FIX: Outermost panic recovery around the
	// entire JIT execution path (Compile + Execute + result construction).
	// Previously only the interpreter path (Interpreter.run) had a defer
	// recover() — the JIT path did not. A malicious contract that triggered
	// a panic inside jitCompiler.Compile/Execute() (e.g., via JIT-compiled
	// array out-of-bounds, nil dereference, or integer overflow) would
	// propagate up the stack and crash the entire node. A single malicious
	// transaction could DoS the whole network.
	//
	// This mirrors the QVM-R10-C1 fix in environment.go: any panic from the
	// JIT path is caught here, logged with gas forensic context, state is
	// rolled back to the pre-execution snapshot (if one was taken), and all
	// remaining gas is consumed (matching EVM convention for fatal execution
	// errors, and discouraging panic-triggering contracts for gas griefing).
	//
	// `snapshot` is captured by closure and set below; if the panic occurs
	// before snapshot is taken (i.e., during Compile), stateDB.RevertToSnapshot
	// is skipped (no snapshot to revert to — state was not modified yet).
	//
	// Note: `result` is a named return value so this deferred function can
	// replace it. The named return also ensures that if a panic occurs AFTER
	// result has been assigned (e.g., during the final return statement
	// construction), we still overwrite it with the error result.
	var snapshot int = -1 // sentinel: -1 means no snapshot taken yet
	// R14-LOW (2026-07-21): env is declared here (before the defer) so the
	// panic recovery path can access env.logs. It stays nil if the panic
	// occurs during jitCompiler.Compile (before env is constructed below).
	var env *Environment
	// R14-MED (2026-07-21): Snapshot transientStorage / txCreatedContracts /
	// reentryCounts BEFORE execution so we can roll them back on panic.
	//
	// When ctx.ParentEnv != nil (sub-call), these maps are SHARED references
	// to the parent's maps (see the ParentEnv != nil branch below). A TSTORE
	// in the sub-call writes directly into parent.transientStorage. If the
	// JIT then panics, stateDB.RevertToSnapshot rolls back the stateDB but
	// leaves the transientStorage writes intact — corrupting the parent's
	// view. Subsequent sibling sub-calls see the panicked sub-call's dirty
	// TSTORE writes, breaking EIP-1153 semantics and any reentrancy locks
	// implemented via TSTORE/TLOAD.
	//
	// The snapshot is a deep copy of the three maps. On panic, we restore
	// the parent's maps to their pre-execution state. On success, the
	// snapshot is discarded (the writes are legitimate and should persist).
	// The deep-copy cost is O(n) where n is the current transientStorage
	// size, paid only when ParentEnv != nil (sub-call path). Top-level
	// calls (ParentEnv == nil) allocate fresh maps that are discarded with
	// the env, so no snapshot is needed.
	var tsSnapshot map[Address]map[Hash]Hash
	var tccSnapshot map[Address]bool
	var rcSnapshot map[Address]int
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: QVM executeWithJIT panic recovered (gas_limit=%d): %v",
				ctx.Gas, r)

			// Zeroize return data defensively in case the panic occurred
			// mid-copy of sensitive material (e.g., PQClean key material)
			// into the return data buffer.
			if result != nil && result.ReturnData != nil {
				for i := range result.ReturnData {
					result.ReturnData[i] = 0
				}
			}

			// Roll back ALL state changes if a snapshot was taken. The panic
			// may have left the stateDB in an inconsistent/partially-modified
			// state.
			if snapshot >= 0 {
				stateDB.RevertToSnapshot(snapshot)
			}

			// R14-MED: Roll back transientStorage / txCreatedContracts /
			// reentryCounts to their pre-execution state. This is critical
			// when ctx.ParentEnv != nil because the sub-call's TSTORE writes
			// went directly into the parent's shared maps. Without this
			// rollback, sibling sub-calls would see the panicked sub-call's
			// dirty transientStorage writes (EIP-1153 violation) and the
			// parent's reentrancy locks could be in an inconsistent state.
			if ctx.ParentEnv != nil && tsSnapshot != nil {
				ctx.ParentEnv.transientStorage = tsSnapshot
				ctx.ParentEnv.txCreatedContracts = tccSnapshot
				ctx.ParentEnv.reentryCounts = rcSnapshot
			}

			result = &ExecutionResult{
				ReturnData: nil,
				GasUsed:    ctx.Gas, // Consume all gas on panic (EVM convention)
				GasRefund:  0,
				// R14-LOW (2026-07-21): Preserve logs collected before the
				// panic, matching the interpreter path (environment.go:409
				// uses `Logs: env.logs`). Previously this was `nil`, which
				// meant a panic-triggering transaction produced different
				// receipt roots depending on whether JIT was active — a
				// consensus fork risk of the same class as QVM-R14-CRIT-001
				// (which fixed the GasUsed divergence). env is nil if the
				// panic occurred during jitCompiler.Compile (before env was
				// constructed); in that case there are no logs to preserve.
				Logs: func() []*Log {
					if env != nil {
						return env.logs
					}
					return nil
				}(),
				Err:      fmt.Errorf("%w: JIT execution panic: %v", ErrPanicRecovery, r),
				Reverted: true,
			}
			// R31-P2 FIX (P2-7, 2026-07-28): Sync env state with the result.
			// Same fix as environment.go run() — callers that inspect env
			// directly must see the panic reflected in env.reverted/env.err.
			if env != nil {
				env.reverted = true
				env.err = fmt.Errorf("%w: JIT execution panic: %v", ErrPanicRecovery, r)
			}
		}
	}()

	plan, err := e.jitCompiler.Compile(ctx.Code)
	if err != nil {
		return e.interpreter.Execute(ctx, stateDB)
	}

	snapshot = stateDB.Snapshot()

	env = &Environment{
		ctx:         ctx,
		stateDB:     stateDB,
		stack:       NewStack(),
		memory:      NewMemory(),
		gas:         NewGasMeter(ctx.Gas),
		gasTable:    e.interpreter.gasTable,
		precompiled: e.precompiled,
		pc:          0,
		logs:        make([]*Log, 0),
		returnData:  nil,
		blockHashes: ctx.BlockHashes,
		parentEnv:   ctx.ParentEnv,
	}

	// QVM-FIX: Initialize transientStorage / txCreatedContracts /
	// reentryCounts consistently with Interpreter.Execute (qvm.go:218-236).
	// Without this, the JIT execution path has nil maps causing:
	//   - TLOAD/TSTORE (EIP-1153) always returning zero (reentrancy locks broken)
	//   - SELFDESTRUCT EIP-6780 check no-op (nil map = all selfdestructs swallowed)
	//   - IncrementReentryCount panic on nil map write
	if ctx.ParentEnv != nil {
		env.transientStorage = ctx.ParentEnv.transientStorage
		env.txCreatedContracts = ctx.ParentEnv.txCreatedContracts
		env.reentryCounts = ctx.ParentEnv.reentryCounts
		// R14-MED: Deep-copy the parent's maps NOW (before execution) so
		// we can restore them on panic. This snapshot is only taken for
		// sub-call paths (ParentEnv != nil) where the maps are shared.
		// Top-level calls allocate fresh maps that don't need snapshotting.
		tsSnapshot = make(map[Address]map[Hash]Hash, len(ctx.ParentEnv.transientStorage))
		for addr, slots := range ctx.ParentEnv.transientStorage {
			tsSnapshot[addr] = make(map[Hash]Hash, len(slots))
			for k, v := range slots {
				tsSnapshot[addr][k] = v
			}
		}
		tccSnapshot = make(map[Address]bool, len(ctx.ParentEnv.txCreatedContracts))
		for k, v := range ctx.ParentEnv.txCreatedContracts {
			tccSnapshot[k] = v
		}
		rcSnapshot = make(map[Address]int, len(ctx.ParentEnv.reentryCounts))
		for k, v := range ctx.ParentEnv.reentryCounts {
			rcSnapshot[k] = v
		}
	} else {
		env.transientStorage = make(map[Address]map[Hash]Hash)
		env.txCreatedContracts = make(map[Address]bool)
		env.reentryCounts = make(map[Address]int)
	}

	if ctx.ParentEnv != nil {
		env.activeAddresses = make([]Address, len(ctx.ParentEnv.activeAddresses))
		copy(env.activeAddresses, ctx.ParentEnv.activeAddresses)
	} else {
		env.activeAddresses = make([]Address, 0, 2)
		if ctx.Caller != ctx.Address {
			env.PushActiveAddress(ctx.Caller)
		}
	}
	env.PushActiveAddress(ctx.Address)

	env.jumpDests = make(map[uint64]bool)
	for pc := range plan.JumpDests {
		env.jumpDests[pc] = true
	}

	jitEnv := newJITEnvAdapter(env, e.interpreter)

	// FIX: Check abort channel before JIT execution. The interpreter's
	// run() loop (environment.go) checks env.ctx.AbortCh every 1024 opcodes,
	// but the JIT execution path (jitCompiler.Execute) does not. Without this
	// check, a long-running JIT execution cannot be canceled (e.g., by
	// EstimateGas timeout), causing unbounded resource consumption.
	if ctx.AbortCh != nil {
		select {
		case <-ctx.AbortCh:
			return &ExecutionResult{
				ReturnData: nil,
				GasUsed:    ctx.Gas,
				Err:        errors.New("execution aborted"),
			}
		default:
		}
	}

	jitErr := e.jitCompiler.Execute(plan, jitEnv)

	// audit-fix P2-1b-8: Only fall back to interpreter on ErrInvalidOpcode
	// (JIT-unsupported opcode). Other errors (OOG, stack overflow/underflow,
	// memory overflow, write protection) are terminal and should not fall back.
	if jitErr != nil {
		// ErrInvalidOpcode means JIT doesn't support this opcode; fall back
		// to interpreter for re-execution. Gas consumed by JIT is not counted
		// (state has been rolled back, interpreter executes from scratch).
		if jitErr == jit.ErrInvalidOpcode {
			stateDB.RevertToSnapshot(snapshot)
			return e.interpreter.Execute(ctx, stateDB)
		}

		// Other errors are terminal; return JIT execution result directly
		// (including consumed gas). For OOG, EVM semantics require consuming
		// all remaining gas.
		gasUsed := env.gas.FinalUsed()
		mappedErr := mapJITErr(jitErr)
		if mappedErr != ErrExecutionReverted {
			// Non-REVERT errors consume all gas.
			gasUsed = ctx.Gas
		}
		return &ExecutionResult{
			ReturnData: env.returnData,
			GasUsed:    gasUsed,
			GasRefund:  env.gas.RefundAmount(),
			Logs:       env.logs,
			Err:        mappedErr,
			Reverted:   env.reverted,
		}
	}

	result = &ExecutionResult{
		ReturnData: env.returnData,
		GasUsed:    env.gas.FinalUsed(),
		GasRefund:  env.gas.RefundAmount(),
		Logs:       env.logs,
		Err:        mapJITErr(env.err),
		Reverted:   env.reverted,
	}

	// Defensive: if reverted is true but err is nil (e.g., JIT REVERT didn't set err),
	// ensure result.Err is set to ErrExecutionReverted so callers detect the revert.
	if result.Reverted && result.Err == nil {
		result.Err = ErrExecutionReverted
	}

	return result
}

// ExecuteWithRollback executes contract code and rolls back state on gas exhaustion.
// This ensures that if gas runs out, the state is reverted to before execution.
// FIX: Verified gas handling is CONSISTENT with CallWithRollback.
// Both functions follow the same EVM gas semantics:
//   - Non-revert failure (OOG, invalid opcode, etc.): GasUsed = total gas (all consumed)
//   - REVERT: preserve actual gas used from execution
//   - Success: return actual gas used from Execute()
func (e *Executor) ExecuteWithRollback(ctx *ExecutionContext, stateDB StateDB) *ExecutionResult {
	// Take a snapshot before execution
	snapshot := stateDB.Snapshot()

	// Execute the contract
	result := e.Execute(ctx, stateDB)

	// audit-fix R2-M3: revert on ANY execution error, not just OOG.
	// Per EVM semantics, all state changes must be rolled back on failure.
	// CRITICAL FIX: REVERT should only consume actual used gas, not all gas
	if result.Err != nil {
		stateDB.RevertToSnapshot(snapshot)
		if !result.Reverted {
			// Non-revert failures consume all remaining gas
			result.GasUsed = ctx.Gas
		}
		// For REVERT, preserve the actual gas used from execution
	}

	return result
}

// EstimateGas estimates the gas required for a contract call.
func (e *Executor) EstimateGas(ctx *ExecutionContext, stateDB StateDB) (uint64, error) {
	return e.gasEstimator.EstimateGas(e, ctx, stateDB, 0, ctx.GasLimit)
}

// EstimateGasWithRange estimates gas with a specified search range.
func (e *Executor) EstimateGasWithRange(ctx *ExecutionContext, stateDB StateDB, lo, hi uint64) (uint64, error) {
	return e.gasEstimator.EstimateGas(e, ctx, stateDB, lo, hi)
}

// Call executes a contract call.

// isEVMTranslatedCode detects if deployed code was translated from EVM bytecode.
// EVM contracts compiled by Solidity start with PUSH1 0x80 PUSH1 0x40 MSTORE,
// which translates to QVM: 0x10 0x80 0x10 0x40 0x51.
//
// L19-011 FIX: Extended the prefix check from 5 bytes to 8 bytes when available,
// matching the full Solidity preamble: PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE
// DUP1 ISZERO (QVM: 0x10 0x80 0x10 0x40 0x51 0x74 0x17 0x35).
// QVM3-001 FIX: The 5-byte fallback has been removed (see QVM-002 FIX below).
// Only the 8-byte prefix is checked; contracts shorter than 8 bytes are never
// identified as EVM-translated.
//
// P3-QV-03 FIX (2026-08-03): **PRIMARY detection now uses the explicit
// EVMTranslatedMarker prepended by TranslateEVMBytecode (see
// evm_translate.go const EVMTranslatedMarker), giving ZERO false-positive
// risk for contracts translated after this change. The 8-byte preamble
// pattern check below is the LEGACY fallback path used only for contracts
// deployed before this marker was introduced (in-process test contracts
// committed without re-deploy, persisted bbolt-deployed code, and any
// in-flight deployments from bridge or governance wrappers that cached
// pre-marker translations). Audit recommendation was migrated to the
// explicit marker, eliminating the 2^-64 false-positive concern raised
// in the audit (a future QASM compiler could unintentionally emit the
// same Solidity preamble pattern, causing stack-pop order to be
// reversed on legitimate QVM-native contracts).
//
// Future hardening: once all deployment paths can be guaranteed to
// re-route through TranslateEVMBytecode with the marker (e.g. once the
// rollup Create / Create2 paths force-rewrite pre-marker deployments
// during a protocol upgrade), the legacy 8-byte pattern check can be
// removed. For now, defense-in-depth keeps both checks: marker first
// (zero FP), pattern second (legacy compat).
func isEVMTranslatedCode(code []byte) bool {
	// P3-QV-03 PRIMARY: check the explicit translation marker first.
	// The marker is byte-equal `EVMTranslatedMarker` (8 bytes) prepended
	// exactly once by TranslateEVMBytecode. No QVM-native contract would
	// legitimately begin with these specific 8 bytes (all are invalid
	// QVM opcode prefixes — see the marker doc string for the rationale).
	if len(code) >= len(EVMTranslatedMarker) &&
		string(code[:len(EVMTranslatedMarker)]) == EVMTranslatedMarker {
		return true
	}
	// P3-QV-03 LEGACY FALLBACK: 8-byte Solidity preamble sniff. Kept to
	// preserve backward compatibility with contracts deployed before
	// this change — the next protocol upgrade at which point Create /
	// Create2 force-retranslation should remove this block. The risk
	// profile of this fallback is the audit's original 2^-64 FP per
	// the FIN-RA-008 mitigation writeup.
	//
	// QVFIX: Removed 5-byte fallback check to eliminate the ~2^-40
	// false-positive risk. Only the 8-byte prefix is checked, which
	// matches the full Solidity preamble and has a false-positive
	// probability of ~2^-64. Contracts shorter than 8 bytes are never
	// EVM-translated.
	if len(code) >= 8 &&
		code[0] == 0x10 && // PUSH1
		code[1] == 0x80 && // 0x80
		code[2] == 0x10 && // PUSH1
		code[3] == 0x40 && // 0x40
		code[4] == 0x51 && // MSTORE (QVM)
		code[5] == 0x74 && // CALLVALUE (QVM)
		code[6] == 0x17 && // DUP1 (QVM)
		code[7] == 0x35 { // ISZERO (QVM)
		return true
	}
	return false
}

// IsEVMTranslatedCodeExported is the exported form of isEVMTranslatedCode,
// for use by external packages (e.g. bridge / rpc / rollup) that need to
// inspect deployed code without coupling to the QVM-internal helper.
// Read-only accessor; does NOT grant the ability to set the marker.
// P3-QV-03 (2026-08-03) introduced the marker; this accessor checks both
// the marker and the legacy 8-byte preamble pattern.
func IsEVMTranslatedCodeExported(code []byte) bool {
	return isEVMTranslatedCode(code)
}

// StripEVMTranslatedMarkerFromRuntimeCode removes the EVMTranslatedMarker
// prefix from runtime-deployed bytecode IF present (i.e. if the bytecode
// was the output of TranslateEVMBytecode). Callers that bitwise-copy the
// translated code into StateDB (SetCode) MUST strip the marker first —
// the marker is NOT a QVM opcode and the interpreter would hit invalid
// PC positions if it executed the marker bytes. Returns the code
// unchanged if no marker is present (typical handler fast-path for
// native QVM bytecode). P3-QV-03 (2026-08-03).
//
// This function is INTENTIONALLY not called by TranslateEVMBytecode
// itself — the caller (e.g. Create / Create2) decides whether to
// keep the marker (EVMCompatible detection pre-runtime) or strip it
// (runtime exec) based on whether they're storing metadata or
// runtime-bytecode.
func StripEVMTranslatedMarkerFromRuntimeCode(code []byte) []byte {
	if len(code) >= len(EVMTranslatedMarker) &&
		string(code[:len(EVMTranslatedMarker)]) == EVMTranslatedMarker {
		return code[len(EVMTranslatedMarker):]
	}
	return code
}

func (e *Executor) Call(
	stateDB StateDB,
	caller, callee Address,
	input []byte,
	gas uint64,
	value *big.Int,
	blockCtx *BlockContext,
	depth int,
) *ExecutionResult {
	return e.CallWithRollback(stateDB, caller, callee, input, gas, value, blockCtx, true, depth)
}

// CallWithRollback executes a contract call with optional state rollback on failure.
func (e *Executor) CallWithRollback(
	stateDB StateDB,
	caller, callee Address,
	input []byte,
	gas uint64,
	value *big.Int,
	blockCtx *BlockContext,
	rollbackOnGasExhaustion bool,
	depth int,
) *ExecutionResult {
	// P3-V9 FIX: Reject calls to the reserved zero address (0x0). This mirrors
	// the L10-020 guard in opCall/opCallCode (which push 0 at the opcode layer)
	// at the public Executor API, so direct callers of Call/CallWithRollback
	// (node bridge, AA entrypoint, parallel executor) cannot bypass it. The
	// zero address is reserved and must never hold code or receive value.
	if callee == (Address{}) {
		return &ExecutionResult{
			Err:     ErrZeroAddress,
			GasUsed: 0,
		}
	}

	// R32-P1-10 FIX (2026-07-28): EIP-150 63/64 gas rule defense-in-depth.
	// The opcode handlers (opCall/opCallCode/opDelegateCall/opStaticCall)
	// already apply the 63/64 rule via CalculateCallGas before calling
	// i.Execute() directly. However, Executor.CallWithRollback is a public
	// API also used by the AA EntryPoint and ParallelExecutor as a TOP-LEVEL
	// entry point (depth=0, gas=tx.gasLimit - intrinsicGas). At depth=0 the
	// 63/64 rule does NOT apply (the transaction is the root caller).
	//
	// The defense-in-depth check below handles the case where a future caller
	// invokes CallWithRollback from a NESTED context (depth > 0). Without
	// this check, a nested caller could pass its entire remaining gas to the
	// sub-call, leaving zero gas for error handling/revert in the parent
	// frame — a violation of EIP-150's intent. When depth > 0, we cap the
	// gas to 63/64 of the requested amount, reserving 1/64 for the caller.
	//
	// This is a no-op for current callers (EntryPoint, ParallelExecutor) which
	// always pass depth=0.
	if depth > 0 && gas > 0 {
		// maxGas = gas - gas/64 (EIP-150: reserve 1/64 for parent)
		maxGas := gas - gas/64
		if maxGas < gas { // guard against underflow (gas=0 already handled above)
			gas = maxGas
		}
	}

	// Take snapshot for potential rollback
	snapshot := stateDB.Snapshot()

	// Get contract code
	code := stateDB.GetCode(callee)
	if len(code) == 0 {
		// Check if this is a precompiled contract
		calleeTypes := typesAddr(callee)
		if e.precompiled.IsPrecompiled(calleeTypes) {
			// QVM- (2026-07-20) FIX: Inject execution context
			// before Run. Without this, on-chain calls to the multisig
			// precompile (0x66) fail with "stateDB not set" — the
			// precompile's stateDB/blockTime/chainID were only being
			// injected by the RPC layer (on a separate instance).
			//
			// QVM-R13-HIGH-002 (2026-07-21) FIX: Use the atomic
			// Set+dispatch path (Registry.RunWithContext) instead of
			// the legacy injectPrecompileContext + Registry.Run
			// two-step sequence. The legacy sequence had a TOCTOU race
			// window in parallel execution mode where another goroutine
			// could interleave a different stateDB/blockTime/chainID
			// between the Sets and Run. The new path performs Set +
			// dispatch under a SINGLE lock acquisition.
			//
			// R38-P0-01 (2026-08-01) FIX: Route through the caller-aware
			// V2 path so a V2 precompile (multisig) can gate register/
			// proposal/execute on the authenticated caller/origin instead
			// of attacker-supplied calldata. The V2 registry falls back
			// to the legacy atomic RunWithContext (and then to the pure
			// Run) for every precompile that does not implement
			// ContextAwarePrecompiledContractV2, so sha256/ecrecover/
			// dilithiumVerify/kyberKEM execute exactly as before.
			callerT := typesAddr(caller)
			originT := callerT // At top-level Call, origin == caller
			var valueT *big.Int
			if value != nil {
				valueT = new(big.Int).Set(value)
			}
			output, gasUsed, err := executePrecompiledAtomicV2(e.precompiled, calleeTypes, stateDB,
				callerT, originT, valueT, blockCtx.Timestamp, blockCtx.ChainID, false, input, gas)
			if err != nil {
				stateDB.RevertToSnapshot(snapshot)
				return &ExecutionResult{
					Err: err,
					// R6-QV-001 FIX: Use gasUsed (actual gas consumed by the
					// precompile before failing) instead of gas (total allocated).
					// Returning the full gas allocation would overcharge the caller.
					GasUsed: gasUsed,
				}
			}
			return &ExecutionResult{
				ReturnData: output,
				GasUsed:    gasUsed,
			}
		}

		// No code, just transfer value
		if value != nil && value.Sign() > 0 {
			callerBalance := stateDB.GetBalance(caller)
			if callerBalance.Cmp(value) < 0 {
				return &ExecutionResult{
					Err:     ErrInsufficientBalance,
					GasUsed: gas,
				}
			}
			stateDB.SetBalance(caller, new(big.Int).Sub(callerBalance, value))
			calleeBalance := stateDB.GetBalance(callee)
			stateDB.SetBalance(callee, new(big.Int).Add(calleeBalance, value))
		}
		// FIX: Report GasUsed > 0 when state was modified (value transfer).
		// Previously returned GasUsed=0 even after modifying balances, which could
		// mislead callers into thinking no work was done. The actual call cost
		// (base + value transfer) is charged by the opcode handler via
		// CalculateCallGas. Here we report a nominal GasVeryLow to indicate
		// state modification occurred.
		gasUsed := uint64(0)
		if value != nil && value.Sign() > 0 {
			if gas >= GasVeryLow {
				gasUsed = GasVeryLow
			} else {
				gasUsed = gas
			}
		}
		return &ExecutionResult{
			GasUsed: gasUsed,
		}
	}

	// Create execution context
	ctx := &ExecutionContext{
		Origin:      caller,
		GasPrice:    blockCtx.GasPrice,
		Caller:      caller,
		Address:     callee,
		Value:       value,
		BlockNumber: blockCtx.BlockNumber,
		Timestamp:   blockCtx.Timestamp,
		Coinbase:    blockCtx.Coinbase,
		GasLimit:    blockCtx.GasLimit,
		ChainID:     blockCtx.ChainID,
		BlockHashes: blockCtx.BlockHashes,
		// QVM- (2026-07-20): properly initialize EIP-1559/4844/4399 fields.
		BaseFee:       baseFeeToUint64(blockCtx.BaseFee),
		BlobBaseFee:   baseFeeToUint64(blockCtx.BlobBaseFee),
		PrevRandao:    blockCtx.PrevRandao,
		Code:          code,
		Input:         input,
		Gas:           gas,
		Depth:         depth,
		ReadOnly:      false,
		EVMCompatible: isEVMTranslatedCode(code),
	}

	// Transfer value
	if value != nil && value.Sign() > 0 {
		callerBalance := stateDB.GetBalance(caller)
		if callerBalance.Cmp(value) < 0 {
			return &ExecutionResult{
				Err:     ErrInsufficientBalance,
				GasUsed: gas,
			}
		}
		stateDB.SetBalance(caller, new(big.Int).Sub(callerBalance, value))
		calleeBalance := stateDB.GetBalance(callee)
		stateDB.SetBalance(callee, new(big.Int).Add(calleeBalance, value))
	}

	result := e.Execute(ctx, stateDB)

	// audit-fix  (HIGH): revert on ANY execution error, not just OOG.
	// Per EVM semantics, all state changes (including value transfer above)
	// must be rolled back when execution fails for any reason — REVERT,
	// invalid opcode, stack underflow, etc. The previous check only reverted
	// on ErrOutOfGas, leaving value permanently transferred on other failures.
	if result.Err != nil {
		stateDB.RevertToSnapshot(snapshot)
		if !result.Reverted {
			result.GasUsed = gas // All gas is consumed on non-revert failures
		}
	}

	return result
}

// EstimateCallGas estimates the gas required for a contract call.
func (e *Executor) EstimateCallGas(
	stateDB StateDB,
	caller, callee Address,
	input []byte,
	value *big.Int,
	blockCtx *BlockContext,
	depth int,
) (uint64, error) {
	code := stateDB.GetCode(callee)
	if len(code) == 0 {
		calleeTypes := typesAddr(callee)
		if e.precompiled.IsPrecompiled(calleeTypes) {
			return e.precompiled.Get(calleeTypes).RequiredGas(input), nil
		}
		return GasTxCall, nil
	}

	ctx := &ExecutionContext{
		Origin:      caller,
		GasPrice:    blockCtx.GasPrice,
		Caller:      caller,
		Address:     callee,
		Value:       value,
		BlockNumber: blockCtx.BlockNumber,
		Timestamp:   blockCtx.Timestamp,
		Coinbase:    blockCtx.Coinbase,
		GasLimit:    blockCtx.GasLimit,
		ChainID:     blockCtx.ChainID,
		BlockHashes: blockCtx.BlockHashes,
		// QVM- (2026-07-20): properly initialize EIP-1559/4844/4399 fields.
		BaseFee:       baseFeeToUint64(blockCtx.BaseFee),
		BlobBaseFee:   baseFeeToUint64(blockCtx.BlobBaseFee),
		PrevRandao:    blockCtx.PrevRandao,
		Code:          code,
		Input:         input,
		Gas:           blockCtx.GasLimit,
		Depth:         0,
		ReadOnly:      false,
		EVMCompatible: isEVMTranslatedCode(code),
	}

	return e.EstimateGas(ctx, stateDB)
}

// StaticCall executes a read-only contract call.
func (e *Executor) StaticCall(
	stateDB StateDB,
	caller, callee Address,
	input []byte,
	gas uint64,
	blockCtx *BlockContext,
	depth int,
) *ExecutionResult {
	// FIX: Handle precompiled contracts. StaticCall previously returned
	// an empty result for precompiled addresses (which have no bytecode),
	// inconsistent with opStaticCall which executes precompiled logic.
	if e.precompiled != nil && e.precompiled.IsPrecompiled(typesAddr(callee)) {
		// QVM- (2026-07-20) FIX: STATICCALL must reject stateful
		// precompiles. The interpreter's opStaticCall path (via
		// executePrecompiled at call.go:58-69) already enforces this via the
		// StatefulPrecompiledContract optional interface — but Executor.StaticCall
		// (used by the eth_call RPC and other read-only API surfaces) called
		// e.precompiled.Run() directly, bypassing the guard. That allowed a
		// read-only eth_call to invoke multisig.registerWallet /
		// createProposal / approveProposal / executeProposal — methods that
		// mutate stateDB storage and balances — breaking STATICCALL's
		// read-only semantics. Mirrors the interpreter's guard here.
		calleeTypes := typesAddr(callee)
		if pc := e.precompiled.Get(calleeTypes); pc != nil {
			if sp, ok := pc.(precompiled.StatefulPrecompiledContract); ok && sp.IsStateful() {
				return &ExecutionResult{
					Err:     ErrWriteProtection,
					GasUsed: 0,
				}
			}
			// QVM- (2026-07-20): Inject context for non-stateful
			// context-aware precompiles (e.g. future read-only precompiles
			// that need blockTime/chainID for domain separation). Stateful
			// precompiles are already rejected above, so this only fires
			// for pure precompiles that happen to implement the context
			// interface — currently none, but future-proofed.
			//
			// QVM-R13-HIGH-002 (2026-07-21) FIX: Use the atomic
			// Set+dispatch path (Registry.RunWithContext) instead of
			// the legacy inject + Run sequence — same fix as Call above.
		}
		// executePrecompiledAtomic handles both atomic (single-lock) and
		// legacy (separate Set + Run) paths based on whether the precompile
		// implements AtomicContextPrecompiledContract. Pure precompiles
		// (sha256, etc.) don't implement either interface and just call Run.
		//
		// R38-P0-01 (2026-08-01) FIX: Route through the caller-aware V2 path
		// (same as CallWithRollback above) so a V2 precompile receives the
		// authenticated caller/origin. StaticCall passes isStatic=true so a
		// V2 precompile can refuse state writes; QVM-R10-H2 already rejects
		// stateful precompiles under STATICCALL earlier in the dispatch, so
		// this is belt-and-suspenders.
		callerT := typesAddr(caller)
		originT := callerT
		output, gasUsed, err := executePrecompiledAtomicV2(e.precompiled, typesAddr(callee), stateDB,
			callerT, originT, nil, blockCtx.Timestamp, blockCtx.ChainID, true, input, gas)
		if err != nil {
			return &ExecutionResult{
				Err:     err,
				GasUsed: gasUsed,
			}
		}
		return &ExecutionResult{
			ReturnData: output,
			GasUsed:    gasUsed,
		}
	}

	code := stateDB.GetCode(callee)
	if len(code) == 0 {
		return &ExecutionResult{
			GasUsed: 0,
		}
	}

	ctx := &ExecutionContext{
		Origin:      caller,
		GasPrice:    blockCtx.GasPrice,
		Caller:      caller,
		Address:     callee,
		Value:       big.NewInt(0),
		BlockNumber: blockCtx.BlockNumber,
		Timestamp:   blockCtx.Timestamp,
		Coinbase:    blockCtx.Coinbase,
		GasLimit:    blockCtx.GasLimit,
		ChainID:     blockCtx.ChainID,
		BlockHashes: blockCtx.BlockHashes,
		// QVM- (2026-07-20): properly initialize EIP-1559/4844/4399 fields.
		BaseFee:       baseFeeToUint64(blockCtx.BaseFee),
		BlobBaseFee:   baseFeeToUint64(blockCtx.BlobBaseFee),
		PrevRandao:    blockCtx.PrevRandao,
		Code:          code,
		Input:         input,
		Gas:           gas,
		Depth:         depth, // FIX: use passed depth instead of hardcoded 0
		ReadOnly:      true,
		EVMCompatible: isEVMTranslatedCode(code),
	}

	return e.Execute(ctx, stateDB)
}

// BlockContext contains block-level context for execution.
type BlockContext struct {
	BlockNumber uint64
	Timestamp   int64
	Coinbase    Address
	GasLimit    uint64
	GasPrice    *big.Int
	BaseFee     *big.Int // EIP-1559: base fee per gas for this block
	BlobBaseFee *big.Int // EIP-7516: blob base fee per gas (for BLOBBASEFEE opcode)
	PrevRandao  Hash     // EIP-4399: previous RANDAO mix (for PREVRANDAO opcode, replaces DIFFICULTY)
	ChainID     uint64
	BlockHashes map[uint64]Hash // Recent block hashes (last 256 blocks) for BLOCKHASH opcode
}

// baseFeeToUint64 safely converts a *big.Int base fee to uint64 for
// ExecutionContext.BaseFee. Returns 0 if the input is nil (caller failed
// to set it) — the EVM spec treats an unset BaseFee as 0.
//
// QVM- (2026-07-20) FIX: Previously all ExecutionContext creations
// left BaseFee/BlobBaseFee as the zero value (0) because BlockContext.BaseFee
// is *big.Int but ExecutionContext.BaseFee is uint64 — there was no
// conversion at the construction site. opBaseFee therefore always
// pushed 0, breaking EIP-1559 contracts that depend on BASEFEE.
func baseFeeToUint64(bf *big.Int) uint64 {
	if bf == nil {
		return 0
	}
	if !bf.IsUint64() {
		// Cap at MaxUint64 — a base fee that doesn't fit in uint64
		// is itself a bug, but we don't want to panic the EVM.
		return ^uint64(0)
	}
	return bf.Uint64()
}

// Create deploys a new contract.
// audit-fix R10-M3: takes a state snapshot and reverts on any failure,
// ensuring value transfers and nonce changes are rolled back per EVM spec.
func (e *Executor) Create(
	stateDB StateDB,
	caller Address,
	initCode []byte,
	gas uint64,
	value *big.Int,
	blockCtx *BlockContext,
	depth int,
) (*ExecutionResult, Address) {
	// NOTE: We do NOT validate initCode with QuickValidate here.
	// initCode includes constructor arguments appended after the bytecode,
	// which are raw binary data (not QVM instructions). Validating them as
	// opcodes causes false "truncated push data" errors when constructor args
	// contain bytes in the PUSH opcode range (0x10-0x2F).
	// The initCode is actually executed by the interpreter, so invalid opcodes
	// will cause runtime errors naturally. Only deployed (runtime) code is
	// validated via ValidateDeployedCode below.

	// R32-P1-09 FIX (2026-07-28): EIP-3860 — enforce maximum initcode size
	// on the public Executor.Create API. The interpreter's opCreateGeneric
	// already enforces this (operations_missing.go:1215-1217), but Executor.Create
	// is a public API called directly by EntryPoint.executeInitCode and other
	// paths that bypass the interpreter. Without this check, an attacker could
	// deploy a 10MB+ initcode contract via the AA EntryPoint, forcing the VM
	// to allocate/copy huge memory regions and hash gigabytes of data (DoS).
	if len(initCode) > MaxInitCodeSize {
		return &ExecutionResult{
			Err:     ErrInitCodeSizeExceeded,
			GasUsed: gas,
		}, Address{}
	}

	// R32-P1-09 FIX (2026-07-28): EIP-3860 CreateDataGas — charge 2 gas per
	// 32-byte word of initcode. This surcharge was missing from the public
	// Executor.Create API (only opCreateGeneric charged it), allowing direct
	// callers to deploy oversized initcode at underpriced gas. We charge it
	// here as defense-in-depth; the interpreter path also charges it via
	// opCreateGeneric so nested CREATEs from within contracts are also covered.
	initCodeWords := (uint64(len(initCode)) + 31) / 32
	createDataCost, err := SafeMulGas(initCodeWords, GasCreateData)
	if err != nil {
		return &ExecutionResult{
			Err:     fmt.Errorf("create gas overflow: EIP-3860 CreateDataGas"),
			GasUsed: gas,
		}, Address{}
	}
	if gas < createDataCost {
		return &ExecutionResult{
			Err:     ErrOutOfGas,
			GasUsed: gas,
		}, Address{}
	}
	gas -= createDataCost

	// R32-P1-10 FIX (2026-07-28): EIP-150 63/64 gas rule defense-in-depth.
	// opCreateGeneric already applies the 63/64 rule via
	// `env.gas.Remaining() - env.gas.Remaining()/64` (operations_missing.go:1438).
	// This public API is currently only called from top-level paths
	// (EntryPoint.executeInitCode, ParallelExecutor.executeContractCreate)
	// where depth=0 and EIP-150 does not apply. This check guards against
	// future nested callers (depth > 0) that would otherwise bypass EIP-150.
	if depth > 0 && gas > 0 {
		maxGas := gas - gas/64
		if maxGas < gas {
			gas = maxGas
		}
	}

	// Calculate contract address
	// The caller's nonce has already been incremented by the transaction executor
	// (TxExecutor.Execute increments nonce before calling Create), so we use
	// nonce-1 for the contract address calculation to match the standard
	// CreateAddress(sender, tx.Nonce) convention used in adapters.go.
	currentNonce := stateDB.GetNonce(caller)
	if currentNonce == 0 {
		return &ExecutionResult{
			Err:     ErrInvalidNonce,
			GasUsed: gas,
		}, Address{}
	}
	createNonce := currentNonce - 1
	contractAddr := CreateAddress(caller, createNonce)

	// Check for collision — account already exists if it has code, a nonce, or was created
	if stateDB.Exist(contractAddr) || stateDB.GetCodeSize(contractAddr) > 0 || stateDB.GetNonce(contractAddr) > 0 {
		return &ExecutionResult{
			Err:     ErrContractAddressCollision,
			GasUsed: gas,
		}, Address{}
	}

	// audit-fix R10-M3: snapshot before state mutations so we can revert on failure
	snapshot := stateDB.Snapshot()

	// R37-P3-21 FIX (2026-07-31): EIP-161 — a newly created contract account
	// starts with nonce 1 (matches go-ethereum create()). Previously the
	// contract account nonce stayed 0, so a nested CREATE computing the same
	// address during init execution would bypass the GetNonce>0 collision
	// check, and the account was considered "empty" and could be pruned.
	// Placed after the snapshot so any later failure reverts it.
	stateDB.SetNonce(contractAddr, 1)

	// NOTE: Nonce increment is handled by TxExecutor.Execute BEFORE calling Create.
	// Do NOT increment nonce here to avoid double-increment.

	// Transfer value
	if value != nil && value.Sign() > 0 {
		callerBalance := stateDB.GetBalance(caller)
		if callerBalance.Cmp(value) < 0 {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     ErrInsufficientBalance,
				GasUsed: gas,
			}, Address{}
		}
		stateDB.SetBalance(caller, new(big.Int).Sub(callerBalance, value))
		stateDB.SetBalance(contractAddr, value)
	}

	// EVM COMPATIBILITY: Auto-detect EVM bytecode and translate to QVM format.
	// EVM bytecode uses opcode 0x60-0x7F for PUSH1-PUSH32, while QVM uses 0x10-0x2F.
	// If the bytecode is in EVM format, translate it to QVM opcodes.
	// This allows Solidity-compiled contracts to run on QVM.
	originalInput := initCode
	// EVM COMPATIBILITY: Translate Code but keep Input original.
	// Constructor args (ABI-encoded data) must NOT be translated.
	// FIX: Clarify why both Input and OriginalCode use originalInput:
	// - Code: translated QVM bytecode (for execution by the interpreter)
	// - Input: original EVM bytecode (CALLDATA returns constructor args in ABI format)
	// - OriginalCode: original EVM bytecode (CODECOPY/CALLDATACOPY in EVM mode
	//   must return the original, not the translated bytecode)
	if len(initCode) > 0 && IsEVMBytecode(initCode) {
		translated, err := TranslateEVMBytecode(initCode)
		if err != nil {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     fmt.Errorf("evm translation failed: %w", err),
				GasUsed: gas,
			}, Address{}
		}
		initCode = translated
		log.Printf("[EVM-COMPAT] Translated %d bytes EVM -> %d bytes QVM", len(originalInput), len(initCode))
	}

	// Create execution context for init code
	// In EVM, during contract creation, the entire transaction data (init code +
	// constructor args) is available as calldata. We set Input = initCode so that
	// CALLDATALOAD can read constructor arguments appended after the bytecode.
	ctx := &ExecutionContext{
		Origin:      caller,
		GasPrice:    blockCtx.GasPrice,
		Caller:      caller,
		Address:     contractAddr,
		Value:       value,
		BlockNumber: blockCtx.BlockNumber,
		Timestamp:   blockCtx.Timestamp,
		Coinbase:    blockCtx.Coinbase,
		GasLimit:    blockCtx.GasLimit,
		ChainID:     blockCtx.ChainID,
		BlockHashes: blockCtx.BlockHashes,
		// QVM- (2026-07-20): properly initialize EIP-1559/4844/4399 fields.
		BaseFee:        baseFeeToUint64(blockCtx.BaseFee),
		BlobBaseFee:    baseFeeToUint64(blockCtx.BlobBaseFee),
		PrevRandao:     blockCtx.PrevRandao,
		Code:           initCode,
		Input:          originalInput,
		OriginalCode:   originalInput,
		EVMCompatible:  isEVMTranslatedCode(initCode), // R7-QV-001 FIX: Detect EVM-translated code dynamically
		Gas:            gas,
		Depth:          depth, // R35-P1-01 FIX: was hardcoded 0, bypassing reentrancy protection in nested calls
		ReadOnly:       false,
		SkipValidation: true, // initCode includes constructor args, skip QuickValidate
	}

	// Execute init code
	result := e.Execute(ctx, stateDB)

	if result.Err != nil {
		stateDB.RevertToSnapshot(snapshot)
		return result, Address{}
	}

	// Deploy the returned code
	deployedCode := result.ReturnData

	// EVM COMPATIBILITY: translate runtime code from EVM to QVM format.
	// R122-STEP6 fail-closed: if the runtime code looks like EVM but cannot
	// be translated, revert the deployment instead of storing raw EVM
	// bytecode that the QVM interpreter would misexecute (EVM/QVM differ in
	// arithmetic operand order — see docs/EVM-COMPATIBILITY.md).
	if len(deployedCode) > 0 && IsEVMBytecode(deployedCode) {
		translated, err := TranslateEVMBytecode(deployedCode)
		if err != nil {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     fmt.Errorf("evm runtime translation failed (deployment rejected, fail-closed): %w", err),
				GasUsed: result.GasUsed,
			}, Address{}
		}
		deployedCode = translated
	}
	if len(deployedCode) > MaxCodeSize {
		stateDB.RevertToSnapshot(snapshot)
		return &ExecutionResult{
			Err:     ErrMaxCodeSizeExceeded,
			GasUsed: result.GasUsed,
		}, Address{}
	}

	// Validate deployed code.
	// QVM-004 NOTE: ValidateDeployedCode does not re-check JUMPDEST integrity
	// itself — that is already enforced by the BytecodeValidator.Validate()
	// path (which marks every JUMPDEST and validates PUSH data) invoked inside
	// ValidateDeployedCode. ValidateDeployedCode is an ADDITIONAL check that
	// runs the full validation (including jumpdest analysis) plus the EIP-3541
	// prefix/contract-size policy on the FINAL deployed code. See
	// qvm/validator.go ValidateDeployedCode for details.
	if valResult := e.validator.ValidateDeployedCode(deployedCode); !valResult.Valid {
		stateDB.RevertToSnapshot(snapshot)
		// R32-P3-06 FIX (2026-07-28): Use ErrInvalidBytecode (wrapping the
		// specific validation error) instead of the misleading ErrInvalidOpcode.
		// The failure could be due to code size, push data, jump target,
		// stack imbalance, or EIP-3541 prefix — not necessarily an invalid opcode.
		deployErr := ErrInvalidBytecode
		if firstErr := valResult.FirstError(); firstErr != nil {
			deployErr = fmt.Errorf("%w: %v", ErrInvalidBytecode, firstErr)
		}
		return &ExecutionResult{
			Err:     deployErr,
			GasUsed: result.GasUsed,
		}, Address{}
	}

	// Charge for code storage
	// audit-fix H-6: overflow-safe gas accounting for code deposit
	codeLen := uint64(len(deployedCode))
	if GasCodeDeposit != 0 && codeLen > 0 {
		// audit-fix H-6 / QV-03 FIX: Use SafeMulGas for overflow-safe
		// multiplication instead of a manual divide-back check.
		codeStorageCost, merr := SafeMulGas(codeLen, GasCodeDeposit)
		if merr != nil {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     ErrOutOfGas,
				GasUsed: gas,
			}, Address{}
		}
		// Check addition overflow with SafeAddGas
		newGasUsed, aerr := SafeAddGas(result.GasUsed, codeStorageCost)
		if aerr != nil {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     ErrOutOfGas,
				GasUsed: gas,
			}, Address{}
		}
		result.GasUsed = newGasUsed
		// Verify total gas used does not exceed allocation
		if result.GasUsed > gas {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     ErrOutOfGas,
				GasUsed: gas,
			}, Address{}
		}
	}

	// Store the code
	stateDB.SetCode(contractAddr, deployedCode)

	return result, contractAddr
}

// Create2 deploys a new contract with a deterministic address.
// audit-fix R10-M3: takes a state snapshot and reverts on any failure.
func (e *Executor) Create2(
	stateDB StateDB,
	caller Address,
	initCode []byte,
	salt Hash,
	gas uint64,
	value *big.Int,
	blockCtx *BlockContext,
	depth int,
) (*ExecutionResult, Address) {
	// NOTE: We do NOT validate initCode with QuickValidate here.
	// See Create() for the rationale — initCode includes constructor arguments
	// that are raw binary data, not QVM instructions.

	// R32-P1-09 FIX (2026-07-28): EIP-3860 — enforce maximum initcode size on
	// the public Executor.Create2 API. Mirrors the check in Executor.Create.
	// CREATE2 also hashes the initcode (keccak256 for address derivation), so
	// an oversized initcode is both a memory DoS and a hashing DoS vector.
	if len(initCode) > MaxInitCodeSize {
		return &ExecutionResult{
			Err:     ErrInitCodeSizeExceeded,
			GasUsed: gas,
		}, Address{}
	}

	// R32-P1-09 FIX (2026-07-28): EIP-3860 CreateDataGas for CREATE2. CREATE2
	// also charges the hash cost (6 gas/word) in opCreateGeneric; we charge
	// the CreateDataGas (2 gas/word) here as defense-in-depth on the public
	// API. The hash cost is charged in opCreateGeneric when called via the
	// interpreter; direct callers via Executor.Create2 pay only CreateDataGas
	// here, which is the minimum EIP-3860 requirement.
	initCodeWords := (uint64(len(initCode)) + 31) / 32
	createDataCost, err := SafeMulGas(initCodeWords, GasCreateData)
	if err != nil {
		return &ExecutionResult{
			Err:     fmt.Errorf("create2 gas overflow: EIP-3860 CreateDataGas"),
			GasUsed: gas,
		}, Address{}
	}
	if gas < createDataCost {
		return &ExecutionResult{
			Err:     ErrOutOfGas,
			GasUsed: gas,
		}, Address{}
	}
	gas -= createDataCost

	// R32-P1-10 FIX (2026-07-28): EIP-150 63/64 gas rule defense-in-depth
	// for CREATE2. Mirrors the check in Executor.Create. See Create() for
	// full rationale.
	if depth > 0 && gas > 0 {
		maxGas := gas - gas/64
		if maxGas < gas {
			gas = maxGas
		}
	}

	// Calculate contract address using CREATE2 formula.
	// QVM-003 NOTE (intentional): The CREATE2 address is computed from the
	// ORIGINAL initCode (as supplied by the caller), NOT from any
	// EVM->QVM-translated code. This is correct EVM behavior: per EIP-1014
	// the CREATE2 address is keccak256(0xff || deployer || salt ||
	// keccak256(init_code)) where init_code is exactly the bytes the deployer
	// passed in. Translation to QVM format happens below (line ~859) and only
	// affects what gets EXECUTED, not the deterministic address. Using the
	// translated bytes here would change the address and break the CREATE2
	// address stability guarantee that contracts and off-chain tools rely on.
	contractAddr := Create2Address(caller, salt, initCode)

	// Check for collision — account already exists if it has code, a nonce, or was created
	if stateDB.Exist(contractAddr) || stateDB.GetCodeSize(contractAddr) > 0 || stateDB.GetNonce(contractAddr) > 0 {
		return &ExecutionResult{
			Err:     ErrContractAddressCollision,
			GasUsed: gas,
		}, Address{}
	}

	// audit-fix R10-M3: snapshot before state mutations so we can revert on failure
	snapshot := stateDB.Snapshot()

	// R37-P3-21 FIX (2026-07-31): EIP-161 — a newly created contract account
	// starts with nonce 1 (matches go-ethereum create2()). See Create() for
	// full rationale. Placed after the snapshot so any later failure reverts it.
	stateDB.SetNonce(contractAddr, 1)

	// NOTE: Nonce increment is handled by TxExecutor.Execute BEFORE calling Create2.
	// Do NOT increment nonce here to avoid double-increment.

	// Transfer value
	if value != nil && value.Sign() > 0 {
		callerBalance := stateDB.GetBalance(caller)
		if callerBalance.Cmp(value) < 0 {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     ErrInsufficientBalance,
				GasUsed: gas,
			}, Address{}
		}
		stateDB.SetBalance(caller, new(big.Int).Sub(callerBalance, value))
		stateDB.SetBalance(contractAddr, value)
	}

	// V21-001/V21-002 FIX: Auto-detect EVM bytecode and translate to QVM format.
	// Mirrors the Create() implementation — constructor args (ABI-encoded data)
	// appended after the bytecode must NOT be translated, so we keep the original
	// for Input/OriginalCode and only translate the executable portion.
	originalInput := initCode
	if len(initCode) > 0 && IsEVMBytecode(initCode) {
		translated, err := TranslateEVMBytecode(initCode)
		if err != nil {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     fmt.Errorf("evm translation failed: %w", err),
				GasUsed: gas,
			}, Address{}
		}
		initCode = translated
		log.Printf("[EVM-COMPAT] Translated %d bytes EVM -> %d bytes QVM (CREATE2)", len(originalInput), len(initCode))
	}

	// Create execution context for init code
	// See Create() for rationale — Input = originalInput so CALLDATALOAD can read
	// constructor arguments appended after the bytecode.
	ctx := &ExecutionContext{
		Origin:      caller,
		GasPrice:    blockCtx.GasPrice,
		Caller:      caller,
		Address:     contractAddr,
		Value:       value,
		BlockNumber: blockCtx.BlockNumber,
		Timestamp:   blockCtx.Timestamp,
		Coinbase:    blockCtx.Coinbase,
		GasLimit:    blockCtx.GasLimit,
		ChainID:     blockCtx.ChainID,
		BlockHashes: blockCtx.BlockHashes,
		// QVM- (2026-07-20): properly initialize EIP-1559/4844/4399 fields.
		BaseFee:        baseFeeToUint64(blockCtx.BaseFee),
		BlobBaseFee:    baseFeeToUint64(blockCtx.BlobBaseFee),
		PrevRandao:     blockCtx.PrevRandao,
		Code:           initCode,
		Input:          originalInput,
		OriginalCode:   originalInput,
		EVMCompatible:  isEVMTranslatedCode(initCode), // R7-QV-001 FIX: Detect EVM-translated code dynamically
		Gas:            gas,
		Depth:          depth, // R35-P1-01 FIX: was hardcoded 0, bypassing reentrancy protection in nested calls
		ReadOnly:       false,
		SkipValidation: true, // initCode includes constructor args, skip QuickValidate
	}

	// Execute init code
	result := e.Execute(ctx, stateDB)

	if result.Err != nil {
		stateDB.RevertToSnapshot(snapshot)
		return result, Address{}
	}

	// Deploy the returned code
	deployedCode := result.ReturnData

	// V21-002 FIX: translate runtime code from EVM to QVM format (mirrors Create).
	// R122-STEP6 fail-closed: see the identical block in Create().
	if len(deployedCode) > 0 && IsEVMBytecode(deployedCode) {
		translated, err := TranslateEVMBytecode(deployedCode)
		if err != nil {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     fmt.Errorf("evm runtime translation failed (deployment rejected, fail-closed): %w", err),
				GasUsed: result.GasUsed,
			}, Address{}
		}
		deployedCode = translated
	}
	if len(deployedCode) > MaxCodeSize {
		stateDB.RevertToSnapshot(snapshot)
		return &ExecutionResult{
			Err:     ErrMaxCodeSizeExceeded,
			GasUsed: result.GasUsed,
		}, Address{}
	}

	// Validate deployed code
	if valResult := e.validator.ValidateDeployedCode(deployedCode); !valResult.Valid {
		stateDB.RevertToSnapshot(snapshot)
		// R32-P3-06 FIX (2026-07-28): Use ErrInvalidBytecode (wrapping the
		// specific validation error) instead of the misleading ErrInvalidOpcode.
		deployErr := ErrInvalidBytecode
		if firstErr := valResult.FirstError(); firstErr != nil {
			deployErr = fmt.Errorf("%w: %v", ErrInvalidBytecode, firstErr)
		}
		return &ExecutionResult{
			Err:     deployErr,
			GasUsed: result.GasUsed,
		}, Address{}
	}

	// Charge for code storage
	// R43-QVM-CREATE2-01 (2026-08-03): unified with Create's gas
	// accounting — previously used a manual divide-back check +
	// manual addition overflow check, while Create() used the
	// SafeMulGas / SafeAddGas helpers. The manual path was correct
	// but inconsistent and a maintenance burden (any future change
	// to SafeMulGas/SafeAddGas semantics would need to be mirrored
	// here manually). Using the helpers means both CREATE and
	// CREATE2 share the same overflow protection surface, and the
	// audit-tool diff against Create() returns to zero. Misuse
	// risk (under-priced code deposit DoS) is identical to before
	// because the helpers produce the same numerical results.
	codeLen2 := uint64(len(deployedCode))
	if GasCodeDeposit != 0 && codeLen2 > 0 {
		codeStorageCost, merr := SafeMulGas(codeLen2, GasCodeDeposit)
		if merr != nil {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     ErrOutOfGas,
				GasUsed: gas,
			}, Address{}
		}
		newGasUsed, aerr := SafeAddGas(result.GasUsed, codeStorageCost)
		if aerr != nil {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     ErrOutOfGas,
				GasUsed: gas,
			}, Address{}
		}
		result.GasUsed = newGasUsed
		if result.GasUsed > gas {
			stateDB.RevertToSnapshot(snapshot)
			return &ExecutionResult{
				Err:     ErrOutOfGas,
				GasUsed: gas,
			}, Address{}
		}
	}

	// Store the code
	stateDB.SetCode(contractAddr, deployedCode)

	return result, contractAddr
}

// CreateAddress calculates the address for a contract created with CREATE.
// audit-fix R68-QVM-2 [CRITICAL]: Use correct RLP encoding per EIP-161 / EVM spec.
// The previous implementation used raw concatenation, producing addresses that
// differ from the EVM standard (address = keccak256(RLP(caller, nonce))[12:]).
// This caused deployed contracts to have different addresses than external
// tools (e.g., hardhat, foundry) would predict for the same caller+nonce.
func CreateAddress(caller Address, nonce uint64) Address {
	// RLP encode: list [caller_bytes, nonce]
	// First, encode caller as 20-byte string: 0x94 + 20 bytes
	data := make([]byte, 0, 64)
	data = append(data, 0x94) // 0x80 + 20 = 0x80 + 0x14 = 0x94
	data = append(data, caller[:]...)

	// RLP encode nonce
	if nonce == 0 {
		data = append(data, 0x80) // empty string
	} else if nonce < 128 {
		data = append(data, byte(nonce))
	} else {
		var buf []byte
		n := nonce
		for n > 0 {
			buf = append([]byte{byte(n & 0xff)}, buf...)
			n >>= 8
		}
		data = append(data, byte(0x80+len(buf))) // #nosec G115 -- RLP: buf len < 56 guaranteed by caller
		data = append(data, buf...)
	}

	// rlpListPrefix returns the RLP list prefix and encodes listLen according to
	// EIP-161 (Spurious Dragon fork). For listLen < 56: prefix = 0xc0 + listLen (single
	// byte). For listLen >= 56: prefix = 0xf7 + numBytes(listLen), followed by the
	// length encoded in numBytes(listLen) bytes (big-endian).
	// audit-fix R69-QVM-3 [CRITICAL]: Previous code hardcoded 0xf8 for the >=56 branch,
	// which is only correct when numBytes(listLen)==1 (i.e., 56 <= listLen <= 255).
	// For listLen >= 256, the correct prefix is 0xf9 (numBytes=2) or 0xfa (numBytes=3),
	// and the length must be encoded as 2-3 bytes. The hardcoded else branch is dead
	// code for current use (20-byte address + nonce <= 29 bytes), but would produce
	// wrong addresses if caller or nonce encoding ever changed.
	rlpListPrefix := func(listLen int) []byte {
		if listLen < 56 {
			return []byte{byte(0xc0 + listLen)} // #nosec G115 -- RLP: listLen < 56 by branch condition
		}
		// Count bytes needed to encode listLen
		n := listLen
		numBytes := 0
		for n > 0 {
			numBytes++
			n >>= 8
		}
		prefix := byte(0xf7 + numBytes) // #nosec G115 -- RLP: numBytes <= 8 (max int64 = 8 bytes)
		// Encode listLen in numBytes bytes (big-endian)
		encodedLen := make([]byte, numBytes)
		n = listLen
		for i := numBytes - 1; i >= 0; i-- {
			encodedLen[i] = byte(n & 0xff) // #nosec G115 -- masking to single byte
			n >>= 8
		}
		result := make([]byte, 0, 1+numBytes+listLen)
		result = append(result, prefix)
		result = append(result, encodedLen...)
		return result
	}

	listLen := len(data)
	var encoded []byte
	if listLen < 56 {
		encoded = append([]byte{byte(0xc0 + listLen)}, data...)
	} else {
		prefix := rlpListPrefix(listLen)
		encoded = append(prefix, data...)
	}

	hash := keccak256(encoded)
	var addr Address
	copy(addr[:], hash[12:])
	return addr
}

// Create2Address calculates the address for a contract created with CREATE2.
func Create2Address(caller Address, salt Hash, initCode []byte) Address {
	// address = keccak256(0xff ++ caller ++ salt ++ keccak256(initCode))[12:]
	codeHash := keccak256(initCode)

	data := make([]byte, 1+20+32+32)
	data[0] = 0xff
	copy(data[1:21], caller[:])
	copy(data[21:53], salt[:])
	copy(data[53:85], codeHash[:])

	hash := keccak256(data)
	var addr Address
	copy(addr[:], hash[12:])
	return addr
}

// keccak256 computes the Keccak-256 hash.
// audit-fix R4-H2: replaced XOR-fold placeholder with real Keccak-256.
// The placeholder trivially collided, producing incorrect contract addresses.
func keccak256(data []byte) Hash {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

func typesAddr(a Address) types.Address {
	var ta types.Address
	copy(ta[:], a[:])
	return ta
}
