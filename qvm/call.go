// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"

	"github.com/quantaureum/qau/qvm/precompiled"
)

// CallContext holds context for contract calls.
type CallContext struct {
	Caller   Address
	Address  Address
	Value    *big.Int
	Input    []byte
	Gas      uint64
	ReadOnly bool
}

// CallResult holds the result of a contract call.
type CallResult struct {
	ReturnData []byte
	GasUsed    uint64
	Err        error
}

// executePrecompiled checks if the target address is a precompiled contract and
// executes it directly if so. Returns (executed, success, error) where:
//   - executed=true means the precompiled contract was run and the caller should
//     return immediately (success indicates whether it pushed 1 or 0).
//   - executed=false means the target is not a precompiled contract and the
//     caller should proceed with normal execution.
//   - success indicates whether the precompiled execution succeeded (true=push 1)
//     or failed (false=push 0). Callers should use this instead of Peek-ing the
//     stack to detect failure (R5-P3-2).
//   - error is non-nil only for actual errors (e.g. memory.Set failure), not for
//     precompile logic failures.
//
// QVM-R10-H2 (2026-07-19) FIX: Added `static` parameter. When true (caller is
// STATICCALL), stateful precompiled contracts are rejected — preventing a
// STATICCALL context from bypassing the read-only guarantee by routing
// through a precompile that mutates state (e.g. multisig createProposal,
// approveProposal, executeProposal). Previously, a STATICCALL to the multisig
// precompile could create/approve/execute proposals despite STATICCALL
// supposedly forbidding state changes — breaking EVM-expected invariants
// and potentially allowing read-only view functions to launch attacks.
func (i *Interpreter) executePrecompiled(env *Environment, addr Address, input []byte, callGas uint64, outOffset, outSize uint64, static bool) (executed bool, success bool, err error) {
	if env.precompiled == nil {
		return false, false, nil
	}
	addrTypes := typesAddr(addr)
	if !env.precompiled.IsPrecompiled(addrTypes) {
		return false, false, nil
	}

	// QVM-R10-H2: Reject stateful precompiles in STATICCALL context.
	// Use Registry.Get + type assertion to check IsStateful() without
	// changing the PrecompiledContract interface.
	if static {
		if pc := env.precompiled.Get(addrTypes); pc != nil {
			if sp, ok := pc.(precompiled.StatefulPrecompiledContract); ok && sp.IsStateful() {
				// Refund the already-consumed callGas (caller consumed
				// it before executePrecompiled; we must return it so
				// the parent doesn't lose gas for a rejected call).
				env.gas.Return(callGas)
				env.returnData = nil
				return true, false, env.stack.PushUint64(0)
			}
		}
	}

	// QVM- (2026-07-20) FIX: Inject execution context (stateDB,
	// blockTime, chainID) into context-aware precompiles before Run.
	// Without this, on-chain CALLs to the multisig precompile (0x66) fail
	// with "stateDB not set" because only the RPC layer was wiring the
	// context (on a separate precompile instance). The env.ctx fields are
	// already populated by the executor from the block context, so we
	// pass them through here.
	//
	// QVM-R13-HIGH-002 (2026-07-21) FIX: Use the atomic Set+dispatch path
	// (Registry.RunWithContext → AtomicContextPrecompiledContract.RunWithContext)
	// instead of the legacy injectPrecompileContext + Registry.Run two-step
	// sequence. The legacy sequence performed three separate locked Set
	// operations then a fourth locked Run, creating a TOCTOU race window in
	// parallel execution mode where another goroutine could interleave a
	// different stateDB/blockTime/chainID between the Sets and Run. The new
	// path performs Set + dispatch under a SINGLE lock acquisition.
	var output []byte
	var gasUsed uint64
	var runErr error
	if pc := env.precompiled.Get(addrTypes); pc != nil {
		// R38-P0-01 (2026-08-01): route through the caller-aware V2 path so
		// a V2 precompile (future multisig V2 at 0x66) can gate register/
		// proposal/execute on the authenticated caller/origin instead of
		// attacker-supplied calldata. The V2 registry falls back to the
		// legacy atomic RunWithContext (and then to the pure Run) for every
		// precompile that does not implement ContextAwarePrecompiledContractV2,
		// so sha256/ecrecover/dilithiumVerify/kyberKEM/legacy-multisig execute
		// exactly as before. `static` true here (passed in from opStaticCall /
		// ExecuteReadOnly) maps to CallKindStaticCall so a V2 precompile can
		// refuse state writes; QVM-R10-H2 already rejects stateful precompiles
		// under STATICCALL earlier in the dispatch, so this is belt-and-suspenders.
		callerT := typesAddr(env.ctx.Caller)
		originT := typesAddr(env.ctx.Origin)
		var valueT *big.Int
		if env.ctx.Value != nil {
			valueT = new(big.Int).Set(env.ctx.Value)
		}
		output, gasUsed, runErr = executePrecompiledAtomicV2(env.precompiled, addrTypes, env.stateDB,
			callerT, originT, valueT, env.ctx.Timestamp, env.ctx.ChainID, static, input, callGas)
	} else {
		// Should not happen (IsPrecompiled already checked), but be defensive.
		output, gasUsed, runErr = env.precompiled.Run(addrTypes, input, callGas)
	}
	if runErr != nil {
		// R5-P2-1 FIX: Refund unused gas on precompile failure.
		// The caller (opCall etc.) already consumed callGas from env.gas.
		// On failure, the unused portion (callGas - gasUsed) must be returned.
		// For OOG, gasUsed == callGas so refund is 0 (all gas consumed, EVM-correct).
		// For invalid input, gasUsed == requiredGas so refund is callGas - requiredGas.
		if gasUsed < callGas {
			env.gas.Return(callGas - gasUsed)
		}
		env.returnData = nil
		return true, false, env.stack.PushUint64(0)
	}

	// SECURITY FIX (R3-P1-1): Do NOT consume gasUsed here —the caller (opCall etc.)
	// already consumed callGas from env.gas before calling executePrecompiled.
	// Consuming gasUsed again would double-charge: net = callGas + gasUsed - (callGas - gasUsed) = 2*gasUsed.
	// Just return the unused portion of callGas.
	if gasUsed < callGas {
		env.gas.Return(callGas - gasUsed)
	}

	// Store return data
	env.returnData = output

	// Copy return data to memory
	if outSize > 0 && len(output) > 0 {
		copySize := outSize
		if uint64(len(output)) < copySize {
			copySize = uint64(len(output))
		}
		if err := env.memory.Set(outOffset, output[:copySize]); err != nil {
			return true, false, err
		}
	}

	return true, true, env.stack.PushUint64(1)
}

// opCall implements the CALL opcode.
//
// R39-P3-02 (2026-08-02) — QASM authoring contract / documentation:
// CALL pushes the success/failure flag on the stack. QVM contract
// authors writing QASM assembly MUST check this flag immediately
// after every CALL — otherwise a failed sub-call leaves its SSTORE
// side effects in place and the calling contract continues as if the
// call succeeded. The canonical post-CALL pattern, mirroring the
// EVM-idiom "CALL → ISZERO → JUMPI @revert" taught in Solidity
// guides, is:
//
//	; after CALL:
//	CALL
//	DUP1                  ; duplicate success flag for the EQ check
//	ISZERO                ; 1 if call FAILED, 0 if it succeeded
//	PUSH <failed_label>   ; jump target when call failed
//	JUMPI                 ; jump if ISZERO returned 1 (call failed)
//	POP                   ; success path: clear the original flag
//
// Without this pattern, the audit's R39-P3-02 finding warns "SSTORE
// after CALL won't auto-revert; a sub-call failure leaves its partial
// state mutations in place". The vulnerability was already illustrated
// by LinearVesting.release() — the contract issued a CALL to transfer
// QAU without checking the flag, and a reverted transfer still left
// the contract's accounting updated. The fix added the DUP1/ISZERO/
// JUMPI pattern; this comment documents the same rule for future
// QASM contracts so the same bug isn't re-introduced.
//
// QVM ENFORCEMENT NOTE: QVM does NOT enforce this pattern at the
// opcode level (CALL is silent-OK); the rule is a contract-authoring
// discipline that should be enforced by:
//  1. QASM linters / compilers when they become available (today QASM
//     is hand-written bytecode);
//  2. Code review checklists for contract auditors;
//  3. Documentation in the QASM authoring guide (this comment, plus
//     the test fixture qvm/precompiled/multisig_r39_p0_02_test.go
//     that exercises a fail-closed CALL pattern, are the references).
//
// QVM IMPLEMENTATION NOTE: opCall pushes 1 on success and 0 on
// failure (see the fallthrough at the bottom of this function). The
// gas-charging / depth-limit / existence checks are this function's;
// the inline flag-push is the contract's responsibility.
func (i *Interpreter) opCall(env *Environment) error {
	// Pop arguments from stack.
	// FIX: Verified EVM-compatible mode stack pop order is correct.
	// The EVMCompatible flag (the "cond" variable referenced in the audit)
	// selects between two pop orders. Both branches pop exactly 7 items with
	// no off-by-one: EVM mode pops gas→ddr→alue→nOffset→nSize→utOffset→utSize
	// (gas on stack top), QVM mode pops outSize→utOffset→nSize→nOffset→
	// value→ddr→as (retSize on stack top). The order is reversed because
	// EVM and QVM define opposite stack conventions for CALL arguments.
	// EVM order (gas on top): gas, addr, value, argsOffset, argsSize, retOffset, retSize
	// QVM order (retSize on top): outSize, outOffset, inSize, inOffset, value, addr, gas
	var outSizeWord, outOffsetWord, inSizeWord, inOffsetWord, valueWord, addrWord, gasWord Word
	var err error
	if env.ctx.EVMCompatible {
		gasWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		addrWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		valueWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
	} else {
		outSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		valueWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		addrWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		gasWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
	}
	// Convert to values
	gas := gasWord.ToUint64()
	var addr Address
	copy(addr[:], addrWord[12:])
	value := valueWord.ToBigInt()
	inOffset := inOffsetWord.ToUint64()
	inSize := inSizeWord.ToUint64()
	outOffset := outOffsetWord.ToUint64()
	outSize := outSizeWord.ToUint64()

	// Check write protection for value transfer
	if env.ctx.ReadOnly && value.Sign() > 0 {
		return ErrWriteProtection
	}

	// Calculate memory-expansion cost EVEN for the zero-address reject path
	// so the gas scheme is consistent. P3-QV-04 FIX (2026-08-03): the
	// previous code returned env.stack.PushUint64(0) right after the
	// zero-address check WITHOUT consuming any gas, enabling zero-cost
	// probing of zero-address behavior — an attacker could CALL the
	// zero address repeatedly and observe return / gas-left
	// differences to fingerprint the VM, or worse, drain the
	// CALL's input memory target then re-query without paying.
	// AUDIT-FULL H-4 (2026-08-14): the logic now lives in the shared
	// rejectZeroAddrCall helper so every call opcode (CALL, STATICCALL,
	// CALLCODE, DELEGATECALL, AUTHCALL) charges identically.

	// L10-020: Prevent calls to the zero address (0x0), a reserved address.
	// P3-QV-04: now gas-aware — see rejectZeroAddrCall.
	var zeroAddr Address
	if addr == zeroAddr {
		return rejectZeroAddrCall(env, gas, inOffset, inSize, outOffset, outSize)
	}

	// Calculate gas cost
	hasValue := value.Sign() > 0
	isNewAccount := !env.stateDB.Exist(addr)
	isCold := !env.stateDB.AddressInAccessList(addr)

	// Calculate memory expansion costs BEFORE calculating call gas,
	// so that callGas is computed from the gas remaining after ALL fixed costs.
	var memExpansionCost uint64
	if inSize > 0 {
		if inOffset+inSize < inOffset {
			return ErrMemoryOverflow
		}
		memExpansionCost += MemoryExpansionCost(env.memory.Size(), inOffset+inSize)
	}
	if outSize > 0 {
		if outOffset+outSize < outOffset {
			return ErrMemoryOverflow
		}
		outExpansion := MemoryExpansionCost(env.memory.Size(), outOffset+outSize)
		if outExpansion > memExpansionCost {
			memExpansionCost = outExpansion
		}
	}

	// SECURITY FIX (RISK-008): Calculate callGas based on gas remaining AFTER
	// deducting both callCost and memory expansion costs. Previously, callGas
	// was computed from env.gas.Remaining() before memory costs were deducted,
	// which could cause Consume(callGas) to fail if memory costs were significant.
	// This aligns with the EVM specification where the 63/64 rule applies to
	// gas remaining after all upfront costs.
	availableAfterFixed := env.gas.Remaining()
	if availableAfterFixed < memExpansionCost {
		return ErrOutOfGas
	}
	availableAfterFixed -= memExpansionCost

	// R5-P3-3 FIX: Account for reentrancy guard gas (2300) in callGas calculation.
	// The reentrancy guard gas penalty must be deducted from availableAfterFixed
	// BEFORE calculating callGas. Without this, the caller may allocate too much
	// gas to the sub-call (63/64 rule), leaving insufficient gas for the 2300
	// reentrancy penalty consumed later —causing legitimate CALLs to fail.
	// This check uses pre-increment callDepth (>= 1 means we're in a sub-call
	// where reentrancy is possible).
	reentrancyGuardGas := uint64(0)
	targetHasCode := len(env.stateDB.GetCode(addr)) > 0
	reentryIncremented := false
	if targetHasCode && env.callDepth >= 1 && env.IsAddressActive(addr) {
		// AUDIT (2026) QVFIX: Hard-block after MaxReentriesPerAddress
		// reentries to the same address within one transaction. The 2300 gas
		// penalty below remains as the per-reentry economic disincentive.
		if !env.IncrementReentryCount(addr) {
			return env.stack.PushUint64(0)
		}
		reentryIncremented = true
		// QVM- (2026-07-20) FIX: Decrement the reentry counter when
		// this CALL frame returns (success, revert, or error). Without this,
		// the counter would saturate at MaxReentriesPerAddress after a few
		// legitimate reentries, permanently DoS'ing the address within the
		// transaction.
		defer func() {
			if reentryIncremented {
				env.DecrementReentryCount(addr)
			}
		}()
		reentrancyGuardGas = 2300
		if availableAfterFixed < reentrancyGuardGas {
			return env.stack.PushUint64(0)
		}
		availableAfterFixed -= reentrancyGuardGas
	}

	callCost, callGas := CalculateCallGas(
		env.gasTable,
		availableAfterFixed,
		gas,
		hasValue,
		isNewAccount,
		isCold,
	)

	// FIX: Verify callCost does not exceed available gas before consuming.
	// CalculateCallGas may return math.MaxUint64 on overflow, which would cause
	// Consume() to fail with a confusing "out of gas" message. Fail explicitly
	// here for clarity and defense-in-depth.
	if callCost > availableAfterFixed {
		return env.stack.PushUint64(0)
	}

	if err := env.gas.Consume(callCost); err != nil {
		return err
	}

	// Add to access list
	env.stateDB.AddAddressToAccessList(addr)

	// audit-fix QVM-MEM-1: Consume memory expansion gas ONCE based on the maximum
	// memory size needed, not separately for input and output. The previous code
	// consumed MemoryExpansionCost for input AND output separately, but EVM memory
	// expansion is based on the highest offset accessed —charging both overcounts.
	// The memExpansionCost was already subtracted from availableAfterFixed above
	// to compute callGas correctly, so we must consume exactly that amount here.
	if memExpansionCost > 0 {
		if err := env.gas.Consume(memExpansionCost); err != nil {
			return err
		}
	}

	// Get input data
	var input []byte
	if inSize > 0 {
		input, err = env.memory.Get(inOffset, inSize)
		if err != nil {
			return err
		}
	}

	// Check balance for value transfer
	if hasValue {
		balance := env.stateDB.GetBalance(env.ctx.Address)
		if balance.Cmp(value) < 0 {
			return env.stack.PushUint64(0)
		}
	}

	// Create call context
	callCtx := &ExecutionContext{
		Origin:        env.ctx.Origin,
		GasPrice:      env.ctx.GasPrice,
		Caller:        env.ctx.Address,
		Address:       addr,
		Value:         value,
		BlockNumber:   env.ctx.BlockNumber,
		Timestamp:     env.ctx.Timestamp,
		Coinbase:      env.ctx.Coinbase,
		GasLimit:      env.ctx.GasLimit,
		ChainID:       env.ctx.ChainID,
		BaseFee:       env.ctx.BaseFee,     // QVM- propagate BASEFEE opcode value
		BlobBaseFee:   env.ctx.BlobBaseFee, // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:    env.ctx.PrevRandao,  // QVM- propagate PREVRANDAO opcode value
		Code:          env.stateDB.GetCode(addr),
		Input:         input,
		Gas:           callGas,
		Depth:         env.ctx.Depth + 1,
		ReadOnly:      env.ctx.ReadOnly,
		EVMCompatible: isEVMTranslatedCode(env.stateDB.GetCode(addr)), // R7-QV-001 FIX: Detect EVM-translated code dynamically
		ParentEnv:     env,                                            // audit-fix CRIT-REENTRY: pass current env for reentrancy tracking
	}

	// CR40-C9 FIX: Unified depth tracking to eliminate race condition
	// Increment env.callDepth BEFORE any checks to ensure atomic depth tracking
	// FIX: Synchronize callCtx.Depth with env.callDepth to eliminate
	// dual-tracking inconsistency. Previously callCtx.Depth was set to
	// env.ctx.Depth + 1 (line 290) while env.callDepth was incremented separately
	// (line 298), causing them to diverge. Now callCtx.Depth is updated AFTER
	// the increment so both reflect the same depth.
	env.callDepth++
	callCtx.Depth = int(env.callDepth)
	defer func() {
		// Always decrement call depth when returning
		env.callDepth--
	}()

	// CR40-C9 FIX: Use env.callDepth for depth check instead of callCtx.Depth
	// This ensures consistent depth tracking across all call types
	// FIX: Use >= (not >) for consistency with executor.go which checks
	// ctx.Depth >= MaxCallDepth. The > check was dead code since executor.go's
	// more strict check fires first.
	if env.callDepth >= MaxCallDepth {
		return env.stack.PushUint64(0)
	}

	// SECURITY FIX (audit QVM-01): Restored cross-contract reentrancy protection.
	// The previous audit (2026-06-14) removed blanket reentrancy blocking to enable
	// EVM-compatible composability. However, QASM contracts may not have access to
	// ReentrancyGuard (unlike Solidity contracts). We now use a hybrid approach:
	//
	// 1. MaxCallDepth (1024) prevents unbounded recursion / stack overflow
	// 2. Cross-contract reentrancy detection: if a contract calls BACK to an
	//    already-active contract in the call stack (A→→ pattern), we add a
	//    reentrancy guard gas penalty rather than blocking outright. This makes
	//    reentrancy attacks economically prohibitive while allowing legitimate
	//    composability (A→→ where C is a new contract).
	// 3. PushActiveAddress loop detection prevents immediate self-reentrant
	//    infinite loops on the SAME address at the SAME depth.
	//
	// R5-P3-3 FIX: reentrancyGuardGas was pre-calculated above (before callGas
	// calculation) and already deducted from availableAfterFixed. Here we only
	// consume it from env.gas.
	// R5-P4-1 FIX: On gas consumption failure, return push 0 directly without
	// the previous no-op truncation (env.activeAddresses[:len(env.activeAddresses)]
	// was a no-op since PushActiveAddress hasn't been called yet).
	if reentrancyGuardGas > 0 {
		if err := env.gas.Consume(reentrancyGuardGas); err != nil {
			return env.stack.PushUint64(0)
		}
	}

	// CRIT-1 FIX: Save activeAddresses length to restore on revert/error
	// Baseline length before push to ensure correct pop on all exit paths.
	// P3-V1 AUDIT NOTE (cleanup logic is correct): The savedActiveLen pattern
	// is used consistently across opCall/opCallCode/opDelegateCall/opStaticCall.
	// Every branch that returns after this point restores
	// `env.activeAddresses = env.activeAddresses[:savedActiveLen]` (either inline
	// or via defer) BEFORE returning, so the active-address stack can never
	// leak entries from a sub-call, regardless of success/revert/error path.
	// This is the equivalent of a defer-pop that runs on ALL exit paths.
	savedActiveLen := len(env.activeAddresses)

	// R24-C8 FIX: Check if push succeeded - fail call if max depth exceeded
	// R41-C-C1 FIX: Restore activeAddresses before early return.
	// PushActiveAddress may have partially grown the slice before failing,
	// so we must restore to savedActiveLen to prevent stack corruption.
	if !env.PushActiveAddress(addr) {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return env.stack.PushUint64(0)
	}

	// audit-fix R2-H1: snapshot BEFORE value transfer so that revert
	// undoes both the transfer and the sub-call's state changes.
	snapshot := env.stateDB.Snapshot()

	// Transfer value
	if hasValue {
		// SECURITY (audit 2026-06-14, M3): The previous code had a dead balance
		// check here ("if callerBalance < value { /* will fail */ }") that did
		// nothing —the real guard is earlier (balance < value →push 0 at the
		// top of opCall), so by this point balance >= value is guaranteed.
		// Removed the misleading dead branch; the transfer below is safe.
		callerBalance := env.stateDB.GetBalance(env.ctx.Address)
		env.stateDB.SetBalance(env.ctx.Address, new(big.Int).Sub(callerBalance, value))
		calleeBalance := env.stateDB.GetBalance(addr)
		env.stateDB.SetBalance(addr, new(big.Int).Add(calleeBalance, value))
	}

	// audit-fix R3-F11: deduct callGas from parent BEFORE the sub-call.
	// Without this, the child's gas was never charged to the parent.
	if err := env.gas.Consume(callGas); err != nil {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		// SECURITY FIX (R3-P1-2): Roll back value transfer on OOG.
		// The snapshot was taken before the value transfer (line 275),
		// so RevertToSnapshot undoes the balance changes.
		env.stateDB.RevertToSnapshot(snapshot)
		return env.stack.PushUint64(0)
	}

	// Check if the target is a precompiled contract.
	// Precompiled contracts have no bytecode (GetCode returns empty), so
	// i.Execute() would just succeed with empty return data without actually
	// running the precompiled logic. We must detect and execute them directly.
	// QVM-R10-H2 / R37-P1-QVM-02 FIX (2026-07-30): pass the INHERITED
	// read-only flag instead of a hardcoded false. A STATICCALL ancestor
	// propagates ReadOnly=true into this frame; forwarding it prevents
	// stateful precompiles (e.g. multisig 0x66 ExecuteProposal) from
	// mutating state under a static-call guarantee.
	if executed, success, err := i.executePrecompiled(env, addr, input, callGas, outOffset, outSize, env.ctx.ReadOnly); executed {
		// R5-P3-2 FIX: Use the success return value instead of Peek-ing the
		// stack to detect failure. If precompiled execution failed, roll back
		// the value transfer (R4-P1-1).
		if !success {
			env.stateDB.RevertToSnapshot(snapshot)
		}
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return err
	}

	// Execute call
	if env.tracer != nil {
		env.tracer.CaptureEnter(CALL, env.ctx.Address, addr, input, callGas, value)
	}
	result := i.Execute(callCtx, env.stateDB)
	if env.tracer != nil {
		env.tracer.CaptureExit(result.ReturnData, result.GasUsed, result.Err)
	}
	//  AUDIT NOTE: Execute returns an ExecutionResult with Err field.
	// Sub-call failures do NOT abort the parent call — this matches EVM
	// semantics where a failed CALL pushes 0 to the stack and execution
	// continues. The result.Err is checked later to determine success/failure
	// pushed to the stack.

	// audit-fix R3-F11: return unused gas from sub-call to parent.
	if result.GasUsed < callGas {
		env.gas.Return(callGas - result.GasUsed)
	}

	// Handle result
	//
	// L7-015 NOTE: Two distinct failure paths after a sub-call:
	//   - error path (result.Err != nil && !result.Reverted): an execution
	//     error (out-of-gas, invalid opcode, ...). State rolls back to the
	//     snapshot, returnData is cleared, NO logs are propagated, and 0
	//     (failure) is pushed.
	//   - revert path (result.Reverted): the callee executed REVERT. State
	//     rolls back to the snapshot too, but returnData PRESERVES the
	//     revert reason so the caller can inspect it. Logs from a reverted
	//     sub-call are discarded (L5-003) to prevent log-injection.
	if result.Err != nil && !result.Reverted {
		// CRIT-1 FIX: Restore activeAddresses BEFORE state revert
		// This ensures reentrancy protection stays consistent
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		env.stateDB.RevertToSnapshot(snapshot)
		env.returnData = nil
		return env.stack.PushUint64(0)
	}

	if result.Reverted {
		// CRIT-1 FIX: Restore activeAddresses on revert as well
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		env.stateDB.RevertToSnapshot(snapshot)
	}

	// Store return data
	env.returnData = result.ReturnData

	// Copy return data to memory
	if outSize > 0 && len(result.ReturnData) > 0 {
		copySize := outSize
		if uint64(len(result.ReturnData)) < copySize {
			copySize = uint64(len(result.ReturnData))
		}
		if err := env.memory.Set(outOffset, result.ReturnData[:copySize]); err != nil {
			env.activeAddresses = env.activeAddresses[:savedActiveLen]
			return err
		}
	}

	// Add logs
	// audit-fix L5-003: Only propagate logs from non-reverted sub-calls.
	// When a sub-call reverts, its state changes are rolled back, and its
	// logs should also be discarded to prevent log injection attacks where
	// a malicious contract emits fake events before reverting.
	if !result.Reverted {
		env.logs = append(env.logs, result.Logs...)
	}

	// CR40-C4 FIX: Cleanup activeAddresses on normal return path
	env.activeAddresses = env.activeAddresses[:savedActiveLen]

	// Push success/failure
	if result.Err != nil {
		return env.stack.PushUint64(0)
	}
	return env.stack.PushUint64(1)
}

// rejectZeroAddrCall implements the gas-aware zero-address rejection shared
// by all call opcodes (AUDIT-FULL H-4, 2026-08-14). P3-QV-04 introduced this
// scheme for opCall only; STATICCALL/CALLCODE/DELEGATECALL/AUTHCALL still
// returned 0 without charging gas, allowing zero-cost probing.
//
// Path: compute memory-expansion cost (same formula as the non-zero-address
// path), consume it, then charge a base call cost via CalculateCallGas
// (warm, no value, no new account — the zero address is conventionally in
// the access list), then push 0. The 63/64 rule is preserved because we
// never enter a sub-call frame in this path.
func rejectZeroAddrCall(env *Environment, gas, inOffset, inSize, outOffset, outSize uint64) error {
	// Compute memory-expansion cost.
	var memCost uint64
	if inSize > 0 {
		if inOffset+inSize < inOffset {
			return ErrMemoryOverflow
		}
		memCost += MemoryExpansionCost(env.memory.Size(), inOffset+inSize)
	}
	if outSize > 0 {
		if outOffset+outSize < outOffset {
			return ErrMemoryOverflow
		}
		outExp := MemoryExpansionCost(env.memory.Size(), outOffset+outSize)
		if outExp > memCost {
			memCost = outExp
		}
	}
	if env.gas.Remaining() < memCost {
		return ErrOutOfGas
	}
	if err := env.gas.Consume(memCost); err != nil {
		return err
	}
	// Charge callCost via CalculateCallGas consistency — zero account
	// exists so isNewAccount=false; treat addr as warm (zero addr is
	// conventionally warm; a cold-path analysis would be overkill
	// here and would require access-list mutation, which would
	// itself need accounting). Use a static base cost mirroring
	// CalculateCallGas's callCost for the warmcase (no value).
	callCost, _ := CalculateCallGas(
		env.gasTable,
		env.gas.Remaining(),
		gas,
		false, // hasValue = false (zero address refuses value transfer)
		false, // isNewAccount = false (zero address does NOT create account)
		false, // isCold = false (warm — see above rationale)
	)
	if callCost > env.gas.Remaining() {
		return env.stack.PushUint64(0)
	}
	if err := env.gas.Consume(callCost); err != nil {
		return err
	}
	return env.stack.PushUint64(0)
}

// opStaticCall implements the STATICCALL opcode.
func (i *Interpreter) opStaticCall(env *Environment) error {
	// Pop arguments from stack.
	// EVM order (gas on top): gas, addr, argsOffset, argsSize, retOffset, retSize
	// QVM order (retSize on top): outSize, outOffset, inSize, inOffset, addr, gas
	var outSizeWord, outOffsetWord, inSizeWord, inOffsetWord, addrWord, gasWord Word
	var err error
	if env.ctx.EVMCompatible {
		gasWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		addrWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
	} else {
		outSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		addrWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		gasWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
	}
	// Convert to values
	gas := gasWord.ToUint64()
	var addr Address
	copy(addr[:], addrWord[12:])
	inOffset := inOffsetWord.ToUint64()
	inSize := inSizeWord.ToUint64()
	outOffset := outOffsetWord.ToUint64()
	outSize := outSizeWord.ToUint64()

	// L10-020: Prevent calls to the zero address (0x0), a reserved address.
	// AUDIT-FULL H-4 (2026-08-14): now gas-aware via the shared helper.
	var zeroAddr Address
	if addr == zeroAddr {
		return rejectZeroAddrCall(env, gas, inOffset, inSize, outOffset, outSize)
	}

	// Calculate gas cost
	isCold := !env.stateDB.AddressInAccessList(addr)

	// SECURITY FIX (RISK-008): Pre-calculate memory expansion costs before
	// computing callGas, consistent with opCall fix.
	var memExpansionCost uint64
	if inSize > 0 {
		if inOffset+inSize < inOffset {
			return ErrMemoryOverflow
		}
		memExpansionCost += MemoryExpansionCost(env.memory.Size(), inOffset+inSize)
	}
	if outSize > 0 {
		if outOffset+outSize < outOffset {
			return ErrMemoryOverflow
		}
		outExpansion := MemoryExpansionCost(env.memory.Size(), outOffset+outSize)
		if outExpansion > memExpansionCost {
			memExpansionCost = outExpansion
		}
	}

	availableAfterFixed := env.gas.Remaining()
	if availableAfterFixed < memExpansionCost {
		return ErrOutOfGas
	}
	availableAfterFixed -= memExpansionCost

	// R2-P3-19 FIX: Add reentrancy guard gas for STATICCALL, consistent with opCall/opDelegateCall/opCallCode.
	// Although STATICCALL is read-only, cross-contract reentrancy (A→(STATICCALL)→)
	// can still be exploited for state probing or view-function reentrancy attacks.
	// The 2300 gas penalty makes such attacks economically prohibitive.
	reentrancyGuardGas := uint64(0)
	targetHasCode := len(env.stateDB.GetCode(addr)) > 0
	reentryIncremented := false
	if targetHasCode && env.callDepth >= 1 && env.IsAddressActive(addr) {
		// AUDIT (2026) QVFIX: Hard-block after MaxReentriesPerAddress
		// reentries to the same address within one transaction. The 2300 gas
		// penalty below remains as the per-reentry economic disincentive.
		if !env.IncrementReentryCount(addr) {
			return env.stack.PushUint64(0)
		}
		reentryIncremented = true
		// QVM- (2026-07-20) FIX: Decrement the reentry counter when
		// this STATICCALL frame returns. See opCall for full rationale.
		defer func() {
			if reentryIncremented {
				env.DecrementReentryCount(addr)
			}
		}()
		reentrancyGuardGas = 2300
		if availableAfterFixed < reentrancyGuardGas {
			return env.stack.PushUint64(0)
		}
		availableAfterFixed -= reentrancyGuardGas
	}

	callCost, callGas := CalculateCallGas(
		env.gasTable,
		availableAfterFixed,
		gas,
		false, // no value
		false, // not new account
		isCold,
	)

	// AUDIT-FULL QV-06 (2026-08-14): Verify callCost does not exceed available
	// gas before consuming, mirroring the  fix in opCall. CalculateCallGas
	// may return math.MaxUint64 on overflow; without this check Consume() would
	// fail with a confusing "out of gas" instead of a clean revert-style failure.
	if callCost > availableAfterFixed {
		return env.stack.PushUint64(0)
	}

	if err := env.gas.Consume(callCost); err != nil {
		return err
	}

	// Add to access list
	env.stateDB.AddAddressToAccessList(addr)

	// audit-fix QVM-MEM-1: Consume memory expansion gas ONCE (same fix as opCall).
	if memExpansionCost > 0 {
		if err := env.gas.Consume(memExpansionCost); err != nil {
			return err
		}
	}

	// R2-P3-19 FIX: Consume reentrancy guard gas after memory expansion, before callGas.
	if reentrancyGuardGas > 0 {
		if err := env.gas.Consume(reentrancyGuardGas); err != nil {
			return env.stack.PushUint64(0)
		}
	}

	// Get input data
	var input []byte
	if inSize > 0 {
		input, err = env.memory.Get(inOffset, inSize)
		if err != nil {
			return err
		}
	}

	// Create call context (read-only)
	callCtx := &ExecutionContext{
		Origin:        env.ctx.Origin,
		GasPrice:      env.ctx.GasPrice,
		Caller:        env.ctx.Address,
		Address:       addr,
		Value:         big.NewInt(0),
		BlockNumber:   env.ctx.BlockNumber,
		Timestamp:     env.ctx.Timestamp,
		Coinbase:      env.ctx.Coinbase,
		GasLimit:      env.ctx.GasLimit,
		ChainID:       env.ctx.ChainID,
		BaseFee:       env.ctx.BaseFee,     // QVM- propagate BASEFEE opcode value
		BlobBaseFee:   env.ctx.BlobBaseFee, // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:    env.ctx.PrevRandao,  // QVM- propagate PREVRANDAO opcode value
		Code:          env.stateDB.GetCode(addr),
		Input:         input,
		Gas:           callGas,
		Depth:         env.ctx.Depth + 1,
		ReadOnly:      true,                                           // Static call is always read-only
		EVMCompatible: isEVMTranslatedCode(env.stateDB.GetCode(addr)), // R7-QV-001 FIX: Detect EVM-translated code dynamically
		ParentEnv:     env,                                            // audit-fix CRIT-REENTRY: pass current env for reentrancy tracking
	}

	// CR40-C9 FIX: Unified depth tracking to eliminate race condition
	// Increment env.callDepth BEFORE any checks to ensure atomic depth tracking
	// FIX: Synchronize callCtx.Depth with env.callDepth (see opCall).
	env.callDepth++
	callCtx.Depth = int(env.callDepth)
	defer func() {
		env.callDepth--
	}()

	// CR40-C9 FIX: Use env.callDepth for depth check instead of callCtx.Depth
	// FIX: Use >= (not >) for consistency with opCall and executor.go
	if env.callDepth >= MaxCallDepth {
		return env.stack.PushUint64(0)
	}

	// CRIT-1 FIX: Save activeAddresses length for proper restore on all exit paths
	// Baseline length before push to ensure correct pop on all exit paths.
	savedActiveLen := len(env.activeAddresses)

	// CRIT-1 FIX: Check if push succeeded - fail call if max depth exceeded
	if !env.PushActiveAddress(addr) {
		// R8-QV-001 FIX: Restore activeAddresses for consistency with
		// opCall/opDelegateCall, even though PushActiveAddress does not
		// modify the slice on failure. This is defensive against future
		// implementation changes.
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return env.stack.PushUint64(0)
	}

	defer func() {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
	}()

	// audit-fix R3-F11: deduct callGas from parent BEFORE the sub-call.
	if err := env.gas.Consume(callGas); err != nil {
		// Gas consume failed - defer will restore activeAddresses
		return env.stack.PushUint64(0)
	}

	// Check if the target is a precompiled contract.
	// Precompiled contracts have no bytecode, so i.Execute() would succeed
	// with empty return data. Execute precompiled logic directly instead.
	// R6-QV-002 FIX: Use the success return value for consistency with opCall
	// and opCallCode. Although STATICCALL is read-only (no state to revert),
	// checking success ensures consistent behavior across all CALL opcodes.
	// QVM-R10-H2: pass static=true (STATICCALL must reject stateful precompiles).
	//
	// R35-P2-QVM-01 FIX (2026-07-29): Add Snapshot before precompiled check
	// for defense-in-depth, matching opCall/opCallCode/opDelegateCall. Although
	// static=true should reject stateful precompiles, a Snapshot + revert-on-
	// failure costs nothing and protects against any future precompile that
	// might mutate state despite the static flag (e.g. via a bug in the static
	// guard). Without this, a stateful precompile that slipped through the
	// static check would leave its state mutations permanently applied.
	staticSnapshot := env.stateDB.Snapshot()
	if executed, success, err := i.executePrecompiled(env, addr, input, callGas, outOffset, outSize, true); executed {
		if !success {
			env.stateDB.RevertToSnapshot(staticSnapshot)
		}
		return err
	}

	// Execute call
	if env.tracer != nil {
		env.tracer.CaptureEnter(STATICCALL, env.ctx.Address, addr, input, callGas, big.NewInt(0))
	}
	result := i.Execute(callCtx, env.stateDB)
	if env.tracer != nil {
		env.tracer.CaptureExit(result.ReturnData, result.GasUsed, result.Err)
	}

	// CRIT-1 FIX: Defer handles restore of activeAddresses on ALL exit paths
	// No explicit PopActiveAddress needed - defer restores to savedActiveLen

	// audit-fix R3-F11: return unused gas from sub-call to parent.
	if result.GasUsed < callGas {
		env.gas.Return(callGas - result.GasUsed)
	}

	// Store return data
	env.returnData = result.ReturnData

	// Copy return data to memory
	if outSize > 0 && len(result.ReturnData) > 0 {
		copySize := outSize
		if uint64(len(result.ReturnData)) < copySize {
			copySize = uint64(len(result.ReturnData))
		}
		if err := env.memory.Set(outOffset, result.ReturnData[:copySize]); err != nil {
			return err
		}
	}

	// Push success/failure
	if result.Err != nil {
		return env.stack.PushUint64(0)
	}
	return env.stack.PushUint64(1)
}

// opDelegateCall implements the DELEGATECALL opcode.
//
//	(P3): Gas cost calculation for DELEGATECALL mirrors opCall:
//	1. memExpansionCost —memory growth for input/output buffers (charged once
//	   via MemoryExpansionCost on the union of in/out ranges).
//	2. reentrancyGuardGas —2300 charged for reentrant calls into a contract
//	   (targetHasCode && callDepth >= 1 && IsAddressActive(ctx.Address)).
//	   DELEGATECALL runs in the caller's storage context, so reentrancy is
//	   detected via ctx.Address (not the target addr).
//	3. callCost/callGas —base call gas + EIP-2929 cold-access surcharge,
//	   computed by CalculateCallGas against gas remaining after (1)+(2).
//
// Fixed costs (memory, reentrancy) are reserved first so the gas passed to
// CalculateCallGas cannot be double-spent.
func (i *Interpreter) opDelegateCall(env *Environment) error {
	// Pop arguments from stack.
	// EVM order (gas on top): gas, addr, argsOffset, argsSize, retOffset, retSize
	// QVM order (retSize on top): outSize, outOffset, inSize, inOffset, addr, gas
	var outSizeWord, outOffsetWord, inSizeWord, inOffsetWord, addrWord, gasWord Word
	var err error
	if env.ctx.EVMCompatible {
		gasWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		addrWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
	} else {
		outSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		addrWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		gasWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
	}
	// Convert to values
	gas := gasWord.ToUint64()
	var addr Address
	copy(addr[:], addrWord[12:])
	inOffset := inOffsetWord.ToUint64()
	inSize := inSizeWord.ToUint64()
	outOffset := outOffsetWord.ToUint64()
	outSize := outSizeWord.ToUint64()

	// L10-020: Prevent calls to the zero address (0x0), a reserved address.
	// AUDIT-FULL H-4 (2026-08-14): now gas-aware via the shared helper.
	var zeroAddr Address
	if addr == zeroAddr {
		return rejectZeroAddrCall(env, gas, inOffset, inSize, outOffset, outSize)
	}

	// Calculate gas cost
	isCold := !env.stateDB.AddressInAccessList(addr)

	// SECURITY FIX (RISK-008): Pre-calculate memory expansion costs before
	// computing callGas, consistent with opCall fix.
	var memExpansionCost uint64
	if inSize > 0 {
		if inOffset+inSize < inOffset {
			return ErrMemoryOverflow
		}
		memExpansionCost += MemoryExpansionCost(env.memory.Size(), inOffset+inSize)
	}
	if outSize > 0 {
		if outOffset+outSize < outOffset {
			return ErrMemoryOverflow
		}
		outExpansion := MemoryExpansionCost(env.memory.Size(), outOffset+outSize)
		if outExpansion > memExpansionCost {
			memExpansionCost = outExpansion
		}
	}

	availableAfterFixed := env.gas.Remaining()
	if availableAfterFixed < memExpansionCost {
		return ErrOutOfGas
	}
	availableAfterFixed -= memExpansionCost

	// R6-P3 FIX: Add reentrancy guard gas for DELEGATECALL, consistent with opCall/opAuthCall.
	// DELEGATECALL executes external code in the current contract's storage context,
	// making reentrancy attacks potentially dangerous.
	// SECURITY (audit P0-): Must check env.ctx.Address (not addr) for reentrancy,
	// consistent with PushActiveAddress(env.ctx.Address) below. DELEGATECALL runs in
	// the CURRENT contract's context, so reentrancy is detected via ctx.Address.
	reentrancyGuardGas := uint64(0)
	targetHasCode := len(env.stateDB.GetCode(addr)) > 0
	reentryIncremented := false
	if targetHasCode && env.callDepth >= 1 && env.IsAddressActive(env.ctx.Address) {
		// AUDIT (2026) QVFIX: Hard-block after MaxReentriesPerAddress.
		if !env.IncrementReentryCount(env.ctx.Address) {
			return env.stack.PushUint64(0)
		}
		reentryIncremented = true
		// QVM- (2026-07-20) FIX: Decrement the reentry counter when
		// this DELEGATECALL frame returns. See opCall for full rationale.
		defer func() {
			if reentryIncremented {
				env.DecrementReentryCount(env.ctx.Address)
			}
		}()
		reentrancyGuardGas = 2300
		if availableAfterFixed < reentrancyGuardGas {
			return env.stack.PushUint64(0)
		}
		availableAfterFixed -= reentrancyGuardGas
	}

	callCost, callGas := CalculateCallGas(
		env.gasTable,
		availableAfterFixed,
		gas,
		false,
		false,
		isCold,
	)

	if err := env.gas.Consume(callCost); err != nil {
		return err
	}

	// Add to access list
	env.stateDB.AddAddressToAccessList(addr)

	// audit-fix QVM-MEM-1: Consume memory expansion gas ONCE (same fix as opCall).
	if memExpansionCost > 0 {
		if err := env.gas.Consume(memExpansionCost); err != nil {
			return err
		}
	}

	// R6-P3 FIX: Consume reentrancy guard gas after memory expansion, before callGas.
	if reentrancyGuardGas > 0 {
		if err := env.gas.Consume(reentrancyGuardGas); err != nil {
			return env.stack.PushUint64(0)
		}
	}

	// Get input data
	var input []byte
	if inSize > 0 {
		input, err = env.memory.Get(inOffset, inSize)
		if err != nil {
			return err
		}
	}

	// Create call context (delegate call uses caller's context)
	callCtx := &ExecutionContext{
		Origin:        env.ctx.Origin,
		GasPrice:      env.ctx.GasPrice,
		Caller:        env.ctx.Caller,  // Keep original caller
		Address:       env.ctx.Address, // Keep current address (storage context)
		Value:         env.ctx.Value,   // Keep original value
		BlockNumber:   env.ctx.BlockNumber,
		Timestamp:     env.ctx.Timestamp,
		Coinbase:      env.ctx.Coinbase,
		GasLimit:      env.ctx.GasLimit,
		ChainID:       env.ctx.ChainID,
		BaseFee:       env.ctx.BaseFee,           // QVM- propagate BASEFEE opcode value
		BlobBaseFee:   env.ctx.BlobBaseFee,       // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:    env.ctx.PrevRandao,        // QVM- propagate PREVRANDAO opcode value
		Code:          env.stateDB.GetCode(addr), // Use target's code
		Input:         input,
		Gas:           callGas,
		Depth:         env.ctx.Depth + 1,
		ReadOnly:      env.ctx.ReadOnly,
		EVMCompatible: isEVMTranslatedCode(env.stateDB.GetCode(addr)), // R7-QV-001 FIX: Detect EVM-translated code dynamically
		ParentEnv:     env,                                            // audit-fix CRIT-REENTRY: pass current env for reentrancy tracking
	}

	// CR40-C9 FIX: Unified depth tracking to eliminate race condition
	// Increment env.callDepth BEFORE any checks to ensure atomic depth tracking
	// FIX: Synchronize callCtx.Depth with env.callDepth (see opCall).
	env.callDepth++
	callCtx.Depth = int(env.callDepth)
	defer func() {
		env.callDepth--
	}()

	// CR40-C9 FIX: Use env.callDepth for depth check instead of callCtx.Depth
	// FIX: Use >= (not >) for consistency with opCall and executor.go
	if env.callDepth >= MaxCallDepth {
		return env.stack.PushUint64(0)
	}

	// R6-P3 FIX: DELEGATECALL now has reentrancy guard gas (2300) consistent with opCall.
	// The guard gas is consumed above, before the callGas. PushActiveAddress below
	// provides cross-contract reentrancy detection.
	// L19-012 FIX: Removed dead code - targetHasCode was reassigned but never used,
	// and _ = env.ctx.Address was a no-op. Both were leftover from a previous
	// refactoring and served no purpose.

	// CRIT-1 FIX: Save activeAddresses length to restore on revert/error
	// Baseline length before push to ensure correct pop on all exit paths.
	savedActiveLen := len(env.activeAddresses)

	// R24-C8 FIX: Check if push succeeded - fail call if max depth exceeded
	// R41-C-C1 FIX: Restore activeAddresses before early return.
	// PushActiveAddress may have partially grown the slice before failing,
	// so we must restore to savedActiveLen to prevent stack corruption.
	// SECURITY (audit P2-): DELEGATECALL runs in the CURRENT contract's
	// context, so the reentrancy guard must track env.ctx.Address (the caller)
	// not addr (the target). Without this fix, a B->A->B reentrancy via
	// DELEGATECALL would bypass detection because addr != ctx.Address.
	if !env.PushActiveAddress(env.ctx.Address) {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return env.stack.PushUint64(0)
	}

	// audit-fix R3-F11: deduct callGas from parent BEFORE the sub-call.
	if err := env.gas.Consume(callGas); err != nil {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return env.stack.PushUint64(0)
	}

	// R35-P0-02 FIX: Take Snapshot BEFORE executePrecompiled so that stateful
	// precompiled contracts (e.g., multisig at 0x66 implementing
	// StatefulPrecompiledContract via SetState) can be rolled back on failure.
	// Previously the snapshot was taken AFTER the precompiled check (line 1114),
	// so a failed stateful precompiled execution left partial state changes
	// (e.g., funds deducted but proposal not created) with no rollback path.
	// This aligns DELEGATECALL with opCall (line 446) and opCallCode (line 607)
	// which both take Snapshot before precompiled execution.
	snapshot := env.stateDB.Snapshot()

	// Check if the target is a precompiled contract.
	// DELEGATECALL to a precompiled contract executes the precompiled logic
	// in the caller's storage context (no value transfer, no storage changes
	// to the precompiled address).
	// QVM-R10-H2 / R37-P1-QVM-02 FIX (2026-07-30): pass the INHERITED
	// read-only flag instead of a hardcoded false. DELEGATECALL inside a
	// STATICCALL chain still runs under the static guarantee (ReadOnly
	// propagates via ctx), so stateful precompiles must stay rejected.
	if executed, success, err := i.executePrecompiled(env, addr, input, callGas, outOffset, outSize, env.ctx.ReadOnly); executed {
		if !success || err != nil {
			// Precompiled failed — roll back any state changes it made.
			env.stateDB.RevertToSnapshot(snapshot)
		}
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return err
	}

	// Execute call
	if env.tracer != nil {
		env.tracer.CaptureEnter(DELEGATECALL, env.ctx.Address, addr, input, callGas, big.NewInt(0))
	}
	result := i.Execute(callCtx, env.stateDB)
	if env.tracer != nil {
		env.tracer.CaptureExit(result.ReturnData, result.GasUsed, result.Err)
	}

	// audit-fix R3-F11: return unused gas from sub-call to parent.
	if result.GasUsed < callGas {
		env.gas.Return(callGas - result.GasUsed)
	}

	// Handle result
	if result.Err != nil && !result.Reverted {
		// CRIT-1 FIX: Restore activeAddresses BEFORE state revert
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		env.stateDB.RevertToSnapshot(snapshot)
		env.returnData = nil
		return env.stack.PushUint64(0)
	}

	if result.Reverted {
		// CRIT-1 FIX: Restore activeAddresses on revert as well
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		env.stateDB.RevertToSnapshot(snapshot)
	}

	// Store return data
	env.returnData = result.ReturnData

	// Copy return data to memory
	if outSize > 0 && len(result.ReturnData) > 0 {
		copySize := outSize
		if uint64(len(result.ReturnData)) < copySize {
			copySize = uint64(len(result.ReturnData))
		}
		if err := env.memory.Set(outOffset, result.ReturnData[:copySize]); err != nil {
			env.activeAddresses = env.activeAddresses[:savedActiveLen]
			return err
		}
	}

	// Add logs
	// audit-fix L5-003: Only propagate logs from non-reverted sub-calls.
	// When a sub-call reverts, its state changes are rolled back, and its
	// logs should also be discarded to prevent log injection attacks where
	// a malicious contract emits fake events before reverting.
	if !result.Reverted {
		env.logs = append(env.logs, result.Logs...)
	}

	// CR40-C4 FIX: Cleanup activeAddresses on normal return path
	env.activeAddresses = env.activeAddresses[:savedActiveLen]

	// Push success/failure
	if result.Err != nil {
		return env.stack.PushUint64(0)
	}
	return env.stack.PushUint64(1)
}
