// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/qvm/precompiled"
	"github.com/quantaureum/qau/types"
)

// qvmStateDBAdapter adapts a qvm.StateDB to the precompiled.MultisigStateDB
// interface. This allows the multisig precompile (and any other context-aware
// precompile) to read/write chain state during QVM execution.
//
// QVM-R12-002 (2026-07-20) FIX: Previously, the multisig precompile's
// SetStateDB was only called from the RPC layer (rpc/multisig_api.go), which
// used a separate precompile instance. The QVM executor's shared registry
// instance never had its stateDB injected, so any on-chain CALL to the
// multisig address (0x66) failed with "stateDB not set".
//
// The adapter converts between qvm.Address/qvm.Hash (local [20]/[32]byte
// arrays) and types.Address/types.Hash (the canonical types used by the
// precompiled package). These are structurally identical but distinct types
// in Go's type system, so conversion requires a copy.
//
// SubBalance/AddBalance are implemented via GetBalance + SetBalance because
// the qvm.StateDB interface does not have native Sub/Add balance methods
// (unlike the RPC layer's ChainStateDB). The implementation includes
// underflow protection: SubBalance returns an error if the current balance
// is less than the requested amount, preventing negative balances.
type qvmStateDBAdapter struct {
	db StateDB
}

// compile-time assertion that qvmStateDBAdapter implements MultisigStateDB
var _ precompiled.MultisigStateDB = (*qvmStateDBAdapter)(nil)

func (a *qvmStateDBAdapter) GetState(addr types.Address, key types.Hash) types.Hash {
	var qAddr Address
	copy(qAddr[:], addr[:])
	var qKey Hash
	copy(qKey[:], key[:])
	val := a.db.GetState(qAddr, qKey)
	var tVal types.Hash
	copy(tVal[:], val[:])
	return tVal
}

func (a *qvmStateDBAdapter) SetState(addr types.Address, key, value types.Hash) {
	var qAddr Address
	copy(qAddr[:], addr[:])
	var qKey, qVal Hash
	copy(qKey[:], key[:])
	copy(qVal[:], value[:])
	a.db.SetState(qAddr, qKey, qVal)
}

func (a *qvmStateDBAdapter) GetBalance(addr types.Address) *big.Int {
	var qAddr Address
	copy(qAddr[:], addr[:])
	return new(big.Int).Set(a.db.GetBalance(qAddr))
}

func (a *qvmStateDBAdapter) SubBalance(addr types.Address, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return nil
	}
	var qAddr Address
	copy(qAddr[:], addr[:])
	bal := a.db.GetBalance(qAddr)
	if bal.Cmp(amount) < 0 {
		return fmt.Errorf("multisig: insufficient balance for SubBalance: have %s, need %s", bal.String(), amount.String())
	}
	a.db.SetBalance(qAddr, new(big.Int).Sub(bal, amount))
	return nil
}

func (a *qvmStateDBAdapter) AddBalance(addr types.Address, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return nil
	}
	var qAddr Address
	copy(qAddr[:], addr[:])
	bal := a.db.GetBalance(qAddr)
	a.db.SetBalance(qAddr, new(big.Int).Add(bal, amount))
	return nil
}

// Snapshot returns a snapshot ID that can be used to revert the state DB to
// the point at which Snapshot was called. Delegates to the underlying qvm
// StateDB.
//
// R14-LOW (QVM audit): Previously the adapter did not expose
// Snapshot/RevertToSnapshot, so a context-aware precompile that wanted to
// do its own internal partial snapshot/revert (independent of the
// executor's call-level snapshot) had no way to do so. The executor and
// interpreter already take a snapshot before invoking a precompile and
// revert on error (executor.go:581/605, call.go:446/482), so this is a
// defense-in-depth capability for precompiles that need finer-grained
// rollback control.
//
// Precompiles access this via the optional SnapshotableStateDB interface:
//
//	if ss, ok := c.stateDB.(interface{ Snapshot() int; RevertToSnapshot(int) }); ok {
//	    snap := ss.Snapshot()
//	    defer ss.RevertToSnapshot(snap) // or call explicitly on error
//	}
func (a *qvmStateDBAdapter) Snapshot() int {
	return a.db.Snapshot()
}

// RevertToSnapshot reverts the state DB to the snapshot identified by id.
// Delegates to the underlying qvm StateDB. See Snapshot for rationale.
func (a *qvmStateDBAdapter) RevertToSnapshot(id int) {
	a.db.RevertToSnapshot(id)
}

// injectPrecompileContext injects the execution context (stateDB, block
// timestamp, chain ID) into a context-aware precompiled contract before Run.
//
// QVM-R12-002 (2026-07-20) FIX: This is called by the QVM executor (opCall,
// opStaticCall, opDelegateCall, Executor.Call, Executor.StaticCall) right
// before invoking a precompile's Run method. Precompiles that implement
// ContextAwarePrecompiledContract get the current execution context; those
// that don't (pure precompiles like sha256, ecrecover, identity) are
// unaffected.
//
// QVM-R13-HIGH-002 (2026-07-21) UPDATE: This function is now considered
// LEGACY for the executor path. It performs three SEPARATE locked Set
// operations, then Run performs a fourth locked operation — creating a TOCTOU
// race window in parallel execution mode. The executor now prefers
// executePrecompiledAtomic (which uses Registry.RunWithContext →
// AtomicContextPrecompiledContract.RunWithContext, single-lock Set+dispatch).
// This function is retained for backward compatibility and for callers that
// need to inject context without immediately running (e.g. tests, RPC layer
// initialization).
//
// CONCURRENCY: See the note on ContextAwarePrecompiledContract. The Set
// methods acquire the precompile's internal mutex, and Run also acquires it.
// In sequential execution, the Set→Run sequence is safe. In parallel mode,
// callers should ensure no two goroutines invoke the same precompile
// instance concurrently (the multisig precompile is rarely called in
// parallel since it's an administrative operation).
//
// blockTime is int64 (matching ExecutionContext.Timestamp / BlockContext.Timestamp)
// and is converted to uint64 for the precompile's SetBlockTime. Block
// timestamps are unix seconds and always non-negative; negative values are
// clamped to 0 as a defensive measure.
func injectPrecompileContext(pc precompiled.PrecompiledContract, stateDB StateDB, blockTime int64, chainID uint64) {
	if ca, ok := pc.(precompiled.ContextAwarePrecompiledContract); ok {
		ca.SetStateDB(&qvmStateDBAdapter{db: stateDB})
		var bt uint64
		if blockTime > 0 {
			bt = uint64(blockTime)
		}
		ca.SetBlockTime(bt)
		ca.SetChainID(chainID)
	}
}

// executePrecompiledAtomic executes a precompiled contract via the atomic
// Set+dispatch path, eliminating the TOCTOU race between inject and Run.
//
// QVM-R13-HIGH-002 (2026-07-21) FIX: Replaces the legacy
// injectPrecompileContext + Registry.Run two-step sequence. If the precompile
// implements AtomicContextPrecompiledContract, this helper calls
// RunWithContext (single-lock Set+dispatch). Otherwise it falls back to
// injectPrecompileContext + Run, which is only safe for sequential execution.
//
// Returns (output, gasUsed, err). gasUsed is the precompile's RequiredGas
// (charged regardless of success/failure, EVM semantics). Callers are
// responsible for refunding (callGas - gasUsed) on failure.
//
// blockTime is int64 (matching ExecutionContext.Timestamp / BlockContext.Timestamp)
// and is converted to uint64 for the precompile's SetBlockTime. Block
// timestamps are unix seconds and always non-negative; negative values are
// clamped to 0 as a defensive measure.
func executePrecompiledAtomic(reg *precompiled.Registry, addr types.Address, stateDB StateDB, blockTime int64, chainID uint64, input []byte, callGas uint64) ([]byte, uint64, error) {
	var bt uint64
	if blockTime > 0 {
		bt = uint64(blockTime)
	}
	// Registry.RunWithContext handles both the atomic path (preferred) and
	// the legacy inject+Run fallback (for precompiles that don't implement
	// AtomicContextPrecompiledContract).
	return reg.RunWithContext(addr, &qvmStateDBAdapter{db: stateDB}, bt, chainID, input, callGas)
}

// executePrecompiledAtomicV2 is the R38-P0-01 caller-aware dispatch path.
// It builds a precompiled.PrecompileContext from the authenticated
// ExecutionContext and routes the call through Registry.RunWithContextV2,
// which prefers a V2 precompile's RunWithContextV2 (so the precompile can
// gate register/proposal/execute on the real caller) and falls back to the
// legacy atomic / sequential paths otherwise. The fallback keeps every
// existing precompile (sha256, ecrecover, dilithiumVerify, kyberKEM, legacy
// multisig) functioning without modification.
//
// caller is the immediate invoker of the precompile (the executor's `caller`
// param for top-level Call; env.ctx.Address for a nested call). origin is
// the outermost EOA (preserved across nested calls). value is the call
// value. isStatic reports whether the frame is a STATICALL.
func executePrecompiledAtomicV2(reg *precompiled.Registry, addr types.Address, stateDB StateDB,
	caller, origin types.Address, value *big.Int, blockTime int64, chainID uint64,
	isStatic bool, input []byte, callGas uint64) ([]byte, uint64, error) {

	var bt uint64
	if blockTime > 0 {
		bt = uint64(blockTime)
	}

	kind := precompiled.CallKindCall
	if isStatic {
		kind = precompiled.CallKindStaticCall
	}

	ctx := precompiled.PrecompileContext{
		Caller:    caller,
		Origin:    origin,
		BlockTime: bt,
		ChainID:   chainID,
		Value:     value,
		CallKind:  kind,
	}
	return reg.RunWithContextV2(ctx, addr, &qvmStateDBAdapter{db: stateDB}, input, callGas)
}
