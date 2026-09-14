// Quantaureum Node source, version 1.0.0.
package precompiled

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/types"
)

var ErrOutOfGas = errors.New("out of gas")

// R30-IMPLEMENT (2026-07-27): P3-QVM-REGISTRY-RECOVER — sentinel error
// returned by Registry.Run / RunWithContext when a precompiled contract's
// Run / RunWithContext / Set* method panics. The deferred recover() converts
// the panic into an error that WRAPS errPrecompilePanic so callers can
// distinguish panic-recovery errors from normal precompile errors via
// errors.Is(err, errPrecompilePanic). Gas (requiredGas) is still charged on
// panic — EVM semantics.
var errPrecompilePanic = errors.New("precompiled contract panicked")

type PrecompiledContract interface {
	Address() types.Address
	RequiredGas(input []byte) uint64
	Run(input []byte) ([]byte, error)
}

// StatefulPrecompiledContract is an OPTIONAL interface that a precompiled
// contract may implement to declare that it modifies chain state (storage,
// balances, etc.). QVM-R10-H2 (2026-07-19): the executor uses this to reject
// calls from STATICCALL contexts, which are supposed to be read-only.
//
// Pure precompiles (sha256, ecrecover, identity, etc.) do NOT implement this
// interface — they remain callable from STATICCALL. Only state-mutating
// precompiles (e.g. MultisigPrecompiled, which creates/approves/executes
// proposals and transfers balances) implement it and return true.
//
// Default behavior: if a precompile does NOT implement this interface, it is
// considered stateless and may be called from any context.
type StatefulPrecompiledContract interface {
	// IsStateful returns true if the precompile modifies chain state.
	// The method MUST be constant-time-independent of input (it returns a
	// per-contract boolean, not per-input), so the executor can call it
	// without leaking timing information.
	IsStateful() bool
}

// ContextAwarePrecompiledContract is an OPTIONAL interface that a precompiled
// contract may implement to declare that it requires execution context
// (stateDB, block timestamp, chain ID) to be injected before each Run call.
//
// QVM-R12-002 (2026-07-20) FIX: The multisig precompile has SetStateDB /
// SetBlockTime / SetChainID methods, but the QVM executor never called them
// during normal execution — only the RPC layer did (on a separate instance).
// This meant any on-chain CALL to the multisig precompile address (0x66)
// would fail with "stateDB not set", making registerWallet / createProposal /
// approveProposal / executeProposal completely unusable from smart contracts.
//
// The executor now checks for this interface before each Run and injects
// the current execution context. Precompiles that do NOT implement this
// interface are unaffected (pure precompiles like sha256, ecrecover, etc.
// don't need context injection).
//
// CONCURRENCY NOTE: The Set methods + Run sequence is NOT atomic. In
// sequential execution (the default), this is safe because only one
// goroutine accesses the precompile at a time. In parallel execution mode
// (Block-STM, behind a flag), concurrent calls to the same precompile
// instance could race on the injected context. The multisig precompile's
// internal mutex (c.mu) serializes Run calls, but context injection should
// be done as close to Run as possible to minimize the race window.
//
// QVM-R13-HIGH-002 (2026-07-21) UPDATE: ContextAwarePrecompiledContract is
// now considered LEGACY for the executor path. Implementors SHOULD also
// implement AtomicContextPrecompiledContract (below) so the executor can
// use RunWithContext (single-lock Set+dispatch) and eliminate the TOCTOU
// race entirely. The Set methods remain available for sequential callers
// (RPC layer, tests).
type ContextAwarePrecompiledContract interface {
	SetStateDB(MultisigStateDB)
	SetBlockTime(uint64)
	SetChainID(uint64)
}

// AtomicContextPrecompiledContract is an OPTIONAL interface that a
// context-aware precompiled contract may implement to atomically inject its
// execution context AND run its dispatch logic under a SINGLE mutex
// acquisition.
//
// QVM-R13-HIGH-002 (2026-07-21) FIX: Previously, the QVM executor called
// SetStateDB / SetBlockTime / SetChainID as three separate locked operations,
// then called Run (which acquires the same lock again). In parallel execution
// mode (Block-STM behind a flag), multiple goroutines invoking the same
// precompile instance could interleave context sets between these four lock
// acquisitions — goroutine A's SetStateDB could be followed by goroutine B's
// SetStateDB, then goroutine A's Run would execute against goroutine B's
// stateDB. This TOCTOU race led to wrong balance operations, cross-transaction
// state leakage, and state root divergence between validators.
//
// Implementors MUST hold their internal mutex for the entire Set + dispatch
// sequence so that no other goroutine can observe or mutate the context
// mid-flight.
//
// The QVM executor checks for this interface first and prefers RunWithContext
// over the legacy Set + Run sequence. Precompiles that implement only
// ContextAwarePrecompiledContract (without RunWithContext) fall back to the
// legacy path, which is safe only for sequential execution.
type AtomicContextPrecompiledContract interface {
	RunWithContext(stateDB MultisigStateDB, blockTime uint64, chainID uint64, input []byte) ([]byte, error)
}

// CallKind identifies the EVM call flavor that reached a precompile. It
// lets a precompile distinguish a user CALL from a DELEGATECALL that
// forwarded caller/value, mirroring EIP-7's callKind so the precompile
// cannot be tricked by a wrapper contract impersonating the caller.
type CallKind uint8

const (
	// CallKindCall is a normal CALL (or precompile equivalent) with a
	// distinct caller and optional value transfer.
	CallKindCall CallKind = iota
	// CallKindStaticCall is a STATICCALL; state writes must be rejected.
	CallKindStaticCall
	// CallKindDelegateCall forwards the original caller and value; the
	// precompile should treat Caller as the outermost originator, not
	// the delegating contract.
	CallKindDelegateCall
	// CallKindCallCode is the legacy EIP-7 CALLCODE; rarely used but
	// enumerated for completeness.
	CallKindCallCode
)

// PrecompileContext carries the authenticated execution context a V2
// precompile needs to gate its actions on the real caller rather than on
// attacker-supplied calldata (R38-P0-01). Every field is set by the
// executor from the live ExecutionContext; precompiles can trust it.
type PrecompileContext struct {
	// Caller is the immediate invoker of the precompile (env.ctx.Caller
	// for top-level, env.ctx.Address for nested CALL/DELEGATECALL).
	Caller types.Address
	// Origin is the EOA that initiated the outermost transaction. It is
	// preserved across nested calls so a precompile cannot be tricked by
	// a wrapper contract that wants to impersonate the sender.
	Origin types.Address
	// BlockTime is the block timestamp in unix seconds.
	BlockTime uint64
	// ChainID is the current chain ID. Precompiles bind it to prevent
	// cross-chain replay of approvals.
	ChainID uint64
	// Value is the QAU amount transferred alongside the call (0 for
	// STATICCALL / DELEGATECALL with no value).
	Value *big.Int
	// CallKind identifies the call flavor (CALL/STATICCALL/DELEGATECALL).
	CallKind CallKind
}

// ContextAwarePrecompiledContractV2 is an OPTIONAL interface a precompile
// may implement to receive the authenticated PrecompileContext (R38-P0-01).
// The executor prefers RunWithContextV2 over the legacy RunWithContext so a
// V2 precompile can gate register/proposal/execute on the real caller
// instead of attacker-supplied calldata. Precompiles that do NOT implement
// this interface are unaffected and continue to use RunWithContext or the
// legacy Set+Run path.
//
// Implementors MUST hold their internal mutex for the entire dispatch so
// the atomic-context guarantee from QVM-R13-HIGH-002 is preserved under
// parallel execution.
type ContextAwarePrecompiledContractV2 interface {
	RunWithContextV2(ctx PrecompileContext, stateDB MultisigStateDB, input []byte) ([]byte, error)
}

// RunWithContextV2 dispatches to the V2 atomic context path when the
// registered precompile implements ContextAwarePrecompiledContractV2. It
// falls back to RunWithContext (legacy atomic) and then to Set+Run (legacy
// sequential) so the addition is fully backward-compatible with every
// existing precompile (sha256, ecrecover, dilithiumVerify, kyberKEM, and
// the legacy multisig).
//
// Gas accounting is identical to RunWithContext: requiredGas is charged
// regardless of success/failure (EVM semantics), and gasUsed == requiredGas.
// A panic in any path is converted into errPrecompilePanic (defense in
// depth, R30-IMPLEMENT).
func (r *Registry) RunWithContextV2(ctx PrecompileContext, addr types.Address, stateDB MultisigStateDB, input []byte, gas uint64) ([]byte, uint64, error) {
	c := r.contracts[addr]
	if c == nil {
		return nil, gas, nil
	}

	requiredGas := c.RequiredGas(input)
	if gas < requiredGas {
		return nil, gas, ErrOutOfGas
	}

	var output []byte
	var err error
	func() {
		defer func() {
			if recv := recover(); recv != nil {
				err = fmt.Errorf("%w: %v", errPrecompilePanic, recv)
				output = nil
			}
		}()

		// R38-P0-01: prefer the V2 atomic path so the precompile receives
		// the authenticated caller/origin and can bind register/proposal/
		// execute to the real invoker.
		if v2, ok := c.(ContextAwarePrecompiledContractV2); ok {
			output, err = v2.RunWithContextV2(ctx, stateDB, input)
			return
		}

		// Legacy atomic path: caller-unaware context. Used by the legacy
		// multisig (0x66) and any precompile that has not migrated to V2.
		if atomic, ok := c.(AtomicContextPrecompiledContract); ok {
			output, err = atomic.RunWithContext(stateDB, ctx.BlockTime, ctx.ChainID, input)
			return
		}

		// Legacy sequential fallback: separate Set + Run. Pure precompiles
		// (sha256, ecrecover, etc.) hit this branch unchanged.
		if ca, ok := c.(ContextAwarePrecompiledContract); ok {
			ca.SetStateDB(stateDB)
			ca.SetBlockTime(ctx.BlockTime)
			ca.SetChainID(ctx.ChainID)
		}
		output, err = c.Run(input)
	}()

	return output, requiredGas, err
}

// BatchableContract is the interface for precompiled contracts supporting batch calls
// when multiple precompile calls can be merged, call overhead is reduced
type BatchableContract interface {
	PrecompiledContract
	// BatchRun executes multiple inputs in one batch, returning the corresponding results
	// implementers may share common computation (e.g. reusing the KECCAK256 hasher)
	BatchRun(inputs [][]byte) ([][]byte, error)
}

type Registry struct {
	contracts map[types.Address]PrecompiledContract
}

func NewRegistry() *Registry {
	r := &Registry{
		contracts: make(map[types.Address]PrecompiledContract),
	}
	r.registerStandard()
	return r
}

func (r *Registry) registerStandard() {
	r.Register(newECRecover())
	r.Register(newSHA256())
	r.Register(newRIPEMD160())
	r.Register(newIdentity())
	r.Register(newModExp())
	r.Register(newBN256Add())
	r.Register(newBN256ScalarMul())
	r.Register(newBN256Pairing())
	r.Register(newBlake2F())
	r.Register(newKZGPointEvaluation()) // EIP-4844 KZG point evaluation at 0x0A
	r.Register(newDilithiumVerify())
	r.Register(newKyberKEM())
	r.Register(newMultisigPrecompiled())
	r.Register(newMultisigV2Precompiled())
}

func (r *Registry) Register(c PrecompiledContract) {
	r.contracts[c.Address()] = c
}

func (r *Registry) Get(addr types.Address) PrecompiledContract {
	return r.contracts[addr]
}

func (r *Registry) IsPrecompiled(addr types.Address) bool {
	_, ok := r.contracts[addr]
	return ok
}

func (r *Registry) Run(addr types.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	c := r.contracts[addr]
	if c == nil {
		return nil, gas, nil
	}

	requiredGas := c.RequiredGas(input)
	if gas < requiredGas {
		return nil, gas, ErrOutOfGas
	}

	// R30-IMPLEMENT (2026-07-27): P3-QVM-REGISTRY-RECOVER — defense-in-depth
	// defer recover(). A panicking precompile would crash the caller (e.g.
	// the QVM executor goroutine or a BatchRunParallel worker goroutine, which
	// had no outer recover). Convert the panic into an error wrapping
	// errPrecompilePanic so callers can distinguish panic-recovery errors from
	// normal precompile errors. Gas (requiredGas) is still charged — EVM
	// semantics: requiredGas is charged regardless of success/failure.
	var output []byte
	var err error
	func() {
		defer func() {
			if recv := recover(); recv != nil {
				err = fmt.Errorf("%w: %v", errPrecompilePanic, recv)
				output = nil
			}
		}()
		output, err = c.Run(input)
	}()

	return output, requiredGas, err
}

// RunWithContext executes a precompiled contract with atomic context injection.
//
// QVM-R13-HIGH-002 (2026-07-21) FIX: If the precompile implements
// AtomicContextPrecompiledContract, this method uses RunWithContext (single
// lock for Set+dispatch), eliminating the TOCTOU race between the separate
// Set methods and Run that existed in the legacy injectPrecompileContext +
// Registry.Run sequence.
//
// If the precompile does NOT implement the atomic interface, this method
// falls back to the legacy sequence (inject + Run). The fallback is only
// safe for sequential execution; pure precompiles (sha256, ecrecover, etc.)
// do not implement either context interface and are unaffected.
//
// Gas accounting is identical to Registry.Run: requiredGas is charged
// regardless of success/failure (EVM semantics), and gasUsed == requiredGas.
// Callers are responsible for refunding (callGas - gasUsed) on failure.
//
// The stateDB parameter is the caller's raw stateDB interface; this method
// does NOT wrap it in any adapter. The QVM executor passes a
// qvmStateDBAdapter-wrapped stateDB because the precompile expects the
// precompiled.MultisigStateDB interface. We accept the raw interface here
// and let the caller handle adaptation, so this Registry method stays
// independent of the QVM package (no import cycle).
func (r *Registry) RunWithContext(addr types.Address, stateDB MultisigStateDB, blockTime uint64, chainID uint64, input []byte, gas uint64) ([]byte, uint64, error) {
	c := r.contracts[addr]
	if c == nil {
		return nil, gas, nil
	}

	requiredGas := c.RequiredGas(input)
	if gas < requiredGas {
		return nil, gas, ErrOutOfGas
	}

	// R30-IMPLEMENT (2026-07-27): P3-QVM-REGISTRY-RECOVER — defense-in-depth
	// defer recover() covering BOTH the atomic RunWithContext path AND the
	// legacy Set + Run path. A panic in RunWithContext, SetStateDB,
	// SetBlockTime, SetChainID, or Run is converted into an error wrapping
	// errPrecompilePanic. Gas (requiredGas) is still charged — EVM semantics.
	var output []byte
	var err error
	func() {
		defer func() {
			if recv := recover(); recv != nil {
				err = fmt.Errorf("%w: %v", errPrecompilePanic, recv)
				output = nil
			}
		}()

		// Prefer the atomic Set+dispatch path when available.
		if atomic, ok := c.(AtomicContextPrecompiledContract); ok {
			output, err = atomic.RunWithContext(stateDB, blockTime, chainID, input)
			return
		}

		// Legacy fallback: separate Set + Run. Only safe for sequential execution.
		if ca, ok := c.(ContextAwarePrecompiledContract); ok {
			ca.SetStateDB(stateDB)
			ca.SetBlockTime(blockTime)
			ca.SetChainID(chainID)
		}
		output, err = c.Run(input)
	}()

	return output, requiredGas, err
}

// BatchCall invokes the same precompiled contract in batch
// when several inputs target the same address, they merge into one batch call to cut overhead
//
// QVM-R13-MED-001 (2026-07-21) FIX: Previously this method called c.Run(input)
// directly WITHOUT injecting execution context (stateDB / blockTime / chainID).
// Although BatchCall is currently unused (dead code) and therefore not
// exploitable today, the same pattern in the QVM executor's main Run path
// caused QVM-R12-002: on-chain CALL to the multisig precompile at 0x66 would
// panic with "stateDB not set". If BatchCall is ever wired into a future
// executor path, the missing context injection would reintroduce that bug.
//
// Fix: add stateDB / blockTime / chainID parameters and route each per-input
// dispatch through the same RunWithContext path used by the executor:
//   - AtomicContextPrecompiledContract → single-lock Set+dispatch
//   - ContextAwarePrecompiledContract → legacy Set + Run (sequential only)
//   - Pure precompiles (no context interface) → direct Run
//
// Gas accounting is unchanged: requiredGas is charged per input, summed
// with overflow protection, and the total is returned as gasUsed regardless
// of per-input success/failure (EVM semantics).
func (r *Registry) BatchCall(addr types.Address, stateDB MultisigStateDB, blockTime uint64, chainID uint64, inputs [][]byte, gas uint64) ([][]byte, uint64, error) {
	c := r.contracts[addr]
	if c == nil {
		return nil, gas, nil
	}

	// compute total gas
	// HIGH-2 (R8 2026-07-19 FIX): Inline overflow check to avoid importing
	// parent qvm package (would create import cycle: qvm -> precompiled).
	// Without overflow check, an attacker could craft inputs whose total
	// RequiredGas wraps around to a small number, passing the `gas < totalGas`
	// check while actual execution consumes near-MaxUint64 gas — a free-run
	// attack vector. geth has had similar overflow bugs historically.
	totalGas := uint64(0)
	for _, input := range inputs {
		required := c.RequiredGas(input)
		// Overflow check: a + b > MaxUint64 iff a > MaxUint64 - b.
		if totalGas > math.MaxUint64-required {
			return nil, gas, ErrOutOfGas
		}
		totalGas += required
	}
	if gas < totalGas {
		return nil, gas, ErrOutOfGas
	}

	// if the contract supports the batch interface, use the batch call.
	// NOTE: BatchableContract is implemented by pure-function precompiles
	// (currently only keccak256Precompiled), which do not implement ContextAware,
	// so BatchRun needs no context injection. If a stateful batched precompile
	// appears later, it must handle context inside BatchRun itself, and this call site
	// should reject it via type assertion rather than silently dropping the context.
	if batchable, ok := c.(BatchableContract); ok {
		// Defense-in-depth: stateful BatchableContract must not silently
		// bypass context injection. It should implement RunWithContext and
		// be handled by the per-input loop below, not the batch fast-path.
		if _, stateful := c.(StatefulPrecompiledContract); !stateful {
			results, err := batchable.BatchRun(inputs)
			return results, totalGas, err
		}
		// Fall through to per-input dispatch with context injection.
	}

	// no batch interface (or a stateful batched contract) — execute one by one with context injection
	results := make([][]byte, len(inputs))
	for i, input := range inputs {
		output, _, err := r.runOneWithContext(c, stateDB, blockTime, chainID, input)
		if err != nil {
			return nil, totalGas, err
		}
		results[i] = output
	}
	return results, totalGas, nil
}

// BatchRunParallel executes several precompiled contracts at different addresses in parallel
// when a batch of txs touches different precompiles, they can run in parallel to reduce latency
//
// QVM-R13-MED-001 (2026-07-21) FIX: Previously this method called r.Run(addr,
// input, gas) WITHOUT injecting execution context. The same fix as BatchCall
// applies: add stateDB / blockTime / chainID parameters and route each
// per-call dispatch through RunWithContext.
//
// CONCURRENCY NOTE: Each goroutine calls runOneWithContext independently. The
// AtomicContextPrecompiledContract path holds the precompile's internal mutex
// for the Set+dispatch sequence, so concurrent goroutines invoking the SAME
// precompile address are serialized correctly. The legacy
// ContextAwarePrecompiledContract path (Set+Run) is NOT safe for concurrent
// invocation of the same instance — callers must ensure that no two parallel
// calls in `calls` target the same address when the precompile only
// implements the legacy interface. Pure precompiles (sha256, ecrecover,
// keccak256, etc.) have no per-instance state and are safe.
func (r *Registry) BatchRunParallel(calls []struct {
	Addr  types.Address
	Input []byte
	Gas   uint64
}, stateDB MultisigStateDB, blockTime uint64, chainID uint64) []struct {
	Output  []byte
	GasUsed uint64
	Err     error
} {
	results := make([]struct {
		Output  []byte
		GasUsed uint64
		Err     error
	}, len(calls))

	// R35-P2-PRECOMPILE-03 FIX (2026-07-29): Previously ALL calls were
	// launched as goroutines, including calls to legacy
	// ContextAwarePrecompiledContract instances. The legacy interface uses
	// Set+Run (two separate calls), so two goroutines targeting the same
	// instance could interleave SetStateDB→Run→SetStateDB→Run, causing one
	// goroutine to execute against the wrong stateDB (TOCTOU). The code
	// comment acknowledged this but did not enforce it.
	//
	// Fix: partition calls into "safe for parallel" (pure + AtomicContext)
	// and "must be sequential" (legacy ContextAware). Parallel-safe calls
	// run as goroutines; legacy calls run sequentially after the parallel
	// batch completes. This eliminates the TOCTOU without requiring callers
	// to know which precompiles are legacy.
	var parallelIdx, sequentialIdx []int
	for i, call := range calls {
		c := r.contracts[call.Addr]
		if c == nil {
			// Unknown contract — will error in RunWithContext, run in parallel.
			parallelIdx = append(parallelIdx, i)
			continue
		}
		if _, isAtomic := c.(AtomicContextPrecompiledContract); isAtomic {
			parallelIdx = append(parallelIdx, i)
			continue
		}
		if _, isContextAware := c.(ContextAwarePrecompiledContract); isContextAware {
			// Legacy ContextAware — NOT safe for concurrent invocation.
			sequentialIdx = append(sequentialIdx, i)
			continue
		}
		// Pure precompile (no context interface) — safe for parallel.
		parallelIdx = append(parallelIdx, i)
	}

	// Run parallel-safe calls as goroutines.
	var wg sync.WaitGroup
	for _, idx := range parallelIdx {
		call := calls[idx]
		wg.Add(1)
		go func(idx int, addr types.Address, input []byte, gas uint64) {
			defer wg.Done()
			output, gasUsed, err := r.RunWithContext(addr, stateDB, blockTime, chainID, input, gas)
			results[idx].Output = output
			results[idx].GasUsed = gasUsed
			results[idx].Err = err
		}(idx, call.Addr, call.Input, call.Gas)
	}
	wg.Wait()

	// Run legacy ContextAware calls SEQUENTIALLY to prevent TOCTOU.
	for _, idx := range sequentialIdx {
		call := calls[idx]
		output, gasUsed, err := r.RunWithContext(call.Addr, stateDB, blockTime, chainID, call.Input, call.Gas)
		results[idx].Output = output
		results[idx].GasUsed = gasUsed
		results[idx].Err = err
	}

	return results
}

// runOneWithContext dispatches a single input to a precompiled contract with
// context injection, mirroring the RunWithContext path but on an already-
// resolved contract instance (saves a map lookup in BatchCall's per-input
// loop). The gas accounting is the caller's responsibility — this helper
// charges no gas.
func (r *Registry) runOneWithContext(c PrecompiledContract, stateDB MultisigStateDB, blockTime uint64, chainID uint64, input []byte) ([]byte, uint64, error) {
	if atomic, ok := c.(AtomicContextPrecompiledContract); ok {
		output, err := atomic.RunWithContext(stateDB, blockTime, chainID, input)
		return output, 0, err
	}
	if ca, ok := c.(ContextAwarePrecompiledContract); ok {
		ca.SetStateDB(stateDB)
		ca.SetBlockTime(blockTime)
		ca.SetChainID(chainID)
	}
	output, err := c.Run(input)
	return output, 0, err
}
