// Quantaureum Node source, version 1.0.0.
// Package parallel implements Block-STM parallel transaction execution.
package parallel

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// ParallelQVM implements parallel execution of smart contract calls.
// It uses dependency analysis to identify independent calls that can
// be executed in parallel while maintaining sequential consistency.
type ParallelQVM struct {
	config    *ParallelQVMConfig
	scheduler *ContractScheduler
	mvMemory  *MVMemory
	baseState StateDB

	// Results storage
	results   []*ContractExecutionResult
	resultsMu sync.Mutex

	// Worker coordination
	wg       sync.WaitGroup
	stopCh   chan struct{}
	doneCh   chan struct{}
	doneOnce sync.Once

	// Execution statistics
	totalExecutions int64
	totalConflicts  int64

	// Retry tracking
	retryQueue   []int
	retryQueueMu sync.Mutex
	incarnations []int32 // Incarnation counter for each transaction

	// Metrics reporter
	metricsReporter STMMetricsReporter

	// SECURITY FIX H-2: coinbase address for block context.
	// Previously the coinbase variable in executeCall was declared but never
	// assigned, remaining as the zero value. This caused the block context
	// coinbase (used for block reward attribution and COINBASE opcode) to be
	// an all-zero address. SetCoinbase allows callers to provide the actual
	// block proposer address before executing calls.
	coinbase types.Address

	// AUDIT (2026) QVM-03: Block context fields for TIMESTAMP/NUMBER
	// opcodes. Previously, executeCall hardcoded BlockNumber=0 and Timestamp=0,
	// causing consensus divergence if the parallel executor is used on the
	// consensus path (contracts reading TIMESTAMP/NUMBER would get 0 instead
	// of the actual block values).
	blockNumber uint64
	timestamp   int64

	// AUDIT (2026) QVM B-5 FIX: Gas price for execution context.
	// Previously executeCall hardcoded GasPrice=1 wei, causing incorrect gas
	// accounting and consensus divergence with the sequential executor.
	// SetGasPrice allows callers to provide the actual transaction/block gas
	// price before executing calls. Defaults to 1 wei only when unset.
	gasPrice *big.Int

	// AUDIT (2026) R4-QVFIX: consensus-safe guard.
	// ParallelQVM.Execute is NOT consensus-safe on its own — it skips nonce
	// increment, intrinsic gas charging, and (historically) block context
	// setup. The higher-level ParallelExecutor wraps Execute and adds these
	// checks. This flag prevents direct use of Execute on the consensus path.
	// Defaults to false — callers must explicitly call EnableConsensusMode()
	// (after implementing the missing checks) or use ParallelExecutor instead.
	consensusSafe bool
}

// NewParallelQVM creates a new parallel QVM executor.
func NewParallelQVM(config *ParallelQVMConfig) *ParallelQVM {
	if config == nil {
		config = DefaultParallelQVMConfig()
	}
	if config.NumWorkers <= 0 {
		config.NumWorkers = runtime.NumCPU()
	}

	return &ParallelQVM{
		config:       config,
		mvMemory:     NewMVMemory(),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
		retryQueue:   make([]int, 0),
		incarnations: make([]int32, 0),
	}
}

// EnableConsensusMode explicitly opts in to using ParallelQVM.Execute directly.
// AUDIT (2026) R4-QVM-01: ParallelQVM.Execute is NOT consensus-safe on
// its own. Before calling this method, the caller MUST ensure that:
//  1. The caller's nonce is incremented for each transaction (Execute does
//     NOT do this — see executor.go:341 for the correct pattern).
//  2. Intrinsic gas (21000 + calldata cost) is charged before execution
//     (Execute does NOT do this — see ParallelExecutor.intrinsicGas).
//  3. Block context (SetBlockContext/SetCoinbase/SetGasPrice) is set to
//     match the sequential executor.
//
// In production, prefer ParallelExecutor (qvm/parallel/executor.go) which
// wraps Execute and adds these checks automatically. This method is intended
// for tests or for callers who have implemented the checks in their own
// wrapper layer.
func (pq *ParallelQVM) EnableConsensusMode() {
	pq.consensusSafe = true
}

// Execute executes a batch of contract calls in parallel using Block-STM with optimistic concurrency control.
// Returns results in the same order as the input calls.
//
// AUDIT (2026) R4-QVFIX: Execute is guarded by the consensusSafe flag.
// ParallelQVM.Execute is NOT consensus-safe on its own — it does not increment
// the caller's nonce, does not charge intrinsic gas, and relies on the caller
// to set block context. The higher-level ParallelExecutor wraps Execute and
// adds these missing checks. Production code should use ParallelExecutor, not
// ParallelQVM.Execute directly. To use Execute directly (e.g., in tests or
// after implementing the missing checks), call EnableConsensusMode() first.
func (pq *ParallelQVM) Execute(calls []*ContractCall, state StateDB) ([]*ContractExecutionResult, error) {
	if len(calls) == 0 {
		return []*ContractExecutionResult{}, nil
	}

	// AUDIT (2026) R4-QVM-01: Refuse to execute unless explicitly enabled.
	// This prevents accidental wiring of ParallelQVM.Execute into the consensus
	// path (which would cause nonce/intrinsic-gas divergence vs. the sequential
	// executor). The guard is opt-in: callers who understand the risks can call
	// EnableConsensusMode() to bypass.
	if !pq.consensusSafe {
		return nil, ErrParallelQVMNotConsensusSafe
	}

	// L6-007 FIX: Runtime validation - reject execution when ChainID is unset (0).
	// DefaultParallelQVMConfig returns ChainID=0 to force explicit configuration;
	// running with ChainID=0 would disable EIP-155 cross-chain replay protection.
	if pq.config == nil || pq.config.ChainID == 0 {
		return nil, ErrChainIDNotSet
	}

	// AUDIT (2026) QVM B-1 FIX: Warn if block context was not set.
	// Without SetBlockContext/SetCoinbase, TIMESTAMP/NUMBER/COINBASE opcodes
	// return 0, causing consensus divergence with the sequential executor.
	if pq.blockNumber == 0 && pq.timestamp == 0 {
		log.Printf("[WARN] ParallelQVM.Execute: block context not set (SetBlockContext not called) — TIMESTAMP/NUMBER/COINBASE will be 0 (QVM B-1)")
	}

	// Initialize execution state
	pq.baseState = state
	pq.mvMemory.Clear()
	pq.stopCh = make(chan struct{})
	pq.doneCh = make(chan struct{})
	pq.doneOnce = sync.Once{}
	pq.retryQueue = make([]int, 0)
	pq.incarnations = make([]int32, len(calls))

	// For single call, execute directly
	if len(calls) == 1 {
		result := pq.executeCall(0, calls[0], state)
		// QVM-FIX: Single-call fast path previously applied StateChanges
		// directly without going through validateResults, skipping the
		// incarnation-consistency check that the multi-call path performs.
		// While a single call has no cross-tx conflicts, the executeCall
		// panic-recovery branch may still leave stale writes in mvMemory
		// (the wrapper's RevertToSnapshot calls mvMemory.DeleteVersion, but
		// this is a defensive second sweep on the failure path). Without
		// this, a panic in executeCall could leave mvMemory entries that
		// survive Clear() and bleed into subsequent Execute batches.
		if result != nil && !result.Success {
			incarnation := 0
			if len(pq.incarnations) > 0 {
				incarnation = int(atomic.LoadInt32(&pq.incarnations[0]))
			}
			pq.mvMemory.DeleteVersion(0, incarnation)
		}
		// AUDIT (2026) QVM B-2 FIX: Apply state changes from the single-call
		// fast path. Previously, the result's StateChanges were computed but never
		// applied to the underlying state — the multi-call path calls
		// applyStateChanges(MergeResults(...)) at line 181, but this fast path
		// skipped that, silently discarding all writes (transfers, SSTORE, etc.).
		if result != nil && result.Success && result.StateChanges != nil {
			pq.applyStateChanges(result.StateChanges)
		}
		return []*ContractExecutionResult{result}, nil
	}

	// Initialize results array
	results := make([]*ContractExecutionResult, len(calls))

	// Retry loop for optimistic execution
	retryCount := 0
	success := false

	for retryCount < pq.config.MaxRetries && !success {
		// Reset state for this retry
		pq.mvMemory.Clear()
		pq.results = make([]*ContractExecutionResult, len(calls))
		// SECURITY FIX: Clear retry queue to prevent unbounded memory growth
		// Previously retryQueue was populated but never cleared, causing memory leak
		pq.retryQueueMu.Lock()
		pq.retryQueue = pq.retryQueue[:0]
		pq.retryQueueMu.Unlock()
		atomic.AddInt64(&pq.totalConflicts, 1)

		// Create new scheduler for this retry
		pq.scheduler = NewContractScheduler(calls)

		// Analyze dependencies if speculative execution is disabled
		if !pq.config.EnableSpeculativeExecution {
			pq.scheduler.AnalyzeDependencies()
		}

		// Start scheduler
		pq.scheduler.Start()

		// Start worker goroutines
		numWorkers := pq.config.NumWorkers
		if numWorkers > len(calls) {
			numWorkers = len(calls)
		}

		pq.wg = sync.WaitGroup{}
		for i := 0; i < numWorkers; i++ {
			pq.wg.Add(1)
			go pq.worker(calls)
		}

		// Wait for completion
		done := make(chan struct{})
		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "Parallel QVM WaitGroup goroutine panic: %v\n", r)
				}
				close(done)
			}()
			pq.wg.Wait()
		}()

		select {
		case <-done:
			// All calls executed
			retryCount++

			// Merge results and check for conflicts
			finalChanges, err := pq.MergeResults(pq.results)
			if err != nil {
				continue
			}

			// Validate results for conflicts
			if pq.validateResults() {
				// No conflicts, merge and return
				results = pq.results
				pq.applyStateChanges(finalChanges)
				success = true
			}
		case <-pq.stopCh:
			// Execution stopped
			return nil, errors.New("execution stopped")
		}
	}

	if !success {
		// All retries failed, fall back to sequential execution
		pq.recordMetrics(len(calls), int(atomic.LoadInt64(&pq.totalConflicts)), retryCount, true, 1.0)
		return pq.executeSequentially(calls, state), nil
	}

	pq.recordMetrics(len(calls), int(atomic.LoadInt64(&pq.totalConflicts)), retryCount, false, float64(len(calls))/float64(retryCount+1))
	return results, nil
}

func (pq *ParallelQVM) recordMetrics(batchSize, conflicts, retries int, sequentialFallback bool, speedup float64) {
	if pq.metricsReporter != nil {
		pq.metricsReporter.RecordSTMExecution(batchSize, conflicts, retries, sequentialFallback, speedup)
	}
}

// executeSequentially executes calls sequentially as a fallback.
func (pq *ParallelQVM) executeSequentially(calls []*ContractCall, state StateDB) []*ContractExecutionResult {
	results := make([]*ContractExecutionResult, len(calls))
	// Apply each call's changes immediately to maintain state
	for i, call := range calls {
		result := pq.executeCall(i, call, state)
		results[i] = result
		if result.Success {
			// Apply changes immediately for sequential execution
			pq.applyStateChanges(result.StateChanges)
		}
	}
	return results
}

// validateResults checks if execution results are consistent.
// In Block-STM, this validates that all reads are still valid against current writes.
//
// Validation Algorithm:
//  1. Check for execution failures - any failed transaction invalidates the batch
//  2. Build final write set - map each (address, key) to the Version of the last transaction that wrote to it
//  3. Validate read sets - for each transaction's reads, verify that:
//     a. The incarnation matches (handles retry scenarios)
//     b. The TxIndex matches (read saw the correct writer)
//     c. The Value matches (CRIT-2 FIX: prevents malicious validator attacks)
//
// This ensures serializability: parallel execution produces the same result as sequential execution.
func (pq *ParallelQVM) validateResults() bool {
	pq.resultsMu.Lock()
	defer pq.resultsMu.Unlock()

	// Check for any failed executions
	for _, result := range pq.results {
		if result != nil && !result.Success {
			return false
		}
	}

	// Build final write set: map[addr][key] -> Version of last writer
	// CRIT-2 FIX: Now stores full Version including Value for comparison
	finalWrites := make(map[types.Address]map[types.Hash]Version)

	for txIdx, result := range pq.results {
		if result == nil || !result.Success {
			continue
		}

		// FIX: Skip results from stale incarnations. When a transaction
		// is retried, its incarnation increments and a new result overwrites the
		// old one. However, if validation runs before the retry completes, the
		// old result (from a previous incarnation) may still be present. Its
		// writes must not be included in the final write set.
		if txIdx < len(pq.incarnations) && result.Incarnation != int(pq.incarnations[txIdx]) {
			continue
		}

		// Record all writes from this transaction with their versions
		for addr, keys := range result.WriteSet {
			if finalWrites[addr] == nil {
				finalWrites[addr] = make(map[types.Hash]Version)
			}
			for key, value := range keys {
				// CRIT-2 FIX: Store Version with Value for comparison
				finalWrites[addr][key] = Version{
					TxIndex:     txIdx,
					Incarnation: int(pq.incarnations[txIdx]),
					Value:       value,
				}
			}
		}
	}

	// Validate read sets against final write set
	for txIdx, result := range pq.results {
		if result == nil || !result.Success {
			continue
		}

		// FIX: Skip results from stale incarnations. A result from an
		// aborted incarnation has invalid read sets that must not be validated
		// against the current state, as the reads were from a discarded execution.
		if txIdx < len(pq.incarnations) && result.Incarnation != int(pq.incarnations[txIdx]) {
			pq.markForRetry(txIdx)
			return false
		}

		for addr, reads := range result.ReadSet {
			for key, readVersion := range reads {
				// Find the final write version for this key
				finalWriteTx := pq.getFinalWriteVersion(addr, key, txIdx, finalWrites)

				// HIGH-1 FIX: Also check incarnation to handle retry scenarios
				// When a transaction is retried, its incarnation increments.
				// A read from a previous (aborted) incarnation should not validate
				// against a write from a different incarnation.
				//
				// L6-030 FIX: Guard against array out-of-bounds. getFinalWriteVersion
				// returns Version{TxIndex: -1} when there is no prior writer (the read
				// came from the base state). Accessing pq.incarnations[-1] would panic.
				// The array access must happen only after confirming TxIndex >= 0 and
				// within the bounds of the incarnations slice.
				if finalWriteTx.TxIndex >= 0 {
					if finalWriteTx.TxIndex >= len(pq.incarnations) {
						// Defensive: incarnation array is shorter than expected; treat as conflict.
						pq.markForRetry(txIdx)
						return false
					}
					expectedIncarnation := int(pq.incarnations[finalWriteTx.TxIndex])
					if readVersion.Incarnation != expectedIncarnation {
						pq.markForRetry(txIdx)
						return false
					}
					// L8-013 CONFIRMED FIXED: The incarnation array access is guarded
					// by the L6-030 FIX bounds check above (TxIndex >= 0 and
					// TxIndex < len(pq.incarnations)), preventing out-of-bounds panic.
				}

				// If read version doesn't match final write version, we have a conflict
				if readVersion.TxIndex != finalWriteTx.TxIndex {
					pq.markForRetry(txIdx)
					return false
				}

				// CRIT-2 FIX: Compare actual values to prevent malicious validator attacks
				// A malicious validator could commit a tx with same TxIndex/Incarnation
				// but different Value (e.g., transfer 100 instead of 50). Now we detect this.
				if finalWriteTx.TxIndex >= 0 && finalWriteTx.Value != nil {
					if !pq.valuesEqual(readVersion.Value, finalWriteTx.Value) {
						pq.markForRetry(txIdx)
						return false
					}
				}
			}
		}
	}

	return true
}

// CRIT-2 FIX: valuesEqual compares two values for equality, handling common types.
// This is needed because balance writes use *big.Int while storage uses types.Hash.
func (pq *ParallelQVM) valuesEqual(v1, v2 any) bool {
	if v1 == nil && v2 == nil {
		return true
	}
	if v1 == nil || v2 == nil {
		return false
	}

	// Compare big.Int values (balances)
	if b1, ok := v1.(*big.Int); ok {
		if b2, ok := v2.(*big.Int); ok {
			return b1.Cmp(b2) == 0
		}
	}

	// Compare uint64 values (nonces)
	if n1, ok := v1.(uint64); ok {
		if n2, ok := v2.(uint64); ok {
			return n1 == n2
		}
	}

	// Compare byte slices (code)
	if c1, ok := v1.([]byte); ok {
		if c2, ok := v2.([]byte); ok {
			if len(c1) != len(c2) {
				return false
			}
			for i := range c1 {
				if c1[i] != c2[i] {
					return false
				}
			}
			return true
		}
	}

	// Compare Hash values (storage)
	if h1, ok := v1.(types.Hash); ok {
		if h2, ok := v2.(types.Hash); ok {
			return h1 == h2
		}
	}

	// Fallback: direct comparison
	return v1 == v2
}

// getFinalWriteVersion finds the Version that should have been visible when txIdx read this key.
// Returns Version{TxIndex: -1} if no prior write exists (read from base state).
// We need to find the LAST transaction before txIdx that wrote to this key.
func (pq *ParallelQVM) getFinalWriteVersion(addr types.Address, key types.Hash, txIdx int, finalWrites map[types.Address]map[types.Hash]Version) Version {
	lastWriter := Version{TxIndex: -1}

	// Scan all results to find the last writer before txIdx
	for i := 0; i < txIdx; i++ {
		result := pq.results[i]
		if result == nil || !result.Success {
			continue
		}

		// Check if this transaction wrote to the key
		if result.WriteSet[addr] != nil {
			if value, wrote := result.WriteSet[addr][key]; wrote {
				// This transaction wrote to this key - update lastWriter
				lastWriter = Version{
					TxIndex:     i,
					Incarnation: int(pq.incarnations[i]),
					Value:       value,
				}
			}
		}
	}

	return lastWriter
}

// markForRetry marks a transaction for retry.
func (pq *ParallelQVM) markForRetry(txIdx int) {
	pq.retryQueueMu.Lock()
	defer pq.retryQueueMu.Unlock()

	// Check if already in retry queue
	for _, idx := range pq.retryQueue {
		if idx == txIdx {
			return
		}
	}

	pq.retryQueue = append(pq.retryQueue, txIdx)
	atomic.AddInt32(&pq.incarnations[txIdx], 1)
}

// worker is a goroutine that executes contract calls.
func (pq *ParallelQVM) worker(calls []*ContractCall) {
	defer pq.wg.Done()
	// R32-P1-05 FIX (2026-07-28): top-level panic recovery. A panic in
	// executeCall, resultsMu section, or CompleteCall would otherwise kill
	// this worker silently. If all workers die, the scheduler's NextCall/
	// Gosched loop deadlocks in callers waiting for results. On panic, we
	// log and return; the WaitGroup count drops, but Execute() will
	// eventually return with whatever results were produced (callers must
	// already handle missing results as failures — see ValidateResults).
	defer func() {
		if r := recover(); r != nil {
			// Record a failure result so the caller sees a defined error
			// rather than a missing entry that could mask the panic.
			pq.resultsMu.Lock()
			for i := range calls {
				if pq.results[i] == nil {
					pq.results[i] = &ContractExecutionResult{
						Index:       i,
						Success:     false,
						Error:       fmt.Errorf("parallel qvm worker panic: %v", r),
						Incarnation: int(atomic.LoadInt32(&pq.incarnations[i])),
					}
				}
			}
			pq.resultsMu.Unlock()
			// Drain the remaining calls so the scheduler can complete and
			// Execute() doesn't deadlock waiting for IsComplete().
			for {
				idx := pq.scheduler.NextCall()
				if idx < 0 {
					break
				}
				pq.scheduler.CompleteCall(idx)
			}
		}
	}()

	for {
		select {
		case <-pq.stopCh:
			return
		default:
		}

		// Get next call to execute
		callIdx := pq.scheduler.NextCall()
		if callIdx < 0 {
			// Check if all done
			if pq.scheduler.IsComplete() {
				return
			}
			// Brief yield
			runtime.Gosched()
			continue
		}

		// Execute the call
		call := calls[callIdx]
		// R32-P1-05: per-call recover — a single panicking call must not kill
		// the worker. We record a failure result and continue with the next
		// call so the scheduler still makes progress.
		result := func() (r *ContractExecutionResult) {
			defer func() {
				if p := recover(); p != nil {
					r = &ContractExecutionResult{
						Index:       callIdx,
						Success:     false,
						Error:       fmt.Errorf("contract call panic at index %d: %v", callIdx, p),
						Incarnation: int(atomic.LoadInt32(&pq.incarnations[callIdx])),
					}
				}
			}()
			return pq.executeCall(callIdx, call, pq.baseState)
		}()

		// Store result
		pq.resultsMu.Lock()
		pq.results[callIdx] = result
		pq.resultsMu.Unlock()

		// Mark call as complete
		pq.scheduler.CompleteCall(callIdx)
		atomic.AddInt64(&pq.totalExecutions, 1)
	}
}

// executeCall executes a single contract call.
func (pq *ParallelQVM) executeCall(index int, call *ContractCall, state StateDB) *ContractExecutionResult {
	// Get current incarnation for this transaction
	incarnation := int(atomic.LoadInt32(&pq.incarnations[index]))

	result := &ContractExecutionResult{
		Index:        index,
		Success:      false,
		StateChanges: NewStateChanges(),
		ReadSet:      make(map[types.Address]map[types.Hash]Version),
		WriteSet:     make(map[types.Address]map[types.Hash]any),
		Incarnation:  incarnation, // FIX: record incarnation for stale result detection
	}

	// Create isolated state wrapper for this call
	wrapper := &isolatedStateWrapper{
		baseState:   state,
		changes:     result.StateChanges,
		call:        call,
		mvMemory:    pq.mvMemory,
		txIndex:     index,
		incarnation: incarnation,
		readSet:     result.ReadSet,
		writeSet:    result.WriteSet,
	}

	// Check if contract has code
	code := wrapper.GetCode(call.Contract)
	if len(code) == 0 {
		// No code - treat as simple transfer if value > 0
		if call.Value > 0 {
			gasUsed, err := pq.executeTransfer(call, wrapper)
			result.GasUsed = gasUsed
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Success = true
			}
		} else {
			result.Success = true
			result.GasUsed = 0
		}
		return result
	}

	// AUDIT (2026) R2-HIGH-03 (QVM-): Perform value transfer and
	// balance check BEFORE invoking the interpreter for contract calls.
	// Previously, the contract-call path skipped this, causing the caller's
	// balance to not be debited and the contract's balance to not be credited
	// — leading to consensus divergence with the sequential executor and
	// potential inflation. The sequential executor (executor.go:515-527) does
	// this transfer; the parallel path must match.
	if call.Value > 0 {
		transferGas, err := pq.executeTransfer(call, wrapper)
		if err != nil {
			result.Error = err
			result.Success = false
			result.GasUsed = transferGas
			return result
		}
	}

	// SECURITY FIX QVM-H4: Integrate full QVM interpreter for parallel execution
	// Create a StateDB adapter that converts between types.Address and qvm.Address
	stateAdapter := &qvmStateAdapter{wrapper: wrapper}

	// Create execution context for the interpreter
	// Convert types.Address to qvm.Address
	// SECURITY FIX H-2: copy actual coinbase from ParallelQVM struct instead of
	// leaving the zero value. The coinbase is set via SetCoinbase before Execute.
	// FIX: Verify caller address is set correctly.
	// For CALL semantics, Caller must be the original caller (call.Caller),
	// NOT the current contract address (call.Contract / env.ctx.Address).
	// Each ContractCall in the parallel batch represents a top-level call where
	// Caller=tx sender and Contract=target. Using call.Caller here is correct.
	var origin, caller, contract, coinbase qvm.Address
	copy(origin[:], call.Caller[:])
	copy(caller[:], call.Caller[:])
	copy(contract[:], call.Contract[:])
	copy(coinbase[:], pq.coinbase[:])

	ctx := &qvm.ExecutionContext{
		Origin:      origin,
		GasPrice:    pq.effectiveGasPrice(), // AUDIT (2026) QVM B-5 FIX: use configured gas price
		Caller:      caller,
		Address:     contract,
		Value:       new(big.Int).SetUint64(call.Value),
		BlockNumber: pq.blockNumber, // AUDIT (2026) QVM-03: use actual block number
		Timestamp:   pq.timestamp,   // AUDIT (2026) QVM-03: use actual timestamp
		Coinbase:    coinbase,
		GasLimit:    call.Gas,
		// CRITICAL FIX: Use configured ChainID instead of hardcoded value
		// to prevent cross-chain replay attacks
		ChainID:  pq.config.ChainID,
		Code:     code,
		Input:    call.Input,
		Gas:      call.Gas,
		Depth:    0,
		ReadOnly: false,
	}

	// CRIT-3 FIX: Add panic recovery for proper Block-STM snapshot isolation
	// If QVM execution panics after WriteSet is applied to shared mvMemory,
	// the state would be corrupted. We need to rollback on panic.
	snapshotID := wrapper.Snapshot()
	var execResult *qvm.ExecutionResult

	func() {
		defer func() {
			if r := recover(); r != nil {
				// CRIT-3 FIX: Panic during execution - rollback snapshot to clean up
				// This prevents corrupted mvMemory state from affecting other transactions
				wrapper.RevertToSnapshot(snapshotID)
				// Mark result as failed with panic error
				result.Success = false
				result.Error = fmt.Errorf("execution panic: %v", r)
				result.GasUsed = 0
				result.ReturnData = nil
			}
		}()

		// Create interpreter and execute
		interpreter := qvm.NewInterpreter()
		execResult = interpreter.Execute(ctx, stateAdapter)
	}()

	// If panic recovery set execResult to nil, skip processing
	if execResult == nil {
		return result
	}

	// Map execution result to contract execution result
	result.GasUsed = execResult.GasUsed
	result.ReturnData = execResult.ReturnData

	// Convert qvm.Log to parallel.Log
	result.Logs = make([]*Log, len(execResult.Logs))
	for i, qvmLog := range execResult.Logs {
		var addr types.Address
		copy(addr[:], qvmLog.Address[:])

		topics := make([]types.Hash, len(qvmLog.Topics))
		for j, qvmTopic := range qvmLog.Topics {
			copy(topics[j][:], qvmTopic[:])
		}

		result.Logs[i] = &Log{
			Address: addr,
			Topics:  topics,
			Data:    qvmLog.Data,
		}
	}

	result.Error = execResult.Err

	if execResult.Err == nil {
		result.Success = true
	} else {
		result.Success = false
	}

	return result
}

// executeTransfer executes a simple value transfer.
// QVM-R14-HIGH-001 (2026-07-21) FIX: Previously returned a hardcoded 21000 gas,
// which was wrong for two reasons:
//  1. Double-counting: the 21000 base transaction cost is intrinsic gas, already
//     charged by ParallelExecutor at the top level (executor.go:447). Returning
//     21000 here added it a second time, making parallel-path transfers consume
//     ~42000 gas vs 21000 on the sequential path — a consensus fork if parallel
//     execution is enabled.
//  2. Missing EIP-2929: a CALL to an EOA address with value also incurs cold/warm
//     account access costs (2600 cold / 100 warm) and a value-transfer stipend
//     (9000+2300). The hardcoded 21000 ignored all of these.
//
// The fix returns 0 gas on success, matching the ParallelExecutor.executeTransfer
// (executor.go:541) and the sequential Executor.CallWithRollback (executor.go:548-559),
// where gas accounting for the transfer is handled by the caller's gas pool
// (opCall deducts callGas / callStipend before dispatching). On balance
// failure we consume the entire call gas allocation, matching the sequential
// executor's "insufficient balance = all gas consumed" semantics.
func (pq *ParallelQVM) executeTransfer(call *ContractCall, state *isolatedStateWrapper) (uint64, error) {
	if call.Value == 0 {
		return 0, nil
	}

	// Check sender balance
	senderBalance := state.GetBalance(call.Caller)
	// audit-fix R6-M1: use SetUint64 to avoid int64 overflow when Value > MaxInt64
	valueBI := new(big.Int).SetUint64(call.Value)

	if senderBalance.Cmp(valueBI) < 0 {
		// QVM-R14-HIGH-001: Consume all allocated gas on balance failure,
		// matching the sequential executor (executor.go:554 returns GasUsed: gas
		// for insufficient-balance transfers). Without this, a failed parallel
		// transfer would appear to consume no gas, creating a gas griefing
		// vector and a consensus divergence vs. the sequential path.
		return call.Gas, errors.New("insufficient balance for transfer")
	}

	// Deduct from sender
	newSenderBalance := new(big.Int).Sub(senderBalance, valueBI)
	state.SetBalance(call.Caller, newSenderBalance)

	// Add to recipient
	recipientBalance := state.GetBalance(call.Contract)
	newRecipientBalance := new(big.Int).Add(recipientBalance, valueBI)
	state.SetBalance(call.Contract, newRecipientBalance)

	// QVM-R14-HIGH-001: Return 0 on success. Gas accounting for value transfers
	// is the caller's responsibility:
	//   - Top-level txs:    intrinsic gas (21000+data) charged by ParallelExecutor
	//   - Contract sub-calls: callGas + stipend (9000+2300) + EIP-2929 access costs
	//     are deducted by the CALL opcode (opCall in call.go) before dispatch.
	// The transfer itself does not consume additional gas beyond what the
	// caller has already allocated.
	return 0, nil
}

// MergeResults merges execution results into a single StateChanges.
// Results are merged in order to maintain sequential consistency.
func (pq *ParallelQVM) MergeResults(results []*ContractExecutionResult) (*StateChanges, error) {
	merged := NewStateChanges()

	for i, result := range results {
		if result == nil {
			return nil, errors.New("nil result at index")
		}

		// Only merge successful executions
		if result.Success && result.StateChanges != nil {
			merged.Merge(result.StateChanges)
		}

		// Update call's read/write sets for dependency tracking
		// R47-QV-05 FIX: Add nil check for pq.scheduler to prevent panic.
		if pq.scheduler != nil && i < len(pq.scheduler.calls) {
			call := pq.scheduler.calls[i]
			pq.updateCallSets(call, result.StateChanges)
		}
	}

	return merged, nil
}

// updateCallSets updates a call's read/write sets based on state changes.
func (pq *ParallelQVM) updateCallSets(call *ContractCall, changes *StateChanges) {
	if changes == nil {
		return
	}

	changes.mu.RLock()
	defer changes.mu.RUnlock()

	// Record balance writes
	for addr := range changes.Balances {
		call.AddWrite(addr, types.Hash{}) // Use empty hash for balance
	}

	// Record nonce writes
	for addr := range changes.Nonces {
		var nonceKey types.Hash
		nonceKey[0] = 0x01 // Marker for nonce
		call.AddWrite(addr, nonceKey)
	}

	// Record storage writes
	for addr, slots := range changes.Storage {
		for key := range slots {
			call.AddWrite(addr, key)
		}
	}

	// Record code writes
	for addr := range changes.Code {
		var codeKey types.Hash
		codeKey[0] = 0x02 // Marker for code
		call.AddWrite(addr, codeKey)
	}
}

// applyStateChanges applies merged state changes to the base state.
func (pq *ParallelQVM) applyStateChanges(changes *StateChanges) {
	if changes == nil {
		return
	}

	changes.mu.RLock()
	defer changes.mu.RUnlock()

	for addr, balance := range changes.Balances {
		pq.baseState.SetBalance(addr, balance)
	}

	for addr, nonce := range changes.Nonces {
		pq.baseState.SetNonce(addr, nonce)
	}

	for addr, slots := range changes.Storage {
		for key, value := range slots {
			pq.baseState.SetState(addr, key, value)
		}
	}

	for addr, code := range changes.Code {
		pq.baseState.SetCode(addr, code)
	}
}

// DetectConflicts returns groups of conflicting calls.
func (pq *ParallelQVM) DetectConflicts(calls []*ContractCall) [][]int {
	scheduler := NewContractScheduler(calls)
	return scheduler.DetectConflicts()
}

// Stats returns execution statistics.
func (pq *ParallelQVM) Stats() (executions, conflicts int64) {
	return atomic.LoadInt64(&pq.totalExecutions), atomic.LoadInt64(&pq.totalConflicts)
}

func (pq *ParallelQVM) SetMetricsReporter(reporter STMMetricsReporter) {
	pq.metricsReporter = reporter
}

// SetCoinbase sets the coinbase address (block proposer) used for execution context.
// SECURITY FIX H-2: Callers must invoke this before Execute to provide the actual
// block proposer address. If not called, the coinbase remains the zero address,
// which may cause incorrect block reward attribution and COINBASE opcode behavior.
func (pq *ParallelQVM) SetCoinbase(addr types.Address) {
	pq.coinbase = addr
}

// SetBlockContext sets the block number and timestamp for execution context.
// AUDIT (2026) QVM-03: Callers must invoke this before Execute to provide
// the actual block number and timestamp. Without this, TIMESTAMP and NUMBER
// opcodes return 0, causing consensus divergence if the parallel executor
// is used on the consensus path.
func (pq *ParallelQVM) SetBlockContext(blockNumber uint64, timestamp int64) {
	pq.blockNumber = blockNumber
	pq.timestamp = timestamp
}

// SetGasPrice sets the gas price used for the execution context.
// AUDIT (2026) QVM B-5 FIX: Callers should invoke this before Execute to
// provide the actual transaction/block gas price. If not called, GasPrice
// defaults to 1 wei (the previous hardcoded behavior) for backwards compatibility.
func (pq *ParallelQVM) SetGasPrice(price *big.Int) {
	if price != nil && price.Sign() > 0 {
		pq.gasPrice = new(big.Int).Set(price)
	}
}

// effectiveGasPrice returns the configured gas price, defaulting to 1 wei if
// SetGasPrice was never called. This preserves backwards compatibility while
// allowing callers to override with the actual transaction gas price.
func (pq *ParallelQVM) effectiveGasPrice() *big.Int {
	if pq.gasPrice != nil && pq.gasPrice.Sign() > 0 {
		return new(big.Int).Set(pq.gasPrice)
	}
	return big.NewInt(1)
}
