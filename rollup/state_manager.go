// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

type StateManager struct {
	mu     sync.RWMutex
	config *RollupConfig
	// maxHistoryEntries is the dynamic retention bound computed from the
	// configured ChallengePeriod and BlockTime. RLLP-FIX: this
	// replaces the old hard-coded maxStateHistoryEntries=1000 that did not
	// cover the 7-day challenge window.
	maxHistoryEntries int
	stateRoots        map[uint64]types.Hash
	accountStates     map[types.Address]*RollupAccount
	// W-P0-1 (2026-07-13): Historical state snapshots indexed by stateRoot.
	// Populated by ProcessBatch so that SimulateBatch (the fraud-proof
	// verification path) can execute against the state as it was at the time
	// of the challenged batch, even after the live state has advanced.
	// AUDIT (2026) BRDG-06 FIX: Bounded retention via FIFO eviction.
	// stateHistoryOrder tracks insertion order; when len(stateHistory) exceeds
	// maxStateHistoryEntries, the oldest entries are evicted. This bounds
	// memory usage while keeping recent snapshots available for fraud proofs
	// within the challenge window. The max should be tuned to cover at least
	// challenge_period / batch_interval batches.
	stateHistory      map[types.Hash]map[types.Address]*RollupAccount
	stateHistoryOrder []types.Hash
	// W-P0-2 (2026-07-13): QVM executor for L2 contract calls. When nil,
	// processBatchLocked falls back to simple-transfer-only mode (tx.Data is
	// ignored). Production deployments MUST call SetExecutor() before
	// accepting L2 transactions.
	executor QVMExecutor
	// W-P1-3 (2026-07-13): Optional persistence layer for state snapshots.
	persistence Persistence
	// W-P1-6 (2026-07-14): Sparse Merkle tree mirroring accountStates.
	// Rebuilt by computeStateRoot() on each call; used by Prove() to
	// generate Merkle inclusion proofs for L2→L1 withdrawals.
	// Caller MUST hold sm.mu when accessing smt (no internal locking).
	smt *SparseMerkleTree
}

// maxStateHistoryEntries bounds the number of historical state snapshots
// retained for fraud-proof verification. Each entry is a full deep-copy of
// the account state map, so this directly bounds memory usage.
// AUDIT (2026) BRDG-06: prevents unbounded memory growth from
// long-running rollup engines processing thousands of batches.
//
// AUDIT (2026) RLLP-FIX (CRITICAL): The previous hard-coded value
// of 1000 entries covered only ~33 minutes at the default 2s block time —
// far short of the 7-day challenge period (DefaultChallengePeriod). This
// meant fraud-proof verification against batches still inside the challenge
// window would silently fail with "state root not found" errors, allowing
// malicious sequencers to finalize invalid state.
//
// The fix makes the retention window DYNAMIC and CHALLENGE-PERIOD-AWARE:
//   - NewStateManager computes maxHistory from config.ChallengePeriod and
//     config.BlockTime, ensuring snapshots cover the full challenge window
//     plus a 25% safety margin (handles clock drift / batch gaps).
//   - A floor of 1000 is kept for development configurations with very
//     short challenge periods (e.g. tests using 30s).
//   - A ceiling of 500000 prevents unbounded memory growth even if an
//     operator misconfigures an absurdly long challenge period; above the
//     ceiling, persistence layer (W-P1-3) should be used instead.
//   - Validate() rejects ChallengePeriod/BlockTime combinations that would
//     require more than 500000 in-memory snapshots, forcing operators to
//     either shorten the period or wire up the persistence layer.
//
// Math (default config):
//
//	challenge_period = 7*24h = 604800s
//	block_time        = 2s
//	maxHistory        = ceil(604800/2 * 1.25) = 378000 entries
//	memory estimate   = 378000 * avg_account_size (~1KB) ≈ 378MB
//	This is acceptable for a server-class rollup prover node. For resource-
//	constrained deployments, set up Persistence (W-P1-3) to spill to disk.
const (
	minStateHistoryEntries   = 1000   // floor for dev/test configs
	maxStateHistoryEntries   = 500000 // ceiling — above this, require disk persistence
	stateHistorySafetyMargin = 1.25   // +25% to absorb clock drift and batch gaps
)

// QVMExecutor is the subset of qvm.Executor needed by the rollup for L2
// contract execution. The real *qvm.Executor satisfies this interface.
// W-P0-2 (2026-07-13)
type QVMExecutor interface {
	Call(stateDB qvm.StateDB, caller, callee qvm.Address, input []byte, gas uint64, value *big.Int, blockCtx *qvm.BlockContext, depth int) *qvm.ExecutionResult
}

// SetExecutor injects the QVM executor for L2 contract call execution.
// W-P0-2 (2026-07-13): Without this, tx.Data is silently ignored and
// contract calls are treated as simple transfers.
func (sm *StateManager) SetExecutor(executor QVMExecutor) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.executor = executor
}

// SetPersistence injects the persistence layer for state snapshots.
// W-P1-3 FIX (2026-07-13): When set, PersistSnapshot() flushes account
// states + stateRoots to disk; RestoreFromSnapshot() loads them on startup.
func (sm *StateManager) SetPersistence(p Persistence) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.persistence = p
}

// PersistSnapshot flushes the current account states + stateRoots to the
// persistence layer. Called by RollupEngine after each successful batch.
// W-P1-3 FIX (2026-07-13)
func (sm *StateManager) PersistSnapshot() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.persistence == nil {
		return nil
	}
	return sm.persistence.SaveStateSnapshot(sm.accountStates, sm.stateRoots)
}

// RestoreFromSnapshot loads account states + stateRoots from persistence
// into memory, replacing any existing state. Called once on engine startup.
// W-P1-3 FIX (2026-07-13)
//
// W-P2-4 FIX (2026-07-14): Also rebuild the in-memory Sparse Merkle Tree
// (sm.smt) from the restored accountStates. Without this, GetCurrentRoot()
// returns the root of an empty tree after restart, and Prove() generates
// invalid inclusion proofs — breaking L2→L1 withdrawals that rely on
// account proofs after a node restart. The stateRoots map (keyed by batch
// index) is restored separately and is not affected by the SMT rebuild.
func (sm *StateManager) RestoreFromSnapshot(states map[types.Address]*RollupAccount, stateRoots map[uint64]types.Hash) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.accountStates = states
	sm.stateRoots = stateRoots
	// Rebuild the SMT so GetCurrentRoot()/Prove() reflect the restored state.
	// computeStateRoot() requires the caller to hold sm.mu, which we do.
	sm.computeStateRoot()
}

type RollupAccount struct {
	Nonce    uint64
	Balance  *big.Int
	CodeHash types.Hash
	Storage  map[types.Hash]types.Hash
	// W-P0-2 (2026-07-13): Contract bytecode. Populated by contract
	// deployment (QVM Create) or direct SetCode via the StateDB adapter.
	// CodeHash is sha256(Code); accounts without code have CodeHash == {}.
	Code []byte
}

func NewStateManager(config *RollupConfig) *StateManager {
	// RLLP-FIX: Compute dynamic retention bound from challenge period.
	maxHistory := computeStateHistoryEntries(config)
	return &StateManager{
		config:            config,
		maxHistoryEntries: maxHistory,
		stateRoots:        make(map[uint64]types.Hash),
		accountStates:     make(map[types.Address]*RollupAccount),
		stateHistory:      make(map[types.Hash]map[types.Address]*RollupAccount),
		smt:               NewSparseMerkleTree(),
	}
}

// computeStateHistoryEntries returns the number of state snapshots to retain
// in memory, derived from the challenge period and block time so that every
// batch inside the challenge window has its snapshot available for fraud-proof
// verification. RLLP-FIX.
//
// Returns minStateHistoryEntries when config is nil or BlockTime/ChallengePeriod
// are zero (defensive — these should be caught by Validate()).
func computeStateHistoryEntries(config *RollupConfig) int {
	if config == nil || config.BlockTime <= 0 || config.ChallengePeriod <= 0 {
		return minStateHistoryEntries
	}
	// snapshots_needed = ceil(challenge_period / block_time) * safety_margin
	blocksInChallenge := float64(config.ChallengePeriod) / float64(config.BlockTime)
	needed := int(blocksInChallenge*stateHistorySafetyMargin + 0.999) // ceil rounding
	if needed < minStateHistoryEntries {
		return minStateHistoryEntries
	}
	if needed > maxStateHistoryEntries {
		return maxStateHistoryEntries
	}
	return needed
}

// deepCopyAccounts creates a fully independent copy of the account state map.
// Used by W-P0-1 to archive historical snapshots and to create simulation
// working copies that don't mutate the live state.
func deepCopyAccounts(src map[types.Address]*RollupAccount) map[types.Address]*RollupAccount {
	dst := make(map[types.Address]*RollupAccount, len(src))
	for addr, acc := range src {
		storageCopy := make(map[types.Hash]types.Hash, len(acc.Storage))
		for k, v := range acc.Storage {
			storageCopy[k] = v
		}
		var codeCopy []byte
		if acc.Code != nil {
			codeCopy = append([]byte(nil), acc.Code...)
		}
		dst[addr] = &RollupAccount{
			Nonce:    acc.Nonce,
			Balance:  new(big.Int).Set(acc.Balance),
			CodeHash: acc.CodeHash,
			Storage:  storageCopy,
			Code:     codeCopy,
		}
	}
	return dst
}

// ProcessBatch executes a batch of L2 transactions against the current state,
// validates the prevStateRoot, and archives the resulting postStateRoot keyed
// by batchIndex so that GetStateRoot(batchIndex) returns the correct value.
//
// W-P0-3 FIX (2026-07-13): Previously ProcessBatch returned newRoot but never
// wrote it to sm.stateRoots, so RPC qau_rollupGetStateRoot(batchIndex) always
// returned "not found". Now the caller passes batchIndex and ProcessBatch
// archives newRoot into sm.stateRoots[batchIndex] on success.
//
// W-P0-1 FIX (2026-07-13): ProcessBatch now also archives state snapshots
// (account states) into stateHistory, indexed by stateRoot. This allows
// SimulateBatch (the fraud-proof verification path) to execute against the
// state as it was at the time of the challenged batch, even after the live
// state has advanced — preventing a malicious sequencer from escaping
// challenge by processing additional batches.
//
// Note: SimulateBatch deliberately does NOT archive — it only computes what
// the post-root would be, without mutating long-term state.
func (sm *StateManager) ProcessBatch(batchIndex uint64, prevStateRoot types.Hash, txs []*RollupTransaction) (types.Hash, uint64, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// AUDIT (2026) HIGH-11: Validate prevStateRoot against the current
	// state root before executing. Without this, a sequencer could claim an
	// arbitrary prevStateRoot that doesn't match the actual state, making
	// fraud proofs unreliable (they run against mutable global state, not the
	// batch's declared pre-state).
	// Exception: if accountStates is empty (genesis), accept any prevStateRoot
	// since there's no state to compare against yet.
	if len(sm.accountStates) > 0 {
		currentRoot := sm.computeStateRoot()
		if prevStateRoot != currentRoot {
			return types.Hash{}, 0, ErrInvalidStateTransition
		}
	}

	// W-P0-1: Archive the pre-state snapshot under prevStateRoot so that
	// SimulateBatch can verify fraud proofs for this batch later. This is
	// especially important for batch 0 whose pre-state is the genesis state
	// (never archived as a post-state of any prior batch). For subsequent
	// batches, the pre-state equals the previous batch's post-state which is
	// already archived, so the dedup check avoids storing it twice.
	if _, exists := sm.stateHistory[prevStateRoot]; !exists {
		sm.archiveStateSnapshot(prevStateRoot, sm.accountStates)
	}

	// R37-FIX P2-BRIDGE-03 (2026-07-30): snapshot accountStates before the
	// batch so that a mid-batch failure can be rolled back. Without this,
	// processBatchLocked's early return on the first invalid tx leaves all
	// prior txs' state mutations permanently in sm.accountStates — an
	// inconsistent partial batch that diverges from the declared prevStateRoot.
	preStateSnapshot := deepCopyAccounts(sm.accountStates)

	newRoot, gasUsed, err := sm.processBatchLocked(prevStateRoot, txs)
	if err != nil {
		sm.accountStates = preStateSnapshot
		return types.Hash{}, 0, err
	}

	// W-P0-3 FIX: Archive the post-state root by batch index so that
	// GetStateRoot(batchIndex) returns the correct value. This is the only
	// write path into sm.stateRoots.
	sm.stateRoots[batchIndex] = newRoot

	// W-P0-1: Archive the post-state snapshot under newRoot so that
	// SimulateBatch can verify fraud proofs for the NEXT batch (whose
	// pre-state is this batch's post-state).
	sm.archiveStateSnapshot(newRoot, sm.accountStates)

	return newRoot, gasUsed, nil
}

// archiveStateSnapshot stores a deep-copy of the given account states under the
// given stateRoot key, with FIFO eviction when the history exceeds
// sm.maxHistoryEntries. The caller must hold sm.mu (write).
// AUDIT (2026) BRDG-06 FIX: bounds memory usage of stateHistory.
// RLLP-FIX (2026-07-17): uses dynamic maxHistoryEntries computed from
// ChallengePeriod to guarantee all snapshots within the challenge window are
// retained for fraud-proof verification.
func (sm *StateManager) archiveStateSnapshot(stateRoot types.Hash, states map[types.Address]*RollupAccount) {
	if _, exists := sm.stateHistory[stateRoot]; exists {
		return // already archived
	}
	sm.stateHistory[stateRoot] = deepCopyAccounts(states)
	sm.stateHistoryOrder = append(sm.stateHistoryOrder, stateRoot)

	// FIFO eviction: remove oldest entries until we're back under the limit.
	limit := sm.maxHistoryEntries
	if limit <= 0 {
		limit = minStateHistoryEntries // defensive: should never happen
	}
	for len(sm.stateHistory) > limit {
		oldest := sm.stateHistoryOrder[0]
		sm.stateHistoryOrder = sm.stateHistoryOrder[1:]
		delete(sm.stateHistory, oldest)
	}
}

// processBatchLocked executes a batch without acquiring the mutex. The caller
// must hold sm.mu.
// Rollback handling: ProcessBatch archives a deep-copy pre-state snapshot
// (R37-FIX P2-BRIDGE-03) and restores sm.accountStates on any error return
// from this function, so mid-batch failures never leave a partial batch.
// Per-tx QVM failures roll back via the QVM's own RevertToSnapshot.
//
// W-P0-2 (2026-07-13): When a QVM executor is configured and the target
// account has code (CodeHash != {}), the transaction is routed to the QVM
// for contract execution. The QVM handles value transfer and state changes
// via the rollupStateDB adapter. Gas is charged based on actual QVM gasUsed.
// On QVM failure (revert or error), state changes are rolled back by the QVM
// (via RevertToSnapshot), but gas is still charged and the batch continues
// with the next transaction.
func (sm *StateManager) processBatchLocked(prevStateRoot types.Hash, txs []*RollupTransaction) (types.Hash, uint64, error) {
	var totalGasUsed uint64

	for _, tx := range txs {
		fromAcc := sm.getOrCreateAccount(tx.From)
		if fromAcc.Nonce != tx.Nonce {
			return types.Hash{}, 0, ErrInvalidStateTransition
		}

		gasCost := new(big.Int).Mul(
			new(big.Int).SetUint64(tx.GasLimit),
			new(big.Int).SetUint64(tx.GasPrice),
		)
		// R9-RP-001 FIX: Treat nil Value as zero to prevent nil pointer panic.
		txValue := tx.Value
		if txValue == nil {
			txValue = big.NewInt(0)
		}

		// RLLP- (2026-07-16): Withdrawal burn semantics. When
		// BridgeAddress is configured and this tx sends value to it, the
		// value is BURNED from L2 supply (deducted from sender, NOT credited
		// to the bridge account). This maintains the L2 supply invariant:
		// every L1 release corresponds 1:1 to an L2 burn. Without this, the
		// bridge account on L2 would accumulate tokens that are also
		// released on L1 — a double-spend. The burn is checked BEFORE the
		// contract-call path so that even if the bridge address somehow has
		// code deployed to it, withdrawal value is still burned (defense in
		// depth).
		isWithdrawalBurn := sm.config != nil &&
			sm.config.BridgeAddress != (types.Address{}) &&
			tx.To != nil &&
			*tx.To == sm.config.BridgeAddress

		if isWithdrawalBurn {
			// Deduct value + gas from sender, increment nonce, but DO NOT
			// credit the bridge account. The value is removed from L2
			// circulation entirely.
			totalCost := new(big.Int).Add(txValue, gasCost)
			if fromAcc.Balance.Cmp(totalCost) < 0 {
				return types.Hash{}, 0, ErrInvalidStateTransition
			}
			fromAcc.Balance.Sub(fromAcc.Balance, totalCost)
			fromAcc.Nonce++
			// R8-RP-002 FIX: Safe gas addition with overflow check.
			newTotal, err := qvm.SafeAddGas(totalGasUsed, tx.GasLimit)
			if err != nil {
				return types.Hash{}, 0, ErrInvalidStateTransition
			}
			// R9-RP-003 FIX: Check batch-level gas limit.
			if sm.config != nil && newTotal > sm.config.GasLimit {
				return types.Hash{}, 0, ErrInvalidStateTransition
			}
			totalGasUsed = newTotal
			// Intentionally do NOT credit txValue to the bridge account —
			// the value is burned. L1 release happens separately via
			// ProcessFinalizedBatch → L1Bridge.ProcessWithdrawal.
			continue
		}

		// W-P0-2: Determine if this tx targets a contract (has code).
		isContractCall := false
		if tx.To != nil {
			toAcc := sm.getOrCreateAccount(*tx.To)
			if toAcc.CodeHash != (types.Hash{}) {
				isContractCall = true
			}
		}

		if isContractCall && sm.executor != nil {
			// W-P0-2: Contract call — route to QVM.
			// QVM handles value transfer via StateDB; we only deduct gas here.
			totalNeeded := new(big.Int).Add(txValue, gasCost)
			if fromAcc.Balance.Cmp(totalNeeded) < 0 {
				return types.Hash{}, 0, ErrInvalidStateTransition
			}
			fromAcc.Balance.Sub(fromAcc.Balance, gasCost)
			fromAcc.Nonce++

			gasUsed := sm.executeContractCall(tx, txValue)

			// R8-RP-002: Safe gas addition with overflow check.
			newTotal, err := qvm.SafeAddGas(totalGasUsed, gasUsed)
			if err != nil {
				return types.Hash{}, 0, ErrInvalidStateTransition
			}
			if sm.config != nil && newTotal > sm.config.GasLimit {
				return types.Hash{}, 0, ErrInvalidStateTransition
			}
			totalGasUsed = newTotal
		} else {
			// Simple transfer (existing behavior — no code or no executor).
			totalCost := new(big.Int).Add(txValue, gasCost)
			if fromAcc.Balance.Cmp(totalCost) < 0 {
				return types.Hash{}, 0, ErrInvalidStateTransition
			}
			fromAcc.Balance.Sub(fromAcc.Balance, totalCost)
			fromAcc.Nonce++
			// R8-RP-002 FIX: Use safe addition to prevent uint64 overflow.
			newTotal, err := qvm.SafeAddGas(totalGasUsed, tx.GasLimit)
			if err != nil {
				return types.Hash{}, 0, ErrInvalidStateTransition
			}
			// R9-RP-003 FIX: Check batch-level gas limit.
			if sm.config != nil && newTotal > sm.config.GasLimit {
				return types.Hash{}, 0, ErrInvalidStateTransition
			}
			totalGasUsed = newTotal

			if tx.To != nil {
				toAcc := sm.getOrCreateAccount(*tx.To)
				toAcc.Balance.Add(toAcc.Balance, txValue)
			}
		}
	}

	newRoot := sm.computeStateRoot()
	return newRoot, totalGasUsed, nil
}

// executeContractCall routes a contract call to the QVM and handles gas
// accounting. The caller (processBatchLocked) must hold sm.mu.
// Rollback handling: delegated to the QVM's snapshot/revert (see below);
// batch-level failure rollback is in ProcessBatch (deep-copy restore).
//
// W-P0-2 (2026-07-13): The QVM's Call method:
//  1. Takes a state snapshot (via StateDB.Snapshot)
//  2. Transfers value from caller to callee (via StateDB.SetBalance)
//  3. Executes the contract bytecode
//  4. On failure: calls RevertToSnapshot to roll back ALL state changes
//     (including value transfer); GasUsed reflects actual consumption
//
// After the QVM returns, we refund (gasLimit - gasUsed) * gasPrice to the
// sender. On failure, the state is already rolled back by the QVM — we
// still charge gas and continue the batch (the failed tx is included but
// its state changes are void).
func (sm *StateManager) executeContractCall(tx *RollupTransaction, txValue *big.Int) uint64 {
	stateDB := newRollupStateDB(sm.accountStates)
	blockCtx := &qvm.BlockContext{
		BlockNumber: 0, // TODO: pass actual batch index
		Timestamp:   0, // TODO: pass batch timestamp
		GasLimit:    sm.config.GasLimit,
		GasPrice:    new(big.Int).SetUint64(tx.GasPrice),
		ChainID:     sm.config.ChainID,
	}

	result := sm.executor.Call(
		stateDB,
		toQVMAddr(tx.From),
		toQVMAddr(*tx.To),
		tx.Data,
		tx.GasLimit,
		txValue,
		blockCtx,
		0, // depth 0 = top-level call
	)

	// Re-fetch fromAcc because RevertToSnapshot may have replaced the
	// account object in the map with a deep-copied one.
	fromAcc := sm.getOrCreateAccount(tx.From)

	gasUsed := result.GasUsed
	if gasUsed > tx.GasLimit {
		gasUsed = tx.GasLimit // safety clamp
	}

	// Refund unused gas: (gasLimit - gasUsed) * gasPrice
	if gasUsed < tx.GasLimit {
		refund := new(big.Int).Mul(
			new(big.Int).SetUint64(tx.GasLimit-gasUsed),
			new(big.Int).SetUint64(tx.GasPrice),
		)
		fromAcc.Balance.Add(fromAcc.Balance, refund)
	}

	if result.Err != nil {
		log.Printf("[WARN] rollup: contract call to %x failed: %v (reverted=%v, gasUsed=%d)",
			(*tx.To)[:8], result.Err, result.Reverted, gasUsed)
	}

	return gasUsed
}

// SimulateBatch executes a batch against a historical state snapshot (indexed
// by prevStateRoot) WITHOUT mutating the live state. This is the fraud-proof
// verification path: it computes what the post-state root WOULD be if txs were
// applied to the state that existed at the time of the challenged batch.
//
// W-P0-1 FIX (2026-07-13): Previously SimulateBatch could only execute
// against the CURRENT live state. If the sequencer processed additional
// batches after the fraudulent one, the live state would no longer match
// prevStateRoot, causing SimulateBatch to return ErrInvalidStateTransition
// and the fraud proof to be rejected — letting the sequencer escape
// challenge. Now SimulateBatch loads the historical state snapshot from
// stateHistory (populated by ProcessBatch) and executes on a deep copy.
//
// Fallback: if prevStateRoot is not in stateHistory but matches the current
// state root (or the state is empty/genesis), SimulateBatch executes against
// a snapshot of the current state. This maintains backward compatibility and
// handles the genesis case before any ProcessBatch has run.
func (sm *StateManager) SimulateBatch(prevStateRoot types.Hash, txs []*RollupTransaction) (types.Hash, uint64, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// W-P0-1: Primary path — load historical state snapshot.
	if historicalStates, exists := sm.stateHistory[prevStateRoot]; exists {
		// Deep-copy the historical snapshot so simulation doesn't mutate it.
		simStates := deepCopyAccounts(historicalStates)
		// Temporarily swap in the simulation state. processBatchLocked and
		// computeStateRoot both operate on sm.accountStates, so the swap
		// makes them execute against the historical copy. The defer
		// guarantees the live state is restored even on panic.
		savedStates := sm.accountStates
		sm.accountStates = simStates
		defer func() { sm.accountStates = savedStates }()

		newRoot, gasUsed, err := sm.processBatchLocked(prevStateRoot, txs)
		return newRoot, gasUsed, err
	}

	// W-P0-1: Fallback path — prevStateRoot not in history. If it matches the
	// current state root (or state is empty/genesis), execute against a
	// snapshot of the current state. This handles:
	//   - Genesis fraud proofs (before any ProcessBatch has archived history)
	//   - Tests that verify against the live state
	//   - Fraud proofs for the most recent batch (state hasn't advanced yet)
	if len(sm.accountStates) > 0 {
		currentRoot := sm.computeStateRoot()
		if prevStateRoot != currentRoot {
			// prevStateRoot is neither in history nor matches current state —
			// we cannot verify this fraud proof. Fail-closed.
			return types.Hash{}, 0, ErrInvalidStateTransition
		}
	}

	// audit-fix Round3 H-1: hold the write lock for the entire snapshot →
	// simulate → restore cycle so restore() cannot race with a concurrent
	// ProcessBatch. snapshotLocked/restoreLocked operate without locking
	// (caller holds the lock).
	snap := sm.snapshotLocked()
	newRoot, gasUsed, err := sm.processBatchLocked(prevStateRoot, txs)
	if err != nil {
		sm.restoreLocked(snap)
		return types.Hash{}, 0, err
	}
	sm.restoreLocked(snap)
	return newRoot, gasUsed, nil
}

// snapshotLocked takes a snapshot of the current account states. The caller
// must hold sm.mu (read or write).
func (sm *StateManager) snapshotLocked() map[types.Address]struct {
	nonce    uint64
	balance  *big.Int
	codeHash types.Hash
	storage  map[types.Hash]types.Hash
} {
	snap := make(map[types.Address]struct {
		nonce    uint64
		balance  *big.Int
		codeHash types.Hash
		storage  map[types.Hash]types.Hash
	})
	for addr, acc := range sm.accountStates {
		storageCopy := make(map[types.Hash]types.Hash, len(acc.Storage))
		for k, v := range acc.Storage {
			storageCopy[k] = v
		}
		snap[addr] = struct {
			nonce    uint64
			balance  *big.Int
			codeHash types.Hash
			storage  map[types.Hash]types.Hash
		}{
			nonce:    acc.Nonce,
			balance:  new(big.Int).Set(acc.Balance),
			codeHash: acc.CodeHash,
			storage:  storageCopy,
		}
	}
	return snap
}

// restoreLocked restores account states from a snapshot. The caller must hold
// sm.mu (write).
// R8-RP-001 FIX: Also delete accounts created during simulation that were not
// in the original snapshot. Without this, ghost accounts (balance 0, created
// by getOrCreateAccount during SimulateBatch) pollute subsequent state root
// computations.
func (sm *StateManager) restoreLocked(snap map[types.Address]struct {
	nonce    uint64
	balance  *big.Int
	codeHash types.Hash
	storage  map[types.Hash]types.Hash
}) {
	// Restore existing accounts from the snapshot
	for addr, saved := range snap {
		if acc, ok := sm.accountStates[addr]; ok {
			acc.Nonce = saved.nonce
			acc.Balance.Set(saved.balance)
			acc.CodeHash = saved.codeHash
			acc.Storage = saved.storage
		}
	}
	// Delete ghost accounts created during simulation
	for addr := range sm.accountStates {
		if _, ok := snap[addr]; !ok {
			delete(sm.accountStates, addr)
		}
	}
}

func (sm *StateManager) getOrCreateAccount(addr types.Address) *RollupAccount {
	acc, exists := sm.accountStates[addr]
	if !exists {
		acc = &RollupAccount{
			Balance: new(big.Int),
			Storage: make(map[types.Hash]types.Hash),
		}
		sm.accountStates[addr] = acc
	}
	return acc
}

func (sm *StateManager) GetAccount(addr types.Address) *RollupAccount {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.accountStates[addr]
}

// MintBalance increases an account's L2 balance by the given amount.
// Used by L2Bridge.ProcessDeposit to mint L2 balance corresponding to a
// locked L1 deposit. This is the only path that creates L2 QAU — all other
// transfers simply move existing balance between L2 accounts.
// W-P1-6 FIX (2026-07-13)
func (sm *StateManager) MintBalance(addr types.Address, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return fmt.Errorf("mint amount must be positive")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	acc := sm.getOrCreateAccountLocked(addr)
	acc.Balance.Add(acc.Balance, amount)
	return nil
}

// BurnBalance decreases an account's L2 balance by the given amount.
// Returns an error if the account has insufficient balance. Used to burn
// L2 QAU during withdrawals (the value is removed from L2 supply and later
// released on L1 by the bridge).
// W-P1-6 FIX (2026-07-13)
func (sm *StateManager) BurnBalance(addr types.Address, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return fmt.Errorf("burn amount must be positive")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	acc := sm.getOrCreateAccountLocked(addr)
	if acc.Balance.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient balance: have %s, need %s", acc.Balance.String(), amount.String())
	}
	acc.Balance.Sub(acc.Balance, amount)
	return nil
}

// getOrCreateAccountLocked is the lock-free version of getOrCreateAccount.
// Caller MUST hold sm.mu. Extracted so MintBalance/BurnBalance can share
// the critical section without re-acquiring the lock.
// W-P1-6 FIX (2026-07-13)
func (sm *StateManager) getOrCreateAccountLocked(addr types.Address) *RollupAccount {
	acc, exists := sm.accountStates[addr]
	if !exists {
		acc = &RollupAccount{
			Balance: new(big.Int),
			Storage: make(map[types.Hash]types.Hash),
		}
		sm.accountStates[addr] = acc
	}
	return acc
}

// ProveAccount generates a Merkle inclusion proof for the given account
// against the current state root. The proof can be verified by anyone who
// knows the state root (e.g. an L1 bridge contract).
//
// W-P1-6 FIX (2026-07-14): Uses the cached SMT (rebuilt by the last
// computeStateRoot call). The caller should ensure computeStateRoot was
// called recently (it is called at the end of every ProcessBatch, so the
// SMT reflects the latest state).
//
// Returns the proof and the account's leaf hash. If the account does not
// exist, returns a non-inclusion proof (leaf hash = zero leaf).
func (sm *StateManager) ProveAccount(addr types.Address) (*MerkleProof, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.smt == nil {
		return nil, fmt.Errorf("SMT not initialized (computeStateRoot not yet called)")
	}
	return sm.smt.Prove(addr)
}

// ProveAccountAtState generates a Merkle inclusion proof for the given address
// against a historical state root. The historical state must have been
// archived by ProcessBatch (via archiveStateSnapshot). If the state root is
// unknown or has been evicted (exceeds maxStateHistoryEntries), returns an error.
//
// W-P1-6 (2026-07-14): Used by L2Bridge.ProcessFinalizedBatch to generate
// Merkle withdrawal proofs against the batch's post-state root, even after
// the live state has advanced. This is the key primitive that makes L2→L1
// withdrawals trust-minimized: the L1 bridge verifies the Merkle proof
// against the finalized state root, proving the withdrawer's account was
// included in the finalized L2 state.
func (sm *StateManager) ProveAccountAtState(addr types.Address, stateRoot types.Hash) (*MerkleProof, error) {
	proof, _, err := sm.ProveAccountWithStateAtState(addr, stateRoot)
	return proof, err
}

// ProveAccountWithStateAtState returns a Merkle inclusion proof for addr at
// the given finalized stateRoot, along with the account state at that root.
// The account state is needed by the L1 bridge to populate the
// MerkleWithdrawalProof's account fields (audit R4-BRDG-02: bind withdrawal
// amount to proven account balance).
func (sm *StateManager) ProveAccountWithStateAtState(addr types.Address, stateRoot types.Hash) (*MerkleProof, *RollupAccount, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	historicalStates, ok := sm.stateHistory[stateRoot]
	if !ok {
		return nil, nil, fmt.Errorf("state root %x not found in history (evicted or unknown)", stateRoot[:8])
	}

	acc, exists := historicalStates[addr]
	if !exists {
		return nil, nil, fmt.Errorf("account %x not found at state root %x", addr[:8], stateRoot[:8])
	}

	// Build a temporary SMT from the historical account states.
	smt := NewSparseMerkleTree()
	entries := make(map[types.Address]types.Hash, len(historicalStates))
	for a, acc := range historicalStates {
		entries[a] = ComputeAccountLeafHash(a, acc)
	}
	smt.BatchInsert(entries)

	// Verify the rebuilt root matches the expected stateRoot.
	rebuiltRoot := smt.Root()
	if rebuiltRoot != stateRoot {
		return nil, nil, fmt.Errorf("internal error: rebuilt SMT root %x does not match expected %x",
			rebuiltRoot[:8], stateRoot[:8])
	}

	proof, err := smt.Prove(addr)
	if err != nil {
		return nil, nil, err
	}
	return proof, acc, nil
}

// GetStateRoot returns the current SMT root without rebuilding.
// Useful for callers that want to read the root without triggering a rebuild.
// W-P1-6 FIX (2026-07-14)
func (sm *StateManager) GetCurrentRoot() types.Hash {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.smt == nil {
		return smtZeroHashes[SparseMerkleTreeDepth]
	}
	return sm.smt.Root()
}

func (sm *StateManager) GetStateRoot(batchIndex uint64) (types.Hash, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	root, exists := sm.stateRoots[batchIndex]
	return root, exists
}

// computeStateRoot rebuilds the Sparse Merkle Tree from the current
// accountStates and returns its root. The rebuilt SMT is cached in sm.smt
// so that Prove() can generate Merkle inclusion proofs immediately after.
//
// W-P1-6 FIX (2026-07-14): Replaced the linear SHA256 hash with a sparse
// Merkle tree. This enables O(log₂ N) = O(160) inclusion proofs for any
// account, which is required for trust-minimized L2→L1 withdrawals.
//
// The SMT leaf hash covers the same fields as the old linear hash:
// addr || nonce || balanceLen || balance || codeHash || storageRoot
// (storageRoot is a sorted-key SHA256 over the account's storage entries,
// matching the old linear hash's storage computation exactly).
//
// Caller MUST hold sm.mu (write lock or read lock — rebuild is safe under
// either, but the cached smt replacement requires write lock to be race-free
// with concurrent Prove calls).
func (sm *StateManager) computeStateRoot() types.Hash {
	// W-P1-6: Rebuild SMT from scratch. O(N * 160) where N = account count.
	// For typical rollup workloads (thousands of accounts) this is fast
	// enough; for very large state, an incremental SMT (updated on each
	// SetBalance/SetNonce/SetState) would be more efficient.
	smt := NewSparseMerkleTree()
	entries := make(map[types.Address]types.Hash, len(sm.accountStates))
	for addr, acc := range sm.accountStates {
		entries[addr] = ComputeAccountLeafHash(addr, acc)
	}
	smt.BatchInsert(entries)
	sm.smt = smt
	return smt.Root()
}
