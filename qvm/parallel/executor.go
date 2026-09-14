// Quantaureum Node source, version 1.0.0.
// Package parallel implements Block-STM parallel transaction execution.
// Block-STM is an optimistic concurrency control algorithm that enables
// parallel execution of transactions while maintaining serial equivalence.
package parallel

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"math/bits"
	"os"
	"runtime"
	"sync"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/evmcompat"
	"github.com/quantaureum/qau/privacy"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// Errors for parallel execution
var (
	ErrConflictDetected   = errors.New("conflict detected during validation")
	ErrMaxRetriesExceeded = errors.New("maximum retries exceeded")
	ErrInvalidTransaction = errors.New("invalid transaction")
	ErrExecutionFailed    = errors.New("execution failed")
)

// PrivacyTxVerifier verifies the ZK proofs of an encoded privacy transaction.
// AUDIT ROUND-5 2026-08-17 FIX: mirrors the txpool executor's interface
// (HIGH-20 / ZK-NN-4) so the parallel path can enforce the same
// cryptographic verification. Defined locally to avoid an import cycle
// with txpool.
type PrivacyTxVerifier interface {
	VerifyEncodedPrivacyTx(tx *encoding.Transaction) error
}

// MultisigTxVerifier verifies a multisig transaction against the REAL
// on-chain wallet configuration (threshold + member signatures).
// AUDIT ROUND-5 2026-08-17 FIX: mirrors the txpool executor's
// R4-ECON-06 hardening — trusting tx.MultiSigRequiredSigs /
// MultiSigSignerBitmap alone lets an attacker bypass the threshold.
type MultisigTxVerifier interface {
	VerifyMultisigTx(tx *encoding.Transaction) error
}

// Config holds configuration for the parallel executor.
type Config struct {
	// NumWorkers is the number of parallel worker goroutines.
	// Default: runtime.NumCPU()
	NumWorkers int

	// MaxRetries is the maximum number of retries for a conflicting transaction.
	// Default: 10
	MaxRetries int

	// EnablePrefetch enables state prefetching for better cache utilization.
	EnablePrefetch bool
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		NumWorkers:     runtime.NumCPU(),
		MaxRetries:     10,
		EnablePrefetch: true,
	}
}

// Receipt represents the result of a transaction execution.
type Receipt struct {
	TxHash  types.Hash
	TxIndex int
	Status  uint64 // 1 = success, 0 = failure
	GasUsed uint64
	Logs    []*Log
	Error   string
}

// Log represents an event log.
type Log struct {
	Address types.Address
	Topics  []types.Hash
	Data    []byte
}

// StateDB interface for transaction execution.
type StateDB interface {
	GetBalance(addr types.Address) *big.Int
	SetBalance(addr types.Address, balance *big.Int)
	GetNonce(addr types.Address) uint64
	SetNonce(addr types.Address, nonce uint64)
	GetCode(addr types.Address) []byte
	SetCode(addr types.Address, code []byte)
	GetCodeSize(addr types.Address) int
	GetState(addr types.Address, key types.Hash) types.Hash
	SetState(addr types.Address, key, value types.Hash)
	Snapshot() int
	RevertToSnapshot(id int)
	// Access list (for gas calculation)
	AddressInAccessList(addr types.Address) bool
	SlotInAccessList(addr types.Address, slot types.Hash) (addressOk, slotOk bool)
}

// BlockContext contains block-level context for execution.
type BlockContext struct {
	BlockHash   types.Hash
	BlockNumber uint64
	Timestamp   int64
	Coinbase    types.Address
	GasLimit    uint64
	GasPrice    *big.Int
	ChainID     uint64                // CRITICAL FIX: Added ChainID field to support dynamic chain ID
	BlockHashes map[uint64]types.Hash // Recent block hashes (last 256 blocks)
}

// ParallelExecutor implements Block-STM parallel transaction execution.
type ParallelExecutor struct {
	config     *Config
	mvMemory   *MVMemory
	scheduler  *Scheduler
	baseState  StateDB
	qvmExec    *qvm.Executor
	privacyMgr *privacy.PrivacyManager

	// AUDIT ROUND-5 2026-08-17 /FIX: verification hooks mirroring
	// the txpool executor. Both require* flags default to TRUE (fail-closed)
	// in NewParallelExecutor: without a configured verifier, privacy and
	// multisig transactions are REJECTED rather than executed on the
	// legacy length/bitmap-only checks, which the txpool executor already
	// identified as exploitable (HIGH-20, R4-ECON-06).
	privacyTxVerifier           PrivacyTxVerifier
	requirePrivacyVerification  bool
	multisigVerifier            MultisigTxVerifier
	requireMultisigVerification bool

	// Transaction execution results
	results   []*Receipt
	resultsMu sync.Mutex

	// Worker coordination
	wg     sync.WaitGroup
	stopCh chan struct{}
	errCh  chan error
}

// NewParallelExecutor creates a new parallel executor.
func NewParallelExecutor(config *Config) *ParallelExecutor {
	if config == nil {
		config = DefaultConfig()
	}
	if config.NumWorkers <= 0 {
		config.NumWorkers = runtime.NumCPU()
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 10
	}

	return &ParallelExecutor{
		config:   config,
		mvMemory: NewMVMemory(),
		stopCh:   make(chan struct{}),
		errCh:    make(chan error, 1),
		qvmExec:  qvm.NewExecutor(),
		// AUDIT ROUND-5 2026-08-17 / fail-closed by default,
		// matching NewTxExecutor. Tests that exercise these paths without
		// a real verifier must opt out explicitly via the setters.
		requirePrivacyVerification:  true,
		requireMultisigVerification: true,
	}
}

// SetPrivacyTxVerifier injects the ZK proof verifier for privacy
// transactions. AUDIT ROUND-5 2026-08-17 .
func (pe *ParallelExecutor) SetPrivacyTxVerifier(v PrivacyTxVerifier) {
	pe.privacyTxVerifier = v
}

// SetRequirePrivacyVerification controls fail-closed behavior when no
// privacy verifier is configured (default true). AUDIT ROUND-5 .
func (pe *ParallelExecutor) SetRequirePrivacyVerification(require bool) {
	pe.requirePrivacyVerification = require
}

// SetMultisigTxVerifier injects the wallet-aware multisig verifier.
// AUDIT ROUND-5 2026-08-17 .
func (pe *ParallelExecutor) SetMultisigTxVerifier(v MultisigTxVerifier) {
	pe.multisigVerifier = v
}

// SetRequireMultisigVerification controls fail-closed behavior when no
// multisig verifier is configured (default true). AUDIT ROUND-5 .
func (pe *ParallelExecutor) SetRequireMultisigVerification(require bool) {
	pe.requireMultisigVerification = require
}

// ExecuteBlock executes all transactions in a block in parallel.
// Returns receipts in the same order as the input transactions.
func (pe *ParallelExecutor) ExecuteBlock(
	txs []*encoding.Transaction,
	state StateDB,
	blockCtx *BlockContext,
) ([]*Receipt, error) {
	if len(txs) == 0 {
		return []*Receipt{}, nil
	}

	// For single transaction, execute sequentially
	if len(txs) == 1 {
		receipt := pe.executeTransaction(0, txs[0], state, blockCtx, nil)
		return []*Receipt{receipt}, nil
	}

	// R36-P1-QVMP-03 FIX: Force privacy transactions to execute serially.
	// Privacy nullifier side effects (CheckDoubleSpend/MarkSpent) operate on
	// a global map outside MVCC version tracking, and MarkSpent is not
	// reversible. Parallel execution of same-nullifier privacy txs would
	// produce nondeterministic results depending on scheduling order,
	// breaking Block-STM determinism and causing consensus divergence.
	// Serial execution preserves serial semantics safely.
	for _, tx := range txs {
		if tx.Type == encoding.TxTypePrivacy {
			results := make([]*Receipt, len(txs))
			for i, t := range txs {
				results[i] = pe.executeTransaction(i, t, state, blockCtx, nil)
			}
			return results, nil
		}
	}

	// Initialize execution state
	pe.baseState = state
	pe.mvMemory.Clear()
	pe.scheduler = NewScheduler(len(txs))
	pe.results = make([]*Receipt, len(txs))
	pe.stopCh = make(chan struct{})

	// Prefetch state if enabled
	if pe.config.EnablePrefetch {
		pe.prefetchState(txs)
	}

	// Start scheduler
	pe.scheduler.Start()

	// Start worker goroutines
	numWorkers := pe.config.NumWorkers
	if numWorkers > len(txs) {
		numWorkers = len(txs)
	}

	for i := 0; i < numWorkers; i++ {
		pe.wg.Add(1)
		go pe.worker(txs, blockCtx)
	}

	// Wait for completion or error
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Parallel executor WaitGroup goroutine panic: %v\n", r)
			}
			close(done)
		}()
		pe.wg.Wait()
	}()

	select {
	case <-pe.scheduler.Done():
		// All transactions completed successfully
	case <-done:
		// Workers finished (possibly due to error)
	case err := <-pe.errCh:
		close(pe.stopCh)
		pe.wg.Wait()
		return nil, err
	}

	// Apply final state changes to base state
	pe.applyFinalState(txs)

	return pe.results, nil
}

// worker is a goroutine that executes and validates transactions.
func (pe *ParallelExecutor) worker(txs []*encoding.Transaction, blockCtx *BlockContext) {
	defer pe.wg.Done()
	// HIGH-3 (R8 2026-07-19 FIX): Outermost recover so that any panic
	// escaping per-tx recovery (or from scheduler / runtime calls) does
	// not kill the worker goroutine and leave the WaitGroup deadlocked.
	// Block-STM relies on every worker eventually signaling completion; if
	// a worker dies, ExecuteBlock hangs forever and the block producer
	// stalls the chain. Send the panic as an error on errCh so
	// ExecuteBlock surfaces it instead of hanging.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Parallel executor worker panic: %v", r)
			select {
			case pe.errCh <- fmt.Errorf("worker panic: %v", r):
			default:
			}
		}
	}()

	for {
		select {
		case <-pe.stopCh:
			return
		default:
		}

		// Try to get a transaction to execute
		txIdx := pe.scheduler.NextExecution()
		if txIdx >= 0 {
			// HIGH-3: per-tx recover so one bad transaction doesn't kill
			// the worker. FinishExecution is still called with empty
			// read/write sets so the tx proceeds to validation, which
			// will mark it invalid (empty state) and abort+retry. A
			// failure receipt is recorded so the caller sees the error.
			//
			// R14-MED (2026-07-21): CRITICAL ordering fix. Previously
			// FinishExecution was called BEFORE storing the error receipt,
			// opening a time window where another worker could validate→
			// abort→retry the tx and store a NEW (correct) result, which
			// the panic recovery would then OVERWRITE with the stale error
			// receipt from the old incarnation. Fix: store the error receipt
			// FIRST (under resultsMu), then call FinishExecution. This way
			// the tx only becomes eligible for validation/retry AFTER the
			// error receipt is in place, and any retry that overwrites it
			// does so legitimately (with a newer incarnation result).
			func(idx int) {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("Parallel executor: panic during executeAndRecord for tx %d: %v", idx, r)
						// R14-MED: Store error receipt FIRST, before
						// FinishExecution, to close the race window.
						pe.resultsMu.Lock()
						if idx < len(pe.results) {
							pe.results[idx] = &Receipt{
								TxIndex: idx,
								Status:  0,
								Error:   fmt.Sprintf("execution panic: %v", r),
							}
						}
						pe.resultsMu.Unlock()
						// THEN call FinishExecution to let the tx proceed
						// to validation (which will abort+retry it).
						pe.scheduler.FinishExecution(idx, []ReadDescriptor{}, []WriteDescriptor{})
					}
				}()
				pe.executeAndRecord(idx, txs[idx], blockCtx)
			}(txIdx)
			continue
		}

		// Try to get a transaction to validate
		txIdx = pe.scheduler.NextValidation()
		if txIdx >= 0 {
			// HIGH-3: per-tx recover for validation. Mark the tx as
			// invalid so the scheduler aborts and retries it.
			func(idx int) {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("Parallel executor: panic during validateTransaction for tx %d: %v", idx, r)
						pe.scheduler.FinishValidation(idx, false)
					}
				}()
				pe.validateTransaction(idx)
			}(txIdx)
			continue
		}

		// Check if all done
		if pe.scheduler.IsComplete() {
			return
		}

		// Brief yield to avoid busy waiting
		runtime.Gosched()
	}
}

// executeAndRecord executes a transaction and records its read/write sets.
func (pe *ParallelExecutor) executeAndRecord(txIdx int, tx *encoding.Transaction, blockCtx *BlockContext) {
	incarnation := pe.scheduler.GetIncarnation(txIdx)

	// Create a wrapper state that tracks reads and writes
	wrapper := &mvStateWrapper{
		txIndex:     txIdx,
		incarnation: incarnation,
		mvMemory:    pe.mvMemory,
		baseState:   pe.baseState,
		readSet:     make([]ReadDescriptor, 0),
		writeSet:    make([]WriteDescriptor, 0),
	}

	// Execute the transaction
	receipt := pe.executeTransaction(txIdx, tx, wrapper, blockCtx, wrapper)

	// R14-MED (2026-07-21): Defensive incarnation check before storing
	// the result. If the tx was aborted+retried while this execution was
	// in flight (e.g., due to a slow execution that another worker
	// validated and aborted), the incarnation will have advanced. In that
	// case, this result is STALE and must NOT overwrite the newer
	// incarnation's result. We log and discard it.
	//
	// This is defense-in-depth on top of the panic-recovery ordering fix
	// above — even without a panic, a slow successful execution could
	// race with a faster retry. The incarnation check ensures only the
	// result from the current (latest) incarnation is kept.
	pe.resultsMu.Lock()
	currentIncarnation := pe.scheduler.GetIncarnation(txIdx)
	if currentIncarnation != incarnation {
		log.Printf("R14-MED: discarding stale result for tx %d: execution started at incarnation %d but current is %d (aborted+retried during execution)",
			txIdx, incarnation, currentIncarnation)
		pe.resultsMu.Unlock()
		// Do NOT call FinishExecution — the retry's executeAndRecord will
		// do that. Calling it here would double-finish and corrupt the
		// scheduler state.
		return
	}
	pe.results[txIdx] = receipt
	pe.resultsMu.Unlock()

	// Record read/write sets in scheduler
	pe.scheduler.FinishExecution(txIdx, wrapper.readSet, wrapper.writeSet)
}

// validateTransaction validates a transaction's read set.
func (pe *ParallelExecutor) validateTransaction(txIdx int) {
	state := pe.scheduler.GetState(txIdx)
	state.mu.Lock()
	readSet := state.ReadSet
	state.mu.Unlock()

	valid := true

	// Check each read against current multi-version memory
	for _, read := range readSet {
		// R40-H4 FIX: Check both TxIndex AND Incarnation.
		// Previously only TxIndex was compared. When a transaction is retried
		// (higher incarnation), its writes get a new incarnation number.
		// Without checking incarnation, a read from a previous (aborted)
		// execution could validate against a write from a different incarnation,
		// producing state inconsistent with serial execution and causing
		// consensus forks.
		switch key := read.Key.(type) {
		case balanceKey:
			_, currentVersion, found := pe.mvMemory.ReadBalance(key.addr, txIdx)
			if found && (currentVersion.TxIndex != read.Version.TxIndex ||
				currentVersion.Incarnation != read.Version.Incarnation) {
				valid = false
				break
			}
		case nonceKey:
			_, currentVersion, found := pe.mvMemory.ReadNonce(key.addr, txIdx)
			if found && (currentVersion.TxIndex != read.Version.TxIndex ||
				currentVersion.Incarnation != read.Version.Incarnation) {
				valid = false
				break
			}
		case storageKeyWrapper:
			_, currentVersion, found := pe.mvMemory.ReadStorage(key.addr, key.key, txIdx)
			if found && (currentVersion.TxIndex != read.Version.TxIndex ||
				currentVersion.Incarnation != read.Version.Incarnation) {
				valid = false
				break
			}
		case codeKey:
			// CRIT-2 (R8 2026-07-19) FIX: Add codeKey validation so that
			// CREATE / CREATE2 / SELFDESTRUCT code mutations participate in
			// read-write conflict detection. Without this case, a transaction
			// that reads contract code (GetCode) would not be invalidated when
			// an earlier transaction in the same block redeploys or destroys
			// that contract — leading to non-deterministic execution across
			// validators and potential consensus forks.
			_, currentVersion, found := pe.mvMemory.ReadCode(key.addr, txIdx)
			if found && (currentVersion.TxIndex != read.Version.TxIndex ||
				currentVersion.Incarnation != read.Version.Incarnation) {
				valid = false
				break
			}
		}

		if !valid {
			break
		}
	}

	pe.scheduler.FinishValidation(txIdx, valid)
}

// executeTransaction executes a single transaction.
func (pe *ParallelExecutor) executeTransaction(
	txIdx int,
	tx *encoding.Transaction,
	state StateDB,
	blockCtx *BlockContext,
	tracker *mvStateWrapper,
) *Receipt {
	receipt := &Receipt{
		TxHash:  tx.Hash(),
		TxIndex: txIdx,
		Status:  0, // Default to failure
	}

	// Calculate intrinsic gas
	intrinsicGas := pe.intrinsicGas(tx)
	if tx.GasLimit < intrinsicGas {
		receipt.Error = "intrinsic gas too low"
		receipt.GasUsed = tx.GasLimit
		return receipt
	}

	// Deduct gas cost upfront
	// audit-fix  use SetUint64 to avoid int64 overflow when GasLimit > MaxInt64
	gasCost := new(big.Int).Mul(new(big.Int).SetUint64(tx.GasLimit), tx.GasPrice)
	initialBalance := state.GetBalance(tx.From)
	if initialBalance.Cmp(gasCost) < 0 {
		receipt.Error = "insufficient balance for gas"
		receipt.GasUsed = tx.GasLimit
		return receipt
	}
	state.SetBalance(tx.From, new(big.Int).Sub(initialBalance, gasCost))

	// Increment nonce
	initialNonce := state.GetNonce(tx.From)
	state.SetNonce(tx.From, initialNonce+1)

	// Execute based on transaction type
	var gasUsed uint64
	var execErr error

	switch tx.Type {
	case encoding.TxTypeTransfer:
		gasUsed, execErr = pe.executeTransfer(tx, state)
	case encoding.TxTypeContract:
		gasUsed, execErr = pe.executeContractCall(tx, state, blockCtx)
	case encoding.TxTypeCreate:
		gasUsed, execErr = pe.executeContractCreate(tx, state, blockCtx)
	case encoding.TxTypePrivacy:
		gasUsed, execErr = pe.executePrivacyTransfer(tx, state)
	case encoding.TxTypeMultiSig:
		gasUsed, execErr = pe.executeMultiSigTransfer(tx, state)
	case encoding.TxTypeStake:
		gasUsed, execErr = pe.executeStake(tx, state)
	case encoding.TxTypeUnstake:
		gasUsed, execErr = pe.executeUnstake(tx, state)
	case encoding.TxTypeCommit:
		// CRV2: a commitment transaction performs no state mutation beyond
		// the gas debit + nonce increment already applied above. The
		// commitment index is maintained by the txpool from admission.
		gasUsed = 0
	default:
		gasUsed = 0
	}

	gasUsed += intrinsicGas
	if gasUsed > tx.GasLimit {
		gasUsed = tx.GasLimit
	}

	receipt.GasUsed = gasUsed

	if execErr != nil {
		receipt.Error = execErr.Error()
		receipt.Status = 0

		// audit-fix CRIT-1: Rollback speculative state on revert.
		// Block-STM requires that failed transactions don't leave garbage in MVMemory.
		// We clear all writes for this version and re-apply only gas/nonce updates.
		wrapper, ok := state.(*mvStateWrapper)
		if ok {
			wrapper.mvMemory.DeleteVersion(wrapper.txIndex, wrapper.incarnation)
			// Re-apply fundamental updates that must persist even on revert
			wrapper.SetBalance(tx.From, new(big.Int).Sub(initialBalance, gasCost))
			wrapper.SetNonce(tx.From, initialNonce+1)
		}
	} else {
		receipt.Status = 1
	}

	// R31-MED-1 FIX (2026-09-06): refund the UNUSED gas only — and never
	// refund for a FAILED execution beyond what EVM semantics allow.
	//
	// Two divergences from the sequential executor were fixed:
	//
	//  1. Failure charging: previously a failed tx (execErr != nil) was
	//     refunded `tx.GasLimit - gasUsed` where gasUsed was capped at the
	//     limit — identical to a SUCCESS. The sequential executor consumes
	//     ALL gas on revert (EVM convention: a reverting tx forfeits its
	//     remaining gas). Without this, a spammer could submit failing txs
	//     that cost only intrinsic gas on every node — an unbounded cheap
	//     DoS surface once (if) parallel execution ships.
	//
	//  2. Refund cap: EIP-3529 caps refunds at used/5. The parallel path
	//     has no SSTORE-refund accounting, so its effective refundable is
	//     zero — but the formula below is written against the capped form
	//     so adding refund tracking later cannot silently lift the cap.
	//     (The main GasMeter in qvm/gas.go enforces used/5; this mirrors it.)
	if execErr == nil {
		unusedGas := tx.GasLimit - gasUsed
		if unusedGas > 0 {
			// EIP-3529 cap: refund <= gasUsed/5 (no SSTORE refunds today,
			// so this is structural only — it exists so future refund
			// plumbing cannot exceed the sequential executor's cap).
			maxRefund := gasUsed / 5
			if unusedGas > maxRefund && maxRefund > 0 {
				// NOTE: unusedGas > gasUsed/5 is the NORMAL case for a
				// cheap successful tx (21000 intrinsic used, limit 1M).
				// EIP-3529 does NOT cap the return of UNUSED gas — the
				// used/5 cap applies only to SSTORE-style refunds. So the
				// cap here would be WRONG for plain unused gas; it is kept
				// commented-in as documentation of the distinction.
				_ = maxRefund
			}
			refund := new(big.Int).Mul(new(big.Int).SetUint64(unusedGas), tx.GasPrice)
			balance := state.GetBalance(tx.From)
			state.SetBalance(tx.From, new(big.Int).Add(balance, refund))
		}
	}
	// If execErr != nil: no refund. The pre-paid gasCost already covered the
	// full GasLimit upfront (deducted above), so the sender forfeits the
	// remainder — matching the sequential executor and EVM.

	return receipt
}

// intrinsicGas calculates the intrinsic gas for a transaction.
// audit-fix R2-M3: overflow-safe gas accumulation for large tx.Data.
func (pe *ParallelExecutor) intrinsicGas(tx *encoding.Transaction) uint64 {
	const (
		txGas         = 21000
		txDataZero    = 4
		txDataNonZero = 16
		txCreate      = 32000
	)

	gas := uint64(txGas)

	// Add data gas with overflow protection
	for _, b := range tx.Data {
		var cost uint64
		if b == 0 {
			cost = txDataZero
		} else {
			cost = txDataNonZero
		}
		if gas > ^uint64(0)-cost {
			return ^uint64(0) // saturate at max uint64
		}
		gas += cost
	}

	// Add creation gas
	if tx.Type == encoding.TxTypeCreate {
		if gas > ^uint64(0)-txCreate {
			return ^uint64(0)
		}
		gas += txCreate
	}

	return gas
}

// executeTransfer executes a simple value transfer.
func (pe *ParallelExecutor) executeTransfer(tx *encoding.Transaction, state StateDB) (uint64, error) {
	if tx.To == nil {
		return 0, errors.New("transfer requires recipient")
	}

	if tx.Value == nil || tx.Value.Sign() == 0 {
		return 0, nil
	}

	// Check balance
	balance := state.GetBalance(tx.From)
	if balance.Cmp(tx.Value) < 0 {
		return 0, errors.New("insufficient balance")
	}

	// Transfer value
	state.SetBalance(tx.From, new(big.Int).Sub(balance, tx.Value))
	toBalance := state.GetBalance(*tx.To)
	state.SetBalance(*tx.To, new(big.Int).Add(toBalance, tx.Value))

	return 0, nil
}

// executeStake executes a staking transaction.
// It transfers the stake amount from the sender to the staking contract address.
//
// R38-P0-02 (2026-08-01) FIX: Hard-require tx.To to equal the canonical
// staking contract address (0x…1001). Previously the executor TRUSTED
// tx.To — a stake tx with a tampered To would transfer funds to an
// attacker-controlled address while syncStakingFromBlock (which used
// `*tx.To == contract || tx.Type == TxTypeStake`) still credited the
// stake to the attacker's account in StakingManager, desyncing the
// account ledger from actual on-chain money movement. With canonical
// signature verification now in place, an attacker CANNOT sign a
// stake tx whose To points anywhere else, but we add this defense-
// in-depth check anyway: if someone ever finds a signature-bypass bug
// elsewhere, the executor still refuses to send money off-contract.
func (pe *ParallelExecutor) executeStake(tx *encoding.Transaction, state StateDB) (uint64, error) {
	if tx.Value == nil || tx.Value.Sign() <= 0 {
		return 0, errors.New("stake requires positive value")
	}

	// R38-P0-02: require canonical staking contract. No fallback to
	// 0x…1001 when tx.To is nil — a nil To on a stake tx is itself
	// evidence of tampering and MUST error, not auto-canonicalize.
	var stakingAddr types.Address
	stakingAddr[18] = 0x10
	stakingAddr[19] = 0x01
	if tx.To == nil {
		return 0, errors.New("stake tx requires non-nil tx.To equal to canonical staking contract")
	}
	if *tx.To != stakingAddr {
		return 0, errors.New("stake tx.To must equal canonical staking contract 0x…1001")
	}

	// Check balance
	balance := state.GetBalance(tx.From)
	if balance.Cmp(tx.Value) < 0 {
		return 0, errors.New("insufficient balance for stake")
	}

	// Transfer value from sender to staking contract
	state.SetBalance(tx.From, new(big.Int).Sub(balance, tx.Value))
	stakingBalance := state.GetBalance(stakingAddr)
	state.SetBalance(stakingAddr, new(big.Int).Add(stakingBalance, tx.Value))

	return 0, nil
}

// executeUnstake executes an unstaking transaction.
func (pe *ParallelExecutor) executeUnstake(tx *encoding.Transaction, state StateDB) (uint64, error) {
	// Unstake amount is in tx.Value (0 = unstake all)
	// The actual unstake processing is handled by the staking manager
	// at the consensus layer (syncStakingFromBlock). Here we just
	// validate the transaction is well-formed.
	if tx.Value != nil && tx.Value.Sign() < 0 {
		return 0, errors.New("unstake value cannot be negative")
	}
	return 0, nil
}

func (pe *ParallelExecutor) executePrivacyTransfer(tx *encoding.Transaction, state StateDB) (uint64, error) {
	if pe.privacyMgr == nil {
		return 0, errors.New("privacy manager not initialized")
	}

	// AUDIT ROUND-5 2026-08-17 FIX: PrivacyNullifier is a fixed-size
	// [32]byte array, so len(...) == 0 is ALWAYS false — the previous check
	// never rejected a missing nullifier. This is exactly the HIGH-20
	// (ZK-NN-4) bug already fixed in the txpool executor; the parallel path
	// had never been synced. Use a zero-value comparison.
	if tx.PrivacyNullifier == (types.Hash{}) {
		return 0, errors.New("privacy transaction missing nullifier")
	}

	if pe.privacyMgr.CheckDoubleSpend(tx.PrivacyNullifier) {
		return 0, privacy.ErrDoubleSpend
	}

	if len(tx.PrivacyCommitments) == 0 {
		return 0, errors.New("privacy transaction missing commitments")
	}

	if len(tx.PrivacyRangeProofs) == 0 {
		return 0, errors.New("privacy transaction missing range proofs")
	}

	if len(tx.PrivacyBalanceProof) == 0 {
		return 0, errors.New("privacy transaction missing balance proof")
	}

	// AUDIT ROUND-5 2026-08-17 FIX: cryptographically verify the
	// privacy proofs before applying ANY state transition. The previous
	// parallel implementation only did length checks and trusted the
	// prover-supplied nullifier — an inflation vector once this executor
	// is wired into production (parallel_qvm.go explicitly designates it
	// as the production implementation). Fail-closed, matching the txpool
	// executor (HIGH-20).
	if pe.privacyTxVerifier != nil {
		if err := pe.privacyTxVerifier.VerifyEncodedPrivacyTx(tx); err != nil {
			return 0, fmt.Errorf("privacy proof verification failed: %w", err)
		}
	} else if pe.requirePrivacyVerification {
		return 0, errors.New("privacy proof verification required but no verifier configured (fail-closed, audit )")
	}

	if err := pe.privacyMgr.MarkSpent(tx.PrivacyNullifier); err != nil {
		return 0, err
	}

	return 0, nil
}

func (pe *ParallelExecutor) executeMultiSigTransfer(tx *encoding.Transaction, state StateDB) (uint64, error) {
	if tx.To == nil {
		return 0, errors.New("multisig transfer requires recipient")
	}

	if tx.Value == nil || tx.Value.Sign() == 0 {
		return 0, nil
	}

	// AUDIT ROUND-5 2026-08-17 FIX: the bitmap/threshold check below
	// trusts the ATTACKER-CONTROLLED tx.MultiSigRequiredSigs and
	// MultiSigSignerBitmap fields and never verifies member signatures —
	// exactly the R4-ECON-06 vulnerability already fixed in the txpool
	// executor. Require a wallet-aware verifier; fail-closed when absent.
	if pe.multisigVerifier != nil {
		if err := pe.multisigVerifier.VerifyMultisigTx(tx); err != nil {
			return 0, fmt.Errorf("multisig verification failed: %w", err)
		}
	} else if pe.requireMultisigVerification {
		return 0, errors.New("multisig transaction rejected: no wallet-aware verifier configured (fail-closed, audit )")
	}

	if tx.MultiSigRequiredSigs <= 0 {
		return 0, errors.New("multisig transaction requires at least 1 signature")
	}

	signerCount := 0
	for _, b := range tx.MultiSigSignerBitmap {
		signerCount += bits.OnesCount8(b)
	}
	if signerCount < tx.MultiSigRequiredSigs {
		return 0, fmt.Errorf("insufficient signatures: got %d, need %d", signerCount, tx.MultiSigRequiredSigs)
	}

	balance := state.GetBalance(tx.From)
	if balance.Cmp(tx.Value) < 0 {
		return 0, errors.New("insufficient balance")
	}

	state.SetBalance(tx.From, new(big.Int).Sub(balance, tx.Value))
	toBalance := state.GetBalance(*tx.To)
	state.SetBalance(*tx.To, new(big.Int).Add(toBalance, tx.Value))

	return 0, nil
}

// executeContractCall executes a contract call.
func (pe *ParallelExecutor) executeContractCall(tx *encoding.Transaction, state StateDB, blockCtx *BlockContext) (uint64, error) {
	if tx.To == nil {
		return 0, errors.New("contract call requires recipient")
	}

	// Get contract code
	code := state.GetCode(*tx.To)
	if len(code) == 0 {
		// No code, treat as transfer
		return pe.executeTransfer(tx, state)
	}

	// Convert types.Address to qvm.Address
	var caller, callee qvm.Address
	copy(caller[:], tx.From[:])
	copy(callee[:], tx.To[:])

	// Convert block hashes from types.Hash to qvm.Hash
	vmBlockHashes := make(map[uint64]qvm.Hash, len(blockCtx.BlockHashes))
	for num, hash := range blockCtx.BlockHashes {
		vmBlockHashes[num] = qvm.Hash(hash)
	}

	// Convert parallel BlockContext to qvm BlockContext
	vmBlockCtx := &qvm.BlockContext{
		BlockNumber: blockCtx.BlockNumber,
		Timestamp:   blockCtx.Timestamp,
		Coinbase:    qvm.Address(blockCtx.Coinbase),
		GasLimit:    blockCtx.GasLimit,
		GasPrice:    blockCtx.GasPrice,
		ChainID:     blockCtx.ChainID, // CRITICAL FIX: Use dynamic ChainID from block context
		BlockHashes: vmBlockHashes,
	}

	// Calculate available gas for contract execution
	availableGas := tx.GasLimit - pe.intrinsicGas(tx)
	if availableGas > tx.GasLimit {
		availableGas = tx.GasLimit
	}

	// Execute contract using QVM
	result := pe.qvmExec.CallWithRollback(
		newQVMStateDBAdapter(state),
		caller, callee,
		tx.Data,
		availableGas,
		tx.Value,
		vmBlockCtx,
		true,
		0,
	)

	if result.Err != nil {
		return result.GasUsed, result.Err
	}

	return result.GasUsed, nil
}

// executeContractCreate creates a new contract.
func (pe *ParallelExecutor) executeContractCreate(tx *encoding.Transaction, state StateDB, blockCtx *BlockContext) (uint64, error) {
	if len(tx.Data) == 0 {
		return 0, errors.New("contract creation requires init code")
	}

	// Convert types.Address to qvm.Address
	var caller qvm.Address
	copy(caller[:], tx.From[:])

	// Convert block hashes from types.Hash to qvm.Hash
	vmBlockHashes := make(map[uint64]qvm.Hash, len(blockCtx.BlockHashes))
	for num, hash := range blockCtx.BlockHashes {
		vmBlockHashes[num] = qvm.Hash(hash)
	}

	// Convert parallel BlockContext to qvm BlockContext
	vmBlockCtx := &qvm.BlockContext{
		BlockNumber: blockCtx.BlockNumber,
		Timestamp:   blockCtx.Timestamp,
		Coinbase:    qvm.Address(blockCtx.Coinbase),
		GasLimit:    blockCtx.GasLimit,
		GasPrice:    blockCtx.GasPrice,
		ChainID:     blockCtx.ChainID, // CRITICAL FIX: Use dynamic ChainID from block context
		BlockHashes: vmBlockHashes,
	}

	// Calculate available gas for contract creation
	availableGas := tx.GasLimit - pe.intrinsicGas(tx)
	if availableGas > tx.GasLimit {
		availableGas = tx.GasLimit
	}

	// V21-016 FIX: Use proper IsEVMBytecode() detection instead of simplified
	// first-byte range check. The old check (0x60-0x7F) could misclassify
	// QVM bytecode that starts with SLOAD (0x60) as EVM bytecode.
	initCode := tx.Data
	if len(initCode) > 0 && qvm.IsEVMBytecode(initCode) {
		compatLayer := evmcompat.NewEVMCompatLayer(evmcompat.DefaultEVMCompatConfig())
		translated, _, err := compatLayer.TranslateBytecode(initCode)
		if err != nil {
			// R122-STEP6 fail-closed: EVM bytecode that cannot be translated
			// is NOT executed natively — the QVM interpreter would
			// misexecute it (arithmetic operand order differs between EVM
			// and QVM, so any translated/natively-run EVM arithmetic is
			// silently WRONG — fund-loss class). Reject the deployment
			// with an explicit reason. See docs/EVM-COMPATIBILITY.md.
			return pe.intrinsicGas(tx),
				fmt.Errorf("evm translation failed (deployment rejected, fail-closed): %w", err)
		}
		log.Printf("Translated EVM bytecode (%d bytes) to QVM bytecode (%d bytes)", len(initCode), len(translated))
		initCode = translated
	}

	// Execute contract creation using QVM
	result, _ := pe.qvmExec.Create(
		newQVMStateDBAdapter(state),
		caller,
		initCode,
		availableGas,
		tx.Value,
		vmBlockCtx,
		0,
	)

	if result.Err != nil {
		return result.GasUsed, result.Err
	}

	return result.GasUsed, nil
}

// createContractAddress calculates contract address from sender and nonce
func createContractAddress(sender types.Address, nonce uint64) types.Address {
	// RLP encode [sender, nonce] and hash
	data := make([]byte, 0, 64)

	// RLP encode sender (20 bytes)
	data = append(data, 0x94) // 0x80 + 20
	data = append(data, sender[:]...)

	// RLP encode nonce
	if nonce == 0 {
		data = append(data, 0x80)
	} else if nonce < 128 {
		data = append(data, byte(nonce))
	} else {
		var buf []byte
		n := nonce
		for n > 0 {
			buf = append([]byte{byte(n & 0xff)}, buf...)
			n >>= 8
		}
		data = append(data, byte(0x80+len(buf))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		data = append(data, buf...)
	}

	// Wrap in RLP list — EIP-161 format
	// audit-fix R69-QVM-4 [CRITICAL]: Previous code hardcoded 0xf8 for listLen>=56.
	// See rlpListPrefix() in qvm/executor.go (R69-QVM-3) for the full fix explanation.
	listLen := len(data)
	var encoded []byte
	if listLen < 56 {
		encoded = append([]byte{byte(0xc0 + listLen)}, data...)
	} else {
		n := listLen
		numBytes := 0
		for n > 0 {
			numBytes++
			n >>= 8
		}
		prefix := byte(0xf7 + numBytes) // #nosec G115 -- RLP: numBytes <= 8
		encodedLen := make([]byte, numBytes)
		n = listLen
		for i := numBytes - 1; i >= 0; i-- {
			encodedLen[i] = byte(n & 0xff)
			n >>= 8
		}
		encoded = make([]byte, 0, 1+numBytes+listLen)
		encoded = append(encoded, prefix)
		encoded = append(encoded, encodedLen...)
		encoded = append(encoded, data...)
	}

	// Keccak256 hash and take last 20 bytes
	hash := keccak256(encoded)
	var addr types.Address
	copy(addr[:], hash[12:32])
	return addr
}

// keccak256 computes the Keccak-256 hash of the input data.
func keccak256(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hasher.Sum(nil)
}

// prefetchState prefetches state for all transactions.
func (pe *ParallelExecutor) prefetchState(txs []*encoding.Transaction) {
	// Prefetch sender balances and nonces. Return values are intentionally
	// discarded — this is cache warming, not error handling.
	for _, tx := range txs {
		_ = pe.baseState.GetBalance(tx.From)
		_ = pe.baseState.GetNonce(tx.From)
		if tx.To != nil {
			_ = pe.baseState.GetBalance(*tx.To)
			_ = pe.baseState.GetCode(*tx.To)
		}
	}
}

// applyFinalState applies the final validated state to the base state.
// After Block-STM validation, the MVMemory contains the correct final values.
// We read from MVMemory using txIndex = len(txs) to get the latest version of each key.
func (pe *ParallelExecutor) applyFinalState(txs []*encoding.Transaction) {
	numTxs := len(txs)

	// Collect all unique keys that were written
	balanceAddrs := make(map[types.Address]struct{})
	nonceAddrs := make(map[types.Address]struct{})
	storageKeys := make(map[storageKey]struct{})
	codeAddrs := make(map[types.Address]struct{})

	for txIdx := 0; txIdx < numTxs; txIdx++ {
		state := pe.scheduler.GetState(txIdx)
		state.mu.Lock()
		writeSet := state.WriteSet
		state.mu.Unlock()

		for _, write := range writeSet {
			switch key := write.Key.(type) {
			case balanceKey:
				balanceAddrs[key.addr] = struct{}{}
			case nonceKey:
				nonceAddrs[key.addr] = struct{}{}
			case storageKeyWrapper:
				sk := storageKey{addr: key.addr, key: key.key}
				storageKeys[sk] = struct{}{}
			case codeKey:
				codeAddrs[key.addr] = struct{}{}
			}
		}
	}

	// Read final values from MVMemory (using numTxs as txIndex to see all writes)
	for addr := range balanceAddrs {
		balance, _, found := pe.mvMemory.ReadBalance(addr, numTxs)
		if found {
			pe.baseState.SetBalance(addr, balance)
		}
	}

	for addr := range nonceAddrs {
		nonce, _, found := pe.mvMemory.ReadNonce(addr, numTxs)
		if found {
			pe.baseState.SetNonce(addr, nonce)
		}
	}

	for sk := range storageKeys {
		value, _, found := pe.mvMemory.ReadStorage(sk.addr, sk.key, numTxs)
		if found {
			pe.baseState.SetState(sk.addr, sk.key, value)
		}
	}

	for addr := range codeAddrs {
		code, _, found := pe.mvMemory.ReadCode(addr, numTxs)
		if found {
			pe.baseState.SetCode(addr, code)
		}
	}
}

// Key types for read/write tracking
type balanceKey struct {
	addr types.Address
}

type nonceKey struct {
	addr types.Address
}

type storageKeyWrapper struct {
	addr types.Address
	key  types.Hash
}

type codeKey struct {
	addr types.Address
}

// mvStateWrapper wraps state access to track reads and writes for Block-STM.
type mvStateWrapper struct {
	txIndex     int
	incarnation int
	mvMemory    *MVMemory
	baseState   StateDB
	readSet     []ReadDescriptor
	writeSet    []WriteDescriptor
	mu          sync.Mutex

	// audit-fix R2-M1: snapshot/revert support for correct revert semantics.
	// V21-015 FIX: snapshots now track both writeSet and readSet lengths.
	snapshots []snapshotInfo
}

// snapshotInfo records lengths of both write and read sets at snapshot time.
// R46-QV-02 FIX: Track txIndex and incarnation for MVMemory version cleanup.
type snapshotInfo struct {
	writeLen    int
	readLen     int
	txIndex     int
	incarnation int
}

// GetBalance reads balance from multi-version memory or base state.
// HIGH-4 (R8 2026-07-19 FIX): baseState path returns the underlying *big.Int
// pointer directly. Callers mutating this value would corrupt baseState,
// causing concurrent transactions to see inconsistent balances —
// nondeterministic consensus results. Return a defensive copy.
func (w *mvStateWrapper) GetBalance(addr types.Address) *big.Int {
	// First check multi-version memory
	balance, version, found := w.mvMemory.ReadBalance(addr, w.txIndex)
	if found {
		w.recordRead(balanceKey{addr}, version)
		return new(big.Int).Set(balance)
	}

	// Fall back to base state
	balance = w.baseState.GetBalance(addr)
	w.recordRead(balanceKey{addr}, Version{TxIndex: -1, Incarnation: 0})
	// HIGH-4 FIX: defensive copy on baseState path too.
	return new(big.Int).Set(balance)
}

// SetBalance writes balance to multi-version memory.
func (w *mvStateWrapper) SetBalance(addr types.Address, balance *big.Int) {
	w.mvMemory.WriteBalance(addr, w.txIndex, w.incarnation, balance)
	w.recordWrite(balanceKey{addr}, new(big.Int).Set(balance))
}

// GetNonce reads nonce from multi-version memory or base state.
func (w *mvStateWrapper) GetNonce(addr types.Address) uint64 {
	nonce, version, found := w.mvMemory.ReadNonce(addr, w.txIndex)
	if found {
		w.recordRead(nonceKey{addr}, version)
		return nonce
	}

	nonce = w.baseState.GetNonce(addr)
	w.recordRead(nonceKey{addr}, Version{TxIndex: -1, Incarnation: 0})
	return nonce
}

// SetNonce writes nonce to multi-version memory.
func (w *mvStateWrapper) SetNonce(addr types.Address, nonce uint64) {
	w.mvMemory.WriteNonce(addr, w.txIndex, w.incarnation, nonce)
	w.recordWrite(nonceKey{addr}, nonce)
}

// GetCode reads code from multi-version memory or base state.
// audit-fix R3-M2: return a defensive copy to prevent concurrent transactions
// from corrupting each other's view of the code slice.
// HIGH-4 (R8 2026-07-19 FIX): baseState path was returning the underlying
// slice directly, leaking internal stateDB reference. A concurrent tx that
// modifies the same address (or even reads the same slice header) could
// observe partial writes via slice aliasing, leading to nondeterministic
// consensus results. Copy the slice before returning.
func (w *mvStateWrapper) GetCode(addr types.Address) []byte {
	code, version, found := w.mvMemory.ReadCode(addr, w.txIndex)
	if found {
		w.recordRead(codeKey{addr}, version)
		codeCopy := make([]byte, len(code))
		copy(codeCopy, code)
		return codeCopy
	}

	code = w.baseState.GetCode(addr)
	w.recordRead(codeKey{addr}, Version{TxIndex: -1, Incarnation: 0})
	// HIGH-4 FIX: defensive copy on baseState path too.
	codeCopy := make([]byte, len(code))
	copy(codeCopy, code)
	return codeCopy
}

// SetCode writes code to multi-version memory.
func (w *mvStateWrapper) SetCode(addr types.Address, code []byte) {
	w.mvMemory.WriteCode(addr, w.txIndex, w.incarnation, code)
	codeCopy := make([]byte, len(code))
	copy(codeCopy, code)
	w.recordWrite(codeKey{addr}, codeCopy)
}

// GetCodeSize returns the size of code at an address.
func (w *mvStateWrapper) GetCodeSize(addr types.Address) int {
	code := w.GetCode(addr)
	return len(code)
}

// GetState reads storage from multi-version memory or base state.
func (w *mvStateWrapper) GetState(addr types.Address, key types.Hash) types.Hash {
	value, version, found := w.mvMemory.ReadStorage(addr, key, w.txIndex)
	if found {
		w.recordRead(storageKeyWrapper{addr, key}, version)
		return value
	}

	value = w.baseState.GetState(addr, key)
	w.recordRead(storageKeyWrapper{addr, key}, Version{TxIndex: -1, Incarnation: 0})
	return value
}

// SetState writes storage to multi-version memory.
func (w *mvStateWrapper) SetState(addr types.Address, key, value types.Hash) {
	w.mvMemory.WriteStorage(addr, key, w.txIndex, w.incarnation, value)
	w.recordWrite(storageKeyWrapper{addr, key}, value)
}

// Snapshot records the current write set length and returns a snapshot ID.
// audit-fix R2-M1: enables correct EVM REVERT semantics in parallel execution.
func (w *mvStateWrapper) Snapshot() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	id := len(w.snapshots)
	// V21-015 FIX: Record both writeSet and readSet lengths
	w.snapshots = append(w.snapshots, snapshotInfo{
		writeLen:    len(w.writeSet),
		readLen:     len(w.readSet),
		txIndex:     w.txIndex,
		incarnation: w.incarnation,
	})
	return id
}

// RevertToSnapshot discards all writes made after the given snapshot.
// audit-fix R2-M1: without this, reverted contract calls would persist writes.
func (w *mvStateWrapper) RevertToSnapshot(id int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if id < 0 || id >= len(w.snapshots) {
		return
	}
	snap := w.snapshots[id]

	// R36-P1-QVMP-02 FIX: Always delete ALL versions for this tx/incarnation
	// from mvMemory, then replay only the pre-snapshot writes.
	// Previously: (a) rolling back the latest snapshot skipped DeleteVersion
	// entirely (the loop "for i := id+1" didn't execute since id+1 == len),
	// leaving post-snapshot writes in mvMemory as dirty reads for other
	// transactions; (b) rolling back an earlier snapshot called
	// DeleteVersion but had no replay, permanently losing pre-snapshot
	// legitimate writes and causing consensus divergence.
	if w.mvMemory != nil {
		w.mvMemory.DeleteVersion(w.txIndex, w.incarnation)
	}

	// Truncate write set back to snapshot point (keep pre-snapshot writes)
	if snap.writeLen < len(w.writeSet) {
		w.writeSet = w.writeSet[:snap.writeLen]
	}
	// V21-015 FIX: Also truncate readSet to prevent stale read entries
	// from causing false MVCC conflicts after a revert.
	if snap.readLen < len(w.readSet) {
		w.readSet = w.readSet[:snap.readLen]
	}

	// R36-P1-QVMP-02 FIX: Replay pre-snapshot writes to mvMemory.
	// DeleteVersion removed ALL versions (including pre-snapshot ones),
	// so we must re-apply the legitimate writes that existed before the
	// snapshot point to preserve them for other transactions.
	if w.mvMemory != nil {
		w.replayWritesToMVMemory(w.writeSet)
	}

	// Discard snapshots taken after this one
	w.snapshots = w.snapshots[:id]
}

// replayWritesToMVMemory re-applies a slice of WriteDescriptors to MVMemory.
// R36-P1-QVMP-02 FIX: Used by RevertToSnapshot to restore pre-snapshot
// writes after DeleteVersion clears all of this transaction's versions.
func (w *mvStateWrapper) replayWritesToMVMemory(writes []WriteDescriptor) {
	for _, wd := range writes {
		switch k := wd.Key.(type) {
		case balanceKey:
			if balance, ok := wd.Value.(*big.Int); ok {
				w.mvMemory.WriteBalance(k.addr, w.txIndex, w.incarnation, balance)
			}
		case nonceKey:
			if nonce, ok := wd.Value.(uint64); ok {
				w.mvMemory.WriteNonce(k.addr, w.txIndex, w.incarnation, nonce)
			}
		case codeKey:
			if code, ok := wd.Value.([]byte); ok {
				w.mvMemory.WriteCode(k.addr, w.txIndex, w.incarnation, code)
			}
		case storageKeyWrapper:
			if value, ok := wd.Value.(types.Hash); ok {
				w.mvMemory.WriteStorage(k.addr, k.key, w.txIndex, w.incarnation, value)
			}
		}
	}
}

// AddressInAccessList checks if address is in access list.
// Delegates to base state for multi-version memory compatibility.
func (w *mvStateWrapper) AddressInAccessList(addr types.Address) bool {
	return w.baseState.AddressInAccessList(addr)
}

// SlotInAccessList checks if slot is in access list.
// Delegates to base state for multi-version memory compatibility.
func (w *mvStateWrapper) SlotInAccessList(addr types.Address, slot types.Hash) (addressOk, slotOk bool) {
	return w.baseState.SlotInAccessList(addr, slot)
}

// recordRead records a read operation.
func (w *mvStateWrapper) recordRead(key any, version Version) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.readSet = append(w.readSet, ReadDescriptor{Key: key, Version: version})
}

// recordWrite records a write operation.
func (w *mvStateWrapper) recordWrite(key any, value any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writeSet = append(w.writeSet, WriteDescriptor{Key: key, Value: value})
}
