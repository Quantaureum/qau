// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

var (
	ErrInvalidChainID         = errors.New("invalid chain ID")
	ErrInvalidBatchSize       = errors.New("invalid batch size")
	ErrInvalidBlockTime       = errors.New("invalid block time")
	ErrInvalidChallengePeriod = errors.New("invalid challenge period")
	ErrInvalidGasLimit        = errors.New("invalid gas limit")
	ErrBatchFull              = errors.New("batch is full")
	ErrInsufficientTxs        = errors.New("insufficient transactions to build batch")
	ErrBatchNotFound          = errors.New("batch not found")
	ErrBatchAlreadySubmitted  = errors.New("batch already submitted")
	ErrBatchNotSubmitted      = errors.New("batch not submitted")
	ErrChallengePeriodNotOver = errors.New("challenge period not over")
	ErrRollupNotRunning       = errors.New("rollup not running")
	ErrRollupAlreadyRunning   = errors.New("rollup already running")
	ErrInvalidStateTransition = errors.New("invalid state transition")
	ErrFraudProofInvalid      = errors.New("invalid fraud proof")
	// AUDIT (2026) RLLP-FIX (CRITICAL): Returned by FinalizeBatch
	// when a valid fraud proof exists for the batch. Callers (finalizeLoop,
	// RPC) must NOT treat this as a transient error — the batch cannot be
	// finalized until the dispute is resolved. The batch has been
	// auto-transitioned to BatchStatusChallenged.
	ErrBatchChallenged = errors.New("batch has a fraud proof — finalization blocked")
)

type RollupStatus uint8

const (
	RollupStatusStopped  RollupStatus = 0
	RollupStatusRunning  RollupStatus = 1
	RollupStatusPaused   RollupStatus = 2
	RollupStatusStopping RollupStatus = 3
)

// WithdrawalProcessor is a hook invoked after a batch is finalized.
// W-P1-6 (L1↔L2 bridge) will implement this to release L1 withdrawals
// whose proof was anchored in the finalized batch. Until then it remains
// nil — finalizeLoop simply skips the withdrawal step.
// W-P1-5 FIX (2026-07-13)
type WithdrawalProcessor interface {
	// ProcessFinalizedBatch is called once per finalized batch. Errors are
	// logged but do NOT roll back the finalization — the batch is already
	// committed on L1. Implementations must be idempotent because the
	// engine may call this multiple times if the node restarts.
	ProcessFinalizedBatch(batch *Batch) error
}

type RollupEngine struct {
	mu           sync.RWMutex
	config       *RollupConfig
	status       RollupStatus
	batchManager *BatchManager
	sequencer    *Sequencer
	stateManager *StateManager
	fraudProver  *FraudProver
	// W-P1-3 (2026-07-13): Optional persistence layer. When nil, the engine
	// runs in-memory only (state lost on restart). When set via
	// SetPersistence(), the engine persists state after each batch/fraud-proof
	// and restores on Start().
	persistence Persistence
	// W-P1-4 (2026-07-13): Optional L1 anchor layer. When nil, batches are
	// not anchored to L1 (challenge deadline uses wall-clock time). When set
	// via SetL1Anchor(), each submitted batch is anchored to L1 and the
	// challenge deadline uses L1 block height (submitHeight + challengeBlocks).
	l1Anchor L1Anchor
	// W-P1-5 (2026-07-13): Optional withdrawal processor hook. Called by
	// finalizeLoop after a batch transitions to Finalized. Nil until W-P1-6
	// wires the L1↔L2 bridge.
	withdrawalProcessor WithdrawalProcessor
	// W-P3-1 (2026-07-14): Prometheus metrics for L2 monitoring. Nil when
	// metrics are not configured (e.g. in unit tests); all helper methods
	// are nil-safe.
	metrics *RollupMetrics
	// W-P3-1 (2026-07-14): L1 height at which the most recent batch was
	// anchored. Used to compute rollup_l1_anchor_lag = currentHeight - lastAnchorHeight.
	lastAnchorHeight uint64
	// W-P3-2 (2026-07-14): Consecutive batch failures (Build/Process/Submit
	// errors or panics). Reset to 0 on success. Exposed via the
	// qau_rollup_consecutive_batch_failures gauge; alert fires when > 5.
	consecutiveFailures uint64

	// W-P1-7 (2026-07-15): Decentralized sequencer election. When non-nil,
	// only the current epoch's sequencer (or the failover sequencer after
	// SequencerTimeout missed cycles) builds batches. When nil, the engine
	// operates in legacy single-sequencer mode (any node builds batches).
	sequencerElector SequencerElector
	// localAddress is this node's validator address. Used to determine
	// whether this node is the current sequencer. Zero = legacy mode.
	localAddress types.Address
	// missedBatchCount tracks consecutive batch cycles where the current
	// sequencer did not produce a batch (as observed by this node). When
	// this reaches SequencerTimeout, the next sequencer takes over.
	missedBatchCount uint64
	// lastSequencerAddr tracks the last known current sequencer. When the
	// sequencer changes (new epoch or failover), missedBatchCount is reset.
	lastSequencerAddr types.Address
	// lastObservedBatchTime is the wall-clock time at which this node last
	// received a batch from the current sequencer (via P2P gossip or L1
	// anchoring observation). It is the liveness evidence required by
	// shouldBuildBatch before authorizing a failover takeover: a non-current
	// sequencer MUST observe that time.Since(lastObservedBatchTime) exceeds
	// the timeout window before it can safely take over. Without this gate,
	// every non-sequencer node would take over after SequencerTimeout ticks
	// even when the current sequencer is healthy, producing dual sequencers
	// and conflicting batches (P1-ROLLUP-02).
	// Zero means "never observed" — failover is allowed after the timeout.
	// P1-ROLLUP-02 FIX (2026-07-30)
	lastObservedBatchTime time.Time

	// R39-P2-06 (2026-08-02) FIX: liveness evidence fingerprint of the
	// last batch that updated lastObservedBatchTime. The audit's finding
	// observes that the previous RecordBatchReceivedFromCurrentSequencer()
	// took no arguments — a malicious attacker controlling the caller
	// could feed evidence-less liveness ticks to keep the gate
	// permanently open (suppressing legitimate failover) forever. We
	// now require the caller to supply a real batch fingerprint
	// (batchHash + postStateRoot hash) and reject calls where either is
	// the zero hash (the audit's "batch info completeness" check). This field is
	// the stored fingerprint — used for forensics after a failover event
	// AND for the gate's completeness invariant.
	// Zero value means "never observed" — matches the
	// lastObservedBatchTime zero semantics.
	lastObservedBatchEvidence types.Hash

	startTime    time.Time
	totalBatches uint64
	totalTxs     uint64

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewRollupEngine(config *RollupConfig) (*RollupEngine, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	engine := &RollupEngine{
		config:       config,
		status:       RollupStatusStopped,
		batchManager: NewBatchManager(config, config.GenesisStateRoot),
		stopCh:       make(chan struct{}),
	}

	engine.sequencer = NewSequencer(config, engine.batchManager)
	engine.stateManager = NewStateManager(config)
	engine.fraudProver = NewFraudProver(config, engine.stateManager)

	return engine, nil
}

// SetFraudProofVerifier configures the signature verifier for fraud proof
// challenger authentication. Production deployments MUST call this before
// accepting fraud proofs.
// R3-C1 FIX (2026-07-06): Exposed to ensure production code can configure
// the verifier that is now required by default (fail-closed).
func (e *RollupEngine) SetFraudProofVerifier(sv SignatureVerifier) {
	e.fraudProver.SetSignatureVerifier(sv)
}

// SetTxSignatureVerifier configures the L2 transaction signature verifier.
// AUDIT (2026) HIGH-10: Production deployments MUST call this before
// accepting L2 transactions to prevent unauthorized transfers.
func (e *RollupEngine) SetTxSignatureVerifier(sv TxSignatureVerifier) {
	e.sequencer.SetTxSignatureVerifier(sv)
}

// SetRequireTxSig enables/disables strict L2 transaction signature mode.
func (e *RollupEngine) SetRequireTxSig(require bool) {
	e.sequencer.SetRequireTxSig(require)
}

// SetExecutor injects the QVM executor for L2 contract call execution.
// AUDIT (2026) BRDG-06: Production deployments MUST call this before
// accepting L2 transactions with contract calls. Without this, tx.Data is
// silently ignored and contract calls are treated as simple transfers.
func (e *RollupEngine) SetExecutor(executor QVMExecutor) {
	e.stateManager.SetExecutor(executor)
}

// SetWithdrawalProcessor injects the L1↔L2 bridge withdrawal hook.
// W-P1-5 FIX (2026-07-13): Called by finalizeLoop after a batch is finalized.
// W-P1-6 will wire the real bridge implementation; until then it stays nil
// and finalizeLoop skips the withdrawal step.
func (e *RollupEngine) SetWithdrawalProcessor(wp WithdrawalProcessor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.withdrawalProcessor = wp
}

// SetMetrics injects Prometheus metrics for L2 monitoring. When set, the
// engine reports status, batch counters, durations, and L1 anchor lag.
// W-P3-1 FIX (2026-07-14)
func (e *RollupEngine) SetMetrics(m *RollupMetrics) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.metrics = m
	// Propagate to the fraud prover so SubmitFraudProof/VerifyFraudProof
	// can increment their respective counters.
	if e.fraudProver != nil {
		e.fraudProver.SetMetrics(m)
	}
	// Reflect current status immediately so the gauge is accurate before
	// the first Start()/Stop() call.
	m.SetStatus(e.status)
}

// GetMetrics returns the configured metrics instance (may be nil).
func (e *RollupEngine) GetMetrics() *RollupMetrics {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.metrics
}

// GetL2Bridge returns the L2 bridge if one is wired as the withdrawal
// processor, or nil otherwise. Used by RPC to query bridge state.
// W-P1-6 Phase 3 (2026-07-14)
func (e *RollupEngine) GetL2Bridge() *L2Bridge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if wp, ok := e.withdrawalProcessor.(*L2Bridge); ok {
		return wp
	}
	return nil
}

func (e *RollupEngine) Start() error {
	// W-P1-3 (2026-07-13): Restore persisted L2 state BEFORE acquiring the
	// status lock + starting batchLoop. RestoreState acquires e.mu itself,
	// so it must run outside the lock below. If restore fails, the engine
	// still starts (in-memory fresh state) but logs a warning.
	if e.persistence != nil {
		if err := e.RestoreState(); err != nil {
			log.Printf("[rollup] WARN: state restore failed, starting fresh: %v", err)
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.status == RollupStatusRunning {
		return ErrRollupAlreadyRunning
	}

	// RLLP- (2026-07-17): Warn if WithdrawalProcessor is not configured.
	// Without it, finalized batches' withdrawal transactions are silently
	// dropped — the L2 burn happens but no L1 release is triggered. This is
	// a configuration trap: operators forgetting to call
	// SetWithdrawalProcessor(bridge) would see funds stuck on L1.
	if e.withdrawalProcessor == nil {
		log.Printf("[rollup] WARN: WithdrawalProcessor not set — withdrawals will be dropped. " +
			"Call SetWithdrawalProcessor(bridge) before Start() to enable L2→L1 withdrawals.")
	}

	e.status = RollupStatusRunning
	e.startTime = time.Now()
	e.metrics.SetStatus(e.status)

	e.wg.Add(1)
	go e.batchLoop()
	// W-P1-5 (2026-07-13): Auto-finalize loop. Scans Submitted batches every
	// FinalizeCheckInterval and calls FinalizeBatch when the challenge period
	// has elapsed. Decoupled from batchLoop so finalize cadence does not
	// depend on L2 block time.
	e.wg.Add(1)
	go e.finalizeLoop()

	// R38-P2-05 FIX (2026-08-02): Start the L2 bridge's background retry
	// worker so transient L1 withdrawal failures do not stay stuck forever.
	// The bridge is owned by Node (which calls SetWithdrawalProcessor), but
	// its lifecycle MUST follow the engine's: start with the engine, stop
	// with the engine. We reach it through the WithdrawalProcessor slot
	// (already wired before Start()). Per audit R38-P2-05, the previous
	// implementation of RetryPendingWithdrawals had Start() defined but no
	// production caller, so failed withdrawals were permanently locked.
	// Hold the lock only long enough to capture the typed bridge pointer.
	if lb, ok := e.withdrawalProcessor.(*L2Bridge); ok && lb != nil {
		lb.Start()
	}

	return nil
}

func (e *RollupEngine) Stop() error {
	e.mu.Lock()
	if e.status != RollupStatusRunning {
		e.mu.Unlock()
		return ErrRollupNotRunning
	}
	e.status = RollupStatusStopping
	e.mu.Unlock()

	close(e.stopCh)
	e.wg.Wait()

	// R38-P2-05 FIX (2026-08-02): Stop the L2 bridge retry worker paired
	// with Start()'s lb.Start() above. Wait happens AFTER engine goroutines
	// exit so the bridge cannot call back into the engine mid-shutdown.
	e.mu.Lock()
	lb, _ := e.withdrawalProcessor.(*L2Bridge)
	e.mu.Unlock()
	if lb != nil {
		lb.Stop()
	}

	e.mu.Lock()
	e.status = RollupStatusStopped
	e.metrics.SetStatus(e.status)
	e.mu.Unlock()

	return nil
}

func (e *RollupEngine) batchLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.BlockTime)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			// W-P3-1 (2026-07-14): Update L1 anchor lag before each batch
			// attempt. The lag = currentL1Height - lastAnchorHeight, showing
			// how many L1 blocks have passed since the most recent batch was
			// anchored. A growing lag signals the sequencer is not keeping up.
			e.updateL1AnchorLag()
			e.tryBuildAndSubmitBatch()
		}
	}
}

// updateL1AnchorLag computes the L1 anchor lag metric. If no L1 anchor is
// configured or no batch has been anchored yet, the gauge stays at 0.
// W-P3-1 FIX (2026-07-14)
//
// RACE-B FIX (2026-08-19): the lastAnchorHeight read is now guarded by
// e.mu.RLock() — anchorBatch (l1_anchor.go) writes the field under e.mu.Lock,
// and tests read it via GetLastAnchorHeight() under the same RWMutex. Without
// the read lock, `go test -race` flagged a concurrent read/write. The
// l1Anchor.GetCurrentHeight() call is left outside the lock to avoid holding
// e.mu during a foreign goroutine's I/O; the snapshot is reused for both the
// zero-check and the subtraction so the read/write race window on the field
// is closed by the RLock alone.
func (e *RollupEngine) updateL1AnchorLag() {
	if e.l1Anchor == nil {
		return
	}
	e.mu.RLock()
	last := e.lastAnchorHeight
	e.mu.RUnlock()
	if last == 0 {
		return
	}
	current := e.l1Anchor.GetCurrentHeight()
	if current >= last {
		e.metrics.SetL1AnchorLag(current - last)
	}
}

// GetLastAnchorHeight returns the L1 block height at which the most recent
// batch was anchored. Provided so tests and diagnostics can observe the field
// without reading it directly (it is protected by e.mu — also written by
// anchorBatch under e.mu.Lock and restored by RestoreState under the same
// lock). RACE-B FIX (2026-08-19).
func (e *RollupEngine) GetLastAnchorHeight() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastAnchorHeight
}

// finalizeLoop periodically scans Submitted batches and transitions them to
// Finalized once the challenge period has elapsed.
// W-P1-5 FIX (2026-07-13)
//
// The loop is decoupled from batchLoop for two reasons:
//  1. Finalize cadence does not need to match L2 block time — challenge
//     periods are on the order of hours/days, so scanning every 30s is
//     more than sufficient.
//  2. A panic in finalize must not stall batch production. The dedicated
//     goroutine + recover() in tryFinalizeBatches isolates failures.
func (e *RollupEngine) finalizeLoop() {
	defer e.wg.Done()

	interval := e.config.FinalizeCheckInterval
	if interval <= 0 {
		interval = DefaultFinalizeCheckInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.tryFinalizeBatches()
		}
	}
}

// tryFinalizeBatches scans all Submitted batches and finalizes those whose
// challenge period has elapsed. Errors are logged but non-fatal — the loop
// retries on the next tick.
// W-P1-5 FIX (2026-07-13)
func (e *RollupEngine) tryFinalizeBatches() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[rollup] PANIC in tryFinalizeBatches: %v", r)
			// W-P3-3 (2026-07-14): Increment panic counter so the alert
			// manager can fire a critical alert.
			e.metrics.IncBatchLoopPanic()
		}
	}()

	e.mu.RLock()
	if e.status != RollupStatusRunning {
		e.mu.RUnlock()
		return
	}
	wp := e.withdrawalProcessor
	e.mu.RUnlock()

	indices := e.batchManager.GetSubmittedBatchIndices()
	if len(indices) == 0 {
		return
	}

	// R41-ROLLUP-01 (2026-08-03) FIX: propagate the L1 anchor's current
	// height to the BatchManager BEFORE running FinalizeBatch. Without
	// this, BatchManager.l1CurrentHeight stays at its zero-initialized
	// value forever (no production caller invokes SetL1CurrentHeight),
	// and FinalizeBatch's check `bm.l1CurrentHeight < batch.SubmitHeight
	// + bm.l1ChallengeBlocks` returns ErrChallengePeriodNotOver for EVERY
	// batch that has an L1 anchor (SubmitHeight > 0). The net effect was
	// that all anchored batches were unfinalizable in production, and the
	// L1-anchor challenge-period mechanism (RLLP-) was effectively
	// dead code. updateL1AnchorLag already reads l1Anchor.GetCurrentHeight
	// for the metric; we now also feed it into BatchManager so the
	// finalization gate can actually open. Idempotent: both SetL1CurrentHeight
	// and GetCurrentHeight are mutex-protected; calling this on every
	// tryFinalizeBatches tick (1 Hz) is cheap.
	if e.l1Anchor != nil {
		e.batchManager.SetL1CurrentHeight(e.l1Anchor.GetCurrentHeight())
	}

	for _, idx := range indices {
		// FinalizeBatch does its own deadline check (wall-clock OR L1 height
		// via SubmitHeight). If the challenge period is not over yet, it
		// returns ErrChallengePeriodNotOver, which is expected and not
		// logged as an error.
		//
		// AUDIT (2026) RLLP- ErrBatchChallenged is also expected
		// (a fraud proof was submitted for this batch — finalization is
		// permanently blocked until dispute resolution). ErrBatchNotSubmitted
		// can occur on a race where a concurrent Engine.SubmitFraudProof
		// already transitioned the batch to Challenged between
		// GetSubmittedBatchIndices and FinalizeBatch. Both are silent.
		//
		// R43-ROLLUP-FAIL-01 (2026-08-03): reject finalization while
		// AnchorFailed=true. A batch whose L1 anchor never landed must
		// NOT be allowed to finalize, otherwise the sequencer can exit
		// leaving users no L1 commitment to fraud-challenge against.
		// anchorBatch sets AnchorFailed + retries up to maxAnchorRetries
		// in-place; if those retries are exhausted, the batch stays
		// AnchorFailed until either (a) a future batchLoop sweep calls
		// anchorBatch again on this batch, or (b) an operator manually
		// resolves the L1 outage and re-runs a re-anchor tool. Neither
		// is provided here; the gate is intentionally conservative.
		if b, gerr := e.batchManager.GetBatch(idx); gerr == nil && b != nil && b.AnchorFailed {
			log.Printf("[rollup] WARN R43-ROLLUP-FAIL-01: skipping finalize of batch %d — anchor failed and retries exhausted (anchor_retries=%d); batch will be re-anchored on a future anchorBatch attempt or held pending until L1 outage is resolved",
				idx, b.AnchorRetries)
			continue
		}
		err := e.batchManager.FinalizeBatch(idx)
		if err == nil {
			log.Printf("[rollup] batch %d auto-finalized", idx)
			// W-P1-5: Trigger withdrawal processing if configured. Errors
			// are logged but do NOT roll back the finalization — the batch
			// is already committed. Implementations must be idempotent.
			if wp != nil {
				if batch, gerr := e.batchManager.GetBatch(idx); gerr == nil && batch != nil {
					if werr := wp.ProcessFinalizedBatch(batch); werr != nil {
						log.Printf("[rollup] WARN: withdrawal processing for batch %d failed: %v", idx, werr)
					}
				}
			}
			continue
		}
		if !errors.Is(err, ErrChallengePeriodNotOver) &&
			!errors.Is(err, ErrBatchChallenged) &&
			!errors.Is(err, ErrBatchNotSubmitted) {
			// Unexpected error — log for diagnostics.
			log.Printf("[rollup] WARN: FinalizeBatch(%d) failed: %v", idx, err)
		}
	}
}

func (e *RollupEngine) tryBuildAndSubmitBatch() {
	// R9-RP-002 FIX: Add panic recovery to prevent a single batch processing
	// panic from crashing the entire node. batchLoop has no recover, so any
	// panic in this function (including from ProcessBatch) propagates up.
	//
	// W-P3-3 (2026-07-14): On panic, increment the batch_loop_panics_total
	// counter and the consecutive-failure gauge so the alert manager can fire
	// a critical alert.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[rollup] PANIC in tryBuildAndSubmitBatch: %v", r)
			e.mu.Lock()
			e.consecutiveFailures++
			cf := e.consecutiveFailures
			e.mu.Unlock()
			e.metrics.IncBatchLoopPanic()
			e.metrics.SetConsecutiveBatchFailures(cf)
		}
	}()
	e.mu.RLock()
	if e.status != RollupStatusRunning {
		e.mu.RUnlock()
		return
	}
	e.mu.RUnlock()

	// W-P1-7 (2026-07-15): Decentralized sequencer check. When a sequencer
	// elector is configured, only the current epoch's sequencer (or the
	// failover sequencer after SequencerTimeout missed cycles) builds batches.
	// Non-sequencer nodes skip batch production but keep the loop running so
	// they can take over if the current sequencer fails.
	if !e.shouldBuildBatch() {
		// Increment miss counter so failover can trigger after SequencerTimeout.
		e.mu.Lock()
		e.missedBatchCount++
		e.mu.Unlock()
		return
	}

	// W-P3-1 (2026-07-14): Update pending-tx gauge before building so the
	// operator can see queue depth even when no batch is produced.
	e.metrics.SetPendingTxs(e.batchManager.PendingTxCount())

	buildStart := time.Now()
	batch, err := e.batchManager.BuildBatch()
	e.metrics.ObserveBuildDuration(time.Since(buildStart))
	if err != nil {
		if !errors.Is(err, ErrInsufficientTxs) && !errors.Is(err, ErrBatchFull) {
			log.Printf("[rollup] BuildBatch failed: %v", err)
			// W-P3-2: Only count unexpected errors as failures. "Insufficient
			// txs" and "batch full" are normal flow-control conditions, not
			// failures that should trigger the consecutive-failure alert.
			e.mu.Lock()
			e.consecutiveFailures++
			cf := e.consecutiveFailures
			e.mu.Unlock()
			e.metrics.SetConsecutiveBatchFailures(cf)
		}
		return
	}

	prevRoot := batch.PrevStateRoot
	txs := batch.Transactions

	//  NOTE (P3): Batch verification. ProcessBatch re-executes every L2
	// transaction in the batch against the pre-state root (prevRoot) and returns
	// the resulting post-state root and gas used. If any transaction produces an
	// invalid state transition, ProcessBatch returns an error and the batch is
	// dropped (never submitted). The derived submitHash anchors the batch to its
	// post-root so fraud proofs can challenge an incorrect root on the L1.
	processStart := time.Now()
	postRoot, gasUsed, err := e.stateManager.ProcessBatch(batch.Index, prevRoot, txs)
	e.metrics.ObserveProcessDuration(time.Since(processStart))
	if err != nil {
		log.Printf("[rollup] ProcessBatch failed (index=%d, prevRoot=%x, txCount=%d): %v", batch.Index, prevRoot, len(txs), err)
		// W-P3-2: ProcessBatch failure is a real error — count it.
		e.mu.Lock()
		e.consecutiveFailures++
		cf := e.consecutiveFailures
		e.mu.Unlock()
		e.metrics.SetConsecutiveBatchFailures(cf)
		return
	}

	batch.TotalGasUsed = gasUsed

	// audit-fix M-4: Compute a deterministic submission hash from the batch
	// data and post-state-root instead of passing a zero-value txHash.
	// The previous code used `var txHash types.Hash` (all zeros), which meant
	// batch.SubmitTxHash was always zero — breaking fraud proof verification
	// and any L1-reference logic that depends on a non-zero submission hash.
	// Since this rollup engine does not submit to a real L1 chain, we derive
	// a cryptographic hash from (BatchHash || PostStateRoot) as the submission
	// anchor. A real deployment would replace this with the actual L1 tx hash.
	submitHash := computeSubmitHash(batch.BatchHash, postRoot)

	submitStart := time.Now()
	e.mu.Lock()
	err = e.batchManager.SubmitBatch(batch.Index, postRoot, submitHash)
	if err != nil {
		log.Printf("[rollup] SubmitBatch failed (index=%d, postRoot=%x): %v", batch.Index, postRoot, err)
		// W-P3-2: SubmitBatch failure is a real error — count it.
		e.consecutiveFailures++
	} else {
		e.totalBatches++
		e.totalTxs += uint64(batch.TxCount)
		// W-P3-2: Reset consecutive failures on success.
		e.consecutiveFailures = 0
		// W-P1-7 (2026-07-15): Reset miss counter on successful batch
		// production — the current sequencer is alive.
		e.missedBatchCount = 0
	}
	cf := e.consecutiveFailures
	e.mu.Unlock()
	e.metrics.ObserveSubmitDuration(time.Since(submitStart))
	e.metrics.SetConsecutiveBatchFailures(cf)

	// W-P1-3 (2026-07-13): Persist L2 state to disk after a successful batch
	// submission. Errors are logged inside persistStateAfterBatch (non-fatal).
	if err == nil {
		// W-P3-1: Increment batch + tx counters only on success.
		e.metrics.IncBatches()
		e.metrics.AddTxs(uint64(batch.TxCount))
		e.persistStateAfterBatch(batch)
		// W-P1-4 (2026-07-13): Anchor the batch to L1. Records batchHash +
		// postStateRoot + txDataHash at the current L1 height, enabling
		// challengers to verify batch integrity and determine the challenge
		// deadline. Errors are logged inside anchorBatch (non-fatal).
		e.anchorBatch(batch)

		// R38-P1-14 (2026-08-01): Refresh the sequencer-liveness observation
		// clock after a successful local batch build+anchor. This node just
		// produced (and, when L1 anchoring is configured, committed) a batch,
		// which is the strongest possible evidence that "the current
		// sequencer is alive" — at minimum self, and in a P2P-gossip wiring
		// this is the same hook other sequencers would call when they observe
		// the current sequencer's batch. Without this signal, the
		// P1-ROLLUP-02 failover gate in shouldBuildBatch (SequencerTimeout *
		// BlockTime silence window keyed off lastObservedBatchTime) could
		// never become non-zero on a non-receiving node, leaving the safety
		// gate effectively disabled. RecordBatchReceivedFromCurrentSequencer
		// is a no-op when no elector is configured (legacy single-sequencer).
		//
		// R39-P2-06 (2026-08-02) FIX: pass the batch fingerprint
		// (BatchHash + postRoot) so the gate's liveness-evidence invariant
		// holds. Without these args, an attacker controlling the caller
		// could feed evidence-less liveness ticks to keep the gate
		// permanently open (suppressing legitimate failover). The new
		// fail-closed signature requires BOTH non-zero — the audit's
		// "liveness gate update path did not carry batch info completeness" finding.
		e.RecordBatchReceivedFromCurrentSequencer(batch.BatchHash, postRoot)
	}

	// W-P3-1: Update pending-tx gauge after building (queue is now lighter).
	e.metrics.SetPendingTxs(e.batchManager.PendingTxCount())
}

// computeSubmitHash derives a deterministic submission hash from the batch
// hash and post-state-root. This replaces the previous zero-value txHash.
func computeSubmitHash(batchHash types.Hash, postRoot types.Hash) types.Hash {
	h := sha3.NewLegacyKeccak256()
	h.Write(batchHash[:])
	h.Write(postRoot[:])
	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

func (e *RollupEngine) SubmitL2Transaction(tx *RollupTransaction) error {
	e.mu.RLock()
	if e.status != RollupStatusRunning {
		e.mu.RUnlock()
		return ErrRollupNotRunning
	}
	e.mu.RUnlock()

	return e.sequencer.AcceptTransaction(tx)
}

func (e *RollupEngine) GetStatus() RollupStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status
}

func (e *RollupEngine) GetStats() (totalBatches, totalTxs uint64, uptime time.Duration) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	totalBatches = e.totalBatches
	totalTxs = e.totalTxs
	if e.status == RollupStatusRunning {
		uptime = time.Since(e.startTime)
	}
	return
}

func (e *RollupEngine) GetBatchManager() *BatchManager {
	return e.batchManager
}

func (e *RollupEngine) GetStateManager() *StateManager {
	return e.stateManager
}

func (e *RollupEngine) GetFraudProver() *FraudProver {
	return e.fraudProver
}

// SubmitFraudProof accepts a challenger's fraud proof, verifies it, stores it,
// and immediately transitions the accused batch to Challenged status.
//
// AUDIT (2026) RLLP-FIX (CRITICAL): This is the production
// challenger entry point. It wires together the three actions that the
// previous implementation left disconnected:
//  1. FraudProver.SubmitFraudProof — verify + store the proof
//  2. BatchManager.ChallengeBatch  — transition batch → Challenged so the
//     finalizeLoop cannot silently finalize it on the next tick
//  3. (FinalizeBatch independently re-checks HasFraudProof as defense-in-depth)
//
// If the proof is accepted but the batch has already transitioned out of
// Submitted (e.g. a race where FinalizeBatch auto-challenged it, or the batch
// was already Challenged), the proof remains stored — FinalizeBatch will still
// block on HasFraudProof. The status transition error is logged but not
// returned, because the challenger's goal (block finalization) is achieved
// regardless.
//
// Returns nil only if the proof was verified AND stored successfully.
func (e *RollupEngine) SubmitFraudProof(proof *FraudProof) error {
	if proof == nil {
		return ErrFraudProofInvalid
	}
	if e.fraudProver == nil {
		return ErrFraudProofInvalid
	}

	// Step 1: verify + store the proof. This is the fail-closed gate —
	// if verification fails, the batch is NOT challenged and the caller
	// receives the verification error.
	if err := e.fraudProver.SubmitFraudProof(proof); err != nil {
		return err
	}

	// Step 2: immediately transition the batch to Challenged. This is a
	// best-effort operation — if it fails because the batch already
	// transitioned (race with FinalizeBatch's auto-challenge, or already
	// Challenged), the proof is still stored and FinalizeBatch will block.
	if e.batchManager != nil {
		if err := e.batchManager.ChallengeBatch(proof.BatchIndex); err != nil {
			// Log the transition failure but DO NOT return it — the proof
			// is stored, which is what matters for blocking finalization.
			// ChallengeBatch returns ErrBatchNotSubmitted when the batch is
			// already Challenged or already Finalized; both are safe here.
			log.Printf("[rollup] SubmitFraudProof: ChallengeBatch(%d) returned %v (proof stored, finalization still blocked by HasFraudProof check)",
				proof.BatchIndex, err)
		} else {
			log.Printf("[rollup] SECURITY: batch %d challenged by %x — finalization blocked (RLLP-)",
				proof.BatchIndex, proof.Challenger[:8])
		}
	}

	return nil
}

func (e *RollupEngine) GetConfig() *RollupConfig {
	return e.config
}
