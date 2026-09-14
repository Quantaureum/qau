// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file implements block finality confirmation.
package consensus

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
)

// finalityLogger is the package logger for finality-related events.
// audit-fix LOW: use project logger instead of standard log for consistent formatting.
var finalityLogger = logging.Global()

var (
	// ErrBlockNotFinalized is returned when block is not finalized
	ErrBlockNotFinalized = errors.New("block not finalized")

	// ErrInsufficientVotes is returned when there are not enough votes
	ErrInsufficientVotes = errors.New("insufficient votes for finality")

	// ErrAlreadyFinalized is returned when block is already finalized
	ErrAlreadyFinalized = errors.New("block already finalized")

	// ErrFinalityHeightMismatch is returned when finality height doesn't match
	ErrFinalityHeightMismatch = errors.New("finality height mismatch")
)

// FinalizedBlock represents a finalized block with its votes
type FinalizedBlock struct {
	Height    uint64
	BlockHash types.Hash
	Votes     []*Vote
}

// FinalityTracker tracks block finality.
//
// P4-4 DEAD CODE NOTICE (2026-07-14):
// In production, FinalityTracker is dead code. Double-sign detection was sunk
// to QPOS → VotingManager → DoubleSignDetector → SlashingManager (P0-4 fix).
// FinalityTracker is retained only because some tests still reference it
// (TestFinalityTracker_*). Do NOT add new production callers — use
// VotingManager.AddVote / QPOS.ProcessAttestation instead.
type FinalityTracker struct {
	mu              sync.RWMutex
	finalizedBlocks map[uint64]*FinalizedBlock
	latestFinalized uint64
	validatorMgr    *ValidatorManager
	// voteHistory tracks votes by validator and height for double-sign detection
	// vote conflict detection: tracks validator votes to detect double signing
	// R44-CS-004 FIX: voteHistory is capped per validator to prevent OOM.
	// Entries older than maxVoteHistoryHeights behind latestFinalized are pruned.
	// R35-P0-07 FIX: Added round dimension. Previously map[Address]map[uint64]*Vote
	// (addr→height→vote) caused false double-sign detection when validators
	// voted for different blocks in different rounds at the same height —
	// which is REQUIRED protocol behavior during round changes.
	voteHistory           map[types.Address]map[uint64]map[uint32]*Vote
	maxVoteHistoryHeights uint64
	// slashingManager handles evidence submission for double-signing offenses
	slashingManager *SlashingManager
	// broadcastEvidence sends evidence to peers for propagating slashable offenses
	broadcastEvidence func(*SlashingEvidence)
	// CRITICAL FIX: Evidence queue for pending evidence when slashingManager unavailable
	evidenceQueue []*SlashingEvidence
	// R30-IMPLEMENT (2026-07-27): Configurable broadcast timeout and retry
	// count for broadcastEvidenceWithRetry. Defaults (5s × 3 = 15s) match
	// the previous hardcoded values; tests override to 50ms × 3 = 150ms to
	// keep the test suite fast (PERF Boost9).
	broadcastTimeout    time.Duration
	broadcastMaxRetries int
}

// NewFinalityTracker creates a new finality tracker
func NewFinalityTracker(validatorMgr *ValidatorManager) *FinalityTracker {
	return &FinalityTracker{
		finalizedBlocks:       make(map[uint64]*FinalizedBlock),
		latestFinalized:       0,
		validatorMgr:          validatorMgr,
		voteHistory:           make(map[types.Address]map[uint64]map[uint32]*Vote),
		maxVoteHistoryHeights: 10000, // R44-CS-004: keep last 10K heights per validator
		evidenceQueue:         make([]*SlashingEvidence, 0),
		broadcastTimeout:      5 * time.Second,
		broadcastMaxRetries:   3,
	}
}

// pruneVoteHistoryLocked removes vote history entries older than
// maxVoteHistoryHeights behind latestFinalized. Caller must hold ft.mu (write).
func (ft *FinalityTracker) pruneVoteHistoryLocked() {
	if ft.maxVoteHistoryHeights == 0 || ft.latestFinalized < ft.maxVoteHistoryHeights {
		return
	}
	cutoff := ft.latestFinalized - ft.maxVoteHistoryHeights
	for addr, heights := range ft.voteHistory {
		for h := range heights {
			if h < cutoff {
				delete(heights, h)
			}
		}
		if len(heights) == 0 {
			delete(ft.voteHistory, addr)
		}
	}
}

// CheckVoteConflict checks if a vote conflicts with an existing vote at the same height
// Returns SlashingEvidence if double signing is detected, nil otherwise
// vote conflict detection: detects double signing before storing votes
func (ft *FinalityTracker) CheckVoteConflict(vote *Vote) *SlashingEvidence {
	if vote == nil {
		return nil
	}

	ft.mu.RLock()
	defer ft.mu.RUnlock()

	// Check if we have a vote from this validator at this height and round
	// R35-P0-07 FIX: Only same (height, round) with different block hashes is double-sign.
	if validatorVotes, exists := ft.voteHistory[vote.ValidatorAddr]; exists {
		if roundVotes, exists := validatorVotes[vote.Height]; exists {
			if existingVote, exists := roundVotes[vote.Round]; exists {
				// Check if it's a different block hash (double signing)
				if existingVote.BlockHash != vote.BlockHash {
					return &SlashingEvidence{
						Reason:        SlashingReasonDoubleSigning,
						ValidatorAddr: vote.ValidatorAddr,
						Height:        vote.Height,
						Vote1:         deepCopyVote(existingVote), // SECURITY FIX: prevent caller mutation
						Vote2:         deepCopyVote(vote),         // SECURITY FIX: prevent caller mutation
					}
				}
			}
		}
	}
	return nil
}

// RecordVote records a vote and checks for double signing.
// Returns SlashingEvidence if double signing is detected.
// Conflict check and recording are done atomically under a single lock
// to prevent TOCTOU race conditions.
func (ft *FinalityTracker) RecordVote(vote *Vote) *SlashingEvidence {
	if vote == nil {
		return nil
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	// Check for conflict under the same lock (atomic with recording)
	// R35-P0-07 FIX: Only votes at the SAME (height, round) with DIFFERENT
	// block hashes constitute double-signing. Different rounds at the same
	// height are normal protocol behavior during round changes.
	if validatorVotes, exists := ft.voteHistory[vote.ValidatorAddr]; exists {
		if roundVotes, exists := validatorVotes[vote.Height]; exists {
			if existingVote, exists := roundVotes[vote.Round]; exists {
				if existingVote.BlockHash != vote.BlockHash {
					return &SlashingEvidence{
						Reason:        SlashingReasonDoubleSigning,
						ValidatorAddr: vote.ValidatorAddr,
						Height:        vote.Height,
						Vote1:         deepCopyVote(existingVote), // SECURITY FIX: prevent caller mutation
						Vote2:         deepCopyVote(vote),         // SECURITY FIX: prevent caller mutation
					}
				}
				// Same vote, already recorded
				return nil
			}
		}
	}

	// Initialize vote history for this validator if needed
	if ft.voteHistory[vote.ValidatorAddr] == nil {
		ft.voteHistory[vote.ValidatorAddr] = make(map[uint64]map[uint32]*Vote)
	}
	if ft.voteHistory[vote.ValidatorAddr][vote.Height] == nil {
		ft.voteHistory[vote.ValidatorAddr][vote.Height] = make(map[uint32]*Vote)
	}

	// Record the vote
	ft.voteHistory[vote.ValidatorAddr][vote.Height][vote.Round] = deepCopyVote(vote)
	return nil
}

// FinalizeBlock attempts to finalize a block with the given votes
// vote conflict detection: checks for double signing before finalizing
// CS-06 FIX: Added variadic blockTime parameter for deterministic evidence
// timestamps. When provided, blockTime[0] is used instead of time.Now().Unix().
func (ft *FinalityTracker) FinalizeBlock(height uint64, blockHash types.Hash, votes []*Vote, blockTime ...int64) error {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	// Check if already finalized
	if _, exists := ft.finalizedBlocks[height]; exists {
		return ErrAlreadyFinalized
	}

	// Create vote collector to verify quorum
	vc := NewVoteCollector(height, 0, blockHash, ft.validatorMgr)

	// Add all votes with conflict detection
	for _, vote := range votes {
		if vote.Height != height || vote.BlockHash != blockHash {
			continue
		}

		// Check for existing conflicting votes at the same height (double signing detection)
		// vote conflict detection: check before storing
		// R35-P0-07 FIX: Only same (height, round) with different block hashes is double-sign.
		if validatorVotes, exists := ft.voteHistory[vote.ValidatorAddr]; exists {
			if roundVotes, exists := validatorVotes[vote.Height]; exists {
				if existingVote, exists := roundVotes[vote.Round]; exists {
					// Compare block hashes to detect conflicting votes
					if existingVote.BlockHash != vote.BlockHash {
						// audit-fix LOW-1: Forward double-signing evidence to slashing manager
						// instead of silently rejecting. This ensures malicious validators are
						// actually penalized for equivocation.
						// CRITICAL FIX: Queue evidence locally first to prevent loss
						// CS-06 FIX: Use deterministic blockTime for evidence timestamp
						// when provided; fall back to time.Now() for non-consensus callers.
						var evidenceTimestamp int64
						if len(blockTime) > 0 {
							evidenceTimestamp = blockTime[0]
						} else {
							evidenceTimestamp = time.Now().Unix()
						}
						evidence := &SlashingEvidence{
							Reason:        SlashingReasonDoubleSigning,
							ValidatorAddr: vote.ValidatorAddr,
							Height:        vote.Height,
							Vote1:         deepCopyVote(existingVote),
							Vote2:         deepCopyVote(vote),
							Timestamp:     evidenceTimestamp,
						}
						ft.queueEvidence(evidence)
						// R4-P1-1 FIX: Move SubmitEvidence and broadcastEvidenceWithRetry
						// to a goroutine to prevent blocking FinalizeBlock while holding
						// ft.mu. broadcastEvidenceWithRetry can block for up to ~15s
						// (3 retries * 5s timeout), stalling all finality processing.
						if ft.slashingManager != nil || ft.broadcastEvidence != nil {
							evCopy := &SlashingEvidence{
								Reason:        evidence.Reason,
								ValidatorAddr: evidence.ValidatorAddr,
								Height:        evidence.Height,
								Timestamp:     evidence.Timestamp,
								Vote1:         deepCopyVote(evidence.Vote1),
								Vote2:         deepCopyVote(evidence.Vote2),
							}
							sm := ft.slashingManager
							broadcastFn := ft.broadcastEvidenceWithRetry
							// R34-CONS-P0-003 FIX: Capture deterministic blockTime for
							// SubmitEvidence to prevent non-deterministic slashing timestamps
							// and jailUntil divergence across nodes. Use evidenceTimestamp
							// (which is consensus-derived when available) as the blockTime.
							submitBlockTime := evidenceTimestamp
							go func() {
								defer func() {
									if r := recover(); r != nil {
										finalityLogger.Errorf("panic in evidence submission goroutine: %v", r)
									}
								}()
								if sm != nil {
									if _, submitErr := sm.SubmitEvidence(evCopy, getVotingSystemCaller(), submitBlockTime); submitErr != nil {
										finalityLogger.Errorf("CRITICAL: failed to submit double-signing evidence for %x at height %d: %v",
											evCopy.ValidatorAddr, evCopy.Height, submitErr)
									}
								}
								if broadcastErr := broadcastFn(evCopy); broadcastErr != nil {
									finalityLogger.Errorf("failed to broadcast evidence for %x at height %d: %v",
										evCopy.ValidatorAddr, evCopy.Height, broadcastErr)
								}
							}()
						}
					}
					continue
				}
			}
		}

		// Record the vote in history
		// R35-P0-07 FIX: Use round dimension to avoid false double-sign.
		if ft.voteHistory[vote.ValidatorAddr] == nil {
			ft.voteHistory[vote.ValidatorAddr] = make(map[uint64]map[uint32]*Vote)
		}
		if ft.voteHistory[vote.ValidatorAddr][vote.Height] == nil {
			ft.voteHistory[vote.ValidatorAddr][vote.Height] = make(map[uint32]*Vote)
		}
		ft.voteHistory[vote.ValidatorAddr][vote.Height][vote.Round] = deepCopyVote(vote)

		// audit-remediation: vote conflict detection completed above
		// Double signing is detected by comparing block hashes at same height
		// Conflicting votes are rejected before reaching this point
		if err := vc.AddVote(vote); err != nil {
			// audit-fix LOW: use project logger for consistent log formatting
			finalityLogger.Warnf("WARN: failed to add vote from %x at height %d: %v", vote.ValidatorAddr, vote.Height, err)
		}
	}

	// Check if we have quorum
	if !vc.HasQuorum() {
		return ErrInsufficientVotes
	}

	// Finalize the block
	ft.finalizedBlocks[height] = &FinalizedBlock{
		Height:    height,
		BlockHash: blockHash,
		Votes:     vc.GetVotes(),
	}

	// Update latest finalized if this is newer
	if height > ft.latestFinalized {
		ft.latestFinalized = height
	}

	// M6-4: Log block finalization at Info level for production observability
	finalityLogger.Infof("block finalized: height=%d hash=%x votes=%d", height, blockHash, len(ft.finalizedBlocks[height].Votes))

	// audit-fix L-4: auto-prune vote history and old finalized blocks
	// to prevent unbounded memory growth. Keep 2 epochs of margin.
	// MEDIUM FIX: Use size-based pruning strategy instead of fixed height
	// This ensures memory usage stays bounded even during high activity
	const maxFinalizedBlocks = 128 // ~4 epochs worth of blocks
	if len(ft.finalizedBlocks) > maxFinalizedBlocks {
		// Prune oldest blocks based on height
		pruneBelow := ft.latestFinalized - 64
		for h := range ft.finalizedBlocks {
			if h < pruneBelow {
				delete(ft.finalizedBlocks, h)
			}
		}
	}
	// R44-CS-004 FIX: Use height-based pruning instead of random map iteration.
	// The previous code deleted entries in non-deterministic map order, which
	// could remove recent votes while keeping old ones. Now we prune by cutoff
	// height (maxVoteHistoryHeights behind latestFinalized) plus a per-validator
	// cap as a secondary safeguard.
	ft.pruneVoteHistoryLocked()
	// Per-validator secondary cap for edge cases (e.g. many votes at same height)
	const maxVoteHistoryPerValidator = 64
	for addr, heights := range ft.voteHistory {
		if len(heights) > maxVoteHistoryPerValidator {
			// Sort heights and delete the oldest entries
			sortedHeights := make([]uint64, 0, len(heights))
			for h := range heights {
				sortedHeights = append(sortedHeights, h)
			}
			sort.Slice(sortedHeights, func(i, j int) bool { return sortedHeights[i] < sortedHeights[j] })
			pruneCount := len(sortedHeights) - maxVoteHistoryPerValidator
			for i := 0; i < pruneCount; i++ {
				delete(heights, sortedHeights[i])
			}
		}
		if len(heights) == 0 {
			delete(ft.voteHistory, addr)
		}
	}

	// audit-fix H-4: cap voteHistory even when finality is not advancing
	// (e.g. during network partition). Prevents unbounded memory growth.
	const maxVoteHistoryEntries = MaxVoteHistoryEntries
	totalVotes := 0
	for _, heights := range ft.voteHistory {
		totalVotes += len(heights)
	}
	if totalVotes > maxVoteHistoryEntries {
		// Evict oldest entries by finding the lowest height across all validators
		for totalVotes > maxVoteHistoryEntries*9/10 { // shrink to 90%
			var lowestHeight uint64 = ^uint64(0)
			var lowestAddr types.Address
			for addr, heights := range ft.voteHistory {
				for h := range heights {
					if h < lowestHeight {
						lowestHeight = h
						lowestAddr = addr
					}
				}
			}
			if lowestHeight == ^uint64(0) {
				break
			}
			delete(ft.voteHistory[lowestAddr], lowestHeight)
			if len(ft.voteHistory[lowestAddr]) == 0 {
				delete(ft.voteHistory, lowestAddr)
			}
			totalVotes--
		}
	}

	return nil
}

// IsFinalized returns true if the block at the given height is finalized
func (ft *FinalityTracker) IsFinalized(height uint64) bool {
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	_, exists := ft.finalizedBlocks[height]
	return exists
}

// GetFinalizedBlock returns the finalized block at the given height.
// audit-fix NEW-19: returns a deep copy to prevent callers from mutating internal state.
func (ft *FinalityTracker) GetFinalizedBlock(height uint64) (*FinalizedBlock, error) {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	fb, exists := ft.finalizedBlocks[height]
	if !exists {
		return nil, ErrBlockNotFinalized
	}

	return deepCopyFinalizedBlock(fb), nil
}

// LatestFinalizedHeight returns the height of the latest finalized block
func (ft *FinalityTracker) LatestFinalizedHeight() uint64 {
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	return ft.latestFinalized
}

// VerifyFinality verifies that a block has proper finality
func (ft *FinalityTracker) VerifyFinality(height uint64, blockHash types.Hash) error {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	fb, exists := ft.finalizedBlocks[height]
	if !exists {
		return ErrBlockNotFinalized
	}

	if fb.BlockHash != blockHash {
		return ErrFinalityHeightMismatch
	}

	return nil
}

// GetFinalityVotes returns the votes that finalized a block.
// audit-fix NEW-19: deep-copies Vote structs (including Signature byte slices)
// to prevent callers from mutating internal consensus state.
func (ft *FinalityTracker) GetFinalityVotes(height uint64) ([]*Vote, error) {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	fb, exists := ft.finalizedBlocks[height]
	if !exists {
		return nil, ErrBlockNotFinalized
	}

	votes := make([]*Vote, len(fb.Votes))
	for i, v := range fb.Votes {
		votes[i] = deepCopyVote(v)
	}
	return votes, nil
}

// deepCopyFinalizedBlock returns a deep copy of a FinalizedBlock.
// audit-fix NEW-19: prevents callers from mutating internal finality state.
func deepCopyFinalizedBlock(fb *FinalizedBlock) *FinalizedBlock {
	if fb == nil {
		return nil
	}
	cpy := &FinalizedBlock{
		Height:    fb.Height,
		BlockHash: fb.BlockHash,
	}
	if len(fb.Votes) > 0 {
		cpy.Votes = make([]*Vote, len(fb.Votes))
		for i, v := range fb.Votes {
			cpy.Votes[i] = deepCopyVote(v)
		}
	}
	return cpy
}

// SetBroadcastEvidence sets the broadcast function for slashing evidence.
// CONS-R11-005 (2026-07-20): Takes ft.mu.Lock() to synchronize with
// concurrent reads in broadcastEvidenceWithRetry. FinalizeBlock launches
// a goroutine that calls broadcastEvidenceWithRetry, which reads
// ft.broadcastEvidence. Without a synchronized setter, a concurrent write
// to ft.broadcastEvidence (e.g., during reconfiguration) would race with
// that read. All writes MUST go through this setter; direct field
// assignment is unsafe.
func (ft *FinalityTracker) SetBroadcastEvidence(fn func(*SlashingEvidence)) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.broadcastEvidence = fn
}

// broadcastEvidenceWithRetry attempts to broadcast evidence with retry logic.
// Returns error if all retries fail, but evidence should still be processed locally.
// HIGH FIX: Ensures evidence broadcast failures are handled gracefully without
// blocking block finalization, while still attempting multiple broadcasts.
// audit-fix Round3 M-2: Use a stop channel to signal goroutines to exit when
// the function returns. Previously, on timeout the goroutine running
// ft.broadcastEvidence was abandoned, causing a goroutine leak. Now stopCh is
// closed via defer when the function returns, allowing pending goroutines to
// exit at their next check.
//
// CONS-R11-005 (2026-07-20): This method is invoked from a goroutine launched
// by FinalizeBlock (which holds ft.mu when launching, but the goroutine itself
// runs without that lock). Previously it read ft.broadcastEvidence directly
// (lines 459, 495) without synchronization — a data race if SetBroadcastEvidence
// is called concurrently. Now we take ft.mu.RLock() briefly to capture the
// function pointer into a local variable, release the lock, and use the local
// variable for all subsequent calls (including in inner retry goroutines).
// The actual broadcast call is outside the lock to avoid holding ft.mu during
// the potentially slow network operation.
func (ft *FinalityTracker) broadcastEvidenceWithRetry(evidence *SlashingEvidence) error {
	ft.mu.RLock()
	broadcastFn := ft.broadcastEvidence
	timeout := ft.broadcastTimeout
	maxRetries := ft.broadcastMaxRetries
	ft.mu.RUnlock()
	if broadcastFn == nil {
		return nil
	}
	// R30-IMPLEMENT (2026-07-27): Fall back to production defaults if the
	// fields were not initialized (e.g., by tests that construct
	// FinalityTracker via struct literal without NewFinalityTracker).
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if maxRetries <= 0 {
		maxRetries = 3
	}

	var lastErr error

	// audit-fix Round3 M-2: stopCh is closed when the function returns,
	// signaling all pending goroutines to exit.
	stopCh := make(chan struct{})
	defer close(stopCh)

	for i := 0; i < maxRetries; i++ {
		// Use a timeout for each broadcast attempt
		done := make(chan struct{})
		go func() {
			// R8-P3 FIX: Only close(done) on successful completion.
			// Previously, defer close(done) always ran (even on panic),
			// causing the outer select to report success when the broadcast
			// actually panicked. Now, success flag ensures done is only
			// closed when broadcastEvidence completes without panic.
			success := false
			defer func() {
				if r := recover(); r != nil {
					finalityLogger.Errorf("panic in evidence broadcast goroutine: %v", r)
				}
				if success {
					close(done)
				}
			}()
			// audit-fix Round3 M-2: check stop signal before calling broadcast
			select {
			case <-stopCh:
				return
			default:
			}
			// CONS-R11-005: use captured broadcastFn instead of ft.broadcastEvidence
			// to avoid re-reading the field without synchronization in this inner
			// goroutine.
			broadcastFn(evidence)
			success = true
		}()

		select {
		case <-done:
			return nil // Success
		case <-time.After(timeout):
			lastErr = errors.New("broadcast timeout")
			// Continue to retry; stopCh will be closed on function return,
			// allowing the abandoned goroutine to exit if it hasn't already.
		}
	}

	return fmt.Errorf("evidence broadcast failed after %d attempts: %w", maxRetries, lastErr)
}

// queueEvidence adds evidence to the local queue for persistence
// CRITICAL FIX: Ensures evidence is not lost on broadcast or submission failures
// IMPORTANT: Caller must hold ft.mu.Lock() since this is called from FinalizeBlock
// which already holds the lock. Use QueueEvidence for external callers.
func (ft *FinalityTracker) queueEvidence(evidence *SlashingEvidence) {
	if evidence == nil {
		return
	}
	// NOTE: No lock here - caller (FinalizeBlock) already holds ft.mu.Lock()
	// Limit queue size to prevent unbounded memory growth
	if len(ft.evidenceQueue) >= MaxEvidenceQueue {
		// Remove oldest evidence (FIFO)
		ft.evidenceQueue = ft.evidenceQueue[1:]
	}
	ft.evidenceQueue = append(ft.evidenceQueue, evidence)
}

// QueueEvidence adds evidence to the local queue (thread-safe version for external callers)
func (ft *FinalityTracker) QueueEvidence(evidence *SlashingEvidence) {
	if evidence == nil {
		return
	}
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if len(ft.evidenceQueue) >= MaxEvidenceQueue {
		ft.evidenceQueue = ft.evidenceQueue[1:]
	}
	ft.evidenceQueue = append(ft.evidenceQueue, evidence)
}

// GetQueuedEvidence returns and clears the queued evidence
// Call this after slashingManager is initialized to submit pending evidence
func (ft *FinalityTracker) GetQueuedEvidence() []*SlashingEvidence {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	queue := ft.evidenceQueue
	ft.evidenceQueue = make([]*SlashingEvidence, 0)
	return queue
}

// SetSlashingManager attaches a SlashingManager to this FinalityTracker and
// drains any pending evidence that was queued before the manager was available.
//
// R30-IMPLEMENT (2026-07-27): Implements the test contract in
// cons_r15_l01_l03_test.go:152. Without this setter, evidence queued via
// QueueEvidence (e.g. by external callers or by FinalizeBlock when no
// SlashingManager was attached yet) would sit in evidenceQueue forever —
// the offender would never be penalized through the FinalityTracker path.
//
// Mirrors VotingManager.SetSlashingManager (voting.go:895) and
// VoteCollector.SetSlashingManager (voting.go:407) drain patterns:
// set field → drain queue → submit each evidence to the SlashingManager.
// Submission happens OUTSIDE ft.mu to avoid potential lock-ordering issues
// with SlashingManager.SubmitEvidence (which acquires its own lock and may
// call back into ValidatorManager).
// audit-remediation: reviewed 2026-09-11 — wiring setter called once by the
// node assembler; not a stake-mutation surface. SubmitEvidence re-validates
// evidence and enforces penalty bounds independently.
func (ft *FinalityTracker) SetSlashingManager(sm *SlashingManager) {
	ft.mu.Lock()
	ft.slashingManager = sm
	queued := ft.evidenceQueue
	ft.evidenceQueue = make([]*SlashingEvidence, 0)
	ft.mu.Unlock()

	if sm != nil && len(queued) > 0 {
		caller := getVotingSystemCaller()
		for _, evidence := range queued {
			// R34-CONS-P0-003 FIX: Pass evidence.Timestamp as blockTime for
			// deterministic slashing. Queued evidence already has Timestamp set
			// from a consensus time source; using it here prevents time.Now()
			// fallback which causes jailUntil divergence across nodes.
			var bt int64
			if evidence.Timestamp > 0 {
				bt = evidence.Timestamp
			}
			if _, err := sm.SubmitEvidence(evidence, caller, bt); err != nil {
				finalityLogger.Warnf("FinalityTracker: failed to submit queued evidence to SlashingManager: %v", err)
			}
		}
		finalityLogger.Infof("FinalityTracker: drained %d queued slashing evidence items after SetSlashingManager", len(queued))
	}
}

// PruneFinalizedBlocks removes finalized blocks below the given height
func (ft *FinalityTracker) PruneFinalizedBlocks(keepAbove uint64) int {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	pruned := 0
	for height := range ft.finalizedBlocks {
		if height < keepAbove {
			delete(ft.finalizedBlocks, height)
			pruned++
		}
	}

	// Also prune vote history
	for addr, heights := range ft.voteHistory {
		for height := range heights {
			if height < keepAbove {
				delete(heights, height)
			}
		}
		if len(heights) == 0 {
			delete(ft.voteHistory, addr)
		}
	}

	return pruned
}
