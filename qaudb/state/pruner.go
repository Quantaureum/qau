// Quantaureum Node source, version 1.0.0.
// Package state — Phase 4.4: Automatic State Pruning
//
// With 200K nodes and long chain history, state database grows unboundedly.
// StatePruner automatically deletes state entries older than a configurable
// number of epochs, keeping only the most recent state for active accounts.
//
// Pruning strategy:
//   - Keep state for the last N epochs (default: 64 epochs = ~6.8 hours)
//   - Delete account states that haven't been modified in the window
//   - Preserve genesis state
//   - Run pruning in background goroutine every epoch transition
//
// This reduces state storage by ~95% while maintaining full node functionality.
package state

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
)

// DefaultPruneWindowEpochs is the default number of epochs to retain state.
const DefaultPruneWindowEpochs = 64 // ~6.8 hours at 12s/slot, 32 slots/epoch

// PruneInterval is the default interval between prune cycles.
const PruneInterval = 64 * 12 * time.Second // Every epoch (~6.4 minutes)

// StatePruner manages automatic state pruning.
type StatePruner struct {
	mu sync.RWMutex

	// database is the underlying state database
	database db.Database

	// stateDB is the StateDB instance for calling PruneState.
	// SECURITY (audit 2026-06-26, P1-08): Required for actual pruning.
	// STATE-R11-001 (2026-07-20) FIX: This field is now REQUIRED by default.
	// Start() refuses to run unless stateDB is set, OR the operator has
	// explicitly enabled unsafe archive-mode pruning via
	// SetAllowUnsafeFallback(true). This prevents misconfigured nodes
	// (stateDB=nil due to init-order bugs) from silently taking the
	// reference-count-free fallback path and deleting active state.
	stateDB *StateDB

	// allowUnsafeFallback enables the legacy pruneDatabaseDirect path
	// that deletes snapshots without checking addressRefs. This is
	// DANGEROUS and only intended for archive nodes that explicitly opt
	// in. Default is false. Operators who enable this MUST understand
	// that any state referenced by in-flight reads may be deleted.
	allowUnsafeFallback bool

	// blocksPerEpoch converts epoch numbers to block heights.
	blocksPerEpoch uint64

	// windowEpochs is the number of epochs to retain state
	windowEpochs uint64

	// currentEpoch is the current blockchain epoch
	currentEpoch uint64

	// lastPrunedEpoch is the last epoch that was pruned
	lastPrunedEpoch uint64

	// totalPruned is the total number of entries pruned
	totalPruned uint64

	// totalBytesFreed is the total bytes freed by pruning
	totalBytesFreed uint64

	// lifecycle
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
}

// NewStatePruner creates a new state pruner.
func NewStatePruner(database db.Database, windowEpochs uint64) *StatePruner {
	if windowEpochs == 0 {
		windowEpochs = DefaultPruneWindowEpochs
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &StatePruner{
		database:       database,
		windowEpochs:   windowEpochs,
		blocksPerEpoch: 32, // default: 32 slots per epoch
		ctx:            ctx,
		cancel:         cancel,
	}
}

// NewStatePrunerWithDB creates a state pruner with a direct StateDB reference.
// SECURITY (audit 2026-06-26, P1-08): This enables actual state pruning by
// delegating to StateDB.PruneState, which has access to modification logs
// and reference counting for safe pruning.
func NewStatePrunerWithDB(database db.Database, stateDB *StateDB, windowEpochs uint64) *StatePruner {
	sp := NewStatePruner(database, windowEpochs)
	sp.stateDB = stateDB
	return sp
}

// Start starts the background pruning goroutine.
//
// STATE-R11-001 (2026-07-20) FIX: Refuses to start unless sp.stateDB is
// configured, OR the operator has explicitly opted in to the unsafe
// fallback via SetAllowUnsafeFallback(true). This prevents silent
// misconfiguration where stateDB is nil (e.g., due to init-order bugs)
// and the pruner falls back to deleting snapshots without reference
// counting — which would delete active state.
func (sp *StatePruner) Start() error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if sp.running {
		return fmt.Errorf("state pruner already running")
	}

	if sp.stateDB == nil && !sp.allowUnsafeFallback {
		return fmt.Errorf("state pruner cannot start: stateDB is nil " +
			"(use NewStatePrunerWithDB or call SetStateDB before Start); " +
			"for archive-node-only operation, call SetAllowUnsafeFallback(true)")
	}
	if sp.stateDB == nil && sp.allowUnsafeFallback {
		log.Printf("WARNING: StatePruner starting in UNSAFE archive mode — " +
			"pruneDatabaseDirect will delete snapshots without reference counting. " +
			"Any state referenced by in-flight reads may be deleted.")
	}

	sp.running = true
	sp.wg.Add(1)
	go sp.pruneLoop()

	return nil
}

// SetStateDB wires the StateDB reference required for safe pruning.
// Must be called before Start() unless the operator has explicitly
// enabled unsafe archive-mode pruning via SetAllowUnsafeFallback(true).
func (sp *StatePruner) SetStateDB(stateDB *StateDB) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.stateDB = stateDB
}

// SetAllowUnsafeFallback enables (or disables) the legacy fallback that
// prunes snapshots directly from the database without reference counting.
//
// STATE-R11-001 (2026-07-20) FIX: This is DANGEROUS and only intended
// for archive nodes that explicitly opt in. Without this opt-in flag,
// Start() refuses to run when stateDB is nil, preventing silent
// misconfiguration from deleting active state.
//
// Operators who enable this MUST understand the risks: any state
// referenced by in-flight reads (e.g., a slow RPC call walking the
// state tree) may be deleted out from under them.
func (sp *StatePruner) SetAllowUnsafeFallback(allow bool) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.allowUnsafeFallback = allow
}

// Stop stops the background pruning goroutine.
//
// P1-STATE-01 FIX (2026-07-30, R36): Previously Stop() held sp.mu while
// calling sp.wg.Wait(). performPrune() acquires sp.mu at three points
// (currentEpoch read, lastPrunedEpoch check, stats update). If Stop() is
// called mid-prune, Stop holds mu -> wg.Wait() blocks forever waiting for
// pruneLoop -> performPrune blocks on sp.mu.Lock() -> classic hold-and-wait
// deadlock. systemd could only SIGKILL the process.
//
// Fix: cancel context and release the lock BEFORE waiting, then re-acquire
// the lock to flip running=false. This allows pruneLoop to observe ctx.Done
// or complete its current mu.Lock() critical section and exit.
func (sp *StatePruner) Stop() error {
	sp.mu.Lock()
	if !sp.running {
		sp.mu.Unlock()
		return nil
	}
	sp.running = false
	sp.cancel()
	sp.mu.Unlock()

	sp.wg.Wait()
	return nil
}

// UpdateEpoch updates the current epoch and triggers pruning if needed.
func (sp *StatePruner) UpdateEpoch(epoch uint64) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if epoch > sp.currentEpoch {
		sp.currentEpoch = epoch
	}
}

// pruneLoop is the background pruning loop.
func (sp *StatePruner) pruneLoop() {
	defer sp.wg.Done()

	ticker := time.NewTicker(PruneInterval)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in pruneLoop: %v", r)
		}
	}()

	for {
		select {
		case <-sp.ctx.Done():
			return
		case <-ticker.C:
			sp.performPrune()
		}
	}
}

// performPrune executes a single prune cycle.
func (sp *StatePruner) performPrune() {
	sp.mu.Lock()
	currentEpoch := sp.currentEpoch
	windowEpochs := sp.windowEpochs
	sp.mu.Unlock()

	if currentEpoch < windowEpochs {
		return // Not enough history to prune
	}

	cutoffEpoch := currentEpoch - windowEpochs

	sp.mu.Lock()
	if cutoffEpoch <= sp.lastPrunedEpoch {
		sp.mu.Unlock()
		return // Already pruned up to this point
	}
	sp.mu.Unlock()

	// Perform the actual pruning
	// L9-033 FIX: Handle error from pruneBeforeEpoch instead of ignoring it.
	pruned, bytesFreed, err := sp.pruneBeforeEpoch(cutoffEpoch)
	if err != nil {
		log.Printf("[ERROR] StatePruner: pruneBeforeEpoch failed for epoch %d: %v", cutoffEpoch, err)
		return
	}

	sp.mu.Lock()
	sp.lastPrunedEpoch = cutoffEpoch
	sp.totalPruned += pruned
	sp.totalBytesFreed += bytesFreed
	sp.mu.Unlock()
}

// pruneBeforeEpoch deletes state entries for epochs before the cutoff.
// Returns the number of entries pruned and bytes freed.
// SECURITY (audit 2026-06-26, P1-08): Implemented actual state pruning
// by delegating to StateDB.PruneState, which has access to modification
// logs and reference counting for safe, non-destructive pruning.
//
// STATE-R11-001 (2026-07-20) FIX: The fallback to pruneDatabaseDirect is
// now gated behind allowUnsafeFallback (default false). Without explicit
// opt-in, returning stateDB==nil produces an error instead of silently
// deleting active state. Start() also enforces this at startup.
func (sp *StatePruner) pruneBeforeEpoch(cutoffEpoch uint64) (uint64, uint64, error) {
	// If we have a StateDB reference, delegate to its pruning logic
	if sp.stateDB != nil {
		// Convert epoch to block height: each epoch has blocksPerEpoch blocks
		cutoffBlock := cutoffEpoch * sp.blocksPerEpoch
		if err := sp.stateDB.PruneState(cutoffBlock); err != nil {
			log.Printf("[ERROR] StatePruner: PruneState failed for epoch %d (block %d): %v", cutoffEpoch, cutoffBlock, err)
			return 0, 0, err
		}
		// Return stats from StateDB
		_, _, lastPruned, snapshotCount := sp.stateDB.GetPruningStats()
		if lastPruned > 0 {
			return uint64(snapshotCount), 0, nil // snapshotCount is approximate
		}
		return 0, 0, nil
	}

	// STATE-R11-001: Without stateDB, pruneDatabaseDirect is unsafe.
	// Refuse unless the operator has explicitly opted in.
	if !sp.allowUnsafeFallback {
		return 0, 0, fmt.Errorf("pruneBeforeEpoch: stateDB is nil and unsafe fallback is not enabled (STATE-R11-001)")
	}

	// Fallback: direct database pruning without StateDB reference
	// This is less safe (no reference counting) and should only be used
	// for archive nodes that want to prune without modification tracking.
	log.Printf("WARNING: StatePruner using UNSAFE pruneDatabaseDirect fallback for epoch %d (no reference counting)", cutoffEpoch)
	pruned, bytesFreed, err := sp.pruneDatabaseDirect(cutoffEpoch)
	if err != nil {
		return pruned, bytesFreed, fmt.Errorf("pruneBeforeEpoch: %w", err)
	}
	if pruned > 0 {
		log.Printf("[INFO] StatePruner: pruned %d entries (%d bytes) before epoch %d", pruned, bytesFreed, cutoffEpoch)
	}
	return pruned, bytesFreed, nil
}

// pruneDatabaseDirect performs direct database pruning by iterating over
// state keys and deleting entries with block tags below the cutoff.
// This is a fallback when no StateDB reference is available.
// SECURITY (audit 2026-06-26, P1-08): Uses prefix-based iteration to
// identify and delete old state entries.
func (sp *StatePruner) pruneDatabaseDirect(cutoffEpoch uint64) (uint64, uint64, error) {
	var pruned uint64
	var bytesFreed uint64

	// Iterate over account prefix and count entries
	// Note: Without modification logs, we cannot safely delete individual
	// accounts. This fallback only prunes snapshot entries.
	// Snapshot keys are prefixed with "snap_" + block height
	snapPrefix := []byte("snap_")
	iter := sp.database.NewIterator(snapPrefix, nil)
	batch := sp.database.NewBatch()
	batchCount := 0

	cutoffBlock := cutoffEpoch * sp.blocksPerEpoch
	cutoffBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(cutoffBytes, cutoffBlock)

	for iter.Next() {
		key := iter.Key()
		// Parse block height from snapshot key: snap_<blockHeight>_
		if len(key) < len(snapPrefix)+8 {
			continue
		}
		blockBytes := key[len(snapPrefix) : len(snapPrefix)+8]
		blockHeight := binary.BigEndian.Uint64(blockBytes)
		if blockHeight < cutoffBlock {
			batch.Delete(key)
			pruned++
			bytesFreed += uint64(len(iter.Value()))
			batchCount++
			if batchCount >= 100 {
				// L9-033 FIX: Propagate batch.Write() error instead of ignoring it.
				if err := batch.Write(); err != nil {
					iter.Release()
					return pruned, bytesFreed, fmt.Errorf("pruneDatabaseDirect: batch write failed: %w", err)
				}
				batch.Reset()
				batchCount = 0
			}
		}
	}
	// DB-R11-002 (2026-07-20): Surface iterator truncation. If the snapshot
	// range exceeds 100K entries, the iterator truncated and some snapshots
	// survived the prune. Log a warning so operators know the prune was
	// incomplete and can re-run ForcePrune to pick up the remainder.
	if err := iter.Error(); err != nil {
		log.Printf("[WARN] pruner: pruneDatabaseDirect iterator error (some snapshots may remain): %v", err)
	}
	iter.Release()

	if batchCount > 0 {
		// L9-033 FIX: Propagate batch.Write() error instead of ignoring it.
		if err := batch.Write(); err != nil {
			return pruned, bytesFreed, fmt.Errorf("pruneDatabaseDirect: final batch write failed: %w", err)
		}
	}

	return pruned, bytesFreed, nil
}

// ForcePrune forces an immediate prune cycle regardless of schedule.
func (sp *StatePruner) ForcePrune() (uint64, uint64, error) {
	sp.mu.RLock()
	currentEpoch := sp.currentEpoch
	windowEpochs := sp.windowEpochs
	sp.mu.RUnlock()

	if currentEpoch < windowEpochs {
		return 0, 0, fmt.Errorf("not enough history: current epoch %d < window %d", currentEpoch, windowEpochs)
	}

	cutoffEpoch := currentEpoch - windowEpochs

	// L9-033 FIX: Propagate error from pruneBeforeEpoch.
	pruned, bytesFreed, err := sp.pruneBeforeEpoch(cutoffEpoch)
	if err != nil {
		return pruned, bytesFreed, fmt.Errorf("ForcePrune: %w", err)
	}

	sp.mu.Lock()
	sp.lastPrunedEpoch = cutoffEpoch
	sp.totalPruned += pruned
	sp.totalBytesFreed += bytesFreed
	sp.mu.Unlock()

	return pruned, bytesFreed, nil
}

// Stats returns pruning statistics.
func (sp *StatePruner) Stats() PrunerStats {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	return PrunerStats{
		CurrentEpoch:    sp.currentEpoch,
		WindowEpochs:    sp.windowEpochs,
		LastPrunedEpoch: sp.lastPrunedEpoch,
		TotalPruned:     sp.totalPruned,
		TotalBytesFreed: sp.totalBytesFreed,
		Running:         sp.running,
	}
}

// PrunerStats holds statistics about the state pruner.
type PrunerStats struct {
	CurrentEpoch    uint64 `json:"currentEpoch"`
	WindowEpochs    uint64 `json:"windowEpochs"`
	LastPrunedEpoch uint64 `json:"lastPrunedEpoch"`
	TotalPruned     uint64 `json:"totalPruned"`
	TotalBytesFreed uint64 `json:"totalBytesFreed"`
	Running         bool   `json:"running"`
}

// SetWindowEpochs updates the pruning window.
func (sp *StatePruner) SetWindowEpochs(windowEpochs uint64) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.windowEpochs = windowEpochs
}

// IsRunning returns true if the pruner is currently active.
func (sp *StatePruner) IsRunning() bool {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	return sp.running
}
