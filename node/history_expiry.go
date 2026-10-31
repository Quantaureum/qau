// Quantaureum Node source, version 1.0.0.
package node

import (
	"errors"
	"sync"
	"time"

	"github.com/quantaureum/qau/encoding"
)

var (
	ErrHistoryExpirationDisabled = errors.New("history expiration is disabled")
	ErrInvalidRetentionPeriod    = errors.New("invalid retention period")
	// ErrHistoryExpiryUnsupported reports that block-history pruning was
	// requested but is refused. R30 F4 (2026-10-30): deleting blocks from the
	// bottom of the store leaves a gap that BlockStore.findContinuousTipLocked
	// cannot see past (it scans upward from height 1 and stops at the first
	// missing height), so the next restart reports continuousTip == 0 and the
	// R53 fragmented-chain repair deletes everything above genesis. It also
	// removes the blocks a restored finality checkpoint is anchored to. State
	// pruning is the supported way to bound disk usage.
	ErrHistoryExpiryUnsupported = errors.New("block-history expiry is unsupported: deleting blocks below the tip breaks store continuity and leaves restored finality checkpoints without backing blocks; use state pruning instead")
)

const (
	DefaultHistoryRetentionBlocks = 31536000 // ~1 year at 1s blocks
	DefaultHistoryRetentionTime   = 365 * 24 * time.Hour
	MinHistoryRetentionBlocks     = 50000 // Minimum ~14 hours
	MaxHistoryRetentionBlocks     = 100000000
)

type HistoryExpirationConfig struct {
	Enabled         bool
	RetentionBlocks uint64
	RetentionTime   time.Duration
	PruneBatchSize  uint64
	PruneInterval   uint64
}

// DefaultHistoryExpirationConfig returns the default configuration. R30 F4:
// Enabled is false because block-history pruning is unsupported (see
// ErrHistoryExpiryUnsupported); the retention values remain for a future,
// continuity-aware implementation.
func DefaultHistoryExpirationConfig() HistoryExpirationConfig {
	return HistoryExpirationConfig{
		Enabled:         false,
		RetentionBlocks: DefaultHistoryRetentionBlocks,
		RetentionTime:   DefaultHistoryRetentionTime,
		PruneBatchSize:  1000,
		PruneInterval:   1024,
	}
}

type HistoryExpirationStats struct {
	Enabled           bool
	RetentionBlocks   uint64
	RetentionTime     time.Duration
	LastPrunedBlock   uint64
	TotalBlocksPruned uint64
	TotalBytesFreed   uint64
	LastPruneTime     time.Time
	LastPruneDuration time.Duration
}

type HistoryExpirer struct {
	mu         sync.Mutex
	config     HistoryExpirationConfig
	stats      HistoryExpirationStats
	blockStore BlockStoreReader
	running    bool
	stopCh     chan struct{}
	// R46-RP-02: WaitGroup for graceful shutdown of the prune goroutine.
	wg sync.WaitGroup
}

type BlockStoreReader interface {
	GetBlockByHeight(height uint64) (*encoding.Block, error)
	DeleteBlockRange(from, to uint64) (uint64, error)
	GetLatestHeight() uint64
	GetOldestHeight() uint64
}

func NewHistoryExpirer(config HistoryExpirationConfig, blockStore BlockStoreReader) *HistoryExpirer {
	return &HistoryExpirer{
		config:     config,
		blockStore: blockStore,
		stats: HistoryExpirationStats{
			Enabled:         config.Enabled,
			RetentionBlocks: config.RetentionBlocks,
			RetentionTime:   config.RetentionTime,
		},
		stopCh: make(chan struct{}),
	}
}

func (he *HistoryExpirer) Start() error {
	he.mu.Lock()
	defer he.mu.Unlock()

	if !he.config.Enabled {
		return ErrHistoryExpirationDisabled
	}

	// R30 F4: refuse to start instead of corrupting the store. This is the only
	// production entry point, so blocking it here keeps pruneLoop from ever
	// running.
	nodeLog.Error("history expiry: refusing to enable block-history pruning; deleting blocks below the tip breaks store continuity and finality backing. Unset QAU_HISTORY_EXPIRY and use state pruning instead")
	return ErrHistoryExpiryUnsupported
}

func (he *HistoryExpirer) Stop() {
	he.mu.Lock()
	if he.running {
		close(he.stopCh)
		he.running = false
	}
	he.mu.Unlock()
	// R46-RP-02 FIX: Wait for the goroutine to exit outside the lock
	// to avoid deadlock (pruneLoop may try to acquire he.mu).
	he.wg.Wait()
	// Reset stopCh for future Start() calls.
	he.mu.Lock()
	he.stopCh = make(chan struct{})
	he.mu.Unlock()
}

func (he *HistoryExpirer) pruneLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("panic in pruneLoop: %v", r)
		}
	}()

	for {
		select {
		case <-he.stopCh:
			return
		case <-ticker.C:
			he.pruneHistory()
		}
	}
}

// pruneHistory runs one prune pass from the background loop. R30 F4: dormant,
// because Start() refuses to launch pruneLoop while block-history pruning is
// unsupported. It stays wired to pruneOnce so that the algorithm keeps its unit
// tests and any future, continuity-aware implementation has one call site.
func (he *HistoryExpirer) pruneHistory() {
	if _, err := he.pruneOnce(); err != nil && !errors.Is(err, ErrHistoryExpirationDisabled) {
		nodeLog.Warn("history expiry: prune pass skipped: %v", err)
	}
}

// pruneOnce is the pruning algorithm itself: it deletes the range
// [oldestHeight, latestHeight-retention] when that range is non-empty and enough
// new history has accumulated since the last pass.
//
// R30 F4 (2026-10-30): this must NOT be reachable from production code paths
// while ErrHistoryExpiryUnsupported stands — see that error for why deleting the
// bottom of the store breaks continuity and finality backing. The genesis clamp
// below is defense in depth: an adapter that reports 0 (BlockStore does not
// track its oldest height) must never cause the genesis block to be deleted.
func (he *HistoryExpirer) pruneOnce() (uint64, error) {
	he.mu.Lock()
	config := he.config
	he.mu.Unlock()

	if !config.Enabled {
		return 0, ErrHistoryExpirationDisabled
	}

	currentHeight := he.blockStore.GetLatestHeight()
	if currentHeight < config.RetentionBlocks {
		return 0, nil
	}

	pruneBefore := currentHeight - config.RetentionBlocks

	he.mu.Lock()
	tooSoon := pruneBefore <= he.stats.LastPrunedBlock+config.PruneInterval
	he.mu.Unlock()
	if tooSoon {
		return 0, nil
	}

	startTime := time.Now()

	oldestHeight := he.blockStore.GetOldestHeight()
	if oldestHeight < 1 {
		oldestHeight = 1
	}
	if oldestHeight >= pruneBefore {
		return 0, nil
	}

	bytesFreed, err := he.blockStore.DeleteBlockRange(oldestHeight, pruneBefore)
	if err != nil {
		return 0, err
	}

	he.mu.Lock()
	he.stats.LastPrunedBlock = pruneBefore
	he.stats.TotalBlocksPruned += pruneBefore - oldestHeight
	he.stats.TotalBytesFreed += bytesFreed
	he.stats.LastPruneTime = startTime
	he.stats.LastPruneDuration = time.Since(startTime)
	he.mu.Unlock()

	return bytesFreed, nil
}

func (he *HistoryExpirer) GetStats() HistoryExpirationStats {
	he.mu.Lock()
	defer he.mu.Unlock()
	return he.stats
}

func (he *HistoryExpirer) UpdateConfig(config HistoryExpirationConfig) error {
	if config.RetentionBlocks < MinHistoryRetentionBlocks {
		return ErrInvalidRetentionPeriod
	}
	if config.RetentionBlocks > MaxHistoryRetentionBlocks {
		config.RetentionBlocks = MaxHistoryRetentionBlocks
	}

	// R12-NODE-001 FIX: Inline Stop/Start logic to avoid self-deadlock.
	// Previously, UpdateConfig held he.mu (defer Unlock) then called
	// he.Stop() and he.Start(), both of which try to re-acquire he.mu.
	// sync.Mutex is non-reentrant, causing a permanent deadlock.
	he.mu.Lock()

	wasRunning := he.running
	if wasRunning {
		// Inline stop: close stopCh, mark not running
		close(he.stopCh)
		he.running = false
		he.mu.Unlock()
		// Wait for goroutine to exit (outside lock to avoid deadlock)
		he.wg.Wait()
		he.mu.Lock()
		he.stopCh = make(chan struct{})
	}

	// R30 F4: UpdateConfig can note the requested configuration, but it can never
	// start the pruner: Start() is the only place that sets he.running and it now
	// refuses while block-history pruning is unsupported. The stats mirror the
	// requested config, not the running state.
	he.config = config
	he.stats.Enabled = config.Enabled
	he.stats.RetentionBlocks = config.RetentionBlocks
	he.stats.RetentionTime = config.RetentionTime

	if wasRunning && config.Enabled {
		// Inline start: launch goroutine
		he.running = true
		he.wg.Add(1)
		go func() {
			defer he.wg.Done()
			he.pruneLoop()
		}()
	}

	he.mu.Unlock()
	return nil
}

// ForcePrune forces a prune pass. R30 F4: refused while block-history pruning is
// unsupported — the operator-facing way to reclaim space is state pruning, not
// deleting the bottom of the block store (see ErrHistoryExpiryUnsupported).
func (he *HistoryExpirer) ForcePrune() (uint64, error) {
	he.mu.Lock()
	config := he.config
	he.mu.Unlock()

	if !config.Enabled {
		return 0, ErrHistoryExpirationDisabled
	}

	nodeLog.Error("history expiry: refusing forced block-history prune; deleting blocks below the tip breaks store continuity and finality backing. Use state pruning instead")
	return 0, ErrHistoryExpiryUnsupported
}
