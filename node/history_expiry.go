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

func DefaultHistoryExpirationConfig() HistoryExpirationConfig {
	return HistoryExpirationConfig{
		Enabled:         true,
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

	if he.running {
		return nil
	}

	he.running = true
	// R46-RP-02 FIX: Track the goroutine with a WaitGroup so Stop() can
	// wait for it to exit, preventing the race where Stop() closes stopCh
	// and makes a new one while the goroutine is still reading the old one.
	he.wg.Add(1)
	go func() {
		defer he.wg.Done()
		he.pruneLoop()
	}()
	return nil
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

func (he *HistoryExpirer) pruneHistory() {
	he.mu.Lock()
	config := he.config
	he.mu.Unlock()

	if !config.Enabled {
		return
	}

	currentHeight := he.blockStore.GetLatestHeight()
	if currentHeight < config.RetentionBlocks {
		return
	}

	pruneBefore := currentHeight - config.RetentionBlocks

	he.mu.Lock()
	if pruneBefore <= he.stats.LastPrunedBlock+config.PruneInterval {
		he.mu.Unlock()
		return
	}
	he.mu.Unlock()

	startTime := time.Now()

	oldestHeight := he.blockStore.GetOldestHeight()
	if oldestHeight >= pruneBefore {
		return
	}

	bytesFreed, err := he.blockStore.DeleteBlockRange(oldestHeight, pruneBefore)
	if err != nil {
		return
	}

	he.mu.Lock()
	he.stats.LastPrunedBlock = pruneBefore
	he.stats.TotalBlocksPruned += pruneBefore - oldestHeight
	he.stats.TotalBytesFreed += bytesFreed
	he.stats.LastPruneTime = startTime
	he.stats.LastPruneDuration = time.Since(startTime)
	he.mu.Unlock()
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

func (he *HistoryExpirer) ForcePrune() (uint64, error) {
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
	oldestHeight := he.blockStore.GetOldestHeight()
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
	he.stats.LastPruneTime = time.Now()
	he.mu.Unlock()

	return bytesFreed, nil
}
