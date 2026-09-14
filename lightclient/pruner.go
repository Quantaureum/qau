// Quantaureum Node source, version 1.0.0.
package lightclient

import (
	"sync"
	"time"

	"github.com/quantaureum/qau/qaudb/state"
)

type PrunerConfig struct {
	CheckpointRetention uint64
	PruneInterval       time.Duration
	MaxPruneBatchSize   uint64
}

func DefaultPrunerConfig() *PrunerConfig {
	return &PrunerConfig{
		CheckpointRetention: 3,
		PruneInterval:       5 * time.Minute,
		MaxPruneBatchSize:   2000,
	}
}

type StatePruner struct {
	stateDB *state.StateDB
	syncer  *HeaderSyncer
	config  *PrunerConfig
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
}

func NewStatePruner(stateDB *state.StateDB, syncer *HeaderSyncer, config *PrunerConfig) *StatePruner {
	if config == nil {
		config = DefaultPrunerConfig()
	}
	return &StatePruner{
		stateDB: stateDB,
		syncer:  syncer,
		config:  config,
		stopCh:  make(chan struct{}),
	}
}

func (sp *StatePruner) Start() {
	sp.mu.Lock()
	if sp.stopped {
		sp.mu.Unlock()
		return
	}
	sp.mu.Unlock()

	go sp.pruneLoop()
}

func (sp *StatePruner) Stop() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.stopped {
		return
	}
	sp.stopped = true
	close(sp.stopCh)
}

func (sp *StatePruner) pruneLoop() {
	ticker := time.NewTicker(sp.config.PruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sp.stopCh:
			return
		case <-ticker.C:
			sp.prune()
		}
	}
}

func (sp *StatePruner) prune() {
	if sp.stateDB == nil || sp.syncer == nil {
		return
	}

	checkpoints := sp.syncer.GetAllCheckpoints()
	if len(checkpoints) == 0 {
		return
	}

	retention := sp.config.CheckpointRetention
	if retention == 0 {
		retention = 1
	}
	if uint64(len(checkpoints)) <= retention {
		return
	}

	var oldestRetainedHeight uint64 = ^uint64(0)
	for _, cp := range checkpoints {
		if cp.Height < oldestRetainedHeight {
			oldestRetainedHeight = cp.Height
		}
	}

	pruneBefore := oldestRetainedHeight
	if pruneBefore > 0 {
		pruneBefore--
	}

	sp.stateDB.SetPruneKeepBlocks(pruneBefore)
	sp.stateDB.SetPruneBatchSize(sp.config.MaxPruneBatchSize)

	currentHeight := sp.syncer.GetLatestHeight()
	if currentHeight > 0 {
		_ = sp.stateDB.PruneState(currentHeight)
	}
}

func (sp *StatePruner) PruneNow() {
	sp.prune()
}
