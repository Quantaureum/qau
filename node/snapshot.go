// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
)

// SnapshotManager manages state-snapshot creation and restore
type SnapshotManager struct {
	db          db.Database
	snapshotDir string
	interval    uint64 // blocks between snapshots
	keepCount   int    // number of recent snapshots to keep
	mu          sync.Mutex
	stopCh      chan struct{}
	stopOnce    sync.Once      // FIX: prevent double-close panic
	wg          sync.WaitGroup // FIX: track goroutine lifecycle
}

// snapshotMeta describes snapshot metadata
type snapshotMeta struct {
	Height    uint64 `json:"height"`
	Timestamp int64  `json:"timestamp"`
	BlockHash string `json:"block_hash"`
}

// NewSnapshotManager constructs a snapshot manager
func NewSnapshotManager(database db.Database, dir string, interval uint64, keepCount int) *SnapshotManager {
	return &SnapshotManager{
		db:          database,
		snapshotDir: dir,
		interval:    interval,
		keepCount:   keepCount,
		stopCh:      make(chan struct{}),
	}
}

// CreateSnapshot produces a snapshot at the given height
// exports the current DB state into the target directory
func (sm *SnapshotManager) CreateSnapshot(height uint64) error {
	// R35 P3 FIX (2026-07-29): Move I/O outside the lock. All struct fields
	// accessed here (snapshotDir, db) are immutable after construction, so
	// holding sm.mu during file I/O unnecessarily serializes callers and
	// blocks auto-snapshot/StopAutoSnapshot. Copy the immutable config under
	// the lock, then release before doing any I/O.
	sm.mu.Lock()
	snapshotDir := sm.snapshotDir
	sm.mu.Unlock()

	// create the snapshot directory
	snapDir := filepath.Join(snapshotDir, fmt.Sprintf("snapshot-%d", height))
	if err := os.MkdirAll(snapDir, 0755); err != nil {
		return fmt.Errorf("failed to create snapshot directory: %w", err)
	}

	// write metadata
	meta := snapshotMeta{
		Height:    height,
		Timestamp: time.Now().Unix(),
	}
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	metaPath := filepath.Join(snapDir, "meta.json")
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// export the database contents to the data file
	dataPath := filepath.Join(snapDir, "data.json")
	if err := sm.exportDatabase(dataPath); err != nil {
		// remove the failed snapshot directory
		os.RemoveAll(snapDir)
		return fmt.Errorf("failed to export the database: %w", err)
	}

	return nil
}

// RestoreSnapshot loads the snapshot at the given height
func (sm *SnapshotManager) RestoreSnapshot(height uint64) error {
	// R35 P3 FIX (2026-07-29): Move I/O outside the lock. snapshotDir is
	// immutable after construction; sm.db (used by importDatabase) has its
	// own internal locking. Holding sm.mu during file reads and DB writes
	// unnecessarily blocks concurrent operations.
	sm.mu.Lock()
	snapshotDir := sm.snapshotDir
	sm.mu.Unlock()

	snapDir := filepath.Join(snapshotDir, fmt.Sprintf("snapshot-%d", height))
	metaPath := filepath.Join(snapDir, "meta.json")
	dataPath := filepath.Join(snapDir, "data.json")

	// ensure the snapshot exists
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		return fmt.Errorf("no snapshot exists at height %d", height)
	}

	// validate metadata
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}
	var meta snapshotMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}
	if meta.Height != height {
		return fmt.Errorf("snapshot metadata height mismatch: wanted %d, got %d", height, meta.Height)
	}

	// import the data into the database
	if err := sm.importDatabase(dataPath); err != nil {
		return fmt.Errorf("failed to import the database: %w", err)
	}

	return nil
}

// ListSnapshots returns available snapshot heights in ascending order
func (sm *SnapshotManager) ListSnapshots() ([]uint64, error) {
	entries, err := os.ReadDir(sm.snapshotDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read the snapshot directory: %w", err)
	}

	var heights []uint64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// parse the height from the directory name
		var h uint64
		if _, err := fmt.Sscanf(entry.Name(), "snapshot-%d", &h); err != nil {
			continue
		}

		// metadata file exists
		metaPath := filepath.Join(sm.snapshotDir, entry.Name(), "meta.json")
		if _, err := os.Stat(metaPath); err != nil {
			continue
		}

		heights = append(heights, h)
	}

	sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })
	return heights, nil
}

// PruneSnapshots removes older snapshots, keeping the most recent keepCount
func (sm *SnapshotManager) PruneSnapshots() error {
	// R35 P3 FIX (2026-07-29): Move I/O outside the lock. snapshotDir and
	// keepCount are immutable after construction; ListSnapshots does os.ReadDir
	// and os.RemoveAll does filesystem I/O — neither needs sm.mu. Holding the
	// lock during these operations blocks concurrent CreateSnapshot calls and
	// the auto-snapshot goroutine.
	sm.mu.Lock()
	snapshotDir := sm.snapshotDir
	keepCount := sm.keepCount
	sm.mu.Unlock()

	heights, err := sm.ListSnapshots()
	if err != nil {
		return err
	}

	// If fewer snapshots exist than keepCount, nothing to do
	if len(heights) <= keepCount {
		return nil
	}

	// Delete the oldest snapshot
	toDelete := heights[:len(heights)-keepCount]
	for _, h := range toDelete {
		snapDir := filepath.Join(snapshotDir, fmt.Sprintf("snapshot-%d", h))
		if err := os.RemoveAll(snapDir); err != nil {
			return fmt.Errorf("failed to delete snapshot %d: %w", h, err)
		}
		// On Windows, os.RemoveAll may return nil but leave the directory
		// visible due to pending file deletes. Manually remove any
		// remaining files and the directory itself.
		if entries, derr := os.ReadDir(snapDir); derr == nil {
			for _, e := range entries {
				_ = os.Remove(filepath.Join(snapDir, e.Name()))
			}
			_ = os.Remove(snapDir)
		}
	}

	return nil
}

// StartAutoSnapshot starts the automatic snapshot goroutine
// getHeight is a callback used to fetch the current block height
func (sm *SnapshotManager) StartAutoSnapshot(getHeight func() uint64) {
	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				// FIX: log panics for debugging
				log.Printf("SnapshotManager auto-snapshot goroutine panic: %v", r)
			}
		}()

		var lastSnapshotHeight uint64

		for {
			select {
			case <-sm.stopCh:
				return
			case <-time.After(10 * time.Second):
				currentHeight := getHeight()

				// check if a snapshot is due
				if currentHeight > 0 && currentHeight-lastSnapshotHeight >= sm.interval {
					if err := sm.CreateSnapshot(currentHeight); err != nil {
						continue
					}
					lastSnapshotHeight = currentHeight

					// after creating a snapshot, prune old ones
					_ = sm.PruneSnapshots()
				}
			}
		}
	}()
}

// StopAutoSnapshot stops automatic snapshotting
func (sm *SnapshotManager) StopAutoSnapshot() {
	// FIX: use sync.Once to prevent double-close panic
	sm.stopOnce.Do(func() {
		close(sm.stopCh)
	})
	sm.wg.Wait()
}

// exportDatabase writes the database contents to a JSON file
func (sm *SnapshotManager) exportDatabase(path string) error {
	iter := sm.db.NewIterator(nil, nil)
	defer iter.Release()

	// collect all key-value pairs
	type kvEntry struct {
		Key   []byte `json:"key"`
		Value []byte `json:"value"`
	}
	var entries []kvEntry

	for iter.Next() {
		key := make([]byte, len(iter.Key()))
		copy(key, iter.Key())
		value := make([]byte, len(iter.Value()))
		copy(value, iter.Value())
		entries = append(entries, kvEntry{Key: key, Value: value})
	}

	if err := iter.Error(); err != nil {
		return fmt.Errorf("database iteration failed: %w", err)
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("failed to serialize data: %w", err)
	}

	// R12-NODE-003 FIX: Use 0600 (owner-only) instead of 0644 (world-readable).
	// Snapshot files contain full database state including account data.
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write data file: %w", err)
	}

	return nil
}

// importDatabase loads a JSON data file into the database
func (sm *SnapshotManager) importDatabase(path string) error {
	// R12-NODE-004 FIX: Validate file integrity before importing.
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	// R12-NODE-003/R12-NODE-004: Check file permissions are owner-only.
	// On Windows, Unix permission bits are not meaningful (always 0666),
	// so skip this check. On Unix, enforce 0600.
	if info.Mode().Perm()&0077 != 0 && runtime.GOOS != "windows" {
		return fmt.Errorf("snapshot file permissions too permissive: %o (must be 0600)", info.Mode().Perm())
	}
	// Reject suspiciously large files (>10GB)
	if info.Size() > 10*1024*1024*1024 {
		return fmt.Errorf("snapshot file too large: %d bytes", info.Size())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read data file: %w", err)
	}

	type kvEntry struct {
		Key   []byte `json:"key"`
		Value []byte `json:"value"`
	}

	var entries []kvEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to deserialize data: %w", err)
	}

	// use a batch write for atomicity
	batch := sm.db.NewBatch()
	for _, entry := range entries {
		if err := batch.Put(entry.Key, entry.Value); err != nil {
			return fmt.Errorf("failed to write batch: %w", err)
		}
	}

	if err := batch.Write(); err != nil {
		return fmt.Errorf("failed to commit batch: %w", err)
	}

	return nil
}
