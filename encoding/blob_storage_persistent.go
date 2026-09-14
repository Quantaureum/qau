// Quantaureum Node source, version 1.0.0.
package encoding

// Persistent Blob Storage — P0-9 (2026-07-14)
//
// Wraps the in-memory BlobStorage with a persistence layer so blob matrices
// survive node restarts. Without this, DAS sampling requests for historical
// slots fail after a restart, breaking data availability guarantees.
//
// Design:
//   - Hot cache: in-memory map (existing BlobStorage) for recent slots
//   - Cold storage: pluggable KV store (BlobKVStore interface) for all slots
//   - StoreMatrix writes to both cache and cold storage
//   - GetCell checks cache first, then falls back to cold storage (and
//     promotes the entry back into the hot cache on cache miss)
//   - GC evicts from both layers based on retention config
//
// The BlobKVStore interface is defined here so the encoding package does NOT
// depend on bbolt. The caller (node/node.go) injects a bbolt-backed adapter
// that implements BlobKVStore.
//
// Key schema in KV store:
//   da:blob:<slot>:<blobIndex> -> serialized BlobStorageEntry
//
// Serialization: length-prefixed binary format (not JSON) because the matrix
// is a fixed-size array of fixed-size cells — binary is compact and avoids
// reflection overhead.

import (
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"
)

// BlobKVStore is the persistence interface for blob storage. It's a subset
// of the qaudb.Database interface, defined here to keep the encoding package
// independent of the storage implementation.
// P0-9 (2026-07-14)
type BlobKVStore interface {
	// Get retrieves a value by key. Returns an error wrapping ErrBlobNotFound
	// if the key does not exist.
	Get(key []byte) ([]byte, error)
	// Put stores a key-value pair.
	Put(key, value []byte) error
	// Delete removes a key-value pair.
	Delete(key []byte) error
	// Has checks if a key exists.
	Has(key []byte) (bool, error)
	// NewIterator creates an iterator over keys with the given prefix.
	NewIterator(prefix []byte, start []byte) BlobKVIterator
}

// BlobKVIterator iterates over a BlobKVStore's key/value pairs in key order.
type BlobKVIterator interface {
	Next() bool
	Key() []byte
	Value() []byte
	Error() error
	Release()
}

// ErrBlobNotFound is returned when a blob is not found in the KV store.
// P0-9 (2026-07-14)
var ErrBlobNotFound = fmt.Errorf("blob not found in KV store")

// BlobStorageBackend is the storage abstraction used by DankshardingEngine.
// Both *BlobStorage (in-memory) and *PersistentBlobStorage (cache + KV store)
// implement this interface, allowing the engine to swap implementations
// without changing its code.
// P0-9 (2026-07-14)
type BlobStorageBackend interface {
	StoreMatrix(slot uint64, blobIndex int, matrix BlobMatrixExtended, commitments []KZGCommitment) error
	GetCell(slot uint64, blobIndex, row, col int) (*Cell, *KZGCommitment, error)
	GetCommitments(slot uint64) []KZGCommitment
	HasBlob(slot uint64, blobIndex int) bool
	GetBlobCount(slot uint64) int
	GC(currentSlot uint64)
	SetRetentionConfig(cfg DASRetentionConfig)
}

// Compile-time assertions that both implementations satisfy the interface.
var _ BlobStorageBackend = (*BlobStorage)(nil)
var _ BlobStorageBackend = (*PersistentBlobStorage)(nil)

// PersistentBlobStorage is a BlobStorage implementation backed by a pluggable
// KV store. It maintains an in-memory LRU hot cache for recent slots and a
// persistent store for historical slots.
// P0-9 (2026-07-14)
type PersistentBlobStorage struct {
	mu          sync.RWMutex
	cache       map[string]*BlobStorageEntry
	cacheOrder  []string // FIFO order for eviction
	maxSize     int64
	currentSize int64
	retention   DASRetentionConfig
	store       BlobKVStore
}

// NewPersistentBlobStorage creates a new persistent blob storage backed by
// the given KV store. If store is nil, the storage operates in memory-only
// mode (same as BlobStorage) — useful for testing and for nodes that don't
// need persistence.
func NewPersistentBlobStorage(store BlobKVStore) *PersistentBlobStorage {
	return &PersistentBlobStorage{
		cache:     make(map[string]*BlobStorageEntry),
		maxSize:   MaxBlobStorageSize,
		retention: DefaultDASRetentionConfig(),
		store:     store,
	}
}

// NewPersistentBlobStorageWithRetention creates a persistent blob storage
// with a custom retention configuration.
func NewPersistentBlobStorageWithRetention(store BlobKVStore, retention DASRetentionConfig) *PersistentBlobStorage {
	return &PersistentBlobStorage{
		cache:     make(map[string]*BlobStorageEntry),
		maxSize:   MaxBlobStorageSize,
		retention: retention,
		store:     store,
	}
}

// SetRetentionConfig updates the retention configuration.
// DA-R5-05 (2026-07-16): Rejects invalid configurations (those violating
// the Blob >= Session >= Attest > Decay invariants) and keeps the previous
// config — fail-closed against accidental availability regression.
func (s *PersistentBlobStorage) SetRetentionConfig(cfg DASRetentionConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validateAndLogRetention(cfg, "PersistentBlobStorage.SetRetentionConfig") {
		return
	}
	s.retention = cfg
}

func (s *PersistentBlobStorage) key(slot uint64, blobIndex int) string {
	return fmt.Sprintf("%d:%d", slot, blobIndex)
}

func (s *PersistentBlobStorage) dbKey(slot uint64, blobIndex int) []byte {
	// da:blob:<slot>:<blobIndex>
	// Fixed-length 21-byte key: "da:blob:" (8) + slot (8) + ":" (1) + blobIndex (4)
	k := make([]byte, 21)
	copy(k[0:8], []byte("da:blob:"))
	binary.BigEndian.PutUint64(k[8:16], slot)
	k[16] = ':'
	binary.BigEndian.PutUint32(k[17:21], uint32(blobIndex))
	return k
}

func (s *PersistentBlobStorage) entrySize(entry *BlobStorageEntry) int64 {
	size := int64(len(entry.Commitments) * 48)
	size += entry.Matrix.MemoryBytes()
	return size
}

// StoreMatrix stores a blob matrix and its commitments in both the hot cache
// and the persistent KV store.
func (s *PersistentBlobStorage) StoreMatrix(slot uint64, blobIndex int, matrix BlobMatrixExtended, commitments []KZGCommitment) error {
	s.mu.Lock()

	// P1-13 (2026-07-14): Infer originalCount for sparse storage.
	originalCount := MaxBlobColumns
	if commitments != nil {
		originalCount = len(commitments)
		if originalCount > MaxBlobColumns {
			originalCount = MaxBlobColumns
		}
	} else {
		commitments = ComputeKZGCommitmentsForMatrix(matrix, MaxBlobColumnsExt)
	}

	k := s.key(slot, blobIndex)
	if _, exists := s.cache[k]; exists {
		// Already in cache — assume already persisted
		s.mu.Unlock()
		return nil
	}

	entry := &BlobStorageEntry{
		Slot:        slot,
		BlobIndex:   blobIndex,
		Matrix:      NewSparseBlobMatrix(matrix, originalCount),
		Commitments: commitments,
		StoredAt:    time.Now(),
	}
	entrySize := s.entrySize(entry)

	if s.currentSize+entrySize > s.maxSize {
		s.evictOldestLocked()
	}

	s.cache[k] = entry
	s.cacheOrder = append(s.cacheOrder, k)
	s.currentSize += entrySize
	s.mu.Unlock()

	// Persist to KV store outside the lock to avoid blocking other reads.
	// Errors are logged but non-fatal — the in-memory state is still correct,
	// only persistence is lost (same pattern as rollup persistence).
	if s.store != nil {
		data := encodePersistentEntry(entry)
		dbKey := s.dbKey(slot, blobIndex)
		if err := s.store.Put(dbKey, data); err != nil {
			log.Printf("[da] WARN: persist blob (slot=%d, index=%d) failed: %v", slot, blobIndex, err)
		}
	}

	return nil
}

// GetCell retrieves a cell from the hot cache, falling back to the KV store
// on cache miss. On cache miss, the entry is promoted back into the hot cache.
func (s *PersistentBlobStorage) GetCell(slot uint64, blobIndex, row, col int) (*Cell, *KZGCommitment, error) {
	s.mu.RLock()
	k := s.key(slot, blobIndex)
	entry, exists := s.cache[k]
	s.mu.RUnlock()

	if !exists && s.store != nil {
		// Cache miss — try KV store
		dbKey := s.dbKey(slot, blobIndex)
		data, err := s.store.Get(dbKey)
		if err != nil {
			return nil, nil, fmt.Errorf("blob not found: slot=%d, index=%d (cache miss, store error: %w)", slot, blobIndex, err)
		}
		entry, err = decodePersistentEntry(data)
		if err != nil {
			return nil, nil, fmt.Errorf("decode blob (slot=%d, index=%d): %w", slot, blobIndex, err)
		}
		// Promote to hot cache
		s.mu.Lock()
		if _, exists := s.cache[k]; !exists {
			if s.currentSize+s.entrySize(entry) > s.maxSize {
				s.evictOldestLocked()
			}
			s.cache[k] = entry
			s.cacheOrder = append(s.cacheOrder, k)
			s.currentSize += s.entrySize(entry)
		}
		s.mu.Unlock()
	} else if !exists {
		return nil, nil, fmt.Errorf("blob not found: slot=%d, index=%d", slot, blobIndex)
	}

	if col < 0 || col >= MaxBlobColumnsExt {
		return nil, nil, fmt.Errorf("column out of range: %d", col)
	}
	if row < 0 || row >= CellsPerBlobExtended {
		return nil, nil, fmt.Errorf("row out of range: %d", row)
	}

	cell := entry.Matrix.GetCellPtr(row, col)

	// R37-P3-17 FIX (2026-07-31): blobIndex must be non-negative.
	var commitment *KZGCommitment
	if blobIndex >= 0 && blobIndex < len(entry.Commitments) {
		commitment = &entry.Commitments[blobIndex]
	}

	return cell, commitment, nil
}

// GetCommitments returns commitments for a given slot from the cache or store.
func (s *PersistentBlobStorage) GetCommitments(slot uint64) []KZGCommitment {
	s.mu.RLock()
	for _, entry := range s.cache {
		if entry.Slot == slot {
			commitments := entry.Commitments
			s.mu.RUnlock()
			return commitments
		}
	}
	s.mu.RUnlock()

	// Cache miss — try KV store (scan all blob indices for this slot)
	if s.store != nil {
		prefix := []byte("da:blob:")
		slotBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(slotBytes, slot)
		prefix = append(prefix, slotBytes...)
		prefix = append(prefix, ':')

		iter := s.store.NewIterator(prefix, nil)
		defer iter.Release()
		if iter.Next() {
			entry, err := decodePersistentEntry(iter.Value())
			if err == nil {
				return entry.Commitments
			}
		}
		if err := iter.Error(); err != nil {
			log.Printf("[da] WARN: GetCommitments iterator error: %v", err)
		}
	}
	return nil
}

// HasBlob checks if a blob exists in cache or KV store.
func (s *PersistentBlobStorage) HasBlob(slot uint64, blobIndex int) bool {
	s.mu.RLock()
	_, exists := s.cache[s.key(slot, blobIndex)]
	s.mu.RUnlock()
	if exists {
		return true
	}
	if s.store != nil {
		ok, err := s.store.Has(s.dbKey(slot, blobIndex))
		return err == nil && ok
	}
	return false
}

// GetBlobCount returns the number of blobs for a given slot in the cache.
// Note: this only checks the cache, not the KV store, for performance.
func (s *PersistentBlobStorage) GetBlobCount(slot uint64) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, entry := range s.cache {
		if entry.Slot == slot {
			count++
		}
	}
	return count
}

// evictOldestLocked evicts the oldest entry from the hot cache.
// Caller must hold s.mu (write).
func (s *PersistentBlobStorage) evictOldestLocked() {
	if len(s.cacheOrder) == 0 {
		return
	}
	oldestKey := s.cacheOrder[0]
	s.cacheOrder = s.cacheOrder[1:]
	if entry, ok := s.cache[oldestKey]; ok {
		s.currentSize -= s.entrySize(entry)
		delete(s.cache, oldestKey)
	}
}

// GC evicts entries older than retention from both cache and KV store.
func (s *PersistentBlobStorage) GC(currentSlot uint64) {
	s.mu.Lock()
	retentionSlots := s.retention.BlobRetentionSlots
	var toDelete []string
	for k, entry := range s.cache {
		if entry.Slot+retentionSlots < currentSlot {
			s.currentSize -= s.entrySize(entry)
			delete(s.cache, k)
			toDelete = append(toDelete, k)
		}
	}
	// Rebuild cacheOrder without evicted keys
	if len(toDelete) > 0 {
		newOrder := make([]string, 0, len(s.cacheOrder)-len(toDelete))
		deleteSet := make(map[string]bool, len(toDelete))
		for _, k := range toDelete {
			deleteSet[k] = true
		}
		for _, k := range s.cacheOrder {
			if !deleteSet[k] {
				newOrder = append(newOrder, k)
			}
		}
		s.cacheOrder = newOrder
	}
	s.mu.Unlock()

	// Delete from KV store outside the lock
	if s.store != nil && len(toDelete) > 0 {
		for _, k := range toDelete {
			// Parse slot and blobIndex from key "slot:blobIndex"
			var slot uint64
			var idx int
			if _, err := fmt.Sscanf(k, "%d:%d", &slot, &idx); err == nil {
				if err := s.store.Delete(s.dbKey(slot, idx)); err != nil {
					log.Printf("[da] WARN: GC delete blob (slot=%d, index=%d) failed: %v", slot, idx, err)
				}
			}
		}
	}
}

// Stats returns the cache entry count and total cache size.
// Note: this only reflects the hot cache, not the KV store.
func (s *PersistentBlobStorage) Stats() (entryCount int, totalSize int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cache), s.currentSize
}

// --- Serialization ---

// encodePersistentEntry serializes a BlobStorageEntry into a compact binary
// format. P1-13 (2026-07-14): sparse format — only stores original columns.
//
// Layout:
//
//	[8]  Slot (uint64 big-endian)
//	[4]  BlobIndex (uint32 big-endian)
//	[8]  StoredAt (int64 unix nano, big-endian)
//	[4]  len(Commitments) (uint32)
//	[4]  OriginalCount (uint32) — P1-13: number of original columns stored
//	[48 * len(Commitments)]  Commitments
//	[OriginalCount * CellsPerBlobExtended * CellSize]  Matrix (original cols only)
//
// Total fixed overhead: 28 bytes + variable commitments.
// Sparse matrix size: n * 8192 * 32 bytes (n ≤ 6) — up to 50% smaller than
// the previous fixed 12 * 8192 * 32 = ~3MB.
func encodePersistentEntry(entry *BlobStorageEntry) []byte {
	commitCount := len(entry.Commitments)
	originalCount := entry.Matrix.OriginalCount
	matrixSize := originalCount * CellsPerBlobExtended * CellSize
	totalSize := 8 + 4 + 8 + 4 + 4 + commitCount*48 + matrixSize

	buf := make([]byte, totalSize)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:offset+8], entry.Slot)
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(entry.BlobIndex))
	offset += 4

	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(entry.StoredAt.UnixNano()))
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(commitCount))
	offset += 4

	// P1-13: OriginalCount field
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(originalCount))
	offset += 4

	for _, c := range entry.Commitments {
		copy(buf[offset:offset+48], c[:])
		offset += 48
	}

	// P1-13: Only serialize original columns, not parity.
	for col := 0; col < originalCount; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			copy(buf[offset:offset+CellSize], entry.Matrix.OriginalColumns[col][row][:])
			offset += CellSize
		}
	}

	return buf
}

// decodePersistentEntry deserializes a BlobStorageEntry from the binary format.
// P1-13 (2026-07-14): Sparse format — reads originalCount and only original
// columns. Parity columns are recomputed on demand via SparseBlobMatrix.
func decodePersistentEntry(data []byte) (*BlobStorageEntry, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("data too short: need >= 28, got %d", len(data))
	}

	offset := 0
	slot := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	blobIndex := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	storedAtNano := int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	commitCount := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// P1-13: OriginalCount field
	originalCount := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// R37-P3-16 FIX (2026-07-31): commitCount must be bounded. An unchecked
	// large value causes commitCount*48 to overflow int (wrap to negative
	// on 32-bit, or to a small positive on 64-bit), bypassing the length
	// check below and enabling a massive allocation in the loops that follow.
	if commitCount < 0 || commitCount > MaxBlobColumnsExt {
		return nil, fmt.Errorf("invalid commitCount: %d", commitCount)
	}
	if originalCount < 0 || originalCount > MaxBlobColumnsExt {
		return nil, fmt.Errorf("invalid originalCount: %d", originalCount)
	}

	expectedSize := 28 + commitCount*48 + originalCount*CellsPerBlobExtended*CellSize
	if len(data) < expectedSize {
		return nil, fmt.Errorf("data too short: need %d, got %d", expectedSize, len(data))
	}

	commitments := make([]KZGCommitment, commitCount)
	for i := 0; i < commitCount; i++ {
		copy(commitments[i][:], data[offset:offset+48])
		offset += 48
	}

	// P1-13: Read only original columns into SparseBlobMatrix.
	originalCols := make([]BlobCellsExtended, originalCount)
	for col := 0; col < originalCount; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			copy(originalCols[col][row][:], data[offset:offset+CellSize])
			offset += CellSize
		}
	}

	return &BlobStorageEntry{
		Slot:        slot,
		BlobIndex:   blobIndex,
		Matrix:      SparseBlobMatrix{OriginalColumns: originalCols, OriginalCount: originalCount},
		Commitments: commitments,
		StoredAt:    time.Unix(0, storedAtNano),
	}, nil
}
