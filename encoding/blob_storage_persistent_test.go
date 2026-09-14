// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

// mockBlobKVStore is an in-memory implementation of BlobKVStore for testing.
// It simulates a persistent KV store with sorted iteration.
type mockBlobKVStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMockBlobKVStore() *mockBlobKVStore {
	return &mockBlobKVStore{data: make(map[string][]byte)}
}

func (m *mockBlobKVStore) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[string(key)]
	if !ok {
		return nil, ErrBlobNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (m *mockBlobKVStore) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := make([]byte, len(value))
	copy(v, value)
	m.data[string(key)] = v
	return nil
}

func (m *mockBlobKVStore) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *mockBlobKVStore) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[string(key)]
	return ok, nil
}

func (m *mockBlobKVStore) NewIterator(prefix []byte, start []byte) BlobKVIterator {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.data {
		if bytes.HasPrefix([]byte(k), prefix) {
			if start == nil || bytes.Compare([]byte(k), start) >= 0 {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	out := make([]struct{ k, v []byte }, len(keys))
	for i, k := range keys {
		v := m.data[k]
		kc := make([]byte, len(k))
		copy(kc, k)
		vc := make([]byte, len(v))
		copy(vc, v)
		out[i] = struct{ k, v []byte }{kc, vc}
	}
	return &mockIterator{items: out, idx: -1}
}

type mockIterator struct {
	items []struct{ k, v []byte }
	idx   int
}

func (it *mockIterator) Next() bool {
	it.idx++
	return it.idx < len(it.items)
}

func (it *mockIterator) Key() []byte {
	if it.idx < 0 || it.idx >= len(it.items) {
		return nil
	}
	return it.items[it.idx].k
}

func (it *mockIterator) Value() []byte {
	if it.idx < 0 || it.idx >= len(it.items) {
		return nil
	}
	return it.items[it.idx].v
}

func (it *mockIterator) Error() error { return nil }

func (it *mockIterator) Release() {
	it.items = nil
}

// makeTestMatrix creates a BlobMatrixExtended filled with a deterministic
// pattern so tests can verify cell values round-trip correctly.
// P1-13: Only the first originalCount columns will be stored in sparse format;
// callers should verify original columns round-trip and parity columns are
// recomputed correctly via SparseBlobMatrix.
func makeTestMatrix(seed byte) BlobMatrixExtended {
	var m BlobMatrixExtended
	for col := 0; col < MaxBlobColumnsExt; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			for k := 0; k < CellSize; k++ {
				m[col][row][k] = seed ^ byte(col) ^ byte(row) ^ byte(k)
			}
		}
	}
	return m
}

func TestPersistentBlobStorage_SerializationRoundTrip(t *testing.T) {
	t.Run("with commitments", func(t *testing.T) {
		matrix := makeTestMatrix(0xAB)
		commitments := []KZGCommitment{
			{0x01, 0x02, 0x03}, {0x04, 0x05, 0x06}, {0x07, 0x08, 0x09},
		}
		// P1-13: originalCount = len(commitments) = 3
		originalCount := len(commitments)
		entry := &BlobStorageEntry{
			Slot:        42,
			BlobIndex:   3,
			Matrix:      NewSparseBlobMatrix(matrix, originalCount),
			Commitments: commitments,
			StoredAt:    time.Unix(0, 1700000000_000000000),
		}

		data := encodePersistentEntry(entry)
		if len(data) == 0 {
			t.Fatal("encodePersistentEntry returned empty data")
		}

		// P1-13: Expected size: 28 + 3*48 + 3*8192*32 = 28 + 144 + 786432 = 786604
		expectedSize := 28 + len(commitments)*48 + originalCount*CellsPerBlobExtended*CellSize
		if len(data) != expectedSize {
			t.Errorf("encoded size = %d, want %d", len(data), expectedSize)
		}

		decoded, err := decodePersistentEntry(data)
		if err != nil {
			t.Fatalf("decodePersistentEntry failed: %v", err)
		}

		if decoded.Slot != entry.Slot {
			t.Errorf("Slot: got %d, want %d", decoded.Slot, entry.Slot)
		}
		if decoded.BlobIndex != entry.BlobIndex {
			t.Errorf("BlobIndex: got %d, want %d", decoded.BlobIndex, entry.BlobIndex)
		}
		if !decoded.StoredAt.Equal(entry.StoredAt) {
			t.Errorf("StoredAt: got %v, want %v", decoded.StoredAt, entry.StoredAt)
		}
		if len(decoded.Commitments) != len(entry.Commitments) {
			t.Fatalf("Commitments length: got %d, want %d", len(decoded.Commitments), len(entry.Commitments))
		}
		for i, c := range entry.Commitments {
			if decoded.Commitments[i] != c {
				t.Errorf("Commitment[%d] mismatch", i)
			}
		}
		// P1-13: Spot-check original columns round-trip exactly.
		if decoded.Matrix.GetCell(0, 0) != entry.Matrix.GetCell(0, 0) {
			t.Error("Matrix[0][0] mismatch")
		}
		if decoded.Matrix.OriginalCount != originalCount {
			t.Errorf("OriginalCount: got %d, want %d", decoded.Matrix.OriginalCount, originalCount)
		}
	})

	t.Run("with empty commitments", func(t *testing.T) {
		matrix := makeTestMatrix(0x11)
		// P1-13: No commitments → originalCount defaults to MaxBlobColumns (6)
		entry := &BlobStorageEntry{
			Slot:        1,
			BlobIndex:   0,
			Matrix:      NewSparseBlobMatrix(matrix, MaxBlobColumns),
			Commitments: nil,
			StoredAt:    time.Unix(0, 0),
		}

		data := encodePersistentEntry(entry)
		decoded, err := decodePersistentEntry(data)
		if err != nil {
			t.Fatalf("decodePersistentEntry failed: %v", err)
		}
		if len(decoded.Commitments) != 0 {
			t.Errorf("expected 0 commitments, got %d", len(decoded.Commitments))
		}
		if decoded.Matrix.GetCell(0, 0) != entry.Matrix.GetCell(0, 0) {
			t.Error("Matrix mismatch")
		}
	})

	t.Run("decode invalid data", func(t *testing.T) {
		// Too short
		_, err := decodePersistentEntry([]byte{1, 2, 3})
		if err == nil {
			t.Error("expected error for short data")
		}

		// Truncated matrix
		matrix := makeTestMatrix(0x22)
		entry := &BlobStorageEntry{Slot: 1, BlobIndex: 0, Matrix: NewSparseBlobMatrix(matrix, MaxBlobColumns), Commitments: nil, StoredAt: time.Now()}
		data := encodePersistentEntry(entry)
		// Truncate by 100 bytes
		truncated := data[:len(data)-100]
		_, err = decodePersistentEntry(truncated)
		if err == nil {
			t.Error("expected error for truncated data")
		}
	})
}

func TestPersistentBlobStorage_MemoryOnly(t *testing.T) {
	// nil store → behaves like in-memory BlobStorage
	s := NewPersistentBlobStorage(nil)

	matrix := makeTestMatrix(0xCD)
	commitments := []KZGCommitment{{0xAA}, {0xBB}}

	if err := s.StoreMatrix(10, 0, matrix, commitments); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}

	if !s.HasBlob(10, 0) {
		t.Error("HasBlob(10, 0) should be true after store")
	}
	if s.HasBlob(10, 1) {
		t.Error("HasBlob(10, 1) should be false")
	}
	if s.HasBlob(11, 0) {
		t.Error("HasBlob(11, 0) should be false")
	}

	cell, commitment, err := s.GetCell(10, 0, 0, 0)
	if err != nil {
		t.Fatalf("GetCell failed: %v", err)
	}
	if cell == nil {
		t.Fatal("cell is nil")
	}
	expectedCell := matrix[0][0]
	if *cell != expectedCell {
		t.Errorf("cell mismatch: got %v, want %v", *cell, expectedCell)
	}
	if commitment == nil {
		t.Fatal("commitment is nil")
	}
	if *commitment != commitments[0] {
		t.Errorf("commitment mismatch: got %v, want %v", *commitment, commitments[0])
	}

	// GetCell on non-existent blob should error
	_, _, err = s.GetCell(99, 0, 0, 0)
	if err == nil {
		t.Error("GetCell on non-existent blob should fail")
	}

	// GetCommitments
	got := s.GetCommitments(10)
	if len(got) != len(commitments) {
		t.Errorf("GetCommitments: got %d, want %d", len(got), len(commitments))
	}
	if got[0] != commitments[0] {
		t.Errorf("GetCommitments[0] mismatch")
	}

	// GetCommitments for missing slot
	if got := s.GetCommitments(99); got != nil {
		t.Errorf("GetCommitments(99) should be nil, got %v", got)
	}

	// GetBlobCount
	if count := s.GetBlobCount(10); count != 1 {
		t.Errorf("GetBlobCount(10) = %d, want 1", count)
	}

	// Stats
	count, size := s.Stats()
	if count != 1 {
		t.Errorf("Stats count = %d, want 1", count)
	}
	if size <= 0 {
		t.Errorf("Stats size = %d, should be > 0", size)
	}
}

func TestPersistentBlobStorage_WithStore(t *testing.T) {
	store := newMockBlobKVStore()
	s := NewPersistentBlobStorage(store)

	matrix := makeTestMatrix(0xEF)
	commitments := []KZGCommitment{{0xCC}, {0xDD}}

	if err := s.StoreMatrix(20, 0, matrix, commitments); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}

	// Verify persisted to KV store
	ok, err := store.Has(s.dbKey(20, 0))
	if err != nil || !ok {
		t.Error("blob should be persisted to KV store")
	}

	// GetCell from cache (should work without touching store)
	cell, _, err := s.GetCell(20, 0, 0, 0)
	if err != nil {
		t.Fatalf("GetCell failed: %v", err)
	}
	if *cell != matrix[0][0] {
		t.Error("cell mismatch from cache")
	}

	// Force cache eviction by storing more blobs with a tiny maxSize
	s2 := NewPersistentBlobStorage(store)
	// Manually clear cache to simulate restart
	s2.mu.Lock()
	s2.cache = make(map[string]*BlobStorageEntry)
	s2.cacheOrder = nil
	s2.currentSize = 0
	s2.mu.Unlock()

	// GetCell should now go to KV store and promote back to cache
	cell2, commitment2, err := s2.GetCell(20, 0, 0, 0)
	if err != nil {
		t.Fatalf("GetCell after cache clear failed: %v", err)
	}
	if *cell2 != matrix[0][0] {
		t.Error("cell mismatch from store")
	}
	if commitment2 == nil || *commitment2 != commitments[0] {
		t.Error("commitment mismatch from store")
	}

	// After GetCell, entry should be promoted back to cache
	s2.mu.RLock()
	_, inCache := s2.cache[s2.key(20, 0)]
	s2.mu.RUnlock()
	if !inCache {
		t.Error("entry should be promoted back to cache after cache miss")
	}
}

func TestPersistentBlobStorage_HasBlob(t *testing.T) {
	store := newMockBlobKVStore()
	s := NewPersistentBlobStorage(store)

	matrix := makeTestMatrix(0x42)
	if err := s.StoreMatrix(30, 1, matrix, nil); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}

	// In cache
	if !s.HasBlob(30, 1) {
		t.Error("HasBlob should return true for cached blob")
	}

	// Clear cache to test KV store path
	s.mu.Lock()
	s.cache = make(map[string]*BlobStorageEntry)
	s.cacheOrder = nil
	s.currentSize = 0
	s.mu.Unlock()

	// In KV store
	if !s.HasBlob(30, 1) {
		t.Error("HasBlob should return true for store-backed blob")
	}
	if s.HasBlob(30, 99) {
		t.Error("HasBlob should return false for missing blob")
	}
}

func TestPersistentBlobStorage_GC(t *testing.T) {
	store := newMockBlobKVStore()
	retention := DefaultDASRetentionConfig()
	retention.BlobRetentionSlots = 5
	s := NewPersistentBlobStorageWithRetention(store, retention)

	// Store blobs in slots 10, 11, 12, 20
	matrix := makeTestMatrix(0x77)
	for _, slot := range []uint64{10, 11, 12, 20} {
		if err := s.StoreMatrix(slot, 0, matrix, nil); err != nil {
			t.Fatalf("StoreMatrix(%d) failed: %v", slot, err)
		}
	}

	// Verify all 4 in cache and store
	if count, _ := s.Stats(); count != 4 {
		t.Errorf("cache count = %d, want 4", count)
	}
	if ok, _ := store.Has(s.dbKey(10, 0)); !ok {
		t.Error("slot 10 should be in store")
	}

	// GC at currentSlot=20: slots 10-12 are older than 20-5=15, so they get evicted.
	// Slot 20 itself: 20+5=25, 25 < 20 is false, so it stays.
	s.GC(20)

	// Slots 10, 11, 12 should be evicted from cache
	if count, _ := s.Stats(); count != 1 {
		t.Errorf("after GC, cache count = %d, want 1 (only slot 20)", count)
	}
	if s.HasBlob(10, 0) {
		// HasBlob checks both cache and store; the store entry was deleted by GC
		t.Error("slot 10 should be evicted from cache and store by GC")
	}
	if ok, _ := store.Has(s.dbKey(10, 0)); ok {
		t.Error("slot 10 should be deleted from KV store by GC")
	}
	if ok, _ := store.Has(s.dbKey(11, 0)); ok {
		t.Error("slot 11 should be deleted from KV store by GC")
	}
	if ok, _ := store.Has(s.dbKey(12, 0)); ok {
		t.Error("slot 12 should be deleted from KV store by GC")
	}
	// Slot 20 should survive
	if !s.HasBlob(20, 0) {
		t.Error("slot 20 should survive GC")
	}
	if ok, _ := store.Has(s.dbKey(20, 0)); !ok {
		t.Error("slot 20 should still be in KV store after GC")
	}
}

func TestPersistentBlobStorage_GetCommitmentsFromStore(t *testing.T) {
	store := newMockBlobKVStore()
	s := NewPersistentBlobStorage(store)

	matrix := makeTestMatrix(0x55)
	commitments := []KZGCommitment{{0x11}, {0x22}, {0x33}}
	if err := s.StoreMatrix(40, 0, matrix, commitments); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}

	// Clear cache to force KV store lookup
	s.mu.Lock()
	s.cache = make(map[string]*BlobStorageEntry)
	s.cacheOrder = nil
	s.currentSize = 0
	s.mu.Unlock()

	got := s.GetCommitments(40)
	if got == nil {
		t.Fatal("GetCommitments returned nil for store-backed slot")
	}
	if len(got) != len(commitments) {
		t.Fatalf("GetCommitments length: got %d, want %d", len(got), len(commitments))
	}
	for i, c := range commitments {
		if got[i] != c {
			t.Errorf("GetCommitments[%d] mismatch", i)
		}
	}

	// Missing slot
	if got := s.GetCommitments(99); got != nil {
		t.Errorf("GetCommitments(99) should be nil, got %v", got)
	}
}

func TestPersistentBlobStorage_Eviction(t *testing.T) {
	// Test LRU eviction when cache exceeds maxSize
	store := newMockBlobKVStore()
	s := NewPersistentBlobStorage(store)
	// Force a small maxSize so eviction triggers.
	// P1-13: sparse storage uses ~1.5MB per entry (6 cols × 8192 × 32),
	// so set maxSize to fit 2 entries (~3MB) but not 3 (~4.5MB).
	s.mu.Lock()
	s.maxSize = 3_200_000 // ~3.2MB: 2 entries fit, 3rd triggers eviction
	s.mu.Unlock()

	matrix := makeTestMatrix(0x88)
	if err := s.StoreMatrix(1, 0, matrix, nil); err != nil {
		t.Fatalf("StoreMatrix(1, 0) failed: %v", err)
	}
	if err := s.StoreMatrix(2, 0, matrix, nil); err != nil {
		t.Fatalf("StoreMatrix(2, 0) failed: %v", err)
	}
	// Third entry should trigger eviction of slot 1
	if err := s.StoreMatrix(3, 0, matrix, nil); err != nil {
		t.Fatalf("StoreMatrix(3, 0) failed: %v", err)
	}

	// Slot 1 should be evicted from cache (but still in KV store)
	s.mu.RLock()
	_, inCache := s.cache[s.key(1, 0)]
	s.mu.RUnlock()
	if inCache {
		t.Error("slot 1 should have been evicted from cache")
	}
	// Slots 2 and 3 should still be in cache
	s.mu.RLock()
	_, inCache2 := s.cache[s.key(2, 0)]
	_, inCache3 := s.cache[s.key(3, 0)]
	s.mu.RUnlock()
	if !inCache2 {
		t.Error("slot 2 should still be in cache")
	}
	if !inCache3 {
		t.Error("slot 3 should still be in cache")
	}
	// All should be in KV store
	if ok, _ := store.Has(s.dbKey(1, 0)); !ok {
		t.Error("slot 1 should still be in KV store after eviction")
	}
}

func TestPersistentBlobStorage_IdempotentStore(t *testing.T) {
	// Storing the same (slot, blobIndex) twice should be a no-op
	store := newMockBlobKVStore()
	s := NewPersistentBlobStorage(store)

	matrix1 := makeTestMatrix(0x99)
	if err := s.StoreMatrix(50, 0, matrix1, nil); err != nil {
		t.Fatalf("StoreMatrix(50, 0) first call failed: %v", err)
	}
	matrix2 := makeTestMatrix(0xAA) // different matrix
	if err := s.StoreMatrix(50, 0, matrix2, nil); err != nil {
		t.Fatalf("StoreMatrix(50, 0) second call failed: %v", err)
	}

	// The first stored matrix should be returned (idempotent — second store is a no-op)
	cell, _, err := s.GetCell(50, 0, 0, 0)
	if err != nil {
		t.Fatalf("GetCell failed: %v", err)
	}
	if *cell != matrix1[0][0] {
		t.Error("second StoreMatrix should not overwrite the first")
	}
}

func TestPersistentBlobStorage_OutOfRange(t *testing.T) {
	s := NewPersistentBlobStorage(nil)
	matrix := makeTestMatrix(0xBB)
	if err := s.StoreMatrix(60, 0, matrix, nil); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}

	// Column out of range
	_, _, err := s.GetCell(60, 0, 0, MaxBlobColumnsExt)
	if err == nil {
		t.Error("GetCell with col=MaxBlobColumnsExt should fail")
	}
	_, _, err = s.GetCell(60, 0, 0, -1)
	if err == nil {
		t.Error("GetCell with col=-1 should fail")
	}
	// Row out of range
	_, _, err = s.GetCell(60, 0, CellsPerBlobExtended, 0)
	if err == nil {
		t.Error("GetCell with row=CellsPerBlobExtended should fail")
	}
	_, _, err = s.GetCell(60, 0, -1, 0)
	if err == nil {
		t.Error("GetCell with row=-1 should fail")
	}
}

func TestPersistentBlobStorage_SetRetentionConfig(t *testing.T) {
	s := NewPersistentBlobStorage(nil)
	// DA-R5-05 (2026-07-16): Use a fully valid config that satisfies the
	// Blob >= Session >= Attest > Decay invariants. Setting only
	// BlobRetentionSlots=256 while leaving Session=1024 (the new default)
	// would now be rejected by Validate() — see TestDA_R5_05_SetRetention_RejectsInvalid.
	newCfg := DASRetentionConfig{
		BlobRetentionSlots:    4096,
		SessionRetentionSlots: 2048,
		AttestRetentionSlots:  1024,
		ConfidenceDecaySlots:  256,
		MinConfidenceDecay:    0.5,
		GCTickerInterval:      60 * time.Second,
	}
	s.SetRetentionConfig(newCfg)

	s.mu.RLock()
	got := s.retention.BlobRetentionSlots
	s.mu.RUnlock()
	if got != 4096 {
		t.Errorf("retention.BlobRetentionSlots = %d, want 4096", got)
	}
}

func TestPersistentBlobStorage_Concurrent(t *testing.T) {
	// Run concurrent StoreMatrix + GetCell + HasBlob to check for races
	store := newMockBlobKVStore()
	s := NewPersistentBlobStorage(store)

	const goroutines = 8
	const opsPerG = 4 // 32 total entries (each ~3MB = ~96MB total, under 256MB cap)

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Writers
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < opsPerG; i++ {
				slot := uint64(gid*opsPerG + i)
				matrix := makeTestMatrix(byte(slot))
				_ = s.StoreMatrix(slot, 0, matrix, nil)
			}
		}(g)
	}
	// Readers
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < opsPerG; i++ {
				slot := uint64(gid*opsPerG + i)
				_, _, _ = s.GetCell(slot, 0, 0, 0)
				_ = s.HasBlob(slot, 0)
				_ = s.GetCommitments(slot)
			}
		}(g)
	}
	wg.Wait()

	// All entries should be present (either in cache or store)
	total := goroutines * opsPerG
	for i := 0; i < total; i++ {
		if !s.HasBlob(uint64(i), 0) {
			t.Errorf("blob (slot=%d, index=0) missing after concurrent ops", i)
		}
	}
}

// TestPersistentBlobStorage_DoD verifies the P0-9 DoD:
// "after a node restart, BlobStorage.HasBlob(slot, index) still returns true for historical slots"
// We simulate a restart by creating a new PersistentBlobStorage backed by
// the same KV store.
func TestPersistentBlobStorage_DoD_SurvivesRestart(t *testing.T) {
	store := newMockBlobKVStore()

	// First "instance" — store some blobs
	s1 := NewPersistentBlobStorage(store)
	matrix := makeTestMatrix(0xFE)
	commitments := []KZGCommitment{{0xCA}, {0xFE}}
	if err := s1.StoreMatrix(100, 0, matrix, commitments); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}
	if err := s1.StoreMatrix(101, 0, matrix, commitments); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}

	// Simulate restart — discard s1, create s2 with same store
	s2 := NewPersistentBlobStorage(store)

	// HasBlob must return true for historical slots
	if !s2.HasBlob(100, 0) {
		t.Error("DoD violation: HasBlob(100, 0) returned false after restart")
	}
	if !s2.HasBlob(101, 0) {
		t.Error("DoD violation: HasBlob(101, 0) returned false after restart")
	}

	// GetCell must also work (via cache promotion from KV store)
	cell, commitment, err := s2.GetCell(100, 0, 0, 0)
	if err != nil {
		t.Fatalf("DoD violation: GetCell(100, 0, 0, 0) failed after restart: %v", err)
	}
	if *cell != matrix[0][0] {
		t.Error("cell value mismatch after restart")
	}
	if commitment == nil || *commitment != commitments[0] {
		t.Error("commitment mismatch after restart")
	}

	// GetCommitments must also work
	got := s2.GetCommitments(101)
	if got == nil || len(got) != len(commitments) {
		t.Errorf("GetCommitments(101) after restart: got %v, want %v", got, commitments)
	}
}

// suppress unused import errors for fmt/errors if not used
var _ = errors.New
var _ = fmt.Sprintf
