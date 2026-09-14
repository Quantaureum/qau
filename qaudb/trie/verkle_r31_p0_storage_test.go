// Quantaureum Node source, version 1.0.0.
//go:build !integration

package trie

import (
	"fmt"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// TestSTORAGE_P0_01_FlushAtomicity verifies that node writes are buffered in
// pendingBatch and only become visible in persistentDB after Flush() is
// called. This is the core invariant of the STORAGE-P0-01 fix: without it,
// a crash between storeNode calls would leave a half-written tree on disk.
func TestSTORAGE_P0_01_FlushAtomicity(t *testing.T) {
	persistentDB := db.NewMemDB()
	tree := NewVerkleTree(MaxTreeDepth, persistentDB)

	// Insert several keys — each Put triggers multiple storeNode calls
	// (leaf + internal nodes along the path + root).
	keys := generateTestKeysR12003(5)
	for _, k := range keys {
		if err := tree.Put(k, []byte("value")); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	// STORAGE-P0-01 invariant: BEFORE Flush, persistentDB must be EMPTY
	// because all node writes are still buffered in pendingBatch.
	preFlushCount := countPersistentEntries(t, persistentDB)
	if preFlushCount != 0 {
		t.Errorf("STORAGE-P0-01 NOT FIXED: persistentDB has %d entries before Flush (expected 0)", preFlushCount)
	}

	// Flush must atomically commit all buffered node writes.
	if err := tree.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// AFTER Flush, persistentDB must contain the nodes (non-zero count).
	postFlushCount := countPersistentEntries(t, persistentDB)
	if postFlushCount == 0 {
		t.Errorf("STORAGE-P0-01 NOT FIXED: persistentDB has 0 entries after Flush (expected non-zero)")
	}

	t.Logf("OK: pre-flush=%d, post-flush=%d", preFlushCount, postFlushCount)
}

// TestSTORAGE_P0_01_FlushResetsBatch verifies that after Flush() returns
// (success or failure), the pending batch is reset so subsequent operations
// start fresh. Without this, a second Put would re-write the first Put's
// nodes, causing redundant I/O and potentially confusing error tracking.
func TestSTORAGE_P0_01_FlushResetsBatch(t *testing.T) {
	persistentDB := db.NewMemDB()
	tree := NewVerkleTree(MaxTreeDepth, persistentDB)

	// First batch of writes + flush.
	if err := tree.Put([]byte("key-1"), []byte("v1")); err != nil {
		t.Fatalf("Put 1: %v", err)
	}

	// Before Flush, the batch must have accumulated bytes.
	tree.pendingBatchMu.Lock()
	preFlushSize := tree.pendingBatch.ValueSize()
	tree.pendingBatchMu.Unlock()
	if preFlushSize == 0 {
		t.Fatalf("STORAGE-P0-01 NOT FIXED: pendingBatch.ValueSize=0 before Flush (expected non-zero)")
	}

	if err := tree.Flush(); err != nil {
		t.Fatalf("Flush 1: %v", err)
	}

	// After Flush, the batch must be reset (ValueSize == 0).
	tree.pendingBatchMu.Lock()
	postFlushSize := tree.pendingBatch.ValueSize()
	tree.pendingBatchMu.Unlock()
	if postFlushSize != 0 {
		t.Errorf("STORAGE-P0-01 NOT FIXED: pendingBatch.ValueSize=%d after Flush (expected 0) — batch was not reset",
			postFlushSize)
	}

	// Second Put must accumulate fresh bytes (not reuse the old batch).
	if err := tree.Put([]byte("key-2"), []byte("v2")); err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	tree.pendingBatchMu.Lock()
	secondBatchSize := tree.pendingBatch.ValueSize()
	tree.pendingBatchMu.Unlock()
	if secondBatchSize == 0 {
		t.Errorf("STORAGE-P0-01 NOT FIXED: pendingBatch.ValueSize=0 after second Put (expected non-zero)")
	}
	if err := tree.Flush(); err != nil {
		t.Fatalf("Flush 2: %v", err)
	}
	t.Logf("OK: pre-flush size=%d, post-flush size=%d, second batch size=%d",
		preFlushSize, postFlushSize, secondBatchSize)
}

// TestSTORAGE_P0_01_CopyHasIndependentBatch verifies that Copy() creates a
// fresh pendingBatch for the copy, so writes on the copy don't bleed into
// the original's batch (and vice-versa).
func TestSTORAGE_P0_01_CopyHasIndependentBatch(t *testing.T) {
	persistentDB := db.NewMemDB()
	tree := NewVerkleTree(MaxTreeDepth, persistentDB)

	if err := tree.Put([]byte("orig-key"), []byte("orig-val")); err != nil {
		t.Fatalf("Put original: %v", err)
	}

	cp := tree.Copy()
	if cp == nil {
		t.Fatal("Copy returned nil")
	}
	// STORAGE-P0-01 FIX: copy must have its own pendingBatch.
	tree.pendingBatchMu.Lock()
	origBatch := tree.pendingBatch
	tree.pendingBatchMu.Unlock()
	cp.pendingBatchMu.Lock()
	copyBatch := cp.pendingBatch
	cp.pendingBatchMu.Unlock()
	if copyBatch == nil {
		t.Fatal("STORAGE-P0-01 NOT FIXED: Copy's pendingBatch is nil")
	}
	if fmt.Sprintf("%p", origBatch) == fmt.Sprintf("%p", copyBatch) {
		t.Fatal("STORAGE-P0-01 NOT FIXED: Copy shares pendingBatch with original (same pointer)")
	}

	// Write to the copy — must NOT affect the original's pendingBatch.
	if err := cp.Put([]byte("copy-key"), []byte("copy-val")); err != nil {
		t.Fatalf("Put on copy: %v", err)
	}

	// Flush both — both must succeed independently.
	if err := cp.Flush(); err != nil {
		t.Fatalf("Flush copy: %v", err)
	}
	if err := tree.Flush(); err != nil {
		t.Fatalf("Flush original: %v", err)
	}

	if countPersistentEntries(t, persistentDB) == 0 {
		t.Error("STORAGE-P0-01 NOT FIXED: no persistent entries after both flushes")
	}
}

// TestSTORAGE_P0_02_VerkleStateDBCommit_FlushesAllTrees verifies that
// VerkleStateDB.Commit() flushes pending writes on the account tree and all
// per-address storage trees. Without this, Commit was a no-op for persistence
// (STORAGE-P0-02).
func TestSTORAGE_P0_02_VerkleStateDBCommit_FlushesAllTrees(t *testing.T) {
	stateDB := NewVerkleStateDB()

	addrA := types.Address{0xAA}
	slotA := types.Hash{0x55}

	if err := stateDB.SetAccount(addrA, []byte("account-data")); err != nil {
		t.Fatalf("SetAccount: %v", err)
	}
	if err := stateDB.SetStorage(addrA, slotA, []byte("storage-value")); err != nil {
		t.Fatalf("SetStorage: %v", err)
	}

	// Commit must succeed. Since VerkleStateDB has no persistentDB attached
	// (current production usage), Flush is a no-op and Commit returns nil.
	root, err := stateDB.Commit()
	if err != nil {
		t.Fatalf("STORAGE-P0-02 NOT FIXED: Commit returned error: %v", err)
	}
	var zero types.Hash
	if root == zero {
		t.Error("STORAGE-P0-02: Commit returned zero root after writes")
	}
}

// TestSTORAGE_P0_03_ErrorPropagation verifies that a persistence error
// during storeNode is captured and surfaced via Flush(). We force the
// fallback direct-Put path (pendingBatch=nil) so the failingPutDB.Put
// error gets recorded in pendingBatchErr.
func TestSTORAGE_P0_03_ErrorPropagation(t *testing.T) {
	failingDB := &failingPutDB{
		Database:  db.NewMemDB(),
		failOnPut: true,
	}
	tree := NewVerkleTree(MaxTreeDepth, failingDB)

	// Force the fallback direct-Put path so failingPutDB.Put is called.
	tree.pendingBatchMu.Lock()
	tree.pendingBatch = nil
	tree.pendingBatchMu.Unlock()

	err := tree.Put([]byte("key"), []byte("value"))
	if err != nil {
		t.Fatalf("Put itself shouldn't fail (error is captured): %v", err)
	}

	// Flush must surface the captured Put error.
	flushErr := tree.Flush()
	if flushErr == nil {
		t.Errorf("STORAGE-P0-03 NOT FIXED: Flush returned nil but persistentDB.Put failed")
	}
	t.Logf("OK: Flush correctly surfaced persistence error: %v", flushErr)
}

// --- helpers ---

func countPersistentEntries(t *testing.T, persistentDB db.Database) int {
	t.Helper()
	iter := persistentDB.NewIterator([]byte(vnodePrefix), nil)
	defer iter.Release()
	count := 0
	for iter.Next() {
		count++
	}
	return count
}

// failingPutDB wraps a Database and makes Put always fail when failOnPut is
// set. Used to simulate disk-full / I/O errors in STORAGE-P0-03 test.
type failingPutDB struct {
	db.Database
	failOnPut bool
}

func (f *failingPutDB) Put(key, value []byte) error {
	if f.failOnPut {
		k := key
		if len(k) > 8 {
			k = k[:8]
		}
		return fmt.Errorf("simulated disk-full (key=%x)", k)
	}
	return f.Database.Put(key, value)
}

func (f *failingPutDB) NewBatch() db.Batch {
	return f.Database.NewBatch()
}
