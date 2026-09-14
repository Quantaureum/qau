// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/db"
)

// TestBlobKVStore_BoltDB verifies the bbolt-backed adapter works correctly
// with a real BoltDB instance. This is the production code path — the mock
// store tests in encoding/ only verify the interface contract.
// P0-9 (2026-07-14)
func TestBlobKVStore_BoltDB(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "blobkv-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	bolt, err := db.NewBoltDB(tmpDir)
	if err != nil {
		t.Fatalf("NewBoltDB failed: %v", err)
	}
	defer bolt.Close()

	store := NewBlobKVStore(bolt)
	if store == nil {
		t.Fatal("NewBlobKVStore returned nil for non-nil database")
	}

	// Put + Get
	key := []byte("da:blob:42:0")
	val := []byte("test-blob-data")
	if err := store.Put(key, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !bytes.Equal(got, val) {
		t.Errorf("Get returned %v, want %v", got, val)
	}

	// Has
	ok, err := store.Has(key)
	if err != nil || !ok {
		t.Errorf("Has returned (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = store.Has([]byte("nonexistent"))
	if err != nil || ok {
		t.Errorf("Has(nonexistent) returned (%v, %v), want (false, nil)", ok, err)
	}

	// Get on missing key should return ErrBlobNotFound
	_, err = store.Get([]byte("nonexistent"))
	if err == nil {
		t.Error("Get on missing key should return error")
	}
	if err != encoding.ErrBlobNotFound {
		t.Errorf("Get on missing key returned %v, want ErrBlobNotFound", err)
	}

	// Iterator
	prefix := []byte("da:blob:")
	for i := 1; i <= 3; i++ {
		k := []byte("da:blob:42:" + string(rune('0'+i)))
		if err := store.Put(k, []byte("val-"+string(rune('0'+i)))); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	iter := store.NewIterator(prefix, nil)
	defer iter.Release()
	var keys [][]byte
	for iter.Next() {
		k := make([]byte, len(iter.Key()))
		copy(k, iter.Key())
		keys = append(keys, k)
	}
	if err := iter.Error(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}
	if len(keys) != 4 { // original + 3 new
		t.Errorf("iterator returned %d keys, want 4", len(keys))
	}
	for _, k := range keys {
		if !bytes.HasPrefix(k, prefix) {
			t.Errorf("key %v does not have prefix %v", k, prefix)
		}
	}

	// Delete
	if err := store.Delete(key); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	ok, _ = store.Has(key)
	if ok {
		t.Error("Has should return false after Delete")
	}
}

// TestBlobKVStore_NilDB verifies nil-safety: NewBlobKVStore(nil) returns nil,
// which causes PersistentBlobStorage to operate in memory-only mode.
func TestBlobKVStore_NilDB(t *testing.T) {
	store := NewBlobKVStore(nil)
	if store != nil {
		t.Error("NewBlobKVStore(nil) should return nil")
	}
}

// TestBlobKVStore_PersistentBlobStorageIntegration verifies the full stack:
// PersistentBlobStorage + bbolt adapter + real BoltDB. This simulates the
// production code path and verifies the DoD:
// "After a node restart, BlobStorage.HasBlob(slot, index) must still return true for historical slots"
func TestBlobKVStore_PersistentBlobStorageIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "blob-persistent-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Instance 1: store a blob
	bolt1, err := db.NewBoltDB(tmpDir)
	if err != nil {
		t.Fatalf("NewBoltDB failed: %v", err)
	}
	store1 := NewBlobKVStore(bolt1)
	storage1 := encoding.NewPersistentBlobStorage(store1)

	matrix := makeTestMatrix(0xFE)
	commitments := []encoding.KZGCommitment{{0xCA}, {0xFE}}
	if err := storage1.StoreMatrix(100, 0, matrix, commitments); err != nil {
		t.Fatalf("StoreMatrix failed: %v", err)
	}
	// Close the database to simulate node shutdown
	bolt1.Close()

	// Instance 2: open the same database file, verify blob survives
	bolt2, err := db.NewBoltDB(tmpDir)
	if err != nil {
		t.Fatalf("NewBoltDB (reopen) failed: %v", err)
	}
	defer bolt2.Close()
	store2 := NewBlobKVStore(bolt2)
	storage2 := encoding.NewPersistentBlobStorage(store2)

	// DoD: HasBlob must return true for historical slot after restart
	if !storage2.HasBlob(100, 0) {
		t.Error("DoD violation: HasBlob(100, 0) returned false after reopen")
	}

	// GetCell must also work (via cache promotion from KV store)
	cell, commitment, err := storage2.GetCell(100, 0, 0, 0)
	if err != nil {
		t.Fatalf("GetCell after reopen failed: %v", err)
	}
	if *cell != matrix[0][0] {
		t.Error("cell value mismatch after reopen")
	}
	if commitment == nil || *commitment != commitments[0] {
		t.Error("commitment mismatch after reopen")
	}

	// GetCommitments must also work
	got := storage2.GetCommitments(100)
	if got == nil || len(got) != len(commitments) {
		t.Errorf("GetCommitments after reopen: got %v, want %v", got, commitments)
	}
}

// makeTestMatrix mirrors the helper in encoding tests.
func makeTestMatrix(seed byte) encoding.BlobMatrixExtended {
	var m encoding.BlobMatrixExtended
	for col := 0; col < encoding.MaxBlobColumnsExt; col++ {
		for row := 0; row < encoding.CellsPerBlobExtended; row++ {
			for k := 0; k < encoding.CellSize; k++ {
				m[col][row][k] = seed ^ byte(col) ^ byte(row) ^ byte(k)
			}
		}
	}
	return m
}

// suppress unused import
var _ = filepath.Join
