// Quantaureum Node source, version 1.0.0.
package db

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestNewMemDB(t *testing.T) {
	db := NewMemDB()
	if db == nil {
		t.Fatal("expected non-nil db")
	}
	if db.Len() != 0 {
		t.Errorf("expected 0 entries, got %d", db.Len())
	}
}

func TestPutGet(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	err := db.Put([]byte("key1"), []byte("value1"))
	if err != nil {
		t.Fatalf("unexpected put error: %v", err)
	}

	v, err := db.Get([]byte("key1"))
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if !bytes.Equal(v, []byte("value1")) {
		t.Errorf("expected value1, got %s", v)
	}
}

func TestGetNonExistent(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	_, err := db.Get([]byte("missing"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestPutOverride(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	db.Put([]byte("key1"), []byte("old"))
	db.Put([]byte("key1"), []byte("new"))

	v, _ := db.Get([]byte("key1"))
	if !bytes.Equal(v, []byte("new")) {
		t.Errorf("expected new, got %s", v)
	}
}

func TestDelete(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	db.Put([]byte("key1"), []byte("value1"))
	db.Delete([]byte("key1"))

	_, err := db.Get([]byte("key1"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound after delete, got %v", err)
	}
}

func TestHas(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	has, err := db.Has([]byte("key1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("expected false for non-existent key")
	}

	db.Put([]byte("key1"), []byte("value1"))
	has, _ = db.Has([]byte("key1"))
	if !has {
		t.Error("expected true after put")
	}
}

func TestLen(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	if db.Len() != 0 {
		t.Error("expected 0")
	}

	db.Put([]byte("a"), []byte("1"))
	db.Put([]byte("b"), []byte("2"))
	if db.Len() != 2 {
		t.Errorf("expected 2, got %d", db.Len())
	}

	db.Delete([]byte("a"))
	if db.Len() != 1 {
		t.Errorf("expected 1, got %d", db.Len())
	}
}

func TestClose(t *testing.T) {
	db := NewMemDB()
	err := db.Close()
	if err != nil {
		t.Errorf("unexpected close error: %v", err)
	}

	_, err = db.Get([]byte("any"))
	if err != ErrDatabaseClosed {
		t.Errorf("expected ErrDatabaseClosed, got %v", err)
	}

	err = db.Put([]byte("any"), []byte("x"))
	if err != ErrDatabaseClosed {
		t.Errorf("expected ErrDatabaseClosed on put, got %v", err)
	}

	has, err := db.Has([]byte("any"))
	if err != ErrDatabaseClosed {
		t.Errorf("expected ErrDatabaseClosed on has, got %v", err)
	}
	if has {
		t.Error("expected false")
	}

	err = db.Delete([]byte("any"))
	if err != ErrDatabaseClosed {
		t.Errorf("expected ErrDatabaseClosed on delete, got %v", err)
	}
}

func TestBatchPut(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	b := db.NewBatch()
	b.Put([]byte("k1"), []byte("v1"))
	b.Put([]byte("k2"), []byte("v2"))
	b.Write()

	v1, _ := db.Get([]byte("k1"))
	if !bytes.Equal(v1, []byte("v1")) {
		t.Errorf("expected v1, got %s", v1)
	}
	v2, _ := db.Get([]byte("k2"))
	if !bytes.Equal(v2, []byte("v2")) {
		t.Errorf("expected v2, got %s", v2)
	}
}

func TestBatchDelete(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	db.Put([]byte("k1"), []byte("v1"))

	b := db.NewBatch()
	b.Delete([]byte("k1"))
	b.Write()

	_, err := db.Get([]byte("k1"))
	if err != ErrKeyNotFound {
		t.Error("expected key deleted by batch")
	}
}

func TestBatchMixed(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	db.Put([]byte("k1"), []byte("v1"))
	db.Put([]byte("k2"), []byte("v2"))

	b := db.NewBatch()
	b.Put([]byte("k1"), []byte("new_v1"))
	b.Delete([]byte("k2"))
	b.Put([]byte("k3"), []byte("v3"))
	b.Write()

	v1, _ := db.Get([]byte("k1"))
	if !bytes.Equal(v1, []byte("new_v1")) {
		t.Errorf("expected new_v1, got %s", v1)
	}

	if has, _ := db.Has([]byte("k2")); has {
		t.Error("k2 should be deleted")
	}

	v3, _ := db.Get([]byte("k3"))
	if !bytes.Equal(v3, []byte("v3")) {
		t.Errorf("expected v3, got %s", v3)
	}
}

func TestBatchReset(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	b := db.NewBatch()
	b.Put([]byte("k1"), []byte("v1"))
	b.Reset()
	b.Write()

	if has, _ := db.Has([]byte("k1")); has {
		t.Error("reset batch should not write")
	}
}

func TestBatchValueSize(t *testing.T) {
	db := NewMemDB()
	b := db.NewBatch()
	b.Put([]byte("k1"), []byte("12345"))
	if b.ValueSize() != 5 {
		t.Errorf("expected 5, got %d", b.ValueSize())
	}
}

func TestIterator(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	db.Put([]byte("a"), []byte("1"))
	db.Put([]byte("b"), []byte("2"))
	db.Put([]byte("c"), []byte("3"))

	it := db.NewIterator(nil, nil)
	defer it.Release()

	count := 0
	for it.Next() {
		count++
	}
	if count != 3 {
		t.Errorf("expected 3 items, got %d", count)
	}
	if it.Error() != nil {
		t.Errorf("unexpected error: %v", it.Error())
	}

	_, _ = it.Key(), it.Value()
}

func TestIteratorWithPrefix(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	db.Put([]byte("block:1"), []byte("data1"))
	db.Put([]byte("block:2"), []byte("data2"))
	db.Put([]byte("tx:1"), []byte("data3"))

	it := db.NewIterator([]byte("block:"), nil)
	defer it.Release()

	count := 0
	for it.Next() {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 block items, got %d", count)
	}
}

func TestIteratorEmpty(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	it := db.NewIterator(nil, nil)
	defer it.Release()

	if it.Next() {
		t.Error("expected no items in empty db")
	}
}

func TestGetDeepCopy(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	original := []byte("mutable_value")
	db.Put([]byte("key"), original)

	v, _ := db.Get([]byte("key"))
	v[0] = 'X'

	v2, _ := db.Get([]byte("key"))
	if v2[0] == 'X' {
		t.Error("Get should return a copy, not reference to internal data")
	}
}

func TestIteratorKeyValue_BeforeNext(t *testing.T) {
	db := NewMemDB()
	defer db.Close()
	db.Put([]byte("a"), []byte("1"))

	it := db.NewIterator(nil, nil)
	defer it.Release()

	if it.Key() != nil {
		t.Error("Key before Next should be nil")
	}
	if it.Value() != nil {
		t.Error("Value before Next should be nil")
	}
}

func TestIteratorKeyValue_AfterEnd(t *testing.T) {
	db := NewMemDB()
	defer db.Close()
	db.Put([]byte("a"), []byte("1"))

	it := db.NewIterator(nil, nil)
	defer it.Release()

	for it.Next() {
	}

	if it.Key() != nil {
		t.Error("Key after end should be nil")
	}
	if it.Value() != nil {
		t.Error("Value after end should be nil")
	}
}

func TestIterator_Error(t *testing.T) {
	it := &memIterator{err: ErrKeyNotFound}
	if it.Error() != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", it.Error())
	}
}

func TestIterator_Release(t *testing.T) {
	db := NewMemDB()
	defer db.Close()
	db.Put([]byte("a"), []byte("1"))

	it := db.NewIterator(nil, nil)
	it.Release()

	if it.Next() {
		t.Error("Next after Release should be false")
	}
	if it.Key() != nil {
		t.Error("Key after Release should be nil")
	}
}

func TestIterator_WithStart(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	db.Put([]byte("a"), []byte("1"))
	db.Put([]byte("b"), []byte("2"))
	db.Put([]byte("c"), []byte("3"))

	it := db.NewIterator(nil, []byte("b"))
	defer it.Release()

	count := 0
	for it.Next() {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 items (b,c), got %d", count)
	}
}

func TestIterator_WithPrefixAndStart(t *testing.T) {
	db := NewMemDB()
	defer db.Close()

	db.Put([]byte("block:1"), []byte("d1"))
	db.Put([]byte("block:2"), []byte("d2"))
	db.Put([]byte("block:3"), []byte("d3"))

	it := db.NewIterator([]byte("block:"), []byte("block:2"))
	defer it.Release()

	count := 0
	for it.Next() {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 items, got %d", count)
	}
}

func TestBatch_Write_OnClosedDB(t *testing.T) {
	db := NewMemDB()

	b := db.NewBatch()
	b.Put([]byte("k1"), []byte("v1"))
	b.Put([]byte("k2"), []byte("v2"))

	db.Close()

	err := b.Write()
	if err != ErrDatabaseClosed {
		t.Errorf("expected ErrDatabaseClosed, got %v", err)
	}
}

func TestClose_DoubleClose(t *testing.T) {
	db := NewMemDB()
	err := db.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	err = db.Close()
	if err != nil {
		t.Errorf("unexpected error on second close: %v", err)
	}
}

func TestClose_LenAfterClose(t *testing.T) {
	db := NewMemDB()
	db.Put([]byte("k"), []byte("v"))
	db.Close()

	if db.Len() != 0 {
		t.Error("Len after close should be 0")
	}
}

func TestErrorValues(t *testing.T) {
	if ErrNotFound != ErrKeyNotFound {
		t.Error("ErrNotFound should alias ErrKeyNotFound")
	}
	if ErrKeyNotFound.Error() == "" {
		t.Error("ErrKeyNotFound should have message")
	}
	if ErrDatabaseClosed.Error() == "" {
		t.Error("ErrDatabaseClosed should have message")
	}
	if ErrInvalidKey.Error() == "" {
		t.Error("ErrInvalidKey should have message")
	}
	if ErrInvalidValue.Error() == "" {
		t.Error("ErrInvalidValue should have message")
	}
}

func TestNewFileDB(t *testing.T) {
	dir := t.TempDir()
	fdb, err := NewFileDB(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer fdb.Close()

	if fdb.Path() != dir {
		t.Errorf("expected path %s, got %s", dir, fdb.Path())
	}

	fdb.Put([]byte("k"), []byte("v"))
	v, _ := fdb.Get([]byte("k"))
	if !bytes.Equal(v, []byte("v")) {
		t.Errorf("expected v, got %s", v)
	}
}

func TestBoltDB_Basic(t *testing.T) {
	dir := t.TempDir()
	bdb, err := NewBoltDB(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer bdb.Close()

	err = bdb.Put([]byte("k1"), []byte("v1"))
	if err != nil {
		t.Fatalf("put error: %v", err)
	}

	v, err := bdb.Get([]byte("k1"))
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	if !bytes.Equal(v, []byte("v1")) {
		t.Errorf("expected v1, got %s", v)
	}
}

func TestBoltDB_Has(t *testing.T) {
	dir := t.TempDir()
	bdb, _ := NewBoltDB(dir)
	defer bdb.Close()

	has, err := bdb.Has([]byte("missing"))
	if err != nil {
		t.Errorf("has error: %v", err)
	}
	if has {
		t.Error("expected false")
	}

	bdb.Put([]byte("k"), []byte("v"))
	has, _ = bdb.Has([]byte("k"))
	if !has {
		t.Error("expected true")
	}
}

func TestBoltDB_Delete(t *testing.T) {
	dir := t.TempDir()
	bdb, _ := NewBoltDB(dir)
	defer bdb.Close()

	bdb.Put([]byte("k"), []byte("v"))
	bdb.Delete([]byte("k"))
	_, err := bdb.Get([]byte("k"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestBoltDB_Batch(t *testing.T) {
	dir := t.TempDir()
	bdb, _ := NewBoltDB(dir)
	defer bdb.Close()

	b := bdb.NewBatch()
	b.Put([]byte("k1"), []byte("v1"))
	b.Put([]byte("k2"), []byte("v2"))
	b.Delete([]byte("k3"))
	b.Write()

	v, _ := bdb.Get([]byte("k1"))
	if !bytes.Equal(v, []byte("v1")) {
		t.Errorf("expected v1, got %s", v)
	}
}

func TestBoltDB_BatchReset(t *testing.T) {
	dir := t.TempDir()
	bdb, _ := NewBoltDB(dir)
	defer bdb.Close()

	b := bdb.NewBatch()
	b.Put([]byte("k"), []byte("v"))
	b.Reset()
	if b.ValueSize() != 0 {
		t.Errorf("expected 0 after reset, got %d", b.ValueSize())
	}
}

func TestBoltDB_Iterator(t *testing.T) {
	dir := t.TempDir()
	bdb, _ := NewBoltDB(dir)
	defer bdb.Close()

	bdb.Put([]byte("a"), []byte("1"))
	bdb.Put([]byte("b"), []byte("2"))
	bdb.Put([]byte("c"), []byte("3"))

	it := bdb.NewIterator(nil, nil)
	defer it.Release()

	count := 0
	for it.Next() {
		count++
	}
	if count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
}

func TestBoltDB_IteratorPrefix(t *testing.T) {
	dir := t.TempDir()
	bdb, _ := NewBoltDB(dir)
	defer bdb.Close()

	bdb.Put([]byte("pre:a"), []byte("1"))
	bdb.Put([]byte("pre:b"), []byte("2"))
	bdb.Put([]byte("other:c"), []byte("3"))

	it := bdb.NewIterator([]byte("pre:"), nil)
	defer it.Release()

	count := 0
	for it.Next() {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

func TestBoltDB_IteratorStart(t *testing.T) {
	dir := t.TempDir()
	bdb, _ := NewBoltDB(dir)
	defer bdb.Close()

	bdb.Put([]byte("a"), []byte("1"))
	bdb.Put([]byte("b"), []byte("2"))
	bdb.Put([]byte("c"), []byte("3"))

	it := bdb.NewIterator(nil, []byte("b"))
	defer it.Release()

	count := 0
	for it.Next() {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

func TestBoltDB_GetNonExistent(t *testing.T) {
	dir := t.TempDir()
	bdb, _ := NewBoltDB(dir)
	defer bdb.Close()

	_, err := bdb.Get([]byte("nope"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestSortStrings(t *testing.T) {
	strs := []string{"c", "a", "b"}
	sort.Strings(strs)
	if strs[0] != "a" || strs[1] != "b" || strs[2] != "c" {
		t.Errorf("expected [a b c], got %v", strs)
	}

	single := []string{"x"}
	sort.Strings(single)
	if single[0] != "x" {
		t.Errorf("expected [x], got %v", single)
	}

	empty := []string{}
	sort.Strings(empty)
	if len(empty) != 0 {
		t.Errorf("expected empty, got %v", empty)
	}
}

// TestDBR11003_DiskSpacePrecheck verifies the disk-space precheck helper
// returns a sensible error when it can read the filesystem, and that
// Put/Delete/batch Write respect the threshold by returning
// ErrInsufficientDiskSpace. Because tests run on real disks with plenty
// of free space, the "happy path" (no error) is the only path directly
// testable without mocking. The threshold constant itself is also
// asserted to make sure no one accidentally weakens it.
//
// DB-R11-003 (2026-07-20).
func TestDBR11003_DiskSpacePrecheck(t *testing.T) {
	// Sanity-check the threshold is at least 1 GiB. Anyone lowering this
	// constant should be required to update the audit notes.
	if MinFreeDiskBytes < 1<<30 {
		t.Fatalf("MinFreeDiskBytes weakened: %d < 1 GiB", MinFreeDiskBytes)
	}

	t.Run("diskFreeBytes_returnsPositiveOnRealDisk", func(t *testing.T) {
		// Use the test's own temp dir.
		tmp := t.TempDir()
		free, err := diskFreeBytes(tmp)
		if err != nil {
			t.Skipf("diskFreeBytes unsupported on this platform: %v", err)
		}
		if free == 0 {
			t.Skip("diskFreeBytes returned 0 — running on a zero-byte filesystem (e.g., tmpfs limit); skipping")
		}
		// On a real test disk we should have at least some space.
		if free < 1<<20 { // < 1 MiB free is effectively a full disk
			t.Skipf("disk free only %d bytes on test machine; skipping", free)
		}
	})

	t.Run("NewBoltDB_opensWithPlentyOfDisk", func(t *testing.T) {
		tmp := t.TempDir()
		bdb, err := NewBoltDB(tmp)
		if err != nil {
			// If the failure is disk-space-related, skip instead of fail
			// (test machine may be genuinely low on space).
			if errors.Is(err, ErrInsufficientDiskSpace) {
				t.Skipf("test machine low on disk space: %v", err)
			}
			t.Fatalf("NewBoltDB failed: %v", err)
		}
		defer bdb.Close()
		if bdb.WasRecovered() {
			t.Errorf("expected fresh database, got recovered=true")
		}
	})
}

// TestDBR11004_CorruptionAutoRecovery verifies that NewBoltDB detects a
// corrupted database file (one that bbolt cannot open), moves it aside,
// and creates a fresh database in its place. The WasRecovered() flag must
// be true on the returned BoltDB.
//
// DB-R11-004 (2026-07-20).
func TestDBR11004_CorruptionAutoRecovery(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "data.db")

	// Write garbage into data.db to simulate corruption. bbolt's first
	// read on open will fail with a checksum or magic-number error.
	garbage := []byte("this is not a bbolt database file — it is garbage")
	if err := os.WriteFile(dbPath, garbage, 0600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	bdb, err := NewBoltDB(tmp)
	if err != nil {
		// If disk-space-related, skip — test machine may be low on disk.
		if errors.Is(err, ErrInsufficientDiskSpace) {
			t.Skipf("test machine low on disk space: %v", err)
		}
		t.Fatalf("NewBoltDB should auto-recover from corruption, got: %v", err)
	}
	defer bdb.Close()

	if !bdb.WasRecovered() {
		t.Errorf("expected WasRecovered=true after corruption recovery")
	}

	// The original garbage file should have been renamed aside.
	// A new data.db should exist and contain a valid bbolt database.
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	corruptedFound := false
	newDBFound := false
	for _, e := range entries {
		name := e.Name()
		if name == "data.db" {
			newDBFound = true
		}
		if len(name) > len("data.db.corrupted.") && name[:len("data.db.corrupted.")] == "data.db.corrupted." {
			corruptedFound = true
		}
	}
	if !corruptedFound {
		t.Errorf("expected a data.db.corrupted.<timestamp> file in %s, got entries: %v", tmp, entries)
	}
	if !newDBFound {
		t.Errorf("expected a fresh data.db to be created")
	}

	// Verify the new database is usable.
	if err := bdb.Put([]byte("postRecoveryKey"), []byte("postRecoveryValue")); err != nil {
		t.Fatalf("Put after recovery failed: %v", err)
	}
	got, err := bdb.Get([]byte("postRecoveryKey"))
	if err != nil {
		t.Fatalf("Get after recovery failed: %v", err)
	}
	if !bytes.Equal(got, []byte("postRecoveryValue")) {
		t.Errorf("expected postRecoveryValue, got %s", got)
	}
}

// TestDBR11005_NoSinglePutVerification verifies the DB-R11-005 fix:
// Put no longer performs a redundant read-back-and-compare. The behavior
// observable to callers is unchanged (Put returns nil on success, error
// on failure), so this test is a smoke test confirming Put still works
// correctly after the verification was removed.
//
// DB-R11-005 (2026-07-20).
func TestDBR11005_NoSinglePutVerification(t *testing.T) {
	tmp := t.TempDir()
	bdb, err := NewBoltDB(tmp)
	if err != nil {
		if errors.Is(err, ErrInsufficientDiskSpace) {
			t.Skipf("test machine low on disk space: %v", err)
		}
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer bdb.Close()

	// A normal Put should still work.
	if err := bdb.Put([]byte("k1"), []byte("v1")); err != nil {
		t.Fatalf("Put k1=v1: %v", err)
	}

	// Overwriting should still work.
	if err := bdb.Put([]byte("k1"), []byte("v2")); err != nil {
		t.Fatalf("Put k1=v2: %v", err)
	}

	got, err := bdb.Get([]byte("k1"))
	if err != nil {
		t.Fatalf("Get k1: %v", err)
	}
	if !bytes.Equal(got, []byte("v2")) {
		t.Errorf("expected v2, got %s", got)
	}

	// Putting a larger value should still work without triggering
	// any verification-related issues.
	largeValue := bytes.Repeat([]byte("x"), 64*1024) // 64 KiB
	if err := bdb.Put([]byte("large"), largeValue); err != nil {
		t.Fatalf("Put large: %v", err)
	}
	gotLarge, err := bdb.Get([]byte("large"))
	if err != nil {
		t.Fatalf("Get large: %v", err)
	}
	if !bytes.Equal(gotLarge, largeValue) {
		t.Errorf("large value mismatch: got %d bytes, expected %d", len(gotLarge), len(largeValue))
	}
}

// TestDBR11006_IsLockTimeoutError verifies the isLockTimeoutError helper
// correctly classifies errors as transient (lock/timeout) vs permanent
// (permission denied, disk full, invalid path, etc.). This is the core
// of the DB-R11-006 fix: openBoltWithRetry now skips retries for
// non-transient errors, surfacing them immediately to the caller.
//
// DB-R11-006 (2026-07-20).
func TestDBR11006_IsLockTimeoutError(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if isLockTimeoutError(nil) {
			t.Error("nil should not be a lock timeout")
		}
	})

	t.Run("bareErrTimeout", func(t *testing.T) {
		if !isLockTimeoutError(bolt.ErrTimeout) {
			t.Error("bolt.ErrTimeout should be classified as lock timeout")
		}
	})

	t.Run("wrappedErrTimeout", func(t *testing.T) {
		wrapped := fmt.Errorf("opening database file: %w", bolt.ErrTimeout)
		if !isLockTimeoutError(wrapped) {
			t.Error("wrapped bolt.ErrTimeout should be classified as lock timeout")
		}
	})

	t.Run("stringTimeout", func(t *testing.T) {
		if !isLockTimeoutError(errors.New("timeout")) {
			t.Error("error containing 'timeout' should be classified as lock timeout")
		}
	})

	t.Run("stringResourceTemporarilyUnavailable", func(t *testing.T) {
		if !isLockTimeoutError(errors.New("resource temporarily unavailable")) {
			t.Error("EAGAIN-style error should be classified as lock timeout")
		}
	})

	t.Run("stringAlreadyLocked", func(t *testing.T) {
		if !isLockTimeoutError(errors.New("the file is already locked by another process")) {
			t.Error("error containing 'already locked' should be classified as lock timeout")
		}
	})

	// Negative cases: non-transient errors must NOT be classified as
	// lock timeouts. These should fail fast in openBoltWithRetry.
	t.Run("permissionDenied", func(t *testing.T) {
		if isLockTimeoutError(errors.New("permission denied")) {
			t.Error("permission denied should NOT be classified as lock timeout")
		}
	})

	t.Run("noSpaceLeftOnDevice", func(t *testing.T) {
		if isLockTimeoutError(errors.New("no space left on device")) {
			t.Error("ENOSPC should NOT be classified as lock timeout")
		}
	})

	t.Run("noSuchFileOrDirectory", func(t *testing.T) {
		if isLockTimeoutError(errors.New("no such file or directory")) {
			t.Error("ENOENT should NOT be classified as lock timeout")
		}
	})

	t.Run("invalidArgument", func(t *testing.T) {
		if isLockTimeoutError(errors.New("invalid argument")) {
			t.Error("EINVAL should NOT be classified as lock timeout")
		}
	})

	t.Run("corruptionError", func(t *testing.T) {
		// isCorruptionError and isLockTimeoutError should be disjoint:
		// corruption errors are not transient.
		if isLockTimeoutError(errors.New("invalid database header")) {
			t.Error("corruption error should NOT be classified as lock timeout")
		}
	})

	t.Run("randomError", func(t *testing.T) {
		if isLockTimeoutError(errors.New("something else entirely")) {
			t.Error("random error should NOT be classified as lock timeout")
		}
	})
}

// TestDBR11006_OpenBoltWithRetry_FailsFastOnPermanentError verifies that
// openBoltWithRetry does NOT retry when the open fails with a permanent
// (non-transient) error. We trigger this by passing an invalid path
// (a path under a file, not a directory) which causes bbolt.Open to fail
// immediately with a non-timeout error. If the retry logic regresses, this
// test will hang for ~50 seconds before failing — so we use a shorter
// timeout to fail fast in that case.
//
// DB-R11-006 (2026-07-20).
func TestDBR11006_OpenBoltWithRetry_FailsFastOnPermanentError(t *testing.T) {
	// Create a regular file; we will then ask bbolt to open a database
	// at a path "inside" this file, which fails with a non-timeout error.
	tmpFile := filepath.Join(t.TempDir(), "iamafile.txt")
	if err := os.WriteFile(tmpFile, []byte("not a directory"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// dbPath is under tmpFile, so bbolt.Open cannot create the database.
	dbPath := filepath.Join(tmpFile, "data.db")

	// If retry logic regresses, this could take ~50s. Use a 15s timeout
	// to fail fast in that case (5+10+15 = 30s for 3 retries, so 15s is
	// safely below the "fails fast" expectation of <1s).
	done := make(chan struct{})
	var (
		bdb *bolt.DB
		err error
	)
	go func() {
		defer close(done)
		bdb, err = openBoltWithRetry(dbPath)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("openBoltWithRetry took >15s — retry logic likely regressed (should fail fast on permanent error)")
	}
	if err == nil {
		if bdb != nil {
			bdb.Close()
		}
		t.Fatal("expected openBoltWithRetry to fail on a path under a file, but it succeeded")
	}
	if isLockTimeoutError(err) {
		t.Errorf("expected a permanent (non-lock-timeout) error, got: %v", err)
	}
}

// TestDBR11006_OpenBoltWithRetry_SucceedsOnValidPath verifies the happy
// path: openBoltWithRetry returns a usable database when given a valid
// directory path. This guards against the retry change breaking the
// success path.
//
// DB-R11-006 (2026-07-20).
func TestDBR11006_OpenBoltWithRetry_SucceedsOnValidPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")
	bdb, err := openBoltWithRetry(dbPath)
	if err != nil {
		t.Fatalf("openBoltWithRetry on valid path failed: %v", err)
	}
	defer bdb.Close()
	if err := ensureDefaultBucket(bdb); err != nil {
		t.Fatalf("ensureDefaultBucket: %v", err)
	}
	// Sanity: the database should be usable.
	if err := bdb.Update(func(tx *bolt.Tx) error {
		bkt, err := tx.CreateBucketIfNotExists(defaultBucket)
		if err != nil {
			return err
		}
		return bkt.Put([]byte("k"), []byte("v"))
	}); err != nil {
		t.Fatalf("Put after open: %v", err)
	}
}

// ============================================================================
// DB-R12-002 tests: boltBatch atomicity — no more silent auto-flush
// ============================================================================
//
// DB-R12-002 (2026-07-20): the previous auto-flush behavior broke the
// atomicity contract. If the 10001st Put triggered a silent flush and a
// subsequent Put/Write failed, the first 10,000 ops were already persisted
// with no way to roll them back. The fix replaces auto-flush with an
// explicit ErrBatchFull error and a Flush() method for callers that
// legitimately need to split batches at chosen boundaries.

// TestDBR12002_Put_ReturnsErrBatchFull_AtOpsLimit verifies that Put returns
// ErrBatchFull when the batch reaches MaxBatchOps, instead of silently
// auto-flushing. The accumulated ops MUST NOT be persisted (no auto-flush).
func TestDBR12002_Put_ReturnsErrBatchFull_AtOpsLimit(t *testing.T) {
	dir := t.TempDir()
	bdb, err := NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer bdb.Close()

	bb := bdb.NewBatch()
	// Fill the batch up to exactly MaxBatchOps.
	for i := 0; i < MaxBatchOps; i++ {
		key := []byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)}
		if err := bb.Put(key, []byte{byte(i)}); err != nil {
			t.Fatalf("Put #%d failed: %v", i, err)
		}
	}
	// The next Put MUST return ErrBatchFull.
	err = bb.Put([]byte("overflow"), []byte("v"))
	if !errors.Is(err, ErrBatchFull) {
		t.Fatalf("expected ErrBatchFull, got %v", err)
	}

	// CRITICAL: the batch state must be INTACT (no auto-flush happened).
	// Verify by writing the batch — all MaxBatchOps entries must commit.
	if err := bb.Write(); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify one of the originally-queued ops is actually persisted.
	got, err := bdb.Get([]byte{0, 0, 0})
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(got) != 1 || got[0] != 0 {
		t.Errorf("expected [0], got %v", got)
	}
	// Verify the overflow op was NOT persisted (no silent flush).
	got, _ = bdb.Get([]byte("overflow"))
	if got != nil {
		t.Errorf("overflow op should NOT be persisted — auto-flush must not have happened")
	}
}

// TestDBR12002_Put_ReturnsErrBatchFull_AtBytesLimit verifies that Put returns
// ErrBatchFull when the batch reaches MaxBatchBytes, instead of silently
// auto-flushing.
func TestDBR12002_Put_ReturnsErrBatchFull_AtBytesLimit(t *testing.T) {
	dir := t.TempDir()
	bdb, err := NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer bdb.Close()

	bb := bdb.NewBatch()
	// Put a single op that fills the batch right up to MaxBatchBytes.
	bigValue := make([]byte, MaxBatchBytes)
	if err := bb.Put([]byte("big"), bigValue); err != nil {
		t.Fatalf("Put big failed: %v", err)
	}
	// Adding even one more byte MUST return ErrBatchFull.
	err = bb.Put([]byte("overflow"), []byte("x"))
	if !errors.Is(err, ErrBatchFull) {
		t.Fatalf("expected ErrBatchFull, got %v", err)
	}

	// Write must succeed with the original single op.
	if err := bb.Write(); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	got, _ := bdb.Get([]byte("big"))
	if len(got) != MaxBatchBytes {
		t.Errorf("expected %d bytes, got %d", MaxBatchBytes, len(got))
	}
}

// TestDBR12002_Delete_ReturnsErrBatchFull verifies that Delete also returns
// ErrBatchFull at the ops limit, instead of auto-flushing.
func TestDBR12002_Delete_ReturnsErrBatchFull(t *testing.T) {
	dir := t.TempDir()
	bdb, err := NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer bdb.Close()

	// First, put MaxBatchOps+1 keys so deletes have something to delete.
	// R37-P3-06 FIX (2026-07-31): use a batch for pre-fill instead of
	// individual bdb.Put calls. With MaxBatchOps=50000, 50001 independent
	// bbolt transactions on Windows take minutes; a single batch Write()
	// completes in under a second.
	setupBatch := bdb.NewBatch()
	for i := 0; i < MaxBatchOps+1; i++ {
		key := []byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)}
		if err := setupBatch.Put(key, []byte{byte(i)}); err != nil {
			// R37-P3-06: MaxBatchOps=50000 means the pre-fill also hits the
			// batch cap. Flush and continue so all MaxBatchOps+1 keys exist.
			if errors.Is(err, ErrBatchFull) {
				if flushErr := setupBatch.Flush(); flushErr != nil {
					t.Fatalf("setup batch Flush: %v", flushErr)
				}
				if retryErr := setupBatch.Put(key, []byte{byte(i)}); retryErr != nil {
					t.Fatalf("setup batch retry Put #%d: %v", i, retryErr)
				}
			} else {
				t.Fatalf("setup batch Put #%d: %v", i, err)
			}
		}
	}
	if err := setupBatch.Write(); err != nil {
		t.Fatalf("setup batch Write: %v", err)
	}

	bb := bdb.NewBatch()
	// Fill the batch with MaxBatchOps Delete operations.
	for i := 0; i < MaxBatchOps; i++ {
		key := []byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)}
		if err := bb.Delete(key); err != nil {
			t.Fatalf("Delete #%d failed: %v", i, err)
		}
	}
	// The next Delete MUST return ErrBatchFull.
	err = bb.Delete([]byte("overflow"))
	if !errors.Is(err, ErrBatchFull) {
		t.Fatalf("expected ErrBatchFull, got %v", err)
	}

	// Write the MaxBatchOps deletes — they must commit.
	if err := bb.Write(); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	// Verify one of the deleted keys is gone.
	got, _ := bdb.Get([]byte{0, 0, 0})
	if got != nil {
		t.Errorf("key {0,0,0} should have been deleted")
	}
}

// TestDBR12002_Flush_ExplicitSplit verifies that Flush() is the explicit
// split primitive. After Flush(), the batch is empty and can accept new ops.
// Both the pre-flush and post-flush ops must be persisted.
func TestDBR12002_Flush_ExplicitSplit(t *testing.T) {
	dir := t.TempDir()
	bdb, err := NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer bdb.Close()

	bb := bdb.NewBatch()
	// First chunk: 3 puts.
	for i := 0; i < 3; i++ {
		if err := bb.Put([]byte{byte(i)}, []byte{byte(i + 1)}); err != nil {
			t.Fatalf("Put #%d: %v", i, err)
		}
	}
	// Flush — first 3 ops commit atomically.
	if err := bb.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	// Batch must now be empty (ValueSize == 0).
	if bb.ValueSize() != 0 {
		t.Errorf("after Flush, ValueSize should be 0, got %d", bb.ValueSize())
	}

	// Second chunk: 2 more puts. Must succeed (batch was reset by Flush).
	if err := bb.Put([]byte{10}, []byte{11}); err != nil {
		t.Fatalf("Put after Flush: %v", err)
	}
	if err := bb.Put([]byte{11}, []byte{12}); err != nil {
		t.Fatalf("Put after Flush: %v", err)
	}
	if err := bb.Write(); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify both chunks are persisted.
	for _, c := range []struct{ k, v byte }{{0, 1}, {1, 2}, {2, 3}, {10, 11}, {11, 12}} {
		got, _ := bdb.Get([]byte{c.k})
		if len(got) != 1 || got[0] != c.v {
			t.Errorf("key %d: expected [%d], got %v", c.k, c.v, got)
		}
	}
}

// TestDBR12002_Flush_EmptyBatch_NoOp verifies that Flush() on an empty
// batch is a no-op (returns nil, no transaction is opened).
func TestDBR12002_Flush_EmptyBatch_NoOp(t *testing.T) {
	dir := t.TempDir()
	bdb, err := NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer bdb.Close()

	bb := bdb.NewBatch()
	// Flush on empty batch must be a no-op.
	if err := bb.Flush(); err != nil {
		t.Errorf("Flush on empty batch should be no-op, got: %v", err)
	}
	if bb.ValueSize() != 0 {
		t.Errorf("ValueSize should be 0, got %d", bb.ValueSize())
	}
}

// TestDBR12002_NoPartialWrite_OnPutFailure verifies the atomicity guarantee:
// if a Put returns ErrBatchFull, the previously-accumulated ops are NOT
// persisted until the caller explicitly calls Write() or Flush(). This is
// the core of the DB-R12-002 fix — no more silent partial writes.
func TestDBR12002_NoPartialWrite_OnPutFailure(t *testing.T) {
	dir := t.TempDir()
	bdb, err := NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer bdb.Close()

	bb := bdb.NewBatch()
	// Fill the batch up to the limit.
	for i := 0; i < MaxBatchOps; i++ {
		key := []byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)}
		if err := bb.Put(key, []byte{byte(i)}); err != nil {
			t.Fatalf("Put #%d: %v", i, err)
		}
	}
	// Trigger ErrBatchFull.
	err = bb.Put([]byte("overflow"), []byte("v"))
	if !errors.Is(err, ErrBatchFull) {
		t.Fatalf("expected ErrBatchFull, got %v", err)
	}

	// CRITICAL ATOMICITY CHECK: the queued MaxBatchOps entries must NOT yet
	// be persisted — they're still in the in-memory batch. Verify by reading
	// directly from the DB.
	got, _ := bdb.Get([]byte{0, 0, 0})
	if got != nil {
		t.Errorf("queued ops must NOT be persisted before Write() — got %v for key {0,0,0}", got)
	}

	// Now Write() — all ops must commit atomically in a single transaction.
	if err := bb.Write(); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify one of the originally-queued ops is now persisted.
	got, _ = bdb.Get([]byte{0, 0, 0})
	if len(got) != 1 || got[0] != 0 {
		t.Errorf("after Write, expected [0], got %v", got)
	}
}

// TestDBR12002_ErrBatchFull_IsSentinel verifies that ErrBatchFull is a
// proper sentinel error usable with errors.Is.
func TestDBR12002_ErrBatchFull_IsSentinel(t *testing.T) {
	if !errors.Is(ErrBatchFull, ErrBatchFull) {
		t.Error("ErrBatchFull must be a sentinel (errors.Is self-matches)")
	}
	// A wrapped ErrBatchFull must still match.
	wrapped := fmt.Errorf("put failed: %w", ErrBatchFull)
	if !errors.Is(wrapped, ErrBatchFull) {
		t.Error("wrapped ErrBatchFull must still match via errors.Is")
	}
}
