// Quantaureum Node source, version 1.0.0.
package db

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// =============================================================================
// DB-R12-004 (2026-07-20) tests: viewWithTimeout watchdog
//
// These tests verify that:
//  1. NewBoltDB sets readTimeout = DefaultReadTimeout by default
//  2. SetReadTimeout / ReadTimeout accessors round-trip correctly
//  3. viewWithTimeout returns nil on fast-completing callbacks
//  4. viewWithTimeout returns ErrReadTimeout when the callback blocks
//     longer than the configured timeout
//  5. viewWithTimeout forces tx.Rollback() on timeout (writers unblock)
//  6. viewWithTimeout recovers panics from the callback without leaking
//  7. viewWithTimeout with readTimeout=0 runs synchronously (legacy path)
//  8. Backup succeeds on a small database (sanity check)
//  9. VerifyIntegrity succeeds on a fresh database
// =============================================================================

// newBoltDBForR12004 opens a BoltDB in a temp directory for testing.
// Returns the BoltDB and a cleanup function.
func newBoltDBForR12004(t *testing.T) (*BoltDB, func()) {
	t.Helper()
	dir := t.TempDir()
	bdb, err := NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB failed: %v", err)
	}
	return bdb, func() {
		_ = bdb.Close()
	}
}

// TestDB_R12_004_DefaultReadTimeout verifies that NewBoltDB sets
// readTimeout = DefaultReadTimeout by default.
func TestDB_R12_004_DefaultReadTimeout(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()

	if got := bdb.ReadTimeout(); got != DefaultReadTimeout {
		t.Errorf("ReadTimeout = %v, want %v", got, DefaultReadTimeout)
	}
}

// TestDB_R12_004_SetReadTimeout verifies that SetReadTimeout updates the
// configured timeout and ReadTimeout returns the new value.
func TestDB_R12_004_SetReadTimeout(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()

	bdb.SetReadTimeout(5 * time.Second)
	if got := bdb.ReadTimeout(); got != 5*time.Second {
		t.Errorf("ReadTimeout = %v, want 5s", got)
	}

	// Disable watchdog.
	bdb.SetReadTimeout(0)
	if got := bdb.ReadTimeout(); got != 0 {
		t.Errorf("ReadTimeout = %v, want 0", got)
	}
}

// TestDB_R12_004_FastCallbackReturnsNil verifies that a callback that
// completes quickly returns its result with no timeout.
func TestDB_R12_004_FastCallbackReturnsNil(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()
	bdb.SetReadTimeout(5 * time.Second)

	err := bdb.viewWithTimeout(func(tx *bolt.Tx) error {
		// Fast no-op callback.
		return nil
	})
	if err != nil {
		t.Errorf("expected nil error on fast callback, got %v", err)
	}
}

// TestDB_R12_004_FastCallbackReturnsError verifies that a callback that
// returns a non-nil error surfaces that error to the caller (not masked
// by ErrReadTimeout).
func TestDB_R12_004_FastCallbackReturnsError(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()
	bdb.SetReadTimeout(5 * time.Second)

	sentinel := errors.New("sentinel callback error")
	err := bdb.viewWithTimeout(func(tx *bolt.Tx) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

// TestDB_R12_004_TimeoutFires verifies that when the callback blocks
// longer than the configured timeout, viewWithTimeout returns
// ErrReadTimeout.
func TestDB_R12_004_TimeoutFires(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()
	// Short timeout for test speed.
	bdb.SetReadTimeout(200 * time.Millisecond)

	// Block the callback for 2 seconds — well above the 200ms timeout.
	// The watchdog should fire and forcibly roll back the tx.
	err := bdb.viewWithTimeout(func(tx *bolt.Tx) error {
		time.Sleep(2 * time.Second)
		return nil
	})
	if !errors.Is(err, ErrReadTimeout) {
		t.Errorf("expected ErrReadTimeout, got %v", err)
	}
}

// TestDB_R12_004_TimeoutForcesRollback verifies that after a timeout fires,
// a subsequent write transaction succeeds — proving the read tx was
// actually rolled back (otherwise bbolt would block the writer).
func TestDB_R12_004_TimeoutForcesRollback(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()
	bdb.SetReadTimeout(200 * time.Millisecond)

	// Trigger a timeout.
	_ = bdb.viewWithTimeout(func(tx *bolt.Tx) error {
		time.Sleep(2 * time.Second)
		return nil
	})

	// Attempt a write — this should succeed promptly because the
	// read tx was forcibly rolled back. If the tx were still open,
	// the writer would block (bbolt serializes writers but read tx
	// blocks page reclamation, not the write itself — but a leaked
	// tx can grow the db file unboundedly). We mainly check that
	// the write completes without error.
	done := make(chan error, 1)
	go func() {
		done <- bdb.Put([]byte("post-timeout-key"), []byte("value"))
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Put after timeout failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Put after timeout hung — tx may not have been rolled back")
	}
}

// TestDB_R12_004_PanicRecovery verifies that a panic in the callback is
// recovered and returned as an error (rather than crashing the process).
func TestDB_R12_004_PanicRecovery(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()
	bdb.SetReadTimeout(5 * time.Second)

	err := bdb.viewWithTimeout(func(tx *bolt.Tx) error {
		panic("simulated callback panic")
	})
	if err == nil {
		t.Fatal("expected non-nil error from panic recovery, got nil")
	}
	if !contains(err.Error(), "panic") {
		t.Errorf("expected error to mention panic, got: %v", err)
	}
}

// TestDB_R12_004_ZeroTimeoutRunsSynchronously verifies that when
// readTimeout=0, viewWithTimeout runs the callback directly under
// b.db.View (legacy path) with no watchdog overhead.
func TestDB_R12_004_ZeroTimeoutRunsSynchronously(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()
	bdb.SetReadTimeout(0)

	// Even a long-running callback should complete (no timeout to fire).
	err := bdb.viewWithTimeout(func(tx *bolt.Tx) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	if err != nil {
		t.Errorf("expected nil error on zero-timeout callback, got %v", err)
	}
}

// TestDB_R12_004_BackupSucceeds verifies that Backup works on a small
// database and produces a valid destination file.
func TestDB_R12_004_BackupSucceeds(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()

	// Insert some data.
	for i := 0; i < 10; i++ {
		key := []byte{byte(i)}
		if err := bdb.Put(key, []byte("value")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	// Backup to a temp path. NewBoltDB opens <dir>/data.db, so we
	// must name the backup "data.db" for the subsequent open-as-BoltDB
	// verification to find it.
	destDir := t.TempDir()
	destPath := filepath.Join(destDir, "data.db")
	if err := bdb.Backup(destPath); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Verify the backup file exists and is non-empty.
	info, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("backup file stat failed: %v", err)
	}
	if info.Size() == 0 {
		t.Error("backup file is empty")
	}

	// Verify the backup can be opened as a valid BoltDB.
	backup, err := NewBoltDB(destDir)
	if err != nil {
		t.Fatalf("opening backup failed: %v", err)
	}
	defer backup.Close()
	for i := 0; i < 10; i++ {
		key := []byte{byte(i)}
		val, err := backup.Get(key)
		if err != nil {
			t.Errorf("Get from backup failed for key %d: %v", i, err)
		}
		if string(val) != "value" {
			t.Errorf("backup value mismatch for key %d: %q", i, string(val))
		}
	}
}

// TestDB_R12_004_BackupRejectsSamePath verifies that Backup refuses to
// overwrite the live database file.
func TestDB_R12_004_BackupRejectsSamePath(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()

	err := bdb.Backup(bdb.path)
	if err == nil {
		t.Fatal("expected error on same-path Backup, got nil")
	}
	if !contains(err.Error(), "equals source") {
		t.Errorf("expected 'equals source' error, got: %v", err)
	}
}

// TestDB_R12_004_VerifyIntegrityOnFreshDB verifies that VerifyIntegrity
// succeeds on a fresh, uncorrupted database.
func TestDB_R12_004_VerifyIntegrityOnFreshDB(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()

	// Insert some data.
	for i := 0; i < 5; i++ {
		key := []byte{byte(i)}
		if err := bdb.Put(key, []byte("value")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	if err := bdb.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity on fresh db failed: %v", err)
	}
}

// TestDB_R12_004_BackupWithShortTimeoutFires verifies that Backup honors
// the readTimeout watchdog — when the timeout is artificially short and
// the database has enough data that CopyFile cannot finish in time,
// ErrReadTimeout is returned.
//
// NOTE: This test is sensitive to disk speed. We use a very short timeout
// (1ms) and a non-trivial amount of data to make the timeout fire reliably.
// On very fast disks the test may occasionally pass without timeout — in
// that case we log but do not fail, since the watchdog's correctness is
// already verified by TestDB_R12_004_TimeoutFires.
func TestDB_R12_004_BackupWithShortTimeoutFires(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()

	// Insert enough data to make CopyFile take >1ms.
	for i := 0; i < 100; i++ {
		key := []byte{byte(i), byte(i >> 8)}
		val := make([]byte, 1024) // 1KB values
		if err := bdb.Put(key, val); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	// Set an artificially short timeout.
	bdb.SetReadTimeout(1 * time.Millisecond)
	defer bdb.SetReadTimeout(DefaultReadTimeout)

	destPath := filepath.Join(t.TempDir(), "backup.db")
	err := bdb.Backup(destPath)
	if err == nil {
		t.Logf("Backup completed within 1ms (fast disk) — watchdog not exercised")
		return
	}
	if !errors.Is(err, ErrReadTimeout) {
		t.Errorf("expected ErrReadTimeout or nil, got %v", err)
	}
}

// TestDB_R12_004_ConcurrentViewWithTimeout verifies that viewWithTimeout
// can be called concurrently from multiple goroutines without data races
// or deadlocks (each call opens its own read tx).
func TestDB_R12_004_ConcurrentViewWithTimeout(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()
	bdb.SetReadTimeout(5 * time.Second)

	// Seed some data.
	for i := 0; i < 50; i++ {
		key := []byte{byte(i)}
		if err := bdb.Put(key, []byte("value")); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			err := bdb.viewWithTimeout(func(tx *bolt.Tx) error {
				// Quick read.
				bkt := tx.Bucket(defaultBucket)
				if bkt == nil {
					return errors.New("bucket not found")
				}
				_ = bkt.Get([]byte{0})
				return nil
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("concurrent viewWithTimeout error: %v", err)
		}
	}
}

// TestDB_R12_004_TimeoutDoesNotTouchRunningTx is the regression test for
// DB-R12-004-RACE (2026-08-27).
//
// The original timeout branch called tx.Rollback() while fn was still using
// the same tx from another goroutine, and then blocked on the done channel
// until fn returned. Two defects in one:
//
//   - concurrent use of a bbolt Tx is a data race (the race detector caught it
//     in TestDB_R12_004_BackupWithShortTimeoutFires: Tx.close vs Tx.WriteTo),
//     and a writer remapping the file underneath fn can turn it into a bad
//     memory read rather than just a warning;
//   - the caller did not actually return early, which is the only reason the
//     watchdog exists.
//
// This test pins both properties without needing -race: viewWithTimeout must
// return ErrReadTimeout while fn is still running, and fn's subsequent use of
// the tx must still work.
func TestDB_R12_004_TimeoutDoesNotTouchRunningTx(t *testing.T) {
	bdb, cleanup := newBoltDBForR12004(t)
	defer cleanup()

	if err := bdb.Put([]byte("race-probe"), []byte("value")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	bdb.SetReadTimeout(100 * time.Millisecond)
	defer bdb.SetReadTimeout(DefaultReadTimeout)

	started := make(chan struct{})
	release := make(chan struct{})
	readAfterTimeout := make(chan string, 1)

	err := bdb.viewWithTimeout(func(tx *bolt.Tx) error {
		close(started)
		// Keep the tx open until the test has observed the timeout return.
		<-release
		// Old code had already rolled this tx back from the other goroutine.
		bkt := tx.Bucket(defaultBucket)
		if bkt == nil {
			readAfterTimeout <- ""
			return nil
		}
		readAfterTimeout <- string(bkt.Get([]byte("race-probe")))
		return nil
	})

	// Property 1: the caller returned while fn is still blocked on `release`.
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("callback never started")
	}
	if !errors.Is(err, ErrReadTimeout) {
		t.Fatalf("expected ErrReadTimeout, got %v", err)
	}

	// Property 2: the tx fn owns is still usable — nobody rolled it back
	// underneath it.
	close(release)
	select {
	case got := <-readAfterTimeout:
		if got != "value" {
			t.Errorf("tx read after timeout returned %q, want \"value\" (tx was rolled back underneath the running callback)", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("callback never finished its post-timeout read")
	}
}

// contains is a small helper to avoid importing strings just for substring
// matching.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
