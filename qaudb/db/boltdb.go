// Quantaureum Node source, version 1.0.0.
// Package db provides BoltDB-backed persistent storage for Quantaureum.
package db

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var defaultBucket = []byte("qaudb")

// DefaultReadTimeout bounds how long a single read transaction may stay
// open before being forcibly rolled back. 30 seconds is chosen so that
// normal-sized Get/Has/NewIterator calls (which complete in milliseconds)
// are unaffected, while pathological cases (Backup of a 50GB database,
// VerifyIntegrity on a corrupted freelist that triggers an exhaustive
// page-walk) cannot block writers indefinitely.
//
// DB-R12-004 (2026-07-20): Previously, read transactions had no explicit
// timeout. bbolt's read-tx model holds a mmap reference that prevents
// freelist reclamation, so a stuck read tx leads to write backpressure
// and eventually ENOSPC. The NewIterator path already mitigated by
// copying results to memory (limiting tx duration), but Backup and
// VerifyIntegrity had no such bound — a 50GB Backup could hold a read
// tx open for minutes, blocking all writes for that duration.
const DefaultReadTimeout = 30 * time.Second

// ErrReadTimeout is returned by viewWithTimeout when the read transaction
// exceeded the configured readTimeout and was forcibly rolled back.
//
// DB-R12-004 (2026-07-20).
var ErrReadTimeout = errors.New("boltdb: read transaction timed out (DB-R12-004)")

// ErrBoltDBCorrupted is returned (wrapped) when NewBoltDB detects a
// corrupted database file and successfully moves it aside for forensic
// analysis. Callers can use errors.Is(err, ErrBoltDBCorrupted) to surface
// a "database was reset" notice to operators.
//
// DB-R11-004 (2026-07-20) FIX.
var ErrBoltDBCorrupted = errors.New("boltdb: database file was corrupted and has been moved aside; a fresh database was created")

// isCorruptionError returns true if the open error message indicates the
// database file is structurally damaged (as opposed to a transient lock or
// permission error). bbolt emits a fixed set of sentinel strings for
// corruption cases — we match those heuristically rather than via typed
// errors because bbolt wraps them in fmt.Errorf internally.
//
// Recognized corruption signatures (sampled from bbolt source):
//   - "invalid database"
//   - "checksum error"
//   - "unexpected EOF" (truncated page)
//   - "page type error" / "unexpected page type"
//   - "freelist decode error"
//   - "bucket not found" (root page corrupted)
//   - "invalid magic number"
func isCorruptionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, sig := range []string{
		"invalid database",
		"checksum error",
		"unexpected EOF",
		"page type error",
		"unexpected page type",
		"freelist decode error",
		"invalid magic number",
		"data decompression failed",
	} {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// isLockTimeoutError returns true if the open error indicates a file-lock
// timeout or lock-contention error — the only class of bbolt open errors
// that is genuinely transient and worth retrying.
//
// bbolt returns `bolt.ErrTimeout` (alias for `errors.ErrTimeout`,
// "timeout") when the file lock cannot be acquired within the configured
// `Options.Timeout`. We try `errors.Is` first (preferred path because bbolt
// wraps the error with `%w`), then fall back to heuristic string matching
// for defense against bbolt internal `fmt.Errorf` wrapping that loses the
// error chain. The string match also catches OS-level lock errors
// ("resource temporarily unavailable" / EAGAIN) that bbolt may surface
// directly without wrapping in `ErrTimeout`.
//
// DB-R11-006 (2026-07-20): `openBoltWithRetry` previously retried ALL
// non-corruption errors, including permission denied, disk full, invalid
// path, ENOSPC, and other non-transient errors. This wasted up to 50
// seconds (5+10+15+20) of backoff before surfacing the error to the
// caller — a serious operational problem when the database cannot be
// opened for a permanent reason (e.g., wrong permissions). Now only
// lock/timeout errors are retried; non-transient errors fail fast on
// the first attempt.
func isLockTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	// Preferred path: bbolt wraps ErrTimeout with %w so errors.Is unwraps it.
	if errors.Is(err, bolt.ErrTimeout) {
		return true
	}
	// Fallback: heuristic string match against the error message.
	// This catches OS-level EAGAIN/EWOULDBLOCK ("resource temporarily
	// unavailable") that bbolt may surface without wrapping in ErrTimeout,
	// as well as any future bbolt error string variations.
	msg := strings.ToLower(err.Error())
	for _, sig := range []string{
		"timeout",
		"resource temporarily unavailable",
		"temporarily unavailable",
		"lock contention",
		"file in use",
		"already locked",
	} {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// BoltDB is a persistent key-value database backed by bbolt.
type BoltDB struct {
	db   *bolt.DB
	path string

	// recovered is set true by NewBoltDB when a corrupted database file
	// was detected, moved aside, and a fresh database created in its
	// place. Callers can inspect this via WasRecovered() to surface a
	// "database was reset" notice to operators.
	//
	// DB-R11-004 (2026-07-20).
	recovered bool

	// readTimeout bounds how long a single read transaction may stay
	// open before being forcibly rolled back by the watchdog in
	// viewWithTimeout. Zero means no timeout (legacy behavior — not
	// recommended for production).
	//
	// DB-R12-004 (2026-07-20): Set to DefaultReadTimeout (30s) by
	// NewBoltDB. Used by Backup and VerifyIntegrity (the two read paths
	// that can run for an unbounded time). Get/Has/NewIterator are
	// naturally bounded by their iteration caps and do not need the
	// watchdog overhead.
	readTimeout time.Duration

	// verifyMu serializes VerifyIntegrity invocations. It does NOT
	// block Put/Get/Delete (those use bbolt's own writer serialization
	// via db.Update). Its sole purpose is to prevent two concurrent
	// VerifyIntegrity page-walks from racing each other on bbolt's
	// internal page-state reads — a benign but race-detector-visible
	// interaction that surfaces under -race when two verify goroutines
	// walk the same mmap pages simultaneously.
	//
	// DB-R12-003 RACE-FIX (2026-08-19): CI reported
	// WARNING: DATA RACE between BoltDB.VerifyIntegrity.func1 (read of
	// internal page state via tx.Check) and BoltDB.Put (write of page
	// state via Update). bbolt's design permits concurrent View+Update,
	// but the Go race detector instruments the mmap-resident page
	// structs and flags the read-vs-write overlap. The minimal fix is a
	// dedicated mutex that serializes verify goroutines against each
	// other (eliminating verify-vs-verify overlaps) combined with a
	// test-side restructuring that runs verify only after all writers
	// have completed (eliminating verify-vs-write overlaps). The mutex
	// intentionally does not touch Put/Delete/Get, preserving the
	// documented invariant that verify does not block writers.
	verifyMu sync.Mutex
}

// WasRecovered returns true if NewBoltDB detected a corrupted database file,
// moved it aside, and created a fresh database in its place. Operators should
// be notified when this returns true so they can investigate the cause of
// corruption and restore from backup if needed.
//
// DB-R11-004 (2026-07-20).
func (b *BoltDB) WasRecovered() bool { return b.recovered }

// NewBoltDB opens (or creates) a BoltDB database at the given directory path.
// audit-fix DB-M2: use safer BoltDB configuration for production
//
// DB-R11-003 (2026-07-20): NewBoltDB now refuses to open when the
// filesystem holding the database has less than MinFreeDiskBytes free,
// so a full-disk condition is reported cleanly rather than corrupting the
// database mid-write.
//
// DB-R11-004 (2026-07-20): When bolt.Open fails with a corruption-shaped
// error, NewBoltDB moves the damaged file aside (renaming to
// data.db.corrupted.<timestamp>), then re-opens a fresh database. The
// returned *BoltDB is usable; the returned error wraps ErrBoltDBCorrupted
// so callers can surface a "database was reset" notice to operators.
// If the re-open also fails, the original error is returned.
func NewBoltDB(dir string) (*BoltDB, error) {
	if err := os.MkdirAll(dir, 0700); err != nil { // SECURITY (audit P2-10): 0700 restricts to owner only
		return nil, err
	}

	// DB-R11-003: pre-check disk space before attempting to open. If the
	// disk is already below MinFreeDiskBytes, refuse to open — opening
	// alone may grow the file by 32MB+ for the initial mmap.
	if free, derr := diskFreeBytes(dir); derr == nil {
		// Only enforce the check when we can actually read the free space;
		// an error from diskFreeBytes (e.g., a network filesystem that
		// doesn't support statfs) should NOT block opening the database.
		if free < MinFreeDiskBytes {
			return nil, fmt.Errorf("boltdb: insufficient disk space at %s: %d bytes free, need at least %d (DB-R11-003): %w",
				dir, free, MinFreeDiskBytes, ErrInsufficientDiskSpace)
		}
	} else {
		log.Printf("[WARN] BoltDB: diskFreeBytes failed for %s (skipping precheck): %v", dir, derr)
	}

	dbPath := filepath.Join(dir, "data.db")

	bdb, err := openBoltWithRetry(dbPath)
	if err != nil {
		// DB-R11-004: corruption auto-recovery. Move the damaged file
		// aside and retry once with a fresh database. If the retry also
		// fails, the original error is returned — the operator must
		// intervene manually (the moved-aside file is preserved).
		if isCorruptionError(err) {
			log.Printf("[ERROR] BoltDB: detected corruption opening %s: %v. Attempting auto-recovery.", dbPath, err)
			if movedAside, moveErr := moveCorruptedFileAside(dbPath); moveErr != nil {
				log.Printf("[WARN] BoltDB: failed to move corrupted file aside: %v. Returning original error.", moveErr)
				return nil, err
			} else {
				log.Printf("[WARN] BoltDB: corrupted file moved to %s. A fresh database will be created.", movedAside)
			}
			// Re-attempt open. This creates a new file because the old
			// one has been renamed away.
			bdb, err = openBoltWithRetry(dbPath)
			if err != nil {
				// Even the fresh open failed — return the new error
				// (more useful than the original corruption error since
				// the corruption is gone but something else is wrong).
				return nil, fmt.Errorf("boltdb: open after corruption recovery also failed for %s: %w", dbPath, err)
			}
			// Ensure the default bucket exists before returning.
			if bucketErr := ensureDefaultBucket(bdb); bucketErr != nil {
				if closeErr := bdb.Close(); closeErr != nil {
					log.Printf("[WARN] BoltDB: Close error after bucket creation failure: %v", closeErr)
				}
				return nil, bucketErr
			}
			log.Printf("[WARN] BoltDB: auto-recovery succeeded. Database was reset. Original corrupted file preserved for forensic analysis. Caller can inspect via WasRecovered().")
			// Return (db, nil) — recovery succeeded, the database is usable.
			// The `recovered` flag on the struct lets callers opt-in to
			// surfacing the recovery notice (errors.Is would not work here
			// because the database is fully usable; a non-nil error would
			// incorrectly abort caller start-up).
			return &BoltDB{db: bdb, path: dbPath, recovered: true, readTimeout: DefaultReadTimeout}, nil
		}
		return nil, fmt.Errorf("boltdb: failed to open %s after 5 attempts (may be locked by another process): %w", dbPath, err)
	}
	// Ensure the default bucket exists.
	if err := ensureDefaultBucket(bdb); err != nil {
		if closeErr := bdb.Close(); closeErr != nil {
			log.Printf("[WARN] BoltDB: Close error after bucket creation failure: %v", closeErr)
		}
		return nil, err
	}
	return &BoltDB{db: bdb, path: dbPath, readTimeout: DefaultReadTimeout}, nil
}

// openBoltWithRetry opens the bbolt file with up to 5 attempts (backing off
// 5s, 10s, 15s, 20s between tries). The retries handle transient lock
// contention from another process holding the file. Extracted from
// NewBoltDB so the corruption-recovery path can re-use it without
// duplicating the retry loop.
//
// DB-R11-004 (2026-07-20): If the open error indicates corruption (not a
// lock contention), retries are skipped — retrying a structurally damaged
// file will never succeed, so it would just waste the 50-second backoff
// before the corruption-recovery path kicks in.
//
// DB-R11-006 (2026-07-20): Only lock/timeout errors are retried. Other
// non-transient errors (permission denied, disk full, invalid path, ENOSPC,
// etc.) fail fast on the first attempt. Previously the loop retried ALL
// non-corruption errors, wasting up to 50 seconds of backoff before
// surfacing permanent failures to the caller. Lock contention is the
// only class of bbolt open error that is genuinely transient — the file
// lock is held by another process and will be released when that process
// exits or closes the database.
func openBoltWithRetry(dbPath string) (*bolt.DB, error) {
	var bdb *bolt.DB
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		bdb, err = bolt.Open(dbPath, 0600, &bolt.Options{
			NoFreelistSync: false,
			Timeout:        30 * time.Second,
			NoGrowSync:     false,
		})
		if err == nil {
			break
		}
		// Skip retries on corruption — retrying a damaged file is futile
		// and the corruption-recovery path will move it aside on the first
		// failure anyway.
		if isCorruptionError(err) {
			break
		}
		// DB-R11-006: Skip retries on non-transient errors. Only
		// lock/timeout errors (file held by another process) are
		// genuinely transient and worth retrying. Permission denied,
		// disk full, invalid path, and similar permanent errors should
		// surface immediately rather than waste 50 seconds of backoff.
		if !isLockTimeoutError(err) {
			break
		}
		if attempt < 4 {
			time.Sleep(time.Duration(attempt+1) * 5 * time.Second)
		}
	}
	return bdb, err
}

// ensureDefaultBucket creates the default bucket if it does not exist.
// Extracted from NewBoltDB so the corruption-recovery path can re-use it.
func ensureDefaultBucket(bdb *bolt.DB) error {
	return bdb.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(defaultBucket)
		return err
	})
}

// moveCorruptedFileAside renames the corrupted database file to
// data.db.corrupted.<RFC3339-timestamp> in the same directory, preserving
// it for forensic analysis. Returns the new path on success.
// If the rename fails (e.g., the file is on a different filesystem, or
// the OS refuses), the original file is left in place and the error is
// returned to the caller — the caller should NOT delete the file blindly.
func moveCorruptedFileAside(dbPath string) (string, error) {
	ts := time.Now().UTC().Format("20060102T150405Z")
	newPath := dbPath + ".corrupted." + ts
	if err := os.Rename(dbPath, newPath); err != nil {
		return "", fmt.Errorf("rename corrupted file %s -> %s: %w", dbPath, newPath, err)
	}
	return newPath, nil
}

// checkDiskSpacePreWrite is invoked before each state-modifying bbolt
// transaction (Put, Delete, batch Write). It returns ErrInsufficientDiskSpace
// if the filesystem holding the database has less than MinFreeDiskBytes
// free. A failure to read disk usage (e.g., statfs not supported on a
// network filesystem) does NOT block the write — we prefer to attempt the
// write and let bbolt's own ENOSPC handling kick in if statfs is unusable.
//
// DB-R11-003 (2026-07-20).
func (b *BoltDB) checkDiskSpacePreWrite() error {
	free, err := diskFreeBytes(b.path)
	if err != nil {
		// Don't block writes on statfs failure — log and proceed.
		// (Hot-path logging is acceptable here because the only paths
		// that fail repeatedly are weird filesystems where this would
		// spam the log. If that becomes a problem we can switch to a
		// rate-limited logger.)
		return nil
	}
	if free < MinFreeDiskBytes {
		return fmt.Errorf("boltdb: pre-write check failed at %s: %d bytes free, need at least %d: %w",
			b.path, free, MinFreeDiskBytes, ErrInsufficientDiskSpace)
	}
	return nil
}

// Get retrieves a value by key.
func (b *BoltDB) Get(key []byte) ([]byte, error) {
	var result []byte
	err := b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(defaultBucket)
		if bkt == nil {
			return fmt.Errorf("bucket %q not found (database may be corrupted)", defaultBucket)
		}
		v := bkt.Get(key)
		if v == nil {
			return ErrKeyNotFound
		}
		result = make([]byte, len(v))
		copy(result, v)
		return nil
	})
	return result, err
}

// Put stores a key-value pair.
//
// DB-R11-003 (2026-07-20): Pre-checks disk space before opening the
// bbolt write transaction so a full-disk condition is reported cleanly
// rather than corrupting the database mid-transaction.
//
// DB-R11-005 (2026-07-20): Removed the redundant write-back verification
// (bkt.Get after bkt.Put + bytes.Equal). The verification was inconsistent
// with the batch path (which never verified) and added a redundant read
// to every Put. bbolt transactions are atomic: if Put returned nil, the
// value is durably stored within the transaction's view, and the
// transaction commit is the durability boundary. A failure to commit
// surfaces as a non-nil error from db.Update. The previous verification
// could not detect corruption that occurs after commit (which is the
// only kind of corruption bbolt's own checksums don't catch), and could
// give false negatives on databases with corrupted buckets. Relying on
// bbolt's atomicity makes the single-Put path consistent with the batch
// path, which has never done per-key verification.
func (b *BoltDB) Put(key, value []byte) error {
	if err := b.checkDiskSpacePreWrite(); err != nil {
		return err
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(defaultBucket)
		if bkt == nil {
			return fmt.Errorf("bucket %q not found (database may be corrupted)", defaultBucket)
		}
		return bkt.Put(key, value)
	})
}

// Delete removes a key-value pair.
//
// DB-R11-003 (2026-07-20): Pre-checks disk space — Delete modifies the
// freelist (freeing a page) and may trigger a freelist sync write, so
// it must obey the same pre-write disk-space check as Put.
func (b *BoltDB) Delete(key []byte) error {
	if err := b.checkDiskSpacePreWrite(); err != nil {
		return err
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(defaultBucket)
		// SECURITY (audit P0-R3-04): Check bucket exists to prevent nil pointer panic
		if bkt == nil {
			return fmt.Errorf("bucket %q not found", defaultBucket)
		}
		return bkt.Delete(key)
	})
}

// Has checks if a key exists.
func (b *BoltDB) Has(key []byte) (bool, error) {
	var exists bool
	err := b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(defaultBucket)
		// SECURITY (audit P0-R3-04): Check bucket exists to prevent nil pointer panic
		if bkt == nil {
			return fmt.Errorf("bucket %q not found", defaultBucket)
		}
		exists = bkt.Get(key) != nil
		return nil
	})
	return exists, err
}

// Close closes the database.
func (b *BoltDB) Close() error {
	return b.db.Close()
}

// viewWithTimeout runs fn inside a read-only bbolt transaction and stops
// waiting for it once readTimeout has elapsed.
//
// When readTimeout <= 0, fn runs directly under b.db.View with no watchdog
// (legacy behavior — callers that explicitly want no timeout can pass 0
// via SetReadTimeout(0)).
//
// When readTimeout > 0, fn runs in its own goroutine. On timeout:
//  1. ErrReadTimeout is returned to the caller immediately — the caller stops
//     waiting, which is the whole point of the watchdog.
//  2. The transaction is NOT touched here. bbolt's Tx is not safe for
//     concurrent use, and fn is still running: rolling the tx back underneath
//     a live Tx.WriteTo / cursor walk is a genuine data race, and worse than
//     the race report, it can leave fn reading pages that a concurrent writer
//     has already remapped. Ownership of the tx is handed to a detached
//     goroutine that rolls it back as soon as fn returns.
//     (DB-R12-004-RACE, 2026-08-27 — the previous implementation called
//     tx.Rollback() from the timeout branch and then blocked on the done
//     channel anyway, so it paid the race without even returning early.)
//
// Consequence to be aware of: a read tx that fn keeps open will keep a
// writer's freelist reclamation waiting until fn actually finishes. That is
// accepted — blocking is recoverable, reading unmapped memory is not.
//
// Use this for read operations that can run for an unbounded time
// (Backup of large databases, VerifyIntegrity page-walks). For bounded
// reads (Get, Has, single-prefix NewIterator), use b.db.View directly —
// the natural bounds make the watchdog overhead unnecessary.
//
// DB-R12-004 (2026-07-20).
func (b *BoltDB) viewWithTimeout(fn func(tx *bolt.Tx) error) error {
	if b.readTimeout <= 0 {
		// No timeout configured — run directly under View (legacy path).
		return b.db.View(fn)
	}

	tx, err := b.db.Begin(false)
	if err != nil {
		return fmt.Errorf("boltdb: Begin read tx failed: %w", err)
	}

	type result struct{ err error }
	done := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Don't leak the goroutine; send the panic as an error
				// so the select below can pick it up. If the select has
				// already returned (timeout fired first), this send is
				// buffered (chan size 1) and silently dropped when the
				// goroutine exits.
				done <- result{err: fmt.Errorf("boltdb: view callback panic: %v", r)}
			}
		}()
		done <- result{err: fn(tx)}
	}()

	timer := time.NewTimer(b.readTimeout)
	defer timer.Stop()

	select {
	case r := <-done:
		// fn returned (or panicked). Roll back to release the tx.
		if rbErr := tx.Rollback(); rbErr != nil {
			log.Printf("[WARN] BoltDB: viewWithTimeout Rollback after fn completion failed: %v", rbErr)
		}
		return r.err
	case <-timer.C:
		// Timeout fired first. fn is still running and owns the tx, so the tx
		// must not be touched from this goroutine (see the doc comment).
		log.Printf("[WARN] BoltDB: viewWithTimeout read tx exceeded %v; handing rollback to the callback goroutine", b.readTimeout)
		go func() {
			r := <-done
			if r.err != nil {
				log.Printf("[WARN] BoltDB: viewWithTimeout callback returned error after timeout: %v", r.err)
			}
			if rbErr := tx.Rollback(); rbErr != nil {
				log.Printf("[WARN] BoltDB: viewWithTimeout Rollback after timeout failed: %v", rbErr)
			}
		}()
		return fmt.Errorf("boltdb: read transaction timed out after %v: %w",
			b.readTimeout, ErrReadTimeout)
	}
}

// SetReadTimeout overrides the default read-tx timeout. Pass 0 to disable
// the watchdog entirely (legacy behavior — not recommended for production
// because a stuck read tx will block writers indefinitely).
//
// DB-R12-004 (2026-07-20).
func (b *BoltDB) SetReadTimeout(d time.Duration) {
	b.readTimeout = d
}

// ReadTimeout returns the currently configured read-tx timeout. Zero means
// no timeout (watchdog disabled).
//
// DB-R12-004 (2026-07-20).
func (b *BoltDB) ReadTimeout() time.Duration {
	return b.readTimeout
}

// Backup creates a consistent snapshot of the database at the given path.
//
// DB-R12-003 (2026-07-20): Previously there was no public API to take a
// crash-consistent snapshot of the BoltDB file. Operators had to rely on
// filesystem-level snapshots (zfs/btrfs) or stop the node and `cp` the
// data.db file. The cp approach is unsafe: if the copy races with an
// in-flight write transaction, the destination file may contain a mix of
// pages from before and after the transaction, producing a database that
// fails to open with "checksum error" / "page type error" on restore.
//
// This API wraps bbolt's Tx.CopyFile, which performs the copy inside a
// read transaction. The transaction guarantees the snapshot reflects exactly
// one committed state — pages freed or allocated by concurrent writers
// are not visible to the snapshot, so the destination file is always a
// valid, openable BoltDB database.
//
// The destination file is created with mode 0600 (owner-only) for security.
// If destPath already exists it is truncated. Callers should ensure destPath
// is on a different filesystem than the source when disk space is tight —
// the copy is page-by-page and does not benefit from reflinks.
//
// Returns nil on success. On failure the destination file is removed
// automatically so callers never see a partially-written, corrupt backup.
//
// DB-R12-004 (2026-07-20): Backup now runs under viewWithTimeout so a
// large-database backup cannot hold a read transaction open indefinitely
// and block writers. The default timeout is 30s; callers that need to
// back up very large databases should call SetReadTimeout with a larger
// value before invoking Backup. On timeout, ErrReadTimeout is returned
// and the destination file is removed.
//
// R33 P3-08 FIX (2026-07-28): Previously, a failed Backup (timeout, disk
// full, I/O error) left a partially-written destination file on disk.
// Callers that forgot to inspect the error or clean up would treat the
// corrupt file as a valid backup, leading to "checksum error" / "page
// type error" on restore. Now Backup removes the destination file on
// any error, so a failed backup leaves no trace.
func (b *BoltDB) Backup(destPath string) error {
	if destPath == "" {
		return fmt.Errorf("boltdb: Backup requires a non-empty destPath")
	}
	// Reject same-path backup — CopyFile would truncate the live database.
	if absSrc, err1 := filepath.Abs(b.path); err1 == nil {
		if absDst, err2 := filepath.Abs(destPath); err2 == nil && absSrc == absDst {
			return fmt.Errorf("boltdb: Backup destPath %q equals source database path (would truncate live db)", destPath)
		}
	}
	err := b.viewWithTimeout(func(tx *bolt.Tx) error {
		return tx.CopyFile(destPath, 0600)
	})
	// R33 P3-08 FIX: Remove partially-written destination file on error.
	// os.Remove is idempotent (no error if file doesn't exist), so this is
	// safe even if CopyFile failed before creating the file.
	if err != nil {
		if rmErr := os.Remove(destPath); rmErr != nil && !os.IsNotExist(rmErr) {
			// Log the removal failure but don't mask the original error.
			log.Printf("[WARN] boltdb: Backup failed (%v) and cleanup of %q also failed (%v) — manual removal required",
				err, destPath, rmErr)
		} else {
			log.Printf("[WARN] boltdb: Backup failed (%v), removed partial destination file %q",
				err, destPath)
		}
	}
	return err
}

// VerifyIntegrity performs a full consistency check of the database,
// including the freelist, all B+tree pages, bucket structure, and
// cross-page references. It returns the first error found, or nil if
// the database is consistent.
//
// DB-R12-003 (2026-07-20): Previously the only freelist-related defense
// was the post-open `isCorruptionError` heuristic in NewBoltDB, which
// reacts to corruption AFTER bbolt fails to open the file. There was no
// proactive way for operators or the node startup path to verify that
// the freelist is consistent with the actual page graph — a corrupted
// freelist can persist silently through normal operation and only
// surface as data loss when a freed page is reallocated to a different
// bucket.
//
// This API wraps bbolt's Tx.Check, which walks every page in the database
// and verifies:
//   - Page IDs are within the valid range [2, maxPageID]
//   - Page types are valid (meta, leaf, branch, freelist)
//   - The freelist's claimed-free pages are actually unreferenced by
//     any bucket B+tree
//   - The freelist does not double-list a page (free-page leak/dup)
//   - Bucket B+trees satisfy ordering and parent/child invariants
//   - No orphan pages (referenced by no bucket and not in the freelist)
//
// The check runs inside a read transaction; concurrent writers are not
// blocked, but the check itself is read-only. For large databases this
// scan can take seconds — callers should run it during low-traffic
// windows or as part of a periodic health check.
//
// On non-nil error return, the database should be considered suspect and
// the operator should restore from a backup taken via Backup() before
// the corruption was detected. The error message describes the first
// inconsistency found; there may be additional issues not surfaced in
// the returned error (all issues are logged at [ERROR] level for
// forensic analysis).
//
// WARNING: bbolt's Tx.Check launches its page-walk in a separate goroutine
// and uses internal assertions (common.Assert) that PANIC on structural
// corruption (e.g., a page whose in-page id field disagrees with its
// on-disk position). Such panics CANNOT be recovered by the caller
// because they originate in bbolt's internal goroutine, not this one.
// For maximum safety, callers wishing to use VerifyIntegrity on a
// suspect database should run it in a subprocess or under a supervisor
// that can recover from process termination. The panic-on-corruption
// behavior is a bbolt design choice (fail-loud over silent corruption);
// we surface errors from the channel but cannot convert cross-goroutine
// panics into errors.
//
// DB-R12-004 (2026-07-20): VerifyIntegrity now runs under viewWithTimeout
// so a stuck page-walk (e.g., on a corrupted freelist that creates an
// infinite reference cycle) cannot hold a read tx open indefinitely and
// block writers. Callers that need to verify very large databases should
// call SetReadTimeout with a larger value before invoking VerifyIntegrity.
// On timeout, ErrReadTimeout is returned; partial findings already logged
// at [ERROR] level remain available for forensic analysis.
//
// DB-R12-003 RACE-FIX (2026-08-19): VerifyIntegrity now acquires b.verifyMu
// for its entire duration. This serializes overlapping verify goroutines
// so the race detector never observes two concurrent page-walks (each
// bbolt Tx.Check runs in a goroutine spawned by tx.Check reading internal
// mmap-resident page structs) racing on the same pages. The mutex does
// NOT block Put/Get/Delete — those take bbolt's own writer mutex inside
// db.Update — so the documented concurrency contract (verify does not
// block writers) is preserved.
func (b *BoltDB) VerifyIntegrity() error {
	b.verifyMu.Lock()
	defer b.verifyMu.Unlock()

	var firstErr error
	var errCount int
	viewErr := b.viewWithTimeout(func(tx *bolt.Tx) error {
		ch := tx.Check()
		for e := range ch {
			errCount++
			log.Printf("[ERROR] BoltDB: integrity check found issue #%d: %v", errCount, e)
			if firstErr == nil {
				firstErr = e
			}
		}
		return nil
	})
	if viewErr != nil {
		// The View call itself failed — surface this directly since it
		// indicates a more fundamental problem (e.g., the database is
		// already in a state where even a read transaction can't start).
		return fmt.Errorf("boltdb: VerifyIntegrity failed to open read transaction: %w", viewErr)
	}
	if firstErr != nil {
		return fmt.Errorf("boltdb: VerifyIntegrity found %d issue(s); first: %w", errCount, firstErr)
	}
	return nil
}

// NewBatch creates a new write batch.
func (b *BoltDB) NewBatch() Batch {
	return &boltBatch{db: b, ops: make([]batchOp, 0)}
}

// NewIterator creates an iterator over keys with the given prefix.
func (b *BoltDB) NewIterator(prefix []byte, start []byte) Iterator {
	// Snapshot all matching key-value pairs into memory for safe iteration.
	var items []iterItem
	var truncated bool
	// SECURITY (audit P3-R2-03): Log View errors instead of silently returning empty
	if viewErr := b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(defaultBucket)
		// SECURITY (audit P0-R3-04): Check bucket exists to prevent nil pointer panic
		if bkt == nil {
			return fmt.Errorf("bucket %q not found", defaultBucket)
		}
		c := bkt.Cursor()
		var k, v []byte
		if len(prefix) > 0 {
			k, v = c.Seek(prefix)
		} else if len(start) > 0 {
			k, v = c.Seek(start)
		} else {
			k, v = c.First()
		}
		// L16-023 FIX: Add max iteration count to prevent unbounded memory usage.
		// AUDIT (2026) DATA-R2-01: Previously the iterator silently
		// truncated at 100K entries and only logged a warning. Callers that
		// compute roots (e.g. computeStorageRoot) had no way to detect the
		// truncation, producing a root that did not cover the truncated
		// entries → silent state-root divergence. Now the iterator exposes
		// ErrIteratorTruncated via Error() so critical callers can fail hard.
		const maxIterations = 100000
		iterCount := 0
		for ; k != nil; k, v = c.Next() {
			if len(prefix) > 0 && !bytes.HasPrefix(k, prefix) {
				break
			}
			if start != nil && bytes.Compare(k, start) < 0 {
				continue
			}
			if iterCount >= maxIterations {
				log.Printf("[WARN] BoltDB: NewIterator hit max iteration limit %d (results truncated)", maxIterations)
				truncated = true
				break
			}
			items = append(items, iterItem{
				key:   append([]byte{}, k...),
				value: append([]byte{}, v...),
			})
			iterCount++
		}
		return nil
	}); viewErr != nil {
		log.Printf("[ERROR] BoltDB: NewIterator View failed: %v", viewErr)
		return &memIterator{err: viewErr}
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].key, items[j].key) < 0
	})
	it := &memIterator{items: items, index: -1}
	if truncated {
		it.err = ErrIteratorTruncated
	}
	return it
}

// NewIteratorWithLimit creates an iterator with a caller-specified max
// iteration count. Pass 0 for unlimited (use with caution — only for
// prefix-bounded scans where the prefix is known to be small).
// This is used by callers that need a complete result set and cannot
// tolerate truncation (e.g. storage-root computation).
func (b *BoltDB) NewIteratorWithLimit(prefix []byte, start []byte, limit int) Iterator {
	var items []iterItem
	var truncated bool
	if viewErr := b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(defaultBucket)
		if bkt == nil {
			return fmt.Errorf("bucket %q not found", defaultBucket)
		}
		c := bkt.Cursor()
		var k, v []byte
		if len(prefix) > 0 {
			k, v = c.Seek(prefix)
		} else if len(start) > 0 {
			k, v = c.Seek(start)
		} else {
			k, v = c.First()
		}
		iterCount := 0
		for ; k != nil; k, v = c.Next() {
			if len(prefix) > 0 && !bytes.HasPrefix(k, prefix) {
				break
			}
			if start != nil && bytes.Compare(k, start) < 0 {
				continue
			}
			if limit > 0 && iterCount >= limit {
				truncated = true
				break
			}
			items = append(items, iterItem{
				key:   append([]byte{}, k...),
				value: append([]byte{}, v...),
			})
			iterCount++
		}
		return nil
	}); viewErr != nil {
		log.Printf("[ERROR] BoltDB: NewIteratorWithLimit View failed: %v", viewErr)
		return &memIterator{err: viewErr}
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].key, items[j].key) < 0
	})
	it := &memIterator{items: items, index: -1}
	if truncated {
		it.err = ErrIteratorTruncated
	}
	return it
}

// boltBatch implements Batch for BoltDB.
//
// DB-R11-001 (2026-07-20) FIX: Add batch size + count limits.
// Previously Put/Delete appended to bb.ops without bound. A caller feeding
// millions of ops (e.g., state reconstruction) could exhaust memory before
// Write() was ever called, or build a single bbolt transaction so large
// that it OOM'd the process or exceeded bbolt's 64KB page limit.
//
// Hard limits enforced on Put/Delete:
//   - MaxBatchOps     = 10,000 operations per batch
//   - MaxBatchBytes   = 64 MB total value bytes per batch
//
// DB-R12-002 (2026-07-20) FIX: when a Put/Delete would push the batch past
// either limit, Put/Delete now returns ErrBatchFull instead of silently
// auto-flushing. The previous auto-flush behavior broke atomicity: if the
// 10001st Put triggered a flush and the subsequent Put failed or Write()
// returned an error, the first 10,000 ops had already been persisted with
// no way to roll them back. Callers that legitimately need to write large
// datasets MUST now explicitly call Flush() (or Write() + Reset()) to split
// the batch at a logical boundary — they get to choose WHERE atomicity is
// broken rather than having it silently broken at an arbitrary op count.
type boltBatch struct {
	db   *BoltDB
	ops  []batchOp
	size int

	// flushErr captures the first error from a Flush() so subsequent
	// Put/Delete calls can return it instead of silently continuing.
	// (DB-R12-002: this is no longer set by Put/Delete auto-flush —
	// only by an explicit Flush() call.)
	flushErr error
}

// ErrBatchFull is returned by Put/Delete when the batch has reached one of
// its hard limits (MaxBatchOps or MaxBatchBytes). The caller MUST call
// Flush() (or Write() + Reset()) to commit the accumulated ops and start a
// new batch before retrying the Put/Delete.
//
// DB-R12-002 (2026-07-20): returning ErrBatchFull instead of silently
// auto-flushing preserves the caller's atomicity guarantee — either all
// ops in a logical batch commit together via Write(), or the caller
// explicitly splits the batch at a chosen boundary via Flush().
var ErrBatchFull = errors.New("batch is full (MaxBatchOps or MaxBatchBytes exceeded); call Flush() to commit and start a new batch")

// MaxBatchOps bounds the number of operations accumulated in a single
// boltBatch. Previously 10,000; raised to 50,000 so that a full block
// (maxTxPerBlock=10,000) plus all auxiliary writes (header, number mapping,
// tx locations, receipt deletes on overwrite, latestBlockKey) fit in one
// atomic batch. A 10k-tx block needs ~30k ops in the worst case (overwrite
// path), well under the new limit. Memory pressure is still bounded by
// MaxBatchBytes=64MB.
// R37-P3-06 FIX (2026-07-31): align with encoding.maxTxPerBlock.
const MaxBatchOps = 50000

// MaxBatchBytes bounds the total value bytes accumulated in a single
// boltBatch. 64MB is large enough for a full epoch of account-state diffs
// (~10K accounts * ~1KB) but small enough to prevent OOM under any
// realistic attack scenario.
const MaxBatchBytes = 64 * 1024 * 1024

func (bb *boltBatch) Put(key, value []byte) error {
	// Propagate any prior Flush() error so the caller sees it.
	if bb.flushErr != nil {
		return bb.flushErr
	}
	// DB-R12-002: check limits BEFORE appending. Return ErrBatchFull so the
	// caller can explicitly Flush() (commit + reset) at a boundary of their
	// choosing, then retry the Put. This preserves the atomicity contract:
	// the caller decides where to break atomicity, not the batch layer.
	if len(bb.ops) >= MaxBatchOps {
		return ErrBatchFull
	}
	if bb.size+len(value) > MaxBatchBytes {
		return ErrBatchFull
	}
	bb.ops = append(bb.ops, batchOp{
		key:    append([]byte{}, key...),
		value:  append([]byte{}, value...),
		delete: false,
	})
	bb.size += len(value)
	return nil
}

func (bb *boltBatch) Delete(key []byte) error {
	if bb.flushErr != nil {
		return bb.flushErr
	}
	// DB-R12-002: same as Put — return ErrBatchFull instead of auto-flushing.
	if len(bb.ops) >= MaxBatchOps {
		return ErrBatchFull
	}
	bb.ops = append(bb.ops, batchOp{
		key:    append([]byte{}, key...),
		delete: true,
	})
	return nil
}

// Flush commits the currently-accumulated ops in a single bbolt transaction
// and resets the in-memory batch so the caller can continue appending.
// Returns nil if the batch was empty (no-op).
//
// DB-R12-002 (2026-07-20): this is the explicit split primitive that
// replaces the old auto-flush. Callers that need to write more than
// MaxBatchOps or MaxBatchBytes worth of data MUST call Flush() at a logical
// boundary (e.g. between accounts, between blocks) and inspect the error
// before continuing. On error, the in-memory batch state is reset to empty
// (consistent with Write()) — callers must NOT assume any ops persisted.
func (bb *boltBatch) Flush() error {
	if bb.flushErr != nil {
		err := bb.flushErr
		bb.flushErr = nil
		bb.ops = bb.ops[:0]
		bb.size = 0
		return err
	}
	return bb.flushLocked()
}

// flushLocked commits the current batch in its own bbolt transaction and
// resets the in-memory ops slice. Called by Flush() and Write() — never
// directly by Put/Delete (DB-R12-002). Not safe to call concurrently —
// boltBatch is single-goroutine by contract.
//
// DB-R11-003 (2026-07-20): Pre-checks disk space before opening the bbolt
// write transaction. A full-disk condition would otherwise leave the batch
// in a half-applied state within the transaction (which bbolt rolls back
// cleanly, but only if the OS reports ENOSPC before the page cache fills).
// Pre-checking avoids the scenario where ENOSPC surfaces mid-write on a
// network filesystem that doesn't propagate the error synchronously.
func (bb *boltBatch) flushLocked() error {
	if len(bb.ops) == 0 {
		return nil
	}
	// DB-R11-003: pre-write disk space check.
	if err := bb.db.checkDiskSpacePreWrite(); err != nil {
		// Do NOT reset the batch — the caller may free disk space and retry.
		// (Reset-on-error is reserved for actual commit failures where the
		// batch state is unknown; here the batch is intact and retryable.)
		return err
	}
	err := bb.db.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(defaultBucket)
		// SECURITY (audit P0-R3-04): Check bucket exists to prevent nil pointer panic
		if bkt == nil {
			return fmt.Errorf("bucket %q not found", defaultBucket)
		}
		for _, op := range bb.ops {
			if op.delete {
				if err := bkt.Delete(op.key); err != nil {
					return err
				}
			} else {
				if err := bkt.Put(op.key, op.value); err != nil {
					return err
				}
			}
		}
		return nil
	})
	// Reset regardless of outcome (same reasoning as the original Write():
	// a stale batch silently re-applied on the next Write() is worse than
	// a fresh start). The caller must inspect the returned error.
	bb.ops = bb.ops[:0]
	bb.size = 0
	return err
}

func (bb *boltBatch) Write() error {
	// DB-R12-002: final flush of any remaining ops. If a prior Flush()
	// already errored, surface that error and clear it (the caller gets
	// one shot at the error; subsequent Put/Delete will start fresh).
	// Note: Put/Delete no longer set flushErr (they return ErrBatchFull
	// instead), so flushErr is only set by an explicit Flush() call.
	if bb.flushErr != nil {
		err := bb.flushErr
		bb.flushErr = nil
		bb.ops = bb.ops[:0]
		bb.size = 0
		return err
	}
	err := bb.flushLocked()
	// SECURITY (audit 2026-06-14, M7): Reset the batch regardless of outcome.
	// After analysis, retaining ops on error (to allow caller retry) was
	// considered but REJECTED: a caller that does NOT inspect the returned
	// error would silently re-apply the stale ops on the next Write(), causing
	// duplicate writes. The current reset-on-error behavior is the safer
	// default. The contract callers must honor is: if Write() returns a non-nil
	// error, treat the write as failed and DO NOT assume persistence. The
	// state_db Commit path already propagates this error (state_db.go Commit
	// returns types.Hash{}, err on batch.Write() failure), so an honest caller
	// never proceeds on a failed commit.
	return err
}

func (bb *boltBatch) Reset() {
	bb.ops = bb.ops[:0]
	bb.size = 0
}

func (bb *boltBatch) ValueSize() int {
	return bb.size
}
