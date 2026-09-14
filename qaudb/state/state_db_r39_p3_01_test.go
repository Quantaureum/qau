// Quantaureum Node source, version 1.0.0.
package state

// R39-P3-01 (2026-08-02) regression tests for commit-pending marker
// clear ERROR-level reporting + atomic counter.
//
// Audit (R39-P3-01): commitPendingKey marker clear failures were logged
// only at WARN severity — operators running log-level=ERROR would miss
// the signal entirely, leaving bbolt-disk-health degradation silent
// until a node hangs on a stuck Verkle rebuild at startup.
//
// The fix elevates the four relevant log.Printf calls to ERROR level
// (with the "R39-P3-01" tag) AND introduces a monotonic
// commitPendingMarkerCloggedCount atomic counter exposed via
// CommitPendingMarkerCloggedCount(). The counter is the single
// monitoring-friendly surface that operators and qauctl can scrape to
// alert when bbolt becomes unhealthy.
//
// We retain the fail-safe design (the next-startup RecoverConsistency
// rebuilds the Verkle tree from BoltDB state; we do NOT abort Commit
// because the account batch.Write already succeeded and an aborted
// Commit would risk caller retry that double-commits).
//
// Tests in this file pin three guarantees:
//   1. Commit() with a marker-clear failure increments
//      CommitPendingMarkerCloggedCount and returns nil (not error —
//      fail-safe retained).
//   2. RollbackToHeight() with a marker-clear failure also increments
//      the counter and returns nil (same fail-safe rationale).
//   3. The counter is monotonic across multiple clogging events.
//
// Strategy: we wrap db.Database with a "failingDeleteDB" wrapper whose
// Batch.Delete returns a fixed error for the commit-pending key. This
// routes the marker clear through the failing path while leaving
// account-data writes through the real MemDB working — letting the
// batch.Write succeed (so the fail-safe fires correctly).

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// r39P3_01MarkerClearErr is the fixed error returned by the wrapper
// when the batch's Delete is called on the commit-pending marker key.
// Identity-checkable so the test can distinguish real Commit-fail from
// wrapper-induced fail.
var r39P3_01MarkerClearErr = errors.New("R39-P3-01-test: simulated bbolt Delete failure on commit-pending marker")

// r39P3_01FailingDeleteDB wraps a real MemDB but returns a Batch whose
// Delete() fails on the commit-pending marker key. All other ops route
// to the inner MemDB / memBatch.
type r39P3_01FailingDeleteDB struct {
	inner db.Database
}

func newR39P3_01FailingDeleteDB() *r39P3_01FailingDeleteDB {
	return &r39P3_01FailingDeleteDB{inner: db.NewMemDB()}
}

// All non-batch-creating methods route directly to the inner Database —
// we want the StateDB to observe a fully functional memDB on the Get/
// Put/Has/Iterator surfaces.
func (f *r39P3_01FailingDeleteDB) Get(key []byte) ([]byte, error) { return f.inner.Get(key) }
func (f *r39P3_01FailingDeleteDB) Put(key, value []byte) error    { return f.inner.Put(key, value) }
func (f *r39P3_01FailingDeleteDB) Delete(key []byte) error        { return f.inner.Delete(key) }
func (f *r39P3_01FailingDeleteDB) Has(key []byte) (bool, error)   { return f.inner.Has(key) }
func (f *r39P3_01FailingDeleteDB) Close() error                   { return f.inner.Close() }
func (f *r39P3_01FailingDeleteDB) NewIterator(p, s []byte) db.Iterator {
	return f.inner.NewIterator(p, s)
}
func (f *r39P3_01FailingDeleteDB) NewIteratorWithLimit(p, s []byte, n int) db.Iterator {
	return f.inner.NewIteratorWithLimit(p, s, n)
}

// NewBatch returns an inner-batch wrapper whose Delete trips the
// marker-clear failure path.
func (f *r39P3_01FailingDeleteDB) NewBatch() db.Batch {
	return &r39P3_01FailDeleteBatch{inner: f.inner.NewBatch()}
}

// r39P3_01FailDeleteBatch wraps a real db.Batch whose Delete returns
// r39P3_01MarkerClearErr when called on the commit-pending marker key.
// All other ops route to the inner batch (Put / Write / Reset / Flush /
// ValueSize) so the StateDB's normal commit logic still works for the
// account-data writes — only the marker clear trips.
type r39P3_01FailDeleteBatch struct {
	inner db.Batch
}

func (b *r39P3_01FailDeleteBatch) Put(k, v []byte) error { return b.inner.Put(k, v) }
func (b *r39P3_01FailDeleteBatch) Delete(k []byte) error {
	if bytes.Equal(k, commitPendingKey) {
		return r39P3_01MarkerClearErr
	}
	return b.inner.Delete(k)
}
func (b *r39P3_01FailDeleteBatch) Write() error   { return b.inner.Write() }
func (b *r39P3_01FailDeleteBatch) Reset()         { b.inner.Reset() }
func (b *r39P3_01FailDeleteBatch) ValueSize() int { return b.inner.ValueSize() }
func (b *r39P3_01FailDeleteBatch) Flush() error   { return b.inner.Flush() }

// ── Test 1: Commit() with marker-clear failure bumps counter, returns nil. ──

// TestR39_P3_01_Commit_MarkerClearFail_BumpsCounter_ReturnsNil pins the
// audit's contract: when the commit-pending marker clear Delete fails
// (bbolt disk health degraded), the Commit() call:
//
//   - returns nil (fail-safe retained — account batch.Write already
//     succeeded; an aborted Commit would risk caller double-commit);
//   - increments the R39-P3-01 counter so operators monitoring
//     CommitPendingMarkerCloggedCount see the failure.
//
// Without the counter, the operator would only discover the bbolt-disk
// failure at restart time, when RecoverConsistency hangs on a 1M-node
// Verkle rebuild — minutes of downtime the early ERROR-level log +
// counter would have flagged.
//
// Fixture: StateDB built over a failingDeleteDB. Set a balance for an
// account and Commit at height 1. The commit-pending marker clear Delete
// returns r39P3_01MarkerClearErr. We assert counter went 0→1 and Commit
// returned nil.
func TestR39_P3_01_Commit_MarkerClearFail_BumpsCounter_ReturnsNil(t *testing.T) {
	sdb := NewStateDB(newR39P3_01FailingDeleteDB())
	if got := sdb.CommitPendingMarkerCloggedCount(); got != 0 {
		t.Fatalf("R39-P3-01: precondition — counter must start at 0, got %d", got)
	}
	addr := types.BytesToAddress([]byte{0xAA})
	sdb.SetBalance(addr, big.NewInt(1000))
	root, err := sdb.Commit(1)
	if err != nil {
		t.Fatalf("R39-P3-01: Commit MUST return nil on marker-clear failure (fail-safe retained — account batch.Write already succeeded; an aborted Commit would risk caller retry that double-commits) — got error: %v", err)
	}
	// Sanity: root is non-zero (the account-data batch.Write succeeded).
	var zeroHash types.Hash
	if root == zeroHash {
		t.Fatalf("R39-P3-01: Commit returned a zero root — the account batch.Write also failed (fixture bug; the failingDeleteDB is supposed to ONLY fail marker-clear, not account writes)")
	}
	if got := sdb.CommitPendingMarkerCloggedCount(); got != 1 {
		t.Fatalf("R39-P3-01: CommitPendingMarkerCloggedCount must be 1 after a single marker-clear failure — got %d (audit's R39-P3-01 finding remains: operators monitoring CommitPendingMarkerCloggedCount would NOT see the disk-health signal)", got)
	}
}

// ── Test 2: RollbackToHeight() with marker-clear failure bumps counter. ──

// TestR39_P3_01_RollbackToHeight_MarkerClearFail_BumpsCounter pins the
// same contract on the Rollback path: the post-rollback marker clear
// has the same fail-safe + ERROR + counter semantics.
//
// Fixture: seed beforeImages at heights 1 and 2, call RollbackToHeight(1),
// trigger the marker-clear failure. Counter must bump.
func TestR39_P3_01_RollbackToHeight_MarkerClearFail_BumpsCounter(t *testing.T) {
	sdb := NewStateDB(newR39P3_01FailingDeleteDB())
	addr := types.BytesToAddress([]byte{0xBB})
	r39P2_02SeedBeforeImage(sdb, 1, addr)
	r39P2_02SeedBeforeImage(sdb, 2, addr)
	if got := sdb.CommitPendingMarkerCloggedCount(); got != 0 {
		t.Fatalf("R39-P3-01: precondition — counter must start at 0, got %d", got)
	}
	if err := sdb.RollbackToHeight(1); err != nil {
		t.Fatalf("R39-P3-01: RollbackToHeight MUST return nil on marker-clear failure (fail-safe retained) — got error: %v", err)
	}
	if got := sdb.CommitPendingMarkerCloggedCount(); got < 1 {
		t.Fatalf("R39-P3-01: RollbackToHeight's marker-clear failure MUST bump CommitPendingMarkerCloggedCount — got %d (expected >=1; audit's R39-P3-01 finding remains on the rollback path)", got)
	}
}

// ── Test 3: counter is monotonic across multiple events. ──

// TestR39_P3_01_Counter_Monotonic_AcrossMultiple pins the monotonic
// contract: the counter MUST NOT reset after a successful Commit; it
// accumulates the lifetime clogging-event count. Operators with
// monitoring tools (qauctl status, Prometheus scrape) configure alerts
// on the DELTA, not the absolute value, so a non-monotonic counter
// would silently drop alert thresholds when a transient healthy commit
// "reset" the value.
//
// Fixture: seed multiple Commits, each followed by a marker-clear
// failure; counter must increment by 1 per failure (not reset).
func TestR39_P3_01_Counter_Monotonic_AcrossMultiple(t *testing.T) {
	sdb := NewStateDB(newR39P3_01FailingDeleteDB())
	addr := types.BytesToAddress([]byte{0xCC})
	for i := 1; i <= 3; i++ {
		sdb.SetBalance(addr, big.NewInt(int64(1000*i)))
		if _, err := sdb.Commit(uint64(i)); err != nil {
			t.Fatalf("R39-P3-01: Commit at iteration %d returned unexpected error %v", i, err)
		}
	}
	// Three Commits → three marker-clear failures → counter == 3.
	// Each Commit exercises one marker clear (the postBatch.Delete at
	// line ~1853). The wrapper's Delete trips on commitPendingKey so
	// every Commit increments once.
	if got := sdb.CommitPendingMarkerCloggedCount(); got < 3 {
		t.Fatalf("R39-P3-01: counter must be monotonic — after 3 Commit iterations with marker-clear failures, counter must be >=3, got %d (non-monotonic counter would lead monitoring tools to drop alerts when a transient healthy commit 'reset' the value)", got)
	}
}

// ── Test 4: nil StateDB's CommitPendingMarkerCloggedCount returns 0 safely. ──

// TestR39_P3_01_NilStateDB_ReturnsZero pins the defensive nil-guard:
// operators querying a not-yet-initialized StateDB ref MUST NOT panic.
// Without the nil check, monitoring tools running during startup would
// crash on `s == nil`.
func TestR39_P3_01_NilStateDB_ReturnsZero(t *testing.T) {
	var nilSDB *StateDB
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("R39-P3-01: CommitPendingMarkerCloggedCount panicked on nil StateDB — operator dashboards running during startup would crash on the nil ref: %v", r)
		}
	}()
	if got := nilSDB.CommitPendingMarkerCloggedCount(); got != 0 {
		t.Fatalf("R39-P3-01: nil StateDB's CommitPendingMarkerCloggedCount must return 0, got %d", got)
	}
}
