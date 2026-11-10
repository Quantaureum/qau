// M4-F2 hardening regression (audit finding: epoch-reward marker drop not
// atomic with rollback). RollbackToHeight used to delete durable epoch-reward
// markers in a separate best-effort batch AFTER the rollback batch committed,
// swallowing delete failures as WARN and still returning nil — stale markers
// survived a "successful" rollback and made re-execution skip the epoch
// rewards a second time. The fix stages the marker deletes into the SAME
// batch as the balance rollback and aborts fail-closed on any error.
package state

import (
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// markerDeleteFailBatch delegates everything to a healthy batch but fails
// Delete for epoch-reward marker keys, isolating the failure to the marker
// cleanup path (account/storage rollback keys still succeed).
type markerDeleteFailBatch struct {
	inner db.Batch
}

func (b *markerDeleteFailBatch) Put(key, value []byte) error { return b.inner.Put(key, value) }
func (b *markerDeleteFailBatch) Delete(key []byte) error {
	if len(key) >= len(epochRewardAppliedPrefix) && string(key[:len(epochRewardAppliedPrefix)]) == string(epochRewardAppliedPrefix) {
		return errors.New("simulated epoch-reward marker delete failure")
	}
	return b.inner.Delete(key)
}

func (b *markerDeleteFailBatch) Write() error   { return b.inner.Write() }
func (b *markerDeleteFailBatch) Reset()         { b.inner.Reset() }
func (b *markerDeleteFailBatch) ValueSize() int { return b.inner.ValueSize() }
func (b *markerDeleteFailBatch) Flush() error   { return b.inner.Flush() }

// markerDeleteFailDB delegates reads/iterators to the backing DB but hands
// out marker-delete-failing batches.
type markerDeleteFailDB struct {
	db.Database
}

func (d *markerDeleteFailDB) NewBatch() db.Batch {
	return &markerDeleteFailBatch{inner: d.Database.NewBatch()}
}

// TestM4F2_RollbackMarkerDeleteFailureFailsClosed asserts the atomic-unit
// contract:
//   - when staging the marker deletes fails, RollbackToHeight returns an
//     error (never a silent WARN + nil);
//   - the durable state is untouched (the whole rollback batch aborted:
//     balances still post-fork, markers still present) so the unit is atomic;
//   - the in-memory undo and the staged pending marks survive for a retry;
//   - after the failure is removed, the retried rollback fully heals:
//     markers dropped, balances restored.
func TestM4F2_RollbackMarkerDeleteFailureFailsClosed(t *testing.T) {
	backing := db.NewMemDB()
	sdb := NewStateDB(backing)
	addr := types.Address{0x66}

	// Fixture: baseline commit at height 31, epoch-boundary commit at height
	// 32 (balance 100 -> 200 plus the epoch-1 reward marker).
	sdb.SetBalance(addr, big.NewInt(100))
	if _, err := sdb.CommitWithBlock(31); err != nil {
		t.Fatalf("baseline commit failed: %v", err)
	}
	sdb.SetBalance(addr, big.NewInt(200))
	sdb.MarkEpochRewardPending(1, 32)
	if _, err := sdb.CommitWithBlock(32); err != nil {
		t.Fatalf("boundary commit failed: %v", err)
	}
	if !sdb.EpochRewardApplied(1) {
		t.Fatal("fixture broken: marker must be applied after the commit")
	}
	// Stage a second, NOT-YET-COMMITTED mark (epoch 2 at height 33): a failed
	// Commit leaves such marks in memory, and the rollback must drop them
	// once it succeeds — but preserve them while it fails.
	sdb.MarkEpochRewardPending(2, 33)

	// Inject marker-delete failures.
	sdb.mu.Lock()
	sdb.db = &markerDeleteFailDB{Database: backing}
	sdb.mu.Unlock()

	err := sdb.RollbackToHeight(32)
	if err == nil {
		t.Fatal("M4-F2 NOT FIXED: RollbackToHeight returned nil despite the epoch-reward marker delete failure (silent WARN + nil)")
	}

	// Durable state must be consistent with the aborted atomic unit: nothing
	// from the rollback batch landed. The marker survives (it will be dropped
	// together with the balance restore on the retry) and the balance is
	// still the post-fork value.
	raw, gerr := backing.Get(epochRewardAppliedKey(1))
	if gerr != nil || len(raw) != 8 || binary.BigEndian.Uint64(raw) != 32 {
		t.Fatalf("M4-F2: durable marker must be untouched by the aborted rollback (got %v, err=%v)", raw, gerr)
	}
	rawAcc, gerr := backing.Get(append(accountPrefix, addr[:]...))
	if gerr != nil || len(rawAcc) == 0 {
		t.Fatalf("M4-F2: durable account must be untouched by the aborted rollback (err=%v)", gerr)
	}
	var acc Account
	if derr := decodeAccount(rawAcc, &acc); derr != nil {
		t.Fatalf("M4-F2: failed to decode durable account: %v", derr)
	}
	if acc.Balance.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("M4-F2 NOT ATOMIC: durable balance is %s after the aborted rollback, want 200 (rollback half-applied)", acc.Balance)
	}
	if marker, merr := backing.Get(commitPendingKey); merr == nil && len(marker) > 0 {
		t.Fatal("M4-F2: commit-pending marker must not be durable after an aborted rollback (batch was never written)")
	}

	// The in-memory undo must be preserved (R38-P1-05) so the rollback can be
	// retried, and the staged-but-uncommitted mark must not be dropped by the
	// failed attempt.
	sdb.mu.RLock()
	_, undoPreserved := sdb.beforeImages[32]
	pendingMark, markPreserved := sdb.pendingEpochRewardMarks[2]
	sdb.mu.RUnlock()
	if !undoPreserved {
		t.Fatal("M4-F2: beforeImages for the rolled-back height were dropped despite the failed rollback — the rollback is unreplayable")
	}
	if !markPreserved || pendingMark != 33 {
		t.Fatalf("M4-F2: staged pending mark must survive the failed rollback for the retry (present=%v, value=%d)", markPreserved, pendingMark)
	}

	// Heal: remove the injection and retry. The retried rollback must drop
	// the durable markers atomically with the balance restore.
	sdb.mu.Lock()
	sdb.db = backing
	sdb.mu.Unlock()
	if err := sdb.RollbackToHeight(32); err != nil {
		t.Fatalf("healing rollback failed: %v", err)
	}
	if sdb.EpochRewardApplied(1) {
		t.Fatal("M4-F2: marker survived the successful rollback — re-execution would skip the epoch rewards")
	}
	if got := sdb.GetBalance(addr); got == nil || got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("M4-F2: balance after the healing rollback = %v, want 100", got)
	}
	sdb.mu.RLock()
	_, markStillPending := sdb.pendingEpochRewardMarks[2]
	sdb.mu.RUnlock()
	if markStillPending {
		t.Fatal("M4-F2: in-memory pending mark (epoch 2, height 33 >= fork 32) was not dropped by the successful rollback")
	}

	reopened := NewStateDB(backing)
	if reopened.EpochRewardApplied(1) {
		t.Fatal("M4-F2: rolled-back marker resurrected after restart")
	}
}
