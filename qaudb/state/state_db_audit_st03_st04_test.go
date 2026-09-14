// Quantaureum Node source, version 1.0.0.
package state

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
)

// TestST03_CommitAbortKeepsDirtyState is the regression test for AUDIT
// ST-03 (2026-08-14): when Commit() aborts because a silent mutation error
// was recorded (lastError), the dirty state must NOT be cleared. The failed
// mutation never entered the dirty maps, while the SUCCESSFUL mutations of
// the same transaction did (and were also applied in-place to the account
// cache by the setters). Clearing the dirty maps on the error path left the
// cache mutations orphaned — readable forever, but never persistable — and
// left the caller no way to inspect or revert the half-applied transaction.
//
// The contract after the fix: an aborted Commit keeps the dirty state (and
// clears lastError so a subsequent transaction is not spuriously aborted);
// callers that need a clean slate call Revert(), which clears dirty state,
// caches, snapshots and lastError together.
func TestST03_CommitAbortKeepsDirtyState(t *testing.T) {
	underlying := db.NewMemDB()
	failing := &failingGetDB{Database: underlying, failOnGet: false}
	sdb := NewStateDB(failing)

	badAddr := types.Address{0xBD}
	okAddr := types.Address{0x4F}

	// Seed both accounts so they land in the account cache after Commit.
	sdb.SetNonce(badAddr, 1)
	sdb.SetNonce(okAddr, 1)
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	// Evict ONLY badAddr from the cache so its next load hits the (failing)
	// DB, while okAddr keeps being served from cache.
	sdb.mu.Lock()
	delete(sdb.accountCache, badAddr)
	sdb.mu.Unlock()

	// badAddr load fails -> lastError recorded, mutation not applied.
	failing.failOnGet = true
	sdb.SetNonce(badAddr, 2)

	// okAddr is served from cache -> mutation succeeds, enters dirty state
	// (and mutates the cached account in place, mirroring the setters).
	sdb.SetNonce(okAddr, 7)

	if _, err := sdb.Commit(); err == nil {
		t.Fatal("ST-03 regression: Commit succeeded despite recorded silent mutation error")
	}

	// ST-03 core assertion: the dirty state SURVIVES the aborted Commit.
	sdb.mu.RLock()
	dirtyAcc, inDirty := sdb.dirtyAccounts[okAddr]
	dirtyLen := len(sdb.dirtyAccounts)
	sdb.mu.RUnlock()
	if dirtyLen == 0 || !inDirty {
		t.Fatalf("ST-03 NOT FIXED: aborted Commit cleared the dirty state (len=%d, okAddr present=%v)", dirtyLen, inDirty)
	}
	if dirtyAcc.Nonce != 7 {
		t.Fatalf("ST-03 NOT FIXED: dirty account nonce = %d, want 7", dirtyAcc.Nonce)
	}
	// The failed mutation must NOT have been staged.
	sdb.mu.RLock()
	_, badInDirty := sdb.dirtyAccounts[badAddr]
	sdb.mu.RUnlock()
	if badInDirty {
		t.Fatal("ST-03 regression: failed mutation (badAddr) was staged into dirty state")
	}

	// lastError must be cleared so the next transaction is not spuriously
	// aborted (long-lived StateDBs, e.g. the syncer's, must not wedge).
	sdb.mu.RLock()
	lastErr := sdb.lastError
	sdb.mu.RUnlock()
	if lastErr != nil {
		t.Fatalf("ST-03 regression: lastError not cleared after aborted Commit: %v", lastErr)
	}

	// Revert() remains the consistent reset path: dirty state cleared.
	sdb.Revert()
	sdb.mu.RLock()
	afterRevert := len(sdb.dirtyAccounts)
	sdb.mu.RUnlock()
	if afterRevert != 0 {
		t.Fatalf("ST-03 regression: Revert() left %d dirty accounts", afterRevert)
	}
}

// verkleFailBatch is a db.Batch whose every mutating op fails. Attached to
// a dedicated Verkle tree (see TestST04_VerkleFailureKeepsDirtyState) it
// simulates persistent Verkle node-storage I/O failure while the StateDB's
// own account batch keeps writing to the real database — exactly the
// "account batch committed, Verkle tree update failed" window AUDIT ST-04
// describes.
type verkleFailBatch struct{}

func (b *verkleFailBatch) Put(key, value []byte) error {
	return errors.New("simulated verkle node write failure")
}

func (b *verkleFailBatch) Delete(key []byte) error {
	return errors.New("simulated verkle node delete failure")
}

func (b *verkleFailBatch) Write() error {
	return errors.New("simulated verkle batch write failure")
}

func (b *verkleFailBatch) Reset()         {}
func (b *verkleFailBatch) ValueSize() int { return 0 }
func (b *verkleFailBatch) Flush() error {
	return errors.New("simulated verkle batch flush failure")
}

// verkleFailDB delegates reads/iterators to a real MemDB but hands out
// always-failing batches, so VerkleTree.Put records a pendingBatchErr and
// VerkleTree.Flush() surfaces it (the P1-STATE-04 Write-retry inside Flush
// also fails, keeping the error sticky).
type verkleFailDB struct {
	db.Database
}

func (d *verkleFailDB) NewBatch() db.Batch { return &verkleFailBatch{} }

// TestST04_VerkleFailureKeepsDirtyState is the regression test for AUDIT
// ST-04 (2026-08-14): when the account batch commits to the DB but the
// derived Verkle tree update fails, Commit() must NOT clear the dirty
// state. Keeping it lets the next Commit re-stage the same (idempotent)
// account writes and retry the tree updates, healing the stale derived
// index in-process instead of requiring a restart + RecoverConsistency
// rebuild. Previously the dirty state was cleared unconditionally, so the
// failed Verkle update could never be retried or rolled back.
func TestST04_VerkleFailureKeepsDirtyState(t *testing.T) {
	sdb := NewStateDB(db.NewMemDB())

	// Swap in a Verkle tree backed by a failing persistent DB. The swap
	// happens before any mutation, so all Verkle persistence goes through
	// the failing batches while the account store stays healthy.
	sdb.mu.Lock()
	sdb.stateTrie = trie.NewVerkleTree(256, &verkleFailDB{Database: db.NewMemDB()})
	sdb.mu.Unlock()

	addr := types.Address{0x57}

	// Stage a mutation and Commit. The account batch must succeed; the
	// Verkle flush must fail (injected). Per the existing contract Commit
	// still returns a nil error (the authoritative state is in the DB and
	// the commit-pending marker triggers a rebuild on restart).
	sdb.SetNonce(addr, 42)
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("Commit returned error on Verkle failure (contract: nil error, stale tree): %v", err)
	}

	// ST-04 core assertion: the dirty state SURVIVES the failed Verkle
	// update so a later Commit can retry the tree update.
	sdb.mu.RLock()
	dirtyLen := len(sdb.dirtyAccounts)
	dirtyAcc, inDirty := sdb.dirtyAccounts[addr]
	sdb.mu.RUnlock()
	if dirtyLen == 0 || !inDirty {
		t.Fatalf("ST-04 NOT FIXED: Commit cleared dirty state despite Verkle update failure (len=%d, addr present=%v)", dirtyLen, inDirty)
	}
	if dirtyAcc.Nonce != 42 {
		t.Fatalf("ST-04 NOT FIXED: dirty account nonce = %d, want 42", dirtyAcc.Nonce)
	}

	// The account write itself IS durable (batch.Write succeeded).
	if got := sdb.GetNonce(addr); got != 42 {
		t.Fatalf("account nonce after commit = %d, want 42 (account batch must be durable)", got)
	}

	// Self-healing path: swap in a healthy Verkle tree and Commit again.
	// The retained dirty state re-stages the account (idempotent rewrite)
	// and the Verkle update now succeeds, so the dirty state is cleared.
	sdb.mu.Lock()
	sdb.stateTrie = trie.NewVerkleTree(256, db.NewMemDB())
	sdb.mu.Unlock()
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("healing Commit failed: %v", err)
	}
	sdb.mu.RLock()
	afterHeal := len(sdb.dirtyAccounts)
	sdb.mu.RUnlock()
	if afterHeal != 0 {
		t.Fatalf("ST-04 regression: dirty state (%d accounts) not cleared after successful Verkle update", afterHeal)
	}
}
