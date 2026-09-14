// Quantaureum Node source, version 1.0.0.
// Package state — R38-P1-05 regression tests.
//
// AUDIT (2026) R38-P1-05: Storage — RollbackToHeight deleted per-height
// entries from beforeImages / modificationLog INSIDE the apply-loop, i.e.
// BEFORE batch.Write() committed. A process crash (or a batch.Write failure)
// during rollback would therefore lose the in-memory undo records: the next
// startup would have no undo to replay, silently leaving the node
// half-rolled-back with a state root permanently divergent from honest peers.
//
// The fix:
//  1. Collect the heights to be cleaned into pendingUndoHeights inside the
//     loop instead of deleting immediately.
//  2. Drop them from beforeImages / modificationLog ONLY AFTER batch.Write()
//     returns nil. On Write failure, return the error WITHOUT clearing the
//     undo, preserving it for the next-startup retry.
//
// These tests verify:
//  1. When batch.Write fails, beforeImages / modificationLog are NOT cleared
//     (the rollback stays replayable).
//  2. On the happy path (batch.Write succeeds), the undo records ARE cleared
//     after the durable commit.
//  3. On Write failure, the in-memory state remains consistent (no partial
//     cleanup leaves the maps in a torn state).
package state

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// failWriteBatch wraps a db.Batch and forces Write() to fail after the first
// call. Flush()/Reset()/Put()/Delete()/ValueSize() delegate to the inner batch
// so the rest of RollbackToHeight (which may rely on Flush for large batches)
// keeps working up to the final Write() that we instrument to fail.
type failWriteBatch struct {
	db.Batch
	writeCalls   int
	writeFailure error
}

func (b *failWriteBatch) Write() error {
	b.writeCalls++
	if b.writeFailure != nil {
		// Force a failure so the rollback cannot durably commit.
		return b.writeFailure
	}
	return b.Batch.Write()
}

// failingBatchDB wraps a Database and returns a failWriteBatch from NewBatch
// so tests can deterministically simulate a batch.Write() failure during
// RollbackToHeight. All other Database methods (Get/Put/Delete/Has/Close/
// NewIterator) delegate to the embedded Database.
type failingBatchDB struct {
	db.Database
	writeFailure error
	// writeCalls captures the most recent batch's Write call count, if a
	// test wants to assert that Write was actually attempted.
	writeCalls int
}

func (f *failingBatchDB) NewBatch() db.Batch {
	inner := f.Database.NewBatch()
	return &failWriteBatch{
		Batch:        inner,
		writeFailure: f.writeFailure,
	}
}

// plantBeforeImage writes a before-image for (height, addr) directly into the
// StateDB's private beforeImages map. Tests use this to set up a deterministic
// rollback scenario without driving a full Commit cycle.
func plantBeforeImage(s *StateDB, height uint64, addr types.Address, acc *Account, storage map[types.Hash]types.Hash) {
	if s.beforeImages[height] == nil {
		s.beforeImages[height] = make(map[types.Address]*accountBeforeImage)
	}
	if storage == nil {
		storage = make(map[types.Hash]types.Hash)
	}
	s.beforeImages[height][addr] = &accountBeforeImage{
		account: acc,
		storage: storage,
	}
}

// plantModificationLog writes a modificationLog entry for (height, addrs)
// so tests can assert that modLog entries are also preserved/removed in lock
// step with beforeImages.
func plantModificationLog(s *StateDB, height uint64, addrs ...types.Address) {
	s.modificationLog[height] = append(s.modificationLog[height], addrs...)
}

// TestR38P1_05_RollbackToHeight_PreservesUndoBeforeBatchCommit verifies that
// when batch.Write() fails, the in-memory undo records (beforeImages /
// modificationLog) are NOT deleted. The pre-fix code deleted them inside the
// apply-loop, so a Write failure would leave the rollback unreplayable.
func TestR38P1_05_RollbackToHeight_PreservesUndoBeforeBatchCommit(t *testing.T) {
	underlying := db.NewMemDB()
	failing := &failingBatchDB{
		Database:     underlying,
		writeFailure: errors.New("simulated batch.Write failure (R38-P1-05)"),
	}
	// Use NewStateDB with the failing DB. Construction does not touch batch
	// writes (no marker) so RecoverConsistency returns nil.
	sdb := NewStateDB(failing)

	addr := testAddr(0x51)
	// Plant a before-image indicating addr should be restored to balance 100
	// at height 2. Plant a fresh account at height 2 too so the rollback has
	// something to write to BoltDB (via the failing batch).
	restoredAcc := NewAccount()
	restoredAcc.Balance = big.NewInt(100)
	restoredAcc.Nonce = 3
	plantBeforeImage(sdb, 2, addr, restoredAcc, nil)
	plantModificationLog(sdb, 2, addr)

	// Sanity: the undo is present before rollback.
	if _, ok := sdb.beforeImages[2]; !ok {
		t.Fatalf("setup: beforeImages[2] not planted")
	}
	if _, ok := sdb.modificationLog[2]; !ok {
		t.Fatalf("setup: modificationLog[2] not planted")
	}

	// Rollback to height 2 — must fail because batch.Write fails.
	err := sdb.RollbackToHeight(2)
	if err == nil {
		t.Fatalf("R38-P1-05 test setup invalid: expected RollbackToHeight to fail " +
			"because batch.Write is forced to fail")
	}

	// KEY ASSERTION: the undo records MUST still be present so the rollback
	// can be replayed on the next startup / operator retry. If the fix is
	// missing, beforeImages[2] is already gone (deleted inside the loop).
	if _, ok := sdb.beforeImages[2]; !ok {
		t.Fatalf("R38-P1-05 NOT FIXED: beforeImages[2] was deleted before batch.Write " +
			"committed — on a real crash the next startup would have no undo to " +
			"replay, leaving the node half-rolled-back with a divergent state root")
	}
	// The actual before-image content must be intact (not half-cleared).
	bi := sdb.beforeImages[2][addr]
	if bi == nil || bi.account == nil {
		t.Fatalf("R38-P1-05: before-image for addr was emptied on Write failure — " +
			"undo content must be preserved verbatim for retry")
	}
	if bi.account.Balance.Cmp(big.NewInt(100)) != 0 || bi.account.Nonce != 3 {
		t.Fatalf("R38-P1-05: before-image content changed on Write failure: balance=%s nonce=%d",
			bi.account.Balance.String(), bi.account.Nonce)
	}
	// modificationLog must also be preserved in lock step.
	if _, ok := sdb.modificationLog[2]; !ok {
		t.Fatalf("R38-P1-05 NOT FIXED: modificationLog[2] was deleted before " +
			"batch.Write committed — undo state for retry must stay consistent")
	}
}

// TestR38P1_05_RollbackToHeight_DeletesUndoAfterBatchCommit verifies the
// happy path: when batch.Write() succeeds, the in-memory undo records ARE
// cleared after the durable commit. This guards against an over-strict fix
// that would leak undo records forever (memory growth + replay-once-only
// invariant violation).
func TestR38P1_05_RollbackToHeight_DeletesUndoAfterBatchCommit(t *testing.T) {
	underlying := db.NewMemDB()
	// Plain MemDB — batch.Write succeeds.
	sdb := NewStateDB(underlying)

	addr := testAddr(0x52)
	restoredAcc := NewAccount()
	restoredAcc.Balance = big.NewInt(250)
	plantBeforeImage(sdb, 2, addr, restoredAcc, nil)
	plantModificationLog(sdb, 2, addr)

	if err := sdb.RollbackToHeight(2); err != nil {
		t.Fatalf("RollbackToHeight should succeed on happy path: %v", err)
	}

	if _, ok := sdb.beforeImages[2]; ok {
		t.Fatalf("R38-P1-05: beforeImages[2] should be cleared after a " +
			"successful durable rollback")
	}
	if _, ok := sdb.modificationLog[2]; ok {
		t.Fatalf("R38-P1-05: modificationLog[2] should be cleared after a " +
			"successful durable rollback")
	}
}

// TestR38P1_05_RollbackToHeight_BatchWriteFailure_DoesNotLeaveOriginalStateCorrupted
// verifies that a Write failure leaves the in-memory undo state self-
// consistent: no height is half-deleted (present in beforeImages but not
// modificationLog, or vice versa). A torn undo map would confuse the next
// rollback attempt.
func TestR38P1_05_RollbackToHeight_BatchWriteFailure_DoesNotLeaveOriginalStateCorrupted(t *testing.T) {
	underlying := db.NewMemDB()
	failing := &failingBatchDB{
		Database:     underlying,
		writeFailure: errors.New("simulated batch.Write failure (R38-P1-05 torn)"),
	}
	sdb := NewStateDB(failing)

	// Plant undo at two heights so we can detect a torn cleanup.
	h := uint64(3)
	for i := byte(0x60); i < 0x62; i++ {
		a := testAddr(i)
		acc := NewAccount()
		acc.Balance = big.NewInt(int64(i) * 10)
		plantBeforeImage(sdb, h, a, acc, nil)
	}
	plantModificationLog(sdb, h, testAddr(0x60), testAddr(0x61))

	if err := sdb.RollbackToHeight(h); err == nil {
		t.Fatalf("expected RollbackToHeight to fail under injected Write failure")
	}

	// Both maps must agree about height h (both present → both safe to retry).
	_, biPresent := sdb.beforeImages[h]
	_, mlPresent := sdb.modificationLog[h]
	if biPresent != mlPresent {
		t.Fatalf("R38-P1-05: torn undo state after Write failure — beforeImages[%d] present=%v, "+
			"modificationLog[%d] present=%v (must agree)", h, biPresent, h, mlPresent)
	}
	if !biPresent {
		t.Fatalf("R38-P1-05: undo for height %d was dropped on Write failure — must be preserved for retry", h)
	}
}
