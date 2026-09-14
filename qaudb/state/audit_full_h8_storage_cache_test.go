// Quantaureum Node source, version 1.0.0.
package state

// AUDIT-FULL H-8 (2026-08-14) regression tests.
//
// Bug: in Commit's storage-only path (account has dirty storage but is NOT
// in dirtyAccounts), the code mutated `acc.StorageRoot` in place on the
// pointer returned by getAccountLocked — which points INTO the account
// cache — BEFORE batch.Write(). If the write failed, the cache held a
// StorageRoot that was never persisted (cache/DB inconsistency).
//
// Fix: copy the account, mutate the copy, and defer the cache replacement
// to the post-write pendingCache loop (same pattern as R40-P2-02).
//
// Tests:
//  1. Failed batch.Write → cached account's StorageRoot unchanged.
//  2. Successful commit → cached account's StorageRoot IS updated.

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

func TestAuditFullH8_FailedCommitLeavesStorageRootCacheIntact(t *testing.T) {
	underlying := db.NewMemDB()
	sdb := NewStateDB(underlying)

	addr := testAddr(0x71)

	// Create and durably commit the account so it exists and is cached.
	sdb.SetBalance(addr, big.NewInt(42))
	if _, err := sdb.Commit(1); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	// Prime the account cache and capture the committed StorageRoot.
	accBefore, err := sdb.GetAccount(addr)
	if err != nil {
		t.Fatalf("GetAccount failed: %v", err)
	}
	rootBefore := accBefore.StorageRoot

	// Now swap in a DB whose batch.Write always fails.
	failing := &failingBatchDB{
		Database:     underlying,
		writeFailure: errors.New("simulated batch.Write failure (AUDIT-FULL H-8)"),
	}
	sdb.mu.Lock()
	sdb.db = failing
	sdb.mu.Unlock()

	// Storage-only modification: dirtyStorage gets an entry, dirtyAccounts
	// does not — this drives the exact path fixed by H-8.
	key := types.Hash{0x0a}
	val := types.Hash{0x0b}
	sdb.SetStorage(addr, key, val)

	if _, err := sdb.Commit(2); err == nil {
		t.Fatal("expected Commit to fail with injected batch.Write failure")
	}

	// The cached account must still carry the OLD StorageRoot.
	sdb.mu.RLock()
	cached, ok := sdb.accountCache[addr]
	sdb.mu.RUnlock()
	if !ok {
		t.Fatal("account missing from cache after failed commit")
	}
	if cached.StorageRoot != rootBefore {
		t.Fatalf("AUDIT-FULL H-8 NOT FIXED: cache StorageRoot mutated before durable write (got %x, want old %x)",
			cached.StorageRoot, rootBefore)
	}
}

func TestAuditFullH8_SuccessfulCommitUpdatesStorageRootCache(t *testing.T) {
	sdb := NewStateDB(db.NewMemDB())

	addr := testAddr(0x72)

	sdb.SetBalance(addr, big.NewInt(7))
	if _, err := sdb.Commit(1); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	accBefore, err := sdb.GetAccount(addr)
	if err != nil {
		t.Fatalf("GetAccount failed: %v", err)
	}
	rootBefore := accBefore.StorageRoot

	// Storage-only modification.
	sdb.SetStorage(addr, types.Hash{0x0c}, types.Hash{0x0d})

	if _, err := sdb.Commit(2); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// After a SUCCESSFUL commit the cache must reflect the new root.
	accAfter, err := sdb.GetAccount(addr)
	if err != nil {
		t.Fatalf("GetAccount failed: %v", err)
	}
	if accAfter.StorageRoot == rootBefore {
		// A single storage slot changes the root in practice; if roots
		// happen to collide the test would be vacuous, so fail loudly.
		t.Fatalf("expected StorageRoot to change after committing a storage slot (both %x)", rootBefore)
	}

	// And the durable DB must agree with the cache (encode/decode roundtrip).
	sdb.mu.RLock()
	persisted, err := sdb.getAccountLocked(addr)
	sdb.mu.RUnlock()
	if err != nil {
		t.Fatalf("getAccountLocked failed: %v", err)
	}
	if persisted.StorageRoot != accAfter.StorageRoot {
		t.Fatalf("cache/DB mismatch: cached root %x != persisted root %x",
			accAfter.StorageRoot, persisted.StorageRoot)
	}
}
