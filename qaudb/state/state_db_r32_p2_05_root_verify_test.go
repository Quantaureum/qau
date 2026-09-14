// Quantaureum Node source, version 1.0.0.
// Package state — R32-P2-05 regression tests.
//
// AUDIT (2026) R32-P2-05: Storage — RecoverConsistency() rebuilds the
// Verkle tree from BoltDB account state but does NOT verify the rebuilt
// root matches the last committed root. If the rebuild silently produced
// a wrong tree (e.g., a Put failed mid-iteration, or BoltDB data was
// corrupted), the node would continue with a wrong state root, causing
// a consensus fork.
//
// The fix:
//  1. Commit() persists the last-known-good state root to lastCommittedRootKey
//     after a fully successful commit (batch.Write + Verkle update + marker clear).
//  2. RecoverConsistency() reads lastCommittedRootKey and compares it with
//     the rebuilt tree's root. If they differ, returns an error (fail-closed).
//  3. If lastCommittedRootKey is missing (first run or persist failed),
//     the check is skipped — it's defense-in-depth, not a correctness requirement.
//
// These tests verify:
//  1. Commit() persists lastCommittedRootKey
//  2. RecoverConsistency succeeds when rebuilt root matches persisted root
//  3. RecoverConsistency fails (fail-closed) when rebuilt root does NOT match
//  4. RecoverConsistency skips the check when lastCommittedRootKey is missing
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// TestR32_P2_05_Commit_PersistsLastCommittedRoot verifies that a successful
// Commit writes the last-known-good state root to lastCommittedRootKey.
// RecoverConsistency reads this key to verify the rebuilt tree.
func TestR32_P2_05_Commit_PersistsLastCommittedRoot(t *testing.T) {
	memDB := db.NewMemDB()
	s := NewStateDB(memDB)

	addr := testAddr(0x42)
	acc := NewAccount()
	acc.Balance = big.NewInt(1000)
	s.SetAccount(addr, acc)

	root, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// R32-P2-05: lastCommittedRootKey should now exist with the root value.
	persistedBytes, err := memDB.Get(lastCommittedRootKey)
	if err != nil {
		t.Fatalf("R32-P2-05 NOT FIXED: lastCommittedRootKey not persisted after successful Commit: %v", err)
	}
	if len(persistedBytes) != types.HashLength {
		t.Fatalf("R32-P2-05: lastCommittedRootKey has wrong length: got %d, want %d",
			len(persistedBytes), types.HashLength)
	}
	var persistedRoot types.Hash
	copy(persistedRoot[:], persistedBytes)
	if persistedRoot != root {
		t.Fatalf("R32-P2-05: persisted root %x != committed root %x",
			persistedRoot, root)
	}
}

// TestR32_P2_05_RecoverConsistency_MatchingRoot_Succeeds verifies that
// RecoverConsistency succeeds when the rebuilt Verkle root matches the
// persisted last-committed root. This is the normal crash-recovery path.
func TestR32_P2_05_RecoverConsistency_MatchingRoot_Succeeds(t *testing.T) {
	memDB := db.NewMemDB()
	s := NewStateDB(memDB)

	// Commit some state → persists lastCommittedRootKey.
	addr := testAddr(0x99)
	acc := NewAccount()
	acc.Balance = big.NewInt(5000)
	acc.Nonce = 7
	s.SetAccount(addr, acc)
	expectedRoot, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Simulate a crash: write commit-pending marker (as if batch.Write
	// succeeded but Verkle Put didn't complete).
	if err := memDB.Put(commitPendingKey, []byte{1}); err != nil {
		t.Fatalf("failed to write commit-pending marker: %v", err)
	}

	// Create a NEW StateDB — RecoverConsistency should rebuild and verify.
	s2 := NewStateDB(memDB)

	// RecoverConsistency should succeed because the rebuilt root matches
	// the persisted lastCommittedRoot.
	if err := s2.RecoverConsistency(); err != nil {
		t.Fatalf("R32-P2-05: RecoverConsistency failed with matching root: %v", err)
	}

	// The rebuilt root should match the original committed root.
	if actualRoot := s2.Root(); actualRoot != expectedRoot {
		t.Errorf("R32-P2-05: rebuilt root %s != expected root %s",
			actualRoot, expectedRoot)
	}
}

// TestR32_P2_05_RecoverConsistency_MismatchedRoot_Fails is the KEY regression
// test. It verifies that RecoverConsistency returns an error (fail-closed)
// when the rebuilt Verkle root does NOT match the persisted last-committed
// root. This is the exact scenario R32-P2-05 addresses: a silent rebuild
// producing a wrong tree.
//
// Without the fix, RecoverConsistency would silently return nil and the node
// would continue with a wrong state root, causing a consensus fork.
//
// Test strategy: Commit some state (persists correct root), then corrupt
// lastCommittedRootKey by writing a different root value. RecoverConsistency
// rebuilds the tree from BoltDB (producing the correct root), then compares
// with the corrupted persisted root → mismatch → error.
//
// Note: We call RecoverConsistency on the SAME StateDB instance (not a new
// one) because NewStateDB calls RecoverConsistency internally in its
// constructor and swallows the error. By reusing the existing instance,
// the first RecoverConsistency (in NewStateDB) was a no-op (no marker), and
// the second call (after we corrupt the data) directly tests the fix.
func TestR32_P2_05_RecoverConsistency_MismatchedRoot_Fails(t *testing.T) {
	memDB := db.NewMemDB()
	s := NewStateDB(memDB)

	// Commit account → persists correct root to lastCommittedRootKey.
	addr := testAddr(0x01)
	acc := NewAccount()
	acc.Balance = big.NewInt(1000)
	s.SetAccount(addr, acc)
	_, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Read the correct persisted root.
	correctRootBytes, err := memDB.Get(lastCommittedRootKey)
	if err != nil {
		t.Fatalf("lastCommittedRootKey not found: %v", err)
	}

	// Corrupt lastCommittedRootKey by flipping the first byte.
	// This simulates: BoltDB data corruption, or a Put that failed mid-iteration
	// producing a different root, or any scenario where the rebuilt root
	// doesn't match the last known good root.
	corruptedRootBytes := make([]byte, len(correctRootBytes))
	copy(corruptedRootBytes, correctRootBytes)
	corruptedRootBytes[0] ^= 0xFF // flip all bits of first byte
	if err := memDB.Put(lastCommittedRootKey, corruptedRootBytes); err != nil {
		t.Fatalf("failed to corrupt lastCommittedRootKey: %v", err)
	}

	// Verify the corruption took effect.
	persistedAfter, _ := memDB.Get(lastCommittedRootKey)
	if persistedAfter[0] == correctRootBytes[0] {
		t.Fatal("corruption did not take effect — first byte unchanged")
	}

	// Write commit-pending marker to trigger rebuild.
	if err := memDB.Put(commitPendingKey, []byte{1}); err != nil {
		t.Fatalf("failed to write commit-pending marker: %v", err)
	}

	// R32-P2-05: RecoverConsistency MUST fail because the rebuilt root
	// (correct, from BoltDB account data) does NOT match the corrupted
	// persisted lastCommittedRoot.
	err = s.RecoverConsistency()
	if err == nil {
		t.Fatal("R32-P2-05 NOT FIXED: RecoverConsistency returned nil despite " +
			"rebuilt root mismatching lastCommittedRoot — should fail-closed " +
			"to prevent consensus fork from wrong state root")
	}
}

// TestR32_P2_05_RecoverConsistency_NoPersistedRoot_SkipsCheck verifies that
// RecoverConsistency skips the root comparison when lastCommittedRootKey is
// missing (first run, or the P2-05 persist failed). This is the graceful
// degradation path — the root check is defense-in-depth, not a correctness
// requirement, so if there's no reference to compare against, we proceed.
func TestR32_P2_05_RecoverConsistency_NoPersistedRoot_SkipsCheck(t *testing.T) {
	memDB := db.NewMemDB()

	// Manually write an account to BoltDB (bypassing Commit, so no
	// lastCommittedRootKey is written).
	addr := testAddr(0x50)
	acc := NewAccount()
	acc.Balance = big.NewInt(777)
	accBytes, _ := serializeAccount(acc)
	_ = memDB.Put(append(accountPrefix, addr[:]...), accBytes)

	// Write commit-pending marker to trigger rebuild.
	if err := memDB.Put(commitPendingKey, []byte{1}); err != nil {
		t.Fatalf("failed to write commit-pending marker: %v", err)
	}

	// Verify lastCommittedRootKey does NOT exist.
	if _, err := memDB.Get(lastCommittedRootKey); err == nil {
		t.Fatal("lastCommittedRootKey should not exist before any Commit")
	}

	// Create a NEW StateDB — RecoverConsistency should succeed (skip check).
	s2 := NewStateDB(memDB)
	if err := s2.RecoverConsistency(); err != nil {
		t.Fatalf("R32-P2-05: RecoverConsistency should skip root check when "+
			"lastCommittedRootKey is missing, got error: %v", err)
	}
}

// TestR32_P2_05_RecoverConsistency_MultipleCommits_UsesLatestRoot verifies
// that after multiple commits, lastCommittedRootKey holds the LATEST root
// (not the first). This ensures RecoverConsistency compares against the
// most recent state, not a stale one.
func TestR32_P2_05_RecoverConsistency_MultipleCommits_UsesLatestRoot(t *testing.T) {
	memDB := db.NewMemDB()
	s := NewStateDB(memDB)

	// Commit three times with different accounts.
	for i := byte(1); i <= 3; i++ {
		addr := testAddr(i)
		acc := NewAccount()
		acc.Balance = big.NewInt(int64(i) * 1000)
		s.SetAccount(addr, acc)
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit %d failed: %v", i, err)
		}
	}

	// The persisted root should match the LAST commit's root.
	finalRoot := s.Root()
	persistedBytes, err := memDB.Get(lastCommittedRootKey)
	if err != nil {
		t.Fatalf("lastCommittedRootKey not found: %v", err)
	}
	var persistedRoot types.Hash
	copy(persistedRoot[:], persistedBytes)
	if persistedRoot != finalRoot {
		t.Fatalf("R32-P2-05: persisted root %x != final root %x "+
			"(should hold the LATEST committed root)",
			persistedRoot, finalRoot)
	}
}
