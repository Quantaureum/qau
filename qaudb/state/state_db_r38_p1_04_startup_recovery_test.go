// Quantaureum Node source, version 1.0.0.
// Package state —R38-P1-04 regression tests.
//
// AUDIT (2026) R38-P1-04: Storage —NewStateDB panics when
// RecoverConsistency fails, but the panic path does not expose the error to
// callers that want to retry or investigate. Worse, RecoverConsistency's
// root-mismatch branch deleted the commit-pending marker before returning,
// so the next startup would SKIP the rebuild (no marker) and silently
// continue with a divergent state root —exactly the consensus-fork risk
// R32-P2-05 was built to prevent.
//
// The fix:
//  1. Add OpenStateDB(database) (*StateDB, error) that propagates the
//     recovery error instead of panicking, for production startup code.
//     NewStateDB keeps its legacy panic-on-error contract for existing
//     tests and node.go (migrated separately).
//  2. RecoverConsistency's root-mismatch branch PRESERVES the marker so
//     the next startup re-enters the rebuild/verify path and gets a fresh
//     chance after the operator has investigated/restored a backup.
//
// These tests verify:
//  1. OpenStateDB returns (nil, error) —not a panic —on root mismatch.
//  2. The marker is preserved after a mismatch so a second OpenStateDB
//     call on the same DB re-enters RecoverConsistency (retry path).
//  3. OpenStateDB returns (*StateDB, nil) on the happy path (matching root).
//  4. RecoverConsistency directly preserves the marker on mismatch.
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// seedRootMismatchDB builds a MemDB in the exact state that triggers the
// RecoverConsistency root-mismatch branch:
//   - one account is committed (so lastCommittedRootKey holds the correct root)
//   - lastCommittedRootKey is then corrupted so it disagrees with the rebuilt root
//   - commitPendingKey is written so RecoverConsistency enters the rebuild path
//
// It returns the MemDB and the persisted (correct) root bytes for assertions.
func seedRootMismatchDB(t *testing.T) (memdb db.Database, correctRootBytes []byte) {
	t.Helper()
	memDB := db.NewMemDB()
	s := NewStateDB(memDB)

	addr := testAddr(0x17)
	acc := NewAccount()
	acc.Balance = big.NewInt(1000)
	s.SetAccount(addr, acc)
	if _, err := s.Commit(); err != nil {
		t.Fatalf("seed: Commit failed: %v", err)
	}

	correctRootBytes, err := memDB.Get(lastCommittedRootKey)
	if err != nil || len(correctRootBytes) != types.HashLength {
		t.Fatalf("seed: lastCommittedRootKey missing or wrong length: %v len=%d", err, len(correctRootBytes))
	}

	corrupted := make([]byte, len(correctRootBytes))
	copy(corrupted, correctRootBytes)
	corrupted[0] ^= 0xFF
	if err := memDB.Put(lastCommittedRootKey, corrupted); err != nil {
		t.Fatalf("seed: failed to corrupt lastCommittedRootKey: %v", err)
	}
	if err := memDB.Put(commitPendingKey, []byte{1}); err != nil {
		t.Fatalf("seed: failed to write commit-pending marker: %v", err)
	}
	return memDB, correctRootBytes
}

// markerExists returns true if the commit-pending marker is still in the DB.
func markerExists(t *testing.T, database db.Database, label string) bool {
	t.Helper()
	v, err := database.Get(commitPendingKey)
	if err == db.ErrKeyNotFound {
		return false
	}
	if err != nil {
		t.Fatalf("markerExists(%s): unexpected Get error: %v", label, err)
	}
	_ = v
	return true
}

// TestR38P1_04_OpenStateDB_FailsOnRecoveryMismatch verifies OpenStateDB
// returns (nil, error) —NOT a panic —when the rebuilt Verkle root does not
// match the persisted last-committed root. This is the production-friendly
// counterpart to NewStateDB's panic path.
func TestR38P1_04_OpenStateDB_FailsOnRecoveryMismatch(t *testing.T) {
	memDB, _ := seedRootMismatchDB(t)

	sdb, err := OpenStateDB(memDB)
	if err == nil {
		t.Fatalf("R38-P1-04 NOT FIXED: OpenStateDB returned (sdb=%v, nil) despite "+
			"rebuilt root mismatching lastCommittedRoot —should fail-closed "+
			"to prevent consensus fork from a wrong state root", sdb)
	}
	if sdb != nil {
		t.Fatalf("R38-P1-04: OpenStateDB should return nil StateDB on error, got non-nil")
	}
}

// TestR38P1_04_OpenStateDB_PreservesCommitMarkerForRetry verifies that after
// a mismatch, the commit-pending marker is STILL in the DB, so a second
// OpenStateDB call re-enters RecoverConsistency (the retry path). The pre-fix
// code deleted the marker before returning the error, so the next startup
// would skip the rebuild and silently accept the wrong root.
func TestR38P1_04_OpenStateDB_PreservesCommitMarkerForRetry(t *testing.T) {
	memDB, _ := seedRootMismatchDB(t)

	_, _ = OpenStateDB(memDB) // expect error; we don't care about its value here

	if !markerExists(t, memDB, "after-first-OpenStateDB") {
		t.Fatalf("R38-P1-04 NOT FIXED: commit-pending marker was deleted after a " +
			"root mismatch —the next startup would skip the rebuild and " +
			"silently accept a divergent state root")
	}

	// A second OpenStateDB on the same DB must STILL enter the recovery path
	// (i.e., still see the marker and still fail-closed). If the marker had
	// been deleted, the second call would return (sdb, nil) and we'd lose
	// the only signal that the on-disk state is corrupt.
	sdb2, err2 := OpenStateDB(memDB)
	if err2 == nil {
		t.Fatalf("R38-P1-04: second OpenStateDB should still fail-closed because "+
			"the marker (and the mismatch) are still present, got (sdb=%v, nil)", sdb2)
	}
	if sdb2 != nil {
		t.Fatalf("R38-P1-04: second OpenStateDB should return nil StateDB on error, got non-nil")
	}
	if !markerExists(t, memDB, "after-second-OpenStateDB") {
		t.Fatalf("R38-P1-04: marker disappeared after second OpenStateDB —" +
			"recovery must be idempotent and preserve the retry marker")
	}
}

// TestR38P1_04_OpenStateDB_SuccessOnMatchingRoot verifies the happy path:
// when the rebuilt Verkle root matches the persisted last-committed root,
// OpenStateDB returns (*StateDB, nil). This guards against an over-strict
// fix that would reject legitimate recoveries.
func TestR38P1_04_OpenStateDB_SuccessOnMatchingRoot(t *testing.T) {
	memDB := db.NewMemDB()
	s := NewStateDB(memDB)

	addr := testAddr(0x29)
	acc := NewAccount()
	acc.Balance = big.NewInt(42)
	s.SetAccount(addr, acc)
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Simulate a crash after batch.Write but before the Verkle update:
	// the account data + lastCommittedRootKey are present, and we add the
	// marker so OpenStateDB enters the rebuild path on a fresh instance.
	if err := memDB.Put(commitPendingKey, []byte{1}); err != nil {
		t.Fatalf("failed to write commit-pending marker: %v", err)
	}

	sdb, err := OpenStateDB(memDB)
	if err != nil {
		t.Fatalf("R38-P1-04: OpenStateDB should succeed on matching root, got error: %v", err)
	}
	if sdb == nil {
		t.Fatal("R38-P1-04: OpenStateDB returned (nil, nil) on matching root")
	}
	// After a successful recovery the marker must be cleared.
	if markerExists(t, memDB, "after-successful-OpenStateDB") {
		t.Fatalf("R38-P1-04: marker should be cleared after a successful recovery")
	}
}

// TestR38P1_04_RecoverConsistency_PreservesMarkerOnMismatch directly exercises
// RecoverConsistency (not OpenStateDB) and asserts the marker survives the
// mismatch. This covers callers that already hold a StateDB and invoke
// recovery directly (e.g., the R32-P2-05 test pattern).
func TestR38P1_04_RecoverConsistency_PreservesMarkerOnMismatch(t *testing.T) {
	memDB := db.NewMemDB()
	s := NewStateDB(memDB)

	addr := testAddr(0x31)
	acc := NewAccount()
	acc.Balance = big.NewInt(7000)
	s.SetAccount(addr, acc)
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	correctRootBytes, err := memDB.Get(lastCommittedRootKey)
	if err != nil || len(correctRootBytes) != types.HashLength {
		t.Fatalf("lastCommittedRootKey missing or wrong length: %v len=%d", err, len(correctRootBytes))
	}
	corrupted := make([]byte, len(correctRootBytes))
	copy(corrupted, correctRootBytes)
	corrupted[0] ^= 0xFF
	if err := memDB.Put(lastCommittedRootKey, corrupted); err != nil {
		t.Fatalf("failed to corrupt lastCommittedRootKey: %v", err)
	}
	if err := memDB.Put(commitPendingKey, []byte{1}); err != nil {
		t.Fatalf("failed to write commit-pending marker: %v", err)
	}

	// First RecoverConsistency (inside NewStateDB) was a no-op (no marker
	// at construction time). This direct call hits the mismatch branch.
	if err := s.RecoverConsistency(); err == nil {
		t.Fatalf("R38-P1-04 NOT FIXED: RecoverConsistency returned nil despite " +
			"rebuilt root mismatching lastCommittedRoot —should fail-closed")
	}

	if !markerExists(t, memDB, "after-RecoverConsistency-mismatch") {
		t.Fatalf("R38-P1-04 NOT FIXED: RecoverConsistency deleted the commit-pending " +
			"marker on root mismatch —the next startup would skip the rebuild " +
			"and silently accept a divergent state root")
	}
}
