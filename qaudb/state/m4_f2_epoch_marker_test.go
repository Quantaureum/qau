// M4-F2 regression: epoch-reward idempotency markers must be durable only
// together with the balances they certify, and must be dropped when the
// recorded block is rolled back (those blocks will be re-executed).
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// TestM4F2_MarkerDurableOnlyWithCommit verifies the marker lands in the same
// batch as the account writes: invisible before Commit, visible (and
// surviving a restart) after it.
func TestM4F2_MarkerDurableOnlyWithCommit(t *testing.T) {
	shared := db.NewMemDB()
	sdb := NewStateDB(shared)
	addr := types.Address{0x33}

	sdb.SetBalance(addr, big.NewInt(1000))
	sdb.MarkEpochRewardPending(1, 32)

	// Pending marks are process-local; a second instance over the same DB
	// models "before the commit became durable".
	pre := NewStateDB(shared)
	if pre.EpochRewardApplied(1) {
		t.Fatal("M4-F2: a staged (uncommitted) marker must not be durable")
	}

	if _, err := sdb.CommitWithBlock(32); err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	if !sdb.EpochRewardApplied(1) {
		t.Fatal("M4-F2: marker missing after a successful commit")
	}

	post := NewStateDB(shared)
	if !post.EpochRewardApplied(1) {
		t.Fatal("M4-F2: marker did not survive a restart")
	}
}

// TestM4F2_RollbackDropsMarker verifies a rollback past the marker's block
// height removes both the staged and the durable marker, so the re-executed
// boundary block pays its rewards again exactly once.
func TestM4F2_RollbackDropsMarker(t *testing.T) {
	shared := db.NewMemDB()
	sdb := NewStateDB(shared)
	addr := types.Address{0x44}

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

	if err := sdb.RollbackToHeight(32); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if sdb.EpochRewardApplied(1) {
		t.Fatal("M4-F2: marker survived the rollback — the re-executed block would skip its rewards")
	}

	reopened := NewStateDB(shared)
	if reopened.EpochRewardApplied(1) {
		t.Fatal("M4-F2: rolled-back marker resurrected after restart")
	}
}
