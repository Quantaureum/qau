// M4-F3 regression: RollbackToHeight must not report success when the
// in-memory before-image history was lost across a restart but the durable
// state is still at or above the requested fork height.
//
// Before the fix the empty-beforeImages branch returned nil unconditionally,
// so a post-restart fork rollback was a silent no-op: the caller believed the
// state had been rewound while it still sat on the abandoned chain.
package state

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// TestM4F3_RollbackAfterRestartReturnsError reproduces the restart semantics:
// the same underlying DB is reopened, so beforeImages (in-memory only) is
// empty while `_last_committed_height_` is restored from disk. Requesting a
// rollback to that height must be refused explicitly.
func TestM4F3_RollbackAfterRestartReturnsError(t *testing.T) {
	shared := db.NewMemDB()
	addr := types.Address{0x11, 0x22}

	writer := NewStateDB(shared)
	writer.SetBalance(addr, big.NewInt(500))
	if _, err := writer.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline commit at height 1 failed: %v", err)
	}
	writer.SetBalance(addr, big.NewInt(900))
	if _, err := writer.CommitWithBlock(2); err != nil {
		t.Fatalf("baseline commit at height 2 failed: %v", err)
	}

	// Restart: a new instance over the same DB loses the in-memory undo log.
	restarted := NewStateDB(shared)
	if restarted.HasRollbackHistory() {
		t.Fatal("fixture broken: a restarted StateDB must not report rollback history")
	}
	if got := restarted.LastCommittedHeight(); got != 2 {
		t.Fatalf("restart must restore lastCommittedHeight from disk, got %d want 2", got)
	}

	err := restarted.RollbackToHeight(2)
	if err == nil {
		t.Fatal("M4-F3 NOT FIXED: RollbackToHeight(2) returned nil after a restart " +
			"even though the durable state is still at height 2 — the rollback was a silent no-op")
	}
	if !errors.Is(err, ErrRollbackHistoryUnavailable) {
		t.Fatalf("M4-F3: expected ErrRollbackHistoryUnavailable, got %v", err)
	}

	// A refused rollback must leave the state exactly where it was.
	if got := restarted.GetBalance(addr); got.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("refused rollback mutated the balance: got %s want 900", got)
	}
	if got := restarted.LastCommittedHeight(); got != 2 {
		t.Fatalf("refused rollback mutated lastCommittedHeight: got %d want 2", got)
	}
}

// TestM4F3_RollbackWithoutHistoryBelowCommittedHeightIsNoOp pins the other
// half of the guard: when the durable height is already below the target
// (fresh node, or rollback target below what was ever committed), there is
// genuinely nothing to undo and nil is the correct answer.
func TestM4F3_RollbackWithoutHistoryBelowCommittedHeightIsNoOp(t *testing.T) {
	fresh := NewStateDB(db.NewMemDB())
	if got := fresh.LastCommittedHeight(); got != 0 {
		t.Fatalf("fresh StateDB lastCommittedHeight = %d, want 0", got)
	}
	if err := fresh.RollbackToHeight(1); err != nil {
		t.Fatalf("rollback below the committed height must be a no-op, got %v", err)
	}
	if err := fresh.RollbackToHeight(0); err != nil {
		t.Fatalf("rollback to genesis must be a no-op, got %v", err)
	}
}
