// Quantaureum Node source, version 1.0.0.
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// R87-ROLLBACK-ROOT: after a fork rollback the state root MUST return to the
// exact historical root, otherwise the node keeps producing/validating against
// a state that no peer shares — every subsequent block mismatches and the
// divergence is permanent.
//
// Rollback correctness is the primary invariant because every later state
// transition is derived from the restored state.
func TestR87_RollbackRestoresHistoricalRoot(t *testing.T) {
	alice := types.BytesToAddress([]byte{0xa1})
	bob := types.BytesToAddress([]byte{0xb0})

	sdb := NewStateDB()

	// Block 1: fund alice.
	sdb.SetBalance(alice, big.NewInt(1000))
	root1, err := sdb.CommitWithBlock(1)
	if err != nil {
		t.Fatalf("CommitWithBlock(1): %v", err)
	}

	// Block 2: alice -> bob 100.
	sdb.SetBalance(alice, big.NewInt(900))
	if err := sdb.AddBalance(bob, big.NewInt(100)); err != nil {
		t.Fatalf("AddBalance(bob): %v", err)
	}
	root2, err := sdb.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("CommitWithBlock(2): %v", err)
	}

	// Block 3: alice -> bob 100 again.
	sdb.SetBalance(alice, big.NewInt(800))
	if err := sdb.AddBalance(bob, big.NewInt(100)); err != nil {
		t.Fatalf("AddBalance(bob): %v", err)
	}
	root3, err := sdb.CommitWithBlock(3)
	if err != nil {
		t.Fatalf("CommitWithBlock(3): %v", err)
	}

	if root1 == root2 || root2 == root3 {
		t.Fatalf("test setup broken: roots not distinct (%x %x %x)", root1[:8], root2[:8], root3[:8])
	}

	// Roll back block 3 — the state must become exactly the post-block-2 state.
	if err := sdb.RollbackToHeight(3); err != nil {
		t.Fatalf("RollbackToHeight(3): %v", err)
	}
	if got := sdb.GetBalance(alice); got.Cmp(big.NewInt(900)) != 0 {
		t.Errorf("R87: after rollback alice balance = %s, want 900", got)
	}
	if got := sdb.GetBalance(bob); got.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("R87: after rollback bob balance = %s, want 100", got)
	}
	if got := sdb.Root(); got != root2 {
		t.Errorf("R87: after RollbackToHeight(3) the state root is %x, want the "+
			"post-block-2 root %x. A rollback that restores balances but NOT the "+
			"root leaves the node permanently diverged: every later block it "+
			"validates or produces carries a root no peer agrees with.",
			got[:8], root2[:8])
	}
}

// TestR87_RollbackThenReapplyMatchesStraightLine is the fork-recovery shape:
// a node applies a branch, rolls it back, then applies the canonical block at
// the same height. Its final root must equal what a node that only ever saw
// the canonical chain computes.
func TestR87_RollbackThenReapplyMatchesStraightLine(t *testing.T) {
	alice := types.BytesToAddress([]byte{0xa1})
	bob := types.BytesToAddress([]byte{0xb0})
	carol := types.BytesToAddress([]byte{0xc0})

	// Reference node: only ever sees the canonical block 2 (alice -> carol).
	ref := NewStateDB()
	ref.SetBalance(alice, big.NewInt(1000))
	if _, err := ref.CommitWithBlock(1); err != nil {
		t.Fatalf("ref CommitWithBlock(1): %v", err)
	}
	ref.SetBalance(alice, big.NewInt(700))
	if err := ref.AddBalance(carol, big.NewInt(300)); err != nil {
		t.Fatalf("ref AddBalance: %v", err)
	}
	refRoot, err := ref.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("ref CommitWithBlock(2): %v", err)
	}

	// Forked node: applies the losing block 2 (alice -> bob), rolls it back,
	// then applies the canonical block 2.
	fork := NewStateDB()
	fork.SetBalance(alice, big.NewInt(1000))
	if _, err := fork.CommitWithBlock(1); err != nil {
		t.Fatalf("fork CommitWithBlock(1): %v", err)
	}
	fork.SetBalance(alice, big.NewInt(500))
	if err := fork.AddBalance(bob, big.NewInt(500)); err != nil {
		t.Fatalf("fork AddBalance(bob): %v", err)
	}
	if _, err := fork.CommitWithBlock(2); err != nil {
		t.Fatalf("fork CommitWithBlock(2) losing branch: %v", err)
	}
	if err := fork.RollbackToHeight(2); err != nil {
		t.Fatalf("fork RollbackToHeight(2): %v", err)
	}
	fork.SetBalance(alice, big.NewInt(700))
	if err := fork.AddBalance(carol, big.NewInt(300)); err != nil {
		t.Fatalf("fork AddBalance(carol): %v", err)
	}
	forkRoot, err := fork.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("fork CommitWithBlock(2) canonical: %v", err)
	}

	if forkRoot != refRoot {
		t.Fatalf("R87: a node that forked and recovered derived root %x while a "+
			"node that only saw the canonical chain derived %x — fork recovery "+
			"leaves permanent state divergence (bob=%s should be 0 after rollback).",
			forkRoot[:8], refRoot[:8], fork.GetBalance(bob))
	}
	if got := fork.GetBalance(bob); got.Sign() != 0 {
		t.Errorf("R87: bob still holds %s after the losing branch was rolled back", got)
	}
}
