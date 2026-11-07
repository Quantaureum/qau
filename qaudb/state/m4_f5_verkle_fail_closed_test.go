// M4-F5 regression: when the Verkle tree update fails AFTER the account
// batch is already durable, Commit must fail closed. Before the fix the code
// fell through to rootLocked() and persisted a root derived from a partially
// updated tree together with the committed height — a wrong root that every
// later block was then validated against.
package state

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
)

// TestM4F5_VerkleFailureFailsClosed asserts:
//   - CommitWithBlock returns ErrStateIndexUnavailable and a zero root (never
//     a root computed from the partially updated tree);
//   - the durable root and the committed height do NOT advance;
//   - the commit-pending marker stays so the next startup rebuilds the index;
//   - the dirty accounts stay staged so an in-process retry can heal.
func TestM4F5_VerkleFailureFailsClosed(t *testing.T) {
	memDB := db.NewMemDB()
	sdb := NewStateDB(memDB)
	addr := types.Address{0x55}

	sdb.SetBalance(addr, big.NewInt(100))
	root0, err := sdb.CommitWithBlock(0)
	if err != nil {
		t.Fatalf("baseline commit failed: %v", err)
	}

	// Swap in a Verkle tree whose persistent batches always fail.
	sdb.mu.Lock()
	sdb.stateTrie = trie.NewVerkleTree(256, &verkleFailDB{Database: db.NewMemDB()})
	sdb.mu.Unlock()

	sdb.SetBalance(addr, big.NewInt(200))
	root, err := sdb.CommitWithBlock(1)
	if err == nil {
		t.Fatal("M4-F5 NOT FIXED: CommitWithBlock returned nil after a Verkle update failure")
	}
	if !errors.Is(err, ErrStateIndexUnavailable) {
		t.Fatalf("M4-F5: expected ErrStateIndexUnavailable, got %v", err)
	}
	if root != (types.Hash{}) {
		t.Fatalf("M4-F5 NOT FIXED: Commit returned a non-zero root %x computed from a partially updated tree", root[:8])
	}

	if got := sdb.LastCommittedHeight(); got != 0 {
		t.Fatalf("M4-F5: lastCommittedHeight advanced to %d despite the index failure", got)
	}
	persisted, gerr := memDB.Get(lastCommittedRootKey)
	if gerr != nil || len(persisted) != types.HashLength {
		t.Fatalf("M4-F5: persisted last-committed root missing/corrupt after failed commit: %v", gerr)
	}
	var persistedRoot types.Hash
	copy(persistedRoot[:], persisted)
	if persistedRoot != root0 {
		t.Fatalf("M4-F5 NOT FIXED: persisted root changed to %x on a failed commit (want the previous %x)",
			persistedRoot[:8], root0[:8])
	}

	if marker, merr := memDB.Get(commitPendingKey); merr != nil || len(marker) == 0 {
		t.Fatalf("M4-F5: commit-pending marker must remain so the next startup rebuilds the Verkle tree (err=%v)", merr)
	}

	sdb.mu.RLock()
	dirty := len(sdb.dirtyAccounts)
	sdb.mu.RUnlock()
	if dirty == 0 {
		t.Fatal("M4-F5: dirty accounts were cleared despite the index failure — an in-process retry cannot heal the tree")
	}

	// Self-healing path: with a healthy tree the retry commits normally.
	sdb.mu.Lock()
	sdb.stateTrie = trie.NewVerkleTree(256, memDB)
	sdb.mu.Unlock()
	if _, err := sdb.CommitWithBlock(1); err != nil {
		t.Fatalf("healing commit failed: %v", err)
	}
	if got := sdb.LastCommittedHeight(); got != 1 {
		t.Fatalf("healing commit left lastCommittedHeight at %d, want 1", got)
	}
}
