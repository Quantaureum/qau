// Quantaureum Node source, version 1.0.0.
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestEmptyBlockCopyPreservesFullTrie reproduces the block-producer path:
//  1. seed N genesis accounts, Commit -> root0 (full trie)
//  2. Copy() (as block builder does)
//  3. Commit() the copy with NO changes (empty block) -> root1
//
// Invariant: root1 MUST equal root0 (an empty block commits nothing; the trie
// still holds ALL accounts). If root1 != root0 or root1 == f(only one account),
// the trie is being reset per block -> the "stateRoot = f(proposer)" bug.
func TestEmptyBlockCopyPreservesFullTrie(t *testing.T) {
	sdb := NewStateDB()
	// 10 genesis accounts with distinct balances.
	var addrs []types.Address
	for i := 0; i < 10; i++ {
		a := types.BytesToAddress([]byte{byte(i + 1)})
		addrs = append(addrs, a)
		sdb.SetBalance(a, big.NewInt(int64(1000+i*100)))
	}

	root0, err := sdb.Commit(0)
	if err != nil {
		t.Fatalf("initial Commit: %v", err)
	}
	t.Logf("root0 (full 10-account trie) = %x", root0[:])

	// Block builder: stateDB.Copy()
	builder := sdb.Copy()
	root1, err := builder.Commit(1) // empty block, no state change
	if err != nil {
		t.Fatalf("builder Commit(empty): %v", err)
	}
	t.Logf("root1 (empty block commit on copy) = %x", root1[:])

	if root0 != root1 {
		t.Errorf("EMPTY-BLOCK BUG: empty commit changed root %x -> %x (trie reset?)", root0[:], root1[:])
	}

	// Sanity: a real change must change the root.
	builder2 := sdb.Copy()
	builder2.AddBalance(addrs[0], big.NewInt(500))
	root2, err := builder2.Commit(2)
	if err != nil {
		t.Fatalf("builder Commit(change): %v", err)
	}
	t.Logf("root2 (after +500 to acc0) = %x", root2[:])
	if root0 == root2 {
		t.Errorf("state not accumulating: balance change did not alter root")
	}
}
