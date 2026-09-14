// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// TestR87_RootIndependentOfInsertionOrder: StateDB.Commit iterates
// s.dirtyAccounts with `for addr, acc := range` — Go randomizes map iteration
// order, so the Verkle tree receives the same accounts in a DIFFERENT order on
// every node (and on every run). If the derived root depends on insertion
// order, two nodes holding IDENTICAL account state derive DIFFERENT roots.
func TestR87_RootIndependentOfInsertionOrder(t *testing.T) {
	addrs := make([]types.Address, 24)
	for i := range addrs {
		addrs[i] = types.BytesToAddress([]byte{byte(i + 1), 0xAA, byte(0xF0 - i)})
	}

	roots := make(map[types.Hash]int)
	for run := 0; run < 12; run++ {
		sdb := state.NewStateDB()
		for i, a := range addrs {
			sdb.SetBalance(a, big.NewInt(int64(1000+i)))
			sdb.SetNonce(a, uint64(i))
		}
		root, err := sdb.CommitWithBlock(1)
		if err != nil {
			t.Fatalf("run %d CommitWithBlock: %v", run, err)
		}
		roots[root]++
	}
	if len(roots) != 1 {
		t.Fatalf("R87: identical account state produced %d DIFFERENT state roots "+
			"across 12 runs — the root depends on Go map iteration order:\n  %v",
			len(roots), roots)
	}
}
