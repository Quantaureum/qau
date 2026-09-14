// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// TestR87_EmptyCommitsDoNotChangeRoot verifies that an empty block does not
// mutate the derived state root. Empty blocks apply no state change, so the
// root must remain constant across a long sequence of empty commits.
func TestR87_EmptyCommitsDoNotChangeRoot(t *testing.T) {
	alice := types.BytesToAddress([]byte{0xa1})

	sdb := state.NewStateDB()
	sdb.SetBalance(alice, big.NewInt(1_000_000))
	if _, err := sdb.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}
	baseline := sdb.Root()

	// Simulate a long run of empty blocks. The range must exceed
	// pruneKeepBlocks (default 128) because PruneState is a no-op below that
	// threshold.
	seen := map[types.Hash][]uint64{}
	for h := uint64(2); h <= 260; h++ {
		root, err := sdb.CommitWithBlock(h)
		if err != nil {
			t.Fatalf("CommitWithBlock(%d): %v", h, err)
		}
		seen[root] = append(seen[root], h)
	}

	if len(seen) != 1 {
		t.Fatalf("R87: %d DIFFERENT state roots across 39 EMPTY commits "+
			"(baseline=%x). An empty block must not change the root:\n  %v",
			len(seen), baseline[:8], seen)
	}
	for root := range seen {
		if root != baseline {
			t.Fatalf("R87: empty commits moved the root away from the baseline: "+
				"baseline=%x got=%x", baseline[:8], root[:8])
		}
	}
}
