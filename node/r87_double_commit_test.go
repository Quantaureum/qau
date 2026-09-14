// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// TestR87_DoubleCommitSameHeightKeepsRoot pins the asymmetry between the two
// production paths:
//
//	proposer (block_producer.go buildBlock):
//	    ... execute txs ...
//	    stateDB.CommitWithBlock(h)        <- line ~2587, return value DISCARDED
//	    ... epoch rewards ...
//	    stateRoot = stateDB.CommitWithBlock(h)  <- line ~2713, goes into header
//
//	validator (syncer.go applyBlockInternal):
//	    ... execute txs ... applyEpochRewards ...
//	    stateRoot = stateDB.CommitWithBlock(h)  <- committed exactly ONCE
//
// The proposer therefore commits height h TWICE and stamps the second root into
// the header, while every validator commits once and compares against the first
// root. If CommitWithBlock is not idempotent for an unchanged dirty set, every
// block mismatches — which is exactly what the devnet shows.
func TestR87_DoubleCommitSameHeightKeepsRoot(t *testing.T) {
	alice := types.BytesToAddress([]byte{0xa1})
	bob := types.BytesToAddress([]byte{0xb0})

	sdb := state.NewStateDB()
	sdb.SetBalance(alice, big.NewInt(1_000_000))
	if _, err := sdb.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	// Apply block 2's state changes.
	sdb.SetBalance(alice, big.NewInt(1_000_000-77))
	if err := sdb.AddBalance(bob, big.NewInt(77)); err != nil {
		t.Fatalf("AddBalance: %v", err)
	}
	sdb.SetNonce(alice, 1)

	first, err := sdb.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("first CommitWithBlock(2): %v", err)
	}
	second, err := sdb.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("second CommitWithBlock(2): %v", err)
	}

	if first != second {
		t.Fatalf("R87: CommitWithBlock(2) is NOT idempotent — committing the same "+
			"height twice yields a different root:\n"+
			"  1st (what validators compute) = %x\n"+
			"  2nd (what the proposer stamps into the header) = %x\n"+
			"The proposer commits twice (block_producer.go ~2587 and ~2713) while "+
			"the syncer commits once, so EVERY block mismatches.",
			first[:], second[:])
	}
}
