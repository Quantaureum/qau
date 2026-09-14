// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// R87-STATEROOT-COPY: reproduce the production "state root mismatch" WARN that
// fires on essentially EVERY block on a live devnet (186/260/161 occurrences in
// ~190 blocks across three nodes).
//
// The existing TestStateRootE2E_NoDoubleHexEncoding does NOT cover the real
// topology: it takes Copy() BEFORE any commit, so both sides commit an
// identical dirty set from an identical empty baseline and trivially agree.
//
// The real proposer/validator topology is:
//
//  1. both nodes already hold committed state for block h-1 (a baseline)
//  2. the PROPOSER builds on stateDB.Copy() (see block_producer.go
//     blockBuildState), applies block h, CommitWithBlock(h) -> header.StateRoot
//  3. the VALIDATOR applies the same block h to its MAIN stateDB and
//     CommitWithBlock(h) -> compared against header.StateRoot
//
// Step 2 vs step 3 is the only asymmetry in the system, so if the roots differ
// here, that asymmetry is the root cause of the production WARN.
func TestR87_ProposerCopyRootMatchesValidatorMainRoot(t *testing.T) {
	alice := types.BytesToAddress([]byte{0xa1})
	bob := types.BytesToAddress([]byte{0xb0})

	// --- Baseline: block 1 committed identically on both nodes. ---
	proposerDB := state.NewStateDB()
	validatorDB := state.NewStateDB()
	for _, sdb := range []*state.StateDB{proposerDB, validatorDB} {
		sdb.SetBalance(alice, big.NewInt(1_000_000))
		if _, err := sdb.CommitWithBlock(1); err != nil {
			t.Fatalf("baseline CommitWithBlock(1): %v", err)
		}
	}
	baseP, baseV := proposerDB.Root(), validatorDB.Root()
	if baseP != baseV {
		t.Fatalf("baseline roots already differ: proposer=%x validator=%x", baseP[:8], baseV[:8])
	}

	// --- Block 2: alice -> bob, applied on BOTH sides identically. ---
	// Proposer builds on an isolated Copy() (block_producer.go topology).
	buildState := proposerDB.Copy()
	applyTransfer(t, buildState, alice, bob, big.NewInt(1_234))
	producerRoot, err := buildState.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("proposer CommitWithBlock(2): %v", err)
	}

	// Validator applies to its main stateDB (syncer.applyBlockInternal topology).
	applyTransfer(t, validatorDB, alice, bob, big.NewInt(1_234))
	validatorRoot, err := validatorDB.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("validator CommitWithBlock(2): %v", err)
	}

	if producerRoot != validatorRoot {
		t.Fatalf("R87: proposer (built on Copy) and validator (main stateDB) "+
			"derived DIFFERENT state roots for an identical block:\n"+
			"  proposer  = %x\n  validator = %x\n"+
			"This is the production 'state root mismatch' WARN: the header root "+
			"comes from the Copy() path, every peer recomputes on its main "+
			"stateDB, so every block mismatches.",
			producerRoot[:], validatorRoot[:])
	}
}

// TestR87_EmptyBlockOnCopyKeepsBaselineRoot pins the empty-block case: applying
// no state changes must leave the root exactly at the baseline on BOTH the
// Copy() path and the main-stateDB path. On the live devnet three consecutive
// empty blocks (25/26/27) all carried header root 47b23121… while peers
// computed a different value, so the empty path is affected too.
func TestR87_EmptyBlockOnCopyKeepsBaselineRoot(t *testing.T) {
	alice := types.BytesToAddress([]byte{0xa1})

	sdb := state.NewStateDB()
	sdb.SetBalance(alice, big.NewInt(500))
	if _, err := sdb.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}
	baseline := sdb.Root()

	// Proposer: empty block on an isolated copy.
	buildState := sdb.Copy()
	producerRoot, err := buildState.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("proposer CommitWithBlock(2): %v", err)
	}

	// Validator: empty block on the main stateDB.
	validatorRoot, err := sdb.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("validator CommitWithBlock(2): %v", err)
	}

	if producerRoot != baseline {
		t.Errorf("R87: empty block on Copy() changed the root: baseline=%x got=%x",
			baseline[:8], producerRoot[:8])
	}
	if validatorRoot != baseline {
		t.Errorf("R87: empty block on main stateDB changed the root: baseline=%x got=%x",
			baseline[:8], validatorRoot[:8])
	}
	if producerRoot != validatorRoot {
		t.Errorf("R87: empty-block roots differ: proposer=%x validator=%x",
			producerRoot[:8], validatorRoot[:8])
	}
}

// applyTransfer mirrors what the tx executor does to state for a plain
// transfer: debit sender, credit recipient, bump sender nonce.
func applyTransfer(t *testing.T, sdb *state.StateDB, from, to types.Address, amount *big.Int) {
	t.Helper()
	fromBal := sdb.GetBalance(from)
	if fromBal.Cmp(amount) < 0 {
		t.Fatalf("applyTransfer: insufficient balance %s < %s", fromBal, amount)
	}
	sdb.SetBalance(from, new(big.Int).Sub(fromBal, amount))
	if err := sdb.AddBalance(to, amount); err != nil {
		t.Fatalf("AddBalance(to): %v", err)
	}
	sdb.SetNonce(from, sdb.GetNonce(from)+1)
}
