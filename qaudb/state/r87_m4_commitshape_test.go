// Quantaureum Node source, version 1.0.0.
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// R87-M4-ROOTCAUSE: the decisive experiment for the long-standing
// "state root mismatch" WARN (M4 / R63-STATE-ROOT-TRUST).
//
// The two code paths are NOT symmetric in how many times they commit:
//
//	proposer  (node/block_producer.go buildBlock)
//	  execute txs
//	  if len(txs) > 0 { CommitWithBlock(h) }   <-- :2598, return value DISCARDED
//	  apply epoch rewards (epoch-boundary blocks only)
//	  CommitWithBlock(h)                       <-- :2729, root stamped into header
//
//	validator (node/syncer.go applyBlockInternal)
//	  execute txs
//	  apply epoch rewards
//	  CommitWithBlock(h)                       <-- exactly once
//
// So on a block that carries transactions the proposer commits height h TWICE
// while every validator commits it ONCE. Devnet matched this precisely: the
// first mismatch on the diverged chain was at block 24 — the first block with a
// transaction — and its header root (07d7a2d5) differed from what the same
// node's own syncer recomputed (47b23121), while blocks 25-27 (empty) carried
// headers equal to the syncer's value.
//
// These tests compare the two commit shapes directly. Any divergence is a
// consensus-level defect: the proposer stamps a root no validator can reproduce.
func TestR87M4_DoubleCommitWithInterleavedWriteMatchesSingleCommit(t *testing.T) {
	// Addresses chosen so the "tx" set and the "reward" set overlap partially,
	// which is the real shape: the coinbase collects gas fees during execution
	// AND may receive an epoch reward.
	sender := types.BytesToAddress([]byte{0x51})
	recipient := types.BytesToAddress([]byte{0x52})
	coinbase := types.BytesToAddress([]byte{0xc0})
	otherValidator := types.BytesToAddress([]byte{0xc1})

	// seed applies the identical pre-block-h state to a fresh StateDB.
	seed := func(s *StateDB) {
		s.SetBalance(sender, big.NewInt(1_000_000))
		s.SetBalance(coinbase, big.NewInt(5_000))
		s.SetBalance(otherValidator, big.NewInt(7_000))
		if _, err := s.CommitWithBlock(23); err != nil {
			t.Fatalf("seed CommitWithBlock(23): %v", err)
		}
	}
	// txWrites is what the executor does for one transfer plus gas to coinbase.
	txWrites := func(s *StateDB) {
		s.SetBalance(sender, big.NewInt(1_000_000-1_000-21))
		if err := s.AddBalance(recipient, big.NewInt(1_000)); err != nil {
			t.Fatalf("AddBalance(recipient): %v", err)
		}
		if err := s.AddBalance(coinbase, big.NewInt(21)); err != nil {
			t.Fatalf("AddBalance(coinbase): %v", err)
		}
		s.SetNonce(sender, 1)
	}
	// rewardWrites is what applyEpochRewards does on an epoch-boundary block.
	rewardWrites := func(s *StateDB) {
		if err := s.AddBalance(coinbase, big.NewInt(500)); err != nil {
			t.Fatalf("AddBalance(coinbase) reward: %v", err)
		}
		if err := s.AddBalance(otherValidator, big.NewInt(300)); err != nil {
			t.Fatalf("AddBalance(otherValidator) reward: %v", err)
		}
	}

	// --- Proposer shape: commit(h), then rewards, then commit(h) again.
	proposer := NewStateDB()
	seed(proposer)
	txWrites(proposer)
	firstRoot, err := proposer.CommitWithBlock(24)
	if err != nil {
		t.Fatalf("proposer first CommitWithBlock(24): %v", err)
	}
	rewardWrites(proposer)
	proposerRoot, err := proposer.CommitWithBlock(24)
	if err != nil {
		t.Fatalf("proposer second CommitWithBlock(24): %v", err)
	}

	// --- Validator shape: txs and rewards, then a single commit(h).
	validator := NewStateDB()
	seed(validator)
	txWrites(validator)
	rewardWrites(validator)
	validatorRoot, err := validator.CommitWithBlock(24)
	if err != nil {
		t.Fatalf("validator CommitWithBlock(24): %v", err)
	}

	// Balances must agree regardless of commit shape.
	for _, c := range []struct {
		name string
		addr types.Address
		want int64
	}{
		{"sender", sender, 1_000_000 - 1_000 - 21},
		{"recipient", recipient, 1_000},
		{"coinbase", coinbase, 5_000 + 21 + 500},
		{"otherValidator", otherValidator, 7_000 + 300},
	} {
		p := proposer.GetBalance(c.addr)
		v := validator.GetBalance(c.addr)
		if p.Cmp(v) != 0 || p.Cmp(big.NewInt(c.want)) != 0 {
			t.Errorf("%s: proposer=%s validator=%s want=%d", c.name, p, v, c.want)
		}
	}

	if proposerRoot != validatorRoot {
		t.Fatalf("R87-M4 ROOT CAUSE CONFIRMED: the proposer's extra CommitWithBlock(h) "+
			"before applying epoch rewards changes the stamped root.\n"+
			"  proposer  (commit, rewards, commit) = %x\n"+
			"  validator (txs+rewards, commit)     = %x\n"+
			"  proposer's discarded first root     = %x\n"+
			"Balances are identical, so this is purely a commit-shape artifact: the "+
			"proposer stamps a header root that NO validator can reproduce.",
			proposerRoot[:12], validatorRoot[:12], firstRoot[:12])
	}
}

// TestR87M4_DoubleCommitNoRewardsMatchesSingleCommit isolates the non-boundary
// case: transactions only, no interleaved write between the two commits. This
// is the common block shape, so if it diverged EVERY tx block would mismatch.
func TestR87M4_DoubleCommitNoRewardsMatchesSingleCommit(t *testing.T) {
	sender := types.BytesToAddress([]byte{0x51})
	recipient := types.BytesToAddress([]byte{0x52})

	build := func(double bool) types.Hash {
		s := NewStateDB()
		s.SetBalance(sender, big.NewInt(1_000_000))
		if _, err := s.CommitWithBlock(23); err != nil {
			t.Fatalf("CommitWithBlock(23): %v", err)
		}
		s.SetBalance(sender, big.NewInt(999_000))
		if err := s.AddBalance(recipient, big.NewInt(1_000)); err != nil {
			t.Fatalf("AddBalance: %v", err)
		}
		s.SetNonce(sender, 1)
		root, err := s.CommitWithBlock(24)
		if err != nil {
			t.Fatalf("CommitWithBlock(24): %v", err)
		}
		if double {
			root, err = s.CommitWithBlock(24)
			if err != nil {
				t.Fatalf("second CommitWithBlock(24): %v", err)
			}
		}
		return root
	}

	if got, want := build(true), build(false); got != want {
		t.Fatalf("R87-M4: committing height 24 twice with no interleaved write "+
			"yields %x, single commit yields %x — every transaction-carrying block "+
			"would mismatch on every validator", got[:12], want[:12])
	}
}
