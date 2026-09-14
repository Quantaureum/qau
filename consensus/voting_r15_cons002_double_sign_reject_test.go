// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// CONS-R15-002 (2026-07-22): VoteCollector.AddVote must REJECT (not accept)
// a vote when the DoubleSignDetector flags it as cross-block equivocation.
// Previously the vote was stored and counted toward quorum even after
// detecting double-sign — an equivocating validator's second vote could
// help reach finality with tainted stake.

func TestCONS_R15_002_DoubleSign_RejectedNotCounted(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddGenesisValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}

	detector := NewDoubleSignDetector()
	blockA := types.Hash{0x01}
	blockB := types.Hash{0x02}
	vcA := NewVoteCollector(100, 0, blockA, vmgr)
	vcA.SetDoubleSignDetector(detector)
	vcB := NewVoteCollector(100, 0, blockB, vmgr)
	vcB.SetDoubleSignDetector(detector)

	// First vote for block A — accepted.
	voteA := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockA, ValidatorAddr: addr}
	if err := voteA.Sign(privKey); err != nil {
		t.Fatalf("voteA.Sign: %v", err)
	}
	if err := vcA.AddVote(voteA); err != nil {
		t.Fatalf("vcA.AddVote(voteA): %v", err)
	}

	// Equivocating vote for block B — must be REJECTED.
	voteB := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockB, ValidatorAddr: addr}
	if err := voteB.Sign(privKey); err != nil {
		t.Fatalf("voteB.Sign: %v", err)
	}
	err := vcB.AddVote(voteB)
	if !errors.Is(err, ErrDoubleSign) {
		t.Fatalf("expected ErrDoubleSign, got %v", err)
	}

	// The rejected vote must NOT be in vcB's votes map.
	if vcB.HasVoted(addr) {
		t.Error("equivocating vote should NOT be stored in vcB.votes")
	}

	// vcB's votedStake must remain zero (vote was not counted).
	// HasQuorum should be false with zero voted stake.
	if vcB.HasQuorum() {
		t.Error("vcB should NOT have quorum with rejected vote")
	}

	// Evidence should still be generated for slashing.
	evidence := detector.GetEvidence()
	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence entry, got %d", len(evidence))
	}
	if evidence[0].Reason != SlashingReasonDoubleSigning {
		t.Errorf("evidence reason: want %v, got %v", SlashingReasonDoubleSigning, evidence[0].Reason)
	}
}

func TestCONS_R15_002_DuplicateVote_AcceptedInNewCollector(t *testing.T) {
	// When the same vote (same block hash) was already recorded by the
	// detector (e.g. forwarded by FinalityTracker), a new VoteCollector
	// for the SAME block should still accept it. ErrDuplicateVote from
	// the detector is benign and must NOT cause rejection.
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddGenesisValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}

	detector := NewDoubleSignDetector()
	blockA := types.Hash{0x01}
	vcA := NewVoteCollector(100, 0, blockA, vmgr)
	vcA.SetDoubleSignDetector(detector)
	vcA2 := NewVoteCollector(100, 0, blockA, vmgr) // same block, different collector
	vcA2.SetDoubleSignDetector(detector)

	voteA := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockA, ValidatorAddr: addr}
	if err := voteA.Sign(privKey); err != nil {
		t.Fatalf("voteA.Sign: %v", err)
	}

	// First collector accepts and records in detector.
	if err := vcA.AddVote(voteA); err != nil {
		t.Fatalf("vcA.AddVote: %v", err)
	}

	// Second collector for same block — detector returns ErrDuplicateVote
	// (same vote already seen), but vcA2 should still accept the vote
	// because it's the first time THIS collector sees it.
	if err := vcA2.AddVote(voteA); err != nil {
		t.Fatalf("vcA2.AddVote should accept duplicate-vote (same block), got %v", err)
	}
	if !vcA2.HasVoted(addr) {
		t.Error("vcA2 should have the vote recorded")
	}
}
