// Quantaureum Node source, version 1.0.0.
// Package economics — R3-09 deposit release tests.
//
// Verifies that once a DepositLocker is wired, GovernanceManager releases the
// reservation when a proposal reaches a terminal state (rejected or executed).
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func newGovernanceWithLocker(t *testing.T) (*GovernanceManager, *mockDepositLocker) {
	t.Helper()
	gm := NewGovernanceManager(DefaultGovernanceConfig())
	t.Cleanup(gm.Close)
	locker := newMockDepositLocker()
	gm.SetDepositLocker(locker)
	return gm, locker
}

func createTestProposal(t *testing.T, gm *GovernanceManager, proposer types.Address, nonce uint64) *Proposal {
	t.Helper()
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	changes := []ParameterChange{{Parameter: "InflationRate", NewValue: "500"}}
	proposal, err := gm.CreateProposal(
		proposer,
		ProposalTypeParameter,
		"title",
		"description",
		changes,
		deposit,
		100,
		big.NewInt(1000),
		nonce,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	return proposal
}

func TestGOV_R3_09_DepositReleasedOnRejectedFinalize(t *testing.T) {
	gm, locker := newGovernanceWithLocker(t)
	proposer := types.BytesToAddress([]byte{0x21})
	proposal := createTestProposal(t, gm, proposer, 1)

	if err := gm.FinalizeProposal(proposal.ID, big.NewInt(1000), proposal.EndHeight); err != nil {
		t.Fatalf("FinalizeProposal: %v", err)
	}

	stored, err := gm.GetProposal(proposal.ID)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	if stored.Status != ProposalStatusRejected {
		t.Fatalf("proposal status = %v, want rejected", stored.Status)
	}
	if got := locker.UnlockCount(); got != 1 {
		t.Fatalf("UnlockDeposit calls = %d, want 1", got)
	}
	if got := locker.TotalUnlocked(); got.Cmp(proposal.Deposit) != 0 {
		t.Fatalf("unlocked amount = %s, want %s", got, proposal.Deposit)
	}
}

func TestGOV_R3_09_DepositReleasedOnExecution(t *testing.T) {
	gm, locker := newGovernanceWithLocker(t)
	cfg := gm.GetConfig()

	sq := newMockStakeQuerier()
	voter := types.BytesToAddress([]byte{0x22})
	sq.stakes[voter] = big.NewInt(1000)
	gm.SetStakeQuerier(sq)

	proposer := types.BytesToAddress([]byte{0x23})
	sq.stakes[proposer] = new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	proposal := createTestProposal(t, gm, proposer, 1)

	if err := gm.Vote(proposal.ID, voter, VoteOptionYes, big.NewInt(1000), proposal.StartHeight); err != nil {
		t.Fatalf("Vote: %v", err)
	}
	if err := gm.FinalizeProposal(proposal.ID, big.NewInt(1000), proposal.EndHeight); err != nil {
		t.Fatalf("FinalizeProposal: %v", err)
	}
	stored, err := gm.GetProposal(proposal.ID)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	if stored.Status != ProposalStatusPassed {
		t.Fatalf("proposal status = %v, want passed", stored.Status)
	}
	if got := locker.UnlockCount(); got != 0 {
		t.Fatalf("a passed proposal must keep its deposit reserved, unlock calls = %d", got)
	}

	if err := gm.ExecuteProposal(proposal.ID, proposal.EndHeight+cfg.ExecutionDelay); err != nil {
		t.Fatalf("ExecuteProposal: %v", err)
	}
	stored, err = gm.GetProposal(proposal.ID)
	if err != nil {
		t.Fatalf("GetProposal after execute: %v", err)
	}
	if stored.Status != ProposalStatusExecuted {
		t.Fatalf("proposal status = %v, want executed", stored.Status)
	}
	if got := locker.UnlockCount(); got != 1 {
		t.Fatalf("UnlockDeposit calls after execution = %d, want 1", got)
	}
	if got := locker.TotalUnlocked(); got.Cmp(proposal.Deposit) != 0 {
		t.Fatalf("unlocked amount = %s, want %s", got, proposal.Deposit)
	}
}

func TestGOV_R3_09_ReleaseIsIdempotentAcrossEviction(t *testing.T) {
	gm, locker := newGovernanceWithLocker(t)
	proposer := types.BytesToAddress([]byte{0x24})
	proposal := createTestProposal(t, gm, proposer, 1)

	if err := gm.FinalizeProposal(proposal.ID, big.NewInt(1000), proposal.EndHeight); err != nil {
		t.Fatalf("FinalizeProposal: %v", err)
	}
	// evictOldProposals runs on the next ExecuteProposal and must not
	// double-release an already released reservation.
	gm.mu.Lock()
	gm.evictOldProposals()
	gm.mu.Unlock()

	if got := locker.UnlockCount(); got != 1 {
		t.Fatalf("UnlockDeposit calls = %d, want 1 (idempotent)", got)
	}
}
