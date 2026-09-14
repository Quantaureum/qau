// Quantaureum Node source, version 1.0.0.
package economics

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

type mockStakeQuerier struct {
	stakes map[types.Address]*big.Int
	err    error
}

// mockEmergencyHandler is a test implementation of EmergencyActionHandler.
// P1-T6 (2026-07-14): Used to verify GovernanceManager.ExecuteProposal
// correctly delegates Emergency-type proposals to the handler.
type mockEmergencyHandler struct {
	fn func(proposalID uint64, proposer types.Address, title, description string) error
}

func (m *mockEmergencyHandler) HandleEmergencyAction(proposalID uint64, proposer types.Address, title, description string) error {
	if m.fn != nil {
		return m.fn(proposalID, proposer, title, description)
	}
	return nil
}

func (m *mockStakeQuerier) GetStakeAmount(addr types.Address) (*big.Int, error) {
	if m.err != nil {
		return nil, m.err
	}
	if stake, ok := m.stakes[addr]; ok {
		return new(big.Int).Set(stake), nil
	}
	return big.NewInt(0), nil
}

// GetStakeAmountAtHeight implements StakeSnapshotQuerier.
// R35-P0-14 FIX: GovernanceManager.Vote() now requires StakeSnapshotQuerier
// (fail-closed). For tests that don't specifically test historical snapshot
// behavior, return the current stake as a best-effort approximation (same
// as the production stakeQuerierAdapter in node/node.go).
func (m *mockStakeQuerier) GetStakeAmountAtHeight(addr types.Address, height uint64) (*big.Int, error) {
	return m.GetStakeAmount(addr)
}

func newMockStakeQuerier() *mockStakeQuerier {
	return &mockStakeQuerier{stakes: make(map[types.Address]*big.Int)}
}

func TestGovernanceManager_Full(t *testing.T) {
	t.Run("DefaultGovernanceConfig", func(t *testing.T) {
		cfg := DefaultGovernanceConfig()
		if cfg.VotingPeriod == 0 {
			t.Error("VotingPeriod should not be 0")
		}
		if cfg.QuorumThreshold == 0 {
			t.Error("QuorumThreshold should not be 0")
		}
		if cfg.PassThreshold == 0 {
			t.Error("PassThreshold should not be 0")
		}
		if cfg.ProposalDeposit == nil {
			t.Error("ProposalDeposit should not be nil")
		}
	})

	t.Run("NewGovernanceManager_nilConfig", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()
		if gm == nil {
			t.Fatal("manager is nil")
		}
	})

	t.Run("Close", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		gm.Close()
		gm.Close() // double close should be safe
	})

	t.Run("SetStakeQuerier", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		sq := newMockStakeQuerier()
		gm.SetStakeQuerier(sq)

		if gm.stakeQuerier == nil {
			t.Error("stake querier should be set")
		}
	})

	t.Run("InitializeParameters", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		params := map[string]string{
			"inflation_rate": "50",
			"StakingAPY":     "50",
		}
		gm.InitializeParameters(params)

		v, exists := gm.GetParameter("inflation_rate")
		if !exists || v != "50" {
			t.Errorf("expected 50, got %s", v)
		}
	})

	t.Run("GetParameter_notFound", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		_, exists := gm.GetParameter("nonexistent")
		if exists {
			t.Error("should not exist")
		}
	})

	t.Run("SetParameter", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		err := gm.setParameter("MinStakeAmount", "42")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		v, exists := gm.GetParameter("MinStakeAmount")
		if !exists || v != "42" {
			t.Errorf("expected 42, got %s", v)
		}
	})

	t.Run("GetAllParameters_empty", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		params := gm.GetAllParameters()
		if len(params) != 0 {
			t.Errorf("expected 0, got %d", len(params))
		}
	})

	t.Run("GetAllParameters", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		gm.InitializeParameters(map[string]string{"a": "1", "b": "2"})
		params := gm.GetAllParameters()
		if len(params) != 2 {
			t.Errorf("expected 2, got %d", len(params))
		}
	})

	t.Run("GetConfig", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		cfg := gm.GetConfig()
		if cfg.VotingPeriod == 0 {
			t.Error("VotingPeriod should not be 0")
		}
	})

	t.Run("ProposalCount_empty", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		if gm.ProposalCount() != 0 {
			t.Errorf("expected 0, got %d", gm.ProposalCount())
		}
	})
}

func TestGovernanceManager_Proposals(t *testing.T) {
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

	t.Run("CreateProposal_insufficientDeposit", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		_, err := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "title", "desc", nil, big.NewInt(0), 100, nil, 43, nil)
		if err != ErrInsufficientVotePower {
			t.Errorf("expected ErrInsufficientVotePower, got %v", err)
		}
	})

	t.Run("CreateProposal_nilDeposit", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		_, err := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "title", "desc", nil, nil, 100, nil, 42, nil)
		if err != ErrInsufficientVotePower {
			t.Errorf("expected ErrInsufficientVotePower, got %v", err)
		}
	})

	t.Run("CreateProposal_parameterNoChanges", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		_, err := gm.CreateProposal(types.Address{1}, ProposalTypeParameter, "title", "desc", nil, deposit, 100, nil, 41, nil)
		if err != ErrInvalidParameter {
			t.Errorf("expected ErrInvalidParameter, got %v", err)
		}
	})

	t.Run("CreateProposal_parameterWithChanges", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		changes := []ParameterChange{
			{Parameter: "inflation_rate", OldValue: "80", NewValue: "50"},
		}
		proposal, err := gm.CreateProposal(types.Address{1}, ProposalTypeParameter, "title", "desc", changes, deposit, 100, nil, 40, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if proposal.ID != 1 {
			t.Errorf("expected ID 1, got %d", proposal.ID)
		}
		if proposal.Status != ProposalStatusActive {
			t.Errorf("expected active, got %d", proposal.Status)
		}
		if gm.ProposalCount() != 1 {
			t.Errorf("expected 1 proposal, got %d", gm.ProposalCount())
		}
	})

	t.Run("CreateProposal_upgrade", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		proposal, err := gm.CreateProposal(types.Address{2}, ProposalTypeUpgrade, "Upgrade v2", "Protocol upgrade", nil, deposit, 200, nil, 39, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if proposal.Type != ProposalTypeUpgrade {
			t.Errorf("expected upgrade type, got %d", proposal.Type)
		}
	})

	t.Run("CreateProposal_emergency", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		proposal, err := gm.CreateProposal(types.Address{3}, ProposalTypeEmergency, "Emergency", "Urgent fix", nil, deposit, 300, nil, 38, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if proposal.Type != ProposalTypeEmergency {
			t.Errorf("expected emergency type, got %d", proposal.Type)
		}
	})

	t.Run("GetProposal_notFound", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		_, err := gm.GetProposal(999)
		if err != ErrProposalNotFound {
			t.Errorf("expected ErrProposalNotFound, got %v", err)
		}
	})

	t.Run("GetProposal_found", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 37, nil)
		retrieved, err := gm.GetProposal(p.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved.ID != p.ID {
			t.Errorf("expected ID %d, got %d", p.ID, retrieved.ID)
		}
		if retrieved.YesVotes == nil {
			t.Error("YesVotes should not be nil (copy)")
		}
		// Verify deep copy
		retrieved.YesVotes.Set(big.NewInt(999))
		original, _ := gm.GetProposal(p.ID)
		if original.YesVotes.Cmp(big.NewInt(999)) == 0 {
			t.Error("modifying copy should not affect original")
		}
	})

	t.Run("GetActiveProposals_empty", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		active := gm.GetActiveProposals()
		if len(active) != 0 {
			t.Errorf("expected 0, got %d", len(active))
		}
	})

	t.Run("GetActiveProposals_withItems", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "P1", "D1", nil, deposit, 100, nil, 36, nil)
		gm.CreateProposal(types.Address{2}, ProposalTypeUpgrade, "P2", "D2", nil, deposit, 100, nil, 35, nil)

		active := gm.GetActiveProposals()
		if len(active) != 2 {
			t.Errorf("expected 2, got %d", len(active))
		}
	})

	t.Run("GetVote_notFound_proposal", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		_, err := gm.GetVote(999, types.Address{1})
		if err != ErrProposalNotFound {
			t.Errorf("expected ErrProposalNotFound, got %v", err)
		}
	})

	t.Run("GetVote_notFound_voter", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 34, nil)
		_, err := gm.GetVote(p.ID, types.Address{99})
		if err == nil {
			t.Error("expected error for vote not found")
		}
	})

	t.Run("ProposalCount_multiple", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "P1", "D", nil, deposit, 100, nil, 33, nil)
		gm.CreateProposal(types.Address{2}, ProposalTypeUpgrade, "P2", "D", nil, deposit, 100, nil, 32, nil)
		gm.CreateProposal(types.Address{3}, ProposalTypeUpgrade, "P3", "D", nil, deposit, 100, nil, 31, nil)

		if gm.ProposalCount() != 3 {
			t.Errorf("expected 3, got %d", gm.ProposalCount())
		}
	})
}

func TestGovernanceManager_Voting(t *testing.T) {
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

	setupGM := func() *GovernanceManager {
		gm := NewGovernanceManager(nil)
		sq := newMockStakeQuerier()
		sq.stakes[types.Address{1}] = new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
		sq.stakes[types.Address{2}] = new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
		sq.stakes[types.Address{3}] = new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		gm.SetStakeQuerier(sq)
		return gm
	}

	t.Run("Vote_proposalNotFound", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		err := gm.Vote(999, types.Address{1}, VoteOptionYes, big.NewInt(100), 100)
		if err != ErrProposalNotFound {
			t.Errorf("expected ErrProposalNotFound, got %v", err)
		}
	})

	t.Run("Vote_noStakeQuerier", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 30, nil)

		err := gm.Vote(p.ID, types.Address{1}, VoteOptionYes, big.NewInt(100), 100)
		if err == nil {
			t.Error("expected error for missing stake querier")
		}
	})

	t.Run("Vote_nilVotePower", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 29, nil)

		err := gm.Vote(p.ID, types.Address{1}, VoteOptionYes, nil, 100)
		if err != ErrInsufficientVotePower {
			t.Errorf("expected ErrInsufficientVotePower, got %v", err)
		}
	})

	t.Run("Vote_zeroVotePower", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 28, nil)

		err := gm.Vote(p.ID, types.Address{1}, VoteOptionYes, big.NewInt(0), 100)
		if err != ErrInsufficientVotePower {
			t.Errorf("expected ErrInsufficientVotePower, got %v", err)
		}
	})

	t.Run("Vote_proposalExpired", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		cfg := &GovernanceConfig{
			VotingPeriod:    300, // R25-017: >= MinVotingPeriodBlocks (300)
			QuorumThreshold: 3300,
			PassThreshold:   5000,
			ProposalDeposit: deposit,
			ExecutionDelay:  100,
		}
		gm2 := NewGovernanceManager(cfg)
		defer gm2.Close()
		sq := newMockStakeQuerier()
		// FIX: increase proposer stake to meet the ProposalDeposit
		// requirement (M-10 fix). Previously was 1000, but deposit is
		// 100 * 10^18, so CreateProposal returned nil → p.ID panicked.
		sq.stakes[types.Address{1}] = deposit
		gm2.SetStakeQuerier(sq)

		p, err := gm2.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 1, nil, 27, nil)
		if err != nil {
			t.Fatalf("CreateProposal failed: %v", err)
		}

		err = gm2.Vote(p.ID, types.Address{1}, VoteOptionYes, big.NewInt(100), 400)
		if err != ErrProposalExpired {
			t.Errorf("expected ErrProposalExpired, got %v", err)
		}
	})

	t.Run("CreateProposal_minVotingPeriod", func(t *testing.T) {
		// R25-017: CreateProposal must reject a config whose VotingPeriod is
		// below MinVotingPeriodBlocks (governance rushing attack prevention).
		shortCfg := &GovernanceConfig{
			VotingPeriod:    MinVotingPeriodBlocks - 1,
			QuorumThreshold: 3300,
			PassThreshold:   5000,
			ProposalDeposit: deposit,
			ExecutionDelay:  100,
		}
		gms := NewGovernanceManager(shortCfg)
		defer gms.Close()
		sq := newMockStakeQuerier()
		sq.stakes[types.Address{1}] = deposit
		gms.SetStakeQuerier(sq)

		_, err := gms.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 1, nil, 26, nil)
		if err == nil {
			t.Fatalf("expected error for voting period below minimum, got nil")
		}
	})

	t.Run("Vote_yes", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 25, nil)

		votePower := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		err := gm.Vote(p.ID, types.Address{1}, VoteOptionYes, votePower, 110)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		proposal, _ := gm.GetProposal(p.ID)
		if proposal.YesVotes.Cmp(votePower) != 0 {
			t.Errorf("expected %s yes votes, got %s", votePower, proposal.YesVotes)
		}

		vote, err := gm.GetVote(p.ID, types.Address{1})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vote.Option != VoteOptionYes {
			t.Errorf("expected VoteOptionYes, got %d", vote.Option)
		}
	})

	t.Run("Vote_no", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 24, nil)

		votePower := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
		err := gm.Vote(p.ID, types.Address{2}, VoteOptionNo, votePower, 110)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		proposal, _ := gm.GetProposal(p.ID)
		if proposal.NoVotes.Cmp(votePower) != 0 {
			t.Errorf("expected %s no votes, got %s", votePower, proposal.NoVotes)
		}
	})

	t.Run("Vote_abstain", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 23, nil)

		votePower := new(big.Int).Mul(big.NewInt(30), big.NewInt(1e18))
		err := gm.Vote(p.ID, types.Address{3}, VoteOptionAbstain, votePower, 110)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		proposal, _ := gm.GetProposal(p.ID)
		if proposal.AbstainVotes.Cmp(votePower) != 0 {
			t.Errorf("expected %s abstain votes, got %s", votePower, proposal.AbstainVotes)
		}
	})

	t.Run("Vote_alreadyVoted", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 22, nil)

		gm.Vote(p.ID, types.Address{1}, VoteOptionYes, big.NewInt(100), 110)
		err := gm.Vote(p.ID, types.Address{1}, VoteOptionNo, big.NewInt(100), 120)
		if err != ErrAlreadyVoted {
			t.Errorf("expected ErrAlreadyVoted, got %v", err)
		}
	})

	t.Run("Vote_votePowerExceedsStake", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 21, nil)

		// voter {1} has 1000e18 stake, try voting with 2000e18
		votePower := new(big.Int).Mul(big.NewInt(2000), big.NewInt(1e18))
		err := gm.Vote(p.ID, types.Address{1}, VoteOptionYes, votePower, 110)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should be clamped to actual stake (1000e18)
		proposal, _ := gm.GetProposal(p.ID)
		expected := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
		if proposal.YesVotes.Cmp(expected) != 0 {
			t.Errorf("expected %s clamped votes, got %s", expected, proposal.YesVotes)
		}

		// Vote power adjustments should be recorded
		adj := gm.GetVotePowerAdjustments()
		if len(adj) != 1 {
			t.Errorf("expected 1 adjustment, got %d", len(adj))
		}
		if adj[0].ProposalID != p.ID {
			t.Errorf("expected proposal %d, got %d", p.ID, adj[0].ProposalID)
		}

		adjForProp := gm.GetVotePowerAdjustmentsForProposal(p.ID)
		if len(adjForProp) != 1 {
			t.Errorf("expected 1 adjustment for proposal, got %d", len(adjForProp))
		}

		adjForVoter := gm.GetVotePowerAdjustmentsForVoter(types.Address{1})
		if len(adjForVoter) != 1 {
			t.Errorf("expected 1 adjustment for voter, got %d", len(adjForVoter))
		}
	})

	t.Run("Vote_voterNotStaked", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 20, nil)

		err := gm.Vote(p.ID, types.Address{99}, VoteOptionYes, big.NewInt(100), 110)
		if err != ErrInsufficientVotePower {
			t.Errorf("expected ErrInsufficientVotePower, got %v", err)
		}
	})

	t.Run("Vote_exactStake", func(t *testing.T) {
		gm := setupGM()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 19, nil)

		exactStake := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
		err := gm.Vote(p.ID, types.Address{1}, VoteOptionYes, exactStake, 110)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		adj := gm.GetVotePowerAdjustments()
		if len(adj) != 0 {
			t.Errorf("expected 0 adjustments when power equals stake, got %d", len(adj))
		}
	})
}

func TestGovernanceManager_Finalize(t *testing.T) {
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

	setup := func() (*GovernanceManager, *mockStakeQuerier) {
		gm := NewGovernanceManager(nil)
		sq := newMockStakeQuerier()
		sq.stakes[types.Address{1}] = new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
		sq.stakes[types.Address{2}] = new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
		sq.stakes[types.Address{3}] = new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		gm.SetStakeQuerier(sq)
		return gm, sq
	}

	t.Run("Finalize_notFound", func(t *testing.T) {
		gm, _ := setup()
		defer gm.Close()

		err := gm.FinalizeProposal(999, big.NewInt(1000), 100)
		if err != ErrProposalNotFound {
			t.Errorf("expected ErrProposalNotFound, got %v", err)
		}
	})

	t.Run("Finalize_votingNotEnded", func(t *testing.T) {
		gm, _ := setup()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 18, nil)
		err := gm.FinalizeProposal(p.ID, big.NewInt(1000), 100)
		if err == nil {
			t.Error("expected error for voting not ended")
		}
	})

	t.Run("Finalize_notActive", func(t *testing.T) {
		gm, _ := setup()
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 17, nil)
		p.Status = ProposalStatusPassed
		gm.proposals[p.ID] = p

		err := gm.FinalizeProposal(p.ID, big.NewInt(1000), p.EndHeight+1)
		if err != ErrProposalNotActive {
			t.Errorf("expected ErrProposalNotActive, got %v", err)
		}
	})

	t.Run("Finalize_passed", func(t *testing.T) {
		gm, sq := setup()
		defer gm.Close()

		votingPeriod := DefaultGovernanceConfig().VotingPeriod
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 16, nil)

		// Vote yes with sufficient power to pass
		gm.Vote(p.ID, types.Address{1}, VoteOptionYes, sq.stakes[types.Address{1}], 110)
		gm.Vote(p.ID, types.Address{2}, VoteOptionYes, sq.stakes[types.Address{2}], 110)

		totalVP := new(big.Int).Add(sq.stakes[types.Address{1}], sq.stakes[types.Address{2}])
		totalVP.Add(totalVP, sq.stakes[types.Address{3}])

		err := gm.FinalizeProposal(p.ID, totalVP, 100+votingPeriod+1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		proposal, _ := gm.GetProposal(p.ID)
		if proposal.Status != ProposalStatusPassed {
			t.Errorf("expected passed, got %d", proposal.Status)
		}
	})

	t.Run("Finalize_rejected_quorum", func(t *testing.T) {
		gm, _ := setup()
		defer gm.Close()

		votingPeriod := DefaultGovernanceConfig().VotingPeriod
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 15, nil)

		smallStake := big.NewInt(100)
		gm.Vote(p.ID, types.Address{3}, VoteOptionYes, smallStake, 110)

		totalVP := new(big.Int).Mul(big.NewInt(100000), big.NewInt(1e18))
		err := gm.FinalizeProposal(p.ID, totalVP, 100+votingPeriod+1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		proposal, _ := gm.GetProposal(p.ID)
		if proposal.Status != ProposalStatusRejected {
			t.Errorf("expected rejected (quorum not met), got %d", proposal.Status)
		}
	})

	t.Run("Finalize_rejected_noYesVotes", func(t *testing.T) {
		gm, sq := setup()
		defer gm.Close()

		votingPeriod := DefaultGovernanceConfig().VotingPeriod
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 14, nil)

		// Vote no with all power
		gm.Vote(p.ID, types.Address{1}, VoteOptionNo, sq.stakes[types.Address{1}], 110)

		totalVP := sq.stakes[types.Address{1}]
		err := gm.FinalizeProposal(p.ID, totalVP, 100+votingPeriod+1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		proposal, _ := gm.GetProposal(p.ID)
		if proposal.Status != ProposalStatusRejected {
			t.Errorf("expected rejected (no yes votes), got %d", proposal.Status)
		}
	})

	t.Run("Finalize_votesExceedTotal", func(t *testing.T) {
		gm, sq := setup()
		defer gm.Close()

		votingPeriod := DefaultGovernanceConfig().VotingPeriod
		// L12-004 FIX: totalVotePower is snapshotted at proposal creation time.
		totalVP := new(big.Int).Add(sq.stakes[types.Address{1}], sq.stakes[types.Address{2}])
		totalVP.Add(totalVP, sq.stakes[types.Address{3}])
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, totalVP, 13, nil)

		gm.Vote(p.ID, types.Address{1}, VoteOptionYes, sq.stakes[types.Address{1}], 110)

		// L12-004 FIX: totalVotePower is snapshotted at creation time, so the
		// caller-supplied value of 1 is ignored. The snapshot (1600e18) exceeds
		// the vote (1000e18), so no "votes exceed total" error occurs.
		err := gm.FinalizeProposal(p.ID, big.NewInt(1), 100+votingPeriod+1)
		if err != nil {
			t.Errorf("expected no error with snapshot totalVotePower: %v", err)
		}
	})

	t.Run("Finalize_withoutStakeQuerier_cannotVote", func(t *testing.T) {
		// L6-005 fix: Without stakeQuerier, Vote() rejects all votes.
		// This means FinalizeProposal can never have votes > totalVotePower.
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 12, nil)

		// Vote should fail without stakeQuerier
		err := gm.Vote(p.ID, types.Address{1}, VoteOptionYes, big.NewInt(1000), 110)
		if err == nil {
			t.Error("expected error when voting without stakeQuerier")
		}
	})

	t.Run("Finalize_withStakeQuerier_cap", func(t *testing.T) {
		gm, sq := setup()
		defer gm.Close()

		votingPeriod := DefaultGovernanceConfig().VotingPeriod
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 11, nil)

		gm.Vote(p.ID, types.Address{1}, VoteOptionYes, sq.stakes[types.Address{1}], 110)

		// Pass inflated totalVotePower
		hugeTotal := new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)
		err := gm.FinalizeProposal(p.ID, hugeTotal, 100+votingPeriod+1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be rejected since staked votes alone can't meet quorum against huge total
	})
}

func TestGovernanceManager_Execute(t *testing.T) {
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

	t.Run("Execute_notFound", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		err := gm.ExecuteProposal(999, 100)
		if err != ErrProposalNotFound {
			t.Errorf("expected ErrProposalNotFound, got %v", err)
		}
	})

	t.Run("Execute_notPassed", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 10, nil)
		p.Status = ProposalStatusActive
		gm.proposals[p.ID] = p

		err := gm.ExecuteProposal(p.ID, 100)
		if err == nil {
			t.Error("expected error for not passed")
		}
	})

	t.Run("Execute_delayNotPassed", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 9, nil)
		p.Status = ProposalStatusPassed
		gm.proposals[p.ID] = p

		err := gm.ExecuteProposal(p.ID, p.EndHeight+1)
		if err == nil {
			t.Error("expected error for execution delay not passed")
		}
	})

	t.Run("Execute_parameterChange", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		changes := []ParameterChange{
			{Parameter: "inflation_rate", OldValue: "80", NewValue: "50"},
		}
		execDelay := DefaultGovernanceConfig().ExecutionDelay
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeParameter, "Change inflation", "Desc", changes, deposit, 100, nil, 8, nil)
		p.Status = ProposalStatusPassed
		gm.proposals[p.ID] = p

		err := gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		v, exists := gm.GetParameter("inflation_rate")
		if !exists || v != "50" {
			t.Errorf("expected 50, got %s (exists=%v)", v, exists)
		}

		proposal, _ := gm.GetProposal(p.ID)
		if proposal.Status != ProposalStatusExecuted {
			t.Errorf("expected executed, got %d", proposal.Status)
		}
	})

	t.Run("Execute_upgrade", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		execDelay := DefaultGovernanceConfig().ExecutionDelay
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Upgrade", "Desc", nil, deposit, 100, nil, 7, nil)
		p.Status = ProposalStatusPassed
		gm.proposals[p.ID] = p

		err := gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Execute_triggersEviction", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()
		// Set maxFinalizedProposals very low
		gm.maxFinalizedProposals = 3

		execDelay := DefaultGovernanceConfig().ExecutionDelay

		// Create and execute 5 proposals
		// R41-L3ECON-05 / R43-GOVSIG-01: nonce must be strictly monotonic
		// for each proposer within the loop. The loop's `i` (0..4) generates
		// nonces 1..5 which satisfy the strict-monotonic gate inside
		// CreateProposal for the same proposer types.Address{1}. Replace
		// any previously-patched static nonce (e.g. `6`) here.
		for i := 0; i < 5; i++ {
			p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Upgrade", "Desc", nil, deposit, 100, nil, uint64(i)+1, nil)
			p.Status = ProposalStatusPassed
			gm.proposals[p.ID] = p
			gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
		}

		// Oldest should have been evicted
		_, err := gm.GetProposal(1)
		if err != ErrProposalNotFound {
			t.Errorf("expected oldest proposal to be evicted, got err=%v", err)
		}
	})

	// P1-T6 (2026-07-14): Verify ExecuteProposal invokes the EmergencyActionHandler
	// for Emergency-type proposals, and does NOT invoke it for other types.
	t.Run("Execute_emergencyInvokesHandler", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		var handlerCalled bool
		var capturedID uint64
		var capturedTitle string
		var capturedProposer types.Address
		mockHandler := &mockEmergencyHandler{
			fn: func(id uint64, proposer types.Address, title, desc string) error {
				handlerCalled = true
				capturedID = id
				capturedTitle = title
				capturedProposer = proposer
				return nil
			},
		}
		gm.SetEmergencyActionHandler(mockHandler)

		execDelay := DefaultGovernanceConfig().ExecutionDelay
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeEmergency, "Emergency Halt", "Critical bug", nil, deposit, 100, nil, 5, nil)
		p.Status = ProposalStatusPassed
		gm.proposals[p.ID] = p

		err := gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !handlerCalled {
			t.Fatal("EmergencyActionHandler was not called for Emergency proposal")
		}
		if capturedID != p.ID {
			t.Errorf("handler proposalID = %d, want %d", capturedID, p.ID)
		}
		if capturedTitle != "Emergency Halt" {
			t.Errorf("handler title = %q, want %q", capturedTitle, "Emergency Halt")
		}
		// GOV-R7-09: Verify the real proposer is forwarded to the handler
		// so audit logs can attribute the emergency halt correctly.
		expectedProposer := types.Address{1}
		if capturedProposer != expectedProposer {
			t.Errorf("handler proposer = %x, want %x", capturedProposer[:4], expectedProposer[:4])
		}

		// Proposal should be marked Executed even if handler had an error (best-effort).
		proposal, _ := gm.GetProposal(p.ID)
		if proposal.Status != ProposalStatusExecuted {
			t.Errorf("expected Executed, got %d", proposal.Status)
		}
	})

	// P1-T6: Verify handler is NOT called for non-Emergency proposals.
	t.Run("Execute_nonEmergencyDoesNotInvokeHandler", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		var handlerCalled bool
		mockHandler := &mockEmergencyHandler{
			fn: func(id uint64, proposer types.Address, title, desc string) error {
				handlerCalled = true
				return nil
			},
		}
		gm.SetEmergencyActionHandler(mockHandler)

		execDelay := DefaultGovernanceConfig().ExecutionDelay
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Upgrade", "Desc", nil, deposit, 100, nil, 4, nil)
		p.Status = ProposalStatusPassed
		gm.proposals[p.ID] = p

		err := gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if handlerCalled {
			t.Fatal("EmergencyActionHandler should NOT be called for Upgrade proposal")
		}
	})

	// P1-T6: Verify handler error does not block proposal execution (best-effort).
	t.Run("Execute_emergencyHandlerErrorDoesNotBlock", func(t *testing.T) {
		gm := NewGovernanceManager(nil)
		defer gm.Close()

		mockHandler := &mockEmergencyHandler{
			fn: func(id uint64, proposer types.Address, title, desc string) error {
				return fmt.Errorf("simulated handler failure")
			},
		}
		gm.SetEmergencyActionHandler(mockHandler)

		execDelay := DefaultGovernanceConfig().ExecutionDelay
		p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeEmergency, "Emergency", "Desc", nil, deposit, 100, nil, 3, nil)
		p.Status = ProposalStatusPassed
		gm.proposals[p.ID] = p

		err := gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
		if err != nil {
			t.Fatalf("ExecuteProposal should succeed even if handler fails, got: %v", err)
		}

		proposal, _ := gm.GetProposal(p.ID)
		if proposal.Status != ProposalStatusExecuted {
			t.Errorf("expected Executed despite handler error, got %d", proposal.Status)
		}
	})
}

func TestGovernanceManager_VotePowerAdjustments(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	sq := newMockStakeQuerier()
	sq.stakes[types.Address{1}] = new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	sq.stakes[types.Address{2}] = new(big.Int).Mul(big.NewInt(200), big.NewInt(1e18))
	gm.SetStakeQuerier(sq)

	deposit := DefaultGovernanceConfig().ProposalDeposit

	t.Run("noAdjustments_empty", func(t *testing.T) {
		adj := gm.GetVotePowerAdjustments()
		if len(adj) != 0 {
			t.Errorf("expected 0, got %d", len(adj))
		}
	})

	p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeUpgrade, "Test", "Desc", nil, deposit, 100, nil, 2, nil)
	p2, _ := gm.CreateProposal(types.Address{2}, ProposalTypeUpgrade, "Test2", "Desc2", nil, deposit, 200, nil, 1, nil)

	// Vote with inflated power on proposal 1
	inflatedPower := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	gm.Vote(p.ID, types.Address{1}, VoteOptionYes, inflatedPower, 110)

	// Vote with inflated power on proposal 2
	gm.Vote(p2.ID, types.Address{2}, VoteOptionYes, inflatedPower, 210)

	t.Run("GetVotePowerAdjustments_all", func(t *testing.T) {
		adj := gm.GetVotePowerAdjustments()
		if len(adj) != 2 {
			t.Errorf("expected 2, got %d", len(adj))
		}
	})

	t.Run("GetVotePowerAdjustmentsForProposal", func(t *testing.T) {
		adj := gm.GetVotePowerAdjustmentsForProposal(p.ID)
		if len(adj) != 1 {
			t.Errorf("expected 1 for proposal %d, got %d", p.ID, len(adj))
		}
		expectedVoter := types.Address{}
		expectedVoter[0] = 1
		if adj[0].Voter != expectedVoter {
			t.Errorf("expected voter {1}, got %v", adj[0].Voter)
		}
	})

	t.Run("GetVotePowerAdjustmentsForProposal_empty", func(t *testing.T) {
		adj := gm.GetVotePowerAdjustmentsForProposal(999)
		if len(adj) != 0 {
			t.Errorf("expected 0, got %d", len(adj))
		}
	})

	t.Run("GetVotePowerAdjustmentsForVoter", func(t *testing.T) {
		adj := gm.GetVotePowerAdjustmentsForVoter(types.Address{1})
		if len(adj) != 1 {
			t.Errorf("expected 1 for voter {1}, got %d", len(adj))
		}
	})

	t.Run("GetVotePowerAdjustmentsForVoter_empty", func(t *testing.T) {
		adj := gm.GetVotePowerAdjustmentsForVoter(types.Address{99})
		if len(adj) != 0 {
			t.Errorf("expected 0, got %d", len(adj))
		}
	})
}

func TestGovernanceManager_RecordVotePowerAdjustment(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	t.Run("nilInputs", func(t *testing.T) {
		gm.recordVotePowerAdjustment(1, types.Address{1}, nil, big.NewInt(100), big.NewInt(50), 100)
		gm.recordVotePowerAdjustment(1, types.Address{1}, big.NewInt(100), nil, big.NewInt(50), 100)
		gm.recordVotePowerAdjustment(1, types.Address{1}, big.NewInt(100), big.NewInt(100), nil, 100)

		adj := gm.GetVotePowerAdjustments()
		if len(adj) != 0 {
			t.Errorf("expected 0 adjustments with nil inputs, got %d", len(adj))
		}
	})

	t.Run("record_cap", func(t *testing.T) {
		// Set low cap and record many events
		gm2 := NewGovernanceManager(nil)
		defer gm2.Close()

		// Override max limit
		for i := 0; i < 10002; i++ {
			gm2.recordVotePowerAdjustment(uint64(i%10), types.Address{1}, big.NewInt(200), big.NewInt(100), big.NewInt(100), uint64(i))
		}

		events := gm2.GetVotePowerAdjustments()
		if len(events) > 10000 {
			t.Errorf("expected <=10000 events, got %d", len(events))
		}
	})
}

// TestGovernanceManager_DefaultDenyWhitelist verifies that unknown parameters
// are rejected by the default-deny whitelist.
// SECURITY (audit P1-R3-04): Only whitelisted parameters should be settable.
func TestGovernanceManager_DefaultDenyWhitelist(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	// Known parameter should succeed
	err := gm.setParameter("MinStakeAmount", "1000")
	if err != nil {
		t.Errorf("known parameter should succeed: %v", err)
	}

	// Unknown parameter should fail
	err = gm.setParameter("MaliciousParam", "999")
	if err == nil {
		t.Error("unknown parameter should be rejected by default-deny whitelist")
	}
	t.Logf("Correctly rejected unknown parameter: %v", err)

	// Block params should succeed
	err = gm.setParameter("MaxBlockSize", "4194304")
	if err != nil {
		t.Errorf("MaxBlockSize should be in whitelist: %v", err)
	}

	err = gm.setParameter("BlockGasLimit", "30000000")
	if err != nil {
		t.Errorf("BlockGasLimit should be in whitelist: %v", err)
	}

	err = gm.setParameter("BaseFee", "1000000000")
	if err != nil {
		t.Errorf("BaseFee should be in whitelist: %v", err)
	}

	// Another unknown parameter should fail
	err = gm.setParameter("EvilBackdoor", "1")
	if err == nil {
		t.Error("unknown parameter 'EvilBackdoor' should be rejected")
	}
}
