// Quantaureum Node source, version 1.0.0.
// Package economics — GOV-R12-001 tests.
//
// Verifies the fix for the audit finding:
//
//	Governance voting used current stake instead of a voting-power snapshot, allowing temporary large stakes to vote then immediately unstake
//
// Before the fix, GovernanceManager.Vote validated votePower against the
// voter's CURRENT stake (GetStakeAmount), which allowed an attacker to:
//  1. Stake a large amount
//  2. Wait for or create a proposal (snapshot height H0)
//  3. Vote with their full (temporary) stake at height H1 > H0
//  4. Immediately unstake after voting at height H2 > H1
//  5. Their vote still counted with full power even though they no longer
//     held the stake at the time of vote finalization
//
// After the fix, when the StakeQuerier implements StakeSnapshotQuerier,
// Vote validates votePower against the voter's stake AT THE PROPOSAL'S
// START HEIGHT. This means:
//   - Staking AFTER the snapshot does not grant additional vote power.
//   - Unstaking AFTER the snapshot does not reduce vote power (the vote
//     was already bounded by the snapshot stake, not the current stake).
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// snapshotMockStakeQuerier is a StakeSnapshotQuerier implementation that
// records stake changes over time. SetStakeAt records the stake at a given
// height. GetStakeAmountAtHeight returns the most recent stake set at or
// before the queried height.
type snapshotMockStakeQuerier struct {
	// history maps height -> delta applied at that height.
	history map[uint64]map[types.Address]*big.Int
	// current stakes (for the basic GetStakeAmount call).
	current map[types.Address]*big.Int
}

func newSnapshotMockStakeQuerier() *snapshotMockStakeQuerier {
	return &snapshotMockStakeQuerier{
		history: make(map[uint64]map[types.Address]*big.Int),
		current: make(map[types.Address]*big.Int),
	}
}

// SetStakeAt records that addr had stake amount at exactly height.
// Subsequent GetStakeAmountAtHeight queries for >= height will return
// this amount (until a later SetStakeAt overrides it).
func (m *snapshotMockStakeQuerier) SetStakeAt(height uint64, addr types.Address, amount *big.Int) {
	if m.history[height] == nil {
		m.history[height] = make(map[types.Address]*big.Int)
	}
	m.history[height][addr] = new(big.Int).Set(amount)
	m.current[addr] = new(big.Int).Set(amount)
}

// GetStakeAmount implements the basic StakeQuerier interface.
func (m *snapshotMockStakeQuerier) GetStakeAmount(addr types.Address) (*big.Int, error) {
	if stake, ok := m.current[addr]; ok {
		return new(big.Int).Set(stake), nil
	}
	return big.NewInt(0), nil
}

// GetStakeAmountAtHeight returns the stake amount for addr at the given
// height. Returns the latest recorded stake at or before height.
// If no stake was recorded at or before height, returns 0.
func (m *snapshotMockStakeQuerier) GetStakeAmountAtHeight(addr types.Address, height uint64) (*big.Int, error) {
	var latestHeight uint64
	var latestAmount *big.Int
	found := false
	for h, stakes := range m.history {
		if h > height {
			continue
		}
		if amount, ok := stakes[addr]; ok {
			if !found || h > latestHeight {
				latestHeight = h
				latestAmount = amount
				found = true
			}
		}
	}
	if !found {
		return big.NewInt(0), nil
	}
	return new(big.Int).Set(latestAmount), nil
}

// defaultDeposit matches DefaultGovernanceConfig().ProposalDeposit (100 * 1e18).
var defaultDeposit = new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

// TestGOV_R12_001_VoteUsesSnapshotStake_NotCurrentStake is the core
// regression test for the audit finding.
//
// Scenario:
//   - At height 100, attacker has enough stake to pass the proposer-deposit
//     check but only 100 at the snapshot for vote power. Proposal created
//     at height 100 (snapshot height = 100).
//   - At height 110, attacker stakes an additional 10,000 QAU (AFTER snapshot).
//   - At height 120, attacker tries to vote with votePower=10,000+100.
//   - Vote must be CLAMPED to 100 (snapshot stake), not 10,100 (current).
//
// Before the fix (current-stake validation), votePower would be accepted at
// the full 10,100 because GetStakeAmount returns the live stake. After the
// fix (snapshot validation), GetStakeAmountAtHeight(100) returns 100 and
// votePower is clamped to 100.
func TestGOV_R12_001_VoteUsesSnapshotStake_NotCurrentStake(t *testing.T) {
	sq := newSnapshotMockStakeQuerier()
	attacker := types.Address{0xAA}

	// At height 100: attacker has exactly the deposit amount (passes
	// CreateProposal proposer-stake check) plus 100 vote power.
	sq.SetStakeAt(100, attacker, defaultDeposit)

	cfg := DefaultGovernanceConfig()
	cfg.VotingPeriod = 1000 // long voting period
	gm := NewGovernanceManager(cfg)
	defer gm.Close()
	gm.SetStakeQuerier(sq)

	// Create proposal at height 100 (snapshot height).
	proposal, err := gm.CreateProposal(
		attacker,
		ProposalTypeUpgrade,
		"Test",
		"Test GOV-R12-001",
		nil,
		new(big.Int).Set(defaultDeposit), // deposit
		100,                              // currentHeight = snapshot height
		big.NewInt(0),                    // totalVotePower at snapshot,
		48,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}

	// At height 110, attacker stakes 10,000 more (AFTER snapshot).
	// Their CURRENT stake is now deposit + 10,000.
	sq.SetStakeAt(110, attacker, new(big.Int).Add(defaultDeposit, big.NewInt(10000)))

	// At height 120, attacker tries to vote with votePower = current stake.
	// Must be CLAMPED to the snapshot stake (just the deposit amount).
	voteClaim := new(big.Int).Add(defaultDeposit, big.NewInt(10000))
	err = gm.Vote(proposal.ID, attacker, VoteOptionYes, voteClaim, 120)
	if err != nil {
		t.Fatalf("Vote should have succeeded (with clamping), got: %v", err)
	}

	vote, err := gm.GetVote(proposal.ID, attacker)
	if err != nil {
		t.Fatalf("GetVote failed: %v", err)
	}
	if vote.VotePower.Cmp(defaultDeposit) != 0 {
		t.Fatalf("GOV-R12-001 REGRESSION: votePower = %s, want %s (snapshot stake at h=100, not current %s)",
			vote.VotePower.String(), defaultDeposit.String(), voteClaim.String())
	}
}

// TestGOV_R12_001_VoteRejectedWhenSnapshotStakeIsZero verifies that a user
// who had ZERO stake at the snapshot cannot vote even if they later stake
// a large amount before voting.
//
// Scenario:
//   - At height 100, attacker has 0 stake. Proposal created at height 100.
//   - At height 110, attacker stakes 10,000 QAU (AFTER snapshot).
//   - At height 120, attacker tries to vote with votePower=10,000.
//   - Vote must be REJECTED — they had no stake at snapshot height.
//
// This is the most direct regression check for the audit finding.
func TestGOV_R12_001_VoteRejectedWhenSnapshotStakeIsZero(t *testing.T) {
	sq := newSnapshotMockStakeQuerier()
	// Proposer has enough stake for deposit.
	proposer := types.Address{0xBB}
	sq.SetStakeAt(100, proposer, defaultDeposit)
	// Attacker has ZERO stake at height 100.
	attacker := types.Address{0xCC}
	// (Don't call SetStakeAt — defaults to 0.)

	cfg := DefaultGovernanceConfig()
	cfg.VotingPeriod = 1000
	gm := NewGovernanceManager(cfg)
	defer gm.Close()
	gm.SetStakeQuerier(sq)

	proposal, err := gm.CreateProposal(
		proposer,
		ProposalTypeUpgrade,
		"Test",
		"Test GOV-R12-001 zero snapshot",
		nil,
		new(big.Int).Set(defaultDeposit),
		100,
		big.NewInt(0),
		47,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}

	// At height 110, attacker stakes 10,000 (after snapshot).
	sq.SetStakeAt(110, attacker, big.NewInt(10000))

	// At height 120, attacker tries to vote with 10,000.
	// Must be REJECTED — snapshot stake was 0.
	err = gm.Vote(proposal.ID, attacker, VoteOptionYes, big.NewInt(10000), 120)
	if err == nil {
		t.Fatal("GOV-R12-001 REGRESSION: vote accepted even though attacker had 0 stake at snapshot height (only staked AFTER snapshot)")
	}
}

// TestGOV_R12_001_UnstakeAfterSnapshotDoesNotReduceVotePower verifies that
// unstaking AFTER the snapshot does not reduce the user's vote power.
//
// Scenario:
//   - At height 100, user has 5,000 stake (above deposit). Proposal created.
//   - At height 110, user unstakes to 1,000 (current stake = 1,000).
//   - At height 120, user votes with votePower=5,000.
//   - VotePower must be ACCEPTED at 5,000 (snapshot stake), not clamped to 1,000.
//
// This is the EXACT attack described in the audit finding: "temporarily
// stake big, vote, then immediately unstake". Before the fix, the
// unstake would reduce current stake and votePower would be clamped to
// 1,000. After the fix (snapshot validation), the snapshot stake (5,000)
// is preserved.
func TestGOV_R12_001_UnstakeAfterSnapshotDoesNotReduceVotePower(t *testing.T) {
	sq := newSnapshotMockStakeQuerier()
	user := types.Address{0xDD}

	// At height 100: user has 5,000 (snapshot stake).
	sq.SetStakeAt(100, user, big.NewInt(5000))

	// Use ProposalDeposit=0 to focus on the vote power validation logic
	// (the proposer-stake check would otherwise require stake >= 100e18,
	// which is unrelated to the GOV-R12-001 fix).
	cfg := DefaultGovernanceConfig()
	cfg.VotingPeriod = 1000
	cfg.ProposalDeposit = big.NewInt(0)
	gm := NewGovernanceManager(cfg)
	defer gm.Close()
	gm.SetStakeQuerier(sq)

	proposal, err := gm.CreateProposal(
		user,
		ProposalTypeUpgrade,
		"Test",
		"Test GOV-R12-001 unstake",
		nil,
		big.NewInt(0),
		100,
		big.NewInt(0),
		46,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}

	// At height 110, user unstakes to 1,000.
	sq.SetStakeAt(110, user, big.NewInt(1000))

	// At height 120, user votes with 5,000 (snapshot stake).
	err = gm.Vote(proposal.ID, user, VoteOptionYes, big.NewInt(5000), 120)
	if err != nil {
		t.Fatalf("Vote should have succeeded with snapshot stake, got: %v", err)
	}

	vote, err := gm.GetVote(proposal.ID, user)
	if err != nil {
		t.Fatalf("GetVote failed: %v", err)
	}
	if vote.VotePower.Cmp(big.NewInt(5000)) != 0 {
		t.Fatalf("GOV-R12-001 REGRESSION: votePower = %s, want 5000 (snapshot stake preserved despite unstake)",
			vote.VotePower.String())
	}
}

// TestGOV_R12_001_LegacyQuerier_FailsClosed verifies that when the
// StakeQuerier does NOT implement StakeSnapshotQuerier, Vote is REJECTED
// (fail-closed). R35-P0-14: previously Vote fell back to current-stake
// validation, leaving production vulnerable to the GOV-R12-001 attack
// (stake → vote → unstake). The fallback was removed; this test now
// verifies the fail-closed behavior.
func TestGOV_R12_001_LegacyQuerier_FailsClosed(t *testing.T) {
	// legacyOnlyStakeQuerier implements StakeQuerier but NOT
	// StakeSnapshotQuerier.
	sq := &legacyOnlyStakeQuerier{
		stakes: map[types.Address]*big.Int{
			{0xEE}: big.NewInt(5000),
		},
	}

	// ProposalDeposit=0 so the proposer-stake check does not dominate
	// the legacy-fallback test (we want to verify the vote path, not the
	// proposer-deposit path).
	cfg := DefaultGovernanceConfig()
	cfg.VotingPeriod = 1000
	cfg.ProposalDeposit = big.NewInt(0)
	gm := NewGovernanceManager(cfg)
	defer gm.Close()
	gm.SetStakeQuerier(sq)

	// Verify the mock does NOT implement StakeSnapshotQuerier.
	if _, ok := interface{}(sq).(StakeSnapshotQuerier); ok {
		t.Fatal("test setup: legacyOnlyStakeQuerier should NOT implement StakeSnapshotQuerier")
	}

	proposer := types.Address{0xEE}
	proposal, err := gm.CreateProposal(
		proposer,
		ProposalTypeUpgrade,
		"Test",
		"Test GOV-R12-001 fail-closed",
		nil,
		big.NewInt(0),
		100,
		big.NewInt(0),
		45,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}

	// Vote MUST be rejected because the querier does not implement
	// StakeSnapshotQuerier (R35-P0-14 fail-closed).
	err = gm.Vote(proposal.ID, proposer, VoteOptionYes, big.NewInt(1000), 120)
	if err == nil {
		t.Fatal("GOV-R12-001 REGRESSION: Vote with legacy-only querier should have been rejected (R35-P0-14 fail-closed), got nil")
	}
}

// legacyOnlyStakeQuerier implements StakeQuerier but NOT
// StakeSnapshotQuerier. Used to verify R35-P0-14 fail-closed behavior.
type legacyOnlyStakeQuerier struct {
	stakes map[types.Address]*big.Int
}

func (m *legacyOnlyStakeQuerier) GetStakeAmount(addr types.Address) (*big.Int, error) {
	if stake, ok := m.stakes[addr]; ok {
		return new(big.Int).Set(stake), nil
	}
	return big.NewInt(0), nil
}

// TestGOV_R12_001_SnapshotErrorFailsClosed verifies that if the snapshot
// querier returns an error, the vote is rejected (fail-closed).
// This prevents an attacker from bypassing validation by causing a
// snapshot-query error.
func TestGOV_R12_001_SnapshotErrorFailsClosed(t *testing.T) {
	sq := &errorSnapshotQuerier{}

	cfg := DefaultGovernanceConfig()
	cfg.VotingPeriod = 1000
	gm := NewGovernanceManager(cfg)
	defer gm.Close()
	gm.SetStakeQuerier(sq)

	proposer := types.Address{0x99}
	// errorSnapshotQuerier returns 1000 for GetStakeAmount (passes deposit check
	// only if deposit <= 1000; default deposit is 100e18, so we need a custom
	// deposit. Use a config with zero deposit for this test.
	cfg.ProposalDeposit = big.NewInt(0)
	gm2 := NewGovernanceManager(cfg)
	defer gm2.Close()
	gm2.SetStakeQuerier(sq)

	proposal, err := gm2.CreateProposal(
		proposer,
		ProposalTypeUpgrade,
		"Test",
		"Test GOV-R12-001 error fail-closed",
		nil,
		big.NewInt(0),
		100,
		big.NewInt(0),
		44,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}

	// Vote must be rejected due to snapshot query error.
	err = gm2.Vote(proposal.ID, proposer, VoteOptionYes, big.NewInt(100), 120)
	if err == nil {
		t.Fatal("GOV-R12-001 REGRESSION: vote accepted even though snapshot query returned error (should fail-closed)")
	}
}

// errorSnapshotQuerier is a StakeSnapshotQuerier that always returns an
// error from GetStakeAmountAtHeight, used to verify fail-closed behavior.
type errorSnapshotQuerier struct{}

func (m *errorSnapshotQuerier) GetStakeAmount(addr types.Address) (*big.Int, error) {
	return big.NewInt(1000), nil
}

func (m *errorSnapshotQuerier) GetStakeAmountAtHeight(addr types.Address, height uint64) (*big.Int, error) {
	return nil, errSnapshotUnavailable
}

// errSnapshotUnavailable is a sentinel error used by errorSnapshotQuerier.
var errSnapshotUnavailable = &snapshotError{}

type snapshotError struct{}

func (e *snapshotError) Error() string { return "snapshot unavailable" }
