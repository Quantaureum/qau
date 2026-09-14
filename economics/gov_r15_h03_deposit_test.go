// Quantaureum Node source, version 1.0.0.
// Package economics — GOV-R15-H03 tests.
//
// Verifies the fix for the audit finding:
//
//	CreateProposal never actually deducted the deposit, allowing zero-cost proposal spam
//
// Before the fix, GovernanceManager.CreateProposal recorded the deposit on
// the Proposal struct but never actually charged it — a proposer could
// submit unlimited proposals at no cost, DoSing the governance system.
//
// After the fix, when a DepositLocker is wired (via SetDepositLocker),
// CreateProposal calls LockDeposit(proposer, deposit, proposalID) BEFORE
// storing the proposal. If LockDeposit fails (e.g. insufficient balance),
// the proposal is rejected and not stored. If no DepositLocker is wired,
// the backward-compatible behavior is preserved (deposit recorded but not
// charged) — this is for tests only; production MUST wire one.
package economics

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/quantaureum/qau/types"
)

// mockDepositLocker records every LockDeposit/UnlockDeposit/SlashDeposit call
// and optionally returns a configured error. Used to verify CreateProposal
// actually charges the deposit before storing the proposal.
//
// CRIT-06 (R17): Extended to track Unlock/Slash calls and enforce idempotency
// via the settled set (matching the production contract).
type mockDepositLocker struct {
	mu          sync.Mutex
	calls       []mockDepositCall
	failWith    error
	totalLocked *big.Int
	// CRIT-06: track settled proposalIDs for idempotency.
	settled     map[uint64]bool
	unlockCount int
	slashCount  int
	unlocked    *big.Int // total refunded
	slashed     *big.Int // total slashed
}

type mockDepositCall struct {
	Op         string // "lock" | "unlock" | "slash"
	Addr       types.Address
	Amount     *big.Int
	ProposalID uint64
}

func newMockDepositLocker() *mockDepositLocker {
	return &mockDepositLocker{
		totalLocked: new(big.Int),
		settled:     make(map[uint64]bool),
		unlocked:    new(big.Int),
		slashed:     new(big.Int),
	}
}

func (m *mockDepositLocker) LockDeposit(addr types.Address, amount *big.Int, proposalID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockDepositCall{
		Op:         "lock",
		Addr:       addr,
		Amount:     new(big.Int).Set(amount),
		ProposalID: proposalID,
	})
	if m.failWith != nil {
		return m.failWith
	}
	m.totalLocked.Add(m.totalLocked, amount)
	return nil
}

// UnlockDeposit refunds the deposit. CRIT-06 (R17): idempotent on proposalID.
func (m *mockDepositLocker) UnlockDeposit(addr types.Address, amount *big.Int, proposalID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.settled[proposalID] {
		return nil // idempotent
	}
	m.calls = append(m.calls, mockDepositCall{
		Op:         "unlock",
		Addr:       addr,
		Amount:     new(big.Int).Set(amount),
		ProposalID: proposalID,
	})
	if m.failWith != nil {
		return m.failWith
	}
	m.settled[proposalID] = true
	m.unlockCount++
	m.unlocked.Add(m.unlocked, amount)
	return nil
}

// SlashDeposit burns the deposit. CRIT-06 (R17): idempotent on proposalID.
func (m *mockDepositLocker) SlashDeposit(addr types.Address, amount *big.Int, proposalID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.settled[proposalID] {
		return nil // idempotent
	}
	m.calls = append(m.calls, mockDepositCall{
		Op:         "slash",
		Addr:       addr,
		Amount:     new(big.Int).Set(amount),
		ProposalID: proposalID,
	})
	if m.failWith != nil {
		return m.failWith
	}
	m.settled[proposalID] = true
	m.slashCount++
	m.slashed.Add(m.slashed, amount)
	return nil
}

func (m *mockDepositLocker) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func (m *mockDepositLocker) TotalLocked() *big.Int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return new(big.Int).Set(m.totalLocked)
}

func (m *mockDepositLocker) SetFail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failWith = err
}

// CRIT-06 (R17): helpers for verifying unlock/slash behavior.
func (m *mockDepositLocker) UnlockCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unlockCount
}

func (m *mockDepositLocker) SlashCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.slashCount
}

func (m *mockDepositLocker) TotalUnlocked() *big.Int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return new(big.Int).Set(m.unlocked)
}

func (m *mockDepositLocker) TotalSlashed() *big.Int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return new(big.Int).Set(m.slashed)
}

// TestGOV_R15_H03_DepositLocker_ChargedOnCreate verifies that when a
// DepositLocker is wired, CreateProposal calls LockDeposit with the
// proposer address, the deposit amount, and the proposal ID, BEFORE the
// proposal is stored.
func TestGOV_R15_H03_DepositLocker_ChargedOnCreate(t *testing.T) {
	gm := NewGovernanceManager(DefaultGovernanceConfig())
	defer gm.Close()

	locker := newMockDepositLocker()
	gm.SetDepositLocker(locker)

	proposer := types.BytesToAddress([]byte{0x01})
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

	// Use a parameter proposal so it passes validation.
	changes := []ParameterChange{{Parameter: "inflation_rate", NewValue: "0.05"}}

	// Track nextProposalID before the call (should be 1 by default).
	proposal, err := gm.CreateProposal(
		proposer,
		ProposalTypeParameter,
		"title",
		"description",
		changes,
		deposit,
		100,              // currentHeight
		big.NewInt(1000), // totalVotePower,
		59,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}

	if locker.CallCount() != 1 {
		t.Fatalf("LockDeposit should be called exactly once, got %d calls", locker.CallCount())
	}

	call := locker.calls[0]
	if call.Addr != proposer {
		t.Errorf("LockDeposit called with wrong addr: got %x, want %x", call.Addr, proposer)
	}
	if call.Amount.Cmp(deposit) != 0 {
		t.Errorf("LockDeposit called with wrong amount: got %s, want %s", call.Amount.String(), deposit.String())
	}
	if call.ProposalID != proposal.ID {
		t.Errorf("LockDeposit called with wrong proposalID: got %d, want %d", call.ProposalID, proposal.ID)
	}

	// The proposal should be stored after successful lock.
	stored, err := gm.GetProposal(proposal.ID)
	if err != nil {
		t.Fatalf("GetProposal failed: %v", err)
	}
	if stored.Deposit.Cmp(deposit) != 0 {
		t.Errorf("stored proposal deposit mismatch: got %s, want %s", stored.Deposit.String(), deposit.String())
	}

	// Total locked should equal deposit.
	if locker.TotalLocked().Cmp(deposit) != 0 {
		t.Errorf("total locked mismatch: got %s, want %s", locker.TotalLocked().String(), deposit.String())
	}
}

// TestGOV_R15_H03_DepositLocker_FailureRejectsProposal verifies that when
// LockDeposit fails (e.g. insufficient balance), CreateProposal returns an
// error and the proposal is NOT stored. This is the core DoS protection —
// a proposer who cannot afford the deposit cannot create a proposal.
func TestGOV_R15_H03_DepositLocker_FailureRejectsProposal(t *testing.T) {
	gm := NewGovernanceManager(DefaultGovernanceConfig())
	defer gm.Close()

	locker := newMockDepositLocker()
	locker.SetFail(errors.New("insufficient balance"))
	gm.SetDepositLocker(locker)

	proposer := types.BytesToAddress([]byte{0x02})
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	changes := []ParameterChange{{Parameter: "inflation_rate", NewValue: "0.05"}}

	proposal, err := gm.CreateProposal(
		proposer,
		ProposalTypeParameter,
		"title",
		"description",
		changes,
		deposit,
		100,
		big.NewInt(1000),
		58,
		nil,
	)
	if err == nil {
		t.Fatal("CreateProposal should fail when LockDeposit fails")
	}
	if proposal != nil {
		t.Fatalf("CreateProposal should return nil proposal on lock failure, got %v", proposal)
	}

	// Verify the proposal was NOT stored.
	if locker.CallCount() != 1 {
		t.Fatalf("LockDeposit should be called once (failed), got %d", locker.CallCount())
	}

	// nextProposalID should NOT be consumed (proposal was not stored).
	// We verify this by retrying with a working locker — the next proposal
	// should get ID 1 (the failed attempt did not increment the counter).
	locker.SetFail(nil)
	proposal2, err := gm.CreateProposal(
		proposer,
		ProposalTypeParameter,
		"title2",
		"description2",
		changes,
		deposit,
		100,
		big.NewInt(1000),
		57,
		nil,
	)
	if err != nil {
		t.Fatalf("retry CreateProposal should succeed: %v", err)
	}
	if proposal2.ID != 1 {
		t.Errorf("failed attempt should not consume proposal ID; expected ID=1, got %d", proposal2.ID)
	}
}

// TestGOV_R15_H03_DepositLocker_NilLockerBackwardCompat verifies that when
// no DepositLocker is wired (nil), CreateProposal preserves the old
// behavior — the deposit is recorded on the proposal but not actually
// charged. This keeps existing tests working; production MUST wire a locker.
func TestGOV_R15_H03_DepositLocker_NilLockerBackwardCompat(t *testing.T) {
	gm := NewGovernanceManager(DefaultGovernanceConfig())
	defer gm.Close()

	// Intentionally NOT calling SetDepositLocker — gm.depositLocker stays nil.

	proposer := types.BytesToAddress([]byte{0x03})
	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	changes := []ParameterChange{{Parameter: "inflation_rate", NewValue: "0.05"}}

	proposal, err := gm.CreateProposal(
		proposer,
		ProposalTypeParameter,
		"title",
		"description",
		changes,
		deposit,
		100,
		big.NewInt(1000),
		56,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateProposal should succeed without DepositLocker (backward compat): %v", err)
	}
	if proposal == nil {
		t.Fatal("CreateProposal returned nil proposal without error")
	}
	if proposal.Deposit.Cmp(deposit) != 0 {
		t.Errorf("proposal deposit mismatch: got %s, want %s", proposal.Deposit.String(), deposit.String())
	}
}

// TestGOV_R15_H03_DepositLocker_MultipleProposals verifies that each
// CreateProposal call results in exactly one LockDeposit call with the
// correct proposal ID — no proposal is stored without charging.
func TestGOV_R15_H03_DepositLocker_MultipleProposals(t *testing.T) {
	gm := NewGovernanceManager(DefaultGovernanceConfig())
	defer gm.Close()

	locker := newMockDepositLocker()
	gm.SetDepositLocker(locker)

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	changes := []ParameterChange{{Parameter: "inflation_rate", NewValue: "0.05"}}

	for i := 0; i < 3; i++ {
		proposer := types.BytesToAddress([]byte{byte(0x10 + i)})
		_, err := gm.CreateProposal(
			proposer,
			ProposalTypeParameter,
			"title",
			"description",
			changes,
			deposit,
			uint64(100+i),
			big.NewInt(1000),
			55,
			nil,
		)
		if err != nil {
			t.Fatalf("CreateProposal[%d] failed: %v", i, err)
		}
	}

	if locker.CallCount() != 3 {
		t.Fatalf("LockDeposit should be called 3 times, got %d", locker.CallCount())
	}

	// Each call should have a distinct, monotonically increasing proposal ID.
	expectedTotal := new(big.Int).Mul(big.NewInt(3), deposit)
	if locker.TotalLocked().Cmp(expectedTotal) != 0 {
		t.Errorf("total locked mismatch: got %s, want %s",
			locker.TotalLocked().String(), expectedTotal.String())
	}

	seenIDs := make(map[uint64]bool)
	for _, call := range locker.calls {
		if seenIDs[call.ProposalID] {
			t.Errorf("duplicate proposal ID %d in LockDeposit calls", call.ProposalID)
		}
		seenIDs[call.ProposalID] = true
	}
	if len(seenIDs) != 3 {
		t.Errorf("expected 3 distinct proposal IDs, got %d", len(seenIDs))
	}
}
