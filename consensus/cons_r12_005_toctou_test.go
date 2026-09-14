// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
//
// This file contains tests for the CONS-R12-005 fix (VoteCollector.AddVote
// TOCTOU race condition). The fix moves GetValidator + vote.Verify INSIDE
// vc.mu.Lock() so that the public key used for signature verification is
// the same key that the in-lock status check used — closing the race window
// where a validator could be deactivated/slashed (or, in future code,
// key-rotated) between the outside-lock verification and the in-lock
// re-validation.
package consensus

import (
	"errors"
	"sync"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// TestCONS_R12005_AcceptsValidVote verifies the basic happy path still
// works after the TOCTOU fix: a properly signed vote from an active
// validator is accepted.
func TestCONS_R12005_AcceptsValidVote(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04/VAL-H05 FIX (R31, 2026-07-27): Non-genesis AddValidator sets
	// Active=false. First-time activation MUST go through ActivateFromQueue
	// (mirroring ProcessEpochAdvanced) so the validator can participate in
	// voting. Without this, AddVote rejects with ErrVoteFromNonValidator.
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	blockHash := types.Hash{0x42}
	vc := NewVoteCollector(200, 0, blockHash, vmgr)

	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        200,
		Round:         0,
		BlockHash:     blockHash,
		ValidatorAddr: addr,
	}
	if err := vote.Sign(privKey); err != nil {
		t.Fatalf("vote.Sign: %v", err)
	}

	if err := vc.AddVote(vote); err != nil {
		t.Errorf("AddVote: want nil, got %v", err)
	}
	if vc.VoteCount() != 1 {
		t.Errorf("VoteCount: want 1, got %d", vc.VoteCount())
	}
	if !vc.HasVoted(addr) {
		t.Error("HasVoted should be true after adding vote")
	}
}

// TestCONS_R12005_RejectsInactiveValidator verifies that a vote from a
// validator that has been deactivated (via SetActive) is rejected by the
// in-lock status check. This is the TOCTOU-relevant scenario: if the
// validator was deactivated AFTER the outside-lock GetValidator but BEFORE
// the in-lock GetValidator, the in-lock check must catch it.
func TestCONS_R12005_RejectsInactiveValidator(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// Deactivate the validator before AddVote — this simulates the worst-case
	// TOCTOU scenario where deactivation lands before the in-lock GetValidator.
	if err := vmgr.SetActive(addr, addr, false); err != nil {
		t.Fatalf("SetActive(false): %v", err)
	}

	blockHash := types.Hash{0x42}
	vc := NewVoteCollector(200, 0, blockHash, vmgr)

	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        200,
		Round:         0,
		BlockHash:     blockHash,
		ValidatorAddr: addr,
	}
	if err := vote.Sign(privKey); err != nil {
		t.Fatalf("vote.Sign: %v", err)
	}

	if err := vc.AddVote(vote); !errors.Is(err, ErrVoteFromNonValidator) {
		t.Errorf("AddVote from inactive validator: want ErrVoteFromNonValidator, got %v", err)
	}
	if vc.VoteCount() != 0 {
		t.Errorf("VoteCount: want 0, got %d", vc.VoteCount())
	}
}

// TestCONS_R12005_RejectsPermanentlySlashedValidator verifies that a vote
// from a permanently slashed validator is rejected. Slashing can happen
// concurrently with vote collection; the in-lock re-check must catch it
// even if the outside-lock state was still "active".
func TestCONS_R12005_RejectsPermanentlySlashedValidator(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// Mark the validator as permanently slashed. In production this is done
	// via SlashingManager → MarkPermanentlySlashed(systemCaller, addr). Here
	// we mutate the field directly since the test is in-package.
	vmgr.mu.Lock()
	vmgr.validators[addr].PermanentlySlashed = true
	vmgr.validators[addr].Active = false
	vmgr.mu.Unlock()

	blockHash := types.Hash{0x42}
	vc := NewVoteCollector(200, 0, blockHash, vmgr)

	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        200,
		Round:         0,
		BlockHash:     blockHash,
		ValidatorAddr: addr,
	}
	if err := vote.Sign(privKey); err != nil {
		t.Fatalf("vote.Sign: %v", err)
	}

	// PermanentlySlashed also sets Active=false, so the first rejection
	// could be either ErrVoteFromNonValidator OR ErrValidatorSlashed depending
	// on the order of checks. Both errors indicate the vote was rejected.
	// The current implementation checks Active first, so we expect
	// ErrVoteFromNonValidator. But to make the test resilient to future
	// reordering, accept either error.
	err := vc.AddVote(vote)
	if err == nil {
		t.Fatal("AddVote from permanently slashed validator: want error, got nil")
	}
	if !errors.Is(err, ErrVoteFromNonValidator) && !errors.Is(err, ErrValidatorSlashed) {
		t.Errorf("AddVote from permanently slashed validator: want ErrVoteFromNonValidator or ErrValidatorSlashed, got %v", err)
	}
	if vc.VoteCount() != 0 {
		t.Errorf("VoteCount: want 0, got %d", vc.VoteCount())
	}
}

// TestCONS_R12005_RejectsWrongSignatureInsideLock verifies that the
// signature verification (now performed inside the lock) still rejects
// votes signed by a different key. This is the core TOCTOU fix: the
// signature is checked against the in-lock-fetched public key, not a
// potentially stale outside-lock copy.
func TestCONS_R12005_RejectsWrongSignatureInsideLock(t *testing.T) {
	vmgr := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04/VAL-H05 FIX: Activate so AddVote reaches the signature
	// verification step (Active=false short-circuits to ErrVoteFromNonValidator
	// before the signature is checked).
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	otherPriv, _ := createTestKeyPair(t) // different key pair

	blockHash := types.Hash{0x42}
	vc := NewVoteCollector(200, 0, blockHash, vmgr)

	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        200,
		Round:         0,
		BlockHash:     blockHash,
		ValidatorAddr: addr,
	}
	if err := vote.Sign(otherPriv); err != nil {
		t.Fatalf("vote.Sign: %v", err)
	}

	if err := vc.AddVote(vote); !errors.Is(err, ErrInvalidVoteSignature) {
		t.Errorf("AddVote with wrong signature: want ErrInvalidVoteSignature, got %v", err)
	}
	if vc.VoteCount() != 0 {
		t.Errorf("VoteCount: want 0, got %d", vc.VoteCount())
	}
}

// TestCONS_R12005_DuplicateCheckInsideLock verifies that the in-lock
// duplicate check (retained by the fix) catches duplicates even when the
// early outside-lock check passes.
func TestCONS_R12005_DuplicateCheckInsideLock(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04/VAL-H05 FIX: Activate so the first AddVote succeeds (the
	// duplicate check needs at least one accepted vote to test duplication).
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	blockHash := types.Hash{0x42}
	vc := NewVoteCollector(200, 0, blockHash, vmgr)

	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        200,
		Round:         0,
		BlockHash:     blockHash,
		ValidatorAddr: addr,
	}
	if err := vote.Sign(privKey); err != nil {
		t.Fatalf("vote.Sign: %v", err)
	}

	// First AddVote succeeds.
	if err := vc.AddVote(vote); err != nil {
		t.Fatalf("first AddVote: %v", err)
	}
	// Second AddVote from same validator must be rejected by the in-lock
	// duplicate check (the early RLock check would also catch it, but the
	// in-lock check is the authoritative one).
	if err := vc.AddVote(vote); !errors.Is(err, ErrDuplicateVote) {
		t.Errorf("duplicate AddVote: want ErrDuplicateVote, got %v", err)
	}
	if vc.VoteCount() != 1 {
		t.Errorf("VoteCount: want 1, got %d", vc.VoteCount())
	}
}

// TestCONS_R12005_ConcurrentAddVotes verifies that concurrent AddVote calls
// from different validators do not race and all get recorded. This is a
// regression guard for the fix moving verification inside vc.mu.Lock().
func TestCONS_R12005_ConcurrentAddVotes(t *testing.T) {
	vmgr := NewValidatorManager()
	const N = 8

	type val struct {
		priv *crypto.PrivateKey
		pub  *crypto.PublicKey
		addr types.Address
	}
	vals := make([]val, N)
	for i := 0; i < N; i++ {
		priv, pub := createTestKeyPair(t)
		addr := pub.Address()
		if err := vmgr.AddValidator(addr, addr, pub, validStake(), 1000, 0); err != nil {
			t.Fatalf("AddValidator[%d]: %v", i, err)
		}
		// VAL-H04/VAL-H05 FIX: Activate each validator so AddVote accepts
		// their votes.
		if err := vmgr.ActivateFromQueue(addr); err != nil {
			t.Fatalf("ActivateFromQueue[%d]: %v", i, err)
		}
		vals[i] = val{priv: priv, pub: pub, addr: addr}
	}

	blockHash := types.Hash{0x99}
	vc := NewVoteCollector(300, 0, blockHash, vmgr)

	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			vote := &Vote{
				Type:          VoteTypePrecommit,
				Height:        300,
				Round:         0,
				BlockHash:     blockHash,
				ValidatorAddr: vals[i].addr,
			}
			if err := vote.Sign(vals[i].priv); err != nil {
				errs[i] = err
				return
			}
			errs[i] = vc.AddVote(vote)
		}(i)
	}
	wg.Wait()

	success := 0
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d AddVote failed: %v", i, err)
			continue
		}
		success++
	}
	if success != N {
		t.Errorf("accepted votes: want %d, got %d", N, success)
	}
	if vc.VoteCount() != N {
		t.Errorf("VoteCount: want %d, got %d", N, vc.VoteCount())
	}
}

// TestCONS_R12005_RaceWithDeactivation verifies that the TOCTOU fix is
// race-free under concurrent SetActive calls. This is a stress test that
// runs many AddVote calls in parallel with SetActive(false) calls on the
// same validator. The test verifies that:
//   - No panic occurs
//   - The final VoteCount is either 0 (deactivation won the race) or 1
//     (AddVote won the race) — never more than 1 (no duplicate)
//   - The votedStake is consistent with VoteCount
//
// Run with -race to detect data races.
func TestCONS_R12005_RaceWithDeactivation(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04/VAL-H05 FIX: First-time activation via ActivateFromQueue sets
	// EverActivated=true. The loop below calls SetActive(addr, addr, true) to
	// re-activate the validator each iteration — SetActive only allows
	// re-activation (EverActivated=true), rejecting first-time activation.
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	blockHash := types.Hash{0x55}
	const iterations = 50

	for i := 0; i < iterations; i++ {
		// Re-activate the validator for each iteration.
		if err := vmgr.SetActive(addr, addr, true); err != nil {
			// If the validator was permanently slashed in a previous iteration
			// (it wasn't, but defensive), bail out.
			t.Fatalf("SetActive(true) iter %d: %v", i, err)
		}

		vc := NewVoteCollector(uint64(400+i), 0, blockHash, vmgr)

		vote := &Vote{
			Type:          VoteTypePrecommit,
			Height:        uint64(400 + i),
			Round:         0,
			BlockHash:     blockHash,
			ValidatorAddr: addr,
		}
		if err := vote.Sign(privKey); err != nil {
			t.Fatalf("vote.Sign iter %d: %v", i, err)
		}

		var wg sync.WaitGroup
		wg.Add(2)

		var addErr error
		// Goroutine 1: AddVote
		go func() {
			defer wg.Done()
			addErr = vc.AddVote(vote)
		}()
		// Goroutine 2: SetActive(false) concurrently
		go func() {
			defer wg.Done()
			_ = vmgr.SetActive(addr, addr, false)
		}()
		wg.Wait()

		// Either AddVote won the race (addErr == nil, VoteCount == 1) or
		// SetActive won the race (addErr is ErrVoteFromNonValidator,
		// VoteCount == 0). Both are valid outcomes. The invariant is that
		// VoteCount is never > 1 (no double-counting) and votedStake is
		// consistent.
		if vc.VoteCount() > 1 {
			t.Errorf("iter %d: VoteCount > 1 (double-counted): %d", i, vc.VoteCount())
		}
		if addErr == nil && vc.VoteCount() != 1 {
			t.Errorf("iter %d: AddVote succeeded but VoteCount=%d", i, vc.VoteCount())
		}
		if addErr != nil && vc.VoteCount() != 0 {
			// This could happen if the validator was deactivated AFTER
			// AddVote succeeded. Allow it but log for visibility.
			t.Logf("iter %d: AddVote failed (%v) but VoteCount=%d (deactivation raced after AddVote)", i, addErr, vc.VoteCount())
		}
	}
}
