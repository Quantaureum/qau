// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ── P1-4: QPOS DA availability checker tests ──

// TestQPOS_SetDAAvailabilityChecker verifies the setter stores and clears
// the DA availability checker callback. P1-4 (2026-07-14).
func TestQPOS_SetDAAvailabilityChecker(t *testing.T) {
	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Initially nil.
	if qpos.daAvailabilityCheck != nil {
		t.Error("expected nil daAvailabilityCheck by default")
	}

	// Set a checker.
	called := false
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		called = true
		return nil
	})
	if qpos.daAvailabilityCheck == nil {
		t.Error("expected non-nil daAvailabilityCheck after set")
	}

	// CheckDAAvailability should call the checker.
	if err := qpos.CheckDAAvailability(1); err != nil {
		t.Errorf("CheckDAAvailability returned error: %v", err)
	}
	if !called {
		t.Error("expected checker to be called")
	}

	// Clear by setting nil.
	qpos.SetDAAvailabilityChecker(nil)
	if qpos.daAvailabilityCheck != nil {
		t.Error("expected nil daAvailabilityCheck after clearing")
	}
}

// TestQPOS_CheckDAAvailability_NoChecker verifies that CheckDAAvailability
// returns nil (available) when no checker is configured. P1-4 (2026-07-14).
func TestQPOS_CheckDAAvailability_NoChecker(t *testing.T) {
	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	if err := qpos.CheckDAAvailability(1); err != nil {
		t.Errorf("expected nil error when no checker, got %v", err)
	}
}

// TestQPOS_CheckDAAvailability_Available verifies that CheckDAAvailability
// returns nil when the checker reports DA as available. P1-4 (2026-07-14).
func TestQPOS_CheckDAAvailability_Available(t *testing.T) {
	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return nil // DA available
	})

	if err := qpos.CheckDAAvailability(42); err != nil {
		t.Errorf("expected nil for available DA, got %v", err)
	}
}

// TestQPOS_CheckDAAvailability_NotAvailable verifies that CheckDAAvailability
// returns the checker's error when DA is not available. P1-4 (2026-07-14).
func TestQPOS_CheckDAAvailability_NotAvailable(t *testing.T) {
	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	errDA := errors.New("DA sampling failed: 30% available < 66.67% threshold")
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return errDA
	})

	err = qpos.CheckDAAvailability(42)
	if err == nil {
		t.Fatal("expected error for unavailable DA, got nil")
	}
	if !errors.Is(err, errDA) {
		t.Errorf("expected errDA, got %v", err)
	}
}

// TestQPOS_CanPropose_DASoftCheck verifies that CanPropose STILL returns true
// even when the DA check fails — the check is soft (log warning only).
// Liveness takes priority over strictness at the proposal stage.
// P1-4 (2026-07-14).
func TestQPOS_CanPropose_DASoftCheck(t *testing.T) {
	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Set a DA checker that always fails.
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return errors.New("DA unavailable")
	})

	// CanPropose should still return true (soft check, non-blocking).
	// slot=1 → checks parent slot 0.
	result := qpos.CanPropose(0, 1)
	if !result {
		t.Error("CanPropose should return true even when DA check fails (soft check, liveness priority)")
	}
}

// TestQPOS_CanPropose_NoDAChecker verifies that CanPropose works normally
// when no DA checker is configured. P1-4 (2026-07-14).
func TestQPOS_CanPropose_NoDAChecker(t *testing.T) {
	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// No DA checker — CanPropose should work normally.
	result := qpos.CanPropose(0, 1)
	if !result {
		t.Error("CanPropose should return true when no DA checker is configured")
	}
}

// ── P1-4: ThreeChambersFlow FinalizeBlock DA tests ──

// TestThreeChambersFlow_FinalizeBlock_DARefused verifies that FinalizeBlock
// REFUSES to finalize when the DA availability check fails. P1-4 (2026-07-14).
// This is the HARD check — blocks with unavailable DA must not be finalized.
func TestThreeChambersFlow_FinalizeBlock_DARefused(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	flow := NewThreeChambersFlow(qpos, coordinator)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	// Propose → Review → Seal → Complete QTD → attempt Finalize
	if err := flow.ProposeBlock(1, blockHash, 3); err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[1] = &ReviewSlotResult{
		Slot:          1,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	if err := flow.ReviewBlock(1); err != nil {
		t.Fatalf("ReviewBlock failed: %v", err)
	}
	if err := flow.SealBlock(1); err != nil {
		t.Fatalf("SealBlock failed: %v", err)
	}

	// Submit partial seals to complete QTD threshold (2-of-3).
	for _, member := range []int{0, 1, 2} {
		mockSig := []byte("partial-seal-" + string(rune('A'+member)) + "-min16bytes")
		if err := qfs.SubmitPartialSeal(member, 1, mockSig); err != nil {
			break
		}
	}
	if err := flow.CompleteSeal(1); err != nil {
		t.Fatalf("CompleteSeal failed: %v", err)
	}

	// Now set a DA checker that ALWAYS FAILS.
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return errors.New("DA sampling failed: blob data not available")
	})

	// FinalizeBlock should REFUSE — DA not available.
	err = flow.FinalizeBlock(1)
	if err == nil {
		t.Fatal("FinalizeBlock should fail when DA check fails, but returned nil")
	}

	// Verify the block is NOT finalized.
	lc := flow.GetLifecycle(1)
	if lc.Phase == PhaseFinalized {
		t.Error("block should NOT be finalized when DA check fails")
	}
}

// TestThreeChambersFlow_FinalizeBlock_DAAvailable verifies that FinalizeBlock
// SUCCEEDS when the DA availability check passes. P1-4 (2026-07-14).
func TestThreeChambersFlow_FinalizeBlock_DAAvailable(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	flow := NewThreeChambersFlow(qpos, coordinator)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	if err := flow.ProposeBlock(1, blockHash, 3); err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[1] = &ReviewSlotResult{
		Slot:          1,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	if err := flow.ReviewBlock(1); err != nil {
		t.Fatalf("ReviewBlock failed: %v", err)
	}
	if err := flow.SealBlock(1); err != nil {
		t.Fatalf("SealBlock failed: %v", err)
	}

	for _, member := range []int{0, 1, 2} {
		mockSig := []byte("partial-seal-" + string(rune('A'+member)) + "-min16bytes")
		if err := qfs.SubmitPartialSeal(member, 1, mockSig); err != nil {
			break
		}
	}
	if err := flow.CompleteSeal(1); err != nil {
		t.Fatalf("CompleteSeal failed: %v", err)
	}

	// Set a DA checker that SUCCEEDS (returns nil = available).
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return nil
	})

	// FinalizeBlock should SUCCEED — DA is available.
	if err := flow.FinalizeBlock(1); err != nil {
		t.Fatalf("FinalizeBlock should succeed when DA is available, got: %v", err)
	}

	lc := flow.GetLifecycle(1)
	if lc.Phase != PhaseFinalized {
		t.Errorf("expected PhaseFinalized, got %v", lc.Phase)
	}
}

// TestThreeChambersFlow_FinalizeBlock_NoChecker verifies that FinalizeBlock
// SUCCEEDS when no DA checker is configured (DA verification is opt-in).
// P1-4 (2026-07-14).
func TestThreeChambersFlow_FinalizeBlock_NoChecker(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	flow := NewThreeChambersFlow(qpos, coordinator)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	if err := flow.ProposeBlock(1, blockHash, 3); err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[1] = &ReviewSlotResult{
		Slot:          1,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	if err := flow.ReviewBlock(1); err != nil {
		t.Fatalf("ReviewBlock failed: %v", err)
	}
	if err := flow.SealBlock(1); err != nil {
		t.Fatalf("SealBlock failed: %v", err)
	}

	for _, member := range []int{0, 1, 2} {
		mockSig := []byte("partial-seal-" + string(rune('A'+member)) + "-min16bytes")
		if err := qfs.SubmitPartialSeal(member, 1, mockSig); err != nil {
			break
		}
	}
	if err := flow.CompleteSeal(1); err != nil {
		t.Fatalf("CompleteSeal failed: %v", err)
	}

	// No DA checker configured — FinalizeBlock should succeed (opt-in).
	if err := flow.FinalizeBlock(1); err != nil {
		t.Fatalf("FinalizeBlock should succeed with no DA checker, got: %v", err)
	}

	lc := flow.GetLifecycle(1)
	if lc.Phase != PhaseFinalized {
		t.Errorf("expected PhaseFinalized, got %v", lc.Phase)
	}
}
