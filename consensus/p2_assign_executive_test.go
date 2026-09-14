// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"os"
	"strings"
	"testing"
)

// TestP2_ASSIGN_EXECUTIVE_ProductionModeRejected verifies that
// AssignExecutive returns ErrAssignExecutiveDisabledInProduction when
// QAU_PRODUCTION=1 is set in the environment.
//
// P2-ASSIGN-EXECUTIVE FIX (R29, 2026-07-26): In production mode, direct
// Executive assignment is forbidden — production code MUST use
// TransitionExecutiveForEpoch, which runs VRF-based stake-weighted random
// selection (SelectExecutiveForEpoch) and enforces the requireDistributedDKG
// production gate. This test confirms the QAU_PRODUCTION hard gate works.
func TestP2_ASSIGN_EXECUTIVE_ProductionModeRejected(t *testing.T) {
	// Save and restore QAU_PRODUCTION env var.
	orig := os.Getenv("QAU_PRODUCTION")
	defer func() {
		if orig == "" {
			os.Unsetenv("QAU_PRODUCTION")
		} else {
			os.Setenv("QAU_PRODUCTION", orig)
		}
	}()

	os.Setenv("QAU_PRODUCTION", "1")

	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}

	err = coordinator.AssignExecutive([]int{0, 1, 2}, 999)
	if err == nil {
		t.Fatal("P2-ASSIGN-EXECUTIVE REGRESSION: AssignExecutive should fail in QAU_PRODUCTION=1 mode")
	}
	if err != ErrAssignExecutiveDisabledInProduction {
		t.Errorf("AssignExecutive in QAU_PRODUCTION=1 returned wrong error: got %v, want %v",
			err, ErrAssignExecutiveDisabledInProduction)
	}
}

// TestP2_ASSIGN_EXECUTIVE_RequireDistributedDKGRejected verifies that
// AssignExecutive returns ErrAssignExecutiveDisabledInProduction when
// requireDistributedDKG=true is set on the coordinator (even without
// QAU_PRODUCTION env var). This is defense-in-depth: it catches the case
// where a node is configured for mainnet (SetRequireDistributedDKG(true))
// but the QAU_PRODUCTION env var was forgotten.
func TestP2_ASSIGN_EXECUTIVE_RequireDistributedDKGRejected(t *testing.T) {
	// Ensure QAU_PRODUCTION is NOT set (so only the requireDistributedDKG
	// gate is active).
	orig := os.Getenv("QAU_PRODUCTION")
	defer func() {
		if orig == "" {
			os.Unsetenv("QAU_PRODUCTION")
		} else {
			os.Setenv("QAU_PRODUCTION", orig)
		}
	}()
	os.Unsetenv("QAU_PRODUCTION")

	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}

	// Enable the distributed DKG production gate (mainnet config).
	coordinator.SetRequireDistributedDKG(true)

	err = coordinator.AssignExecutive([]int{0, 1, 2}, 999)
	if err == nil {
		t.Fatal("P2-ASSIGN-EXECUTIVE REGRESSION: AssignExecutive should fail when requireDistributedDKG=true")
	}
	if err != ErrAssignExecutiveDisabledInProduction &&
		!strings.Contains(err.Error(), "requireDistributedDKG=true") {
		t.Errorf("AssignExecutive with requireDistributedDKG=true returned wrong error: got %v, want %v (or wrapped)",
			err, ErrAssignExecutiveDisabledInProduction)
	}
}

// TestP2_ASSIGN_EXECUTIVE_IdempotencyCheck verifies that a second
// AssignExecutive call for the SAME epoch is rejected with
// ErrExecutiveAlreadyAssigned. This prevents a second direct call from
// silently overwriting legitimate VRF-selected members with
// attacker-chosen ones.
func TestP2_ASSIGN_EXECUTIVE_IdempotencyCheck(t *testing.T) {
	// Ensure QAU_PRODUCTION is NOT set.
	orig := os.Getenv("QAU_PRODUCTION")
	defer func() {
		if orig == "" {
			os.Unsetenv("QAU_PRODUCTION")
		} else {
			os.Setenv("QAU_PRODUCTION", orig)
		}
	}()
	os.Unsetenv("QAU_PRODUCTION")

	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}

	// First call for epoch 999 should succeed.
	if err := coordinator.AssignExecutive([]int{0, 1, 2}, 999); err != nil {
		t.Fatalf("first AssignExecutive for epoch 999 failed: %v", err)
	}

	// Second call for the SAME epoch with DIFFERENT members must fail.
	// This is the core idempotency check — without it, an attacker could
	// silently overwrite the legitimate assignment mid-epoch.
	err = coordinator.AssignExecutive([]int{7, 8, 9}, 999)
	if err == nil {
		t.Fatal("P2-ASSIGN-EXECUTIVE REGRESSION: second AssignExecutive for same epoch should fail (idempotency)")
	}
	if err != ErrExecutiveAlreadyAssigned &&
		!strings.Contains(err.Error(), "already has executive members") {
		t.Errorf("second AssignExecutive returned wrong error: got %v, want %v (or wrapped)",
			err, ErrExecutiveAlreadyAssigned)
	}

	// Verify the original assignment is intact (not overwritten).
	members := coordinator.GetExecutiveMembersForEpoch(999)
	if len(members) != 3 || members[0] != 0 || members[1] != 1 || members[2] != 2 {
		t.Errorf("original assignment was overwritten: got %v, want [0 1 2]", members)
	}
}

// TestP2_ASSIGN_EXECUTIVE_DifferentEpochsAllowed verifies that
// AssignExecutive for DIFFERENT epochs still works (idempotency is
// per-epoch, not global).
func TestP2_ASSIGN_EXECUTIVE_DifferentEpochsAllowed(t *testing.T) {
	orig := os.Getenv("QAU_PRODUCTION")
	defer func() {
		if orig == "" {
			os.Unsetenv("QAU_PRODUCTION")
		} else {
			os.Setenv("QAU_PRODUCTION", orig)
		}
	}()
	os.Unsetenv("QAU_PRODUCTION")

	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}

	// Assign Executive for different epochs — each should succeed.
	for epoch := uint64(1000); epoch < 1010; epoch++ {
		if err := coordinator.AssignExecutive([]int{0, 1, 2}, epoch); err != nil {
			t.Errorf("AssignExecutive for epoch %d failed: %v", epoch, err)
		}
	}

	// Verify each epoch has its own assignment.
	for epoch := uint64(1000); epoch < 1010; epoch++ {
		members := coordinator.GetExecutiveMembersForEpoch(epoch)
		if len(members) != 3 {
			t.Errorf("epoch %d: expected 3 members, got %d", epoch, len(members))
		}
	}
}

// TestP2_ASSIGN_EXECUTIVE_FailedAssignmentDoesNotReserveEpoch verifies
// that when AssignExecutive fails (e.g., due to cross-chamber conflict),
// the epoch is NOT marked as assigned — a subsequent call with valid
// members can still succeed. This is important because the idempotency
// check should only fire when an assignment was actually stored, not when
// a previous call failed before reaching the assignment step.
func TestP2_ASSIGN_EXECUTIVE_FailedAssignmentDoesNotReserveEpoch(t *testing.T) {
	orig := os.Getenv("QAU_PRODUCTION")
	defer func() {
		if orig == "" {
			os.Unsetenv("QAU_PRODUCTION")
		} else {
			os.Setenv("QAU_PRODUCTION", orig)
		}
	}()
	os.Unsetenv("QAU_PRODUCTION")

	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}

	// Assign validator 0 to Proposing first (slot 1, epoch 0).
	if err := coordinator.AssignProposing(0, 1); err != nil {
		t.Fatalf("AssignProposing failed: %v", err)
	}

	// R53-FIX (2026-08-06): Proposing is a per-slot role (validator 0 is
	// proposing epoch 0). Executive conflicts are now per-epoch, so a
	// Proposing role only blocks Executive assignment for the SAME epoch.
	// Use epoch 0 (validator 0's proposing epoch) to exercise the conflict.
	// Try to assign validator 0 to Executive for epoch 0 — should fail with
	// cross-chamber conflict (NOT idempotency).
	err = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	if err == nil {
		t.Fatal("AssignExecutive with validator 0 (in Proposing for epoch 0) should fail with cross-chamber conflict")
	}
	if err != ErrExecutivePowerExceeded &&
		!strings.Contains(err.Error(), "executive member cannot also serve") {
		t.Errorf("expected cross-chamber conflict error, got: %v", err)
	}

	// The epoch 0 should NOT be reserved (the failed call should not
	// have stored anything). A subsequent call with valid members should
	// succeed.
	if err := coordinator.AssignExecutive([]int{3, 4, 5}, 0); err != nil {
		t.Errorf("AssignExecutive for epoch 0 with valid members should succeed after previous failure: %v", err)
	}

	// Verify the assignment.
	members := coordinator.GetExecutiveMembersForEpoch(0)
	if len(members) != 3 || members[0] != 3 || members[1] != 4 || members[2] != 5 {
		t.Errorf("epoch 0 assignment = %v, want [3 4 5]", members)
	}
}
