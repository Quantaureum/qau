// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
)

// TestCHAMBER_H03_CanSeal_RejectsStaleEpochMembership verifies the
// CHAMBER-H03 fix: a validator assigned to Executive for epoch N must
// NOT pass CanSeal in epoch N+1 unless explicitly re-assigned.
//
// CHAMBER-H03 (R29, 2026-07-25): Previously CanSeal used
// ChamberAssignment.IsInChamber which ignored the Epoch field on
// ChamberRole. The ChamberAssignment.roles map is
// map[int]*ChamberRole (one role per validator, overwritten on each
// Assign), so it cannot represent "validator X is Executive for
// epoch N AND not Executive for epoch N+1". A validator assigned to
// Executive for epoch N would still pass CanSeal in epoch N+1 if the
// stale role hadn't been pruned yet, allowing an ex-Executive member
// to submit partial QTD seals in the wrong epoch.
//
// The fix uses epochExecutive map (map[uint64][]int) which stores the
// exact Executive member list per epoch. CanSeal now requires the
// validator to be in epochExecutive[epoch].
func TestCHAMBER_H03_CanSeal_RejectsStaleEpochMembership(t *testing.T) {
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

	// Assign Executive for epoch 5 only.
	if err := coordinator.AssignExecutive([]int{4, 5, 6}, 5); err != nil {
		t.Fatalf("AssignExecutive(epoch=5) failed: %v", err)
	}
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	// Verify CanSeal for epoch 5 returns true for assigned members.
	for _, idx := range []int{4, 5, 6} {
		if !coordinator.CanSeal(idx, 5) {
			t.Errorf("validator %d should be able to seal in epoch 5 (assigned)", idx)
		}
	}

	// Verify CanSeal for epoch 6 (NOT assigned) returns false.
	// CHAMBER-H03 fix: previously this would return true because
	// IsInChamber ignored the Epoch field.
	for _, idx := range []int{4, 5, 6} {
		if coordinator.CanSeal(idx, 6) {
			t.Errorf("validator %d should NOT be able to seal in epoch 6 (not assigned for epoch 6) — CHAMBER-H03 bypass",
				idx)
		}
	}

	// Verify CanSeal for epoch 4 (also not assigned) returns false.
	for _, idx := range []int{4, 5, 6} {
		if coordinator.CanSeal(idx, 4) {
			t.Errorf("validator %d should NOT be able to seal in epoch 4 (not assigned for epoch 4) — CHAMBER-H03 bypass",
				idx)
		}
	}

	// Verify non-executive validators cannot seal in any epoch.
	for _, idx := range []int{0, 1, 2, 3, 7, 8, 9} {
		if coordinator.CanSeal(idx, 5) {
			t.Errorf("non-executive validator %d should NOT be able to seal in epoch 5", idx)
		}
	}
}

// TestCHAMBER_H03_CanSeal_FailClosedOnUnassignedEpoch verifies that
// CanSeal returns false (fail-closed) when no Executive assignment
// exists for the given epoch.
//
// This is a defensive check: during epoch transitions before the new
// Executive is elected, CanSeal must fail-closed rather than allow
// any validator to seal.
func TestCHAMBER_H03_CanSeal_FailClosedOnUnassignedEpoch(t *testing.T) {
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

	// Assign Executive for epoch 5 only.
	_ = coordinator.AssignExecutive([]int{4, 5, 6}, 5)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	// Epoch 999 has no Executive assignment → fail-closed.
	for _, idx := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9} {
		if coordinator.CanSeal(idx, 999) {
			t.Errorf("validator %d should NOT be able to seal in epoch 999 (no Executive assignment — fail-closed)",
				idx)
		}
	}
}

// TestCHAMBER_H03_CanSeal_PerEpochIsolation verifies that two different
// epochs can have different Executive members, and CanSeal correctly
// distinguishes them. This is the core security guarantee of the
// CHAMBER-H03 fix.
func TestCHAMBER_H03_CanSeal_PerEpochIsolation(t *testing.T) {
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

	// Epoch 5: Executive = {4, 5, 6}
	_ = coordinator.AssignExecutive([]int{4, 5, 6}, 5)
	// Epoch 6: Executive = {7, 8, 9} (different members)
	_ = coordinator.AssignExecutive([]int{7, 8, 9}, 6)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	// Epoch 5: {4,5,6} can seal, {7,8,9} cannot.
	for _, idx := range []int{4, 5, 6} {
		if !coordinator.CanSeal(idx, 5) {
			t.Errorf("validator %d should seal in epoch 5", idx)
		}
	}
	for _, idx := range []int{7, 8, 9} {
		if coordinator.CanSeal(idx, 5) {
			t.Errorf("validator %d should NOT seal in epoch 5 (only epoch 6)", idx)
		}
	}

	// Epoch 6: {7,8,9} can seal, {4,5,6} cannot.
	for _, idx := range []int{7, 8, 9} {
		if !coordinator.CanSeal(idx, 6) {
			t.Errorf("validator %d should seal in epoch 6", idx)
		}
	}
	for _, idx := range []int{4, 5, 6} {
		if coordinator.CanSeal(idx, 6) {
			t.Errorf("validator %d should NOT seal in epoch 6 (only epoch 5)", idx)
		}
	}
}
