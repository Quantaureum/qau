// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestChamberIDString(t *testing.T) {
	tests := []struct {
		id       ChamberID
		expected string
	}{
		{ChamberNone, "None"},
		{ChamberProposing, "Proposing Chamber"},
		{ChamberReview, "Review Chamber"},
		{ChamberExecutive, "Executive Chamber"},
		{ChamberID(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.id.String(); got != tt.expected {
			t.Errorf("ChamberID(%d).String() = %q, want %q", tt.id, got, tt.expected)
		}
	}
}

func TestChamberAssignmentBasic(t *testing.T) {
	pa := NewChamberAssignment()

	pa.Assign(0, ChamberProposing, 1, 0)
	pa.Assign(1, ChamberReview, 1, 0)
	pa.Assign(2, ChamberExecutive, 0, 0)

	if !pa.IsInChamber(0, ChamberProposing) {
		t.Error("validator 0 should be in Proposing Chamber")
	}
	if !pa.IsInChamber(1, ChamberReview) {
		t.Error("validator 1 should be in Review Chamber")
	}
	if !pa.IsInChamber(2, ChamberExecutive) {
		t.Error("validator 2 should be in Executive Chamber")
	}
	if pa.IsInChamber(0, ChamberReview) {
		t.Error("validator 0 should NOT be in Review Chamber")
	}
	if pa.IsInChamber(0, ChamberExecutive) {
		t.Error("validator 0 should NOT be in Executive Chamber")
	}

	proposing := pa.GetValidatorsInChamber(ChamberProposing)
	if len(proposing) != 1 || proposing[0] != 0 {
		t.Errorf("Proposing members = %v, want [0]", proposing)
	}

	review := pa.GetValidatorsInChamber(ChamberReview)
	if len(review) != 1 || review[0] != 1 {
		t.Errorf("Review members = %v, want [1]", review)
	}
}

func TestChamberAssignmentClearSlot(t *testing.T) {
	pa := NewChamberAssignment()

	pa.Assign(0, ChamberProposing, 5, 0)
	pa.Assign(1, ChamberReview, 5, 0)
	pa.Assign(2, ChamberProposing, 6, 0)

	pa.ClearSlot(5)

	if pa.IsInChamber(0, ChamberProposing) {
		t.Error("validator 0 should be cleared after ClearSlot(5)")
	}
	if pa.IsInChamber(1, ChamberReview) {
		t.Error("validator 1 should be cleared after ClearSlot(5)")
	}
	if !pa.IsInChamber(2, ChamberProposing) {
		t.Error("validator 2 should still be in Proposing Chamber (slot 6)")
	}
}

func TestExecutiveChamberBasic(t *testing.T) {
	sc := NewExecutiveChamber(3, 2)

	if sc.Size() != 3 {
		t.Errorf("Size() = %d, want 3", sc.Size())
	}
	if sc.Threshold() != 2 {
		t.Errorf("Threshold() = %d, want 2", sc.Threshold())
	}
	if sc.State() != ExecutiveIdle {
		t.Errorf("State() = %v, want Idle", sc.State())
	}

	err := sc.SetMembers([]int{0, 1, 2}, 1)
	if err != nil {
		t.Fatalf("SetMembers failed: %v", err)
	}

	if sc.State() != ExecutiveDKGRunning {
		t.Errorf("State() = %v, want DKGRunning", sc.State())
	}
	if !sc.IsMember(0) || !sc.IsMember(1) || !sc.IsMember(2) {
		t.Error("All members should be recognized")
	}
	if sc.IsMember(3) {
		t.Error("Validator 3 should not be a member")
	}

	_ = sc.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	if sc.State() != ExecutiveActive {
		t.Errorf("State() = %v, want Active", sc.State())
	}
	if !sc.IsActive() {
		t.Error("Chamber should be active after DKG")
	}

	sc.StartSealing()
	if sc.State() != ExecutiveSealing {
		t.Errorf("State() = %v, want Sealing", sc.State())
	}

	sc.RecordSeal(true)
	sc.RecordSeal(true)
	sc.RecordSeal(false)

	stats := sc.Stats()
	if stats["sealCount"].(uint64) != 2 {
		t.Errorf("sealCount = %v, want 2", stats["sealCount"])
	}
	if stats["sealFail"].(uint64) != 1 {
		t.Errorf("sealFail = %v, want 1", stats["sealFail"])
	}
}

func TestExecutiveChamberValidation(t *testing.T) {
	sc := NewExecutiveChamber(3, 2)

	// M4-FIX (2026-08-18): SetMembers now accepts 1 to size members
	// (dynamic sizing for small validator sets). 2 members for a size-3
	// chamber is now valid.
	err := sc.SetMembers([]int{0, 1}, 1)
	if err != nil {
		t.Errorf("SetMembers with 2 members for size-3 chamber should work (dynamic sizing): %v", err)
	}

	// Re-create for the duplicate test
	sc = NewExecutiveChamber(3, 2)
	err = sc.SetMembers([]int{0, 0, 1}, 1)
	if err == nil {
		t.Error("SetMembers with duplicate members should fail")
	}

	// Empty members should still fail
	sc = NewExecutiveChamber(3, 2)
	err = sc.SetMembers([]int{}, 1)
	if err == nil {
		t.Error("SetMembers with empty members should fail")
	}
}

func TestThreeChambersPowerSeparation(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	if !qpos.HasChambers() {
		t.Fatal("QPOS should have chambers after InitChambers")
	}

	coordinator := qpos.GetChambersCoordinator()

	err = coordinator.AssignProposing(0, 1)
	if err != nil {
		t.Fatalf("AssignProposing failed: %v", err)
	}

	if !qpos.CanPropose(0, 1) {
		t.Error("Validator 0 should be able to propose (is Proposing)")
	}
	if qpos.CanAttest(0, 1) {
		t.Error("Validator 0 should NOT be able to attest (is Proposing)")
	}
	if qpos.CanSeal(0, 0) {
		t.Error("Validator 0 should NOT be able to seal (is Proposing)")
	}

	err = coordinator.AssignReview([]int{1, 2, 3}, 1)
	if err != nil {
		t.Fatalf("AssignReview failed: %v", err)
	}

	for _, idx := range []int{1, 2, 3} {
		if qpos.CanPropose(idx, 1) {
			t.Errorf("Validator %d should NOT propose (is Review)", idx)
		}
		if !qpos.CanAttest(idx, 1) {
			t.Errorf("Validator %d should be able to attest (is Review)", idx)
		}
		if qpos.CanSeal(idx, 0) {
			t.Errorf("Validator %d should NOT seal (is Review)", idx)
		}
	}

	err = coordinator.AssignExecutive([]int{4, 5, 6}, 0)
	if err != nil {
		t.Fatalf("AssignExecutive failed: %v", err)
	}

	// R93-CHAMBER-DEGRADED (2026-08-30): the Executive chamber's propose/attest
	// exclusion now applies only while the chamber is genuinely ACTIVE (DKG
	// complete). AssignExecutive alone leaves it in ExecutiveIdle, in which
	// state members intentionally keep their rights — see
	// executiveRestrictionsActiveLocked. Drive the chamber to ExecutiveActive so
	// this test keeps asserting what it was written to assert: power separation
	// under an operational chamber.
	if err := coordinator.executive.SetMembers([]int{4, 5, 6}, 0); err != nil {
		t.Fatalf("SetMembers failed: %v", err)
	}
	activateExecutive(t, coordinator)

	for _, idx := range []int{4, 5, 6} {
		if qpos.CanPropose(idx, 1) {
			t.Errorf("Validator %d should NOT propose (is Executive)", idx)
		}
		if qpos.CanAttest(idx, 1) {
			t.Errorf("Validator %d should NOT attest (is Executive)", idx)
		}
		if !qpos.CanSeal(idx, 0) {
			t.Errorf("Validator %d should be able to seal (is Executive)", idx)
		}
	}

	t.Log("=== 2.1 Three Chambers power separation: PASS ===")
}

func TestThreeChambersConflictPrevention(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()

	err = coordinator.AssignProposing(0, 1)
	if err != nil {
		t.Fatalf("AssignProposing failed: %v", err)
	}

	err = coordinator.AssignReview([]int{0, 1}, 1)
	if err == nil {
		t.Error("Should fail: validator 0 already in Proposing cannot join Review")
	}

	err = coordinator.AssignExecutive([]int{0, 2, 3}, 0)
	if err == nil {
		t.Error("Should fail: validator 0 already in Proposing cannot join Executive")
	}

	err = coordinator.AssignReview([]int{1, 2, 3}, 1)
	if err != nil {
		t.Fatalf("AssignReview for non-conflicting validators should succeed: %v", err)
	}

	err = coordinator.AssignExecutive([]int{1, 4, 5}, 0)
	if err == nil {
		t.Error("Should fail: validator 1 already in Review cannot join Executive")
	}

	t.Log("=== 2.1 Cross-chamber conflict prevention: PASS ===")
}

func TestExecutiveSelectionForEpoch(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()

	members, err := coordinator.SelectExecutiveForEpoch(1, vs)
	if err != nil {
		t.Fatalf("SelectExecutiveForEpoch failed: %v", err)
	}

	// M4-FIX (2026-08-18): Executive size is now dynamic based on
	// validator count. For 10 validators, executiveSizeForValidatorCount
	// returns 2 (10/3 - 1 = 2) to ensure enough Review Chamber members
	// can attest for 2/3 supermajority finality.
	expectedSize := 2
	if len(members) != expectedSize {
		t.Fatalf("Expected %d Executive members, got %d", expectedSize, len(members))
	}

	memberSet := make(map[int]bool)
	for _, m := range members {
		if memberSet[m] {
			t.Errorf("Duplicate member %d in Executive chamber", m)
		}
		memberSet[m] = true
	}

	// R93-CHAMBER-DEGRADED (2026-08-30): activate the chamber before asserting
	// the propose/attest exclusion — SelectExecutiveForEpoch only elects members,
	// it does not complete DKG, and an inactive chamber no longer strips rights.
	if err := coordinator.executive.SetMembers(members, 1); err != nil {
		t.Fatalf("SetMembers failed: %v", err)
	}
	activateExecutive(t, coordinator)

	for _, m := range members {
		if !qpos.CanSeal(m, 1) {
			t.Errorf("Executive member %d should be able to seal", m)
		}
		// R53-FIX (2026-08-06): CanPropose/CanAttest are now epoch-scoped.
		// Executive members are blocked from proposing/attesting only within
		// their own epoch (slot 32 = first slot of epoch 1). The previous
		// assertion used slot 1 (epoch 0), which is outside the Executive
		// member's epoch and must now be allowed.
		if qpos.CanPropose(m, 32) {
			t.Errorf("Executive member %d should NOT be able to propose in its epoch", m)
		}
		if qpos.CanAttest(m, 32) {
			t.Errorf("Executive member %d should NOT be able to attest in its epoch", m)
		}
	}

	members2, err := coordinator.SelectExecutiveForEpoch(1, vs)
	if err != nil {
		t.Fatalf("Second SelectExecutiveForEpoch should return cached: %v", err)
	}
	if len(members2) != len(members) {
		t.Error("Cached result should match original")
	}

	t.Log("=== 2.1 Executive chamber selection: PASS ===")
}

// TestTransitionExecutiveForEpoch verifies P0-2: that TransitionExecutiveForEpoch
// selects members, sets them on the ExecutiveChamber, and activates it when
// a group public key is provided.
// 03-P0-2 (2026-07-14)
func TestTransitionExecutiveForEpoch(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil after InitChambers")
	}

	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}

	// Before transition: executive should NOT be active
	if executive.IsActive() {
		t.Error("executive should not be active before transition")
	}

	// Case 1: Transition with non-empty groupPublicKey → should activate
	// Key must satisfy SetDKGComplete's min length (GOV-R7-01).
	groupPk := make([]byte, minGroupPublicKeyLen)
	err = coordinator.TransitionExecutiveForEpoch(1, vs, groupPk)
	if err != nil {
		t.Fatalf("TransitionExecutiveForEpoch failed: %v", err)
	}

	if !executive.IsActive() {
		t.Error("executive should be active after transition with group public key")
	}

	// Verify epoch is set
	if executive.Epoch() != 1 {
		t.Errorf("expected epoch 1, got %d", executive.Epoch())
	}

	// Case 2: Idempotency — calling again for same epoch should be no-op
	err = coordinator.TransitionExecutiveForEpoch(1, vs, groupPk)
	if err != nil {
		t.Fatalf("idempotent transition should succeed: %v", err)
	}

	t.Log("=== P0-2 Executive chamber transition: PASS ===")
}

// TestTransitionExecutiveForEpoch_NoGroupKey verifies that without a group
// public key, the executive chamber is selected but NOT activated (DKG pending).
// 03-P0-2 (2026-07-14)
func TestTransitionExecutiveForEpoch_NoGroupKey(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	executive := coordinator.GetExecutiveChamber()

	// R88-F: high-genesis exemption — see SelectExecutiveForEpoch guard.
	qpos.SetFirstBlockEpoch(2)

	// Transition with nil groupPublicKey → members selected but DKG pending
	err = coordinator.TransitionExecutiveForEpoch(2, vs, nil)
	if err != nil {
		t.Fatalf("TransitionExecutiveForEpoch with nil groupPk failed: %v", err)
	}

	// Executive should NOT be active (DKG not complete)
	if executive.IsActive() {
		t.Error("executive should not be active without DKG completion")
	}

	// But epoch should be set (members were selected)
	if executive.Epoch() != 2 {
		t.Errorf("expected epoch 2, got %d", executive.Epoch())
	}

	t.Log("=== P0-2 Executive DKG pending: PASS ===")
}

func TestGetProposerForSlotWithChambers(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	proposer1, err := qpos.GetProposerForSlot(0)
	if err != nil {
		t.Fatalf("GetProposerForSlot without chambers failed: %v", err)
	}
	if proposer1 == nil {
		t.Fatal("Proposer should not be nil")
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)

	proposer2, err := qpos.GetProposerForSlot(0)
	if err != nil {
		t.Fatalf("GetProposerForSlot with chambers failed: %v", err)
	}
	if proposer2 == nil {
		t.Fatal("Proposer should not be nil even with chambers")
	}

	t.Logf("Proposer without chambers: %s", proposer1.Address.String()[:8])
	t.Logf("Proposer with chambers: %s", proposer2.Address.String()[:8])
	t.Log("=== 2.1 GetProposerForSlot with chambers: PASS ===")
}

func TestChamberStatus(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()

	_ = coordinator.AssignProposing(0, 1)
	_ = coordinator.AssignReview([]int{1, 2, 3}, 1)
	_ = coordinator.AssignExecutive([]int{4, 5, 6}, 0)

	status := coordinator.GetChamberStatus()
	if status == nil {
		t.Fatal("GetChamberStatus should not return nil")
	}

	proposing := status["proposing"].(map[string]any)
	if proposing["count"].(int) != 1 {
		t.Errorf("Proposing count = %v, want 1", proposing["count"])
	}

	review := status["review"].(map[string]any)
	if review["count"].(int) != 3 {
		t.Errorf("Review count = %v, want 3", review["count"])
	}

	executive := status["executive"].(map[string]any)
	if executive["count"].(int) != 3 {
		t.Errorf("Executive count = %v, want 3", executive["count"])
	}

	t.Log("=== 2.1 Chamber status reporting: PASS ===")
}

func TestChamberCleanup(t *testing.T) {
	pa := NewChamberAssignment()

	pa.Assign(0, ChamberProposing, 5, 0)
	pa.Assign(1, ChamberReview, 5, 0)
	pa.Assign(2, ChamberExecutive, 0, 1)

	pa.ClearSlot(5)

	if pa.IsInChamber(0, ChamberProposing) {
		t.Error("Slot 5 assignments should be cleared")
	}
	if pa.IsInChamber(1, ChamberReview) {
		t.Error("Slot 5 assignments should be cleared")
	}
	if !pa.IsInChamber(2, ChamberExecutive) {
		t.Error("Executive (epoch-based) should NOT be cleared by ClearSlot")
	}

	pa.ClearEpoch(1)
	if pa.IsInChamber(2, ChamberExecutive) {
		t.Error("Executive epoch 1 should be cleared by ClearEpoch")
	}
}

func createTestValidatorSet(t *testing.T, count int) *ValidatorSet {
	t.Helper()
	validators := make([]*Validator, count)
	for i := 0; i < count; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		addr[1] = byte(i >> 8)
		validators[i] = &Validator{
			Address:        addr,
			Stake:          big.NewInt(1000),
			Active:         true,
			Commission:     0,
			PublicKeyBytes: make([]byte, 1952),
		}
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("createTestValidatorSet failed: %v", err)
	}
	return vs
}
