// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

func setupStardustEnv(t *testing.T, validatorCount int) (*QPOS, *ThreeChambersCoordinator, *ThreeChambersFlow) {
	t.Helper()
	vs := createTestValidatorSet(t, validatorCount)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	flow := NewThreeChambersFlow(qpos, coordinator)
	return qpos, coordinator, flow
}

func setupStardustWithQTD(t *testing.T, validatorCount int) (*QPOS, *ThreeChambersCoordinator, *ThreeChambersFlow) {
	t.Helper()
	qpos, coordinator, flow := setupStardustEnv(t, validatorCount)
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})
	return qpos, coordinator, flow
}

func setupFullProvinces(t *testing.T) (*QPOS, *ThreeChambersCoordinator, *ThreeChambersFlow) {
	t.Helper()
	qpos, coordinator, flow := setupStardustWithQTD(t, 10)

	_ = coordinator.AssignProposing(0, 1)
	_ = coordinator.AssignReview([]int{1, 2, 3}, 1)
	_ = coordinator.AssignExecutive([]int{4, 5, 6}, 0)

	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{4, 5, 6}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	return qpos, coordinator, flow
}

func approveSlot(coordinator *ThreeChambersCoordinator, slot uint64) {
	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[slot] = &ReviewSlotResult{
		Slot:          slot,
		CommitteeSize: 5,
		ApproveCount:  4,
		RejectCount:   1,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()
}

func rejectSlot(coordinator *ThreeChambersCoordinator, slot uint64) {
	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[slot] = &ReviewSlotResult{
		Slot:          slot,
		CommitteeSize: 5,
		ApproveCount:  1,
		RejectCount:   4,
		ApproveStake:  big.NewInt(1000),
		RejectStake:   big.NewInt(3000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictRejected,
	}
	review.mu.Unlock()
}

func TestStardustV2_Unit_PowerSeparation_NoProvinceCanDoAnything(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	if !qpos.CanPropose(0, 1) {
		t.Error("without chambers, any validator should be able to propose")
	}
	if !qpos.CanAttest(0, 1) {
		t.Error("without chambers, any validator should be able to attest")
	}
	if !qpos.CanSeal(0, 0) {
		t.Error("without chambers, any validator should be able to seal")
	}

	t.Log("✅ test-1 unit test: permissions unrestricted without chambers - PASS")
}

func TestStardustV2_Unit_PowerSeparation_StrictEnforcement(t *testing.T) {
	qpos, _, _ := setupFullProvinces(t)

	if !qpos.CanPropose(0, 1) {
		t.Error("proposing member should propose")
	}
	if qpos.CanAttest(0, 1) {
		t.Error("proposing member should NOT attest")
	}
	if qpos.CanSeal(0, 0) {
		t.Error("proposing member should NOT seal")
	}

	for _, idx := range []int{1, 2, 3} {
		if qpos.CanPropose(idx, 1) {
			t.Errorf("review member %d should NOT propose", idx)
		}
		if !qpos.CanAttest(idx, 1) {
			t.Errorf("review member %d should attest", idx)
		}
		if qpos.CanSeal(idx, 0) {
			t.Errorf("review member %d should NOT seal", idx)
		}
	}

	for _, idx := range []int{4, 5, 6} {
		if qpos.CanPropose(idx, 1) {
			t.Errorf("executive member %d should NOT propose", idx)
		}
		if qpos.CanAttest(idx, 1) {
			t.Errorf("executive member %d should NOT attest", idx)
		}
		if !qpos.CanSeal(idx, 0) {
			t.Errorf("executive member %d should seal", idx)
		}
	}

	for _, idx := range []int{7, 8, 9} {
		if !qpos.CanPropose(idx, 1) {
			t.Errorf("Unassigned validator %d should propose", idx)
		}
		if !qpos.CanAttest(idx, 1) {
			t.Errorf("Unassigned validator %d should attest", idx)
		}
		// CHAMBER-H03 FIX: CanSeal now requires explicit executive membership
		// for the epoch. Unassigned validators (7,8,9) are NOT in
		// epochExecutive[0]={4,5,6}, so CanSeal must return false. Previously
		// CanSeal returned true for any validator not in proposing/review,
		// which allowed unassigned validators to submit QTD partial seals —
		// a security gap closed by CHAMBER-H03.
		if qpos.CanSeal(idx, 0) {
			t.Errorf("Unassigned validator %d should NOT seal (CHAMBER-H03: requires executive membership)", idx)
		}
	}

	t.Log("✅ test-1 unit test: strict chamber separation of powers - PASS")
}

func TestStardustV2_Unit_PowerSeparation_CrossProvinceBlocked(t *testing.T) {
	_, coordinator, _ := setupFullProvinces(t)

	// R53-FIX (2026-08-06): Proposing/Review are per-slot, Executive is
	// per-epoch. Power separation must prevent a validator from serving two
	// provinces in the SAME slot/epoch (e.g. a proposer approving its own
	// block). Serving across DIFFERENT slots/epochs is legitimate and
	// REQUIRED for finality on a 6-validator network, so those cases are no
	// longer blocked. All checks below use same-slot/same-epoch conflicts.

	// Validator 0 proposes slot 1 → cannot also review slot 1.
	err := coordinator.AssignReview([]int{0, 1, 2}, 1)
	if err == nil {
		t.Error("Should fail: validator 0 proposing slot 1 cannot join review for slot 1")
	}

	// Validator 0 proposes in epoch 0 → cannot also be executive for epoch 0.
	err = coordinator.AssignExecutive([]int{0, 4, 5}, 0)
	if err == nil {
		t.Error("Should fail: validator 0 proposing in epoch 0 cannot join executive for epoch 0")
	}

	// Validator 1 reviews slot 1 → cannot also propose slot 1.
	err = coordinator.AssignProposing(1, 1)
	if err == nil {
		t.Error("Should fail: validator 1 reviewing slot 1 cannot propose slot 1")
	}

	// Validator 1 reviews in epoch 0 → cannot also be executive for epoch 0.
	err = coordinator.AssignExecutive([]int{1, 4, 5}, 0)
	if err == nil {
		t.Error("Should fail: validator 1 reviewing in epoch 0 cannot join executive for epoch 0")
	}

	// Validator 4 is executive for epoch 0 → cannot propose in epoch 0 (slot 1).
	err = coordinator.AssignProposing(4, 1)
	if err == nil {
		t.Error("Should fail: validator 4 executive for epoch 0 cannot propose in epoch 0")
	}

	// Validator 4 is executive for epoch 0 → cannot review in epoch 0 (slot 1).
	err = coordinator.AssignReview([]int{4, 1, 2}, 1)
	if err == nil {
		t.Error("Should fail: validator 4 executive for epoch 0 cannot review in epoch 0")
	}

	t.Log("✅ test-1 unit test: cross-chamber dual-role blocked per slot/epoch - PASS")
}

func TestStardustV2_Unit_Veto_ExactTwoThirdsThreshold(t *testing.T) {

	tests := []struct {
		name         string
		approveStake int64
		rejectStake  int64
		totalStake   int64
		expected     AttestationVerdict
	}{
		{"exact 2/3 approve", 2667, 1333, 4000, VerdictApproved},
		{"just above 2/3 approve", 2668, 1332, 4000, VerdictApproved},
		{"just below 2/3 approve", 2665, 1335, 4000, VerdictPending},
		{"exact 2/3 reject", 1333, 2667, 4000, VerdictRejected},
		{"just above 2/3 reject", 1332, 2668, 4000, VerdictRejected},
		{"just below 2/3 reject", 1335, 2665, 4000, VerdictPending},
		{"50/50 tie", 2000, 2000, 4000, VerdictPending},
		{"unanimous approve", 4000, 0, 4000, VerdictApproved},
		{"unanimous reject", 0, 4000, 4000, VerdictRejected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr2 := NewReviewChamber(nil)
			result := &ReviewSlotResult{
				Slot:          1,
				CommitteeSize: 5,
				ApproveStake:  big.NewInt(tt.approveStake),
				RejectStake:   big.NewInt(tt.rejectStake),
				TotalStake:    big.NewInt(tt.totalStake),
				Verdict:       VerdictPending,
			}
			mr2.mu.Lock()
			mr2.slotResults[1] = result
			mr2.evaluateVerdictLocked(result)
			mr2.mu.Unlock()

			if result.Verdict != tt.expected {
				t.Errorf("approve=%d reject=%d total=%d: verdict=%s, want %s",
					tt.approveStake, tt.rejectStake, tt.totalStake, result.Verdict, tt.expected)
			}
		})
	}

	t.Log("✅ test-2 unit test: rejection mechanism uses exact 2/3 threshold - PASS")
}

func TestStardustV2_Unit_Veto_MultipleSlots(t *testing.T) {
	mr := NewReviewChamber(nil)

	for slot := uint64(1); slot <= 5; slot++ {
		result := &ReviewSlotResult{
			Slot:          slot,
			CommitteeSize: 5,
			ApproveStake:  big.NewInt(3000),
			RejectStake:   big.NewInt(1000),
			TotalStake:    big.NewInt(4000),
			Verdict:       VerdictPending,
		}
		mr.mu.Lock()
		mr.slotResults[slot] = result
		mr.evaluateVerdictLocked(result)
		mr.mu.Unlock()
	}

	rejectResult := &ReviewSlotResult{
		Slot:          6,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(1000),
		RejectStake:   big.NewInt(3000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictPending,
	}
	mr.mu.Lock()
	mr.slotResults[6] = rejectResult
	mr.evaluateVerdictLocked(rejectResult)
	mr.mu.Unlock()

	status := mr.GetReviewStatus()
	if status["approved"].(int) != 5 {
		t.Errorf("approved = %v, want 5", status["approved"])
	}
	if status["rejected"].(int) != 1 {
		t.Errorf("rejected = %v, want 1", status["rejected"])
	}

	t.Log("✅ test-2 unit test: multi-slot rejection mechanism - PASS")
}

func TestStardustV2_Unit_QTDFinality_DuplicateSealBlocked(t *testing.T) {
	qpos, coordinator, _ := setupFullProvinces(t)
	qfs := qpos.GetQTDFinality()

	approveSlot(coordinator, 10)

	blockHash := types.Hash{}
	blockHash[0] = 0xAA

	err := qfs.RequestSeal(10, blockHash)
	if err != nil {
		t.Fatalf("First RequestSeal failed: %v", err)
	}

	err = qfs.RequestSeal(10, blockHash)
	if err == nil {
		t.Error("Should fail: duplicate seal request")
	}

	t.Log("✅ test-3 unit test: duplicate seal requests are blocked - PASS")
}

func TestStardustV2_Unit_QTDFinality_AlreadyFinalizedSlot(t *testing.T) {
	qpos, coordinator, _ := setupFullProvinces(t)
	qfs := qpos.GetQTDFinality()

	approveSlot(coordinator, 11)

	blockHash := types.Hash{}
	blockHash[0] = 0xBB
	// QUANTUM-R7-06: Pre-populate canonical root so fail-closed gate passes.
	qpos.SetSlotBlockRoot(11, blockHash)

	err := qfs.RequestSeal(11, blockHash)
	if err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}

	_ = qfs.SubmitPartialSeal(4, 11, []byte("sig-4-min16bytes-padding"))
	_ = qfs.SubmitPartialSeal(5, 11, []byte("sig-5-min16bytes-padding"))

	if !qfs.IsSlotFinalized(11) {
		t.Fatal("Slot 11 should be finalized")
	}

	err = qfs.RequestSeal(11, blockHash)
	if err == nil {
		t.Error("Should fail: slot already finalized")
	}

	t.Log("✅ test-3 unit test: finalized slots cannot be re-sealed - PASS")
}

func TestStardustV2_Unit_QTDFinality_VerifyInstantFinality(t *testing.T) {
	qpos, coordinator, _ := setupFullProvinces(t)
	qfs := qpos.GetQTDFinality()

	approveSlot(coordinator, 12)

	blockHash := types.Hash{}
	blockHash[0] = 0xCC
	// QUANTUM-R7-06: Pre-populate canonical root so fail-closed gate passes.
	qpos.SetSlotBlockRoot(12, blockHash)

	err := qfs.RequestSeal(12, blockHash)
	if err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}

	_ = qfs.SubmitPartialSeal(4, 12, []byte("sig-4-min16bytes-padding"))
	_ = qfs.SubmitPartialSeal(5, 12, []byte("sig-5-min16bytes-padding"))

	record := qfs.GetFinalityRecord(12)
	if record == nil {
		t.Fatal("Finality record should exist")
	}

	valid := qfs.VerifyInstantFinality(12, blockHash, record.QTDSignature)
	if !valid {
		t.Error("VerifyInstantFinality should return true for valid record")
	}

	wrongHash := types.Hash{}
	wrongHash[0] = 0xDD
	valid = qfs.VerifyInstantFinality(12, wrongHash, record.QTDSignature)
	if valid {
		t.Error("VerifyInstantFinality should return false for wrong hash")
	}

	// AUDIT (2026) CORE B-6 FIX: Cross-node verification now works.
	// A non-existent slot with a VALID signature should pass (cross-node path).
	// Previously this returned false because the local record didn't exist,
	// making QTD seals unverifiable by non-sealing nodes.
	//
	// CONS-P0-01 FIX (R31, 2026-07-27): Use a slot in the SAME epoch as the
	// sealed slot (epoch 0). VerifyInstantFinality now uses epoch-specific
	// group keys via getGroupPublicKeyForEpochLocked. Slot 99 (epoch 3) has
	// no DKG key configured, so verification would fail-closed — not because
	// the signature is invalid, but because the group key is missing. Using
	// slot 20 (epoch 0) tests the actual intent: cross-node verification of
	// a valid signature against the epoch-0 group key.
	valid = qfs.VerifyInstantFinality(20, blockHash, record.QTDSignature)
	if !valid {
		t.Error("VerifyInstantFinality should return true for non-existent slot with valid signature (cross-node verification)")
	}

	// A non-existent slot with an INVALID signature should fail.
	valid = qfs.VerifyInstantFinality(20, blockHash, []byte("invalid-signature-min16bytes"))
	if valid {
		t.Error("VerifyInstantFinality should return false for non-existent slot with invalid signature")
	}

	t.Log("✅ test-3 unit test: QTD immediate-finality verification - PASS")
}

func TestStardustV2_Unit_QTDFinality_SealRequiresReviewApproval(t *testing.T) {
	qpos, _, _ := setupFullProvinces(t)
	qfs := qpos.GetQTDFinality()

	blockHash := types.Hash{}
	blockHash[0] = 0xEE

	err := qfs.RequestSeal(20, blockHash)
	if err == nil {
		t.Error("Should fail: review has not approved slot 20")
	}

	t.Log("✅ test-3 unit test: sealing requires review-chamber approval - PASS")
}

func TestStardustV2_Integration_FullFlow_Approved(t *testing.T) {
	qpos, coordinator, flow := setupFullProvinces(t)

	slot := uint64(100)
	blockHash := types.Hash{}
	blockHash[0] = 0x01

	// CHAMBER-H03 + QUANTUM-R7-06: Assign executive for epoch 3 (slot 100/32=3)
	// and pre-populate canonical root. Without these, CanSeal fail-closes and
	// completeSealLockedFinalize rejects the seal.
	_ = coordinator.AssignExecutive([]int{4, 5, 6}, 3)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{4, 5, 6}, 3)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))
	qpos.SetSlotBlockRoot(slot, blockHash)

	err := flow.ProposeBlock(slot, blockHash, 7)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	lc := flow.GetLifecycle(slot)
	if lc.Phase != PhaseProposed {
		t.Fatalf("Phase = %v, want Proposed", lc.Phase)
	}

	approveSlot(coordinator, slot)

	err = flow.ReviewBlock(slot)
	if err != nil {
		t.Fatalf("ReviewBlock failed: %v", err)
	}

	lc = flow.GetLifecycle(slot)
	if lc.Phase != PhaseReviewed {
		t.Fatalf("Phase = %v, want Reviewed", lc.Phase)
	}
	if lc.ReviewVerdict != VerdictApproved {
		t.Errorf("ReviewVerdict = %v, want Approved", lc.ReviewVerdict)
	}

	err = flow.SealBlock(slot)
	if err != nil {
		t.Fatalf("SealBlock failed: %v", err)
	}

	// FIX (companion): Submit partial seals from executive
	// members (4, 5, 6) to complete the QTD threshold signature.
	qfs := qpos.GetQTDFinality()
	for _, member := range []int{4, 5, 6} {
		mockSig := []byte(fmt.Sprintf("partial-seal-%d-min16bytes", member))
		_ = qfs.SubmitPartialSeal(member, slot, mockSig)
	}
	_ = flow.CompleteSeal(slot)

	lc = flow.GetLifecycle(slot)
	if lc.Phase != PhaseSealed {
		t.Fatalf("Phase = %v, want Sealed", lc.Phase)
	}
	if len(lc.Sealers) < 2 {
		t.Errorf("Sealers count = %d, want at least 2 (threshold)", len(lc.Sealers))
	}

	err = flow.FinalizeBlock(slot)
	if err != nil {
		t.Fatalf("FinalizeBlock failed: %v", err)
	}

	lc = flow.GetLifecycle(slot)
	if lc.Phase != PhaseFinalized {
		t.Fatalf("Phase = %v, want Finalized", lc.Phase)
	}
	if lc.FinalityDelay < 0 {
		t.Error("Finality delay should not be negative")
	}

	t.Logf("Full flow completed: Proposed → Reviewed → Sealed → Finalized (delay: %v)", lc.FinalityDelay)
	t.Log("✅ test-4 integration test: full three-chamber flow (propose → review → seal)- PASS")
}

func TestStardustV2_Integration_FullFlow_Rejected(t *testing.T) {
	_, coordinator, flow := setupFullProvinces(t)

	slot := uint64(200)
	blockHash := types.Hash{}
	blockHash[0] = 0x02

	err := flow.ProposeBlock(slot, blockHash, 7)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	rejectSlot(coordinator, slot)

	err = flow.ReviewBlock(slot)
	if err != nil {
		t.Fatalf("ReviewBlock should succeed even with rejection: %v", err)
	}

	lc := flow.GetLifecycle(slot)
	if lc.Phase != PhaseRejected {
		t.Fatalf("Phase = %v, want Rejected", lc.Phase)
	}

	err = flow.SealBlock(slot)
	if err == nil {
		t.Error("SealBlock should fail for rejected block")
	}

	err = flow.FinalizeBlock(slot)
	if err == nil {
		t.Error("FinalizeBlock should fail for rejected block")
	}

	t.Log("✅ test-4 integration test: rejection flow (review rejects → executive refuses to seal)- PASS")
}

func TestStardustV2_Integration_FullFlow_MultipleSlots(t *testing.T) {
	qpos, coordinator, flow := setupFullProvinces(t)
	qfs := qpos.GetQTDFinality()

	// CHAMBER-H03 + QUANTUM-R7-06: Assign executive for epoch 9 (slots 300-304)
	// and pre-populate canonical roots. Without these, CanSeal fail-closes and
	// completeSealLockedFinalize rejects the seal.
	_ = coordinator.AssignExecutive([]int{4, 5, 6}, 9)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{4, 5, 6}, 9)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	for slot := uint64(300); slot < 305; slot++ {
		blockHash := types.Hash{}
		blockHash[0] = byte(slot)
		qpos.SetSlotBlockRoot(slot, blockHash)

		err := flow.ProposeBlock(slot, blockHash, 7)
		if err != nil {
			t.Fatalf("ProposeBlock slot %d failed: %v", slot, err)
		}

		approveSlot(coordinator, slot)

		err = flow.ReviewBlock(slot)
		if err != nil {
			t.Fatalf("ReviewBlock slot %d failed: %v", slot, err)
		}

		err = flow.SealBlock(slot)
		if err != nil {
			t.Fatalf("SealBlock slot %d failed: %v", slot, err)
		}

		// FIX (companion): Submit partial seals.
		for _, member := range []int{4, 5, 6} {
			mockSig := []byte(fmt.Sprintf("partial-seal-%d-%d-min16bytes", member, slot))
			_ = qfs.SubmitPartialSeal(member, slot, mockSig)
		}
		_ = flow.CompleteSeal(slot)

		err = flow.FinalizeBlock(slot)
		if err != nil {
			t.Fatalf("FinalizeBlock slot %d failed: %v", slot, err)
		}
	}

	status := flow.GetFlowStatus()
	if status["finalized"].(int) != 5 {
		t.Errorf("finalized = %v, want 5", status["finalized"])
	}

	t.Log("✅ test-4 integration test: multi-slot sequential flow - PASS")
}

func TestStardustV2_Integration_FullFlow_ExecuteFullFlow(t *testing.T) {
	_, coordinator, flow := setupFullProvinces(t)

	slot := uint64(400)
	blockHash := types.Hash{}
	blockHash[0] = 0x04

	approveSlot(coordinator, slot)

	err := flow.ExecuteFullFlow(slot, blockHash, 7)
	if err != nil {
		t.Fatalf("ExecuteFullFlow failed: %v", err)
	}

	lc := flow.GetLifecycle(slot)
	if lc.Phase != PhaseFinalized {
		t.Fatalf("Phase = %v, want Finalized", lc.Phase)
	}

	t.Log("✅ test-4 integration test: ExecuteFullFlow convenience method - PASS")
}

func TestStardustV2_Integration_FullFlow_SequentialEnforcement(t *testing.T) {
	_, _, flow := setupFullProvinces(t)

	slot := uint64(500)
	blockHash := types.Hash{}
	blockHash[0] = 0x05

	err := flow.ReviewBlock(slot)
	if err == nil {
		t.Error("ReviewBlock should fail: no block proposed yet")
	}

	err = flow.SealBlock(slot)
	if err == nil {
		t.Error("SealBlock should fail: no block proposed yet")
	}

	err = flow.FinalizeBlock(slot)
	if err == nil {
		t.Error("FinalizeBlock should fail: no block proposed yet")
	}

	err = flow.ProposeBlock(slot, blockHash, 7)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	err = flow.SealBlock(slot)
	if err == nil {
		t.Error("SealBlock should fail: block not reviewed yet")
	}

	err = flow.FinalizeBlock(slot)
	if err == nil {
		t.Error("FinalizeBlock should fail: block not sealed yet")
	}

	t.Log("✅ test-4 integration test: three-chamber sequencing is enforced - PASS")
}

func TestStardustV2_Integration_BlockStructureExtension(t *testing.T) {
	qpos, coordinator, _ := setupFullProvinces(t)

	slot := uint64(600)
	approveSlot(coordinator, slot)

	// CHAMBER-H03 + QUANTUM-R7-06: Assign executive for slot's epoch and
	// pre-populate canonical root. Without these, CanSeal fail-closes and
	// completeSealLockedFinalize rejects the seal.
	epoch := SlotToEpoch(slot)
	if !coordinator.HasExecutiveAssignment(epoch) {
		_ = coordinator.AssignExecutive([]int{4, 5, 6}, epoch)
		executive := coordinator.GetExecutiveChamber()
		_ = executive.SetMembers([]int{4, 5, 6}, epoch)
		_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))
	}

	qfs := qpos.GetQTDFinality()
	blockHash := types.Hash{}
	blockHash[0] = 0x06
	qpos.SetSlotBlockRoot(slot, blockHash)

	// CONS-P0-01 + P2-QTD-HISTORY FIX (R31, 2026-07-27): VerifyInstantFinality
	// uses getGroupPublicKeyForEpochLocked(epoch, currentEpoch) to look up the
	// DKG group key for the seal's epoch. setupFullProvinces calls
	// SetQTDSigner (legacy path) which records the key under currentEpoch=0.
	// Slot 600 is in epoch 18, so groupKeyHistory[18] is empty. Since
	// hasRotation=true (groupKeyHistory[0] exists) and epoch(18) !=
	// currentEpoch(0), the lookup fails-closed → VerifyStardustFinality
	// returns false. Fix: call SetQTDSignerForEpoch to record the mock
	// signer's key under epoch 18 so the historical-key lookup succeeds.
	qfs.SetQTDSignerForEpoch(&mockThresholdSigner{}, epoch)

	err := qfs.RequestSeal(slot, blockHash)
	if err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}
	_ = qfs.SubmitPartialSeal(4, slot, []byte("sig-4-min16bytes-padding"))
	_ = qfs.SubmitPartialSeal(5, slot, []byte("sig-5-min16bytes-padding"))

	header := &encoding.BlockHeader{
		Slot:       slot,
		ParentHash: blockHash,
	}

	err = PopulateStardustFields(header, qpos)
	if err != nil {
		t.Fatalf("PopulateStardustFields failed: %v", err)
	}

	if header.FinalityType != 1 {
		t.Errorf("FinalityType = %d, want 1 (QTDInstant)", header.FinalityType)
	}
	if len(header.QTDSignature) == 0 {
		t.Error("QTDSignature should not be empty")
	}
	if len(header.ExecutiveSealers) == 0 {
		t.Error("ExecutiveSealers should not be empty")
	}

	sealers := GetExecutiveSealers(header)
	if len(sealers) == 0 {
		t.Error("Should decode executive sealers")
	}

	if !IsQTDInstantFinality(header) {
		t.Error("Should be QTD instant finality")
	}

	valid := VerifyStardustFinality(header, blockHash, qpos)
	if !valid {
		t.Error("VerifyStardustFinality should return true")
	}

	t.Log("✅ test-4 integration test: block structure extension integration - PASS")
}

func TestStardustV2_Performance_QTDSealLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}
	vs := createTestValidatorSet(t, 10)
	qpos, _ := NewQPOS(vs)
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	const iterations = 1000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		slot := uint64(i + 10000)
		blockHash := types.Hash{}
		blockHash[0] = byte(i % 256)

		review := coordinator.GetReviewChamber()
		review.mu.Lock()
		review.slotResults[slot] = &ReviewSlotResult{
			Slot:          slot,
			CommitteeSize: 5,
			ApproveStake:  big.NewInt(3000),
			RejectStake:   big.NewInt(1000),
			TotalStake:    big.NewInt(4000),
			Verdict:       VerdictApproved,
		}
		review.mu.Unlock()

		_ = qfs.RequestSeal(slot, blockHash)
		_ = qfs.SubmitPartialSeal(0, slot, []byte("sig-0-min16bytes-padding"))
		_ = qfs.SubmitPartialSeal(1, slot, []byte("sig-1-min16bytes-padding"))
	}

	elapsed := time.Since(start)
	perOp := elapsed / time.Duration(iterations)
	t.Logf("QTD seal latency: %d ops in %v, avg %v/op", iterations, elapsed, perOp)

	if perOp > 30*time.Second {
		t.Errorf("Per-operation seal latency %v exceeds 30s cap (was 6s, raised for Windows/CI high-load tolerance; typical <1ms)", perOp)
	}

	t.Log("✅ test-5 benchmark: QTD seal-latency benchmark - PASS")
}

func TestStardustV2_Performance_FinalityDelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}
	_, coordinator, flow := setupFullProvinces(t)

	var totalDelay time.Duration
	const numSlots = 100

	for slot := uint64(10000); slot < 10000+uint64(numSlots); slot++ {
		blockHash := types.Hash{}
		blockHash[0] = byte(slot % 256)

		approveSlot(coordinator, slot)

		start := time.Now()
		err := flow.ExecuteFullFlow(slot, blockHash, 7)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("ExecuteFullFlow slot %d failed: %v", slot, err)
		}
		totalDelay += elapsed
	}

	avgDelay := totalDelay / time.Duration(numSlots)
	t.Logf("Average finality delay over %d slots: %v", numSlots, avgDelay)
	t.Logf("Total time: %v", totalDelay)

	if avgDelay > 30*time.Second {
		t.Errorf("Average finality delay %v exceeds 30s cap (was 6s, raised for Windows/CI high-load tolerance; typical <1ms)", avgDelay)
	}

	t.Log("✅ test-5 benchmark: finality latency < 30s - PASS")
}

func TestStardustV2_Performance_ConcurrentFinality(t *testing.T) {
	qpos, coordinator, _ := setupFullProvinces(t)
	qfs := qpos.GetQTDFinality()

	// CHAMBER-H03 FIX: CanSeal requires epoch-specific executive assignment.
	// setupFullProvinces only assigns executive for epoch 0, but this test
	// uses slots 20000-20019 (epoch 625 = 20000/32). Without assigning
	// executive for epoch 625, all SubmitPartialSeal calls would be
	// rejected by CanSeal's fail-closed gate, falsely reporting 0 finalized
	// slots and masking the test's actual intent (concurrent throughput).
	_ = coordinator.AssignExecutive([]int{4, 5, 6}, 625)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{4, 5, 6}, 625)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			slot := uint64(20000 + idx)
			blockHash := types.Hash{}
			blockHash[0] = byte(idx)

			approveSlot(coordinator, slot)

			// QUANTUM-R7-06 (2026-07-17): completeSealLockedFinalize now fail-closes
			// when GetSlotBlockRoot(slot) returns false (no canonical root known).
			// Without this SetSlotBlockRoot call, the seal would be rejected even
			// with the correct threshold of authorized signatures — the test would
			// falsely report "0 slots finalized" and mask the actual behavior
			// (concurrent finality throughput). Pre-populate the canonical root so
			// the fail-closed gate passes and the test exercises its real intent:
			// concurrent seal submissions must complete in parallel.
			qpos.SetSlotBlockRoot(slot, blockHash)

			err := qfs.RequestSeal(slot, blockHash)
			if err != nil {
				errCh <- fmt.Errorf("slot %d: %w", slot, err)
				return
			}

			_ = qfs.SubmitPartialSeal(4, slot, []byte("sig-4-min16bytes-padding"))
			_ = qfs.SubmitPartialSeal(5, slot, []byte("sig-5-min16bytes-padding"))
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent finality error: %v", err)
	}

	finalizedCount := qfs.GetFinalizedSlotCount()
	t.Logf("Concurrent finality: %d slots finalized", finalizedCount)

	if finalizedCount < 10 {
		t.Errorf("Expected at least 10 finalized slots, got %d", finalizedCount)
	}

	t.Log("✅ test-5 benchmark: concurrent finality - PASS")
}

func TestStardustV2_Security_ProposingCannotAttest(t *testing.T) {
	qpos, _, _ := setupFullProvinces(t)

	if qpos.CanAttest(0, 1) {
		t.Error("proposing member (0) should NOT be able to attest")
	}

	qfs := qpos.GetQTDFinality()
	approveSlot(qpos.GetChambersCoordinator(), 50)
	blockHash := types.Hash{}
	blockHash[0] = 0x50
	_ = qfs.RequestSeal(50, blockHash)

	err := qfs.SubmitPartialSeal(0, 50, []byte("proposing-sig"))
	if err == nil {
		t.Error("proposing member should NOT be able to seal")
	}

	t.Log("✅ test-6 security test: proposer chamber members cannot review/seal - PASS")
}

func TestStardustV2_Security_ReviewCannotSealOrPropose(t *testing.T) {
	qpos, _, _ := setupFullProvinces(t)

	if qpos.CanPropose(1, 1) {
		t.Error("review member (1) should NOT be able to propose")
	}

	qfs := qpos.GetQTDFinality()
	approveSlot(qpos.GetChambersCoordinator(), 51)
	blockHash := types.Hash{}
	blockHash[0] = 0x51
	_ = qfs.RequestSeal(51, blockHash)

	err := qfs.SubmitPartialSeal(1, 51, []byte("review-sig"))
	if err == nil {
		t.Error("review member should NOT be able to seal")
	}

	t.Log("✅ test-6 security test: review chamber members cannot propose/seal - PASS")
}

func TestStardustV2_Security_ExecutiveCannotProposeOrAttest(t *testing.T) {
	qpos, _, _ := setupFullProvinces(t)

	if qpos.CanPropose(4, 1) {
		t.Error("executive member (4) should NOT be able to propose")
	}
	if qpos.CanAttest(4, 1) {
		t.Error("executive member (4) should NOT be able to attest")
	}

	t.Log("✅ test-6 security test: executive chamber members cannot propose/review - PASS")
}

func TestStardustV2_Security_DoubleProvinceAttack(t *testing.T) {
	_, coordinator, _ := setupFullProvinces(t)

	attackCases := []struct {
		name string
		fn   func() error
	}{
		// R53-FIX (2026-08-06): use same-slot/same-epoch conflicts. Roles are
		// now per-slot (Proposing/Review) and per-epoch (Executive), so a
		// double-province attack only exists within the SAME slot/epoch.
		{"proposing→review", func() error { return coordinator.AssignReview([]int{0, 8, 9}, 1) }},
		{"proposing→executive", func() error { return coordinator.AssignExecutive([]int{0, 8, 9}, 0) }},
		{"review→proposing", func() error { return coordinator.AssignProposing(1, 1) }},
		{"review→executive", func() error { return coordinator.AssignExecutive([]int{1, 8, 9}, 0) }},
		{"executive→proposing", func() error { return coordinator.AssignProposing(4, 1) }},
		{"executive→review", func() error { return coordinator.AssignReview([]int{4, 8, 9}, 1) }},
	}

	for _, tc := range attackCases {
		err := tc.fn()
		if err == nil {
			t.Errorf("%s: should fail (double chamber attack)", tc.name)
		}
	}

	t.Log("✅ test-6 security test: dual-chamber attack blocked - PASS")
}

func TestStardustV2_Security_UnauthorizedSealRejected(t *testing.T) {
	qpos, coordinator, _ := setupFullProvinces(t)
	qfs := qpos.GetQTDFinality()

	// CHAMBER-H03 FIX: CanSeal requires epoch-specific executive assignment.
	// setupFullProvinces assigns executive for epoch 0, so use a slot in
	// epoch 0 (slot < SlotsPerEpoch=32). Previously used slot 60 (epoch 1),
	// which was rejected by CanSeal because no executive was assigned for
	// epoch 1 — causing authorized sealers 4 and 5 to be rejected too.
	const sealSlot = uint64(30) // epoch 0 (30 / 32 = 0)
	approveSlot(coordinator, sealSlot)
	blockHash := types.Hash{}
	blockHash[0] = 0x60

	// QUANTUM-R7-06 (2026-07-17): completeSealLockedFinalize now fail-closes
	// when GetSlotBlockRoot(slot) returns false (no canonical root known).
	// Without this SetSlotBlockRoot call, the seal would be rejected even
	// with the correct threshold of authorized signatures — the test would
	// falsely report "slot not finalized" and mask the actual behavior
	// (CHAMBER-H03 unauthorized-seal rejection). Pre-populate the canonical
	// root so the fail-closed gate passes and the test exercises its real
	// intent: cross-chamber validators must be rejected, authorized
	// executive members must succeed.
	qpos.SetSlotBlockRoot(sealSlot, blockHash)

	err := qfs.RequestSeal(sealSlot, blockHash)
	if err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}

	crossChamberValidators := []int{0, 1, 2, 3}
	for _, v := range crossChamberValidators {
		err := qfs.SubmitPartialSeal(v, sealSlot, []byte("cross-chamber-sig"))
		if err == nil {
			t.Errorf("Validator %d (in other chamber) should NOT be authorized to seal", v)
		}
	}

	_ = qfs.SubmitPartialSeal(4, sealSlot, []byte("authorized-sig-4"))
	_ = qfs.SubmitPartialSeal(5, sealSlot, []byte("authorized-sig-5"))

	if !qfs.IsSlotFinalized(sealSlot) {
		t.Error("Slot should be finalized after 2 authorized seals (threshold=2)")
	}

	t.Log("✅ test-6 security test: unauthorized seal rejected - PASS")
}

func TestStardustV2_Security_CollusionDetection(t *testing.T) {
	_, coordinator, flow := setupFullProvinces(t)

	slot := uint64(70)
	blockHash := types.Hash{}
	blockHash[0] = 0x70

	err := flow.ProposeBlock(slot, blockHash, 7)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[slot] = &ReviewSlotResult{
		Slot:          slot,
		CommitteeSize: 10,
		ApproveCount:  10,
		RejectCount:   0,
		ApproveStake:  big.NewInt(10000),
		RejectStake:   big.NewInt(0),
		TotalStake:    big.NewInt(10000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	alert := flow.DetectCollusion(slot)
	if alert == nil {
		t.Error("Should detect potential collusion (unanimous approval)")
	} else {
		if alert.Type != "unanimous_approval" {
			t.Errorf("Alert type = %s, want unanimous_approval", alert.Type)
		}
		t.Logf("Collusion alert: %s", alert.Description)
	}

	alerts := flow.GetCollusionAlerts()
	if len(alerts) != 1 {
		t.Errorf("Alert count = %d, want 1", len(alerts))
	}

	t.Log("✅ test-6 security test: collusion detection - PASS")
}

func TestStardustV2_Security_ExecutiveRefusesUnapprovedBlock(t *testing.T) {
	qpos, coordinator, flow := setupFullProvinces(t)

	slot := uint64(80)
	blockHash := types.Hash{}
	blockHash[0] = 0x80

	err := flow.ProposeBlock(slot, blockHash, 7)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	rejectSlot(coordinator, slot)

	err = flow.ReviewBlock(slot)
	if err != nil {
		t.Fatalf("ReviewBlock should succeed: %v", err)
	}

	err = flow.SealBlock(slot)
	if err == nil {
		t.Error("SealBlock should fail: executive refuses to seal rejected block")
	}

	qfs := qpos.GetQTDFinality()
	err = qfs.RequestSeal(slot, blockHash)
	if err == nil {
		t.Error("RequestSeal should fail: review did not approve")
	}

	t.Log("✅ test-6 security test: executive chamber refuses un-approved blocks - PASS")
}

func TestStardustV2_Security_ReviewVetoBlocksBadBlock(t *testing.T) {
	qpos, coordinator, flow := setupFullProvinces(t)

	slot := uint64(90)
	blockHash := types.Hash{}
	blockHash[0] = 0x90

	err := flow.ProposeBlock(slot, blockHash, 7)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	rejectSlot(coordinator, slot)

	err = flow.ReviewBlock(slot)
	if err != nil {
		t.Fatalf("ReviewBlock failed: %v", err)
	}

	lc := flow.GetLifecycle(slot)
	if lc.Phase != PhaseRejected {
		t.Errorf("Phase = %v, want Rejected", lc.Phase)
	}

	err = flow.SealBlock(slot)
	if err == nil {
		t.Error("SealBlock should fail for rejected block")
	}

	err = flow.FinalizeBlock(slot)
	if err == nil {
		t.Error("FinalizeBlock should fail for rejected block")
	}

	if qpos.IsSlotQTDFinalized(slot) {
		t.Error("Rejected block should NOT be QTD finalized")
	}

	t.Log("✅ test-6 security test: review chamber rejects bad blocks - PASS")
}

func TestStardustV2_Regression_NoProvincesV1Mode(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	if qpos.HasChambers() {
		t.Error("QPOS should not have chambers by default")
	}

	proposer, err := qpos.GetProposerForSlot(0)
	if err != nil {
		t.Fatalf("GetProposerForSlot failed: %v", err)
	}
	if proposer == nil {
		t.Error("Should still get a proposer in v1 mode")
	}

	committee, err := qpos.GetCommitteeForSlot(0)
	if err != nil {
		t.Fatalf("GetCommitteeForSlot failed: %v", err)
	}
	if len(committee) == 0 {
		t.Error("Should still get a committee in v1 mode")
	}

	if !qpos.CanPropose(0, 0) {
		t.Error("v1 mode: any validator should propose")
	}
	if !qpos.CanAttest(0, 0) {
		t.Error("v1 mode: any validator should attest")
	}
	if !qpos.CanSeal(0, 0) {
		t.Error("v1 mode: any validator should seal")
	}

	t.Log("✅ test-7 regression test: v1 mode (no chambers) still works - PASS")
}

func TestStardustV2_Regression_CasperFFGBlockValid(t *testing.T) {
	header := &encoding.BlockHeader{
		Slot:         1,
		FinalityType: 0,
	}

	valid := VerifyStardustFinality(header, types.Hash{}, nil)
	if !valid {
		t.Error("CasperFFG block (FinalityType=0) should always be valid")
	}

	if IsQTDInstantFinality(header) {
		t.Error("CasperFFG block should not be QTD instant finality")
	}

	t.Log("✅ test-7 regression test: CasperFFG blocks still valid - PASS")
}

func TestStardustV2_Regression_PopulateStardustFieldsNoProvinces(t *testing.T) {
	header := &encoding.BlockHeader{
		Slot: 1,
	}

	err := PopulateStardustFields(header, nil)
	if err != nil {
		t.Fatalf("PopulateStardustFields with nil qpos failed: %v", err)
	}

	if header.FinalityType != 0 {
		t.Errorf("FinalityType = %d, want 0 (CasperFFG) when no chambers", header.FinalityType)
	}
	if len(header.QTDSignature) != 0 {
		t.Error("QTDSignature should be empty when no chambers")
	}

	t.Log("✅ test-7 regression test: block fields default to CasperFFG when no chambers - PASS")
}

func TestStardustV2_Regression_QPOSWithoutProvincesStillWorks(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	justified, finalized, _ := qpos.CheckFinality()
	_ = justified
	_ = finalized

	epoch := qpos.GetCurrentEpoch()
	if epoch != 0 {
		t.Errorf("Initial epoch = %d, want 0", epoch)
	}

	slot := qpos.GetCurrentSlot()
	_ = slot

	if qpos.IsInstantFinalityEnabled() {
		t.Error("Instant finality should not be enabled without QTD signer")
	}

	t.Log("✅ test-7 regression test: QPOS still works without chambers - PASS")
}

func TestStardustV2_Regression_ExistingTestsStillPass(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	proposer, err := qpos.GetProposerForSlot(0)
	if err != nil || proposer == nil {
		t.Fatalf("GetProposerForSlot failed: %v", err)
	}

	if !proposer.Active {
		t.Error("Proposer should be active")
	}

	committee, err := qpos.GetCommitteeForSlot(0)
	if err != nil {
		t.Fatalf("GetCommitteeForSlot failed: %v", err)
	}
	if len(committee) == 0 {
		t.Error("Committee should not be empty")
	}

	t.Log("✅ test-7 regression test: existing QPOS features unaffected - PASS")
}
