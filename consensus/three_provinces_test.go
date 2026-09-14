// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestBlockPhaseString(t *testing.T) {
	tests := []struct {
		phase    BlockPhase
		expected string
	}{
		{PhaseNone, "None"},
		{PhaseProposed, "Proposed"},
		{PhaseReviewed, "Reviewed"},
		{PhaseSealed, "Sealed"},
		{PhaseFinalized, "Finalized"},
		{PhaseRejected, "Rejected"},
		{BlockPhase(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.phase.String(); got != tt.expected {
			t.Errorf("BlockPhase(%d).String() = %q, want %q", tt.phase, got, tt.expected)
		}
	}
}

func TestThreeChambersFlowPropose(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	flow := NewThreeChambersFlow(qpos, coordinator)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	err = flow.ProposeBlock(1, blockHash, 0)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	lc := flow.GetLifecycle(1)
	if lc == nil {
		t.Fatal("Lifecycle should exist")
	}
	if lc.Phase != PhaseProposed {
		t.Errorf("Phase = %v, want Proposed", lc.Phase)
	}
	if lc.Proposer != 0 {
		t.Errorf("Proposer = %d, want 0", lc.Proposer)
	}

	t.Log("=== 2.4 Three Chambers flow: propose: PASS ===")
}

func TestThreeChambersFlowSequentialOrder(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	flow := NewThreeChambersFlow(qpos, coordinator)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	err = flow.ReviewBlock(1)
	if err == nil {
		t.Error("ReviewBlock should fail: no block proposed yet")
	}

	err = flow.ProposeBlock(1, blockHash, 0)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	err = flow.SealBlock(1)
	if err == nil {
		t.Error("SealBlock should fail: block not reviewed yet")
	}

	t.Log("=== 2.4 Three Chambers flow: sequential order enforcement: PASS ===")
}

func TestThreeChambersFlowExecutiveRefusesUnapproved(t *testing.T) {
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

	err = flow.ProposeBlock(1, blockHash, 3)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[1] = &ReviewSlotResult{
		Slot:          1,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(1000),
		RejectStake:   big.NewInt(3000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictRejected,
	}
	review.mu.Unlock()

	err = flow.ReviewBlock(1)
	if err != nil {
		t.Fatalf("ReviewBlock should succeed (even with rejection): %v", err)
	}

	lc := flow.GetLifecycle(1)
	if lc.Phase != PhaseRejected {
		t.Errorf("Phase = %v, want Rejected", lc.Phase)
	}

	err = flow.SealBlock(1)
	if err == nil {
		t.Error("SealBlock should fail: Executive refuses to seal rejected block")
	}

	t.Log("=== 2.4 Three Chambers flow: Executive refuses unapproved block: PASS ===")
}

func TestThreeChambersFlowFullApproval(t *testing.T) {
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

	err = flow.ProposeBlock(1, blockHash, 3)
	if err != nil {
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

	err = flow.ReviewBlock(1)
	if err != nil {
		t.Fatalf("ReviewBlock failed: %v", err)
	}

	lc := flow.GetLifecycle(1)
	if lc.Phase != PhaseReviewed {
		t.Errorf("Phase = %v, want Reviewed", lc.Phase)
	}

	err = flow.SealBlock(1)
	if err != nil {
		t.Fatalf("SealBlock failed: %v", err)
	}

	// FIX (companion): Submit partial seals from executive
	// members (0, 1, 2) to complete the QTD threshold signature.
	// Threshold is 2-of-3, so the seal completes after 2 submissions.
	// The 3rd submission will fail with "no pending seal" which is expected.
	for _, member := range []int{0, 1, 2} {
		mockSig := []byte(fmt.Sprintf("partial-seal-%d-min16bytes", member))
		err = qfs.SubmitPartialSeal(member, 1, mockSig)
		if err != nil {
			// After threshold is reached, pending seal is removed.
			// Subsequent submissions are expected to fail.
			break
		}
	}

	err = flow.CompleteSeal(1)
	if err != nil {
		t.Fatalf("CompleteSeal failed: %v", err)
	}

	lc = flow.GetLifecycle(1)
	if lc.Phase != PhaseSealed {
		t.Errorf("Phase = %v, want Sealed", lc.Phase)
	}
	if len(lc.Sealers) < 2 {
		t.Errorf("Sealers count = %d, want at least 2 (threshold)", len(lc.Sealers))
	}

	err = flow.FinalizeBlock(1)
	if err != nil {
		t.Fatalf("FinalizeBlock failed: %v", err)
	}

	lc = flow.GetLifecycle(1)
	if lc.Phase != PhaseFinalized {
		t.Errorf("Phase = %v, want Finalized", lc.Phase)
	}

	t.Logf("Block lifecycle: Proposed → Reviewed → Sealed → Finalized")
	t.Logf("Finality delay: %v", lc.FinalityDelay)
	t.Log("=== 2.4 Three Chambers flow: full approval lifecycle: PASS ===")
}

func TestThreeChambersFlowCollusionDetection(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	flow := NewThreeChambersFlow(qpos, coordinator)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	err = flow.ProposeBlock(1, blockHash, 0)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[1] = &ReviewSlotResult{
		Slot:          1,
		CommitteeSize: 10,
		ApproveCount:  10,
		RejectCount:   0,
		ApproveStake:  big.NewInt(10000),
		RejectStake:   big.NewInt(0),
		TotalStake:    big.NewInt(10000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	alert := flow.DetectCollusion(1)
	if alert == nil {
		t.Error("Should detect potential collusion (unanimous approval)")
	} else {
		t.Logf("Collusion alert: %s", alert.Description)
	}

	alerts := flow.GetCollusionAlerts()
	if len(alerts) != 1 {
		t.Errorf("Alert count = %d, want 1", len(alerts))
	}

	t.Log("=== 2.4 Three Chambers flow: collusion detection: PASS ===")
}

func TestThreeChambersFlowStatus(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	flow := NewThreeChambersFlow(qpos, coordinator)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	_ = flow.ProposeBlock(1, blockHash, 0)

	status := flow.GetFlowStatus()
	if status["totalBlocks"].(int) != 1 {
		t.Errorf("totalBlocks = %v, want 1", status["totalBlocks"])
	}
	if status["proposed"].(int) != 1 {
		t.Errorf("proposed = %v, want 1", status["proposed"])
	}

	t.Log("=== 2.4 Three Chambers flow: status reporting: PASS ===")
}

func TestThreeChambersFlowCleanup(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	flow := NewThreeChambersFlow(qpos, coordinator)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	_ = flow.ProposeBlock(1, blockHash, 0)

	flow.CleanupSlot(1)

	lc := flow.GetLifecycle(1)
	if lc != nil {
		t.Error("Lifecycle should be cleaned up")
	}

	t.Log("=== 2.4 Three Chambers flow: cleanup: PASS ===")
}
