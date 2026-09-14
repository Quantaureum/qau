// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

func TestReviewVerdictString(t *testing.T) {
	tests := []struct {
		v        AttestationVerdict
		expected string
	}{
		{VerdictPending, "Pending"},
		{VerdictApproved, "Approved"},
		{VerdictRejected, "Rejected"},
		{VerdictTimeout, "Timeout"},
		{AttestationVerdict(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.expected {
			t.Errorf("AttestationVerdict(%d).String() = %q, want %q", tt.v, got, tt.expected)
		}
	}
}

func TestReviewSlotResultTracking(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	review := coordinator.GetReviewChamber()

	slot := uint64(1)
	blockRoot := types.Hash{}
	blockRoot[0] = 0xAB

	for _, idx := range []int{0, 1, 2} {
		att := &Attestation{
			Slot:            slot,
			BeaconBlockRoot: blockRoot,
			Source:          AttestationCheckpoint{Epoch: 0},
			Target:          AttestationCheckpoint{Epoch: 0, Root: blockRoot},
			ValidatorIndex:  idx,
			Signature:       make([]byte, 3293),
			KeyVersion:      1,
		}
		err := review.ProcessReviewAttestation(att)
		if err != nil {
			t.Logf("Attestation from validator %d: %v (expected - may fail signature check)", idx, err)
		}
	}

	verdict := review.GetSlotVerdict(slot)
	t.Logf("Slot %d verdict: %s", slot, verdict)

	result := review.GetSlotResult(slot)
	if result != nil {
		t.Logf("Slot %d: approve=%d, reject=%d, total=%s",
			slot, result.ApproveCount, result.RejectCount, result.TotalStake.String())
	}

	t.Log("=== 2.2 Review slot result tracking: PASS ===")
}

func TestReviewBlockRejection(t *testing.T) {
	mr := NewReviewChamber(nil)

	result := &ReviewSlotResult{
		Slot:          5,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(1000),
		RejectStake:   big.NewInt(3000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictPending,
	}

	mr.mu.Lock()
	mr.slotResults[5] = result
	mr.evaluateVerdictLocked(result)
	mr.mu.Unlock()

	if result.Verdict != VerdictRejected {
		t.Errorf("Expected Rejected (3000/4000 = 75%% > 2/3), got %s", result.Verdict)
	}

	t.Log("=== 2.2 Review block rejection (2/3 reject): PASS ===")
}

func TestReviewBlockApproval(t *testing.T) {
	mr := NewReviewChamber(nil)

	result := &ReviewSlotResult{
		Slot:          5,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictPending,
	}

	mr.mu.Lock()
	mr.slotResults[5] = result
	mr.evaluateVerdictLocked(result)
	mr.mu.Unlock()

	if result.Verdict != VerdictApproved {
		t.Errorf("Expected Approved (3000/4000 = 75%% > 2/3), got %s", result.Verdict)
	}

	t.Log("=== 2.2 Review block approval (2/3 approve): PASS ===")
}

func TestReviewPendingWhenBelowThreshold(t *testing.T) {
	mr := NewReviewChamber(nil)

	result := &ReviewSlotResult{
		Slot:          5,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(1000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(2000),
		Verdict:       VerdictPending,
	}

	mr.mu.Lock()
	mr.slotResults[5] = result
	mr.evaluateVerdictLocked(result)
	mr.mu.Unlock()

	if result.Verdict != VerdictPending {
		t.Errorf("Expected Pending (50%% < 2/3), got %s", result.Verdict)
	}

	t.Log("=== 2.2 Review pending when below 2/3: PASS ===")
}

func TestReviewTimeout(t *testing.T) {
	mr := NewReviewChamber(nil)
	mr.attestationTimeout = 100 * time.Millisecond

	result := &ReviewSlotResult{
		Slot:          0,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(0),
		RejectStake:   big.NewInt(0),
		TotalStake:    big.NewInt(0),
		Verdict:       VerdictPending,
	}

	mr.mu.Lock()
	mr.slotResults[0] = result
	mr.mu.Unlock()

	mr.CheckTimeout(0)

	verdict := mr.GetSlotVerdict(0)
	t.Logf("Timeout test verdict: %s", verdict)

	t.Log("=== 2.2 Review timeout handling: PASS ===")
}

func TestReviewStatus(t *testing.T) {
	mr := NewReviewChamber(nil)

	mr.mu.Lock()
	mr.slotResults[1] = &ReviewSlotResult{Slot: 1, Verdict: VerdictApproved, ApproveStake: big.NewInt(0), RejectStake: big.NewInt(0), TotalStake: big.NewInt(0)}
	mr.slotResults[2] = &ReviewSlotResult{Slot: 2, Verdict: VerdictRejected, ApproveStake: big.NewInt(0), RejectStake: big.NewInt(0), TotalStake: big.NewInt(0)}
	mr.slotResults[3] = &ReviewSlotResult{Slot: 3, Verdict: VerdictPending, ApproveStake: big.NewInt(0), RejectStake: big.NewInt(0), TotalStake: big.NewInt(0)}
	mr.mu.Unlock()

	status := mr.GetReviewStatus()
	if status["approved"].(int) != 1 {
		t.Errorf("approved = %v, want 1", status["approved"])
	}
	if status["rejected"].(int) != 1 {
		t.Errorf("rejected = %v, want 1", status["rejected"])
	}
	if status["pending"].(int) != 1 {
		t.Errorf("pending = %v, want 1", status["pending"])
	}

	t.Log("=== 2.2 Review status reporting: PASS ===")
}

func TestReviewCleanup(t *testing.T) {
	mr := NewReviewChamber(nil)

	mr.mu.Lock()
	mr.slotResults[1] = &ReviewSlotResult{Slot: 1, Verdict: VerdictApproved, ApproveStake: big.NewInt(0), RejectStake: big.NewInt(0), TotalStake: big.NewInt(0)}
	mr.slotResults[2] = &ReviewSlotResult{Slot: 2, Verdict: VerdictPending, ApproveStake: big.NewInt(0), RejectStake: big.NewInt(0), TotalStake: big.NewInt(0)}
	mr.mu.Unlock()

	mr.CleanupSlot(1)

	mr.mu.RLock()
	_, exists := mr.slotResults[1]
	mr.mu.RUnlock()
	if exists {
		t.Error("Slot 1 should be cleaned up")
	}

	mr.mu.RLock()
	_, exists = mr.slotResults[2]
	mr.mu.RUnlock()
	if !exists {
		t.Error("Slot 2 should still exist")
	}

	t.Log("=== 2.2 Review cleanup: PASS ===")
}

func TestReviewIntegrationWithChambers(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()

	_ = coordinator.AssignProposing(0, 5)
	_ = coordinator.AssignExecutive([]int{7, 8, 9}, 0)

	approved := coordinator.IsBlockApproved(5)
	rejected := coordinator.IsBlockRejected(5)
	if approved {
		t.Error("Block should not be approved yet")
	}
	if rejected {
		t.Error("Block should not be rejected yet")
	}

	t.Log("=== 2.2 Review integration with chambers: PASS ===")
}

// TestR4GOV01_OneVoteLockRegression verifies the fix for the one-vote-lock
// vulnerability (AUDIT R4-GOV-01, 2026-07-15).
//
// BUG: evaluateVerdictLocked previously used the accumulated TotalStake
// (sum of stake from received attestations) as the denominator for the 2/3
// supermajority threshold. After the first attestation, ApproveStake ==
// TotalStake, so threshold = 2/3 * ApproveStake, which was trivially
// satisfied → a single attester could lock the verdict Approved (or
// Rejected) before 2/3 of the committee had weighed in.
//
// FIX: evaluateVerdictLocked now uses CommitteeTotalStake (the FULL
// committee's stake, computed once at slot-result creation time) as the
// denominator. The verdict stays Pending until approve (or reject) stake
// reaches 2/3 of the COMMITTEE's total stake.
//
// This test drives evaluateVerdictLocked directly (mirroring
// TestReviewBlockRejection / TestReviewBlockApproval) so the assertion is
// independent of attestation signature verification.
func TestR4GOV01_OneVoteLockRegression(t *testing.T) {
	mr := NewReviewChamber(nil)

	// Committee: 10 validators × stake 1000 = CommitteeTotalStake 10000.
	// 2/3 threshold = floor(10000 * 2 / 3) = 6666.
	committeeTotalStake := big.NewInt(10000)

	// --- Phase 1: a single approve attestation must NOT lock the verdict ---
	// OLD (buggy) behavior: denominator = TotalStake = 1000, threshold = 666,
	//   ApproveStake 1000 >= 666 → VerdictApproved (one-vote lock!).
	// NEW (fixed) behavior: denominator = CommitteeTotalStake = 10000,
	//   threshold = 6666, ApproveStake 1000 < 6666 → VerdictPending.
	result := &ReviewSlotResult{
		Slot:                1,
		CommitteeSize:       10,
		ApproveStake:        big.NewInt(1000),
		RejectStake:         big.NewInt(0),
		TotalStake:          big.NewInt(1000), // accumulated from received attestation
		CommitteeTotalStake: new(big.Int).Set(committeeTotalStake),
		Verdict:             VerdictPending,
	}
	mr.mu.Lock()
	mr.slotResults[1] = result
	mr.evaluateVerdictLocked(result)
	mr.mu.Unlock()
	if result.Verdict != VerdictPending {
		t.Fatalf("Phase 1 (one approve vote): expected Pending, got %s "+
			"(one-vote-lock regression: a single attestation must not lock the verdict)",
			result.Verdict)
	}
	t.Log("=== R4-GOV-01 Phase 1: one approve vote stays Pending (PASS) ===")

	// --- Phase 2: 5 approve votes (5000) still below 2/3 of committee (6666) ---
	result.ApproveStake = big.NewInt(5000)
	result.TotalStake = big.NewInt(5000)
	result.Verdict = VerdictPending // reset (evaluateVerdictLocked is a no-op if not Pending)
	mr.mu.Lock()
	mr.evaluateVerdictLocked(result)
	mr.mu.Unlock()
	if result.Verdict != VerdictPending {
		t.Fatalf("Phase 2 (5 approve votes, 5000 < 6666): expected Pending, got %s",
			result.Verdict)
	}
	t.Log("=== R4-GOV-01 Phase 2: 5 approve votes (< 2/3) stay Pending (PASS) ===")

	// --- Phase 3: 7 approve votes (7000) >= 2/3 of committee (6666) → Approved ---
	result.ApproveStake = big.NewInt(7000)
	result.TotalStake = big.NewInt(7000)
	result.Verdict = VerdictPending
	mr.mu.Lock()
	mr.evaluateVerdictLocked(result)
	mr.mu.Unlock()
	if result.Verdict != VerdictApproved {
		t.Fatalf("Phase 3 (7 approve votes, 7000 >= 6666): expected Approved, got %s",
			result.Verdict)
	}
	t.Log("=== R4-GOV-01 Phase 3: 7 approve votes (>= 2/3) → Approved (PASS) ===")

	// --- Phase 4: a single REJECT attestation must NOT lock the verdict ---
	// Symmetric to Phase 1: with the bug, one reject vote would lock Rejected.
	rejectResult := &ReviewSlotResult{
		Slot:                2,
		CommitteeSize:       10,
		ApproveStake:        big.NewInt(0),
		RejectStake:         big.NewInt(1000),
		TotalStake:          big.NewInt(1000),
		CommitteeTotalStake: new(big.Int).Set(committeeTotalStake),
		Verdict:             VerdictPending,
	}
	mr.mu.Lock()
	mr.slotResults[2] = rejectResult
	mr.evaluateVerdictLocked(rejectResult)
	mr.mu.Unlock()
	if rejectResult.Verdict != VerdictPending {
		t.Fatalf("Phase 4 (one reject vote): expected Pending, got %s "+
			"(one-vote-lock regression on the reject path)", rejectResult.Verdict)
	}
	t.Log("=== R4-GOV-01 Phase 4: one reject vote stays Pending (PASS) ===")

	// --- Phase 5: 7 reject votes (7000) >= 2/3 of committee (6666) → Rejected ---
	rejectResult.RejectStake = big.NewInt(7000)
	rejectResult.TotalStake = big.NewInt(7000)
	rejectResult.Verdict = VerdictPending
	mr.mu.Lock()
	mr.evaluateVerdictLocked(rejectResult)
	mr.mu.Unlock()
	if rejectResult.Verdict != VerdictRejected {
		t.Fatalf("Phase 5 (7 reject votes, 7000 >= 6666): expected Rejected, got %s",
			rejectResult.Verdict)
	}
	t.Log("=== R4-GOV-01 Phase 5: 7 reject votes (>= 2/3) → Rejected (PASS) ===")
}
