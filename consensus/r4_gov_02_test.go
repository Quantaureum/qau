// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// setupR4GOV02Test creates a full QPOS + SlashingManager + ValidatorManager +
// MinistryRegistry wiring with a real key pair so that evidence verification
// (VerifyDoubleSigningEvidence) succeeds. Returns all components needed for
// double-punishment guard tests.
func setupR4GOV02Test(t *testing.T) (*QPOS, *SlashingManager, *ValidatorManager, *MinistryRevenue, *crypto.PrivateKey, *crypto.PublicKey, types.Address, int) {
	t.Helper()

	privKey, pubKey := createTestKeyPair(t)
	targetAddr := pubKey.Address()

	validators := []*Validator{
		{
			Address:        targetAddr,
			Stake:          validStake(),
			Active:         true,
			PublicKeyBytes: pubKey.Bytes(),
		},
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	vm := NewValidatorManager()
	if err := vm.AddValidator(targetAddr, targetAddr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}
	// VAL-H04/VAL-H05 FIX (R31, 2026-07-27): First-time activation MUST go
	// through ActivateFromQueue (sets EverActivated=true). SetActive is now
	// reserved for re-activation (e.g. unjail) of validators that have been
	// active at least once.
	if err := vm.ActivateFromQueue(targetAddr); err != nil {
		t.Fatalf("ActivateFromQueue failed: %v", err)
	}

	sm := NewSlashingManager(vm)
	qpos.SetSlashingManager(sm)
	sm.SetQPOS(qpos)

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	registry := NewMinistryRegistry(qpos, coordinator)
	RegisterSystemCaller(testSystemCaller)
	mr := registry.Revenue()

	targetIndex := vs.GetValidatorIndex(targetAddr)
	if targetIndex < 0 {
		t.Fatalf("validator %x not found in set", targetAddr[:8])
	}

	return qpos, sm, vm, mr, privKey, pubKey, targetAddr, targetIndex
}

// makeDoubleSignEvidence creates valid double-signing evidence at the given height.
func makeDoubleSignEvidence(t *testing.T, privKey *crypto.PrivateKey, addr types.Address, height uint64) *SlashingEvidence {
	t.Helper()
	vote1 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        height,
		Round:         0,
		BlockHash:     types.Hash{0x01},
		ValidatorAddr: addr,
	}
	vote2 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        height,
		Round:         0,
		BlockHash:     types.Hash{0x02},
		ValidatorAddr: addr,
	}
	if err := vote1.Sign(privKey); err != nil {
		t.Fatalf("vote1.Sign failed: %v", err)
	}
	if err := vote2.Sign(privKey); err != nil {
		t.Fatalf("vote2.Sign failed: %v", err)
	}
	return &SlashingEvidence{
		ValidatorAddr: addr,
		Reason:        SlashingReasonDoubleSigning,
		Height:        height,
		Vote1:         vote1,
		Vote2:         vote2,
		Timestamp:     time.Now().Unix(),
	}
}

// TestR4GOV02_RecordOffenseOnly_BlocksExecuteSlashing verifies that after
// SlashingManager records an offense via RecordOffenseOnly (simulating the
// first slashing path having recorded the offense), the second slashing path
// (MinistryRevenue.ExecuteSlashing) is rejected by the IsOffenseSlashed guard.
//
// This directly tests the R4-GOV-02 fix: the offense key must use `height`
// (not `epoch`). Before the fix, ExecuteSlashing called
// IsOffenseSlashed(addr, reason, epoch), which never matched the key
// "addr:reason:height" set by RecordOffenseOnly → the guard was defeated.
func TestR4GOV02_RecordOffenseOnly_BlocksExecuteSlashing(t *testing.T) {
	_, sm, _, mr, _, _, targetAddr, targetIndex := setupR4GOV02Test(t)

	const offenseHeight = uint64(100)
	const epoch = uint64(5) // deliberately different from offenseHeight

	// Simulate the first path having recorded the offense (without marking
	// the validator as slashed in QPOS — so Guard 1 IsSlashed does NOT fire).
	sm.RecordOffenseOnly(targetAddr, SlashingReasonDoubleSigning, offenseHeight)

	// Verify the offense is recorded.
	if !sm.IsOffenseSlashed(targetAddr, SlashingReasonDoubleSigning, offenseHeight) {
		t.Fatal("precondition: offense should be recorded")
	}

	// Verify the validator is NOT yet marked as slashed in QPOS (Guard 1
	// should not fire — isolates Guard 2 for this test).
	if mr.qpos.IsSlashed(targetIndex) {
		t.Fatal("precondition: validator should NOT be slashed in QPOS (to isolate Guard 2)")
	}

	stake := validStake()
	_, err := mr.ExecuteSlashing(testSystemCaller, targetIndex, SlashingReasonDoubleSigning, stake, epoch, offenseHeight)
	if err == nil {
		t.Fatal("ExecuteSlashing should fail — offense already recorded (R4-GOV-02 Guard 2)")
	}

	// Verify the error mentions "already slashed" (Guard 2 message).
	errStr := err.Error()
	if !strings.Contains(errStr, "already slashed") {
		t.Errorf("error should mention 'already slashed', got: %s", errStr)
	}
	// Verify the error mentions the height (not the epoch), confirming the
	// key unification on `height`.
	if !strings.Contains(errStr, "height 100") {
		t.Errorf("error should mention 'height 100' (not epoch), got: %s", errStr)
	}

	t.Logf("R4-GOV-02 Guard 2 rejection: %v", err)
	t.Log("=== R4-GOV-02: RecordOffenseOnly blocks ExecuteSlashing: PASS ===")
}

// TestR4GOV02_DifferentHeight_NotBlockedByGuard verifies that the
// IsOffenseSlashed guard does NOT false-positive on a different height.
// An offense recorded at height=100 should NOT block ExecuteSlashing
// for height=200 — they are different offenses.
func TestR4GOV02_DifferentHeight_NotBlockedByGuard(t *testing.T) {
	_, sm, _, mr, _, _, targetAddr, targetIndex := setupR4GOV02Test(t)

	const recordedHeight = uint64(100)
	const differentHeight = uint64(200)
	const epoch = uint64(5)

	// Record an offense at height 100.
	sm.RecordOffenseOnly(targetAddr, SlashingReasonDoubleSigning, recordedHeight)

	// Verify it's recorded.
	if !sm.IsOffenseSlashed(targetAddr, SlashingReasonDoubleSigning, recordedHeight) {
		t.Fatal("precondition: offense at height 100 should be recorded")
	}
	// Verify the different height is NOT recorded.
	if sm.IsOffenseSlashed(targetAddr, SlashingReasonDoubleSigning, differentHeight) {
		t.Fatal("offense at height 200 should NOT be recorded (different offense)")
	}

	stake := validStake()
	record, err := mr.ExecuteSlashing(testSystemCaller, targetIndex, SlashingReasonDoubleSigning, stake, epoch, differentHeight)
	if err != nil {
		// If it failed, verify it's NOT because of Guard 2 (already slashed).
		errStr := err.Error()
		if strings.Contains(errStr, "already slashed") {
			t.Fatalf("ExecuteSlashing for different height should NOT be blocked by Guard 2, got: %v", err)
		}
		t.Logf("ExecuteSlashing failed for other reason (acceptable): %v", err)
	} else {
		if record == nil {
			t.Fatal("ExecuteSlashing returned nil record without error")
		}
		t.Logf("ExecuteSlashing succeeded for different height (penalty=%s)", record.Amount.String())
	}

	t.Log("=== R4-GOV-02: Different height not blocked by Guard 2: PASS ===")
}

// TestR4GOV02_SubmitEvidence_BlocksExecuteSlashing verifies the full
// integration: after SlashingManager.SubmitEvidence (Path 1) slashes an
// offense, MinistryRevenue.ExecuteSlashing (Path 2) for the same offense
// is rejected.
func TestR4GOV02_SubmitEvidence_BlocksExecuteSlashing(t *testing.T) {
	_, sm, _, mr, privKey, _, targetAddr, targetIndex := setupR4GOV02Test(t)

	const offenseHeight = uint64(100)
	const epoch = uint64(5) // deliberately different from offenseHeight

	evidence := makeDoubleSignEvidence(t, privKey, targetAddr, offenseHeight)

	// Path 1: SubmitEvidence slashes the validator.
	blockTime := time.Now().Unix()
	_, err := sm.SubmitEvidence(evidence, sm.systemCaller, blockTime)
	if err != nil {
		t.Fatalf("SubmitEvidence (Path 1) failed: %v", err)
	}

	// Sync the async MarkValidatorSlashedByAddress goroutine.
	sm.SyncPendingSlashes()

	// Verify the offense is recorded.
	if !sm.IsOffenseSlashed(targetAddr, SlashingReasonDoubleSigning, offenseHeight) {
		t.Fatal("precondition: offense should be recorded after SubmitEvidence")
	}

	// Path 2: ExecuteSlashing for the same offense should be rejected.
	stake := validStake()
	_, err = mr.ExecuteSlashing(testSystemCaller, targetIndex, SlashingReasonDoubleSigning, stake, epoch, offenseHeight)
	if err == nil {
		t.Fatal("ExecuteSlashing (Path 2) should fail — offense already slashed by Path 1")
	}

	// Verify the error mentions double punishment prevention.
	errStr := err.Error()
	if !strings.Contains(errStr, "double punishment") && !strings.Contains(errStr, "already slashed") {
		t.Errorf("error should mention double punishment or already slashed, got: %s", errStr)
	}

	t.Logf("R4-GOV-02 Path 1 → Path 2 rejection: %v", err)
	t.Log("=== R4-GOV-02: SubmitEvidence blocks ExecuteSlashing: PASS ===")
}

// TestR4GOV02_ExecuteSlashing_BlocksSubmitEvidence verifies the reverse
// direction: after MinistryRevenue.ExecuteSlashing (Path 2) slashes an
// offense, SlashingManager.SubmitEvidence (Path 1) does NOT double-slash.
func TestR4GOV02_ExecuteSlashing_BlocksSubmitEvidence(t *testing.T) {
	_, sm, _, mr, privKey, _, targetAddr, targetIndex := setupR4GOV02Test(t)

	const offenseHeight = uint64(100)
	const epoch = uint64(5)

	// Path 2: ExecuteSlashing slashes the validator.
	stake := validStake()
	record, err := mr.ExecuteSlashing(testSystemCaller, targetIndex, SlashingReasonDoubleSigning, stake, epoch, offenseHeight)
	if err != nil {
		t.Fatalf("ExecuteSlashing (Path 2) failed: %v", err)
	}
	if record == nil {
		t.Fatal("ExecuteSlashing returned nil record")
	}

	// Verify the offense is recorded with the height key.
	if !sm.IsOffenseSlashed(targetAddr, SlashingReasonDoubleSigning, offenseHeight) {
		t.Fatal("offense should be recorded after ExecuteSlashing")
	}

	// Capture stake after Path 2.
	validator, _ := sm.validatorMgr.GetValidator(targetAddr)
	stakeAfterPath2 := new(big.Int).Set(validator.Stake)

	// Path 1: SubmitEvidence for the same offense.
	evidence := makeDoubleSignEvidence(t, privKey, targetAddr, offenseHeight)
	blockTime := time.Now().Unix()
	_, err = sm.SubmitEvidence(evidence, sm.systemCaller, blockTime)

	// SubmitEvidence may return ErrAlreadySlashed or succeed without
	// double-slashing (QPOS-already-slashed path). Either way, the stake
	// must NOT be reduced again.
	if err != nil {
		// If it returned an error, it should be ErrAlreadySlashed.
		if !strings.Contains(err.Error(), "already slashed") {
			t.Logf("SubmitEvidence returned non-slash error (acceptable): %v", err)
		}
	}

	// Verify the stake was NOT reduced a second time.
	validator2, _ := sm.validatorMgr.GetValidator(targetAddr)
	if validator2.Stake.Cmp(stakeAfterPath2) != 0 {
		t.Errorf("stake was double-reduced: before=%s after=%s (R4-GOV-02 double-slash)",
			stakeAfterPath2.String(), validator2.Stake.String())
	}

	t.Log("=== R4-GOV-02: ExecuteSlashing blocks SubmitEvidence double-slash: PASS ===")
}

// TestR4GOV03_NoPhantomRecordOnGuardRejection verifies that when the
// double-punishment guard rejects ExecuteSlashing, no phantom record is
// left in slashRecords and totalSlashed is not inflated.
//
// This tests the R4-GOV-03 fix: previously the record was appended and
// totalSlashed updated BEFORE the guards, so a guard rejection left a
// phantom record.
func TestR4GOV03_NoPhantomRecordOnGuardRejection(t *testing.T) {
	_, sm, _, mr, _, _, targetAddr, targetIndex := setupR4GOV02Test(t)

	const offenseHeight = uint64(100)
	const epoch = uint64(5)

	// Record the offense (simulating Path 1 having already slashed).
	sm.RecordOffenseOnly(targetAddr, SlashingReasonDoubleSigning, offenseHeight)

	// Capture state before the rejected call.
	slashRecordsBefore := mr.GetSlashRecords(targetIndex)
	summaryBefore := mr.GetFinancialSummary()
	totalSlashedBefore := summaryBefore["totalSlashed"].(string)
	totalExecsBefore := summaryBefore["totalSlashExecutions"].(int)

	// ExecuteSlashing should be rejected by Guard 2.
	stake := validStake()
	_, err := mr.ExecuteSlashing(testSystemCaller, targetIndex, SlashingReasonDoubleSigning, stake, epoch, offenseHeight)
	if err == nil {
		t.Fatal("ExecuteSlashing should be rejected by Guard 2")
	}

	// Verify NO phantom record was added.
	slashRecordsAfter := mr.GetSlashRecords(targetIndex)
	if len(slashRecordsAfter) != len(slashRecordsBefore) {
		t.Errorf("phantom record created: before=%d records, after=%d records (R4-GOV-03)",
			len(slashRecordsBefore), len(slashRecordsAfter))
	}

	// Verify totalSlashed and totalSlashExecutions were NOT inflated.
	summaryAfter := mr.GetFinancialSummary()
	totalSlashedAfter := summaryAfter["totalSlashed"].(string)
	totalExecsAfter := summaryAfter["totalSlashExecutions"].(int)
	if totalSlashedAfter != totalSlashedBefore {
		t.Errorf("totalSlashed inflated: before=%s after=%s (R4-GOV-03)",
			totalSlashedBefore, totalSlashedAfter)
	}
	if totalExecsAfter != totalExecsBefore {
		t.Errorf("totalSlashExecutions inflated: before=%d after=%d (R4-GOV-03)",
			totalExecsBefore, totalExecsAfter)
	}

	t.Log("=== R4-GOV-03: No phantom record on guard rejection: PASS ===")
}
