// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestCONS_R15_L01_VoteCollector_SetSlashingManager verifies that
// SetSlashingManager correctly attaches a SlashingManager to the VoteCollector.
// CONS-R15-L01 (2026-07-23) FIX: Without this setter, the direct VoteCollector
// path detects double-sign but never penalizes the offender.
func TestCONS_R15_L01_VoteCollector_SetSlashingManager(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddGenesisValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}

	sm := NewSlashingManager(vmgr)
	detector := NewDoubleSignDetector()
	blockA := types.Hash{0x01}
	blockB := types.Hash{0x02}

	vcA := NewVoteCollector(100, 0, blockA, vmgr)
	vcA.SetDoubleSignDetector(detector)
	vcA.SetSlashingManager(sm)

	vcB := NewVoteCollector(100, 0, blockB, vmgr)
	vcB.SetDoubleSignDetector(detector)
	vcB.SetSlashingManager(sm)

	// Validator votes for block A — should succeed.
	voteA := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockA, ValidatorAddr: addr}
	if err := voteA.Sign(privKey); err != nil {
		t.Fatalf("voteA.Sign: %v", err)
	}
	if err := vcA.AddVote(voteA); err != nil {
		t.Fatalf("vcA.AddVote(voteA): %v", err)
	}

	// Validator votes for block B — equivocation, should be rejected.
	voteB := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockB, ValidatorAddr: addr}
	if err := voteB.Sign(privKey); err != nil {
		t.Fatalf("voteB.Sign: %v", err)
	}
	err := vcB.AddVote(voteB)
	if !errors.Is(err, ErrDoubleSign) {
		t.Fatalf("vcB.AddVote(voteB): want ErrDoubleSign, got %v", err)
	}

	// The SlashingManager should have received and recorded the evidence.
	// Verify the validator was slashed.
	vInfo, vErr := vmgr.GetValidator(addr)
	if vErr != nil {
		t.Fatalf("GetValidator: %v", vErr)
	}
	if !vInfo.PermanentlySlashed {
		t.Error("validator should be permanently slashed after double-sign evidence was submitted")
	}
}

// TestCONS_R15_L01_VoteCollector_NoSlashingManager_NoCrash verifies that when
// no SlashingManager is set (the default state), AddVote still detects
// double-sign and returns ErrDoubleSign without crashing. The evidence is
// captured but not submitted (graceful degradation).
func TestCONS_R15_L01_VoteCollector_NoSlashingManager_NoCrash(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddGenesisValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}

	detector := NewDoubleSignDetector()
	blockA := types.Hash{0x01}
	blockB := types.Hash{0x02}

	vcA := NewVoteCollector(100, 0, blockA, vmgr)
	vcA.SetDoubleSignDetector(detector)
	// Intentionally do NOT call SetSlashingManager — default state.

	vcB := NewVoteCollector(100, 0, blockB, vmgr)
	vcB.SetDoubleSignDetector(detector)

	voteA := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockA, ValidatorAddr: addr}
	if err := voteA.Sign(privKey); err != nil {
		t.Fatalf("voteA.Sign: %v", err)
	}
	if err := vcA.AddVote(voteA); err != nil {
		t.Fatalf("vcA.AddVote(voteA): %v", err)
	}

	voteB := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockB, ValidatorAddr: addr}
	if err := voteB.Sign(privKey); err != nil {
		t.Fatalf("voteB.Sign: %v", err)
	}
	// Should still return ErrDoubleSign, just without submitting evidence.
	err := vcB.AddVote(voteB)
	if !errors.Is(err, ErrDoubleSign) {
		t.Fatalf("vcB.AddVote(voteB): want ErrDoubleSign, got %v", err)
	}

	// Validator should NOT be slashed (no SlashingManager to submit to).
	vInfo, vErr := vmgr.GetValidator(addr)
	if vErr != nil {
		t.Fatalf("GetValidator: %v", vErr)
	}
	if vInfo.PermanentlySlashed {
		t.Error("validator should NOT be slashed when no SlashingManager is set")
	}
}

// TestCONS_R15_L01_FinalityTracker_SetSlashingManager verifies that
// FinalityTracker.SetSlashingManager correctly sets the slashingManager field
// and drains queued evidence.
func TestCONS_R15_L01_FinalityTracker_SetSlashingManager(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddGenesisValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}

	ft := NewFinalityTracker(vmgr)
	sm := NewSlashingManager(vmgr)

	// Create properly signed votes for double-sign evidence.
	vote1 := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: types.Hash{0x01}, ValidatorAddr: addr}
	if err := vote1.Sign(privKey); err != nil {
		t.Fatalf("vote1.Sign: %v", err)
	}
	vote2 := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: types.Hash{0x02}, ValidatorAddr: addr}
	if err := vote2.Sign(privKey); err != nil {
		t.Fatalf("vote2.Sign: %v", err)
	}

	// Queue evidence manually before setting SlashingManager.
	// R33 CONS-03: Evidence must have a non-zero Timestamp — the slashing
	// layer now rejects Timestamp==0 without blockTime (consensus determinism).
	evidence := &SlashingEvidence{
		Reason:        SlashingReasonDoubleSigning,
		ValidatorAddr: addr,
		Height:        100,
		Timestamp:     time.Now().Unix(),
		Vote1:         vote1,
		Vote2:         vote2,
	}
	ft.QueueEvidence(evidence)

	// Set SlashingManager — should drain the queue and submit evidence.
	// NOTE: Do NOT call GetQueuedEvidence() before this, as it CLEARS the queue.
	ft.SetSlashingManager(sm)

	// Queue should be empty after drain.
	if queued := ft.GetQueuedEvidence(); len(queued) != 0 {
		t.Errorf("queued evidence after drain: want 0, got %d", len(queued))
	}

	// Validator should be slashed (evidence was submitted during drain).
	vInfo, vErr := vmgr.GetValidator(addr)
	if vErr != nil {
		t.Fatalf("GetValidator: %v", vErr)
	}
	if !vInfo.PermanentlySlashed {
		t.Error("validator should be permanently slashed after SetSlashingManager drained evidence")
	}
}

// TestCONS_R15_L03_SyncCommittee_PerSubmissionPrune verifies that
// SubmitSyncCommitteeSignature prunes old entries on every submission,
// keeping the map bounded at maxSignatureSlots. CONS-R15-L03 (2026-07-23) FIX:
// Previously cleanup only ran in RotateCommittee (every 256 epochs), allowing
// unbounded memory growth between rotations.
func TestCONS_R15_L03_SyncCommittee_PerSubmissionPrune(t *testing.T) {
	// Use a mock verifier that accepts all signatures.
	mockVerifier := &mockSyncSigVerifier{accept: true}
	scm := NewSyncCommitteeManager(mockVerifier)
	// CONS-R17-L03: Default pruneInterval=64 amortizes pruning. For this
	// test we set pruneInterval=1 to verify per-submission pruning still
	// works correctly (the original CONS-R15-L03 test intent).
	scm.pruneInterval = 1

	// Set up a committee with 1 validator.
	validator := &Validator{
		Address:        types.Address{0xAA},
		PublicKeyBytes: []byte{0x42},
		Stake:          validStake(),
		Active:         true,
	}
	scm.validators = []*Validator{validator}
	scm.currentCommittee = &SyncCommittee{
		Period:           0,
		ValidatorIndices: []int{0},
	}

	// Submit signatures for maxSignatureSlots + 50 slots.
	// Without per-submission pruning, memberSignatures would grow to 1074.
	// With pruning, it should stay bounded at maxSignatureSlots (1024).
	// CONS-R18-CRIT-01 (2026-07-24): SubmitSyncCommitteeSignature now takes
	// blockRoot/epoch/chainID to match the unified lightclient message format.
	// The mock verifier accepts all signatures regardless of message content.
	// CONS-M02 (R24, 2026-07-25): SubmitSyncCommitteeSignature now takes
	// height as the first parameter (for the V1/V2 fork-height gate). Test
	// uses slot==height (1:1) since forkHeight=0 → both produce V2.
	totalSlots := scm.maxSignatureSlots + 50
	dummyBlockRoot := types.Hash{0x01}
	for slot := 0; slot < totalSlots; slot++ {
		scm.SubmitSyncCommitteeSignature(uint64(slot), uint64(slot), 0, []byte("sig"), dummyBlockRoot, 0, 1668)
	}

	// Verify the map is bounded.
	scm.mu.RLock()
	memberLen := len(scm.memberSignatures)
	sigLen := len(scm.signatures)
	scm.mu.RUnlock()

	if memberLen > scm.maxSignatureSlots {
		t.Errorf("memberSignatures size %d exceeds maxSignatureSlots %d (no per-submission pruning)", memberLen, scm.maxSignatureSlots)
	}
	if sigLen > scm.maxSignatureSlots {
		t.Errorf("signatures size %d exceeds maxSignatureSlots %d", sigLen, scm.maxSignatureSlots)
	}

	// Verify the most recent slots are kept (slots 50..1073 if totalSlots=1074).
	// The oldest slots (0..49) should have been pruned.
	scm.mu.RLock()
	_, hasOld := scm.memberSignatures[0]
	_, hasRecent := scm.memberSignatures[uint64(totalSlots-1)]
	scm.mu.RUnlock()

	if hasOld {
		t.Error("oldest slot 0 should have been pruned")
	}
	if !hasRecent {
		t.Errorf("most recent slot %d should still be present", totalSlots-1)
	}
}

// TestCONS_R15_L03_SyncCommittee_PruneCutoffGapFix verifies that the pruning
// logic correctly handles the case where maxSlot ≤ maxSignatureSlots but
// len > maxSignatureSlots. The old code set cutoff=0 in this case and deleted
// nothing; the new code sorts and deletes the oldest entries.
func TestCONS_R15_L03_SyncCommittee_PruneCutoffGapFix(t *testing.T) {
	scm := NewSyncCommitteeManager()
	scm.maxSignatureSlots = 5 // small limit for easy testing

	// Manually populate memberSignatures with 8 entries (slots 0-7).
	// maxSlot=7, maxSignatureSlots=5. Old code: cutoff = 7-5 = 2, deletes 0,1.
	// But if slots were 0,1,2,3,4,5,6,7 and maxSignatureSlots=5, old code
	// would keep 2,3,4,5,6,7 = 6 entries (one too many because cutoff=2
	// means slots < 2 are deleted, keeping slots 2-7 = 6 entries).
	// The new sort-based approach keeps exactly 5: slots 3,4,5,6,7.
	scm.mu.Lock()
	for slot := 0; slot < 8; slot++ {
		scm.memberSignatures[uint64(slot)] = map[int][]byte{0: []byte("sig")}
	}
	scm.pruneSignaturesLocked()
	memberLen := len(scm.memberSignatures)
	hasOldest := false
	if _, ok := scm.memberSignatures[0]; ok {
		hasOldest = true
	}
	hasNewest := false
	if _, ok := scm.memberSignatures[7]; ok {
		hasNewest = true
	}
	scm.mu.Unlock()

	if memberLen != 5 {
		t.Errorf("after prune: want 5 entries, got %d", memberLen)
	}
	if hasOldest {
		t.Error("oldest slot 0 should have been pruned")
	}
	if !hasNewest {
		t.Error("newest slot 7 should still be present")
	}
}

// mockSyncSigVerifier is a test stub that accepts or rejects all signatures.
type mockSyncSigVerifier struct {
	accept bool
}

func (m *mockSyncSigVerifier) VerifySignature(pubKey []byte, message []byte, signature []byte) bool {
	return m.accept
}
