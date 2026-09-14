// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// r5_gov_r5_02_attachSlashingManager creates a ValidatorManager +
// SlashingManager with a real Dilithium3 key pair for the given validator
// index in QPOS, attaches them to qpos, and returns the SlashingManager +
// key pair.
//
// This helper exists because GOV-R5-02 (2026-07-16) changed VerifyEvidence
// from fail-open (skip check when slashingManager==nil) to fail-closed
// (reject when slashingManager==nil). Tests that previously relied on the
// fail-open behavior must now provide a real SlashingManager with valid
// cryptographic signatures.
func r5_gov_r5_02_attachSlashingManager(t *testing.T, qpos *QPOS, validatorIndex int) (*SlashingManager, *crypto.KeyPair) {
	t.Helper()

	vs := qpos.GetValidatorSet()
	if vs == nil {
		t.Fatal("qpos has no validator set")
	}
	validators := vs.Validators()
	if validatorIndex < 0 || validatorIndex >= len(validators) {
		t.Fatalf("validator index %d out of range (%d validators)", validatorIndex, len(validators))
	}
	addr := validators[validatorIndex].Address

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	vm := NewValidatorManager()
	if err := vm.AddValidator(testSystemCaller, addr, kp.Public, new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)), 100, 1); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}

	sm := NewSlashingManager(vm)
	sm.SetQPOS(qpos)
	qpos.slashingManager = sm

	return sm, kp
}

// r5_gov_r5_02_buildDoubleSignEvidence builds valid double-signing evidence
// with real Dilithium3 signatures for the given validator address and key pair.
// Timestamp is set to 0 to skip the age check in VerifyEvidence (which only
// applies when Timestamp > 0).
func r5_gov_r5_02_buildDoubleSignEvidence(t *testing.T, addr types.Address, kp *crypto.KeyPair, height uint64) *SlashingEvidence {
	t.Helper()

	vote1 := &Vote{
		ValidatorAddr: addr,
		Height:        height,
		BlockHash:     types.Hash{0x01},
	}
	if err := vote1.Sign(kp.Private); err != nil {
		t.Fatalf("vote1.Sign: %v", err)
	}

	vote2 := &Vote{
		ValidatorAddr: addr,
		Height:        height,
		BlockHash:     types.Hash{0x02},
	}
	if err := vote2.Sign(kp.Private); err != nil {
		t.Fatalf("vote2.Sign: %v", err)
	}

	return &SlashingEvidence{
		Reason:        SlashingReasonDoubleSigning,
		ValidatorAddr: addr,
		Height:        height,
		Vote1:         vote1,
		Vote2:         vote2,
		Timestamp:     0, // skip age check (VerifyEvidence only checks age if Timestamp > 0)
	}
}

// TestGOV_R5_02_QposNilRejectsEvidence verifies that when qpos is nil,
// VerifyEvidence rejects the case (fail-closed) instead of marking it
// Verified (the old fail-open behavior).
//
// GOV-R5-02 (2026-07-16): Misconfiguration or partial deployment where
// MinistryJustice.qpos is nil must NOT allow unverified disputes to
// proceed to ExecuteSlashing via ResolveDispute.
func TestGOV_R5_02_QposNilRejectsEvidence(t *testing.T) {
	// Create MinistryJustice with nil qpos — simulates misconfiguration.
	mj := NewMinistryJustice(nil, nil, nil)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	evidence := &SlashingEvidence{
		Reason:    SlashingReasonDoubleSigning,
		Height:    1,
		Timestamp: 0,
	}

	caseID, err := mj.SubmitDispute(testSystemCaller, DisputeDoubleSpend, 1, blockHash, 0, 1, evidence)
	if err != nil {
		t.Fatalf("SubmitDispute failed: %v", err)
	}

	// VerifyEvidence must fail (fail-closed) because qpos is nil.
	err = mj.VerifyEvidence(testSystemCaller, caseID)
	if err == nil {
		t.Fatal("GOV-R5-02: VerifyEvidence should fail when qpos is nil (fail-closed)")
	}

	// Case must be Rejected, NOT Verified.
	c := mj.GetCase(caseID)
	if c == nil {
		t.Fatal("case should exist")
	}
	if c.Status != DisputeStatusRejected {
		t.Errorf("GOV-R5-02: case status = %v, want Rejected (qpos nil → fail-closed)", c.Status)
	}
	if c.Verdict == "" {
		t.Error("GOV-R5-02: verdict should be non-empty explaining the rejection")
	}

	t.Logf("GOV-R5-02 qpos-nil fail-closed: err=%v, verdict=%q", err, c.Verdict)
}

// TestGOV_R5_02_SlashingManagerNilRejectsEvidence verifies that when
// qpos is non-nil but slashingManager is nil, VerifyEvidence rejects
// the case (fail-closed) instead of skipping verification.
//
// This is the primary regression test for the old fail-open behavior:
// previously the code used `if qpos != nil && slashingManager != nil`
// which SKIPPED verification when either was nil, falling through to
// mark the case as Verified.
func TestGOV_R5_02_SlashingManagerNilRejectsEvidence(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	mj := registry.Justice()
	// qpos is non-nil (set by setupMinistryRegistry), but slashingManager
	// is nil (not attached by setupMinistryRegistry).

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	evidence := &SlashingEvidence{
		Reason:    SlashingReasonDoubleSigning,
		Height:    1,
		Timestamp: 0,
	}

	caseID, err := mj.SubmitDispute(testSystemCaller, DisputeDoubleSpend, 1, blockHash, 0, 1, evidence)
	if err != nil {
		t.Fatalf("SubmitDispute failed: %v", err)
	}

	// VerifyEvidence must fail (fail-closed) because slashingManager is nil.
	err = mj.VerifyEvidence(testSystemCaller, caseID)
	if err == nil {
		t.Fatal("GOV-R5-02: VerifyEvidence should fail when slashingManager is nil (fail-closed)")
	}

	c := mj.GetCase(caseID)
	if c == nil {
		t.Fatal("case should exist")
	}
	if c.Status != DisputeStatusRejected {
		t.Errorf("GOV-R5-02: case status = %v, want Rejected (slashingManager nil → fail-closed)", c.Status)
	}
	if c.Verdict == "" {
		t.Error("GOV-R5-02: verdict should be non-empty explaining the rejection")
	}

	t.Logf("GOV-R5-02 slashingManager-nil fail-closed: err=%v, verdict=%q", err, c.Verdict)
}

// TestGOV_R5_02_ValidEvidencePasses verifies that with a properly
// configured SlashingManager and valid cryptographic evidence,
// VerifyEvidence succeeds and marks the case as Verified.
//
// This confirms the fail-closed fix does not break the legitimate path.
func TestGOV_R5_02_ValidEvidencePasses(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	mj := registry.Justice()

	// Attach SlashingManager with real key pair for validator index 1.
	_, kp := r5_gov_r5_02_attachSlashingManager(t, qpos, 1)
	vs := qpos.GetValidatorSet()
	addr := vs.Validators()[1].Address

	// Build valid double-signing evidence with real signatures.
	evidence := r5_gov_r5_02_buildDoubleSignEvidence(t, addr, kp, 1)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	caseID, err := mj.SubmitDispute(testSystemCaller, DisputeDoubleSpend, 1, blockHash, 0, 1, evidence)
	if err != nil {
		t.Fatalf("SubmitDispute failed: %v", err)
	}

	// VerifyEvidence must succeed with valid evidence + configured SlashingManager.
	if err := mj.VerifyEvidence(testSystemCaller, caseID); err != nil {
		t.Fatalf("GOV-R5-02: VerifyEvidence should pass with valid evidence: %v", err)
	}

	c := mj.GetCase(caseID)
	if c == nil {
		t.Fatal("case should exist")
	}
	if c.Status != DisputeStatusVerified {
		t.Errorf("GOV-R5-02: case status = %v, want Verified (valid evidence)", c.Status)
	}

	t.Log("GOV-R5-02 valid evidence passes verification: PASS")
}

// TestGOV_R5_02_InvalidEvidenceRejected verifies that with a configured
// SlashingManager but INVALID evidence (e.g., missing votes),
// VerifyEvidence rejects the case.
//
// This confirms the fail-closed fix also correctly rejects bad evidence
// when the SlashingManager IS present.
func TestGOV_R5_02_InvalidEvidenceRejected(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	mj := registry.Justice()

	// Attach SlashingManager (present but evidence will be invalid).
	r5_gov_r5_02_attachSlashingManager(t, qpos, 1)

	// Evidence with no Vote1/Vote2 — invalid for double-signing.
	evidence := &SlashingEvidence{
		Reason:    SlashingReasonDoubleSigning,
		Height:    1,
		Timestamp: 0,
		// Vote1 and Vote2 intentionally nil — VerifyDoubleSigningEvidence
		// will reject this.
	}

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	caseID, err := mj.SubmitDispute(testSystemCaller, DisputeDoubleSpend, 1, blockHash, 0, 1, evidence)
	if err != nil {
		t.Fatalf("SubmitDispute failed: %v", err)
	}

	// VerifyEvidence must fail because evidence is invalid (no votes).
	// Note: when SlashingManager.VerifyEvidence returns an error,
	// MinistryJustice.VerifyEvidence returns nil but sets status to Rejected.
	if err := mj.VerifyEvidence(testSystemCaller, caseID); err != nil {
		t.Fatalf("GOV-R5-02: VerifyEvidence returned error for invalid evidence (expected nil error, Rejected status): %v", err)
	}

	c := mj.GetCase(caseID)
	if c == nil {
		t.Fatal("case should exist")
	}
	if c.Status != DisputeStatusRejected {
		t.Errorf("GOV-R5-02: case status = %v, want Rejected (invalid evidence)", c.Status)
	}

	t.Logf("GOV-R5-02 invalid evidence rejected: verdict=%q", c.Verdict)
}
