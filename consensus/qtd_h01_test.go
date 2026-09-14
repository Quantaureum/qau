// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
)

// nonThresholdSigner is a test-only ThresholdKeySigner that returns
// IsThresholdMode()==false. Used to verify the QTD-H01 fix in
// SetQTDSigner and ActivateQTDInstantFinality: a non-nil signer that
// is NOT in threshold mode must be rejected (cannot bypass the QTD
// cryptographic gate by injecting a single-party signer whose
// VerifyBlock may be maliciously implemented to always return true).
type nonThresholdSigner struct{}

func (m *nonThresholdSigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("non-threshold-block-sig"), nil
}
func (m *nonThresholdSigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("non-threshold-vote-sig"), nil
}
func (m *nonThresholdSigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	// Deliberately always returns true to demonstrate the bypass risk:
	// without QTD-H01 fix, this signer would be accepted and could
	// rubber-stamp any block as validly QTD-sealed.
	return true
}
func (m *nonThresholdSigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return true
}
func (m *nonThresholdSigner) GroupPublicKey() []byte {
	return []byte("non-threshold-group-key")
}
func (m *nonThresholdSigner) IsThresholdMode() bool {
	// QTD-H01 trigger: signer is non-nil but NOT in threshold mode.
	return false
}
func (m *nonThresholdSigner) AggregatePartialSignatures(
	sealers []int, partialSigs map[int][]byte, message []byte,
) ([]byte, error) {
	return []byte("non-threshold-aggregated-sig"), nil
}

// TestQTD_H01_SetQTDSigner_RejectsNonThresholdSigner verifies that
// SetQTDSigner rejects a non-nil signer with IsThresholdMode()==false.
// Without the fix, the signer would be stored in qfs.qtdSigner and could
// bypass the cryptographic gate in SubmitCompletedSeal (whose check
// short-circuits when signer != nil but IsThresholdMode()==false).
func TestQTD_H01_SetQTDSigner_RejectsNonThresholdSigner(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)

	// Attempt to set a non-threshold signer — must be rejected.
	qfs.SetQTDSigner(&nonThresholdSigner{})

	// Signer must NOT be stored.
	if qfs.qtdSigner != nil {
		t.Fatal("SetQTDSigner accepted non-threshold-mode signer (QTD-H01 regression): qtdSigner is non-nil")
	}

	// finalityType must remain CasperFFG (no transition to QTDInstant).
	if qfs.GetFinalityType() != FinalityCasperFFG {
		t.Errorf("finalityType = %v, want CasperFFG (QTD-H01 regression: non-threshold signer triggered QTDInstant)",
			qfs.GetFinalityType())
	}
	if qfs.IsInstantFinality() {
		t.Error("IsInstantFinality()=true after rejected non-threshold signer (QTD-H01 regression)")
	}
}

// TestQTD_H01_SetQTDSigner_AcceptsNilSigner verifies that nil is still
// accepted (deactivation path) — the QTD-H01 fix only rejects non-nil
// non-threshold signers, not nil.
func TestQTD_H01_SetQTDSigner_AcceptsNilSigner(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)

	// First activate with a valid threshold signer.
	qfs.SetQTDSigner(&mockThresholdSigner{})
	if qfs.qtdSigner == nil {
		t.Fatal("threshold signer was not stored")
	}
	if qfs.GetFinalityType() != FinalityQTDInstant {
		t.Errorf("finalityType = %v, want QTDInstant", qfs.GetFinalityType())
	}

	// Now deactivate with nil — must be allowed.
	qfs.SetQTDSigner(nil)
	if qfs.qtdSigner != nil {
		t.Error("qtdSigner should be nil after SetQTDSigner(nil)")
	}
	if qfs.GetFinalityType() != FinalityCasperFFG {
		t.Errorf("finalityType = %v, want CasperFFG after deactivation", qfs.GetFinalityType())
	}
}

// TestQTD_H01_ActivateQTDInstantFinality_RejectsNonThresholdSigner
// verifies the same invariant on the ActivateQTDInstantFinality entry
// point. ActivateQTDInstantFinality must also reject a non-threshold
// signer (it calls SetQTDSigner internally, but defense-in-depth
// requires the check at the public entry too — qtd_activation.go:70-72).
func TestQTD_H01_ActivateQTDInstantFinality_RejectsNonThresholdSigner(t *testing.T) {
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

	// In test mode RequireDistributedDKG() == false, so ActivateQTDInstantFinality
	// does NOT enforce group-key equality. But the IsThresholdMode() check
	// (QTD-H01) must still fire unconditionally.
	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}
	if !executive.IsActive() {
		t.Fatal("executive chamber not active after SetDKGComplete")
	}

	qfs := qpos.GetQTDFinality()
	cfg := DefaultQTDConfig()

	err = qfs.ActivateQTDInstantFinality(&nonThresholdSigner{}, cfg)
	if err == nil {
		t.Fatal("ActivateQTDInstantFinality accepted non-threshold signer (QTD-H01 regression)")
	}

	// Signer must NOT be stored.
	if qfs.qtdSigner != nil {
		t.Fatal("qtdSigner is non-nil after ActivateQTDInstantFinality rejected non-threshold signer")
	}
	if qfs.GetFinalityType() != FinalityCasperFFG {
		t.Errorf("finalityType = %v, want CasperFFG (QTD-H01 regression)", qfs.GetFinalityType())
	}
}
