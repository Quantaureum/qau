// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
)

// TestQTD_H07_SetQTDSigner_Nil_ResetsFinalityType verifies that calling
// SetQTDSigner(nil) resets finalityType to FinalityCasperFFG, NOT leaving
// it as FinalityQTDInstant.
//
// QTD-H07 / QTD-CRIT-02 FIX (R29, 2026-07-25): Previously, setting
// signer=nil left finalityType=FinalityQTDInstant, causing
// IsInstantFinality() to return true with no signer available — a
// state-machine inconsistency that could bypass Deactivate authorization
// (DeactivateQTDInstantFinality checks finalityType before doing anything).
// Now finalityType is set based on whether signer is non-nil AND in
// threshold mode.
//
// This is a security-critical invariant:
//
//	finalityType == FinalityQTDInstant  <=>  qtdSigner != nil && qtdSigner.IsThresholdMode()
//
// Without this invariant, an attacker could:
//  1. Call SetQTDSigner(mockSigner) → finalityType = QTDInstant
//  2. Call SetQTDSigner(nil) → qtdSigner = nil BUT finalityType = QTDInstant (bug)
//  3. IsInstantFinality() returns true → code paths think QTD is active
//  4. SubmitCompletedSeal/VerifyInstantFinality use nil signer → panic
//     or, worse, accidentally fail-open in some code path
func TestQTD_H07_SetQTDSigner_Nil_ResetsFinalityType(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	// Initially: CasperFFG, no signer.
	if qfs.GetFinalityType() != FinalityCasperFFG {
		t.Fatalf("initial finalityType = %v, want CasperFFG", qfs.GetFinalityType())
	}
	if qfs.IsInstantFinality() {
		t.Fatal("initial IsInstantFinality() = true, want false")
	}

	// Set a threshold signer → finalityType becomes QTDInstant.
	qfs.SetQTDSigner(&mockThresholdSigner{})
	if qfs.GetFinalityType() != FinalityQTDInstant {
		t.Fatalf("after SetQTDSigner(threshold): finalityType = %v, want QTDInstant", qfs.GetFinalityType())
	}
	if !qfs.IsInstantFinality() {
		t.Fatal("after SetQTDSigner(threshold): IsInstantFinality() = false, want true")
	}

	// Set nil signer → finalityType MUST revert to CasperFFG (QTD-H07 fix).
	qfs.SetQTDSigner(nil)
	if qfs.GetFinalityType() != FinalityCasperFFG {
		t.Errorf("after SetQTDSigner(nil): finalityType = %v, want CasperFFG (QTD-H07: nil signer must reset finalityType)",
			qfs.GetFinalityType())
	}
	if qfs.IsInstantFinality() {
		t.Error("after SetQTDSigner(nil): IsInstantFinality() = true, want false (QTD-H07: nil signer must disable instant finality)")
	}

	// Verify qtdSigner is actually nil.
	qfs.mu.RLock()
	signer := qfs.qtdSigner
	qfs.mu.RUnlock()
	if signer != nil {
		t.Errorf("after SetQTDSigner(nil): qtdSigner = %v, want nil", signer)
	}
}

// TestQTD_H07_SetQTDSigner_NonThreshold_ResetsFinalityType verifies that
// setting a non-threshold-mode signer also reverts finalityType to
// CasperFFG. QTD-H07 fix combines with QTD-H01: QTD-H01 rejects non-nil
// non-threshold signers entirely, so the only way to reach the "else"
// branch in SetQTDSigner is via signer=nil. But the code's else branch
// also covers the theoretical case where QTD-H01's check is bypassed
// (defense in depth). This test verifies the else branch works.
//
// Since QTD-H01 rejects non-threshold signers, this test uses a signer
// that claims NOT to be in threshold mode and verifies SetQTDSigner
// rejects it AND leaves finalityType as CasperFFG.
func TestQTD_H07_SetQTDSigner_NonThreshold_ResetsFinalityType(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	// Set a threshold signer first to enable QTDInstant.
	qfs.SetQTDSigner(&mockThresholdSigner{})
	if qfs.GetFinalityType() != FinalityQTDInstant {
		t.Fatalf("setup: finalityType = %v, want QTDInstant", qfs.GetFinalityType())
	}

	// Try to set a non-threshold signer. QTD-H01 should reject this and
	// leave the existing signer/finalityType unchanged (since the function
	// returns early without modifying qfs.qtdSigner or finalityType).
	nonThreshold := &nonThresholdSigner{}
	qfs.SetQTDSigner(nonThreshold)

	// QTD-H01 rejection means the existing threshold signer remains.
	qfs.mu.RLock()
	signer := qfs.qtdSigner
	qfs.mu.RUnlock()
	if signer == nil {
		t.Fatal("after SetQTDSigner(nonThreshold): qtdSigner = nil, want previous threshold signer (QTD-H01 should reject without clearing)")
	}
	// finalityType should still be QTDInstant (rejection didn't modify state).
	if qfs.GetFinalityType() != FinalityQTDInstant {
		t.Errorf("after SetQTDSigner(nonThreshold): finalityType = %v, want QTDInstant (QTD-H01 rejection must not modify state)",
			qfs.GetFinalityType())
	}

	// Now explicitly set nil to disable QTD — this MUST reset finalityType.
	qfs.SetQTDSigner(nil)
	if qfs.GetFinalityType() != FinalityCasperFFG {
		t.Errorf("after SetQTDSigner(nil): finalityType = %v, want CasperFFG (QTD-H07)",
			qfs.GetFinalityType())
	}
}

// TestQTD_H07_SetQTDSigner_StateMachineInvariant verifies the security
// invariant: finalityType == FinalityQTDInstant iff qtdSigner != nil &&
// qtdSigner.IsThresholdMode(). This invariant must hold across all
// transitions.
func TestQTD_H07_SetQTDSigner_StateMachineInvariant(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	transitions := []struct {
		name        string
		signer      ThresholdKeySigner
		wantFinal   FinalityType
		wantInstant bool
	}{
		{"initial -> nil", nil, FinalityCasperFFG, false},
		{"nil -> threshold", &mockThresholdSigner{}, FinalityQTDInstant, true},
		{"threshold -> nil", nil, FinalityCasperFFG, false},
		{"nil -> threshold (re-enable)", &mockThresholdSigner{}, FinalityQTDInstant, true},
		{"threshold -> nil (final disable)", nil, FinalityCasperFFG, false},
	}

	for i, tt := range transitions {
		qfs.SetQTDSigner(tt.signer)
		gotFinal := qfs.GetFinalityType()
		gotInstant := qfs.IsInstantFinality()
		if gotFinal != tt.wantFinal {
			t.Errorf("transition %d (%s): finalityType = %v, want %v",
				i, tt.name, gotFinal, tt.wantFinal)
		}
		if gotInstant != tt.wantInstant {
			t.Errorf("transition %d (%s): IsInstantFinality() = %v, want %v",
				i, tt.name, gotInstant, tt.wantInstant)
		}
		// Verify invariant: QTDInstant <=> (signer != nil && threshold)
		qfs.mu.RLock()
		signer := qfs.qtdSigner
		qfs.mu.RUnlock()
		invariantHolds := (gotFinal == FinalityQTDInstant) ==
			(signer != nil && signer.IsThresholdMode())
		if !invariantHolds {
			t.Errorf("transition %d (%s): invariant broken — finalityType=%v but signer=%v threshold=%v",
				i, tt.name, gotFinal, signer != nil, signer != nil && signer.IsThresholdMode())
		}
	}
}

// nonThresholdSigner is defined in qtd_h01_test.go — reused here.
