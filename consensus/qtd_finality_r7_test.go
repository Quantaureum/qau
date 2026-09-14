// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR7SubmitCompletedSeal verifies the R7 P0-1 fix: a pre-computed
// QTD threshold signature can be submitted directly to complete a pending seal,
// bypassing the broken partial-seal collection in node/qtd_seal.go.
func TestR7SubmitCompletedSeal(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	// CONS-P0-01 + P2-QTD-HISTORY FIX (R31, 2026-07-27): Use
	// SetQTDSignerForEpoch to record the signer's group key under epoch 0
	// (slot 5 / SlotsPerEpoch=32 = epoch 0). SetQTDSigner records under
	// qpos.GetCurrentEpoch(), which is wall-clock-derived and can be
	// non-zero when a prior test in the same package called SetGenesisTime.
	// That would cause getGroupPublicKeyForEpochLocked(0, nonZero) to
	// fail-closed (QTD-H03: group public key empty for epoch 0).
	qfs.SetQTDSignerForEpoch(&mockThresholdSigner{}, 0)

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[5] = &ReviewSlotResult{
		Slot:          5,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	blockHash := types.Hash{}
	blockHash[0] = 0xAB

	// QUANTUM-FIX: completeSealLockedFinalize now fails closed when
	// no canonical root is known for the slot. Set the slot block root so
	// the seal can be finalized (mirrors production behavior where the
	// canonical block is imported before QTD sealing).
	qpos.SetSlotBlockRoot(5, blockHash)

	if err := qpos.RequestQTDFinalitySeal(5, blockHash); err != nil {
		t.Fatalf("RequestQTDFinalitySeal failed: %v", err)
	}

	sealers := []int{0, 1, 2}
	sig := []byte("mock-aggregated-qtd-threshold-signature")
	if err := qfs.SubmitCompletedSeal(5, sig, sealers); err != nil {
		t.Fatalf("SubmitCompletedSeal failed: %v", err)
	}

	if !qfs.IsSlotFinalized(5) {
		t.Error("Slot 5 should be finalized after SubmitCompletedSeal")
	}

	record := qfs.GetFinalityRecord(5)
	if record == nil {
		t.Fatal("Finality record missing for slot 5")
	}
	if string(record.QTDSignature) != "mock-aggregated-qtd-threshold-signature" {
		t.Errorf("QTDSignature mismatch")
	}
	if len(record.Sealers) != 3 {
		t.Errorf("Sealers count = %d, want 3", len(record.Sealers))
	}

	t.Log("=== R7 P0-1: SubmitCompletedSeal: PASS ===")
}

// TestR7SubmitCompletedSealRejectsNonCanonical verifies R4-CORE-04.
func TestR7SubmitCompletedSealRejectsNonCanonical(t *testing.T) {
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
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[5] = &ReviewSlotResult{
		Slot:         5,
		ApproveStake: big.NewInt(3000),
		RejectStake:  big.NewInt(1000),
		TotalStake:   big.NewInt(4000),
		Verdict:      VerdictApproved,
	}
	review.mu.Unlock()

	canonicalHash := types.Hash{}
	canonicalHash[0] = 0xCC
	qpos.SetSlotBlockRoot(5, canonicalHash)

	requestHash := types.Hash{}
	requestHash[0] = 0xAB

	if err := qpos.RequestQTDFinalitySeal(5, requestHash); err == nil {
		t.Error("RequestQTDFinalitySeal should reject non-canonical blockHash (R4-CORE-04)")
	}

	t.Log("=== R4-CORE-04: rejects non-canonical: PASS ===")
}

// TestR7AggregateAndCompleteSeal verifies the R7 P0-1 production path.
func TestR7AggregateAndCompleteSeal(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	// CONS-P0-01 + P2-QTD-HISTORY FIX (R31, 2026-07-27): Use
	// SetQTDSignerForEpoch to record the signer's group key under epoch 0
	// (slot 7 / SlotsPerEpoch=32 = epoch 0). See TestR7SubmitCompletedSeal
	// for the full rationale (SetQTDSigner uses wall-clock-derived epoch
	// which can be polluted by prior tests calling SetGenesisTime).
	qfs.SetQTDSignerForEpoch(&mockThresholdSigner{}, 0)

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[7] = &ReviewSlotResult{
		Slot:         7,
		ApproveStake: big.NewInt(3000),
		RejectStake:  big.NewInt(1000),
		TotalStake:   big.NewInt(4000),
		Verdict:      VerdictApproved,
	}
	review.mu.Unlock()

	blockHash := types.Hash{}
	blockHash[0] = 0xDD

	// QUANTUM-FIX: completeSealLockedFinalize now fails closed when
	// no canonical root is known for the slot. Set the slot block root so
	// the seal can be finalized (mirrors production behavior where the
	// canonical block is imported before QTD sealing).
	qpos.SetSlotBlockRoot(7, blockHash)

	if err := qpos.RequestQTDFinalitySeal(7, blockHash); err != nil {
		t.Fatalf("RequestQTDFinalitySeal failed: %v", err)
	}

	sealers := []int{0, 1, 2}
	if err := qfs.AggregateAndCompleteSeal(7, sealers); err != nil {
		t.Fatalf("AggregateAndCompleteSeal failed: %v", err)
	}

	if !qfs.IsSlotFinalized(7) {
		t.Error("Slot 7 should be finalized after AggregateAndCompleteSeal")
	}

	t.Log("=== R7 P0-1: AggregateAndCompleteSeal: PASS ===")
}

// TestR7AggregateAndCompleteSealFailsClosed verifies fail-closed behavior.
func TestR7AggregateAndCompleteSealFailsClosed(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&failingR7ThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[9] = &ReviewSlotResult{
		Slot:         9,
		ApproveStake: big.NewInt(3000),
		RejectStake:  big.NewInt(1000),
		TotalStake:   big.NewInt(4000),
		Verdict:      VerdictApproved,
	}
	review.mu.Unlock()

	blockHash := types.Hash{}
	blockHash[0] = 0xEE

	if err := qpos.RequestQTDFinalitySeal(9, blockHash); err != nil {
		t.Fatalf("RequestQTDFinalitySeal failed: %v", err)
	}

	sealers := []int{0, 1, 2}
	err = qfs.AggregateAndCompleteSeal(9, sealers)
	if err == nil {
		t.Error("AggregateAndCompleteSeal should fail when signer fails (fail-closed)")
	}

	if qfs.IsSlotFinalized(9) {
		t.Error("Slot 9 should NOT be finalized when signing fails")
	}

	t.Log("=== R7 P0-1: AggregateAndCompleteSeal fail-closed: PASS ===")
}

// TestR7SubmitCompletedSealRejectsEmptySig verifies that empty signatures
// are rejected (defense against placeholder signatures).
func TestR7SubmitCompletedSealRejectsEmptySig(t *testing.T) {
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
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[11] = &ReviewSlotResult{
		Slot:         11,
		ApproveStake: big.NewInt(3000),
		RejectStake:  big.NewInt(1000),
		TotalStake:   big.NewInt(4000),
		Verdict:      VerdictApproved,
	}
	review.mu.Unlock()

	blockHash := types.Hash{}
	blockHash[0] = 0xFF

	if err := qpos.RequestQTDFinalitySeal(11, blockHash); err != nil {
		t.Fatalf("RequestQTDFinalitySeal failed: %v", err)
	}

	sealers := []int{0, 1, 2}
	err = qfs.SubmitCompletedSeal(11, []byte{}, sealers)
	if err == nil {
		t.Error("SubmitCompletedSeal should reject empty signature")
	}

	if qfs.IsSlotFinalized(11) {
		t.Error("Slot 11 should NOT be finalized with empty signature")
	}

	t.Log("=== R7 P0-1: rejects empty sig: PASS ===")
}

// failingR7ThresholdSigner always fails, simulating distributed signing failure.
type failingR7ThresholdSigner struct{}

func (f *failingR7ThresholdSigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return nil, fmt.Errorf("failing signer: SignBlock always fails")
}
func (f *failingR7ThresholdSigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return nil, fmt.Errorf("failing signer: SignVote always fails")
}
func (f *failingR7ThresholdSigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	return false
}
func (f *failingR7ThresholdSigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return false
}
func (f *failingR7ThresholdSigner) GroupPublicKey() []byte {
	return nil
}
func (f *failingR7ThresholdSigner) IsThresholdMode() bool {
	return true
}
func (f *failingR7ThresholdSigner) AggregatePartialSignatures(sealers []int, partialSigs map[int][]byte, message []byte) ([]byte, error) {
	return nil, fmt.Errorf("failing signer: AggregatePartialSignatures always fails (simulating distributed signing timeout)")
}
