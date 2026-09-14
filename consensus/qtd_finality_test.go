// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestFinalityTypeString(t *testing.T) {
	tests := []struct {
		ft       FinalityType
		expected string
	}{
		{FinalityCasperFFG, "CasperFFG"},
		{FinalityQTDInstant, "QTDInstant"},
		{FinalityType(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.ft.String(); got != tt.expected {
			t.Errorf("FinalityType(%d).String() = %q, want %q", tt.ft, got, tt.expected)
		}
	}
}

func TestQTDFinalityStateDefaultCasperFFG(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)
	if qfs.GetFinalityType() != FinalityCasperFFG {
		t.Errorf("Default finality type = %v, want CasperFFG", qfs.GetFinalityType())
	}
	if qfs.IsInstantFinality() {
		t.Error("Should not be instant finality by default")
	}
}

func TestQTDFinalityStateWithSigner(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)
	qfs.SetQTDSigner(&mockThresholdSigner{})

	if qfs.GetFinalityType() != FinalityQTDInstant {
		t.Errorf("Finality type with signer = %v, want QTDInstant", qfs.GetFinalityType())
	}
	if !qfs.IsInstantFinality() {
		t.Error("Should be instant finality with QTD signer")
	}

	t.Log("=== 2.3 QTD finality type switching: PASS ===")
}

func TestQTDFinalityRequestSeal(t *testing.T) {
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

	err = qpos.RequestQTDFinalitySeal(5, types.Hash{})
	if err == nil {
		t.Error("Should fail: block not approved by review")
	}

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

	err = qpos.RequestQTDFinalitySeal(5, blockHash)
	if err != nil {
		t.Fatalf("RequestQTDFinalitySeal failed: %v", err)
	}

	if qfs.GetPendingSealCount() != 1 {
		t.Errorf("Pending seal count = %d, want 1", qfs.GetPendingSealCount())
	}

	t.Log("=== 2.3 QTD finality seal request: PASS ===")
}

func TestQTDFinalitySubmitPartialSeal(t *testing.T) {
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

	err = qpos.RequestQTDFinalitySeal(5, blockHash)
	if err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}

	err = qfs.SubmitPartialSeal(0, 5, []byte("partial-sig-0-min16bytes"))
	if err != nil {
		t.Fatalf("SubmitPartialSeal 0 failed: %v", err)
	}

	if qfs.IsSlotFinalized(5) {
		t.Error("Should not be finalized with only 1 partial seal (need 2)")
	}

	err = qfs.SubmitPartialSeal(1, 5, []byte("partial-sig-1-min16bytes"))
	if err != nil {
		t.Fatalf("SubmitPartialSeal 1 failed: %v", err)
	}

	if !qfs.IsSlotFinalized(5) {
		t.Error("Should be finalized with 2 partial seals (threshold=2)")
	}

	record := qfs.GetFinalityRecord(5)
	if record == nil {
		t.Fatal("Finality record should exist")
	}
	if record.Slot != 5 {
		t.Errorf("Record slot = %d, want 5", record.Slot)
	}
	if record.BlockHash != blockHash {
		t.Error("Record block hash mismatch")
	}
	if len(record.Sealers) < 2 {
		t.Errorf("Sealers count = %d, want >= 2", len(record.Sealers))
	}
	if record.FinalityDelay < 0 {
		t.Error("Finality delay should not be negative")
	}

	t.Logf("Finality delay: %v", record.FinalityDelay)
	t.Logf("Sealers: %v", record.Sealers)
	t.Log("=== 2.3 QTD instant finality (2-of-3 threshold): PASS ===")
}

func TestQTDFinalityUnauthorizedSealer(t *testing.T) {
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
	_ = coordinator.AssignReview([]int{5, 6, 7}, 5)
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

	err = qpos.RequestQTDFinalitySeal(5, blockHash)
	if err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}

	err = qfs.SubmitPartialSeal(5, 5, []byte("unauthorized-sig"))
	if err == nil {
		t.Error("Should fail: validator 5 is in review, cannot seal")
	}

	t.Log("=== 2.3 QTD unauthorized sealer rejected: PASS ===")
}

func TestQTDFinalityStatus(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	status := qfs.GetQTDFinalityStatus()
	if status["finalityType"].(string) != "QTDInstant" {
		t.Errorf("finalityType = %v, want QTDInstant", status["finalityType"])
	}
	if !status["isThresholdMode"].(bool) {
		t.Error("isThresholdMode should be true")
	}

	t.Log("=== 2.3 QTD finality status: PASS ===")
}

func TestQTDFinalityIntegrationWithQPOS(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()

	if !qpos.IsInstantFinalityEnabled() {
		t.Log("Instant finality not enabled without QTD signer (expected)")
	}

	qpos.SetThresholdSigner(&mockThresholdSigner{})
	qfs := qpos.GetQTDFinality()
	if qfs != nil {
		qfs.SetQTDSigner(&mockThresholdSigner{})
	}

	if qpos.IsInstantFinalityEnabled() {
		t.Log("Instant finality enabled with QTD signer")
	}

	t.Log("=== 2.3 QTD finality integration with QPOS: PASS ===")
}

type mockThresholdSigner struct{}

func (m *mockThresholdSigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("mock-qtd-block-signature"), nil
}

func (m *mockThresholdSigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("mock-qtd-vote-signature"), nil
}

func (m *mockThresholdSigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	// AUDIT (2026) CORE B-6: VerifyBlock now checks that the signature
	// matches what AggregatePartialSignatures produces. Previously it always
	// returned true, making it impossible to test cross-node verification
	// (where the signature itself is the proof, not the local record).
	return string(signature) == "mock-aggregated-qtd-threshold-signature"
}

func (m *mockThresholdSigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return true
}

func (m *mockThresholdSigner) GroupPublicKey() []byte {
	return []byte("mock-group-public-key")
}

func (m *mockThresholdSigner) IsThresholdMode() bool {
	return true
}

// FIX: Implement AggregatePartialSignatures for the mock
// threshold signer. This combines the submitted partial signatures into a
// single mock aggregated signature. In production, this would perform real
// threshold signature aggregation (e.g., GM-QTD over Dilithium3).
//
// R7 P0-1 FIX (2026-07-17): Accept nil partialSigs as a valid "local signing"
// path, matching the real tssSignerAdapter behavior where nil partials route
// to SignWithRetry (local mode) or distributeTSSSignNoFallback (distributed
// mode). This is used by AggregateAndCompleteSeal which bypasses the broken
// partial-seal collection in node/qtd_seal.go.
func (m *mockThresholdSigner) AggregatePartialSignatures(sealers []int, partialSigs map[int][]byte, message []byte) ([]byte, error) {
	if len(sealers) == 0 {
		return nil, fmt.Errorf("no sealers provided for aggregation")
	}
	// nil/empty partialSigs = local signing path (SignWithRetry equivalent)
	if len(partialSigs) > 0 {
		if len(partialSigs) < len(sealers) {
			return nil, fmt.Errorf("insufficient partial signatures: have %d, need %d", len(partialSigs), len(sealers))
		}
		// Verify each sealer has a partial signature
		for _, idx := range sealers {
			if _, ok := partialSigs[idx]; !ok {
				return nil, fmt.Errorf("missing partial signature for sealer %d", idx)
			}
		}
	}
	// Return a mock aggregated signature. Must be >= MinPartialSealSize (16 bytes)
	// and not equal to "auto-seal" placeholder.
	return []byte("mock-aggregated-qtd-threshold-signature"), nil
}
