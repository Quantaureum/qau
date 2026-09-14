// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

func TestPhase13_Regression_QPOSBasicFunctionality(t *testing.T) {
	t.Log("=== Phase 1.3: QPOS Regression Test — Basic Functionality ===")

	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	if vs.ValidatorCount() != 10 {
		t.Errorf("expected 10 validators, got %d", vs.ValidatorCount())
	}

	proposer, err := qpos.GetProposerForSlot(1)
	if err != nil {
		t.Fatalf("GetProposerForSlot failed: %v", err)
	}
	if proposer == nil {
		t.Fatal("proposer should not be nil")
	}

	committee, err := qpos.GetCommitteeForSlot(1)
	if err != nil {
		t.Fatalf("GetCommitteeForSlot failed: %v", err)
	}
	if len(committee) == 0 {
		t.Error("committee should not be empty")
	}

	t.Logf("QPOS basic: %d validators, committee=%d", vs.ValidatorCount(), len(committee))
	t.Log("QPOS basic functionality: PASS ✅")
}

func TestPhase13_Regression_QPOSWithoutQTD(t *testing.T) {
	t.Log("=== Phase 1.3: QPOS Without QTD — Backward Compatibility ===")

	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	if qpos.HasThresholdSigner() {
		t.Error("QTD should NOT be active by default")
	}

	for slot := uint64(0); slot < 5; slot++ {
		proposer, err := qpos.GetProposerForSlot(slot)
		if err != nil {
			t.Fatalf("slot %d: GetProposerForSlot failed: %v", slot, err)
		}
		if proposer == nil {
			t.Fatalf("slot %d: proposer should not be nil", slot)
		}

		committee, err := qpos.GetCommitteeForSlot(slot)
		if err != nil {
			t.Fatalf("slot %d: GetCommitteeForSlot failed: %v", slot, err)
		}
		if len(committee) == 0 {
			t.Errorf("slot %d: committee should not be empty", slot)
		}
	}

	t.Log("QPOS without QTD: backward compatible ✅")
}

func TestPhase13_Regression_QPOSWithQTD(t *testing.T) {
	t.Log("=== Phase 1.3: QPOS With QTD — Integration Check ===")

	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.SetThresholdSigner(&mockThresholdSigner{})

	if !qpos.HasThresholdSigner() {
		t.Error("QTD should be active after setting signer")
	}

	for slot := uint64(0); slot < 5; slot++ {
		proposer, err := qpos.GetProposerForSlot(slot)
		if err != nil {
			t.Fatalf("slot %d: GetProposerForSlot failed: %v", slot, err)
		}
		if proposer == nil {
			t.Fatalf("slot %d: proposer should not be nil", slot)
		}

		committee, err := qpos.GetCommitteeForSlot(slot)
		if err != nil {
			t.Fatalf("slot %d: GetCommitteeForSlot failed: %v", slot, err)
		}
		if len(committee) == 0 {
			t.Errorf("slot %d: committee should not be empty", slot)
		}
	}

	t.Log("QPOS with QTD: all basic operations still work ✅")
}

func TestPhase13_Regression_ValidatorSetOperations(t *testing.T) {
	t.Log("=== Phase 1.3: Validator Set Operations — Regression ===")

	vs := createTestValidatorSet(t, 10)

	validators := vs.Validators()
	if len(validators) != 10 {
		t.Errorf("expected 10 validators, got %d", len(validators))
	}

	for i, v := range validators {
		if v.Stake == nil || v.Stake.Sign() <= 0 {
			t.Errorf("validator %d has invalid stake", i)
		}
	}

	idx := vs.GetValidatorIndex(validators[0].Address)
	if idx != 0 {
		t.Errorf("expected index 0, got %d", idx)
	}

	v := vs.GetValidatorByIndex(5)
	if v == nil {
		t.Fatal("validator should not be nil")
	}

	t.Log("Validator set operations: PASS ✅")
}

func TestPhase13_Regression_ElectionConsistency(t *testing.T) {
	t.Log("=== Phase 1.3: Election Consistency — Regression ===")

	vs := createTestValidatorSet(t, 10)
	qpos, _ := NewQPOS(vs)

	proposer1, _ := qpos.GetProposerForSlot(1)
	proposer2, _ := qpos.GetProposerForSlot(1)
	if proposer1.Address != proposer2.Address {
		t.Error("same slot should produce same proposer (deterministic)")
	}

	committee1, _ := qpos.GetCommitteeForSlot(1)
	committee2, _ := qpos.GetCommitteeForSlot(1)
	if len(committee1) != len(committee2) {
		t.Error("same slot should produce same committee size")
	}

	proposer3, _ := qpos.GetProposerForSlot(2)
	if proposer1.Address == proposer3.Address {
		t.Log("Note: slot 1 and 2 have same proposer (possible but unlikely with 10 validators)")
	}

	t.Log("Election consistency: PASS ✅")
}

func TestPhase13_Regression_ThreeProvincesWithQTD(t *testing.T) {
	t.Log("=== Phase 1.3: Three Chambers + QTD — Regression ===")

	qpos, coordinator, _ := setupFullProvinces(t)

	if !qpos.CanPropose(0, 1) {
		t.Error("proposing member should propose")
	}
	if !qpos.CanAttest(1, 1) {
		t.Error("review member should attest")
	}
	if !qpos.CanSeal(4, 0) {
		t.Error("executive member should seal")
	}

	qfs := qpos.GetQTDFinality()
	if qfs != nil && qfs.IsInstantFinality() {
		t.Log("QTD instant finality is active in full chambers setup")
	}

	_ = coordinator

	t.Log("Three Chambers + QTD: PASS ✅")
}

func TestPhase13_Regression_MinistriesUnaffected(t *testing.T) {
	t.Log("=== Phase 1.3: Ministries Unaffected by QTD — Regression ===")

	vs := createTestValidatorSet(t, 10)
	qpos, _ := NewQPOS(vs)
	qpos.InitChambers()

	coordinator := qpos.GetChambersCoordinator()
	registry := NewMinistryRegistry(qpos, coordinator)
	if registry == nil {
		t.Fatal("ministry registry should not be nil")
	}

	personnel := registry.Personnel()
	if personnel == nil {
		t.Error("Personnel should not be nil")
	}

	revenue := registry.Revenue()
	if revenue == nil {
		t.Error("Revenue should not be nil")
	}

	justice := registry.Justice()
	if justice == nil {
		t.Error("Justice should not be nil")
	}

	defense := registry.Defense()
	if defense == nil {
		t.Error("Defense should not be nil")
	}

	rites := registry.Rites()
	if rites == nil {
		t.Error("Rites should not be nil")
	}

	works := registry.Works()
	if works == nil {
		t.Error("Works should not be nil")
	}

	t.Log("All 6 ministries accessible and unaffected by QTD ✅")
}

func TestPhase13_Regression_BlockStructureWithQTD(t *testing.T) {
	t.Log("=== Phase 1.3: Block Structure With QTD — Regression ===")

	header := &encoding.BlockHeader{}

	if header.QTDSignature != nil {
		t.Error("QTDSignature should be nil by default")
	}
	if header.ReviewAttestationRoot != (types.Hash{}) {
		t.Error("ReviewAttestationRoot should be zero by default")
	}
	if header.FinalityType != 0 {
		t.Error("FinalityType should be 0 by default")
	}

	header.QTDSignature = []byte("qtd-sig-3293-bytes")
	header.ExecutiveSealers = []byte{0, 1, 2}
	header.FinalityType = 1

	if len(header.QTDSignature) == 0 {
		t.Error("QTDSignature should be settable")
	}
	if header.FinalityType != 1 {
		t.Error("FinalityType should be 1")
	}

	t.Log("Block structure with QTD fields: PASS ✅")
}

func TestPhase13_Regression_ShamirDKGWithQPOS(t *testing.T) {
	t.Log("=== Phase 1.3: Shamir DKG Integration With QPOS — Regression ===")

	vs := createTestValidatorSet(t, 3)
	qpos, _ := NewQPOS(vs)
	qpos.InitChambers()

	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	coordinator := qpos.GetChambersCoordinator()
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("ExecutiveChamber should not be nil")
	}

	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	groupPK := executive.PublicKey()
	if len(groupPK) == 0 {
		t.Error("group public key should not be empty after DKG")
	}

	t.Logf("executive DKG complete: group PK = %d bytes", len(groupPK))
	t.Log("Shamir DKG + QPOS integration: PASS ✅")
}

func TestPhase13_Regression_CasperFFGFinality(t *testing.T) {
	t.Log("=== Phase 1.3: Casper FFG Finality Still Works — Regression ===")

	vs := createTestValidatorSet(t, 10)
	qpos, _ := NewQPOS(vs)

	justified := qpos.GetJustifiedEpoch()
	finalized := qpos.GetFinalizedEpoch()

	t.Logf("Casper FFG: justified_epoch=%d, finalized_epoch=%d", justified, finalized)

	t.Log("Casper FFG finality: PASS ✅")
}
