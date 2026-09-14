// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

func TestBlockHeaderStardustFields(t *testing.T) {
	header := &encoding.BlockHeader{
		Slot:         1,
		Epoch:        0,
		FinalityType: 1,
	}

	header.QTDSignature = []byte("qtd-threshold-signature")
	header.ReviewAttestationRoot = types.Hash{0x01}
	header.ExecutiveSealers = []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}

	if !IsQTDInstantFinality(header) {
		t.Error("Should be QTD instant finality")
	}

	sealers := GetExecutiveSealers(header)
	if len(sealers) != 3 {
		t.Fatalf("Sealers count = %d, want 3", len(sealers))
	}
	if sealers[0] != 0 || sealers[1] != 1 || sealers[2] != 2 {
		t.Errorf("Sealers = %v, want [0 1 2]", sealers)
	}

	header.FinalityType = 0
	if IsQTDInstantFinality(header) {
		t.Error("Should not be QTD instant finality when FinalityType=0")
	}

	t.Log("=== 2.6 Block header stardust fields: PASS ===")
}

func TestPopulateStardustFieldsNoProvinces(t *testing.T) {
	header := &encoding.BlockHeader{Slot: 1}

	err := PopulateStardustFields(header, nil)
	if err != nil {
		t.Fatalf("PopulateStardustFields with nil QPOS should not error: %v", err)
	}
	if header.FinalityType != 0 {
		t.Errorf("FinalityType = %d, want 0 (CasperFFG)", header.FinalityType)
	}

	vs := createTestValidatorSet(t, 10)
	qpos, _ := NewQPOS(vs)

	err = PopulateStardustFields(header, qpos)
	if err != nil {
		t.Fatalf("PopulateStardustFields without chambers should not error: %v", err)
	}
	if header.FinalityType != 0 {
		t.Errorf("FinalityType = %d, want 0 (CasperFFG) without chambers", header.FinalityType)
	}

	t.Log("=== 2.6 Populate stardust fields (no chambers): PASS ===")
}

func TestPopulateStardustFieldsWithProvinces(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, _ := NewQPOS(vs)
	qpos.InitChambers()

	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[1] = &ReviewSlotResult{
		Slot:          1,
		CommitteeSize: 5,
		ApproveCount:  4,
		RejectCount:   1,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	flow := NewThreeChambersFlow(qpos, coordinator)
	blockHash := types.Hash{}
	blockHash[0] = 0x01

	_ = flow.ProposeBlock(1, blockHash, 3)
	_ = flow.ReviewBlock(1)
	_ = flow.SealBlock(1)

	// FIX (companion): Submit partial seals from executive
	// members (0, 1, 2) to complete the QTD threshold signature.
	for _, member := range []int{0, 1, 2} {
		mockSig := []byte(fmt.Sprintf("partial-seal-%d-min16bytes", member))
		_ = qfs.SubmitPartialSeal(member, 1, mockSig)
	}
	_ = flow.CompleteSeal(1)
	_ = flow.FinalizeBlock(1)

	header := &encoding.BlockHeader{Slot: 1, Epoch: 0}
	err := PopulateStardustFields(header, qpos)
	if err != nil {
		t.Fatalf("PopulateStardustFields failed: %v", err)
	}

	if header.FinalityType != 1 {
		t.Errorf("FinalityType = %d, want 1 (QTDInstant)", header.FinalityType)
	}
	if len(header.QTDSignature) == 0 {
		t.Error("QTDSignature should not be empty")
	}
	if header.ReviewAttestationRoot == (types.Hash{}) {
		t.Error("ReviewAttestationRoot should not be zero")
	}
	if len(header.ExecutiveSealers) == 0 {
		t.Error("ExecutiveSealers should not be empty")
	}

	sealers := GetExecutiveSealers(header)
	if len(sealers) < 2 {
		t.Errorf("Should have at least 2 sealers (2-of-3 threshold), got %d", len(sealers))
	}

	t.Logf("FinalityType: %d, QTD sig len: %d, Sealers: %v", header.FinalityType, len(header.QTDSignature), sealers)
	t.Log("=== 2.6 Populate stardust fields (with chambers): PASS ===")
}

func TestVerifyStardustFinality(t *testing.T) {
	header := &encoding.BlockHeader{Slot: 1, FinalityType: 0}
	if !VerifyStardustFinality(header, types.Hash{}, nil) {
		t.Error("CasperFFG blocks should always pass verification")
	}

	header.FinalityType = 2
	if VerifyStardustFinality(header, types.Hash{}, nil) {
		t.Error("Unknown finality type should fail verification")
	}

	header.FinalityType = 1
	if VerifyStardustFinality(nil, types.Hash{}, nil) {
		t.Error("Nil header should fail verification")
	}

	t.Log("=== 2.6 Verify stardust finality: PASS ===")
}

func TestGetExecutiveSealersEmpty(t *testing.T) {
	if sealers := GetExecutiveSealers(nil); sealers != nil {
		t.Error("Nil header should return nil sealers")
	}

	header := &encoding.BlockHeader{}
	if sealers := GetExecutiveSealers(header); sealers != nil {
		t.Error("Empty ExecutiveSealers should return nil")
	}

	t.Log("=== 2.6 Get executive sealers (edge cases): PASS ===")
}

func TestBlockHeaderEqualWithStardust(t *testing.T) {
	h1 := &encoding.BlockHeader{
		Slot:                  1,
		FinalityType:          1,
		QTDSignature:          []byte("sig1"),
		ReviewAttestationRoot: types.Hash{0x01},
		ExecutiveSealers:      []byte{0, 0, 0, 0},
	}

	h2 := &encoding.BlockHeader{
		Slot:                  1,
		FinalityType:          1,
		QTDSignature:          []byte("sig1"),
		ReviewAttestationRoot: types.Hash{0x01},
		ExecutiveSealers:      []byte{0, 0, 0, 0},
	}

	if !h1.Equal(h2) {
		t.Error("Identical stardust headers should be equal")
	}

	h2.FinalityType = 0
	if h1.Equal(h2) {
		t.Error("Different FinalityType headers should not be equal")
	}

	t.Log("=== 2.6 Block header equality with stardust fields: PASS ===")
}
