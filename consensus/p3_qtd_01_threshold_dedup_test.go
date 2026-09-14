// Quantaureum Node source, version 1.0.0.
package consensus

// P3-QTD-01 FIX (R29, 2026-07-26): Regression tests for the centralized
// snapshotExecutiveStakes + computeSealerWeight helpers.
//
// Previously the weight-threshold computation (snapshot executive member
// stakes → compute total → compute requiredWeight = ceil(2/3 * total))
// and the sealer weight accumulation (sum stakes of participating
// sealers) were duplicated across three call sites:
//   - RequestSeal (local seal request path)
//   - ReceiveSealAnnouncement (P2P-received seal path)
//   - completeSealLocked (local seal completion path)
//
// The three copies had already diverged slightly (different variable
// names for the modulo check, slightly different guard structure). The
// fix centralized the logic into snapshotExecutiveStakes and
// computeSealerWeight. These tests verify the helpers compute the
// correct values so the three call sites remain consistent.

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestP3_QTD_01_SnapshotExecutiveStakes_ComputesCorrectThreshold
// verifies that snapshotExecutiveStakes returns the correct member stakes,
// total executive stake, and required weight (ceil(2/3 * total)).
//
// Setup: 10 validators with stakes [100, 100, 9800, 1000, 1000, ...].
// Executive chamber = {0, 1, 2} (total = 10000).
// RequiredWeight = ceil(10000 * 2 / 3) = ceil(20000/3) = ceil(6666.67) = 6667.
func TestP3_QTD_01_SnapshotExecutiveStakes_ComputesCorrectThreshold(t *testing.T) {
	validators := make([]*Validator, 10)
	for i := 0; i < 10; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		stake := big.NewInt(1000)
		if i == 0 {
			stake = big.NewInt(100) // small stake
		} else if i == 1 {
			stake = big.NewInt(100) // small stake
		} else if i == 2 {
			stake = big.NewInt(9800) // large stake
		}
		validators[i] = &Validator{
			Address:        addr,
			Stake:          stake,
			Active:         true,
			PublicKeyBytes: make([]byte, 1952),
		}
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}

	// Executive chamber = {0, 1, 2}, total stake = 100 + 100 + 9800 = 10000
	if err := coordinator.AssignExecutive([]int{0, 1, 2}, 0); err != nil {
		t.Fatalf("AssignExecutive failed: %v", err)
	}
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	qfs := qpos.GetQTDFinality()

	// Call the shared helper.
	memberStakes, totalExecutiveStake, requiredWeight := qfs.snapshotExecutiveStakes(0)

	// Verify member stakes.
	if memberStakes == nil {
		t.Fatal("P3-QTD-01 REGRESSION: memberStakes is nil — snapshotExecutiveStakes " +
			"should return a non-nil map when the executive chamber is configured")
	}
	if len(memberStakes) != 3 {
		t.Errorf("expected 3 executive members, got %d", len(memberStakes))
	}
	for _, idx := range []int{0, 1, 2} {
		if _, ok := memberStakes[idx]; !ok {
			t.Errorf("memberStakes missing member %d", idx)
		}
	}

	// Verify total stake = 10000.
	if totalExecutiveStake == nil {
		t.Fatal("P3-QTD-01 REGRESSION: totalExecutiveStake is nil")
	}
	if totalExecutiveStake.Cmp(big.NewInt(10000)) != 0 {
		t.Errorf("totalExecutiveStake = %s, want 10000", totalExecutiveStake.String())
	}

	// Verify required weight = ceil(10000 * 2 / 3) = 6667.
	if requiredWeight == nil {
		t.Fatal("P3-QTD-01 REGRESSION: requiredWeight is nil")
	}
	if requiredWeight.Cmp(big.NewInt(6667)) != 0 {
		t.Errorf("requiredWeight = %s, want 6667 (ceil(2/3 * 10000))",
			requiredWeight.String())
	}
}

// TestP3_QTD_01_SnapshotExecutiveStakes_CeilingRounding verifies the
// ceil(2/3 * total) computation rounds UP for non-divisible totals.
//
// Setup: total = 10 → 2*10 = 20 → 20/3 = 6 remainder 2 → ceil = 7.
// This catches regressions where the modulo check is accidentally
// inverted (using floor instead of ceil), which would lower the
// threshold and allow minority-stake finalization.
func TestP3_QTD_01_SnapshotExecutiveStakes_CeilingRounding(t *testing.T) {
	validators := make([]*Validator, 3)
	for i := 0; i < 3; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		// Each validator has stake = 10/3 is not integer; use stake=3 each
		// so total = 9, then 2*9=18, 18/3=6, remainder 0 → ceil = 6.
		// To get remainder > 0, use stakes [3, 3, 4] → total = 10.
		stake := big.NewInt(3)
		if i == 2 {
			stake = big.NewInt(4)
		}
		validators[i] = &Validator{
			Address:        addr,
			Stake:          stake,
			Active:         true,
			PublicKeyBytes: make([]byte, 1952),
		}
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if err := coordinator.AssignExecutive([]int{0, 1, 2}, 0); err != nil {
		t.Fatalf("AssignExecutive failed: %v", err)
	}
	executive := coordinator.GetExecutiveChamber()
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	qfs := qpos.GetQTDFinality()
	_, total, requiredWeight := qfs.snapshotExecutiveStakes(0)

	// total = 3 + 3 + 4 = 10
	if total.Cmp(big.NewInt(10)) != 0 {
		t.Errorf("total = %s, want 10", total.String())
	}

	// ceil(10 * 2 / 3) = ceil(20/3) = ceil(6.67) = 7
	if requiredWeight.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("P3-QTD-01 REGRESSION: requiredWeight = %s, want 7 "+
			"(ceil(2/3 * 10) = 7, NOT floor = 6). The modulo check "+
			"may be inverted, lowering the threshold and allowing "+
			"minority-stake finalization.", requiredWeight.String())
	}
}

// TestP3_QTD_01_SnapshotExecutiveStakes_NilWhenNoCoordinator verifies
// the helper returns (nil, nil, nil) when the coordinator is unavailable,
// matching the previous behavior where the weight check was skipped
// rather than failing closed. This is important because callers
// (RequestSeal, ReceiveSealAnnouncement) rely on the nil return to
// skip the weight check gracefully when stakes are not configured.
func TestP3_QTD_01_SnapshotExecutiveStakes_NilWhenNoCoordinator(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	// Do NOT call InitChambers — coordinator will be nil.
	qfs := NewQTDFinalityState(qpos)

	memberStakes, total, requiredWeight := qfs.snapshotExecutiveStakes(0)

	if memberStakes != nil || total != nil || requiredWeight != nil {
		t.Errorf("P3-QTD-01 REGRESSION: expected (nil, nil, nil) when "+
			"coordinator is nil, got (%v, %v, %v). Callers rely on "+
			"the nil return to skip the weight check — a non-nil "+
			"return with zero values could cause division-by-zero or "+
			"false rejection.", memberStakes, total, requiredWeight)
	}
}

// TestP3_QTD_01_ComputeSealerWeight_AccumulatesCorrectly verifies
// computeSealerWeight sums the stakes of the given sealers correctly,
// including the edge case of duplicate indices (which should be
// counted multiple times, matching the original inline behavior —
// the dedup happens at a higher level in ReceiveSealAnnouncement).
func TestP3_QTD_01_ComputeSealerWeight_AccumulatesCorrectly(t *testing.T) {
	memberStakes := map[int]*big.Int{
		0: big.NewInt(100),
		1: big.NewInt(200),
		2: big.NewInt(9800),
	}

	tests := []struct {
		name    string
		sealers []int
		want    int64
	}{
		{"empty sealers", []int{}, 0},
		{"single sealer", []int{0}, 100},
		{"two sealers", []int{0, 1}, 300},
		{"all sealers", []int{0, 1, 2}, 10100},
		{"unknown index skipped", []int{0, 99}, 100}, // 99 not in map
		{"negative index skipped", []int{-1, 0}, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeSealerWeight(tt.sealers, memberStakes)
			if got.Cmp(big.NewInt(tt.want)) != 0 {
				t.Errorf("computeSealerWeight(%v) = %s, want %d",
					tt.sealers, got.String(), tt.want)
			}
		})
	}
}

// TestP3_QTD_01_ComputeSealerWeight_NilStakeSkipped verifies that
// nil stake entries in the memberStakes map are safely skipped,
// preventing a nil-pointer dereference panic. This mirrors the
// original inline `if stake, ok := memberStakes[idx]; ok && stake != nil`
// guard.
func TestP3_QTD_01_ComputeSealerWeight_NilStakeSkipped(t *testing.T) {
	memberStakes := map[int]*big.Int{
		0: big.NewInt(100),
		1: nil, // nil stake — should be skipped, not panic
		2: big.NewInt(300),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("P3-QTD-01 REGRESSION: computeSealerWeight panicked "+
				"on nil stake: %v. The helper must skip nil entries "+
				"gracefully (matching the original inline guard "+
				"`if stake, ok := ...; ok && stake != nil`).", r)
		}
	}()

	got := computeSealerWeight([]int{0, 1, 2}, memberStakes)
	// 100 + (nil skipped) + 300 = 400
	if got.Cmp(big.NewInt(400)) != 0 {
		t.Errorf("computeSealerWeight with nil stake = %s, want 400 "+
			"(nil stake should be skipped)", got.String())
	}
}

// TestP3_QTD_01_RequestSealAndReceiveSealAnnouncement_UseSameThreshold
// is the core consistency test: it verifies that the requiredWeight
// computed by RequestSeal (stored in PendingSeal) matches the
// requiredWeight computed by ReceiveSealAnnouncement (used inline to
// reject insufficient-weight seals).
//
// Before the P3-QTD-01 fix, the two paths had separate inline
// computations that could diverge. Now both use snapshotExecutiveStakes,
// so they MUST return identical values for the same epoch.
func TestP3_QTD_01_RequestSealAndReceiveSealAnnouncement_UseSameThreshold(t *testing.T) {
	validators := make([]*Validator, 10)
	for i := 0; i < 10; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		stake := big.NewInt(1000)
		if i == 0 {
			stake = big.NewInt(100)
		} else if i == 1 {
			stake = big.NewInt(100)
		} else if i == 2 {
			stake = big.NewInt(9800)
		}
		validators[i] = &Validator{
			Address:        addr,
			Stake:          stake,
			Active:         true,
			PublicKeyBytes: make([]byte, 1952),
		}
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if err := coordinator.AssignExecutive([]int{0, 1, 2}, 0); err != nil {
		t.Fatalf("AssignExecutive failed: %v", err)
	}
	executive := coordinator.GetExecutiveChamber()
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	// Compute the threshold via the shared helper (used by both paths).
	_, _, expectedRequiredWeight := qfs.snapshotExecutiveStakes(0)
	if expectedRequiredWeight == nil {
		t.Fatal("expected non-nil requiredWeight from snapshotExecutiveStakes")
	}

	// Path 1: RequestSeal stores RequiredWeight in the PendingSeal.
	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[7] = &ReviewSlotResult{
		Slot:          7,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	blockHash := types.Hash{}
	blockHash[0] = 0xCD
	qpos.SetSlotBlockRoot(7, blockHash)

	if err := qpos.RequestQTDFinalitySeal(7, blockHash); err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}

	// Read the PendingSeal's RequiredWeight (set by RequestSeal via the helper).
	qfs.mu.RLock()
	pending, exists := qfs.pendingSeals[7]
	qfs.mu.RUnlock()
	if !exists {
		t.Fatal("PendingSeal for slot 7 not found")
	}
	if pending.RequiredWeight == nil {
		t.Fatal("PendingSeal.RequiredWeight is nil — RequestSeal did not " +
			"use snapshotExecutiveStakes")
	}
	if pending.RequiredWeight.Cmp(expectedRequiredWeight) != 0 {
		t.Errorf("P3-QTD-01 REGRESSION: RequestSeal RequiredWeight = %s, "+
			"but snapshotExecutiveStakes returned %s. The two paths "+
			"diverged — they MUST use the same helper.",
			pending.RequiredWeight.String(), expectedRequiredWeight.String())
	}

	// Path 2: ReceiveSealAnnouncement uses the same helper internally.
	// We verify this by checking that a seal with weight JUST BELOW the
	// threshold is rejected, and one AT OR ABOVE the threshold is accepted
	// (cryptographic verification is mocked, so the weight check is the
	// only gate).
	//
	// Executive stakes: 0=100, 1=100, 2=9800. Total=10000. Threshold=6667.
	// Sealers {0, 1} → weight 200 < 6667 → rejected.
	// Sealers {0, 2} → weight 9900 >= 6667 → accepted (if sig verifies).
	//
	// We can't easily test the "accepted" path here because the mock
	// signer's VerifyBlock requires the signature to be exactly
	// "mock-aggregated-qtd-threshold-signature". But we CAN test the
	// "rejected" path — if the threshold computed by ReceiveSealAnnouncement
	// differs from the one computed by RequestSeal, the rejection would
	// not happen at the expected weight.

	// Use a different slot to avoid collision with the pending seal above.
	slot2 := uint64(8)
	blockHash2 := types.Hash{}
	blockHash2[0] = 0xEF
	qpos.SetSlotBlockRoot(slot2, blockHash2)

	// Construct a seal with sealers {0, 1} (weight 200, below threshold).
	// The mock signer will reject any signature, so we expect false.
	// But the IMPORTANT thing is: if the threshold were wrong (e.g., 0
	// or nil), the function might accept before even checking the
	// signature. We verify the threshold check runs by confirming the
	// function does NOT panic and returns false.
	//
	// Note: We can't directly assert "rejected due to weight" vs
	// "rejected due to signature" from the outside. The consistency
	// is already verified by Path 1 above (same helper → same value).
	// This path just confirms ReceiveSealAnnouncement doesn't panic
	// when the helper returns non-nil values.
	ok := qfs.ReceiveSealAnnouncement(slot2, blockHash2,
		[]byte("mock-aggregated-qtd-threshold-signature"), []int{0, 1})
	// Expected: false (either weight threshold or signature check fails).
	// We don't care WHICH check fails — only that it doesn't panic and
	// doesn't accept a below-threshold seal.
	if ok {
		t.Error("P3-QTD-01: ReceiveSealAnnouncement accepted a seal with " +
			"sealers {0,1} (weight 200 < threshold 6667). The weight " +
			"check did not run, or the threshold was computed incorrectly.")
	}
}
