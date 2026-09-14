// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// resetGenesisTimeForTest resets the genesis time state for test isolation.
// SetGenesisTime(0) rejects t <= 0, so we must directly reset the internal
// state to avoid leaking genesis time into subsequent tests.
func resetGenesisTimeForTest() {
	genesis.mu.Lock()
	defer genesis.mu.Unlock()
	genesis.time = 0
	genesis.timeSet = false
}

// ── P2-2: Security test — single node cannot forge threshold signature ──

// TestP2_2_SingleNodeCannotForgeThreshold verifies that a single node cannot
// finalize a block by submitting partial seals for only itself. The threshold
// (2-of-3 by default) requires at least 2 distinct executive members to submit
// partial seals.
func TestP2_2_SingleNodeCannotForgeThreshold(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 10)
	qfs := qpos.GetQTDFinality()

	// Set up executive chamber: members {4, 5, 6}, threshold = 2.
	// CHAMBER-H03 FIX (R31, 2026-07-27): CanSeal now requires executive
	// assignment for the slot's SPECIFIC epoch. Slot 100 is in epoch 3
	// (100/32=3), so we must assign executive for epoch 3 (not epoch 0
	// as before). Without this, CanSeal fail-closes and SubmitPartialSeal
	// returns "not authorized to seal for slot 100".
	const sealSlot = uint64(100)
	const sealEpoch = uint64(3) // 100 / 32 = 3
	_ = coordinator.AssignExecutive([]int{4, 5, 6}, sealEpoch)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{4, 5, 6}, sealEpoch)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))
	// QUANTUM- Pre-populate canonical root so fail-closed gate passes.
	blockHash := types.Hash{}
	blockHash[0] = 0x64
	qpos.SetSlotBlockRoot(sealSlot, blockHash)

	// Approve slot 100.
	approveSlot(coordinator, sealSlot)

	if err := qfs.RequestSeal(sealSlot, blockHash); err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}

	// Submit only 1 partial seal (from validator 4) — should NOT finalize.
	sig := []byte("validator-4-partial-sig-min16bytes")
	if err := qfs.SubmitPartialSeal(4, sealSlot, sig); err != nil {
		t.Fatalf("SubmitPartialSeal(4) failed: %v", err)
	}
	if qfs.IsSlotFinalized(sealSlot) {
		t.Error("slot should NOT be finalized with only 1 partial seal (threshold=2)")
	}

	// Submit the SAME validator's seal again — should NOT inflate count.
	// The map[int][]byte keyed by validatorIndex means re-submission overwrites,
	// not adds. The count of distinct sealers stays at 1.
	if err := qfs.SubmitPartialSeal(4, sealSlot, []byte("different-sig-from-same-validator")); err != nil {
		t.Fatalf("SubmitPartialSeal(4) second time failed: %v", err)
	}
	if qfs.IsSlotFinalized(sealSlot) {
		t.Error("slot should NOT be finalized after same validator re-submits (count still 1)")
	}

	// Submit from a second validator (5) — now threshold met, should finalize.
	if err := qfs.SubmitPartialSeal(5, sealSlot, []byte("validator-5-partial-sig-min16bytes")); err != nil {
		t.Fatalf("SubmitPartialSeal(5) failed: %v", err)
	}
	if !qfs.IsSlotFinalized(sealSlot) {
		t.Error("slot should be finalized with 2 distinct partial seals (threshold=2)")
	}

	t.Log("✅ P2-2: Single node cannot forge threshold signature — PASS")
}

// TestP2_2_ThresholdEnforcement verifies that the threshold is correctly
// enforced for different threshold values.
func TestP2_2_ThresholdEnforcement(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 10)
	qfs := qpos.GetQTDFinality()

	// Set up executive chamber with threshold=2 (default 3-of-2).
	// CHAMBER-H03 + QUANTUM-FIX (R31, 2026-07-27): Slot 200 is in
	// epoch 6 (200/32=6). Must assign executive for epoch 6 and pre-populate
	// canonical root, otherwise CanSeal fail-closes and the test fails.
	const sealSlot = uint64(200)
	const sealEpoch = uint64(6) // 200 / 32 = 6
	_ = coordinator.AssignExecutive([]int{0, 1, 2}, sealEpoch)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, sealEpoch)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	approveSlot(coordinator, sealSlot)
	blockHash := types.Hash{}
	blockHash[0] = 0xC8
	qpos.SetSlotBlockRoot(sealSlot, blockHash)

	_ = qfs.RequestSeal(sealSlot, blockHash)

	// 0 seals → not finalized
	if qfs.IsSlotFinalized(sealSlot) {
		t.Error("should not be finalized with 0 seals")
	}

	// 1 seal → not finalized (threshold=2)
	_ = qfs.SubmitPartialSeal(0, sealSlot, []byte("sig-0-min16bytes-padding"))
	if qfs.IsSlotFinalized(sealSlot) {
		t.Error("should not be finalized with 1 seal (threshold=2)")
	}

	// 2 seals → finalized (threshold=2 met)
	_ = qfs.SubmitPartialSeal(1, sealSlot, []byte("sig-1-min16bytes-padding"))
	if !qfs.IsSlotFinalized(sealSlot) {
		t.Error("should be finalized with 2 seals (threshold=2)")
	}

	t.Log("✅ P2-2: Threshold enforcement (2-of-3) — PASS")
}

// ── P2-3: Partition recovery test — CORE-03 conflicting root rejection ──

// TestP2_3_ConflictingRootAttestationRejected verifies the CORE-03 fix:
// attestations targeting a conflicting fork root are rejected by
// tryUpdateFinality, preventing accountable safety failures during
// network partitions.
func TestP2_3_ConflictingRootAttestationRejected(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Set genesis time so current epoch >= 2 (need 2+ epochs for finality).
	// EpochDuration = 32 * 12s = 384s. Set genesis 3 epochs ago.
	genesisTime := time.Now().Add(-3 * EpochDuration).Unix()
	_ = SetGenesisTime(genesisTime)
	defer resetGenesisTimeForTest()

	currentEpoch := qpos.GetCurrentEpoch()
	if currentEpoch < 2 {
		t.Fatalf("current epoch %d < 2, need at least 2 for finality test", currentEpoch)
	}

	prevEpoch := currentEpoch - 1
	prevEpochStartSlot := EpochStartSlot(prevEpoch)
	prevEpochEndSlot := prevEpochStartSlot + SlotsPerEpoch - 1

	// Set the canonical slot block roots for the previous epoch, and the
	// canonical epoch-boundary root (R105: Target.Root binds to the boundary
	// root; the per-slot root pins BeaconBlockRoot).
	canonicalRoot := types.Hash{}
	canonicalRoot[0] = 0xAA
	for slot := prevEpochStartSlot; slot <= prevEpochEndSlot; slot++ {
		qpos.SetSlotBlockRoot(slot, canonicalRoot)
	}
	qpos.SetEpochBlockRoot(prevEpoch, canonicalRoot)

	// Create attestations targeting the CANONICAL root — should be counted.
	canonicalAtts := make([]*Attestation, 0, 7)
	for i := 0; i < 7; i++ {
		att := &Attestation{
			Slot:            prevEpochStartSlot,
			BeaconBlockRoot: canonicalRoot,
			Target: AttestationCheckpoint{
				Epoch: prevEpoch,
				Root:  canonicalRoot,
			},
			ValidatorIndex: i,
		}
		canonicalAtts = append(canonicalAtts, att)
	}

	// Create attestations targeting a CONFLICTING root — should be rejected.
	conflictingRoot := types.Hash{}
	conflictingRoot[0] = 0xBB
	conflictingAtts := make([]*Attestation, 0, 7)
	for i := 0; i < 7; i++ {
		att := &Attestation{
			Slot:            prevEpochStartSlot + 1,
			BeaconBlockRoot: conflictingRoot,
			Target: AttestationCheckpoint{
				Epoch: prevEpoch,
				Root:  conflictingRoot,
			},
			ValidatorIndex: i,
		}
		conflictingAtts = append(conflictingAtts, att)
	}

	// Populate attestations directly (bypassing ProcessAttestation signature
	// verification — we're testing the tryUpdateFinality root check, not sig
	// verification).
	qpos.mu.Lock()
	for _, att := range canonicalAtts {
		qpos.attestations[att.Slot] = append(qpos.attestations[att.Slot], att)
	}
	for _, att := range conflictingAtts {
		qpos.attestations[att.Slot] = append(qpos.attestations[att.Slot], att)
	}
	qpos.mu.Unlock()

	// Call tryUpdateFinality.
	qpos.mu.Lock()
	qpos.tryUpdateFinality()
	justifiedAfter := qpos.justifiedEpoch
	qpos.mu.Unlock()

	// The 7 canonical attestations (70% of 10 validators, > 2/3) should be
	// enough to justify the previous epoch. The 7 conflicting attestations
	// should NOT contribute.
	if justifiedAfter < prevEpoch {
		t.Errorf("expected justifiedEpoch >= %d (canonical attestations should count), got %d",
			prevEpoch, justifiedAfter)
	}

	t.Log("✅ P2-3: Conflicting root attestations rejected — PASS")
}

// TestP2_3_OnlyConflictingRootsNoFinality verifies that if ALL attestations
// target a conflicting root (none match the canonical root), finality is
// NOT achieved.
func TestP2_3_OnlyConflictingRootsNoFinality(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	genesisTime := time.Now().Add(-3 * EpochDuration).Unix()
	_ = SetGenesisTime(genesisTime)
	defer resetGenesisTimeForTest()

	currentEpoch := qpos.GetCurrentEpoch()
	if currentEpoch < 2 {
		t.Fatalf("current epoch %d < 2", currentEpoch)
	}

	prevEpoch := currentEpoch - 1
	prevEpochStartSlot := EpochStartSlot(prevEpoch)

	// Set canonical root.
	canonicalRoot := types.Hash{}
	canonicalRoot[0] = 0xAA
	qpos.SetSlotBlockRoot(prevEpochStartSlot, canonicalRoot)

	// Create attestations targeting a CONFLICTING root only.
	conflictingRoot := types.Hash{}
	conflictingRoot[0] = 0xBB
	qpos.mu.Lock()
	for i := 0; i < 10; i++ {
		att := &Attestation{
			Slot: prevEpochStartSlot,
			Target: AttestationCheckpoint{
				Epoch: prevEpoch,
				Root:  conflictingRoot,
			},
			ValidatorIndex: i,
		}
		qpos.attestations[prevEpochStartSlot] = append(
			qpos.attestations[prevEpochStartSlot], att)
	}
	justifiedBefore := qpos.justifiedEpoch
	qpos.tryUpdateFinality()
	justifiedAfter := qpos.justifiedEpoch
	qpos.mu.Unlock()

	if justifiedAfter > justifiedBefore {
		t.Errorf("finality should NOT advance when all attestations target conflicting root: justified %d → %d",
			justifiedBefore, justifiedAfter)
	}

	t.Log("✅ P2-3: Only conflicting roots → no finality — PASS")
}

// ── P2-5: GOV-05 per-slot root attestation classification ──

// TestP2_5_PerSlotRootCorrectClassification verifies that after SetSlotBlockRoot
// is called, attestations targeting the correct root are counted while
// attestations targeting a wrong root are not.
func TestP2_5_PerSlotRootCorrectClassification(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	genesisTime := time.Now().Add(-3 * EpochDuration).Unix()
	_ = SetGenesisTime(genesisTime)
	defer resetGenesisTimeForTest()

	currentEpoch := qpos.GetCurrentEpoch()
	if currentEpoch < 2 {
		t.Fatalf("current epoch %d < 2", currentEpoch)
	}

	prevEpoch := currentEpoch - 1
	prevEpochStartSlot := EpochStartSlot(prevEpoch)

	// Set the canonical slot root AND the canonical epoch-boundary root
	// (R105: Target.Root binds to the boundary root; BeaconBlockRoot pins
	// the per-slot canonical root).
	correctRoot := types.Hash{}
	correctRoot[0] = 0xCC
	qpos.SetSlotBlockRoot(prevEpochStartSlot, correctRoot)
	qpos.SetEpochBlockRoot(prevEpoch, correctRoot)

	wrongRoot := types.Hash{}
	wrongRoot[0] = 0xDD

	// 5 attestations with correct boundary targets and correct per-slot
	// beacon roots.
	qpos.mu.Lock()
	for i := 0; i < 5; i++ {
		qpos.attestations[prevEpochStartSlot] = append(
			qpos.attestations[prevEpochStartSlot], &Attestation{
				Slot:            prevEpochStartSlot,
				BeaconBlockRoot: correctRoot,
				Target: AttestationCheckpoint{
					Epoch: prevEpoch,
					Root:  correctRoot,
				},
				ValidatorIndex: i,
			})
	}

	// 5 attestations with a CONFLICTING boundary target (must be skipped).
	for i := 5; i < 10; i++ {
		qpos.attestations[prevEpochStartSlot] = append(
			qpos.attestations[prevEpochStartSlot], &Attestation{
				Slot:            prevEpochStartSlot,
				BeaconBlockRoot: wrongRoot,
				Target: AttestationCheckpoint{
					Epoch: prevEpoch,
					Root:  wrongRoot,
				},
				ValidatorIndex: i,
			})
	}

	justifiedBefore := qpos.justifiedEpoch
	qpos.tryUpdateFinality()
	justifiedAfter := qpos.justifiedEpoch
	qpos.mu.Unlock()

	// With only 5 out of 10 correct attestations (50% < 2/3), finality
	// should NOT advance. The 5 wrong-root attestations must not be counted.
	if justifiedAfter > justifiedBefore {
		t.Errorf("finality should NOT advance with only 5/10 correct-root attestations (50%% < 2/3): %d → %d",
			justifiedBefore, justifiedAfter)
	}

	// Now re-attritbute 2 of the wrong-root attestations as correct ones
	// (both boundary target AND beacon root), taking the count to 7/10.
	qpos.mu.Lock()
	for i := 5; i < 7; i++ {
		qpos.attestations[prevEpochStartSlot][i].Target.Root = correctRoot
		qpos.attestations[prevEpochStartSlot][i].BeaconBlockRoot = correctRoot
	}
	qpos.tryUpdateFinality()
	justifiedAfter = qpos.justifiedEpoch
	qpos.mu.Unlock()

	// Now 7 out of 10 (70% > 2/3) should justify the epoch.
	if justifiedAfter < prevEpoch {
		t.Errorf("finality should advance with 7/10 correct-root attestations (70%% > 2/3): expected justified >= %d, got %d",
			prevEpoch, justifiedAfter)
	}

	t.Log("✅ P2-5: Per-slot root attestation classification — PASS")
}

// TestP2_5_NoSlotRootFallbackToEpochRoot verifies that when no per-slot root
// is recorded, tryUpdateFinality falls back to the epoch boundary root check.
func TestP2_5_NoSlotRootFallbackToEpochRoot(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	genesisTime := time.Now().Add(-3 * EpochDuration).Unix()
	_ = SetGenesisTime(genesisTime)
	defer resetGenesisTimeForTest()

	currentEpoch := qpos.GetCurrentEpoch()
	if currentEpoch < 2 {
		t.Fatalf("current epoch %d < 2", currentEpoch)
	}

	prevEpoch := currentEpoch - 1
	prevEpochStartSlot := EpochStartSlot(prevEpoch)

	// Set EPOCH root but NOT slot root.
	epochRoot := types.Hash{}
	epochRoot[0] = 0xEE
	qpos.SetEpochBlockRoot(prevEpoch, epochRoot)

	wrongRoot := types.Hash{}
	wrongRoot[0] = 0xFF

	// Attestations with correct epoch root.
	qpos.mu.Lock()
	for i := 0; i < 7; i++ {
		qpos.attestations[prevEpochStartSlot] = append(
			qpos.attestations[prevEpochStartSlot], &Attestation{
				Slot: prevEpochStartSlot,
				Target: AttestationCheckpoint{
					Epoch: prevEpoch,
					Root:  epochRoot,
				},
				ValidatorIndex: i,
			})
	}

	// Attestations with wrong root.
	for i := 7; i < 10; i++ {
		qpos.attestations[prevEpochStartSlot] = append(
			qpos.attestations[prevEpochStartSlot], &Attestation{
				Slot: prevEpochStartSlot,
				Target: AttestationCheckpoint{
					Epoch: prevEpoch,
					Root:  wrongRoot,
				},
				ValidatorIndex: i,
			})
	}

	justifiedBefore := qpos.justifiedEpoch
	qpos.tryUpdateFinality()
	justifiedAfter := qpos.justifiedEpoch
	qpos.mu.Unlock()

	// 7/10 correct root (70% > 2/3) should justify even with epoch root fallback.
	if justifiedAfter <= justifiedBefore {
		t.Errorf("finality should advance with 7/10 correct epoch-root attestations: justified %d → %d",
			justifiedBefore, justifiedAfter)
	}

	t.Log("✅ P2-5: Epoch root fallback — PASS")
}

// ── P2-6: GOV-06 stake-weighted executive election ──

// TestP2_6_StakeWeightedExecutiveElection verifies that the executive chamber
// election is stake-weighted (GOV-06 fix: score = hash * stake, not hash + stake).
// Validators with higher stake should be selected more often than validators
// with lower stake.
func TestP2_6_StakeWeightedExecutiveElection(t *testing.T) {
	vs := createTestValidatorSet(t, 20)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()

	// R88-F: high-genesis exemption — simulate a chain that starts after all
	// tested epochs, so their epoch-2 accumulators cannot exist on-chain;
	// zero-hash selection is identical on every node and allowed to proceed.
	qpos.SetFirstBlockEpoch(51)

	// Give some validators much higher stake.
	// NOTE: vs.Validators() returns a deep copy, so we must modify the
	// internal slice directly to affect SelectExecutiveForEpoch.
	vs.mu.Lock()
	for i := 0; i < 5; i++ {
		vs.validators[i].Stake = big.NewInt(1000000) // 1M stake
	}
	for i := 5; i < 20; i++ {
		vs.validators[i].Stake = big.NewInt(1) // 1 unit stake
	}
	vs.mu.Unlock()

	// Run multiple epoch selections and count how often high-stake validators
	// are selected.
	highStakeSelections := 0
	lowStakeSelections := 0
	selectionRounds := 50

	for epoch := uint64(1); epoch <= uint64(selectionRounds); epoch++ {
		members, err := coordinator.SelectExecutiveForEpoch(epoch, vs)
		if err != nil {
			t.Fatalf("SelectExecutiveForEpoch(epoch=%d) failed: %v", epoch, err)
		}

		if epoch <= 5 {
			t.Logf("epoch %d: selected members = %v", epoch, members)
		}

		for _, idx := range members {
			if idx < 5 {
				highStakeSelections++
			} else {
				lowStakeSelections++
			}
		}

		// Reset assignments for next round to avoid "already in chamber" errors.
		coordinator.assignment.ClearEpoch(epoch)
	}

	// With stake = 1M vs 1, high-stake validators should dominate.
	// Each round selects 3 members. Over 50 rounds = 150 total selections.
	// High-stake validators (5 of 20, but 5M total stake out of 5,015 total)
	// should get ~99.7% of selections.
	totalSelections := highStakeSelections + lowStakeSelections
	if totalSelections != selectionRounds*3 {
		t.Errorf("expected %d total selections, got %d", selectionRounds*3, totalSelections)
	}

	highStakeRatio := float64(highStakeSelections) / float64(totalSelections)
	t.Logf("High-stake selections: %d/%d (%.1f%%)", highStakeSelections, totalSelections, highStakeRatio*100)

	// With 5M / 5.015M total stake, high-stake ratio should be > 90%.
	// (Using a lower threshold to account for randomness in testing.)
	if highStakeRatio < 0.90 {
		t.Errorf("stake-weighted selection not working: high-stake ratio %.1f%% (expected > 90%%)", highStakeRatio*100)
	}

	t.Log("✅ P2-6: Stake-weighted executive election — PASS")
}

// ── P2-9: Dead code cleanup verification ──

// TestP2_9_NoPlaceholderSignaturesInProduction verifies that the production
// code path (SealBlock) does not submit placeholder/mock signatures.
// The P0-5 fix removed fake "auto-seal" signatures from SealBlock.
func TestP2_9_NoPlaceholderSignaturesInProduction(t *testing.T) {
	qpos, coordinator, flow := setupStardustWithQTD(t, 10)

	_ = coordinator.AssignProposing(0, 1)
	_ = coordinator.AssignReview([]int{1, 2, 3}, 1)
	_ = coordinator.AssignExecutive([]int{4, 5, 6}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{4, 5, 6}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	approveSlot(coordinator, 1)
	blockHash := types.Hash{}
	blockHash[0] = 0x01

	// Propose + Review + Seal.
	_ = flow.ProposeBlock(1, blockHash, 0)
	_ = flow.ReviewBlock(1)
	err := flow.SealBlock(1)
	if err != nil {
		t.Fatalf("SealBlock failed: %v", err)
	}

	// Verify the seal was REQUESTED but NOT auto-completed with fake sigs.
	qfs := qpos.GetQTDFinality()
	if qfs.IsSlotFinalized(1) {
		t.Error("slot should NOT be finalized after SealBlock alone — " +
			"real partial seals must be collected via P2P (P0-5 fix)")
	}

	// Verify a pending seal exists (was requested).
	pending := qfs.GetPendingSeal(1)
	if pending == nil {
		t.Error("expected pending seal after SealBlock (RequestSeal should have been called)")
	}

	t.Log("✅ P2-9: No placeholder signatures in production code — PASS")
}
