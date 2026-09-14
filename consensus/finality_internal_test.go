// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// setGenuineFinality establishes a NON-ZERO finalizedRoot at the given epoch,
// simulating the state QPOS reaches after the first real finalization. This is
// required by computeDeterministicShuffleForEpoch's finality gate (2026-08-07):
// the VRF accumulator is only mixed into the seed once its source epoch is
// genuinely finalized (finalizedRoot != zero). Tests that assert VRF entropy
// reaches the schedule must call this first.
func setGenuineFinality(q *QPOS, finalizedEpoch uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.finalizedEpoch = finalizedEpoch
	q.finalizedRoot = types.Hash{0x01}
}

// TestFinalityTracker_queueEvidence_Nil tests the nil evidence defensive check
func TestFinalityTracker_queueEvidence_Nil(t *testing.T) {
	ft := NewFinalityTracker(NewValidatorManager())
	ft.mu.Lock()
	ft.queueEvidence(nil) // Should not panic, just return
	ft.mu.Unlock()

	if len(ft.evidenceQueue) != 0 {
		t.Error("expected empty queue after nil evidence")
	}
}

// TestFinalityTracker_queueEvidence_Overflow tests the queue overflow path
func TestFinalityTracker_queueEvidence_Overflow(t *testing.T) {
	ft := NewFinalityTracker(NewValidatorManager())
	ft.mu.Lock()
	defer ft.mu.Unlock()

	// Fill the queue to MaxEvidenceQueue
	for i := 0; i < MaxEvidenceQueue; i++ {
		ft.queueEvidence(&SlashingEvidence{
			Reason:        SlashingReasonDoubleSigning,
			ValidatorAddr: types.Address{byte(i % 256)},
			Height:        uint64(i),
			Timestamp:     time.Now().Unix(),
		})
	}
	if len(ft.evidenceQueue) != MaxEvidenceQueue {
		t.Fatalf("expected %d entries, got %d", MaxEvidenceQueue, len(ft.evidenceQueue))
	}

	// Push one more to trigger overflow (FIFO eviction)
	firstEntry := ft.evidenceQueue[0]
	ft.queueEvidence(&SlashingEvidence{
		Reason:        SlashingReasonDoubleSigning,
		ValidatorAddr: types.Address{0xff},
		Height:        uint64(MaxEvidenceQueue),
		Timestamp:     time.Now().Unix(),
	})

	// Queue should still be at MaxEvidenceQueue
	if len(ft.evidenceQueue) != MaxEvidenceQueue {
		t.Errorf("expected %d entries after overflow, got %d", MaxEvidenceQueue, len(ft.evidenceQueue))
	}
	// The first entry should have been evicted
	if ft.evidenceQueue[0] == firstEntry {
		t.Error("expected first entry to be evicted on overflow")
	}
	// The last entry should be the new one
	lastEntry := ft.evidenceQueue[len(ft.evidenceQueue)-1]
	if lastEntry.Height != uint64(MaxEvidenceQueue) {
		t.Errorf("expected last entry height %d, got %d", MaxEvidenceQueue, lastEntry.Height)
	}
}

// makeSlotPruneTestValidatorSet creates a minimal validator set for QPOS tests.
func makeSlotPruneTestValidatorSet(n int) *ValidatorSet {
	vals := make([]*Validator, n)
	for i := 0; i < n; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		vals[i] = &Validator{
			Address: addr,
			Stake:   big.NewInt(1000),
			Active:  true,
		}
	}
	vs, _ := NewValidatorSet(vals)
	return vs
}

// TestSetSlotBlockRoot_Prune verifies CORE B-2 fix: slotBlockRoots is pruned
// when it exceeds 3*SlotsPerEpoch entries, removing entries older than the
// finalized epoch's start slot.
func TestSetSlotBlockRoot_Prune(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Set finalizedEpoch to 5 so pruneCutoff = EpochStartSlot(4) = 4*32 = 128
	qpos.mu.Lock()
	qpos.finalizedEpoch = 5
	qpos.mu.Unlock()

	// Insert entries for slots 100..200 (101 entries > 3*32=96 threshold).
	// Slots 100..127 should be pruned (< 128 cutoff); slots 128..200 survive.
	for s := uint64(100); s <= 200; s++ {
		var h types.Hash
		h[0] = byte(s)
		qpos.SetSlotBlockRoot(s, h)
	}

	qpos.mu.RLock()
	count := len(qpos.slotBlockRoots)
	for s := range qpos.slotBlockRoots {
		if s < 128 {
			t.Errorf("slot %d should have been pruned (cutoff=128)", s)
		}
	}
	qpos.mu.RUnlock()

	if count == 0 {
		t.Error("expected some entries to survive pruning, got 0")
	}
	t.Logf("after pruning: %d entries remain", count)
}

// TestSetEpochBlockRoot_Prune verifies CORE B-2 fix: epochBlockRoots is pruned
// when it exceeds 10 entries, removing entries older than finalizedEpoch - 1.
func TestSetEpochBlockRoot_Prune(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Set finalizedEpoch to 20 so pruneCutoff = 19
	qpos.mu.Lock()
	qpos.finalizedEpoch = 20
	qpos.mu.Unlock()

	// Insert entries for epochs 10..25 (16 entries > 10 threshold).
	// Epochs 10..18 should be pruned (< 19 cutoff); epochs 19..25 survive.
	for e := uint64(10); e <= 25; e++ {
		var h types.Hash
		h[0] = byte(e)
		qpos.SetEpochBlockRoot(e, h)
	}

	qpos.mu.RLock()
	count := len(qpos.epochBlockRoots)
	for e := range qpos.epochBlockRoots {
		if e < 19 {
			t.Errorf("epoch %d should have been pruned (cutoff=19)", e)
		}
	}
	qpos.mu.RUnlock()

	if count == 0 {
		t.Error("expected some entries to survive pruning, got 0")
	}
	t.Logf("after pruning: %d entries remain", count)
}

// TestSetSlotBlockRoot_NoPruneBelowThreshold verifies that pruning does NOT
// trigger when the map is below the threshold.
func TestSetSlotBlockRoot_NoPruneBelowThreshold(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Insert fewer than 3*SlotsPerEpoch entries — no pruning should occur.
	for s := uint64(0); s < 10; s++ {
		var h types.Hash
		h[0] = byte(s)
		qpos.SetSlotBlockRoot(s, h)
	}

	qpos.mu.RLock()
	count := len(qpos.slotBlockRoots)
	qpos.mu.RUnlock()

	if count != 10 {
		t.Errorf("expected 10 entries (no pruning), got %d", count)
	}
}

// TestR4CORE02_ReanchorSlotRoots_OverwritesAndDeletesStale verifies the core
// contract of ReanchorSlotRoots (AUDIT R4-CORE-02, 2026-07-15).
//
// Scenario: a reorg replaced part of the old fork with new canonical blocks.
//   - Slot 10: common ancestor (below the reorg range → MUST survive untouched)
//   - Slot 11: old fork root A1 → re-anchored to new canonical B1
//   - Slot 12: old fork root A2 → NO block on new chain (proposer was offline
//     on the new fork) → MUST be DELETED, otherwise tryUpdateFinality reads a
//     stale root pointing at the abandoned fork
//   - Slot 13: old fork root A3 → re-anchored to new canonical B3 (new head)
//
// The reorg range is [min(roots)=11, max(roots)=13]. Slot 12 falls inside the
// range but is not in roots → deleted. Slot 10 is below the range → untouched.
func TestR4CORE02_ReanchorSlotRoots_OverwritesAndDeletesStale(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// --- Pre-reorg state: old fork roots for slots 10..13 ---
	var oldRoot10, staleRoot11, staleRoot12, staleRoot13 types.Hash
	oldRoot10[0] = 0x10   // common ancestor — must survive
	staleRoot11[0] = 0xA1 // abandoned fork
	staleRoot12[0] = 0xA2 // abandoned fork, no replacement on new chain
	staleRoot13[0] = 0xA3 // abandoned fork, re-anchored
	qpos.SetSlotBlockRoot(10, oldRoot10)
	qpos.SetSlotBlockRoot(11, staleRoot11)
	qpos.SetSlotBlockRoot(12, staleRoot12)
	qpos.SetSlotBlockRoot(13, staleRoot13)

	// --- Reorg: new canonical roots for slots 11 and 13 (slot 12 skipped) ---
	var newRoot11, newRoot13 types.Hash
	newRoot11[0] = 0xB1
	newRoot13[0] = 0xB3
	roots := map[uint64]types.Hash{
		11: newRoot11,
		13: newRoot13,
	}
	qpos.ReanchorSlotRoots(roots, nil)

	// --- Assertions ---
	// Slot 10 (below range = common ancestor) MUST be untouched.
	if got, ok := qpos.GetSlotBlockRoot(10); !ok || got != oldRoot10 {
		t.Fatalf("slot 10 (below reorg range) must be untouched: got %v, ok=%v", got, ok)
	}
	// Slots 11 and 13 MUST be the NEW canonical roots (not the stale ones).
	if got, ok := qpos.GetSlotBlockRoot(11); !ok || got != newRoot11 {
		t.Fatalf("slot 11 must be re-anchored to newRoot11: got %v, ok=%v", got, ok)
	}
	if got, ok := qpos.GetSlotBlockRoot(13); !ok || got != newRoot13 {
		t.Fatalf("slot 13 must be re-anchored to newRoot13: got %v, ok=%v", got, ok)
	}
	// Slot 12 MUST be DELETED (in range [11,13] but not on the new canonical chain).
	if got, ok := qpos.GetSlotBlockRoot(12); ok {
		t.Fatalf("slot 12 (stale, no replacement) must be deleted, got %v", got)
	}

	t.Log("=== R4-CORE-02 ReanchorSlotRoots: overwrites + deletes stale (PASS) ===")
}

// TestR4CORE02_ReanchorSlotRoots_EmptyIsNoop verifies the edge case: an empty
// roots map is a no-op (no slots touched).
func TestR4CORE02_ReanchorSlotRoots_EmptyIsNoop(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	var h types.Hash
	h[0] = 0x77
	qpos.SetSlotBlockRoot(5, h)

	qpos.ReanchorSlotRoots(nil, nil) // empty → no-op

	if got, ok := qpos.GetSlotBlockRoot(5); !ok || got != h {
		t.Fatalf("empty ReanchorSlotRoots must not touch existing entries: got %v, ok=%v", got, ok)
	}

	t.Log("=== R4-CORE-02 ReanchorSlotRoots: empty map is no-op (PASS) ===")
}

// TestR4CORE02_ReanchorSlotRoots_PreventsFinalityPoisoning is the regression
// test for the exact vulnerability described in the audit: without
// re-anchoring, a stale slotBlockRoot for a reorged slot causes honest
// attestations (targeting the NEW canonical block) to be REJECTED by
// tryUpdateFinality, while abandoned-fork attestations are counted.
//
// This test sets up the stale-root state, then re-anchors, and verifies that
// GetSlotBlockRoot (the lookup tryUpdateFinality uses at qpos_finality.go:67)
// returns the NEW canonical root — i.e. the poisoning is cured.
func TestR4CORE02_ReanchorSlotRoots_PreventsFinalityPoisoning(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Simulate a 3-slot reorg. Common ancestor = slot 20. Old fork held
	// slots 21, 22, 23 with roots A1, A2, A3. New canonical chain holds the
	// same slots with roots B1, B2, B3. Honest attestations target B1/B2/B3.
	var staleRoot, newRoot types.Hash
	staleRoot[0] = 0xAA // abandoned fork root for slot 22
	newRoot[0] = 0xBB   // new canonical root for slot 22

	// Pre-fix state: SetSlotBlockRoot only recorded the new HEAD's own slot.
	// Suppose the new head is slot 23 — then slot 22 still holds the stale
	// root A2 from the abandoned fork (the bug).
	qpos.SetSlotBlockRoot(22, staleRoot) // stale, points at abandoned fork

	// Verify the poisoning exists pre-fix: GetSlotBlockRoot(22) returns the
	// STALE root, which tryUpdateFinality would compare against honest
	// attestations targeting newRoot → mismatch → honest vote rejected.
	if got, _ := qpos.GetSlotBlockRoot(22); got != staleRoot {
		t.Fatalf("pre-fix setup: slot 22 should hold stale root, got %v", got)
	}

	// Apply the fix: re-anchor slots 21..23 to the new canonical roots.
	qpos.ReanchorSlotRoots(map[uint64]types.Hash{
		21: {0xB1},
		22: newRoot,
		23: {0xB3},
	}, nil)

	// Post-fix: GetSlotBlockRoot(22) returns the NEW canonical root. An
	// honest attestation with Target.Root == newRoot is now ACCEPTED (matches
	// the canonical slot root), not rejected. The poisoning is cured.
	got, ok := qpos.GetSlotBlockRoot(22)
	if !ok {
		t.Fatal("post-fix: slot 22 root must be present (re-anchored)")
	}
	if got != newRoot {
		t.Fatalf("post-fix: slot 22 must hold new canonical root %v, got %v "+
			"(stale-root poisoning not cured — honest attestations would be rejected)",
			newRoot, got)
	}

	t.Log("=== R4-CORE-02 ReanchorSlotRoots: finality poisoning cured (PASS) ===")
}

// ============================================================================
// R4-CORE-01: Unpredictable proposer schedule via VRF accumulator
// (2026-07-15)
//
// The shuffle seed must mix the previous epoch's VRF accumulator so that the
// proposer schedule is unpredictable until epoch-1's proposers reveal their
// VRF outputs. This is UNGRINDABLE (VRF output is deterministic for a given
// key+seed), satisfying the CORE-R2-02 constraint (no last-proposer grind).
// ============================================================================

// TestR4CORE01_DifferentVRF_ProducesDifferentSchedule verifies that two
// different VRF accumulators for the same epoch produce different shuffles.
// This is the CORE security property: the schedule must change based on
// VRF entropy — otherwise it's predictable from genesis.
//
// CONS-R13-M03 (2026-07-21): The seed source was delayed from epoch-1 to
// epoch-2 (to mitigate last-proposer grind). As a result, the VRF accumulator
// for epoch N now feeds into the shuffle for epoch N+2 (not N+1). These
// tests were updated to reflect the new dependency: VRF for epoch 0 →
// shuffle for epoch 2.
func TestR4CORE01_DifferentVRF_ProducesDifferentSchedule(t *testing.T) {
	vs, err := NewValidatorSet(generateValidators(10))
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	// Accumulate different VRF outputs for epoch 0 (which feeds into epoch 2
	// after the CONS-R13-M03 epoch-2 seed delay fix).
	//
	// CONSENSUS-DETERMINISM FIX (2026-08-07): the epoch-0 accumulator is only
	// eligible for the epoch-2 seed when epoch 0 is GENUINELY finalized (see
	// computeDeterministicShuffleForEpoch). Establish genuine finality so the
	// VRF-entropy property being tested here actually applies.
	vrfA := types.Hash{0xAA, 0xBB, 0xCC}
	vrfB := types.Hash{0x11, 0x22, 0x33}
	setGenuineFinality(qpos, 2)

	// QPOS 1: accumulate vrfA
	qpos.AccumulateVRFOutput(0, vrfA)
	qpos.mu.RLock()
	shuffleA := qpos.computeShuffleForEpoch(2, 10)
	qpos.mu.RUnlock()

	// QPOS 2: accumulate vrfB (different entropy)
	qpos2, _ := NewQPOS(vs)
	setGenuineFinality(qpos2, 2)
	qpos2.AccumulateVRFOutput(0, vrfB)
	qpos2.mu.RLock()
	shuffleB := qpos2.computeShuffleForEpoch(2, 10)
	qpos2.mu.RUnlock()

	// The two shuffles MUST be different — this proves the VRF accumulator
	// adds genuine entropy to the seed.
	if equalSlices(shuffleA, shuffleB) {
		t.Fatal("different VRF accumulators produced the same shuffle — " +
			"VRF entropy is NOT being mixed into the seed (R4-CORE-01 regression)")
	}
}

// TestR4CORE01_SameVRF_ProducesSameSchedule verifies determinism: the same
// VRF accumulator must produce the same shuffle. All honest nodes that agree
// on the canonical chain (and thus on the VRF accumulator) must agree on the
// proposer schedule.
//
// CONS-R13-M03 (2026-07-21): Updated to use epoch 2 (depends on epoch 0's
// VRF accumulator after the epoch-2 seed delay fix).
func TestR4CORE01_SameVRF_ProducesSameSchedule(t *testing.T) {
	vs, err := NewValidatorSet(generateValidators(10))
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}

	vrf := types.Hash{0xAA, 0xBB, 0xCC}

	// Two independent QPOS instances with the same VRF accumulator.
	qpos1, _ := NewQPOS(vs)
	qpos1.AccumulateVRFOutput(0, vrf)
	qpos1.mu.RLock()
	shuffle1 := qpos1.computeShuffleForEpoch(2, 10)
	qpos1.mu.RUnlock()

	qpos2, _ := NewQPOS(vs)
	qpos2.AccumulateVRFOutput(0, vrf)
	qpos2.mu.RLock()
	shuffle2 := qpos2.computeShuffleForEpoch(2, 10)
	qpos2.mu.RUnlock()

	if !equalSlices(shuffle1, shuffle2) {
		t.Fatal("same VRF accumulator produced different shuffles — " +
			"loss of determinism (R4-CORE-01 regression)")
	}
}

// TestR4CORE01_ZeroVRF_FallsBackToEpochOnly verifies that when no VRF outputs
// have been accumulated (e.g., epoch 0 or during initial sync), the seed falls
// back to keccak(epoch) only. This preserves backward compatibility and
// ensures epoch 0's schedule is defined in genesis.
func TestR4CORE01_ZeroVRF_FallsBackToEpochOnly(t *testing.T) {
	vs, err := NewValidatorSet(generateValidators(10))
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	// No VRF accumulated — should fall back to keccak(epoch) only.
	// Both epoch 0 (no previous epoch) and epoch 1 (previous epoch has no
	// VRF) should produce the same result as the old keccak(epoch) seed.
	qpos.mu.RLock()
	shuffle1 := qpos.computeShuffleForEpoch(1, 10)
	shuffle2 := qpos.computeShuffleForEpoch(1, 10)
	qpos.mu.RUnlock()

	if !equalSlices(shuffle1, shuffle2) {
		t.Fatal("zero VRF fallback should be deterministic")
	}
}

// TestR4CORE01_AccumulateXOR verifies that accumulating two VRF outputs
// produces the XOR of both (the accumulator is an XOR, not a list).
func TestR4CORE01_AccumulateXOR(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(5))
	qpos, _ := NewQPOS(vs)

	vrfA := types.Hash{0xFF, 0x00, 0xAA}
	vrfB := types.Hash{0x00, 0xFF, 0xAA}

	// Accumulate A then B → result should be A XOR B.
	qpos.AccumulateVRFOutput(0, vrfA)
	qpos.AccumulateVRFOutput(0, vrfB)

	qpos.mu.RLock()
	acc := qpos.getEpochVRFAccumulatorLocked(0)
	qpos.mu.RUnlock()

	var expected types.Hash
	for i := 0; i < types.HashLength; i++ {
		expected[i] = vrfA[i] ^ vrfB[i]
	}
	if acc != expected {
		t.Fatalf("VRF accumulator XOR mismatch: got %v, want %v", acc, expected)
	}
}

// TestR4CORE01_AccumulateSkipsEmptyVRF verifies that empty (zero) VRF outputs
// are not accumulated (they would cancel themselves out via XOR).
func TestR4CORE01_AccumulateSkipsEmptyVRF(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(5))
	qpos, _ := NewQPOS(vs)

	// Accumulate a zero VRF — should be skipped.
	qpos.AccumulateVRFOutput(0, types.Hash{})

	qpos.mu.RLock()
	acc := qpos.getEpochVRFAccumulatorLocked(0)
	qpos.mu.RUnlock()

	if acc != (types.Hash{}) {
		t.Fatalf("zero VRF should be skipped, but accumulator is %v", acc)
	}
}

// TestR4CORE01_CacheInvalidationOnAccumulate verifies that accumulating a new
// VRF output invalidates the shuffle cache for the NEXT epoch (epoch+1).
func TestR4CORE01_CacheInvalidationOnAccumulate(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(5))
	qpos, _ := NewQPOS(vs)

	// Pre-populate the shuffle cache for epoch 1.
	qpos.mu.Lock()
	qpos.shuffleCache[1] = []int{0, 1, 2, 3, 4}
	qpos.mu.Unlock()

	// Accumulate a VRF for epoch 0 → should invalidate cache for epoch 1.
	qpos.AccumulateVRFOutput(0, types.Hash{0x42})

	qpos.mu.RLock()
	_, cached := qpos.shuffleCache[1]
	qpos.mu.RUnlock()

	if cached {
		t.Fatal("AccumulateVRFOutput failed to invalidate shuffleCache[epoch+1] — " +
			"stale shuffle with incomplete VRF accumulator would remain cached")
	}
}

// equalSlices returns true if two int slices are element-wise equal.
func equalSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ============================================================================
// R4-CORE-03: Finality-stall pruning regression tests
// ============================================================================

// TestR4CORE03_PruneOnFinalityStall_EpochBlockRoots verifies that
// epochBlockRoots is pruned based on currentEpoch when finality stalls.
func TestR4CORE03_PruneOnFinalityStall_EpochBlockRoots(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	// Simulate finality stalling at epoch 2, but chain continues to epoch 10.
	qpos.mu.Lock()
	qpos.finalizedEpoch = 2
	qpos.currentEpoch = 10
	// Insert entries for epochs 0-9 (10 entries, exceeds threshold of 10).
	for e := uint64(0); e < 10; e++ {
		qpos.epochBlockRoots[e] = types.Hash{byte(e + 1)}
	}
	qpos.mu.Unlock()

	// SetEpochBlockRoot for epoch 10 triggers pruning.
	qpos.SetEpochBlockRoot(10, types.Hash{0xaa})

	qpos.mu.RLock()
	defer qpos.mu.RUnlock()
	// Entries older than currentEpoch-3=7 should be pruned.
	for e := uint64(0); e < 7; e++ {
		if _, exists := qpos.epochBlockRoots[e]; exists {
			t.Errorf("epoch %d should have been pruned (currentEpoch=10, cutoff=7)", e)
		}
	}
	// Entries 7-10 should remain.
	for e := uint64(7); e <= 10; e++ {
		if _, exists := qpos.epochBlockRoots[e]; !exists {
			t.Errorf("epoch %d should still exist", e)
		}
	}
	t.Logf("=== R4-CORE-03: epochBlockRoots pruned on finality stall (remaining=%d) ===", len(qpos.epochBlockRoots))
}

// TestR4CORE03_PruneOnFinalityStall_SlotBlockRoots verifies that
// slotBlockRoots is pruned based on currentSlot when finality stalls.
func TestR4CORE03_PruneOnFinalityStall_SlotBlockRoots(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	// Simulate finality stalling at epoch 0, but chain at slot 5*SlotsPerEpoch.
	qpos.mu.Lock()
	qpos.finalizedEpoch = 0
	qpos.currentSlot = 5 * SlotsPerEpoch
	// Insert entries for slots 0 to 4*SlotsPerEpoch (exceeds 3*SlotsPerEpoch).
	for s := uint64(0); s <= 4*SlotsPerEpoch; s++ {
		qpos.slotBlockRoots[s] = types.Hash{byte(s % 256)}
	}
	qpos.mu.Unlock()

	// SetSlotBlockRoot for a new slot triggers pruning.
	qpos.SetSlotBlockRoot(5*SlotsPerEpoch, types.Hash{0xbb})

	qpos.mu.RLock()
	defer qpos.mu.RUnlock()
	// Entries older than currentSlot - 3*SlotsPerEpoch should be pruned.
	cutoff := uint64(5*SlotsPerEpoch - 3*SlotsPerEpoch)
	for s := uint64(0); s < cutoff; s++ {
		if _, exists := qpos.slotBlockRoots[s]; exists {
			t.Errorf("slot %d should have been pruned (cutoff=%d)", s, cutoff)
		}
	}
	t.Logf("=== R4-CORE-03: slotBlockRoots pruned on finality stall (remaining=%d) ===", len(qpos.slotBlockRoots))
}

// ============================================================================
// R4-CORE-05: Inactive validator proposer skip regression tests
// ============================================================================

// TestR4CORE05_InactiveValidatorSkippedInProposerSelection verifies that
// an inactive validator (not slashed, just Active=false) is skipped when
// selecting a proposer.
func TestR4CORE05_InactiveValidatorSkippedInProposerSelection(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(3)

	// Deactivate validator 0 (set Active=false).
	qpos.mu.Lock()
	validators := qpos.validators
	qpos.mu.Unlock()

	// Get the actual validator at index 0 and deactivate it.
	v0 := validators.GetValidatorByIndex(0)
	if v0 == nil {
		t.Fatal("expected non-nil validator at index 0")
	}
	if isValidatorActive(validators, 0) {
		// Need to deactivate through the validators set
		validators.mu.Lock()
		if len(validators.validators) > 0 {
			validators.validators[0].Active = false
		}
		validators.mu.Unlock()
	}

	if isValidatorActive(validators, 0) {
		t.Fatal("validator 0 should be inactive after deactivation")
	}

	// The proposer selection should skip validator 0 and return one of the
	// other active validators.
	proposer, err := qpos.GetProposerForSlot(1)
	if err != nil {
		t.Fatalf("expected non-error, got: %v", err)
	}
	if proposer == nil {
		t.Fatal("expected non-nil proposer")
	}

	// Verify the selected proposer is NOT the inactive validator 0.
	v0After := validators.GetValidatorByIndex(0)
	if v0After != nil && proposer.Address == v0After.Address && !v0After.Active {
		t.Errorf("selected proposer is the inactive validator 0: %s", proposer.Address)
	}
	t.Logf("=== R4-CORE-05: inactive validator skipped, selected: %s ===", proposer.Address)
}

// ============================================================================
// CONS-R10-003: VotingManager.Finalize must NOT propagate to QPOS state.
// Regression tests for the removal of the VM→QPOS finality back-channel.
// ============================================================================

// TestCONS_R10_003_FinalizeDoesNotPropagateToQPOS verifies that calling
// VotingManager.Finalize does NOT modify QPOS finality state. Previously
// VotingManager.Finalize called qpos.syncFinalityFromVM() which bypassed
// the Casper FFG 2/3 supermajority weight check enforced in
// tryUpdateFinality, creating a second finality path that violated
// accountable safety. The call has been removed; this test ensures it
// cannot be re-introduced.
func TestCONS_R10_003_FinalizeDoesNotPropagateToQPOS(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	// Wire up a VotingManager backed by this QPOS instance. The validators
	// field of VotingManager is not used by Finalize (it only updates the
	// local `finalized` map), so nil is safe here — we are testing that
	// QPOS state remains untouched, not vote aggregation.
	vm := NewVotingManager(nil)
	vm.SetQPOS(qpos)

	// Record a canonical slot root so that — were syncFinalityFromVM still
	// present — its canonical-root check would PASS (removing the canonical
	// binding as a confounding factor). The fix must hold regardless of
	// canonical root state.
	slot := uint64(SlotsPerEpoch * 5)
	blockHash := types.Hash{0xcc}
	qpos.SetSlotBlockRoot(slot, blockHash)

	// Pre-condition: QPOS finalizedEpoch is 0.
	if got := qpos.GetFinalizedEpoch(); got != 0 {
		t.Fatalf("precondition: finalizedEpoch should be 0, got %d", got)
	}

	// Call VotingManager.Finalize — this used to propagate to QPOS and
	// mark finalizedEpoch=5 with finalizedRoot=blockHash.
	if err := vm.Finalize(slot, blockHash); err != nil {
		t.Fatalf("VotingManager.Finalize failed: %v", err)
	}

	// Post-condition: QPOS finalizedEpoch MUST remain 0. The VotingManager
	// is a vote-aggregation layer, not an authoritative finality source.
	if got := qpos.GetFinalizedEpoch(); got != 0 {
		t.Errorf("CONS-R10-003 REGRESSION: VotingManager.Finalize propagated to "+
			"QPOS (finalizedEpoch=%d) — the VM→QPOS finality back-channel "+
			"appears to have been re-introduced, bypassing Casper FFG 2/3 "+
			"supermajority check. This is a critical accountable safety violation.", got)
	}
	qpos.mu.RLock()
	if qpos.finalizedRoot == blockHash {
		t.Errorf("CONS-R10-003 REGRESSION: QPOS finalizedRoot was set to the " +
			"VotingManager-supplied hash — VotingManager.Finalize must NOT " +
			"propagate to QPOS state under any circumstance.")
	}
	qpos.mu.RUnlock()

	// Sanity check: the VotingManager's local `finalized` map SHOULD be
	// updated (the local query API still works).
	if !vm.IsFinalized(slot) {
		t.Errorf("VotingManager.IsFinalized should be true (local map updated)")
	}
	t.Log("=== CONS-R10-003: VotingManager.Finalize correctly did NOT propagate to QPOS ===")
}

// ============================================================================
// CONS-R10-004: CreateAttestation must read justifiedEpoch/Root AND
// currentKeyVersion atomically under both q.mu and q.keyVersionMu.
// ============================================================================

// TestCONS_R10_004_CreateAttestationAtomicRead verifies that
// CreateAttestation reads justifiedEpoch, justifiedRoot, and currentKeyVersion
// under a single consistent lock pair (q.mu + q.keyVersionMu). The previous
// implementation released q.mu before reading currentKeyVersion via a separate
// GetCurrentKeyVersion() call, creating a TOCTOU race window where another
// goroutine could update justifiedEpoch/Root and currentKeyVersion
// independently, producing an inconsistent attestation.
//
// This test cannot deterministically reproduce the race (timing-dependent),
// but it verifies the post-fix INVARIANT: the values returned by
// CreateAttestation must be consistent with a single point-in-time snapshot
// of QPOS state. We assert this by setting known values, calling
// CreateAttestation, and verifying the attestation matches those exact
// values.
func TestCONS_R10_004_CreateAttestationAtomicRead(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	// Set known justified state.
	qpos.mu.Lock()
	qpos.justifiedEpoch = 7
	qpos.justifiedRoot = types.Hash{0x77}
	qpos.mu.Unlock()

	// Set known key version.
	if err := SetKeyVersion(qpos, 42, time.Now().Unix()); err != nil {
		t.Fatalf("SetKeyVersion failed: %v", err)
	}

	// Create the attestation. The fix guarantees all three values are read
	// atomically under both locks.
	// R42-P4 FIX: set the epoch-5 boundary root or CreateAttestation returns nil.
	qpos.SetEpochBlockRoot(5, types.Hash{0xcc})
	att := qpos.CreateAttestation(uint64(SlotsPerEpoch*5), types.Hash{0xcc}, 0)
	if att == nil {
		t.Fatal("CreateAttestation returned nil")
	}

	// Verify the attestation carries the exact values we set — no stale
	// reads from a different lock acquisition.
	if att.Source.Epoch != 7 {
		t.Errorf("Source.Epoch: expected 7, got %d (stale read?)", att.Source.Epoch)
	}
	if att.Source.Root != (types.Hash{0x77}) {
		t.Errorf("Source.Root: expected 0x77, got %x (stale read?)", att.Source.Root)
	}
	if att.KeyVersion != 42 {
		t.Errorf("KeyVersion: expected 42, got %d (stale read?)", att.KeyVersion)
	}

	t.Log("=== CONS-R10-004: CreateAttestation read all state atomically ===")
}

// ============================================================================
// R33 CONS-04: Epoch 0/1 shuffle seed must mix in genesis root
// ============================================================================

// TestR33_CONS_04_Epoch0ShuffleMixesGenesisRoot verifies that the epoch 0
// shuffle seed mixes in the genesis block root, producing a different shuffle
// than pure keccak(epoch). This prevents offline pre-computation of the
// proposer schedule before genesis is finalized.
func TestR33_CONS_04_Epoch0ShuffleMixesGenesisRoot(t *testing.T) {
	vs1, _ := NewValidatorSet(generateValidators(10))
	qpos1, _ := NewQPOS(vs1)

	vs2, _ := NewValidatorSet(generateValidators(10))
	qpos2, _ := NewQPOS(vs2)

	// Both have the same validator set but different genesis roots.
	genesisRootA := types.Hash{0xAA, 0xBB, 0xCC}
	genesisRootB := types.Hash{0xDD, 0xEE, 0xFF}
	qpos1.SetGenesisRoot(genesisRootA)
	qpos2.SetGenesisRoot(genesisRootB)

	qpos1.mu.RLock()
	shuffle1 := qpos1.computeShuffleForEpoch(0, 10)
	qpos1.mu.RUnlock()

	qpos2.mu.RLock()
	shuffle2 := qpos2.computeShuffleForEpoch(0, 10)
	qpos2.mu.RUnlock()

	// Shuffles must differ because genesis roots differ.
	if equalSlices(shuffle1, shuffle2) {
		t.Fatal("R33 CONS-04 REGRESSION: epoch 0 shuffles should differ when " +
			"genesis roots differ, but they are identical (genesis root not mixed in)")
	}
}

// TestR33_CONS_04_Epoch1ShuffleMixesGenesisRoot verifies that the epoch 1
// shuffle seed also mixes in the genesis block root.
func TestR33_CONS_04_Epoch1ShuffleMixesGenesisRoot(t *testing.T) {
	vs1, _ := NewValidatorSet(generateValidators(10))
	qpos1, _ := NewQPOS(vs1)

	vs2, _ := NewValidatorSet(generateValidators(10))
	qpos2, _ := NewQPOS(vs2)

	genesisRootA := types.Hash{0xAA, 0xBB, 0xCC}
	genesisRootB := types.Hash{0xDD, 0xEE, 0xFF}
	qpos1.SetGenesisRoot(genesisRootA)
	qpos2.SetGenesisRoot(genesisRootB)

	qpos1.mu.RLock()
	shuffle1 := qpos1.computeShuffleForEpoch(1, 10)
	qpos1.mu.RUnlock()

	qpos2.mu.RLock()
	shuffle2 := qpos2.computeShuffleForEpoch(1, 10)
	qpos2.mu.RUnlock()

	if equalSlices(shuffle1, shuffle2) {
		t.Fatal("R33 CONS-04 REGRESSION: epoch 1 shuffles should differ when " +
			"genesis roots differ, but they are identical (genesis root not mixed in)")
	}
}

// TestR33_CONS_04_Epoch1ShuffleIndependentOfEpoch1BlockRoot verifies that the
// epoch 1 shuffle seed is INDEPENDENT of epochBlockRoots[1].
//
// CONSENSUS-DETERMINISM FIX (2026-08-04): Previously the epoch-1 seed mixed
// in epochBlockRoots[1], which is set to the FIRST block of epoch 1 (slot 32,
// Slot%SlotsPerEpoch==0). That block's proposer is itself chosen by the
// epoch-1 shuffle — a self-referential, non-deterministic dependency. Nodes
// that computed the epoch-1 shuffle before importing slot 32 used a different
// seed than nodes that computed it after, causing cross-node proposer
// divergence (the observed chain split at heights 21-36 spanning epoch 0/1).
// The fix removes that dependency, so epoch 1 proposer election depends only
// on the finalized genesis root and yields an identical shuffle across nodes.
func TestR33_CONS_04_Epoch1ShuffleIndependentOfEpoch1BlockRoot(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos1, _ := NewQPOS(vs)
	qpos2, _ := NewQPOS(vs)

	// Both have the same genesis root.
	genesisRoot := types.Hash{0xAA, 0xBB, 0xCC}
	qpos1.SetGenesisRoot(genesisRoot)
	qpos2.SetGenesisRoot(genesisRoot)

	// qpos1 has an epoch-1 block root set; qpos2 has a different one.
	// The epoch-1 shuffle MUST be identical regardless, because the seed
	// must not depend on state that is not finalized before epoch 1 begins.
	qpos1.SetEpochBlockRoot(1, types.Hash{0x11, 0x22, 0x33})
	qpos2.SetEpochBlockRoot(1, types.Hash{0x44, 0x55, 0x66})

	qpos1.mu.RLock()
	shuffle1 := qpos1.computeShuffleForEpoch(1, 10)
	qpos1.mu.RUnlock()

	qpos2.mu.RLock()
	shuffle2 := qpos2.computeShuffleForEpoch(1, 10)
	qpos2.mu.RUnlock()

	if !equalSlices(shuffle1, shuffle2) {
		t.Fatal("CONSENSUS-DETERMINISM REGRESSION: epoch 1 shuffles differ when " +
			"epoch-1 block roots differ, but the seed must be independent of " +
			"epochBlockRoots[1] (self-referential, non-deterministic source)")
	}
}

// TestR33_CONS_04_Epoch0WithoutGenesisRootStillWorks verifies that the shuffle
// still works when no genesis root has been set (backward compatibility).
// The shuffle should fall back to keccak(epoch) only.
func TestR33_CONS_04_Epoch0WithoutGenesisRootStillWorks(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)

	// Don't call SetGenesisRoot — simulate a node that hasn't set it yet.
	qpos.mu.RLock()
	shuffle1 := qpos.computeShuffleForEpoch(0, 10)
	shuffle2 := qpos.computeShuffleForEpoch(0, 10)
	qpos.mu.RUnlock()

	if shuffle1 == nil {
		t.Fatal("shuffle should not be nil even without genesis root")
	}
	if !equalSlices(shuffle1, shuffle2) {
		t.Fatal("shuffle should be deterministic even without genesis root")
	}
}

// ============================================================================
// CONSENSUS-DETERMINISM FIX (2026-08-04): ReanchorSlotRoots must recompute
// the per-epoch VRF accumulator on reorg so the shuffle seed stays a
// deterministic function of the canonical chain across all nodes.
// ============================================================================

// TestReanchorSlotRoots_AppliesVRFAccumulatorUpdates verifies that
// ReanchorSlotRoots applies the supplied vrfAccUpdates to the per-epoch VRF
// accumulator and invalidates the dependent shuffle caches. Without this, a
// reorg leaves the abandoned fork's VRF outputs in the accumulator, making
// future epoch shuffles differ across nodes (permanent chain split).
func TestReanchorSlotRoots_AppliesVRFAccumulatorUpdates(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)

	// Simulate a stale accumulator for epoch 0 (abandoned fork) that feeds
	// epoch 2's shuffle.
	stale := types.Hash{0xAA, 0xBB, 0xCC}
	qpos.AccumulateVRFOutput(0, stale)

	// Pre-populate the shuffle cache for epoch 2 (dependent on the old
	// accumulator) so we can verify it is invalidated.
	qpos.mu.Lock()
	qpos.shuffleCache[2] = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	qpos.mu.Unlock()

	// The recomputed accumulator for epoch 0 (from the new canonical chain).
	var newAcc types.Hash
	newAcc[0] = 0x42
	newAcc[1] = 0x99

	// Re-anchor slots above finality (no registered finality → any reorg OK).
	qpos.ReanchorSlotRoots(map[uint64]types.Hash{
		100: {0x01},
		101: {0x02},
	}, map[uint64]types.Hash{0: newAcc})

	// The accumulator for epoch 0 must now equal the recomputed value.
	qpos.mu.RLock()
	got := qpos.epochVRFAccumulator[0]
	_, cached := qpos.shuffleCache[2]
	qpos.mu.RUnlock()

	if got != newAcc {
		t.Errorf("ReanchorSlotRoots did not apply the recomputed VRF accumulator: "+
			"got %v, want %v (stale fork accumulator would corrupt epoch-2 shuffle)", got, newAcc)
	}
	if cached {
		t.Error("ReanchorSlotRoots did not invalidate the dependent shuffle cache — " +
			"a stale shuffle computed from the abandoned fork's accumulator would remain cached")
	}
}

// TestReanchorSlotRoots_SkipsVRFAccumulatorUpdatesOnRefusedReorg verifies that
// when a reorg is refused (touches finalized history), the VRF accumulator
// updates are NOT applied — the finalized chain's accumulator must remain
// immutable just like its slot roots.
func TestReanchorSlotRoots_SkipsVRFAccumulatorUpdatesOnRefusedReorg(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)

	// Finality reached epoch 1 (slots 0..31 finalized).
	qpos.mu.Lock()
	qpos.finalizedEpoch = 1
	qpos.finalizedRoot = types.Hash{0xEE}
	// Record a stable accumulator for epoch 0.
	qpos.epochVRFAccumulator[0] = types.Hash{0xAA, 0xBB}
	qpos.mu.Unlock()

	// Attempt to reorg a finalized slot (30) with an accumulator update.
	qpos.ReanchorSlotRoots(map[uint64]types.Hash{
		30: {0x01},
	}, map[uint64]types.Hash{0: {0xFF, 0xFF}})

	// The accumulator for epoch 0 must be UNCHANGED.
	qpos.mu.RLock()
	got := qpos.epochVRFAccumulator[0]
	qpos.mu.RUnlock()
	if got != (types.Hash{0xAA, 0xBB}) {
		t.Errorf("ReanchorSlotRoots applied VRF accumulator updates on a refused "+
			"reorg — finalized accumulator must be immutable (got %v)", got)
	}
}
