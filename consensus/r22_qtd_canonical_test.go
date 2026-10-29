// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// R22 (2026-10-29): regression tests for the revert of the R19-F08 record
// rollback and the new IsCanonicalSeal accessor.
//
// Background: R19-F08 deleted a QTD seal record from instantFinalizedSlots
// whenever the asynchronous canonical-root check found no matching root. That
// deletion raced the two consumers that read the record synchronously
// (reproduced locally: 2 failures in 40 runs of
// TestPopulateStardustFieldsWithProvinces) and it contradicted the R4-CORE-04
// invariant that a quorum-approved seal is RETAINED as threshold-agreement
// proof even when its block is not canonical. R22 reverts the deletion and
// instead reports the canonical status honestly (IsCanonicalSeal).

// TestR22_IsCanonicalSeal pins the accessor's three-way semantics without any
// concurrency: it must report "not confirmed" for a missing record and for an
// unknown canonical root, "confirmed" only for a matching known root, and
// "not confirmed" for a known-and-different root.
func TestR22_IsCanonicalSeal(t *testing.T) {
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	// No record at all -> false.
	if qfs.IsCanonicalSeal(7) {
		t.Fatal("no record: IsCanonicalSeal must be false")
	}

	// Plant records directly (same pattern as qtd_epoch_sealers_test.go).
	matching := types.Hash{0xAA}
	different := types.Hash{0xBB}
	unknown := types.Hash{0xCC}
	qfs.mu.Lock()
	qfs.instantFinalizedSlots[7] = &InstantFinalityRecord{Slot: 7, BlockHash: matching, Sealers: []int{0, 1}}
	qfs.instantFinalizedSlots[8] = &InstantFinalityRecord{Slot: 8, BlockHash: different, Sealers: []int{0, 1}}
	qfs.instantFinalizedSlots[9] = &InstantFinalityRecord{Slot: 9, BlockHash: unknown, Sealers: []int{0, 1}}
	qfs.mu.Unlock()

	// Root not established for any of them -> all "not confirmed".
	if qfs.IsCanonicalSeal(7) || qfs.IsCanonicalSeal(8) || qfs.IsCanonicalSeal(9) {
		t.Fatal("unknown canonical root: IsCanonicalSeal must be false for all")
	}

	// Matching root -> true.
	qpos.SetSlotBlockRoot(7, matching)
	if !qfs.IsCanonicalSeal(7) {
		t.Error("matching known root: IsCanonicalSeal must be true")
	}

	// Known-and-different -> false: the slot's canonical root is some OTHER
	// block than the one the seal recorded.
	qpos.SetSlotBlockRoot(8, types.Hash{0xDD})
	if qfs.IsCanonicalSeal(8) {
		t.Error("known-and-different root: IsCanonicalSeal must be false")
	}
}

// TestR22_NonCanonicalSealRecordSurvivesAsyncFinalize is the negative control
// for the reverted rollback. It reproduces the R4-CORE-04 scenario (a seal
// whose hash is NOT the canonical slot root) and then gives the asynchronous
// finalize goroutine a full second to run. Pre-fix, that goroutine deleted
// the record on a timing race (and qpos finality was not advanced). Post-fix,
// the record must survive (it is the threshold-agreement proof) while qpos
// finality still must NOT advance to the non-canonical hash.
func TestR22_NonCanonicalSealRecordSurvivesAsyncFinalize(t *testing.T) {
	vs := createTestValidatorSet(t, 3)
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
		ApproveCount:  4,
		RejectCount:   1,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	nonCanonical := types.Hash{0x22}
	if err := qpos.RequestQTDFinalitySeal(5, nonCanonical); err != nil {
		t.Fatalf("RequestSeal should be allowed while the root is unknown: %v", err)
	}
	// The canonical slot root lands on a DIFFERENT block after the seal is
	// requested (simulates a fork / reorg between RequestSeal and completion).
	canonical := types.Hash{0x11}
	qpos.SetSlotBlockRoot(5, canonical)

	_ = qfs.SubmitPartialSeal(0, 5, []byte("partial-sig-0-min16bytes"))
	_ = qfs.SubmitPartialSeal(1, 5, []byte("partial-sig-1-min16bytes"))

	// Give the async finalize goroutine a generous window to (pre-fix) delete
	// the record. If the rollback bug is present the record disappears here
	// and this assertion fails.
	time.Sleep(1500 * time.Millisecond)

	rec := qfs.GetFinalityRecord(5)
	if rec == nil {
		t.Fatal("non-canonical seal record must SURVIVE the async finalizer (threshold-agreement proof); it was deleted — R19-F08 rollback regression")
	}

	// The consensus finality state must NOT have advanced to the
	// non-canonical hash (the pre-existing fail-closed behavior is preserved).
	qpos.mu.RLock()
	finalizedRoot := qpos.finalizedRoot
	qpos.mu.RUnlock()
	if finalizedRoot == nonCanonical {
		t.Fatal("qpos.finalizedRoot must not advance to a non-canonical block hash")
	}
	if qfs.IsCanonicalSeal(5) {
		t.Error("the sealed hash is not the canonical root; IsCanonicalSeal(5) must be false")
	}
}

// TestR22_StardustFieldsDoNotBindStaleSeal is the negative control for the
// header-population guard added with the R22 revert: a retained record whose
// block is NOT the slot's canonical root must never be presented as the new
// block's finality proof. The normal production case (canonical root not yet
// known for the slot) must still copy the signature, and so must a record
// whose hash IS the known canonical root.
func TestR22_StardustFieldsDoNotBindStaleSeal(t *testing.T) {
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	recorded := types.Hash{0xAA}
	sealSig := []byte("qtd-threshold-signature-for-recorded-block")
	qfs.mu.Lock()
	qfs.instantFinalizedSlots[5] = &InstantFinalityRecord{
		Slot:         5,
		BlockHash:    recorded,
		QTDSignature: append([]byte(nil), sealSig...),
		Sealers:      []int{0, 1},
	}
	qfs.mu.Unlock()

	// (a) Canonical root unknown (the normal production case) -> copied.
	unknownRoot := &encoding.BlockHeader{Slot: 5}
	if err := PopulateStardustFields(unknownRoot, qpos); err != nil {
		t.Fatalf("PopulateStardustFields failed: %v", err)
	}
	if len(unknownRoot.QTDSignature) == 0 {
		t.Fatal("root unknown: the recorded seal signature must be copied (normal production path)")
	}

	// (b) Known canonical root that DIFFERS from the record -> must NOT be
	// copied: the record belongs to another block at this slot (reorg after
	// a non-canonical seal).
	qpos.SetSlotBlockRoot(5, types.Hash{0xBB})
	staleHeader := &encoding.BlockHeader{Slot: 5}
	if err := PopulateStardustFields(staleHeader, qpos); err != nil {
		t.Fatalf("PopulateStardustFields failed: %v", err)
	}
	if len(staleHeader.QTDSignature) != 0 {
		t.Fatal("stale record: a different block's seal signature must not be attached to this header")
	}

	// (c) Known canonical root that MATCHES the record -> copied.
	qpos.SetSlotBlockRoot(5, recorded)
	boundHeader := &encoding.BlockHeader{Slot: 5}
	if err := PopulateStardustFields(boundHeader, qpos); err != nil {
		t.Fatalf("PopulateStardustFields failed: %v", err)
	}
	if len(boundHeader.QTDSignature) == 0 {
		t.Fatal("matching canonical root: the seal signature must be copied")
	}
}
