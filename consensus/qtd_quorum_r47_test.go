// Quantaureum Node source, version 1.0.0.
package consensus

// R47-QTD-QUORUM (2026-09-26) regression tests.
//
// R47 changed the QTD seal quorum in two ways:
//  1. RequiredWeight basis widened from the executive chamber for the epoch
//     to the FULL validator set (the DKG threshold-group holder set covers
//     every validator). Locked by TestP3_QTD_01_SnapshotSealerStakes_* in
//     p3_qtd_01_threshold_dedup_test.go.
//  2. RequiredCount is now max(executive.Threshold(), signer.Threshold()):
//     an aggregated threshold signature only verifies when >= t partial
//     signatures are combined, so a RequiredCount below the DKG group's t
//     would create pending seals that can never complete. A signer that does
//     not track a threshold shape (test mocks, single-node signers) returns
//     0 and the chamber quorum remains the floor.
//
// The tests below lock semantics (2) at both the field level and the
// behavior level.

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// thresholdShapeSigner wraps mockThresholdSigner and reports an explicit
// DKG group threshold shape. Used to verify RequiredCount takes the max of
// the chamber threshold and the signer threshold.
type thresholdShapeSigner struct {
	mockThresholdSigner
	threshold int
}

func (s *thresholdShapeSigner) Threshold() int { return s.threshold }

// TestR47_RequiredCount_TakesMaxOfSignerAndChamberThreshold verifies that
// RequestSeal stores RequiredCount = max(executive.Threshold(), signer.Threshold()).
//
// Topology: 4 equal-stake validators (total 4000, RequiredWeight 2667),
// executive {0,1,2} with chamber threshold 2, signer reporting a 4-of-6 DKG
// group shape. RequiredCount must be 4 — and three executive signatures
// (weight 3000 >= 2667, count 3 < 4) must NOT complete the seal. This proves
// the count gate is enforced independently of the weight gate: without the
// R47 max(), the seal would have completed at count 2 with a signature that
// the DKG group can never aggregate.
func TestR47_RequiredCount_TakesMaxOfSignerAndChamberThreshold(t *testing.T) {
	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&thresholdShapeSigner{threshold: 4})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	const slot = uint64(1)
	approveSlot(coordinator, slot)
	blockHash := types.Hash{}
	blockHash[0] = 0x47
	qpos.SetSlotBlockRoot(slot, blockHash)

	if err := qfs.RequestSeal(slot, blockHash); err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}

	qfs.mu.RLock()
	pending := qfs.pendingSeals[slot]
	qfs.mu.RUnlock()
	if pending == nil {
		t.Fatal("pending seal missing after RequestSeal")
	}
	if pending.RequiredCount != 4 {
		t.Errorf("RequiredCount = %d, want 4 (max of chamber threshold 2 and signer threshold 4)",
			pending.RequiredCount)
	}

	// Three executive signatures: count 3 < RequiredCount 4 even though the
	// weight (3000) clears the bar (2667). The seal must NOT complete.
	for _, member := range []int{0, 1, 2} {
		if err := qfs.SubmitPartialSeal(member, slot, []byte("r47-shape-sig-min16bytes")); err != nil {
			t.Fatalf("SubmitPartialSeal(%d) failed: %v", member, err)
		}
	}

	qfs.mu.RLock()
	pending = qfs.pendingSeals[slot]
	sigCount := 0
	if pending != nil {
		sigCount = len(pending.PartialSigs)
	}
	qfs.mu.RUnlock()

	if qfs.IsSlotFinalized(slot) {
		t.Error("seal completed with count 3 < RequiredCount 4 — the DKG group shape was ignored")
	}
	if pending == nil {
		t.Fatal("pending seal was deleted before RequiredCount was reached")
	}
	if sigCount != 3 {
		t.Errorf("expected 3 retained sigs (weight met, count not), got %d", sigCount)
	}
}

// TestR47_RequiredCount_FallsBackToChamberWhenSignerThresholdZero verifies
// the fallback semantics: when the active signer reports Threshold() == 0
// (no tracked threshold shape — test mocks, single-node signers), the
// RequiredCount stays at the executive chamber threshold and the seal
// completes at the chamber quorum.
func TestR47_RequiredCount_FallsBackToChamberWhenSignerThresholdZero(t *testing.T) {
	// 3 validators so the executive {0,1,2} IS the full set:
	// total 3000, RequiredWeight 2000, two signatures cover 2000.
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	// mockThresholdSigner.Threshold() returns 0 (no tracked shape).
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	const slot = uint64(2)
	approveSlot(coordinator, slot)
	blockHash := types.Hash{}
	blockHash[0] = 0x48
	qpos.SetSlotBlockRoot(slot, blockHash)

	if err := qfs.RequestSeal(slot, blockHash); err != nil {
		t.Fatalf("RequestSeal failed: %v", err)
	}

	qfs.mu.RLock()
	pending := qfs.pendingSeals[slot]
	qfs.mu.RUnlock()
	if pending == nil {
		t.Fatal("pending seal missing after RequestSeal")
	}
	if pending.RequiredCount != 2 {
		t.Errorf("RequiredCount = %d, want 2 (chamber threshold; signer Threshold()==0 must not lower or raise it)",
			pending.RequiredCount)
	}

	// Two distinct signatures complete the seal at the chamber quorum.
	if err := qfs.SubmitPartialSeal(0, slot, []byte("r47-fallback-sig-0-min16bytes")); err != nil {
		t.Fatalf("SubmitPartialSeal(0) failed: %v", err)
	}
	if err := qfs.SubmitPartialSeal(1, slot, []byte("r47-fallback-sig-1-min16bytes")); err != nil {
		t.Fatalf("SubmitPartialSeal(1) failed: %v", err)
	}
	if !qfs.IsSlotFinalized(slot) {
		t.Error("seal should complete with 2 signatures when signer reports no threshold shape")
	}
}
