// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// ============================================================================
// QR-21: a reorg that rewrites epoch e's VRF accumulator must release any
// VDF stand-down pin derived from the abandoned accumulator. The seed for
// shuffle epoch e+2 mixes acc[e], so pins on e/e+1/e+2 are stale the moment
// the reorg is accepted; a pinned node would otherwise hard-reject the
// canonical chain (ErrVDFSeedUnavailable -> ErrInvalidProposer) until
// restart. The wiring lives in reanchorSlotRoots' accepted path and mirrors
// the e+1/e+2 cache-invalidation policy of SetAllEpochVRFAccumulators.
// ============================================================================

// TestReanchorSlotRoots_ReleasesVDFSeedStopsOnAcceptedReorg verifies that an
// accepted reorg carrying accumulator updates releases the stand-down pins
// for the reorganized epoch and its dependent epochs, while leaving pins on
// unrelated epochs untouched.
func TestReanchorSlotRoots_ReleasesVDFSeedStopsOnAcceptedReorg(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)

	const pinned uint64 = 4
	// Pin the reorganized epoch, its two dependent epochs, and an unrelated
	// epoch that the reorg must not touch.
	qpos.MarkVDFSeedStopped(pinned)
	qpos.MarkVDFSeedStopped(pinned + 1)
	qpos.MarkVDFSeedStopped(pinned + 2)
	qpos.MarkVDFSeedStopped(pinned + 5)

	var newAcc types.Hash
	newAcc[0] = 0x42
	newAcc[1] = 0x99

	qpos.ReanchorSlotRoots(map[uint64]types.Hash{
		100: {0x01},
		101: {0x02},
	}, map[uint64]types.Hash{pinned: newAcc})

	qpos.mu.RLock()
	got := qpos.epochVRFAccumulator[pinned]
	qpos.mu.RUnlock()
	if got != newAcc {
		t.Fatalf("ReanchorSlotRoots did not apply the recomputed accumulator: got %v, want %v", got, newAcc)
	}
	for _, e := range []uint64{pinned, pinned + 1, pinned + 2} {
		if qpos.VDFSeedStopped(e) {
			t.Errorf("VDF stand-down pin for epoch %d survived a reorg that rewrote epoch %d's accumulator — "+
				"the node would keep rejecting the canonical chain until restart (QR-21)", e, pinned)
		}
	}
	if !qpos.VDFSeedStopped(pinned + 5) {
		t.Errorf("stand-down pin for unrelated epoch %d must survive the reorg", pinned+5)
	}
}

// TestReanchorSlotRoots_KeepsVDFSeedStopsOnRefusedReorg verifies the negative
// control: when the reorg is refused (touches finalized history), neither the
// accumulators nor the stand-down pins may change.
func TestReanchorSlotRoots_KeepsVDFSeedStopsOnRefusedReorg(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)

	// Finality reached epoch 1 (slots 0..31 finalized).
	qpos.mu.Lock()
	qpos.finalizedEpoch = 1
	qpos.finalizedRoot = types.Hash{0xEE}
	qpos.mu.Unlock()

	for _, e := range []uint64{0, 1, 2, 5} {
		qpos.MarkVDFSeedStopped(e)
	}

	qpos.ReanchorSlotRoots(map[uint64]types.Hash{
		30: {0x01},
	}, map[uint64]types.Hash{0: {0xFF, 0xFF}})

	for _, e := range []uint64{0, 1, 2, 5} {
		if !qpos.VDFSeedStopped(e) {
			t.Errorf("VDF stand-down pin for epoch %d was released by a REFUSED reorg — "+
				"pins must only follow accepted accumulator rewrites (QR-21)", e)
		}
	}
}

// TestReanchorSlotRoots_KeepsVDFSeedStopsWhenNoAccumulatorChanged verifies
// that a pure head rollback (no accumulator updates in the reorg plan)
// releases nothing: the pins are only stale if their source accumulator was
// rewritten.
func TestReanchorSlotRoots_KeepsVDFSeedStopsWhenNoAccumulatorChanged(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)

	for _, e := range []uint64{4, 5, 6, 9} {
		qpos.MarkVDFSeedStopped(e)
	}

	qpos.ReanchorSlotRoots(map[uint64]types.Hash{
		100: {0x01},
	}, nil)

	for _, e := range []uint64{4, 5, 6, 9} {
		if !qpos.VDFSeedStopped(e) {
			t.Errorf("VDF stand-down pin for epoch %d was released although the reorg carried no accumulator updates", e)
		}
	}
}

// TestSetEpochVRFAccumulator_ReleasesDependentVDFSeedStops verifies that the
// per-block accumulator write (header replay, calibration) releases the
// stand-down pins on the dependent epochs under the same e+1/e+2 policy as
// its own cache invalidation.
func TestSetEpochVRFAccumulator_ReleasesDependentVDFSeedStops(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)

	for _, e := range []uint64{5, 6, 9} {
		qpos.MarkVDFSeedStopped(e)
	}

	qpos.SetEpochVRFAccumulator(4, types.Hash{0x42})

	for _, e := range []uint64{5, 6} {
		if qpos.VDFSeedStopped(e) {
			t.Errorf("VDF stand-down pin for dependent epoch %d survived an accumulator rewrite of epoch 4", e)
		}
	}
	if !qpos.VDFSeedStopped(9) {
		t.Error("stand-down pin for unrelated epoch 9 must survive")
	}
}

// TestSetAllEpochVRFAccumulators_ReleasesDependentVDFSeedStops verifies the
// bulk store-load write path releases dependent pins under the same policy.
func TestSetAllEpochVRFAccumulators_ReleasesDependentVDFSeedStops(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)

	for _, e := range []uint64{5, 6, 9} {
		qpos.MarkVDFSeedStopped(e)
	}

	qpos.SetAllEpochVRFAccumulators(map[uint64]types.Hash{
		4: {0x42},
	})

	for _, e := range []uint64{5, 6} {
		if qpos.VDFSeedStopped(e) {
			t.Errorf("VDF stand-down pin for dependent epoch %d survived a bulk accumulator restore of epoch 4", e)
		}
	}
	if !qpos.VDFSeedStopped(9) {
		t.Error("stand-down pin for unrelated epoch 9 must survive")
	}
}

// TestClearEpochVRFAccumulatorsFrom_ReleasesDependentVDFSeedStops verifies
// that a fork-rollback accumulator wipe releases the pins that depended on
// the removed state; persistent VDF failures re-pin on the next election.
func TestClearEpochVRFAccumulatorsFrom_ReleasesDependentVDFSeedStops(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(10))
	qpos, _ := NewQPOS(vs)

	qpos.AccumulateVRFOutput(4, types.Hash{0x11})
	for _, e := range []uint64{5, 6, 9} {
		qpos.MarkVDFSeedStopped(e)
	}

	qpos.ClearEpochVRFAccumulatorsFrom(4)

	for _, e := range []uint64{5, 6} {
		if qpos.VDFSeedStopped(e) {
			t.Errorf("VDF stand-down pin for dependent epoch %d survived a rollback accumulator wipe from epoch 4", e)
		}
	}
	if !qpos.VDFSeedStopped(9) {
		t.Error("stand-down pin for unrelated epoch 9 must survive")
	}
}
