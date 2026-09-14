// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestQTDFinality_EpochBoundaryWindowContract pins the observable semantics
// of IsSlotFinalized around the first slot of a new epoch.
//
// Publication is two-phase by design (R38-003): completeSealLocked writes the
// finality record into instantFinalizedSlots synchronously, but hands the
// qpos.finalizedEpoch update to a goroutine so the qpos.mu -> qfs.mu lock
// order is preserved. IsSlotFinalized cross-checks record.Epoch against
// qpos.GetFinalizedEpoch() (R39-P2-01). Consumers were audited (2026-08-27):
//
//   - RPC "finalized" block tag reads finalizedEpoch directly, not this method
//   - the only production callers of CompleteSeal/FinalizeBlock
//     (node/block_producer.go per-slot tick, node/qtd_seal.go) retry on the
//     next tick, so a transient false costs one tick of lifecycle latency
//   - no fork-choice or reorg path consults IsSlotFinalized
//
// So the contract pinned here is: the window answers false (never panics,
// never errors), it converges to true once finalizedEpoch reaches the
// record's epoch, and once true the answer is stable while the record lives.
// A refactor that wants to close the window (publishing epoch and record
// atomically) must keep these properties; a refactor that accidentally makes
// the cross-check stricter (e.g. finalizedEpoch > record.Epoch) breaks the
// convergence assertion below.
func TestQTDFinality_EpochBoundaryWindowContract(t *testing.T) {
	qpos, _, _ := setupStardustWithQTD(t, 10)
	qfs := qpos.GetQTDFinality()

	const boundarySlot = uint64(10016) // first slot of the following epoch
	const prevEpoch = uint64(312)
	const boundaryEpoch = uint64(313)

	// Simulate the mid-window state deterministically: the record for the
	// boundary slot is published (completeSealLocked ran), but the finalize
	// goroutine has not landed yet, so finalizedEpoch still points at the
	// previous epoch.
	qfs.mu.Lock()
	qfs.instantFinalizedSlots[boundarySlot] = &InstantFinalityRecord{
		Slot:      boundarySlot,
		BlockHash: types.Hash{0x0A},
		SealedAt:  time.Unix(int64(boundarySlot), 0),
		Sealers:   []int{4, 5},
		ChainID:   1333,
		Epoch:     boundaryEpoch,
	}
	qfs.mu.Unlock()
	setFinalizedEpoch(t, qpos, prevEpoch)

	// (1) Inside the window the answer is false. This documents today's
	// behavior — a conservative "not yet", the safe direction.
	if qfs.IsSlotFinalized(boundarySlot) {
		t.Error("inside the epoch-boundary window the answer should still be false (conservative)")
	}

	// (2) Convergence: once the goroutine lands and finalizedEpoch reaches
	// the record's epoch, the answer must flip to true. Equality must be
	// sufficient (not finalizedEpoch > record.Epoch).
	setFinalizedEpoch(t, qpos, boundaryEpoch)
	if !qfs.IsSlotFinalized(boundarySlot) {
		t.Error("once finalizedEpoch == record.Epoch the slot must be finalized")
	}

	// (3) Stability: a later epoch must not flip the answer back.
	setFinalizedEpoch(t, qpos, boundaryEpoch+87)
	if !qfs.IsSlotFinalized(boundarySlot) {
		t.Error("a finalized slot must stay finalized as finalizedEpoch advances")
	}

	// (4) Same-window lookup for a slot sealed in an ALREADY finalized epoch
	// is true immediately — no window, because finalizedEpoch >= record.Epoch
	// holds from publication onward. This is the property the per-slot tick
	// in block_producer relies on for every non-boundary slot.
	const sameEpochSlot = uint64(10020) // same epoch as boundarySlot
	qfs.mu.Lock()
	qfs.instantFinalizedSlots[sameEpochSlot] = &InstantFinalityRecord{
		Slot:      sameEpochSlot,
		BlockHash: types.Hash{0x0B},
		SealedAt:  time.Unix(int64(sameEpochSlot), 0),
		Sealers:   []int{4, 5},
		ChainID:   1333,
		Epoch:     boundaryEpoch,
	}
	qfs.mu.Unlock()
	if !qfs.IsSlotFinalized(sameEpochSlot) {
		t.Error("a slot sealed in an already-finalized epoch must be final immediately")
	}
}

// TestQTDFinality_BoundarySealConvergesBounded drives the real pipeline:
// seal a slot in epoch A, wait for its finalize goroutine (so finalizedEpoch
// becomes non-zero and the cross-check is live), then seal the first slot of
// epoch A+1 and assert IsSlotFinalized converges to true within a bounded
// wait. This is the production-shaped version of the contract above.
func TestQTDFinality_BoundarySealConvergesBounded(t *testing.T) {
	qpos, coordinator, _ := setupStardustWithQTD(t, 10)
	qfs := qpos.GetQTDFinality()

	sealReal := func(slot uint64) {
		t.Helper()
		epoch := slot / uint64(SlotsPerEpoch)
		_ = coordinator.AssignExecutive([]int{4, 5, 6}, epoch)
		if executive := coordinator.GetExecutiveChamber(); executive != nil {
			_ = executive.SetMembers([]int{4, 5, 6}, epoch)
			_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))
		}
		blockHash := types.Hash{}
		blockHash[0] = byte(slot % 256)
		qpos.SetSlotBlockRoot(slot, blockHash)
		approveSlot(coordinator, slot)
		if err := qfs.RequestSeal(slot, blockHash); err != nil {
			t.Fatalf("RequestSeal(%d): %v", slot, err)
		}
		if err := qfs.SubmitPartialSeal(4, slot, []byte("partial-seal-4-min16bytes")); err != nil {
			t.Fatalf("SubmitPartialSeal(4, %d): %v", slot, err)
		}
		if err := qfs.SubmitPartialSeal(5, slot, []byte("partial-seal-5-min16bytes")); err != nil {
			t.Fatalf("SubmitPartialSeal(5, %d): %v", slot, err)
		}
	}

	// Seal one slot in epoch 312 and wait for the finalize goroutine so the
	// cross-check becomes live (finalizedEpoch = 312 != 0).
	sealReal(10000)
	waitFor(t, "epoch 312 finality", 5*time.Second, func() bool {
		return qpos.GetFinalizedEpoch() >= 312
	})

	// Seal the first slot of epoch 313 through the real pipeline.
	sealReal(10016)

	// Convergence must happen within a bounded wait regardless of goroutine
	// scheduling: either the goroutine already landed (immediately true) or
	// it lands shortly after.
	waitFor(t, "epoch-boundary slot convergence", 5*time.Second, func() bool {
		return qfs.IsSlotFinalized(10016)
	})
	if got := qpos.GetFinalizedEpoch(); got < 313 {
		t.Errorf("finalizedEpoch should have advanced to 313, got %d", got)
	}
}

func setFinalizedEpoch(t *testing.T, qpos *QPOS, epoch uint64) {
	t.Helper()
	qpos.mu.Lock()
	qpos.finalizedEpoch = epoch
	qpos.mu.Unlock()
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", what)
	}
}
