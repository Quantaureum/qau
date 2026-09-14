// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

// Demonstrates the PRE-R88-C hazard: bulk-loading the persisted checkpoints
// (SetAllEpochVRFAccumulators, the old behavior) populates fork entropy for
// an epoch with no surviving blocks, defeating the R45 cold-start guard.
func TestR88C_OldBulkLoadHazard(t *testing.T) {
	qpos, err := consensus.NewQPOS(r88BPValidatorSet(t))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.SetEpochVRFAccumulator(10, types.Hash{0x0A}) // replay result

	// Old behavior: bulk-load everything, including fork entropy for epoch 13.
	forkAcc := types.Hash{0xDD}
	qpos.SetAllEpochVRFAccumulators(map[uint64]types.Hash{13: forkAcc})

	if got := qpos.GetEpochVRFAccumulator(13); got == (types.Hash{}) {
		t.Fatal("expected the bulk-load to populate acc[13] (hazard demo setup)")
	}
	// With acc[13] populated, GetProposerForSlot does NOT take the cold-start
	// path — the shuffle is computed from fork entropy and NOT marked cold:
	// every consumer unknowingly acts on the diverged schedule.
	if _, err := qpos.GetProposerForSlot(15 * consensus.SlotsPerEpoch); err != nil {
		t.Fatalf("GetProposerForSlot: %v", err)
	}
	if !qpos.IsProposerScheduleReadyForEpoch(15) {
		t.Fatal("epoch 15 wrongly cold-start: with bulk-loaded acc[13] the guard is defeated (this is the pre-fix hazard)")
	}
}
