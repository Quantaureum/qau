// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestCONS_R40_P1_01_VRFAccumulatorNotPrunedWhenNeeded verifies the pruning
// fix for the proposer-divergence bug.
//
// Root cause: proposer election for epoch N reads epochVRFAccumulator[N-2]
// (the epoch-2 seed delay). The old pruning logic deleted every accumulator
// e < (finalizedEpoch - 1). When finalizedEpoch advanced past N-1, the
// accumulator for N-2 was deleted, so getEpochVRFAccumulatorLocked(N-2)
// returned the zero hash → a different seed → a different proposer →
// cross-node chain split. Nodes that had advanced further (higher
// finalizedEpoch) pruned N-2 earlier than nodes that had not, so the
// majority and the minority disagreed on the canonical proposer.
//
// The fix caps the prune cutoff at (currentEpoch - 3), so the accumulator
// for (currentEpoch - 2) — the farthest epoch any future election still
// depends on — is always retained.
func TestCONS_R40_P1_01_VRFAccumulatorNotPrunedWhenNeeded(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Simulate a chain that has accumulated VRF outputs for epochs 0..19.
	// Each epoch gets a distinct, non-zero VRF output.
	for e := uint64(0); e <= 19; e++ {
		qpos.AccumulateVRFOutput(e, types.Hash{byte(e + 1)})
	}

	// Advance finality far enough that the OLD buggy logic would prune
	// epoch 17 (needed for epoch 19's shuffle) when processing epoch 19.
	// finalizedEpoch = 19 → old pruneCutoff = 18 → deletes e < 18, i.e. 17.
	qpos.mu.Lock()
	qpos.finalizedEpoch = 19
	qpos.mu.Unlock()

	// Trigger pruning by accumulating one more VRF output for epoch 19.
	// (len(epochVRFAccumulator) > 10, so the pruning branch runs.)
	qpos.AccumulateVRFOutput(19, types.Hash{0xAA})

	// The epochs that epoch-19's shuffle depends on (epoch 17) and, by
	// extension, the still-needed epochs (18, 19) must be retained.
	for _, e := range []uint64{17, 18, 19} {
		got := qpos.GetEpochVRFAccumulator(e)
		if got == (types.Hash{}) {
			t.Fatalf("CONS-R40-P1-01 REGRESSION: VRF accumulator for epoch %d "+
				"was pruned but is still needed by epoch %d's proposer election "+
				"(seed source = epoch-2). Pruning it diverges the proposer across nodes.",
				e, e+2)
		}
	}
}

// TestCONS_R40_P1_01_ShuffleDeterministicUnderPruning verifies that the
// proposer for a slot is deterministic regardless of how far each node has
// advanced (finalizedEpoch), i.e. pruning no longer changes the election.
func TestCONS_R40_P1_01_ShuffleDeterministicUnderPruning(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)

	// Node A: finished accumulating epochs 0..19, then advanced finality to 19.
	qa, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS A failed: %v", err)
	}
	for e := uint64(0); e <= 19; e++ {
		qa.AccumulateVRFOutput(e, types.Hash{byte(e + 1)})
	}
	qa.mu.Lock()
	qa.finalizedEpoch = 19
	qa.mu.Unlock()
	qa.AccumulateVRFOutput(19, types.Hash{0xAA}) // trigger pruning

	// Node B: identical accumulation but lower finality (has NOT pruned).
	qb, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS B failed: %v", err)
	}
	for e := uint64(0); e <= 19; e++ {
		qb.AccumulateVRFOutput(e, types.Hash{byte(e + 1)})
	}
	qb.mu.Lock()
	qb.finalizedEpoch = 15
	qb.mu.Unlock()
	qb.AccumulateVRFOutput(19, types.Hash{0xAA})

	slot := uint64(627) // epoch 19, slot 19
	pa, errA := qa.GetProposerForSlot(slot)
	pb, errB := qb.GetProposerForSlot(slot)
	if errA != nil || errB != nil {
		t.Fatalf("GetProposerForSlot error: A=%v B=%v", errA, errB)
	}
	if pa == nil || pb == nil {
		t.Fatalf("nil proposer: A=%v B=%v", pa, pb)
	}
	if pa.Address != pb.Address {
		t.Fatalf("CONS-R40-P1-01 REGRESSION: proposer for slot %d diverges across "+
			"nodes with different finalizedEpoch (pruning changed the election): "+
			"A=%x B=%x", slot, pa.Address[:4], pb.Address[:4])
	}
}
