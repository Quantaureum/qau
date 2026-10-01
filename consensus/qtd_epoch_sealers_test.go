// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"reflect"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestQTDEpochSealersIncludesNonBoundarySlots(t *testing.T) {
	engine, err := NewQPOS(createTestValidatorSet(t, 9))
	if err != nil {
		t.Fatal(err)
	}
	engine.finalizedEpoch = 1
	state := NewQTDFinalityState(engine)
	for slot, sealers := range map[uint64][]int{35: {8, 0}, 40: {0, 8}, 41: {4}, 64: {3, 6}} {
		root := types.Hash{byte(slot)}
		state.instantFinalizedSlots[slot] = &InstantFinalityRecord{Slot: slot, BlockHash: root, Sealers: sealers}
		engine.SetSlotBlockRoot(slot, root)
	}
	engine.SetSlotBlockRoot(41, types.Hash{99})
	if got := state.GetEpochSealers(1); !reflect.DeepEqual(got, []int{0, 8}) {
		t.Fatalf("epoch sealers = %v, want sorted unique canonical sealers [0 8]", got)
	}
	if got := state.GetEpochSealers(2); len(got) != 0 {
		t.Fatalf("included unfinalized epoch: %v", got)
	}
}
