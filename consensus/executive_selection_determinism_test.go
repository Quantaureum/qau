// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"reflect"
	"testing"
)

func TestExecutiveSelectionIgnoresLocalSlotAssignments(t *testing.T) {
	validators := createTestValidatorSet(t, 9)
	baseline, err := NewQPOS(validators)
	if err != nil {
		t.Fatal(err)
	}
	baseline.InitChambers()
	expected, err := baseline.GetChambersCoordinator().SelectExecutiveForEpoch(1, validators)
	if err != nil {
		t.Fatal(err)
	}

	for _, chamber := range []ChamberID{ChamberProposing, ChamberReview} {
		engine, err := NewQPOS(validators)
		if err != nil {
			t.Fatal(err)
		}
		engine.InitChambers()
		coordinator := engine.GetChambersCoordinator()
		coordinator.assignment.Assign(expected[0], chamber, SlotsPerEpoch+2, 1)
		actual, err := coordinator.SelectExecutiveForEpoch(1, validators)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("local chamber %v changed committee: got %v, want %v", chamber, actual, expected)
		}
	}
}
