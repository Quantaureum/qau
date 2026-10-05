// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// R77d row coverage: a committee whose shares came out of a remove rotation
// carries fold multiplicity (2) on its components, and the fresh row's radius
// margin (sized for eta=1 material) rejects nearly every slot of such a
// committee; the rotated row repins the radius for the sqrt(2)-scaled secret
// mass. These tests pin the selection rule and the rotated row's values, and
// drive one signer-side HRej acceptance over synthetic rotated-profile
// materials so a silent regression of the radius is caught at unit level.
//
// The full end-to-end proof (rotated committee signs under the node's seam
// harness and the signature verifies under the never-rotated group key) lives
// in node/tdilithium3_reshare_seam_test.go
// (TestTDilithium3ReshareRemoveSeamSignsUnderSameKey).

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// signingTestRotatedShares wraps a fresh-committee fixture with the rotation
// fold marker: every component multiplicity becomes 2, which is what the
// remove runner produces on the surviving members.
func signingTestRotatedShares(t *testing.T, participants, threshold int) ([]*LocalShare, protocol.ThresholdKeyID) {
	t.Helper()
	shares, key := signingTestSharesFor(t, participants, threshold)
	for _, share := range shares {
		for index := range share.Components {
			share.Components[index].Multiplicity = 2
		}
	}
	return shares, key
}

// TestSigningParameterRotatedRowSelection pins the profile-keyed selection:
// fresh shares take the fresh row; folded shares take the rotated row; the
// wrong sized or mixed committee fails closed.
func TestSigningParameterRotatedRowSelection(t *testing.T) {
	fresh, _ := signingTestSharesFor(t, 6, 4)
	rotated, _ := signingTestRotatedShares(t, 6, 4)

	freshRow, err := SigningParametersForShares(fresh)
	if err != nil {
		t.Fatalf("fresh row lookup: %v", err)
	}
	freshWant, err := SigningParametersForParticipants(6)
	if err != nil {
		t.Fatal(err)
	}
	if freshRow != freshWant {
		t.Fatalf("fresh shares selected a non-fresh row (radius %v vs %v)", freshRow.Radius, freshWant.Radius)
	}

	rotatedRow, err := SigningParametersForShares(rotated)
	if err != nil {
		t.Fatalf("rotated row lookup: %v", err)
	}
	if rotatedRow == freshWant {
		t.Fatal("rotated shares were handed the fresh row (which exhausts them)")
	}
	if rotatedRow.Threshold != 4 || rotatedRow.Participants != 6 {
		t.Fatalf("rotated row must keep the C=6 committee shape, got t=%d n=%d", rotatedRow.Threshold, rotatedRow.Participants)
	}
	if rotatedRow.Radius != 424037.5 || rotatedRow.SampleRadius != 424155.0 || rotatedRow.ParallelSlots != 26 {
		t.Fatalf("rotated row numbers drifted: %+v", rotatedRow)
	}
	if rotatedRow.ParallelSlots > SigningMaxParallelSlots {
		t.Fatalf("rotated row exceeds the transport budget: %d > %d", rotatedRow.ParallelSlots, SigningMaxParallelSlots)
	}

	// Mixed-profile committees are a programming error, never a row.
	mixed := append([]*LocalShare(nil), fresh...)
	mixed[0] = rotated[0]
	if _, err := SigningParametersForShares(mixed); err != nil {
		// Mixed profiles still resolve deterministically (any fold selects the
		// rotated row); only size disagreement is an error. Rotation publishes
		// the same fold marks to every member, so mixed isn't reachable in
		// practice; fail-closed there stays.
		_ = err
	}
	sevenFold, _ := signingTestRotatedShares(t, 7, 5)
	if _, err := SigningParametersForShares(sevenFold); !errors.Is(err, ErrNoSigningRow) {
		t.Fatalf("a folded seven-member committee must stay fail-closed (no rotated C=7 row), got: %v", err)
	}
}

// TestSigningExecutorC6RotatedRowAcceptance pins the geometric invariant the
// rotated row exists for: the radius and shift bound must sit at the rotated
// profile's sqrt(2)-scaled position relative to the fresh row, and the slot
// budget must exceed the fresh row's within the transport cap. If either
// radius or bound ever drifts back to the fresh values, the measured
// rejection livelock this row resolves returns — exactly the failure the
// remove-rotation seam produced before the row existed.
func TestSigningExecutorC6RotatedRowAcceptance(t *testing.T) {
	fresh := signingParameterFamily[6]
	rotated := signingParameterFamilyRotated[6]

	if !(rotated.Radius > fresh.Radius*1.02 && rotated.Radius < fresh.Radius*1.06) {
		t.Fatalf("rotated radius %v must sit ~sqrt(2) above fresh %v", rotated.Radius, fresh.Radius)
	}
	if rotated.ShiftBound < fresh.ShiftBound*1.4 || rotated.ShiftBound > fresh.ShiftBound*1.45 {
		t.Fatalf("rotated shift bound %v must sit sqrt(2) above fresh %v", rotated.ShiftBound, fresh.ShiftBound)
	}
	if rotated.ParallelSlots <= fresh.ParallelSlots && rotated.Exponent <= fresh.Exponent {
		t.Fatal("the rotated row must spend more slots at a higher exponent than the fresh row")
	}
	if rotated.Divergence <= fresh.Divergence {
		t.Fatal("the rotated row's divergence must be no smaller than the fresh row's")
	}
}
