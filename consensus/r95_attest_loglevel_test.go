// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"fmt"
	"testing"
)

// R95-ATTEST-LOGLEVEL regression test.
//
// Without this fix every node can log a WARN per slot of the form
//
//	ProcessReviewAttestation failed for slot 669 (validator=5):
//	validator 5 cannot attest: not in Review Chamber for slot 669
//
// The rejected validator index is exactly that slot's own block proposer.
//
// So the rejection is CORRECT and structurally guaranteed: BlockProducer
// creates and broadcasts an attestation for the slot it just proposed, every
// peer receives it, and ThreeChambersCoordinator.CanAttest correctly refuses it
// because the slot's proposer may not also attest.
//
// The defect is the SIGNAL, not the behavior. The identical
// ProcessReviewAttestation call is logged at Debug in
// node/block_producer.go:1724 but at Warn in node/node.go:8041 — an unintended
// asymmetry that buried genuinely actionable warnings. During R93/R94
// forensics this one message accounted for ~1/3 of all WARN volume and had to
// dominate otherwise actionable warning output.
//
// FIX: give the condition a sentinel (ErrNotInReviewChamber) so the receiver
// can classify it as expected-and-routine (Debug) while any OTHER
// ProcessReviewAttestation failure still surfaces at Warn. Classification by
// sentinel, never by string matching.
func TestR95_NotInReviewChamberIsSentinelClassifiable(t *testing.T) {
	// The rejection path must be identifiable via errors.Is so callers can
	// choose a log level without matching on message text.
	wrapped := fmt.Errorf("validator %d cannot attest: %w for slot %d", 5, ErrNotInReviewChamber, 669)
	if !errors.Is(wrapped, ErrNotInReviewChamber) {
		t.Fatal("errors.Is must match ErrNotInReviewChamber through wrapping")
	}

	// A different failure must NOT be misclassified as the routine one,
	// otherwise the fix would silence real problems.
	other := fmt.Errorf("attester %d: %w", 5, ErrNotInCommittee)
	if errors.Is(other, ErrNotInReviewChamber) {
		t.Error("ErrNotInCommittee must not satisfy errors.Is(ErrNotInReviewChamber) — " +
			"downgrading it to Debug would hide a real committee-membership fault")
	}
	if errors.Is(ErrInvalidAttestation, ErrNotInReviewChamber) {
		t.Error("ErrInvalidAttestation must not satisfy errors.Is(ErrNotInReviewChamber)")
	}
}

// TestR95_ProposerAttestationRejectionCarriesSentinel drives the real
// ProcessReviewAttestation path: the slot's assigned proposer attests, gets
// refused, and the error must carry the sentinel.
//
// Fails without the fix: the error is a bare fmt.Errorf with no sentinel, so
// errors.Is returns false and node.go cannot distinguish it from a genuine
// fault.
func TestR95_ProposerAttestationRejectionCarriesSentinel(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	coordinator := NewThreeChambersCoordinator(qpos)
	qpos.SetChambersCoordinator(coordinator)

	const proposerIdx = 4
	const slot = uint64(669)

	// Mirror production: GetProposerForSlot assigns the elected proposer to
	// ChamberProposing for that slot.
	if err := coordinator.AssignProposing(proposerIdx, slot); err != nil {
		t.Fatalf("AssignProposing: %v", err)
	}

	review := coordinator.GetReviewChamber()
	if review == nil {
		t.Fatal("review chamber must exist")
	}

	err = review.ProcessReviewAttestation(&Attestation{
		Slot:           slot,
		ValidatorIndex: proposerIdx,
	})
	if err == nil {
		t.Fatal("the slot's own proposer must not be allowed to attest")
	}
	if !errors.Is(err, ErrNotInReviewChamber) {
		t.Errorf("ProcessReviewAttestation error = %v; must wrap ErrNotInReviewChamber so the "+
			"receiver can log this expected-every-slot condition at Debug instead of Warn "+
			"(R95-ATTEST-LOGLEVEL). Without the sentinel, node.go emits a WARN per slot "+
			"and buries actionable warnings.", err)
	}
}
