// Quantaureum Node source, version 1.0.0.
package tss

import (
	"github.com/quantaureum/qau/wallet/tss/qtd"
	"testing"
)

func TestDistributedRound2RequiresPrivateContributions(t *testing.T) {
	signer := NewDistributedSigner(nil)
	sessionID := [32]byte{1}
	signer.sessions[sessionID] = &DistributedSession{
		Threshold: 2, ParticipantIDs: []int{1, 2},
		round2Reveals: make(map[int]*qtd.Round2Reveal),
	}
	for _, participantID := range []int{1, 2} {
		if err := signer.SubmitRound2Reveal(sessionID, &qtd.Round2Reveal{ParticipantID: participantID}); err != nil {
			t.Fatal(err)
		}
	}
	if signer.IsRound2Complete(sessionID) {
		t.Fatal("public reveals alone must not make Round2 ready for aggregation")
	}
	if err := signer.AttachZ0Contribution(sessionID, 1, []byte{1}, []byte{2}); err != nil {
		t.Fatal(err)
	}
	if signer.IsRound2Complete(sessionID) {
		t.Fatal("one private contribution is insufficient")
	}
	if err := signer.AttachZ0Contribution(sessionID, 2, []byte{3}, []byte{4}); err != nil {
		t.Fatal(err)
	}
	if !signer.IsRound2Complete(sessionID) {
		t.Fatal("Round2 did not complete after all private contributions arrived")
	}
}

func TestDistributedPrivateRevealMayArriveBeforePublic(t *testing.T) {
	signer := NewDistributedSigner(nil)
	sessionID := [32]byte{2}
	signer.sessions[sessionID] = &DistributedSession{
		Threshold: 2, ParticipantIDs: []int{1, 2}, round2Reveals: make(map[int]*qtd.Round2Reveal),
	}
	if err := signer.AttachZ0Contribution(sessionID, 1, []byte{3}, []byte{4}); err != nil {
		t.Fatalf("private contribution arriving before its public reveal was lost: %v", err)
	}
	if err := signer.SubmitRound2Reveal(sessionID, &qtd.Round2Reveal{ParticipantID: 1, WShare: []byte{5}}); err != nil {
		t.Fatal(err)
	}
	if err := signer.SubmitRound2Reveal(sessionID, &qtd.Round2Reveal{ParticipantID: 1, WShare: []byte{5}}); err != nil {
		t.Fatal(err)
	}
	if err := signer.SubmitRound2Reveal(sessionID, &qtd.Round2Reveal{ParticipantID: 2, WShare: []byte{6}}); err != nil {
		t.Fatal(err)
	}
	if err := signer.AttachZ0Contribution(sessionID, 2, []byte{7}, []byte{8}); err != nil {
		t.Fatal(err)
	}
	if !signer.IsRound2Complete(sessionID) {
		t.Fatal("duplicate public reveal erased the private contribution")
	}
}
