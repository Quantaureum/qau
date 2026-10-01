// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"
)

func TestDKGComplaintRejectsFalseAndUnrelatedEvidence(t *testing.T) {
	complaint := testDKGComplaint()
	if err := complaint.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := complaint.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalComplaint(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if restored != complaint {
		t.Fatal("complaint round trip mismatch")
	}
	tests := []struct {
		name   string
		mutate func(*Complaint)
	}{
		{name: "evidence session", mutate: func(value *Complaint) { value.Evidence.SessionDigest[0] ^= 1 }},
		{name: "evidence committee", mutate: func(value *Complaint) { value.Evidence.CommitteeDigest[0] ^= 1 }},
		{name: "evidence group", mutate: func(value *Complaint) { value.Evidence.GroupMask = RSSGroupMask(0b001101) }},
		{name: "evidence leader", mutate: func(value *Complaint) { value.Evidence.LeaderPosition = 1 }},
		{name: "evidence attempt", mutate: func(value *Complaint) { value.Evidence.Attempt = 1 }},
		{name: "zero evidence digest", mutate: func(value *Complaint) { value.Evidence.MessageDigest = [32]byte{} }},
		{name: "leader complains", mutate: func(value *Complaint) { value.ComplainantPosition = value.LeaderPosition }},
		{name: "unknown reason", mutate: func(value *Complaint) { value.Reason = ComplaintReasonUnknown }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := complaint
			test.mutate(&mutated)
			if !errors.Is(mutated.Validate(), ErrInvalidComplaint) {
				t.Fatalf("invalid complaint error = %v", mutated.Validate())
			}
		})
	}
	falseMissing := complaint
	falseMissing.Reason = ComplaintReasonMissingSeed
	if !errors.Is(falseMissing.Validate(), ErrInvalidComplaint) {
		t.Fatalf("missing-seed complaint exposed seed: %v", falseMissing.Validate())
	}
}

func TestDKGComplaintReplacesLeadersAndAbortsAfterThreeFailures(t *testing.T) {
	message := testGroupSeedMessage()
	state, err := NewGroupAttemptState(message.SessionDigest, message.CommitteeDigest, message.GroupMask)
	if err != nil {
		t.Fatal(err)
	}
	for attempt, wantNextLeader := range []uint8{1, 3} {
		current := message
		current.Attempt = uint8(attempt)
		current.LeaderPosition, _ = current.GroupMask.Leader(current.Attempt)
		current.RecipientPosition = nextGroupRecipient(current.GroupMask, current.LeaderPosition)
		current.Seed[0] = byte(10 + attempt)
		if err := state.AcceptSeed(current); err != nil {
			t.Fatal(err)
		}
		complaint := complaintForMessage(t, current)
		if err := state.ApplyComplaint(complaint); err != nil {
			t.Fatal(err)
		}
		if state.Attempt != uint8(attempt+1) || state.LeaderPosition != wantNextLeader || state.SeedMessageDigest != ([32]byte{}) {
			t.Fatalf("replacement state = attempt %d leader %d seed %x", state.Attempt, state.LeaderPosition, state.SeedMessageDigest)
		}
	}
	finalMessage := message
	finalMessage.Attempt = 2
	finalMessage.LeaderPosition = 3
	finalMessage.RecipientPosition = 0
	finalMessage.Seed[0] = 12
	if err := state.AcceptSeed(finalMessage); err != nil {
		t.Fatal(err)
	}
	if err := state.ApplyComplaint(complaintForMessage(t, finalMessage)); !errors.Is(err, ErrDKGSessionAbort) {
		t.Fatalf("third failure error = %v", err)
	}
	if !state.Aborted {
		t.Fatal("third failed leader did not abort session")
	}
}

func TestDKGComplaintCannotReplaceAcceptedContribution(t *testing.T) {
	message := testGroupSeedMessage()
	state, err := NewGroupAttemptState(message.SessionDigest, message.CommitteeDigest, message.GroupMask)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.AcceptSeed(message); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkContributionAccepted([32]byte{9}); err != nil {
		t.Fatal(err)
	}
	if err := state.ApplyComplaint(complaintForMessage(t, message)); !errors.Is(err, ErrGroupContributionFinalized) {
		t.Fatalf("accepted contribution replacement error = %v", err)
	}
}

func testDKGComplaint() Complaint {
	return Complaint{
		SessionDigest:       [32]byte{1, 2, 3},
		CommitteeDigest:     [32]byte{4, 5, 6},
		GroupMask:           RSSGroupMask(0b001011),
		LeaderPosition:      0,
		ComplainantPosition: 1,
		Attempt:             0,
		Reason:              ComplaintReasonConflictingSeeds,
		Evidence: ComplaintEvidence{
			SessionDigest:   [32]byte{1, 2, 3},
			CommitteeDigest: [32]byte{4, 5, 6},
			GroupMask:       RSSGroupMask(0b001011),
			LeaderPosition:  0,
			Attempt:         0,
			MessageDigest:   [32]byte{7, 8, 9},
			RevealedSeed:    [32]byte{10, 11, 12},
		},
	}
}

func complaintForMessage(t *testing.T, message GroupSeedMessage) Complaint {
	t.Helper()
	digest, err := message.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return Complaint{
		SessionDigest:       message.SessionDigest,
		CommitteeDigest:     message.CommitteeDigest,
		GroupMask:           message.GroupMask,
		LeaderPosition:      message.LeaderPosition,
		ComplainantPosition: message.RecipientPosition,
		Attempt:             message.Attempt,
		Reason:              ComplaintReasonConflictingSeeds,
		Evidence: ComplaintEvidence{
			SessionDigest:   message.SessionDigest,
			CommitteeDigest: message.CommitteeDigest,
			GroupMask:       message.GroupMask,
			LeaderPosition:  message.LeaderPosition,
			Attempt:         message.Attempt,
			MessageDigest:   digest,
			RevealedSeed:    message.Seed,
		},
	}
}

func nextGroupRecipient(group RSSGroupMask, leader uint8) uint8 {
	for position := uint8(0); position < 6; position++ {
		if group.Contains(position) && position != leader {
			return position
		}
	}
	return 0
}
