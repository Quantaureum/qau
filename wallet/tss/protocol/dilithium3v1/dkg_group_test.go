// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"
)

func TestDKGGroupSeedMessageBindsContextAndRejectsEquivocation(t *testing.T) {
	message := testGroupSeedMessage()
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := message.ValidateFor(message.SessionDigest, message.CommitteeDigest, message.GroupMask, message.RecipientPosition); err != nil {
		t.Fatal(err)
	}
	encoded, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalGroupSeedMessage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if restored != message {
		t.Fatal("group seed message round trip mismatch")
	}
	mutations := []struct {
		name   string
		mutate func(*GroupSeedMessage)
	}{
		{name: "session", mutate: func(value *GroupSeedMessage) { value.SessionDigest[0] ^= 1 }},
		{name: "committee", mutate: func(value *GroupSeedMessage) { value.CommitteeDigest[0] ^= 1 }},
		{name: "group", mutate: func(value *GroupSeedMessage) { value.GroupMask = RSSGroupMask(0b001101) }},
		{name: "leader", mutate: func(value *GroupSeedMessage) { value.LeaderPosition = 1 }},
		{name: "recipient", mutate: func(value *GroupSeedMessage) { value.RecipientPosition = 3 }},
		{name: "attempt", mutate: func(value *GroupSeedMessage) { value.Attempt = 1 }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			mutated := message
			test.mutate(&mutated)
			if err := mutated.ValidateFor(message.SessionDigest, message.CommitteeDigest, message.GroupMask, message.RecipientPosition); !errors.Is(err, ErrInvalidGroupSeedMessage) {
				t.Fatalf("changed context error = %v", err)
			}
		})
	}
	state, err := NewGroupAttemptState(message.SessionDigest, message.CommitteeDigest, message.GroupMask)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.AcceptSeed(message); err != nil {
		t.Fatal(err)
	}
	changedSeed := message
	changedSeed.Seed[0] ^= 1
	if err := state.AcceptSeed(changedSeed); !errors.Is(err, ErrConflictingGroupSeed) {
		t.Fatalf("changed seed error = %v", err)
	}
}

func TestDKGGroupAcknowledgementsRejectDuplicatesAndContributionConflicts(t *testing.T) {
	message := testGroupSeedMessage()
	messageDigest, err := message.Digest()
	if err != nil {
		t.Fatal(err)
	}
	seedCommitmentDigest, err := message.SeedCommitmentDigest()
	if err != nil {
		t.Fatal(err)
	}
	otherRecipientMessage := message
	otherRecipientMessage.RecipientPosition = 3
	otherRecipientDigest, err := otherRecipientMessage.Digest()
	if err != nil {
		t.Fatal(err)
	}
	contributionDigest := [32]byte{9, 8, 7}
	set, err := NewGroupAcknowledgementSet(message, contributionDigest)
	if err != nil {
		t.Fatal(err)
	}
	positions := []uint8{0, 1, 3}
	for index, position := range positions {
		participantMessageDigest := messageDigest
		if position == message.LeaderPosition {
			participantMessageDigest = seedCommitmentDigest
		} else if position == otherRecipientMessage.RecipientPosition {
			participantMessageDigest = otherRecipientDigest
		}
		acknowledgement := ContributionAcknowledgement{
			SessionDigest:        message.SessionDigest,
			CommitteeDigest:      message.CommitteeDigest,
			GroupMask:            message.GroupMask,
			LeaderPosition:       message.LeaderPosition,
			ParticipantPosition:  position,
			Attempt:              message.Attempt,
			SeedCommitmentDigest: seedCommitmentDigest,
			SeedMessageDigest:    participantMessageDigest,
			ContributionDigest:   contributionDigest,
		}
		encoded, err := acknowledgement.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := UnmarshalContributionAcknowledgement(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if restored != acknowledgement {
			t.Fatal("acknowledgement round trip mismatch")
		}
		if err := set.Add(acknowledgement); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if err := set.Add(acknowledgement); !errors.Is(err, ErrDuplicateGroupAcknowledgement) {
				t.Fatalf("duplicate acknowledgement error = %v", err)
			}
			conflicting := acknowledgement
			conflicting.ParticipantPosition = 1
			conflicting.ContributionDigest[0] ^= 1
			if err := set.Add(conflicting); !errors.Is(err, ErrConflictingPublicContribution) {
				t.Fatalf("conflicting contribution error = %v", err)
			}
		}
	}
	if !set.Complete() {
		t.Fatal("three matching group acknowledgements did not complete")
	}
}

func testGroupSeedMessage() GroupSeedMessage {
	return GroupSeedMessage{
		SessionDigest:     [32]byte{1, 2, 3},
		CommitteeDigest:   [32]byte{4, 5, 6},
		GroupMask:         RSSGroupMask(0b001011),
		LeaderPosition:    0,
		RecipientPosition: 1,
		Attempt:           0,
		Seed:              [32]byte{7, 8, 9},
	}
}
