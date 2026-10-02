// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// binomial is the exact group-count oracle for the family test.
func binomial(n, k int) int {
	return int(new(big.Int).Binomial(int64(n), int64(k)).Int64())
}

// TestRSSCommitteeFamily verifies the CNF-RSS security combinatorics for every
// committee size in the R76a family [6, 12]: group counts match binomial(C,
// floor(C/3)+1), every position owns binomial(C-1, floor(C/3)); every
// t-subset of positions intersects every group, and every (t-1)-coalition
// misses at least one group (the replication threshold property).
func TestRSSCommitteeFamily(t *testing.T) {
	for participants := MinCommitteeParticipants; participants <= MaxCommitteeParticipants; participants++ {
		groups, err := CanonicalRSSGroupsFor(participants)
		if err != nil {
			t.Fatalf("C=%d: %v", participants, err)
		}
		threshold := ThresholdForParticipants(participants)
		groupSize := GroupSizeForParticipants(participants)
		if len(groups) != binomial(participants, groupSize) {
			t.Fatalf("C=%d: group count %d, want binomial(%d,%d)=%d", participants, len(groups), participants, groupSize, binomial(participants, groupSize))
		}
		for _, group := range groups {
			if err := group.ValidateFor(participants); err != nil {
				t.Fatalf("C=%d canonical group %b invalid: %v", participants, group, err)
			}
		}
		for position := uint8(0); position < uint8(participants); position++ {
			owned, err := GroupsForPositionN(position, participants)
			if err != nil {
				t.Fatalf("C=%d: %v", participants, err)
			}
			if len(owned) != binomial(participants-1, groupSize-1) {
				t.Fatalf("C=%d position %d owns %d groups, want %d", participants, position, len(owned), binomial(participants-1, groupSize-1))
			}
		}
		// Exhaustive coalition check for small sizes, sampled for large ones.
		type trial struct{ active uint16 }
		var trials []trial
		if participants <= 9 {
			for mask := 0; mask < (1 << participants); mask++ {
				trials = append(trials, trial{uint16(mask)})
			}
		} else {
			state := uint64(0xC001FACE)
			for index := 0; index < 200000; index++ {
				state = state*6364136223846793005 + 1442695040888963407
				trials = append(trials, trial{uint16(state >> 48)})
			}
		}
		for _, item := range trials {
			active := item.active
			popcount := 0
			for bit := 0; bit < participants; bit++ {
				if active&(1<<bit) != 0 {
					popcount++
				}
			}
			covers := true
			for _, group := range groups {
				if uint16(group)&active == 0 {
					covers = false
					break
				}
			}
			if covers && popcount < threshold {
				t.Fatalf("C=%d: coalition %012b with %d < t=%d members covers all groups", participants, active, popcount, threshold)
			}
			if !covers && popcount >= threshold {
				t.Fatalf("C=%d: coalition %012b with %d >= t=%d members misses a group", participants, active, popcount, threshold)
			}
		}
		// Allocation assigns every group to an active holder and balances.
		active := uint16(0)
		for position := uint8(0); position < uint8(threshold); position++ {
			active |= 1 << position
		}
		allocation, err := AllocateRSSGroupsFor(active, participants)
		if err != nil {
			t.Fatalf("C=%d allocation: %v", participants, err)
		}
		owned := make([]int, participants)
		for groupIndex, owner := range allocation {
			if active&(1<<owner) == 0 || !groups[groupIndex].Contains(owner) {
				t.Fatalf("C=%d: group %d allocated to position %d outside the active set or group", participants, groupIndex, owner)
			}
			owned[owner]++
		}
		minimum, maximum := len(groups), 0
		for _, count := range owned {
			if count > 0 {
				minimum = min(minimum, count)
				maximum = max(maximum, count)
			}
		}
		if maximum-minimum > 1 {
			t.Fatalf("C=%d allocation imbalance: min=%d max=%d", participants, minimum, maximum)
		}
		// Leader rotation covers every group member.
		for _, group := range groups {
			for attempt := uint8(0); attempt < uint8(groupSize); attempt++ {
				leader, err := group.Leader(attempt)
				if err != nil || !group.Contains(leader) {
					t.Fatalf("C=%d group %b attempt %d: leader=%d err=%v", participants, group, attempt, leader, err)
				}
			}
			if _, err := group.Leader(uint8(groupSize)); err == nil {
				t.Fatalf("C=%d group %b accepted an out-of-range leader attempt", participants, group)
			}
		}
	}
}

// TestCommitteeFamilyValidation pins the family validation rule and its
// fail-closed edges.
func TestCommitteeFamilyValidation(t *testing.T) {
	accept := func(participants int, threshold uint32) {
		t.Helper()
		ids := make([]uint32, participants)
		for index := range ids {
			ids[index] = uint32(index + 1)
		}
		committee := protocol.CommitteeID{Version: 1, Threshold: threshold, Participants: ids}
		if err := protocol.ValidateDilithium3V1Committee(committee); err != nil {
			t.Fatalf("C=%d t=%d rejected: %v", participants, threshold, err)
		}
	}
	reject := func(participants int, threshold uint32) {
		t.Helper()
		ids := make([]uint32, participants)
		for index := range ids {
			ids[index] = uint32(index + 1)
		}
		committee := protocol.CommitteeID{Version: 1, Threshold: threshold, Participants: ids}
		if err := protocol.ValidateDilithium3V1Committee(committee); err == nil {
			t.Fatalf("C=%d t=%d accepted", participants, threshold)
		}
	}
	accept(6, 4)
	accept(7, 5)
	accept(12, 8)
	reject(6, 5)
	reject(7, 4)
	reject(7, 6)
	reject(5, 4)
	reject(13, 9)
}

// TestSigningRejectsNonSixCommittee pins the R76 fail-closed boundary: the
// signing MPC is pinned per committee row, so any committee shape without a
// pinned parameter row (C = 8..12 after R76b) must stop before any signing
// state exists, with the row table — not the committee family check — as the
// second line of defense.
func TestSigningRejectsNonSixCommittee(t *testing.T) {
	shares, key, _ := testMode3RSSShares(t)
	upgraded := []*LocalShare{}
	committee := protocol.CommitteeID{Version: 1, Threshold: 6, Participants: []uint32{1, 2, 3, 4, 5, 6, 7, 8}}
	for index := 0; index < 6; index++ {
		share := shares[index].Clone()
		share.Committee = committee.Clone()
		share.ParticipantID = committee.Participants[index]
		share.ParticipantPosition = uint8(index)
		groups, err := GroupsForPositionN(uint8(index), 8)
		if err != nil {
			t.Fatal(err)
		}
		components := make([]RSSComponent, len(groups))
		for componentIndex, group := range groups {
			leader, err := group.Leader(0)
			if err != nil {
				t.Fatal(err)
			}
			components[componentIndex] = RSSComponent{
				GroupMask:          group,
				DealerPosition:     leader,
				ContributionDigest: [32]byte{0x77, byte(index), byte(componentIndex), 1},
				Multiplicity:       1,
			}
			components[componentIndex].S1[0][0] = Coefficient(index + 1)
			components[componentIndex].S2[0][0] = Q - Coefficient(index+1)
		}
		share.Components = components
		if err := share.Validate(); err != nil {
			t.Fatalf("synthetic share %d invalid: %v", index, err)
		}
		upgraded = append(upgraded, share)
	}
	journal := signingTestJournal(t)
	record := mpcTestRecord(t, 0x77)
	request := protocol.SignRequest{Protocol: protocol.ThresholdProtocolDilithium3V1, Key: key.Clone(), Committee: upgraded[0].Committee.Clone(), ChainID: 1333, Epoch: 1, Slot: 1, Domain: protocol.SigningDomainFinality, Message: []byte("R76 family gate"), AttemptNonce: [32]byte{9}}
	if err := request.Validate(); err != nil {
		t.Fatalf("family committee rejected at the request layer: %v", err)
	}
	var randomness []*signingRandomness
	attempt, err := newSigningAttempt(journal, record, request, upgraded, signingTestCoordinator, randomness)
	if !errors.Is(err, ErrUnsupportedSigningCommitteeSize) {
		t.Fatalf("signing attempt against C=8: %v", err)
	}
	if attempt != nil {
		t.Fatal("attempt created against an unpinned committee row")
	}
}
