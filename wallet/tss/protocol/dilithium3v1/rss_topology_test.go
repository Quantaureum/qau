// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"math/bits"
	"testing"
)

func TestRSSCanonicalTopology(t *testing.T) {
	groups := CanonicalRSSGroups()
	seen := make(map[RSSGroupMask]struct{}, len(groups))
	for index, group := range groups {
		if err := group.Validate(); err != nil {
			t.Fatalf("group %d validation: %v", index, err)
		}
		if index > 0 && group <= groups[index-1] {
			t.Fatalf("groups are not strictly increasing at %d", index)
		}
		if bits.OnesCount8(uint8(group)) != 3 {
			t.Fatalf("group %06b does not contain three positions", group)
		}
		if _, exists := seen[group]; exists {
			t.Fatalf("duplicate group %06b", group)
		}
		seen[group] = struct{}{}
	}
	if len(seen) != 20 {
		t.Fatalf("group count = %d, want 20", len(seen))
	}

	for position := uint8(0); position < 6; position++ {
		owned, err := GroupsForPosition(position)
		if err != nil {
			t.Fatalf("GroupsForPosition(%d): %v", position, err)
		}
		for index, group := range owned {
			if !group.Contains(position) {
				t.Fatalf("position %d does not own group %06b", position, group)
			}
			if index > 0 && group <= owned[index-1] {
				t.Fatalf("owned groups for %d are not ordered", position)
			}
		}
	}
}

func TestRSSRejectsInvalidGroupsAndPositions(t *testing.T) {
	// Family validation (R76a): a mask is valid if some committee size in
	// [6, 12] uses it canonically. 15 (popcount 4, positions 0..3) is a
	// canonical group of the nine-to-eleven-member committees.
	for _, group := range []RSSGroupMask{0, 1, 3, 0xff} {
		if !errors.Is(group.Validate(), ErrInvalidRSSGroup) {
			t.Fatalf("group %08b error = %v", group, group.Validate())
		}
	}
	// The strict C=6 rule still rejects groups outside its own committee.
	for _, group := range []RSSGroupMask{0, 1, 3, 15, 0b1000111, 0xff} {
		if !errors.Is(group.ValidateFor(6), ErrInvalidRSSGroup) {
			t.Fatalf("group %08b c=6 error = %v", group, group.ValidateFor(6))
		}
	}
	if _, err := GroupsForPosition(6); !errors.Is(err, ErrInvalidRSSPosition) {
		t.Fatalf("position error = %v", err)
	}
}

func TestRSSFourOfSixAllocation(t *testing.T) {
	groups := CanonicalRSSGroups()
	for activeMask := uint8(0); activeMask < 1<<6; activeMask++ {
		if bits.OnesCount8(activeMask) != 4 {
			continue
		}
		allocation, err := AllocateRSSGroups(activeMask)
		if err != nil {
			t.Fatalf("AllocateRSSGroups(%06b): %v", activeMask, err)
		}
		var assigned [6]int
		for index, group := range groups {
			position := allocation[index]
			if activeMask&(1<<position) == 0 {
				t.Fatalf("group %06b assigned to inactive position %d", group, position)
			}
			if !group.Contains(position) {
				t.Fatalf("group %06b assigned to non-holder %d", group, position)
			}
			assigned[position]++
		}
		for position := uint8(0); position < 6; position++ {
			want := 0
			if activeMask&(1<<position) != 0 {
				want = 5
			}
			if assigned[position] != want {
				t.Fatalf("active set %06b assigns %d components to position %d, want %d", activeMask, assigned[position], position, want)
			}
		}
		again, err := AllocateRSSGroups(activeMask)
		if err != nil || again != allocation {
			t.Fatalf("non-deterministic allocation for %06b: %v", activeMask, err)
		}
	}
	if _, err := AllocateRSSGroups(0b000111); !errors.Is(err, ErrInvalidRSSActiveSet) {
		t.Fatalf("three-member active set error = %v", err)
	}
	if _, err := AllocateRSSGroups(0b011111); !errors.Is(err, ErrInvalidRSSActiveSet) {
		t.Fatalf("five-member active set error = %v", err)
	}
}

func TestRSSPrivacyBoundary(t *testing.T) {
	groups := CanonicalRSSGroups()
	for coalition := uint8(0); coalition < 1<<6; coalition++ {
		if bits.OnesCount8(coalition) > 3 {
			continue
		}
		foundDisjoint := false
		for _, group := range groups {
			if uint8(group)&coalition == 0 {
				foundDisjoint = true
				break
			}
		}
		if !foundDisjoint {
			t.Fatalf("coalition %06b knows every RSS component", coalition)
		}
	}
}

func TestRSSLeaderReplacement(t *testing.T) {
	group := RSSGroupMask(0b101010)
	want := []uint8{1, 3, 5}
	for attempt, wantPosition := range want {
		got, err := group.Leader(uint8(attempt))
		if err != nil {
			t.Fatalf("Leader(%d): %v", attempt, err)
		}
		if got != wantPosition {
			t.Fatalf("Leader(%d) = %d, want %d", attempt, got, wantPosition)
		}
	}
	if _, err := group.Leader(3); !errors.Is(err, ErrRSSLeaderExhausted) {
		t.Fatalf("exhausted leader error = %v", err)
	}
}
