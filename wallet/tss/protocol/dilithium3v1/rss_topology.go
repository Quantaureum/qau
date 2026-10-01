// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"math/bits"
)

const rssPositionMask uint8 = (1 << 6) - 1

var (
	ErrInvalidRSSGroup     = errors.New("invalid Dilithium3 v1 RSS group")
	ErrInvalidRSSPosition  = errors.New("invalid Dilithium3 v1 RSS position")
	ErrInvalidRSSActiveSet = errors.New("invalid Dilithium3 v1 RSS active set")
	ErrRSSLeaderExhausted  = errors.New("Dilithium3 v1 RSS group leaders exhausted")
)

// RSSGroupMask identifies one three-position replicated secret component.
type RSSGroupMask uint8

// CanonicalRSSGroups returns all twenty three-position groups in mask order.
func CanonicalRSSGroups() [20]RSSGroupMask {
	var groups [20]RSSGroupMask
	groupIndex := 0
	for mask := uint8(0); mask <= rssPositionMask; mask++ {
		if bits.OnesCount8(mask) == 3 {
			groups[groupIndex] = RSSGroupMask(mask)
			groupIndex++
		}
	}
	return groups
}

// Validate requires exactly three positions from the fixed six-member committee.
func (group RSSGroupMask) Validate() error {
	mask := uint8(group)
	if mask&^rssPositionMask != 0 || bits.OnesCount8(mask) != 3 {
		return ErrInvalidRSSGroup
	}
	return nil
}

// Contains reports whether the group contains a canonical committee position.
func (group RSSGroupMask) Contains(position uint8) bool {
	return position < 6 && uint8(group)&(1<<position) != 0
}

// Leader returns the deterministic group leader for one fresh attempt.
func (group RSSGroupMask) Leader(attempt uint8) (uint8, error) {
	if err := group.Validate(); err != nil {
		return 0, err
	}
	if attempt >= 3 {
		return 0, ErrRSSLeaderExhausted
	}
	remaining := attempt
	for position := uint8(0); position < 6; position++ {
		if !group.Contains(position) {
			continue
		}
		if remaining == 0 {
			return position, nil
		}
		remaining--
	}
	return 0, ErrRSSLeaderExhausted
}

// GroupsForPosition returns the ten canonical components held by one position.
func GroupsForPosition(position uint8) ([10]RSSGroupMask, error) {
	if position >= 6 {
		return [10]RSSGroupMask{}, ErrInvalidRSSPosition
	}
	groups := CanonicalRSSGroups()
	var owned [10]RSSGroupMask
	ownedIndex := 0
	for _, group := range groups {
		if group.Contains(position) {
			owned[ownedIndex] = group
			ownedIndex++
		}
	}
	return owned, nil
}

// AllocateRSSGroups assigns each active holder five components.
func AllocateRSSGroups(activeMask uint8) ([20]uint8, error) {
	if activeMask&^rssPositionMask != 0 || bits.OnesCount8(activeMask) != 4 {
		return [20]uint8{}, ErrInvalidRSSActiveSet
	}
	groups := CanonicalRSSGroups()
	var allocation [20]uint8
	firstInactive := uint8(bits.TrailingZeros8(rssPositionMask &^ activeMask))
	var activePositions [4]uint8
	for position, index := uint8(0), 0; position < 6; position++ {
		if activeMask&(1<<position) != 0 {
			activePositions[index] = position
			index++
		}
	}
	for index, group := range groups {
		intersection := uint8(group) & activeMask
		switch bits.OnesCount8(intersection) {
		case 1:
			allocation[index] = uint8(bits.TrailingZeros8(intersection))
		case 2:
			if uint8(group)&(1<<firstInactive) != 0 {
				allocation[index] = uint8(bits.TrailingZeros8(intersection))
			} else {
				allocation[index] = uint8(bits.Len8(intersection) - 1)
			}
		case 3:
			missing := uint8(bits.TrailingZeros8(activeMask &^ intersection))
			rank := bits.OnesCount8(activeMask & ((1 << missing) - 1))
			allocation[index] = activePositions[(rank+1)%len(activePositions)]
		default:
			return [20]uint8{}, ErrInvalidRSSActiveSet
		}
	}
	return allocation, nil
}
