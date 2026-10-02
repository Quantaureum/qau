// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"math/bits"
	"sort"
)

// v1 CNF-RSS topology (dynamic committee family, R76).
//
// Committees are C positions numbered 0..C-1 in canonical roster order with
// C in [6, 12] (protocol.Dilithium3V1Min/MaxParticipants) and threshold
// t = ceil(2C/3). A replicated secret component belongs to a group of
// g = C - t + 1 = floor(C/3)+1 positions; the group count is binomial(C, g)
// (20 for C=6, 35 for C=7, ... 792 for C=12). Every active set of t positions
// intersects every group because t + g > C, and every coalition of t-1
// positions misses at least one group. Masks are uint16 bit-sets over
// committee positions; C <= 12 keeps them comfortably inside 16 bits.
//
// C=6 reproduces the original fixed four-of-six topology bit-for-bit: the
// same 20 masks, the same ten components per position, the same group leader
// chain, and the same active-set allocation rule.

var (
	ErrInvalidRSSGroup       = errors.New("invalid Dilithium3 v1 RSS group")
	ErrInvalidRSSPosition    = errors.New("invalid Dilithium3 v1 RSS position")
	ErrInvalidRSSActiveSet   = errors.New("invalid Dilithium3 v1 RSS active set")
	ErrRSSLeaderExhausted    = errors.New("Dilithium3 v1 RSS group leaders exhausted")
	ErrInvalidRSSParticipant = errors.New("invalid Dilithium3 v1 RSS participant count")
)

// RSSGroupMask identifies one replicated-group secret component as a bit-set
// of committee positions.
type RSSGroupMask uint16

func rssPositionMask(participants int) uint16 {
	return (uint16(1) << participants) - 1
}

// rssGroupSize returns the replicated group size g = C - t + 1.
func rssGroupSize(participants int) int {
	return GroupSizeForParticipants(participants)
}

func rssValidParticipants(participants int) error {
	if participants < MinCommitteeParticipants || participants > MaxCommitteeParticipants {
		return ErrInvalidRSSParticipant
	}
	return nil
}

// CanonicalRSSGroupsFor returns all binomial(C, g) groups in mask order.
func CanonicalRSSGroupsFor(participants int) ([]RSSGroupMask, error) {
	if err := rssValidParticipants(participants); err != nil {
		return nil, err
	}
	groupSize := rssGroupSize(participants)
	positionMask := rssPositionMask(participants)
	groups := make([]RSSGroupMask, 0, 4096)
	for mask := uint16(0); mask <= positionMask; mask++ {
		if bits.OnesCount16(mask) == groupSize {
			groups = append(groups, RSSGroupMask(mask))
		}
	}
	return groups, nil
}

// CanonicalRSSGroups returns the original twenty-group six-member topology.
func CanonicalRSSGroups() [20]RSSGroupMask {
	groups, err := CanonicalRSSGroupsFor(6)
	if err != nil {
		return [20]RSSGroupMask{}
	}
	var fixed [20]RSSGroupMask
	copy(fixed[:], groups)
	return fixed
}

// ValidateFor requires the mask to be a canonical group of the given
// committee size: exactly g(C) = C - t + 1 positions, all below C.
func (group RSSGroupMask) ValidateFor(participants int) error {
	if err := rssValidParticipants(participants); err != nil {
		return err
	}
	mask := uint16(group)
	if mask&^rssPositionMask(participants) != 0 || bits.OnesCount16(mask) != rssGroupSize(participants) {
		return ErrInvalidRSSGroup
	}
	return nil
}

// Validate requires the mask to be a canonical group of SOME committee size
// in the family (R76a). Structure is bound to the session's committee
// elsewhere (canonical group lists are derived from the session's committee
// size and every round compares against them); a mask that no family member
// could have produced is rejected here, for every other mask the session
// checks decide.
func (group RSSGroupMask) Validate() error {
	mask := uint16(group)
	if mask == 0 || mask&^rssPositionMask(MaxCommitteeParticipants) != 0 {
		return ErrInvalidRSSGroup
	}
	popcount := bits.OnesCount16(mask)
	for participants := MinCommitteeParticipants; participants <= MaxCommitteeParticipants; participants++ {
		if popcount == rssGroupSize(participants) {
			if mask&^rssPositionMask(participants) == 0 {
				return nil
			}
		}
	}
	return ErrInvalidRSSGroup
}

// Contains reports whether the group contains a canonical committee position.
func (group RSSGroupMask) Contains(position uint8) bool {
	return position < 16 && uint16(group)&(1<<position) != 0
}

// Leader returns the deterministic group leader for one fresh attempt:
// positions of the group in ascending order. The attempt bound is the group
// size, which the mask itself encodes, so no committee size is needed.
func (group RSSGroupMask) Leader(attempt uint8) (uint8, error) {
	if err := group.Validate(); err != nil {
		return 0, err
	}
	if int(attempt) >= bits.OnesCount16(uint16(group)) {
		return 0, ErrRSSLeaderExhausted
	}
	remaining := int(attempt)
	for position := uint8(0); position < 16; position++ {
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

// GroupsForPositionN returns the canonical components held by one position in
// a C-member committee.
func GroupsForPositionN(position uint8, participants int) ([]RSSGroupMask, error) {
	groups, err := CanonicalRSSGroupsFor(participants)
	if err != nil {
		return nil, err
	}
	if int(position) >= participants {
		return nil, ErrInvalidRSSPosition
	}
	owned := make([]RSSGroupMask, 0, len(groups)/2)
	for _, group := range groups {
		if group.Contains(position) {
			owned = append(owned, group)
		}
	}
	return owned, nil
}

// GroupsForPosition returns the ten canonical components held by one position
// of the fixed six-member committee.
func GroupsForPosition(position uint8) ([10]RSSGroupMask, error) {
	owned, err := GroupsForPositionN(position, 6)
	if err != nil {
		return [10]RSSGroupMask{}, err
	}
	var fixed [10]RSSGroupMask
	copy(fixed[:], owned)
	return fixed, nil
}

// AllocateRSSGroupsFor assigns every canonical group of a C-member committee
// to exactly one of the t active holders, deterministically.
//
// Correctness requires only that the owner of a group is an active member of
// the group; the distribution should additionally stay balanced (within one
// group between holders) for load symmetry. For C = 6 this reproduces the
// original bit-exact rules (intersection sizes 1/2/3 select the sole member,
// a first-inactive-guided endpoint, or the rotation by the rank of the first
// excluded active). For C >= 7 the group must also be covered when fewer than
// three actives are outside it, which the legacy rotation cannot guarantee,
// so these committees use intersection load balancing: groups are served in
// ascending intersection size and each one goes to the least-loaded active
// member contained in it. The six-member profile is pinned
// bit-exact by TestRSSFourOfSixAllocation.
func AllocateRSSGroupsFor(activeMask uint16, participants int) ([]uint8, error) {
	if err := rssValidParticipants(participants); err != nil {
		return nil, err
	}
	threshold := ThresholdForParticipants(participants)
	positionMask := rssPositionMask(participants)
	if activeMask&^positionMask != 0 || bits.OnesCount16(activeMask) != threshold {
		return nil, ErrInvalidRSSActiveSet
	}
	groups, err := CanonicalRSSGroupsFor(participants)
	if err != nil {
		return nil, err
	}
	allocation := make([]uint8, len(groups))
	firstInactive := uint8(bits.TrailingZeros16(positionMask &^ activeMask))
	activePositions := make([]uint8, 0, threshold)
	for position := uint8(0); position < uint8(participants); position++ {
		if activeMask&(1<<position) != 0 {
			activePositions = append(activePositions, position)
		}
	}
	legacy := participants == 6
	for index, group := range groups {
		intersection := uint16(group) & activeMask
		if legacy {
			switch bits.OnesCount16(intersection) {
			case 1:
				allocation[index] = uint8(bits.TrailingZeros16(intersection))
			case 2:
				if uint16(group)&(1<<firstInactive) != 0 {
					allocation[index] = uint8(bits.TrailingZeros16(intersection))
				} else {
					allocation[index] = uint8(bits.Len16(intersection) - 1)
				}
			default:
				remaining := activeMask &^ intersection
				missing := uint8(bits.TrailingZeros16(remaining))
				rank := bits.OnesCount16(activeMask & ((1 << missing) - 1))
				allocation[index] = activePositions[(rank+1)%len(activePositions)]
			}
			continue
		}
		// Intersection load balancing, tightest masks first: process groups in
		// order of ascending intersection size (canonical index as tie-break)
		// and assign each group to the least-loaded member of its intersection
		// (lowest position on ties). Small intersections constrain the fewest
		// owners, so serving them first keeps the final distribution within
		// one group of perfect balance; the order affects only the assignment
		// outcome, not the assignment validity.
	}
	if legacy {
		return allocation, nil
	}
	order := make([]int, len(groups))
	for index := range order {
		order[index] = index
	}
	sort.SliceStable(order, func(i, j int) bool {
		left := bits.OnesCount16(uint16(groups[order[i]]) & activeMask)
		right := bits.OnesCount16(uint16(groups[order[j]]) & activeMask)
		if left != right {
			return left < right
		}
		return order[i] < order[j]
	})
	var load [MaxCommitteeParticipants]int
	for _, index := range order {
		intersection := uint16(groups[index]) & activeMask
		if intersection == 0 {
			return nil, ErrInvalidRSSActiveSet
		}
		// Intersection load balancing: choose the least-loaded owner among
		// the intersection members, lowest position on ties. Every owner
		// belongs to both the group and the active set by construction.
		owner := uint8(0)
		ownerLoad := int(^uint(0) >> 1)
		for position := uint8(0); position < uint8(participants); position++ {
			if intersection&(1<<position) == 0 {
				continue
			}
			if load[position] < ownerLoad {
				owner = position
				ownerLoad = load[position]
			}
		}
		allocation[index] = owner
		load[owner]++
	}
	return allocation, nil
}

// groupSizeForMask returns the number of ones in the mask.
func groupSizeForMask(mask RSSGroupMask) int {
	return bits.OnesCount16(uint16(mask))
}

// AllocateRSSGroups assigns each active holder five components (fixed
// six-member committee, t = 4).
func AllocateRSSGroups(activeMask uint8) ([20]uint8, error) {
	allocation, err := AllocateRSSGroupsFor(uint16(activeMask), 6)
	if err != nil {
		return [20]uint8{}, err
	}
	var fixed [20]uint8
	copy(fixed[:], allocation)
	return fixed, nil
}

// SortedCommitteePositions returns the committee positions ascending; helper
// for callers that iterate C positions without a mask.
func SortedCommitteePositions(participants int) []uint8 {
	positions := make([]uint8, participants)
	for i := range positions {
		positions[i] = uint8(i)
	}
	sort.Slice(positions, func(i, j int) bool { return positions[i] < positions[j] })
	return positions
}
