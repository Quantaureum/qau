package dilithium3v1

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// reshare_r77.go implements the R77 same-key rotation plan for the CNF-RSS
// family: given a committee of size C and a target committee of size C+1 or
// C-1 touching exactly one position, the plan maps every old group component
// into the new topology so the family-wide key sum is invariant. The wire
// choreography that moves the deltas between members lives in the node
// reshare driver; this file carries the pure, deterministic core the driver
// and its tests agree on.

var (
	// ErrReshareRotationInput marks a rotation plan request the family does
	// not support: committee sizes out of range, multi-position deltas, or
	// shape-preserving no-ops.
	ErrReshareRotationInput = errors.New("invalid Dilithium3 v1 reshare rotation")
	// ErrReshareComponentMissing marks an Apply call whose source component
	// set cannot reproduce the old key (a carry or fold source is absent).
	ErrReshareComponentMissing = errors.New("missing Dilithium3 v1 reshare component")
)

// ReshareFoldAssignment moves one leaver-group component into a surviving
// target group. The anchor is a member of both source and target; it is the
// unique authority allowed to publish the source component as the delta.
type ReshareFoldAssignment struct {
	Source         RSSGroupMask
	Target         RSSGroupMask
	AnchorPosition uint8
}

// ReshareRotationPlan is the deterministic mapping from one committee
// topology to its rotated successor. Exactly one of the two shapes is
// populated: remove-shaped plans carry FoldAssignments, add-shaped plans
// carry WeaveGroups plus a designated CorrectionGroup whose weaver delivers
// the aggregate negative so the woven groups contribute zero.
type ReshareRotationPlan struct {
	OldParticipants int
	NewParticipants int
	// Leaver is the dropped old position on remove rotations
	// (NewParticipants+1 == OldParticipants); zero otherwise. HasLeaver
	// distinguishes a position-zero leaver from an add rotation.
	Leaver    uint8
	HasLeaver bool
	// Weaver is the joiner position on add rotations; it belongs to every
	// new group and therefore holds the only legitimate handle on the
	// aggregate correction.
	Weaver    uint8
	HasWeaver bool
	// CarryGroups hold the new-coordinates masks of groups whose component
	// moves unchanged.
	CarryGroups []RSSGroupMask
	// FoldAssignments map every source group of the leaver onto its
	// surviving target (old coordinates for Source, new for Target).
	FoldAssignments []ReshareFoldAssignment
	// WeaveGroups list the joiner groups in canonical order, the last one
	// being the CorrectionGroup.
	WeaveGroups     []RSSGroupMask
	CorrectionGroup RSSGroupMask
}

// groupMaskPositions enumerates member positions of a canonical group mask.
// The family committee never exceeds twelve members.
func groupMaskPositions(group RSSGroupMask) []uint8 {
	positions := make([]uint8, 0, 4)
	for position := uint8(0); position < 12; position++ {
		if group.Contains(position) {
			positions = append(positions, position)
		}
	}
	return positions
}

// groupMaskFromPositions assembles the canonical mask of a position list.
func groupMaskFromPositions(positions []uint8) (RSSGroupMask, error) {
	var mask uint16
	for _, position := range positions {
		if position >= 12 {
			return 0, fmt.Errorf("%w: position %d outside the family", ErrReshareRotationInput, position)
		}
		if mask&(uint16(1)<<position) != 0 {
			return 0, fmt.Errorf("%w: position %d repeated", ErrReshareRotationInput, position)
		}
		mask |= uint16(1) << position
	}
	group := RSSGroupMask(mask)
	if err := group.Validate(); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrReshareRotationInput, err)
	}
	return group, nil
}

// shiftedMask renumerates an old-coordinates group onto the new committee
// after a leaver: every position strictly above the leaver shifts down one.
func shiftedMask(group RSSGroupMask, leaver uint8) RSSGroupMask {
	var mask uint16
	for _, position := range groupMaskPositions(group) {
		shifted := position
		if position > leaver {
			shifted--
		}
		mask |= uint16(1) << shifted
	}
	return RSSGroupMask(mask)
}

// unshiftedMask maps a new-coordinates mask back to old coordinates when the
// leaver was dropped.
func unshiftedMask(group RSSGroupMask, leaver uint8) RSSGroupMask {
	var mask uint16
	for _, position := range groupMaskPositions(group) {
		restored := position
		if position >= leaver {
			restored++
		}
		mask |= uint16(1) << restored
	}
	return RSSGroupMask(mask)
}

// PlanReshareRotation derives the deterministic rotation plan for a
// one-position membership delta between two family committees. Add
// rotations list the joiner position, which must be the appended last
// position of the new committee (the roster sampler's order); remove
// rotations list the leaver position. Everything else fails closed,
// including same-shape swaps (compose remove and add instead).
func PlanReshareRotation(oldParticipants, newParticipants int, changed ...uint8) (*ReshareRotationPlan, error) {
	if oldParticipants != 6 && oldParticipants != 7 {
		// The pure core is pinned to the signed family rows; wider sizes
		// land with the sampler work in a later stage.
		return nil, fmt.Errorf("%w: old committee size %d", ErrReshareRotationInput, oldParticipants)
	}
	if newParticipants != 6 && newParticipants != 7 {
		return nil, fmt.Errorf("%w: new committee size %d", ErrReshareRotationInput, newParticipants)
	}
	if len(changed) != 1 {
		return nil, fmt.Errorf("%w: exactly one position must change, got %d", ErrReshareRotationInput, len(changed))
	}
	position := changed[0]
	plan := &ReshareRotationPlan{
		OldParticipants: oldParticipants,
		NewParticipants: newParticipants,
	}
	oldGroups, err := CanonicalRSSGroupsFor(oldParticipants)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReshareRotationInput, err)
	}
	switch {
	case newParticipants == oldParticipants+1:
		joiner := uint8(newParticipants - 1)
		if position != joiner {
			return nil, fmt.Errorf("%w: joiner must occupy the appended position %d, got %d", ErrReshareRotationInput, joiner, position)
		}
		plan.Weaver = joiner
		plan.HasWeaver = true
		newGroups, err := CanonicalRSSGroupsFor(newParticipants)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrReshareRotationInput, err)
		}
		for _, group := range oldGroups {
			if group.Contains(joiner) {
				return nil, fmt.Errorf("%w: old topology leaks the joiner position", ErrReshareRotationInput)
			}
			plan.CarryGroups = append(plan.CarryGroups, group)
		}
		for _, group := range newGroups {
			if group.Contains(joiner) {
				plan.WeaveGroups = append(plan.WeaveGroups, group)
			}
		}
		if len(plan.WeaveGroups) == 0 {
			return nil, fmt.Errorf("%w: no joiner groups", ErrReshareRotationInput)
		}
		plan.CorrectionGroup = plan.WeaveGroups[len(plan.WeaveGroups)-1]
	case newParticipants == oldParticipants-1:
		if position >= uint8(oldParticipants) {
			return nil, fmt.Errorf("%w: leaver %d outside the old committee", ErrReshareRotationInput, position)
		}
		plan.Leaver = position
		plan.HasLeaver = true
		groupSize := GroupSizeForParticipants(oldParticipants)
		assignedTargets := make(map[RSSGroupMask]struct{})
		for _, group := range oldGroups {
			if !group.Contains(position) {
				plan.CarryGroups = append(plan.CarryGroups, shiftedMask(group, position))
				continue
			}
			// Fold every leaver group into a surviving target whose third
			// member is the smallest remaining old position outside the
			// other two members; those other two anchor the fold.
			members := groupMaskPositions(group)
			if len(members) != groupSize {
				return nil, fmt.Errorf("%w: group %06b width %d", ErrReshareRotationInput, uint16(group), len(members))
			}
			survivors := make([]uint8, 0, groupSize-1)
			for _, member := range members {
				if member != position {
					survivors = append(survivors, member)
				}
			}
			if len(survivors) != groupSize-1 {
				return nil, fmt.Errorf("%w: leaver group %06b width", ErrReshareRotationInput, uint16(group))
			}
			targetPositions := append([]uint8{}, survivors...)
			assigned := false
			for candidate := uint8(0); candidate < uint8(oldParticipants); candidate++ {
				if candidate == position || group.Contains(candidate) {
					continue
				}
				targetOld, err := groupMaskFromPositions(append(append([]uint8{}, targetPositions...), candidate))
				if err != nil {
					return nil, err
				}
				target := shiftedMask(targetOld, position)
				if _, taken := assignedTargets[target]; taken {
					continue
				}
				assignedTargets[target] = struct{}{}
				plan.FoldAssignments = append(plan.FoldAssignments, ReshareFoldAssignment{
					Source:         group,
					Target:         target,
					AnchorPosition: survivors[0],
				})
				assigned = true
				break
			}
			if !assigned {
				// Injection failure is structural, not adversarial: fall back
				// to the fresh-key path exactly like a multi-position delta.
				return nil, fmt.Errorf("%w: no injectable fold target for group %06b", ErrReshareRotationInput, uint16(group))
			}
		}
	default:
		return nil, fmt.Errorf("%w: committee size step %d->%d", ErrReshareRotationInput, oldParticipants, newParticipants)
	}
	return plan, nil
}

// Apply maps an old-committee component set into the new topology under
// this plan. Remove rotations ignore the weave input; add rotations require
// one freshly derived component per weave group and overwrite the
// correction group with the aggregate negative of the others. The returned
// map covers exactly the new canonical groups; the caller re-establishes
// key invariance by comparing public-contribution sums.
func (plan *ReshareRotationPlan) Apply(
	oldComponents map[RSSGroupMask]RSSComponent,
	weave map[RSSGroupMask]RSSComponent,
) (map[RSSGroupMask]RSSComponent, error) {
	if plan == nil {
		return nil, fmt.Errorf("%w: nil plan", ErrReshareRotationInput)
	}
	switch {
	case plan.HasWeaver:
		out := make(map[RSSGroupMask]RSSComponent, len(plan.CarryGroups)+len(plan.WeaveGroups))
		for _, group := range plan.CarryGroups {
			component, ok := oldComponents[group]
			if !ok {
				return nil, fmt.Errorf("%w: carry group %06b absent", ErrReshareComponentMissing, uint16(group))
			}
			out[group] = component
		}
		var aggregation RSSComponent
		accumulated := false
		for _, group := range plan.WeaveGroups {
			fresh, ok := weave[group]
			if !ok {
				return nil, fmt.Errorf("%w: weave group %06b has no fresh component", ErrReshareComponentMissing, uint16(group))
			}
			if group == plan.CorrectionGroup {
				continue
			}
			out[group] = fresh
			if accumulated {
				aggregation = addRSSComponent(aggregation, fresh)
			} else {
				aggregation = fresh
				accumulated = true
			}
		}
		// The correction group's component is the additive inverse of the
		// other joiner groups' sum, so the woven family contributes zero.
		var zero RSSComponent
		out[plan.CorrectionGroup] = subRSSComponent(zero, aggregation)
		return out, nil
	case plan.HasLeaver:
		out := make(map[RSSGroupMask]RSSComponent, len(plan.CarryGroups))
		for _, group := range plan.CarryGroups {
			oldMask := unshiftedMask(group, plan.Leaver)
			component, ok := oldComponents[oldMask]
			if !ok {
				return nil, fmt.Errorf("%w: carry group %06b absent", ErrReshareComponentMissing, uint16(oldMask))
			}
			out[group] = component
		}
		deltas := make(map[RSSGroupMask]RSSComponent)
		for _, fold := range plan.FoldAssignments {
			source, ok := oldComponents[fold.Source]
			if !ok {
				return nil, fmt.Errorf("%w: fold source %06b absent", ErrReshareComponentMissing, uint16(fold.Source))
			}
			deltas[fold.Target] = addRSSComponent(deltas[fold.Target], source)
		}
		for target, delta := range deltas {
			base, ok := out[target]
			if !ok {
				return nil, fmt.Errorf("%w: fold target %06b is not a carry group", ErrReshareComponentMissing, uint16(target))
			}
			out[target] = addRSSComponent(base, delta)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: plan has no shape", ErrReshareRotationInput)
	}
}

// PlanReshareRotationForCommittees lifts a pair of participant-ID committees
// (versions anchored by the caller) to the pure position-level rotation
// plan. Roster order defines positions: on remove rotations the leaver's
// position is located and later positions shift down; on add rotations the
// joiner must be the appended tail of the new list, because anything else
// would renumber old members and break carry invariance. Same-shape
// reshuffles and multi-member deltas fail closed so the caller can fall
// back to the fresh-key DKG path.
func PlanReshareRotationForCommittees(oldCommittee, next protocol.CommitteeID) (*ReshareRotationPlan, error) {
	if len(oldCommittee.Participants) == 0 || len(next.Participants) == 0 {
		return nil, fmt.Errorf("%w: empty committee", ErrReshareRotationInput)
	}
	oldSize, newSize := len(oldCommittee.Participants), len(next.Participants)
	if next.Threshold != uint32(ThresholdForParticipants(newSize)) ||
		oldCommittee.Threshold != uint32(ThresholdForParticipants(oldSize)) {
		return nil, fmt.Errorf("%w: committee threshold off the family rule", ErrReshareRotationInput)
	}
	switch {
	case newSize == oldSize-1:
		nextSet := make(map[uint32]bool, newSize)
		for _, participant := range next.Participants {
			nextSet[participant] = true
		}
		leavers := make([]uint8, 0, oldSize-newSize)
		for index, participant := range oldCommittee.Participants {
			if !nextSet[participant] {
				leavers = append(leavers, uint8(index))
			}
		}
		if len(leavers) != 1 {
			return nil, fmt.Errorf("%w: remove rotation with %d leavers", ErrReshareRotationInput, len(leavers))
		}
		leaver := leavers[0]
		// Verify the relative order is untouched apart from the leaver.
		for newPosition, participant := range next.Participants {
			oldPosition := newPosition
			if newPosition >= int(leaver) {
				oldPosition++
			}
			if oldCommittee.Participants[oldPosition] != participant {
				return nil, fmt.Errorf("%w: remove rotation reorders position %d", ErrReshareRotationInput, newPosition)
			}
		}
		return PlanReshareRotation(oldSize, newSize, leaver)
	case newSize == oldSize+1:
		for position, participant := range oldCommittee.Participants {
			if next.Participants[position] != participant {
				return nil, fmt.Errorf("%w: add rotation reorders position %d", ErrReshareRotationInput, position)
			}
		}
		oldSet := make(map[uint32]bool, oldSize)
		for _, participant := range oldCommittee.Participants {
			oldSet[participant] = true
		}
		if oldSet[next.Participants[newSize-1]] {
			return nil, fmt.Errorf("%w: appended joiner %d already a member", ErrReshareRotationInput, next.Participants[newSize-1])
		}
		return PlanReshareRotation(oldSize, newSize, uint8(newSize-1))
	default:
		return nil, fmt.Errorf("%w: committee size step %d->%d", ErrReshareRotationInput, oldSize, newSize)
	}
}

// ReshareFoldDelta is the per-anchor delivery unit of a remove rotation:
// the anchor's own copy of one leaver-group component, addressed to every
// member of the target group. The delta is publicly verifiable — recipients
// recompute the source group's public contribution from the component and
// compare it against the retired certificate's transcript — and it reveals
// nothing beyond what the target members hold after the fold, since the
// source and target share at least two members.
type ReshareFoldDelta struct {
	Source    RSSGroupMask
	Target    RSSGroupMask
	Component RSSComponent
}

// FoldDeltasFor returns the fold deltas the anchor position is authority
// over. The anchor works in old coordinates and must hold every source it
// anchors; a missing source fails closed so a rotated share never
// silently drops an old group's contribution.
func (plan *ReshareRotationPlan) FoldDeltasFor(
	anchorPosition uint8,
	localComponents map[RSSGroupMask]RSSComponent,
) ([]ReshareFoldDelta, error) {
	if plan == nil || !plan.HasLeaver {
		return nil, fmt.Errorf("%w: fold delivery on a non-remove plan", ErrReshareRotationInput)
	}
	var deltas []ReshareFoldDelta
	for _, fold := range plan.FoldAssignments {
		if fold.AnchorPosition != anchorPosition {
			continue
		}
		source, ok := localComponents[fold.Source]
		if !ok {
			return nil, fmt.Errorf("%w: anchor %d does not hold fold source %06b", ErrReshareComponentMissing, anchorPosition, uint16(fold.Source))
		}
		deltas = append(deltas, ReshareFoldDelta{
			Source:    fold.Source,
			Target:    fold.Target,
			Component: source,
		})
	}
	return deltas, nil
}

// AssembleLocalComponents maps one continuing position's old-component set
// into the new committee's coordinates: carry groups are remapped, and the
// fold deltas addressed at any target group the position belongs to are
// summed in. The result is exactly the set of new-coordinates groups the
// position must hold — anything else indicates wrong delivery or corruption
// and fails closed.
func (plan *ReshareRotationPlan) AssembleLocalComponents(
	newPosition uint8,
	localComponents map[RSSGroupMask]RSSComponent,
	deltas []ReshareFoldDelta,
) (map[RSSGroupMask]RSSComponent, error) {
	if plan == nil || !plan.HasLeaver {
		return nil, fmt.Errorf("%w: local assembly on a non-remove plan", ErrReshareRotationInput)
	}
	if newPosition >= uint8(plan.NewParticipants) {
		return nil, fmt.Errorf("%w: position %d outside the new committee", ErrReshareRotationInput, newPosition)
	}
	out := make(map[RSSGroupMask]RSSComponent, len(plan.CarryGroups))
	for _, group := range plan.CarryGroups {
		if !group.Contains(newPosition) {
			continue
		}
		oldMask := unshiftedMask(group, plan.Leaver)
		component, ok := localComponents[oldMask]
		if !ok {
			return nil, fmt.Errorf("%w: carry group %06b absent from position %d", ErrReshareComponentMissing, uint16(oldMask), newPosition)
		}
		component.GroupMask = group
		out[group] = component
	}
	seen := make(map[RSSGroupMask]bool)
	for _, delta := range deltas {
		if !delta.Target.Contains(newPosition) {
			return nil, fmt.Errorf("%w: delta of group %06b delivered to a non-member", ErrReshareRotationInput, uint16(delta.Target))
		}
		if seen[delta.Target] {
			continue
		}
		seen[delta.Target] = true
		base, ok := out[delta.Target]
		if !ok {
			return nil, fmt.Errorf("%w: fold target %06b is not carried by position %d", ErrReshareComponentMissing, uint16(delta.Target), newPosition)
		}
		folded := addRSSComponent(base, delta.Component)
		// The composed component records the mix of both digests so the
		// contribution identity that appears in any rotated transcript is
		// unique to this rotation step.
		folded.ContributionDigest = sha3.Sum256(append(append([]byte("QAU-TDILITHIUM3-V1-RESHARE-FOLD"), base.ContributionDigest[:]...), delta.Component.ContributionDigest[:]...))
		out[delta.Target] = folded
	}
	// Every fold targeting a group this position holds must have arrived.
	for _, fold := range plan.FoldAssignments {
		if fold.Target.Contains(newPosition) && !seen[fold.Target] {
			return nil, fmt.Errorf("%w: fold delta for %06b missing at position %d", ErrReshareComponentMissing, uint16(fold.Target), newPosition)
		}
	}
	return out, nil
}

// WeaverCorrection computes the additive inverse of the joiner groups'
// aggregate outside the correction group. The weaver is a member of every
// joiner group, so it is the only position able to compute it — and it
// already knows every component that feeds the sum.
func (plan *ReshareRotationPlan) WeaverCorrection(
	weaveComponents map[RSSGroupMask]RSSComponent,
) (RSSComponent, error) {
	if plan == nil || !plan.HasWeaver {
		return RSSComponent{}, fmt.Errorf("%w: weaver correction on a non-add plan", ErrReshareRotationInput)
	}
	var aggregation RSSComponent
	accumulated := false
	for _, group := range plan.WeaveGroups {
		if group == plan.CorrectionGroup {
			continue
		}
		fresh, ok := weaveComponents[group]
		if !ok {
			return RSSComponent{}, fmt.Errorf("%w: weave group %06b has no fresh component", ErrReshareComponentMissing, uint16(group))
		}
		if accumulated {
			aggregation = addRSSComponent(aggregation, fresh)
		} else {
			aggregation = fresh
			accumulated = true
		}
	}
	var zero RSSComponent
	return subRSSComponent(zero, aggregation), nil
}

// ReshareWeaveDelta is the weaver's signed replacement component for the
// correction group of an add rotation. Members of the correction group
// adopt it instead of their freshly derived value, having verified the
// public relation sum(t_weave) == 0 against the family transcript.
type ReshareWeaveDelta struct {
	CorrectionGroup RSSGroupMask
	Component       RSSComponent
}

// WeaverDelta wraps WeaverCorrection in the wire-shape envelope members of
// the correction group consume.
func (plan *ReshareRotationPlan) WeaverDelta(
	weaveComponents map[RSSGroupMask]RSSComponent,
) (ReshareWeaveDelta, error) {
	correction, err := plan.WeaverCorrection(weaveComponents)
	if err != nil {
		return ReshareWeaveDelta{}, err
	}
	correction.GroupMask = plan.CorrectionGroup
	correction.DealerPosition = plan.Weaver
	if correction.ContributionDigest == ([32]byte{}) {
		// Bind the correction's contribution identity to the full weave family
		// canonical order so every member agrees on it byte for byte.
		mixed := []byte("QAU-TDILITHIUM3-V1-RESHARE-CORRECTION")
		mixed = append(mixed, byte(uint16(plan.CorrectionGroup)>>8), byte(uint16(plan.CorrectionGroup)))
		for _, weaveGroup := range plan.WeaveGroups {
			if weaveGroup == plan.CorrectionGroup {
				continue
			}
			mixed = append(mixed, byte(uint16(weaveGroup)>>8), byte(uint16(weaveGroup)))
			digest := weaveComponents[weaveGroup].ContributionDigest
			mixed = append(mixed, digest[:]...)
		}
		correction.ContributionDigest = sha3.Sum256(mixed)
	}
	return ReshareWeaveDelta{CorrectionGroup: plan.CorrectionGroup, Component: correction}, nil
}

// AssembleAddLocalComponents maps one new-committee position's materials
// into the add-rotated component set: continuing members carry their old
// groups and adopt the fresh/ woven components of joiner groups they
// belong to; the joiner (which carries nothing) adopts every joiner group.
// Members of the correction group must receive the weaver delta and the
// adopted correction must equal the weaver's own recomputation — any
// divergence (forged or stale delta) fails closed.
func (plan *ReshareRotationPlan) AssembleAddLocalComponents(
	newPosition uint8,
	carried map[RSSGroupMask]RSSComponent,
	weave map[RSSGroupMask]RSSComponent,
	delta *ReshareWeaveDelta,
) (map[RSSGroupMask]RSSComponent, error) {
	if plan == nil || !plan.HasWeaver {
		return nil, fmt.Errorf("%w: add assembly on a non-add plan", ErrReshareRotationInput)
	}
	if newPosition >= uint8(plan.NewParticipants) {
		return nil, fmt.Errorf("%w: position %d outside the new committee", ErrReshareRotationInput, newPosition)
	}
	needsOfSelf := plan.CorrectionGroup.Contains(newPosition)
	if needsOfSelf && (delta == nil || delta.CorrectionGroup != plan.CorrectionGroup) {
		return nil, fmt.Errorf("%w: weaver delta names the wrong correction group %06b", ErrReshareRotationInput, uint16(deltaOrZero(delta)))
	}
	out := make(map[RSSGroupMask]RSSComponent, len(plan.CarryGroups)+len(plan.WeaveGroups))
	for _, group := range plan.CarryGroups {
		if !group.Contains(newPosition) {
			continue
		}
		component, ok := carried[group]
		if !ok {
			return nil, fmt.Errorf("%w: carry group %06b absent from position %d", ErrReshareComponentMissing, uint16(group), newPosition)
		}
		out[group] = component
	}
	for _, group := range plan.WeaveGroups {
		if !group.Contains(newPosition) {
			continue
		}
		if group == plan.CorrectionGroup {
			adopted := delta.Component
			adopted.GroupMask = group
			out[group] = adopted
			continue
		}
		fresh, ok := weave[group]
		if !ok {
			return nil, fmt.Errorf("%w: weave group %06b has no fresh component at position %d", ErrReshareComponentMissing, uint16(group), newPosition)
		}
		out[group] = fresh
	}
	// Forge detection: a caller holding the full joiner-group set (the
	// weaver itself and offline verifiers) recomputes the correction exactly
	// and refuses any divergence; members who hold only their own groups
	// defer the relation check to the family public-key comparison their
	// activation certificate performs.
	if needsOfSelf && len(weave) == len(plan.WeaveGroups) {
		want, err := plan.WeaverDelta(weave)
		if err != nil {
			return nil, err
		}
		if delta.Component != want.Component {
			return nil, fmt.Errorf("%w: weaver delta mismatch for group %06b", ErrReshareRotationInput, uint16(plan.CorrectionGroup))
		}
	}
	return out, nil
}

func deltaOrZero(delta *ReshareWeaveDelta) RSSGroupMask {
	if delta == nil {
		return 0
	}
	return delta.CorrectionGroup
}

// ReshareSessionNonceDomain namespaces the reshare session nonce so a
// same-key ceremony can never collide with a fresh-key DKG session on the
// same chain inputs.
const ReshareSessionNonceDomain = "QAU-TDILITHIUM3-V1-RESHARE-SESSION"

// ReshareSessionNonce binds the reshare session to the chain, the previous
// committee, the previous group public key, and the rotated committee. It
// is deterministic and needs no extra consensus round; every ceremony side
// (anchor, weaver, recipients) recomputes identically.
func ReshareSessionNonce(
	chainID uint64,
	genesis [32]byte,
	previousCommitteeDigest [32]byte,
	previousPublicKey []byte,
	committeeDigest [32]byte,
	nonce [32]byte,
) [32]byte {
	var joined []byte
	for _, part := range [][]byte{
		[]byte(ReshareSessionNonceDomain),
		uint64Bytes(chainID),
		genesis[:],
		previousCommitteeDigest[:],
		previousPublicKey,
		committeeDigest[:],
		nonce[:],
	} {
		joined = append(joined, part...)
	}
	return sha3.Sum256(joined)
}

func uint64Bytes(value uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	return out[:]
}

// ResharedShare builds the rotated LocalShare for one continuing member of
// a remove rotation from its old share and the fold deltas addressed to its
// new topology. The share keeps the same key identity (generation and group
// public key are untouched), bumps the committee and the activation epoch,
// and carries exactly the new-coordinates group set the resulting
// validation requires — component masks are renumbered and the composition
// of every target group is the carried base plus the anchor's fold delta.
func (plan *ReshareRotationPlan) ResharedShare(
	old *LocalShare,
	next protocol.CommitteeID,
	transcriptDigest [32]byte,
	deltas []ReshareFoldDelta,
) (*LocalShare, error) {
	if plan == nil || !plan.HasLeaver {
		return nil, fmt.Errorf("%w: reshared share requires a remove plan", ErrReshareRotationInput)
	}
	if err := old.Validate(); err != nil {
		return nil, fmt.Errorf("%w: old share: %v", ErrReshareRotationInput, err)
	}
	if len(old.Committee.Participants) != plan.OldParticipants {
		return nil, fmt.Errorf("%w: old share committee size %d, plan expects %d", ErrReshareRotationInput, len(old.Committee.Participants), plan.OldParticipants)
	}
	if len(next.Participants) != plan.NewParticipants {
		return nil, fmt.Errorf("%w: new committee size %d, plan expects %d", ErrReshareRotationInput, len(next.Participants), plan.NewParticipants)
	}
	oldPosition, found := committeePosition(old.Committee, old.ParticipantID)
	if !found {
		return nil, fmt.Errorf("%w: participant %d left the committee", ErrReshareRotationInput, old.ParticipantID)
	}
	if oldPosition == plan.Leaver {
		return nil, fmt.Errorf("%w: the leaver cannot carry a reshared share", ErrReshareRotationInput)
	}
	newPosition := oldPosition
	if oldPosition > plan.Leaver {
		newPosition--
	}
	if next.Participants[newPosition] != old.ParticipantID {
		return nil, fmt.Errorf("%w: participant %d lost its position", ErrReshareRotationInput, old.ParticipantID)
	}
	local := make(map[RSSGroupMask]RSSComponent, len(old.Components))
	for _, component := range old.Components {
		local[component.GroupMask] = component
	}
	assembled, err := plan.AssembleLocalComponents(newPosition, local, deltas)
	if err != nil {
		return nil, err
	}
	expected, err := GroupsForPositionN(newPosition, plan.NewParticipants)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReshareRotationInput, err)
	}
	components := make([]RSSComponent, 0, len(expected))
	for _, group := range expected {
		component, ok := assembled[group]
		if !ok {
			return nil, fmt.Errorf("%w: owned group %06b missing at new position %d", ErrReshareComponentMissing, uint16(group), newPosition)
		}
		if int(component.DealerPosition) >= plan.OldParticipants {
			return nil, fmt.Errorf("%w: dealer %d outside the old committee", ErrReshareRotationInput, component.DealerPosition)
		}
		if component.DealerPosition > plan.Leaver {
			component.DealerPosition--
		}
		if !group.Contains(component.DealerPosition) {
			return nil, fmt.Errorf("%w: dealer %d not in group %06b after remap", ErrReshareRotationInput, component.DealerPosition, uint16(group))
		}
		components = append(components, component)
	}
	return &LocalShare{
		Protocol:            old.Protocol,
		Key:                 old.Key.Clone(),
		Committee:           next.Clone(),
		ParticipantID:       old.ParticipantID,
		ParticipantPosition: newPosition,
		ActivationEpoch:     old.ActivationEpoch + 1,
		TranscriptDigest:    transcriptDigest,
		Rho:                 old.Rho,
		Components:          components,
	}, nil
}

// ResharedAddedShare builds the rotated LocalShare for one member of an add
// rotation. Continuing members keep their carried groups and adopt the
// freshly derived components of every joiner group they belong to; the
// correction group's members adopt the weaver's signed delta instead of the
// fresh value; the joiner has no carry material. The key identity fields
// (algorithm, generation, public key, rho, activation-epoch base) are
// supplied out of band by the rotation request so the joiner's envelope is
// provably identical to every continuing member's.
func (plan *ReshareRotationPlan) ResharedAddedShare(
	old *LocalShare, // nil for the joiner
	next protocol.CommitteeID,
	previousKey protocol.ThresholdKeyID,
	rho [32]byte,
	activationEpoch uint64,
	transcriptDigest [32]byte,
	weave map[RSSGroupMask]RSSComponent,
	delta *ReshareWeaveDelta,
) (*LocalShare, error) {
	if plan == nil || !plan.HasWeaver {
		return nil, fmt.Errorf("%w: added share requires an add plan", ErrReshareRotationInput)
	}
	if len(next.Participants) != plan.NewParticipants {
		return nil, fmt.Errorf("%w: new committee size %d, plan expects %d", ErrReshareRotationInput, len(next.Participants), plan.NewParticipants)
	}
	needsDelta := false
	// The correction group's members (and the weaver) must hold the delta;
	// everyone else ignores it entirely.
	probePosition := uint8(plan.NewParticipants)
	if old != nil {
		p, found := committeePosition(old.Committee, old.ParticipantID)
		if found {
			probePosition = p
		}
	} else {
		probePosition = plan.Weaver
	}
	if probePosition < uint8(plan.NewParticipants) && plan.CorrectionGroup.Contains(probePosition) {
		needsDelta = true
	}
	if needsDelta && (delta == nil || delta.CorrectionGroup != plan.CorrectionGroup) {
		return nil, fmt.Errorf("%w: weaver delta names %06b, expected %06b", ErrReshareRotationInput, uint16(deltaOrZero(delta)), uint16(plan.CorrectionGroup))
	}
	if old == nil && (len(previousKey.PublicKey) == 0) {
		return nil, fmt.Errorf("%w: the joiner must receive the previous key identity", ErrReshareRotationInput)
	}

	var position uint8
	var participantID uint32
	var carried map[RSSGroupMask]RSSComponent
	var epoch uint64 = activationEpoch
	if old != nil {
		if err := old.Validate(); err != nil {
			return nil, fmt.Errorf("%w: old share: %v", ErrReshareRotationInput, err)
		}
		if len(old.Committee.Participants) != plan.OldParticipants {
			return nil, fmt.Errorf("%w: old share committee size %d, plan expects %d", ErrReshareRotationInput, len(old.Committee.Participants), plan.OldParticipants)
		}
		p, found := committeePosition(old.Committee, old.ParticipantID)
		if !found {
			return nil, fmt.Errorf("%w: participant %d not a continuing member", ErrReshareRotationInput, old.ParticipantID)
		}
		if p == plan.Weaver {
			return nil, fmt.Errorf("%w: the joiner cannot carry old share material", ErrReshareRotationInput)
		}
		position, participantID = p, old.ParticipantID
		epoch = old.ActivationEpoch + 1
		previousKey = old.Key.Clone()
		rho = old.Rho
		carried = make(map[RSSGroupMask]RSSComponent, len(old.Components))
		for _, component := range old.Components {
			carried[component.GroupMask] = component
		}
	} else {
		position = plan.Weaver
		participantID = next.Participants[position]
	}
	if next.Participants[position] != participantID {
		return nil, fmt.Errorf("%w: participant %d lost its position in the new committee", ErrReshareRotationInput, participantID)
	}

	assembled, err := plan.AssembleAddLocalComponents(position, carried, weave, delta)
	if err != nil {
		return nil, err
	}
	expected, err := GroupsForPositionN(position, plan.NewParticipants)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReshareRotationInput, err)
	}
	components := make([]RSSComponent, 0, len(expected))
	for _, group := range expected {
		component, ok := assembled[group]
		if !ok {
			return nil, fmt.Errorf("%w: owned group %06b missing at new position %d", ErrReshareComponentMissing, uint16(group), position)
		}
		components = append(components, component)
	}
	return &LocalShare{
		Protocol:            protocol.ThresholdProtocolDilithium3V1,
		Key:                 previousKey,
		Committee:           next.Clone(),
		ParticipantID:       participantID,
		ParticipantPosition: position,
		ActivationEpoch:     epoch,
		TranscriptDigest:    transcriptDigest,
		Rho:                 rho,
		Components:          components,
	}, nil
}

// addRSSComponent adds two components coefficient-wise modulo q.
func addRSSComponent(left, right RSSComponent) RSSComponent {
	result := left
	for index := range result.S1 {
		result.S1[index] = Add(result.S1[index], right.S1[index])
	}
	for index := range result.S2 {
		result.S2[index] = Add(result.S2[index], right.S2[index])
	}
	result.Multiplicity = uint32(componentMultiplicity(left) + componentMultiplicity(right))
	return result
}

// subRSSComponent computes left - right component-wise modulo q; with a zero
// left side it yields the additive inverse of right. The multiplicity of a
// difference is the sum it would have been as an addition: every underlying
// base contribution still flows through the signer's partial norm bound.
func subRSSComponent(left, right RSSComponent) RSSComponent {
	result := left
	for index := range result.S1 {
		result.S1[index] = Sub(result.S1[index], right.S1[index])
	}
	for index := range result.S2 {
		result.S2[index] = Sub(result.S2[index], right.S2[index])
	}
	if left == (RSSComponent{}) {
		result.Multiplicity = uint32(componentMultiplicity(right))
	} else {
		result.Multiplicity = uint32(componentMultiplicity(left) + componentMultiplicity(right))
	}
	return result
}

// ---------------------------------------------------------------------------
// Wire payloads (R77 section 4): one private delta message carries either a
// fold assignment's source component (remove shape) or the weaver's
// correction component (add shape). The message is self-contained: session
// digest pins it to one rotation, the new-committee digest pins the target
// topology, and the component itself travels so the receiving member can
// both fold it and re-derive its contribution-digest mixing deterministically.
// ---------------------------------------------------------------------------

const (
	reshareDeltaWireMagic      = "QTD3RDLT"
	ReshareDeltaKindFold       = uint8(1)
	ReshareDeltaKindCorrection = uint8(2)
)

// ReshareDeltaWire is the on-the-wire delta body inside the versioned
// threshold envelope. AnchorPosition and RecipientPosition use NEW-committee
// coordinates: anchors and recipients are survivors of the removal (or
// members of the grown committee), so their new positions are always
// defined; the leaver's old positions appear only inside the group masks.
type ReshareDeltaWire struct {
	SessionDigest    [32]byte
	CommitteeDigest  [32]byte
	Kind             uint8
	SourceGroup      RSSGroupMask
	TargetGroup      RSSGroupMask
	AnchorPosition   uint8
	RecipientPosition uint8
	Component        RSSComponent
}

// MarshalBinary produces the canonical fixed layout.
func (message ReshareDeltaWire) MarshalBinary() ([]byte, error) {
	if message.Kind != ReshareDeltaKindFold && message.Kind != ReshareDeltaKindCorrection {
		return nil, fmt.Errorf("%w: reshare delta kind %d", ErrReshareRotationInput, message.Kind)
	}
	if message.Component.Multiplicity == 0 {
		return nil, fmt.Errorf("%w: reshare delta component has zero multiplicity", ErrReshareRotationInput)
	}
	encoded := make([]byte, 0, 8+32+32+1+2+2+1+1+32+4+(L+K)*PolyEncodedSize)
	encoded = append(encoded, reshareDeltaWireMagic...)
	encoded = append(encoded, message.SessionDigest[:]...)
	encoded = append(encoded, message.CommitteeDigest[:]...)
	encoded = append(encoded, message.Kind)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(message.SourceGroup))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(message.TargetGroup))
	encoded = append(encoded, message.AnchorPosition)
	encoded = append(encoded, message.RecipientPosition)
	encoded = append(encoded, message.Component.ContributionDigest[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(componentMultiplicity(message.Component)))
	encoded, err := appendVectorL(encoded, message.Component.S1)
	if err != nil {
		return nil, err
	}
	return appendVectorK(encoded, message.Component.S2)
}

// UnmarshalReshareDeltaWire decodes the fixed layout, checking the kind and
// all length boundaries before any secret material is touched.
func UnmarshalReshareDeltaWire(encoded []byte) (ReshareDeltaWire, error) {
	var message ReshareDeltaWire
	if len(encoded) < 8 || string(encoded[:8]) != reshareDeltaWireMagic {
		return message, fmt.Errorf("%w: reshare delta magic", ErrReshareRotationInput)
	}
	offset := 8
	copy(message.SessionDigest[:], encoded[offset:offset+32])
	offset += 32
	copy(message.CommitteeDigest[:], encoded[offset:offset+32])
	offset += 32
	message.Kind = encoded[offset]
	offset++
	if message.Kind != ReshareDeltaKindFold && message.Kind != ReshareDeltaKindCorrection {
		return message, fmt.Errorf("%w: reshare delta kind %d", ErrReshareRotationInput, message.Kind)
	}
	message.SourceGroup = RSSGroupMask(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	message.TargetGroup = RSSGroupMask(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	message.AnchorPosition = encoded[offset]
	offset++
	message.RecipientPosition = encoded[offset]
	offset++
	copy(message.Component.ContributionDigest[:], encoded[offset:offset+32])
	offset += 32
	message.Component.Multiplicity = binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	if message.Component.Multiplicity == 0 {
		return message, fmt.Errorf("%w: reshare delta component has zero multiplicity", ErrReshareRotationInput)
	}
	var err error
	message.Component.S1, offset, err = decodeVectorL(encoded, offset)
	if err != nil {
		return message, err
	}
	message.Component.S2, offset, err = decodeVectorK(encoded, offset)
	if err != nil {
		return message, err
	}
	if offset != len(encoded) {
		return message, fmt.Errorf("%w: trailing bytes in reshare delta", ErrReshareRotationInput)
	}
	message.Component.GroupMask = message.SourceGroup
	if message.Kind == ReshareDeltaKindCorrection {
		message.Component.GroupMask = message.TargetGroup
	}
	return message, nil
}

// AddVectorL/AddVectorK are the exported modulo-q vector additions the
// reshare ceremony drivers outside this package need for transcript checks.
func AddVectorL(left, right VectorL) VectorL  { return addVectorL(left, right) }
func AddVectorK(left, right VectorK) VectorK  { return addVectorK(left, right) }

// addVectorL adds two module vectors coefficient-wise modulo q.
func addVectorL(left, right VectorL) VectorL {
	var result VectorL
	for index := range result {
		result[index] = Add(left[index], right[index])
	}
	return result
}

// addVectorK adds two module vectors coefficient-wise modulo q.
func addVectorK(left, right VectorK) VectorK {
	var result VectorK
	for index := range result {
		result[index] = Add(left[index], right[index])
	}
	return result
}
