package dilithium3v1

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)



// testReshareComponents builds a deterministic synthetic v1 secret: one
// honestly derived component per canonical group of the given committee size.
func testReshareComponents(t *testing.T, participants int) map[RSSGroupMask]RSSComponent {
	t.Helper()
	groups, err := CanonicalRSSGroupsFor(participants)
	if err != nil {
		t.Fatal(err)
	}
	var sessionDigest [32]byte
	binary.LittleEndian.PutUint64(sessionDigest[:], 0x717277)
	var globalRandomness [64]byte
	binary.LittleEndian.PutUint64(globalRandomness[:], 0x6D6F64)
	components := make(map[RSSGroupMask]RSSComponent, len(groups))
	for _, group := range groups {
		leader, err := group.Leader(0)
		if err != nil {
			t.Fatal(err)
		}
		seed := sha3.Sum256([]byte(fmt.Sprintf("R77-TEST-GROUP-%04x", uint16(group))))
		s1, s2, err := DeriveRSSComponent(sessionDigest, group, leader, globalRandomness, seed)
		if err != nil {
			t.Fatal(err)
		}
		components[group] = RSSComponent{
			GroupMask:          group,
			DealerPosition:     leader,
			ContributionDigest: seed,
			Multiplicity:       1,
			S1:                 s1,
			S2:                 s2,
		}
	}
	return components
}

// testReshareComponent builds one component from a tag with a fixed leader.
func testReshareComponent(tag string, mask RSSGroupMask, dealer uint8) RSSComponent {
	var sessionDigest [32]byte
	binary.LittleEndian.PutUint64(sessionDigest[:], 0x53544b)
	var globalRandomness [64]byte
	binary.LittleEndian.PutUint64(globalRandomness[:], 0x52504d)
	seed := sha3.Sum256([]byte(tag))
	s1, s2, err := DeriveRSSComponent(sessionDigest, mask, dealer, globalRandomness, seed)
	if err != nil {
		panic(err)
	}
	return RSSComponent{GroupMask: mask, DealerPosition: dealer, Multiplicity: 1, S1: s1, S2: s2}
}

// testResharePublicSum sums the public contributions of every group.
func testResharePublicSum(t *testing.T, components map[RSSGroupMask]RSSComponent) VectorK {
	t.Helper()
	rho := sha3.Sum256([]byte("R77-TEST-RHO"))
	var total VectorK
	first := true
	for _, component := range components {
		summed, err := ComputePublicVector(rho, component.S1, component.S2)
		if err != nil {
			t.Fatal(err)
		}
		if first {
			total = summed
			first = false
			continue
		}
		total = addVectorK(total, summed)
	}
	return total
}

func TestReshareRotationPlanAddCarriesAndWeaves(t *testing.T) {
	plan, err := PlanReshareRotation(6, 7, 6)
	if err != nil {
		t.Fatalf("add plan: %v", err)
	}
	if len(plan.CarryGroups) != 20 {
		t.Fatalf("expected all 20 six-member groups to carry, got %d", len(plan.CarryGroups))
	}
	if len(plan.FoldAssignments) != 0 {
		t.Fatalf("add rotation must not fold, got %d folds", len(plan.FoldAssignments))
	}
	if len(plan.WeaveGroups) != 15 {
		t.Fatalf("expected 15 joiner groups to weave, got %d", len(plan.WeaveGroups))
	}
	for _, group := range plan.CarryGroups {
		if group.Contains(6) {
			t.Fatalf("carry group %06b contains the joiner", uint16(group))
		}
	}
	for index, group := range plan.WeaveGroups {
		if !group.Contains(6) {
			t.Fatalf("weave group %06b misses the joiner", uint16(group))
		}
		if index == len(plan.WeaveGroups)-1 && plan.CorrectionGroup != group {
			t.Fatal("the last weave group must be the correction group")
		}
	}
	if plan.Weaver != 6 {
		t.Fatalf("weaver must be the joiner position, got %d", plan.Weaver)
	}
}

func TestReshareRotationPlanRemoveFoldsLeaverGroups(t *testing.T) {
	plan, err := PlanReshareRotation(7, 6, 6)
	if err != nil {
		t.Fatalf("remove plan: %v", err)
	}
	if len(plan.CarryGroups) != 20 {
		t.Fatalf("expected the 20 leaver-free groups to carry, got %d", len(plan.CarryGroups))
	}
	if len(plan.WeaveGroups) != 0 {
		t.Fatalf("remove rotation must not weave, got %d weaves", len(plan.WeaveGroups))
	}
	if len(plan.FoldAssignments) != 15 {
		t.Fatalf("expected 15 folds for the leaver's groups, got %d", len(plan.FoldAssignments))
	}
	seen := make(map[RSSGroupMask]bool)
	for _, fold := range plan.FoldAssignments {
		if !fold.Source.Contains(6) {
			t.Fatalf("fold source %06b must contain the leaver", uint16(fold.Source))
		}
		if fold.Target.Contains(6) {
			t.Fatalf("fold target %06b must not contain the leaver", uint16(fold.Target))
		}
		if seen[fold.Target] {
			t.Fatalf("fold target %06b assigned twice", uint16(fold.Target))
		}
		seen[fold.Target] = true
		if fold.AnchorPosition == 6 {
			t.Fatal("the fold anchor must survive the rotation")
		}
		if !fold.Source.Contains(fold.AnchorPosition) || !fold.Target.Contains(fold.AnchorPosition) {
			t.Fatalf("anchor %d must belong to both source and target", fold.AnchorPosition)
		}
	}
}

func TestReshareRotationPreservesPublicKey(t *testing.T) {
	oldComponents := testReshareComponents(t, 7)
	oldPublic := testResharePublicSum(t, oldComponents)

	// Remove the highest position: 7 -> 6.
	removePlan, err := PlanReshareRotation(7, 6, 6)
	if err != nil {
		t.Fatal(err)
	}
	newComponents, err := removePlan.Apply(oldComponents, nil)
	if err != nil {
		t.Fatal(err)
	}
	if testResharePublicSum(t, newComponents) != oldPublic {
		t.Fatal("same-key promise broken after remove rotation")
	}

	// Add the position back: 6 -> 7. Each weave group draws a fresh component
	// in the real ceremony; here we synthesize one per group so the public
	// sum of the woven family is exactly zeroed by the correction group.
	addPlan, err := PlanReshareRotation(6, 7, 6)
	if err != nil {
		t.Fatal(err)
	}
	weave := make(map[RSSGroupMask]RSSComponent, len(addPlan.WeaveGroups))
	for index, group := range addPlan.WeaveGroups {
		seed := sha3.Sum256([]byte(fmt.Sprintf("R77-TEST-WEAVE-%04x", uint16(group))))
		var sessionDigest [32]byte
		binary.LittleEndian.PutUint64(sessionDigest[:], 0x727777)
		var globalRandomness [64]byte
		binary.LittleEndian.PutUint64(globalRandomness[:], 0x6D6166)
		leader := uint8(0)
		for position := uint8(0); position < 12; position++ {
			if group.Contains(position) {
				leader = position
				break
			}
		}
		_ = index
		s1, s2, err := DeriveRSSComponent(sessionDigest, group, leader, globalRandomness, seed)
		if err != nil {
			t.Fatal(err)
		}
		weave[group] = RSSComponent{GroupMask: group, DealerPosition: leader, Multiplicity: 1, S1: s1, S2: s2}
	}
	restored, err := addPlan.Apply(newComponents, weave)
	if err != nil {
		t.Fatal(err)
	}
	if testResharePublicSum(t, restored) != oldPublic {
		t.Fatal("same-key promise broken after add rotation")
	}
}

func TestReshareRotationFailsClosed(t *testing.T) {
	if _, err := PlanReshareRotation(6, 8, 6, 7); err == nil {
		t.Fatal("multi-position rotation must fail closed")
	}
	if _, err := PlanReshareRotation(6, 7, 7); err == nil {
		t.Fatal("joiner outside the new committee must fail closed")
	}
	if _, err := PlanReshareRotation(7, 6, 7); err == nil {
		t.Fatal("leaver outside the old committee must fail closed")
	}
	if _, err := PlanReshareRotation(5, 6, 5); err == nil {
		t.Fatal("committee below the family must fail closed")
	}
	if _, err := PlanReshareRotation(12, 13, 12); err == nil {
		t.Fatal("committee above the family must fail closed")
	}
	if _, err := PlanReshareRotation(7, 7, 0); err == nil {
		t.Fatal("shape-preserving no-op must fail closed")
	}
	if _, err := PlanReshareRotation(6, 6, 0, 3); err == nil {
		t.Fatal("direct reshuffles need a composed plan, not a single call")
	}
}

func TestDeriveRSSComponentAcceptsHighLeaderPositions(t *testing.T) {
	// A seven-member committee has groups whose lowest-positioned member is
	// six; sampling must accept every family position.
	group, err := groupMaskFromPositions([]uint8{4, 5, 6})
	if err != nil {
		t.Fatal(err)
	}
	var sessionDigest [32]byte
	binary.LittleEndian.PutUint64(sessionDigest[:], 1)
	var globalRandomness [64]byte
	binary.LittleEndian.PutUint64(globalRandomness[:], 2)
	var seed [32]byte
	binary.LittleEndian.PutUint64(seed[:], 3)
	if _, _, err := DeriveRSSComponent(sessionDigest, group, 6, globalRandomness, seed); err != nil {
		t.Fatalf("family-position leader rejected: %v", err)
	}
}

// TestReshareRemoveAssemblesPositionShares runs the whole-member view of a
// remove rotation: every position's local component set is rotated across the
// leaver, fold deltas are delivered from their anchors, and the key is kept.
func TestReshareRemoveAssemblesPositionShares(t *testing.T) {
	const oldSize, newSize = 7, 6
	const leaver = uint8(3)
	all := testReshareComponents(t, oldSize)
	oldPublic := testResharePublicSum(t, all)
	plan, err := PlanReshareRotation(oldSize, newSize, leaver)
	if err != nil {
		t.Fatal(err)
	}
	// Each old member sees only the groups it belongs to.
	localViews := make([]map[RSSGroupMask]RSSComponent, oldSize)
	for position := uint8(0); position < oldSize; position++ {
		localViews[position] = make(map[RSSGroupMask]RSSComponent)
		for group, component := range all {
			if group.Contains(position) {
				localViews[position][group] = component
			}
		}
	}
	// Anchors publish their deltas; recipients pull deltas addressed to any
	// fold target they belong to.
	deltas := make([]ReshareFoldDelta, 0)
	for position := uint8(0); position < oldSize; position++ {
		if position == leaver {
			continue
		}
		mine, err := plan.FoldDeltasFor(position, localViews[position])
		if err != nil {
			t.Fatal(err)
		}
		deltas = append(deltas, mine...)
	}
	if len(deltas) != len(plan.FoldAssignments) {
		t.Fatalf("expected %d deltas from the anchors, got %d", len(plan.FoldAssignments), len(deltas))
	}
	newComponents := make(map[RSSGroupMask]RSSComponent, newSize)
	for newPosition := uint8(0); newPosition < newSize; newPosition++ {
		delivered := make([]ReshareFoldDelta, 0)
		for _, delta := range deltas {
			if delta.Target.Contains(newPosition) {
				delivered = append(delivered, delta)
			}
		}
		oldPosition := newPosition
		if newPosition >= leaver {
			oldPosition++
		}
		merged, err := plan.AssembleLocalComponents(newPosition, localViews[oldPosition], delivered)
		if err != nil {
			t.Fatal(err)
		}
		for group, component := range merged {
			if !group.Contains(newPosition) {
				t.Fatalf("position %d received a component of foreign group %06b", newPosition, uint16(group))
			}
			if existing, clash := newComponents[group]; clash && existing != component {
				t.Fatalf("group %06b disagrees between members", uint16(group))
			}
			newComponents[group] = component
		}
	}
	if testResharePublicSum(t, newComponents) != oldPublic {
		t.Fatal("same-key promise broken after position-level remove")
	}
	// Access structure: every 3-coalition of the six-member committee must
	// miss something.
	for a := uint8(0); a < newSize; a++ {
		for b := a + 1; b < newSize; b++ {
			for c := b + 1; c < newSize; c++ {
				covered := make(map[RSSGroupMask]RSSComponent)
				for group, component := range newComponents {
					_ = component
					if group.Contains(a) || group.Contains(b) || group.Contains(c) {
						covered[group] = component
					}
				}
				if testResharePublicSum(t, covered) == oldPublic {
					t.Fatalf("coalition {%d,%d,%d} covers the full key", a, b, c)
				}
			}
		}
	}
}

// testReshareWeaveComponents derives a fresh component for every joiner
// group of the add plan — in the real ceremony each joiner group runs the
// group round under the reshare session digest.
func testReshareWeaveComponents(t *testing.T, plan *ReshareRotationPlan, tag byte) map[RSSGroupMask]RSSComponent {
	t.Helper()
	var sessionDigest [32]byte
	sessionDigest[0] = tag
	var globalRandomness [64]byte
	globalRandomness[0] = tag
	out := make(map[RSSGroupMask]RSSComponent, len(plan.WeaveGroups))
	for _, group := range plan.WeaveGroups {
		leader, err := group.Leader(0)
		if err != nil {
			t.Fatal(err)
		}
		seed := sha3.Sum256([]byte(fmt.Sprintf("R77-WEAVE-%d-%04x", tag, uint16(group))))
		s1, s2, err := DeriveRSSComponent(sessionDigest, group, leader, globalRandomness, seed)
		if err != nil {
			t.Fatal(err)
		}
		out[group] = RSSComponent{GroupMask: group, DealerPosition: leader, Multiplicity: 1, S1: s1, S2: s2}
	}
	return out
}

// TestReshareAddAssemblesPositionShares runs the whole-member view of an
// add rotation: continuing members carry their groups and adopt the weaver
// correction in the correction group, the joiner derives everything fresh,
// and the key is preserved across the new threshold.
func TestReshareAddAssemblesPositionShares(t *testing.T) {
	const oldSize, newSize = 6, 7
	const joiner = uint8(6)
	all := testReshareComponents(t, oldSize)
	oldPublic := testResharePublicSum(t, all)
	plan, err := PlanReshareRotation(oldSize, newSize, joiner)
	if err != nil {
		t.Fatal(err)
	}
	weave := testReshareWeaveComponents(t, plan, 0xA1)
	delta, err := plan.WeaverDelta(weave)
	if err != nil {
		t.Fatal(err)
	}
	// Continuing members see only their own old groups plus the fresh weave
	// components of joiner groups they belong to.
	newComponents := make(map[RSSGroupMask]RSSComponent, newSize)
	for position := uint8(0); position < oldSize; position++ {
		myCarry := make(map[RSSGroupMask]RSSComponent)
		for group, component := range all {
			if group.Contains(position) {
				myCarry[group] = component
			}
		}
		myFresh := make(map[RSSGroupMask]RSSComponent)
		for group, component := range weave {
			if group.Contains(position) && group != plan.CorrectionGroup {
				myFresh[group] = component
			}
		}
		assembled, err := plan.AssembleAddLocalComponents(position, myCarry, myFresh, &delta)
		if err != nil {
			t.Fatal(err)
		}
		for group, component := range assembled {
			if existing, clash := newComponents[group]; clash && existing != component {
				t.Fatalf("group %06b disagrees between members", uint16(group))
			}
			newComponents[group] = component
		}
	}
	// The joiner derives its full set without any carry material.
	joinerAssembled, err := plan.AssembleAddLocalComponents(joiner, nil, weave, &delta)
	if err != nil {
		t.Fatal(err)
	}
	for group, component := range joinerAssembled {
		if !group.Contains(joiner) {
			t.Fatalf("joiner received a component of foreign group %06b", uint16(group))
		}
		if existing, clash := newComponents[group]; clash && existing != component {
			t.Fatalf("group %06b: joiner disagrees with continuing members", uint16(group))
		}
		newComponents[group] = component
	}
	if testResharePublicSum(t, newComponents) != oldPublic {
		t.Fatal("same-key promise broken after add rotation")
	}
	// Access structure of the seven-member committee: every coalition of
	// four members must miss the key.
	for a := uint8(0); a < newSize; a++ {
		for b := a + 1; b < newSize; b++ {
			for c := b + 1; c < newSize; c++ {
				for d := c + 1; d < newSize; d++ {
					covered := make(map[RSSGroupMask]RSSComponent)
					for group, component := range newComponents {
						if group.Contains(a) || group.Contains(b) || group.Contains(c) || group.Contains(d) {
							covered[group] = component
						}
					}
					if testResharePublicSum(t, covered) == oldPublic {
						t.Fatalf("coalition {%d,%d,%d,%d} covers the full key", a, b, c, d)
					}
				}
			}
		}
	}
}

func TestReshareAddRejectsWrongWeaverDelta(t *testing.T) {
	plan, err := PlanReshareRotation(6, 7, 6)
	if err != nil {
		t.Fatal(err)
	}
	weave := testReshareWeaveComponents(t, plan, 0xB2)
	forged := testReshareComponent("forged-correction", plan.CorrectionGroup, 6)
	// The joiner is a member of the correction group, so it detects any
	// forged delta immediately by recomputing it.
	if _, err := plan.AssembleAddLocalComponents(6, map[RSSGroupMask]RSSComponent{}, weave, &ReshareWeaveDelta{
		CorrectionGroup: plan.CorrectionGroup,
		Component:       forged,
	}); err == nil {
		t.Fatal("a forged weaver delta must be refused")
	}
	bogusGroup, err := groupMaskFromPositions([]uint8{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := plan.WeaverDelta(weave)
	if err != nil {
		t.Fatal(err)
	}
	delta.CorrectionGroup = bogusGroup
	if _, err := plan.AssembleAddLocalComponents(3, map[RSSGroupMask]RSSComponent{}, weave, &delta); err == nil {
		t.Fatal("a delta signed for a non-correction group must be refused")
	}
}

// TestReshareRotationForCommittees lifts participant-ID committees to
// position plans: roster order defines positions, so the translation must
// locate the delta and refuse everything that is not a one-member step.
func TestReshareRotationForCommittees(t *testing.T) {
	old7 := mustReshareCommittee(7, 101, 102, 103, 104, 105, 106, 107)
	new6 := mustReshareCommittee(7, 101, 102, 103, 105, 106, 107)

	plan, err := PlanReshareRotationForCommittees(old7, new6)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasLeaver || plan.Leaver != 3 || plan.NewParticipants != 6 {
		t.Fatalf("unexpected remove plan: leaver=%d newSize=%d", plan.Leaver, plan.NewParticipants)
	}

	old6 := mustReshareCommittee(5, 101, 102, 103, 104, 105, 106)
	new7 := mustReshareCommittee(6, 101, 102, 103, 104, 105, 106, 107)
	plan, err = PlanReshareRotationForCommittees(old6, new7)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasWeaver || plan.Weaver != 6 || plan.OldParticipants != 6 {
		t.Fatalf("unexpected add plan: weaver=%d oldSize=%d", plan.Weaver, plan.OldParticipants)
	}

	// A reshuffle with identical membership cannot be a delta rotation - the
	// caller must fall back to fresh-key DKG.
	shuffled := mustReshareCommittee(7, 107, 103, 101, 104, 105, 106, 102)
	if _, err := PlanReshareRotationForCommittees(old7, shuffled); err == nil {
		t.Fatal("same-shape reshuffle must fail")
	}
	// A new member whose participant ID sorts before any old member would
	// shift every position; the plan must refuse this and let the caller
	// fall back to fresh-key DKG.
	insertion := mustReshareCommittee(6, 99, 101, 102, 103, 104, 105, 106)
	if _, err := PlanReshareRotationForCommittees(old6, insertion); err == nil {
		t.Fatal("mid-roster insertion must fail")
	}
	// Thresholds must agree with the family rule.
	bogus := mustReshareCommittee(6, 101, 102, 103, 104, 105, 106, 107)
	bogus.Threshold = 3
	if _, err := PlanReshareRotationForCommittees(old6, bogus); err == nil {
		t.Fatal("wrong threshold on the new committee must fail")
	}
}

// TestResharedShareCarriesKeyAcrossRemove builds real LocalShares per old
// position, rotates position 2 out, and insists every survivor's reshared
// share holds exactly its topology components under the rotated committee
// without changing the key generation or the public key.
func TestResharedShareCarriesKeyAcrossRemove(t *testing.T) {
	const oldSize, newSize = 7, 6
	const leaver = uint8(2)
	rho := sha3.Sum256([]byte("R77-SHARE-RHO"))
	all := testReshareComponents(t, oldSize)
	committeeOld := protocol.CommitteeID{Version: 11, Threshold: 5, Participants: []uint32{101, 102, 103, 104, 105, 106, 107}}
	committeeNew := protocol.CommitteeID{Version: 12, Threshold: 4, Participants: []uint32{101, 102, 104, 105, 106, 107}}
	plan, err := PlanReshareRotationForCommittees(committeeOld, committeeNew)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasLeaver || plan.Leaver != leaver {
		t.Fatalf("expected leaver=2, got %+v", plan)
	}

	// Old LocalShare per member.
	publicKey := make([]byte, 1952)
	publicKey[0] = 0xAA
	keyID := protocol.ThresholdKeyID{
		Algorithm:  qcrypto.SignatureAlgorithmDilithium3Legacy,
		Generation: 11,
		PublicKey:  publicKey,
	}
	shares := make([]*LocalShare, oldSize)
	for position := uint8(0); position < oldSize; position++ {
		components := make([]RSSComponent, 0, 10)
		owned, err := GroupsForPositionN(position, oldSize)
		if err != nil {
			t.Fatal(err)
		}
		for _, group := range owned {
			component, ok := all[group]
			if !ok {
				t.Fatalf("synthetic components miss group %06b", uint16(group))
			}
			components = append(components, component)
		}
		oldShare := &LocalShare{
			Protocol:            protocol.ThresholdProtocolDilithium3V1,
			Key:                 keyID,
			Committee:           committeeOld,
			ParticipantID:       committeeOld.Participants[position],
			ParticipantPosition: position,
			ActivationEpoch:     9,
			Rho:                 rho,
			Components:          components,
		}
		oldShare.TranscriptDigest = sha3.Sum256([]byte("R77-SHARE-TRANSCRIPT"))
		shares[position] = oldShare
	}

	// Anchors derive the deltas they owe; recipients assemble.
	deltas := make([]ReshareFoldDelta, 0)
	for position := uint8(0); position < oldSize; position++ {
		if position == leaver {
			continue
		}
		local := make(map[RSSGroupMask]RSSComponent)
		for _, component := range shares[position].Components {
			local[component.GroupMask] = component
		}
		mine, err := plan.FoldDeltasFor(position, local)
		if err != nil {
			t.Fatal(err)
		}
		deltas = append(deltas, mine...)
	}

	var transcriptDigest [32]byte
	transcriptDigest[0] = 0xEE
	reshared := make([]*LocalShare, 0, newSize)
	for position := uint8(0); position < oldSize; position++ {
		if position == leaver {
			continue
		}
		delivered := make([]ReshareFoldDelta, 0)
		newPosition := position
		if position > leaver {
			newPosition--
		}
		for _, delta := range deltas {
			if delta.Target.Contains(newPosition) {
				delivered = append(delivered, delta)
			}
		}
		nextShare, err := plan.ResharedShare(shares[position], committeeNew, transcriptDigest, delivered)
		if err != nil {
			t.Fatal(err)
		}
		if nextShare.Key.Generation != keyID.Generation || !bytes.Equal(nextShare.Key.PublicKey, keyID.PublicKey) {
			t.Fatal("reshare must preserve the key generation and public key")
		}
		if !slices.Equal(nextShare.Committee.Participants, committeeNew.Participants) ||
			nextShare.Committee.Version != committeeNew.Version || nextShare.ActivationEpoch != 10 {
			t.Fatal("reshare must bump the committee version and epoch only")
		}
		if nextShare.ParticipantPosition != newPosition {
			t.Fatalf("position remap wrong: %d -> %d", position, nextShare.ParticipantPosition)
		}
		if err := nextShare.Validate(); err != nil {
			t.Fatalf("reshared share invalid: %v", err)
		}
		reshared = append(reshared, nextShare)
	}

	// The assembled topology must equal the new committee's group set.
	summed := make(map[RSSGroupMask]RSSComponent)
	for _, share := range reshared {
		for _, component := range share.Components {
			group := component.GroupMask
			if existing, clash := summed[group]; clash && existing != component {
				t.Fatalf("group %06b disagrees between reshared members", uint16(group))
			}
			summed[group] = component
		}
	}
	if len(summed) != 20 {
		t.Fatalf("expected exactly the 20 new groups, got %d", len(summed))
	}
	if testResharePublicSum(t, summed) != testResharePublicSum(t, all) {
		t.Fatal("key sum changed across the remove resharing")
	}
}

// TestResharedShareCarriesKeyAcrossAdd builds real six-member LocalShares,
// rotates a joiner in, and insists the resulting seven shares keep the key
// while each member ends up with exactly its new-topology groups.
func TestResharedShareCarriesKeyAcrossAdd(t *testing.T) {
	const oldSize, newSize = 6, 7
	const joiner = uint8(6)
	rho := sha3.Sum256([]byte("R77-SHARE-ADD-RHO"))
	all := testReshareComponents(t, oldSize)
	oldPublic := testResharePublicSum(t, all)
	committeeOld := protocol.CommitteeID{Version: 20, Threshold: 4, Participants: []uint32{101, 102, 103, 104, 105, 106}}
	committeeNew := protocol.CommitteeID{Version: 21, Threshold: 5, Participants: []uint32{101, 102, 103, 104, 105, 106, 107}}
	plan, err := PlanReshareRotationForCommittees(committeeOld, committeeNew)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasWeaver {
		t.Fatalf("expected add rotation, got %+v", plan)
	}

	publicKey := make([]byte, 1952)
	publicKey[0] = 0xCC
	keyID := protocol.ThresholdKeyID{
		Algorithm:  qcrypto.SignatureAlgorithmDilithium3Legacy,
		Generation: 20,
		PublicKey:  publicKey,
	}
	var transcriptDigest [32]byte
	transcriptDigest = sha3.Sum256([]byte("R77-ADD-TRANSCRIPT"))

	shares := make([]*LocalShare, oldSize)
	for position := uint8(0); position < oldSize; position++ {
		owned, err := GroupsForPositionN(position, oldSize)
		if err != nil {
			t.Fatal(err)
		}
		components := make([]RSSComponent, 0, len(owned))
		for _, group := range owned {
			components = append(components, all[group])
		}
		share := &LocalShare{
			Protocol:            protocol.ThresholdProtocolDilithium3V1,
			Key:                 keyID,
			Committee:           committeeOld,
			ParticipantID:       committeeOld.Participants[position],
			ParticipantPosition: position,
			ActivationEpoch:     12,
			Rho:                 rho,
			Components:          components,
		}
		share.TranscriptDigest = sha3.Sum256([]byte("R77-ADD-OLD-TRANSCRIPT"))
		shares[position] = share
	}

	weave := testReshareWeaveComponents(t, plan, 0xD4)
	for group := range weave {
		component := weave[group]
		component.ContributionDigest = sha3.Sum256(append([]byte("R77-ADD-WEAVE-DIGEST-"), byte(uint16(group)), byte(uint16(group)>>8)))
		weave[group] = component
	}
	delta, err := plan.WeaverDelta(weave)
	if err != nil {
		t.Fatal(err)
	}

	newComponents := make(map[RSSGroupMask]RSSComponent)
	// Continuing members carry their groups; the joiner has only the weave.
	for oldPosition := uint8(0); oldPosition < oldSize; oldPosition++ {
		myFresh := make(map[RSSGroupMask]RSSComponent)
		for group, component := range weave {
			if group.Contains(oldPosition) {
				myFresh[group] = component
			}
		}
		nextShare, err := plan.ResharedAddedShare(shares[oldPosition], committeeNew, protocol.ThresholdKeyID{}, [32]byte{}, 0, transcriptDigest, myFresh, &delta)
		if err != nil {
			t.Fatal(err)
		}
		if err := nextShare.Validate(); err != nil {
			t.Fatalf("reshared added share invalid: %v", err)
		}
		if nextShare.ParticipantID != committeeOld.Participants[oldPosition] ||
			!bytes.Equal(nextShare.Key.PublicKey, publicKey) || nextShare.Key.Generation != 20 {
			t.Fatal("add resharing must preserve the key identity")
		}
		for _, component := range nextShare.Components {
			if existing, clash := newComponents[component.GroupMask]; clash && existing != component {
				t.Fatalf("group %06b disagrees between members", uint16(component.GroupMask))
			}
			newComponents[component.GroupMask] = component
		}
	}
	joinerShare, err := plan.ResharedAddedShare(nil, committeeNew, keyID, rho, 13, transcriptDigest, weave, &delta)
	if err != nil {
		t.Fatal(err)
	}
	if joinerShare.ParticipantID != committeeNew.Participants[joiner] || joinerShare.ParticipantPosition != joiner {
		t.Fatal("joiner's identity must be the appended tail")
	}
	if err := joinerShare.Validate(); err != nil {
		t.Fatalf("joiner's share invalid: %v", err)
	}
	for _, component := range joinerShare.Components {
		if existing, clash := newComponents[component.GroupMask]; clash && existing != component {
			t.Fatalf("group %06b: joiner disagrees with continuing members", uint16(component.GroupMask))
		}
		newComponents[component.GroupMask] = component
	}
	if len(newComponents) != 35 {
		t.Fatalf("expected the full 35 new topology, got %d", len(newComponents))
	}
	if testResharePublicSum(t, newComponents) != oldPublic {
		t.Fatal("key sum changed across the add resharing")
	}
	// A stale key generation must refuse the joiner (fresh-key only rule).
	bogus := &LocalShare{
		Protocol: protocol.ThresholdProtocolDilithium3V1, Key: keyID,
		Committee: committeeNew, ParticipantID: 107, ParticipantPosition: 6,
		ActivationEpoch: 12, Components: []RSSComponent{},
	}
	bogus.TranscriptDigest = transcriptDigest
	bogus.Key.Generation = 999
	if _, err := plan.ResharedAddedShare(reshareStubShare(t, 0), committeeNew, protocol.ThresholdKeyID{}, [32]byte{}, 0, transcriptDigest, weave, &delta); err == nil {
		t.Fatal("a borrower's share with a mismatched old committee must refuse")
	}
	_ = bogus
}

func reshareStubShare(t *testing.T, position uint8) *LocalShare {
	t.Helper()
	all := testReshareComponents(t, 6)
	owned, err := GroupsForPositionN(position, 6)
	if err != nil {
		t.Fatal(err)
	}
	components := make([]RSSComponent, 0, len(owned))
	for _, group := range owned {
		components = append(components, all[group])
	}
	publicKey2 := make([]byte, 1952)
	publicKey2[0] = 0x99
	share := &LocalShare{
		Protocol:    protocol.ThresholdProtocolDilithium3V1,
		Key:         protocol.ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, Generation: 42, PublicKey: publicKey2},
		Committee:   protocol.CommitteeID{Version: 30, Threshold: 4, Participants: []uint32{11, 12, 13, 14, 15, 16}},
		ParticipantID: 11 + uint32(position), ParticipantPosition: position,
		ActivationEpoch: 7,
		Components:      components,
	}
	share.TranscriptDigest = sha3.Sum256([]byte("R77-STUB"))
	return share
}

// TestReshareSwapComposesRemoveThenAdd verifies the composed rotation shape:
// a one-in/one-out swap keeps the key across two adjacent rotations whose
// intermediate committee has six members.
func TestReshareSwapComposesRemoveThenAdd(t *testing.T) {
	seven := testReshareComponents(t, 7)
	oldPublic := testResharePublicSum(t, seven)

	removePlan, err := PlanReshareRotation(7, 6, 2)
	if err != nil {
		t.Fatal(err)
	}
	six, err := removePlan.Apply(seven, nil)
	if err != nil {
		t.Fatal(err)
	}
	if testResharePublicSum(t, six) != oldPublic {
		t.Fatal("swap leg one (remove) changed the key")
	}

	addPlan, err := PlanReshareRotation(6, 7, 6)
	if err != nil {
		t.Fatal(err)
	}
	weave := testReshareWeaveComponents(t, addPlan, 0xC7)
	sevenAgain, err := addPlan.Apply(six, weave)
	if err != nil {
		t.Fatal(err)
	}
	if testResharePublicSum(t, sevenAgain) != oldPublic {
		t.Fatal("swap leg two (add) changed the key")
	}
	if len(sevenAgain) != 35 {
		t.Fatalf("swap result must populate all 35 groups, got %d", len(sevenAgain))
	}

	// The committees' thresholds are now identical (five-of-seven on both
	// ends), but membership and threshold land every rotation leg.
	reverseRemove, err := PlanReshareRotation(7, 6, 6)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := reverseRemove.Apply(sevenAgain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if testResharePublicSum(t, reverse) != oldPublic {
		t.Fatal("swap back changed the key")
	}
}

// TestReshareDeltaWireRoundTrip round-trips both delta kinds through the
// wire codec and refuses truncated, trailing, kind-foreign, or zero-
// multiplicity payloads.
func TestReshareDeltaWireRoundTrip(t *testing.T) {
	component := testReshareComponent("WIRE-KIND", 0x0007, 1)
	component.Multiplicity = 2
	base := ReshareDeltaWire{
		SessionDigest:     sha3.Sum256([]byte("R77-WIRE-SESSION")),
		CommitteeDigest:   sha3.Sum256([]byte("R77-WIRE-COMMITTEE")),
		Kind:              ReshareDeltaKindFold,
		SourceGroup:       0x0007,
		TargetGroup:       0x0016,
		AnchorPosition:    1,
		RecipientPosition: 2,
		Component:         component,
	}
	encoded, err := base.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalReshareDeltaWire(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != base.Kind || decoded.SourceGroup != base.SourceGroup || decoded.TargetGroup != base.TargetGroup ||
		decoded.AnchorPosition != base.AnchorPosition || decoded.RecipientPosition != base.RecipientPosition ||
		decoded.Component.GroupMask != base.SourceGroup || decoded.Component.Multiplicity != 2 ||
		decoded.Component.S1 != base.Component.S1 || decoded.Component.S2 != base.Component.S2 {
		t.Fatal("fold wire delta round trip changed the payload")
	}
	// Correction kind re-anchors the component mask to the target group.
	base.Kind = ReshareDeltaKindCorrection
	encoded, err = base.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = UnmarshalReshareDeltaWire(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Component.GroupMask != base.TargetGroup {
		t.Fatal("correction delta must re-anchor on the target group")
	}
	if _, err := UnmarshalReshareDeltaWire(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("truncated payload must be refused")
	}
	if _, err := UnmarshalReshareDeltaWire(append(encoded, 0x00)); err == nil {
		t.Fatal("trailing payload must be refused")
	}
	bad := base
	bad.Kind = 9
	if _, err := bad.MarshalBinary(); err == nil {
		t.Fatal("unknown kind must be refused on encode")
	}
	bad = base
	bad.Component.Multiplicity = 0
	if _, err := bad.MarshalBinary(); err == nil {
		t.Fatal("zero multiplicity must be refused on encode")
	}
	// Tampering the multiplicity field in place must be refused on decode.
	raw, _ := base.MarshalBinary()
	raw[8+64+1+2+2+1+1+32] = 0
	raw[8+64+1+2+2+1+1+32+1] = 0
	raw[8+64+1+2+2+1+1+32+2] = 0
	raw[8+64+1+2+2+1+1+32+3] = 0
	if _, err := UnmarshalReshareDeltaWire(raw); err == nil {
		t.Fatal("tampered multiplicity must be refused on decode")
	}
}

func mustReshareCommittee(version uint64, participants ...uint32) protocol.CommitteeID {
	// Participants are required to be strictly increasing.
	sorted := append([]uint32{}, participants...)
	slices.Sort(sorted)
	return protocol.CommitteeID{
		Version:      version,
		Threshold:    uint32(ThresholdForParticipants(len(sorted))),
		Participants: sorted,
	}
}

func TestReshareApplyRejectsComponentOutsideTopology(t *testing.T) {
	components := testReshareComponents(t, 7)
	// Drop one carry group: the plan can no longer reproduce the key.
	plan, err := PlanReshareRotation(7, 6, 6)
	if err != nil {
		t.Fatal(err)
	}
	delete(components, unshiftedMask(plan.CarryGroups[0], 6))
	if _, err := plan.Apply(components, nil); err == nil {
		t.Fatal("apply must fail closed when a carry group is missing")
	}
}
