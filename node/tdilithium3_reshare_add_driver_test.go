package node

import (
	"crypto/sha3"
	"fmt"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// TestReshareAddRunnerDrivesAllMembers runs a full six-to-seven add
// rotation: continuing members carry their groups and adopt the weave
// components of the joiner groups they belong to, the joiner contributes as
// the weaver, and everyone ends up with a share that validates and matches
// on public key.
func TestReshareAddRunnerDrivesAllMembers(t *testing.T) {
	const oldSize, newSize = 6, 7
	const joiner = uint8(6)
	plan, err := dilithium3v1.PlanReshareRotation(6, 7, joiner)
	if err != nil {
		t.Fatal(err)
	}
	oldCommittee := protocol.CommitteeID{Version: 20, Threshold: 4, Participants: []uint32{101, 102, 103, 104, 105, 106}}
	nextCommittee := protocol.CommitteeID{Version: 21, Threshold: 5, Participants: []uint32{101, 102, 103, 104, 105, 106, 107}}

	all6 := testReshareNodeComponents(t, oldSize)
	oldKey := mustReshareNodeKeyID()
	oldRho := sha3Of("NODE-R77-ADD-RHO")

	oldShares := make([]*dilithium3v1.LocalShare, oldSize)
	for position := uint8(0); position < oldSize; position++ {
		owned, err := dilithium3v1.GroupsForPositionN(position, oldSize)
		if err != nil {
			t.Fatal(err)
		}
		components := make([]dilithium3v1.RSSComponent, 0, len(owned))
		for _, group := range owned {
			components = append(components, all6[group])
		}
		oldShares[position] = &dilithium3v1.LocalShare{
			Protocol:            protocol.ThresholdProtocolDilithium3V1,
			Key:                 oldKey,
			Committee:           oldCommittee,
			ParticipantID:       oldCommittee.Participants[position],
			ParticipantPosition: position,
			ActivationEpoch:     12,
			TranscriptDigest:    sha3Of("NODE-R77-ADD-OLDTRANSCRIPT"),
			Rho:                 oldRho,
			Components:          components,
		}
	}

	// The fresh-ceremony component family every member receives (group rounds
	// for the joiner groups produce these values).
	weaveComponents := map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent{}
	var sessionDigest [32]byte
	sessionDigest[0] = 0xA7
	var globalRandomness [64]byte
	for index := range globalRandomness {
		globalRandomness[index] = byte(index + 13)
	}
	for _, group := range plan.WeaveGroups {
		leader, err := group.Leader(0)
		if err != nil {
			t.Fatal(err)
		}
		seed := sha3Of(fmt.Sprintf("NODE-R77-WEAVE-%04x", uint16(group)))
		s1, s2, err := dilithium3v1.DeriveRSSComponent(sessionDigest, group, leader, globalRandomness, seed)
		if err != nil {
			t.Fatal(err)
		}
		weaveComponents[group] = dilithium3v1.RSSComponent{
			GroupMask:          group,
			DealerPosition:     leader,
			ContributionDigest: sha3Of(fmt.Sprintf("NODE-R77-WEAVE-DIGEST-%04x", uint16(group))),
			Multiplicity:       1,
			S1:                 s1,
			S2:                 s2,
		}
	}

	// Runner-one per member; the joiner has no old share.
	runners := make(map[uint8]*tdilithium3ReshareAddRunner, newSize)
	for position := uint8(0); position < newSize; position++ {
		var old *dilithium3v1.LocalShare
		if position != joiner {
			old = oldShares[position]
		}
		// Each member receives only the weave components of groups it
		// belongs to.
		myFresh := make(map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent)
		for group, component := range weaveComponents {
			if group.Contains(position) {
				myFresh[group] = component
			}
		}
		r, err := newTDilithium3ReshareAddRunner(plan, old, nextCommittee, oldKey, oldRho, 13, testReshareNodeTranscript, myFresh)
		if err != nil {
			t.Fatal(err)
		}
		runners[position] = r
	}

	// Weaver announces the correction; correction-group members adopt.
	weaver := runners[joiner]
	delta, err := weaver.WeaverDelta()
	if err != nil {
		t.Fatal(err)
	}
	for position, runner := range runners {
		if position == joiner {
			continue
		}
		if plan.CorrectionGroup.Contains(position) {
			if err := runner.ReceiveWeaveDelta(dilithium3v1.ReshareWeaveDelta{
				CorrectionGroup: delta.CorrectionGroup,
				Component:       delta.Component,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	shares := make([]*dilithium3v1.LocalShare, 0, newSize)
	for position, runner := range runners {
		if !runner.Ready() {
			t.Fatalf("runner at position %d not ready", position)
		}
		share, err := runner.Assemble()
		if err != nil {
			t.Fatal(err)
		}
		if err := share.Validate(); err != nil {
			t.Fatalf("share invalid at position %d: %v", position, err)
		}
		shares = append(shares, share)
	}

	// Public key invariance verified through the family's component set.
	newComponents := make(map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent)
	for _, share := range shares {
		for _, component := range share.Components {
			if existing, clash := newComponents[component.GroupMask]; clash && existing != component {
				t.Fatalf("group %06b disagrees between members", uint16(component.GroupMask))
			}
			newComponents[component.GroupMask] = component
		}
	}
	if len(newComponents) != 35 {
		t.Fatalf("expected the full 35-group topology, got %d", len(newComponents))
	}
	oldSum := testReshareNodePublicSum(t, all6)
	newSum := testReshareNodePublicSum(t, newComponents)
	if newSum != oldSum {
		t.Fatal("key invariant broken across the add rotation")
	}
}

func mustReshareNodeKeyID() protocol.ThresholdKeyID {
	publicKey := make([]byte, 1952)
	publicKey[0] = 0xAA
	return protocol.ThresholdKeyID{
		Algorithm:  qcrypto.SignatureAlgorithmDilithium3Legacy,
		Generation: 20,
		PublicKey:  publicKey,
	}
}

func sha3Of(tag string) [32]byte {
	return sha3.Sum256([]byte(tag))
}

// testReshareNodePublicSum sums the public contribution vectors over a
// component map using the same rho compared to ShareAssemblePublicLayout.
func testReshareNodePublicSum(t *testing.T, components map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent) dilithium3v1.VectorK {
	t.Helper()
	rho := sha3Of("NODE-R77-ADD-RHO")
	var total dilithium3v1.VectorK
	first := true
	for _, component := range components {
		summed, err := dilithium3v1.ComputePublicVector(rho, component.S1, component.S2)
		if err != nil {
			t.Fatal(err)
		}
		if first {
			total = summed
			first = false
			continue
		}
		total = dilithium3v1.AddVectorK(total, summed)
	}
	return total
}
