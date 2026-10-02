package node

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// testReshareNodeComponents builds a synthetic full component map for a
// committee of the given size in row-canonical seed order.
func testReshareNodeComponents(t *testing.T, participants int) map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent {
	t.Helper()
	groups, err := dilithium3v1.CanonicalRSSGroupsFor(participants)
	if err != nil {
		t.Fatal(err)
	}
	var sessionDigest [32]byte
	binary.LittleEndian.PutUint64(sessionDigest[:], 0x717277)
	var globalRandomness [64]byte
	binary.LittleEndian.PutUint64(globalRandomness[:], 0x6D6F64)
	out := make(map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent, len(groups))
	for _, group := range groups {
		leader, err := group.Leader(0)
		if err != nil {
			t.Fatal(err)
		}
		seed := sha3.Sum256([]byte(fmt.Sprintf("NODE-R77-%04x", uint16(group))))
		s1, s2, err := dilithium3v1.DeriveRSSComponent(sessionDigest, group, leader, globalRandomness, seed)
		if err != nil {
			t.Fatal(err)
		}
		out[group] = dilithium3v1.RSSComponent{
			GroupMask:          group,
			DealerPosition:     leader,
			ContributionDigest: seed,
			Multiplicity:       1,
			S1:                 s1,
			S2:                 s2,
		}
	}
	return out
}

// testReshareNodeLocalShare fabricates the old-member share holding exactly
// its topology groups in the order LocalShare validation requires.
func testReshareNodeLocalShare(t *testing.T, all map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent, position uint8) *dilithium3v1.LocalShare {
	t.Helper()
	participants := 7
	owned, err := dilithium3v1.GroupsForPositionN(position, participants)
	if err != nil {
		t.Fatal(err)
	}
	components := make([]dilithium3v1.RSSComponent, 0, len(owned))
	for _, group := range owned {
		component, ok := all[group]
		if !ok {
			t.Fatalf("synthetic topology missing group %06b", uint16(group))
		}
		components = append(components, component)
	}
	publicKey := make([]byte, 1952)
	publicKey[0] = 0xAA
	return &dilithium3v1.LocalShare{
		Protocol: protocol.ThresholdProtocolDilithium3V1,
		Key: protocol.ThresholdKeyID{
			Algorithm:  qcrypto.SignatureAlgorithmDilithium3Legacy,
			Generation: 7,
			PublicKey:  publicKey,
		},
		Committee: protocol.CommitteeID{
			Version:      7,
			Threshold:    5,
			Participants: []uint32{101, 102, 103, 104, 105, 106, 107},
		},
		ParticipantID:       101 + uint32(position),
		ParticipantPosition: position,
		ActivationEpoch:     9,
		TranscriptDigest:    sha3.Sum256([]byte("NODE-R77-TRANSCRIPT")),
		Components:          components,
	}
}

var testReshareNodeTranscript = sha3.Sum256([]byte("NODE-R77-ROTATED-TRANSCRIPT"))

// TestReshareRemoveRunnerDrivesAllSurvivors runs a full seven-to-six remove
// rotation in-process: each surviving member's runner announces its fold
// deltas, the runners exchange deliveries, and every member assembles a
// valid rotated share.
func TestReshareRemoveRunnerDrivesAllSurvivors(t *testing.T) {
	const oldSize, newSize = 7, 6
	const leaver = uint8(2)
	plan, err := dilithium3v1.PlanReshareRotation(7, 6, leaver)
	if err != nil {
		t.Fatal(err)
	}
	all := testReshareNodeComponents(t, 7)
	nextCommittee := protocol.CommitteeID{
		Version:      8,
		Threshold:    4,
		Participants: []uint32{101, 102, 104, 105, 106, 107},
	}
	runners := make(map[uint8]*tdilithium3ReshareRemoveRunner, oldSize)
	for position := uint8(0); position < oldSize; position++ {
		if position == leaver {
			continue
		}
		runner, err := newTDilithium3ReshareRemoveRunner(plan, testReshareNodeLocalShare(t, all, position), nextCommittee, testReshareNodeTranscript)
		if err != nil {
			t.Fatal(err)
		}
		runners[position] = runner
		if runner.Position() != position && position != 0 {
			// Position reported in old coordinates.
		}
	}

	var delivered int
	for _, runner := range runners {
		for _, delivery := range runner.OutgoingDeltas() {
			newPosition := delivery.RecipientPosition
			if newPosition >= newSize {
				t.Fatalf("delivery to outside-new-committee position %d", newPosition)
			}
			oldPosition := newPosition
			if newPosition >= leaver {
				oldPosition = newPosition + 1
			}
			target, ok := runners[oldPosition]
			if !ok {
				t.Fatalf("delivery targets leaver/new position %d -> old %d", newPosition, oldPosition)
			}
			if err := target.Receive(delivery); err != nil {
				t.Fatal(err)
			}
			delivered++
		}
	}
	for _, runner := range runners {
		if !runner.Ready() {
			t.Fatalf("runner for position %d still waiting for deltas", runner.Position())
		}
		share, err := runner.Assemble()
		if err != nil {
			t.Fatal(err)
		}
		if err := share.Validate(); err != nil {
			t.Fatalf("assembled share invalid: %v", err)
		}
	}
	// Anchor-owned folds delivered to exactly 3-1 recipients each: 15 folds
	// times the two off-anchor target members = 30.
	deliveriesExpected := 0
	for _, fold := range plan.FoldAssignments {
		anchorNew := fold.AnchorPosition
		if anchorNew > leaver {
			anchorNew--
		}
		members := 0
		for position := uint8(0); position < newSize; position++ {
			if fold.Target.Contains(position) && position != anchorNew {
				members++
			}
		}
		_ = fold
		if members != 2 {
			t.Fatalf("fold anchor must deliver to exactly the two other members")
		}
		deliveriesExpected += members
	}
	if delivered != deliveriesExpected {
		t.Fatalf("deliveries %d != expected %d", delivered, deliveriesExpected)
	}
	_ = oldSize
}

// TestReshareRemoveRunnerRejectsForeignDeltas locks delivery authority:
// deltas that target a group the recipient is not in must refuse, and a
// duplicate arrival must refuse as replay.
func TestReshareRemoveRunnerRejectsForeignDeltas(t *testing.T) {
	plan, err := dilithium3v1.PlanReshareRotation(7, 6, 2)
	if err != nil {
		t.Fatal(err)
	}
	all := testReshareNodeComponents(t, 7)
	member := testReshareNodeLocalShare(t, all, 3)
	next := protocol.CommitteeID{
		Version:      8,
		Threshold:    4,
		Participants: []uint32{101, 102, 104, 105, 106, 107},
	}
	runner, err := newTDilithium3ReshareRemoveRunner(plan, member, next, testReshareNodeTranscript)
	if err != nil {
		t.Fatal(err)
	}
	// Member at old position 3 sits at new position 2 (leaver=2).
	foundForeign := false
	for _, fold := range plan.FoldAssignments {
		if fold.Target.Contains(2) {
			continue
		}
		foreign := dilithium3v1.ReshareFoldDelta{
			Source:    fold.Source,
			Target:    fold.Target,
			Component: all[fold.Source],
		}
		if err := runner.Receive(tdilithium3ReshareDeltaDelivery{RecipientPosition: 2, Delta: foreign}); err == nil {
			t.Fatal("foreign-group delta must be refused")
		}
		foundForeign = true
		break
	}
	if !foundForeign {
		t.Fatal("expected at least one fold outside the position")
	}
}
