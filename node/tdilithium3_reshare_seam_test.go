// Quantaureum Node source, version 1.0.0.
package node

// R77 remove-rotation seam: seven real DKG shares rotate to six and a fresh
// four-of-six quorum signs under the UNCHANGED group public key. This is the
// acceptance-grade protocol proof of the rotation: the key the committee
// presents to consensus never changes when membership does.

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const tdilithium3ReshareSeamParticipants = 7

// tdilithium3ReshareFixture is the rotation counterpart of the DKG seam
// fixture: shares of a completed seven-member ceremony, the group public
// key, and one mode3 identity key per participant.
type tdilithium3ReshareFixture struct {
	session     dilithium3v1.DKGSession
	groupKey    []byte
	shares      []*dilithium3v1.LocalShare
	identities  map[uint32]tdilithium3SigningIdentity
	privateKeys map[uint32]*mode3.PrivateKey
	peers       map[uint32]p2p.PeerID
}

// tdilithium3ReshareFixtureFor runs the full seven-node ceremony and returns
// the per-member shares together with fresh DEVNET ONLY identity bindings.
func tdilithium3ReshareFixtureFor(t *testing.T) *tdilithium3ReshareFixture {
	t.Helper()
	harness := newTDilithium3DKGFamilyHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	for position, err := range harness.runPhase(ctx, func(ctx context.Context, position int) error {
		return harness.nodes[position].runTDilithium3DKGRandomness(ctx, harness.runners[position], harness.exchanges[position], harness.sign(position), harness.broadcast(position))
	}) {
		if err != nil {
			t.Fatalf("node %d randomness: %v", position, err)
		}
	}
	groups, err := dilithium3v1.CanonicalRSSGroupsFor(tdilithium3ReshareSeamParticipants)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		for position, err := range harness.runPhase(ctx, func(ctx context.Context, position int) error {
			return harness.nodes[position].runTDilithium3DKGGroup(ctx, harness.runners[position], group, harness.exchanges[position], harness.sign(position), harness.broadcast(position), harness.sendPrivate(position))
		}) {
			if err != nil {
				t.Fatalf("node %d group %06b: %v", position, group, err)
			}
		}
	}
	fixture := &tdilithium3ReshareFixture{
		session:     harness.runners[0].session.Clone(),
		identities:  make(map[uint32]tdilithium3SigningIdentity, len(harness.nodes)),
		privateKeys: make(map[uint32]*mode3.PrivateKey, len(harness.nodes)),
		peers:       make(map[uint32]p2p.PeerID, len(harness.nodes)),
	}
	for position, runner := range harness.runners {
		result, err := tdilithium3DKGFinalize(runner)
		if err != nil {
			t.Fatalf("node %d finalize: %v", position, err)
		}
		loaded, err := runner.shareStore.LoadCandidate(
			result.Share.Key.Generation, result.Share.ParticipantID, runner.password,
		)
		if err != nil {
			t.Fatalf("participant %d reload: %v", position, err)
		}
		fixture.shares = append(fixture.shares, loaded)
		fixture.groupKey = append([]byte(nil), result.PublicKey[:]...)
		t.Cleanup(fixture.shares[position].Zeroize)

		var seed [mode3.SeedSize]byte
		copy(seed[:], "DEVNET ONLY reshare seam identity")
		seed[0] ^= byte(position)
		publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
		participantID := loaded.ParticipantID
		peer := p2p.PeerID(fmt.Sprintf("reshare-seam-peer-%d", participantID))
		fixture.privateKeys[participantID] = privateKey
		fixture.peers[participantID] = peer
		fixture.identities[participantID] = tdilithium3SigningIdentity{
			Peer:             peer,
			ValidatorAddress: types.AddressFromPublicKey(publicKey.Bytes()),
			PublicKey:        publicKey.Bytes(),
		}
	}
	return fixture
}

// TestTDilithium3ReshareRemoveSeamSignsUnderSameKey removes one member of
// the seven-member committee, assembles every survivor's rotated share via
// the remove runner, and makes a four-of-six quorum of the SURVIVORS sign
// under the never-changed group public key.
func TestTDilithium3ReshareRemoveSeamSignsUnderSameKey(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3ReshareFixtureFor(t)
	const leaver = uint8(2)

	plan, err := dilithium3v1.PlanReshareRotation(tdilithium3ReshareSeamParticipants, tdilithium3ReshareSeamParticipants-1, leaver)
	if err != nil {
		t.Fatal(err)
	}
	newCommittee := fixture.shares[0].Committee.Clone()
	newCommittee.Version++
	newCommittee.Participants = append([]uint32{},
		newCommittee.Participants[:leaver]...,
	)
	newCommittee.Participants = append(newCommittee.Participants, fixture.shares[0].Committee.Participants[leaver+1:]...)
	newCommittee.Threshold = protocol.Dilithium3V1ThresholdFor(uint32(len(newCommittee.Participants)))
	transcript := fixture.shares[0].TranscriptDigest

	runners := make([]*tdilithium3ReshareRemoveRunner, 0, tdilithium3ReshareSeamParticipants)
	byOldPosition := make(map[uint8]*tdilithium3ReshareRemoveRunner, tdilithium3ReshareSeamParticipants)
	for position := uint8(0); position < tdilithium3ReshareSeamParticipants; position++ {
		if position == leaver {
			continue
		}
		runner, err := newTDilithium3ReshareRemoveRunner(plan, fixture.shares[position], newCommittee, transcript)
		if err != nil {
			t.Fatalf("runner for position %d: %v", position, err)
		}
		runners = append(runners, runner)
		byOldPosition[position] = runner
	}

	// In-proc dispatch mirrors the ceremony's private delivery: anchor to the
	// other target-group members, identified by their new position.
	delivered := 0
	for _, runner := range runners {
		for _, delivery := range runner.OutgoingDeltas() {
			oldRecipient := delivery.RecipientPosition
			if oldRecipient >= leaver {
				oldRecipient++
			}
			target, found := byOldPosition[oldRecipient]
			if !found {
				t.Fatalf("delivery addressed at absent position %d", oldRecipient)
			}
			if err := target.Receive(delivery); err != nil {
				t.Fatal(err)
			}
			delivered++
		}
	}
	if delivered == 0 {
		t.Fatal("remove rotation delivered no deltas")
	}

	rotated := make(map[uint32]*dilithium3v1.LocalShare, len(runners))
	for _, runner := range runners {
		if !runner.Ready() {
			t.Fatalf("runner at position %d not ready", runner.Position())
		}
		share, err := runner.Assemble()
		if err != nil {
			t.Fatalf("assemble for position %d: %v", runner.Position(), err)
		}
		if err := share.Validate(); err != nil {
			t.Fatalf("rotated share at position %d invalid: %v", runner.Position(), err)
		}
		if !bytes.Equal(share.Key.PublicKey, fixture.groupKey) {
			t.Fatalf("rotated share at position %d mutated the group public key", runner.Position())
		}
		if share.Key.Generation != fixture.shares[0].Key.Generation {
			t.Fatalf("rotated share at position %d changed the key generation", runner.Position())
		}
		if !bytes.Equal(share.Key.PublicKey, fixture.shares[0].Key.PublicKey) ||
			share.Committee.Version <= fixture.shares[0].Committee.Version {
			t.Fatal("rotation must keep the key identity and advance the committee version")
		}
		rotated[share.ParticipantID] = share
		t.Cleanup(share.Zeroize)
	}
	if len(rotated) != tdilithium3ReshareSeamParticipants-1 {
		t.Fatalf("rotation produced %d shares, want 6", len(rotated))
	}

	// Sign with a four-of-six quorum of the new committee (threshold(t=4 of
	// 6) is the rotate's C=6 family threshold).
	signers := newCommittee.Participants[:4]
	for index, participantID := range signers {
		if rotated[participantID] == nil {
			t.Fatalf("signer %d (%d) has no rotated share", index, participantID)
		}
	}
	share := rotated[signers[0]]

	seamFixture := &tdilithium3SeamFixture{
		session:     fixture.session.Clone(),
		groupKey:    append([]byte(nil), fixture.groupKey...),
		identities:  make(map[uint32]tdilithium3SigningIdentity, len(signers)),
		privateKeys: make(map[uint32]*mode3.PrivateKey, len(signers)),
		peers:       make(map[uint32]p2p.PeerID, len(signers)),
	}
	seamFixture.session.Committee = newCommittee.Clone()
	seamFixture.session.ActivationEpoch = fixture.session.ActivationEpoch + 1
	for index, participantID := range signers {
		seamFixture.shares[index] = rotated[participantID]
		seamFixture.identities[participantID] = fixture.identities[participantID]
		seamFixture.privateKeys[participantID] = fixture.privateKeys[participantID]
		seamFixture.peers[participantID] = fixture.peers[participantID]
	}

	request := tdilithium3SeamRequest(
		t, share, seamFixture.session.ActivationEpoch, 72, []byte(tdilithium3SeamTestMessage),
	)
	if signature := tdilithium3SeamHarnessFor(t, seamFixture, signers, request, 0).signOne(t); signature != nil {
		return
	}
	tdilithium3SeamSign(t, seamFixture, signers, share, 72)
}
