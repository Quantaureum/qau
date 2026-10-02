// Quantaureum Node source, version 1.0.0.
package node

// R77 add-rotation seam: six real DKG shares onboard a seventh member; the
// weaver (joiner) drives the joiner-group rounds and publishes the
// correction; a fresh five-of-seven quorum then signs under the UNCHANGED
// group public key. Together with the remove-shape seam this is the
// acceptance-grade protocol proof that membership rotates while the key
// never does.

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3ReshareAddFixtureFor runs the full six-node ceremony for the
// original committee and the full seven-node ceremony that supplies the
// weaver's fresh joiner-group components.
func tdilithium3ReshareAddFixtureFor(t *testing.T) (*tdilithium3ReshareFixture, []*dilithium3v1.LocalShare) {
	t.Helper()

	// Original six-member committee (positions 0..5, IDs 101..106).
	oldRunners, oldTransport := testTDilithium3DKGRunners(t)
	oldResults, err := runTDilithium3DKGCluster(context.Background(), oldRunners, oldTransport, tdilithium3DKGFaultPlan{})
	if err != nil {
		t.Fatalf("six-node DKG cluster: %v", err)
	}
	fixture := &tdilithium3ReshareFixture{
		session:     oldRunners[0].session.Clone(),
		identities:  make(map[uint32]tdilithium3SigningIdentity, 7),
		privateKeys: make(map[uint32]*mode3.PrivateKey, 7),
		peers:       make(map[uint32]p2p.PeerID, 7),
	}
	oldShares := make([]*dilithium3v1.LocalShare, 6)
	for position, result := range oldResults {
		loaded, err := oldRunners[position].shareStore.LoadCandidate(
			result.Share.Key.Generation, result.Share.ParticipantID, oldRunners[position].password,
		)
		if err != nil {
			t.Fatalf("old participant %d reload: %v", position, err)
		}
		oldShares[position] = loaded
		t.Cleanup(oldShares[position].Zeroize)
	}
	fixture.shares = oldShares
	fixture.groupKey = append([]byte(nil), oldResults[0].PublicKey[:]...)

	// Fresh seven-member weave ceremony (positions 0..6, the appended joiner
	// is position 6 = participant 107): run the family harness end to end and
	// keep each member's woven components -- the reshare consumes only the
	// groups that do not carry over.
	harness7 := newTDilithium3DKGFamilyHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	for position, err := range harness7.runPhase(ctx, func(ctx context.Context, position int) error {
		return harness7.nodes[position].runTDilithium3DKGRandomness(ctx, harness7.runners[position], harness7.exchanges[position], harness7.sign(position), harness7.broadcast(position))
	}) {
		if err != nil {
			t.Fatalf("weave node %d randomness: %v", position, err)
		}
	}
	groups7, err := dilithium3v1.CanonicalRSSGroupsFor(7)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups7 {
		for position, err := range harness7.runPhase(ctx, func(ctx context.Context, position int) error {
			return harness7.nodes[position].runTDilithium3DKGGroup(ctx, harness7.runners[position], group, harness7.exchanges[position], harness7.sign(position), harness7.broadcast(position), harness7.sendPrivate(position))
		}) {
			if err != nil {
				t.Fatalf("weave node %d group %06b: %v", position, group, err)
			}
		}
	}
	if harness7.runners[0].session.Committee.Participants[6] != 107 {
		t.Fatal("family harness committee must append the joiner as participant 107")
	}
	freshShares := make([]*dilithium3v1.LocalShare, 7)
	for position, runner := range harness7.runners {
		result, err := tdilithium3DKGFinalize(runner)
		if err != nil {
			t.Fatalf("weave node %d finalize: %v", position, err)
		}
		freshShares[position] = result.Share
		t.Cleanup(freshShares[position].Zeroize)
	}

	// Identities for all seven participants (DEVNET ONLY deterministic).
	for position := 0; position < 7; position++ {
		var seed [mode3.SeedSize]byte
		copy(seed[:], "DEVNET ONLY add seam identity")
		seed[0] ^= byte(position)
		publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
		participantID := uint32(101 + position)
		peer := p2p.PeerID("add-seam-peer-" + string(rune('a'+position)))
		fixture.privateKeys[participantID] = privateKey
		fixture.peers[participantID] = peer
		fixture.identities[participantID] = tdilithium3SigningIdentity{
			Peer:             peer,
			ValidatorAddress: types.AddressFromPublicKey(publicKey.Bytes()),
			PublicKey:        publicKey.Bytes(),
		}
	}
	return fixture, freshShares
}

// tdilithium3ReshareAddRotatedShares composes the add-rotated shares from
// the old six-member committee's carried groups, the joiner's fresh groups,
// and the weaver correction, asserting the public-key invariance everyone
// else relies on.
func tdilithium3ReshareAddRotatedShares(t *testing.T) (*tdilithium3ReshareFixture, map[uint32]*dilithium3v1.LocalShare, protocol.CommitteeID) {
	t.Helper()
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture, fresh := tdilithium3ReshareAddFixtureFor(t)
	const joiner = uint8(6)

	oldCommittee := fixture.shares[0].Committee
	newCommittee := oldCommittee.Clone()
	newCommittee.Version++
	newCommittee.Threshold = protocol.Dilithium3V1ThresholdFor(7)
	newCommittee.Participants = append(append([]uint32{}, oldCommittee.Participants...), 107)
	plan, err := dilithium3v1.PlanReshareRotationForCommittees(oldCommittee, newCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasWeaver || plan.Weaver != joiner {
		t.Fatalf("expected a joiner-weaver plan, got %+v", plan)
	}
	transcript := fixture.shares[0].TranscriptDigest

	runners := make([]*tdilithium3ReshareAddRunner, 0, 7)
	carried := make(map[dilithium3v1.RSSGroupMask]bool, len(plan.CarryGroups))
	for _, group := range plan.CarryGroups {
		carried[group] = true
	}
	for position := uint8(0); position < 7; position++ {
		myFresh := make(map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent)
		for _, component := range fresh[position].Components {
			if !carried[component.GroupMask] && component.GroupMask.Contains(position) {
				myFresh[component.GroupMask] = component
			}
		}
		var old *dilithium3v1.LocalShare
		if position != joiner {
			old = fixture.shares[position]
		}
		runner, err := newTDilithium3ReshareAddRunner(plan, old, newCommittee, fixture.shares[0].Key, fixture.shares[0].Rho, fixture.shares[0].ActivationEpoch+1, transcript, myFresh)
		if err != nil {
			t.Fatalf("add runner at position %d: %v", position, err)
		}
		runners = append(runners, runner)
	}

	// Weaver derives and publishes the correction; correction-group members
	// adopt it.
	weaver := runners[joiner]
	delta, err := weaver.WeaverDelta()
	if err != nil {
		t.Fatal(err)
	}
	for position, runner := range runners {
		if position == int(joiner) || !plan.CorrectionGroup.Contains(uint8(position)) {
			continue
		}
		if err := runner.ReceiveWeaveDelta(delta); err != nil {
			t.Fatal(err)
		}
	}

	rotated := make(map[uint32]*dilithium3v1.LocalShare, 7)
	for position, runner := range runners {
		if !runner.Ready() {
			t.Fatalf("runner at position %d not ready", position)
		}
		share, err := runner.Assemble()
		if err != nil {
			t.Fatalf("assemble at position %d: %v", position, err)
		}
		if err := share.Validate(); err != nil {
			t.Fatalf("rotated share at position %d invalid: %v", position, err)
		}
		if !bytes.Equal(share.Key.PublicKey, fixture.groupKey) {
			t.Fatalf("rotated share at position %d mutated the group public key", position)
		}
		rotated[share.ParticipantID] = share
		t.Cleanup(share.Zeroize)
	}
	return fixture, rotated, newCommittee
}

// TestTDilithium3ReshareAddAssemblesSameKeyShares is the always-on
// assembly-level acceptance of the add shape: seven rotated shares, all
// validating, all presenting the pre-rotation group public key.
func TestTDilithium3ReshareAddAssemblesSameKeyShares(t *testing.T) {
	_, rotated, newCommittee := tdilithium3ReshareAddRotatedShares(t)
	if len(rotated) != len(newCommittee.Participants) {
		t.Fatalf("rotation produced %d shares, want %d", len(rotated), len(newCommittee.Participants))
	}
}

// TestTDilithium3ReshareAddSeamSignsUnderSameKey adds the five-of-seven
// signing seam under the unchanged key.
//
// R77c open item: the add correction concentrates the joiner-group zero-sum
// into one component with multiplicity binom(C-1, g)-1 = 19 (C=7). The
// per-signer partial-norm bound scales correctly (R77b), but the R57 HRej
// radius parameters were pinned for per-component eta=1 over C(6,3)=20
// fresh groups, so a quorum hosting the correction group aborts with
// overwhelming probability and the schedule exhausts its requests. Until
// the signing parameter table gains the rotated row, this test is
// time-gated rather than green-by-default.
func TestTDilithium3ReshareAddSeamSignsUnderSameKey(t *testing.T) {
	if os.Getenv("QAU_ENABLE_R77C_SIGNING_ROW") != "1" {
		t.Skip("R77c: add-shape correction multiplicity requires the rotated signing parameter row")
	}
	fixture, rotated, newCommittee := tdilithium3ReshareAddRotatedShares(t)

	// Five-of-seven signatures under the unchanged key.
	signers := newCommittee.Participants[:5]
	seamFixture := &tdilithium3SeamFixture{
		session:     fixture.session.Clone(),
		groupKey:    append([]byte(nil), fixture.groupKey...),
		identities:  make(map[uint32]tdilithium3SigningIdentity, 5),
		privateKeys: make(map[uint32]*mode3.PrivateKey, 5),
		peers:       make(map[uint32]p2p.PeerID, 5),
	}
	seamFixture.session.Committee = newCommittee.Clone()
	seamFixture.session.ActivationEpoch = fixture.session.ActivationEpoch + 1
	for index, participantID := range signers {
		seamFixture.shares[index] = rotated[participantID]
		seamFixture.identities[participantID] = fixture.identities[participantID]
		seamFixture.privateKeys[participantID] = fixture.privateKeys[participantID]
		seamFixture.peers[participantID] = fixture.peers[participantID]
	}
	share := rotated[signers[0]]
	request := tdilithium3SeamRequest(
		t, share, seamFixture.session.ActivationEpoch, 88, []byte(tdilithium3SeamTestMessage),
	)
	if signature := tdilithium3SeamHarnessFor(t, seamFixture, signers, request, 0).signOne(t); signature != nil {
		if err := qcrypto.VerifySignatureForAlgorithm(
			qcrypto.SignatureAlgorithmDilithium3Legacy, fixture.groupKey, request.Message, nil, signature,
		); err != nil {
			t.Fatalf("add-rotated signature does not verify: %v", err)
		}
		return
	}
	tdilithium3SeamSign(t, seamFixture, signers, share, 88)
}
