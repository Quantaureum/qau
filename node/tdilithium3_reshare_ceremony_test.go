// Quantaureum Node source, version 1.0.0.
package node

// R77 wire choreography test: the remove rotation over real signed
// envelopes. Seven fresh shares rotate to six; every fold delivery passes
// through protocol envelope encoding, the p2p envelope validator, the
// authenticated inbox, and the runner, exactly as production routes it.

import (
	"bytes"
	"crypto/sha3"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// TestTDilithium3ReshareRemoveWireSeam drives the fold delivery of a
// six-member rotation through the real envelope + inbox stack and asserts
// every member re-derives byte-identical rotated components under the
// unchanged key.
func TestTDilithium3ReshareRemoveWireSeam(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3ReshareFixtureFor(t)

	oldCommittee := fixture.shares[0].Committee
	leaver := uint8(3)
	newParticipants := append([]uint32(nil), oldCommittee.Participants[:leaver]...)
	newParticipants = append(newParticipants, oldCommittee.Participants[leaver+1:]...)
	newCommittee := protocol.CommitteeID{
		Version:      oldCommittee.Version + 1,
		Threshold:    protocol.Dilithium3V1ThresholdFor(6),
		Participants: newParticipants,
	}
	plan, err := tdilithium3ReshareRotationFor(oldCommittee, newCommittee)
	if err != nil {
		t.Fatal(err)
	}

	// Reshare-shaped session with the nonce pinning the previous key.
	sessionDigest, err := fixture.session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	session := fixture.session.Clone()
	session.Committee = newCommittee
	session.KeyGeneration = fixture.shares[0].Key.Generation + 1
	session.ActivationEpoch = fixture.session.ActivationEpoch + 1
	keyDigest := sha3.Sum256(fixture.groupKey)
	session.Nonce = sha3.Sum256(append(sessionDigest[:], keyDigest[:]...))
	if err := session.Validate(); err != nil {
		t.Fatal(err)
	}
	reshareSessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	transcript := sha3.Sum256(append([]byte("R77-WIRE-SEAM"), fixture.shares[0].TranscriptDigest[:]...))
	committeeDigest, err := newCommittee.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}

	newPosByOld := func(oldPos uint8) uint8 {
		if oldPos > leaver {
			return oldPos - 1
		}
		return oldPos
	}
	verifyFrom := func(participantID uint32, message, signature []byte) bool {
		identity, found := fixture.identities[participantID]
		if !found {
			return false
		}
		key, err := qcrypto.PublicKeyFromBytes(identity.PublicKey)
		if err != nil {
			return false
		}
		return qcrypto.Verify(key, message, signature)
	}
	resolvePeer := func(peer p2p.PeerID) (uint32, bool) {
		for participantID, candidate := range fixture.peers {
			if candidate == peer {
				return participantID, true
			}
		}
		return 0, false
	}

	// One runner and inbox per surviving member, roster-bound to the fixture.
	type member struct {
		runner      *tdilithium3ReshareRemoveRunner
		inbox       *tdilithium3DKGInbox
		participant uint32
		newPos      uint8
	}
	members := make([]*member, 0, 6)
	signFor := func(privateKey *mode3.PrivateKey) func([]byte) ([]byte, error) {
		return func(message []byte) ([]byte, error) {
			signature := make([]byte, mode3.SignatureSize)
			mode3.SignTo(privateKey, message, signature)
			return signature, nil
		}
	}
	for oldPos := 0; oldPos < tdilithium3ReshareSeamParticipants; oldPos++ {
		if oldPos == int(leaver) {
			continue
		}
		newPos := newPosByOld(uint8(oldPos))
		participantID := newParticipants[newPos]
		runner, err := newTDilithium3ReshareRemoveRunner(plan, fixture.shares[oldPos].Clone(), newCommittee, transcript)
		if err != nil {
			t.Fatal(err)
		}
		inbox, err := newTDilithium3DKGInbox(session, newPos, verifyFrom, resolvePeer)
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, &member{runner: runner, inbox: inbox, participant: participantID, newPos: newPos})
	}

	// Every member publishes; every envelope passes the p2p payload
	// validator, the structural+identity validation and the inbox.
	for _, sender := range members {
		for _, delivery := range sender.runner.OutgoingDeltas() {
			wire := dilithium3v1.ReshareDeltaWire{
				SessionDigest:     reshareSessionDigest,
				CommitteeDigest:   committeeDigest,
				Kind:              dilithium3v1.ReshareDeltaKindFold,
				SourceGroup:       delivery.Delta.Source,
				TargetGroup:       delivery.Delta.Target,
				AnchorPosition:    sender.newPos,
				RecipientPosition: delivery.RecipientPosition,
				Component:         delivery.Delta.Component,
			}
			payload, err := wire.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3ReshareDelta,
				sender.newPos, 1, payload, signFor(fixture.privateKeys[sender.participant]))
			if err != nil {
				t.Fatal(err)
			}
			if err := p2p.ValidateTDilithium3DKGEnvelope(p2p.MsgTypeTDilithium3ReshareDelta, encoded); err != nil {
				t.Fatalf("p2p envelope validation: %v", err)
			}
			receiver := members[delivery.RecipientPosition]
			message := p2p.PeerMessage{From: fixture.peers[sender.participant], Type: p2p.MsgTypeTDilithium3ReshareDelta, Payload: encoded}
			if err := receiver.inbox.accept(message); err != nil {
				t.Fatalf("inbox delivery from new position %d: %v", sender.newPos, err)
			}
			if err := receiver.inbox.accept(message); err != nil {
				t.Fatalf("inbox replay of a seen delta must be accepted idempotently: %v", err)
			}
		}
	}

	// Fold the delta mailboxes into each runner.
	for _, receiver := range members {
		for {
			var inbound tdilithium3DKGVerifiedMessage
			select {
			case inbound = <-receiver.inbox.messages:
			default:
				inbound = tdilithium3DKGVerifiedMessage{}
			}
			if inbound.Payload == nil {
				break
			}
			wire, err := dilithium3v1.UnmarshalReshareDeltaWire(inbound.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := receiver.runner.Receive(tdilithium3ReshareDeltaDelivery{
				RecipientPosition: wire.RecipientPosition,
				Delta: dilithium3v1.ReshareFoldDelta{
					Source:    wire.SourceGroup,
					Target:    wire.TargetGroup,
					Component: wire.Component,
				},
			}); err != nil {
				t.Fatalf("runner at new position %d: %v", receiver.newPos, err)
			}
		}
		if !receiver.runner.Ready() {
			t.Fatalf("runner at new position %d still pending deltas", receiver.newPos)
		}
	}

	// Everyone assembles byte-identical rotated components on the unchanged
	// key, preserving the generation.
	baseShare, err := members[0].runner.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(baseShare.Zeroize)
	if !bytes.Equal(baseShare.Key.PublicKey, fixture.groupKey) {
		t.Fatal("rotated share changed the group public key")
	}
	if baseShare.Key.Generation != fixture.shares[0].Key.Generation {
		t.Fatal("rotated share advanced the generation")
	}
	if baseShare.Committee.Version != newCommittee.Version || len(baseShare.Committee.Participants) != len(newParticipants) {
		t.Fatal("rotated share is not versioned as the six-member committee")
	}
	reference := map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent{}
	for _, component := range baseShare.Components {
		reference[component.GroupMask] = component
	}
	for _, member := range members[1:] {
		share, err := member.runner.Assemble()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(share.Zeroize)
		if err := share.Validate(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(share.Key.PublicKey, fixture.groupKey) {
			t.Fatal("a rotated member produced a divergent group key")
		}
		for _, component := range share.Components {
			want, found := reference[component.GroupMask]
			if !found {
				// Groups are member-specific; only the groups both members
				// hold are comparable row by row.
				continue
			}
			if component.S1 != want.S1 || component.S2 != want.S2 ||
				component.Multiplicity != want.Multiplicity ||
				component.ContributionDigest != want.ContributionDigest {
				t.Fatalf("cross-member disagreement on group %06b", uint16(component.GroupMask))
			}
		}
	}
}
