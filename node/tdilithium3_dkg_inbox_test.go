// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGInboxRejectsUntrustedAndReplayedMessages(t *testing.T) {
	session := testTDilithium3DKGSession()
	session.IdentityRosterDigest = testTDilithium3IdentityRosterDigest(t, session, "DEVNET ONLY inbox peer")
	var seed [mode3.SeedSize]byte
	copy(seed[:], "DEVNET ONLY inbox peer 0")
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	senderID := session.Committee.Participants[0]
	verifier := dilithium3v1.DKGIdentityVerifier(func(id uint32, message, signature []byte) bool {
		return id == senderID && mode3.Verify(publicKey, message, signature)
	})
	resolvePeer := func(peer p2p.PeerID) (uint32, bool) { return senderID, peer == "peer-0" }
	if _, err := newTDilithium3DKGInbox(session, 1, nil, resolvePeer); err == nil {
		t.Fatal("missing verifier accepted")
	}
	if _, err := newTDilithium3DKGInbox(session, 1, verifier, nil); err == nil {
		t.Fatal("missing peer binding accepted")
	}
	inbox, err := newTDilithium3DKGInbox(session, 1, verifier, resolvePeer)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(message []byte) ([]byte, error) {
		signature := make([]byte, mode3.SignatureSize)
		mode3.SignTo(privateKey, message, signature)
		return signature, nil
	}
	encode := func(sequence uint32, first byte) p2p.PeerMessage {
		t.Helper()
		payload := make([]byte, 32)
		payload[0] = first
		packet, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGRandomness, 0, sequence, payload, sign)
		if err != nil {
			t.Fatal(err)
		}
		return p2p.PeerMessage{From: "peer-0", Type: p2p.MsgTypeTDilithium3DKGRandomness, Payload: packet}
	}
	message := encode(1, 1)
	if err := inbox.accept(message); err != nil {
		t.Fatal(err)
	}
	if err := inbox.accept(message); err != nil {
		t.Fatal(err)
	}
	if len(inbox.messages) != 1 {
		t.Fatal("duplicate enqueued twice")
	}
	if err := inbox.accept(encode(1, 2)); err == nil {
		t.Fatal("conflicting sequence accepted")
	}
	wrongPeer := message
	wrongPeer.From = "peer-other"
	if err := inbox.accept(wrongPeer); err == nil {
		t.Fatal("unmapped source accepted")
	}
	identityChecks := 0
	guarded, err := newTDilithium3DKGInbox(session, 1, func(id uint32, signed, signature []byte) bool {
		identityChecks++
		return verifier(id, signed, signature)
	}, resolvePeer)
	if err != nil {
		t.Fatal(err)
	}
	if err := guarded.accept(wrongPeer); err == nil || identityChecks != 0 {
		t.Fatal("unmapped peer reached identity signature verification")
	}
	tampered := message
	tampered.Payload = append([]byte(nil), message.Payload...)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if err := inbox.accept(tampered); err == nil {
		t.Fatal("invalid signature accepted")
	}
	foreign := session.Clone()
	foreign.ChainID++
	foreignInbox, err := newTDilithium3DKGInbox(foreign, 1, verifier, resolvePeer)
	if err != nil {
		t.Fatal(err)
	}
	if err := foreignInbox.accept(message); err == nil {
		t.Fatal("foreign session accepted")
	}
	if err := inbox.accept(p2p.PeerMessage{From: "peer-0", Type: p2p.MsgTypeTDilithium3DKGActivation, Payload: message.Payload}); err == nil {
		t.Fatal("activation accepted")
	}
	sessionDigest, _ := session.Digest()
	committeeDigest, _ := session.Committee.CanonicalDigest()
	seedMessage := dilithium3v1.GroupSeedMessage{
		SessionDigest: sessionDigest, CommitteeDigest: committeeDigest,
		GroupMask: dilithium3v1.CanonicalRSSGroups()[0], LeaderPosition: 0,
		RecipientPosition: 2, Seed: [32]byte{4},
	}
	seedPayload, err := seedMessage.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	seedPacket, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, 0, 1, seedPayload, sign)
	if err != nil {
		t.Fatal(err)
	}
	privateMessage := p2p.PeerMessage{From: "peer-0", Type: p2p.MsgTypeTDilithium3DKGGroupSeed, Payload: seedPacket}
	if err := inbox.accept(privateMessage); err == nil {
		t.Fatal("seed addressed to another recipient accepted")
	}
	seedMessage.RecipientPosition = 1
	seedPayload, err = seedMessage.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	privateMessage.Payload, err = encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, 0, 1, seedPayload, sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.accept(privateMessage); err != nil {
		t.Fatal(err)
	}
	if (<-inbox.messages).Type != message.Type {
		t.Fatal("verified packet not delivered")
	}
	if (<-inbox.messages).Type != privateMessage.Type {
		t.Fatal("verified private packet not delivered")
	}
	followup := privateMessage
	followup.Payload, err = encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, 0, 2, seedPayload, sign)
	if err != nil {
		t.Fatal(err)
	}
	identities := make(map[uint32]tdilithium3DKGIdentity, len(session.Committee.Participants))
	for position, participantID := range session.Committee.Participants {
		var peerSeed [mode3.SeedSize]byte
		copy(peerSeed[:], fmt.Sprintf("DEVNET ONLY inbox peer %d", position))
		peerKey, _ := mode3.NewKeyFromSeed(&peerSeed)
		identities[participantID] = tdilithium3DKGIdentity{
			Peer:             p2p.PeerID(fmt.Sprintf("peer-%d", position)),
			ValidatorAddress: types.AddressFromPublicKey(peerKey.Bytes()), PublicKey: peerKey.Bytes(),
		}
	}
	boundInbox, err := newTDilithium3DKGInboxFromIdentitySnapshot(session, 1, identities)
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}, tdilithium3DKGInbox: boundInbox}
	node.handleTSSMessage(followup)
	if len(boundInbox.messages) != 0 {
		t.Fatal("disabled experimental backend accepted a packet")
	}
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	node.config.NetworkID = MainnetNetworkID
	node.handleTSSMessage(followup)
	if len(boundInbox.messages) != 0 {
		t.Fatal("mainnet accepted experimental DKG packet")
	}
	mainnetSession := session.Clone()
	mainnetSession.ChainID = MainnetNetworkID
	mainnetInbox, err := newTDilithium3DKGInboxFromIdentitySnapshot(mainnetSession, 1, identities)
	if err != nil {
		t.Fatal(err)
	}
	mainnetRandomness := make([]byte, 32)
	mainnetRandomness[0] = 3
	mainnetPacket, err := encodeTDilithium3DKGSignedEnvelope(mainnetSession, p2p.MsgTypeTDilithium3DKGRandomness, 0, 1, mainnetRandomness, sign)
	if err != nil {
		t.Fatal(err)
	}
	mainnetNode := &Node{config: &Config{NetworkID: MainnetNetworkID}, tdilithium3DKGInbox: mainnetInbox}
	mainnetNode.handleTSSMessage(p2p.PeerMessage{From: "peer-0", Type: p2p.MsgTypeTDilithium3DKGRandomness, Payload: mainnetPacket})
	if len(mainnetInbox.messages) != 0 {
		t.Fatal("mainnet session accepted experimental DKG packet")
	}
	(&Node{tdilithium3DKGInbox: mainnetInbox}).handleTSSMessage(p2p.PeerMessage{From: "peer-0", Type: p2p.MsgTypeTDilithium3DKGRandomness, Payload: mainnetPacket})
	if len(mainnetInbox.messages) != 0 {
		t.Fatal("missing network config accepted experimental DKG packet")
	}
	node.config.NetworkID = DevnetNetworkID
	node.handleTSSMessage(followup)
	if len(boundInbox.messages) != 0 {
		t.Fatal("foreign chain accepted DKG packet")
	}
	node.config.NetworkID = TestnetNetworkID
	node.handleTSSMessage(followup)
	if len(boundInbox.messages) != 1 {
		t.Fatal("node failed to route new DKG message")
	}
	node.handleTSSMessage(p2p.PeerMessage{From: "peer-other", Type: p2p.MsgTypeTDilithium3DKGRandomness, Payload: message.Payload})
	if len(boundInbox.messages) != 1 {
		t.Fatal("node routed an untrusted DKG message")
	}
	<-boundInbox.messages
	for range tdilithium3DKGInboxCapacity {
		inbox.messages <- tdilithium3DKGVerifiedMessage{Type: p2p.MsgTypeTDilithium3DKGGroupSeed}
	}
	next := privateMessage
	next.Payload, err = encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, 0, 3, seedPayload, sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.accept(next); err == nil {
		t.Fatal("full inbox accepted an extra packet")
	}
	<-inbox.messages
	if err := inbox.accept(next); err != nil {
		t.Fatalf("failed delivery poisoned replay state: %v", err)
	}
}
