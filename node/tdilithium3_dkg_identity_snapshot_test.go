// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
)

func TestTDilithium3DKGIdentitySnapshot(t *testing.T) {
	session := testTDilithium3DKGSession()
	session.IdentityRosterDigest = testTDilithium3IdentityRosterDigest(t, session, "DEVNET ONLY snapshot identity")
	identities := make(map[uint32]tdilithium3DKGIdentity, 6)
	for position, participantID := range session.Committee.Participants {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY snapshot identity %d", position))
		publicKey, _ := mode3.NewKeyFromSeed(&seed)
		identities[participantID] = tdilithium3DKGIdentity{Peer: p2p.PeerID(string(rune('a' + position))), ValidatorAddress: types.AddressFromPublicKey(publicKey.Bytes()), PublicKey: publicKey.Bytes()}
	}
	if _, err := newTDilithium3DKGInboxFromIdentitySnapshot(session, 1, nil); err == nil {
		t.Fatal("incomplete snapshot accepted")
	}
	duplicate := make(map[uint32]tdilithium3DKGIdentity, len(identities))
	for id, identity := range identities {
		duplicate[id] = identity
	}
	identity := duplicate[session.Committee.Participants[1]]
	identity.Peer = duplicate[session.Committee.Participants[0]].Peer
	duplicate[session.Committee.Participants[1]] = identity
	if _, err := newTDilithium3DKGInboxFromIdentitySnapshot(session, 1, duplicate); err == nil {
		t.Fatal("duplicate peer binding accepted")
	}
	identity.Peer = "b"
	identity.PublicKey = identities[session.Committee.Participants[0]].PublicKey
	duplicate[session.Committee.Participants[1]] = identity
	if _, err := newTDilithium3DKGInboxFromIdentitySnapshot(session, 1, duplicate); err == nil {
		t.Fatal("duplicate identity key accepted")
	}
	identity.PublicKey = make([]byte, mode3.PublicKeySize)
	duplicate[session.Committee.Participants[1]] = identity
	if _, err := newTDilithium3DKGInboxFromIdentitySnapshot(session, 1, duplicate); err == nil {
		t.Fatal("degenerate identity key accepted")
	}
	inbox, err := newTDilithium3DKGInboxFromIdentitySnapshot(session, 1, identities)
	if err != nil {
		t.Fatal(err)
	}
	otherAddress := make(map[uint32]tdilithium3DKGIdentity, len(identities))
	for id, entry := range identities {
		otherAddress[id] = entry
	}
	changedAddress := otherAddress[session.Committee.Participants[0]]
	changedAddress.ValidatorAddress[0] ^= 1
	otherAddress[session.Committee.Participants[0]] = changedAddress
	if _, err := newTDilithium3DKGInboxFromIdentitySnapshot(session, 1, otherAddress); err == nil {
		t.Fatal("identity address changed without changing session digest")
	}
	var alternateSeed [mode3.SeedSize]byte
	copy(alternateSeed[:], "DEVNET ONLY alternate snapshot key")
	alternateKey, _ := mode3.NewKeyFromSeed(&alternateSeed)
	changedAddress = identities[session.Committee.Participants[0]]
	changedAddress.PublicKey = alternateKey.Bytes()
	otherAddress[session.Committee.Participants[0]] = changedAddress
	if _, err := newTDilithium3DKGInboxFromIdentitySnapshot(session, 1, otherAddress); err == nil {
		t.Fatal("historical identity key changed without changing session digest")
	}
	identity = identities[session.Committee.Participants[0]]
	identity.PublicKey[0] ^= 1
	delete(identities, session.Committee.Participants[0])
	var seed [mode3.SeedSize]byte
	copy(seed[:], "DEVNET ONLY snapshot identity 0")
	_, privateKey := mode3.NewKeyFromSeed(&seed)
	sign := func(message []byte) ([]byte, error) {
		signature := make([]byte, mode3.SignatureSize)
		mode3.SignTo(privateKey, message, signature)
		return signature, nil
	}
	payload := make([]byte, 32)
	payload[0] = 1
	encoded, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGRandomness, 0, 1, payload, sign)
	if err != nil {
		t.Fatal(err)
	}
	packet := p2p.PeerMessage{From: "a", Type: p2p.MsgTypeTDilithium3DKGRandomness, Payload: encoded}
	if err := inbox.accept(packet); err != nil {
		t.Fatalf("immutable snapshot rejected valid sender: %v", err)
	}
	packet.From = "c"
	if err := inbox.accept(packet); err == nil {
		t.Fatal("misbound peer accepted a signed envelope")
	}
	packet.From = "a"
	seed = [mode3.SeedSize]byte{}
	copy(seed[:], "DEVNET ONLY snapshot identity 1")
	_, privateKey = mode3.NewKeyFromSeed(&seed)
	encoded, err = encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGRandomness, 0, 1, payload, sign)
	if err != nil {
		t.Fatal(err)
	}
	packet.Payload = encoded
	if err := inbox.accept(packet); err == nil {
		t.Fatal("wrong identity key accepted a signed envelope")
	}
}

func TestTDilithium3DKGUnboundInboxCannotEnterNetwork(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	session := testTDilithium3DKGSession()
	inbox, err := newTDilithium3DKGInbox(session, 0, func(uint32, []byte, []byte) bool { return true }, func(p2p.PeerID) (uint32, bool) { return session.Committee.Participants[0], true })
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}, tdilithium3DKGInbox: inbox}
	if node.tdilithium3DKGInboundAllowed() {
		t.Fatal("raw inbox bypassed roster binding")
	}
}
