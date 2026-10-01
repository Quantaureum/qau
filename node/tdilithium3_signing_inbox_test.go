// Quantaureum Node source, version 1.0.0.
package node

// Tests of the node-side signing executor inbox: only a message that is bound
// to the signing context, signed by the peer that sent it, and carries the
// sender's next sequence reaches the slot driver's channel.

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3SigningInboxTestFixture binds one signing context to four
// deterministic DEVNET ONLY identities and their signing callbacks.
type tdilithium3SigningInboxTestFixture struct {
	context    tdilithium3SigningContext
	identities map[uint32]tdilithium3SigningIdentity
	publicKeys map[uint32]*mode3.PublicKey
	signers    map[uint32]func([]byte) ([]byte, error)
}

func tdilithium3SigningInboxTestFixtureFor(t *testing.T) *tdilithium3SigningInboxTestFixture {
	t.Helper()
	context := tdilithium3SigningContext{
		SessionID:        [32]byte{0x57, 0x11},
		KeyGeneration:    7,
		CommitteeVersion: 3,
		Signers:          [4]uint32{1, 3, 5, 8},
	}
	identities := make(map[uint32]tdilithium3SigningIdentity, len(context.Signers))
	publicKeys := make(map[uint32]*mode3.PublicKey, len(context.Signers))
	signers := make(map[uint32]func([]byte) ([]byte, error), len(context.Signers))
	for index, participantID := range context.Signers {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY signing identity %d", index))
		publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
		identities[participantID] = tdilithium3SigningIdentity{
			Peer:             p2p.PeerID(fmt.Sprintf("peer-%d", participantID)),
			ValidatorAddress: types.AddressFromPublicKey(publicKey.Bytes()),
			PublicKey:        publicKey.Bytes(),
		}
		publicKeys[participantID] = publicKey
		signers[participantID] = func(message []byte) ([]byte, error) {
			signature := make([]byte, mode3.SignatureSize)
			mode3.SignTo(privateKey, message, signature)
			return signature, nil
		}
	}
	return &tdilithium3SigningInboxTestFixture{
		context: context, identities: identities, publicKeys: publicKeys, signers: signers,
	}
}

// packet assembles one signed round message from one signer.
func (fixture *tdilithium3SigningInboxTestFixture) packet(
	t *testing.T,
	senderID uint32,
	messageType uint8,
	sequence uint32,
	payload []byte,
) p2p.PeerMessage {
	t.Helper()
	encoded, err := encodeTDilithium3SigningEnvelope(
		fixture.context, messageType, senderID, sequence, payload, fixture.signers[senderID],
	)
	if err != nil {
		t.Fatalf("encode kind %d: %v", messageType, err)
	}
	return p2p.PeerMessage{From: fixture.identities[senderID].Peer, Type: messageType, Payload: encoded}
}

// TestTDilithium3SigningInboxAcceptsVerifiedRoundMessages requires every round
// kind to reach the channel with its wallet-side kind, sender, sequence, and
// payload, requires an identical retransmission to be idempotent, a conflicting
// payload for a used sequence to be refused, and a fresh message to be accepted
// whatever its arrival order.
func TestTDilithium3SigningInboxAcceptsVerifiedRoundMessages(t *testing.T) {
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	inbox, err := newTDilithium3SigningInboxFromIdentitySnapshot(fixture.context, fixture.identities)
	if err != nil {
		t.Fatal(err)
	}
	kinds := []uint8{
		p2p.MsgTypeTDilithium3SigningCommit,
		p2p.MsgTypeTDilithium3SigningReveal,
		p2p.MsgTypeTDilithium3SigningAcceptance,
		p2p.MsgTypeTDilithium3SigningResponse,
	}
	wantKinds := []uint16{
		dilithium3v1.SigningExecutorKindCommit,
		dilithium3v1.SigningExecutorKindReveal,
		dilithium3v1.SigningExecutorKindAcceptance,
		dilithium3v1.SigningExecutorKindResponse,
	}
	var packets []p2p.PeerMessage
	for index, messageType := range kinds {
		payload := tdilithium3SigningTestPayload(t, messageType)
		packet := fixture.packet(t, 1, messageType, uint32(index+1), payload)
		if err := inbox.accept(packet); err != nil {
			t.Fatalf("kind %d: %v", messageType, err)
		}
		packets = append(packets, packet)
		verified := <-inbox.messages
		if verified.Kind != wantKinds[index] || verified.SenderID != 1 ||
			verified.Sequence != uint32(index+1) || string(verified.Payload) != string(payload) {
			t.Fatalf("kind %d: verified %+v", messageType, verified)
		}
		decodeVerifiedRoundMessage(t, verified)
	}
	// An identical retransmission is idempotent, so it is not queued twice.
	for _, packet := range packets {
		if err := inbox.accept(packet); err != nil {
			t.Fatalf("retransmission refused: %v", err)
		}
	}
	if len(inbox.messages) != 0 {
		t.Fatal("retransmissions were queued again")
	}
	// A second, different payload for a used sequence is a conflict.
	conflictPayload, err := dilithium3v1.EncodeSigningExecutorCommit(1, [32]byte{0x52})
	if err != nil {
		t.Fatal(err)
	}
	conflicting := fixture.packet(t, 1, kinds[0], 1, conflictPayload)
	if err := inbox.accept(conflicting); err == nil {
		t.Fatal("conflicting sequence accepted")
	}
	// Fresh messages are accepted in any arrival order: the p2p transport may
	// reorder them, and ordering is the party's concern, not the inbox's.
	outOfOrder := fixture.packet(t, 3, kinds[2], 7, tdilithium3SigningTestPayload(t, kinds[2]))
	if err := inbox.accept(outOfOrder); err != nil {
		t.Fatalf("out-of-order fresh message refused: %v", err)
	}
	if verified := <-inbox.messages; verified.SenderID != 3 || verified.Sequence != 7 {
		t.Fatalf("out-of-order message verified as %+v", verified)
	}
	// The same envelope is still idempotent, and the same sender may reuse its
	// own sequence space for another message.
	if err := inbox.accept(outOfOrder); err != nil {
		t.Fatalf("out-of-order retransmission refused: %v", err)
	}
	older := fixture.packet(t, 3, kinds[0], 2, tdilithium3SigningTestPayload(t, kinds[0]))
	if err := inbox.accept(older); err != nil {
		t.Fatalf("lower-sequence fresh message refused: %v", err)
	}
}

// TestTDilithium3SigningInboxRejectsUntrustedMessages requires every failed
// binding to be refused before delivery: unknown kinds, unmapped peers, peers
// bound to another signer, wrong identity keys, tampered payloads, and foreign
// sessions.
func TestTDilithium3SigningInboxRejectsUntrustedMessages(t *testing.T) {
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	kind := p2p.MsgTypeTDilithium3SigningCommit
	payload := tdilithium3SigningTestPayload(t, kind)
	valid := fixture.packet(t, 1, kind, 1, payload)

	if _, err := newTDilithium3SigningInbox(fixture.context, nil, func(p2p.PeerID) (uint32, bool) { return 1, true }); err == nil {
		t.Fatal("missing verifier accepted")
	}
	if _, err := newTDilithium3SigningInbox(fixture.context, func(uint32, []byte, []byte) bool { return true }, nil); err == nil {
		t.Fatal("missing peer binding accepted")
	}
	identityChecks := 0
	inbox, err := newTDilithium3SigningInbox(
		fixture.context,
		func(senderID uint32, message, signature []byte) bool {
			identityChecks++
			return verifyTDilithium3SigningTestIdentity(t, fixture, senderID, message, signature)
		},
		func(peer p2p.PeerID) (uint32, bool) {
			for participantID, identity := range fixture.identities {
				if identity.Peer == peer {
					return participantID, true
				}
			}
			return 0, false
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.accept(p2p.PeerMessage{From: "peer-1", Type: 101, Payload: valid.Payload}); err == nil {
		t.Fatal("unknown message type accepted")
	}
	unmapped := valid
	unmapped.From = "peer-other"
	if err := inbox.accept(unmapped); err == nil || identityChecks != 0 {
		t.Fatal("unmapped source reached identity verification or was accepted")
	}
	misbound := valid
	misbound.From = fixture.identities[3].Peer
	if err := inbox.accept(misbound); err == nil {
		t.Fatal("peer bound to another signer accepted")
	}
	wrongKey, err := encodeTDilithium3SigningEnvelope(
		fixture.context, kind, 1, 1, payload, fixture.signers[3],
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.accept(p2p.PeerMessage{From: fixture.identities[1].Peer, Type: kind, Payload: wrongKey}); err == nil {
		t.Fatal("wrong identity key accepted")
	}
	tampered := valid
	tampered.Payload = append([]byte(nil), valid.Payload...)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if err := inbox.accept(tampered); err == nil {
		t.Fatal("tampered payload accepted")
	}
	foreign := fixture.context
	foreign.SessionID = [32]byte{0x58}
	foreignPacket, err := encodeTDilithium3SigningEnvelope(foreign, kind, 1, 1, payload, fixture.signers[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.accept(p2p.PeerMessage{From: fixture.identities[1].Peer, Type: kind, Payload: foreignPacket}); err == nil {
		t.Fatal("foreign session accepted")
	}
	if err := inbox.accept(valid); err != nil {
		t.Fatalf("bound message refused: %v", err)
	}
}

// decodeVerifiedRoundMessage decodes one verified payload with the wallet-side
// decoder of its kind: the slot driver hands the payload to the party, so the
// cross-layer contract is that the wallet decoders accept it as it arrives.
func decodeVerifiedRoundMessage(t *testing.T, verified tdilithium3SigningVerifiedMessage) {
	t.Helper()
	switch verified.Kind {
	case dilithium3v1.SigningExecutorKindCommit:
		if _, _, err := dilithium3v1.DecodeSigningExecutorCommit(verified.Payload); err != nil {
			t.Fatalf("commit payload: %v", err)
		}
	case dilithium3v1.SigningExecutorKindReveal:
		if _, _, err := dilithium3v1.DecodeSigningExecutorReveal(verified.Payload); err != nil {
			t.Fatalf("reveal payload: %v", err)
		}
	case dilithium3v1.SigningExecutorKindAcceptance:
		if _, _, err := dilithium3v1.DecodeSigningExecutorAcceptance(verified.Payload); err != nil {
			t.Fatalf("acceptance payload: %v", err)
		}
	case dilithium3v1.SigningExecutorKindResponse:
		if _, _, err := dilithium3v1.DecodeSigningExecutorResponse(verified.Payload); err != nil {
			t.Fatalf("response payload: %v", err)
		}
	default:
		t.Fatalf("verified message carries unknown wallet kind %d", verified.Kind)
	}
}

// verifyTDilithium3SigningTestIdentity checks one test signature against the
// fixture's own public key for the claimed sender.
func verifyTDilithium3SigningTestIdentity(
	t *testing.T,
	fixture *tdilithium3SigningInboxTestFixture,
	senderID uint32,
	message, signature []byte,
) bool {
	t.Helper()
	publicKey, found := fixture.publicKeys[senderID]
	if !found {
		return false
	}
	return mode3.Verify(publicKey, message, signature)
}

// TestTDilithium3SigningInboxIdentitySnapshotBinding requires the snapshot
// constructor to refuse an incomplete snapshot, duplicate peers, duplicate
// keys, and degenerate keys, and requires a raw inbox to stay inadmissible.
func TestTDilithium3SigningInboxIdentitySnapshotBinding(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	incomplete := make(map[uint32]tdilithium3SigningIdentity, len(fixture.identities)-1)
	for participantID, identity := range fixture.identities {
		if participantID == fixture.context.Signers[3] {
			continue
		}
		incomplete[participantID] = identity
	}
	if _, err := newTDilithium3SigningInboxFromIdentitySnapshot(fixture.context, incomplete); err == nil {
		t.Fatal("incomplete snapshot accepted")
	}
	duplicatePeer := make(map[uint32]tdilithium3SigningIdentity, len(fixture.identities))
	for participantID, identity := range fixture.identities {
		duplicatePeer[participantID] = identity
	}
	identity := duplicatePeer[fixture.context.Signers[1]]
	identity.Peer = duplicatePeer[fixture.context.Signers[0]].Peer
	duplicatePeer[fixture.context.Signers[1]] = identity
	if _, err := newTDilithium3SigningInboxFromIdentitySnapshot(fixture.context, duplicatePeer); err == nil {
		t.Fatal("duplicate peer binding accepted")
	}
	duplicateKey := make(map[uint32]tdilithium3SigningIdentity, len(fixture.identities))
	for participantID, identity := range fixture.identities {
		duplicateKey[participantID] = identity
	}
	identity = duplicateKey[fixture.context.Signers[1]]
	identity.PublicKey = duplicateKey[fixture.context.Signers[0]].PublicKey
	duplicateKey[fixture.context.Signers[1]] = identity
	if _, err := newTDilithium3SigningInboxFromIdentitySnapshot(fixture.context, duplicateKey); err == nil {
		t.Fatal("duplicate identity key accepted")
	}
	degenerate := make(map[uint32]tdilithium3SigningIdentity, len(fixture.identities))
	for participantID, identity := range fixture.identities {
		degenerate[participantID] = identity
	}
	identity = degenerate[fixture.context.Signers[1]]
	identity.PublicKey = make([]byte, mode3.PublicKeySize)
	degenerate[fixture.context.Signers[1]] = identity
	if _, err := newTDilithium3SigningInboxFromIdentitySnapshot(fixture.context, degenerate); err == nil {
		t.Fatal("degenerate identity key accepted")
	}
	raw, err := newTDilithium3SigningInbox(
		fixture.context,
		func(uint32, []byte, []byte) bool { return true },
		func(p2p.PeerID) (uint32, bool) { return fixture.context.Signers[0], true },
	)
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	node.registerTDilithium3SigningInbox(raw)
	if node.tdilithium3SigningInboundAllowed() {
		t.Fatal("raw inbox bypassed identity snapshot binding")
	}
}

// TestTDilithium3SigningInboxRouting requires handleTSSMessage to feed the
// installed inbox only on an admissible node: a bound inbox on a testnet with
// the experimental gate open delivers, and the mainnet, the closed gate, and
// the empty node all drop.
func TestTDilithium3SigningInboxRouting(t *testing.T) {
	fixture := tdilithium3SigningInboxTestFixtureFor(t)
	newInbox := func(t *testing.T) *tdilithium3SigningInbox {
		t.Helper()
		inbox, err := newTDilithium3SigningInboxFromIdentitySnapshot(fixture.context, fixture.identities)
		if err != nil {
			t.Fatal(err)
		}
		return inbox
	}
	packet := fixture.packet(
		t, 1, p2p.MsgTypeTDilithium3SigningCommit, 1, tdilithium3SigningTestPayload(t, p2p.MsgTypeTDilithium3SigningCommit),
	)

	t.Run("testnet with the gate open", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
		node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
		node.installTDilithium3SigningInbox(newInbox(t))
		node.handleTSSMessage(packet)
		if len(node.tdilithium3SigningInboxSnapshot().messages) != 1 {
			t.Fatal("admissible inbox did not receive the message")
		}
	})

	t.Run("mainnet", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
		node := &Node{config: &Config{NetworkID: MainnetNetworkID}}
		node.installTDilithium3SigningInbox(newInbox(t))
		node.handleTSSMessage(packet)
		if len(node.tdilithium3SigningInboxSnapshot().messages) != 0 {
			t.Fatal("mainnet node consumed a signing message")
		}
	})

	t.Run("gate closed", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "0")
		node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
		node.installTDilithium3SigningInbox(newInbox(t))
		node.handleTSSMessage(packet)
		if len(node.tdilithium3SigningInboxSnapshot().messages) != 0 {
			t.Fatal("closed gate consumed a signing message")
		}
	})

	t.Run("no slot running", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
		node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
		node.handleTSSMessage(packet)
	})

	t.Run("clearing the inbox", func(t *testing.T) {
		t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
		node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
		node.installTDilithium3SigningInbox(newInbox(t))
		if node.tdilithium3SigningInboxSnapshot() == nil {
			t.Fatal("installed inbox is not visible")
		}
		node.installTDilithium3SigningInbox(nil)
		if node.tdilithium3SigningInboxSnapshot() != nil || node.tdilithium3SigningInboundAllowed() {
			t.Fatal("cleared inbox is still visible")
		}
	})
}
