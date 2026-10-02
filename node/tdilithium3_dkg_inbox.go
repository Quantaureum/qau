// Quantaureum Node source, version 1.0.0.
package node

import (
	"crypto/sha3"
	"fmt"
	"sync"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const (
	tdilithium3DKGInboxCapacity  = 64
	tdilithium3DKGReplayCapacity = 512
)

type tdilithium3DKGReplayKey struct {
	messageType uint8
	senderID    uint32
	sequence    uint32
	groupMask   dilithium3v1.RSSGroupMask
	attempt     uint8
}

type tdilithium3DKGVerifiedMessage struct {
	Type     uint8
	SenderID uint32
	Sequence uint32
	Payload  []byte
}

type tdilithium3DKGInbox struct {
	session           dilithium3v1.DKGSession
	recipientPosition uint8
	rosterBound       bool
	verifyIdentity    dilithium3v1.DKGIdentityVerifier
	resolvePeer       func(p2p.PeerID) (uint32, bool)
	messages          chan tdilithium3DKGVerifiedMessage
	mu                sync.Mutex
	seen              map[tdilithium3DKGReplayKey][32]byte
}

type tdilithium3DKGIdentity struct {
	Peer             p2p.PeerID
	ValidatorAddress types.Address
	PublicKey        []byte
}

func newTDilithium3DKGInboxFromIdentitySnapshot(session dilithium3v1.DKGSession, recipientPosition uint8, identities map[uint32]tdilithium3DKGIdentity) (*tdilithium3DKGInbox, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if len(identities) != len(session.Committee.Participants) {
		return nil, fmt.Errorf("Dilithium3 DKG identity snapshot must contain the entire committee")
	}
	peers := make(map[p2p.PeerID]uint32, len(identities))
	keys := make(map[uint32]*qcrypto.PublicKey, len(identities))
	keyHashes := make(map[[32]byte]bool, len(identities))
	bindings := make([]dilithium3v1.DKGIdentityBinding, 0, len(identities))
	for _, participantID := range session.Committee.Participants {
		identity, found := identities[participantID]
		if !found || identity.Peer == "" {
			return nil, fmt.Errorf("Dilithium3 DKG participant identity missing")
		}
		if _, duplicate := peers[identity.Peer]; duplicate {
			return nil, fmt.Errorf("Dilithium3 DKG peer bound to multiple participants")
		}
		key, err := qcrypto.PublicKeyFromBytes(identity.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("Dilithium3 DKG participant public key invalid: %w", err)
		}
		keyHash := sha3.Sum256(identity.PublicKey)
		if keyHashes[keyHash] {
			return nil, fmt.Errorf("Dilithium3 DKG public key bound to multiple participants")
		}
		keyHashes[keyHash] = true
		peers[identity.Peer] = participantID
		keys[participantID] = key
		bindings = append(bindings, dilithium3v1.DKGIdentityBinding{
			ParticipantID: participantID, ValidatorAddress: [20]byte(identity.ValidatorAddress), PublicKey: identity.PublicKey,
		})
	}
	rosterDigest, err := dilithium3v1.DKGIdentityRosterDigest(session.Committee, bindings)
	if err != nil || rosterDigest != session.IdentityRosterDigest {
		return nil, fmt.Errorf("Dilithium3 DKG identity snapshot does not match session roster")
	}
	verify := func(participantID uint32, message, signature []byte) bool {
		key, found := keys[participantID]
		return found && qcrypto.Verify(key, message, signature)
	}
	resolve := func(peer p2p.PeerID) (uint32, bool) {
		participantID, found := peers[peer]
		return participantID, found
	}
	inbox, err := newTDilithium3DKGInbox(session, recipientPosition, verify, resolve)
	if err != nil {
		return nil, err
	}
	inbox.rosterBound = true
	return inbox, nil
}

// tdilithium3DKGInboxSnapshot returns the installed Dilithium3 v1 DKG inbox, or
// nil when no ceremony is running. The inbox field is written by the ceremony
// goroutine and read by the TSS processing loop, so callers must never touch
// the field directly.
func (n *Node) tdilithium3DKGInboxSnapshot() *tdilithium3DKGInbox {
	if n == nil {
		return nil
	}
	n.tdilithium3DKGInboxMu.RLock()
	defer n.tdilithium3DKGInboxMu.RUnlock()
	return n.tdilithium3DKGInbox
}

// installTDilithium3DKGInbox publishes the node's authenticated DKG inbox.
// Passing nil clears it. The DKG ceremony is its only writer.
func (n *Node) installTDilithium3DKGInbox(inbox *tdilithium3DKGInbox) {
	if n == nil {
		return
	}
	n.tdilithium3DKGInboxMu.Lock()
	defer n.tdilithium3DKGInboxMu.Unlock()
	n.tdilithium3DKGInbox = inbox
}

// tdilithium3DKGInboxAdmissible reports whether an already-snapshotted inbox may
// consume inbound v1 messages on this node. It is separate from
// tdilithium3DKGInboundAllowed so a caller that has resolved the inbox once can
// authorize and deliver from the same snapshot instead of reading the field
// twice.
func (n *Node) tdilithium3DKGInboxAdmissible(inbox *tdilithium3DKGInbox) bool {
	return n != nil && n.config != nil && inbox != nil &&
		inbox.rosterBound &&
		n.config.NetworkID == inbox.session.ChainID &&
		experimentalTDilithium3V1EnabledForNetwork(n.config.NetworkID)
}

func (n *Node) tdilithium3DKGInboundAllowed() bool {
	return n.tdilithium3DKGInboxAdmissible(n.tdilithium3DKGInboxSnapshot())
}

func newTDilithium3DKGInbox(session dilithium3v1.DKGSession, recipientPosition uint8, verifier dilithium3v1.DKGIdentityVerifier, resolvePeer func(p2p.PeerID) (uint32, bool)) (*tdilithium3DKGInbox, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if recipientPosition >= uint8(len(session.Committee.Participants)) || verifier == nil || resolvePeer == nil {
		return nil, fmt.Errorf("Dilithium3 DKG inbox requires committee recipient, identity verifier and peer binding")
	}
	return &tdilithium3DKGInbox{
		session: session.Clone(), recipientPosition: recipientPosition,
		verifyIdentity: verifier, resolvePeer: resolvePeer,
		messages: make(chan tdilithium3DKGVerifiedMessage, tdilithium3DKGInboxCapacity),
		seen:     make(map[tdilithium3DKGReplayKey][32]byte),
	}, nil
}

func (inbox *tdilithium3DKGInbox) accept(message p2p.PeerMessage) error {
	if inbox == nil || message.Type == p2p.MsgTypeTDilithium3DKGActivation {
		return fmt.Errorf("Dilithium3 DKG inbox is disabled or message requires activation verification")
	}
	peerSender, ok := inbox.resolvePeer(message.From)
	if !ok {
		return fmt.Errorf("Dilithium3 DKG source peer is not bound to a participant")
	}
	var recipient *uint8
	if message.Type == p2p.MsgTypeTDilithium3DKGGroupSeed || message.Type == p2p.MsgTypeTDilithium3ReshareDelta {
		recipient = &inbox.recipientPosition
	}
	envelope, err := validateTDilithium3DKGInbound(message.Type, message.Payload, inbox.session, recipient, inbox.verifyIdentity)
	if err != nil {
		return err
	}
	if peerSender != envelope.SenderID {
		return fmt.Errorf("Dilithium3 DKG source peer does not match signed sender")
	}
	key := tdilithium3DKGReplayKey{messageType: message.Type, senderID: envelope.SenderID, sequence: envelope.Sequence}
	switch message.Type {
	case p2p.MsgTypeTDilithium3DKGGroupSeed:
		seed, err := dilithium3v1.UnmarshalGroupSeedMessage(envelope.Payload)
		if err != nil {
			return err
		}
		key.groupMask, key.attempt = seed.GroupMask, seed.Attempt
	case p2p.MsgTypeTDilithium3DKGAcknowledgement:
		acknowledgement, err := dilithium3v1.UnmarshalContributionAcknowledgement(envelope.Payload)
		if err != nil {
			return err
		}
		key.groupMask, key.attempt = acknowledgement.GroupMask, acknowledgement.Attempt
	case p2p.MsgTypeTDilithium3DKGComplaint:
		complaint, err := dilithium3v1.UnmarshalComplaint(envelope.Payload)
		if err != nil {
			return err
		}
		key.groupMask, key.attempt = complaint.GroupMask, complaint.Attempt
	case p2p.MsgTypeTDilithium3DKGContribution:
		contribution, err := dilithium3v1.UnmarshalPublicContribution(envelope.Payload)
		if err != nil {
			return err
		}
		key.groupMask = contribution.GroupMask
	case p2p.MsgTypeTDilithium3ReshareDelta:
		delta, err := dilithium3v1.UnmarshalReshareDeltaWire(envelope.Payload)
		if err != nil {
			return err
		}
		key.groupMask, key.attempt = delta.TargetGroup, delta.Kind^byte(uint16(delta.SourceGroup))
	}
	digest := sha3.Sum256(envelope.Payload)
	inbox.mu.Lock()
	defer inbox.mu.Unlock()
	if prior, exists := inbox.seen[key]; exists {
		if prior != digest {
			return fmt.Errorf("conflicting Dilithium3 DKG sequence")
		}
		return nil
	}
	if len(inbox.seen) >= tdilithium3DKGReplayCapacity {
		return fmt.Errorf("Dilithium3 DKG replay window exhausted")
	}
	copyMessage := tdilithium3DKGVerifiedMessage{
		Type: message.Type, SenderID: envelope.SenderID, Sequence: envelope.Sequence,
		Payload: append([]byte(nil), envelope.Payload...),
	}
	select {
	case inbox.messages <- copyMessage:
		inbox.seen[key] = digest
		return nil
	default:
		return fmt.Errorf("Dilithium3 DKG inbox full")
	}
}
