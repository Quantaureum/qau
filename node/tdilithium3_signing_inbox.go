// Quantaureum Node source, version 1.0.0.
package node

// Node-side inbox of the signing executor (design note, Slice 4). It is the
// transport-bound counterpart of the wallet-side party: the four p2p kinds
// 97..100 reserved by R64 arrive here, and only a message that passes the whole
// inbound order reaches the slot driver's channel:
//
//	p2p structure and canonical payload (R64)
//	-> envelope context and sender membership (R65)
//	-> sender identity signature (R65)
//	-> source-peer binding (this snapshot)
//	-> sequence-keyed replay and equivocation table (this inbox)
//
// The inbox mirrors the DKG inbox: a per-session identity snapshot, a replay
// table, and a bounded channel of verified messages. Unlike the DKG ceremony,
// a slot binds only four signers of the committee, so the snapshot must cover
// those four; the slot's chain is bound by its session identifier, which hashes
// the signing request (including its chain ID), so the mainnet exclusion of the
// admissibility gate is the network check.
//
// Nothing here decides whether a slot is accepted: the party applies its own
// gate and its own round logic to every delivered message, and the reason codes
// it reports are the wallet side's bounded outcomes.

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
	tdilithium3SigningInboxCapacity  = 64
	tdilithium3SigningReplayCapacity = 256
)

// tdilithium3SigningWireKind maps one wallet-side round kind onto its p2p
// message type.
func tdilithium3SigningWireKind(kind uint16) (uint8, bool) {
	switch kind {
	case dilithium3v1.SigningExecutorKindCommit:
		return p2p.MsgTypeTDilithium3SigningCommit, true
	case dilithium3v1.SigningExecutorKindReveal:
		return p2p.MsgTypeTDilithium3SigningReveal, true
	case dilithium3v1.SigningExecutorKindAcceptance:
		return p2p.MsgTypeTDilithium3SigningAcceptance, true
	case dilithium3v1.SigningExecutorKindResponse:
		return p2p.MsgTypeTDilithium3SigningResponse, true
	default:
		return 0, false
	}
}

// tdilithium3SigningWalletKind maps one p2p message type back onto the
// wallet-side round kind the party consumes. The p2p validator pins the
// payload format of every kind, so the mapping is authoritative.
func tdilithium3SigningWalletKind(messageType uint8) (uint16, bool) {
	switch messageType {
	case p2p.MsgTypeTDilithium3SigningCommit:
		return dilithium3v1.SigningExecutorKindCommit, true
	case p2p.MsgTypeTDilithium3SigningReveal:
		return dilithium3v1.SigningExecutorKindReveal, true
	case p2p.MsgTypeTDilithium3SigningAcceptance:
		return dilithium3v1.SigningExecutorKindAcceptance, true
	case p2p.MsgTypeTDilithium3SigningResponse:
		return dilithium3v1.SigningExecutorKindResponse, true
	default:
		return 0, false
	}
}

// tdilithium3SigningIdentity is one signer's network identity: the peer its
// messages arrive from, its validator address, and its Dilithium3 public key.
// tdilithium3SigningIdentity binds one participant to the peer that speaks for
// it, its validator address, and its identity public key.
type tdilithium3SigningIdentity struct {
	Peer             p2p.PeerID
	ValidatorAddress types.Address
	PublicKey        []byte
}

// sessionTag returns a short, log-safe identifier of the inbox's session, so a
// trace line names which of the parallel candidate sessions it concerns.
func (inbox *tdilithium3SigningInbox) sessionTag() string {
	if inbox == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%x", inbox.context.SessionID[:6])
}

// tdilithium3SigningKindName renders one round kind for a trace line.
func tdilithium3SigningKindName(kind uint16) string {
	switch kind {
	case dilithium3v1.SigningExecutorKindCommit:
		return "commit"
	case dilithium3v1.SigningExecutorKindReveal:
		return "reveal"
	case dilithium3v1.SigningExecutorKindAcceptance:
		return "acceptance"
	case dilithium3v1.SigningExecutorKindResponse:
		return "response"
	default:
		return fmt.Sprintf("kind-%d", kind)
	}
}

// tdilithium3SigningVerifiedMessage is one inbound round message that passed
// every check of the inbox. Kind is the wallet-side round kind, so the slot
// driver hands it to the party without another mapping.
type tdilithium3SigningVerifiedMessage struct {
	Kind     uint16
	SenderID uint32
	Sequence uint32
	Payload  []byte
}

// tdilithium3SigningReplayKey identifies one logical message of one sender.
// The sequence is the sender's own order, so the kind is already bound by the
// envelope the digest covers.
type tdilithium3SigningReplayKey struct {
	senderID uint32
	sequence uint32
}

// tdilithium3SigningInbox authorizes and de-duplicates inbound round messages
// before any of them reaches a slot.
type tdilithium3SigningInbox struct {
	context        tdilithium3SigningContext
	rosterBound    bool
	verifyIdentity tdilithium3SigningIdentityVerifier
	resolvePeer    func(p2p.PeerID) (uint32, bool)
	messages       chan tdilithium3SigningVerifiedMessage

	mu   sync.Mutex
	seen map[tdilithium3SigningReplayKey][32]byte
}

// newTDilithium3SigningInboxFromIdentitySnapshot binds an inbox to the
// identities of the four active signers. The snapshot must cover every signer,
// bind every peer and every public key to exactly one participant, and parse
// every key; the resulting inbox is roster-bound and therefore admissible on a
// live node.
func newTDilithium3SigningInboxFromIdentitySnapshot(
	context tdilithium3SigningContext,
	identities map[uint32]tdilithium3SigningIdentity,
) (*tdilithium3SigningInbox, error) {
	if err := context.Validate(); err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("Dilithium3 signing identity snapshot is empty")
	}
	peers := make(map[p2p.PeerID]uint32, len(identities))
	keys := make(map[uint32]*qcrypto.PublicKey, len(identities))
	keyHashes := make(map[[32]byte]bool, len(identities))
	for participantID, identity := range identities {
		if participantID == 0 || identity.Peer == "" {
			return nil, fmt.Errorf("Dilithium3 signing identity is incomplete")
		}
		if _, duplicate := peers[identity.Peer]; duplicate {
			return nil, fmt.Errorf("Dilithium3 signing peer bound to multiple participants")
		}
		key, err := qcrypto.PublicKeyFromBytes(identity.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("Dilithium3 signing participant public key invalid: %w", err)
		}
		keyHash := sha3.Sum256(identity.PublicKey)
		if keyHashes[keyHash] {
			return nil, fmt.Errorf("Dilithium3 signing public key bound to multiple participants")
		}
		keyHashes[keyHash] = true
		peers[identity.Peer] = participantID
		keys[participantID] = key
	}
	for _, signer := range context.Signers {
		if _, found := keys[signer]; !found {
			return nil, fmt.Errorf("Dilithium3 signing identity snapshot is missing signer %d", signer)
		}
	}
	verify := func(participantID uint32, message, signature []byte) bool {
		key, found := keys[participantID]
		return found && qcrypto.Verify(key, message, signature)
	}
	resolve := func(peer p2p.PeerID) (uint32, bool) {
		participantID, found := peers[peer]
		return participantID, found
	}
	inbox, err := newTDilithium3SigningInbox(context, verify, resolve)
	if err != nil {
		return nil, err
	}
	inbox.rosterBound = true
	return inbox, nil
}

// newTDilithium3SigningInbox builds an inbox from a caller-supplied verifier
// and peer binding. It is not roster-bound, so the admissibility gate refuses
// it on a live node; tests and the snapshot constructor are its callers.
func newTDilithium3SigningInbox(
	context tdilithium3SigningContext,
	verifier tdilithium3SigningIdentityVerifier,
	resolvePeer func(p2p.PeerID) (uint32, bool),
) (*tdilithium3SigningInbox, error) {
	if err := context.Validate(); err != nil {
		return nil, err
	}
	if verifier == nil || resolvePeer == nil {
		return nil, fmt.Errorf("Dilithium3 signing inbox requires an identity verifier and a peer binding")
	}
	return &tdilithium3SigningInbox{
		context:        context,
		verifyIdentity: verifier,
		resolvePeer:    resolvePeer,
		messages:       make(chan tdilithium3SigningVerifiedMessage, tdilithium3SigningInboxCapacity),
		seen:           make(map[tdilithium3SigningReplayKey][32]byte),
	}, nil
}

// tdilithium3SigningInboxForSession returns the registered inbox of one signing
// session, or nil when no session with that id is running. Inbound routing
// looks the inbox up by the session id carried in the envelope, so concurrent
// candidate sessions each receive only their own messages.
func (n *Node) tdilithium3SigningInboxForSession(sessionID [32]byte) *tdilithium3SigningInbox {
	if n == nil {
		return nil
	}
	n.tdilithium3SigningInboxMu.RLock()
	defer n.tdilithium3SigningInboxMu.RUnlock()
	return n.tdilithium3SigningInboxes[sessionID]
}

// tdilithium3SigningInboxSnapshot returns one registered signing inbox, or nil
// when none is running. It exists for callers and tests that operate a single
// session; routing of concurrent sessions uses tdilithium3SigningInboxForSession.
func (n *Node) tdilithium3SigningInboxSnapshot() *tdilithium3SigningInbox {
	if n == nil {
		return nil
	}
	n.tdilithium3SigningInboxMu.RLock()
	defer n.tdilithium3SigningInboxMu.RUnlock()
	for _, inbox := range n.tdilithium3SigningInboxes {
		return inbox
	}
	return nil
}

// registerTDilithium3SigningInbox publishes one session's authenticated signing
// inbox under its session id. The slot owner is its only writer, and it clears
// the entry with unregisterTDilithium3SigningInbox when the session ends.
func (n *Node) registerTDilithium3SigningInbox(inbox *tdilithium3SigningInbox) {
	if n == nil || inbox == nil {
		return
	}
	n.tdilithium3SigningInboxMu.Lock()
	defer n.tdilithium3SigningInboxMu.Unlock()
	if n.tdilithium3SigningInboxes == nil {
		n.tdilithium3SigningInboxes = make(map[[32]byte]*tdilithium3SigningInbox)
	}
	n.tdilithium3SigningInboxes[inbox.context.SessionID] = inbox
}

// unregisterTDilithium3SigningInbox removes one session's inbox, but only when
// the registered inbox is still this one: a session id is unique per candidate,
// so this guards against a late unregister clearing a newer registration.
func (n *Node) unregisterTDilithium3SigningInbox(inbox *tdilithium3SigningInbox) {
	if n == nil || inbox == nil {
		return
	}
	n.tdilithium3SigningInboxMu.Lock()
	defer n.tdilithium3SigningInboxMu.Unlock()
	if n.tdilithium3SigningInboxes[inbox.context.SessionID] == inbox {
		delete(n.tdilithium3SigningInboxes, inbox.context.SessionID)
	}
}

// installTDilithium3SigningInbox registers one inbox, or clears every inbox when
// passed nil. It preserves the single-session lifecycle used by tests; the
// production seal path uses register / unregister so its concurrent sessions do
// not clear each other.
func (n *Node) installTDilithium3SigningInbox(inbox *tdilithium3SigningInbox) {
	if n == nil {
		return
	}
	if inbox == nil {
		n.tdilithium3SigningInboxMu.Lock()
		n.tdilithium3SigningInboxes = nil
		n.tdilithium3SigningInboxMu.Unlock()
		return
	}
	n.registerTDilithium3SigningInbox(inbox)
}

// tdilithium3SigningInboxAdmissible reports whether an already-snapshotted
// inbox may consume inbound round messages on this node: the inbox must be
// bound to a signer identity snapshot and the experimental Dilithium3 v1 gate
// must be open for this network (mainnet additionally requires the explicit
// QAU_ENABLE_TDILITHIUM3_V1_MAINNET acknowledgement).
func (n *Node) tdilithium3SigningInboxAdmissible(inbox *tdilithium3SigningInbox) bool {
	return n != nil && n.config != nil && inbox != nil &&
		inbox.rosterBound &&
		experimentalTDilithium3V1EnabledForNetwork(n.config.NetworkID)
}

func (n *Node) tdilithium3SigningInboundAllowed() bool {
	return n.tdilithium3SigningInboxAdmissible(n.tdilithium3SigningInboxSnapshot())
}

// accept verifies one inbound p2p message and hands it to the slot driver. An
// identical retransmission is idempotent, and a second, different payload for a
// sequence the sender already used is a conflict. Fresh messages are accepted
// in any arrival order -- the p2p transport may reorder them, and the sender's
// strictly increasing sequence is a framing property, not a receiver rule.
// Ordering cannot be a safety property here: a wrong-slot payload is refused by
// the party as unauthorized, and a second payload for one (slot, kind) is its
// conflict, both attributed by the party itself.
func (inbox *tdilithium3SigningInbox) accept(message p2p.PeerMessage) error {
	if inbox == nil {
		return fmt.Errorf("Dilithium3 signing inbox is missing")
	}
	kind, known := tdilithium3SigningWalletKind(message.Type)
	if !known {
		return fmt.Errorf("Dilithium3 signing inbox does not accept message type %d", message.Type)
	}
	peerSender, ok := inbox.resolvePeer(message.From)
	if !ok {
		tdilithium3SealTrace("inbox %s: inbound %s from unbound peer %s refused",
			inbox.sessionTag(), tdilithium3SigningKindName(kind), message.From)
		return fmt.Errorf("Dilithium3 signing source peer is not bound to a signer")
	}
	envelope, err := verifyTDilithium3SigningInbound(message.Type, message.Payload, inbox.context, inbox.verifyIdentity)
	if err != nil {
		tdilithium3SealTrace("inbox %s: inbound %s from signer %d refused: %v",
			inbox.sessionTag(), tdilithium3SigningKindName(kind), peerSender, err)
		return err
	}
	if peerSender != envelope.SenderID {
		return fmt.Errorf("Dilithium3 signing source peer does not match signed sender")
	}
	digest := sha3.Sum256(message.Payload)
	key := tdilithium3SigningReplayKey{senderID: envelope.SenderID, sequence: envelope.Sequence}
	inbox.mu.Lock()
	defer inbox.mu.Unlock()
	if prior, exists := inbox.seen[key]; exists {
		if prior != digest {
			return fmt.Errorf("conflicting Dilithium3 signing sequence")
		}
		return nil
	}
	if len(inbox.seen) >= tdilithium3SigningReplayCapacity {
		return fmt.Errorf("Dilithium3 signing replay window exhausted")
	}
	verified := tdilithium3SigningVerifiedMessage{
		Kind:     kind,
		SenderID: envelope.SenderID,
		Sequence: envelope.Sequence,
		Payload:  append([]byte(nil), envelope.Payload...),
	}
	select {
	case inbox.messages <- verified:
		inbox.seen[key] = digest
		tdilithium3SealTrace("inbox %s: accepted %s from signer %d",
			inbox.sessionTag(), tdilithium3SigningKindName(kind), verified.SenderID)
		return nil
	default:
		tdilithium3SealTrace("inbox %s: full, dropped %s from signer %d",
			inbox.sessionTag(), tdilithium3SigningKindName(kind), verified.SenderID)
		return fmt.Errorf("Dilithium3 signing inbox full")
	}
}
