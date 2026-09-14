// Quantaureum Node source, version 1.0.0.
// Package gossipsub implements the GossipSub v1.1 protocol for Quantaureum.
//
// GossipSub is a decentralized, peer-to-peer pubsub protocol designed for
// blockchain networks. It uses a mesh overlay network where each peer
// maintains a subset of connections (mesh) for each topic it subscribes to.
//
// Key features:
//   - Topic-based message routing: Block/Tx/Vote/Attestation on separate topics
//   - Mesh overlay: Each topic has 6-12 mesh peers for efficient propagation
//   - Graft/Prune: Dynamic mesh maintenance based on peer score
//   - Heartbeat: Periodic mesh health checks (1 second interval)
//   - Fanout: Messages forwarded to D (6) non-mesh peers for redundancy
//   - IWANT/IHAVE: Pull-based message retrieval for missed messages
//
// Phase 2: This implementation wraps the existing P2P transport layer
// (encrypted TCP + Dilithium3 auth) and adds GossipSub message routing on top.
// It does NOT replace the transport — it enhances message propagation efficiency.
package gossipsub

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// ProtocolID is the GossipSub protocol identifier
	ProtocolID = "/qau/gossipsub/1.1.0"

	// Mesh parameters
	GossipSubD     = 6  // Desired mesh size (low side)
	GossipSubDHi   = 12 // Max mesh size before pruning (high side)
	GossipSubDLo   = 4  // Min mesh size before grafting (low threshold)
	GossipSubDLazy = 6  // Lazy mode: graft if below this threshold

	// Fanout parameters
	GossipSubFanoutTTL    = 60 * time.Second // Fanout expiry time
	GossipSubGossipFactor = 0.25             // Fraction of peers to gossip to
	GossipSubPruneBackoff = 1 * time.Minute  // Time before allowing re-graft

	// Heartbeat
	GossipSubHeartbeatInterval = 1 * time.Second

	// Message cache
	// AUDIT (2026) R3-P2P-04 FIX: Bumped from 5 to 100. The previous
	// value of 5 was far below realistic propagation fan-out: with even a
	// modest mesh of D=6 peers, the same block/tx arrives from multiple
	// peers within milliseconds, exhausting the 5-entry dedup window in
	// well under a heartbeat. Once the window rolls over, the same message
	// is re-delivered to handlers and re-forwarded to the mesh, enabling
	// amplification. 100 covers the IHAVE advertisement window comfortably.
	GossipSubHistoryLength = 100 // Number of recent messages to cache per topic (IHAVE)
	GossipSubHistoryGossip = 3   // Number of history windows to gossip in IHAVE

	// AUDIT (2026) R3-P2P-04 FIX: Dedup cache parameters, separate
	// from the IHAVE cache. The IHAVE cache is bounded by HistoryLength
	// (100 entries) and serves peer advertisement queries. The dedup
	// cache is bounded by MaxSeenMessages + MessageDedupTTL and prevents
	// the same MessageID from being delivered to handlers or re-forwarded
	// to the mesh within the TTL window. With 12s block times and bursty
	// tx traffic, a 2-minute TTL covers ~10 blocks of propagation slack
	// while keeping per-topic memory bounded.
	GossipSubMessageDedupTTL = 2 * time.Minute
	GossipSubMaxSeenMessages = 5000 // Safety cap per topic (TTL normally bounds growth)

	// IWANT
	GossipSubIWantLimit       = 256 // Max IWANT messages per heartbeat
	GossipSubIWantPeerTimeout = 3 * time.Second

	// R5-P4-2: Control message limits to prevent DoS via oversized ControlMessage.
	// A malicious peer could send a ControlMessage with extremely large
	// Graft/Prune/IHave/IWant arrays, causing excessive processing. These
	// limits cap the number of each control type processed per message.
	GossipSubMaxGrafts = 100 // Max GRAFT messages per ControlMessage
	GossipSubMaxPrunes = 100 // Max PRUNE messages per ControlMessage
	GossipSubMaxIHave  = 100 // Max IHAVE messages per ControlMessage
	GossipSubMaxIWant  = 100 // Max IWANT messages per ControlMessage

	// SECURITY (audit P2P-10): Bounds applied at decode time to prevent
	// unbounded memory allocation from peer-supplied uint16 counts. Without
	// these caps, a malicious peer can force ~24× instantaneous memory
	// amplification by declaring large counts in a small packet.
	GossipSubMaxMessages       = 100 // Max published messages per RPC
	GossipSubMaxMsgIDsPerIHave = 256 // Max MessageIDs per IHAVE entry
	GossipSubMaxMsgIDsPerIWant = 256 // Max MessageIDs per IWANT entry

	// N5 FIX (2026-07-06 R2): Maximum message size for GossipSub.
	// Defense-in-depth: even if the encrypted transport allows larger messages,
	// the protocol layer enforces a hard cap to prevent memory exhaustion.
	MaxMessageSize = 10 * 1024 * 1024 // 10MB
)

// =============================================================================
// Topic Names
// =============================================================================

// Standard GossipSub topic names for Quantaureum
const (
	TopicBlocks             = "qau_blocks_v1"
	TopicTransactions       = "qau_txs_v1"
	TopicVotes              = "qau_votes_v1"
	TopicAttestations       = "qau_attestations_v1"
	TopicShardBlocks        = "qau_shard_blocks_v1"     // P1-1: shard block propagation
	TopicCrossShardMessages = "qau_cross_shard_msgs_v1" // P1-1: cross-shard message relay
	// P2P-R13-CRIT-003 (2026-07-21, R12-H02 regression fix): CRL
	// revocation list propagation topic. Peers periodically broadcast
	// their local CRL snapshot on this topic so that a revocation
	// performed on Node A propagates to Node B without operator
	// intervention. The snapshot is monotonic (only adds, never removes)
	// so a malicious peer cannot un-revoke a cert.
	TopicCRL = "qau_crl_v1"
)

// PayloadSignatureVerifier verifies the cryptographic signature embedded
// in a GossipSub message payload before the message is delivered to
// handlers or forwarded to the mesh.
//
// P2P-R11-CRIT-001 (2026-07-20) FIX: GossipSub previously only validated
// message size, format, and replay — never the payload signature. mTLS
// authenticates the connection, but a compromised peer can still inject
// forged payloads. This verifier provides defense-in-depth by dropping
// forged payloads at the first hop.
//
// Returns nil if the payload's signature is valid (or if the topic does
// not require signature verification). Returns a non-nil error if the
// signature is missing, malformed, or fails verification — the caller
// MUST drop the message and penalize the source peer.
//
// Implementations MUST be safe for concurrent use.
type PayloadSignatureVerifier interface {
	// VerifyPayload verifies the payload for the given topic.
	// topic is one of the TopicBlocks / TopicVotes / TopicTransactions /
	// TopicAttestations constants (or a custom topic).
	VerifyPayload(topic string, payload []byte) error
}

// isAllowedTopic checks if a topic name is in the whitelist.
// SECURITY (audit 2026-06-24, M-3): Prevent unauthorized topics from being
// used for mesh maintenance or message delivery.
func isAllowedTopic(topicName string) bool {
	switch topicName {
	case TopicBlocks, TopicTransactions, TopicVotes, TopicAttestations,
		TopicShardBlocks, TopicCrossShardMessages, TopicCRL:
		return true
	default:
		return false
	}
}

// IsAllowedTopic is the exported form of isAllowedTopic for use by external
// packages (e.g., tests that verify topic whitelisting without constructing
// a full GossipSub router).
//
// P2P-R13-CRIT-003 (2026-07-21).
func IsAllowedTopic(topicName string) bool {
	return isAllowedTopic(topicName)
}

// =============================================================================
// Message ID
// =============================================================================

// MessageID is a unique identifier for a GossipSub message (32 bytes)
type MessageID [32]byte

// String returns the hex representation of the MessageID
func (id MessageID) String() string {
	return hex.EncodeToString(id[:])
}

// ComputeMessageID computes a SHA3-256 based message ID from topic + data
func ComputeMessageID(topic string, data []byte) MessageID {
	// Use the existing hash from p2p package
	h := hashMessage(topic, data)
	var id MessageID
	copy(id[:], h)
	return id
}

// =============================================================================
// Peer ID (compatible with p2p.PeerID)
// =============================================================================

// PeerID is a string-based peer identifier compatible with p2p.PeerID
type PeerID = string

// =============================================================================
// Message structure
// =============================================================================

// Message represents a GossipSub message
type Message struct {
	// MessageID is the unique ID of this message
	ID MessageID
	// Topic is the topic this message belongs to
	Topic string
	// Data is the raw message payload
	Data []byte
	// From is the peer that sent this message (set by router)
	From PeerID
	// SeqNo is the sequence number assigned by the originator
	SeqNo uint64
	// ReceivedAt is when this message was received
	ReceivedAt time.Time
}

// =============================================================================
// RPC structure for GossipSub control messages
// =============================================================================

// RPC encapsulates all GossipSub control messages in a single exchange
type RPC struct {
	// Messages contains the actual data messages
	Messages []*Message
	// Control contains graft/prune/ihave/iwant messages
	Control *ControlMessage
}

// ControlMessage contains mesh maintenance messages
type ControlMessage struct {
	// Graft is a list of topics the sender wants to join our mesh for
	Graft []*ControlGraft
	// Prune is a list of topics the sender wants to leave our mesh for
	Prune []*ControlPrune
	// IHave announces message IDs the sender has
	IHave []*ControlIHave
	// IWant requests specific message IDs
	IWant []*ControlIWant
}

// ControlGraft notifies a peer that we want to join their mesh
type ControlGraft struct {
	Topic string
}

// ControlPrune notifies a peer that we are leaving their mesh
type ControlPrune struct {
	Topic  string
	Reason string
}

// ControlIHave announces available message IDs
type ControlIHave struct {
	Topic      string
	MessageIDs []MessageID
}

// ControlIWant requests specific message IDs
type ControlIWant struct {
	MessageIDs []MessageID
}

// =============================================================================
// Peer State
// =============================================================================

// peerState tracks a peer's relationship with this node
type peerState struct {
	id PeerID

	// Topics this peer subscribes to
	topics map[string]*topicState

	// If true, this peer is in our mesh for the given topic
	// (tracked per topic via the topics map)

	mu sync.RWMutex
}

// topicState tracks the relationship with a peer for a specific topic
type topicState struct {
	topic string

	// Whether this peer is in our mesh for this topic
	inMesh bool

	// When we last sent a graft to this peer (for backoff)
	graftTime time.Time

	// When we last sent a prune to this peer (for backoff)
	pruneTime time.Time

	// Peer score for this topic (updated by scorer)
	score float64
}

// =============================================================================
// Topic
// =============================================================================

// Topic represents a GossipSub topic with its mesh overlay
type Topic struct {
	name string
	gs   *GossipSub

	// Mesh peers: peers we are connected to for this topic
	mesh   map[PeerID]*peerState
	meshMu sync.RWMutex

	// Fanout peers: peers we forward to when not in full mesh
	fanout   map[PeerID]time.Time
	fanoutMu sync.RWMutex

	// Message cache for IHAVE announcements
	messageCache []*Message
	cacheMu      sync.RWMutex

	// AUDIT (2026) R3-P2P-04 FIX: Dedicated dedup cache, separate from
	// the IHAVE cache. The IHAVE cache is bounded by HistoryLength (100
	// entries) and serves peer advertisement queries — it is intentionally
	// small. The dedup cache below is bounded by MessageDedupTTL +
	// MaxSeenMessages and prevents the same MessageID from being delivered
	// to handlers or re-forwarded to the mesh within the TTL window.
	// Previously, both functions shared the same 5-entry slice, so under
	// any realistic fan-out the window rolled over in milliseconds and
	// duplicates were re-delivered/re-forwarded, enabling amplification.
	seenMessages map[MessageID]time.Time

	// P2P-H04 FIX (R29, 2026-07-26): Mesh message-delivery deficit tracking.
	//
	// windowDeliveredMsgIDs records the MessageIDs that the GossipSub
	// router delivered to handlers during the current heartbeat window,
	// along with the peer that delivered each message. When a new message
	// is delivered, every mesh peer EXCEPT the delivering peer is
	// recorded as "potentially missing" this message; the next message
	// from that peer clears the entry. At heartbeat time, any message
	// still in deliveredMsgPeers with only one peer (the original
	// deliverer) counts as a "missing forward" for every OTHER mesh
	// peer that was in the mesh at the time.
	//
	// To keep memory bounded, we cap the map at windowMsgCap entries
	// (oldest evicted) and prune entries older than windowMsgTTL at
	// each heartbeat.
	deliveredMsgPeers   map[MessageID]map[PeerID]time.Time
	deliveredMsgPeersMu sync.Mutex
	windowDeliveries    int // total messages delivered in current window
	windowMsgCap        int
	windowMsgTTL        time.Duration

	// Sequence number counter
	seqNo uint64
}

// =============================================================================
// GossipSub Router
// =============================================================================

// MessageHandler is called when a new message arrives on a topic
type MessageHandler func(msg *Message)

// TopicMessageValidator validates a GossipSub message's content before it is
// delivered to handlers or forwarded to the mesh.
//
// AUDIT (2026) R4-P2P-03: GossipSub previously forwarded all messages
// unconditionally — there was no validation gate between receiving a message
// and calling forwardMessage. A malicious peer could inject malformed
// blocks/txs and have them propagated to the entire mesh, wasting bandwidth
// and forcing every node to perform expensive validation. The validator gate
// pushes validation to the edge: invalid messages are dropped at the first
// hop and the source peer is penalized via RecordInvalidMessage.
//
// The validator is optional. When nil (the default), all messages pass —
// preserving backward compatibility. The node layer is expected to wire up
// a real validator that performs topic-specific checks (block signature,
// transaction structure, vote attestation, etc.).
//
// ValidateMessage returns nil if the message is valid and may be delivered
// and forwarded. A non-nil error means the message is invalid; it will be
// dropped, not forwarded, and the source peer's score will be decremented.
type TopicMessageValidator interface {
	ValidateMessage(msg *Message) error
}

// noOpValidator is the default validator that accepts every message.
// Used when no validator is configured, preserving backward compatibility.
type noOpValidator struct{}

func (noOpValidator) ValidateMessage(msg *Message) error { return nil }

// Config holds GossipSub configuration
type Config struct {
	// D is the desired mesh size
	D int
	// DHi is the max mesh size before pruning
	DHi int
	// DLo is the min mesh size before grafting
	DLo int
	// HeartbeatInterval is the interval between heartbeats
	HeartbeatInterval time.Duration
	// HistoryLength is the number of messages to cache per topic
	HistoryLength int
	// FanoutTTL is how long fanout entries live
	FanoutTTL time.Duration
	// PruneBackoff is the minimum time between prune and re-graft
	PruneBackoff time.Duration

	// AUDIT (2026) R3-P2P-04 FIX: Dedup cache parameters.
	// MessageDedupTTL is how long a MessageID stays in the dedup cache.
	// MaxSeenMessages is a hard cap on dedup cache size per topic (safety
	// valve in case TTL pruning falls behind or message rate spikes).
	MessageDedupTTL time.Duration
	MaxSeenMessages int
}

// DefaultConfig returns the recommended GossipSub configuration
func DefaultConfig() *Config {
	return &Config{
		D:                 GossipSubD,
		DHi:               GossipSubDHi,
		DLo:               GossipSubDLo,
		HeartbeatInterval: GossipSubHeartbeatInterval,
		HistoryLength:     GossipSubHistoryLength,
		FanoutTTL:         GossipSubFanoutTTL,
		PruneBackoff:      GossipSubPruneBackoff,
		MessageDedupTTL:   GossipSubMessageDedupTTL,
		MaxSeenMessages:   GossipSubMaxSeenMessages,
	}
}

// iwantRateTracker tracks per-peer IWANT request counts within a time window
// to prevent a single peer from flooding the network with IWANT requests.
type iwantRateTracker struct {
	count     int
	windowEnd time.Time
}

// graftRateTracker tracks per-peer GRAFT request counts within a time window
// to prevent a single peer from flooding the mesh with GRAFT requests.
//
// P2P-R12-M01 (2026-07-20) FIX: Previously, handleGraft had no per-peer
// rate limit. The existing GossipSubMaxGrafts cap (100 per ControlMessage)
// only bounds one RPC, but a malicious peer can send many small RPCs each
// carrying 1-2 GRAFTs, repeatedly churning the mesh (graft → prune → graft)
// and consuming CPU. This tracker applies the same per-peer sliding-window
// pattern already used for IWANT to GRAFT messages.
type graftRateTracker struct {
	count     int
	windowEnd time.Time
}

// ihaveRateTracker tracks per-peer IHAVE message-ID processing counts within
// a time window to prevent a single peer from flooding the node with IHAVE
// announcements containing many bogus message IDs.
//
// P2P-R16-M03 (2026-07-23) FIX: The existing per-RPC caps (GossipSubMaxIHave=100
// entries, GossipSubMaxMsgIDsPerIHave=256 IDs per entry) bound a single control
// message, but a peer can send many RPCs per second. Each announced message ID
// triggers a hasSeenMessage cache lookup, so 100×256=25600 lookups per RPC at
// high RPC rate consumes significant CPU. The IWANT *response* is already
// rate-limited (GossipSubIWantLimit=256 per heartbeat + iwantRateLimit), but
// the IHAVE *processing* cost was not. This tracker caps the total number of
// IHAVE-advertised message IDs processed per peer per window, mirroring the
// iwantRateTracker pattern.
type ihaveRateTracker struct {
	count     int
	windowEnd time.Time
}

// iwantPromise tracks an outstanding IWANT request so that peers who
// advertise a message via IHAVE but never deliver it can be penalized.
// P2P-H01 (R24, 2026-07-25).
type iwantPromise struct {
	peer   PeerID
	sentAt time.Time
}

// GossipSub is the main router implementing the GossipSub protocol
type GossipSub struct {
	cfg *Config

	// All known peers
	peers   map[PeerID]*peerState
	peersMu sync.RWMutex

	// All active topics
	topics   map[string]*Topic
	topicsMu sync.RWMutex

	// Message handlers per topic
	handlers   map[string]MessageHandler
	handlersMu sync.RWMutex

	// Peer connection interface (send messages to peers)
	sender MessageSender

	// Peer scorer for mesh maintenance decisions
	scorer *PeerScorer

	// AUDIT (2026) R4-P2P-03: Message validator gate. Runs BEFORE
	// forwardMessage so invalid messages are dropped at the first hop.
	// The source peer is penalized via RecordInvalidMessage. When nil, a
	// noOpValidator accepts every message (backward compatibility).
	// validatorMu guards validator so deliverMessage can read it without
	// holding gs.mu (which would block Start/Stop during slow handlers).
	validator   TopicMessageValidator
	validatorMu sync.RWMutex

	// P2P-R11-CRIT-001 (2026-07-20) FIX: Optional payload-level Dilithium3
	// signature verifier for GossipSub messages. When set, deliverMessage
	// invokes it AFTER the TopicMessageValidator passes (so format/size/
	// replay checks still run first), and drops messages whose signature
	// does not verify. When nil, behavior is unchanged (fail-open,
	// backward compatible).
	payloadVerifier   PayloadSignatureVerifier
	payloadVerifierMu sync.RWMutex

	// Per-peer IWANT rate limiting (audit 2026-06-24, L-3)
	iwantRateLimit map[PeerID]*iwantRateTracker
	iwantRateMu    sync.Mutex

	// P2P-R12-M01 (2026-07-20): Per-peer GRAFT rate limiting. Same
	// sliding-window pattern as iwantRateLimit. See graftRateTracker
	// doc comment for the attack this prevents.
	graftRateLimit map[PeerID]*graftRateTracker
	graftRateMu    sync.Mutex

	// P2P-R16-M03 (2026-07-23): Per-peer IHAVE rate limiting. Same
	// sliding-window pattern as iwantRateLimit/graftRateLimit. See
	// ihaveRateTracker doc comment for the amplification attack this
	// prevents.
	ihaveRateLimit map[PeerID]*ihaveRateTracker
	ihaveRateMu    sync.Mutex

	// P2P-H01 (R24, 2026-07-25): IWANT broken-promise tracking. When we
	// send an IWANT for a message ID to a peer (because they advertised
	// it via IHAVE), we record a promise here. When the message arrives
	// (deliverMessage), the promise is fulfilled (deleted). The heartbeat
	// sweeps expired promises — any promise older than
	// GossipSubIWantPeerTimeout without fulfillment means the peer
	// advertised a message they never delivered, wasting our egress
	// IWANT and the ingress slot we reserved for the response. Each
	// broken promise incurs a RecordInvalidMessage penalty, eventually
	// pushing the peer below scoreGraylist so the mesh drops them.
	// Without this, a malicious peer could endlessly advertise bogus
	// IHAVEs to force us to send IWANTs (egress amplification + CPU on
	// our side to track and timeout) with no scoring consequence.
	iwantPromises   map[MessageID]*iwantPromise
	iwantPromisesMu sync.Mutex

	// Background context
	ctx    context.Context
	cancel context.CancelFunc

	// Whether GossipSub is running
	started bool
	mu      sync.Mutex

	// Wait group for background goroutines
	wg sync.WaitGroup
}

// MessageSender is the interface for sending messages to peers.
// Implemented by the P2P Host layer.
type MessageSender interface {
	// SendGossipSub sends a GossipSub RPC to a specific peer
	SendGossipSub(peerID PeerID, data []byte) error
	// GetConnectedPeers returns the list of currently connected peer IDs
	GetConnectedPeers() []PeerID
	// GetPeerScore returns the score for a peer (from existing scoring system)
	GetPeerScore(peerID PeerID) float64
}

// NewGossipSub creates a new GossipSub router
func NewGossipSub(cfg *Config, sender MessageSender) *GossipSub {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &GossipSub{
		cfg:            cfg,
		peers:          make(map[PeerID]*peerState),
		topics:         make(map[string]*Topic),
		handlers:       make(map[string]MessageHandler),
		sender:         sender,
		scorer:         NewPeerScorer(),
		validator:      noOpValidator{}, // R4-P2P-03: default accepts all messages
		iwantRateLimit: make(map[PeerID]*iwantRateTracker),
		graftRateLimit: make(map[PeerID]*graftRateTracker), // P2P-R12-M01
		ihaveRateLimit: make(map[PeerID]*ihaveRateTracker), // P2P-R16-M03
		iwantPromises:  make(map[MessageID]*iwantPromise),  // P2P-H01
		ctx:            ctx,
		cancel:         cancel,
	}
}

// SetMessageValidator installs a validator that runs on every incoming
// message before it is delivered to handlers or forwarded to the mesh.
// Passing nil restores the default no-op validator (accept all messages).
//
// AUDIT (2026) R4-P2P-03: Without this gate, GossipSub forwarded
// unverified messages to the entire mesh, enabling a malicious peer to
// amplify junk across the network at the cost of only one hop's bandwidth.
func (gs *GossipSub) SetMessageValidator(v TopicMessageValidator) {
	gs.validatorMu.Lock()
	defer gs.validatorMu.Unlock()
	if v == nil {
		gs.validator = noOpValidator{}
		return
	}
	gs.validator = v
}

// SetPayloadSignatureVerifier installs a payload-level Dilithium3 signature
// verifier for GossipSub messages (P2P-R11-CRIT-001, 2026-07-20).
//
// When set, deliverMessage invokes the verifier for sensitive topics
// (TopicBlocks / TopicVotes / TopicTransactions / TopicAttestations)
// AFTER the TopicMessageValidator passes (so format/size/replay checks
// still run first), and drops messages whose signature does not verify.
//
// Pass nil to disable (restores backward-compatible fail-open behavior).
// Safe to call concurrently with deliverMessage.
func (gs *GossipSub) SetPayloadSignatureVerifier(verifier PayloadSignatureVerifier) {
	gs.payloadVerifierMu.Lock()
	defer gs.payloadVerifierMu.Unlock()
	gs.payloadVerifier = verifier
}

// Start begins the GossipSub heartbeat loop
func (gs *GossipSub) Start() error {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	if gs.started {
		return fmt.Errorf("GossipSub already started")
	}
	gs.started = true

	gs.wg.Add(1)
	go gs.heartbeatLoop()

	return nil
}

// Stop stops the GossipSub router
func (gs *GossipSub) Stop() {
	gs.mu.Lock()
	if !gs.started {
		gs.mu.Unlock()
		return
	}
	gs.started = false
	gs.mu.Unlock()

	gs.cancel()
	gs.wg.Wait()
}

// =============================================================================
// Topic Management
// =============================================================================

// JoinTopic subscribes to a topic and registers a message handler
func (gs *GossipSub) JoinTopic(topicName string, handler MessageHandler) (*Topic, error) {
	// SECURITY (audit 2026-06-24, L-1): Validate topic against whitelist to
	// prevent arbitrary topic subscription.
	if !isAllowedTopic(topicName) {
		return nil, fmt.Errorf("topic %s is not in the allowed whitelist", topicName)
	}

	gs.topicsMu.Lock()
	defer gs.topicsMu.Unlock()

	if _, exists := gs.topics[topicName]; exists {
		return nil, fmt.Errorf("already subscribed to topic %s", topicName)
	}

	t := &Topic{
		name:         topicName,
		gs:           gs,
		mesh:         make(map[PeerID]*peerState),
		fanout:       make(map[PeerID]time.Time),
		messageCache: make([]*Message, 0, gs.cfg.HistoryLength),
		// AUDIT (2026) R3-P2P-04 FIX: Initialize the dedicated dedup cache.
		seenMessages: make(map[MessageID]time.Time, gs.cfg.MaxSeenMessages),
		// P2P-H04 FIX (R29, 2026-07-26): Initialize mesh-delivery deficit tracker.
		// windowMsgCap bounds memory under high message rates; windowMsgTTL
		// bounds the time a message stays in the deficit tracker (must be
		// >= HeartbeatInterval so the heartbeat can evaluate it at least
		// once before pruning).
		deliveredMsgPeers: make(map[MessageID]map[PeerID]time.Time),
		windowMsgCap:      256,
		windowMsgTTL:      30 * time.Second,
	}
	gs.topics[topicName] = t

	gs.handlersMu.Lock()
	gs.handlers[topicName] = handler
	gs.handlersMu.Unlock()

	// Immediately try to build mesh
	// GOSSIP-R18-L03 (2026-07-23): Wrap the one-shot goroutine with
	// defer recover() to match the codebase standard for all goroutines.
	// Although tryBuildMesh is designed to be one-shot and the heartbeat
	// loop already has its own recover, an unrecovered panic here (e.g.
	// from a future bug in sendGraft or peerScore) would crash the entire
	// node process. Defensive: log and swallow.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("WARN: gossipsub tryBuildMesh panic (topic=%s): %v", topicName, r)
			}
		}()
		gs.tryBuildMesh(t)
	}()

	return t, nil
}

// LeaveTopic unsubscribes from a topic
func (gs *GossipSub) LeaveTopic(topicName string) error {
	gs.topicsMu.Lock()
	defer gs.topicsMu.Unlock()

	t, exists := gs.topics[topicName]
	if !exists {
		return fmt.Errorf("not subscribed to topic %s", topicName)
	}

	// Send PRUNE to all mesh peers
	t.meshMu.RLock()
	for pid := range t.mesh {
		gs.sendPrune(pid, topicName, "unsubscribed")
	}
	t.meshMu.RUnlock()

	delete(gs.topics, topicName)

	gs.handlersMu.Lock()
	delete(gs.handlers, topicName)
	gs.handlersMu.Unlock()

	return nil
}

// =============================================================================
// Message Publishing
// =============================================================================

// Publish sends a message to all subscribers of a topic
func (gs *GossipSub) Publish(topicName string, data []byte) error {
	// N5 FIX (2026-07-06 R2): Enforce message size limit at publish time.
	if len(data) > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max %d)", len(data), MaxMessageSize)
	}

	gs.topicsMu.RLock()
	t, exists := gs.topics[topicName]
	gs.topicsMu.RUnlock()

	if !exists {
		return fmt.Errorf("not subscribed to topic %s", topicName)
	}

	// Compute message ID
	msgID := ComputeMessageID(topicName, data)

	// Create message
	t.cacheMu.Lock()
	seqNo := t.seqNo
	t.seqNo++
	t.cacheMu.Unlock()

	msg := &Message{
		ID:         msgID,
		Topic:      topicName,
		Data:       data,
		SeqNo:      seqNo,
		ReceivedAt: time.Now(),
	}

	// Cache the message
	t.cacheMessage(msg)

	// Send to mesh peers
	t.meshMu.RLock()
	meshPeers := make([]PeerID, 0, len(t.mesh))
	for pid := range t.mesh {
		meshPeers = append(meshPeers, pid)
	}
	t.meshMu.RUnlock()

	for _, pid := range meshPeers {
		gs.sendMessageToPeer(pid, msg)
	}

	// Also send to fanout peers
	t.fanoutMu.RLock()
	now := time.Now()
	for pid, expiry := range t.fanout {
		if now.Before(expiry) {
			gs.sendMessageToPeer(pid, msg)
		}
	}
	t.fanoutMu.RUnlock()

	return nil
}

// =============================================================================
// Message Reception (called by P2P layer when receiving GossipSub RPC)
// =============================================================================

// HandleRPC processes an incoming GossipSub RPC from a peer
func (gs *GossipSub) HandleRPC(from PeerID, data []byte) error {
	rpc, err := DecodeRPC(data)
	if err != nil {
		return fmt.Errorf("failed to decode GossipSub RPC: %w", err)
	}

	// Process messages
	for _, msg := range rpc.Messages {
		msg.From = from
		msg.ReceivedAt = time.Now()
		gs.deliverMessage(msg)
	}

	// Process control messages
	if rpc.Control != nil {
		gs.handleControl(from, rpc.Control)
	}

	return nil
}

// deliverMessage routes a message to the appropriate topic handler
// SECURITY FIX (audit P2-01): Added dedup check before processing and forwarding.
// Previously, duplicate messages were processed by handlers and forwarded to
// mesh peers unconditionally, enabling message amplification attacks.
//
// AUDIT (2026) R4-P2P-03: Added (1) a validator gate that runs AFTER the
// dedup check and BEFORE the handler/forward — invalid messages are dropped
// at the first hop and the source peer is penalized via
// RecordInvalidMessage; (2) a RecordDuplicate call on dedup cache hit so
// peers that spam already-seen messages accumulate a small negative score.
// Together these give the scorer the missing negative signals: invalid
// messages strongly decrement the score, duplicates weakly decrement it.
func (gs *GossipSub) deliverMessage(msg *Message) {
	// SECURITY (audit 2026-06-24, M-3): Reject topics not in the whitelist.
	if !isAllowedTopic(msg.Topic) {
		return
	}

	// P2P-H01 (R24, 2026-07-25): Fulfill any pending IWANT promise for
	// this message. The peer (regardless of who delivered it) provided
	// the message body we requested via IWANT, so the promise is
	// fulfilled.
	//
	// R33 P3-02 FIX (2026-07-28): Previously the promise was deleted
	// UNCONDITIONALLY before the dedup and validation checks. This meant
	// a peer who delivered an INVALID message (failed ValidateMessage or
	// VerifyPayload) had their promise satisfied without actually
	// delivering usable content, escaping the broken-promise penalty at
	// sweepExpiredIWANTPromises. Now:
	//  - For DUPLICATES (already seen): fulfill the promise. The peer
	//    delivered a valid message that we already received from someone
	//    else — this is a legitimate race, not a broken promise.
	//  - For INVALID messages: do NOT fulfill the promise. The peer
	//    delivered junk; the heartbeat sweep will penalize them.
	//  - For VALID messages: fulfill the promise after all checks pass.
	gs.topicsMu.RLock()
	t, exists := gs.topics[msg.Topic]
	gs.topicsMu.RUnlock()
	if exists {
		// SECURITY FIX (audit P2-02): Acquire read lock around hasSeenMessage
		// to prevent data race with cacheMessage's write lock. No other locks
		// are held here (topicsMu was released above), so no deadlock risk.
		t.cacheMu.RLock()
		seen := t.hasSeenMessage(msg.ID)
		t.cacheMu.RUnlock()
		if seen {
			// R33 P3-02 FIX: Duplicate of an already-seen message. Fulfill
			// the promise because the peer did deliver a valid message
			// (we already validated it earlier). This is a legitimate race.
			gs.iwantPromisesMu.Lock()
			delete(gs.iwantPromises, msg.ID)
			gs.iwantPromisesMu.Unlock()

			// AUDIT (2026) R4-P2P-03: Record the duplicate so the
			// scorer has a negative signal for peers that spam already-
			// seen messages. The per-duplicate penalty is deliberately
			// small (1.0) so honest peers that legitimately forward
			// duplicates during propagation are not harmed.
			gs.scorer.RecordDuplicate(msg.From, msg.Topic)
			return // Already processed, skip
		}
	}

	// AUDIT (2026) R4-P2P-03: Validation gate. Run the validator
	// BEFORE delivering to handlers or forwarding to the mesh. Invalid
	// messages are dropped at the first hop and the source peer is
	// penalized. This prevents a malicious peer from amplifying junk
	// across the network at the cost of only one hop's bandwidth.
	// The validator is read under validatorMu.RLock to avoid a data
	// race with SetMessageValidator; the lock is released before the
	// (potentially slow) ValidateMessage call's work is observed by
	// the caller, but the call itself uses a local copy of v.
	gs.validatorMu.RLock()
	v := gs.validator
	gs.validatorMu.RUnlock()
	if v == nil {
		v = noOpValidator{}
	}
	if err := v.ValidateMessage(msg); err != nil {
		gs.scorer.RecordInvalidMessage(msg.From, msg.Topic)
		// R33 P3-02 FIX: Do NOT fulfill the promise for invalid messages.
		// The peer delivered junk; the heartbeat sweep will penalize them
		// for the broken promise.
		return
	}

	// P2P-R11-CRIT-001 (2026-07-20) FIX: Verify payload-level Dilithium3
	// signature for sensitive topics BEFORE delivering to handlers or
	// forwarding to the mesh. mTLS authenticates the connection, but a
	// compromised peer (or MITM after mTLS termination) could still
	// inject forged payloads. Drop forged messages at the first hop.
	// Fail-open when no verifier is configured (backward compat).
	gs.payloadVerifierMu.RLock()
	verifier := gs.payloadVerifier
	gs.payloadVerifierMu.RUnlock()
	if verifier != nil {
		if err := verifier.VerifyPayload(msg.Topic, msg.Data); err != nil {
			gs.scorer.RecordInvalidMessage(msg.From, msg.Topic)
			// R33 P3-02 FIX: Do NOT fulfill the promise for invalid payloads.
			return
		}
	}

	// R33 P3-02 FIX: All validation checks passed. NOW fulfill the
	// IWANT promise — the peer delivered a valid, usable message.
	gs.iwantPromisesMu.Lock()
	delete(gs.iwantPromises, msg.ID)
	gs.iwantPromisesMu.Unlock()

	gs.handlersMu.RLock()
	handler, handlerExists := gs.handlers[msg.Topic]
	gs.handlersMu.RUnlock()

	if handlerExists && handler != nil {
		// R33 P2P-11 FIX (2026-07-28): Wrap handler invocation in a
		// local panic recovery. A panic in a topic handler (e.g., nil
		// pointer deref in application-layer block/tx processing, or an
		// unexpected type assertion failure) would otherwise propagate
		// up through deliverMessage → handleSubscriptionMessage →
		// InjectRPC and crash the entire GossipSub goroutine. This is
		// strictly a defense-in-depth measure: handlers should fail
		// gracefully on their own, but we cannot trust every handler
		// author to do so. The panic is logged with the topic and
		// message ID for debugging, and the source peer is penalized
		// via RecordInvalidMessage (the message may have been crafted
		// to trigger the panic).
		func() {
			defer func() {
				if r := recover(); r != nil {
					if gs.scorer != nil {
						gs.scorer.RecordInvalidMessage(msg.From, "handler-panic")
					}
					// Use log (already imported, writes to stderr, no buffering)
					// to avoid depending on a specific logger instance inside
					// the hot path.
					log.Printf("deliverMessage: handler panic recovered (topic=%s from=%s panic=%v)",
						msg.Topic, msg.From, r)
				}
			}()
			handler(msg)
		}()
	}

	// Update peer scorer
	gs.scorer.RecordMessageDelivery(msg.From, msg.Topic)

	// P2P-H04 FIX (R29, 2026-07-26): Record this delivery in the topic's
	// deficit tracker. If this is the first mesh peer to deliver this
	// message, all OTHER mesh peers are now "potentially missing" it; if
	// a subsequent peer also delivers it (within windowMsgTTL), that
	// peer is no longer missing. At heartbeat, messages with only one
	// delivering peer count as missing-forwards for every other mesh
	// peer that was in the mesh at delivery time.
	gs.recordMeshDelivery(msg)

	// Forward to mesh peers (don't send back to origin)
	gs.forwardMessage(msg)
}

// recordMeshDelivery records that msg.From delivered msg to us, and updates
// the per-topic deficit tracker. P2P-H04 FIX (R29, 2026-07-26).
//
// Logic:
//  1. If this is the FIRST delivery of msg.ID: create entry with
//     {msg.From: now}. Every OTHER mesh peer is now potentially missing
//     this message.
//  2. If this is a SUBSEQUENT delivery (duplicate from another peer):
//     add the new delivering peer to the entry. That peer is no longer
//     missing the message. Other peers not in the entry are still
//     potentially missing.
//  3. Enforce windowMsgCap by evicting the oldest entry when the map
//     exceeds the cap.
//
// The heartbeat (evaluateMissingForwards) iterates the tracker and for
// each message, every mesh peer NOT in the entry's peer set is charged
// with a missing forward (via IncrementMissingForward).
//
// This method holds deliveredMsgPeersMu (per-topic) and briefly takes
// meshMu.RLock to snapshot mesh peers. No GossipSub-wide lock is held.
func (gs *GossipSub) recordMeshDelivery(msg *Message) {
	gs.topicsMu.RLock()
	t, exists := gs.topics[msg.Topic]
	gs.topicsMu.RUnlock()
	if !exists {
		return
	}

	now := time.Now()
	t.deliveredMsgPeersMu.Lock()
	defer t.deliveredMsgPeersMu.Unlock()

	// Enforce cap: evict oldest entry when map is full.
	if _, ok := t.deliveredMsgPeers[msg.ID]; !ok {
		if len(t.deliveredMsgPeers) >= t.windowMsgCap {
			// Evict the entry with the oldest timestamp.
			var oldestID MessageID
			var oldestTime time.Time
			first := true
			for id, peers := range t.deliveredMsgPeers {
				for _, ts := range peers {
					if first || ts.Before(oldestTime) {
						oldestID = id
						oldestTime = ts
						first = false
					}
				}
			}
			if !first {
				delete(t.deliveredMsgPeers, oldestID)
			}
		}
		t.windowDeliveries++
	}

	if t.deliveredMsgPeers[msg.ID] == nil {
		t.deliveredMsgPeers[msg.ID] = make(map[PeerID]time.Time)
	}
	t.deliveredMsgPeers[msg.ID][msg.From] = now
}

// evaluateMissingForwards scans the topic's deliveredMsgPeers tracker and
// charges every mesh peer that did NOT deliver a message with a missing
// forward. After evaluation, the tracker is reset for the next window.
//
// P2P-H04 FIX (R29, 2026-07-26). Called by performHeartbeat.
//
// Algorithm:
//  1. Snapshot current mesh peers.
//  2. For each tracked message, find mesh peers NOT in the delivering-peers
//     set. Each such peer gets one IncrementMissingForward.
//  3. Prune entries older than windowMsgTTL (defensive — the cap eviction
//     in recordMeshDelivery should keep the map bounded, but TTL pruning
//     handles the case where the cap is large and messages linger).
//  4. Reset windowDeliveries to 0 for the next window.
//  5. Return the total windowDeliveries count so the caller can pass it
//     to ApplyMissingForwardPenalty for ratio computation.
func (gs *GossipSub) evaluateMissingForwards(t *Topic) int {
	t.meshMu.RLock()
	meshPeers := make([]PeerID, 0, len(t.mesh))
	for pid := range t.mesh {
		meshPeers = append(meshPeers, pid)
	}
	t.meshMu.RUnlock()

	now := time.Now()

	t.deliveredMsgPeersMu.Lock()
	defer t.deliveredMsgPeersMu.Unlock()

	totalDeliveries := t.windowDeliveries

	for id, peers := range t.deliveredMsgPeers {
		// Prune stale entries.
		stale := true
		for _, ts := range peers {
			if now.Sub(ts) < t.windowMsgTTL {
				stale = false
				break
			}
		}
		if stale {
			delete(t.deliveredMsgPeers, id)
			continue
		}

		// Charge mesh peers not in the delivering-peers set.
		for _, pid := range meshPeers {
			if _, delivered := peers[pid]; delivered {
				continue
			}
			// Don't charge ourselves (we're not in mesh).
			if pid == "" {
				continue
			}
			gs.scorer.IncrementMissingForward(pid)
		}
	}

	// Reset window counter for next window.
	t.windowDeliveries = 0
	// NOTE: We do NOT clear deliveredMsgPeers here — entries linger until
	// they age out via windowMsgTTL pruning above. This allows messages
	// delivered near the heartbeat boundary to still count for the NEXT
	// window's deficit if the peer eventually delivers them. The cap
	// eviction in recordMeshDelivery bounds memory growth.

	return totalDeliveries
}

// forwardMessage sends a received message to mesh peers (excluding sender)
// SECURITY FIX (audit P2-01): Check cacheMessage return to skip forwarding
// duplicate messages, preventing amplification attacks.
func (gs *GossipSub) forwardMessage(msg *Message) {
	gs.topicsMu.RLock()
	t, exists := gs.topics[msg.Topic]
	gs.topicsMu.RUnlock()

	if !exists {
		return
	}

	// Cache the message for IHAVE and dedup.
	// SECURITY FIX: If already cached (duplicate), skip forwarding.
	// SECURITY FIX (audit P2-02): Acquire read lock around hasSeenMessage
	// to prevent data race with cacheMessage's write lock. No other locks
	// are held here (topicsMu was released above), so no deadlock risk.
	t.cacheMu.RLock()
	seen := t.hasSeenMessage(msg.ID)
	t.cacheMu.RUnlock()
	if seen {
		return
	}
	t.cacheMessage(msg)

	// Forward to mesh peers (excluding originator)
	t.meshMu.RLock()
	for pid := range t.mesh {
		if pid != msg.From {
			gs.sendMessageToPeer(pid, msg)
		}
	}
	t.meshMu.RUnlock()

	// Fanout to some non-mesh peers for redundancy
	t.fanoutMu.RLock()
	now := time.Now()
	fanoutCount := 0
	for pid, expiry := range t.fanout {
		if pid == msg.From {
			continue
		}
		if now.Before(expiry) && fanoutCount < gs.cfg.D {
			gs.sendMessageToPeer(pid, msg)
			fanoutCount++
		}
	}
	t.fanoutMu.RUnlock()
}

// handleControl processes GossipSub control messages.
// R5-P4-2 FIX: Each control type array is capped to prevent DoS via
// oversized ControlMessage from a malicious peer.
func (gs *GossipSub) handleControl(from PeerID, ctrl *ControlMessage) {
	// Process GRAFT requests (capped to prevent DoS)
	grafts := ctrl.Graft
	if len(grafts) > GossipSubMaxGrafts {
		grafts = grafts[:GossipSubMaxGrafts]
	}
	for _, graft := range grafts {
		gs.handleGraft(from, graft.Topic)
	}

	// Process PRUNE requests (capped to prevent DoS)
	prunes := ctrl.Prune
	if len(prunes) > GossipSubMaxPrunes {
		prunes = prunes[:GossipSubMaxPrunes]
	}
	for _, prune := range prunes {
		gs.handlePrune(from, prune.Topic)
	}

	// Process IHAVE announcements (capped to prevent DoS)
	ihaves := ctrl.IHave
	if len(ihaves) > GossipSubMaxIHave {
		ihaves = ihaves[:GossipSubMaxIHave]
	}

	// P2P-R16-M03 (2026-07-23): Per-peer IHAVE rate limiting. Count the
	// total message IDs advertised across all IHAVE entries in this RPC and
	// check against the per-peer sliding-window budget BEFORE doing any
	// cache lookups. If the peer has exhausted its budget, skip IHAVE
	// processing entirely for this RPC (the IWANT response is already
	// capped, so skipping just means we don't request messages from a
	// peer that is already flooding us).
	totalIHaveIDs := 0
	for _, ihave := range ihaves {
		totalIHaveIDs += len(ihave.MessageIDs)
	}
	if !gs.allowIHave(from, totalIHaveIDs) {
		// P2P-R21-H01: Penalize peers that exceed the IHAVE rate limit.
		// Without this, a malicious peer can flood IHAVE at exactly the
		// rate-limit ceiling forever, wasting our CPU on every RPC without
		// any scoring consequence. The penalty per violation equals one
		// invalid message (invalidMessagePenalty), so sustained flooding
		// pushes the peer below scoreGraylist and off the mesh.
		if gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(from, "ihave-rate-limit")
		}
		ihaves = nil
	}

	// SECURITY (audit P2P-12): Batch all IWANT requests into a single RPC.
	// Previously each IHAVE entry triggered a separate sendIWant RPC, so
	// 100 IHAVE entries → up to 100 RPCs to the same peer (egress amplification).
	// Now all wanted MessageIDs are collected and sent in one RPC.
	var allWantIDs []MessageID
	for _, ihave := range ihaves {
		wantIDs := gs.handleIHave(from, ihave)
		allWantIDs = append(allWantIDs, wantIDs...)
		if len(allWantIDs) >= GossipSubIWantLimit {
			allWantIDs = allWantIDs[:GossipSubIWantLimit]
			break
		}
	}
	if len(allWantIDs) > 0 {
		gs.sendIWant(from, allWantIDs)
	}

	// Process IWANT requests (capped to prevent DoS)
	iwants := ctrl.IWant
	if len(iwants) > GossipSubMaxIWant {
		iwants = iwants[:GossipSubMaxIWant]
	}
	for _, iwant := range iwants {
		gs.handleIWant(from, iwant)
	}
}

// =============================================================================
// Mesh Maintenance
// =============================================================================

// heartbeatLoop runs periodic mesh maintenance
//
// R14-MED (2026-07-21): Added panic recovery. Without this, a panic in
// performHeartbeat (or any code it calls: syncPeers, heartbeatTopic,
// tryBuildMesh, pruneExcessPeers, sendIHaveToRandom) would kill the
// goroutine silently. The WaitGroup is decremented, but no one is
// notified — GossipSub continues running with no heartbeat, causing
// mesh degradation (no graft/prune, no fanout cleanup, no dedup
// pruning) without any log. The node slowly loses mesh connectivity
// and stops receiving blocks/votes/attestations.
func (gs *GossipSub) heartbeatLoop() {
	defer gs.wg.Done()
	// R14-MED: Outer recovery keeps the loop alive even if one heartbeat
	// panics. The loop continues to the next tick so transient panics
	// (e.g., from a malformed peer message processed during mesh
	// maintenance) do not permanently disable GossipSub.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[GossipSub] heartbeatLoop panic recovered (mesh maintenance continues on next tick): %v", r)
		}
	}()

	ticker := time.NewTicker(gs.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-gs.ctx.Done():
			return
		case <-ticker.C:
			// R14-MED: Per-tick recovery so a single bad tick does not
			// kill the loop. The outer defer is a backstop for panics
			// that escape this inner recover (should not happen, but
			// defense-in-depth).
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[GossipSub] performHeartbeat panic recovered: %v", r)
					}
				}()
				gs.performHeartbeat()
			}()
		}
	}
}

// performHeartbeat runs one round of mesh maintenance
func (gs *GossipSub) performHeartbeat() {
	// Update peer list from transport
	gs.syncPeers()

	// R14-MED (2026-07-21): Periodic sweep of stale rate-limit tracker
	// entries for graftRateLimit and iwantRateLimit. syncPeers() already
	// cleans entries on disconnect, but a peer that stays connected and
	// sends one GRAFT/IWANT then goes idle keeps its tracker entry
	// forever (with an expired windowEnd). Under peer churn this
	// accumulates stale entries bounded by connected-peer count, but
	// long-lived connections with many briefly-active peers can still
	// leak. Sweep every heartbeat (1s) and delete entries whose
	// windowEnd is more than 5x the rate window in the past AND whose
	// peer is no longer in gs.peers (defense-in-depth against syncPeers
	// races).
	gs.sweepStaleRateTrackers()

	// P2P-H01 (R24, 2026-07-25): Penalize peers whose IWANT promises
	// expired without fulfillment. Runs every heartbeat (1s) so broken
	// promises are caught soon after the GossipSubIWantPeerTimeout
	// (3s) window elapses, bounding the window during which a malicious
	// advertiser can waste our egress IWANTs without consequence.
	gs.sweepExpiredIWANTPromises()

	gs.topicsMu.RLock()
	topics := make([]*Topic, 0, len(gs.topics))
	for _, t := range gs.topics {
		topics = append(topics, t)
	}
	gs.topicsMu.RUnlock()

	for _, t := range topics {
		// AUDIT (2026) R3-P2P-04 FIX: Trim expired dedup entries every
		// heartbeat so the seenMessages map stays bounded under the TTL.
		// Without this, the map grows without bound until MaxSeenMessages
		// is hit, at which point arbitrary eviction kicks in (less LRU-ish).
		t.PruneSeenMessages()
		gs.heartbeatTopic(t)
	}

	// P2P-H04 FIX (R29, 2026-07-26): Evaluate mesh message-delivery deficit
	// per topic and apply penalties to peers that failed to forward a
	// significant fraction of the messages that other mesh peers delivered.
	// The penalty is applied AT MOST ONCE per peer per window via
	// ApplyMissingForwardPenalty, so the score impact is bounded even if a
	// peer missed many messages.
	//
	// We evaluate AFTER heartbeatTopic so the mesh is up-to-date (grafts/
	// prunes from this heartbeat are reflected). The totalDeliveries sum
	// across all topics is passed to ApplyMissingForwardPenalty as the
	// denominator for the deficit ratio — a peer is penalized only if its
	// missing-forward count is at least missingForwardRatioThreshold of
	// the total deliveries AND at least missingForwardMinAbsolute.
	totalWindowDeliveries := 0
	for _, t := range topics {
		totalWindowDeliveries += gs.evaluateMissingForwards(t)
	}
	gs.scorer.ApplyMissingForwardPenalty(totalWindowDeliveries)
}

// sweepStaleRateTrackers removes graftRateLimit/iwantRateLimit/ihaveRateLimit
// entries for peers that are no longer connected OR whose windowEnd is far in
// the past (5x the rate window). R14-MED (2026-07-21): see comment in
// performHeartbeat for the full rationale.
func (gs *GossipSub) sweepStaleRateTrackers() {
	now := time.Now()
	staleThreshold := 50 * time.Second // 5x the 10s rate window

	// Build a snapshot of currently-connected peer IDs so we can drop
	// tracker entries for peers that are no longer in gs.peers. We
	// intentionally do NOT take gs.peersMu here to avoid lock ordering
	// issues (syncPeers already holds peersMu during disconnect cleanup);
	// instead we read the peer set via the sender interface which is
	// safe for concurrent access.
	connectedSet := make(map[PeerID]bool)
	for _, pid := range gs.sender.GetConnectedPeers() {
		connectedSet[pid] = true
	}

	gs.graftRateMu.Lock()
	for pid, tracker := range gs.graftRateLimit {
		if !connectedSet[pid] || now.Sub(tracker.windowEnd) > staleThreshold {
			delete(gs.graftRateLimit, pid)
		}
	}
	gs.graftRateMu.Unlock()

	gs.iwantRateMu.Lock()
	for pid, tracker := range gs.iwantRateLimit {
		if !connectedSet[pid] || now.Sub(tracker.windowEnd) > staleThreshold {
			delete(gs.iwantRateLimit, pid)
		}
	}
	gs.iwantRateMu.Unlock()

	// P2P-R16-M03: same sweep for ihaveRateLimit.
	gs.ihaveRateMu.Lock()
	for pid, tracker := range gs.ihaveRateLimit {
		if !connectedSet[pid] || now.Sub(tracker.windowEnd) > staleThreshold {
			delete(gs.ihaveRateLimit, pid)
		}
	}
	gs.ihaveRateMu.Unlock()
}

// sweepExpiredIWANTPromises penalizes peers whose IWANT promises have
// expired without fulfillment and removes those entries from the map.
// P2P-H01 (R24, 2026-07-25).
//
// A promise expires when the peer advertised a message via IHAVE, we sent
// an IWANT for it, but the message body never arrived within
// GossipSubIWantPeerTimeout. Each expired promise is a "broken promise"
// — the peer wasted our egress IWANT and the ingress slot we reserved.
// We penalize the peer via RecordInvalidMessage (reusing the existing
// penalty path so the score blends with other negative signals) and drop
// the promise so it can't be double-counted on the next heartbeat.
//
// Promises for peers that have since disconnected are silently dropped
// (no penalty — the peer may have crashed or network-partitioned, which
// is not malicious behavior worth scoring against their return).
func (gs *GossipSub) sweepExpiredIWANTPromises() {
	now := time.Now()

	// Snapshot connected peers so we don't penalize disconnected ones
	// (they may have crashed rather than maliciously withheld the msg).
	connectedSet := make(map[PeerID]bool)
	for _, pid := range gs.sender.GetConnectedPeers() {
		connectedSet[pid] = true
	}

	gs.iwantPromisesMu.Lock()
	defer gs.iwantPromisesMu.Unlock()

	for id, p := range gs.iwantPromises {
		if now.Sub(p.sentAt) < GossipSubIWantPeerTimeout {
			continue // still within the delivery window
		}
		// Promise expired. Penalize the peer if still connected.
		if connectedSet[p.peer] && gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(p.peer, "iwant-broken-promise")
		}
		delete(gs.iwantPromises, id)
	}
}

// syncPeers updates the internal peer list from the transport layer
func (gs *GossipSub) syncPeers() {
	connectedPeers := gs.sender.GetConnectedPeers()

	gs.peersMu.Lock()
	defer gs.peersMu.Unlock()

	// Add new peers
	for _, pid := range connectedPeers {
		if _, exists := gs.peers[pid]; !exists {
			gs.peers[pid] = &peerState{
				id:     pid,
				topics: make(map[string]*topicState),
			}
		}
	}

	// Remove disconnected peers
	connectedSet := make(map[PeerID]bool, len(connectedPeers))
	for _, cp := range connectedPeers {
		connectedSet[cp] = true
	}
	for pid := range gs.peers {
		if !connectedSet[pid] {
			delete(gs.peers, pid)
			// audit-fix: clean up iwantRateLimit to prevent map memory leak.
			// Previously, disconnected peers were removed from gs.peers but
			// their iwantRateTracker entries remained in iwantRateLimit forever.
			gs.iwantRateMu.Lock()
			delete(gs.iwantRateLimit, pid)
			gs.iwantRateMu.Unlock()
			// P2P-R12-M01: same cleanup for graftRateLimit.
			gs.graftRateMu.Lock()
			delete(gs.graftRateLimit, pid)
			gs.graftRateMu.Unlock()
			// P2P-R16-M03: same cleanup for ihaveRateLimit.
			gs.ihaveRateMu.Lock()
			delete(gs.ihaveRateLimit, pid)
			gs.ihaveRateMu.Unlock()
		}
	}
}

// heartbeatTopic performs mesh maintenance for a single topic
func (gs *GossipSub) heartbeatTopic(t *Topic) {
	t.meshMu.RLock()
	meshSize := len(t.mesh)
	meshPeers := make([]PeerID, 0, meshSize)
	for pid := range t.mesh {
		meshPeers = append(meshPeers, pid)
	}
	t.meshMu.RUnlock()

	// Get all peers that could be in our mesh
	gs.peersMu.RLock()
	eligiblePeers := make([]PeerID, 0, len(gs.peers))
	for pid := range gs.peers {
		eligiblePeers = append(eligiblePeers, pid)
	}
	gs.peersMu.RUnlock()

	// P2P-R16-H04 (2026-07-22) FIX: Proactively evict graylisted peers
	// REGARDLESS of mesh size. A peer with score < scoreGraylist (-50) is
	// malicious or broken and must always be evicted — keeping it just to
	// maintain DLo wastes bandwidth and lets attackers stay in the mesh
	// indefinitely. The original code had two bugs:
	//   1. The graylist eviction was placed AFTER the `meshSize < DLo`
	//      early return, so it was never reached when the mesh was small.
	//   2. The DLo cap (`evictable = len(mesh) - DLo`) prevented eviction
	//      even when the code was reached, if the mesh was below DLo.
	// Both are fixed here: eviction runs first, with no DLo cap.
	graylistedPeers := make([]PeerID, 0)
	for _, pid := range meshPeers {
		if gs.peerScore(pid) < scoreGraylist {
			graylistedPeers = append(graylistedPeers, pid)
		}
	}
	if len(graylistedPeers) > 0 {
		t.meshMu.Lock()
		for _, pid := range graylistedPeers {
			delete(t.mesh, pid)
			gs.sendPrune(pid, t.name, "score_below_graylist")
		}
		t.meshMu.Unlock()
		// Recalculate mesh state after graylist eviction.
		t.meshMu.RLock()
		meshSize = len(t.mesh)
		meshPeers = make([]PeerID, 0, meshSize)
		for pid := range t.mesh {
			meshPeers = append(meshPeers, pid)
		}
		t.meshMu.RUnlock()
	}

	// If mesh is too small, try to graft new peers
	if meshSize < gs.cfg.DLo {
		gs.tryBuildMesh(t)
		return
	}

	// If mesh is too big, prune some peers
	if meshSize > gs.cfg.DHi {
		gs.pruneExcessPeers(t, meshPeers, meshSize-gs.cfg.D)
	}

	// P2P-H03 (R17, 2026-07-23) FIX: Proactively evict low-score peers
	// (score in [scoreGraylist, scoreAcceptable)) when the mesh is healthy
	// AND better replacement candidates are available. The P2P-R16-H04 fix
	// above only evicts peers below scoreGraylist (-50). Peers with score
	// in [-50, 0) are below scoreAcceptable ("Minimum for mesh inclusion"
	// per scorer.go:28) but were never evicted, so they stayed in the mesh
	// indefinitely. This block replaces them with better peers when possible.
	//
	// Design: we only evict a low-score peer if there is at least one
	// non-mesh peer with score >= scoreAcceptable available to replace it.
	// This avoids pointless churn (evict + re-graft the same peer) and
	// avoids shrinking the mesh below DLo when no better candidates exist.
	t.meshMu.RLock()
	currentMeshSet := make(map[PeerID]bool, len(t.mesh))
	for pid := range t.mesh {
		currentMeshSet[pid] = true
	}
	t.meshMu.RUnlock()

	// Find low-score mesh peers (score in [scoreGraylist, scoreAcceptable)).
	// Peers below scoreGraylist were already evicted above.
	lowScorePeers := make([]PeerID, 0)
	for _, pid := range meshPeers {
		if !currentMeshSet[pid] {
			continue // already evicted above
		}
		s := gs.peerScore(pid)
		if s >= scoreGraylist && s < scoreAcceptable {
			lowScorePeers = append(lowScorePeers, pid)
		}
	}

	if len(lowScorePeers) > 0 {
		// Find replacement candidates: non-mesh peers with score >= scoreAcceptable.
		replacements := make([]PeerID, 0, len(lowScorePeers))
		for _, pid := range eligiblePeers {
			if currentMeshSet[pid] {
				continue
			}
			if gs.peerScore(pid) >= scoreAcceptable {
				replacements = append(replacements, pid)
			}
		}

		// Only evict up to the number of available replacements.
		evictCount := len(lowScorePeers)
		if evictCount > len(replacements) {
			evictCount = len(replacements)
		}
		// Also cap to avoid shrinking below DLo.
		t.meshMu.RLock()
		evictable := len(t.mesh) - gs.cfg.DLo
		t.meshMu.RUnlock()
		if evictable < 0 {
			evictable = 0
		}
		if evictCount > evictable {
			evictCount = evictable
		}

		if evictCount > 0 {
			t.meshMu.Lock()
			for i := 0; i < evictCount; i++ {
				delete(t.mesh, lowScorePeers[i])
				gs.sendPrune(lowScorePeers[i], t.name, "score_below_acceptable")
			}
			t.meshMu.Unlock()
			// Graft replacement peers to refill the mesh. tryBuildMesh in
			// the next heartbeat will handle this, but we can also graft
			// directly here for faster convergence.
			for i := 0; i < evictCount; i++ {
				gs.sendGraft(replacements[i], t.name)
			}
		}
	}

	// Periodically send IHAVE to random peers
	gs.sendIHaveToRandom(t)

	// Clean up expired fanout entries
	t.fanoutMu.Lock()
	now := time.Now()
	for pid, expiry := range t.fanout {
		if now.After(expiry) {
			delete(t.fanout, pid)
		}
	}
	t.fanoutMu.Unlock()
}

// tryBuildMesh attempts to grow the mesh to the desired size.
// IMPORTANT: This function must NOT hold any locks across lock acquisitions
// to avoid deadlocks. It reads mesh state and peer state in separate phases.
func (gs *GossipSub) tryBuildMesh(t *Topic) {
	// Phase 1: Snapshot mesh state under meshMu, then release
	t.meshMu.RLock()
	currentSize := len(t.mesh)
	meshSet := make(map[PeerID]bool, currentSize)
	for pid := range t.mesh {
		meshSet[pid] = true
	}
	t.meshMu.RUnlock()

	if currentSize >= gs.cfg.D {
		return
	}

	// Phase 2: Get candidates (peers NOT in mesh) under peersMu, then release
	gs.peersMu.RLock()
	candidates := make([]PeerID, 0, len(gs.peers))
	for pid := range gs.peers {
		if !meshSet[pid] {
			candidates = append(candidates, pid)
		}
	}
	gs.peersMu.RUnlock()

	// P2P-R16-M07 (2026-07-23) FIX: Prefilter graylisted peers before
	// sending GRAFT. Previously, tryBuildMesh selected graft candidates
	// only by mesh membership exclusion, never consulting peerScore().
	// A peer penalized below scoreGraylist (-50) would receive a GRAFT,
	// only to immediately PRUNE us back — wasting outbound bandwidth on
	// every mesh rebuild. Now we filter such peers BEFORE the shuffle,
	// so only peers with a non-graylist score are considered. This runs
	// with NO locks held, consistent with peerScore()'s locking contract
	// and the function's "no locks across lock acquisitions" constraint.
	filtered := candidates[:0]
	for _, pid := range candidates {
		if gs.peerScore(pid) >= scoreGraylist {
			filtered = append(filtered, pid)
		}
	}
	candidates = filtered

	// Shuffle candidates
	shuffleSlice(candidates)

	needed := gs.cfg.D - currentSize
	if needed > len(candidates) {
		needed = len(candidates)
	}

	// Phase 3: Send grafts (no locks held during send)
	for i := 0; i < needed; i++ {
		pid := candidates[i]
		gs.sendGraft(pid, t.name)
		t.meshMu.Lock()
		t.mesh[pid] = nil // Will be filled when peer responds
		t.meshMu.Unlock()
	}
}

// peerScore returns the effective score for a peer, combining GossipSub's
// own scorer with the application-layer score exposed via MessageSender.
//
// P2P-R15-H01 (2026-07-22) FIX: Previously, GossipSub only consulted its
// own scorer (gs.scorer) for mesh maintenance decisions (pruneExcessPeers,
// handleGraft). The Host's PeerScorer — which tracks application-layer
// penalties like invalid blocks, votes, and transactions — was never
// consulted because the MessageSender.GetPeerScore callback was declared
// on the interface but never invoked by the mesh maintenance path. As a
// result, a peer heavily penalized by the Host (e.g., for sending invalid
// blocks) could still be in good standing in GossipSub's mesh, continuing
// to propagate messages.
//
// After the fix, peerScore combines the two scores by taking the minimum:
//   - If either scorer penalizes the peer below scoreGraylist, the peer is
//     excluded from the mesh.
//   - If the application-layer score is 0.0 (neutral / no opinion), only
//     the GossipSub score is used. This preserves backward compatibility
//     with test mocks that return 0 for all peers — their behavior is
//     unchanged.
//   - If gs.sender is nil (defensive), only the GossipSub score is used.
func (gs *GossipSub) peerScore(pid PeerID) float64 {
	gossipScore := gs.scorer.GetScore(pid)
	if gs.sender == nil {
		return gossipScore
	}
	appScore := gs.sender.GetPeerScore(pid)
	if appScore == 0.0 {
		// Neutral / no opinion from the application layer — use the
		// GossipSub score only. This preserves backward compatibility
		// with test mocks whose GetPeerScore returns 0 for every peer.
		return gossipScore
	}
	// Take the minimum so a peer penalized by EITHER scorer is excluded
	// from the mesh. A peer that is bad at the application layer (e.g.,
	// sends invalid blocks) should not remain in the mesh even if its
	// gossip-layer behavior is fine, and vice versa.
	if appScore < gossipScore {
		return appScore
	}
	return gossipScore
}

// pruneExcessPeers removes the lowest-scored peers from mesh
func (gs *GossipSub) pruneExcessPeers(t *Topic, peers []PeerID, toPrune int) {
	// Sort by score (lowest first)
	type scoredPeer struct {
		id    PeerID
		score float64
	}
	scored := make([]scoredPeer, len(peers))
	for i, pid := range peers {
		// P2P-R15-H01: use peerScore() which combines GossipSub's own
		// scorer with the application-layer score from MessageSender.
		scored[i] = scoredPeer{id: pid, score: gs.peerScore(pid)}
	}

	// Sort by score ascending
	for i := 0; i < len(scored)-1; i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[j].score < scored[i].score {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	// Prune the lowest scored
	for i := 0; i < toPrune && i < len(scored); i++ {
		gs.sendPrune(scored[i].id, t.name, "mesh_oversized")
		t.meshMu.Lock()
		delete(t.mesh, scored[i].id)
		t.meshMu.Unlock()
	}
}

// =============================================================================
// Control Message Handlers
// =============================================================================

func (gs *GossipSub) handleGraft(from PeerID, topicName string) {
	// SECURITY (audit 2026-06-24, M-3): Reject topics not in the whitelist.
	if !isAllowedTopic(topicName) {
		// R33 P2P-07 FIX (2026-07-28): Record GRAFT for non-whitelisted topic
		// as invalid message. Without this penalty, a malicious peer can probe
		// the topic whitelist at zero cost (no scoring impact), and a sybil
		// army can flood GRAFTs for junk topics to waste handleGraft CPU.
		// Penalty is small (invalidMessagePenalty=30, blended) but accumulates
		// across many violations to eventually push peer below scoreGraylist.
		if gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(from, "graft-invalid-topic")
		}
		return
	}

	// P2P-R12-M01 (2026-07-20) FIX: Per-peer GRAFT rate limit.
	// A peer can send at most maxGraftPerWindow GRAFT messages within
	// graftRateWindow. This prevents mesh-churn DoS where a malicious
	// peer floods many small ControlMessages each carrying 1-2 GRAFTs
	// (the per-RPC cap of GossipSubMaxGrafts=100 does not bound the
	// aggregate rate across RPCs). 50/window is generous: legitimate
	// mesh maintenance triggers at most DLo=4 GRAFTs per heartbeat per
	// topic, and heartbeat runs every 1s, so even with all topics at
	// once the steady-state rate is ~4-16/s — far below 50/10s.
	const (
		maxGraftPerWindow = 50
		graftRateWindow   = 10 * time.Second
	)
	if !gs.allowGraft(from, maxGraftPerWindow, graftRateWindow) {
		// Silently drop — sending a PRUNE back would amplify the attack
		// (one GRAFT in → one PRUNE out → attacker learns mesh state).
		// The peer scorer's existing P2P-09 backoff still applies to
		// any GRAFTs that do slip through, so this is defense-in-depth.
		// R33 P2P-07 FIX (2026-07-28): Record rate-limit violation so the
		// peer scorer blends this signal with other misbehavior. Without
		// recording, a peer could spam GRAFTs up to the rate limit on
		// every window with zero scoring impact.
		if gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(from, "graft-rate-limit")
		}
		return
	}

	gs.topicsMu.RLock()
	t, exists := gs.topics[topicName]
	gs.topicsMu.RUnlock()

	if !exists {
		// We don't subscribe to this topic, send PRUNE
		// R33 P2P-07 FIX (2026-07-28): Record GRAFT for topic we don't
		// subscribe to. Spec-wise this is a protocol violation: peers should
		// only GRAFT topics they've seen us advertise via our subscription
		// bitmask. Repeated GRAFTs for unsubscribed topics indicate either a
		// buggy peer or active probing.
		if gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(from, "graft-unsubscribed-topic")
		}
		gs.sendPrune(from, topicName, "not_subscribed")
		return
	}

	// SECURITY (audit P2P-09): Score gating — reject GRAFT from peers below
	// the graylist threshold. Prevents known-bad/malicious peers from joining
	// the mesh and receiving all message traffic.
	// P2P-R15-H01: use peerScore() which combines GossipSub's own scorer
	// with the application-layer score from MessageSender, so a peer
	// penalized by the Host (e.g., for invalid blocks) is also excluded
	// from the GossipSub mesh.
	if score := gs.peerScore(from); score < scoreGraylist {
		gs.sendPrune(from, topicName, "score_too_low")
		return
	}

	// SECURITY (audit P2P-09): Backoff enforcement — if we recently PRUNED this
	// peer for this topic, reject the GRAFT until PruneBackoff has elapsed.
	// Prevents mesh churn from peers rapidly GRAFTing after being PRUNED.
	if gs.inBackoff(from, topicName) {
		// R33 P2P-07 FIX (2026-07-28): Record backoff violation. A GRAFT
		// during backoff is a clear protocol violation (libp2p spec: peers
		// MUST wait for PruneBackoff before re-GRAFTing). Without penalty,
		// a peer can ignore backoff indefinitely with zero cost.
		if gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(from, "graft-backoff-violation")
		}
		gs.sendPrune(from, topicName, "backoff_active")
		return
	}

	t.meshMu.Lock()
	defer t.meshMu.Unlock()

	if _, inMesh := t.mesh[from]; inMesh {
		return // Already in mesh
	}

	// Check mesh size
	if len(t.mesh) >= gs.cfg.DHi {
		// Mesh is full, send PRUNE
		gs.sendPrune(from, topicName, "mesh_full")
		return
	}

	// Add to mesh
	gs.peersMu.RLock()
	ps, exists := gs.peers[from]
	gs.peersMu.RUnlock()

	if exists {
		t.mesh[from] = ps
	} else {
		t.mesh[from] = nil
	}

	// Record graft time for this peer/topic (used for backoff bookkeeping).
	gs.recordGraft(from, topicName)
}

// allowGraft returns true if the peer is below the per-peer GRAFT rate
// limit and increments the counter. Returns false if the peer has exceeded
// the limit (the GRAFT should be silently dropped).
//
// P2P-R12-M01 (2026-07-20): same sliding-window pattern as IWANT. See
// graftRateTracker doc comment for the attack this prevents.
func (gs *GossipSub) allowGraft(from PeerID, maxPerWindow int, window time.Duration) bool {
	gs.graftRateMu.Lock()
	defer gs.graftRateMu.Unlock()
	// R15-MED (2026-07-22): Defensive hard cap on the graftRateLimit map
	// size. The heartbeat sweep (sweepStaleRateTrackers) already removes
	// stale/disconnected entries every 1s, but a burst of sybil peers
	// connecting within one heartbeat window could grow the map beyond
	// the P2P host's max-peer limit before the sweep runs. This cap
	// triggers immediate eviction of stale entries when the threshold
	// is reached, preventing unbounded memory growth. Fail-closed: if
	// the map is still at cap after eviction (all entries fresh), reject
	// the new entry rather than allowing growth.
	const maxGraftTrackerEntries = 10000
	if len(gs.graftRateLimit) >= maxGraftTrackerEntries {
		cutoff := time.Now().Add(-window)
		for pid, tr := range gs.graftRateLimit {
			if tr.windowEnd.Before(cutoff) {
				delete(gs.graftRateLimit, pid)
			}
		}
		if len(gs.graftRateLimit) >= maxGraftTrackerEntries {
			return false
		}
	}
	tracker, ok := gs.graftRateLimit[from]
	now := time.Now()
	if !ok || now.After(tracker.windowEnd) {
		tracker = &graftRateTracker{
			count:     0,
			windowEnd: now.Add(window),
		}
		gs.graftRateLimit[from] = tracker
	}
	if tracker.count >= maxPerWindow {
		return false
	}
	tracker.count++
	return true
}

func (gs *GossipSub) handlePrune(from PeerID, topicName string) {
	// R33 P2P-08 FIX (2026-07-28): Reject PRUNE for topics not in the
	// whitelist. handleGraft already rejects non-whitelisted topics, but
	// handlePrune had no such check. A malicious peer could send PRUNE for
	// arbitrary junk topic names, and although `exists` would be false
	// (we don't subscribe to junk topics) and we'd return early, the
	// topicsMu.RLock still wastes CPU scanning the topics map. More
	// importantly, recording the violation via RecordInvalidMessage
	// establishes a scoring signal for peers probing the topic namespace.
	if !isAllowedTopic(topicName) {
		if gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(from, "prune-invalid-topic")
		}
		return
	}

	gs.topicsMu.RLock()
	t, exists := gs.topics[topicName]
	gs.topicsMu.RUnlock()

	if !exists {
		// R33 P2P-08 FIX: Record PRUNE for topic we don't subscribe to.
		// A peer should only PRUNE topics it has seen us advertise. PRUNEs
		// for unknown topics are protocol violations (buggy peer or active
		// probing). Recording establishes a scoring signal for repeat
		// offenders.
		if gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(from, "prune-unsubscribed-topic")
		}
		return
	}

	t.meshMu.Lock()
	delete(t.mesh, from)
	t.meshMu.Unlock()

	// Add to fanout for potential future use
	t.fanoutMu.Lock()
	t.fanout[from] = time.Now().Add(gs.cfg.FanoutTTL)
	t.fanoutMu.Unlock()
}

// allowIHave checks and updates the per-peer IHAVE message-ID rate limit.
// Returns true if the peer is within its sliding-window budget, false if
// the peer has exhausted it (in which case the caller should skip IHAVE
// processing for this RPC). Mirrors the iwantRateLimit pattern.
//
// P2P-R16-M03 (2026-07-23): Bounds the total number of IHAVE-advertised
// message IDs processed per peer per 10s window. The cap (4096) is generous:
// a healthy mesh peer advertises at most HistoryLength (100) messages per
// topic per heartbeat, and heartbeats fire every 1s, so ~1000 IDs/s =
// 10000/10s across all topics. 4096/10s leaves headroom for legitimate
// bursts while blocking the 25600-IDs-per-RPC flood that an attacker can
// send without this limit.
func (gs *GossipSub) allowIHave(from PeerID, idCount int) bool {
	if idCount <= 0 {
		return true
	}
	const (
		maxIHavePerWindow = 4096
		ihaveRateWindow   = 10 * time.Second
		// Same defensive hard cap as iwantRateLimit to prevent map memory
		// growth from a burst of sybil peers within one heartbeat window.
		maxIHaveTrackerEntries = 10000
	)
	gs.ihaveRateMu.Lock()
	defer gs.ihaveRateMu.Unlock()
	if len(gs.ihaveRateLimit) >= maxIHaveTrackerEntries {
		cutoff := time.Now().Add(-ihaveRateWindow)
		for pid, tr := range gs.ihaveRateLimit {
			if tr.windowEnd.Before(cutoff) {
				delete(gs.ihaveRateLimit, pid)
			}
		}
		if len(gs.ihaveRateLimit) >= maxIHaveTrackerEntries {
			return false
		}
	}
	tracker, ok := gs.ihaveRateLimit[from]
	now := time.Now()
	if !ok || now.After(tracker.windowEnd) {
		tracker = &ihaveRateTracker{
			count:     0,
			windowEnd: now.Add(ihaveRateWindow),
		}
		gs.ihaveRateLimit[from] = tracker
	}
	if tracker.count+idCount > maxIHavePerWindow {
		return false
	}
	tracker.count += idCount
	return true
}

// handleIHave collects the MessageIDs we want to request from the peer.
// SECURITY (audit P2P-12): Returns IDs instead of sending immediately,
// allowing the caller to batch all IWANTs into a single RPC.
//
// P2P-R21-H01 (2026-07-24) FIX: Penalize peers that send IHAVE for unknown
// topics. Previously such peers were silently ignored, so a malicious peer
// could endlessly spam IHAVE for bogus topics to waste our CPU on the
// topic lookup and message-ID scan without any scoring consequence. Now
// each IHAVE for an unknown topic incurs a RecordInvalidMessage penalty,
// eventually pushing the peer below scoreGraylist and off the mesh.
func (gs *GossipSub) handleIHave(from PeerID, ihave *ControlIHave) []MessageID {
	gs.topicsMu.RLock()
	t, exists := gs.topics[ihave.Topic]
	gs.topicsMu.RUnlock()

	if !exists {
		// P2P-R21-H01: Penalize peers advertising topics we don't subscribe to.
		// Honest peers should not IHAVE a topic we never joined — at worst
		// it's a race with an unsubscribe, but the penalty is small enough
		// (invalidMessagePenalty) that a single race won't ban the peer,
		// while sustained spam accumulates.
		if gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(from, ihave.Topic)
		}
		return nil
	}

	// Check which messages we haven't seen
	var wantIDs []MessageID
	t.cacheMu.RLock()
	for _, msgID := range ihave.MessageIDs {
		if !t.hasSeenMessage(msgID) {
			wantIDs = append(wantIDs, msgID)
			if len(wantIDs) >= GossipSubIWantLimit {
				break
			}
		}
	}
	t.cacheMu.RUnlock()

	return wantIDs
}

func (gs *GossipSub) handleIWant(from PeerID, iwant *ControlIWant) {
	// SECURITY (audit 2026-06-24, M-2): Limit IWANT request size to prevent amplification
	const maxIWantMessageIDs = 256
	if len(iwant.MessageIDs) > maxIWantMessageIDs {
		iwant.MessageIDs = iwant.MessageIDs[:maxIWantMessageIDs]
	}

	// SECURITY (audit 2026-06-24, L-3): Per-peer IWANT rate limiting.
	// A single peer can request at most maxIWantPerWindow message IDs within
	// a iwantRateWindow. This prevents a malicious peer from flooding the
	// network with IWANT requests to amplify traffic.
	const (
		maxIWantPerWindow = 1024
		iwantRateWindow   = 10 * time.Second
	)
	gs.iwantRateMu.Lock()
	// R15-MED (2026-07-22): Defensive hard cap on the iwantRateLimit map
	// size. The heartbeat sweep (sweepStaleRateTrackers) already removes
	// stale/disconnected entries every 1s, but a burst of sybil peers
	// connecting within one heartbeat window could grow the map beyond
	// the P2P host's max-peer limit before the sweep runs. This cap
	// triggers immediate eviction of stale entries when the threshold
	// is reached, preventing unbounded memory growth. Fail-closed: if
	// the map is still at cap after eviction (all entries fresh), reject
	// the new entry rather than allowing growth.
	const maxIWANTTrackerEntries = 10000
	if len(gs.iwantRateLimit) >= maxIWANTTrackerEntries {
		cutoff := time.Now().Add(-iwantRateWindow)
		for pid, tr := range gs.iwantRateLimit {
			if tr.windowEnd.Before(cutoff) {
				delete(gs.iwantRateLimit, pid)
			}
		}
		if len(gs.iwantRateLimit) >= maxIWANTTrackerEntries {
			gs.iwantRateMu.Unlock()
			return
		}
	}
	tracker, ok := gs.iwantRateLimit[from]
	now := time.Now()
	if !ok || now.After(tracker.windowEnd) {
		tracker = &iwantRateTracker{
			count:     0,
			windowEnd: now.Add(iwantRateWindow),
		}
		gs.iwantRateLimit[from] = tracker
	}
	allowed := tracker.count+len(iwant.MessageIDs) <= maxIWantPerWindow
	if allowed {
		tracker.count += len(iwant.MessageIDs)
	}
	gs.iwantRateMu.Unlock()
	if !allowed {
		// P2P-R21-H01: Penalize peers that exceed the IWANT rate limit.
		// Same rationale as the IHAVE rate-limit penalty: without it a
		// malicious peer can forever send IWANTs at exactly the ceiling,
		// forcing us to do the rate-limit bookkeeping on every RPC with
		// no scoring consequence. The penalty per violation equals one
		// invalid message; sustained flooding pushes the peer off the mesh.
		if gs.scorer != nil {
			gs.scorer.RecordInvalidMessage(from, "iwant-rate-limit")
		}
		return
	}

	// SECURITY (audit 2026-06-24, L-2): Collect matching messages under the
	// read lock, then release the lock before performing network I/O so that
	// a slow send does not block other topic operations.
	//
	// R14-MED (2026-07-21): Previously the topicsMu.RLock was acquired inside
	// the inner loop, causing up to maxIWantMessageIDs (256) redundant
	// RLock/RUnlock cycles per handleIWant call. Each cycle also iterated
	// every topic, so total cost was O(N*M*cacheLen). Hoisting the RLock
	// outside the loop reduces this to O(1) RLock acquisitions and keeps
	// the same O(N*M*cacheLen) scan but without lock contention overhead.
	// RLock is a reader lock so concurrent readers (other handleIWant /
	// handleIHave calls) are not blocked; only rare subscribe/unsubscribe
	// writers wait, which is acceptable.
	var messages []*Message
	// P2P-R21-H01: Track how many requested IDs were NOT found in any topic
	// cache. A peer that IWANTs non-existent message IDs is either buggy or
	// probing for amplification vectors — sustained misses accumulate a
	// RecordInvalidMessage penalty per miss, eventually pushing the peer
	// below scoreGraylist and off the mesh. We penalize per-miss so that
	// a peer sending 256 bogus IDs in one IWANT gets a much larger penalty
	// than one sending a single miss (which could be a legitimate race).
	missCount := 0
	gs.topicsMu.RLock()
	for _, msgID := range iwant.MessageIDs {
		found := false
		for _, t := range gs.topics {
			if msg := t.findCachedMessage(msgID); msg != nil {
				messages = append(messages, msg)
				found = true
				break
			}
		}
		if !found {
			missCount++
		}
	}
	gs.topicsMu.RUnlock()

	// P2P-R21-H01: Apply per-miss penalty. Cap the penalty at 3 misses per
	// IWANT (so a single oversized IWANT cannot instantly ban a peer), but
	// sustained bogus IWANTs across heartbeats will still accumulate.
	if gs.scorer != nil && missCount > 0 {
		penaltyMisses := missCount
		if penaltyMisses > 3 {
			penaltyMisses = 3
		}
		for i := 0; i < penaltyMisses; i++ {
			gs.scorer.RecordInvalidMessage(from, "iwant-miss")
		}
	}

	// Send messages outside the lock. Defense-in-depth: cap the number of
	// messages sent per handleIWant call so a peer cannot trigger an
	// unbounded burst even if it somehow bypassed the per-window rate limit
	// (e.g. via a long-lived connection that accumulates credit across
	// many windows before issuing one giant IWANT).
	const maxMessagesPerIWantResponse = 256
	if len(messages) > maxMessagesPerIWantResponse {
		messages = messages[:maxMessagesPerIWantResponse]
	}
	for _, msg := range messages {
		gs.sendMessageToPeer(from, msg)
	}
}

// =============================================================================
// Sending Helpers
// =============================================================================

func (gs *GossipSub) sendMessageToPeer(pid PeerID, msg *Message) {
	rpc := &RPC{
		Messages: []*Message{msg},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		// R14-MED (2026-07-21): Was silently dropped. Log so operators
		// can diagnose mesh degradation caused by encoding failures.
		log.Printf("[GossipSub] sendMessageToPeer: EncodeRPC failed for peer=%s msgID=%s: %v", pid, msg.ID, err)
		return
	}
	gs.sender.SendGossipSub(pid, data)
}

func (gs *GossipSub) sendGraft(pid PeerID, topic string) {
	rpc := &RPC{
		Control: &ControlMessage{
			Graft: []*ControlGraft{{Topic: topic}},
		},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		// R14-MED: Was silently dropped. GRAFT loss causes mesh
		// desynchronization — the peer never adds us to its mesh for
		// this topic, and we silently stop receiving messages.
		log.Printf("[GossipSub] sendGraft: EncodeRPC failed for peer=%s topic=%s: %v", pid, topic, err)
		return
	}
	gs.sender.SendGossipSub(pid, data)
}

func (gs *GossipSub) sendPrune(pid PeerID, topic string, reason string) {
	rpc := &RPC{
		Control: &ControlMessage{
			Prune: []*ControlPrune{{Topic: topic, Reason: reason}},
		},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		// R14-MED: Was silently dropped. PRUNE loss causes the peer to
		// keep sending us messages for a topic we left, wasting bandwidth
		// and creating mesh inconsistency.
		log.Printf("[GossipSub] sendPrune: EncodeRPC failed for peer=%s topic=%s: %v", pid, topic, err)
		return
	}
	gs.sender.SendGossipSub(pid, data)

	// SECURITY (audit P2P-09): Record prune time so that a premature GRAFT
	// from this peer for this topic is rejected until PruneBackoff elapses.
	// This prevents mesh churn from peers rapidly re-GRAFTing after PRUNE.
	gs.recordPrune(pid, topic)
}

// getOrCreatePeerState returns the peerState for pid, creating it if needed.
// Caller must NOT hold gs.peersMu. SECURITY (audit P2P-09).
func (gs *GossipSub) getOrCreatePeerState(pid PeerID) *peerState {
	gs.peersMu.Lock()
	defer gs.peersMu.Unlock()
	ps, exists := gs.peers[pid]
	if !exists {
		ps = &peerState{
			id:     pid,
			topics: make(map[string]*topicState),
		}
		gs.peers[pid] = ps
	}
	return ps
}

// inBackoff checks if a peer is in prune backoff for a topic.
// SECURITY (audit P2P-09): GRAFT from a peer still in backoff is rejected.
func (gs *GossipSub) inBackoff(pid PeerID, topic string) bool {
	gs.peersMu.RLock()
	ps, exists := gs.peers[pid]
	gs.peersMu.RUnlock()
	if !exists {
		return false
	}

	ps.mu.RLock()
	defer ps.mu.RUnlock()
	ts, exists := ps.topics[topic]
	if !exists || ts.pruneTime.IsZero() {
		return false
	}
	return time.Since(ts.pruneTime) < gs.cfg.PruneBackoff
}

// recordPrune records the prune time for a peer/topic pair.
// SECURITY (audit P2P-09): Enables backoff enforcement on subsequent GRAFTs.
func (gs *GossipSub) recordPrune(pid PeerID, topic string) {
	ps := gs.getOrCreatePeerState(pid)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ts, exists := ps.topics[topic]
	if !exists {
		ts = &topicState{topic: topic}
		ps.topics[topic] = ts
	}
	ts.pruneTime = time.Now()
}

// recordGraft records the graft time for a peer/topic pair.
// SECURITY (audit P2P-09): Bookkeeping for mesh membership tracking.
func (gs *GossipSub) recordGraft(pid PeerID, topic string) {
	ps := gs.getOrCreatePeerState(pid)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ts, exists := ps.topics[topic]
	if !exists {
		ts = &topicState{topic: topic}
		ps.topics[topic] = ts
	}
	ts.graftTime = time.Now()
}

func (gs *GossipSub) sendIWant(pid PeerID, msgIDs []MessageID) {
	rpc := &RPC{
		Control: &ControlMessage{
			IWant: []*ControlIWant{{MessageIDs: msgIDs}},
		},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		// R14-MED: Was silently dropped. IWANT loss means we never
		// request the message body from this peer, potentially leaving
		// a gap in our block/vote history.
		log.Printf("[GossipSub] sendIWant: EncodeRPC failed for peer=%s msgCount=%d: %v", pid, len(msgIDs), err)
		return
	}
	gs.sender.SendGossipSub(pid, data)

	// P2P-H01 (R24, 2026-07-25): Record a promise for each requested
	// message ID. The peer advertised these via IHAVE, so they implicitly
	// promised to deliver the message body when we IWANT it. If the
	// message doesn't arrive within GossipSubIWantPeerTimeout, the
	// heartbeat sweep penalizes the peer for breaking the promise.
	// Keyed by MessageID — if we already have an outstanding promise for
	// the same ID (e.g., re-requested after a partial timeout), the
	// latest peer/sentAt wins. This is intentional: we only penalize the
	// most recent advertiser, avoiding double-counting.
	now := time.Now()
	gs.iwantPromisesMu.Lock()
	for _, id := range msgIDs {
		gs.iwantPromises[id] = &iwantPromise{peer: pid, sentAt: now}
	}
	gs.iwantPromisesMu.Unlock()
}

func (gs *GossipSub) sendIHaveToRandom(t *Topic) {
	t.cacheMu.RLock()
	if len(t.messageCache) == 0 {
		t.cacheMu.RUnlock()
		return
	}

	// Collect recent message IDs
	msgIDs := make([]MessageID, 0, len(t.messageCache))
	for _, msg := range t.messageCache {
		msgIDs = append(msgIDs, msg.ID)
	}
	t.cacheMu.RUnlock()

	if len(msgIDs) == 0 {
		return
	}

	// Select random non-mesh peers to gossip to
	// Phase 1: Snapshot mesh state, then release
	t.meshMu.RLock()
	meshSet := make(map[PeerID]bool, len(t.mesh))
	for pid := range t.mesh {
		meshSet[pid] = true
	}
	t.meshMu.RUnlock()

	// Phase 2: Get non-mesh candidates under peersMu, then release
	gs.peersMu.RLock()
	var candidates []PeerID
	for pid := range gs.peers {
		if !meshSet[pid] {
			candidates = append(candidates, pid)
		}
	}
	gs.peersMu.RUnlock()

	if len(candidates) == 0 {
		return
	}

	// Gossip to a fraction of peers
	gossipCount := int(float64(len(candidates)) * GossipSubGossipFactor)
	if gossipCount < 1 {
		gossipCount = 1
	}
	if gossipCount > len(candidates) {
		gossipCount = len(candidates)
	}

	shuffleSlice(candidates)

	for i := 0; i < gossipCount; i++ {
		rpc := &RPC{
			Control: &ControlMessage{
				IHave: []*ControlIHave{{
					Topic:      t.name,
					MessageIDs: msgIDs,
				}},
			},
		}
		data, err := EncodeRPC(rpc)
		if err != nil {
			// R14-MED: Was silently `continue`. IHAVE loss reduces
			// message propagation coverage — peers we skipped never
			// learn we have these messages cached.
			log.Printf("[GossipSub] sendIHaveToRandom: EncodeRPC failed for peer=%s topic=%s msgCount=%d: %v", candidates[i], t.name, len(msgIDs), err)
			continue
		}
		gs.sender.SendGossipSub(candidates[i], data)
	}
}

// =============================================================================
// Topic helpers
// =============================================================================

func (t *Topic) cacheMessage(msg *Message) {
	t.cacheMu.Lock()
	defer t.cacheMu.Unlock()

	// AUDIT (2026) R3-P2P-04 FIX: Insert into the dedicated dedup cache
	// (seenMessages) for O(1) lookup with TTL eviction. The IHAVE cache
	// (messageCache) below remains bounded by HistoryLength for peer
	// advertisement queries. Previously both functions shared the same
	// 5-entry slice with O(n) linear scan, so under any realistic fan-out
	// the window rolled over in milliseconds and duplicates slipped past.
	now := time.Now()
	if _, exists := t.seenMessages[msg.ID]; !exists {
		t.seenMessages[msg.ID] = now
		// Safety cap: if the TTL pruner falls behind (e.g., heartbeats
		// stalled) or message rate spikes, drop oldest entries to keep
		// memory bounded. Normal operation relies on TTL eviction.
		if len(t.seenMessages) > t.gs.cfg.MaxSeenMessages {
			t.pruneSeenMessagesLocked(now)
			// P3-P2P-GOSSIP-EVICTION FIX (R29, 2026-07-26): If still over cap
			// after TTL pruning (clock skew or sustained spike), evict the
			// OLDEST entries by timestamp — NOT arbitrary entries via Go map
			// random iteration. The previous `for id := range t.seenMessages`
			// loop used Go's randomized map iteration order, which meant an
			// attacker flooding junk messages could cause legitimate recent
			// messages to be evicted. Once evicted, the attacker re-sends
			// the legitimate message ID; since it's no longer in the dedup
			// cache, it's treated as new and re-delivered to subscribers —
			// enabling message-replay amplification and mesh disruption.
			//
			// Evicting by oldest-timestamp is the correct policy because:
			//  1. It mirrors the TTL pruner's intent (older = more likely
			//     expired or stale).
			//  2. It is deterministic — the same set of entries will be
			//     evicted regardless of map iteration order, so an attacker
			//     cannot influence which entries survive by timing their
			//     flood to coincide with a favorable iteration order.
			//  3. It protects recently-cached legitimate messages: an
			//     attacker's flood messages all carry `now` as their
			//     timestamp, so they're the NEWEST and will not be evicted
			//     until after legitimate older messages — but legitimate
			//     older messages have already had time to be delivered to
			//     the mesh, so evicting them after delivery is safe (the
			//     dedup cache's purpose is to prevent RE-delivery, not to
			//     preserve delivery guarantees).
			//
			// The cost is O(N) per eviction sweep where N = current cache
			// size, but this sweep only runs when the cache exceeds
			// MaxSeenMessages (5000) — a rare event under normal operation.
			// Under attack, the sweep runs more often but bounds the
			// attacker's amplification: they can force at most
			// MaxSeenMessages/2 evictions before their own messages start
			// being evicted (since their messages are newest).
			for len(t.seenMessages) > t.gs.cfg.MaxSeenMessages {
				var oldestID MessageID
				var oldestTS time.Time
				first := true
				for id, ts := range t.seenMessages {
					if first || ts.Before(oldestTS) {
						oldestID = id
						oldestTS = ts
						first = false
					}
				}
				delete(t.seenMessages, oldestID)
			}
		}
	}

	// IHAVE cache: check duplicate, then append + trim to history length.
	for _, cached := range t.messageCache {
		if cached.ID == msg.ID {
			return
		}
	}
	t.messageCache = append(t.messageCache, msg)
	if len(t.messageCache) > t.gs.cfg.HistoryLength {
		t.messageCache = t.messageCache[len(t.messageCache)-t.gs.cfg.HistoryLength:]
	}
}

// pruneSeenMessagesLocked removes expired entries from the dedup cache.
// Caller MUST hold t.cacheMu (write).
func (t *Topic) pruneSeenMessagesLocked(now time.Time) {
	ttl := t.gs.cfg.MessageDedupTTL
	if ttl <= 0 {
		return
	}
	cutoff := now.Add(-ttl)
	for id, ts := range t.seenMessages {
		if ts.Before(cutoff) || ts.Equal(cutoff) {
			delete(t.seenMessages, id)
		}
	}
}

// PruneSeenMessages is the heartbeat-invoked wrapper that acquires the lock
// and trims expired entries from the dedup cache. Called from performHeartbeat.
func (t *Topic) PruneSeenMessages() {
	t.cacheMu.Lock()
	defer t.cacheMu.Unlock()
	t.pruneSeenMessagesLocked(time.Now())
}

func (t *Topic) hasSeenMessage(id MessageID) bool {
	// AUDIT (2026) R3-P2P-04 FIX: Look up in the dedicated dedup cache
	// (O(1) map lookup) instead of the IHAVE slice (O(n) linear scan).
	// Caller holds cacheMu.RLock().
	_, seen := t.seenMessages[id]
	return seen
}

func (t *Topic) findCachedMessage(id MessageID) *Message {
	t.cacheMu.RLock()
	defer t.cacheMu.RUnlock()
	for _, msg := range t.messageCache {
		if msg.ID == id {
			return msg
		}
	}
	return nil
}

// =============================================================================
// Utilities
// =============================================================================

// hashMessage computes a SHA3-256 hash of topic + data for message ID
func hashMessage(topic string, data []byte) []byte {
	// Use golang.org/x/crypto/sha3 as used elsewhere in the project
	return hashWithSHA3(append([]byte(topic), data...))
}

// hashWithSHA3 computes a SHA3-256 hash
func hashWithSHA3(data []byte) []byte {
	// We use a simple implementation to avoid importing sha3 in this package
	// The actual hash will use the project's crypto utilities
	h := make([]byte, 32)
	copy(h, simpleHash(data))
	return h
}

// simpleHash has been replaced with SHA3-256 to prevent message ID collisions.
// SECURITY (audit 2026-06-24, H-1): The previous XOR-based placeholder hash was
// trivially collisionable, allowing attackers to forge messages with duplicate
// MessageIDs and bypass gossip dedup. Use a cryptographic hash instead.
func simpleHash(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}

// shuffleSlice randomly shuffles a string slice using crypto/rand
func shuffleSlice(s []PeerID) {
	for i := len(s) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			continue
		}
		s[i], s[int(j.Int64())] = s[int(j.Int64())], s[i]
	}
}

// InjectRPC injects a decoded RPC message from a peer into the router.
// This is used by the simulation layer to bypass the network transport.
//
// R33 P2P-02 FIX (2026-07-28): Added defer recover() to prevent handler panics
// from crashing the process. deliverMessage/handleControl process untrusted
// remote data; a panic in any handler would kill the entire node without
// recovery.
//
// R33 P2-13 FIX (2026-07-28): Added explicit nil defense for rpc itself and
// for nil elements within rpc.Messages. Previously, only panic recovery
// protected against nil elements — but recovery is a coarse defense: it
// catches the panic AFTER the goroutine state is already unwound, losing
// all subsequent messages in the same RPC batch. Now we skip nil elements
// explicitly, so a single malformed (nil) message in a batch of 100 does
// not cause the other 99 valid messages to be dropped.
func (gs *GossipSub) InjectRPC(from PeerID, rpc *RPC) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ERROR] gossipsub: InjectRPC panic from peer %v: %v", from, r)
		}
	}()

	// R33 P2-13 FIX: Defensive nil check for rpc itself. Callers should
	// never pass nil, but the public API must not panic on nil input.
	if rpc == nil {
		log.Printf("[WARN] gossipsub: InjectRPC called with nil rpc from peer %v", from)
		return
	}

	gs.mu.Lock()
	if !gs.started {
		gs.mu.Unlock()
		return
	}
	gs.mu.Unlock()

	gs.peersMu.Lock()
	if _, ok := gs.peers[from]; !ok {
		gs.peers[from] = &peerState{
			id:     from,
			topics: make(map[string]*topicState),
		}
	}
	gs.peersMu.Unlock()

	// Process messages
	// R33 P2-13 FIX: Skip nil message elements explicitly. A nil element
	// in rpc.Messages indicates a decoder bug or a malformed message from
	// the wire. Skipping it preserves the rest of the batch.
	for _, msg := range rpc.Messages {
		if msg == nil {
			log.Printf("[WARN] gossipsub: InjectRPC skipping nil message from peer %v", from)
			continue
		}
		msg.From = from
		gs.deliverMessage(msg)
	}

	// Process control messages
	if rpc.Control != nil {
		gs.handleControl(from, rpc.Control)
	}
}

// GetMeshPeers returns the list of peer IDs in our mesh for a given topic.
func (gs *GossipSub) GetMeshPeers(topic string) []PeerID {
	gs.topicsMu.RLock()
	t, ok := gs.topics[topic]
	gs.topicsMu.RUnlock()
	if !ok {
		return nil
	}

	t.meshMu.RLock()
	defer t.meshMu.RUnlock()

	peers := make([]PeerID, 0, len(t.mesh))
	for pid := range t.mesh {
		peers = append(peers, pid)
	}
	return peers
}

// GetConnectedPeers returns all peers known to this GossipSub router.
func (gs *GossipSub) GetConnectedPeers() []PeerID {
	gs.peersMu.RLock()
	defer gs.peersMu.RUnlock()

	peers := make([]PeerID, 0, len(gs.peers))
	for pid := range gs.peers {
		peers = append(peers, pid)
	}
	return peers
}

// =============================================================================
// RPC Encoding/Decoding
// =============================================================================

// EncodeRPC encodes a GossipSub RPC to bytes
func EncodeRPC(rpc *RPC) ([]byte, error) {
	// Simple binary encoding:
	// Format: message_count(2) + [msg_len(4) + topic_len(1) + topic + seqno(8) + msgid(32) + data]
	//       + control_present(1) + [if present: graft_count(2) + prunes + ihaves + iwants]

	// Calculate total size
	totalSize := 2 // message count
	for _, msg := range rpc.Messages {
		totalSize += 4 + 1 + len(msg.Topic) + 8 + 32 + len(msg.Data)
	}
	totalSize += 1 // control present flag

	if rpc.Control != nil {
		totalSize += 2 // graft count
		for _, g := range rpc.Control.Graft {
			totalSize += 1 + len(g.Topic)
		}
		totalSize += 2 // prune count
		for _, p := range rpc.Control.Prune {
			totalSize += 1 + len(p.Topic) + 1 + len(p.Reason)
		}
		totalSize += 2 // ihave count
		for _, ih := range rpc.Control.IHave {
			totalSize += 1 + len(ih.Topic) + 2 + len(ih.MessageIDs)*32
		}
		totalSize += 2 // iwant count
		for _, iw := range rpc.Control.IWant {
			totalSize += 2 + len(iw.MessageIDs)*32
		}
	}

	buf := make([]byte, totalSize)
	offset := 0

	// Encode messages
	msgCount := uint16(len(rpc.Messages))
	binary.BigEndian.PutUint16(buf[offset:], msgCount)
	offset += 2

	for _, msg := range rpc.Messages {
		// Message length (placeholder, fill later)
		msgLenPos := offset
		offset += 4

		// Topic
		topicLen := byte(len(msg.Topic))
		buf[offset] = topicLen
		offset++
		copy(buf[offset:], msg.Topic)
		offset += int(topicLen)

		// SeqNo
		binary.BigEndian.PutUint64(buf[offset:], msg.SeqNo)
		offset += 8

		// MessageID
		copy(buf[offset:], msg.ID[:])
		offset += 32

		// Data
		copy(buf[offset:], msg.Data)
		offset += len(msg.Data)

		// Fill message length
		msgLen := uint32(offset - msgLenPos - 4)
		binary.BigEndian.PutUint32(buf[msgLenPos:], msgLen)
	}

	// Control present flag
	if rpc.Control != nil {
		buf[offset] = 1
		offset++

		// Graft
		graftCount := uint16(len(rpc.Control.Graft))
		binary.BigEndian.PutUint16(buf[offset:], graftCount)
		offset += 2
		for _, g := range rpc.Control.Graft {
			buf[offset] = byte(len(g.Topic))
			offset++
			copy(buf[offset:], g.Topic)
			offset += len(g.Topic)
		}

		// Prune
		pruneCount := uint16(len(rpc.Control.Prune))
		binary.BigEndian.PutUint16(buf[offset:], pruneCount)
		offset += 2
		for _, p := range rpc.Control.Prune {
			buf[offset] = byte(len(p.Topic))
			offset++
			copy(buf[offset:], p.Topic)
			offset += len(p.Topic)
			buf[offset] = byte(len(p.Reason))
			offset++
			copy(buf[offset:], p.Reason)
			offset += len(p.Reason)
		}

		// IHave
		ihaveCount := uint16(len(rpc.Control.IHave))
		binary.BigEndian.PutUint16(buf[offset:], ihaveCount)
		offset += 2
		for _, ih := range rpc.Control.IHave {
			buf[offset] = byte(len(ih.Topic))
			offset++
			copy(buf[offset:], ih.Topic)
			offset += len(ih.Topic)
			idCount := uint16(len(ih.MessageIDs))
			binary.BigEndian.PutUint16(buf[offset:], idCount)
			offset += 2
			for _, id := range ih.MessageIDs {
				copy(buf[offset:], id[:])
				offset += 32
			}
		}

		// IWant
		iwantCount := uint16(len(rpc.Control.IWant))
		binary.BigEndian.PutUint16(buf[offset:], iwantCount)
		offset += 2
		for _, iw := range rpc.Control.IWant {
			idCount := uint16(len(iw.MessageIDs))
			binary.BigEndian.PutUint16(buf[offset:], idCount)
			offset += 2
			for _, id := range iw.MessageIDs {
				copy(buf[offset:], id[:])
				offset += 32
			}
		}
	} else {
		buf[offset] = 0
		offset++
	}

	return buf[:offset], nil
}

// DecodeRPC decodes a GossipSub RPC from bytes
func DecodeRPC(data []byte) (*RPC, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("RPC too short")
	}

	rpc := &RPC{}
	offset := 0

	// Decode messages
	msgCount := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// SECURITY (audit P2P-10): Cap message count at decode time to prevent
	// unbounded pre-allocation from a peer-supplied uint16 (up to 65535).
	if msgCount > GossipSubMaxMessages {
		return nil, fmt.Errorf("RPC message count %d exceeds max %d", msgCount, GossipSubMaxMessages)
	}

	rpc.Messages = make([]*Message, 0, msgCount)
	for i := uint16(0); i < msgCount; i++ {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("RPC truncated at message %d", i)
		}
		msgLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		end := offset + int(msgLen)
		if end > len(data) {
			return nil, fmt.Errorf("RPC message %d exceeds data length", i)
		}

		msg := &Message{}

		// Topic
		if offset >= len(data) {
			return nil, fmt.Errorf("RPC truncated at topic length")
		}
		topicLen := data[offset] // #nosec G602 -- offset<len(data) checked above
		offset++
		if offset+int(topicLen) > end {
			return nil, fmt.Errorf("RPC topic exceeds message boundary")
		}
		msg.Topic = string(data[offset : offset+int(topicLen)])
		offset += int(topicLen)

		// SeqNo
		if offset+8 > end {
			return nil, fmt.Errorf("RPC truncated at seqno")
		}
		msg.SeqNo = binary.BigEndian.Uint64(data[offset:])
		offset += 8

		// MessageID
		if offset+32 > end {
			return nil, fmt.Errorf("RPC truncated at message ID")
		}
		copy(msg.ID[:], data[offset:offset+32])
		offset += 32

		// Data
		// N5 FIX (2026-07-06 R2): Enforce message size limit on deserialization.
		dataLen := end - offset
		if dataLen > MaxMessageSize {
			return nil, fmt.Errorf("message too large: %d bytes (max %d)", dataLen, MaxMessageSize)
		}
		msg.Data = make([]byte, dataLen)
		copy(msg.Data, data[offset:end])
		offset = end

		msg.ReceivedAt = time.Now()
		rpc.Messages = append(rpc.Messages, msg)
	}

	// Control
	if offset < len(data) {
		hasControl := data[offset]
		offset++

		if hasControl == 1 && offset < len(data) {
			ctrl := &ControlMessage{}

			// Graft
			if offset+2 <= len(data) {
				graftCount := binary.BigEndian.Uint16(data[offset:])
				offset += 2
				// SECURITY (audit P2P-10): Cap at decode time.
				if graftCount > GossipSubMaxGrafts {
					return nil, fmt.Errorf("graft count %d exceeds max %d", graftCount, GossipSubMaxGrafts)
				}
				for i := uint16(0); i < graftCount; i++ {
					if offset >= len(data) {
						break
					}
					topicLen := data[offset]
					offset++
					if offset+int(topicLen) > len(data) {
						break
					}
					topic := string(data[offset : offset+int(topicLen)])
					offset += int(topicLen)
					ctrl.Graft = append(ctrl.Graft, &ControlGraft{Topic: topic})
				}
			}

			// Prune
			if offset+2 <= len(data) {
				pruneCount := binary.BigEndian.Uint16(data[offset:])
				offset += 2
				// SECURITY (audit P2P-10): Cap at decode time.
				if pruneCount > GossipSubMaxPrunes {
					return nil, fmt.Errorf("prune count %d exceeds max %d", pruneCount, GossipSubMaxPrunes)
				}
				for i := uint16(0); i < pruneCount; i++ {
					if offset >= len(data) {
						break
					}
					topicLen := data[offset]
					offset++
					if offset+int(topicLen) > len(data) {
						break
					}
					topic := string(data[offset : offset+int(topicLen)])
					offset += int(topicLen)

					if offset >= len(data) {
						break
					}
					reasonLen := data[offset]
					offset++
					if offset+int(reasonLen) > len(data) {
						break
					}
					reason := string(data[offset : offset+int(reasonLen)])
					offset += int(reasonLen)

					ctrl.Prune = append(ctrl.Prune, &ControlPrune{Topic: topic, Reason: reason})
				}
			}

			// IHave
			if offset+2 <= len(data) {
				ihaveCount := binary.BigEndian.Uint16(data[offset:])
				offset += 2
				// SECURITY (audit P2P-10): Cap at decode time.
				if ihaveCount > GossipSubMaxIHave {
					return nil, fmt.Errorf("ihave count %d exceeds max %d", ihaveCount, GossipSubMaxIHave)
				}
				for i := uint16(0); i < ihaveCount; i++ {
					if offset >= len(data) {
						break
					}
					topicLen := data[offset]
					offset++
					if offset+int(topicLen) > len(data) {
						break
					}
					topic := string(data[offset : offset+int(topicLen)])
					offset += int(topicLen)

					if offset+2 > len(data) {
						break
					}
					idCount := binary.BigEndian.Uint16(data[offset:])
					offset += 2

					// SECURITY (audit P2P-10): Cap MessageID count per IHAVE at
					// decode time to prevent unbounded iteration.
					if idCount > GossipSubMaxMsgIDsPerIHave {
						return nil, fmt.Errorf("ihave msgid count %d exceeds max %d", idCount, GossipSubMaxMsgIDsPerIHave)
					}

					// P2P-GS-01 FIX (deep-audit 2026-07-12): bound the capacity
					// hint to what the remaining bytes can actually hold (each ID is
					// 32 bytes). A peer-supplied idCount (up to 65535) across many
					// IHave entries otherwise forces ~131GB of pre-allocation from a
					// ~200KB message. The inner loop already breaks on short data.
					ihaveHint := int(idCount)
					if rem := (len(data) - offset) / 32; ihaveHint > rem {
						ihaveHint = rem
					}
					ihave := &ControlIHave{Topic: topic, MessageIDs: make([]MessageID, 0, ihaveHint)}
					for j := uint16(0); j < idCount; j++ {
						if offset+32 > len(data) {
							break
						}
						var id MessageID
						copy(id[:], data[offset:offset+32])
						offset += 32
						ihave.MessageIDs = append(ihave.MessageIDs, id)
					}
					ctrl.IHave = append(ctrl.IHave, ihave)
				}
			}

			// IWant
			if offset+2 <= len(data) {
				iwantCount := binary.BigEndian.Uint16(data[offset:])
				offset += 2
				// SECURITY (audit P2P-10): Cap at decode time.
				if iwantCount > GossipSubMaxIWant {
					return nil, fmt.Errorf("iwant count %d exceeds max %d", iwantCount, GossipSubMaxIWant)
				}
				for i := uint16(0); i < iwantCount; i++ {
					if offset+2 > len(data) {
						break
					}
					idCount := binary.BigEndian.Uint16(data[offset:])
					offset += 2

					// SECURITY (audit P2P-10): Cap MessageID count per IWANT at
					// decode time to prevent unbounded iteration.
					if idCount > GossipSubMaxMsgIDsPerIWant {
						return nil, fmt.Errorf("iwant msgid count %d exceeds max %d", idCount, GossipSubMaxMsgIDsPerIWant)
					}

					// P2P-GS-01 FIX (deep-audit 2026-07-12): bound the capacity hint
					// to the bytes actually remaining (32 per ID), as for IHave above.
					iwantHint := int(idCount)
					if rem := (len(data) - offset) / 32; iwantHint > rem {
						iwantHint = rem
					}
					iwant := &ControlIWant{MessageIDs: make([]MessageID, 0, iwantHint)}
					for j := uint16(0); j < idCount; j++ {
						if offset+32 > len(data) {
							break
						}
						var id MessageID
						copy(id[:], data[offset:offset+32])
						offset += 32
						iwant.MessageIDs = append(iwant.MessageIDs, id)
					}
					ctrl.IWant = append(ctrl.IWant, iwant)
				}
			}

			rpc.Control = ctrl
		}
	}

	return rpc, nil
}
