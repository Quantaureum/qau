// Quantaureum Node source, version 1.0.0.
// Package p2p implements the peer-to-peer network layer for Quantaureum.
// This implementation provides a foundation that can be extended with libp2p.
package p2p

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/metrics"
	"github.com/quantaureum/qau/p2p/discover"
	"github.com/quantaureum/qau/p2p/enode"
	"github.com/quantaureum/qau/p2p/gossipsub"
	"github.com/quantaureum/qau/types"
)

var hostLog = logging.Global()

const (
	// ProtocolID is the protocol identifier for Quantaureum
	ProtocolID = "/qau/1.0.0"

	// DiscoveryNamespace is the namespace for peer discovery
	DiscoveryNamespace = "qau-network"

	// DefaultPort is the default P2P port
	DefaultPort = 9000

	// HandshakeTimestampTolerance is the maximum allowed age of a handshake timestamp
	// to prevent replay attacks. Handshake messages older than this are rejected.
	// SECURITY FIX Q-B-009: Increased from 10s to 30s. 10 seconds is too tight for
	// global distributed nodes with NTP drift, VM clock skew, and network latency.
	// 30s maintains replay resistance while preventing false positives.
	HandshakeTimestampTolerance = 30 * time.Second

	// DefaultHandshakeTimeout is the deadline applied to an inbound/outbound
	// connection for the full handshake to complete.  (P3): previously a
	// hardcoded 60s magic number inline in handleConnection; extracted to a named
	// constant so it is visible and tunable. 60s tolerates high-latency/global
	// peers plus the Dilithium3 PoW handshake without hanging connections open.
	DefaultHandshakeTimeout = 60 * time.Second

	// defaultPeerReadTimeout is the per-message read deadline applied inside
	// readLoop before each header read. R14-LOW (P2P-LOW-09): previously an
	// inline `120 * time.Second` magic number at the SetReadDeadline call site
	// — promoted to a named constant alongside DefaultHandshakeTimeout so it
	// is discoverable and tunable in one place. 120s is generous: a healthy
	// peer sends a header within milliseconds; the long timeout tolerates GC
	// pauses, network jitter, and slow block propagation on far-flung nodes
	// without prematurely disconnecting them.
	defaultPeerReadTimeout = 120 * time.Second

	// defaultMaxPerIPHandshakes caps the number of concurrent inbound PQ
	// handshakes a single remote IP may have in flight. AUDIT (2026)
	// R4-P2P-02: Without this cap, a single IP can open 32 stalled TCP
	// connections and monopolize all handshakeSem slots for ~60s each.
	// A limit of 3 allows legitimate nodes behind NAT (multiple peers
	// share one public IP) to connect while blocking per-IP handshake
	// flooding. Legitimate peers that need more concurrent inbound
	// handshakes should use distinct IPs.
	defaultMaxPerIPHandshakes = 3

	// defaultMaxPerIPMessages caps the number of post-handshake messages
	// a single remote IP may send per second. P2P-R12-M02 (2026-07-20):
	// the existing rateLimiter is per-PeerID (500 msg/sec). Combined with
	// defaultMaxPerIPHandshakes=3, an attacker controlling 3 peers from one
	// IP could otherwise send up to 1500 msg/sec — 3× the per-peer limit.
	// This per-IP limiter bounds the aggregate post-handshake message rate
	// at 1000 msg/sec per IP (2× the per-peer limit, accommodating
	// legitimate NAT scenarios where 2 honest peers share one public IP).
	// Reuses the existing RateLimiter primitive (keyed by PeerID(ip)) so
	// the same sliding-window + eviction + violation-tracking machinery
	// applies. Violations escalate through the same penaltyManager as
	// per-peer rate-limit violations.
	defaultMaxPerIPMessages = 1000

	// defaultMaxPerIPConnAttemptsPerSec caps the number of inbound TCP
	// connection ATTEMPTS a single remote IP may make per second.
	//
	// R32-P3-03 FIX (2026-07-28): the existing perIPLimiter (concurrent
	// handshake cap = 3) only bounds IN-FLIGHT handshakes. It does NOT
	// bound the rate of new connection attempts — an attacker can rapidly
	// cycle connect→reject→reconnect thousands of times per second. Each
	// attempt consumes:
	//   - one net.Conn accept + goroutine spawn in acceptLoop
	//   - one perIPLimiter.acquire call (map lookup + mutex)
	//   - one warn log line on rejection (disk I/O)
	//   - one metrics.AddHandshakeFailure counter increment
	// Even though all attempts are rejected at the perIPLimiter gate, the
	// aggregate resource consumption can degrade node performance.
	//
	// 10 attempts/sec/IP is well above legitimate peer reconnection rates
	// (a healthy peer reconnects at most once per minute after a network
	// blip). It catches automated connection flooding while allowing
	// legitimate NAT retry behavior (typical NAT gives up after 3-5 SYN
	// retries within ~10 seconds, well under 10/sec sustained).
	//
	// Reuses the existing RateLimiter primitive (keyed by PeerID(ip)) so
	// the same sliding-window + eviction + violation-tracking machinery
	// applies. This limiter runs BEFORE perIPLimiter.acquire and BEFORE
	// the PQ handshake, so a flooding IP is rejected without any
	// cryptographic work or log noise.
	defaultMaxPerIPConnAttemptsPerSec = 10

	// defaultMaxPerPeerTxsPerSec caps the number of transaction messages
	// (MsgTypeTransaction and MsgTypeTxHashResponse) a single peer may send
	// per second.
	//
	// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): The global rateLimiter
	// (500 msg/sec) applies to ALL non-sync message types, so a peer could
	// use its entire 500 msg/sec budget on MsgTypeTransaction alone. Since
	// each transaction triggers Dilithium3 signature verification (CPU-
	// intensive, ~3293-byte signature), 500 txs/sec from a single peer
	// would saturate the verification pipeline and starve legitimate txs.
	//
	// 50 txs/sec/peer is 10% of the global per-peer message budget —
	// generous enough for honest block builders and DEX bots (which rarely
	// exceed 10 txs/sec), but tight enough to prevent a single peer from
	// monopolizing the BatchValidateWithState goroutine pool. The limit is
	// per-PeerID, so a Sybil attacker controlling N peers gets N×50 = 50N
	// txs/sec aggregate, bounded by the per-IP limiter (1000 msg/sec) and
	// per-IP handshake cap (3 concurrent).
	defaultMaxPerPeerTxsPerSec = 50

	// defaultMaxPerPeerOutboundMsgsPerSec caps the number of messages the
	// node writes to a single peer's connection per second (outbound rate).
	//
	// P2-WRITELOOP-RATELIMIT FIX (R29, 2026-07-26): Previously writeLoop had
	// NO outbound rate limit — a peer could send many MsgTypeBlockReq
	// messages (within the inbound 500 msg/sec cap) and trigger an equal
	// number of large MsgTypeBlockResp messages, saturating the outbound
	// bandwidth and starving other peers. The inbound rate limiter counts
	// messages, not bytes, so it doesn't limit amplification (1-byte
	// request → 10MB response).
	//
	// 200 msg/sec/peer is 40% of the inbound per-peer cap (500/sec). This
	// allows legitimate sync (which sends ~10-50 msg/sec during catch-up)
	// while bounding amplification. When the limit is hit, the message is
	// dropped (not queued) — this is preferable to blocking writeLoop
	// (which would stall all peers' write loops via a shared broadcast
	// goroutine). Dropped messages are logged so operators can detect
	// sustained rate-limiting (which may indicate a misconfigured peer or
	// an attack).
	defaultMaxPerPeerOutboundMsgsPerSec = 200
)

// perIPHandshakeLimiter tracks the number of in-flight inbound handshakes per
// remote IP. It runs BEFORE the PQ handshake (ServerHandshake) and BEFORE the
// global handshakeSem acquisition, so a flooding IP is rejected without
// consuming any post-quantum cryptography resources.
//
// AUDIT (2026) R4-P2P-02 FIX: Previously, the only pre-handshake gate
// was the global handshakeSem (cap 32). CheckConnection (which has per-/24
// and per-/16 limits) runs only AFTER ServerHandshake, so a single IP
// could hold all 32 slots for the full handshake timeout. This limiter
// provides the missing pre-handshake per-IP admission control.
type perIPHandshakeLimiter struct {
	mu       sync.Mutex
	counts   map[string]int
	maxPerIP int
}

func newPerIPHandshakeLimiter(maxPerIP int) *perIPHandshakeLimiter {
	return &perIPHandshakeLimiter{
		counts:   make(map[string]int),
		maxPerIP: maxPerIP,
	}
}

// acquire returns true if the IP is below the per-IP cap and increments
// the in-flight count. Returns false if the IP is already at the cap.
func (l *perIPHandshakeLimiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] >= l.maxPerIP {
		return false
	}
	l.counts[ip]++
	return true
}

// release decrements the in-flight count for the IP. Safe to call even if
// the count is already zero (defensive — the caller uses defer).
func (l *perIPHandshakeLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] > 0 {
		l.counts[ip]--
		if l.counts[ip] == 0 {
			delete(l.counts, ip)
		}
	}
}

// extractIPFromAddr is defined in ratelimit.go (P2P-C-02 R29 version with
// full IP normalization and empty-input handling).

// PeerID represents a unique peer identifier
type PeerID string

// NewPeerID generates a new random peer ID.
// Returns error if crypto/rand fails.
func NewPeerID() (PeerID, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	return PeerID(hex.EncodeToString(b)), nil
}

// String returns the string representation of the peer ID
func (p PeerID) String() string {
	return string(p)
}

// Config holds the P2P network configuration
type Config struct {
	// ListenAddr is the address to listen on
	ListenAddr string

	// BootstrapPeers are the initial peers to connect to
	BootstrapPeers []string

	// MaxPeers is the maximum number of peers to connect to
	MaxPeers int

	// MaxInboundPeers caps the number of INBOUND (accepted) connections.
	// SYNC-P2P-02 FIX (deep-audit 2026-07-12): without a separate inbound limit,
	// an adversary can open MaxPeers inbound connections, filling the peer table
	// and starving outbound/bootstrap dials to honest peers (an eclipse vector).
	// When 0, it defaults to MaxPeers*2/3, reserving ~1/3 of slots for outbound.
	MaxInboundPeers int

	// NodeID is the node's unique identifier
	NodeID PeerID

	// EnableDHT enables DHT-based peer discovery
	EnableDHT bool

	// NodeDBPath is the path to persist discovered nodes
	NodeDBPath string

	// TrustedPeers is a whitelist of trusted peer IDs (hex-encoded).
	// When WhitelistOnly is true, only these peers are allowed to connect.
	TrustedPeers []string

	// WhitelistOnly restricts connections to TrustedPeers only.
	// In this mode, unknown nodes are rejected at connection time and
	// discovered nodes not in the whitelist are ignored.
	WhitelistOnly bool

	// DevMode skips expensive PoW computation for local development
	DevMode bool

	// NetworkID is the network chain ID (1668=mainnet, 1669=testnet, 1333=devnet).
	// Used for security assertions: DevMode should never be enabled on mainnet.
	NetworkID uint64

	// NodeKeyPath is the path to a file containing a 32-byte hex-encoded seed
	// for deterministic Dilithium3 key pair generation. If the file exists,
	// the node identity (PeerID/enode) is stable across restarts.
	// If the file does not exist, a new seed is generated and saved.
	NodeKeyPath string

	// ExternalIP is the publicly reachable IP address of this node.
	// Used to construct the enode URL advertised to other peers.
	// If empty, the IP from the listener is used (which may be 0.0.0.0 or ::).
	ExternalIP string

	// ConnPool is the connection pool configuration. When nil, the Host
	// uses DefaultConnPoolConfig() for outbound-maintenance decisions.
	// P2P-R28-H01: MinOutboundConns and MinOutboundRatio are now enforced
	// by outboundMaintenanceLoop (started in Start()).
	ConnPool *ConnPoolConfig
}

// DefaultConfig returns a default P2P configuration.
// R40-L4 FIX: Returns an error instead of silently using an empty PeerID when
// crypto/rand fails. An empty PeerID is a security risk — it allows the node to
// connect with a predictable/colliding identity, enabling impersonation attacks.
// Callers must handle the error (e.g., by refusing to start the node).
//
//	SECURITY NOTE: The default ListenAddr is 127.0.0.1 (localhost only).
//
// Operators who change ListenAddr to 0.0.0.0 must ensure:
//  1. A firewall restricts access to the P2P port (9000) to trusted peers.
//  2. ExternalIP is set to the node's public IP so discovery advertises a
//     reachable address (see ).
//  3. TLS is enabled (see R32-P4-4b certificate manager).
//
// Binding to 0.0.0.0 without these precautions exposes the node to direct
// internet attacks and makes it unreachable by discovery peers.
func DefaultConfig() (*Config, error) {
	nodeID, err := NewPeerID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate peer ID for default config: %w", err)
	}
	return &Config{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", DefaultPort),
		MaxPeers:   200, // Phase 1: 50→200 for 50-node scaling
		NodeID:     nodeID,
		EnableDHT:  true,
	}, nil
}

// Host represents a P2P network host
type Host struct {
	config *Config
	id     PeerID

	// audit-fix R2-H1: Dilithium3 key pair for cryptographic peer authentication.
	// The private key signs challenges; the public key is sent to peers for verification.
	// PeerID is derived from the public key hash, binding identity to the key.
	nodeKeyPair *crypto.KeyPair

	// audit-fix LEGACY-1: Pre-computed PoW nonce for Sybil resistance.
	// Computed once at Host creation from our enode.ID so that:
	// 1. Host's custom handshake (verifyPeerProofOfWork) can use it directly
	// 2. RLPx connections can be configured via SetPoWNonce before handshake
	// Without this, RLPx AuthMessagePQ.PowNonce would be 0, causing PoW verification
	// to fail on the remote side and breaking Sybil resistance.
	powNonce uint64

	// Network
	listener net.Listener
	peers    map[PeerID]*Peer
	peersMu  sync.RWMutex

	// AUDIT (2026) HIGH-15: semaphore limiting concurrent inbound PQ
	// handshakes to prevent pre-authentication resource exhaustion. Each
	// inbound connection runs the Kyber768+Dilithium3 handshake in its own
	// goroutine; this channel caps how many can run simultaneously.
	handshakeSem chan struct{}

	// AUDIT (2026) R4-P2P-02: per-IP inbound handshake limiter.
	// Prevents a single IP from monopolizing all 32 handshakeSem slots
	// by opening many stalled TCP connections (each holds a slot for
	// up to DefaultHandshakeTimeout ~30s). The limiter runs BEFORE the
	// handshakeSem acquisition and before ServerHandshake, so a
	// flooding IP is rejected without consuming PQ handshake resources.
	perIPLimiter *perIPHandshakeLimiter

	// Message channels
	blockCh    chan []byte
	blockReqCh chan PeerMessage // audit-fix R2-M4: carries peer ID so handler can reply to requester only
	txCh       chan []byte
	txBatchCh  chan []byte // TPS FIX: Buffer for batched tx broadcast (reduces P2P message count)
	voteCh     chan []byte
	// R45 (2026-08-12): commit-reveal gossip — REMOVED by CRV2. Commitments are
	// now on-chain TxTypeCommit transactions, so the index is built from block
	// application (node/syncer.go) and pool admission (txpool/pool.go) instead of
	// being gossiped. The channel and its subscriber (Node.commitProcessingLoop)
	// are gone; MsgTypeCommit is still registered in the message validator so a
	// peer running the old build gets a clean rejection rather than a protocol
	// error, but nothing produces or consumes those frames anymore.
	statusCh  chan PeerMessage // Channel for status messages (carries From peerID)
	expertCh  chan []byte      // Channel for expert network messages
	snapCh    chan []byte      // Channel for snap sync messages
	snapReqCh chan PeerMessage // Channel for snap sync requests
	// ETHEREUM-PARITY SYNC (2026-08-13): typed response channel for the
	// extended sync protocol (snap storage/bytecode, headers, receipts).
	// snapCh is []byte and cannot carry the message type, so responses for
	// the new message kinds are dispatched here instead.
	syncRespCh   chan PeerMessage
	checkpointCh chan []byte      // Channel for checkpoint signature/request messages
	tssCh        chan PeerMessage // Channel for TSS (threshold signature) messages
	qtdSealCh    chan PeerMessage // P1-4: Channel for QTD partial seal messages
	dasReqCh     chan PeerMessage // P0-10: Channel for DAS sample requests (incoming)

	// P1-12 (RPC-H1, 2026-07-19): Per-request response routing for DAS
	// sample responses. Each in-flight SendSampleRequest registers a
	// pending channel keyed by the RequestID it placed in the wire-level
	// DASSampleRequest. handleDASProtocol reads the RequestID from the
	// incoming response payload and dispatches it to the matching
	// pending channel. This closes the response-confusion vector where
	// previously a shared broadcast channel (dasRespCh) was consumed by
	// whatever sampler happened to call SubscribeDASResponses first,
	// allowing a malicious peer to inject arbitrary cell data matched
	// to the wrong request, or to starve a specific sampler by
	// pre-empting its response.
	dasPending   map[uint64]chan PeerMessage
	dasPendingMu sync.Mutex

	// P1-1 (2026-07-14): Shard protocol channels
	shardBlockCh        chan []byte      // Shard block broadcasts (proposer → validators)
	shardBlockReqCh     chan PeerMessage // Shard block requests (carries PeerID for reply)
	shardBlockRespCh    chan PeerMessage // Shard block responses (sync reply)
	shardAttestationCh  chan []byte      // Shard finalization attestations (validator → proposer)
	crossShardMsgCh     chan []byte      // Cross-shard message propagation
	crossShardReceiptCh chan []byte      // Cross-shard receipt propagation

	// Rate limiter
	rateLimiter *RateLimiter

	// P2P-R12-M02 (2026-07-20): post-handshake per-IP message rate limiter.
	// Same *RateLimiter primitive as rateLimiter, but keyed by PeerID(ip)
	// instead of PeerID. Bounds aggregate post-handshake message rate per
	// remote IP so an attacker cannot multiply throughput by opening many
	// peer connections from one IP (within the per-IP handshake cap).
	perIPRateLimiter *RateLimiter

	// R32-P3-03 (2026-07-28): pre-handshake per-IP connection ATTEMPT rate
	// limiter. Bounds the rate of new inbound TCP connection attempts per
	// remote IP. Runs BEFORE perIPLimiter.acquire and BEFORE the PQ
	// handshake, so a flooding IP is rejected without consuming any
	// cryptographic work or in-flight handshake slot. Reuses the existing
	// *RateLimiter primitive (keyed by PeerID(ip)) for sliding-window +
	// eviction + violation-tracking consistency with perIPRateLimiter.
	perIPConnRateLimiter *RateLimiter

	// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): per-peer transaction rate
	// limiter. Tighter than the global rateLimiter because each tx triggers
	// expensive Dilithium3 signature verification. Without this, a peer could
	// use its entire 500 msg/sec budget on MsgTypeTransaction, saturating
	// the verification pipeline. See defaultMaxPerPeerTxsPerSec for rationale.
	txRateLimiter *RateLimiter

	// P2-WRITELOOP-RATELIMIT FIX (R29, 2026-07-26): per-peer OUTBOUND rate
	// limiter. Caps the number of messages writeLoop writes to a single
	// peer's connection per second. Without this, a peer could trigger
	// amplification attacks (small request → large response) that saturate
	// outbound bandwidth. See defaultMaxPerPeerOutboundMsgsPerSec for
	// rationale.
	outRateLimiter *RateLimiter

	// Blacklist
	blacklist *Blacklist

	// PenaltyManager — Phase 1: tiered penalty mechanism
	penaltyManager *PenaltyManager

	// Broadcaster
	broadcaster *Broadcaster

	// Message validator (Requirements: 3.3, 3.4)
	messageValidator *MessageValidator

	// audit-fix P2P-1: Sybil/eclipse resistance integrated into Host
	sybilResistance *SybilResistance

	// Node discovery: Kademlia-like routing table for peer discovery
	discoverTable *discover.Table

	// UDP discovery transport (separate from TCP data channel)
	udpTransport *discover.UDPTransport

	// Peer scoring system for multi-dimensional reputation tracking
	peerScorer *PeerScorer

	// Protocol registry for sub-protocol negotiation and routing
	protocolRegistry *ProtocolRegistry

	// Whitelist for trusted peers (fast lookup set)
	trustedPeers   map[PeerID]bool
	trustedPeersMu sync.RWMutex

	// R15-CRIT-001 (2026-07-22): per-peer CRL message rate limiting.
	// A malicious peer could otherwise flood the local node with CRL
	// snapshots, each requiring JSON unmarshal + monotonic merge under
	// the CRL write lock. 5 minutes / peer is generous (legitimate
	// nodes broadcast at most once per 5-minute ticker) while bounding
	// worst-case lock contention under attack.
	crlRateLimiter   map[PeerID]time.Time
	crlRateLimiterMu sync.Mutex

	// P2P-R16-M06 (2026-07-23) FIX: Replaces testing.Testing() bypass.
	// When true, crlAuthorizeIssuer skips all CRL issuer authentication.
	// Defaults to false (secure). Tests set this to true via struct literal
	// to bypass auth for CRL messages constructed without signatures.
	// Production code MUST NOT set this to true.
	skipCRLAuth bool

	// GossipSub router — Phase 2: topic-based message propagation
	gossipSubRouter *gossipsub.GossipSub

	// CompactTxManager — TPS OPTIMIZATION: compact tx propagation
	// Broadcasts 32-byte tx hashes instead of 5.5KB full txs, reducing
	// P2P bandwidth by ~99% during high-throughput bursts.
	compactTx *CompactTxManager

	// CompactBlockManager — TPS OPTIMIZATION: compact block propagation
	// Broadcasts block header + tx hashes (~45KB) instead of full block (~7.3MB).
	compactBlock *CompactBlockManager

	// TSS: validator address → peer ID mapping for directed TSS message routing.
	// Populated by the node layer when validators connect and announce their addresses.
	validatorPeerMap   map[types.Address]PeerID
	validatorPeerMapMu sync.RWMutex
	// AUDIT-FULL H-2 FIX (2026-08-14): the exported RegisterValidatorPeer is
	// denied by default. Only the Host's own verified status path (internal
	// registerValidatorPeer) may write mappings, unless the node layer
	// explicitly grants the capability via AuthorizeValidatorRegistration.
	validatorRegAuthorized int32

	// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02): active-set verifier +
	// clock-skew freshness window + anti-replay nonce tracker. All three
	// are OPTIONAL — when nil/zero the host falls back to the R37 + R38-P2-01
	// Fix behavior (signature check + Address-binding check). When set,
	// the host additionally requires:
	//   (a) (address, pubKey) is in the chain's CURRENT active validator
	//       set (avoids stale-tval polluting router)
	//   (b) status.Timestamp within +/- statusFreshnessWindowSec of wall clock
	//       (defeats rekey-window replay)
	//   (c) (address, peer, nonce) tuple not seen before (defeats
	//       intra-freshness-window replay)
	//
	// All three are set via the Set* methods; defaults are zero so existing
	// deployments upgrade transparently (no behavioral change until the
	// node opts in via setters, mirroring the BlockValidator.SetSyncProposerVerification
	// opt-in path used by R38-P1-08 deep fix).
	activeValidatorIdentityVerifier ActiveValidatorIdentityVerifier
	statusFreshnessWindowSec        uint64
	sessionNonceTracker             *SessionNonceTracker

	// Context and cancellation
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.RWMutex
	closed bool

	// R32-P4-4b FIX: Optional mTLS layer wrapping TCP before the custom
	// post-quantum encrypted handshake. When configured, all P2P connections
	// are first wrapped in TLS 1.3 (providing standard certificate-based
	// authentication), then the Kyber768+Dilithium3+AES-GCM handshake runs
	// inside the TLS tunnel for post-quantum forward secrecy.
	// When nil (development mode), the custom encrypted transport runs
	// directly over TCP as before.
	certManager *NodeCertificateManager

	// P2P-R13-CRIT-001 (2026-07-21, R12-H01 regression fix): Background
	// goroutine for periodic mTLS certificate rotation. Without this,
	// certManager.CheckAndRotateCertificate is never called in production,
	// and the leaf cert expires after 24h — taking the node offline.
	// Initialized in Start() when certManager != nil; closed in Stop()
	// via certRotationCancel.
	certRotationCancel context.CancelFunc
	certRotationDone   chan struct{}

	// P2P-R13-CRIT-003 (2026-07-21, R12-H02 regression fix): Background
	// goroutine for periodic CRL snapshot broadcast via GossipSub. Without
	// this, revocations performed locally never propagate to other peers,
	// leaving them blind to revoked certs. Initialized in Start() when
	// certManager != nil AND gossipSubRouter != nil; closed in Stop()
	// via crlBroadcastCancel.
	crlBroadcastCancel context.CancelFunc
	crlBroadcastDone   chan struct{}
}

// Peer represents a connected peer
type Peer struct {
	ID        PeerID
	Addr      string
	Conn      net.Conn
	Connected bool
	Latency   time.Duration
	Version   string
	Direction Direction

	agreedProtocols []ProtocolSpec
	mu              sync.Mutex

	sendCh chan []byte
	ctx    context.Context
	cancel context.CancelFunc

	// P2P-R28-H02 FIX (2026-07-25): closeSendCh guards sendCh closure to
	// prevent double-close panics. readLoop and disconnectPeer may both
	// run cleanup concurrently — without sync.Once, a double close on
	// sendCh would panic and crash the node.
	closeOnce sync.Once
	// P2P-H01 FIX (R29, audit 2026-07-25): disconnectCleanupOnce ensures
	// sybilResistance.OnDisconnect and peerScorer.OnDisconnect run exactly
	// once per peer, regardless of whether readLoop or writeLoop runs the
	// cleanup first. Without this, writeLoop had NO OnDisconnect calls
	// (IP count leak → permanent rejection of that IP), and adding them
	// naively would double-decrement / double-penalize when readLoop also
	// runs its defer.
	disconnectCleanupOnce sync.Once
}

// disconnectCleanup runs sybil-resistance and peer-scorer disconnect hooks
// exactly once per peer. Safe to call from both readLoop and writeLoop
// defers. P2P-H01 FIX (R29).
//
// FIX (2026-07-27): also release the discovery layer's ReputationManager IP/subnet counts
// via discoverTable.ReleaseIPConnection. The earlier fix already released on the removeNode
// path, but on P2P-layer peer disconnect the discovery table entry is not necessarily removed,
// so IP counts only grow (with decayIPCounts as the sole backstop; see
// sybil_protection.go:283-286), eventually tripping MaxConnectionsPerIP and locking out honest peers.
// Here we release immediately on active-connection teardown, forming a double release with SybilResistance.OnDisconnect.
func (p *Peer) disconnectCleanup(h *Host) {
	p.disconnectCleanupOnce.Do(func() {
		h.sybilResistance.OnDisconnect(p.ID, p.Addr)
		h.peerScorer.OnDisconnect(p.ID, false)
		// R37-P3-18 FIX (2026-07-31): drop validator→PeerID mappings that
		// reference this peer so directed TSS routing never targets a
		// disconnected peer. Runs inside disconnectCleanupOnce, so it
		// executes exactly once per peer on every disconnect path
		// (readLoop/writeLoop defer, Disconnect, disconnectPeer).
		h.removeValidatorMappingsForPeer(p.ID)
		// nil check defends tests and partially-initialized cases (discoverTable is
		// nil before SetDiscoverTable). ReleaseIPConnection also nil-checks internally.
		if h.discoverTable != nil {
			h.discoverTable.ReleaseIPConnection(p.Addr)
		}
	})
}

// closeSendCh closes the peer's send channel exactly once.
// P2P-R28-H02: This is safe to call from multiple goroutines (readLoop,
// disconnectPeer, disconnectAllPeersForCertRotation) without risking a
// "close of closed channel" panic.
func (p *Peer) closeSendCh() {
	p.closeOnce.Do(func() {
		close(p.sendCh)
	})
}

// Direction represents the connection direction
type Direction int

const (
	DirInbound Direction = iota
	DirOutbound
)

func (d Direction) String() string {
	switch d {
	case DirInbound:
		return "inbound"
	case DirOutbound:
		return "outbound"
	default:
		return "unknown"
	}
}

// loadOrGenerateNodeKey loads a Dilithium3 key pair from a seed file.
// If the file exists, it reads the 32-byte hex seed and generates a deterministic key pair.
// If the file does not exist, it generates a new random seed, saves it, and returns a key pair.
func loadOrGenerateNodeKey(path string) (*crypto.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		hexStr := strings.TrimSpace(string(data))
		seed, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("invalid nodekey hex in %s: %w", path, err)
		}
		if len(seed) != 32 {
			return nil, fmt.Errorf("nodekey seed must be 32 bytes, got %d in %s", len(seed), path)
		}
		kp, err := crypto.GenerateKeyPairFromSeed(seed)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair from seed: %w", err)
		}
		logging.Global().Info("Loaded persistent node identity from file", map[string]any{
			"path": path,
		})
		return kp, nil
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create nodekey directory %s: %w", dir, err)
	}
	hexSeed := hex.EncodeToString(seed)
	if err := os.WriteFile(path, []byte(hexSeed+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("failed to write nodekey to %s: %w", path, err)
	}
	kp, err := crypto.GenerateKeyPairFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair from new seed: %w", err)
	}
	logging.Global().Info("Generated and saved new node identity", map[string]any{
		"path": path,
	})
	return kp, nil
}

// NewHost creates a new P2P host
func NewHost(cfg *Config) (*Host, error) {
	if cfg == nil {
		var err error
		cfg, err = DefaultConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
	}

	// FIX: Hard validation — reject 0.0.0.0 listen address when
	// ExternalIP is not set. Binding to 0.0.0.0 without a configured external
	// IP means discovery advertises an unreachable address, and exposes the
	// node to direct internet attacks. Operators who genuinely need 0.0.0.0
	// must also set ExternalIP.
	// FIX: Also reject ":port" (empty host), which is equivalent to
	// 0.0.0.0:port — Go's net package binds to all interfaces when host is
	// empty. Previously this bypassed the 0.0.0.0 check because
	// net.ParseIP("") returns nil.
	if cfg.ExternalIP == "" {
		if host, _, err := net.SplitHostPort(cfg.ListenAddr); err == nil {
			// Empty host (":9000") binds to all interfaces, same as 0.0.0.0.
			if host == "" {
				return nil, fmt.Errorf(
					"ListenAddr %q has no host (equivalent to 0.0.0.0) but ExternalIP is not set; "+
						"either set ListenAddr to a specific IP (e.g. 127.0.0.1:9000) or set ExternalIP "+
						"to the node's publicly reachable IP address", cfg.ListenAddr)
			}
			if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
				return nil, fmt.Errorf(
					"ListenAddr %q binds to all interfaces (0.0.0.0/::) but ExternalIP is not set; "+
						"either set ListenAddr to a specific IP (e.g. 127.0.0.1:9000) or set ExternalIP "+
						"to the node's publicly reachable IP address", cfg.ListenAddr)
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	var nodeKeyPair *crypto.KeyPair
	var nodeKeyErr error
	if cfg.NodeKeyPath != "" {
		nodeKeyPair, nodeKeyErr = loadOrGenerateNodeKey(cfg.NodeKeyPath)
	} else {
		nodeKeyPair, nodeKeyErr = crypto.GenerateKeyPair()
	}
	if nodeKeyErr != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize node key: %w", nodeKeyErr)
	}
	// audit-fix H-P2P-1: Derive PeerID from SHA3-256 hash of the FULL public key.
	// Previously used only the first 32 bytes of the raw public key, which:
	// (1) Does not guarantee uniform distribution (Dilithium3 keys have structure)
	// (2) Allows potential identity collision — an attacker could craft a different
	//     key pair whose first 32 bytes match a target peer's ID
	// Using SHA3-256 over the complete public key ensures:
	// - Uniform distribution of PeerIDs (collision resistance ~2^128)
	// - Binding of PeerID to the entire key material (any change → different ID)
	pubBytes := nodeKeyPair.Public.Bytes()
	pubHasher := sha3.New256()
	pubHasher.Write(pubBytes)
	peerID := PeerID(hex.EncodeToString(pubHasher.Sum(nil)))
	cfg.NodeID = peerID

	// audit-fix LEGACY-1: Compute PoW nonce from our enode.ID at Host creation time.
	// This ensures RLPx connections can be configured with a valid PoW nonce
	// via SetPoWNonce before InitiatorHandshake/ResponderHandshake.
	// Without this, c.powNonce defaults to 0, causing remote PoW verification to fail.
	var ourNodeID enode.ID
	copy(ourNodeID[:], pubHasher.Sum(nil))
	// R99-POW-RECOMPUTE: tell the PoW cache where it may write. NodeDBPath is
	// derived from the node's DataDir (node/config.go:986
	// filepath.Join(c.DataDir, "nodes")), so its parent is that DataDir — a
	// directory the service demonstrably owns, unlike the os.UserConfigDir()
	// fallback that ProtectHome=true blocks.
	if cfg.NodeDBPath != "" {
		SetPoWCacheDir(filepath.Dir(cfg.NodeDBPath))
	}
	powNonceBytes, err := generatePoWNonce(ourNodeID[:], cfg.DevMode)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to compute PoW nonce: %w", err)
	}
	powNonce := binary.LittleEndian.Uint64(powNonceBytes)
	logging.Global().Debug("NewHost: PoW nonce computed", map[string]any{
		"powNonce": powNonce,
	})

	h := &Host{
		config:       cfg,
		id:           peerID,
		nodeKeyPair:  nodeKeyPair,
		powNonce:     powNonce,
		peers:        make(map[PeerID]*Peer),
		handshakeSem: make(chan struct{}, 32),                             // AUDIT (2026) HIGH-15: cap concurrent inbound handshakes
		perIPLimiter: newPerIPHandshakeLimiter(defaultMaxPerIPHandshakes), // R4-P2P-02: per-IP admission before handshake
		blockCh:      make(chan []byte, 2000),
		blockReqCh:   make(chan PeerMessage, 100),
		txCh:         make(chan []byte, 4096),
		txBatchCh:    make(chan []byte, 4096),
		voteCh:       make(chan []byte, 100),
		statusCh:     make(chan PeerMessage, 1000),
		expertCh:     make(chan []byte, 100),
		snapCh:       make(chan []byte, 100),
		snapReqCh:    make(chan PeerMessage, 100),
		// ETHEREUM-PARITY SYNC (2026-08-13)
		syncRespCh:           make(chan PeerMessage, 256),
		checkpointCh:         make(chan []byte, 50),
		tssCh:                make(chan PeerMessage, 100),
		qtdSealCh:            make(chan PeerMessage, 100),
		dasReqCh:             make(chan PeerMessage, 100),
		dasPending:           make(map[uint64]chan PeerMessage),
		shardBlockCh:         make(chan []byte, 200),
		shardBlockReqCh:      make(chan PeerMessage, 50),
		shardBlockRespCh:     make(chan PeerMessage, 50),
		shardAttestationCh:   make(chan []byte, 200),
		crossShardMsgCh:      make(chan []byte, 200),
		crossShardReceiptCh:  make(chan []byte, 200),
		validatorPeerMap:     make(map[types.Address]PeerID),
		rateLimiter:          NewRateLimiter(500, time.Second),
		perIPRateLimiter:     NewRateLimiter(defaultMaxPerIPMessages, time.Second),             // P2P-R12-M02
		perIPConnRateLimiter: NewRateLimiter(defaultMaxPerIPConnAttemptsPerSec, time.Second),   // R32-P3-03: pre-handshake connection attempt rate limit
		txRateLimiter:        NewRateLimiter(defaultMaxPerPeerTxsPerSec, time.Second),          // P2-TXPOOL-RATELIMIT
		outRateLimiter:       NewRateLimiter(defaultMaxPerPeerOutboundMsgsPerSec, time.Second), // P2-WRITELOOP-RATELIMIT
		blacklist:            NewBlacklist(),
		penaltyManager:       DefaultPenaltyConfig(),
		messageValidator:     NewMessageValidator(),
		sybilResistance:      NewSybilResistance(),
		peerScorer:           NewPeerScorer(),
		protocolRegistry:     NewProtocolRegistry(),
		ctx:                  ctx,
		cancel:               cancel,
	}

	h.broadcaster = NewBroadcaster(h)

	// Phase 1: Wire up penalty manager with blacklist and start decay loop
	h.penaltyManager.SetBlacklist(h.blacklist)
	h.penaltyManager.Start()

	// P2P-R11-M02 (2026-07-20) FIX: opt the Blacklist into persistence so
	// permanent and long-TTL bans survive node restarts. The path honors the
	// QAU_DATA_DIR convention used by the PoW cache. Failures are non-fatal —
	// the blacklist still works in-memory, it just does not survive restart.
	if dataDir := os.Getenv("QAU_DATA_DIR"); dataDir != "" {
		blPath := filepath.Join(dataDir, "blacklist.json")
		if err := h.blacklist.SetPersistencePath(blPath); err != nil {
			//nolint:gosec // G706: path comes from QAU_DATA_DIR env, err is an error value; non-injectable.
			log.Printf("[WARN] p2p: failed to load blacklist persistence from %s: %v (starting with empty blacklist)",
				blPath, err)
		}
	}

	// Build trusted peers set for fast lookup
	h.trustedPeers = make(map[PeerID]bool, len(cfg.TrustedPeers))
	for _, p := range cfg.TrustedPeers {
		h.trustedPeers[PeerID(p)] = true
	}

	// R15-CRIT-001: initialize per-peer CRL rate limiter.
	h.crlRateLimiter = make(map[PeerID]time.Time)

	// Initialize Kademlia-like routing table for node discovery
	if cfg.EnableDHT {
		discoverCfg := &discover.Config{
			SelfID:   ourNodeID,
			MaxNodes: 256 * 16,
		}
		discoverTable, err := discover.NewTable(discoverCfg)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create discovery table: %w", err)
		}
		h.discoverTable = discoverTable

		// Load persisted nodes from disk
		if cfg.NodeDBPath != "" {
			if err := discoverTable.LoadNodes(cfg.NodeDBPath); err != nil {
				logging.Global().Debug("No persisted nodes found (first run)", map[string]any{
					"path":  cfg.NodeDBPath,
					"error": err.Error(),
				})
			} else {
				logging.Global().Info("Loaded persisted nodes", map[string]any{
					"path": cfg.NodeDBPath,
				})
			}
		}

		discoverTable.SetNodeAddedCallback(func(n *enode.Node) {
			logging.Global().Debug("Discovery: node added to table", map[string]any{
				"nodeID": n.ID().Hex(),
				"ip":     n.IP().String(),
			})
		})
		discoverTable.SetNodeRemovedCallback(func(n *enode.Node) {
			logging.Global().Debug("Discovery: node removed from table", map[string]any{
				"nodeID": n.ID().Hex(),
			})
		})

		// Initialize UDP discovery transport
		udpAddr := cfg.ListenAddr
		if host, portStr, err := net.SplitHostPort(cfg.ListenAddr); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil {
				udpAddr = net.JoinHostPort(host, strconv.Itoa(port))
			}
		}
		// FIX: Use ExternalIP for UDP discovery localNode instead of
		// hardcoded 0.0.0.0. Advertising 0.0.0.0 makes the node unreachable
		// by other peers in the discovery network. If ExternalIP is not set,
		// fall back to the ListenAddr's host (which may be 0.0.0.0 if the
		// operator explicitly chose to bind to all interfaces).
		discoveryIP := net.ParseIP("0.0.0.0")
		if cfg.ExternalIP != "" {
			if parsed := net.ParseIP(cfg.ExternalIP); parsed != nil {
				discoveryIP = parsed
			}
		} else if host, _, err := net.SplitHostPort(cfg.ListenAddr); err == nil {
			if parsed := net.ParseIP(host); parsed != nil && !parsed.IsUnspecified() {
				discoveryIP = parsed
			}
		}
		if discoveryIP.IsUnspecified() {
			// FIX: Do not advertise 0.0.0.0 in UDP discovery — an
			// unreachable node pollutes the discovery table with bad entries
			// for all peers. Skip UDP discovery entirely; the node can still
			// participate via direct peer connections (StaticNodes).
			logging.Global().Warn("P2P discovery skipped — ExternalIP not set and ListenAddr is 0.0.0.0; "+
				"set ExternalIP in config to enable discovery and make the node reachable",
				map[string]any{"listenAddr": cfg.ListenAddr})
		} else {
			localNode := enode.NewNode(ourNodeID, discoveryIP, 0, 0)
			udpTransport, err := discover.NewUDPTransport(ctx, localNode, discoverTable, udpAddr)
			if err != nil {
				logging.Global().Warn("Failed to start UDP discovery transport", map[string]any{
					"error": err.Error(),
				})
			} else {
				h.udpTransport = udpTransport
				logging.Global().Info("UDP discovery transport started", map[string]any{
					"addr": udpAddr,
				})
			}
		}
	}

	// Register sub-protocols
	h.registerProtocols()

	// Phase 2: Initialize GossipSub router for topic-based message propagation
	h.gossipSubRouter = gossipsub.NewGossipSub(nil, h)

	return h, nil
}

// SetCertificateManager configures optional mTLS for P2P connections (R32-P4-4b).
// When set, all inbound and outbound TCP connections are wrapped in TLS 1.3
// before the custom post-quantum encrypted handshake runs, providing standard
// certificate-based peer authentication in addition to the PQ handshake.
func (h *Host) SetCertificateManager(ncm *NodeCertificateManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.certManager = ncm
}

// Start starts the P2P host.
// SECURITY FIX Q-B-003: All P2P traffic is now encrypted with AES-256-GCM
// using per-connection ephemeral keys derived from a Dilithium3-signed key exchange.
// This replaces the previous raw TCP transport which exposed all handshake and
// message traffic to passive eavesdropping and active MITM.
func (h *Host) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return fmt.Errorf("host is closed")
	}

	// SECURITY FIX Q-B-003: Use TLS 1.3-like encrypted listener instead of raw TCP.
	// The transport encryptor wraps net.Conn with AES-256-GCM + ephemeral keys.
	plainListener, err := net.Listen("tcp", h.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	// R32-P4-4b FIX: Wrap listener in TLS 1.3 when a certificate manager
	// is configured. This provides standard X.509 certificate-based peer
	// authentication before the custom post-quantum handshake runs.
	var baseListener net.Listener = plainListener
	if h.certManager != nil {
		tlsConfig, tlsErr := h.certManager.GetTLSConfig()
		if tlsErr != nil {
			plainListener.Close()
			return fmt.Errorf("failed to build TLS config: %w", tlsErr)
		}
		baseListener = tls.NewListener(plainListener, tlsConfig)
	}
	h.listener = newEncryptedListener(baseListener, h.nodeKeyPair, h.config.DevMode)

	// Accept incoming connections
	go h.acceptLoop()

	// Connect to bootstrap peers
	go h.connectBootstrapPeers()

	// P2P-R28-H01 FIX (2026-07-25): Start outbound maintenance loop to
	// actively ensure MinOutboundConns / MinOutboundRatio are satisfied.
	// Without this, the MinOutboundConns / MinOutboundRatio config values
	// in ConnPoolConfig were dead code — defined but never enforced. An
	// attacker could fill all peer slots with inbound connections (eclipse
	// attack setup), preventing the node from reaching honest peers.
	// This loop periodically checks the outbound ratio and dials random
	// discovered nodes if below the minimum, mirroring geth's
	// dialScheduling logic.
	go h.outboundMaintenanceLoop()

	// SECURITY FIX Q-B-003b: Start a background goroutine to rotate
	// ephemeral encryption keys periodically (every 24 hours) to limit
	// the impact of a compromised session key.
	go h.encryptionKeyRotationLoop()

	// Start node discovery loops
	if h.discoverTable != nil {
		go h.discoveryRefreshLoop()
		go h.peerPingLoop()
	}

	// Start peer scorer cleanup loop to prevent unbounded map growth
	go h.peerScorerCleanupLoop()

	// TPS FIX: Start transaction batch broadcast loop.
	// Collects incoming txs and sends them in batches of up to 100 txs per
	// P2P message, reducing message count by ~100x during high-throughput bursts.
	go h.txBatchLoop()

	// TPS OPTIMIZATION: Initialize compact tx manager for hash-based propagation.
	// Reduces P2P bandwidth by ~99%: broadcasts 32-byte hashes instead of 5.5KB txs.
	h.compactTx = NewCompactTxManager(h)
	go h.compactTxCleanupLoop()

	// P3-10/P3-11 FIX: periodically purge expired P2P rate-limiter windows and
	// stale message-dedup entries so memory stays bounded under low traffic.
	h.messageValidator.StartCleanup(h.ctx)

	// TPS OPTIMIZATION: Initialize compact block manager for header+hash propagation.
	h.compactBlock = NewCompactBlockManager(h, h.compactTx)

	// Phase 2: Start GossipSub router
	if h.gossipSubRouter != nil {
		if err := h.gossipSubRouter.Start(); err != nil {
			logging.Global().Warn("Failed to start GossipSub router", map[string]any{
				"error": err.Error(),
			})
		} else {
			logging.Global().Info("GossipSub router started")
		}
	}

	// P2P-R13-CRIT-001 (2026-07-21, R12-H01 regression fix): Start the
	// certificate rotation goroutine. The R12 implementation wrote
	// CheckAndRotateCertificate() but never called it from production code
	// — only from tests. As a result, the leaf cert expired after 24h and
	// all P2P connections failed. This goroutine performs:
	//   1. An initial check at startup (rotates if cert is already close
	//      to expiry — useful after a long downtime).
	//   2. A periodic check every 1 hour. The cert has 24h validity, so
	//      hourly checks give 24 chances to rotate before expiry — more
	//      than enough margin even if some checks are missed due to
	//      transient errors.
	//   3. Rotation threshold = 2h. Cert is rotated when <2h validity
	//      remains, giving a 2h buffer for any rotation failure to be
	//      detected by an operator before the cert actually expires.
	if h.certManager != nil {
		const rotationThreshold = 2 * time.Hour
		const checkInterval = 1 * time.Hour
		// P2P-R14-CRIT-002 (2026-07-21): register a rotation callback
		// that proactively disconnects all connected peers after a
		// successful cert rotation. Without this, peers still hold the
		// OLD pinned public key and reject the new cert on the next
		// connection attempt — the rotated node gets isolated from the
		// network until every peer's pinning is manually cleared.
		// Disconnecting forces peers to reconnect, which triggers the
		// normal handshake and re-pinning with the new cert.
		h.certManager.RegisterRotationCallback(h.disconnectAllPeersForCertRotation)
		if err := h.certManager.CheckAndRotateCertificate(rotationThreshold); err != nil {
			logging.Global().Warn("Initial certificate rotation check failed",
				map[string]any{"error": err.Error()})
		}
		rotCtx, rotCancel := context.WithCancel(h.ctx)
		h.certRotationCancel = rotCancel
		h.certRotationDone = make(chan struct{})
		go h.certRotationLoop(rotCtx, rotationThreshold, checkInterval, h.certRotationDone)

		// P2P-R13-CRIT-003 (2026-07-21, R12-H02 regression fix): Subscribe
		// to the CRL gossipsub topic and start the periodic CRL broadcast
		// goroutine. Without this wiring, GetCRLSnapshot/MergeCRLSnapshot
		// were never called from production code — revocations performed on
		// Node A never propagated to Node B, leaving the network blind to
		// revoked certs until every operator manually called RevokeCertificate.
		// We join the topic after GossipSub has started (above) so the
		// subscription is registered with a live router.
		if h.gossipSubRouter != nil {
			if _, err := h.gossipSubRouter.JoinTopic(gossipsub.TopicCRL, h.handleCRLMessage); err != nil {
				logging.Global().Warn("Failed to join CRL topic",
					map[string]any{"error": err.Error()})
			} else {
				crlCtx, crlCancel := context.WithCancel(h.ctx)
				h.crlBroadcastCancel = crlCancel
				h.crlBroadcastDone = make(chan struct{})
				go h.crlBroadcastLoop(crlCtx, h.crlBroadcastDone)
			}
		}
	}

	return nil
}

// certRotationLoop periodically checks the leaf certificate and rotates
// it when less than rotationThreshold validity remains.
//
// P2P-R13-CRIT-001 (2026-07-21, R12-H01 regression fix).
func (h *Host) certRotationLoop(ctx context.Context, rotationThreshold, checkInterval time.Duration, done chan<- struct{}) {
	// P2P-R15-MED-5: Panic recovery so a cert-manager bug cannot crash the node.
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("certRotationLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	defer close(done)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if h.certManager == nil {
				return
			}
			if err := h.certManager.CheckAndRotateCertificate(rotationThreshold); err != nil {
				logging.Global().Warn("Certificate rotation check failed",
					map[string]any{
						"error":     err.Error(),
						"remaining": h.certManager.CertificateRemainingValidity().String(),
					})
			}
		}
	}
}

// crlBroadcastLoop periodically broadcasts the local CRL snapshot via
// the GossipSub CRL topic so other peers can merge it into their local
// CRL. The broadcast interval is 5 minutes — frequent enough that a
// revocation propagates within minutes, but not so frequent as to
// burden the network with redundant traffic.
//
// P2P-R13-CRIT-003 (2026-07-21, R12-H02 regression fix).
func (h *Host) crlBroadcastLoop(ctx context.Context, done chan<- struct{}) {
	// P2P-R15-MED-5: Panic recovery so a CRL broadcast bug cannot crash the node.
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("crlBroadcastLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	defer close(done)
	const broadcastInterval = 5 * time.Minute
	ticker := time.NewTicker(broadcastInterval)
	defer ticker.Stop()
	// Broadcast once at startup so a fresh revocation propagates
	// immediately after the node joins the network.
	h.broadcastCRLSnapshot()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.broadcastCRLSnapshot()
		}
	}
}

// broadcastCRLSnapshot marshals the local CRL snapshot and publishes it
// to the GossipSub CRL topic. Failures are logged but non-fatal — the
// next ticker will retry. Best-effort: we don't track delivery
// acknowledgments; the monotonic merge semantics of MergeCRLSnapshot
// make duplicate broadcasts idempotent (a peer receiving the same
// snapshot twice will see 0 newly added on the second merge).
//
// P2P-R13-CRIT-003 (2026-07-21, R12-H02 regression fix).
// R15-CRIT-001 (2026-07-22): sign the snapshot with the node's leaf
// certificate private key before publishing so receivers can authenticate
// the issuer.
func (h *Host) broadcastCRLSnapshot() {
	if h.certManager == nil || h.gossipSubRouter == nil {
		return
	}
	snap := h.certManager.GetCRLSnapshot()
	if snap == nil {
		return
	}
	// Quick path: don't broadcast an empty CRL (no revocations). This
	// avoids flooding the network with empty snapshots at startup when
	// no certs have been revoked.
	if len(snap.RevokedSNs) == 0 {
		return
	}
	// R15-CRIT-001: sign before publishing. Best-effort: if signing
	// fails (e.g., no private key in a read-only test manager), log a
	// warning and publish unsigned so the snapshot still propagates.
	// Receivers in production will require either a valid signature OR
	// trusted-peer authorization (see handleCRLMessage).
	nodeID := PeerID("")
	if h.config != nil {
		nodeID = h.config.NodeID
	}
	if nodeID != "" {
		if err := h.certManager.SignCRLSnapshot(snap, nodeID); err != nil {
			logging.Global().Warn("Failed to sign CRL snapshot; publishing unsigned",
				map[string]any{"error": err.Error()})
		}
	}
	data, err := json.Marshal(snap)
	if err != nil {
		logging.Global().Warn("Failed to marshal CRL snapshot",
			map[string]any{"error": err.Error()})
		return
	}
	if err := h.gossipSubRouter.Publish(gossipsub.TopicCRL, data); err != nil {
		logging.Global().Warn("Failed to publish CRL snapshot",
			map[string]any{"error": err.Error()})
	}
}

// crlRateLimitInterval is the minimum interval between accepted CRL
// messages from a single peer. R15-CRIT-001.
//
// P2P-R15-H05 (2026-07-22): This rate limit ALSO resolves the CRL
// write-lock DoS described in H05. Without it, a malicious peer could
// send CRL snapshots at high frequency, each acquiring the CRL write
// lock inside MergeCRLSnapshot, starving new-connection handshakes
// that need the CRL for cert-status checks. With this limit, at most
// 1 message per 5 minutes per peer reaches MergeCRLSnapshot — the
// rate-limit check itself runs under a separate mutex
// (crlRateLimiterMu) and does NOT touch the CRL lock, so rejected
// messages never contend with handshakes.
const crlRateLimitInterval = 5 * time.Minute

// crlRateLimitMaxEntries bounds the crlRateLimiter map size to prevent
// unbounded memory growth from sybil peers. R15-CRIT-001.
const crlRateLimitMaxEntries = 10000

// handleCRLMessage is the GossipSub handler for incoming CRL snapshot
// messages. It unmarshals the snapshot, enforces per-peer rate limiting,
// authenticates the issuer (signature or trusted-peer authorization),
// then merges the snapshot into the local CRL.
//
// Authentication policy (R15-CRIT-001, 2026-07-22):
//   - Per-peer rate limit: at most 1 message / 5 minutes / peer.
//   - IssuerPeerID in the snapshot MUST match msg.From.
//   - If the local certManager has the issuer's trusted certificate, the
//     snapshot signature MUST verify against it.
//   - If the issuer's cert is not known locally, the peer MUST be in the
//     host's trustedPeers whitelist. Otherwise the snapshot is dropped.
//   - When h.skipCRLAuth is true (test-only, defaults false), signature and
//     trusted-peer authorization are skipped (rate limit still enforced)
//     to preserve existing test behavior. P2P-R16-M06 (2026-07-23): replaced
//     testing.Testing() with this explicit flag so a test binary accidentally
//     deployed to production cannot disable CRL auth.
//
// P2P-R13-CRIT-003 (2026-07-21, R12-H02 regression fix).
func (h *Host) handleCRLMessage(msg *gossipsub.Message) {
	if h.certManager == nil {
		return
	}
	if len(msg.Data) == 0 {
		return
	}
	// Defense-in-depth: cap the snapshot size to prevent OOM from a
	// malicious peer sending a huge snapshot. A CRL with 1M revoked
	// serials would be ~50MB (each serial is ~20 chars + timestamp);
	// 1MB is more than enough for any realistic CRL.
	const maxCRLSnapshotSize = 1 << 20 // 1MB
	if len(msg.Data) > maxCRLSnapshotSize {
		logging.Global().Warn("Dropping oversized CRL snapshot",
			map[string]any{"size": len(msg.Data), "max": maxCRLSnapshotSize})
		return
	}

	// R15-CRIT-001: per-peer rate limit.
	if !h.crlRateLimitAllow(PeerID(msg.From)) {
		logging.Global().Warn("Dropping CRL snapshot: per-peer rate limit exceeded",
			map[string]any{"peer": msg.From, "interval": crlRateLimitInterval.String()})
		return
	}

	var snap CRLSnapshot
	if err := json.Unmarshal(msg.Data, &snap); err != nil {
		logging.Global().Warn("Failed to unmarshal CRL snapshot",
			map[string]any{"error": err.Error()})
		return
	}

	// R15-CRIT-001: issuer authorization.
	if !h.crlAuthorizeIssuer(PeerID(msg.From), &snap) {
		logging.Global().Warn("Dropping CRL snapshot: issuer authorization failed",
			map[string]any{
				"peer":          msg.From,
				"issuer_peer":   snap.IssuerPeerID,
				"has_signature": len(snap.Signature) > 0,
			})
		return
	}

	added, err := h.certManager.MergeCRLSnapshot(&snap)
	if err != nil {
		logging.Global().Warn("Failed to merge CRL snapshot",
			map[string]any{"error": err.Error()})
		return
	}
	if added > 0 {
		logging.Global().Info("Merged CRL snapshot from peer",
			map[string]any{
				"new_revocations": added,
				"peer":            msg.From,
			})
	}
}

// crlRateLimitAllow returns true if the peer is allowed to send a CRL
// message now (at most 1 per crlRateLimitInterval). Updates the last-seen
// timestamp on accept. R15-CRIT-001.
func (h *Host) crlRateLimitAllow(peer PeerID) bool {
	now := time.Now()
	h.crlRateLimiterMu.Lock()
	defer h.crlRateLimiterMu.Unlock()
	// Defensive: tests construct Host without going through NewHost, so
	// the map may be nil. Lazy-initialize on first use.
	if h.crlRateLimiter == nil {
		h.crlRateLimiter = make(map[PeerID]time.Time)
	}
	if last, ok := h.crlRateLimiter[peer]; ok && now.Sub(last) < crlRateLimitInterval {
		return false
	}
	// Bound the map size: if at capacity, evict oldest entries.
	if len(h.crlRateLimiter) >= crlRateLimitMaxEntries {
		// Lazy eviction: drop ~10% of oldest entries to amortize cost.
		threshold := now.Add(-crlRateLimitInterval)
		for p, t := range h.crlRateLimiter {
			if t.Before(threshold) {
				delete(h.crlRateLimiter, p)
			}
		}
		// If still at capacity (many active peers), drop the new entry
		// rather than allowing unbounded growth.
		if len(h.crlRateLimiter) >= crlRateLimitMaxEntries {
			return false
		}
	}
	h.crlRateLimiter[peer] = now
	return true
}

// crlAuthorizeIssuer enforces the R15-CRIT-001 authentication policy.
// Returns true if the snapshot is authenticated; false if it should be
// dropped.
func (h *Host) crlAuthorizeIssuer(from PeerID, snap *CRLSnapshot) bool {
	// P2P-R16-M06 (2026-07-23) FIX: Replaced testing.Testing() with an
	// explicit h.skipCRLAuth flag. testing.Testing() returned true for ANY
	// test binary, meaning a test binary accidentally deployed to production
	// would have CRL auth fully disabled. The flag defaults to false (secure)
	// and is only set to true by tests in the same package via struct literal.
	if h.skipCRLAuth {
		return true
	}

	// IssuerPeerID must match the GossipSub carrier's From field when
	// present. A mismatch means the snapshot was forwarded by a peer
	// other than the issuer — drop it (legitimate forwarding would
	// preserve the original issuer, but we want direct-from-issuer only
	// for CRL distribution).
	if snap.IssuerPeerID != "" && snap.IssuerPeerID != string(from) {
		return false
	}

	// Path 1: signature verification against a locally known issuer cert.
	if h.certManager.HasIssuerCertificate(from) {
		// Signature is REQUIRED when the issuer is a known CA peer.
		if !h.certManager.VerifyCRLSnapshotSignature(snap) {
			return false
		}
		return true
	}

	// Path 2: trusted-peer whitelist authorization. We don't have the
	// issuer's cert locally (Path 1 would have caught it), so we cannot
	// independently verify the signature. This is the common path for
	// non-CA peers that the operator has explicitly trusted via
	// config.TrustedPeers.
	//
	// P2P-R16-CRIT-001 (2026-07-22) FIX: Previously this block returned
	// true unconditionally whether or not a signature was present, and
	// never called VerifyCRLSnapshotSignature — contradicting the comment
	// which claimed opportunistic verification. A compromised trusted
	// peer (including bootstrap nodes) could inject arbitrary CRLs with
	// forged signatures that were never checked, enabling network
	// partition attacks.
	//
	// P2P-R16-H01 (2026-07-23) FIX: Removed the "no signature → accept"
	// path. ALL CRLs from trusted peers must now carry a valid signature.
	// Previously, a misconfigured operator adding a malicious peer to
	// TrustedPeers allowed that peer to send unsigned CRLs causing
	// network partition. Now:
	//   - No signature present: REJECT (signature is mandatory).
	//   - Signature present AND verifiable: accept (defense in depth).
	//   - Signature present but NOT verifiable: REJECT. Operators must
	//     add the issuer's cert via AddTrustedPeer BEFORE trusting its
	//     CRLs, so VerifyCRLSnapshotSignature can authenticate the
	//     signature.
	if h.IsTrustedPeer(from) {
		if len(snap.Signature) == 0 {
			// P2P-R16-H01: Signature is mandatory even for trusted peers.
			logging.Global().Warn("Rejecting CRL from trusted peer: missing signature",
				map[string]any{"peer": string(from)})
			return false
		}
		// Signature present — verify. If we can't verify (no local cert
		// for the issuer), reject: operators must add the issuer's cert
		// via AddTrustedPeer so the signature can be authenticated.
		return h.certManager.VerifyCRLSnapshotSignature(snap)
	}

	// No authorization path matched: drop.
	return false
}

// compactTxCleanupLoop periodically cleans up expired pending hash entries.
func (h *Host) compactTxCleanupLoop() {
	// P2P-R16-CRIT-002 (2026-07-22) FIX: Panic recovery so a CompactTx
	// cleanup bug cannot silently halt this loop (CompactTx cache leak).
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("compactTxCleanupLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			if h.compactTx != nil {
				h.compactTx.CleanupPending()
			}
		}
	}
}

// CompactTx returns the compact tx manager for hash-based tx propagation.
func (h *Host) CompactTx() *CompactTxManager {
	return h.compactTx
}

// CompactBlock returns the compact block manager for header+hash block propagation.
func (h *Host) CompactBlock() *CompactBlockManager {
	return h.compactBlock
}

// encryptionKeyRotationLoop periodically forces re-handshake on long-lived
// connections to limit exposure window of compromised session keys.
func (h *Host) encryptionKeyRotationLoop() {
	// P2P-R16-CRIT-002 (2026-07-22) FIX: Panic recovery so a key-rotation
	// bug cannot silently halt this loop (forward secrecy degraded).
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("encryptionKeyRotationLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.peersMu.RLock()
			peers := make([]*Peer, 0, len(h.peers))
			for _, peer := range h.peers {
				if peer.Connected {
					peers = append(peers, peer)
				}
			}
			h.peersMu.RUnlock()
			for _, peer := range peers {
				if encConn, ok := peer.Conn.(*encryptedConn); ok {
					if err := encConn.RotateKeys(); err != nil {
						logging.Global().Debug("Key rotation failed, connection will reconnect", map[string]any{
							"peer":  string(peer.ID),
							"error": err.Error(),
						})
					} else {
						logging.Global().Debug("Encryption key rotated successfully", map[string]any{
							"peer": string(peer.ID),
						})
					}
				}
			}
		}
	}
}

// peerScorerCleanupLoop periodically removes stale peer entries from the scorer
// to prevent unbounded memory growth from long-lived connections.
//
// R39-P1-06 (2026-08-02) FIX: this loop ALSO enforces PeerScorer.IsBanned
// decisions — previously IsBanned was computed (and unit-tested) but never
// consumed by the production path, so a peer whose score had crossed the
// ban threshold would remain connected indefinitely. The audit's
// recommendation is "call IsBanned inside Host.handlePeerScore or the gossipsub peerScoreInspector
// cycle and disconnect immediately"; here we wire the cheaper
// loop-driven sweep (30s) so the ban decision lands at most 30s after the
// score crosses the threshold. This is observability-grade hardening: the
// gossipsub mesh itself uses peer scores for mesh-maintenance decisions
// (PX/PRUNE), so banned peers are already mesh-dampened before this sweep
// drops their connection; but the sweep closes the "IsBanned is dead code"
// finding — without it, a banned peer's TCP connection stays open consuming
// resources and re-attempting misbehavior every reconnect.
//
// Lock-order note: enforcePeerBans acquires peersMu and then may call
// disconnectPeer which does NOT take peersMu itself (caller-must-hold
// per its docstring). No other mutex is acquired inside enforcePeerBans,
// so no lock-ordering hazard with the rest of the host.
func (h *Host) peerScorerCleanupLoop() {
	// P2P-R16-CRIT-002 (2026-07-22) FIX: Panic recovery so a scorer-cleanup
	// bug cannot silently halt this loop (PeerScorer memory leak).
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("peerScorerCleanupLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	// Cleanup every 5 minutes
	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()
	// R39-P1-06: ban enforcement runs on a faster, independent ticker so
	// the 5-minute stale-peers cleanup cadence doesn't bound the
	// responsiveness of ban enforcement.
	banTicker := time.NewTicker(30 * time.Second)
	defer banTicker.Stop()

	// Also cleanup on startup to remove any stale entries from previous runs
	h.cleanupPeerScorer()
	// And do an initial ban sweep so a peer that already had a bad score
	// (e.g., score recovered from disk, or score pushed below threshold by
	// a flood of RecordProtocolViolation calls during startup) is dropped
	// immediately rather than waiting up to 30s.
	h.enforcePeerBans()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-cleanupTicker.C:
			h.cleanupPeerScorer()
		case <-banTicker.C:
			// R39-P1-06: dump banned peers before the next cleanup cycle.
			h.enforcePeerBans()
		}
	}
}

func (h *Host) cleanupPeerScorer() {
	// Remove peers that haven't been seen in 1 hour or have very low scores
	removed := h.peerScorer.CleanupStalePeers(1*time.Hour, -50.0)
	if removed > 0 {
		logging.Global().Debug("Cleaned up stale peer entries", map[string]any{
			"removed": removed,
			"active":  h.peerScorer.PeerCount(),
		})
	}
}

// enforcePeerBans walks every connected peer, asks the PeerScorer if the
// peer is currently banned (score ≤ banThreshold), and if so disconnects
// the peer by calling disconnectPeer.
//
// R39-P1-06 (2026-08-02) FIX: closes the audit's "IsBanned is dead code"
// finding. Before this fix, PeerScorer.IsBanned was unit-tested to make
// the right decision but the Host never CONSUMED the decision — a peer
// whose score was pushed below the ban threshold by repeated
// RecordProtocolViolation calls would stay connected forever, continuing
// to spam invalid messages; the score would decay back above threshold
// and the peer would re-enter acceptable standing without ever being
// disconnected. The ban decision must produce an observable effect on the
// connection or the PeerScorer's score is purely cosmetic.
//
// The sweep runs from peerScorerCleanupLoop's 30s ticker; per-cycle cost
// is O(numConnectedPeers). For each banned peer we observe:
//   - record an IsBanned counter bump (for operator dashboards) at WARN
//     severity so an operator can correlate "peer count drops" events
//     against the recent sub-threshold score trajectory;
//   - call disconnectPeer (which itself calls peerScorer.OnDisconnect
//     with planned=false, marking the disconnect as forced-ban so the
//     score isn't double-counted).
//
// We snapshot the peer IDs under peersMu BEFORE calling disconnectPeer;
// disconnectPeer modifies h.peers, so we cannot iterate h.peers directly
// under the lock while disconnecting (Go's map iteration is unsafe under
// concurrent modification). We collect the banned peer IDs first, then
// call disconnectPeer per banned ID, freeing the lock between iterations
// so any shutdown/disconnect path that needs peersMu can make progress.
//
// Lock-ordering: peerScorer.IsBanned takes the PeerScorer's internal
// mutex; we do NOT acquire any PeerScorer mutex here, only peersMu.
// disconnectPeer expects the caller to hold peersMu and does NOT take it
// internally; we therefore re-acquire peersMu per disconnect iteration.
// This is a "snapshot-then-loop" pattern; the lock is released between
// iterations so a heavy ban batch cannot freeze peersMu for the full
// disconnect fan-out.
func (h *Host) enforcePeerBans() {
	if h.peerScorer == nil {
		// Defensive: nothing to enforce if scorer isn't wired (e.g.,
		// tests that construct a Host shell without a scorer).
		return
	}
	// Step 1: snapshot banned peer IDs (and their *Peer) so we can drop
	// the lock before disconnecting. We collect the *Peer pointer because
	// re-locking just to look up the peer by ID again is wasteful — and
	// the *Peer is safe to use outside the lock because disconnectPeer
	// only touches its cancel/Conn fields and removes it from h.peers
	// (the peer struct itself is stable enough for the disconnect path).
	type bannedPeer struct {
		id   PeerID
		peer *Peer
	}
	var toBan []bannedPeer

	h.peersMu.Lock()
	for id, p := range h.peers {
		// PeerScorer.IsBanned returns true iff score ≤ banThreshold; the
		// default banThreshold is ScoreBanThreshold=-50, so peers the
		// scorer has never heard of (GetScore=0) are NOT banned — only
		// peers whose score has been actively pushed below -50 by
		// RecordProtocolViolation / RecordTimeout / similar bad-peer
		// accounting trips this gate. That makes the sweep self-gating:
		// it doesn't disconnect "freshly connected peers I haven't
		// scored yet" (their score is 0, stay above -50), only peers the
		// scorer has ACTIVELY demoted.
		if h.peerScorer.IsBanned(id) {
			toBan = append(toBan, bannedPeer{id: id, peer: p})
		}
	}
	h.peersMu.Unlock()

	if len(toBan) == 0 {
		return
	}

	// Step 2: disconnect each banned peer. We re-acquire peersMu per
	// iteration because disconnectPeer expects the caller to hold the
	// lock; we release it between iterations so concurrent goroutines
	// needing peersMu (e.g., acceptLoop connecting new peers) can
	// proceed. This is a "resume the map" pattern — between iterations
	// the map may shrink (other disconnect paths) or grow (new peers
	// connecting), but each bannedPeer.peer is a stable pointer that
	// remains valid until its Conn.Close is called; calling cancel()
	// twice is a no-op (peer.cancel uses a context.WithCancel which is
	// idempotent).
	// R40-P2-01 (2026-08-03): wrap each iteration in an IIFE so the
	// `peersMu` release path goes through `defer` instead of a manual
	// `Unlock()` at the bottom. The previous manual-unlock form would
	// leave `peersMu` permanently held if `disconnectPeer` (or any code
	// path it reaches) panicked — freezing every subsequent acceptLoop,
	// outbound dial, and discovery op that needs `peersMu` until node
	// restart. The IIFE preserves the "release between iterations so
	// concurrent goroutines can proceed" intent documented above.
	for _, bp := range toBan {
		func() {
			h.peersMu.Lock()
			defer h.peersMu.Unlock()
			// Re-check that the peer is STILL in h.peers — between the
			// snapshot and now, a concurrent disconnect path (readLoop EOF,
			// cert-rotation sweep, manual disconnect) may have already
			// removed it. If so, skip; calling disconnectPeer on a peer
			// whose entry was already deleted would double-decay the
			// PeerScorer (disconnectPeer calls peerScorer.OnDisconnect),
			// which inflates the "bad peer churn" metric and can drive
			// legitimate peers below threshold in a thundering-herd storm.
			if _, stillConnected := h.peers[bp.id]; !stillConnected {
				return
			}
			// Avoid double-OnDisconnect: disconnectPeer already invokes
			// peerScorer.OnDisconnect(bp.id, true) ("planned=false" →
			// the scorer counts the disconnect as forced, not as the peer
			// churning). We must NOT also call OnDisconnect here.
			logging.Global().Warn("R39-P1-06: disconnecting banned peer", map[string]any{
				"peerID":   string(bp.id),
				"score":    h.peerScorer.GetScore(bp.id),
				"reason":   "banned-by-scorer",
				"audit-id": "R39-P1-06",
			})
			h.disconnectPeer(bp.peer) // caller-must-hold peersMu — we are the caller
		}()
	}
}

func (h *Host) discoveryRefreshLoop() {
	// P2P-R16-CRIT-002 (2026-07-22) FIX: Panic recovery so a discovery
	// bug cannot silently halt this loop (node cannot find new peers →
	// network isolation).
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("discoveryRefreshLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	refreshInterval := 30 * time.Minute
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	// Initial refresh after a short delay to let bootstrap connections establish
	initialDelay := time.NewTimer(15 * time.Second)
	defer initialDelay.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-initialDelay.C:
			h.doDiscoveryRefresh()
		case <-ticker.C:
			h.doDiscoveryRefresh()
		}
	}
}

// maxDiscoveryPeers limits how many peers the discovery process should aim for.
// SECURITY FIX (L14-021): Without this limit, discovery would keep finding and
// adding new peers indefinitely, consuming memory and bandwidth even though the
// connection pool already caps active connections. This early-exit prevents
// unnecessary discovery traffic when we already have enough peers.
const maxDiscoveryPeers = 50

func (h *Host) doDiscoveryRefresh() {
	if h.discoverTable == nil {
		return
	}

	// SECURITY FIX (L14-021): Skip discovery if we already have enough peers.
	// This prevents unbounded peer discovery that wastes bandwidth and memory.
	h.peersMu.RLock()
	connectedCount := 0
	for _, peer := range h.peers {
		if peer.Connected {
			connectedCount++
		}
	}
	h.peersMu.RUnlock()
	if connectedCount >= maxDiscoveryPeers {
		return
	}

	// Add bootstrap peers to discovery table.
	// Bootstrap peers may be in enode:// format or host:port format.
	for _, addr := range h.config.BootstrapPeers {
		var ip net.IP
		var port int
		var nodeID enode.ID

		if strings.HasPrefix(addr, "enode://") {
			// Parse enode URL (like Ethereum: enode://hex@ip:port)
			node, err := enode.ParseV4(addr)
			if err != nil {
				logging.Global().Debug("Failed to parse bootstrap enode for discovery", map[string]any{
					"addr":  addr,
					"error": err.Error(),
				})
				continue
			}
			ip = node.IP()
			port = node.TCP()
			nodeID = node.ID()
		} else {
			// Plain host:port format
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				continue
			}
			port, err = strconv.Atoi(portStr)
			if err != nil {
				continue
			}
			ip = net.ParseIP(host)
			if ip == nil {
				continue
			}
			nodeID = h.peerIDToEnodeID(PeerID(host + ":" + portStr))
		}

		n := enode.NewNode(nodeID, ip, port, port)
		h.discoverTable.AddTrustedNode(n)
	}

	// Add connected peers to discovery table
	h.peersMu.RLock()
	for _, peer := range h.peers {
		if !peer.Connected {
			continue
		}
		host, portStr, err := net.SplitHostPort(peer.Addr)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		nodeID := h.peerIDToEnodeID(peer.ID)
		n := enode.NewNode(nodeID, ip, port, port)
		h.discoverTable.AddTrustedNode(n)
	}
	h.peersMu.RUnlock()

	// Perform random lookups to discover new peers (like Ethereum's doRefresh)
	for i := 0; i < 3; i++ {
		h.performRandomLookup()
	}

	// Persist discovered nodes to disk
	if h.config.NodeDBPath != "" && h.discoverTable != nil {
		if err := h.discoverTable.SaveNodes(h.config.NodeDBPath); err != nil {
			logging.Global().Debug("Failed to persist nodes", map[string]any{
				"error": err.Error(),
			})
		} else {
			logging.Global().Info("Persisted discovered nodes", map[string]any{
				"path": h.config.NodeDBPath,
			})
		}
	}
}

func (h *Host) performRandomLookup() {
	if h.discoverTable == nil {
		return
	}

	// Prefer UDP discovery transport if available
	if h.udpTransport != nil {
		nodes, err := h.udpTransport.LookupRandom()
		if err != nil {
			logging.Global().Debug("UDP random lookup failed", map[string]any{
				"error": err.Error(),
			})
		} else {
			logging.Global().Debug("UDP random lookup completed", map[string]any{
				"nodesFound": len(nodes),
			})
		}
		return
	}

	// Fallback to TCP-based discovery
	var target enode.ID
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		logging.Global().Debug("crypto/rand.Read failed in performRandomLookup", map[string]any{
			"error": err.Error(),
		})
		return
	}
	copy(target[:], b)

	lookupCtx, cancel := context.WithTimeout(h.ctx, 30*time.Second)
	defer cancel()

	queryFn := func(n *enode.Node) ([]*enode.Node, error) {
		peerID := h.enodeIDToPeerID(n.ID())
		h.peersMu.RLock()
		peer, exists := h.peers[peerID]
		h.peersMu.RUnlock()
		if !exists || !peer.Connected {
			return nil, errors.New("peer not connected")
		}

		findNodePayload := make([]byte, 32)
		copy(findNodePayload, target[:])
		findNodeMsg, err := EncodeMessage(MsgTypeFindNode, findNodePayload)
		if err != nil {
			return nil, err
		}

		select {
		case peer.sendCh <- findNodeMsg:
		default:
			return nil, errors.New("send channel full")
		}

		return nil, nil
	}

	lookup := discover.NewLookup(lookupCtx, h.discoverTable, target, queryFn)
	lookup.Run()
}

func (h *Host) peerPingLoop() {
	// P2P-R16-CRIT-002 (2026-07-22) FIX: Panic recovery so a ping bug
	// cannot silently halt this loop (dead connections accumulate →
	// mesh rot).
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("peerPingLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.pingAllPeers()
		}
	}
}

func (h *Host) pingAllPeers() {
	h.peersMu.RLock()
	peers := make([]*Peer, 0, len(h.peers))
	for _, peer := range h.peers {
		if peer.Connected {
			peers = append(peers, peer)
		}
	}
	h.peersMu.RUnlock()

	pingMsg, err := EncodeMessage(MsgTypePing, nil)
	if err != nil {
		return
	}

	for _, peer := range peers {
		select {
		case peer.sendCh <- pingMsg:
		default:
		}
	}
}

// Stop stops the P2P host
func (h *Host) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}
	h.closed = true

	// Cancel context
	h.cancel()

	// SECURITY FIX Q-B-010: Stop background goroutines to prevent leaks.
	h.rateLimiter.Stop()
	h.perIPRateLimiter.Stop()     // P2P-R12-M02
	h.perIPConnRateLimiter.Stop() // R32-P3-03: stop pre-handshake connection rate limiter
	h.txRateLimiter.Stop()        // P2-TXPOOL-RATELIMIT
	h.blacklist.Stop()
	h.penaltyManager.Stop()

	// R37-P3-19 FIX (2026-07-31): Stop the Broadcaster and PeerScorer
	// background goroutines. Both spawn long-running cleanup goroutines
	// (cleanupCache / backgroundCleanup) that previously outlived
	// Host.Stop(), leaking goroutines on shutdown and on test hosts.
	// Both Stop() methods are sync.Once-guarded and safe to call once.
	if h.broadcaster != nil {
		h.broadcaster.Stop()
	}
	if h.peerScorer != nil {
		h.peerScorer.Stop()
	}

	// Phase 2: Stop GossipSub router
	if h.gossipSubRouter != nil {
		h.gossipSubRouter.Stop()
	}

	// Close listener
	if h.listener != nil {
		h.listener.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	}

	// Close all peer connections
	h.peersMu.Lock()
	for _, peer := range h.peers {
		peer.cancel()
		if peer.Conn != nil {
			peer.Conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		}
	}
	h.peersMu.Unlock()

	// Persist discovered nodes before shutdown
	if h.config.NodeDBPath != "" && h.discoverTable != nil {
		if err := h.discoverTable.SaveNodes(h.config.NodeDBPath); err != nil {
			logging.Global().Debug("Failed to persist nodes on shutdown", map[string]any{
				"error": err.Error(),
			})
		}
	}

	if h.udpTransport != nil {
		h.udpTransport.Close()
	}

	// P2P-R13-CRIT-001 (2026-07-21, R12-H01 regression fix): Stop the
	// cert rotation goroutine and wait for it to exit. We release h.mu
	// during the wait because certRotationLoop doesn't touch h.mu (it
	// only reads h.certManager under its own RWMutex) — holding h.mu
	// here would deadlock if the rotation goroutine ever needed to call
	// a Host method that acquires h.mu.
	if h.certRotationCancel != nil {
		h.certRotationCancel()
		h.mu.Unlock()
		if h.certRotationDone != nil {
			<-h.certRotationDone
		}
		h.mu.Lock()
		h.certRotationCancel = nil
		h.certRotationDone = nil
	}

	// P2P-R13-CRIT-003 (2026-07-21, R12-H02 regression fix): Stop the
	// CRL broadcast goroutine and wait for it to exit. Same unlock/wait/lock
	// pattern as above — crlBroadcastLoop doesn't touch h.mu.
	if h.crlBroadcastCancel != nil {
		h.crlBroadcastCancel()
		h.mu.Unlock()
		if h.crlBroadcastDone != nil {
			<-h.crlBroadcastDone
		}
		h.mu.Lock()
		h.crlBroadcastCancel = nil
		h.crlBroadcastDone = nil
	}

	// P2P-R16-M08 (2026-07-23): Stop the NCM CRL cleanup goroutine to
	// prevent leakage on shutdown.
	if h.certManager != nil {
		h.certManager.Close()
	}

	return nil
}

// ID returns the host's peer ID
func (h *Host) ID() PeerID {
	return h.id
}

// PoWNonce returns the pre-computed proof-of-work nonce for this host.
// audit-fix LEGACY-1: Callers creating RLPx connections MUST call
// rlpxConn.SetPoWNonce(h.PoWNonce()) before InitiatorHandshake/ResponderHandshake
// to ensure the PoW nonce is included in the auth message for Sybil resistance.
func (h *Host) PoWNonce() uint64 {
	return h.powNonce
}

// Addr returns the host's listen address
func (h *Host) Addr() string {
	if h.listener != nil {
		return h.listener.Addr().String()
	}
	return h.config.ListenAddr
}

// EnodeURL returns the enode URL for this host
func (h *Host) EnodeURL() string {
	var ip string
	var port int
	if h.listener != nil {
		addr := h.listener.Addr().(*net.TCPAddr)
		port = addr.Port
		if h.config.ExternalIP != "" {
			ip = h.config.ExternalIP
		} else {
			ip = addr.IP.String()
		}
	} else {
		return fmt.Sprintf("enode://%s@%s", h.id, h.config.ListenAddr)
	}
	return fmt.Sprintf("enode://%s@%s:%d", h.id, ip, port)
}

// Peers returns the list of connected peers
func (h *Host) Peers() []PeerInfo {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()

	result := make([]PeerInfo, 0, len(h.peers))
	for _, peer := range h.peers {
		// P2P-C-02 (R29): use IP-aware check so an attacker rotating
		// PeerIDs from a banned IP/subnet is filtered from peer listings.
		if h.blacklist.IsBlacklistedWithIP(peer.ID, peer.Addr) {
			continue
		}
		result = append(result, PeerInfo{
			ID:        peer.ID,
			Addr:      peer.Addr,
			Latency:   peer.Latency,
			Connected: peer.Connected,
			Direction: peer.Direction,
			Version:   peer.Version,
		})
	}
	return result
}

// PeerCount returns the number of connected peers
// placeholderPeerPrefix marks a transient peer-table entry that reserves a slot
// during the handshake (before the real PeerID is known). SYNC-P2P-01 FIX
// (deep-audit 2026-07-12): these must be excluded from PeerCount so a burst of
// concurrent inbound handshakes does not transiently inflate the count that
// gates syncer fork acceptance and sync progress.
const placeholderPeerPrefix = "__pending__"

func (h *Host) PeerCount() int {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()
	count := 0
	for id := range h.peers {
		if strings.HasPrefix(string(id), placeholderPeerPrefix) {
			continue // skip handshake placeholders
		}
		count++
	}
	return count
}

// ConnectedPeerCount returns the number of peers with active connections.
func (h *Host) ConnectedPeerCount() int {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()
	count := 0
	for _, peer := range h.peers {
		if peer.Connected {
			count++
		}
	}
	return count
}

// Connect connects to a peer without pinning its authenticated identity.
// SECURITY FIX Q-B-003: Outbound connections now perform encrypted handshake.
func (h *Host) Connect(ctx context.Context, addr string) error {
	return h.dial(ctx, addr, "")
}

// ConnectVerified connects to a peer and requires its authenticated PeerID to
// match expectedID. It is used for bootstrap records whose identity is pinned
// by the enode node ID.
func (h *Host) ConnectVerified(ctx context.Context, addr string, expectedID PeerID) error {
	if expectedID == "" {
		return errors.New("expected peer ID is empty")
	}
	return h.dial(ctx, addr, expectedID)
}

func (h *Host) dial(ctx context.Context, addr string, expectedID PeerID) error {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			// R48-RP-07 FIX: Defensive nil check before Close.
			if conn != nil {
				conn.Close()
			}
			return fmt.Errorf("failed to set connection deadline: %w", err)
		}
	}

	// R32-P4-4b FIX: Wrap outbound connection in TLS 1.3 when a certificate
	// manager is configured, matching the server-side listener wrapping.
	if h.certManager != nil {
		tlsConfig, tlsErr := h.certManager.GetTLSConfig()
		if tlsErr != nil {
			if conn != nil {
				conn.Close()
			}
			return fmt.Errorf("failed to build TLS config: %w", tlsErr)
		}
		// InsecureSkipVerify is set because we use VerifyPeerCertificate
		// for custom chain validation (CA-based, not hostname-based).
		// The actual verification happens in NodeCertificateManager.
		tlsConfig.InsecureSkipVerify = true
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			if conn != nil {
				conn.Close()
			}
			return fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	// Perform encrypted handshake before adding to peer list
	encConn, err := performClientHandshake(conn, h.nodeKeyPair, h.id, expectedID, h.powNonce)
	if err != nil {
		if conn != nil {
			conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		}
		return fmt.Errorf("encrypted handshake failed: %w", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return fmt.Errorf("failed to clear connection deadline: %w", err)
	}

	return h.handleConnection(encConn, DirOutbound)
}

// Disconnect disconnects from a peer
func (h *Host) Disconnect(id PeerID) error {
	h.peersMu.Lock()
	defer h.peersMu.Unlock()

	peer, exists := h.peers[id]
	if !exists {
		return fmt.Errorf("peer not found")
	}

	// audit-fix P2P-1: update sybil resistance state on disconnect
	h.sybilResistance.OnDisconnect(id, peer.Addr)

	h.peerScorer.OnDisconnect(id, true)

	logging.Global().Warn("Disconnect: canceling peer context", map[string]any{
		"peerID":    string(id),
		"addr":      peer.Addr,
		"direction": peer.Direction.String(),
	})

	peer.cancel()
	if peer.Conn != nil {
		peer.Conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	}
	delete(h.peers, id)

	return nil
}

// disconnectPeer disconnects a peer without acquiring peersMu lock (caller must hold lock)
// audit-fix RATE-LIMIT-1: used for rate limit violation disconnections
func (h *Host) disconnectPeer(peer *Peer) {
	logging.Global().Warn("disconnectPeer: canceling peer context", map[string]any{
		"peerID":    string(peer.ID),
		"addr":      peer.Addr,
		"direction": peer.Direction.String(),
	})
	peer.cancel()
	if peer.Conn != nil {
		peer.Conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	}
	delete(h.peers, peer.ID)
	h.peerScorer.OnDisconnect(peer.ID, true)
}

// disconnectAllPeersForCertRotation disconnects every currently-connected
// peer so they reconnect and learn the new leaf certificate via the normal
// handshake.
//
// P2P-R14-CRIT-002 (2026-07-21): after CheckAndRotateCertificate regenerates
// the local cert/keypair, peers still hold the OLD pinned public key (TOFU,
// see P2P-R12-H03). Any subsequent connection attempt from the rotated node
// would be rejected by the peer's pinning check, isolating the rotated node
// until every peer's pinning is manually cleared. By proactively disconnecting
// all peers, we force them to re-dial us (or accept our re-dial), which
// triggers a fresh handshake that re-pins the new public key.
//
// P2P-R15-MED-4 (2026-07-22): Previously, this ONLY disconnected peers and
// relied on remote peers to re-dial. But the reconnectLoop only reconnects
// to bootstrap peers, not regular peers — so non-bootstrap connections were
// permanently lost. Now we save the addresses of disconnected peers and
// actively re-dial them after a brief delay (to allow the cert rotation to
// complete and the new cert to be loaded).
//
// This is registered as a rotation callback via
// NodeCertificateManager.RegisterRotationCallback. It runs in the rotation
// goroutine, so it must not block on network I/O. peer.cancel() and
// Conn.Close() are non-blocking from the caller's perspective (they signal
// the peer goroutines to exit; the actual teardown happens asynchronously).
// The reconnection is launched as a separate goroutine.
func (h *Host) disconnectAllPeersForCertRotation() {
	// Save peer addresses BEFORE clearing the map so we can re-dial them.
	h.peersMu.Lock()
	disconnected := 0
	var reconnectAddrs []string
	for _, peer := range h.peers {
		peer.cancel()
		if peer.Conn != nil {
			peer.Conn.Close() // #nosec G104 -- non-critical //nolint:errcheck
		}
		h.peerScorer.OnDisconnect(peer.ID, true)
		disconnected++
		// P2P-R15-MED-4: Save the address for reconnection. Skip bootstrap
		// peers (they're handled by reconnectLoop) and peers without a
		// valid address.
		if peer.Addr != "" && !h.isBootstrapAddr(peer.Addr) {
			reconnectAddrs = append(reconnectAddrs, peer.Addr)
		}
	}
	// Clear the peer map. Reconnection will populate it as peers re-handshake.
	h.peers = make(map[PeerID]*Peer)
	h.peersMu.Unlock()

	logging.Global().Info("P2P-R14-CRIT-002: disconnected all peers after cert rotation",
		map[string]any{"peer_count": disconnected, "reconnect_candidates": len(reconnectAddrs)})

	// P2P-R15-MED-4: Actively re-dial non-bootstrap peers after a brief
	// delay. The delay allows the cert rotation to complete and the new
	// cert to be fully loaded before we attempt re-handshakes. Launched as
	// a goroutine so the rotation callback returns immediately (it must
	// not block on network I/O).
	if len(reconnectAddrs) > 0 {
		go h.reconnectAfterCertRotation(reconnectAddrs)
	}
}

// reconnectAfterCertRotation re-dials peers that were disconnected during
// cert rotation. P2P-R15-MED-4 (2026-07-22).
//
// P2P-R16-L01 (2026-07-23) FIX:
//   - Add defer recover() so a panic (e.g. nil peer, map concurrent write)
//     during reconnection cannot permanently silence this goroutine.
//   - Replace blocking time.Sleep with a select on h.ctx.Done() so Stop()
//     cancels the delay and the goroutine exits promptly.
func (h *Host) reconnectAfterCertRotation(addrs []string) {
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("P2P-R16-L01: reconnectAfterCertRotation panic recovered", map[string]any{
				"panic":      fmt.Sprintf("%v", r),
				"addr_count": len(addrs),
			})
		}
	}()

	// Brief delay to allow cert rotation to complete and new cert to load.
	// Use a cancellable select so Stop() (which cancels h.ctx) interrupts
	// the wait instead of blocking up to 5 seconds during shutdown.
	select {
	case <-time.After(5 * time.Second):
	case <-h.ctx.Done():
		return
	}

	reconnected := 0
	for _, addr := range addrs {
		// Skip if already reconnected (remote peer may have re-dialed first).
		h.peersMu.RLock()
		alreadyConnected := false
		for _, peer := range h.peers {
			if peer.Addr == addr {
				alreadyConnected = true
				break
			}
		}
		h.peersMu.RUnlock()
		if alreadyConnected {
			continue
		}

		// Honor shutdown mid-loop: avoid dialing new peers if the host is
		// already stopping.
		if h.ctx.Err() != nil {
			return
		}

		ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
		if err := h.Connect(ctx, addr); err != nil {
			logging.Global().Debug("P2P-R15-MED-4: reconnect after cert rotation failed", map[string]any{
				"address": addr,
				"error":   err.Error(),
			})
		} else {
			reconnected++
		}
		cancel()
	}
	logging.Global().Info("P2P-R15-MED-4: cert rotation reconnection complete", map[string]any{
		"attempted":   len(addrs),
		"reconnected": reconnected,
	})
}

// isBootstrapAddr returns true if the given address matches one of the
// configured bootstrap peers. P2P-R15-MED-4: used to skip bootstrap peers
// in reconnectAfterCertRotation (they're already handled by reconnectLoop).
func (h *Host) isBootstrapAddr(addr string) bool {
	for _, bp := range h.config.BootstrapPeers {
		if bp == addr {
			return true
		}
	}
	return false
}

// audit-fix RATE-LIMIT-1: ban duration for rate limit violations
const RateLimitBanDuration = time.Hour

// acceptLoop accepts incoming connections.
// AUDIT (2026) HIGH-15: the raw TCP accept is decoupled from the PQ
// handshake. Each accepted connection runs the handshake in its own
// goroutine (capped by handshakeSem) so a single stalled peer cannot
// block other inbound connections.
func (h *Host) acceptLoop() {
	// P2P-R15-MED-5 (2026-07-22): Panic recovery so an Accept error path
	// (e.g., nil listener after concurrent Close) cannot crash the node.
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("acceptLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	// Type-assert to *encryptedListener to use the async accept path.
	encListener, ok := h.listener.(*encryptedListener)
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}

		var conn net.Conn
		var err error
		if ok {
			conn, err = encListener.AcceptRaw()
		} else {
			conn, err = h.listener.Accept()
		}
		if err != nil {
			if h.ctx.Err() != nil {
				return
			}
			continue
		}

		go func(rawConn net.Conn) {
			// P2P-R10-H1 (2026-07-19) FIX: Wrap the entire inbound
			// connection handler in a panic recovery so a malicious or
			// buggy handshake/peer message cannot crash the entire node.
			// Without this, a panic in ServerHandshake, handleConnection,
			// or any of their callees propagates up the goroutine stack
			// and terminates the Go runtime (crashing the node).
			defer func() {
				if r := recover(); r != nil {
					logging.Global().Error("Inbound connection handler panic recovered", map[string]any{
						"addr":  rawConn.RemoteAddr().String(),
						"panic": fmt.Sprintf("%v", r),
					})
					rawConn.Close() // #nosec G104 -- best-effort close after panic //nolint:errcheck
				}
			}()
			// If async handshake is available, run it here (not in Accept).
			var encConn net.Conn = rawConn
			if ok {
				// AUDIT (2026) R4-P2P-02: Per-IP admission control
				// BEFORE the PQ handshake. A single IP can otherwise open
				// many stalled TCP connections, each holding one of the 32
				// handshakeSem slots for ~30s (DefaultHandshakeTimeout),
				// monopolizing all inbound-handshake capacity. The per-IP
				// limiter rejects excess connections from the same IP
				// before any Kyber768/Dilithium3 work begins.
				ip, _, splitErr := net.SplitHostPort(rawConn.RemoteAddr().String())
				if splitErr != nil {
					ip = rawConn.RemoteAddr().String()
				}
				// Loopback exemption: on local test networks all nodes share 127.0.0.1/::1,
				// and the pre-handshake per-IP limits (max 3 concurrent handshakes + 10/s connection attempts)
				// would deadlock local multi-node setups. Production nodes listen on public IPs and never accept
				// loopback P2P connections, so the exemption does not weaken production security.
				parsedIP := net.ParseIP(ip)
				isLoopback := parsedIP != nil && parsedIP.IsLoopback()
				if !isLoopback {
					// R32-P3-03 FIX (2026-07-28): Pre-handshake per-IP
					// connection ATTEMPT rate limit. perIPLimiter below only
					// caps CONCURRENT in-flight handshakes; it does not cap the
					// RATE of new connection attempts. An attacker can rapidly
					// cycle connect→reject→reconnect thousands of times per
					// second, consuming accept goroutines, mutex cycles, and
					// log I/O even though every attempt is rejected. This rate
					// limiter rejects excess attempts BEFORE perIPLimiter.acquire
					// and BEFORE any log line is written, minimizing resource
					// consumption during a connection flood. The limit
					// (defaultMaxPerIPConnAttemptsPerSec = 10/sec) is well above
					// legitimate peer reconnection rates.
					if !h.perIPConnRateLimiter.Allow(PeerID(ip)) {
						rawConn.Close()
						// Intentionally NOT logging at Warn here — a flooded
						// IP can generate thousands of rejections per second,
						// and logging each one would amplify disk I/O during
						// the exact attack scenario this limiter is designed
						// to mitigate. The metrics.AddHandshakeFailure counter
						// still increments so operators can alert on the
						// aggregate rate via the /metrics endpoint.
						metrics.Global().AddHandshakeFailure()
						return
					}
					if !h.perIPLimiter.acquire(ip) {
						rawConn.Close()
						logging.Global().Warn("Inbound handshake rejected: per-IP limit exceeded (pre-handshake DoS protection)", map[string]any{
							"addr": rawConn.RemoteAddr().String(),
							"ip":   ip,
						})
						// R14-LOW (P2P-LOW-06): Aggregate handshake failures in
						// metrics so operators can alert on attack patterns
						// (e.g., a single IP exceeding the per-IP cap repeatedly).
						metrics.Global().AddHandshakeFailure()
						return
					}
					defer h.perIPLimiter.release(ip)
				}

				// AUDIT (2026) HIGH-15: semaphore limits concurrent
				// handshakes to prevent pre-auth resource exhaustion.
				//
				// AUDIT (2026) R3-P2P-03 FIX: Use NON-BLOCKING send.
				// Previously this was a blocking select with only ctx.Done
				// as an alternative — an attacker could flood raw TCP
				// connections, each spawning a goroutine that parked here
				// waiting for a slot. The handshakeSem (cap 32) bounded
				// concurrent handshakes, but NOT the number of pending
				// pre-auth goroutines or the FDs they held. Under a SYN
				// flood the node would accumulate unlimited goroutines +
				// FDs (only capped by OS limits, at which point the
				// process crashes). Now: if no slot is immediately
				// available, the connection is rejected at the edge.
				select {
				case h.handshakeSem <- struct{}{}:
					defer func() { <-h.handshakeSem }()
				default:
					rawConn.Close()
					logging.Global().Warn("Inbound handshake rejected: semaphore full (pre-auth DoS protection)", map[string]any{
						"addr": rawConn.RemoteAddr().String(),
					})
					return
				case <-h.ctx.Done():
					rawConn.Close()
					return
				}
				hc, hsErr := encListener.ServerHandshake(rawConn)
				if hsErr != nil {
					rawConn.Close()
					logging.Global().Warn("Inbound PQ handshake failed", map[string]any{
						"addr":  rawConn.RemoteAddr().String(),
						"error": hsErr.Error(),
					})
					// R14-LOW (P2P-LOW-06): Aggregate handshake failures in
					// metrics so operators can alert on attack patterns
					// (e.g., malformed PQ handshakes from a botnet).
					metrics.Global().AddHandshakeFailure()
					return
				}
				encConn = hc
			}
			if err := h.handleConnection(encConn, DirInbound); err != nil {
				logging.Global().Warn("Inbound connection failed", map[string]any{
					"addr":  encConn.RemoteAddr().String(),
					"error": err.Error(),
				})
				// R14-LOW (P2P-LOW-06): Aggregate post-handshake connection
				// failures too — these include peer-ID mismatches, signature
				// verification failures, and protocol violations. Counting
				// them alongside pre-handshake failures gives operators a
				// complete picture of P2P-layer rejection pressure.
				metrics.Global().AddHandshakeFailure()
			}
		}(conn)
	}
}

// handleConnection handles a new connection
func (h *Host) handleConnection(conn net.Conn, dir Direction) error {
	// SECURITY FIX: Add connection timeout to prevent resource exhaustion.
	//  (P3): use the named DefaultHandshakeTimeout constant instead of a
	// hardcoded 60s magic number so the deadline is tunable in one place.
	//
	// P2-DEADLINE FIX (R29, 2026-07-26): Previously the error from SetDeadline
	// was silently ignored (#nosec G104). If SetDeadline fails, the connection
	// has NO timeout — a malicious peer could hold the connection open forever,
	// exhausting the max-peers slot and causing resource exhaustion DoS. Now
	// we return the error so the caller closes the connection and frees the
	// slot. This is security-critical: the deadline is the only protection
	// against Slowloris-style attacks on the handshake.
	if err := conn.SetDeadline(time.Now().Add(DefaultHandshakeTimeout)); err != nil {
		conn.Close()
		return fmt.Errorf("failed to set handshake deadline: %w", err)
	}

	// R40-H11 FIX: Single atomic check-and-reserve for max peers.
	// Previously there were two separate lock acquisitions with a gap between
	// them (TOCTOU race), allowing multiple goroutines to pass the first check
	// simultaneously and exceed MaxPeers. Now we reserve a slot atomically
	// using a placeholder peer entry, and clean it up on failure.
	//
	// FIX: the MaxPeers check now applies to BOTH inbound and outbound
	// connections (total peer count), not just inbound. Previously outbound
	// connections bypassed the limit entirely, allowing the node to exceed
	// MaxPeers via active dials.
	h.peersMu.Lock()
	if len(h.peers) >= h.config.MaxPeers {
		h.peersMu.Unlock()
		conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		return fmt.Errorf("max peers reached")
	}
	// SYNC-P2P-02 FIX (deep-audit 2026-07-12): enforce a separate inbound cap so
	// inbound connections cannot fill the entire peer table and starve outbound
	// dials to honest peers (eclipse mitigation). Placeholders carry Direction,
	// so in-flight inbound handshakes count toward the cap too.
	if dir == DirInbound {
		maxInbound := h.config.MaxInboundPeers
		if maxInbound <= 0 {
			maxInbound = h.config.MaxPeers * 2 / 3
			if maxInbound <= 0 {
				maxInbound = h.config.MaxPeers // tiny MaxPeers: fall back to total cap
			}
		}
		inbound := 0
		for _, p := range h.peers {
			if p.Direction == DirInbound {
				inbound++
			}
		}
		if inbound >= maxInbound {
			h.peersMu.Unlock()
			conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
			return fmt.Errorf("max inbound peers reached")
		}
	}
	// Reserve a slot with a temporary placeholder to prevent other goroutines
	// from also passing the max-peers check while we perform the handshake.
	// Use a unique placeholder ID derived from the remote address.
	placeholderID := PeerID(placeholderPeerPrefix + conn.RemoteAddr().String())
	h.peers[placeholderID] = &Peer{
		ID:        placeholderID,
		Addr:      conn.RemoteAddr().String(),
		Connected: false,
		Direction: dir,
	}
	h.peersMu.Unlock()

	// Clean up placeholder on any failure path
	removePlaceholder := func() {
		h.peersMu.Lock()
		delete(h.peers, placeholderID)
		h.peersMu.Unlock()
	}

	peerID, err := h.performHandshake(conn, dir)
	if err != nil {
		removePlaceholder()
		conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		return err
	}

	// P2P-C-02 (R29): use IP-aware blacklist check so a Sybil attacker
	// rotating PeerIDs from a banned IP/subnet is rejected at handshake.
	// conn.RemoteAddr() gives us the raw "host:port" string; the
	// Blacklist internally normalizes it.
	remoteAddr := ""
	if conn != nil {
		if ra := conn.RemoteAddr(); ra != nil {
			remoteAddr = ra.String()
		}
	}
	if h.blacklist.IsBlacklistedWithIP(peerID, remoteAddr) && !h.isBootstrapPeer(peerID) {
		removePlaceholder()
		conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		return fmt.Errorf("peer is blacklisted")
	}

	if h.config.WhitelistOnly && !h.trustedPeers[peerID] {
		removePlaceholder()
		conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		logging.Global().Warn("Rejected non-whitelisted peer", map[string]any{
			"peerID": string(peerID),
			"addr":   conn.RemoteAddr().String(),
		})
		return fmt.Errorf("peer not in whitelist")
	}

	if !h.isBootstrapPeer(peerID) {
		if err := h.sybilResistance.CheckConnection(peerID, conn.RemoteAddr().String()); err != nil {
			removePlaceholder()
			conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
			return fmt.Errorf("sybil resistance rejected connection: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(h.ctx)
	peer := &Peer{
		ID:        peerID,
		Addr:      conn.RemoteAddr().String(),
		Conn:      conn,
		Connected: true,
		Direction: dir,
		sendCh:    make(chan []byte, 4096), // TPS FIX: 100→4096, prevents silent tx broadcast drops
		ctx:       ctx,
		cancel:    cancel,
	}

	// R40-H11 FIX: Atomically swap placeholder with real peer entry.
	// Duplicate connection handling: if we already have a connection to this peer,
	// keep the outbound connection and close the inbound (Ethereum standard practice).
	h.peersMu.Lock()
	delete(h.peers, placeholderID)
	if existing, exists := h.peers[peerID]; exists {
		selfIsLower := string(h.id) < string(peerID)
		keepOutbound := selfIsLower
		if keepOutbound {
			if dir == DirOutbound {
				h.peers[peerID] = peer
				h.peersMu.Unlock()
				existing.cancel()
				if existing.Conn != nil {
					existing.Conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
				}
				logging.Global().Info("Replacing with outbound (self ID lower)", map[string]any{
					"peerID":      string(peerID),
					"existingDir": existing.Direction.String(),
				})
			} else {
				h.peersMu.Unlock()
				logging.Global().Info("Closing duplicate inbound (self ID lower)", map[string]any{
					"peerID":      string(peerID),
					"existingDir": existing.Direction.String(),
				})
				conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
				return fmt.Errorf("duplicate connection: keeping existing")
			}
		} else {
			if dir == DirInbound {
				h.peers[peerID] = peer
				h.peersMu.Unlock()
				existing.cancel()
				if existing.Conn != nil {
					existing.Conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
				}
				logging.Global().Info("Replacing with inbound (peer ID lower)", map[string]any{
					"peerID":      string(peerID),
					"existingDir": existing.Direction.String(),
				})
			} else {
				h.peersMu.Unlock()
				logging.Global().Info("Closing duplicate outbound (peer ID lower)", map[string]any{
					"peerID":      string(peerID),
					"existingDir": existing.Direction.String(),
				})
				conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
				return fmt.Errorf("duplicate connection: keeping existing")
			}
		}
	} else {
		h.peers[peerID] = peer
		h.peersMu.Unlock()
	}

	// Record connection in peer scorer
	isBootstrap := h.isBootstrapPeer(peerID)
	h.peerScorer.OnConnect(peerID, isBootstrap)

	// Enable TCP keep-alive to prevent silent connection drops
	setTCPKeepAlive(peer.Conn)

	// Start read/write loops
	go h.readLoop(peer)
	go h.writeLoop(peer)

	return nil
}

func (h *Host) isBootstrapPeer(id PeerID) bool {
	// L14-003 FIX: Use exact match instead of strings.Contains to prevent
	// partial matches. strings.Contains allowed a short peer ID to match
	// against any bootstrap peer address containing it as a substring.
	for _, bp := range h.config.BootstrapPeers {
		if bp == string(id) {
			return true
		}
	}
	return false
}

// PeerIdentityVerifier defines the interface for peer identity verification
// peer identity verification: interface for cryptographic identity verification
type PeerIdentityVerifier interface {
	// VerifyPeerIdentity verifies a peer's identity using challenge-response
	VerifyPeerIdentity(conn net.Conn, peerID PeerID) error
}

// ErrIdentityMismatch is returned when peer ID doesn't match public key
var ErrIdentityMismatch = fmt.Errorf("peer identity mismatch")

// ErrInvalidSignature is returned when peer signature verification fails
var ErrInvalidSignature = fmt.Errorf("invalid peer signature")

// isLoopbackConn returns true if the connection's remote address is a
// loopback address (127.0.0.1 / ::1). Used to skip PoW verification for
// local test networks where all nodes share the loopback interface.
// P3-LOCALNET FIX (2026-08-07).
func isLoopbackConn(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return false
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.IsLoopback()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}

// performHandshake performs the handshake with a peer
// Implements bidirectional challenge-response protocol with replay attack protection
func (h *Host) performHandshake(conn net.Conn, dir Direction) (PeerID, error) {
	// FIX: Use DefaultHandshakeTimeout constant instead of hardcoded
	// 60s to ensure consistency if the constant is ever adjusted.
	//
	// P2-DEADLINE FIX (R29, 2026-07-26): Previously the SetDeadline error was
	// silently ignored. If SetDeadline fails, the handshake has no timeout —
	// a malicious peer could stall the handshake forever, tying up a peer
	// slot and a goroutine. Now we return the error immediately. The defer
	// that clears the deadline also logs on error (cleanup path — the
	// connection is about to be closed anyway, but logging helps diagnose
	// connection issues).
	if err := conn.SetDeadline(time.Now().Add(DefaultHandshakeTimeout)); err != nil {
		return "", fmt.Errorf("failed to set handshake deadline: %w", err)
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			logging.Global().Warn("performHandshake: failed to clear connection deadline",
				map[string]any{"error": err.Error()})
		}
	}()

	// Step 1: Exchange IDs with timestamp for replay protection
	// CRITICAL SECURITY FIX: Include timestamp to prevent replay attacks
	// Format: timestamp (8 bytes big-endian) + idBytes
	idBytes := []byte(h.id)
	handshakeData := make([]byte, 8+len(idBytes))
	binary.BigEndian.PutUint64(handshakeData[:8], uint64(time.Now().Unix())) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	copy(handshakeData[8:], idBytes)

	msg, err := EncodeMessage(MsgTypeStatus, handshakeData)
	if err != nil {
		return "", err
	}

	if _, err := conn.Write(msg); err != nil {
		return "", err
	}

	// audit-fix R3-M6: use readHandshakeMessage to prevent partial TCP reads
	decoded, err := readHandshakeMessage(conn)
	if err != nil {
		return "", fmt.Errorf("failed to read peer ID: %w", err)
	}

	// CRITICAL SECURITY FIX: Verify timestamp to prevent replay attacks
	// Format expected: timestamp (8 bytes) + peerID
	if len(decoded.Payload) < 8 {
		return "", fmt.Errorf("handshake payload too short: need at least 8 bytes for timestamp")
	}
	peerTimestamp := int64(binary.BigEndian.Uint64(decoded.Payload[:8])) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	now := time.Now().Unix()
	timeDiff := now - peerTimestamp
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > int64(HandshakeTimestampTolerance.Seconds()) {
		return "", fmt.Errorf("handshake timestamp out of range: diff=%d seconds, max allowed=%d", timeDiff, HandshakeTimestampTolerance)
	}

	peerID := PeerID(decoded.Payload[8:])

	// CRITICAL SECURITY FIX: Verify ProofOfWork for Sybil resistance
	// Exchange and verify PoW nonces after ID exchange
	//
	// P3-LOCALNET FIX (2026-08-07): Skip PoW for loopback connections.
	// PoW (difficulty=24) takes ~28s per nonce. When multiple local nodes
	// connect simultaneously, the bootstrap node must compute PoW serially
	// for each, exceeding the 60s handshake deadline → i/o timeout →
	// connection rejected → nodes can't sync → chain fork.
	// Production nodes listen on public IPs and never accept P2P connections
	// from loopback, so this exemption does not weaken production security.
	if isLoopbackConn(conn) {
		hostLog.Info("performHandshake: skipping PoW verification for loopback connection")
	} else if err := h.verifyPeerProofOfWork(conn, peerID); err != nil {
		return "", fmt.Errorf("proof-of-work verification failed: %w", err)
	}

	// Exchange and verify QNR records (cryptographic identity binding)
	if _, err := h.exchangeQNR(conn, peerID); err != nil {
		return "", fmt.Errorf("QNR exchange failed: %w", err)
	}

	// Step 2: Bidirectional challenge-response
	// Outbound connection initiates challenge, inbound responds first
	if dir == DirOutbound {
		// We initiated: send challenge, then respond to their challenge
		if err := h.sendAndReceiveChallenge(conn, peerID); err != nil {
			return "", fmt.Errorf("challenge-response failed: %w", err)
		}
	} else {
		// They initiated: respond to their challenge, then send ours
		if err := h.receiveAndRespondChallenge(conn, peerID); err != nil {
			return "", fmt.Errorf("challenge-response failed: %w", err)
		}
	}

	// Step 3: Protocol negotiation — agree on sub-protocols
	// Only the outbound side initiates; inbound side responds
	if dir == DirOutbound {
		if err := h.performProtocolNegotiation(conn, peerID); err != nil {
			return "", fmt.Errorf("protocol negotiation failed: %w", err)
		}
	} else {
		if err := h.respondProtocolNegotiation(conn, peerID); err != nil {
			return "", fmt.Errorf("protocol negotiation response failed: %w", err)
		}
	}

	return peerID, nil
}

// verifyPeerProofOfWork exchanges and verifies proof-of-work nonces with a peer.
// CRITICAL SECURITY FIX: Integrate VerifyProofOfWork into host handshake for Sybil resistance.
// This function is called after ID exchange but before challenge-response.
func (h *Host) verifyPeerProofOfWork(conn net.Conn, peerID PeerID) error {
	// CRITICAL FIX C-15-v2: Generate PoW using our enode.ID (SHA3-256 of public key)
	// so peer can verify with VerifyProofOfWork which uses enode.ID.
	// BUG FIX: Previously used raw public key bytes (1952 bytes) as input to
	// generatePoWNonce, but VerifyProofOfWork uses enode.ID (32-byte hash of pubkey).
	// This mismatch caused ALL PoW verifications to fail, completely breaking
	// Sybil resistance. Now both sides use the same 32-byte enode.ID.
	pubBytes := h.nodeKeyPair.Public.Bytes()
	pubHasher := sha3.New256()
	pubHasher.Write(pubBytes)
	var ourNodeID enode.ID
	copy(ourNodeID[:], pubHasher.Sum(nil))
	ourNonce, err := generatePoWNonce(ourNodeID[:], h.config.DevMode)
	if err != nil {
		return fmt.Errorf("failed to generate PoW nonce: %w", err)
	}

	// Send our nonce (8 bytes big-endian)
	nonceMsg, err := EncodeMessage(MsgTypeProofOfWork, ourNonce)
	if err != nil {
		return fmt.Errorf("failed to encode PoW message: %w", err)
	}
	if _, err := conn.Write(nonceMsg); err != nil {
		return fmt.Errorf("failed to send PoW nonce: %w", err)
	}

	// Receive peer's nonce
	peerNonceMsg, err := readHandshakeMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read peer PoW nonce: %w", err)
	}
	if peerNonceMsg.Type != MsgTypeProofOfWork {
		return fmt.Errorf("expected PoW message type %d, got %d", MsgTypeProofOfWork, peerNonceMsg.Type)
	}
	if len(peerNonceMsg.Payload) != 8 {
		return fmt.Errorf("invalid PoW nonce length: expected 8 bytes, got %d", len(peerNonceMsg.Payload))
	}
	// R40-H2 FIX: Use LittleEndian to match generatePoWNonce() and
	// discover.VerifyProofOfWork() which both use LittleEndian encoding.
	// Previously BigEndian was used here, causing nonce byte order mismatch:
	// generation (LE) -> send (LE bytes) -> receive (BE decode) -> verify (LE encode)
	// would produce a different uint64, causing valid PoW to be rejected.
	peerNonce := binary.LittleEndian.Uint64(peerNonceMsg.Payload)

	// DEV MODE: Skip PoW verification — nodes generate trivial nonces that won't pass difficulty check.
	// Sybil resistance is not needed in local dev environments.
	//
	// CRITICAL SECURITY WARNING (audit-fix CRIT-DEVMODE):
	// DevMode bypasses PoW verification which is a CRITICAL Sybil resistance mechanism.
	// If DevMode is enabled on Mainnet, this creates a critical vulnerability where an attacker
	// could create unlimited fake peers without computing real PoW.
	//
	// Defense-in-depth: Even though node.go:Start() validates DevMode is disabled on Mainnet,
	// we add an explicit assertion here as a safety net. If DevMode+Mainnet somehow reaches
	// this code, we MUST fail rather than silently bypass security.
	if h.config.DevMode {
		if h.config.NetworkID == 1668 { // MainnetNetworkID
			// SECURITY: This should NEVER happen due to node.go startup check, but if it does,
			// we MUST fail hard rather than bypass PoW on mainnet.
			logging.Error("SECURITY ASSERTION FAILED: DevMode is enabled on Mainnet! "+
				"This bypasses PoW verification (critical Sybil resistance). "+
				"Rejecting peer connection to protect network integrity. "+
				"Reference: p2p/host.go:1039-1043, 1073", map[string]any{
				"peerID":    peerID,
				"networkID": h.config.NetworkID,
			})
			return fmt.Errorf("DevMode+MainnetPoWBypass: rejected for security")
		}
		// P3-LOG-01 FIX (R30, 2026-07-27): Use logging.Global().Warn() so SIEM
		// pipelines can collect this security-relevant event.
		logging.Global().Warn("DEV MODE enabled — PoW verification skipped. "+
			"Reference: p2p/host.go:1039-1043. "+
			"Only use DevMode in isolated development environments with no network exposure.", map[string]any{
			"peerID": peerID,
		})
		return nil
	}

	// CRITICAL: Verify peer's PoW using discover.VerifyProofOfWork
	// Convert PeerID to enode.ID for verification
	peerIDBytes, err := hex.DecodeString(string(peerID))
	if err != nil {
		return fmt.Errorf("failed to decode peer ID: %w", err)
	}
	var nodeID enode.ID
	if len(peerIDBytes) >= 32 {
		copy(nodeID[:], peerIDBytes[:32])
	} else {
		copy(nodeID[:], peerIDBytes)
	}

	if !discover.VerifyProofOfWork(nodeID, peerNonce) {
		return discover.ErrInvalidProofOfWork
	}

	return nil
}

// generatePoWNonce computes a valid proof-of-work nonce for a given node ID.
// Uses a hash-based PoW: hash(nodeID || nonce) must have leading MinProofOfWorkDifficulty bits = 0.
// CRITICAL FIX C-15: Now uses nodeID as input so peer can verify with the same format.
// The nonce is generated locally and sent to peer; peer verifies using peer's node ID.
// powCacheFile is the path where PoW nonce is cached after first computation.
const powCacheFile = "pow_cache.json"

var powCacheMu sync.Mutex

type powCacheEntry struct {
	NodeIDHex  string `json:"nodeId"`
	NonceHex   string `json:"nonce"`
	Difficulty int    `json:"difficulty"`
}

func generatePoWNonce(nodeID []byte, devMode bool) ([]byte, error) {
	if os.Getenv("QAU_DEV_MODE_BLOCKS") == "1" || devMode {
		nonce := make([]byte, 8)
		binary.LittleEndian.PutUint64(nonce, 42)
		logging.Global().Debug("generatePoWNonce: DEV MODE — returning trivial nonce", nil)
		return nonce, nil
	}

	powCacheMu.Lock()
	defer powCacheMu.Unlock()

	nodeIDHex := hex.EncodeToString(nodeID)
	difficulty := discover.MinProofOfWorkDifficulty

	// R99-POW-RECOMPUTE (2026-08-30): consult the in-process memo FIRST. The
	// nonce is a pure function of (nodeID, difficulty), both fixed for the
	// process lifetime, so one search per process is always sufficient. Before
	// this, the on-disk file was the only cache; when it could not be written
	// (systemd ProtectHome=true made the fallback /root/.config unreachable)
	// every handshake re-ran a 32.5 s search while holding powCacheMu,
	// serializing all peer connections and preventing the mesh from forming.
	if memo := lookupPoWMemoLocked(nodeIDHex, difficulty); memo != nil {
		out := make([]byte, len(memo))
		copy(out, memo)
		return out, nil
	}

	cached, err := loadPoWCache(nodeIDHex, difficulty)
	if err == nil && cached != nil {
		storePoWMemoLocked(nodeIDHex, difficulty, cached)
		logging.Global().Debug("generatePoWNonce: loaded cached nonce", map[string]any{
			"cachePath": powCacheFilePath(),
		})
		return cached, nil
	}

	logging.Global().Info("generatePoWNonce: computing PoW nonce", map[string]any{
		"difficulty": difficulty,
	})

	target := new(big.Int).Lsh(big.NewInt(1), 256-uint(difficulty))
	nonce := make([]byte, 8)

	start := time.Now()
	maxIter := uint64(1) << (difficulty + 6)
	if maxIter > 1<<30 {
		maxIter = 1 << 30
	}

	for i := uint64(0); i < maxIter; i++ {
		binary.LittleEndian.PutUint64(nonce, i)

		hasher := sha3.New256()
		hasher.Write(nodeID)
		hasher.Write(nonce)
		hash := hasher.Sum(nil)

		hashInt := new(big.Int).SetBytes(hash)
		if hashInt.Cmp(target) < 0 {
			elapsed := time.Since(start)
			powComputations.Add(1)
			logging.Global().Info("generatePoWNonce: PoW nonce found", map[string]any{
				"iterations": i,
				"difficulty": difficulty,
				"elapsed":    elapsed.String(),
			})

			// R99-POW-RECOMPUTE: memoize BEFORE attempting to persist, so a
			// failure to write to disk can never cause a recomputation.
			storePoWMemoLocked(nodeIDHex, difficulty, nonce)

			if saveErr := savePoWCache(nodeIDHex, nonce, difficulty); saveErr != nil {
				// Still only a WARN: the in-process memo makes this
				// non-fatal for the running node. It costs one search per
				// restart, which is why the path resolution was also fixed
				// (see resolvePoWCachePath).
				logging.Global().Warn("generatePoWNonce: failed to cache nonce to disk "+
					"(in-process memo active, so this costs one search per restart, not per handshake)",
					map[string]any{
						"error": saveErr.Error(),
						"path":  powCacheFilePath(),
					})
			}

			return nonce, nil
		}

		if i%5000000 == 0 && i > 0 {
			elapsed := time.Since(start)
			logging.Global().Debug("generatePoWNonce: still searching", map[string]any{
				"iterations": i,
				"elapsed":    elapsed.String(),
			})
		}
	}

	return nil, errors.New("PoW computation failed to find valid nonce")
}

// powCacheFilePath resolves where the PoW nonce is persisted.
//
// SECURITY (audit 2026-06-14, L5): the original hardcoded "/var/lib/quantaureum"
// fallback was invalid on Windows and many other systems.
//
// R99-POW-RECOMPUTE (2026-08-30): the os.UserConfigDir() fallback it was
// replaced with resolves to /root/.config for a root service, which
// systemd ProtectHome=true renders unreachable — so on mainnet every save
// failed and every handshake recomputed a 32.5 s search. The node's own data
// directory is now consulted (installed via SetPoWCacheDir) between the
// environment override and the user-config fallback. See resolvePoWCachePath
// for the full precedence order and rationale.
func powCacheFilePath() string {
	return powCacheFilePathR99()
}

func loadPoWCache(nodeIDHex string, difficulty int) ([]byte, error) {
	path := powCacheFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entry powCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	if entry.NodeIDHex != nodeIDHex {
		return nil, fmt.Errorf("nodeID mismatch")
	}
	// R38-P4 FIX: Removed empty if body. A cached difficulty >= required
	// difficulty is valid (harder nonce satisfies easier requirement).
	// Only reject when cached difficulty < required.
	if entry.Difficulty < difficulty {
		return nil, fmt.Errorf("cached difficulty %d < required %d", entry.Difficulty, difficulty)
	}

	nonce, err := hex.DecodeString(entry.NonceHex)
	if err != nil {
		return nil, err
	}

	nodeID, _ := hex.DecodeString(entry.NodeIDHex)
	target := new(big.Int).Lsh(big.NewInt(1), 256-uint(difficulty))
	hasher := sha3.New256()
	hasher.Write(nodeID)
	hasher.Write(nonce)
	hash := hasher.Sum(nil)
	hashInt := new(big.Int).SetBytes(hash)
	if hashInt.Cmp(target) >= 0 {
		return nil, fmt.Errorf("cached nonce fails verification")
	}

	return nonce, nil
}

func savePoWCache(nodeIDHex string, nonce []byte, difficulty int) error {
	path := powCacheFilePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	entry := powCacheEntry{
		NodeIDHex:  nodeIDHex,
		NonceHex:   hex.EncodeToString(nonce),
		Difficulty: difficulty,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// sendAndReceiveChallenge handles challenge-response for outbound connections
func (h *Host) sendAndReceiveChallenge(conn net.Conn, peerID PeerID) error {
	// Generate and send our challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	challengeMsg, err := EncodeMessage(MsgTypeChallenge, challenge)
	if err != nil {
		return err
	}

	if _, err := conn.Write(challengeMsg); err != nil {
		return fmt.Errorf("failed to send challenge: %w", err)
	}

	// audit-fix R3-M6: use readHandshakeMessage to handle TCP fragmentation
	// for Dilithium3 responses (~5245 bytes: sig 3293 + pubkey 1952)
	response, err := readHandshakeMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read challenge response: %w", err)
	}

	if response.Type != MsgTypeChallengeResponse {
		return fmt.Errorf("unexpected message type: %d, expected challenge response", response.Type)
	}

	// Verify the peer's response against our challenge
	if !verifyChallengeResponse(challenge, response.Payload, peerID) {
		return ErrInvalidSignature
	}

	// audit-fix R3-M6: use readHandshakeMessage for reliable reads
	peerChallenge, err := readHandshakeMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read peer challenge: %w", err)
	}

	if peerChallenge.Type != MsgTypeChallenge {
		return fmt.Errorf("unexpected message type: %d, expected challenge", peerChallenge.Type)
	}

	// audit-fix R3-L6: Send our response (Dilithium3 signature)
	responseData := h.signChallenge(peerChallenge.Payload)
	// audit-fix R3-L3: guard against nil if Dilithium3 signing fails.
	if responseData == nil {
		return fmt.Errorf("failed to sign challenge: signing returned nil")
	}
	responseMsg, err := EncodeMessage(MsgTypeChallengeResponse, responseData)
	if err != nil {
		return err
	}

	if _, err := conn.Write(responseMsg); err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	return nil
}

// receiveAndRespondChallenge handles challenge-response for inbound connections
func (h *Host) receiveAndRespondChallenge(conn net.Conn, peerID PeerID) error {
	// audit-fix R3-M6: use readHandshakeMessage for reliable reads
	challenge, err := readHandshakeMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read challenge: %w", err)
	}

	if challenge.Type != MsgTypeChallenge {
		return fmt.Errorf("unexpected message type: %d, expected challenge", challenge.Type)
	}

	// audit-fix R3-L6: Send our response (Dilithium3 signature)
	responseData := h.signChallenge(challenge.Payload)
	// audit-fix R3-L3: guard against nil if Dilithium3 signing fails.
	if responseData == nil {
		return fmt.Errorf("failed to sign challenge: signing returned nil")
	}
	responseMsg, err := EncodeMessage(MsgTypeChallengeResponse, responseData)
	if err != nil {
		return err
	}

	if _, err := conn.Write(responseMsg); err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	// Now send our challenge
	ourChallenge := make([]byte, 32)
	if _, err := rand.Read(ourChallenge); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	challengeMsg, err := EncodeMessage(MsgTypeChallenge, ourChallenge)
	if err != nil {
		return err
	}

	if _, err := conn.Write(challengeMsg); err != nil {
		return fmt.Errorf("failed to send challenge: %w", err)
	}

	// audit-fix R3-M6: use readHandshakeMessage for reliable reads
	response, err := readHandshakeMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if response.Type != MsgTypeChallengeResponse {
		return fmt.Errorf("unexpected message type: %d, expected challenge response", response.Type)
	}

	// Verify the peer's response against our challenge
	if !verifyChallengeResponse(ourChallenge, response.Payload, peerID) {
		return ErrInvalidSignature
	}

	return nil
}

// signChallenge signs a challenge using the node's Dilithium3 private key.
// audit-fix R2-H1: replaces HMAC scheme with Dilithium3 signature-based authentication.
// Returns: signature (3293 bytes) || publicKey (1952 bytes)
// The verifier can then check the signature and derive PeerID from the public key.
func (h *Host) signChallenge(challenge []byte) []byte {
	sig, err := crypto.Sign(h.nodeKeyPair.Private, challenge)
	if err != nil {
		return nil
	}
	pubBytes := h.nodeKeyPair.Public.Bytes()
	// Format: sig || pubkey
	result := make([]byte, len(sig)+len(pubBytes))
	copy(result, sig)
	copy(result[len(sig):], pubBytes)
	return result
}

// verifyChallengeResponse verifies a Dilithium3 signature over the challenge
// and checks that the embedded public key matches the claimed PeerID.
// audit-fix R2-H1: replaces the no-op HMAC length check with real cryptographic
// verification. The peer must possess the Dilithium3 private key corresponding
// to its claimed identity.
func verifyChallengeResponse(challenge, response []byte, peerID PeerID) bool {
	// Response format: signature (3293 bytes) || publicKey (1952 bytes)
	expectedLen := crypto.Dilithium3SignatureSize + crypto.Dilithium3PublicKeySize
	if len(response) != expectedLen {
		return false
	}

	sig := response[:crypto.Dilithium3SignatureSize]
	pubKeyBytes := response[crypto.Dilithium3SignatureSize:]

	// Parse the public key
	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return false
	}

	// Verify the signature over the challenge
	if !crypto.Verify(pubKey, challenge, sig) {
		return false
	}

	// Verify the public key matches the claimed PeerID
	// SECURITY FIX: Must use the same PeerID derivation as NewHost().
	// NewHost derives PeerID = hex(SHA3-256(fullPublicKey)), NOT hex(pubKey[:32]).
	// Using only the first 32 bytes would allow identity collisions — an attacker
	// could craft a different key pair whose first 32 bytes match a target peer's ID.
	pubHasher := sha3.New256()
	pubHasher.Write(pubKeyBytes)
	expectedID := PeerID(hex.EncodeToString(pubHasher.Sum(nil)))
	return subtle.ConstantTimeCompare([]byte(expectedID), []byte(peerID)) == 1
}

// verifyPeerIdentity is deprecated - use bidirectional challenge-response in performHandshake
// Kept for interface compatibility
func (h *Host) verifyPeerIdentity(conn net.Conn, peerID PeerID) error {
	return nil // Now handled in performHandshake
}

// isSyncMessage returns true for message types used in block/state synchronization.
// Sync messages bypass P2P rate limiting because they are request-response pairs
// initiated by the local node, not arbitrary external traffic.
// Reference: go-ethereum p2p/peer.go — rate control is at the application layer
// (downloader/msgrate), not the P2P transport layer.
//
//	(P3): Message priority model. Quantaureum's P2P layer does NOT use
//
// explicit priority queues at the transport level; instead, priority is implied
// by message type via this function:
//   - Sync/status messages (blocks, state snapshots, status) bypass rate
//     limiting because they are self-initiated request/response pairs and are
//     latency-critical for chain convergence.
//   - Gossip/transaction-announce messages (tx hash announce, compact blocks,
//     gossipsub) also bypass rate limiting as they are high-frequency, small,
//     and flood-controlled by the gossipsub mesh, not per-peer limits.
//   - All other message types are subject to per-peer rate limiting to bound
//     bandwidth/CPU from external peers.
//
// This mirrors go-ethereum, where rate control lives at the application layer
// (downloader/msgrate) rather than the wire protocol. If true transport-level
// prioritization is needed in future, add a bounded priority queue per peer.
func isSyncMessage(msgType uint8) bool {
	switch msgType {
	case MsgTypeBlock, MsgTypeBlockReq, MsgTypeBlockResp,
		MsgTypeStatus,
		MsgTypeSnapStateReq, MsgTypeSnapStateResp,
		MsgTypeSnapRangeReq, MsgTypeSnapRangeResp,
		// ETHEREUM-PARITY SYNC (2026-08-13): extended sync protocol traffic
		// gets the lenient sync rate limit, same as BlockReq/BlockResp.
		MsgTypeSnapStorageReq, MsgTypeSnapStorageResp,
		MsgTypeSnapBytecodeReq, MsgTypeSnapBytecodeResp,
		MsgTypeHeaderReq, MsgTypeHeaderResp,
		MsgTypeReceiptReq, MsgTypeReceiptResp:
		return true
	case MsgTypeTxHashAnnounce, MsgTypeTxHashRequest, MsgTypeTxHashResponse, MsgTypeCompactBlock, MsgTypeGossipSub:
		return true
	default:
		return false
	}
}

// readLoop reads messages from a peer
func (h *Host) readLoop(peer *Peer) {
	// P2P-R10-H1 (2026-07-19) FIX: Top-priority panic recovery so that a
	// malicious payload (oversized header, malformed message, deeply nested
	// protocol frame, etc.) cannot crash the node by triggering a panic in
	// readFull, message dispatch, or any handler called from this loop.
	// Without this defer, a panic propagates up and terminates the Go
	// runtime. The cleanup (peer eviction + conn close) below still runs
	// because this defer is registered BEFORE the cleanup defer — Go runs
	// defers LIFO, so the panic-recovery defer runs LAST (after cleanup),
	// which is the desired order: clean up peer state, then swallow panic.
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("readLoop panic recovered", map[string]any{
				"peerID": string(peer.ID),
				"addr":   peer.Addr,
				"panic":  fmt.Sprintf("%v", r),
			})
		}
	}()
	// P2P-R28-H02 FIX (2026-07-25): Symmetric cleanup for readLoop.
	// Previously when readLoop exited (peer disconnect, malformed message,
	// context cancel), it removed the peer from h.peers and closed
	// peer.Conn, but did NOT:
	//   1. Call peer.cancel() — so writeLoop's `<-peer.ctx.Done()` never
	//      fired. writeLoop would block forever on `peer.sendCh`, leaking
	//      the goroutine. Each disconnected peer leaked one goroutine plus
	//      its 4096-buffered sendCh (up to 4096 * ~5KB = 20MB of queued
	//      messages per leaked peer). Over time, node memory would grow
	//      unbounded and the Go scheduler would slow down (goroutine
	//      starvation, similar to the DASClient leak in R20).
	//   2. Close peer.sendCh — so any goroutine doing a blocking send
	//      (SendMessage, broadcastTx, etc.) would also leak.
	// Now we call peer.cancel() FIRST (signals writeLoop to exit via
	// ctx.Done), then close peer.sendCh (unblocks any goroutine doing a
	// blocking send on this peer). The close is guarded by a sync.Once
	// (see Peer.closeOnce) to prevent double-close panics if disconnectPeer
	// also runs concurrently.
	defer func() {
		h.peersMu.Lock()
		if current, exists := h.peers[peer.ID]; exists && current == peer {
			delete(h.peers, peer.ID)
		}
		h.peersMu.Unlock()
		// P2P-R28-H02: Signal writeLoop to exit via context cancellation.
		// This must happen BEFORE Conn.Close() so writeLoop's select can
		// observe ctx.Done() and exit cleanly rather than blocking on
		// sendCh.
		peer.cancel()
		// P2P-R28-H02: Close sendCh to unblock any goroutine doing a
		// blocking send to this peer. Use sync.Once to avoid double-close
		// panic if disconnectPeer or another cleanup path also closes it.
		peer.closeSendCh()
		// P2P-H01 FIX (R29): Run sybilResistance + peerScorer OnDisconnect
		// exactly once via disconnectCleanupOnce. writeLoop's defer also
		// calls this — whichever runs first does the cleanup; the other
		// is a no-op. Prevents IP-count leak when writeLoop exits first.
		peer.disconnectCleanup(h)
		logging.Global().Info("Peer disconnected", map[string]any{
			"peerID":    string(peer.ID),
			"addr":      peer.Addr,
			"direction": peer.Direction.String(),
		})
		// R49-RP-01 FIX: Add nil check for peer.Conn, consistent with disconnectPeer.
		if peer.Conn != nil {
			peer.Conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		}
	}()

	for {
		select {
		case <-peer.ctx.Done():
			logging.Global().Warn("readLoop: peer context canceled, disconnecting", map[string]any{
				"peerID":    string(peer.ID),
				"addr":      peer.Addr,
				"direction": peer.Direction.String(),
				"ctxErr":    peer.ctx.Err().Error(),
			})
			return
		default:
		}

		startTime := time.Now()
		// R14-LOW (P2P-LOW-03 + P2P-LOW-09): Previously this was
		//   `peer.Conn.SetReadDeadline(time.Now().Add(120 * time.Second))`
		// with `#nosec G104 -- error intentionally ignored`, meaning a half-closed
		// connection that silently fails SetReadDeadline would leave the read loop
		// blocked indefinitely — invisible to operators. We now:
		//   (1) use the named constant defaultPeerReadTimeout (P2P-LOW-09) so the
		//       timeout is discoverable and tunable in one place;
		//   (2) log the error at debug level (P2P-LOW-03) so a stuck read loop
		//       surfaces in operator dashboards without flooding the journal
		//       (the subsequent readFull call will surface a real I/O failure
		//       at warn level and disconnect the peer — the debug log here is
		//       defense-in-depth for the rare case where SetReadDeadline fails
		//       but readFull still returns nil).
		if err := peer.Conn.SetReadDeadline(time.Now().Add(defaultPeerReadTimeout)); err != nil {
			logging.Global().Debug("readLoop: SetReadDeadline failed", map[string]any{
				"peerID": string(peer.ID),
				"addr":   peer.Addr,
				"error":  err.Error(),
			})
		}

		header := make([]byte, MsgHeaderSize)
		if _, err := readFull(peer.Conn, header); err != nil {
			logging.Global().Warn("readLoop: header read failed, disconnecting peer", map[string]any{
				"peerID": string(peer.ID),
				"addr":   peer.Addr,
				"error":  err.Error(),
			})
			return
		}

		length := binary.BigEndian.Uint32(header[1:5])
		if length > MaxMsgSize {
			// P3-N1 FIX: Disconnect the peer IMMEDIATELY instead of just logging
			// and continuing. An oversized message indicates a buggy/malicious
			// peer or a protocol violation; keeping the connection open lets the
			// peer repeatedly spam oversized headers (resource exhaustion / DoS).
			// Returning from readLoop triggers the deferred cleanup at the top of
			// the loop (sybilResistance.OnDisconnect, peerScorer.OnDisconnect,
			// peer.Conn.Close), which fully tears down the connection.
			logging.Global().Warn("readLoop: oversized message, disconnecting peer", map[string]any{
				"peerID": string(peer.ID),
				"addr":   peer.Addr,
				"length": length,
				"max":    MaxMsgSize,
			})
			if h.handleMalformedMessageWithIP(peer.ID, peer.Addr, ErrMsgTooLarge) {
				h.peerScorer.RecordProtocolViolation(peer.ID)
			}
			return
		}

		payload := make([]byte, length)
		if length > 0 {
			if _, err := readFull(peer.Conn, payload); err != nil {
				logging.Global().Warn("readLoop: payload read failed, disconnecting peer", map[string]any{
					"peerID": string(peer.ID),
					"addr":   peer.Addr,
					"error":  err.Error(),
				})
				return
			}
		}

		// Combine header and payload
		fullMsg := make([]byte, MsgHeaderSize+int(length))
		copy(fullMsg[:MsgHeaderSize], header)
		copy(fullMsg[MsgHeaderSize:], payload)

		msgType := header[0]
		pureMsgType := msgType &^ MsgFlagCompressed

		if !isSyncMessage(pureMsgType) {
			// P2P-R12-M02 (2026-07-20): per-IP post-handshake rate limit.
			// Bounds the aggregate message rate from one remote IP so an
			// attacker cannot multiply throughput by opening many peer
			// connections from the same IP (within the per-IP handshake
			// cap of 3). The per-peer limiter below still catches a
			// single peer flooding; this limiter is defense-in-depth for
			// the multi-peer-from-one-IP attack vector. Silent drop —
			// no penaltyManager escalation (that is the per-peer limiter's
			// job; per-IP is just an additional cap).
			ip := extractIPFromAddr(peer.Addr)
			if ip != "" && !h.perIPRateLimiter.Allow(PeerID(ip)) {
				logging.Global().Warn("readLoop: per-IP rate limit exceeded, dropping message", map[string]any{
					"peerID":    string(peer.ID),
					"addr":      peer.Addr,
					"ip":        ip,
					"msgType":   pureMsgType,
					"direction": peer.Direction.String(),
				})
				continue
			}
			if !h.rateLimiter.Allow(peer.ID) {
				logging.Global().Warn("readLoop: rate limit exceeded, dropping message", map[string]any{
					"peerID":    string(peer.ID),
					"addr":      peer.Addr,
					"msgType":   pureMsgType,
					"direction": peer.Direction.String(),
				})
				if h.rateLimiter.RecordViolation(peer.ID) {
					h.peersMu.Lock()
					if !h.isBootstrapPeer(peer.ID) {
						// Phase 1: tiered penalties — record the violation and auto-escalate.
						// Pass peer.Addr to enable IP/subnet-layer banning,
						// stopping Sybil attackers from rotating PeerIDs to evade bans.
						level := h.penaltyManager.RecordViolationWithIP(peer.ID, peer.Addr, ViolationRateLimit)
						logging.Global().Warn("Rate limit violation escalated", map[string]any{
							"peerID": string(peer.ID),
							"addr":   peer.Addr,
							"level":  level.String(),
						})
						h.disconnectPeer(peer)
					} else {
						logging.Global().Warn("Rate limit exceeded for bootstrap peer, not disconnecting", map[string]any{
							"peerID": string(peer.ID),
							"addr":   peer.Addr,
						})
					}
					h.peersMu.Unlock()
				}
				continue
			}
		} // end if !isSyncMessage(pureMsgType)

		if err := h.messageValidator.ValidateRawMessage(fullMsg); err != nil {
			logging.Global().Warn("readLoop: ValidateRawMessage failed", map[string]any{
				"peerID":  string(peer.ID),
				"addr":    peer.Addr,
				"msgType": pureMsgType,
				"length":  length,
				"error":   err.Error(),
			})
			if h.handleMalformedMessageWithIP(peer.ID, peer.Addr, err) {
				h.peerScorer.RecordProtocolViolation(peer.ID)
			}
			continue
		}

		msg, err := DecodeMessage(fullMsg)
		if err != nil {
			logging.Global().Warn("readLoop: DecodeMessage failed", map[string]any{
				"peerID":  string(peer.ID),
				"addr":    peer.Addr,
				"msgType": pureMsgType,
				"length":  length,
				"error":   err.Error(),
			})
			if h.handleMalformedMessageWithIP(peer.ID, peer.Addr, err) {
				h.peerScorer.RecordProtocolViolation(peer.ID)
			}
			continue
		}

		msg.From = peer.ID

		if err := h.messageValidator.ValidateMessage(msg); err != nil {
			logging.Global().Warn("readLoop: ValidateMessage failed", map[string]any{
				"peerID":    string(peer.ID),
				"addr":      peer.Addr,
				"msgType":   msg.Type,
				"payloadSz": len(msg.Payload),
				"error":     err.Error(),
			})
			if h.handleMalformedMessageWithIP(peer.ID, peer.Addr, err) {
				h.peerScorer.RecordProtocolViolation(peer.ID)
			}
			continue
		}

		h.peerScorer.RecordResponseTime(peer.ID, time.Since(startTime))

		if pureMsgType == MsgTypeBlock || pureMsgType == MsgTypeBlockReq || pureMsgType == MsgTypeBlockResp {
			logging.Global().Info("readLoop: received sync message", map[string]any{
				"peerID":    string(peer.ID),
				"addr":      peer.Addr,
				"msgType":   pureMsgType,
				"payloadSz": len(msg.Payload),
				"direction": peer.Direction.String(),
			})
		}

		h.routeMessage(msg)
	}
}

// readFull reads exactly len(buf) bytes from the connection
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// readHandshakeMessage reads a complete P2P message during handshake using
// readFull to prevent partial reads on TCP streams.
// audit-fix R3-M6: replaces single conn.Read() calls that may return partial
// data for large payloads like Dilithium3 signatures (~5245 bytes).
func readHandshakeMessage(conn net.Conn) (*Message, error) {
	header := make([]byte, MsgHeaderSize)
	if _, err := readFull(conn, header); err != nil {
		return nil, fmt.Errorf("failed to read message header: %w", err)
	}

	length := binary.BigEndian.Uint32(header[1:5])
	if length > MaxMsgSize {
		return nil, ErrMsgTooLarge
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := readFull(conn, payload); err != nil {
			return nil, fmt.Errorf("failed to read message payload: %w", err)
		}
	}

	fullMsg := make([]byte, MsgHeaderSize+int(length))
	copy(fullMsg[:MsgHeaderSize], header)
	copy(fullMsg[MsgHeaderSize:], payload)

	return DecodeMessage(fullMsg)
}

// setTCPKeepAlive enables TCP keep-alive on a connection to prevent silent
// connection drops caused by idle TCP connections being terminated by
// intermediate network devices (firewalls, NAT gateways, load balancers).
// This unwraps encryptedConn to reach the underlying TCP connection.
func setTCPKeepAlive(conn net.Conn) {
	if conn == nil {
		return
	}

	// Unwrap encryptedConn to get the underlying TCP connection
	var tcpConn *net.TCPConn
	switch c := conn.(type) {
	case *net.TCPConn:
		tcpConn = c
	case *encryptedConn:
		if tc, ok := c.Conn.(*net.TCPConn); ok {
			tcpConn = tc
		}
	}

	if tcpConn == nil {
		return
	}

	// Enable keep-alive with 30-second idle time
	// After 30s of idle, send keep-alive probes every 10s
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)
}

// writeLoop writes messages to a peer
func (h *Host) writeLoop(peer *Peer) {
	// P2P-R15-MED-5 (2026-07-22): Panic recovery so a write error (e.g.,
	// nil conn after concurrent close, buffer overflow) cannot crash the
	// node. Mirrors readLoop's recovery pattern (P2P-R10-H1).
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("writeLoop panic recovered", map[string]any{
				"peerID": string(peer.ID),
				"addr":   peer.Addr,
				"panic":  fmt.Sprintf("%v", r),
			})
		}
	}()
	// P2P-R28-H02 FIX (2026-07-25): Defensive cleanup to ensure that even
	// if writeLoop exits via an unhandled path (panic recovery, write
	// error, etc.), the peer is torn down symmetrically. Previously
	// writeLoop had NO cleanup defer — if it exited via a write error, it
	// would NOT cancel peer.ctx or close peer.Conn, leaving readLoop
	// blocked on a connection that would never be closed. readLoop would
	// eventually time out (defaultPeerReadTimeout=120s), but during that
	// window the peer entry remained in h.peers and could be selected for
	// block/tx broadcast (which would block on the dead sendCh).
	// Now both readLoop and writeLoop have symmetric cleanup. The
	// closeOnce guard prevents double-close panics if both defers run.
	defer func() {
		// Signal readLoop to exit (it may be blocked on readFull).
		peer.cancel()
		// Close sendCh to unblock any goroutine doing a blocking send.
		peer.closeSendCh()
		// Close the connection to unblock any pending read/write.
		if peer.Conn != nil {
			peer.Conn.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		}
		// Remove from peers map (idempotent — readLoop's defer also does this).
		h.peersMu.Lock()
		if current, exists := h.peers[peer.ID]; exists && current == peer {
			delete(h.peers, peer.ID)
		}
		h.peersMu.Unlock()
		// P2P-H01 FIX (R29): Run sybil-resistance + peer-scorer disconnect
		// cleanup. Previously writeLoop had NO OnDisconnect calls, so if
		// writeLoop exited first (e.g. write error) the IP count was never
		// decremented — accumulating until that IP's new connections were
		// permanently rejected. disconnectCleanupOnce makes this safe to
		// call from both loops; whichever runs first does the work.
		peer.disconnectCleanup(h)
	}()
	for {
		select {
		case <-peer.ctx.Done():
			logging.Global().Warn("writeLoop: peer context canceled, disconnecting", map[string]any{
				"peerID":    string(peer.ID),
				"addr":      peer.Addr,
				"direction": peer.Direction.String(),
				"ctxErr":    peer.ctx.Err().Error(),
			})
			return
		case data, ok := <-peer.sendCh:
			// P2P-R28-H02: sendCh may be closed by readLoop's cleanup or
			// disconnectPeer. ok=false means channel is closed and drained —
			// exit cleanly rather than writing to a closed channel (which
			// would panic).
			if !ok {
				return
			}
			// P2-WRITELOOP-RATELIMIT FIX (R29, 2026-07-26): Per-peer outbound
			// rate limit. Without this, a peer could trigger amplification
			// attacks (e.g., many MsgTypeBlockReq → many large
			// MsgTypeBlockResp) that saturate outbound bandwidth and starve
			// other peers. The limit is checked BEFORE SetWriteDeadline so
			// that rate-limited messages don't consume a deadline slot.
			// When the limit is hit, the message is DROPPED (not queued) —
			// this is preferable to blocking writeLoop (which would stall
			// all peers' write loops via shared broadcast goroutines). The
			// drop is logged so operators can detect sustained rate-limiting.
			// We do NOT record a violation or disconnect the peer here —
			// outbound rate limiting is a self-protection measure, not a
			// peer-misconduct signal (the peer may be legitimately syncing
			// and requesting many blocks).
			if !h.outRateLimiter.Allow(peer.ID) {
				logging.Global().Warn("writeLoop: outbound rate limit exceeded, dropping message",
					map[string]any{
						"peerID": string(peer.ID),
						"addr":   peer.Addr,
						"size":   len(data),
					})
				continue
			}
			// P2-DEADLINE FIX (R29, 2026-07-26): Previously the SetWriteDeadline
			// error was silently ignored. If SetWriteDeadline fails, the Write
			// call has no timeout — a stalled peer could block writeLoop
			// forever, tying up the goroutine and preventing the peer from
			// being disconnected. Now we log the error and skip the write
			// (returning exits writeLoop, which triggers cleanup). The
			// subsequent Write would likely fail anyway if the deadline
			// couldn't be set (the connection is probably in a bad state),
			// so returning early is safer than attempting an unbounded Write.
			if err := peer.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
				logging.Global().Warn("writeLoop: SetWriteDeadline failed, disconnecting peer",
					map[string]any{
						"peerID": string(peer.ID),
						"addr":   peer.Addr,
						"error":  err.Error(),
					})
				return
			}
			if _, err := peer.Conn.Write(data); err != nil {
				return
			}
		}
	}
}

// routeMessage routes a message to the appropriate channel
func (h *Host) routeMessage(msg *Message) {
	// I22-005 FIX: Defense-in-depth maximum message size check at the
	// dispatcher. The readLoop already enforces MaxMsgSize (10MB) before
	// decoding, and ValidateRawMessage/ValidateMessage enforce per-type
	// limits. This final guard ensures no message - regardless of its origin
	// path - is dispatched to a handler with a payload exceeding the unified
	// MaxMessageSize, preventing memory exhaustion in message handlers.
	if msg == nil {
		return
	}
	if len(msg.Payload) > MaxMessageSize {
		logging.Global().Warn("routeMessage: dropping oversized message", map[string]any{
			"peerID":    string(msg.From),
			"msgType":   msg.Type,
			"payloadSz": len(msg.Payload),
		})
		if h.handleMalformedMessage(msg.From, ErrMsgTooLarge) {
			h.peerScorer.RecordProtocolViolation(msg.From)
		}
		return
	}
	switch msg.Type {
	case MsgTypeProtocolNegotiate:
		h.handleProtocolNegotiate(msg)
	case MsgTypeProtocolNegotiateResp:
		h.handleProtocolNegotiateResp(msg)
	case MsgTypeGossipSub:
		h.handleGossipSubMessage(msg.From, msg.Payload)
	default:
		if err := h.protocolRegistry.RouteMessage(msg); err != nil {
			logging.Global().Debug("Protocol routing failed", map[string]any{
				"msgType": msg.Type,
				"from":    msg.From,
				"error":   err.Error(),
			})
		}
	}
}

// handleMalformedMessage handles malformed messages
// Phase 1: tiered penalties — PenaltyManager replaces simple binary banning
// Returns true if the error was a real protocol violation (caller should
// also record a peer-score penalty), false for benign conditions like
// duplicate messages that are normal in gossip protocols.
func (h *Host) handleMalformedMessage(p PeerID, err error) bool {
	return h.handleMalformedMessageWithIP(p, "", err)
}

// handleMalformedMessageWithIP is the Sybil-resistant variant of handleMalformedMessage.
//
// When ip is non-empty, an escalation-triggered ban is written to all three
// layers (peer/IP/subnet). Callers that know peer.Addr, such as readLoop,
// should prefer this variant.
func (h *Host) handleMalformedMessageWithIP(p PeerID, ip string, err error) bool {
	// Duplicate messages are EXPECTED in gossip: the same block/vote/attestation
	// is relayed by multiple peers. Do NOT penalize — just debug-log and return.
	if errors.Is(err, ErrDuplicateMessage) {
		logging.Global().Debug("Duplicate message ignored (normal gossip behavior)", map[string]any{
			"peerID": string(p),
		})
		return false
	}

	level := h.penaltyManager.RecordViolationWithIP(p, ip, ViolationBadMessage)
	logging.Global().Warn("Malformed message received", map[string]any{
		"peerID": string(p),
		"addr":   ip,
		"level":  level.String(),
		"error":  err.Error(),
	})
	return true
}

func (h *Host) registerProtocols() {
	// Base protocol (qau) — message types 1-14
	h.protocolRegistry.Register(ProtocolSpec{
		Name:    ProtocolBase,
		Version: ProtocolBaseVersion,
		MsgTypes: map[uint8]bool{
			MsgTypeBlock: true, MsgTypeTransaction: true, MsgTypeVote: true,
			MsgTypeBlockReq: true, MsgTypeBlockResp: true,
			MsgTypeTxReq: true, MsgTypeTxResp: true,
			MsgTypeStatus: true, MsgTypePing: true, MsgTypePong: true,
			MsgTypeChallenge: true, MsgTypeChallengeResponse: true,
			MsgTypeBatch: true, MsgTypeProofOfWork: true,
			MsgTypeTxHashAnnounce: true,
			MsgTypeTxHashRequest:  true,
			MsgTypeTxHashResponse: true,
			MsgTypeCompactBlock:   true,
		},
		Handler: h.handleBaseProtocol,
	})

	// Discovery protocol (qau_discovery) — message types 15-19
	h.protocolRegistry.Register(ProtocolSpec{
		Name:    ProtocolDiscovery,
		Version: ProtocolDiscoveryVersion,
		MsgTypes: map[uint8]bool{
			MsgTypeFindNode: true, MsgTypeNeighbors: true, MsgTypeQNR: true,
		},
		Handler: h.handleDiscoveryProtocol,
	})

	// Consensus protocol (qau_consensus) — message types 20-29
	h.protocolRegistry.Register(ProtocolSpec{
		Name:    ProtocolConsensus,
		Version: ProtocolConsensusVersion,
		MsgTypes: map[uint8]bool{
			MsgTypeAttestation: true, MsgTypeAggregateAttest: true,
			MsgTypeProposerSlashing: true, MsgTypeAttesterSlashing: true,
			MsgTypeCheckpointSig: true, MsgTypeCheckpointReq: true,
			MsgTypeQTDSealRequest: true, MsgTypeQTDPartialSeal: true,
			// HIGH-01 (R18, 2026-07-23): completed QTD seal announcements
			MsgTypeQTDSealAnnouncement: true,
		},
		Handler: h.handleConsensusProtocol,
	})

	// Snap sync protocol (qau_snap) — message types 40-49 (+ receipts 63-64)
	// ETHEREUM-PARITY SYNC (2026-08-13): extended with snap storage/bytecode
	// (44-47), header-first skeleton sync (48-49) and receipts (63-64,
	// hosted here because the registry forbids duplicate protocol names).
	h.protocolRegistry.Register(ProtocolSpec{
		Name:    ProtocolSnapSync,
		Version: ProtocolSnapSyncVersion,
		MsgTypes: map[uint8]bool{
			MsgTypeSnapStateReq: true, MsgTypeSnapStateResp: true,
			MsgTypeSnapRangeReq: true, MsgTypeSnapRangeResp: true,
			MsgTypeSnapStorageReq: true, MsgTypeSnapStorageResp: true,
			MsgTypeSnapBytecodeReq: true, MsgTypeSnapBytecodeResp: true,
			MsgTypeHeaderReq: true, MsgTypeHeaderResp: true,
			MsgTypeReceiptReq: true, MsgTypeReceiptResp: true,
		},
		Handler: h.handleSnapProtocol,
	})

	// Expert protocol (qau_expert) — message types 30-39
	h.protocolRegistry.Register(ProtocolSpec{
		Name:    ProtocolExpert,
		Version: ProtocolExpertVersion,
		MsgTypes: map[uint8]bool{
			MsgTypeExpert: true,
		},
		Handler: h.handleExpertProtocol,
	})

	// TSS protocol (qau_tss) — message types 70-79
	// Distributed threshold signing for QTD finality.
	// All TSS messages carry the sender's PeerID via PeerMessage so the
	// node layer can route responses to the correct peer.
	// Task 5 (node-layer distributed DKG): MsgTypeTSSDKGCommitment (77) and
	// MsgTypeTSSDKGAck (78) are the distributed DKG round messages routed by
	// handleTSSMessage to the DKG coordinator's transport.
	h.protocolRegistry.Register(ProtocolSpec{
		Name:    ProtocolTSS,
		Version: ProtocolTSSVersion,
		MsgTypes: map[uint8]bool{
			MsgTypeTSSSessionInit:   true,
			MsgTypeTSSRound1Commit:  true,
			MsgTypeTSSRound2Reveal:  true,
			MsgTypeTSSRound2Private: true,
			MsgTypeTSSSignature:     true,
			MsgTypeTSSDKGShare:      true,
			MsgTypeTSSDKGCommitment: true,
			MsgTypeTSSDKGAck:        true,
		},
		Handler: h.handleTSSProtocol,
	})

	// DAS protocol (qau_das) — message types 50-53
	// P0-10 (2026-07-14): Data Availability Sampling protocol for exchanging
	// blob cell samples between DA committee members. Enables nodes to verify
	// that blob data is available without downloading entire blobs.
	// Request/response pattern: MsgTypeDASSampleReq (50) → MsgTypeDASSampleResp (51)
	h.protocolRegistry.Register(ProtocolSpec{
		Name:    ProtocolDAS,
		Version: ProtocolDASVersion,
		MsgTypes: map[uint8]bool{
			MsgTypeDASSampleReq:       true,
			MsgTypeDASSampleResp:      true,
			MsgTypeDASAttestation:     true,
			MsgTypeDASAggregateAttest: true,
		},
		Handler: h.handleDASProtocol,
	})

	// Shard protocol (qau_shard) — message types 80-85
	// P1-1 (2026-07-14): Shard block propagation, cross-shard message relay,
	// and finalization attestation channels. Without this protocol, shard
	// blocks and cross-shard messages only exist in a single node's memory.
	h.protocolRegistry.Register(ProtocolSpec{
		Name:    ProtocolShard,
		Version: ProtocolShardVersion,
		MsgTypes: map[uint8]bool{
			MsgTypeShardBlock:        true,
			MsgTypeShardBlockReq:     true,
			MsgTypeShardBlockResp:    true,
			MsgTypeShardAttestation:  true,
			MsgTypeCrossShardMsg:     true,
			MsgTypeCrossShardReceipt: true,
		},
		Handler: h.handleShardProtocol,
	})
}

func (h *Host) handleBaseProtocol(msg *Message) error {
	switch msg.Type {
	case MsgTypeBlock:
		if len(msg.Payload) < 32 || len(msg.Payload) > 10*1024*1024 {
			logging.Global().Warn("handleBaseProtocol: block payload size out of range", map[string]any{"from": msg.From, "size": len(msg.Payload)})
			return nil
		}
		select {
		case h.blockCh <- msg.Payload:
		case <-time.After(5 * time.Second):
			logging.Global().Warn("handleBaseProtocol: blockCh write timeout, dropping block", map[string]any{"from": msg.From})
		}
	case MsgTypeTransaction:
		// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): Per-peer tx rate limit.
		// Each tx triggers Dilithium3 signature verification (CPU-intensive).
		// Without this limit, a peer could use its entire 500 msg/sec global
		// budget on MsgTypeTransaction, saturating the verification pipeline.
		// The limit is checked BEFORE dedup so that even duplicate-tx flooding
		// (which is cheap for the sender but consumes dedup map memory) is
		// throttled. On violation, we drop the tx and record a violation; on
		// the 3rd violation within 1 minute, the peer is disconnected (same
		// escalation as the global rate limiter).
		if !h.txRateLimiter.Allow(msg.From) {
			hostLog.Warnf("tx rate limit exceeded for peer %s, dropping tx", msg.From)
			if h.txRateLimiter.RecordViolation(msg.From) {
				h.peersMu.Lock()
				if !h.isBootstrapPeer(msg.From) {
					// Look up the peer to get its address for IP/subnet banning
					// (P2P-C-02) and to call disconnectPeer which needs *Peer.
					if peer, exists := h.peers[msg.From]; exists {
						level := h.penaltyManager.RecordViolationWithIP(msg.From, peer.Addr, ViolationRateLimit)
						logging.Global().Warn("tx rate limit violation escalated, disconnecting peer",
							map[string]any{"peer": string(msg.From), "addr": peer.Addr, "level": level.String()})
						h.disconnectPeer(peer)
					} else {
						// Peer already disconnected or unknown — record violation
						// with empty address so the PeerID is still tracked.
						level := h.penaltyManager.RecordViolationWithIP(msg.From, "", ViolationRateLimit)
						logging.Global().Warn("tx rate limit violation for unknown peer",
							map[string]any{"peer": string(msg.From), "level": level.String()})
					}
				} else {
					logging.Global().Warn("tx rate limit exceeded for bootstrap peer, not disconnecting",
						map[string]any{"peer": string(msg.From)})
				}
				h.peersMu.Unlock()
			}
			return nil
		}
		// TPS FIX: Incoming dedup — prevent duplicate txs from flooding txCh.
		// When a tx is broadcast to N peers, each peer re-broadcasts to others,
		// causing the same tx to arrive up to N times. Without dedup, txCh
		// overflows and unique txs are silently dropped.
		if h.broadcaster == nil || h.broadcaster.MarkTxSeenIfNew(msg.Payload) {
			hostLog.Infof("Received tx from peer %s: size=%d", msg.From, len(msg.Payload))
			select {
			case h.txCh <- msg.Payload:
			default:
				hostLog.Warnf("txCh full, dropping incoming tx from peer %s", msg.From)
			}
		}
	case MsgTypeVote:
		select {
		case h.voteCh <- msg.Payload:
		default:
		}
	case MsgTypeStatus:
		// Auto-register validator address → PeerID mapping for TSS.
		// R37-FIX P2-P2P-01 (2026-07-30): only register after verifying the
		// peer's Dilithium3 signature over the status payload proves key
		// ownership. Without this, any peer can claim an arbitrary validator
		// address, hijacking TSS message routing.
		if status, err := DecodeStatusMessage(msg.Payload); err == nil {
			if status.ValidatorAddress != (types.Address{}) {
				verified := false
				if len(status.ValidatorPublicKey) > 0 && len(status.ValidatorSignature) > 0 && len(msg.Payload) >= 104 {
					if pubKey, err := crypto.PublicKeyFromBytes(status.ValidatorPublicKey); err == nil {
						basePayload := msg.Payload[:104]
						// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02): The V2
						// extension block (Timestamp + SessionNonce) is part of
						// the SIGNED DOMAIN. We verify against the EXTENDED
						// signed range when the V2 extension is present (i.e.
						// the trailing bytes include at least 4+24 bytes after
						// the signature). Without this extension binding, an
						// attacker could repackage a peer's signed base with a
						// bogus Timestamp/SessionNonce to defeat the freshness
						// + replay checks below.
						signedPayload := basePayload
						if status.Timestamp > 0 || status.SessionNonce != ([16]byte{}) {
							// Find the offset of the V2 extension's value bytes
							// (Timestamp||SessionNonce) by skipping the length-
							// prefixed pk and sig blocks. We mirror
							// DecodeStatusMessage's offset bookkeeping so the
							// signed range exactly matches what the V2 sender
							// signed: base[:104] || Timestamp[8] || Nonce[16].
							extStart, ok := findV2ExtensionValueOffset(msg.Payload)
							if ok && extStart+24 <= len(msg.Payload) {
								extended := make([]byte, 0, 104+24)
								extended = append(extended, basePayload...)
								extended = append(extended, msg.Payload[extStart:extStart+24]...)
								signedPayload = extended
							}
						}
						verified = pubKey.Verify(signedPayload, status.ValidatorSignature)
						// R38-P2-01 FIX (2026-08-02): The R37 check only proves
						// the peer holds the private key for ValidatorPublicKey.
						// It does NOT prove that ValidatorAddress belongs to
						// that key. Since ValidatorAddress is also inside the
						// signed base payload (offset 84:104), an attacker can
						// set ValidatorAddress = victimAddress, sign with its
						// own key, and overwrite the victim's PeerID mapping —
						// hijacking TSS message routing. Bind the address to
						// the signing key exactly like stake/unstake bindings.
						if verified && pubKey.Address() != status.ValidatorAddress {
							verified = false
						}
						// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02):
						// Active-set membership verification. When an
						// ActiveValidatorIdentityVerifier is configured (via
						// SetActiveValidatorIdentityVerifier) the host consults
						// it to confirm (address, pubkey) is in the chain's
						// current active validator set. Without this check, a
						// past-val / removed-from-active-set peer can still
						// claim its old validator address, polluting the
						// validator→PeerID routing table with stale entries.
						if verified && h.activeValidatorIdentityVerifier != nil {
							if err := h.activeValidatorIdentityVerifier.VerifyActiveValidator(status.ValidatorAddress, status.ValidatorPublicKey); err != nil {
								verified = false
								hostLog.Warnf("R38-P2-01 deep-fix: ActiveValidatorIdentityVerifier rejected (validator %x peer %s): %v",
									status.ValidatorAddress[:4], msg.From, err)
							}
						}
						// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02):
						// Clock-skew freshness window. When the V2 extension is
						// present (Timestamp > 0), the status MUST arrive within
						// +/- window ms of the host's wall clock. Without this
						// an attacker who replays a recorded status within the
						// 5-minute TLS-shared-secret rekey window can reset the
						// Address→PeerID mapping to point at themselves.
						if verified && status.Timestamp > 0 && h.statusFreshnessWindowSec > 0 {
							now := uint64(time.Now().Unix())
							delta := uint64(0)
							if now > status.Timestamp {
								delta = now - status.Timestamp
							} else {
								delta = status.Timestamp - now
							}
							if delta > h.statusFreshnessWindowSec {
								verified = false
								hostLog.Warnf("R38-P2-01 deep-fix: status timestamp outside freshness window (validator %x peer %s delta=%ds window=%ds)",
									status.ValidatorAddress[:4], msg.From, delta, h.statusFreshnessWindowSec)
							}
						}
						// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02):
						// Anti-replay check. When a SessionNonce is present we
						// register (ValidatorAddress, SenderPeerID, SessionNonce)
						// in h.sessionNonceTracker and reject the status if the
						// tuple has been seen before. Without this, an attacker
						// who records a status frame and replays it within the
						// freshness window (e.g., 60s drift) can hijack TSS
						// message routing.
						if verified && status.SessionNonce != ([16]byte{}) && h.sessionNonceTracker != nil {
							if h.sessionNonceTracker.Seen(status.ValidatorAddress, msg.From, status.SessionNonce) {
								verified = false
								hostLog.Warnf("R38-P2-01 deep-fix: status replay rejected (validator %x peer %s nonce %x)",
									status.ValidatorAddress[:4], msg.From, status.SessionNonce[:4])
							}
						}
					}
				}
				if verified {
					// AUDIT-FULL H-2 FIX (2026-08-14): use the trusted internal
					// registration path — the exported RegisterValidatorPeer is
					// capability-gated for arbitrary callers.
					h.registerValidatorPeer(status.ValidatorAddress, msg.From)
				} else {
					hostLog.Warnf("Rejecting unverified validator status from peer %s (address %x)",
						msg.From, status.ValidatorAddress[:4])
				}
			}
		}
		select {
		case h.statusCh <- PeerMessage{From: msg.From, Payload: msg.Payload}:
		default:
		}
	case MsgTypeBlockReq:
		select {
		case h.blockReqCh <- PeerMessage{From: msg.From, Payload: msg.Payload}:
		default:
		}
	case MsgTypeBlockResp:
		resp, err := DecodeBlockResponse(msg.Payload)
		if err != nil {
			return err
		}
		// SYNC-P2P-04 FIX (deep-audit 2026-07-12): bound the TOTAL time spent
		// enqueuing a single BlockResp so a slow blockCh drain cannot hold this
		// peer's readLoop hostage. Previously each block waited up to 30s and up
		// to ~500 blocks were iterated, so one response could block the reader
		// for minutes. We give the whole response a small budget; once it is
		// exhausted, remaining blocks are attempted non-blocking and otherwise
		// dropped (the syncer re-requests missing heights).
		respCtx, respCancel := context.WithTimeout(h.ctx, 2*time.Second)
		writtenCount := 0
		for _, blockData := range resp.Blocks {
			if len(blockData) < 32 || len(blockData) > 10*1024*1024 {
				logging.Global().Warn("handleBaseProtocol: blockData size out of range from BlockResp", map[string]any{"from": msg.From, "size": len(blockData)})
				continue
			}
			select {
			case h.blockCh <- blockData:
				writtenCount++
			case <-respCtx.Done():
				// Budget exhausted (or host shutting down): one last non-blocking
				// attempt, then drop. Subsequent iterations take this path too.
				select {
				case h.blockCh <- blockData:
					writtenCount++
				default:
				}
			}
		}
		respCancel()
		if writtenCount > 0 {
			logging.Global().Info("handleBaseProtocol: wrote blocks to blockCh", map[string]any{"count": writtenCount, "total": len(resp.Blocks), "from": msg.From, "blockChLen": len(h.blockCh)})
		}
	case MsgTypeBatch:
		batch, err := DecodeBatchMessage(msg.Payload)
		if err != nil {
			return err
		}
		for _, subMsg := range batch.Messages {
			if subMsg.Type == MsgTypeBatch {
				continue
			}
			if err := h.messageValidator.ValidateMessage(subMsg); err != nil {
				h.handleMalformedMessage(msg.From, err)
				continue
			}
			subMsg.From = msg.From
			h.routeMessage(subMsg)
		}
	case MsgTypeTxHashAnnounce:
		// TPS OPTIMIZATION: Compact tx propagation — received tx hashes.
		// Check which hashes we're missing and request full txs for those.
		if h.compactTx != nil {
			announce, err := DecodeTxHashAnnounce(msg.Payload)
			if err != nil {
				return err
			}
			missing := h.compactTx.HandleTxHashAnnounce(announce)
			if len(missing) > 0 {
				h.compactTx.RequestMissingTxs(msg.From, missing)
			}
		}
	case MsgTypeTxHashRequest:
		// TPS OPTIMIZATION: Peer requests full txs for given hashes.
		if h.compactTx != nil {
			req, err := DecodeTxHashRequest(msg.Payload)
			if err != nil {
				return err
			}
			resp := h.compactTx.HandleTxHashRequest(req)
			if resp != nil {
				respData := EncodeTxHashResponse(resp)
				msgData, err := EncodeMessage(MsgTypeTxHashResponse, respData)
				if err == nil {
					h.SendRaw(msg.From, msgData) //nolint:errcheck
				}
			}
		}
	case MsgTypeTxHashResponse:
		// TPS OPTIMIZATION: Received full txs for previously requested hashes.
		// Push to txCh for normal processing (same as receiving a full tx broadcast).
		if h.compactTx != nil {
			resp, err := DecodeTxHashResponse(msg.Payload)
			if err != nil {
				return err
			}
			txs := h.compactTx.HandleTxHashResponse(resp)
			for _, txData := range txs {
				// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): Apply the same
				// per-peer tx rate limit as MsgTypeTransaction. A peer could
				// otherwise pack many txs into a single TxHashResponse to
				// bypass the per-message rate limit. Each tx in the response
				// consumes one Allow() token, mirroring the per-tx accounting
				// of MsgTypeTransaction. If the limit is exceeded, the
				// remaining txs in this response are dropped (we don't
				// disconnect the peer mid-response to avoid partial-state
				// issues — the violation is recorded and the next message
				// from this peer will trigger disconnection if needed).
				if !h.txRateLimiter.Allow(msg.From) {
					hostLog.Warnf("tx rate limit exceeded for peer %s during TxHashResponse, dropping remaining %d txs", msg.From, len(txs))
					if h.txRateLimiter.RecordViolation(msg.From) {
						h.peersMu.Lock()
						if !h.isBootstrapPeer(msg.From) {
							if peer, exists := h.peers[msg.From]; exists {
								level := h.penaltyManager.RecordViolationWithIP(msg.From, peer.Addr, ViolationRateLimit)
								logging.Global().Warn("tx rate limit violation escalated during TxHashResponse, disconnecting peer",
									map[string]any{"peer": string(msg.From), "addr": peer.Addr, "level": level.String()})
								h.disconnectPeer(peer)
							}
						}
						h.peersMu.Unlock()
					}
					return nil
				}
				// Use same dedup + txCh path as MsgTypeTransaction
				if h.broadcaster == nil || h.broadcaster.MarkTxSeenIfNew(txData) {
					select {
					case h.txCh <- txData:
					default:
					}
				}
			}
		}
	case MsgTypeCompactBlock:
		// TPS OPTIMIZATION: Compact block — header + tx hashes.
		// Store in pending for potential reconstruction, but do NOT request
		// missing txs here. The full block broadcast will arrive shortly and
		// provide all txs directly, avoiding an extra request-response round trip.
		if h.compactBlock != nil {
			cb, err := DecodeCompactBlock(msg.Payload)
			if err != nil {
				return err
			}
			// Just store — the full block broadcast will handle processing
			h.compactBlock.HandleCompactBlock(cb)
		}
	case MsgTypePing:
		h.handlePing(msg)
	case MsgTypePong:
		h.handlePong(msg)
	}
	return nil
}

func (h *Host) handleDiscoveryProtocol(msg *Message) error {
	switch msg.Type {
	case MsgTypeFindNode:
		h.handleFindNode(msg)
	case MsgTypeNeighbors:
		h.handleNeighbors(msg)
	case MsgTypeQNR:
		h.handleQNR(msg)
	}
	return nil
}

func (h *Host) handleConsensusProtocol(msg *Message) error {
	switch msg.Type {
	case MsgTypeCheckpointSig, MsgTypeCheckpointReq:
		select {
		case h.checkpointCh <- msg.Payload:
		default:
			logging.Global().Warn("handleConsensusProtocol: checkpointCh full, dropping message",
				map[string]any{"type": msg.Type, "from": msg.From})
		}
	case MsgTypeQTDSealRequest, MsgTypeQTDPartialSeal:
		// P1-4: Route QTD partial seal messages to the dedicated channel.
		pm := PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}
		select {
		case h.qtdSealCh <- pm:
		default:
			logging.Global().Warn("handleConsensusProtocol: qtdSealCh full, dropping message",
				map[string]any{"type": msg.Type, "from": msg.From})
		}
	case MsgTypeQTDSealAnnouncement:
		// HIGH-01 (R18, 2026-07-23): Route QTD seal announcements to
		// the same channel as seal requests/partial seals. The node's
		// qtdSealProcessingLoop dispatches by message type.
		pm := PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}
		select {
		case h.qtdSealCh <- pm:
		default:
			logging.Global().Warn("handleConsensusProtocol: qtdSealCh full, dropping seal announcement",
				map[string]any{"type": msg.Type, "from": msg.From})
		}
	default:
		select {
		case h.voteCh <- msg.Payload:
		default:
		}
	}
	return nil
}

func (h *Host) handleSnapProtocol(msg *Message) error {
	switch msg.Type {
	case MsgTypeSnapStateReq, MsgTypeSnapRangeReq:
		select {
		case h.snapReqCh <- PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}:
		default:
		}
	// ETHEREUM-PARITY SYNC (2026-08-13): requests carry From+Type so the
	// snap server can reply to the requester; ALL responses (including the
	// legacy SnapStateResp/SnapRangeResp, which previously landed in
	// statusCh and were mis-parsed as status messages) are dispatched via
	// syncRespCh with their type so the syncer can route each to the right
	// handler (request IDs correlate async request/response pairs).
	case MsgTypeSnapStateResp, MsgTypeSnapRangeResp,
		MsgTypeSnapStorageResp, MsgTypeSnapBytecodeResp,
		MsgTypeHeaderResp, MsgTypeReceiptResp:
		select {
		case h.syncRespCh <- PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}:
		default:
		}
	case MsgTypeSnapStorageReq, MsgTypeSnapBytecodeReq,
		MsgTypeHeaderReq, MsgTypeReceiptReq:
		select {
		case h.snapReqCh <- PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}:
		default:
		}
	}
	return nil
}

func (h *Host) handleExpertProtocol(msg *Message) error {
	select {
	case h.expertCh <- msg.Payload:
	default:
	}
	return nil
}

// handleTSSProtocol routes TSS protocol messages to the tssCh channel.
// All TSS message types are forwarded with the sender's PeerID so the node
// layer can route responses (e.g., Round2 reveals) back to the correct peer.
func (h *Host) handleTSSProtocol(msg *Message) error {
	pm := PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}
	select {
	case h.tssCh <- pm:
	default:
		logging.Global().Warn("handleTSSProtocol: tssCh full, dropping message",
			map[string]any{"type": msg.Type, "from": msg.From})
	}
	return nil
}

// handleDASProtocol routes DAS protocol messages to the appropriate channel.
// P0-10 (2026-07-14):
//   - MsgTypeDASSampleReq (50) → dasReqCh (node layer handles and sends response)
//   - MsgTypeDASSampleResp (51) → dasPending[RequestID] (caller-specific pending channel)
//   - MsgTypeDASAttestation (52) → dasReqCh (treated as a request-like message for the node layer)
//   - MsgTypeDASAggregateAttest (53) → dasReqCh
//
// P1-12 (RPC-H1, 2026-07-19): Sample responses are routed via RequestID,
// not a shared broadcast channel. This closes the response-confusion
// vulnerability where a malicious peer could inject a forged response
// matched to the wrong request (or where concurrent samplers would
// steal each other's responses). If no pending channel is registered for
// the response's RequestID (e.g. the requester already timed out and
// unregistered, or the peer sent an unsolicited response), the message
// is dropped with a warning.
//
// Message size is validated to prevent DoS (fixed-size format expected).
func (h *Host) handleDASProtocol(msg *Message) error {
	// P0-10 DoS protection: validate message size before routing.
	// P1-12: DASSampleRequest is exactly 28 bytes (RequestID 8 + Slot 8 +
	// BlobIndex 4 + CellRow 4 + CellCol 4).
	// DASSampleResponse is exactly 28 + CellSize + 48 = DASSampleResponseSize.
	// DASAttestation and DASAggregateAttestation are variable but bounded.
	switch msg.Type {
	case MsgTypeDASSampleReq:
		if len(msg.Payload) != encoding.DASSampleRequestSize {
			logging.Global().Warn("handleDASProtocol: DASSampleReq wrong size",
				map[string]any{"from": msg.From, "size": len(msg.Payload), "expected": encoding.DASSampleRequestSize})
			return nil
		}
		select {
		case h.dasReqCh <- PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}:
		default:
			logging.Global().Warn("handleDASProtocol: dasReqCh full, dropping sample request",
				map[string]any{"from": msg.From})
		}
	case MsgTypeDASSampleResp:
		if len(msg.Payload) != encoding.DASSampleResponseSize {
			logging.Global().Warn("handleDASProtocol: DASSampleResp wrong size",
				map[string]any{"from": msg.From, "size": len(msg.Payload), "expected": encoding.DASSampleResponseSize})
			return nil
		}
		// P1-12 (RPC-H1): Dispatch by RequestID (first 8 bytes of payload)
		// to the per-request pending channel registered by SendSampleRequest.
		requestID := binary.BigEndian.Uint64(msg.Payload[0:8])
		h.dasPendingMu.Lock()
		ch, ok := h.dasPending[requestID]
		h.dasPendingMu.Unlock()
		if !ok {
			// No pending channel for this RequestID. Common causes:
			//  - Requester already timed out and unregistered
			//  - Late response arriving after the requester gave up
			//  - Peer sent an unsolicited response (potential abuse)
			// Drop silently — this is expected when timeouts occur.
			logging.Global().Debug("handleDASProtocol: DASSampleResp no pending channel",
				map[string]any{"from": msg.From, "requestID": requestID})
			return nil
		}
		select {
		case ch <- PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}:
		default:
			logging.Global().Warn("handleDASProtocol: pending channel full, dropping sample response",
				map[string]any{"from": msg.From, "requestID": requestID})
		}
	case MsgTypeDASAttestation, MsgTypeDASAggregateAttest:
		// Attestations are bounded at 10KB (well under MaxMsgSize)
		if len(msg.Payload) > 10*1024 {
			logging.Global().Warn("handleDASProtocol: attestation too large",
				map[string]any{"from": msg.From, "size": len(msg.Payload)})
			return nil
		}
		select {
		case h.dasReqCh <- PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}:
		default:
			logging.Global().Warn("handleDASProtocol: dasReqCh full, dropping attestation",
				map[string]any{"from": msg.From})
		}
	}
	return nil
}

// handleShardProtocol routes shard protocol messages to the appropriate channel.
// P1-1 (2026-07-14):
//   - MsgTypeShardBlock (80) → shardBlockCh (node layer validates + adds to chain)
//   - MsgTypeShardBlockReq (81) → shardBlockReqCh (node layer replies with block)
//   - MsgTypeShardBlockResp (82) → shardBlockRespCh (sync response)
//   - MsgTypeShardAttestation (83) → shardAttestationCh (node layer collects for quorum)
//   - MsgTypeCrossShardMsg (84) → crossShardMsgCh (node layer relays to dest shard)
//   - MsgTypeCrossShardReceipt (85) → crossShardReceiptCh (node layer marks relayed)
//
// Message size is validated by ValidateMessage() before routing. Non-blocking
// channel writes drop messages when the channel is full (prefer dropping over
// blocking the peer readLoop).
func (h *Host) handleShardProtocol(msg *Message) error {
	switch msg.Type {
	case MsgTypeShardBlock:
		select {
		case h.shardBlockCh <- msg.Payload:
		default:
			hostLog.Warnf("shardBlockCh full, dropping shard block from peer %s", msg.From)
		}
	case MsgTypeShardBlockReq:
		select {
		case h.shardBlockReqCh <- PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}:
		default:
			hostLog.Warnf("shardBlockReqCh full, dropping shard block request from peer %s", msg.From)
		}
	case MsgTypeShardBlockResp:
		select {
		case h.shardBlockRespCh <- PeerMessage{From: msg.From, Type: msg.Type, Payload: msg.Payload}:
		default:
			hostLog.Warnf("shardBlockRespCh full, dropping shard block response from peer %s", msg.From)
		}
	case MsgTypeShardAttestation:
		select {
		case h.shardAttestationCh <- msg.Payload:
		default:
			hostLog.Warnf("shardAttestationCh full, dropping shard attestation from peer %s", msg.From)
		}
	case MsgTypeCrossShardMsg:
		select {
		case h.crossShardMsgCh <- msg.Payload:
		default:
			hostLog.Warnf("crossShardMsgCh full, dropping cross-shard message from peer %s", msg.From)
		}
	case MsgTypeCrossShardReceipt:
		select {
		case h.crossShardReceiptCh <- msg.Payload:
		default:
			hostLog.Warnf("crossShardReceiptCh full, dropping cross-shard receipt from peer %s", msg.From)
		}
	}
	return nil
}

func (h *Host) handleQNR(msg *Message) {
	if h.discoverTable == nil {
		return
	}
	// P2P-R12-L01 (2026-07-20) defense-in-depth: explicitly cap payload size
	// before invoking the decoder. The message-validator framework already
	// rejects oversized QNR messages upstream, but a defense-in-depth size
	// check here ensures that even if a future code path bypasses the
	// validator (e.g., a new protocol handler that doesn't run validators),
	// the decoder won't be fed unbounded input.
	if len(msg.Payload) > MaxQNRMessageSize {
		logging.Global().Warn("handleQNR: payload exceeds MaxQNRMessageSize",
			map[string]any{"size": len(msg.Payload), "max": MaxQNRMessageSize})
		return
	}
	record, err := enode.DecodeRecord(msg.Payload)
	if err != nil {
		return
	}
	// SECURITY (audit P2P-11): Use record.ToNode() which:
	//  1. Verifies the ENR signature (prevents MITM tampering)
	//  2. Derives the node ID from the Dilithium3 public key (via DeriveID)
	// Previously this used HexToID(record.ID()) which treated the identity
	// scheme string (e.g. "v4") as a hex node ID — always failing silently.
	node, err := record.ToNode()
	if err != nil {
		return
	}
	h.discoverTable.AddNode(node)
}

func (h *Host) negotiateProtocols(peer *Peer) error {
	myProtocols := h.protocolRegistry.SupportedProtocols()
	negotiateMsg := &ProtocolNegotiateMessage{Protocols: myProtocols}
	payload, err := EncodeProtocolNegotiate(negotiateMsg)
	if err != nil {
		return fmt.Errorf("failed to encode protocol negotiate: %w", err)
	}

	encoded, err := EncodeMessage(MsgTypeProtocolNegotiate, payload)
	if err != nil {
		return fmt.Errorf("failed to encode protocol negotiate message: %w", err)
	}

	if _, err := peer.Conn.Write(encoded); err != nil {
		return fmt.Errorf("failed to send protocol negotiate: %w", err)
	}

	return nil
}

func (h *Host) handleProtocolNegotiate(msg *Message) {
	peerProtocols, err := DecodeProtocolNegotiate(msg.Payload)
	if err != nil {
		return
	}

	agreed := h.protocolRegistry.Negotiate(peerProtocols.Protocols)
	resp := &ProtocolNegotiateRespMessage{AgreedProtocols: agreed}
	payload, err := EncodeProtocolNegotiateResp(resp)
	if err != nil {
		return
	}

	encoded, err := EncodeMessage(MsgTypeProtocolNegotiateResp, payload)
	if err != nil {
		return
	}

	h.sendToPeer(msg.From, encoded)
}

func (h *Host) handleProtocolNegotiateResp(msg *Message) {
	resp, err := DecodeProtocolNegotiateResp(msg.Payload)
	if err != nil {
		return
	}

	h.peersMu.RLock()
	peer, ok := h.peers[msg.From]
	h.peersMu.RUnlock()

	if ok {
		peer.mu.Lock()
		peer.agreedProtocols = resp.AgreedProtocols
		peer.mu.Unlock()
	}
}

func (h *Host) handlePing(msg *Message) {
	pongMsg, err := EncodeMessage(MsgTypePong, msg.Payload)
	if err != nil {
		return
	}
	h.sendToPeer(msg.From, pongMsg)
}

func (h *Host) handlePong(msg *Message) {
	if h.discoverTable == nil {
		return
	}
	nodeID := h.peerIDToEnodeID(msg.From)
	h.discoverTable.UpdateNodeActivity(nodeID)
}

func (h *Host) handleFindNode(msg *Message) {
	if h.discoverTable == nil {
		return
	}
	if len(msg.Payload) != 32 {
		return
	}
	var target enode.ID
	copy(target[:], msg.Payload)

	closest := h.discoverTable.FindClosest(target, 16)

	neighborsPayload := encodeNeighbors(closest)
	// P2P-R12-L03 (2026-07-20) defense-in-depth: verify the encoded response
	// fits within MaxNeighborsMessageSize before sending. encodeNeighbors is
	// structurally bounded (2 + count*38, max 2+255*38 = 9692 bytes), so
	// under normal operation this check never trips. It exists so that a
	// future change to encodeNeighbors (e.g., adding QNR records inline)
	// cannot silently produce oversized responses that the receiver would
	// reject — fail-closed rather than waste bandwidth on a doomed send.
	if len(neighborsPayload) > MaxNeighborsMessageSize {
		// Truncate by re-encoding with fewer neighbors.
		maxCount := (MaxNeighborsMessageSize - 2) / 38
		if maxCount > len(closest) {
			maxCount = len(closest)
		}
		if maxCount > 255 {
			maxCount = 255
		}
		truncated := make([]*enode.Node, 0, maxCount)
		for i := 0; i < maxCount; i++ {
			truncated = append(truncated, closest[i])
		}
		neighborsPayload = encodeNeighbors(truncated)
		// Re-check after truncation — if still over, drop the response entirely.
		if len(neighborsPayload) > MaxNeighborsMessageSize {
			logging.Global().Warn("handleFindNode: response still oversized after truncation",
				map[string]any{"size": len(neighborsPayload), "max": MaxNeighborsMessageSize})
			return
		}
	}
	neighborsMsg, err := EncodeMessage(MsgTypeNeighbors, neighborsPayload)
	if err != nil {
		return
	}
	h.sendToPeer(msg.From, neighborsMsg)
}

func (h *Host) handleNeighbors(msg *Message) {
	if h.discoverTable == nil {
		return
	}
	// P2P-R12-L02 (2026-07-20) defense-in-depth: explicitly cap payload size
	// before invoking the decoder. The NeighborsValidator already rejects
	// oversized messages upstream, but a defense-in-depth check here
	// ensures the decoder is never fed unbounded input even if a future
	// code path bypasses the validator framework.
	if len(msg.Payload) > MaxNeighborsMessageSize {
		logging.Global().Warn("handleNeighbors: payload exceeds MaxNeighborsMessageSize",
			map[string]any{"size": len(msg.Payload), "max": MaxNeighborsMessageSize})
		return
	}
	nodes := decodeNeighbors(msg.Payload)
	// P2P-R12-L02 (2026-07-20): cap the number of AddNode calls per message
	// so a single Neighbors message cannot trigger unbounded discovery-table
	// insertions (each AddNode may do non-trivial work). 64 is a generous cap
	// above the standard 16-node response but well below the 255 decoder cap.
	const maxNodesPerMessage = 64
	if len(nodes) > maxNodesPerMessage {
		nodes = nodes[:maxNodesPerMessage]
	}
	for _, n := range nodes {
		peerID := h.enodeIDToPeerID(n.ID())
		if h.config.WhitelistOnly && !h.trustedPeers[peerID] {
			continue
		}
		h.discoverTable.AddNode(n)
	}
}

func (h *Host) sendToPeer(peerID PeerID, data []byte) {
	h.peersMu.RLock()
	peer, exists := h.peers[peerID]
	h.peersMu.RUnlock()
	if !exists || !peer.Connected {
		return
	}
	select {
	case peer.sendCh <- data:
	default:
	}
}

func (h *Host) buildQNRRecord() (*enode.Record, error) {
	r := enode.NewRecord()
	r.SetID("qnr-v1")
	r.SetPublicKey(h.nodeKeyPair.Public.Bytes())

	if h.listener != nil {
		addr := h.listener.Addr().String()
		host, portStr, err := net.SplitHostPort(addr)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil {
				r.SetIP(ip)
			}
			if port, err := strconv.Atoi(portStr); err == nil {
				r.SetTCP(port)
				r.SetUDP(port)
			}
		}
	}

	r.SetPoWNonce(h.powNonce)

	signedData := r.EncodeSignedData()
	sig, err := h.nodeKeyPair.Private.Sign(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign QNR: %w", err)
	}
	r.SetSignature(sig)

	return r, nil
}

func (h *Host) exchangeQNR(conn net.Conn, peerID PeerID) (*enode.Record, error) {
	ourQNR, err := h.buildQNRRecord()
	if err != nil {
		logging.Global().Error("exchangeQNR: failed to build QNR", map[string]any{"error": err.Error()})
		return nil, fmt.Errorf("failed to build QNR: %w", err)
	}

	qnrBytes, err := ourQNR.Encode()
	if err != nil {
		logging.Global().Error("exchangeQNR: failed to encode QNR", map[string]any{"error": err.Error()})
		return nil, fmt.Errorf("failed to encode QNR: %w", err)
	}

	qnrMsg, err := EncodeMessage(MsgTypeQNR, qnrBytes)
	if err != nil {
		logging.Global().Error("exchangeQNR: failed to encode QNR message", map[string]any{"error": err.Error()})
		return nil, fmt.Errorf("failed to encode QNR message: %w", err)
	}

	if _, err := conn.Write(qnrMsg); err != nil {
		logging.Global().Error("exchangeQNR: failed to send QNR", map[string]any{"error": err.Error()})
		return nil, fmt.Errorf("failed to send QNR: %w", err)
	}

	peerQNRMsg, err := readHandshakeMessage(conn)
	if err != nil {
		logging.Global().Error("exchangeQNR: failed to read peer QNR", map[string]any{"error": err.Error()})
		return nil, fmt.Errorf("failed to read peer QNR: %w", err)
	}

	if peerQNRMsg.Type != MsgTypeQNR {
		logging.Global().Error("exchangeQNR: unexpected message type", map[string]any{"expected": MsgTypeQNR, "got": peerQNRMsg.Type})
		return nil, fmt.Errorf("expected QNR message, got type %d", peerQNRMsg.Type)
	}

	peerQNR, err := enode.DecodeRecord(peerQNRMsg.Payload)
	if err != nil {
		logging.Global().Error("exchangeQNR: failed to decode peer QNR", map[string]any{"error": err.Error()})
		return nil, fmt.Errorf("failed to decode peer QNR: %w", err)
	}

	if err := peerQNR.VerifySignature(); err != nil {
		logging.Global().Error("exchangeQNR: peer QNR signature invalid", map[string]any{"error": err.Error()})
		return nil, fmt.Errorf("peer QNR signature invalid: %w", err)
	}

	peerPubKey := peerQNR.PublicKey()
	if peerPubKey == nil {
		logging.Global().Error("exchangeQNR: peer QNR missing public key")
		return nil, fmt.Errorf("peer QNR missing public key")
	}

	pubHasher := sha3.New256()
	pubHasher.Write(peerPubKey)
	expectedPeerID := PeerID(hex.EncodeToString(pubHasher.Sum(nil)))
	if expectedPeerID != peerID {
		logging.Global().Error("exchangeQNR: public key mismatch", map[string]any{
			"expected": expectedPeerID,
			"got":      peerID,
		})
		return nil, fmt.Errorf("QNR public key does not match peer ID")
	}

	return peerQNR, nil
}

func (h *Host) peerIDToEnodeID(peerID PeerID) enode.ID {
	idBytes, err := hex.DecodeString(string(peerID))
	if err != nil || len(idBytes) < 32 {
		var empty enode.ID
		return empty
	}
	var id enode.ID
	copy(id[:], idBytes[:32])
	return id
}

func (h *Host) enodeIDToPeerID(id enode.ID) PeerID {
	return PeerID(hex.EncodeToString(id[:]))
}

func (h *Host) performProtocolNegotiation(conn net.Conn, peerID PeerID) error {
	myProtocols := h.protocolRegistry.SupportedProtocols()
	negotiateMsg := &ProtocolNegotiateMessage{Protocols: myProtocols}
	payload, err := EncodeProtocolNegotiate(negotiateMsg)
	if err != nil {
		return fmt.Errorf("failed to encode protocol negotiate: %w", err)
	}

	encoded, err := EncodeMessage(MsgTypeProtocolNegotiate, payload)
	if err != nil {
		return fmt.Errorf("failed to encode protocol negotiate message: %w", err)
	}

	if _, err := conn.Write(encoded); err != nil {
		return fmt.Errorf("failed to send protocol negotiate: %w", err)
	}

	respMsg, err := readHandshakeMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read protocol negotiate response: %w", err)
	}

	if respMsg.Type != MsgTypeProtocolNegotiateResp {
		return fmt.Errorf("expected protocol negotiate response type %d, got %d", MsgTypeProtocolNegotiateResp, respMsg.Type)
	}

	resp, err := DecodeProtocolNegotiateResp(respMsg.Payload)
	if err != nil {
		return fmt.Errorf("failed to decode protocol negotiate response: %w", err)
	}

	h.peersMu.RLock()
	peer, ok := h.peers[peerID]
	h.peersMu.RUnlock()

	if ok {
		peer.mu.Lock()
		peer.agreedProtocols = resp.AgreedProtocols
		peer.mu.Unlock()
	}

	logging.Global().Debug("Protocol negotiation completed", map[string]any{
		"peer":            peerID,
		"agreedProtocols": len(resp.AgreedProtocols),
	})

	return nil
}

func (h *Host) respondProtocolNegotiation(conn net.Conn, peerID PeerID) error {
	reqMsg, err := readHandshakeMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read protocol negotiate request: %w", err)
	}

	if reqMsg.Type != MsgTypeProtocolNegotiate {
		return fmt.Errorf("expected protocol negotiate type %d, got %d", MsgTypeProtocolNegotiate, reqMsg.Type)
	}

	peerProtocols, err := DecodeProtocolNegotiate(reqMsg.Payload)
	if err != nil {
		return fmt.Errorf("failed to decode peer protocols: %w", err)
	}

	agreed := h.protocolRegistry.Negotiate(peerProtocols.Protocols)
	resp := &ProtocolNegotiateRespMessage{AgreedProtocols: agreed}
	payload, err := EncodeProtocolNegotiateResp(resp)
	if err != nil {
		return fmt.Errorf("failed to encode protocol negotiate response: %w", err)
	}

	encoded, err := EncodeMessage(MsgTypeProtocolNegotiateResp, payload)
	if err != nil {
		return fmt.Errorf("failed to encode protocol negotiate response message: %w", err)
	}

	if _, err := conn.Write(encoded); err != nil {
		return fmt.Errorf("failed to send protocol negotiate response: %w", err)
	}

	h.peersMu.RLock()
	peer, ok := h.peers[peerID]
	h.peersMu.RUnlock()

	if ok {
		peer.mu.Lock()
		peer.agreedProtocols = agreed
		peer.mu.Unlock()
	}

	logging.Global().Debug("Protocol negotiation responded", map[string]any{
		"peer":            peerID,
		"agreedProtocols": len(agreed),
	})

	return nil
}

func encodeNeighbors(nodes []*enode.Node) []byte {
	var ipv4Nodes []*enode.Node
	for _, n := range nodes {
		if n.IP() != nil && n.IP().To4() != nil {
			ipv4Nodes = append(ipv4Nodes, n)
		}
	}
	count := uint16(len(ipv4Nodes))
	if count > 255 {
		count = 255
	}
	buf := make([]byte, 2+int(count)*38)
	binary.BigEndian.PutUint16(buf[:2], count)
	offset := 2
	for i := uint16(0); i < count; i++ {
		n := ipv4Nodes[i]
		copy(buf[offset:offset+32], n.ID().Bytes())
		ip4 := n.IP().To4()
		copy(buf[offset+32:offset+36], ip4)
		binary.BigEndian.PutUint16(buf[offset+36:offset+38], uint16(n.TCP()))
		offset += 38
	}
	return buf
}

func decodeNeighbors(data []byte) []*enode.Node {
	if len(data) < 2 {
		return nil
	}
	count := binary.BigEndian.Uint16(data[:2])
	if count > 255 {
		count = 255
	}
	nodes := make([]*enode.Node, 0, count)
	offset := 2
	for i := uint16(0); i < count && offset+38 <= len(data); i++ {
		var id enode.ID
		copy(id[:], data[offset:offset+32])
		ip := net.IPv4(data[offset+32], data[offset+33], data[offset+34], data[offset+35])
		port := int(binary.BigEndian.Uint16(data[offset+36 : offset+38]))
		n := enode.NewNode(id, ip, port, port)
		nodes = append(nodes, n)
		offset += 38
	}
	return nodes
}

// connectBootstrapPeers connects to bootstrap peers and persisted known nodes.
// This follows Ethereum's pattern: first connect bootnodes, then try persisted peers from nodedb.
func (h *Host) connectBootstrapPeers() {
	// P2P-R16-M09 (2026-07-23) FIX: Panic recovery so a bootstrap connection
	// bug (e.g., nil pointer in enode.ParseV4, panic in h.Connect) cannot
	// crash the node during startup. Without this, the node would be left
	// isolated with no bootstrap connections and no reconnect loop (which is
	// launched at the end of this function). Matches the recover pattern used
	// by acceptLoop, readLoop, reconnectLoop, and all other P2P goroutines.
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("connectBootstrapPeers panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()

	// Phase 1: Connect to configured bootstrap peers
	for _, addr := range h.config.BootstrapPeers {
		address := addr
		expectedID := PeerID("")
		if strings.HasPrefix(addr, "enode://") {
			if node, err := enode.ParseV4(addr); err == nil {
				address = fmt.Sprintf("%s:%d", node.IP().String(), node.TCP())
				expectedID = h.enodeIDToPeerID(node.ID())
				logging.Global().Info("Connecting to bootstrap peer", map[string]any{
					"enode": addr,
					"dial":  address,
				})
			} else {
				logging.Global().Warn("Failed to parse bootstrap peer enode URL", map[string]any{
					"address": addr,
					"error":   err.Error(),
				})
			}
		}
		ctx, cancel := context.WithTimeout(h.ctx, 30*time.Second)
		var err error
		if expectedID != "" {
			err = h.ConnectVerified(ctx, address, expectedID)
		} else {
			err = h.Connect(ctx, address)
		}
		if err != nil {
			logging.Global().Warn("Failed to connect to bootstrap peer", map[string]any{
				"address": address,
				"error":   err.Error(),
			})
		} else {
			logging.Global().Info("Connected to bootstrap peer", map[string]any{
				"address": address,
			})
		}
		cancel()
	}

	// Phase 2: Try to connect to persisted known nodes from discovery table.
	// Like Ethereum, we load previously discovered nodes from disk and attempt
	// connections. This allows nodes to find each other even if bootnodes are down.
	if h.discoverTable != nil {
		knownNodes := h.discoverTable.ReadRandomNodes(10)
		connected := 0
		for _, node := range knownNodes {
			if node == nil {
				continue
			}
			addr := fmt.Sprintf("%s:%d", node.IP().String(), node.TCP())
			ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
			if err := h.Connect(ctx, addr); err != nil {
				logging.Global().Debug("Failed to connect to persisted node", map[string]any{
					"address": addr,
					"error":   err.Error(),
				})
			} else {
				connected++
				logging.Global().Info("Connected to persisted node", map[string]any{
					"address": addr,
				})
			}
			cancel()
		}
		if len(knownNodes) > 0 {
			logging.Global().Info("Persisted node connection summary", map[string]any{
				"attempted": len(knownNodes),
				"connected": connected,
			})
		}
	}

	// Start background reconnection loop
	go h.reconnectLoop()
}

// reconnectLoop periodically tries to reconnect to bootstrap peers
func (h *Host) reconnectLoop() {
	// P2P-R16-CRIT-002 (2026-07-22) FIX: Panic recovery so a reconnection
	// bug cannot silently halt this loop (bootstrap reconnection stops →
	// disconnected node cannot recover).
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("reconnectLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.tryReconnectBootstrapPeers() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		}
	}
}

// outboundMaintenanceLoop periodically ensures the node maintains a minimum
// number/ratio of outbound (self-dialed) connections, mitigating eclipse attacks.
//
// P2P-R28-H01 FIX (2026-07-25): Previously ConnPoolConfig.MinOutboundConns
// and MinOutboundRatio were defined but NEVER enforced — the Host had no
// loop that proactively dialed new peers when the outbound count dropped
// below the minimum. An attacker could:
//  1. Open MaxPeers inbound connections to fill the peer table.
//  2. The MaxInboundPeers cap (MaxPeers*2/3) limits inbound, but the
//     remaining 1/3 was never proactively filled by outbound dials.
//  3. Over time, natural peer churn could reduce the outbound count to 0,
//     leaving the node dependent entirely on inbound connections from
//     attacker-controlled peers.
//
// This loop runs every 30s and:
//  1. Counts current outbound peers.
//  2. If below MinOutboundConns OR below MinOutboundRatio, dials random
//     discovered nodes from the DHT to restore the minimum.
//  3. Skips if discovery is disabled (no nodes to dial) or context is done.
//
// The loop is conservative: it dials at most 3 nodes per tick to avoid
// connection storms, and uses short timeouts so a slow peer doesn't block
// the loop.
func (h *Host) outboundMaintenanceLoop() {
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("outboundMaintenanceLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.ensureMinOutboundConnections()
		}
	}
}

// ensureMinOutboundConnections checks the current outbound peer count and
// dials random discovered nodes if below the configured minimum.
//
// P2P-R28-H01: Extracted from outboundMaintenanceLoop for testability.
// Returns the number of dial attempts made.
func (h *Host) ensureMinOutboundConnections() int {
	// Defaults match DefaultConnPoolConfig: 3 outbound, 0.3 ratio.
	minOutbound := 3
	minRatio := 0.3
	if h.config.ConnPool != nil {
		if h.config.ConnPool.MinOutboundConns > 0 {
			minOutbound = h.config.ConnPool.MinOutboundConns
		}
		if h.config.ConnPool.MinOutboundRatio > 0 {
			minRatio = h.config.ConnPool.MinOutboundRatio
		}
	}

	// Count outbound peers under lock, then release before dialing.
	h.peersMu.Lock()
	totalPeers := 0
	outboundPeers := 0
	for _, p := range h.peers {
		// Skip placeholders (not yet connected).
		if !p.Connected {
			continue
		}
		totalPeers++
		if p.Direction == DirOutbound {
			outboundPeers++
		}
	}
	h.peersMu.Unlock()

	// Determine the deficit.
	// Required = max(minOutbound, ceil(minRatio * totalPeers)).
	// The max() ensures we always have at least minOutbound outbound peers,
	// even if totalPeers is small (e.g., startup).
	required := minOutbound
	if totalPeers > 0 {
		ratioRequired := int(math.Ceil(minRatio * float64(totalPeers)))
		if ratioRequired > required {
			required = ratioRequired
		}
	}
	if outboundPeers >= required {
		return 0
	}
	deficit := required - outboundPeers
	// Cap dial attempts per tick to avoid connection storms.
	if deficit > 3 {
		deficit = 3
	}

	// Need discovered nodes to dial. If discovery is disabled, we cannot
	// maintain outbound connections beyond bootstrap peers (handled by
	// reconnectLoop). Log once and return.
	if h.discoverTable == nil {
		logging.Global().Debug("outboundMaintenance: discovery disabled, cannot dial new peers",
			map[string]any{
				"outbound": outboundPeers,
				"required": required,
			})
		return 0
	}

	// Read random nodes from the DHT. Request more than the deficit to
	// allow for nodes that are already connected or unreachable.
	readCount := deficit * 3
	if readCount < 10 {
		readCount = 10
	}
	candidates := h.discoverTable.ReadRandomNodes(readCount)
	if len(candidates) == 0 {
		return 0
	}

	// Build a set of already-connected peer addresses (under lock) to
	// skip them during dialing.
	h.peersMu.Lock()
	connectedAddrs := make(map[string]bool, len(h.peers))
	for _, p := range h.peers {
		if host, _, err := net.SplitHostPort(p.Addr); err == nil {
			connectedAddrs[host] = true
		}
	}
	h.peersMu.Unlock()

	attempts := 0
	for _, node := range candidates {
		if attempts >= deficit {
			break
		}
		if node == nil {
			continue
		}
		nodeIP := node.IP().String()
		if connectedAddrs[nodeIP] {
			continue
		}
		addr := fmt.Sprintf("%s:%d", nodeIP, node.TCP())
		ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
		if err := h.Connect(ctx, addr); err != nil {
			logging.Global().Debug("outboundMaintenance: dial failed",
				map[string]any{
					"address": addr,
					"error":   err.Error(),
				})
		} else {
			logging.Global().Info("outboundMaintenance: dialed new outbound peer",
				map[string]any{
					"address":  addr,
					"outbound": outboundPeers + attempts + 1,
					"required": required,
				})
		}
		cancel()
		attempts++
	}
	return attempts
}

// tryReconnectBootstrapPeers attempts to reconnect to bootstrap peers if not connected
// CRITICAL FIX R14: Don't hold peersMu during Connect() call to prevent deadlock.
// Connect() -> handleConnection() also needs peersMu, so we must release our lock
// before calling Connect(). This eliminates the deadlock but introduces a small
// race window where multiple goroutines might attempt the same connection -
// this is acceptable as Connect will handle duplicates gracefully.
func (h *Host) tryReconnectBootstrapPeers() error {
	// First pass: determine which addresses need connection attempts (under lock)
	h.peersMu.Lock()
	var addrsToConnect []string
	for _, addr := range h.config.BootstrapPeers {
		alreadyConnected := false
		targetHost := ""
		if strings.HasPrefix(addr, "enode://") {
			if node, err := enode.ParseV4(addr); err == nil {
				targetHost = node.IP().String()
			}
		} else {
			targetHost, _, _ = net.SplitHostPort(addr)
		}
		for _, peer := range h.peers {
			peerHost, _, _ := net.SplitHostPort(peer.Addr)
			if peerHost == targetHost {
				alreadyConnected = true
				break
			}
			if (peerHost == "127.0.0.1" || peerHost == "localhost") &&
				(targetHost == "127.0.0.1" || targetHost == "localhost") {
				alreadyConnected = true
				break
			}
		}
		if !alreadyConnected {
			addrsToConnect = append(addrsToConnect, addr)
		}
	}
	h.peersMu.Unlock()

	// Second pass: attempt connections without holding the lock
	// This prevents deadlock since Connect() -> handleConnection() needs peersMu too
	var lastErr error
	for _, addr := range addrsToConnect {
		dialAddr := addr
		expectedID := PeerID("")
		if strings.HasPrefix(addr, "enode://") {
			if node, err := enode.ParseV4(addr); err == nil {
				dialAddr = fmt.Sprintf("%s:%d", node.IP().String(), node.TCP())
				expectedID = h.enodeIDToPeerID(node.ID())
			} else {
				logging.Global().Warn("Failed to parse bootstrap peer enode URL for reconnection", map[string]any{
					"address": addr,
					"error":   err.Error(),
				})
				lastErr = err
				continue
			}
		}
		ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
		var err error
		if expectedID != "" {
			err = h.ConnectVerified(ctx, dialAddr, expectedID)
		} else {
			err = h.Connect(ctx, dialAddr)
		}
		if err != nil {
			logging.Global().Warn("Failed to reconnect to bootstrap peer", map[string]any{
				"address": addr,
				"error":   err.Error(),
			})
			lastErr = err
		} else {
			logging.Global().Info("Reconnected to bootstrap peer", map[string]any{
				"address": addr,
			})
		}
		cancel()
	}
	return lastErr
}

// SubscribeBlocks returns a channel for receiving blocks
func (h *Host) SubscribeBlocks() <-chan []byte {
	return h.blockCh
}

// SubscribeBlockRequests returns a channel for receiving block requests.
// audit-fix R2-M4: carries PeerID so the handler can reply to the requester.
func (h *Host) SubscribeBlockRequests() <-chan PeerMessage {
	return h.blockReqCh
}

// SubscribeTransactions returns a channel for receiving transactions
func (h *Host) SubscribeTransactions() <-chan []byte {
	return h.txCh
}

// SubscribeVotes returns a channel for receiving votes
func (h *Host) SubscribeVotes() <-chan []byte {
	return h.voteCh
}

// SubscribeStatus returns a channel for receiving status messages
func (h *Host) SubscribeStatus() <-chan PeerMessage {
	return h.statusCh
}

// SubscribeExpert returns a channel for receiving expert network messages
func (h *Host) SubscribeExpert() <-chan []byte {
	return h.expertCh
}

// SubscribeSnapSync returns a channel for receiving snap sync messages
func (h *Host) SubscribeSnapSync() <-chan []byte {
	return h.snapCh
}

// SubscribeSnapRequests returns a channel for receiving snap sync requests
func (h *Host) SubscribeSnapRequests() <-chan PeerMessage {
	return h.snapReqCh
}

// SubscribeSyncResponses returns a channel for receiving extended sync
// protocol responses (snap storage/bytecode, headers, receipts).
// ETHEREUM-PARITY SYNC (2026-08-13).
func (h *Host) SubscribeSyncResponses() <-chan PeerMessage {
	return h.syncRespCh
}

// SubscribeCheckpoint returns a channel for receiving checkpoint signature/request messages
func (h *Host) SubscribeCheckpoint() <-chan []byte {
	return h.checkpointCh
}

// SubscribeTSS returns a channel for receiving TSS (threshold signature) messages.
// Each message includes the sender's PeerID so the node layer can route responses.
func (h *Host) SubscribeTSS() <-chan PeerMessage {
	return h.tssCh
}

// SubscribeQTDSeal returns a channel for receiving QTD partial seal messages.
// P1-4: Used by the node's qtdProcessingLoop to handle incoming partial seals.
func (h *Host) SubscribeQTDSeal() <-chan PeerMessage {
	return h.qtdSealCh
}

// SubscribeDASRequests returns a channel for receiving incoming DAS messages.
// P0-10 (2026-07-14): Used by the node's DAS handler to process incoming
// sample requests (and reply with cells) and incoming attestations.
// Each message carries the sender's PeerID via PeerMessage.
func (h *Host) SubscribeDASRequests() <-chan PeerMessage {
	return h.dasReqCh
}

// RegisterDASResponseChannel registers a pending channel for a DAS sample
// response with the given RequestID.
// P1-12 (RPC-H1, 2026-07-19): Replaces the deprecated shared
// SubscribeDASResponses() channel. SendSampleRequest calls this before
// sending the request so that handleDASProtocol can route the response
// by RequestID instead of broadcasting to a single shared channel.
//
// Returns the channel that will receive at most one PeerMessage (the
// response). The caller MUST call UnregisterDASResponseChannel when done
// (either after receiving a response or after timing out) to prevent
// the map from growing unboundedly.
//
// If a channel is already registered for requestID (extremely unlikely
// given uint64 space), the existing channel is overwritten — the prior
// caller will simply time out and unregister. This is acceptable for
// an error path that should never occur in practice.
func (h *Host) RegisterDASResponseChannel(requestID uint64) chan PeerMessage {
	ch := make(chan PeerMessage, 1)
	h.dasPendingMu.Lock()
	h.dasPending[requestID] = ch
	h.dasPendingMu.Unlock()
	return ch
}

// UnregisterDASResponseChannel removes the pending channel for the given
// RequestID. Safe to call multiple times and after the channel has already
// been consumed. P1-12 (RPC-H1, 2026-07-19).
func (h *Host) UnregisterDASResponseChannel(requestID uint64) {
	h.dasPendingMu.Lock()
	delete(h.dasPending, requestID)
	h.dasPendingMu.Unlock()
}

// SendDASSampleRequest sends a DAS sample request to a specific peer.
// P0-10 (2026-07-14)
func (h *Host) SendDASSampleRequest(peerID PeerID, data []byte) error {
	msg, err := EncodeMessage(MsgTypeDASSampleReq, data)
	if err != nil {
		return err
	}
	return h.SendRaw(peerID, msg)
}

// SendDASSampleResponse sends a DAS sample response to a specific peer.
// P0-10 (2026-07-14)
func (h *Host) SendDASSampleResponse(peerID PeerID, data []byte) error {
	msg, err := EncodeMessage(MsgTypeDASSampleResp, data)
	if err != nil {
		return err
	}
	return h.SendRaw(peerID, msg)
}

// BroadcastDASAttestation broadcasts a DAS attestation to all peers.
// P0-10 (2026-07-14)
func (h *Host) BroadcastDASAttestation(data []byte) error {
	return h.broadcast(MsgTypeDASAttestation, data)
}

// BroadcastDASAggregateAttestation broadcasts an aggregate DAS attestation.
// P0-10 (2026-07-14)
func (h *Host) BroadcastDASAggregateAttestation(data []byte) error {
	return h.broadcast(MsgTypeDASAggregateAttest, data)
}

// --- Shard protocol P2P API (P1-1) ---

// BroadcastShardBlock broadcasts a shard block to all peers.
// P1-1 (2026-07-14): Called by the shard proposer after ProposeBlock.
func (h *Host) BroadcastShardBlock(data []byte) error {
	return h.broadcast(MsgTypeShardBlock, data)
}

// BroadcastShardAttestation broadcasts a shard block finalization attestation.
// P1-1 (2026-07-14): Called by validators who agree to finalize a shard block.
func (h *Host) BroadcastShardAttestation(data []byte) error {
	return h.broadcast(MsgTypeShardAttestation, data)
}

// BroadcastCrossShardMessage broadcasts a cross-shard message to all peers.
// P1-1 (2026-07-14): Called by the source shard to relay a message to the
// destination shard's validator set.
func (h *Host) BroadcastCrossShardMessage(data []byte) error {
	return h.broadcast(MsgTypeCrossShardMsg, data)
}

// BroadcastCrossShardReceipt broadcasts a cross-shard receipt.
// P1-1 (2026-07-14): Called by the destination shard to confirm message relay.
func (h *Host) BroadcastCrossShardReceipt(data []byte) error {
	return h.broadcast(MsgTypeCrossShardReceipt, data)
}

// SendShardBlockRequest sends a shard block request to a specific peer.
// P1-1 (2026-07-14): Used for shard chain sync (request by shardID + height).
func (h *Host) SendShardBlockRequest(peerID PeerID, data []byte) error {
	msg, err := EncodeMessage(MsgTypeShardBlockReq, data)
	if err != nil {
		return err
	}
	return h.SendRaw(peerID, msg)
}

// SendShardBlockResponse sends a shard block response to a specific peer.
// P1-1 (2026-07-14): Reply to a shard block request with the requested block.
func (h *Host) SendShardBlockResponse(peerID PeerID, data []byte) error {
	msg, err := EncodeMessage(MsgTypeShardBlockResp, data)
	if err != nil {
		return err
	}
	return h.SendRaw(peerID, msg)
}

// SubscribeShardBlocks returns a channel for receiving shard block broadcasts.
// P1-1 (2026-07-14)
func (h *Host) SubscribeShardBlocks() <-chan []byte {
	return h.shardBlockCh
}

// SubscribeShardBlockRequests returns a channel for receiving shard block requests.
// P1-1 (2026-07-14): Each message carries the sender's PeerID for reply.
func (h *Host) SubscribeShardBlockRequests() <-chan PeerMessage {
	return h.shardBlockReqCh
}

// SubscribeShardBlockResponses returns a channel for receiving shard block responses.
// P1-1 (2026-07-14): Used by the sync layer to read responses to block requests.
func (h *Host) SubscribeShardBlockResponses() <-chan PeerMessage {
	return h.shardBlockRespCh
}

// SubscribeShardAttestations returns a channel for receiving shard attestations.
// P1-1 (2026-07-14): The node layer collects these for quorum finalization.
func (h *Host) SubscribeShardAttestations() <-chan []byte {
	return h.shardAttestationCh
}

// SubscribeCrossShardMessages returns a channel for receiving cross-shard messages.
// P1-1 (2026-07-14): The node layer relays these to the destination shard.
func (h *Host) SubscribeCrossShardMessages() <-chan []byte {
	return h.crossShardMsgCh
}

// SubscribeCrossShardReceipts returns a channel for receiving cross-shard receipts.
// P1-1 (2026-07-14): The node layer marks messages as relayed upon receipt.
func (h *Host) SubscribeCrossShardReceipts() <-chan []byte {
	return h.crossShardReceiptCh
}

// BroadcastQTDPartialSeal broadcasts a QTD partial seal to all peers.
// P1-4: Called by executive chamber members to distribute their partial seal.
func (h *Host) BroadcastQTDPartialSeal(data []byte) error {
	return h.broadcast(MsgTypeQTDPartialSeal, data)
}

// BroadcastQTDSealRequest broadcasts a QTD seal request to all peers.
// P1-4: Called by the block producer to request partial seals from executive members.
func (h *Host) BroadcastQTDSealRequest(data []byte) error {
	return h.broadcast(MsgTypeQTDSealRequest, data)
}

// BroadcastQTDSealAnnouncement broadcasts a completed QTD seal to all peers.
// HIGH-01 (R18, 2026-07-23): called by the block producer after the QTD
// seal is completed, so syncing nodes can attach the seal to their copy
// of the block (which they received bare, without the seal).
func (h *Host) BroadcastQTDSealAnnouncement(data []byte) error {
	return h.broadcast(MsgTypeQTDSealAnnouncement, data)
}

// BroadcastBlock broadcasts a block to all peers
func (h *Host) BroadcastBlock(ctx context.Context, data []byte) error {
	return h.broadcast(MsgTypeBlock, data)
}

// BroadcastTransaction broadcasts a transaction to all peers.
// TPS FIX: Instead of broadcasting each tx individually (which floods sendCh
// and causes silent drops during high-throughput bursts), txs are pushed to
// txBatchCh. A background goroutine (txBatchLoop) collects them and broadcasts
// in batches of up to 100 txs per P2P message, reducing message count by ~100x.
func (h *Host) BroadcastTransaction(ctx context.Context, data []byte) error {
	select {
	case h.txBatchCh <- data:
		return nil
	default:
		// Fallback: if batch channel is full, broadcast directly
		return h.broadcast(MsgTypeTransaction, data)
	}
}

// txBatchLoop collects transactions from txBatchCh and broadcasts them in
// batches to reduce P2P message count. Mimics Ethereum's tx batch broadcast
// (maxTxPacketSize = 100KB, ~400 txs per batch).
//
// Flush conditions:
//   - 100 txs collected (immediate flush, ~535KB per batch, well within 2MB limit)
//   - 10ms elapsed since first tx in current batch (latency-bound flush)
//
// This reduces P2P messages by ~100x during bursts: 4096 txs → 42 batch messages
// instead of 4096 individual messages, preventing sendCh overflow.
func (h *Host) txBatchLoop() {
	// P2P-R15-MED-5: Panic recovery so a tx-broadcast bug cannot crash the node.
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("txBatchLoop panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	const (
		maxBatchSize  = 100                   // Max txs per batch message
		flushInterval = 10 * time.Millisecond // Max latency before flushing
	)

	batch := make([][]byte, 0, maxBatchSize)
	timer := time.NewTimer(flushInterval)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}

		// TPS OPTIMIZATION: Store txs in CompactTxManager so that compact block
		// propagation can check which txs peers already have. Also broadcast
		// tx hash announces (non-blocking goroutine) so peers can request missing
		// txs via TxHashRequest — full txs are still broadcast below via batch.
		if h.compactTx != nil {
			hashes := make([][]byte, 0, len(batch))
			for _, txData := range batch {
				txHash := HashData(txData)
				h.compactTx.StoreTx(txHash, txData)
				hashes = append(hashes, txHash)
			}
			if len(hashes) > 0 {
				go h.compactTx.BroadcastTxHashes(hashes)
			}
		}

		// Broadcast full txs as batch (primary propagation method)
		// Encode txs as a BatchMessage containing MsgTypeTransaction sub-messages
		msgs := make([]*Message, len(batch))
		for i, txData := range batch {
			msgs[i] = &Message{Type: MsgTypeTransaction, Payload: txData}
		}
		batchData, err := EncodeBatchMessage(&BatchMessage{Messages: msgs})
		if err == nil {
			if berr := h.broadcast(MsgTypeBatch, batchData); berr != nil {
				hostLog.Warnf("Failed to broadcast batch transactions: %v", berr)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-h.ctx.Done():
			flush() // Flush remaining txs on shutdown
			return
		case txData := <-h.txBatchCh:
			batch = append(batch, txData)
			if len(batch) >= maxBatchSize {
				flush()
				timer.Reset(flushInterval)
			}
		case <-timer.C:
			flush()
			timer.Reset(flushInterval)
		}
	}
}

// BroadcastVote broadcasts a vote to all peers
func (h *Host) BroadcastVote(ctx context.Context, data []byte) error {
	return h.broadcast(MsgTypeVote, data)
}

// BroadcastAttestation broadcasts an attestation to all peers
func (h *Host) BroadcastAttestation(ctx context.Context, data []byte) error {
	return h.broadcast(MsgTypeAttestation, data)
}

// BroadcastAggregateAttestation broadcasts an aggregated attestation to all peers
func (h *Host) BroadcastAggregateAttestation(ctx context.Context, data []byte) error {
	return h.broadcast(MsgTypeAggregateAttest, data)
}

// BroadcastStatus broadcasts a status message to all peers
func (h *Host) BroadcastStatus(ctx context.Context, data []byte) error {
	return h.broadcast(MsgTypeStatus, data)
}

// BroadcastCheckpointSignature broadcasts a checkpoint signature to all peers
func (h *Host) BroadcastCheckpointSignature(ctx context.Context, data []byte) error {
	return h.broadcast(MsgTypeCheckpointSig, data)
}

// BroadcastCheckpointRequest broadcasts a checkpoint request to all peers
func (h *Host) BroadcastCheckpointRequest(ctx context.Context, data []byte) error {
	return h.broadcast(MsgTypeCheckpointReq, data)
}

// BroadcastRaw broadcasts a pre-encoded message to all peers
func (h *Host) BroadcastRaw(ctx context.Context, data []byte) error {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()

	for _, peer := range h.peers {
		if !peer.Connected {
			continue
		}
		select {
		case peer.sendCh <- data:
		default:
			// Channel full, skip
		}
	}

	return nil
}

// BroadcastTSS broadcasts a TSS message to all connected peers.
// Used for Round1 commitments and session init (public data, safe to broadcast).
func (h *Host) BroadcastTSS(msgType uint8, data []byte) error {
	return h.broadcast(msgType, data)
}

// SendTSSToPeer sends a TSS message to a specific peer via point-to-point.
// Used for Round2 reveals and private shares (not broadcast).
func (h *Host) SendTSSToPeer(peerID PeerID, msgType uint8, data []byte) error {
	msg, err := EncodeMessage(msgType, data)
	if err != nil {
		return err
	}
	return h.SendRaw(peerID, msg)
}

// --- TSS Validator Address → PeerID Mapping ---

// ActiveValidatorIdentityVerifier is the Protocol V2 deep-fix boundary
// for active-set membership verification. When configured on the Host via
// SetActiveValidatorIdentityVerifier, every received StatusMessage with
// a non-empty ValidatorAddress + ValidatorPublicKey is checked against
// this verifier BEFORE the Address→PeerID mapping is updated.
//
// Implementations: the node layer wires a binding that consults the
// live QPOS validator set (or the consensus quorum tracker) to confirm
// (address, pubKey) is currently an active validator. Returning an error
// rejects the status (fail-closed).
//
// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02). See plans/2026-08-01-
// r38-p2-and-verification.md §R38-P2-01.
type ActiveValidatorIdentityVerifier interface {
	VerifyActiveValidator(address types.Address, publicKey []byte) error
}

// SessionNonceTracker is the Protocol V2 anti-replay backend for status
// messages. It tracks (validatorAddress, senderPeerID, sessionNonce)
// tuples via a map; clients consult Seen() to check+record in one call.
// Older entries can be periodically pruned by callers (e.g., evicted at
// the `statusFreshnessWindowSec` boundary) — See(Pure) records nothing
// is removed; pruning is left to a separate Trim method callers can
// periodically invoke. Concurrency-safe.
//
// AUDIT-FULL NW-06 (2026-08-14): by default the tracked set is memory-only,
// so a process restart forgets every recorded tuple and a replayed status
// frame whose Timestamp still falls inside statusFreshnessWindowSec is
// accepted exactly once more after the restart. Operators who need
// restart-surviving replay protection can install a SessionNoncePersister
// via SetPersister (or Host.EnableSessionNoncePersistence for the
// file-backed implementation): the persisted set is loaded when the hook
// is installed and snapshotted on every mutation.
//
// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02).
type SessionNonceTracker struct {
	mu        sync.Mutex
	seen      map[[56]byte]struct{}
	persister SessionNoncePersister
}

// NewSessionNonceTracker constructs an empty tracker.
func NewSessionNonceTracker() *SessionNonceTracker {
	return &SessionNonceTracker{seen: make(map[[56]byte]struct{})}
}

// SessionNoncePersister is the optional persistence hook for the
// SessionNonceTracker (AUDIT-FULL NW-06, 2026-08-14). See the tracker's
// doc comment for the restart-replay rationale. Implementations must be
// safe for concurrent use; Save receives the FULL current key set (a
// snapshot) and should write it atomically so a crash mid-save never
// truncates the store.
type SessionNoncePersister interface {
	// Save atomically persists the full set of tracked keys.
	Save(keys [][56]byte) error
	// Load returns the previously persisted keys. An absent store (first
	// run) must return (nil, nil), not an error.
	Load() ([][56]byte, error)
}

// FileSessionNoncePersister is a JSON-file-backed SessionNoncePersister
// storing hex-encoded 56-byte keys. It writes atomically (temp file +
// rename, 0600), following the same pattern as the bridge nonce store
// (AUDIT-FULL H-14).
type FileSessionNoncePersister struct {
	path string
	mu   sync.Mutex
}

// NewFileSessionNoncePersister returns a file-backed persister storing
// the tracked set at path (e.g. <datadir>/session_nonces.json).
func NewFileSessionNoncePersister(path string) *FileSessionNoncePersister {
	return &FileSessionNoncePersister{path: path}
}

// Save implements SessionNoncePersister.
func (f *FileSessionNoncePersister) Save(keys [][56]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	encoded := make([]string, 0, len(keys))
	for _, k := range keys {
		encoded = append(encoded, hex.EncodeToString(k[:]))
	}
	data, err := json.Marshal(encoded)
	if err != nil {
		return fmt.Errorf("marshal session-nonce store: %w", err)
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write session-nonce store %s: %w", f.path, err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("rename session-nonce store %s: %w", f.path, err)
	}
	return nil
}

// Load implements SessionNoncePersister. Corrupt individual entries are
// skipped (a truncated hex string or wrong length must not poison the
// whole store); a missing file yields (nil, nil).
func (f *FileSessionNoncePersister) Load() ([][56]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // fresh start — nothing to load
		}
		return nil, fmt.Errorf("read session-nonce store %s: %w", f.path, err)
	}
	var encoded []string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return nil, fmt.Errorf("parse session-nonce store %s: %w", f.path, err)
	}
	keys := make([][56]byte, 0, len(encoded))
	for _, s := range encoded {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 56 {
			continue // skip corrupt entry, keep the valid rest
		}
		var k [56]byte
		copy(k[:], b)
		keys = append(keys, k)
	}
	return keys, nil
}

// sessionNonceKey composes the [56]byte composite key:
// 20B address + 20B peerID + 16B nonce (peerID type-cast to a fixed [20]byte).
// PeerIDs longer than 20 bytes are truncated to 20 (hash-style); shorter
// peerIDs are zero-padded right. This is a content-addressable fingerprint
// collision-tolerant tradeoff — we accept rare collisions in the replay
// set in exchange for a fixed-size map key; matches against the EXACT
// (addr, peer, nonce) tuple are still enforced at the verifier layer
// because attackers cannot reuse a colliding key without already having
// recorded the SAME nonce for the SAME (addr, peer).
func sessionNonceKey(addr types.Address, peerID PeerID, nonce [16]byte) [56]byte {
	var k [56]byte
	copy(k[0:20], addr[:])
	p := []byte(peerID)
	if len(p) > 20 {
		p = p[:20]
	}
	copy(k[20:20+len(p)], p)
	copy(k[40:56], nonce[:])
	return k
}

// Seen returns true if the (addr, peer, nonce) tuple has already been
// recorded (i.e., this status frame is a replay). If the tuple is new,
// Seen atomically records it and returns false (i.e., this is the first
// time we have seen it). This atomic check-and-set under a single lock
// is required to defeat concurrent replay attempts from multiple peers
// handing stale same-nonce frames to us simultaneously.
//
// On `true` (replay detected) callers MUST set verified=false; the
// caller's caller (the status handler) logs and drops the status frame.
func (t *SessionNonceTracker) Seen(addr types.Address, peerID PeerID, nonce [16]byte) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := sessionNonceKey(addr, peerID, nonce)
	if _, ok := t.seen[k]; ok {
		return true
	}
	t.seen[k] = struct{}{}
	t.persistLocked()
	return false
}

// SetPersister installs an optional persistence hook (AUDIT-FULL NW-06)
// and loads any previously persisted keys into the tracker so the replay
// window survives restarts. Passing nil disables persistence and restores
// the legacy memory-only behavior. Load errors are returned so callers
// can fail-closed on a corrupt store; Save errors are logged by the
// tracker and never propagated — the in-memory anti-replay decision has
// already been made when Save runs and must not fail status processing.
func (t *SessionNonceTracker) SetPersister(p SessionNoncePersister) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.persister = p
	if p == nil {
		return nil
	}
	keys, err := p.Load()
	if err != nil {
		return fmt.Errorf("session-nonce tracker: load persisted keys: %w", err)
	}
	for _, k := range keys {
		t.seen[k] = struct{}{}
	}
	if len(keys) > 0 {
		hostLog.Info("Loaded persisted session nonces", map[string]any{"count": len(keys)})
	}
	return nil
}

// persistLocked snapshots the tracked set to the configured persister (if
// any). Persistence failures are logged, never propagated. Callers must
// hold t.mu.
func (t *SessionNonceTracker) persistLocked() {
	if t.persister == nil {
		return
	}
	keys := make([][56]byte, 0, len(t.seen))
	for k := range t.seen {
		keys = append(keys, k)
	}
	if err := t.persister.Save(keys); err != nil {
		log.Printf("[ERROR] p2p: NW-06: failed to persist session-nonce tracker: %v (anti-replay window will not survive restart)", err)
	}
}

// Len returns the number of tracked tuples. Useful for tests asserting
// tracker growth and for periodic pruning decisions.
func (t *SessionNonceTracker) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.seen)
}

// Trim drops entries beyond the configured capacity (last-LRU by
// undefined order — the map iteration order; we accept this since the
// tracker is bounded by a freshness window anyway and collisions are
// uncorrelated).
func (t *SessionNonceTracker) Trim(max int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.seen) <= max {
		return
	}
	drop := len(t.seen) - max
	i := 0
	for k := range t.seen {
		delete(t.seen, k)
		i++
		if i >= drop {
			break
		}
	}
	t.persistLocked()
}

// SetActiveValidatorIdentityVerifier installs the Protocol V2 active-set
// verifier. May be called with nil to disable (default). R38-P2-01 deep-fix.
func (h *Host) SetActiveValidatorIdentityVerifier(v ActiveValidatorIdentityVerifier) {
	h.peersMu.Lock()
	defer h.peersMu.Unlock()
	h.activeValidatorIdentityVerifier = v
}

// SetStatusFreshnessWindowSec configures the maximum clock skew (in
// seconds) between the sender's status.Timestamp and the host's wall
// clock. 0 disables the freshness check (legacy R37 / R38-P2-01 Fix
// behavior). R38-P2-01 deep-fix.
func (h *Host) SetStatusFreshnessWindowSec(seconds uint64) {
	h.peersMu.Lock()
	defer h.peersMu.Unlock()
	h.statusFreshnessWindowSec = seconds
}

// SetSessionNonceTracker installs the anti-replay tracker. May be called
// with nil to disable (default). R38-P2-01 deep-fix.
func (h *Host) SetSessionNonceTracker(t *SessionNonceTracker) {
	h.peersMu.Lock()
	defer h.peersMu.Unlock()
	h.sessionNonceTracker = t
}

// EnableSessionNoncePersistence configures file-backed persistence for the
// host's anti-replay session-nonce tracker (AUDIT-FULL NW-06, 2026-08-14).
// If no tracker is installed yet, an empty one is created first. Without
// this hook the tracker is memory-only and a restart forgets the replay
// window — a replayed status frame whose Timestamp is still inside
// statusFreshnessWindowSec would be accepted once more after the restart.
// Returns the Load error (if any) so callers can fail-closed on a corrupt
// store.
func (h *Host) EnableSessionNoncePersistence(path string) error {
	h.peersMu.RLock()
	tracker := h.sessionNonceTracker
	h.peersMu.RUnlock()
	if tracker == nil {
		tracker = NewSessionNonceTracker()
		h.SetSessionNonceTracker(tracker)
	}
	return tracker.SetPersister(NewFileSessionNoncePersister(path))
}

// findV2ExtensionValueOffset returns the byte offset where the V2
// extension's VALUE bytes (Timestamp||SessionNonce) begin within the
// encoded status payload. The offset is:
//
//	104 (base) + 4 (pkLen) + pkLen + 4 (sigLen) + sigLen + 4 (extLen)
//
// Returns (0, false) if the payload is too short to contain the V2
// extension or the encoded extLen header is malformed. R38-P2-01 deep-fix.
//
// We deliberately mirror DecodeStatusMessage's offset bookkeeping so the
// signed range we construct in the status handler EXACTLY matches what the
// V2 sender signed (base[:104] || Timestamp || SessionNonce).
func findV2ExtensionValueOffset(payload []byte) (int, bool) {
	if len(payload) < 104 {
		return 0, false
	}
	offset := 104
	if len(payload) < offset+4 {
		return 0, false
	}
	pkLen := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
	offset += 4
	if len(payload) < offset+pkLen {
		return 0, false
	}
	offset += pkLen
	if len(payload) < offset+4 {
		return 0, false
	}
	sigLen := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
	offset += 4
	if len(payload) < offset+sigLen {
		return 0, false
	}
	offset += sigLen
	if len(payload) < offset+4 {
		return 0, false
	}
	extLen := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
	offset += 4
	if extLen < 24 || len(payload) < offset+24 {
		return 0, false
	}
	return offset, true
}

// MaxValidatorPeerEntries bounds the size of validatorPeerMap.
// R37-P3-18 FIX (2026-07-31): without a cap, a buggy or compromised
// caller (the node layer registers mappings on validator-set updates)
// could grow the map without bound. 10000 matches MaxPeerScoreEntries
// and is orders of magnitude above any realistic validator set.
const MaxValidatorPeerEntries = 10000

// AuthorizeValidatorRegistration grants the capability to call the exported
// RegisterValidatorPeer. AUDIT-FULL H-2 FIX (2026-08-14): previously any
// internal module or compromised code path holding the Host could register
// an arbitrary (address, peerID) mapping and hijack directed TSS message
// routing. The node layer (Host owner) should call this once during setup
// ONLY if it needs to register mappings outside the verified status path;
// registration via that path (signature + freshness + anti-replay checked)
// is unaffected.
func (h *Host) AuthorizeValidatorRegistration() {
	atomic.StoreInt32(&h.validatorRegAuthorized, 1)
}

// RegisterValidatorPeer maps a validator address to its P2P PeerID.
// AUDIT-FULL H-2 FIX (2026-08-14): this exported entry point is DENIED
// unless the node layer has explicitly granted the capability via
// AuthorizeValidatorRegistration(). Unauthorized calls are rejected with
// a warning (fail-closed) instead of silently mutating TSS routing.
func (h *Host) RegisterValidatorPeer(addr types.Address, peerID PeerID) {
	if atomic.LoadInt32(&h.validatorRegAuthorized) != 1 {
		hostLog.Warnf("AUDIT-FULL H-2: unauthorized RegisterValidatorPeer rejected (validator %x peer %s) — capability not granted",
			addr[:min(len(addr), 4)], peerID)
		return
	}
	h.registerValidatorPeer(addr, peerID)
}

// registerValidatorPeer is the trusted internal registration path used by
// the Host's verified status-message handler (signature-verified,
// freshness-window and anti-replay checked) — see handleStatusMessage.
func (h *Host) registerValidatorPeer(addr types.Address, peerID PeerID) {
	h.validatorPeerMapMu.Lock()
	defer h.validatorPeerMapMu.Unlock()
	// R37-P3-18 FIX (2026-07-31): enforce MaxValidatorPeerEntries.
	// Re-registration of an EXISTING address is always allowed (a
	// validator reconnecting with a new PeerID must be able to update
	// its mapping); only NEW addresses are rejected at capacity.
	if _, exists := h.validatorPeerMap[addr]; !exists && len(h.validatorPeerMap) >= MaxValidatorPeerEntries {
		logging.Global().Warn("RegisterValidatorPeer: validator peer map at capacity, rejecting new entry", map[string]any{
			"addr":     addr.String(),
			"capacity": MaxValidatorPeerEntries,
		})
		return
	}
	h.validatorPeerMap[addr] = peerID
}

// UnregisterValidatorPeer removes a validator address mapping.
func (h *Host) UnregisterValidatorPeer(addr types.Address) {
	h.validatorPeerMapMu.Lock()
	defer h.validatorPeerMapMu.Unlock()
	delete(h.validatorPeerMap, addr)
}

// removeValidatorMappingsForPeer removes all validator address mappings that
// point to the given PeerID.
// R37-P3-18 FIX (2026-07-31): called from Peer.disconnectCleanup so a
// disconnected validator's mapping cannot linger and misdirect TSS
// point-to-point messages to a dead peer. The map is bounded by
// MaxValidatorPeerEntries, so the O(n) scan is cheap.
func (h *Host) removeValidatorMappingsForPeer(peerID PeerID) {
	h.validatorPeerMapMu.Lock()
	defer h.validatorPeerMapMu.Unlock()
	for addr, pid := range h.validatorPeerMap {
		if pid == peerID {
			delete(h.validatorPeerMap, addr)
		}
	}
}

// GetPeerIDForValidator returns the PeerID for a given validator address.
// Returns false if no mapping exists.
func (h *Host) GetPeerIDForValidator(addr types.Address) (PeerID, bool) {
	h.validatorPeerMapMu.RLock()
	defer h.validatorPeerMapMu.RUnlock()
	pid, ok := h.validatorPeerMap[addr]
	return pid, ok
}

// GetValidatorForPeer returns the validator address for a given PeerID.
// This is the reverse lookup of GetPeerIDForValidator.
// AUDIT (2026) TSS B-3: Used to bind P2P message senders to their
// validator identity, preventing participantID spoofing in TSS rounds.
// Returns false if no mapping exists.
func (h *Host) GetValidatorForPeer(peerID PeerID) (types.Address, bool) {
	h.validatorPeerMapMu.RLock()
	defer h.validatorPeerMapMu.RUnlock()
	for addr, pid := range h.validatorPeerMap {
		if pid == peerID {
			return addr, true
		}
	}
	return types.Address{}, false
}

// SendTSSToValidator sends a TSS message to a specific validator by address.
// Looks up the PeerID from the validator peer map and sends the message P2P.
func (h *Host) SendTSSToValidator(addr types.Address, msgType uint8, data []byte) error {
	peerID, ok := h.GetPeerIDForValidator(addr)
	if !ok {
		return fmt.Errorf("no peer mapping for validator %s", addr.String())
	}
	return h.SendTSSToPeer(peerID, msgType, data)
}

// SendBlockToPeer sends a block message to a specific peer.
// audit-fix R2-M4: used by handleBlockRequest to reply only to the requester
// instead of broadcasting to all peers.
func (h *Host) SendBlockToPeer(peerID PeerID, data []byte) error {
	msg, err := EncodeMessage(MsgTypeBlock, data)
	if err != nil {
		return err
	}

	h.peersMu.RLock()
	peer, exists := h.peers[peerID]
	h.peersMu.RUnlock()

	if !exists || !peer.Connected {
		return fmt.Errorf("peer %s not found or not connected", peerID)
	}

	select {
	case peer.sendCh <- msg:
		return nil
	default:
		return fmt.Errorf("send channel full for peer %s", peerID)
	}
}

// SendBatchToPeer sends a batch message to a specific peer.
func (h *Host) SendBatchToPeer(peerID PeerID, data []byte) error {
	msg, err := EncodeMessage(MsgTypeBatch, data)
	if err != nil {
		return err
	}

	h.peersMu.RLock()
	peer, exists := h.peers[peerID]
	h.peersMu.RUnlock()

	if !exists || !peer.Connected {
		return fmt.Errorf("peer %s not found or not connected", peerID)
	}

	select {
	case peer.sendCh <- msg:
		return nil
	default:
		return fmt.Errorf("send channel full for peer %s", peerID)
	}
}

// SendRaw sends a pre-encoded message to a specific peer.
func (h *Host) SendRaw(peerID PeerID, data []byte) error {
	h.peersMu.RLock()
	peer, exists := h.peers[peerID]
	h.peersMu.RUnlock()

	if !exists || !peer.Connected {
		return fmt.Errorf("peer %s not found or not connected", peerID)
	}

	select {
	case peer.sendCh <- data:
		return nil
	default:
		return fmt.Errorf("send channel full for peer %s", peerID)
	}
}

// broadcast sends a message to all connected peers
func (h *Host) broadcast(msgType uint8, data []byte) error {
	msg, err := EncodeMessage(msgType, data)
	if err != nil {
		return err
	}

	h.peersMu.RLock()
	defer h.peersMu.RUnlock()

	sent := 0
	skipped := 0
	for _, peer := range h.peers {
		if !peer.Connected {
			continue
		}
		select {
		case peer.sendCh <- msg:
			sent++
		default:
			skipped++
		}
	}
	if msgType == MsgTypeBatch || msgType == MsgTypeTransaction {
		hostLog.Infof("broadcast: type=%d sent=%d skipped=%d total_peers=%d", msgType, sent, skipped, len(h.peers))
	}
	// R45-LOG-FIX (2026-08-12): log MsgTypeCommit broadcast result so
	// we can verify via journalctl that commits are actually being sent
	// to peers. Previous code only logged Batch/Transaction and silently
	// dropped Commit broadcast stats — making P2P commit gossip failures
	// invisible to operators.
	if msgType == MsgTypeCommit {
		hostLog.Infof("broadcast(MsgTypeCommit): sent=%d skipped=%d total_peers=%d", sent, skipped, len(h.peers))
	}

	return nil
}

// Broadcaster returns the broadcaster
func (h *Host) Broadcaster() *Broadcaster {
	return h.broadcaster
}

// RateLimiter returns the rate limiter
func (h *Host) RateLimiter() *RateLimiter {
	return h.rateLimiter
}

// TxRateLimiter returns the per-peer transaction rate limiter.
//
// P2-TXPOOL-RATELIMIT FIX (R29, 2026-07-26): Exposed for observability and
// testing. This is the tighter per-peer tx rate limiter (default 50 txs/sec)
// that guards the Dilithium3 verification pipeline from a single peer
// flooding MsgTypeTransaction / MsgTypeTxHashResponse.
func (h *Host) TxRateLimiter() *RateLimiter {
	return h.txRateLimiter
}

// Blacklist returns the blacklist
func (h *Host) Blacklist() *Blacklist {
	return h.blacklist
}

// PenaltyManager returns the penalty manager (Phase 1: tiered penalties)
func (h *Host) PenaltyManager() *PenaltyManager {
	return h.penaltyManager
}

// IsTrustedPeer checks if a peer is in the whitelist
func (h *Host) IsTrustedPeer(peerID PeerID) bool {
	h.trustedPeersMu.RLock()
	defer h.trustedPeersMu.RUnlock()
	return h.trustedPeers[peerID]
}

// AddTrustedPeer adds a peer to the whitelist at runtime
func (h *Host) AddTrustedPeer(peerID PeerID) {
	h.trustedPeersMu.Lock()
	defer h.trustedPeersMu.Unlock()
	h.trustedPeers[peerID] = true
}

// RemoveTrustedPeer removes a peer from the whitelist at runtime
func (h *Host) RemoveTrustedPeer(peerID PeerID) {
	h.trustedPeersMu.Lock()
	defer h.trustedPeersMu.Unlock()
	delete(h.trustedPeers, peerID)
}

// TrustedPeers returns a copy of the trusted peers list
func (h *Host) TrustedPeers() []PeerID {
	h.trustedPeersMu.RLock()
	defer h.trustedPeersMu.RUnlock()
	peers := make([]PeerID, 0, len(h.trustedPeers))
	for p := range h.trustedPeers {
		peers = append(peers, p)
	}
	return peers
}

// MessageValidator returns the message validator
// Requirements: 3.3, 3.4
func (h *Host) MessageValidator() *MessageValidator {
	return h.messageValidator
}

// SybilResistance provides Sybil attack resistance mechanisms.
// sybil resistance implemented - reputation-based peer scoring
// audit-fix P2P-1: added /16 wide subnet limits to prevent datacenter concentration
type SybilResistance struct {
	mu sync.RWMutex

	// Peer reputation scores (0-100, higher is better)
	reputation map[PeerID]int

	// Connection timestamps for rate limiting new connections
	connectionTimes map[PeerID]time.Time

	// Minimum reputation required to stay connected
	minReputation int

	// Maximum connections per /24 subnet
	maxPerSubnet int

	// audit-fix P2P-1: Maximum connections per /16 wide subnet (datacenter protection)
	maxPerWideSubnet int

	// IP subnet connection counts (/24)
	subnetCounts map[string]int

	// audit-fix P2P-1: Wide subnet connection counts (/16)
	wideSubnetCounts map[string]int
}

// NewSybilResistance creates a new Sybil resistance manager
func NewSybilResistance() *SybilResistance {
	return &SybilResistance{
		reputation:       make(map[PeerID]int),
		connectionTimes:  make(map[PeerID]time.Time),
		minReputation:    10,
		maxPerSubnet:     3, // SECURITY FIX P2P-H2: Reduced from 5 to 3 for stronger Sybil resistance
		maxPerWideSubnet: 8, // SECURITY FIX P2P-H2: Reduced from 15 to 8 to prevent datacenter concentration
		subnetCounts:     make(map[string]int),
		wideSubnetCounts: make(map[string]int),
	}
}

// CheckConnection checks if a new connection should be allowed.
// Returns an error if the connection should be rejected.
// sybil resistance: rate limiting and subnet-based restrictions
// audit-fix P2P-1: added /16 wide subnet check for datacenter concentration prevention
func (sr *SybilResistance) CheckConnection(peerID PeerID, addr string) error {
	// Loopback exemption: on local test networks all nodes share the
	// 127.0.0.1/24 subnet; the /24 cap (maxPerSubnet=3) would deadlock
	// local 6+ node setups. Production nodes listen on public IPs and
	// never accept loopback P2P connections, so the exemption is safe.
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if parsed := net.ParseIP(host); parsed != nil && parsed.IsLoopback() {
			return nil
		}
	} else if parsed := net.ParseIP(addr); parsed != nil && parsed.IsLoopback() {
		return nil
	}

	sr.mu.Lock()
	defer sr.mu.Unlock()

	// Check if peer has been seen before and has low reputation
	if rep, exists := sr.reputation[peerID]; exists && rep < sr.minReputation {
		return fmt.Errorf("peer has low reputation: %d", rep)
	}

	// Extract subnet from address (first 3 octets for IPv4)
	subnet := extractSubnet(addr)
	if subnet != "" {
		if count := sr.subnetCounts[subnet]; count >= sr.maxPerSubnet {
			return fmt.Errorf("too many connections from /24 subnet %s", subnet)
		}
	}

	// audit-fix P2P-1: check /16 wide subnet to prevent datacenter concentration
	wideSubnet := extractWideSubnet(addr)
	if wideSubnet != "" {
		if count := sr.wideSubnetCounts[wideSubnet]; count >= sr.maxPerWideSubnet {
			return fmt.Errorf("too many connections from /16 subnet %s", wideSubnet)
		}
	}

	// Check connection rate (max 1 connection per 10 seconds from same peer)
	if lastConn, exists := sr.connectionTimes[peerID]; exists {
		if time.Since(lastConn) < 10*time.Second {
			return fmt.Errorf("connection rate limit exceeded")
		}
	}

	// Record connection
	sr.connectionTimes[peerID] = time.Now()
	if subnet != "" {
		sr.subnetCounts[subnet]++
	}
	if wideSubnet != "" {
		sr.wideSubnetCounts[wideSubnet]++
	}

	// Initialize reputation for new peers
	if _, exists := sr.reputation[peerID]; !exists {
		sr.reputation[peerID] = 50 // Start with neutral reputation
	}

	return nil
}

// RecordGoodBehavior increases a peer's reputation
func (sr *SybilResistance) RecordGoodBehavior(peerID PeerID) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if rep, exists := sr.reputation[peerID]; exists {
		sr.reputation[peerID] = min(100, rep+1)
	} else {
		sr.reputation[peerID] = 51
	}
}

// RecordBadBehavior decreases a peer's reputation
func (sr *SybilResistance) RecordBadBehavior(peerID PeerID) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if rep, exists := sr.reputation[peerID]; exists {
		sr.reputation[peerID] = max(0, rep-10)
	} else {
		sr.reputation[peerID] = 40
	}
}

// GetReputation returns a peer's reputation score
func (sr *SybilResistance) GetReputation(peerID PeerID) int {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return sr.reputation[peerID]
}

// OnDisconnect updates state when a peer disconnects
func (sr *SybilResistance) OnDisconnect(peerID PeerID, addr string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	subnet := extractSubnet(addr)
	if subnet != "" {
		if count := sr.subnetCounts[subnet]; count > 0 {
			sr.subnetCounts[subnet] = count - 1
		}
		// audit-fix NEW-22: remove empty subnet entry to prevent map growth.
		if sr.subnetCounts[subnet] == 0 {
			delete(sr.subnetCounts, subnet)
		}
	}

	// audit-fix P2P-1: decrement wide subnet count on disconnect
	wideSubnet := extractWideSubnet(addr)
	if wideSubnet != "" {
		if count := sr.wideSubnetCounts[wideSubnet]; count > 0 {
			sr.wideSubnetCounts[wideSubnet] = count - 1
		}
		if sr.wideSubnetCounts[wideSubnet] == 0 {
			delete(sr.wideSubnetCounts, wideSubnet)
		}
	}

	delete(sr.connectionTimes, peerID)

	cutoff := time.Now().Add(-1 * time.Minute)
	for pid, t := range sr.connectionTimes {
		if t.Before(cutoff) {
			delete(sr.connectionTimes, pid)
		}
	}
}

// extractSubnet extracts the /24 subnet from an address
func extractSubnet(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}

	// For IPv4, use /24 subnet
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d", ip4[0], ip4[1], ip4[2])
	}

	// For IPv6, use /64 subnet (first 8 bytes) - standard for SLAAC
	if len(ip) == 16 {
		return fmt.Sprintf("%x:%x:%x:%x", ip[0:2], ip[2:4], ip[4:6], ip[6:8])
	}

	return ""
}

// audit-fix P2P-1: extractWideSubnet extracts the /16 subnet from an address
// to detect datacenter/cloud provider concentration.
func extractWideSubnet(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}

	// For IPv4, use /16 subnet (first 2 octets)
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d", ip4[0], ip4[1])
	}

	// For IPv6, use /64 subnet (first 8 bytes) - standard for SLAAC
	if len(ip) == 16 {
		return fmt.Sprintf("%x:%x:%x:%x", ip[0:2], ip[2:4], ip[4:6], ip[6:8])
	}

	return ""
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
