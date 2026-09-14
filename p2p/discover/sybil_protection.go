// Quantaureum Node source, version 1.0.0.
// Package discover implements enhanced node discovery with Sybil attack protection
package discover

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/quantaureum/qau/p2p/enode"
)

const (
	// MinProofOfWorkDifficulty is the minimum difficulty for node ID proof-of-work.
	// SECURITY FIX (audit P2P-02): Increased from 20 to 24 (~2^24 hashes ≈ 16M).
	// Previous 2^20 was only ~1M hashes, trivially computed by modern GPUs in
	// microseconds, allowing mass Sybil identity generation. 2^24 takes ~1-2s
	// on ARM64 and is significantly harder for GPU farms.
	//
	// AUDIT-FULL ROUND3 2026-08-15 LOW-04 — ACCEPTED-IN-PLACE:
	// Audit re-flagged that 2^24 = ~16ms on a single RTX 4090 (~1 GHz
	// hash rate), well short of Ethereum discv5's 60-bit difficulty
	// target. Reviewers concluded 24 is acceptable here because this
	// PoW is a TIERED, NOT STANDALONE defense: it is layered on top of:
	//   - MaxConnectionsPerIP=3 + MaxConnectionsPerSubnet=10 (this file),
	//     enforced during RecordIPConnection before any reputation is read.
	//   - MaxTrackedIPs=10000 + LRU eviction (this file),
	//   - MaxTrackedScores=50000 + LRU eviction (MEDIUM-01, this file),
	//     bounding the table even when an attacker pays the PoW cost.
	// A higher PoW difficulty would additionally strain mobile / light
	// clients honest nodes run. Bumping to a discv5-grade 60-bit is
	// tracked separately and is a CONSENSUS-LEVEL migration (ENR
	// format, node-id derivation); leaving at 24 until that migration
	// is scoped. No code change required for this audit closure.
	MinProofOfWorkDifficulty = 24

	// MinReputationThreshold is the minimum reputation score required for DHT insertion
	MinReputationThreshold = 10

	// ReputationDecayInterval is how often reputation scores decay
	ReputationDecayInterval = 24 * time.Hour

	// ReputationDecayFactor is the factor by which reputation decays
	ReputationDecayFactor = 0.9

	// MaxConnectionsPerIP limits connections from a single IP address
	MaxConnectionsPerIP = 3

	// MaxConnectionsPerSubnet limits connections from a single /24 subnet
	MaxConnectionsPerSubnet = 10

	// NodeVerificationTimeout is the timeout for node verification challenges
	NodeVerificationTimeout = 10 * time.Second

	// AUDIT (2026) P2P-04: IP connection count decay interval. Connections
	// not refreshed within this window are decayed by 1, preventing permanent
	// lockout when ReleaseIPConnection is never called (the current code path
	// never calls it). This also bounds the map size by evicting zero-count
	// entries during periodic decay.
	IPCountDecayInterval = 1 * time.Hour

	// AUDIT (2026) P2P-04: Maximum number of tracked IP entries. When
	// exceeded, oldest entries are evicted during RecordIPConnection.
	MaxTrackedIPs = 10000

	// AUDIT-FULL-ROUND3 2026-08-15 MEDIUFIX: Upper bound for the
	// ReputationManager.scores map. Attackers controlling many IPs (within
	// the ≤3 connections/IP cap) could still fan out TONS of node IDs and
	// call Increase/DecreaseReputation on each, populating scores without
	// bound (DecayReputations drops only Score < threshold, so positive and
	// near-zero entries accrete forever). Capped to 50000 — same ballpark as
	// MaxTrackedIPs but looser because reputation entries are ~2× smaller and
	// tracked long-term for honest peers; over-cap we LRU-evict by oldest
	// LastUpdated (matching the ipCounts strategy). Also tightened the_decay
	// delete gate (LOW-02) so stale near-zero entries get reaped proactively.
	MaxTrackedScores = 50000
)

var (
	// ErrInvalidProofOfWork is returned when node ID proof-of-work is insufficient
	ErrInvalidProofOfWork = errors.New("insufficient proof-of-work for node ID")

	// ErrInsufficientReputation is returned when node reputation is too low
	ErrInsufficientReputation = errors.New("insufficient reputation for DHT insertion")

	// ErrNodeVerificationFailed is returned when node verification challenge fails
	ErrNodeVerificationFailed = errors.New("node verification failed")

	// ErrTooManyConnectionsFromIP is returned when IP has too many connections
	ErrTooManyConnectionsFromIP = errors.New("too many connections from this IP")
)

// ReputationScore tracks a node's reputation
type ReputationScore struct {
	Score        int
	LastUpdated  time.Time
	Violations   int
	GoodBehavior int
}

// ReputationManager manages node reputation scores
type ReputationManager struct {
	mu           sync.RWMutex
	scores       map[enode.ID]*ReputationScore
	ipCounts     map[string]int       // Track connections per IP
	subnetCounts map[string]int       // Track connections per /24 subnet
	ipLastSeen   map[string]time.Time // AUDIT (2026) P2P-04: track last activity per IP for decay
	lastDecay    time.Time
	lastIPDecay  time.Time // AUDIT (2026) P2P-04: last time IP counts were decayed
}

// NewReputationManager creates a new reputation manager
func NewReputationManager() *ReputationManager {
	return &ReputationManager{
		scores:       make(map[enode.ID]*ReputationScore),
		ipCounts:     make(map[string]int),
		subnetCounts: make(map[string]int),
		ipLastSeen:   make(map[string]time.Time),
		lastDecay:    time.Now(),
		lastIPDecay:  time.Now(),
	}
}

// GetReputation returns the reputation score for a node
func (rm *ReputationManager) GetReputation(id enode.ID) int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if score, exists := rm.scores[id]; exists {
		return score.Score
	}
	return 0 // New nodes start with 0 reputation
}

// IncreaseReputation increases a node's reputation for good behavior
func (rm *ReputationManager) IncreaseReputation(id enode.ID, amount int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	score, exists := rm.scores[id]
	if !exists {
		// AUDIT-FULL-ROUND3 MEDIUFIX: bound the scores map. Only NEW
		// entries risk unbounded growth (existing entries just mutate in
		// place). Evict the oldest-by-LastUpdated entry to make room — this
		// matches the documented "LRU by lastSeen" strategy of MaxTrackedIPs
		// and is O(N) only on the rare overflow path, not on every call.
		if len(rm.scores) >= MaxTrackedScores {
			rm.evictOldestScores(MaxTrackedScores / 10) // evict 10%
		}
		score = &ReputationScore{
			Score:       0,
			LastUpdated: time.Now(),
		}
		rm.scores[id] = score
	}

	score.Score += amount
	score.GoodBehavior++
	score.LastUpdated = time.Now()

	// Cap reputation at 100
	if score.Score > 100 {
		score.Score = 100
	}
}

// DecreaseReputation decreases a node's reputation for bad behavior
func (rm *ReputationManager) DecreaseReputation(id enode.ID, amount int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	score, exists := rm.scores[id]
	if !exists {
		// AUDIT-FULL-ROUND3 MEDIUFIX: bound the scores map (mirror of
		// the IncreaseReputation cap). An attacker wiring fake node IDs to
		// DecreaseReputation would otherwise pump the map size unboundedly.
		if len(rm.scores) >= MaxTrackedScores {
			rm.evictOldestScores(MaxTrackedScores / 10)
		}
		score = &ReputationScore{
			Score:       0,
			LastUpdated: time.Now(),
		}
		rm.scores[id] = score
	}

	score.Score -= amount
	score.Violations++
	score.LastUpdated = time.Now()

	// Reputation can go negative
	if score.Score < -100 {
		score.Score = -100
	}
}

// RecordIPConnection records a connection from an IP address
func (rm *ReputationManager) RecordIPConnection(ip string) error {
	// Loopback exemption: on local test networks all nodes share 127.0.0.1/::1,
	// so Sybil-resistance limits do not apply to localhost (not a real attack scenario).
	// Production nodes listen on public IPs and would not accept loopback P2P connections.
	if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
		return nil
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	// AUDIT (2026) P2P-04: Bounded eviction. When the IP tracking map
	// exceeds MaxTrackedIPs, evict the oldest entries (by lastSeen) before
	// adding new ones. This prevents unbounded memory growth from attacker-
	// controlled diverse IPs. Existing IPs are not evicted (only new ones
	// are rejected if the cap is reached after eviction).
	if _, exists := rm.ipCounts[ip]; !exists && len(rm.ipCounts) >= MaxTrackedIPs {
		rm.evictOldestIPs(MaxTrackedIPs / 10) // evict 10% at a time
		// If still at cap after eviction, reject the new IP
		if len(rm.ipCounts) >= MaxTrackedIPs {
			return fmt.Errorf("IP tracking table full (%d entries); cannot track new IP", MaxTrackedIPs)
		}
	}

	count := rm.ipCounts[ip]
	if count >= MaxConnectionsPerIP {
		return ErrTooManyConnectionsFromIP
	}

	subnet := ipToSubnet(ip)
	subnetCount := rm.subnetCounts[subnet]
	if subnetCount >= MaxConnectionsPerSubnet {
		return fmt.Errorf("too many connections from subnet %s", subnet)
	}

	rm.ipCounts[ip] = count + 1
	rm.subnetCounts[subnet] = subnetCount + 1
	rm.ipLastSeen[ip] = time.Now()
	return nil
}

// evictOldestIPs removes the n IPs with the oldest lastSeen timestamps.
// AUDIT (2026) P2P-04: Called when the IP tracking map exceeds
// MaxTrackedIPs. Caller MUST hold rm.mu.
func (rm *ReputationManager) evictOldestIPs(n int) {
	if n <= 0 || len(rm.ipLastSeen) == 0 {
		return
	}

	// Build a slice of (ip, lastSeen) for sorting
	type ipEntry struct {
		ip       string
		lastSeen time.Time
	}
	entries := make([]ipEntry, 0, len(rm.ipLastSeen))
	for ip, ts := range rm.ipLastSeen {
		entries = append(entries, ipEntry{ip, ts})
	}

	// Sort by lastSeen ascending (oldest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastSeen.Before(entries[j].lastSeen)
	})

	// Evict up to n entries
	evictCount := n
	if evictCount > len(entries) {
		evictCount = len(entries)
	}
	for i := 0; i < evictCount; i++ {
		ip := entries[i].ip
		count := rm.ipCounts[ip]
		delete(rm.ipCounts, ip)
		delete(rm.ipLastSeen, ip)
		// Decay subnet count by the IP's contribution
		subnet := ipToSubnet(ip)
		if sc := rm.subnetCounts[subnet]; sc > count {
			rm.subnetCounts[subnet] = sc - count
		} else {
			delete(rm.subnetCounts, subnet)
		}
	}
}

func ipToSubnet(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return ip
	}
	ip4[3] = 0
	return ip4.String()
}

// ReleaseIPConnection releases a connection from an IP address
func (rm *ReputationManager) ReleaseIPConnection(ip string) {
	// Loopback exemption: symmetric with RecordIPConnection — loopback connections are not counted,
	// and release returns immediately, avoiding erroneous decrements.
	if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
		return
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	if count := rm.ipCounts[ip]; count > 0 {
		rm.ipCounts[ip] = count - 1
		if rm.ipCounts[ip] == 0 {
			delete(rm.ipCounts, ip)
			delete(rm.ipLastSeen, ip) // AUDIT (2026) P2P-04: clean up timestamp
		}
	}

	subnet := ipToSubnet(ip)
	if count := rm.subnetCounts[subnet]; count > 0 {
		rm.subnetCounts[subnet] = count - 1
		if rm.subnetCounts[subnet] == 0 {
			delete(rm.subnetCounts, subnet)
		}
	}
}

// DecayReputations applies time-based decay to all reputation scores
func (rm *ReputationManager) DecayReputations() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	if now.Sub(rm.lastDecay) < ReputationDecayInterval {
		// AUDIT (2026) P2P-04: Even when reputation decay isn't due, still
		// decay IP counts on a shorter interval. ReleaseIPConnection is never
		// called by the P2P layer, so without this decay, IP/subnet counters
		// only increase, permanently locking out honest nodes whose IPs were
		// briefly associated with dropped connections.
		rm.decayIPCounts(now)
		return
	}

	for id, score := range rm.scores {
		// Decay reputation towards 0
		if score.Score > 0 {
			score.Score = int(float64(score.Score) * ReputationDecayFactor)
		} else if score.Score < 0 {
			score.Score = int(float64(score.Score) * ReputationDecayFactor)
		}

		// AUDIT-FULL-ROUND3 2026-08-15 LOW-02 FIX: previously dropped only
		// Score < -50, which left a long tail of near-zero (and all positive)
		// entries sitting in the scores map forever — combined with the
		// (pre-fix) absence of any insert-side cap this was the OOM vector.
		// Now also drop entries whose decayed score lands below
		// MinReputationThreshold (=10): a node that has been idle long enough
		// for its reputation to decay below the DHT-insert threshold isn't
		// doing anything useful for us, so freeing its slot is safe. Negative
		// scores still get dropped aggressively. This complements the
		// MaxTrackedScores LRU cap at insert (MEDIUM-01): the cap is the
		// hard ceiling, this proactive prune is the garbage collector that
		// keeps us well under the ceiling under normal load.
		if score.Score < MinReputationThreshold {
			delete(rm.scores, id)
		}
	}

	rm.lastDecay = now
	// AUDIT (2026) P2P-04: Also decay IP counts during full decay.
	rm.decayIPCounts(now)
}

// evictOldestScores removes the n entries in rm.scores with the oldest
// LastUpdated timestamps. AUDIT-FULL-ROUND3 2026-08-15 MEDIUFIX:
// called by IncreaseReputation/DecreaseReputation when inserting a NEW
// entry would exceed MaxTrackedScores. Strategy matches evictOldestIPs
// (oldest-by-lastSeen) so a peer that hasn't been touched in a while (and
// whose score has therefore decayed via DecayReputations) is the natural
// candidate for eviction. Caller MUST hold rm.mu.
func (rm *ReputationManager) evictOldestScores(n int) {
	if n <= 0 || len(rm.scores) == 0 {
		return
	}

	type scoreEntry struct {
		id          enode.ID
		lastUpdated time.Time
	}
	entries := make([]scoreEntry, 0, len(rm.scores))
	for id, sc := range rm.scores {
		entries = append(entries, scoreEntry{id, sc.LastUpdated})
	}

	// Oldest LastUpdated first — same selection rule as evictOldestIPs.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastUpdated.Before(entries[j].lastUpdated)
	})

	evictCount := n
	if evictCount > len(entries) {
		evictCount = len(entries)
	}
	for i := 0; i < evictCount; i++ {
		delete(rm.scores, entries[i].id)
	}
}

// decayIPCounts decrements IP/subnet connection counts for IPs not seen
// within IPCountDecayInterval, deleting zero-count entries. This prevents
// unbounded map growth and permanent IP lockout when ReleaseIPConnection
// is never called. Caller MUST hold rm.mu.
func (rm *ReputationManager) decayIPCounts(now time.Time) {
	if now.Sub(rm.lastIPDecay) < IPCountDecayInterval {
		return
	}
	rm.lastIPDecay = now

	for ip, lastSeen := range rm.ipLastSeen {
		if now.Sub(lastSeen) >= IPCountDecayInterval {
			count := rm.ipCounts[ip]
			// Decay by 1 (not to zero) so temporarily idle peers aren't fully reset
			if count > 1 {
				rm.ipCounts[ip] = count - 1
			} else {
				delete(rm.ipCounts, ip)
				delete(rm.ipLastSeen, ip)
				// Also decrement subnet count
				subnet := ipToSubnet(ip)
				if sc := rm.subnetCounts[subnet]; sc > 1 {
					rm.subnetCounts[subnet] = sc - 1
				} else {
					delete(rm.subnetCounts, subnet)
				}
			}
		}
	}
}

// VerifyProofOfWork verifies that a node ID has sufficient proof-of-work.
// audit-fix CRIT-SYBIL: PoW verification is integrated into the P2P handshake.
// This function is called from:
// 1. rlpx/handshake_pq.go:ResponderHandshakeWithStore() - verifies initiator's PoW
// 2. rlpx/handshake_pq.go:verifyResponderPoW() - verifies responder's PoW
func VerifyProofOfWork(id enode.ID, nonce uint64) bool {
	// Combine node ID and nonce (matching generatePoWNonce's LittleEndian encoding)
	data := make([]byte, len(id)+8)
	copy(data, id[:])
	binary.LittleEndian.PutUint64(data[len(id):], nonce)

	// Hash the data using SHA3-256 (standard NIST SHA3, matching generation)
	hasher := sha3.New256()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	// Check leading zeros (difficulty)
	hashInt := new(big.Int).SetBytes(hash)
	target := new(big.Int).Lsh(big.NewInt(1), 256-MinProofOfWorkDifficulty)

	return hashInt.Cmp(target) < 0
}

// ValidateNodeID validates that a node ID is derived from its public key
// audit-fix CR-4: Verify ENR record signature BEFORE checking content.
// Without this, an attacker can relay a valid node's ENR record (containing
// PoW nonce) without owning the corresponding private key, enabling identity
// spoofing for eclipse/sybil attacks.
// AUDIT (2026) P2P-03: Also verify the PoW nonce embedded in the ENR.
// Previously PoW was only enforced at the RLPx handshake (host.go), so an
// attacker could self-sign an ENR with an arbitrary IP and inject it into
// the routing table via discovery messages without ever completing a
// handshake or computing the expensive 2^24 PoW. This enabled cheap
// Sybil/eclipse attacks via routing-table poisoning. Production nodes
// already embed their PoW nonce in the ENR (host.go:buildQNRRecord calls
// r.SetPoWNonce), so requiring it here does not break honest nodes.
//
// P2P-C03 FIX (R30, 2026-07-26): CRITICAL REGRESSION FIX.
// R29 made ENR mandatory for ALL nodes, but traditional discv4 NEIGHBORS
// responses only carry (IP, Port, ID) without an ENR. Requiring ENR for
// discv4-discovered peers caused the entire DHT to fail: new nodes could
// only connect to statically-configured bootstrap nodes and could not
// discover any other peers, partitioning the network.
//
// New behavior:
//   - Node with ENR    → full validation (signature, pubkey binding, PoW)
//   - Node without ENR → basic validation only (non-nil, routable IP,
//     non-zero ID). Caller should schedule a lazy
//     ENRRequest to fetch the ENR before trusting
//     the node for sensitive operations.
//   - PoW is still enforced at RLPx handshake (host.go), so an attacker
//     cannot leverage the relaxed discovery-time check to bypass PoW —
//     they cannot establish a session without computing it.
func ValidateNodeID(n *enode.Node) error {
	if n == nil {
		return errors.New("node is nil")
	}

	// Basic ID check applies to every node (with or without ENR).
	if n.ID() == (enode.ID{}) {
		return errors.New("node has zero ID")
	}

	// Basic IP routability check applies to every node.
	if ip := n.IP(); ip != nil && enode.IsUnroutableIP(ip) {
		return fmt.Errorf("node IP %s is unroutable", ip)
	}

	// P2P-C03: Nodes without an ENR are traditional discv4 discoveries.
	// Accept them into the routing table so DHT discovery works; defer
	// ENR-based security checks to the RLPx handshake (host.go enforces
	// PoW before any session is established) and/or lazy ENRRequest.
	if !n.HasENR() {
		return nil
	}

	// Get the node's ENR record
	record := n.Record()
	if record == nil {
		// Defensive: HasENR returned true but Record() is nil — treat as
		// discv4 node and accept (basic checks above already passed).
		return nil
	}

	// audit-fix CR-4: Verify ENR signature before trusting any ENR content.
	// An attacker who cannot sign cannot create a valid ENR for their node.
	if err := record.VerifySignature(); err != nil {
		return fmt.Errorf("ENR signature verification failed: %w", err)
	}

	// Get the public key from ENR
	// SECURITY FIX: Changed from "secp256k1" to "dilithium3" to match the actual
	// post-quantum cryptography used in this blockchain (was allowing bypass of ID validation)
	pubKeyBytes, ok := record.Get("dilithium3")
	if !ok {
		return errors.New("no dilithium3 public key in ENR record")
	}

	// AUDIT (2026) P2P-03/P2P-11 FIX: Use enode.DeriveID (the canonical
	// derivation used by NewNode/DecodeENR) instead of an ad-hoc SHA3-256 hash.
	// The old SHA3-256 derivation diverged from the network's actual ID
	// derivation (DeriveID takes the first IDLength bytes of the pubkey), so
	// either the check always failed or it allowed an attacker to present ENRs
	// whose claimed node ID (DeriveID result) did not match the SHA3-256 check.
	// This breaks both the identity binding (P2P-11) and the PoW gate (P2P-03),
	// since PoW is bound to n.ID() but the SHA3-256 check was bound to a
	// different value. Using the canonical DeriveID makes the ID-publickey
	// binding consistent across the entire discovery stack.
	expectedID := enode.DeriveID(pubKeyBytes)
	if n.ID() != expectedID {
		return fmt.Errorf("node ID does not match public key derivation")
	}

	// AUDIT (2026) P2P-03: Verify PoW nonce is present and valid.
	// This prevents cheap Sybil attacks where an attacker self-signs ENR
	// records without computing the expensive proof-of-work. The PoW nonce
	// is verified against the node ID (which was just confirmed to match
	// the signed public key hash), so it cannot be forged without the
	// private key AND the PoW computation.
	powNonce, hasPow := record.GetPoWNonce()
	if !hasPow {
		return errors.New("no PoW nonce in ENR record")
	}
	if !VerifyProofOfWork(n.ID(), powNonce) {
		return ErrInvalidProofOfWork
	}

	return nil
}

// ValidateNodeIDWithENR performs full ENR validation on a node that now has
// an ENR record (e.g. after a lazy ENRRequest). Returns an error if the node
// still has no ENR — callers should keep deferring trust in that case.
//
// P2P-C03 FIX (R30, 2026-07-26).
func ValidateNodeIDWithENR(n *enode.Node) error {
	if n == nil {
		return errors.New("node is nil")
	}
	if !n.HasENR() {
		return errors.New("node still has no ENR record — full validation deferred")
	}
	return ValidateNodeID(n)
}

// GenerateChallenge generates a random challenge for node verification
func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	return challenge, nil
}
