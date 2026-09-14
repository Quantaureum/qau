// Quantaureum Node source, version 1.0.0.
// Package rlpx implements the RLPx encrypted transport protocol.
// This file implements post-quantum secure handshake using Kyber-768 KEM.
//
// SHARED INTERFACE WARNING - MUST SYNC WITH WALLET
// Wallet: the quantaureum-wallet repo
// Key Derivation: HKDF-SHAKE256 (quantum-safe, 256-bit security)
// Version: v2.0 - Unified with Wallet using SHAKE256 for quantum resistance
// =============================================================================
package rlpx

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"github.com/quantaureum/qau/crypto"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/p2p/discover"
	"github.com/quantaureum/qau/p2p/enode"
)

const (
	// Protocol version for post-quantum handshake
	protocolVersionPQ = 5

	// Nonce size for handshake
	nonceSize = 32

	// Handshake timeout
	// SECURITY FIX (audit P2P-01): Reduced from 1800s to 30s to prevent Slowloris DoS.
	handshakeTimeoutPQ = 30 * time.Second

	// Derived key material size.
	// R37-FIX P1-P2P-01 (2026-07-30): Derive 160 bytes (5 × 32) with explicit
	// DIRECTIONAL keys. The R40-C6 layout (128 bytes: sendKey, recvKey,
	// macSecret, egressMACKey) could not be aligned between initiator and
	// responder — both sides stored EgressMAC=egressMACKey while their
	// IngressMAC differed (k1 vs k0), so the first frame in EACH direction
	// failed MAC verification (and the CTR IVs were misaligned too).
	// New layout: encKeyAB, encKeyBA, macSecret, macKeyAB, macKeyBA — see
	// deriveSessionKeys for the exact assignment.
	derivedKeySize = 160

	// Kyber-768 ciphertext size (1088 bytes) for replay protection
	// SECURITY FIX: Validate ciphertext length to prevent malformed input attacks
	kyberCiphertextSize = 1088

	// Kyber-768 public key size (1184 bytes) for validation
	// SECURITY FIX: Validate public key length to prevent malformed input attacks
	kyberPublicKeySize = 1184

	// Dilithium3 signature size for validation
	// SECURITY FIX: Validate signature length
	dilithiumSignatureSize = 3293

	// Replay protection window for handshake timestamp.
	// SECURITY FIX: Reject handshakes older than this window to prevent replay attacks.
	//
	// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): Previously 60 seconds, which gave a
	// ±60s acceptance window (120 seconds total replay attack surface). An attacker
	// who captured a handshake message could replay it within this 120s window to
	// establish a fraudulent connection or exhaust server resources.
	//
	// Reduced to 15 seconds — this still tolerates:
	//   - Cross-continental RTT (~150-300ms one-way)
	//   - Mobile/satellite latency (~500-1000ms)
	//   - NTP clock skew (~1-2s typical, up to 5s in poorly-synced environments)
	//   - Handshake processing time (<1s for Kyber768 + Dilithium3 on modern hardware)
	// while shrinking the replay attack surface by 4x (from 120s to 30s).
	//
	// Defense-in-depth: Even within this 15s window, replays are prevented by the
	// handshakeReplayCache (see below), which tracks (peerID + nonce) pairs that
	// have been seen. An attacker who replays a captured handshake within the
	// timestamp window will be rejected because the nonce is already in the cache.
	//
	// Trade-off: A tighter window (e.g., 5s) would further reduce the replay
	// surface but risks rejecting legitimate handshakes on high-latency or
	// poorly-synced networks. 15s is the sweet spot identified by:
	//   - go-ethereum uses ~5s for header timestamp validation (block propagation)
	//   - TLS 1.3 allows up to 10s for ClientHello replay detection (PSK mode)
	//   - Noise protocol framework recommends 5-30s depending on transport
	// We choose 15s as a conservative bound that accommodates real-world network
	// conditions while providing strong replay protection.
	handshakeTimestampWindow = 15 * time.Second

	// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): Global handshake replay cache.
	//
	// Without a nonce cache, even a tight timestamp window allows replays within
	// that window. The cache tracks (peerID + nonce) pairs that have been seen
	// in a successfully-decoded handshake message. If the same pair appears again
	// within the cache's TTL, the replay is rejected.
	//
	// The cache is global (not per-connection) because an attacker can replay a
	// captured handshake to a DIFFERENT connection — per-connection caches would
	// not detect this. The cache is bounded to prevent memory exhaustion: when
	// the cache exceeds maxReplayCacheEntries, the oldest entries (by timestamp)
	// are evicted. The TTL is 2x the timestamp window to ensure entries remain
	// in the cache for the full duration of the replay window plus a safety margin.
	//
	// Thread-safety: All access is protected by replayCacheMu. The cache is only
	// accessed from decodeAuthMessagePQ and decodeAuthResponsePQ, which are called
	// from handshake goroutines. The mutex is fine-grained (held only for the
	// cache lookup+insert) to avoid blocking concurrent handshakes.
	handshakeReplayCacheTTL = 30 * time.Second // 2x handshakeTimestampWindow

	// maxReplayCacheEntries bounds the cache size to prevent memory exhaustion.
	// Each entry is ~100 bytes (peerID 32 + nonce 32 + timestamp 8 + map overhead).
	// 10,000 entries × 100 bytes = ~1MB, which is negligible for a node that may
	// handle thousands of concurrent handshakes. When the cache is full, the
	// oldest entries are evicted (LRU-like behavior via timestamp-based purge).
	maxReplayCacheEntries = 10000

	// MaxAuthResponseSize is the maximum expected size for auth response
	// Based on: version(1) + maxCtLen(2) + maxCiphertext(1088) + maxNonceLen(2) +
	// nonce(32) + timestamp(8) + maxSigLen(2) + maxSig(3293) + responderID(32)
	// Plus some overhead for future extensions.
	// SECURITY FIX: Limit buffer to prevent DoS via memory exhaustion
	MaxAuthResponseSize = 8 * 1024 // 8KB

	// MinAuthMessageSize is the minimum expected size for an auth message
	MinAuthMessageSize = 1 + 2 + kyberPublicKeySize + 2 + nonceSize + 8 + 8 + 2 + dilithiumSignatureSize + 32
	// MinAuthResponseSize is the minimum expected size for an auth response
	// P2P-P1-01 FIX (R31, 2026-07-27): Added 8 bytes for PowNonce field.
	MinAuthResponseSize = 1 + 2 + kyberCiphertextSize + 2 + nonceSize + 8 + 8 + 2 + dilithiumSignatureSize + 32

	// CRYPTO-R18-CRIT-01 (2026-07-24): Domain separation tags for P2P handshake
	// signatures. Previously the handshake signed raw concatenated fields
	// (version||kyberKey||nonce||timestamp||peerID) without any protocol-context
	// prefix, violating the principle that the same key used across different
	// protocols must have unique domain tags. Without these tags, a signature
	// from one protocol context could theoretically be replayed in another.
	// The initiator and responder use DIFFERENT tags so a signature from one
	// role cannot be replayed as the other. NUL terminator prevents prefix
	// extension attacks.
	handshakeInitiatorDomainTag = "QUANTAUREUM_P2P_HANDSHAKE_INIT_V1\x00"
	handshakeResponderDomainTag = "QUANTAUREUM_P2P_HANDSHAKE_RESP_V1\x00"
)

// verifyResponderPoW verifies that the responder has performed sufficient PoW.
// This prevents Sybil attacks where an attacker could create many fake identities
// without spending computational resources on PoW.
//
// CRITICAL FIX: This verification must be called in InitiatorHandshake before
// accepting any connection from a remote responder. Without this check, an attacker
// could bypass Sybil protection by initiating cheap connections to honest nodes.
//
// P2P-P1-01 FIX (R31, 2026-07-27): Previously this function required the remote
// node to carry an ENR record with a "pow" entry. discv4 nodes do not have an
// ENR, so they could not be dialed by the initiator — even though ValidateNodeID
// (discovery layer) was already relaxed to accept discv4 peers. This broke the
// end-to-end discv4 compatibility story declared in R30/P2P-C03.
//
// The fix adds an optional `authResp` parameter. The verification order is:
//  1. If remoteNode has an ENR with a "pow" entry, use the ENR nonce (discv5 path).
//     If authResp is also available and its PowNonce differs from the ENR nonce,
//     reject — this is a defense-in-depth check against stripping/replay.
//  2. Otherwise, fall back to authResp.PowNonce (discv4 path). The PowNonce field
//     is covered by the responder's Dilithium3 signature over the response, so an
//     attacker cannot strip or replace it without invalidating the signature.
//  3. If neither source provides a nonce, fail-closed.
//
// The authResp parameter may be nil when the caller has not yet decoded the
// response (no caller currently passes nil, but the signature permits it for
// future code paths that want to verify PoW before decoding the full response).
func verifyResponderPoW(remoteNode *enode.Node, authResp *AuthResponsePQ) error {
	if remoteNode == nil {
		// Without a remote node we cannot compute the node ID used by PoW.
		// Fail-closed — do not silently skip verification.
		return fmt.Errorf("%w: remote node is nil", ErrInvalidProofOfWork)
	}

	nodeID := remoteNode.ID()
	var enrNonce *uint64
	if record := remoteNode.Record(); record != nil {
		if powBytes, ok := record.Get("pow"); ok {
			if len(powBytes) != 8 {
				return fmt.Errorf("%w: invalid PoW nonce length in ENR: expected 8, got %d", ErrInvalidProofOfWork, len(powBytes))
			}
			n := binary.BigEndian.Uint64(powBytes)
			enrNonce = &n
		}
	}

	// Pick the nonce to verify, with cross-validation between sources.
	var nonceToVerify uint64
	switch {
	case enrNonce != nil && authResp != nil:
		// Both sources present — they MUST agree. A mismatch indicates either
		// an attacker tampered with one of the fields, or the responder is
		// advertising a different PoW to different peers (which would be
		// pointless because PoW is bound to the node ID). Either way, reject.
		if *enrNonce != authResp.PowNonce {
			return fmt.Errorf("%w: ENR PoW nonce (%d) != response PoW nonce (%d) for node %v",
				ErrInvalidProofOfWork, *enrNonce, authResp.PowNonce, nodeID)
		}
		nonceToVerify = *enrNonce
	case enrNonce != nil:
		// discv5 path: ENR present, response not yet decoded (or PowNonce=0
		// because the responder is a legacy node that didn't include it).
		// The legacy case (authResp==nil) is fine — the ENR is the only source.
		// The authResp.PowNonce==0 case is also fine for legacy responders, but
		// we still verify the ENR nonce below.
		nonceToVerify = *enrNonce
	case authResp != nil:
		// discv4 path: no ENR, use the response's PowNonce. This is the path
		// that P2P-P1-01 specifically fixes. The nonce is signed by the
		// responder's Dilithium3 key (see signData in
		// ResponderHandshakeWithStore), so it cannot be forged.
		nonceToVerify = authResp.PowNonce
	default:
		// Neither source provides a nonce. Fail-closed to prevent Sybil bypass.
		return fmt.Errorf("%w: responder has no PoW nonce in ENR or auth response for node %v",
			ErrInvalidProofOfWork, nodeID)
	}

	// Verify the PoW meets the difficulty requirement using centralized sybil protection
	if !discover.VerifyProofOfWork(nodeID, nonceToVerify) {
		return fmt.Errorf("%w: insufficient PoW difficulty for node %v (nonce=%d)",
			ErrInvalidProofOfWork, nodeID, nonceToVerify)
	}

	return nil
}

var (
	// ErrInvalidHandshakeMessage is returned when handshake message is malformed
	ErrInvalidHandshakeMessage = errors.New("invalid handshake message")

	// ErrHandshakeTimeout is returned when handshake times out
	ErrHandshakeTimeout = errors.New("handshake timeout")

	// ErrInvalidProtocolVersion is returned when protocol version doesn't match
	ErrInvalidProtocolVersion = errors.New("invalid protocol version")

	// ErrSignatureVerificationFailed is returned when signature verification fails
	ErrSignatureVerificationFailed = errors.New("signature verification failed")

	// ErrMissingPublicKey is returned when remote node's public key is not available
	ErrMissingPublicKey = errors.New("remote node public key not available")

	// ErrInvalidProofOfWork is returned when PoW verification fails
	ErrInvalidProofOfWork = errors.New("insufficient proof-of-work")

	// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): ErrHandshakeReplay is returned when
	// a handshake message is detected as a replay (same peerID + nonce already seen
	// within the cache TTL). This is a distinct error from ErrInvalidHandshakeMessage
	// so that callers and operators can distinguish "malformed message" from
	// "replay attack detected" — the latter is a stronger security signal that may
	// warrant peer blacklisting or alerting.
	ErrHandshakeReplay = errors.New("handshake replay detected")
)

// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): handshakeReplayCache tracks
// (peerID + nonce) pairs that have been observed in successfully-decoded
// handshake messages. If the same pair appears again within the cache's TTL,
// the handshake is rejected as a replay.
//
// Design:
//   - Key: 64-byte concatenation of peerID (32) + nonce (32). This uniquely
//     identifies a handshake attempt from a specific peer with a specific
//     nonce. Using both peerID and nonce (rather than just nonce) allows
//     different peers to use the same nonce without false positives —
//     nonces are random 32-byte values so collisions are astronomically
//     unlikely, but defense-in-depth is cheap here.
//   - Value: timestamp of when the entry was inserted (used for TTL-based
//     eviction).
//   - Eviction: When the cache exceeds maxReplayCacheEntries, ALL entries
//     older than handshakeReplayCacheTTL are purged. If the cache is still
//     over capacity after purging expired entries (indicating a burst of
//     handshakes within the TTL window), the oldest entries are evicted
//     regardless of TTL to bound memory usage. This is a simple
//     time-based LRU that avoids the overhead of a true LRU list.
//
// The cache is a package-level singleton (not per-Conn) because replays can
// target different connections — e.g., an attacker captures a handshake to
// connection A, then replays it to connection B. A per-Conn cache would not
// detect this.
type handshakeReplayCache struct {
	mu      sync.Mutex
	entries map[[64]byte]time.Time // key = peerID||nonce, value = insertion time
}

// globalReplayCache is the singleton instance used by decodeAuthMessagePQ and
// decodeAuthResponsePQ. It is initialized at package load time and never nil.
var globalReplayCache = &handshakeReplayCache{
	entries: make(map[[64]byte]time.Time),
}

// checkReplay verifies that the (peerID, nonce) pair has not been seen
// recently. Returns ErrHandshakeReplay if the pair is already in the cache
// (within the TTL). It does NOT insert into the cache.
//
// R33 P2P-01 FIX (2026-07-28): Previously checkAndRecord inserted the entry
// atomically with the check, BEFORE signature/PoW verification. An attacker
// could send a handshake with a victim's public peerID and a fake signature
// to poison the cache, blocking the legitimate peer for 30 seconds (DoS).
// Now callers MUST call commitReplay AFTER all verification (PoW + signature)
// succeeds. This mirrors the checkHandshakeReplay/commitHandshakeReplay split
// in p2p/encrypted_transport.go.
func (c *handshakeReplayCache) checkReplay(peerID enode.ID, nonce []byte) error {
	if len(nonce) != nonceSize {
		// Malformed nonce — don't pollute the cache, let the caller handle it.
		return fmt.Errorf("%w: invalid nonce length %d", ErrInvalidHandshakeMessage, len(nonce))
	}

	// Build the composite key: peerID (32 bytes) || nonce (32 bytes) = 64 bytes.
	var key [64]byte
	copy(key[:32], peerID[:])
	copy(key[32:], nonce)

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if this (peerID, nonce) pair is already in the cache and within TTL.
	if ts, exists := c.entries[key]; exists {
		if now.Sub(ts) < handshakeReplayCacheTTL {
			// REPLAY DETECTED: The same (peerID, nonce) pair was seen less than
			// handshakeReplayCacheTTL ago. This is a replay attack — reject it.
			//
			// We do NOT refresh the timestamp on a replay detection. This means
			// an attacker who replays the same message repeatedly will be rejected
			// each time, but the original entry will expire naturally after the TTL.
			// Refreshing would allow an attacker to keep the entry alive forever
			// by continuously replaying, potentially evicting legitimate entries.
			return fmt.Errorf("%w: peerID=%x nonce=%x already seen %s ago",
				ErrHandshakeReplay, peerID[:8], nonce[:8], now.Sub(ts).Round(time.Second))
		}
		// Entry exists but is expired — not a replay. The caller will commit
		// a fresh entry after verification succeeds.
	}

	return nil
}

// commitReplay inserts the (peerID, nonce) pair into the cache after all
// verification (PoW + signature) has succeeded. This prevents attackers from
// poisoning the cache with unverified handshakes.
//
// R33 P2P-01 FIX (2026-07-28): Split from checkAndRecord to implement the
// two-step check-then-commit pattern.
func (c *handshakeReplayCache) commitReplay(peerID enode.ID, nonce []byte) error {
	if len(nonce) != nonceSize {
		return fmt.Errorf("%w: invalid nonce length %d", ErrInvalidHandshakeMessage, len(nonce))
	}

	// Build the composite key: peerID (32 bytes) || nonce (32 bytes) = 64 bytes.
	var key [64]byte
	copy(key[:32], peerID[:])
	copy(key[32:], nonce)

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Purge expired entries if the cache is at capacity.
	if len(c.entries) >= maxReplayCacheEntries {
		c.purgeExpiredLocked(now)
		if len(c.entries) >= maxReplayCacheEntries {
			c.evictOldestLocked(maxReplayCacheEntries / 10) // evict 10% = 1000 entries
		}
	}

	// Record the (peerID, nonce) pair with the current timestamp.
	c.entries[key] = now
	return nil
}

// purgeExpiredLocked removes all entries older than handshakeReplayCacheTTL.
// MUST be called with c.mu held.
func (c *handshakeReplayCache) purgeExpiredLocked(now time.Time) {
	for key, ts := range c.entries {
		if now.Sub(ts) >= handshakeReplayCacheTTL {
			delete(c.entries, key)
		}
	}
}

// evictOldestLocked removes the n oldest entries from the cache, regardless
// of TTL. This is used as a last-resort memory-bounding measure when the
// cache is full and no entries have expired. MUST be called with c.mu held.
//
// Implementation: This is O(n log n) due to sorting, but it only runs when
// the cache is full AND no entries have expired (indicating a sustained
// handshake flood within the TTL window). In normal operation this path is
// never taken.
func (c *handshakeReplayCache) evictOldestLocked(n int) {
	if n <= 0 || len(c.entries) == 0 {
		return
	}

	// Build a slice of (key, timestamp) pairs sorted by timestamp.
	type entry struct {
		key [64]byte
		ts  time.Time
	}
	entries := make([]entry, 0, len(c.entries))
	for k, ts := range c.entries {
		entries = append(entries, entry{k, ts})
	}

	// Partial sort: we only need the n oldest entries. A full sort is simpler
	// and correct; the cache-full path is rare enough that O(n log n) is
	// acceptable.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ts.Before(entries[j].ts)
	})

	// Evict the first n entries (oldest).
	for i := 0; i < n && i < len(entries); i++ {
		delete(c.entries, entries[i].key)
	}
}

// resetForTesting clears the cache. Only used in tests to ensure a clean
// state between test cases. Production code MUST NOT call this.
func (c *handshakeReplayCache) resetForTesting() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[[64]byte]time.Time)
}

// NodeStore is an interface for looking up nodes by ID
type NodeStore interface {
	GetNode(id enode.ID) (*enode.Node, error)
}

// Conn represents a connection with its node store
type ConnWithStore struct {
	*Conn
	nodeStore NodeStore
}

// NewConnWithStore creates a new connection with node store
func NewConnWithStore(conn *Conn, store NodeStore) *ConnWithStore {
	return &ConnWithStore{
		Conn:      conn,
		nodeStore: store,
	}
}

// AuthMessagePQ represents the initiator's authentication message
type AuthMessagePQ struct {
	Version     uint8    // Protocol version (5)
	KyberPubKey []byte   // Kyber-768 public key (1184 bytes)
	Nonce       []byte   // Random nonce (32 bytes)
	Timestamp   uint64   // Unix timestamp for replay protection
	PowNonce    uint64   // PoW nonce for Sybil resistance
	Signature   []byte   // Dilithium3 signature
	InitiatorID enode.ID // Initiator's node ID
}

// AuthResponsePQ represents the responder's authentication response
type AuthResponsePQ struct {
	Version         uint8    // Protocol version (5)
	KyberCiphertext []byte   // Kyber-768 ciphertext (1088 bytes)
	Nonce           []byte   // Random nonce (32 bytes)
	Timestamp       uint64   // Unix timestamp for replay protection
	PowNonce        uint64   // PoW nonce for Sybil resistance (P2P-P1-01 FIX R31, 2026-07-27)
	Signature       []byte   // Dilithium3 signature
	ResponderID     enode.ID // Responder's node ID
}

// encodeAuthMessagePQ encodes an auth message to bytes
func encodeAuthMessagePQ(msg *AuthMessagePQ) []byte {
	// Calculate total size
	size := 1 + // version
		2 + len(msg.KyberPubKey) + // kyber pub key with length prefix
		2 + len(msg.Nonce) + // nonce with length prefix
		8 + // timestamp (uint64)
		8 + // powNonce (uint64)
		2 + len(msg.Signature) + // signature with length prefix
		len(msg.InitiatorID) // initiator ID

	buf := make([]byte, size)
	offset := 0

	// Version
	buf[offset] = msg.Version
	offset++

	// Kyber public key
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(msg.KyberPubKey))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 2
	copy(buf[offset:], msg.KyberPubKey)
	offset += len(msg.KyberPubKey)

	// Nonce
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(msg.Nonce))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 2
	copy(buf[offset:], msg.Nonce)
	offset += len(msg.Nonce)

	// Timestamp for replay protection
	binary.BigEndian.PutUint64(buf[offset:], msg.Timestamp)
	offset += 8

	// PoW nonce for Sybil resistance
	binary.BigEndian.PutUint64(buf[offset:], msg.PowNonce)
	offset += 8

	// Signature
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(msg.Signature))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 2
	copy(buf[offset:], msg.Signature)
	offset += len(msg.Signature)

	// Initiator ID
	copy(buf[offset:], msg.InitiatorID[:])

	return buf
}

// decodeAuthMessagePQ decodes an auth message from bytes
func decodeAuthMessagePQ(data []byte) (*AuthMessagePQ, error) {
	// Minimum size: version(1) + keyLen(2) + kyberPubKey(1184) + nonceLen(2) + nonce(32) + timestamp(8) + powNonce(8) + sigLen(2) + sig(3293) + initiatorID(32)
	minSize := 1 + 2 + kyberPublicKeySize + 2 + nonceSize + 8 + 8 + 2 + dilithiumSignatureSize + 32
	if len(data) < minSize {
		return nil, ErrInvalidHandshakeMessage
	}

	msg := &AuthMessagePQ{}
	offset := 0

	// Version
	msg.Version = data[offset]
	offset++

	if msg.Version != protocolVersionPQ {
		return nil, ErrInvalidProtocolVersion
	}

	// Kyber public key - SECURITY FIX: Validate exact length
	keyLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if int(keyLen) != kyberPublicKeySize {
		return nil, fmt.Errorf("%w: invalid Kyber public key length: expected %d, got %d", ErrInvalidHandshakeMessage, kyberPublicKeySize, keyLen)
	}
	if offset+int(keyLen) > len(data) {
		return nil, ErrInvalidHandshakeMessage
	}
	msg.KyberPubKey = make([]byte, keyLen)
	copy(msg.KyberPubKey, data[offset:offset+int(keyLen)])
	offset += int(keyLen)

	// Nonce
	nonceLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if int(nonceLen) != nonceSize {
		return nil, fmt.Errorf("%w: invalid nonce length: expected %d, got %d", ErrInvalidHandshakeMessage, nonceSize, nonceLen)
	}
	if offset+int(nonceLen) > len(data) {
		return nil, ErrInvalidHandshakeMessage
	}
	msg.Nonce = make([]byte, nonceLen)
	copy(msg.Nonce, data[offset:offset+int(nonceLen)])
	offset += int(nonceLen)

	// Timestamp - SECURITY FIX: Validate timestamp for replay protection
	msg.Timestamp = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	// R21-MEDIUM FIX: Use time.Duration arithmetic directly to avoid float64 precision loss
	// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): Window reduced from 60s to 15s.
	now := time.Now()
	window := handshakeTimestampWindow
	if msg.Timestamp < uint64(now.Add(-window).Unix()) || msg.Timestamp > uint64(now.Add(window).Unix()) { //nolint:gosec,G115
		return nil, fmt.Errorf("%w: timestamp outside acceptable window", ErrInvalidHandshakeMessage)
	}

	// PoW nonce - CRITICAL FIX: Verify proof-of-work before accepting connection
	msg.PowNonce = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Signature - SECURITY FIX: Validate exact length
	sigLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if int(sigLen) != dilithiumSignatureSize {
		return nil, fmt.Errorf("%w: invalid signature length: expected %d, got %d", ErrInvalidHandshakeMessage, dilithiumSignatureSize, sigLen)
	}
	if offset+int(sigLen) > len(data) {
		return nil, ErrInvalidHandshakeMessage
	}
	msg.Signature = make([]byte, sigLen)
	copy(msg.Signature, data[offset:offset+int(sigLen)])
	offset += int(sigLen)

	// Initiator ID
	if offset+32 > len(data) {
		return nil, ErrInvalidHandshakeMessage
	}
	copy(msg.InitiatorID[:], data[offset:offset+32])

	// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): Check the global replay cache
	// AFTER successfully decoding all fields (including the signature and
	// InitiatorID). We check the (InitiatorID, Nonce) pair so that a replayed
	// handshake message — even to a different connection — is rejected.
	//
	// R33 P2P-01 FIX (2026-07-28): Only CHECK here, do NOT record. Recording
	// happens in commitReplay, called by ResponderHandshakeWithStore AFTER
	// PoW + signature verification succeeds. This prevents an attacker from
	// poisoning the cache with a victim's peerID + fake signature, which
	// would block the legitimate peer for 30 seconds.
	if err := globalReplayCache.checkReplay(msg.InitiatorID, msg.Nonce); err != nil {
		return nil, err
	}

	return msg, nil
}

// encodeAuthResponsePQ encodes an auth response to bytes
//
// P2P-P1-01 FIX (R31, 2026-07-27): Added 8-byte PowNonce field after Timestamp
// so the responder can prove its Sybil-resistance PoW without depending on ENR.
// This is required for discv4 compatibility — discv4 nodes do not carry an ENR
// record, so the initiator cannot read the PoW nonce from ENR during
// verifyResponderPoW. By embedding PowNonce in the response itself, we restore
// Sybil protection for both discv4 and discv5 peers. The PowNonce is also
// covered by the Dilithium3 signature (see signData in ResponderHandshakeWithStore)
// to prevent an attacker from stripping or replacing it.
func encodeAuthResponsePQ(resp *AuthResponsePQ) []byte {
	// Calculate total size
	size := 1 + // version
		2 + len(resp.KyberCiphertext) + // kyber ciphertext with length prefix
		2 + len(resp.Nonce) + // nonce with length prefix
		8 + // timestamp (uint64)
		8 + // powNonce (uint64) — P2P-P1-01 FIX
		2 + len(resp.Signature) + // signature with length prefix
		len(resp.ResponderID) // responder ID

	buf := make([]byte, size)
	offset := 0

	// Version
	buf[offset] = resp.Version
	offset++

	// Kyber ciphertext
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(resp.KyberCiphertext))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 2
	copy(buf[offset:], resp.KyberCiphertext)
	offset += len(resp.KyberCiphertext)

	// Nonce
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(resp.Nonce))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 2
	copy(buf[offset:], resp.Nonce)
	offset += len(resp.Nonce)

	// Timestamp for replay protection
	binary.BigEndian.PutUint64(buf[offset:], resp.Timestamp)
	offset += 8

	// PoW nonce for Sybil resistance (P2P-P1-01 FIX)
	binary.BigEndian.PutUint64(buf[offset:], resp.PowNonce)
	offset += 8

	// Signature
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(resp.Signature))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 2
	copy(buf[offset:], resp.Signature)
	offset += len(resp.Signature)

	// Responder ID
	copy(buf[offset:], resp.ResponderID[:])

	return buf
}

// decodeAuthResponsePQ decodes an auth response from bytes
//
// P2P-P1-01 FIX (R31, 2026-07-27): Added decoding of 8-byte PowNonce field
// after Timestamp. The field is mandatory (not optional/length-prefixed) to
// keep the wire format fixed-width and prevent a downgrade attack where an
// attacker strips the field to bypass Sybil protection. The minimum size
// constant (MinAuthResponseSize) was updated accordingly, so any response
// missing the field is rejected before reaching this decoder.
func decodeAuthResponsePQ(data []byte) (*AuthResponsePQ, error) {
	// Minimum size: version(1) + ctLen(2) + ciphertext(1088) + nonceLen(2) + nonce(32) + timestamp(8) + powNonce(8) + sigLen(2) + sig(3293) + responderID(32)
	minSize := 1 + 2 + kyberCiphertextSize + 2 + nonceSize + 8 + 8 + 2 + dilithiumSignatureSize + 32
	if len(data) < minSize {
		return nil, ErrInvalidHandshakeMessage
	}

	resp := &AuthResponsePQ{}
	offset := 0

	// Version
	resp.Version = data[offset]
	offset++

	if resp.Version != protocolVersionPQ {
		return nil, ErrInvalidProtocolVersion
	}

	// Kyber ciphertext - SECURITY FIX: Validate exact length
	ctLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if int(ctLen) != kyberCiphertextSize {
		return nil, fmt.Errorf("%w: invalid Kyber ciphertext length: expected %d, got %d", ErrInvalidHandshakeMessage, kyberCiphertextSize, ctLen)
	}
	if offset+int(ctLen) > len(data) {
		return nil, ErrInvalidHandshakeMessage
	}
	resp.KyberCiphertext = make([]byte, ctLen)
	copy(resp.KyberCiphertext, data[offset:offset+int(ctLen)])
	offset += int(ctLen)

	// Nonce
	nonceLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if int(nonceLen) != nonceSize {
		return nil, fmt.Errorf("%w: invalid nonce length: expected %d, got %d", ErrInvalidHandshakeMessage, nonceSize, nonceLen)
	}
	if offset+int(nonceLen) > len(data) {
		return nil, ErrInvalidHandshakeMessage
	}
	resp.Nonce = make([]byte, nonceLen)
	copy(resp.Nonce, data[offset:offset+int(nonceLen)])
	offset += int(nonceLen)

	// Timestamp - SECURITY FIX: Validate timestamp for replay protection
	resp.Timestamp = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	// R22-M1 FIX: Use time.Duration arithmetic directly to avoid float64 precision loss
	// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): Window reduced from 60s to 15s.
	now := time.Now()
	window := handshakeTimestampWindow
	if resp.Timestamp < uint64(now.Add(-window).Unix()) || resp.Timestamp > uint64(now.Add(window).Unix()) { //nolint:gosec,G115
		return nil, fmt.Errorf("%w: timestamp outside acceptable window", ErrInvalidHandshakeMessage)
	}

	// PoW nonce (P2P-P1-01 FIX R31, 2026-07-27): mandatory 8-byte field. Used
	// by the initiator to verify the responder's Sybil-resistance PoW when the
	// responder has no ENR (discv4 nodes). When the responder DOES have an ENR
	// with a "pow" entry, the initiator cross-checks both sources and rejects
	// on mismatch (defense-in-depth against stripping/replay).
	if offset+8 > len(data) {
		return nil, ErrInvalidHandshakeMessage
	}
	resp.PowNonce = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Signature - SECURITY FIX: Validate exact length
	sigLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if int(sigLen) != dilithiumSignatureSize {
		return nil, fmt.Errorf("%w: invalid signature length: expected %d, got %d", ErrInvalidHandshakeMessage, dilithiumSignatureSize, sigLen)
	}
	if offset+int(sigLen) > len(data) {
		return nil, ErrInvalidHandshakeMessage
	}
	resp.Signature = make([]byte, sigLen)
	copy(resp.Signature, data[offset:offset+int(sigLen)])
	offset += int(sigLen)

	// Responder ID
	if offset+32 > len(data) {
		return nil, ErrInvalidHandshakeMessage
	}
	copy(resp.ResponderID[:], data[offset:offset+32])

	// P2-REPLAY-WINDOW FIX (R29, 2026-07-26): Check the global replay cache for
	// the responder's (ResponderID, Nonce) pair. Same rationale as in
	// decodeAuthMessagePQ: place the check at the end because ResponderID is
	// the last field.
	//
	// R33 P2P-01 FIX (2026-07-28): Only CHECK here, do NOT record. Recording
	// happens in commitReplay, called by InitiatorHandshake AFTER PoW +
	// signature verification succeeds.
	if err := globalReplayCache.checkReplay(resp.ResponderID, resp.Nonce); err != nil {
		return nil, err
	}

	return resp, nil
}

// deriveSessionKeys derives session keys using HKDF-SHA3-256
// SHARED INTERFACE: Must match Wallet's deriveAESKey in hybrid-encryption.ts:60
// Algorithm: HKDF-SHA3-256(sharedSecret, salt, info)
// Version: v2.0 - Both sides use SHA3-256 for quantum-safe key derivation (256-bit security)
// SECURITY: SHA3-256 provides 256-bit security against quantum attacks vs 128-bit for SHA256
//
// R37-FIX P1-P2P-01 (2026-07-30): DIRECTIONAL key layout. Both sides call this
// with (initiatorNonce, responderNonce) in the SAME order and therefore derive
// identical key material. The returned keys are direction-labeled so that
// each side can pick its own send/receive keys WITHOUT any swapping:
//
//	encKeyAB  — AES key for initiator→responder traffic (init.AES / resp.IngressAES)
//	encKeyBA  — AES key for responder→initiator traffic (resp.AES / init.IngressAES)
//	macSecret — shared HMAC key for computeMAC/rollMACState (both directions)
//	macKeyAB  — initial rolling-MAC state for initiator→responder (init.EgressMAC / resp.IngressMAC)
//	macKeyBA  — initial rolling-MAC state for responder→initiator (resp.EgressMAC / init.IngressMAC)
//
// This preserves the R40-C6 key-separation principle (AES keys are never used
// as MAC state) while guaranteeing init.EgressMAC == resp.IngressMAC and
// resp.EgressMAC == init.IngressMAC. CTR IVs are taken from the directional
// MAC state (see initEncryption), which aligns them automatically.
func deriveSessionKeys(sharedSecret, initiatorNonce, responderNonce []byte) (encKeyAB, encKeyBA, macSecret, macKeyAB, macKeyBA []byte, err error) {
	info := make([]byte, 0, 20+len(initiatorNonce)+len(responderNonce))
	info = append(info, []byte("quantaureum-p2p-v5")...)
	info = append(info, 0x00)
	info = append(info, initiatorNonce...)
	info = append(info, 0x00)
	info = append(info, responderNonce...)

	hkdf := hkdf.New(sha3.New256, sharedSecret, nil, info)
	keyMaterial := make([]byte, derivedKeySize)
	if _, err := io.ReadFull(hkdf, keyMaterial); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	// Split into five 32-byte keys (R37-FIX P1-P2P-01: directional layout).
	// R47-M2 FIX: Copy key material into independent slices, then zero the
	// combined buffer. Without copies, the returned keys would be views into
	// keyMaterial and zeroing it would corrupt the returned keys.
	encKeyAB = make([]byte, 32)
	encKeyBA = make([]byte, 32)
	macSecret = make([]byte, 32)
	macKeyAB = make([]byte, 32)
	macKeyBA = make([]byte, 32)
	copy(encKeyAB, keyMaterial[0:32])
	copy(encKeyBA, keyMaterial[32:64])
	copy(macSecret, keyMaterial[64:96])
	copy(macKeyAB, keyMaterial[96:128])
	copy(macKeyBA, keyMaterial[128:160])
	crypto.ZeroBytesSecure(keyMaterial) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck

	return encKeyAB, encKeyBA, macSecret, macKeyAB, macKeyBA, nil
}

// InitiatorHandshake performs the initiator side of the post-quantum handshake
func (c *Conn) InitiatorHandshake(localPrivKey *crypto.PrivateKey, remoteNode *enode.Node) error {
	// Set handshake timeout.
	//
	// P2-DEADLINE FIX (R29, 2026-07-26): Previously the SetDeadline error was
	// silently ignored (#nosec G104). If SetDeadline fails, the handshake has
	// no timeout — a malicious peer could stall the handshake forever, tying
	// up a goroutine and preventing the connection from being cleaned up.
	// The handshake timeout is security-critical: it bounds the window for
	// PoW computation, replay attack attempts, and resource exhaustion. Now
	// we return the error so the caller closes the connection. The defer
	// that clears the deadline also logs on error (cleanup path).
	if err := c.conn.SetDeadline(time.Now().Add(handshakeTimeoutPQ)); err != nil {
		return fmt.Errorf("failed to set handshake deadline: %w", err)
	}
	defer func() {
		if err := c.conn.SetDeadline(time.Time{}); err != nil {
			// Log warning — the connection is about to be closed anyway, but
			// a failure to clear the deadline indicates a connection-state
			// issue that may affect the next handshake on the same conn.
			logging.Global().Warn("InitiatorHandshake: failed to clear deadline",
				map[string]any{"error": err.Error()})
		}
	}()

	// Get remote node ID
	remoteNodeID := remoteNode.ID()

	// Generate ephemeral Kyber key pair
	kyberKeyPair, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return fmt.Errorf("%w: failed to generate Kyber key pair: %v", ErrHandshakeFailed, err)
	}
	// audit-fix LEGACY-2: Use Zeroize for deterministic multi-pass key zeroing
	defer kyberKeyPair.Private.Zeroize()

	// Generate nonce
	localNonce := make([]byte, nonceSize)
	if _, err := rand.Read(localNonce); err != nil {
		return fmt.Errorf("%w: failed to generate nonce: %v", ErrHandshakeFailed, err)
	}

	// Get Kyber public key bytes
	kyberPubKeyBytes, err := kyberKeyPair.Public.Bytes()
	if err != nil {
		return fmt.Errorf("%w: failed to serialize Kyber public key: %v", ErrHandshakeFailed, err)
	}

	// Create auth message with timestamp for replay protection
	authMsg := &AuthMessagePQ{
		Version:     protocolVersionPQ,
		KyberPubKey: kyberPubKeyBytes,
		Nonce:       localNonce,
		Timestamp:   uint64(time.Now().Unix()), // #nosec G115 -- value range verified by caller
		PowNonce:    c.powNonce,                // CRITICAL FIX: Include PoW nonce for Sybil resistance
		InitiatorID: c.localID,
	}

	// Sign the auth message (sign: domainTag || version || kyberPubKey || nonce || timestamp || initiatorID)
	// CRYPTO-R18-CRIT-01 (2026-07-24): Added domain separation tag prefix.
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], authMsg.Timestamp)
	signData := make([]byte, 0, len(handshakeInitiatorDomainTag)+1+len(authMsg.KyberPubKey)+len(authMsg.Nonce)+8+32)
	signData = append(signData, handshakeInitiatorDomainTag...)
	signData = append(signData, authMsg.Version)
	signData = append(signData, authMsg.KyberPubKey...)
	signData = append(signData, authMsg.Nonce...)
	signData = append(signData, timestampBytes[:]...)
	signData = append(signData, authMsg.InitiatorID[:]...)

	signature, err := crypto.Sign(localPrivKey, signData)
	if err != nil {
		return fmt.Errorf("%w: failed to sign auth message: %v", ErrHandshakeFailed, err)
	}
	authMsg.Signature = signature

	// Encode and send auth message with 2-byte length prefix
	authMsgBytes := encodeAuthMessagePQ(authMsg)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(authMsgBytes))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	if _, err := c.conn.Write(append(lenBuf, authMsgBytes...)); err != nil {
		return fmt.Errorf("%w: failed to send auth message: %v", ErrHandshakeFailed, err)
	}

	// Read auth response using length-prefix protocol
	if _, err := io.ReadFull(c.conn, lenBuf); err != nil {
		return fmt.Errorf("%w: failed to read response length: %v", ErrHandshakeFailed, err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	if respLen < uint16(MinAuthResponseSize) || respLen > uint16(MaxAuthResponseSize) {
		return fmt.Errorf("%w: invalid response length %d", ErrHandshakeFailed, respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(c.conn, respBuf); err != nil {
		return fmt.Errorf("%w: failed to read auth response: %v", ErrHandshakeFailed, err)
	}

	// Decode auth response
	authResp, err := decodeAuthResponsePQ(respBuf)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	// R33 P2P-14 FIX (2026-07-28): Defense-in-depth version check.
	// decodeAuthResponsePQ already rejects resp.Version != protocolVersionPQ,
	// but we re-check here so that even if the decoder is later refactored
	// to accept multiple versions (e.g., for protocol upgrades), the
	// initiator will STILL refuse any response not matching the version it
	// sent. This prevents a downgrade attack where a MITM tampers the
	// initiator's outbound version to a weaker value and the responder
	// replies with that weaker version — the initiator would detect the
	// mismatch and abort. The session keys are also bound to the version
	// via the "quantaureum-p2p-v5" info string in deriveSessionKeys, so a
	// version mismatch would also produce non-matching keys and fail at
	// the first encrypted frame.
	if authResp.Version != protocolVersionPQ {
		return fmt.Errorf("%w: response version %d does not match expected %d (downgrade attempt?)",
			ErrInvalidProtocolVersion, authResp.Version, protocolVersionPQ)
	}

	// CRITICAL FIX: Verify responder's PoW BEFORE accepting the connection
	// This prevents Sybil attacks where an attacker creates many fake identities
	// without spending computational resources on PoW. The responder must prove
	// they did work by including a valid PoW nonce in their ENR.
	//
	// P2P-P1-01 FIX (R31, 2026-07-27): Pass the decoded authResp so that
	// verifyResponderPoW can fall back to authResp.PowNonce when the responder
	// is a discv4 node without an ENR. This closes the end-to-end discv4
	// compatibility gap left by R30/P2P-C03 (which only fixed the discovery
	// layer, not the connection layer).
	if err := verifyResponderPoW(remoteNode, authResp); err != nil {
		return fmt.Errorf("%w: responder PoW verification failed: %v", ErrHandshakeFailed, err)
	}

	// Verify responder ID matches expected remote node ID
	if subtle.ConstantTimeCompare(authResp.ResponderID[:], remoteNodeID[:]) != 1 {
		return fmt.Errorf("%w: responder ID mismatch", ErrHandshakeFailed)
	}

	// Verify Dilithium3 signature on auth response
	remotePubKey, err := getDilithiumPublicKey(remoteNode)
	if err != nil {
		return fmt.Errorf("%w: failed to get remote public key: %v", ErrHandshakeFailed, err)
	}

	if err := verifyAuthResponseSignature(authResp, remotePubKey); err != nil {
		return fmt.Errorf("%w: signature verification failed: %v", ErrHandshakeFailed, err)
	}

	// R33 P2P-01 FIX (2026-07-28): Commit the replay cache entry AFTER PoW +
	// signature verification succeeded. This prevents cache poisoning by
	// unverified handshakes (attacker sends victim's peerID + fake signature).
	if err := globalReplayCache.commitReplay(authResp.ResponderID, authResp.Nonce); err != nil {
		return fmt.Errorf("%w: failed to commit replay cache: %v", ErrHandshakeFailed, err)
	}

	// Decapsulate shared secret using Kyber
	sharedSecret, err := kyberKeyPair.Private.Decapsulate(authResp.KyberCiphertext)
	if err != nil {
		return fmt.Errorf("%w: failed to decapsulate shared secret: %v", ErrHandshakeFailed, err)
	}
	defer crypto.ZeroBytesSecure(sharedSecret)

	// Derive session keys
	// R37-FIX P1-P2P-01 (2026-07-30): Directional keys — no swapping needed.
	// Both sides call deriveSessionKeys with (initiatorNonce, responderNonce)
	// in the same order and pick direction-labeled keys.
	encKeyAB, encKeyBA, macSecret, macKeyAB, macKeyBA, err := deriveSessionKeys(sharedSecret, localNonce, authResp.Nonce)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	// Store secrets (initiator = "A" side):
	//   AES        = encKeyAB (encrypt A→B)        — responder decrypts with IngressAES=encKeyAB
	//   IngressAES = encKeyBA (decrypt B→A)        — responder encrypts with AES=encKeyBA
	//   EgressMAC  = macKeyAB (MAC state A→B)      — responder's IngressMAC=macKeyAB
	//   IngressMAC = macKeyBA (MAC state B→A)      — responder's EgressMAC=macKeyBA
	// R33 P2P-13 FIX (2026-07-28): IngressAES is the dedicated AES decryption
	// key that is never rolled; IngressMAC is the MAC state that gets rolled
	// after each frame.
	c.secrets = &Secrets{
		AES:        encKeyAB,
		MAC:        macSecret,
		EgressMAC:  macKeyAB,
		IngressMAC: macKeyBA,
		IngressAES: encKeyBA,
	}

	// Initialize encryption
	if err := c.initEncryption(); err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	c.remoteID = authResp.ResponderID
	// R37-FIX P1-P2P-02 (2026-07-30): Lock in the canonical MAC AAD order
	// initiatorID||responderID. As the initiator, localID is the initiator.
	c.setMacAAD(true)
	c.handshakeDone = true
	// R20-C2 FIX: Reset sequence counters after successful handshake.
	// Both sides start at sequence 1 (0 is invalid).
	c.readSeq = 0
	c.writeSeq = 0

	return nil
}

// ResponderHandshake performs the responder side of the post-quantum handshake
func (c *Conn) ResponderHandshake(localPrivKey *crypto.PrivateKey) error {
	return c.ResponderHandshakeWithStore(localPrivKey, nil)
}

// ResponderHandshakeWithStore performs the responder side of the post-quantum handshake
// with optional NodeStore for signature verification.
// If nodeStore is provided, the initiator's signature will be verified against their
// Dilithium3 public key from the ENR record.
//
// SECURITY (audit P2P-13): PoW and timestamp are verified after full message decode.
// The previous "early PoW" prefix parsing was removed because it was broken (bad
// offset), dead (nonce discarded), and redundant (timestamp already checked in
// decodeAuthMessagePQ). The InitiatorID needed for PoW verification is at the end
// of the message, so early verification from a small prefix is not possible.
func (c *Conn) ResponderHandshakeWithStore(localPrivKey *crypto.PrivateKey, nodeStore NodeStore) error {
	// Set handshake timeout.
	//
	// P2-DEADLINE FIX (R29, 2026-07-26): Previously the SetDeadline error was
	// silently ignored (#nosec G104). If SetDeadline fails, the handshake has
	// no timeout — a malicious peer could stall the handshake forever, tying
	// up a goroutine and preventing the connection from being cleaned up.
	// The handshake timeout is security-critical: it bounds the window for
	// PoW computation, replay attack attempts, and resource exhaustion. Now
	// we return the error so the caller closes the connection. The defer
	// that clears the deadline also logs on error (cleanup path).
	if err := c.conn.SetDeadline(time.Now().Add(handshakeTimeoutPQ)); err != nil {
		return fmt.Errorf("failed to set handshake deadline: %w", err)
	}
	defer func() {
		if err := c.conn.SetDeadline(time.Time{}); err != nil {
			logging.Global().Warn("ResponderHandshakeWithStore: failed to clear deadline",
				map[string]any{"error": err.Error()})
		}
	}()

	// Read auth message using length-prefix protocol
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, lenBuf); err != nil {
		return fmt.Errorf("%w: failed to read auth message length: %v", ErrHandshakeFailed, err)
	}
	authLen := binary.BigEndian.Uint16(lenBuf)
	if authLen < uint16(MinAuthMessageSize) || authLen > uint16(MaxAuthResponseSize) {
		return fmt.Errorf("%w: invalid auth message length %d", ErrHandshakeFailed, authLen)
	}

	// SECURITY (audit P2P-13): The previous "early PoW" prefix parsing was
	// removed — it was broken (offset calculation had an extra +2, reading
	// nonceLen from the wrong position), dead (the extracted PoW nonce was
	// discarded with `_ =`), and misleading (comments claimed "Early PoW
	// verification" but only validated the timestamp). The timestamp is
	// already validated inside decodeAuthMessagePQ, and PoW is verified
	// below after full decode (the InitiatorID needed for PoW verification
	// is at the END of the message, after the variable-length signature,
	// so it cannot be extracted from a small prefix anyway).
	authBuf := make([]byte, authLen)
	if _, err := io.ReadFull(c.conn, authBuf); err != nil {
		return fmt.Errorf("%w: failed to read auth message: %v", ErrHandshakeFailed, err)
	}

	// Decode auth message (validates version, field lengths, and timestamp)
	authMsg, err := decodeAuthMessagePQ(authBuf)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	// R33 P2P-14 FIX (2026-07-28): Defense-in-depth version check.
	// decodeAuthMessagePQ already rejects msg.Version != protocolVersionPQ,
	// but we re-check here so that even if the decoder is later refactored
	// to accept multiple versions, the responder will STILL refuse any
	// message not matching the only version it supports. This prevents a
	// downgrade attack where a MITM lowers the initiator's version field
	// to force a weaker protocol. The version is also bound to session
	// keys via the "quantaureum-p2p-v5" info string in deriveSessionKeys.
	if authMsg.Version != protocolVersionPQ {
		return fmt.Errorf("%w: initiator version %d does not match expected %d (downgrade attempt?)",
			ErrInvalidProtocolVersion, authMsg.Version, protocolVersionPQ)
	}

	// CRITICAL FIX: Verify proof-of-work to prevent Sybil attacks.
	// Requires computational work so an attacker cannot create many fake
	// identities cheaply. The InitiatorID and PowNonce are both needed
	// for verification, and InitiatorID is at the end of the message
	// (after the variable-length signature), so this must happen after
	// full decode.
	if !discover.VerifyProofOfWork(authMsg.InitiatorID, authMsg.PowNonce) {
		return fmt.Errorf("%w: proof-of-work verification failed for node %v", ErrHandshakeFailed, authMsg.InitiatorID)
	}

	// Signature verification: NodeStore is required for Dilithium signature verification.
	// PoW alone is not sufficient for identity verification - we need cryptographic
	// signature verification to bind the connection to a specific node identity.
	// H-NEW-2 FIX: Require NodeStore to not be nil to enforce signature verification.
	// CRITICAL FIX: Also check if nodeStore is a nil interface (not just nil value)
	if nodeStore == nil {
		return fmt.Errorf("%w: nodeStore is required for signature verification", ErrHandshakeFailed)
	}
	// CRITICAL FIX: Attempt to use nodeStore to verify it's not a nil interface with nil underlying value
	node, err := nodeStore.GetNode(authMsg.InitiatorID)
	if err != nil || node == nil {
		return fmt.Errorf("%w: nodeStore failed to return valid node (possible nil interface or lookup error): %v", ErrHandshakeFailed, err)
	}

	pubKey, err := getDilithiumPublicKey(node)
	if err != nil {
		return fmt.Errorf("%w: failed to get initiator public key: %v", ErrHandshakeFailed, err)
	}

	if err := verifyAuthMessageSignature(authMsg, pubKey); err != nil {
		return fmt.Errorf("%w: initiator signature verification failed: %v", ErrHandshakeFailed, err)
	}

	// R33 P2P-01 FIX (2026-07-28): Commit the replay cache entry AFTER PoW +
	// signature verification succeeded. This prevents cache poisoning by
	// unverified handshakes (attacker sends victim's peerID + fake signature).
	if err := globalReplayCache.commitReplay(authMsg.InitiatorID, authMsg.Nonce); err != nil {
		return fmt.Errorf("%w: failed to commit replay cache: %v", ErrHandshakeFailed, err)
	}

	// Parse Kyber public key
	kyberPubKey, err := crypto.KyberPublicKeyFromBytes(authMsg.KyberPubKey)
	if err != nil {
		return fmt.Errorf("%w: invalid Kyber public key: %v", ErrHandshakeFailed, err)
	}

	// Generate ephemeral Kyber key pair for encapsulation
	kyberKeyPair, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return fmt.Errorf("%w: failed to generate Kyber key pair: %v", ErrHandshakeFailed, err)
	}
	// audit-fix LEGACY-2: Use Zeroize for deterministic multi-pass key zeroing
	defer kyberKeyPair.Private.Zeroize()

	// Encapsulate shared secret
	sharedSecret, ciphertext, err := kyberKeyPair.Private.Exchange(kyberPubKey)
	if err != nil {
		return fmt.Errorf("%w: failed to encapsulate shared secret: %v", ErrHandshakeFailed, err)
	}
	defer crypto.ZeroBytesSecure(sharedSecret)

	// Generate nonce
	localNonce := make([]byte, nonceSize)
	if _, err := rand.Read(localNonce); err != nil {
		return fmt.Errorf("%w: failed to generate nonce: %v", ErrHandshakeFailed, err)
	}

	// Create auth response with timestamp for replay protection
	// P2P-P1-01 FIX (R31, 2026-07-27): Include PowNonce so the initiator can
	// verify the responder's Sybil-resistance PoW even when the responder has
	// no ENR (discv4 nodes). Without this field, an initiator dialing a discv4
	// responder would fail at verifyResponderPoW because there's no ENR to read
	// the nonce from.
	authResp := &AuthResponsePQ{
		Version:         protocolVersionPQ,
		KyberCiphertext: ciphertext,
		Nonce:           localNonce,
		Timestamp:       uint64(time.Now().Unix()), // #nosec G115 -- value range verified by caller
		PowNonce:        c.powNonce,                // P2P-P1-01 FIX: signed PoW nonce
		ResponderID:     c.localID,
	}

	// Sign the auth response (sign: domainTag || version || ciphertext || nonce || timestamp || powNonce || responderID)
	// CRYPTO-R18-CRIT-01 (2026-07-24): Added domain separation tag prefix.
	// P2P-P1-01 FIX (R31, 2026-07-27): PowNonce is now covered by the signature
	// to prevent stripping/replacement attacks. An attacker who removes or
	// modifies the PowNonce field would invalidate the signature.
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], authResp.Timestamp)
	var powNonceBytes [8]byte
	binary.BigEndian.PutUint64(powNonceBytes[:], authResp.PowNonce)
	signData := make([]byte, 0, len(handshakeResponderDomainTag)+1+len(authResp.KyberCiphertext)+len(authResp.Nonce)+8+8+32)
	signData = append(signData, handshakeResponderDomainTag...)
	signData = append(signData, authResp.Version)
	signData = append(signData, authResp.KyberCiphertext...)
	signData = append(signData, authResp.Nonce...)
	signData = append(signData, timestampBytes[:]...)
	signData = append(signData, powNonceBytes[:]...) // P2P-P1-01 FIX: sign PowNonce
	signData = append(signData, authResp.ResponderID[:]...)

	signature, err := crypto.Sign(localPrivKey, signData)
	if err != nil {
		return fmt.Errorf("%w: failed to sign auth response: %v", ErrHandshakeFailed, err)
	}
	authResp.Signature = signature

	// Encode and send auth response with 2-byte length prefix
	authRespBytes := encodeAuthResponsePQ(authResp)
	respLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(respLenBuf, uint16(len(authRespBytes))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	if _, err := c.conn.Write(append(respLenBuf, authRespBytes...)); err != nil {
		return fmt.Errorf("%w: failed to send auth response: %v", ErrHandshakeFailed, err)
	}

	// Derive session keys
	// R37-FIX P1-P2P-01 (2026-07-30): Directional keys — no swapping needed.
	// Nonces are passed in the SAME order as the initiator (initiatorNonce,
	// responderNonce), so both sides derive identical key material.
	encKeyAB, encKeyBA, macSecret, macKeyAB, macKeyBA, err := deriveSessionKeys(sharedSecret, authMsg.Nonce, localNonce)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	// Store secrets (responder = "B" side — picks the opposite directions):
	//   AES        = encKeyBA (encrypt B→A)        — initiator decrypts with IngressAES=encKeyBA
	//   IngressAES = encKeyAB (decrypt A→B)        — initiator encrypts with AES=encKeyAB
	//   EgressMAC  = macKeyBA (MAC state B→A)      — initiator's IngressMAC=macKeyBA
	//   IngressMAC = macKeyAB (MAC state A→B)      — initiator's EgressMAC=macKeyAB
	c.secrets = &Secrets{
		AES:        encKeyBA,
		MAC:        macSecret,
		EgressMAC:  macKeyBA,
		IngressMAC: macKeyAB,
		IngressAES: encKeyAB,
	}

	// Initialize encryption
	if err := c.initEncryption(); err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	c.remoteID = authMsg.InitiatorID
	// R37-FIX P1-P2P-02 (2026-07-30): Lock in the canonical MAC AAD order
	// initiatorID||responderID. As the responder, remoteID is the initiator.
	c.setMacAAD(false)
	c.handshakeDone = true
	// R20-C2 FIX: Reset sequence counters after successful handshake.
	// Both sides start at sequence 1 (0 is invalid).
	c.readSeq = 0
	c.writeSeq = 0

	return nil
}

// getDilithiumPublicKey retrieves the Dilithium3 public key from a node's ENR record
func getDilithiumPublicKey(node *enode.Node) (*crypto.PublicKey, error) {
	if node == nil {
		return nil, ErrMissingPublicKey
	}

	record := node.Record()
	if record == nil {
		return nil, fmt.Errorf("%w: node has no ENR record", ErrMissingPublicKey)
	}

	// Get Dilithium3 public key from ENR record
	pubKeyBytes, ok := record.Get("dilithium3")
	if !ok {
		return nil, fmt.Errorf("%w: dilithium3 key not found in ENR", ErrMissingPublicKey)
	}

	// Parse public key
	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid dilithium3 public key: %w", err)
	}

	return pubKey, nil
}

// verifyAuthMessageSignature verifies the Dilithium3 signature on an auth message
func verifyAuthMessageSignature(authMsg *AuthMessagePQ, pubKey *crypto.PublicKey) error {
	// Construct the message that was signed
	// CRYPTO-R18-CRIT-01 (2026-07-24): Message format now includes domain tag prefix:
	// domainTag || version || kyber_pub_key || nonce || timestamp || initiator_id
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], authMsg.Timestamp)
	msgSize := len(handshakeInitiatorDomainTag) + 1 + len(authMsg.KyberPubKey) + len(authMsg.Nonce) + 8 + len(authMsg.InitiatorID)
	message := make([]byte, msgSize)
	offset := 0

	copy(message[offset:], handshakeInitiatorDomainTag)
	offset += len(handshakeInitiatorDomainTag)

	message[offset] = authMsg.Version
	offset++

	copy(message[offset:], authMsg.KyberPubKey)
	offset += len(authMsg.KyberPubKey)

	copy(message[offset:], authMsg.Nonce)
	offset += len(authMsg.Nonce)

	copy(message[offset:], timestampBytes[:])
	offset += 8

	copy(message[offset:], authMsg.InitiatorID[:])

	// Verify signature
	if !pubKey.Verify(message, authMsg.Signature) {
		return ErrSignatureVerificationFailed
	}

	return nil
}

// verifyAuthResponseSignature verifies the Dilithium3 signature on an auth response
//
// P2P-P1-01 FIX (R31, 2026-07-27): The signed message now includes PowNonce
// between Timestamp and ResponderID, matching the signData layout in
// ResponderHandshakeWithStore. This binds the PoW nonce to the responder's
// signature so an attacker cannot strip or replace it without invalidating
// the signature.
func verifyAuthResponseSignature(authResp *AuthResponsePQ, pubKey *crypto.PublicKey) error {
	// Construct the message that was signed
	// CRYPTO-R18-CRIT-01 (2026-07-24): Message format now includes domain tag prefix:
	// domainTag || version || kyber_ciphertext || nonce || timestamp || powNonce || responder_id
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], authResp.Timestamp)
	var powNonceBytes [8]byte
	binary.BigEndian.PutUint64(powNonceBytes[:], authResp.PowNonce)
	msgSize := len(handshakeResponderDomainTag) + 1 + len(authResp.KyberCiphertext) + len(authResp.Nonce) + 8 + 8 + len(authResp.ResponderID)
	message := make([]byte, msgSize)
	offset := 0

	copy(message[offset:], handshakeResponderDomainTag)
	offset += len(handshakeResponderDomainTag)

	message[offset] = authResp.Version
	offset++

	copy(message[offset:], authResp.KyberCiphertext)
	offset += len(authResp.KyberCiphertext)

	copy(message[offset:], authResp.Nonce)
	offset += len(authResp.Nonce)

	copy(message[offset:], timestampBytes[:])
	offset += 8

	copy(message[offset:], powNonceBytes[:]) // P2P-P1-01 FIX: verify PowNonce
	offset += 8

	copy(message[offset:], authResp.ResponderID[:])

	// Verify signature
	if !pubKey.Verify(message, authResp.Signature) {
		return ErrSignatureVerificationFailed
	}

	return nil
}
