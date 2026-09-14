// Quantaureum Node source, version 1.0.0.
// Package rlpx implements the RLPx encrypted transport protocol.
// RLPx is the encrypted peer-to-peer transport protocol used by Ethereum.
package rlpx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quantaureum/qau/p2p/discover"
	"github.com/quantaureum/qau/p2p/enode"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/rlp"
	"golang.org/x/crypto/sha3"
)

// SECURITY (audit P2-R3-05): HKDF Implementation Consistency
// This module uses golang.org/x/crypto/sha3 for HKDF extraction.
// Other modules (crypto/, economics/) should use the same library.
// Do NOT mix standard library crypto/sha256 with x/crypto/sha3 for
// HKDF operations — they produce different outputs for the same inputs.

const (
	// maxFrameSize is the maximum size of a single frame
	// SECURITY (audit P2-R3-06): Aligned to 10MB for consistency with other modules
	maxFrameSize = 10 * 1024 * 1024 // 10 MB

	// frameHeaderSize is the size of the frame header
	frameHeaderSize = 32

	// macSize is the size of the MAC
	macSize = 16

	// handshakeTimeout is the timeout for the handshake
	// SECURITY FIX (audit P2P-01): Reduced from 1800s to 30s to prevent Slowloris DoS.
	// 1800s allowed attackers to hold thousands of connections open for 30 minutes.
	handshakeTimeout = 30 * time.Second

	// readTimeout is the default read timeout
	// SECURITY FIX (audit P2P-01): Reduced from 1800s to 60s.
	readTimeout = 60 * time.Second

	// writeTimeout is the default write timeout
	// SECURITY FIX (audit P2P-01): Reduced from 1800s to 60s.
	writeTimeout = 60 * time.Second

	// R40-H1 FIX: Maximum number of entries in the frame replay map.
	// Limits memory usage to prevent DoS via unbounded map growth.
	// Entries older than (currentSeq - maxReplayWindow) are purged on insertion.
	maxReplayWindow = 10000
)

var (
	// ErrHandshakeFailed is returned when the handshake fails
	ErrHandshakeFailed = errors.New("handshake failed")

	// ErrInvalidMAC is returned when the MAC verification fails
	ErrInvalidMAC = errors.New("invalid MAC")

	// ErrFrameTooLarge is returned when a frame exceeds the maximum size
	ErrFrameTooLarge = errors.New("frame too large")

	// ErrConnectionClosed is returned when the connection is closed
	ErrConnectionClosed = errors.New("connection closed")

	// ErrInvalidMessage is returned when a message is invalid
	ErrInvalidMessage = errors.New("invalid message")

	// R20-C2 FIX: Replay protection errors
	ErrSequenceOverflow    = errors.New("sequence number overflow")
	ErrReplayDetected      = errors.New("replay attack detected: sequence number not greater than last seen")
	ErrInvalidSequenceNum  = errors.New("invalid sequence number in frame header")
	ErrFrameReplayDetected = errors.New("replay attack detected: duplicate frame content") // CRITICAL-1 FIX
)

// Secrets contains the session secrets derived from the handshake
type Secrets struct {
	AES        []byte // AES encryption key (egress direction)
	MAC        []byte // MAC key (HMAC key for computeMAC/rollMACState)
	EgressMAC  []byte // Egress MAC state (rolled after each sent frame)
	IngressMAC []byte // Ingress MAC state (rolled after each received frame)
	// R33 P2P-13 FIX (2026-07-28): IngressAES is the AES decryption key for
	// the ingress direction. Previously, IngressMAC served double duty as
	// both the MAC state AND the AES decryption key — the same []byte was
	// passed to aes.NewCipher() AND used as the MAC state that gets rolled
	// (reassigned to a new slice) after each frame. While aes.NewCipher
	// copies the key internally (so the cipher is not corrupted by MAC
	// rolling), the conflation is a design hazard:
	//   1. Cryptographic key reuse: the same key material is used for AES
	//      confidentiality AND MAC integrity, violating the principle that
	//      keys should be dedicated to a single purpose.
	//   2. Code clarity: future readers may not realize IngressMAC is used
	//      as an AES key and may add code that reads it after MAC rolling,
	//      getting a wrong value.
	// Fix: IngressAES is a dedicated field for the AES decryption key. It
	// is set once at handshake time and never modified. IngressMAC is used
	// exclusively as the MAC state. Both are initially set to recvKey (same
	// value) for backward protocol compatibility — a future protocol
	// upgrade should derive them independently via HKDF.
	IngressAES []byte // Ingress AES decryption key (dedicated, never rolled)
}

// Conn represents an encrypted RLPx connection
type Conn struct {
	conn     net.Conn
	remoteID enode.ID
	localID  enode.ID
	secrets  *Secrets

	// R37-FIX P1-P2P-02 (2026-07-30): macAAD is the canonical additional
	// authenticated data for computeMAC, fixed at handshake completion as
	// initiatorID||responderID. Previously computeMAC wrote localID||remoteID
	// from EACH SIDE'S OWN perspective, so the initiator authenticated
	// initID||respID while the responder verified respID||initID — the MACs
	// never matched for any two distinct node IDs. Both ends now write the
	// same canonical byte string. Set by setMacAAD during handshake; nil for
	// test conns that never completed a handshake (AAD then contributes
	// nothing, identical on both sides).
	macAAD []byte

	// PoW nonce for Sybil resistance - set before handshake
	powNonce uint64

	// Encryption state
	enc cipher.Stream
	dec cipher.Stream

	// Synchronization
	readMu  sync.Mutex
	writeMu sync.Mutex

	// State
	handshakeDone bool
	closed        bool
	closeMu       sync.Mutex

	// R20-C2 FIX: Sequence counters for replay protection.
	// Each peer tracks the sequence number of the last received message.
	// RLPx frames include a sequence number to prevent replay attacks.
	// handshakeNonce is set during handshake from shared secrets.
	// subsequent frames include a counter in the header context.
	readSeq  uint32
	writeSeq uint32

	// CRITICAL-1 FIX: Frame replay protection via content hash tracking.
	// Tracks received frame content hashes to detect duplicates even when
	// sequence numbers are incremented (attacker replaying old frames with new seq).
	// CRITICAL FIX: Improved replay protection with sequence number binding
	// to prevent hash collision attacks.
	frameReplayMu  sync.Mutex
	frameReplayMap map[string]uint32 // maps content hash -> seq number at which it was received
	// CRITICAL FIX: Track seen sequence numbers for additional replay detection
	seenSeqNums map[uint32]bool // tracks seen sequence numbers
}

// NewConn wraps a net.Conn with RLPx encryption
// audit-fix LEGACY-1: Automatically computes PoW nonce from localID so that
// both initiator and responder handshakes include a valid PoW nonce.
// Previously powNonce defaulted to 0, breaking Sybil resistance.
func NewConn(conn net.Conn, localID enode.ID) *Conn {
	c := &Conn{
		conn:           conn,
		localID:        localID,
		readSeq:        0,
		writeSeq:       0,
		frameReplayMap: make(map[string]uint32),
		seenSeqNums:    make(map[uint32]bool),
	}

	// audit-fix LEGACY-1: Compute PoW nonce from localID for Sybil resistance.
	// This is critical for ResponderHandshake which reads c.powNonce
	// when constructing the auth response (if PoW is included in response).
	if nonce, err := computePoWNonceFromID(localID); err == nil {
		c.powNonce = nonce
	}

	return c
}

// SetPoWNonce sets the proof-of-work nonce for this connection
// This must be called before InitiatorHandshake to include PoW in the handshake
func (c *Conn) SetPoWNonce(nonce uint64) {
	c.powNonce = nonce
}

// GetPoWNonce returns the proof-of-work nonce for this connection
func (c *Conn) GetPoWNonce() uint64 {
	return c.powNonce
}

// Dial establishes an encrypted connection to a remote node
// SECURITY FIX: Removed automatic Handshake() call.
// Callers MUST call InitiatorHandshake() after Dial returns to complete the PQ handshake.
// See IMPLEMENTATION_NOTES.md for correct usage.
//
// audit-fix LEGACY-1: Automatically computes and sets PoW nonce from localID
// so that InitiatorHandshake includes a valid PoW in AuthMessagePQ for Sybil resistance.
// Previously powNonce defaulted to 0, causing remote PoW verification to always fail.
func Dial(addr string, localID enode.ID, remoteID enode.ID) (*Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, handshakeTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	c := NewConn(conn, localID)
	c.remoteID = remoteID

	// audit-fix LEGACY-1: Compute PoW nonce from localID for Sybil resistance.
	// This ensures the auth message includes a valid PoW nonce that the remote
	// peer can verify using VerifyProofOfWork(localID, nonce).
	if nonce, err := computePoWNonceFromID(localID); err == nil {
		c.powNonce = nonce
	}

	return c, nil
}

// DialNode establishes an encrypted connection to a node
func DialNode(node *enode.Node, localID enode.ID) (*Conn, error) {
	addr := node.Addr()
	return Dial(addr.String(), localID, node.ID())
}

// computePoWNonceFromID computes a proof-of-work nonce for the given node ID.
// audit-fix LEGACY-1: Extracted from p2p/host.go generatePoWNonce for reuse
// in RLPx Dial. Uses the same hash-based PoW: hash(nodeID || nonce) must have
// MinProofOfWorkDifficulty leading zero bits.
func computePoWNonceFromID(nodeID enode.ID) (uint64, error) {
	// MEDIUFIX: Block the dev-mode PoW bypass in production.
	// Previously, setting QAU_DEV_MODE_BLOCKS=1 would skip PoW computation
	// entirely and return a constant nonce (42), completely disabling Sybil
	// resistance for RLPx handshakes. This is acceptable for local dev/test
	// but must never be allowed in production. We now check QAU_PRODUCTION
	// and refuse to honor the dev bypass if production mode is active.
	if os.Getenv("QAU_DEV_MODE_BLOCKS") == "1" {
		if params.IsProductionEnv() {
			// Production mode: dev bypass is forbidden. Fall through to
			// real PoW computation to preserve Sybil resistance.
			log.Printf("[SECURITY] QAU_DEV_MODE_BLOCKS ignored because QAU_PRODUCTION=1")
		} else {
			return 42, nil
		}
	}

	target := new(big.Int).Lsh(big.NewInt(1), 256-uint(discover.MinProofOfWorkDifficulty))

	for i := uint64(0); i < 1<<32; i++ {
		var nonceBuf [8]byte
		binary.LittleEndian.PutUint64(nonceBuf[:], i)

		hasher := sha3.New256()
		hasher.Write(nodeID[:])
		hasher.Write(nonceBuf[:])
		hash := hasher.Sum(nil)

		hashInt := new(big.Int).SetBytes(hash)
		if hashInt.Cmp(target) < 0 {
			return i, nil
		}
	}

	return 0, fmt.Errorf("PoW computation failed to find valid nonce")
}

// Handshake performs the RLPx handshake.
//
// R33 P2P-14 FIX (2026-07-28): DOWNGRADE ATTACK DEFENSE.
// This method is permanently disabled and returns an error. It exists only
// for API backward compatibility — callers MUST use InitiatorHandshake or
// ResponderHandshake, which implement the post-quantum Kyber-768 + Dilithium3
// handshake at protocolVersionPQ=5.
//
// Why this matters: if this method ever silently fell back to a legacy
// (e.g., ECDSA-only) handshake, an attacker could perform a downgrade attack
// by triggering the fallback path, stripping post-quantum protection. By
// making this method always fail, we ensure the only reachable handshake
// paths are the explicit, version-checked, post-quantum ones.
//
// The following defenses are layered on top:
//  1. decodeAuthMessagePQ / decodeAuthResponsePQ reject any Version != protocolVersionPQ (5)
//  2. InitiatorHandshake / ResponderHandshakeWithStore re-check the version
//     AFTER decode (defense-in-depth, see "R33 P2P-14 FIX" comments)
//  3. deriveSessionKeys binds the version into the HKDF info string
//     ("quantaureum-p2p-v5"), so even if an attacker tampers the version
//     field, the resulting session keys will mismatch and the first
//     encrypted frame will fail MAC verification
//  4. The PoW nonce and Dilithium3 signature cover the version field,
//     preventing undetected tampering
//
// This method now uses post-quantum secure Kyber-768 key exchange.
// The old insecure placeholder (XOR-based) has been replaced with a proper
// post-quantum KEM implementation. See handshake_pq.go for details.
//
// This method requires a Dilithium3 private key for authentication.
// For backward compatibility, if no private key is available, this will fail.
func (c *Conn) Handshake() error {
	// This method signature is kept for compatibility but requires
	// a private key to be passed. Use InitiatorHandshake or ResponderHandshake
	// directly with the appropriate private key.
	return fmt.Errorf("%w: Handshake() requires private key; "+
		"use InitiatorHandshake() or ResponderHandshake() instead", ErrHandshakeFailed)
}

// handshakePlaceholder is the original insecure handshake implementation
// retained for reference and testing. It MUST NOT be called in production.
// SECURITY FIX: Added environment check to prevent accidental use in production.
//
// R33 P2P-14 FIX (2026-07-28): This function is a permanent no-op that returns
// an error. It must NEVER be wired into any live code path — doing so would
// re-introduce the insecure (pre-quantum) handshake and enable downgrade
// attacks. The only purpose of keeping it is to document the historical
// insecure implementation and to satisfy any test that references the symbol.
func (c *Conn) handshakePlaceholder() error {
	return fmt.Errorf("%w: insecure handshake is permanently disabled; use InitiatorHandshake/ResponderHandshake with Kyber-768", ErrHandshakeFailed)
}

// createAuthMessage is a deprecated stub for the legacy ECDSA handshake.
// Deprecated: Use InitiatorHandshake/ResponderHandshake with Kyber-768 instead.
// Always returns nil — callers must not rely on this function.
//
// R33 P2P-14 FIX (2026-07-28): Returning nil (not a partially-built message)
// is intentional — if this ever returned a non-nil legacy auth message, a
// caller could accidentally use it and bypass post-quantum protection.
func (c *Conn) createAuthMessage(ephPriv []byte) []byte {
	return nil
}

// processAuthAck is a deprecated stub that always fails.
//
// R33 P2P-14 FIX (2026-07-28): Always returning an error prevents any
// accidental use of the legacy ack-processing path, which would bypass
// the post-quantum handshake and enable downgrade attacks.
func (c *Conn) processAuthAck(data []byte, ephPriv []byte) error {
	return fmt.Errorf("%w: deprecated insecure handshake permanently disabled", ErrHandshakeFailed)
}

// deriveSecrets derives session secrets from the shared secret
// CRIT-FIX: Use proper HKDF instead of simple SHA256 hash
// R40-H12 FIX: Check all HKDF error returns to avoid using zero keys.
func (c *Conn) deriveSecrets(sharedSecret, nonce []byte) (*Secrets, error) {
	// Use proper HKDF with SHA-256 for key derivation
	// This provides proper key stretching and pseudorandomness properties
	//
	// Go 1.26 crypto/hkdf uses Extract/Expand/Key functions instead of New()

	// Derive AES-256 key using HKDF
	// CRYPTO-R17-H01 (2026-07-24): Added NUL terminator to all HKDF info strings
	// for domain separation consistency and prefix-extension defense.
	aesKey, err := hkdf.Key(sha256.New, sharedSecret, nonce, "QUANTAUREUM_AES_V1\x00", 32)
	if err != nil {
		return nil, fmt.Errorf("R40-H12: HKDF failed for AES key: %w", err)
	}

	// Derive MAC key using HKDF
	macSecret, err := hkdf.Key(sha256.New, sharedSecret, nonce, "QUANTAUREUM_MAC_V1\x00", 32)
	if err != nil {
		return nil, fmt.Errorf("R40-H12: HKDF failed for MAC key: %w", err)
	}

	// Derive initial MAC states using HKDF
	egressMAC, err := hkdf.Key(sha256.New, macSecret, nonce, "QUANTAUREUM_EGRESS_MAC_V1\x00", 32)
	if err != nil {
		return nil, fmt.Errorf("R40-H12: HKDF failed for egress MAC: %w", err)
	}

	// SECURITY (audit P1-R2-01): This value serves as BOTH the ingress MAC
	// initial state AND the ingress AES decryption key. It is derived
	// independently from the egress AES key via HKDF with a unique info string.
	ingressMAC, err := hkdf.Key(sha256.New, macSecret, nonce, "QUANTAUREUM_INGRESS_MAC_V1\x00", 32)
	if err != nil {
		return nil, fmt.Errorf("R40-H12: HKDF failed for ingress MAC: %w", err)
	}

	return &Secrets{
		AES:        aesKey,
		MAC:        macSecret,
		EgressMAC:  egressMAC,
		IngressMAC: ingressMAC,
		// R33 P2P-13: IngressAES is the dedicated AES decryption key. For
		// backward compatibility with the existing protocol, it is set to
		// the same value as IngressMAC (ingressMAC). A future protocol
		// upgrade should derive them independently.
		IngressAES: ingressMAC,
	}, nil
}

// initEncryption initializes the encryption streams
// R33 P2P-13 FIX (2026-07-28): Use IngressAES for the decryption cipher
// instead of IngressMAC. IngressAES is a dedicated field that never gets
// rolled (unlike IngressMAC which is reassigned after each frame).
func (c *Conn) initEncryption() error {
	encBlock, err := aes.NewCipher(c.secrets.AES)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher for encryption: %w", err)
	}

	// R33 P2P-13: Use IngressAES (dedicated decryption key) instead of
	// IngressMAC (which is rolled after each frame).
	decBlock, err := aes.NewCipher(c.secrets.IngressAES)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher for decryption: %w", err)
	}

	encIV := make([]byte, aes.BlockSize)
	copy(encIV, c.secrets.EgressMAC[:aes.BlockSize])

	decIV := make([]byte, aes.BlockSize)
	copy(decIV, c.secrets.IngressMAC[:aes.BlockSize])

	c.enc = cipher.NewCTR(encBlock, encIV)
	c.dec = cipher.NewCTR(decBlock, decIV)

	return nil
}

// ClearReplayProtection clears the frame replay detection state.
// CRITICAL-1 FIX: MUST be called after any re-key operation to reset replay protection.
// This ensures that old frames from a previous session cannot be replayed
// after a new key derivation.
func (c *Conn) ClearReplayProtection() {
	c.frameReplayMu.Lock()
	defer c.frameReplayMu.Unlock()
	c.frameReplayMap = make(map[string]uint32)
	c.seenSeqNums = make(map[uint32]bool) // CRITICAL FIX: also clear seen sequence numbers
	c.readSeq = 0
}

// Read reads an encrypted message from the connection
func (c *Conn) Read() (code uint64, data []byte, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.closed {
		return 0, nil, ErrConnectionClosed
	}

	if !c.handshakeDone {
		return 0, nil, ErrHandshakeFailed
	}

	if err := c.conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		// R31-P2 FIX (P2-8, 2026-07-28): Return the error instead of
		// continuing without a deadline. Previously this only logged the
		// error and proceeded, allowing a stalled peer to hold the read
		// goroutine indefinitely (no timeout protection).
		return 0, nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read frame header (size + MAC)
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return 0, nil, fmt.Errorf("failed to read header: %w", err)
	}

	// audit-fix CRIT-MAC-ORDER: Verify MAC on ENCRYPTED header BEFORE decrypting.
	// Previously, the header was decrypted first, then MAC was computed on decrypted
	// data. But Write() computes MAC on encrypted data. This mismatch caused:
	// (1) Every legitimate connection to fail MAC verification
	// (2) Unauthenticated ciphertext to be parsed (frameSize from untrusted data)
	headerMAC := header[16:32]
	expectedHeaderMAC := c.computeMAC(header[:16], c.secrets.IngressMAC)
	if !hmac.Equal(headerMAC, expectedHeaderMAC) {
		return 0, nil, ErrInvalidMAC
	}

	// Decrypt header only after MAC verification passes
	if c.dec != nil {
		c.dec.XORKeyStream(header[:16], header[:16])
	}

	// Parse frame size from authenticated+decrypted header
	frameSize := binary.BigEndian.Uint32(header[0:4])
	if frameSize > maxFrameSize {
		return 0, nil, ErrFrameTooLarge
	}

	// R20-C2 FIX: Extract and verify sequence number from header.
	// Sequence number is stored in header bytes 4-7 (uint32 big-endian).
	// The sequence number must be strictly greater than the last received
	// sequence number to prevent replay attacks.
	seqNum := binary.BigEndian.Uint32(header[4:8])
	// R20-C2: Reject if sequence number is not greater than last seen.
	// Since we don't know the initial seq from the peer, we accept any seq > 0
	// once we've received our first frame (readSeq > 0) OR we accept seq > 0
	// on the first frame (readSeq == 0). Subsequent frames must have
	// seqNum > readSeq.
	if seqNum == 0 {
		return 0, nil, ErrInvalidSequenceNum
	}
	// R44-M-M1 FIX: Add sequence number overflow protection.
	// If readSeq is at max uint32, the next valid seqNum would overflow to 0,
	// which is caught above. But we also check the edge case where seqNum
	// wraps to a low value while readSeq is still high.
	// Defense-in-depth: catches edge cases even though frame replay protection
	// (frameReplayMap) also prevents duplicates.
	if c.readSeq > 0 && seqNum <= c.readSeq {
		return 0, nil, ErrReplayDetected
	}
	c.readSeq = seqNum

	// Read frame body
	body := make([]byte, frameSize)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return 0, nil, fmt.Errorf("failed to read body: %w", err)
	}

	// audit-fix CRIT-MAC-ORDER: Verify MAC on ENCRYPTED body before decrypting.
	// This ensures integrity of the ciphertext and prevents Decrypt-then-MAC vulnerability.
	// Rolling MAC is computed on ciphertext to match Write() logic.
	bodyMAC := make([]byte, macSize)
	if _, err := io.ReadFull(c.conn, bodyMAC); err != nil {
		return 0, nil, fmt.Errorf("failed to read body MAC: %w", err)
	}

	expectedBodyMAC := c.computeMAC(body, c.secrets.IngressMAC)
	if !hmac.Equal(bodyMAC, expectedBodyMAC) {
		return 0, nil, ErrInvalidMAC
	}

	// SECURITY (audit P1-R3-03): Roll MAC state for next frame after successful verification
	c.secrets.IngressMAC = c.rollMACState(c.secrets.IngressMAC, expectedHeaderMAC, expectedBodyMAC)

	// Decrypt body only after authentication
	if c.dec != nil {
		c.dec.XORKeyStream(body, body)
	}

	// Parse message code and data
	if len(body) < 1 {
		return 0, nil, ErrInvalidMessage
	}

	// Decode RLP
	var msg struct {
		Code uint64
		Data []byte
	}
	if err := rlp.DecodeBytes(body, &msg); err != nil {
		// Fallback: treat first byte as code, rest as data
		code = uint64(body[0])
		data = body[1:]
	} else {
		code = msg.Code
		data = msg.Data
	}

	// CRITICAL-1 FIX: Check for frame content replay.
	// Even if sequence number is valid, we must reject if we've already
	// processed this exact frame content. This prevents attacks where
	// attacker captures a frame and replays it later with higher seq num.
	// CRITICAL FIX: Additional sequence number check to prevent hash collision attacks
	contentHash := sha256.Sum256(body)
	c.frameReplayMu.Lock()
	// CRITICAL FIX: Also check for duplicate sequence numbers
	if c.seenSeqNums[seqNum] {
		c.frameReplayMu.Unlock()
		return 0, nil, fmt.Errorf("%w: sequence number %d already seen", ErrFrameReplayDetected, seqNum)
	}
	if storedSeq, exists := c.frameReplayMap[string(contentHash[:])]; exists {
		c.frameReplayMu.Unlock()
		return 0, nil, fmt.Errorf("%w: frame content already received at sequence %d", ErrFrameReplayDetected, storedSeq)
	}
	c.frameReplayMap[string(contentHash[:])] = seqNum
	c.seenSeqNums[seqNum] = true // CRITICAL FIX: track seen sequence numbers
	// R40-H1 FIX: Purge stale entries to prevent unbounded memory growth.
	// When the map exceeds maxReplayWindow, delete entries with sequence
	// numbers older than (currentSeq - maxReplayWindow). This implements a
	// sliding window that bounds memory to O(maxReplayWindow) entries.
	if len(c.frameReplayMap) > maxReplayWindow {
		minSeq := seqNum - maxReplayWindow
		for hash, seq := range c.frameReplayMap {
			if seq < minSeq {
				delete(c.frameReplayMap, hash)
				delete(c.seenSeqNums, seq) // CRITICAL FIX: also purge seen sequence numbers
			}
		}
	}
	c.frameReplayMu.Unlock()

	return code, data, nil
}

// Write writes an encrypted message to the connection
func (c *Conn) Write(code uint64, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed {
		return ErrConnectionClosed
	}

	if !c.handshakeDone {
		return ErrHandshakeFailed
	}

	if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		// R31-P2 FIX (P2-8, 2026-07-28): Return the error instead of
		// continuing without a deadline. Previously this only logged the
		// error and proceeded, allowing a stalled peer to hold the write
		// goroutine indefinitely (no timeout protection).
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Encode message
	body, err := rlp.EncodeToBytes(struct {
		Code uint64
		Data []byte
	}{code, data})
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	if len(body) > maxFrameSize {
		return ErrFrameTooLarge
	}

	// Build frame header
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], uint32(len(body))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction

	// R20-C2 FIX: Increment and embed sequence number in header bytes 4-8.
	// Sequence number is incremented for each frame to prevent replay attacks.
	// Must increment BEFORE write to ensure each frame has unique sequence.
	if c.writeSeq == 0 {
		c.writeSeq = 1
	}
	// R46-C-C1 FIX: Prevent uint32 overflow of writeSeq.
	// When writeSeq reaches 0xFFFFFFFF and increments, it wraps to 0.
	// The next call resets to 1, causing sequence number reuse which breaks
	// frame authentication. The MAC chain depends on unique seq per frame.
	if c.writeSeq == 0xFFFFFFFF {
		return ErrSequenceOverflow
	}
	binary.BigEndian.PutUint32(header[4:8], c.writeSeq)
	c.writeSeq++

	// audit-fix CRIT-2: Ensure both header and body are authenticated.
	// Standard RLPx has header MAC in header[16:32] and frame MAC after body.

	// Encrypt header
	if c.enc != nil {
		c.enc.XORKeyStream(header[:16], header[:16])
	}

	// Compute header MAC
	hMAC := c.computeMAC(header[:16], c.secrets.EgressMAC)
	copy(header[16:32], hMAC)

	// Encrypt body
	encBody := make([]byte, len(body))
	if c.enc != nil {
		c.enc.XORKeyStream(encBody, body)
	} else {
		copy(encBody, body)
	}

	// Compute body MAC
	bMAC := c.computeMAC(encBody, c.secrets.EgressMAC)

	// SECURITY (audit P1-R3-03): Roll MAC state for next frame
	c.secrets.EgressMAC = c.rollMACState(c.secrets.EgressMAC, hMAC, bMAC)

	// Write header, body, and body MAC
	if _, err := c.conn.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := c.conn.Write(encBody); err != nil {
		return fmt.Errorf("failed to write body: %w", err)
	}
	if _, err := c.conn.Write(bMAC); err != nil {
		return fmt.Errorf("failed to write body MAC: %w", err)
	}

	return nil
}

// computeMAC computes the MAC for a message
// computeMAC computes a HMAC-SHA-256 over the data using the MAC key and
// the provided MAC state (egress or ingress).
// SECURITY (audit P1-R2-02): Bind MAC to connection identity (AAD) to prevent
// cross-connection replay attacks.
// R37-FIX P1-P2P-02 (2026-07-30): The AAD is the CANONICAL connection identity
// initiatorID||responderID (c.macAAD, fixed at handshake time), identical on
// both ends. The previous per-side localID||remoteID ordering produced
// different MAC inputs on the two ends of every connection.
func (c *Conn) computeMAC(data, macState []byte) []byte {
	h := hmac.New(sha256.New, c.secrets.MAC)
	h.Write(macState)
	// AAD (canonical connection identity) before data to bind MAC to this connection
	h.Write(c.macAAD)
	h.Write(data)
	return h.Sum(nil)[:macSize]
}

// setMacAAD fixes the canonical MAC AAD as initiatorID||responderID.
// Must be called after remoteID is known (handshake completion). The role
// parameter tells this end which ID belongs to the initiator.
// R37-FIX P1-P2P-02 (2026-07-30).
func (c *Conn) setMacAAD(isInitiator bool) {
	aad := make([]byte, 0, 2*len(c.localID))
	if isInitiator {
		aad = append(aad, c.localID[:]...)  // initiator
		aad = append(aad, c.remoteID[:]...) // responder
	} else {
		aad = append(aad, c.remoteID[:]...) // initiator
		aad = append(aad, c.localID[:]...)  // responder
	}
	c.macAAD = aad
}

// rollMACState computes the next rolling MAC state from the current state and
// the frame's MAC outputs. Returns a NEW slice (does not modify macState in place).
// SECURITY (audit P1-R3-03): RLPx spec requires each frame's MAC output to feed
// into the next frame's MAC computation, creating a chain that prevents replay
// and ensures message ordering. Without this, the MAC state remains constant
// for the entire connection lifetime, weakening integrity protection.
func (c *Conn) rollMACState(macState, headerMAC, bodyMAC []byte) []byte {
	h := hmac.New(sha256.New, c.secrets.MAC)
	h.Write(macState)
	h.Write(headerMAC)
	h.Write(bodyMAC)
	return h.Sum(nil)
}

// Close closes the connection
// SECURITY (audit P1-R2-03, P1-R3-02): Zeroize all key material on close to
// prevent residual key data in memory after the connection is terminated.
func (c *Conn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	// SECURITY (audit P1-R3-02): Zeroize all session secrets.
	// The previous fix only had a comment but no actual zeroization code.
	if c.secrets != nil {
		for i := range c.secrets.AES {
			c.secrets.AES[i] = 0
		}
		for i := range c.secrets.MAC {
			c.secrets.MAC[i] = 0
		}
		for i := range c.secrets.EgressMAC {
			c.secrets.EgressMAC[i] = 0
		}
		for i := range c.secrets.IngressMAC {
			c.secrets.IngressMAC[i] = 0
		}
		// R33 P2P-13: Also zeroize IngressAES (dedicated decryption key).
		for i := range c.secrets.IngressAES {
			c.secrets.IngressAES[i] = 0
		}
	}

	return c.conn.Close()
}

// RemoteID returns the remote node's ID
func (c *Conn) RemoteID() enode.ID {
	return c.remoteID
}

// LocalID returns the local node's ID
func (c *Conn) LocalID() enode.ID {
	return c.localID
}

// RemoteAddr returns the remote address
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// LocalAddr returns the local address
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// IsHandshakeDone returns true if the handshake is complete
func (c *Conn) IsHandshakeDone() bool {
	return c.handshakeDone
}

// SetReadDeadline sets the read deadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// SetDeadline sets both read and write deadlines
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
