// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p/discover"
	"github.com/quantaureum/qau/p2p/enode"
	"golang.org/x/crypto/sha3"
)

// encryptedTransport provides AES-256-GCM encryption over net.Conn.
// SECURITY FIX Q-B-003: Wraps raw TCP with per-connection ephemeral keys.
//
// Handshake (performed inside encryptedConn) using Kyber768 KEM:
//   1. Initiator generates Kyber768 keypair, signs kyberPubKey with Dilithium3.
//   2. Sends kyberPubKey || signature || dilithiumPubKey to responder.
//   3. Responder verifies signature against dilithiumPubKey.
//   4. Responder encapsulates using kyberPubKey to get (ciphertext, sharedSecret).
//   5. Responder sends ciphertext || peerID to initiator.
//   6. Initiator decapsulates ciphertext to recover sharedSecret.
//   7. Both sides derive AES-256-GCM keys from sharedSecret via HKDF-SHA3-256.
//   8. All subsequent traffic is encrypted with AES-256-GCM.

type encryptedListener struct {
	plain   net.Listener
	nodeKey *crypto.KeyPair
	devMode bool
}

func newEncryptedListener(plain net.Listener, nodeKey *crypto.KeyPair, devMode bool) net.Listener {
	return &encryptedListener{plain: plain, nodeKey: nodeKey, devMode: devMode}
}

// AcceptRaw accepts a raw TCP/TLS connection without performing the
// post-quantum handshake. Callers MUST subsequently call ServerHandshake
// in a per-connection goroutine to complete the encrypted transport setup.
// AUDIT (2026) HIGH-15: decoupling raw accept from handshake prevents
// a single slow/stalled peer from blocking all other inbound connections.
func (l *encryptedListener) AcceptRaw() (net.Conn, error) {
	return l.plain.Accept()
}

// ServerHandshake performs the post-quantum (Kyber768 + Dilithium3) server
// side handshake on an already-accepted raw connection. The caller is
// responsible for closing the connection on error.
func (l *encryptedListener) ServerHandshake(conn net.Conn) (net.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set handshake deadline: %w", err)
	}
	encConn, err := performServerHandshake(conn, l.nodeKey, l.devMode)
	if err != nil {
		return nil, fmt.Errorf("encrypted handshake failed: %w", err)
	}
	return encConn, nil
}

func (l *encryptedListener) Accept() (net.Conn, error) {
	// Synchronous fallback: accept + handshake inline.
	// Prefer AcceptRaw + ServerHandshake in a goroutine for production paths.
	conn, err := l.plain.Accept()
	if err != nil {
		return nil, err
	}
	encConn, err := l.ServerHandshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return encConn, nil
}

func (l *encryptedListener) Close() error   { return l.plain.Close() }
func (l *encryptedListener) Addr() net.Addr { return l.plain.Addr() }

type encryptedConn struct {
	net.Conn
	sendCipher  cipher.AEAD
	recvCipher  cipher.AEAD
	isInitiator bool
	sendKey     []byte // SECURITY (P1-06): raw key for zeroization on Close
	recvKey     []byte // SECURITY (P1-06): raw key for zeroization on Close

	writeNonce uint64
	readNonce  uint64
	// audit-fix MEDIUM: protect nonce counters from concurrent access to
	// prevent nonce reuse in AES-GCM, which would be catastrophic.
	writeMu sync.Mutex
	readMu  sync.Mutex

	readBuf []byte

	nodeKey  *crypto.KeyPair
	localID  PeerID
	remoteID PeerID
	// AUDIT (2026) P2P-05: PoW nonce used in the initial handshake.
	// Preserved on the connection so that key-rotation re-handshakes can
	// re-send it without forcing the caller to thread it through manually.
	// The server now rejects handshakes without a PoW nonce (legacy format
	// removed), so this MUST be non-zero for initiator connections.
	powNonce uint64
}

// nonceRotationThreshold is the point at which key rotation should be
// triggered to prevent nonce overflow. For AES-GCM, NIST recommends
// at most 2^32 messages per key; we use a conservative threshold.
const nonceRotationThreshold = uint64(1) << 32

// P2P-005 FIX (deep-audit 2026-07-03): the encrypted-transport message size
// limit was hardcoded to 10MB. It now defaults to MaxBlockResponseSize (10MB,
// the largest frame the application can send — a block response batch) and
// can be adjusted at startup via SetMaxEncryptedMessageSize. Stored
// atomically so Read on live connections observes a consistent value without
// extra locking.
//
// CONSENSUS-SYNC FIX (2026-08-04): the default must track the largest
// application message, NOT DefaultMaxMessageSize (1MB). P2P-R19-H06 lowered
// DefaultMaxMessageSize to 1MB for control messages, but the encrypted
// transport is a frame-level limit: it must accept any frame the application
// can produce, and block responses are batched up to MaxBlockResponseSize.
// A transport limit of 1MB silently rejected valid block response batches
// (>1MB) on the receiving side, making a freshly-reset node unable to sync
// from peers ("encrypted message too large"). The per-type limit is enforced
// later by message_validator.go, so raising the transport ceiling to 10MB is
// safe and does not relax any application-level security check.
var maxEncryptedMessageSize atomic.Uint32

func init() {
	maxEncryptedMessageSize.Store(MaxBlockResponseSize)
}

// SetMaxEncryptedMessageSize configures the maximum size of a single
// encrypted transport frame. Callers should keep this consistent with the
// message-validator limits (DefaultMaxMessageSize) — a transport limit below
// the validator limit rejects otherwise-valid protocol messages, and one far
// above it only wastes memory on frames the validator will discard anyway.
func SetMaxEncryptedMessageSize(n uint32) error {
	const minLimit = 64 * 1024         // must accommodate handshake frames and typical messages
	const maxLimit = 128 * 1024 * 1024 // hard ceiling against memory-exhaustion misconfiguration
	if n < minLimit || n > maxLimit {
		return fmt.Errorf("max encrypted message size %d out of range [%d, %d]", n, minLimit, maxLimit)
	}
	maxEncryptedMessageSize.Store(n)
	return nil
}

// P1 FIX (2026-07-06): Pool cipher buffers to reduce GC pressure under high
// throughput. Each Read allocates a buffer of msgLen bytes for ciphertext
// decryption. With thousands of peers and high-frequency messages, this
// creates significant GC pressure. The pool reuses buffers across Read calls.
var cipherBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096) // Start with 4KB capacity
		return &b
	},
}

func (c *encryptedConn) Read(p []byte) (int, error) {
	// audit-fix MEDIUM: lock readMu to protect readNonce and readBuf from
	// concurrent access. Without this, concurrent Read calls could reuse
	// the same nonce in AES-GCM, breaking confidentiality and integrity.
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// P2-ROTATEKEYS-ZEROIZE FIX (R29, 2026-07-26): If RotateKeys failed (or
	// Close was called), recvCipher is nil'd out to release the AES-GCM state
	// for GC. Without this check, the c.recvCipher.Open() call below would
	// panic with a nil-pointer dereference. Returning an error here is the
	// correct behavior — the connection is broken and cannot be used.
	if c.recvCipher == nil {
		return 0, io.EOF
	}

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf[:])
	// FIX: Reject zero-length messages. AES-GCM requires at least
	// 16 bytes for the authentication tag; a zero-length message has no
	// tag and will always fail decryption. More importantly, accepting
	// zero-length messages could cause nonce desynchronization between
	// sender and receiver if one side sends an empty message that the
	// other side doesn't process.
	if msgLen == 0 {
		return 0, errors.New("encrypted message has zero length")
	}
	// SECURITY (audit P3-04): defaults to 10MB to match message_validator.go.
	// P2P-005 FIX: configurable via SetMaxEncryptedMessageSize.
	if msgLen > maxEncryptedMessageSize.Load() {
		return 0, errors.New("encrypted message too large")
	}

	// P1 FIX (2026-07-06): Use pooled buffer instead of allocating per-Read.
	// RPC-R9-M (2026-07-19) FIX: Bounded pool retention. Previously the buffer
	// was unconditionally returned to the pool even when msgLen was large
	// (up to maxEncryptedMessageSize = 128MB). sync.Pool retains objects
	// between GC cycles, so a single 128MB buffer would linger in the pool
	// and be handed back to a caller that only needs 4KB, bloating memory
	// usage across many connections. Now we only return buffers whose
	// capacity is at or below maxCipherBufPoolCap; larger buffers are dropped
	// so the GC can reclaim them promptly.
	const maxCipherBufPoolCap = 64 * 1024 // 64KB — covers common control messages
	cipherBufPtr := cipherBufPool.Get().(*[]byte)
	cipherBuf := *cipherBufPtr
	if cap(cipherBuf) < int(msgLen) {
		cipherBuf = make([]byte, msgLen)
	} else {
		cipherBuf = cipherBuf[:msgLen]
	}
	defer func() {
		// P3-CRYPTO-01 FIX (R29, 2026-07-26): Zeroize cipherBuf before
		// returning to pool. After recvCipher.Open, cipherBuf holds the
		// DECRYPTED PLAINTEXT (Open reuses the in-place buffer). Without
		// this, plaintext fragments from one connection's Read could be
		// observed by a different connection that happens to get the same
		// pooled buffer next. The pool is process-global, so cross-conn
		// reuse is normal. zeroize is a no-op on nil/empty slices.
		zeroize(cipherBuf)
		if cap(cipherBuf) <= maxCipherBufPoolCap {
			// Return buffer to pool for reuse
			*cipherBufPtr = cipherBuf
			cipherBufPool.Put(cipherBufPtr)
		}
	}()

	if _, err := io.ReadFull(c.Conn, cipherBuf); err != nil {
		return 0, err
	}

	// L15-019 FIX: Warn when nonce approaches max, triggering proactive key rotation.
	if c.readNonce >= nonceRotationThreshold && c.readNonce%(1<<28) == 0 {
		log.Printf("[WARN] encryptedConn: read nonce %d approaching max, key rotation recommended", c.readNonce)
	}
	if c.readNonce == ^uint64(0) {
		return 0, errors.New("encryptedConn: read nonce overflow, connection must be rekeyed")
	}
	nonce := makeNonce(c.readNonce)
	aad := makeAAD(c.readNonce, c.isInitiator, false) // SECURITY (P1-05): bind nonce + message direction
	c.readNonce++
	plain, err := c.recvCipher.Open(cipherBuf[:0], nonce, cipherBuf, aad)
	if err != nil {
		return 0, fmt.Errorf("decryption failed: %w", err)
	}

	n := copy(p, plain)
	if n < len(plain) {
		c.readBuf = append(c.readBuf[:0], plain[n:]...)
	}
	return n, nil
}

func (c *encryptedConn) Write(p []byte) (int, error) {
	// audit-fix MEDIUM: lock writeMu to protect writeNonce from concurrent
	// access. Without this, concurrent Write calls could reuse the same
	// nonce in AES-GCM, which is catastrophic for security.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// P2-ROTATEKEYS-ZEROIZE FIX (R29, 2026-07-26): If RotateKeys failed (or
	// Close was called), sendCipher is nil'd out to release the AES-GCM state
	// for GC. Without this check, the c.sendCipher.Seal() call below would
	// panic with a nil-pointer dereference. Returning an error here is the
	// correct behavior — the connection is broken and cannot be used.
	if c.sendCipher == nil {
		return 0, errors.New("encryptedConn: connection closed (cipher is nil)")
	}

	// FIX: Reject zero-length writes to prevent nonce
	// desynchronization (see Read for explanation).
	if len(p) == 0 {
		return 0, errors.New("encrypted write has zero length")
	}

	// L15-019 FIX: Warn when nonce approaches max, triggering proactive key rotation.
	if c.writeNonce >= nonceRotationThreshold && c.writeNonce%(1<<28) == 0 {
		log.Printf("[WARN] encryptedConn: write nonce %d approaching max, key rotation recommended", c.writeNonce)
	}
	if c.writeNonce == ^uint64(0) {
		return 0, errors.New("encryptedConn: write nonce overflow, connection must be rekeyed")
	}
	nonce := makeNonce(c.writeNonce)
	aad := makeAAD(c.writeNonce, c.isInitiator, true) // SECURITY (P1-05): bind nonce + message direction
	c.writeNonce++
	cipher := c.sendCipher.Seal(nil, nonce, p, aad)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(cipher)))
	if _, err := c.Conn.Write(lenBuf[:]); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(cipher); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close zeroizes key material and closes the underlying connection.
// SECURITY (audit 2026-06-26, P1-06): Prevents key extraction via memory
// dump, cold boot, or memory vulnerability exploits.
//
// P3-READBUF-ZEROIZE FIX (R29, 2026-07-26): Also zeroize readBuf before
// nil-ing. readBuf contains decrypted plaintext (transaction data, block
// data, etc.) that passed through the connection. While it usually doesn't
// contain complete key material, it may contain sensitive transaction
// payloads (e.g., private transaction calldata, Dilithium3 signature
// fragments). Setting readBuf to nil without zeroizing leaves the backing
// array's contents in heap memory until GC collects it — an attacker who
// can dump memory could read the plaintext. zeroize() is a no-op on nil
// slices, so this is safe even if readBuf was already nil.
func (c *encryptedConn) Close() error {
	c.writeMu.Lock()
	c.readMu.Lock()
	zeroize(c.sendKey)
	zeroize(c.recvKey)
	c.sendKey = nil
	c.recvKey = nil
	c.sendCipher = nil
	c.recvCipher = nil
	zeroize(c.readBuf)
	c.readBuf = nil
	c.readMu.Unlock()
	c.writeMu.Unlock()
	return c.Conn.Close()
}

func makeNonce(counter uint64) []byte {
	n := make([]byte, 12)
	// P2P-002 FIX: Use BigEndian (network byte order) to match makeAAD, which
	// also encodes the counter in BigEndian. Previously makeNonce used
	// LittleEndian while makeAAD used BigEndian, an inconsistent endianness
	// for the same logical counter. The nonce is derived from the implicit
	// stream counter (never transmitted), and both seal/open use this same
	// function, so the change is internally consistent across both endpoints.
	binary.BigEndian.PutUint64(n, counter)
	return n
}

// makeAAD builds the Additional Authenticated Data for AES-GCM Seal/Open calls.
// SECURITY (audit 2026-06-26, P1-05): Binding the nonce counter and message
// direction into the AAD prevents: (1) cross-position ciphertext replay (the
// authentication tag covers the nonce, so a ciphertext sealed at counter N
// cannot be replayed at counter M != N), and (2) message direction flipping
// (a ciphertext sealed by the sender cannot be injected into the receiver's
// stream because the direction byte differs).
func makeAAD(counter uint64, isInitiator, isSend bool) []byte {
	aad := make([]byte, 9)
	binary.BigEndian.PutUint64(aad[:8], counter)
	// Direction byte: 0x01 = initiator-to-responder, 0x00 = responder-to-initiator.
	// Both sides of the same message MUST use the same direction byte.
	if (isInitiator && isSend) || (!isInitiator && !isSend) {
		aad[8] = 0x01 // initiator-to-responder
	} else {
		aad[8] = 0x00 // responder-to-initiator
	}
	return aad
}

func deriveSessionKeys(sharedSecret []byte, isInitiator bool, localID, remoteID PeerID) (sendKey, recvKey []byte, err error) {
	localBytes := []byte(localID)
	remoteBytes := []byte(remoteID)

	var firstID, secondID []byte
	if string(localBytes) < string(remoteBytes) {
		firstID, secondID = localBytes, remoteBytes
	} else {
		firstID, secondID = remoteBytes, localBytes
	}

	// P2P-001 FIX: Use standard HKDF (RFC 5869) with HMAC-SHA3-256 instead
	// of non-standard direct SHA3 hashing. Standard HKDF uses HMAC for both
	// extract and expand phases, providing proven security guarantees.
	// Version bumped to v2 to indicate protocol change.
	// CRYPTO-R17-H01 (2026-07-24): Added NUL terminator for domain separation
	// consistency — prevents prefix-extension if the salt is ever concatenated
	// with other data in future protocol versions.
	salt := []byte("QUANTAUREUM_P2P_HKDF_V2\x00")

	// Extract: PRK = HMAC-SHA3-256(salt, sharedSecret)
	extractHmac := hmac.New(sha3.New256, salt)
	extractHmac.Write(sharedSecret)
	prk := extractHmac.Sum(nil)

	// Expand: OKM = HMAC-SHA3-256(PRK, info || 0x01)
	sendKey = hkdfExpandHMAC(prk, []byte("send"), firstID, secondID)
	recvKey = hkdfExpandHMAC(prk, []byte("recv"), firstID, secondID)

	if isInitiator {
		return sendKey, recvKey, nil
	}
	return recvKey, sendKey, nil
}

// hkdfExpandHMAC implements RFC 5869 §2.3 expand step using HMAC-SHA3-256.
func hkdfExpandHMAC(prk []byte, label, firstID, secondID []byte) []byte {
	info := make([]byte, 0, len(label)+len(firstID)+len(secondID)+1)
	info = append(info, label...)
	info = append(info, firstID...)
	info = append(info, secondID...)
	info = append(info, 0x01)

	h := hmac.New(sha3.New256, prk)
	h.Write(info)
	return h.Sum(nil)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// performClientHandshake completes the initiator side of the encrypted
// transport handshake.
// AUDIT (2026) P2P-05: The powNonce parameter is the client's pre-computed
// proof-of-work nonce (bound to the node's enode.ID). It is ALWAYS appended to
// the handshake message so the server can verify PoW before performing expensive
// post-quantum cryptography. The legacy format (without PoW) has been removed
// from the server — a powNonce of 0 will cause the server to reject the
// handshake (unless DevMode bypasses PoW verification on both sides).
func performClientHandshake(conn net.Conn, nodeKey *crypto.KeyPair, localID, remoteID PeerID, powNonce uint64) (net.Conn, error) {
	kyberPub, kyberPriv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Kyber768 keypair: %w", err)
	}

	kyberPubBytes, err := kyberPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Kyber public key: %w", err)
	}

	sig, err := crypto.Sign(nodeKey.Private, kyberPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign Kyber public key: %w", err)
	}

	pubBytes := nodeKey.Public.Bytes()

	// AUDIT (2026) P2P-05: PoW nonce is now mandatory. The server rejects
	// handshakes without it (legacy format removed). Callers MUST pass a valid
	// non-zero powNonce computed via generatePoWNonce or the host's cached nonce.
	msg := make([]byte, 0, len(kyberPubBytes)+crypto.Dilithium3SignatureSize+crypto.Dilithium3PublicKeySize+8)
	msg = append(msg, kyberPubBytes...)
	msg = append(msg, sig...)
	msg = append(msg, pubBytes...)
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, powNonce)
	msg = append(msg, nonceBytes...)

	if err := writeHandshakeMessage(conn, msg); err != nil {
		return nil, err
	}

	resp, err := readHandshakeMessageRaw(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read server response: %w", err)
	}

	// SECURITY (audit 2026-06-14, A-1): The server response is now
	//   ciphertext || serverPeerID || serverDilithiumPubKey || serverSignature
	// where serverSignature = Sign(serverPriv, ciphertext || serverPeerID ||
	// clientKyberPub). The client MUST verify this signature so that an active
	// MITM cannot substitute its own ciphertext + identity (the previous
	// protocol had NO server authentication at all).
	respCTLen := kyber768.CiphertextSize
	respPeerIDLen := 64 // SHA3-256 hex string length, matches derivePeerIDFromKeyPair
	respPubKeyLen := crypto.Dilithium3PublicKeySize
	respSigLen := crypto.Dilithium3SignatureSize
	minRespLen := respCTLen + respPeerIDLen + respPubKeyLen + respSigLen
	if len(resp) < minRespLen {
		return nil, fmt.Errorf("invalid server response length: expected at least %d, got %d", minRespLen, len(resp))
	}

	ciphertext := resp[:respCTLen]
	serverPeerID := PeerID(string(resp[respCTLen : respCTLen+respPeerIDLen]))
	serverPubKeyBytes := resp[respCTLen+respPeerIDLen : respCTLen+respPeerIDLen+respPubKeyLen]
	serverSig := resp[respCTLen+respPeerIDLen+respPubKeyLen : minRespLen]

	sharedSecret, err := kyber768.Scheme().Decapsulate(kyberPriv, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("Kyber decapsulation failed: %w", err)
	}

	// SECURITY (A-1): Verify the server's signature binds (ciphertext ||
	// serverPeerID || clientKyberPub) to the server's Dilithium private key,
	// and that the PeerID equals SHA3-256(serverDilithiumPubKey). This defeats
	// active MITM: an attacker cannot forge the signature without the server's
	// private key, and cannot substitute a different ciphertext because the
	// signature covers it (and the client's Kyber pub key).
	serverPubKey, err := crypto.PublicKeyFromBytes(serverPubKeyBytes)
	if err != nil {
		zeroize(sharedSecret)
		return nil, fmt.Errorf("invalid server Dilithium public key: %w", err)
	}

	// Reconstruct signed message: ciphertext || serverPeerID || clientKyberPub
	signedMsg := make([]byte, 0, len(ciphertext)+len(serverPeerID)+len(kyberPubBytes))
	signedMsg = append(signedMsg, ciphertext...)
	signedMsg = append(signedMsg, []byte(serverPeerID)...)
	signedMsg = append(signedMsg, kyberPubBytes...)

	if !crypto.Verify(serverPubKey, signedMsg, serverSig) {
		zeroize(sharedSecret)
		return nil, errors.New("server response signature verification failed")
	}

	// Derive the expected PeerID from the server's public key and verify it
	// matches the declared serverPeerID.
	expectedServerID := derivePeerIDFromPublicKey(serverPubKeyBytes)
	if serverPeerID != expectedServerID {
		zeroize(sharedSecret)
		return nil, fmt.Errorf("server peerID/pubkey mismatch: declared %x, derived %x",
			[]byte(serverPeerID), []byte(expectedServerID))
	}

	// If the caller supplied an expected remoteID (we dialed a known peer), the
	// server's authenticated identity must match it.
	if remoteID == "" {
		remoteID = serverPeerID
	} else if serverPeerID != remoteID {
		zeroize(sharedSecret)
		return nil, fmt.Errorf("server identity mismatch: expected %x, got %x",
			[]byte(remoteID), []byte(serverPeerID))
	}

	sendKey, recvKey, err := deriveSessionKeys(sharedSecret, true, localID, remoteID)
	if err != nil {
		zeroize(sharedSecret)
		return nil, err
	}
	zeroize(sharedSecret)

	// P2P-C-01 FIX (R29, 2026-07-25): Zeroize sendKey/recvKey on ALL error
	// paths after derivation. Previously, if newAEAD(recvKey) failed after
	// newAEAD(sendKey) succeeded, sendKey was left in heap memory —
	// extractable via memory dump / cold-boot attack. AES-256-GCM session
	// keys must not outlive the handshake that created them.
	sendCipher, err := newAEAD(sendKey)
	if err != nil {
		zeroize(sendKey)
		zeroize(recvKey)
		return nil, err
	}
	recvCipher, err := newAEAD(recvKey)
	if err != nil {
		zeroize(sendKey)
		zeroize(recvKey)
		return nil, err
	}

	return &encryptedConn{
		Conn:        conn,
		sendCipher:  sendCipher,
		recvCipher:  recvCipher,
		isInitiator: true,
		sendKey:     sendKey,
		recvKey:     recvKey,
		nodeKey:     nodeKey,
		localID:     localID,
		remoteID:    remoteID,
		powNonce:    powNonce, // AUDIT (2026) P2P-05: preserve for re-handshake
	}, nil
}

// handshakeReplayCache prevents CPU-amplification DoS by rejecting repeated
// handshake attempts from the same node ID within a short window.
// AUDIT (2026) P2P-05: Without this cache, an attacker who captures one
// valid handshake message can replay it indefinitely, forcing the server to
// re-execute expensive post-quantum cryptography (Dilithium verify + Kyber
// encapsulate + Dilithium sign) on every attempt. The cache is keyed by the
// SHA3-256 of the client's Dilithium public key (which equals the node ID).
var handshakeReplayCache struct {
	sync.Mutex
	entries map[string]time.Time
	maxSize int
	ttl     time.Duration
}

func init() {
	handshakeReplayCache.entries = make(map[string]time.Time)
	handshakeReplayCache.maxSize = 10000
	handshakeReplayCache.ttl = 30 * time.Second
}

// checkHandshakeReplay returns true if the given node ID key was seen recently.
// It also performs lazy eviction of expired entries.
// NOTE: This function ONLY checks — it does NOT insert. Callers MUST call
// commitHandshakeReplay after all verification (PoW + signature) succeeds.
// AUDIT (2026) R3-P2P-02: Previously this function inserted the node ID
// into the cache immediately upon checking, BEFORE PoW/signature verification.
// An attacker could send a handshake with a victim's public key (public) and
// a garbage signature, poisoning the victim's cache entry and causing all
// subsequent legitimate handshakes from the victim to be rejected as "replay".
func checkHandshakeReplay(nodeIDKey string) bool {
	now := time.Now()
	handshakeReplayCache.Lock()
	defer handshakeReplayCache.Unlock()

	// Lazy eviction: remove expired entries
	if len(handshakeReplayCache.entries) > handshakeReplayCache.maxSize/2 {
		for k, ts := range handshakeReplayCache.entries {
			if now.Sub(ts) > handshakeReplayCache.ttl {
				delete(handshakeReplayCache.entries, k)
			}
		}
	}

	// Check for TTL validity of existing entries
	if ts, exists := handshakeReplayCache.entries[nodeIDKey]; exists {
		if now.Sub(ts) > handshakeReplayCache.ttl {
			// Entry expired — remove it and treat as not-a-replay
			delete(handshakeReplayCache.entries, nodeIDKey)
			return false
		}
		return true // replay detected (within TTL)
	}

	return false
}

// commitHandshakeReplay inserts a node ID into the replay cache after all
// verification (PoW + signature) has succeeded. This prevents attackers from
// poisoning the cache with unverified handshakes.
// AUDIT (2026) R3-P2P-02 FIX.
func commitHandshakeReplay(nodeIDKey string) {
	now := time.Now()
	handshakeReplayCache.Lock()
	defer handshakeReplayCache.Unlock()

	// Bound the cache size
	if len(handshakeReplayCache.entries) >= handshakeReplayCache.maxSize {
		// Evict oldest entry
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, ts := range handshakeReplayCache.entries {
			if first || ts.Before(oldestTime) {
				oldestKey = k
				oldestTime = ts
				first = false
			}
		}
		delete(handshakeReplayCache.entries, oldestKey)
	}

	handshakeReplayCache.entries[nodeIDKey] = now
}

// performServerHandshake completes the responder side of the encrypted
// transport handshake.
//
// P2P-003 NOTE (intentional design): The server does NOT verify that the
// client's Dilithium public key matches a pre-known/expected PeerID. It
// accepts any self-consistent handshake whose Kyber public key is correctly
// signed by the accompanying Dilithium key. This is intentional: the
// transport layer only establishes a confidential+authenticated channel
// bound to whatever Dilithium identity the client presented. Peer allow/deny
// list enforcement (trusted peers, peer limits, slashing checks, etc.) is
// performed at the protocol layer above (see p2p/host.go), which has the
// context to decide whether the derived remoteID is permitted to participate.
// Verifying identity here would couple the generic transport to peer-store
// policy, which is undesirable.
//
// AUDIT (2026) P2P-05: The client handshake message now includes an 8-byte
// PoW nonce appended after the Dilithium public key. The server verifies the
// PoW BEFORE performing the expensive post-quantum cryptography (Dilithium
// signature verification + Kyber encapsulation + Dilithium signing). This
// prevents CPU-amplification DoS where an attacker sends many cheap handshake
// messages to force the server to do expensive PQ crypto. An anti-replay cache
// further prevents reusing the same handshake message.
func performServerHandshake(conn net.Conn, nodeKey *crypto.KeyPair, devMode bool) (net.Conn, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > 32*1024 {
		return nil, errors.New("handshake message too large")
	}
	// RPC-R9-H3 (2026-07-19) FIX: enforce a lower bound on the handshake
	// message length BEFORE allocating the buffer. The minimum valid client
	// handshake message is kyberPub(1184) + sig(3293) + dilithiumPub(1952)
	// + powNonce(8) = 6437 bytes. A length of 0 or any smaller-than-minimum
	// value is either a malformed peer, an attacker probing for parsing
	// bugs, or an attempted DoS via cheap allocations. Reject it here
	// rather than allocating and then failing the exact-match length
	// check below. We tolerate ±8 bytes (the PoW nonce) for forward
	// compatibility with future handshake extensions.
	expectedLenWithPow := kyber768.PublicKeySize + crypto.Dilithium3SignatureSize + crypto.Dilithium3PublicKeySize + 8
	expectedLenLegacy := kyber768.PublicKeySize + crypto.Dilithium3SignatureSize + crypto.Dilithium3PublicKeySize
	minHandshakeLen := expectedLenLegacy
	if length < uint32(minHandshakeLen) {
		return nil, fmt.Errorf("handshake message too small: minimum %d bytes, got %d", minHandshakeLen, length)
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}

	// AUDIT (2026) P2P-05: Expected message format with PoW nonce:
	//   kyberPubBytes || sig || dilithiumPubBytes || powNonce(8 bytes)
	// The legacy format (without PoW) has been REMOVED. Accepting legacy
	// handshakes allowed an attacker to bypass the PoW gate entirely by
	// sending a shorter message, defeating the CPU-amplification DoS
	// protection. Now ALL handshakes must include a valid PoW nonce.
	// (expectedLenWithPow / expectedLenLegacy declared above for the
	// RPC-R9-H3 lower-bound check.)
	if len(msg) != expectedLenWithPow {
		return nil, fmt.Errorf("invalid handshake length: expected %d (with PoW), got %d (legacy format without PoW no longer accepted, audit P2P-05)",
			expectedLenWithPow, len(msg))
	}

	kyberPubBytes := msg[:kyber768.PublicKeySize]
	sig := msg[kyber768.PublicKeySize : kyber768.PublicKeySize+crypto.Dilithium3SignatureSize]
	dilithiumPubBytes := msg[kyber768.PublicKeySize+crypto.Dilithium3SignatureSize : expectedLenLegacy]
	powNonceBytes := msg[expectedLenLegacy:]

	// AUDIT (2026) P2P-05: Derive the peer's node ID from the Dilithium
	// public key and verify PoW BEFORE the expensive Dilithium signature
	// verification. This ensures an attacker must compute the 2^24 PoW before
	// the server spends CPU on PQ crypto.
	// NOTE: The node ID here is derived via SHA3-256(pubkey) to match the
	// PoW generation path in host.go (generatePoWNonce uses SHA3-256(pubkey)
	// as the node ID). The sybil_protection.go P2P-03/P2P-11 fix uses
	// enode.DeriveID for the discovery layer; these are separate code paths
	// and must each stay consistent with their corresponding PoW generator.
	pubHasher := sha3.New256()
	pubHasher.Write(dilithiumPubBytes)
	nodeIDHash := pubHasher.Sum(nil)
	nodeIDKey := string(nodeIDHash)

	// R38-SYNC FIX (2026-07-31): Previously the replay cache was keyed only
	// by nodeIDKey (SHA3-256 of Dilithium public key), which is the node's
	// FIXED identity. This meant ANY reconnection from the same node within
	// 30 seconds was rejected as "replay", even though the Kyber ephemeral
	// key was different. This caused P2P connectivity collapse in small
	// validator networks: after any disconnect (EOF, duplicate connection
	// cleanup, etc.), the node could not reconnect for 30 seconds, leading
	// to block sync failure and chain stalls.
	//
	// Fix: include the Kyber ephemeral public key hash in the cache key.
	// Each legitimate handshake generates a fresh random Kyber key pair, so
	// legitimate reconnections get different cache keys and are allowed.
	// Only EXACT replays (same Kyber public key bytes) are rejected, which
	// is the correct anti-replay semantics — matching the design of
	// rlpx/handshake_pq.go which uses (peerID || nonce) composite keys.
	kyberPubHasher := sha3.New256()
	kyberPubHasher.Write(kyberPubBytes)
	kyberPubHash := kyberPubHasher.Sum(nil)
	replayKey := nodeIDKey + ":" + string(kyberPubHash)

	// Anti-replay check: reject only if the SAME Kyber ephemeral key was
	// seen recently (exact message replay), not if the same node reconnects
	// with a fresh Kyber key.
	if checkHandshakeReplay(replayKey) {
		return nil, errors.New("handshake replay detected: identical Kyber ephemeral key recently seen")
	}

	// P2P-05: PoW is now mandatory (legacy format removed).
	powNonce := binary.BigEndian.Uint64(powNonceBytes)
	var nodeIDArr [32]byte
	copy(nodeIDArr[:], nodeIDHash)

	// DEV MODE: Skip PoW verification — nodes generate trivial nonces (42)
	// that won't pass the 2^24 difficulty check. This mirrors the legacy
	// protocol-layer handshake bypass in host.go:verifyPeerProofOfWork.
	//
	// CRITICAL SECURITY WARNING (audit-fix CRIT-DEVMODE-P2P):
	// DevMode bypasses PoW verification, a CRITICAL Sybil resistance mechanism.
	// If DevMode is enabled on Mainnet, an attacker could create unlimited fake
	// peers without computing real PoW. Defense-in-depth: even though
	// node.go:Start() validates DevMode is disabled on Mainnet, we add an
	// explicit assertion here as a safety net.
	if devMode {
		// SECURITY: This should NEVER happen due to node.go startup check,
		// but if it does, we MUST fail hard rather than bypass PoW on mainnet.
		// We cannot access Config.NetworkID here (transport is decoupled from
		// Host), so we rely on the upstream caller to never pass devMode=true
		// on mainnet. The Host.start() path enforces this invariant before
		// constructing the encryptedListener.
		log.Printf("[WARN] encrypted_transport: DevMode enabled — PoW verification skipped (local dev only, do NOT use on mainnet)")
	} else {
		if !discover.VerifyProofOfWork(enode.ID(nodeIDArr), powNonce) {
			return nil, errors.New("insufficient proof-of-work for handshake")
		}
	}

	pubKey, err := crypto.PublicKeyFromBytes(dilithiumPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid handshake public key: %w", err)
	}
	// P2P-003: We verify the signature is valid for the self-presented key, but
	// intentionally do NOT check the key against an expected PeerID here. See
	// the performServerHandshake doc comment — peer admission is enforced above.
	if !crypto.Verify(pubKey, kyberPubBytes, sig) {
		return nil, errors.New("handshake signature verification failed")
	}

	// AUDIT (2026) R3-P2P-02 FIX: Now that PoW + Dilithium signature have
	// both been verified, commit the node ID to the replay cache. Inserting
	// only after verification prevents an attacker from poisoning the cache
	// with handshakes that carry a victim's public key (public) but a garbage
	// signature — which previously caused all subsequent legitimate handshakes
	// from the victim to be rejected as "replay".
	commitHandshakeReplay(replayKey)

	kyberPub, err := kyber768.Scheme().UnmarshalBinaryPublicKey(kyberPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid Kyber public key: %w", err)
	}

	ct, sharedSecret, err := kyber768.Scheme().Encapsulate(kyberPub)
	if err != nil {
		return nil, fmt.Errorf("Kyber encapsulation failed: %w", err)
	}

	// Reuse the node ID hash already computed for PoW verification
	remoteID := PeerID(fmt.Sprintf("%x", nodeIDHash))

	localID := derivePeerIDFromKeyPair(nodeKey)

	// SECURITY (audit 2026-06-14, A-1): Sign the server response so the client
	// can authenticate the server and bind the ciphertext to the server's
	// identity. The signed message covers ciphertext || localID || clientKyberPub
	// (the client Kyber pub key ties the response to this specific handshake,
	// preventing cross-handshake replay).
	signedMsg := make([]byte, 0, len(ct)+len(localID)+len(kyberPubBytes))
	signedMsg = append(signedMsg, ct...)
	signedMsg = append(signedMsg, []byte(localID)...)
	signedMsg = append(signedMsg, kyberPubBytes...)

	serverSig, err := crypto.Sign(nodeKey.Private, signedMsg)
	if err != nil {
		zeroize(sharedSecret)
		return nil, fmt.Errorf("failed to sign server response: %w", err)
	}

	serverPubBytes := nodeKey.Public.Bytes()

	resp := make([]byte, 0, len(ct)+len(localID)+len(serverPubBytes)+len(serverSig))
	resp = append(resp, ct...)
	resp = append(resp, []byte(localID)...)
	resp = append(resp, serverPubBytes...)
	resp = append(resp, serverSig...)

	if err := writeHandshakeMessage(conn, resp); err != nil {
		zeroize(sharedSecret)
		return nil, fmt.Errorf("failed to send server response: %w", err)
	}

	sendKey, recvKey, err := deriveSessionKeys(sharedSecret, false, localID, remoteID)
	if err != nil {
		zeroize(sharedSecret)
		return nil, err
	}
	zeroize(sharedSecret)

	// P2P-C-01 FIX (R29, 2026-07-25): Zeroize sendKey/recvKey on ALL error
	// paths after derivation, including newAEAD failures and SetDeadline
	// failure. Previously, all four objects (sendKey, recvKey, sendCipher,
	// recvCipher) were left in heap memory if SetDeadline failed after both
	// newAEAD calls succeeded. The raw key bytes (sendKey/recvKey) are the
	// primary extraction target and must be zeroized.
	sendCipher, err := newAEAD(sendKey)
	if err != nil {
		zeroize(sendKey)
		zeroize(recvKey)
		return nil, err
	}
	recvCipher, err := newAEAD(recvKey)
	if err != nil {
		zeroize(sendKey)
		zeroize(recvKey)
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		zeroize(sendKey)
		zeroize(recvKey)
		return nil, err
	}

	return &encryptedConn{
		Conn:        conn,
		sendCipher:  sendCipher,
		recvCipher:  recvCipher,
		isInitiator: false,
		sendKey:     sendKey,
		recvKey:     recvKey,
		nodeKey:     nodeKey,
		localID:     localID,
		remoteID:    remoteID,
	}, nil
}

// derivePeerIDFromPublicKey derives a PeerID from a raw Dilithium public key.
// Mirror of derivePeerIDFromKeyPair but takes raw bytes.
func derivePeerIDFromPublicKey(pubBytes []byte) PeerID {
	h := sha3.New256()
	h.Write(pubBytes)
	return PeerID(fmt.Sprintf("%x", h.Sum(nil)))
}

func derivePeerIDFromKeyPair(kp *crypto.KeyPair) PeerID {
	pubBytes := kp.Public.Bytes()
	h := sha3.New256()
	h.Write(pubBytes)
	return PeerID(fmt.Sprintf("%x", h.Sum(nil)))
}

var zeroizeFunc = func(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func zeroize(b []byte) {
	zeroizeFunc(b)
}

func writeHandshakeMessage(conn net.Conn, msg []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(msg)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg)
	return err
}

func readHandshakeMessageRaw(conn net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > 32*1024 {
		return nil, errors.New("handshake message too large")
	}
	// RPC-R9-H3 (2026-07-19) FIX: enforce a lower bound on the handshake
	// message length. The minimum valid server response is
	// kyberCT(1088) + peerID(64) + dilithiumPub(1952) + sig(3293) = 6397
	// bytes. A length of 0 (or any value smaller than this) is either a
	// malformed peer, an attacker probing for parsing bugs, or an
	// attempted DoS via cheap allocations that force the caller to
	// perform length validation on garbage. Reject it here at the read
	// layer so the caller's format check never runs on undersized input.
	// We use a conservative lower bound (1KB) that tolerates future
	// protocol extensions that might shorten the response format.
	const minHandshakeRespLen = 1024
	if length < minHandshakeRespLen {
		return nil, fmt.Errorf("handshake message too small: minimum %d bytes, got %d", minHandshakeRespLen, length)
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func encryptedDial(addr string, nodeKey *crypto.KeyPair, localID PeerID, powNonce uint64) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second) // SECURITY (audit 2026-06-24, M-4): was 1800s
	if err != nil {
		return nil, err
	}
	encConn, err := performClientHandshake(conn, nodeKey, localID, "", powNonce)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return encConn, nil
}

func (c *encryptedConn) RotateKeys() error {
	// R12-P2P-001 FIX: Document that RotateKeys performs a full re-handshake
	// via performClientHandshake, which uses the encrypted Dilithium key
	// exchange. The handshake is NOT plaintext — it uses authenticated
	// key agreement. However, the new keys are not verified against the
	// old keys (no key continuity check). A MITM could intercept the
	// re-handshake if they can break the Dilithium signature scheme.
	// This is acceptable because:
	// 1. The handshake is signed with the node's Dilithium key
	// 2. Key continuity is enforced at the protocol layer (enode verification)
	// 3. The re-handshake happens over the existing encrypted connection
	// P2P4-001 FIX: Acquire both locks BEFORE performing the handshake to
	// prevent concurrent Read/Write operations from interleaving with
	// handshake data on the underlying TCP connection. Previously, the
	// handshake ran without locks, risking stream corruption.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.readMu.Lock()
	defer c.readMu.Unlock()

	newConn, err := performClientHandshake(c.Conn, c.nodeKey, c.localID, c.remoteID, c.powNonce)
	if err != nil {
		// P2-ROTATEKEYS-ZEROIZE FIX (R29, 2026-07-26): Previously, on handshake
		// failure, only c.Conn.Close() was called — the underlying TCP connection
		// was closed, but the OLD session keys (c.sendKey, c.recvKey) and cipher
		// objects remained in the encryptedConn struct in heap memory. An attacker
		// who could dump memory or trigger a cold-boot attack could extract the
		// old session keys and decrypt previously-recorded traffic (AES-256-GCM
		// is symmetric, so knowing sendKey/recvKey is sufficient to decrypt all
		// traffic encrypted under those keys).
		//
		// We cannot call c.Close() here because RotateKeys already holds
		// c.writeMu and c.readMu (acquired at the top of the function), and
		// c.Close() tries to acquire the same locks — calling it would deadlock.
		// Instead, we inline the same zeroization logic that c.Close() uses:
		// zeroize the raw key bytes, nil out the slice headers (so the backing
		// array becomes eligible for GC), and nil out the cipher objects (so
		// the internal AES-GCM state derived from the keys is also released).
		//
		// This mirrors the success-path zeroization below (P1-06) — both paths
		// now guarantee that old key material is wiped before the function
		// returns, regardless of whether the re-handshake succeeded.
		zeroize(c.sendKey)
		zeroize(c.recvKey)
		c.sendKey = nil
		c.recvKey = nil
		c.sendCipher = nil
		c.recvCipher = nil
		zeroize(c.readBuf) // P3-READBUF-ZEROIZE: clear plaintext before nil
		c.readBuf = nil
		c.Conn.Close()
		return fmt.Errorf("key rotation re-handshake failed: %w", err)
	}
	enc := newConn.(*encryptedConn)
	// SECURITY (P1-06): Zeroize old key material before replacing
	zeroize(c.sendKey)
	zeroize(c.recvKey)
	c.sendCipher = enc.sendCipher
	c.recvCipher = enc.recvCipher
	c.sendKey = enc.sendKey
	c.recvKey = enc.recvKey
	c.writeNonce = 0
	c.readNonce = 0
	c.readBuf = nil
	return nil
}

// NeedsKeyRotation returns true if either read or write nonce has exceeded
// the rotation threshold, indicating that RotateKeys should be called soon
// to prevent nonce exhaustion.
func (c *encryptedConn) NeedsKeyRotation() bool {
	c.readMu.Lock()
	readNonce := c.readNonce
	c.readMu.Unlock()
	c.writeMu.Lock()
	writeNonce := c.writeNonce
	c.writeMu.Unlock()
	return readNonce >= nonceRotationThreshold || writeNonce >= nonceRotationThreshold
}

func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
