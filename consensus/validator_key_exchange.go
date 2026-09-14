// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	maxValidatorKyberKeys    = 250000
	maxEncryptedSessions     = 1024
	sessionKeyValidity       = 4 * time.Hour
	sessionKeyRotationPeriod = 1 * time.Hour
	kyberPublicKeySize       = crypto.KyberPublicKeySize
	kyberCiphertextSize      = crypto.KyberCiphertextSize
)

var (
	ErrKyberKeyNotRegistered = errors.New("kyber public key not registered for validator")
	ErrKyberKeyAlreadyExists = errors.New("kyber public key already registered for validator")
	ErrKyberKeyInvalidSize   = errors.New("invalid kyber public key size")
	ErrSessionNotFound       = errors.New("encrypted session not found")
	ErrSessionExpired        = errors.New("encrypted session expired")
	ErrSessionLimitExceeded  = errors.New("encrypted session limit exceeded")
	ErrInvalidCiphertext     = errors.New("invalid ciphertext for session")
	ErrInvalidNonce          = errors.New("invalid nonce")
	// SECURITY FIX (P1): SealForPeer sender authentication.
	// The sender address embedded inside the encrypted payload does not
	// match the peer address supplied to OpenFromPeer.
	ErrSenderMismatch = errors.New("sender address mismatch in encrypted payload")
	// SECURITY FIX (P1): SealForPeer sender authentication.
	// The sender address is not a registered validator on this node.
	ErrSenderNotValidator = errors.New("sender is not a registered validator")
)

type EncryptedSession struct {
	PeerAddr    types.Address
	SendNonce   uint64
	RecvNonce   uint64
	Established time.Time
	ExpiresAt   time.Time
	sendCipher  cipher.AEAD
	recvCipher  cipher.AEAD
	// audit-fix MEDIUM: protect nonce counters from concurrent access to
	// prevent nonce reuse in AES-GCM, which would be catastrophic.
	sendMu sync.Mutex
	recvMu sync.Mutex
}

func (s *EncryptedSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt) // NOT consensus-critical: local session expiry check
}

func (s *EncryptedSession) Encrypt(plaintext []byte) ([]byte, error) {
	if s.IsExpired() {
		return nil, ErrSessionExpired
	}
	// audit-fix MEDIUM: mutex protects SendNonce from concurrent access to
	// prevent nonce reuse in AES-GCM, which would compromise confidentiality
	// and integrity of the encrypted channel.
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	// audit-fix MEDIUM: check for nonce counter exhaustion before increment
	if s.SendNonce == ^uint64(0) {
		return nil, ErrInvalidNonce
	}
	nonce := make([]byte, 12)
	for i := 0; i < 8; i++ {
		nonce[i] = byte(s.SendNonce >> uint(i*8))
	}
	s.SendNonce++
	return s.sendCipher.Seal(nil, nonce, plaintext, nil), nil
}

func (s *EncryptedSession) Decrypt(ciphertext []byte) ([]byte, error) {
	if s.IsExpired() {
		return nil, ErrSessionExpired
	}
	// audit-fix MEDIUM: mutex protects RecvNonce from concurrent access to
	// prevent nonce reuse and ensure monotonic nonce ordering.
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	// audit-fix MEDIUM: check for nonce counter exhaustion before increment
	if s.RecvNonce == ^uint64(0) {
		return nil, ErrInvalidNonce
	}
	nonce := make([]byte, 12)
	for i := 0; i < 8; i++ {
		nonce[i] = byte(s.RecvNonce >> uint(i*8))
	}
	s.RecvNonce++
	return s.recvCipher.Open(nil, nonce, ciphertext, nil)
}

// TSSAuthSigner provides Dilithium3 authentication for TSS share transport.
// AUDIT (2026) HIGH-07: SealForPeer/OpenFromPeer previously relied solely
// on Kyber KEM + AES-GCM with sender address embedded in plaintext. The AES
// key was derived from the Kyber shared secret (which only requires the
// receiver's public key) + public addresses — the sender's private key never
// entered the derivation, allowing anyone to forge messages.
type TSSAuthSigner interface {
	// SignTSS signs the message with the local validator's Dilithium3 key.
	SignTSS(msg []byte) ([]byte, error)
	// VerifyTSS verifies the signature was produced by the claimed sender.
	VerifyTSS(sender types.Address, msg, sig []byte) bool
}

// ValidatorSetLookup checks whether an address is a known active consensus
// validator. AUDIT (2026) CRND-06: Kyber key registration uses TOFU
// (trust-on-first-use) without binding the registering address to consensus
// identity. An attacker can race ahead of chain sync and poison the registry
// with their own Kyber key for a validator address that hasn't yet appeared
// on-chain, then intercept that validator's TSS shares.
// When a ValidatorSetLookup is configured (production), RegisterKyberKey
// rejects addresses that are not currently in the validator set.
type ValidatorSetLookup interface {
	// IsActiveValidator returns true if addr is a known active validator
	// in the current consensus set.
	IsActiveValidator(addr types.Address) bool
}

type ValidatorKeyExchange struct {
	mu         sync.RWMutex
	kyberKeys  map[types.Address][]byte
	sessions   map[string]*EncryptedSession
	localAddr  types.Address
	localKyber *crypto.KyberKeyPair

	// AUDIT (2026) HIGH-07/CRND-07: Dilithium3 sender authentication
	authSigner  TSSAuthSigner
	requireAuth bool
	// CRND-07: track latest timestamp per peer to reject replayed messages
	peerTimestamps map[types.Address]int64
	// AUDIT (2026) CRND-01: track latest Kyber-broadcast timestamp per
	// peer to reject replayed key-exchange broadcasts. Without this, a captured
	// signed broadcast (addr || kyberPubKey) could be replayed indefinitely,
	// enabling downgrade attacks (replay an older valid key to overwrite a
	// legitimately rotated key). The timestamp is included in the signed
	// message, so it cannot be forged without the validator's Dilithium key.
	kyberBroadcastTimestamps map[types.Address]int64
	// AUDIT (2026) CRND-06: optional consensus identity binding.
	// When set, RegisterKyberKey rejects addresses that are not in the
	// active validator set, preventing pre-sync registry poisoning.
	validatorLookup ValidatorSetLookup
}

func NewValidatorKeyExchange(localAddr types.Address) (*ValidatorKeyExchange, error) {
	kp, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate local Kyber keypair: %w", err)
	}
	return &ValidatorKeyExchange{
		kyberKeys:                make(map[types.Address][]byte),
		sessions:                 make(map[string]*EncryptedSession),
		localAddr:                localAddr,
		localKyber:               kp,
		requireAuth:              true, // AUDIT (2026) HIGH-07: fail-closed by default
		peerTimestamps:           make(map[types.Address]int64),
		kyberBroadcastTimestamps: make(map[types.Address]int64),
	}, nil
}

func NewValidatorKeyExchangeWithKey(localAddr types.Address, kp *crypto.KyberKeyPair) *ValidatorKeyExchange {
	return &ValidatorKeyExchange{
		kyberKeys:                make(map[types.Address][]byte),
		sessions:                 make(map[string]*EncryptedSession),
		localAddr:                localAddr,
		localKyber:               kp,
		requireAuth:              true, // AUDIT (2026) HIGH-07: fail-closed by default
		peerTimestamps:           make(map[types.Address]int64),
		kyberBroadcastTimestamps: make(map[types.Address]int64),
	}
}

// CheckKyberBroadcastFreshness validates that a Kyber key-exchange broadcast
// timestamp is within the acceptable clock-skew window AND strictly newer
// than the last timestamp seen from the same validator. This prevents replay
// attacks where a captured signed broadcast is retransmitted later.
//
// AUDIT (2026) CRND-01 FIX: The signed message previously had no
// timestamp/nonce, making it replayable indefinitely. Now the timestamp is
// included in the signed payload (addr || timestamp || kyberPubKey), so it
// cannot be forged without the validator's Dilithium key, and stale or
// replayed broadcasts are rejected.
//
// Returns nil if the timestamp is fresh and strictly monotonic; otherwise
// returns an error describing why the broadcast was rejected.
//
// AUDIT (2026) CRND-FIX: Split into check-only (this function)
// and commit (CommitKyberBroadcastFreshness). Previously, this function both
// checked AND wrote the high-water mark, so a forged broadcast with a future
// timestamp would advance the high-water mark BEFORE signature verification
// — blocking the legitimate validator's subsequent broadcast as "out-of-order".
// Now the caller must call CommitKyberBroadcastFreshness AFTER signature
// verification succeeds.
func (vke *ValidatorKeyExchange) CheckKyberBroadcastFreshness(addr types.Address, timestamp int64) error {
	const maxClockSkewSeconds = int64(5 * 60) // 5 minutes, matching OpenFromPeer
	now := time.Now().Unix()
	if timestamp < now-maxClockSkewSeconds || timestamp > now+maxClockSkewSeconds {
		return fmt.Errorf("kyber broadcast timestamp out of range (ts=%d, now=%d, skew=%ds)",
			timestamp, now, maxClockSkewSeconds)
	}

	vke.mu.Lock()
	defer vke.mu.Unlock()
	lastTs, exists := vke.kyberBroadcastTimestamps[addr]
	if exists && timestamp <= lastTs {
		return fmt.Errorf("kyber broadcast replayed or out-of-order (ts=%d, last=%d)", timestamp, lastTs)
	}
	// NOTE: Do NOT write the high-water mark here. The caller must call
	// CommitKyberBroadcastFreshness after signature verification succeeds.
	return nil
}

// CommitKyberBroadcastFreshness records the high-water mark for a Kyber
// key-exchange broadcast. Must be called AFTER signature verification
// succeeds to prevent a forged broadcast from poisoning the freshness cache.
// AUDIT (2026) CRND-FIX.
func (vke *ValidatorKeyExchange) CommitKyberBroadcastFreshness(addr types.Address, timestamp int64) {
	vke.mu.Lock()
	defer vke.mu.Unlock()
	// Only update if the new timestamp is greater (defensive — the check
	// should have already verified this, but a concurrent legitimate broadcast
	// may have committed a higher timestamp in the meantime).
	if lastTs, exists := vke.kyberBroadcastTimestamps[addr]; exists && timestamp <= lastTs {
		return
	}
	vke.kyberBroadcastTimestamps[addr] = timestamp
}

// SetAuthSigner configures the Dilithium3 signer for TSS share authentication.
// AUDIT (2026) HIGH-07: Production deployments MUST call this before
// using SealForPeer/OpenFromPeer to prevent sender forgery.
func (vke *ValidatorKeyExchange) SetAuthSigner(signer TSSAuthSigner) {
	vke.mu.Lock()
	defer vke.mu.Unlock()
	vke.authSigner = signer
}

// SetRequireAuth enables/disables strict authentication mode.
func (vke *ValidatorKeyExchange) SetRequireAuth(require bool) {
	vke.mu.Lock()
	defer vke.mu.Unlock()
	vke.requireAuth = require
}

// SetValidatorLookup configures the consensus identity binding for Kyber key
// registration. AUDIT (2026) CRND-06: when set, RegisterKyberKey will
// reject addresses that are not currently in the active validator set,
// preventing pre-sync registry poisoning. Production deployments MUST call
// this before any TSS key exchange occurs. When nil (default, used by tests),
// the TOFU behavior is retained for backward compatibility.
func (vke *ValidatorKeyExchange) SetValidatorLookup(lookup ValidatorSetLookup) {
	vke.mu.Lock()
	defer vke.mu.Unlock()
	vke.validatorLookup = lookup
}

func (vke *ValidatorKeyExchange) RegisterKyberKey(addr types.Address, kyberPubKey []byte) error {
	if len(kyberPubKey) != kyberPublicKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrKyberKeyInvalidSize, kyberPublicKeySize, len(kyberPubKey))
	}

	vke.mu.Lock()
	defer vke.mu.Unlock()

	// AUDIT (2026) CRND-06: bind Kyber key registration to consensus
	// identity when a validator set lookup is configured. Without this, an
	// attacker racing ahead of chain sync could register a Kyber key for a
	// validator address that hasn't appeared on-chain yet, then intercept
	// that validator's TSS shares once consensus starts. The lookup is
	// optional to preserve backward-compatible test behavior.
	if vke.validatorLookup != nil && !vke.validatorLookup.IsActiveValidator(addr) {
		return fmt.Errorf("%w: address %s is not an active consensus validator", ErrKyberKeyNotRegistered, addr.ShortString())
	}

	if len(vke.kyberKeys) >= maxValidatorKyberKeys {
		if _, exists := vke.kyberKeys[addr]; !exists {
			return ErrSessionLimitExceeded
		}
	}

	// SECURITY FIX (P1): Prevent Kyber key replacement attacks.
	// If a key is already registered for this address:
	//   - Same key  → idempotent success (no-op)
	//   - Different key → reject with ErrKyberKeyAlreadyExists
	// Previously, RegisterKyberKey silently overwrote the existing key,
	// allowing an attacker to replace any validator's Kyber public key via
	// a crafted P2P TSSKeyExchange message and subsequently decrypt or
	// forge that validator's encrypted TSS shares.
	if existing, exists := vke.kyberKeys[addr]; exists {
		if bytes.Equal(existing, kyberPubKey) {
			return nil // idempotent: same key already registered
		}
		return ErrKyberKeyAlreadyExists
	}

	vke.kyberKeys[addr] = append([]byte(nil), kyberPubKey...)
	return nil
}

// ForceReplaceKyberKey unconditionally replaces the Kyber public key for a
// validator address. This is used during legitimate key rotation: when a
// validator rotates its local Kyber key and broadcasts the new key, other
// nodes must replace the old key in their registry. The caller MUST have
// already verified that the sender is a known active validator before calling
// this method, since it bypasses the ErrKyberKeyAlreadyExists protection.
func (vke *ValidatorKeyExchange) ForceReplaceKyberKey(addr types.Address, kyberPubKey []byte) error {
	if len(kyberPubKey) != kyberPublicKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrKyberKeyInvalidSize, kyberPublicKeySize, len(kyberPubKey))
	}

	vke.mu.Lock()
	defer vke.mu.Unlock()

	vke.kyberKeys[addr] = append([]byte(nil), kyberPubKey...)
	return nil
}

func (vke *ValidatorKeyExchange) GetKyberKey(addr types.Address) ([]byte, error) {
	vke.mu.RLock()
	defer vke.mu.RUnlock()

	key, ok := vke.kyberKeys[addr]
	if !ok {
		return nil, ErrKyberKeyNotRegistered
	}
	return append([]byte(nil), key...), nil
}

// IsRegisteredValidator returns true if a Kyber public key has been registered
// for the given address. This is used by OpenFromPeer to verify that the sender
// of an encrypted TSS share is a known validator.
func (vke *ValidatorKeyExchange) IsRegisteredValidator(addr types.Address) bool {
	vke.mu.RLock()
	defer vke.mu.RUnlock()
	_, ok := vke.kyberKeys[addr]
	return ok
}

func (vke *ValidatorKeyExchange) UnregisterKyberKey(addr types.Address) {
	vke.mu.Lock()
	defer vke.mu.Unlock()

	delete(vke.kyberKeys, addr)

	// AUDIT (2026) CONS-FIX: prune timestamp maps to prevent
	// unbounded growth as validators churn. Previously these maps were
	// never cleaned up, causing slow memory growth on long-running nodes
	// with validator set turnover.
	delete(vke.peerTimestamps, addr)
	delete(vke.kyberBroadcastTimestamps, addr)

	prefix := addr.String()
	for k := range vke.sessions {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(vke.sessions, k)
		}
	}
}

func (vke *ValidatorKeyExchange) LocalKyberPublicKey() ([]byte, error) {
	vke.mu.RLock()
	defer vke.mu.RUnlock()

	if vke.localKyber == nil || vke.localKyber.Public == nil {
		return nil, ErrKyberKeyNotRegistered
	}
	return vke.localKyber.Public.Bytes()
}

func (vke *ValidatorKeyExchange) InitiateSession(peerAddr types.Address) ([]byte, error) {
	vke.mu.Lock()
	defer vke.mu.Unlock()

	peerKey, ok := vke.kyberKeys[peerAddr]
	if !ok {
		return nil, ErrKyberKeyNotRegistered
	}

	peerKyberPub, err := crypto.KyberPublicKeyFromBytes(peerKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer Kyber public key: %w", err)
	}

	sharedSecret, ciphertext, err := vke.localKyber.Private.Exchange(peerKyberPub)
	if err != nil {
		return nil, fmt.Errorf("Kyber encapsulation failed: %w", err)
	}
	defer crypto.ZeroBytesSecure(sharedSecret)

	sessionID := sessionID(vke.localAddr, peerAddr)

	sendKey, recvKey, err := deriveValidatorSessionKeys(sharedSecret, vke.localAddr, peerAddr, true)
	if err != nil {
		return nil, fmt.Errorf("session key derivation failed: %w", err)
	}

	session, err := newEncryptedSession(peerAddr, sendKey, recvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	vke.evictExpiredSessionsLocked()
	if len(vke.sessions) >= maxEncryptedSessions {
		return nil, ErrSessionLimitExceeded
	}

	vke.sessions[sessionID] = session
	return ciphertext, nil
}

func (vke *ValidatorKeyExchange) CompleteSession(peerAddr types.Address, ciphertext []byte) error {
	vke.mu.Lock()
	defer vke.mu.Unlock()

	if len(ciphertext) != kyberCiphertextSize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidCiphertext, kyberCiphertextSize, len(ciphertext))
	}

	sharedSecret, err := vke.localKyber.Private.Decapsulate(ciphertext)
	if err != nil {
		return fmt.Errorf("Kyber decapsulation failed: %w", err)
	}
	defer crypto.ZeroBytesSecure(sharedSecret)

	sessionID := sessionID(peerAddr, vke.localAddr)

	sendKey, recvKey, err := deriveValidatorSessionKeys(sharedSecret, peerAddr, vke.localAddr, false)
	if err != nil {
		return fmt.Errorf("session key derivation failed: %w", err)
	}

	session, err := newEncryptedSession(peerAddr, sendKey, recvKey)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	vke.evictExpiredSessionsLocked()
	if len(vke.sessions) >= maxEncryptedSessions {
		return ErrSessionLimitExceeded
	}

	vke.sessions[sessionID] = session
	return nil
}

func (vke *ValidatorKeyExchange) EncryptForPeer(peerAddr types.Address, plaintext []byte) ([]byte, error) {
	vke.mu.RLock()
	session, ok := vke.sessions[sessionID(vke.localAddr, peerAddr)]
	vke.mu.RUnlock()

	if !ok {
		return nil, ErrSessionNotFound
	}
	return session.Encrypt(plaintext)
}

func (vke *ValidatorKeyExchange) DecryptFromPeer(peerAddr types.Address, ciphertext []byte) ([]byte, error) {
	vke.mu.RLock()
	session, ok := vke.sessions[sessionID(peerAddr, vke.localAddr)]
	vke.mu.RUnlock()

	if !ok {
		return nil, ErrSessionNotFound
	}
	return session.Decrypt(ciphertext)
}

func (vke *ValidatorKeyExchange) GetSession(peerAddr types.Address) (*EncryptedSession, error) {
	vke.mu.RLock()
	defer vke.mu.RUnlock()

	sid := sessionID(vke.localAddr, peerAddr)
	session, ok := vke.sessions[sid]
	if !ok {
		sid = sessionID(peerAddr, vke.localAddr)
		session, ok = vke.sessions[sid]
	}
	if !ok {
		return nil, ErrSessionNotFound
	}
	if session.IsExpired() {
		return nil, ErrSessionExpired
	}
	return session, nil
}

func (vke *ValidatorKeyExchange) RotateLocalKey() error {
	vke.mu.Lock()
	defer vke.mu.Unlock()

	kp, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate new Kyber keypair: %w", err)
	}

	if vke.localKyber != nil && vke.localKyber.Private != nil {
		vke.localKyber.Private.Zeroize()
	}
	vke.localKyber = kp

	// SECURITY FIX (P1): Update the local address's Kyber key in the registry
	// to reflect the rotation. Without this, RegisterKyberKey would reject
	// the re-broadcast of the new key with ErrKyberKeyAlreadyExists (since the
	// old key is still in the map), breaking key rotation + re-broadcast flow.
	pubBytes, err := kp.Public.Bytes()
	if err != nil {
		return fmt.Errorf("failed to serialize new Kyber public key: %w", err)
	}
	vke.kyberKeys[vke.localAddr] = append([]byte(nil), pubBytes...)

	for k := range vke.sessions {
		delete(vke.sessions, k)
	}

	return nil
}

func (vke *ValidatorKeyExchange) ActiveSessionCount() int {
	vke.mu.RLock()
	defer vke.mu.RUnlock()

	count := 0
	for _, s := range vke.sessions {
		if !s.IsExpired() {
			count++
		}
	}
	return count
}

func (vke *ValidatorKeyExchange) RegisteredKeyCount() int {
	vke.mu.RLock()
	defer vke.mu.RUnlock()
	return len(vke.kyberKeys)
}

func (vke *ValidatorKeyExchange) GetStatus() map[string]interface{} {
	vke.mu.RLock()
	defer vke.mu.RUnlock()

	activeSessions := 0
	expiredSessions := 0
	for _, s := range vke.sessions {
		if s.IsExpired() {
			expiredSessions++
		} else {
			activeSessions++
		}
	}

	return map[string]interface{}{
		"registered_keys":  len(vke.kyberKeys),
		"active_sessions":  activeSessions,
		"expired_sessions": expiredSessions,
		"local_addr":       vke.localAddr.String(),
		"has_local_key":    vke.localKyber != nil,
	}
}

func (vke *ValidatorKeyExchange) evictExpiredSessionsLocked() {
	now := time.Now() // NOT consensus-critical: local session cleanup
	for k, s := range vke.sessions {
		if now.After(s.ExpiresAt) {
			delete(vke.sessions, k)
		}
	}
}

func (vke *ValidatorKeyExchange) SyncFromValidatorSet(vs *ValidatorSet) {
	count := vs.ValidatorCount()
	for i := 0; i < count; i++ {
		v := vs.GetValidatorByIndex(i)
		if v == nil || !v.Active {
			continue
		}
		if len(v.KyberPublicKeyBytes) == 0 {
			continue
		}
		vke.RegisterKyberKey(v.Address, v.KyberPublicKeyBytes)
	}
}

func sessionID(initiator, responder types.Address) string {
	return fmt.Sprintf("%s->%s", initiator.String(), responder.String())
}

func deriveValidatorSessionKeys(sharedSecret []byte, initiator, responder types.Address, isInitiator bool) (sendKey, recvKey []byte, err error) {
	initBytes := initiator.Bytes()
	respBytes := responder.Bytes()

	var firstID, secondID []byte
	if string(initBytes) < string(respBytes) {
		firstID, secondID = initBytes, respBytes
	} else {
		firstID, secondID = respBytes, initBytes
	}

	h := sha3.New256()
	h.Write([]byte("quantaureum-validator-session-v1"))
	h.Write(sharedSecret)
	h.Write(firstID)
	h.Write(secondID)
	prk := h.Sum(nil)

	sendKey = hkdfExpandValidatorKey(prk, "send", firstID, secondID)
	recvKey = hkdfExpandValidatorKey(prk, "recv", firstID, secondID)

	if isInitiator {
		return sendKey, recvKey, nil
	}
	return recvKey, sendKey, nil
}

func hkdfExpandValidatorKey(prk []byte, label string, firstID, secondID []byte) []byte {
	h := sha3.New256()
	h.Write(prk)
	h.Write([]byte(label))
	h.Write(firstID)
	h.Write(secondID)
	h.Write([]byte{0x01})
	result := h.Sum(nil)
	return result
}

func newEncryptedSession(peerAddr types.Address, sendKey, recvKey []byte) (*EncryptedSession, error) {
	sendBlock, err := aes.NewCipher(sendKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create send cipher: %w", err)
	}
	sendAEAD, err := cipher.NewGCM(sendBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create send AEAD: %w", err)
	}

	recvBlock, err := aes.NewCipher(recvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create recv cipher: %w", err)
	}
	recvAEAD, err := cipher.NewGCM(recvBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create recv AEAD: %w", err)
	}

	now := time.Now() // NOT consensus-critical: local session creation timestamp
	// L18-008 FIX: Do not store raw session keys in the struct.
	// The AEAD ciphers are sufficient for encryption/decryption;
	// retaining raw keys in plaintext is unnecessary and unsafe.
	// Zeroize the raw keys after creating AEAD ciphers.
	for i := range sendKey {
		sendKey[i] = 0
	}
	for i := range recvKey {
		recvKey[i] = 0
	}
	return &EncryptedSession{
		PeerAddr:    peerAddr,
		Established: now,
		ExpiresAt:   now.Add(sessionKeyValidity),
		sendCipher:  sendAEAD,
		recvCipher:  recvAEAD,
	}, nil
}

func GenerateKyberKeyPairForValidator() (*crypto.KyberKeyPair, error) {
	return crypto.GenerateKyberKeyPair()
}

func CreateValidatorKyberRegistration(addr types.Address) ([]byte, *crypto.KyberKeyPair, error) {
	kp, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Kyber keypair: %w", err)
	}

	pubBytes, err := kp.Public.Bytes()
	if err != nil {
		kp.Private.Zeroize()
		return nil, nil, fmt.Errorf("failed to serialize Kyber public key: %w", err)
	}

	return pubBytes, kp, nil
}

func VerifyKyberPublicKey(pubKeyBytes []byte) error {
	if len(pubKeyBytes) != kyberPublicKeySize {
		// FIX: Do not leak public key length in error message.
		// Previously: "expected %d bytes, got %d" — an attacker could use
		// the actual length to distinguish between key format variants.
		return ErrKyberKeyInvalidSize
	}

	_, err := crypto.KyberPublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid Kyber public key: %w", err)
	}
	return nil
}

// SealForPeer performs a one-shot Kyber768 KEM + AES-256-GCM DEM encryption
// for a peer. Unlike EncryptForPeer, this does not require a pre-established
// session — it encapsulates a fresh shared secret using the peer's registered
// Kyber public key on every call.
//
// This is used to encrypt TSS private shares (ScShare, S2Share, T0Share) before
// P2P transport. The output format is:
//
//	kyberCiphertext (1088 bytes) + nonce (12 bytes) + aesCiphertext
//
// SECURITY (P0 fix): Private signing shares MUST NEVER be sent in plaintext.
// Previous code broadcast ScShare + S2Share + T0Share unencrypted via
// BroadcastTSS, completely breaking t-of-n threshold signature security.
//
// SECURITY (P1 fix): The sender's address (localAddr, 20 bytes) is prepended
// to the plaintext BEFORE AES-GCM encryption, so it is authenticated by the
// AEAD tag. The receiver verifies in OpenFromPeer that:
//  1. The embedded sender address matches the peerAddr argument.
//  2. The sender is a registered validator on this node.
//
// This prevents an attacker from forging TSS shares under a different identity
// even if they know the aggregator's Kyber public key.
func (vke *ValidatorKeyExchange) SealForPeer(peerAddr types.Address, plaintext []byte) ([]byte, error) {
	vke.mu.RLock()
	peerKey, ok := vke.kyberKeys[peerAddr]
	localKyber := vke.localKyber
	localAddr := vke.localAddr
	signer := vke.authSigner
	requireAuth := vke.requireAuth
	vke.mu.RUnlock()

	if !ok {
		return nil, ErrKyberKeyNotRegistered
	}
	if localKyber == nil || localKyber.Private == nil {
		return nil, ErrKyberKeyNotRegistered
	}

	// AUDIT (2026) HIGH-07: Sign the payload with Dilithium3 to prove
	// the sender actually holds the private key for the claimed address.
	// The Kyber KEM shared secret alone doesn't authenticate the sender
	// because it only requires the receiver's public key.
	timestamp := time.Now().Unix()
	var sig []byte
	if signer != nil {
		sigMsg := buildTSSAuthMessage(localAddr, peerAddr, timestamp, plaintext)
		s, err := signer.SignTSS(sigMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to sign TSS payload: %w", err)
		}
		sig = s
	} else if requireAuth {
		return nil, fmt.Errorf("auth signer not configured (fail-closed)")
	}

	peerKyberPub, err := crypto.KyberPublicKeyFromBytes(peerKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer Kyber public key: %w", err)
	}

	sharedSecret, kyberCiphertext, err := localKyber.Private.Exchange(peerKyberPub)
	if err != nil {
		return nil, fmt.Errorf("Kyber encapsulation failed: %w", err)
	}
	defer crypto.ZeroBytesSecure(sharedSecret)

	aesKey := deriveOneShotKey(sharedSecret, localAddr[:], peerAddr[:])

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// AUDIT (2026) HIGH-07/CRND-07: Payload format is now:
	//   senderAddr(20) || timestamp(8) || sigLen(4) || sig(M) || plaintext(N)
	// The timestamp enables anti-replay; the signature proves sender identity.
	sigLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLenBytes, uint32(len(sig)))
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(timestamp))

	authenticatedPayload := make([]byte, 0, len(localAddr)+8+4+len(sig)+len(plaintext))
	authenticatedPayload = append(authenticatedPayload, localAddr[:]...)
	authenticatedPayload = append(authenticatedPayload, tsBytes...)
	authenticatedPayload = append(authenticatedPayload, sigLenBytes...)
	authenticatedPayload = append(authenticatedPayload, sig...)
	authenticatedPayload = append(authenticatedPayload, plaintext...)

	aesCiphertext := aead.Seal(nil, nonce, authenticatedPayload, nil)

	output := make([]byte, 0, len(kyberCiphertext)+len(nonce)+len(aesCiphertext))
	output = append(output, kyberCiphertext...)
	output = append(output, nonce...)
	output = append(output, aesCiphertext...)
	return output, nil
}

// OpenFromPeer decrypts a one-shot Kyber768 KEM + AES-256-GCM DEM ciphertext
// from a peer. This is the counterpart to SealForPeer.
//
// SECURITY (P0 fix): If decryption fails the caller MUST reject the message.
// No plaintext fallback is permitted for private TSS shares.
//
// SECURITY (P1 fix): After decryption, the sender's address is extracted from
// the first 20 bytes of the plaintext (authenticated by the AES-GCM tag).
// OpenFromPeer verifies that:
//  1. The embedded sender address matches the peerAddr argument.
//  2. The sender is a registered validator on this node (has a Kyber key).
//
// If either check fails, the message is rejected with an error.
func (vke *ValidatorKeyExchange) OpenFromPeer(peerAddr types.Address, ciphertext []byte) ([]byte, error) {
	vke.mu.RLock()
	localKyber := vke.localKyber
	localAddr := vke.localAddr
	signer := vke.authSigner
	requireAuth := vke.requireAuth
	vke.mu.RUnlock()

	if localKyber == nil || localKyber.Private == nil {
		return nil, ErrKyberKeyNotRegistered
	}

	kyberCtLen := crypto.KyberCiphertextSize
	nonceSize := 12 // AES-GCM standard nonce size

	if len(ciphertext) < kyberCtLen+nonceSize {
		return nil, ErrInvalidCiphertext
	}

	kyberCiphertext := ciphertext[:kyberCtLen]
	nonce := ciphertext[kyberCtLen : kyberCtLen+nonceSize]
	aesCiphertext := ciphertext[kyberCtLen+nonceSize:]

	sharedSecret, err := localKyber.Private.Decapsulate(kyberCiphertext)
	if err != nil {
		return nil, fmt.Errorf("Kyber decapsulation failed: %w", err)
	}
	defer crypto.ZeroBytesSecure(sharedSecret)

	aesKey := deriveOneShotKey(sharedSecret, peerAddr[:], localAddr[:])

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, aesCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	// AUDIT (2026) HIGH-07/CRND-07: Payload format is:
	//   senderAddr(20) || timestamp(8) || sigLen(4) || sig(M) || plaintext(N)
	addrLen := len(localAddr) // types.Address is 20 bytes
	if len(plaintext) < addrLen+8+4 {
		return nil, fmt.Errorf("%w: decrypted payload too short for header", ErrInvalidCiphertext)
	}

	var embeddedSender types.Address
	copy(embeddedSender[:], plaintext[:addrLen])

	// Verify the embedded sender matches the peerAddr argument.
	if embeddedSender != peerAddr {
		return nil, fmt.Errorf("%w: embedded=%s, expected=%s", ErrSenderMismatch, embeddedSender.String(), peerAddr.String())
	}

	// Verify the sender is a registered validator on this node.
	if !vke.IsRegisteredValidator(peerAddr) {
		return nil, fmt.Errorf("%w: %s", ErrSenderNotValidator, peerAddr.String())
	}

	// Extract timestamp and check freshness (CRND-07: anti-replay).
	timestamp := int64(binary.BigEndian.Uint64(plaintext[addrLen : addrLen+8]))
	const maxClockSkewSeconds = int64(5 * 60) // 5 minutes
	now := time.Now().Unix()
	if timestamp < now-maxClockSkewSeconds || timestamp > now+maxClockSkewSeconds {
		return nil, fmt.Errorf("%w: timestamp out of acceptable range (stale or future)", ErrInvalidCiphertext)
	}

	// CRND-07: Reject replayed messages (timestamp <= last seen from this peer).
	// CRND-FIX: Only READ the high-water mark here for early rejection.
	// The WRITE (updating the high-water mark) is deferred to AFTER signature
	// verification succeeds. Previously, the high-water mark was updated before
	// signature verification, allowing an attacker who can produce a valid
	// AES-GCM ciphertext (requires the Kyber shared secret) but an invalid
	// Dilithium signature to poison the high-water mark with a large timestamp.
	// The victim's subsequent legitimate shares (with smaller timestamps) would
	// then be falsely rejected as replays, causing TSS liveness DoS.
	vke.mu.RLock()
	lastTs, exists := vke.peerTimestamps[peerAddr]
	vke.mu.RUnlock()
	if exists && timestamp <= lastTs {
		return nil, fmt.Errorf("%w: replayed or out-of-order message (ts=%d, last=%d)", ErrInvalidCiphertext, timestamp, lastTs)
	}

	// Extract signature.
	sigOff := addrLen + 8
	sigLen := int(binary.BigEndian.Uint32(plaintext[sigOff : sigOff+4]))
	if sigLen < 0 || sigLen > 1<<16 {
		return nil, fmt.Errorf("%w: invalid signature length %d", ErrInvalidCiphertext, sigLen)
	}
	payloadOff := sigOff + 4 + sigLen
	if len(plaintext) < payloadOff {
		return nil, fmt.Errorf("%w: payload too short for signature", ErrInvalidCiphertext)
	}
	sig := plaintext[sigOff+4 : payloadOff]
	actualPlaintext := plaintext[payloadOff:]

	// AUDIT (2026) HIGH-07: Verify Dilithium3 signature.
	if sigLen > 0 {
		if signer == nil {
			return nil, fmt.Errorf("%w: signature present but no verifier configured", ErrInvalidCiphertext)
		}
		sigMsg := buildTSSAuthMessage(peerAddr, localAddr, timestamp, actualPlaintext)
		if !signer.VerifyTSS(peerAddr, sigMsg, sig) {
			return nil, fmt.Errorf("%w: Dilithium signature verification failed", ErrInvalidCiphertext)
		}
	} else if requireAuth {
		return nil, fmt.Errorf("%w: signature required but absent (fail-closed)", ErrInvalidCiphertext)
	}

	// CRND-FIX: Update the anti-replay high-water mark ONLY AFTER all
	// cryptographic checks (AES-GCM decryption + Dilithium signature verification)
	// have passed. This prevents state poisoning via messages with invalid
	// signatures but valid AES-GCM tags.
	// CRND-07 session binding: the timestamp is bound to the (peerAddr, payload)
	// via the Dilithium signature over buildTSSAuthMessage(peerAddr, localAddr,
	// timestamp, actualPlaintext), so it cannot be transplanted across sessions
	// or payloads without invalidating the signature.
	vke.mu.Lock()
	// Re-check under write lock: another goroutine may have updated the mark
	// concurrently between the RLock read above and this write lock.
	currentTs, stillExists := vke.peerTimestamps[peerAddr]
	if stillExists && timestamp <= currentTs {
		vke.mu.Unlock()
		return nil, fmt.Errorf("%w: concurrent replay detected (ts=%d, current=%d)", ErrInvalidCiphertext, timestamp, currentTs)
	}
	vke.peerTimestamps[peerAddr] = timestamp
	vke.mu.Unlock()

	return actualPlaintext, nil
}

// buildTSSAuthMessage constructs the message that the sender must sign.
// Covers: senderAddr || recipientAddr || timestamp || plaintext
func buildTSSAuthMessage(sender, recipient types.Address, timestamp int64, plaintext []byte) []byte {
	msg := make([]byte, 0, 20+20+8+len(plaintext))
	msg = append(msg, sender[:]...)
	msg = append(msg, recipient[:]...)
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(timestamp))
	msg = append(msg, tsBytes...)
	msg = append(msg, plaintext...)
	return msg
}

// deriveOneShotKey derives a 32-byte AES-256 key from a Kyber shared secret
// and both party addresses. The addresses are sorted to ensure both sides
// derive the same key regardless of who is the sender or receiver.
func deriveOneShotKey(sharedSecret, senderAddr, recipientAddr []byte) []byte {
	var firstID, secondID []byte
	if string(senderAddr) < string(recipientAddr) {
		firstID, secondID = senderAddr, recipientAddr
	} else {
		firstID, secondID = recipientAddr, senderAddr
	}

	h := sha3.New256()
	h.Write([]byte("quantaureum-tss-one-shot-v1"))
	h.Write(sharedSecret)
	h.Write(firstID)
	h.Write(secondID)
	return h.Sum(nil)
}
