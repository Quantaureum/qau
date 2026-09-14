// Quantaureum Node source, version 1.0.0.
package stealth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/hkdf"
)

const maxAnnouncements = 10000

const stealthKeyPoolSize = 256

type StealthManager struct {
	mu            sync.RWMutex
	registry      map[types.Address]*StealthMetaAddress
	announcements []*StealthAnnouncement
	keyPools      map[types.Address]*StealthKeyPool
}

type StealthKeyPool struct {
	mu      sync.RWMutex
	entries []*StealthKeyPoolEntry
}

type StealthKeyPoolEntry struct {
	Index      uint32
	PublicKey  []byte
	PrivateKey []byte
	Used       bool
}

func NewStealthManager() *StealthManager {
	return &StealthManager{
		registry:      make(map[types.Address]*StealthMetaAddress),
		announcements: make([]*StealthAnnouncement, 0),
		keyPools:      make(map[types.Address]*StealthKeyPool),
	}
}

func GenerateStealthKeys() (*StealthMetaAddress, *crypto.PrivateKey, *crypto.PrivateKey, []byte, error) {
	spendKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate spend key: %w", err)
	}

	viewKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate view key: %w", err)
	}

	kemPub, kemPriv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate KEM key: %w", err)
	}

	kemPubBytes, err := kemPub.MarshalBinary()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal KEM public key: %w", err)
	}

	kemPrivBytes := make([]byte, kyber768.PrivateKeySize)
	kemPriv.Pack(kemPrivBytes)

	metaAddr := &StealthMetaAddress{
		SpendPublicKey: spendKeyPair.Public.Bytes(),
		ViewPublicKey:  viewKeyPair.Public.Bytes(),
		KemPublicKey:   kemPubBytes,
	}

	return metaAddr, spendKeyPair.Private, viewKeyPair.Private, kemPrivBytes, nil
}

func (sm *StealthManager) RegisterStealthAddress(ownerAddr types.Address, metaAddr *StealthMetaAddress) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if metaAddr == nil || len(metaAddr.SpendPublicKey) == 0 || len(metaAddr.ViewPublicKey) == 0 || len(metaAddr.KemPublicKey) == 0 {
		return ErrInvalidMetaAddress
	}

	if _, exists := sm.registry[ownerAddr]; exists {
		return ErrAlreadyRegistered
	}

	sm.registry[ownerAddr] = metaAddr

	pool := &StealthKeyPool{
		entries: make([]*StealthKeyPoolEntry, 0, stealthKeyPoolSize),
	}
	sm.keyPools[ownerAddr] = pool

	return nil
}

func (sm *StealthManager) LookupStealthMetaAddress(addr types.Address) (*StealthMetaAddress, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	meta, ok := sm.registry[addr]
	if !ok {
		return nil, ErrAnnouncementNotFound
	}

	result := &StealthMetaAddress{
		SpendPublicKey: make([]byte, len(meta.SpendPublicKey)),
		ViewPublicKey:  make([]byte, len(meta.ViewPublicKey)),
		KemPublicKey:   make([]byte, len(meta.KemPublicKey)),
		RegisteredAt:   meta.RegisteredAt,
	}
	copy(result.SpendPublicKey, meta.SpendPublicKey)
	copy(result.ViewPublicKey, meta.ViewPublicKey)
	copy(result.KemPublicKey, meta.KemPublicKey)

	return result, nil
}

// GenerateStealthAddress creates a one-time stealth address using Kyber KEM.
//
// Protocol:
// 1. Sender calls Kyber768.Encapsulate(receiverKemPubKey) → (sharedSecret, ciphertext)
// 2. Sender derives a deterministic index from the sharedSecret via HKDF
// 3. Sender generates a one-time Dilithium3 key pair seeded by the sharedSecret
// 4. The one-time public key becomes the stealth address
// 5. The announcement contains the Kyber ciphertext (not the ephemeral Dilithium3 key)
// 6. Receiver decapsulates the ciphertext → same sharedSecret → same index → same key pair
//
// CRITICAL FIX: Sender MUST sign the announcement to prove ownership of funds.
// Without this, attackers could create announcements for addresses they don't own.
func (sm *StealthManager) GenerateStealthAddress(metaAddr *StealthMetaAddress, senderSpendKey *crypto.PrivateKey) (*StealthAddress, *StealthAnnouncement, error) {
	if metaAddr == nil {
		return nil, nil, ErrInvalidMetaAddress
	}

	if len(metaAddr.KemPublicKey) == 0 {
		return nil, nil, ErrInvalidMetaAddress
	}

	sharedSecret, kemCt, err := encapsulateSharedSecret(metaAddr.KemPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encapsulate shared secret: %w", err)
	}

	stealthIndex, err := deriveStealthIndex(sharedSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("stealth index derivation failed: %w", err)
	}

	stealthKeyPair, err := deriveDeterministicKeyPair(sharedSecret, stealthIndex)
	if err != nil {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
		return nil, nil, fmt.Errorf("failed to derive stealth key pair: %w", err)
	}

	stealthPubKey := stealthKeyPair.Public.Bytes()
	addrHash := sha256.Sum256(stealthPubKey)

	stealthAddr := &StealthAddress{
		EphemeralPubKey: stealthPubKey,
		AddressHash:     addrHash,
	}

	// CRITICAL FIX: Generate sender signature to prove ownership of funds
	var senderPubKey, senderSig []byte
	if senderSpendKey != nil {
		senderPubKey = senderSpendKey.PublicKey().Bytes()
		// Sign the stealth address hash to prove sender owns the funds
		sig, err := senderSpendKey.Sign(addrHash[:])
		if err != nil {
			for i := range sharedSecret {
				sharedSecret[i] = 0
			}
			return nil, nil, fmt.Errorf("failed to sign announcement: %w", err)
		}
		senderSig = sig
	}

	announcement := &StealthAnnouncement{
		EphemeralPubKey: stealthPubKey,
		StealthAddrHash: addrHash,
		KemCiphertext:   kemCt,
		SenderPubKey:    senderPubKey,
		SenderSignature: senderSig,
	}

	sm.mu.Lock()
	if len(sm.announcements) >= maxAnnouncements {
		for i := 0; i < maxAnnouncements/2; i++ {
			sm.announcements[i] = nil
		}
		sm.announcements = sm.announcements[maxAnnouncements/2:]
	}
	sm.announcements = append(sm.announcements, announcement)
	sm.mu.Unlock()

	for i := range sharedSecret {
		sharedSecret[i] = 0
	}

	return stealthAddr, announcement, nil
}

// ScanAnnouncements scans all announcements for stealth addresses belonging to the receiver.
//
// For each announcement:
// 1. Decapsulate the Kyber ciphertext → sharedSecret
// 2. Derive the same deterministic index and key pair
// 3. Compare the derived public key hash with the announcement's stealth address hash
// 4. CRITICAL FIX: Verify sender signature to prove they own the funds being spent
// 5. If all checks pass, this stealth address belongs to the receiver
func (sm *StealthManager) ScanAnnouncements(kemPrivKey []byte, spendPubKey []byte) ([]*StealthAddress, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	results := make([]*StealthAddress, 0)

	for _, ann := range sm.announcements {
		sharedSecret, err := decapsulateSharedSecret(kemPrivKey, ann.KemCiphertext)
		if err != nil {
			continue
		}

		stealthIndex, derr := deriveStealthIndex(sharedSecret)
		if derr != nil {
			continue
		}

		stealthKeyPair, err := deriveDeterministicKeyPair(sharedSecret, stealthIndex)
		if err != nil {
			for i := range sharedSecret {
				sharedSecret[i] = 0
			}
			continue
		}

		derivedPubKey := stealthKeyPair.Public.Bytes()
		derivedHash := sha256.Sum256(derivedPubKey)

		for i := range sharedSecret {
			sharedSecret[i] = 0
		}

		if derivedHash != ann.StealthAddrHash {
			continue
		}

		// A matching announcement MUST carry a sender signature; verify it.
		// PRIV-STEALTH-01 FIX (deep-audit 2026-07-12): a matching announcement
		// that is missing SenderPubKey/SenderSignature is skipped (continue), not
		// treated as a fatal scan error. The old `return err` let anyone who
		// encapsulated to the victim's KEM key inject a single unsigned matching
		// announcement and thereby prevent the victim from detecting ANY of their
		// incoming stealth outputs (DoS). This mirrors the signature-verification
		// failure path just below, which already continues.
		if ann.SenderPubKey == nil || ann.SenderSignature == nil {
			continue
		}
		if err := sm.verifySenderSignature(ann, spendPubKey); err != nil {
			// Signature verification failed - could be fraud attempt
			continue
		}

		results = append(results, &StealthAddress{
			EphemeralPubKey: ann.EphemeralPubKey,
			AddressHash:     ann.StealthAddrHash,
		})
	}

	return results, nil
}

// verifySenderSignature verifies that the announcement was signed by the
// holder of the private key corresponding to ann.SenderPubKey.
//
// DESIGN NOTE (audit 2026-06-14): The stealth model in this codebase uses a
// one-time sender keypair (see PrivacyManager.SendPrivacyTransaction, which
// generates a fresh sender key per announcement). Therefore this signature
// proves ONLY that the announcement was created by someone holding that
// one-time private key — it does NOT prove ownership of the funds being spent.
// Fund ownership is enforced elsewhere by the confidential transaction's
// input/nullifier accounting, not by this signature.
//
// The expectedSpendPubKey parameter is therefore intentionally NOT bound into
// the verification: binding it would break the one-time-key model (senders do
// not possess the receiver's spend key). The parameter is retained for API
// stability and future protocol extensions that may introduce sender identity
// binding; today it is validated only for size (defensive).
func (sm *StealthManager) verifySenderSignature(ann *StealthAnnouncement, expectedSpendPubKey []byte) error {
	// Defensive size validation of the expected key (not used for binding today).
	if len(expectedSpendPubKey) != crypto.Dilithium3PublicKeySize {
		return fmt.Errorf("invalid expected spend public key size: expected %d, got %d",
			crypto.Dilithium3PublicKeySize, len(expectedSpendPubKey))
	}

	// The sender must provide their (one-time) public key
	if len(ann.SenderPubKey) != crypto.Dilithium3PublicKeySize {
		return fmt.Errorf("invalid sender public key size: expected %d, got %d",
			crypto.Dilithium3PublicKeySize, len(ann.SenderPubKey))
	}

	// Verify signature size
	if len(ann.SenderSignature) != crypto.Dilithium3SignatureSize {
		return fmt.Errorf("invalid signature size: expected %d, got %d",
			crypto.Dilithium3SignatureSize, len(ann.SenderSignature))
	}

	// Signature message is the stealth address hash - proves the announcement
	// was created by the holder of the one-time sender key.
	sigMsg := ann.StealthAddrHash[:]

	// Verify the signature using the sender's public key
	pubKey, err := crypto.PublicKeyFromBytes(ann.SenderPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse sender public key: %w", err)
	}

	if !crypto.Verify(pubKey, sigMsg, ann.SenderSignature) {
		return errors.New("sender signature verification failed")
	}

	return nil
}

// RecoverPrivateKey recovers the private key for a stealth address.
//
// The sender and receiver both derive the same deterministic key pair from the
// shared secret, so the receiver can directly recover the private key.
func (sm *StealthManager) RecoverPrivateKey(announcement *StealthAnnouncement, kemPrivKey []byte, spendPrivKey []byte) ([]byte, error) {
	if announcement == nil {
		return nil, ErrRecoveryFailed
	}

	sharedSecret, err := decapsulateSharedSecret(kemPrivKey, announcement.KemCiphertext)
	if err != nil {
		return nil, ErrRecoveryFailed
	}

	stealthIndex, err := deriveStealthIndex(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("stealth index derivation failed: %w", err)
	}

	stealthKeyPair, err := deriveDeterministicKeyPair(sharedSecret, stealthIndex)
	if err != nil {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
		return nil, ErrRecoveryFailed
	}

	privKeyBytes := stealthKeyPair.Private.Bytes()

	for i := range sharedSecret {
		sharedSecret[i] = 0
	}

	return privKeyBytes, nil
}

func (sm *StealthManager) AnnouncementCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.announcements)
}

func encapsulateSharedSecret(kemPubKeyBytes []byte) (sharedSecret []byte, ciphertext []byte, err error) {
	if len(kemPubKeyBytes) != kyber768.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid KEM public key size: expected %d, got %d", kyber768.PublicKeySize, len(kemPubKeyBytes))
	}

	kemPub := &kyber768.PublicKey{}
	kemPub.Unpack(kemPubKeyBytes)

	ct := make([]byte, kyber768.CiphertextSize)
	ss := make([]byte, kyber768.SharedKeySize)
	kemPub.EncapsulateTo(ct, ss, nil)

	return ss, ct, nil
}

func decapsulateSharedSecret(kemPrivKeyBytes []byte, ciphertext []byte) ([]byte, error) {
	if len(kemPrivKeyBytes) != kyber768.PrivateKeySize {
		return nil, fmt.Errorf("invalid KEM private key size: expected %d, got %d", kyber768.PrivateKeySize, len(kemPrivKeyBytes))
	}

	if len(ciphertext) != kyber768.CiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext size: expected %d, got %d", kyber768.CiphertextSize, len(ciphertext))
	}

	kemPriv := &kyber768.PrivateKey{}
	kemPriv.Unpack(kemPrivKeyBytes)

	ss := make([]byte, kyber768.SharedKeySize)
	kemPriv.DecapsulateTo(ss, ciphertext)

	return ss, nil
}

// deriveStealthIndex derives a deterministic 32-bit index from the shared secret.
// This index is used to select or generate a specific key pair via hierarchical
// deterministic derivation (index is mixed into the key seed at deriveDeterministicKeyPair).
// Full 32-bit entropy eliminates the ~2^24 collision surface that existed when the
// index was reduced modulo 256.
// R11-PRIV-006 FIX: Return error on HKDF failure instead of silently
// returning index 0, which could cause key pair collisions.
func deriveStealthIndex(sharedSecret []byte) (uint32, error) {
	reader := hkdf.New(sha256.New, sharedSecret, nil, []byte("quantaureum-stealth-index-v2"))
	indexBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, indexBytes); err != nil {
		return 0, fmt.Errorf("deriveStealthIndex: HKDF read failed: %w", err)
	}
	return binary.BigEndian.Uint32(indexBytes), nil
}

// deriveDeterministicKeyPair generates a Dilithium3 key pair deterministically
// from the shared secret and index. Both sender and receiver will derive
// the same key pair given the same shared secret.
//
// This replaces the previous XOR-based approach which was broken for Dilithium3
// because XOR destroys the mathematical relationship between public and private keys.
// Instead, we use the shared secret as entropy to seed a deterministic key generation.
func deriveDeterministicKeyPair(sharedSecret []byte, index uint32) (*crypto.KeyPair, error) {
	reader := hkdf.New(sha256.New, sharedSecret, nil, []byte("quantaureum-stealth-keypair-v2"))

	seed := make([]byte, 96)
	if _, err := io.ReadFull(reader, seed); err != nil {
		return nil, fmt.Errorf("stealth: failed to derive key seed: %w", err)
	}

	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	seed = append(seed, indexBytes...)

	return crypto.GenerateKeyPairFromSeed(seed)
}

func generateRandomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
