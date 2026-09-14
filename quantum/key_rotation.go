// Quantaureum Node source, version 1.0.0.
package quantum

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"time"

	qaucrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

var (
	ErrKeyExpired         = errors.New("key has expired")
	ErrKeyNotYetValid     = errors.New("key is not yet valid")
	ErrRotationInProgress = errors.New("key rotation already in progress")
	ErrNoActiveKey        = errors.New("no active key available")
	ErrInvalidKeyID       = errors.New("invalid key ID")
	// ErrUnauthorizedSigner: the signer is not in the authorized list
	// audit fix (CRITICAL-2): Approve requires authorization checks
	ErrUnauthorizedSigner = errors.New("signer not authorized")
)

type KeyState uint8

const (
	KeyStatePending  KeyState = 0
	KeyStateActive   KeyState = 1
	KeyStateRetiring KeyState = 2
	KeyStateRetired  KeyState = 3
	KeyStateRevoked  KeyState = 4
)

type QuantumKey struct {
	ID               string
	PublicKey        []byte
	EncryptedPrivKey []byte `json:"-"`
	PrivKeyNonce     []byte `json:"-"`
	State            KeyState
	CreatedAt        int64
	ActivatedAt      int64
	ExpiresAt        int64
	Algorithm        string
	Version          uint64
}

type RotationPolicy struct {
	RotationInterval  time.Duration
	GracePeriod       time.Duration
	MaxKeyAge         time.Duration
	MinOverlapPeriod  time.Duration
	AutoRotate        bool
	RequireMultiSig   bool
	ApprovalThreshold int
	// R3-N2 FIX (2026-07-06): MaxRotations limits total rotations to prevent
	// infinite loop if AutoRotate bugs cause rapid cycling. 0 = unlimited.
	MaxRotations int
	// R3-N2 FIX (2026-07-06): MinRotationInterval is a defensive floor to
	// prevent excessively rapid rotations even if RotationInterval is
	// misconfigured to 0. Defaults to 1 minute.
	MinRotationInterval time.Duration
}

func DefaultRotationPolicy() *RotationPolicy {
	return &RotationPolicy{
		RotationInterval:    30 * 24 * time.Hour,
		GracePeriod:         7 * 24 * time.Hour,
		MaxKeyAge:           90 * 24 * time.Hour,
		MinOverlapPeriod:    24 * time.Hour,
		AutoRotate:          true,
		RequireMultiSig:     false,
		ApprovalThreshold:   2,
		MaxRotations:        1000,            // R3-N2 FIX: sane upper bound
		MinRotationInterval: 1 * time.Minute, // R3-N2 FIX: defensive floor
	}
}

type KeyRotationManager struct {
	mu              sync.RWMutex
	policy          *RotationPolicy
	keys            map[string]*QuantumKey
	activeKeyID     string
	rotationHistory []RotationRecord
	lastRotation    time.Time
	rotating        bool
	encKey          []byte
}

type RotationRecord struct {
	OldKeyID    string
	NewKeyID    string
	RotatedAt   int64
	BlockHeight uint64
	Reason      string
}

func NewKeyRotationManager(policy *RotationPolicy) (*KeyRotationManager, error) {
	if policy == nil {
		policy = DefaultRotationPolicy()
	}

	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		// L18-030 FIX: Zero out encKey before returning to avoid residual data.
		for i := range encKey {
			encKey[i] = 0
		}
		// audit-fix CRITICAL-2: Return error instead of panic to prevent DoS.
		// An attacker triggering entropy exhaustion could crash all validator nodes.
		return nil, fmt.Errorf("key_rotation: failed to generate encryption key: %w", err)
	}

	return &KeyRotationManager{
		policy:          policy,
		keys:            make(map[string]*QuantumKey),
		rotationHistory: make([]RotationRecord, 0),
		encKey:          encKey,
	}, nil
}

// encryptPrivKeyWith encrypts privKey using the provided encKey, avoiding the
// need to temporarily swap krm.encKey. FIX: extracted from
// encryptPrivKey to enable key rotation to re-encrypt with a new key without
// mutating shared state.
func encryptPrivKeyWith(encKey, privKey []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	encrypted := aesgcm.Seal(nil, nonce, privKey, nil)
	return encrypted, nonce, nil
}

func (krm *KeyRotationManager) encryptPrivKey(privKey []byte) ([]byte, []byte, error) {
	return encryptPrivKeyWith(krm.encKey, privKey)
}

func (krm *KeyRotationManager) decryptPrivKey(key *QuantumKey) ([]byte, error) {
	block, err := aes.NewCipher(krm.encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	decrypted, err := aesgcm.Open(nil, key.PrivKeyNonce, key.EncryptedPrivKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}
	return decrypted, nil
}

func (krm *KeyRotationManager) GenerateKey(algorithm string) (*QuantumKey, error) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	keyID := "qk-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + hex.EncodeToString(randBytes)

	kp, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate quantum key pair: %w", err)
	}
	pubKey := kp.Public.Bytes()
	privKey := kp.Private.Bytes()
	kp.Private.Zeroize()

	encPrivKey, nonce, err := krm.encryptPrivKey(privKey)
	for i := range privKey {
		privKey[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	now := time.Now()
	key := &QuantumKey{
		ID:               keyID,
		PublicKey:        pubKey,
		EncryptedPrivKey: encPrivKey,
		PrivKeyNonce:     nonce,
		State:            KeyStatePending,
		CreatedAt:        now.Unix(),
		ExpiresAt:        now.Add(krm.policy.MaxKeyAge).Unix(),
		Algorithm:        algorithm,
		Version:          1,
	}

	krm.keys[keyID] = key
	return key, nil
}

func (krm *KeyRotationManager) ActivateKey(keyID string) error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	key, exists := krm.keys[keyID]
	if !exists {
		return ErrInvalidKeyID
	}

	if key.State == KeyStateRevoked {
		return fmt.Errorf("cannot activate revoked key")
	}

	if krm.activeKeyID != "" {
		oldKey := krm.keys[krm.activeKeyID]
		if oldKey != nil && oldKey.State == KeyStateActive {
			oldKey.State = KeyStateRetiring
		}
	}

	key.State = KeyStateActive
	key.ActivatedAt = time.Now().Unix()
	krm.activeKeyID = keyID

	return nil
}

func (krm *KeyRotationManager) RotateKey(reason string, blockHeight uint64) (*RotationRecord, error) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if krm.rotating {
		return nil, ErrRotationInProgress
	}

	if krm.activeKeyID == "" {
		return nil, ErrNoActiveKey
	}

	// R3-N2 FIX (2026-07-06): Enforce MaxRotations limit to prevent
	// infinite rotation loops from exhausting key storage.
	if krm.policy.MaxRotations > 0 && len(krm.rotationHistory) >= krm.policy.MaxRotations {
		return nil, fmt.Errorf("max rotations limit (%d) reached", krm.policy.MaxRotations)
	}

	// R3-N2 FIX (2026-07-06): Enforce MinRotationInterval as a defensive
	// floor to prevent excessively rapid rotations.
	if krm.policy.MinRotationInterval > 0 && !krm.lastRotation.IsZero() {
		elapsed := time.Since(krm.lastRotation)
		if elapsed < krm.policy.MinRotationInterval {
			return nil, fmt.Errorf("rotation too soon: %v since last rotation, minimum %v required",
				elapsed, krm.policy.MinRotationInterval)
		}
	}

	krm.rotating = true
	defer func() { krm.rotating = false }()

	oldKey := krm.keys[krm.activeKeyID]
	if oldKey == nil {
		return nil, ErrNoActiveKey
	}

	newKey, err := krm.generateKeyLocked(oldKey.Algorithm)
	if err != nil {
		return nil, err
	}

	newKey.State = KeyStateActive
	newKey.ActivatedAt = time.Now().Unix()

	oldKey.State = KeyStateRetired

	record := RotationRecord{
		OldKeyID:    oldKey.ID,
		NewKeyID:    newKey.ID,
		RotatedAt:   time.Now().Unix(),
		BlockHeight: blockHeight,
		Reason:      reason,
	}

	krm.activeKeyID = newKey.ID
	krm.lastRotation = time.Now()
	krm.rotationHistory = append(krm.rotationHistory, record)

	if len(krm.rotationHistory) > 100 {
		// CRITICAL: Zeroize truncated entries before dropping them
		excess := len(krm.rotationHistory) - 100
		for i := 0; i < excess; i++ {
			krm.rotationHistory[i] = RotationRecord{}
		}
		krm.rotationHistory = krm.rotationHistory[len(krm.rotationHistory)-100:]
	}

	// P3-5 fix: Rotate the encryption key (encKey) together with the quantum key.
	// This re-encrypts all stored private keys with a fresh encKey, preventing
	// indefinite exposure if encKey is ever compromised.
	if err := krm.rotateEncryptionKeyLocked(); err != nil {
		return &record, fmt.Errorf("quantum key rotated but encryption key rotation failed: %w", err)
	}

	return &record, nil
}

// rotateEncryptionKeyLocked rotates the encryption key (encKey) that protects
// all stored private keys. It MUST be called with krm.mu write lock held.
//
// P3-5 fix: Previously encKey was generated once in NewKeyRotationManager and
// never rotated, meaning a compromised encKey would permanently expose all
// private keys. Now encKey rotates together with quantum keys in RotateKey.
//
// The rotation is atomic: if any step fails, the original key material and
// encKey remain unchanged. The algorithm:
//  1. Generate a new 32-byte encKey
//  2. For each stored key, decrypt with the old encKey and re-encrypt with
//     the new encKey, collecting the new ciphertexts in a temporary map
//  3. Only after all keys are successfully re-encrypted, commit: replace
//     each key's ciphertext with the new one, swap encKey, and zeroize the old
func (krm *KeyRotationManager) rotateEncryptionKeyLocked() error {
	// 1. Generate new encKey
	newEncKey := make([]byte, 32)
	if _, err := rand.Read(newEncKey); err != nil {
		return fmt.Errorf("key_rotation: failed to generate new encryption key: %w", err)
	}

	// 2. Decrypt all stored private keys with old encKey, re-encrypt with new
	//    encKey. Collect new ciphertexts in a temporary map so that a failure
	//    leaves the original key material untouched.
	type newCiphertext struct {
		encPrivKey []byte
		nonce      []byte
	}
	reEncrypted := make(map[string]newCiphertext, len(krm.keys))

	for keyID, key := range krm.keys {
		if key.EncryptedPrivKey == nil {
			continue
		}

		// Decrypt with current (old) encKey
		plaintext, err := krm.decryptPrivKey(key)
		if err != nil {
			_ = qaucrypto.ZeroBytesSecure(newEncKey)
			return fmt.Errorf("key_rotation: failed to decrypt key %s for encKey rotation: %w", keyID, err)
		}

		// Re-encrypt with new encKey (temporarily swap encKey)
		// FIX: Use a key-parameterized encryption function instead of
		// temporarily swapping krm.encKey. The old code did:
		//   oldEncKey := krm.encKey
		//   krm.encKey = newEncKey
		//   encPrivKey, nonce, err := krm.encryptPrivKey(plaintext)
		//   krm.encKey = oldEncKey
		// This temporary swap was fragile: if encryptPrivKey panicked,
		// krm.encKey would remain pointing to newEncKey (inconsistent
		// state). By passing newEncKey explicitly to encryptPrivKeyWith,
		// krm.encKey is never mutated during re-encryption, eliminating
		// the swap window entirely.
		encPrivKey, nonce, err := encryptPrivKeyWith(newEncKey, plaintext)

		// Zeroize plaintext immediately
		_ = qaucrypto.ZeroBytesSecure(plaintext)

		if err != nil {
			_ = qaucrypto.ZeroBytesSecure(newEncKey)
			return fmt.Errorf("key_rotation: failed to re-encrypt key %s for encKey rotation: %w", keyID, err)
		}

		reEncrypted[keyID] = newCiphertext{encPrivKey: encPrivKey, nonce: nonce}
	}

	// 3. Commit: apply all new ciphertexts, swap encKey, zeroize old encKey
	oldEncKey := krm.encKey
	for keyID, nc := range reEncrypted {
		key := krm.keys[keyID]
		// Zeroize the old ciphertext before replacing
		if key.EncryptedPrivKey != nil {
			_ = qaucrypto.ZeroBytesSecure(key.EncryptedPrivKey)
		}
		key.EncryptedPrivKey = nc.encPrivKey
		key.PrivKeyNonce = nc.nonce
	}
	krm.encKey = newEncKey
	if oldEncKey != nil {
		_ = qaucrypto.ZeroBytesSecure(oldEncKey)
	}

	return nil
}

func (krm *KeyRotationManager) generateKeyLocked(algorithm string) (*QuantumKey, error) {
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	keyID := "qk-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + hex.EncodeToString(randBytes)

	kp, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate quantum key pair: %w", err)
	}
	pubKey := kp.Public.Bytes()
	privKey := kp.Private.Bytes()
	kp.Private.Zeroize()

	encPrivKey, nonce, encErr := krm.encryptPrivKey(privKey)
	for i := range privKey {
		privKey[i] = 0
	}
	if encErr != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", encErr)
	}

	now := time.Now()
	key := &QuantumKey{
		ID:               keyID,
		PublicKey:        pubKey,
		EncryptedPrivKey: encPrivKey,
		PrivKeyNonce:     nonce,
		State:            KeyStatePending,
		CreatedAt:        now.Unix(),
		ExpiresAt:        now.Add(krm.policy.MaxKeyAge).Unix(),
		Algorithm:        algorithm,
		Version:          1,
	}

	krm.keys[keyID] = key
	return key, nil
}

func (krm *KeyRotationManager) GetActiveKey() (*QuantumKey, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if krm.activeKeyID == "" {
		return nil, ErrNoActiveKey
	}

	key, exists := krm.keys[krm.activeKeyID]
	if !exists {
		return nil, ErrNoActiveKey
	}

	if time.Now().Unix() > key.ExpiresAt {
		return nil, ErrKeyExpired
	}

	// R6-P3-5: Return a safe copy excluding sensitive fields (EncryptedPrivKey,
	// PrivKeyNonce), matching GetKey's safe-copy structure. Previously the
	// internal *QuantumKey pointer was returned directly, allowing callers to
	// access or mutate encrypted private key material.
	safeCopy := &QuantumKey{
		ID:        key.ID,
		PublicKey: key.PublicKey,
		State:     key.State,
		CreatedAt: key.CreatedAt,
		ExpiresAt: key.ExpiresAt,
		Algorithm: key.Algorithm,
		Version:   key.Version,
	}
	return safeCopy, nil
}

func (krm *KeyRotationManager) GetKey(keyID string) (*QuantumKey, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	key, exists := krm.keys[keyID]
	if !exists {
		return nil, ErrInvalidKeyID
	}
	safeCopy := &QuantumKey{
		ID:        key.ID,
		PublicKey: key.PublicKey,
		State:     key.State,
		CreatedAt: key.CreatedAt,
		ExpiresAt: key.ExpiresAt,
		Algorithm: key.Algorithm,
		Version:   key.Version,
	}
	return safeCopy, nil
}

func (krm *KeyRotationManager) SignWithKey(keyID string, message []byte) ([]byte, error) {
	krm.mu.RLock()
	key, exists := krm.keys[keyID]
	if !exists {
		krm.mu.RUnlock()
		return nil, ErrInvalidKeyID
	}
	if key.State != KeyStateActive {
		krm.mu.RUnlock()
		return nil, fmt.Errorf("key is not active")
	}
	privKeyBytes, err := krm.decryptPrivKey(key)
	krm.mu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key for signing: %w", err)
	}
	// CRITICAL: Zeroize immediately after constructing key, not at function exit
	privKey, err := qaucrypto.PrivateKeyFromBytes(privKeyBytes)
	for i := range privKeyBytes {
		privKeyBytes[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct private key: %w", err)
	}
	// SECURITY FIX (audit P3-4): Add runtime.KeepAlive to prevent GC from
	// collecting privKey before the cgo Sign operation completes. Without this,
	// the Go runtime could free the PrivateKey object while Dilithium3 C code
	// still holds a pointer to its internal buffer.
	sig, err := privKey.Sign(message)
	runtime.KeepAlive(privKey)
	// SECURITY FIX (R2 P2): Zeroize the private key object after signing to
	// prevent sensitive key material from lingering in memory longer than needed.
	privKey.Zeroize()
	return sig, err
}

func (krm *KeyRotationManager) RevokeKey(keyID string) error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	key, exists := krm.keys[keyID]
	if !exists {
		return ErrInvalidKeyID
	}

	key.State = KeyStateRevoked

	if krm.activeKeyID == keyID {
		krm.activeKeyID = ""
	}

	return nil
}

func (krm *KeyRotationManager) CheckExpiry() []string {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	now := time.Now().Unix()
	var expired []string

	for id, key := range krm.keys {
		if key.State == KeyStateActive && now > key.ExpiresAt {
			expired = append(expired, id)
		}
	}

	return expired
}

func (krm *KeyRotationManager) GetRotationHistory() []RotationRecord {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	history := make([]RotationRecord, len(krm.rotationHistory))
	copy(history, krm.rotationHistory)
	return history
}

func (krm *KeyRotationManager) TimeUntilNextRotation() time.Duration {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	elapsed := time.Since(krm.lastRotation)
	if elapsed >= krm.policy.RotationInterval {
		return 0
	}
	return krm.policy.RotationInterval - elapsed
}

func (krm *KeyRotationManager) DeriveKeyID(pubKey []byte) string {
	h := sha256.Sum256(pubKey)
	return "qk-" + hex.EncodeToString(h[:8])
}

// MultiSigApproval implements multi-signature approval logic
// audit fix (CRITICAL-2): an authorizedSigners field is added; only authorized signers may approve
type MultiSigApproval struct {
	mu                sync.Mutex
	approvals         map[string]map[types.Address]bool
	threshold         int
	authorizedSigners map[types.Address]bool // authorized-signer allowlist; empty means unrestricted (backward-compatible)
}

// NewMultiSigApproval creates a multi-signature approval instance
// audit fix (CRITICAL-2): the authorizedSigners parameter restricts approval to authorized signers
// An empty authorizedSigners means unrestricted (backward-compatible), but production should always provide the list
func NewMultiSigApproval(threshold int, authorizedSigners ...types.Address) *MultiSigApproval {
	msa := &MultiSigApproval{
		approvals:         make(map[string]map[types.Address]bool),
		threshold:         threshold,
		authorizedSigners: make(map[types.Address]bool),
	}
	for _, signer := range authorizedSigners {
		msa.authorizedSigners[signer] = true
	}
	return msa
}

// Approve records a signer's approval of the given operation
// audit fix (CRITICAL-2): verify the signer is in the authorized list
// If authorizedSigners is set and the signer is absent, return ErrUnauthorizedSigner
func (msa *MultiSigApproval) Approve(operationID string, signer types.Address) bool {
	msa.mu.Lock()
	defer msa.mu.Unlock()

	// security fix: if the allowlist is set, verify the signer is in it
	if len(msa.authorizedSigners) > 0 {
		if !msa.authorizedSigners[signer] {
			return false
		}
	}

	if msa.approvals[operationID] == nil {
		msa.approvals[operationID] = make(map[types.Address]bool)
	}

	msa.approvals[operationID][signer] = true
	return len(msa.approvals[operationID]) >= msa.threshold
}

func (msa *MultiSigApproval) GetApprovalCount(operationID string) int {
	msa.mu.Lock()
	defer msa.mu.Unlock()

	if msa.approvals[operationID] == nil {
		return 0
	}
	return len(msa.approvals[operationID])
}

// Close securely destroys the KeyRotationManager by zeroizing all sensitive data.
// This MUST be called when the manager is no longer needed to prevent key material
// from remaining in memory. After Close(), the manager is unusable.
func (krm *KeyRotationManager) Close() error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	// CRITICAL: Zeroize the encryption key - it protects all stored private keys
	// R3-P3-3: Use ZeroBytesSecure instead of a simple for loop to prevent
	// compiler dead-store optimization from eliminating the zeroing.
	if krm.encKey != nil {
		_ = qaucrypto.ZeroBytesSecure(krm.encKey)
		krm.encKey = nil
	}

	// Zeroize any cached key material in memory
	for _, key := range krm.keys {
		if key.EncryptedPrivKey != nil {
			// R6-P3-3: Use ZeroBytesSecure for consistency with encKey zeroing.
			_ = qaucrypto.ZeroBytesSecure(key.EncryptedPrivKey)
		}
		key.EncryptedPrivKey = nil
		key.PrivKeyNonce = nil
	}

	// Clear rotation history which may contain sensitive key references
	for i := range krm.rotationHistory {
		krm.rotationHistory[i] = RotationRecord{}
	}
	krm.rotationHistory = nil

	return nil
}

// Zeroize frees the KeyRotationManager resources, alias for Close().
func (krm *KeyRotationManager) Zeroize() error {
	return krm.Close()
}
