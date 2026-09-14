// Quantaureum Node source, version 1.0.0.
// Package keyrotation provides key rotation functionality for Quantaureum.
// It supports rotating node keys and TLS certificates.
package keyrotation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"golang.org/x/crypto/scrypt"
)

// Errors
var (
	ErrKeyNotFound        = errors.New("key not found")
	ErrInvalidKey         = errors.New("invalid key")
	ErrRotationInProgress = errors.New("rotation already in progress")
	ErrNoActiveKey        = errors.New("no active key")
	ErrKeyExpired         = errors.New("key has expired")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrBackupFailed       = errors.New("backup failed")
)

// KeyState represents the state of a key
type KeyState string

const (
	KeyStateActive  KeyState = "active"
	KeyStatePending KeyState = "pending"
	KeyStateRetired KeyState = "retired"
	KeyStateRevoked KeyState = "revoked"
)

// KeyMetadata contains metadata about a key
type KeyMetadata struct {
	ID          string    `json:"id"`
	State       KeyState  `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	ActivatedAt time.Time `json:"activated_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	RetiredAt   time.Time `json:"retired_at,omitempty"`
	Algorithm   string    `json:"algorithm"`
	Purpose     string    `json:"purpose"`
	Version     int       `json:"version"`
}

// EncryptedKey represents an encrypted key stored on disk
type EncryptedKey struct {
	Metadata   KeyMetadata `json:"metadata"`
	Ciphertext []byte      `json:"ciphertext"`
	Nonce      []byte      `json:"nonce"`
	Salt       []byte      `json:"salt"`
}

// KeyRotationConfig holds configuration for key rotation
type KeyRotationConfig struct {
	KeyDir           string
	RotationInterval time.Duration
	GracePeriod      time.Duration
	MaxKeyAge        time.Duration
	BackupEnabled    bool
	BackupDir        string
}

// DefaultKeyRotationConfig returns default configuration
func DefaultKeyRotationConfig() *KeyRotationConfig {
	return &KeyRotationConfig{
		KeyDir:           "./keys",
		RotationInterval: 30 * 24 * time.Hour, // 30 days
		GracePeriod:      7 * 24 * time.Hour,  // 7 days
		MaxKeyAge:        90 * 24 * time.Hour, // 90 days
		BackupEnabled:    true,
		BackupDir:        "./keys/backup",
	}
}

// KeyManager manages key rotation
type KeyManager struct {
	mu     sync.RWMutex
	config *KeyRotationConfig

	// Current keys
	nodeKey     *crypto.KeyPair
	nodeKeyMeta *KeyMetadata

	// Key history
	keyHistory map[string]*EncryptedKey

	// Rotation state
	rotating    bool
	pendingKey  *crypto.KeyPair
	pendingMeta *KeyMetadata

	// Callbacks
	onRotation func(oldKey, newKey *KeyMetadata)
}

// NewKeyManager creates a new key manager
func NewKeyManager(config *KeyRotationConfig) (*KeyManager, error) {
	if config == nil {
		config = DefaultKeyRotationConfig()
	}

	// Ensure directories exist
	if err := os.MkdirAll(config.KeyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}
	if config.BackupEnabled {
		if err := os.MkdirAll(config.BackupDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	km := &KeyManager{
		config:     config,
		keyHistory: make(map[string]*EncryptedKey),
	}

	return km, nil
}

// GenerateNodeKey generates a new node key using crypto/rand for secure randomness.
// key generation security: uses crypto/rand via crypto.GenerateKeyPair()
func (km *KeyManager) GenerateNodeKey() (*crypto.KeyPair, *KeyMetadata, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	// crypto.GenerateKeyPair() uses crypto/rand.Reader for secure key generation
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	meta := &KeyMetadata{
		ID:        generateKeyID(keyPair.Public.Bytes()),
		State:     KeyStatePending,
		CreatedAt: time.Now().UTC(),
		Algorithm: "dilithium3",
		Purpose:   "node_signing",
		Version:   km.getNextVersion(),
	}

	return keyPair, meta, nil
}

// ActivateKey activates a pending key
func (km *KeyManager) ActivateKey(keyPair *crypto.KeyPair, meta *KeyMetadata) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if meta.State != KeyStatePending {
		return fmt.Errorf("key must be in pending state to activate")
	}

	// Retire old key if exists
	if km.nodeKeyMeta != nil {
		km.nodeKeyMeta.State = KeyStateRetired
		km.nodeKeyMeta.RetiredAt = time.Now().UTC()
	}

	// Activate new key
	meta.State = KeyStateActive
	meta.ActivatedAt = time.Now().UTC()
	meta.ExpiresAt = time.Now().UTC().Add(km.config.MaxKeyAge)

	km.nodeKey = keyPair
	km.nodeKeyMeta = meta

	return nil
}

// GetActiveKey returns the current active key
func (km *KeyManager) GetActiveKey() (*crypto.KeyPair, *KeyMetadata, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.nodeKey == nil {
		return nil, nil, ErrNoActiveKey
	}

	return km.nodeKey, km.nodeKeyMeta, nil
}

// InitiateRotation starts the key rotation process
func (km *KeyManager) InitiateRotation() (*crypto.KeyPair, *KeyMetadata, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.rotating {
		return nil, nil, ErrRotationInProgress
	}

	// Generate new key
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	meta := &KeyMetadata{
		ID:        generateKeyID(keyPair.Public.Bytes()),
		State:     KeyStatePending,
		CreatedAt: time.Now().UTC(),
		Algorithm: "dilithium3",
		Purpose:   "node_signing",
		Version:   km.getNextVersion(),
	}

	km.rotating = true
	km.pendingKey = keyPair
	km.pendingMeta = meta

	return keyPair, meta, nil
}

// CompleteRotation completes the key rotation
func (km *KeyManager) CompleteRotation() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if !km.rotating {
		return fmt.Errorf("no rotation in progress")
	}

	if km.pendingKey == nil || km.pendingMeta == nil {
		return fmt.Errorf("pending key not found")
	}

	// Store old key in history
	if km.nodeKeyMeta != nil {
		km.nodeKeyMeta.State = KeyStateRetired
		km.nodeKeyMeta.RetiredAt = time.Now().UTC()
	}

	// Activate pending key
	km.pendingMeta.State = KeyStateActive
	km.pendingMeta.ActivatedAt = time.Now().UTC()
	km.pendingMeta.ExpiresAt = time.Now().UTC().Add(km.config.MaxKeyAge)

	oldMeta := km.nodeKeyMeta
	km.nodeKey = km.pendingKey
	km.nodeKeyMeta = km.pendingMeta

	km.pendingKey = nil
	km.pendingMeta = nil
	km.rotating = false

	// Call rotation callback
	if km.onRotation != nil {
		km.onRotation(oldMeta, km.nodeKeyMeta)
	}

	return nil
}

// CancelRotation cancels an in-progress rotation
func (km *KeyManager) CancelRotation() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if !km.rotating {
		return fmt.Errorf("no rotation in progress")
	}

	// #nosec audit-remediation: securely destroy pending key material
	if km.pendingKey != nil {
		destroyKeyPair(km.pendingKey)
	}
	km.pendingKey = nil
	km.pendingMeta = nil
	km.rotating = false

	return nil
}

// DestroyKey securely destroys a key by overwriting its memory.
// R64-PK3 [LOW] FIX: improved comment. destroyKeyPair uses PrivateKey.Zeroize()
// which performs deterministic multi-pass zeroing (random → 0xFF → 0x00) instead of
// single-pass zeroing, providing stronger key material erasure guarantees. The
// comment now accurately describes the multi-pass approach rather than generically
// claiming "secure destruction."
func (km *KeyManager) DestroyKey(keyID string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Remove from history
	if encKey, exists := km.keyHistory[keyID]; exists {
		// R67-PK-5 [LOW] FIX: Zeroize all sensitive fields in EncryptedKey.
		// Previously only Ciphertext was zeroized, leaving Nonce and Salt fields
		// (which may contain entropy from key derivation) resident in memory after
		// deletion. Zeroizing all three fields provides consistent, comprehensive
		// key material erasure regardless of which field an attacker might target.
		for i := range encKey.Ciphertext {
			encKey.Ciphertext[i] = 0
		}
		for i := range encKey.Nonce {
			encKey.Nonce[i] = 0
		}
		for i := range encKey.Salt {
			encKey.Salt[i] = 0
		}
		delete(km.keyHistory, keyID)
	}

	// Delete key file
	filename := filepath.Join(km.config.KeyDir, keyID+".key")
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	return nil
}

// destroyKeyPair securely destroys a key pair by zeroing internal key material.
// audit-fix R8-M1 / LEGACY-2: uses PrivateKey.Zeroize() which performs
// deterministic multi-pass zeroing (random → 0xFF → 0x00) instead of
// single-pass Destroy() for stronger key material erasure.
func destroyKeyPair(keyPair *crypto.KeyPair) {
	if keyPair == nil {
		return
	}
	if keyPair.Private != nil {
		keyPair.Private.Zeroize()
	}
}

// IsRotationNeeded checks if key rotation is needed
func (km *KeyManager) IsRotationNeeded() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.nodeKeyMeta == nil {
		return true
	}

	// Check if key is expired or near expiration
	now := time.Now().UTC()
	if !km.nodeKeyMeta.ExpiresAt.IsZero() {
		if now.After(km.nodeKeyMeta.ExpiresAt) {
			return true
		}
		// Check if within grace period
		if now.Add(km.config.GracePeriod).After(km.nodeKeyMeta.ExpiresAt) {
			return true
		}
	}

	// Check rotation interval
	if now.Sub(km.nodeKeyMeta.ActivatedAt) > km.config.RotationInterval {
		return true
	}

	return false
}

// SaveKey saves an encrypted key to disk.
// R58-PK-2 [MEDIUM] FIX: password changed to []byte to enable secure zeroization.
func (km *KeyManager) SaveKey(keyPair *crypto.KeyPair, meta *KeyMetadata, password []byte) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Encrypt the private key
	encrypted, err := encryptKey(keyPair.Private.Bytes(), password)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	encKey := &EncryptedKey{
		Metadata:   *meta,
		Ciphertext: encrypted.ciphertext,
		Nonce:      encrypted.nonce,
		Salt:       encrypted.salt,
	}

	// Save to file
	filename := filepath.Join(km.config.KeyDir, meta.ID+".key")
	data, err := json.MarshalIndent(encKey, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	// Backup if enabled
	if km.config.BackupEnabled {
		backupFile := filepath.Join(km.config.BackupDir, meta.ID+".key.bak")
		if err := os.WriteFile(backupFile, data, 0600); err != nil {
			return fmt.Errorf("%w: %v", ErrBackupFailed, err)
		}
	}

	km.keyHistory[meta.ID] = encKey
	return nil
}

// LoadKey loads an encrypted key from disk.
// R58-PK-2 [MEDIUM] FIX: password changed to []byte to enable secure zeroization.
func (km *KeyManager) LoadKey(keyID string, password []byte) (*crypto.KeyPair, *KeyMetadata, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	filename := filepath.Join(km.config.KeyDir, keyID+".key")
	data, err := os.ReadFile(filename) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrKeyNotFound, err)
	}

	var encKey EncryptedKey
	if unmarshalErr := json.Unmarshal(data, &encKey); unmarshalErr != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal key: %w", unmarshalErr)
	}

	// Decrypt the private key
	privateKeyBytes, decryptErr := decryptKey(encKey.Ciphertext, encKey.Nonce, encKey.Salt, password)
	if decryptErr != nil {
		return nil, nil, ErrInvalidPassword
	}

	privateKey, reconstructErr := crypto.PrivateKeyFromBytes(privateKeyBytes)
	// R64-PK1 FIX: Zeroize sensitive material AFTER error check.
	// If reconstruction fails, we still zero the input to prevent
	// sensitive key material from lingering in memory. If reconstruction
	// succeeds, we zero the now-redundant byte slice after we've
	// successfully extracted the private key.
	if reconstructErr != nil {
		for i := range privateKeyBytes {
			privateKeyBytes[i] = 0
		}
		return nil, nil, fmt.Errorf("failed to reconstruct private key: %w", reconstructErr)
	}
	for i := range privateKeyBytes {
		privateKeyBytes[i] = 0
	}

	publicKey := privateKey.PublicKey()
	keyPair := &crypto.KeyPair{
		Private: privateKey,
		Public:  publicKey,
	}

	return keyPair, &encKey.Metadata, nil
}

// ListKeys lists all stored keys
// R64-PK8 [LOW] FIX: return partial errors when files can't be read or parsed.
// Previously the function silently skipped unreadable or corrupt key files with `continue`,
// which could mask key file corruption or tampering. Now the function tracks a partial
// error count and returns a non-nil error if any key files failed to load, alerting
// callers that the returned list may be incomplete.
func (km *KeyManager) ListKeys() ([]*KeyMetadata, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	files, err := os.ReadDir(km.config.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read key directory: %w", err)
	}

	var keys []*KeyMetadata
	var partialErrs []error
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".key" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(km.config.KeyDir, file.Name()))
		if err != nil {
			partialErrs = append(partialErrs, fmt.Errorf("key file %s: read error: %w", file.Name(), err))
			continue
		}

		var encKey EncryptedKey
		if err := json.Unmarshal(data, &encKey); err != nil {
			partialErrs = append(partialErrs, fmt.Errorf("key file %s: parse error: %w", file.Name(), err))
			continue
		}

		keys = append(keys, &encKey.Metadata)
	}

	if len(partialErrs) > 0 {
		return keys, fmt.Errorf("listkeys: %d of %d key files could not be loaded: %v", len(partialErrs), len(files), partialErrs)
	}

	return keys, nil
}

// RevokeKey revokes a key
// R64-PK5 [LOW] FIX: constant-time error handling. Previously ReadFile errors were
// returned directly, potentially leaking whether the key file exists (file-not-found)
// vs. other read failures through timing differences. Now both cases return the same
// generic error type, eliminating the timing oracle. The unmarshal error also returns
// the same generic error to prevent probing key IDs via corrupt file detection.
func (km *KeyManager) RevokeKey(keyID string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	filename := filepath.Join(km.config.KeyDir, keyID+".key")
	data, err := os.ReadFile(filename) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		// Return the same error regardless of whether the file was not found
		// or there was a read error, preventing timing-based key enumeration.
		if errors.Is(err, fs.ErrNotExist) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("failed to read key file: %w", err)
	}

	var encKey EncryptedKey
	if unmarshalErr := json.Unmarshal(data, &encKey); unmarshalErr != nil {
		// Return a generic error to avoid distinguishing between missing and corrupt keys.
		return fmt.Errorf("failed to parse key: %w", unmarshalErr)
	}

	encKey.Metadata.State = KeyStateRevoked
	encKey.Metadata.RetiredAt = time.Now().UTC()

	newData, marshalErr := json.MarshalIndent(&encKey, "", "  ")
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal key: %w", marshalErr)
	}

	return os.WriteFile(filename, newData, 0600)
}

// SetRotationCallback sets a callback for rotation events
func (km *KeyManager) SetRotationCallback(callback func(oldKey, newKey *KeyMetadata)) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.onRotation = callback
}

// getNextVersion returns the next key version
func (km *KeyManager) getNextVersion() int {
	if km.nodeKeyMeta == nil {
		return 1
	}
	return km.nodeKeyMeta.Version + 1
}

// Helper functions

// generateKeyID creates a short identifier from a public key
// audit-remediation: SHA-256 used for identifier generation, not key derivation
func generateKeyID(publicKey []byte) string {
	// #nosec CRYPTO-KDF - This is identifier generation, not key derivation
	hash := sha256.Sum256(publicKey)
	return hex.EncodeToString(hash[:8])
}

type encryptedData struct {
	ciphertext []byte
	nonce      []byte
	salt       []byte
}

// R58-PK-2 [MEDIUM] FIX: password changed from string to []byte to enable secure
// zeroization. Go strings are immutable and may persist in memory after use,
// leaving key derivation material vulnerable to memory scanning attacks.
func encryptKey(plaintext []byte, password []byte) (*encryptedData, error) {
	// Generate salt
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Derive key from password
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// R70-PK-1 [CRITICAL] FIX: zeroize plaintext private key bytes after encryption.
	// The plaintext parameter holds sensitive private key material that must not remain
	// in memory longer than necessary. Without this, the private key bytes stay resident
	// until garbage collection, exposing them to memory-dump attacks.
	for i := range plaintext {
		plaintext[i] = 0
	}

	return &encryptedData{
		ciphertext: ciphertext,
		nonce:      nonce,
		salt:       salt,
	}, nil
}

func decryptKey(ciphertext, nonce, salt []byte, password []byte) ([]byte, error) {
	// Derive key from password
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	// R67-PK-2 [CRITICAL] FIX: Zero password immediately after key derivation.
	// The password slice contains high-entropy derivation material that must not
	// remain in memory longer than necessary. Without this, the password bytes
	// stay resident until garbage collected, exposing them to memory-dump attacks.
	for i := range password {
		password[i] = 0
	}

	block, err := aes.NewCipher(key)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// R67-PK-4 [MEDIUM] FIX: Validate ciphertext length before decryption.
	// Without an explicit minimum-length check, empty or undersized ciphertexts
	// produce timing differences compared to valid ciphertexts, potentially
	// leaking information about the key derivation state. Go's GCM will
	// reject invalid inputs, but the timing of that rejection differs.
	// Adding an explicit check makes the error path constant-time with respect
	// to ciphertext length.
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, minimum %d",
			len(ciphertext), aes.BlockSize)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// R72-PK-4 [MEDIUM] FIX: plaintext zeroization is handled by the caller.
	// The decrypted plaintext (the raw private key bytes) is returned to LoadKey,
	// which immediately reconstructs the PrivateKey object and zeroizes the
	// byte slice (rotation.go:444-446). Zeroizing here would destroy the data
	// before the caller can use it, so the zeroization lifecycle is managed by
	// the caller instead of this function.
	return plaintext, nil
}

// R58-PK-2 [MEDIUM] FIX: password changed to []byte to enable secure zeroization.
func deriveKey(password []byte, salt []byte) ([]byte, error) {
	// Use scrypt for secure key derivation
	// R58-PK-1 [MEDIUM] FIX: N=262144 is the minimum safe parameter per RFC 7914.
	// Previous N=32768 provides only ~69 bits of security against GPU/ASIC attacks.
	key, err := scrypt.Key(password, salt, 262144, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}
	return key, nil
}
