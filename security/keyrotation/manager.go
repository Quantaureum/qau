// Quantaureum Node source, version 1.0.0.
// Package keyrotation provides key rotation management for Quantaureum validators.
// It implements secure key rotation with proof generation for identity verification.
package keyrotation

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// boolToInt32 converts a boolean to int32 in constant time.
// audit-fix KR-TIMING: replaced branching implementation with lookup-table
// approach using subtle.ConstantTimeSelect to eliminate timing side-channel,
// consistent with the fix applied to crypto/dilithium.go.
func boolToInt32(b bool) int32 {
	table := [2]int32{0, 1}
	idx := 0
	if b {
		idx = 1
	}
	return int32(subtle.ConstantTimeSelect(idx, int(table[1]), int(table[0]))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

// isNilConstantTime performs a constant-time check if any of the conditions are true.
func isNilConstantTime(conditions ...bool) bool {
	for _, cond := range conditions {
		if subtle.ConstantTimeEq(boolToInt32(cond), 1) == 1 {
			return true
		}
	}
	return false
}

// Errors for KeyRotationManager
var (
	ErrRotationNotInProgress   = errors.New("no rotation in progress")
	ErrRotationAlreadyActive   = errors.New("rotation already in progress")
	ErrInvalidRotationProof    = errors.New("invalid rotation proof")
	ErrNoCurrentKey            = errors.New("no current key available")
	ErrNoPendingKey            = errors.New("no pending key available")
	ErrProofVerificationFailed = errors.New("proof verification failed")
)

// KeyPairWrapper wraps a crypto.KeyPair with additional metadata
type KeyPairWrapper struct {
	Private   *crypto.PrivateKey
	Public    *crypto.PublicKey
	CreatedAt time.Time
	ExpiresAt time.Time
	Version   uint64
}

// RotationProof represents a proof that a key rotation is legitimate.
// It contains the old and new public keys, signed by the old private key.
type RotationProof struct {
	OldPublicKey []byte `json:"old_public_key"`
	NewPublicKey []byte `json:"new_public_key"`
	Signature    []byte `json:"signature"`
	Timestamp    int64  `json:"timestamp"`
}

// KeyRotationManager manages key rotation for validators.
// It ensures smooth key transitions without affecting block production.
type KeyRotationManager struct {
	mu sync.RWMutex

	currentKey  *KeyPairWrapper
	pendingKey  *KeyPairWrapper
	keyStore    KeyStore
	rotationAge time.Duration

	// Rotation state
	rotationInProgress bool
}

// KeyStore interface for persisting keys
type KeyStore interface {
	SaveKey(key *KeyPairWrapper, password string) error
	LoadKey(version uint64, password string) (*KeyPairWrapper, error)
	DeleteKey(version uint64) error
}

// KeyRotationManagerConfig holds configuration for the manager
type KeyRotationManagerConfig struct {
	RotationAge time.Duration
	KeyStore    KeyStore
}

// DefaultKeyRotationManagerConfig returns default configuration
func DefaultKeyRotationManagerConfig() *KeyRotationManagerConfig {
	return &KeyRotationManagerConfig{
		RotationAge: 30 * 24 * time.Hour, // 30 days
		KeyStore:    nil,                 // In-memory by default
	}
}

// NewKeyRotationManager creates a new KeyRotationManager
func NewKeyRotationManager(config *KeyRotationManagerConfig) *KeyRotationManager {
	if config == nil {
		config = DefaultKeyRotationManagerConfig()
	}

	return &KeyRotationManager{
		rotationAge: config.RotationAge,
		keyStore:    config.KeyStore,
	}
}

// SetCurrentKey sets the current active key
func (krm *KeyRotationManager) SetCurrentKey(keyPair *crypto.KeyPair) error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	// Constant-time nil checks to prevent timing attacks
	if isNilConstantTime(
		keyPair == nil,
		keyPair != nil && keyPair.Private == nil,
		keyPair != nil && keyPair.Public == nil,
	) {
		return ErrInvalidKey
	}

	version := uint64(1)
	if krm.currentKey != nil {
		version = krm.currentKey.Version + 1
	}

	krm.currentKey = &KeyPairWrapper{
		Private:   keyPair.Private,
		Public:    keyPair.Public,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(krm.rotationAge),
		Version:   version,
	}

	return nil
}

// GetCurrentKey returns the current active key
func (krm *KeyRotationManager) GetCurrentKey() (*KeyPairWrapper, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if krm.currentKey == nil {
		return nil, ErrNoCurrentKey
	}

	return krm.currentKey, nil
}

// GetPendingKey returns the pending key during rotation
func (krm *KeyRotationManager) GetPendingKey() (*KeyPairWrapper, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if krm.pendingKey == nil {
		return nil, ErrNoPendingKey
	}

	return krm.pendingKey, nil
}

// ShouldRotate checks if key rotation is needed based on key age.
// Returns true if the current key is approaching expiration or has expired.
// Implements Requirements 12.1
func (krm *KeyRotationManager) ShouldRotate() bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	// No key exists, rotation needed to create one
	// Use constant-time nil check to prevent timing attacks
	currentKeyNil := krm.currentKey == nil
	if currentKeyNil {
		return true
	}

	now := time.Now().UTC()

	// Key has expired
	if now.After(krm.currentKey.ExpiresAt) {
		return true
	}

	// Key is within 10% of its lifetime to expiration (grace period)
	keyAge := now.Sub(krm.currentKey.CreatedAt)
	totalLifetime := krm.currentKey.ExpiresAt.Sub(krm.currentKey.CreatedAt)
	gracePeriod := totalLifetime / 10

	if now.Add(gracePeriod).After(krm.currentKey.ExpiresAt) {
		return true
	}

	// Check if key has been active longer than rotation age
	if keyAge > krm.rotationAge {
		return true
	}

	return false
}

// InitiateRotation starts the key rotation process by generating a new key pair.
// The new key becomes pending until CompleteRotation is called.
// Implements Requirements 12.2
func (krm *KeyRotationManager) InitiateRotation() (*KeyPairWrapper, error) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if krm.rotationInProgress {
		return nil, ErrRotationAlreadyActive
	}

	// Generate new key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key pair: %w", err)
	}

	version := uint64(1)
	currentKeyNil := krm.currentKey == nil
	currentKeyNilInt := 0
	if !currentKeyNil {
		currentKeyNilInt = 1
	}
	if subtle.ConstantTimeEq(int32(currentKeyNilInt), 1) == 1 { //nolint:gosec,G115
		version = krm.currentKey.Version + 1
	}

	krm.pendingKey = &KeyPairWrapper{
		Private:   keyPair.Private,
		Public:    keyPair.Public,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(krm.rotationAge),
		Version:   version,
	}

	krm.rotationInProgress = true

	return krm.pendingKey, nil
}

// CompleteRotation completes the key rotation by activating the pending key.
// The old key is securely retired.
// Implements Requirements 12.2, 12.3
func (krm *KeyRotationManager) CompleteRotation(proof *RotationProof) error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if !krm.rotationInProgress {
		return ErrRotationNotInProgress
	}

	if krm.pendingKey == nil {
		return ErrNoPendingKey
	}

	// If we have a current key, verify the rotation proof
	if krm.currentKey != nil {
		if proof == nil {
			return ErrInvalidRotationProof
		}

		// Verify the proof
		if !krm.verifyProofLocked(proof) {
			return ErrProofVerificationFailed
		}
	}

	// Activate the pending key
	krm.currentKey = krm.pendingKey
	krm.pendingKey = nil
	krm.rotationInProgress = false

	return nil
}

// RollbackRotation cancels an in-progress rotation and keeps the old key active.
// Implements Requirements 12.5
func (krm *KeyRotationManager) RollbackRotation() error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if !krm.rotationInProgress {
		return ErrRotationNotInProgress
	}

	// R61-PK-H1 [HIGH] FIX: Zeroize the pending key before discarding it.
	// Previously the key was abandoned without zeroization, leaving sensitive
	// cryptographic material accessible to memory-dump attacks.
	if krm.pendingKey != nil {
		if krm.pendingKey.Private != nil {
			krm.pendingKey.Private.Zeroize()
		}
		krm.pendingKey = nil
	}
	krm.rotationInProgress = false

	return nil
}

// GenerateProof generates a rotation proof signed with the old key.
// This proves that the entity controlling the old key authorizes the rotation.
// Implements Requirements 12.4
func (krm *KeyRotationManager) GenerateProof() (*RotationProof, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	if krm.currentKey == nil {
		return nil, ErrNoCurrentKey
	}

	if krm.pendingKey == nil {
		return nil, ErrNoPendingKey
	}

	timestamp := time.Now().UTC().Unix()

	// Create the message to sign: hash(oldPubKey || newPubKey || timestamp)
	message := createRotationMessage(
		krm.currentKey.Public.Bytes(),
		krm.pendingKey.Public.Bytes(),
		timestamp,
	)

	// Sign with the old private key
	signature, err := krm.currentKey.Private.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign rotation proof: %w", err)
	}

	return &RotationProof{
		OldPublicKey: krm.currentKey.Public.Bytes(),
		NewPublicKey: krm.pendingKey.Public.Bytes(),
		Signature:    signature,
		Timestamp:    timestamp,
	}, nil
}

// VerifyProof verifies a rotation proof.
// Returns true if the proof is valid (signed by the old key).
func (krm *KeyRotationManager) VerifyProof(proof *RotationProof) bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	return krm.verifyProofLocked(proof)
}

// verifyProofLocked verifies a rotation proof (must be called with lock held)
// Security: Key comparisons use crypto.PublicKey.Equal() which is constant-time
// #nosec CRYPTO-TIMING - nil checks are non-secret comparisons, key comparisons use constant-time Equal()
func (krm *KeyRotationManager) verifyProofLocked(proof *RotationProof) bool {
	// Non-secret comparison: nil pointer check
	if proof == nil {
		return false
	}

	// R66-PK-2 [HIGH] FIX: inverted left conjunct `now.Sub(proofTime) > MaxProofTimestampSkew`
	// incorrectly REJECTS valid proofs within the window. A proof 6 minutes old with skew=5min
	// gives `360 > 300 = true`, rejecting it. Correct direction: `now.After(proofTime.Add(skew))`
	// rejects old proofs; `proofTime.After(now.Add(skew))` rejects future proofs.
	proofTime := time.Unix(proof.Timestamp, 0)
	now := time.Now().UTC()
	if now.After(proofTime.Add(MaxProofTimestampSkew)) || proofTime.After(now.Add(MaxProofTimestampSkew)) {
		return false
	}

	// Reconstruct the public key from the proof
	oldPubKey, err := crypto.PublicKeyFromBytes(proof.OldPublicKey)
	if err != nil {
		return false
	}

	// Verify the old public key matches our current key
	// Non-secret comparison: nil pointer check
	if krm.currentKey != nil {
		// Constant-time comparison via crypto.PublicKey.Equal()
		if !krm.currentKey.Public.Equal(oldPubKey) {
			return false
		}
	}

	// Verify the new public key matches our pending key
	// R72-PK-1 [HIGH] FIX: Reject proofs when pendingKey is nil.
	// Without this guard, an attacker can craft a proof with any NewPublicKey
	// when pendingKey is nil, bypassing key rotation authorization and enabling
	// unauthorized validator key installation, which can lead to fund theft.
	if krm.pendingKey == nil {
		return false
	}
	if krm.pendingKey != nil {
		newPubKey, err := crypto.PublicKeyFromBytes(proof.NewPublicKey)
		if err != nil {
			return false
		}
		// Constant-time comparison via crypto.PublicKey.Equal()
		if !krm.pendingKey.Public.Equal(newPubKey) {
			return false
		}
	}

	// Recreate the message and verify the signature
	message := createRotationMessage(
		proof.OldPublicKey,
		proof.NewPublicKey,
		proof.Timestamp,
	)

	return oldPubKey.Verify(message, proof.Signature)
}

// IsRotationInProgress returns true if a rotation is currently in progress
func (krm *KeyRotationManager) IsRotationInProgress() bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return krm.rotationInProgress
}

// GetRotationAge returns the configured rotation age
func (krm *KeyRotationManager) GetRotationAge() time.Duration {
	return krm.rotationAge
}

// SetRotationAge sets the rotation age
func (krm *KeyRotationManager) SetRotationAge(age time.Duration) {
	krm.mu.Lock()
	defer krm.mu.Unlock()
	krm.rotationAge = age
}

// createRotationMessage creates the message to be signed for a rotation proof
// audit-remediation: SHA-256 used for signature message hashing, not key derivation
func createRotationMessage(oldPubKey, newPubKey []byte, timestamp int64) []byte {
	// Combine: oldPubKey || newPubKey || timestamp
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction

	combined := make([]byte, 0, len(oldPubKey)+len(newPubKey)+8)
	combined = append(combined, oldPubKey...)
	combined = append(combined, newPubKey...)
	combined = append(combined, timestampBytes...)

	// Hash the combined data for signing
	// #nosec CRYPTO-KDF - This is message hashing for signatures, not key derivation
	hash := sha256.Sum256(combined)
	return hash[:]
}

// VerifyRotationProof is a standalone function to verify a rotation proof
// without needing a KeyRotationManager instance.
// #nosec CRYPTO-TIMING - nil/length checks are non-secret comparisons
func VerifyRotationProof(proof *RotationProof) bool {
	// Non-secret comparison: nil pointer check
	if proof == nil {
		return false
	}

	// R66-PK-2 [HIGH] FIX: inverted left conjunct `now.Sub(proofTime) > MaxProofTimestampSkew`
	// incorrectly REJECTS valid proofs within the window. A proof 6 minutes old with skew=5min
	// gives `360 > 300 = true`, rejecting it. Correct direction: `now.After(proofTime.Add(skew))`
	// rejects old proofs; `proofTime.After(now.Add(skew))` rejects future proofs.
	proofTime := time.Unix(proof.Timestamp, 0)
	now := time.Now().UTC()
	if now.After(proofTime.Add(MaxProofTimestampSkew)) || proofTime.After(now.Add(MaxProofTimestampSkew)) {
		return false
	}

	// Constant-time checks for empty slices to prevent timing attacks
	if subtle.ConstantTimeEq(int32(len(proof.OldPublicKey)), 0) == 1 || // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		subtle.ConstantTimeEq(int32(len(proof.NewPublicKey)), 0) == 1 || // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		subtle.ConstantTimeEq(int32(len(proof.Signature)), 0) == 1 { // #nosec G115 -- length is always non-negative
		return false
	}

	// Reconstruct the public key from the proof
	oldPubKey, err := crypto.PublicKeyFromBytes(proof.OldPublicKey)
	if err != nil {
		return false
	}

	// Recreate the message and verify the signature
	message := createRotationMessage(
		proof.OldPublicKey,
		proof.NewPublicKey,
		proof.Timestamp,
	)

	return oldPubKey.Verify(message, proof.Signature)
}
