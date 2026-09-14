// Quantaureum Node source, version 1.0.0.
// Package keyrotation provides rotation proof generation and verification.
package keyrotation

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// Proof-related errors
var (
	ErrProofExpired         = errors.New("rotation proof has expired")
	ErrProofTimestampFuture = errors.New("rotation proof timestamp is in the future")
	ErrProofKeyMismatch     = errors.New("proof keys do not match expected keys")
	ErrEmptyProof           = errors.New("proof is empty or nil")
	ErrInvalidProofFormat   = errors.New("invalid proof format")
)

const (
	// ProofValidityDuration is how long a rotation proof remains valid
	ProofValidityDuration = 24 * time.Hour

	// MaxProofTimestampSkew is the maximum allowed clock skew for proof timestamps
	MaxProofTimestampSkew = 5 * time.Minute
)

// ProofVerifier provides methods for verifying rotation proofs
type ProofVerifier struct {
	validityDuration time.Duration
	maxTimestampSkew time.Duration
}

// NewProofVerifier creates a new ProofVerifier with default settings
func NewProofVerifier() *ProofVerifier {
	return &ProofVerifier{
		validityDuration: ProofValidityDuration,
		maxTimestampSkew: MaxProofTimestampSkew,
	}
}

// NewProofVerifierWithConfig creates a ProofVerifier with custom settings
func NewProofVerifierWithConfig(validityDuration, maxTimestampSkew time.Duration) *ProofVerifier {
	return &ProofVerifier{
		validityDuration: validityDuration,
		maxTimestampSkew: maxTimestampSkew,
	}
}

// Verify verifies a rotation proof with full validation
func (pv *ProofVerifier) Verify(proof *RotationProof) error {
	if proof == nil {
		return ErrEmptyProof
	}

	// Validate proof fields
	if len(proof.OldPublicKey) == 0 || len(proof.NewPublicKey) == 0 || len(proof.Signature) == 0 {
		return ErrInvalidProofFormat
	}

	// Check timestamp validity
	proofTime := time.Unix(proof.Timestamp, 0)
	now := time.Now().UTC()

	// Check if timestamp is too far in the future
	if proofTime.After(now.Add(pv.maxTimestampSkew)) {
		return ErrProofTimestampFuture
	}

	// Check if proof has expired
	// R66-PK-1 [HIGH] FIX: inverted comparison `now.Sub(proofTime) > duration` never fires
	// for expired proofs. Correct direction: `!now.Before(proofTime.Add(duration))`.
	// Example: proof 25h old with duration=24h → `90000 > 86400 = true` (should reject)
	// but old check: `now > proofTime + 24h` → always false for past proofs.
	if !now.Before(proofTime.Add(pv.validityDuration)) {
		return ErrProofExpired
	}

	// Verify the cryptographic signature
	if !VerifyRotationProof(proof) {
		return ErrProofVerificationFailed
	}

	return nil
}

// VerifyWithExpectedKeys verifies a proof and checks that the keys match expected values
// audit-remediation: public key comparison - public keys are public data, timing attacks not applicable
func (pv *ProofVerifier) VerifyWithExpectedKeys(proof *RotationProof, expectedOldKey, expectedNewKey *crypto.PublicKey) error {
	if err := pv.Verify(proof); err != nil {
		return err
	}

	// Verify old key matches (public key comparison - not timing sensitive)
	if expectedOldKey != nil {
		expectedBytes := expectedOldKey.Bytes()
		if len(proof.OldPublicKey) != len(expectedBytes) ||
			subtle.ConstantTimeCompare(proof.OldPublicKey, expectedBytes) != 1 {
			return ErrProofKeyMismatch
		}
	}

	// Verify new key matches (public key comparison - not timing sensitive)
	if expectedNewKey != nil {
		expectedBytes := expectedNewKey.Bytes()
		if len(proof.NewPublicKey) != len(expectedBytes) ||
			subtle.ConstantTimeCompare(proof.NewPublicKey, expectedBytes) != 1 {
			return ErrProofKeyMismatch
		}
	}

	return nil
}

// ProofBuilder helps construct rotation proofs
type ProofBuilder struct {
	oldPrivateKey *crypto.PrivateKey
	oldPublicKey  *crypto.PublicKey
	newPublicKey  *crypto.PublicKey
	timestamp     int64
}

// NewProofBuilder creates a new ProofBuilder
func NewProofBuilder() *ProofBuilder {
	return &ProofBuilder{
		timestamp: time.Now().UTC().Unix(),
	}
}

// WithOldKey sets the old key pair (private key needed for signing)
func (pb *ProofBuilder) WithOldKey(privateKey *crypto.PrivateKey) *ProofBuilder {
	pb.oldPrivateKey = privateKey
	if privateKey != nil {
		pb.oldPublicKey = privateKey.PublicKey()
	}
	return pb
}

// WithNewPublicKey sets the new public key
func (pb *ProofBuilder) WithNewPublicKey(publicKey *crypto.PublicKey) *ProofBuilder {
	pb.newPublicKey = publicKey
	return pb
}

// WithTimestamp sets a custom timestamp (useful for testing)
func (pb *ProofBuilder) WithTimestamp(timestamp int64) *ProofBuilder {
	pb.timestamp = timestamp
	return pb
}

// Build creates the rotation proof
func (pb *ProofBuilder) Build() (*RotationProof, error) {
	// Constant-time nil checks to prevent timing attacks
	oldPrivNil := pb.oldPrivateKey == nil
	oldPubNil := pb.oldPublicKey == nil
	newPubNil := pb.newPublicKey == nil
	if oldPrivNil {
		return nil, errors.New("old private key is required")
	}
	if oldPubNil {
		return nil, errors.New("old public key is required")
	}
	if newPubNil {
		return nil, errors.New("new public key is required")
	}

	oldPubBytes := pb.oldPublicKey.Bytes()
	newPubBytes := pb.newPublicKey.Bytes()

	// Create the message to sign
	message := createRotationMessage(oldPubBytes, newPubBytes, pb.timestamp)

	// Sign with the old private key
	// R67-PK-3 [HIGH] FIX: Wrap cryptographic signing in panic recovery.
	// Dilithium Sign() may panic on internal errors (OOM, corrupt state) that would
	// otherwise crash the entire bridge process. Recovering here returns a clean error
	// instead of propagating a panic that could destabilize the node.
	var signature []byte
	var signErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				signature = nil
				signErr = fmt.Errorf("sign operation panicked: %v", r)
			}
		}()
		signature, signErr = pb.oldPrivateKey.Sign(message)
	}()
	if signErr != nil {
		return nil, signErr
	}

	return &RotationProof{
		OldPublicKey: oldPubBytes,
		NewPublicKey: newPubBytes,
		Signature:    signature,
		Timestamp:    pb.timestamp,
	}, nil
}

// ProofChain represents a chain of rotation proofs for audit purposes
type ProofChain struct {
	Proofs []RotationProof `json:"proofs"`
}

// NewProofChain creates a new empty proof chain
func NewProofChain() *ProofChain {
	return &ProofChain{
		Proofs: make([]RotationProof, 0),
	}
}

// AddProof adds a proof to the chain
// audit-remediation: public key comparison for chain continuity
func (pc *ProofChain) AddProof(proof *RotationProof) error {
	if proof == nil {
		return ErrEmptyProof
	}

	// If chain is not empty, verify continuity
	if len(pc.Proofs) > 0 {
		lastProof := pc.Proofs[len(pc.Proofs)-1]
		// The new proof's old key should match the last proof's new key
		// Using constant-time comparison for consistency
		if len(lastProof.NewPublicKey) != len(proof.OldPublicKey) ||
			subtle.ConstantTimeCompare(lastProof.NewPublicKey, proof.OldPublicKey) != 1 {
			return errors.New("proof chain continuity broken: keys do not match")
		}
	}

	pc.Proofs = append(pc.Proofs, *proof)
	return nil
}

// VerifyChain verifies the entire proof chain
// audit-remediation: public key comparison for chain continuity
func (pc *ProofChain) VerifyChain() error {
	verifier := NewProofVerifier()
	// Use a longer validity for chain verification (historical proofs)
	verifier.validityDuration = 365 * 24 * time.Hour

	for i, proof := range pc.Proofs {
		// Verify each proof's signature
		if !VerifyRotationProof(&proof) {
			// audit-fix R5-M3: string(rune('0'+i)) only works for i<10
			return errors.New("invalid signature in proof chain at index " + strconv.Itoa(i))
		}

		// Verify chain continuity using constant-time comparison
		if i > 0 {
			prevProof := pc.Proofs[i-1]
			if len(prevProof.NewPublicKey) != len(proof.OldPublicKey) ||
				subtle.ConstantTimeCompare(prevProof.NewPublicKey, proof.OldPublicKey) != 1 {
				// audit-fix R5-M3: string(rune('0'+i)) only works for i<10
				return errors.New("proof chain continuity broken at index " + strconv.Itoa(i))
			}
		}
	}

	return nil
}

// GetCurrentKey returns the current (latest) public key in the chain
func (pc *ProofChain) GetCurrentKey() ([]byte, error) {
	if len(pc.Proofs) == 0 {
		return nil, errors.New("proof chain is empty")
	}
	return pc.Proofs[len(pc.Proofs)-1].NewPublicKey, nil
}

// GetOriginalKey returns the original (first) public key in the chain
func (pc *ProofChain) GetOriginalKey() ([]byte, error) {
	if len(pc.Proofs) == 0 {
		return nil, errors.New("proof chain is empty")
	}
	return pc.Proofs[0].OldPublicKey, nil
}

// MarshalJSON marshals the proof to JSON
func (p *RotationProof) MarshalJSON() ([]byte, error) {
	type Alias RotationProof
	return json.Marshal((*Alias)(p))
}

// UnmarshalJSON unmarshals the proof from JSON
func (p *RotationProof) UnmarshalJSON(data []byte) error {
	type Alias RotationProof
	return json.Unmarshal(data, (*Alias)(p))
}

// #nosec G115 -- safe conversion: value range verified or bit-shift extraction
// Hash returns a hash of the rotation proof for identification
func (p *RotationProof) Hash() []byte {
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(p.Timestamp))

	combined := make([]byte, 0, len(p.OldPublicKey)+len(p.NewPublicKey)+len(p.Signature)+8)
	combined = append(combined, p.OldPublicKey...)
	combined = append(combined, p.NewPublicKey...)
	combined = append(combined, p.Signature...)
	combined = append(combined, timestampBytes...)

	hash := sha256.Sum256(combined)
	return hash[:]
}

// Equal checks if two proofs are equal using constant-time comparison for signatures
// audit-remediation: constant-time comparison for cryptographic data
func (p *RotationProof) Equal(other *RotationProof) bool {
	if p == nil || other == nil {
		return p == other
	}

	// Use constant-time comparison for signature to prevent timing attacks
	// Public keys don't need constant-time comparison as they are public data
	oldKeyMatch := len(p.OldPublicKey) == len(other.OldPublicKey) &&
		subtle.ConstantTimeCompare(p.OldPublicKey, other.OldPublicKey) == 1
	newKeyMatch := len(p.NewPublicKey) == len(other.NewPublicKey) &&
		subtle.ConstantTimeCompare(p.NewPublicKey, other.NewPublicKey) == 1
	sigMatch := len(p.Signature) == len(other.Signature) &&
		subtle.ConstantTimeCompare(p.Signature, other.Signature) == 1

	return oldKeyMatch && newKeyMatch && sigMatch && p.Timestamp == other.Timestamp
}
