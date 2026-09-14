// Quantaureum Node source, version 1.0.0.
// Package miner provides block sealing and signing using Dilithium3 post-quantum cryptography.
package miner

import (
	"errors"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

var (
	ErrNoValidator   = errors.New("no validator set")
	ErrSigningFailed = errors.New("block signing failed")
	ErrInvalidBlock  = errors.New("invalid block")
	ErrVerifyFailed  = errors.New("signature verification failed")
)

type Signer interface {
	Sign(hash []byte) ([]byte, error)
	PublicKey() *crypto.PublicKey
	Address() types.Address
}

type ValidatorAccount struct {
	privateKey *crypto.PrivateKey
	publicKey  *crypto.PublicKey
	address    types.Address
}

func NewValidatorAccount(privateKey *crypto.PrivateKey) (*ValidatorAccount, error) {
	if privateKey == nil {
		return nil, ErrNoValidator
	}

	pubKey := privateKey.PublicKey()
	address := pubKey.Address()

	return &ValidatorAccount{
		privateKey: privateKey,
		publicKey:  pubKey,
		address:    address,
	}, nil
}

// NewValidatorAccountFromKeyPair creates a ValidatorAccount from a crypto.KeyPair.
func NewValidatorAccountFromKeyPair(kp *crypto.KeyPair) (*ValidatorAccount, error) {
	if kp == nil || kp.Private == nil {
		return nil, ErrNoValidator
	}
	return NewValidatorAccount(kp.Private)
}

func (v *ValidatorAccount) Sign(hash []byte) ([]byte, error) {
	return crypto.Sign(v.privateKey, hash)
}

func (v *ValidatorAccount) PublicKey() *crypto.PublicKey {
	return v.publicKey
}

func (v *ValidatorAccount) Address() types.Address {
	return v.address
}

type Sealer struct {
	mu        sync.RWMutex
	validator Signer
}

func NewSealer() *Sealer {
	return &Sealer{}
}

// SetValidator sets the validator for block signing.
// audit-fix L-17: mutex protection for concurrent access safety.
// L18-035 FIX: Reject nil validator to prevent nil pointer issues later.
func (s *Sealer) SetValidator(validator Signer) {
	if validator == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validator = validator
}

// GetValidator returns the current validator.
// audit-fix L-18/I-2: accessor method for encapsulated field access.
func (s *Sealer) GetValidator() Signer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.validator
}

// SealBlock seals a block with the validator's signature.
// audit-fix L-17: mutex protection for concurrent access safety.
func (s *Sealer) SealBlock(block *encoding.Block) (*encoding.Block, error) {
	s.mu.RLock()
	validator := s.validator
	s.mu.RUnlock()

	if validator == nil {
		return nil, ErrNoValidator
	}

	if block == nil || block.Header == nil {
		return nil, ErrInvalidBlock
	}

	signingHash, err := computeSigningHash(block.Header)
	if err != nil {
		return nil, err
	}

	signature, err := validator.Sign(signingHash[:])
	if err != nil {
		return nil, ErrSigningFailed
	}

	block.Header.Signature = signature
	block.Header.ProposerAddr = validator.Address()

	return block, nil
}

// computeSigningHash computes the signing hash for a block header.
// MINER-SEAL-01 FIX (deep-audit 2026-07-12): sign over the FULL header (all
// fields) minus the post-signing fields, exactly as the canonical signer
// core/block_validator.go computeSigningData does. The previous hand-listed
// field copy omitted GasLimit, GasUsed, BaseFee, BlobGasUsed and ExcessBlobGas,
// leaving them at zero in the signed data — so those fee/gas fields were
// unsigned and malleable for any path using miner.VerifyBlockSignature, and the
// hash did not match the node/core signature over the same block.
// C21-007 FIX (R50, 2026-08-05): Strip stardust fields (FinalityType,
// QTDSignature, ExecutiveSealers, ReviewAttestationRoot) — same as
// core/block_validator.go and node/block_producer.go computeSigningData.
func computeSigningHash(header *encoding.BlockHeader) (types.Hash, error) {
	headerCopy := *header
	headerCopy.Signature = nil
	headerCopy.SyncCommitteeSig = nil
	headerCopy.SyncCommitteeBits = nil
	headerCopy.QTDSignature = nil
	headerCopy.ExecutiveSealers = nil
	headerCopy.ReviewAttestationRoot = types.Hash{}
	headerCopy.FinalityType = 0

	data, err := encoding.MarshalBlockHeader(&headerCopy)
	if err != nil {
		return types.Hash{}, err
	}

	return sha3.Sum256(data), nil
}

func VerifyBlockSignature(block *encoding.Block, pubKey *crypto.PublicKey) (bool, error) {
	if block == nil || block.Header == nil {
		return false, ErrInvalidBlock
	}

	if pubKey == nil {
		return false, ErrVerifyFailed
	}

	signingHash, err := computeSigningHash(block.Header)
	if err != nil {
		return false, err
	}

	return crypto.Verify(pubKey, signingHash[:], block.Header.Signature), nil
}

func RecoverSignerAddress(block *encoding.Block, pubKeyBytes []byte) (types.Address, error) {
	if block == nil || block.Header == nil {
		return types.Address{}, ErrInvalidBlock
	}

	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return types.Address{}, err
	}

	signingHash, err := computeSigningHash(block.Header)
	if err != nil {
		return types.Address{}, err
	}

	if !crypto.Verify(pubKey, signingHash[:], block.Header.Signature) {
		return types.Address{}, ErrVerifyFailed
	}

	return pubKey.Address(), nil
}
