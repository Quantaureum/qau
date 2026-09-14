// Quantaureum Go SDK source, version 1.0.0.
// Package accounts provides account management functionality for the Quantaureum Go SDK.
// Uses Dilithium3 post-quantum cryptographic signatures.
package accounts

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
	"github.com/quantaureum/qau/sdks/go-sdk/utils"
	"golang.org/x/crypto/sha3"
)

const (
	PublicKeySize  = mode3.PublicKeySize  // 1952 bytes
	PrivateKeySize = mode3.PrivateKeySize // 4000 bytes
	SignatureSize  = mode3.SignatureSize  // 3293 bytes
)

// Account represents a quantum-safe blockchain account with Dilithium3 keys.
type Account struct {
	privateKey *mode3.PrivateKey
	publicKey  *mode3.PublicKey
	address    common.Address
	mnemonic   []byte // Optional, set if created from mnemonic; stored as []byte for secure zeroization
}

// NewAccount creates a new account with a randomly generated Dilithium3 key pair.
func NewAccount() (*Account, error) {
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return &Account{
		privateKey: priv,
		publicKey:  pub,
		address:    publicKeyToAddress(pub),
	}, nil
}

// NewAccountFromPrivateKey creates an account from an existing Dilithium3 private key.
func NewAccountFromPrivateKey(privateKey *mode3.PrivateKey) *Account {
	if privateKey == nil {
		return nil
	}
	pub := privateKey.Public().(*mode3.PublicKey)
	return &Account{
		privateKey: privateKey,
		publicKey:  pub,
		address:    publicKeyToAddress(pub),
	}
}

// NewAccountFromPrivateKeyBytes creates an account from raw private key bytes.
func NewAccountFromPrivateKeyBytes(keyBytes []byte) (*Account, error) {
	if len(keyBytes) != PrivateKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", errors.ErrInvalidPrivateKey, PrivateKeySize, len(keyBytes))
	}

	var privKey mode3.PrivateKey
	privKey.Unpack((*[PrivateKeySize]byte)(keyBytes))

	return NewAccountFromPrivateKey(&privKey), nil
}

// NewAccountFromPrivateKeyHex creates an account from a hex-encoded private key.
func NewAccountFromPrivateKeyHex(hexKey string) (*Account, error) {
	if hexKey == "" {
		return nil, errors.ErrInvalidPrivateKey
	}

	keyBytes, err := utils.HexToBytes(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrInvalidPrivateKey, err)
	}

	return NewAccountFromPrivateKeyBytes(keyBytes)
}

// Address returns the account's address.
func (a *Account) Address() common.Address {
	if a == nil {
		return common.Address{}
	}
	return a.address
}

// PrivateKeyBytes returns the private key as a byte slice.
func (a *Account) PrivateKeyBytes() []byte {
	if a == nil || a.privateKey == nil {
		return nil
	}
	return a.privateKey.Bytes()
}

// PrivateKeyHex returns the private key as a hex string with 0x prefix.
func (a *Account) PrivateKeyHex() string {
	if a == nil || a.privateKey == nil {
		return ""
	}
	return utils.BytesToHex(a.privateKey.Bytes())
}

// PublicKeyBytes returns the public key bytes (1952 bytes for Dilithium3).
func (a *Account) PublicKeyBytes() []byte {
	if a == nil || a.publicKey == nil {
		return nil
	}
	return a.publicKey.Bytes()
}

// PublicKeyHex returns the public key as a hex string with 0x prefix.
func (a *Account) PublicKeyHex() string {
	if a == nil || a.publicKey == nil {
		return ""
	}
	return utils.BytesToHex(a.publicKey.Bytes())
}

// Mnemonic returns the mnemonic phrase bytes if the account was created from one.
// Returns nil if no mnemonic was used.
func (a *Account) Mnemonic() []byte {
	if a == nil {
		return nil
	}
	return a.mnemonic
}

// ZeroizeMnemonic securely zeros the stored mnemonic bytes.
// Should be called after key derivation is complete to prevent memory leakage.
// Returns an error if zeroization fails.
func (a *Account) ZeroizeMnemonic() error {
	if a == nil || len(a.mnemonic) == 0 {
		return nil
	}
	for i := range a.mnemonic {
		a.mnemonic[i] = 0
	}
	a.mnemonic = nil
	return nil
}

// publicKeyToAddress derives an address from a Dilithium3 public key.
// The address is the last 20 bytes of SHA3-256(publicKey), identical to the
// chain-side derivation in types.AddressFromPublicKey and the wallet's
// dilithium3.ts deriveAddress. Keccak-256 MUST NOT be used here — it yields
// different addresses and the node would reject signatures with
// "public key does not match claimed address".
func publicKeyToAddress(pubKey *mode3.PublicKey) common.Address {
	if pubKey == nil {
		return common.Address{}
	}
	hash := sha3.Sum256(pubKey.Bytes())
	return common.BytesToAddress(hash[12:])
}

// keccak256 calculates the Keccak-256 hash of the input data.
func keccak256(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hasher.Sum(nil)
}

// Sign signs a message hash with this account's Dilithium3 private key.
// Returns the signature bytes (3293 bytes for Dilithium3).
func (a *Account) Sign(hash []byte) ([]byte, error) {
	if a == nil || a.privateKey == nil {
		return nil, fmt.Errorf("account or private key is nil")
	}
	if len(hash) == 0 {
		return nil, fmt.Errorf("hash cannot be empty")
	}

	// Sign with Dilithium3
	signature := make([]byte, SignatureSize)
	mode3.SignTo(a.privateKey, hash, signature)
	return signature, nil
}

// Ensure rand is used
var _ = rand.Reader
