// Quantaureum Node source, version 1.0.0.
package stealth

import (
	"errors"

	"github.com/quantaureum/qau/types"
)

var (
	ErrInvalidMetaAddress   = errors.New("stealth: invalid meta address")
	ErrInvalidEphemeralKey  = errors.New("stealth: invalid ephemeral key")
	ErrAnnouncementNotFound = errors.New("stealth: announcement not found")
	ErrScanFailed           = errors.New("stealth: scan failed")
	ErrRecoveryFailed       = errors.New("stealth: recovery failed")
	ErrAlreadyRegistered    = errors.New("stealth: meta address already registered")
)

type StealthAddress struct {
	EphemeralPubKey []byte
	AddressHash     types.Hash
}

type StealthMetaAddress struct {
	SpendPublicKey []byte
	ViewPublicKey  []byte
	KemPublicKey   []byte
	RegisteredAt   uint64
}

type StealthAnnouncement struct {
	EphemeralPubKey []byte
	StealthAddrHash types.Hash
	KemCiphertext   []byte
	BlockNumber     uint64
	TxHash          types.Hash
	// CRITICAL FIX: Add sender authentication to prevent unauthorized spending
	SenderPubKey    []byte // Sender's public key for verification (spend public key)
	SenderSignature []byte // Signature proving sender owns the funds (Dilithium3)
}
