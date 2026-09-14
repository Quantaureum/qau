// Quantaureum Node source, version 1.0.0.
// Package params defines protocol parameters for Quantaureum.
//
// =============================================================================
// SHARED INTERFACE WARNING - DO NOT MODIFY WITHOUT SYNCING WITH WALLET
// =============================================================================
// This file defines SHARED PROTOCOL PARAMETERS with Quantaureum Wallet.
// Any changes to ChainID constraints, signature sizes, or address formats
// MUST be synchronized with the Wallet implementation.
//
// Shared ChainID constraints (enforced in Wallet tx-utils.ts):
//   - Valid range: 1 to 65535 (matches uint16 for protocol compatibility)
//   - ChainID = 0 is INVALID in production and rejected by both Wallet and Core
//   - ChainID = 0 is ONLY allowed for specific local test networks (see AllowedZeroChainIDNetworks)
//   - ChainID is cryptographically bound to signatures (EIP-155 style)
//
// Wallet implementation: the quantaureum-wallet repo
// Core validation: the Quantaureum repo
// =============================================================================
package params

// ChainID parameters
const (
	// MinChainID is the minimum valid chain ID (0 is reserved/invalid)
	MinChainID = 1

	// MaxChainID is the maximum valid chain ID (uint16 max for protocol compatibility)
	MaxChainID = 65535
)

// AllowedZeroChainIDNetworks defines networks where ChainID=0 is permitted
// This is for local development and test networks only
// Version: v1.0 - Synchronized with Wallet
var AllowedZeroChainIDNetworks = map[string]bool{
	"localhost":     true,
	"127.0.0.1":     true,
	"hardhat":       true,
	"ganache":       true,
	"testnet-local": true,
}

// IsZeroChainIDAllowed checks if the given network allows ChainID=0
// This should ONLY be used for local development/test networks
func IsZeroChainIDAllowed(networkName string) bool {
	return AllowedZeroChainIDNetworks[networkName]
}

// Cryptography parameters
const (
	// Dilithium3 signature sizes
	DilithiumPublicKeySize  = 1952
	DilithiumPrivateKeySize = 4000
	DilithiumSignatureSize  = 3293

	// Kyber key encapsulation sizes
	KyberPublicKeySize  = 1184
	KyberPrivateKeySize = 2400
	KyberCiphertextSize = 1088
	KyberSharedKeySize  = 32

	// Address parameters
	AddressLength = 20
	HashLength    = 32
)

// QVM (Virtual Machine) parameters
const (
	MaxCodeSize    = 24576            // Maximum contract code size (24KB)
	MaxCallDepth   = 1024             // Maximum call stack depth
	MaxStackSize   = 1024             // Maximum stack size
	MaxMemorySize  = 32 * 1024 * 1024 // Maximum memory (32MB)
	CallGas        = 700              // Gas for CALL operation
	CreateGas      = 32000            // Gas for CREATE operation
	SstoreSetGas   = 20000            // Gas for SSTORE (new value)
	SstoreResetGas = 5000             // Gas for SSTORE (existing value)
	SloadGas       = 800              // Gas for SLOAD
)

// Storage parameters
const (
	MaxTrieCacheSize = 256  // Maximum trie cache size (MB)
	PruningRetention = 128  // Blocks to retain before pruning
	SnapshotInterval = 1024 // Blocks between snapshots
)

// Sync parameters
const (
	MaxBlockFetch   = 128 // Maximum blocks per sync request
	MaxHeaderFetch  = 192 // Maximum headers per sync request
	MaxReceiptFetch = 256 // Maximum receipts per sync request
	SyncTimeout     = 30  // Sync request timeout (seconds)
)
