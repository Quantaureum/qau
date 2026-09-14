// Quantaureum Node source, version 1.0.0.
// Package crypto provides cryptographic primitives for the Quantaureum blockchain.
// It implements post-quantum cryptography using Dilithium3 for digital signatures.
//
// =============================================================================
// SHARED INTERFACE WARNING - DO NOT MODIFY WITHOUT SYNCING WITH WALLET
// =============================================================================
// This file implements a SHARED INTERFACE with Quantaureum Wallet
// (app/scripts/lib/quantum-crypto/dilithium3.ts).
// Any changes to signature sizes, key formats, or serialization MUST be
// synchronized with the Wallet implementation.
//
// Shared parameters:
//   - Dilithium3PublicKeySize: 1952 bytes
//   - Dilithium3PrivateKeySize: 4000 bytes
//   - Dilithium3SignatureSize: 3293 bytes
//
// Wallet implementation: the quantaureum-wallet repo
// =============================================================================
package crypto
