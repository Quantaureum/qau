// Quantaureum Go SDK source, version 1.0.0.
// Package accounts provides transaction signing functionality.
package accounts

import (
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/sdks/go-sdk/common"
)

// TxLike is an interface for transaction-like types that can be signed.
// This avoids circular dependency with the types package while allowing
// the accounts package to work with transactions.
type TxLike interface {
	RLPEncodeForSigning(chainID *big.Int) []byte
	SetSignature(v, r, s *big.Int)
}

// rawSigner is an optional interface that types can implement to store the
// raw Dilithium3 signature bytes without splitting into V/R/S components.
//
// AUDIT 2026-07-12 KEYS-11 FIX: big.Int.SetBytes strips leading zero bytes
// from each half of the signature, so reassembling R.Bytes()+S.Bytes() can
// produce a shorter byte sequence than the original 3293-byte Dilithium3
// signature, causing chain verification to fail (or worse, mismatch
// silently). Types implementing SetRawSignature preserve the exact bytes.
type rawSigner interface {
	SetRawSignature(sig []byte)
}

// TxCopier is an interface for types that can create copies of themselves.
type TxCopier interface {
	Copy() any
}

// SignTransactionGeneric signs a transaction-like object with the account's Dilithium3 private key.
// The chainID is used for EIP-155 replay protection.
// Returns a new signed transaction (does not modify the original).
//
// AUDIT 2026-07-12 KEYS-11 FIX: Previously split the 3293-byte Dilithium3
// signature into two halves stored as big.Int R and S values. This was
// incorrect because big.Int.SetBytes strips leading zero bytes —
// reassembling via R.Bytes()+S.Bytes() can produce a shorter byte sequence
// that does not match the original signature, causing chain verification to
// fail or mismatch silently. The chain's Transaction type uses a single
// []byte Signature field, not V/R/S. Now stores the raw signature bytes via
// SetRawSignature when the type supports it; falls back to the lossy V/R/S
// split only for legacy types that don't implement rawSigner.
func (a *Account) SignTransactionGeneric(tx any, chainID *big.Int) (any, error) {
	if a == nil || a.privateKey == nil {
		return nil, fmt.Errorf("account or private key is nil")
	}
	if tx == nil {
		return nil, fmt.Errorf("transaction is nil")
	}
	if chainID == nil {
		chainID = big.NewInt(0)
	}

	// Check if tx implements TxLike
	txLike, ok := tx.(TxLike)
	if !ok {
		return nil, fmt.Errorf("transaction does not implement required interface")
	}

	// Create a copy if possible
	var signedTx any
	if copier, ok := tx.(TxCopier); ok {
		signedTx = copier.Copy()
		txLike = signedTx.(TxLike)
	} else {
		signedTx = tx
	}

	// Get the transaction hash for signing (with EIP-155 replay protection)
	txHash := txLike.RLPEncodeForSigning(chainID)

	// Sign with Dilithium3 (produces 3293 bytes)
	signature := make([]byte, SignatureSize)
	mode3.SignTo(a.privateKey, txHash, signature)

	// AUDIT 2026-07-12 KEYS-11 FIX: Store the raw signature bytes directly
	// when the transaction type supports it. This preserves the exact 3293-
	// byte signature, avoiding the big.Int.SetBytes leading-zero stripping
	// bug that occurs when splitting into V/R/S components.
	if rs, ok := txLike.(rawSigner); ok {
		rs.SetRawSignature(signature)
		return signedTx, nil
	}

	// Legacy fallback: split into V/R/S. WARNING: This loses leading zero
	// bytes from each half. Use SetRawSignature for Dilithium3 signatures.
	midpoint := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:midpoint])
	s := new(big.Int).SetBytes(signature[midpoint:])
	v := new(big.Int).Set(chainID)
	txLike.SetSignature(v, r, s)

	return signedTx, nil
}

// RecoverAddress attempts to recover the signer's address from a hash and signature.
//
// IMPORTANT: This function always returns an error for Dilithium3 signatures.
// Unlike ECDSA, post-quantum signatures (Dilithium3) do not support public key
// recovery from signatures. The public key must be known in advance to verify
// the signature.
//
// For Quantaureum transactions, the sender's address should be obtained from
// the transaction metadata or by verifying the signature against a known public key.
func RecoverAddress(hash []byte, signature []byte) (common.Address, error) {
	return common.Address{}, fmt.Errorf("RecoverAddress not supported for Dilithium3 - post-quantum signatures do not support key recovery")
}

// RecoverTransactionSigner attempts to recover the signer's address from a signed transaction.
//
// IMPORTANT: This function always returns an error for Dilithium3 signatures.
// Unlike ECDSA, post-quantum signatures (Dilithium3) do not support public key
// recovery from signatures. The public key must be known in advance to verify
// the signature.
//
// For Quantaureum transactions, the sender's address should be obtained from
// the transaction metadata or by verifying the signature against a known public key.
func RecoverTransactionSigner(tx any, chainID *big.Int) (common.Address, error) {
	return common.Address{}, fmt.Errorf("RecoverTransactionSigner not supported for Dilithium3 - post-quantum signatures do not support key recovery")
}
