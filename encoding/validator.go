// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"fmt"

	"github.com/quantaureum/qau/crypto"
)

// TransactionValidator is the canonical interface for transaction authorization
// verification in Quantaureum. Any code path that ingests transactions into
// the consensus MUST use this interface.
//
// This interface is defined in the encoding package alongside Transaction
// because it requires access to the Transaction type. Directly calling
// VerifyTransactionAuthorization or crypto.Verify outside this interface
// is a security violation.
//
// Usage:
//
//	validator := NewDefaultValidator()
//	err := validator.ValidateTx(tx)
//	errs := validator.ValidateTxBatch(txs)
type TransactionValidator interface {
	// ValidateTx verifies a single transaction's authorization.
	// Returns nil only if all checks pass:
	//   1. PublicKey length == Dilithium3PublicKeySize
	//   2. Signature length == Dilithium3SignatureSize
	//   3. PublicKey derives an address equal to tx.From
	//   4. Type-specific canonical signature verification passes
	//
	// Any non-nil error MUST be propagated; do not ignore or swallow.
	ValidateTx(tx *Transaction) error

	// ValidateTxBatch verifies multiple transactions efficiently.
	// Behavior MUST be strictly equivalent to calling ValidateTx on each element.
	// errs[i] corresponds to txs[i]. A nil entry means the transaction passed.
	ValidateTxBatch(txs []*Transaction) []error
}

// DefaultValidator is the production implementation of TransactionValidator.
// It wraps VerifyTransactionAuthorization and adds optional ChainID validation.
type DefaultValidator struct {
	// ExpectedChainID is the chain ID this validator enforces.
	// Set to 0 to skip ChainID validation (for testing only).
	ExpectedChainID uint64
}

// NewDefaultValidator creates a new DefaultValidator with the given chain ID.
// Pass 0 to skip chain ID validation (useful for testing).
func NewDefaultValidator(chainID uint64) *DefaultValidator {
	return &DefaultValidator{ExpectedChainID: chainID}
}

// ValidateTx implements TransactionValidator.ValidateTx.
// It delegates to VerifyTransactionAuthorization and optionally checks ChainID.
// Nonce validation: this is a stateless signature/authorization validator only;
// nonce monotonicity enforced in ValidateWithState (txpool/validator.go) which
// has access to account state, and in BatchValidator.ValidateNonces for batch
// admission paths.
func (v *DefaultValidator) ValidateTx(tx *Transaction) error {
	// Step 1: Canonical authorization check (covers PublicKey, Signature, From binding, type dispatch)
	if err := VerifyTransactionAuthorization(tx); err != nil {
		return err
	}

	// Step 2: Optional ChainID validation for cross-chain replay protection.
	// R43-ERR-CHAINID-01 (2026-08-03): previously reused
	// ErrAuthUnknownTxType, conflating "wrong chain ID" with "unknown tx
	// type" and making cross-chain replay attempts invisible in logs.
	// Use the dedicated sentinel so callers (block_validator, txpool, RPC
	// admit hook) can classify chain-ID mismatches distinctly.
	if v.ExpectedChainID > 0 && tx.ChainID != 0 && tx.ChainID != v.ExpectedChainID {
		return fmt.Errorf("%w: expected %d got %d", ErrAuthChainIDMismatch, v.ExpectedChainID, tx.ChainID)
	}

	return nil
}

// ValidateTxBatch implements TransactionValidator.ValidateTxBatch.
// It validates each transaction individually and returns a slice of errors.
// Nonce validation: stateless per-tx authorization only; nonce monotonicity
// enforced in ValidateWithState / BatchValidator.ValidateNonces (see ValidateTx).
func (v *DefaultValidator) ValidateTxBatch(txs []*Transaction) []error {
	errs := make([]error, len(txs))
	for i, tx := range txs {
		errs[i] = v.ValidateTx(tx)
	}
	return errs
}

// Ensure DefaultValidator satisfies the interface at compile time.
var _ TransactionValidator = (*DefaultValidator)(nil)

// Export sizes for external validation (matching crypto package constants)
const (
	// Dilithium3PublicKeySize is the expected public key size in bytes
	Dilithium3PublicKeySize = crypto.Dilithium3PublicKeySize

	// Dilithium3SignatureSize is the expected signature size in bytes
	Dilithium3SignatureSize = crypto.Dilithium3SignatureSize
)
