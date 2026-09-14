// Quantaureum Node source, version 1.0.0.
// Package txpool implements the transaction pool for Quantaureum.
package txpool

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// PublicKeyRegistry provides access to public keys by address.
// This is used for signature verification when the public key is not
// included in the transaction (e.g., for known accounts).
type PublicKeyRegistry interface {
	// GetPublicKey returns the public key for an address, or nil if not found.
	GetPublicKey(addr types.Address) *crypto.PublicKey
}

// ============================================================================
// LEGACY COMPATIBILITY CONFIGURATION
// ============================================================================
// AllowLegacySignatures was a backward-compatibility flag for secp256k1 (ECDSA) signatures.
//
// COMPLETED: The Quantaureum native wallet (quantaureum-wallet) has been released with
// full Dilithium3 post-quantum signature support. Legacy secp256k1 signatures are now
// PERMANENTLY DISABLED. All transactions MUST use Dilithium3 quantum-resistant signatures.
//
// ============================================================================
// ============================================================================
// QUANTUM SECURITY - LEGACY SIGNATURES PERMANENTLY DISABLED
// ============================================================================
// All secp256k1 (ECDSA) signatures are PERMANENTLY DISABLED for quantum security.
// All transactions MUST use Dilithium3 quantum-resistant signatures.
// ============================================================================

// Validation errors
var (
	ErrInvalidChainID          = errors.New("transaction chain ID does not match node chain ID")
	ErrInvalidSignature        = errors.New("invalid transaction signature")
	ErrLegacySignatureDisabled = errors.New("legacy secp256k1 signatures are disabled")
	ErrMissingPublicKey        = errors.New("missing public key for signature verification")
	ErrPublicKeyMismatch       = errors.New("public key does not match sender address")
	ErrInsufficientBalance     = errors.New("insufficient balance for transfer")
	ErrInsufficientGas         = errors.New("insufficient balance for gas")
	ErrNonceTooLow             = errors.New("nonce too low")
	ErrNonceTooHigh            = errors.New("nonce too high")
	ErrGasLimitTooLow          = errors.New("gas limit too low")
	ErrGasLimitTooHigh         = errors.New("gas limit exceeds block gas limit")
	ErrGasPriceTooLow          = errors.New("gas price below minimum")
	// ErrNilGasPrice rejects transactions without a gas price outright.
	// AUDIT (2026) FIX: previously a nil GasPrice silently fell
	// back to 0 in calculateTxCost, admitting zero-cost transactions on any
	// path that bypassed pool ingress checks. Cost accounting now fails
	// closed instead.
	ErrNilGasPrice      = errors.New("nil gas price")
	ErrTxTooLarge       = errors.New("transaction size too large")
	ErrInvalidRecipient = errors.New("invalid recipient address")
	ErrNegativeValue    = errors.New("negative value")
)

// Validation constants
const (
	MaxTxSize   = 128 * 1024 // 128 KB max transaction size
	MinGasLimit = 21000      // Minimum gas for a transaction

	// CRV2: exact length of the commitHash carried in a TxTypeCommit Data
	// field (SHA3-256 output).
	CRV2CommitHashLen = 32
	MaxGasLimit       = 30_000_000 // Maximum gas limit (30M)
	// MaxNonceGap controls how far ahead a transaction's nonce can be from the
	// current account nonce. Set to 128 to allow high-throughput TPS testing,
	// allowing 129 pending transactions per address (nonce, nonce+1, ..., nonce+128).
	// Previously 16 (matching Ethereum default), but this limited TPS to ~0.28.
	// DoS protection is handled by DefaultPoolSize (global cap 4096) and
	// DefaultAccountSlots (per-address cap) instead.
	MaxNonceGap = 64 // SECURITY (audit P2-R3-09): reduced from 128 to limit DoS
	// audit-fix C-2: CRITICAL - MaxPendingTxsPerAddress must equal MaxNonceGap + 1
	// This ensures consistency: if MaxNonceGap = 128, then exactly 129 txs can be pending
	MaxPendingTxsPerAddress = MaxNonceGap + 1
)

// audit-fix C-2: compile-time validation that parameters are consistent
func init() {
	if MaxPendingTxsPerAddress != MaxNonceGap+1 {
		panic(fmt.Sprintf(
			"CONFIGURATION ERROR: MaxPendingTxsPerAddress (%d) must equal MaxNonceGap+1 (%d). "+
				"Inconsistent parameters allow attackers to lock victim accounts with high-nonce flood attacks.",
			MaxPendingTxsPerAddress, MaxNonceGap+1))
	}
}

// StateReader provides read access to account state.
type StateReader interface {
	GetBalance(addr types.Address) *big.Int
	GetNonce(addr types.Address) uint64
}

// TxValidator validates transactions before they enter the transaction pool.
type TxValidator struct {
	// FIX: mu protects minGasPrice, blockGasLimit, chainID, and
	// pubKeyRegistry from concurrent reads/writes. Previously these fields
	// were accessed without synchronization, causing data races when
	// SetMinGasPrice/SetBlockGasLimit were called concurrently with
	// ValidateBasic/ValidateWithState.
	mu              sync.RWMutex
	minGasPrice     *big.Int
	blockGasLimit   uint64
	chainID         uint64
	pubKeyRegistry  PublicKeyRegistry
	signingVerifier *crypto.SigningVerifier
	// privacyEnabled gates TxTypePrivacy acceptance. Default false.
	// See SetPrivacyEnabled docs and audit R4-ZK-01.
	privacyEnabled bool
}

// NewTxValidator creates a new transaction validator.
func NewTxValidator(minGasPrice *big.Int, blockGasLimit uint64, chainID uint64) *TxValidator {
	if minGasPrice == nil {
		minGasPrice = big.NewInt(1)
	}
	return &TxValidator{
		minGasPrice:     minGasPrice,
		blockGasLimit:   blockGasLimit,
		chainID:         chainID,
		signingVerifier: crypto.NewSigningVerifier(),
	}
}

// GetSigningVerifier returns the signing verifier used by this tx validator.
// This allows sharing the same SignatureCache between txpool and block validation,
// maximizing cache hit rates when block txs were already verified in the txpool.
func (v *TxValidator) GetSigningVerifier() *crypto.SigningVerifier {
	return v.signingVerifier
}

// NewTxValidatorWithRegistry creates a new transaction validator with a public key registry.
// The registry is used to look up public keys for signature verification when the
// public key is not included in the transaction.
func NewTxValidatorWithRegistry(minGasPrice *big.Int, blockGasLimit uint64, chainID uint64, registry PublicKeyRegistry) *TxValidator {
	v := NewTxValidator(minGasPrice, blockGasLimit, chainID)
	v.pubKeyRegistry = registry
	return v
}

// SetPublicKeyRegistry sets the public key registry for signature verification.
func (v *TxValidator) SetPublicKeyRegistry(registry PublicKeyRegistry) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pubKeyRegistry = registry
}

// SetAllowLegacySignatures is permanently disabled.
// Legacy secp256k1 signatures create a quantum security vulnerability.
// All transactions MUST use Dilithium3 quantum-resistant signatures.
// Deprecated: This function exists for API compatibility only and has no effect.
func (v *TxValidator) SetAllowLegacySignatures(allow bool) {
	// Legacy signatures permanently disabled - this function does nothing
	// Security: All transactions must use Dilithium3 signatures
}

// SetChainID sets the chain ID for EIP-155 signature verification.
// LEGACY COMPATIBILITY - for MetaMask/Ethereum wallets
func (v *TxValidator) SetChainID(chainID uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.chainID = chainID
}

// privacyEnabled controls whether privacy transactions (TxTypePrivacy) are
// accepted into the pool. Default false — the ZK privacy subsystem is not
// wired in production (no PrivacyTxVerifier configured), so accepting a
// privacy tx into the mempool would let it reach the executor's fail-closed
// path. Although the executor now rejects privacy tx before any state
// mutation (audit R4-ZK-01 fix), rejecting at ingress is cleaner and
// prevents mempool pollution.
func (v *TxValidator) SetPrivacyEnabled(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.privacyEnabled = enabled
}

// intrinsicGasForValidation computes the minimum gas required for the
// transaction using the default gas table constants (consensus values).
// This mirrors TxExecutor.intrinsicGas but is available without a TxExecutor
// instance, so the validator can reject transactions that would fail the
// executor's intrinsic gas check BEFORE they enter the pool.
//
// R36-P1-TXPOOL-01 FIX (2026-07-30): Without this check at ingress, an
// attacker could submit GasLimit=21000 with 128KB of data — the executor
// rejects it (intrinsic gas too low) but the tx still enters the block
// with zero cost and a fraudulent GasUsed=tx.GasLimit receipt.
func intrinsicGasForValidation(tx *encoding.Transaction) uint64 {
	const (
		txGas         uint64 = 21000
		txDataZero    uint64 = 4
		txDataNonZero uint64 = 16
		txCreate      uint64 = 32000
	)
	gas := txGas
	for _, b := range tx.Data {
		if b == 0 {
			gas += txDataZero
		} else {
			gas += txDataNonZero
		}
	}
	if tx.Type == encoding.TxTypeCreate {
		gas += txCreate
	}
	return gas
}

// validateBasicFields performs the stateless field validation checks common to
// both ValidateBasic and validateBasicWithoutSignature.
// P2-15 FIX: extracted shared logic to eliminate code duplication and ensure
// consistent validation across both code paths.
func (v *TxValidator) validateBasicFields(tx *encoding.Transaction) error {
	// SECURITY (audit R4-ZK-01): Reject privacy transactions at ingress
	// when the privacy subsystem is not enabled. Privacy txs skip
	// signature verification (validator.go ValidateBasic) and nonce
	// checks — accepting them when no verifier is configured would allow
	// a forged privacy tx to reach the executor. The executor now also
	// fail-closes before any state mutation, but rejecting at ingress
	// prevents mempool pollution and the associated griefing vector.
	if tx.Type == encoding.TxTypePrivacy {
		v.mu.RLock()
		enabled := v.privacyEnabled
		v.mu.RUnlock()
		if !enabled {
			return errors.New("privacy transactions are not enabled on this node")
		}
	}

	// Check transaction size
	if tx.Size() > MaxTxSize {
		return ErrTxTooLarge
	}

	// FIX: Read chain ID under lock to prevent concurrent modification.
	v.mu.RLock()
	chainID := v.chainID
	v.mu.RUnlock()

	// Validate chain ID to prevent cross-network replay attacks.
	// SECURITY FIX: ChainID must always be explicitly set and must match the node's chain.
	// tx.ChainID == 0 is invalid for quantum transactions - all must carry explicit chain ID.
	// FIXED: Now ALWAYS validates chainID, not just when v.chainID != 0
	if tx.ChainID == 0 {
		return ErrInvalidChainID
	}
	if tx.ChainID != chainID {
		return ErrInvalidChainID
	}

	// Check for negative value
	if tx.Value != nil && tx.Value.Sign() < 0 {
		return ErrNegativeValue
	}

	// audit-fix R11-HIGH-DUST: Enforce minimum transaction value (dust limit)
	// for pure transfers only. Contract calls (tx.Data is non-empty) are allowed
	// with Value=0 since they pay gas for execution.
	const minTxValue = 1000 // 1000 photons
	isContractCall := len(tx.Data) > 0
	if !isContractCall && tx.Value != nil && tx.Value.Sign() > 0 && tx.Value.Cmp(big.NewInt(minTxValue)) < 0 {
		return errors.New("transfer value too low (dust)")
	}

	// Check gas limit
	if tx.GasLimit < MinGasLimit {
		return ErrGasLimitTooLow
	}

	// R36-P1-TXPOOL-01 FIX (2026-07-30): Reject transactions whose GasLimit
	// cannot cover the intrinsic gas (21000 + data gas + creation gas).
	// Previously the pool only checked GasLimit >= 21000 (MinGasLimit),
	// allowing an attacker to submit GasLimit=21000 with 128KB of data.
	// The executor would reject it as intrinsic-gas-too-low but the tx
	// still entered the block with zero cost (free block space DoS) and
	// receipt.GasUsed was fraudulently set to tx.GasLimit. This check
	// closes the entry gap so such txs never enter the pool.
	if tx.GasLimit < intrinsicGasForValidation(tx) {
		return ErrIntrinsicGas
	}

	// L14-004 FIX: Enforce absolute maximum gas limit (30M) regardless of
	// blockGasLimit configuration. This prevents misconfigured nodes from
	// accepting transactions with unreasonably high gas limits.
	if tx.GasLimit > MaxGasLimit {
		return ErrGasLimitTooHigh
	}

	// FIX: Read blockGasLimit and minGasPrice under lock.
	v.mu.RLock()
	blockGasLimit := v.blockGasLimit
	minGasPrice := v.minGasPrice
	v.mu.RUnlock()

	if tx.GasLimit > blockGasLimit {
		return ErrGasLimitTooHigh
	}

	// Check gas price
	// R34 P2-02 FIX (2026-07-29): Clarify GasPrice semantics.
	// Quantaureum requires ALL transaction types (including TxTypeDynamicFee)
	// to set tx.GasPrice. For dynamic-fee transactions, callers SHOULD set
	// tx.GasPrice = tx.MaxFeePerGas so the pool can reject transactions
	// whose fee cap is below minGasPrice. The executor's effectiveGasPrice()
	// logic still computes the actual on-chain fee from MaxFeePerGas /
	// MaxPriorityFeePerGas / BaseFee, but the pool's acceptance gate uses
	// tx.GasPrice as a unified lower bound.
	//
	// The executor's nil-GasPrice handling (executor.go:371-377) is retained
	// as defense-in-depth for transactions that bypass the pool (e.g.,
	// block-applied transactions from peers during sync), but the txpool
	// invariant is: if GasPrice is nil, the transaction is rejected here.
	if tx.GasPrice == nil || tx.GasPrice.Cmp(minGasPrice) < 0 {
		return ErrGasPriceTooLow
	}

	// CRV2: Commitment transactions carry exactly one 32-byte commitHash in
	// Data, move no value, and target the zero address. Anything else claiming
	// to be a commit tx is malformed — reject at ingress so the pool's
	// commitment index never contains ambiguous entries.
	if tx.Type == encoding.TxTypeCommit {
		if len(tx.Data) != CRV2CommitHashLen {
			return fmt.Errorf("commit transaction Data must be exactly %d bytes (commitHash), got %d",
				CRV2CommitHashLen, len(tx.Data))
		}
		if tx.Value == nil || tx.Value.Sign() != 0 {
			return errors.New("commit transaction must carry Value = 0")
		}
		if tx.To == nil || *tx.To != (types.Address{}) {
			return errors.New("commit transaction must target the zero address")
		}
	}

	return nil
}

// ValidateBasic performs basic validation without state access.
// Note: Nonce monotonicity is enforced in ValidateWithState which has access to account state.
// This function only performs stateless validation checks.
// nonce monotonicity enforced in ValidateWithState
func (v *TxValidator) ValidateBasic(tx *encoding.Transaction) error {
	// P2-15 FIX: delegate field validation to shared helper
	if err := v.validateBasicFields(tx); err != nil {
		return err
	}

	// R38-P0-02 (2026-08-01) FIX: Replace the stake/unstake signature
	// skip with canonical VerifyTransactionAuthorization. Every tx type —
	// including TxTypeStake / TxTypeUnstake — goes through the unified
	// authorization check, which:
	//   - validates Dilithium3 pubkey length / signature length
	//   - enforces pubkey.Address() == tx.From
	//   - for ordinary tx verifies tx.SigningHash()
	//   - for stake/unstake re-derives ComputeStakeAuthorizationHash over
	//     the canonical fields (chainID/from/recipient/txType/value/
	//     commission/nonce) and verifies the canonical signature
	// This eliminates the post-signature tamper window the legacy
	// "string-domain stake signature" left open.
	// Privacy tx continue to skip Dilithium3 verification at this layer;
	// they carry ZK proofs whose check happens later (executePrivacyTransfer).
	if tx.Type != encoding.TxTypePrivacy {
		if err := encoding.VerifyTransactionAuthorization(tx); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
	}

	return nil
}

// ValidateWithState performs full validation including state checks.
func (v *TxValidator) ValidateWithState(tx *encoding.Transaction, state StateReader) error {
	// First do basic validation
	if err := v.ValidateBasic(tx); err != nil {
		return err
	}

	// L11-026 SECURITY JUSTIFICATION: Privacy transactions (TxTypePrivacy)
	// intentionally skip nonce and balance checks. This is safe because:
	//
	// 1. Replay protection: Privacy transactions use nullifiers (cryptographic
	//    hashes of spent input notes) for replay protection, NOT account nonces.
	//    Once a nullifier is published on-chain, the same input note cannot be
	//    spent again. The tx.From in a privacy transaction is a commitment or
	//    nullifier reference, not a regular account address, so checking
	//    state.GetNonce(tx.From) would always return 0 - the check is meaningless.
	//
	// 2. Balance sufficiency: Privacy transaction values are hidden inside
	//    zero-knowledge proofs. The ZK proof verifies that: (a) the sender owns
	//    the input notes (spending authority), (b) sum(inputs) >= sum(outputs)
	//    + fee (no inflation), and (c) note commitments are well-formed.
	//    The public account balance does NOT reflect shielded funds - they
	//    live in note commitments, not in public state. Checking the public
	//    balance would always fail or return 0.
	//
	// Adding nonce/balance checks for privacy transactions would break the
	// privacy model without providing any security benefit.
	if tx.Type != encoding.TxTypePrivacy {
		accountNonce := state.GetNonce(tx.From)
		if tx.Nonce < accountNonce {
			return ErrNonceTooLow
		}
		if tx.Nonce > accountNonce+MaxNonceGap {
			return ErrNonceTooHigh
		}
	}

	// Balance check - skipped for privacy transactions (see L11-026 justification above)
	if tx.Type != encoding.TxTypePrivacy {
		balance := state.GetBalance(tx.From)
		cost, err := v.calculateTxCost(tx)
		if err != nil {
			return err
		}
		if balance.Cmp(cost) < 0 {
			return ErrInsufficientBalance
		}
	}

	return nil
}

// validateBasicWithoutSignature performs the same checks as ValidateBasic
// but skips Dilithium3 signature verification. This allows batch validation
// to separate fast checks from expensive crypto operations.
// P2-15 FIX: now delegates to the shared validateBasicFields helper to
// eliminate code duplication with ValidateBasic.
func (v *TxValidator) validateBasicWithoutSignature(tx *encoding.Transaction) error {
	return v.validateBasicFields(tx)
}

// BatchValidateWithState validates a batch of transactions with parallel
// Dilithium3 signature verification. It separates fast checks (format, nonce,
// balance) from expensive signature verification, running signatures through
// BatchVerifier with parallel workers and SignatureCache.
//
// Returns a slice of errors, one for each transaction (nil = valid).
// This is used by TxPool.BatchAdd to speed up high-throughput tx ingestion.
func (v *TxValidator) BatchValidateWithState(txs []*encoding.Transaction, state StateReader) []error {
	errs := make([]error, len(txs))

	// Phase 1: Fast validation (serial) — everything except Dilithium3 verification
	for i, tx := range txs {
		if err := v.validateBasicWithoutSignature(tx); err != nil {
			errs[i] = err
			continue
		}

		// State validation (nonce, balance) - skipped for privacy transactions.
		// See L11-026 security justification in ValidateWithState above for why
		// this is safe (nullifier-based replay protection + ZK proof of ownership).
		if tx.Type != encoding.TxTypePrivacy {
			accountNonce := state.GetNonce(tx.From)
			if tx.Nonce < accountNonce {
				errs[i] = ErrNonceTooLow
				continue
			}
			if tx.Nonce > accountNonce+MaxNonceGap {
				errs[i] = ErrNonceTooHigh
				continue
			}
			balance := state.GetBalance(tx.From)
			cost, err := v.calculateTxCost(tx)
			if err != nil {
				errs[i] = err
				continue
			}
			if balance.Cmp(cost) < 0 {
				errs[i] = ErrInsufficientBalance
				continue
			}
		}

		// Privacy transactions use ZK proofs, no Dilithium3 verification needed.
		// R40-P0-03 (2026-08-03) FIX: the prior implementation at this point
		// (Phase 1 of BatchValidateWithState) pushed EVERY non-privacy tx —
		// including stake/unstake — into a parallel BatchVerifier pipeline that
		// verified `tx.Signature` against `tx.SigningHash()`. For stake/unstake
		// transactions, however, the canonical authorization message is
		// `ComputeStakeAuthorizationHash(method|chainID|from|recipient|txType|...)`,
		// NOT `SigningHash()` (R39-P0-03 unified this on the single-admission
		// path via `encoding.VerifyTransactionAuthorization`, but the batch
		// path was NOT synced, silently rejecting every P2P-relayed stake tx).
		//
		// Worse, the preceding comment block claimed the old SigningHash path
		// had been reverted — while the code immediately below still pushed
		// every tx into the same SigningHash-based pipeline. The comment was a
		// lie and the code was the bug.
		//
		// The fix: every non-privacy tx now goes through the SAME canonical
		// `encoding.VerifyTransactionAuthorization` helper used by
		// `ValidateBasic` (single-admission path). That helper dispatches on
		// tx.Type internally (SigningHash for transfer/contract/create,
		// ComputeStakeAuthorizationHash for stake/unstake), enforces
		// Dilithium3 pubkey/signature lengths, and checks pubkey→address
		// equality — uniformly with the single-admission path.
		//
		// We pay the cost of losing the parallel BatchVerifier micro-
		// optimization for stake/unstake txs. That is acceptable: (1) the
		// canonical helper already short-circuits on length/destination checks
		// before invoking the crypto layer, and (2) correctness MUST win over
		// throughput — a batch path that silently rejects all valid stake txs
		// is not an optimization, it is a regression.
		if tx.Type == encoding.TxTypePrivacy {
			continue
		}

		if err := encoding.VerifyTransactionAuthorization(tx); err != nil {
			errs[i] = err
			continue
		}
	}

	return errs
}

// verifySignature verifies the transaction signature using Dilithium3.
// Requirements: 3.6 - Verify signatures before acceptance
//
// For Dilithium signatures, we need the public key to verify. The public key
// can be obtained from:
// 1. The transaction's PublicKey field (for first-time senders or explicit inclusion)
// 2. The public key registry (for known accounts)
//
// The method also verifies that the public key matches the From address.
func (v *TxValidator) verifySignature(tx *encoding.Transaction) bool {
	return v.ValidateSignature(tx) == nil
}

// ValidateSignature performs full signature validation and returns a specific error.
// Requirements: 3.6 - Verify signatures before acceptance
//
// This method supports two signature types:
// 1. Dilithium3 (quantum-resistant) - Primary signature scheme
// 2. secp256k1/ECDSA (legacy) - For MetaMask/Ethereum wallet compatibility
//
// LEGACY COMPATIBILITY: secp256k1 support can be disabled by setting
// allowLegacySignatures to false or AllowLegacySignatures global to false.
//
// Note: Nonce monotonicity is enforced in ValidateWithState, not here.
// nonce monotonicity enforced in ValidateWithState
//
// SECURITY FIX: Legacy secp256k1 signatures are PERMANENTLY DISABLED.
// Only Dilithium3 quantum-resistant signatures are accepted.
// This method only validates Dilithium3 signatures.
func (v *TxValidator) ValidateSignature(tx *encoding.Transaction) error {
	// All secp256k1 (ECDSA) signatures are permanently disabled for quantum security.
	// We skip the length check since validateDilithiumSignature will catch invalid lengths.
	// If the signature is 65 bytes (legacy format), it will be rejected as invalid.
	return v.validateDilithiumSignature(tx)
}

// validateDilithiumSignature validates a Dilithium3 (quantum-resistant) signature
func (v *TxValidator) validateDilithiumSignature(tx *encoding.Transaction) error {
	var pubKeyBytes []byte

	if len(tx.PublicKey) > 0 {
		pubKeyBytes = tx.PublicKey
	} else {
		// FIX: Read pubKeyRegistry under lock.
		v.mu.RLock()
		registry := v.pubKeyRegistry
		v.mu.RUnlock()
		if registry != nil {
			pubKey := registry.GetPublicKey(tx.From)
			if pubKey != nil {
				pubKeyBytes = pubKey.Bytes()
			}
		}
	}

	if len(pubKeyBytes) == 0 {
		return ErrMissingPublicKey
	}

	// I22-004 FIX: Explicit signature length check for defense-in-depth.
	// Dilithium3 signatures are exactly 3293 bytes. The underlying
	// VerifyTransactionSignature call would reject malformed signatures,
	// but an explicit length check provides early rejection (avoiding the
	// expensive Dilithium3 verification) and defense-in-depth.
	const dilithium3SigSize = 3293
	if len(tx.Signature) != dilithium3SigSize {
		return fmt.Errorf("invalid signature length: %d, expected %d", len(tx.Signature), dilithium3SigSize)
	}

	derivedAddr := crypto.PublicKeyAddressFromBytes(pubKeyBytes)
	if derivedAddr != tx.From {
		return ErrPublicKeyMismatch
	}

	signingHash, err := tx.SigningHash()
	if err != nil {
		return err
	}

	if err := v.signingVerifier.VerifyTransactionSignature(pubKeyBytes, signingHash[:], tx.Signature); err != nil {
		return ErrInvalidSignature
	}

	return nil
}

// calculateTxCost calculates the total cost of a transaction.
func (v *TxValidator) calculateTxCost(tx *encoding.Transaction) (*big.Int, error) {
	// cost = value + gasLimit * gasPrice
	// Safe conversion: clamp GasLimit to MaxInt64 to prevent overflow
	gasLimitSafe := tx.GasLimit
	if gasLimitSafe > math.MaxInt64 {
		gasLimitSafe = math.MaxInt64
	}
	// AUDIT (2026) FIX: a nil GasPrice is now a hard validation
	// error instead of silently degrading to a zero gas cost. The previous
	// 0-fallback let transactions that bypassed pool ingress (e.g. block-
	// applied txs from peers during sync) carry zero fee, enabling a block
	// producer to self-deal free transactions. Fail closed: every non-
	// privacy transaction must declare a positive gas price (the block
	// validator enforces the same invariant via encoding.Transaction.
	// Validate, which rejects nil/zero GasPrice).
	if tx.GasPrice == nil {
		return nil, ErrNilGasPrice
	}
	gasCost := new(big.Int).Mul(
		big.NewInt(int64(gasLimitSafe)), // #nosec G115 - overflow checked above
		tx.GasPrice,
	)

	total := new(big.Int).Set(gasCost)
	if tx.Value != nil {
		total.Add(total, tx.Value)
	}

	return total, nil
}

// SetMinGasPrice updates the minimum gas price.
func (v *TxValidator) SetMinGasPrice(price *big.Int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.minGasPrice = price
}

// SetBlockGasLimit updates the block gas limit.
func (v *TxValidator) SetBlockGasLimit(limit uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.blockGasLimit = limit
}

// ValidateGasLimit validates that a gas limit is within acceptable bounds.
// Requirements: 3.5 - Validate gas limits are within acceptable bounds
// Returns nil if valid, or an appropriate error if invalid.
// Note: This is a gas-only validation. Nonce monotonicity is enforced in ValidateWithState.
// nonce monotonicity enforced in ValidateWithState
func (v *TxValidator) ValidateGasLimit(gasLimit uint64) error {
	// Check minimum gas limit
	if gasLimit < MinGasLimit {
		return ErrGasLimitTooLow
	}

	// Check against absolute maximum
	if gasLimit > MaxGasLimit {
		return ErrGasLimitTooHigh
	}

	// FIX: Read blockGasLimit under lock.
	v.mu.RLock()
	blockGasLimit := v.blockGasLimit
	v.mu.RUnlock()

	// Check against block gas limit (which may be lower than MaxGasLimit)
	if gasLimit > blockGasLimit {
		return ErrGasLimitTooHigh
	}

	return nil
}

// IsGasLimitValid returns true if the gas limit is within acceptable bounds.
// This is a convenience method for quick validation checks.
func (v *TxValidator) IsGasLimitValid(gasLimit uint64) bool {
	return v.ValidateGasLimit(gasLimit) == nil
}

// GetGasLimitBounds returns the minimum and maximum acceptable gas limits.
func (v *TxValidator) GetGasLimitBounds() (min, max uint64) {
	// FIX: Read blockGasLimit under lock.
	v.mu.RLock()
	blockGasLimit := v.blockGasLimit
	v.mu.RUnlock()

	max = blockGasLimit
	if MaxGasLimit < max {
		max = MaxGasLimit
	}
	return MinGasLimit, max
}
