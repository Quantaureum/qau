// Quantaureum Node source, version 1.0.0.
// Package validation provides input validation framework for Quantaureum.
// This file implements batch transaction validation for improved efficiency.
// Implements Requirements 13.1, 13.2: batch signature verification and format validation.
package validation

import (
	"errors"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// Batch validation errors
var (
	ErrBatchEmpty            = errors.New("batch is empty")
	ErrBatchTooLarge         = errors.New("batch exceeds maximum size")
	ErrSignatureVerifyFailed = errors.New("signature verification failed")
	ErrNonceNotContinuous    = errors.New("nonce is not continuous")
	ErrGasOutOfRange         = errors.New("gas is out of valid range")
)

// Batch validation constants
const (
	DefaultBatchSize        = 100
	DefaultCacheSize        = 10000
	MinBatchGasLimit        = 21000      // Minimum gas for a transaction
	MaxBatchGasLimit        = 30_000_000 // Maximum gas limit
	DefaultMinGasPrice      = 1
	MaxTransactionsPerBatch = 10000 // R58-PK-4 [LOW] FIX: hard cap prevents unbounded memory growth from malicious batches
)

// BatchValidationResult represents the result of validating a single transaction.
type BatchValidationResult struct {
	Valid   bool
	Error   error
	TxHash  types.Hash
	GasUsed uint64
}

// PublicKeyProvider provides public keys for addresses.
type PublicKeyProvider interface {
	GetPublicKey(addr types.Address) (*crypto.PublicKey, error)
}

// BatchStateReader provides read access to account state for validation.
type BatchStateReader interface {
	GetBalance(addr types.Address) *big.Int
	GetNonce(addr types.Address) uint64
}

// BatchValidator provides batch transaction validation with signature caching.
// Implements Requirements 13.1: batch signature verification for improved efficiency.
type BatchValidator struct {
	mu sync.RWMutex

	// Signature verification cache using LRU eviction
	sigCache *SignatureCache

	// Configuration
	batchSize   int
	minGasPrice *big.Int
	maxGasLimit uint64

	// Public key provider for signature verification
	keyProvider PublicKeyProvider
}

// NewBatchValidator creates a new BatchValidator with default settings.
func NewBatchValidator(keyProvider PublicKeyProvider) *BatchValidator {
	return &BatchValidator{
		sigCache:    NewSignatureCache(DefaultCacheSize),
		batchSize:   DefaultBatchSize,
		minGasPrice: big.NewInt(DefaultMinGasPrice),
		maxGasLimit: MaxBatchGasLimit,
		keyProvider: keyProvider,
	}
}

// NewBatchValidatorWithConfig creates a new BatchValidator with custom configuration.
func NewBatchValidatorWithConfig(keyProvider PublicKeyProvider, cacheSize, batchSize int, minGasPrice *big.Int) *BatchValidator {
	if cacheSize <= 0 {
		cacheSize = DefaultCacheSize
	}
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}
	if minGasPrice == nil {
		minGasPrice = big.NewInt(DefaultMinGasPrice)
	}
	return &BatchValidator{
		sigCache:    NewSignatureCache(cacheSize),
		batchSize:   batchSize,
		minGasPrice: minGasPrice,
		maxGasLimit: MaxBatchGasLimit,
		keyProvider: keyProvider,
	}
}

// ValidateBatch validates a batch of transactions and returns results for each.
// Implements Requirements 13.1, 13.2: batch validation with signature verification.
func (bv *BatchValidator) ValidateBatch(txs []*encoding.Transaction) []*BatchValidationResult {
	if len(txs) == 0 {
		return nil
	}

	// R58-PK-4 [LOW] FIX: hard cap prevents unbounded memory growth from malicious batches
	if len(txs) > MaxTransactionsPerBatch {
		return []*BatchValidationResult{{
			Valid: false,
			Error: ErrBatchTooLarge,
		}}
	}

	results := make([]*BatchValidationResult, len(txs))
	for i, tx := range txs {
		results[i] = bv.validateSingle(tx)
	}
	return results
}

// validateSingle validates a single transaction.
func (bv *BatchValidator) validateSingle(tx *encoding.Transaction) *BatchValidationResult {
	if tx == nil {
		return &BatchValidationResult{
			Valid: false,
			Error: errors.New("nil transaction"),
		}
	}

	hash := tx.Hash()
	result := &BatchValidationResult{TxHash: hash}

	// Validate format first (fast checks)
	if err := bv.validateFormat(tx); err != nil {
		result.Error = err
		return result
	}

	// Validate signature (may use cache)
	if !bv.verifySignature(tx) {
		result.Error = ErrSignatureVerifyFailed
		return result
	}

	result.Valid = true
	result.GasUsed = tx.GasLimit
	return result
}

// validateFormat performs basic format validation.
// Implements Requirements 13.2: microsecond-level format validation.
func (bv *BatchValidator) validateFormat(tx *encoding.Transaction) error {
	// audit-fix R4-M2 + NEW-21: snapshot both minGasPrice and maxGasLimit under
	// lock to avoid data races with SetMinGasPrice / SetMaxGasLimit.
	bv.mu.RLock()
	minGasPrice := bv.minGasPrice
	maxGasLimit := bv.maxGasLimit
	bv.mu.RUnlock()

	// Check gas limit
	if tx.GasLimit < MinBatchGasLimit {
		return ErrGasOutOfRange
	}
	if tx.GasLimit > maxGasLimit {
		return ErrGasOutOfRange
	}

	// Check gas price
	if tx.GasPrice == nil || tx.GasPrice.Cmp(minGasPrice) < 0 {
		return ErrGasOutOfRange
	}

	// Check value is not negative
	if tx.Value != nil && tx.Value.Sign() < 0 {
		return ErrInvalidValue
	}

	// Check signature is present
	// audit-fix R5-H1: byte(len()) wraps at 256; use direct length check
	if len(tx.Signature) == 0 {
		return ErrInvalidSignature
	}

	return nil
}

// ValidateSignatures validates signatures for a batch of transactions.
// Returns a slice of booleans indicating whether each signature is valid.
// Implements Requirements 13.1: batch signature verification.
func (bv *BatchValidator) ValidateSignatures(txs []*encoding.Transaction) []bool {
	if len(txs) == 0 {
		return nil
	}

	results := make([]bool, len(txs))
	for i, tx := range txs {
		if tx == nil {
			results[i] = false
			continue
		}
		results[i] = bv.verifySignature(tx)
	}
	return results
}

// verifySignature verifies a transaction authorization using the unified
// DefaultValidator interface, with caching for performance.
//
// R42-REFACTOR: Previously, signature verification used a custom
// doVerifySignature method that:
// 1. Looked up the public key from tx.From (not from tx.PublicKey)
// 2. Verified only SigningHash, not the canonical authorization hash
// 3. Did NOT support stake/unstake transactions (only ordinary tx types)
// 4. Bypassed From↔PublicKey binding check entirely
//
// This created R41-L6TXP-07 style vulnerabilities where the batch validator
// could be used to forge transactions by providing a matching signature
// for a different key than the transaction's declared sender.
//
// Now verification uses encoding.DefaultValidator.ValidateTx which:
//  1. Checks PublicKey size and Signature size
//  2. Verifies From↔PublicKey binding (prevents address forgery)
//  3. Dispatches on tx.Type to the correct canonical hash verification
//     (SigningHash for ordinary tx, ComputeStakeAuthorizationHash for stake/unstake)
//  4. Returns typed errors that can be debugged
//
// Caching: Only VALID results are cached. Invalid results are never stored
// so that a transient verification failure cannot poison the cache.
func (bv *BatchValidator) verifySignature(tx *encoding.Transaction) bool {
	if tx == nil {
		return false
	}

	hash := tx.Hash()

	// Check cache first (only positives are ever stored)
	if cached, ok := bv.sigCache.Get(hash); ok {
		return cached
	}

	// Use DefaultValidator for unified verification
	validator := encoding.NewDefaultValidator(0) // 0 = skip chain ID validation
	err := validator.ValidateTx(tx)
	valid := err == nil

	// Cache result ONLY when valid, to prevent poisoning.
	if valid {
		bv.sigCache.Set(hash, true)
	}

	return valid
}

// ValidateNonces validates nonces for a batch of transactions against state.
// Returns a slice of booleans indicating whether each nonce is valid.
// Implements Requirements 13.3: nonce continuity and uniqueness validation.
func (bv *BatchValidator) ValidateNonces(txs []*encoding.Transaction, state BatchStateReader) []bool {
	if len(txs) == 0 || state == nil {
		return nil
	}

	results := make([]bool, len(txs))
	expectedNonces := make(map[types.Address]uint64)

	for i, tx := range txs {
		if tx == nil {
			results[i] = false
			continue
		}

		// Get expected nonce for this account
		expected, ok := expectedNonces[tx.From]
		if !ok {
			expected = state.GetNonce(tx.From)
		}

		// Check if nonce matches expected
		if tx.Nonce == expected {
			results[i] = true
			expectedNonces[tx.From] = expected + 1
		} else {
			results[i] = false
		}
	}

	return results
}

// ValidateGas validates gas parameters for a batch of transactions.
// Returns a slice of booleans indicating whether each gas configuration is valid.
// Implements Requirements 13.4: gas price and limit validation.
// audit-fix NEW-21: snapshot minGasPrice and maxGasLimit under lock to
// prevent data races with SetMinGasPrice / SetMaxGasLimit.
func (bv *BatchValidator) ValidateGas(txs []*encoding.Transaction) []bool {
	if len(txs) == 0 {
		return nil
	}

	bv.mu.RLock()
	minGasPrice := bv.minGasPrice
	maxGasLimit := bv.maxGasLimit
	bv.mu.RUnlock()

	results := make([]bool, len(txs))
	for i, tx := range txs {
		if tx == nil {
			results[i] = false
			continue
		}

		// Check gas limit range
		if tx.GasLimit < MinBatchGasLimit || tx.GasLimit > maxGasLimit {
			results[i] = false
			continue
		}

		// Check gas price
		if tx.GasPrice == nil || tx.GasPrice.Cmp(minGasPrice) < 0 {
			results[i] = false
			continue
		}

		results[i] = true
	}

	return results
}

// ValidateWithState performs full validation including state checks.
// Implements Requirements 13.3, 13.4, 13.5: complete validation with state.
func (bv *BatchValidator) ValidateWithState(txs []*encoding.Transaction, state BatchStateReader) []*BatchValidationResult {
	if len(txs) == 0 {
		return nil
	}

	results := make([]*BatchValidationResult, len(txs))

	// SEC-VAL-01 FIX (deep-audit 2026-07-12): guard a nil state reader (unlike
	// ValidateNonces, this method did not). Calling state.GetNonce/GetBalance on
	// a nil reader panics and can crash the goroutine/node.
	if state == nil {
		for i := range results {
			results[i] = &BatchValidationResult{Valid: false, Error: errors.New("nil state reader")}
		}
		return results
	}

	// First validate signatures in batch
	sigResults := bv.ValidateSignatures(txs)

	// Then validate each transaction with state
	for i, tx := range txs {
		if tx == nil {
			results[i] = &BatchValidationResult{
				Valid: false,
				Error: errors.New("nil transaction"),
			}
			continue
		}

		hash := tx.Hash()
		result := &BatchValidationResult{TxHash: hash}

		// Check signature result
		if !sigResults[i] {
			result.Error = ErrSignatureVerifyFailed
			results[i] = result
			continue
		}

		// Validate format
		if err := bv.validateFormat(tx); err != nil {
			result.Error = err
			results[i] = result
			continue
		}

		// Validate nonce
		accountNonce := state.GetNonce(tx.From)
		if tx.Nonce < accountNonce {
			result.Error = ErrNonceNotContinuous
			results[i] = result
			continue
		}

		// Validate balance
		balance := state.GetBalance(tx.From)
		// SEC-VAL-01 FIX: treat a nil balance (unknown account) as zero; the old
		// balance.Cmp(cost) nil-dereferenced and panicked for such accounts.
		if balance == nil {
			balance = big.NewInt(0)
		}
		cost := bv.calculateTxCost(tx)
		if balance.Cmp(cost) < 0 {
			result.Error = errors.New("insufficient balance")
			results[i] = result
			continue
		}

		result.Valid = true
		result.GasUsed = tx.GasLimit
		results[i] = result
	}

	return results
}

// calculateTxCost calculates the total cost of a transaction.
func (bv *BatchValidator) calculateTxCost(tx *encoding.Transaction) *big.Int {
	// audit-fix R5-F19: use SetUint64 to avoid silent int64 overflow on large GasLimit
	gasCost := new(big.Int).Mul(
		new(big.Int).SetUint64(tx.GasLimit),
		tx.GasPrice,
	)

	total := new(big.Int).Set(gasCost)
	if tx.Value != nil {
		total.Add(total, tx.Value)
	}

	return total
}

// ClearCache clears the signature verification cache.
func (bv *BatchValidator) ClearCache() {
	bv.sigCache.Clear()
}

// CacheSize returns the current number of cached signature results.
func (bv *BatchValidator) CacheSize() int {
	return bv.sigCache.Size()
}

// SetMinGasPrice updates the minimum gas price.
func (bv *BatchValidator) SetMinGasPrice(price *big.Int) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.minGasPrice = price
}

// SetMaxGasLimit updates the maximum gas limit.
func (bv *BatchValidator) SetMaxGasLimit(limit uint64) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.maxGasLimit = limit
}

// IsCached returns whether a transaction's signature verification result is cached.
func (bv *BatchValidator) IsCached(hash types.Hash) bool {
	return bv.sigCache.Contains(hash)
}

// GetCachedResult returns the cached signature verification result for a transaction.
// Returns (result, true) if cached, (false, false) if not cached.
func (bv *BatchValidator) GetCachedResult(hash types.Hash) (bool, bool) {
	return bv.sigCache.Get(hash)
}

// SignatureBatchVerifier provides batch signature verification.
type SignatureBatchVerifier struct {
	pubKeys    []*crypto.PublicKey
	messages   [][]byte
	signatures [][]byte
}

// NewSignatureBatchVerifier creates a new SignatureBatchVerifier.
func NewSignatureBatchVerifier() *SignatureBatchVerifier {
	return &SignatureBatchVerifier{
		pubKeys:    make([]*crypto.PublicKey, 0),
		messages:   make([][]byte, 0),
		signatures: make([][]byte, 0),
	}
}

// Add adds a signature to verify.
func (sbv *SignatureBatchVerifier) Add(pubKey *crypto.PublicKey, msg, sig []byte) {
	sbv.pubKeys = append(sbv.pubKeys, pubKey)
	sbv.messages = append(sbv.messages, msg)
	sbv.signatures = append(sbv.signatures, sig)
}

// Verify verifies all signatures and returns results for each.
func (sbv *SignatureBatchVerifier) Verify() []bool {
	results := make([]bool, len(sbv.pubKeys))

	for i := range sbv.pubKeys {
		if sbv.pubKeys[i] == nil || len(sbv.signatures[i]) != crypto.Dilithium3SignatureSize {
			results[i] = false
			continue
		}
		results[i] = crypto.Verify(sbv.pubKeys[i], sbv.messages[i], sbv.signatures[i])
	}

	return results
}

// Count returns the number of signatures to verify.
func (sbv *SignatureBatchVerifier) Count() int {
	return len(sbv.pubKeys)
}

// Clear clears all pending verifications.
func (sbv *SignatureBatchVerifier) Clear() {
	sbv.pubKeys = sbv.pubKeys[:0]
	sbv.messages = sbv.messages[:0]
	sbv.signatures = sbv.signatures[:0]
}
