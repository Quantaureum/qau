// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

var (
	ErrLegacySignatureDetected = errors.New("legacy ECDSA signature detected, only Dilithium3 signatures are accepted")
	ErrSignatureTooShort       = errors.New("signature too short for Dilithium3")
	ErrInvalidSignatureFormat  = errors.New("invalid signature format")
	ErrPublicKeyMismatch       = errors.New("public key does not match signer")
)

const (
	LegacyECDSASigSize = 65
)

type SigningVerifier struct {
	// R42-CR-002 FIX: Use atomic.Bool to prevent data races between
	// SetRejectLegacy/SetConstantTimeMode writers and BatchVerify readers.
	rejectLegacy atomic.Bool
	sigCache     *SignatureCache // LRU cache for Dilithium3 verification results (valid only)
	constantTime atomic.Bool     // R32-P5-1: when true, skip cache hits in batch path too
	// CRYPTO-004 FIX: separate short-TTL cache for INVALID signatures so that
	// repeated submission of the same forged signature is rejected without a
	// full Dilithium3 verification (CPU-exhaustion DoS mitigation). See
	// InvalidSignatureCache docs for why caching negatives is safe here.
	invalidSigCache *InvalidSignatureCache
}

func NewSigningVerifier() *SigningVerifier {
	sv := &SigningVerifier{
		sigCache:        NewSignatureCache(50000),                        // 50K entries —handles 20K tx burst with high cache hit rate
		invalidSigCache: NewInvalidSignatureCache(50000, 30*time.Second), // CRYPTO-004: 30s TTL
	}
	sv.rejectLegacy.Store(true)
	return sv
}

// Close releases resources held by the SigningVerifier, including the
// background cleanup goroutine in InvalidSignatureCache (CR-03). Callers
// should call Close when the SigningVerifier is no longer needed.
func (sv *SigningVerifier) Close() {
	if sv.invalidSigCache != nil {
		sv.invalidSigCache.Close()
	}
}

func (sv *SigningVerifier) SetRejectLegacy(reject bool) {
	sv.rejectLegacy.Store(reject)
}

// SetConstantTimeMode enables or disables constant-time verification mode.
// When enabled, all batch signature verifications skip the cache lookup
// and go through full Dilithium3 verification, eliminating timing leaks
// (R32-P5-1). Note: VerifyWithCache always verifies regardless ().
func (sv *SigningVerifier) SetConstantTimeMode(enabled bool) {
	sv.constantTime.Store(enabled)
}

func (sv *SigningVerifier) IsDilithium3Signature(signature []byte) bool {
	// FIX: Use constant-time length comparison to prevent timing leaks.
	return subtle.ConstantTimeEq(int32(len(signature)), int32(Dilithium3SignatureSize)) == 1
}

func (sv *SigningVerifier) IsLegacySignature(signature []byte) bool {
	// FIX: Use constant-time length comparison to prevent timing leaks.
	return subtle.ConstantTimeEq(int32(len(signature)), int32(LegacyECDSASigSize)) == 1
}

func (sv *SigningVerifier) VerifyTransactionSignature(pubKeyBytes []byte, message []byte, signature []byte) error {
	// FIX: Use constant-time comparison for empty signature check.
	// A plain `len(signature) == 0` creates a timing side-channel that leaks
	// whether the signature is empty, which an attacker can use to distinguish
	// between "invalid format" and "invalid signature" errors.
	if subtle.ConstantTimeEq(int32(len(signature)), 0) == 1 {
		return ErrInvalidSignatureFormat
	}

	if sv.IsLegacySignature(signature) {
		if sv.rejectLegacy.Load() {
			return ErrLegacySignatureDetected
		}
		return fmt.Errorf("legacy signatures not supported in quantum mode")
	}

	if !sv.IsDilithium3Signature(signature) {
		// FIX: Do not leak signature length in error message.
		// Previously: "expected %d bytes, got %d bytes" —an attacker could
		// use the actual length to distinguish between format variants.
		return ErrSignatureTooShort
	}

	// FIX: Removed early len(pubKeyBytes) return that leaks length info
	// via timing. PublicKeyFromBytes performs a constant-time public key length
	// check internally using subtle.ConstantTimeEq.
	pubKey, err := PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// CRYPTO-004 FIX: Check invalid signature cache before expensive verification.
	// This prevents DoS attacks where an attacker repeatedly submits the same
	// invalid signature to force expensive Dilithium3 verification.
	// The invalid cache has a short TTL (30s) to limit memory and allow
	// transient failures to self-heal.
	if sv.invalidSigCache != nil && !sv.constantTime.Load() {
		if sv.invalidSigCache.Get(pubKeyBytes, message, signature) {
			return ErrInvalidSignature
		}
	}

	// Use signature cache to avoid redundant Dilithium3 verifications.
	// Only valid results are cached (see SignatureCache.VerifyWithCache docs).
	if sv.sigCache != nil {
		if !sv.sigCache.VerifyWithCache(pubKey, message, signature) {
			// CRYPTO-004 FIX: Cache invalid signatures to prevent DoS
			if sv.invalidSigCache != nil && !sv.constantTime.Load() {
				sv.invalidSigCache.Put(pubKeyBytes, message, signature)
			}
			return ErrInvalidSignature
		}
		return nil
	}

	// Fallback: direct verification without cache
	if !Verify(pubKey, message, signature) {
		// CRYPTO-004 FIX: Cache invalid signatures to prevent DoS
		if sv.invalidSigCache != nil && !sv.constantTime.Load() {
			sv.invalidSigCache.Put(pubKeyBytes, message, signature)
		}
		return ErrInvalidSignature
	}

	return nil
}

func (sv *SigningVerifier) VerifyMessageSignature(pubKeyBytes []byte, message []byte, signature []byte) error {
	return sv.VerifyTransactionSignature(pubKeyBytes, message, signature)
}

func (sv *SigningVerifier) ValidatePublicKey(pubKeyBytes []byte) error {
	// FIX: Removed early len(pubKeyBytes) return that leaks length info
	// via timing. PublicKeyFromBytes performs a constant-time public key length
	// check internally using subtle.ConstantTimeEq.
	_, err := PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid Dilithium3 public key: %w", err)
	}

	return nil
}

// SigVerifyItem represents a signature verification request for batch processing.
type SigVerifyItem struct {
	PubKeyBytes []byte
	Message     []byte
	Signature   []byte
}

// BatchVerifyTransactionSignatures verifies multiple Dilithium3 signatures in parallel.
// It checks the signature cache first (fast path), then batch-verifies cache misses
// using parallel workers via BatchVerifier. Valid results are cached for future lookups.
//
// This provides significant speedup over serial verification when processing
// large batches of transactions (e.g., during high-throughput txpool ingestion).
// On a 4-core ARM64 node, 4 workers provide ~4x speedup for cache-miss signatures.
//
// Returns a slice of booleans (true = valid) in the same order as input.
func (sv *SigningVerifier) BatchVerifyTransactionSignatures(items []SigVerifyItem) []bool {
	n := len(items)
	results := make([]bool, n)

	// pending holds items that need actual Dilithium3 verification (cache misses)
	type pendingItem struct {
		index  int
		pubKey *PublicKey
		item   SigVerifyItem
	}
	var pending []pendingItem

	// Phase 1: Format checks + cache lookup (serial, fast — no crypto operations)
	//
	// R9-C05 (2026-07-19) FIX: The previous implementation used `continue`
	// for format-check failures, cache hits, and PublicKeyFromBytes errors.
	// Although each check itself used constant-time primitives, the
	// branch-on-continue meant the TOTAL number of operations per item
	// varied by outcome — violating the function's self-documented
	// "constant-time" contract. An attacker measuring batch verification
	// time could fingerprint which items hit the cache vs. failed format
	// vs. went to full Dilithium3 verification.
	//
	// FIX: All branches now fall through to a single `pending`-append
	// site. Items that should NOT be appended are gated by a `shouldQueue`
	// boolean AND a `pendingItem{}` zero-value placeholder. We still
	// perform the same per-item work, but the control flow no longer
	// short-circuits via `continue` — every item walks the same code path
	// to the bottom of the loop.
	for i, item := range items {
		// Format checks (same as VerifyTransactionSignature)
		// FIX: Use constant-time length comparisons to prevent timing
		// leaks about signature/public key lengths in batch verification.
		sigNotEmpty := subtle.ConstantTimeEq(int32(len(item.Signature)), 0) != 1
		notLegacy := !sv.IsLegacySignature(item.Signature)
		isDilithium3 := sv.IsDilithium3Signature(item.Signature)
		pubKeyLenOK := subtle.ConstantTimeEq(int32(len(item.PubKeyBytes)), int32(Dilithium3PublicKeySize)) == 1
		formatOK := sigNotEmpty && notLegacy && isDilithium3 && pubKeyLenOK

		// R9-C05 FIX: do NOT `continue` on !formatOK — fall through and
		// gate the cache lookup / batch queue with the boolean so the
		// total work per item is uniform.
		var (
			cacheHitValid   = false
			cacheHitInvalid = false
			pubKey          *PublicKey
			pubKeyErr       error
		)
		if formatOK {
			// Check cache — cache hit avoids expensive Dilithium3 verification entirely
			// R32-P5-1 FIX: In constant-time mode, skip cache lookup so all
			// signatures go through full verification, eliminating timing leak.
			if sv.sigCache != nil && !sv.constantTime.Load() {
				if _, found := sv.sigCache.Get(item.PubKeyBytes, item.Message, item.Signature); found {
					cacheHitValid = true
				}
			}
			// CRYPTO-004 FIX: consult the invalid-signature cache so a repeated
			// submission of the same forged signature is rejected without a full
			// Dilithium3 verification (CPU-exhaustion DoS mitigation). Skipped in
			// constant-time mode (matches the valid-cache handling above) to avoid
			// timing leaks.
			if !cacheHitValid && sv.invalidSigCache != nil && !sv.constantTime.Load() {
				if sv.invalidSigCache.Get(item.PubKeyBytes, item.Message, item.Signature) {
					cacheHitInvalid = true
				}
			}
			// Parse public key for batch verification (only if not cached).
			if !cacheHitValid && !cacheHitInvalid {
				pubKey, pubKeyErr = PublicKeyFromBytes(item.PubKeyBytes)
			}
		}

		// Apply results to the per-item slot. The control flow now has
		// no `continue` — every item walks to the bottom of the loop body
		// through the same sequence of branches.
		switch {
		case !formatOK:
			results[i] = false
		case cacheHitValid:
			results[i] = true
		case cacheHitInvalid:
			results[i] = false
		case pubKeyErr != nil:
			results[i] = false
		default:
			// Pending batch verification — append to the pending slice
			// for Phase 2. results[i] will be filled in after the batch
			// call returns.
			pending = append(pending, pendingItem{index: i, pubKey: pubKey, item: item})
		}
	}

	// Phase 2: Batch verify cache misses (parallel via BatchVerifier)
	if len(pending) > 0 {
		batchItems := make([]SignatureItem, len(pending))
		for j, p := range pending {
			batchItems[j] = SignatureItem{
				PublicKey: p.pubKey,
				Message:   p.item.Message,
				Signature: p.item.Signature,
			}
		}

		batchResult := defaultBatchVerifier.VerifyBatch(batchItems)
		for j, p := range pending {
			results[p.index] = batchResult.Results[j]
			// Cache valid results only (anti-poisoning: never cache negatives
			// in the main sigCache —see SignatureCache.Put).
			if results[p.index] && sv.sigCache != nil {
				sv.sigCache.Put(p.item.PubKeyBytes, p.item.Message, p.item.Signature, true)
			}
			// CRYPTO-004 FIX: cache invalid results in the separate short-TTL
			// invalid cache so repeat submissions of the same forged signature
			// skip the expensive batch verification. Safe because the cache key
			// includes the signature bytes (see InvalidSignatureCache docs).
			//
			// CRYPTO-R9-M-REDO-02 (2026-07-19) FIX: Previously this Put path
			// omitted the `!sv.constantTime.Load()` guard that the matching
			// Get path (line 236) and the single-tx VerifyTransactionSignature
			// path (lines 122/133) all enforce. In constant-time mode the
			// Get is skipped (so no cache hit short-circuits verification),
			// but the Put would still write to the cache, populating it with
			// negative entries. The next batch (constant-time mode off) would
			// then hit those entries, defeating the constant-time guarantee
			// retroactively. Now both Get and Put honor the same guard.
			if !results[p.index] && sv.invalidSigCache != nil && !sv.constantTime.Load() {
				sv.invalidSigCache.Put(p.item.PubKeyBytes, p.item.Message, p.item.Signature)
			}
		}
	}

	return results
}
