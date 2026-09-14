// Quantaureum Node source, version 1.0.0.
package quantum

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	qaucrypto "github.com/quantaureum/qau/crypto"
)

var (
	ErrInsufficientSignatures = errors.New("insufficient signatures for aggregation")
	ErrInvalidSignature       = errors.New("invalid signature")
	ErrAggregationFailed      = errors.New("signature aggregation failed")
	// ErrTooManySignatures: the signature count exceeds the cap
	// R7-P3-2: Aggregate() lacked a maxSignatures cap, posing a resource-exhaustion DoS risk
	ErrTooManySignatures = errors.New("too many signatures for aggregation")
	// ErrChallengeGenerationFailed: the entropy source failed while generating a challenge
	// audit fix (CRITICAL-4): after removing the predictable fallback, an explicit error is required
	ErrChallengeGenerationFailed = errors.New("challenge generation failed: entropy source unavailable")
	// audit-fix L5-010: Duplicate signature detection
	ErrDuplicateSignature = errors.New("duplicate signature detected")
)

type AggregatedSignature struct {
	Signatures [][]byte
	PublicKeys [][]byte
	Message    []byte
	Aggregated []byte
	Bitmap     []byte
	Count      int
	Threshold  int
}

type QuantumSignatureAggregator struct {
	mu               sync.RWMutex
	minSignatures    int
	maxSignatures    int
	maxCacheSize     int
	aggregationCache map[string]*AggregatedSignature
	// L4-009: Track insertion order for FIFO cache eviction.
	cacheOrder []string
	// FIX: strict mode rejects empty public keys during aggregation.
	// Defaults to true. When false, empty public keys are allowed during
	// aggregation (but still rejected during VerifyAggregation per ).
	rejectEmptyPublicKeys bool
}

func NewQuantumSignatureAggregator(minSigs, maxSigs int) *QuantumSignatureAggregator {
	// R7-P3-2: Ensure a reasonable default maxSignatures to prevent DoS.
	// If the caller passes a non-positive value, default to 512.
	if maxSigs <= 0 {
		maxSigs = 512
	}
	return &QuantumSignatureAggregator{
		minSignatures:         minSigs,
		maxSignatures:         maxSigs,
		maxCacheSize:          1000,
		aggregationCache:      make(map[string]*AggregatedSignature),
		rejectEmptyPublicKeys: true,
	}
}

// SetStrictEmptyPublicKeys enables or disables strict mode for empty public keys.
// When enabled (default), Aggregate rejects empty public keys. When disabled,
// empty public keys are allowed during aggregation but still rejected during
// VerifyAggregation.
// FIX: Expose strict mode as a configurable parameter.
func (qsa *QuantumSignatureAggregator) SetStrictEmptyPublicKeys(enabled bool) {
	qsa.mu.Lock()
	defer qsa.mu.Unlock()
	qsa.rejectEmptyPublicKeys = enabled
}

func (qsa *QuantumSignatureAggregator) Aggregate(
	message []byte,
	signatures [][]byte,
	publicKeys [][]byte,
) (*AggregatedSignature, error) {
	// R7-P3-2: Enforce maxSignatures upper limit to prevent resource
	// exhaustion DoS. Without this check, a caller could pass an arbitrarily
	// large number of signatures, consuming unbounded memory and CPU.
	if len(signatures) > qsa.maxSignatures {
		return nil, fmt.Errorf("%w: %d exceeds maximum %d",
			ErrTooManySignatures, len(signatures), qsa.maxSignatures)
	}

	if len(signatures) < qsa.minSignatures {
		return nil, ErrInsufficientSignatures
	}

	if len(signatures) != len(publicKeys) {
		return nil, fmt.Errorf("signature and public key count mismatch: %d != %d",
			len(signatures), len(publicKeys))
	}

	// FIX: In strict mode (default), reject empty public keys during
	// aggregation. An empty public key means the corresponding signature
	// cannot be authenticated. Previously, empty keys were only rejected
	// during VerifyAggregation, allowing unauthenticated signatures to be
	// mixed into aggregates. Rejecting them at aggregation time provides
	// earlier and stronger protection.
	if qsa.rejectEmptyPublicKeys {
		for i, key := range publicKeys {
			if len(key) == 0 {
				return nil, fmt.Errorf("empty public key at index %d: strict mode rejects unauthenticated signatures", i)
			}
		}
	}

	// audit-fix L5-010: Deduplicate signatures to prevent an attacker from
	// passing N copies of the same signature to bypass minSignatures threshold.
	seen := make(map[string]struct{}, len(signatures))
	for _, sig := range signatures {
		key := string(sig)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("%w: duplicate signature detected", ErrDuplicateSignature)
		}
		seen[key] = struct{}{}
	}
	if len(seen) < qsa.minSignatures {
		return nil, fmt.Errorf("%w: after dedup only %d unique signatures, need %d",
			ErrInsufficientSignatures, len(seen), qsa.minSignatures)
	}

	msgHash := sha256.Sum256(message)

	// FIX: the cache key must include the hashes of the signatures and public keys. The original used only the message hash + signature count,
	// so two different signature sets aggregated over the same message with the same count made the second caller hit
	// the first caller's cache (with wrong signatures/keys). Binding each signature to its public key by index also prevents reordering attacks.
	sigHasher := sha256.New()
	// L16-019 FIX: Replaced fmt.Sprintf with strconv.Itoa to avoid string allocation in hot path.
	for i, sig := range signatures {
		sigHasher.Write([]byte("idx-" + strconv.Itoa(i) + "-"))
		sigHasher.Write(sig)
	}
	sigHash := sigHasher.Sum(nil)

	keyHasher := sha256.New()
	for i, key := range publicKeys {
		keyHasher.Write([]byte("idx-" + strconv.Itoa(i) + "-"))
		keyHasher.Write(key)
	}
	keyHash := keyHasher.Sum(nil)

	cacheKey := hex.EncodeToString(msgHash[:]) + "-" + hex.EncodeToString(sigHash) + "-" + hex.EncodeToString(keyHash) + "-" + strconv.Itoa(len(signatures))

	qsa.mu.RLock()
	if cached, exists := qsa.aggregationCache[cacheKey]; exists {
		qsa.mu.RUnlock()
		// R6-P2-1: Return a deep copy to prevent callers from mutating cached data.
		return copyAggregatedSignature(cached), nil
	}
	qsa.mu.RUnlock()

	// CRITICAL: Make defensive copies to prevent caller data exposure via slice reslicing
	sigCopy := make([][]byte, len(signatures))
	keyCopy := make([][]byte, len(publicKeys))
	for i := range signatures {
		sigCopy[i] = make([]byte, len(signatures[i]))
		copy(sigCopy[i], signatures[i])
		keyCopy[i] = make([]byte, len(publicKeys[i]))
		copy(keyCopy[i], publicKeys[i])
	}

	// CRITICAL: Make a copy of message to prevent caller modification exposure
	msgCopy := make([]byte, len(message))
	copy(msgCopy, message)

	bitmap := make([]byte, (len(signatures)+7)/8)
	for i := range sigCopy {
		bitmap[i/8] |= 1 << (i % 8)
	}

	aggregated := qsa.combineSignatures(sigCopy)

	agg := &AggregatedSignature{
		Signatures: sigCopy,
		PublicKeys: keyCopy,
		Message:    msgCopy,
		Aggregated: aggregated,
		Bitmap:     bitmap,
		Count:      len(sigCopy),
		Threshold:  qsa.minSignatures,
	}

	qsa.mu.Lock()
	if len(qsa.aggregationCache) >= qsa.maxCacheSize {
		// L4-009 FIX: Evict only the oldest entry (FIFO) instead of clearing
		// the entire cache. Preserves hot entries and avoids cache stampede.
		if len(qsa.cacheOrder) > 0 {
			oldestKey := qsa.cacheOrder[0]
			qsa.cacheOrder = qsa.cacheOrder[1:]
			if v, ok := qsa.aggregationCache[oldestKey]; ok {
				// CRITICAL: Zeroize sensitive data before cache eviction
				for i := range v.Signatures {
					for j := range v.Signatures[i] {
						v.Signatures[i][j] = 0
					}
				}
				for i := range v.PublicKeys {
					for j := range v.PublicKeys[i] {
						v.PublicKeys[i][j] = 0
					}
				}
				for i := range v.Aggregated {
					v.Aggregated[i] = 0
				}
				delete(qsa.aggregationCache, oldestKey)
			}
		}
	}
	qsa.aggregationCache[cacheKey] = agg
	qsa.cacheOrder = append(qsa.cacheOrder, cacheKey)
	qsa.mu.Unlock()

	return agg, nil
}

// copyAggregatedSignature returns a deep copy of an AggregatedSignature so that
// cached entries cannot be mutated by callers receiving the returned pointer.
// R6-P2-1: Aggregate previously returned the internal *AggregatedSignature
// pointer on cache hit, allowing callers to modify cached Signatures,
// PublicKeys, Message, and Aggregated fields.
func copyAggregatedSignature(agg *AggregatedSignature) *AggregatedSignature {
	if agg == nil {
		return nil
	}
	cp := &AggregatedSignature{
		Count:     agg.Count,
		Threshold: agg.Threshold,
	}
	// Deep copy Signatures
	cp.Signatures = make([][]byte, len(agg.Signatures))
	for i, sig := range agg.Signatures {
		cp.Signatures[i] = make([]byte, len(sig))
		copy(cp.Signatures[i], sig)
	}
	// Deep copy PublicKeys
	cp.PublicKeys = make([][]byte, len(agg.PublicKeys))
	for i, key := range agg.PublicKeys {
		cp.PublicKeys[i] = make([]byte, len(key))
		copy(cp.PublicKeys[i], key)
	}
	// Deep copy Message
	cp.Message = make([]byte, len(agg.Message))
	copy(cp.Message, agg.Message)
	// Deep copy Aggregated
	cp.Aggregated = make([]byte, len(agg.Aggregated))
	copy(cp.Aggregated, agg.Aggregated)
	// Deep copy Bitmap
	cp.Bitmap = make([]byte, len(agg.Bitmap))
	copy(cp.Bitmap, agg.Bitmap)
	return cp
}

func (qsa *QuantumSignatureAggregator) combineSignatures(signatures [][]byte) []byte {
	// audit-fix CRITICAL-1: Use HMAC-SHA256 with domain separation instead of simple SHA256.
	// FIX: Correct misleading comment. The HMAC key "QUANTAUREUM_AGG_V1" is
	// a FIXED domain-separation string, NOT a secret key. This means:
	//   - It provides domain separation (prevents cross-protocol signature confusion)
	//   - It does NOT prevent forgery by parties who don't possess all signatures,
	//     because the "key" is publicly known.
	//   - Actual forgery prevention comes from VerifyAggregation() which individually
	//     verifies each Dilithium3 signature against its public key (line 306+).
	// The HMAC here serves as a collision-resistant binding mechanism, not a MAC.
	h := hmac.New(sha256.New, []byte("QUANTAUREUM_AGG_V1"))
	h.Write([]byte("sigcount-" + strconv.Itoa(len(signatures))))
	for i, sig := range signatures {
		// Bind each signature to its index to prevent reordering attacks
		h.Write([]byte("idx-" + strconv.Itoa(i) + "-"))
		h.Write(sig)
	}
	return h.Sum(nil)
}

func (qsa *QuantumSignatureAggregator) VerifyAggregation(agg *AggregatedSignature) bool {
	if agg == nil {
		return false
	}

	// R8-P3 FIX: Limit the number of signatures to prevent CPU DoS.
	// Without this check, a malicious caller could pass an AggregatedSignature
	// with a huge number of signatures, causing excessive CPU consumption
	// during combineSignatures and individual verification.
	if len(agg.Signatures) > qsa.maxSignatures {
		return false
	}

	if agg.Count < agg.Threshold {
		return false
	}

	// QUANT-AGG-01 FIX (deep-audit 2026-07-12): bind the self-reported Count to
	// the actual signature set. Count and Threshold are attacker-settable struct
	// fields and the HMAC binding below covers len(agg.Signatures), not Count, so
	// without this an aggregate can claim (e.g.) Count=100 while carrying a single
	// valid signature — fooling any consumer that trusts Count for quorum.
	if agg.Count != len(agg.Signatures) {
		return false
	}

	expected := qsa.combineSignatures(agg.Signatures)
	if len(expected) != len(agg.Aggregated) {
		return false
	}

	if subtle.ConstantTimeCompare(expected, agg.Aggregated) != 1 {
		return false
	}

	// R4-P2-2: Verify each individual Dilithium3 signature against its public key.
	// Previously only the aggregated field binding was checked, never the
	// individual signatures. A malicious party could include an invalid signature
	// that passes the aggregation check. Now each signature is cryptographically
	// verified. Non-standard sizes are REJECTED (not silently skipped) to prevent
	// forged signatures from bypassing individual verification while passing HMAC.
	if len(agg.Signatures) != len(agg.PublicKeys) {
		return false
	}
	// AUDIT (2026) R4-CRND-03 FIX: Reject duplicate public keys.
	// Without this check, an attacker could submit the same (pubKey, sig)
	// pair multiple times to inflate the Count field, making the aggregation
	// appear to have more signers than it actually does. This could be used
	// to fake a quorum (e.g., Count=100 with only 1 unique signer).
	// Production consensus uses consensus/bls.go which already deduplicates;
	// this fix hardens the quantum library path used in tests and future paths.
	seenPubKeys := make(map[string]struct{}, len(agg.PublicKeys))
	for i, sig := range agg.Signatures {
		pubKeyBytes := agg.PublicKeys[i]
		//  SECURITY FIX: Return false when no public key is provided.
		// Previously, empty public keys caused verification to be silently skipped,
		// allowing invalid signatures to be mixed into aggregates without
		// cryptographic verification. An empty public key means the signature
		// cannot be authenticated, so the entire aggregation must fail.
		if len(pubKeyBytes) == 0 {
			return false
		}
		// Reject non-standard sizes: a valid Dilithium3 public key is exactly
		// 1952 bytes and a valid signature is exactly 3293 bytes.
		if len(pubKeyBytes) != qaucrypto.Dilithium3PublicKeySize || len(sig) != qaucrypto.Dilithium3SignatureSize {
			return false
		}
		// R4-CRND-03: Reject duplicate public keys.
		pubKeyHex := hex.EncodeToString(pubKeyBytes)
		if _, exists := seenPubKeys[pubKeyHex]; exists {
			return false
		}
		seenPubKeys[pubKeyHex] = struct{}{}

		pubKey, err := qaucrypto.PublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			return false
		}
		if !qaucrypto.Verify(pubKey, agg.Message, sig) {
			return false
		}
	}

	return true
}

func (qsa *QuantumSignatureAggregator) MergeAggregations(a, b *AggregatedSignature) (*AggregatedSignature, error) {
	if a == nil || b == nil {
		return nil, ErrAggregationFailed
	}

	// SECURITY FIX (P2-2): Verify that both aggregations are for the same
	// message before merging. Merging signatures over different messages
	// would produce an invalid aggregated signature.
	if !bytes.Equal(a.Message, b.Message) {
		return nil, ErrAggregationFailed
	}

	totalSigs := a.Count + b.Count
	if totalSigs > qsa.maxSignatures {
		return nil, fmt.Errorf("merged count %d exceeds max %d", totalSigs, qsa.maxSignatures)
	}

	mergedSigs := make([][]byte, 0, totalSigs)
	mergedSigs = append(mergedSigs, a.Signatures...)
	mergedSigs = append(mergedSigs, b.Signatures...)

	mergedKeys := make([][]byte, 0, totalSigs)
	mergedKeys = append(mergedKeys, a.PublicKeys...)
	mergedKeys = append(mergedKeys, b.PublicKeys...)

	return qsa.Aggregate(a.Message, mergedSigs, mergedKeys)
}

type ThresholdSignatureScheme struct {
	mu               sync.RWMutex
	totalShares      int
	threshold        int
	shares           map[int][]byte
	verificationKeys map[int][]byte
}

func NewThresholdSignatureScheme(totalShares, threshold int) *ThresholdSignatureScheme {
	return &ThresholdSignatureScheme{
		totalShares:      totalShares,
		threshold:        threshold,
		shares:           make(map[int][]byte),
		verificationKeys: make(map[int][]byte),
	}
}

func (tss *ThresholdSignatureScheme) AddShare(index int, share []byte, verificationKey []byte) error {
	tss.mu.Lock()
	defer tss.mu.Unlock()

	if index < 0 || index >= tss.totalShares {
		return fmt.Errorf("invalid share index: %d", index)
	}

	// CRITICAL: Zeroize old share before replacing to prevent memory leakage
	if existing, ok := tss.shares[index]; ok {
		for i := range existing {
			existing[i] = 0
		}
	}

	// R3-P2-1: Deep-copy share and verificationKey before storing to prevent
	// the caller from mutating already-stored data via the original slice reference.
	shareCopy := make([]byte, len(share))
	copy(shareCopy, share)
	vkCopy := make([]byte, len(verificationKey))
	copy(vkCopy, verificationKey)
	tss.shares[index] = shareCopy
	tss.verificationKeys[index] = vkCopy
	return nil
}

// ZeroizeShare securely clears a share from memory
func (tss *ThresholdSignatureScheme) ZeroizeShare(index int) {
	tss.mu.Lock()
	defer tss.mu.Unlock()

	if existing, ok := tss.shares[index]; ok {
		for i := range existing {
			existing[i] = 0
		}
		delete(tss.shares, index)
	}
	delete(tss.verificationKeys, index)
}

func (tss *ThresholdSignatureScheme) CombineShares(message []byte) ([]byte, error) {
	tss.mu.RLock()
	defer tss.mu.RUnlock()

	if len(tss.shares) < tss.threshold {
		return nil, fmt.Errorf("insufficient shares: %d < %d", len(tss.shares), tss.threshold)
	}

	// R3-P2-2: Verify each individual share against its verificationKey before
	// combining. The verificationKeys field was stored but never used, allowing
	// a malicious share to pollute the combined result. Now each share is
	// cryptographically verified. Non-standard sizes are REJECTED (not silently
	// skipped) to prevent forged shares from bypassing individual verification
	// while polluting the combined result.
	for idx, share := range tss.shares {
		vk, hasVK := tss.verificationKeys[idx]
		//  SECURITY FIX: Return an error when verificationKey is missing
		// or empty. Previously, missing verification keys caused share verification
		// to be silently skipped, allowing untrusted shares to pollute the combined
		// result. An empty verification key means the share cannot be authenticated.
		if !hasVK || len(vk) == 0 {
			return nil, fmt.Errorf("share %d: missing or empty verification key; cannot verify share", idx)
		}
		// Reject non-standard sizes: a valid Dilithium3 public key is exactly
		// 1952 bytes and a valid share/signature is exactly 3293 bytes.
		if len(vk) != qaucrypto.Dilithium3PublicKeySize || len(share) != qaucrypto.Dilithium3SignatureSize {
			return nil, fmt.Errorf("share %d: non-standard verification key size %d or share size %d", idx, len(vk), len(share))
		}
		pubKey, err := qaucrypto.PublicKeyFromBytes(vk)
		if err != nil {
			return nil, fmt.Errorf("share %d: invalid verification key: %w", idx, err)
		}
		if !qaucrypto.Verify(pubKey, message, share) {
			return nil, fmt.Errorf("share %d: verification failed", idx)
		}
	}

	// audit-fix HIGH-4: Use HMAC with message-bound key instead of simple SHA256.
	// This binds the combined signature to the message and prevents share substitution attacks.
	//
	// L11-032 SECURITY RATIONALE (non-standard key usage):
	// Using the (public) message as the HMAC key is non-standard — HMAC keys are
	// normally secret. Here the HMAC is NOT used as a signature primitive; it is
	// only a deterministic aggregation/binding function. Its security goals are:
	//   1. Message binding: the aggregate digest is bound to the exact message
	//      being signed, so shares collected for one message cannot be replayed
	//      to produce a valid aggregate for a different message.
	//   2. Share ordering/integrity: the sorted shares and their indices are
	//      folded into the digest, so an attacker cannot reorder or substitute
	//      shares without changing the output.
	// Confidentiality is not a goal here because the message is already public,
	// and forgery is already prevented by the per-share Dilithium3 verification
	// performed above (line Verify(pubKey, message, share)). The HMAC merely
	// makes the aggregation tamper-evident and message-bound; it is not the
	// cryptographic signature itself.
	h := hmac.New(sha256.New, message)
	h.Write([]byte("threshold-" + strconv.Itoa(tss.threshold) + "-sharecount-" + strconv.Itoa(len(tss.shares))))

	indices := make([]int, 0, len(tss.shares))
	for idx := range tss.shares {
		indices = append(indices, idx)
	}

	// L18-031 FIX: Use sort.Ints instead of O(n^2) bubble sort
	sort.Ints(indices)

	for _, idx := range indices {
		h.Write([]byte("share-" + strconv.Itoa(idx) + "-"))
		h.Write(tss.shares[idx])
	}

	return h.Sum(nil), nil
}

func (tss *ThresholdSignatureScheme) ShareCount() int {
	tss.mu.RLock()
	defer tss.mu.RUnlock()
	return len(tss.shares)
}

func (tss *ThresholdSignatureScheme) HasThreshold() bool {
	tss.mu.RLock()
	defer tss.mu.RUnlock()
	return len(tss.shares) >= tss.threshold
}

type QuantumProofGenerator struct {
	mu             sync.Mutex
	challenges     map[string][]byte
	responses      map[string][]byte
	sessionSecrets map[string][]byte // per-session HMAC keys, never exposed
	// R39-P3 FIX: Track session creation time for TTL-based expiry.
	sessionCreated map[string]time.Time
}

func NewQuantumProofGenerator() *QuantumProofGenerator {
	return &QuantumProofGenerator{
		challenges:     make(map[string][]byte),
		responses:      make(map[string][]byte),
		sessionSecrets: make(map[string][]byte),
		sessionCreated: make(map[string]time.Time),
	}
}

// GenerateChallenge generates a random challenge for the given session
// audit fix (CRITICAL-4): the predictable fallback (byte(i ^ 0xAA)) is removed; rand.Read failure returns an error
// audit fix (CRITICAL-1): also generate the session secret used for HMAC verification in VerifyResponse
// sessionSecret stays inside qpg and is never exposed, so a prover cannot forge a valid response without it
func (qpg *QuantumProofGenerator) GenerateChallenge(sessionID string) ([]byte, error) {
	qpg.mu.Lock()
	defer qpg.mu.Unlock()

	// R39-P3 FIX: Evict expired sessions before creating a new one.
	qpg.evictExpiredSessionsLocked()

	challenge := make([]byte, 32)
	// security fix: on rand.Read failure, return an error instead of a predictable fallback
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChallengeGenerationFailed, err)
	}

	// generate the session key for HMAC verification (never shown to the prover)
	sessionSecret := make([]byte, 32)
	if _, err := rand.Read(sessionSecret); err != nil {
		// clean up the already-generated challenge
		for i := range challenge {
			challenge[i] = 0
		}
		return nil, fmt.Errorf("%w: failed to generate session secret: %v", ErrChallengeGenerationFailed, err)
	}

	qpg.challenges[sessionID] = challenge
	// R39-P3 FIX: Zero the old sessionSecret before overwriting, if it exists.
	if oldSecret, exists := qpg.sessionSecrets[sessionID]; exists {
		for i := range oldSecret {
			oldSecret[i] = 0
		}
	}
	qpg.sessionSecrets[sessionID] = sessionSecret
	// R39-P3 FIX: Record creation time for TTL-based expiry.
	qpg.sessionCreated[sessionID] = time.Now()
	return challenge, nil
}

// R39-P3 FIX: evictExpiredSessionsLocked removes sessions older than 30 minutes.
// Must be called with qpg.mu held.
func (qpg *QuantumProofGenerator) evictExpiredSessionsLocked() {
	const sessionTTL = 30 * time.Minute
	now := time.Now()
	for sid, created := range qpg.sessionCreated {
		if now.Sub(created) > sessionTTL {
			if secret, ok := qpg.sessionSecrets[sid]; ok {
				for i := range secret {
					secret[i] = 0
				}
				delete(qpg.sessionSecrets, sid)
			}
			delete(qpg.challenges, sid)
			delete(qpg.responses, sid)
			delete(qpg.sessionCreated, sid)
		}
	}
}

// VerifyResponse verifies the prover's response to the challenge
// audit fix (CRITICAL-1): the original only verified SHA256(challenge) == response[:32],
// but the challenge is public, so anyone could forge a response.
// The fix verifies response[:32] == HMAC(sessionSecret, challenge),
// where sessionSecret is generated in GenerateChallenge and kept inside qpg, never revealed to the prover.
// Only entities knowing sessionSecret (qpg itself or its authorized parties) can produce a valid response.
func (qpg *QuantumProofGenerator) VerifyResponse(sessionID string, response []byte) bool {
	qpg.mu.Lock()
	defer qpg.mu.Unlock()

	challenge, exists := qpg.challenges[sessionID]
	if !exists {
		return false
	}

	sessionSecret, secretExists := qpg.sessionSecrets[sessionID]
	if !secretExists {
		return false
	}

	if len(response) < 32 {
		return false
	}

	// compute the expected response as HMAC-SHA256(sessionSecret, challenge)
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write(challenge)
	expected := mac.Sum(nil)

	// constant-time comparison, preventing timing side channels
	if subtle.ConstantTimeCompare(response[:32], expected) != 1 {
		return false
	}

	qpg.responses[sessionID] = response
	return true
}

// ComputeResponse computes the valid HMAC response for a challenge in the given
// session. This allows external callers (other packages) to produce valid
// responses for VerifyResponse without exposing the internal sessionSecret.
// R4-P2-1: VerifyResponse used an internally generated sessionSecret as the HMAC
// key, but no method was provided for external callers to compute a valid
// response, making the API unusable from outside the package.
func (qpg *QuantumProofGenerator) ComputeResponse(sessionID string) ([]byte, error) {
	qpg.mu.Lock()
	defer qpg.mu.Unlock()

	challenge, exists := qpg.challenges[sessionID]
	if !exists {
		return nil, fmt.Errorf("challenge not found for session: %s", sessionID)
	}
	sessionSecret, secretExists := qpg.sessionSecrets[sessionID]
	if !secretExists {
		return nil, fmt.Errorf("session secret not found for session: %s", sessionID)
	}
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write(challenge)
	// N19-007 FIX: Changed from 64 bytes to 32 bytes. The previous code
	// allocated 64 bytes but only filled the first 32 with the HMAC output,
	// leaving the remaining 32 bytes as unused zero padding. VerifyResponse
	// only checks response[:32], so 32 bytes is sufficient. Using mac.Sum(nil)
	// returns exactly the 32-byte HMAC output without wasted allocation.
	response := mac.Sum(nil)
	return response, nil
}

// ClearSession securely zeroizes and removes challenge/response for a session
func (qpg *QuantumProofGenerator) ClearSession(sessionID string) {
	qpg.mu.Lock()
	defer qpg.mu.Unlock()

	if challenge, ok := qpg.challenges[sessionID]; ok {
		for i := range challenge {
			challenge[i] = 0
		}
		delete(qpg.challenges, sessionID)
	}
	if response, ok := qpg.responses[sessionID]; ok {
		for i := range response {
			response[i] = 0
		}
		delete(qpg.responses, sessionID)
	}
	// audit fix (CRITICAL-1): wipe the session key
	if secret, ok := qpg.sessionSecrets[sessionID]; ok {
		for i := range secret {
			secret[i] = 0
		}
		delete(qpg.sessionSecrets, sessionID)
	}
}
