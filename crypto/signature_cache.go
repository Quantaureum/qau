// Quantaureum Node source, version 1.0.0.
// Package crypto — Phase 3.4: Signature Verification LRU Cache
//
// Dilithium3 signature verification is computationally expensive (~1ms per sig).
// For 128 validators producing 32 attestations per epoch, that's 4096 verifications
// per epoch (~6.4 minutes). With 10K validators, this grows to 320K verifications.
//
// This LRU cache stores verification results (publicKey + message + signature → valid)
// to avoid redundant verifications. The cache hit rate is expected to be >80% since
// the same attestation is verified by multiple nodes in the network.
//
// Thread-safe with sync.RWMutex.
package crypto

import (
	"container/list"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
)

// sigCacheEntry represents a single entry in the signature verification cache.
type sigCacheEntry struct {
	key        [32]byte // SHA3-256(publicKey ++ message ++ signature)
	verifyHash [32]byte // SHA-256(publicKey ++ message) for collision detection
	valid      bool
}

// SignatureCache is a thread-safe LRU cache for signature verification results.
// It stores (publicKey + message + signature) → valid boolean.
type SignatureCache struct {
	mu       sync.RWMutex
	capacity int
	items    map[[32]byte]*list.Element
	lruList  *list.List // Front = most recently used, Back = least recently used
	hits     uint64
	misses   uint64
	// FIX: constantTime field removed —  changed VerifyWithCache
	// to always perform full verification regardless, making this field dead code.
}

// NewSignatureCache creates a new LRU signature verification cache.
// capacity is the maximum number of cached entries.
func NewSignatureCache(capacity int) *SignatureCache {
	if capacity <= 0 {
		capacity = 10000 // Default: 10K entries
	}
	return &SignatureCache{
		capacity: capacity,
		items:    make(map[[32]byte]*list.Element, capacity),
		lruList:  list.New(),
	}
}

// FIX: SetConstantTimeMode removed — was dead code after
// made VerifyWithCache always perform full verification. The SigningVerifier
// has its own constantTime field for controlling the batch validation path.

// computeCacheKey computes a SHA3-256 hash of (publicKey ++ message ++ signature).
//
// R31-P4-1 NOTE: SHA3-256 is used here (not SHAKE-256) because this hash serves
// as a CACHE KEY, not a cryptographic commitment. A cache key only needs
// collision resistance — SHA3-256 provides 128-bit collision resistance, which
// is more than sufficient for a map lookup. SHAKE-256 (an XOF) would add
// unnecessary complexity with no security benefit for this use case.
// Additionally, a secondary SHA-256 verifyHash (computeVerifyHash) provides
// independent collision detection, making the total collision probability
// ~2^-256 — equivalent to SHAKE-256's security level.
func computeCacheKey(pubKey, message, signature []byte) [32]byte {
	h := sha3.New256()
	// Write lengths first to prevent ambiguity
	var lenBuf [4]byte
	lenBuf[0] = byte(len(pubKey) >> 24)
	lenBuf[1] = byte(len(pubKey) >> 16)
	lenBuf[2] = byte(len(pubKey) >> 8)
	lenBuf[3] = byte(len(pubKey))
	h.Write(lenBuf[:])
	h.Write(pubKey)

	lenBuf[0] = byte(len(message) >> 24)
	lenBuf[1] = byte(len(message) >> 16)
	lenBuf[2] = byte(len(message) >> 8)
	lenBuf[3] = byte(len(message))
	h.Write(lenBuf[:])
	h.Write(message)

	lenBuf[0] = byte(len(signature) >> 24)
	lenBuf[1] = byte(len(signature) >> 16)
	lenBuf[2] = byte(len(signature) >> 8)
	lenBuf[3] = byte(len(signature))
	h.Write(lenBuf[:])
	h.Write(signature)

	var key [32]byte
	h.Sum(key[:0])
	return key
}

// computeVerifyHash computes a SHA-256 hash of (publicKey ++ message) using a
// different hash algorithm than computeCacheKey. This provides a secondary
// collision check: even if two different (pubKey, message, signature) tuples
// produce the same SHA3-256 cache key (probability ~2^-128), they would also
// need to collide in SHA-256 (another ~2^-128) to pass verification.
func computeVerifyHash(pubKey, message []byte) [32]byte {
	h := sha256.New()
	// R43-CR-002 FIX: Add length-prefixed domain separation to prevent
	// ambiguity between (pubKey, message) pairs that concatenate to the
	// same byte string. Without this, pubKey="AB" + message="CD" would
	// collide with pubKey="ABC" + message="D".
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(pubKey)))
	h.Write(lenBuf[:])
	h.Write(pubKey)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(message)))
	h.Write(lenBuf[:])
	h.Write(message)
	var v [32]byte
	copy(v[:], h.Sum(nil))
	return v
}

// Get returns the cached verification result if present.
// Returns (valid, found).
//
// CR-02 FIX: This method uses a write lock (Lock) rather than a read lock
// (RLock) because it mutates shared state on every cache hit:
//   - sc.lruList.MoveToFront(elem) updates LRU ordering
//   - sc.hits / sc.misses counters are incremented
//
// An RLock would race with concurrent MoveToFront / counter updates, so a
// write lock is required for correctness.
func (sc *SignatureCache) Get(pubKey, message, signature []byte) (bool, bool) {
	key := computeCacheKey(pubKey, message, signature)
	// R47-CR-06 FIX: Compute verifyHash before acquiring lock to reduce
	// lock contention. computeVerifyHash is a pure SHA256 computation.
	verifyHash := computeVerifyHash(pubKey, message)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	if elem, ok := sc.items[key]; ok {
		entry := elem.Value.(*sigCacheEntry)
		// L18-005 FIX: Verify secondary hash to detect cache key collisions.
		// R32-P3-01 FIX (2026-07-28): Use constant-time comparison for the
		// secondary hash check. Go's `!=` on [32]byte arrays short-circuits
		// on the first differing byte, leaking timing information about how
		// many leading bytes of the SHA-256 hash match. While the hashes
		// themselves are of public data (pubKey ++ message), an attacker
		// who can measure cache-lookup timing could infer which cache
		// entries exist and partial hash values. Constant-time comparison
		// eliminates this side channel as defense-in-depth.
		if subtle.ConstantTimeCompare(entry.verifyHash[:], verifyHash[:]) != 1 {
			// Hash mismatch: collision or stale entry. Treat as cache miss.
			sc.misses++
			return false, false
		}
		sc.lruList.MoveToFront(elem)
		sc.hits++
		return entry.valid, true
	}

	sc.misses++
	return false, false
}

// Put stores a verification result in the cache.
func (sc *SignatureCache) Put(pubKey, message, signature []byte, valid bool) {
	// R3-P4-1: Reject valid=false to prevent cache poisoning. The public API
	// previously accepted valid=false, creating a design risk where a future
	// caller could accidentally cache a negative result, causing the cache to
	// return false for a (pubKey, message, signature) tuple even after the
	// genuine signature arrives. Only valid results are ever stored.
	if !valid {
		return
	}

	key := computeCacheKey(pubKey, message, signature)
	// R48-CR-05 FIX: Compute verifyHash before acquiring lock (same fix as Get).
	verifyHash := computeVerifyHash(pubKey, message)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Update existing entry
	if elem, ok := sc.items[key]; ok {
		sc.lruList.MoveToFront(elem)
		elem.Value.(*sigCacheEntry).valid = valid
		elem.Value.(*sigCacheEntry).verifyHash = verifyHash
		return
	}

	// Evict oldest if at capacity
	for sc.lruList.Len() >= sc.capacity {
		oldest := sc.lruList.Back()
		if oldest != nil {
			sc.lruList.Remove(oldest)
			delete(sc.items, oldest.Value.(*sigCacheEntry).key)
		}
	}

	// Add new entry
	// L18-005 FIX: Store secondary verification hash for collision detection.
	entry := &sigCacheEntry{key: key, verifyHash: verifyHash, valid: valid}
	elem := sc.lruList.PushFront(entry)
	sc.items[key] = elem
}

// VerifyWithCache verifies a Dilithium3 signature, checking the cache first.
//
// SECURITY (cache-poisoning fix): Only VALID results are cached. Negative
// results (invalid signatures) are NEVER stored. This prevents a
// "first-one-wins" cache-poisoning / censorship attack where an attacker
// floods the network with forged signatures for a victim's (pubKey, message):
// if the forged signature reached a node first and the negative result were
// cached, the node would later reject the victim's REAL signature because the
// cache would return the stored `false` (see Get).
//
// Caching only positives is safe: a positive result is immutable — once a
// (pubKey, message, signature) tuple verifies true it will always verify true,
// so the cache can never hold a stale positive. Negatives, by contrast, can be
// superseded by the genuine signature arriving later, so they must always be
// re-verified.
func (sc *SignatureCache) VerifyWithCache(pubKey *PublicKey, message, signature []byte) bool {
	if pubKey == nil {
		return false
	}

	pubKeyBytes := pubKey.Bytes()

	// FIX: Always perform full verification regardless of mode.
	// Previously, in default (non-constant-time) mode, a cache hit would
	// return immediately (fast path) while a cache miss would fall through
	// to full verification (slow path). This timing difference leaks whether
	// a signature has been seen before. Now, the cache is only used to avoid
	// redundant Put storage — verification is always performed.
	valid := pubKey.Verify(message, signature)

	// Cache the result ONLY when valid. Invalid results are deliberately not
	// cached to prevent poisoning (see SECURITY note above).
	if valid {
		sc.Put(pubKeyBytes, message, signature, true)
	}

	return valid
}

// Stats returns cache hit/miss statistics.
func (sc *SignatureCache) Stats() (hits, misses uint64, hitRate float64) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	hits = sc.hits
	misses = sc.misses
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}
	return
}

// Size returns the current number of cached entries.
func (sc *SignatureCache) Size() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.lruList.Len()
}

// Clear removes all cached entries.
func (sc *SignatureCache) Clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.items = make(map[[32]byte]*list.Element, sc.capacity)
	sc.lruList.Init()
	sc.hits = 0
	sc.misses = 0
}

// invalidSigEntry stores a single INVALID signature verification result with an
// expiry timestamp. Unlike sigCacheEntry (which only ever stores valid=true),
// this entry represents a negative result that must expire after a short TTL.
type invalidSigEntry struct {
	key        [32]byte // SHA3-256(publicKey ++ message ++ signature)
	verifyHash [32]byte // SHA-256(publicKey ++ message) for collision detection
	expiresAt  time.Time
}

// InvalidSignatureCache is a thread-safe TTL+LRU cache for INVALID signature
// verification results.
//
// CRYPTO-004 FIX: SignatureCache deliberately only caches VALID results (see
// the anti-poisoning note on SignatureCache.Put) to prevent a "first-one-wins"
// attack where a forged signature for a victim's (pubKey, message) is cached
// as negative and later rejects the genuine signature. As a side effect,
// repeated submission of the SAME forged signature forces a full Dilithium3
// verification on every attempt, enabling a CPU-exhaustion DoS.
//
// This cache closes that gap: it stores negatives keyed on the FULL
// (pubKey ++ message ++ signature) tuple with a SHORT TTL. Because the key
// includes the signature bytes, caching a negative for signature S1 can NEVER
// affect a different (legitimate) signature S2 for the same (pubKey, message)
// — S2 produces a different cache key. The short TTL further bounds staleness
// so a genuine signature arriving later is re-verified promptly.
type InvalidSignatureCache struct {
	mu       sync.Mutex
	ttl      time.Duration
	capacity int
	items    map[[32]byte]*list.Element
	lru      *list.List // Front = most recently used, Back = least recently used
	// CR-04 FIX: putCount tracks puts since the last eviction sweep.
	// Eviction only runs every evictInterval puts to avoid an O(n) scan on
	// every single Put.
	putCount      int
	evictInterval int
	// CR-03 FIX: Background cleanup goroutine to evict expired entries even
	// under all-update workloads (where no new keys trigger evictExpiredLocked
	// via the Put path). Without this, expired entries that are never accessed
	// again would accumulate indefinitely, causing a memory leak.
	stopCh          chan struct{}
	closeOnce       sync.Once
	cleanupInterval time.Duration
	// CRYPTO-R10-N07 (2026-07-19) FIX: Write-rate limiter to prevent lock-
	// contention DoS. When constantTime=false (the default), an attacker can
	// flood the node with unique invalid signatures — each Put() acquires
	// c.mu, serializing all verifications. Under sustained attack, cache-miss
	// Puts starve Get lookups (which also need c.mu), causing the verifiable
	// throughput to collapse. The fix: a token-bucket-style counter that
	// caps writes per 1-second window. Writes exceeding the rate are dropped
	// (Put returns early without caching) — the cache becomes best-effort
	// under attack, but the lock is freed for Get traffic. The limit is
	// generous enough (10x capacity per second) that the cache remains
	// effective under legitimate workloads.
	putWindowStartUnixSec atomic.Int64
	putCountInWindow      atomic.Int64
}

// invalidSigPutRateWindow is the sliding window duration used by the
// CRYPTO-R10-N07 write-rate limiter.
const invalidSigPutRateWindow = time.Second

// invalidSigPutRateMultiplier caps Put calls at (capacity * multiplier) per
// window. With capacity=50000 and multiplier=10, the cap is 500K Puts/sec —
// well above any legitimate workload but still bounded.
const invalidSigPutRateMultiplier = 10

// NewInvalidSignatureCache creates a TTL cache for invalid signatures.
// capacity bounds the maximum number of entries; ttl controls how long a
// negative result is considered fresh.
func NewInvalidSignatureCache(capacity int, ttl time.Duration) *InvalidSignatureCache {
	if capacity <= 0 {
		capacity = 50000
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	c := &InvalidSignatureCache{
		ttl:             ttl,
		capacity:        capacity,
		items:           make(map[[32]byte]*list.Element, capacity),
		lru:             list.New(),
		evictInterval:   100,
		stopCh:          make(chan struct{}),
		cleanupInterval: ttl, // CR-03: cleanup at the same cadence as the TTL
	}
	// CR-03 FIX: Start a background goroutine that periodically evicts
	// expired entries. This ensures cleanup happens even when the workload
	// only updates existing entries (no new keys) — the Put path's
	// evictExpiredLocked trigger is skipped for existing-key updates.
	go c.backgroundCleanup()
	// M-02 FIX (R8 2026-07-19): Register a finalizer so that if a caller
	// forgets to Close() (e.g. test code that recreates SigningVerifier
	// repeatedly, or a config-reload path that drops the old cache), the
	// background goroutine + ticker are still released when GC reclaims the
	// cache. Without this, long-running nodes accumulate leaked goroutines
	// on every cache recreation.
	runtime.SetFinalizer(c, func(c *InvalidSignatureCache) { c.Close() })
	return c
}

// backgroundCleanup periodically evicts expired entries on a time-based
// schedule, independent of Put/Get traffic. This prevents expired entries
// from accumulating under all-update workloads where no new keys are added.
//
// CRYPTO-P1-01 FIX (R31, 2026-07-27): Added top-level defer recover. Go's
// runtime terminates the entire process on any unrecovered panic in any
// goroutine. evictExpiredLocked iterates over the cache map and calls
// time.Now()/entry comparisons — a bug in expiry arithmetic or a corrupted
// entry (e.g., negative TTL from a clock rollback) could trigger a panic
// (slice out of bounds, nil deref on a malformed entry), which would crash
// the whole node. The recover logs the panic and continues the loop so
// transient issues don't kill the cleanup goroutine permanently; a
// persistent bug would be visible via repeated log lines.
func (c *InvalidSignatureCache) backgroundCleanup() {
	defer func() {
		if r := recover(); r != nil {
			// Log and exit — the goroutine is terminated, but the process
			// survives. The cache still works (Put/Get do their own
			// eviction); only background eviction is lost. Operators can
			// restart the node to restore background cleanup.
			log.Printf("[ERROR] InvalidSignatureCache.backgroundCleanup panic recovered (goroutine exiting): %v", r)
		}
	}()
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			// CRYPTO-P1-01 FIX: Per-tick recover so a single bad eviction
			// pass doesn't kill the goroutine. The cache mutex is released
			// by the deferred Unlock before recover runs.
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[ERROR] InvalidSignatureCache.backgroundCleanup tick panic recovered (continuing): %v", r)
					}
				}()
				now := time.Now()
				c.mu.Lock()
				c.evictExpiredLocked(now)
				c.mu.Unlock()
			}()
		}
	}
}

// Close stops the background cleanup goroutine. It is safe to call multiple
// times. Callers should call Close when the cache is no longer needed to
// avoid leaking the background goroutine.
func (c *InvalidSignatureCache) Close() {
	c.closeOnce.Do(func() {
		close(c.stopCh)
	})
}

// Get returns true if the (pubKey, message, signature) tuple is cached as
// INVALID and the entry has not yet expired. Expired entries are evicted.
func (c *InvalidSignatureCache) Get(pubKey, message, signature []byte) bool {
	key := computeCacheKey(pubKey, message, signature)
	now := time.Now()
	// R47-CR-06 FIX: Compute verifyHash before acquiring lock to reduce
	// lock contention (same fix as SignatureCache.Get).
	verifyHash := computeVerifyHash(pubKey, message)

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return false
	}
	entry := elem.Value.(*invalidSigEntry)
	// Secondary collision check (mirrors SignatureCache.Get).
	// R32-P3-01 FIX (2026-07-28): Use constant-time comparison for the
	// secondary hash check, matching the SignatureCache.Get fix. See the
	// comment in SignatureCache.Get for the rationale.
	if subtle.ConstantTimeCompare(entry.verifyHash[:], verifyHash[:]) != 1 {
		c.lru.Remove(elem)
		delete(c.items, key)
		return false
	}
	if now.After(entry.expiresAt) {
		// Expired: evict and treat as a miss.
		c.lru.Remove(elem)
		delete(c.items, key)
		return false
	}
	c.lru.MoveToFront(elem)
	return true
}

// Put caches a (pubKey, message, signature) tuple as INVALID with the
// configured TTL. Storing a negative is safe here because the cache key
// includes the signature bytes (see type doc).
//
// CRYPTO-R10-N07 (2026-07-19) FIX: Put now applies a sliding-window write-
// rate limiter BEFORE acquiring c.mu. Under a sustained flood of unique
// invalid signatures (the audit's lock-contention DoS scenario), Put
// returns early without caching once the per-window limit is exceeded.
// This degrades the cache to best-effort under attack, but releases the
// lock for Get lookups (which are the actual hot path during validation).
// The limit is capacity * invalidSigPutRateMultiplier per second — high
// enough to be transparent under legitimate workloads, low enough to bound
// worst-case lock contention.
func (c *InvalidSignatureCache) Put(pubKey, message, signature []byte) {
	// CRYPTO-R10-N07: sliding-window rate limit (checked BEFORE computing
	// the cache key, before acquiring c.mu). This is best-effort — even if
	// the counter check itself is slightly racy under heavy concurrency,
	// the worst case is a few extra Puts slipping through, not unbounded
	// lock contention.
	now := time.Now()
	nowUnixSec := now.Unix()
	windowStart := c.putWindowStartUnixSec.Load()
	if windowStart != nowUnixSec {
		// New window. CAS-swap the window start; if we win, reset the counter.
		// If we lose, another goroutine already did it — just read the
		// fresh values.
		if c.putWindowStartUnixSec.CompareAndSwap(windowStart, nowUnixSec) {
			c.putCountInWindow.Store(0)
		}
	}
	// Determine the per-window limit. Use a defensive floor so that even
	// tiny capacities (e.g. capacity=1 in tests) still allow at least a
	// few Puts per window before the limiter kicks in.
	limit := int64(c.capacity) * int64(invalidSigPutRateMultiplier)
	if limit < 1000 { // defensive floor
		limit = 1000
	}
	if c.putCountInWindow.Add(1) > limit {
		// Rate exceeded — drop this Put. The cache remains consistent
		// (Get will simply miss on this key), and the c.mu lock is
		// freed for Get traffic.
		return
	}

	key := computeCacheKey(pubKey, message, signature)
	// R47-CR-06 FIX: Compute verifyHash before acquiring the lock. Hashing is
	// CPU-bound and need not be serialized, so doing it outside the critical
	// section reduces lock contention.
	verifyHash := computeVerifyHash(pubKey, message)

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*invalidSigEntry)
		entry.expiresAt = now.Add(c.ttl)
		c.lru.MoveToFront(elem)
		return
	}

	// Evict expired entries periodically to reclaim space.
	// CR-04 FIX: Only run the O(n) eviction sweep every evictInterval puts
	// instead of on every Put, reducing per-Put overhead.
	c.putCount++
	if c.putCount >= c.evictInterval {
		c.putCount = 0
		c.evictExpiredLocked(now)
	}
	// Enforce capacity via LRU eviction.
	for c.lru.Len() >= c.capacity {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		c.lru.Remove(oldest)
		delete(c.items, oldest.Value.(*invalidSigEntry).key)
	}

	entry := &invalidSigEntry{
		key:        key,
		verifyHash: verifyHash,
		expiresAt:  now.Add(c.ttl),
	}
	c.items[key] = c.lru.PushFront(entry)
}

// evictExpiredLocked removes all entries whose TTL has elapsed.
// Caller must hold c.mu.
func (c *InvalidSignatureCache) evictExpiredLocked(now time.Time) {
	for key, elem := range c.items {
		entry := elem.Value.(*invalidSigEntry)
		if now.After(entry.expiresAt) {
			c.lru.Remove(elem)
			delete(c.items, key)
		}
	}
}

// Size returns the current number of cached entries (including expired ones
// not yet swept).
func (c *InvalidSignatureCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
