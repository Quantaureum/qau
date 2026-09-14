// Quantaureum Node source, version 1.0.0.
// Package cache provides multi-level caching for Quantaureum blockchain.
package cache

import (
	"container/list"
	"log"
	"sync"
	"time"
)

// CacheLevel represents a level in the cache hierarchy
type CacheLevel int

const (
	// L1Cache is the fastest, smallest cache (hot data)
	L1Cache CacheLevel = iota
	// L2Cache is medium speed, medium size
	L2Cache
	// L3Cache is slower, larger cache
	L3Cache
)

// CacheEntry represents a cached item.
//
// CACHE-R11-003 (2026-07-20): Removed the unused `Size int` field. The
// field was declared but never set or read by any code path (LRUCache.Put
// and PutPreservingExpiry construct CacheEntry literals without populating
// Size, and no eviction logic consulted it). Implementing size-based
// eviction would require changing Put's signature to accept a size
// parameter and updating every caller — a disproportionate change for
// the current cache usage pattern (count-based LRU is sufficient). The
// audit explicitly offered either option; we chose deletion to keep the
// API minimal and to remove the misleading suggestion that the cache
// tracks memory footprint when it does not.
//
// CACHE-R12-001 (2026-07-20): Reintroduced size tracking — but stored
// outside the entry (in LRUCache.currentMemory) rather than as a field
// on CacheEntry. This avoids the original API problem (Put's signature
// is unchanged; size is computed internally via sizeFunc) while still
// enabling memory-based eviction to prevent OOM from large []byte values.
type CacheEntry struct {
	Key       string
	Value     any
	ExpiresAt time.Time
	Level     CacheLevel
}

// LRUCache is a simple LRU cache implementation
type LRUCache struct {
	mu       sync.RWMutex
	capacity int
	items    map[string]*list.Element
	order    *list.List

	// CACHE-R12-001 (2026-07-20): Memory byte tracking.
	// maxMemory is the maximum total bytes allowed for all entries
	// (0 = no memory limit, only count-based eviction applies).
	// currentMemory is the sum of all entry sizes (as computed by sizeFunc).
	// sizeFunc computes the byte size of a cached value; if nil, no
	// memory tracking is performed (legacy behavior).
	//
	// Without memory tracking, a single Put of a 1 GB []byte would be
	// stored in the cache regardless of capacity (count-based eviction
	// only fires on the next Put, not on the oversized Put itself). With
	// memory tracking, oversized entries are rejected before insertion
	// if they alone exceed maxMemory, and the LRU is evicted until
	// currentMemory + entrySize <= maxMemory before inserting.
	maxMemory     int64
	currentMemory int64
	sizeFunc      func(any) int64
}

// NewLRUCache creates a new LRU cache
// L14-038/L15-037 FIX: Clamp negative capacity to 0 to prevent undefined behavior.
// CACHE-R11-002 (2026-07-20) FIX: capacity=0 is a silent footgun. Put() with
// capacity=0 used to silently store entries anyway (the order.Len() >= 0
// eviction guard always fires, evicts nothing from the empty list, then
// PushFront adds the entry — bypassing the capacity contract). Now we
// promote capacity=0 to 1 so the cache behaves as a degenerate but
// consistent 1-slot LRU: Put works, the next Put evicts the prior entry.
// We also log a one-time warning so callers notice the misconfiguration
// (almost always a forgotten constructor argument or a config typo).
func NewLRUCache(capacity int) *LRUCache {
	if capacity < 0 {
		capacity = 0
	}
	if capacity == 0 {
		log.Printf("[WARN] cache: NewLRUCache called with capacity=0; promoting to 1 (capacity=0 is a no-op footgun — caller should pass a positive capacity)")
		capacity = 1
	}
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		order:    list.New(),
	}
}

// NewLRUCacheWithMemoryLimit creates a new LRU cache with both count-based
// and memory-based eviction.
//
// CACHE-R12-001 (2026-07-20): This constructor enables memory byte
// tracking. When maxMemory > 0 and sizeFunc != nil:
//   - Each Put computes the entry's byte size via sizeFunc.
//   - If a single entry exceeds maxMemory, it is rejected (logged at WARN).
//   - Before inserting, LRU entries are evicted until
//     currentMemory + entrySize <= maxMemory.
//   - count-based eviction (capacity) still applies alongside.
//
// When maxMemory == 0 or sizeFunc == nil, behavior is identical to
// NewLRUCache (count-based eviction only). This preserves backward
// compatibility for existing callers.
//
// The default sizeFunc handles []byte and string exactly; other types
// return 0 (rely on count-based eviction). Callers storing large custom
// types should provide a custom sizeFunc.
func NewLRUCacheWithMemoryLimit(capacity int, maxMemory int64, sizeFunc func(any) int64) *LRUCache {
	c := NewLRUCache(capacity)
	c.maxMemory = maxMemory
	c.sizeFunc = sizeFunc
	return c
}

// DefaultSizeFunc is the default size estimator used when no SizeFunc is
// configured. It handles the most common large-value types exactly:
//   - []byte → len(v)
//   - string → len(v)
//   - nil → 0
//
// For other types, it returns 0 (the value is not counted toward memory
// limit; only count-based eviction applies). This is a defensive choice:
// we cannot accurately estimate struct sizes without reflection, and
// underestimating is safer than overestimating (which could cause
// premature eviction). The audit concern (large []byte OOM) is fully
// addressed by the []byte/string cases.
//
// Callers storing large non-byte types (e.g., big structs) should provide
// a custom SizeFunc.
func DefaultSizeFunc(v any) int64 {
	switch x := v.(type) {
	case []byte:
		return int64(len(x))
	case string:
		return int64(len(x))
	case nil:
		return 0
	default:
		return 0
	}
}

// entrySize returns the byte size of the entry's value, or 0 if no
// sizeFunc is configured (memory tracking disabled).
func (c *LRUCache) entrySize(value any) int64 {
	if c.sizeFunc == nil {
		return 0
	}
	return c.sizeFunc(value)
}

// addMemory adds size to currentMemory. Caller must hold c.mu.
func (c *LRUCache) addMemory(size int64) {
	c.currentMemory += size
}

// subMemory subtracts size from currentMemory, clamped at 0 to prevent
// underflow from accounting bugs. Caller must hold c.mu.
func (c *LRUCache) subMemory(size int64) {
	c.currentMemory -= size
	if c.currentMemory < 0 {
		c.currentMemory = 0
	}
}

// evictUntilMemoryFits evicts LRU entries until currentMemory + needed <= maxMemory.
// If a single entry alone exceeds maxMemory, all entries are evicted.
// Caller must hold c.mu. No-op when maxMemory == 0 (memory tracking disabled).
func (c *LRUCache) evictUntilMemoryFits(needed int64) {
	if c.maxMemory <= 0 {
		return
	}
	for c.currentMemory+needed > c.maxMemory && c.order.Len() > 0 {
		c.evict()
	}
}

// getEntry safely extracts a CacheEntry from a list element.
// The element is always from our own list with our own entry type.
func getEntry(elem *list.Element) *CacheEntry {
	return elem.Value.(*CacheEntry) //nolint:errcheck
}

// Get retrieves an item from the cache
func (c *LRUCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		entry := getEntry(elem)
		// Check expiration
		if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
			// CACHE-R12-001: subtract memory before removing.
			c.subMemory(c.entrySize(entry.Value))
			c.order.Remove(elem)
			delete(c.items, key)
			return nil, false
		}
		// Move to front (most recently used)
		c.order.MoveToFront(elem)
		return entry.Value, true
	}
	return nil, false
}

// GetWithExpiry retrieves an item along with its current ExpiresAt timestamp.
// Used by MultiLevelCache.Get to preserve the remaining TTL when promoting
// an item across tiers (CACHE-R11-001). Returns (value, expiresAt, ok).
// expiresAt is the zero time if the entry has no TTL.
func (c *LRUCache) GetWithExpiry(key string) (any, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		entry := getEntry(elem)
		// Check expiration
		if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
			// CACHE-R12-001: subtract memory before removing.
			c.subMemory(c.entrySize(entry.Value))
			c.order.Remove(elem)
			delete(c.items, key)
			return nil, time.Time{}, false
		}
		// Move to front (most recently used)
		c.order.MoveToFront(elem)
		return entry.Value, entry.ExpiresAt, true
	}
	return nil, time.Time{}, false
}

// Put adds an item to the cache
//
// CACHE-R12-001 (2026-07-20): When memory tracking is enabled (maxMemory > 0
// and sizeFunc != nil), this method:
//  1. Computes the entry's byte size via sizeFunc.
//  2. If the entry alone exceeds maxMemory, it is rejected (logged at WARN)
//     and NOT stored — preventing a single oversized Put from blowing past
//     the memory budget.
//  3. Before inserting, LRU entries are evicted until
//     currentMemory + entrySize <= maxMemory.
//  4. When updating an existing entry, the old value's size is subtracted
//     before adding the new value's size.
//
// When memory tracking is disabled (maxMemory == 0 or sizeFunc == nil),
// behavior is identical to before: count-based LRU eviction only.
func (c *LRUCache) Put(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Calculate expiration
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	entry := &CacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: expiresAt,
	}

	// CACHE-R12-001: Compute new entry's memory size.
	newSize := c.entrySize(value)

	// Update existing entry
	if elem, ok := c.items[key]; ok {
		// Subtract old value's size, then add new value's size.
		oldEntry := getEntry(elem)
		oldSize := c.entrySize(oldEntry.Value)
		c.subMemory(oldSize)
		c.addMemory(newSize)
		c.order.MoveToFront(elem)
		elem.Value = entry
		// After update, evict if we exceeded memory (the update itself
		// may have pushed us over). Eviction removes the LRU entry,
		// which may NOT be the one we just updated.
		if c.maxMemory > 0 && c.currentMemory > c.maxMemory {
			c.evictUntilMemoryFits(0)
		}
		return
	}

	// CACHE-R12-001: Reject oversized entries before insertion.
	// A single entry that alone exceeds maxMemory would make eviction
	// impossible (even evicting everything wouldn't fit it), so reject.
	if c.maxMemory > 0 && newSize > c.maxMemory {
		log.Printf("[WARN] cache: Put rejected entry %q size %d exceeds maxMemory %d",
			key, newSize, c.maxMemory)
		return
	}

	// Evict if at capacity (count-based)
	if c.order.Len() >= c.capacity {
		c.evict()
	}

	// CACHE-R12-001: Evict until memory fits (memory-based).
	c.evictUntilMemoryFits(newSize)

	// Add new entry
	elem := c.order.PushFront(entry)
	c.items[key] = elem
	c.addMemory(newSize)
}

// PutPreservingExpiry adds an item to the cache, but caps its TTL at the
// earlier of (a) the supplied newTTL or (b) the supplied currentExpiry.
//
// CACHE-R11-001 (2026-07-20): When MultiLevelCache.Get promotes an item
// from a lower tier (L2→L1, L3→L2), passing the new tier's full TTL
// resets the item's lifetime — so a single access to cold data refreshes
// its TTL to the new tier's default, defeating tiered expiry. An attacker
// who walks the entire L3 once could promote every item to L1 with a
// fresh L1 TTL, evicting genuine hot data and pinning cold data in the
// hot tier.
//
// Promote paths now pass the source entry's current ExpiresAt; this
// method clamps the new entry's ExpiresAt to min(now+newTTL, currentExpiry)
// so the promoted item never outlives its original deadline. Callers
// passing a zero currentExpiry get the unmodified newTTL behavior
// (preserving Put semantics).
func (c *LRUCache) PutPreservingExpiry(key string, value any, newTTL time.Duration, currentExpiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var expiresAt time.Time
	if newTTL > 0 {
		expiresAt = now.Add(newTTL)
	}
	// If the caller supplied a current expiry that is sooner, honor it.
	if !currentExpiry.IsZero() && currentExpiry.Before(expiresAt) {
		expiresAt = currentExpiry
	}
	// If the preserved expiry is already in the past, do not insert at all.
	if !expiresAt.IsZero() && expiresAt.Before(now) {
		// Defensive: remove any stale entry so callers don't observe a
		// phantom hit on a follow-up Get.
		if elem, ok := c.items[key]; ok {
			// CACHE-R12-001: subtract memory before removing.
			oldEntry := getEntry(elem)
			c.subMemory(c.entrySize(oldEntry.Value))
			c.order.Remove(elem)
			delete(c.items, key)
		}
		return
	}

	entry := &CacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: expiresAt,
	}

	// CACHE-R12-001: Compute new entry's memory size.
	newSize := c.entrySize(value)

	// Update existing entry
	if elem, ok := c.items[key]; ok {
		// Subtract old value's size, then add new value's size.
		oldEntry := getEntry(elem)
		oldSize := c.entrySize(oldEntry.Value)
		c.subMemory(oldSize)
		c.addMemory(newSize)
		c.order.MoveToFront(elem)
		elem.Value = entry
		// After update, evict if we exceeded memory.
		if c.maxMemory > 0 && c.currentMemory > c.maxMemory {
			c.evictUntilMemoryFits(0)
		}
		return
	}

	// CACHE-R12-001: Reject oversized entries before insertion.
	if c.maxMemory > 0 && newSize > c.maxMemory {
		log.Printf("[WARN] cache: PutPreservingExpiry rejected entry %q size %d exceeds maxMemory %d",
			key, newSize, c.maxMemory)
		return
	}

	// Evict if at capacity
	if c.order.Len() >= c.capacity {
		c.evict()
	}

	// CACHE-R12-001: Evict until memory fits.
	c.evictUntilMemoryFits(newSize)

	// Add new entry
	elem := c.order.PushFront(entry)
	c.items[key] = elem
	c.addMemory(newSize)
}

// Delete removes an item from the cache
func (c *LRUCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		// CACHE-R12-001: subtract memory before removing.
		entry := getEntry(elem)
		c.subMemory(c.entrySize(entry.Value))
		c.order.Remove(elem)
		delete(c.items, key)
	}
}

// evict removes the least recently used item
//
// CACHE-R12-001 (2026-07-20): Also subtracts the evicted entry's memory
// from currentMemory to keep the accounting accurate.
func (c *LRUCache) evict() {
	elem := c.order.Back()
	if elem != nil {
		entry := getEntry(elem)
		c.subMemory(c.entrySize(entry.Value))
		c.order.Remove(elem)
		delete(c.items, entry.Key)
	}
}

// Len returns the number of items in the cache
func (c *LRUCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.order.Len()
}

// MemoryUsage returns the current total bytes used by all entries in the
// cache. Returns 0 when memory tracking is disabled (maxMemory == 0 or
// sizeFunc == nil).
//
// CACHE-R12-001 (2026-07-20): Exposed for observability — callers can
// monitor cache memory pressure and adjust limits dynamically.
func (c *LRUCache) MemoryUsage() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentMemory
}

// MaxMemory returns the configured maximum memory limit in bytes.
// Returns 0 when memory tracking is disabled.
func (c *LRUCache) MaxMemory() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxMemory
}

// Clear removes all items from the cache
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentMemory = 0
	c.items = make(map[string]*list.Element)
	c.order = list.New()
}

// MultiLevelCache provides a multi-level caching system
type MultiLevelCache struct {
	mu sync.RWMutex

	// Cache levels
	l1 *LRUCache // Hot data, small capacity
	l2 *LRUCache // Warm data, medium capacity
	l3 *LRUCache // Cold data, large capacity

	// TTL settings
	l1TTL time.Duration
	l2TTL time.Duration
	l3TTL time.Duration

	// Stats
	hits   uint64
	misses uint64
}

// MultiLevelCacheConfig holds configuration for MultiLevelCache
//
// CACHE-R12-001 (2026-07-20): Changed L*MaxSize from `any` to `int` and
// L*MaxMemory from `any` to `int64`. Previously these fields were declared
// as `any` for "type flexibility" but never read by NewMultiLevelCache,
// making them silent no-ops — a caller setting L1MaxMemory=64MB got no
// memory limit at all, allowing a single oversized []byte to OOM the node.
//
// Now:
//   - L*MaxSize (> 0) overrides L*Capacity (count-based limit).
//   - L*MaxMemory (> 0) enables memory byte tracking (requires SizeFunc
//     or falls back to DefaultSizeFunc).
//   - SizeFunc computes a cached value's byte size. If nil, defaults to
//     DefaultSizeFunc (handles []byte and string exactly; other types
//     return 0 — rely on count-based eviction).
type MultiLevelCacheConfig struct {
	L1Capacity int
	L2Capacity int
	L3Capacity int
	L1TTL      time.Duration
	L2TTL      time.Duration
	L3TTL      time.Duration
	// Count-based limits (alias for L*Capacity when > 0).
	L1MaxSize int
	L2MaxSize int
	L3MaxSize int
	// Memory-based limits in bytes (0 = no memory limit).
	L1MaxMemory int64
	L2MaxMemory int64
	L3MaxMemory int64
	// SizeFunc computes the byte size of a cached value.
	// If nil, uses DefaultSizeFunc.
	SizeFunc func(any) int64
	// Additional fields
	TTL          time.Duration
	PromoteOnHit bool
}

// DefaultMultiLevelCacheConfig returns default configuration
//
// CACHE-R12-001 (2026-07-20): Added default memory limits:
//   - L1: 64 MB (hot data, small but fast)
//   - L2: 256 MB (warm data)
//   - L3: 1 GB (cold data, large)
//
// These match the node's default CacheOptConfig values. Combined with
// the default SizeFunc (which tracks []byte and string sizes exactly),
// this prevents a single oversized Put from OOMing the node.
func DefaultMultiLevelCacheConfig() *MultiLevelCacheConfig {
	return &MultiLevelCacheConfig{
		L1Capacity:  1000,
		L2Capacity:  10000,
		L3Capacity:  100000,
		L1TTL:       1 * time.Minute,
		L2TTL:       5 * time.Minute,
		L3TTL:       30 * time.Minute,
		L1MaxMemory: 64 * 1024 * 1024,   // 64 MB
		L2MaxMemory: 256 * 1024 * 1024,  // 256 MB
		L3MaxMemory: 1024 * 1024 * 1024, // 1 GB
		SizeFunc:    DefaultSizeFunc,
	}
}

// NewMultiLevelCache creates a new multi-level cache
//
// CACHE-R12-001 (2026-07-20): Now wires up L*MaxSize and L*MaxMemory
// from the config (previously declared but unused). When L*MaxSize > 0,
// it overrides L*Capacity. When L*MaxMemory > 0 and SizeFunc != nil,
// memory byte tracking is enabled per level.
func NewMultiLevelCache(config *MultiLevelCacheConfig) *MultiLevelCache {
	if config == nil {
		config = DefaultMultiLevelCacheConfig()
	}

	// Resolve effective capacities: L*MaxSize overrides L*Capacity when > 0.
	l1Cap := config.L1Capacity
	if config.L1MaxSize > 0 {
		l1Cap = config.L1MaxSize
	}
	l2Cap := config.L2Capacity
	if config.L2MaxSize > 0 {
		l2Cap = config.L2MaxSize
	}
	l3Cap := config.L3Capacity
	if config.L3MaxSize > 0 {
		l3Cap = config.L3MaxSize
	}

	// Resolve size function: default to DefaultSizeFunc when nil.
	sizeFunc := config.SizeFunc
	if sizeFunc == nil {
		sizeFunc = DefaultSizeFunc
	}

	// Use the memory-limit constructor when memory limit is set;
	// otherwise fall back to count-only constructor.
	var l1, l2, l3 *LRUCache
	if config.L1MaxMemory > 0 {
		l1 = NewLRUCacheWithMemoryLimit(l1Cap, config.L1MaxMemory, sizeFunc)
	} else {
		l1 = NewLRUCache(l1Cap)
	}
	if config.L2MaxMemory > 0 {
		l2 = NewLRUCacheWithMemoryLimit(l2Cap, config.L2MaxMemory, sizeFunc)
	} else {
		l2 = NewLRUCache(l2Cap)
	}
	if config.L3MaxMemory > 0 {
		l3 = NewLRUCacheWithMemoryLimit(l3Cap, config.L3MaxMemory, sizeFunc)
	} else {
		l3 = NewLRUCache(l3Cap)
	}

	return &MultiLevelCache{
		l1:    l1,
		l2:    l2,
		l3:    l3,
		l1TTL: config.L1TTL,
		l2TTL: config.L2TTL,
		l3TTL: config.L3TTL,
	}
}

// Get retrieves an item from the cache, checking all levels
//
// CACHE-R11-001 (2026-07-20): Promotion paths now preserve the source
// entry's remaining TTL instead of resetting it to the target tier's
// default. Without this, a single access to every L3 item would promote
// them all to L2/L1 with fresh TTLs, evicting genuine hot data and
// pinning cold data in the hot tier (cache pollution + tiered-expiry
// bypass). Now an item promoted from L3→L2→L1 retains its original L3
// expiry deadline, ensuring cold data expires when it would have expired
// anyway. New items inserted via Put/PutHot/PutWarm/PutCold still get
// the full tier TTL (correct behavior for fresh data).
func (c *MultiLevelCache) Get(key string) (any, bool) {
	// R33 P2-03 FIX (2026-07-28): Lock-ordering documentation.
	//
	// All locks in MultiLevelCache are acquired SEQUENTIALLY — never nested.
	// Each LRU operation (l1.Get, l2.GetWithExpiry, l1.PutPreservingExpiry,
	// etc.) acquires its own internal mutex and releases it before returning.
	// The stats mutex (c.mu) is similarly acquired and released independently.
	//
	// Lock ordering (always top-down, never holding two at once):
	//   1. L1.mu (in l1.Get) → release
	//   2. c.mu (stats update) → release
	//   3. L2.mu (in l2.GetWithExpiry) → release
	//   4. L1.mu (in l1.PutPreservingExpiry) → release
	//   5. c.mu (stats update) → release
	//   6. L3.mu (in l3.GetWithExpiry) → release
	//   7. L2.mu (in l2.PutPreservingExpiry) → release
	//   8. c.mu (stats update) → release
	//
	// Because no two locks are held simultaneously, deadlock is impossible.
	// The original P2-03 concern was about potential lock-order inversion
	// between cache levels, but the sequential acquire-release pattern
	// eliminates this risk. This comment documents the invariant for
	// future maintainers.

	// Try L1 first
	if val, ok := c.l1.Get(key); ok {
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		return val, true
	}

	// Try L2 — promote to L1 preserving remaining TTL
	if val, expiry, ok := c.l2.GetWithExpiry(key); ok {
		c.l1.PutPreservingExpiry(key, val, c.l1TTL, expiry)
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		return val, true
	}

	// Try L3 — promote to L2 preserving remaining TTL
	if val, expiry, ok := c.l3.GetWithExpiry(key); ok {
		c.l2.PutPreservingExpiry(key, val, c.l2TTL, expiry)
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		return val, true
	}

	c.mu.Lock()
	c.misses++
	c.mu.Unlock()
	return nil, false
}

// Put adds an item to the cache at the specified level
func (c *MultiLevelCache) Put(key string, value any, level CacheLevel) {
	switch level {
	case L1Cache:
		c.l1.Put(key, value, c.l1TTL)
	case L2Cache:
		c.l2.Put(key, value, c.l2TTL)
	case L3Cache:
		c.l3.Put(key, value, c.l3TTL)
	default:
		c.l1.Put(key, value, c.l1TTL)
	}
}

// PutHot adds an item to the L1 cache
func (c *MultiLevelCache) PutHot(key string, value any) {
	c.Put(key, value, L1Cache)
}

// PutWarm adds an item to the L2 cache
func (c *MultiLevelCache) PutWarm(key string, value any) {
	c.Put(key, value, L2Cache)
}

// PutCold adds an item to the L3 cache
func (c *MultiLevelCache) PutCold(key string, value any) {
	c.Put(key, value, L3Cache)
}

// Delete removes an item from all cache levels
func (c *MultiLevelCache) Delete(key string) {
	c.l1.Delete(key)
	c.l2.Delete(key)
	c.l3.Delete(key)
}

// Clear removes all items from all cache levels
func (c *MultiLevelCache) Clear() {
	c.l1.Clear()
	c.l2.Clear()
	c.l3.Clear()

	c.mu.Lock()
	c.hits = 0
	c.misses = 0
	c.mu.Unlock()
}

// Stats returns cache statistics
func (c *MultiLevelCache) Stats() (hits, misses uint64, hitRate float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hits = c.hits
	misses = c.misses
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}
	return
}

// Size returns the total number of items across all levels
func (c *MultiLevelCache) Size() int {
	return c.l1.Len() + c.l2.Len() + c.l3.Len()
}
