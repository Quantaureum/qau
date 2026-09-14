// Quantaureum Node source, version 1.0.0.
// Package validation provides input validation framework for Quantaureum.
// This file implements signature verification result caching.
// Implements Requirements 13.3, 13.4, 13.5: signature caching, nonce and gas validation.
package validation

import (
	"container/list"
	"sync"

	"github.com/quantaureum/qau/types"
)

// SignatureCache provides LRU caching for signature verification results.
// Implements Requirements 13.3: signature verification result caching.
type SignatureCache struct {
	mu       sync.RWMutex
	capacity int
	cache    map[types.Hash]*list.Element
	lru      *list.List
}

// cacheEntry represents a cached signature verification result.
type cacheEntry struct {
	hash  types.Hash
	valid bool
}

// NewSignatureCache creates a new SignatureCache with the specified capacity.
func NewSignatureCache(capacity int) *SignatureCache {
	if capacity <= 0 {
		capacity = DefaultCacheSize
	}
	return &SignatureCache{
		capacity: capacity,
		cache:    make(map[types.Hash]*list.Element),
		lru:      list.New(),
	}
}

// Get retrieves a cached signature verification result.
// Returns (result, true) if found, (false, false) if not found.
func (sc *SignatureCache) Get(hash types.Hash) (bool, bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if elem, ok := sc.cache[hash]; ok {
		// Move to front (most recently used)
		sc.lru.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		return entry.valid, true
	}
	return false, false
}

// Set stores a signature verification result in the cache.
func (sc *SignatureCache) Set(hash types.Hash, valid bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Check if already exists
	if elem, ok := sc.cache[hash]; ok {
		sc.lru.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		entry.valid = valid
		return
	}

	// Evict oldest if at capacity
	if sc.lru.Len() >= sc.capacity {
		sc.evictOldest()
	}

	// Add new entry
	entry := &cacheEntry{hash: hash, valid: valid}
	elem := sc.lru.PushFront(entry)
	sc.cache[hash] = elem
}

// evictOldest removes the least recently used entry.
func (sc *SignatureCache) evictOldest() {
	oldest := sc.lru.Back()
	if oldest != nil {
		entry := oldest.Value.(*cacheEntry)
		delete(sc.cache, entry.hash)
		sc.lru.Remove(oldest)
	}
}

// Delete removes an entry from the cache.
func (sc *SignatureCache) Delete(hash types.Hash) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if elem, ok := sc.cache[hash]; ok {
		delete(sc.cache, hash)
		sc.lru.Remove(elem)
	}
}

// Clear removes all entries from the cache.
func (sc *SignatureCache) Clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.cache = make(map[types.Hash]*list.Element)
	sc.lru.Init()
}

// Size returns the current number of cached entries.
func (sc *SignatureCache) Size() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.lru.Len()
}

// Capacity returns the maximum capacity of the cache.
func (sc *SignatureCache) Capacity() int {
	return sc.capacity
}

// Contains checks if a hash is in the cache.
func (sc *SignatureCache) Contains(hash types.Hash) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	_, ok := sc.cache[hash]
	return ok
}
