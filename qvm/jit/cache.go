// Quantaureum Node source, version 1.0.0.
package jit

import (
	"container/list"
	"sync"
)

type cacheEntry struct {
	hash [32]byte
	plan *ExecutionPlan
	elem *list.Element
}

type CompilationCache struct {
	mu       sync.RWMutex
	maxSize  int
	items    map[[32]byte]*cacheEntry
	lruList  *list.List
	hits     uint64
	misses   uint64
	compiles uint64
}

func NewCompilationCache(maxSize int) *CompilationCache {
	// R25-034 NOTE (P3): JIT compilation cache size. Defaults to 256 entries
	// (LRU-evicted) when maxSize <= 0. Each entry holds a compiled ExecutionPlan
	// keyed by code hash; 256 is sufficient for typical contract working sets
	// while bounding memory. The JIT compiler itself is disabled by default
	// (qvm/executor.go jitEnabled=false), so this cache is only populated when
	// the operator explicitly enables JIT compilation.
	if maxSize <= 0 {
		maxSize = 256
	}
	return &CompilationCache{
		maxSize: maxSize,
		items:   make(map[[32]byte]*cacheEntry),
		lruList: list.New(),
	}
}

func (c *CompilationCache) Get(hash [32]byte) (*ExecutionPlan, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[hash]
	if !ok {
		c.misses++
		return nil, false
	}

	c.lruList.MoveToFront(entry.elem)
	c.hits++
	return entry.plan, true
}

func (c *CompilationCache) Put(hash [32]byte, plan *ExecutionPlan) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[hash]; ok {
		entry.plan = plan
		c.lruList.MoveToFront(entry.elem)
		return
	}

	for c.lruList.Len() >= c.maxSize {
		c.evictLocked()
	}

	elem := c.lruList.PushFront(hash)
	c.items[hash] = &cacheEntry{
		hash: hash,
		plan: plan,
		elem: elem,
	}
	c.compiles++
}

func (c *CompilationCache) evictLocked() {
	back := c.lruList.Back()
	if back == nil {
		return
	}
	hash := c.lruList.Remove(back).([32]byte)
	delete(c.items, hash)
}

func (c *CompilationCache) Remove(hash [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[hash]; ok {
		c.lruList.Remove(entry.elem)
		delete(c.items, hash)
	}
}

func (c *CompilationCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[[32]byte]*cacheEntry)
	c.lruList.Init()
	c.hits = 0
	c.misses = 0
	c.compiles = 0
}

func (c *CompilationCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *CompilationCache) Stats() (hits, misses, compiles uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, c.compiles
}

func (c *CompilationCache) HitRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := c.hits + c.misses
	if total == 0 {
		return 0
	}
	return float64(c.hits) / float64(total)
}
