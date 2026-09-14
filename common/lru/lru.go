// Quantaureum Node source, version 1.0.0.
// Package lru provides a generic LRU (Least Recently Used) cache implementation.
package lru

import (
	"container/list"
	"sync"
)

// Cache is a generic LRU cache with thread-safe operations.
type Cache[K comparable, V any] struct {
	maxSize int
	items   map[K]*list.Element
	order   *list.List
	mu      sync.RWMutex
}

// entry represents a key-value pair stored in the cache.
type entry[K comparable, V any] struct {
	key   K
	value V
}

// New creates a new LRU cache with the specified maximum size.
// If size is <= 0, a default size of 100 is used.
func New[K comparable, V any](size int) *Cache[K, V] {
	if size <= 0 {
		size = 100
	}
	return &Cache[K, V]{
		maxSize: size,
		items:   make(map[K]*list.Element),
		order:   list.New(),
	}
}

// getEntry retrieves the entry from a list element, safely.
// The element is always from our own list with our own entry type.
func getEntry[K comparable, V any](elem *list.Element) *entry[K, V] {
	return elem.Value.(*entry[K, V]) //nolint:errcheck
}

// Get retrieves a value from the cache by key.
// Returns the value and true if found, or zero value and false if not found.
// Accessing an item moves it to the front (most recently used).
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		return getEntry[K, V](elem).value, true
	}

	var zero V
	return zero, false
}

// Peek retrieves a value from the cache without updating its position.
// Returns the value and true if found, or zero value and false if not found.
func (c *Cache[K, V]) Peek(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if elem, ok := c.items[key]; ok {
		return getEntry[K, V](elem).value, true
	}

	var zero V
	return zero, false
}

// Put adds or updates a key-value pair in the cache.
// If the key already exists, its value is updated and it's moved to the front.
// If the cache is full, the least recently used item is evicted.
func (c *Cache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If key exists, update value and move to front
	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		getEntry[K, V](elem).value = value
		return
	}

	// Add new entry
	e := &entry[K, V]{key: key, value: value}
	elem := c.order.PushFront(e)
	c.items[key] = elem

	// Evict oldest if over capacity
	if c.order.Len() > c.maxSize {
		c.evictOldest()
	}
}

// Remove removes a key from the cache.
// Returns true if the key was found and removed, false otherwise.
func (c *Cache[K, V]) Remove(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.removeElement(elem)
		return true
	}
	return false
}

// Len returns the current number of items in the cache.
func (c *Cache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.order.Len()
}

// MaxSize returns the maximum capacity of the cache.
func (c *Cache[K, V]) MaxSize() int {
	return c.maxSize
}

// Contains checks if a key exists in the cache without updating its position.
func (c *Cache[K, V]) Contains(key K) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.items[key]
	return ok
}

// Keys returns all keys in the cache, from most to least recently used.
func (c *Cache[K, V]) Keys() []K {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]K, 0, c.order.Len())
	for elem := c.order.Front(); elem != nil; elem = elem.Next() {
		keys = append(keys, getEntry[K, V](elem).key)
	}
	return keys
}

// Clear removes all items from the cache.
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[K]*list.Element)
	c.order.Init()
}

// evictOldest removes the least recently used item from the cache.
// Must be called with lock held.
func (c *Cache[K, V]) evictOldest() {
	elem := c.order.Back()
	if elem != nil {
		c.removeElement(elem)
	}
}

// removeElement removes an element from the cache.
// Must be called with lock held.
func (c *Cache[K, V]) removeElement(elem *list.Element) {
	c.order.Remove(elem)
	e := getEntry[K, V](elem)
	delete(c.items, e.key)
}

// GetOrPut retrieves a value if it exists, or puts and returns the provided value.
// Returns the value and true if it was already in the cache, or the new value and false.
func (c *Cache[K, V]) GetOrPut(key K, value V) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		return getEntry[K, V](elem).value, true
	}

	// Add new entry
	e := &entry[K, V]{key: key, value: value}
	elem := c.order.PushFront(e)
	c.items[key] = elem

	// Evict oldest if over capacity
	if c.order.Len() > c.maxSize {
		c.evictOldest()
	}

	return value, false
}
