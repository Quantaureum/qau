// Quantaureum Node source, version 1.0.0.
// Package db provides the database abstraction layer for Quantaureum.
package db

import (
	"errors"
	"sort"
	"sync"
)

// Common errors
var (
	ErrKeyNotFound    = errors.New("key not found")
	ErrNotFound       = ErrKeyNotFound // Alias for compatibility
	ErrDatabaseClosed = errors.New("database closed")
	ErrInvalidKey     = errors.New("invalid key")
	ErrInvalidValue   = errors.New("invalid value")
	// ErrIteratorTruncated is returned by Iterator.Error() when the iterator
	// hit its internal max-iteration limit and silently stopped before
	// exhausting all matching keys. Callers that require a complete result
	// set (e.g. storage-root computation) MUST check Iterator.Error() and
	// treat this as a hard failure — otherwise they will produce a root that
	// does not cover the truncated entries, causing a silent state-root
	// divergence between nodes.
	// AUDIT (2026) DATA-R2-01: Previously the iterator just logged a
	// warning and returned a truncated result with no error, so callers had
	// no way to detect the truncation.
	ErrIteratorTruncated = errors.New("iterator truncated at max iteration limit")
)

// Database defines the interface for key-value storage
type Database interface {
	// Get retrieves a value by key
	Get(key []byte) ([]byte, error)
	// Put stores a key-value pair
	Put(key, value []byte) error
	// Delete removes a key-value pair
	Delete(key []byte) error
	// Has checks if a key exists
	Has(key []byte) (bool, error)
	// Close closes the database
	Close() error
	// NewBatch creates a new batch for atomic writes
	NewBatch() Batch
	// NewIterator creates a new iterator over keys with the given prefix
	NewIterator(prefix []byte, start []byte) Iterator
	// NewIteratorWithLimit creates an iterator with a caller-specified max
	// iteration count. Pass limit=0 for unlimited (no truncation).
	// AUDIT R4-DATA-02 (2026-07-15): computeStorageRoot uses this with
	// limit=0 so that accounts with >100k storage slots are not permanently
	// locked out of commits. The previous NewIterator hard-capped at 100k
	// entries and returned ErrIteratorTruncated, causing Commit to fail
	// for any block touching such an account — a chain-liveness deadlock
	// for successful token/NFT contracts. Gas cost per SSTORE is the
	// natural DoS protection against unbounded storage growth.
	NewIteratorWithLimit(prefix []byte, start []byte, limit int) Iterator
}

// Iterator iterates over a database's key/value pairs in key order
type Iterator interface {
	// Next moves to the next key/value pair
	Next() bool
	// Key returns the key of the current key/value pair
	Key() []byte
	// Value returns the value of the current key/value pair
	Value() []byte
	// Error returns any accumulated error
	Error() error
	// Release releases resources
	Release()
}

// Batch defines the interface for batch operations
type Batch interface {
	// Put adds a put operation to the batch
	Put(key, value []byte) error
	// Delete adds a delete operation to the batch
	Delete(key []byte) error
	// Write executes all operations in the batch
	Write() error
	// Reset clears all operations in the batch
	Reset()
	// ValueSize returns the total size of values in the batch
	ValueSize() int
	// Flush commits the currently-accumulated ops and resets the in-memory
	// batch so the caller can continue appending. This is the explicit
	// split primitive introduced by DB-R12-002 — callers that legitimately
	// need to write more than MaxBatchOps or MaxBatchBytes worth of data
	// MUST call Flush() at a logical boundary (e.g. between accounts,
	// between blocks) and inspect the error before continuing.
	// Implementations that do not enforce size limits (e.g. memBatch)
	// implement Flush() as Write() + Reset().
	Flush() error
}

// MemDB is an in-memory database implementation for testing
type MemDB struct {
	mu     sync.RWMutex
	data   map[string][]byte
	closed bool
}

// NewMemDB creates a new in-memory database
func NewMemDB() *MemDB {
	return &MemDB{
		data: make(map[string][]byte),
	}
}

// FileDB wraps BoltDB for file-based persistent database
// audit-fix DB-M1: replaced MemDB stub with real BoltDB persistence
type FileDB struct {
	*BoltDB
	path string
}

// NewFileDB creates a new file-based database using BoltDB for persistence
// audit-fix DB-M1: now uses BoltDB instead of MemDB to ensure data persistence
func NewFileDB(path string) (*FileDB, error) {
	boltDB, err := NewBoltDB(path)
	if err != nil {
		return nil, err
	}
	return &FileDB{
		BoltDB: boltDB,
		path:   path,
	}, nil
}

// Path returns the database path
func (db *FileDB) Path() string {
	return db.path
}

// Get retrieves a value by key
func (db *MemDB) Get(key []byte) ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.closed {
		return nil, ErrDatabaseClosed
	}

	value, ok := db.data[string(key)]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Return a copy to prevent modification
	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// Put stores a key-value pair
func (db *MemDB) Put(key, value []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.closed {
		return ErrDatabaseClosed
	}

	// Store copies to prevent external modification
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)

	db.data[string(keyCopy)] = valueCopy
	return nil
}

// Delete removes a key-value pair
func (db *MemDB) Delete(key []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.closed {
		return ErrDatabaseClosed
	}

	delete(db.data, string(key))
	return nil
}

// Has checks if a key exists
func (db *MemDB) Has(key []byte) (bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.closed {
		return false, ErrDatabaseClosed
	}

	_, ok := db.data[string(key)]
	return ok, nil
}

// Close closes the database
func (db *MemDB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.closed = true
	db.data = nil
	return nil
}

// NewBatch creates a new batch for atomic writes
func (db *MemDB) NewBatch() Batch {
	return &memBatch{
		db:   db,
		ops:  make([]batchOp, 0),
		size: 0,
	}
}

// Len returns the number of entries in the database
func (db *MemDB) Len() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.data)
}

// NewIterator creates a new iterator over keys with the given prefix
func (db *MemDB) NewIterator(prefix []byte, start []byte) Iterator {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// I22-007 FIX: Check database closed state before creating an iterator.
	// Get/Put/Delete/Has already guard db.closed; iterators must too, so
	// that callers receive ErrDatabaseClosed via Iterator.Error() instead of
	// a silently-empty result set after Close() nils out db.data.
	if db.closed {
		return &memIterator{err: ErrDatabaseClosed}
	}

	// Collect all keys with the given prefix
	var keys []string
	for k := range db.data {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == string(prefix)) {
			if start == nil || k >= string(start) {
				keys = append(keys, k)
			}
		}
	}

	// Sort keys for consistent ordering
	sort.Strings(keys)

	// Build key-value pairs
	items := make([]iterItem, len(keys))
	for i, k := range keys {
		value := db.data[k]
		items[i] = iterItem{
			key:   []byte(k),
			value: append([]byte{}, value...),
		}
	}

	return &memIterator{
		items: items,
		index: -1,
	}
}

// NewIteratorWithLimit creates an iterator with a caller-specified max
// iteration count. For MemDB (in-memory), the limit is honored if > 0 but
// is unnecessary since there is no I/O cost. Pass limit=0 for unlimited.
// AUDIT R4-DATA-02: required by the Database interface so that
// computeStorageRoot can request unlimited iteration.
func (db *MemDB) NewIteratorWithLimit(prefix []byte, start []byte, limit int) Iterator {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.closed {
		return &memIterator{err: ErrDatabaseClosed}
	}

	var keys []string
	for k := range db.data {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == string(prefix)) {
			if start == nil || k >= string(start) {
				keys = append(keys, k)
			}
		}
	}

	sort.Strings(keys)

	// Apply limit if > 0
	var truncated bool
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
		truncated = true
	}

	items := make([]iterItem, len(keys))
	for i, k := range keys {
		value := db.data[k]
		items[i] = iterItem{
			key:   []byte(k),
			value: append([]byte{}, value...),
		}
	}

	it := &memIterator{
		items: items,
		index: -1,
	}
	if truncated {
		it.err = ErrIteratorTruncated
	}
	return it
}

// iterItem holds a key-value pair for iteration
type iterItem struct {
	key   []byte
	value []byte
}

// memIterator is an in-memory iterator implementation
type memIterator struct {
	items []iterItem
	index int
	err   error
}

// Next moves to the next key/value pair
func (it *memIterator) Next() bool {
	it.index++
	return it.index < len(it.items)
}

// Key returns the key of the current key/value pair
func (it *memIterator) Key() []byte {
	if it.index < 0 || it.index >= len(it.items) {
		return nil
	}
	return it.items[it.index].key
}

// Value returns the value of the current key/value pair
func (it *memIterator) Value() []byte {
	if it.index < 0 || it.index >= len(it.items) {
		return nil
	}
	return it.items[it.index].value
}

// Error returns any accumulated error
func (it *memIterator) Error() error {
	return it.err
}

// Release releases resources
func (it *memIterator) Release() {
	it.items = nil
}

// batchOp represents a single batch operation
type batchOp struct {
	key    []byte
	value  []byte
	delete bool
}

// memBatch is an in-memory batch implementation
type memBatch struct {
	db   *MemDB
	ops  []batchOp
	size int
}

// Put adds a put operation to the batch
func (b *memBatch) Put(key, value []byte) error {
	b.ops = append(b.ops, batchOp{
		key:    append([]byte{}, key...),
		value:  append([]byte{}, value...),
		delete: false,
	})
	b.size += len(value)
	return nil
}

// Delete adds a delete operation to the batch
func (b *memBatch) Delete(key []byte) error {
	b.ops = append(b.ops, batchOp{
		key:    append([]byte{}, key...),
		delete: true,
	})
	return nil
}

// Write executes all operations in the batch
func (b *memBatch) Write() error {
	b.db.mu.Lock()
	defer b.db.mu.Unlock()

	if b.db.closed {
		return ErrDatabaseClosed
	}

	for _, op := range b.ops {
		if op.delete {
			delete(b.db.data, string(op.key))
		} else {
			b.db.data[string(op.key)] = op.value
		}
	}

	return nil
}

// Flush commits the currently-accumulated ops and resets the in-memory batch.
// DB-R12-002 (2026-07-20): MemDB does not enforce size limits, so Flush is
// equivalent to Write + Reset. It exists to satisfy the Batch interface so
// callers can write size-limit-agnostic code that uses Flush() to split at
// logical boundaries.
func (b *memBatch) Flush() error {
	if err := b.Write(); err != nil {
		return err
	}
	b.Reset()
	return nil
}

// Reset clears all operations in the batch
func (b *memBatch) Reset() {
	b.ops = b.ops[:0]
	b.size = 0
}

// ValueSize returns the total size of values in the batch
func (b *memBatch) ValueSize() int {
	return b.size
}
