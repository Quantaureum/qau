// Quantaureum Node source, version 1.0.0.
// Package parallel implements Block-STM parallel transaction execution.
package parallel

import (
	"math/big"
	"sync"

	"github.com/quantaureum/qau/types"
)

// Version represents a version of a value in multi-version memory.
// CRIT-1 FIX: Added Value field to prevent malicious validator attacks.
// A validator could commit a transaction with same TxIndex/Incarnation but
// different Value (e.g., transfer 100 instead of 50). Now we compare Values.
type Version struct {
	TxIndex     int
	Incarnation int
	Value       any // CRIT-1 FIX: Actual value for conflict detection
}

// MVEntry represents an entry in multi-version memory.
type MVEntry struct {
	Value      any
	Version    Version
	IsEstimate bool // True if this is an estimated value (not yet validated)
}

// ReadDescriptor records a read operation.
type ReadDescriptor struct {
	Key     any
	Version Version
}

// WriteDescriptor records a write operation.
type WriteDescriptor struct {
	Key   any
	Value any
}

// sortedVersions stores versions in a sorted slice for efficient lookup
type sortedVersions struct {
	mu       sync.RWMutex
	versions []versionEntry
}

// versionEntry stores a version with its transaction index
type versionEntry struct {
	txIndex     int
	value       any
	incarnation int
	isEstimate  bool
}

// MVMemory implements multi-version memory for Block-STM.
// It stores multiple versions of each key, indexed by transaction index.
//
// Version Tracking:
//   - Each write is tagged with (txIndex, incarnation) to uniquely identify it
//   - Reads return the latest version with txIndex < reader's txIndex
//   - Versions are stored in sorted order for efficient binary search lookup
//   - This enables optimistic concurrency: transactions read speculative values
//     and validation ensures reads remain consistent with final write order
//
// Memory Management:
// - Versions are stored in sorted slices, bounded by number of transactions
// - Clear() resets all version history between execution batches
// - DeleteVersion() removes aborted transaction writes during retry
type MVMemory struct {
	// Account balances: address -> sorted versions
	balances sync.Map

	// Account nonces: address -> sorted versions
	nonces sync.Map

	// Storage: (address, key) -> sorted versions
	storage sync.Map

	// Code: address -> sorted versions
	code sync.Map
}

// NewMVMemory creates a new multi-version memory.
func NewMVMemory() *MVMemory {
	return &MVMemory{}
}

// storageKey combines address and storage key.
type storageKey struct {
	addr types.Address
	key  types.Hash
}

// versionedValue stores a value with its version.
type versionedValue struct {
	value       any
	incarnation int
	isEstimate  bool
}

// getVersionMap gets or creates a version map for a key.
func (m *MVMemory) getVersionMap(store *sync.Map, key any) *sortedVersions {
	value, _ := store.LoadOrStore(key, &sortedVersions{})
	return value.(*sortedVersions) //nolint:errcheck
}

// add adds a version entry to the sorted slice, maintaining order
func (s *sortedVersions) add(txIndex, incarnation int, value any, isEstimate bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create new entry
	entry := versionEntry{
		txIndex:     txIndex,
		value:       value,
		incarnation: incarnation,
		isEstimate:  isEstimate,
	}

	// Find insertion point using binary search
	left, right := 0, len(s.versions)-1
	insertAt := len(s.versions)

	for left <= right {
		mid := left + (right-left)/2
		if s.versions[mid].txIndex > txIndex {
			insertAt = mid
			right = mid - 1
		} else if s.versions[mid].txIndex < txIndex {
			left = mid + 1
		} else {
			// Replace existing entry for this txIndex
			s.versions[mid] = entry
			return
		}
	}

	// Insert new entry
	s.versions = append(s.versions, versionEntry{})
	copy(s.versions[insertAt+1:], s.versions[insertAt:])
	s.versions[insertAt] = entry
}

// WriteBalance writes a balance value for a transaction.
func (m *MVMemory) WriteBalance(addr types.Address, txIndex, incarnation int, balance *big.Int) {
	versions := m.getVersionMap(&m.balances, addr)
	versions.add(txIndex, incarnation, new(big.Int).Set(balance), false)
}

// find finds the latest version entry less than txIndex.
// audit-fix R7-8: returns a copy (not pointer) to prevent stale pointer after
// slice reallocation by concurrent add() calls.
func (s *sortedVersions) find(txIndex int) (versionEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Binary search for the largest entry with txIndex < target
	left, right := 0, len(s.versions)-1
	foundIdx := -1

	for left <= right {
		mid := left + (right-left)/2
		if s.versions[mid].txIndex < txIndex {
			// This is a candidate, look for larger candidates
			foundIdx = mid
			left = mid + 1
		} else {
			// Look in left half
			right = mid - 1
		}
	}

	if foundIdx < 0 {
		return versionEntry{}, false
	}
	return s.versions[foundIdx], true
}

// ReadBalance reads the latest balance visible to a transaction.
func (m *MVMemory) ReadBalance(addr types.Address, txIndex int) (*big.Int, Version, bool) {
	versions := m.getVersionMap(&m.balances, addr)

	// Find the highest version less than txIndex using binary search
	result, found := versions.find(txIndex)
	if !found {
		return nil, Version{}, false
	}

	// V21-004 FIX: Use comma-ok type assertion to prevent panic on type mismatch
	val, ok := result.value.(*big.Int)
	if !ok {
		return nil, Version{}, false
	}
	// CRIT-1 (R8 2026-07-19) FIX (defensive depth): Populate Version.Value with
	// a defensive copy of the balance so callers that bypass isolated_state.go
	// (which fills Value via recordRead) still receive the actual value for
	// conflict detection. Without this, a future code path could compare
	// (TxIndex, Incarnation) only and miss a malicious validator committing
	// same-version-but-different-value writes.
	return val, Version{
		TxIndex:     result.txIndex,
		Incarnation: result.incarnation,
		Value:       new(big.Int).Set(val),
	}, !result.isEstimate
}

// WriteNonce writes a nonce value for a transaction.
func (m *MVMemory) WriteNonce(addr types.Address, txIndex, incarnation int, nonce uint64) {
	versions := m.getVersionMap(&m.nonces, addr)
	versions.add(txIndex, incarnation, nonce, false)
}

// ReadNonce reads the latest nonce visible to a transaction.
func (m *MVMemory) ReadNonce(addr types.Address, txIndex int) (uint64, Version, bool) {
	versions := m.getVersionMap(&m.nonces, addr)
	result, found := versions.find(txIndex)
	if !found {
		return 0, Version{}, false
	}

	// V21-004 FIX: Use comma-ok type assertion to prevent panic on type mismatch
	val, ok := result.value.(uint64)
	if !ok {
		return 0, Version{}, false
	}
	// CRIT-1 (R8 2026-07-19) FIX (defensive depth): Populate Version.Value.
	return val, Version{
		TxIndex:     result.txIndex,
		Incarnation: result.incarnation,
		Value:       val,
	}, !result.isEstimate
}

// WriteStorage writes a storage value for a transaction.
func (m *MVMemory) WriteStorage(addr types.Address, key types.Hash, txIndex, incarnation int, value types.Hash) {
	sk := storageKey{addr: addr, key: key}
	versions := m.getVersionMap(&m.storage, sk)
	versions.add(txIndex, incarnation, value, false)
}

// ReadStorage reads the latest storage value visible to a transaction.
func (m *MVMemory) ReadStorage(addr types.Address, key types.Hash, txIndex int) (types.Hash, Version, bool) {
	sk := storageKey{addr: addr, key: key}
	versions := m.getVersionMap(&m.storage, sk)
	result, found := versions.find(txIndex)
	if !found {
		return types.Hash{}, Version{}, false
	}

	// V21-004 FIX: Use comma-ok type assertion to prevent panic on type mismatch
	val, ok := result.value.(types.Hash)
	if !ok {
		return types.Hash{}, Version{}, false
	}
	// CRIT-1 (R8 2026-07-19) FIX (defensive depth): Populate Version.Value.
	return val, Version{
		TxIndex:     result.txIndex,
		Incarnation: result.incarnation,
		Value:       val,
	}, !result.isEstimate
}

// WriteCode writes contract code for a transaction.
func (m *MVMemory) WriteCode(addr types.Address, txIndex, incarnation int, code []byte) {
	versions := m.getVersionMap(&m.code, addr)
	codeCopy := make([]byte, len(code))
	copy(codeCopy, code)
	versions.add(txIndex, incarnation, codeCopy, false)
}

// ReadCode reads the latest code visible to a transaction.
func (m *MVMemory) ReadCode(addr types.Address, txIndex int) ([]byte, Version, bool) {
	versions := m.getVersionMap(&m.code, addr)
	result, found := versions.find(txIndex)
	if !found {
		return nil, Version{}, false
	}

	// V21-004 FIX: Use comma-ok type assertion to prevent panic on type mismatch
	val, ok := result.value.([]byte)
	if !ok {
		return nil, Version{}, false
	}
	// CRIT-1 (R8 2026-07-19) FIX (defensive depth): Populate Version.Value with
	// a defensive copy of the code so callers can use it for conflict detection
	// without aliasing the stored slice.
	return val, Version{
		TxIndex:     result.txIndex,
		Incarnation: result.incarnation,
		Value:       append([]byte(nil), val...),
	}, !result.isEstimate
}

// deleteVersion deletes all entries with the given txIndex and incarnation.
// H-3 FIX: Added incarnation check to prevent race condition where a retry
// could replace the entry between find and delete.
func (s *sortedVersions) deleteVersion(txIndex, incarnation int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Binary search for the entry with matching txIndex
	left, right := 0, len(s.versions)-1
	for left <= right {
		mid := left + (right-left)/2
		if s.versions[mid].txIndex == txIndex {
			// H-3 FIX: Verify incarnation matches before deleting
			// If incarnation does not match, the entry was replaced by a retry
			// and should not be deleted
			if s.versions[mid].incarnation != incarnation {
				return
			}
			// Found the entry with matching version, delete it
			s.versions = append(s.versions[:mid], s.versions[mid+1:]...)
			return
		} else if s.versions[mid].txIndex < txIndex {
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
}

// DeleteVersion deletes all writes from a transaction.
// H-3 FIX: Added incarnation parameter to verify version before deletion.
func (m *MVMemory) DeleteVersion(txIndex, incarnation int) {
	deleteVersion := func(store *sync.Map) {
		store.Range(func(key, value any) bool {
			versions := value.(*sortedVersions)
			versions.deleteVersion(txIndex, incarnation)
			return true
		})
	}

	deleteVersion(&m.balances)
	deleteVersion(&m.nonces)
	deleteVersion(&m.storage)
	deleteVersion(&m.code)
}

// Clear clears all multi-version memory.
func (m *MVMemory) Clear() {
	m.balances = sync.Map{}
	m.nonces = sync.Map{}
	m.storage = sync.Map{}
	m.code = sync.Map{}
}
