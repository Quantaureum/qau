// Quantaureum Node source, version 1.0.0.
// Package parallel implements Block-STM parallel transaction execution.
package parallel

import (
	"math/big"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/sha3"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// isolatedStateWrapper wraps state access for isolated contract execution.
// It tracks all reads and writes for conflict detection.
type isolatedStateWrapper struct {
	baseState   StateDB
	changes     *StateChanges
	call        *ContractCall
	mvMemory    *MVMemory
	txIndex     int
	incarnation int
	readSet     map[types.Address]map[types.Hash]Version
	writeSet    map[types.Address]map[types.Hash]any
	snapshots   map[int32]*isolatedSnapshot // Snapshot ID -> state at snapshot time (atomic)
	snapshotID  int32                       // Next snapshot ID (atomic)
	// SECURITY FIX: Mutex to protect readSet/writeSet from concurrent access
	// Previously these were accessed without synchronization causing races
	rwMu sync.Mutex
}

// GetBalance reads balance, recording the read.
func (w *isolatedStateWrapper) GetBalance(addr types.Address) *big.Int {
	// Record read
	w.call.AddRead(addr, types.Hash{})

	// Check local changes first
	w.changes.mu.RLock()
	if balance, ok := w.changes.Balances[addr]; ok {
		w.changes.mu.RUnlock()
		// Record read from own write
		w.recordRead(addr, types.Hash{}, Version{TxIndex: w.txIndex, Incarnation: w.incarnation}, balance)
		return new(big.Int).Set(balance)
	}
	w.changes.mu.RUnlock()

	// Try to read from MVMemory
	if balance, version, valid := w.mvMemory.ReadBalance(addr, w.txIndex); valid {
		w.recordRead(addr, types.Hash{}, version, balance)
		return new(big.Int).Set(balance)
	}

	// Fall back to base state
	balance := w.baseState.GetBalance(addr)
	w.recordRead(addr, types.Hash{}, Version{TxIndex: -1, Incarnation: 0}, balance)
	return balance
}

// SetBalance writes balance.
func (w *isolatedStateWrapper) SetBalance(addr types.Address, balance *big.Int) {
	w.changes.SetBalance(addr, balance)
	w.recordWrite(addr, types.Hash{}, balance)
	// Write to MVMemory
	w.mvMemory.WriteBalance(addr, w.txIndex, w.incarnation, balance)
}

// recordRead records a read operation with its version and value.
// CRIT-2 FIX: Now also stores the actual value read to detect value mismatch attacks.
// A malicious validator could commit a tx with same TxIndex/Incarnation but different Value.
func (w *isolatedStateWrapper) recordRead(addr types.Address, key types.Hash, version Version, value any) {
	// SECURITY FIX: Protect readSet with mutex to prevent concurrent map writes
	w.rwMu.Lock()
	defer w.rwMu.Unlock()
	if w.readSet[addr] == nil {
		w.readSet[addr] = make(map[types.Hash]Version)
	}
	version.Value = value // CRIT-2 FIX: Store value for conflict detection
	w.readSet[addr][key] = version
}

// recordWrite records a write operation.
// SECURITY FIX: Protect writeSet with mutex to prevent concurrent map writes
func (w *isolatedStateWrapper) recordWrite(addr types.Address, key types.Hash, value any) {
	w.rwMu.Lock()
	defer w.rwMu.Unlock()
	if w.writeSet[addr] == nil {
		w.writeSet[addr] = make(map[types.Hash]any)
	}
	w.writeSet[addr][key] = value
}

// GetNonce reads nonce, recording the read.
func (w *isolatedStateWrapper) GetNonce(addr types.Address) uint64 {
	var nonceKey types.Hash
	nonceKey[0] = 0x01
	w.call.AddRead(addr, nonceKey)

	w.changes.mu.RLock()
	if nonce, ok := w.changes.Nonces[addr]; ok {
		w.changes.mu.RUnlock()
		w.recordRead(addr, nonceKey, Version{TxIndex: w.txIndex, Incarnation: w.incarnation}, nonce)
		return nonce
	}
	w.changes.mu.RUnlock()

	// Try to read from MVMemory
	if nonce, version, valid := w.mvMemory.ReadNonce(addr, w.txIndex); valid {
		w.recordRead(addr, nonceKey, version, nonce)
		return nonce
	}

	// Fall back to base state
	nonce := w.baseState.GetNonce(addr)
	w.recordRead(addr, nonceKey, Version{TxIndex: -1, Incarnation: 0}, nonce)
	return nonce
}

// SetNonce writes nonce.
func (w *isolatedStateWrapper) SetNonce(addr types.Address, nonce uint64) {
	w.changes.SetNonce(addr, nonce)
	var nonceKey types.Hash
	nonceKey[0] = 0x01
	w.recordWrite(addr, nonceKey, nonce)
	w.mvMemory.WriteNonce(addr, w.txIndex, w.incarnation, nonce)
}

// GetCode reads code, recording the read.
func (w *isolatedStateWrapper) GetCode(addr types.Address) []byte {
	var codeKey types.Hash
	codeKey[0] = 0x02
	w.call.AddRead(addr, codeKey)

	w.changes.mu.RLock()
	if code, ok := w.changes.Code[addr]; ok {
		w.changes.mu.RUnlock()
		w.recordRead(addr, codeKey, Version{TxIndex: w.txIndex, Incarnation: w.incarnation}, code)
		return code
	}
	w.changes.mu.RUnlock()

	// Try to read from MVMemory
	if code, version, valid := w.mvMemory.ReadCode(addr, w.txIndex); valid {
		w.recordRead(addr, codeKey, version, code)
		return code
	}

	// Fall back to base state
	code := w.baseState.GetCode(addr)
	w.recordRead(addr, codeKey, Version{TxIndex: -1, Incarnation: 0}, code)
	return code
}

// SetCode writes code.
func (w *isolatedStateWrapper) SetCode(addr types.Address, code []byte) {
	w.changes.SetCode(addr, code)
	var codeKey types.Hash
	codeKey[0] = 0x02
	w.recordWrite(addr, codeKey, code)
	w.mvMemory.WriteCode(addr, w.txIndex, w.incarnation, code)
}

// GetCodeSize returns code size.
func (w *isolatedStateWrapper) GetCodeSize(addr types.Address) int {
	return len(w.GetCode(addr))
}

// GetState reads storage, recording the read.
func (w *isolatedStateWrapper) GetState(addr types.Address, key types.Hash) types.Hash {
	w.call.AddRead(addr, key)

	w.changes.mu.RLock()
	if slots, ok := w.changes.Storage[addr]; ok {
		if value, ok := slots[key]; ok {
			w.changes.mu.RUnlock()
			w.recordRead(addr, key, Version{TxIndex: w.txIndex, Incarnation: w.incarnation}, value)
			return value
		}
	}
	w.changes.mu.RUnlock()

	// Try to read from MVMemory
	if value, version, valid := w.mvMemory.ReadStorage(addr, key, w.txIndex); valid {
		w.recordRead(addr, key, version, value)
		return value
	}

	// Fall back to base state
	value := w.baseState.GetState(addr, key)
	w.recordRead(addr, key, Version{TxIndex: -1, Incarnation: 0}, value)
	return value
}

// SetState writes storage. Rollback handling: changes are journaled — they
// land in w.changes (MultiVersion memory) and are only committed when the tx
// reaches its post-processing phase; a reorg/abort drops the whole tx's
// version set via RevertToSnapshot.
func (w *isolatedStateWrapper) SetState(addr types.Address, key, value types.Hash) {
	w.changes.SetStorage(addr, key, value)
	w.recordWrite(addr, key, value)
	w.mvMemory.WriteStorage(addr, key, w.txIndex, w.incarnation, value)
}

// isolatedSnapshot captures the full state at a snapshot point for revert.
// V21-015 FIX: In addition to StateChanges, this also saves copies of
// readSet and writeSet so they can be restored on RevertToSnapshot.
// Without this, stale read/write entries from reverted nested calls remain,
// causing false MVCC conflicts and incorrect write tracking.
type isolatedSnapshot struct {
	changes  *StateChanges
	readSet  map[types.Address]map[types.Hash]Version
	writeSet map[types.Address]map[types.Hash]any
}

// copyReadSet creates a deep copy of the readSet map.
func copyReadSet(src map[types.Address]map[types.Hash]Version) map[types.Address]map[types.Hash]Version {
	dst := make(map[types.Address]map[types.Hash]Version, len(src))
	for addr, slots := range src {
		slotsCopy := make(map[types.Hash]Version, len(slots))
		for k, v := range slots {
			slotsCopy[k] = v
		}
		dst[addr] = slotsCopy
	}
	return dst
}

// copyWriteSet creates a deep copy of the writeSet map.
func copyWriteSet(src map[types.Address]map[types.Hash]any) map[types.Address]map[types.Hash]any {
	dst := make(map[types.Address]map[types.Hash]any, len(src))
	for addr, slots := range src {
		slotsCopy := make(map[types.Hash]any, len(slots))
		for k, v := range slots {
			slotsCopy[k] = v
		}
		dst[addr] = slotsCopy
	}
	return dst
}

// Snapshot creates a snapshot of the current state for nested call reversion.
// Returns a unique snapshot ID that should be passed to RevertToSnapshot.
// SECURITY FIX: Use atomic operations for snapshotID to prevent race conditions
func (w *isolatedStateWrapper) Snapshot() int {
	// SECURITY FIX: Use atomic increment to prevent race conditions on snapshot ID
	id := atomic.AddInt32(&w.snapshotID, 1)
	if w.snapshots == nil {
		w.snapshots = make(map[int32]*isolatedSnapshot)
	}

	// V21-015 FIX: Copy readSet and writeSet under rwMu to allow restoration
	// on revert. We copy before calling Merge to avoid holding rwMu while
	// Merge acquires changes.mu (which would reverse the lock ordering in
	// GetBalance: changes.mu -> rwMu, causing a potential deadlock).
	w.rwMu.Lock()
	readSetCopy := copyReadSet(w.readSet)
	writeSetCopy := copyWriteSet(w.writeSet)
	w.rwMu.Unlock()

	// Save a copy of current state for reversion
	snapshot := NewStateChanges()
	snapshot.Merge(w.changes)
	w.snapshots[id] = &isolatedSnapshot{
		changes:  snapshot,
		readSet:  readSetCopy,
		writeSet: writeSetCopy,
	}
	return int(id)
}

// RevertToSnapshot reverts to a previously created snapshot.
// Discards all state changes made after the snapshot was taken.
// SECURITY FIX: Use rwMu to prevent race with concurrent writes that could
// corrupt state or operate on wrong changes object.
func (w *isolatedStateWrapper) RevertToSnapshot(id int) {
	if w.snapshots == nil {
		return
	}

	w.rwMu.Lock()
	defer w.rwMu.Unlock()

	// R36-P2-QVMP-01 FIX: If the snapshot ID is unknown (e.g. double
	// rollback), return immediately without touching mvMemory. Previously
	// the code fell through to w.mvMemory.DeleteVersion below, which
	// deletes ALL versions of this transaction with no replay — losing
	// legitimate pre-snapshot writes and causing consensus divergence.
	// This makes RevertToSnapshot idempotent for unknown IDs, matching
	// the guard already present in mvStateWrapper.RevertToSnapshot.
	snapshot, ok := w.snapshots[int32(id)] //nolint:gosec,G115
	if !ok {
		return
	}

	// R35-P0-03 FIX: Capture the snapshot's writeSet BEFORE deleting it,
	// so we can re-apply the pre-snapshot writes to MVMemory after
	// DeleteVersion removes ALL of this transaction's versions.
	// R36-P1-QVMP-01 FIX: Copy contents instead of pointer swap.
	// The previous fix did w.changes = snapshot.changes (pointer swap),
	// which disconnected result.StateChanges (still pointing to the
	// old object) from the wrapper's ongoing writes (now going to the
	// new snapshot object). MergeResults would then merge stale data.
	// Reset+Merge keeps the pointer identity stable so result.StateChanges
	// stays connected to the wrapper.
	w.changes.Reset()
	w.changes.Merge(snapshot.changes)
	// V21-015 FIX: Restore readSet and writeSet to snapshot state.
	// This removes stale read/write entries from reverted nested calls,
	// preventing false MVCC conflicts and incorrect write tracking.
	w.readSet = snapshot.readSet
	w.writeSet = snapshot.writeSet
	restoredWriteSet := snapshot.writeSet
	delete(w.snapshots, int32(id)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction

	// R40-C4 FIX: Delete only this transaction's writes from mvMemory, not all.
	w.mvMemory.DeleteVersion(w.txIndex, w.incarnation)

	// R35-P0-03 FIX: Re-apply the restored (pre-snapshot) writeSet to
	// MVMemory so legitimate writes are preserved. Without this, the
	// DeleteVersion above would wipe ALL of this transaction's versions,
	// including those committed before the snapshot — causing permanent
	// state loss and consensus divergence.
	if restoredWriteSet != nil {
		w.replayWriteSetToMVMemory(restoredWriteSet)
	}
}

// replayWriteSetToMVMemory re-applies a writeSet to MVMemory.
// R35-P0-03 FIX: Used by RevertToSnapshot to restore pre-snapshot writes
// after DeleteVersion clears all of this transaction's versions.
// Key conventions (must match SetBalance/SetNonce/SetCode/SetState):
//   - types.Hash{} (zero) → balance (*big.Int)
//   - types.Hash{0x01}   → nonce (uint64)
//   - types.Hash{0x02}   → code ([]byte)
//   - any other key      → storage value (types.Hash)
func (w *isolatedStateWrapper) replayWriteSetToMVMemory(writeSet map[types.Address]map[types.Hash]any) {
	var zeroKey types.Hash  // {}
	var nonceKey types.Hash // {0x01}
	nonceKey[0] = 0x01
	var codeKey types.Hash // {0x02}
	codeKey[0] = 0x02

	for addr, slots := range writeSet {
		for key, value := range slots {
			switch key {
			case zeroKey:
				if balance, ok := value.(*big.Int); ok {
					w.mvMemory.WriteBalance(addr, w.txIndex, w.incarnation, balance)
				}
			case nonceKey:
				if nonce, ok := value.(uint64); ok {
					w.mvMemory.WriteNonce(addr, w.txIndex, w.incarnation, nonce)
				}
			case codeKey:
				if code, ok := value.([]byte); ok {
					w.mvMemory.WriteCode(addr, w.txIndex, w.incarnation, code)
				}
			default:
				if sv, ok := value.(types.Hash); ok {
					w.mvMemory.WriteStorage(addr, key, w.txIndex, w.incarnation, sv)
				}
			}
		}
	}
}

// MarkSelfDestruct marks an account for self-destruct in the changes.
func (w *isolatedStateWrapper) MarkSelfDestruct(addr types.Address) {
	w.changes.MarkSelfDestruct(addr)
}

// HasSelfDestructed checks if an account has self-destructed.
func (w *isolatedStateWrapper) HasSelfDestructed(addr types.Address) bool {
	return w.changes.HasSelfDestructed(addr)
}

// AddAddressToAccess adds an address to the access list.
func (w *isolatedStateWrapper) AddAddressToAccess(addr types.Address) {
	w.changes.AddAddressToAccess(addr)
}

// AddressInAccess checks if an address is in the access list.
func (w *isolatedStateWrapper) AddressInAccess(addr types.Address) bool {
	return w.changes.AddressInAccess(addr)
}

// AddSlotToAccess adds a slot to the access list.
func (w *isolatedStateWrapper) AddSlotToAccess(addr types.Address, slot types.Hash) {
	w.changes.AddSlotToAccess(addr, slot)
}

// SlotInAccess checks if a slot is in the access list.
func (w *isolatedStateWrapper) SlotInAccess(addr types.Address, slot types.Hash) bool {
	return w.changes.SlotInAccess(addr, slot)
}

// BaseState returns the base state database.
func (w *isolatedStateWrapper) BaseState() StateDB {
	return w.baseState
}

// qvmStateAdapter adapts isolatedStateWrapper to qvm.StateDB interface.
// It converts between types.Address/types.Hash and qvm.Address/qvm.Hash.
type qvmStateAdapter struct {
	wrapper *isolatedStateWrapper

	// FIX: Cache for GetCodeHash to avoid recomputing Keccak-256
	// on every call. Code hashes are immutable within a single execution
	// (code is set via SetCode which updates the underlying state), so
	// caching is safe within the lifetime of one adapter instance.
	codeHashCache map[qvm.Address]qvm.Hash
	cacheMu       sync.RWMutex
}

// GetBalance reads balance.
func (a *qvmStateAdapter) GetBalance(addr qvm.Address) *big.Int {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	return a.wrapper.GetBalance(typesAddr)
}

// SetBalance writes balance.
func (a *qvmStateAdapter) SetBalance(addr qvm.Address, balance *big.Int) {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	a.wrapper.SetBalance(typesAddr, balance)
}

// GetNonce reads nonce.
func (a *qvmStateAdapter) GetNonce(addr qvm.Address) uint64 {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	return a.wrapper.GetNonce(typesAddr)
}

// SetNonce writes nonce.
func (a *qvmStateAdapter) SetNonce(addr qvm.Address, nonce uint64) {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	a.wrapper.SetNonce(typesAddr, nonce)
}

// GetCode reads code.
func (a *qvmStateAdapter) GetCode(addr qvm.Address) []byte {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	return a.wrapper.GetCode(typesAddr)
}

// SetCode writes code.
func (a *qvmStateAdapter) SetCode(addr qvm.Address, code []byte) {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	a.wrapper.SetCode(typesAddr, code)
	// FIX: Invalidate cached code hash when code changes.
	a.cacheMu.Lock()
	if a.codeHashCache != nil {
		delete(a.codeHashCache, addr)
	}
	a.cacheMu.Unlock()
}

// GetCodeHash returns code hash.
func (a *qvmStateAdapter) GetCodeHash(addr qvm.Address) qvm.Hash {
	// FIX: Check cache first to avoid recomputing Keccak-256 hash.
	a.cacheMu.RLock()
	if a.codeHashCache != nil {
		if hash, ok := a.codeHashCache[addr]; ok {
			a.cacheMu.RUnlock()
			return hash
		}
	}
	a.cacheMu.RUnlock()

	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	code := a.wrapper.GetCode(typesAddr)

	// Compute hash of code
	if len(code) == 0 {
		// Cache empty hash for no code
		a.cacheMu.Lock()
		if a.codeHashCache == nil {
			a.codeHashCache = make(map[qvm.Address]qvm.Hash)
		}
		a.codeHashCache[addr] = qvm.Hash{}
		a.cacheMu.Unlock()
		return qvm.Hash{} // Empty hash for no code
	}

	// Compute Keccak-256 hash (EIP-1052)
	var hash qvm.Hash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(code)
	h := hasher.Sum(nil)
	copy(hash[:], h[:])

	// Store in cache
	a.cacheMu.Lock()
	if a.codeHashCache == nil {
		a.codeHashCache = make(map[qvm.Address]qvm.Hash)
	}
	a.codeHashCache[addr] = hash
	a.cacheMu.Unlock()

	return hash
}

// GetCodeSize returns code size.
func (a *qvmStateAdapter) GetCodeSize(addr qvm.Address) int {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	return a.wrapper.GetCodeSize(typesAddr)
}

// GetState reads storage.
func (a *qvmStateAdapter) GetState(addr qvm.Address, key qvm.Hash) qvm.Hash {
	var typesAddr types.Address
	var typesKey types.Hash
	copy(typesAddr[:], addr[:])
	copy(typesKey[:], key[:])
	typesValue := a.wrapper.GetState(typesAddr, typesKey)
	var qvmValue qvm.Hash
	copy(qvmValue[:], typesValue[:])
	return qvmValue
}

// SetState writes storage (adapter — delegates to the journaled wrapper;
// rollback handling and journal-based atomicity live there).
func (a *qvmStateAdapter) SetState(addr qvm.Address, key, value qvm.Hash) {
	var typesAddr types.Address
	var typesKey, typesValue types.Hash
	copy(typesAddr[:], addr[:])
	copy(typesKey[:], key[:])
	copy(typesValue[:], value[:])
	a.wrapper.SetState(typesAddr, typesKey, typesValue)
}

// Exist checks if account exists.
func (a *qvmStateAdapter) Exist(addr qvm.Address) bool {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	// Check if account has balance, nonce, or code
	balance := a.wrapper.GetBalance(typesAddr)
	nonce := a.wrapper.GetNonce(typesAddr)
	code := a.wrapper.GetCode(typesAddr)
	return balance.Sign() > 0 || nonce > 0 || len(code) > 0
}

// Empty checks if account is empty.
func (a *qvmStateAdapter) Empty(addr qvm.Address) bool {
	return !a.Exist(addr)
}

// Snapshot creates a snapshot.
func (a *qvmStateAdapter) Snapshot() int {
	return a.wrapper.Snapshot()
}

// RevertToSnapshot reverts to snapshot.
func (a *qvmStateAdapter) RevertToSnapshot(id int) {
	a.wrapper.RevertToSnapshot(id)
}

// SelfDestruct marks account for destruction.
func (a *qvmStateAdapter) SelfDestruct(addr qvm.Address) {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	a.wrapper.MarkSelfDestruct(typesAddr)
}

// HasSelfDestructed checks if account self-destructed.
func (a *qvmStateAdapter) HasSelfDestructed(addr qvm.Address) bool {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	return a.wrapper.HasSelfDestructed(typesAddr)
}

// AddAddressToAccessList adds address to access list.
func (a *qvmStateAdapter) AddAddressToAccessList(addr qvm.Address) {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])
	a.wrapper.AddAddressToAccess(typesAddr)
}

// AddSlotToAccessList adds slot to access list.
func (a *qvmStateAdapter) AddSlotToAccessList(addr qvm.Address, slot qvm.Hash) {
	var typesAddr types.Address
	var typesSlot types.Hash
	copy(typesAddr[:], addr[:])
	copy(typesSlot[:], slot[:])
	a.wrapper.AddSlotToAccess(typesAddr, typesSlot)
}

// AddressInAccessList checks if address is in access list.
func (a *qvmStateAdapter) AddressInAccessList(addr qvm.Address) bool {
	var typesAddr types.Address
	copy(typesAddr[:], addr[:])

	// First check our tracked access list
	if a.wrapper.AddressInAccess(typesAddr) {
		return true
	}

	// Fall back to base state's access list
	return a.wrapper.BaseState().AddressInAccessList(typesAddr)
}

// SlotInAccessList checks if slot is in access list.
func (a *qvmStateAdapter) SlotInAccessList(addr qvm.Address, slot qvm.Hash) (addressOk, slotOk bool) {
	var typesAddr types.Address
	var typesSlot types.Hash
	copy(typesAddr[:], addr[:])
	copy(typesSlot[:], slot[:])

	// First check our tracked access list
	addressInAccess := a.wrapper.AddressInAccess(typesAddr)
	slotInAccess := a.wrapper.SlotInAccess(typesAddr, typesSlot)

	if addressInAccess && slotInAccess {
		return true, true
	}

	// QVFIX: If address is in wrapper's access list but slot is not,
	// return warm for address (true) but cold for slot (false)
	if addressInAccess {
		return true, false
	}

	// Fall back to base state's access list
	addrOk := a.wrapper.BaseState().AddressInAccessList(typesAddr)
	slotResultOk, slotResult := a.wrapper.BaseState().SlotInAccessList(typesAddr, typesSlot)
	return addrOk || slotResultOk, slotResult
}
