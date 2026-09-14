// Quantaureum Node source, version 1.0.0.
// Package qvmasync provides adapters between different StateDB implementations.
package qvmasync

import (
	"math/big"
	"sync"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// R47-H-H1 FIX: Implement EIP-2929 access list tracking in StateDBAdapter.
// Previously, the access list methods were stubs that returned false/ignored calls.
// This caused ALL storage accesses to be charged at cold prices (2100 gas for SLOAD,
// 2600 for BALANCE) even for warm accesses, overcharging users by up to 20x.
// The adapter now tracks warm addresses and storage slots per EIP-2930 semantics.

// StateDBAdapter wraps a txpool StateDB to implement qvm.StateDB interface.
type StateDBAdapter struct {
	StateDB interface {
		GetBalance(addr types.Address) *big.Int
		SetBalance(addr types.Address, balance *big.Int)
		GetNonce(addr types.Address) uint64
		SetNonce(addr types.Address, nonce uint64)
		GetCode(addr types.Address) []byte
		SetCode(addr types.Address, code []byte)
		GetState(addr types.Address, key types.Hash) types.Hash
		SetState(addr types.Address, key, value types.Hash)
		Snapshot() int
		RevertToSnapshot(id int)
	}

	// V21-018 FIX: Add mutex to protect concurrent access to maps.
	mu                sync.RWMutex
	addressAccessList map[qvm.Address]struct{}
	slotAccessList    map[qvm.Address]map[qvm.Hash]struct{}
	accessSnapshots   []accessSnapshot
	// QV-04 FIX: snapshotIDMap decouples the adapter's snapshot tracking from
	// the underlying StateDB's ID scheme. It maps each StateDB snapshot ID
	// (returned by Snapshot()) to the corresponding index in accessSnapshots.
	// Previously, RevertToSnapshot assumed the StateDB returned sequential IDs
	// starting from 0 that matched slice indices — fragile if the StateDB uses
	// a different scheme (e.g. monotonically increasing, non-zero-based).
	snapshotIDMap map[int]int

	selfDestructed map[qvm.Address]struct{}
}

type accessSnapshot struct {
	addressAccessList map[qvm.Address]struct{}
	slotAccessList    map[qvm.Address]map[qvm.Hash]struct{}
	selfDestructed    map[qvm.Address]struct{}
}

// Snapshot captures both the underlying StateDB snapshot and the access list snapshot.
// Returns the StateDB snapshot ID. Callers should use this method for all snapshot
// operations to ensure the access list is properly snapshotted.
// R47-H-H1 FIX: Previously delegated to embedded StateDB, now coordinates both.
// QV-04 FIX: The returned ID is the underlying StateDB's snapshot ID. The adapter
// maintains an internal map (snapshotIDMap) to translate it to the correct
// accessSnapshots index, so non-sequential or non-zero-based StateDB IDs work
// correctly.
func (a *StateDBAdapter) Snapshot() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	snap := accessSnapshot{}
	if a.addressAccessList != nil {
		snap.addressAccessList = make(map[qvm.Address]struct{}, len(a.addressAccessList))
		for k, v := range a.addressAccessList {
			snap.addressAccessList[k] = v
		}
	}
	if a.slotAccessList != nil {
		snap.slotAccessList = make(map[qvm.Address]map[qvm.Hash]struct{}, len(a.slotAccessList))
		for addr, slots := range a.slotAccessList {
			snap.slotAccessList[addr] = make(map[qvm.Hash]struct{}, len(slots))
			for k, v := range slots {
				snap.slotAccessList[addr][k] = v
			}
		}
	}
	if a.selfDestructed != nil {
		snap.selfDestructed = make(map[qvm.Address]struct{}, len(a.selfDestructed))
		for k := range a.selfDestructed {
			snap.selfDestructed[k] = struct{}{}
		}
	}

	// QV-04 FIX: Obtain the StateDB snapshot ID first, then record the mapping
	// from that ID to the index in accessSnapshots. This avoids assuming the
	// StateDB returns sequential zero-based IDs.
	stateDBID := a.StateDB.Snapshot()
	if a.snapshotIDMap == nil {
		a.snapshotIDMap = make(map[int]int)
	}
	a.snapshotIDMap[stateDBID] = len(a.accessSnapshots)
	a.accessSnapshots = append(a.accessSnapshots, snap)

	return stateDBID
}

// RevertToSnapshot reverts both the underlying StateDB and the access list.
// R47-H-H1 FIX: Previously delegated to embedded StateDB, now coordinates both.
// QV-04 FIX: Uses snapshotIDMap to look up the correct index in accessSnapshots
// instead of assuming the snapshot ID equals the slice index.
func (a *StateDBAdapter) RevertToSnapshot(snapshotID int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// QV-04 FIX: Look up the accessSnapshots index via the map rather than
	// assuming snapshotID == index.
	if idx, ok := a.snapshotIDMap[snapshotID]; ok && idx >= 0 && idx < len(a.accessSnapshots) {
		snap := a.accessSnapshots[idx]
		a.addressAccessList = snap.addressAccessList
		a.slotAccessList = snap.slotAccessList
		a.selfDestructed = snap.selfDestructed
		// Truncate the slice: remove the reverted snapshot and all subsequent ones.
		a.accessSnapshots = a.accessSnapshots[:idx]
		// Clean up map entries for the removed indices.
		for id, i := range a.snapshotIDMap {
			if i >= idx {
				delete(a.snapshotIDMap, id)
			}
		}
	}

	a.StateDB.RevertToSnapshot(snapshotID)
}

// ConvertAddress converts qvm.Address to types.Address.
func ConvertAddress(addr qvm.Address) types.Address {
	return types.Address(addr)
}

// ConvertHash converts qvm.Hash to types.Hash.
func ConvertHash(hash qvm.Hash) types.Hash {
	return types.Hash(hash)
}

// ConvertAddressToQVM converts types.Address to qvm.Address.
func ConvertAddressToQVM(addr types.Address) qvm.Address {
	return qvm.Address(addr)
}

// ConvertHashToQVM converts types.Hash to qvm.Hash.
func ConvertHashToQVM(hash types.Hash) qvm.Hash {
	return qvm.Hash(hash)
}

// GetBalance returns the balance of an account.
func (a *StateDBAdapter) GetBalance(addr qvm.Address) *big.Int {
	return a.StateDB.GetBalance(ConvertAddress(addr))
}

// SetBalance sets the balance of an account.
func (a *StateDBAdapter) SetBalance(addr qvm.Address, balance *big.Int) {
	a.StateDB.SetBalance(ConvertAddress(addr), balance)
}

// GetNonce returns the nonce of an account.
func (a *StateDBAdapter) GetNonce(addr qvm.Address) uint64 {
	return a.StateDB.GetNonce(ConvertAddress(addr))
}

// SetNonce sets the nonce of an account.
func (a *StateDBAdapter) SetNonce(addr qvm.Address, nonce uint64) {
	a.StateDB.SetNonce(ConvertAddress(addr), nonce)
}

// GetCode returns the code of an account.
func (a *StateDBAdapter) GetCode(addr qvm.Address) []byte {
	return a.StateDB.GetCode(ConvertAddress(addr))
}

// SetCode sets the code of an account.
func (a *StateDBAdapter) SetCode(addr qvm.Address, code []byte) {
	a.StateDB.SetCode(ConvertAddress(addr), code)
}

// GetCodeHash returns the code hash of an account.
// Computes the hash from code since txpool StateDB doesn't store code hash.
func (a *StateDBAdapter) GetCodeHash(addr qvm.Address) qvm.Hash {
	code := a.StateDB.GetCode(ConvertAddress(addr))
	if len(code) == 0 {
		return qvm.Hash{}
	}
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(code)
	var hash qvm.Hash
	copy(hash[:], hasher.Sum(nil))
	return hash
}

// GetCodeSize returns the code size of an account.
// Computes size from code since txpool StateDB doesn't have GetCodeSize.
func (a *StateDBAdapter) GetCodeSize(addr qvm.Address) int {
	return len(a.StateDB.GetCode(ConvertAddress(addr)))
}

// GetState returns the state value for a given key.
func (a *StateDBAdapter) GetState(addr qvm.Address, key qvm.Hash) qvm.Hash {
	return qvm.Hash(a.StateDB.GetState(ConvertAddress(addr), ConvertHash(key)))
}

// committedStateReader is an optional capability of the wrapped StateDB to
// return the storage value committed at the start of the transaction. Used for
// EIP-3529 gas refund calculation. If the wrapped DB does not implement it,
// GetCommittedState falls back to GetState (the live value).
type committedStateReader interface {
	GetCommittedState(addr types.Address, key types.Hash) types.Hash
}

// GetCommittedState returns the storage value committed at the start of the
// transaction (EIP-3529). If the wrapped StateDB supports committed reads it
// delegates; otherwise it falls back to the current live value (GetState).
func (a *StateDBAdapter) GetCommittedState(addr qvm.Address, key qvm.Hash) qvm.Hash {
	tAddr := ConvertAddress(addr)
	tKey := ConvertHash(key)
	if cr, ok := a.StateDB.(committedStateReader); ok {
		return qvm.Hash(cr.GetCommittedState(tAddr, tKey))
	}
	return qvm.Hash(a.StateDB.GetState(tAddr, tKey))
}

// SetState sets the state value for a given key.
func (a *StateDBAdapter) SetState(addr qvm.Address, key, value qvm.Hash) {
	a.StateDB.SetState(ConvertAddress(addr), ConvertHash(key), ConvertHash(value))
}

// Exist returns true if the account exists.
func (a *StateDBAdapter) Exist(addr qvm.Address) bool {
	addr2 := ConvertAddress(addr)
	return a.StateDB.GetBalance(addr2).Sign() != 0 ||
		a.StateDB.GetNonce(addr2) != 0 ||
		len(a.StateDB.GetCode(addr2)) > 0
}

// Empty returns true if the account is empty.
func (a *StateDBAdapter) Empty(addr qvm.Address) bool {
	addr2 := ConvertAddress(addr)
	return a.StateDB.GetBalance(addr2).Sign() == 0 &&
		a.StateDB.GetNonce(addr2) == 0 &&
		len(a.StateDB.GetCode(addr2)) == 0
}

// SelfDestruct marks an account for self-destruct.
// R46-QV-03 FIX: Add mutex protection for selfDestructed map access.
func (a *StateDBAdapter) SelfDestruct(addr qvm.Address) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.StateDB.SetBalance(ConvertAddress(addr), big.NewInt(0))
	a.StateDB.SetCode(ConvertAddress(addr), nil)
	a.StateDB.SetNonce(ConvertAddress(addr), 0)
	if a.selfDestructed == nil {
		a.selfDestructed = make(map[qvm.Address]struct{})
	}
	a.selfDestructed[addr] = struct{}{}
}

func (a *StateDBAdapter) HasSelfDestructed(addr qvm.Address) bool {
	// QV-01 FIX: Read-only operation; use RLock/RUnlock instead of Lock/Unlock
	// to avoid unnecessary write-lock contention.
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.selfDestructed == nil {
		return false
	}
	_, ok := a.selfDestructed[addr]
	return ok
}

// AddAddressToAccessList adds an address to the access list (marks as warm).
// R47-H-H1 FIX: Previously a stub. Now properly tracks warm addresses per EIP-2929.
func (a *StateDBAdapter) AddAddressToAccessList(addr qvm.Address) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.addressAccessList == nil {
		a.addressAccessList = make(map[qvm.Address]struct{})
	}
	a.addressAccessList[addr] = struct{}{}
}

// AddSlotToAccessList adds a slot to the access list (marks as warm).
// Also marks the containing address as warm.
// R47-H-H1 FIX: Previously a stub. Now properly tracks warm slots per EIP-2929.
func (a *StateDBAdapter) AddSlotToAccessList(addr qvm.Address, slot qvm.Hash) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// V21-018 FIX: Inline address add to avoid recursive locking
	if a.addressAccessList == nil {
		a.addressAccessList = make(map[qvm.Address]struct{})
	}
	a.addressAccessList[addr] = struct{}{}

	if a.slotAccessList == nil {
		a.slotAccessList = make(map[qvm.Address]map[qvm.Hash]struct{})
	}
	if a.slotAccessList[addr] == nil {
		a.slotAccessList[addr] = make(map[qvm.Hash]struct{})
	}
	a.slotAccessList[addr][slot] = struct{}{}
}

// AddressInAccessList returns true if the address is in the access list (warm).
// R47-H-H1 FIX: Previously always returned false (stub).
func (a *StateDBAdapter) AddressInAccessList(addr qvm.Address) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.addressAccessList == nil {
		return false
	}
	_, ok := a.addressAccessList[addr]
	return ok
}

// SlotInAccessList returns (addressWarm, slotWarm) for EIP-2929 gas calculation.
// R47-H-H1 FIX: Previously always returned (false, false) (stub).
// The first return value indicates if the address was already warm.
// The second return value indicates if the slot was already warm.
func (a *StateDBAdapter) SlotInAccessList(addr qvm.Address, slot qvm.Hash) (bool, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	// V21-018 FIX: Inline address check to avoid recursive RLock deadlock
	var addrWarm bool
	if a.addressAccessList != nil {
		_, addrWarm = a.addressAccessList[addr]
	}

	var slotWarm bool
	if a.slotAccessList != nil {
		if slots, ok := a.slotAccessList[addr]; ok {
			_, slotWarm = slots[slot]
		}
	}
	return addrWarm, slotWarm
}
