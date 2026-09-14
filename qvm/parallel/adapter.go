// Quantaureum Node source, version 1.0.0.
package parallel

import (
	"math/big"
	"sync"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// qvmStateDBAdapter wraps a parallel StateDB to implement qvm.StateDB interface.
type qvmStateDBAdapter struct {
	stateDB       StateDB
	addressAccess map[qvm.Address]bool
	slotAccess    map[qvm.Address]map[qvm.Hash]bool
	// SECURITY FIX H-3/H-4: Track self-destructed accounts.
	// Previously SelfDestruct was a no-op and HasSelfDestructed always
	// returned false, allowing contracts to continue executing after
	// self-destruct and bypassing self-destruct semantics.
	selfDestructed map[qvm.Address]bool
	// FIX: mu protects addressAccess, slotAccess, and selfDestructed
	// maps from concurrent access. Previously these maps were accessed
	// without synchronization, causing data races when multiple goroutines
	// executed transactions in parallel.
	mu sync.Mutex
}

// newQVMStateDBAdapter creates a new adapter wrapping the parallel StateDB.
func newQVMStateDBAdapter(stateDB StateDB) *qvmStateDBAdapter {
	return &qvmStateDBAdapter{
		stateDB:        stateDB,
		addressAccess:  make(map[qvm.Address]bool),
		slotAccess:     make(map[qvm.Address]map[qvm.Hash]bool),
		selfDestructed: make(map[qvm.Address]bool),
	}
}

// convertAddr converts qvm.Address to types.Address.
func convertAddr(addr qvm.Address) types.Address {
	var tAddr types.Address
	copy(tAddr[:], addr[:])
	return tAddr
}

// convertHash converts qvm.Hash to types.Hash.
func convertHash(hash qvm.Hash) types.Hash {
	var tHash types.Hash
	copy(tHash[:], hash[:])
	return tHash
}

// convertAddrToQVM converts types.Address to qvm.Address.
func convertAddrToQVM(addr types.Address) qvm.Address {
	var qAddr qvm.Address
	copy(qAddr[:], addr[:])
	return qAddr
}

// convertHashToQVM converts types.Hash to qvm.Hash.
func convertHashToQVM(hash types.Hash) qvm.Hash {
	var qHash qvm.Hash
	copy(qHash[:], hash[:])
	return qHash
}

// GetBalance returns the balance of an account.
func (a *qvmStateDBAdapter) GetBalance(addr qvm.Address) *big.Int {
	return a.stateDB.GetBalance(convertAddr(addr))
}

// SetBalance sets the balance of an account.
func (a *qvmStateDBAdapter) SetBalance(addr qvm.Address, balance *big.Int) {
	a.stateDB.SetBalance(convertAddr(addr), balance)
}

// GetNonce returns the nonce of an account.
func (a *qvmStateDBAdapter) GetNonce(addr qvm.Address) uint64 {
	return a.stateDB.GetNonce(convertAddr(addr))
}

// SetNonce sets the nonce of an account.
func (a *qvmStateDBAdapter) SetNonce(addr qvm.Address, nonce uint64) {
	a.stateDB.SetNonce(convertAddr(addr), nonce)
}

// GetCode returns the code of an account.
func (a *qvmStateDBAdapter) GetCode(addr qvm.Address) []byte {
	return a.stateDB.GetCode(convertAddr(addr))
}

// SetCode sets the code of an account.
func (a *qvmStateDBAdapter) SetCode(addr qvm.Address, code []byte) {
	a.stateDB.SetCode(convertAddr(addr), code)
}

// GetCodeHash returns the code hash of an account.
func (a *qvmStateDBAdapter) GetCodeHash(addr qvm.Address) qvm.Hash {
	// Compute hash from code using keccak256
	code := a.stateDB.GetCode(convertAddr(addr))
	if len(code) == 0 {
		return qvm.Hash{}
	}
	return keccak256Hash(code)
}

// GetCodeSize returns the code size of an account.
func (a *qvmStateDBAdapter) GetCodeSize(addr qvm.Address) int {
	return a.stateDB.GetCodeSize(convertAddr(addr))
}

// GetState returns the state value for a given key.
func (a *qvmStateDBAdapter) GetState(addr qvm.Address, key qvm.Hash) qvm.Hash {
	return convertHashToQVM(a.stateDB.GetState(convertAddr(addr), convertHash(key)))
}

// SetState sets the state value for a given key.
func (a *qvmStateDBAdapter) SetState(addr qvm.Address, key, value qvm.Hash) {
	a.stateDB.SetState(convertAddr(addr), convertHash(key), convertHash(value))
}

// Exist returns true if the account exists.
// FIX: Also check balance. Previously only code size and nonce were
// checked, so an account with a non-zero balance but no code and zero nonce
// would be considered non-existent. This is incorrect — an account exists
// if it has any of: code, nonce, or balance.
func (a *qvmStateDBAdapter) Exist(addr qvm.Address) bool {
	tAddr := convertAddr(addr)
	return a.stateDB.GetCodeSize(tAddr) > 0 || a.stateDB.GetNonce(tAddr) > 0 || a.stateDB.GetBalance(tAddr).Sign() > 0
}

// Empty returns true if the account is empty.
func (a *qvmStateDBAdapter) Empty(addr qvm.Address) bool {
	tAddr := convertAddr(addr)
	return a.stateDB.GetBalance(tAddr).Sign() == 0 &&
		a.stateDB.GetNonce(tAddr) == 0 &&
		a.stateDB.GetCodeSize(tAddr) == 0
}

// Snapshot returns a snapshot of the current state.
func (a *qvmStateDBAdapter) Snapshot() int {
	return a.stateDB.Snapshot()
}

// RevertToSnapshot reverts to a previous snapshot.
func (a *qvmStateDBAdapter) RevertToSnapshot(id int) {
	a.stateDB.RevertToSnapshot(id)
}

// SelfDestruct marks an account for self-destruct.
// SECURITY FIX H-3: Previously this was a no-op, allowing contracts to
// continue operating after self-destruct. Now it marks the account as
// destructed and clears its state (balance, nonce, code) to prevent
// further operations. The QVM interpreter is responsible for transferring
// the remaining balance to the beneficiary before calling SelfDestruct.
func (a *qvmStateDBAdapter) SelfDestruct(addr qvm.Address) {
	tAddr := convertAddr(addr)
	// FIX: Protect selfDestructed map with mutex.
	a.mu.Lock()
	a.selfDestructed[addr] = true
	a.mu.Unlock()
	// Clear account state to enforce self-destruct semantics
	a.stateDB.SetBalance(tAddr, big.NewInt(0))
	a.stateDB.SetNonce(tAddr, 0)
	a.stateDB.SetCode(tAddr, nil)
}

// HasSelfDestructed returns true if the account has self-destructed.
// SECURITY FIX H-4: Previously always returned false, allowing destructed
// contracts to be called again. Now returns the actual tracked state.
func (a *qvmStateDBAdapter) HasSelfDestructed(addr qvm.Address) bool {
	// FIX: Protect selfDestructed map with mutex.
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.selfDestructed[addr]
}

// AddAddressToAccessList adds an address to the access list.
func (a *qvmStateDBAdapter) AddAddressToAccessList(addr qvm.Address) {
	// MED-3 FIX: Actually track address access for EIP-2929 gas calculation
	// FIX: Protect addressAccess map with mutex.
	a.mu.Lock()
	defer a.mu.Unlock()
	a.addressAccess[addr] = true
}

// AddSlotToAccessList adds a slot to the access list.
func (a *qvmStateDBAdapter) AddSlotToAccessList(addr qvm.Address, slot qvm.Hash) {
	// MED-3 FIX: Actually track slot access for EIP-2929 gas calculation
	// FIX: Protect slotAccess map with mutex.
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.slotAccess[addr] == nil {
		a.slotAccess[addr] = make(map[qvm.Hash]bool)
	}
	a.slotAccess[addr][slot] = true
}

// AddressInAccessList returns true if the address is in the access list.
// MED-3 FIX: Now properly tracks access and returns cold/warm correctly.
func (a *qvmStateDBAdapter) AddressInAccessList(addr qvm.Address) bool {
	// FIX: Protect addressAccess map with mutex.
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addressAccess[addr]
}

// SlotInAccessList returns true if the slot is in the access list.
// MED-3 FIX: Now properly tracks access and returns cold/warm correctly.
// Returns (inAccessList, isWarm).
func (a *qvmStateDBAdapter) SlotInAccessList(addr qvm.Address, slot qvm.Hash) (bool, bool) {
	// FIX: Protect slotAccess map with mutex.
	a.mu.Lock()
	defer a.mu.Unlock()
	if slots, ok := a.slotAccess[addr]; ok {
		return true, slots[slot]
	}
	return false, false
}

// keccak256Hash computes the Keccak-256 hash of the input data.
func keccak256Hash(data []byte) qvm.Hash {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	var hash qvm.Hash
	copy(hash[:], hasher.Sum(nil))
	return hash
}
