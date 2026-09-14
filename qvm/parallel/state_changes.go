// Quantaureum Node source, version 1.0.0.
// Package parallel implements Block-STM parallel transaction execution.
package parallel

import (
	"errors"
	"math/big"
	"runtime"
	"sync"
	"unsafe"

	"github.com/quantaureum/qau/types"
)

// ParallelQVM errors
var (
	ErrNoCallsProvided     = errors.New("no contract calls provided")
	ErrCallIndexOutOfRange = errors.New("call index out of range")
	ErrStateMergeFailed    = errors.New("state merge failed")
	ErrExecutionConflict   = errors.New("execution conflict detected")
	// ErrChainIDNotSet is returned when ParallelQVM is executed without an
	// explicit non-zero ChainID (L6-007). ChainID=0 disables EIP-155
	// cross-chain replay protection.
	ErrChainIDNotSet = errors.New("parallel QVM: ChainID must be set to a non-zero value")
	// AUDIT (2026) R4-QVM-01: ParallelQVM.Execute is not consensus-safe —
	// it does not increment the caller's nonce, does not charge intrinsic gas,
	// and (before the QVM-03 fix) used zero block context. The higher-level
	// ParallelExecutor (qvm/parallel/executor.go) wraps Execute and adds
	// these missing checks; production code must use ParallelExecutor, not
	// ParallelQVM.Execute directly. This guard prevents accidental direct
	// use of Execute on the consensus path. Call EnableConsensusMode() to
	// explicitly opt in (after implementing the three missing checks).
	ErrParallelQVMNotConsensusSafe = errors.New("parallel QVM: Execute is not consensus-safe (no nonce increment, no intrinsic gas); use ParallelExecutor or call EnableConsensusMode after implementing the missing checks")
)

// ParallelQVMConfig holds configuration for parallel QVM execution.
type ParallelQVMConfig struct {
	// NumWorkers is the number of parallel worker goroutines.
	NumWorkers int

	// MaxRetries is the maximum number of retries for conflicting calls.
	MaxRetries int

	// EnableSpeculativeExecution enables speculative parallel execution.
	EnableSpeculativeExecution bool

	// ChainID is the blockchain network ID for transaction replay protection.
	// CRITICAL FIX: ChainID must be explicitly set to prevent cross-chain replay attacks.
	ChainID uint64
}

// DefaultParallelQVMConfig returns the default configuration.
func DefaultParallelQVMConfig() *ParallelQVMConfig {
	return &ParallelQVMConfig{
		NumWorkers:                 runtime.NumCPU(),
		MaxRetries:                 5,
		EnableSpeculativeExecution: true,
		// CRITICAL FIX: Default ChainID 0 will cause validation to fail,
		// forcing explicit ChainID configuration
		ChainID: 0,
	}
}

// ContractExecutionResult represents the result of a contract call execution.
type ContractExecutionResult struct {
	Index      int
	Success    bool
	GasUsed    uint64
	ReturnData []byte
	Error      error
	Logs       []*Log

	// State changes made by this call
	StateChanges *StateChanges

	// Read/Write sets for Block-STM validation
	ReadSet  map[types.Address]map[types.Hash]Version // Records read versions
	WriteSet map[types.Address]map[types.Hash]any     // Records written values

	// FIX: Incarnation when this result was produced.
	// Used to detect stale results from aborted incarnations during validation.
	Incarnation int
}

// StateChanges tracks all state modifications made during execution.
type StateChanges struct {
	Balances       map[types.Address]*big.Int
	Nonces         map[types.Address]uint64
	Storage        map[types.Address]map[types.Hash]types.Hash
	Code           map[types.Address][]byte
	SelfDestructed map[types.Address]bool                // Tracks self-destructed accounts
	AddressAccess  map[types.Address]bool                // Tracks accessed addresses
	SlotAccess     map[types.Address]map[types.Hash]bool // Tracks accessed slots
	mu             sync.RWMutex
}

// addrLessThan compares two StateChanges pointers for lock ordering.
// Used to prevent ABBA deadlocks in Merge().
func addrLessThan(a, b *StateChanges) bool {
	// Compare struct memory addresses for consistent lock ordering
	return uintptr(unsafe.Pointer(a)) < uintptr(unsafe.Pointer(b)) // #nosec G103 -- unsafe operation reviewed and deemed necessary for performance
}

// NewStateChanges creates a new StateChanges instance.
func NewStateChanges() *StateChanges {
	return &StateChanges{
		Balances:       make(map[types.Address]*big.Int),
		Nonces:         make(map[types.Address]uint64),
		Storage:        make(map[types.Address]map[types.Hash]types.Hash),
		Code:           make(map[types.Address][]byte),
		SelfDestructed: make(map[types.Address]bool),
		AddressAccess:  make(map[types.Address]bool),
		SlotAccess:     make(map[types.Address]map[types.Hash]bool),
	}
}

// Reset clears all state changes, allowing the same StateChanges pointer
// to be reused. R36-P1-QVMP-01 FIX: Used by RevertToSnapshot to restore
// snapshot contents without pointer swap, keeping result.StateChanges
// connected to the wrapper's ongoing writes.
func (sc *StateChanges) Reset() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for k := range sc.Balances {
		delete(sc.Balances, k)
	}
	for k := range sc.Nonces {
		delete(sc.Nonces, k)
	}
	for k := range sc.Storage {
		delete(sc.Storage, k)
	}
	for k := range sc.Code {
		delete(sc.Code, k)
	}
	for k := range sc.SelfDestructed {
		delete(sc.SelfDestructed, k)
	}
	for k := range sc.AddressAccess {
		delete(sc.AddressAccess, k)
	}
	for k := range sc.SlotAccess {
		delete(sc.SlotAccess, k)
	}
}

// SetBalance records a balance change.
func (sc *StateChanges) SetBalance(addr types.Address, balance *big.Int) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.Balances[addr] = new(big.Int).Set(balance)
}

// SetNonce records a nonce change.
func (sc *StateChanges) SetNonce(addr types.Address, nonce uint64) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.Nonces[addr] = nonce
}

// SetStorage records a storage change.
func (sc *StateChanges) SetStorage(addr types.Address, key, value types.Hash) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.Storage[addr] == nil {
		sc.Storage[addr] = make(map[types.Hash]types.Hash)
	}
	sc.Storage[addr][key] = value
}

// SetCode records a code change.
func (sc *StateChanges) SetCode(addr types.Address, code []byte) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	codeCopy := make([]byte, len(code))
	copy(codeCopy, code)
	sc.Code[addr] = codeCopy
}

// Merge merges another StateChanges into this one.
// Later changes override earlier ones.
// SECURITY FIX: Prevent ABBA deadlock by always acquiring locks in consistent order.
// We compare pointer addresses to determine lock ordering.
func (sc *StateChanges) Merge(other *StateChanges) {
	if other == nil {
		return
	}

	// ABBA deadlock prevention: always lock in consistent address order
	if sc == other {
		sc.mu.Lock()
		defer sc.mu.Unlock()
		sc.mergeInternal(other)
		return
	}

	// Lock in address order to prevent deadlock
	if addrLessThan(sc, other) {
		sc.mu.Lock()
		other.mu.RLock()
		defer func() {
			other.mu.RUnlock()
			sc.mu.Unlock()
		}()
	} else {
		other.mu.RLock()
		sc.mu.Lock()
		defer func() {
			sc.mu.Unlock()
			other.mu.RUnlock()
		}()
	}

	sc.mergeInternal(other)
}

// mergeInternal performs the actual merge work. Caller must hold appropriate locks.
func (sc *StateChanges) mergeInternal(other *StateChanges) {
	for addr, balance := range other.Balances {
		sc.Balances[addr] = new(big.Int).Set(balance)
	}

	for addr, nonce := range other.Nonces {
		sc.Nonces[addr] = nonce
	}

	for addr, slots := range other.Storage {
		if sc.Storage[addr] == nil {
			sc.Storage[addr] = make(map[types.Hash]types.Hash)
		}
		for key, value := range slots {
			sc.Storage[addr][key] = value
		}
	}

	for addr, code := range other.Code {
		codeCopy := make([]byte, len(code))
		copy(codeCopy, code)
		sc.Code[addr] = codeCopy
	}

	// Merge self-destruct state
	for addr := range other.SelfDestructed {
		sc.SelfDestructed[addr] = true
	}

	// Merge address access list
	for addr := range other.AddressAccess {
		sc.AddressAccess[addr] = true
	}

	// Merge slot access list
	for addr, slots := range other.SlotAccess {
		if sc.SlotAccess[addr] == nil {
			sc.SlotAccess[addr] = make(map[types.Hash]bool)
		}
		for slot := range slots {
			sc.SlotAccess[addr][slot] = true
		}
	}
}

// IsEmpty returns true if there are no state changes.
func (sc *StateChanges) IsEmpty() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return len(sc.Balances) == 0 && len(sc.Nonces) == 0 &&
		len(sc.Storage) == 0 && len(sc.Code) == 0 &&
		len(sc.SelfDestructed) == 0 && len(sc.AddressAccess) == 0 &&
		len(sc.SlotAccess) == 0
}

// MarkSelfDestruct marks an account as self-destructed.
func (sc *StateChanges) MarkSelfDestruct(addr types.Address) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.SelfDestructed[addr] = true
}

// HasSelfDestructed checks if an account has been marked as self-destructed.
func (sc *StateChanges) HasSelfDestructed(addr types.Address) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.SelfDestructed[addr]
}

// AddAddressToAccess adds an address to the access list.
func (sc *StateChanges) AddAddressToAccess(addr types.Address) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.AddressAccess[addr] = true
}

// AddressInAccess checks if an address is in the access list.
func (sc *StateChanges) AddressInAccess(addr types.Address) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.AddressAccess[addr]
}

// AddSlotToAccess adds a slot to the access list.
func (sc *StateChanges) AddSlotToAccess(addr types.Address, slot types.Hash) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.SlotAccess[addr] == nil {
		sc.SlotAccess[addr] = make(map[types.Hash]bool)
	}
	sc.SlotAccess[addr][slot] = true
}

// SlotInAccess checks if a slot is in the access list.
func (sc *StateChanges) SlotInAccess(addr types.Address, slot types.Hash) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if slots, ok := sc.SlotAccess[addr]; ok {
		return slots[slot]
	}
	return false
}
