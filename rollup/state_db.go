// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"crypto/sha256"
	"math/big"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// rollupStateDB adapts map[types.Address]*RollupAccount to the qvm.StateDB
// interface, enabling the QVM to read and modify rollup L2 state.
//
// W-P0-2 (2026-07-13): The adapter handles type conversion between
// qvm.Address/qvm.Hash and types.Address/types.Hash (both are [20]byte /
// [32]byte but distinct Go types). Snapshot/RevertToSnapshot use a stack of
// deep-copied state maps so the QVM can roll back failed executions.
type rollupStateDB struct {
	states    map[types.Address]*RollupAccount
	snapshots []map[types.Address]*RollupAccount
}

func newRollupStateDB(states map[types.Address]*RollupAccount) *rollupStateDB {
	return &rollupStateDB{states: states}
}

// --- type conversion helpers ---

func toQVMAddr(a types.Address) qvm.Address {
	var qa qvm.Address
	copy(qa[:], a[:])
	return qa
}

func fromQVMAddr(a qvm.Address) types.Address {
	var ta types.Address
	copy(ta[:], a[:])
	return ta
}

func toQVMHash(h types.Hash) qvm.Hash {
	var qh qvm.Hash
	copy(qh[:], h[:])
	return qh
}

func fromQVMHash(h qvm.Hash) types.Hash {
	var th types.Hash
	copy(th[:], h[:])
	return th
}

// --- Account operations ---

func (s *rollupStateDB) GetBalance(addr qvm.Address) *big.Int {
	acc := s.getOrCreate(fromQVMAddr(addr))
	if acc.Balance == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(acc.Balance)
}

func (s *rollupStateDB) SetBalance(addr qvm.Address, balance *big.Int) {
	acc := s.getOrCreate(fromQVMAddr(addr))
	acc.Balance = new(big.Int).Set(balance)
}

func (s *rollupStateDB) GetNonce(addr qvm.Address) uint64 {
	acc := s.getOrCreate(fromQVMAddr(addr))
	return acc.Nonce
}

func (s *rollupStateDB) SetNonce(addr qvm.Address, nonce uint64) {
	acc := s.getOrCreate(fromQVMAddr(addr))
	acc.Nonce = nonce
}

// --- Code operations ---

func (s *rollupStateDB) GetCode(addr qvm.Address) []byte {
	tAddr := fromQVMAddr(addr)
	acc, ok := s.states[tAddr]
	if !ok {
		return nil
	}
	return acc.Code
}

func (s *rollupStateDB) SetCode(addr qvm.Address, code []byte) {
	acc := s.getOrCreate(fromQVMAddr(addr))
	acc.Code = append([]byte(nil), code...)
	if len(code) == 0 {
		acc.CodeHash = types.Hash{}
		return
	}
	h := sha256.Sum256(code)
	acc.CodeHash = types.Hash(h)
}

func (s *rollupStateDB) GetCodeHash(addr qvm.Address) qvm.Hash {
	tAddr := fromQVMAddr(addr)
	acc, ok := s.states[tAddr]
	if !ok {
		return qvm.Hash{}
	}
	return toQVMHash(acc.CodeHash)
}

func (s *rollupStateDB) GetCodeSize(addr qvm.Address) int {
	tAddr := fromQVMAddr(addr)
	acc, ok := s.states[tAddr]
	if !ok {
		return 0
	}
	return len(acc.Code)
}

// --- Storage operations ---

func (s *rollupStateDB) GetState(addr qvm.Address, key qvm.Hash) qvm.Hash {
	tAddr := fromQVMAddr(addr)
	acc, ok := s.states[tAddr]
	if !ok {
		return qvm.Hash{}
	}
	return toQVMHash(acc.Storage[fromQVMHash(key)])
}

// SetState writes a storage slot. This is the raw journal-less layer:
// atomicity (snapshot/restore) is provided by the callers — the QVM's
// Snapshot/RevertToSnapshot for contract execution, and ProcessBatch's
// deep-copy pre-state restore for batch-level failure rollback.
func (s *rollupStateDB) SetState(addr qvm.Address, key, value qvm.Hash) {
	acc := s.getOrCreate(fromQVMAddr(addr))
	acc.Storage[fromQVMHash(key)] = fromQVMHash(value)
}

// --- Account existence ---

func (s *rollupStateDB) Exist(addr qvm.Address) bool {
	tAddr := fromQVMAddr(addr)
	acc, ok := s.states[tAddr]
	if !ok {
		return false
	}
	return acc.Nonce > 0 || acc.Balance.Sign() > 0 || len(acc.Code) > 0
}

func (s *rollupStateDB) Empty(addr qvm.Address) bool {
	tAddr := fromQVMAddr(addr)
	acc, ok := s.states[tAddr]
	if !ok {
		return true
	}
	return acc.Nonce == 0 && acc.Balance.Sign() == 0 && len(acc.Code) == 0
}

// --- Snapshot and revert ---

func (s *rollupStateDB) Snapshot() int {
	snap := deepCopyAccounts(s.states)
	s.snapshots = append(s.snapshots, snap)
	return len(s.snapshots) - 1
}

func (s *rollupStateDB) RevertToSnapshot(id int) {
	if id < 0 || id >= len(s.snapshots) {
		return
	}
	snap := s.snapshots[id]
	// Clear current state in-place (s.states is the same map as
	// sm.accountStates, so in-place update ensures the live state reflects
	// the rollback).
	for k := range s.states {
		delete(s.states, k)
	}
	restored := deepCopyAccounts(snap)
	for addr, acc := range restored {
		s.states[addr] = acc
	}
	// Truncate the snapshot stack.
	s.snapshots = s.snapshots[:id]
}

// --- Self destruct ---

func (s *rollupStateDB) SelfDestruct(addr qvm.Address) {
	tAddr := fromQVMAddr(addr)
	acc, ok := s.states[tAddr]
	if !ok {
		return
	}
	acc.Balance.SetInt64(0)
	acc.Code = nil
	acc.CodeHash = types.Hash{}
	acc.Storage = make(map[types.Hash]types.Hash)
}

func (s *rollupStateDB) HasSelfDestructed(addr qvm.Address) bool {
	// Rollup does not track self-destruct separately; a destructed account
	// has zero balance and no code.
	tAddr := fromQVMAddr(addr)
	acc, ok := s.states[tAddr]
	if !ok {
		return false
	}
	return len(acc.Code) == 0 && acc.CodeHash == (types.Hash{}) && acc.Balance.Sign() == 0 && len(acc.Storage) == 0
}

// --- Access list (no-op stubs; rollup does not use EIP-2930 access lists) ---

func (s *rollupStateDB) AddAddressToAccessList(addr qvm.Address)             {}
func (s *rollupStateDB) AddSlotToAccessList(addr qvm.Address, slot qvm.Hash) {}
func (s *rollupStateDB) AddressInAccessList(addr qvm.Address) bool           { return false }
func (s *rollupStateDB) SlotInAccessList(addr qvm.Address, slot qvm.Hash) (bool, bool) {
	return false, false
}

// getOrCreate returns the account at addr, creating an empty one if it
// doesn't exist. This mirrors StateManager.getOrCreateAccount behavior.
func (s *rollupStateDB) getOrCreate(addr types.Address) *RollupAccount {
	acc, ok := s.states[addr]
	if !ok {
		acc = &RollupAccount{
			Balance: new(big.Int),
			Storage: make(map[types.Hash]types.Hash),
		}
		s.states[addr] = acc
	}
	return acc
}
