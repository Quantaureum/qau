// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"
)

// fuzzStateDB is a simple StateDB implementation for fuzzing
type fuzzStateDB struct {
	balances       map[Address]*big.Int
	storage        map[Address]map[Hash]Hash
	codes          map[Address][]byte
	nonces         map[Address]uint64
	selfDestructed map[Address]bool
	accessList     *AccessList
	snapshotID     int
	snapshots      []fuzzSnapshot
}

type fuzzSnapshot struct {
	balances       map[Address]*big.Int
	storage        map[Address]map[Hash]Hash
	codes          map[Address][]byte
	nonces         map[Address]uint64
	selfDestructed map[Address]bool
}

func newFuzzStateDB() *fuzzStateDB {
	return &fuzzStateDB{
		balances:       make(map[Address]*big.Int),
		storage:        make(map[Address]map[Hash]Hash),
		codes:          make(map[Address][]byte),
		nonces:         make(map[Address]uint64),
		selfDestructed: make(map[Address]bool),
		accessList:     NewAccessList(),
	}
}

func (s *fuzzStateDB) GetBalance(addr Address) *big.Int {
	if b, ok := s.balances[addr]; ok {
		return new(big.Int).Set(b)
	}
	return new(big.Int)
}

func (s *fuzzStateDB) SetBalance(addr Address, balance *big.Int) {
	s.balances[addr] = new(big.Int).Set(balance)
}

func (s *fuzzStateDB) GetNonce(addr Address) uint64 {
	return s.nonces[addr]
}

func (s *fuzzStateDB) SetNonce(addr Address, nonce uint64) {
	s.nonces[addr] = nonce
}

func (s *fuzzStateDB) GetCode(addr Address) []byte {
	if code, ok := s.codes[addr]; ok {
		cpy := make([]byte, len(code))
		copy(cpy, code)
		return cpy
	}
	return nil
}

func (s *fuzzStateDB) SetCode(addr Address, code []byte) {
	cpy := make([]byte, len(code))
	copy(cpy, code)
	s.codes[addr] = cpy
}

func (s *fuzzStateDB) GetCodeHash(addr Address) Hash {
	code, ok := s.codes[addr]
	if !ok || len(code) == 0 {
		return Hash{}
	}
	// simple hash computation for fuzzing
	var h Hash
	copy(h[:], code[:min(len(code), 32)])
	return h
}

func (s *fuzzStateDB) GetCodeSize(addr Address) int {
	if code, ok := s.codes[addr]; ok {
		return len(code)
	}
	return 0
}

func (s *fuzzStateDB) GetState(addr Address, key Hash) Hash {
	if storage, ok := s.storage[addr]; ok {
		return storage[key]
	}
	return Hash{}
}

func (s *fuzzStateDB) SetState(addr Address, key, value Hash) {
	if s.storage[addr] == nil {
		s.storage[addr] = make(map[Hash]Hash)
	}
	s.storage[addr][key] = value
}

func (s *fuzzStateDB) Exist(addr Address) bool {
	_, hasBalance := s.balances[addr]
	_, hasCode := s.codes[addr]
	_, hasNonce := s.nonces[addr]
	return hasBalance || hasCode || hasNonce
}

func (s *fuzzStateDB) Empty(addr Address) bool {
	balance := s.GetBalance(addr)
	code := s.GetCode(addr)
	nonce := s.GetNonce(addr)
	return balance.Sign() == 0 && len(code) == 0 && nonce == 0
}

func (s *fuzzStateDB) Snapshot() int {
	id := s.snapshotID
	s.snapshotID++

	snap := fuzzSnapshot{
		balances:       make(map[Address]*big.Int),
		storage:        make(map[Address]map[Hash]Hash),
		codes:          make(map[Address][]byte),
		nonces:         make(map[Address]uint64),
		selfDestructed: make(map[Address]bool),
	}

	for k, v := range s.balances {
		snap.balances[k] = new(big.Int).Set(v)
	}
	for k, v := range s.storage {
		snap.storage[k] = make(map[Hash]Hash)
		for kk, vv := range v {
			snap.storage[k][kk] = vv
		}
	}
	for k, v := range s.codes {
		cpy := make([]byte, len(v))
		copy(cpy, v)
		snap.codes[k] = cpy
	}
	for k, v := range s.nonces {
		snap.nonces[k] = v
	}
	for k, v := range s.selfDestructed {
		snap.selfDestructed[k] = v
	}

	s.snapshots = append(s.snapshots, snap)
	return id
}

func (s *fuzzStateDB) RevertToSnapshot(id int) {
	if id < 0 || id >= len(s.snapshots) {
		return
	}
	snap := s.snapshots[id]
	s.balances = snap.balances
	s.storage = snap.storage
	s.codes = snap.codes
	s.nonces = snap.nonces
	s.selfDestructed = snap.selfDestructed
}

func (s *fuzzStateDB) SelfDestruct(addr Address) {
	s.selfDestructed[addr] = true
	delete(s.balances, addr)
	delete(s.codes, addr)
	delete(s.storage, addr)
}

func (s *fuzzStateDB) HasSelfDestructed(addr Address) bool {
	return s.selfDestructed[addr]
}

func (s *fuzzStateDB) AddAddressToAccessList(addr Address) {
	s.accessList.AddAddress(addr)
}

func (s *fuzzStateDB) AddSlotToAccessList(addr Address, slot Hash) {
	s.accessList.AddSlot(addr, slot)
}

func (s *fuzzStateDB) AddressInAccessList(addr Address) bool {
	return s.accessList.IsAddressWarm(addr)
}

func (s *fuzzStateDB) SlotInAccessList(addr Address, slot Hash) (addressOk, slotOk bool) {
	addressOk = s.accessList.IsAddressWarm(addr)
	slotOk = s.accessList.IsSlotWarm(addr, slot)
	return
}

// newFuzzExecutionContext builds an execution context for fuzzing
func newFuzzExecutionContext(bytecode []byte) *ExecutionContext {
	return &ExecutionContext{
		Origin:      Address{},
		GasPrice:    big.NewInt(1),
		Caller:      Address{1},
		Address:     Address{2},
		Value:       big.NewInt(0),
		BlockNumber: 100,
		Timestamp:   1000000,
		Coinbase:    Address{},
		GasLimit:    1000000,
		ChainID:     1668,
		BlockHashes: make(map[uint64]Hash),
		Code:        bytecode,
		Input:       nil,
		Gas:         1000000,
		Depth:       0,
		ReadOnly:    false,
	}
}

// FuzzBytecodeExecution: arbitrary bytecode must never cause a panic
func FuzzBytecodeExecution(f *testing.F) {
	// seed corpus: various legal and illegal bytecode sequences
	f.Add([]byte{0x00})                                           // STOP
	f.Add([]byte{0x60, 0x01, 0x60, 0x02, 0x20})                   // PUSH1 1, PUSH1 2, ADD
	f.Add([]byte{0x60, 0x05, 0x60, 0x03, 0x23})                   // PUSH1 5, PUSH1 3, DIV
	f.Add([]byte{0x60, 0x01, 0x01})                               // PUSH1 1, ADD (stack underflow)
	f.Add([]byte{0x60, 0x01, 0x56})                               // PUSH1 1, JUMP (invalid dest)
	f.Add([]byte{0x60, 0x01, 0x60, 0x02, 0x61})                   // PUSH1 1, PUSH1 2, INVALID
	f.Add([]byte{0x03, 0x60, 0x00})                               // JUMPDEST, PUSH1 0
	f.Add([]byte{0xFF})                                           // undefined opcode
	f.Add([]byte{})                                               // empty bytecode
	f.Add([]byte{0x60, 0xFF, 0x60, 0xFF, 0x60, 0xFF, 0x20, 0x20}) // chained arithmetic

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		if len(bytecode) > 1024 {
			return // size cap to prevent timeouts
		}
		interp := NewInterpreter()
		ctx := newFuzzExecutionContext(bytecode)
		stateDB := newFuzzStateDB()
		// errors are not checked; only no-panic matters
		result := interp.Execute(ctx, stateDB)
		_ = result
	})
}

// FuzzStackOperations: stack-op boundary conditions
func FuzzStackOperations(f *testing.F) {
	// seed corpus: bytecode focused on stack ops
	f.Add([]byte{0x16})                         // POP (empty stack)
	f.Add([]byte{0x60, 0x01, 0x16})             // PUSH1 1, POP
	f.Add([]byte{0x60, 0x01, 0x17})             // PUSH1 1, DUP1
	f.Add([]byte{0x60, 0x01, 0x60, 0x02, 0x1B}) // PUSH1 1, PUSH1 2, SWAP1
	f.Add([]byte{0x17})                         // DUP1 (empty stack)
	f.Add([]byte{0x1B})                         // SWAP1 (empty stack)
	f.Add([]byte{0x60, 0x01, 0x18})             // PUSH1 1, DUP2 (underflow)
	f.Add([]byte{0x60, 0x01, 0x1C})             // PUSH1 1, SWAP2 (underflow)

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		if len(bytecode) > 512 {
			return
		}
		interp := NewInterpreter()
		ctx := newFuzzExecutionContext(bytecode)
		stateDB := newFuzzStateDB()
		result := interp.Execute(ctx, stateDB)
		_ = result
	})
}

// FuzzMemoryOperations: memory-op boundary conditions
func FuzzMemoryOperations(f *testing.F) {
	// seed corpus: memory ops (MLOAD, MSTORE, MSTORE8, MSIZE, MCOPY)
	f.Add([]byte{0x60, 0x00, 0x50})                                     // PUSH1 0, MLOAD
	f.Add([]byte{0x60, 0x01, 0x60, 0x00, 0x51})                         // PUSH1 1, PUSH1 0, MSTORE
	f.Add([]byte{0x60, 0xFF, 0x60, 0x00, 0x52})                         // PUSH1 0xFF, PUSH1 0, MSTORE8
	f.Add([]byte{0x53})                                                 // MSIZE
	f.Add([]byte{0x60, 0x20, 0x60, 0x00, 0x60, 0x20, 0x60, 0x00, 0x54}) // MCOPY
	f.Add([]byte{0x60, 0xFF, 0xFF, 0xFF, 0xFF, 0x50})                   // large-offset MLOAD

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		if len(bytecode) > 512 {
			return
		}
		interp := NewInterpreter()
		ctx := newFuzzExecutionContext(bytecode)
		stateDB := newFuzzStateDB()
		result := interp.Execute(ctx, stateDB)
		_ = result
	})
}

// FuzzStorageOperations: storage-op boundary conditions
func FuzzStorageOperations(f *testing.F) {
	// seed corpus: SLOAD, SSTORE
	f.Add([]byte{0x60, 0x00, 0x60})                               // PUSH1 0, SLOAD
	f.Add([]byte{0x60, 0x01, 0x60, 0x00, 0x61})                   // PUSH1 1, PUSH1 0, SSTORE
	f.Add([]byte{0x60, 0x00, 0x60, 0x00, 0x61, 0x60, 0x00, 0x60}) // SSTORE then SLOAD

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		if len(bytecode) > 512 {
			return
		}
		interp := NewInterpreter()
		ctx := newFuzzExecutionContext(bytecode)
		stateDB := newFuzzStateDB()
		result := interp.Execute(ctx, stateDB)
		_ = result
	})
}

// FuzzArithmeticOperations: arithmetic overflow and boundaries
func FuzzArithmeticOperations(f *testing.F) {
	// seed corpus: various arithmetic ops
	f.Add([]byte{0x60, 0xFF, 0x60, 0xFF, 0x20})             // PUSH1 0xFF, PUSH1 0xFF, ADD
	f.Add([]byte{0x60, 0x00, 0x60, 0x01, 0x21})             // PUSH1 0, PUSH1 1, SUB
	f.Add([]byte{0x60, 0xFF, 0x60, 0xFF, 0x22})             // PUSH1 0xFF, PUSH1 0xFF, MUL
	f.Add([]byte{0x60, 0x01, 0x60, 0x00, 0x23})             // PUSH1 1, PUSH1 0, DIV (div-by-zero)
	f.Add([]byte{0x60, 0x01, 0x60, 0x00, 0x24})             // PUSH1 1, PUSH1 0, MOD (div-by-zero)
	f.Add([]byte{0x60, 0x01, 0x60, 0x01, 0x60, 0x00, 0x25}) // ADDMOD (N=0)
	f.Add([]byte{0x60, 0x01, 0x60, 0x01, 0x60, 0x00, 0x26}) // MULMOD (N=0)
	f.Add([]byte{0x60, 0x02, 0x60, 0x40, 0x27})             // PUSH1 2, PUSH1 64, EXP

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		if len(bytecode) > 512 {
			return
		}
		interp := NewInterpreter()
		ctx := newFuzzExecutionContext(bytecode)
		stateDB := newFuzzStateDB()
		result := interp.Execute(ctx, stateDB)
		_ = result
	})
}

// FuzzCallOperations: call depth and recursion
func FuzzCallOperations(f *testing.F) {
	// seed corpus: CALL, STATICCALL, DELEGATECALL, CREATE
	f.Add([]byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x90}) // CALL (7 args)
	f.Add([]byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x93})             // STATICCALL (6 args)
	f.Add([]byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x92})             // DELEGATECALL (6 args)
	f.Add([]byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x94})                                                 // CREATE (3 args)
	f.Add([]byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x95})                                     // CREATE2 (4 args)

	f.Fuzz(func(t *testing.T, bytecode []byte) {
		if len(bytecode) > 512 {
			return
		}
		interp := NewInterpreter()
		ctx := newFuzzExecutionContext(bytecode)
		stateDB := newFuzzStateDB()
		result := interp.Execute(ctx, stateDB)
		_ = result
	})
}
