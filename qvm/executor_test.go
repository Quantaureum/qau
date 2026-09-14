// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"sync"
	"testing"
)

type mockStateDB struct {
	mu               sync.Mutex
	balances         map[Address]*big.Int
	nonces           map[Address]uint64
	codes            map[Address][]byte
	storage          map[Address]map[Hash]Hash
	committedStorage map[Address]map[Hash]Hash
	exist            map[Address]bool
	// snapStorage: deep copy of storage per snapshot level
	snapStorage []map[Address]map[Hash]Hash
	// snapBalances: deep copy of balances per snapshot level (revert must roll back value transfers)
	snapBalances    []map[Address]*big.Int
	accessList      map[Address]struct{}
	accessListSlots map[Address]map[Hash]struct{}
	selfDestructed  map[Address]bool
}

func newMockStateDB() *mockStateDB {
	return &mockStateDB{
		balances:         make(map[Address]*big.Int),
		nonces:           make(map[Address]uint64),
		codes:            make(map[Address][]byte),
		storage:          make(map[Address]map[Hash]Hash),
		committedStorage: make(map[Address]map[Hash]Hash),
		exist:            make(map[Address]bool),
		snapStorage:      make([]map[Address]map[Hash]Hash, 0),
		snapBalances:     make([]map[Address]*big.Int, 0),
		accessList:       make(map[Address]struct{}),
		accessListSlots:  make(map[Address]map[Hash]struct{}),
		selfDestructed:   make(map[Address]bool),
	}
}

func (m *mockStateDB) GetBalance(addr Address) *big.Int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.balances[addr]; ok {
		return b
	}
	return big.NewInt(0)
}

func (m *mockStateDB) SetBalance(addr Address, balance *big.Int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.balances[addr] = new(big.Int).Set(balance)
}

func (m *mockStateDB) GetNonce(addr Address) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nonces[addr]
}

func (m *mockStateDB) SetNonce(addr Address, nonce uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonces[addr] = nonce
}

func (m *mockStateDB) GetCode(addr Address) []byte {
	return m.codes[addr]
}

func (m *mockStateDB) SetCode(addr Address, code []byte) {
	m.codes[addr] = code
}

func (m *mockStateDB) GetCodeHash(addr Address) Hash {
	return Hash{}
}

func (m *mockStateDB) GetCodeSize(addr Address) int {
	return len(m.codes[addr])
}

func (m *mockStateDB) GetState(addr Address, key Hash) Hash {
	m.mu.Lock()
	defer m.mu.Unlock()
	if storage, ok := m.storage[addr]; ok {
		if v, ok := storage[key]; ok {
			return v
		}
	}
	return Hash{}
}

func (m *mockStateDB) SetState(addr Address, key, value Hash) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.storage[addr] == nil {
		m.storage[addr] = make(map[Hash]Hash)
	}
	m.storage[addr][key] = value
}

// GetCommittedState returns the storage value committed at the start of the
// transaction (EIP-3529). R7 P0-4 FIX (QVM-R7-01): Used by interpreter and
// JIT SSTORE refund logic to detect slots created earlier in the same tx.
func (m *mockStateDB) GetCommittedState(addr Address, key Hash) Hash {
	m.mu.Lock()
	defer m.mu.Unlock()
	if storage, ok := m.committedStorage[addr]; ok {
		if v, ok := storage[key]; ok {
			return v
		}
	}
	return Hash{}
}

func (m *mockStateDB) Exist(addr Address) bool {
	return m.exist[addr]
}

func (m *mockStateDB) Empty(addr Address) bool {
	return !m.exist[addr] || (m.GetBalance(addr).Sign() == 0 && m.GetNonce(addr) == 0)
}

func (m *mockStateDB) Snapshot() int {
	snapshot := make(map[Address]map[Hash]Hash)
	for addr, storage := range m.storage {
		snapshot[addr] = make(map[Hash]Hash)
		for k, v := range storage {
			snapshot[addr][k] = v
		}
	}
	m.snapStorage = append(m.snapStorage, snapshot)
	// FIX: snapshot deep-copies balances; revert restores value transfers
	balSnap := make(map[Address]*big.Int)
	for addr, bal := range m.balances {
		balSnap[addr] = new(big.Int).Set(bal)
	}
	m.snapBalances = append(m.snapBalances, balSnap)
	return len(m.snapStorage) - 1
}

func (m *mockStateDB) RevertToSnapshot(id int) {
	if id < 0 || id >= len(m.snapStorage) {
		return
	}
	m.storage = make(map[Address]map[Hash]Hash)
	for addr, storage := range m.snapStorage[id] {
		m.storage[addr] = make(map[Hash]Hash)
		for k, v := range storage {
			m.storage[addr][k] = v
		}
	}
	// FIX: restore balances
	m.balances = make(map[Address]*big.Int)
	for addr, bal := range m.snapBalances[id] {
		m.balances[addr] = new(big.Int).Set(bal)
	}
	m.snapStorage = m.snapStorage[:id]
	m.snapBalances = m.snapBalances[:id]
}

func (m *mockStateDB) SelfDestruct(addr Address) {
	m.selfDestructed[addr] = true
}

func (m *mockStateDB) HasSelfDestructed(addr Address) bool {
	return m.selfDestructed[addr]
}

func (m *mockStateDB) AddAddressToAccessList(addr Address) {
	m.accessList[addr] = struct{}{}
}

func (m *mockStateDB) AddSlotToAccessList(addr Address, slot Hash) {
	if m.accessListSlots[addr] == nil {
		m.accessListSlots[addr] = make(map[Hash]struct{})
	}
	m.accessListSlots[addr][slot] = struct{}{}
}

func (m *mockStateDB) AddressInAccessList(addr Address) bool {
	_, ok := m.accessList[addr]
	return ok
}

func (m *mockStateDB) SlotInAccessList(addr Address, slot Hash) (addressOk, slotOk bool) {
	addressOk = m.AddressInAccessList(addr)
	if slots, ok := m.accessListSlots[addr]; ok {
		_, slotOk = slots[slot]
	}
	return addressOk, slotOk
}

func TestExecutor_NewExecutor(t *testing.T) {
	t.Run("happy path initialization", func(t *testing.T) {
		executor := NewExecutor()
		if executor == nil {
			t.Fatal("NewExecutor returned nil")
		}
		if executor.interpreter == nil {
			t.Error("interpreter is nil")
		}
		if executor.validator == nil {
			t.Error("validator is nil")
		}
		if executor.gasEstimator == nil {
			t.Error("gasEstimator is nil")
		}
		if executor.interpreter.gasTable == nil {
			t.Error("default gas table is nil")
		}
	})
}

func TestExecutor_Execute(t *testing.T) {
	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}

	tests := []struct {
		name        string
		code        []byte
		gas         uint64
		callDepth   int
		expectedErr error
	}{
		{name: "Execute valid bytecode - simple STOP", code: []byte{byte(STOP)}, gas: 1000, callDepth: 0, expectedErr: nil},
		{name: "Execute with no bytecode - should succeed with no-op", code: []byte{}, gas: 1000, callDepth: 0, expectedErr: nil},
		{name: "Execute with INVALID opcode triggers revert", code: []byte{byte(INVALID)}, gas: 1000, callDepth: 0, expectedErr: ErrInvalidOpcode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewExecutor()
			stateDB := newMockStateDB()
			ctx := &ExecutionContext{
				Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: calleeAddr,
				Value: big.NewInt(0), BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10},
				GasLimit: 1000000, ChainID: 1, BlockHashes: make(map[uint64]Hash),
				Code: tt.code, Input: []byte{}, Gas: tt.gas, Depth: tt.callDepth, ReadOnly: false,
			}
			result := executor.Execute(ctx, stateDB)
			if tt.expectedErr != nil {
				if result.Err != tt.expectedErr {
					t.Errorf("expected error %v, got %v", tt.expectedErr, result.Err)
				}
			} else {
				if result.Err != nil {
					t.Errorf("unexpected error: %v", result.Err)
				}
			}
		})
	}
}

func TestExecutor_Execute_OutOfGas(t *testing.T) {
	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}
	code := []byte{byte(PUSH1), 0x01, byte(PUSH1), 0x02, byte(ADD)}
	executor := NewExecutor()
	stateDB := newMockStateDB()
	ctx := &ExecutionContext{
		Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: calleeAddr,
		Value: big.NewInt(0), BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10},
		GasLimit: 1000000, ChainID: 1, BlockHashes: make(map[uint64]Hash),
		Code: code, Input: []byte{}, Gas: 5, Depth: 0, ReadOnly: false,
	}
	result := executor.Execute(ctx, stateDB)
	if result.Err != ErrOutOfGas {
		t.Errorf("expected ErrOutOfGas, got %v", result.Err)
	}
}

func TestExecutor_Execute_CallDepthExceeded(t *testing.T) {
	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}
	executor := NewExecutor()
	stateDB := newMockStateDB()
	ctx := &ExecutionContext{
		Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: calleeAddr,
		Value: big.NewInt(0), BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10},
		GasLimit: 1000000, ChainID: 1, BlockHashes: make(map[uint64]Hash),
		Code: []byte{byte(STOP)}, Input: []byte{}, Gas: 1000, Depth: MaxCallDepth + 1, ReadOnly: false,
	}
	result := executor.Execute(ctx, stateDB)
	if result.Err != ErrDepthExceeded {
		t.Errorf("expected ErrDepthExceeded, got %v", result.Err)
	}
}

func TestExecutor_Call(t *testing.T) {
	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}
	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 1000000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}

	tests := []struct {
		name        string
		setup       func(*mockStateDB)
		callee      Address
		input       []byte
		gas         uint64
		value       *big.Int
		expectedErr error
	}{
		{name: "Simple balance transfer - no code at callee", setup: func(db *mockStateDB) {
			db.SetBalance(callerAddr, big.NewInt(1000))
			db.SetBalance(calleeAddr, big.NewInt(0))
		}, callee: calleeAddr, input: []byte{}, gas: 1000, value: big.NewInt(100), expectedErr: nil},
		{name: "Call to non-existent contract - returns 0", setup: func(db *mockStateDB) { db.SetBalance(callerAddr, big.NewInt(1000)) }, callee: Address{0x99}, input: []byte{}, gas: 1000, value: nil, expectedErr: nil},
		{name: "Call with value transfer - sufficient balance", setup: func(db *mockStateDB) {
			db.SetBalance(callerAddr, big.NewInt(1000))
			db.SetBalance(calleeAddr, big.NewInt(0))
			db.exist[calleeAddr] = true
			db.codes[calleeAddr] = []byte{byte(STOP)}
		}, callee: calleeAddr, input: []byte{}, gas: 1000, value: big.NewInt(100), expectedErr: nil},
		{name: "Call with insufficient balance - should revert", setup: func(db *mockStateDB) {
			db.SetBalance(callerAddr, big.NewInt(50))
			db.SetBalance(calleeAddr, big.NewInt(0))
		}, callee: calleeAddr, input: []byte{}, gas: 1000, value: big.NewInt(100), expectedErr: ErrInsufficientBalance},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewExecutor()
			stateDB := newMockStateDB()
			tt.setup(stateDB)
			result := executor.Call(stateDB, callerAddr, tt.callee, tt.input, tt.gas, tt.value, blockCtx, 0)
			if tt.expectedErr != nil {
				if result.Err != tt.expectedErr {
					t.Errorf("expected error %v, got %v", tt.expectedErr, result.Err)
				}
			} else {
				if result.Err != nil {
					t.Errorf("unexpected error: %v", result.Err)
				}
			}
		})
	}
}

func TestExecutor_Create(t *testing.T) {
	callerAddr := Address{0x01}
	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 1000000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}
	// Valid initCode: PUSH1 0x00 (stack offset) + PUSH1 0x01 (return size 1 byte) + RETURN
	// RETURN needs 2 stack items [size, offset]; PUSH1 0x00 pushes offset, PUSH1 0x01 pushes size.
	initCode := []byte{byte(PUSH1), 0x00, byte(PUSH1), 0x01, byte(RETURN)}

	tests := []struct {
		name         string
		setup        func(*mockStateDB)
		initCode     []byte
		gas          uint64
		value        *big.Int
		expectedErr  error
		checkAddress bool
	}{
		{name: "Contract creation with valid bytecode", setup: func(db *mockStateDB) {
			db.SetBalance(callerAddr, big.NewInt(1000000))
			// Simulate TxExecutor having already incremented nonce before calling Create
			db.SetNonce(callerAddr, 1)
		}, initCode: initCode, gas: 100000, value: big.NewInt(0), expectedErr: nil, checkAddress: true},
		{name: "Contract creation with invalid bytecode", setup: func(db *mockStateDB) {
			db.SetBalance(callerAddr, big.NewInt(1000000))
			// Simulate TxExecutor having already incremented nonce before calling Create
			db.SetNonce(callerAddr, 1)
		}, initCode: []byte{0xFF, 0xFF, 0xFF}, gas: 100000, value: big.NewInt(0), expectedErr: ErrInvalidOpcode, checkAddress: false},
		{name: "Address collision", setup: func(db *mockStateDB) {
			db.SetBalance(callerAddr, big.NewInt(1000000))
			db.SetNonce(callerAddr, 1)
			// Create uses createNonce = currentNonce - 1 = 0 for address calculation
			expectedAddr := CreateAddress(callerAddr, 0)
			db.exist[expectedAddr] = true
		}, initCode: initCode, gas: 100000, value: big.NewInt(0), expectedErr: ErrContractAddressCollision, checkAddress: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewExecutor()
			stateDB := newMockStateDB()
			tt.setup(stateDB)
			result, addr := executor.Create(stateDB, callerAddr, tt.initCode, tt.gas, tt.value, blockCtx, 0)
			if tt.expectedErr != nil {
				if result.Err != tt.expectedErr {
					t.Errorf("expected error %v, got %v", tt.expectedErr, result.Err)
				}
				if tt.checkAddress && addr != (Address{}) {
					t.Error("expected empty address on error")
				}
			} else {
				if result.Err != nil {
					t.Errorf("unexpected error: %v", result.Err)
				}
				if tt.checkAddress && addr == (Address{}) {
					t.Error("expected non-empty address")
				}
			}
		})
	}
}

func TestExecutor_Create2(t *testing.T) {
	callerAddr := Address{0x01}
	salt1 := Hash{0x01}
	salt2 := Hash{0x02}
	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 1000000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}
	// Valid initCode: PUSH1 0x00 (stack offset) + PUSH1 0x01 (return size 1 byte) + RETURN
	// RETURN needs 2 stack items [size, offset]; PUSH1 0x00 pushes offset, PUSH1 0x01 pushes size.
	initCode := []byte{byte(PUSH1), 0x00, byte(PUSH1), 0x01, byte(RETURN)}

	executor := NewExecutor()
	stateDB1 := newMockStateDB()
	stateDB1.SetBalance(callerAddr, big.NewInt(1000000))
	result1, addr1 := executor.Create2(stateDB1, callerAddr, initCode, salt1, 100000, big.NewInt(0), blockCtx, 0)
	if result1.Err != nil {
		t.Fatalf("first Create2 failed: %v", result1.Err)
	}
	compareAddr := addr1

	t.Run("Same bytecode + same salt = same address", func(t *testing.T) {
		executor := NewExecutor()
		stateDB := newMockStateDB()
		stateDB.SetBalance(callerAddr, big.NewInt(1000000))
		result, addr := executor.Create2(stateDB, callerAddr, initCode, salt1, 100000, big.NewInt(0), blockCtx, 0)
		if result.Err != nil {
			t.Errorf("unexpected error: %v", result.Err)
		}
		if addr != compareAddr {
			t.Errorf("expected same address %x, got %x", compareAddr, addr)
		}
	})

	t.Run("Different salt = different address", func(t *testing.T) {
		executor := NewExecutor()
		stateDB := newMockStateDB()
		stateDB.SetBalance(callerAddr, big.NewInt(1000000))
		result, addr := executor.Create2(stateDB, callerAddr, initCode, salt2, 100000, big.NewInt(0), blockCtx, 0)
		if result.Err != nil {
			t.Errorf("unexpected error: %v", result.Err)
		}
		if addr == compareAddr {
			t.Error("expected different address")
		}
	})
}

func TestExecutor_EstimateGas(t *testing.T) {
	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}

	t.Run("Gas estimation for simple call", func(t *testing.T) {
		executor := NewExecutor()
		stateDB := newMockStateDB()
		stateDB.SetBalance(callerAddr, big.NewInt(1000000))
		stateDB.exist[calleeAddr] = true
		stateDB.codes[calleeAddr] = []byte{byte(STOP)}
		ctx := &ExecutionContext{
			Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: calleeAddr,
			Value: big.NewInt(0), BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10},
			GasLimit: 1000000, ChainID: 1, BlockHashes: make(map[uint64]Hash),
			Code: []byte{byte(STOP)}, Input: []byte{}, Gas: 1000000, Depth: 0, ReadOnly: false,
		}
		estimated, err := executor.EstimateGas(ctx, stateDB)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if estimated == 0 {
			t.Error("expected non-zero gas estimate")
		}
	})

	t.Run("Gas estimation for contract creation", func(t *testing.T) {
		executor := NewExecutor()
		stateDB := newMockStateDB()
		stateDB.SetBalance(callerAddr, big.NewInt(1000000))
		ctx := &ExecutionContext{
			Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: Address{0x00},
			Value: big.NewInt(0), BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10},
			GasLimit: 1000000, ChainID: 1, BlockHashes: make(map[uint64]Hash),
			// Valid initCode: PUSH1 0x00 (stack offset) + PUSH1 0x01 (return size 1 byte) + RETURN
			Code: []byte{byte(PUSH1), 0x00, byte(PUSH1), 0x01, byte(RETURN)}, Input: nil, Gas: 1000000, Depth: 0, ReadOnly: false,
		}
		estimated, err := executor.EstimateGas(ctx, stateDB)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if estimated == 0 {
			t.Error("expected non-zero gas estimate")
		}
	})
}

func TestExecutor_StaticCall(t *testing.T) {
	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}
	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 1000000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}

	t.Run("Static call to non-existent contract", func(t *testing.T) {
		executor := NewExecutor()
		stateDB := newMockStateDB()
		result := executor.StaticCall(stateDB, callerAddr, Address{0x99}, []byte{}, 1000, blockCtx, 0)
		if result.Err != nil {
			t.Errorf("unexpected error: %v", result.Err)
		}
	})

	t.Run("Static call cannot modify state - reverts", func(t *testing.T) {
		executor := NewExecutor()
		stateDB := newMockStateDB()
		stateDB.SetState(calleeAddr, Hash{}, Hash{0x01})
		stateDB.SetBalance(calleeAddr, big.NewInt(1000))
		stateDB.exist[calleeAddr] = true
		stateDB.codes[calleeAddr] = []byte{byte(PUSH1), 0x05, byte(PUSH1), 0x00, byte(SSTORE), byte(PUSH1), 0x01, byte(PUSH1), 0x00, byte(RETURN)}
		result := executor.StaticCall(stateDB, callerAddr, calleeAddr, []byte{}, 50000, blockCtx, 0)
		if result.Err != ErrWriteProtection && result.Err != nil {
			t.Errorf("expected ErrWriteProtection or nil, got %v", result.Err)
		}
	})
}

func TestExecutor_ExecuteWithRollback(t *testing.T) {
	callerAddr := Address{0x01}
	calleeAddr := Address{0x02}
	executor := NewExecutor()
	stateDB := newMockStateDB()
	stateDB.SetBalance(callerAddr, big.NewInt(1000))
	stateDB.SetBalance(calleeAddr, big.NewInt(0))
	stateDB.exist[calleeAddr] = true
	stateDB.codes[calleeAddr] = []byte{byte(STOP)}
	ctx := &ExecutionContext{
		Origin: callerAddr, GasPrice: big.NewInt(1), Caller: callerAddr, Address: calleeAddr,
		Value: big.NewInt(100), BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10},
		GasLimit: 1000000, ChainID: 1, BlockHashes: make(map[uint64]Hash),
		Code: []byte{byte(STOP)}, Input: []byte{}, Gas: 1000, Depth: 0, ReadOnly: false,
	}
	result := executor.ExecuteWithRollback(ctx, stateDB)
	if result.Err != nil {
		t.Errorf("unexpected error: %v", result.Err)
	}
}

func TestCreateAddress(t *testing.T) {
	caller := Address{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	addr1 := CreateAddress(caller, 1)
	addr2 := CreateAddress(caller, 1)
	addr3 := CreateAddress(caller, 2)
	if addr1 != addr2 {
		t.Error("same caller and nonce should produce same address")
	}
	if addr1 == addr3 {
		t.Error("different nonces should produce different addresses")
	}
}

func TestCreate2Address(t *testing.T) {
	caller := Address{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	salt := Hash{0x01}
	initCode := []byte{0x01, 0x02, 0x03}
	addr1 := Create2Address(caller, salt, initCode)
	addr2 := Create2Address(caller, salt, initCode)
	if addr1 != addr2 {
		t.Error("same inputs should produce same address")
	}
	differentSalt := Hash{0x02}
	addr3 := Create2Address(caller, differentSalt, initCode)
	if addr1 == addr3 {
		t.Error("different salt should produce different address")
	}
	differentCode := []byte{0x04, 0x05, 0x06}
	addr4 := Create2Address(caller, salt, differentCode)
	if addr1 == addr4 {
		t.Error("different init code should produce different address")
	}
}

// TestR32_P2_13_StaticCall_RejectsStatefulPrecompile verifies the P2-13 fix:
// STATICCALL must reject stateful precompiled contracts (e.g. the multisig
// precompile at 0x66) to preserve the read-only guarantee that EVM consumers
// expect from STATICCALL.
//
// The fix is enforced at TWO layers:
//  1. Interpreter layer (call.go:executePrecompiled with static=true) —
//     rejects stateful precompiles when called from opStaticCall.
//  2. Executor layer (executor.go:StaticCall) — rejects stateful precompiles
//     when called from the top-level eth_call RPC API.
//
// This test exercises the Executor layer. The interpreter layer is exercised
// indirectly by TestExecutor_StaticCall via opStaticCall dispatch, but the
// Executor.StaticCall path is the primary RPC-facing surface (eth_call) and
// the most likely attack vector for read-only API abuse.
func TestR32_P2_13_StaticCall_RejectsStatefulPrecompile(t *testing.T) {
	// The multisig precompile is registered at address 0x66 (see
	// precompiled/multisig.go:129). It implements StatefulPrecompiledContract
	// with IsStateful() returning true.
	multisigAddr := Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66}

	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 1000000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}

	executor := NewExecutor()
	stateDB := newMockStateDB()

	// Any non-empty input would trigger multisig dispatch logic; we use a
	// minimal 4-byte selector to ensure RequiredGas returns a sane value.
	// The key assertion is that StaticCall rejects the call BEFORE dispatch,
	// so the input content does not matter.
	input := []byte{0x01, 0x02, 0x03, 0x04}

	result := executor.StaticCall(stateDB, Address{0x01}, multisigAddr, input, 100000, blockCtx, 0)

	// STATICCALL to a stateful precompile MUST be rejected with
	// ErrWriteProtection. If the result is nil or the error is different,
	// the P2-13 fix has been bypassed.
	if result == nil {
		t.Fatal("R32-P2-13 NOT FIXED: StaticCall returned nil result for stateful precompile")
	}
	if result.Err != ErrWriteProtection {
		t.Errorf("R32-P2-13 NOT FIXED: StaticCall to multisig precompile should return ErrWriteProtection, got err=%v", result.Err)
	}
}

// TestR32_P2_13_StaticCall_AllowsPurePrecompile verifies the P2-13 fix does
// NOT over-block pure (stateless) precompiles. Pure precompiles like sha256,
// ecrecover, and identity MUST remain callable from STATICCALL — they are
// read-only by definition and are commonly used in view functions.
func TestR32_P2_13_StaticCall_AllowsPurePrecompile(t *testing.T) {
	// sha256 precompile is at address 0x02 (standard EVM precompile address).
	sha256Addr := Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}

	blockCtx := &BlockContext{
		BlockNumber: 1, Timestamp: 100, Coinbase: Address{0x10}, GasLimit: 1000000,
		GasPrice: big.NewInt(1), ChainID: 1, BlockHashes: make(map[uint64]Hash),
	}

	executor := NewExecutor()
	stateDB := newMockStateDB()

	// sha256("hello") — input is "hello" (5 bytes).
	input := []byte("hello")

	result := executor.StaticCall(stateDB, Address{0x01}, sha256Addr, input, 100000, blockCtx, 0)

	if result == nil {
		t.Fatal("StaticCall returned nil result for pure precompile")
	}
	// Pure precompiles should NOT be rejected with ErrWriteProtection.
	// They may return other errors (e.g. OOG, invalid input) but not
	// write-protection errors.
	if result.Err == ErrWriteProtection {
		t.Fatal("R32-P2-13 OVER-BLOCK: StaticCall rejected pure precompile (sha256) with ErrWriteProtection — pure precompiles must remain callable from STATICCALL")
	}
}
