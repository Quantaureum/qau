// Quantaureum Node source, version 1.0.0.
package jit

import (
	"crypto/sha256"
	"math/big"
	"testing"
	"time"
)

type mockStack struct {
	data []Word
}

func newMockStack() *mockStack {
	return &mockStack{data: make([]Word, 0)}
}

func (s *mockStack) Push(w Word) error {
	s.data = append(s.data, w)
	return nil
}

func (s *mockStack) Pop() (Word, error) {
	if len(s.data) == 0 {
		return Word{}, &vmError{msg: "stack underflow"}
	}
	w := s.data[len(s.data)-1]
	s.data = s.data[:len(s.data)-1]
	return w, nil
}

func (s *mockStack) PopUint64() (uint64, error) {
	w, err := s.Pop()
	if err != nil {
		return 0, err
	}
	return w.ToUint64(), nil
}

func (s *mockStack) PopBigInt() (*big.Int, error) {
	w, err := s.Pop()
	if err != nil {
		return nil, err
	}
	return w.ToBigInt(), nil
}

func (s *mockStack) PushUint64(v uint64) error {
	return s.Push(NewWordFromUint64(v))
}

func (s *mockStack) PushBigInt(v *big.Int) error {
	return s.Push(NewWord(v.Bytes()))
}

func (s *mockStack) Dup(n int) error {
	if n < 1 || n > len(s.data) {
		return &vmError{msg: "invalid dup index"}
	}
	return s.Push(s.data[len(s.data)-n])
}

func (s *mockStack) Swap(n int) error {
	if n < 1 || n >= len(s.data) {
		return &vmError{msg: "invalid swap index"}
	}
	top := len(s.data) - 1
	s.data[top], s.data[top-n] = s.data[top-n], s.data[top]
	return nil
}

func (s *mockStack) Len() int {
	return len(s.data)
}

type mockMemory struct {
	data []byte
}

func newMockMemory() *mockMemory {
	return &mockMemory{data: make([]byte, 0)}
}

func (m *mockMemory) Load(offset, size uint64) []byte {
	end := offset + size
	if end > uint64(len(m.data)) {
		needed := make([]byte, end-uint64(len(m.data)))
		m.data = append(m.data, needed...)
	}
	result := make([]byte, size)
	copy(result, m.data[offset:end])
	return result
}

func (m *mockMemory) Store(offset uint64, data []byte) error {
	end := offset + uint64(len(data))
	if end > uint64(len(m.data)) {
		needed := make([]byte, end-uint64(len(m.data)))
		m.data = append(m.data, needed...)
	}
	copy(m.data[offset:], data)
	return nil
}

func (m *mockMemory) Len() uint64 {
	return uint64(len(m.data))
}

type mockGas struct {
	available uint64
	used      uint64
	refund    uint64
}

func newMockGas(limit uint64) *mockGas {
	return &mockGas{available: limit}
}

func (g *mockGas) Available() uint64 {
	return g.available - g.used
}

func (g *mockGas) Consume(amount uint64) error {
	if g.used+amount > g.available {
		g.used = g.available
		return &vmError{msg: "out of gas"}
	}
	g.used += amount
	return nil
}

func (g *mockGas) FinalUsed() uint64 {
	maxRefund := g.used / 5
	actualRefund := g.refund
	if actualRefund > maxRefund {
		actualRefund = maxRefund
	}
	return g.used - actualRefund
}

func (g *mockGas) RefundAmount() uint64 {
	return g.refund
}

// audit fix: Return refunds unused gas
func (g *mockGas) Return(amount uint64) {
	if amount > g.used {
		amount = g.used
	}
	g.used -= amount
}

// audit fix: Refund adds gas refunds (e.g. SSTORE storage clearing)
func (g *mockGas) Refund(amount uint64) {
	g.refund += amount
}

type mockContext struct {
	origin      Address
	gasPrice    *big.Int
	caller      Address
	address     Address
	value       *big.Int
	blockNumber uint64
	timestamp   int64
	coinbase    Address
	gasLimit    uint64
	chainID     uint64
	code        []byte
	input       []byte
	depth       int
}

func newMockContext() *mockContext {
	return &mockContext{
		gasPrice:    big.NewInt(1),
		value:       big.NewInt(0),
		blockNumber: 1,
		timestamp:   100,
		chainID:     1669,
		code:        []byte{},
		input:       []byte{},
	}
}

func (c *mockContext) Origin() Address     { return c.origin }
func (c *mockContext) GasPrice() *big.Int  { return c.gasPrice }
func (c *mockContext) Caller() Address     { return c.caller }
func (c *mockContext) Address() Address    { return c.address }
func (c *mockContext) Value() *big.Int     { return c.value }
func (c *mockContext) BlockNumber() uint64 { return c.blockNumber }
func (c *mockContext) Timestamp() int64    { return c.timestamp }
func (c *mockContext) Coinbase() Address   { return c.coinbase }
func (c *mockContext) GasLimit() uint64    { return c.gasLimit }
func (c *mockContext) ChainID() uint64     { return c.chainID }
func (c *mockContext) Code() []byte        { return c.code }
func (c *mockContext) Input() []byte       { return c.input }
func (c *mockContext) Depth() int          { return c.depth }

// audit fix: new context methods
func (c *mockContext) PrevRandao() Hash    { return Hash{} }
func (c *mockContext) BlobHashes() []Hash  { return nil }
func (c *mockContext) BaseFee() uint64     { return 0 }
func (c *mockContext) BlobBaseFee() uint64 { return 0 }

type mockState struct {
	balances map[Address]*big.Int
	nonces   map[Address]uint64
	codes    map[Address][]byte
	storage  map[Address]map[Hash]Hash
	exist    map[Address]bool
}

func newMockState() *mockState {
	return &mockState{
		balances: make(map[Address]*big.Int),
		nonces:   make(map[Address]uint64),
		codes:    make(map[Address][]byte),
		storage:  make(map[Address]map[Hash]Hash),
		exist:    make(map[Address]bool),
	}
}

func (s *mockState) GetBalance(addr Address) *big.Int {
	if b, ok := s.balances[addr]; ok {
		return new(big.Int).Set(b)
	}
	return big.NewInt(0)
}

func (s *mockState) SetBalance(addr Address, balance *big.Int) {
	s.balances[addr] = new(big.Int).Set(balance)
}

func (s *mockState) GetNonce(addr Address) uint64 {
	return s.nonces[addr]
}

func (s *mockState) SetNonce(addr Address, nonce uint64) {
	s.nonces[addr] = nonce
}

func (s *mockState) GetCode(addr Address) []byte {
	return s.codes[addr]
}

func (s *mockState) SetCode(addr Address, code []byte) {
	s.codes[addr] = code
}

func (s *mockState) GetCodeHash(addr Address) Hash {
	return Hash{}
}

func (s *mockState) GetCodeSize(addr Address) int {
	return len(s.codes[addr])
}

func (s *mockState) GetState(addr Address, key Hash) Hash {
	if store, ok := s.storage[addr]; ok {
		if val, ok2 := store[key]; ok2 {
			return val
		}
	}
	return Hash{}
}

func (s *mockState) SetState(addr Address, key, value Hash) {
	if _, ok := s.storage[addr]; !ok {
		s.storage[addr] = make(map[Hash]Hash)
	}
	s.storage[addr][key] = value
}

func (s *mockState) Exist(addr Address) bool                               { return s.exist[addr] }
func (s *mockState) Empty(addr Address) bool                               { return !s.exist[addr] }
func (s *mockState) Snapshot() int                                         { return 0 }
func (s *mockState) RevertToSnapshot(id int)                               {}
func (s *mockState) SelfDestruct(addr Address)                             {}
func (s *mockState) HasSelfDestructed(addr Address) bool                   { return false }
func (s *mockState) AddAddressToAccessList(addr Address)                   {}
func (s *mockState) AddSlotToAccessList(addr Address, slot Hash)           {}
func (s *mockState) AddressInAccessList(addr Address) bool                 { return false }
func (s *mockState) SlotInAccessList(addr Address, slot Hash) (bool, bool) { return false, false }

type mockEnv struct {
	stack          *mockStack
	memory         *mockMemory
	gas            *mockGas
	ctx            *mockContext
	state          *mockState
	stopped        bool
	logs           []*Log
	returnData     []byte
	reverted       bool
	err            error
	pc             uint64
	jumpDests      map[uint64]bool
	blockHash      func(uint64) Hash
	lastReturnData []byte
	// FIX: Configurable Call/Create behavior for JIT consistency tests.
	callSucceeds bool
	addrActive   bool
	callDepthVal int
	callCount    int
	createCount  int
}

func newMockEnv(gasLimit uint64) *mockEnv {
	return &mockEnv{
		stack:     newMockStack(),
		memory:    newMockMemory(),
		gas:       newMockGas(gasLimit),
		ctx:       newMockContext(),
		state:     newMockState(),
		jumpDests: make(map[uint64]bool),
	}
}

func (e *mockEnv) Stack() VMStack    { return e.stack }
func (e *mockEnv) Memory() VMMemory  { return e.memory }
func (e *mockEnv) Gas() VMGas        { return e.gas }
func (e *mockEnv) Ctx() VMContext    { return e.ctx }
func (e *mockEnv) StateDB() VMState  { return e.state }
func (e *mockEnv) Stopped() bool     { return e.stopped }
func (e *mockEnv) SetStopped(v bool) { e.stopped = v }
func (e *mockEnv) GetBlockHash(blockNum uint64) Hash {
	if e.blockHash != nil {
		return e.blockHash(blockNum)
	}
	return Hash{}
}
func (e *mockEnv) AddLog(log *Log)            { e.logs = append(e.logs, log) }
func (e *mockEnv) SetReturnData(data []byte)  { e.returnData = data }
func (e *mockEnv) ReturnData() []byte         { return e.returnData }
func (e *mockEnv) SetReverted(v bool)         { e.reverted = v }
func (e *mockEnv) SetErr(err error)           { e.err = err }
func (e *mockEnv) Err() error                 { return e.err }
func (e *mockEnv) PC() uint64                 { return e.pc }
func (e *mockEnv) SetPC(pc uint64)            { e.pc = pc }
func (e *mockEnv) JumpDests() map[uint64]bool { return e.jumpDests }
func (e *mockEnv) ReadOnly() bool             { return false }

// audit fix: transient-storage methods
func (e *mockEnv) GetTransientState(addr Address, key Hash) Hash   { return Hash{} }
func (e *mockEnv) SetTransientState(addr Address, key, value Hash) {}

func (e *mockEnv) Call(caller Address, addr Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	e.callCount++
	if e.callSucceeds {
		return []byte{0x01}, gas / 2, nil
	}
	return nil, 0, ErrInvalidOpcode
}
func (e *mockEnv) CallCode(caller Address, addr Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	if e.callSucceeds {
		return []byte{0x01}, gas / 2, nil
	}
	return nil, 0, ErrInvalidOpcode
}
func (e *mockEnv) DelegateCall(caller Address, addr Address, input []byte, gas uint64) ([]byte, uint64, error) {
	if e.callSucceeds {
		return []byte{0x01}, gas / 2, nil
	}
	return nil, 0, ErrInvalidOpcode
}
func (e *mockEnv) StaticCall(caller Address, addr Address, input []byte, gas uint64) ([]byte, uint64, error) {
	if e.callSucceeds {
		return []byte{0x01}, gas / 2, nil
	}
	return nil, 0, ErrInvalidOpcode
}
func (e *mockEnv) Create(caller Address, input []byte, gas uint64, value *big.Int, salt *Hash) ([]byte, Address, uint64, error) {
	e.createCount++
	if e.callSucceeds {
		return []byte{0x01}, Address{0x01}, gas / 2, nil
	}
	return nil, Address{}, 0, ErrInvalidOpcode
}
func (e *mockEnv) LastReturnData() []byte    { return e.lastReturnData }
func (e *mockEnv) SelfDestruct(addr Address) {}

// FIX: Implement reentrancy state methods for VMEnvironment interface.
// FIX: Made configurable for JIT consistency tests.
func (e *mockEnv) IsAddressActive(addr Address) bool { return e.addrActive }
func (e *mockEnv) CallDepth() int                    { return e.callDepthVal }

func TestJITCompiler_Compile_EmptyCode(t *testing.T) {
	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Ops) != 0 {
		t.Errorf("expected 0 ops for empty code, got %d", len(plan.Ops))
	}
}

func TestJITCompiler_Compile_PushAndAdd(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x01, byte(PUSH1), 0x02, byte(ADD)}
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// PUSH+ADD may be merged by peephole optimization, so we expect at least 2 ops
	if len(plan.Ops) < 2 {
		t.Errorf("expected at least 2 ops, got %d", len(plan.Ops))
	}
}

func TestJITCompiler_Compile_CacheHit(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x0A, byte(PUSH1), 0x14, byte(MUL)}

	plan1, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("first compile failed: %v", err)
	}

	plan2, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("second compile failed: %v", err)
	}

	if plan1 != plan2 {
		t.Error("cache hit should return same plan pointer")
	}

	hits, misses, compiles := compiler.Cache().Stats()
	if hits != 1 {
		t.Errorf("expected 1 cache hit, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 cache miss, got %d", misses)
	}
	if compiles != 1 {
		t.Errorf("expected 1 compile, got %d", compiles)
	}
}

func TestJITCompiler_Compile_DifferentCode(t *testing.T) {
	compiler := NewJITCompiler(256)
	code1 := []byte{byte(PUSH1), 0x01, byte(PUSH1), 0x02, byte(ADD)}
	code2 := []byte{byte(PUSH1), 0x03, byte(PUSH1), 0x04, byte(SUB)}

	_, err := compiler.Compile(code1)
	if err != nil {
		t.Fatalf("compile code1 failed: %v", err)
	}
	_, err = compiler.Compile(code2)
	if err != nil {
		t.Fatalf("compile code2 failed: %v", err)
	}

	_, misses, compiles := compiler.Cache().Stats()
	if misses != 2 {
		t.Errorf("expected 2 cache misses, got %d", misses)
	}
	if compiles != 2 {
		t.Errorf("expected 2 compiles, got %d", compiles)
	}
}

func TestJITCompiler_Execute_Add(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x0A, byte(PUSH1), 0x14, byte(ADD), byte(STOP)}
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	err = compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	if env.stack.Len() != 1 {
		t.Fatalf("expected 1 item on stack, got %d", env.stack.Len())
	}
	result, _ := env.stack.Pop()
	expected := uint64(0x0A + 0x14)
	if result.ToUint64() != expected {
		t.Errorf("expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_Sub(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x14, byte(PUSH1), 0x64, byte(SUB), byte(STOP)}
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	err = compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	result, _ := env.stack.Pop()
	expected := uint64(0x64 - 0x14)
	if result.ToUint64() != expected {
		t.Errorf("expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_Mul(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x06, byte(PUSH1), 0x07, byte(MUL), byte(STOP)}
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	err = compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	result, _ := env.stack.Pop()
	expected := uint64(0x06 * 0x07)
	if result.ToUint64() != expected {
		t.Errorf("expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_Div(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x0A, byte(PUSH1), 0x64, byte(DIV), byte(STOP)}
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	err = compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	result, _ := env.stack.Pop()
	expected := uint64(0x64 / 0x0A)
	if result.ToUint64() != expected {
		t.Errorf("expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_DivByZero(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x00, byte(PUSH1), 0x0A, byte(DIV), byte(STOP)}
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	err = compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("division by zero should return 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_Mod(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x03, byte(PUSH1), 0x0A, byte(MOD), byte(STOP)}
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	err = compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	result, _ := env.stack.Pop()
	expected := uint64(0x0A % 0x03)
	if result.ToUint64() != expected {
		t.Errorf("expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_Exp(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x03, byte(PUSH1), 0x02, byte(EXP), byte(STOP)}
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	env := newMockEnv(100000)
	err = compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	result, _ := env.stack.Pop()
	expected := uint64(8)
	if result.ToUint64() != expected {
		t.Errorf("2^3 expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_Lt(t *testing.T) {
	tests := []struct {
		name     string
		a, b     uint64
		expected uint64
	}{
		{"a_lt_b", 5, 10, 1},
		{"a_gt_b", 10, 5, 0},
		{"a_eq_b", 5, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewJITCompiler(256)
			code := []byte{
				byte(PUSH1), byte(tt.b),
				byte(PUSH1), byte(tt.a),
				byte(LT), byte(STOP),
			}
			plan, _ := compiler.Compile(code)
			env := newMockEnv(100000)
			err := compiler.Execute(plan, env)
			if err != nil {
				t.Fatalf("execute failed: %v", err)
			}
			result, _ := env.stack.Pop()
			if result.ToUint64() != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result.ToUint64())
			}
		})
	}
}

func TestJITCompiler_Execute_Gt(t *testing.T) {
	tests := []struct {
		name     string
		a, b     uint64
		expected uint64
	}{
		{"a_gt_b", 10, 5, 1},
		{"a_lt_b", 5, 10, 0},
		{"a_eq_b", 5, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewJITCompiler(256)
			code := []byte{
				byte(PUSH1), byte(tt.b),
				byte(PUSH1), byte(tt.a),
				byte(GT), byte(STOP),
			}
			plan, _ := compiler.Compile(code)
			env := newMockEnv(100000)
			err := compiler.Execute(plan, env)
			if err != nil {
				t.Fatalf("execute failed: %v", err)
			}
			result, _ := env.stack.Pop()
			if result.ToUint64() != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result.ToUint64())
			}
		})
	}
}

func TestJITCompiler_Execute_Eq(t *testing.T) {
	tests := []struct {
		name     string
		a, b     uint64
		expected uint64
	}{
		{"equal", 5, 5, 1},
		{"not_equal", 5, 10, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewJITCompiler(256)
			code := []byte{
				byte(PUSH1), byte(tt.a),
				byte(PUSH1), byte(tt.b),
				byte(EQ), byte(STOP),
			}
			plan, _ := compiler.Compile(code)
			env := newMockEnv(100000)
			err := compiler.Execute(plan, env)
			if err != nil {
				t.Fatalf("execute failed: %v", err)
			}
			result, _ := env.stack.Pop()
			if result.ToUint64() != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result.ToUint64())
			}
		})
	}
}

func TestJITCompiler_Execute_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		val      uint64
		expected uint64
	}{
		{"zero", 0, 1},
		{"non_zero", 42, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewJITCompiler(256)
			code := []byte{
				byte(PUSH1), byte(tt.val),
				byte(ISZERO), byte(STOP),
			}
			plan, _ := compiler.Compile(code)
			env := newMockEnv(100000)
			err := compiler.Execute(plan, env)
			if err != nil {
				t.Fatalf("execute failed: %v", err)
			}
			result, _ := env.stack.Pop()
			if result.ToUint64() != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result.ToUint64())
			}
		})
	}
}

func TestJITCompiler_Execute_BitwiseOps(t *testing.T) {
	tests := []struct {
		name     string
		op       OpCode
		a, b     uint64
		expected uint64
	}{
		{"and", AND, 0x0F, 0xF0, 0x00},
		{"or", OR, 0x0F, 0xF0, 0xFF},
		{"xor", XOR, 0x0F, 0xFF, 0xF0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler := NewJITCompiler(256)
			code := []byte{
				byte(PUSH1), byte(tt.a),
				byte(PUSH1), byte(tt.b),
				byte(tt.op), byte(STOP),
			}
			plan, _ := compiler.Compile(code)
			env := newMockEnv(100000)
			err := compiler.Execute(plan, env)
			if err != nil {
				t.Fatalf("execute failed: %v", err)
			}
			result, _ := env.stack.Pop()
			if result.ToUint64() != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result.ToUint64())
			}
		})
	}
}

func TestJITCompiler_Execute_Not(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x00, byte(NOT), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.IsZero() {
		t.Error("NOT of 0 should be non-zero (max uint256)")
	}
}

func TestJITCompiler_Execute_Shl(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x03, byte(PUSH1), 0x02, byte(SHL), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	expected := uint64(3 << 2)
	if result.ToUint64() != expected {
		t.Errorf("3 << 2 expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_Shr(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x0C, byte(PUSH1), 0x02, byte(SHR), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	expected := uint64(12 >> 2)
	if result.ToUint64() != expected {
		t.Errorf("12 >> 2 expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_Pop(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x2A, byte(PUSH1), 0x01, byte(POP), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if env.stack.Len() != 1 {
		t.Errorf("expected 1 item after pop, got %d", env.stack.Len())
	}
}

func TestJITCompiler_Execute_Dup(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x2A, byte(DUP1), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if env.stack.Len() != 2 {
		t.Fatalf("expected 2 items after dup, got %d", env.stack.Len())
	}
	top, _ := env.stack.Pop()
	second, _ := env.stack.Pop()
	if top != second {
		t.Error("DUP1 should duplicate the top item")
	}
	if top.ToUint64() != 0x2A {
		t.Errorf("expected 0x2A, got %d", top.ToUint64())
	}
}

func TestJITCompiler_Execute_Swap(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x01,
		byte(PUSH1), 0x02,
		byte(SWAP1),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	top, _ := env.stack.Pop()
	second, _ := env.stack.Pop()
	if top.ToUint64() != 0x01 {
		t.Errorf("after SWAP1 top should be 0x01, got %d", top.ToUint64())
	}
	if second.ToUint64() != 0x02 {
		t.Errorf("after SWAP1 second should be 0x02, got %d", second.ToUint64())
	}
}

func TestJITCompiler_Execute_MemoryOps(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x2A,
		byte(PUSH1), 0x00,
		byte(MSTORE),
		byte(PUSH1), 0x00,
		byte(MLOAD),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0x2A {
		t.Errorf("memory round-trip expected 0x2A, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_StorageOps(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x2A,
		byte(PUSH1), 0x01,
		byte(SSTORE),
		byte(PUSH1), 0x01,
		byte(SLOAD),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0x2A {
		t.Errorf("storage round-trip expected 0x2A, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_ContextOps(t *testing.T) {
	compiler := NewJITCompiler(256)

	t.Run("ADDRESS", func(t *testing.T) {
		code := []byte{byte(ADDRESS), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.address = Address{0x02}
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.Bytes()[12] != 0x02 {
			t.Errorf("ADDRESS expected byte 12 = 0x02, got 0x%02x", result.Bytes()[12])
		}
	})

	t.Run("CALLER", func(t *testing.T) {
		code := []byte{byte(CALLER), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.caller = Address{0x01}
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.Bytes()[12] != 0x01 {
			t.Errorf("CALLER expected byte 12 = 0x01, got 0x%02x", result.Bytes()[12])
		}
	})

	t.Run("ORIGIN", func(t *testing.T) {
		code := []byte{byte(ORIGIN), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.origin = Address{0x03}
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.Bytes()[12] != 0x03 {
			t.Errorf("ORIGIN expected byte 12 = 0x03, got 0x%02x", result.Bytes()[12])
		}
	})

	t.Run("CALLVALUE", func(t *testing.T) {
		code := []byte{byte(CALLVALUE), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.value = big.NewInt(100)
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.ToUint64() != 100 {
			t.Errorf("CALLVALUE expected 100, got %d", result.ToUint64())
		}
	})

	t.Run("NUMBER", func(t *testing.T) {
		code := []byte{byte(NUMBER), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.blockNumber = 42
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.ToUint64() != 42 {
			t.Errorf("NUMBER expected 42, got %d", result.ToUint64())
		}
	})

	t.Run("CHAINID", func(t *testing.T) {
		code := []byte{byte(CHAINID), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.chainID = 1669
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.ToUint64() != 1669 {
			t.Errorf("CHAINID expected 1669, got %d", result.ToUint64())
		}
	})

	t.Run("TIMESTAMP", func(t *testing.T) {
		code := []byte{byte(TIMESTAMP), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.timestamp = 1000
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.ToUint64() != 1000 {
			t.Errorf("TIMESTAMP expected 1000, got %d", result.ToUint64())
		}
	})

	t.Run("GASPRICE", func(t *testing.T) {
		code := []byte{byte(GASPRICE), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.gasPrice = big.NewInt(50)
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.ToUint64() != 50 {
			t.Errorf("GASPRICE expected 50, got %d", result.ToUint64())
		}
	})

	t.Run("CODESIZE", func(t *testing.T) {
		code := []byte{byte(CODESIZE), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.code = []byte{0x01, 0x02, 0x03}
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.ToUint64() != 3 {
			t.Errorf("CODESIZE expected 3, got %d", result.ToUint64())
		}
	})

	t.Run("CALLDATASIZE", func(t *testing.T) {
		code := []byte{byte(CALLDATASIZE), byte(STOP)}
		plan, _ := compiler.Compile(code)
		e := newMockEnv(100000)
		e.ctx.input = []byte{0xAA, 0xBB}
		compiler.Execute(plan, e)
		result, _ := e.stack.Pop()
		if result.ToUint64() != 2 {
			t.Errorf("CALLDATASIZE expected 2, got %d", result.ToUint64())
		}
	})
}

func TestJITCompiler_Execute_LogOps(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x20,
		byte(PUSH1), 0x00,
		byte(LOG0),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.memory.Store(0, make([]byte, 32))
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if len(env.logs) != 1 {
		t.Errorf("expected 1 log, got %d", len(env.logs))
	}
}

func TestJITCompiler_Execute_SelfBalance(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(SELFBALANCE), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.state.SetBalance(env.ctx.address, big.NewInt(1000))
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 1000 {
		t.Errorf("SELFBALANCE expected 1000, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_Balance(t *testing.T) {
	compiler := NewJITCompiler(256)
	targetAddr := Address{0x99}
	addrBytes := make([]byte, 32)
	copy(addrBytes[12:], targetAddr[:])
	code := append([]byte{byte(PUSH32)}, addrBytes...)
	code = append(code, byte(BALANCE), byte(STOP))
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.state.SetBalance(targetAddr, big.NewInt(500))
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 500 {
		t.Errorf("BALANCE expected 500, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_OutOfGas(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x01, byte(PUSH1), 0x02, byte(ADD), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(2)
	err := compiler.Execute(plan, env)
	if err == nil {
		t.Error("expected out of gas error, got nil")
	}
}

func TestJITCompiler_Execute_InvalidOpcode(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(INVALID)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err == nil {
		t.Error("expected invalid opcode error, got nil")
	}
}

func TestJITCompiler_Execute_Stop(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x01, byte(STOP), byte(PUSH1), 0x02}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if env.stack.Len() != 1 {
		t.Errorf("STOP should leave stack with 1 item, got %d", env.stack.Len())
	}
}

func TestJITCompiler_Execute_CallDataLoad(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x00,
		byte(CALLDATALOAD),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.input = []byte{0x01, 0x02, 0x03, 0x04}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.Bytes()[0] != 0x01 {
		t.Errorf("CALLDATALOAD first byte expected 0x01, got 0x%02x", result.Bytes()[0])
	}
}

func TestJITCompiler_Execute_CallDataCopy(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x04,
		byte(PUSH1), 0x00,
		byte(PUSH1), 0x00,
		byte(CALLDATACOPY),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.input = []byte{0x01, 0x02, 0x03, 0x04}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	data := env.memory.Load(0, 4)
	if len(data) != 4 || data[0] != 0x01 {
		t.Errorf("CALLDATACOPY expected [1,2,3,4], got %v", data)
	}
}

func TestJITCompiler_Execute_CodeCopy(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x03,
		byte(PUSH1), 0x00,
		byte(PUSH1), 0x00,
		byte(CODECOPY),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.code = []byte{0xAA, 0xBB, 0xCC}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	data := env.memory.Load(0, 3)
	if data[0] != 0xAA || data[1] != 0xBB || data[2] != 0xCC {
		t.Errorf("CODECOPY expected [AA,BB,CC], got %v", data)
	}
}

func TestJITCompiler_Execute_Sha3(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x04,
		byte(PUSH1), 0x00,
		byte(SHA3),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.memory.Store(0, []byte{0x01, 0x02, 0x03, 0x04})
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.IsZero() {
		t.Error("SHA3 should return non-zero hash")
	}
}

func TestJITCompiler_Execute_BlockHash(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x01,
		byte(BLOCKHASH),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	expectedHash := Hash{0xAA}
	env.blockHash = func(blockNum uint64) Hash {
		if blockNum == 1 {
			return expectedHash
		}
		return Hash{}
	}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.Bytes()[0] != 0xAA {
		t.Errorf("BLOCKHASH expected first byte 0xAA, got 0x%02x", result.Bytes()[0])
	}
}

func TestJITCompiler_Execute_MStore8(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x2A,
		byte(PUSH1), 0x00,
		byte(MSTORE8),
		byte(PUSH1), 0x00,
		byte(MLOAD),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.Bytes()[0] != 0x2A {
		t.Errorf("MSTORE8 round-trip expected 0x2A, got 0x%02x", result.Bytes()[0])
	}
}

func TestJITCompiler_Execute_Coinbase(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(COINBASE), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.coinbase = Address{0x10}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.Bytes()[12] != 0x10 {
		t.Errorf("COINBASE expected byte 12 = 0x10, got 0x%02x", result.Bytes()[12])
	}
}

func TestJITCompiler_Execute_Gas(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(GAS), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() == 0 {
		t.Error("GAS should return non-zero available gas")
	}
}

func TestJITCompiler_Execute_ComplexExpression(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x03,
		byte(PUSH1), 0x04,
		byte(MUL),
		byte(PUSH1), 0x02,
		byte(ADD),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	expected := uint64(3*4 + 2)
	if result.ToUint64() != expected {
		t.Errorf("(3*4)+2 expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_LogWithTopics(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x01,
		byte(PUSH1), 0x02,
		byte(PUSH1), 0x20,
		byte(PUSH1), 0x00,
		byte(LOG2),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.memory.Store(0, make([]byte, 32))
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if len(env.logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(env.logs))
	}
	if len(env.logs[0].Topics) != 2 {
		t.Errorf("LOG2 expected 2 topics, got %d", len(env.logs[0].Topics))
	}
}

func TestJITCompiler_Execute_Push2(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH2), 0x01, 0x02, byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.Bytes()[30] != 0x01 || result.Bytes()[31] != 0x02 {
		t.Errorf("PUSH2 expected [..., 0x01, 0x02], got %v", result.Bytes()[30:])
	}
}

func TestJITCompiler_Execute_Push32(t *testing.T) {
	compiler := NewJITCompiler(256)
	data := make([]byte, 32)
	data[31] = 0xFF
	code := append([]byte{byte(PUSH32)}, data...)
	code = append(code, byte(STOP))
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.Bytes()[31] != 0xFF {
		t.Errorf("PUSH32 expected last byte 0xFF, got 0x%02x", result.Bytes()[31])
	}
}

func TestJITCompiler_Execute_Dup2(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x01,
		byte(PUSH1), 0x02,
		byte(DUP2),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if env.stack.Len() != 3 {
		t.Fatalf("expected 3 items, got %d", env.stack.Len())
	}
	top, _ := env.stack.Pop()
	if top.ToUint64() != 0x01 {
		t.Errorf("DUP2 top expected 0x01, got %d", top.ToUint64())
	}
}

func TestJITCompiler_Execute_Swap2(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x01,
		byte(PUSH1), 0x02,
		byte(PUSH1), 0x03,
		byte(SWAP2),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	top, _ := env.stack.Pop()
	if top.ToUint64() != 0x01 {
		t.Errorf("SWAP2 top expected 0x01, got %d", top.ToUint64())
	}
}

func TestJITCompiler_Execute_PC(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PC), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("PC at position 0 expected 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_JumpDest(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(JUMPDEST), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if len(plan.JumpDests) != 1 {
		t.Errorf("expected 1 jumpdest, got %d", len(plan.JumpDests))
	}
}

func TestJITCompiler_Execute_ModByZero(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x00, byte(PUSH1), 0x0A, byte(MOD), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("mod by zero should return 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_ShlLarge(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0xFF, byte(PUSH1), 0x01, byte(SHL), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.IsZero() {
		t.Error("SHL by 255 should not be zero")
	}
}

func TestJITCompiler_Execute_ShlOver256(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x01, byte(PUSH2), 0x01, 0x01, byte(SHL), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if !result.IsZero() {
		t.Error("SHL by >= 256 should return 0")
	}
}

func TestJITCompiler_Execute_ShrOver256(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(PUSH1), 0x01, byte(PUSH2), 0x01, 0x01, byte(SHR), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if !result.IsZero() {
		t.Error("SHR by >= 256 should return 0")
	}
}

func TestJITCompiler_Execute_MultipleLogs(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x20, byte(PUSH1), 0x00, byte(LOG0),
		byte(PUSH1), 0x20, byte(PUSH1), 0x00, byte(LOG0),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.memory.Store(0, make([]byte, 64))
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if len(env.logs) != 2 {
		t.Errorf("expected 2 logs, got %d", len(env.logs))
	}
}

func TestJITCompiler_Execute_AllLogLevels(t *testing.T) {
	for level := 0; level <= 4; level++ {
		op := OpCode(byte(LOG0) + byte(level))
		compiler := NewJITCompiler(256)
		code := []byte{}
		for i := 0; i < level; i++ {
			code = append(code, byte(PUSH1), byte(i+1))
		}
		code = append(code, byte(PUSH1), 0x20, byte(PUSH1), 0x00, byte(op), byte(STOP))
		plan, _ := compiler.Compile(code)
		env := newMockEnv(100000)
		env.memory.Store(0, make([]byte, 32))
		err := compiler.Execute(plan, env)
		if err != nil {
			t.Errorf("LOG%d failed: %v", level, err)
		}
	}
}

func TestJITCompiler_Execute_StoragePersistence(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x2A, byte(PUSH1), 0x01, byte(SSTORE),
		byte(PUSH1), 0x2A, byte(PUSH1), 0x02, byte(SSTORE),
		byte(PUSH1), 0x01, byte(SLOAD),
		byte(PUSH1), 0x02, byte(SLOAD),
		byte(ADD),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	expected := uint64(0x2A + 0x2A)
	if result.ToUint64() != expected {
		t.Errorf("expected %d, got %d", expected, result.ToUint64())
	}
}

func TestJITCompiler_Execute_MemoryExpansion(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x2A,
		byte(PUSH2), 0x01, 0x00,
		byte(MSTORE),
		byte(PUSH2), 0x01, 0x00,
		byte(MLOAD),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0x2A {
		t.Errorf("memory expansion round-trip expected 0x2A, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_CallDataLoadOutOfBounds(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x10,
		byte(CALLDATALOAD),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.input = []byte{0x01}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if !result.IsZero() {
		t.Error("CALLDATALOAD out of bounds should return 0")
	}
}

func TestJITCompiler_Execute_CodeCopyOutOfBounds(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x10,
		byte(PUSH1), 0x10,
		byte(PUSH1), 0x00,
		byte(CODECOPY),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.code = []byte{0x01}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
}

func TestJITCompiler_Execute_CallDataCopyOutOfBounds(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{
		byte(PUSH1), 0x10,
		byte(PUSH1), 0x10,
		byte(PUSH1), 0x00,
		byte(CALLDATACOPY),
		byte(STOP),
	}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.input = []byte{0x01}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
}

func TestJITCompiler_Execute_EmptyInput(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(CALLDATASIZE), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.input = []byte{}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("CALLDATASIZE for empty input expected 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_EmptyCode(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(CODESIZE), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.code = []byte{}
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("CODESIZE for empty code expected 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_ZeroValue(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(CALLVALUE), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.value = big.NewInt(0)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("CALLVALUE for zero expected 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_ZeroGasPrice(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(GASPRICE), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.gasPrice = big.NewInt(0)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("GASPRICE for zero expected 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_ZeroBalance(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(SELFBALANCE), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("SELFBALANCE for new account expected 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_ZeroBlockNumber(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(NUMBER), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.blockNumber = 0
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("NUMBER for zero expected 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_ZeroTimestamp(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(TIMESTAMP), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.timestamp = 0
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("TIMESTAMP for zero expected 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_ZeroChainID(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(CHAINID), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	env.ctx.chainID = 0
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if result.ToUint64() != 0 {
		t.Errorf("CHAINID for zero expected 0, got %d", result.ToUint64())
	}
}

func TestJITCompiler_Execute_ZeroCoinbase(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(COINBASE), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if !result.IsZero() {
		t.Error("COINBASE for zero address should be zero")
	}
}

func TestJITCompiler_Execute_ZeroOrigin(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(ORIGIN), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if !result.IsZero() {
		t.Error("ORIGIN for zero address should be zero")
	}
}

func TestJITCompiler_Execute_ZeroCaller(t *testing.T) {
	compiler := NewJITCompiler(256)
	code := []byte{byte(CALLER), byte(STOP)}
	plan, _ := compiler.Compile(code)
	env := newMockEnv(100000)
	err := compiler.Execute(plan, env)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	result, _ := env.stack.Pop()
	if !result.IsZero() {
		t.Error("CALLER for zero address should be zero")
	}
}

func TestCompilationCache_NewWithZeroSize(t *testing.T) {
	c := NewCompilationCache(0)
	if c.Size() != 0 {
		t.Error("expected empty cache")
	}
}

func TestCompilationCache_PutAndGet(t *testing.T) {
	c := NewCompilationCache(10)
	hash := sha256.Sum256([]byte("code1"))
	plan := &ExecutionPlan{}

	c.Put(hash, plan)
	got, ok := c.Get(hash)
	if !ok {
		t.Error("expected cache hit")
	}
	if got != plan {
		t.Error("plan mismatch")
	}
}

func TestCompilationCache_Get_Miss(t *testing.T) {
	c := NewCompilationCache(10)
	hash := sha256.Sum256([]byte("missing"))
	_, ok := c.Get(hash)
	if ok {
		t.Error("expected cache miss")
	}
}

func TestCompilationCache_Put_Overwrite(t *testing.T) {
	c := NewCompilationCache(10)
	hash := sha256.Sum256([]byte("code"))
	p1 := &ExecutionPlan{}
	p2 := &ExecutionPlan{}

	c.Put(hash, p1)
	c.Put(hash, p2) // overwrite

	got, _ := c.Get(hash)
	if got != p2 {
		t.Error("expected overwritten plan")
	}
}

func TestCompilationCache_Eviction(t *testing.T) {
	c := NewCompilationCache(2)
	p1 := &ExecutionPlan{}
	p2 := &ExecutionPlan{}
	p3 := &ExecutionPlan{}

	h1 := sha256.Sum256([]byte("1"))
	h2 := sha256.Sum256([]byte("2"))
	h3 := sha256.Sum256([]byte("3"))

	c.Put(h1, p1)
	c.Put(h2, p2)
	c.Put(h3, p3) // should evict h1 (oldest)

	if c.Size() != 2 {
		t.Errorf("expected size 2, got %d", c.Size())
	}

	_, ok := c.Get(h1)
	if ok {
		t.Error("h1 should be evicted")
	}
	_, ok = c.Get(h2)
	if !ok {
		t.Error("h2 should remain")
	}
}

func TestCompilationCache_Remove(t *testing.T) {
	c := NewCompilationCache(10)
	hash := sha256.Sum256([]byte("code"))
	c.Put(hash, &ExecutionPlan{})

	c.Remove(hash)
	_, ok := c.Get(hash)
	if ok {
		t.Error("should be removed")
	}

	// Remove non-existent (no panic)
	c.Remove(sha256.Sum256([]byte("ghost")))
}

func TestCompilationCache_Clear(t *testing.T) {
	c := NewCompilationCache(10)
	c.Put(sha256.Sum256([]byte("a")), &ExecutionPlan{})
	c.Put(sha256.Sum256([]byte("b")), &ExecutionPlan{})

	c.Clear()
	if c.Size() != 0 {
		t.Error("expected empty after clear")
	}

	h, m, cmp := c.Stats()
	if h != 0 || m != 0 || cmp != 0 {
		t.Error("stats should be reset")
	}
}

func TestCompilationCache_Stats(t *testing.T) {
	c := NewCompilationCache(10)
	h1 := sha256.Sum256([]byte("k1"))
	h2 := sha256.Sum256([]byte("k2"))

	c.Put(h1, &ExecutionPlan{})
	c.Put(h2, &ExecutionPlan{})
	c.Get(h1)
	c.Get(h1)
	c.Get(sha256.Sum256([]byte("miss1")))
	c.Get(sha256.Sum256([]byte("miss2")))

	hits, misses, compiles := c.Stats()
	if hits != 2 {
		t.Errorf("expected 2 hits, got %d", hits)
	}
	if misses != 2 {
		t.Errorf("expected 2 misses, got %d", misses)
	}
	if compiles != 2 {
		t.Errorf("expected 2 compiles, got %d", compiles)
	}
}

func TestCompilationCache_HitRate(t *testing.T) {
	c := NewCompilationCache(10)

	// Zero total
	if c.HitRate() != 0.0 {
		t.Error("hit rate should be 0 when no lookups")
	}

	h1 := sha256.Sum256([]byte("k1"))
	c.Put(h1, &ExecutionPlan{})
	c.Get(h1)
	c.Get(h1)
	c.Get(sha256.Sum256([]byte("miss")))

	rate := c.HitRate()
	if rate != 2.0/3.0 {
		t.Errorf("expected 2/3 hit rate, got %f", rate)
	}
}

func TestPrecompileQueue_New(t *testing.T) {
	compiler := NewJITCompiler(256)
	q := NewPrecompileQueue(compiler, 0)
	if q.Size() != 0 {
		t.Error("expected empty queue")
	}
}

func TestPrecompileQueue_Enqueue(t *testing.T) {
	compiler := NewJITCompiler(256)
	q := NewPrecompileQueue(compiler, 10)

	hash := sha256.Sum256([]byte{byte(PUSH1), 0x01, byte(STOP)})
	q.Enqueue(hash, []byte{byte(PUSH1), 0x01, byte(STOP)}, 5)
	if q.Size() != 1 {
		t.Errorf("expected size 1, got %d", q.Size())
	}
}

func TestPrecompileQueue_Enqueue_Duplicate(t *testing.T) {
	compiler := NewJITCompiler(256)
	q := NewPrecompileQueue(compiler, 10)

	hash := sha256.Sum256([]byte{byte(PUSH1), 0x01, byte(STOP)})
	code := []byte{byte(PUSH1), 0x01, byte(STOP)}
	q.Enqueue(hash, code, 1)
	q.Enqueue(hash, code, 10)
	if q.Size() != 1 {
		t.Errorf("expected size 1 (duplicate), got %d", q.Size())
	}

	// Check priority updated
	entry := q.Dequeue()
	if entry == nil || entry.Priority != 10 {
		t.Errorf("expected priority 10, got %v", entry)
	}
}

func TestPrecompileQueue_Enqueue_FullQueue(t *testing.T) {
	compiler := NewJITCompiler(256)
	q := NewPrecompileQueue(compiler, 2)

	q.Enqueue(sha256.Sum256([]byte("a")), []byte{byte(STOP)}, 1)
	q.Enqueue(sha256.Sum256([]byte("b")), []byte{byte(STOP)}, 2)
	// Queue is full, replace lowest priority (priority 1 entry)
	q.Enqueue(sha256.Sum256([]byte("c")), []byte{byte(STOP)}, 3)

	if q.Size() != 2 {
		t.Errorf("expected size 2, got %d", q.Size())
	}
}

func TestPrecompileQueue_Dequeue_Empty(t *testing.T) {
	compiler := NewJITCompiler(256)
	q := NewPrecompileQueue(compiler, 10)
	if q.Dequeue() != nil {
		t.Error("expected nil from empty queue")
	}
}

func TestPrecompileQueue_Dequeue_PriorityOrder(t *testing.T) {
	compiler := NewJITCompiler(256)
	q := NewPrecompileQueue(compiler, 10)

	q.Enqueue(sha256.Sum256([]byte("a")), []byte{byte(STOP)}, 1)
	q.Enqueue(sha256.Sum256([]byte("b")), []byte{byte(STOP)}, 5)
	q.Enqueue(sha256.Sum256([]byte("c")), []byte{byte(STOP)}, 3)

	e := q.Dequeue()
	if e == nil || e.Priority != 5 {
		t.Errorf("expected highest priority (5), got %d", e.Priority)
	}
}

func TestPrecompileQueue_Stats(t *testing.T) {
	compiler := NewJITCompiler(256)
	q := NewPrecompileQueue(compiler, 10)
	q.Enqueue(sha256.Sum256([]byte("x")), []byte{byte(STOP)}, 1)

	pre, skip, qlen := q.Stats()
	if pre != 0 || skip != 0 || qlen != 1 {
		t.Errorf("stats mismatch: pre=%d skipped=%d qlen=%d", pre, skip, qlen)
	}
}

func TestPrecompileQueue_PrecompileBatch(t *testing.T) {
	compiler := NewJITCompiler(256)
	q := NewPrecompileQueue(compiler, 10)

	codes := [][]byte{
		{byte(PUSH1), 0x2A, byte(STOP)},
		{byte(PUSH1), 0x01, byte(PUSH1), 0x02, byte(ADD), byte(STOP)},
	}
	count := q.PrecompileBatch(codes)
	if count != 2 {
		t.Errorf("expected 2 compiled, got %d", count)
	}
}

func TestPrecompileQueue_PrecompileBatch_Empty(t *testing.T) {
	compiler := NewJITCompiler(256)
	q := NewPrecompileQueue(compiler, 10)

	count := q.PrecompileBatch([][]byte{})
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestCompiler_Cache(t *testing.T) {
	compiler := NewJITCompiler(64)
	c := compiler.Cache()
	if c == nil {
		t.Error("expected non-nil cache")
	}
	if c.Size() != 0 {
		t.Error("expected empty cache")
	}
}

func TestJITCompiler_Compile_CacheIntegration(t *testing.T) {
	compiler := NewJITCompiler(10)
	code := []byte{byte(PUSH1), 0x01, byte(PUSH1), 0x02, byte(ADD), byte(STOP)}

	plan1, err1 := compiler.Compile(code)
	plan2, err2 := compiler.Compile(code)

	if err1 != nil || err2 != nil {
		t.Fatalf("compile failed: %v, %v", err1, err2)
	}
	if plan1 == nil || plan2 == nil {
		t.Fatal("compile returned nil")
	}
}

func TestVMError(t *testing.T) {
	e := &vmError{msg: "test error"}
	if e.Error() != "test error" {
		t.Errorf("expected 'test error', got '%s'", e.Error())
	}
}

func TestPrecompileQueue_StartStop(t *testing.T) {
	compiler := NewJITCompiler(10)
	q := NewPrecompileQueue(compiler, 64)
	q.Start(time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	q.Stop()
}

func TestPrecompileQueue_EnqueueProcess(t *testing.T) {
	compiler := NewJITCompiler(10)
	q := NewPrecompileQueue(compiler, 64)

	var codeHash [32]byte
	codeHash[0] = 1
	q.Enqueue(codeHash, []byte{byte(STOP)}, 1)

	q.Start(time.Millisecond)
	time.Sleep(3 * time.Millisecond)
	q.Stop()
}

// FIX: JIT consistency tests for CALL/CREATE opcodes.
// These tests verify that the JIT compiler correctly handles CALL and CREATE,
// including gas charging (base cost, 63/64 rule, reentrancy guard).

func TestJITCompiler_Execute_CALL_Success(t *testing.T) {
	// CALL with: gas=10000, addr=0x01, value=0, inOffset=0, inSize=0, outOffset=0, outSize=0
	// Stack order (top to bottom): gas, addr, value, inOffset, inSize, outOffset, outSize
	code := []byte{
		byte(PUSH1), 0x00, // outSize
		byte(PUSH1), 0x00, // outOffset
		byte(PUSH1), 0x00, // inSize
		byte(PUSH1), 0x00, // inOffset
		byte(PUSH1), 0x00, // value
		byte(PUSH1), 0x01, // addr (padded to 32 bytes, last byte = 0x01)
		byte(PUSH2), 0x27, 0x10, // gas = 10000
		byte(CALL),
		byte(STOP),
	}
	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	env := newMockEnv(100000)
	env.callSucceeds = true
	// Mark target address as existing so no new-account gas is charged.
	env.state.exist[Address{0x01}] = true

	if err := compiler.Execute(plan, env); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Verify CALL was invoked.
	if env.callCount != 1 {
		t.Errorf("expected 1 CALL, got %d", env.callCount)
	}

	// Verify gas was consumed (at least base CALL cost + some gas to callee).
	consumed := env.gas.used
	if consumed == 0 {
		t.Error("expected gas to be consumed by CALL")
	}

	// Verify success return value on stack.
	result, _ := env.stack.Pop()
	if result.IsZero() {
		t.Error("expected CALL to return success (1) on stack")
	}
}

func TestJITCompiler_Execute_CALL_ReentrancyGuardGas(t *testing.T) {
	// Same CALL but with reentrancy detected (addrActive=true, callDepth=1).
	// The JIT compiler should charge 2300 gas BEFORE the 63/64 rule.
	code := []byte{
		byte(PUSH1), 0x00, // outSize
		byte(PUSH1), 0x00, // outOffset
		byte(PUSH1), 0x00, // inSize
		byte(PUSH1), 0x00, // inOffset
		byte(PUSH1), 0x00, // value
		byte(PUSH1), 0x01, // addr
		byte(PUSH2), 0x27, 0x10, // gas = 10000
		byte(CALL),
		byte(STOP),
	}
	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	// Test 1: Without reentrancy (baseline gas).
	envBase := newMockEnv(100000)
	envBase.callSucceeds = true
	envBase.addrActive = false
	envBase.callDepthVal = 1
	envBase.state.exist[Address{0x01}] = true // exist check not used (no value), keep for clarity
	if err := compiler.Execute(plan, envBase); err != nil {
		t.Fatalf("baseline execute failed: %v", err)
	}
	baseConsumed := envBase.gas.used

	// Test 2: With reentrancy (should consume 2300 more gas).
	// FIX: targetHasCode must be true for reentrancy guard to fire.
	// Set code at target address so GetCode returns non-empty slice.
	// PUSH1 0x01 creates addr with 0x01 at byte[19] (big-endian, last byte).
	var targetAddr Address
	targetAddr[19] = 0x01
	envReentry := newMockEnv(100000)
	envReentry.callSucceeds = true
	envReentry.addrActive = true
	envReentry.callDepthVal = 1
	envReentry.state.exist[targetAddr] = true
	envReentry.state.codes[targetAddr] = []byte{0x00} // target has code
	if err := compiler.Execute(plan, envReentry); err != nil {
		t.Fatalf("reentry execute failed: %v", err)
	}
	reentryConsumed := envReentry.gas.used

	diff := reentryConsumed - baseConsumed
	if diff < 2300 {
		t.Errorf("reentrancy guard gas: expected >= 2300 extra gas, got %d (base=%d, reentry=%d)",
			diff, baseConsumed, reentryConsumed)
	}
}

func TestJITCompiler_Execute_CREATE_Success(t *testing.T) {
	// CREATE with: value=0, inOffset=0, inSize=0
	// Stack order: value, inOffset, inSize
	code := []byte{
		byte(PUSH1), 0x00, // inSize
		byte(PUSH1), 0x00, // inOffset
		byte(PUSH1), 0x00, // value
		byte(PUSH2), 0x27, 0x10, // gas (not on stack for CREATE, but we need gas in env)
		byte(POP), // pop the gas (CREATE doesn't take gas arg on stack)
		byte(CREATE),
		byte(STOP),
	}
	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	env := newMockEnv(100000)
	env.callSucceeds = true

	if err := compiler.Execute(plan, env); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Verify CREATE was invoked.
	if env.createCount != 1 {
		t.Errorf("expected 1 CREATE, got %d", env.createCount)
	}

	// Verify gas was consumed.
	consumed := env.gas.used
	if consumed == 0 {
		t.Error("expected gas to be consumed by CREATE")
	}

	// Verify address was pushed on stack (non-zero for success).
	result, _ := env.stack.Pop()
	if result.IsZero() {
		t.Error("expected CREATE to return non-zero address on stack")
	}
}

func TestJITCompiler_Execute_STATICCALL_Success(t *testing.T) {
	// STATICCALL with: gas=10000, addr=0x01, inOffset=0, inSize=0, outOffset=0, outSize=0
	code := []byte{
		byte(PUSH1), 0x00, // outSize
		byte(PUSH1), 0x00, // outOffset
		byte(PUSH1), 0x00, // inSize
		byte(PUSH1), 0x00, // inOffset
		byte(PUSH1), 0x01, // addr
		byte(PUSH2), 0x27, 0x10, // gas = 10000
		byte(STATICCALL),
		byte(STOP),
	}
	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	env := newMockEnv(100000)
	env.callSucceeds = true

	if err := compiler.Execute(plan, env); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Verify success return value on stack.
	result, _ := env.stack.Pop()
	if result.IsZero() {
		t.Error("expected STATICCALL to return success (1) on stack")
	}
}

func TestJITCompiler_Execute_DELEGATECALL_Success(t *testing.T) {
	// DELEGATECALL with: gas=10000, addr=0x01, inOffset=0, inSize=0, outOffset=0, outSize=0
	code := []byte{
		byte(PUSH1), 0x00, // outSize
		byte(PUSH1), 0x00, // outOffset
		byte(PUSH1), 0x00, // inSize
		byte(PUSH1), 0x00, // inOffset
		byte(PUSH1), 0x01, // addr
		byte(PUSH2), 0x27, 0x10, // gas = 10000
		byte(DELEGATECALL),
		byte(STOP),
	}
	compiler := NewJITCompiler(256)
	plan, err := compiler.Compile(code)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	env := newMockEnv(100000)
	env.callSucceeds = true

	if err := compiler.Execute(plan, env); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Verify success return value on stack.
	result, _ := env.stack.Pop()
	if result.IsZero() {
		t.Error("expected DELEGATECALL to return success (1) on stack")
	}
}
