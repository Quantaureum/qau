// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qvm/jit"
)

type benchStateDB struct {
	balances map[Address]*big.Int
	storage  map[Address]map[Hash]Hash
	codes    map[Address][]byte
}

func newBenchStateDB() *benchStateDB {
	return &benchStateDB{
		balances: make(map[Address]*big.Int),
		storage:  make(map[Address]map[Hash]Hash),
		codes:    make(map[Address][]byte),
	}
}

func (s *benchStateDB) GetBalance(addr Address) *big.Int {
	if b, ok := s.balances[addr]; ok {
		return new(big.Int).Set(b)
	}
	return big.NewInt(0)
}

func (s *benchStateDB) SetBalance(addr Address, balance *big.Int) {
	s.balances[addr] = new(big.Int).Set(balance)
}

func (s *benchStateDB) GetNonce(addr Address) uint64        { return 0 }
func (s *benchStateDB) SetNonce(addr Address, nonce uint64) {}

func (s *benchStateDB) GetCode(addr Address) []byte {
	if c, ok := s.codes[addr]; ok {
		return c
	}
	return nil
}

func (s *benchStateDB) SetCode(addr Address, code []byte) {
	s.codes[addr] = code
}

func (s *benchStateDB) GetCodeHash(addr Address) Hash {
	code := s.GetCode(addr)
	if code == nil {
		return Hash{}
	}
	var h Hash
	copy(h[:], code)
	return h
}

func (s *benchStateDB) GetCodeSize(addr Address) int {
	return len(s.GetCode(addr))
}

func (s *benchStateDB) GetState(addr Address, key Hash) Hash {
	if store, ok := s.storage[addr]; ok {
		if val, ok2 := store[key]; ok2 {
			return val
		}
	}
	return Hash{}
}

func (s *benchStateDB) SetState(addr Address, key, value Hash) {
	if s.storage[addr] == nil {
		s.storage[addr] = make(map[Hash]Hash)
	}
	s.storage[addr][key] = value
}

func (s *benchStateDB) Exist(addr Address) bool { return true }
func (s *benchStateDB) Empty(addr Address) bool { return false }

func (s *benchStateDB) Snapshot() int           { return 0 }
func (s *benchStateDB) RevertToSnapshot(id int) {}

func (s *benchStateDB) AddBalance(addr Address, amount *big.Int) {
	bal := s.GetBalance(addr)
	s.SetBalance(addr, new(big.Int).Add(bal, amount))
}

func (s *benchStateDB) SubBalance(addr Address, amount *big.Int) {
	bal := s.GetBalance(addr)
	s.SetBalance(addr, new(big.Int).Sub(bal, amount))
}

func (s *benchStateDB) AddRefund(uint64)  {}
func (s *benchStateDB) SubRefund(uint64)  {}
func (s *benchStateDB) GetRefund() uint64 { return 0 }

func (s *benchStateDB) AddLog(*Log)              {}
func (s *benchStateDB) AddPreimage(Hash, []byte) {}

func (s *benchStateDB) Suicide(addr Address) bool           { return false }
func (s *benchStateDB) HasSuicided(addr Address) bool       { return false }
func (s *benchStateDB) SelfDestruct(addr Address)           {}
func (s *benchStateDB) HasSelfDestructed(addr Address) bool { return false }

func (s *benchStateDB) AddAddressToAccessList(addr Address)                   {}
func (s *benchStateDB) AddSlotToAccessList(addr Address, slot Hash)           {}
func (s *benchStateDB) AddressInAccessList(addr Address) bool                 { return true }
func (s *benchStateDB) SlotInAccessList(addr Address, slot Hash) (bool, bool) { return true, true }

func makeBenchCtx(code []byte, gas uint64) *ExecutionContext {
	return &ExecutionContext{
		Origin:      Address{0x01},
		GasPrice:    big.NewInt(100),
		Caller:      Address{0x01},
		Address:     Address{0x02},
		Value:       big.NewInt(0),
		BlockNumber: 100,
		Timestamp:   1000000,
		Coinbase:    Address{0x03},
		GasLimit:    gas,
		ChainID:     1,
		Code:        code,
		Input:       nil,
		Gas:         gas,
		Depth:       0,
		ReadOnly:    false,
	}
}

func makeSimpleArithmeticCode() []byte {
	return []byte{
		byte(PUSH1), 0x03,
		byte(PUSH1), 0x04,
		byte(ADD),
		byte(PUSH1), 0x02,
		byte(MUL),
		byte(PUSH1), 0x05,
		byte(SUB),
		byte(STOP),
	}
}

func makeMemoryIntensiveCode() []byte {
	code := []byte{}
	for i := 0; i < 10; i++ {
		code = append(code, byte(PUSH1), byte(i))
		code = append(code, byte(PUSH1), byte(i*32))
		code = append(code, byte(MSTORE))
	}
	code = append(code, byte(STOP))
	return code
}

func makeStorageIntensiveCode() []byte {
	code := []byte{}
	for i := 0; i < 5; i++ {
		code = append(code, byte(PUSH1), byte(i+1))
		code = append(code, byte(PUSH1), byte(i))
		code = append(code, byte(SSTORE))
	}
	code = append(code, byte(STOP))
	return code
}

func makeLoopCode(iterations byte) []byte {
	return []byte{
		byte(PUSH1), iterations,
		byte(JUMPDEST),
		byte(PUSH1), 0x01,
		byte(SWAP1),
		byte(SUB),
		byte(DUP1),
		byte(PUSH1), 0x00,
		byte(GT),
		byte(PUSH1), 0x02,
		byte(JUMPI),
		byte(STOP),
	}
}

func makeHashIntensiveCode() []byte {
	code := []byte{}
	for i := 0; i < 5; i++ {
		code = append(code, byte(PUSH1), 0x20)
		code = append(code, byte(PUSH1), 0x00)
		code = append(code, byte(SHA3))
		code = append(code, byte(POP))
	}
	code = append(code, byte(STOP))
	return code
}

func BenchmarkInterpreter_SimpleArithmetic(b *testing.B) {
	code := makeSimpleArithmeticCode()
	interpreter := NewInterpreter()
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 100000)
		interpreter.Execute(ctx, stateDB)
	}
}

func BenchmarkJIT_SimpleArithmetic(b *testing.B) {
	code := makeSimpleArithmeticCode()
	compiler := jit.NewJITCompiler(256)
	plan, _ := compiler.Compile(code)
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 100000)
		env := &Environment{
			ctx:      ctx,
			stateDB:  stateDB,
			stack:    NewStack(),
			memory:   NewMemory(),
			gas:      NewGasMeter(ctx.Gas),
			gasTable: DefaultGasTable(),
		}
		jitEnv := newJITEnvAdapter(env, NewInterpreter())
		compiler.Execute(plan, jitEnv)
	}
}

func BenchmarkInterpreter_MemoryIntensive(b *testing.B) {
	code := makeMemoryIntensiveCode()
	interpreter := NewInterpreter()
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 100000)
		interpreter.Execute(ctx, stateDB)
	}
}

func BenchmarkJIT_MemoryIntensive(b *testing.B) {
	code := makeMemoryIntensiveCode()
	compiler := jit.NewJITCompiler(256)
	plan, _ := compiler.Compile(code)
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 100000)
		env := &Environment{
			ctx:      ctx,
			stateDB:  stateDB,
			stack:    NewStack(),
			memory:   NewMemory(),
			gas:      NewGasMeter(ctx.Gas),
			gasTable: DefaultGasTable(),
		}
		jitEnv := newJITEnvAdapter(env, NewInterpreter())
		compiler.Execute(plan, jitEnv)
	}
}

func BenchmarkInterpreter_StorageIntensive(b *testing.B) {
	code := makeStorageIntensiveCode()
	interpreter := NewInterpreter()
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 100000)
		interpreter.Execute(ctx, stateDB)
	}
}

func BenchmarkJIT_StorageIntensive(b *testing.B) {
	code := makeStorageIntensiveCode()
	compiler := jit.NewJITCompiler(256)
	plan, _ := compiler.Compile(code)
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 100000)
		env := &Environment{
			ctx:      ctx,
			stateDB:  stateDB,
			stack:    NewStack(),
			memory:   NewMemory(),
			gas:      NewGasMeter(ctx.Gas),
			gasTable: DefaultGasTable(),
		}
		jitEnv := newJITEnvAdapter(env, NewInterpreter())
		compiler.Execute(plan, jitEnv)
	}
}

func BenchmarkInterpreter_Loop(b *testing.B) {
	code := makeLoopCode(50)
	interpreter := NewInterpreter()
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 1000000)
		interpreter.Execute(ctx, stateDB)
	}
}

func BenchmarkJIT_Loop(b *testing.B) {
	code := makeLoopCode(50)
	compiler := jit.NewJITCompiler(256)
	plan, _ := compiler.Compile(code)
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 1000000)
		env := &Environment{
			ctx:      ctx,
			stateDB:  stateDB,
			stack:    NewStack(),
			memory:   NewMemory(),
			gas:      NewGasMeter(ctx.Gas),
			gasTable: DefaultGasTable(),
		}
		jitEnv := newJITEnvAdapter(env, NewInterpreter())
		compiler.Execute(plan, jitEnv)
	}
}

func BenchmarkInterpreter_HashIntensive(b *testing.B) {
	code := makeHashIntensiveCode()
	interpreter := NewInterpreter()
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 100000)
		interpreter.Execute(ctx, stateDB)
	}
}

func BenchmarkJIT_HashIntensive(b *testing.B) {
	code := makeHashIntensiveCode()
	compiler := jit.NewJITCompiler(256)
	plan, _ := compiler.Compile(code)
	stateDB := newBenchStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := makeBenchCtx(code, 100000)
		env := &Environment{
			ctx:      ctx,
			stateDB:  stateDB,
			stack:    NewStack(),
			memory:   NewMemory(),
			gas:      NewGasMeter(ctx.Gas),
			gasTable: DefaultGasTable(),
		}
		jitEnv := newJITEnvAdapter(env, NewInterpreter())
		compiler.Execute(plan, jitEnv)
	}
}

func BenchmarkJITCompiler_Compile(b *testing.B) {
	code := makeSimpleArithmeticCode()
	compiler := jit.NewJITCompiler(256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compiler.Compile(code)
	}
}

func BenchmarkJITCompiler_CompileWithCache(b *testing.B) {
	code := makeSimpleArithmeticCode()
	compiler := jit.NewJITCompiler(256)
	compiler.Compile(code)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compiler.Compile(code)
	}
}
