// Quantaureum Node source, version 1.0.0.
package parallel

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// minimalMockState is a minimal StateDB implementation for testing the
// consensus-safe guard without depending on the full QVM stack.
type minimalMockState struct {
	balances map[types.Address]*big.Int
	nonces   map[types.Address]uint64
	codes    map[types.Address][]byte
	storage  map[types.Address]map[types.Hash]types.Hash
}

func newMinimalMockState() *minimalMockState {
	return &minimalMockState{
		balances: make(map[types.Address]*big.Int),
		nonces:   make(map[types.Address]uint64),
		codes:    make(map[types.Address][]byte),
		storage:  make(map[types.Address]map[types.Hash]types.Hash),
	}
}

func (m *minimalMockState) GetBalance(addr types.Address) *big.Int {
	if b, ok := m.balances[addr]; ok {
		return b
	}
	return big.NewInt(0)
}
func (m *minimalMockState) SetBalance(addr types.Address, balance *big.Int) {
	m.balances[addr] = new(big.Int).Set(balance)
}
func (m *minimalMockState) GetNonce(addr types.Address) uint64        { return m.nonces[addr] }
func (m *minimalMockState) SetNonce(addr types.Address, nonce uint64) { m.nonces[addr] = nonce }
func (m *minimalMockState) GetCode(addr types.Address) []byte         { return m.codes[addr] }
func (m *minimalMockState) SetCode(addr types.Address, code []byte)   { m.codes[addr] = code }
func (m *minimalMockState) GetCodeSize(addr types.Address) int        { return len(m.codes[addr]) }
func (m *minimalMockState) GetState(addr types.Address, key types.Hash) types.Hash {
	if s, ok := m.storage[addr]; ok {
		return s[key]
	}
	return types.Hash{}
}
func (m *minimalMockState) SetState(addr types.Address, key, value types.Hash) {
	if m.storage[addr] == nil {
		m.storage[addr] = make(map[types.Hash]types.Hash)
	}
	m.storage[addr][key] = value
}
func (m *minimalMockState) Snapshot() int                               { return 0 }
func (m *minimalMockState) RevertToSnapshot(id int)                     {}
func (m *minimalMockState) AddressInAccessList(addr types.Address) bool { return false }
func (m *minimalMockState) SlotInAccessList(addr types.Address, slot types.Hash) (bool, bool) {
	return false, false
}

// TestR4QVM01_Execute_RefusedByDefault verifies that ParallelQVM.Execute
// returns ErrParallelQVMNotConsensusSafe when called without first calling
// EnableConsensusMode(). This prevents accidental wiring of the
// non-consensus-safe Execute into the consensus path (which would cause
// nonce/intrinsic-gas divergence vs. the sequential executor).
//
// AUDIT (2026) R4-QVM-01.
func TestR4QVM01_Execute_RefusedByDefault(t *testing.T) {
	config := DefaultParallelQVMConfig()
	config.ChainID = 1 // Set ChainID to isolate the test to the consensusSafe guard
	pq := NewParallelQVM(config)

	calls := []*ContractCall{
		NewContractCall(0, types.Address{0x02}, types.Address{0x01}, nil, 100000, 0),
	}

	_, err := pq.Execute(calls, newMinimalMockState())
	if err != ErrParallelQVMNotConsensusSafe {
		t.Fatalf("R4-QVM-01: expected ErrParallelQVMNotConsensusSafe, got %v", err)
	}
}

// TestR4QVM01_EnableConsensusMode_PassesGuard verifies that after calling
// EnableConsensusMode(), the consensusSafe guard is bypassed and execution
// proceeds (may still fail for other reasons, but NOT with
// ErrParallelQVMNotConsensusSafe).
//
// AUDIT (2026) R4-QVM-01.
func TestR4QVM01_EnableConsensusMode_PassesGuard(t *testing.T) {
	config := DefaultParallelQVMConfig()
	config.ChainID = 1
	pq := NewParallelQVM(config)
	pq.EnableConsensusMode()

	// Use a call with Value=0 and no code at the target — executeCall will
	// take the "no code" fast path and return success without invoking
	// the interpreter, so we don't need a full QVM setup.
	calls := []*ContractCall{
		NewContractCall(0, types.Address{0x02}, types.Address{0x01}, nil, 100000, 0),
	}

	results, err := pq.Execute(calls, newMinimalMockState())
	if err == ErrParallelQVMNotConsensusSafe {
		t.Fatal("R4-QVM-01: EnableConsensusMode should bypass the guard, but ErrParallelQVMNotConsensusSafe was returned")
	}
	// Other errors are acceptable — we only verify the guard was bypassed.
	if err != nil && results == nil {
		t.Logf("R4-QVM-01: Execute returned error (acceptable, guard was bypassed): %v", err)
	} else {
		t.Logf("R4-QVM-01: Execute succeeded after EnableConsensusMode (results=%d)", len(results))
	}
}
