// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// r4SimStateDB is a minimal StateDB for SimulateValidation tests: it only
// carries the code entries the tests set; everything else is empty.
type r4SimStateDB struct {
	codes map[Address][]byte
}

func newR4SimStateDB() *r4SimStateDB {
	return &r4SimStateDB{codes: make(map[Address][]byte)}
}

func (s *r4SimStateDB) GetBalance(addr Address) *big.Int {
	return big.NewInt(0)
}
func (s *r4SimStateDB) SetBalance(addr Address, balance *big.Int) {}
func (s *r4SimStateDB) GetNonce(addr Address) uint64              { return 0 }
func (s *r4SimStateDB) SetNonce(addr Address, nonce uint64)       {}
func (s *r4SimStateDB) GetCode(addr Address) []byte {
	if c, ok := s.codes[addr]; ok {
		return c
	}
	return nil
}
func (s *r4SimStateDB) SetCode(addr Address, code []byte)    { s.codes[addr] = code }
func (s *r4SimStateDB) GetCodeHash(addr Address) Hash        { return Hash{} }
func (s *r4SimStateDB) GetCodeSize(addr Address) int         { return len(s.GetCode(addr)) }
func (s *r4SimStateDB) GetState(addr Address, key Hash) Hash { return Hash{} }
func (s *r4SimStateDB) SetState(addr Address, key, value Hash) {
}
func (s *r4SimStateDB) Exist(addr Address) bool {
	_, ok := s.codes[addr]
	return ok
}
func (s *r4SimStateDB) Empty(addr Address) bool             { return len(s.GetCode(addr)) == 0 }
func (s *r4SimStateDB) Snapshot() int                       { return 0 }
func (s *r4SimStateDB) RevertToSnapshot(id int)             {}
func (s *r4SimStateDB) SelfDestruct(addr Address)           {}
func (s *r4SimStateDB) HasSelfDestructed(addr Address) bool { return false }
func (s *r4SimStateDB) AddAddressToAccessList(addr Address) {
}
func (s *r4SimStateDB) AddSlotToAccessList(addr Address, slot Hash) {}
func (s *r4SimStateDB) AddressInAccessList(addr Address) bool       { return false }
func (s *r4SimStateDB) SlotInAccessList(addr Address, slot Hash) (bool, bool) {
	return false, false
}

func r4SimUserOp(sender types.Address, initCode []byte) *encoding.UserOperation {
	return &encoding.UserOperation{
		Sender:               sender,
		Nonce:                0,
		CallData:             []byte{0x01},
		InitCode:             initCode,
		CallGasLimit:         21000,
		VerificationGasLimit: 100000,
		PreVerificationGas:   21000,
		MaxFeePerGas:         big.NewInt(2_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(1_500_000_000),
		Signature:            []byte{0xde, 0xad},
	}
}

// R4-RES: SimulateValidation (the admission-validation path the bundler uses)
// must reject a sender with no code and no InitCode with ErrSenderNotContract,
// matching handleSingleOp's guard.
func TestSimulateValidation_R4Res_CodelessSenderRejected(t *testing.T) {
	ep := NewEntryPoint(nil)
	stateDB := newR4SimStateDB()
	sender := types.Address{0x11}

	res, err := ep.SimulateValidation(r4SimUserOp(sender, nil), stateDB, &BlockContext{GasLimit: 1000000}, &encoding.UserOpBundle{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatal("codeless sender with empty InitCode must not validate")
	}
	if !errors.Is(res.ValidationError, ErrSenderNotContract) {
		t.Fatalf("expected ErrSenderNotContract, got: %v", res.ValidationError)
	}
}

// A sender that carries contract code is not rejected by the codeless guard:
// the simulation proceeds past the guard into the execution path. With a fully
// constructed executor (no EVM adapter), that path fails for other reasons —
// the assertion is that the guard itself did not fire.
func TestSimulateValidation_R4Res_CodelessGuardNotFiredForContract(t *testing.T) {
	ep := NewEntryPoint(NewExecutor())
	sender := types.Address{0x22}

	stateDB := newR4SimStateDB()
	stateDB.codes[Address(sender)] = []byte{0x60, 0x00} // sender with code
	_, err := ep.SimulateValidation(r4SimUserOp(sender, nil), stateDB, &BlockContext{GasLimit: 1000000}, &encoding.UserOpBundle{})
	if err != nil && errors.Is(err, ErrSenderNotContract) {
		t.Fatalf("codeless guard must not fire for a contract sender, got: %v", err)
	}
}
