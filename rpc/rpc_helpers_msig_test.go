// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"math/big"

	"github.com/quantaureum/qau/types"
)

// mockChainStateDBHC is a no-op ChainStateDB used by multisig API tests.
// It lives in a tracked test helper so CI can compile the audited regression
// tests that reference it (the local-only coverage file previously defining
// it is excluded by .gitignore's *_cover* pattern).
type mockChainStateDBHC struct{}

func (m *mockChainStateDBHC) GetState(addr types.Address, key types.Hash) types.Hash {
	return types.Hash{}
}

func (m *mockChainStateDBHC) SetState(addr types.Address, key, value types.Hash) {}

func (m *mockChainStateDBHC) GetBalance(addr types.Address) *big.Int { return big.NewInt(0) }

func (m *mockChainStateDBHC) SubBalance(addr types.Address, amount *big.Int) error { return nil }

func (m *mockChainStateDBHC) AddBalance(addr types.Address, amount *big.Int) error { return nil }
