// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// clearTxStateTrackingStateDB is a test StateDB that tracks whether
// ClearTxState was called. It implements the txStateResetter optional
// interface so the executor's per-tx cleanup logic can be verified.
type clearTxStateTrackingStateDB struct {
	mockState
	clearTxStateCalled bool
}

func (m *clearTxStateTrackingStateDB) ClearTxState() {
	m.clearTxStateCalled = true
}

// TestP2_CLEAR_TX_STATE_ExecuteCallsClearTxState verifies that the executor
// calls ClearTxState() on the StateDB at the start of every Execute() call
// when the StateDB implements the txStateResetter interface.
//
// Without this fix, per-tx state (accessList, transientStorage,
// selfDestructs, refund) from a previous successful tx would leak into
// the next tx within the same block — violating EIP-2929 (warm slots
// should be cold), EIP-1153 (transient storage is per-tx), and
// corrupting gas refund accounting.
func TestP2_CLEAR_TX_STATE_ExecuteCallsClearTxState(t *testing.T) {
	executor := NewTxExecutor()

	// Create a state DB that tracks ClearTxState calls.
	state := &clearTxStateTrackingStateDB{
		mockState: mockState{
			balances: make(map[types.Address]*big.Int),
			nonces:   make(map[types.Address]uint64),
		},
	}

	// Give the sender enough balance for gas.
	sender := types.Address{0x01}
	state.balances[sender] = big.NewInt(1e18)

	blockCtx := &BlockContext{
		BlockHash:   types.Hash{},
		BlockNumber: 1,
		GasLimit:    30000000,
	}

	tx := &encoding.Transaction{
		Type:     encoding.TxTypeTransfer,
		From:     sender,
		To:       &types.Address{0x02},
		Value:    big.NewInt(100),
		GasLimit: 30000000,
		GasPrice: big.NewInt(1),
		Nonce:    0,
	}

	// Execute the tx.
	receipt := executor.Execute(tx, state, blockCtx)

	// Verify ClearTxState was called at the start of Execute.
	if !state.clearTxStateCalled {
		t.Fatal("P2-CLEAR-TX-STATE REGRESSION: executor.Execute did not call ClearTxState() on a StateDB that implements txStateResetter — per-tx state would leak across transactions")
	}

	// The tx should still execute normally (ClearTxState is a no-op on
	// a fresh StateDB, so it shouldn't break anything).
	if receipt.Status != 1 {
		t.Errorf("expected tx to succeed (status=1), got status=%d err=%s", receipt.Status, receipt.Error)
	}
}

// TestP2_CLEAR_TX_STATE_StateDBWithoutResetterStillWorks verifies that the
// executor still works with StateDB implementations that do NOT implement
// txStateResetter (e.g., test mocks, RPC adapters). The type assertion
// should fail silently and execution should proceed normally.
func TestP2_CLEAR_TX_STATE_StateDBWithoutResetterStillWorks(t *testing.T) {
	executor := NewTxExecutor()

	// mockState does NOT implement ClearTxState().
	state := &mockState{
		balances: make(map[types.Address]*big.Int),
		nonces:   make(map[types.Address]uint64),
	}

	sender := types.Address{0x01}
	state.balances[sender] = big.NewInt(1e18)

	blockCtx := &BlockContext{
		BlockHash:   types.Hash{},
		BlockNumber: 1,
		GasLimit:    30000000,
	}

	tx := &encoding.Transaction{
		Type:     encoding.TxTypeTransfer,
		From:     sender,
		To:       &types.Address{0x02},
		Value:    big.NewInt(100),
		GasLimit: 30000000,
		GasPrice: big.NewInt(1),
		Nonce:    0,
	}

	// Execute should NOT panic and should return a receipt.
	receipt := executor.Execute(tx, state, blockCtx)

	if receipt == nil {
		t.Fatal("Execute returned nil receipt when StateDB does not implement txStateResetter")
	}
}

// TestP2_CLEAR_TX_STATE_CalledBeforeGasCheck verifies that ClearTxState is
// called even for transactions that fail the intrinsic gas check. This
// ensures that a rejected tx doesn't leave stale per-tx state for the next
// tx in the block.
func TestP2_CLEAR_TX_STATE_CalledBeforeGasCheck(t *testing.T) {
	executor := NewTxExecutor()

	state := &clearTxStateTrackingStateDB{
		mockState: mockState{
			balances: make(map[types.Address]*big.Int),
			nonces:   make(map[types.Address]uint64),
		},
	}

	sender := types.Address{0x01}
	state.balances[sender] = big.NewInt(1e18)

	blockCtx := &BlockContext{
		BlockHash:   types.Hash{},
		BlockNumber: 1,
		GasLimit:    30000000,
	}

	// Create a tx with gas limit below intrinsic gas — should be rejected.
	tx := &encoding.Transaction{
		Type:     encoding.TxTypeTransfer,
		From:     sender,
		To:       &types.Address{0x02},
		Value:    big.NewInt(100),
		GasLimit: 100, // too low — will fail intrinsic gas check
		GasPrice: big.NewInt(1),
		Nonce:    0,
	}

	receipt := executor.Execute(tx, state, blockCtx)

	// The tx should fail (intrinsic gas).
	if receipt.Status == 1 {
		t.Error("expected tx to fail due to insufficient gas limit")
	}

	// But ClearTxState should still have been called — the cleanup is
	// unconditional on entry, before any gas checks.
	if !state.clearTxStateCalled {
		t.Fatal("P2-CLEAR-TX-STATE REGRESSION: ClearTxState was NOT called for a tx that failed the intrinsic gas check — stale per-tx state would leak to the next tx")
	}
}
