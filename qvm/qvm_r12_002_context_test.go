// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qvm/precompiled"
	"github.com/quantaureum/qau/types"
)

// TestQVM_R12002_qvmStateDBAdapter_GetSetState verifies that the adapter
// correctly converts between qvm.Address/Hash and types.Address/Hash for
// state read/write operations.
//
// QVM-R12-002 (2026-07-20): The multisig precompile requires a MultisigStateDB
// to read/write its storage. The qvmStateDBAdapter wraps qvm.StateDB and
// adapts it to the precompiled.MultisigStateDB interface. Without this
// adapter, on-chain CALLs to the multisig address (0x66) would fail with
// "stateDB not set" because the executor never injected stateDB.
func TestQVM_R12002_qvmStateDBAdapter_GetSetState(t *testing.T) {
	sdb := newMockStateDB()
	adapter := &qvmStateDBAdapter{db: sdb}

	addr := types.Address{0x11, 0x22}
	key := types.Hash{0xAA}
	val := types.Hash{0xBB}

	adapter.SetState(addr, key, val)
	got := adapter.GetState(addr, key)
	if got != val {
		t.Errorf("GetState mismatch: got %x, want %x", got, val)
	}

	// Verify the underlying qvm.StateDB was actually written to (not some
	// shadow copy).
	var qAddr Address
	copy(qAddr[:], addr[:])
	var qKey Hash
	copy(qKey[:], key[:])
	var qVal Hash
	copy(qVal[:], val[:])
	if sdb.GetState(qAddr, qKey) != qVal {
		t.Error("underlying qvm.StateDB was not written by adapter")
	}
}

// TestQVM_R12002_qvmStateDBAdapter_BalanceOperations verifies SubBalance and
// AddBalance correctly modify the underlying stateDB and handle insufficient
// funds.
func TestQVM_R12002_qvmStateDBAdapter_BalanceOperations(t *testing.T) {
	sdb := newMockStateDB()
	adapter := &qvmStateDBAdapter{db: sdb}

	addr := types.Address{0x42}
	sdb.SetBalance(Address{0x42}, big.NewInt(1000))

	// SubBalance within bounds.
	if err := adapter.SubBalance(addr, big.NewInt(300)); err != nil {
		t.Fatalf("SubBalance should succeed: %v", err)
	}
	if got := adapter.GetBalance(addr); got.Cmp(big.NewInt(700)) != 0 {
		t.Errorf("after SubBalance(300), balance = %s, want 700", got)
	}

	// SubBalance beyond balance should fail.
	if err := adapter.SubBalance(addr, big.NewInt(10000)); err == nil {
		t.Error("SubBalance with insufficient funds should return error")
	}

	// AddBalance.
	if err := adapter.AddBalance(addr, big.NewInt(500)); err != nil {
		t.Fatalf("AddBalance should succeed: %v", err)
	}
	if got := adapter.GetBalance(addr); got.Cmp(big.NewInt(1200)) != 0 {
		t.Errorf("after AddBalance(500), balance = %s, want 1200", got)
	}
}

// TestQVM_R12002_qvmStateDBAdapter_ZeroAmountIsNoOp verifies that SubBalance
// and AddBalance with nil/zero/non-positive amounts are no-ops (defensive).
func TestQVM_R12002_qvmStateDBAdapter_ZeroAmountIsNoOp(t *testing.T) {
	sdb := newMockStateDB()
	adapter := &qvmStateDBAdapter{db: sdb}

	addr := types.Address{0x99}
	sdb.SetBalance(Address{0x99}, big.NewInt(500))

	// nil amount.
	if err := adapter.SubBalance(addr, nil); err != nil {
		t.Errorf("SubBalance(nil) should be no-op, got error: %v", err)
	}
	if err := adapter.AddBalance(addr, nil); err != nil {
		t.Errorf("AddBalance(nil) should be no-op, got error: %v", err)
	}

	// Zero amount.
	zero := big.NewInt(0)
	if err := adapter.SubBalance(addr, zero); err != nil {
		t.Errorf("SubBalance(0) should be no-op, got error: %v", err)
	}
	if err := adapter.AddBalance(addr, zero); err != nil {
		t.Errorf("AddBalance(0) should be no-op, got error: %v", err)
	}

	// Negative amount.
	neg := big.NewInt(-100)
	if err := adapter.SubBalance(addr, neg); err != nil {
		t.Errorf("SubBalance(negative) should be no-op, got error: %v", err)
	}
	if err := adapter.AddBalance(addr, neg); err != nil {
		t.Errorf("AddBalance(negative) should be no-op, got error: %v", err)
	}

	// Balance should be unchanged.
	if got := adapter.GetBalance(addr); got.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("balance changed after zero/negative ops: got %s, want 500", got)
	}
}

// TestQVM_R12002_InjectPrecompileContext_MultisigGetsContext verifies that
// injectPrecompileContext correctly identifies the multisig precompile as a
// ContextAwarePrecompiledContract and injects stateDB/blockTime/chainID.
//
// This is the core of QVM-R12-002: before this fix, the QVM executor never
// called SetStateDB/SetBlockTime/SetChainID on the multisig precompile, so
// any on-chain CALL to 0x66 failed with "stateDB not set".
func TestQVM_R12002_InjectPrecompileContext_MultisigGetsContext(t *testing.T) {
	registry := precompiled.NewRegistry()
	multisigAddr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66}
	pc := registry.Get(multisigAddr)
	if pc == nil {
		t.Fatal("multisig precompile not registered at 0x66")
	}

	// Verify it implements ContextAwarePrecompiledContract.
	if _, ok := pc.(precompiled.ContextAwarePrecompiledContract); !ok {
		t.Fatal("multisig precompile should implement ContextAwarePrecompiledContract")
	}

	// Before injection, calling Run should fail with "stateDB not set".
	_, err := pc.Run([]byte{0x05}) // MultisigFuncGetWalletConfig
	if err == nil {
		t.Fatal("Run before context injection should fail with 'stateDB not set'")
	}

	// Inject context.
	sdb := newMockStateDB()
	injectPrecompileContext(pc, sdb, 1700000000, 1668)

	// After injection, Run should no longer fail with "stateDB not set".
	// It may still fail for other reasons (empty input, wallet not found,
	// etc.), but NOT with the stateDB error.
	_, err = pc.Run([]byte{0x05})
	if err != nil && err.Error() == "multisig: stateDB not set" {
		t.Errorf("after context injection, Run should not fail with 'stateDB not set', but got: %v", err)
	}
}

// TestQVM_R12002_InjectPrecompileContext_PurePrecompileUnaffected verifies
// that pure precompiles (sha256, ecrecover, identity) are not affected by
// context injection — they don't implement ContextAwarePrecompiledContract.
func TestQVM_R12002_InjectPrecompileContext_PurePrecompileUnaffected(t *testing.T) {
	registry := precompiled.NewRegistry()

	// SHA256 is at address 0x02.
	sha256Addr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	pc := registry.Get(sha256Addr)
	if pc == nil {
		t.Fatal("sha256 precompile not registered at 0x02")
	}

	// Verify it does NOT implement ContextAwarePrecompiledContract.
	if _, ok := pc.(precompiled.ContextAwarePrecompiledContract); ok {
		t.Error("sha256 precompile should NOT implement ContextAwarePrecompiledContract")
	}

	// injectPrecompileContext should be a no-op for sha256.
	sdb := newMockStateDB()
	// This should not panic or modify the precompile.
	injectPrecompileContext(pc, sdb, 1700000000, 1668)

	// sha256 should still work correctly.
	input := []byte("hello")
	output, err := pc.Run(input)
	if err != nil {
		t.Fatalf("sha256 Run failed: %v", err)
	}
	if len(output) != 32 {
		t.Errorf("sha256 output should be 32 bytes, got %d", len(output))
	}
}

// TestQVM_R12002_qvmStateDBAdapter_ImplementsInterface is a compile-time
// assertion that qvmStateDBAdapter implements precompiled.MultisigStateDB.
// This ensures the adapter won't silently drift from the interface.
func TestQVM_R12002_qvmStateDBAdapter_ImplementsInterface(t *testing.T) {
	var _ precompiled.MultisigStateDB = (*qvmStateDBAdapter)(nil)
	// Also verify via runtime assertion.
	var adapter interface{} = &qvmStateDBAdapter{}
	if _, ok := adapter.(precompiled.MultisigStateDB); !ok {
		t.Error("qvmStateDBAdapter does not implement precompiled.MultisigStateDB")
	}
}
