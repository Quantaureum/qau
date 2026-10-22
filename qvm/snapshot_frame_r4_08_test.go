package qvm_test

// R4-08 (2026-10-21 fourth-round audit) regression tests.
//
// A call frame journals a state snapshot so a failed sub-call can be rolled
// back. Historically the entry was only consumed when the frame reverted, so
// every SUCCESSFUL frame leaked one entry onto the StateDB snapshot stack for
// the lifetime of the transaction. Once state.maxSnapshotDepth (1024) was
// reached, Snapshot() started returning the -1 depth sentinel, which meant
// later frames either ran with no rollback path at all or rewound the whole
// in-flight frame chain. Both are deterministic, so the node kept agreeing
// with itself while silently losing writes.
//
// The fix bounds the journal by the LIVE call depth (frames release their
// entry when they complete) and refuses a frame that cannot be journaled.

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/qvm/qvmasync"
	"github.com/quantaureum/qau/types"
)

func r408Address(b byte) types.Address {
	var a types.Address
	a[19] = b
	return a
}

func r408QVMAddress(a types.Address) qvm.Address {
	var q qvm.Address
	copy(q[:], a[:])
	return q
}

func r408BlockCtx() *qvm.BlockContext {
	return &qvm.BlockContext{
		BlockNumber: 1,
		Timestamp:   1_700_000_000,
		Coinbase:    qvm.Address{},
		GasLimit:    30_000_000,
		GasPrice:    big.NewInt(1),
		ChainID:     1668,
		BlockHashes: make(map[uint64]qvm.Hash),
	}
}

// TestR408_SuccessfulValueTransferFramesDoNotLeakJournal drives far more
// completed frames than the state journal used to hold and asserts the stack
// stays empty. Before the fix the depth grew by one per call and crossed the
// cap around the 1024th frame.
func TestR408_SuccessfulValueTransferFramesDoNotLeakJournal(t *testing.T) {
	sdb := state.NewStateDB()
	adapter := &qvmasync.StateDBAdapter{StateDB: sdb}

	from := r408Address(0xa1)
	to := r408Address(0xb2)
	sdb.SetBalance(from, big.NewInt(1_000_000_000))

	exec := qvm.NewExecutor()
	ctx := r408BlockCtx()

	for i := 0; i < 1100; i++ {
		res := exec.CallWithRollback(adapter, r408QVMAddress(from), r408QVMAddress(to),
			nil, 100_000, big.NewInt(1), ctx, true, 0)
		if res.Err != nil {
			t.Fatalf("call %d failed: %v", i, res.Err)
		}
		if depth := sdb.SnapshotDepth(); depth != 0 {
			t.Fatalf("journal leaked after %d successful frames: snapshot depth = %d, want 0", i+1, depth)
		}
	}

	if got := sdb.GetBalance(to); got.Cmp(big.NewInt(1100)) != 0 {
		t.Fatalf("value transfers lost: recipient balance = %s, want 1100", got)
	}
}

// TestR408_ContractFrameReleasesJournal runs a contract that writes storage
// and asserts the executing frames leave the stack balanced.
func TestR408_ContractFrameReleasesJournal(t *testing.T) {
	sdb := state.NewStateDB()
	adapter := &qvmasync.StateDBAdapter{StateDB: sdb}

	callee := r408Address(0xc3)
	caller := r408Address(0xa1)
	// PUSH1 0x2a PUSH1 0x00 SSTORE  -> store 42 at slot 0, then run off the end.
	code := []byte{byte(qvm.PUSH1), 0x2a, byte(qvm.PUSH1), 0x00, byte(qvm.SSTORE)}
	sdb.SetCode(callee, code)
	sdb.SetBalance(caller, big.NewInt(1_000_000))

	exec := qvm.NewExecutor()
	ctx := r408BlockCtx()

	for i := 0; i < 1100; i++ {
		res := exec.CallWithRollback(adapter, r408QVMAddress(caller), r408QVMAddress(callee),
			nil, 200_000, nil, ctx, true, 0)
		if res.Err != nil {
			t.Fatalf("call %d failed: %v (gas=%d)", i, res.Err, res.GasUsed)
		}
		if depth := sdb.SnapshotDepth(); depth != 0 {
			t.Fatalf("journal leaked after %d contract frames: snapshot depth = %d, want 0", i+1, depth)
		}
	}

	if got := sdb.GetState(callee, types.Hash{}); got != (types.Hash{31: 0x2a}) {
		t.Fatalf("storage write lost: slot 0 = %x", got)
	}
}

// TestR408_JournalExhaustionFailsCallClosed pins the guard: when the journal
// genuinely cannot grow (an unrelated frame chain filled it), a new frame must
// fail instead of executing with no rollback path.
func TestR408_JournalExhaustionFailsCallClosed(t *testing.T) {
	sdb := state.NewStateDB()
	adapter := &qvmasync.StateDBAdapter{StateDB: sdb}

	callee := r408Address(0xc3)
	caller := r408Address(0xa1)
	code := []byte{byte(qvm.PUSH1), 0x2a, byte(qvm.PUSH1), 0x00, byte(qvm.SSTORE)}
	sdb.SetCode(callee, code)

	// Stand the frame chain up: an outer write that must survive.
	sdb.SetBalance(caller, big.NewInt(500))
	outer := sdb.Snapshot()
	if outer < 0 {
		t.Fatalf("unexpected journal exhaustion while filling: %d", outer)
	}

	// Fill the journal to its capacity with live frames.
	for {
		if sdb.Snapshot() < 0 {
			break
		}
	}
	if sdb.SnapshotDepth() == 0 {
		t.Fatal("expected the journal to be full")
	}

	exec := qvm.NewExecutor()
	res := exec.CallWithRollback(adapter, r408QVMAddress(caller), r408QVMAddress(callee),
		nil, 200_000, nil, r408BlockCtx(), true, 0)
	if res.Err == nil {
		t.Fatal("expected the call to fail when no journal entry could be taken")
	}
	if got := sdb.GetState(callee, types.Hash{}); got != (types.Hash{}) {
		t.Fatalf("an unjournaled frame must not have written storage, got %x", got)
	}
	if bal := sdb.GetBalance(caller); bal.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("the outer frame's write must survive, got %s", bal)
	}
}
