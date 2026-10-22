// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// R6-03 (2026-10-21 sixth-round audit): three lifecycle entry points rewrote or
// flushed live state without owning the StateDB execution frame (R4-07 contract
// C1): the operator RPC debug_rollbackChainToHeight (forkRecoveryBackend.
// RollbackToFork), the syncer's OnForkRollback callback, and the "flush-data"
// shutdown hook. Each now goes through StateDB.WithExecutionFrame; these tests
// pin the CALL SITES, because the state-level guarantee is worthless if a caller
// keeps using the unwrapped method.
//
// The probe pattern is the R5-03 one: hold the frame, start the lifecycle call,
// require that it cannot have completed, release, require that it does complete,
// then require the frame to be free again afterwards.

// frameWait is how long a lifecycle call is given to (wrongly) finish while
// another frame is held. A blocked execMu acquire cannot return inside it.
const frameWait = 150 * time.Millisecond

func waitForFrameFree(t *testing.T, sdb *state.StateDB, what string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if release, ok := sdb.TryBeginExecution(); ok {
			release()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s left the execution frame held", what)
}

func TestR6_03_ForkRollbackWaitsForExecutionFrame(t *testing.T) {
	n, _ := newReplayTestNode(t, 5, 1)
	backend := newForkRecoveryBackend(n)

	// Simulate an import in flight on the same StateDB instance.
	held := n.stateDB.BeginExecution()

	type result struct {
		deleted int
		err     error
	}
	done := make(chan result, 1)
	go func() {
		deleted, err := backend.RollbackToFork(3)
		done <- result{deleted: deleted, err: err}
	}()

	select {
	case res := <-done:
		held()
		t.Fatalf("RollbackToFork completed while another frame was held (deleted=%d err=%v) — it rewrote committed state underneath a live execution", res.deleted, res.err)
	case <-time.After(frameWait):
	}

	held()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("RollbackToFork after the frame was released: %v", res.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("RollbackToFork never completed after the held frame was released")
	}

	waitForFrameFree(t, n.stateDB, "RollbackToFork")
}

func TestR6_03_ForkRollbackWithoutHolderCompletes(t *testing.T) {
	n, _ := newReplayTestNode(t, 5, 1)
	backend := newForkRecoveryBackend(n)

	deleted, err := backend.RollbackToFork(3)
	if err != nil {
		t.Fatalf("RollbackToFork on an idle state: %v", err)
	}
	if deleted == 0 {
		t.Error("RollbackToFork deleted no blocks — the fixture is not exercising the rollback path")
	}
	waitForFrameFree(t, n.stateDB, "RollbackToFork")
	if depth := n.stateDB.SnapshotDepth(); depth != 0 {
		t.Errorf("snapshot journal depth after rollback = %d, want 0", depth)
	}
}

func TestR6_03_ShutdownFlushWaitsForExecutionFrame(t *testing.T) {
	n, _ := newReplayTestNode(t, 3, 1)

	// Pending, uncommitted write so the flush has something to persist.
	n.stateDB.SetBalance(types.Address{0x77}, big.NewInt(42))

	held := n.stateDB.BeginExecution()

	done := make(chan struct{}, 1)
	go func() {
		_ = n.flushStateForShutdown(context.Background())
		done <- struct{}{}
	}()

	select {
	case <-done:
		held()
		t.Fatal("the shutdown flush committed while another frame was held — it flushed a journal that belongs to a live execution")
	case <-time.After(frameWait):
	}

	held()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the shutdown flush never completed after the held frame was released")
	}

	waitForFrameFree(t, n.stateDB, "flushStateForShutdown")
	if bal := n.stateDB.GetBalance(types.Address{0x77}); bal.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("balance after flush = %s, want 42 — the flush did not persist the pending write", bal)
	}
	if depth := n.stateDB.SnapshotDepth(); depth != 0 {
		t.Errorf("snapshot journal depth after flush = %d, want 0", depth)
	}
}

func TestR6_03_ShutdownFlushWithoutStateDBIsNoop(t *testing.T) {
	n := &Node{config: &Config{MaxGasLimit: 30_000_000}}
	if err := n.flushStateForShutdown(context.Background()); err != nil {
		t.Fatalf("flush with no state DB: %v", err)
	}
}
