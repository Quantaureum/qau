// Quantaureum Node source, version 1.0.0.
package state

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R6-03 (2026-10-21 sixth-round audit): the state lifecycle entry points that
// rewrite committed accounts (RollbackToHeight) or flush the shared journal and
// snapshot stack (a Commit that is not part of a block transition, e.g. the
// shutdown flush) ran without the R4-07 contract C1 execution frame. A rollback
// could therefore restore before-images underneath a block transition that was
// still journaling the post-fork writes, and a shutdown Commit could persist a
// half-applied block while clearing the snapshot stack out from under the live
// frame.
//
// The fix is StateDB.WithExecutionFrame, which every such call site now goes
// through, so the invariant is pinned here once rather than per caller.

func newFrameTestStateDB(t *testing.T) *StateDB {
	t.Helper()
	sdb := NewStateDB(db.NewMemDB())
	if sdb == nil {
		t.Fatal("NewStateDB returned nil")
	}
	return sdb
}

func TestR6_03_WithExecutionFrameExcludesOtherFrames(t *testing.T) {
	sdb := newFrameTestStateDB(t)

	insideReleased := false
	err := sdb.WithExecutionFrame(func() error {
		// While the frame is held, a speculative caller (eth_call path) must be
		// told to back off rather than sharing the journal.
		if release, ok := sdb.TryBeginExecution(); ok {
			release()
			t.Error("TryBeginExecution succeeded while WithExecutionFrame held the frame")
		}
		insideReleased = true
		return nil
	})
	if err != nil {
		t.Fatalf("WithExecutionFrame: %v", err)
	}
	if !insideReleased {
		t.Fatal("fn never ran")
	}

	// Released on the normal return path.
	release, ok := sdb.TryBeginExecution()
	if !ok {
		t.Fatal("WithExecutionFrame leaked the execution frame on return")
	}
	release()
}

func TestR6_03_WithExecutionFrameReleasesOnErrorAndPanic(t *testing.T) {
	sdb := newFrameTestStateDB(t)

	wantErr := errors.New("rollback refused")
	if err := sdb.WithExecutionFrame(func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("error not propagated: %v", err)
	}
	release, ok := sdb.TryBeginExecution()
	if !ok {
		t.Fatal("frame still held after fn returned an error")
	}
	release()

	// The deferred release must also run while the stack is unwinding, otherwise
	// one panicking lifecycle call wedges the state for the life of the process.
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected the panic to propagate out of WithExecutionFrame")
			}
		}()
		_ = sdb.WithExecutionFrame(func() error { panic("boom") })
	}()

	release, ok = sdb.TryBeginExecution()
	if !ok {
		t.Fatal("frame still held after fn panicked")
	}
	release()
}

// TestR6_03_RollbackUnderFrameSerialisesWithCommit is the reproduction of the
// R6-03 hazard at the state level: a rollback wrapped in the frame cannot
// interleave with a Commit that flushes the same dirty account set.
func TestR6_03_RollbackUnderFrameSerialisesWithCommit(t *testing.T) {
	sdb := newFrameTestStateDB(t)

	addr := types.Address{0x60}
	sdb.SetBalance(addr, big.NewInt(100))
	if _, err := sdb.Commit(1); err != nil {
		t.Fatalf("Commit(1): %v", err)
	}

	// A block transition in flight: it holds the frame and has journaled work.
	transition := sdb.BeginExecution()
	sdb.SetBalance(addr, big.NewInt(7))

	rollbackDone := make(chan error, 1)
	go func() {
		rollbackDone <- sdb.WithExecutionFrame(func() error {
			return sdb.RollbackToHeight(1)
		})
	}()

	// The rollback must wait for the transition instead of rewriting committed
	// accounts underneath it.
	select {
	case err := <-rollbackDone:
		transition()
		t.Fatalf("rollback completed while another frame was held: err=%v", err)
	case <-time.After(100 * time.Millisecond):
	}

	transition()

	select {
	case err := <-rollbackDone:
		if err != nil {
			t.Fatalf("rollback after the frame was released: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("rollback did not complete after the held frame was released")
	}

	if release, ok := sdb.TryBeginExecution(); !ok {
		t.Fatal("execution frame still held after the rollback returned")
	} else {
		release()
	}
}
