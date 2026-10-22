// Quantaureum Node source, version 1.0.0.
package state

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R9-01 (2026-10-21 ninth-round audit): StateDB.Close() closed s.db on whichever
// instance was asked, taking only that instance's s.mu. Two properties make that
// wrong on this codebase:
//
//   - The handle is shared by construction. Copy() keeps it (state_db.go's Copy
//     sets db: s.db), a build copy swaps it for its own write buffer and Promote
//     hands the base back (s.db = base) — so after one adopted block the instance
//     that was replaced and the instance that replaced it are users of ONE
//     handle. A close is therefore a durable write like any other: if it can land
//     in the middle of a promote replay, the base is left half-applied AND the
//     commit-pending marker becomes un-readable, because the handle
//     RecoverConsistency needs to fail closed is gone. Close was taking none of
//     the locks that prevent that.
//   - Nothing in production could therefore call it. The node lifecycle never
//     released the state handle at all, which is the other half of R9-01 and is
//     pinned in node/node_r9_01_stop_closes_state_test.go.
//
// The fix routes Close through the per-database control block that R8-01 already
// established (durableDisk): wait on the writer gate, then release the base
// handle at most once. Every test below fails if either half is removed.

// r901CloseSpy counts the closes that reach the wrapped database and can be told
// to fail, which is how the exactly-once and retryable properties are observed.
type r901CloseSpy struct {
	db.Database
	mu     sync.Mutex
	closes int
	fail   error
}

func (s *r901CloseSpy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	if s.fail != nil {
		return s.fail
	}
	return s.Database.Close()
}

func (s *r901CloseSpy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

func (s *r901CloseSpy) setFail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

// TestR9_01_CloseWaitsForTheDurableWritersOnItsDatabase pins the serialization
// half: a close must not overtake a durable writer holding the gate, otherwise it
// pulls the handle out from under a commit or a promote replay in progress.
func TestR9_01_CloseWaitsForTheDurableWritersOnItsDatabase(t *testing.T) {
	spy := &r901CloseSpy{Database: db.NewMemDB()}
	live := NewStateDB(spy)
	gate := live.DurableWriterGateForTesting()
	if gate == nil {
		t.Fatal("no writer gate to hold")
	}

	alice := types.Address{0xa1}
	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	r801AssertBlocksBehindGate(t, "Close", gate, live.Close)
}

// TestR9_01_CloseReleasesOneSharedHandleExactlyOnce pins the other half. Three
// instances of one graph ask for the same shutdown: the released handle must be
// closed once, and the later asks must not report a double close as a new failure.
func TestR9_01_CloseReleasesOneSharedHandleExactlyOnce(t *testing.T) {
	spy := &r901CloseSpy{Database: db.NewMemDB()}
	live := NewStateDB(spy)

	alice := types.Address{0xa1}
	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	// Close from a copy first — that is the shape production reaches after a
	// promoted block, where the instance the node holds is not the one that was
	// constructed over the handle.
	build := live.Copy()
	if err := build.Close(); err != nil {
		t.Fatalf("Close from a copy: %v", err)
	}
	if err := live.Close(); err != nil {
		t.Fatalf("Close from the original after the copy already closed the handle: %v", err)
	}
	if err := live.Close(); err != nil {
		t.Fatalf("second Close from the original: %v", err)
	}

	if got := spy.count(); got != 1 {
		t.Errorf("the shared handle was closed %d time(s), want exactly 1 — one handle is shared by the whole instance graph", got)
	}
}

// TestR9_01_BuildCopyCloseReleasesTheBaseDiskNotItsBuffer pins the target of the
// close. A provisional build copy writes through its own capture buffer, and
// Capture.Close() is a no-op that reports success — so a Close that kept using
// s.db would "succeed" while the real disk stayed open, holding its file lock.
func TestR9_01_BuildCopyCloseReleasesTheBaseDiskNotItsBuffer(t *testing.T) {
	spy := &r901CloseSpy{Database: db.NewMemDB()}
	live := NewStateDB(spy)

	alice := types.Address{0xa1}
	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil — the copy is still wired to live disk state")
	}
	build.SetBalance(alice, big.NewInt(2000))
	if _, err := build.CommitWithBlock(2); err != nil {
		t.Fatalf("build copy CommitWithBlock(2): %v", err)
	}

	if err := build.Close(); err != nil {
		t.Fatalf("Close on a provisional build copy: %v", err)
	}
	if got := spy.count(); got != 1 {
		t.Errorf("closing a build copy released the base database %d time(s), want 1 — a build copy's s.db is its write buffer, and closing the buffer leaves the real disk (and its file lock) open", got)
	}
}

// TestR9_01_PromotedInstanceAndTheInstanceItReplacedShareOneClose closes the loop
// with R7-01/R8-01: after Promote the discarded live instance and the adopted copy
// point at the same handle, so both teardowns must resolve into one release.
func TestR9_01_PromotedInstanceAndTheInstanceItReplacedShareOneClose(t *testing.T) {
	spy := &r901CloseSpy{Database: db.NewMemDB()}
	live := NewStateDB(spy)

	alice := types.Address{0xa1}
	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil — the copy is still wired to live disk state")
	}
	bob := types.Address{0xb0}
	build.SetBalance(bob, big.NewInt(4000))
	if _, err := build.CommitWithBlock(2); err != nil {
		t.Fatalf("build copy CommitWithBlock(2): %v", err)
	}
	if err := build.Promote(); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	// The node would now hold `build` and drop `live`, but both were handed to
	// somebody at some point; whichever is shut down, the handle goes once.
	if err := live.Close(); err != nil {
		t.Fatalf("Close on the replaced instance: %v", err)
	}
	if err := build.Close(); err != nil {
		t.Fatalf("Close on the adopted instance: %v", err)
	}
	if got := spy.count(); got != 1 {
		t.Errorf("after Promote the two instances closed the shared handle %d time(s), want exactly 1", got)
	}
}

// TestR9_01_FailedCloseCanBeRetried pins that a close that did not release the
// handle is not recorded as released. Swallowing it would put the leak back: the
// file lock would stay held while every later Close reported success.
func TestR9_01_FailedCloseCanBeRetried(t *testing.T) {
	spy := &r901CloseSpy{Database: db.NewMemDB(), fail: errors.New("simulated close failure")}
	live := NewStateDB(spy)

	if err := live.Close(); err == nil {
		t.Fatal("Close reported success while the handle reported a failure")
	}

	spy.setFail(nil)
	if err := live.Close(); err != nil {
		t.Fatalf("retry after a failed close: %v", err)
	}
	if got := spy.count(); got != 2 {
		t.Errorf("the retry closed the handle %d time(s) in total, want 2 (the failed attempt plus the successful retry) — a failed close must remain retryable", got)
	}
}
