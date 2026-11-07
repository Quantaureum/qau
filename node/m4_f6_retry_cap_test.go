// M4-F6 regression: the same height must not be retried forever. Once the
// bounded budget is exhausted the syncer stops re-executing it and reports an
// explicit degradation instead of accumulating an unbounded mismatch counter
// (the M4 shape: thousands of mismatches at one height).
package node

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestM4F6_SameHeightRetryBudget asserts the 8th failure exhausts the budget
// (and fires the hook exactly once), while a different height starts fresh.
func TestM4F6_SameHeightRetryBudget(t *testing.T) {
	s, _, _ := r38p1_08_newSyncerWithStore(t)

	height := uint64(42)
	var hookHeight uint64
	var hookAttempts int
	s.SetOnStateRootRetryExhausted(func(h uint64, attempts int) {
		hookHeight = h
		hookAttempts = attempts
	})

	for i := 1; i <= maxStateRootRetriesPerHeight; i++ {
		got := s.noteStateRootRetry(height)
		wantExhausted := i == maxStateRootRetriesPerHeight
		if got != wantExhausted {
			t.Fatalf("attempt %d: noteStateRootRetry = %v, want %v", i, got, wantExhausted)
		}
	}
	if !s.IsStateRootRetryExhausted(height) {
		t.Fatal("M4-F6: budget must be exhausted after the last allowed attempt")
	}
	if hookHeight != height || hookAttempts != maxStateRootRetriesPerHeight {
		t.Fatalf("M4-F6: hook got (height=%d attempts=%d), want (%d %d)",
			hookHeight, hookAttempts, height, maxStateRootRetriesPerHeight)
	}

	// A different height resets the counter; a later success clears it.
	if s.noteStateRootRetry(height + 1) {
		t.Fatal("M4-F6: a new height must start with a fresh budget")
	}
	if s.IsStateRootRetryExhausted(height) {
		t.Fatal("M4-F6: exhaustion must be scoped to the exhausted height")
	}
	s.mu.RLock()
	count := s.stateRootRetryCount
	at := s.stateRootRetryHeight
	s.mu.RUnlock()
	if at != height+1 || count != 1 {
		t.Fatalf("M4-F6: counter reset broken (height=%d count=%d)", at, count)
	}

	s.resetStateRootRetry()
	if s.IsStateRootRetryExhausted(height + 1) {
		t.Fatal("M4-F6: a successful apply must clear the retry budget")
	}
}

// TestM4F6_ConfigurableRetryLimit asserts the per-height budget can be
// overridden by config while 0 keeps the documented default of 8, and that
// the override takes effect immediately.
func TestM4F6_ConfigurableRetryLimit(t *testing.T) {
	s, _, _ := r38p1_08_newSyncerWithStore(t)

	if got := s.StateRootRetryLimit(); got != maxStateRootRetriesPerHeight {
		t.Fatalf("default limit = %d, want %d", got, maxStateRootRetriesPerHeight)
	}

	s.SetStateRootRetryLimit(3)
	if got := s.StateRootRetryLimit(); got != 3 {
		t.Fatalf("configured limit = %d, want 3", got)
	}

	height := uint64(77)
	for i := 1; i <= 2; i++ {
		if s.noteStateRootRetry(height) {
			t.Fatalf("attempt %d exhausted the budget early (limit 3)", i)
		}
	}
	if !s.noteStateRootRetry(height) {
		t.Fatal("3rd attempt must exhaust a configured budget of 3")
	}
	if !s.IsStateRootRetryExhausted(height) {
		t.Fatal("configured budget exhaustion not reported")
	}

	s.SetStateRootRetryLimit(0)
	if got := s.StateRootRetryLimit(); got != maxStateRootRetriesPerHeight {
		t.Fatalf("limit after reset = %d, want default %d", got, maxStateRootRetriesPerHeight)
	}
}

// TestM4F6_ExhaustedHeightRefusedWithoutTouchingState asserts ProcessBlock
// short-circuits an exhausted height before storing the block or executing
// anything.
func TestM4F6_ExhaustedHeightRefusedWithoutTouchingState(t *testing.T) {
	s, bs, _ := r38p1_08_newSyncerWithStore(t)
	blk, blkHash := m4f1_buildMismatchBlock(t, s, bs) // height 1

	addr := types.Address{0x99}
	s.stateDB.SetBalance(addr, big.NewInt(700))
	if _, err := s.stateDB.CommitWithBlock(0); err != nil {
		t.Fatalf("baseline commit failed: %v", err)
	}

	for i := 1; i <= maxStateRootRetriesPerHeight; i++ {
		s.noteStateRootRetry(blk.Header.Height)
	}
	if !s.IsStateRootRetryExhausted(blk.Header.Height) {
		t.Fatal("fixture broken: budget was not exhausted")
	}

	balanceBefore := new(big.Int).Set(s.stateDB.GetBalance(addr))
	heightBefore := s.stateDB.LastCommittedHeight()

	err := s.ProcessBlock(blk)
	if err == nil {
		t.Fatal("M4-F6: exhausted height must be refused, got nil")
	}
	if !errors.Is(err, ErrStateRootRetryExhausted) {
		t.Fatalf("M4-F6: expected ErrStateRootRetryExhausted, got %v", err)
	}

	if got := s.stateDB.GetBalance(addr); got.Cmp(balanceBefore) != 0 {
		t.Fatalf("M4-F6: refused block touched state (balance %s → %s)", balanceBefore, got)
	}
	if got := s.stateDB.LastCommittedHeight(); got != heightBefore {
		t.Fatalf("M4-F6: refused block advanced state (%d → %d)", heightBefore, got)
	}
	if exists, _ := bs.HasBlock(blkHash); exists {
		t.Fatal("M4-F6: refused block was stored anyway")
	}
	if got := s.currentHeight; got != 0 {
		t.Fatalf("M4-F6: refused block advanced currentHeight to %d", got)
	}
}
