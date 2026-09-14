// Quantaureum Node source, version 1.0.0.
package state

// R39-P2-02 (2026-08-02) regression tests for RollbackToHeight's
// silent-skip on pruned history.
//
// Audit (R39-P2-02): RollbackToHeight(forkHeight) silently returned nil
// when no beforeImages existed at >= forkHeight — even if forkHeight was
// BELOW the smallest retained beforeImage height (i.e. history was
// pruned and the rollback target unreachable). Operators would think
// the rollback succeeded, but the chain actually retained its current
// post-fork state — silently divergent from what the operator intended.
//
// The fix distinguishes:
//   - "nothing to do" (legitimate, return nil): forkHeight >=
//     minRetained beforeImage height — some retained history exists
//     at or above the target.
//   - "already pruned" (silent corruption, MUST error): forkHeight <
//     minRetained beforeImage height — history below was pruned and
//     the rollback target is unreachable.
//
// Tests in this file pin three guarantees:
//   1. RollbackToHeight with forkHeight below minRetained MUST return
//      an error containing the "R39-P2-02" marker.
//   2. RollbackToHeight with forkHeight above minRetained (no entries
//      at >= forkHeight) returns nil (legitimate nothing-to-do).
//   3. RollbackToHeight on a fresh StateDB (no beforeImages at all)
//      returns nil regardless of forkHeight (fresh-node rollback is
//      always a no-op — there's no history to be "pruned").

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// r39P2_02NewStateDB builds a fresh StateDB backed by a MemDB. We don't
// use the production BoltDB here (filesystem-coupled timing makes the
// test flaky on CI under load); MemDB exposes the same Database / Batch
// contract the production code reads through, so production code paths
// cannot detect the swap.
func r39P2_02NewStateDB(t *testing.T) *StateDB {
	t.Helper()
	sdb := NewStateDB(db.NewMemDB())
	return sdb
}

// r39P2_02SeedBeforeImage writes a synthetic beforeImage record at the
// given height with arbitrary account/state content. We bypass the
// stateDB.Set / block commit plumbing and write directly into the
// beforeImages map (under s.mu) so we can plant entries at exact
// heights without needing a block processor.
func r39P2_02SeedBeforeImage(sdb *StateDB, height uint64, addr types.Address) {
	sdb.mu.Lock()
	defer sdb.mu.Unlock()
	if sdb.beforeImages == nil {
		sdb.beforeImages = make(map[uint64]map[types.Address]*accountBeforeImage)
	}
	if _, ok := sdb.beforeImages[height]; !ok {
		sdb.beforeImages[height] = make(map[types.Address]*accountBeforeImage)
	}
	// nil account → StateDB treats this as "account did not exist before this block".
	sdb.beforeImages[height][addr] = &accountBeforeImage{
		account: nil,
		storage: nil,
	}
}

// ── Test 1: forkHeight < minRetained → MUST error with R39-P2-02 marker. ──

// TestR39_P2_02_RollbackToHeight_PrunedTarget_ReturnsError pins the FIX:
// when forkHeight is BELOW the smallest retained beforeImage height,
// RollbackToHeight MUST return an error containing the R39-P2-02 marker
// (operators grep logs for this string to identify the failure mode).
// Without this contract, the audit's silent-divergence finding returns.
//
// Fixture: seed beforeImages at heights 100, 200, 300 (simulating a node
// that pruned heights < 100 — e.g. retention window=2 epochs of 50
// blocks each). Call RollbackToHeight(50) — 50 < 100 (minRetained).
func TestR39_P2_02_RollbackToHeight_PrunedTarget_ReturnsError(t *testing.T) {
	sdb := r39P2_02NewStateDB(t)
	addr := types.BytesToAddress([]byte{0x01})
	r39P2_02SeedBeforeImage(sdb, 100, addr)
	r39P2_02SeedBeforeImage(sdb, 200, addr)
	r39P2_02SeedBeforeImage(sdb, 300, addr)

	// Sanity: minRetained should be 100.
	sdb.mu.RLock()
	minRetained := uint64(0)
	first := true
	for h := range sdb.beforeImages {
		if first || h < minRetained {
			minRetained = h
			first = false
		}
	}
	sdb.mu.RUnlock()
	if minRetained != 100 {
		t.Fatalf("R39-P2-02: fixture precondition — expected minRetained=100, got %d", minRetained)
	}

	// forkHeight=50 is below minRetained-1=99 — the target is pruned.
	// (forkHeight = minRetained-1 = 99 would be reachable — rolling
	// back height 100 lands at post-99 state, which IS forkHeight=99.
	// The audit's silent-divergence case is forkHeight strictly below
	// minRetainedActive - 1.)
	const forkHeight uint64 = 50
	err := sdb.RollbackToHeight(forkHeight)
	if err == nil {
		t.Fatalf("R39-P2-02: RollbackToHeight(%d) returned nil when forkHeight < minRetained(%d) — the audit's silent-divergence finding is NOT fixed; operator would continue under the false impression that the rollback succeeded, while the chain retains its current (post-fork) state", forkHeight, minRetained)
	}
	if !strings.Contains(err.Error(), "R39-P2-02") {
		t.Fatalf("R39-P2-02: RollbackToHeight(%d) returned an error without the R39-P2-02 marker string — operators grep logs for this string to identify the failure mode; got: %v", forkHeight, err)
	}
	if !strings.Contains(err.Error(), "pruned") {
		t.Fatalf("R39-P2-02: RollbackToHeight(%d) returned an error without the word 'pruned' — the error message must clearly identify the failure as history pruning, not generic I/O; got: %v", forkHeight, err)
	}
}

// ── Test 2: forkHeight > minRetained (no entries >= forkHeight) → nil. ──

// TestR39_P2_02_RollbackToHeight_NothingToDo_ReturnsNil pins the
// legitimate nothing-to-do path: forkHeight is ABOVE minRetained but no
// beforeImages exist AT or ABOVE forkHeight — meaning we're rolling back
// to a height we haven't reached yet (or already rolled back). The
// function must return nil (no error, no work). Without this contract, a
// future refactor that errors on missing entries would break legitimate
// "forkHeight above current tip" rollbacks.
//
// Fixture: seed beforeImages at heights 100, 200, 300. Call
// RollbackToHeight(500) — 500 > minRetained=100 but no entries at >= 500.
func TestR39_P2_02_RollbackToHeight_NothingToDo_ReturnsNil(t *testing.T) {
	sdb := r39P2_02NewStateDB(t)
	addr := types.BytesToAddress([]byte{0x02})
	r39P2_02SeedBeforeImage(sdb, 100, addr)
	r39P2_02SeedBeforeImage(sdb, 200, addr)
	r39P2_02SeedBeforeImage(sdb, 300, addr)

	const forkHeight uint64 = 500 // above tip (300), nothing to roll back
	err := sdb.RollbackToHeight(forkHeight)
	if err != nil {
		t.Fatalf("R39-P2-02: RollbackToHeight(%d) when forkHeight > minRetained(%d) AND no entries at >= forkHeight MUST return nil (legitimate nothing-to-do) — got error: %v; the fix must not regress the happy path", forkHeight, 100, err)
	}

	// Sanity: no beforeImages destroyed (we didn't roll back anything).
	sdb.mu.RLock()
	remaining := len(sdb.beforeImages)
	sdb.mu.RUnlock()
	if remaining != 3 {
		t.Fatalf("R39-P2-02: nothing-to-do rollback must not destroy any beforeImages — got remaining=%d (expected 3)", remaining)
	}
}

// ── Test 3: fresh StateDB (no beforeImages) → always nil. ──

// TestR39_P2_02_RollbackToHeight_FreshStateDB_ReturnsNil pins the fresh-
// node edge case: a brand-new StateDB with no beforeImages at all can
// have a RollbackToHeight(anyHeight) called on it and the call must
// return nil. This is the legitimate "fresh node, nothing has been
// committed, nothing to roll back" path; without the explicit
// empty-map guard in the fix, the empty-map case would be treated as
// "minRetained = maxUint64 ⇒ forkHeight always < minRetained ⇒ error",
// which would break initial-bootstrap calls from node.go that
// initialize then rollback to height 0 to reset any in-memory state.
//
// Fixture: fresh StateDB, beforeImages is empty. Call RollbackToHeight(50)
// — should return nil. Call RollbackToHeight(99999) — should also
// return nil.
func TestR39_P2_02_RollbackToHeight_FreshStateDB_ReturnsNil(t *testing.T) {
	sdb := r39P2_02NewStateDB(t)

	// Sanity: beforeImages is empty
	sdb.mu.RLock()
	beforeLen := len(sdb.beforeImages)
	sdb.mu.RUnlock()
	if beforeLen != 0 {
		t.Fatalf("R39-P2-02: fixture precondition — expected empty beforeImages, got len=%d", beforeLen)
	}

	for _, h := range []uint64{0, 50, 99999} {
		if err := sdb.RollbackToHeight(h); err != nil {
			t.Fatalf("R39-P2-02: fresh StateDB RollbackToHeight(%d) MUST return nil (legitimate nothing-to-do on a node with no history) — got error: %v; without the empty-map guard, initial-bootstrap rollbacks would fail spuriously", h, err)
		}
	}
}

// ── Test 4: forkHeight == minRetained → legitimate nothing-to-do (nil). ──

// TestR39_P2_02_RollbackToHeight_ForkEQMinRetained pins the boundary:
// when forkHeight equals the smallest retained beforeImage height, the
// target is NOT pruned (we can roll back ALL heights >= forkHeight
// including minRetainedHeight itself). This is the legitimate nothing-
// to-do path — there's exactly nothing ABOVE minRetained to roll back,
// OR minRetained itself is being targeted for roll back (handled by the
// existing loop since forkHeight is in [forkHeight, +inf)).
//
// Without this contract, a future refactor that uses `<=` instead of
// `<` would spuriously error on this legitimate case.
func TestR39_P2_02_RollbackToHeight_ForkEQMinRetained(t *testing.T) {
	sdb := r39P2_02NewStateDB(t)
	addr := types.BytesToAddress([]byte{0x03})
	r39P2_02SeedBeforeImage(sdb, 100, addr)

	const forkHeight uint64 = 100
	err := sdb.RollbackToHeight(forkHeight)
	if err != nil {
		t.Fatalf("R39-P2-02: RollbackToHeight(%d) when forkHeight == minRetained MUST return nil (legitimate — forkHeight is the smallest retained, no pruning involved) — got error: %v", forkHeight, err)
	}
}
