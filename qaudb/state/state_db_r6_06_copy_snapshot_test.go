// Quantaureum Node source, version 1.0.0.
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R6-06 (2026-10-21 sixth-round audit): StateDB.Copy() handed every copy the
// SAME stateSnapshots map as the original (pruning bookkeeping: block height ->
// state root), while each instance guards that map with its own s.mu. That is
// reachable in the normal node topology, not just in tests: block_producer.go
// builds a block on stateDB.Copy() and commits that copy through
// CommitWithBlock, which calls CreateSnapshot and PruneState — both of which
// write the map — while the import path commits the main StateDB on another
// goroutine. Two mutexes protecting one Go map means concurrent map writes,
// which the runtime raises as an unrecoverable fatal error (no recover() can
// catch it), and even when the two passes do not collide, a block-building copy
// that is thrown away still rewrote or deleted the live instance's history.
//
// The fix deep-copies the map, the same treatment Copy() already gives
// dirtyAccounts, dirtyStorage, storageCache, the snapshot stack, accessList,
// logs, selfDestructs, transientStorage and pendingCodeWrites.

func pruningSnapshotCount(t *testing.T, sdb *StateDB) int {
	t.Helper()
	_, _, _, count := sdb.GetPruningStats()
	return count
}

func TestR6_06_CopyDoesNotSharePruningBookkeeping(t *testing.T) {
	parent := NewStateDB(db.NewMemDB())
	addr := types.Address{0xa1}
	parent.SetBalance(addr, big.NewInt(1))
	if _, err := parent.Commit(1); err != nil {
		t.Fatalf("parent Commit: %v", err)
	}
	if err := parent.CreateSnapshot(1024); err != nil {
		t.Fatalf("parent CreateSnapshot: %v", err)
	}
	if got := pruningSnapshotCount(t, parent); got != 1 {
		t.Fatalf("fixture: parent snapshot count = %d, want 1", got)
	}

	builder := parent.Copy()
	// Copy() must still carry the history over — the isolation below is about
	// mutation, not about forgetting.
	if got := pruningSnapshotCount(t, builder); got != 1 {
		t.Fatalf("copy snapshot count = %d, want the inherited 1", got)
	}

	// A block-building copy writing a snapshot must not show up in the live
	// instance. Pre-fix this is the same map, so the parent jumps to 2 — and the
	// write happened under the copy's mutex while the import path could be
	// writing the same map under the parent's mutex.
	if err := builder.CreateSnapshot(2048); err != nil {
		t.Fatalf("builder CreateSnapshot: %v", err)
	}
	if got := pruningSnapshotCount(t, parent); got != 1 {
		t.Fatalf("parent snapshot count = %d after the copy wrote a snapshot: Copy() shares stateSnapshots, so the discarded building copy mutated the live StateDB (and the two instances' mutexes do not exclude each other — concurrent map writes are a fatal runtime error)", got)
	}
	if got := pruningSnapshotCount(t, builder); got != 2 {
		t.Fatalf("copy snapshot count = %d, want its own 2", got)
	}

	// ...and the other direction: the live instance's bookkeeping must not leak
	// into a copy that is still building.
	if err := parent.CreateSnapshot(3072); err != nil {
		t.Fatalf("parent CreateSnapshot(3072): %v", err)
	}
	if got := pruningSnapshotCount(t, parent); got != 2 {
		t.Fatalf("parent snapshot count = %d, want 2", got)
	}
	if got := pruningSnapshotCount(t, builder); got != 2 {
		t.Fatalf("copy snapshot count = %d, want it to stay at its own 2", got)
	}
}

func TestR6_06_CopyPruneCannotDeleteLiveSnapshots(t *testing.T) {
	// The production shape: the builder commits its copy at a height past the
	// retention window, which runs PruneState's delete pass. 2000 is deliberately
	// not a multiple of snapshotInterval (1024) so that this test exercises the
	// prune pass alone and not a fresh snapshot write.
	parent := NewStateDB(db.NewMemDB())
	if err := parent.CreateSnapshot(1024); err != nil {
		t.Fatalf("parent CreateSnapshot: %v", err)
	}

	builder := parent.Copy()
	if _, err := builder.CommitWithBlock(2000); err != nil {
		t.Fatalf("builder CommitWithBlock: %v", err)
	}

	if got := pruningSnapshotCount(t, builder); got != 0 {
		t.Fatalf("copy snapshot count = %d, want its stale 1024 entry pruned away", got)
	}
	if got := pruningSnapshotCount(t, parent); got != 1 {
		t.Fatalf("parent snapshot count = %d after the building copy pruned, want 1: the copy deleted the live instance's bookkeeping through the shared map", got)
	}
}
