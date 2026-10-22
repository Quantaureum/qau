// Quantaureum Node source, version 1.0.0.
package state

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R9-02 (2026-10-21 ninth-round audit, plan item C: integration evidence for the
// R8-02 marker): R8-02 made Promote publish the commit-pending marker BEFORE
// replaying, precisely so that a replay which dies halfway cannot be mistaken for
// a clean shutdown. The evidence up to the eighth round was unit-level: the
// marker survives, the anchor is not advertised, part of the block is on disk.
// What was never pinned is the half that makes those properties worth having —
// that a FRESH instance over that same disk (which is exactly what
// node.initState() constructs on boot) refuses to serve instead of opening for
// business on a state that holds half of a block.
//
// This test closes that gap end-to-end: build a real half-applied disk, restart
// over it, and require the restart to fail closed and to leave the disk
// quarantined for the next boot.

func r9_02HalfAppliedDisk(t *testing.T) (db.Database, db.Database) {
	t.Helper()

	inner := db.NewMemDB()
	alice := types.Address{0xa1}
	poison := types.Address{0xb4}

	base := &r802PoisonDB{Database: inner, poison: string(append(accountPrefix, poison[:]...))}
	live := NewStateDB(base)
	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil")
	}
	for i := 0; i < 6; i++ {
		build.SetBalance(types.Address{byte(0xb0 + i)}, big.NewInt(int64(100+i)))
	}
	if _, err := build.CommitWithBlock(2); err != nil {
		t.Fatalf("build copy CommitWithBlock(2): %v", err)
	}

	base.txs = nil
	base.limit = 3

	err := build.Promote()
	if err == nil {
		t.Fatal("Promote succeeded although the replay was supposed to fail — the fixture is not exercising a partial apply")
	}
	if errors.Is(err, ErrStaleBuildState) {
		t.Fatalf("Promote failed on the staleness fence instead of the injected replay fault: %v", err)
	}
	if len(base.transactions()) == 0 {
		t.Fatal("the replay applied nothing before failing, so the disk is not half-applied and this test proves nothing")
	}

	// The restart happens on healthy media: the fault that killed the replay has
	// nothing to do with what the next boot reads.
	base.limit = 0
	base.poison = ""
	base.txs = nil

	return inner, base
}

func TestR9_02_RestartRefusesADiskWhosePromoteReplayDiedHalfway(t *testing.T) {
	inner, base := r9_02HalfAppliedDisk(t)

	if _, err := inner.Get(commitPendingKey); err != nil {
		t.Fatalf("setup: the commit-pending marker is not durable (%v) — there is nothing for the restart to detect", err)
	}

	// The error-returning construction path (R38-P1-04).
	sdb, err := OpenStateDB(base)
	if err == nil {
		root := sdb.Root()
		t.Fatalf("a node restarted over a disk that holds half of block 2 opened for business instead of refusing (root=%x) — R8-02's marker is written for nothing if the boot trusts this database", root)
	}
	if sdb != nil {
		t.Errorf("OpenStateDB returned both an instance and an error — a refused boot must not hand out a usable StateDB")
	}

	// Refusing once is not enough: the disk must stay quarantined so the NEXT boot
	// cannot read it as a clean shutdown. Clearing the marker on the failure path
	// would silently convert "half a block" into "committed state" one restart
	// later.
	if _, err := inner.Get(commitPendingKey); err != nil {
		t.Errorf("the refused boot cleared the commit-pending marker (%v) — the next restart would treat this half-applied database as a clean one", err)
	}

	// And the production shape: node.initState() uses NewStateDB, whose contract is
	// to halt rather than serve (documented on NewStateDB).
	panicked := func() (didPanic bool) {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		disk := NewStateDB(base)
		_ = disk.Root()
		return false
	}()
	if !panicked {
		t.Error("NewStateDB over the half-applied disk came up without halting — node.initState() would then serve a state root no other node reproduces")
	}
}
