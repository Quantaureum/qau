// Quantaureum Node source, version 1.0.0.
package trie

import (
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
)

// R7-01 (2026-10-21 seventh-round audit): VerkleTree.Copy() deliberately shares
// persistentDB with the original (the R39-P1-05 design, with Flush serialized on
// a shared mutex), so a block-building copy flushed its node writes into the live
// database. StateDB isolates a build copy by retargeting the tree onto the copy's
// own write buffer, and that isolation only holds if SetPersistentDB (a) refuses
// to re-home a tree that still has queued node writes and (b) really redirects
// later flushes. These tests pin both properties at the trie layer, because
// StateDB.CopyForBuild depends on them.

func countPrefixedKeys(t *testing.T, d db.Database, prefix string) int {
	t.Helper()
	it := d.NewIterator([]byte(prefix), nil)
	defer it.Release()
	count := 0
	for it.Next() {
		count++
	}
	if err := it.Error(); err != nil {
		t.Fatalf("iterator over prefix %q: %v", prefix, err)
	}
	return count
}

// TestR7_01_SetPersistentDBRefusesUnflushedNodeWrites pins the guardrail: the
// queued batch belongs to the outgoing database, so re-homing it silently would
// either drop node writes or apply them to the wrong target.
func TestR7_01_SetPersistentDBRefusesUnflushedNodeWrites(t *testing.T) {
	base := db.NewMemDB()
	tree := NewVerkleTree(256, base)

	if err := tree.Put([]byte("account_00000000000000001"), []byte("value_A_data_padding__")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	tree.Root() // serializes the touched nodes into the pending batch

	next := db.NewMemDB()
	if err := tree.SetPersistentDB(next); err == nil {
		t.Fatal("SetPersistentDB accepted a tree with queued node writes — " +
			"those writes would be replayed into the wrong database")
	}
	if tree.PersistentDB() != base {
		t.Error("a refused SetPersistentDB still retargeted the tree")
	}

	if err := tree.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if countPrefixedKeys(t, base, "vnode:") == 0 {
		t.Fatal("setup: the first flush wrote no nodes to the original database")
	}
	if err := tree.SetPersistentDB(next); err != nil {
		t.Fatalf("SetPersistentDB after Flush: %v", err)
	}
	if tree.PersistentDB() != next {
		t.Fatal("tree still flushes node writes into the original database")
	}

	// The re-homed batch must follow the new target, not the old one.
	baseBefore := countPrefixedKeys(t, base, "vnode:")
	if err := tree.Put([]byte("account_00000000000000002"), []byte("value_B_data_padding__")); err != nil {
		t.Fatalf("Put after retarget: %v", err)
	}
	tree.Root()
	if err := tree.Flush(); err != nil {
		t.Fatalf("Flush after retarget: %v", err)
	}
	if got := countPrefixedKeys(t, base, "vnode:"); got != baseBefore {
		t.Errorf("write after retarget still landed in the original database: %d nodes, want %d",
			got, baseBefore)
	}
	if got := countPrefixedKeys(t, next, "vnode:"); got == 0 {
		t.Error("write after retarget did not land in the new database")
	}
}

// TestR7_01_CopiedTreeRetargetLeavesOriginalFlushTarget checks the assumption
// behind CopyForBuild: the copy is built from Copy(), which shares the original's
// persistentDB, so retargeting the copy must not move the original.
func TestR7_01_CopiedTreeRetargetLeavesOriginalFlushTarget(t *testing.T) {
	base := db.NewMemDB()
	original := NewVerkleTree(256, base)

	if err := original.Put([]byte("account_00000000000000001"), []byte("value_A_data_padding__")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := original.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	build := original.Copy()
	if build.PersistentDB() != original.PersistentDB() {
		t.Skip("this build does not share the persistent database between copies")
	}

	buffer := db.NewMemDB()
	if err := build.SetPersistentDB(buffer); err != nil {
		t.Fatalf("SetPersistentDB on the copy: %v", err)
	}
	if original.PersistentDB() != base {
		t.Errorf("retargeting the copy moved the original too: got %v, want the base database",
			original.PersistentDB())
	}

	if err := build.Put([]byte("account_00000000000000002"), []byte("value_B_data_padding__")); err != nil {
		t.Fatalf("Put on the copy: %v", err)
	}
	build.Root()
	if err := build.Flush(); err != nil {
		t.Fatalf("Flush on the copy: %v", err)
	}
	if got := countPrefixedKeys(t, base, "vnode:"); got == 0 {
		t.Fatal("setup: the original's flush wrote nothing")
	}
	if countPrefixedKeys(t, buffer, "vnode:") == 0 {
		t.Error("the copy's node writes did not reach its own buffer")
	}
}
