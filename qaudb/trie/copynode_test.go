// Quantaureum Node source, version 1.0.0.
package trie

import (
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
)

// TestCopyNodePreservesExtensionChild proves the state-root mismatch root cause:
// ExtensionNode deserialized via DecodeExtensionNode has Child==nil but
// childHash!=empty. Before the fix, copyNode ignored childHash and created a
// broken ExtensionNode with an empty childHash -> different root.
func TestCopyNodePreservesExtensionChild(t *testing.T) {
	// Build a tree with two keys that share a prefix -> forces an ExtensionNode
	memdb := db.NewMemDB()
	tree := NewVerkleTree(256, memdb)

	keyA := []byte("account_00000000000000001")
	valA := []byte("value_A_data_padding__")
	keyB := []byte("account_00000000000000002")
	valB := []byte("value_B_data_padding__")

	if err := tree.Put(keyA, valA); err != nil {
		t.Fatalf("Put A: %v", err)
	}
	if err := tree.Put(keyB, valB); err != nil {
		t.Fatalf("Put B: %v", err)
	}
	// STORAGE-P0-01 FIX (R31, 2026-07-27): node writes are buffered in
	// pendingBatch. Without Flush(), the round-trip test below would load
	// an empty tree from persistentDB and fail the root comparison.
	if err := tree.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	originalRoot := tree.Root()

	// Has an ExtensionNode? At minimum, the copy must preserve the root.
	cp := tree.Copy()
	copiedRoot := cp.Root()

	if originalRoot != copiedRoot {
		t.Fatalf("ROOT MISMATCH after Copy(): original=%x copied=%x\n"+
			"copyNode corrupts ExtensionNode children (Child==nil, childHash!=empty -> dropped)",
			originalRoot, copiedRoot)
	}

	// Also test round-trip: load a fresh tree from the same persistent DB.
	// The freshly-loaded tree decodes nodes from disk (Child==nil everywhere),
	// then Copy() must still yield the same root.
	tree2 := NewVerkleTree(256, memdb)
	loadedRoot := tree2.Root()
	if loadedRoot != originalRoot {
		t.Fatalf("loaded root mismatch: original=%x loaded=%x", originalRoot, loadedRoot)
	}
	cp2 := tree2.Copy()
	if cp2.Root() != originalRoot {
		t.Fatalf("ROOT MISMATCH after Copy() of loaded tree: original=%x copied=%x",
			originalRoot, cp2.Root())
	}

	t.Logf("OK: all roots consistent = %x", originalRoot)
}
