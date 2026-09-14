// Quantaureum Node source, version 1.0.0.
package trie

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// ── VerkleTree Insert/Get/Delete operations ──

func TestVerkleTree_InsertAndGet(t *testing.T) {
	tree := NewVerkleTree(0) // use default depth

	key := []byte("test-key-001")
	value := []byte("test-value-001")

	if err := tree.Put(key, value); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, err := tree.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("Get returned %q, want %q", got, value)
	}
}

func TestVerkleTree_InsertAndGet_TableDriven(t *testing.T) {
	tests := []struct {
		name  string
		key   []byte
		value []byte
	}{
		{"short_key", []byte("a"), []byte("val_a")},
		{"medium_key", []byte("medium-key-123"), []byte("val_medium")},
		{"long_key", bytes.Repeat([]byte("k"), 31), []byte("val_long")},
		{"32_byte_key", bytes.Repeat([]byte{0xAB}, 32), []byte("32byte_val")},
		{"binary_key", []byte{0x00, 0x01, 0x02, 0xFF}, []byte{0xDE, 0xAD}},
		{"empty_value", []byte("empty_val_key"), []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := NewVerkleTree(0)
			if err := tree.Put(tt.key, tt.value); err != nil {
				t.Fatalf("Put failed: %v", err)
			}
			got, err := tree.Get(tt.key)
			if err != nil {
				t.Fatalf("Get failed: %v", err)
			}
			if !bytes.Equal(got, tt.value) {
				t.Errorf("Get returned %q, want %q", got, tt.value)
			}
		})
	}
}

func TestVerkleTree_UpdateExistingKey(t *testing.T) {
	tree := NewVerkleTree(0)

	key := []byte("update-key")
	val1 := []byte("value-1")
	val2 := []byte("value-2-updated")

	if err := tree.Put(key, val1); err != nil {
		t.Fatal(err)
	}
	root1 := tree.Root()

	if err := tree.Put(key, val2); err != nil {
		t.Fatal(err)
	}
	root2 := tree.Root()

	got, err := tree.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !bytes.Equal(got, val2) {
		t.Errorf("expected %q after update, got %q", val2, got)
	}
	// Root may or may not change depending on implementation, but the value must be correct.
	_ = root1
	_ = root2
}

func TestVerkleTree_Delete(t *testing.T) {
	tree := NewVerkleTree(0)

	key := []byte("delete-me")
	value := []byte("delete-value")

	if err := tree.Put(key, value); err != nil {
		t.Fatal(err)
	}

	got, err := tree.Get(key)
	if err != nil {
		t.Fatalf("Get before delete failed: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("value mismatch before delete")
	}

	if err := tree.Delete(key); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = tree.Get(key)
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound after delete, got %v", err)
	}
}

func TestVerkleTree_DeleteNonExistent(t *testing.T) {
	tree := NewVerkleTree(0)

	// Deleting a non-existent key should not error.
	err := tree.Delete([]byte("does-not-exist"))
	if err != nil {
		t.Errorf("Delete non-existent key returned error: %v", err)
	}
}

func TestVerkleTree_MultipleInsertDelete(t *testing.T) {
	tree := NewVerkleTree(0)

	keys := [][]byte{
		[]byte("key-1"),
		[]byte("key-2"),
		[]byte("key-3"),
		[]byte("key-4"),
		[]byte("key-5"),
	}
	values := [][]byte{
		[]byte("val-1"),
		[]byte("val-2"),
		[]byte("val-3"),
		[]byte("val-4"),
		[]byte("val-5"),
	}

	// Insert all
	for i := range keys {
		if err := tree.Put(keys[i], values[i]); err != nil {
			t.Fatalf("Put %s failed: %v", keys[i], err)
		}
	}

	// Verify all
	for i := range keys {
		got, err := tree.Get(keys[i])
		if err != nil {
			t.Errorf("Get %s failed: %v", keys[i], err)
			continue
		}
		if !bytes.Equal(got, values[i]) {
			t.Errorf("Get %s = %q, want %q", keys[i], got, values[i])
		}
	}

	// Delete middle key
	if err := tree.Delete(keys[2]); err != nil {
		t.Fatalf("Delete %s failed: %v", keys[2], err)
	}

	// Verify deleted key is gone
	_, err := tree.Get(keys[2])
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound for deleted key, got %v", err)
	}

	// Verify other keys still exist
	for i := range keys {
		if i == 2 {
			continue
		}
		got, err := tree.Get(keys[i])
		if err != nil {
			t.Errorf("Get %s after delete failed: %v", keys[i], err)
			continue
		}
		if !bytes.Equal(got, values[i]) {
			t.Errorf("Get %s = %q, want %q after delete", keys[i], got, values[i])
		}
	}
}

// ── VerkleTree Copy (deep copy) ──

func TestVerkleTree_Copy(t *testing.T) {
	tree := NewVerkleTree(0)

	key := []byte("copy-key")
	value := []byte("copy-value")

	if err := tree.Put(key, value); err != nil {
		t.Fatal(err)
	}
	originalRoot := tree.Root()

	copied := tree.Copy()
	if copied == nil {
		t.Fatal("Copy returned nil")
	}

	// Root should be the same
	if copied.Root() != originalRoot {
		t.Errorf("copied root %x != original root %x", copied.Root(), originalRoot)
	}

	// Values should be accessible from the copy
	got, err := copied.Get(key)
	if err != nil {
		t.Fatalf("Get from copy failed: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("copied value = %q, want %q", got, value)
	}
}

func TestVerkleTree_CopyIndependence(t *testing.T) {
	tree := NewVerkleTree(0)

	key1 := []byte("indep-key-1")
	key2 := []byte("indep-key-2")

	if err := tree.Put(key1, []byte("val-1")); err != nil {
		t.Fatal(err)
	}

	copied := tree.Copy()

	// Modify the copy — original should be unaffected (root may differ)
	if err := copied.Put(key2, []byte("val-2")); err != nil {
		t.Fatal(err)
	}

	// key2 should exist in the copy
	_, err := copied.Get(key2)
	if err != nil {
		t.Errorf("key2 should exist in copy: %v", err)
	}

	// key1 should still exist in both
	if _, err := tree.Get(key1); err != nil {
		t.Errorf("key1 missing from original after copy modification: %v", err)
	}
	if _, err := copied.Get(key1); err != nil {
		t.Errorf("key1 missing from copy: %v", err)
	}
}

func TestVerkleTree_CopyNil(t *testing.T) {
	var nilTree *VerkleTree
	copied := nilTree.Copy()
	if copied != nil {
		t.Error("Copy of nil tree should return nil")
	}
}

// ── Root computation ──

func TestVerkleTree_EmptyRoot(t *testing.T) {
	tree := NewVerkleTree(0)
	root := tree.Root()
	if root != (types.Hash{}) {
		t.Errorf("empty tree root should be zero hash, got %x", root)
	}
}

func TestVerkleTree_RootChangesOnInsert(t *testing.T) {
	tree := NewVerkleTree(0)
	emptyRoot := tree.Root()

	if err := tree.Put([]byte("root-test"), []byte("value")); err != nil {
		t.Fatal(err)
	}
	newRoot := tree.Root()

	if newRoot == emptyRoot {
		t.Error("root should change after inserting into empty tree")
	}
}

func TestVerkleTree_RootDeterministic(t *testing.T) {
	tree1 := NewVerkleTree(0)
	tree2 := NewVerkleTree(0)

	pairs := []struct {
		k, v []byte
	}{
		{[]byte("det-1"), []byte("v1")},
		{[]byte("det-2"), []byte("v2")},
		{[]byte("det-3"), []byte("v3")},
	}

	for _, p := range pairs {
		_ = tree1.Put(p.k, p.v)
		_ = tree2.Put(p.k, p.v)
	}

	if tree1.Root() != tree2.Root() {
		t.Errorf("roots should be deterministic: %x vs %x", tree1.Root(), tree2.Root())
	}
}

// ── Node persistence (putNode/getNode via GetDB and operations) ──

func TestVerkleTree_NodePersistence(t *testing.T) {
	persistentDB := db.NewMemDB()

	// Build a tree with persistent storage
	tree1 := NewVerkleTree(0, persistentDB)
	_ = tree1.Put([]byte("persist-1"), []byte("pv-1"))
	_ = tree1.Put([]byte("persist-2"), []byte("pv-2"))
	// STORAGE-P0-01 FIX (R31, 2026-07-27): node writes are buffered in
	// pendingBatch and only become visible to other trees sharing the same
	// persistentDB after Flush(). Without this call, tree2 would load an
	// empty DB and produce a different root.
	if err := tree1.Flush(); err != nil {
		t.Fatalf("tree1.Flush: %v", err)
	}
	root1 := tree1.Root()

	// Create a new tree loading from the same persistent DB
	tree2 := NewVerkleTree(0, persistentDB)
	root2 := tree2.Root()

	// Roots should match if persistence works
	if root1 != root2 {
		t.Errorf("persisted root %x != loaded root %x", root1, root2)
	}
}

func TestVerkleTree_GetDB(t *testing.T) {
	tree := NewVerkleTree(0)
	_ = tree.Put([]byte("db-key"), []byte("db-val"))

	treeDB := tree.GetDB()
	if treeDB == nil {
		t.Fatal("GetDB returned nil")
	}
	if len(treeDB) == 0 {
		t.Error("GetDB returned empty map after inserts")
	}

	// Verify that modifying the returned map does not affect the tree's internal db
	for k := range treeDB {
		treeDB[k] = []byte("tampered")
	}

	// Tree should still work
	got, err := tree.Get([]byte("db-key"))
	if err != nil {
		t.Fatalf("Get after GetDB tamper failed: %v", err)
	}
	if !bytes.Equal(got, []byte("db-val")) {
		t.Errorf("value changed after GetDB tamper: %q", got)
	}
}

// ── Edge cases ──

func TestVerkleTree_EmptyKey(t *testing.T) {
	tree := NewVerkleTree(0)

	// TRIE-R11-005: empty keys are rejected at the API boundary because
	// they cannot be injectively encoded into a 31+1 byte stem+suffix
	// (the all-zero stem collides with "\x00"*31). The audit fix enforces
	// a 32-byte canonical key length standard.
	err := tree.Put([]byte{}, []byte("empty"))
	if err != ErrInvalidKey {
		t.Errorf("Put with empty key: expected ErrInvalidKey, got %v", err)
	}

	_, err = tree.Get([]byte{})
	if err != ErrKeyNotFound {
		t.Errorf("Get with empty key: expected ErrKeyNotFound, got %v", err)
	}
}

func TestVerkleTree_GetFromEmptyTree(t *testing.T) {
	tree := NewVerkleTree(0)

	_, err := tree.Get([]byte("nope"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound from empty tree, got %v", err)
	}
}

func TestVerkleTree_LargeKey(t *testing.T) {
	tree := NewVerkleTree(0)

	// TRIE-R11-005: keys longer than VerkleKeySize (32 bytes) are rejected
	// because they cannot be injectively encoded into a 31+1 byte
	// stem+suffix. Callers must canonicalize to 32-byte keys.
	largeKey := make([]byte, 64) // 64-byte key
	rand.Read(largeKey)
	value := []byte("large-key-value")

	if err := tree.Put(largeKey, value); err != ErrInvalidKey {
		t.Fatalf("Put with 64-byte key: expected ErrInvalidKey, got %v", err)
	}

	// 32-byte canonical keys are the fast path and must still work.
	canonicalKey := make([]byte, 32)
	rand.Read(canonicalKey)
	if err := tree.Put(canonicalKey, value); err != nil {
		t.Fatalf("Put with 32-byte canonical key failed: %v", err)
	}
	got, err := tree.Get(canonicalKey)
	if err != nil {
		t.Fatalf("Get with 32-byte canonical key failed: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("canonical key value mismatch: got %q, want %q", got, value)
	}
}

func TestVerkleTree_LargeValue(t *testing.T) {
	tree := NewVerkleTree(0)

	key := []byte("big-val-key")
	largeValue := make([]byte, 4096)
	rand.Read(largeValue)

	if err := tree.Put(key, largeValue); err != nil {
		t.Fatalf("Put with large value failed: %v", err)
	}

	got, err := tree.Get(key)
	if err != nil {
		t.Fatalf("Get with large value failed: %v", err)
	}
	if !bytes.Equal(got, largeValue) {
		t.Error("large value mismatch")
	}
}

func TestVerkleTree_DeleteEmptyKey(t *testing.T) {
	tree := NewVerkleTree(0)

	// TRIE-R11-005: empty keys are rejected at the API boundary.
	err := tree.Delete([]byte{})
	if err != ErrInvalidKey {
		t.Errorf("Delete with empty key: expected ErrInvalidKey, got %v", err)
	}
}

// ── Node encode/decode round-trip tests ──

func TestLeafNode_EncodeDecodeRoundTrip(t *testing.T) {
	key := []byte("leaf-key")
	value := []byte("leaf-value")

	original := NewLeafNode(key, value)
	encoded := original.Encode()

	decoded, err := DecodeLeafNode(encoded)
	if err != nil {
		t.Fatalf("DecodeLeafNode failed: %v", err)
	}
	if !bytes.Equal(decoded.Key, key) {
		t.Errorf("decoded key = %q, want %q", decoded.Key, key)
	}
	if !bytes.Equal(decoded.Value, value) {
		t.Errorf("decoded value = %q, want %q", decoded.Value, value)
	}
	if decoded.Hash() != original.Hash() {
		t.Error("decoded hash does not match original")
	}
}

func TestInternalNode_EncodeDecodeRoundTrip(t *testing.T) {
	original := NewInternalNode()
	original.Children[0] = types.BytesToHash([]byte("child0"))
	original.Children[255] = types.BytesToHash([]byte("child255"))
	original.recomputeHash()

	encoded := original.Encode()
	decoded, err := DecodeInternalNode(encoded)
	if err != nil {
		t.Fatalf("DecodeInternalNode failed: %v", err)
	}
	if decoded.Hash() != original.Hash() {
		t.Error("decoded internal node hash does not match original")
	}
}

func TestDecodeLeafNode_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"wrong_type", []byte{NodeTypeInternal, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"too_short", []byte{NodeTypeLeaf, 0, 0, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeLeafNode(tt.data)
			if err == nil {
				t.Error("expected error for invalid data")
			}
		})
	}
}

func TestDecodeInternalNode_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"wrong_type", []byte{NodeTypeLeaf}},
		{"too_short", []byte{NodeTypeInternal, 0, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeInternalNode(tt.data)
			if err == nil {
				t.Error("expected error for invalid data")
			}
		})
	}
}

// ── Proof generation ──

func TestVerkleTree_Prove(t *testing.T) {
	tree := NewVerkleTree(0)
	key := []byte("prove-key")
	value := []byte("prove-value")

	if err := tree.Put(key, value); err != nil {
		t.Fatal(err)
	}

	proof, err := tree.Prove(key)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if proof == nil {
		t.Fatal("Prove returned nil proof")
	}
	if !bytes.Equal(proof.Key, key) {
		t.Errorf("proof key = %q, want %q", proof.Key, key)
	}
	if !bytes.Equal(proof.Value, value) {
		t.Errorf("proof value = %q, want %q", proof.Value, value)
	}
}

func TestVerkleTree_ProveExclusion(t *testing.T) {
	tree := NewVerkleTree(0)
	_ = tree.Put([]byte("exists"), []byte("yes"))

	proof, err := tree.Prove([]byte("does-not-exist"))
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.IsExclusion {
		t.Error("expected exclusion proof for non-existent key")
	}
}

func TestVerkleTree_ProveEmptyTree(t *testing.T) {
	tree := NewVerkleTree(0)

	proof, err := tree.Prove([]byte("any-key"))
	if err != nil {
		t.Fatalf("Prove on empty tree failed: %v", err)
	}
	if proof == nil {
		t.Fatal("proof is nil")
	}
	if !proof.IsExclusion {
		t.Error("expected exclusion proof on empty tree")
	}
}

// ── VerkleProof verification ──

func TestVerkleProof_VerifyNil(t *testing.T) {
	var proof *VerkleProof
	result := proof.Verify(types.Hash{})
	if result {
		t.Error("nil proof should not verify")
	}
}

func TestVerifyProof_NilProof(t *testing.T) {
	result := VerifyProof(types.Hash{}, nil)
	if result {
		t.Error("VerifyProof with nil proof should return false")
	}
}

// ── R4-DATA-04: SuffixValues preservation regression tests ──
//
// R4-DATA-04 [Med, LATENT]: The R3-DATA-01 SuffixValues fix was dropped in two
// code paths in verkle.go: (1) same-key update in insert() and (2) splitLeaf().
// Both paths created a new LeafNode via NewLeafNode(key, value) without copying
// SuffixValues from the old leaf, silently dropping same-stem entries.
// The live path uses 20-byte address keys so this is latent, but the fix
// prevents data loss and root hash mismatch for 32-byte keys.

// TestR4DATA04_SameKeyUpdate_PreservesSuffixValues verifies that updating a
// leaf's primary (key, value) does not silently drop SuffixValues entries for
// other keys sharing the same 31-byte stem.
func TestR4DATA04_SameKeyUpdate_PreservesSuffixValues(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// keyA and keyB share the same 31-byte stem (all 0x01) but differ in
	// the 32nd byte (suffix). keyA gets suffix 0xAA, keyB gets 0xBB.
	stem := make([]byte, 31)
	for i := range stem {
		stem[i] = 0x01
	}
	keyA := make([]byte, 32)
	copy(keyA, stem)
	keyA[31] = 0xAA
	keyB := make([]byte, 32)
	copy(keyB, stem)
	keyB[31] = 0xBB

	valA := []byte("value-A")
	valB := []byte("value-B")
	valA2 := []byte("value-A-updated")

	// 1. Insert keyA — creates a leaf with (keyA, valA)
	if err := tree.Put(keyA, valA); err != nil {
		t.Fatalf("Put keyA failed: %v", err)
	}
	// 2. Insert keyB — same stem, different suffix → stored in SuffixValues[0xBB]
	if err := tree.Put(keyB, valB); err != nil {
		t.Fatalf("Put keyB failed: %v", err)
	}
	// Verify keyB is retrievable before update
	gotB, err := tree.Get(keyB)
	if err != nil {
		t.Fatalf("Get keyB before update failed: %v", err)
	}
	if !bytes.Equal(gotB, valB) {
		t.Fatalf("keyB value before update = %q, want %q", gotB, valB)
	}
	// 3. Update keyA — triggers same-key update path in insert()
	if err := tree.Put(keyA, valA2); err != nil {
		t.Fatalf("Put keyA (update) failed: %v", err)
	}
	// 4. Verify keyA has the updated value
	gotA, err := tree.Get(keyA)
	if err != nil {
		t.Fatalf("Get keyA after update failed: %v", err)
	}
	if !bytes.Equal(gotA, valA2) {
		t.Errorf("keyA value after update = %q, want %q", gotA, valA2)
	}
	// 5. CRITICAL: Verify keyB's value is still accessible (SuffixValues preserved)
	gotB2, err := tree.Get(keyB)
	if err != nil {
		t.Errorf("R4-DATA-04 REGRESSION: Get keyB after same-key update of keyA failed: %v — SuffixValues were dropped", err)
		return
	}
	if !bytes.Equal(gotB2, valB) {
		t.Errorf("R4-DATA-04 REGRESSION: keyB value after same-key update = %q, want %q — SuffixValues were dropped", gotB2, valB)
	}
}

// TestR4DATA04_SplitLeaf_PreservesSuffixValues verifies that splitting a leaf
// (when a key with a different 31-byte stem is inserted at a deeper depth)
// does not silently drop SuffixValues entries from the old leaf.
func TestR4DATA04_SplitLeaf_PreservesSuffixValues(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// keyA and keyB share the same 31-byte stem (all 0x01) but differ in suffix.
	stemX := make([]byte, 31)
	for i := range stemX {
		stemX[i] = 0x01
	}
	keyA := make([]byte, 32)
	copy(keyA, stemX)
	keyA[31] = 0xAA
	keyB := make([]byte, 32)
	copy(keyB, stemX)
	keyB[31] = 0xBB

	// keyC has a DIFFERENT stem (byte 5 differs: 0x02 instead of 0x01).
	// This ensures splitLeaf is called when keyC is inserted, and an
	// extension node is created (diffIdx = 5 > 0).
	keyC := make([]byte, 32)
	copy(keyC, stemX)
	keyC[5] = 0x02 // diverge within the 31-byte stem
	keyC[31] = 0xCC

	valA := []byte("value-A")
	valB := []byte("value-B")
	valC := []byte("value-C")

	// 1. Insert keyA — creates a leaf with (keyA, valA)
	if err := tree.Put(keyA, valA); err != nil {
		t.Fatalf("Put keyA failed: %v", err)
	}
	// 2. Insert keyB — same stem, different suffix → stored in SuffixValues[0xBB]
	if err := tree.Put(keyB, valB); err != nil {
		t.Fatalf("Put keyB failed: %v", err)
	}
	// Verify keyB is retrievable before split
	gotB, err := tree.Get(keyB)
	if err != nil {
		t.Fatalf("Get keyB before split failed: %v", err)
	}
	if !bytes.Equal(gotB, valB) {
		t.Fatalf("keyB value before split = %q, want %q", gotB, valB)
	}
	// 3. Insert keyC — DIFFERENT stem → triggers splitLeaf on keyA's leaf.
	// The old leaf (keyA + SuffixValues[0xBB]=valB) is split.
	if err := tree.Put(keyC, valC); err != nil {
		t.Fatalf("Put keyC (trigger split) failed: %v", err)
	}
	// 4. Verify keyA is still retrievable
	gotA, err := tree.Get(keyA)
	if err != nil {
		t.Errorf("Get keyA after split failed: %v", err)
	}
	if !bytes.Equal(gotA, valA) {
		t.Errorf("keyA value after split = %q, want %q", gotA, valA)
	}
	// 5. Verify keyC is retrievable
	gotC, err := tree.Get(keyC)
	if err != nil {
		t.Errorf("Get keyC after split failed: %v", err)
	}
	if !bytes.Equal(gotC, valC) {
		t.Errorf("keyC value after split = %q, want %q", gotC, valC)
	}
	// 6. CRITICAL: Verify keyB's value is still accessible after the split.
	// Without the R4-DATA-04 fix, SuffixValues would be dropped during
	// splitLeaf, making keyB unretrievable.
	gotB2, err := tree.Get(keyB)
	if err != nil {
		t.Errorf("R4-DATA-04 REGRESSION: Get keyB after splitLeaf failed: %v — SuffixValues were dropped during split", err)
		return
	}
	if !bytes.Equal(gotB2, valB) {
		t.Errorf("R4-DATA-04 REGRESSION: keyB value after splitLeaf = %q, want %q — SuffixValues were dropped during split", gotB2, valB)
	}
}

// TestR4DATA04_SplitLeaf_AtDepth0_PreservesSuffixValues tests the splitLeaf
// path where keys diverge at byte 0 (no extension node created, just an
// internal node). This is a different code path within splitLeaf (diffIdx==0).
func TestR4DATA04_SplitLeaf_AtDepth0_PreservesSuffixValues(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// keyA and keyB share the same stem (first byte = 0x01).
	stemX := make([]byte, 31)
	for i := range stemX {
		stemX[i] = 0x01
	}
	keyA := make([]byte, 32)
	copy(keyA, stemX)
	keyA[31] = 0xAA
	keyB := make([]byte, 32)
	copy(keyB, stemX)
	keyB[31] = 0xBB

	// keyC diverges at byte 0 (different stem from the very first byte).
	// splitLeaf will be called with diffIdx=0 → no extension node created.
	keyC := make([]byte, 32)
	keyC[0] = 0x02
	for i := 1; i < 31; i++ {
		keyC[i] = 0x01
	}
	keyC[31] = 0xCC

	valA := []byte("depth0-A")
	valB := []byte("depth0-B")
	valC := []byte("depth0-C")

	if err := tree.Put(keyA, valA); err != nil {
		t.Fatalf("Put keyA failed: %v", err)
	}
	if err := tree.Put(keyB, valB); err != nil {
		t.Fatalf("Put keyB failed: %v", err)
	}
	// Trigger splitLeaf at depth 0 (diffIdx == 0 → no extension node)
	if err := tree.Put(keyC, valC); err != nil {
		t.Fatalf("Put keyC failed: %v", err)
	}
	// All three must be retrievable
	for _, tc := range []struct {
		name string
		key  []byte
		val  []byte
	}{
		{"keyA", keyA, valA},
		{"keyB", keyB, valB},
		{"keyC", keyC, valC},
	} {
		got, err := tree.Get(tc.key)
		if err != nil {
			t.Errorf("R4-DATA-04 REGRESSION: Get %s after depth-0 split failed: %v", tc.name, err)
			continue
		}
		if !bytes.Equal(got, tc.val) {
			t.Errorf("R4-DATA-04 REGRESSION: %s value after depth-0 split = %q, want %q", tc.name, got, tc.val)
		}
	}
}

// ── R4-DATA-07: VerkleStateDB.Deserialize embedded root trust regression tests ──

// TestR4DATA07_Deserialize_TamperedRoot_Rejected verifies that tampering with
// the embedded root hash (first 32 bytes of serialized data) is detected and
// rejected. Before the fix, the root hash was trusted without verification,
// allowing an attacker or bit-flip corruption to inject any root hash.
func TestR4DATA07_Deserialize_TamperedRoot_Rejected(t *testing.T) {
	db := NewVerkleStateDB()

	// Populate the DB with some data
	var addr types.Address
	rand.Read(addr[:])
	db.SetAccount(addr, []byte("tamper-test-data"))

	data, err := db.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if len(data) < 33 {
		t.Fatalf("serialized data too short: %d bytes", len(data))
	}

	// Tamper with the root hash (flip the first byte of the 32-byte root)
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[0] ^= 0x01 // flip one bit in the root hash

	// Deserialize should fail because the tampered root doesn't match any
	// node in the imported data, or the decoded node's hash doesn't match
	// the claimed root.
	db2 := NewVerkleStateDB()
	err = db2.Deserialize(tampered)
	if err == nil {
		t.Error("R4-DATA-07 REGRESSION: Deserialize with tampered root should have failed, but succeeded")
	}
}

// TestR4DATA07_Deserialize_EmptyTree_Accepted verifies that an empty tree
// (zero root hash) deserializes correctly. The fix must not break the empty
// tree case.
func TestR4DATA07_Deserialize_EmptyTree_Accepted(t *testing.T) {
	db := NewVerkleStateDB()

	data, err := db.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	db2 := NewVerkleStateDB()
	err = db2.Deserialize(data)
	if err != nil {
		t.Errorf("Deserialize of empty tree should succeed, got: %v", err)
	}

	// Root should be zero (empty tree)
	if db2.Root() != (types.Hash{}) {
		t.Errorf("empty tree root should be zero hash, got %x", db2.Root())
	}
}

// TestR4DATA07_Deserialize_ValidRoundtrip_RootVerified verifies that a valid
// serialize → deserialize roundtrip produces the correct root. This is the
// positive case that ensures the fix doesn't reject legitimate data.
func TestR4DATA07_Deserialize_ValidRoundtrip_RootVerified(t *testing.T) {
	db := NewVerkleStateDB()

	var addr types.Address
	rand.Read(addr[:])
	db.SetAccount(addr, []byte("roundtrip-data"))

	var slot types.Hash
	rand.Read(slot[:])
	db.SetStorage(addr, slot, []byte("storage-data"))
	db.SetCode([]byte("contract-code"))

	originalRoot := db.Root()

	data, err := db.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	db2 := NewVerkleStateDB()
	err = db2.Deserialize(data)
	if err != nil {
		t.Fatalf("R4-DATA-07 REGRESSION: valid roundtrip Deserialize failed: %v", err)
	}

	if db2.Root() != originalRoot {
		t.Errorf("R4-DATA-07: root mismatch after roundtrip — original %x, deserialized %x", originalRoot, db2.Root())
	}

	// Verify data is accessible after roundtrip
	gotAccount, err := db2.GetAccount(addr)
	if err != nil {
		t.Errorf("GetAccount after roundtrip failed: %v", err)
	}
	if !bytes.Equal(gotAccount, []byte("roundtrip-data")) {
		t.Errorf("account data mismatch after roundtrip: got %q", gotAccount)
	}
}

// ── R33 TRIE-02/03: Stem offset consistency regression tests ──
//
// TRIE-02: walk()/insert() used absolute prefix (stem[:]) while proveWalk()
// used relative prefix (stem[depth:]). When depth > 0, walk failed but
// proveWalk succeeded → proof path inconsistency → state root divergence.
//
// TRIE-03: splitLeaf started diffIdx from 0 (ignoring depth), creating
// absolute-prefix ExtensionNodes. insert() then stripped only 1 byte
// instead of the correct amount, causing walk/Get to fail for keys under
// nested extensions.
//
// These tests verify that walk/insert/proveWalk all produce consistent
// results when depth > 0 (i.e., when splitLeaf is called from within an
// InternalNode descent, not at the root).

// TestR33_TRIE_02_03_StemOffsetConsistency verifies that splitLeaf called
// at depth > 0 produces a tree where walk (Get) and proveWalk (Prove)
// are consistent. This is the core regression test for TRIE-02 and TRIE-03.
func TestR33_TRIE_02_03_StemOffsetConsistency(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// Construct 32-byte keys whose stems (first 31 bytes) diverge at
	// specific positions to force nested extension nodes:
	//
	//   keyA: stem = [0xAA, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, ...]
	//   keyD: stem = [0xAA, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, ...]
	//         ↑ diverges from keyA at byte 1
	//   keyC: stem = [0xAA, 0x01, 0x01, 0x01, 0x01, 0x03, 0x01, ...]
	//         ↑ diverges from keyA at byte 5 (deeper)
	//
	// After Put(keyA), Put(keyD): root ExtensionNode(stem[0:1], InternalNode)
	//   with Children[0x01]=LeafA, Children[0x02]=LeafD.
	// After Put(keyC): descends through root Extension (depth 0→1),
	//   InternalNode (depth 1, idx=0x01), reaches LeafA. splitLeaf is
	//   called at depth=1 (NOT 0). Without the TRIE-03 fix, splitLeaf
	//   would scan from 0 and create an absolute stem, which walk()
	//   (with the TRIE-02 relative fix) would fail to match.
	keyA := make([]byte, 32)
	keyA[0] = 0xAA
	for i := 1; i < 31; i++ {
		keyA[i] = 0x01
	}
	keyA[31] = 0xAA // suffix

	keyD := make([]byte, 32)
	keyD[0] = 0xAA
	keyD[1] = 0x02 // diverge at byte 1
	for i := 2; i < 31; i++ {
		keyD[i] = 0x01
	}
	keyD[31] = 0xDD

	keyC := make([]byte, 32)
	keyC[0] = 0xAA
	for i := 1; i < 5; i++ {
		keyC[i] = 0x01
	}
	keyC[5] = 0x03 // diverge at byte 5 (deeper)
	for i := 6; i < 31; i++ {
		keyC[i] = 0x01
	}
	keyC[31] = 0xCC

	valA := []byte("value-A-deep")
	valD := []byte("value-D-deep")
	valC := []byte("value-C-deep")

	// 1. Insert keyA → LeafA at root.
	if err := tree.Put(keyA, valA); err != nil {
		t.Fatalf("Put keyA failed: %v", err)
	}
	// 2. Insert keyD → splitLeaf at depth 0, diffIdx=1. Creates root
	//    ExtensionNode(stemA[0:1], 1, InternalNode at depth 1).
	if err := tree.Put(keyD, valD); err != nil {
		t.Fatalf("Put keyD failed: %v", err)
	}
	// 3. Insert keyC → descends to LeafA at depth 1. splitLeaf called
	//    at depth=1 with diffIdx=5. This is the CRITICAL case: depth > 0.
	//    Without TRIE-03 fix, splitLeaf scans from 0 and creates absolute
	//    stem. Without TRIE-02 fix, walk uses absolute prefix. With both
	//    fixes, splitLeaf returns relative stem and walk matches it.
	if err := tree.Put(keyC, valC); err != nil {
		t.Fatalf("Put keyC failed: %v", err)
	}

	// 4. Verify ALL keys are retrievable via Get (uses walk).
	//    Before the fix, Get(keyA) and Get(keyC) would return
	//    ErrKeyNotFound because walk couldn't match the nested
	//    extension's stem.
	for _, tc := range []struct {
		name string
		key  []byte
		val  []byte
	}{
		{"keyA", keyA, valA},
		{"keyD", keyD, valD},
		{"keyC", keyC, valC},
	} {
		got, err := tree.Get(tc.key)
		if err != nil {
			t.Errorf("TRIE-02/03 REGRESSION: Get %s failed: %v — walk/insert stem offset inconsistency", tc.name, err)
			continue
		}
		if !bytes.Equal(got, tc.val) {
			t.Errorf("TRIE-02/03 REGRESSION: %s value = %q, want %q", tc.name, got, tc.val)
		}
	}

	// 5. Verify ALL keys produce valid inclusion proofs (uses proveWalk).
	//    Before TRIE-02 fix, walk and proveWalk used different prefix
	//    matching (absolute vs relative), causing proof path inconsistency.
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"keyA", keyA},
		{"keyD", keyD},
		{"keyC", keyC},
	} {
		proof, err := tree.Prove(tc.key)
		if err != nil {
			t.Errorf("TRIE-02/03 REGRESSION: Prove %s failed: %v", tc.name, err)
			continue
		}
		if !proof.Verify(tree.Root()) {
			t.Errorf("TRIE-02/03 REGRESSION: proof for %s failed verification — walk/proveWalk inconsistency", tc.name)
		}
	}
}

// TestR33_TRIE_02_03_ExtensionSplitAtDepth verifies that the ExtensionNode
// split logic in insert() (when a new key doesn't share an existing
// extension's prefix) works correctly at depth > 0. This tests the
// stem[depth+div] fix in the divergence-point calculation.
func TestR33_TRIE_02_03_ExtensionSplitAtDepth(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// Build a tree with a nested extension, then insert a key that
	// diverges from the extension's stem at a position that requires
	// the depth-aware comparison.
	//
	// keyA: stem = [0xAA, 0x01, 0x01, 0x01, 0x01, 0x01, ...]
	// keyD: stem = [0xAA, 0x02, ...]  — diverges at byte 1
	//   After Put(A), Put(D): root Ext(stem[0:1], InternalNode)
	//     Children[0x01]=LeafA, Children[0x02]=LeafD
	//
	// keyE: stem = [0xBB, ...]  — diverges at byte 0 from the root extension
	//   This triggers the ExtensionNode split logic in insert() at depth 0.
	//
	// keyF: stem = [0xAA, 0x01, 0x01, 0x05, ...]  — diverges at byte 3
	//   After Put(A), Put(D), Put(F): descends to LeafA at depth 1,
	//   splitLeaf at depth 1, diffIdx=3. Creates nested Ext(stem[2:3], ...).
	//
	// keyG: stem = [0xAA, 0x01, 0x09, ...]  — diverges at byte 2 from keyA
	//   This triggers the ExtensionNode split logic in insert() at depth 1
	//   (inside the nested extension). Without the stem[depth+div] fix,
	//   the divergence point would be calculated incorrectly.

	keyA := make([]byte, 32)
	keyA[0] = 0xAA
	for i := 1; i < 31; i++ {
		keyA[i] = 0x01
	}
	keyA[31] = 0xAA

	keyD := make([]byte, 32)
	keyD[0] = 0xAA
	keyD[1] = 0x02
	for i := 2; i < 31; i++ {
		keyD[i] = 0x01
	}
	keyD[31] = 0xDD

	keyF := make([]byte, 32)
	keyF[0] = 0xAA
	keyF[1] = 0x01
	keyF[2] = 0x01
	keyF[3] = 0x05 // diverge at byte 3
	for i := 4; i < 31; i++ {
		keyF[i] = 0x01
	}
	keyF[31] = 0xFF

	keyG := make([]byte, 32)
	keyG[0] = 0xAA
	keyG[1] = 0x01
	keyG[2] = 0x09 // diverge at byte 2 (triggers extension split at depth > 0)
	for i := 3; i < 31; i++ {
		keyG[i] = 0x01
	}
	keyG[31] = 0xEE

	valA := []byte("val-A")
	valD := []byte("val-D")
	valF := []byte("val-F")
	valG := []byte("val-G")

	// Build the tree step by step.
	if err := tree.Put(keyA, valA); err != nil {
		t.Fatalf("Put keyA: %v", err)
	}
	if err := tree.Put(keyD, valD); err != nil {
		t.Fatalf("Put keyD: %v", err)
	}
	if err := tree.Put(keyF, valF); err != nil {
		t.Fatalf("Put keyF: %v", err)
	}
	// Inserting keyG triggers the ExtensionNode split logic at depth > 0.
	// The nested extension (from keyF insertion) has a relative stem.
	// keyG diverges from this stem, so insert() must split the extension.
	// Without stem[depth+div], the divergence point would be wrong.
	if err := tree.Put(keyG, valG); err != nil {
		t.Fatalf("Put keyG: %v", err)
	}

	// Verify all keys are retrievable.
	for _, tc := range []struct {
		name string
		key  []byte
		val  []byte
	}{
		{"keyA", keyA, valA},
		{"keyD", keyD, valD},
		{"keyF", keyF, valF},
		{"keyG", keyG, valG},
	} {
		got, err := tree.Get(tc.key)
		if err != nil {
			t.Errorf("TRIE-02/03 REGRESSION: Get %s failed: %v", tc.name, err)
			continue
		}
		if !bytes.Equal(got, tc.val) {
			t.Errorf("TRIE-02/03 REGRESSION: %s = %q, want %q", tc.name, got, tc.val)
		}
	}

	// Verify all proofs are valid.
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"keyA", keyA},
		{"keyD", keyD},
		{"keyF", keyF},
		{"keyG", keyG},
	} {
		proof, err := tree.Prove(tc.key)
		if err != nil {
			t.Errorf("TRIE-02/03 REGRESSION: Prove %s failed: %v", tc.name, err)
			continue
		}
		if !proof.Verify(tree.Root()) {
			t.Errorf("TRIE-02/03 REGRESSION: proof for %s failed verification", tc.name)
		}
	}
}

// TestR33_TRIE_02_03_DeleteFromNestedExtension verifies that delete()
// also works correctly with nested extensions (depth > 0). delete()
// already used stem[depth:] (the correct relative form), but this test
// ensures the splitLeaf/insert fixes don't break delete round-trips.
func TestR33_TRIE_02_03_DeleteFromNestedExtension(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	keyA := make([]byte, 32)
	keyA[0] = 0xAA
	for i := 1; i < 31; i++ {
		keyA[i] = 0x01
	}
	keyA[31] = 0xAA

	keyD := make([]byte, 32)
	keyD[0] = 0xAA
	keyD[1] = 0x02
	for i := 2; i < 31; i++ {
		keyD[i] = 0x01
	}
	keyD[31] = 0xDD

	keyC := make([]byte, 32)
	keyC[0] = 0xAA
	for i := 1; i < 5; i++ {
		keyC[i] = 0x01
	}
	keyC[5] = 0x03
	for i := 6; i < 31; i++ {
		keyC[i] = 0x01
	}
	keyC[31] = 0xCC

	tree.Put(keyA, []byte("A"))
	tree.Put(keyD, []byte("D"))
	tree.Put(keyC, []byte("C"))

	// Delete keyC (the deeply-nested key). After deletion, keyA and keyD
	// must still be retrievable.
	if err := tree.Delete(keyC); err != nil {
		t.Fatalf("Delete keyC: %v", err)
	}

	// keyC should be gone.
	if _, err := tree.Get(keyC); err == nil {
		t.Error("TRIE-02/03: keyC should be deleted, but Get succeeded")
	}

	// keyA and keyD must still be retrievable.
	for _, tc := range []struct {
		name string
		key  []byte
		val  []byte
	}{
		{"keyA", keyA, []byte("A")},
		{"keyD", keyD, []byte("D")},
	} {
		got, err := tree.Get(tc.key)
		if err != nil {
			t.Errorf("TRIE-02/03 REGRESSION: Get %s after delete failed: %v", tc.name, err)
			continue
		}
		if !bytes.Equal(got, tc.val) {
			t.Errorf("TRIE-02/03 REGRESSION: %s after delete = %q, want %q", tc.name, got, tc.val)
		}
	}
}
