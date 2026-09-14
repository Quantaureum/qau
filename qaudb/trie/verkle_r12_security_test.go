// Quantaureum Node source, version 1.0.0.
// Package trie - security tests for TRIE-R12-001/002.
//
// These tests verify that forged Verkle proofs are rejected by the
// rewritten Verify() implementation. The previous verifier had three
// fundamental flaws that allowed forgery:
//
//  1. Path field was completely ignored — an attacker could supply
//     arbitrary Path entries as long as the bottom-up recompute
//     produced the root.
//  2. Extension node Stem prefix was never verified against the query
//     key — an attacker could traverse a wrong path and still produce
//     a valid-looking proof.
//  3. verifyExclusion started from types.Hash{} and recomputed upward,
//     which made it impossible to distinguish "key absent because slot
//     is empty" from "key absent because slot holds a different key".
//     An attacker could forge an exclusion proof for a key that
//     actually exists by claiming the slot was empty.
//
// The new implementation enforces:
//   - len(Path) == len(Siblings) + 1
//   - Path[0] == root
//   - Each level's recomputed parent matches Path[i]
//   - Extension Stem prefix matches query key's stem
//   - ExclusionEvidence cryptographically binds Path[last] to the
//     fork-point node data
package trie

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/quantaureum/qau/types"
)

// helper: make a 32-byte key with first byte set to b.
func makeKey32(firstByte byte) []byte {
	k := make([]byte, 32)
	k[0] = firstByte
	return k
}

// TestTRIE_R12_001_ForgedInclusion_ProofWithWrongValue verifies that an
// attacker cannot forge an inclusion proof by claiming a different
// Value for an existing key. The verifier recomputes leafHash from
// Key+Value and compares to Path[last], so any Value mismatch is
// detected.
func TestTRIE_R12_001_ForgedInclusion_ProofWithWrongValue(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	key := makeKey32(0x42)
	value := []byte("real_value")
	tree.Put(key, value)

	proof, err := tree.Prove(key)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate inclusion proof failed verification")
	}

	// Tamper with Value — verifier should detect leafHash mismatch.
	forged := *proof
	forged.Value = []byte("forged_value")
	if forged.Verify(tree.Root()) {
		t.Error("forged inclusion proof with wrong Value was accepted")
	}
}

// TestTRIE_R12_001_ForgedInclusion_TamperedPath verifies that an
// attacker cannot tamper with Path entries. Each Path[i] is verified
// by recomputing the parent from Path[i+1] + Siblings[i], so any
// tampering is detected.
func TestTRIE_R12_001_ForgedInclusion_TamperedPath(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	// Multiple keys to force creation of InternalNode levels.
	for i := 0; i < 5; i++ {
		key := makeKey32(byte(i))
		tree.Put(key, []byte("value"))
	}

	targetKey := makeKey32(0x02)
	proof, err := tree.Prove(targetKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate inclusion proof failed verification")
	}

	// Tamper with a middle Path entry — verifier should detect.
	forged := *proof
	forged.Path = make([]types.Hash, len(proof.Path))
	copy(forged.Path, proof.Path)
	forged.Path[0] = types.Hash{} // Wrong root hash entry
	if forged.Verify(tree.Root()) {
		t.Error("forged inclusion proof with tampered Path[0] was accepted")
	}
}

// TestTRIE_R12_001_ForgedInclusion_TamperedLastPath verifies that
// tampering with Path[last] (the leaf hash entry) is detected.
func TestTRIE_R12_001_ForgedInclusion_TamperedLastPath(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	for i := 0; i < 5; i++ {
		key := makeKey32(byte(i))
		tree.Put(key, []byte("value"))
	}

	targetKey := makeKey32(0x02)
	proof, err := tree.Prove(targetKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate inclusion proof failed verification")
	}

	// Tamper with Path[last] (leaf hash).
	forged := *proof
	forged.Path = make([]types.Hash, len(proof.Path))
	copy(forged.Path, proof.Path)
	forged.Path[len(forged.Path)-1] = types.Hash{}
	if forged.Verify(tree.Root()) {
		t.Error("forged inclusion proof with tampered Path[last] was accepted")
	}
}

// TestTRIE_R12_001_ForgedInclusion_WrongRoot verifies that a proof
// generated against one root is not accepted against a different root.
func TestTRIE_R12_001_ForgedInclusion_WrongRoot(t *testing.T) {
	tree1 := NewVerkleTree(MaxTreeDepth)
	tree2 := NewVerkleTree(MaxTreeDepth)

	key := makeKey32(0x42)
	tree1.Put(key, []byte("value1"))
	tree2.Put(key, []byte("value2"))

	proof, _ := tree1.Prove(key)
	// Proof from tree1 should NOT verify against tree2's root.
	if proof.Verify(tree2.Root()) {
		t.Error("proof from tree1 was accepted against tree2's root (different root)")
	}
}

// TestTRIE_R12_001_ForgedInclusion_TamperedSiblings verifies that
// tampering with sibling entries is detected.
func TestTRIE_R12_001_ForgedInclusion_TamperedSiblings(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	for i := 0; i < 5; i++ {
		key := makeKey32(byte(i))
		tree.Put(key, []byte("value"))
	}

	targetKey := makeKey32(0x02)
	proof, err := tree.Prove(targetKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate inclusion proof failed verification")
	}

	// Tamper with first sibling at level 0.
	forged := *proof
	forged.Siblings = make([][]SiblingWithIdx, len(proof.Siblings))
	for i := range proof.Siblings {
		forged.Siblings[i] = make([]SiblingWithIdx, len(proof.Siblings[i]))
		copy(forged.Siblings[i], proof.Siblings[i])
	}
	if len(forged.Siblings[0]) > 0 {
		// Flip a byte in the first sibling hash.
		forged.Siblings[0][0].Hash[0] ^= 0xFF
		if forged.Verify(tree.Root()) {
			t.Error("forged inclusion proof with tampered sibling hash was accepted")
		}
	}
}

// TestTRIE_R12_001_ForgedInclusion_WrongKey verifies that a proof
// generated for key A is not accepted for key B (even if both exist
// in the tree). The verifier recomputes stem from p.Key and uses it
// for path index derivation, so a different key produces a different
// path and the recomputed parent won't match Path[i].
func TestTRIE_R12_001_ForgedInclusion_WrongKey(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	keyA := makeKey32(0x01)
	keyB := makeKey32(0x02)
	tree.Put(keyA, []byte("valueA"))
	tree.Put(keyB, []byte("valueB"))

	proofA, _ := tree.Prove(keyA)
	// Use proofA's data but claim it's for keyB.
	forged := *proofA
	forged.Key = keyB
	forged.Value = []byte("valueB")
	if forged.Verify(tree.Root()) {
		t.Error("proof for keyA was accepted when Key was changed to keyB")
	}
}

// TestTRIE_R12_001_StructuralInvariant_PathSiblingsMismatch verifies
// that validateStructure rejects proofs where len(Path) != len(Siblings) + 1.
func TestTRIE_R12_001_StructuralInvariant_PathSiblingsMismatch(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	for i := 0; i < 5; i++ {
		key := makeKey32(byte(i))
		tree.Put(key, []byte("value"))
	}

	targetKey := makeKey32(0x02)
	proof, err := tree.Prove(targetKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate inclusion proof failed verification")
	}

	// Truncate Path by one entry — should fail structural check.
	forged := *proof
	forged.Path = proof.Path[:len(proof.Path)-1]
	if forged.Verify(tree.Root()) {
		t.Error("proof with len(Path) == len(Siblings) was accepted (should require len(Path) == len(Siblings)+1)")
	}
}

// TestTRIE_R12_001_StructuralInvariant_ExtensionStemsMismatch verifies
// that validateStructure rejects proofs where len(ExtensionStems) !=
// len(Siblings).
func TestTRIE_R12_001_StructuralInvariant_ExtensionStemsMismatch(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	for i := 0; i < 5; i++ {
		key := makeKey32(byte(i))
		tree.Put(key, []byte("value"))
	}

	targetKey := makeKey32(0x02)
	proof, err := tree.Prove(targetKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate inclusion proof failed verification")
	}

	// Add a bogus ExtensionStems entry — should fail structural check.
	forged := *proof
	forged.ExtensionStems = append(proof.ExtensionStems, ExtensionLevelData{StemLen: 1})
	if forged.Verify(tree.Root()) {
		t.Error("proof with len(ExtensionStems) != len(Siblings) was accepted")
	}
}

// TestTRIE_R12_001_StructuralInvariant_ExtensionWithSiblings verifies
// that an Extension level (StemLen > 0) cannot have sibling entries.
func TestTRIE_R12_001_StructuralInvariant_ExtensionWithSiblings(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	for i := 0; i < 5; i++ {
		key := makeKey32(byte(i))
		tree.Put(key, []byte("value"))
	}

	targetKey := makeKey32(0x02)
	proof, err := tree.Prove(targetKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate inclusion proof failed verification")
	}

	// Find an Internal level (StemLen == 0) and convert it to Extension
	// (StemLen > 0) while keeping its siblings. validateStructure should
	// reject this combination.
	if len(proof.ExtensionStems) > 0 && len(proof.Siblings) > 0 && len(proof.Siblings[0]) > 0 {
		forged := *proof
		forged.ExtensionStems = make([]ExtensionLevelData, len(proof.ExtensionStems))
		copy(forged.ExtensionStems, proof.ExtensionStems)
		forged.ExtensionStems[0] = ExtensionLevelData{StemLen: 1} // Mark as Extension
		if forged.Verify(tree.Root()) {
			t.Error("Extension level (StemLen>0) with non-empty siblings was accepted")
		}
	}
}

// TestTRIE_R12_002_LegitimateExclusion_EmptySlot verifies that a
// legitimate exclusion proof for an empty slot passes verification.
func TestTRIE_R12_002_LegitimateExclusion_EmptySlot(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	// Insert keys 0x00, 0x01, 0x03 (skip 0x02 to create an empty slot
	// at the InternalNode level).
	tree.Put(makeKey32(0x00), []byte("v0"))
	tree.Put(makeKey32(0x01), []byte("v1"))
	tree.Put(makeKey32(0x03), []byte("v3"))

	// Prove that key 0x02 is absent.
	proof, err := tree.Prove(makeKey32(0x02))
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.IsExclusion {
		t.Fatal("expected exclusion proof for absent key")
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate exclusion proof failed verification")
	}
	if proof.ExclusionEvidence == nil {
		t.Fatal("ExclusionEvidence should be set for exclusion proof")
	}
	if proof.ExclusionEvidence.Type != ExclusionTypeEmptySlot {
		t.Errorf("expected ExclusionTypeEmptySlot, got %v", proof.ExclusionEvidence.Type)
	}
}

// TestTRIE_R12_002_LegitimateExclusion_LeafMismatch verifies that a
// legitimate exclusion proof for a key whose path leads to a leaf
// with a different key passes verification.
func TestTRIE_R12_002_LegitimateExclusion_LeafMismatch(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	// Insert one key (root becomes a LeafNode directly).
	existingKey := makeKey32(0x42)
	tree.Put(existingKey, []byte("value"))

	// Prove that a different key (different first byte) is absent.
	// The proof should be LeafMismatch (root is leaf with wrong key).
	absentKey := makeKey32(0x99)
	proof, err := tree.Prove(absentKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.IsExclusion {
		t.Fatal("expected exclusion proof for absent key")
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate exclusion proof failed verification")
	}
	if proof.ExclusionEvidence == nil {
		t.Fatal("ExclusionEvidence should be set for exclusion proof")
	}
	if proof.ExclusionEvidence.Type != ExclusionTypeLeafMismatch {
		t.Errorf("expected ExclusionTypeLeafMismatch, got %v", proof.ExclusionEvidence.Type)
	}
}

// TestTRIE_R12_002_ForgedExclusion_ClaimsEmptyForExistingKey verifies
// that an attacker cannot forge an exclusion proof for an EXISTING key
// by claiming ExclusionTypeEmptySlot. The previous verifier would
// accept this because it only checked that recomputeParent(zero, sibs,
// idx) == root, which holds for any path — including paths to existing
// keys. The new verifier rejects this because Path[last] must be zero
// for EmptySlot, but a legitimate proof's Path[last] for an existing
// key is the leaf hash (non-zero).
func TestTRIE_R12_002_ForgedExclusion_ClaimsEmptyForExistingKey(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	for i := 0; i < 5; i++ {
		key := makeKey32(byte(i))
		tree.Put(key, []byte("value"))
	}

	// Pick an EXISTING key (0x02) and try to forge an exclusion proof.
	existingKey := makeKey32(0x02)
	legitProof, err := tree.Prove(existingKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if legitProof.IsExclusion {
		t.Fatal("expected inclusion proof for existing key")
	}

	// Forge: claim the key is absent via EmptySlot.
	forged := &VerkleProof{
		Key:  existingKey,
		Path: append([]types.Hash{}, legitProof.Path[:len(legitProof.Path)-1]...), // Drop leaf hash
		Siblings: func() [][]SiblingWithIdx {
			s := make([][]SiblingWithIdx, len(legitProof.Siblings))
			for i := range legitProof.Siblings {
				s[i] = make([]SiblingWithIdx, len(legitProof.Siblings[i]))
				copy(s[i], legitProof.Siblings[i])
			}
			return s
		}(),
		ExtensionStems: append([]ExtensionLevelData{}, legitProof.ExtensionStems...),
		IsExclusion:    true,
		ExclusionEvidence: &ExclusionEvidence{
			Type: ExclusionTypeEmptySlot,
		},
	}
	// Append zero hash as Path[last] to mimic empty slot.
	forged.Path = append(forged.Path, types.Hash{})

	if forged.Verify(tree.Root()) {
		t.Error("forged exclusion proof for EXISTING key (EmptySlot) was accepted")
	}
}

// TestTRIE_R12_002_ForgedExclusion_LeafMismatchWithMatchingKey verifies
// that an attacker cannot forge a LeafMismatch exclusion for a key
// that actually exists by lying about LeafKey. The verifier decodes
// EncodedLeaf and checks leaf.Key != query key — if the encoded leaf's
// key equals the query key, the proof is rejected as fraudulent.
func TestTRIE_R12_002_ForgedExclusion_LeafMismatchWithMatchingKey(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	existingKey := makeKey32(0x42)
	tree.Put(existingKey, []byte("real_value"))

	// Get the legitimate INCLUSION proof (which carries the leaf).
	legitProof, err := tree.Prove(existingKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if legitProof.IsExclusion {
		t.Fatal("expected inclusion proof for existing key")
	}

	// Forge: take the legitimate leaf encoding and claim it as a
	// LeafMismatch exclusion for the SAME key.
	leafHash := legitProof.Path[len(legitProof.Path)-1]
	forged := &VerkleProof{
		Key:         existingKey,
		Path:        []types.Hash{leafHash}, // root == leaf for single-leaf tree
		Siblings:    [][]SiblingWithIdx{},
		IsExclusion: true,
		ExclusionEvidence: &ExclusionEvidence{
			Type: ExclusionTypeLeafMismatch,
			// Use the real leaf encoding (whose Key == existingKey).
			EncodedLeaf: []byte{NodeTypeLeaf, 0, 0, 0, 32},
		},
	}
	// Properly encode a leaf with the existing key.
	leaf := NewLeafNode(existingKey, []byte("real_value"))
	forged.ExclusionEvidence.EncodedLeaf = leaf.Encode()

	if forged.Verify(tree.Root()) {
		t.Error("forged LeafMismatch exclusion for EXISTING key was accepted")
	}
}

// TestTRIE_R12_002_ForgedExclusion_TamperedEncodedLeaf verifies that
// tampering with EncodedLeaf bytes is detected (the recomputed leaf
// hash won't match Path[last]).
func TestTRIE_R12_002_ForgedExclusion_TamperedEncodedLeaf(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	// Insert one key (root becomes a LeafNode directly).
	existingKey := makeKey32(0x42)
	tree.Put(existingKey, []byte("value"))

	// Prove that a different key is absent.
	absentKey := makeKey32(0x99)
	proof, err := tree.Prove(absentKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.IsExclusion {
		t.Fatal("expected exclusion proof")
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate exclusion proof failed verification")
	}
	if proof.ExclusionEvidence == nil || proof.ExclusionEvidence.Type != ExclusionTypeLeafMismatch {
		t.Fatalf("expected LeafMismatch evidence, got %+v", proof.ExclusionEvidence)
	}

	// Tamper with EncodedLeaf — verifier should detect leaf.Hash() mismatch.
	forged := *proof
	tamperedLeaf := append([]byte(nil), proof.ExclusionEvidence.EncodedLeaf...)
	tamperedLeaf[len(tamperedLeaf)-1] ^= 0xFF // Flip last byte (part of value)
	forged.ExclusionEvidence = &ExclusionEvidence{
		Type:        ExclusionTypeLeafMismatch,
		EncodedLeaf: tamperedLeaf,
	}
	if forged.Verify(tree.Root()) {
		t.Error("forged exclusion with tampered EncodedLeaf was accepted")
	}
}

// TestTRIE_R12_002_ForgedExclusion_NoEvidence verifies that an
// exclusion proof without ExclusionEvidence is rejected (fail-closed).
func TestTRIE_R12_002_ForgedExclusion_NoEvidence(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	for i := 0; i < 5; i++ {
		key := makeKey32(byte(i))
		tree.Put(key, []byte("value"))
	}

	// Get legitimate exclusion proof, then strip the evidence.
	legitProof, err := tree.Prove(makeKey32(0x99))
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !legitProof.Verify(tree.Root()) {
		t.Fatal("legitimate exclusion proof failed verification")
	}

	forged := *legitProof
	forged.ExclusionEvidence = nil
	if forged.Verify(tree.Root()) {
		t.Error("exclusion proof with nil ExclusionEvidence was accepted (should fail-closed)")
	}
}

// TestTRIE_R12_002_ForgedExclusion_UnknownType verifies that an
// unknown ExclusionType value is rejected.
func TestTRIE_R12_002_ForgedExclusion_UnknownType(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	for i := 0; i < 5; i++ {
		key := makeKey32(byte(i))
		tree.Put(key, []byte("value"))
	}

	legitProof, err := tree.Prove(makeKey32(0x99))
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !legitProof.Verify(tree.Root()) {
		t.Fatal("legitimate exclusion proof failed verification")
	}

	forged := *legitProof
	forged.ExclusionEvidence = &ExclusionEvidence{
		Type: ExclusionType(0xFF), // Unknown type
	}
	if forged.Verify(tree.Root()) {
		t.Error("exclusion proof with unknown ExclusionType was accepted")
	}
}

// TestTRIE_R12_001_ExtensionStemPrefixMatch verifies that when a tree
// contains an Extension node, the verifier checks the Stem prefix
// matches the query key. A proof generated for a key whose stem
// DOESN'T match the Extension's Stem must fail.
func TestTRIE_R12_001_ExtensionStemPrefixMatch(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// Insert two keys that share a long stem prefix to force creation
	// of an ExtensionNode. Use 32-byte keys whose first 30 bytes are
	// identical.
	keyA := make([]byte, 32)
	keyA[0] = 0xAA
	keyA[29] = 0x01
	keyA[30] = 0xAA
	keyA[31] = 0xAA

	keyB := make([]byte, 32)
	keyB[0] = 0xAA
	keyB[29] = 0x02
	keyB[30] = 0xBB
	keyB[31] = 0xBB

	tree.Put(keyA, []byte("valueA"))
	tree.Put(keyB, []byte("valueB"))

	// Both keys should produce verifiable proofs.
	proofA, _ := tree.Prove(keyA)
	if !proofA.Verify(tree.Root()) {
		t.Fatal("proof for keyA failed verification")
	}
	proofB, _ := tree.Prove(keyB)
	if !proofB.Verify(tree.Root()) {
		t.Fatal("proof for keyB failed verification")
	}

	// Forge: take proofA and change its Key to something that doesn't
	// share the Extension's Stem prefix. The Extension level check
	// (bytes.Equal(stem[depth:depth+ext.StemLen], ext.Stem[:ext.StemLen]))
	// should fail.
	forged := *proofA
	forged.Key = make([]byte, 32)
	forged.Key[0] = 0xBB // Different first byte — different stem
	if forged.Verify(tree.Root()) {
		t.Error("proof with mismatched Extension Stem prefix was accepted")
	}
}

// TestTRIE_R12_002_ForgedExclusion_ExtensionMismatchWithMatchingStem
// verifies that an attacker cannot forge an ExtensionMismatch
// exclusion for a key whose stem actually matches the Extension's
// Stem. The verifier checks that the Stem does NOT prefix-match the
// query key's stem at the fork depth — if it does match, the proof
// is rejected as fraudulent.
func TestTRIE_R12_002_ForgedExclusion_ExtensionMismatchWithMatchingStem(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// Insert two keys with shared prefix to create Extension.
	keyA := make([]byte, 32)
	keyA[0] = 0xAA
	keyA[29] = 0x01
	tree.Put(keyA, []byte("valueA"))

	keyB := make([]byte, 32)
	keyB[0] = 0xAA
	keyB[29] = 0x02
	tree.Put(keyB, []byte("valueB"))

	// Find a key that triggers ExtensionMismatch (different prefix).
	absentKey := make([]byte, 32)
	absentKey[0] = 0xBB // Different first byte
	legitProof, err := tree.Prove(absentKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !legitProof.IsExclusion {
		t.Fatal("expected exclusion proof")
	}
	if !legitProof.Verify(tree.Root()) {
		t.Fatal("legitimate exclusion proof failed verification")
	}

	// If this is an ExtensionMismatch, try to forge: change the
	// query key to one that DOES match the Extension's Stem.
	if legitProof.ExclusionEvidence != nil &&
		legitProof.ExclusionEvidence.Type == ExclusionTypeExtensionMismatch {
		extStem := legitProof.ExclusionEvidence.ExtensionStem
		extStemLen := legitProof.ExclusionEvidence.ExtensionStemLen

		// Construct a key whose stem matches the Extension's stem.
		matchingKey := make([]byte, 32)
		copy(matchingKey[:extStemLen], extStem[:extStemLen])

		forged := *legitProof
		forged.Key = matchingKey
		if forged.Verify(tree.Root()) {
			t.Error("ExtensionMismatch proof for key matching Extension's Stem was accepted (should reject as fraudulent)")
		}
	}
}

// TestTRIE_R12_001_LargeDatasetRoundTrip verifies that the new
// verifier correctly handles proofs in a large tree with many keys
// (which creates multiple InternalNode levels and possibly ExtensionNodes).
func TestTRIE_R12_001_LargeDatasetRoundTrip(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	count := 200
	for i := 0; i < count; i++ {
		key := make([]byte, 32)
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		rand.Read(key[2:])
		tree.Put(key, []byte{byte(i)})
	}

	// Verify inclusion proofs for all keys.
	for i := 0; i < count; i++ {
		key := make([]byte, 32)
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		// We can't reproduce the random bytes, so skip keys we can't
		// reconstruct. Instead, just test a few keys we know.
		break
	}

	// Test inclusion for a key we know exists.
	knownKey := make([]byte, 32)
	knownKey[0] = 0x01
	knownKey[1] = 0x00
	// This key might not exist due to random bytes — use a deterministic
	// test instead.
	tree2 := NewVerkleTree(MaxTreeDepth)
	for i := 0; i < 100; i++ {
		key := make([]byte, 32)
		key[0] = byte(i)
		tree2.Put(key, []byte{byte(i)})
	}
	for i := 0; i < 100; i++ {
		key := make([]byte, 32)
		key[0] = byte(i)
		proof, err := tree2.Prove(key)
		if err != nil {
			t.Fatalf("Prove failed for key %d: %v", i, err)
		}
		if !proof.Verify(tree2.Root()) {
			t.Errorf("inclusion proof failed for key %d", i)
		}
	}
}

// TestTRIE_R12_002_LargeDatasetExclusion verifies exclusion proofs for
// absent keys in a large tree.
func TestTRIE_R12_002_LargeDatasetExclusion(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	// Insert keys 0-99 (skip 100-199).
	for i := 0; i < 100; i++ {
		key := make([]byte, 32)
		key[0] = byte(i)
		tree.Put(key, []byte{byte(i)})
	}

	// Prove absence of keys 100-150.
	for i := 100; i < 150; i++ {
		key := make([]byte, 32)
		key[0] = byte(i)
		proof, err := tree.Prove(key)
		if err != nil {
			t.Fatalf("Prove failed for absent key %d: %v", i, err)
		}
		if !proof.IsExclusion {
			t.Errorf("expected exclusion proof for absent key %d", i)
			continue
		}
		if !proof.Verify(tree.Root()) {
			t.Errorf("legitimate exclusion proof failed for absent key %d", i)
		}
		if proof.ExclusionEvidence == nil {
			t.Errorf("ExclusionEvidence nil for absent key %d", i)
		}
	}
}

// TestTRIE_R12_001_NilProof verifies that a nil proof is rejected.
func TestTRIE_R12_001_NilProof(t *testing.T) {
	var nilProof *VerkleProof
	if nilProof.Verify(types.Hash{}) {
		t.Error("nil proof was accepted")
	}
	if nilProof.Verify(types.Hash{0x01}) {
		t.Error("nil proof was accepted against non-zero root")
	}
}

// TestTRIE_R12_001_EmptyTreeExclusion verifies that an empty tree
// (rootNode == nil) produces a valid exclusion proof for any key.
func TestTRIE_R12_001_EmptyTreeExclusion(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	// Tree is empty — rootNode == nil.
	root := tree.Root()
	if root != (types.Hash{}) {
		t.Fatalf("expected zero root for empty tree, got %x", root)
	}

	proof, err := tree.Prove([]byte("any_key"))
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.IsExclusion {
		t.Fatal("expected exclusion proof for empty tree")
	}
	// Verify against zero root.
	if !proof.Verify(root) {
		t.Fatal("legitimate empty-tree exclusion proof failed verification")
	}
	// Verify against non-zero root — should fail (root mismatch).
	if proof.Verify(types.Hash{0x01}) {
		t.Error("empty-tree exclusion proof was accepted against non-zero root")
	}
}

// TestTRIE_R12_001_SingleLeafTreeInclusion verifies the simplest
// inclusion case: a tree with a single key (root == leaf).
func TestTRIE_R12_001_SingleLeafTreeInclusion(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	key := makeKey32(0x42)
	value := []byte("single_value")
	tree.Put(key, value)

	proof, err := tree.Prove(key)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if proof.IsExclusion {
		t.Fatal("expected inclusion proof for single-leaf tree")
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate single-leaf inclusion proof failed verification")
	}

	// Structural checks.
	if len(proof.Path) != 1 {
		t.Errorf("expected Path length 1 for single-leaf tree, got %d", len(proof.Path))
	}
	if len(proof.Siblings) != 0 {
		t.Errorf("expected Siblings length 0 for single-leaf tree, got %d", len(proof.Siblings))
	}
	if len(proof.ExtensionStems) != 0 {
		t.Errorf("expected ExtensionStems length 0 for single-leaf tree, got %d", len(proof.ExtensionStems))
	}
}

// TestTRIE_R12_001_SingleLeafTreeExclusion verifies exclusion proof
// for a single-leaf tree (key doesn't match the leaf).
func TestTRIE_R12_001_SingleLeafTreeExclusion(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	existingKey := makeKey32(0x42)
	tree.Put(existingKey, []byte("value"))

	// Prove absence of a key with a different first byte.
	absentKey := makeKey32(0x99)
	proof, err := tree.Prove(absentKey)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if !proof.IsExclusion {
		t.Fatal("expected exclusion proof")
	}
	if !proof.Verify(tree.Root()) {
		t.Fatal("legitimate single-leaf exclusion proof failed verification")
	}
	if proof.ExclusionEvidence == nil {
		t.Fatal("ExclusionEvidence should be set")
	}
	if proof.ExclusionEvidence.Type != ExclusionTypeLeafMismatch {
		t.Errorf("expected LeafMismatch, got %v", proof.ExclusionEvidence.Type)
	}
	// Decode EncodedLeaf and verify leaf key doesn't match query key.
	leaf, err := DecodeLeafNode(proof.ExclusionEvidence.EncodedLeaf)
	if err != nil {
		t.Fatalf("failed to decode EncodedLeaf: %v", err)
	}
	if bytes.Equal(leaf.Key, absentKey) {
		t.Error("decoded leaf key matches absent query key (proof would be fraudulent)")
	}
}

// TestTRIE_R12_002_ForgedInclusion_ClaimsExclusionForExistingKey verifies
// that an attacker cannot flip IsExclusion on an inclusion proof to
// forge an exclusion for an existing key. The verifier checks
// ExclusionEvidence, which would be nil for an inclusion proof.
func TestTRIE_R12_002_ForgedInclusion_ClaimsExclusionForExistingKey(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)
	key := makeKey32(0x42)
	tree.Put(key, []byte("value"))

	legitProof, err := tree.Prove(key)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if legitProof.IsExclusion {
		t.Fatal("expected inclusion proof")
	}

	// Forge: flip IsExclusion to true. ExclusionEvidence is nil
	// (inclusion proofs don't set it), so verifier should fail-closed.
	forged := *legitProof
	forged.IsExclusion = true
	if forged.Verify(tree.Root()) {
		t.Error("inclusion proof with IsExclusion flipped to true was accepted (should fail-closed on nil ExclusionEvidence)")
	}
}

// TestTRIE_R12_001_SuffixValueInclusion verifies that inclusion proofs
// for suffix-indexed entries (same 31-byte stem, different 32nd byte)
// work correctly.
func TestTRIE_R12_001_SuffixValueInclusion(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// Insert two keys with the same first 31 bytes but different 32nd
	// byte. These should be stored as suffix-indexed entries in a
	// single LeafNode.
	keyA := make([]byte, 32)
	keyA[0] = 0xAA
	keyA[31] = 0x01

	keyB := make([]byte, 32)
	keyB[0] = 0xAA
	keyB[31] = 0x02

	tree.Put(keyA, []byte("valueA"))
	tree.Put(keyB, []byte("valueB"))

	// Both should have verifiable inclusion proofs.
	proofA, _ := tree.Prove(keyA)
	if !proofA.Verify(tree.Root()) {
		t.Error("suffix-indexed inclusion proof A failed verification")
	}
	proofB, _ := tree.Prove(keyB)
	if !proofB.Verify(tree.Root()) {
		t.Error("suffix-indexed inclusion proof B failed verification")
	}

	// A different suffix (0x03) should be excluded.
	keyC := make([]byte, 32)
	keyC[0] = 0xAA
	keyC[31] = 0x03
	proofC, _ := tree.Prove(keyC)
	if !proofC.IsExclusion {
		t.Fatal("expected exclusion proof for absent suffix")
	}
	// Note: proofC might be LeafMismatch (existing leaf has same stem
	// but no matching suffix) — verifier should still accept it.
	if !proofC.Verify(tree.Root()) {
		t.Error("legitimate exclusion proof for absent suffix failed verification")
	}
}
