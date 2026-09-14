// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// --- Helpers ---

func makeAddr(byte0 byte) types.Address {
	var a types.Address
	a[0] = byte0
	return a
}

func makeAddrFromBytes(b ...byte) types.Address {
	var a types.Address
	for i, v := range b {
		if i >= 20 {
			break
		}
		a[i] = v
	}
	return a
}

func makeLeafHash(seed byte) types.Hash {
	return sha256.Sum256([]byte{seed})
}

// --- Tests ---

// TestSMT_EmptyTreeRoot verifies that a new SMT has the all-zero root.
func TestSMT_EmptyTreeRoot(t *testing.T) {
	smt := NewSparseMerkleTree()
	root := smt.Root()
	expected := smtZeroHashes[SparseMerkleTreeDepth]
	if root != expected {
		t.Errorf("empty tree root mismatch:\n  got  %x\n  want %x", root, expected)
	}
}

// TestSMT_InsertSingleLeaf verifies that inserting one leaf changes the root
// from the empty root and that the leaf is retrievable via Get.
func TestSMT_InsertSingleLeaf(t *testing.T) {
	smt := NewSparseMerkleTree()
	emptyRoot := smt.Root()

	addr := makeAddr(0x42)
	leaf := makeLeafHash(1)
	smt.Insert(addr, leaf)

	newRoot := smt.Root()
	if newRoot == emptyRoot {
		t.Fatal("root should change after insert")
	}

	got, ok := smt.Get(addr)
	if !ok {
		t.Fatal("Get should find inserted leaf")
	}
	if got != leaf {
		t.Errorf("leaf mismatch: got %x, want %x", got, leaf)
	}
}

// TestSMT_ProveVerify_Inclusion verifies that a proof for an existing leaf
// verifies against the current root.
func TestSMT_ProveVerify_Inclusion(t *testing.T) {
	smt := NewSparseMerkleTree()
	addr := makeAddr(0x42)
	leaf := makeLeafHash(1)
	smt.Insert(addr, leaf)

	root := smt.Root()
	proof, err := smt.Prove(addr)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if proof.LeafHash != leaf {
		t.Errorf("proof leaf hash mismatch: got %x, want %x", proof.LeafHash, leaf)
	}
	if len(proof.Siblings) != SparseMerkleTreeDepth {
		t.Fatalf("expected %d siblings, got %d", SparseMerkleTreeDepth, len(proof.Siblings))
	}

	if !VerifyMerkleProof(addr, proof, root) {
		t.Error("VerifyMerkleProof should return true for valid inclusion proof")
	}
}

// TestSMT_ProveVerify_NonInclusion verifies that a proof for a non-existent
// address uses the zero leaf hash and verifies against the root.
func TestSMT_ProveVerify_NonInclusion(t *testing.T) {
	smt := NewSparseMerkleTree()
	existing := makeAddr(0x42)
	smt.Insert(existing, makeLeafHash(1))

	root := smt.Root()

	// Prove a non-existent address.
	missing := makeAddr(0x99)
	proof, err := smt.Prove(missing)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if proof.LeafHash != smtZeroHashes[0] {
		t.Error("non-inclusion proof should have zero leaf hash")
	}

	// The proof should verify against the root with the zero leaf hash.
	if !VerifyMerkleProof(missing, proof, root) {
		t.Error("VerifyMerkleProof should return true for valid non-inclusion proof")
	}
}

// TestSMT_ProveVerify_EmptyTree verifies that a proof on a completely empty
// tree (all addresses absent) verifies against the empty root.
func TestSMT_ProveVerify_EmptyTree(t *testing.T) {
	smt := NewSparseMerkleTree()
	root := smt.Root()

	addr := makeAddr(0x01)
	proof, err := smt.Prove(addr)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if proof.LeafHash != smtZeroHashes[0] {
		t.Error("empty tree proof should have zero leaf hash")
	}
	if !VerifyMerkleProof(addr, proof, root) {
		t.Error("proof should verify against empty tree root")
	}
}

// TestSMT_UpdateLeaf verifies that updating an existing leaf changes the root
// and that the new proof verifies while the old proof fails.
func TestSMT_UpdateLeaf(t *testing.T) {
	smt := NewSparseMerkleTree()
	addr := makeAddr(0x42)

	leaf1 := makeLeafHash(1)
	smt.Insert(addr, leaf1)
	root1 := smt.Root()

	proof1, _ := smt.Prove(addr)
	if !VerifyMerkleProof(addr, proof1, root1) {
		t.Fatal("proof1 should verify against root1")
	}

	// Update the leaf.
	leaf2 := makeLeafHash(2)
	smt.Insert(addr, leaf2)
	root2 := smt.Root()

	if root2 == root1 {
		t.Fatal("root should change after leaf update")
	}

	// Old proof should NOT verify against new root.
	if VerifyMerkleProof(addr, proof1, root2) {
		t.Error("old proof should NOT verify against new root after update")
	}

	// New proof should verify against new root.
	proof2, _ := smt.Prove(addr)
	if !VerifyMerkleProof(addr, proof2, root2) {
		t.Error("new proof should verify against new root")
	}
}

// TestSMT_InsertOrderDeterminism verifies that inserting the same set of
// leaves in different orders produces the same root. This is the core
// correctness property that was broken by Bugs 1-3.
func TestSMT_InsertOrderDeterminism(t *testing.T) {
	leaves := map[types.Address]types.Hash{
		makeAddr(0x01): makeLeafHash(1),
		makeAddr(0x02): makeLeafHash(2),
		makeAddr(0x03): makeLeafHash(3),
		makeAddr(0x04): makeLeafHash(4),
		makeAddr(0x05): makeLeafHash(5),
	}

	// Build a canonical root using BatchInsert (which iterates the map once).
	smtCanonical := NewSparseMerkleTree()
	smtCanonical.BatchInsert(leaves)
	rootCanonical := smtCanonical.Root()

	// Build the tree multiple times via individual Insert in different orders.
	// Go map iteration is randomized, so running this in a loop exercises
	// different insertion orders automatically.
	for i := 0; i < 20; i++ {
		smt := NewSparseMerkleTree()
		for addr, leaf := range leaves {
			smt.Insert(addr, leaf)
		}
		root := smt.Root()
		if root != rootCanonical {
			t.Fatalf("iteration %d: root mismatch (non-deterministic):\n  got  %x\n  want %x", i, root, rootCanonical)
		}
	}
}

// TestSMT_BatchInsertEquivalentToIndividual verifies that BatchInsert produces
// the same root as calling Insert for each entry individually.
func TestSMT_BatchInsertEquivalentToIndividual(t *testing.T) {
	leaves := map[types.Address]types.Hash{
		makeAddr(0x10): makeLeafHash(0x10),
		makeAddr(0x20): makeLeafHash(0x20),
		makeAddr(0x30): makeLeafHash(0x30),
	}

	smtBatch := NewSparseMerkleTree()
	smtBatch.BatchInsert(leaves)

	smtIndividual := NewSparseMerkleTree()
	for addr, leaf := range leaves {
		smtIndividual.Insert(addr, leaf)
	}

	if smtBatch.Root() != smtIndividual.Root() {
		t.Errorf("BatchInsert root != Individual Insert root:\n  batch     %x\n  individual %x",
			smtBatch.Root(), smtIndividual.Root())
	}
}

// TestSMT_Sparsity verifies that inserting leaves at addresses that diverge
// at different bit positions produces correct proofs. This tests the
// progressive path truncation invariant.
func TestSMT_Sparsity(t *testing.T) {
	// Addresses that diverge at different bit positions:
	//   addrA: 0x80... → bit 0 (MSB of byte 0) = 1
	//   addrB: 0x40... → bit 1 = 1, bit 0 = 0
	//   addrC: 0x01... → bit 7 (LSB of byte 0) = 1
	//   addrD: 0x00...0x01 at byte 19 → diverges at bit 159 (LSB of last byte)
	leaves := map[types.Address]types.Hash{
		makeAddrFromBytes(0x80): makeLeafHash(0xA),
		makeAddrFromBytes(0x40): makeLeafHash(0xB),
		makeAddrFromBytes(0x01): makeLeafHash(0xC),
		makeAddrFromBytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01): makeLeafHash(0xD),
	}

	smt := NewSparseMerkleTree()
	smt.BatchInsert(leaves)
	root := smt.Root()

	if root == smtZeroHashes[SparseMerkleTreeDepth] {
		t.Fatal("root should differ from empty root after inserts")
	}

	// Verify inclusion proofs for all leaves.
	for addr, expectedLeaf := range leaves {
		proof, err := smt.Prove(addr)
		if err != nil {
			t.Fatalf("Prove(%x) failed: %v", addr, err)
		}
		if proof.LeafHash != expectedLeaf {
			t.Errorf("leaf hash mismatch for %x", addr)
		}
		if !VerifyMerkleProof(addr, proof, root) {
			t.Errorf("inclusion proof failed for %x", addr)
		}
	}
}

// TestSMT_Clone verifies that Clone produces an independent tree with the
// same root and that mutations to the clone don't affect the original.
func TestSMT_Clone(t *testing.T) {
	smt := NewSparseMerkleTree()
	addr1 := makeAddr(0x01)
	smt.Insert(addr1, makeLeafHash(1))
	root1 := smt.Root()

	clone := smt.Clone()
	if clone.Root() != root1 {
		t.Fatal("clone root should match original root")
	}

	// Mutate the clone.
	addr2 := makeAddr(0x02)
	clone.Insert(addr2, makeLeafHash(2))
	root2Clone := clone.Root()

	// Original should be unchanged.
	if smt.Root() != root1 {
		t.Error("original root should not change after clone mutation")
	}
	if smt.Root() == root2Clone {
		t.Error("original root should differ from clone's mutated root")
	}

	// Verify the original doesn't have addr2.
	if _, ok := smt.Get(addr2); ok {
		t.Error("original should not have addr2 inserted into clone")
	}
}

// cloneProof returns a deep copy of a MerkleProof (including the Siblings slice).
func cloneProof(p *MerkleProof) *MerkleProof {
	cp := &MerkleProof{
		LeafHash: p.LeafHash,
		Siblings: make([]types.Hash, len(p.Siblings)),
	}
	copy(cp.Siblings, p.Siblings)
	return cp
}

// TestSMT_TamperedProof verifies that a tampered proof is rejected.
func TestSMT_TamperedProof(t *testing.T) {
	smt := NewSparseMerkleTree()
	addr := makeAddr(0x42)
	leaf := makeLeafHash(1)
	smt.Insert(addr, leaf)
	root := smt.Root()

	proof, _ := smt.Prove(addr)

	// Tamper with a sibling hash.
	tampered := cloneProof(proof)
	tampered.Siblings[0] = makeLeafHash(0xFF)
	if VerifyMerkleProof(addr, tampered, root) {
		t.Error("tampered sibling[0] should fail verification")
	}

	// Tamper with the leaf hash.
	tampered2 := cloneProof(proof)
	tampered2.LeafHash = makeLeafHash(0xEE)
	if VerifyMerkleProof(addr, tampered2, root) {
		t.Error("tampered leaf hash should fail verification")
	}

	// Tamper with a middle sibling.
	tampered3 := cloneProof(proof)
	tampered3.Siblings[80] = makeLeafHash(0xDD)
	if VerifyMerkleProof(addr, tampered3, root) {
		t.Error("tampered sibling[80] should fail verification")
	}

	// Original proof should still verify (was not mutated by tampering).
	if !VerifyMerkleProof(addr, proof, root) {
		t.Error("original proof should still verify after tampering copies")
	}
}

// TestSMT_ProofWrongAddress verifies that a proof generated for address A
// does NOT verify for address B (even if both are in the tree).
func TestSMT_ProofWrongAddress(t *testing.T) {
	smt := NewSparseMerkleTree()
	addrA := makeAddr(0x01)
	addrB := makeAddr(0x02)
	smt.Insert(addrA, makeLeafHash(1))
	smt.Insert(addrB, makeLeafHash(2))
	root := smt.Root()

	proofA, _ := smt.Prove(addrA)

	// proofA should NOT verify for addrB.
	if VerifyMerkleProof(addrB, proofA, root) {
		t.Error("proof for addrA should NOT verify for addrB")
	}
}

// TestSMT_VerifyMerkleProof_NilAndMalformed verifies defensive checks.
func TestSMT_VerifyMerkleProof_NilAndMalformed(t *testing.T) {
	addr := makeAddr(0x01)
	root := smtZeroHashes[SparseMerkleTreeDepth]

	// Nil proof.
	if VerifyMerkleProof(addr, nil, root) {
		t.Error("nil proof should fail")
	}

	// Wrong sibling count.
	short := &MerkleProof{
		LeafHash: smtZeroHashes[0],
		Siblings: make([]types.Hash, 10), // not 160
	}
	if VerifyMerkleProof(addr, short, root) {
		t.Error("proof with wrong sibling count should fail")
	}
}

// TestSMT_ComputeAccountLeafHash verifies that the leaf hash is deterministic
// and changes when account data changes.
func TestSMT_ComputeAccountLeafHash(t *testing.T) {
	addr := makeAddr(0x42)

	acc1 := &RollupAccount{
		Nonce:   1,
		Balance: big.NewInt(100),
	}
	hash1 := ComputeAccountLeafHash(addr, acc1)

	acc2 := &RollupAccount{
		Nonce:   2, // different nonce
		Balance: big.NewInt(100),
	}
	hash2 := ComputeAccountLeafHash(addr, acc2)

	if hash1 == hash2 {
		t.Error("leaf hash should change when nonce changes")
	}

	// Same account data → same hash.
	hash1Again := ComputeAccountLeafHash(addr, acc1)
	if hash1 != hash1Again {
		t.Error("leaf hash should be deterministic for same account data")
	}

	// Nil account → zero leaf hash.
	if ComputeAccountLeafHash(addr, nil) != smtZeroHashes[0] {
		t.Error("nil account should produce zero leaf hash")
	}
}

// TestSMT_Size verifies that Size returns the number of stored nodes.
func TestSMT_Size(t *testing.T) {
	smt := NewSparseMerkleTree()
	if smt.Size() != 0 {
		t.Errorf("empty tree size should be 0, got %d", smt.Size())
	}

	smt.Insert(makeAddr(0x01), makeLeafHash(1))
	// After one insert: 1 leaf + 160 ancestors = 161 nodes.
	if smt.Size() != SparseMerkleTreeDepth+1 {
		t.Errorf("after 1 insert, size should be %d, got %d", SparseMerkleTreeDepth+1, smt.Size())
	}

	// Second insert shares some ancestors, so the increase is less than 161.
	sizeAfter1 := smt.Size()
	smt.Insert(makeAddr(0x02), makeLeafHash(2))
	sizeAfter2 := smt.Size()
	if sizeAfter2 <= sizeAfter1 {
		t.Errorf("size should increase after second insert: %d → %d", sizeAfter1, sizeAfter2)
	}
	if sizeAfter2 > 2*(SparseMerkleTreeDepth+1) {
		t.Errorf("size should not exceed 2*(depth+1) after 2 inserts, got %d", sizeAfter2)
	}
}

// TestSMT_LargeBatch verifies correctness with a larger number of leaves,
// exercising many branch divergences.
func TestSMT_LargeBatch(t *testing.T) {
	const n = 100
	leaves := make(map[types.Address]types.Hash, n)
	for i := 0; i < n; i++ {
		addr := makeAddr(byte(i))
		leaves[addr] = makeLeafHash(byte(i))
	}

	smt := NewSparseMerkleTree()
	smt.BatchInsert(leaves)
	root := smt.Root()

	if root == smtZeroHashes[SparseMerkleTreeDepth] {
		t.Fatal("root should differ from empty root")
	}

	// Verify all inclusion proofs.
	for addr, expectedLeaf := range leaves {
		proof, err := smt.Prove(addr)
		if err != nil {
			t.Fatalf("Prove(%x) failed: %v", addr, err)
		}
		if proof.LeafHash != expectedLeaf {
			t.Errorf("leaf mismatch for %x", addr)
		}
		if !VerifyMerkleProof(addr, proof, root) {
			t.Errorf("inclusion proof failed for %x", addr)
		}
	}

	// Verify a non-inclusion proof for an address not in the batch.
	missing := makeAddr(0xFF)
	proof, _ := smt.Prove(missing)
	if proof.LeafHash != smtZeroHashes[0] {
		t.Error("missing address should have zero leaf hash")
	}
	if !VerifyMerkleProof(missing, proof, root) {
		t.Error("non-inclusion proof should verify against root")
	}
}

// TestSMT_ComputeWithdrawalLeafHash verifies that the withdrawal leaf hash
// is deterministic and changes when any input field (withdrawer, amount,
// txIndex) changes. This is the Go-side guarantee for BRDG- the QASM
// L1Bridge contract now computes this hash in-contract, binding the amount
// into the Merkle proof's leaf preimage.
//
// BRDG-FIX (2026-07-16)
func TestSMT_ComputeWithdrawalLeafHash(t *testing.T) {
	withdrawer := types.Address{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14}
	amount := big.NewInt(1000)
	txIndex := 3

	// 1. Deterministic: same inputs → same hash.
	hash1 := ComputeWithdrawalLeafHash(withdrawer, amount, txIndex)
	hash1Again := ComputeWithdrawalLeafHash(withdrawer, amount, txIndex)
	if hash1 != hash1Again {
		t.Fatal("leaf hash should be deterministic for same inputs")
	}

	// 2. Amount change → different hash (core BRDG- property).
	hashDiffAmount := ComputeWithdrawalLeafHash(withdrawer, big.NewInt(999), txIndex)
	if hash1 == hashDiffAmount {
		t.Error("leaf hash should change when amount changes (BRDG-)")
	}

	// 3. Withdrawer change → different hash.
	otherWithdrawer := withdrawer
	otherWithdrawer[19] = 0xff
	hashDiffWithdrawer := ComputeWithdrawalLeafHash(otherWithdrawer, amount, txIndex)
	if hash1 == hashDiffWithdrawer {
		t.Error("leaf hash should change when withdrawer changes")
	}

	// 4. txIndex change → different hash.
	hashDiffTxIndex := ComputeWithdrawalLeafHash(withdrawer, amount, 4)
	if hash1 == hashDiffTxIndex {
		t.Error("leaf hash should change when txIndex changes")
	}

	// 5. Verify against manual SHA256(withdrawer[20] || amount[32] || txIndex[4]).
	h := sha256.New()
	h.Write(withdrawer[:])
	var amountBuf [32]byte
	amountBytes := amount.Bytes()
	copy(amountBuf[32-len(amountBytes):], amountBytes)
	h.Write(amountBuf[:])
	var idxBuf [4]byte
	idxBuf[0] = 0
	idxBuf[1] = 0
	idxBuf[2] = 0
	idxBuf[3] = byte(txIndex)
	h.Write(idxBuf[:])
	var expected types.Hash
	copy(expected[:], h.Sum(nil))
	if hash1 != expected {
		t.Errorf("leaf hash mismatch: got %x, want %x", hash1, expected)
	}
}
