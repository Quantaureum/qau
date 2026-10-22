// Quantaureum Node source, version 1.0.0.
package light

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// F-11 (2026-10-21): baseline coverage for the light package's Merkle
// primitives — these back SPV inclusion proofs, so the verify path gets
// positive and negative vectors (tampered leaf, wrong index, wrong root,
// out-of-range index, oversized sibling lists, single-leaf blocks).

func makeTxHashes(n int) []types.Hash {
	hashes := make([]types.Hash, n)
	for i := range hashes {
		for j := range hashes[i] {
			hashes[i][j] = byte(i*31 + j + 1)
		}
	}
	return hashes
}

func TestBuildMerkleTreeEmpty(t *testing.T) {
	if got := BuildMerkleTree(nil); got != (types.Hash{}) {
		t.Fatalf("empty tree: got non-zero root %s", got.String())
	}
}

func TestBuildMerkleTreeSingleLeaf(t *testing.T) {
	tx := makeTxHashes(1)
	root := BuildMerkleTree(tx)
	if root == (types.Hash{}) {
		t.Fatal("single-leaf tree returned zero root")
	}
	// A single-leaf root must equal the domain-separated leaf hash itself.
	if root != hashLeaf(tx[0][:]) {
		t.Fatal("single-leaf root does not equal leaf hash")
	}
}

func TestMerkleProofRoundTrip(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 8, 13} {
		txs := makeTxHashes(n)
		root := BuildMerkleTree(txs)
		for i := 0; i < n; i++ {
			proof, err := GenerateMerkleProof(txs, i)
			if err != nil {
				t.Fatalf("n=%d index=%d: GenerateMerkleProof: %v", n, i, err)
			}
			if !VerifyMerkleProof(txs[i], root, *proof) {
				t.Fatalf("n=%d index=%d: valid proof rejected", n, i)
			}
		}
	}
}

func TestMerkleProofRejectsTamperedLeaf(t *testing.T) {
	txs := makeTxHashes(6)
	root := BuildMerkleTree(txs)
	proof, err := GenerateMerkleProof(txs, 2)
	if err != nil {
		t.Fatalf("GenerateMerkleProof: %v", err)
	}
	// A different leaf value at the same index must not verify.
	other := makeTxHashes(6)
	other[2] = types.Hash{0xde, 0xad, 0xbe, 0xef}
	if VerifyMerkleProof(other[2], root, *proof) {
		t.Fatal("proof verified against a different transaction hash")
	}
}
func TestMerkleProofRejectsWrongRoot(t *testing.T) {
	txs := makeTxHashes(6)
	root := BuildMerkleTree(txs)
	other := makeTxHashes(7)
	badRoot := BuildMerkleTree(other)
	proof, err := GenerateMerkleProof(txs, 0)
	if err != nil {
		t.Fatalf("GenerateMerkleProof: %v", err)
	}
	if VerifyMerkleProof(txs[0], badRoot, *proof) {
		t.Fatal("proof verified against the wrong root")
	}
	if !VerifyMerkleProof(txs[0], root, *proof) {
		t.Fatal("sanity: proof against the real root must verify")
	}
}

func TestMerkleProofRejectsIndexMismatch(t *testing.T) {
	txs := makeTxHashes(4)
	root := BuildMerkleTree(txs)
	proof, err := GenerateMerkleProof(txs, 0)
	if err != nil {
		t.Fatalf("GenerateMerkleProof: %v", err)
	}
	// Same leaf, same siblings, but claim a different leaf index.
	tampered := *proof
	tampered.LeafIndex = 1
	if VerifyMerkleProof(txs[0], root, tampered) {
		t.Fatal("proof verified with a swapped leaf index")
	}
}

func TestMerkleProofRejectsCraftedProofs(t *testing.T) {
	txs := makeTxHashes(4)
	root := BuildMerkleTree(txs)
	proof, err := GenerateMerkleProof(txs, 0)
	if err != nil {
		t.Fatalf("GenerateMerkleProof: %v", err)
	}

	if p := *proof; VerifyMerkleProof(txs[0], root, p) == false {
		t.Fatal("sanity: base proof must verify")
	}

	// Negative leaf index.
	if p := (MerkleProof{TxHash: txs[0], Siblings: proof.Siblings, LeafIndex: -1}); VerifyMerkleProof(txs[0], root, p) {
		t.Fatal("negative leaf index accepted")
	}

	// Sibling list longer than the maximum tree depth.
	oversized := make([]types.Hash, 33)
	if p := (MerkleProof{TxHash: txs[0], Siblings: oversized, LeafIndex: 0}); VerifyMerkleProof(txs[0], root, p) {
		t.Fatal("oversized sibling list accepted")
	}

	// Proof whose embedded TxHash differs from the claimed one.
	if p := (MerkleProof{TxHash: types.Hash{0xff}, Siblings: proof.Siblings, LeafIndex: 0}); VerifyMerkleProof(txs[0], root, p) {
		t.Fatal("proof with mismatched embedded TxHash accepted")
	}

	// Leaf index not representable by the sibling count.
	if p := (MerkleProof{TxHash: txs[0], Siblings: proof.Siblings, LeafIndex: 1 << 10}); VerifyMerkleProof(txs[0], root, p) {
		t.Fatal("out-of-range leaf index accepted")
	}
}

func TestGenerateMerkleProofBounds(t *testing.T) {
	txs := makeTxHashes(3)
	if _, err := GenerateMerkleProof(nil, 0); err == nil {
		t.Fatal("empty tree accepted")
	}
	if _, err := GenerateMerkleProof(txs, -1); err == nil {
		t.Fatal("negative index accepted")
	}
	if _, err := GenerateMerkleProof(txs, len(txs)); err == nil {
		t.Fatal("index past the end accepted")
	}
}
