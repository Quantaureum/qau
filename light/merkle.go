// Quantaureum Node source, version 1.0.0.
package light

import (
	"golang.org/x/crypto/sha3"

	"github.com/quantaureum/qau/types"
)

// MerkleProof represents a Merkle-tree inclusion proof
type MerkleProof struct {
	// transaction hash
	TxHash types.Hash
	// sibling hashes (leaf-to-root path)
	Siblings []types.Hash
	// leaf index
	LeafIndex int
}

// merkleLeafPrefix and merkleNodePrefix distinguish leaf-node from inner-node hashes
const (
	merkleLeafPrefix = 0x00
	merkleNodePrefix = 0x01
)

// hashLeaf hashes a leaf
func hashLeaf(data []byte) types.Hash {
	h := sha3.New256()
	h.Write([]byte{merkleLeafPrefix})
	h.Write(data)
	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// hashNode hashes an inner node
func hashNode(left, right types.Hash) types.Hash {
	h := sha3.New256()
	h.Write([]byte{merkleNodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// BuildMerkleTree builds a Merkle tree from tx hashes and returns the root.
//
// AUDIT (2026) R4-DATA-08 (CVE-2012-2459 — LATENT): Uses duplicate-last
// padding for odd leaf counts (line 67). See core/block_builder.go
// computeMerkleRoot for the full analysis. The light client builds proofs from
// the same transaction list validated by BlockValidator.validateTransactions,
// which rejects duplicate transaction hashes, so the exploit shape cannot reach
// this code path. Additionally, GenerateMerkleProof below documents the
// duplicate-sibling handling for odd counts at the proof layer.
func BuildMerkleTree(txHashes []types.Hash) types.Hash {
	if len(txHashes) == 0 {
		return types.Hash{}
	}

	// compute leaf hashes
	leaves := make([]types.Hash, len(txHashes))
	for i, txHash := range txHashes {
		leaves[i] = hashLeaf(txHash[:])
	}

	// build level by level
	current := leaves
	for len(current) > 1 {
		var next []types.Hash
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, hashNode(current[i], current[i+1]))
			} else {
				// with an odd node count, the last node pairs with itself
				next = append(next, hashNode(current[i], current[i]))
			}
		}
		current = next
	}

	return current[0]
}

// GenerateMerkleProof generates a Merkle proof for the given transaction
func GenerateMerkleProof(txHashes []types.Hash, txIndex int) (*MerkleProof, error) {
	if len(txHashes) == 0 {
		return nil, ErrEmptyTree
	}
	if txIndex < 0 || txIndex >= len(txHashes) {
		return nil, ErrInvalidIndex
	}

	// compute leaf hashes
	leaves := make([]types.Hash, len(txHashes))
	for i, txHash := range txHashes {
		leaves[i] = hashLeaf(txHash[:])
	}

	var siblings []types.Hash
	idx := txIndex
	current := leaves

	for len(current) > 1 {
		// fetch the sibling
		siblingIdx := idx ^ 1
		if siblingIdx < len(current) {
			siblings = append(siblings, current[siblingIdx])
		} else {
			// with an odd node count, the sibling is the node itself
			siblings = append(siblings, current[idx])
		}

		// compute the next level
		var next []types.Hash
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, hashNode(current[i], current[i+1]))
			} else {
				next = append(next, hashNode(current[i], current[i]))
			}
		}
		current = next
		idx = idx / 2
	}

	return &MerkleProof{
		TxHash:    txHashes[txIndex],
		Siblings:  siblings,
		LeafIndex: txIndex,
	}, nil
}

// VerifyMerkleProof verifies a Merkle proof
func VerifyMerkleProof(txHash types.Hash, expectedRoot types.Hash, proof MerkleProof) bool {
	// AUDIT (2026) BRDG-FIX: Add range and consistency checks.
	// Previously there were no bounds on LeafIndex or Siblings length,
	// and no verification that the proof's TxHash matches the claimed txHash.
	// This allowed crafted proofs with out-of-range indices or excessive
	// siblings to cause undefined behavior or DoS.

	// 1. LeafIndex must be non-negative
	if proof.LeafIndex < 0 {
		return false
	}

	// 2. Siblings count must not exceed max tree depth (2^32 leaves = 32 levels)
	const maxMerkleDepth = 32
	if len(proof.Siblings) > maxMerkleDepth {
		return false
	}

	// 3. The proof's TxHash must match the claimed txHash
	if proof.TxHash != txHash {
		return false
	}

	if len(proof.Siblings) == 0 {
		// a block with a single transaction
		leafHash := hashLeaf(txHash[:])
		return leafHash == expectedRoot
	}

	// 4. LeafIndex must not exceed what the siblings count supports
	// (a tree with d levels has at most 2^d leaves, so LeafIndex < 2^d)
	if proof.LeafIndex >= (1 << len(proof.Siblings)) {
		return false
	}

	// walk from the leaf to the root along the path
	current := hashLeaf(txHash[:])
	idx := proof.LeafIndex

	for _, sibling := range proof.Siblings {
		if idx%2 == 0 {
			// current node is on the left
			current = hashNode(current, sibling)
		} else {
			// current node is on the right
			current = hashNode(sibling, current)
		}
		idx = idx / 2
	}

	// 5. After consuming all siblings, idx should be 0 (we've reached the root)
	if idx != 0 {
		return false
	}

	return current == expectedRoot
}
