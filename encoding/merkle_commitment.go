// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

var errInvalidProof = errors.New("invalid merkle proof encoding")

// DA-FIX (2026-07-17): Post-quantum vector commitment based on 2D Merkle trees.
//
// This replaces the previous hash-stub "KZG commitment" with a proper
// vector commitment scheme:
//   - Commitment: Merkle root of the 2D extended matrix
//   - Proof: Merkle path (row + column) proving cell inclusion
//   - Security: post-quantum (based on SHA-256 collision resistance)
//
// NOTE: This is a vector commitment, NOT a full polynomial commitment
// (like FRI or KZG). It proves that a cell exists at a specific position
// in the matrix, but does NOT prove that the matrix is a valid RS encoding
// of the original blobs. For full polynomial commitment, FRI-based scheme
// is planned as a future upgrade.
//
// Security properties provided:
//   - Binding: finding two different matrices with the same root is
//     computationally infeasible (2^128 birthday bound).
//   - Succinctness: proof size is O(log(rows) + log(cols)) ≈ 544 bytes.
//   - Knowledge soundness: to produce a valid proof for a cell, you need
//     to know the entire Merkle path (i.e., the full matrix).
//   - Post-quantum: secure against quantum adversaries (hash-based).

// MerkleProof represents a 2D Merkle inclusion proof for a single cell.
type MerkleProof struct {
	RowSiblings [][]byte // Sibling hashes along the row (column direction)
	ColSiblings [][]byte // Sibling hashes along the column (row direction)
	RowIndex    int      // Row index of the cell
	ColIndex    int      // Column index of the cell
}

// merkleLeafHash computes the hash of a single cell (leaf node).
// Format: SHA-256(0x00 || cell_data)
// The 0x00 prefix distinguishes leaf nodes from internal nodes.
func merkleLeafHash(cell []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(cell)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// merkleInternalHash computes the hash of an internal node from its two children.
// Format: SHA-256(0x01 || left || right)
// The 0x01 prefix distinguishes internal nodes from leaf nodes (second-preimage resistance).
func merkleInternalHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// nextPowerOf2 returns the smallest power of 2 that is >= n.
func nextPowerOf2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// buildMerkleTree builds a Merkle tree from the given leaf hashes.
// Returns the array of tree nodes, where index 0 is the root.
// Leaves are padded to the next power of 2 with zero hashes.
func buildMerkleTree(leaves [][32]byte) [][32]byte {
	n := len(leaves)
	paddedSize := nextPowerOf2(n)
	treeSize := 2*paddedSize - 1
	tree := make([][32]byte, treeSize)

	// Fill leaves (at the end of the tree array)
	leafStart := treeSize - paddedSize
	for i := 0; i < paddedSize; i++ {
		if i < n {
			tree[leafStart+i] = leaves[i]
		} else {
			tree[leafStart+i] = [32]byte{} // zero padding
		}
	}

	// Build internal nodes bottom-up
	for i := leafStart - 1; i >= 0; i-- {
		left := tree[2*i+1]
		right := tree[2*i+2]
		tree[i] = merkleInternalHash(left, right)
	}

	return tree
}

// generateMerkleProof generates a Merkle inclusion proof for the leaf at the given index.
// tree is the full tree array from buildMerkleTree.
// leafCount is the number of actual leaves (before padding).
func generateMerkleProof(tree [][32]byte, leafIndex, leafCount int) [][]byte {
	paddedSize := nextPowerOf2(leafCount)
	treeSize := 2*paddedSize - 1
	leafStart := treeSize - paddedSize

	nodeIndex := leafStart + leafIndex
	var proof [][]byte

	for nodeIndex > 0 {
		parent := (nodeIndex - 1) / 2
		var sibling [32]byte
		if nodeIndex%2 == 1 {
			// node is left child, sibling is right child
			sibling = tree[2*parent+2]
		} else {
			// node is right child, sibling is left child
			sibling = tree[2*parent+1]
		}
		proof = append(proof, sibling[:])
		nodeIndex = parent
	}

	return proof
}

// maxMerkleProofLen is the maximum allowed Merkle proof length (number of
// sibling hashes). A proof for a tree with N leaves requires at most
// ceil(log2(N)) siblings. We cap at 64 (enough for trees up to 2^64 leaves)
// to prevent attacker-crafted proofs with millions of siblings from
// causing CPU exhaustion in verifyMerkleProof.
//
// R32-P1-13 FIX (2026-07-28): Added to bound verification work for
// attacker-supplied proofs.
const maxMerkleProofLen = 64

// verifyMerkleProof verifies a Merkle inclusion proof.
// root is the expected Merkle root.
// leafHash is the hash of the leaf being proven.
// leafIndex is the index of the leaf.
// leafCount is the total number of leaves.
// proof is the sibling hashes from bottom to top.
//
// R32-P1-13 FIX (2026-07-28): Added boundary checks for leafIndex/leafCount
// and a hard cap on proof length. Previously an attacker could supply
// leafIndex >= leafCount (silently producing wrong roots that compare !=
// root, but wasting CPU) or proofs of unbounded length (CPU DoS).
func verifyMerkleProof(root [32]byte, leafHash [32]byte, leafIndex, leafCount int, proof [][]byte) bool {
	// Boundary checks: reject obviously invalid inputs early.
	if leafCount <= 0 {
		return false
	}
	if leafIndex < 0 || leafIndex >= leafCount {
		return false
	}
	if len(proof) > maxMerkleProofLen {
		return false
	}
	// Each sibling must be exactly 32 bytes (SHA-256 output size).
	for _, sib := range proof {
		if len(sib) != 32 {
			return false
		}
	}

	current := leafHash
	index := leafIndex

	for _, sibling := range proof {
		var sibArr [32]byte
		copy(sibArr[:], sibling)

		if index%2 == 0 {
			// current is left child
			current = merkleInternalHash(current, sibArr)
		} else {
			// current is right child
			current = merkleInternalHash(sibArr, current)
		}
		index = index / 2
	}

	return current == root
}

// BuildMatrixCommitment builds a 2D Merkle commitment for the entire extended matrix.
//
// Structure:
//  1. For each row, compute a Merkle tree of the cells in that row → row root
//  2. Compute a Merkle tree of all row roots → final commitment (root)
//
// Returns the final commitment (Merkle root) and all row roots (for proof generation).
func BuildMatrixCommitment(matrix *BlobMatrixExtended, colCount int) ([32]byte, [][32]byte, error) {
	rows := CellsPerBlobExtended
	cols := colCount
	if cols > MaxBlobColumnsExt {
		cols = MaxBlobColumnsExt
	}

	// Step 1: Compute row roots
	rowRoots := make([][32]byte, rows)
	for row := 0; row < rows; row++ {
		leaves := make([][32]byte, cols)
		for col := 0; col < cols; col++ {
			leaves[col] = merkleLeafHash(matrix[col][row][:])
		}
		tree := buildMerkleTree(leaves)
		rowRoots[row] = tree[0]
	}

	// Step 2: Compute column tree (tree of row roots)
	colTree := buildMerkleTree(rowRoots)
	root := colTree[0]

	return root, rowRoots, nil
}

// BuildRowTrees builds Merkle trees for all rows (for efficient proof generation).
// Returns an array of row trees, where each row tree is in the same format
// as buildMerkleTree (index 0 is the root).
func BuildRowTrees(matrix *BlobMatrixExtended, colCount int) [][][32]byte {
	rows := CellsPerBlobExtended
	cols := colCount
	if cols > MaxBlobColumnsExt {
		cols = MaxBlobColumnsExt
	}

	rowTrees := make([][][32]byte, rows)
	for row := 0; row < rows; row++ {
		leaves := make([][32]byte, cols)
		for col := 0; col < cols; col++ {
			leaves[col] = merkleLeafHash(matrix[col][row][:])
		}
		rowTrees[row] = buildMerkleTree(leaves)
	}

	return rowTrees
}

// GenerateCellProof generates a 2D Merkle proof for a cell at (row, col).
// rowTrees is the array of per-row Merkle trees from BuildRowTrees.
// rowRoots is the array of row root hashes.
// colCount is the number of columns (original + parity).
func GenerateCellProof(rowTrees [][][32]byte, rowRoots [][32]byte, row, col, colCount int) *MerkleProof {
	// Step 1: Generate row proof (within the row)
	rowProof := generateMerkleProof(rowTrees[row], col, colCount)

	// Step 2: Generate column proof (tree of row roots)
	colTree := buildMerkleTree(rowRoots)
	colProof := generateMerkleProof(colTree, row, len(rowRoots))

	return &MerkleProof{
		RowSiblings: rowProof,
		ColSiblings: colProof,
		RowIndex:    row,
		ColIndex:    col,
	}
}

// VerifyCellProof2D verifies a 2D Merkle proof for a cell.
// root is the expected matrix commitment (Merkle root).
// cell is the cell data.
// proof is the 2D Merkle proof.
// colCount is the number of columns in the matrix.
func VerifyCellProof2D(root [32]byte, cell Cell, proof *MerkleProof, colCount int) bool {
	if proof == nil {
		return false
	}
	if proof.RowIndex < 0 || proof.RowIndex >= CellsPerBlobExtended {
		return false
	}
	if proof.ColIndex < 0 || proof.ColIndex >= colCount {
		return false
	}

	// Step 1: Verify row proof (cell → row root)
	leafHash := merkleLeafHash(cell[:])
	rowRoot := [32]byte{}
	if !verifyMerkleProofGetRoot(leafHash, proof.ColIndex, colCount, proof.RowSiblings, &rowRoot) {
		return false
	}

	// Step 2: Verify column proof (row root → matrix root)
	return verifyMerkleProof(root, rowRoot, proof.RowIndex, CellsPerBlobExtended, proof.ColSiblings)
}

// verifyMerkleProofGetRoot is like verifyMerkleProof but returns the computed root
// via the out parameter. Returns true if the proof structure is valid.
//
// R32-P1-13 FIX (2026-07-28): Added the same boundary checks as
// verifyMerkleProof to prevent CPU DoS from attacker-supplied proofs.
// Previously this function had NO validation at all — any leafIndex,
// any leafCount, any proof length was accepted.
func verifyMerkleProofGetRoot(leafHash [32]byte, leafIndex, leafCount int, proof [][]byte, out *[32]byte) bool {
	if leafCount <= 0 {
		return false
	}
	if leafIndex < 0 || leafIndex >= leafCount {
		return false
	}
	if len(proof) > maxMerkleProofLen {
		return false
	}
	for _, sib := range proof {
		if len(sib) != 32 {
			return false
		}
	}

	current := leafHash
	index := leafIndex

	for _, sibling := range proof {
		var sibArr [32]byte
		copy(sibArr[:], sibling)

		if index%2 == 0 {
			current = merkleInternalHash(current, sibArr)
		} else {
			current = merkleInternalHash(sibArr, current)
		}
		index = index / 2
	}

	*out = current
	return true
}

// EncodeMerkleProof serializes a MerkleProof to bytes.
// Format:
//   - 4 bytes: row index (big-endian uint32)
//   - 4 bytes: col index (big-endian uint32)
//   - 4 bytes: row sibling count (big-endian uint32)
//   - 4 bytes: col sibling count (big-endian uint32)
//   - row siblings (each 32 bytes)
//   - col siblings (each 32 bytes)
func EncodeMerkleProof(proof *MerkleProof) []byte {
	if proof == nil {
		return nil
	}
	rowCount := len(proof.RowSiblings)
	colCount := len(proof.ColSiblings)
	totalSize := 16 + rowCount*32 + colCount*32
	buf := make([]byte, totalSize)

	binary.BigEndian.PutUint32(buf[0:4], uint32(proof.RowIndex))
	binary.BigEndian.PutUint32(buf[4:8], uint32(proof.ColIndex))
	binary.BigEndian.PutUint32(buf[8:12], uint32(rowCount))
	binary.BigEndian.PutUint32(buf[12:16], uint32(colCount))

	offset := 16
	for i := 0; i < rowCount; i++ {
		copy(buf[offset:offset+32], proof.RowSiblings[i])
		offset += 32
	}
	for i := 0; i < colCount; i++ {
		copy(buf[offset:offset+32], proof.ColSiblings[i])
		offset += 32
	}

	return buf
}

// DecodeMerkleProof deserializes a MerkleProof from bytes.
//
// R33 DA-02 FIX (2026-07-28): Add upper-bound validation on rowCount and
// colCount. Previously an attacker could craft a proof with rowCount =
// 0xFFFFFFFF, causing expectedSize = 16 + 0xFFFFFFFF*32 + ... to overflow
// uint32 (wrapping to a small value), bypass the length check, and trigger
// a huge make([][]byte, rowCount) allocation → OOM / DoS. Even without
// overflow, rowCount = 1<<28 would request ~4GB of slice headers. Fix:
// reject any dimension exceeding maxMerkleProofDimension (256). Real
// Merkle proofs in Quantaureum's DA use tree depths ≤ 32 (blob count ≤
// 2^32), but the sibling count equals tree depth, which is at most 32 for
// a 4-billion-leaf tree. 256 is a generous upper bound that still
// prevents OOM.
func DecodeMerkleProof(data []byte) (*MerkleProof, error) {
	if len(data) < 16 {
		return nil, errInvalidProof
	}

	rowIndex := int(binary.BigEndian.Uint32(data[0:4]))
	colIndex := int(binary.BigEndian.Uint32(data[4:8]))
	rowCount := int(binary.BigEndian.Uint32(data[8:12]))
	colCount := int(binary.BigEndian.Uint32(data[12:16]))

	// R33 DA-02 FIX: Reject oversized dimensions before any allocation.
	const maxMerkleProofDimension = 256
	if rowCount < 0 || colCount < 0 || rowCount > maxMerkleProofDimension || colCount > maxMerkleProofDimension {
		return nil, fmt.Errorf("%w: dimensions (%d, %d) exceed maximum %d", errInvalidProof, rowCount, colCount, maxMerkleProofDimension)
	}
	// Also validate index bounds — an out-of-bounds index would cause
	// VerifyMerkleProof to read past the tree depth.
	const maxMerkleProofIndex = 1 << 30 // 1 billion leaves is far beyond any real blob count
	if rowIndex < 0 || colIndex < 0 || rowIndex > maxMerkleProofIndex || colIndex > maxMerkleProofIndex {
		return nil, fmt.Errorf("%w: indices (%d, %d) exceed maximum %d", errInvalidProof, rowIndex, colIndex, maxMerkleProofIndex)
	}

	// Use uint64 to avoid overflow on 32-bit platforms when computing
	// expectedSize = 16 + rowCount*32 + colCount*32.
	expectedSize := uint64(16) + uint64(rowCount)*32 + uint64(colCount)*32
	if uint64(len(data)) < expectedSize {
		return nil, errInvalidProof
	}

	proof := &MerkleProof{
		RowIndex: rowIndex,
		ColIndex: colIndex,
	}

	offset := 16
	proof.RowSiblings = make([][]byte, rowCount)
	for i := 0; i < rowCount; i++ {
		sib := make([]byte, 32)
		copy(sib, data[offset:offset+32])
		proof.RowSiblings[i] = sib
		offset += 32
	}

	proof.ColSiblings = make([][]byte, colCount)
	for i := 0; i < colCount; i++ {
		sib := make([]byte, 32)
		copy(sib, data[offset:offset+32])
		proof.ColSiblings[i] = sib
		offset += 32
	}

	return proof, nil
}
