// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"testing"
)

func TestMerkleTree_Basic(t *testing.T) {
	leaves := make([][32]byte, 8)
	for i := 0; i < 8; i++ {
		leaves[i][0] = byte(i)
	}

	tree := buildMerkleTree(leaves)
	root := tree[0]

	for i := 0; i < 8; i++ {
		proof := generateMerkleProof(tree, i, 8)
		if !verifyMerkleProof(root, leaves[i], i, 8, proof) {
			t.Errorf("Merkle proof verification failed for leaf %d", i)
		}
	}
}

func TestMerkleTree_NonPowerOf2(t *testing.T) {
	for n := 1; n <= 32; n++ {
		leaves := make([][32]byte, n)
		for i := 0; i < n; i++ {
			leaves[i][0] = byte(i)
		}

		tree := buildMerkleTree(leaves)
		root := tree[0]

		for i := 0; i < n; i++ {
			proof := generateMerkleProof(tree, i, n)
			if !verifyMerkleProof(root, leaves[i], i, n, proof) {
				t.Errorf("Merkle proof verification failed for leaf %d (n=%d)", i, n)
			}
		}
	}
}

func TestMerkleTree_TamperedProof(t *testing.T) {
	leaves := make([][32]byte, 16)
	for i := 0; i < 16; i++ {
		leaves[i][0] = byte(i)
	}

	tree := buildMerkleTree(leaves)
	root := tree[0]

	proof := generateMerkleProof(tree, 5, 16)
	if !verifyMerkleProof(root, leaves[5], 5, 16, proof) {
		t.Fatal("valid proof should verify")
	}

	if len(proof) > 0 {
		tampered := make([][]byte, len(proof))
		for i, p := range proof {
			tampered[i] = make([]byte, 32)
			copy(tampered[i], p)
		}
		tampered[0][0] ^= 0xff
		if verifyMerkleProof(root, leaves[5], 5, 16, tampered) {
			t.Error("tampered proof should not verify")
		}
	}
}

func TestMerkleTree_WrongLeaf(t *testing.T) {
	leaves := make([][32]byte, 16)
	for i := 0; i < 16; i++ {
		leaves[i][0] = byte(i)
	}

	tree := buildMerkleTree(leaves)
	root := tree[0]

	proof := generateMerkleProof(tree, 5, 16)
	if verifyMerkleProof(root, leaves[6], 5, 16, proof) {
		t.Error("wrong leaf should not verify with correct proof")
	}
}

func TestMatrixCommitment_2D(t *testing.T) {
	var matrix BlobMatrixExtended
	for col := 0; col < 2; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			for k := 0; k < CellSize; k++ {
				matrix[col][row][k] = byte((col*1000 + row + k) % 256)
			}
		}
	}

	root, rowRoots, err := BuildMatrixCommitment(&matrix, 2)
	if err != nil {
		t.Fatalf("BuildMatrixCommitment failed: %v", err)
	}

	rowTrees := BuildRowTrees(&matrix, 2)

	testCases := []struct {
		row int
		col int
	}{
		{0, 0},
		{0, 1},
		{100, 0},
		{100, 1},
		{1000, 0},
		{1000, 1},
		{CellsPerBlobExtended - 1, 0},
		{CellsPerBlobExtended - 1, 1},
	}

	for _, tc := range testCases {
		cell := matrix[tc.col][tc.row]
		proof := GenerateCellProof(rowTrees, rowRoots, tc.row, tc.col, 2)

		if !VerifyCellProof2D(root, cell, proof, 2) {
			t.Errorf("2D Merkle proof verification failed for (row=%d, col=%d)", tc.row, tc.col)
		}
	}
}

func TestMatrixCommitment_TamperedCell(t *testing.T) {
	var matrix BlobMatrixExtended
	for col := 0; col < 2; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			for k := 0; k < CellSize; k++ {
				matrix[col][row][k] = byte((col*1000 + row + k) % 256)
			}
		}
	}

	root, rowRoots, err := BuildMatrixCommitment(&matrix, 2)
	if err != nil {
		t.Fatalf("BuildMatrixCommitment failed: %v", err)
	}

	rowTrees := BuildRowTrees(&matrix, 2)
	proof := GenerateCellProof(rowTrees, rowRoots, 100, 0, 2)

	tamperedCell := matrix[0][100]
	tamperedCell[0] ^= 0xff

	if VerifyCellProof2D(root, tamperedCell, proof, 2) {
		t.Error("tampered cell should not verify")
	}
}

func TestMerkleProof_EncodeDecode(t *testing.T) {
	var matrix BlobMatrixExtended
	for col := 0; col < 2; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			for k := 0; k < CellSize; k++ {
				matrix[col][row][k] = byte((col*1000 + row + k) % 256)
			}
		}
	}

	_, rowRoots, _ := BuildMatrixCommitment(&matrix, 2)
	rowTrees := BuildRowTrees(&matrix, 2)
	proof := GenerateCellProof(rowTrees, rowRoots, 123, 1, 2)

	encoded := EncodeMerkleProof(proof)
	decoded, err := DecodeMerkleProof(encoded)
	if err != nil {
		t.Fatalf("DecodeMerkleProof failed: %v", err)
	}

	if decoded.RowIndex != proof.RowIndex {
		t.Errorf("RowIndex mismatch: %d vs %d", decoded.RowIndex, proof.RowIndex)
	}
	if decoded.ColIndex != proof.ColIndex {
		t.Errorf("ColIndex mismatch: %d vs %d", decoded.ColIndex, proof.ColIndex)
	}
	if len(decoded.RowSiblings) != len(proof.RowSiblings) {
		t.Errorf("RowSiblings length mismatch: %d vs %d", len(decoded.RowSiblings), len(proof.RowSiblings))
	}
	for i := range proof.RowSiblings {
		if !bytes.Equal(decoded.RowSiblings[i], proof.RowSiblings[i]) {
			t.Errorf("RowSibling[%d] mismatch", i)
		}
	}
	if len(decoded.ColSiblings) != len(proof.ColSiblings) {
		t.Errorf("ColSiblings length mismatch: %d vs %d", len(decoded.ColSiblings), len(proof.ColSiblings))
	}
}

func TestNextPowerOf2(t *testing.T) {
	cases := []struct {
		input    int
		expected int
	}{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{4096, 4096},
		{4097, 8192},
	}

	for _, tc := range cases {
		result := nextPowerOf2(tc.input)
		if result != tc.expected {
			t.Errorf("nextPowerOf2(%d) = %d, expected %d", tc.input, result, tc.expected)
		}
	}
}
