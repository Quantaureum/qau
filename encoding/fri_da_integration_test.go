// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"testing"
)

// ─── Helpers ───────────────────────────────────────────────────────────────

// newFRIDATestBlob builds a deterministic test blob of the given size.
func newFRIDATestBlob(size int) []byte {
	blob := make([]byte, size)
	for i := 0; i < size; i++ {
		blob[i] = byte((i*31 + 7) & 0xff)
	}
	return blob
}

// newFRIDAValidSetup builds a committed blob + a valid cell proof at cellIndex.
// Returns the blobData, the cell, the proof, and the cell index used.
func newFRIDAValidSetup(t *testing.T, blobSize, cellIndex int) (*FRIDABlobData, Cell, *FRIDACellProof, int) {
	t.Helper()
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}
	blob := newFRIDATestBlob(blobSize)
	blobData, err := FRIDACommitBlob(blob, cfg)
	if err != nil {
		t.Fatalf("FRIDACommitBlob failed: %v", err)
	}
	if cellIndex < 0 || cellIndex >= cfg.DomainSize {
		cellIndex = 11
	}
	cell, err := FRIDAGetCellValue(blobData, cellIndex)
	if err != nil {
		t.Fatalf("FRIDAGetCellValue failed: %v", err)
	}
	proof, err := FRIDAGenerateCellProof(blobData, cellIndex)
	if err != nil {
		t.Fatalf("FRIDAGenerateCellProof failed: %v", err)
	}
	return blobData, cell, proof, cellIndex
}

// ─── Commit + Verify (happy path) ──────────────────────────────────────────

func TestFRIDA_CommitAndVerify_Valid(t *testing.T) {
	blobData, cell, proof, idx := newFRIDAValidSetup(t, 32, 11)

	if !FRIDAVerifyCell(cell, blobData.Commitment, proof, idx) {
		t.Fatal("FRIDAVerifyCell failed for valid cell")
	}
}

func TestFRIDA_CommitAndVerify_MultipleIndices(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}
	blob := newFRIDATestBlob(48)
	blobData, err := FRIDACommitBlob(blob, cfg)
	if err != nil {
		t.Fatalf("FRIDACommitBlob failed: %v", err)
	}

	// Verify a handful of cells at distinct indices spanning the codeword.
	indices := []int{0, 1, 7, 13, 31, 42, 63}
	for _, idx := range indices {
		cell, err := FRIDAGetCellValue(blobData, idx)
		if err != nil {
			t.Fatalf("FRIDAGetCellValue(%d) failed: %v", idx, err)
		}
		proof, err := FRIDAGenerateCellProof(blobData, idx)
		if err != nil {
			t.Fatalf("FRIDAGenerateCellProof(%d) failed: %v", idx, err)
		}
		if !FRIDAVerifyCell(cell, blobData.Commitment, proof, idx) {
			t.Errorf("FRIDAVerifyCell failed at index %d", idx)
		}
	}
}

// ─── Tamper detection ──────────────────────────────────────────────────────

func TestFRIDA_TamperedCellValue(t *testing.T) {
	blobData, cell, proof, idx := newFRIDAValidSetup(t, 32, 11)

	// Flip the first byte of the cell.
	cell[0] ^= 0x01

	if FRIDAVerifyCell(cell, blobData.Commitment, proof, idx) {
		t.Error("FRIDAVerifyCell must fail for tampered cell value")
	}
}

func TestFRIDA_TamperedProofCellValue(t *testing.T) {
	blobData, cell, proof, idx := newFRIDAValidSetup(t, 32, 11)

	// Tamper the proof's underlying CellValue; the Merkle check must fail.
	proof.Opening.CellValue = GF64Add(proof.Opening.CellValue, GF64Element(1))

	if FRIDAVerifyCell(cell, blobData.Commitment, proof, idx) {
		t.Error("FRIDAVerifyCell must fail when proof.CellValue is tampered")
	}
}

func TestFRIDA_TamperedMerkleProof(t *testing.T) {
	blobData, cell, proof, idx := newFRIDAValidSetup(t, 32, 11)

	// Tamper the Merkle path if present.
	if len(proof.Opening.MerkleProof) > 0 {
		sib := make([]byte, len(proof.Opening.MerkleProof[0]))
		copy(sib, proof.Opening.MerkleProof[0])
		sib[0] ^= 0x01
		proof.Opening.MerkleProof[0] = sib
	}

	if FRIDAVerifyCell(cell, blobData.Commitment, proof, idx) {
		t.Error("FRIDAVerifyCell must fail for tampered Merkle proof")
	}
}

func TestFRIDA_TamperedCommitment(t *testing.T) {
	blobData, cell, proof, idx := newFRIDAValidSetup(t, 32, 11)

	// Tamper the first layer root; every verification path must fail.
	if len(blobData.Commitment.LayerRoots) == 0 {
		t.Fatal("commitment has no layer roots")
	}
	blobData.Commitment.LayerRoots[0][0] ^= 0x01

	if FRIDAVerifyCell(cell, blobData.Commitment, proof, idx) {
		t.Error("FRIDAVerifyCell must fail for tampered commitment root")
	}
}

func TestFRIDA_TamperedFinalValue(t *testing.T) {
	blobData, cell, proof, idx := newFRIDAValidSetup(t, 32, 11)

	if len(blobData.Commitment.FinalValues) == 0 {
		t.Fatal("commitment has no final values")
	}
	blobData.Commitment.FinalValues[0] = GF64Add(
		blobData.Commitment.FinalValues[0], GF64Element(1),
	)

	if FRIDAVerifyCell(cell, blobData.Commitment, proof, idx) {
		t.Error("FRIDAVerifyCell must fail for tampered final value")
	}
}

// ─── Index & input validation ──────────────────────────────────────────────

func TestFRIDA_WrongCellIndex(t *testing.T) {
	blobData, cell, proof, idx := newFRIDAValidSetup(t, 32, 11)

	// Use a different cell index for verification than the proof carries.
	wrongIdx := (idx + 1) % blobData.Commitment.DomainSize
	if wrongIdx == idx {
		wrongIdx = (idx + 2) % blobData.Commitment.DomainSize
	}

	if FRIDAVerifyCell(cell, blobData.Commitment, proof, wrongIdx) {
		t.Error("FRIDAVerifyCell must fail when cellIndex != proof.CellIndex")
	}
}

func TestFRIDA_OutOfRangeCellIndex(t *testing.T) {
	blobData, _, proof, _ := newFRIDAValidSetup(t, 32, 11)

	var dummy Cell
	if FRIDAVerifyCell(dummy, blobData.Commitment, proof, -1) {
		t.Error("FRIDAVerifyCell must fail for negative cellIndex")
	}
	if FRIDAVerifyCell(dummy, blobData.Commitment, proof, blobData.Commitment.DomainSize) {
		t.Error("FRIDAVerifyCell must fail for cellIndex == DomainSize")
	}
}

func TestFRIDA_NilInputs(t *testing.T) {
	blobData, cell, proof, idx := newFRIDAValidSetup(t, 32, 11)

	// nil commitment
	if FRIDAVerifyCell(cell, nil, proof, idx) {
		t.Error("FRIDAVerifyCell must fail for nil commitment")
	}
	// nil proof
	if FRIDAVerifyCell(cell, blobData.Commitment, nil, idx) {
		t.Error("FRIDAVerifyCell must fail for nil proof")
	}
	// nil inner opening
	savedOpening := proof.Opening
	proof.Opening = nil
	if FRIDAVerifyCell(cell, blobData.Commitment, proof, idx) {
		t.Error("FRIDAVerifyCell must fail for nil inner Opening")
	}
	proof.Opening = savedOpening
}

func TestFRIDACommitBlob_EmptyBlob(t *testing.T) {
	cfg := FRIConfig{DomainSize: 64, CodeRate: 4, NumQueries: 10, FinalLayerSize: 4}
	if _, err := FRIDACommitBlob(nil, cfg); err == nil {
		t.Error("FRIDACommitBlob must reject nil blob")
	}
	if _, err := FRIDACommitBlob([]byte{}, cfg); err == nil {
		t.Error("FRIDACommitBlob must reject empty blob")
	}
}

func TestFRIDACommitBlob_InvalidConfig(t *testing.T) {
	blob := newFRIDATestBlob(32)
	bad := FRIConfig{DomainSize: 0, CodeRate: 4, NumQueries: 10, FinalLayerSize: 4}
	if _, err := FRIDACommitBlob(blob, bad); err == nil {
		t.Error("FRIDACommitBlob must reject DomainSize=0")
	}
	bad = FRIConfig{DomainSize: 64, CodeRate: 0, NumQueries: 10, FinalLayerSize: 4}
	if _, err := FRIDACommitBlob(blob, bad); err == nil {
		t.Error("FRIDACommitBlob must reject CodeRate=0")
	}
}

func TestFRIDAGenerateCellProof_NilBlobData(t *testing.T) {
	if _, err := FRIDAGenerateCellProof(nil, 0); err == nil {
		t.Error("FRIDAGenerateCellProof must reject nil blobData")
	}
}

func TestFRIDAGetCellValue_OutOfRange(t *testing.T) {
	blobData, _, _, _ := newFRIDAValidSetup(t, 32, 11)
	if _, err := FRIDAGetCellValue(blobData, -1); err == nil {
		t.Error("FRIDAGetCellValue must reject negative index")
	}
	if _, err := FRIDAGetCellValue(blobData, blobData.Commitment.DomainSize); err == nil {
		t.Error("FRIDAGetCellValue must reject index == DomainSize")
	}
}

func TestFRIDAGetCellValue_NilBlobData(t *testing.T) {
	if _, err := FRIDAGetCellValue(nil, 0); err == nil {
		t.Error("FRIDAGetCellValue must reject nil blobData")
	}
}

// ─── FRIDAGetCellValue correctness ─────────────────────────────────────────

func TestFRIDA_GetCellValueMatchesCodeword(t *testing.T) {
	blobData, cell, _, idx := newFRIDAValidSetup(t, 32, 11)
	if idx >= len(blobData.Codeword) {
		t.Fatalf("idx %d out of codeword range %d", idx, len(blobData.Codeword))
	}
	expected := blobData.Codeword[idx]
	got := GF64FromBytes(cell[:8])
	if got != expected {
		t.Errorf("cell value = %d, expected %d", got, expected)
	}
	// Bytes 8..31 must be zero (cell is padded).
	for i := 8; i < CellSize; i++ {
		if cell[i] != 0 {
			t.Errorf("cell byte %d must be zero, got %d", i, cell[i])
			break
		}
	}
}

// ─── Batch verification ────────────────────────────────────────────────────

func TestFRIDA_VerifyBatch(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}
	blob := newFRIDATestBlob(48)
	blobData, err := FRIDACommitBlob(blob, cfg)
	if err != nil {
		t.Fatalf("FRIDACommitBlob failed: %v", err)
	}

	indices := []int{0, 5, 10, 20, 35, 50}
	cells := make([]Cell, len(indices))
	proofs := make([]*FRIDACellProof, len(indices))
	for i, idx := range indices {
		cell, err := FRIDAGetCellValue(blobData, idx)
		if err != nil {
			t.Fatalf("FRIDAGetCellValue(%d) failed: %v", idx, err)
		}
		proof, err := FRIDAGenerateCellProof(blobData, idx)
		if err != nil {
			t.Fatalf("FRIDAGenerateCellProof(%d) failed: %v", idx, err)
		}
		cells[i] = cell
		proofs[i] = proof
	}

	results, err := FRIDAVerifyCellBatch(blobData.Commitment, cells, proofs, indices)
	if err != nil {
		t.Fatalf("FRIDAVerifyCellBatch failed: %v", err)
	}
	for i, ok := range results {
		if !ok {
			t.Errorf("batch verify failed at position %d (idx=%d)", i, indices[i])
		}
	}
}

func TestFRIDA_VerifyBatch_LengthMismatch(t *testing.T) {
	commitment := &FRIDACommitment{DomainSize: 64}
	if _, err := FRIDAVerifyCellBatch(
		commitment,
		make([]Cell, 2),
		make([]*FRIDACellProof, 3),
		[]int{0, 1, 2},
	); err == nil {
		t.Error("FRIDAVerifyCellBatch must fail on length mismatch")
	}
}

func TestFRIDA_VerifyBatch_TamperedCell(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}
	blob := newFRIDATestBlob(48)
	blobData, err := FRIDACommitBlob(blob, cfg)
	if err != nil {
		t.Fatalf("FRIDACommitBlob failed: %v", err)
	}

	indices := []int{3, 9, 17}
	cells := make([]Cell, len(indices))
	proofs := make([]*FRIDACellProof, len(indices))
	for i, idx := range indices {
		cell, err := FRIDAGetCellValue(blobData, idx)
		if err != nil {
			t.Fatalf("FRIDAGetCellValue(%d) failed: %v", idx, err)
		}
		proof, err := FRIDAGenerateCellProof(blobData, idx)
		if err != nil {
			t.Fatalf("FRIDAGenerateCellProof(%d) failed: %v", idx, err)
		}
		cells[i] = cell
		proofs[i] = proof
	}

	// Tamper with the middle cell.
	cells[1][0] ^= 0x01

	results, err := FRIDAVerifyCellBatch(blobData.Commitment, cells, proofs, indices)
	if err != nil {
		t.Fatalf("FRIDAVerifyCellBatch failed: %v", err)
	}
	if results[0] != true {
		t.Error("untampered cell 0 must verify")
	}
	if results[1] != false {
		t.Error("tampered cell 1 must NOT verify")
	}
	if results[2] != true {
		t.Error("untampered cell 2 must verify")
	}
}

// ─── Encode/Decode commitment ──────────────────────────────────────────────

func TestFRIDA_EncodeDecodeCommitment_RoundTrip(t *testing.T) {
	blobData, _, _, _ := newFRIDAValidSetup(t, 32, 11)

	encoded := EncodeFRIDACommitment(blobData.Commitment)
	if len(encoded) == 0 {
		t.Fatal("EncodeFRIDACommitment returned empty bytes")
	}

	decoded, err := DecodeFRIDACommitment(encoded)
	if err != nil {
		t.Fatalf("DecodeFRIDACommitment failed: %v", err)
	}

	// Compare every field.
	if decoded.NumLayers != blobData.Commitment.NumLayers {
		t.Errorf("NumLayers mismatch: %d vs %d",
			decoded.NumLayers, blobData.Commitment.NumLayers)
	}
	if decoded.DomainSize != blobData.Commitment.DomainSize {
		t.Errorf("DomainSize mismatch: %d vs %d",
			decoded.DomainSize, blobData.Commitment.DomainSize)
	}
	if decoded.CodeRate != blobData.Commitment.CodeRate {
		t.Errorf("CodeRate mismatch: %d vs %d",
			decoded.CodeRate, blobData.Commitment.CodeRate)
	}
	if decoded.NumQueries != blobData.Commitment.NumQueries {
		t.Errorf("NumQueries mismatch: %d vs %d",
			decoded.NumQueries, blobData.Commitment.NumQueries)
	}
	if decoded.FinalLayerSize != blobData.Commitment.FinalLayerSize {
		t.Errorf("FinalLayerSize mismatch: %d vs %d",
			decoded.FinalLayerSize, blobData.Commitment.FinalLayerSize)
	}
	if len(decoded.LayerRoots) != len(blobData.Commitment.LayerRoots) {
		t.Fatalf("LayerRoots length mismatch: %d vs %d",
			len(decoded.LayerRoots), len(blobData.Commitment.LayerRoots))
	}
	for i, root := range blobData.Commitment.LayerRoots {
		if decoded.LayerRoots[i] != root {
			t.Errorf("LayerRoots[%d] mismatch", i)
		}
	}
	if len(decoded.FinalValues) != len(blobData.Commitment.FinalValues) {
		t.Fatalf("FinalValues length mismatch: %d vs %d",
			len(decoded.FinalValues), len(blobData.Commitment.FinalValues))
	}
	for i, v := range blobData.Commitment.FinalValues {
		if decoded.FinalValues[i] != v {
			t.Errorf("FinalValues[%d] mismatch: %d vs %d",
				i, decoded.FinalValues[i], v)
		}
	}
}

func TestFRIDA_EncodeNilCommitment(t *testing.T) {
	if got := EncodeFRIDACommitment(nil); got != nil {
		t.Errorf("EncodeFRIDACommitment(nil) = %v, want nil", got)
	}
}

func TestFRIDA_DecodeCommitment_TooShort(t *testing.T) {
	if _, err := DecodeFRIDACommitment([]byte{0, 1, 2}); err == nil {
		t.Error("DecodeFRIDACommitment must reject too-short input")
	}
}

func TestFRIDA_DecodeCommitment_TruncatedLayerRoots(t *testing.T) {
	blobData, _, _, _ := newFRIDAValidSetup(t, 32, 11)
	encoded := EncodeFRIDACommitment(blobData.Commitment)

	// Truncate by 32 bytes — should fail when reading LayerRoots.
	truncated := encoded[:len(encoded)-32]
	if _, err := DecodeFRIDACommitment(truncated); err == nil {
		t.Error("DecodeFRIDACommitment must reject truncated LayerRoots")
	}
}

func TestFRIDA_DecodeCommitment_TruncatedFinalValues(t *testing.T) {
	blobData, _, _, _ := newFRIDAValidSetup(t, 32, 11)
	encoded := EncodeFRIDACommitment(blobData.Commitment)

	// Truncate by 8 bytes — should fail when reading FinalValues.
	truncated := encoded[:len(encoded)-8]
	if _, err := DecodeFRIDACommitment(truncated); err == nil {
		t.Error("DecodeFRIDACommitment must reject truncated FinalValues")
	}
}

// ─── Encode/Decode + Verify integration ────────────────────────────────────

func TestFRIDA_DecodedCommitmentVerifiesCells(t *testing.T) {
	blobData, cell, proof, idx := newFRIDAValidSetup(t, 32, 11)

	// Serialize → deserialize the commitment, then verify a cell against it.
	encoded := EncodeFRIDACommitment(blobData.Commitment)
	decoded, err := DecodeFRIDACommitment(encoded)
	if err != nil {
		t.Fatalf("DecodeFRIDACommitment failed: %v", err)
	}

	if !FRIDAVerifyCell(cell, decoded, proof, idx) {
		t.Error("FRIDAVerifyCell failed against decoded commitment")
	}
}

// ─── All-cell proofs (smoke test) ──────────────────────────────────────────

func TestFRIDA_GenerateAllCellProofs(t *testing.T) {
	// Use a small domain to keep the test fast.
	cfg := FRIConfig{
		DomainSize:     16,
		CodeRate:       4,
		NumQueries:     8,
		FinalLayerSize: 4,
	}
	blob := newFRIDATestBlob(8)
	blobData, err := FRIDACommitBlob(blob, cfg)
	if err != nil {
		t.Fatalf("FRIDACommitBlob failed: %v", err)
	}

	proofs, err := FRIDAGenerateAllCellProofs(blobData)
	if err != nil {
		t.Fatalf("FRIDAGenerateAllCellProofs failed: %v", err)
	}
	if len(proofs) != cfg.DomainSize {
		t.Fatalf("proofs count = %d, want %d", len(proofs), cfg.DomainSize)
	}

	// Verify each proof against its cell.
	for i := 0; i < cfg.DomainSize; i++ {
		cell, err := FRIDAGetCellValue(blobData, i)
		if err != nil {
			t.Fatalf("FRIDAGetCellValue(%d) failed: %v", i, err)
		}
		if !FRIDAVerifyCell(cell, blobData.Commitment, proofs[i], i) {
			t.Errorf("FRIDAVerifyCell failed at index %d", i)
		}
	}
}

func TestFRIDA_GenerateAllCellProofs_NilBlobData(t *testing.T) {
	if _, err := FRIDAGenerateAllCellProofs(nil); err == nil {
		t.Error("FRIDAGenerateAllCellProofs must reject nil blobData")
	}
}

// ─── Cross-check: cell from a different blob must not verify ───────────────

func TestFRIDA_CellFromDifferentBlobFails(t *testing.T) {
	blobData1, _, proof1, idx1 := newFRIDAValidSetup(t, 32, 11)

	// Build a second, different blob.
	blob2 := newFRIDATestBlob(32)
	blob2[0] ^= 0x01 // make it distinct
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}
	blobData2, err := FRIDACommitBlob(blob2, cfg)
	if err != nil {
		t.Fatalf("FRIDACommitBlob(2) failed: %v", err)
	}

	cell2, err := FRIDAGetCellValue(blobData2, idx1)
	if err != nil {
		t.Fatalf("FRIDAGetCellValue(2,%d) failed: %v", idx1, err)
	}

	// Cell from blob2 + proof from blob1 must NOT verify against commitment1.
	if FRIDAVerifyCell(cell2, blobData1.Commitment, proof1, idx1) {
		t.Error("FRIDAVerifyCell must fail when cell is from a different blob")
	}
}

// ─── EncodeFRIDACommitment byte-level determinism ──────────────────────────

func TestFRIDA_EncodeCommitment_Deterministic(t *testing.T) {
	blobData, _, _, _ := newFRIDAValidSetup(t, 32, 11)

	a := EncodeFRIDACommitment(blobData.Commitment)
	b := EncodeFRIDACommitment(blobData.Commitment)
	if !bytes.Equal(a, b) {
		t.Error("EncodeFRIDACommitment must be deterministic")
	}
}
