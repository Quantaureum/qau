// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"math/rand"
	"testing"
)

// makeTestBlob generates a deterministic non-zero Blob for testing.
// Uses a local PRNG so tests are reproducible across runs.
// P0-1 (2026-07-14)
func makeTestBlob(seed int64) Blob {
	var blob Blob
	rng := rand.New(rand.NewSource(seed))
	for i := range blob {
		// Bias toward non-zero: if rng gives 0, use 1.
		b := byte(rng.Intn(256))
		if b == 0 {
			b = 1
		}
		blob[i] = b
	}
	return blob
}

// isCellZero returns true if all bytes in the cell are zero.
// Avoids allocating a comparison slice.
// P0-1 (2026-07-14)
func isCellZero(c Cell) bool {
	for _, b := range c {
		if b != 0 {
			return false
		}
	}
	return true
}

// TestExtendBlob1D_NonZeroParity verifies the DoD requirement:
// "ExtendBlob1D yields non-zero parity at CellsPerBlob=4096"
//
// P0-1 (2026-07-14)
func TestExtendBlob1D_NonZeroParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full-scale ExtendBlob1D test in -short mode")
	}

	blob := makeTestBlob(42)
	cells := BlobToCells(blob)
	extended := ExtendBlob1D(cells)

	// 1. Systematic property: original cells appear verbatim.
	for i := 0; i < CellsPerBlob; i++ {
		if extended[i] != cells[i] {
			t.Fatalf("original cell %d was modified by ExtendBlob1D (systematic property violated)", i)
		}
	}

	// 2. Parity cells must NOT all be zero (the pre-P0-1 bug).
	zeroCount := 0
	for i := CellsPerBlob; i < CellsPerBlobExtended; i++ {
		if isCellZero(extended[i]) {
			zeroCount++
		}
	}
	if zeroCount == CellsPerBlob {
		t.Fatalf("all %d parity cells are zero — P0-1 regression: GF(2^16) extension not working", CellsPerBlob)
	}
	if zeroCount > CellsPerBlob/2 {
		t.Errorf("too many zero parity cells: %d/%d", zeroCount, CellsPerBlob)
	}
	t.Logf("non-zero parity cells: %d/%d", CellsPerBlob-zeroCount, CellsPerBlob)
}

// TestExtendBlob1D_ParityCorrectness verifies that parity cells are correct
// evaluations of the interpolation polynomial, by re-deriving one parity cell
// independently using a naive Lagrange evaluation.
//
// P0-1 (2026-07-14)
func TestExtendBlob1D_ParityCorrectness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full-scale parity correctness test in -short mode")
	}

	blob := makeTestBlob(7)
	cells := BlobToCells(blob)
	extended := ExtendBlob1D(cells)

	// Independently compute P(y) for the first parity cell (y = n+1) using
	// naive Lagrange interpolation on the first 8 elements only (for speed).
	// This cross-checks the optimized implementation in ExtendBlob1D.
	const sampleElems = 8 // first 8 uint16 elements of the cell
	n := CellsPerBlob
	y := uint16(n + 1) // evaluation point for parity[0]

	// Precompute Lagrange weights independently.
	// Standard Lagrange: L_j(y) = prod_{i≠j}(y - x_i) / prod_{i≠j}(x_j - x_i)
	weights := make([]uint16, n)
	for j := 0; j < n; j++ {
		xj := uint16(j + 1)
		denom := uint16(1)
		for i := 0; i < n; i++ {
			if i != j {
				denom = gf16Mul(denom, xj^uint16(i+1))
			}
		}
		fullNum := uint16(1)
		for i := 0; i < n; i++ {
			if i != j {
				fullNum = gf16Mul(fullNum, y^uint16(i+1))
			}
		}
		w, err := gf16Div(fullNum, denom)
		if err != nil {
			t.Fatalf("division failed: %v", err)
		}
		weights[j] = w
	}

	// Compute expected parity for first 8 uint16 elements.
	for elemIdx := 0; elemIdx < sampleElems; elemIdx += 2 {
		var expected uint16
		for j := 0; j < n; j++ {
			cj := uint16(cells[j][elemIdx])<<8 | uint16(cells[j][elemIdx+1])
			expected ^= gf16Mul(cj, weights[j])
		}
		got := uint16(extended[n][elemIdx])<<8 | uint16(extended[n][elemIdx+1])
		if expected != got {
			t.Fatalf("parity cell 0 element %d mismatch: got %d, want %d", elemIdx/2, got, expected)
		}
	}
}

// TestRecoverBlob1D_AllAvailable verifies the fast path: when all original
// cells are available, recovery should return them verbatim.
//
// P0-1 (2026-07-14)
func TestRecoverBlob1D_AllAvailable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full-scale RecoverBlob1D test in -short mode")
	}

	blob := makeTestBlob(100)
	cells := BlobToCells(blob)
	extended := ExtendBlob1D(cells)

	mask := make([]bool, CellsPerBlobExtended)
	for i := 0; i < CellsPerBlob; i++ {
		mask[i] = true
	}

	recovered, err := RecoverBlob1D(extended, mask)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	for i := 0; i < CellsPerBlob; i++ {
		if recovered[i] != cells[i] {
			t.Fatalf("recovered cell %d mismatch", i)
		}
	}
}

// TestRecoverBlob1D_HalfAvailable verifies the DoD requirement:
// "RecoverBlob1D recovers from 50% available cells"
//
// We make only the first n/2 original cells + all parity cells available
// (3n/4 total ≥ n), then erase the second half of original cells and verify
// recovery reconstructs them exactly.
//
// P0-1 (2026-07-14)
func TestRecoverBlob1D_HalfAvailable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full-scale 50%% recovery test in -short mode")
	}

	blob := makeTestBlob(2024)
	cells := BlobToCells(blob)
	extended := ExtendBlob1D(cells)

	n := CellsPerBlob
	mask := make([]bool, CellsPerBlobExtended)

	// Keep first n/2 original cells available.
	for i := 0; i < n/2; i++ {
		mask[i] = true
	}
	// Keep all n parity cells available. Total available = n/2 + n = 3n/2 ≥ n.
	for i := n; i < CellsPerBlobExtended; i++ {
		mask[i] = true
	}

	recovered, err := RecoverBlob1D(extended, mask)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	// Verify ALL original cells match.
	mismatch := 0
	for i := 0; i < n; i++ {
		if recovered[i] != cells[i] {
			mismatch++
		}
	}
	if mismatch > 0 {
		t.Fatalf("%d/%d recovered cells mismatch (expected 0)", mismatch, n)
	}
	t.Logf("successfully recovered all %d original cells from 3n/4 available cells", n)
}

// TestRecoverBlob1D_ExactHalfAvailable tests the boundary case where exactly
// n cells are available (the minimum). We erase half the originals and keep
// only n/2 originals + n/2 parities.
//
// P0-1 (2026-07-14)
func TestRecoverBlob1D_ExactHalfAvailable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full-scale exact-50%% recovery test in -short mode")
	}

	blob := makeTestBlob(99)
	cells := BlobToCells(blob)
	extended := ExtendBlob1D(cells)

	n := CellsPerBlob
	mask := make([]bool, CellsPerBlobExtended)

	// Keep first n/2 originals + first n/2 parities = exactly n available.
	for i := 0; i < n/2; i++ {
		mask[i] = true   // original
		mask[n+i] = true // parity
	}

	recovered, err := RecoverBlob1D(extended, mask)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	mismatch := 0
	for i := 0; i < n; i++ {
		if recovered[i] != cells[i] {
			mismatch++
		}
	}
	if mismatch > 0 {
		t.Fatalf("%d/%d cells mismatch in exact-50%% recovery", mismatch, n)
	}
}

// TestRecoverBlob1D_InsufficientCells verifies the error path.
// Doesn't call ExtendBlob1D (slow); just needs a non-nil extended array.
// P0-1 (2026-07-14)
func TestRecoverBlob1D_InsufficientCells(t *testing.T) {
	var extended BlobCellsExtended // all-zero is fine; we test the count check

	// Provide only n-1 available cells.
	mask := make([]bool, CellsPerBlobExtended)
	for i := 0; i < CellsPerBlob-1; i++ {
		mask[i] = true
	}

	_, err := RecoverBlob1D(extended, mask)
	if err == nil {
		t.Fatal("expected error for insufficient cells, got nil")
	}
}

// TestRecoverBlob1D_MixedAvailability tests recovery with a mixed set of
// available cells: some originals + some parities, with gaps.
// P0-1 (2026-07-14)
func TestRecoverBlob1D_MixedAvailability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mixed-availability recovery test in -short mode")
	}

	blob := makeTestBlob(555)
	cells := BlobToCells(blob)
	extended := ExtendBlob1D(cells)

	n := CellsPerBlob
	mask := make([]bool, CellsPerBlobExtended)

	// Available: every 3rd original (n/3) + all parity (n) = 4n/3 ≥ n.
	// This creates a sparse, gappy availability pattern distinct from the
	// contiguous masks used in the other tests.
	for i := 0; i < n; i += 3 {
		mask[i] = true
	}
	for i := n; i < CellsPerBlobExtended; i++ {
		mask[i] = true
	}

	availableCount := 0
	for _, a := range mask {
		if a {
			availableCount++
		}
	}
	if availableCount < n {
		t.Fatalf("test setup error: only %d available, need %d", availableCount, n)
	}

	recovered, err := RecoverBlob1D(extended, mask)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	mismatch := 0
	for i := 0; i < n; i++ {
		if recovered[i] != cells[i] {
			mismatch++
		}
	}
	if mismatch > 0 {
		t.Fatalf("%d/%d cells mismatch in mixed-availability recovery", mismatch, n)
	}
}

// TestExtendBlobs2D_ColumnParity verifies that 2D extension produces non-zero
// column parity. Uses 2 columns to keep the test fast.
// P0-1 (2026-07-14)
func TestExtendBlobs2D_ColumnParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 2D extension test in -short mode")
	}

	blobs := []Blob{
		makeTestBlob(11),
		makeTestBlob(22),
	}
	matrix, err := ExtendBlobs2D(blobs)
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}

	// 1. Original columns (0..n-1) should contain the 1D-extended data.
	for col := 0; col < len(blobs); col++ {
		cells := BlobToCells(blobs[col])
		extended := ExtendBlob1D(cells)
		for row := 0; row < CellsPerBlobExtended; row++ {
			if matrix[col][row] != extended[row] {
				t.Fatalf("column %d row %d mismatch with 1D extension", col, row)
			}
		}
	}

	// 2. Parity columns (n..MaxBlobColumnsExt-1) must not all be zero.
	n := len(blobs)
	for col := n; col < MaxBlobColumnsExt; col++ {
		zeroRows := 0
		for row := 0; row < CellsPerBlobExtended; row++ {
			if isCellZero(matrix[col][row]) {
				zeroRows++
			}
		}
		if zeroRows == CellsPerBlobExtended {
			t.Errorf("parity column %d is entirely zero", col)
		}
	}
}

// TestRecoverBlobs2D_HalfAvailable tests the full 2D cycle:
// extend → sample (keep 50% rows) → recover → verify.
// Uses 2 columns to keep the test fast.
// P0-1 (2026-07-14)
func TestRecoverBlobs2D_HalfAvailable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 2D recovery test in -short mode")
	}

	blobs := []Blob{
		makeTestBlob(101),
		makeTestBlob(202),
	}
	matrix, err := ExtendBlobs2D(blobs)
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}

	n := len(blobs)
	colMask := make([]bool, MaxBlobColumnsExt)
	for i := 0; i < n; i++ {
		colMask[i] = true // keep all original columns
	}

	// Keep first n/2 rows of originals + all parity rows.
	rowMask := make([]bool, CellsPerBlobExtended)
	for i := 0; i < CellsPerBlob/2; i++ {
		rowMask[i] = true
	}
	for i := CellsPerBlob; i < CellsPerBlobExtended; i++ {
		rowMask[i] = true
	}

	recovered, err := RecoverBlobs2D(matrix, colMask, rowMask, n)
	if err != nil {
		t.Fatalf("RecoverBlobs2D failed: %v", err)
	}

	for col := 0; col < n; col++ {
		if recovered[col] != blobs[col] {
			t.Fatalf("recovered blob %d mismatch", col)
		}
	}
}

// TestExtendBlobs2D_SingleColumn verifies the n=1 edge case: all parity
// columns should equal the original column (degree-0 polynomial).
// P0-1 (2026-07-14)
func TestExtendBlobs2D_SingleColumn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping single-column 2D test in -short mode")
	}

	blob := makeTestBlob(314)
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}

	// All parity columns should equal column 0 (degree-0 polynomial).
	for col := 1; col < MaxBlobColumnsExt; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			if matrix[col][row] != matrix[0][row] {
				t.Fatalf("parity column %d row %d != column 0 (n=1 edge case)", col, row)
			}
		}
	}
}

// ── P1-13: SparseBlobMatrix tests ──

// TestSparseBlobMatrix_OriginalColumnsRoundTrip verifies that original columns
// stored in SparseBlobMatrix match the input matrix exactly. P1-13 (2026-07-14).
func TestSparseBlobMatrix_OriginalColumnsRoundTrip(t *testing.T) {
	blobs := make([]Blob, 3)
	for i := range blobs {
		blobs[i] = makeTestBlob(int64(i + 1))
	}
	matrix, err := ExtendBlobs2D(blobs)
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}

	sparse := NewSparseBlobMatrix(matrix, 3)
	if sparse.OriginalCount != 3 {
		t.Fatalf("OriginalCount = %d, want 3", sparse.OriginalCount)
	}
	if len(sparse.OriginalColumns) != 3 {
		t.Fatalf("len(OriginalColumns) = %d, want 3", len(sparse.OriginalColumns))
	}

	// Verify original columns match
	for col := 0; col < 3; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			got := sparse.GetCell(row, col)
			if got != matrix[col][row] {
				t.Errorf("cell mismatch at col=%d row=%d", col, row)
				break
			}
		}
	}
}

// TestSparseBlobMatrix_ParityCellReconstruction verifies that parity cells
// recomputed by SparseBlobMatrix match the original ExtendBlobs2D output.
// P1-13 (2026-07-14).
func TestSparseBlobMatrix_ParityCellReconstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full-scale parity reconstruction test in -short mode")
	}

	blobs := make([]Blob, 4)
	for i := range blobs {
		blobs[i] = makeTestBlob(int64(i*7 + 1))
	}
	matrix, err := ExtendBlobs2D(blobs)
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}

	sparse := NewSparseBlobMatrix(matrix, 4)

	// Verify parity columns (4..MaxBlobColumnsExt-1) match
	for col := 4; col < MaxBlobColumnsExt; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			got := sparse.GetCell(row, col)
			want := matrix[col][row]
			if got != want {
				t.Errorf("parity cell mismatch at col=%d row=%d", col, row)
				break
			}
		}
	}
}

// TestSparseBlobMatrix_MemoryReduction verifies the DoD: memory usage reduced
// ≥ 50% compared to full BlobMatrixExtended. P1-13 (2026-07-14).
func TestSparseBlobMatrix_MemoryReduction(t *testing.T) {
	fullSize := int64(MaxBlobColumnsExt) * int64(CellsPerBlobExtended) * int64(CellSize)

	testCases := []struct {
		name          string
		originalCount int
	}{
		{"n=1 (worst case savings)", 1},
		{"n=3 (typical)", 3},
		{"n=6 (max blobs, DoD threshold)", MaxBlobColumns},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var matrix BlobMatrixExtended
			sparse := NewSparseBlobMatrix(matrix, tc.originalCount)
			sparseSize := sparse.MemoryBytes()

			reduction := float64(fullSize-sparseSize) / float64(fullSize) * 100
			t.Logf("full=%d bytes, sparse=%d bytes, reduction=%.1f%%", fullSize, sparseSize, reduction)

			if tc.originalCount == MaxBlobColumns {
				// DoD: ≥ 50% even in worst case
				if reduction < 50.0 {
					t.Errorf("memory reduction = %.1f%%, want ≥ 50%%", reduction)
				}
			} else {
				// For smaller counts, reduction should be even higher
				if reduction <= 0 {
					t.Errorf("memory reduction = %.1f%%, want > 0%%", reduction)
				}
			}
		})
	}
}

// TestSparseBlobMatrix_SingleBlobParity verifies the n=1 edge case: all parity
// columns should equal the original column. P1-13 (2026-07-14).
func TestSparseBlobMatrix_SingleBlobParity(t *testing.T) {
	blob := makeTestBlob(42)
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}

	sparse := NewSparseBlobMatrix(matrix, 1)

	// All parity columns should equal column 0
	for col := 1; col < MaxBlobColumnsExt; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			got := sparse.GetCell(row, col)
			want := sparse.GetCell(row, 0)
			if got != want {
				t.Errorf("parity col=%d row=%d != col=0 (n=1 edge case)", col, row)
				break
			}
		}
	}
}

// TestSparseBlobMatrix_ToBlobMatrixExtended verifies full reconstruction.
// P1-13 (2026-07-14).
func TestSparseBlobMatrix_ToBlobMatrixExtended(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full reconstruction test in -short mode")
	}

	blobs := make([]Blob, 3)
	for i := range blobs {
		blobs[i] = makeTestBlob(int64(i*13 + 1))
	}
	matrix, err := ExtendBlobs2D(blobs)
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}

	sparse := NewSparseBlobMatrix(matrix, 3)
	reconstructed := sparse.ToBlobMatrixExtended()

	// All cells (original + parity) should match
	for col := 0; col < MaxBlobColumnsExt; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			if reconstructed[col][row] != matrix[col][row] {
				t.Errorf("reconstructed mismatch at col=%d row=%d", col, row)
				break
			}
		}
	}
}

// TestP2_1_RandomBlobRecoverability verifies that random blobs can be
// recovered after losing exactly 50% of cells (the threshold for
// systematic Reed-Solomon with n=4096, 2n=8192).
//
// P2-1 (2026-07-15): Complements the existing fixed-data tests with
// randomized fuzzing to catch edge cases that deterministic tests miss.
func TestP2_1_RandomBlobRecoverability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping random recovery test in -short mode")
	}

	const rounds = 5
	for round := 0; round < rounds; round++ {
		seed := int64(1000 + round)
		blob := makeTestBlob(seed)

		cells := BlobToCells(blob)
		extended := ExtendBlob1D(cells)

		// Randomly drop 50% of the 2n=8192 cells.
		rng := rand.New(rand.NewSource(seed + 999))
		available := make([]bool, CellsPerBlobExtended)
		availableCount := 0
		for i := range available {
			available[i] = rng.Intn(2) == 0
			if available[i] {
				availableCount++
			}
		}
		// Ensure at least n=4096 are available (recovery threshold).
		for availableCount < CellsPerBlob {
			idx := rng.Intn(CellsPerBlobExtended)
			if !available[idx] {
				available[idx] = true
				availableCount++
			}
		}

		recovered, err := RecoverBlob1D(extended, available)
		if err != nil {
			t.Fatalf("round %d: RecoverBlob1D failed: %v", round, err)
		}

		// Verify recovered original cells match the original.
		for i := 0; i < CellsPerBlob; i++ {
			if recovered[i] != cells[i] {
				t.Errorf("round %d: cell %d mismatch: got %x, want %x",
					round, i, recovered[i], cells[i])
				break
			}
		}
	}
}

// TestP2_1_ZeroBlobRecovery verifies that an all-zero blob can be extended
// and recovered correctly. This is an edge case because the GF(2^16)
// Lagrange interpolation must handle zero evaluations without division by
// zero.
func TestP2_1_ZeroBlobRecovery(t *testing.T) {
	var zeroBlob Blob // all zeros
	cells := BlobToCells(zeroBlob)
	extended := ExtendBlob1D(cells)

	// Parity cells should also be zero (polynomial P(x)=0 → P(anything)=0).
	for i := CellsPerBlob; i < CellsPerBlobExtended; i++ {
		if extended[i] != (Cell{}) {
			t.Errorf("parity cell %d should be zero for zero blob, got %x", i, extended[i])
		}
	}

	// Drop 50% of cells and recover.
	available := make([]bool, CellsPerBlobExtended)
	for i := range available {
		available[i] = i%2 == 0 // keep even-indexed cells
	}
	recovered, err := RecoverBlob1D(extended, available)
	if err != nil {
		t.Fatalf("RecoverBlob1D failed: %v", err)
	}

	for i := 0; i < CellsPerBlob; i++ {
		if recovered[i] != (Cell{}) {
			t.Errorf("recovered cell %d should be zero, got %x", i, recovered[i])
		}
	}
}

// TestP2_1_RecoverWithOnlyParity verifies that a blob can be recovered
// using ONLY parity cells (all original cells lost). This is the worst-case
// recovery scenario for systematic Reed-Solomon.
func TestP2_1_RecoverWithOnlyParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping parity-only recovery test in -short mode")
	}

	blob := makeTestBlob(42)
	cells := BlobToCells(blob)
	extended := ExtendBlob1D(cells)

	// Drop ALL original cells, keep ALL parity cells.
	available := make([]bool, CellsPerBlobExtended)
	for i := CellsPerBlob; i < CellsPerBlobExtended; i++ {
		available[i] = true
	}
	// Need exactly n=4096 available. We have 4096 parity cells.
	recovered, err := RecoverBlob1D(extended, available)
	if err != nil {
		t.Fatalf("RecoverBlob1D with only parity failed: %v", err)
	}

	for i := 0; i < CellsPerBlob; i++ {
		if recovered[i] != cells[i] {
			t.Errorf("cell %d mismatch: got %x, want %x", i, recovered[i], cells[i])
			break
		}
	}
}

// TestP2_1_MultipleRandomBlobs2D verifies 2D extension and recovery with
// multiple random blobs, including column-direction recovery.
func TestP2_1_MultipleRandomBlobs2D(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 2D random recovery test in -short mode")
	}

	const numBlobs = 3
	blobs := make([]Blob, numBlobs)
	for i := range blobs {
		blobs[i] = makeTestBlob(int64(i*100 + 7))
	}

	matrix, err := ExtendBlobs2D(blobs)
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}

	// Verify parity columns are non-zero (at least one cell non-zero).
	for col := numBlobs; col < MaxBlobColumnsExt; col++ {
		allZero := true
		for row := 0; row < CellsPerBlobExtended; row++ {
			if matrix[col][row] != (Cell{}) {
				allZero = false
				break
			}
		}
		if allZero {
			t.Errorf("parity column %d is all zeros for non-zero input blobs", col)
		}
	}

	// 2D recovery: keep all original columns + 50% original rows + all parity rows.
	// This tests row-direction recovery (parity rows fill in missing original rows).
	colMask := make([]bool, MaxBlobColumnsExt)
	for i := 0; i < numBlobs; i++ {
		colMask[i] = true // keep all original columns
	}

	rng := rand.New(rand.NewSource(12345))
	rowMask := make([]bool, CellsPerBlobExtended)
	// Randomly keep 50% of original rows.
	origAvail := 0
	for i := 0; i < CellsPerBlob; i++ {
		rowMask[i] = rng.Intn(2) == 0
		if rowMask[i] {
			origAvail++
		}
	}
	// Ensure at least n/2 original rows available.
	for origAvail < CellsPerBlob/2 {
		idx := rng.Intn(CellsPerBlob)
		if !rowMask[idx] {
			rowMask[idx] = true
			origAvail++
		}
	}
	// Keep all parity rows (for row-direction recovery).
	for i := CellsPerBlob; i < CellsPerBlobExtended; i++ {
		rowMask[i] = true
	}

	recovered, err := RecoverBlobs2D(matrix, colMask, rowMask, numBlobs)
	if err != nil {
		t.Fatalf("RecoverBlobs2D failed: %v", err)
	}

	// Verify recovered original blobs match the originals.
	for col := 0; col < numBlobs; col++ {
		if recovered[col] != blobs[col] {
			t.Errorf("col %d: blob mismatch after 2D recovery", col)
		}
	}
}
