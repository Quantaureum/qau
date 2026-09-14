// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/sha3"
)

const (
	CellsPerBlob         = FieldElementsPerBlob
	CellsPerBlobExtended = CellsPerBlob * 2
	CellSize             = BytesPerFieldElement
	MaxBlobColumns       = MaxBlobsPerBlock
	MaxBlobColumnsExt    = MaxBlobColumns * 2
)

type Cell [CellSize]byte

type BlobCells [CellsPerBlob]Cell

type BlobCellsExtended [CellsPerBlobExtended]Cell

type BlobMatrix [MaxBlobColumns]BlobCells

type BlobMatrixExtended [MaxBlobColumnsExt]BlobCellsExtended

var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	gfExp[0] = 1
	for i := 1; i < 255; i++ {
		gfExp[i] = gfExp[i-1] << 1
		if gfExp[i-1]&0x80 != 0 {
			gfExp[i] ^= 0x1d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}

	for i := 0; i < 255; i++ {
		gfLog[gfExp[i]] = byte(i)
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

var ErrGFDivisionByZero = fmt.Errorf("division by zero in GF(256)")
var ErrGFInverseOfZero = fmt.Errorf("inverse of zero in GF(256)")

func gfDiv(a, b byte) (byte, error) {
	if a == 0 {
		return 0, nil
	}
	if b == 0 {
		return 0, ErrGFDivisionByZero
	}
	logDiff := int(gfLog[a]) - int(gfLog[b])
	if logDiff < 0 {
		logDiff += 255
	}
	return gfExp[logDiff], nil
}

func gfInv(a byte) (byte, error) {
	if a == 0 {
		return 0, ErrGFInverseOfZero
	}
	return gfExp[255-int(gfLog[a])], nil
}

func BlobToCells(blob Blob) BlobCells {
	var cells BlobCells
	for i := 0; i < CellsPerBlob; i++ {
		copy(cells[i][:], blob[i*CellSize:(i+1)*CellSize])
	}
	return cells
}

func CellsToBlob(cells BlobCells) Blob {
	var blob Blob
	for i := 0; i < CellsPerBlob; i++ {
		copy(blob[i*CellSize:(i+1)*CellSize], cells[i][:])
	}
	return blob
}

// ExtendBlob1D extends a blob's cells with parity cells using systematic
// Reed-Solomon over GF(2^16).
//
// P0-1 (2026-07-14): Both original and parity cells are EVALUATIONS of the
// same degree-(n-1) polynomial P(x), at distinct evaluation points:
//   - Original cells: P(1), P(2), ..., P(n)   — positions 0..n-1
//   - Parity cells:   P(n+1), ..., P(2n)       — positions n..2n-1
//
// This is a "systematic" code: original data appears verbatim in the codeword.
// Any n of the 2n cells suffice to recover the original via Lagrange
// interpolation.
//
// Previous code treated cells as polynomial COEFFICIENTS and parity as
// evaluations — a mixed representation that made recovery incorrect when
// original cells were missing (the bug was masked because tests only exercised
// the "all originals available" fast path).
//
// Each 32-byte cell is treated as 16 uint16 elements in big-endian; the
// polynomial is evaluated independently for each element position.
// Complexity: O(n²) for the Lagrange weight precompute + O(n²) for evaluation.
func ExtendBlob1D(cells BlobCells) BlobCellsExtended {
	var extended BlobCellsExtended
	copy(extended[:CellsPerBlob], cells[:])

	n := CellsPerBlob

	// Precompute denom[j] = prod_{i≠j} (x_j − x_i) where x_k = k+1.
	// In GF(2^p), subtraction = XOR.
	denom := make([]uint16, n)
	for j := 0; j < n; j++ {
		xj := uint16(j + 1)
		d := uint16(1)
		for i := 0; i < n; i++ {
			if i != j {
				d = gf16Mul(d, xj^uint16(i+1))
			}
		}
		denom[j] = d
	}

	// For each parity point y = n+k+1, compute P(y) via Lagrange:
	//   P(y) = Σ_j cells[j] · L_j(y)
	//   L_j(y) = num / (y − x_j) / denom[j]
	//   num = Π_i (y − x_i)
	for k := 0; k < n; k++ {
		y := uint16(n + k + 1)

		// num = Π_{i=0}^{n-1} (y XOR (i+1))
		num := uint16(1)
		for i := 0; i < n; i++ {
			num = gf16Mul(num, y^uint16(i+1))
		}

		var parity Cell
		for j := 0; j < n; j++ {
			diff := y ^ uint16(j+1) // y − x_j; never 0 since y > n ≥ x_j
			w, _ := gf16Div(num, diff)
			w, _ = gf16Div(w, denom[j])

			for elemIdx := 0; elemIdx < CellSize; elemIdx += 2 {
				cj := binary.BigEndian.Uint16(cells[j][elemIdx:])
				pe := binary.BigEndian.Uint16(parity[elemIdx:])
				pe ^= gf16Mul(cj, w)
				binary.BigEndian.PutUint16(parity[elemIdx:], pe)
			}
		}
		extended[n+k] = parity
	}

	return extended
}

// RecoverBlob1D recovers original cells from an extended blob given a mask of
// which cells are available. Any n available cells out of 2n suffice.
//
// P0-1 (2026-07-14): Uses Lagrange interpolation over GF(2^16). Available
// cells (original and/or parity) are evaluations of P at distinct points.
// Missing original cells are recovered by evaluating P at the corresponding
// points.
func RecoverBlob1D(extended BlobCellsExtended, availableMask []bool) (BlobCells, error) {
	n := CellsPerBlob

	availableCount := 0
	allOriginalAvailable := true
	for i, avail := range availableMask {
		if avail {
			availableCount++
		}
		if i < n && !avail {
			allOriginalAvailable = false
		}
	}
	if availableCount < n {
		return BlobCells{}, fmt.Errorf("insufficient cells: need %d, have %d", n, availableCount)
	}

	// Fast path: all original cells available — just copy.
	if allOriginalAvailable {
		var recovered BlobCells
		copy(recovered[:], extended[:n])
		return recovered, nil
	}

	// Collect exactly n available indices (we have ≥ n).
	availableIndices := make([]int, 0, n)
	for i, avail := range availableMask {
		if avail {
			availableIndices = append(availableIndices, i)
			if len(availableIndices) == n {
				break
			}
		}
	}

	// Evaluation points: x_i = availableIndices[i] + 1 (1-indexed, distinct).
	xs := make([]uint16, n)
	for i := 0; i < n; i++ {
		xs[i] = uint16(availableIndices[i] + 1)
	}

	// Precompute denom for Lagrange basis over the available points.
	denom := make([]uint16, n)
	for i := 0; i < n; i++ {
		d := uint16(1)
		for j := 0; j < n; j++ {
			if i != j {
				d = gf16Mul(d, xs[i]^xs[j])
			}
		}
		denom[i] = d
	}

	availCells := make([]Cell, n)
	for i := 0; i < n; i++ {
		availCells[i] = extended[availableIndices[i]]
	}

	var recovered BlobCells

	// For each original point y = j+1, recover if missing.
	for j := 0; j < n; j++ {
		if availableMask[j] {
			recovered[j] = extended[j]
			continue
		}

		y := uint16(j + 1)

		// num = Π_k (y − xs[k])
		num := uint16(1)
		for k := 0; k < n; k++ {
			num = gf16Mul(num, y^xs[k])
		}

		var cell Cell
		for i := 0; i < n; i++ {
			diff := y ^ xs[i]
			if diff == 0 {
				// y coincides with an available point — copy directly.
				cell = availCells[i]
				break
			}
			w, err := gf16Div(num, diff)
			if err != nil {
				return BlobCells{}, fmt.Errorf("recovery failed at cell %d: %w", j, err)
			}
			w, err = gf16Div(w, denom[i])
			if err != nil {
				return BlobCells{}, fmt.Errorf("recovery failed at cell %d: %w", j, err)
			}
			for elemIdx := 0; elemIdx < CellSize; elemIdx += 2 {
				vi := binary.BigEndian.Uint16(availCells[i][elemIdx:])
				ce := binary.BigEndian.Uint16(cell[elemIdx:])
				ce ^= gf16Mul(vi, w)
				binary.BigEndian.PutUint16(cell[elemIdx:], ce)
			}
		}
		recovered[j] = cell
	}

	return recovered, nil
}

func solveVandermonde(indices []int, values []byte, n int) ([]byte, error) {
	if len(indices) < n {
		return nil, fmt.Errorf("insufficient equations: %d < %d", len(indices), n)
	}
	for i := 0; i < n; i++ {
		if indices[i] >= 255 {
			return nil, fmt.Errorf("GF(2^8) evaluation point overflow: index %d >= 255", indices[i])
		}
	}

	xs := make([]byte, n)
	ys := make([]byte, n)
	for i := 0; i < n; i++ {
		xs[i] = byte(indices[i] + 1)
		ys[i] = values[i]
	}

	dd := make([][]byte, n)
	for i := 0; i < n; i++ {
		dd[i] = make([]byte, n)
		dd[i][0] = ys[i]
	}

	for j := 1; j < n; j++ {
		for i := 0; i < n-j; i++ {
			denom := xs[i+j] ^ xs[i]
			if denom == 0 {
				return nil, fmt.Errorf("duplicate x values at indices %d and %d", i, i+j)
			}
			ddVal, divErr := gfDiv(dd[i+1][j-1]^dd[i][j-1], denom)
			if divErr != nil {
				return nil, fmt.Errorf("GF(256) division failed: %w", divErr)
			}
			dd[i][j] = ddVal
		}
	}

	coeffs := make([]byte, n)
	coeffs[0] = dd[0][0]

	poly := make([]byte, n)
	poly[0] = 1

	for j := 1; j < n; j++ {
		for i := n - 1; i >= 1; i-- {
			poly[i] = poly[i-1] ^ gfMul(poly[i], xs[j-1])
		}
		poly[0] = gfMul(poly[0], xs[j-1])

		cj := dd[0][j]
		for i := 0; i < n; i++ {
			coeffs[i] ^= gfMul(cj, poly[i])
		}
	}

	return coeffs, nil
}

// ExtendBlobs2D extends blobs both horizontally (1D row extension) and
// vertically (2D column extension), producing a MaxBlobColumnsExt ×
// CellsPerBlobExtended matrix.
//
// P0-1 (2026-07-14): Both 1D and 2D extensions use systematic Reed-Solomon
// over GF(2^16) with Lagrange interpolation. Original columns are evaluations
// at points 1..n; parity columns are evaluations at points n+1..MaxBlobColumnsExt.
// The column count is small (n ≤ MaxBlobColumns = 6), so the O(n²) Lagrange
// precompute is negligible.
func ExtendBlobs2D(blobs []Blob) (BlobMatrixExtended, error) {
	n := len(blobs)
	if n == 0 || n > MaxBlobColumns {
		return BlobMatrixExtended{}, fmt.Errorf("invalid blob count: %d", n)
	}

	var matrix BlobMatrixExtended

	// 1D extend each column (rows direction).
	for col := 0; col < n; col++ {
		cells := BlobToCells(blobs[col])
		extended := ExtendBlob1D(cells)
		for row := 0; row < CellsPerBlobExtended; row++ {
			matrix[col][row] = extended[row]
		}
	}

	// 2D column extension via Lagrange interpolation over GF(2^16).
	// Original columns → evaluation points 1..n.
	// Parity columns   → evaluation points n+1..MaxBlobColumnsExt.
	if n == 1 {
		// Degree-0 polynomial: all parity columns = original column.
		for col := 1; col < MaxBlobColumnsExt; col++ {
			for row := 0; row < CellsPerBlobExtended; row++ {
				matrix[col][row] = matrix[0][row]
			}
		}
		return matrix, nil
	}

	// Precompute denom for column Lagrange basis.
	colDenom := make([]uint16, n)
	for j := 0; j < n; j++ {
		xj := uint16(j + 1)
		d := uint16(1)
		for i := 0; i < n; i++ {
			if i != j {
				d = gf16Mul(d, xj^uint16(i+1))
			}
		}
		colDenom[j] = d
	}

	for col := n; col < MaxBlobColumnsExt; col++ {
		y := uint16(col + 1) // evaluation point for this parity column

		// num = Π_{i=0}^{n-1} (y − (i+1))
		num := uint16(1)
		for i := 0; i < n; i++ {
			num = gf16Mul(num, y^uint16(i+1))
		}

		// Compute Lagrange weights once per column (reused for all rows).
		weights := make([]uint16, n)
		for j := 0; j < n; j++ {
			diff := y ^ uint16(j+1)
			w, _ := gf16Div(num, diff)
			w, _ = gf16Div(w, colDenom[j])
			weights[j] = w
		}

		// For each row, compute parity = Σ_j matrix[j][row] × weights[j].
		for row := 0; row < CellsPerBlobExtended; row++ {
			var parity Cell
			for srcCol := 0; srcCol < n; srcCol++ {
				w := weights[srcCol]
				for k := 0; k < CellSize; k += 2 {
					elem := binary.BigEndian.Uint16(matrix[srcCol][row][k:])
					pe := binary.BigEndian.Uint16(parity[k:])
					pe ^= gf16Mul(elem, w)
					binary.BigEndian.PutUint16(parity[k:], pe)
				}
			}
			matrix[col][row] = parity
		}
	}

	return matrix, nil
}

func RecoverBlobs2D(matrix BlobMatrixExtended, colMask []bool, rowMask []bool, originalCount int) ([]Blob, error) {
	if originalCount <= 0 || originalCount > MaxBlobColumns {
		return nil, fmt.Errorf("invalid original count: %d", originalCount)
	}

	availableCols := 0
	for _, avail := range colMask {
		if avail {
			availableCols++
		}
	}
	if availableCols < originalCount {
		return nil, fmt.Errorf("insufficient columns: need %d, have %d", originalCount, availableCols)
	}

	availableRows := 0
	for _, avail := range rowMask {
		if avail {
			availableRows++
		}
	}
	if availableRows < CellsPerBlob {
		return nil, fmt.Errorf("insufficient rows: need %d, have %d", CellsPerBlob, availableRows)
	}

	blobs := make([]Blob, originalCount)

	for col := 0; col < originalCount; col++ {
		var extended BlobCellsExtended
		for row := 0; row < CellsPerBlobExtended; row++ {
			extended[row] = matrix[col][row]
		}

		cells, err := RecoverBlob1D(extended, rowMask)
		if err != nil {
			return nil, fmt.Errorf("recover blob %d: %w", col, err)
		}
		blobs[col] = CellsToBlob(cells)
	}

	return blobs, nil
}

func ComputeKZGCommitmentsForMatrix(matrix BlobMatrixExtended, colCount int) []KZGCommitment {
	commitments := make([]KZGCommitment, colCount)
	for col := 0; col < colCount; col++ {
		var blob Blob
		for row := 0; row < CellsPerBlob; row++ {
			copy(blob[row*CellSize:(row+1)*CellSize], matrix[col][row][:])
		}
		commitments[col] = KZGCommitmentFromBlob(blob)
	}
	return commitments
}

// ComputeCellProof generates a hash-based proof for a cell against the given
// commitment. The proof is SHA3-256(cell || commitment || row || col), providing:
//   - Data binding: proof is tied to specific cell content
//   - Commitment binding: proof is tied to the blob commitment
//   - Position binding: proof is tied to (row, col) position
//
// ⚠️ SECURITY NOTICE (P0-2): This is NOT a KZG opening proof. It is a hash-based
// scheme providing data integrity only — it cannot prove the cell is a valid
// evaluation of the committed polynomial. See KZGCommitmentFromBlob (blob_tx.go)
// for full security limitations. Danksharding must remain disabled until a real
// post-quantum commitment scheme is implemented.
func ComputeCellProof(cell Cell, row, col int, commitment KZGCommitment) (KZGProof, bool) {
	h := sha3.New256()
	h.Write(cell[:])
	h.Write(commitment[:])
	var posBuf [8]byte
	binary.BigEndian.PutUint32(posBuf[0:4], uint32(row))
	binary.BigEndian.PutUint32(posBuf[4:8], uint32(col))
	h.Write(posBuf[:])

	var proof KZGProof
	hash := h.Sum(nil)
	copy(proof[:32], hash)
	return proof, true
}

// VerifyCellProof verifies that the proof matches the cell, commitment, and
// position. Uses constant-time comparison to prevent timing attacks.
//
// ⚠️ SECURITY NOTICE (P0-2): Verifies hash equality only, NOT polynomial
// commitment validity. See ComputeCellProof security notice.
func VerifyCellProof(cell Cell, commitment KZGCommitment, proof KZGProof, row, col int) bool {
	expected, ok := ComputeCellProof(cell, row, col, commitment)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(proof[:], expected[:]) == 1
}

// ── P1-13: SparseBlobMatrix — sparse storage for BlobMatrixExtended ──
//
// BlobMatrixExtended is a fixed [MaxBlobColumnsExt]BlobCellsExtended array
// (12 × 8192 × 32 = 3,145,728 bytes ≈ 3 MB per entry). Most slots have far
// fewer than MaxBlobsPerBlock (6) blobs, yet the full 12-column matrix is
// allocated unconditionally.
//
// SparseBlobMatrix stores only the n original columns (1D-extended). The 2D
// parity columns (indices n..MaxBlobColumnsExt-1) are recomputed on demand via
// Lagrange interpolation — the same algorithm used by ExtendBlobs2D's column
// extension, but for a single row. The recomputation cost is O(n) per row
// (n ≤ 6), negligible for DAS sampling which is not on the consensus hot path.
//
// Memory savings (DoD: ≥ 50%):
//
//	n=1: 256 KB  instead of 3 MB  → 91.7% reduction
//	n=3: 768 KB  instead of 3 MB  → 75.0% reduction
//	n=6: 1.5 MB  instead of 3 MB  → 50.0% reduction (worst case, still meets DoD)
type SparseBlobMatrix struct {
	// OriginalColumns holds the n original columns, each 1D-extended
	// (CellsPerBlobExtended cells). Parity columns are recomputed on demand.
	OriginalColumns []BlobCellsExtended
	// OriginalCount is n (number of original blobs). Equals len(OriginalColumns).
	OriginalCount int
}

// NewSparseBlobMatrix creates a SparseBlobMatrix from a full BlobMatrixExtended,
// storing only the first originalCount columns. P1-13 (2026-07-14).
func NewSparseBlobMatrix(matrix BlobMatrixExtended, originalCount int) SparseBlobMatrix {
	if originalCount < 0 {
		originalCount = 0
	}
	if originalCount > MaxBlobColumnsExt {
		originalCount = MaxBlobColumnsExt
	}
	cols := make([]BlobCellsExtended, originalCount)
	for i := 0; i < originalCount; i++ {
		cols[i] = matrix[i]
	}
	return SparseBlobMatrix{
		OriginalColumns: cols,
		OriginalCount:   originalCount,
	}
}

// GetCell returns the cell at (row, col). If col < OriginalCount, returns the
// stored cell directly. If col >= OriginalCount, recomputes the 2D parity cell.
func (m *SparseBlobMatrix) GetCell(row, col int) Cell {
	if col < m.OriginalCount {
		return m.OriginalColumns[col][row]
	}
	return m.computeParityCell(row, col)
}

// GetCellPtr returns a pointer to the cell at (row, col). For original columns,
// returns a pointer into the stored array (zero allocation). For parity columns,
// returns a pointer to a newly computed cell (escapes to heap).
func (m *SparseBlobMatrix) GetCellPtr(row, col int) *Cell {
	if col < m.OriginalCount {
		return &m.OriginalColumns[col][row]
	}
	cell := m.computeParityCell(row, col)
	return &cell
}

// computeParityCell computes the 2D parity cell at (row, col) using Lagrange
// interpolation over the original columns. Same algorithm as ExtendBlobs2D's
// column extension, but for a single row. P1-13 (2026-07-14).
func (m *SparseBlobMatrix) computeParityCell(row, col int) Cell {
	n := m.OriginalCount
	if n == 0 {
		return Cell{}
	}
	if n == 1 {
		// Degree-0 polynomial: all parity = original.
		return m.OriginalColumns[0][row]
	}

	y := uint16(col + 1) // evaluation point for this parity column

	// num = Π_{i=0}^{n-1} (y − (i+1))
	num := uint16(1)
	for i := 0; i < n; i++ {
		num = gf16Mul(num, y^uint16(i+1))
	}

	var parity Cell
	for j := 0; j < n; j++ {
		xj := uint16(j + 1)
		diff := y ^ xj
		w, _ := gf16Div(num, diff)

		// denom[j] = Π_{i≠j} (x_j − x_i)
		d := uint16(1)
		for i := 0; i < n; i++ {
			if i != j {
				d = gf16Mul(d, xj^uint16(i+1))
			}
		}
		w, _ = gf16Div(w, d)

		srcCell := m.OriginalColumns[j][row]
		for k := 0; k < CellSize; k += 2 {
			elem := binary.BigEndian.Uint16(srcCell[k:])
			pe := binary.BigEndian.Uint16(parity[k:])
			pe ^= gf16Mul(elem, w)
			binary.BigEndian.PutUint16(parity[k:], pe)
		}
	}
	return parity
}

// ToBlobMatrixExtended reconstructs the full BlobMatrixExtended from the sparse
// representation. Used for backward compatibility and tests. P1-13.
func (m *SparseBlobMatrix) ToBlobMatrixExtended() BlobMatrixExtended {
	var matrix BlobMatrixExtended
	for i := 0; i < m.OriginalCount && i < MaxBlobColumnsExt; i++ {
		matrix[i] = m.OriginalColumns[i]
	}
	for col := m.OriginalCount; col < MaxBlobColumnsExt; col++ {
		for row := 0; row < CellsPerBlobExtended; row++ {
			matrix[col][row] = m.computeParityCell(row, col)
		}
	}
	return matrix
}

// MemoryBytes returns the actual memory used by the sparse representation.
// This is n × CellsPerBlobExtended × CellSize bytes (original columns only).
func (m *SparseBlobMatrix) MemoryBytes() int64 {
	return int64(len(m.OriginalColumns)) * int64(CellsPerBlobExtended) * int64(CellSize)
}
