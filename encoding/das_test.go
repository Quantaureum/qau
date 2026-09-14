// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"math"
	"testing"
)

// ── P2-2: DAS sampling unit tests ──
//
// Focus areas (per 04-da-committee.md P2-2):
//   1. computeConfidence boundary conditions and monotonicity
//   2. calculateSamplesNeeded derivation and minimum bound
//   3. DASVerifier.VerifyDataAvailability rejection paths
//
// These tests complement the basic coverage in danksharding_test.go by
// exercising edge cases, threshold boundaries, and negative paths.

// TestP2_2_ComputeConfidence_Boundaries verifies the DA-R5-06 (2026-07-17)
// binomial upper bound confidence function.
//
// DA-R5-06 replaced the step-function inflation (which mapped observedRate
// ≥0.99 → 0.9999 regardless of sample count) with a sample-count-aware
// binomial bound:
//
//   - If any sample failed (success < total): confidence = observedRate
//     (no inflation — failed samples indicate potential unavailability).
//   - If all samples succeeded (success == total): confidence = 1 - 0.5^k
//     where k = success (binomial upper bound under H0: data unavailable,
//     single-sample hit probability ≤ 0.5).
//   - total == 0 or success == 0: confidence = 0.
//
// P2-2 (2026-07-15); DA-R5-06 (2026-07-17) rewritten for binomial bound.
func TestP2_2_ComputeConfidence_Boundaries(t *testing.T) {
	client := NewDASClient(DefaultDASConfig())

	tests := []struct {
		name           string
		success, total int
		wantConf       float64
	}{
		// All samples succeeded → 1 - 0.5^k (binomial upper bound).
		// 1 - 0.5^100 ≈ 1.0 in float64 (0.5^100 = 7.9e-31 < machine epsilon).
		{"100/100 → ~1.0", 100, 100, 1.0 - math.Pow(0.5, 100)},
		{"10/10 → 1-0.5^10", 10, 10, 1.0 - math.Pow(0.5, 10)},
		{"14/14 → 1-0.5^14 (>0.9999)", 14, 14, 1.0 - math.Pow(0.5, 14)},
		{"990/1000 (has failures) → 0.99", 990, 1000, 0.99},

		// Has failed samples → confidence = observedRate (no inflation).
		{"99/100 → 0.99 (observed, no inflation)", 99, 100, 0.99},
		{"95/100 → 0.95", 95, 100, 0.95},
		{"97/100 → 0.97", 97, 100, 0.97},
		{"98/100 → 0.98", 98, 100, 0.98},
		{"90/100 → 0.90", 90, 100, 0.90},
		{"93/100 → 0.93", 93, 100, 0.93},
		{"94/100 → 0.94", 94, 100, 0.94},
		{"75/100 → 0.75", 75, 100, 0.75},
		{"80/100 → 0.80", 80, 100, 0.80},
		{"89/100 → 0.89", 89, 100, 0.89},
		{"50/100 → 0.50", 50, 100, 0.50},
		{"60/100 → 0.60", 60, 100, 0.60},
		{"74/100 → 0.74", 74, 100, 0.74},
		{"49/100 → 0.49", 49, 100, 0.49},
		{"25/100 → 0.25", 25, 100, 0.25},
		{"1/100 → 0.01", 1, 100, 0.01},
		{"0/100 → 0.0", 0, 100, 0.0},

		// Edge: 0/0 → 0 (avoid div-by-zero)
		{"0/0 → 0.0", 0, 0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.computeConfidence(tt.success, tt.total)
			if got != tt.wantConf {
				t.Errorf("computeConfidence(%d, %d) = %f, want %f",
					tt.success, tt.total, got, tt.wantConf)
			}
		})
	}
}

// TestDA_R5_06_ComputeConfidence_BinomialProperties verifies the key
// properties of the DA-R5-06 binomial upper bound:
//  1. All-success confidence is strictly increasing in k (more samples →
//     higher confidence) within the float64-representable range, fixing the
//     "99/100 == 990/1000 == 0.9999" decoupling. For large k (≥54),
//     1 - 0.5^k saturates to 1.0 in float64 (0.5^54 ≈ 5.55e-17 < machine
//     epsilon near 1.0 ≈ 1.11e-16), so we only assert strict monotonicity up
//     to k=53 and non-decreasing (≥) beyond that.
//  2. Any-failure confidence is bounded by observedRate (no inflation).
//  3. 14 all-success samples is the minimum to reach MinConfidence=0.9999
//     (1 - 0.5^14 ≈ 0.99994 > 0.9999; 1 - 0.5^13 ≈ 0.99988 < 0.9999).
//
// DA-R5-06 (2026-07-17)
func TestDA_R5_06_ComputeConfidence_BinomialProperties(t *testing.T) {
	client := NewDASClient(DefaultDASConfig())

	// Property 1a: All-success confidence strictly increases with k, for k
	// in the float64-representable range (1..53). Beyond k≈53, 0.5^k drops
	// below machine epsilon near 1.0 and 1-tiny rounds to exactly 1.0, so
	// strict monotonicity cannot be observed in float64 even though the
	// mathematical value is still strictly increasing.
	const strictMonotonicityLimit = 53 // 0.5^53 ≈ 1.11e-16 ≈ machine epsilon
	prev := 0.0
	for k := 1; k <= strictMonotonicityLimit; k++ {
		conf := client.computeConfidence(k, k)
		if conf <= prev {
			t.Errorf("all-success confidence not strictly increasing: k=%d conf=%f <= prev=%f", k, conf, prev)
		}
		prev = conf
	}

	// Property 1b: For k beyond the float64-representable range, confidence
	// is non-decreasing (may plateau at 1.0 due to float64 saturation).
	for k := strictMonotonicityLimit + 1; k <= 100; k++ {
		conf := client.computeConfidence(k, k)
		if conf < prev {
			t.Errorf("all-success confidence decreased: k=%d conf=%f < prev=%f", k, conf, prev)
		}
		prev = conf
	}

	// Property 2: Any-failure confidence == observedRate (no inflation).
	// 99/100 must be 0.99, NOT 0.9999 (the old step-function value).
	if conf := client.computeConfidence(99, 100); conf != 0.99 {
		t.Errorf("99/100 = %f, want 0.99 (observed rate, no inflation)", conf)
	}
	// 990/1000 must be 0.99, NOT 0.9999.
	if conf := client.computeConfidence(990, 1000); conf != 0.99 {
		t.Errorf("990/1000 = %f, want 0.99 (observed rate, no inflation)", conf)
	}

	// Property 3: MinConfidence threshold.
	// 13/13 ≈ 0.99988 < 0.9999; 14/14 ≈ 0.99994 > 0.9999.
	if conf := client.computeConfidence(13, 13); conf >= DASMinConfidenceLevel {
		t.Errorf("13/13 = %f, want < %f (MinConfidence)", conf, DASMinConfidenceLevel)
	}
	if conf := client.computeConfidence(14, 14); conf < DASMinConfidenceLevel {
		t.Errorf("14/14 = %f, want >= %f (MinConfidence)", conf, DASMinConfidenceLevel)
	}
}

// TestP2_2_ComputeConfidence_Monotonicity verifies that increasing the
// success count (with fixed total) never decreases the confidence.
//
// P2-2 (2026-07-15)
func TestP2_2_ComputeConfidence_Monotonicity(t *testing.T) {
	client := NewDASClient(DefaultDASConfig())

	const total = 1000
	prevConf := 0.0
	for success := 0; success <= total; success += 10 {
		conf := client.computeConfidence(success, total)
		if conf < prevConf {
			t.Errorf("non-monotonic at success=%d: conf=%f < prev=%f",
				success, conf, prevConf)
		}
		prevConf = conf
	}
}

// TestP2_2_CalculateSamplesNeeded_DefaultAndScaling verifies that
// calculateSamplesNeeded returns 75 (default) for small totalCells and
// scales as totalCells/100 when the ratio drops below 1%.
//
// Logic:
//   - totalCells ≤ 7500 → ratio ≥ 0.01 → stays 75 (default)
//   - totalCells > 7500 → ratio < 0.01 → totalCells/100, min 30
//
// P2-2 (2026-07-15)
func TestP2_2_CalculateSamplesNeeded_DefaultAndScaling(t *testing.T) {
	client := NewDASClient(DefaultDASConfig())

	tests := []struct {
		name        string
		totalCells  int
		wantSamples int
	}{
		// R40-P2-03 (2026-08-03): the `totalCells=0 → 75` case below was
		// testing the pre-R40-P2-03 behavior where a zero-cell blob fell
		// through to the default-sample return value — pointless and a
		// div-by-zero hazard if any downstream call returned samples > 0
		// against a 0-cell blob. The R40-P2-03 hardening short-circuits
		// `calculateSamplesNeeded` to return 0 when `totalCells <= 0`. The
		// parametric case below now asserts that contract.
		{"totalCells=0 → 0 (R40-P2-03 short-circuit)", 0, 0},

		// Negative cells — defensive: auditor noted uint32-overflow could
		// deliver a negative value through int. Same short-circuit returns 0.
		{"totalCells=-1 → 0 (R40-P2-03 short-circuit)", -1, 0},

		// Small: ratio = 75/100 = 0.75 ≥ 0.01 → stays 75
		{"totalCells=100 → 75", 100, 75},

		// Boundary: ratio = 75/7500 = 0.01, NOT < 0.01 → stays 75
		{"totalCells=7500 → 75 (boundary)", 7500, 75},

		// Just above boundary: ratio = 75/7501 ≈ 0.009998 < 0.01 → 7501/100 = 75
		{"totalCells=7501 → 75", 7501, 75},

		// Scaling kicks in: 10000/100 = 100
		{"totalCells=10000 → 100", 10000, 100},

		// Larger: 100000/100 = 1000
		{"totalCells=100000 → 1000", 100000, 1000},

		// Very large: 1000000/100 = 10000
		{"totalCells=1000000 → 10000", 1000000, 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.calculateSamplesNeeded(tt.totalCells)
			if got != tt.wantSamples {
				t.Errorf("calculateSamplesNeeded(%d) = %d, want %d",
					tt.totalCells, got, tt.wantSamples)
			}
		})
	}
}

// TestP2_2_CalculateSamplesNeeded_AlwaysAtLeastDefault verifies that
// calculateSamplesNeeded never returns less than 75 for any POSITIVE
// totalCells. The internal `if samples < 30` guard is dead code for the
// ratio<0.01 path (since totalCells>7500 implies totalCells/100≥75), but
// this test ensures the invariant holds across a wide range.
//
// R40-P2-03 (2026-08-03): the loop now starts at totalCells=1 (not 0). A
// zero-cell blob legitimately returns 0 samples under the R40-P2-03
// zero-/negative-cell short-circuit — "always at least default" only
// holds for `totalCells > 0`. The `totalCells=0` case is covered by the
// dedicated parametric test TestP2_2_CalculateSamplesNeeded_DefaultAndScaling.
//
// P2-2 (2026-07-15); R40-P2-03 (2026-08-03)
func TestP2_2_CalculateSamplesNeeded_AlwaysAtLeastDefault(t *testing.T) {
	client := NewDASClient(DefaultDASConfig())

	// Test a wide range including edge cases around the 7500 boundary.
	// R40-P2-03: start at 1 — `totalCells=0` legitimately returns 0 under
	// the short-circuit guard (out of scope of the "≥ default" invariant).
	for totalCells := 1; totalCells <= 20000; totalCells += 17 {
		samples := client.calculateSamplesNeeded(totalCells)
		if samples < 30 {
			t.Errorf("calculateSamplesNeeded(%d) = %d, want ≥ 30", totalCells, samples)
		}
	}
}

// TestP2_2_VerifyDataAvailability_TamperedCell verifies that the verifier
// rejects a sample whose cell has been tampered with (single byte flipped).
// The proof was computed for the original cell, so verification must fail
// for the tampered cell.
//
// DA-R5-06 (2026-07-17): Updated to use 14 untampered samples (the minimum
// for binomial bound 1 - 0.5^14 ≈ 0.99994 ≥ MinConfidence=0.9999). A single
// untampered sample now yields confidence 0.5 (1 - 0.5^1), which is correct
// — one sample is insufficient evidence of availability.
//
// P2-2 (2026-07-15); DA-R5-06 (2026-07-17)
func TestP2_2_VerifyDataAvailability_TamperedCell(t *testing.T) {
	verifier := NewDASVerifier(DefaultDASConfig())

	// Build a matrix with known data.
	var matrix BlobMatrixExtended
	for row := 0; row < CellsPerBlobExtended; row++ {
		for k := 0; k < CellSize; k++ {
			matrix[0][row][k] = byte(row*10 + k)
		}
	}
	commitments := ComputeKZGCommitmentsForMatrix(matrix, 1)
	commitment := commitments[0]

	// Create one valid sample.
	cell := matrix[0][0]
	proof, _ := ComputeCellProof(cell, 0, 0, commitment)
	sample := DASSampleResponse{
		Slot:      1,
		BlobIndex: 0,
		CellRow:   0,
		CellCol:   0,
		Cell:      cell,
		Proof:     proof,
	}

	// Tamper: flip a byte in the cell.
	tamperedSample := sample
	tamperedSample.Cell[0] ^= 0xFF

	available, confidence := verifier.VerifyDataAvailability(1, commitments, []DASSampleResponse{tamperedSample})
	if available {
		t.Error("tampered cell should not be available")
	}
	if confidence > 0.5 {
		t.Errorf("confidence for tampered cell should be low, got %f", confidence)
	}

	// Sanity check: 14 untampered samples should verify and meet the
	// MinConfidence threshold (1 - 0.5^14 ≈ 0.99994 > 0.9999).
	untamperedSamples := make([]DASSampleResponse, 14)
	for i := 0; i < 14; i++ {
		row := i % CellsPerBlobExtended
		c := matrix[0][row]
		p, _ := ComputeCellProof(c, row, 0, commitment)
		untamperedSamples[i] = DASSampleResponse{
			Slot:      1,
			BlobIndex: 0,
			CellRow:   row,
			CellCol:   0,
			Cell:      c,
			Proof:     p,
		}
	}
	availableOK, confOK := verifier.VerifyDataAvailability(1, commitments, untamperedSamples)
	if !availableOK {
		t.Error("14 untampered samples should be available")
	}
	if confOK < DASMinConfidenceLevel {
		t.Errorf("14 untampered confidence should be >= %f, got %f", DASMinConfidenceLevel, confOK)
	}
}

// TestP2_2_VerifyDataAvailability_WrongCommitment verifies that the verifier
// rejects samples when the commitment doesn't match the cell data.
//
// P2-2 (2026-07-15)
func TestP2_2_VerifyDataAvailability_WrongCommitment(t *testing.T) {
	verifier := NewDASVerifier(DefaultDASConfig())

	// Build a matrix and compute the real commitment.
	var matrix BlobMatrixExtended
	for row := 0; row < CellsPerBlobExtended; row++ {
		for k := 0; k < CellSize; k++ {
			matrix[0][row][k] = byte(row*10 + k)
		}
	}
	realCommitments := ComputeKZGCommitmentsForMatrix(matrix, 1)

	// Create a sample with a valid cell + proof for the REAL commitment.
	cell := matrix[0][0]
	proof, _ := ComputeCellProof(cell, 0, 0, realCommitments[0])
	sample := DASSampleResponse{
		Slot:      1,
		BlobIndex: 0,
		CellRow:   0,
		CellCol:   0,
		Cell:      cell,
		Proof:     proof,
	}

	// Use a WRONG commitment (all zeros) — verification must fail.
	var wrongCommitments []KZGCommitment
	wrongCommitments = append(wrongCommitments, KZGCommitment{})

	available, confidence := verifier.VerifyDataAvailability(1, wrongCommitments, []DASSampleResponse{sample})
	if available {
		t.Error("sample with wrong commitment should not be available")
	}
	if confidence > 0 {
		t.Errorf("confidence with wrong commitment should be 0, got %f", confidence)
	}
}

// TestP2_2_VerifyDataAvailability_BlobIndexOutOfRange verifies that samples
// with BlobIndex >= len(commitments) are silently skipped (not counted as
// success or failure beyond reducing the effective success rate).
//
// P2-2 (2026-07-15)
func TestP2_2_VerifyDataAvailability_BlobIndexOutOfRange(t *testing.T) {
	verifier := NewDASVerifier(DefaultDASConfig())

	var matrix BlobMatrixExtended
	for row := 0; row < CellsPerBlobExtended; row++ {
		for k := 0; k < CellSize; k++ {
			matrix[0][row][k] = byte(row*10 + k)
		}
	}
	commitments := ComputeKZGCommitmentsForMatrix(matrix, 1) // len=1

	cell := matrix[0][0]
	proof, _ := ComputeCellProof(cell, 0, 0, commitments[0])

	// Sample with BlobIndex=5, but len(commitments)=1 → skipped.
	outOfRangeSample := DASSampleResponse{
		Slot:      1,
		BlobIndex: 5,
		CellRow:   0,
		CellCol:   0,
		Cell:      cell,
		Proof:     proof,
	}

	available, confidence := verifier.VerifyDataAvailability(1, commitments, []DASSampleResponse{outOfRangeSample})
	if available {
		t.Error("out-of-range BlobIndex should not be available")
	}
	// successCount=0, total=1 → observedRate=0 → confidence=0
	if confidence != 0 {
		t.Errorf("confidence for all-skipped samples should be 0, got %f", confidence)
	}
}

// TestP2_2_VerifyDataAvailability_PartialInvalid verifies that when some
// samples are valid and some are invalid, the confidence drops proportionally
// and availability is determined by whether confidence meets the threshold.
//
// P2-2 (2026-07-15)
func TestP2_2_VerifyDataAvailability_PartialInvalid(t *testing.T) {
	verifier := NewDASVerifier(DefaultDASConfig())

	var matrix BlobMatrixExtended
	for row := 0; row < CellsPerBlobExtended; row++ {
		for k := 0; k < CellSize; k++ {
			matrix[0][row][k] = byte(row*10 + k)
		}
	}
	commitments := ComputeKZGCommitmentsForMatrix(matrix, 1)
	commitment := commitments[0]

	// Build 10 valid samples.
	var samples []DASSampleResponse
	for i := 0; i < 10; i++ {
		cell := matrix[0][i]
		proof, _ := ComputeCellProof(cell, i, 0, commitment)
		samples = append(samples, DASSampleResponse{
			Slot:      1,
			BlobIndex: 0,
			CellRow:   i,
			CellCol:   0,
			Cell:      cell,
			Proof:     proof,
		})
	}

	// Tamper 5 of the 10 samples.
	for i := 0; i < 5; i++ {
		samples[i].Cell[0] ^= 0xFF
	}

	available, confidence := verifier.VerifyDataAvailability(1, commitments, samples)
	// DA-R5-06 (2026-07-17): 5/10 has failed samples → confidence = observedRate = 0.5
	// (no inflation). Below MinConfidence=0.9999 → not available.
	if available {
		t.Error("50% valid should not meet 0.9999 threshold")
	}
	if confidence != 0.5 {
		t.Errorf("confidence for 5/10 valid should be 0.5, got %f", confidence)
	}
}

// TestP2_2_VerifyDataAvailability_BelowThreshold verifies that a high but
// sub-threshold success rate (e.g., 98%) results in available=false because
// confidence (0.98) < MinConfidence (0.9999).
//
// DA-R5-06 (2026-07-17): With the binomial bound, 98/100 has failed samples →
// confidence = observedRate = 0.98 (no inflation to 0.99).
//
// P2-2 (2026-07-15); DA-R5-06 (2026-07-17)
func TestP2_2_VerifyDataAvailability_BelowThreshold(t *testing.T) {
	verifier := NewDASVerifier(DefaultDASConfig())

	var matrix BlobMatrixExtended
	for row := 0; row < CellsPerBlobExtended; row++ {
		for k := 0; k < CellSize; k++ {
			matrix[0][row][k] = byte(row*10 + k)
		}
	}
	commitments := ComputeKZGCommitmentsForMatrix(matrix, 1)
	commitment := commitments[0]

	// Build 100 samples, 98 valid + 2 tampered.
	var samples []DASSampleResponse
	for i := 0; i < 100; i++ {
		cell := matrix[0][i%CellsPerBlobExtended]
		proof, _ := ComputeCellProof(cell, i%CellsPerBlobExtended, 0, commitment)
		s := DASSampleResponse{
			Slot:      1,
			BlobIndex: 0,
			CellRow:   i % CellsPerBlobExtended,
			CellCol:   0,
			Cell:      cell,
			Proof:     proof,
		}
		// Tamper the first 2.
		if i < 2 {
			s.Cell[0] ^= 0xFF
		}
		samples = append(samples, s)
	}

	available, confidence := verifier.VerifyDataAvailability(1, commitments, samples)
	// 98/100 has failed samples → confidence = 0.98 (observed rate, no inflation)
	// < 0.9999 → not available
	if available {
		t.Error("98% valid (confidence 0.98) should not meet 0.9999 threshold")
	}
	if confidence != 0.98 {
		t.Errorf("confidence for 98/100 valid should be 0.98, got %f", confidence)
	}
}

// TestP2_2_VerifyDataAvailability_AllInvalid verifies that when all samples
// fail verification, available=false and confidence=0.
//
// P2-2 (2026-07-15)
func TestP2_2_VerifyDataAvailability_AllInvalid(t *testing.T) {
	verifier := NewDASVerifier(DefaultDASConfig())

	var matrix BlobMatrixExtended
	for row := 0; row < CellsPerBlobExtended; row++ {
		for k := 0; k < CellSize; k++ {
			matrix[0][row][k] = byte(row*10 + k)
		}
	}
	commitments := ComputeKZGCommitmentsForMatrix(matrix, 1)

	// Build 10 samples, all tampered.
	var samples []DASSampleResponse
	for i := 0; i < 10; i++ {
		cell := matrix[0][i]
		// Use an all-zero proof (will fail verification).
		samples = append(samples, DASSampleResponse{
			Slot:      1,
			BlobIndex: 0,
			CellRow:   i,
			CellCol:   0,
			Cell:      cell,
			Proof:     KZGProof{}, // zero proof → verification fails
		})
	}

	available, confidence := verifier.VerifyDataAvailability(1, commitments, samples)
	if available {
		t.Error("all-invalid samples should not be available")
	}
	if confidence != 0 {
		t.Errorf("confidence for all-invalid should be 0, got %f", confidence)
	}
}
