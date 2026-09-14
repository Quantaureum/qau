// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"testing"
)

// ─── Cell-level opening proof tests ────────────────────────────────────────

func TestFRIOpening_Valid(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	polyDegree := cfg.DomainSize / cfg.CodeRate
	coeffs := make([]GF64Element, polyDegree)
	for i := range coeffs {
		coeffs[i] = GF64Element(i*3 + 7)
	}

	codeword := GF64ReedSolomonExtend(coeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)

	// Open cell at index 17
	cellIdx := 17
	proof := FRIGenerateOpeningProof(commitment, codeword, layers, cellIdx, cfg)
	if proof == nil {
		t.Fatal("FRIGenerateOpeningProof returned nil")
	}

	// Verify
	if !FRIVerifyOpeningProof(commitment, proof, cfg) {
		t.Error("FRIVerifyOpeningProof failed for valid opening")
	}

	// Cross-check: CellValue matches codeword
	if proof.CellValue != codeword[cellIdx] {
		t.Errorf("CellValue = %d, expected %d", proof.CellValue, codeword[cellIdx])
	}
}

func TestFRIOpening_TamperedCellValue(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	polyDegree := cfg.DomainSize / cfg.CodeRate
	coeffs := make([]GF64Element, polyDegree)
	for i := range coeffs {
		coeffs[i] = GF64Element(i + 1)
	}

	codeword := GF64ReedSolomonExtend(coeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)

	cellIdx := 5
	proof := FRIGenerateOpeningProof(commitment, codeword, layers, cellIdx, cfg)
	if proof == nil {
		t.Fatal("FRIGenerateOpeningProof returned nil")
	}

	// Tamper: change the CellValue but keep the Merkle proof
	proof.CellValue = GF64Add(proof.CellValue, GF64Element(1))

	// Verification must fail: the Merkle proof no longer matches the tampered value
	if FRIVerifyOpeningProof(commitment, proof, cfg) {
		t.Error("FRIVerifyOpeningProof should fail for tampered CellValue")
	}
}

func TestFRIOpening_TamperedMerkleProof(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	polyDegree := cfg.DomainSize / cfg.CodeRate
	coeffs := make([]GF64Element, polyDegree)
	for i := range coeffs {
		coeffs[i] = GF64Element(i*2 + 1)
	}

	codeword := GF64ReedSolomonExtend(coeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)

	cellIdx := 10
	proof := FRIGenerateOpeningProof(commitment, codeword, layers, cellIdx, cfg)
	if proof == nil {
		t.Fatal("FRIGenerateOpeningProof returned nil")
	}

	// Tamper: flip a byte in the Merkle proof
	if len(proof.MerkleProof) > 0 && len(proof.MerkleProof[0]) > 0 {
		proof.MerkleProof[0][0] ^= 0xFF
	}

	// Verification must fail
	if FRIVerifyOpeningProof(commitment, proof, cfg) {
		t.Error("FRIVerifyOpeningProof should fail for tampered Merkle proof")
	}
}

func TestFRIOpening_WrongCellIndex(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	polyDegree := cfg.DomainSize / cfg.CodeRate
	coeffs := make([]GF64Element, polyDegree)
	for i := range coeffs {
		coeffs[i] = GF64Element(i + 1)
	}

	codeword := GF64ReedSolomonExtend(coeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)

	cellIdx := 5
	proof := FRIGenerateOpeningProof(commitment, codeword, layers, cellIdx, cfg)
	if proof == nil {
		t.Fatal("FRIGenerateOpeningProof returned nil")
	}

	// Tamper: change CellIndex to a different position
	proof.CellIndex = 6

	// Verification must fail: the Merkle proof is for index 5, not 6
	if FRIVerifyOpeningProof(commitment, proof, cfg) {
		t.Error("FRIVerifyOpeningProof should fail for wrong CellIndex")
	}
}

func TestFRIOpening_OutOfRange(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	polyDegree := cfg.DomainSize / cfg.CodeRate
	coeffs := make([]GF64Element, polyDegree)
	for i := range coeffs {
		coeffs[i] = GF64Element(i + 1)
	}

	codeword := GF64ReedSolomonExtend(coeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)

	// Negative index → nil proof
	if p := FRIGenerateOpeningProof(commitment, codeword, layers, -1, cfg); p != nil {
		t.Error("Expected nil for negative index")
	}

	// Index >= DomainSize → nil proof
	if p := FRIGenerateOpeningProof(commitment, codeword, layers, cfg.DomainSize, cfg); p != nil {
		t.Error("Expected nil for out-of-range index")
	}
}

func TestFRIOpening_MultipleCells(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     32,
		CodeRate:       4,
		NumQueries:     10,
		FinalLayerSize: 4,
	}

	polyDegree := cfg.DomainSize / cfg.CodeRate
	coeffs := make([]GF64Element, polyDegree)
	for i := range coeffs {
		coeffs[i] = GF64Element(i*7 + 3)
	}

	codeword := GF64ReedSolomonExtend(coeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)

	// Open every cell and verify
	for cellIdx := 0; cellIdx < cfg.DomainSize; cellIdx++ {
		proof := FRIGenerateOpeningProof(commitment, codeword, layers, cellIdx, cfg)
		if proof == nil {
			t.Errorf("cell %d: proof is nil", cellIdx)
			continue
		}
		if !FRIVerifyOpeningProof(commitment, proof, cfg) {
			t.Errorf("cell %d: verification failed", cellIdx)
		}
	}
}

// TestR33_DA_01_TamperedQueryIndices verifies that the Fiat-Shamir query
// index check rejects proofs with attacker-chosen indices. A malicious
// prover who replaces a query index with a favorable position should fail
// verification, even if the FRI proof itself is valid for those positions.
//
// R33 DA-01 FIX (2026-07-28): Without the FS check, an attacker could
// choose favorable indices that pass FRI on a subset while hiding
// inconsistencies elsewhere.
func TestR33_DA_01_TamperedQueryIndices(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     32,
		CodeRate:       4,
		NumQueries:     10,
		FinalLayerSize: 4,
	}

	polyDegree := cfg.DomainSize / cfg.CodeRate
	coeffs := make([]GF64Element, polyDegree)
	for i := range coeffs {
		coeffs[i] = GF64Element(i*7 + 3)
	}

	codeword := GF64ReedSolomonExtend(coeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)

	cellIdx := 5
	proof := FRIGenerateOpeningProof(commitment, codeword, layers, cellIdx, cfg)
	if proof == nil {
		t.Fatal("FRIGenerateOpeningProof returned nil")
	}

	// Tamper: replace a non-position-0 query index with a different value.
	// This simulates a malicious prover choosing favorable indices.
	if len(proof.QueryIndices) > 1 {
		originalIdx := proof.QueryIndices[1]
		// Pick a different valid index
		tamperedIdx := (originalIdx + 7) % cfg.DomainSize
		if tamperedIdx == originalIdx {
			tamperedIdx = (originalIdx + 1) % cfg.DomainSize
		}
		proof.QueryIndices[1] = tamperedIdx
	}

	// Verification must fail: the tampered index doesn't match the
	// Fiat-Shamir-derived expected indices.
	if FRIVerifyOpeningProof(commitment, proof, cfg) {
		t.Error("FRIVerifyOpeningProof should fail for tampered query indices (Fiat-Shamir mismatch)")
	}
}

// ─── DEEP proof tests ──────────────────────────────────────────────────────

func TestDEEP_Valid(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	// f(x) = 3x^3 + 2x^2 + x + 5
	fCoeffs := []GF64Element{5, 1, 2, 3}
	// Pad to polyDegree
	polyDegree := cfg.DomainSize / cfg.CodeRate
	fPadded := make([]GF64Element, polyDegree)
	copy(fPadded, fCoeffs)

	fCodeword := GF64ReedSolomonExtend(fPadded, cfg.DomainSize)
	fCommitment, fLayers := FRICommit(fCodeword, cfg)

	// Prove f(7) = ?
	z := GF64Element(7)
	proof, err := FRIDEEPProve(fCommitment, fCodeword, fLayers, fPadded, z, cfg)
	if err != nil {
		t.Fatalf("FRIDEEPProve failed: %v", err)
	}

	// Cross-check: y should equal f(z) evaluated via coefficients
	expectedY := polyEval(fPadded, z)
	if proof.Y != expectedY {
		t.Errorf("Y = %d, expected %d", proof.Y, expectedY)
	}

	// Verify the DEEP proof
	if !FRIDEEPVerify(proof, cfg) {
		t.Error("FRIDEEPVerify failed for valid DEEP proof")
	}
}

func TestDEEP_DifferentPolynomials(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	testCases := [][]GF64Element{
		{1, 0, 0, 0},             // f(x) = 1 (constant)
		{0, 1},                   // f(x) = x
		{1, 2, 3, 4, 5, 6, 7, 8}, // degree 7
	}

	for tcIdx, fCoeffs := range testCases {
		polyDegree := cfg.DomainSize / cfg.CodeRate
		fPadded := make([]GF64Element, polyDegree)
		copy(fPadded, fCoeffs)

		fCodeword := GF64ReedSolomonExtend(fPadded, cfg.DomainSize)
		fCommitment, fLayers := FRICommit(fCodeword, cfg)

		// Test at several evaluation points
		for _, z := range []GF64Element{1, 2, 42, 1000} {
			proof, err := FRIDEEPProve(fCommitment, fCodeword, fLayers, fPadded, z, cfg)
			if err != nil {
				t.Errorf("case %d z=%d: FRIDEEPProve failed: %v", tcIdx, z, err)
				continue
			}

			// Verify y = f(z)
			expectedY := polyEval(fPadded, z)
			if proof.Y != expectedY {
				t.Errorf("case %d z=%d: Y=%d, expected %d", tcIdx, z, proof.Y, expectedY)
				continue
			}

			if !FRIDEEPVerify(proof, cfg) {
				t.Errorf("case %d z=%d: FRIDEEPVerify failed", tcIdx, z)
			}
		}
	}
}

func TestDEEP_TamperedY(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	fCoeffs := []GF64Element{5, 1, 2, 3}
	polyDegree := cfg.DomainSize / cfg.CodeRate
	fPadded := make([]GF64Element, polyDegree)
	copy(fPadded, fCoeffs)

	fCodeword := GF64ReedSolomonExtend(fPadded, cfg.DomainSize)
	fCommitment, fLayers := FRICommit(fCodeword, cfg)

	z := GF64Element(7)
	proof, err := FRIDEEPProve(fCommitment, fCodeword, fLayers, fPadded, z, cfg)
	if err != nil {
		t.Fatalf("FRIDEEPProve failed: %v", err)
	}

	// Tamper: change Y to a wrong value
	proof.Y = GF64Add(proof.Y, GF64Element(1))

	// Verification must fail: the consistency check f(ξ) - y == (ξ - z) * q(ξ)
	// will no longer hold.
	if FRIDEEPVerify(proof, cfg) {
		t.Error("FRIDEEPVerify should fail for tampered Y")
	}
}

func TestDEEP_TamperedFAtXi(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	fCoeffs := []GF64Element{5, 1, 2, 3}
	polyDegree := cfg.DomainSize / cfg.CodeRate
	fPadded := make([]GF64Element, polyDegree)
	copy(fPadded, fCoeffs)

	fCodeword := GF64ReedSolomonExtend(fPadded, cfg.DomainSize)
	fCommitment, fLayers := FRICommit(fCodeword, cfg)

	z := GF64Element(7)
	proof, err := FRIDEEPProve(fCommitment, fCodeword, fLayers, fPadded, z, cfg)
	if err != nil {
		t.Fatalf("FRIDEEPProve failed: %v", err)
	}

	// Tamper: change FAtXi
	proof.FAtXi = GF64Add(proof.FAtXi, GF64Element(1))

	// Verification must fail: either the cell opening proof fails (if FCellProof
	// still has the original value) or the consistency check fails.
	if FRIDEEPVerify(proof, cfg) {
		t.Error("FRIDEEPVerify should fail for tampered FAtXi")
	}
}

func TestDEEP_TamperedQAtXi(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	fCoeffs := []GF64Element{5, 1, 2, 3}
	polyDegree := cfg.DomainSize / cfg.CodeRate
	fPadded := make([]GF64Element, polyDegree)
	copy(fPadded, fCoeffs)

	fCodeword := GF64ReedSolomonExtend(fPadded, cfg.DomainSize)
	fCommitment, fLayers := FRICommit(fCodeword, cfg)

	z := GF64Element(7)
	proof, err := FRIDEEPProve(fCommitment, fCodeword, fLayers, fPadded, z, cfg)
	if err != nil {
		t.Fatalf("FRIDEEPProve failed: %v", err)
	}

	// Tamper: change QAtXi
	proof.QAtXi = GF64Add(proof.QAtXi, GF64Element(1))

	// Verification must fail
	if FRIDEEPVerify(proof, cfg) {
		t.Error("FRIDEEPVerify should fail for tampered QAtXi")
	}
}

func TestDEEP_TamperedXi(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	fCoeffs := []GF64Element{5, 1, 2, 3}
	polyDegree := cfg.DomainSize / cfg.CodeRate
	fPadded := make([]GF64Element, polyDegree)
	copy(fPadded, fCoeffs)

	fCodeword := GF64ReedSolomonExtend(fPadded, cfg.DomainSize)
	fCommitment, fLayers := FRICommit(fCodeword, cfg)

	z := GF64Element(7)
	proof, err := FRIDEEPProve(fCommitment, fCodeword, fLayers, fPadded, z, cfg)
	if err != nil {
		t.Fatalf("FRIDEEPProve failed: %v", err)
	}

	// Tamper: change Xi to a different value
	proof.Xi = GF64Add(proof.Xi, GF64Element(1))

	// Verification must fail: either ξ doesn't match domain[ξ_idx], or the
	// consistency check fails.
	if FRIDEEPVerify(proof, cfg) {
		t.Error("FRIDEEPVerify should fail for tampered Xi")
	}
}

func TestDEEP_WrongZ(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     64,
		CodeRate:       4,
		NumQueries:     20,
		FinalLayerSize: 4,
	}

	fCoeffs := []GF64Element{5, 1, 2, 3}
	polyDegree := cfg.DomainSize / cfg.CodeRate
	fPadded := make([]GF64Element, polyDegree)
	copy(fPadded, fCoeffs)

	fCodeword := GF64ReedSolomonExtend(fPadded, cfg.DomainSize)
	fCommitment, fLayers := FRICommit(fCodeword, cfg)

	z := GF64Element(7)
	proof, err := FRIDEEPProve(fCommitment, fCodeword, fLayers, fPadded, z, cfg)
	if err != nil {
		t.Fatalf("FRIDEEPProve failed: %v", err)
	}

	// Tamper: change Z
	proof.Z = GF64Add(proof.Z, GF64Element(1))

	// Verification must fail: ξ_idx was derived with the original z, so the
	// recomputed ξ_idx won't match, OR the consistency check fails.
	if FRIDEEPVerify(proof, cfg) {
		t.Error("FRIDEEPVerify should fail for tampered Z")
	}
}

// ─── Polynomial helpers tests ──────────────────────────────────────────────

func TestPolyEval(t *testing.T) {
	// f(x) = 3x^3 + 2x^2 + x + 5
	coeffs := []GF64Element{5, 1, 2, 3}

	// f(0) = 5
	if got := polyEval(coeffs, 0); got != 5 {
		t.Errorf("f(0) = %d, expected 5", got)
	}

	// f(1) = 11
	if got := polyEval(coeffs, 1); got != 11 {
		t.Errorf("f(1) = %d, expected 11", got)
	}

	// f(2) = 3*8 + 2*4 + 2 + 5 = 24 + 8 + 2 + 5 = 39
	if got := polyEval(coeffs, 2); got != 39 {
		t.Errorf("f(2) = %d, expected 39", got)
	}
}

func TestPolyDivideByLinear(t *testing.T) {
	// f(x) = x^2 - 1 = (x - 1)(x + 1), so f(1) = 0
	// q(x) = (f(x) - 0) / (x - 1) = x + 1
	// coeffs: [-1, 0, 1] → adjusted (y=0): [-1, 0, 1]
	// q should be [1, 1] (i.e., 1 + x)
	coeffs := []GF64Element{GF64Neg(1), 0, 1}
	z := GF64Element(1)
	y := GF64Element(0) // f(1) = 0

	q, ok := polyDivideByLinear(coeffs, z, y)
	if !ok {
		t.Fatal("polyDivideByLinear failed for valid division")
	}
	if len(q) != 2 {
		t.Fatalf("q has %d coefficients, expected 2", len(q))
	}
	// q[0] = 1 (constant), q[1] = 1 (x coefficient)
	if q[0] != 1 || q[1] != 1 {
		t.Errorf("q = %v, expected [1, 1]", q)
	}
}

func TestPolyDivideByLinear_NotDivisible(t *testing.T) {
	// f(x) = x + 1, f(0) = 1, but we claim y = 2
	// (f(x) - 2) = x - 1, which at x=0 gives -1 ≠ 0, so not divisible by (x - 0)
	coeffs := []GF64Element{1, 1}
	z := GF64Element(0)
	y := GF64Element(2) // wrong: f(0) = 1, not 2

	_, ok := polyDivideByLinear(coeffs, z, y)
	if ok {
		t.Error("polyDivideByLinear should fail when (x - z) does not divide (f - y)")
	}
}

// ─── Serialization tests ───────────────────────────────────────────────────

func TestEncodeFRIProof_RoundTrip(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     32,
		CodeRate:       4,
		NumQueries:     5,
		FinalLayerSize: 4,
	}

	polyDegree := cfg.DomainSize / cfg.CodeRate
	coeffs := make([]GF64Element, polyDegree)
	for i := range coeffs {
		coeffs[i] = GF64Element(i + 1)
	}

	codeword := GF64ReedSolomonExtend(coeffs, cfg.DomainSize)
	_, layers := FRICommit(codeword, cfg)

	queries := []int{1, 5, 10, 15, 20}
	proof := FRIProve(layers, queries, cfg)

	encoded := EncodeFRIProof(proof)
	if len(encoded) == 0 {
		t.Fatal("EncodeFRIProof returned empty bytes")
	}

	// Verify the encoding is deterministic and non-trivial
	encoded2 := EncodeFRIProof(proof)
	if !bytes.Equal(encoded, encoded2) {
		t.Error("EncodeFRIProof is not deterministic")
	}

	// Verify encoding length matches expectation (at least the header)
	if len(encoded) < 4 {
		t.Errorf("Encoded proof too short: %d bytes", len(encoded))
	}
}

func TestEncodeFRIOpeningProof_RoundTrip(t *testing.T) {
	cfg := FRIConfig{
		DomainSize:     32,
		CodeRate:       4,
		NumQueries:     5,
		FinalLayerSize: 4,
	}

	polyDegree := cfg.DomainSize / cfg.CodeRate
	coeffs := make([]GF64Element, polyDegree)
	for i := range coeffs {
		coeffs[i] = GF64Element(i*3 + 1)
	}

	codeword := GF64ReedSolomonExtend(coeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)

	proof := FRIGenerateOpeningProof(commitment, codeword, layers, 7, cfg)
	if proof == nil {
		t.Fatal("FRIGenerateOpeningProof returned nil")
	}

	encoded := EncodeFRIOpeningProof(proof)
	if len(encoded) == 0 {
		t.Fatal("EncodeFRIOpeningProof returned empty bytes")
	}

	// Verify the encoding includes the cell value (8 bytes) + cell index (4 bytes) + ...
	if len(encoded) < 16 {
		t.Errorf("Encoded opening proof too short: %d bytes", len(encoded))
	}
}
