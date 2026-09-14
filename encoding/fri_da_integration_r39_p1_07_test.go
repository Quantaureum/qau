// Quantaureum Node source, version 1.0.0.
// R39-P1-07 + R39-P2-03 (2026-08-02) regression tests.
//
// FRIDAVerifyCell previously had NO lower-bound enforcement on the
// attacker-controlled commitment fields NumQueries and FinalLayerSize:
//
//   - NumQueries == 0 lets an attacker forge ANY commitment, because
//     "verify zero FRI queries" reduces the soundness check to "the
//     commitment opens" (the query loop is skipped and the proof
//     succeeds trivially). DecodeFRIDACommitment's `< 0` cap only triggers
//     for negatives (impossible for unsigned getUint32), so 0 falls
//     through. P1-07 closes this at the verifier entry.
//   - FinalLayerSize == 1 lets an attacker stop the FR.I folding as soon
//     as the domain shrinks to one element, avoiding the degree-bound
//     final check. ValidateFRIConfigForProduction already enforces >= 2
//     for production commitments; P2-03 applies the same threshold at the
//     verifier so attackers can't bypass it by assembling a commitment
//     outside the validated-config path.
//
// These tests pin both gates directly against FRIDAVerifyCell.
package encoding

import (
	"crypto/sha256"
	"testing"
)

// r39P1P07MakeCellWithIndex assembles a minimal "well-formed" cell+proof
// suggesting a fixed cellIndex/cellValue pair. The proof is intentionally
// NOT cryptographically valid — these tests ONLY verify that FRIDAVerifyCell
// rejects up-front when the COMMITMENT is malformed (NumQueries==0 or
// FinalLayerSize<2), BEFORE the proof's cryptographic content matters. The
// exact cell/proof contents therefore don't affect "expect the verifier to
// short-circuit on the commitment guard" — what matters is that the early
// `return false` gates fire BEFORE any cryptographic work.
func r39BuildMalformedCommitment(numQueries, finalLayerSize, domainSize, codeRate, numLayers int) *FRIDACommitment {
	return &FRIDACommitment{
		NumLayers:      numLayers,
		DomainSize:     domainSize,
		CodeRate:       codeRate,
		NumQueries:     numQueries,
		FinalLayerSize: finalLayerSize,
		LayerRoots:     makeRoots(numLayers),
		FinalValues:    makeFinals(numLayers),
	}
}

func makeRoots(n int) [][32]byte {
	roots := make([][32]byte, n)
	for i := 0; i < n; i++ {
		h := sha256.Sum256([]byte{byte(i)})
		roots[i] = h
	}
	return roots
}

func makeFinals(n int) []GF64Element {
	f := make([]GF64Element, n)
	for i := 0; i < n; i++ {
		// Any nonzero value (the verifier gates reject before FinalValues
		// are inspected — these tests only assert the early gates fire).
		f[i] = GF64Element(uint64(i + 1))
	}
	return f
}

// TestR39_P1_07_FRIDAVerifyCell_RejectsZeroNumQueries verifies the verifier
// rejects a commitment with NumQueries == 0 — the soundness-destroying
// attacker path the audit flagged.
func TestR39_P1_07_FRIDAVerifyCell_RejectsZeroNumQueries(t *testing.T) {
	// Build a commitment with all structural fields valid EXCEPT
	// NumQueries == 0. DomainSize is a power of 2, NumLayers / LayerRoots /
	// FinalValues etc. are non-degenerate so the test isolates that
	// NumQueries==0 is the rejection cause.
	c := r39BuildMalformedCommitment(0 /*NumQueries*/, 4, 16, 4, 2)
	cell := Cell{}
	proof := &FRIDACellProof{
		Opening: &FRIOpeningProof{
			CellIndex: 0,
			CellValue: 0,
		},
	}
	// Sanity-check our fixture: the only `structural` defect is NumQueries==0.
	if c.NumQueries != 0 {
		t.Fatalf("fixture: NumQueries must be 0, got %d", c.NumQueries)
	}
	if c.FinalLayerSize < 2 {
		t.Fatalf("fixture: FinalLayerSize must be >= 2 so the test isolates the NumQueries check")
	}

	// FRIDAVerifyCell MUST return false from the NumQueries<=0 guard BEFORE
	// attempting any cryptographic work — the empty proof would otherwise
	// tempt a zero-query implementation to return true.
	got := FRIDAVerifyCell(cell, c, proof, 0)
	if got {
		t.Fatal("R39-P1-07: FRIDAVerifyCell returned true for a commitment with NumQueries == 0 — soundness-destroying bypass is NOT closed")
	}
}

// TestR39_P1_07_FRIDAVerifyCell_RejectsOversizedNumQueries verifies the
// upper-bound guard: a commitment with NumQueries > MaxFRIDANumQueries is
// rejected at the verifier (defense-in-depth against commitments assembled
// outside the decoder, which already caps at MaxFRIDANumQueries).
func TestR39_P1_07_FRIDAVerifyCell_RejectsOversizedNumQueries(t *testing.T) {
	c := r39BuildMalformedCommitment(MaxFRIDANumQueries+1, 4, 16, 4, 2)
	cell := Cell{}
	proof := &FRIDACellProof{
		Opening: &FRIOpeningProof{CellIndex: 0, CellValue: 0},
	}
	if FRIDAVerifyCell(cell, c, proof, 0) {
		t.Fatal("R39-P1-07: FRIDAVerifyCell returned true for NumQueries > MaxFRIDANumQueries — DoS bypass NOT closed")
	}
}

// TestR39_P2_03_FRIDAVerifyCell_RejectsFinalLayerSizeBelow2 verifies the
// P2-03 guard: a commitment with FinalLayerSize == 1 is rejected at the
// verifier. FinalLayerSize==1 means the FR.I folding stops at the first
// size-1 domain, skipping the degree-bound final check; combined with a
// low query count (closed by P1-07), this was the audit's "almost destroys
// soundness" combination.
func TestR39_P2_03_FRIDAVerifyCell_RejectsFinalLayerSizeBelow2(t *testing.T) {
	c := r39BuildMalformedCommitment(10 /*NumQueries — valid*/, 1 /*FinalLayerSize*/, 16, 4, 2)
	cell := Cell{}
	proof := &FRIDACellProof{
		Opening: &FRIOpeningProof{CellIndex: 0, CellValue: 0},
	}
	if FRIDAVerifyCell(cell, c, proof, 0) {
		t.Fatal("R39-P2-03: FRIDAVerifyCell returned true for FinalLayerSize < 2 — folding-bypass guard NOT closed")
	}
}

// TestR39_P1_07_FRIDAVerifyCell_RejectsZeroNumQueriesAndFinalIsolation
// verifies the two guards compose: a commitment malformed in BOTH fields
// is still rejected (the first guard fires).
func TestR39_P1_07_FRIDAVerifyCell_RejectsZeroNumQueriesAndFinalIsolation(t *testing.T) {
	c := r39BuildMalformedCommitment(0, 1, 16, 4, 2)
	cell := Cell{}
	proof := &FRIDACellProof{
		Opening: &FRIOpeningProof{CellIndex: 0, CellValue: 0},
	}
	if FRIDAVerifyCell(cell, c, proof, 0) {
		t.Fatal("R39 guards compose: a commitment malformed in NumQueries AND FinalLayerSize is NOT rejected")
	}
}
