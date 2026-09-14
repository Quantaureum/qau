// Quantaureum Node source, version 1.0.0.
package encoding

// DA-FIX (2026-07-17): FRI opening proofs.
//
// This file implements two kinds of opening proofs on top of the FRI commitment:
//
//  1. FRIOpeningProof (cell-level): proves that a cell at a given index has
//     a specific value in the committed codeword. This is the direct
//     replacement for the hash-based VerifyCellProof stub.
//
//     Proof = Merkle opening (cell ∈ codeword) + FRI proof (codeword ∈ RS code)
//
//  2. FRIDEEPProof (polynomial evaluation): proves that the underlying
//     polynomial f satisfies f(z) = y for an arbitrary point z (not
//     necessarily in the evaluation domain). This is the DEEP protocol
//     (Domain Extension for Eliminating Pretenders) used by production
//     FRI-based polynomial commitment schemes (e.g. STARKs).
//
//     Proof = q-FRI commitment (q = (f - y)/(x - z) is low-degree)
//           + consistency check at a random point ξ
//
// Security: post-quantum (based on FRI + SHA-256 collision resistance).

import (
	"crypto/sha256"
	"encoding/binary"
)

// ─── Cell-level opening proof ──────────────────────────────────────────────

// FRIOpeningProof proves that a cell at a given index has a specific value
// in the committed codeword, and that the codeword is a valid RS encoding.
//
// This is the post-quantum replacement for the hash-based KZG cell proof.
type FRIOpeningProof struct {
	CellValue    GF64Element // Value at the cell
	CellIndex    int         // Index of the cell in the codeword (layer 0)
	MerkleProof  [][]byte    // Merkle path for the cell (against LayerRoots[0])
	FRIProof     *FRIProof   // FRI query proofs (proves codeword is RS code)
	QueryIndices []int       // Query indices used for the FRI proof
}

// FRIGenerateOpeningProof generates an opening proof for a cell at cellIndex.
//
// The proof bundles:
//   - A Merkle opening proof that CellValue is at CellIndex in the codeword
//   - A FRI proof that the codeword is a valid RS encoding
//
// The FRI query indices are derived from the commitment via Fiat-Shamir
// (deterministic), and the cell index is force-included as query 0 so the
// verifier can cross-check CellValue against the FRI's revealed value.
func FRIGenerateOpeningProof(
	commitment *FRICommitment,
	codeword []GF64Element,
	layers []*friLayer,
	cellIndex int,
	cfg FRIConfig,
) *FRIOpeningProof {
	if cellIndex < 0 || cellIndex >= len(codeword) {
		return nil
	}
	if len(layers) == 0 {
		return nil
	}

	// 1. Merkle opening proof for the cell (against layer 0's tree).
	merkleProof := friGenerateMerkleProof(layers[0].merkleTree, cellIndex, len(codeword))

	// 2. FRI query indices via Fiat-Shamir. We force-include cellIndex as
	//    query 0 so the verifier can cross-check the cell value against the
	//    FRI proof's layer-0 value at that index.
	queryIndices := FRIGenerateQueryIndices(commitment, cfg.NumQueries)
	if len(queryIndices) > 0 {
		queryIndices[0] = cellIndex
	}

	// 3. FRI proof for these query indices.
	friProof := FRIProve(layers, queryIndices, cfg)

	return &FRIOpeningProof{
		CellValue:    codeword[cellIndex],
		CellIndex:    cellIndex,
		MerkleProof:  merkleProof,
		FRIProof:     friProof,
		QueryIndices: queryIndices,
	}
}

// FRIVerifyOpeningProof verifies a cell opening proof.
//
// Checks performed:
//  1. Merkle proof: CellValue is at CellIndex in the codeword (committed root)
//  2. FRI proof: codeword is a valid RS encoding
//  3. Cross-check: the FRI proof's layer-0 value at CellIndex equals CellValue
//
// All three checks must pass. Returns true only if the cell is genuinely
// part of a valid RS-encoded codeword committed by `commitment`.
//
// R32-P1-13 FIX (2026-07-28): Added `len(commitment.LayerRoots) > 0` check.
// Previously, an attacker-crafted commitment with empty LayerRoots would
// panic on `commitment.LayerRoots[0]` access.
func FRIVerifyOpeningProof(
	commitment *FRICommitment,
	proof *FRIOpeningProof,
	cfg FRIConfig,
) bool {
	if proof == nil || commitment == nil {
		return false
	}
	if proof.FRIProof == nil {
		return false
	}
	if proof.CellIndex < 0 || proof.CellIndex >= commitment.DomainSize {
		return false
	}
	if len(proof.QueryIndices) == 0 {
		return false
	}
	// R32-P2-15 FIX (2026-07-28): The number of query indices in the opening
	// proof must meet the configured minimum (cfg.NumQueries). Without this
	// check, a malicious prover could submit an opening proof with just 1
	// query (the force-included cellIndex), bypassing the FRI soundness
	// guarantee. FRIVerify (called below) also enforces this, but we check
	// early here to provide a clearer failure path and defense-in-depth.
	if cfg.NumQueries <= 0 {
		return false
	}
	if len(proof.QueryIndices) < cfg.NumQueries {
		return false
	}
	// R32-P1-13: LayerRoots must have at least one entry for the Merkle
	// proof verification against LayerRoots[0].
	if len(commitment.LayerRoots) == 0 {
		return false
	}
	if commitment.DomainSize <= 0 {
		return false
	}

	// R33 DA-01 FIX (2026-07-28): Fiat-Shamir query index derivation.
	// The query indices MUST be derived from the commitment via Fiat-Shamir,
	// not taken from the proof's QueryIndices field. A malicious prover could
	// otherwise choose favorable indices that pass FRI verification on a
	// subset of positions while hiding inconsistencies elsewhere.
	//
	// The prover's protocol (see FRIGenerateOpeningProof) is:
	//   1. Derive expectedIndices = FRIGenerateQueryIndices(commitment, N)
	//   2. Replace expectedIndices[0] with cellIndex (force-include)
	//   3. Build FRI proof for the modified queryIndices
	//
	// So the verifier re-derives expectedIndices and checks that:
	//   - proof.QueryIndices[0] == cellIndex (force-included)
	//   - proof.QueryIndices[1..N-1] matches expectedIndices[1..N-1] as a set
	// Position 0 is excluded from the set comparison because it's overwritten.
	expectedIndices := FRIGenerateQueryIndices(commitment, cfg.NumQueries)
	if !verifyQueryIndicesMatch(proof.QueryIndices, expectedIndices, proof.CellIndex) {
		return false
	}

	// 1. Verify Merkle opening: CellValue is at CellIndex in layer 0.
	if !friVerifyMerkleProof(
		commitment.LayerRoots[0],
		proof.CellValue,
		proof.CellIndex,
		commitment.DomainSize,
		proof.MerkleProof,
	) {
		return false
	}

	// 2. Verify FRI proof (codeword is RS code).
	if !FRIVerify(commitment, proof.FRIProof, proof.QueryIndices, cfg) {
		return false
	}

	// 3. Cross-check: FRI proof's layer-0 value at CellIndex must equal CellValue.
	//    Find the query that matches CellIndex (we force-included it at position 0).
	verified := false
	for qi, idx := range proof.QueryIndices {
		if idx == proof.CellIndex {
			if qi >= len(proof.FRIProof.Queries) {
				return false
			}
			if len(proof.FRIProof.Queries[qi].Layers) == 0 {
				return false
			}
			if proof.FRIProof.Queries[qi].Layers[0].Value != proof.CellValue {
				return false
			}
			verified = true
			break
		}
	}
	if !verified {
		return false
	}

	return true
}

// verifyQueryIndicesMatch checks that the prover's QueryIndices match the
// Fiat-Shamir-derived expected indices, accounting for the force-included
// CellIndex at position 0.
//
// Protocol (see FRIGenerateOpeningProof):
//  1. expectedIndices = FRIGenerateQueryIndices(commitment, N)
//  2. queryIndices[0] = cellIndex (force-include, overwrites expectedIndices[0])
//  3. queryIndices[1..N-1] = expectedIndices[1..N-1] (unchanged)
//
// This function verifies:
//   - proverIndices[0] == cellIndex
//   - proverIndices[1..N-1] as a set == expectedIndices[1..N-1] as a set
//
// R33 DA-01 FIX (2026-07-28): Without this check, a malicious prover could
// choose favorable query indices that pass FRI verification on a subset of
// positions while hiding inconsistencies elsewhere, completely breaking FRI
// soundness.
func verifyQueryIndicesMatch(proverIndices, expectedIndices []int, cellIndex int) bool {
	if len(expectedIndices) == 0 || len(proverIndices) < len(expectedIndices) {
		return false
	}
	// Position 0 must be the force-included CellIndex.
	if proverIndices[0] != cellIndex {
		return false
	}
	// Positions 1..N-1 must match expectedIndices[1..N-1] as a set.
	// (Position 0 is excluded because it's overwritten by cellIndex.)
	proverSet := make(map[int]bool, len(proverIndices)-1)
	for i := 1; i < len(proverIndices); i++ {
		if proverIndices[i] < 0 {
			return false
		}
		proverSet[proverIndices[i]] = true
	}
	for i := 1; i < len(expectedIndices); i++ {
		if !proverSet[expectedIndices[i]] {
			return false
		}
	}
	return true
}

// ─── DEEP: polynomial evaluation at an arbitrary point ─────────────────────

// FRIDEEPProof proves that the polynomial f underlying a FRI commitment
// satisfies f(z) = y, where z is an arbitrary field element (not necessarily
// in the evaluation domain).
//
// Protocol (DEEP-RI):
//  1. Prover computes the quotient polynomial q(x) = (f(x) - y) / (x - z)
//     (this is a polynomial iff f(z) = y)
//  2. Prover FRI-commits q(x) → C_q
//  3. Verifier picks a random point ξ (Fiat-Shamir from C_f, C_q, z, y)
//  4. Prover provides f(ξ) and q(ξ) via cell openings
//  5. Verifier checks: f(ξ) - y == (ξ - z) * q(ξ)
//  6. Verifier checks FRI proofs for both f and q codewords
//
// Security: if f(z) ≠ y, then (f(x) - y) is not divisible by (x - z), so
// q(x) is not a polynomial — the FRI proof for q will fail with high
// probability. The random point ξ prevents the prover from cheating on
// only a few positions.
type FRIDEEPProof struct {
	Z           GF64Element      // Evaluation point z
	Y           GF64Element      // Claimed value f(z) = y
	QCommitment *FRICommitment   // FRI commitment of q(x) = (f(x) - y)/(x - z)
	QCodeword   []GF64Element    // q's codeword (needed for opening proofs)
	QLayers     []*friLayer      // q's FRI layers
	XiIdx       int              // Index of the random check point in the domain
	Xi          GF64Element      // Value of the random check point (domain[XiIdx])
	FAtXi       GF64Element      // f(ξ) — opened value from f's codeword
	QAtXi       GF64Element      // q(ξ) — opened value from q's codeword
	FCellProof  *FRIOpeningProof // Opening proof for f(ξ) in f's codeword
	QCellProof  *FRIOpeningProof // Opening proof for q(ξ) in q's codeword
	FCommitment *FRICommitment   // F's FRI commitment (for verifier convenience)
	FCodeword   []GF64Element    // f's codeword (for opening proofs)
	FLayers     []*friLayer      // f's FRI layers
}

// FRIDEEPProve generates a DEEP proof that f(z) = y, where f is the polynomial
// whose codeword is `fCodeword` (committed via `fCommitment`).
//
// Inputs:
//   - fCommitment: FRI commitment of f's codeword
//   - fCodeword: f's codeword (the prover knows this)
//   - fLayers: FRI layers from FRICommit(fCodeword)
//   - fCoeffs: f's coefficient representation (needed to evaluate f(z) and
//     compute the quotient polynomial)
//   - z: the evaluation point
//   - cfg: FRI configuration (used for q's commitment)
//
// Returns nil if f(z) ≠ y (i.e., (x - z) does not divide (f(x) - y)).
//
// Protocol:
//  1. Compute y = f(z) via coefficient evaluation
//  2. Compute q(x) = (f(x) - y) / (x - z) via synthetic division
//  3. FRI-commit q's codeword
//  4. Derive a random domain index ξ_idx via Fiat-Shamir; let ξ = domain[ξ_idx]
//  5. Generate cell opening proofs for f(ξ) and q(ξ)
//  6. The verifier checks: f(ξ) - y == (ξ - z) * q(ξ)
//
// Security: ξ is a domain point chosen uniformly at random after q is committed.
// If f(z) ≠ y, the prover cannot produce a valid q (FRI fails) AND satisfy
// the consistency check at the random ξ.
//
// R32-P1-13 FIX (2026-07-28): Added validation that fCommitment.DomainSize
// == cfg.DomainSize (previously mismatch could cause OOB panics in fCodeword
// access), nil-checks for friGenerateLayerDomain return value, and
// validation of xiIdx against len(fCodeword)/len(qCodeword) before access.
func FRIDEEPProve(
	fCommitment *FRICommitment,
	fCodeword []GF64Element,
	fLayers []*friLayer,
	fCoeffs []GF64Element,
	z GF64Element,
	cfg FRIConfig,
) (*FRIDEEPProof, error) {
	if fCommitment == nil || len(fCoeffs) == 0 {
		return nil, errDEEPInvalidInput
	}
	if len(fCodeword) != fCommitment.DomainSize {
		return nil, errDEEPInvalidInput
	}
	// R32-P1-13: fCommitment.DomainSize must match cfg.DomainSize so that
	// xiIdx (derived from cfg.DomainSize) is a valid index into fCodeword.
	if fCommitment.DomainSize != cfg.DomainSize {
		return nil, errDEEPInvalidInput
	}
	if cfg.DomainSize <= 0 || cfg.CodeRate <= 0 {
		return nil, errDEEPInvalidInput
	}

	// 1. Evaluate f(z) using the coefficient representation.
	y := polyEval(fCoeffs, z)

	// 2. Compute the quotient polynomial q(x) = (f(x) - y) / (x - z).
	qCoeffs, ok := polyDivideByLinear(fCoeffs, z, y)
	if !ok {
		return nil, errDEEPNotDivisible
	}

	// 3. RS-extend q to a codeword and FRI-commit it.
	//    Pad qCoeffs to polyDegree length to match cfg.DomainSize / cfg.CodeRate.
	polyDegree := cfg.DomainSize / cfg.CodeRate
	if len(qCoeffs) > polyDegree {
		// q has degree len(fCoeffs) - 2, which must be < polyDegree for FRI to work.
		// If f's degree is too high, abort.
		return nil, errDEEPInvalidInput
	}
	qPadded := make([]GF64Element, polyDegree)
	copy(qPadded, qCoeffs)
	qCodeword := GF64ReedSolomonExtend(qPadded, cfg.DomainSize)
	// R32-P1-13: GF64ReedSolomonExtend may return nil for invalid configs.
	if qCodeword == nil {
		return nil, errDEEPInvalidInput
	}
	qCommitment, qLayers := FRICommit(qCodeword, cfg)
	// R32-P1-13: FRICommit may return nil for invalid configs.
	if qCommitment == nil {
		return nil, errDEEPInvalidInput
	}

	// 4. Derive the random check index ξ_idx via Fiat-Shamir.
	//    ξ is a domain point (not an arbitrary field element), so f(ξ) and
	//    q(ξ) can be read directly from the codewords.
	xiIdx := deepDeriveXiIdx(fCommitment, qCommitment, z, y, cfg.DomainSize)
	if xiIdx >= cfg.DomainSize {
		xiIdx = xiIdx % cfg.DomainSize
	}
	// R32-P1-13: Defensive bounds check before indexing into the codewords.
	if xiIdx < 0 || xiIdx >= len(fCodeword) || xiIdx >= len(qCodeword) {
		return nil, errDEEPInvalidInput
	}

	// 5. Read f(ξ) and q(ξ) from the codewords.
	fAtXi := fCodeword[xiIdx]
	qAtXi := qCodeword[xiIdx]

	// 6. Generate cell opening proofs for f(ξ) and q(ξ).
	fCellProof := FRIGenerateOpeningProof(fCommitment, fCodeword, fLayers, xiIdx, cfg)
	qCellProof := FRIGenerateOpeningProof(qCommitment, qCodeword, qLayers, xiIdx, cfg)

	if fCellProof == nil || qCellProof == nil {
		return nil, errDEEPInvalidInput
	}

	// 7. Sanity check (prover side): the consistency equation must hold.
	//    If it doesn't, something is wrong with our math.
	// R32-P1-13: friGenerateLayerDomain may return nil.
	domain0 := friGenerateLayerDomain(0, cfg.DomainSize)
	if domain0 == nil || xiIdx >= len(domain0) {
		return nil, errDEEPInvalidInput
	}
	xiValue := domain0[xiIdx]
	lhs := GF64Sub(fAtXi, y)
	rhs := GF64Mul(GF64Sub(xiValue, z), qAtXi)
	if lhs != rhs {
		// This should never happen if f(z) = y and q is computed correctly.
		return nil, errDEEPConsistencyFailed
	}

	return &FRIDEEPProof{
		Z:           z,
		Y:           y,
		QCommitment: qCommitment,
		QCodeword:   qCodeword,
		QLayers:     qLayers,
		XiIdx:       xiIdx,
		Xi:          xiValue,
		FAtXi:       fAtXi,
		QAtXi:       qAtXi,
		FCellProof:  fCellProof,
		QCellProof:  qCellProof,
		FCommitment: fCommitment,
		FCodeword:   fCodeword,
		FLayers:     fLayers,
	}, nil
}

// FRIDEEPVerify verifies a DEEP proof.
//
// Checks:
//  1. f's cell opening proof is valid (f's codeword is RS code + f(ξ) opened correctly)
//  2. q's cell opening proof is valid (q's codeword is RS code + q(ξ) opened correctly)
//  3. ξ_idx is correctly derived via Fiat-Shamir
//  4. ξ value matches the domain point at ξ_idx
//  5. Consistency: f(ξ) - y == (ξ - z) * q(ξ)  ← THE CORE DEEP CHECK
//
// The consistency check is the heart of DEEP: if f(z) ≠ y, the prover cannot
// satisfy this equation at the random point ξ (chosen after q is committed).
//
// R32-P1-13 FIX (2026-07-28): Added `proof.XiIdx >= 0` check, nil-check for
// friGenerateLayerDomain return value, and `cfg.DomainSize > 0` validation.
// Previously, an attacker-crafted proof with XiIdx < 0 or cfg.DomainSize = 0
// could cause panics in domain access or modulo-by-zero in the Fiat-Shamir
// recompute step.
func FRIDEEPVerify(proof *FRIDEEPProof, cfg FRIConfig) bool {
	if proof == nil {
		return false
	}
	if proof.QCommitment == nil || proof.FCommitment == nil {
		return false
	}
	if proof.FCellProof == nil || proof.QCellProof == nil {
		return false
	}
	if proof.FCommitment.DomainSize != proof.QCommitment.DomainSize {
		return false
	}
	// R32-P1-13: XiIdx must be non-negative. (Upper bound is checked below
	// against cfg.DomainSize.)
	if proof.XiIdx < 0 {
		return false
	}
	if cfg.DomainSize <= 0 {
		return false
	}

	// 1. Verify f's cell opening proof (this also verifies f's FRI commitment).
	if !FRIVerifyOpeningProof(proof.FCommitment, proof.FCellProof, cfg) {
		return false
	}

	// 2. Verify q's cell opening proof (this also verifies q's FRI commitment).
	if !FRIVerifyOpeningProof(proof.QCommitment, proof.QCellProof, cfg) {
		return false
	}

	// 3. Recompute ξ_idx via Fiat-Shamir and check it matches.
	expectedXiIdx := deepDeriveXiIdx(proof.FCommitment, proof.QCommitment, proof.Z, proof.Y, cfg.DomainSize)
	if expectedXiIdx >= cfg.DomainSize {
		expectedXiIdx = expectedXiIdx % cfg.DomainSize
	}
	if expectedXiIdx != proof.XiIdx {
		return false
	}
	// R32-P1-13: After modulo reduction, expectedXiIdx is in [0, cfg.DomainSize).
	// If proof.XiIdx matched expectedXiIdx, it's also in range — but check
	// defensively in case cfg.DomainSize was mutated between the two checks.
	if proof.XiIdx >= cfg.DomainSize {
		return false
	}

	// 4. Verify the cell opening proofs opened at the same index ξ_idx.
	if proof.FCellProof.CellIndex != proof.XiIdx {
		return false
	}
	if proof.QCellProof.CellIndex != proof.XiIdx {
		return false
	}

	// 5. Verify ξ value matches the domain point at ξ_idx.
	domain := friGenerateLayerDomain(0, cfg.DomainSize)
	// R32-P1-13: friGenerateLayerDomain may return nil for invalid cfg.
	if domain == nil || proof.XiIdx >= len(domain) {
		return false
	}
	if domain[proof.XiIdx] != proof.Xi {
		return false
	}

	// 6. Verify the opened values match the claimed FAtXi and QAtXi.
	if proof.FCellProof.CellValue != proof.FAtXi {
		return false
	}
	if proof.QCellProof.CellValue != proof.QAtXi {
		return false
	}

	// 7. THE CORE DEEP CHECK: f(ξ) - y == (ξ - z) * q(ξ)
	//
	// If f(z) = y and q(x) = (f(x) - y)/(x - z), then for any ξ:
	//   f(ξ) - y = (ξ - z) * q(ξ)
	//
	// If f(z) ≠ y, the prover either:
	//   (a) Cannot produce a valid q-FRI commitment (q is not a polynomial), OR
	//   (b) Produces a fake q that doesn't satisfy this equation at random ξ.
	lhs := GF64Sub(proof.FAtXi, proof.Y)
	rhs := GF64Mul(GF64Sub(proof.Xi, proof.Z), proof.QAtXi)
	if lhs != rhs {
		return false
	}

	return true
}

// ─── Polynomial helpers ────────────────────────────────────────────────────

// polyEval evaluates the polynomial Σ coeffs[i] * x^i at point x.
func polyEval(coeffs []GF64Element, x GF64Element) GF64Element {
	// Horner's method: ((...((a_n * x + a_{n-1}) * x + a_{n-2}) * x + ...) * x + a_0)
	result := GF64Element(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = GF64Add(GF64Mul(result, x), coeffs[i])
	}
	return result
}

// polyDivideByLinear computes q(x) such that f(x) - y = (x - z) * q(x).
// Returns (q, true) if (x - z) divides (f(x) - y), else (nil, false).
//
// Uses synthetic division (Ruffini's rule):
//
//	f(x) - y = Σ a_i x^i  (where a_0 is replaced by a_0 - y)
//	q(x) = Σ b_i x^i  where b_{n-1} = a_n, b_{i-1} = a_i + z * b_i
//	The remainder is b_{-1} = a_0 + z * b_0, which must be 0.
func polyDivideByLinear(coeffs []GF64Element, z, y GF64Element) ([]GF64Element, bool) {
	if len(coeffs) == 0 {
		return nil, false
	}

	// Adjust a_0: f(x) - y has coefficients (a_0 - y, a_1, ..., a_n).
	adjusted := make([]GF64Element, len(coeffs))
	copy(adjusted, coeffs)
	adjusted[0] = GF64Sub(adjusted[0], y)

	n := len(adjusted)
	q := make([]GF64Element, n-1)

	// Synthetic division.
	// If f(x) - y = a_n x^n + ... + a_1 x + a_0, then
	// q(x) = b_{n-2} x^{n-2} + ... + b_0, where
	// b_{n-2} = a_n, b_{i-1} = a_{i+1} + z * b_i  (for i = n-2 down to 0)
	// remainder = a_0 + z * b_0
	//
	// Standard Ruffini: walking from highest degree to lowest.
	// b[n-2] = a[n-1]
	// b[i] = a[i+1] + z * b[i+1]   for i = n-3 down to 0
	// rem  = a[0] + z * b[0]
	if n == 1 {
		// f(x) - y = a_0 (constant). If a_0 == 0, q(x) = 0 (empty).
		if adjusted[0] == 0 {
			return []GF64Element{}, true
		}
		return nil, false
	}

	q[n-2] = adjusted[n-1]
	for i := n - 3; i >= 0; i-- {
		q[i] = GF64Add(adjusted[i+1], GF64Mul(z, q[i+1]))
	}
	rem := GF64Add(adjusted[0], GF64Mul(z, q[0]))

	if rem != 0 {
		return nil, false
	}
	return q, true
}

// deepDeriveXiIdx derives the random check point's domain index via Fiat-Shamir.
// ξ_idx = H(C_f || C_q || z || y) mod domainSize.
//
// Since domainSize is a power of 2, the modular reduction is unbiased.
// ξ_idx selects a domain point ξ = domain[ξ_idx] at which the DEEP
// consistency check is performed.
func deepDeriveXiIdx(fCommitment, qCommitment *FRICommitment, z, y GF64Element, domainSize int) int {
	h := sha256.New()
	for _, root := range fCommitment.LayerRoots {
		h.Write(root[:])
	}
	for _, root := range qCommitment.LayerRoots {
		h.Write(root[:])
	}
	h.Write(GF64ToBytes(z))
	h.Write(GF64ToBytes(y))
	hash := h.Sum(nil)
	// Use a full 8-byte read for the index, then reduce mod domainSize.
	idx := binary.BigEndian.Uint64(hash[:8])
	if domainSize <= 0 {
		return 0
	}
	return int(idx % uint64(domainSize))
}

// ─── Errors ────────────────────────────────────────────────────────────────

var errDEEPInvalidInput = newDEEPErr("DEEP: invalid input")
var errDEEPNotDivisible = newDEEPErr("DEEP: (x - z) does not divide (f(x) - y); f(z) ≠ y")
var errDEEPConsistencyFailed = newDEEPErr("DEEP: prover-side consistency check f(ξ)-y == (ξ-z)*q(ξ) failed")

type deepError struct{ msg string }

func (e *deepError) Error() string { return e.msg }
func newDEEPErr(msg string) error  { return &deepError{msg: msg} }

// ─── Serialization ─────────────────────────────────────────────────────────

// EncodeFRIOpeningProof serializes an FRIOpeningProof to bytes.
// Format:
//   - 8 bytes: CellValue (little-endian)
//   - 4 bytes: CellIndex (big-endian uint32)
//   - 4 bytes: MerkleProof length (big-endian uint32)
//   - MerkleProof (each 32 bytes)
//   - FRIProof (variable length, see EncodeFRIProof)
//   - 4 bytes: QueryIndices length
//   - QueryIndices (each 4 bytes, big-endian uint32)
func EncodeFRIOpeningProof(proof *FRIOpeningProof) []byte {
	if proof == nil {
		return nil
	}

	// Pre-compute sizes
	merkleLen := len(proof.MerkleProof)
	queryLen := len(proof.QueryIndices)
	friBytes := EncodeFRIProof(proof.FRIProof)

	totalSize := 8 + 4 + 4 + merkleLen*32 + len(friBytes) + 4 + queryLen*4
	buf := make([]byte, totalSize)

	// CellValue
	copy(buf[0:8], GF64ToBytes(proof.CellValue))
	// CellIndex
	binary.BigEndian.PutUint32(buf[8:12], uint32(proof.CellIndex))
	// MerkleProof length
	binary.BigEndian.PutUint32(buf[12:16], uint32(merkleLen))

	offset := 16
	for i := 0; i < merkleLen; i++ {
		copy(buf[offset:offset+32], proof.MerkleProof[i])
		offset += 32
	}

	// FRIProof
	copy(buf[offset:offset+len(friBytes)], friBytes)
	offset += len(friBytes)

	// QueryIndices length
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(queryLen))
	offset += 4
	for i := 0; i < queryLen; i++ {
		binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(proof.QueryIndices[i]))
		offset += 4
	}

	return buf[:offset]
}

// EncodeFRIProof serializes an FRIProof to bytes.
// Format:
//   - 4 bytes: number of queries
//   - For each query:
//   - 4 bytes: number of layer proofs
//   - For each layer proof:
//   - 8 bytes: Value
//   - 8 bytes: SiblingValue
//   - 4 bytes: Index
//   - 4 bytes: MerkleProof length
//   - MerkleProof (each 32 bytes)
//   - 4 bytes: SiblingMerkleProof length
//   - SiblingMerkleProof (each 32 bytes)
func EncodeFRIProof(proof *FRIProof) []byte {
	if proof == nil {
		return nil
	}

	// Pre-compute size
	totalSize := 4
	for _, q := range proof.Queries {
		totalSize += 4
		for _, lp := range q.Layers {
			totalSize += 8 + 8 + 4 + 4 + len(lp.MerkleProof)*32 + 4 + len(lp.SiblingMerkleProof)*32
		}
	}

	buf := make([]byte, totalSize)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(proof.Queries)))
	offset := 4

	for _, q := range proof.Queries {
		binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(q.Layers)))
		offset += 4
		for _, lp := range q.Layers {
			copy(buf[offset:offset+8], GF64ToBytes(lp.Value))
			offset += 8
			copy(buf[offset:offset+8], GF64ToBytes(lp.SiblingValue))
			offset += 8
			binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(lp.Index))
			offset += 4
			binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(lp.MerkleProof)))
			offset += 4
			for _, sib := range lp.MerkleProof {
				copy(buf[offset:offset+32], sib)
				offset += 32
			}
			binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(lp.SiblingMerkleProof)))
			offset += 4
			for _, sib := range lp.SiblingMerkleProof {
				copy(buf[offset:offset+32], sib)
				offset += 32
			}
		}
	}

	return buf[:offset]
}
