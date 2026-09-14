// Quantaureum Node source, version 1.0.0.
package encoding

// R32-P2-15 FIX (2026-07-28): Regression tests for FRI query count enforcement.
//
// The audit issue P2-15 identified that FRIVerify did not enforce that the
// number of query indices met the configured minimum (cfg.NumQueries). A
// malicious prover could submit a proof with just 1 query (instead of the
// required 80), reducing soundness from 2^(-160) to (3/4)^1 = 75%.
//
// These tests verify:
//  1. A proof with fewer queries than cfg.NumQueries is rejected
//  2. A proof with cfg.NumQueries=0 is rejected (zero-query bypass)
//  3. ValidateFRIConfigForProduction enforces minimum security parameters
//  4. A legitimate proof with exactly cfg.NumQueries queries is accepted

import (
	"testing"
)

// TestR32_P2_15_FRIVerify_RejectsInsufficientQueries verifies that FRIVerify
// rejects a proof that contains fewer queries than cfg.NumQueries.
//
// This is the core P2-15 fix: without the check, a malicious prover could
// submit a proof with just 1 query instead of the configured 80, reducing
// the soundness from 2^(-160) to 75%.
func TestR32_P2_15_FRIVerify_RejectsInsufficientQueries(t *testing.T) {
	// Build a valid FRI commitment and proof with cfg.NumQueries=20.
	cfg := FRIConfig{DomainSize: 16, CodeRate: 4, NumQueries: 20, FinalLayerSize: 4}
	polyCoeffs := []GF64Element{3, 1, 4, 1} // degree 3, domain size 16/4=4
	codeword := GF64ReedSolomonExtend(polyCoeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)
	if commitment == nil {
		t.Fatalf("FRICommit returned nil")
	}

	// Generate a valid proof with 20 queries.
	queryIndices := FRIGenerateQueryIndices(commitment, cfg.NumQueries)
	fullProof := FRIProve(layers, queryIndices, cfg)

	// Sanity: the full proof with 20 queries should verify.
	if !FRIVerify(commitment, fullProof, queryIndices, cfg) {
		t.Fatalf("baseline: full proof with %d queries should verify", cfg.NumQueries)
	}

	// Now truncate the proof to 1 query (simulating a malicious prover).
	maliciousIndices := queryIndices[:1]
	maliciousProof := &FRIProof{
		Queries: fullProof.Queries[:1],
	}

	// The malicious proof must be REJECTED.
	if FRIVerify(commitment, maliciousProof, maliciousIndices, cfg) {
		t.Error("R32-P2-15 NOT FIXED: FRIVerify accepted a proof with 1 query " +
			"when cfg.NumQueries=20. A malicious prover can bypass FRI soundness " +
			"by submitting fewer queries than required.")
	}

	// Also test with 5 queries (still < 20).
	partialIndices := queryIndices[:5]
	partialProof := &FRIProof{
		Queries: fullProof.Queries[:5],
	}
	if FRIVerify(commitment, partialProof, partialIndices, cfg) {
		t.Error("R32-P2-15 NOT FIXED: FRIVerify accepted a proof with 5 queries " +
			"when cfg.NumQueries=20.")
	}
}

// TestR32_P2_15_FRIVerify_RejectsZeroNumQueries verifies that FRIVerify
// rejects proofs when cfg.NumQueries is zero. A zero value would allow
// an empty proof to pass trivially (0 queries = no checks = "valid").
func TestR32_P2_15_FRIVerify_RejectsZeroNumQueries(t *testing.T) {
	cfg := FRIConfig{DomainSize: 16, CodeRate: 4, NumQueries: 0, FinalLayerSize: 4}
	polyCoeffs := []GF64Element{3, 1, 4, 1}
	codeword := GF64ReedSolomonExtend(polyCoeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)
	if commitment == nil {
		t.Fatalf("FRICommit returned nil")
	}

	// An empty proof with 0 queries.
	emptyProof := &FRIProof{Queries: []FRIQueryProof{}}
	emptyIndices := []int{}

	// Must be rejected — a zero-query proof provides zero soundness.
	if FRIVerify(commitment, emptyProof, emptyIndices, cfg) {
		t.Error("R32-P2-15 NOT FIXED: FRIVerify accepted a proof with " +
			"cfg.NumQueries=0. Zero queries means no verification at all.")
	}

	// Also test with a non-empty proof but cfg.NumQueries=0.
	queryIndices := FRIGenerateQueryIndices(commitment, 5)
	realProof := FRIProve(layers, queryIndices, FRIConfig{
		DomainSize: cfg.DomainSize, CodeRate: cfg.CodeRate,
		NumQueries: 5, FinalLayerSize: cfg.FinalLayerSize,
	})
	if FRIVerify(commitment, realProof, queryIndices, cfg) {
		t.Error("R32-P2-15 NOT FIXED: FRIVerify accepted a proof with " +
			"cfg.NumQueries=0 even though queries were provided. " +
			"The config must enforce a positive minimum.")
	}
}

// TestR32_P2_15_FRIVerify_AcceptsExactQueryCount verifies that a proof
// with exactly cfg.NumQueries queries is accepted (no over-blocking).
func TestR32_P2_15_FRIVerify_AcceptsExactQueryCount(t *testing.T) {
	cfg := FRIConfig{DomainSize: 16, CodeRate: 4, NumQueries: 10, FinalLayerSize: 4}
	polyCoeffs := []GF64Element{3, 1, 4, 1}
	codeword := GF64ReedSolomonExtend(polyCoeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)
	if commitment == nil {
		t.Fatalf("FRICommit returned nil")
	}

	queryIndices := FRIGenerateQueryIndices(commitment, cfg.NumQueries)
	proof := FRIProve(layers, queryIndices, cfg)

	// A proof with exactly cfg.NumQueries queries must be accepted.
	if !FRIVerify(commitment, proof, queryIndices, cfg) {
		t.Error("R32-P2-15 OVER-BLOCK: FRIVerify rejected a proof with exactly " +
			"cfg.NumQueries queries. The fix should not reject legitimate proofs.")
	}
}

// TestR32_P2_15_FRIVerify_AcceptsExtraQueries verifies that a proof with
// MORE queries than cfg.NumQueries is accepted (extra queries only improve
// soundness and should not cause rejection).
func TestR32_P2_15_FRIVerify_AcceptsExtraQueries(t *testing.T) {
	cfg := FRIConfig{DomainSize: 16, CodeRate: 4, NumQueries: 5, FinalLayerSize: 4}
	polyCoeffs := []GF64Element{3, 1, 4, 1}
	codeword := GF64ReedSolomonExtend(polyCoeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)
	if commitment == nil {
		t.Fatalf("FRICommit returned nil")
	}

	// Generate 10 queries but config only requires 5.
	queryIndices := FRIGenerateQueryIndices(commitment, 10)
	proof := FRIProve(layers, queryIndices, cfg)

	// The proof has 10 queries, cfg requires 5. Should be accepted (>= check).
	if !FRIVerify(commitment, proof, queryIndices, cfg) {
		t.Error("R32-P2-15 OVER-BLOCK: FRIVerify rejected a proof with MORE " +
			"queries than cfg.NumQueries. Extra queries improve soundness " +
			"and should not cause rejection.")
	}
}

// TestR32_P2_15_FRIOpeningProof_RejectsInsufficientQueries verifies that
// FRIVerifyOpeningProof also rejects proofs with insufficient queries.
// This is the defense-in-depth layer: even if FRIVerify's check were
// bypassed, the opening proof verification would still catch it.
func TestR32_P2_15_FRIOpeningProof_RejectsInsufficientQueries(t *testing.T) {
	cfg := FRIConfig{DomainSize: 16, CodeRate: 4, NumQueries: 20, FinalLayerSize: 4}
	polyCoeffs := []GF64Element{3, 1, 4, 1}
	codeword := GF64ReedSolomonExtend(polyCoeffs, cfg.DomainSize)
	commitment, layers := FRICommit(codeword, cfg)
	if commitment == nil {
		t.Fatalf("FRICommit returned nil")
	}

	// Generate a valid opening proof with 20 queries.
	fullProof := FRIGenerateOpeningProof(commitment, codeword, layers, 0, cfg)
	if fullProof == nil {
		t.Fatalf("FRIGenerateOpeningProof returned nil")
	}

	// Sanity: the full proof should verify.
	if !FRIVerifyOpeningProof(commitment, fullProof, cfg) {
		t.Fatalf("baseline: full opening proof should verify")
	}

	// Create a malicious proof with only 1 query.
	maliciousProof := &FRIOpeningProof{
		CellValue:   fullProof.CellValue,
		CellIndex:   fullProof.CellIndex,
		MerkleProof: fullProof.MerkleProof,
		FRIProof: &FRIProof{
			Queries: fullProof.FRIProof.Queries[:1],
		},
		QueryIndices: fullProof.QueryIndices[:1],
	}

	// The malicious proof must be rejected.
	if FRIVerifyOpeningProof(commitment, maliciousProof, cfg) {
		t.Error("R32-P2-15 NOT FIXED: FRIVerifyOpeningProof accepted a proof " +
			"with 1 query when cfg.NumQueries=20.")
	}
}

// TestR32_P2_15_ValidateFRIConfigForProduction verifies that the production
// config validation function correctly enforces minimum security parameters.
func TestR32_P2_15_ValidateFRIConfigForProduction(t *testing.T) {
	// Valid production config (uses DefaultFRIConfig defaults).
	validCfg := DefaultFRIConfig(4)
	if err := ValidateFRIConfigForProduction(validCfg); err != nil {
		t.Errorf("valid production config rejected: %v", err)
	}

	// NumQueries too low.
	lowQueries := validCfg
	lowQueries.NumQueries = 10
	if err := ValidateFRIConfigForProduction(lowQueries); err == nil {
		t.Error("R32-P2-15 NOT FIXED: ValidateFRIConfigForProduction accepted " +
			"NumQueries=10 (below minimum 40)")
	}

	// NumQueries = 0.
	zeroQueries := validCfg
	zeroQueries.NumQueries = 0
	if err := ValidateFRIConfigForProduction(zeroQueries); err == nil {
		t.Error("R32-P2-15 NOT FIXED: ValidateFRIConfigForProduction accepted " +
			"NumQueries=0")
	}

	// NumQueries = MinProductionNumQueries (boundary — should pass).
	minQueries := validCfg
	minQueries.NumQueries = MinProductionNumQueries
	if err := ValidateFRIConfigForProduction(minQueries); err != nil {
		t.Errorf("NumQueries=MinProductionNumQueries (%d) should pass, got %v",
			MinProductionNumQueries, err)
	}

	// NumQueries = MinProductionNumQueries - 1 (should fail).
	belowMin := validCfg
	belowMin.NumQueries = MinProductionNumQueries - 1
	if err := ValidateFRIConfigForProduction(belowMin); err == nil {
		t.Errorf("R32-P2-15 NOT FIXED: NumQueries=%d (below minimum %d) was accepted",
			MinProductionNumQueries-1, MinProductionNumQueries)
	}

	// CodeRate too low.
	lowRate := validCfg
	lowRate.CodeRate = 1
	if err := ValidateFRIConfigForProduction(lowRate); err == nil {
		t.Error("R32-P2-15 NOT FIXED: ValidateFRIConfigForProduction accepted " +
			"CodeRate=1 (trivially insecure)")
	}

	// DomainSize not power of 2.
	badDomain := validCfg
	badDomain.DomainSize = 15
	if err := ValidateFRIConfigForProduction(badDomain); err == nil {
		t.Error("R32-P2-15 NOT FIXED: ValidateFRIConfigForProduction accepted " +
			"DomainSize=15 (not power of 2)")
	}

	// FinalLayerSize too small.
	smallFinal := validCfg
	smallFinal.FinalLayerSize = 1
	if err := ValidateFRIConfigForProduction(smallFinal); err == nil {
		t.Error("R32-P2-15 NOT FIXED: ValidateFRIConfigForProduction accepted " +
			"FinalLayerSize=1 (no degree bound)")
	}
}

// TestR32_P2_15_DefaultFRIConfig_PassesProductionValidation verifies that
// DefaultFRIConfig produces a config that passes production validation.
// This ensures the default configuration is always production-safe.
func TestR32_P2_15_DefaultFRIConfig_PassesProductionValidation(t *testing.T) {
	for _, polyDeg := range []int{1, 2, 4, 8, 16, 32, 64} {
		cfg := DefaultFRIConfig(polyDeg)
		if err := ValidateFRIConfigForProduction(cfg); err != nil {
			t.Errorf("DefaultFRIConfig(%d) failed production validation: %v",
				polyDeg, err)
		}
	}
}
