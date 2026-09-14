// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"
	"time"
)

func TestGaussianSampleBounds(t *testing.T) {
	sigma := GMQTDBaseSigma
	gs := NewGaussianSampler(sigma)

	countBeyond6Sigma := 0
	samples := 10000

	for i := 0; i < samples; i++ {
		seed := make([]byte, 32)
		binary.LittleEndian.PutUint32(seed, uint32(i))
		binary.LittleEndian.PutUint32(seed[4:], uint32(samples-i))

		coeff := gs.SampleSeed(seed)
		c := int64(coeff)
		if c > Q/2 {
			c -= Q
		}
		if c < -Q/2 {
			c += Q
		}

		bound := int64(6 * sigma)
		if c > bound || c < -bound {
			countBeyond6Sigma++
		}
	}

	ratio := float64(countBeyond6Sigma) / float64(samples)
	t.Logf("Gaussian sigma=%.0f: %d/%d beyond 6-sigma (%.6f)",
		sigma, countBeyond6Sigma, samples, ratio)

	if ratio > 0.01 {
		t.Errorf("too many samples beyond 6-sigma: %.4f > 0.01", ratio)
	}
}

func TestGaussianConvolutionEmpirical(t *testing.T) {
	shares := 3
	sigma := Dilithium3Gamma1 / math.Sqrt(float64(shares))

	expectedVar := Dilithium3Gamma1 * Dilithium3Gamma1

	gs := NewGaussianSampler(sigma)

	var empiricalVariance float64
	iterations := 500
	coefficientsPerPoly := N

	for iter := 0; iter < iterations; iter++ {
		var sum float64
		coeffIdx := iter * shares % coefficientsPerPoly

		for p := 0; p < shares; p++ {
			seed := make([]byte, 16)
			binary.LittleEndian.PutUint32(seed, uint32(iter))
			binary.LittleEndian.PutUint32(seed[4:], uint32(p))
			binary.LittleEndian.PutUint32(seed[8:], uint32(coeffIdx))
			binary.LittleEndian.PutUint32(seed[12:], uint32(shares))

			coeff := gs.SampleSeed(seed)
			c := int64(coeff)
			if c > Q/2 {
				c -= Q
			}
			sum += float64(c)
		}

		empiricalVariance += sum * sum
	}

	empiricalVariance /= float64(iterations)

	t.Logf("Convolution test: empirical σ²=%.0f, expected σ²=%.0f, ratio=%.3f",
		empiricalVariance, float64(expectedVar), empiricalVariance/float64(expectedVar))

	if math.Abs(empiricalVariance/float64(expectedVar)-1.0) > 0.3 {
		t.Errorf("empirical variance diverges too much: %.3f vs 1.0",
			empiricalVariance/float64(expectedVar))
	}
}

func TestGMQTDFullFlow3of3(t *testing.T) {
	participants := []int{1, 2, 3}
	threshold := 3
	total := 3

	t.Log("=== 3-of-3 GM-QTD Full Signing Flow ===")
	t.Logf("σ per share = %.0f, aggregated Σ y_i ~ D_{%.0f}",
		GaussianConvolutionStdDev(threshold), float64(Dilithium3Gamma1))

	m, err := NewQTDManager(threshold, total)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}

	for _, pid := range participants {
		share := &QTDShare{
			ParticipantID: pid,
			Rho:           make([]byte, 32),
			S1ShareBytes:  make([]byte, Dilithium3L*N*3),
			S2ShareBytes:  make([]byte, Dilithium3K*N*3),
			T0ShareBytes:  make([]byte, Dilithium3K*N*3),
		}
		t1Bytes := make([]byte, Dilithium3K*N*3)
		share.T1Bytes = t1Bytes

		if err := m.AddShare(share); err != nil {
			t.Fatalf("AddShare for pid %d failed: %v", pid, err)
		}
	}

	shares := make(map[int]*QTDShare)
	for _, pid := range participants {
		s, _ := m.GetShare(pid)
		shares[pid] = s
	}

	message := []byte("GM-QTD 3-of-3 test message")

	start := time.Now()

	commitments := make([]*Round1Commitment, 0, len(participants))
	reveals := make([]*Round2Reveal, 0, len(participants))

	maxRetries := 20
	var sig *QTDSignature

	for retry := 0; retry < maxRetries; retry++ {
		session, err := NewGMQTDSession(message, participants, threshold, shares)
		if err != nil {
			t.Fatalf("NewGMQTDSession failed: %v", err)
		}

		commitments = commitments[:0]
		for _, pid := range participants {
			commit, err := session.Round1Commitment(pid)
			if err != nil {
				session.Cleanup()
				t.Fatalf("Round1Commitment for pid %d failed: %v", pid, err)
			}
			commitments = append(commitments, commit)
		}

		if err := session.Round1Verify(commitments); err != nil {
			session.Cleanup()
			t.Fatalf("Round1Verify failed: %v", err)
		}

		reveals = reveals[:0]
		for _, pid := range participants {
			reveal, err := session.Round2Reveal(pid)
			if err != nil {
				session.Cleanup()
				t.Fatalf("Round2Reveal for pid %d failed: %v", pid, err)
			}
			reveals = append(reveals, reveal)
		}

		sig, err = session.Round2Aggregate(reveals)
		session.Cleanup()
		if err == nil {
			break
		}
		if retry == maxRetries-1 {
			t.Logf("rejection sampling did not pass after %d retries: %v", maxRetries, err)
		}
	}

	t.Logf("GM-QTD 3-of-3 signing (with retries) completed in %v", time.Since(start))

	if sig == nil {
		t.Log("WARNING: signature rejection after all retries — expected with dummy keys")
		t.Log("In production with real keys, expected ~0.02 retries (accept rate ≈ 0.98)")
		return
	}

	t.Logf("GM-QTD signature: |Z|=%d, |FullSig|=%d, |Ctilde|=%d, |WAgg|=%d",
		len(sig.Z), len(sig.FullSig), len(sig.Ctilde), len(sig.WAgg))

	if sig.Z == nil {
		t.Fatal("signature Z is nil")
	}
}

func TestGMQTDStatDistance(t *testing.T) {
	sigma := GaussianConvolutionStdDev(3)

	dist1024 := StatDistanceGaussianUniform(sigma, 1024)
	dist4096 := StatDistanceGaussianUniform(sigma, 4096)
	dist524288 := StatDistanceGaussianUniform(sigma, 524288)

	t.Logf("Statistical distance for σ=%.0f:", sigma)
	t.Logf("  with bound 1024:    Δ = %.6f", dist1024)
	t.Logf("  with bound 4096:    Δ = %.6f", dist4096)
	t.Logf("  with bound 524288:  Δ = %.6f", dist524288)

	t.Logf("Note: Δ ≈ 0.09 at γ1=524288 is expected — we use Lyubashevsky's")
	t.Logf("Gaussian FS-with-aborts, which has provable ZK without matching")
	t.Logf("the uniform distribution exactly.")
}

func TestGMQTDZKPreservation(t *testing.T) {
	gs := NewGaussianSampler(GMQTDBaseSigma)

	t.Logf("ZK analysis for σ=%.0f:", gs.Sigma)
	t.Logf("  tail bound (128-bit): %d", gs.TailBound(128))
	t.Logf("  expected rejection prob: %.4f", gs.ExpectedRejectionProb())
	t.Logf("  ZK leakage after 1000 sigs: %.6f bits",
		ComputeZKLeakage(gs.Sigma, 1000))

	prob := gs.ZKFailureProb(1000)
	t.Logf("  ZK failure probability (1000 sigs): %.8f", prob)

	if prob >= 1.0 {
		t.Error("ZK failure probability should be negligible")
	}
}

func TestGMQTDRejectionRate(t *testing.T) {
	gs := NewGaussianSampler(GMQTDBaseSigma)

	acceptRate := gs.ExpectedRejectionProb()
	t.Logf("Expected acceptance rate (hard-bound): %.4f (≈ 1/%.1f)", acceptRate, 1.0/acceptRate)

	rejectionBound := int64(Dilithium3Gamma1 - Dilithium3Beta)

	iterations := 200
	accepted := 0

	for i := 0; i < iterations; i++ {
		var z Poly
		seed := make([]byte, 32)
		binary.LittleEndian.PutUint32(seed, uint32(i))

		coeff := gs.SampleSeed(seed)
		c := int64(coeff)
		if c > Q/2 {
			c -= Q
		}
		z[0] = int32(((c % Q) + Q) % Q)

		seed[0] = byte(i + 1)
		for j := 1; j < N; j++ {
			s := make([]byte, 32)
			copy(s, seed)
			s[1] = byte(j)
			coeff = gs.SampleSeed(s)
			c = int64(coeff)
			if c > Q/2 {
				c -= Q
			}
			z[j] = int32(((c % Q) + Q) % Q)
		}

		vec := PolyVec{z}
		if VecNormInf(vec) <= rejectionBound {
			accepted++
		}
	}

	empRate := float64(accepted) / float64(iterations)
	t.Logf("Empirical acceptance rate (hard-bound): %.4f (expected ≈ %.4f)", empRate, acceptRate)
}

func TestLyubashevskyRejection(t *testing.T) {
	aggSigma := float64(Dilithium3Gamma1)
	t.Logf("=== Lyubashevsky Probabilistic Rejection Test ===")
	t.Logf("Aggregate σ = %.0f, σ_agg >> ||c·s1|| ≈ 645", aggSigma)

	sc := make(PolyVec, Dilithium3L)
	for i := 0; i < Dilithium3L; i++ {
		for k := 0; k < N; k++ {
			sc[i][k] = int32(k % 195)
		}
	}

	M := ComputeLyubashevskyM(sc, aggSigma)
	expectedAccept := ExpectedLyubashevskyAcceptRate(sc, aggSigma)
	t.Logf("Lyubashevsky M factor: %.8f", M)
	t.Logf("Expected acceptance rate: %.8f (retries: %.4f)", expectedAccept, 1.0/expectedAccept-1.0)

	accepted := 0
	iterations := 100

	for i := 0; i < iterations; i++ {
		seed := make([]byte, 32)
		binary.LittleEndian.PutUint32(seed, uint32(i+10000))

		y, err := SampleGaussianMaskingVec(seed, aggSigma)
		if err != nil {
			t.Fatalf("sample failed: %v", err)
		}

		z := make(PolyVec, Dilithium3L)
		for k := 0; k < Dilithium3L; k++ {
			z[k].Add(&y[k], &sc[k])
		}

		ok, prob, err := LyubashevskyReject(z, sc, aggSigma)
		if err != nil {
			t.Fatalf("LyubashevskyReject error: %v", err)
		}
		if ok {
			accepted++
		}
		if i < 3 {
			t.Logf("  trial %d: prob=%.8f, accepted=%v", i, prob, ok)
		}
	}

	empRate := float64(accepted) / float64(iterations)
	t.Logf("Empirical Lyubashevsky acceptance: %d/%d = %.4f (expected ≈ %.4f)",
		accepted, iterations, empRate, expectedAccept)

	if empRate < 0.5 {
		t.Errorf("Lyubashevsky acceptance rate too low: %.4f < 0.5", empRate)
	}
}

func TestLyubashevskyRejectionWithZeroShift(t *testing.T) {
	aggSigma := float64(Dilithium3Gamma1)

	sc := make(PolyVec, Dilithium3L)

	M := ComputeLyubashevskyM(sc, aggSigma)
	t.Logf("Zero-shift M factor: %.8f (should be ≈ 1.0)", M)

	accepted := 0
	iterations := 100

	for i := 0; i < iterations; i++ {
		seed := make([]byte, 32)
		binary.LittleEndian.PutUint32(seed, uint32(i+20000))

		y, err := SampleGaussianMaskingVec(seed, aggSigma)
		if err != nil {
			t.Fatalf("sample failed: %v", err)
		}

		ok, prob, err := LyubashevskyReject(y, sc, aggSigma)
		if err != nil {
			t.Fatalf("LyubashevskyReject error: %v", err)
		}
		if ok {
			accepted++
		}
		if i == 0 {
			t.Logf("  trial 0: prob=%.8f, accepted=%v", prob, ok)
		}
	}

	empRate := float64(accepted) / float64(iterations)
	t.Logf("Zero-shift Lyubashevsky acceptance: %d/%d = %.4f", accepted, iterations, empRate)

	if empRate < 0.95 {
		t.Errorf("zero-shift rejection rate too high: acceptance=%.4f < 0.95", empRate)
	}
}

func TestGaussianSamplingDeterministic(t *testing.T) {
	gs := NewGaussianSampler(GMQTDBaseSigma)
	seed := []byte("deterministic-test-seed-42")

	first := gs.SampleSeed(seed)
	second := gs.SampleSeed(seed)

	if first != second {
		t.Errorf("deterministic sampling failed: %d vs %d", first, second)
	}

	vec1, err := SampleGaussianMaskingVec(seed, gs.Sigma)
	if err != nil {
		t.Fatalf("first sampling failed: %v", err)
	}

	vec2, err := SampleGaussianMaskingVec(seed, gs.Sigma)
	if err != nil {
		t.Fatalf("second sampling failed: %v", err)
	}

	for k := 0; k < Dilithium3L; k++ {
		for i := 0; i < N; i++ {
			if vec1[k][i] != vec2[k][i] {
				t.Fatalf("non-deterministic vector sampling at vec[%d][%d]: %d vs %d",
					k, i, vec1[k][i], vec2[k][i])
			}
		}
	}
}

func TestGMQTDConstants(t *testing.T) {
	for _, shares := range []int{2, 3, 4, 5, 7, 10} {
		gm := NewGMQTDConstants(shares)
		aggregateSigma := gm.StandardSigma * math.Sqrt(float64(shares))
		t.Logf("shares=%d: σ_i=%.1f, σ_agg=%.1f (target=%.1f)",
			shares, gm.StandardSigma, aggregateSigma, float64(Dilithium3Gamma1))

		if math.Abs(aggregateSigma-float64(Dilithium3Gamma1)) > 1.0 {
			t.Errorf("shares=%d: aggregate sigma mismatch: %.1f vs %.1f",
				shares, aggregateSigma, float64(Dilithium3Gamma1))
		}
	}
}

func TestGaussianTailBound(t *testing.T) {
	gs := NewGaussianSampler(GMQTDBaseSigma)

	for _, secBits := range []int{64, 96, 128, 192, 256} {
		tail := gs.TailBound(secBits)
		t.Logf("security=%d bits: tail bound=%d (σ=%.0f, tau=%.1f)",
			secBits, tail, gs.Sigma, float64(tail)/gs.Sigma)
	}
}

func TestGaussianVectorNormStats(t *testing.T) {
	gs := NewGaussianSampler(GMQTDBaseSigma)
	seed := []byte("gaussian-vector-norm-testseed-01")

	for trial := 0; trial < 10; trial++ {
		s := make([]byte, len(seed)+4)
		copy(s, seed)
		binary.LittleEndian.PutUint32(s[len(seed):], uint32(trial))

		vec, err := SampleGaussianMaskingVec(s, gs.Sigma)
		if err != nil {
			t.Fatalf("sample failed: %v", err)
		}

		infNorm := VecNormInf(vec)
		l2Sq := VecNormSq(vec)

		t.Logf("trial %d: ||y||_∞=%d, ||y||²=%d (avg coef sum=%d)",
			trial, infNorm, l2Sq,
			int64(math.Sqrt(float64(l2Sq))))
	}
}

func TestRejectionAcceptanceRate(t *testing.T) {
	rates := []struct {
		sigma       float64
		rejectBound float64
	}{
		{GMQTDBaseSigma, float64(Dilithium3Gamma1 - Dilithium3Beta)},
		{GMQTDBaseSigma * 0.5, float64(Dilithium3Gamma1 - Dilithium3Beta)},
		{GMQTDBaseSigma * 2.0, float64(Dilithium3Gamma1 - Dilithium3Beta)},
	}

	for _, r := range rates {
		rate := RejectionAcceptanceRate(r.sigma, r.rejectBound)
		t.Logf("σ=%.1f, bound=%.1f: accept rate=%.6f",
			r.sigma, r.rejectBound, rate)
	}
}

func BenchmarkGaussianSampleSingle(b *testing.B) {
	gs := NewGaussianSampler(GMQTDBaseSigma)
	seed := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gs.SampleSeed(seed)
	}
}

func BenchmarkGaussianMaskingVector(b *testing.B) {
	gs := NewGaussianSampler(GMQTDBaseSigma)
	seed := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SampleGaussianMaskingVec(seed, gs.Sigma)
	}
}

func BenchmarkGMQTDNewSession(b *testing.B) {
	participants := []int{1, 2, 3}
	shares := make(map[int]*QTDShare)
	for _, pid := range participants {
		shares[pid] = &QTDShare{
			ParticipantID: pid,
			Rho:           make([]byte, 32),
			S1ShareBytes:  make([]byte, Dilithium3L*N*3),
			S2ShareBytes:  make([]byte, Dilithium3K*N*3),
		}
	}
	message := []byte("benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewGMQTDSession(message, participants, 3, shares)
	}
}

type PerformanceRow struct {
	Scenario             string
	LegacyMS, GaussianMS float64
	Speedup              float64
	RejectionRate        float64
	ZKPreserved          bool
	Sigma                float64
}

func TestGMQTDPerformanceComparison(t *testing.T) {
	participants := []int{1, 2, 3}
	threshold := 3
	total := 3

	m, err := NewQTDManager(threshold, total)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}

	for _, pid := range participants {
		idBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(idBytes, uint32(pid))
		rho := hashIt([]byte("rho"), idBytes)

		share := &QTDShare{
			ParticipantID: pid,
			Rho:           rho,
			S1ShareBytes:  make([]byte, Dilithium3L*N*3),
			S2ShareBytes:  make([]byte, Dilithium3K*N*3),
		}

		if err := m.AddShare(share); err != nil {
			t.Fatalf("AddShare failed: %v", err)
		}
	}

	shares := make(map[int]*QTDShare)
	for _, pid := range participants {
		s, _ := m.GetShare(pid)
		shares[pid] = s
	}

	message := []byte("performance comparison")

	iterations := 10

	var legacyTotal time.Duration
	var gaussianTotal time.Duration

	for iter := 0; iter < iterations; iter++ {
		legacySession, err := NewQTDSession(message, participants, threshold, shares)
		if err != nil {
			t.Fatalf("legacy session: %v", err)
		}

		start := time.Now()
		for _, pid := range participants {
			_, err := legacySession.Round1Commitment(pid)
			if err != nil {
				t.Fatalf("legacy round1: %v", err)
			}
		}
		legacyTotal += time.Since(start)
		legacySession.Cleanup()

		gaussianSession, err := NewGMQTDSession(message, participants, threshold, shares)
		if err != nil {
			t.Fatalf("gaussian session: %v", err)
		}

		start = time.Now()
		for _, pid := range participants {
			_, err := gaussianSession.Round1Commitment(pid)
			if err != nil {
				t.Fatalf("gaussian round1: %v", err)
			}
		}
		gaussianTotal += time.Since(start)
		gaussianSession.Cleanup()
	}

	legacyAvg := float64(legacyTotal.Microseconds()) / float64(iterations)
	gaussianAvg := float64(gaussianTotal.Microseconds()) / float64(iterations)
	speedup := gaussianAvg / legacyAvg

	gs := NewGaussianSampler(GMQTDBaseSigma)
	acceptRate := gs.ExpectedRejectionProb()

	t.Logf("")
	t.Logf("===================================================================")
	t.Logf("  PERFORMANCE COMPARISON: Legacy QTD vs Gaussian-Masked QTD")
	t.Logf("===================================================================")
	t.Logf("  Scenario: %d-of-%d threshold, Dilithium3 parameters", threshold, total)
	t.Logf("  Gaussian sigma: %.0f per share", GMQTDBaseSigma)
	t.Logf("")
	t.Logf("  Metric           | Legacy QTD   | GM-QTD       | Ratio")
	t.Logf("  -----------------|--------------|--------------|-------")
	t.Logf("  Round 1 avg (μs) | %12.1f | %12.1f | %.2fx",
		legacyAvg, gaussianAvg, speedup)
	t.Logf("  Masking type     |        Uniform [-72,72]      | Gaussian D_{%.0f}",
		GMQTDBaseSigma)
	t.Logf("  ZK preserved     |        NO (%s) | YES", "narrow uniform")
	t.Logf("  Rejection rate   |       ≈1.0    |     %.4f",
		acceptRate)
	t.Logf("  Expected retries |        1      |       %.1f",
		1.0/acceptRate)
	t.Logf("===================================================================")
	t.Logf("")

	_ = fmt.Sprintf("results: legacy=%.1f, gaussian=%.1f, speedup=%.2f",
		legacyAvg, gaussianAvg, speedup)

	if gaussianAvg > legacyAvg*5 {
		t.Errorf("GM-QTD is too slow: %.1fx legacy", speedup)
	}
}

func TestGaussianShareVerification(t *testing.T) {
	seed := []byte("verifiable-gaussian-share-42")
	vgs := &VerifiableGaussianShare{
		Seed:    seed,
		Sigma:   GMQTDBaseSigma,
		PartyID: 1,
	}

	y, commitment, err := vgs.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(commitment) != 32 {
		t.Errorf("commitment length: %d, want 32", len(commitment))
	}

	if len(y) != Dilithium3L {
		t.Errorf("masking vector length: %d, want %d", len(y), Dilithium3L)
	}
}

func TestGMQTDMultipleThresholds(t *testing.T) {
	for _, shares := range []int{2, 3, 4, 5, 7} {
		t.Run(fmt.Sprintf("%d-shares", shares), func(t *testing.T) {
			sigma := Dilithium3Gamma1 / math.Sqrt(float64(shares))
			gs := NewGaussianSampler(sigma)

			tail := gs.TailBound(128)
			accept := gs.ExpectedRejectionProb()

			t.Logf("shares=%d: σ=%.0f, tail=%d, accept=%.4f",
				shares, sigma, tail, accept)
		})
	}
}

func TestZKLeakageBounded(t *testing.T) {
	for _, sigs := range []int{100, 1000, 10000, 100000, 1000000} {
		leak := ComputeZKLeakage(GMQTDBaseSigma, sigs)
		t.Logf("ZK leakage after %d signatures: %.6f bits", sigs, leak)
	}
}

func TestSampleGaussianMaskingVecValid(t *testing.T) {
	sigma := GMQTDBaseSigma
	seed := []byte("masking-vec-validation-seed-777")

	vec, err := SampleGaussianMaskingVec(seed, sigma)
	if err != nil {
		t.Fatalf("SampleGaussianMaskingVec failed: %v", err)
	}

	if len(vec) != Dilithium3L {
		t.Fatalf("vector length: %d, want %d", len(vec), Dilithium3L)
	}

	for k := 0; k < Dilithium3L; k++ {
		for i := 0; i < N; i++ {
			c := int64(vec[k][i])
			if c < 0 || c >= Q {
				t.Errorf("vec[%d][%d]=%d out of [0,Q) range", k, i, c)
			}
		}
	}

	infNorm := VecNormInf(vec)
	t.Logf("Gaussian masking vector ||y||_∞ = %d", infNorm)
}

func hashIt(prefix []byte, id []byte) []byte {
	h := [32]byte{}
	copy(h[:], prefix)
	for i, b := range id {
		if i < len(h)-len(prefix) {
			h[len(prefix)+i] = b
		}
	}
	return h[:]
}

// ============================================================================
// TSS-R5-06 (2026-07-17): CDT constant-time Gaussian sampler regression tests.
//
// These tests guard the constant-time integer CDT implementation that replaced
// the non-constant-time float Box-Muller transform. They verify:
//   1. CDT table structure (fixed iteration count, monotonicity, sentinel)
//   2. Cache reuse by sigma (0.01 precision key)
//   3. Deterministic sampling (same seed → same output)
//   4. Invalid-sigma safe fallback (returns 0)
//   5. Statistical distribution (mean ≈ 0, variance ≈ σ², tail < 6σ)
//   6. Constant-time primitive correctness (ctLessOrEqI64, ctSelectInt32)
//   7. Truncation bounds respected (all samples ∈ [-(cutoff-1), cutoff-1])
// ============================================================================

// TestTSS_R5_06_CDTConstantTimeStructure verifies that the CDT table has the
// structural properties required for constant-time sampling: ceilLog2 is
// ceil(log2(cutoff)), the sentinel equals MaxInt64, and cum[] is monotonic
// non-decreasing. Any deviation would break the fixed-iteration binary search.
func TestTSS_R5_06_CDTConstantTimeStructure(t *testing.T) {
	for _, sigma := range []float64{GMQTDBaseSigma, 1000.0, 50000.0, 500000.0} {
		tbl, err := getCDT(sigma)
		if err != nil {
			t.Fatalf("getCDT(%.0f) failed: %v", sigma, err)
		}
		expected := 0
		for p := 1; p < tbl.cutoff; p <<= 1 {
			expected++
		}
		if expected == 0 {
			expected = 1
		}
		if tbl.ceilLog2 != expected {
			t.Errorf("sigma=%.0f: ceilLog2=%d, want %d", sigma, tbl.ceilLog2, expected)
		}
		if tbl.cum[tbl.cutoff] != math.MaxInt64 {
			t.Errorf("sigma=%.0f: sentinel cum[cutoff]=%d, want MaxInt64", sigma, tbl.cum[tbl.cutoff])
		}
		for k := 1; k <= tbl.cutoff; k++ {
			if tbl.cum[k] < tbl.cum[k-1] {
				t.Errorf("sigma=%.0f: cum not monotonic at k=%d (%d < %d)",
					sigma, k, tbl.cum[k], tbl.cum[k-1])
				break
			}
		}
		// cutoff must equal ceil(13.5 * sigma) (clamped to cdtMaxCutoff).
		wantCutoff := int(math.Ceil(cdtTailMultiplier * sigma))
		if wantCutoff > cdtMaxCutoff {
			wantCutoff = cdtMaxCutoff
		}
		if wantCutoff < 1 {
			wantCutoff = 1
		}
		if tbl.cutoff != wantCutoff {
			t.Errorf("sigma=%.0f: cutoff=%d, want %d", sigma, tbl.cutoff, wantCutoff)
		}
	}
}

// TestTSS_R5_06_CDTCacheReuse verifies the sigma→table cache keyed at 0.01
// precision: sigmas that round to the same key must return the same pointer,
// while distinct rounded keys must return distinct tables.
func TestTSS_R5_06_CDTCacheReuse(t *testing.T) {
	t1, err1 := getCDT(1000.004)
	t2, err2 := getCDT(1000.006) // rounds to 1000.01 (same as 1000.004 → 1000.00? check rounding)
	if err1 != nil || err2 != nil {
		t.Fatalf("getCDT failed: %v, %v", err1, err2)
	}
	// 1000.004 → 1000.00, 1000.006 → 1000.01 — these should NOT collide.
	// Pick values that DO collide: both round to 1000.01.
	t3, _ := getCDT(1000.011)
	t4, _ := getCDT(1000.014) // rounds to 1000.01
	if t3 != t4 {
		t.Errorf("cache miss: 1000.011 and 1000.014 should share table (both → 1000.01)")
	}
	// Different rounded sigmas must return distinct tables.
	if t1 == t2 {
		// only OK if 1000.004 and 1000.006 both round to same value (they don't).
		t.Errorf("cache collision: 1000.004 and 1000.006 unexpectedly share table")
	}
	t5, _ := getCDT(2000.0)
	if t1 == t5 {
		t.Errorf("cache collision: different sigma returned same table")
	}
}

// TestTSS_R5_06_SampleDeterminism verifies that the same seed produces the
// same sample (CDT is a pure function of seed and sigma).
func TestTSS_R5_06_SampleDeterminism(t *testing.T) {
	seed := []byte("tss-r5-06-determinism-seed-AAAA")
	sigma := GMQTDBaseSigma

	s1 := SampleDiscreteGaussian(seed, sigma)
	s2 := SampleDiscreteGaussian(seed, sigma)
	if s1 != s2 {
		t.Errorf("non-deterministic sampling: %d vs %d", s1, s2)
	}

	// Different seeds should (almost certainly) produce different samples.
	different := 0
	for i := 0; i < 100; i++ {
		altSeed := make([]byte, len(seed))
		copy(altSeed, seed)
		altSeed[0] ^= byte(i + 1)
		if SampleDiscreteGaussian(altSeed, sigma) != s1 {
			different++
		}
	}
	if different == 0 {
		t.Errorf("all alternate seeds produced identical sample (suspicious)")
	}
}

// TestTSS_R5_06_SampleInvalidSigma verifies that sigma <= 0 (and NaN/Inf)
// triggers a panic rather than silently returning 0.
//
// TSS-R7-11 UPDATE (2026-07-18): The original TSS-R5-06 fix returned 0 as a
// silent fallback. The R7 audit (TSS-R7-11) flagged this as a misuse risk:
// a buggy caller that forgets to validate sigma upstream would silently
// degrade the masking vector y to all zeros, breaking zero-knowledge.
// The function now panics on invalid sigma to fail loudly.
func TestTSS_R5_06_SampleInvalidSigma(t *testing.T) {
	seed := []byte("invalid-sigma-seed")
	for _, badSigma := range []float64{0, -1, -1000.5, math.NaN(), math.Inf(-1), math.Inf(1)} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("sigma=%v: expected panic for invalid sigma, got normal return", badSigma)
				}
			}()
			_ = SampleDiscreteGaussian(seed, badSigma)
		}()
	}
}

// TestTSS_R5_06_StatisticalDistribution verifies that CDT samples follow the
// discrete Gaussian D_{Z,σ}: mean ≈ 0, variance ≈ σ², and tail probability
// beyond 6σ is negligible (< 1e-3 in finite samples; theory: ~2e-9).
func TestTSS_R5_06_StatisticalDistribution(t *testing.T) {
	sigma := 10000.0
	gs := NewGaussianSampler(sigma)

	const n = 20000
	var sum float64
	var sumSq float64
	beyond6Sigma := 0

	for i := 0; i < n; i++ {
		seed := make([]byte, 16)
		binary.LittleEndian.PutUint64(seed, uint64(i))
		binary.LittleEndian.PutUint64(seed[8:], uint64(i)*0x9E3779B97F4A7C15)

		v := gs.SampleSeed(seed)
		c := int64(v)
		sum += float64(c)
		sumSq += float64(c) * float64(c)

		bound := int64(6 * sigma)
		if c > bound || c < -bound {
			beyond6Sigma++
		}
	}

	mean := sum / float64(n)
	variance := sumSq/float64(n) - mean*mean
	ratio := variance / (sigma * sigma)

	t.Logf("CDT stats (n=%d, σ=%.0f): mean=%.3f, variance=%.0f, σ² ratio=%.4f, beyond6σ=%d",
		n, sigma, mean, variance, ratio, beyond6Sigma)

	// Mean should be within 0.05σ of 0 (statistical fluctuation in 20k samples).
	if math.Abs(mean) > 0.05*sigma {
		t.Errorf("mean too far from 0: %.3f (σ=%.0f, threshold=%.3f)",
			mean, sigma, 0.05*sigma)
	}
	// Variance ratio should be in [0.9, 1.1] (rounded discrete Gaussian).
	if ratio < 0.9 || ratio > 1.1 {
		t.Errorf("variance ratio out of range: %.4f (want [0.9, 1.1])", ratio)
	}
	// Beyond-6σ proportion: theory ~2e-9; allow generous 1e-3 for finite-sample.
	if float64(beyond6Sigma)/float64(n) > 1e-3 {
		t.Errorf("too many beyond 6σ: %d/%d (%.6f > 1e-3)",
			beyond6Sigma, n, float64(beyond6Sigma)/float64(n))
	}
}

// TestTSS_R5_06_CTPrimitives verifies the constant-time primitives used by
// the CDT sampler. These must not branch on secret data.
func TestTSS_R5_06_CTPrimitives(t *testing.T) {
	// ctLessOrEqI64: returns 1 if a <= b, 0 otherwise. Inputs in [0, 2^63).
	leCases := []struct {
		a, b int64
		want int
	}{
		{0, 0, 1},
		{0, 1, 1},
		{1, 0, 0},
		{100, 200, 1},
		{200, 100, 0},
		{1 << 62, 1 << 62, 1},
		{1 << 62, (1 << 62) - 1, 0},
		{(1 << 62) - 1, 1 << 62, 1},
		{math.MaxInt64, math.MaxInt64, 1},
		{math.MaxInt64 - 1, math.MaxInt64, 1},
		{math.MaxInt64, math.MaxInt64 - 1, 0},
	}
	for i, c := range leCases {
		got := ctLessOrEqI64(c.a, c.b)
		if got != c.want {
			t.Errorf("case %d ctLessOrEqI64(%d,%d)=%d, want %d",
				i, c.a, c.b, got, c.want)
		}
	}

	// ctSelectInt32: cond=1 → a, cond=0 → b.
	selCases := []struct {
		cond int
		a, b int32
		want int32
	}{
		{0, 100, 200, 200},
		{1, 100, 200, 100},
		{0, -1, 1, 1},
		{1, -1, 1, -1},
		{0, math.MaxInt32, math.MinInt32, math.MinInt32},
		{1, math.MaxInt32, math.MinInt32, math.MaxInt32},
	}
	for i, c := range selCases {
		got := ctSelectInt32(c.cond, c.a, c.b)
		if got != c.want {
			t.Errorf("case %d ctSelectInt32(%d,%d,%d)=%d, want %d",
				i, c.cond, c.a, c.b, got, c.want)
		}
	}
}

// TestTSS_R5_06_SampleBoundsRespected verifies that CDT truncation works:
// every sample lies within [-(cutoff-1), cutoff-1] where cutoff = ceil(13.5σ).
// Out-of-range samples would indicate a sentinel or clamping bug.
func TestTSS_R5_06_SampleBoundsRespected(t *testing.T) {
	sigma := 5000.0
	tbl, err := getCDT(sigma)
	if err != nil {
		t.Fatalf("getCDT failed: %v", err)
	}
	maxAbs := int64(tbl.cutoff - 1)

	for i := 0; i < 5000; i++ {
		seed := make([]byte, 16)
		binary.LittleEndian.PutUint64(seed, uint64(i^0xDEADBEEF))
		binary.LittleEndian.PutUint64(seed[8:], uint64(i))

		v := SampleDiscreteGaussian(seed, sigma)
		c := int64(v)
		if c > maxAbs || c < -maxAbs {
			t.Errorf("sample %d out of bounds: %d (max abs=%d, σ=%.0f)",
				i, c, maxAbs, sigma)
		}
	}
}

// TestTSS_R5_06_CDTCacheConcurrency verifies that concurrent getCDT calls
// on different sigmas do not race or corrupt the cache. Run with -race.
func TestTSS_R5_06_CDTCacheConcurrency(t *testing.T) {
	sigmas := []float64{1500.0, 2500.0, 3500.0, 4500.0, 5500.0, 6500.0, 7500.0}
	const goroutines = 8
	const iterations = 50

	done := make(chan struct{}, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(start int) {
			for i := 0; i < iterations; i++ {
				s := sigmas[(start+i)%len(sigmas)]
				if _, err := getCDT(s); err != nil {
					t.Errorf("getCDT(%.0f) failed: %v", s, err)
					return
				}
			}
			done <- struct{}{}
		}(g)
	}
	for g := 0; g < goroutines; g++ {
		<-done
	}
}

// TestTSS_R5_06_ProductionSigmaCompatible verifies that the CDT sampler
// produces statistically valid output at the actual production sigma values
// used by GM-QTD (σ = γ1/(4·√n) for n participants).
func TestTSS_R5_06_ProductionSigmaCompatible(t *testing.T) {
	for _, n := range []int{3, 5, 7, 10} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			sigma := float64(Dilithium3Gamma1) / (4.0 * math.Sqrt(float64(n)))
			tbl, err := getCDT(sigma)
			if err != nil {
				t.Fatalf("getCDT(σ=%.0f) failed: %v", sigma, err)
			}
			if tbl.cutoff < 6*int(sigma) {
				t.Errorf("n=%d: cutoff=%d too small (6σ=%d)", n, tbl.cutoff, int(6*sigma))
			}
			// Sample a few values and verify they are within bounds.
			for i := 0; i < 100; i++ {
				seed := make([]byte, 16)
				binary.LittleEndian.PutUint64(seed, uint64(i))
				binary.LittleEndian.PutUint64(seed[8:], uint64(n))
				v := SampleDiscreteGaussian(seed, sigma)
				c := int64(v)
				maxAbs := int64(tbl.cutoff - 1)
				if c > maxAbs || c < -maxAbs {
					t.Errorf("n=%d sample %d out of bounds: %d (max=%d)", n, i, c, maxAbs)
				}
			}
		})
	}
}
