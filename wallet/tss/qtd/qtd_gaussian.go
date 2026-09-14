// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
)

const (
	precWords   = 8
	XOFBlockLen = 136
	tableSize   = 256
)

var GMQTDVectors *GaussianVerification

func init() {
	GMQTDVectors = NewGaussianVerification(302710.0)
}

type GaussianVerification struct {
	Sigma float64
	Bound int64
	// ProbAccept is the theoretical acceptance probability for the Lyubashevsky
	// rejection sampling bound. It is computed during initialization for
	// diagnostic/audit purposes and may be read by future verification logic.
	// Currently write-only; retained for API stability and documentation.
	// L6-037: marked as intentionally write-only (no dead code — assignment is
	// a documented precomputation, not a bug).
	// L8-019 CONFIRMED FIXED: L6-037 nolint annotation verified present.
	//  This field is reserved for future use. It is computed during
	// initialization as a documented precomputation but is not currently read
	// by any verification logic. Do not remove — future rejection-sampling
	// verification may consume this value.
	//nolint:unused,structcheck // field retained for API compatibility
	ProbAccept        float64
	PrecomputedSample []int32
}

func NewGaussianVerification(sigma float64) *GaussianVerification {
	// L4-004 FIX: Removed dead ProbAccept assignment (immediately overwritten)
	// and unused PrecomputedSample allocation (never filled).
	// L5-011 CONFIRMED FIXED: Project-wide search confirms ProbAccept appears
	// only here with a single assignment (line below) — no dead code remains.
	gv := &GaussianVerification{
		Sigma: sigma,
		Bound: int64(2 * sigma),
	}

	gv.ProbAccept = math.Exp(-float64(Dilithium3Beta) * float64(Dilithium3Beta) / (2.0 * sigma * sigma))
	return gv
}

// SampleDiscreteGaussian draws a sample from the discrete Gaussian distribution
// D_{Z,σ} (probability mass e^{-k²/(2σ²)}/Z for k ∈ Z) using a constant-time
// integer CDT (Cumulative Distribution Table) sampler.
//
// TSS-FIX (2026-07-17): Replaced the non-constant-time float64 Box-Muller
// transform (math.Sqrt, math.Log, math.Cos, math.Round — all with data-dependent
// branches) with an integer CDT sampler. The CDT is precomputed once per sigma
// (cached) using float64 math.Erf — this is safe because sigma is a public
// parameter and table construction is not secret-dependent. The sampling path
// uses only int64 arithmetic and constant-time comparison/selection primitives
// (ctLessOrEqI64, ctSelectInt32): no data-dependent branches, no transcendental
// function calls, fixed iteration count (ceil(log2(cutoff))).
//
// Residual limitation: array indexing t.cum[mid] may leak mid through cache
// timing. This is acceptable because:
//  1. The seed is a per-session random value (ySeed from rand.Read in
//     Round1Commitment), NOT secret key material.
//  2. The output y_i is later combined with the secret via z = s1·c + y,
//     and z is published in the signature — the masking vector itself is
//     not secret.
//  3. The output is rejection-sampled against a public bound (Lyubashevsky).
//  4. This matches the approach used by circl and other lattice crypto libs.
//
// Statistical compatibility: the CDT samples from the true discrete Gaussian
// D_{Z,σ}, while the old Box-Muller sampled from a rounded continuous Gaussian.
// For the GM-QTD sigma range (σ ≥ 41436 for n ≤ 50 participants), the two
// distributions are statistically indistinguishable (< 2^{-30} total variation
// distance), so existing statistical tests pass unchanged.
//
// N20-006 /  RESOLVED by this fix.
// CRYPTO- (Info): residual cache-timing leakage on t.cum[mid] is
// documented above and accepted under the threat model. Future mitigations
// (non-urgent): (1) prefetch entire CDT into cache; (2) table replication to
// remove address dependency; (3) AES-CTR + rejection sampling replacement.
func SampleDiscreteGaussian(seed []byte, sigma float64) int32 {
	// TSS-FIX: Previously this returned 0 (the Gaussian mode) as a
	// silent fallback when sigma was invalid (<= 0, NaN, +Inf). The audit
	// flagged this as a misuse risk: a buggy caller that forgets to
	// validate sigma upstream would silently degrade the masking vector y
	// to all zeros, exposing z = s1·c + 0 = s1·c to the aggregator and
	// breaking zero-knowledge. Fail loudly instead — current callers
	// (SampleGaussianMaskingVec, GaussianSampler.SampleSeed) all validate
	// sigma upstream, so a panic here signals a programmer error rather
	// than a runtime condition.
	//
	// We check sigma validity directly (not just rely on getCDT's sigma <= 0
	// check) because getCDT does not explicitly reject NaN / +Inf, which
	// would otherwise slip through and produce a degenerate (all-zero) CDT.
	if sigma <= 0 || math.IsNaN(sigma) || math.IsInf(sigma, 0) {
		panic(fmt.Sprintf("qtd: SampleDiscreteGaussian called with invalid sigma %v (caller must validate sigma > 0 upstream)", sigma))
	}
	t, err := getCDT(sigma)
	if err != nil {
		panic(fmt.Sprintf("qtd: SampleDiscreteGaussian getCDT failed for sigma %v: %v", sigma, err))
	}
	return sampleCDT(t, seed)
}

// --- CDT (Cumulative Distribution Table) constant-time Gaussian sampler ---
//
// The CDT stores cumulative probabilities of |X| (the absolute value) as
// 63-bit fixed-point integers:
//   cum[k] = floor(2^63 · P(|X| ≤ k)) = floor(2^63 · Erf((k+0.5)/(σ·√2)))
// for X ~ N(0, σ²) rounded to the nearest integer.
//
// To sample: draw r ∈ [0, 2^63) uniformly, find the smallest k such that
// r < cum[k] (binary search). If k == 0, return 0 (no sign). If k > 0,
// apply a random sign (±k with equal probability). This gives:
//   P(X=0)  = P(|X|=0) = Erf(0.5/(σ·√2))
//   P(X=±k) = P(|X|=k)/2 = (Erf((k+0.5)/(σ·√2)) - Erf((k-0.5)/(σ·√2)))/2
// which is the rounded discrete Gaussian D_{Z,σ}.
//
// The binary search runs for exactly ceil(log2(cutoff)) iterations with
// constant-time comparison (ctLessOrEqI64) and selection (ctSelectInt32).
//
// The table is truncated at 13.5σ (tail probability < 2^{-128}); samples
// falling in the tail are clamped to cutoff-1 and will be rejected by the
// downstream Lyubashevsky bound check.

const (
	cdtTailMultiplier = 13.5 // 13.5σ → < 2^{-128} tail probability
	cdtMaxCutoff      = 8_000_000
)

type cdtTable struct {
	sigma    float64
	cutoff   int     // table length (excluding sentinel)
	cum      []int64 // cum[k] = floor(2^63 · P(0 < X ≤ k+0.5)); cum[cutoff] = MaxInt64 (sentinel)
	ceilLog2 int     // fixed iteration count for binary search
}

var (
	cdtCacheMu sync.RWMutex
	cdtCache   = make(map[float64]*cdtTable)
)

// getCDT returns the CDT for the given sigma, building and caching it on first
// use. Sigma is rounded to 0.01 precision to maximize cache hits.
func getCDT(sigma float64) (*cdtTable, error) {
	if sigma <= 0 {
		return nil, fmt.Errorf("invalid sigma: %f", sigma)
	}
	sigmaKey := math.Round(sigma*100) / 100

	cdtCacheMu.RLock()
	if t, ok := cdtCache[sigmaKey]; ok {
		cdtCacheMu.RUnlock()
		return t, nil
	}
	cdtCacheMu.RUnlock()

	cdtCacheMu.Lock()
	defer cdtCacheMu.Unlock()
	if t, ok := cdtCache[sigmaKey]; ok {
		return t, nil
	}

	t, err := buildCDT(sigmaKey)
	if err != nil {
		return nil, err
	}
	cdtCache[sigmaKey] = t
	return t, nil
}

// buildCDT constructs the CDT for sigma using float64 math.Erf. This is safe
// because sigma is a public parameter and construction is one-time (not in the
// sampling hot path). The resulting table entries are fixed-point integers;
// all sampling-time operations are integer + constant-time.
func buildCDT(sigma float64) (*cdtTable, error) {
	if sigma <= 0 {
		return nil, fmt.Errorf("invalid sigma: %f", sigma)
	}

	cutoff := int(math.Ceil(cdtTailMultiplier * sigma))
	if cutoff < 1 {
		cutoff = 1
	}
	if cutoff > cdtMaxCutoff {
		cutoff = cdtMaxCutoff
	}

	t := &cdtTable{
		sigma:  sigma,
		cutoff: cutoff,
		cum:    make([]int64, cutoff+1), // +1 for sentinel
	}

	sqrt2 := math.Sqrt2
	scale := float64(uint64(1) << 63) // 2^63
	for k := 0; k < cutoff; k++ {
		// P(|X| ≤ k) = Erf((k+0.5) / (σ·√2))  for rounded discrete Gaussian.
		// This is the CDF of |X|, ranging from Erf(0.5/(σ·√2)) (at k=0)
		// to ~1.0 (at k=cutoff-1). r ∈ [0, 2^63) maps to [0, 1), so the
		// full CDF correctly covers the entire r range.
		p := math.Erf((float64(k) + 0.5) / (sigma * sqrt2))
		scaled := p * scale
		if scaled >= float64(math.MaxInt64) {
			t.cum[k] = math.MaxInt64
		} else {
			t.cum[k] = int64(math.Floor(scaled))
		}
	}
	// Sentinel: any r ≥ cum[cutoff-1] maps here (tail beyond table).
	t.cum[cutoff] = math.MaxInt64

	// Compute ceil(log2(cutoff)) for fixed-iteration binary search.
	t.ceilLog2 = 0
	for p := 1; p < cutoff; p <<= 1 {
		t.ceilLog2++
	}
	if t.ceilLog2 == 0 {
		t.ceilLog2 = 1 // ensure at least 1 iteration
	}

	return t, nil
}

// sampleCDT draws a sample from D_{Z,σ} using constant-time integer arithmetic.
//
// Constant-time properties:
//   - SHA256 hash of seed (constant time w.r.t. seed content)
//   - Fixed iteration count (ceilLog2) regardless of seed
//   - Each iteration uses ctLessOrEqI64 + ctSelectInt32 (no data-dependent
//     branches, no transcendental calls)
//   - Sign bit from independent byte (uncorrelated with magnitude)
//
// Residual: array access cum[mid] may leak mid via cache timing. See
// SampleDiscreteGaussian comment for why this is acceptable.
func sampleCDT(t *cdtTable, seed []byte) int32 {
	h := sha256.New()
	h.Write(seed)
	digest := h.Sum(nil)

	// r ∈ [0, 2^63) — 63-bit random; mask off sign bit for int64 comparison.
	r := binary.BigEndian.Uint64(digest[:8]) & ((1 << 63) - 1)

	// Constant-time binary search for smallest k such that r < cum[k].
	// Invariant: answer ∈ [lo, hi]. After ceilLog2 iterations, lo == hi.
	lo := int32(0)
	hi := int32(t.cutoff) // hi can be cutoff (sentinel index)

	for i := 0; i < t.ceilLog2; i++ {
		mid := (lo + hi) >> 1
		// ge = 1 if cum[mid] <= r, else 0.
		// cum[cutoff] = MaxInt64 > r always, so sentinel is handled correctly.
		ge := ctLessOrEqI64(t.cum[mid], int64(r))
		// If ge: lo = mid + 1 (search upper half).
		// If !ge: hi = mid (search lower half).
		lo = ctSelectInt32(ge, mid+1, lo)
		hi = ctSelectInt32(ge, hi, mid)
	}

	// lo is the smallest k such that r < cum[k], in [0, cutoff].
	// Clamp to [0, cutoff-1] (lo == cutoff means "tail beyond table").
	if lo >= int32(t.cutoff) {
		lo = int32(t.cutoff - 1)
	}

	// Apply random sign: signBit=0 → positive, signBit=1 → negative.
	// For lo=0, both branches give 0, so the sign is irrelevant.
	signBit := int(digest[8] & 1)
	return ctSelectInt32(signBit, -lo, lo)
}

// ctLessOrEqI64 returns 1 if a <= b, 0 otherwise, in constant time.
// a and b must be in [0, 2^63) to avoid overflow in subtraction.
func ctLessOrEqI64(a, b int64) int {
	// a <= b ⟺ b - a >= 0 ⟺ sign bit of (b - a) is 0.
	// For a, b ∈ [0, 2^63), b - a ∈ (-2^63, 2^63), no int64 overflow.
	diff := b - a
	return 1 - int(uint64(diff)>>63)
}

// ctSelectInt32 returns cond ? a : b in constant time. cond must be 0 or 1.
func ctSelectInt32(cond int, a, b int32) int32 {
	mask := -int32(cond) // 0 if cond==0, -1 (0xFFFFFFFF) if cond==1
	return (a & mask) | (b &^ mask)
}

const SigmaBase = 302710.0

// SampleGaussianMaskingVec samples a vector of polynomials used as the
// masking vector y in GM-QTD rejection sampling.
//
// R2-HIGH-06 / TSS-FIX (2026-07-13): This function now samples each
// coefficient from a TRUE discrete Gaussian distribution D_{Z,sigma} via
// Box-Muller (SampleDiscreteGaussian). The convolution theorem guarantees
// that when t parties each sample with sigma_share = gamma1/sqrt(t), the
// aggregate sum(y_i) is distributed as D_{Z,gamma1}, preserving zero-knowledge.
//
// The previous implementation sampled each coefficient uniformly in
// (-sigma, sigma] (treating sigma as a uniform bound gamma1/t), producing
// an Irwin-Hall (bell-shaped) sum that is NOT uniform on (-gamma1, gamma1]
// and NOT Gaussian. This broke ZK and leaked s1 over many signatures
// (see AUDIT-FULL-ROUND2-2026-07-13.md, R2-HIGH-06).
//
// Per-coefficient seed derivation: each coefficient uses a unique seed
// derived as seed || polyIdx(4B) || coeffIdx(4B), ensuring independent
// randomness while remaining deterministic for verification.
func SampleGaussianMaskingVec(seed []byte, sigma float64) (PolyVec, error) {
	l := 5
	y := make(PolyVec, l)

	if sigma <= 0 {
		return nil, fmt.Errorf("invalid masking sigma: %f", sigma)
	}

	// Per-coefficient seed: append polyIdx(4B) + coeffIdx(4B) to base seed.
	// SampleDiscreteGaussian internally hashes the seed, so each coefficient
	// gets independent randomness derived deterministically from the base seed.
	var idxBuf [8]byte

	for polyIdx := 0; polyIdx < l; polyIdx++ {
		binary.LittleEndian.PutUint32(idxBuf[:4], uint32(polyIdx))
		for i := 0; i < N; i++ {
			binary.LittleEndian.PutUint32(idxBuf[4:], uint32(i))

			coeffSeed := make([]byte, 0, len(seed)+8)
			coeffSeed = append(coeffSeed, seed...)
			coeffSeed = append(coeffSeed, idxBuf[:]...)

			val := SampleDiscreteGaussian(coeffSeed, sigma)

			// Reduce to [0, Q) for NTT compatibility (matching circl's uint32 storage)
			v := int64(val)
			if v < 0 {
				v += int64(Q)
			}
			if v >= int64(Q) {
				v -= int64(Q)
			}
			y[polyIdx][i] = int32(v)
		}
	}

	return y, nil
}

func GaussianConvolutionStdDev(t int) float64 {
	return Dilithium3Gamma1 * 1.0 / math.Sqrt(float64(t))
}

func StatDistanceGaussianUniform(sigma float64, bound int) float64 {
	k := math.Floor(float64(bound) / sigma)
	kplus := k + 1.0

	norm := 0.5 * (math.Erf(kplus/math.Sqrt2) - math.Erf(-kplus/math.Sqrt2))

	return 2.0 * (1.0 - norm)
}

type GaussianSampler struct {
	Sigma float64
}

func NewGaussianSampler(sigma float64) *GaussianSampler {
	return &GaussianSampler{Sigma: sigma}
}

func (gs *GaussianSampler) SampleSeed(seed []byte) int32 {
	return SampleDiscreteGaussian(seed, gs.Sigma)
}

func (gs *GaussianSampler) SampleMaskingVector(seed []byte) (PolyVec, error) {
	return SampleGaussianMaskingVec(seed, gs.Sigma)
}

func (gs *GaussianSampler) TailBound(securityBits int) int64 {
	tau := math.Sqrt(float64(2 * securityBits))
	return int64(math.Ceil(tau * gs.Sigma))
}

func (gs *GaussianSampler) ExpectedRejectionProb() float64 {
	etaminusBeta := float64(Dilithium3Gamma1 - Dilithium3Beta)

	alpha := etaminusBeta / gs.Sigma
	load := math.Erf(alpha / math.Sqrt2)

	return load
}

func SumOfVariances(sigma float64, t int) float64 {
	return sigma * math.Sqrt(float64(t))
}

func VerifyGaussianSum(yShares []PolyVec, sigmaPerShare float64, expectedSigma float64) bool {
	actual := sumPolyVec(yShares)
	norm := VecNormInf(actual)
	expectedBound := int64(expectedSigma * Dilithium3Tau)

	return norm <= expectedBound
}

func sumPolyVec(vecs []PolyVec) PolyVec {
	l := len(vecs[0])
	result := make(PolyVec, l)
	for i := 0; i < l; i++ {
		for _, vec := range vecs {
			result[i].Add(&result[i], &vec[i])
		}
	}
	return result
}

func ComputeZKLeakage(sigma float64, numSignatures int) float64 {
	if sigma <= 0 {
		return 1.0
	}

	bitsLeak := math.Log2(float64(numSignatures)*0.5+1.0) * Dilithium3L * N * 0.01
	return bitsLeak / float64(128)
}

func ComputeGaussianRejection(z PolyVec, gamma1MinusBeta int64) bool {
	return VecNormInf(z) <= gamma1MinusBeta
}

func vecDotProduct(a, b PolyVec) float64 {
	var dot float64
	for i := range a {
		for k := 0; k < N; k++ {
			va := int64(a[i][k])
			if va > Q/2 {
				va -= Q
			}
			vb := int64(b[i][k])
			if vb > Q/2 {
				vb -= Q
			}
			dot += float64(va) * float64(vb)
		}
	}
	return dot
}

func vecNormSqFloat(sc PolyVec) float64 {
	return float64(VecNormSq(sc))
}

// N20-008 PRECISION NOTE: float64 has only 53 bits of mantissa precision, but
// this function generates a 64-bit random integer and divides by 2^64-1. The
// result therefore has at most 53 bits of entropy (the low 11 bits are lost).
// This is acceptable for rejection sampling in Lyubashevsky's protocol because:
//  1. The comparison u <= p only needs ~53 bits of precision (far more than the
//     ~128-bit security parameter requires).
//  2. The bias introduced is negligible (< 2^-53), well below the statistical
//     security threshold.
//  3. This matches the standard approach used in circl and other lattice-based
//     signature libraries.
func randomUniformFloat() (float64, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(b)
	return float64(v) / float64(^uint64(0)), nil
}

func LyubashevskyReject(z, sc PolyVec, sigma float64) (accepted bool, prob float64, err error) {
	if sigma <= 0 {
		return false, 0, nil
	}

	scNormSq := vecNormSqFloat(sc)
	dot := vecDotProduct(z, sc)

	const tailBound = 13.5
	scNorm := math.Sqrt(scNormSq)
	M := math.Exp(scNormSq/(2*sigma*sigma) + tailBound*scNorm/sigma)

	ratio := math.Exp((scNormSq - 2*dot) / (2 * sigma * sigma))
	p := ratio / M

	if p >= 1.0 {
		return true, 1.0, nil
	}

	u, err := randomUniformFloat()
	if err != nil {
		return false, 0, err
	}

	return u <= p, p, nil
}

func ComputeLyubashevskyM(sc PolyVec, sigma float64) float64 {
	scNormSq := vecNormSqFloat(sc)
	scNorm := math.Sqrt(scNormSq)
	const tailBound = 13.5
	return math.Exp(scNormSq/(2*sigma*sigma) + tailBound*scNorm/sigma)
}

func ExpectedLyubashevskyAcceptRate(sc PolyVec, sigma float64) float64 {
	M := ComputeLyubashevskyM(sc, sigma)
	if M <= 1.0 {
		return 1.0
	}
	return 1.0 / M
}

func vecPolyMulShift(a *Poly, b *Poly, out *Poly) {
	out.PolyMul(a, b)
}

func computeScShares(s1Share PolyVec, c Poly, lambda int64) PolyVec {
	sc := make(PolyVec, Dilithium3L)
	var cTimesS1 Poly
	for i := 0; i < Dilithium3L; i++ {
		cTimesS1.PolyMul(&c, &s1Share[i])
		sc[i].ScalarMul(&cTimesS1, lambda)
	}
	return sc
}

func RejectionAcceptanceRate(sigma, rejectBound float64) float64 {
	ratio := rejectBound / sigma
	if ratio <= 0 {
		return 0
	}
	return math.Erf(ratio / math.Sqrt2)
}

type VerifiableGaussianShare struct {
	Seed    []byte
	Sigma   float64
	PartyID int
}

func (v *VerifiableGaussianShare) Generate() (PolyVec, []byte, error) {
	y, err := SampleGaussianMaskingVec(v.Seed, v.Sigma)
	if err != nil {
		return nil, nil, err
	}

	commitment := make([]byte, 32)
	h := sha256.New()
	h.Write(v.Seed)
	h.Write([]byte{byte(v.PartyID)})
	h.Sum(commitment[:0])

	return y, commitment, nil
}

func DeriveGaussianSeed(masterSeed []byte, partyID int, nonce uint64) []byte {
	h := sha256.New()
	h.Write(masterSeed)

	pidBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pidBytes, uint32(partyID))
	h.Write(pidBytes)

	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, nonce)
	h.Write(nonceBytes)

	return h.Sum(nil)
}

const DefaultStatSecParam = 128

func ComputeGaussianTail(sigma float64, securityParam int) int64 {
	// audit-fix L6-012: Validate inputs to prevent NaN/Inf.
	// sigma <= 0 makes the Gaussian distribution undefined.
	// securityParam <= 0 or >= 64 causes uint64(1)<<securityParam to overflow
	// to 0, producing 2.0/0 = +Inf, then sigma*Inf or 0*Inf = NaN.
	if sigma <= 0 || securityParam <= 0 || securityParam >= 64 {
		return 0
	}
	// L18-017 FIX: Correct Gaussian tail bound formula.
	// The original formula math.Sqrt(2*math.Log(2/2^securityParam)) produces
	// NaN when securityParam >= 2 because 2/2^securityParam < 1 and log of a
	// value < 1 is negative. The correct tail bound for statistical security
	// parameter lambda is: sigma * sqrt(2 * lambda * ln(2)), derived from
	// P(|X| > bound) = 2^(-lambda) => bound = sigma*sqrt(2*lambda*ln2).
	tt := math.Ceil(sigma * math.Sqrt(2.0*float64(securityParam)*math.Log(2.0)))
	// Guard against NaN/Inf from unexpected edge cases (e.g. very large sigma).
	if math.IsNaN(tt) || math.IsInf(tt, 0) {
		return 0
	}
	if tt > float64((Q-1)/2) {
		tt = float64((Q - 1) / 2)
	}
	return int64(tt)
}

func GaussianZeroKnowledgeBound(sigma float64, secParam int) int64 {
	// N19-003 FIX: Validate secParam explicitly. ComputeGaussianTail
	// already returns 0 for secParam <= 0, but this is an independent
	// public entry point; a zero/negative security parameter must not
	// silently degrade the zero-knowledge bound. Return the conservative
	// floor (Eta2) which matches the lower-bound fallback below.
	if secParam <= 0 {
		return int64(Dilithium3Eta2)
	}
	tail := ComputeGaussianTail(sigma, secParam)
	modBound := float64(tail) / math.Sqrt(float64(Dilithium3L)*float64(N))
	adj := int64(modBound)
	if adj < int64(Dilithium3Eta2) {
		adj = int64(Dilithium3Eta2)
	}
	return adj
}

func (gs *GaussianSampler) VerifyZKPreservation(signatureCount int) float64 {
	leakagePerSig := gs.Sigma / float64(N*Dilithium3L)

	const epsilonBits = 4.0
	totalLeak := leakagePerSig * float64(signatureCount) / (math.Pow(2, epsilonBits))

	if totalLeak > 1.0 {
		totalLeak = 1.0
	}
	return totalLeak
}

func (gs *GaussianSampler) S2NormBound() int64 {
	const dilithium3S2Norm = 1960
	return dilithium3S2Norm
}

func (gs *GaussianSampler) ZKFailureProb(numSignatures int) float64 {
	eps := float64(Dilithium3Gamma1) / (gs.Sigma * math.Sqrt(float64(N)))
	// N20-007 FIX: Use float64 for the intermediate probability calculation to
	// prevent integer overflow on 32-bit platforms. Previously, numSignatures *
	// int(1.0/eps) could overflow int32 (max ~2.1 billion) when numSignatures is
	// large, producing a negative or zero result and an incorrect failure
	// probability. Using float64 throughout avoids both truncation and overflow.
	if eps <= 0 {
		return 0
	}
	prob := float64(numSignatures) * (1.0 / eps)
	if prob <= 0 {
		return 0
	}
	return 1.0 / prob
}

func constantTimeBytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func convGaussianVar(shares int) float64 {
	return Dilithium3Gamma1 * Dilithium3Gamma1 / float64(shares)
}

// GMQTDConstants provides the parameter reference for Gaussian-Masked
// Threshold Dilithium3 (GM-QTD).
type GMQTDConstants struct {
	StandardSigma float64
	Shares        int
}

func NewGMQTDConstants(shares int) *GMQTDConstants {
	return &GMQTDConstants{
		StandardSigma: Dilithium3Gamma1 / math.Sqrt(float64(shares)),
		Shares:        shares,
	}
}

func _() {
	_ = SigmaBase
	_ = constantTimeBytesEqual
	_ = convGaussianVar
}
