// Quantaureum Node source, version 1.0.0.
package encoding

// DA-FIX (2026-07-17): NTT (Number Theoretic Transform) over Goldilocks field.
//
// NTT is used for:
//   1. Evaluating a polynomial at all points of a multiplicative subgroup (evaluation form)
//   2. Interpolating from evaluations back to coefficients (coefficient form)
//   3. Reed-Solomon extension: evaluate on a larger domain for FRI
//
// The Goldilocks field supports NTT up to size 2^32 (since 2^32 | p-1).

// log2 returns log2(n) for powers of 2. Returns 0 for n=0 or n=1.
func gf64Log2(n int) uint {
	r := uint(0)
	for n > 1 {
		n >>= 1
		r++
	}
	return r
}

// reverseBits reverses the lowest `bits` bits of n.
func reverseBits(n int, bits uint) int {
	result := 0
	for i := uint(0); i < bits; i++ {
		result = (result << 1) | (n & 1)
		n >>= 1
	}
	return result
}

// GF64NTT computes the Number Theoretic Transform of coefficient vector `a`.
// Input: polynomial coefficients [a_0, a_1, ..., a_{n-1}] (n must be power of 2).
// omega: primitive n-th root of unity.
// Output: evaluations [f(1), f(ω), f(ω²), ..., f(ω^{n-1})].
//
// Uses iterative Cooley-Tukey butterfly. Time: O(n log n).
func GF64NTT(a []GF64Element, omega GF64Element) []GF64Element {
	n := len(a)
	if n <= 1 {
		result := make([]GF64Element, n)
		copy(result, a)
		return result
	}

	result := make([]GF64Element, n)
	copy(result, a)

	// Bit-reversal permutation
	bits := gf64Log2(n)
	for i := 0; i < n; i++ {
		j := reverseBits(i, bits)
		if i < j {
			result[i], result[j] = result[j], result[i]
		}
	}

	// Cooley-Tukey butterflies (decimation in time)
	for m := 2; m <= n; m *= 2 {
		// omega_m = omega^(n/m) is a primitive m-th root of unity
		omegaM := GF64Pow(omega, uint64(n/m))
		halfM := m / 2
		for k := 0; k < n; k += m {
			w := GF64Element(1)
			for j := 0; j < halfM; j++ {
				t := GF64Mul(w, result[k+j+halfM])
				u := result[k+j]
				result[k+j] = GF64Add(u, t)
				result[k+j+halfM] = GF64Sub(u, t)
				w = GF64Mul(w, omegaM)
			}
		}
	}

	return result
}

// GF64INTT computes the inverse NTT: interpolates evaluations back to coefficients.
// Input: evaluations [f(1), f(ω), ..., f(ω^{n-1})].
// omega: primitive n-th root of unity (same as used in NTT).
// Output: polynomial coefficients [a_0, a_1, ..., a_{n-1}].
//
// ENCODING-P0-01 FIX (R31, 2026-07-27): Returns nil if omega == 0 or n == 0
// (would cause division by zero in GF64Inverse). Callers must check for nil.
func GF64INTT(a []GF64Element, omega GF64Element) []GF64Element {
	n := len(a)
	if n <= 1 {
		result := make([]GF64Element, n)
		copy(result, a)
		return result
	}

	// Inverse NTT = NTT with omega^{-1}, then divide by n
	// ENCODING-P0-01: omega and n are non-zero in normal use (omega is a
	// root of unity, n is the polynomial length), but defensively check
	// to prevent panic propagation from attacker-controlled inputs.
	omegaInv, err := GF64Inverse(omega)
	if err != nil {
		return nil
	}
	result := GF64NTT(a, omegaInv)
	if result == nil {
		return nil
	}

	nInv, err := GF64Inverse(GF64Element(n))
	if err != nil {
		return nil
	}
	for i := range result {
		result[i] = GF64Mul(result[i], nInv)
	}

	return result
}

// GF64Domain generates the multiplicative subgroup of order n.
// Returns [1, ω, ω², ..., ω^{n-1}] where ω is a primitive n-th root of unity.
func GF64Domain(n int) []GF64Element {
	if n <= 0 {
		return nil
	}
	k := gf64Log2(n)
	omega := GF64Generator(k)

	domain := make([]GF64Element, n)
	domain[0] = 1
	for i := 1; i < n; i++ {
		domain[i] = GF64Mul(domain[i-1], omega)
	}
	return domain
}

// GF64DomainRoot returns the primitive n-th root of unity used for the domain.
func GF64DomainRoot(n int) GF64Element {
	k := gf64Log2(n)
	return GF64Generator(k)
}

// GF64EvaluateOnDomain evaluates polynomial `coeffs` on the domain of size `domainSize`.
// domainSize must be >= len(coeffs) and a power of 2.
// Returns evaluations [f(h_0), f(h_1), ..., f(h_{domainSize-1})].
//
// R32-P1-13 FIX (2026-07-28): Returns nil for invalid inputs (domainSize
// not a power of 2, or domainSize < len(coeffs)) instead of silently
// truncating or producing corrupt NTT output. Previously, a non-power-of-2
// domainSize would cause GF64DomainRoot to return 0 (via the GF64Generator
// fix), which then caused GF64NTT to produce all-zero output — a silent
// correctness bug that could let an attacker commit to a malformed codeword.
func GF64EvaluateOnDomain(coeffs []GF64Element, domainSize int) []GF64Element {
	if domainSize <= 0 || domainSize < len(coeffs) {
		return nil
	}
	// domainSize must be a power of 2 for NTT to be correct.
	if domainSize&(domainSize-1) != 0 {
		return nil
	}

	// Pad coefficients to domainSize
	padded := make([]GF64Element, domainSize)
	copy(padded, coeffs)

	omega := GF64DomainRoot(domainSize)
	if omega == 0 {
		// GF64Generator returned 0 because domainSize > 2^32. Reject.
		return nil
	}
	return GF64NTT(padded, omega)
}

// GF64ReedSolomonExtend performs Reed-Solomon extension.
// Given polynomial coefficients of degree < n, evaluates on a domain of size m > n.
// This is the core of the FRI code word generation.
//
// Parameters:
//   - coeffs: polynomial coefficients [a_0, ..., a_{n-1}], n must be power of 2
//   - m: extension factor (output size), must be power of 2 and > n
//
// Returns: evaluations [f(h'_0), ..., f(h'_{m-1})] on the larger domain.
//
// R32-P1-13 FIX (2026-07-28): Returns nil for invalid inputs (m not a
// power of 2, m < len(coeffs), or m > 2^32). Previously these cases would
// silently truncate the polynomial or produce corrupt NTT output.
func GF64ReedSolomonExtend(coeffs []GF64Element, m int) []GF64Element {
	if m <= 0 || m < len(coeffs) {
		return nil
	}
	// m must be a power of 2 for NTT to be correct.
	if m&(m-1) != 0 {
		return nil
	}

	padded := make([]GF64Element, m)
	copy(padded, coeffs)

	omega := GF64DomainRoot(m)
	if omega == 0 {
		// m > 2^32: GF64Generator returned 0. Reject.
		return nil
	}
	return GF64NTT(padded, omega)
}
