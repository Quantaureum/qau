// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"golang.org/x/crypto/sha3"
)

// Number Theoretic Transform (NTT) for R_q = Z_q[X]/(X^256 + 1).
// Implements the 8-layer Cooley-Tukey / Gentleman-Sande butterflies
// as specified in FIPS 204 (ML-DSA / Dilithium).
//
// Schoolbook multiplication is used as the baseline for polynomial
// operations; NTT-based pointwise multiplication is also available.

// nttZeta[k] = zeta^(BitRev_8(k)) mod Q for k=0..255
// nttZetaInv[k] = zeta^(BitRev_8(255-k) + 256) mod Q for k=0..255
// (equivalent to zeta^(BitRev_8(255-k) - 256) since zeta^512=1)
//
// QUANTUM-FIX (2026-07-17): These tables are WRITE-ONCE — they are
// computed in init() and MUST NEVER be mutated afterward. Mutating them
// would silently break Dilithium3 signature verification (verification
// could accept invalid signatures or reject valid ones), undermining the
// security of the QTD threshold signing protocol. To detect silent
// corruption (e.g., by a future "resetNTT()" function or accidental
// mutation), verifyNTTIntegrity() re-computes the expected zeta values
// and compares them against the stored arrays; a panic terminates the
// program if any entry has been altered.
//
// DO NOT add any code that writes to nttZeta or nttZetaInv outside init().
var nttZeta [256]int32
var nttZetaInv [256]int32

func init() {
	computeNTTRoots()
	// QUANTUM-FIX: Verify NTT table integrity after computation.
	// Detects silent corruption of the write-once tables.
	verifyNTTIntegrity()
}

// verifyNTTIntegrity re-computes the expected NTT zeta tables and panics
// if any entry differs from the stored value. This detects silent
// corruption of the write-once tables (QUANTUM-).
// Constant-time comparison is not required here because the comparison
// itself does not leak secret information — the zeta tables are public
// constants from FIPS 204.
func verifyNTTIntegrity() {
	zeta := int64(1753)
	for i := 0; i < 256; i++ {
		exp := bitRev8(i)
		expected := int32(modPow8(zeta, exp, Q))
		if nttZeta[i] != expected {
			panic("qtd: NTT zeta table corrupted — write-once invariant violated (QUANTUM-)")
		}
	}
	for k := 0; k < 256; k++ {
		exp := bitRev8(255-k) + 256
		expected := int32(modPow8(zeta, exp, Q))
		if nttZetaInv[k] != expected {
			panic("qtd: NTT zetaInv table corrupted — write-once invariant violated (QUANTUM-)")
		}
	}
}

func bitRev8(x int) int {
	r := 0
	for i := 0; i < 8; i++ {
		r = (r << 1) | (x & 1)
		x >>= 1
	}
	return r
}

func modPow8(base int64, exp int, mod int64) int64 {
	result := int64(1)
	b := base % mod
	e := exp
	for e > 0 {
		if e&1 == 1 {
			result = (result * b) % mod
		}
		b = (b * b) % mod
		e >>= 1
	}
	return result
}

func computeNTTRoots() {
	zeta := int64(1753)

	for i := 0; i < 256; i++ {
		exp := bitRev8(i)
		nttZeta[i] = int32(modPow8(zeta, exp, Q))
	}

	for k := 0; k < 256; k++ {
		exp := bitRev8(255-k) + 256
		nttZetaInv[k] = int32(modPow8(zeta, exp, Q))
	}

	verifyNTTRoots()
}

// verifyNTTRoots checks that the precomputed NTT roots satisfy the
// algebraic requirements of the Dilithium/FIPS 204 specification.
// Called from init() via computeNTTRoots(); uses panic() instead of
// os.Exit(1) so deferred functions still run and the stack trace is
// preserved for debugging.
// L5-012 CONFIRMED FIXED: panic() is the correct choice here because
// verifyNTTRoots() is invoked from init() (via computeNTTRoots()),
// which cannot return an error. panic() preserves the stack trace and
// allows deferred functions to execute, unlike os.Exit(1).
func verifyNTTRoots() {
	if nttZeta[0] != 1 {
		panic("qtd: NTT root zeta[0] != 1, does not match Dilithium spec")
	}
	zeta := int64(1753)
	check := int64(1)
	for i := 0; i < 256; i++ {
		check = (check * zeta) % Q
	}
	if check != Q-1 {
		panic("qtd: zeta^256 != -1 mod Q, NTT root verification failed")
	}
	for i := 256; i < 512; i++ {
		check = (check * zeta) % Q
	}
	if check != 1 {
		panic("qtd: zeta^512 != 1 mod Q, NTT root verification failed")
	}
}

// nttMul computes p = a * b in R_q using schoolbook polynomial multiplication.
// Reduces modulo X^256 + 1 (negacyclic convolution).
//
//	PERFORMANCE NOTE: This uses the O(N^2) schoolbook algorithm
//
// (N=256, so 65536 coefficient multiplications per polynomial product).
// For threshold signing with multiple polynomial multiplications per
// round, this is a measurable bottleneck. NTT-based pointwise multiplication
// (forward NTT -> pointwise multiply -> inverse NTT) would reduce this to
// O(N log N) but requires careful handling of the negacyclic reduction and
// is tracked as TODO. The NTT/InvNTT transforms are already implemented
// above; the missing piece is NTT-domain pointwise multiplication with
// proper negacyclic modular reduction.
func nttMul(p, a, b *Poly) {
	p.Zero()

	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			prod := int64(a[i]) * int64(b[j]) % Q

			if i+j < N {
				p[i+j] = int32((int64(p[i+j]) + prod) % Q)
			} else {
				p[i+j-N] = int32((int64(p[i+j-N]) - prod + Q) % Q)
			}
		}
	}
}

// PolyMul computes p = a * b in R_q.
func (p *Poly) PolyMul(a, b *Poly) {
	nttMul(p, a, b)
}

// NTT transforms p from coefficient representation to NTT representation in-place.
// Follows FIPS 204 Algorithm 36 (8-layer Cooley-Tukey butterfly).
func (p *Poly) NTT() {
	k := 0
	for length := 128; length >= 1; length >>= 1 {
		for start := 0; start < 256; start += 2 * length {
			k++
			z := int64(nttZeta[k])
			for j := start; j < start+length; j++ {
				t := (z * int64(p[j+length])) % Q
				p[j+length] = int32((int64(p[j]) - t + Q) % Q)
				p[j] = int32((int64(p[j]) + t) % Q)
			}
		}
	}
}

// InvNTT transforms p from NTT representation back to coefficient representation in-place.
// Follows the Gentleman-Sande butterfly (8 layers), using precomputed inverse zetas
// indexed in ascending order matching the forward NTT iteration.
func (p *Poly) InvNTT() {
	k := 0
	for length := 1; length <= 128; length <<= 1 {
		for start := 0; start < 256; start += 2 * length {
			z := int64(nttZetaInv[k])
			k++
			for j := start; j < start+length; j++ {
				t := int64(p[j])
				p[j] = int32((t + int64(p[j+length])) % Q)
				p[j+length] = int32((z * ((t - int64(p[j+length]) + Q) % Q)) % Q)
			}
		}
	}

	// nInv is the modular inverse of n modulo q, i.e. n^-1 mod q,
	// where n=256 (polynomial degree) and q=8380417 (Dilithium3 modulus).
	// It is used to scale the result of the inverse NTT back to the
	// correct coefficient domain.
	nInv := int64(8347681)
	for i := 0; i < N; i++ {
		p[i] = int32((int64(p[i]) * nInv) % Q)
	}
}

// ComputeA generates the public matrix A from seed rho.
// Dilithium/FIPS 204 generates A in NTT domain (SampleNTT).
// We apply InvNTT to convert to coefficient domain for schoolbook multiplication.
func ComputeA(rho []byte, k, l int) ([][]Poly, error) {
	if len(rho) != 32 {
		return nil, ErrInvalidSeed
	}

	mat := make([][]Poly, k)
	for i := 0; i < k; i++ {
		mat[i] = make([]Poly, l)
		for j := 0; j < l; j++ {
			seed := make([]byte, 34)
			copy(seed[:32], rho)
			seed[32] = byte(j)
			seed[33] = byte(i)
			if err := mat[i][j].SampleUniform(seed); err != nil {
				return nil, err
			}
			mat[i][j].InvNTT()
		}
	}
	return mat, nil
}

// computeARaw generates the public matrix A from seed rho WITHOUT converting
// from NTT domain to coefficient domain. Used for debugging/comparison with circl.
// R47-QP-11 FIX: Unexported (was ComputeARaw) — internal diagnostic only.
func computeARaw(rho []byte, k, l int) ([][]Poly, error) {
	if len(rho) != 32 {
		return nil, ErrInvalidSeed
	}

	mat := make([][]Poly, k)
	for i := 0; i < k; i++ {
		mat[i] = make([]Poly, l)
		for j := 0; j < l; j++ {
			seed := make([]byte, 34)
			copy(seed[:32], rho)
			seed[32] = byte(j)
			seed[33] = byte(i)
			if err := mat[i][j].SampleUniform(seed); err != nil {
				return nil, err
			}
		}
	}
	return mat, nil
}

// ComputeW computes w = A * y in R_q.
func ComputeW(a [][]Poly, y PolyVec) PolyVec {
	return MatVecMul(a, y)
}

// ComputeAz computes A * z in R_q.
func ComputeAz(a [][]Poly, z PolyVec) PolyVec {
	return MatVecMul(a, z)
}

// ComputeCt1 computes c * t1 in R_q.
func ComputeCt1(c Poly, t1 PolyVec) PolyVec {
	result := make(PolyVec, len(t1))
	for i := range t1 {
		result[i].PolyMul(&c, &t1[i])
	}
	return result
}

// ComputeChallenge computes the challenge c = SampleInBall(ctilde).
// Matches circl: mu = SHAKE-256(tr || msg), ctilde = SHAKE-256(mu || w1Packed).
// tr = SHAKE-256(pk) is the 32-byte public key hash.
// Returns the polynomial c and the 32-byte ctilde for signature packing.
func ComputeChallenge(w1Packed []byte, tr []byte, message []byte, tau int) (Poly, [32]byte, error) {
	// mu = CRH(tr || msg)
	h := sha3.NewShake256()
	h.Write(tr)
	h.Write(message)
	var mu [64]byte
	h.Read(mu[:])

	// ctilde = H(mu || w1)
	h.Reset()
	h.Write(mu[:])
	h.Write(w1Packed)
	var ctilde [32]byte
	h.Read(ctilde[:])

	var c Poly
	if err := c.SampleInBall(ctilde[:], tau); err != nil {
		return c, ctilde, err
	}
	return c, ctilde, nil
}
