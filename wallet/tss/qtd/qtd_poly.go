// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"fmt"
	"runtime"

	logging "github.com/quantaureum/qau/log"
)

// zeroPolyImpl is the actual zeroing implementation for Poly.
// FIX: Use indirect function call via zeroPolyFunc to prevent the
// compiler from eliminating the zeroing loop as a dead store.
func zeroPolyImpl(p *Poly) {
	for i := 0; i < N; i++ {
		p[i] = 0
	}
}

// zeroPolyFunc is a package-level function variable. The compiler cannot
// prove at compile time that it always points to zeroPolyImpl, so it
// cannot eliminate the writes as dead stores.
var zeroPolyFunc = zeroPolyImpl

// Quantaureum Threshold Dilithium (QTD) - R_q Polynomial Arithmetic
//
// Implements polynomial arithmetic over the ring R_q = Z_q[X]/(X^256 + 1)
// where q = 8380417. This is the foundational mathematical structure used
// by the CRYSTALS-Dilithium3 signature scheme.
//
// Constants are taken from the Dilithium3 specification (FIPS 204).

const (
	N       = 256     // Polynomial degree
	LogN    = 8       // log2(N)
	Q       = 8380417 // Prime modulus
	LogQ    = 23      // log2(Q)
	NTTRoot = 1753    // NTT primitive root: zeta^256 = 1 mod q
)

// Poly represents a polynomial in R_q with N coefficients.
// Each coefficient is in [0, Q-1].
type Poly [N]int32

// PolyVec represents a vector of polynomials over R_q.
type PolyVec []Poly

// PolyMat represents a k x l matrix of polynomials over R_q.
type PolyMat struct {
	Rows int
	Cols int
	Data [][]Poly
}

// NewPoly creates a zero-initialized polynomial.
func NewPoly() *Poly {
	return new(Poly)
}

// Add computes p = a + b mod Q.
//
// CR-09 FIX (audit 2026-08-14): Previously assumed pre-normalized inputs
// (coefficients in [0, Q-1]) and relied on a single conditional subtraction.
// Feeding un-normalized coefficients (negative, e.g. centered Gaussian
// samples, or >= Q from deserialized shares) produced out-of-range results
// that silently violated the Poly invariant and propagated downstream. The
// addition now performs full normalization ((sum % Q) + Q) % Q so the output
// is always in [0, Q-1] regardless of input representation. Callers that
// subsequently invoke Reduce() remain correct (Reduce is idempotent on
// already-normalized values).
func (p *Poly) Add(a, b *Poly) {
	for i := 0; i < N; i++ {
		sum := ((int64(a[i])+int64(b[i]))%Q + Q) % Q
		p[i] = int32(sum)
	}
}

// Sub computes p = a - b mod Q.
func (p *Poly) Sub(a, b *Poly) {
	for i := 0; i < N; i++ {
		diff := a[i] - b[i]
		if diff < 0 {
			diff += Q
		}
		p[i] = diff
	}
}

// ScalarMul computes p = a * scalar mod Q.
func (p *Poly) ScalarMul(a *Poly, scalar int64) {
	scalar = ((scalar % Q) + Q) % Q
	for i := 0; i < N; i++ {
		prod := int32((int64(a[i]) * scalar) % Q)
		p[i] = prod
	}
}

// NormInf computes the infinity norm of the polynomial.
// Returns max(|coeff|) using centered representation in [-Q/2, Q/2].
//
// N19-007 FIX: Uses constant-time operations to prevent timing side-channels
// that could leak coefficient values during Dilithium3 rejection sampling.
// All branching based on coefficient values has been replaced with
// constant-time bit manipulation (CT-min for absolute value, CT-max for
// running maximum). No branch depends on the value of any coefficient.
func (p *Poly) NormInf() int64 {
	var max int64
	for i := 0; i < N; i++ {
		v := int64(p[i])
		// Constant-time centered absolute value: |centered(v)| = min(v, Q-v).
		// When v <= Q/2, centered = v and abs = v.
		// When v > Q/2, centered = v-Q and abs = Q-v.
		// Both v and Q-v are non-negative; min(v, Q-v) gives the correct abs.
		qv := Q - v
		// CT-min(v, qv): both values are non-negative and < Q < 2^24.
		// diff = v - qv = 2*v - Q, range [-Q, Q-2], no int64 overflow.
		diff := v - qv
		signBit := int64(uint64(diff) >> 63) // 1 if v < qv, 0 if v >= qv
		mask := -signBit                     // all 1s if v < qv, all 0s otherwise
		// min = qv ^ ((v ^ qv) & mask) = v if v < qv, qv if v >= qv
		absVal := qv ^ ((v ^ qv) & mask)
		// CT-max(max, absVal): both non-negative, diff2 in [-Q/2, Q/2].
		diff2 := max - absVal
		signBit2 := int64(uint64(diff2) >> 63) // 1 if max < absVal, 0 otherwise
		mask2 := -signBit2                     // all 1s if max < absVal, all 0s otherwise
		// max(a,b) = a ^ ((a ^ b) & mask_lt) where mask_lt = all 1s if a < b
		max = max ^ ((max ^ absVal) & mask2)
	}
	return max
}

// Norm computes the L2 norm squared of the polynomial.
//
// N20-002 FIX: Uses constant-time operations to prevent timing side-channels
// that could leak the secret key norm during Lyubashevsky rejection sampling.
// The conditional branch (if v > Q/2) has been replaced with constant-time
// bit manipulation consistent with NormInf()'s CT implementation.
func (p *Poly) NormSq() int64 {
	var sum int64
	for i := 0; i < N; i++ {
		v := int64(p[i])
		// Constant-time centered representation: centered = v when v <= Q/2,
		// centered = v - Q when v > Q/2. Uses the same CT comparison as NormInf.
		qv := Q - v
		diff := v - qv                       // = 2*v - Q, range [-Q, Q-2], no int64 overflow
		signBit := int64(uint64(diff) >> 63) // 1 if v <= Q/2, 0 if v > Q/2
		mask := -signBit                     // all 1s if v <= Q/2, all 0s if v > Q/2
		// Subtract Q only when v > Q/2 (signBit = 0, mask = 0).
		// Q &^ mask = 0 when mask = all 1s, Q when mask = all 0s.
		subtract := Q &^ mask
		centered := v - subtract
		sum += centered * centered
	}
	return sum
}

// Equals returns true if p == other coefficient-wise.
// L6-040 FIX: Uses constant-time comparison (accumulate XOR of all
// coefficients) instead of early-return. Prevents timing side-channel
// that could leak which coefficients differ.
func (p *Poly) Equals(other *Poly) bool {
	var acc int32
	for i := 0; i < N; i++ {
		acc |= p[i] ^ other[i]
	}
	// acc is zero only if every coefficient pair was identical.
	return acc == 0
}

// Copy copies src into p.
func (p *Poly) Copy(src *Poly) {
	for i := 0; i < N; i++ {
		p[i] = src[i]
	}
}

// Zero sets all coefficients to zero.
// FIX: Use indirect function call (zeroPolyFunc) to prevent the
// compiler from eliminating this zeroing via dead-store optimization.
func (p *Poly) Zero() {
	zeroPolyFunc(p)
	runtime.KeepAlive(p)
}

// ToBytes serializes the polynomial to bytes.
// Each coefficient is encoded as 3 bytes (little-endian, 23 bits).
func (p *Poly) ToBytes() []byte {
	out := make([]byte, N*3)
	for i := 0; i < N; i++ {
		coeff := p[i]
		if coeff < 0 || coeff >= Q {
			// FIX: Log a warning when out-of-range coefficients are
			// detected during normalization. Silent normalization can mask
			// upstream bugs in polynomial arithmetic that produce coefficients
			// outside [0, Q-1]. The warning is throttled by the caller (this
			// function is called per-coefficient, so logging is informational).
			logging.Warn("qtd_poly.ToBytes: coefficient out of range, normalizing", map[string]any{"coefficient": coeff, "index": i, "q": Q})
			coeff = int32((int64(coeff)%Q + Q) % Q)
		}
		t := uint32(coeff)
		out[3*i] = byte(t)
		out[3*i+1] = byte(t >> 8)
		out[3*i+2] = byte(t >> 16)
	}
	return out
}

// FromBytes deserializes a polynomial from bytes.
func (p *Poly) FromBytes(b []byte) error {
	if len(b) != N*3 {
		return ErrInvalidPolyBytes
	}
	for i := 0; i < N; i++ {
		t := uint32(b[3*i]) | uint32(b[3*i+1])<<8 | uint32(b[3*i+2])<<16
		if t >= Q {
			return ErrInvalidPolyBytes
		}
		p[i] = int32(t)
	}
	return nil
}

// Reduce reduces all coefficients to [0, Q-1].
func (p *Poly) Reduce() {
	for i := 0; i < N; i++ {
		p[i] = int32((int64(p[i])%Q + Q) % Q)
	}
}

// Neg computes p = -a mod Q.
func (p *Poly) Neg(a *Poly) {
	for i := 0; i < N; i++ {
		p[i] = int32((Q - int64(a[i])) % Q)
	}
}

// AddScalar computes p = a + scalar mod Q (scalar added to constant term).
func (p *Poly) AddScalar(a *Poly, scalar int32) {
	p.Copy(a)
	scalar = int32(((int64(scalar) % Q) + Q) % Q)
	p[0] += scalar
	if p[0] >= Q {
		p[0] -= Q
	}
}

// SampleUniform samples a polynomial with coefficients uniform in [0, Q-1].
// Uses rejection sampling from the provided seed.
func (p *Poly) SampleUniform(seed []byte) error {
	return sampleUniformPoly(p, seed, 0)
}

// SampleInBall samples a polynomial with exactly Tau non-zero coefficients
// each in {-1, 1}, and the rest zero. This is used for challenge generation.
func (p *Poly) SampleInBall(seed []byte, tau int) error {
	return sampleInBall(p, seed, tau)
}

// SampleError samples a polynomial with coefficients in [-Eta, Eta].
// Used for sampling secret vectors s1, s2.
func (p *Poly) SampleError(seed []byte, eta int) error {
	return sampleError(p, seed, eta)
}

// VecNormInf computes the infinity norm of a polynomial vector.
//
// N19-007 FIX: Uses constant-time max comparison to prevent timing
// side-channels, consistent with Poly.NormInf's constant-time implementation.
func VecNormInf(vec PolyVec) int64 {
	var max int64
	for i := range vec {
		n := vec[i].NormInf()
		// CT-max(max, n): both non-negative, diff in [-Q/2, Q/2].
		diff := max - n
		signBit := int64(uint64(diff) >> 63) // 1 if max < n, 0 otherwise
		mask := -signBit                     // all 1s if max < n, all 0s otherwise
		max = max ^ ((max ^ n) & mask)
	}
	return max
}

// VecNormSq computes the sum of L2 norm squared across all polynomials.
func VecNormSq(vec PolyVec) int64 {
	var sum int64
	for i := range vec {
		sum += vec[i].NormSq()
	}
	return sum
}

// VecAdd computes v = a + b coefficient-wise.
func VecAdd(a, b PolyVec) PolyVec {
	n := len(a)
	v := make(PolyVec, n)
	for i := 0; i < n; i++ {
		v[i].Add(&a[i], &b[i])
	}
	return v
}

// isPolyVecZero returns true if all coefficients in all polynomials of the
// vector are zero. Used to verify that refresh deltas sum to zero.
func isPolyVecZero(vec PolyVec) bool {
	for i := range vec {
		for j := range vec[i] {
			if vec[i][j] != 0 {
				return false
			}
		}
	}
	return true
}

// VecScalarMul computes v = vec * scalar.
func VecScalarMul(vec PolyVec, scalar int64) PolyVec {
	n := len(vec)
	v := make(PolyVec, n)
	for i := 0; i < n; i++ {
		v[i].ScalarMul(&vec[i], scalar)
	}
	return v
}

// VecToBytes serializes a polynomial vector to bytes.
func VecToBytes(vec PolyVec) []byte {
	var out []byte
	for i := range vec {
		out = append(out, vec[i].ToBytes()...)
	}
	return out
}

// VecFromBytes deserializes a polynomial vector from bytes.
func VecFromBytes(b []byte, numPolys int) (PolyVec, error) {
	if len(b) != numPolys*N*3 {
		return nil, ErrInvalidPolyBytes
	}
	vec := make(PolyVec, numPolys)
	for i := 0; i < numPolys; i++ {
		if err := vec[i].FromBytes(b[i*N*3 : (i+1)*N*3]); err != nil {
			return nil, err
		}
	}
	return vec, nil
}

// MatVecMul computes result = mat * vec over R_q.
func MatVecMul(mat [][]Poly, vec PolyVec) PolyVec {
	rows := len(mat)
	result := make(PolyVec, rows)
	for i := 0; i < rows; i++ {
		for j := 0; j < len(vec); j++ {
			var prod Poly
			nttMul(&prod, &mat[i][j], &vec[j])
			result[i].Add(&result[i], &prod)
		}
	}
	return result
}

// UnpackT1 unpacks t1 from circl's Dilithium3 public key format.
// t1 is stored as K polynomials with 10 bits per coefficient (d=13, t1 < 2^10).
// Each polynomial occupies 320 bytes (256 coeffs * 10 bits / 8).
// Output is in the full 3-byte-per-coefficient format compatible with VecFromBytes.
func UnpackT1(packed []byte, numPolys int) (PolyVec, error) {
	polyBytes := 320
	if len(packed) != numPolys*polyBytes {
		return nil, ErrInvalidPolyBytes
	}

	vec := make(PolyVec, numPolys)
	for p := 0; p < numPolys; p++ {
		offset := p * polyBytes
		for i := 0; i < N; i++ {
			bitOff := i * 10
			byteOff := bitOff / 8
			bitShift := bitOff % 8

			var val uint32
			if byteOff+1 < polyBytes {
				val = uint32(packed[offset+byteOff]) | uint32(packed[offset+byteOff+1])<<8
				if byteOff+2 < polyBytes {
					val |= uint32(packed[offset+byteOff+2]) << 16
				}
			}
			val = (val >> bitShift) & 0x3FF
			vec[p][i] = int32(val)
		}
	}
	return vec, nil
}

// UnpackEtaVec unpacks a vector of polynomials from circl's eta-packed format.
// In circl's Dilithium3 private key, s1 and s2 are stored with 4 bits per
// coefficient (eta=4, values in [-4,4] stored as [0,8]).
// Each polynomial occupies 128 bytes (256 coeffs * 4 bits / 8).
func UnpackEtaVec(packed []byte, numPolys int, eta int) (PolyVec, error) {
	polyBytes := 128
	if len(packed) != numPolys*polyBytes {
		return nil, ErrInvalidPolyBytes
	}

	vec := make(PolyVec, numPolys)
	for p := 0; p < numPolys; p++ {
		offset := p * polyBytes
		for i := 0; i < polyBytes; i++ {
			b := packed[offset+i]
			c0 := int32(Q) + int32(eta) - int32(b&0x0F)
			c1 := int32(Q) + int32(eta) - int32(b>>4)
			if c0 >= Q {
				c0 -= Q
			}
			if c1 >= Q {
				c1 -= Q
			}
			vec[p][2*i] = c0
			vec[p][2*i+1] = c1
		}
	}
	return vec, nil
}

// PackW1 packs a w1 polynomial vector using 4-bit per coefficient.
// Matches circl's PackLe16 for Dilithium3 (Gamma1Bits=19).
// Each coefficient (0-15) is packed as 4 bits, 2 coefficients per byte.
// Total size: K * 128 bytes = 768 bytes for Dilithium3.
func PackW1(vec PolyVec) []byte {
	out := make([]byte, len(vec)*N/2)
	for i := range vec {
		offset := i * N / 2
		j := 0
		for k := 0; k < N/2; k++ {
			out[offset+k] = byte(vec[i][j]&0x0F) | byte((vec[i][j+1]&0x0F)<<4)
			j += 2
		}
	}
	return out
}

func UnpackW1(packed []byte, numPolys int) (PolyVec, error) {
	expectedSize := numPolys * N / 2
	if len(packed) < expectedSize {
		return nil, fmt.Errorf("UnpackW1: buffer too small: %d < %d", len(packed), expectedSize)
	}
	vec := make(PolyVec, numPolys)
	for i := 0; i < numPolys; i++ {
		offset := i * N / 2
		j := 0
		for k := 0; k < N/2; k++ {
			vec[i][j] = int32(packed[offset+k] & 0x0F)
			vec[i][j+1] = int32((packed[offset+k] >> 4) & 0x0F)
			j += 2
		}
	}
	return vec, nil
}
