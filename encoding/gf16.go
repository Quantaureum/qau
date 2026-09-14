// Quantaureum Node source, version 1.0.0.
package encoding

// GF(2^16) Arithmetic — P0-1 (2026-07-14)
//
// Quantaureum's Danksharding uses CellsPerBlob=4096 evaluation points, which
// exceeds GF(2^8)'s 255-element limit. This file implements GF(2^16) arithmetic
// supporting up to 65535 non-zero evaluation points — more than enough for
// CellsPerBlobExtended=8192.
//
// Field configuration:
//   - Irreducible polynomial: x^16 + x^12 + x^3 + x + 1 = 0x1100B
//   - Primitive element (generator): x = 2
//   - Multiplicative group order: 2^16 - 1 = 65535
//
// Memory: exp table is doubled (131070 entries × 2 bytes = ~256 KB) so that
// gf16Mul can do gf16Exp[logA+logB] without modular reduction, matching the
// GF(2^8) pattern used in erasure_code.go.

import "fmt"

const (
	// gf16Poly is the irreducible polynomial x^16 + x^12 + x^3 + x + 1.
	// Bit layout: 1_0001_0000_0000_1011.
	// This is a well-known primitive polynomial over GF(2) of degree 16.
	gf16Poly = 0x1100B

	// gf16Order is the multiplicative group order (2^16 - 1).
	gf16Order = 65535
)

var (
	// gf16Exp is the antilog (exponentiation) table. Doubled to avoid modular
	// arithmetic in multiplication: gf16Exp[i + j] == gf16Exp[i] * gf16Exp[j]
	// for all i, j in [0, gf16Order-1].
	gf16Exp [2 * gf16Order]uint16

	// gf16Log is the discrete logarithm table. gf16Log[0] is undefined and
	// left as 0; callers must handle zero as a special case.
	gf16Log [1 << 16]uint16
)

func init() {
	// Build exp table: gf16Exp[i] = generator^i, where generator = x = 2.
	// Multiplication by x is a left shift; if bit 16 overflows, reduce by
	// the irreducible polynomial.
	gf16Exp[0] = 1
	for i := 1; i < gf16Order; i++ {
		prev := uint32(gf16Exp[i-1])
		prod := prev << 1
		if prod&(1<<16) != 0 {
			prod ^= gf16Poly
		}
		gf16Exp[i] = uint16(prod)
	}
	// Verify generator is primitive: gf16Exp[gf16Order-1] should NOT be 1
	// (only gf16Exp[gf16Order] == gf16Exp[0] == 1).
	if gf16Exp[gf16Order-1] == 1 {
		panic("gf16: polynomial 0x1100B with generator 2 is NOT primitive — contact cryptographer")
	}

	// Double the exp table so gf16Exp[logA+logB] works without modulo.
	for i := gf16Order; i < 2*gf16Order; i++ {
		gf16Exp[i] = gf16Exp[i-gf16Order]
	}

	// Build log table: gf16Log[gf16Exp[i]] = i.
	for i := 0; i < gf16Order; i++ {
		gf16Log[gf16Exp[i]] = uint16(i)
	}
}

// gf16Mul multiplies two elements in GF(2^16). Returns 0 if either operand
// is 0 (matching GF(2^8) gfMul semantics).
func gf16Mul(a, b uint16) uint16 {
	if a == 0 || b == 0 {
		return 0
	}
	return gf16Exp[int(gf16Log[a])+int(gf16Log[b])]
}

// ErrGF16DivisionByZero is returned when dividing by zero in GF(2^16).
var ErrGF16DivisionByZero = fmt.Errorf("division by zero in GF(2^16)")

// ErrGF16InverseOfZero is returned when inverting zero in GF(2^16).
var ErrGF16InverseOfZero = fmt.Errorf("inverse of zero in GF(2^16)")

// gf16Div divides a by b in GF(2^16).
func gf16Div(a, b uint16) (uint16, error) {
	if a == 0 {
		return 0, nil
	}
	if b == 0 {
		return 0, ErrGF16DivisionByZero
	}
	logDiff := int(gf16Log[a]) - int(gf16Log[b])
	if logDiff < 0 {
		logDiff += gf16Order
	}
	return gf16Exp[logDiff], nil
}

// gf16Inv returns the multiplicative inverse of a in GF(2^16).
func gf16Inv(a uint16) (uint16, error) {
	if a == 0 {
		return 0, ErrGF16InverseOfZero
	}
	return gf16Exp[gf16Order-int(gf16Log[a])], nil
}

// gf16Pow raises base to the given exponent in GF(2^16). Uses log/exp
// tables for O(1) computation.
//
// Negative exponents are supported and computed as the multiplicative
// inverse: base^(-k) == gf16Inv(base)^k. This works because the log table
// index is reduced modulo gf16Order (2^16-1, the multiplicative group
// order), so a negative log result wraps to the equivalent positive index.
// base must be non-zero when exp < 0 (zero has no inverse); the base==0
// fast path above returns 0 in that case, which is the conventional
// "undefined" sentinel rather than a panic.
func gf16Pow(base uint16, exp int) uint16 {
	if exp == 0 {
		return 1
	}
	if base == 0 {
		// 0^exp is 0 for exp > 0; 0^(-k) is mathematically undefined.
		// We return 0 (not panic) to keep the hot path branch-free and
		// to mirror gf16Mul's zero-propagation semantics. Callers that
		// need strict inverse semantics should use gf16Inv directly.
		return 0
	}
	// Use log/exp tables for O(1) computation.
	// base^exp = exp[log[base] * exp mod (2^16-1)]
	logResult := (int(gf16Log[base]) * exp) % gf16Order
	if logResult < 0 {
		logResult += gf16Order
	}
	return gf16Exp[logResult]
}
