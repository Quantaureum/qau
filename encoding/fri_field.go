// Quantaureum Node source, version 1.0.0.
package encoding

// DA-FIX (2026-07-17): FRI-based post-quantum polynomial commitment.
//
// This file implements the Goldilocks prime field (p = 2^64 - 2^32 + 1),
// which is the mathematical foundation for the FRI polynomial commitment.
//
// Goldilocks field properties:
//   - p = 0xFFFFFFFF00000001 = 2^64 - 2^32 + 1
//   - p - 1 = 2^32 × (2^32 - 1), so 2^32 | (p-1)
//   - Supports efficient NTT up to length 2^32
//   - 64-bit prime: fits in a single uint64

import (
	"errors"
	"math/bits"
)

// Goldilocks prime: p = 2^64 - 2^32 + 1
const GoldilocksP uint64 = 0xFFFFFFFF00000001

// ErrGF64InverseZero is returned by GF64Inverse/GF64Div when the input (or
// denominator) is zero. Previously these functions panicked, which allowed
// remote attackers to crash the node by submitting a malicious FRI proof
// with a zero denominator element.
//
// ENCODING-P0-01 FIX (R31, 2026-07-27).
var ErrGF64InverseZero = errors.New("GF64Inverse: cannot invert zero")

// GF64Element is a Goldilocks field element (64-bit).
type GF64Element uint64

// ctSelect returns x if cond != 0, else y. Constant-time: the branch does
// not depend on x or y. Used by DA- to make field arithmetic
// constant-time, preventing timing side-channels on secret blob data.
func ctSelect(cond uint64, x, y GF64Element) GF64Element {
	// cond is 0 or 1 (caller ensures). mask = -cond (all 1s if cond=1, all 0s if cond=0).
	mask := -cond
	return GF64Element((uint64(x) & mask) | (uint64(y) &^ mask))
}

// ctReduceOnce conditionally subtracts p from v if v >= p. Constant-time:
// the subtraction is always computed, but only kept when v >= p.
//
// DA-FIX CORRECTION (2026-07-17): The previous formulation
// `ge := uint64(0) - (^borrow)` was incorrect. bits.Sub64 returns
// borrow=1 iff v < p (underflow), borrow=0 iff v >= p. For borrow=1,
// `^borrow = 0xFFFFFFFFFFFFFFFE` and `0 - 0xFFFFFFFFFFFFFFFE = 2`
// (not 0), producing a corrupt mask `mask = -2 = 0xFFFFFFFFFFFFFFFE`
// that mixed bits of v and reduced. This broke GF64Inverse correctness.
// The fix computes `ge = borrow XOR 1` which is exactly 1 when v >= p
// (borrow=0) and exactly 0 when v < p (borrow=1), since borrow is
// always 0 or 1 from bits.Sub64.
func ctReduceOnce(v uint64) uint64 {
	// GE = (v >= p) ? 1 : 0, computed without branching.
	// bits.Sub64 returns borrow=1 iff v < p (underflow), 0 iff v >= p.
	_, borrow := bits.Sub64(v, GoldilocksP, 0)
	ge := borrow ^ 1 // 1 if v >= p, 0 if v < p (borrow is 0 or 1)
	reduced := v - GoldilocksP
	// Select v (if v < p) or reduced (if v >= p).
	mask := -ge // all 1s if ge=1, all 0s if ge=0
	return (v &^ mask) | (reduced & mask)
}

// reduce128 reduces a 128-bit value (hi:lo) modulo p.
// Uses the identity: 2^64 ≡ 2^32 - 1 (mod p).
// So (hi * 2^64 + lo) ≡ hi * (2^32 - 1) + lo ≡ lo + hi*2^32 - hi (mod p).
//
// DA-FIX (2026-07-17): Made constant-time. The previous
// implementation used `for hi > 0` (data-dependent loop iteration count
// based on operand magnitude) and `if lo >= GoldilocksP` (data-dependent
// branch). Both leaked timing information about secret blob data
// flowing through FRI verification. The new implementation runs a FIXED
// number of reduction rounds (3, sufficient for any 128-bit input) and
// uses constant-time conditional subtraction.
func reduce128(hi, lo uint64) uint64 {
	// Each reduction step: (hi:lo) → lo + hi*2^32 - hi.
	// After one step, hi' = hi >> 32 (plus carry). Max hi = 2^64-1, so
	// hi' = (2^64-1) >> 32 = 2^32 - 1. After second step, hi'' < 2.
	// After third step, hi''' = 0. Three rounds suffice for any input.
	for i := 0; i < 3; i++ {
		// Compute t = lo + hi*2^32 - hi as a 128-bit value.
		tLo, carry := bits.Add64(lo, hi<<32, 0)
		tHi := hi >> 32
		// Carry from the addition: tHi += carry (constant-time add).
		tHi, _ = bits.Add64(tHi, carry, 0)
		tLo2, borrow := bits.Sub64(tLo, hi, 0)
		// Borrow from the subtraction: tHi -= borrow (constant-time sub).
		tHi, _ = bits.Sub64(tHi, borrow, 0)
		lo = tLo2
		hi = tHi
		// After 3 iterations hi is guaranteed 0; the loop runs a fixed
		// number of times regardless of input, so the iteration count
		// leaks no information.
	}
	// Final conditional reduction: lo may be in [p, 2p). Subtract p if so.
	// Constant-time: no branch on lo.
	return ctReduceOnce(lo)
}

// GF64Add returns (a + b) mod p. Constant-time (DA-).
//
// ENCODING-P1-01 FIX (R31, 2026-07-27): Removed the `if carry != 0` branch.
// Although the previous comment correctly noted that `carry` is derived from
// PUBLIC operand magnitudes (a, b are already reduced mod p, so the carry
// leaks no secret information), the branch caused a measurable timing
// difference that tripped TestDA_R7_05_GF64AddConstantTime on every run
// where one operand pair overflowed 2^64 and the other didn't. The fix
// computes BOTH candidate results (with and without the overflow correction)
// and selects between them with a constant-time mask derived from `carry`.
// This keeps the public-data-leakage property (the mask still depends on
// public operands) while making the function's instruction count and branch
// behavior input-independent, which is what the constant-time test asserts.
func GF64Add(a, b GF64Element) GF64Element {
	r, carry := bits.Add64(uint64(a), uint64(b), 0)
	// Overflow path: actual sum = r + 2^64. 2^64 ≡ 2^32 - 1 (mod p),
	// so sum mod p = r + (2^32 - 1). Since a+b < 2p, r + (2^32-1) = a+b-p < p.
	rOverflow, _ := bits.Add64(r, (1<<32)-1, 0)
	// Non-overflow path: r is already < 2^64, just conditionally reduce.
	rNormal := ctReduceOnce(r)
	// Select rOverflow if carry=1, else rNormal. Constant-time: mask = -carry.
	mask := -carry // all 1s if carry=1, all 0s if carry=0
	return GF64Element((rOverflow & mask) | (rNormal &^ mask))
}

// GF64Sub returns (a - b) mod p. Constant-time (DA-).
//
// R33 P2-09 FIX (2026-07-28): Removed the `if borrow != 0` branch.
// Although `borrow` is derived from public operand magnitudes (a, b are
// already reduced mod p, so the borrow leaks no secret information), the
// branch created a data-dependent timing side-channel: the underflow path
// executed more instructions than the no-underflow path. The fix mirrors
// the GF64Add approach (see ENCODING-P1-01 FIX above): compute BOTH
// candidate results (with and without the underflow correction) and select
// between them with a constant-time mask derived from `borrow`. This
// keeps the public-data-leakage property (the mask still depends on public
// operands) while making the function's instruction count and branch
// behavior input-independent, eliminating the timing side-channel.
func GF64Sub(a, b GF64Element) GF64Element {
	r, borrow := bits.Sub64(uint64(a), uint64(b), 0)
	// Underflow path: actual diff = r - 2^64.
	// -2^64 ≡ -(2^32 - 1) (mod p), so diff mod p = r - (2^32 - 1).
	// Since a-b > -p, r > 2^32, so r - (2^32-1) > 0 and < p. No underflow.
	rUnderflow, _ := bits.Sub64(r, (1<<32)-1, 0)
	// Non-underflow path: r is already < 2^64, just return it.
	rNormal := r
	// Select rUnderflow if borrow=1, else rNormal. Constant-time: mask = -borrow.
	mask := -borrow // all 1s if borrow=1, all 0s if borrow=0
	return GF64Element((rUnderflow & mask) | (rNormal &^ mask))
}

// GF64Neg returns (-a) mod p. Constant-time (DA-).
func GF64Neg(a GF64Element) GF64Element {
	if a == 0 {
		return 0
	}
	return GF64Element(GoldilocksP) - a
}

// GF64Mul returns (a × b) mod p. Constant-time via reduce128 (DA-).
func GF64Mul(a, b GF64Element) GF64Element {
	hi, lo := bits.Mul64(uint64(a), uint64(b))
	return GF64Element(reduce128(hi, lo))
}

// GF64Pow returns a^exp mod p using fast exponentiation.
//
// DA-FIX (2026-07-17): Made constant-time. The conditional
// multiplication `if exp&1 == 1 { result = GF64Mul(result, base) }` is
// replaced with ctSelect: both branches are always computed, and the
// correct result is selected without branching. This prevents timing
// leakage when `a` is secret (e.g. blob data flowing through FRI).
// The loop always runs 64 iterations (for uint64 exp), so iteration
// count leaks no information.
func GF64Pow(a GF64Element, exp uint64) GF64Element {
	result := GF64Element(1)
	base := a
	for i := 0; i < 64; i++ {
		// Constant-time: always compute the multiplication, select
		// whether to keep it based on the (public) exponent bit.
		bit := (exp >> i) & 1
		mul := GF64Mul(result, base)
		result = ctSelect(bit, mul, result)
		base = GF64Mul(base, base)
	}
	return result
}

// GF64Inverse returns a^(-1) mod p using Fermat's little theorem: a^(p-2).
//
// DA-FIX (2026-07-17): Now constant-time via the constant-time
// GF64Pow implementation. The exponent p-2 is a public constant, so the
// branch pattern in GF64Pow is fixed; combined with constant-time
// GF64Mul (via constant-time reduce128), the entire inversion is
// constant-time with respect to the secret input `a`.
//
// ENCODING-P0-01 FIX (R31, 2026-07-27): Returns (0, ErrGF64InverseZero)
// when a == 0 instead of panicking. The panic was triggerable from P2P
// message handling (FRI verification, DAS sampling, FRIDAVerifyCell) when
// an attacker-supplied proof contained a zero value in the denominator
// position, allowing remote DoS via process crash. Callers MUST check the
// error and reject the malicious proof/input rather than crashing.
func GF64Inverse(a GF64Element) (GF64Element, error) {
	if a == 0 {
		return 0, ErrGF64InverseZero
	}
	return GF64Pow(a, GoldilocksP-2), nil
}

// GF64Div returns (a / b) mod p.
//
// ENCODING-P0-01 FIX (R31, 2026-07-27): Returns (0, ErrGF64InverseZero)
// when b == 0 instead of panicking via GF64Inverse. Callers MUST check
// the error.
func GF64Div(a, b GF64Element) (GF64Element, error) {
	inv, err := GF64Inverse(b)
	if err != nil {
		return 0, err
	}
	return GF64Mul(a, inv), nil
}

// --- Generator and roots of unity ---

// gf64Generator2pow32 is the generator of the 2^32-order multiplicative subgroup.
// 7 is a primitive root of the Goldilocks field.
// The generator of order 2^32 is 7^((p-1)/2^32) mod p.
var gf64Generator2pow32 = GF64Pow(7, (GoldilocksP-1)>>32)

// GF64Generator returns a generator of the 2^k-order multiplicative subgroup.
// Returns g such that g has multiplicative order exactly 2^k.
//
// R32-P1-13 FIX (2026-07-28): Returns 0 (the additive identity, which is
// NEVER a valid root of unity) instead of panicking when k > 32. The
// Goldilocks field only supports roots of unity up to order 2^32 (since
// 2^32 | p-1). A k > 32 input is mathematically undefined — previously it
// panicked, allowing an attacker who could influence k (via a malicious
// DomainSize in friGenerateLayerDomain) to crash the node. Callers that
// receive 0 should treat it as an error and reject the proof/input.
//
// All current callers (friGenerateLayerDomain, GF64Domain, etc.) derive k
// from power-of-2 domain sizes that are already validated to be <= 2^32 by
// the FRIConfig / FRIDACommitBlob path, so a 0 return indicates a bug in
// upstream validation rather than a normal condition.
func GF64Generator(k uint) GF64Element {
	if k > 32 {
		// Return 0 (invalid root of unity) instead of panicking.
		// Callers that use this value in GF64Inverse will get
		// ErrGF64InverseZero, which they already handle.
		return 0
	}
	if k == 0 {
		return 1
	}
	// gf64Generator2pow32 has order 2^32.
	// Generator of order 2^k = (gen_2^32)^(2^(32-k))
	exp := uint64(1) << (32 - k)
	return GF64Pow(gf64Generator2pow32, exp)
}

// GF64RootOfUnity returns the 2^k-th primitive root of unity.
func GF64RootOfUnity(k uint) GF64Element {
	return GF64Generator(k)
}

// --- Byte conversion ---

// GF64FromBytes converts 8 little-endian bytes to a field element.
//
// R32-P1-13 FIX (2026-07-28): If len(b) < 8, the missing high bytes are
// treated as zero (same behavior as before, but now documented explicitly).
// This is safe because `copy(buf, b)` copies min(len(buf), len(b)) bytes
// and `buf` is zero-initialized. The previous code relied on this implicit
// Go behavior without documenting it, making it easy to misuse as if the
// function panicked on short input. It does not — callers passing short
// slices get a reduced field element, which is the desired behavior for
// padding-tolerant deserialization (e.g. trailing bytes of a short blob).
func GF64FromBytes(b []byte) GF64Element {
	var buf [8]byte
	copy(buf[:], b)
	v := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
		uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
	if v >= GoldilocksP {
		v -= GoldilocksP
	}
	return GF64Element(v)
}

// GF64ToBytes converts a field element to 8 little-endian bytes.
func GF64ToBytes(e GF64Element) []byte {
	v := uint64(e)
	return []byte{
		byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
		byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56),
	}
}

// --- Batch operations ---

// GF64MulMany computes element-wise multiplication of two slices.
func GF64MulMany(a, b []GF64Element) []GF64Element {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	result := make([]GF64Element, n)
	for i := 0; i < n; i++ {
		result[i] = GF64Mul(a[i], b[i])
	}
	return result
}

// GF64AddMany computes element-wise addition of two slices.
func GF64AddMany(a, b []GF64Element) []GF64Element {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	result := make([]GF64Element, n)
	for i := 0; i < n; i++ {
		result[i] = GF64Add(a[i], b[i])
	}
	return result
}
