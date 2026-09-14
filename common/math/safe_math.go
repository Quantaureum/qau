// Quantaureum Node source, version 1.0.0.
// Package math provides safe mathematical operations for big integers.
package math

import (
	"math"
	"math/big"
)

// maxBig256 is the internal immutable sentinel for the max 256-bit value.
var maxBig256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// MaxBig256 returns the maximum value for a 256-bit unsigned integer.
// Returns a fresh copy to prevent mutation of the shared sentinel.
func MaxBig256() *big.Int { return new(big.Int).Set(maxBig256) }

// Zero returns a new big.Int representing 0.
func Zero() *big.Int { return new(big.Int) }

// One returns a new big.Int representing 1.
func One() *big.Int { return big.NewInt(1) }

// SafeAdd adds two big integers and returns the result along with an overflow flag.
// Returns (result, false) if the result exceeds 256 bits (overflow).
// Returns (result, true) if the operation is safe.
//
// CRYPTO- (2026-07-21) FIX: Previously, nil inputs were silently coerced
// to 0 and the operation was flagged as "safe" (ok=true). This masked upstream
// nil-pointer bugs — a caller that accidentally passed nil (e.g., from a failed
// map lookup or uninitialized field) would get back (0, true), causing the
// caller to proceed with a transfer of 0 instead of the intended amount while
// believing the math was sound. Now nil inputs are treated as invalid and return
// (nil, false), surfacing the bug at the call site.
func SafeAdd(a, b *big.Int) (*big.Int, bool) {
	if a == nil || b == nil {
		return nil, false
	}

	result := new(big.Int).Add(a, b)

	// Check for overflow (result > MaxBig256 or result is negative when inputs are positive)
	if result.Cmp(maxBig256) > 0 {
		return result, false
	}

	// Check for negative result (underflow in unsigned context)
	if result.Sign() < 0 {
		return result, false
	}

	return result, true
}

// SafeSub subtracts b from a and returns the result along with an underflow flag.
// Returns (result, false) if the result is negative (underflow in unsigned context)
// or if the result exceeds 256 bits (overflow in unsigned 256-bit context).
// Returns (result, true) if the operation is safe.
//
// CRYPTO- (2026-07-20) FIX: Previously this function only checked for
// negative results (underflow), missing the upper bound check. If either
// input exceeded 256 bits, the subtraction could silently produce a result
// > MaxBig256 and still be flagged as "safe", causing callers (which assume
// 256-bit unsigned semantics) to mishandle the value. Now we also reject
// results that exceed MaxBig256.
// CRYPTO- (2026-07-21) FIX: Same as SafeAdd — nil inputs are now
// treated as invalid and return (nil, false) instead of being silently
// coerced to 0. See SafeAdd docstring for full rationale.
func SafeSub(a, b *big.Int) (*big.Int, bool) {
	if a == nil || b == nil {
		return nil, false
	}

	result := new(big.Int).Sub(a, b)

	// Check for underflow (negative result)
	if result.Sign() < 0 {
		return result, false
	}

	// CRYPTO-FIX: Check for overflow (result > MaxBig256).
	if result.Cmp(maxBig256) > 0 {
		return result, false
	}

	return result, true
}

// SafeMul multiplies two big integers and returns the result along with an overflow flag.
// Returns (result, false) if the result exceeds 256 bits (overflow).
// Returns (result, true) if the operation is safe.
//
// CRYPTO- (2026-07-21) FIX: nil inputs now return (nil, false) instead
// of (0, true). See SafeAdd docstring for full rationale.
func SafeMul(a, b *big.Int) (*big.Int, bool) {
	if a == nil || b == nil {
		return nil, false
	}

	// If either is zero, result is zero (no overflow possible)
	if a.Sign() == 0 || b.Sign() == 0 {
		return new(big.Int), true
	}

	result := new(big.Int).Mul(a, b)

	// Check for overflow (result > MaxBig256)
	if result.Cmp(maxBig256) > 0 {
		return result, false
	}

	// Check for negative result (when one operand is negative)
	if result.Sign() < 0 {
		return result, false
	}

	return result, true
}

// SafeDiv divides a by b and returns the result along with a division-by-zero flag.
// Returns (nil, false) if b is zero.
// Returns (nil, false) if the result exceeds 256 bits (overflow).
// Returns (result, true) if the operation is safe.
//
// CRYPTO- (2026-07-20) FIX: Previously this function only checked for
// division by zero, missing the 256-bit upper bound check. If `a` was
// > MaxBig256 (e.g., from unchecked arithmetic elsewhere), the division
// could silently propagate an out-of-range value as "safe". Now we reject
// any result > MaxBig256 to enforce 256-bit unsigned semantics consistently.
func SafeDiv(a, b *big.Int) (*big.Int, bool) {
	if b == nil || b.Sign() == 0 {
		return nil, false
	}

	// CRYPTO- (2026-07-21) FIX: nil `a` now returns (nil, false)
	// instead of (0, true). See SafeAdd docstring for full rationale.
	if a == nil {
		return nil, false
	}

	result := new(big.Int).Div(a, b)

	// CRYPTO-FIX: Check for upper bound (result > MaxBig256).
	// This catches inputs that exceed 256 bits (caller bug or unchecked
	// upstream arithmetic) before the value propagates as "safe".
	if result.Sign() < 0 || result.Cmp(maxBig256) > 0 {
		return nil, false
	}

	return result, true
}

// SafeMod returns a mod b along with a division-by-zero flag.
// Returns (nil, false) if b is zero.
// Returns (nil, false) if the result exceeds 256 bits (overflow).
// Returns (result, true) if the operation is safe.
//
// CRYPTO- (2026-07-20) FIX: Previously this function only checked for
// division by zero, missing the 256-bit upper bound check. The mathematical
// result of `a mod b` is always in `[0, |b|)`, so if `b <= MaxBig256` the
// result is guaranteed to fit in 256 bits. However, if `b > MaxBig256` (caller
// bug), the result could exceed 256 bits. We add an explicit upper bound check
// for defense in depth and to surface caller bugs early.
func SafeMod(a, b *big.Int) (*big.Int, bool) {
	if b == nil || b.Sign() == 0 {
		return nil, false
	}

	// CRYPTO- (2026-07-21) FIX: nil `a` now returns (nil, false)
	// instead of (0, true). See SafeAdd docstring for full rationale.
	if a == nil {
		return nil, false
	}

	result := new(big.Int).Mod(a, b)

	// CRYPTO-FIX: Check for upper bound (result > MaxBig256).
	// Although mod semantics bound the result to |b|, an oversized b or a
	// negative result (from negative inputs) should be rejected to enforce
	// 256-bit unsigned semantics consistently with SafeAdd/SafeSub/SafeMul.
	if result.Sign() < 0 || result.Cmp(maxBig256) > 0 {
		return nil, false
	}

	return result, true
}

// SafeExp computes a^b and returns the result along with an overflow flag.
// Returns (result, false) if the result exceeds 256 bits (overflow).
// Returns (result, true) if the operation is safe.
//
// CRYPTO- (2026-07-21) FIX: nil inputs are now treated as invalid and
// return (nil, false), consistent with SafeAdd/SafeSub/SafeMul/SafeDiv/SafeMod
// (fixed in CRYPTO-). Previously nil base was silently coerced to 0 and
// nil exp was silently treated as 0 (returning 1), masking upstream nil-pointer
// bugs. A nil *big.Int is almost certainly a caller error, not a legitimate
// "zero exponent" or "zero base" — callers that intend zero should pass
// new(big.Int) explicitly.
const maxExpBitLen = 256

func SafeExp(base, exp *big.Int) (*big.Int, bool) {
	if base == nil || exp == nil {
		return nil, false
	}
	if exp.Sign() == 0 {
		return big.NewInt(1), true
	}

	// CRYPTO-R10-N04 (2026-07-19) FIX: Previously returned (new(big.Int), true)
	// for negative exponents, signaling "safe, no overflow" while silently
	// returning 0 — masking what is almost certainly a caller bug (integer
	// exponentiation is undefined for negative exponents; the mathematically
	// correct result is a fraction, not 0). Returning (0, true) also created
	// a semantic trap: callers that checked only the `ok` flag would treat
	// the result as a valid 0, propagating an incorrect value through their
	// math. Now we treat negative exponents as invalid input and return
	// (nil, false), surfacing the bug to callers.
	if exp.Sign() < 0 {
		return nil, false
	}

	if exp.BitLen() > maxExpBitLen {
		return nil, false
	}

	// Handle trivial bases that produce constant-size results regardless of exp.
	switch base.Sign() {
	case 0:
		return new(big.Int), true // 0^exp = 0 (for exp > 0)
	}
	absBase := new(big.Int).Abs(base)
	if absBase.Cmp(big.NewInt(1)) == 0 {
		// base is ±1; result is ±1 regardless of exp size
		if base.Sign() < 0 && exp.Bit(0) == 1 {
			return big.NewInt(-1), true
		}
		return big.NewInt(1), true
	}

	// SECURITY (audit DATA-05): Estimate the result bit length BEFORE computing
	// base^exp. The previous code computed the full result first, then checked
	// for overflow. For base=2 and a large exponent (e.g., exp=10^18), this
	// would allocate a result with ~10^18 bits — catastrophic OOM before the
	// overflow check ever runs.
	//
	// The bit length of base^exp is approximately exp * base.BitLen().
	// We reject immediately if this exceeds a generous threshold (65536 bits),
	// which is far beyond the 256-bit limit but small enough that the actual
	// Exp() computation completes in microseconds. This prevents OOM from
	// crafted large exponents while avoiding false positives for any legitimate
	// 256-bit use case.
	const maxExpResultBitLen = 65536
	baseBitLen := base.BitLen() // baseBitLen >= 2 here (|base| >= 2)
	if !exp.IsUint64() {
		// exp > uint64 max; for |base| >= 2, result is astronomically large
		return nil, false
	}
	expU64 := exp.Uint64()
	if expU64 > maxExpResultBitLen/uint64(baseBitLen) {
		return nil, false
	}

	result := new(big.Int).Exp(base, exp, nil)

	// Check for overflow (final verification)
	if result.Cmp(maxBig256) > 0 {
		return result, false
	}

	return result, true
}

// U256 returns the value modulo 2^256, ensuring the result fits in 256 bits.
//
// CRYPTO- (2026-07-21) FIX: nil input now returns nil instead of
// returning 0. Previously U256(nil) returned new(big.Int) (= 0), which silently
// masked upstream nil-pointer bugs — a caller passing an uninitialized value
// would get back 0 and proceed as if the math was valid, potentially causing
// incorrect balance/allowance calculations. Consistent with SafeAdd/SafeSub/
// SafeMul/SafeDiv/SafeMod, nil in → nil out. Callers that want zero-value
// semantics should pass new(big.Int) explicitly.
func U256(x *big.Int) *big.Int {
	if x == nil {
		return nil
	}
	return new(big.Int).And(x, maxBig256)
}

// BigMin returns the smaller of two big integers.
//
// CRYPTO- (2026-07-21) FIX: nil inputs now return nil instead of
// silently returning the other operand. Previously BigMin(nil, x) returned x
// and BigMin(x, nil) returned x, masking upstream nil-pointer bugs. This was
// inconsistent with SafeAdd/SafeSub/etc. which return (nil, false) for nil
// inputs. Callers that need "treat nil as infinity/zero" semantics should
// handle nil explicitly before calling.
func BigMin(a, b *big.Int) *big.Int {
	if a == nil || b == nil {
		return nil
	}
	if a.Cmp(b) < 0 {
		return a
	}
	return b
}

// BigMax returns the larger of two big integers.
//
// CRYPTO- (2026-07-21) FIX: nil inputs now return nil instead of
// silently returning the other operand. See BigMin docstring for rationale.
func BigMax(a, b *big.Int) *big.Int {
	if a == nil || b == nil {
		return nil
	}
	if a.Cmp(b) > 0 {
		return a
	}
	return b
}

func SafeInt64(v uint64) (int64, bool) {
	if v > uint64(1<<63-1) {
		return 0, false
	}
	return int64(v), true
}

// SafeInt converts a uint64 to int safely.
//
// CRYPTO- (2026-07-20) FIX: Previously this function used
// `uint64(1<<63-1)` as the upper bound, which is the max value of int64.
// However, Go's `int` type is platform-dependent: it is 64-bit on 64-bit
// platforms (max = 1<<63-1) but 32-bit on 32-bit platforms (max = 1<<31-1).
// On a 32-bit platform, the old check would pass for any v <= 1<<63-1, then
// the `int(v)` conversion would silently truncate/wrap, producing incorrect
// results for v > math.MaxInt32. Now we use math.MaxInt32 as the conservative
// upper bound so behavior is identical across platforms.
func SafeInt(v uint64) (int, bool) {
	if v > uint64(math.MaxInt32) {
		return 0, false
	}
	return int(v), true
}

func SafeUint64(v int64) (uint64, bool) {
	if v < 0 {
		return 0, false
	}
	return uint64(v), true
}
