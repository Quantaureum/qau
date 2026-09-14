// Quantaureum Node source, version 1.0.0.
// Package math — tests for CRYPTO-R12-001 (SafeSub/SafeDiv/SafeMod missing
// 256-bit upper bound check, SafeInt platform-dependent int overflow).
//
// Audit finding (R12 Medium): SafeSub/SafeDiv/SafeMod only checked for
// negative results (underflow) or division by zero, missing the 256-bit
// upper bound check. If inputs exceeded 256 bits (e.g., from unchecked
// upstream arithmetic), the result could silently exceed MaxBig256 and
// still be flagged as "safe". SafeInt used `1<<63-1` as upper bound, which
// is int64's max — on 32-bit platforms (int = int32), values >
// math.MaxInt32 would pass the check but silently truncate on `int(v)`.
//
// Fix: SafeSub/SafeDiv/SafeMod now reject results > MaxBig256. SafeInt now
// uses math.MaxInt32 as the conservative upper bound for cross-platform
// correctness.
package math

import (
	"math"
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// SafeSub upper bound tests
// ---------------------------------------------------------------------------

// TestCRYPTO_R12001_SafeSub_RejectsResultAboveMaxBig256 verifies the fix:
// a subtraction producing a result > MaxBig256 is rejected (was previously
// flagged as safe).
func TestCRYPTO_R12001_SafeSub_RejectsResultAboveMaxBig256(t *testing.T) {
	// a = MaxBig256 + 100, b = 50 → result = MaxBig256 + 50 > MaxBig256
	a := new(big.Int).Add(MaxBig256(), big.NewInt(100))
	b := big.NewInt(50)

	_, safe := SafeSub(a, b)
	if safe {
		t.Errorf("SafeSub(MaxBig256+100, 50): expected unsafe (result > MaxBig256), got safe")
	}
}

// TestCRYPTO_R12001_SafeSub_ResultExactlyMaxBig256IsSafe verifies the boundary:
// result == MaxBig256 is safe (boundary check uses strict >).
func TestCRYPTO_R12001_SafeSub_ResultExactlyMaxBig256IsSafe(t *testing.T) {
	// a = MaxBig256 + 1, b = 1 → result = MaxBig256 (boundary)
	a := new(big.Int).Add(MaxBig256(), big.NewInt(1))
	b := big.NewInt(1)

	result, safe := SafeSub(a, b)
	if !safe {
		t.Errorf("SafeSub(MaxBig256+1, 1): expected safe (result == MaxBig256), got unsafe")
	}
	if result.Cmp(MaxBig256()) != 0 {
		t.Errorf("expected result == MaxBig256, got %x", result)
	}
}

// TestCRYPTO_R12001_SafeSub_NormalCaseUnaffected verifies that normal
// subtractions still pass after the fix (regression guard).
func TestCRYPTO_R12001_SafeSub_NormalCaseUnaffected(t *testing.T) {
	tests := []struct {
		name string
		a, b *big.Int
		safe bool
	}{
		{"normal", big.NewInt(100), big.NewInt(40), true},
		{"equal", big.NewInt(100), big.NewInt(100), true},
		{"underflow", big.NewInt(40), big.NewInt(100), false},
		{"max_ok", MaxBig256(), big.NewInt(0), true},
		{"max_minus_one", MaxBig256(), big.NewInt(1), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, safe := SafeSub(tt.a, tt.b)
			if safe != tt.safe {
				t.Errorf("SafeSub(%v, %v): expected safe=%v, got %v", tt.a, tt.b, tt.safe, safe)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SafeDiv upper bound tests
// ---------------------------------------------------------------------------

// TestCRYPTO_R12001_SafeDiv_RejectsResultAboveMaxBig256 verifies that a
// division producing a result > MaxBig256 is rejected.
func TestCRYPTO_R12001_SafeDiv_RejectsResultAboveMaxBig256(t *testing.T) {
	// a = (MaxBig256 + 1) * 2 = 2 * MaxBig256 + 2, b = 2
	// result = MaxBig256 + 1 > MaxBig256 → reject
	a := new(big.Int).Mul(new(big.Int).Add(MaxBig256(), big.NewInt(1)), big.NewInt(2))
	b := big.NewInt(2)

	_, safe := SafeDiv(a, b)
	if safe {
		t.Errorf("SafeDiv((MaxBig256+1)*2, 2): expected unsafe (result > MaxBig256), got safe")
	}
}

// TestCRYPTO_R12001_SafeDiv_RejectsNegativeResult verifies that negative
// inputs (which would produce negative results) are rejected.
func TestCRYPTO_R12001_SafeDiv_RejectsNegativeResult(t *testing.T) {
	_, safe := SafeDiv(big.NewInt(-100), big.NewInt(2))
	if safe {
		t.Errorf("SafeDiv(-100, 2): expected unsafe (negative result), got safe")
	}
}

// TestCRYPTO_R12001_SafeDiv_ResultExactlyMaxBig256IsSafe verifies the boundary.
func TestCRYPTO_R12001_SafeDiv_ResultExactlyMaxBig256IsSafe(t *testing.T) {
	// a = MaxBig256 * 2, b = 2 → result = MaxBig256 (boundary)
	a := new(big.Int).Mul(MaxBig256(), big.NewInt(2))
	b := big.NewInt(2)

	result, safe := SafeDiv(a, b)
	if !safe {
		t.Errorf("SafeDiv(MaxBig256*2, 2): expected safe (result == MaxBig256), got unsafe")
	}
	if result.Cmp(MaxBig256()) != 0 {
		t.Errorf("expected result == MaxBig256, got %x", result)
	}
}

// TestCRYPTO_R12001_SafeDiv_NormalCaseUnaffected verifies normal divisions
// still pass after the fix (regression guard).
func TestCRYPTO_R12001_SafeDiv_NormalCaseUnaffected(t *testing.T) {
	_, safe := SafeDiv(big.NewInt(100), big.NewInt(4))
	if !safe {
		t.Error("SafeDiv(100, 4): expected safe")
	}

	_, safe = SafeDiv(big.NewInt(100), big.NewInt(0))
	if safe {
		t.Error("SafeDiv(100, 0): expected unsafe")
	}
}

// ---------------------------------------------------------------------------
// SafeMod upper bound tests
// ---------------------------------------------------------------------------

// TestCRYPTO_R12001_SafeMod_RejectsResultAboveMaxBig256 verifies that a
// result > MaxBig256 is rejected. This happens when b > MaxBig256 and
// a < b (so Mod = a) with a > MaxBig256.
//
// Note: Go's big.Int.Mod implements Euclidean modulus (result is always
// non-negative), so we don't need to test negative-result cases — they
// cannot occur. The upper bound check is the only meaningful addition.
func TestCRYPTO_R12001_SafeMod_RejectsResultAboveMaxBig256(t *testing.T) {
	// b = MaxBig256 + 100, a = MaxBig256 + 50 (a < b, so Mod = a)
	// result = MaxBig256 + 50 > MaxBig256 → reject.
	b := new(big.Int).Add(MaxBig256(), big.NewInt(100))
	a := new(big.Int).Add(MaxBig256(), big.NewInt(50))

	_, safe := SafeMod(a, b)
	if safe {
		t.Errorf("SafeMod(MaxBig256+50, MaxBig256+100): expected unsafe (result > MaxBig256), got safe")
	}
}

// TestCRYPTO_R12001_SafeMod_ResultExactlyMaxBig256IsSafe verifies the boundary:
// result == MaxBig256 is safe (boundary check uses strict >).
func TestCRYPTO_R12001_SafeMod_ResultExactlyMaxBig256IsSafe(t *testing.T) {
	// b = MaxBig256 + 1, a = MaxBig256 (a < b, so Mod = a = MaxBig256)
	b := new(big.Int).Add(MaxBig256(), big.NewInt(1))
	a := MaxBig256()

	result, safe := SafeMod(a, b)
	if !safe {
		t.Errorf("SafeMod(MaxBig256, MaxBig256+1): expected safe (result == MaxBig256), got unsafe")
	}
	if result.Cmp(MaxBig256()) != 0 {
		t.Errorf("expected result == MaxBig256, got %x", result)
	}
}

// TestCRYPTO_R12001_SafeMod_NormalCaseUnaffected verifies normal mod operations
// still pass after the fix (regression guard).
func TestCRYPTO_R12001_SafeMod_NormalCaseUnaffected(t *testing.T) {
	result, safe := SafeMod(big.NewInt(10), big.NewInt(3))
	if !safe {
		t.Error("SafeMod(10, 3): expected safe")
	}
	if result.Int64() != 1 {
		t.Errorf("SafeMod(10, 3): expected 1, got %d", result.Int64())
	}
}

// ---------------------------------------------------------------------------
// SafeInt platform-dependent int overflow tests
// ---------------------------------------------------------------------------

// TestCRYPTO_R12001_SafeInt_RejectsAboveMaxInt32 verifies the fix: SafeInt
// now uses math.MaxInt32 as the upper bound, so values > MaxInt32 are
// rejected (previously they were accepted on 64-bit platforms via the
// `1<<63-1` check, then silently truncated on 32-bit platforms).
func TestCRYPTO_R12001_SafeInt_RejectsAboveMaxInt32(t *testing.T) {
	// v = MaxInt32 + 1 → must be rejected on ALL platforms.
	v := uint64(math.MaxInt32) + 1
	_, safe := SafeInt(v)
	if safe {
		t.Errorf("SafeInt(MaxInt32+1): expected unsafe (cross-platform correctness), got safe")
	}
}

// TestCRYPTO_R12001_SafeInt_AcceptsMaxInt32 verifies the boundary:
// SafeInt(MaxInt32) is safe on all platforms.
func TestCRYPTO_R12001_SafeInt_AcceptsMaxInt32(t *testing.T) {
	v := uint64(math.MaxInt32)
	result, safe := SafeInt(v)
	if !safe {
		t.Errorf("SafeInt(MaxInt32): expected safe, got unsafe")
	}
	if result != math.MaxInt32 {
		t.Errorf("SafeInt(MaxInt32): expected %d, got %d", math.MaxInt32, result)
	}
}

// TestCRYPTO_R12001_SafeInt_AcceptsSmallValue verifies a small value is
// still accepted (regression guard).
func TestCRYPTO_R12001_SafeInt_AcceptsSmallValue(t *testing.T) {
	result, safe := SafeInt(42)
	if !safe {
		t.Error("SafeInt(42): expected safe")
	}
	if result != 42 {
		t.Errorf("SafeInt(42): expected 42, got %d", result)
	}
}

// TestCRYPTO_R12001_SafeInt_RejectsLargeUint64 verifies that a very large
// uint64 (e.g., near MaxInt64) is now rejected, even on 64-bit platforms.
func TestCRYPTO_R12001_SafeInt_RejectsLargeUint64(t *testing.T) {
	// v = 1 << 50 — within int64 range on 64-bit platforms but exceeds
	// MaxInt32, so SafeInt must reject it for cross-platform safety.
	v := uint64(1) << 50
	_, safe := SafeInt(v)
	if safe {
		t.Errorf("SafeInt(1<<50): expected unsafe (cross-platform correctness), got safe")
	}
}

// TestCRYPTO_R12001_SafeInt_ZeroIsSafe verifies the zero value is safe.
func TestCRYPTO_R12001_SafeInt_ZeroIsSafe(t *testing.T) {
	result, safe := SafeInt(0)
	if !safe {
		t.Error("SafeInt(0): expected safe")
	}
	if result != 0 {
		t.Errorf("SafeInt(0): expected 0, got %d", result)
	}
}

// ---------------------------------------------------------------------------
// Cross-check: MaxBig256 boundary is consistent
// ---------------------------------------------------------------------------

// TestCRYPTO_R12001_MaxBig256_BoundaryIs256Bits verifies the sentinel used
// for all upper-bound checks is exactly 2^256 - 1.
func TestCRYPTO_R12001_MaxBig256_BoundaryIs256Bits(t *testing.T) {
	m := MaxBig256()
	if m.BitLen() != 256 {
		t.Errorf("MaxBig256().BitLen() = %d, want 256", m.BitLen())
	}
	// Verify MaxBig256 = 2^256 - 1.
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	expected := new(big.Int).Sub(two256, big.NewInt(1))
	if m.Cmp(expected) != 0 {
		t.Errorf("MaxBig256() = %x, want %x", m, expected)
	}
}
