// Quantaureum Node source, version 1.0.0.
// Package math — regression tests for CRYPTO-R13-003.
//
// Audit finding (R13 High): SafeAdd/SafeSub/SafeMul/SafeDiv/SafeMod silently
// coerced nil inputs to 0 and returned ok=true, masking upstream nil-pointer
// bugs (e.g., uninitialized transfer amount fields, failed map lookups). A
// caller that accidentally passed nil would get back (0, true) — proceeding
// with a transfer of 0 instead of the intended amount while believing the
// math was sound.
//
// Fix: nil inputs now return (nil, false), surfacing the bug at the call site.
// This test file locks in the new fail-fast behavior across all five Safe*
// arithmetic functions and guards against silent regression.
package math

import (
	"math/big"
	"testing"
)

// TestCRYPTO_R13003_NilInputsReturnNilFalse verifies that every Safe*
// arithmetic function rejects nil inputs with (nil, false) rather than
// silently treating nil as 0 and returning ok=true.
func TestCRYPTO_R13003_NilInputsReturnNilFalse(t *testing.T) {
	t.Run("SafeAdd_nil_a", func(t *testing.T) {
		result, safe := SafeAdd(nil, big.NewInt(5))
		if safe {
			t.Errorf("SafeAdd(nil, 5): expected unsafe, got safe (nil silently coerced to 0)")
		}
		if result != nil {
			t.Errorf("SafeAdd(nil, 5): expected nil result, got %v", result)
		}
	})
	t.Run("SafeAdd_nil_b", func(t *testing.T) {
		result, safe := SafeAdd(big.NewInt(5), nil)
		if safe {
			t.Errorf("SafeAdd(5, nil): expected unsafe, got safe (nil silently coerced to 0)")
		}
		if result != nil {
			t.Errorf("SafeAdd(5, nil): expected nil result, got %v", result)
		}
	})
	t.Run("SafeAdd_both_nil", func(t *testing.T) {
		result, safe := SafeAdd(nil, nil)
		if safe {
			t.Errorf("SafeAdd(nil, nil): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeAdd(nil, nil): expected nil result, got %v", result)
		}
	})

	t.Run("SafeSub_nil_a", func(t *testing.T) {
		result, safe := SafeSub(nil, big.NewInt(5))
		if safe {
			t.Errorf("SafeSub(nil, 5): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeSub(nil, 5): expected nil result, got %v", result)
		}
	})
	t.Run("SafeSub_nil_b", func(t *testing.T) {
		result, safe := SafeSub(big.NewInt(5), nil)
		if safe {
			t.Errorf("SafeSub(5, nil): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeSub(5, nil): expected nil result, got %v", result)
		}
	})
	t.Run("SafeSub_both_nil", func(t *testing.T) {
		result, safe := SafeSub(nil, nil)
		if safe {
			t.Errorf("SafeSub(nil, nil): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeSub(nil, nil): expected nil result, got %v", result)
		}
	})

	t.Run("SafeMul_nil_a", func(t *testing.T) {
		result, safe := SafeMul(nil, big.NewInt(5))
		if safe {
			t.Errorf("SafeMul(nil, 5): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeMul(nil, 5): expected nil result, got %v", result)
		}
	})
	t.Run("SafeMul_nil_b", func(t *testing.T) {
		result, safe := SafeMul(big.NewInt(5), nil)
		if safe {
			t.Errorf("SafeMul(5, nil): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeMul(5, nil): expected nil result, got %v", result)
		}
	})

	t.Run("SafeDiv_nil_a", func(t *testing.T) {
		result, safe := SafeDiv(nil, big.NewInt(5))
		if safe {
			t.Errorf("SafeDiv(nil, 5): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeDiv(nil, 5): expected nil result, got %v", result)
		}
	})
	// Note: SafeDiv(nil_b) already returned (nil, false) before the fix;
	// included here for completeness and to guard against regression.
	t.Run("SafeDiv_nil_b", func(t *testing.T) {
		result, safe := SafeDiv(big.NewInt(100), nil)
		if safe {
			t.Errorf("SafeDiv(100, nil): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeDiv(100, nil): expected nil result, got %v", result)
		}
	})

	t.Run("SafeMod_nil_a", func(t *testing.T) {
		result, safe := SafeMod(nil, big.NewInt(3))
		if safe {
			t.Errorf("SafeMod(nil, 3): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeMod(nil, 3): expected nil result, got %v", result)
		}
	})
	// Note: SafeMod(nil_b) already returned (nil, false) before the fix;
	// included here for completeness.
	t.Run("SafeMod_nil_b", func(t *testing.T) {
		result, safe := SafeMod(big.NewInt(10), nil)
		if safe {
			t.Errorf("SafeMod(10, nil): expected unsafe, got safe")
		}
		if result != nil {
			t.Errorf("SafeMod(10, nil): expected nil result, got %v", result)
		}
	})
}

// TestCRYPTO_R13003_NormalInputsUnaffected verifies that the fix did not
// break normal arithmetic — non-nil inputs still produce correct results
// with safe=true. This is a regression guard.
func TestCRYPTO_R13003_NormalInputsUnaffected(t *testing.T) {
	t.Run("SafeAdd", func(t *testing.T) {
		result, safe := SafeAdd(big.NewInt(10), big.NewInt(20))
		if !safe {
			t.Errorf("SafeAdd(10, 20): expected safe, got unsafe")
		}
		if result.Int64() != 30 {
			t.Errorf("SafeAdd(10, 20): expected 30, got %d", result.Int64())
		}
	})
	t.Run("SafeSub", func(t *testing.T) {
		result, safe := SafeSub(big.NewInt(20), big.NewInt(10))
		if !safe {
			t.Errorf("SafeSub(20, 10): expected safe, got unsafe")
		}
		if result.Int64() != 10 {
			t.Errorf("SafeSub(20, 10): expected 10, got %d", result.Int64())
		}
	})
	t.Run("SafeMul", func(t *testing.T) {
		result, safe := SafeMul(big.NewInt(6), big.NewInt(7))
		if !safe {
			t.Errorf("SafeMul(6, 7): expected safe, got unsafe")
		}
		if result.Int64() != 42 {
			t.Errorf("SafeMul(6, 7): expected 42, got %d", result.Int64())
		}
	})
	t.Run("SafeDiv", func(t *testing.T) {
		result, safe := SafeDiv(big.NewInt(100), big.NewInt(4))
		if !safe {
			t.Errorf("SafeDiv(100, 4): expected safe, got unsafe")
		}
		if result.Int64() != 25 {
			t.Errorf("SafeDiv(100, 4): expected 25, got %d", result.Int64())
		}
	})
	t.Run("SafeMod", func(t *testing.T) {
		result, safe := SafeMod(big.NewInt(10), big.NewInt(3))
		if !safe {
			t.Errorf("SafeMod(10, 3): expected safe, got unsafe")
		}
		if result.Int64() != 1 {
			t.Errorf("SafeMod(10, 3): expected 1, got %d", result.Int64())
		}
	})
}

// TestCRYPTO_R13003_ZeroInputsStillSafe verifies that explicit zero inputs
// (non-nil *big.Int with value 0) are still accepted as safe. The fix
// rejects only nil pointers, not zero values — this guards against an
// over-aggressive fix that might reject legitimate zero-value transfers.
func TestCRYPTO_R13003_ZeroInputsStillSafe(t *testing.T) {
	zero := big.NewInt(0)
	nonZero := big.NewInt(100)

	t.Run("SafeAdd_zero_a", func(t *testing.T) {
		result, safe := SafeAdd(zero, nonZero)
		if !safe {
			t.Errorf("SafeAdd(0, 100): expected safe, got unsafe")
		}
		if result.Int64() != 100 {
			t.Errorf("SafeAdd(0, 100): expected 100, got %d", result.Int64())
		}
	})
	t.Run("SafeAdd_zero_b", func(t *testing.T) {
		result, safe := SafeAdd(nonZero, zero)
		if !safe {
			t.Errorf("SafeAdd(100, 0): expected safe, got unsafe")
		}
		if result.Int64() != 100 {
			t.Errorf("SafeAdd(100, 0): expected 100, got %d", result.Int64())
		}
	})
	t.Run("SafeMul_zero_a", func(t *testing.T) {
		result, safe := SafeMul(zero, nonZero)
		if !safe {
			t.Errorf("SafeMul(0, 100): expected safe, got unsafe")
		}
		if result.Int64() != 0 {
			t.Errorf("SafeMul(0, 100): expected 0, got %d", result.Int64())
		}
	})
	t.Run("SafeMul_zero_b", func(t *testing.T) {
		result, safe := SafeMul(nonZero, zero)
		if !safe {
			t.Errorf("SafeMul(100, 0): expected safe, got unsafe")
		}
		if result.Int64() != 0 {
			t.Errorf("SafeMul(100, 0): expected 0, got %d", result.Int64())
		}
	})
}
