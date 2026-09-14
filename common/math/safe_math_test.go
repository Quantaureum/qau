// Quantaureum Node source, version 1.0.0.
package math

import (
	"math/big"
	"testing"
)

func TestMaxBig256(t *testing.T) {
	m := MaxBig256()
	if m == nil {
		t.Fatal("expected non-nil")
	}
	if m.BitLen() != 256 {
		t.Errorf("expected 256 bits, got %d", m.BitLen())
	}
}

func TestZero(t *testing.T) {
	z := Zero()
	if z.Sign() != 0 {
		t.Error("expected zero")
	}
}

func TestOne(t *testing.T) {
	o := One()
	if o.Int64() != 1 {
		t.Errorf("expected 1, got %d", o.Int64())
	}
}

func TestSafeAdd(t *testing.T) {
	tests := []struct {
		name string
		a, b *big.Int
		safe bool
	}{
		{"normal", big.NewInt(10), big.NewInt(20), true},
		// CRYPTO-FIX: nil inputs now return (nil, false) instead of
		// being silently coerced to 0 and flagged as safe.
		{"nil_a", nil, big.NewInt(5), false},
		{"nil_b", big.NewInt(5), nil, false},
		{"both_nil", nil, nil, false},
		{"overflow", MaxBig256(), big.NewInt(1), false},
		{"max_ok", new(big.Int).Sub(MaxBig256(), big.NewInt(1)), big.NewInt(1), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, safe := SafeAdd(tt.a, tt.b)
			if safe != tt.safe {
				t.Errorf("expected safe=%v, got %v", tt.safe, safe)
			}
		})
	}
}

func TestSafeSub(t *testing.T) {
	tests := []struct {
		name string
		a, b *big.Int
		safe bool
	}{
		{"normal", big.NewInt(20), big.NewInt(10), true},
		{"equal", big.NewInt(10), big.NewInt(10), true},
		{"underflow", big.NewInt(5), big.NewInt(10), false},
		// CRYPTO-FIX: nil inputs now return (nil, false).
		{"nil_a", nil, big.NewInt(5), false},
		{"nil_b", big.NewInt(5), nil, false},
		{"both_nil", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, safe := SafeSub(tt.a, tt.b)
			if safe != tt.safe {
				t.Errorf("expected safe=%v, got %v", tt.safe, safe)
			}
		})
	}
}

func TestSafeMul(t *testing.T) {
	tests := []struct {
		name string
		a, b *big.Int
		safe bool
	}{
		{"normal", big.NewInt(10), big.NewInt(20), true},
		{"overflow", MaxBig256(), big.NewInt(2), false},
		// CRYPTO-FIX: nil inputs now return (nil, false).
		{"nil_a", nil, big.NewInt(5), false},
		{"nil_b", big.NewInt(5), nil, false},
		{"zero_a", big.NewInt(0), MaxBig256(), true},
		{"zero_b", MaxBig256(), big.NewInt(0), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, safe := SafeMul(tt.a, tt.b)
			if safe != tt.safe {
				t.Errorf("expected safe=%v, got %v", tt.safe, safe)
			}
		})
	}
}

func TestSafeDiv(t *testing.T) {
	tests := []struct {
		name string
		a, b *big.Int
		safe bool
	}{
		{"normal", big.NewInt(100), big.NewInt(5), true},
		{"div_by_zero", big.NewInt(100), big.NewInt(0), false},
		{"nil_b", big.NewInt(100), nil, false},
		// CRYPTO-FIX: nil `a` now returns (nil, false).
		{"nil_a", nil, big.NewInt(5), false},
		{"result_truncated", big.NewInt(7), big.NewInt(2), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, safe := SafeDiv(tt.a, tt.b)
			if safe != tt.safe {
				t.Errorf("expected safe=%v, got %v", tt.safe, safe)
			}
			if tt.safe && tt.a != nil && tt.b != nil && tt.b.Sign() != 0 {
				expected := new(big.Int).Div(tt.a, tt.b)
				if result.Cmp(expected) != 0 {
					t.Errorf("result mismatch: %v != %v", result, expected)
				}
			}
		})
	}
}

func TestSafeMod(t *testing.T) {
	tests := []struct {
		name string
		a, b *big.Int
		safe bool
	}{
		{"normal", big.NewInt(10), big.NewInt(3), true},
		{"zero_result", big.NewInt(6), big.NewInt(3), true},
		{"div_by_zero", big.NewInt(10), big.NewInt(0), false},
		{"nil_b", big.NewInt(10), nil, false},
		// CRYPTO-FIX: nil `a` now returns (nil, false).
		{"nil_a", nil, big.NewInt(3), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, safe := SafeMod(tt.a, tt.b)
			if safe != tt.safe {
				t.Errorf("expected safe=%v, got %v", tt.safe, safe)
			}
			if tt.safe && tt.b != nil && tt.b.Sign() != 0 {
				var a *big.Int
				if tt.a != nil {
					a = new(big.Int).Set(tt.a)
				} else {
					a = new(big.Int)
				}
				expected := new(big.Int).Mod(a, tt.b)
				if result.Cmp(expected) != 0 {
					t.Errorf("result mismatch: %v != %v", result, expected)
				}
			}
		})
	}
}

func TestSafeExp(t *testing.T) {
	tests := []struct {
		name string
		base *big.Int
		exp  *big.Int
		safe bool
	}{
		{"normal", big.NewInt(2), big.NewInt(10), true},
		{"zero_exp", big.NewInt(5), big.NewInt(0), true},
		// CRYPTO- (2026-07-21): nil inputs now return (nil, false)
		// to be consistent with SafeAdd/SafeSub/etc. Previously nil base
		// was coerced to 0 and nil exp was treated as 0 (returning 1),
		// masking upstream nil-pointer bugs.
		{"nil_base", nil, big.NewInt(3), false},
		{"nil_exp", big.NewInt(5), nil, false},
		// CRYPTO-R10-N04 (2026-07-19) FIX: negative exponent now returns
		// (nil, false) instead of (0, true). Integer exponentiation is
		// undefined for negative exponents; the previous (0, true) masked
		// likely caller bugs by silently returning 0.
		{"negative_exp", big.NewInt(2), big.NewInt(-1), false},
		{"overflow", big.NewInt(2), big.NewInt(257), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, safe := SafeExp(tt.base, tt.exp)
			if safe != tt.safe {
				t.Errorf("expected safe=%v, got %v", tt.safe, safe)
			}
		})
	}
}

func TestU256(t *testing.T) {
	tests := []struct {
		name string
		x    *big.Int
		nil  bool
	}{
		// CRYPTO- (2026-07-21): nil input now returns nil instead of 0.
		{"nil", nil, true},
		{"small", big.NewInt(100), false},
		{"max256", MaxBig256(), false},
		{"overflow", new(big.Int).Add(MaxBig256(), big.NewInt(1)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := U256(tt.x)
			if tt.nil {
				if result != nil {
					t.Errorf("U256(nil) = %v, want nil", result)
				}
				return
			}
			if result.BitLen() > 256 {
				t.Errorf("result exceeds 256 bits: %d", result.BitLen())
			}
		})
	}
}

func TestBigMin(t *testing.T) {
	tests := []struct {
		name     string
		a, b     *big.Int
		expected *big.Int
	}{
		{"a_smaller", big.NewInt(5), big.NewInt(10), big.NewInt(5)},
		{"b_smaller", big.NewInt(10), big.NewInt(5), big.NewInt(5)},
		{"equal", big.NewInt(5), big.NewInt(5), big.NewInt(5)},
		// CRYPTO- (2026-07-21): nil inputs now return nil to be
		// consistent with SafeAdd/SafeSub/etc.
		{"nil_a", nil, big.NewInt(10), nil},
		{"nil_b", big.NewInt(10), nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BigMin(tt.a, tt.b)
			if tt.expected == nil {
				if got != nil {
					t.Errorf("BigMin(%v,%v) = %v, want nil", tt.a, tt.b, got)
				}
				return
			}
			if got == nil || got.Cmp(tt.expected) != 0 {
				t.Errorf("BigMin(%v,%v) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestBigMax(t *testing.T) {
	tests := []struct {
		name     string
		a, b     *big.Int
		expected *big.Int
	}{
		{"a_bigger", big.NewInt(10), big.NewInt(5), big.NewInt(10)},
		{"b_bigger", big.NewInt(5), big.NewInt(10), big.NewInt(10)},
		{"equal", big.NewInt(5), big.NewInt(5), big.NewInt(5)},
		// CRYPTO- (2026-07-21): nil inputs now return nil.
		{"nil_a", nil, big.NewInt(10), nil},
		{"nil_b", big.NewInt(10), nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BigMax(tt.a, tt.b)
			if tt.expected == nil {
				if got != nil {
					t.Errorf("BigMax(%v,%v) = %v, want nil", tt.a, tt.b, got)
				}
				return
			}
			if got == nil || got.Cmp(tt.expected) != 0 {
				t.Errorf("BigMax(%v,%v) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestSafeInt64(t *testing.T) {
	tests := []struct {
		name string
		v    uint64
		safe bool
	}{
		{"ok", 100, true},
		{"max", uint64(1<<63 - 1), true},
		{"overflow", uint64(1 << 63), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, safe := SafeInt64(tt.v)
			if safe != tt.safe {
				t.Errorf("expected safe=%v, got %v", tt.safe, safe)
			}
		})
	}
}

func TestSafeInt(t *testing.T) {
	_, safe := SafeInt(100)
	if !safe {
		t.Error("expected safe for small value")
	}
}

func TestSafeUint64(t *testing.T) {
	tests := []struct {
		name string
		v    int64
		safe bool
	}{
		{"ok", 100, true},
		{"negative", -1, false},
		{"max", int64(1<<63 - 1), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, safe := SafeUint64(tt.v)
			if safe != tt.safe {
				t.Errorf("expected safe=%v, got %v", tt.safe, safe)
			}
		})
	}
}
