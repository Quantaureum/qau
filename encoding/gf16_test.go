// Quantaureum Node source, version 1.0.0.
package encoding

import "testing"

// TestGF16TableIntegrity verifies the exp/log tables are correctly generated.
// P0-1 (2026-07-14)
func TestGF16TableIntegrity(t *testing.T) {
	// Verify generator is primitive: all 65535 non-zero values should be
	// generated exactly once.
	seen := make(map[uint16]bool, gf16Order)
	for i := 0; i < gf16Order; i++ {
		v := gf16Exp[i]
		if v == 0 {
			t.Fatalf("gf16Exp[%d] = 0 (zero should never appear in exp table)", i)
		}
		if seen[v] {
			t.Fatalf("gf16Exp[%d] = %d is a duplicate — generator is NOT primitive", i, v)
		}
		seen[v] = true
	}
	if len(seen) != gf16Order {
		t.Errorf("exp table generated %d unique values, want %d", len(seen), gf16Order)
	}

	// Verify gf16Exp[0] = 1 and gf16Exp[gf16Order-1] != 1 (only g^0 = 1).
	if gf16Exp[0] != 1 {
		t.Errorf("gf16Exp[0] = %d, want 1", gf16Exp[0])
	}
	if gf16Exp[gf16Order-1] == 1 {
		t.Error("gf16Exp[gf16Order-1] = 1 — generator order is too small")
	}

	// Verify doubled table: gf16Exp[i + gf16Order] == gf16Exp[i].
	for _, i := range []int{0, 1, 100, 1000, 10000, gf16Order - 1} {
		if gf16Exp[i] != gf16Exp[i+gf16Order] {
			t.Errorf("doubled table mismatch at i=%d: %d != %d",
				i, gf16Exp[i], gf16Exp[i+gf16Order])
		}
	}

	// Verify log table: gf16Log[gf16Exp[i]] = i for all i.
	for i := 0; i < gf16Order; i++ {
		if gf16Log[gf16Exp[i]] != uint16(i) {
			t.Errorf("gf16Log[gf16Exp[%d]] = %d, want %d",
				i, gf16Log[gf16Exp[i]], i)
			break
		}
	}
}

// TestGF16Mul verifies GF(2^16) multiplication properties.
// P0-1 (2026-07-14)
func TestGF16Mul(t *testing.T) {
	t.Run("zero property", func(t *testing.T) {
		if gf16Mul(0, 5) != 0 {
			t.Error("gf16Mul(0, 5) should be 0")
		}
		if gf16Mul(5, 0) != 0 {
			t.Error("gf16Mul(5, 0) should be 0")
		}
	})

	t.Run("identity", func(t *testing.T) {
		if gf16Mul(1, 5) != 5 {
			t.Error("gf16Mul(1, 5) should be 5")
		}
		if gf16Mul(5, 1) != 5 {
			t.Error("gf16Mul(5, 1) should be 5")
		}
	})

	t.Run("commutativity", func(t *testing.T) {
		// Sample a spread of values.
		for _, a := range []uint16{1, 2, 3, 7, 100, 255, 1000, 50000, 65534} {
			for _, b := range []uint16{1, 2, 3, 7, 100, 255, 1000, 50000, 65534} {
				if gf16Mul(a, b) != gf16Mul(b, a) {
					t.Errorf("gf16Mul(%d, %d) != gf16Mul(%d, %d)", a, b, b, a)
					return
				}
			}
		}
	})

	t.Run("associativity", func(t *testing.T) {
		values := []uint16{1, 2, 3, 7, 100, 255, 1000, 50000, 65534}
		for _, a := range values {
			for _, b := range values {
				for _, c := range values {
					ab := gf16Mul(a, b)
					bc := gf16Mul(b, c)
					if gf16Mul(ab, c) != gf16Mul(a, bc) {
						t.Errorf("gf16Mul not associative for %d,%d,%d", a, b, c)
						return
					}
				}
			}
		}
	})

	t.Run("distributivity", func(t *testing.T) {
		// a * (b + c) == a*b + a*c (where + is XOR in GF(2^16))
		values := []uint16{1, 2, 3, 7, 100, 255, 1000, 50000, 65534}
		for _, a := range values {
			for _, b := range values {
				for _, c := range values {
					lhs := gf16Mul(a, b^c)
					rhs := gf16Mul(a, b) ^ gf16Mul(a, c)
					if lhs != rhs {
						t.Errorf("distributivity failed: gf16Mul(%d, %d^%d)=%d, but %d^%d=%d",
							a, b, c, lhs, gf16Mul(a, b), gf16Mul(a, c), rhs)
						return
					}
				}
			}
		}
	})
}

// TestGF16Div verifies division.
// P0-1 (2026-07-14)
func TestGF16Div(t *testing.T) {
	t.Run("division by zero", func(t *testing.T) {
		_, err := gf16Div(5, 0)
		if err != ErrGF16DivisionByZero {
			t.Errorf("gf16Div(5, 0) error = %v, want %v", err, ErrGF16DivisionByZero)
		}
	})

	t.Run("zero divided", func(t *testing.T) {
		q, err := gf16Div(0, 5)
		if err != nil {
			t.Errorf("gf16Div(0, 5) returned error: %v", err)
		}
		if q != 0 {
			t.Errorf("gf16Div(0, 5) = %d, want 0", q)
		}
	})

	t.Run("quotient * divisor == dividend", func(t *testing.T) {
		for _, a := range []uint16{1, 2, 3, 7, 100, 255, 1000, 50000, 65534} {
			for _, b := range []uint16{1, 2, 3, 7, 100, 255, 1000, 50000, 65534} {
				q, err := gf16Div(a, b)
				if err != nil {
					t.Errorf("gf16Div(%d, %d) error: %v", a, b, err)
					return
				}
				if gf16Mul(q, b) != a {
					t.Errorf("gf16Div(%d, %d) = %d, but %d * %d != %d", a, b, q, q, b, a)
					return
				}
			}
		}
	})
}

// TestGF16Inv verifies multiplicative inverse.
// P0-1 (2026-07-14)
func TestGF16Inv(t *testing.T) {
	t.Run("inverse of zero", func(t *testing.T) {
		_, err := gf16Inv(0)
		if err != ErrGF16InverseOfZero {
			t.Errorf("gf16Inv(0) error = %v, want %v", err, ErrGF16InverseOfZero)
		}
	})

	t.Run("a * inv(a) == 1", func(t *testing.T) {
		for _, a := range []uint16{1, 2, 3, 7, 100, 255, 1000, 50000, 65534} {
			inv, err := gf16Inv(a)
			if err != nil {
				t.Errorf("gf16Inv(%d) error: %v", a, err)
				return
			}
			if gf16Mul(a, inv) != 1 {
				t.Errorf("gf16Inv(%d) = %d, but %d * %d != 1", a, inv, a, inv)
				return
			}
		}
	})
}

// TestGF16Pow verifies exponentiation.
// P0-1 (2026-07-14)
func TestGF16Pow(t *testing.T) {
	t.Run("zero exponent", func(t *testing.T) {
		if gf16Pow(5, 0) != 1 {
			t.Error("gf16Pow(5, 0) should be 1")
		}
	})

	t.Run("zero base", func(t *testing.T) {
		if gf16Pow(0, 5) != 0 {
			t.Error("gf16Pow(0, 5) should be 0")
		}
	})

	t.Run("power matches repeated multiplication", func(t *testing.T) {
		base := uint16(7)
		expected := uint16(1)
		for exp := 0; exp < 20; exp++ {
			if gf16Pow(base, exp) != expected {
				t.Errorf("gf16Pow(%d, %d) = %d, want %d", base, exp, gf16Pow(base, exp), expected)
				return
			}
			expected = gf16Mul(expected, base)
		}
	})

	t.Run("Fermat little theorem: a^(2^16-1) == 1", func(t *testing.T) {
		for _, a := range []uint16{1, 2, 3, 7, 100, 255, 1000, 50000, 65534} {
			if gf16Pow(a, gf16Order) != 1 {
				t.Errorf("gf16Pow(%d, %d) = %d, want 1 (Fermat)", a, gf16Order, gf16Pow(a, gf16Order))
				return
			}
		}
	})

	// DA-R7-10: negative exponents must compute as the multiplicative
	// inverse (base^(-k) == gf16Inv(base)^k). This is a defense-in-depth
	// check — gf16Pow had no explicit negative-exponent validation, but
	// the log/exp table reduction already produces the correct inverse.
	t.Run("negative exponent equals inverse (DA-R7-10)", func(t *testing.T) {
		for _, a := range []uint16{1, 2, 3, 7, 100, 255, 1000, 50000, 65534} {
			inv, err := gf16Inv(a)
			if err != nil {
				t.Errorf("gf16Inv(%d) error: %v", a, err)
				return
			}
			// a^(-1) must equal gf16Inv(a)
			if got := gf16Pow(a, -1); got != inv {
				t.Errorf("gf16Pow(%d, -1) = %d, want %d (inverse)", a, got, inv)
				return
			}
			// a^(-2) must equal gf16Inv(a)^2 == gf16Mul(inv, inv)
			invSq := gf16Mul(inv, inv)
			if got := gf16Pow(a, -2); got != invSq {
				t.Errorf("gf16Pow(%d, -2) = %d, want %d (inverse squared)", a, got, invSq)
				return
			}
			// a * a^(-1) must equal 1
			if got := gf16Mul(a, gf16Pow(a, -1)); got != 1 {
				t.Errorf("gf16Mul(%d, gf16Pow(%d, -1)) = %d, want 1", a, a, got)
				return
			}
		}
	})
}
