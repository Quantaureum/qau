// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"math/bits"
	"testing"
)

// Helper: convert uint64 to GF64Element with reduction
func toGF64(v uint64) GF64Element {
	if v >= GoldilocksP {
		v -= GoldilocksP
	}
	return GF64Element(v)
}

func TestGF64_Add(t *testing.T) {
	// Basic addition
	cases := []struct{ a, b, expected uint64 }{
		{0, 0, 0},
		{1, 2, 3},
		{GoldilocksP - 1, 1, 0},                 // (p-1) + 1 = p ≡ 0
		{GoldilocksP - 1, 2, 1},                 // (p-1) + 2 = p+1 ≡ 1
		{GoldilocksP / 2, GoldilocksP/2 + 1, 0}, // sum = p ≡ 0 (p is odd, so p/2 + p/2 + 1 = p)
	}

	for _, tc := range cases {
		result := GF64Add(toGF64(tc.a), toGF64(tc.b))
		if uint64(result) != tc.expected {
			t.Errorf("GF64Add(%d, %d) = %d, expected %d", tc.a, tc.b, result, tc.expected)
		}
	}
}

func TestGF64_Sub(t *testing.T) {
	// Basic subtraction
	cases := []struct{ a, b, expected uint64 }{
		{0, 0, 0},
		{3, 2, 1},
		{0, 1, GoldilocksP - 1}, // 0 - 1 = -1 ≡ p-1
		{1, 2, GoldilocksP - 1}, // 1 - 2 = -1 ≡ p-1
		{GoldilocksP - 1, GoldilocksP - 1, 0},
	}

	for _, tc := range cases {
		result := GF64Sub(toGF64(tc.a), toGF64(tc.b))
		if uint64(result) != tc.expected {
			t.Errorf("GF64Sub(%d, %d) = %d, expected %d", tc.a, tc.b, result, tc.expected)
		}
	}
}

func TestGF64_Neg(t *testing.T) {
	cases := []struct{ a, expected uint64 }{
		{0, 0},
		{1, GoldilocksP - 1},
		{GoldilocksP - 1, 1},
		{GoldilocksP / 2, GoldilocksP - GoldilocksP/2},
	}

	for _, tc := range cases {
		result := GF64Neg(toGF64(tc.a))
		if uint64(result) != tc.expected {
			t.Errorf("GF64Neg(%d) = %d, expected %d", tc.a, result, tc.expected)
		}
		// Verify: a + (-a) = 0
		sum := GF64Add(toGF64(tc.a), result)
		if sum != 0 {
			t.Errorf("GF64Add(%d, GF64Neg(%d)) = %d, expected 0", tc.a, tc.a, sum)
		}
	}
}

func TestGF64_Mul(t *testing.T) {
	// Small values: verify with direct computation
	cases := []struct{ a, b, expected uint64 }{
		{0, 0, 0},
		{0, 5, 0},
		{1, 5, 5},
		{2, 3, 6},
		{3, 7, 21},
		{255, 256, 65280},
	}

	for _, tc := range cases {
		result := GF64Mul(toGF64(tc.a), toGF64(tc.b))
		if uint64(result) != tc.expected {
			t.Errorf("GF64Mul(%d, %d) = %d, expected %d", tc.a, tc.b, result, tc.expected)
		}
	}
}

func TestGF64_Mul_Large(t *testing.T) {
	// Test with large values near p
	a := toGF64(GoldilocksP - 1) // p-1 ≡ -1
	b := toGF64(GoldilocksP - 1) // p-1 ≡ -1
	result := GF64Mul(a, b)
	// (-1) * (-1) = 1
	if result != 1 {
		t.Errorf("GF64Mul(p-1, p-1) = %d, expected 1 (since p-1 ≡ -1)", result)
	}

	// p-1 * 2 = 2p - 2 ≡ p - 2
	a = toGF64(GoldilocksP - 1)
	b = toGF64(2)
	result = GF64Mul(a, b)
	expected := GoldilocksP - 2
	if uint64(result) != expected {
		t.Errorf("GF64Mul(p-1, 2) = %d, expected %d", result, expected)
	}

	// (p/2) * 2 should be 0 if p is even, or p if p is odd... p is odd
	// Actually p/2 * 2 = p ≡ 0 (mod p)
	halfP := (GoldilocksP) / 2 // floor division
	a = toGF64(halfP)
	b = toGF64(2)
	result = GF64Mul(a, b)
	// halfP * 2 = 2 * floor(p/2). Since p is odd, 2*floor(p/2) = p-1
	if uint64(result) != GoldilocksP-1 {
		t.Errorf("GF64Mul(p/2, 2) = %d, expected %d", result, GoldilocksP-1)
	}
}

func TestGF64_Mul_CrossCheck(t *testing.T) {
	// Cross-check multiplication against 128-bit computation for random-ish values
	testValues := []uint64{
		0, 1, 2, 3, 100, 1000, 1 << 20, 1 << 32, 1 << 40,
		GoldilocksP - 1, GoldilocksP - 2, GoldilocksP / 2,
		0xABCDEF1234567890 % GoldilocksP,
		0x1234567890ABCDEF % GoldilocksP,
		0xFFFFFFFF00000000 % GoldilocksP,
	}

	for _, a := range testValues {
		for _, b := range testValues {
			// Compute using our implementation
			result := uint64(GF64Mul(toGF64(a), toGF64(b)))

			// Compute using 128-bit arithmetic
			hi, lo := bits.Mul64(a, b)
			// Reduce: hi * 2^64 + lo mod p
			// 2^64 ≡ 2^32 - 1 (mod p)
			// So result = lo + hi * (2^32 - 1) mod p
			// Use iterative reduction
			for hi > 0 {
				newLo, carry := bits.Add64(lo, hi<<(32), 0)
				newHi := hi >> 32
				if carry != 0 {
					newHi++
				}
				newLo2, borrow := bits.Sub64(newLo, hi, 0)
				if borrow != 0 {
					newHi--
				}
				lo = newLo2
				hi = newHi
			}
			expected := lo
			for expected >= GoldilocksP {
				expected -= GoldilocksP
			}

			if result != expected {
				t.Errorf("GF64Mul(0x%X, 0x%X) = 0x%X, expected 0x%X", a, b, result, expected)
			}
		}
	}
}

func TestGF64_Inverse(t *testing.T) {
	// a * a^(-1) = 1
	testValues := []GF64Element{
		1, 2, 3, 100, 1000,
		toGF64(GoldilocksP - 1),
		toGF64(GoldilocksP - 2),
		toGF64(GoldilocksP / 2),
		toGF64(1 << 32),
		toGF64(0xABCDEF1234567890),
	}

	for _, a := range testValues {
		if a == 0 {
			continue
		}
		inv, err := GF64Inverse(a)
		if err != nil {
			t.Errorf("GF64Inverse(%d) returned error: %v", a, err)
			continue
		}
		product := GF64Mul(a, inv)
		if product != 1 {
			t.Errorf("GF64Mul(%d, GF64Inverse(%d)) = %d, expected 1", a, a, product)
		}
	}

	// ENCODING-P0-01: Verify GF64Inverse(0) returns error (not panic).
	if _, err := GF64Inverse(0); err == nil {
		t.Error("GF64Inverse(0) should return error, got nil")
	}
}

func TestGF64_Div(t *testing.T) {
	// a / b * b = a
	cases := []struct{ a, b uint64 }{
		{6, 2},
		{100, 5},
		{GoldilocksP - 1, 7},
		{GoldilocksP / 3, 3},
	}

	for _, tc := range cases {
		a := toGF64(tc.a)
		b := toGF64(tc.b)
		if b == 0 {
			continue
		}
		quotient, err := GF64Div(a, b)
		if err != nil {
			t.Errorf("GF64Div(%d, %d) returned error: %v", a, b, err)
			continue
		}
		product := GF64Mul(quotient, b)
		if product != a {
			t.Errorf("GF64Div(%d, %d) * %d = %d, expected %d", a, b, b, product, a)
		}
	}

	// ENCODING-P0-01: Verify GF64Div(_, 0) returns error (not panic).
	if _, err := GF64Div(1, 0); err == nil {
		t.Error("GF64Div(1, 0) should return error, got nil")
	}
}

func TestGF64_Pow(t *testing.T) {
	// 2^10 = 1024
	result := GF64Pow(2, 10)
	if result != 1024 {
		t.Errorf("GF64Pow(2, 10) = %d, expected 1024", result)
	}

	// a^0 = 1
	result = GF64Pow(7, 0)
	if result != 1 {
		t.Errorf("GF64Pow(7, 0) = %d, expected 1", result)
	}

	// a^1 = a
	result = GF64Pow(7, 1)
	if result != 7 {
		t.Errorf("GF64Pow(7, 1) = %d, expected 7", result)
	}

	// Fermat's little theorem: a^(p-1) = 1 for a != 0
	result = GF64Pow(7, GoldilocksP-1)
	if result != 1 {
		t.Errorf("GF64Pow(7, p-1) = %d, expected 1 (Fermat)", result)
	}
}

func TestGF64_Generator(t *testing.T) {
	// The generator of order 2^k should satisfy g^(2^k) = 1 and g^(2^(k-1)) != 1
	for k := uint(1); k <= 20; k++ {
		g := GF64Generator(k)
		order := uint64(1) << k

		// g^order should be 1
		result := GF64Pow(g, order)
		if result != 1 {
			t.Errorf("GF64Generator(%d)^%d = %d, expected 1", k, order, result)
		}

		// g^(order/2) should NOT be 1
		result = GF64Pow(g, order/2)
		if result == 1 {
			t.Errorf("GF64Generator(%d)^(%d) = 1, but should not be 1 (not primitive)", k, order/2)
		}
	}
}

func TestGF64_BytesRoundTrip(t *testing.T) {
	testValues := []GF64Element{
		0, 1, 2, 255, 256, 1 << 20, 1 << 32,
		toGF64(GoldilocksP - 1),
		toGF64(0xABCDEF1234567890),
	}

	for _, v := range testValues {
		b := GF64ToBytes(v)
		if len(b) != 8 {
			t.Errorf("GF64ToBytes(%d) returned %d bytes, expected 8", v, len(b))
		}
		result := GF64FromBytes(b)
		if result != v {
			t.Errorf("GF64FromBytes(GF64ToBytes(%d)) = %d, expected %d", v, result, v)
		}
	}
}

func TestGF64_Distributive(t *testing.T) {
	// a * (b + c) = a*b + a*c
	a := toGF64(123)
	b := toGF64(456)
	c := toGF64(789)

	lhs := GF64Mul(a, GF64Add(b, c))
	rhs := GF64Add(GF64Mul(a, b), GF64Mul(a, c))

	if lhs != rhs {
		t.Errorf("Distributive law failed: a*(b+c)=%d, a*b+a*c=%d", lhs, rhs)
	}
}

func TestGF64_Associative(t *testing.T) {
	// (a * b) * c = a * (b * c)
	a := toGF64(123)
	b := toGF64(456)
	c := toGF64(789)

	lhs := GF64Mul(GF64Mul(a, b), c)
	rhs := GF64Mul(a, GF64Mul(b, c))

	if lhs != rhs {
		t.Errorf("Associative law failed: (a*b)*c=%d, a*(b*c)=%d", lhs, rhs)
	}
}
