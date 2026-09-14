// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"testing"
)

func TestReverseBits(t *testing.T) {
	cases := []struct {
		n, expected int
		bits        uint
	}{
		{0, 0, 3},
		{1, 4, 3}, // 001 → 100
		{2, 2, 3}, // 010 → 010
		{3, 6, 3}, // 011 → 110
		{4, 1, 3}, // 100 → 001
		{5, 5, 3}, // 101 → 101
		{6, 3, 3}, // 110 → 011
		{7, 7, 3}, // 111 → 111
		{0, 0, 4},
		{1, 8, 4},   // 0001 → 1000
		{15, 15, 4}, // 1111 → 1111
	}

	for _, tc := range cases {
		result := reverseBits(tc.n, tc.bits)
		if result != tc.expected {
			t.Errorf("reverseBits(%d, %d) = %d, expected %d", tc.n, tc.bits, result, tc.expected)
		}
	}
}

func TestGF64NTT_RoundTrip(t *testing.T) {
	// NTT followed by INTT should give back the original
	sizes := []int{2, 4, 8, 16, 32, 64, 128, 256}

	for _, n := range sizes {
		coeffs := make([]GF64Element, n)
		for i := 0; i < n; i++ {
			coeffs[i] = GF64Element(i + 1)
		}

		omega := GF64DomainRoot(n)

		// Forward NTT
		evals := GF64NTT(coeffs, omega)

		// Inverse NTT
		recovered := GF64INTT(evals, omega)

		// Verify round trip
		for i := 0; i < n; i++ {
			if recovered[i] != coeffs[i] {
				t.Errorf("NTT round trip failed at size %d, index %d: got %d, expected %d",
					n, i, recovered[i], coeffs[i])
				break
			}
		}
	}
}

func TestGF64NTT_Correctness(t *testing.T) {
	// Verify NTT computes correct polynomial evaluations
	// f(x) = 3 + 2x + x^2
	coeffs := []GF64Element{3, 2, 1, 0} // degree 3 (padded to size 4)

	n := 4
	omega := GF64DomainRoot(n)
	evals := GF64NTT(coeffs, omega)

	// Manually evaluate f at each domain point
	domain := GF64Domain(n)
	for i := 0; i < n; i++ {
		// f(x) = 3 + 2*x + x^2
		x := domain[i]
		x2 := GF64Mul(x, x)
		expected := GF64Add(GF64Add(GF64Element(3), GF64Mul(GF64Element(2), x)), x2)

		if evals[i] != expected {
			t.Errorf("NTT evaluation at domain[%d] = %d, expected %d (f(%d) = %d)",
				i, evals[i], expected, x, expected)
		}
	}
}

func TestGF64NTT_Constant(t *testing.T) {
	// f(x) = 42 should evaluate to 42 everywhere
	n := 8
	coeffs := make([]GF64Element, n)
	coeffs[0] = 42

	omega := GF64DomainRoot(n)
	evals := GF64NTT(coeffs, omega)

	for i := 0; i < n; i++ {
		if evals[i] != 42 {
			t.Errorf("Constant polynomial: evals[%d] = %d, expected 42", i, evals[i])
		}
	}
}

func TestGF64NTT_Linear(t *testing.T) {
	// f(x) = 5 + 3x
	n := 4
	coeffs := []GF64Element{5, 3, 0, 0}

	omega := GF64DomainRoot(n)
	evals := GF64NTT(coeffs, omega)

	domain := GF64Domain(n)
	for i := 0; i < n; i++ {
		// f(x) = 5 + 3*x
		expected := GF64Add(GF64Element(5), GF64Mul(GF64Element(3), domain[i]))
		if evals[i] != expected {
			t.Errorf("Linear polynomial: evals[%d] = %d, expected %d", i, evals[i], expected)
		}
	}
}

func TestGF64Domain(t *testing.T) {
	// The domain should have n distinct elements, all being powers of omega
	n := 16
	domain := GF64Domain(n)
	omega := GF64DomainRoot(n)

	if len(domain) != n {
		t.Fatalf("Domain length = %d, expected %d", len(domain), n)
	}

	// domain[0] should be 1
	if domain[0] != 1 {
		t.Errorf("domain[0] = %d, expected 1", domain[0])
	}

	// domain[i] should be omega^i
	for i := 1; i < n; i++ {
		expected := GF64Mul(domain[i-1], omega)
		if domain[i] != expected {
			t.Errorf("domain[%d] = %d, expected %d (omega^%d)", i, domain[i], expected, i)
		}
	}

	// omega^n should be 1
	if GF64Pow(omega, uint64(n)) != 1 {
		t.Errorf("omega^%d != 1, domain is not a valid subgroup", n)
	}

	// All elements should be distinct (check by verifying omega^i != omega^j for i != j)
	// This is guaranteed if omega has order exactly n
	if GF64Pow(omega, uint64(n/2)) == 1 {
		t.Errorf("omega^(n/2) = 1, omega does not have order n")
	}
}

func TestGF64ReedSolomonExtend(t *testing.T) {
	// RS extension: evaluate a degree-3 polynomial on a domain of size 8
	// f(x) = 1 + 2x + 3x^2 + 4x^3
	coeffs := []GF64Element{1, 2, 3, 4}

	m := 8 // extension factor 2x
	evals := GF64ReedSolomonExtend(coeffs, m)

	if len(evals) != m {
		t.Fatalf("RS extend: got %d evaluations, expected %d", len(evals), m)
	}

	// Verify each evaluation by manual computation
	domain := GF64Domain(m)
	for i := 0; i < m; i++ {
		x := domain[i]
		// f(x) = 1 + 2x + 3x^2 + 4x^3
		x2 := GF64Mul(x, x)
		x3 := GF64Mul(x2, x)
		expected := GF64Add(
			GF64Add(GF64Element(1), GF64Mul(GF64Element(2), x)),
			GF64Add(GF64Mul(GF64Element(3), x2), GF64Mul(GF64Element(4), x3)),
		)
		if evals[i] != expected {
			t.Errorf("RS extend evals[%d] = %d, expected %d", i, evals[i], expected)
		}
	}
}

func TestGF64ReedSolomonExtend_Large(t *testing.T) {
	// Test with larger sizes for performance
	n := 256
	coeffs := make([]GF64Element, n)
	for i := 0; i < n; i++ {
		coeffs[i] = GF64Element(i*7 + 3)
	}

	m := 512 // 2x extension
	evals := GF64ReedSolomonExtend(coeffs, m)

	if len(evals) != m {
		t.Fatalf("RS extend large: got %d evaluations, expected %d", len(evals), m)
	}

	// Spot-check a few evaluations
	domain := GF64Domain(m)
	for _, idx := range []int{0, 1, 100, 255, 511} {
		x := domain[idx]
		// Compute f(x) manually
		expected := GF64Element(0)
		xPow := GF64Element(1)
		for j := 0; j < n; j++ {
			expected = GF64Add(expected, GF64Mul(coeffs[j], xPow))
			xPow = GF64Mul(xPow, x)
		}
		if evals[idx] != expected {
			t.Errorf("RS extend large evals[%d] = %d, expected %d", idx, evals[idx], expected)
		}
	}
}

func TestGF64NTT_Size1(t *testing.T) {
	// Edge case: size 1
	coeffs := []GF64Element{42}
	omega := GF64DomainRoot(1)
	evals := GF64NTT(coeffs, omega)
	if evals[0] != 42 {
		t.Errorf("NTT size 1: got %d, expected 42", evals[0])
	}
}

func TestGF64NTT_Size2(t *testing.T) {
	// f(x) = a + bx, domain = {1, -1}
	// f(1) = a + b, f(-1) = a - b
	a, b := GF64Element(5), GF64Element(3)
	coeffs := []GF64Element{a, b}

	omega := GF64DomainRoot(2)
	evals := GF64NTT(coeffs, omega)

	// omega should be -1 (= p-1)
	if omega != GF64Element(GoldilocksP-1) {
		t.Errorf("Order-2 root of unity = %d, expected %d (p-1)", omega, GoldilocksP-1)
	}

	// f(1) = a + b = 8
	if evals[0] != GF64Add(a, b) {
		t.Errorf("evals[0] = %d, expected %d", evals[0], GF64Add(a, b))
	}
	// f(omega) = f(-1) = a - b = 2
	if evals[1] != GF64Sub(a, b) {
		t.Errorf("evals[1] = %d, expected %d", evals[1], GF64Sub(a, b))
	}
}
