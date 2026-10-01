// Quantaureum Node source, version 1.0.0.
package mldsa65

import "testing"

func TestPower2RoundRecombines(t *testing.T) {
	values := []int32{0, 1, 4095, 4096, 4097, 8191, 8192, 8380416}
	for _, value := range values {
		high, low, err := Power2Round(value)
		if err != nil {
			t.Fatalf("Power2Round(%d): %v", value, err)
		}
		if low <= -(1<<(13-1)) || low > 1<<(13-1) {
			t.Fatalf("Power2Round(%d) low = %d out of range", value, low)
		}
		if got := NormalizeCoefficient(int64(high)*(1<<13) + int64(low)); got != value {
			t.Fatalf("Power2Round(%d) recombined to %d", value, got)
		}
	}
}

func TestDecomposeRecombines(t *testing.T) {
	values := []int32{0, 1, 261887, 261888, 261889, 523775, 523776, 8380416}
	for _, value := range values {
		high, low, err := Decompose(value)
		if err != nil {
			t.Fatalf("Decompose(%d): %v", value, err)
		}
		if high < 0 || high > 15 {
			t.Fatalf("Decompose(%d) high = %d out of range", value, high)
		}
		if low < -261888 || low > 261888 {
			t.Fatalf("Decompose(%d) low = %d out of range", value, low)
		}
		if got := NormalizeCoefficient(int64(high)*523776 + int64(low)); got != value {
			t.Fatalf("Decompose(%d) recombined to %d", value, got)
		}
	}
}

func TestMakeHintUseHintIdentity(t *testing.T) {
	rValues := []int32{0, 1, 261888, 523776, 1047552, 8118529, 8380416}
	fValues := []int32{-196, -1, 0, 1, 196}
	for _, r := range rValues {
		for _, f := range fValues {
			r1, r0, err := Decompose(r)
			if err != nil {
				t.Fatalf("Decompose(%d): %v", r, err)
			}
			z0 := NormalizeCoefficient(int64(r0) - int64(f))
			hint, err := MakeHint(z0, r1)
			if err != nil {
				t.Fatalf("MakeHint(%d, %d): %v", z0, r1, err)
			}
			rPrime := NormalizeCoefficient(int64(r) - int64(f))
			got, err := UseHint(rPrime, hint)
			if err != nil {
				t.Fatalf("UseHint(%d, %d): %v", rPrime, hint, err)
			}
			if got != r1 {
				t.Fatalf("r=%d f=%d hint=%d recovered high=%d, want %d", r, f, hint, got, r1)
			}
		}
	}
}
