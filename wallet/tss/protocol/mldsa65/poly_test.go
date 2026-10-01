// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"testing"
)

func TestNormalizeCoefficient(t *testing.T) {
	tests := []struct {
		input int64
		want  int32
	}{
		{input: -1, want: 8380416},
		{input: 0, want: 0},
		{input: 8380416, want: 8380416},
		{input: 8380417, want: 0},
		{input: 8380418, want: 1},
		{input: -8380418, want: 8380416},
	}
	for _, test := range tests {
		if got := NormalizeCoefficient(test.input); got != test.want {
			t.Fatalf("NormalizeCoefficient(%d) = %d, want %d", test.input, got, test.want)
		}
	}
}

func TestPolyCanonicalArithmetic(t *testing.T) {
	if _, err := NewPoly([]int32{8380417}); !errors.Is(err, ErrNonCanonicalCoefficient) {
		t.Fatalf("NewPoly() error = %v, want %v", err, ErrNonCanonicalCoefficient)
	}

	left, err := NewPoly([]int32{8380416, 1, 7})
	if err != nil {
		t.Fatalf("NewPoly(left): %v", err)
	}
	right, err := NewPoly([]int32{2, 2, 8380416})
	if err != nil {
		t.Fatalf("NewPoly(right): %v", err)
	}

	sum := Add(left, right)
	if sum[0] != 1 || sum[1] != 3 || sum[2] != 6 {
		t.Fatalf("Add() prefix = %v", sum[:3])
	}
	difference := Sub(left, right)
	if difference[0] != 8380414 || difference[1] != 8380416 || difference[2] != 8 {
		t.Fatalf("Sub() prefix = %v", difference[:3])
	}
	scaled := ScalarMul(left, -2)
	if scaled[0] != 2 || scaled[1] != 8380415 || scaled[2] != 8380403 {
		t.Fatalf("ScalarMul() prefix = %v", scaled[:3])
	}
}
