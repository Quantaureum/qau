// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"
)

func TestPolyFixedDimensions(t *testing.T) {
	if len(Poly{}) != N || len(VectorL{}) != L || len(VectorK{}) != K {
		t.Fatalf("unexpected dimensions: poly=%d vectorL=%d vectorK=%d", len(Poly{}), len(VectorL{}), len(VectorK{}))
	}
}

func TestPolyNormalizeHandlesNegativeRepresentatives(t *testing.T) {
	tests := []struct{ value, want Coefficient }{
		{0, 0}, {1, 1}, {-1, Q - 1}, {Q, 0}, {-Q - 1, Q - 1},
	}
	for _, test := range tests {
		if got := Normalize(test.value); got != test.want {
			t.Fatalf("Normalize(%d) = %d, want %d", test.value, got, test.want)
		}
	}
}

func TestPolyArithmeticModuloQ(t *testing.T) {
	left, err := NewPoly([]Coefficient{0, 1, Q - 1, Q - 2})
	if err != nil {
		t.Fatalf("NewPoly(left): %v", err)
	}
	right, err := NewPoly([]Coefficient{1, Q - 1, 2, 3})
	if err != nil {
		t.Fatalf("NewPoly(right): %v", err)
	}
	added := Add(left, right)
	if added[0] != 1 || added[1] != 0 || added[2] != 1 || added[3] != 1 {
		t.Fatalf("Add() prefix = %v", added[:4])
	}
	subtracted := Sub(left, right)
	if subtracted[0] != Q-1 || subtracted[1] != 2 || subtracted[2] != Q-3 || subtracted[3] != Q-5 {
		t.Fatalf("Sub() prefix = %v", subtracted[:4])
	}
	scaled := ScalarMul(right, -2)
	if scaled[0] != Q-2 || scaled[1] != 2 || scaled[2] != Q-4 || scaled[3] != Q-6 {
		t.Fatalf("ScalarMul() prefix = %v", scaled[:4])
	}
}

func TestPolyRejectsNonCanonicalConstruction(t *testing.T) {
	if _, err := NewPoly([]Coefficient{-1}); !errors.Is(err, ErrNonCanonicalCoefficient) {
		t.Fatalf("negative coefficient error = %v", err)
	}
	if _, err := NewPoly([]Coefficient{Q}); !errors.Is(err, ErrNonCanonicalCoefficient) {
		t.Fatalf("coefficient q error = %v", err)
	}
	if _, err := NewPoly(make([]Coefficient, N+1)); !errors.Is(err, ErrNonCanonicalCoefficient) {
		t.Fatalf("oversized polynomial error = %v", err)
	}
}

func TestPolyInfinityNormUsesCenteredRepresentatives(t *testing.T) {
	polynomial := Poly{0, 1, Q - 1, 25, Q - 37}
	if got := InfinityNorm(polynomial); got != 37 {
		t.Fatalf("InfinityNorm() = %d, want 37", got)
	}
}
