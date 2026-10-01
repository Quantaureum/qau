// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"fmt"
)

var ErrNonCanonicalCoefficient = errors.New("non-canonical Dilithium3 coefficient")

// Coefficient stores either a canonical or centered ring representative.
type Coefficient int32

// Poly stores one polynomial in the Dilithium ring.
type Poly [N]Coefficient

// SignedPoly stores centered coefficients used by mode3 encodings.
type SignedPoly [N]Coefficient

// VectorL stores the mode3 secret-vector dimension.
type VectorL [L]Poly

// VectorK stores the mode3 public-vector dimension.
type VectorK [K]Poly

// NewPoly constructs a canonical polynomial and zero-fills missing coefficients.
func NewPoly(coefficients []Coefficient) (Poly, error) {
	if len(coefficients) > N {
		return Poly{}, fmt.Errorf("%w: coefficient count %d exceeds %d", ErrNonCanonicalCoefficient, len(coefficients), N)
	}
	var polynomial Poly
	for index, coefficient := range coefficients {
		if !isCanonicalCoefficient(coefficient) {
			return Poly{}, fmt.Errorf("%w: coefficient %d at index %d", ErrNonCanonicalCoefficient, coefficient, index)
		}
		polynomial[index] = coefficient
	}
	return polynomial, nil
}

// Normalize returns a coefficient modulo q in the interval [0, q).
func Normalize(coefficient Coefficient) Coefficient {
	return normalizeInt64(int64(coefficient))
}

// CenteredCoefficient returns the centered representative of a coefficient in
// the interval (-q/2, q/2].
func CenteredCoefficient(coefficient Coefficient) Coefficient {
	value := Normalize(coefficient)
	if value > Q/2 {
		value -= Q
	}
	return value
}

func normalizeInt64(value int64) Coefficient {
	value %= Q
	if value < 0 {
		value += Q
	}
	return Coefficient(value)
}

// Add adds two polynomials coefficient-wise modulo q.
func Add(left, right Poly) Poly {
	var result Poly
	for index := 0; index < N; index++ {
		result[index] = normalizeInt64(int64(left[index]) + int64(right[index]))
	}
	return result
}

// Sub subtracts two polynomials coefficient-wise modulo q.
func Sub(left, right Poly) Poly {
	var result Poly
	for index := 0; index < N; index++ {
		result[index] = normalizeInt64(int64(left[index]) - int64(right[index]))
	}
	return result
}

// ScalarMul multiplies a polynomial by a scalar modulo q.
func ScalarMul(polynomial Poly, scalar Coefficient) Poly {
	var result Poly
	for index := 0; index < N; index++ {
		result[index] = normalizeInt64(int64(polynomial[index]) * int64(scalar))
	}
	return result
}

// InfinityNorm returns the largest absolute centered coefficient.
func InfinityNorm(polynomial Poly) int32 {
	var maximum int32
	for index := 0; index < N; index++ {
		canonical := int32(Normalize(polynomial[index]))
		centered := canonical
		if centered > Q/2 {
			centered -= Q
		}
		if centered < 0 {
			centered = -centered
		}
		if centered > maximum {
			maximum = centered
		}
	}
	return maximum
}

func isCanonicalCoefficient(coefficient Coefficient) bool {
	return coefficient >= 0 && coefficient < Q
}
