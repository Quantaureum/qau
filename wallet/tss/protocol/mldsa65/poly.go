// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"fmt"
)

const (
	Degree  = 256
	Modulus = 8380417
)

var ErrNonCanonicalCoefficient = errors.New("non-canonical ML-DSA coefficient")

// Poly stores canonical coefficients in [0, q).
type Poly [Degree]int32

// SignedPoly stores centered coefficients for encodings such as z.
type SignedPoly [Degree]int32

// NewPoly constructs a canonical polynomial and zero-fills missing coefficients.
func NewPoly(coefficients []int32) (Poly, error) {
	if len(coefficients) > Degree {
		return Poly{}, fmt.Errorf("%w: coefficient count %d exceeds %d", ErrNonCanonicalCoefficient, len(coefficients), Degree)
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

// NormalizeCoefficient returns value modulo q in [0, q).
func NormalizeCoefficient(value int64) int32 {
	value %= Modulus
	if value < 0 {
		value += Modulus
	}
	return int32(value)
}

// Add adds canonical polynomials coefficient-wise modulo q.
func Add(left, right Poly) Poly {
	var result Poly
	for index := 0; index < Degree; index++ {
		result[index] = NormalizeCoefficient(int64(left[index]) + int64(right[index]))
	}
	return result
}

// Sub subtracts canonical polynomials coefficient-wise modulo q.
func Sub(left, right Poly) Poly {
	var result Poly
	for index := 0; index < Degree; index++ {
		result[index] = NormalizeCoefficient(int64(left[index]) - int64(right[index]))
	}
	return result
}

// ScalarMul multiplies a canonical polynomial by a public scalar modulo q.
func ScalarMul(polynomial Poly, scalar int32) Poly {
	var result Poly
	for index := 0; index < Degree; index++ {
		result[index] = NormalizeCoefficient(int64(polynomial[index]) * int64(scalar))
	}
	return result
}

func isCanonicalCoefficient(coefficient int32) bool {
	return coefficient >= 0 && coefficient < Modulus
}
