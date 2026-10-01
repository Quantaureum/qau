// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"fmt"
)

const (
	power2RoundD = 13
	gamma2       = 261888
	alpha        = 2 * gamma2
	highBitsMask = 15
)

var (
	ErrInvalidRoundingInput = errors.New("invalid ML-DSA rounding input")
	ErrInvalidHint          = errors.New("invalid ML-DSA hint")
)

// Power2Round splits a canonical coefficient into high and centered low bits.
func Power2Round(coefficient int32) (high int32, low int32, err error) {
	if !isCanonicalCoefficient(coefficient) {
		return 0, 0, fmt.Errorf("%w: coefficient %d", ErrInvalidRoundingInput, coefficient)
	}
	low64 := int64(coefficient) % (1 << power2RoundD)
	if low64 > 1<<(power2RoundD-1) {
		low64 -= 1 << power2RoundD
	}
	high64 := (int64(coefficient) - low64) >> power2RoundD
	return int32(high64), int32(low64), nil
}

// Decompose splits a canonical coefficient using alpha = 2*gamma2.
func Decompose(coefficient int32) (high int32, low int32, err error) {
	if !isCanonicalCoefficient(coefficient) {
		return 0, 0, fmt.Errorf("%w: coefficient %d", ErrInvalidRoundingInput, coefficient)
	}

	a := uint32(coefficient)
	a1 := (a + 127) >> 7
	a1 = (a1*1025 + (1 << 21)) >> 22
	a1 &= highBitsMask

	a0 := int64(a) - int64(a1)*alpha
	if a0 > (Modulus-1)/2 {
		a0 -= Modulus
	}
	return int32(a1), int32(a0), nil
}

// MakeHint reports whether the high bits change after applying centered low bits.
func MakeHint(zeroBits, highBits int32) (uint8, error) {
	if !isCanonicalCoefficient(zeroBits) || highBits < 0 || highBits > highBitsMask {
		return 0, ErrInvalidHint
	}
	if zeroBits <= gamma2 || zeroBits > Modulus-gamma2 || (zeroBits == Modulus-gamma2 && highBits == 0) {
		return 0, nil
	}
	return 1, nil
}

// UseHint reconstructs high bits from a canonical coefficient and one-bit hint.
func UseHint(coefficient int32, hint uint8) (int32, error) {
	if hint > 1 {
		return 0, ErrInvalidHint
	}
	high, low, err := Decompose(coefficient)
	if err != nil {
		return 0, err
	}
	if hint == 0 {
		return high, nil
	}
	if low > 0 {
		return (high + 1) & highBitsMask, nil
	}
	return (high - 1) & highBitsMask, nil
}
