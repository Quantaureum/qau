// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import "errors"

const highBitsMask = 15

var (
	ErrInvalidRoundingInput = errors.New("invalid Dilithium3 rounding input")
	ErrInvalidHint          = errors.New("invalid Dilithium3 hint")
)

// HintPoly stores one bit per coefficient.
type HintPoly [N]uint8

// Power2Round splits each coefficient into high and centered low bits.
func Power2Round(polynomial Poly) (high Poly, low Poly) {
	for index := 0; index < N; index++ {
		coefficient := int64(Normalize(polynomial[index]))
		lowBits := coefficient % (1 << D)
		if lowBits > 1<<(D-1) {
			lowBits -= 1 << D
		}
		high[index] = Coefficient((coefficient - lowBits) >> D)
		low[index] = Coefficient(lowBits)
	}
	return high, low
}

// Decompose splits each coefficient using alpha equal to two times gamma2.
func Decompose(polynomial Poly) (high Poly, low Poly) {
	for index := 0; index < N; index++ {
		high[index], low[index] = decomposeCoefficient(polynomial[index])
	}
	return high, low
}

func decomposeCoefficient(coefficient Coefficient) (high Coefficient, low Coefficient) {
	canonical := uint32(Normalize(coefficient))
	highBits := (canonical + 127) >> 7
	highBits = (highBits*1025 + (1 << 21)) >> 22
	highBits &= highBitsMask

	lowBits := int64(canonical) - int64(highBits)*(2*Gamma2)
	if lowBits > (Q-1)/2 {
		lowBits -= Q
	}
	return Coefficient(highBits), Coefficient(lowBits)
}

// HighBits returns the high component of Decompose.
func HighBits(polynomial Poly) Poly {
	high, _ := Decompose(polynomial)
	return high
}

// LowBits returns the centered low component of Decompose.
func LowBits(polynomial Poly) Poly {
	_, low := Decompose(polynomial)
	return low
}

// MakeHint marks coefficients whose high bits change after low-bit adjustment.
func MakeHint(zeroBits, highBits Poly) (HintPoly, error) {
	var hints HintPoly
	for index := 0; index < N; index++ {
		if !isCanonicalCoefficient(zeroBits[index]) || highBits[index] < 0 || highBits[index] > highBitsMask {
			return HintPoly{}, ErrInvalidRoundingInput
		}
		zero := zeroBits[index]
		if zero <= Gamma2 || zero > Q-Gamma2 || (zero == Q-Gamma2 && highBits[index] == 0) {
			continue
		}
		hints[index] = 1
	}
	return hints, nil
}

// UseHint applies one-bit corrections to decomposed high bits.
func UseHint(polynomial Poly, hints HintPoly) (Poly, error) {
	high, low := Decompose(polynomial)
	for index := 0; index < N; index++ {
		switch hints[index] {
		case 0:
			continue
		case 1:
			if low[index] > 0 {
				high[index] = (high[index] + 1) & highBitsMask
			} else {
				high[index] = (high[index] - 1) & highBitsMask
			}
		default:
			return Poly{}, ErrInvalidHint
		}
	}
	return high, nil
}
