// Quantaureum Node source, version 1.0.0.
package dilithium3v1

const nttRoot Coefficient = 1753

// NTTPoly stores evaluations at the 256 roots of X^256+1 in mode3 order.
type NTTPoly [N]Coefficient

// ForwardNTT evaluates a polynomial at the mode3-ordered roots of X^256+1.
func ForwardNTT(polynomial Poly) NTTPoly {
	var transformed NTTPoly
	for evaluationIndex := 0; evaluationIndex < N; evaluationIndex++ {
		point := nttEvaluationPoint(evaluationIndex)
		power := Coefficient(1)
		var sum int64
		for coefficientIndex := 0; coefficientIndex < N; coefficientIndex++ {
			sum += int64(polynomial[coefficientIndex]) * int64(power)
			sum %= Q
			power = normalizeInt64(int64(power) * int64(point))
		}
		transformed[evaluationIndex] = Coefficient(sum)
	}
	return transformed
}

// InverseNTT interpolates a polynomial from mode3-ordered root evaluations.
func InverseNTT(transformed NTTPoly) Poly {
	var accumulated [N]int64
	for evaluationIndex := 0; evaluationIndex < N; evaluationIndex++ {
		pointInverse := modPow(nttEvaluationPoint(evaluationIndex), Q-2)
		power := Coefficient(1)
		for coefficientIndex := 0; coefficientIndex < N; coefficientIndex++ {
			accumulated[coefficientIndex] += int64(transformed[evaluationIndex]) * int64(power)
			accumulated[coefficientIndex] %= Q
			power = normalizeInt64(int64(power) * int64(pointInverse))
		}
	}
	invN := modPow(N, Q-2)
	var polynomial Poly
	for coefficientIndex := 0; coefficientIndex < N; coefficientIndex++ {
		polynomial[coefficientIndex] = normalizeInt64(accumulated[coefficientIndex] * int64(invN))
	}
	return polynomial
}

// MultiplyPolynomials multiplies modulo X^256+1 and q through the NTT domain.
func MultiplyPolynomials(left, right Poly) Poly {
	leftNTT := ForwardNTT(left)
	rightNTT := ForwardNTT(right)
	return InverseNTT(pointwiseMultiply(leftNTT, rightNTT))
}

func pointwiseMultiply(left, right NTTPoly) NTTPoly {
	var result NTTPoly
	for index := 0; index < N; index++ {
		result[index] = normalizeInt64(int64(left[index]) * int64(right[index]))
	}
	return result
}

func nttEvaluationPoint(index int) Coefficient {
	pair := uint8(index >> 1)
	exponent := 2*bitReverse7(pair) + 1
	if index&1 != 0 {
		exponent += N
	}
	return modPow(nttRoot, exponent)
}

func bitReverse7(value uint8) int {
	var reversed int
	for bit := 0; bit < 7; bit++ {
		reversed = reversed<<1 | int(value&1)
		value >>= 1
	}
	return reversed
}

func modPow(base Coefficient, exponent int) Coefficient {
	result := int64(1)
	factor := int64(Normalize(base))
	for exponent > 0 {
		if exponent&1 != 0 {
			result = result * factor % Q
		}
		factor = factor * factor % Q
		exponent >>= 1
	}
	return Coefficient(result)
}
