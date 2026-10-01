// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import "testing"

func TestNTTRoundTripAndNegacyclicMultiplication(t *testing.T) {
	var left Poly
	var right Poly
	for index := 0; index < N; index++ {
		left[index] = Coefficient((index*17 + 3) % Q)
		right[index] = Coefficient((index*29 + 5) % Q)
	}
	transformed := ForwardNTT(left)
	if restored := InverseNTT(transformed); restored != left {
		t.Fatal("NTT round trip mismatch")
	}
	want := testNegacyclicProduct(left, right)
	if got := MultiplyPolynomials(left, right); got != want {
		t.Fatal("NTT multiplication differs from negacyclic oracle")
	}
}

func testNegacyclicProduct(left, right Poly) Poly {
	var accumulated [N]int64
	for leftIndex := 0; leftIndex < N; leftIndex++ {
		for rightIndex := 0; rightIndex < N; rightIndex++ {
			product := int64(left[leftIndex]) * int64(right[rightIndex])
			index := leftIndex + rightIndex
			if index >= N {
				index -= N
				product = -product
			}
			accumulated[index] += product
		}
	}
	var result Poly
	for index, coefficient := range accumulated {
		result[index] = normalizeInt64(coefficient)
	}
	return result
}
