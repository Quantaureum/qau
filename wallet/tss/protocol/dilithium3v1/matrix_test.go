// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bufio"
	"crypto/sha3"
	"testing"
)

func TestMatrixExpansionMatchesMode3Oracle(t *testing.T) {
	var rho [32]byte
	for index := range rho {
		rho[index] = byte(index)
	}
	matrix := ExpandMatrix(rho)
	for row := 0; row < K; row++ {
		for column := 0; column < L; column++ {
			want := testMode3UniformPolynomial(rho, uint16(row<<8|column))
			if matrix[row][column] != want {
				t.Fatalf("matrix[%d][%d] differs from mode3 oracle", row, column)
			}
		}
	}
}

func testMode3UniformPolynomial(seed [32]byte, nonce uint16) NTTPoly {
	shake := sha3.NewSHAKE128()
	_, _ = shake.Write(seed[:])
	_, _ = shake.Write([]byte{byte(nonce), byte(nonce >> 8)})
	reader := bufio.NewReaderSize(shake, 504)
	var polynomial NTTPoly
	for index := range polynomial {
		for {
			first, _ := reader.ReadByte()
			second, _ := reader.ReadByte()
			third, _ := reader.ReadByte()
			candidate := uint32(first) | uint32(second)<<8 | uint32(third&0x7f)<<16
			if candidate < Q {
				polynomial[index] = Coefficient(candidate)
				break
			}
		}
	}
	return polynomial
}
