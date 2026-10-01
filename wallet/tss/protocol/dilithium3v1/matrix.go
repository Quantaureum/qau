// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bufio"
	"crypto/sha3"
	"fmt"
)

// Matrix stores the K-by-L mode3 public matrix in NTT representation.
type Matrix [K][L]NTTPoly

// ExpandMatrix deterministically expands rho using the mode3 SHAKE128 sampler.
func ExpandMatrix(rho [32]byte) Matrix {
	var matrix Matrix
	for row := 0; row < K; row++ {
		for column := 0; column < L; column++ {
			nonce := uint16(row<<8 | column)
			shake := sha3.NewSHAKE128()
			_, _ = shake.Write(rho[:])
			_, _ = shake.Write([]byte{byte(nonce), byte(nonce >> 8)})
			reader := bufio.NewReaderSize(shake, 504)
			for index := 0; index < N; index++ {
				for {
					first, _ := reader.ReadByte()
					second, _ := reader.ReadByte()
					third, _ := reader.ReadByte()
					candidate := uint32(first) | uint32(second)<<8 | uint32(third&0x7f)<<16
					if candidate < Q {
						matrix[row][column][index] = Coefficient(candidate)
						break
					}
				}
			}
		}
	}
	return matrix
}

// ComputePublicVector computes A(rho)*s1+s2 modulo X^256+1 and q.
func ComputePublicVector(rho [32]byte, s1 VectorL, s2 VectorK) (VectorK, error) {
	if err := validateVectorL("s1", s1); err != nil {
		return VectorK{}, fmt.Errorf("invalid public vector input: %w", err)
	}
	if err := validateVectorK("s2", s2); err != nil {
		return VectorK{}, fmt.Errorf("invalid public vector input: %w", err)
	}
	matrix := ExpandMatrix(rho)
	var s1NTT [L]NTTPoly
	for column := 0; column < L; column++ {
		s1NTT[column] = ForwardNTT(s1[column])
	}
	var result VectorK
	for row := 0; row < K; row++ {
		var sum NTTPoly
		for column := 0; column < L; column++ {
			product := pointwiseMultiply(matrix[row][column], s1NTT[column])
			for index := 0; index < N; index++ {
				sum[index] = normalizeInt64(int64(sum[index]) + int64(product[index]))
			}
		}
		result[row] = Add(InverseNTT(sum), s2[row])
	}
	return result, nil
}
