// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import "errors"

const (
	PolyEncodedSize     = N * 3
	HighBitsEncodedSize = N / 2
	ZEncodedSize        = N * 20 / 8
	HintEncodedSize     = Omega + K
)

var (
	ErrInvalidHighBits     = errors.New("invalid Dilithium3 high bits")
	ErrInvalidZCoefficient = errors.New("invalid Dilithium3 z coefficient")
	ErrInvalidHintVector   = errors.New("invalid Dilithium3 hint vector")
	ErrTooManyHints        = errors.New("too many Dilithium3 hints")
)

// HighBitsPoly stores four-bit high-bit coefficients.
type HighBitsPoly [N]uint8

// HintVector stores the six mode3 hint polynomials.
type HintVector [K]HintPoly

// EncodePoly encodes canonical coefficients as fixed-width little-endian values.
func EncodePoly(polynomial Poly) ([PolyEncodedSize]byte, error) {
	var encoded [PolyEncodedSize]byte
	for index, coefficient := range polynomial {
		if !isCanonicalCoefficient(coefficient) {
			return [PolyEncodedSize]byte{}, ErrNonCanonicalCoefficient
		}
		value := uint32(coefficient)
		offset := index * 3
		encoded[offset] = byte(value)
		encoded[offset+1] = byte(value >> 8)
		encoded[offset+2] = byte(value >> 16)
	}
	return encoded, nil
}

// DecodePoly rejects wrong sizes and coefficients outside the canonical field range.
func DecodePoly(encoded []byte) (Poly, error) {
	if len(encoded) != PolyEncodedSize {
		return Poly{}, ErrInvalidEncodingSize
	}
	var polynomial Poly
	for index := 0; index < N; index++ {
		offset := index * 3
		value := uint32(encoded[offset]) | uint32(encoded[offset+1])<<8 | uint32(encoded[offset+2])<<16
		if value >= Q {
			return Poly{}, ErrNonCanonicalCoefficient
		}
		polynomial[index] = Coefficient(value)
	}
	return polynomial, nil
}

// EncodeHighBits packs two four-bit coefficients into each byte.
func EncodeHighBits(polynomial HighBitsPoly) ([HighBitsEncodedSize]byte, error) {
	var encoded [HighBitsEncodedSize]byte
	for index := 0; index < N; index += 2 {
		if polynomial[index] > highBitsMask || polynomial[index+1] > highBitsMask {
			return [HighBitsEncodedSize]byte{}, ErrInvalidHighBits
		}
		encoded[index/2] = polynomial[index] | polynomial[index+1]<<4
	}
	return encoded, nil
}

// DecodeHighBits decodes one fixed-size four-bit polynomial.
func DecodeHighBits(encoded []byte) (HighBitsPoly, error) {
	if len(encoded) != HighBitsEncodedSize {
		return HighBitsPoly{}, ErrInvalidEncodingSize
	}
	var polynomial HighBitsPoly
	for index, value := range encoded {
		polynomial[index*2] = value & highBitsMask
		polynomial[index*2+1] = value >> 4
	}
	return polynomial, nil
}

// EncodeZ packs two centered 20-bit coefficients into five bytes.
func EncodeZ(polynomial SignedPoly) ([ZEncodedSize]byte, error) {
	var encoded [ZEncodedSize]byte
	for coefficientIndex, byteIndex := 0, 0; coefficientIndex < N; coefficientIndex, byteIndex = coefficientIndex+2, byteIndex+5 {
		left := polynomial[coefficientIndex]
		right := polynomial[coefficientIndex+1]
		if left <= -Gamma1 || left > Gamma1 || right <= -Gamma1 || right > Gamma1 {
			return [ZEncodedSize]byte{}, ErrInvalidZCoefficient
		}
		leftEncoded := uint32(Gamma1 - left)
		rightEncoded := uint32(Gamma1 - right)
		encoded[byteIndex] = byte(leftEncoded)
		encoded[byteIndex+1] = byte(leftEncoded >> 8)
		encoded[byteIndex+2] = byte(leftEncoded>>16) | byte(rightEncoded<<4)
		encoded[byteIndex+3] = byte(rightEncoded >> 4)
		encoded[byteIndex+4] = byte(rightEncoded >> 12)
	}
	return encoded, nil
}

// DecodeZ decodes one canonical 640-byte mode3 z polynomial.
func DecodeZ(encoded []byte) (SignedPoly, error) {
	if len(encoded) != ZEncodedSize {
		return SignedPoly{}, ErrInvalidEncodingSize
	}
	var polynomial SignedPoly
	for coefficientIndex, byteIndex := 0, 0; coefficientIndex < N; coefficientIndex, byteIndex = coefficientIndex+2, byteIndex+5 {
		left := uint32(encoded[byteIndex]) | uint32(encoded[byteIndex+1])<<8 | uint32(encoded[byteIndex+2]&0x0f)<<16
		right := uint32(encoded[byteIndex+2]>>4) | uint32(encoded[byteIndex+3])<<4 | uint32(encoded[byteIndex+4])<<12
		polynomial[coefficientIndex] = Coefficient(Gamma1 - int(left))
		polynomial[coefficientIndex+1] = Coefficient(Gamma1 - int(right))
	}
	return polynomial, nil
}

// EncodeHints writes canonical sparse indices and cumulative offsets.
func EncodeHints(hints HintVector) ([HintEncodedSize]byte, error) {
	var encoded [HintEncodedSize]byte
	offset := 0
	for polynomialIndex := range hints {
		for coefficientIndex, hint := range hints[polynomialIndex] {
			if hint > 1 {
				return [HintEncodedSize]byte{}, ErrInvalidHintVector
			}
			if hint == 0 {
				continue
			}
			if offset >= Omega {
				return [HintEncodedSize]byte{}, ErrTooManyHints
			}
			encoded[offset] = byte(coefficientIndex)
			offset++
		}
		encoded[Omega+polynomialIndex] = byte(offset)
	}
	return encoded, nil
}

// DecodeHints rejects every non-canonical sparse hint encoding.
func DecodeHints(encoded []byte) (HintVector, error) {
	if len(encoded) != HintEncodedSize {
		return HintVector{}, ErrInvalidEncodingSize
	}
	var hints HintVector
	previousOffset := 0
	for polynomialIndex := range hints {
		offset := int(encoded[Omega+polynomialIndex])
		if offset < previousOffset || offset > Omega {
			return HintVector{}, ErrInvalidHintVector
		}
		for index := previousOffset; index < offset; index++ {
			if index > previousOffset && encoded[index] <= encoded[index-1] {
				return HintVector{}, ErrInvalidHintVector
			}
			hints[polynomialIndex][encoded[index]] = 1
		}
		previousOffset = offset
	}
	for index := previousOffset; index < Omega; index++ {
		if encoded[index] != 0 {
			return HintVector{}, ErrInvalidHintVector
		}
	}
	return hints, nil
}
