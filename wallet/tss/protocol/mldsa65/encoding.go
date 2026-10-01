// Quantaureum Node source, version 1.0.0.
package mldsa65

import "errors"

const (
	highBitsEncodedSize = Degree / 2
	zEncodedSize        = Degree * 20 / 8
	hintEncodedSize     = 55 + 6
)

var (
	ErrInvalidHighBits     = errors.New("invalid ML-DSA high bits")
	ErrInvalidZCoefficient = errors.New("invalid ML-DSA z coefficient")
	ErrInvalidHintVector   = errors.New("invalid ML-DSA hint vector")
	ErrTooManyHints        = errors.New("too many ML-DSA hints")
)

// HighBitsPoly stores four-bit high-bit coefficients.
type HighBitsPoly [Degree]uint8

// HintVector stores six binary hint polynomials.
type HintVector [6][Degree]uint8

// EncodeHighBits encodes two four-bit coefficients per byte.
func EncodeHighBits(polynomial HighBitsPoly) ([highBitsEncodedSize]byte, error) {
	var encoded [highBitsEncodedSize]byte
	for index := 0; index < Degree; index += 2 {
		if polynomial[index] > highBitsMask || polynomial[index+1] > highBitsMask {
			return [highBitsEncodedSize]byte{}, ErrInvalidHighBits
		}
		encoded[index/2] = polynomial[index] | polynomial[index+1]<<4
	}
	return encoded, nil
}

// EncodeZ encodes two centered 20-bit coefficients into five bytes.
func EncodeZ(polynomial SignedPoly) ([zEncodedSize]byte, error) {
	var encoded [zEncodedSize]byte
	const gamma1 = 1 << 19
	for coefficientIndex, byteIndex := 0, 0; coefficientIndex < Degree; coefficientIndex, byteIndex = coefficientIndex+2, byteIndex+5 {
		left := polynomial[coefficientIndex]
		right := polynomial[coefficientIndex+1]
		if left <= -gamma1 || left > gamma1 || right <= -gamma1 || right > gamma1 {
			return [zEncodedSize]byte{}, ErrInvalidZCoefficient
		}

		leftEncoded := uint32(gamma1 - left)
		rightEncoded := uint32(gamma1 - right)
		encoded[byteIndex] = byte(leftEncoded)
		encoded[byteIndex+1] = byte(leftEncoded >> 8)
		encoded[byteIndex+2] = byte(leftEncoded>>16) | byte(rightEncoded<<4)
		encoded[byteIndex+3] = byte(rightEncoded >> 4)
		encoded[byteIndex+4] = byte(rightEncoded >> 12)
	}
	return encoded, nil
}

// DecodeZ decodes one canonical 640-byte ML-DSA-65 z polynomial.
func DecodeZ(encoded []byte) (SignedPoly, error) {
	if len(encoded) != zEncodedSize {
		return SignedPoly{}, ErrInvalidEncodingSize
	}
	var polynomial SignedPoly
	const gamma1 = 1 << 19
	for coefficientIndex, byteIndex := 0, 0; coefficientIndex < Degree; coefficientIndex, byteIndex = coefficientIndex+2, byteIndex+5 {
		left := uint32(encoded[byteIndex]) |
			uint32(encoded[byteIndex+1])<<8 |
			uint32(encoded[byteIndex+2]&0x0f)<<16
		right := uint32(encoded[byteIndex+2]>>4) |
			uint32(encoded[byteIndex+3])<<4 |
			uint32(encoded[byteIndex+4])<<12
		polynomial[coefficientIndex] = gamma1 - int32(left)
		polynomial[coefficientIndex+1] = gamma1 - int32(right)
	}
	return polynomial, nil
}

// EncodeHints writes canonical sparse hint indices and cumulative offsets.
func EncodeHints(hints HintVector) ([hintEncodedSize]byte, error) {
	var encoded [hintEncodedSize]byte
	offset := 0
	for polynomialIndex := range hints {
		for coefficientIndex, hint := range hints[polynomialIndex] {
			if hint > 1 {
				return [hintEncodedSize]byte{}, ErrInvalidHintVector
			}
			if hint == 0 {
				continue
			}
			if offset >= 55 {
				return [hintEncodedSize]byte{}, ErrTooManyHints
			}
			encoded[offset] = byte(coefficientIndex)
			offset++
		}
		encoded[55+polynomialIndex] = byte(offset)
	}
	return encoded, nil
}

// DecodeHints rejects every non-canonical sparse hint encoding.
func DecodeHints(encoded []byte) (HintVector, error) {
	if len(encoded) != hintEncodedSize {
		return HintVector{}, ErrInvalidEncodingSize
	}
	var hints HintVector
	previousOffset := 0
	for polynomialIndex := range hints {
		offset := int(encoded[55+polynomialIndex])
		if offset < previousOffset || offset > 55 {
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
	for index := previousOffset; index < 55; index++ {
		if encoded[index] != 0 {
			return HintVector{}, ErrInvalidHintVector
		}
	}
	return hints, nil
}
