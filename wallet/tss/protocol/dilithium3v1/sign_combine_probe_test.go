// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"io"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func mode3CommitmentChallenge(key protocol.ThresholdKeyID, message []byte, commitment VectorK) ([CTildeSize]byte, error) {
	if key.Algorithm != qcrypto.SignatureAlgorithmDilithium3Legacy || key.Validate() != nil {
		return [CTildeSize]byte{}, ErrInvalidMode3Signature
	}
	var packedHighBits [K * HighBitsEncodedSize]byte
	for polynomialIndex, polynomial := range commitment {
		for _, coefficient := range polynomial {
			if !isCanonicalCoefficient(coefficient) {
				return [CTildeSize]byte{}, ErrNonCanonicalCoefficient
			}
		}
		var highBits HighBitsPoly
		for coefficientIndex, coefficient := range HighBits(polynomial) {
			highBits[coefficientIndex] = uint8(coefficient)
		}
		encoded, err := EncodeHighBits(highBits)
		if err != nil {
			return [CTildeSize]byte{}, err
		}
		copy(packedHighBits[polynomialIndex*HighBitsEncodedSize:], encoded[:])
	}
	shake := sha3.NewSHAKE256()
	_, _ = shake.Write(key.PublicKey)
	var tr [TRSize]byte
	if _, err := io.ReadFull(shake, tr[:]); err != nil {
		return [CTildeSize]byte{}, err
	}
	shake.Reset()
	_, _ = shake.Write(tr[:])
	_, _ = shake.Write(message)
	var mu [64]byte
	if _, err := io.ReadFull(shake, mu[:]); err != nil {
		return [CTildeSize]byte{}, err
	}
	shake.Reset()
	_, _ = shake.Write(mu[:])
	_, _ = shake.Write(packedHighBits[:])
	var challenge [CTildeSize]byte
	if _, err := io.ReadFull(shake, challenge[:]); err != nil {
		return [CTildeSize]byte{}, err
	}
	return challenge, nil
}

func combineMode3PublicResponses(
	key protocol.ThresholdKeyID,
	message []byte,
	challenge [CTildeSize]byte,
	commitment VectorK,
	responses [L]SignedPoly,
) ([]byte, error) {
	expected, err := mode3CommitmentChallenge(key, message, commitment)
	if err != nil || expected != challenge {
		return nil, ErrInvalidMode3Signature
	}
	challengePolynomial, err := DeriveMode3Challenge(challenge)
	if err != nil {
		return nil, err
	}
	var normalized VectorL
	for polynomialIndex, response := range responses {
		for coefficientIndex, coefficient := range response {
			if coefficient <= -(Gamma1-Beta) || coefficient >= Gamma1-Beta {
				return nil, ErrInvalidZCoefficient
			}
			normalized[polynomialIndex][coefficientIndex] = Normalize(coefficient)
		}
	}
	var rho [32]byte
	copy(rho[:], key.PublicKey[:32])
	az, err := ComputePublicVector(rho, normalized, VectorK{})
	if err != nil {
		return nil, err
	}
	var hints HintVector
	offset := 32
	for polynomialIndex, polynomial := range az {
		var publicT1 Poly
		for coefficientIndex := 0; coefficientIndex < N; coefficientIndex += 4 {
			first := uint32(key.PublicKey[offset])
			second := uint32(key.PublicKey[offset+1])
			third := uint32(key.PublicKey[offset+2])
			fourth := uint32(key.PublicKey[offset+3])
			fifth := uint32(key.PublicKey[offset+4])
			publicT1[coefficientIndex] = Coefficient((first | second<<8) & 0x3ff)
			publicT1[coefficientIndex+1] = Coefficient((second>>2 | third<<6) & 0x3ff)
			publicT1[coefficientIndex+2] = Coefficient((third>>4 | fourth<<4) & 0x3ff)
			publicT1[coefficientIndex+3] = Coefficient((fourth>>6 | fifth<<2) & 0x3ff)
			offset += 5
		}
		verificationInput := Sub(polynomial, MultiplyPolynomials(challengePolynomial, ScalarMul(publicT1, 1<<D)))
		want := HighBits(commitment[polynomialIndex])
		got := HighBits(verificationInput)
		for coefficientIndex := range got {
			if got[coefficientIndex] == want[coefficientIndex] {
				continue
			}
			hints[polynomialIndex][coefficientIndex] = 1
		}
		corrected, err := UseHint(verificationInput, hints[polynomialIndex])
		if err != nil || corrected != want {
			return nil, ErrInvalidMode3Signature
		}
	}
	parts := SignatureParts{Challenge: challenge, Z: responses, Hints: hints}
	return AssembleVerifiedMode3Signature(key, message, parts)
}
