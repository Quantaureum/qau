// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

var ErrInvalidMode3Signature = errors.New("invalid threshold Dilithium3 v1 signature")

type SignatureParts struct {
	Challenge [CTildeSize]byte
	Z         [L]SignedPoly
	Hints     HintVector
}

func ParseMode3Signature(signature []byte) (SignatureParts, error) {
	if err := ValidateSignatureEncoding(signature); err != nil {
		return SignatureParts{}, err
	}
	var parts SignatureParts
	copy(parts.Challenge[:], signature[:CTildeSize])
	offset := CTildeSize
	for index := range parts.Z {
		polynomial, err := DecodeZ(signature[offset : offset+ZEncodedSize])
		if err != nil {
			return SignatureParts{}, err
		}
		parts.Z[index] = polynomial
		offset += ZEncodedSize
	}
	hints, err := DecodeHints(signature[offset:])
	if err != nil {
		return SignatureParts{}, err
	}
	parts.Hints = hints
	return parts, nil
}

func AssembleMode3Signature(parts SignatureParts) ([]byte, error) {
	signature := make([]byte, mode3.SignatureSize)
	copy(signature, parts.Challenge[:])
	offset := CTildeSize
	for _, polynomial := range parts.Z {
		encoded, err := EncodeZ(polynomial)
		if err != nil {
			return nil, err
		}
		copy(signature[offset:offset+ZEncodedSize], encoded[:])
		offset += ZEncodedSize
	}
	encodedHints, err := EncodeHints(parts.Hints)
	if err != nil {
		return nil, err
	}
	copy(signature[offset:], encodedHints[:])
	return signature, nil
}

func AssembleVerifiedMode3Signature(key protocol.ThresholdKeyID, message []byte, parts SignatureParts) ([]byte, error) {
	if key.Algorithm != qcrypto.SignatureAlgorithmDilithium3Legacy {
		return nil, ErrInvalidMode3Signature
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMode3Signature, err)
	}
	signature, err := AssembleMode3Signature(parts)
	if err != nil {
		return nil, err
	}
	if err := qcrypto.VerifySignatureForAlgorithm(key.Algorithm, key.PublicKey, message, nil, signature); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMode3Signature, err)
	}
	return signature, nil
}
