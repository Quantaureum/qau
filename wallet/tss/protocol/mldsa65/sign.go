// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"fmt"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

var ErrAssembledSignatureInvalid = errors.New("assembled ML-DSA-65 signature is invalid")

// SignatureParts contains exactly the public values encoded in a standard signature.
type SignatureParts struct {
	CTilde [48]byte
	Z      [5]SignedPoly
	Hints  HintVector
}

// ParseStandardSignature strictly decodes a standard ML-DSA-65 signature.
func ParseStandardSignature(signature []byte) (SignatureParts, error) {
	if err := ValidateSignatureEncoding(signature); err != nil {
		return SignatureParts{}, err
	}
	var parts SignatureParts
	copy(parts.CTilde[:], signature[:len(parts.CTilde)])
	offset := len(parts.CTilde)
	for index := range parts.Z {
		decoded, err := DecodeZ(signature[offset : offset+zEncodedSize])
		if err != nil {
			return SignatureParts{}, err
		}
		parts.Z[index] = decoded
		offset += zEncodedSize
	}
	hints, err := DecodeHints(signature[offset:])
	if err != nil {
		return SignatureParts{}, err
	}
	parts.Hints = hints
	return parts, nil
}

// AssembleStandardSignature encodes public signature parts in FIPS 204 order.
func AssembleStandardSignature(parts SignatureParts) ([]byte, error) {
	signature := make([]byte, StandardParameters().SignatureSize)
	copy(signature, parts.CTilde[:])
	offset := len(parts.CTilde)
	for index := range parts.Z {
		encoded, err := EncodeZ(parts.Z[index])
		if err != nil {
			return nil, err
		}
		copy(signature[offset:offset+len(encoded)], encoded[:])
		offset += len(encoded)
	}
	encodedHints, err := EncodeHints(parts.Hints)
	if err != nil {
		return nil, err
	}
	copy(signature[offset:], encodedHints[:])
	return signature, nil
}

// AssembleVerifiedSignature assembles and verifies a signature before release.
func AssembleVerifiedSignature(
	key protocol.ThresholdKeyID,
	message []byte,
	context []byte,
	parts SignatureParts,
) ([]byte, error) {
	if err := key.Validate(); err != nil || key.Algorithm != qcrypto.SignatureAlgorithmMLDSA65 {
		return nil, fmt.Errorf("%w: invalid key", ErrAssembledSignatureInvalid)
	}
	signature, err := AssembleStandardSignature(parts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAssembledSignatureInvalid, err)
	}
	if err := qcrypto.VerifySignatureForAlgorithm(
		key.Algorithm,
		key.PublicKey,
		message,
		context,
		signature,
	); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAssembledSignatureInvalid, err)
	}
	return signature, nil
}
