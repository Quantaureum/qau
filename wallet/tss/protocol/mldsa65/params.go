// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"fmt"

	circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var (
	ErrInvalidParameters   = errors.New("invalid ML-DSA-65 parameters")
	ErrInvalidEncodingSize = errors.New("invalid ML-DSA-65 encoding size")
)

// Parameters contains the fixed FIPS 204 ML-DSA-65 and QAU profile values.
type Parameters struct {
	N              int
	Q              int
	K              int
	L              int
	Eta            int
	Tau            int
	Beta           int
	Gamma1         int
	Gamma2         int
	Omega          int
	D              int
	CTildeSize     int
	TRSize         int
	PublicKeySize  int
	PrivateKeySize int
	SignatureSize  int
	Participants   int
	Threshold      int
	MaxCorrupt     int
}

// StandardParameters returns the immutable qau-tmldsa65-v1 profile.
func StandardParameters() Parameters {
	return Parameters{
		N:              256,
		Q:              8380417,
		K:              6,
		L:              5,
		Eta:            4,
		Tau:            49,
		Beta:           196,
		Gamma1:         1 << 19,
		Gamma2:         261888,
		Omega:          55,
		D:              13,
		CTildeSize:     48,
		TRSize:         64,
		PublicKeySize:  circlmldsa65.PublicKeySize,
		PrivateKeySize: circlmldsa65.PrivateKeySize,
		SignatureSize:  circlmldsa65.SignatureSize,
		Participants:   6,
		Threshold:      4,
		MaxCorrupt:     2,
	}
}

// Validate rejects any parameter set that differs from qau-tmldsa65-v1.
func (parameters Parameters) Validate() error {
	if parameters != StandardParameters() {
		return ErrInvalidParameters
	}
	return nil
}

// ValidatePublicKeyEncoding rejects non-standard ML-DSA-65 public-key sizes.
func ValidatePublicKeyEncoding(publicKey []byte) error {
	want := StandardParameters().PublicKeySize
	if len(publicKey) != want {
		return fmt.Errorf("%w: public key length %d, want %d", ErrInvalidEncodingSize, len(publicKey), want)
	}
	return nil
}

// ValidateSignatureEncoding rejects non-standard ML-DSA-65 signature sizes.
func ValidateSignatureEncoding(signature []byte) error {
	want := StandardParameters().SignatureSize
	if len(signature) != want {
		return fmt.Errorf("%w: signature length %d, want %d", ErrInvalidEncodingSize, len(signature), want)
	}
	return nil
}
