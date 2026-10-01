// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var (
	ErrUnsupportedSignatureAlgorithm = errors.New("unsupported signature algorithm")
	ErrSignatureVerificationPanic    = errors.New("signature verification panic")
)

// SignatureAlgorithm identifies the signature encoding and verification rules.
type SignatureAlgorithm uint16

const (
	SignatureAlgorithmUnknown SignatureAlgorithm = iota
	SignatureAlgorithmDilithium3Legacy
	SignatureAlgorithmMLDSA65
)

// Supported reports whether the algorithm has a verifier in this binary.
func (algorithm SignatureAlgorithm) Supported() bool {
	switch algorithm {
	case SignatureAlgorithmDilithium3Legacy, SignatureAlgorithmMLDSA65:
		return true
	default:
		return false
	}
}

// PublicKeySize returns the canonical encoded public-key size.
func (algorithm SignatureAlgorithm) PublicKeySize() int {
	switch algorithm {
	case SignatureAlgorithmDilithium3Legacy:
		return mode3.PublicKeySize
	case SignatureAlgorithmMLDSA65:
		return mldsa65.PublicKeySize
	default:
		return 0
	}
}

// SignatureSize returns the canonical encoded signature size.
func (algorithm SignatureAlgorithm) SignatureSize() int {
	switch algorithm {
	case SignatureAlgorithmDilithium3Legacy:
		return mode3.SignatureSize
	case SignatureAlgorithmMLDSA65:
		return mldsa65.SignatureSize
	default:
		return 0
	}
}

func (algorithm SignatureAlgorithm) String() string {
	switch algorithm {
	case SignatureAlgorithmDilithium3Legacy:
		return "dilithium3-legacy"
	case SignatureAlgorithmMLDSA65:
		return "ml-dsa-65"
	default:
		return "unknown"
	}
}

// VerifySignatureForAlgorithm verifies a signature using explicit algorithm
// metadata rather than inferring the algorithm from encoded lengths.
func VerifySignatureForAlgorithm(
	algorithm SignatureAlgorithm,
	publicKey []byte,
	message []byte,
	context []byte,
	signature []byte,
) (err error) {
	if !algorithm.Supported() {
		return fmt.Errorf("%w: %d", ErrUnsupportedSignatureAlgorithm, algorithm)
	}
	if len(publicKey) != algorithm.PublicKeySize() {
		return fmt.Errorf("%w: %s public key length", ErrInvalidPublicKey, algorithm)
	}
	if len(signature) != algorithm.SignatureSize() {
		return fmt.Errorf("%w: %s signature length", ErrInvalidSignature, algorithm)
	}
	if IsZeroPublicKeyBytes(publicKey) {
		return fmt.Errorf("%w: %s public key is zero", ErrInvalidPublicKey, algorithm)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: %s", ErrSignatureVerificationPanic, algorithm)
		}
	}()

	switch algorithm {
	case SignatureAlgorithmDilithium3Legacy:
		if len(context) != 0 {
			return fmt.Errorf("%w: legacy signatures do not support context", ErrInvalidSignature)
		}
		var encoded [mode3.PublicKeySize]byte
		copy(encoded[:], publicKey)
		var key mode3.PublicKey
		key.Unpack(&encoded)
		if !mode3.Verify(&key, message, signature) {
			return ErrInvalidSignature
		}
	case SignatureAlgorithmMLDSA65:
		var encoded [mldsa65.PublicKeySize]byte
		copy(encoded[:], publicKey)
		var key mldsa65.PublicKey
		key.Unpack(&encoded)
		if !mldsa65.Verify(&key, message, context, signature) {
			return ErrInvalidSignature
		}
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedSignatureAlgorithm, algorithm)
	}

	return nil
}
