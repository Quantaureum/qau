// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func GMQTD_SingleSign(sk *mode3.PrivateKey, pk *mode3.PublicKey, message []byte) ([]byte, error) {
	// L4-016 FIX: Validate pk and sk are non-nil to fail fast on misuse.
	// A nil sk would panic inside mode3.SignTo, and a nil pk indicates a
	// caller error.
	// L5-016 CONFIRMED FIXED: pk nil check added in L4-016.
	if pk == nil {
		return nil, fmt.Errorf("GMQTD_SingleSign: pk must not be nil")
	}
	if sk == nil {
		return nil, fmt.Errorf("GMQTD_SingleSign: sk must not be nil")
	}
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, message, sig)
	// FIX: Use pk for post-sign verification. This ensures the pk
	// parameter is actually used and that sk and pk are a matching key pair.
	// If they don't match, the signature will fail verification and an error
	// is returned, preventing the caller from using an invalid key pair.
	if !mode3.Verify(pk, message, sig) {
		// CRYPTO-FIX: zero the failed signature buffer to enforce
		// minimum residency of sensitive material (defense-in-depth). The
		// buffer holds a valid Dilithium3 signature produced from sk; even
		// though the caller already holds sk, leaving the signature in heap
		// memory until GC broadens the exposure surface.
		SecurelyZeroMemory(sig)
		return nil, fmt.Errorf("GMQTD_SingleSign: post-sign verification failed (sk and pk may not be a matching pair)")
	}
	return sig, nil
}

func GMQTD_SingleVerify(pk *mode3.PublicKey, message, sig []byte) (bool, error) {
	if len(sig) != mode3.SignatureSize {
		return false, fmt.Errorf("GMQTD_SingleVerify: invalid signature size %d, expected %d", len(sig), mode3.SignatureSize)
	}
	return mode3.Verify(pk, message, sig), nil
}
