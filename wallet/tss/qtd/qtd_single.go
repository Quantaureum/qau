// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"fmt"
	"log"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// verifyDilithium3 runs mode3.Verify under recover.
//
// R5-02 (2026-10-21 fifth-round audit): mode3.Verify dereferences the key it is
// handed, so a nil *mode3.PublicKey panics — that is the one input shape that
// panicked in TestR5_02_CirclAndQTDVerifierPanicProbe, while right-length but
// structurally malformed keys and signatures made Verify return false without
// panicking. A nil key is a caller-state error, not remote input, so this guard
// is defense in depth: it normalizes the crash into a verification failure
// instead of letting it take down the verifying process. It mirrors
// crypto.Verify (audit-fix CR-1) and the R4-04 helpers in wallet/tss/signing.go.
// The log line never echoes key or signature material.
func verifyDilithium3(pk *mode3.PublicKey, message, sig []byte) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: GMQTD single verify rejected by panic guard (R5-02): %v", r)
			ok = false
		}
	}()
	return mode3.Verify(pk, message, sig)
}

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
	if !verifyDilithium3(pk, message, sig) {
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
	if pk == nil {
		return false, fmt.Errorf("GMQTD_SingleVerify: pk must not be nil")
	}
	if len(sig) != mode3.SignatureSize {
		return false, fmt.Errorf("GMQTD_SingleVerify: invalid signature size %d, expected %d", len(sig), mode3.SignatureSize)
	}
	// R5-02: verify under recover — a malformed key must not crash the verifier.
	return verifyDilithium3(pk, message, sig), nil
}
