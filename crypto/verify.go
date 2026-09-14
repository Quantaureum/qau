// Quantaureum Node source, version 1.0.0.
// Package crypto provides cryptographic primitives for the Quantaureum blockchain.
// It implements post-quantum cryptography using Dilithium3 for digital signatures.
//
// =============================================================================
// SHARED INTERFACE WARNING - DO NOT MODIFY WITHOUT SYNCING WITH WALLET
// =============================================================================
// This file implements a SHARED INTERFACE with Quantaureum Wallet
// (app/scripts/lib/quantum-crypto/dilithium3.ts).
// Any changes to signature sizes, key formats, or serialization MUST be
// synchronized with the Wallet implementation.
//
// Shared parameters:
//   - Dilithium3PublicKeySize: 1952 bytes
//   - Dilithium3PrivateKeySize: 4000 bytes
//   - Dilithium3SignatureSize: 3293 bytes
//
// Wallet implementation: the quantaureum-wallet repo
// =============================================================================
package crypto

import (
	"crypto/subtle"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	logging "github.com/quantaureum/qau/log"
)

// Signature verification failure reason strings.
//
// R33 P3-11 FIX (2026-07-28): Centralized reason constants so all
// signature-verification paths (crypto.Verify, consensus.VerifyAggregate,
// consensus.Checkpoint.Verify, etc.) use a consistent vocabulary for
// security logging. SIEM/log-analysis tools can grep for these exact
// strings without worrying about per-call-site wording drift.
//
// Add new reasons here rather than inventing ad-hoc strings at call sites.
const (
	// ReasonNilPublicKey indicates the caller passed a nil *PublicKey.
	ReasonNilPublicKey = "nil_public_key"
	// ReasonNilInternalKey indicates the PublicKey wrapper was non-nil but
	// its internal circl key handle was nil (corrupted or uninitialized).
	ReasonNilInternalKey = "nil_internal_key"
	// ReasonWrongPublicKeyLength indicates the serialized public key bytes
	// did not match Dilithium3PublicKeySize (1952).
	ReasonWrongPublicKeyLength = "wrong_public_key_length"
	// ReasonWrongSignatureLength indicates the signature did not match
	// Dilithium3SignatureSize (3293).
	ReasonWrongSignatureLength = "wrong_signature_length"
	// ReasonVerificationFailed indicates mode3.Verify returned false — the
	// signature is cryptographically invalid (forged or corrupted).
	ReasonVerificationFailed = "verification_failed"
	// ReasonVerificationPanic indicates mode3.Verify panicked, typically
	// due to malformed input that bypassed length checks or due to memory
	// corruption. Always logged at Error level.
	ReasonVerificationPanic = "verification_panic"
	// ReasonDuplicatePublicKey indicates the same public key appeared more
	// than once in an aggregate verification batch (CRND-08 defense).
	ReasonDuplicatePublicKey = "duplicate_public_key"
	// ReasonCommitmentMismatch indicates the aggregate signature's binding
	// commitment did not match the expected value for the given
	// publicKeys+message (CRND-08 defense).
	ReasonCommitmentMismatch = "commitment_mismatch"
	// ReasonSignatureCountMismatch indicates the number of signatures in
	// an aggregate did not match the number of public keys.
	ReasonSignatureCountMismatch = "signature_count_mismatch"
	// ReasonZeroPublicKey indicates an all-zero Dilithium3 public key
	// (R37-P0-03). With t1=0 the verification equation degenerates to
	// w' = A·z, allowing keyless signature forgery with (z=0, h=0).
	ReasonZeroPublicKey = "zero_public_key"
)

// IsZeroPublicKeyBytes reports, in constant time, whether b is an all-zero
// Dilithium3 public key. An all-zero public key has t1=0, which degenerates
// the Dilithium verification equation w' = A·z − c·t1·2^d to w' = A·z —
// an attacker can then forge a valid signature for ANY message without the
// private key by choosing z=0, h=0 and precomputing c = H(μ ‖ Encode(0))
// (R37-P0-03, empirically verified against mode3.Verify). circl does NOT
// reject degenerate keys, so every entry point must.
//
// Returns false for nil or wrong-length input (those are rejected by the
// length checks at each call site).
func IsZeroPublicKeyBytes(b []byte) bool {
	if len(b) != Dilithium3PublicKeySize {
		return false
	}
	var zero [Dilithium3PublicKeySize]byte
	return subtle.ConstantTimeCompare(b, zero[:]) == 1
}

// Verify verifies a signature against a message using the public key.
// audit-fix CR-1: Wrap mode3.Verify in recover to prevent panic from
// propagating. Malformed signatures must not crash the node.
//
// R32-P2-04 FIX (2026-07-28): Added defense-in-depth public key byte-length
// validation and structured logging for each failure path. Previously, Verify
// returned false without any indication of WHY verification failed, making it
// hard to distinguish between "nil key", "wrong signature length", and
// "verification failed" — a concern flagged in the R32 audit. The byte-length
// check on the serialized public key guards against any code path that might
// construct a PublicKey bypassing PublicKeyFromBytes (which already validates
// length in constant time).
//
// R33 P3-11 FIX (2026-07-28): Replaced ad-hoc reason strings with the
// centralized Reason* constants above so SIEM/log-analysis tools can grep
// for a single canonical vocabulary across all verification paths.
func Verify(publicKey *PublicKey, message, signature []byte) bool {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	pkIsNil := publicKey == nil
	if subtle.ConstantTimeEq(boolToInt32(pkIsNil), 1) == 1 {
		// R32-P2-04: Structured logging for security monitoring.
		// R33 P3-11 FIX: use centralized ReasonNilPublicKey constant.
		logging.Global().Warn("Dilithium3 Verify rejected: nil public key", map[string]any{
			"category": "SECURITY",
			"reason":   ReasonNilPublicKey,
		})
		return false
	}
	pkKeyIsNil := publicKey.key == nil
	if subtle.ConstantTimeEq(boolToInt32(pkKeyIsNil), 1) == 1 {
		// R32-P2-04: Structured logging for security monitoring.
		// R33 P3-11 FIX: use centralized ReasonNilInternalKey constant.
		logging.Global().Warn("Dilithium3 Verify rejected: nil internal key", map[string]any{
			"category": "SECURITY",
			"reason":   ReasonNilInternalKey,
		})
		return false
	}

	// R32-P2-04: Defense-in-depth — validate the serialized public key length.
	// PublicKeyFromBytes already enforces this at construction time, but this
	// check guards against any future code path that constructs a PublicKey
	// bypassing PublicKeyFromBytes (e.g. via reflection or unsafe pointer
	// manipulation). An attacker-supplied wrong-length public key could
	// trigger out-of-bounds reads in circl's mode3.Verify internals.
	// R33 P3-11 FIX: use centralized ReasonWrongPublicKeyLength constant.
	pkBytes := publicKey.Bytes()
	if subtle.ConstantTimeEq(int32(len(pkBytes)), int32(Dilithium3PublicKeySize)) != 1 {
		logging.Global().Warn("Dilithium3 Verify rejected: wrong public key length", map[string]any{
			"category": "SECURITY",
			"reason":   ReasonWrongPublicKeyLength,
		})
		return false
	}

	// R37-P0-03 FIX (2026-07-30): Reject all-zero public keys. With t1=0 the
	// verification equation degenerates to w' = A·z and mode3.Verify accepts
	// keyless forgeries (z=0, h=0). PublicKeyFromBytes is the primary gate;
	// this is defense-in-depth for any PublicKey constructed by other paths.
	if IsZeroPublicKeyBytes(pkBytes) {
		logging.Global().Warn("Dilithium3 Verify rejected: all-zero public key (keyless forgery vector)", map[string]any{
			"category": "SECURITY",
			"reason":   ReasonZeroPublicKey,
		})
		return false
	}

	// Constant-time signature length check to prevent timing attacks
	// R33 P3-11 FIX: use centralized ReasonWrongSignatureLength constant.
	if subtle.ConstantTimeEq(int32(len(signature)), int32(Dilithium3SignatureSize)) != 1 {
		// R32-P2-04: Structured logging for security monitoring.
		logging.Global().Warn("Dilithium3 Verify rejected: wrong signature length", map[string]any{
			"category": "SECURITY",
			"reason":   ReasonWrongSignatureLength,
		})
		return false
	}

	// audit-fix CR-1: recover prevents panics from malformed signatures crashing the node
	// audit-fix HIGH-C4: Added logging for panic detection (security monitoring)
	// HIGH-C4 FIX: Wrap entire verification including pubKey access in recover-protected func
	var ok bool
	var panicErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicErr = fmt.Errorf("signature verification panic: %v (possible attack or memory corruption)", r)
				ok = false
			}
		}()
		// All operations that could panic must be inside this protected function
		ok = mode3.Verify(publicKey.key, message, signature)
	}()
	if panicErr != nil {
		// R26-Crypto-H3 FIX: Actually log the panic error for security monitoring
		// R40-L5 FIX: Use structured security logging for SIEM integration.
		// R33 P3-11 FIX: use centralized ReasonVerificationPanic constant.
		logging.Global().Error("Signature verification panic: possible attack or memory corruption", map[string]any{
			"category": "SECURITY",
			"reason":   ReasonVerificationPanic,
			"error":    panicErr.Error(),
		})
	}
	return ok
}

// VerifyWithKey is a convenience method to verify a signature with a PublicKey
func (k *PublicKey) Verify(message, signature []byte) bool {
	return Verify(k, message, signature)
}

// VerifyWithDomain verifies a signature that was created with SignWithDomain.
//
// AUDIT (2026) CRY-06 FIX: Corresponds to SignWithDomain — reconstructs
// the same length-prefixed domain-separated message before verifying.
// Callers MUST use the same domain separator that was used for signing.
func VerifyWithDomain(publicKey *PublicKey, domain, message, signature []byte) bool {
	return Verify(publicKey, buildDomainSeparatedMessage(domain, message), signature)
}

// IsLegacySignature checks if a signature is a legacy secp256k1 (ECDSA) signature.
// Legacy signatures are 65 bytes: R (32) || S (32) || V (1)
// Dilithium3 signatures are 3293 bytes.
// Legacy secp256k1 (ECDSA) signatures are permanently disabled for quantum security.
// All transactions must use Dilithium3 quantum-resistant signatures.
