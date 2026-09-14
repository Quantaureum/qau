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
	"encoding/binary"
	"fmt"
	"runtime"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	logging "github.com/quantaureum/qau/log"
)

// Sign signs a message using the private key and returns the signature
// SECURITY FIX Q-B-004 / CRYPTO-R9-H5: Panic recovery now distinguishes
// input-validation errors (returned as normal errors) from memory corruption
// / library tampering (which trigger node shutdown via logging.Fatal).
// R9 audit re-confirmed this recovery is in place and covers the full
// Sign path; the Q-B-004 marker is the original fix, R9-H5 is the audit
// round-9 verification marker.
func Sign(privateKey *PrivateKey, message []byte) ([]byte, error) {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	pkIsNil := privateKey == nil
	if subtle.ConstantTimeEq(boolToInt32(pkIsNil), 1) == 1 {
		return nil, ErrInvalidPrivateKey
	}
	pkKeyIsNil := privateKey.key == nil
	if subtle.ConstantTimeEq(boolToInt32(pkKeyIsNil), 1) == 1 {
		return nil, ErrInvalidPrivateKey
	}

	signature := make([]byte, Dilithium3SignatureSize)

	var panicErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicErr = fmt.Errorf("signing panic: %v", r)
			}
		}()
		mode3.SignTo(privateKey.key, message, signature)
	}()
	// Prevent GC from collecting signature buffer before SignTo completes
	// This ensures the memory is valid during the entire signing operation
	runtime.KeepAlive(signature)
	if panicErr != nil {
		// FIX: Zero the signature buffer on panic — it may contain
		// partial key-derived data written before the panic.
		// R41-CR-003 FIX: Use zeroBytesSecure (three-pass wipe) instead of
		// zeroBytes (single-pass), consistent with kyber.go error paths.
		zeroBytesSecure(signature)
		// SECURITY FIX Q-B-004 / CRYPTO-R9-H5 / CRITICAL FIX: Remove Fatal() call that creates DoS vector.
		// Panic in signing path should return error, NOT shut down the node.
		// An attacker can trigger ANY panic to shut down all validator nodes.
		// Replace string-matching classification with proper error return.
		logging.Global().Error("Dilithium3 signing panic - treating as invalid key",
			map[string]any{
				"category": "SECURITY",
				"error":    panicErr.Error(),
			})
		return nil, fmt.Errorf("%w: signing library panic (key may be corrupted)", ErrInvalidPrivateKey)
	}
	// R30-P3 FIX: Caller responsibility for signature zeroing.
	// The returned signature byte slice contains cryptographic material derived
	// from the private key. The caller MUST zeroize it after use:
	//   sig, _ := Sign(privKey, msg)
	//   defer crypto.ZeroBytesSecure(sig)
	// Failure to zero allows signature reuse via memory dumps or cold boot attacks.
	return signature, nil
}

// Sign is a convenience method to sign a message with a PrivateKey.
// This method satisfies the types.QuantumSigner interface.
func (k *PrivateKey) Sign(message []byte) ([]byte, error) {
	return Sign(k, message)
}

// SignWithDomain signs a message with a domain separator prepended.
//
// AUDIT (2026) CRY-06 FIX: The crypto layer's Sign function signs
// arbitrary bytes without domain separation, relying on callers to include
// their own domain tags. This convenience function makes domain separation
// easier and less error-prone by constructing a length-prefixed message:
//
//	uint32(len(domain)) || domain || uint32(len(message)) || message
//
// Both length prefixes prevent ambiguity between (domain, message) pairs
// that concatenate to the same byte string. Length-prefixing BOTH fields
// (rather than only the message) makes the encoding self-describing: a
// decoder can recover (domain, message) from the byte stream alone without
// out-of-band knowledge of where `domain` ends.
//
// Existing callers that already construct their own domain-separated messages
// (e.g., consensus/voting.go with QUANTAUREUM_VOTE_V2) do NOT need to migrate —
// this function is for new callers and as a recommended pattern.
//
// CRYPTO- (2026-07-20) FIX: Previously the encoding was
// `domain || len(message) || message`, which only length-prefixed the
// message. Without a domain length prefix, a variable-length domain could
// create parsing ambiguity: a decoder that does not know the domain
// length ahead of time could misread the boundary between `domain` and
// `len(message)`, especially if an attacker can influence the domain
// bytes. The fix adds `uint32(len(domain))` at the front so the entire
// encoding is unambiguously self-describing.
func SignWithDomain(privateKey *PrivateKey, domain, message []byte) ([]byte, error) {
	signed, err := Sign(privateKey, buildDomainSeparatedMessage(domain, message))
	if err != nil {
		return nil, err
	}
	return signed, nil
}

// buildDomainSeparatedMessage constructs a self-describing length-prefixed
// domain-separated message:
//
//	uint32(len(domain)) || domain || uint32(len(message)) || message
//
// Both length prefixes are 4-byte big-endian. This encoding is unambiguous:
// given only the byte stream, a decoder can recover (domain, message) without
// any out-of-band knowledge of field lengths.
//
// CRYPTO- (2026-07-20) FIX: Added uint32(len(domain)) prefix so the
// encoding is self-describing. The previous encoding `domain || len(message)
// || message` relied on the decoder knowing the domain length out-of-band,
// which is fragile if domain is ever variable-length or attacker-influenced.
func buildDomainSeparatedMessage(domain, message []byte) []byte {
	var domainLenBuf [4]byte
	var msgLenBuf [4]byte
	binary.BigEndian.PutUint32(domainLenBuf[:], uint32(len(domain)))
	binary.BigEndian.PutUint32(msgLenBuf[:], uint32(len(message)))
	result := make([]byte, 0, 4+len(domain)+4+len(message))
	result = append(result, domainLenBuf[:]...)
	result = append(result, domain...)
	result = append(result, msgLenBuf[:]...)
	result = append(result, message...)
	return result
}
