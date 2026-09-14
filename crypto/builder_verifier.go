// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"fmt"
)

// P4-3 AUDIT NOTE (#nosec directives): Every `#nosec` / `#nolint:gosec`
// directive in the security-critical packages touched by this audit pass
// (crypto, qzkp, quantum, qvm, consensus, economics, p2p, rpc) carries an
// inline justification explaining why the flagged issue is a false positive
// or intentionally accepted (e.g. G115 integer conversions where the value
// range is provably bounded, G104 ignored errors on non-critical best-effort
// operations). They have been spot-checked during this review. Do NOT add a
// bare `#nosec` without a `-- reason` comment — un-annotated suppressions
// mask real issues and will be rejected by review.

// BuilderSignatureVerifier verifies builder signatures without any caching.
//
// P4-1 AUDIT NOTE (no SignatureCache — intentional): Unlike the hot signing /
// verification paths (which use SignatureCache to avoid re-verifying repeated
// block signatures), the BuilderSignatureVerifier deliberately does NOT cache.
// Builder signatures are one-off verifications performed during block
// construction/validation where the (pubKey, message, signature) tuples are
// effectively unique per block, so a cache would provide negligible hit rate
// while adding memory pressure and cache-invalidation complexity. Verification
// here is also a security-critical check where a stale cache entry could
// wrongly accept a signature; skipping the cache keeps the verification path
// simple and always-fresh. This is intentional, not an oversight.
type BuilderSignatureVerifier struct{}

func NewBuilderSignatureVerifier() *BuilderSignatureVerifier {
	return &BuilderSignatureVerifier{}
}

func (v *BuilderSignatureVerifier) Verify(pubKey []byte, message []byte, signature []byte) error {
	// FIX: Removed early len() returns that leak length info via timing.
	// PublicKeyFromBytes performs a constant-time public key length check
	// (subtle.ConstantTimeEq), and Verify performs a constant-time signature
	// length check (subtle.ConstantTimeEq). Relying on these downstream
	// constant-time checks eliminates the timing side channel.
	publicKey, err := PublicKeyFromBytes(pubKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	if !Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}

	return nil
}
