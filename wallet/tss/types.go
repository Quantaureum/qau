// Quantaureum Node source, version 1.0.0.
package tss

import (
	"errors"

	"github.com/quantaureum/qau/crypto"
)

var (
	ErrInvalidConfig               = errors.New("tss: invalid config")
	ErrInvalidShare                = errors.New("tss: invalid share")
	ErrShareVerification           = errors.New("tss: share verification failed")
	ErrInsufficientShares          = errors.New("tss: insufficient shares")
	ErrInvalidShareIndex           = errors.New("tss: invalid share index")
	ErrShareNotFound               = errors.New("tss: share not found")
	ErrCombineFailed               = errors.New("tss: combine failed")
	ErrRefreshFailed               = errors.New("tss: refresh failed")
	ErrCannotRemoveShare           = errors.New("tss: cannot remove share, would drop below threshold")
	ErrSignatureVerificationFailed = errors.New("tss: signature verification failed")
)

func deriveKeyFromSeed(seed []byte) (*crypto.PrivateKey, error) {
	keyPair, err := crypto.GenerateKeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	return keyPair.Private, nil
}

type KeyShare struct {
	Index              int
	Share              []byte
	PublicKey          []byte
	VerificationVector [][]byte
}

type PartialSignature struct {
	Index     int
	Signature []byte
	// Private indicates that Signature contains the combined z0 contribution
	// (Z0Share = λ_i·c·(t0_i - s2_i)) that MUST NOT be broadcast.
	// This is signature-derived (a function of the challenge and key shares),
	// NOT a raw key share — but broadcasting it could leak the signing
	// transcript before the signature is finalized.
	// AUDIT (2026) TSS-FIX (CRITICAL): Replaces the old separate
	// Cs2Share/Ct0Share fields (λ_i·c·s2_i / λ_i·c·t0_i) which allowed the
	// aggregator to invert the challenge polynomial c in the NTT ring and
	// recover s2 and t0 separately, then s1 via A·s1 = t - s2, reconstructing
	// the FULL Dilithium3 private key. The new Z0Share combines the two
	// contributions so the aggregator cannot decompose them (residual risk:
	// s1 recovery only, not full key). The even older ScShare field leaked
	// λ_i·s1_i·c directly.
	// Transport layers MUST call ValidateForBroadcast before sending to any
	// peer other than the aggregator.
	Private bool
}

// ValidateForBroadcast returns an error if this PartialSignature contains
// private masked contributions that must not be broadcast.
func (ps *PartialSignature) ValidateForBroadcast() error {
	if ps != nil && ps.Private {
		return errors.New("tss: partial signature contains private masked contributions and must not be broadcast")
	}
	return nil
}
