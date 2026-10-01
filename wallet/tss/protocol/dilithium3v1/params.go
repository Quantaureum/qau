// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"fmt"
	"math"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const (
	N          = 256
	Q          = 8380417
	K          = 6
	L          = 5
	Eta        = 4
	Tau        = 49
	Beta       = Tau * Eta
	Gamma1     = 1 << 19
	Gamma2     = 261888
	Omega      = 55
	D          = 13
	CTildeSize = 32
	TRSize     = 32
)

// Threshold-signing constants. These are deliberately separate from the CIRCL
// mode3 profile above: Eta and Beta keep their mode3 values for encoding and
// compatibility, while the replicated sharing changes the secret distribution.
const (
	// RSSComponentEta bounds every replicated component coefficient. It is
	// smaller than mode3's Eta because the signing secret is the sum of one
	// component from each replicated group.
	RSSComponentEta = 1

	// RSSAggregateBound bounds one aggregate secret coefficient. It is the
	// component bound times the number of three-member groups, C(6,3) = 20.
	RSSAggregateBound = 20 * RSSComponentEta

	// BetaEffective is the rejection bound of the retired pre-R57 global norm
	// checks. The signing path no longer uses it; it is retained because the
	// retired arithmetic tests reference the two bounds derived from it.
	BetaEffective = Tau * RSSAggregateBound

	// NormBoundZ is the retired pre-R57 rejection bound for ||z||inf.
	NormBoundZ = Gamma1 - BetaEffective

	// NormBoundR0 is the retired pre-R57 rejection bound for the residue of
	// w - c*s2.
	NormBoundR0 = Gamma2 - BetaEffective
)

// Threshold-signing randomness parameters (R57). These are the pinned
// hyperball parameters of the revised signing construction; the derivation,
// the re-verification against the construction reference, and the per-key
// caveats are recorded in
// docs/superpowers/specs/2026-09-24-qau-dilithium3-v1-signing-mpc.md.
const (
	// SigningRandomnessPhi is the smoothing factor phi of the rejection lemma.
	SigningRandomnessPhi = 8

	// SigningRandomnessNu expands the first L blocks of the sampled ball point.
	SigningRandomnessNu = 6

	// SigningRandomnessExponent is log2(1/p), where p is the per-slot
	// acceptance probability of all active signers.
	SigningRandomnessExponent = 3.3

	// SigningRandomnessRadius is the accept radius r of the per-party HRej test.
	SigningRandomnessRadius = 407958.8

	// SigningRandomnessSampleRadius is the sampling radius
	// r' = M^(1/(N*(L+K))) * r.
	SigningRandomnessSampleRadius = 408041.6

	// SigningShiftBound is the per-party challenge-shift bound
	// B = 1.3 * sqrt((K + L/nu^2) * N * 5) * sigma_eta * sqrt(Tau) with
	// sigma_eta = sqrt(((2*RSSComponentEta+1)^2 - 1) / 12).
	SigningShiftBound = 658.64

	// SigningParallelSlots is J, the number of parallel slots per signing
	// request that gives one execution a success probability of at least 1/2.
	SigningParallelSlots = 11
)

// SigningRandomnessDivergence returns M = (1/p)^(1/T), the smooth Renyi
// divergence bound of the per-party rejection at the pinned parameters.
func SigningRandomnessDivergence() float64 {
	return math.Pow(2, SigningRandomnessExponent/float64(protocol.Dilithium3V1Profile().Threshold))
}

var (
	ErrInvalidParameters   = errors.New("invalid Dilithium3 v1 parameters")
	ErrInvalidEncodingSize = errors.New("invalid Dilithium3 v1 encoding size")
)

// Parameters contains the immutable CIRCL mode3 and QAU threshold profile.
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

// StandardParameters returns the immutable qau-threshold-dilithium3-v1 profile.
func StandardParameters() Parameters {
	return Parameters{
		N: N, Q: Q, K: K, L: L, Eta: Eta, Tau: Tau, Beta: Beta,
		Gamma1: Gamma1, Gamma2: Gamma2, Omega: Omega, D: D,
		CTildeSize: CTildeSize, TRSize: TRSize,
		PublicKeySize: mode3.PublicKeySize, PrivateKeySize: mode3.PrivateKeySize,
		SignatureSize: mode3.SignatureSize, Participants: 6, Threshold: 4, MaxCorrupt: 2,
	}
}

// Validate rejects any parameter set that differs from the fixed profile.
func (parameters Parameters) Validate() error {
	if parameters != StandardParameters() {
		return ErrInvalidParameters
	}
	return nil
}

func validateEncodingSize(kind string, encoded []byte, want int) error {
	if len(encoded) != want {
		return fmt.Errorf("%w: %s length %d, want %d", ErrInvalidEncodingSize, kind, len(encoded), want)
	}
	return nil
}

// ValidatePublicKeyEncoding rejects non-mode3 public-key sizes.
func ValidatePublicKeyEncoding(publicKey []byte) error {
	return validateEncodingSize("public key", publicKey, mode3.PublicKeySize)
}

// ValidatePrivateKeyEncoding rejects non-mode3 private-key sizes.
func ValidatePrivateKeyEncoding(privateKey []byte) error {
	return validateEncodingSize("private key", privateKey, mode3.PrivateKeySize)
}

// ValidateSignatureEncoding rejects non-mode3 signature sizes.
func ValidateSignatureEncoding(signature []byte) error {
	return validateEncodingSize("signature", signature, mode3.SignatureSize)
}
