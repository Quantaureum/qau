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

// Parameters contains the CIRCL mode3 constants and the v1 CNF-RSS committee
// shape (Participants, Threshold, MaxCorrupt).
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

// StandardParameters returns the canonical six-of-six committee row of the
// qau-threshold-dilithium3-v1 profile (R76a: one row of the derived family).
func StandardParameters() Parameters {
	return ParametersForParticipants(6)
}

// Committee size family (R76a): the CNF group size is floor(C/3)+1 and the
// threshold is ceil(2C/3); MaxCorrupt stays 2, the deployed threat model.
const (
	MinCommitteeParticipants = 6
	MaxCommitteeParticipants = 12
)

// R76b: the threshold-signing MPC is parameterized per committee size. The
// family derivation (exponent grid search plus Monte-Carlo estimation of the
// public combine-check probabilities over the accepted-randomness model) is
// recorded in docs/superpowers/specs/2026-10-01-qau-dilithium3-v1-dynamic-committee.md
// ("R76b — signing-MPC parameter family"). Only the rows the derivation
// shows to be operational are pinned: C ∈ {6, 7}. C = 8 was measured at
// J ≈ 265 parallel slots (~2 MB per party per request — not operational),
// and C >= 9 is provably degenerate: the hint-weight check collapses because
// the per-coefficient randomness spread grows with sqrt(owned) while the
// mode3 HighBits segment width is fixed. SigningParametersForParticipants
// fails closed for unpinned sizes.

// SigningParameters is one committee row of the R76b signing-MPC family.
type SigningParameters struct {
	Participants  int     // C, committee size
	Threshold     int     // t = ceil(2C/3), active signers per request
	OwnedPerOwner int     // worst-case owned components ceil(binomial(C,g)/t)
	Exponent      float64 // expo, log2 of the per-slot acceptance inverse
	Divergence    float64 // M = 2^(expo/t)
	ShiftBound    float64 // B
	Radius        float64 // r, the accept radius of HRej
	SampleRadius  float64 // r' = M^(1/(N*(L+K))) * r
	HintCheckProb float64 // MC-estimated hint-check probability
	ParallelSlots int     // J = ceil(ln2 / -ln(1-pfinal))
}

// SigningMaxParallelSlots is the largest pinned slot count across the
// signing rows; transports and schedules must stay within it regardless of the
// committee row a request actually uses.
const SigningMaxParallelSlots = 43

// ErrNoSigningRow rejects a committee size with no pinned signing-MPC row.
var ErrNoSigningRow = errors.New("no pinned Dilithium3 v1 signing parameter row")

// signingParameterFamily pins the operational rows. The numbers are pinned to
// 0.01 (B, r, r') exactly as derived; tests re-derive them from the closed
// forms, so the table and the derivation cannot silently diverge.
var signingParameterFamily = map[int]SigningParameters{
	6: {
		Participants: 6, Threshold: 4, OwnedPerOwner: 5,
		Exponent: 3.30, Divergence: SigningRandomnessDivergence(),
		ShiftBound:    SigningShiftBound,
		Radius:        SigningRandomnessRadius,
		SampleRadius:  SigningRandomnessSampleRadius,
		HintCheckProb: 0.6506,
		ParallelSlots: SigningParallelSlots,
	},
	7: {
		Participants: 7, Threshold: 5, OwnedPerOwner: 7,
		Exponent:      4.95,
		Divergence:    math.Pow(2, 4.95/5),
		ShiftBound:    779.31,
		Radius:        402748.8,
		SampleRadius:  402847.0,
		HintCheckProb: 0.5052,
		ParallelSlots: 43,
	},
}

// signingParameterFamilyRotated pins the R77d row for six-member committees
// produced by a remove rotation: every share carries folded components of
// multiplicity 2, so each signer's per-coefficient secret mass is sqrt(2) times
// the fresh profile and the fresh row's radius margin (r'-r = 82.9 against a
// fresh shift bound 658.64/6) is exhausted — every candidate slot rejects.
// The row is measured through r77c_rotated_row.go on the all-components-fold-2
// profile: fresh-family checks reproduce (P1=1, P2=1, Phint=0.5995 above the
// 0.4 band), the per-request success rate matches the fresh row, and J=26
// stays within the transport budget (SigningMaxParallelSlots).
var signingParameterFamilyRotated = map[int]SigningParameters{
	6: {
		Participants: 6, Threshold: 4, OwnedPerOwner: 5,
		Exponent:      4.50,
		Divergence:    math.Pow(2, 4.50/4),
		ShiftBound:    931.45,
		Radius:        424037.5,
		SampleRadius:  424155.0,
		HintCheckProb: 0.5995,
		ParallelSlots: 26,
	},
}

// SigningParametersForParticipants returns the pinned signing-MPC row for a
// committee size; any other size fails closed.
func SigningParametersForParticipants(participants int) (SigningParameters, error) {
	row, ok := signingParameterFamily[participants]
	if !ok {
		return SigningParameters{}, fmt.Errorf("%w: committee size %d", ErrNoSigningRow, participants)
	}
	return row, nil
}

// shareCarriesRotationFold reports whether any component of the share carries
// fold multiplicity above 1: the marker every remove-rotated share gets. Such
// shares cannot sign under the fresh row (the radius margin is sized for
// eta=1 fresh secrets), so rotation state becomes the row selector.
func shareCarriesRotationFold(share *LocalShare) bool {
	if share == nil {
		return false
	}
	for index := range share.Components {
		if componentMultiplicity(share.Components[index]) > 1 {
			return true
		}
	}
	return false
}

// SigningParametersForShares returns the pinned row for the session's share
// profile: every active share must agree on the committee size or the request
// fails closed; if any active share carries a rotation fold, the rotated row is
// selected. All signers of one session rotate together, so the row choice is
// identical on every member.
func SigningParametersForShares(shares []*LocalShare) (SigningParameters, error) {
	if len(shares) == 0 || shares[0] == nil {
		return SigningParameters{}, fmt.Errorf("%w: no active shares", ErrNoSigningRow)
	}
	participants := len(shares[0].Committee.Participants)
	rotated := false
	for _, share := range shares {
		if share == nil {
			continue
		}
		if len(share.Committee.Participants) != participants {
			return SigningParameters{}, fmt.Errorf("%w: shares disagree on the committee size", ErrNoSigningRow)
		}
		if shareCarriesRotationFold(share) {
			rotated = true
		}
	}
	if rotated {
		row, ok := signingParameterFamilyRotated[participants]
		if !ok {
			return SigningParameters{}, fmt.Errorf("%w: rotated committee size %d", ErrNoSigningRow, participants)
		}
		return row, nil
	}
	return SigningParametersForParticipants(participants)
}

// SigningParametersForThresholdCount returns the unique pinned row whose
// threshold count matches; any other signer count fails closed.
func SigningParametersForThresholdCount(threshold int) (SigningParameters, error) {
	for _, row := range signingParameterFamily {
		if row.Threshold == threshold {
			return row, nil
		}
	}
	return SigningParameters{}, fmt.Errorf("%w: signer count %d", ErrNoSigningRow, threshold)
}

// ThresholdForParticipants returns ceil(2C/3), the family threshold rule.
func ThresholdForParticipants(participants int) int {
	return (2*participants + 2) / 3
}

// GroupSizeForParticipants returns the replicated-group size C - t + 1.
func GroupSizeForParticipants(participants int) int {
	return participants - ThresholdForParticipants(participants) + 1
}

// ParametersForParticipants returns the CIRCL mode3 constants with the v1
// committee shape (C, ceil(2C/3), 2). A C outside [6, 12] fails later at
// Validate, keeping out-of-family counts unreachable.
func ParametersForParticipants(participants int) Parameters {
	return Parameters{
		N: N, Q: Q, K: K, L: L, Eta: Eta, Tau: Tau, Beta: Beta,
		Gamma1: Gamma1, Gamma2: Gamma2, Omega: Omega, D: D,
		CTildeSize: CTildeSize, TRSize: TRSize,
		PublicKeySize: mode3.PublicKeySize, PrivateKeySize: mode3.PrivateKeySize,
		SignatureSize: mode3.SignatureSize, Participants: participants,
		Threshold: ThresholdForParticipants(participants), MaxCorrupt: 2,
	}
}

// Validate rejects any parameter set outside the derived committee family:
// the mode3 constants must match the fixed profile and the committee shape
// must obey the (C, ceil(2C/3), 2) rule within the supported range.
func (parameters Parameters) Validate() error {
	canonical := ParametersForParticipants(parameters.Participants)
	if parameters != canonical ||
		parameters.Participants < MinCommitteeParticipants ||
		parameters.Participants > MaxCommitteeParticipants {
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
