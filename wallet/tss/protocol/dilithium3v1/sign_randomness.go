// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Per-slot randomness for the revised four-of-six signing construction: a
// uniform point in the ball of radius SigningRandomnessSampleRadius, its
// rounded imbalanced expansion, and the per-party rejection test of the
// construction reference's HRej. The reference driver holds one of these per
// active signer and slot; a production signer samples its own and reveals only
// the expansion-derived public values. The sampler and the test are part of
// the side-channel review (design note, Open Obligations item 5).

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
)

// ErrInvalidSigningRandomness reports malformed or inconsistent randomness: a
// missing source, a non-finite sample, a point outside the sampling ball, or a
// rounded expansion that does not match the raw point.
var ErrInvalidSigningRandomness = errors.New("invalid Dilithium3 v1 signing randomness")

// signingRandomnessDimension is N*(L+K), the dimension of the sampled ball.
const signingRandomnessDimension = N * (L + K)

// signingRandomness is one signer's per-slot ball point: the raw unexpanded
// sample the rejection test consumes, and the rounded imbalanced expansion
// that the commitment and the response publish. It is never serialized, never
// returned by any transcript, and single-use per slot.
type signingRandomness struct {
	raw    [signingRandomnessDimension]float64
	first  VectorL
	second VectorK
}

// sampleSigningRandomness draws one uniform point in the ball of radius r',
// expands the first L blocks by nu, and rounds every coefficient to the
// nearest integer. The source is the caller's: the reference driver seeds it
// deterministically, and a signer process must supply a cryptographic source
// (design note, Open Obligations item 1).
func sampleSigningRandomness(source *rand.Rand) (*signingRandomness, error) {
	if source == nil {
		return nil, fmt.Errorf("%w: missing source", ErrInvalidSigningRandomness)
	}
	// A uniform point on the sphere in dimension dim+2, projected onto its
	// first dim coordinates, is uniform in the dim-dimensional ball.
	buffer := make([]float64, signingRandomnessDimension+2)
	norm := 0.0
	for index := range buffer {
		buffer[index] = source.NormFloat64()
		norm += buffer[index] * buffer[index]
	}
	if !(norm > 0) || math.IsInf(norm, 0) {
		return nil, fmt.Errorf("%w: degenerate ball sample", ErrInvalidSigningRandomness)
	}
	scale := SigningRandomnessSampleRadius / math.Sqrt(norm)
	point := &signingRandomness{}
	for index := 0; index < signingRandomnessDimension; index++ {
		point.raw[index] = buffer[index] * scale
	}
	point.roundFromRaw()
	return point, nil
}

// roundFromRaw recomputes the rounded expansion from the raw point.
func (point *signingRandomness) roundFromRaw() {
	for row := 0; row < L; row++ {
		for index := 0; index < N; index++ {
			value := math.RoundToEven(point.raw[row*N+index] * SigningRandomnessNu)
			point.first[row][index] = Normalize(Coefficient(value))
		}
	}
	for row := 0; row < K; row++ {
		for index := 0; index < N; index++ {
			value := math.RoundToEven(point.raw[(L+row)*N+index])
			point.second[row][index] = Normalize(Coefficient(value))
		}
	}
}

// validateSigningRandomness requires a finite point inside the sampling ball
// whose rounded expansion is exactly round(nu*x1, x2). The reference driver
// holds the point in one process, so recomputing the expansion is cheap and
// keeps a caller-supplied point from diverging from the published values.
func validateSigningRandomness(point *signingRandomness) error {
	if point == nil {
		return fmt.Errorf("%w: missing point", ErrInvalidSigningRandomness)
	}
	total := 0.0
	for index := 0; index < signingRandomnessDimension; index++ {
		value := point.raw[index]
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return fmt.Errorf("%w: non-finite coordinate %d", ErrInvalidSigningRandomness, index)
		}
		total += value * value
	}
	if total > SigningRandomnessSampleRadius*SigningRandomnessSampleRadius {
		return fmt.Errorf("%w: point outside the sampling ball", ErrInvalidSigningRandomness)
	}
	rounded := &signingRandomness{raw: point.raw}
	rounded.roundFromRaw()
	if rounded.first != point.first || rounded.second != point.second {
		return fmt.Errorf("%w: rounded expansion does not match the raw point", ErrInvalidSigningRandomness)
	}
	return nil
}

// signingRejectionTest evaluates the per-party HRej criterion. The challenge
// shift holds the centered small coefficients of c*spart; the test value is
// (shiftFirst/nu + x1, shiftSecond + x2) against the target ball, and the
// published response is (shiftFirst + round(nu*x1), shiftSecond + round(x2)).
func signingRejectionTest(
	point *signingRandomness,
	shiftFirst [L]SignedPoly,
	shiftSecond [K]SignedPoly,
) (bool, error) {
	if point == nil {
		return false, fmt.Errorf("%w: missing point", ErrInvalidSigningRandomness)
	}
	total := 0.0
	for row := 0; row < L; row++ {
		for index := 0; index < N; index++ {
			value := float64(shiftFirst[row][index])/SigningRandomnessNu + point.raw[row*N+index]
			total += value * value
		}
	}
	for row := 0; row < K; row++ {
		for index := 0; index < N; index++ {
			value := float64(shiftSecond[row][index]) + point.raw[(L+row)*N+index]
			total += value * value
		}
	}
	return total <= SigningRandomnessRadius*SigningRandomnessRadius, nil
}

// signingResponsePart returns z_i^(1) = shiftFirst + round(nu*x1) as centered
// small coefficients. It is only ever computed for a slot the signer accepted.
func signingResponsePart(point *signingRandomness, shiftFirst [L]SignedPoly) [L]SignedPoly {
	var part [L]SignedPoly
	for row := 0; row < L; row++ {
		for index := 0; index < N; index++ {
			rounded := CenteredCoefficient(point.first[row][index])
			part[row][index] = shiftFirst[row][index] + rounded
		}
	}
	return part
}
