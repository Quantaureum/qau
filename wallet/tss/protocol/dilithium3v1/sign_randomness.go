// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Per-slot randomness for the revised four-of-six signing construction: a
// uniform point in the ball of radius SigningRandomnessSampleRadius, its
// rounded imbalanced expansion, and the per-party rejection test of the
// construction reference's HRej. The reference driver holds one of these per
// active signer and slot; a production signer samples its own and reveals only
// the expansion-derived public values. The sampler and the test are part of
// the side-channel review (design note, Open Obligations item 5).
//
// The ball point masks a signer's partial secret in the response it
// broadcasts, so it must be unpredictable to every observer of the round
// messages: a production signer expands a fresh 32-byte seed from a
// cryptographic source with SHAKE256 (sampleSigningExecutorPartyRandomness),
// and the Gaussian coordinates are drawn without any table lookup or branch
// that depends on the accepted values.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// ErrInvalidSigningRandomness reports malformed or inconsistent randomness: a
// missing source, a non-finite sample, a point outside the sampling ball, or a
// rounded expansion that does not match the raw point.
var ErrInvalidSigningRandomness = errors.New("invalid Dilithium3 v1 signing randomness")

// signingRandomnessDimension is N*(L+K), the dimension of the sampled ball.
const signingRandomnessDimension = N * (L + K)

// signingInverseNu turns the expansion's division by nu into a multiplication.
// It does not make the sampler free of secret-dependent floating-point
// latency: the polar method's division and square root, the ball
// normalization, and the logarithm's series argument still divide by values
// derived from the secret sample. On cores where division or square-root
// latency depends on the operands this exposes timing on aggregates of the
// sample; closing it needs a fixed-point sampler, which the side-channel
// review tracks as an open item.
const signingInverseNu = 1.0 / SigningRandomnessNu

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
// nearest integer. The stream supplies uniform bytes: a signer passes the
// SHAKE256 expansion of a fresh cryptographic seed, and tests pass a
// deterministic stream.
func sampleSigningRandomness(stream io.Reader, params SigningParameters) (*signingRandomness, error) {
	if stream == nil {
		return nil, fmt.Errorf("%w: missing source", ErrInvalidSigningRandomness)
	}
	// A uniform point on the sphere in dimension dim+2, projected onto its
	// first dim coordinates, is uniform in the dim-dimensional ball. The
	// dimension plus two is even, so the draws come in polar-method pairs.
	var buffer [signingRandomnessDimension + 2]float64
	defer wipeFloat64s(buffer[:])
	norm := 0.0
	for index := 0; index+1 < len(buffer); index += 2 {
		first, second, err := signingGaussianPair(stream)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSigningRandomness, err)
		}
		buffer[index], buffer[index+1] = first, second
		norm += first*first + second*second
	}
	if !(norm > 0) || math.IsInf(norm, 0) {
		return nil, fmt.Errorf("%w: degenerate ball sample", ErrInvalidSigningRandomness)
	}
	scale := params.SampleRadius / math.Sqrt(norm)
	point := &signingRandomness{}
	for index := 0; index < signingRandomnessDimension; index++ {
		point.raw[index] = buffer[index] * scale
	}
	point.roundFromRaw()
	return point, nil
}

// signingGaussianPair draws two independent standard normal values with
// Marsaglia's polar method. A candidate (u, v) outside the unit disc is
// discarded; discarded candidates are independent of the accepted pair, so the
// number of iterations reveals nothing about the output. The accepted path has
// no table lookup and no branch on the accepted values; its division and
// square root do take secret operands (see signingInverseNu).
func signingGaussianPair(stream io.Reader) (float64, float64, error) {
	var raw [16]byte
	defer wipeBytes(raw[:])
	for {
		if _, err := io.ReadFull(stream, raw[:]); err != nil {
			return 0, 0, fmt.Errorf("randomness stream: %w", err)
		}
		u := 2*signingUnitFloat(binary.LittleEndian.Uint64(raw[0:8])) - 1
		v := 2*signingUnitFloat(binary.LittleEndian.Uint64(raw[8:16])) - 1
		radius := u*u + v*v
		if radius > 0 && radius < 1 {
			scale := math.Sqrt(-2 * signingLogUnit(radius) / radius)
			return u * scale, v * scale, nil
		}
	}
}

// signingUnitFloat maps the top 53 bits of a word to a float64 in [0, 1). The
// value fits in an int64, so the conversion is a single signed instruction
// rather than the unsigned conversion's range branch.
func signingUnitFloat(word uint64) float64 {
	return float64(int64(word>>11)) * 0x1p-53
}

const (
	signingFloat64MantissaMask = 1<<52 - 1
	signingFloat64ExponentBias = 1023
	// signingSqrt2Mantissa is the mantissa field of sqrt(2).
	signingSqrt2Mantissa = 0x6A09E667F3BCD
	// signingLn2Hi + signingLn2Lo = ln 2; signingLn2Hi has trailing zero bits,
	// so k*signingLn2Hi is exact for every exponent k of a float64.
	signingLn2Hi = 6.93147180369123816490e-01
	signingLn2Lo = 1.90821492927058770002e-10
)

// signingLogUnit returns ln(x) for a normal float64 x in (0, 1) with no branch
// and no memory access that depends on x. The argument is split into an
// exponent k and a mantissa m in [sqrt(2)/2, sqrt(2)) -- the half-step that
// recenters m is selected with integer arithmetic, not a comparison -- and
// ln(m) = 2*atanh(t) with t = (m-1)/(m+1), |t| <= 0.1716, is a fixed-length
// odd series whose truncation error is far below one ulp. The standard
// library's Log branches on the mantissa on targets without an assembly
// implementation (arm64), which this replaces on the signing path.
func signingLogUnit(x float64) float64 {
	bits := math.Float64bits(x)
	exponent := int64(bits>>52&0x7ff) - signingFloat64ExponentBias
	mantissa := bits & signingFloat64MantissaMask
	// above is 1 exactly when the mantissa exceeds sqrt(2)'s: the unsigned
	// difference wraps and its top bit is set.
	above := (signingSqrt2Mantissa - mantissa) >> 63
	m := math.Float64frombits(mantissa | (signingFloat64ExponentBias-above)<<52)
	exponent += int64(above)
	t := (m - 1) / (m + 1)
	t2 := t * t
	series := 1.0 / 25
	series = 1.0/23 + t2*series
	series = 1.0/21 + t2*series
	series = 1.0/19 + t2*series
	series = 1.0/17 + t2*series
	series = 1.0/15 + t2*series
	series = 1.0/13 + t2*series
	series = 1.0/11 + t2*series
	series = 1.0/9 + t2*series
	series = 1.0/7 + t2*series
	series = 1.0/5 + t2*series
	series = 1.0/3 + t2*series
	logM := 2 * t * (1 + t2*series)
	k := float64(exponent)
	return k*signingLn2Hi + (logM + k*signingLn2Lo)
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
func validateSigningRandomness(point *signingRandomness, params SigningParameters) error {
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
	if total > params.SampleRadius*params.SampleRadius {
		return fmt.Errorf("%w: point outside the sampling ball", ErrInvalidSigningRandomness)
	}
	rounded := &signingRandomness{raw: point.raw}
	defer rounded.wipe()
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
	radius float64,
) (bool, error) {
	if point == nil {
		return false, fmt.Errorf("%w: missing point", ErrInvalidSigningRandomness)
	}
	total := 0.0
	for row := 0; row < L; row++ {
		for index := 0; index < N; index++ {
			value := float64(shiftFirst[row][index])*signingInverseNu + point.raw[row*N+index]
			total += value * value
		}
	}
	for row := 0; row < K; row++ {
		for index := 0; index < N; index++ {
			value := float64(shiftSecond[row][index]) + point.raw[(L+row)*N+index]
			total += value * value
		}
	}
	return total <= radius*radius, nil
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
