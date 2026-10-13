// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func signingSecurityTestParameters(t *testing.T) SigningParameters {
	t.Helper()
	params, err := SigningParametersForParticipants(6)
	if err != nil {
		t.Fatalf("SigningParametersForParticipants(6): %v", err)
	}
	return params
}

func signingSecurityTestSeed() []byte {
	seed := make([]byte, 64)
	for index := range seed {
		seed[index] = byte(index*37 + 11)
	}
	return seed
}

func signingSecurityTestPoint(t *testing.T, entropy []byte, params SigningParameters) *signingRandomness {
	t.Helper()
	point, err := sampleSigningExecutorPartyRandomness(bytes.NewReader(entropy), params)
	if err != nil {
		t.Fatalf("sampleSigningExecutorPartyRandomness(): %v", err)
	}
	return point
}

// The per-slot ball point is the secret that a signer's broadcast commitment
// and response are masked with; it must depend on every bit of its 256-bit
// seed, so seeds that agree on any reduction of the seed (modulo 2^31-1 here)
// or differ only in their last byte must still give different points.
func TestSigningPartyRandomnessDependsOnTheWholeSeed(t *testing.T) {
	params := signingSecurityTestParameters(t)
	base := signingSecurityTestSeed()
	reference := signingSecurityTestPoint(t, base, params)

	congruent := append([]byte(nil), base...)
	binary.LittleEndian.PutUint64(congruent[:8], binary.LittleEndian.Uint64(base[:8])+((1<<31)-1)*977)
	if signingSecurityTestPoint(t, congruent, params).first == reference.first {
		t.Fatal("seeds congruent modulo 2^31-1 produced the same ball point")
	}

	tail := append([]byte(nil), base...)
	tail[signingBallSeedSize-1] ^= 0x80
	if signingSecurityTestPoint(t, tail, params).first == reference.first {
		t.Fatal("the last seed byte does not influence the ball point")
	}

	again := signingSecurityTestPoint(t, base, params)
	if again.first != reference.first || again.second != reference.second || again.raw != reference.raw {
		t.Fatal("one seed produced two different ball points")
	}

	if _, err := sampleSigningExecutorPartyRandomness(bytes.NewReader(base[:signingBallSeedSize-1]), params); err == nil {
		t.Fatal("a short seed was accepted")
	}
}

// signingSecurityTestStream is a deterministic SHAKE256 stream for the
// distribution tests.
func signingSecurityTestStream(label string) *sha3.SHAKE {
	stream := sha3.NewSHAKE256()
	_, _ = stream.Write([]byte("QAU dilithium3v1 sampler distribution test"))
	_, _ = stream.Write([]byte(label))
	return stream
}

// The Gaussian draws must be standard normal: mean, variance, kurtosis, and a
// binned chi-square against the normal CDF.
func TestSigningGaussianSamplerIsStandardNormal(t *testing.T) {
	stream := signingSecurityTestStream("gaussian")
	const pairs = 100000
	const samples = 2 * pairs
	edges := []float64{math.Inf(-1)}
	for edge := -3.5; edge <= 3.5+1e-9; edge += 0.25 {
		edges = append(edges, edge)
	}
	edges = append(edges, math.Inf(1))
	counts := make([]int, len(edges)-1)
	var sum, sumSquares, sumFourth float64
	record := func(value float64) {
		sum += value
		sumSquares += value * value
		sumFourth += value * value * value * value
		for bin := range counts {
			if value >= edges[bin] && value < edges[bin+1] {
				counts[bin]++
				return
			}
		}
	}
	for draw := 0; draw < pairs; draw++ {
		first, second, err := signingGaussianPair(stream)
		if err != nil {
			t.Fatalf("signingGaussianPair(): %v", err)
		}
		record(first)
		record(second)
	}
	mean := sum / samples
	variance := sumSquares/samples - mean*mean
	kurtosis := sumFourth / samples / (variance * variance)
	if math.Abs(mean) > 5/math.Sqrt(samples) {
		t.Fatalf("mean %.5f is not zero", mean)
	}
	if math.Abs(variance-1) > 5*math.Sqrt(2.0/samples) {
		t.Fatalf("variance %.5f is not one", variance)
	}
	if math.Abs(kurtosis-3) > 5*math.Sqrt(24.0/samples) {
		t.Fatalf("kurtosis %.4f is not three", kurtosis)
	}
	cdf := func(x float64) float64 { return 0.5 * math.Erfc(-x/math.Sqrt2) }
	chiSquare := 0.0
	for bin, observed := range counts {
		expected := samples * (cdf(edges[bin+1]) - cdf(edges[bin]))
		diff := float64(observed) - expected
		chiSquare += diff * diff / expected
	}
	// 29 degrees of freedom; 80 is far beyond the 1e-5 tail.
	if chiSquare > 80 {
		t.Fatalf("chi-square %.1f over %d bins rejects the normal distribution", chiSquare, len(counts))
	}
}

// Ball points must lie inside the sampling ball, with the radial distribution
// of a uniform point (||x||/r')^d ~ U(0,1) and per-coordinate variance
// r'^2/(d+2).
func TestSigningBallSamplerIsUniformInTheBall(t *testing.T) {
	params := signingSecurityTestParameters(t)
	stream := signingSecurityTestStream("ball")
	const points = 48
	dimension := float64(signingRandomnessDimension)
	var radial []float64
	var coordinateSquares float64
	for draw := 0; draw < points; draw++ {
		point, err := sampleSigningRandomness(stream, params)
		if err != nil {
			t.Fatalf("sampleSigningRandomness(): %v", err)
		}
		total := 0.0
		for _, value := range point.raw {
			total += value * value
			coordinateSquares += value * value
		}
		norm := math.Sqrt(total)
		if norm > params.SampleRadius {
			t.Fatalf("point %d has norm %.1f outside the sampling radius %.1f", draw, norm, params.SampleRadius)
		}
		radial = append(radial, math.Pow(norm/params.SampleRadius, dimension))
	}
	// Kolmogorov-Smirnov against U(0,1); 0.30 is past the 1e-3 tail at n=48.
	sortFloat64s(radial)
	maxGap := 0.0
	for index, value := range radial {
		low := value - float64(index)/points
		high := float64(index+1)/points - value
		maxGap = math.Max(maxGap, math.Max(low, high))
	}
	if maxGap > 0.30 {
		t.Fatalf("radial KS statistic %.3f rejects a uniform ball", maxGap)
	}
	want := params.SampleRadius * params.SampleRadius / (dimension + 2)
	got := coordinateSquares / (points * dimension)
	if math.Abs(got-want)/want > 0.02 {
		t.Fatalf("per-coordinate second moment %.1f, want %.1f", got, want)
	}
}

func sortFloat64s(values []float64) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// The branch-free logarithm must match math.Log on (0, 1).
func TestSigningUnitLogMatchesMathLog(t *testing.T) {
	stream := signingSecurityTestStream("log")
	var raw [8]byte
	check := func(x float64) {
		got := signingLogUnit(x)
		want := math.Log(x)
		if diff := math.Abs(got - want); diff > 4e-16*math.Max(1, math.Abs(want)) {
			t.Fatalf("signingLogUnit(%v) = %v, want %v (diff %g)", x, got, want, diff)
		}
	}
	for draw := 0; draw < 200000; draw++ {
		if _, err := stream.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		x := signingUnitFloat(binary.LittleEndian.Uint64(raw[:]))
		if x > 0 {
			check(x)
		}
	}
	for _, x := range []float64{0x1p-106, 0x1p-60, 0x1p-53, 0.25, 0.5, math.Sqrt2 / 2, 0.70710678118654757, 0.9999999999999999, 1 - 0x1p-40} {
		check(x)
	}
	// Relative accuracy near one, where log is tiny.
	for _, delta := range []float64{0x1p-20, 0x1p-30, 0x1p-40, 0x1p-50} {
		x := 1 - delta
		got, want := signingLogUnit(x), math.Log(x)
		if math.Abs(got-want) > 4e-16*math.Abs(want) {
			t.Fatalf("signingLogUnit(1-%g) = %v, want %v", delta, got, want)
		}
	}
}

// Production files of this package must not use math/rand (any version) and
// must not carry the removed secret-printing debug switch.
func TestSigningProductionCodeAvoidsWeakRandomness(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, spec := range parsed.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if path == "math/rand" || path == "math/rand/v2" {
				t.Errorf("%s imports %s", file, path)
			}
		}
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(source, []byte("QAU_DEBUG_SIGNING_NORM")) {
			t.Errorf("%s still reads QAU_DEBUG_SIGNING_NORM", file)
		}
	}
}

// The reciprocal and square root that replace the division and square root
// instructions must stay accurate to a few ulp over every exponent the sampler
// can reach, at the awkward mantissas, and on the exact ranges it uses.
func TestSigningNewtonArithmeticMatchesTheInstructions(t *testing.T) {
	const reciprocalUlps, rootUlps = 2, 3
	check := func(x float64) {
		t.Helper()
		if err := math.Abs(signingReciprocal(x)*x - 1); err > reciprocalUlps*0x1p-52 {
			t.Fatalf("signingReciprocal(%g): relative error %g exceeds %d ulp", x, err, reciprocalUlps)
		}
		root := math.Sqrt(x)
		if err := math.Abs(signingInverseSqrt(x)*root - 1); err > rootUlps*0x1p-52 {
			t.Fatalf("signingInverseSqrt(%g): relative error %g exceeds %d ulp", x, err, rootUlps)
		}
		if err := math.Abs(signingSqrt(x)/root - 1); err > rootUlps*0x1p-52 {
			t.Fatalf("signingSqrt(%g): relative error %g exceeds %d ulp", x, err, rootUlps)
		}
	}
	rng := rand.New(rand.NewPCG(11, 13))
	for draw := 0; draw < 400000; draw++ {
		check(math.Ldexp(1+rng.Float64(), rng.IntN(240)-120))
	}
	for exponent := -120; exponent <= 120; exponent++ {
		for _, mantissa := range []float64{1, 1.5, math.Sqrt2, 2 - 0x1p-52, 1 + 0x1p-52} {
			check(math.Ldexp(mantissa, exponent))
		}
	}
	// The ranges the sampler uses: the polar radius, the logarithm's m+1, the
	// squared norm of the Gaussian vector, and the polar scale argument.
	for draw := 0; draw < 100000; draw++ {
		check(math.Ldexp(1+rng.Float64(), -rng.IntN(106)-1)) // (0, 1)
		check(math.Sqrt2/2 + 1 + rng.Float64()*(math.Sqrt2-math.Sqrt2/2))
		check(2000 + rng.Float64()*2000)
		check(0x1p-52 + rng.Float64()*1e34)
	}
}

// The rounding that replaces math.RoundToEven must agree with it everywhere
// the sampler can reach, ties to even included.
func TestSigningRoundToEvenMatchesTheStandardLibrary(t *testing.T) {
	check := func(x float64) {
		t.Helper()
		if got, want := signingRoundToEven(x), math.RoundToEven(x); got != want {
			t.Fatalf("signingRoundToEven(%v) = %v, want %v", x, got, want)
		}
	}
	rng := rand.New(rand.NewPCG(21, 23))
	for draw := 0; draw < 400000; draw++ {
		check((rng.Float64()*2 - 1) * 5e5)
		check(float64(rng.IntN(2000001)-1000000) + 0.5) // exact ties
		check(float64(rng.IntN(2000001)-1000000) + 0.5 + math.Copysign(0x1p-30, rng.Float64()-0.5))
	}
	for _, x := range []float64{0, math.Copysign(0, -1), 0.5, -0.5, 1.5, -1.5, 2.5, -2.5, 0.49999999999999994, -0.49999999999999994,
		0x1p50 + 0.5, -(0x1p50 + 0.5), 0x1p50 - 0.5, 4.2e5, -4.2e5} {
		check(x)
	}
}

// A sampler that runs on secret-derived values must not contain a division by
// a non-constant, a square root, or another call whose latency depends on its
// operands: the reciprocal and root helpers are built from multiplications and
// subtractions, and the rounding from an addition and a subtraction. The check
// reads every production file of the package, so moving a helper elsewhere does
// not avoid it.
func TestSigningSamplerHasNoVariableLatencyArithmetic(t *testing.T) {
	// The only identifiers of package math the sampler may use: bit casts and
	// classification. params.go builds the public parameter rows and is the only
	// other file allowed to import math.
	allowedMath := map[string]bool{"Float64bits": true, "Float64frombits": true, "IsInf": true, "IsNaN": true}
	const samplerFile = "sign_randomness.go"
	allowedSamplerImports := map[string]bool{"encoding/binary": true, "errors": true, "fmt": true, "io": true, "math": true}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, file, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		importsMath := false
		for _, spec := range parsed.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if path == "math" {
				importsMath = true
				if spec.Name != nil {
					t.Errorf("%s imports math under the name %q", file, spec.Name.Name)
				}
			}
			if file == samplerFile && !allowedSamplerImports[path] {
				t.Errorf("%s imports %q, which the sampler may not use", file, path)
			}
		}
		if importsMath && file != samplerFile && file != "params.go" {
			t.Errorf("%s imports math; only %s and params.go may", file, samplerFile)
		}
		if file != samplerFile {
			continue
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch expression := node.(type) {
			case *ast.SelectorExpr:
				// Every use, call or value, of a math identifier outside the list.
				if pkg, ok := expression.X.(*ast.Ident); ok && pkg.Name == "math" && !allowedMath[expression.Sel.Name] {
					t.Errorf("%s: uses math.%s", fileSet.Position(expression.Pos()), expression.Sel.Name)
				}
			case *ast.BinaryExpr:
				if expression.Op == token.QUO {
					if _, literal := expression.Y.(*ast.BasicLit); !literal && !insideConstDeclaration(parsed, expression) {
						t.Errorf("%s: divides by a non-literal", fileSet.Position(expression.Pos()))
					}
				}
			case *ast.AssignStmt:
				if expression.Tok == token.QUO_ASSIGN {
					t.Errorf("%s: uses /=", fileSet.Position(expression.Pos()))
				}
			}
			return true
		})
	}
}

// insideConstDeclaration reports whether the expression is part of a const
// declaration, whose division the compiler evaluates.
func insideConstDeclaration(file *ast.File, target ast.Node) bool {
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.CONST {
			continue
		}
		if target.Pos() >= generic.Pos() && target.End() <= generic.End() {
			return true
		}
	}
	return false
}

// signingSecurityTestSecretsWiped reports whether a signer's per-slot secrets
// are all zero.
func signingSecurityTestSecretsWiped(signer *signingExecutorSigner) bool {
	signer.lock.Lock()
	defer signer.lock.Unlock()
	for _, value := range signer.randomness.raw {
		if value != 0 {
			return false
		}
	}
	return signer.randomness.first == VectorL{} && signer.randomness.second == VectorK{} &&
		signer.partialFirst == VectorL{} && signer.partialSecond == VectorK{} &&
		signer.shiftFirst == [L]SignedPoly{}
}

// A party erases its ball point, partial secrets, and challenge shift once the
// slot ends: after a signature, and after a slot that starves on silence. The
// caller's point is the party's to copy, never to share.
func TestSigningExecutorPartyErasesSlotSecrets(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	active := fixture.activeShares(t, 0x0F)
	identities := signingExecutorPartyTestIdentities(active)

	slot, randomness := signingExecutorPartyTestAcceptedSlot(t, fixture, active)
	parties := signingExecutorPartyTestParties(
		t, fixture, 0x0F, slot, randomness, signingExecutorTestJournals(t), signingExecutorTestRecords(t, int(slot)),
	)
	for index, party := range parties {
		if err := party.Start(); err != nil {
			t.Fatalf("signer %d: Start(): %v", index, err)
		}
	}
	signingExecutorPartyTestPump(t, parties, identities)
	for index, party := range parties {
		if _, err := party.Finish(); err != nil {
			t.Fatalf("signer %d: Finish(): %v", index, err)
		}
		if !signingSecurityTestSecretsWiped(party.signer) {
			t.Fatalf("signer %d kept per-slot secrets after signing", index)
		}
	}
	for index, point := range randomness {
		if point.first == (VectorL{}) {
			t.Fatalf("the caller's point %d was erased through the party", index)
		}
	}

	silent := signingExecutorPartyTestParties(
		t, fixture, 0x0F, slot+1, signingExecutorTestRandomness(t, 0x51E7),
		signingExecutorTestJournals(t), signingExecutorTestRecords(t, int(slot)+1),
	)
	if err := silent[0].Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	if _, err := silent[0].Finish(); err == nil {
		t.Fatal("a slot without peers produced a signature")
	}
	if !signingSecurityTestSecretsWiped(silent[0].signer) {
		t.Fatal("a starved slot kept its per-slot secrets")
	}
}

// A truncated reshare delta must be refused with an error, never by a panic:
// the decoder runs on every received delta in p2p validation.
func TestUnmarshalReshareDeltaWireRejectsTruncatedInput(t *testing.T) {
	encoded := []byte(reshareDeltaWireMagic)
	for length := 0; length <= len(encoded)+120; length++ {
		input := make([]byte, length)
		copy(input, encoded)
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("length %d: decoder panicked: %v", length, recovered)
				}
			}()
			if _, err := UnmarshalReshareDeltaWire(input); err == nil {
				t.Fatalf("length %d: truncated delta accepted", length)
			}
		}()
	}
}

// A truncated local share must be refused with an error, never by a panic,
// even when its trailing digest is recomputed to match the truncated body.
func TestUnmarshalLocalShareRejectsTruncatedInput(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	rotated := fixture.shares[0].Clone()
	rotated.Rotated = true
	for _, share := range []*LocalShare{fixture.shares[0], rotated} {
		encoded, err := share.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		body := encoded[:len(encoded)-shareDigestSize]
		for length := 0; length < len(body); length += 7 {
			digest := sha3.Sum256(body[:length])
			input := append(append([]byte(nil), body[:length]...), digest[:]...)
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("rotated=%v body length %d: decoder panicked: %v", share.Rotated, length, recovered)
					}
				}()
				if decoded, err := UnmarshalLocalShare(input); err == nil {
					decoded.Zeroize()
					t.Fatalf("rotated=%v body length %d: truncated share accepted", share.Rotated, length)
				}
			}()
		}
	}
	for length := 0; length < shareDigestSize+16; length++ {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("raw length %d: decoder panicked: %v", length, recovered)
				}
			}()
			if _, err := UnmarshalLocalShare(append([]byte(localShareMagic), make([]byte, length)...)); err == nil {
				t.Fatalf("raw length %d: accepted", length)
			}
		}()
	}
	for _, original := range []*LocalShare{fixture.shares[0], rotated} {
		encoded, err := original.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		share, err := UnmarshalLocalShare(encoded)
		if err != nil {
			t.Fatalf("rotated=%v: intact share refused: %v", original.Rotated, err)
		}
		share.Zeroize()
	}
}
