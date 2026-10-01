// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"
)

// mpcTestSeed derives a per-test deterministic engine seed so that every case is
// reproducible without a process-wide random source.
func mpcTestSeed(label byte) [32]byte {
	var seed [32]byte
	for index := range seed {
		seed[index] = label ^ byte(index*7)
	}
	seed[0] = label
	return seed
}

func mpcTestEngine(label byte) *mpcArithmeticEngine {
	return newMPCArithmeticEngine(mpcTestSeed(label))
}

// mpcTestCommittedRecord returns a record committed to exactly one session,
// which is the only lifecycle state the arithmetic entry points accept.
func mpcTestCommittedRecord(t *testing.T, label byte) *PreprocessingRecord {
	t.Helper()
	record := mpcTestRecord(t, label)
	commitMPCTestRecord(t, record, label)
	return record
}

func mpcTestRecord(t *testing.T, label byte) *PreprocessingRecord {
	t.Helper()
	var recordID PreprocessingID
	recordID[0] = label
	recordID[31] = 0x11
	var handle SecretHandle
	handle[0] = label
	handle[7] = 0x22
	var commitment [32]byte
	commitment[0] = label
	commitment[9] = 0x33
	record, err := NewPreprocessingRecord(recordID, uint32(label)+1, handle, commitment)
	if err != nil {
		t.Fatalf("NewPreprocessingRecord(): %v", err)
	}
	return record
}

func mpcTestSession(label byte) [32]byte {
	var sessionID [32]byte
	sessionID[0] = label
	sessionID[5] = 0x44
	return sessionID
}

func commitMPCTestRecord(t *testing.T, record *PreprocessingRecord, label byte) {
	t.Helper()
	if err := record.Commit(mpcTestSession(label)); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
}

// mpcTestBits shares one unsigned integer bit by bit, low bit first.
func mpcTestBits(engine *mpcArithmeticEngine, value uint32, width int) []sharedCoefficient {
	bits := make([]sharedCoefficient, width)
	for index := range bits {
		bits[index] = engine.dealPublic(Coefficient(value >> uint(index) & 1))
	}
	return bits
}

func mpcTestOpenBit(t *testing.T, engine *mpcArithmeticEngine, share sharedCoefficient) Coefficient {
	t.Helper()
	value, err := engine.openBit(share)
	if err != nil {
		t.Fatalf("openBit(): %v", err)
	}
	return value
}

func mpcTestOpenAndCompare(t *testing.T, engine *mpcArithmeticEngine, share sharedCoefficient, want Coefficient, context string) {
	t.Helper()
	value, err := engine.open(share)
	if err != nil {
		t.Fatalf("%s: open(): %v", context, err)
	}
	if value != want {
		t.Fatalf("%s: opened %d, want %d", context, value, want)
	}
}

// mpcTestDealtVector returns an authenticated vector whose coefficients are
// small and comfortably in range for both rejection bounds.
func mpcTestDealtVector(engine *mpcArithmeticEngine, rows int) []sharedPoly {
	vector := make([]sharedPoly, rows)
	for row := range vector {
		var polynomial Poly
		for index := range polynomial {
			polynomial[index] = Coefficient((row*N + index) % 97)
		}
		vector[row] = engine.dealPublicPoly(polynomial)
	}
	return vector
}

// TestMPCArithmeticBooleanCircuits checks the three boolean gates and the free
// NOT against the truth table.
func TestMPCArithmeticBooleanCircuits(t *testing.T) {
	engine := mpcTestEngine(0x10)
	values := []Coefficient{0, 1}
	for _, left := range values {
		for _, right := range values {
			leftShare := engine.dealPublic(left)
			rightShare := engine.dealPublic(right)

			product, err := engine.andBits(leftShare, rightShare)
			if err != nil {
				t.Fatalf("andBits(): %v", err)
			}
			if got := mpcTestOpenBit(t, engine, product); got != left&right {
				t.Fatalf("and(%d, %d) = %d, want %d", left, right, got, left&right)
			}

			exclusive, err := engine.xorBits(leftShare, rightShare)
			if err != nil {
				t.Fatalf("xorBits(): %v", err)
			}
			if got := mpcTestOpenBit(t, engine, exclusive); got != left^right {
				t.Fatalf("xor(%d, %d) = %d, want %d", left, right, got, left^right)
			}

			disjunction, err := engine.orBits(leftShare, rightShare)
			if err != nil {
				t.Fatalf("orBits(): %v", err)
			}
			wantDisjunction := Coefficient(0)
			if left|right != 0 {
				wantDisjunction = 1
			}
			if got := mpcTestOpenBit(t, engine, disjunction); got != wantDisjunction {
				t.Fatalf("or(%d, %d) = %d, want %d", left, right, got, wantDisjunction)
			}
		}
	}
	for _, value := range values {
		if got := mpcTestOpenBit(t, engine, engine.notBit(engine.dealPublic(value))); got != 1-value {
			t.Fatalf("not(%d) = %d, want %d", value, got, 1-value)
		}
	}
}

// TestMPCArithmeticPublicAdderExhaustive sweeps every six-bit operand and every
// six-bit constant, including the carry out of the top cell.
func TestMPCArithmeticPublicAdderExhaustive(t *testing.T) {
	engine := mpcTestEngine(0x11)
	for operand := 0; operand < 64; operand++ {
		bits := mpcTestBits(engine, uint32(operand), 6)
		for constant := 0; constant < 64; constant++ {
			sum, carry, err := engine.addPublicConstant(bits, uint32(constant))
			if err != nil {
				t.Fatalf("addPublicConstant(%d, %d): %v", operand, constant, err)
			}
			total := operand + constant
			for index := 0; index < 6; index++ {
				want := Coefficient(total >> uint(index) & 1)
				if got := mpcTestOpenBit(t, engine, sum[index]); got != want {
					t.Fatalf("add(%d, %d) bit %d = %d, want %d", operand, constant, index, got, want)
				}
			}
			if got := mpcTestOpenBit(t, engine, carry); got != Coefficient(total>>6&1) {
				t.Fatalf("add(%d, %d) carry = %d, want %d", operand, constant, got, total>>6&1)
			}
		}
	}
	if _, _, err := engine.addPublicConstant(mpcTestBits(engine, 0, 6), 64); !errors.Is(err, ErrInvalidMPCOperation) {
		t.Fatalf("over-wide constant error = %v, want %v", err, ErrInvalidMPCOperation)
	}
	if _, _, err := engine.addPublicConstant(nil, 0); !errors.Is(err, ErrInvalidMPCOperation) {
		t.Fatalf("empty adder error = %v, want %v", err, ErrInvalidMPCOperation)
	}
}

// TestMPCArithmeticReductionRestore sweeps the shared-bit adder that restores
// the canonical residue, for the reduction constant and for Q, the mask the
// decomposition's restore step uses.
func TestMPCArithmeticReductionRestore(t *testing.T) {
	engine := mpcTestEngine(0x12)
	samples := []uint32{0, 1, 2, Q - 1, Q - 2, mpcReductionConstant, (Q - 1) / 2, 1 << 23, 1<<24 - 2}
	for _, mask := range []uint32{mpcReductionConstant, Q} {
		for _, sample := range samples {
			for _, carryValue := range []Coefficient{0, 1} {
				bits := mpcTestBits(engine, sample, mpcCanonicalWidth)
				sharedBit := engine.dealPublic(carryValue)
				restored, err := engine.addSharedBitAtConstantPositions(bits, sharedBit, mask)
				if err != nil {
					t.Fatalf("addSharedBitAtConstantPositions(%d, %d, %d): %v", sample, carryValue, mask, err)
				}
				want := (sample + uint32(carryValue)*mask) % (1 << mpcCanonicalWidth)
				for index := 0; index < mpcCanonicalWidth; index++ {
					wantBit := Coefficient(want >> uint(index) & 1)
					if got := mpcTestOpenBit(t, engine, restored[index]); got != wantBit {
						t.Fatalf("restore(%d, %d, %d) bit %d = %d, want %d", sample, carryValue, mask, index, got, wantBit)
					}
				}
			}
		}
	}
	if _, err := engine.addSharedBitAtConstantPositions(mpcTestBits(engine, 0, 8), engine.dealPublic(1), 1<<9); !errors.Is(err, ErrInvalidMPCOperation) {
		t.Fatalf("over-wide mask error = %v, want %v", err, ErrInvalidMPCOperation)
	}
}

// mpcTestBoundaryCoefficients returns the values where the reference rounding or
// the reduction can change behavior, including two-power and alpha multiples.
func mpcTestBoundaryCoefficients() []Coefficient {
	values := []Coefficient{0, 1, 2, 126, 127, 128, 129, Q - 1, Q - 2, Q / 2, Q/2 + 1, (Q - 1) / 2}
	for power := uint(0); power <= 23; power++ {
		base := Coefficient(1) << power
		if base >= Q {
			break
		}
		values = append(values, base-1, base, base+1, Normalize(-base), Normalize(-base+1))
	}
	for multiple := 0; multiple <= 16; multiple++ {
		center := Coefficient(multiple) * Coefficient(2*Gamma2)
		if center >= Q {
			break
		}
		values = append(values, center-1, center, center+1, Normalize(center-1), Normalize(center+1))
	}
	return values
}

// TestMPCArithmeticDecompositionMatchesCanonicalBits requires the distributed
// decomposition to reproduce the canonical bits of every boundary value.
func TestMPCArithmeticDecompositionMatchesCanonicalBits(t *testing.T) {
	engine := mpcTestEngine(0x13)
	for _, value := range mpcTestBoundaryCoefficients() {
		bits, err := engine.decomposeCanonical(engine.dealPublic(value))
		if err != nil {
			t.Fatalf("decomposeCanonical(%d): %v", value, err)
		}
		canonical := uint32(Normalize(value))
		for index := range bits {
			want := Coefficient(canonical >> uint(index) & 1)
			if got := mpcTestOpenBit(t, engine, bits[index]); got != want {
				t.Fatalf("decompose(%d) bit %d = %d, want %d", value, index, got, want)
			}
		}
	}
}

// mpcTestHighBitTransitions scans the reference rounding for every canonical
// value where HighBits changes, and returns those boundaries with two
// neighbors each, the wraparound values, and deterministic random samples.
func mpcTestHighBitTransitions() []Coefficient {
	var values []Coefficient
	previous, _ := decomposeCoefficient(0)
	for canonical := Coefficient(1); canonical < Q; canonical++ {
		current, _ := decomposeCoefficient(canonical)
		if current != previous {
			for delta := Coefficient(-2); delta <= 2; delta++ {
				values = append(values, Normalize(canonical+delta))
			}
		}
		previous = current
	}
	values = append(values, 0, 1, 2, Q-1, Q-2, Q/2, (Q-1)/2)
	state := uint64(0x9E3779B97F4A7C15)
	for count := 0; count < 96; count++ {
		state = state*6364136223846793005 + 1442695040888963407
		values = append(values, Coefficient(state%Q))
	}
	return values
}

// referenceHighBits evaluates the reference rounding on one coefficient.
func referenceHighBits(coefficient Coefficient) Coefficient {
	high, _ := decomposeCoefficient(coefficient)
	return high
}

// TestMPCArithmeticHighBitsMatchesReference requires the distributed formula to
// reproduce decomposeCoefficient bit-exactly across every high-bit transition.
func TestMPCArithmeticHighBitsMatchesReference(t *testing.T) {
	engine := mpcTestEngine(0x14)
	transitions := mpcTestHighBitTransitions()
	if len(transitions) < 32 {
		t.Fatalf("transition scan found %d values, want at least 32", len(transitions))
	}
	for _, value := range transitions {
		got, err := engine.openHighBitsCoefficient(engine.dealPublic(value))
		if err != nil {
			t.Fatalf("openHighBitsCoefficient(%d): %v", value, err)
		}
		want := referenceHighBits(value)
		if got != want {
			t.Fatalf("openHighBitsCoefficient(%d) = %d, want %d", value, got, want)
		}
		if got < 0 || got > highBitsMask {
			t.Fatalf("openHighBitsCoefficient(%d) = %d outside the sixteen-valued range", value, got)
		}
	}
}

// TestMPCArithmeticHighBitsOpensOnlyTheHighPart requires two different secrets
// inside the same bucket to produce the same opened value.
func TestMPCArithmeticHighBitsOpensOnlyTheHighPart(t *testing.T) {
	engine := mpcTestEngine(0x15)
	first := Coefficient(3*2*Gamma2 + 1000)
	second := first + 12345
	if referenceHighBits(first) != referenceHighBits(second) {
		t.Fatalf("test setup: %d and %d are not in the same bucket", first, second)
	}
	firstHigh, err := engine.openHighBitsCoefficient(engine.dealPublic(first))
	if err != nil {
		t.Fatalf("openHighBitsCoefficient(%d): %v", first, err)
	}
	secondHigh, err := engine.openHighBitsCoefficient(engine.dealPublic(second))
	if err != nil {
		t.Fatalf("openHighBitsCoefficient(%d): %v", second, err)
	}
	if firstHigh != secondHigh {
		t.Fatalf("same bucket opened %d and %d", firstHigh, secondHigh)
	}
	if firstHigh != referenceHighBits(first) {
		t.Fatalf("opened %d, want %d", firstHigh, referenceHighBits(first))
	}
}

// TestMPCArithmeticLowResidueMatchesReferenceLowBits requires the linear low
// residue to match the canonical residue of the reference centered LowBits.
func TestMPCArithmeticLowResidueMatchesReferenceLowBits(t *testing.T) {
	engine := mpcTestEngine(0x16)
	for _, value := range mpcTestBoundaryCoefficients() {
		residue, err := engine.lowResidue(engine.dealPublic(value))
		if err != nil {
			t.Fatalf("lowResidue(%d): %v", value, err)
		}
		polynomial := Poly{}
		polynomial[0] = value
		_, low := Decompose(polynomial)
		mpcTestOpenAndCompare(t, engine, residue, Normalize(low[0]), "lowResidue residue")
	}
}

// mpcTestReferenceInRange evaluates the centered predicate in the clear.
func mpcTestReferenceInRange(coefficient Coefficient, bound Coefficient) bool {
	centered := int64(Normalize(coefficient))
	if centered > Q/2 {
		centered -= Q
	}
	if centered < 0 {
		centered = -centered
	}
	return centered < int64(bound)
}

// TestMPCArithmeticNormPredicateBoundaries pins the exact acceptance decision at
// B-1, B, B+1 and at the residue wraparound values for both rejection bounds.
func TestMPCArithmeticNormPredicateBoundaries(t *testing.T) {
	engine := mpcTestEngine(0x17)
	for _, bound := range []Coefficient{NormBoundZ, NormBoundR0} {
		values := []Coefficient{
			0, 1, bound - 1, bound, bound + 1,
			Q - 1, Q - 2, Q - bound, Q - bound + 1, Q - bound + 2,
			bound/2 + 1, Normalize(-bound / 2),
		}
		for _, value := range values {
			passed, err := engine.checkNorm(engine.dealPublic(value), bound)
			if err != nil {
				t.Fatalf("checkNorm(%d, %d): %v", value, bound, err)
			}
			want := mpcTestReferenceInRange(value, bound)
			if passed != want {
				t.Fatalf("checkNorm(%d, %d) = %v, want %v", value, bound, passed, want)
			}
		}
	}
	for _, bound := range []Coefficient{0, -1, (Q-1)/2 + 1, Q} {
		if _, err := engine.checkNorm(engine.dealPublic(1), bound); !errors.Is(err, ErrInvalidMPCOperation) {
			t.Fatalf("bound %d error = %v, want %v", bound, err, ErrInvalidMPCOperation)
		}
	}
}

// TestMPCArithmeticRecordedEntryPoints covers the K-row high-bit opening and the
// recorded norm decision, including a legitimate rejection.
func TestMPCArithmeticRecordedEntryPoints(t *testing.T) {
	engine := mpcTestEngine(0x18)

	highRecord := mpcTestCommittedRecord(t, 0x21)
	var vector []sharedPoly
	var wantHigh VectorK
	for row := 0; row < K; row++ {
		var polynomial Poly
		for index := 0; index < N; index++ {
			polynomial[index] = Coefficient((row*N + index) * 32749 % Q)
		}
		vector = append(vector, engine.dealPublicPoly(polynomial))
		wantHigh[row] = HighBits(polynomial)
	}
	gotHigh, err := engine.openHighBitsVector(highRecord, vector)
	if err != nil {
		t.Fatalf("openHighBitsVector(): %v", err)
	}
	wantEncoded, err := EncodePublicHighBits(wantHigh)
	if err != nil {
		t.Fatalf("EncodePublicHighBits(): %v", err)
	}
	if gotHigh != wantEncoded {
		t.Fatal("openHighBitsVector does not match the reference high bits")
	}

	normRecord := mpcTestCommittedRecord(t, 0x22)
	inRange := mpcTestDealtVector(engine, 2)
	passed, err := engine.checkNormVector(normRecord, inRange, NormBoundZ)
	if err != nil {
		t.Fatalf("checkNormVector(in range): %v", err)
	}
	if !passed {
		t.Fatal("in-range vector was rejected")
	}

	rejectedRecord := mpcTestCommittedRecord(t, 0x23)
	outOfRange := mpcTestDealtVector(engine, 2)
	outOfRange[1][200] = engine.addPublic(outOfRange[1][200], NormBoundZ)
	passed, err = engine.checkNormVector(rejectedRecord, outOfRange, NormBoundZ)
	if err != nil {
		t.Fatalf("checkNormVector(rejection): %v", err)
	}
	if passed {
		t.Fatal("out-of-range vector was accepted")
	}

	if _, err := engine.checkNormVector(mpcTestCommittedRecord(t, 0x24), nil, NormBoundZ); !errors.Is(err, ErrInvalidMPCOperation) {
		t.Fatalf("empty vector error = %v, want %v", err, ErrInvalidMPCOperation)
	}
}

// TestMPCArithmeticEntryPointsRequireCommittedRecord requires the one-time
// lifecycle: no record or an uncommitted record cannot drive an operation.
func TestMPCArithmeticEntryPointsRequireCommittedRecord(t *testing.T) {
	engine := mpcTestEngine(0x19)
	vector := mpcTestDealtVector(engine, K)
	shortVector := mpcTestDealtVector(engine, K-1)
	record := mpcTestRecord(t, 0x31)
	if _, err := engine.openHighBitsVector(record, shortVector); !errors.Is(err, ErrInvalidMPCOperation) {
		t.Fatalf("short vector error = %v, want %v", err, ErrInvalidMPCOperation)
	}
	if _, err := engine.openHighBitsVector(record, vector); !errors.Is(err, ErrInvalidMPCOperation) {
		t.Fatalf("uncommitted record error = %v, want %v", err, ErrInvalidMPCOperation)
	}
	if _, err := engine.openHighBitsVector(nil, vector); !errors.Is(err, ErrInvalidMPCOperation) {
		t.Fatalf("nil record error = %v, want %v", err, ErrInvalidMPCOperation)
	}
	if _, err := engine.checkNormVector(mpcTestRecord(t, 0x32), mpcTestDealtVector(engine, 1), NormBoundZ); !errors.Is(err, ErrInvalidMPCOperation) {
		t.Fatalf("uncommitted norm record error = %v, want %v", err, ErrInvalidMPCOperation)
	}
	if state := record.State(); state != PreprocessingAvailable {
		t.Fatalf("record state = %v, want available after rejected calls", state)
	}
	commitMPCTestRecord(t, record, 0x31)
	if _, err := engine.openHighBitsVector(record, vector); err != nil {
		t.Fatalf("committed record: %v", err)
	}
}

// TestMPCArithmeticValueTamperBurnsRecord requires a tampered value share to
// abort with a MAC failure, burn the record, and fail closed afterwards.
func TestMPCArithmeticValueTamperBurnsRecord(t *testing.T) {
	engine := mpcTestEngine(0x1A)
	record := mpcTestCommittedRecord(t, 0x41)
	vector := mpcTestDealtVector(engine, K)
	tampered := append([]sharedPoly(nil), vector...)
	tampered[2][5][0].value = Normalize(tampered[2][5][0].value + 7)
	if _, err := engine.openHighBitsVector(record, tampered); !errors.Is(err, ErrMPCMacFailure) {
		t.Fatalf("tampered value error = %v, want %v", err, ErrMPCMacFailure)
	}
	if state := record.State(); state != PreprocessingBurned {
		t.Fatalf("record state = %v, want burned", state)
	}
	if _, err := engine.openHighBitsVector(record, vector); !errors.Is(err, ErrMPCAborted) {
		t.Fatalf("reuse error = %v, want %v", err, ErrMPCAborted)
	}
	if _, err := record.SecretHandle(mpcTestSession(0x41)); !errors.Is(err, ErrPreprocessingBurned) {
		t.Fatalf("handle error = %v, want %v", err, ErrPreprocessingBurned)
	}
}

// TestMPCArithmeticMacTamperFailsClosed requires a tampered MAC share to abort
// rather than produce a high bit.
func TestMPCArithmeticMacTamperFailsClosed(t *testing.T) {
	engine := mpcTestEngine(0x1B)
	record := mpcTestCommittedRecord(t, 0x42)
	vector := mpcTestDealtVector(engine, K)
	tampered := append([]sharedPoly(nil), vector...)
	tampered[4][9][0].mac = Normalize(tampered[4][9][0].mac + 1)
	if _, err := engine.openHighBitsVector(record, tampered); !errors.Is(err, ErrMPCMacFailure) {
		t.Fatalf("tampered MAC error = %v, want %v", err, ErrMPCMacFailure)
	}
	if state := record.State(); state != PreprocessingBurned {
		t.Fatalf("record state = %v, want burned", state)
	}
}

// TestMPCArithmeticNormTamperFailsClosed requires the norm circuit to abort on a
// tampered share instead of opening a decision bit.
func TestMPCArithmeticNormTamperFailsClosed(t *testing.T) {
	engine := mpcTestEngine(0x1C)
	record := mpcTestCommittedRecord(t, 0x43)
	vector := mpcTestDealtVector(engine, 2)
	tampered := append([]sharedPoly(nil), vector...)
	tampered[0][3][0].value = Normalize(tampered[0][3][0].value + 1)
	if _, err := engine.checkNormVector(record, tampered, NormBoundZ); !errors.Is(err, ErrMPCMacFailure) {
		t.Fatalf("tampered norm error = %v, want %v", err, ErrMPCMacFailure)
	}
	if state := record.State(); state != PreprocessingBurned {
		t.Fatalf("record state = %v, want burned", state)
	}
	if _, err := engine.checkNormVector(record, vector, NormBoundZ); !errors.Is(err, ErrMPCAborted) {
		t.Fatalf("reuse error = %v, want %v", err, ErrMPCAborted)
	}
}

// TestMPCArithmeticMultiplyDetectsCorruptInput requires the Beaver multiply to
// detect a corrupt triple or a corrupt operand at the next opening.
func TestMPCArithmeticMultiplyDetectsCorruptInput(t *testing.T) {
	engine := mpcTestEngine(0x1D)
	product, err := engine.multiplyWithTriple(engine.dealPublic(7), engine.dealPublic(11), engine.dealerTriple())
	if err != nil {
		t.Fatalf("multiplyWithTriple(): %v", err)
	}
	mpcTestOpenAndCompare(t, engine, product, 77, "valid triple")

	corruptTriple := engine.dealerTriple()
	corruptTriple.c[0].value = Normalize(corruptTriple.c[0].value + 1)
	product, err = engine.multiplyWithTriple(engine.dealPublic(7), engine.dealPublic(11), corruptTriple)
	if err != nil {
		t.Fatalf("multiplyWithTriple(corrupt triple): %v", err)
	}
	if _, err := engine.open(product); !errors.Is(err, ErrMPCMacFailure) {
		t.Fatalf("corrupt triple error = %v, want %v", err, ErrMPCMacFailure)
	}

	corruptOperand := engine.dealPublic(7)
	corruptOperand[3].value = Normalize(corruptOperand[3].value + 3)
	if _, err := engine.multiplyWithTriple(corruptOperand, engine.dealPublic(11), engine.dealerTriple()); !errors.Is(err, ErrMPCMacFailure) {
		t.Fatalf("corrupt operand error = %v, want %v", err, ErrMPCMacFailure)
	}
}

// TestMPCArithmeticOpenBitRejectsNonBit requires the bit invariant to be checked
// after every opening, so a tampered MAC or a non-bit cannot pass as a bit.
func TestMPCArithmeticOpenBitRejectsNonBit(t *testing.T) {
	engine := mpcTestEngine(0x1E)
	for _, value := range []Coefficient{0, 1} {
		if got := mpcTestOpenBit(t, engine, engine.dealPublic(value)); got != value {
			t.Fatalf("openBit(%d) = %d, want %d", value, got, value)
		}
	}
	for _, value := range []Coefficient{2, Q - 1} {
		if _, err := engine.openBit(engine.dealPublic(value)); !errors.Is(err, ErrInvalidMPCOperation) {
			t.Fatalf("openBit(%d) error = %v, want %v", value, err, ErrInvalidMPCOperation)
		}
	}
}

// TestMPCArithmeticCostEnvelope pins the per-coefficient work of the reference
// circuits. The public-constant ripple reuses one product per cell for both the
// sum term and the carry, and only the shared-bit adder pays a second product
// at its set positions, so every multiplication count below is structural and
// constant. The openings counter counts every open, including the two blinded
// Beaver openings each multiplication pays; the leak-relevant openings are only
// the masked decomposition difference and the four high bits.
func TestMPCArithmeticCostEnvelope(t *testing.T) {
	engine := mpcTestEngine(0x1F)
	cases := []struct {
		name            string
		run             func() error
		multiplications int
		openings        int
	}{
		{
			// Two 24-cell constant ripples (2 * 23) plus the 34 products of the
			// shared-bit adder: one real opening plus two per multiplication.
			name: "decomposeCanonical",
			run: func() error {
				_, err := engine.decomposeCanonical(engine.dealPublic(12345))
				return err
			},
			multiplications: 80,
			openings:        161,
		},
		{
			// Decomposition plus the 49 of the shift/rounding ripple: 6 for the OR
			// of bits 0..6, 16 for F = bits[7..22] + t, and 27 for
			// F + (F << 10) + 2^21. The four high bits are the only extra openings.
			name: "openHighBitsCoefficient",
			run: func() error {
				_, err := engine.openHighBitsCoefficient(engine.dealPublic(12345))
				return err
			},
			multiplications: 129,
			openings:        263,
		},
		{
			// Decomposition plus the two 22-cell comparator ripples over the 23
			// canonical bits and the OR of their results; the comparator carries
			// are public, so only the OR and the final decision bit open.
			name: "checkNorm",
			run: func() error {
				_, err := engine.checkNorm(engine.dealPublic(12345), NormBoundZ)
				return err
			},
			multiplications: 125,
			openings:        252,
		},
		{
			// One recorded K-row opening costs one per-coefficient high-bit
			// opening per row and column.
			name: "openHighBitsVector",
			run: func() error {
				record := mpcTestCommittedRecord(t, 0x51)
				_, err := engine.openHighBitsVector(record, mpcTestDealtVector(engine, K))
				return err
			},
			multiplications: K * N * 129,
			openings:        K * N * 263,
		},
	}
	for _, testCase := range cases {
		beforeMultiplications, beforeOpenings := engine.multiplications, engine.openings
		if err := testCase.run(); err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}
		multiplications := engine.multiplications - beforeMultiplications
		openings := engine.openings - beforeOpenings
		if multiplications != testCase.multiplications || openings != testCase.openings {
			t.Fatalf(
				"%s cost = %d multiplications / %d openings, want %d / %d",
				testCase.name, multiplications, openings, testCase.multiplications, testCase.openings,
			)
		}
	}
}
