// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// This file is the in-process reference implementation of the authenticated
// arithmetic that Dilithium3 v1 threshold signing needs. It drives all four
// active signers and the preprocessing dealer inside one process, so it is a
// correctness, leakage, and cost reference and never a production path: no
// deployment may depend on it. Dealerless generation of the mask and triple
// material, the networked executor that carries evidence between processes, and
// the side-channel review remain open obligations of
// docs/superpowers/specs/2026-09-24-qau-dilithium3-v1-signing-mpc.md.

import (
	"crypto/sha3"
	"errors"
	"fmt"
)

const (
	// mpcPartyCount is the number of active signers the reference engine drives.
	mpcPartyCount = 4

	// mpcCanonicalBits is the number of canonical bits a decomposition hands to
	// the circuits. Bit 23 is always zero because Q < 2^23.
	mpcCanonicalBits = 23

	// mpcCanonicalWidth is the width of the addition that restores the canonical
	// residue: r + d < 2*Q < 2^24.
	mpcCanonicalWidth = 24

	// mpcReductionConstant is 2^24 - Q. Adding it to r + d turns the single
	// reduction into a carry, and adding that carry back undoes the reduction.
	mpcReductionConstant = 1<<mpcCanonicalWidth - Q

	// mpcScaleWidth is the width of F + (F << 10) before the rounding constant
	// is added: F is 17 bits, so the scaled value needs 27.
	mpcScaleWidth = 27

	// mpcHighShiftedBitsCount is the width of the rounded canonical value above
	// bit 6: bits 7..22 of the canonical value plus the carry the rounding with
	// 127 adds to them.
	mpcHighShiftedBitsCount = 17

	// mpcHighBitsCount is the number of bits the reference high-bit formula
	// exports: ((h7*1025 + 2^21) >> 22) & 15.
	mpcHighBitsCount = 4

	// mpcReferenceEngineDomain separates the reference engine's deterministic
	// stream from every protocol stream.
	mpcReferenceEngineDomain = "QAU-TDILITHIUM3-V1-MPC-REFERENCE-ENGINE"
)

var (
	// ErrMPCAborted reports that one-time material was already burned. Every
	// later operation on that material fails closed with this error.
	ErrMPCAborted = errors.New("Dilithium3 v1 MPC attempt aborted")

	// ErrMPCMacFailure reports a failed authentication check on an opened value.
	// It is a sticky abort: the bound one-time record burns and no value derived
	// from the shares is released.
	ErrMPCMacFailure = errors.New("Dilithium3 v1 MPC authentication check failed")

	// ErrInvalidMPCOperation reports malformed arithmetic input: a non-bit where
	// a bit is required, a constant wider than its cell vector, a rejection bound
	// outside the checked range, or a missing or uncommitted one-time record.
	ErrInvalidMPCOperation = errors.New("invalid Dilithium3 v1 MPC arithmetic operation")
)

// authenticatedCoefficient is one party's share of a value together with its MAC
// share. For the sharing of a value x with MAC key shares Delta_p and
// Delta = sum_p Delta_p, the invariant is
//
//	sum_p value_p = x  (mod q)   and   sum_p mac_p = Delta * x  (mod q).
//
// Every linear operation preserves both halves; every nonlinear operation is
// followed by a MAC check before any opened value is accepted.
type authenticatedCoefficient struct {
	value Coefficient
	mac   Coefficient
}

// sharedCoefficient is one additively shared field element across the reference
// engine's parties. The type is internal: no exported API carries a share, and
// an authenticated sharing is only ever opened through open and openBit.
type sharedCoefficient [mpcPartyCount]authenticatedCoefficient

// sharedPoly is one additively shared polynomial.
type sharedPoly [N]sharedCoefficient

// mpcTriple is one Beaver multiplication triple: c shares the product a*b and
// every component carries its own authentication.
type mpcTriple struct {
	a sharedCoefficient
	b sharedCoefficient
	c sharedCoefficient
}

// mpcArithmeticEngine simulates the four active signers, the MAC key, and the
// preprocessing dealer of the reference construction. The counters exist so the
// cost envelope is measured rather than assumed.
type mpcArithmeticEngine struct {
	macKeys         [mpcPartyCount]Coefficient
	macKey          Coefficient
	random          *sha3.SHAKE
	multiplications int
	openings        int
}

// newMPCArithmeticEngine builds a deterministic reference engine. The seed
// replaces the distributed randomness a real deployment samples inside each
// party, which is why this engine must never be reachable from a production
// path.
func newMPCArithmeticEngine(seed [32]byte) *mpcArithmeticEngine {
	stream := sha3.NewSHAKE256()
	_, _ = stream.Write([]byte(mpcReferenceEngineDomain))
	_, _ = stream.Write(seed[:])
	engine := &mpcArithmeticEngine{random: stream}
	for party := range engine.macKeys {
		for {
			key := engine.sampleUniform()
			if key != 0 {
				engine.macKeys[party] = key
				engine.macKey = Normalize(engine.macKey + key)
				break
			}
		}
	}
	return engine
}

// nextBytes fills the destination from the deterministic stream. SHAKE never
// fails and always fills the buffer, so the loop has no error path.
func (engine *mpcArithmeticEngine) nextBytes(destination []byte) {
	for filled := 0; filled < len(destination); {
		read, _ := engine.random.Read(destination[filled:])
		filled += read
	}
}

// sampleUniform draws one coefficient uniformly from [0, Q) by rejection over
// three-byte reads.
func (engine *mpcArithmeticEngine) sampleUniform() Coefficient {
	var sample [3]byte
	for {
		engine.nextBytes(sample[:])
		value := uint32(sample[0]) | uint32(sample[1])<<8 | uint32(sample[2])<<16
		if value < Q {
			return Coefficient(value)
		}
	}
}

// dealPublic returns an authenticated sharing of a public value. The value is
// held once and every party MACs the whole value with its own key share, which
// is exactly what makes the MAC check linear.
func (engine *mpcArithmeticEngine) dealPublic(value Coefficient) sharedCoefficient {
	canonical := Normalize(value)
	var share sharedCoefficient
	share[0].value = canonical
	for party := range share {
		share[party].mac = normalizeInt64(int64(engine.macKeys[party]) * int64(canonical))
	}
	return share
}

// dealPublicPoly shares every coefficient of a public polynomial.
func (engine *mpcArithmeticEngine) dealPublicPoly(polynomial Poly) sharedPoly {
	var share sharedPoly
	for index := range polynomial {
		share[index] = engine.dealPublic(polynomial[index])
	}
	return share
}

// dealerTriple samples one Beaver triple. A production deployment generates
// triples without a dealer, so this is reference scaffolding only.
func (engine *mpcArithmeticEngine) dealerTriple() mpcTriple {
	left := engine.sampleUniform()
	right := engine.sampleUniform()
	return mpcTriple{
		a: engine.dealPublic(left),
		b: engine.dealPublic(right),
		c: engine.dealPublic(normalizeInt64(int64(left) * int64(right))),
	}
}

// dealerMask samples the uniform decomposition mask together with its bit
// sharing. Bit 23 of the mask is not shared because a canonical coefficient
// never has it set.
func (engine *mpcArithmeticEngine) dealerMask() (sharedCoefficient, [mpcCanonicalBits]sharedCoefficient) {
	mask := engine.sampleUniform()
	var bits [mpcCanonicalBits]sharedCoefficient
	for index := range bits {
		bits[index] = engine.dealPublic(mask >> uint(index) & 1)
	}
	return engine.dealPublic(mask), bits
}

// addShares adds two authenticated sharings coefficient-wise.
func addShares(left, right sharedCoefficient) sharedCoefficient {
	var result sharedCoefficient
	for party := range result {
		result[party] = authenticatedCoefficient{
			value: normalizeInt64(int64(left[party].value) + int64(right[party].value)),
			mac:   normalizeInt64(int64(left[party].mac) + int64(right[party].mac)),
		}
	}
	return result
}

// subShares subtracts two authenticated sharings coefficient-wise.
func subShares(left, right sharedCoefficient) sharedCoefficient {
	var result sharedCoefficient
	for party := range result {
		result[party] = authenticatedCoefficient{
			value: normalizeInt64(int64(left[party].value) - int64(right[party].value)),
			mac:   normalizeInt64(int64(left[party].mac) - int64(right[party].mac)),
		}
	}
	return result
}

// scaleShare multiplies an authenticated sharing by a public scalar.
func scaleShare(share sharedCoefficient, scalar Coefficient) sharedCoefficient {
	var result sharedCoefficient
	for party := range result {
		result[party] = authenticatedCoefficient{
			value: normalizeInt64(int64(share[party].value) * int64(scalar)),
			mac:   normalizeInt64(int64(share[party].mac) * int64(scalar)),
		}
	}
	return result
}

// twiceShare doubles a sharing without a multiplication: both halves are linear.
func twiceShare(share sharedCoefficient) sharedCoefficient {
	return addShares(share, share)
}

// addPublic adds a public constant: the value lands once, and every party's MAC
// share absorbs Delta_p times the constant so the invariant survives.
func (engine *mpcArithmeticEngine) addPublic(share sharedCoefficient, constant Coefficient) sharedCoefficient {
	canonical := Normalize(constant)
	result := share
	result[0].value = normalizeInt64(int64(result[0].value) + int64(canonical))
	for party := range result {
		result[party].mac = normalizeInt64(
			int64(result[party].mac) + int64(engine.macKeys[party])*int64(canonical),
		)
	}
	return result
}

// subPublic subtracts a public constant.
func (engine *mpcArithmeticEngine) subPublic(share sharedCoefficient, constant Coefficient) sharedCoefficient {
	return engine.addPublic(share, normalizeInt64(-int64(constant)))
}

// notBit returns 1 - x for a shared bit. Negation and a public constant are
// linear, so this costs no multiplication.
func (engine *mpcArithmeticEngine) notBit(share sharedCoefficient) sharedCoefficient {
	return engine.addPublic(scaleShare(share, -1), 1)
}

// open reveals a sharing and verifies its authentication. A failed check is
// returned as ErrMPCMacFailure and the caller must treat the attempt as aborted.
func (engine *mpcArithmeticEngine) open(share sharedCoefficient) (Coefficient, error) {
	engine.openings++
	var value Coefficient
	for party := range share {
		value = normalizeInt64(int64(value) + int64(share[party].value))
	}
	var residue Coefficient
	for party := range share {
		term := normalizeInt64(int64(share[party].mac) - int64(engine.macKeys[party])*int64(value))
		residue = normalizeInt64(int64(residue) + int64(term))
	}
	if residue != 0 {
		return 0, ErrMPCMacFailure
	}
	return value, nil
}

// openBit opens a shared bit and rejects every value that is not zero or one.
// The MAC check runs first: a forged share must abort, not classify.
func (engine *mpcArithmeticEngine) openBit(share sharedCoefficient) (Coefficient, error) {
	value, err := engine.open(share)
	if err != nil {
		return 0, err
	}
	if value != 0 && value != 1 {
		return 0, fmt.Errorf("%w: opened value %d is not a bit", ErrInvalidMPCOperation, value)
	}
	return value, nil
}

// multiply runs one Beaver multiplication with a fresh triple.
func (engine *mpcArithmeticEngine) multiply(left, right sharedCoefficient) (sharedCoefficient, error) {
	return engine.multiplyWithTriple(left, right, engine.dealerTriple())
}

// multiplyWithTriple computes shares of left*right from the triple (a, b, c).
// The two masked differences are opened, so the opened values are independent of
// the operands, and the result stays authenticated.
func (engine *mpcArithmeticEngine) multiplyWithTriple(
	left, right sharedCoefficient,
	triple mpcTriple,
) (sharedCoefficient, error) {
	engine.multiplications++
	delta, err := engine.open(subShares(left, triple.a))
	if err != nil {
		return sharedCoefficient{}, err
	}
	epsilon, err := engine.open(subShares(right, triple.b))
	if err != nil {
		return sharedCoefficient{}, err
	}
	product := addShares(
		triple.c,
		addShares(scaleShare(triple.b, delta), scaleShare(triple.a, epsilon)),
	)
	return engine.addPublic(product, normalizeInt64(int64(delta)*int64(epsilon))), nil
}

// andBits multiplies two shared bits.
func (engine *mpcArithmeticEngine) andBits(left, right sharedCoefficient) (sharedCoefficient, error) {
	return engine.multiply(left, right)
}

// xorBits returns x + y - 2xy from one multiplication.
func (engine *mpcArithmeticEngine) xorBits(left, right sharedCoefficient) (sharedCoefficient, error) {
	product, err := engine.multiply(left, right)
	if err != nil {
		return sharedCoefficient{}, err
	}
	return subShares(addShares(left, right), twiceShare(product)), nil
}

// orBits returns x + y - xy from one multiplication.
func (engine *mpcArithmeticEngine) orBits(left, right sharedCoefficient) (sharedCoefficient, error) {
	product, err := engine.multiply(left, right)
	if err != nil {
		return sharedCoefficient{}, err
	}
	return subShares(addShares(left, right), product), nil
}

// addPublicConstant adds a public constant to a shared bit vector with a ripple
// carry and returns the sum bits plus the carry out of the top cell. Every cell
// after the first costs one multiplication: the product a*c is both the sum term
// (a xor c = a + c - 2ac) and the carry (a and c).
func (engine *mpcArithmeticEngine) addPublicConstant(
	bits []sharedCoefficient,
	constant uint32,
) ([]sharedCoefficient, sharedCoefficient, error) {
	if len(bits) == 0 {
		return nil, sharedCoefficient{}, fmt.Errorf("%w: empty adder", ErrInvalidMPCOperation)
	}
	if uint64(constant) >= uint64(1)<<uint(len(bits)) {
		return nil, sharedCoefficient{}, fmt.Errorf(
			"%w: constant %d does not fit %d cells", ErrInvalidMPCOperation, constant, len(bits),
		)
	}
	sum := make([]sharedCoefficient, len(bits))
	var carry sharedCoefficient
	for index, operand := range bits {
		addendIsSet := constant&(1<<uint(index)) != 0
		if index == 0 {
			// The first cell has a public zero carry, so it is free.
			if addendIsSet {
				sum[0] = engine.notBit(operand)
				carry = operand
			} else {
				sum[0] = operand
			}
			continue
		}
		product, err := engine.multiply(operand, carry)
		if err != nil {
			return nil, sharedCoefficient{}, err
		}
		if addendIsSet {
			// operand + 1 + carry: sum = not(operand xor carry), carry = operand or carry.
			sum[index] = engine.notBit(subShares(addShares(operand, carry), twiceShare(product)))
			carry = subShares(addShares(operand, carry), product)
			continue
		}
		sum[index] = subShares(addShares(operand, carry), twiceShare(product))
		carry = product
	}
	return sum, carry, nil
}

// addSharedBitAtConstantPositions adds one shared bit at every set position of a
// public mask and returns the sum modulo the cell vector width. A cell without
// the addend costs one multiplication; a cell with it costs two, because the
// addend, the operand, and the carry are then all shared bits.
func (engine *mpcArithmeticEngine) addSharedBitAtConstantPositions(
	bits []sharedCoefficient,
	bit sharedCoefficient,
	mask uint32,
) ([]sharedCoefficient, error) {
	if len(bits) == 0 {
		return nil, fmt.Errorf("%w: empty adder", ErrInvalidMPCOperation)
	}
	if uint64(mask) >= uint64(1)<<uint(len(bits)) {
		return nil, fmt.Errorf("%w: mask %d does not fit %d cells", ErrInvalidMPCOperation, mask, len(bits))
	}
	sum := make([]sharedCoefficient, len(bits))
	var carry sharedCoefficient
	for index, operand := range bits {
		addendIsSet := mask&(1<<uint(index)) != 0
		if index == 0 {
			// The first cell has a public zero carry, so it is free.
			if !addendIsSet {
				sum[0] = operand
				continue
			}
			product, err := engine.andBits(operand, bit)
			if err != nil {
				return nil, err
			}
			sum[0] = subShares(addShares(operand, bit), twiceShare(product))
			carry = product
			continue
		}
		if !addendIsSet {
			product, err := engine.andBits(operand, carry)
			if err != nil {
				return nil, err
			}
			sum[index] = subShares(addShares(operand, carry), twiceShare(product))
			carry = product
			continue
		}
		// operand xor bit xor carry with carry = majority(operand, bit, carry).
		// ab and (a xor b)*c cannot both be set, so the two products add directly.
		leftProduct, err := engine.andBits(operand, bit)
		if err != nil {
			return nil, err
		}
		firstSum := subShares(addShares(operand, bit), twiceShare(leftProduct))
		rightProduct, err := engine.andBits(firstSum, carry)
		if err != nil {
			return nil, err
		}
		sum[index] = subShares(addShares(firstSum, carry), twiceShare(rightProduct))
		carry = addShares(leftProduct, rightProduct)
	}
	return sum, nil
}

// decomposeCanonical returns the 23 authenticated canonical bits of a shared
// coefficient. A dealer-provided uniform mask hides the value while the masked
// difference is opened, the reduction carry is extracted from the public
// constant addition, and the carry is added back to restore the canonical
// residue. Bit 23 of that residue is provably zero, so 23 bits suffice.
func (engine *mpcArithmeticEngine) decomposeCanonical(share sharedCoefficient) ([mpcCanonicalBits]sharedCoefficient, error) {
	mask, maskBits := engine.dealerMask()
	difference, err := engine.open(subShares(share, mask))
	if err != nil {
		return [mpcCanonicalBits]sharedCoefficient{}, err
	}
	lane := make([]sharedCoefficient, mpcCanonicalWidth)
	copy(lane, maskBits[:])
	masked, _, err := engine.addPublicConstant(lane, uint32(difference))
	if err != nil {
		return [mpcCanonicalBits]sharedCoefficient{}, err
	}
	// masked holds the bits of s = mask + difference. Adding 2^24 - Q wraps
	// exactly when s >= Q, so the sum output holds s + (2^24 - Q) modulo 2^24
	// and the carry is the reduction bit g = [s >= Q]. Because 2^24 - Q = -Q
	// modulo 2^24 and s < 2Q, adding (1-g)*Q undoes the wrap when g is set and
	// cancels the constant when g is clear, leaving exactly the canonical
	// residue s - g*Q.
	wrapped, reductionCarry, err := engine.addPublicConstant(masked, mpcReductionConstant)
	if err != nil {
		return [mpcCanonicalBits]sharedCoefficient{}, err
	}
	canonical, err := engine.addSharedBitAtConstantPositions(wrapped, engine.notBit(reductionCarry), Q)
	if err != nil {
		return [mpcCanonicalBits]sharedCoefficient{}, err
	}
	var bits [mpcCanonicalBits]sharedCoefficient
	copy(bits[:], canonical[:mpcCanonicalBits])
	return bits, nil
}

// highBitsFromBits evaluates the reference formula on the canonical bits without
// opening anything: t = OR(bits[0..6]) is the carry of adding 127,
// F = bits[7..22] + t, and the four bits of F*1025 + 2^21 above bit 22 are the
// high part. The carry that would become bit 26 is the u = 16 case, which the
// reference formula drops with & 15.
func (engine *mpcArithmeticEngine) highBitsFromBits(
	bits [mpcCanonicalBits]sharedCoefficient,
) ([mpcHighBitsCount]sharedCoefficient, error) {
	empty := [mpcHighBitsCount]sharedCoefficient{}
	shift := bits[0]
	for index := 1; index <= 6; index++ {
		combined, err := engine.orBits(shift, bits[index])
		if err != nil {
			return empty, err
		}
		shift = combined
	}
	scaled := make([]sharedCoefficient, mpcHighShiftedBitsCount)
	scaledCarry, err := engine.andBits(bits[7], shift)
	if err != nil {
		return empty, err
	}
	scaled[0] = subShares(addShares(bits[7], shift), twiceShare(scaledCarry))
	for index := 1; index < mpcHighShiftedBitsCount-1; index++ {
		product, err := engine.andBits(bits[7+index], scaledCarry)
		if err != nil {
			return empty, err
		}
		scaled[index] = subShares(addShares(bits[7+index], scaledCarry), twiceShare(product))
		scaledCarry = product
	}
	scaled[mpcHighShiftedBitsCount-1] = scaledCarry
	return engine.scaleHighBits(scaled)
}

// scaleHighBits completes the reference formula by computing F + (F << 10) plus
// the public rounding constant 2^21 and keeping the four bits above bit 22.
func (engine *mpcArithmeticEngine) scaleHighBits(scaled []sharedCoefficient) ([mpcHighBitsCount]sharedCoefficient, error) {
	empty := [mpcHighBitsCount]sharedCoefficient{}
	if len(scaled) != mpcHighShiftedBitsCount {
		return empty, fmt.Errorf(
			"%w: scaled value has %d bits, want %d", ErrInvalidMPCOperation, len(scaled), mpcHighShiftedBitsCount,
		)
	}
	// P = F + (F << shift) over 27 cells: the low ten cells carry only F's own
	// bits, the next seven add two shared bits and a shared carry, and the top
	// ten add one shared bit to a shared carry.
	const shift = 10
	sum := make([]sharedCoefficient, 0, mpcScaleWidth)
	sum = append(sum, scaled[:shift]...)
	upper := scaled[shift:mpcHighShiftedBitsCount]
	lower := scaled[:mpcHighShiftedBitsCount-shift]
	var carry sharedCoefficient
	for offset := range upper {
		leftOperand := upper[offset]
		rightOperand := lower[offset]
		product, err := engine.andBits(leftOperand, rightOperand)
		if err != nil {
			return empty, err
		}
		partial := subShares(addShares(leftOperand, rightOperand), twiceShare(product))
		if offset == 0 {
			// The first cell with two addends has a public zero carry.
			sum = append(sum, partial)
			carry = product
			continue
		}
		carryProduct, err := engine.andBits(partial, carry)
		if err != nil {
			return empty, err
		}
		sum = append(sum, subShares(addShares(partial, carry), twiceShare(carryProduct)))
		carry = addShares(product, carryProduct)
	}
	for _, addend := range scaled[mpcHighShiftedBitsCount-shift:] {
		product, err := engine.andBits(addend, carry)
		if err != nil {
			return empty, err
		}
		sum = append(sum, subShares(addShares(addend, carry), twiceShare(product)))
		carry = product
	}
	// Adding 2^21 touches only cell 21: with a public zero carry in, its sum bit
	// is the negated operand and its carry out is the operand itself. Cells
	// 22..25 then propagate that carry with no addend of their own, and the
	// carry out of cell 25 is the u = 16 case that & 15 discards.
	var high [mpcHighBitsCount]sharedCoefficient
	carry = sum[21]
	for offset := range high {
		operand := sum[22+offset]
		product, err := engine.andBits(operand, carry)
		if err != nil {
			return empty, err
		}
		high[offset] = subShares(addShares(operand, carry), twiceShare(product))
		carry = product
	}
	return high, nil
}

// openHighBitsCoefficient opens w1 for one shared coefficient: the four
// sixteen-valued high bits and nothing else.
func (engine *mpcArithmeticEngine) openHighBitsCoefficient(share sharedCoefficient) (Coefficient, error) {
	bits, err := engine.decomposeCanonical(share)
	if err != nil {
		return 0, err
	}
	high, err := engine.highBitsFromBits(bits)
	if err != nil {
		return 0, err
	}
	var value Coefficient
	for index := range high {
		bit, err := engine.openBit(high[index])
		if err != nil {
			return 0, err
		}
		value = normalizeInt64(int64(value) + int64(bit)<<uint(index))
	}
	return value, nil
}

// lowResidue returns shares of canonical - high*alpha. The high bits stay shared,
// so nothing is opened here, and the residue names the same canonical value as
// the centered LowBits because centring only changes the representative.
func (engine *mpcArithmeticEngine) lowResidue(share sharedCoefficient) (sharedCoefficient, error) {
	bits, err := engine.decomposeCanonical(share)
	if err != nil {
		return sharedCoefficient{}, err
	}
	high, err := engine.highBitsFromBits(bits)
	if err != nil {
		return sharedCoefficient{}, err
	}
	residue := share
	for index := range high {
		weight := Coefficient(int64(2*Gamma2) << uint(index))
		residue = subShares(residue, scaleShare(high[index], weight))
	}
	return residue, nil
}

// atLeastPublicConstant returns the shared bit [value >= constant] for a
// canonical shared value: adding 2^23 - constant overflows exactly then.
func (engine *mpcArithmeticEngine) atLeastPublicConstant(
	bits [mpcCanonicalBits]sharedCoefficient,
	constant Coefficient,
) (sharedCoefficient, error) {
	if constant < 1 || constant >= Q {
		return sharedCoefficient{}, fmt.Errorf(
			"%w: comparison constant %d outside [1, %d)", ErrInvalidMPCOperation, constant, Q,
		)
	}
	_, carry, err := engine.addPublicConstant(bits[:], uint32(1)<<mpcCanonicalBits-uint32(constant))
	if err != nil {
		return sharedCoefficient{}, err
	}
	return carry, nil
}

// validateNormBound rejects bounds the canonical-residue predicate is not exact
// for: the checked value must be centered far inside (-Q/2, Q/2), and both
// comparison constants must stay positive.
func validateNormBound(bound Coefficient) error {
	if bound < 1 || bound > (Q-1)/2 {
		return fmt.Errorf("%w: norm bound %d outside [1, %d]", ErrInvalidMPCOperation, bound, (Q-1)/2)
	}
	return nil
}

// inRangeBit returns the shared bit [|centered| < bound]: either the canonical
// residue is below the bound, or it is at least Q - bound + 1.
func (engine *mpcArithmeticEngine) inRangeBit(share sharedCoefficient, bound Coefficient) (sharedCoefficient, error) {
	bits, err := engine.decomposeCanonical(share)
	if err != nil {
		return sharedCoefficient{}, err
	}
	carry, err := engine.atLeastPublicConstant(bits, bound)
	if err != nil {
		return sharedCoefficient{}, err
	}
	high, err := engine.atLeastPublicConstant(bits, Q-bound+1)
	if err != nil {
		return sharedCoefficient{}, err
	}
	return engine.orBits(engine.notBit(carry), high)
}

// checkNorm opens exactly one bit: whether every coefficient of one shared
// coefficient is below the bound in absolute value. This is the per-coefficient
// reference seam; the recorded entry point is checkNormVector.
func (engine *mpcArithmeticEngine) checkNorm(share sharedCoefficient, bound Coefficient) (bool, error) {
	if err := validateNormBound(bound); err != nil {
		return false, err
	}
	bit, err := engine.inRangeBit(share, bound)
	if err != nil {
		return false, err
	}
	value, err := engine.openBit(bit)
	if err != nil {
		return false, err
	}
	return value == 1, nil
}

// checkMPCRecordUsable enforces the one-time lifecycle at the recorded entry
// points: only a record committed to exactly one signing session may drive an
// operation, and a burned record aborts every later call.
func checkMPCRecordUsable(record *PreprocessingRecord) error {
	if record == nil {
		return fmt.Errorf("%w: missing preprocessing record", ErrInvalidMPCOperation)
	}
	switch record.State() {
	case PreprocessingCommitted:
		return nil
	case PreprocessingBurned:
		return ErrMPCAborted
	default:
		return fmt.Errorf("%w: preprocessing record is not committed", ErrInvalidMPCOperation)
	}
}

// abortMPCAttempt burns the bound one-time record and returns the failure cause.
func abortMPCAttempt(record *PreprocessingRecord, cause error) error {
	if record == nil {
		return cause
	}
	return record.RejectOpening(cause)
}

// openHighBitsVector computes w1 for one K-row shared vector behind a committed
// one-time record. Any failure burns the record and returns the cause, so a
// later call on the same record fails closed with ErrMPCAborted.
func (engine *mpcArithmeticEngine) openHighBitsVector(
	record *PreprocessingRecord,
	vector []sharedPoly,
) (PublicHighBits, error) {
	if err := checkMPCRecordUsable(record); err != nil {
		return PublicHighBits{}, err
	}
	if len(vector) != K {
		return PublicHighBits{}, fmt.Errorf("%w: %d rows, want %d", ErrInvalidMPCOperation, len(vector), K)
	}
	var high VectorK
	for row := range vector {
		for index := 0; index < N; index++ {
			value, err := engine.openHighBitsCoefficient(vector[row][index])
			if err != nil {
				return PublicHighBits{}, abortMPCAttempt(record, err)
			}
			high[row][index] = value
		}
	}
	return EncodePublicHighBits(high)
}

// checkNormVector opens exactly one bit: whether every coefficient of every row
// is below the bound in absolute value. A rejection is a normal protocol
// outcome and opens nothing else; the attempt and its record are then burned by
// the caller's attempt lifecycle. Any failure burns the record here instead.
func (engine *mpcArithmeticEngine) checkNormVector(
	record *PreprocessingRecord,
	vector []sharedPoly,
	bound Coefficient,
) (bool, error) {
	if err := checkMPCRecordUsable(record); err != nil {
		return false, err
	}
	if len(vector) == 0 {
		return false, fmt.Errorf("%w: empty norm vector", ErrInvalidMPCOperation)
	}
	if err := validateNormBound(bound); err != nil {
		return false, err
	}
	var aggregate sharedCoefficient
	started := false
	for row := range vector {
		for index := 0; index < N; index++ {
			bit, err := engine.inRangeBit(vector[row][index], bound)
			if err != nil {
				return false, abortMPCAttempt(record, err)
			}
			if !started {
				aggregate = bit
				started = true
				continue
			}
			combined, err := engine.andBits(aggregate, bit)
			if err != nil {
				return false, abortMPCAttempt(record, err)
			}
			aggregate = combined
		}
	}
	value, err := engine.openBit(aggregate)
	if err != nil {
		return false, abortMPCAttempt(record, err)
	}
	return value == 1, nil
}

// addPoly adds two shared polynomials coefficient-wise.
func addPoly(left, right sharedPoly) sharedPoly {
	var result sharedPoly
	for index := range result {
		result[index] = addShares(left[index], right[index])
	}
	return result
}

// subPoly subtracts two shared polynomials coefficient-wise.
func subPoly(left, right sharedPoly) sharedPoly {
	var result sharedPoly
	for index := range result {
		result[index] = subShares(left[index], right[index])
	}
	return result
}

// scalePoly multiplies a shared polynomial by a public scalar.
func scalePoly(value sharedPoly, scalar Coefficient) sharedPoly {
	var result sharedPoly
	for index := range result {
		result[index] = scaleShare(value[index], scalar)
	}
	return result
}

// addPublicPoly adds a public constant to every coefficient of a shared
// polynomial.
func (engine *mpcArithmeticEngine) addPublicPoly(value sharedPoly, constant Coefficient) sharedPoly {
	var result sharedPoly
	for index := range result {
		result[index] = engine.addPublic(value[index], constant)
	}
	return result
}

// subPublicPoly subtracts a public constant from every coefficient.
func (engine *mpcArithmeticEngine) subPublicPoly(value sharedPoly, constant Coefficient) sharedPoly {
	return engine.addPublicPoly(value, normalizeInt64(-int64(constant)))
}

// sharedPolyNTT holds one shared polynomial in the NTT domain, per party, for
// the value and MAC halves.
type sharedPolyNTT struct {
	value [mpcPartyCount]NTTPoly
	mac   [mpcPartyCount]NTTPoly
}

// forwardSharedPoly evaluates every party's value and MAC share of a shared
// polynomial at the mode3 NTT points. The transform is a Z_q-linear map, so it
// commutes with the sharing and preserves the MAC invariant.
func forwardSharedPoly(value sharedPoly) sharedPolyNTT {
	var transformed sharedPolyNTT
	for party := 0; party < mpcPartyCount; party++ {
		var valuePoly, macPoly Poly
		for index := 0; index < N; index++ {
			valuePoly[index] = value[index][party].value
			macPoly[index] = value[index][party].mac
		}
		transformed.value[party] = ForwardNTT(valuePoly)
		transformed.mac[party] = ForwardNTT(macPoly)
	}
	return transformed
}

// inverseSharedPoly rebuilds one shared polynomial from party-wise transformed
// value and MAC shares.
func inverseSharedPoly(transformed sharedPolyNTT) sharedPoly {
	var result sharedPoly
	for party := 0; party < mpcPartyCount; party++ {
		valuePoly := InverseNTT(transformed.value[party])
		macPoly := InverseNTT(transformed.mac[party])
		for index := 0; index < N; index++ {
			result[index][party] = authenticatedCoefficient{value: valuePoly[index], mac: macPoly[index]}
		}
	}
	return result
}

// multiplyPublicNTTPoly multiplies a shared polynomial by a public polynomial
// already in NTT form. Multiplication by a public polynomial is Z_q-linear, so
// no Beaver triple is needed and no MAC check is required: every party's value
// and MAC shares are transformed independently.
func multiplyPublicNTTPoly(publicNTT NTTPoly, value sharedPoly) sharedPoly {
	transformed := forwardSharedPoly(value)
	for party := 0; party < mpcPartyCount; party++ {
		transformed.value[party] = pointwiseMultiply(transformed.value[party], publicNTT)
		transformed.mac[party] = pointwiseMultiply(transformed.mac[party], publicNTT)
	}
	return inverseSharedPoly(transformed)
}

// multiplyPublicPoly multiplies a shared polynomial by a public polynomial.
func multiplyPublicPoly(public Poly, value sharedPoly) sharedPoly {
	return multiplyPublicNTTPoly(ForwardNTT(public), value)
}

// multiplyPublicMatrixVector computes matrix * vector over shared rows. The
// shared rows are transformed once and reused across every output row, which is
// what makes the public-matrix products of one nonce and one carry cheap.
func multiplyPublicMatrixVector(matrix Matrix, vector []sharedPoly) ([]sharedPoly, error) {
	if len(vector) != L {
		return nil, fmt.Errorf("%w: %d matrix-vector rows, want %d", ErrInvalidMPCOperation, len(vector), L)
	}
	var columns [L]sharedPolyNTT
	for row := 0; row < L; row++ {
		columns[row] = forwardSharedPoly(vector[row])
	}
	result := make([]sharedPoly, K)
	for outRow := 0; outRow < K; outRow++ {
		var accumulated sharedPolyNTT
		for inRow := 0; inRow < L; inRow++ {
			for party := 0; party < mpcPartyCount; party++ {
				for index := 0; index < N; index++ {
					accumulated.value[party][index] = normalizeInt64(
						int64(accumulated.value[party][index]) +
							int64(columns[inRow].value[party][index])*int64(matrix[outRow][inRow][index]),
					)
					accumulated.mac[party][index] = normalizeInt64(
						int64(accumulated.mac[party][index]) +
							int64(columns[inRow].mac[party][index])*int64(matrix[outRow][inRow][index]),
					)
				}
			}
		}
		result[outRow] = inverseSharedPoly(accumulated)
	}
	return result, nil
}
