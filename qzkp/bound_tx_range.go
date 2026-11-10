// Quantaureum Node source, version 1.0.0.
package qzkp

// TxRangeProof: range proof bound to the REAL transaction Pedersen commitment.
//
// Root fix for audit run-8 (fingerprint node/qzkp-range-proof-self-reference,
// ported as run-4 C-2): the previous confidential range-proof path proved the
// range statement about a MiMC commitment chosen by the prover and linked it,
// via a Schnorr discrete-log proof, to ANOTHER prover-chosen commitment
// Pedersen(MiMC(amount), r). The real transaction commitment
// C_tx = amount*G + blinding*H never entered any proof statement, so the
// range-checked value and the committed value could differ (self-reference).
//
// Binding C_tx into the Schnorr challenge hash was evaluated and REJECTED:
// the Groth16 witness and the Sigma-protocol witness are independent, so a
// prover can honestly satisfy both proofs with different values. Hashing
// C_tx into the Fiat-Shamir challenge only prevents transcript replay; it
// does not create a cross-proof witness equation. The only sound binding
// within this architecture is to make C_tx itself a public input of the
// Groth16 circuit and constrain the Pedersen opening equation in-circuit:
//
//	C_tx == value*G + blinding*H   AND   value < 2^BitLength
//
// G and H are fixed, linearly independent generators, so the opening
// (value, blinding) of C_tx is unique (Pedersen binding) and the circuit
// statement is equivalent to "the transaction amount committed in C_tx is in
// [0, 2^BitLength)". The in-circuit G1 scalar multiplications use gnark's
// emulated (non-native) BLS12-381 G1 arithmetic in complete (infinity- and
// zero-scalar-safe) mode so that degenerate witnesses such as amount = 0
// remain provable and the constraint system stays sound for every witness.

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/algopts"
	sw_bls12381 "github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/quantaureum/qau/pedersen"
)

var (
	// ErrTxCommitmentMismatch is returned when a TxRangeProof is verified
	// against a commitment other than the one it was generated for.
	ErrTxCommitmentMismatch = errors.New("qzkp: tx range proof is not bound to the supplied commitment")
	// ErrInvalidTxCommitment is returned when the bound commitment bytes do
	// not decode to a valid BLS12-381 G1 point (on curve, in subgroup).
	ErrInvalidTxCommitment = errors.New("qzkp: invalid transaction commitment point")
)

const (
	// txRangeCacheKeyPrefix is the versioned circuit cache key prefix. The
	// embedded circuit statement (public input set) is part of the R1CS
	// fingerprint: any change to the statement MUST bump the version so old
	// proving/verifying keys are never mixed with the new circuit.
	txRangeCacheKeyPrefix = "tx_range_v1"
)

// G1PointSize is the compressed size of a BLS12-381 G1 point in bytes. The
// transaction commitment bound into a TxRangeProof is exactly this long.
const G1PointSize = 48

// MaxTxRangeBitLength is the largest bit length for which the range
// constraint is meaningful. The BLS12-381 scalar-field modulus r is a
// 255-bit prime in [2^254, 2^255), so for bitLength >= 255 every canonical
// field element satisfies value < 2^bitLength and the in-circuit upper-bit
// assertions would be vacuous (the proof would degrade to plain
// opening-knowledge with no range guarantee). Proving AND verifying reject
// anything above this bound (fail-closed).
const MaxTxRangeBitLength = 254

// TxRangeProof is a Groth16 range proof whose public input is the real
// transaction Pedersen commitment. See the package-level comment above for
// the binding rationale.
type TxRangeProof struct {
	// ProofBytes is the serialized Groth16 proof over (value, blinding).
	ProofBytes []byte
	// TxCommitment is the 48-byte compressed G1 point C_tx the proof is
	// bound to. It MUST byte-match the commitment extracted from the
	// transaction by the verifier.
	TxCommitment []byte
	// BitLength is the range bound exponent: the proven statement is
	// value < 2^BitLength.
	BitLength int
}

// MarshalBinary serializes the proof as
//
//	[4B len ProofBytes][ProofBytes][4B len TxCommitment][TxCommitment][4B BitLength]
func (trp *TxRangeProof) MarshalBinary() ([]byte, error) {
	if trp == nil {
		return nil, errors.New("qzkp: cannot marshal nil TxRangeProof")
	}
	if err := trp.validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 4+len(trp.ProofBytes)+4+len(trp.TxCommitment)+4)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(trp.ProofBytes)))
	buf = append(buf, trp.ProofBytes...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(trp.TxCommitment)))
	buf = append(buf, trp.TxCommitment...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(trp.BitLength))
	return buf, nil
}

// UnmarshalBinary parses the MarshalBinary format. It is strict: the bound
// commitment must be exactly 48 bytes, the proof bytes non-empty and the bit
// length in [1, MaxTxRangeBitLength]. Proofs that do not carry the full
// binding are rejected here rather than at verification time (fail-closed).
func (trp *TxRangeProof) UnmarshalBinary(data []byte) error {
	const maxFieldSize = 10 * 1024 * 1024
	if trp == nil {
		return errors.New("qzkp: cannot unmarshal into nil TxRangeProof")
	}
	if len(data) < 4 {
		return errors.New("qzkp: insufficient data for TxRangeProof")
	}
	offset := 0
	proofLenU32 := binary.BigEndian.Uint32(data[offset:])
	proofLen, err := safeUint32ToInt(proofLenU32)
	if err != nil {
		return fmt.Errorf("qzkp: ProofBytes length overflow: %w", err)
	}
	offset += 4
	if proofLen == 0 {
		return errors.New("qzkp: ProofBytes is empty")
	}
	if proofLen > maxFieldSize {
		return fmt.Errorf("qzkp: ProofBytes length %d exceeds maximum %d", proofLen, maxFieldSize)
	}
	if offset+proofLen > len(data) {
		return errors.New("qzkp: insufficient data for ProofBytes")
	}
	proofBytes := make([]byte, proofLen)
	copy(proofBytes, data[offset:offset+proofLen])
	offset += proofLen

	if offset+4 > len(data) {
		return errors.New("qzkp: insufficient data for TxCommitment length")
	}
	commitLenU32 := binary.BigEndian.Uint32(data[offset:])
	commitLen, err := safeUint32ToInt(commitLenU32)
	if err != nil {
		return fmt.Errorf("qzkp: TxCommitment length overflow: %w", err)
	}
	offset += 4
	// The bound commitment is a compressed G1 point: exactly 48 bytes. Any
	// other length means the proof is not in the circuit-bound format.
	if commitLen != G1PointSize {
		return fmt.Errorf("qzkp: TxCommitment length %d, expected %d", commitLen, G1PointSize)
	}
	if offset+commitLen > len(data) {
		return errors.New("qzkp: insufficient data for TxCommitment")
	}
	commitBytes := make([]byte, commitLen)
	copy(commitBytes, data[offset:offset+commitLen])
	offset += commitLen

	if offset+4 > len(data) {
		return errors.New("qzkp: insufficient data for BitLength")
	}
	bitLengthU32 := binary.BigEndian.Uint32(data[offset:])
	bitLength, err := safeUint32ToInt(bitLengthU32)
	if err != nil {
		return fmt.Errorf("qzkp: BitLength overflow: %w", err)
	}
	offset += 4
	if bitLength <= 0 || bitLength > MaxTxRangeBitLength {
		return fmt.Errorf("qzkp: BitLength %d out of range [1, %d]", bitLength, MaxTxRangeBitLength)
	}
	// Strict trailing-byte check: the MarshalBinary format is a fixed
	// field sequence, so any bytes left after BitLength mean the payload
	// is not the canonical encoding. Reject instead of silently ignoring
	// the tail (a decoded proof must round-trip byte-exactly).
	if offset != len(data) {
		return fmt.Errorf("qzkp: %d trailing bytes after BitLength", len(data)-offset)
	}

	trp.ProofBytes = proofBytes
	trp.TxCommitment = commitBytes
	trp.BitLength = bitLength
	return nil
}

// validate checks the structural invariants that the proving and verifying
// paths both rely on.
func (trp *TxRangeProof) validate() error {
	if trp == nil {
		return errors.New("qzkp: nil TxRangeProof")
	}
	if len(trp.ProofBytes) == 0 {
		return errors.New("qzkp: ProofBytes is empty")
	}
	if len(trp.TxCommitment) != G1PointSize {
		return fmt.Errorf("qzkp: TxCommitment length %d, expected %d", len(trp.TxCommitment), G1PointSize)
	}
	if trp.BitLength <= 0 || trp.BitLength > MaxTxRangeBitLength {
		return fmt.Errorf("qzkp: BitLength %d out of range [1, %d]", trp.BitLength, MaxTxRangeBitLength)
	}
	return nil
}

// txRangeCircuit proves knowledge of (value, blinding) opening the REAL
// transaction Pedersen commitment with the amount in range:
//
//	C_tx == value*G + blinding*H   AND   value < 2^bitLen
//
// Value and Blinding are emulated BLS12-381 scalar-field elements; Commit is
// the public C_tx point (emulated base field X/Y).
type txRangeCircuit struct {
	// Value is the committed amount (private witness).
	Value emulated.Element[sw_bls12381.ScalarField] `gnark:"value"`
	// Blinding is the Pedersen blinding factor of the transaction
	// commitment (private witness).
	Blinding emulated.Element[sw_bls12381.ScalarField] `gnark:"blinding"`
	// Commit is the real transaction commitment point C_tx (public input).
	Commit sw_bls12381.G1Affine `gnark:",public"`
	// bitLen is the range bound, fixed at circuit-compile time. Changing it
	// changes the circuit fingerprint (cache key includes it).
	bitLen int
	// hGen is the fixed Pedersen H generator, embedded as a compile-time
	// constant (never a witness input). It is deterministic across processes
	// (hash-to-curve of a fixed domain string).
	hGen bls12381.G1Affine
}

func (c *txRangeCircuit) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[sw_bls12381.ScalarField, sw_bls12381.G1Affine](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}

	// Complete arithmetic keeps the constraint system sound and satisfiable
	// for degenerate witnesses (zero amount => [0]G = infinity; the identity
	// is represented as (0,0) per the gnark EVM convention).
	vG := curve.ScalarMulBase(&c.Value, algopts.WithCompleteArithmetic())
	hConst := sw_bls12381.NewG1Affine(c.hGen)
	bH := curve.ScalarMul(&hConst, &c.Blinding, algopts.WithCompleteArithmetic())
	sum := curve.AddUnified(vG, bH)
	curve.AssertIsEqual(sum, &c.Commit)

	// Range check: value in [0, 2^bitLen). ToBitsCanonical returns the unique
	// canonical (value < r) bit decomposition; asserting every bit at and
	// above bitLen is zero excludes the mod-r ambiguity and yields a strict
	// integer bound on the amount.
	frField, err := emulated.NewField[sw_bls12381.ScalarField](api)
	if err != nil {
		return fmt.Errorf("emulated scalar field: %w", err)
	}
	valueBits := frField.ToBitsCanonical(&c.Value)
	for i := c.bitLen; i < len(valueBits); i++ {
		api.AssertIsEqual(valueBits[i], 0)
	}
	return nil
}

// ProveTxValueInRange generates a Groth16 range proof bound to the REAL
// transaction commitment: it proves knowledge of (value, blinding) opening
// commitment with value < 2^bitLength.
//
// The commitment parameter is the transaction's Pedersen commitment bytes
// (48-byte compressed G1 point). The prover recomputes the canonical opening
// point from (value, blinding) and refuses to proceed if it differs from the
// supplied commitment — the proof can only ever bind to the commitment the
// transaction actually carries.
func (sp *SigmaProtocol) ProveTxValueInRange(
	value *big.Int,
	blinding *big.Int,
	bitLength int,
	commitment []byte,
	gen *pedersen.Generator,
) (*TxRangeProof, error) {
	if bitLength <= 0 || bitLength > MaxTxRangeBitLength {
		return nil, fmt.Errorf("invalid bitLength %d: must be in [1, %d]", bitLength, MaxTxRangeBitLength)
	}
	if value == nil || blinding == nil {
		return nil, ErrInvalidWitness
	}
	if value.Sign() < 0 {
		return nil, ErrInvalidWitness
	}
	maxVal := new(big.Int).Lsh(big.NewInt(1), uint(bitLength))
	if value.Cmp(maxVal) >= 0 {
		return nil, ErrInvalidWitness
	}
	if gen == nil {
		return nil, fmt.Errorf("pedersen generator is nil")
	}
	if len(commitment) != G1PointSize {
		return nil, fmt.Errorf("commitment length %d, expected %d", len(commitment), G1PointSize)
	}

	scalarField := ecc.BLS12_381.ScalarField()
	valueMod := new(big.Int).Mod(value, scalarField)
	blindingMod := new(big.Int).Mod(blinding, scalarField)
	defer func() {
		zeroBigInt(valueMod)
		zeroBigInt(blindingMod)
	}()

	// Bind to the caller's commitment: recompute the canonical opening point
	// from (value, blinding) and require byte equality with the supplied
	// commitment. This is prover-side input validation (both values are
	// prover-local), so a constant-time compare is not required; the
	// verifier-side comparison is constant-time.
	recomputed := gen.Commit(valueMod, blindingMod)
	if subtle.ConstantTimeCompare(recomputed.Bytes(), commitment) != 1 {
		return nil, ErrTxCommitmentMismatch
	}

	cacheKey := fmt.Sprintf("%s_%d", txRangeCacheKeyPrefix, bitLength)
	circuit := &txRangeCircuit{bitLen: bitLength, hGen: gen.H}
	cc, err := sp.compileCircuit(cacheKey, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	assignment := &txRangeCircuit{
		Value:    emulated.ValueOf[sw_bls12381.ScalarField](valueMod),
		Blinding: emulated.ValueOf[sw_bls12381.ScalarField](blindingMod),
		Commit:   sw_bls12381.NewG1Affine(recomputed.Point),
		bitLen:   bitLength,
		hGen:     gen.H,
	}
	witness, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := groth16.Prove(cc.ccs, cc.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}

	// Zero the witness vector: it carries the limbs of the amount and the
	// transaction blinding factor (secret material).
	if wVec, ok := witness.Vector().(fr.Vector); ok {
		for i := range wVec {
			wVec[i].SetZero()
		}
	}

	proofWriteBuf := newWriteBuffer()
	if _, err := proof.WriteTo(proofWriteBuf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}

	commitCopy := make([]byte, len(commitment))
	copy(commitCopy, commitment)
	return &TxRangeProof{
		ProofBytes:   proofWriteBuf.Bytes(),
		TxCommitment: commitCopy,
		BitLength:    bitLength,
	}, nil
}

// VerifyTxValueInRange verifies a TxRangeProof against the commitment
// extracted from the transaction. The verifier MUST pass the commitment bytes
// it read from the transaction — the proof is accepted only for the exact
// point it was generated for (constant-time byte comparison before any
// cryptographic work, so a mismatch is indistinguishable from any other
// binding failure and leaks no timing detail).
func (sp *SigmaProtocol) VerifyTxValueInRange(proof *TxRangeProof, commitment []byte) error {
	if proof == nil {
		return ErrProofVerificationFailed
	}
	if err := proof.validate(); err != nil {
		return err
	}
	if len(commitment) != G1PointSize {
		return fmt.Errorf("%w: verifier commitment length %d, expected %d", ErrInvalidTxCommitment, len(commitment), G1PointSize)
	}
	if subtle.ConstantTimeCompare(proof.TxCommitment, commitment) != 1 {
		return ErrTxCommitmentMismatch
	}

	// SetBytes enforces the on-curve and subgroup properties for BLS12-381
	// G1 (cofactor 1), so a malformed or invalid-group commitment is
	// rejected before any circuit work.
	cTx, err := pedersen.CommitmentFromBytes(proof.TxCommitment)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTxCommitment, err)
	}

	cacheKey := fmt.Sprintf("%s_%d", txRangeCacheKeyPrefix, proof.BitLength)
	cc, ok := sp.cache.get(cacheKey)
	if !ok {
		return ErrCircuitNotCompiled
	}

	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	gnarkProof := groth16.NewProof(curve)
	if _, err := gnarkProof.ReadFrom(newReadBuffer(proof.ProofBytes)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}

	// The H generator is deterministic across processes (hash-to-curve of a
	// fixed domain string), so the verifier rebuilds the same compile-time
	// constant the circuit was compiled with.
	gen, err := pedersen.NewGenerator()
	if err != nil {
		return fmt.Errorf("pedersen generator: %w", err)
	}

	// Public-only witness: the private (value, blinding) limbs are zeroed
	// placeholders; only Commit enters the public input vector.
	zeroScalar := emulated.ValueOf[sw_bls12381.ScalarField](0)
	assignment := &txRangeCircuit{
		Value:    zeroScalar,
		Blinding: zeroScalar,
		Commit:   sw_bls12381.NewG1Affine(cTx.Point),
		bitLen:   proof.BitLength,
		hGen:     gen.H,
	}
	publicWitness, err := frontend.NewWitness(assignment, curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("create public witness: %w", err)
	}
	if err := groth16.Verify(gnarkProof, cc.vk, publicWitness); err != nil {
		return ErrProofVerificationFailed
	}
	return nil
}
