// Quantaureum Node source, version 1.0.0.
package qzkp

import (
	"crypto/sha256"
	"crypto/subtle"

	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io"
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	mimc_native "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"

	"github.com/quantaureum/qau/pedersen"
	"github.com/quantaureum/qau/qrng"
)

var (
	ErrBindingVerificationFailed = errors.New("qzkp: commitment binding verification failed")
)

// safeUint32ToInt converts a uint32 to int with overflow check.
// L18-013 FIX: On 32-bit platforms (GOARCH=386, arm), int is 32 bits and
// uint32 values > MaxInt32 would overflow to negative, causing panics in
// make([]byte, n) and incorrect length comparisons.
func safeUint32ToInt(v uint32) (int, error) {
	if v > math.MaxInt32 {
		return 0, fmt.Errorf("qzkp: uint32 value %d exceeds MaxInt32 (%d)", v, math.MaxInt32)
	}
	return int(v), nil
}

type boundRangeCircuit struct {
	Value frontend.Variable `gnark:"value"`
	// audit-fix L6-001 (P0): BindingElem MUST be public so gnark PublicOnly()
	// extracts it. Without ,public, attacker can bind proof to arbitrary commitment.
	BindingElem frontend.Variable `gnark:",public"`
	Commitment  frontend.Variable `gnark:",public"`
	bitLen      int
}

func (c *boundRangeCircuit) Define(api frontend.API) error {
	// L6-046 NOTE: The AssertIsBoolean loop and sum-reconstruction + AssertIsEqual
	// below are REDUNDANT with gnark's api.ToBinary(), which already adds
	// constraints ensuring:
	//   1. Each output bit is boolean (0 or 1)
	//   2. The weighted sum of bits equals c.Value
	// The explicit checks are retained as defense-in-depth — they add redundant
	// constraints that would catch any future regression in gnark's ToBinary.
	// They are NOT removed here to avoid changing the circuit's R1CS fingerprint
	// (which would invalidate existing proving/verifying keys).
	bits := api.ToBinary(c.Value, c.bitLen)
	// (redundant) AssertIsBoolean — see L6-046 note above
	for i := 0; i < c.bitLen; i++ {
		api.AssertIsBoolean(bits[i])
	}

	// (redundant) sum reconstruction + AssertIsEqual — see L6-046 note above
	var sum frontend.Variable = 0
	for i := 0; i < c.bitLen; i++ {
		power := 1 << uint(i)
		sum = api.Add(sum, api.Mul(bits[i], power))
	}
	api.AssertIsEqual(sum, c.Value)

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("mimc init: %w", err)
	}
	h.Write(c.Value)
	h.Write(c.BindingElem)
	api.AssertIsEqual(h.Sum(), c.Commitment)

	return nil
}

type BoundRangeProof struct {
	ProofBytes   []byte
	MimcCommit   []byte
	EcCommitment []byte
	BitLength    int
	// L11-001 FIX: BindingHash cryptographically links the Groth16 proof to the
	// Schnorr binding proof. Computed as SHA3-256(MimcCommit || SchnorrR || BindingElem).
	// Both proofs must carry the same BindingHash, preventing an attacker from using
	// different values (v1 in-range for Groth16, v2 out-of-range for Pedersen).
	BindingHash []byte
}

func (brp *BoundRangeProof) MarshalBinary() ([]byte, error) {
	if brp == nil {
		return nil, nil
	}
	// R30-P4 FIX: Validate ProofBytes is non-empty before serialization.
	// An empty ProofBytes indicates an uninitialized or invalid proof that
	// would produce a valid but meaningless serialization.
	if len(brp.ProofBytes) == 0 {
		return nil, fmt.Errorf("MarshalBinary: ProofBytes is empty")
	}
	buf := make([]byte, 4+len(brp.ProofBytes)+4+len(brp.MimcCommit)+4+len(brp.EcCommitment)+4+4+len(brp.BindingHash))
	offset := 0
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(brp.ProofBytes)))
	offset += 4
	copy(buf[offset:], brp.ProofBytes)
	offset += len(brp.ProofBytes)
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(brp.MimcCommit)))
	offset += 4
	copy(buf[offset:], brp.MimcCommit)
	offset += len(brp.MimcCommit)
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(brp.EcCommitment)))
	offset += 4
	copy(buf[offset:], brp.EcCommitment)
	offset += len(brp.EcCommitment)
	binary.BigEndian.PutUint32(buf[offset:], uint32(brp.BitLength))
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(brp.BindingHash)))
	offset += 4
	copy(buf[offset:], brp.BindingHash)
	return buf, nil
}

func (brp *BoundRangeProof) UnmarshalBinary(data []byte) error {
	const maxFieldSize = 10 * 1024 * 1024
	const maxBitLength = 65536

	if len(data) < 4 {
		return fmt.Errorf("qzkp: insufficient data for BoundRangeProof")
	}
	offset := 0
	proofLenU32 := binary.BigEndian.Uint32(data[offset:])
	proofLen, err := safeUint32ToInt(proofLenU32)
	if err != nil {
		return fmt.Errorf("qzkp: ProofBytes length overflow: %w", err)
	}
	offset += 4
	if proofLen > maxFieldSize {
		return fmt.Errorf("qzkp: ProofBytes length %d exceeds maximum %d", proofLen, maxFieldSize)
	}
	if offset+proofLen > len(data) {
		return fmt.Errorf("qzkp: insufficient data for ProofBytes")
	}
	brp.ProofBytes = make([]byte, proofLen)
	copy(brp.ProofBytes, data[offset:offset+proofLen])
	offset += proofLen
	if offset+4 > len(data) {
		return fmt.Errorf("qzkp: insufficient data for MimcCommit length")
	}
	mimcLenU32 := binary.BigEndian.Uint32(data[offset:])
	mimcLen, err := safeUint32ToInt(mimcLenU32)
	if err != nil {
		return fmt.Errorf("qzkp: MimcCommit length overflow: %w", err)
	}
	offset += 4
	if mimcLen > maxFieldSize {
		return fmt.Errorf("qzkp: MimcCommit length %d exceeds maximum %d", mimcLen, maxFieldSize)
	}
	if offset+mimcLen > len(data) {
		return fmt.Errorf("qzkp: insufficient data for MimcCommit")
	}
	brp.MimcCommit = make([]byte, mimcLen)
	copy(brp.MimcCommit, data[offset:offset+mimcLen])
	offset += mimcLen
	if offset+4 > len(data) {
		return fmt.Errorf("qzkp: insufficient data for EcCommitment length")
	}
	ecLenU32 := binary.BigEndian.Uint32(data[offset:])
	ecLen, err := safeUint32ToInt(ecLenU32)
	if err != nil {
		return fmt.Errorf("qzkp: EcCommitment length overflow: %w", err)
	}
	offset += 4
	if ecLen > maxFieldSize {
		return fmt.Errorf("qzkp: EcCommitment length %d exceeds maximum %d", ecLen, maxFieldSize)
	}
	if offset+ecLen > len(data) {
		return fmt.Errorf("qzkp: insufficient data for EcCommitment")
	}
	brp.EcCommitment = make([]byte, ecLen)
	copy(brp.EcCommitment, data[offset:offset+ecLen])
	offset += ecLen
	if offset+4 > len(data) {
		return fmt.Errorf("qzkp: insufficient data for BitLength")
	}
	bitLengthU32 := binary.BigEndian.Uint32(data[offset:])
	bitLengthInt, err := safeUint32ToInt(bitLengthU32)
	if err != nil {
		return fmt.Errorf("qzkp: BitLength overflow: %w", err)
	}
	brp.BitLength = bitLengthInt
	if brp.BitLength > maxBitLength {
		return fmt.Errorf("qzkp: BitLength %d exceeds maximum %d", brp.BitLength, maxBitLength)
	}
	if offset+4 > len(data) {
		// L16-002 FIX: BindingHash is required. Proofs serialized before the
		// L11-001 binding fix lack this field and must be rejected, as they
		// do not cryptographically link the Groth16 proof to the Schnorr
		// binding proof. Accepting such proofs would allow an attacker to
		// use different values for each proof.
		return fmt.Errorf("qzkp: BindingHash is missing \u2014 proof was serialized before the binding fix and must be rejected")
	}
	bindingHashLenU32 := binary.BigEndian.Uint32(data[offset:])
	bindingHashLen, err := safeUint32ToInt(bindingHashLenU32)
	if err != nil {
		return fmt.Errorf("qzkp: BindingHash length overflow: %w", err)
	}
	offset += 4
	if bindingHashLen > maxFieldSize {
		return fmt.Errorf("qzkp: BindingHash length %d exceeds maximum %d", bindingHashLen, maxFieldSize)
	}
	if offset+bindingHashLen > len(data) {
		return fmt.Errorf("qzkp: insufficient data for BindingHash")
	}
	brp.BindingHash = make([]byte, bindingHashLen)
	copy(brp.BindingHash, data[offset:offset+bindingHashLen])
	// L16-002 FIX: Reject proofs with empty BindingHash. A valid BindingHash
	// is 32 bytes (SHA3-256). An empty BindingHash means the proof does not
	// carry the cryptographic binding and should be rejected.
	if len(brp.BindingHash) == 0 {
		return fmt.Errorf("qzkp: BindingHash is empty \u2014 proof lacks cryptographic binding")
	}
	return nil
}

func (brp *BoundRangeProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ProofBytes   []byte `json:"proof_bytes"`
		MimcCommit   []byte `json:"mimc_commit"`
		EcCommitment []byte `json:"ec_commitment"`
		BitLength    int    `json:"bit_length"`
		BindingHash  []byte `json:"binding_hash"`
	}{
		ProofBytes:   brp.ProofBytes,
		MimcCommit:   brp.MimcCommit,
		EcCommitment: brp.EcCommitment,
		BitLength:    brp.BitLength,
		BindingHash:  brp.BindingHash,
	})
}

func (brp *BoundRangeProof) UnmarshalJSON(data []byte) error {
	aux := &struct {
		ProofBytes   []byte `json:"proof_bytes"`
		MimcCommit   []byte `json:"mimc_commit"`
		EcCommitment []byte `json:"ec_commitment"`
		BitLength    int    `json:"bit_length"`
		BindingHash  []byte `json:"binding_hash"`
	}{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	brp.ProofBytes = aux.ProofBytes
	brp.MimcCommit = aux.MimcCommit
	brp.EcCommitment = aux.EcCommitment
	brp.BitLength = aux.BitLength
	brp.BindingHash = aux.BindingHash
	return nil
}

type SchnorrBindingProof struct {
	RBytes []byte
	SV     []byte
	SR     []byte
	// L11-001 FIX: BindingHash links this Schnorr proof to the corresponding
	// Groth16 proof. Must match BoundRangeProof.BindingHash.
	BindingHash []byte
}

// deriveBindingElement returns a deterministic binding element derived from
// the bitLength. AUDIT (2026) ZK-NN-5: Previously this was derived from
// ecCommitmentBytes, creating a circular dependency when we changed the
// Pedersen commitment to commit to mimcCommit (instead of value). By deriving
// bindingElem from bitLength alone, both prover and verifier can compute it
// independently without circularity. The binding element serves as a domain
// separator for the MiMC hash — it does not need to be unique per proof.
func deriveBindingElement(bitLength int) *big.Int {
	h := sha256.New()
	h.Write([]byte("Quantaureum-BoundRange-Binding-V1"))
	var bitLenBuf [4]byte
	binary.BigEndian.PutUint32(bitLenBuf[:], uint32(bitLength))
	h.Write(bitLenBuf[:])
	digest := h.Sum(nil)
	result := new(big.Int).Mod(new(big.Int).SetBytes(digest), ecc.BLS12_381.ScalarField())
	for i := range digest {
		digest[i] = 0
	}
	return result
}

// computeBindingHash computes a SHA3-256 hash that cryptographically links the
// Groth16 proof (via its MiMC commitment) to the Schnorr binding proof (via its
// R point) through the shared BindingElem.
// L11-001 FIX: This ensures both proofs reference the same value and commitment
// set, preventing an attacker from using different values for each proof.
func computeBindingHash(mimcCommit []byte, schnorrR []byte, bindingElem *big.Int) []byte {
	h := sha3.New256()
	h.Write([]byte("Quantaureum-BoundRange-BindingHash-V1"))
	h.Write(mimcCommit)
	h.Write(schnorrR)
	// FIX: Use fixed-length 32-byte encoding instead of big.Int.Bytes()
	// which produces minimal-length encoding. Minimal-length encoding leaks
	// magnitude information through the byte slice length, enabling timing/
	// storage side channels. The BLS12-381 scalar field modulus is 255 bits,
	// so 32 bytes always suffices. FillBytes panics if the value doesn't fit,
	// which is acceptable here since bindingElem is always reduced modulo the
	// scalar field (255 bits < 256 bits).
	bindingElemBytes := bindingElem.FillBytes(make([]byte, 32))
	h.Write(bindingElemBytes)
	result := h.Sum(nil)
	// R32-P3-4 FIX: Reset hash to clear internal buffers after Sum.
	// Defense-in-depth: prevents sensitive witness material from lingering
	// in the hash's internal state.
	h.Reset()
	// FIX: Zero bindingElemBytes after use. It contains a field
	// element derived from potentially sensitive witness material.
	clear(bindingElemBytes)
	return result
}

func computeBoundMiMC(value *big.Int, bindingElem *big.Int) *big.Int {
	h := mimc_native.NewMiMC()

	scalarField := ecc.BLS12_381.ScalarField()
	valueMod := new(big.Int).Mod(value, scalarField)
	bindingMod := new(big.Int).Mod(bindingElem, scalarField)

	var valueElt fr.Element
	valueElt.SetBigInt(valueMod)
	vb := valueElt.Bytes()
	h.Write(vb[:])

	var bindingElt fr.Element
	bindingElt.SetBigInt(bindingMod)
	bb := bindingElt.Bytes()
	h.Write(bb[:])

	result := h.Sum(nil)
	// FIX: Reset hasher and zero intermediate buffers to prevent
	// sensitive material from lingering in memory after computation.
	h.Reset()
	zeroBigInt(valueMod)
	zeroBigInt(bindingMod)
	valueElt.SetZero()
	bindingElt.SetZero()
	for i := range vb {
		vb[i] = 0
	}
	for i := range bb {
		bb[i] = 0
	}
	// FIX: Zero the result buffer after converting to big.Int.
	// The hash output contains derived circuit data that should not linger.
	retInt := new(big.Int).SetBytes(result)
	for i := range result {
		result[i] = 0
	}
	return retInt
}

func (sp *SigmaProtocol) ProveBoundValueInRange(
	value *big.Int,
	blinding *big.Int,
	bitLength int,
	gen *pedersen.Generator,
) (*BoundRangeProof, *SchnorrBindingProof, error) {
	if bitLength <= 0 || bitLength > 256 {
		return nil, nil, fmt.Errorf("invalid bitLength %d: must be in [1, 256]", bitLength)
	}
	if value.Sign() < 0 {
		return nil, nil, ErrInvalidWitness
	}
	maxVal := new(big.Int).Lsh(big.NewInt(1), uint(bitLength))
	if value.Cmp(maxVal) >= 0 {
		return nil, nil, ErrInvalidWitness
	}

	// AUDIT (2026) ZK-NN-5 FIX: deriveBindingElement no longer depends on
	// ecCommitment, breaking the circular dependency that prevented us from
	// changing what the Pedersen commitment commits to.
	bindingElem := deriveBindingElement(bitLength)
	mimcCommitInt := computeBoundMiMC(value, bindingElem)

	cacheKey := fmt.Sprintf("bound_range_%d", bitLength)
	circuit := &boundRangeCircuit{bitLen: bitLength}
	cc, err := sp.compileCircuit(cacheKey, circuit)
	if err != nil {
		return nil, nil, fmt.Errorf("compile: %w", err)
	}

	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}

	assignment := &boundRangeCircuit{
		Value:       value,
		BindingElem: bindingElem,
		Commitment:  mimcCommitInt,
		bitLen:      bitLength,
	}

	witness, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("create witness: %w", err)
	}

	proof, err := groth16.Prove(cc.ccs, cc.pk, witness)
	if err != nil {
		return nil, nil, fmt.Errorf("prove: %w", err)
	}

	proofWriteBuf := newWriteBuffer()
	if _, err := proof.WriteTo(proofWriteBuf); err != nil {
		return nil, nil, fmt.Errorf("serialize proof: %w", err)
	}
	proofBuf := proofWriteBuf.Bytes()

	// FIX: Use fixed-length 32-byte encoding instead of big.Int.Bytes()
	// which produces minimal-length encoding. Minimal-length encoding leaks
	// magnitude information through the byte slice length, enabling timing/
	// storage side channels. The MiMC hash output is a field element (255 bits),
	// so 32 bytes always suffices.
	mimcBytes := mimcCommitInt.FillBytes(make([]byte, 32))
	mimcCopy := make([]byte, len(mimcBytes))
	copy(mimcCopy, mimcBytes)

	// AUDIT (2026) ZK-NN-5 FIX: Create the Pedersen commitment to the
	// PUBLIC mimcCommit (not to the private value). This ensures the Schnorr
	// proof can only open the commitment to mimcCommit, which is bound to
	// value via the Groth16 circuit (MiMC(value, bindingElem) == mimcCommit).
	// An attacker cannot open the commitment to a different value because:
	//   - If ecCommitment = mimcCommit*G + blinding*H, then
	//     ecCommitment - mimcCommit*G = blinding*H
	//   - The Schnorr proof proves knowledge of blinding s.t. this holds
	//   - If the attacker used value_s != mimcCommit, then
	//     ecCommitment - mimcCommit*G = (value_s - mimcCommit)*G + blinding*H != blinding*H
	//   - The Schnorr proof would fail
	ecCommitment := gen.Commit(mimcCommitInt, blinding)
	ecBytes := ecCommitment.Bytes()
	ecCopy := make([]byte, len(ecBytes))
	copy(ecCopy, ecBytes)

	// FIX: Zero witness vector and internal commitment after proof
	// serialization and commitment bytes are copied.
	if wVec, ok := witness.Vector().(fr.Vector); ok {
		for i := range wVec {
			wVec[i].SetZero()
		}
	}
	mimcCommitInt.SetInt64(0)

	// audit-fix L6-016: Reuse the SigmaProtocol's QRNG instance instead of
	// letting generateSchnorrBinding create a new EntropyPool on every call.
	bindingQ := sp.config.QRNG
	if bindingQ == nil {
		bindingQ, err = qrng.New(qrng.DefaultQRNGConfig())
		if err != nil {
			return nil, nil, fmt.Errorf("qrng init for binding: %w", err)
		}
		defer bindingQ.Close()
	}
	// AUDIT (2026) ZK-NN-5 FIX: generateSchnorrBinding now proves knowledge
	// of blinding only (discrete log proof), not (value, blinding) Pedersen
	// opening. This is because the commitment is to the public mimcCommit.
	bindingProof, err := generateSchnorrBinding(bindingQ, blinding, ecCommitment, gen, mimcCopy)
	if err != nil {
		return nil, nil, fmt.Errorf("generate binding proof: %w", err)
	}

	// L11-001 FIX: Compute binding hash linking Groth16 and Schnorr proofs.
	// bindingHash = SHA3-256(MimcCommit || SchnorrR || BindingElem).
	bindingHash := computeBindingHash(mimcCopy, bindingProof.RBytes, bindingElem)
	// FIX: Zero bindingElem after its last use in computeBindingHash.
	zeroBigInt(bindingElem)
	bindingHashCopy := make([]byte, len(bindingHash))
	copy(bindingHashCopy, bindingHash)

	brp := &BoundRangeProof{
		ProofBytes:   proofBuf,
		MimcCommit:   mimcCopy,
		EcCommitment: ecCopy,
		BitLength:    bitLength,
		BindingHash:  bindingHashCopy,
	}
	bindingProof.BindingHash = make([]byte, len(bindingHash))
	copy(bindingProof.BindingHash, bindingHash)

	return brp, bindingProof, nil
}

func (sp *SigmaProtocol) VerifyBoundValueInRange(
	brp *BoundRangeProof,
	sbp *SchnorrBindingProof,
	gen *pedersen.Generator,
) error {
	if brp == nil || sbp == nil {
		return ErrProofVerificationFailed
	}

	if brp.BitLength <= 0 || brp.BitLength > 256 {
		return fmt.Errorf("qzkp: invalid bit length %d: must be in [1, 256]", brp.BitLength)
	}

	// L10-004 FIX: Validate that all bound witness components have matching
	// BindingElem. For bound proofs, EcCommitment and MimcCommit must both
	// be non-empty (the binding element derived from EcCommitment is the same
	// one used to compute MimcCommit). For unbound proofs, both must be empty.
	// A mismatch indicates a tampered or inconsistent proof where the binding
	// element used in one component differs from another.
	ecBound := len(brp.EcCommitment) > 0
	mimcBound := len(brp.MimcCommit) > 0
	if ecBound != mimcBound {
		return fmt.Errorf("%w: binding element mismatch - EcCommitment and MimcCommit must both be bound or both unbound",
			ErrBindingVerificationFailed)
	}

	ecCommitment, err := pedersen.CommitmentFromBytes(brp.EcCommitment)
	if err != nil {
		return fmt.Errorf("invalid EC commitment in bound range proof: %w", err)
	}

	// AUDIT (2026) ZK-NN-5: deriveBindingElement no longer takes
	// ecCommitmentBytes — it is derived from bitLength only.
	bindingElem := deriveBindingElement(brp.BitLength)
	mimcCommitInt := new(big.Int).SetBytes(brp.MimcCommit)
	// R38-P3 FIX: Zero sensitive big.Int values after use.
	defer func() {
		bindingElem.SetInt64(0)
		mimcCommitInt.SetInt64(0)
	}()

	cacheKey := fmt.Sprintf("bound_range_%d", brp.BitLength)
	cc, ok := sp.cache.get(cacheKey)
	if !ok {
		return ErrCircuitNotCompiled
	}

	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}

	gnarkProof := groth16.NewProof(curve)
	if _, err := gnarkProof.ReadFrom(newReadBuffer(brp.ProofBytes)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}

	assignment := &boundRangeCircuit{
		Commitment:  mimcCommitInt,
		BindingElem: bindingElem,
		bitLen:      brp.BitLength,
	}

	publicWitness, err := frontend.NewWitness(assignment, curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("create public witness: %w", err)
	}

	if err := groth16.Verify(gnarkProof, cc.vk, publicWitness); err != nil {
		return ErrProofVerificationFailed
	}

	// L11-001 FIX: Verify the binding hash linking Groth16 and Schnorr proofs.
	// Recompute bindingHash from public values and verify it matches both proofs.
	expectedBindingHash := computeBindingHash(brp.MimcCommit, sbp.RBytes, bindingElem)
	if subtle.ConstantTimeCompare(brp.BindingHash, expectedBindingHash) != 1 {
		return fmt.Errorf("%w: BoundRangeProof binding hash mismatch - Groth16 and Schnorr proofs are not linked",
			ErrBindingVerificationFailed)
	}
	if subtle.ConstantTimeCompare(sbp.BindingHash, expectedBindingHash) != 1 {
		return fmt.Errorf("%w: SchnorrBindingProof binding hash mismatch - Groth16 and Schnorr proofs are not linked",
			ErrBindingVerificationFailed)
	}

	if err := verifySchnorrBinding(sbp, ecCommitment, gen, brp.MimcCommit); err != nil {
		return fmt.Errorf("%w: %v", ErrBindingVerificationFailed, err)
	}

	return nil
}

// generateSchnorrBinding creates a Schnorr proof of knowledge of `blinding`
// such that ecCommitment - mimcCommit*G = blinding*H.
//
// AUDIT (2026) ZK-NN-5 FIX: This is a discrete-log Schnorr proof (not a
// Pedersen-opening proof). The previous implementation proved knowledge of
// (value, blinding) opening ecCommitment, but did not enforce that `value`
// equaled the circuit's range-checked value. By committing to the PUBLIC
// mimcCommit instead of the private value, the Schnorr proof now provably
// opens to mimcCommit, which is bound to value via the Groth16 circuit.
func generateSchnorrBinding(
	q *qrng.QRNG,
	blinding *big.Int,
	ecCommitment *pedersen.Commitment,
	gen *pedersen.Generator,
	mimcCommitBytes []byte,
) (*SchnorrBindingProof, error) {
	if q == nil {
		return nil, fmt.Errorf("qrng is nil: caller must provide a valid QRNG instance")
	}

	// Compute P = ecCommitment - mimcCommit * G
	mimcCommitInt := new(big.Int).SetBytes(mimcCommitBytes)
	mimcCommitMod := new(big.Int).Mod(mimcCommitInt, fr.Modulus())

	var mimcG bls12381.G1Affine
	mimcG.ScalarMultiplication(&gen.G, mimcCommitMod)

	var P bls12381.G1Affine
	P.Sub(&ecCommitment.Point, &mimcG)

	// Random nonce k
	k, err := q.BigInt(fr.Modulus())
	if err != nil {
		return nil, fmt.Errorf("random k: %w", err)
	}

	// R = k * H
	var R bls12381.G1Affine
	R.ScalarMultiplication(&gen.H, k)

	rFixed := R.Bytes()

	// Challenge: e = H(tag || R || P || ecCommitment || mimcCommit)
	cBytes := ecCommitment.Bytes()
	pBytes := P.Bytes()
	challengeInput := make([]byte, 0, 160+len(mimcCommitBytes))
	challengeInput = append(challengeInput, []byte("quantaureum-schnorr-binding-v3")...)
	challengeInput = append(challengeInput, rFixed[:]...)
	challengeInput = append(challengeInput, pBytes[:]...)
	challengeInput = append(challengeInput, cBytes...)
	challengeInput = append(challengeInput, mimcCommitBytes...)
	challengeHash := sha256.Sum256(challengeInput)
	e := new(big.Int).Mod(new(big.Int).SetBytes(challengeHash[:]), fr.Modulus())

	// Response: s = k + e * blinding
	s := new(big.Int).Add(k, new(big.Int).Mul(e, blinding))
	s.Mod(s, fr.Modulus())

	// Cleanup sensitive material
	defer func() {
		zeroBigInt(k)
		zeroBigInt(e)
		zeroBigInt(s)
		zeroBigInt(mimcCommitInt)
		zeroBigInt(mimcCommitMod)
		clear(challengeInput)
		clear(challengeHash[:])
		zeroG1Affine(&mimcG)
		zeroG1Affine(&P)
		zeroG1Affine(&R)
		clear(pBytes[:])
	}()

	rCopy := make([]byte, 48)
	copy(rCopy, rFixed[:])

	return &SchnorrBindingProof{
		RBytes: rCopy,
		SV:     s.FillBytes(make([]byte, 32)),
		SR:     nil, // not used in discrete log proof (ZK-NN-5 fix)
	}, nil
}

// verifySchnorrBinding verifies the discrete-log Schnorr proof:
//
//	s * H == R + e * P
//
// where P = ecCommitment - mimcCommit * G.
//
// AUDIT (2026) ZK-NN-5 FIX: This enforces that ecCommitment opens to
// mimcCommit (not to an arbitrary value), binding the Pedersen commitment
// to the Groth16 circuit's range-checked value.
func verifySchnorrBinding(
	proof *SchnorrBindingProof,
	ecCommitment *pedersen.Commitment,
	gen *pedersen.Generator,
	mimcCommitBytes []byte,
) error {
	// Compute P = ecCommitment - mimcCommit * G
	mimcCommitInt := new(big.Int).SetBytes(mimcCommitBytes)
	mimcCommitMod := new(big.Int).Mod(mimcCommitInt, fr.Modulus())

	var mimcG bls12381.G1Affine
	mimcG.ScalarMultiplication(&gen.G, mimcCommitMod)

	var P bls12381.G1Affine
	P.Sub(&ecCommitment.Point, &mimcG)

	var rPoint bls12381.G1Affine
	if _, err := rPoint.SetBytes(proof.RBytes); err != nil {
		return fmt.Errorf("invalid R point: %w", err)
	}

	// Challenge: e = H(tag || R || P || ecCommitment || mimcCommit)
	cBytes := ecCommitment.Bytes()
	pBytes := P.Bytes()
	rFixed := rPoint.Bytes()
	challengeInput := make([]byte, 0, 160+len(mimcCommitBytes))
	challengeInput = append(challengeInput, []byte("quantaureum-schnorr-binding-v3")...)
	challengeInput = append(challengeInput, rFixed[:]...)
	challengeInput = append(challengeInput, pBytes[:]...)
	challengeInput = append(challengeInput, cBytes...)
	challengeInput = append(challengeInput, mimcCommitBytes...)
	challengeHash := sha256.Sum256(challengeInput)
	e := new(big.Int).Mod(new(big.Int).SetBytes(challengeHash[:]), fr.Modulus())

	s := new(big.Int).SetBytes(proof.SV)

	defer func() {
		e.SetInt64(0)
		s.SetInt64(0)
		mimcCommitInt.SetInt64(0)
		mimcCommitMod.SetInt64(0)
		clear(challengeInput)
		clear(challengeHash[:])
		clear(rFixed[:])
		clear(cBytes[:])
		clear(pBytes[:])
		zeroG1Affine(&mimcG)
		zeroG1Affine(&P)
	}()

	// Verify: s * H == R + e * P
	var sH bls12381.G1Affine
	sH.ScalarMultiplication(&gen.H, s)

	var eP bls12381.G1Affine
	eP.ScalarMultiplication(&P, e)

	var rhs bls12381.G1Affine
	rhs.Add(&rPoint, &eP)

	defer func() {
		zeroG1Affine(&sH)
		zeroG1Affine(&eP)
		zeroG1Affine(&rhs)
	}()

	lhsBytes := sH.Bytes()
	rhsBytes := rhs.Bytes()
	defer func() {
		clear(lhsBytes[:])
		clear(rhsBytes[:])
	}()

	if subtle.ConstantTimeCompare(lhsBytes[:], rhsBytes[:]) != 1 {
		return fmt.Errorf("schnorr binding verification failed")
	}

	return nil
}

// GenerateSchnorrBinding is an exported wrapper around generateSchnorrBinding
// for use by external packages (e.g., confidential transaction range proofs).
//
// AUDIT (2026) ZK-NN-2 FIX: Allows the confidential transaction module to
// generate Schnorr binding proofs linking MiMC commitments to Pedersen
// commitments for range proofs, not just balance proofs.
func GenerateSchnorrBinding(
	q *qrng.QRNG,
	blinding *big.Int,
	ecCommitment *pedersen.Commitment,
	gen *pedersen.Generator,
	mimcCommitBytes []byte,
) (*SchnorrBindingProof, error) {
	return generateSchnorrBinding(q, blinding, ecCommitment, gen, mimcCommitBytes)
}

// VerifySchnorrBinding is an exported wrapper around verifySchnorrBinding
// for use by external packages (e.g., confidential transaction range proofs).
func VerifySchnorrBinding(
	proof *SchnorrBindingProof,
	ecCommitment *pedersen.Commitment,
	gen *pedersen.Generator,
	mimcCommitBytes []byte,
) error {
	return verifySchnorrBinding(proof, ecCommitment, gen, mimcCommitBytes)
}

type writeBuffer struct {
	data []byte
}

func newWriteBuffer() *writeBuffer {
	return &writeBuffer{}
}

func (w *writeBuffer) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

func (w *writeBuffer) Bytes() []byte {
	return w.data
}

type readBuffer struct {
	data []byte
	pos  int
}

func newReadBuffer(data []byte) *readBuffer {
	return &readBuffer{data: data}
}

func (r *readBuffer) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// zeroBigIntFunc is a package-level variable. The compiler cannot prove at
// compile time that it always points to the same function, so it cannot
// eliminate the writes as dead stores. This follows the same pattern as
// crypto.zeroBytesFunc for guaranteed memory zeroing of big.Int scalars.
var zeroBigIntFunc = func(x *big.Int) {
	if x == nil {
		return
	}
	// Bits() returns the shared internal word slice; zeroing it clears the
	// actual backing array, not a copy. Then reset the value to 0.
	bits := x.Bits()
	for i := range bits {
		bits[i] = 0
	}
	x.SetInt64(0)
}

// zeroBigInt securely zeros a big.Int's internal state to prevent sensitive
// random scalars from lingering in memory after use.
func zeroBigInt(x *big.Int) {
	zeroBigIntFunc(x)
}

// zeroG1AffineFunc is a package-level variable. The compiler cannot prove at
// compile time that it always points to the same function, so it cannot
// eliminate the writes as dead stores. This follows the same pattern as
// zeroBigIntFunc for guaranteed memory zeroing of G1Affine EC points.
var zeroG1AffineFunc = func(p *bls12381.G1Affine) {
	if p == nil {
		return
	}
	p.X.SetZero()
	p.Y.SetZero()
}

// zeroG1Affine securely zeros a bls12381.G1Affine point's internal state to
// prevent sensitive EC point data from lingering in memory after use.
// FIX: EC points derived from random scalars (rG, rH, rPoint) must
// be erased after their bytes are extracted.
func zeroG1Affine(p *bls12381.G1Affine) {
	zeroG1AffineFunc(p)
}
