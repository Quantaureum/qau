// Quantaureum Node source, version 1.0.0.
package quantum

// L14-035 SECURITY NOTE: Zero-knowledge proof sizes depend on the circuit
// complexity and the proving system used. Groth16 proofs on BLS12-381 are
// approximately 192 bytes (3 G1 elements + 2 G2 elements, compressed).
// The proof size is constant regardless of the circuit size, which is a
// key advantage of Groth16. However, the proving key size scales linearly
// with the number of constraints. Larger circuits require more memory
// for proving but produce the same compact proof size.

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	mimc_native "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"

	"github.com/quantaureum/qau/params"
)

var (
	ErrProofVerificationFailed = errors.New("zero-knowledge proof verification failed")
	ErrInvalidWitness          = errors.New("invalid witness")
	ErrCircuitNotSatisfied     = errors.New("circuit not satisfied")
)

type genericCircuit struct {
	PrivateInput frontend.Variable `gnark:"private"`
	PublicInput  frontend.Variable `gnark:",public"`
}

func (c *genericCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.PrivateInput)
	computed := h.Sum()
	api.AssertIsEqual(computed, c.PublicInput)
	return nil
}

type rangeProofCircuit struct {
	Value      frontend.Variable `gnark:"value"`
	Commitment frontend.Variable `gnark:",public"`
	// L4-010 FIX: Bind bounds to the proof as public inputs so that
	// tampering with the bounds in RangeProof invalidates the proof.
	LowerBound frontend.Variable `gnark:",public"`
	UpperBound frontend.Variable `gnark:",public"`
	bitLen     int
}

func (c *rangeProofCircuit) Define(api frontend.API) error {
	// L4-010 FIX: Cryptographically bind the bounds to the proof.
	// Previously bounds were only stored in the RangeProof struct and
	// not part of the circuit, allowing tampering without detection.
	api.AssertIsLessOrEqual(c.LowerBound, c.Value)
	api.AssertIsLessOrEqual(c.Value, c.UpperBound)

	// CRITICAL FIX: ToBinary result MUST be asserted as boolean to enforce
	// that value is in range [0, 2^bitLen). Discarding the result allows
	// gnark to optimize away the range constraint, enabling forged proofs
	// for values outside the claimed range.
	bits := api.ToBinary(c.Value, c.bitLen)
	for i := 0; i < c.bitLen; i++ {
		api.AssertIsBoolean(bits[i])
	}
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.Value)
	computed := h.Sum()
	api.AssertIsEqual(computed, c.Commitment)
	return nil
}

type ZKProof struct {
	ProofBytes   []byte
	PublicInputs [][]byte
	CircuitID    string
}

type ZKCircuit struct {
	ID   string
	Name string
	ccs  constraint.ConstraintSystem
	pk   groth16.ProvingKey
	vk   groth16.VerifyingKey
}

type ZKProver struct {
	mu                 sync.Mutex
	circuits           map[string]*ZKCircuit
	allowInsecureSetup bool
}

func NewZKProver() *ZKProver {
	return &ZKProver{
		circuits: make(map[string]*ZKCircuit),
	}
}

// SetAllowInsecureSetup enables local trusted setup (groth16.Setup with toxic
// waste). Production requires an MPC ceremony. audit-fix Round3 C-1.
// audit-fix: Block in production environment via QAU_PRODUCTION env var.
func (zkp *ZKProver) SetAllowInsecureSetup(allow bool) {
	if allow && params.IsProductionEnv() {
		log.Printf("WARNING: SetAllowInsecureSetup(true) blocked in production environment")
		return
	}
	zkp.mu.Lock()
	defer zkp.mu.Unlock()
	zkp.allowInsecureSetup = allow
}

func (zkp *ZKProver) RegisterCircuit(id string, name string) error {
	zkp.mu.Lock()
	defer zkp.mu.Unlock()

	if _, exists := zkp.circuits[id]; exists {
		return nil
	}

	// audit-fix Round3 C-1: block insecure local trusted setup unless explicitly allowed.
	if !zkp.allowInsecureSetup {
		return errors.New("quantum/zkp: insecure local trusted setup blocked; call SetAllowInsecureSetup(true) for testing only")
	}
	// FIX: Additional env var guard to prevent toxic waste generation in production.
	if os.Getenv("QZKP_DISABLE_SETUP") == "1" {
		return errors.New("quantum/zkp: local trusted setup blocked by QZKP_DISABLE_SETUP=1 env var (production mode)")
	}

	// QUANTUFIX: Log critical warning when local trusted setup is used.
	// groth16.Setup generates toxic waste (trapdoor) that is retained inside the
	// proving key. If leaked, it allows forging proofs. Production must use
	// LoadTrustedSetup() with parameters from an MPC ceremony.
	log.Printf("CRITICAL SECURITY WARNING: RegisterCircuit using local groth16.Setup — toxic waste generated. " +
		"This is NOT safe for production. Use LoadTrustedSetup() with MPC ceremony output instead.")

	circuit := &genericCircuit{}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("compile circuit %s: %w", id, err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("setup circuit %s: %w", id, err)
	}

	zkp.circuits[id] = &ZKCircuit{
		ID:   id,
		Name: name,
		ccs:  ccs,
		pk:   pk,
		vk:   vk,
	}
	return nil
}

// LoadTrustedSetup loads a pre-computed proving key and verifying key from
// external sources (e.g. from an MPC ceremony). This is the ONLY safe way to
// set up circuits in production — local groth16.Setup generates toxic waste.
//
// QUANTUFIX: Added to provide a production-safe alternative to
// RegisterCircuit's local setup. The pk and vk should come from a trusted
// MPC ceremony (e.g. permeate, p0tion, or snarkjs ceremony).
//
// AUDIT (2026) ZK-NN-7 FIX: Previously, LoadTrustedSetup stored ccs=nil,
// which meant GenerateProof would fail with "no compiled constraint system"
// for circuits loaded via this method. This made the trusted setup path
// unusable — the only way to generate proofs was through RegisterCircuit's
// local groth16.Setup (which produces toxic waste). Now LoadTrustedSetup
// compiles the genericCircuit to obtain ccs, so proofs can be generated
// with externally-provided MPC ceremony keys.
func (zkp *ZKProver) LoadTrustedSetup(id string, name string, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	zkp.mu.Lock()
	defer zkp.mu.Unlock()

	if _, exists := zkp.circuits[id]; exists {
		return nil
	}

	if pk == nil || vk == nil {
		return errors.New("quantum/zkp: pk and vk must be non-nil for trusted setup")
	}

	// AUDIT (2026) ZK-NN-7 FIX: Compile the circuit to obtain ccs so
	// that GenerateProof works with loaded trusted setup keys. Previously
	// ccs was nil, making proof generation impossible for trusted setups.
	circuit := &genericCircuit{}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("compile circuit %s for trusted setup: %w", id, err)
	}

	zkp.circuits[id] = &ZKCircuit{
		ID:   id,
		Name: name,
		ccs:  ccs,
		pk:   pk,
		vk:   vk,
	}
	return nil
}

// Destroy clears all circuit data including proving keys from memory.
// QUANTUFIX: Added to allow cleanup of toxic waste / proving keys
// when the prover is no longer needed.
func (zkp *ZKProver) Destroy() {
	zkp.mu.Lock()
	defer zkp.mu.Unlock()
	for id, c := range zkp.circuits {
		c.pk = nil
		c.vk = nil
		c.ccs = nil
		delete(zkp.circuits, id)
	}
}

func (zkp *ZKProver) GetCircuit(id string) (*ZKCircuit, bool) {
	zkp.mu.Lock()
	defer zkp.mu.Unlock()
	c, ok := zkp.circuits[id]
	return c, ok
}

func (zkp *ZKProver) GenerateProof(circuitID string, privateInput *big.Int, publicInput *big.Int) (*ZKProof, error) {
	zkp.mu.Lock()
	defer zkp.mu.Unlock()

	circuit, exists := zkp.circuits[circuitID]
	if !exists {
		return nil, fmt.Errorf("circuit not found: %s", circuitID)
	}

	if privateInput == nil || publicInput == nil {
		return nil, ErrInvalidWitness
	}

	// QUANTUM2-002 FIX: Verify circuit.pk and circuit.ccs are non-nil before
	// calling groth16.Prove. Calling Prove with nil ccs would panic with a
	// nil pointer dereference.
	// AUDIT (2026) ZK-NN-7: LoadTrustedSetup now compiles ccs, so this
	// nil check is defense-in-depth rather than a known failure path.
	if circuit.pk == nil {
		return nil, fmt.Errorf("circuit %s has no proving key — cannot generate proof", circuitID)
	}
	if circuit.ccs == nil {
		return nil, fmt.Errorf("circuit %s has no compiled constraint system — "+
			"ensure RegisterCircuit or LoadTrustedSetup was called", circuitID)
	}

	// L18-026 FIX: Create copies of sensitive inputs so they can be
	// securely zeroed after proof generation without affecting caller data.
	privCopy := new(big.Int).Set(privateInput)
	pubCopy := new(big.Int).Set(publicInput)
	assignment := &genericCircuit{
		PrivateInput: privCopy,
		PublicInput:  pubCopy,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}

	proof, err := groth16.Prove(circuit.ccs, circuit.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("generate proof: %w", err)
	}

	// L18-026 FIX: Zero witness vector and copied assignment fields after
	// proof generation to prevent sensitive data from lingering in memory.
	// The proof object does not retain the witness.
	vec := witness.Vector()
	if vec != nil {
		// QUANTUM-004 NOTE (intentional): The witness.Vector() returned by
		// the gnark circuit is typed as interface{}/backend.Vector. We assert
		// to the concrete bls12381fr.Vector (the in-circuit field element
		// slice) so we can iterate and zero each element. This uses the
		// comma-ok form; a type mismatch (which would indicate a backend
		// mismatch or a corrupted witness) is handled explicitly by returning
		// a descriptive error rather than panicking.
		elems, ok := vec.(bls12381fr.Vector)
		if !ok {
			return nil, fmt.Errorf("witness vector has unexpected type %T, expected fr.Vector", vec)
		}
		var zero bls12381fr.Element
		for i := range elems {
			elems[i] = zero
		}
	}
	privCopy.SetInt64(0)
	pubCopy.SetInt64(0)

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}

	publicInputBytes := publicInput.Bytes()
	pubInputCopy := make([]byte, len(publicInputBytes))
	copy(pubInputCopy, publicInputBytes)

	return &ZKProof{
		ProofBytes:   proofBuf.Bytes(),
		PublicInputs: [][]byte{pubInputCopy},
		CircuitID:    circuitID,
	}, nil
}

type ZKVerifier struct {
	mu       sync.Mutex
	circuits map[string]*ZKCircuit
}

func NewZKVerifier() *ZKVerifier {
	return &ZKVerifier{
		circuits: make(map[string]*ZKCircuit),
	}
}

func (zkv *ZKVerifier) RegisterCircuit(circuit *ZKCircuit) {
	zkv.mu.Lock()
	defer zkv.mu.Unlock()
	zkv.circuits[circuit.ID] = circuit
}

func (zkv *ZKVerifier) VerifyProof(proof *ZKProof) (bool, error) {
	// R3-P4-2: Add nil check to prevent nil pointer dereference panic.
	if proof == nil {
		return false, fmt.Errorf("proof is nil")
	}

	zkv.mu.Lock()
	defer zkv.mu.Unlock()

	circuit, exists := zkv.circuits[proof.CircuitID]
	if !exists {
		return false, fmt.Errorf("circuit not found: %s", proof.CircuitID)
	}

	gnarkProof := groth16.NewProof(ecc.BLS12_381)
	if _, err := gnarkProof.ReadFrom(bytes.NewReader(proof.ProofBytes)); err != nil {
		return false, fmt.Errorf("deserialize proof: %w", err)
	}

	// L13-008 FIX: The genericCircuit binds exactly one public input. Reject
	// proofs with a mismatched public input count to prevent silently ignoring
	// extra inputs that could mislead callers into accepting an incomplete proof.
	if len(proof.PublicInputs) != 1 {
		return false, fmt.Errorf("expected exactly 1 public input, got %d", len(proof.PublicInputs))
	}
	publicInput := new(big.Int)
	publicInput.SetBytes(proof.PublicInputs[0])
	// R38-P3 FIX: Zero publicInput after use to prevent memory residue.
	defer publicInput.SetInt64(0)

	assignment := &genericCircuit{
		PublicInput: publicInput,
	}

	publicWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("create public witness: %w", err)
	}

	err = groth16.Verify(gnarkProof, circuit.vk, publicWitness)
	if err != nil {
		return false, ErrProofVerificationFailed
	}

	return true, nil
}

type RangeProof struct {
	ProofBytes []byte
	LowerBound *big.Int
	UpperBound *big.Int
	Commitment []byte
}

type RangeProofSystem struct {
	mu                 sync.Mutex
	bitLength          int
	ccs                constraint.ConstraintSystem
	pk                 groth16.ProvingKey
	vk                 groth16.VerifyingKey
	compiled           bool
	allowInsecureSetup bool
}

func NewRangeProofSystem(bitLength int) *RangeProofSystem {
	// FIX: Validate bitLength to prevent invalid circuits or memory
	// exhaustion. Matches qzkp/bound_range.go boundary check.
	if bitLength <= 0 || bitLength > 256 {
		return nil
	}
	return &RangeProofSystem{
		bitLength: bitLength,
	}
}

// SetAllowInsecureSetup enables local trusted setup (groth16.Setup with toxic
// waste). Production requires an MPC ceremony. audit-fix Round3 C-1.
// audit-fix: Block in production environment via QAU_PRODUCTION env var.
func (rps *RangeProofSystem) SetAllowInsecureSetup(allow bool) {
	if allow && params.IsProductionEnv() {
		log.Printf("WARNING: SetAllowInsecureSetup(true) blocked in production environment")
		return
	}
	rps.mu.Lock()
	defer rps.mu.Unlock()
	rps.allowInsecureSetup = allow
}

func (rps *RangeProofSystem) compile() error {
	if rps.compiled {
		return nil
	}

	// audit-fix Round3 C-1: block insecure local trusted setup unless explicitly allowed.
	if !rps.allowInsecureSetup {
		return errors.New("quantum/zkp: insecure local trusted setup blocked; call SetAllowInsecureSetup(true) for testing only")
	}
	// FIX: Additional env var guard to prevent toxic waste generation in production.
	if os.Getenv("QZKP_DISABLE_SETUP") == "1" {
		return errors.New("quantum/zkp: local trusted setup blocked by QZKP_DISABLE_SETUP=1 env var (production mode)")
	}

	// QUANTUFIX: Log critical warning when local trusted setup is used.
	log.Printf("CRITICAL SECURITY WARNING: RangeProofSystem.compile using local groth16.Setup — toxic waste generated. " +
		"This is NOT safe for production. Use LoadTrustedRangeSetup() with MPC ceremony output instead.")

	circuit := &rangeProofCircuit{bitLen: rps.bitLength}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("compile range proof circuit: %w", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("setup range proof circuit: %w", err)
	}

	rps.ccs = ccs
	rps.pk = pk
	rps.vk = vk
	rps.compiled = true
	return nil
}

// LoadTrustedRangeSetup loads a pre-computed proving key and verifying key
// from an external MPC ceremony for the range proof circuit. This is the ONLY
// safe way to set up the range proof system in production — local
// groth16.Setup (used by compile()) generates toxic waste.
//
// AUDIT (2026) ZK-NN-7 FIX: The compile() method's warning comment
// referenced LoadTrustedRangeSetup(), but the method did not exist. This
// left no production-safe path for the range proof system. Now production
// deployments can run an MPC ceremony for rangeProofCircuit and load the
// resulting keys via this method, bypassing local groth16.Setup entirely.
//
// The caller must ensure pk/vk were produced from an MPC ceremony using
// the same rangeProofCircuit definition with the same bitLength.
func (rps *RangeProofSystem) LoadTrustedRangeSetup(pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	if pk == nil || vk == nil {
		return errors.New("quantum/zkp: LoadTrustedRangeSetup requires non-nil pk and vk")
	}

	rps.mu.Lock()
	defer rps.mu.Unlock()

	if rps.compiled {
		return nil // already compiled (local or trusted); do not overwrite
	}

	circuit := &rangeProofCircuit{bitLen: rps.bitLength}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("compile range proof circuit for trusted setup: %w", err)
	}

	rps.ccs = ccs
	rps.pk = pk
	rps.vk = vk
	rps.compiled = true
	return nil
}

func (rps *RangeProofSystem) GenerateRangeProof(value *big.Int, lowerBound, upperBound *big.Int) (*RangeProof, error) {
	rps.mu.Lock()
	defer rps.mu.Unlock()

	if value.Cmp(lowerBound) < 0 || value.Cmp(upperBound) > 0 {
		// FIX: Do not leak the actual value or bounds in the error message.
		return nil, fmt.Errorf("range proof generation failed: value out of range")
	}

	if err := rps.compile(); err != nil {
		return nil, err
	}

	commitment := computeNativeMiMC(value)

	// L18-026 FIX: Create copies of sensitive inputs so they can be
	// securely zeroed after proof generation without affecting caller data.
	valCopy := new(big.Int).Set(value)
	commitCopy := new(big.Int).Set(commitment)
	lbCopy := new(big.Int).Set(lowerBound)
	ubCopy := new(big.Int).Set(upperBound)
	assignment := &rangeProofCircuit{
		Value:      valCopy,
		Commitment: commitCopy,
		LowerBound: lbCopy,
		UpperBound: ubCopy,
		bitLen:     rps.bitLength,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create range witness: %w", err)
	}

	proof, err := groth16.Prove(rps.ccs, rps.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("generate range proof: %w", err)
	}

	// L18-026 FIX: Zero witness vector and copied assignment fields after
	// proof generation to prevent sensitive data from lingering in memory.
	vec := witness.Vector()
	if vec != nil {
		// QUANTUM-004 NOTE (intentional): Same comma-ok type assertion pattern
		// as in GenerateProof — see the note there. A type mismatch is handled
		// explicitly by returning a descriptive error (no panic).
		elems, ok := vec.(bls12381fr.Vector)
		if !ok {
			return nil, fmt.Errorf("range witness vector has unexpected type %T, expected fr.Vector", vec)
		}
		var zero bls12381fr.Element
		for i := range elems {
			elems[i] = zero
		}
	}
	// FIX: Explicitly zero assignment.Value (the actual amount) via
	// type assertion, matching the ProveBalance assignment zeroing pattern.
	if bi, ok := assignment.Value.(*big.Int); ok {
		bi.SetInt64(0)
	}
	// FIX: valCopy is the same *big.Int as assignment.Value (set at
	// line 393), so bi.SetInt64(0) above already zeros it. The line below
	// is retained as defense-in-depth in case assignment.Value type changes
	// in the future, but is currently redundant.
	valCopy.SetInt64(0)
	commitCopy.SetInt64(0)
	lbCopy.SetInt64(0)
	ubCopy.SetInt64(0)

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serialize range proof: %w", err)
	}

	commitmentBytes := commitment.Bytes()
	commitmentCopy := make([]byte, len(commitmentBytes))
	copy(commitmentCopy, commitmentBytes)
	// R32-P3-3 FIX: Zero the original commitment after extracting bytes.
	// commitment is derived from the value (sensitive witness material) and
	// must not linger in memory after proof generation.
	commitment.SetInt64(0)

	return &RangeProof{
		ProofBytes: proofBuf.Bytes(),
		LowerBound: new(big.Int).Set(lowerBound),
		UpperBound: new(big.Int).Set(upperBound),
		Commitment: commitmentCopy,
	}, nil
}

func (rps *RangeProofSystem) VerifyRangeProof(proof *RangeProof) bool {
	rps.mu.Lock()
	defer rps.mu.Unlock()

	if proof == nil {
		return false
	}

	// L15-011 FIX: Reject nil/empty commitment to prevent verification bypass.
	// An empty commitment would decode to big.Int(0), which could
	// trivially pass the circuit check in some configurations.
	if len(proof.Commitment) == 0 {
		return false
	}

	if proof.LowerBound.Cmp(proof.UpperBound) >= 0 {
		return false
	}

	if !rps.compiled {
		return false
	}

	gnarkProof := groth16.NewProof(ecc.BLS12_381)
	if _, err := gnarkProof.ReadFrom(bytes.NewReader(proof.ProofBytes)); err != nil {
		return false
	}

	commitment := new(big.Int).SetBytes(proof.Commitment)
	// R38-P3 FIX: Zero commitment after use to prevent memory residue.
	defer commitment.SetInt64(0)

	// L4-010 FIX: Include bounds from the proof as public inputs so the
	// gnark verifier checks they match what was used during proof generation.
	// R6-QP-001 FIX: Copy bounds to prevent the caller from modifying the
	// proof's LowerBound/UpperBound between assignment and verification.
	assignment := &rangeProofCircuit{
		Commitment: commitment,
		LowerBound: new(big.Int).Set(proof.LowerBound),
		UpperBound: new(big.Int).Set(proof.UpperBound),
		bitLen:     rps.bitLength,
	}
	// L8-011 CONFIRMED FIXED: bounds (LowerBound, UpperBound) are bound to the
	// proof as gnark public inputs (L4-010 FIX). The circuit's Define() method
	// asserts LowerBound <= Value <= UpperBound, so tampering with the bounds
	// in the RangeProof struct invalidates the gnark verification.

	publicWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false
	}

	err = groth16.Verify(gnarkProof, rps.vk, publicWitness)
	return err == nil
}

// computeNativeMiMC computes a MiMC hash of a field element.
//
// L11-012 NOTE: This function is duplicated in the qzkp package
// (qzkp/qzkp.go:computeNativeMiMC). The qzkp version uses a shared
// writeFieldElement helper, while this version inlines the same logic
// (Mod -> FillBytes -> Write) because the quantum package cannot import
// qzkp without creating a circular dependency. Both implementations MUST
// stay in sync: any change to one must be reflected in the other.
//
// L10-027 FIX: h.Reset() is called after h.Sum(nil) to clear the MiMC
// hasher's internal state, which still holds the absorbed data. This
// matches the qzkp package's implementation (L9-050 FIX).
func computeNativeMiMC(data *big.Int) *big.Int {
	h := mimc_native.NewMiMC()
	var buf [32]byte
	reduced := new(big.Int).Mod(data, ecc.BLS12_381.ScalarField())
	reduced.FillBytes(buf[:])
	h.Write(buf[:])
	result := h.Sum(nil)
	h.Reset()
	// Copy result before zeroing the buffer.
	out := new(big.Int).SetBytes(result)
	// L18-007 FIX: Zeroize sensitive intermediate buffers after use.
	// buf holds the reduced domain element (secret-derived material).
	// result holds the MiMC hash output (may leak information about the input).
	// reduced holds the scalar-reduced input.
	for i := range buf {
		buf[i] = 0
	}
	for i := range result {
		result[i] = 0
	}
	reduced.SetInt64(0)
	return out
}
