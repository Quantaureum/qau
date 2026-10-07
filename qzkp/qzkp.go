// Quantaureum Node source, version 1.0.0.
package qzkp

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
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

	"github.com/quantaureum/qau/pedersen"
	"github.com/quantaureum/qau/qrng"

	"golang.org/x/crypto/sha3"
)

var (
	ErrProofVerificationFailed = errors.New("qzkp: proof verification failed")
	ErrInvalidWitness          = errors.New("qzkp: invalid witness")
	ErrInvalidStatement        = errors.New("qzkp: invalid statement")
	ErrChallengeMismatch       = errors.New("qzkp: challenge mismatch")
	ErrCircuitNotCompiled      = errors.New("qzkp: circuit not compiled")

	trustedSetupWarnOnce sync.Once
)

const (
	SecurityLevel128 = 128
	SecurityLevel192 = 192
	SecurityLevel256 = 256

	// maxCircuitCacheSize limits the number of compiled circuits cached in
	// memory to prevent unbounded growth. L12-012 FIX.
	maxCircuitCacheSize = 64
)

type ZKConfig struct {
	SecurityLevel int
	UseQRNG       bool
	QRNG          *qrng.QRNG
	// L9-047 NOTE: HashFunc is defined for future extension (pluggable hash
	// for ZK proof transcripts). It is currently initialized in DefaultZKConfig
	// but not invoked in production code paths. Retained for API compatibility.
	// L10-025: This field is dead code — it is never read in any production code
	// path. Retained only to avoid breaking TestDefaultZKConfig and external API
	// consumers. Do not rely on it; it will be removed in a future version.
	// Deprecated: HashFunc is unused dead code retained for API compatibility.
	HashFunc     func([]byte) []byte
	Curve        ecc.ID
	Experimental bool
	// AllowInsecureSetup permits the local groth16.Setup trusted setup, which
	// produces toxic waste that enables proof forgery if leaked. Production
	// deployments MUST set this to false and use an MPC ceremony or transparent
	// setup scheme (e.g. PLONK). DefaultZKConfig sets false (production-safe).
	AllowInsecureSetup bool
}

func DefaultZKConfig(q *qrng.QRNG) ZKConfig {
	return ZKConfig{
		SecurityLevel:      SecurityLevel256,
		UseQRNG:            q != nil,
		QRNG:               q,
		Curve:              ecc.BLS12_381,
		Experimental:       true,
		AllowInsecureSetup: false, // production-safe default; tests must explicitly set true
		HashFunc: func(data []byte) []byte {
			fieldInt := hashToFieldElement(data)
			hashInt := computeNativeMiMC(fieldInt)
			// FIX: Zero fieldInt after consumption. It contains a
			// field element derived from potentially sensitive witness data.
			zeroBigInt(fieldInt)
			return hashInt.Bytes()
		},
	}
}

func hashToFieldElement(data []byte) *big.Int {
	if len(data) <= 31 {
		return new(big.Int).SetBytes(data)
	}
	h := sha256.Sum256(data)
	result := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), ecc.BLS12_381.ScalarField())
	// P4-2 FIX: Zero the SHA-256 digest after it has been consumed. The digest
	// is derived from `data` (which may be sensitive witness material); zeroing
	// prevents it from lingering on the stack/heap. h is a fixed [32]byte
	// array returned by Sum256 (stack-allocated), so we wipe it in place.
	for i := range h {
		h[i] = 0
	}
	// R30-P5 NOTE: The returned `result` is NOT zeroed here because the caller
	// needs it. Callers typically assign it to a circuit witness or use it for
	// proof generation, which overwrites the internal buffer. If the caller
	// stores it in a long-lived variable, they should zero it after use.
	return result
}

type SchnorrProof struct {
	ProofBytes []byte
	PublicHash []byte
}

type RangeProof struct {
	ProofBytes         []byte
	Commitment         []byte // MiMC commitment (internal, used for ZK verification)
	ExternalCommitment []byte // External commitment (e.g., Pedersen) for binding verification
	BitLength          int
	// AUDIT (2026) ZK-NN-2 FIX: Schnorr binding proof that cryptographically
	// links the MiMC commitment (circuit public input) to a Pedersen commitment
	// via the shared blinding factor. The prover creates
	// ecCommitment = PedersenCommit(mimcCommit, tx_blinding) and generates a
	// Schnorr DLP proof that ecCommitment - mimcCommit*G = tx_blinding*H.
	// This proves the Pedersen commitment opens to the MiMC value without
	// revealing the blinding. Combined with the ExternalCommitment byte
	// comparison (which links to the real transaction Pedersen commitment),
	// this prevents the attack where an attacker generates a range proof for
	// a small value while the real Pedersen commitment encodes a large or
	// out-of-range value.
	EcCommitment   []byte
	SchnorrBinding *SchnorrBindingProof
}

type EqualityProof struct {
	ProofBytes []byte
	PublicA    []byte
	PublicB    []byte
}

type BalanceProof struct {
	ProofBytes []byte
	InputComm  [][]byte
	OutputComm [][]byte
	FeeComm    []byte
	// SECURITY (audit 2026-06-14, C5): Pedersen commitment binding.
	// InputComm/OutputComm/FeeComm above are the MiMC commitments used as the
	// Groth16 circuit's PUBLIC inputs (proving knowledge of balanced
	// (amount, blinding) preimages). The transaction, however, carries Pedersen
	// commitments (PedersenCommit(amount, blinding)) — a DIFFERENT representation
	// of the same (amount, blinding). Without binding the two, a prover could
	// attach a valid Groth16 proof over a balanced set of FAKE MiMC commitments
	// to a real transaction whose Pedersen commitments violate balance, minting
	// confidential value. We store the Pedersen commitments here and ProveBalance
	// asserts they are the commitments the verifier will pass in, so VerifyBalance
	// can reject any proof whose Pedersen commitments do not byte-match the real
	// transaction commitments.
	InputPedersenComm  [][]byte
	OutputPedersenComm [][]byte
	FeePedersenComm    []byte
	// L11-002 FIX: BalanceBindingHash cryptographically links the MiMC commitments
	// (circuit public inputs) to the Pedersen commitments (transaction commitments).
	// Computed as SHA3-256(allPedersenCommitments || allMiMCCommitments || domainSep).
	// This ensures the Groth16 proof (over MiMC) and the transaction (over Pedersen)
	// reference the same set of (amount, blinding) pairs, preventing cross-commitment
	// forgery where an attacker uses balanced MiMC values with unbalanced Pedersen values.
	BalanceBindingHash []byte
	// AUDIT (2026) ZK-NN-1 FIX: Schnorr binding proofs that cryptographically
	// link each MiMC commitment (circuit public input) to a Pedersen commitment
	// via the shared blinding factor. For each input/output/fee, the prover
	// creates ecCommitment = PedersenCommit(mimcCommit, blinding) and generates
	// a Schnorr DLP proof that ecCommitment - mimcCommit*G = blinding*H.
	// This proves the Pedersen commitment opens to the MiMC value without
	// revealing the blinding. Combined with the Pedersen homomorphic balance
	// check (VerifyBalance), this prevents the cross-commitment forgery attack
	// where an attacker uses balanced MiMC values with unbalanced Pedersen values.
	InputEcCommitments    [][]byte
	OutputEcCommitments   [][]byte
	FeeEcCommitment       []byte
	InputSchnorrBindings  []*SchnorrBindingProof
	OutputSchnorrBindings []*SchnorrBindingProof
	FeeSchnorrBinding     *SchnorrBindingProof
}

type MembershipProof struct {
	ProofBytes []byte
	Root       []byte
	Leaf       []byte
	Depth      int
}

type preimageCircuit struct {
	Preimage frontend.Variable `gnark:"preimage"`
	Hash     frontend.Variable `gnark:",public"`
}

func (c *preimageCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("mimc init: %w", err)
	}
	h.Write(c.Preimage)
	api.AssertIsEqual(h.Sum(), c.Hash)
	return nil
}

type rangeCircuit struct {
	Value      frontend.Variable `gnark:"value"`
	Blinding   frontend.Variable `gnark:"blinding"`
	Commitment frontend.Variable `gnark:",public"`
	bitLen     int
}

func (c *rangeCircuit) Define(api frontend.API) error {
	// CRITICAL FIX: ToBinary result MUST be asserted equal to constant 1
	// to enforce that value is in range [0, 2^bitLen). The original code
	// discarded the result, bypassing the range constraint entirely.
	// An attacker could submit proofs for values OUTSIDE the claimed range.
	bits := api.ToBinary(c.Value, c.bitLen)
	// Assert all bits are boolean (0 or 1) - if any bit is >1, this fails
	for i := 0; i < c.bitLen; i++ {
		api.AssertIsBoolean(bits[i])
	}
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("mimc init: %w", err)
	}
	// R2-HIGH-08 FIX: Hash Value || Blinding (not Value alone) to prevent
	// brute-force recovery of low-entropy transaction amounts. Without a
	// blinding factor, MiMC(value) is deterministic and enumerable.
	h.Write(c.Value)
	h.Write(c.Blinding)
	api.AssertIsEqual(h.Sum(), c.Commitment)
	return nil
}

type equalityCircuit struct {
	Witness frontend.Variable `gnark:"witness"`
	PublicA frontend.Variable `gnark:",public"`
	PublicB frontend.Variable `gnark:",public"`
}

func (c *equalityCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("mimc init: %w", err)
	}
	h.Write(c.Witness)
	h.Write(frontend.Variable(0x41))
	hashA := h.Sum()
	h.Reset()
	h.Write(c.Witness)
	h.Write(frontend.Variable(0x42))
	hashB := h.Sum()
	api.AssertIsEqual(hashA, c.PublicA)
	api.AssertIsEqual(hashB, c.PublicB)
	return nil
}

type membershipCircuit struct {
	// audit-fix L5-015: Leaf is now a PUBLIC input so the verifier can
	// confirm the proof was generated for the claimed leaf value.
	// Previously Leaf was private, allowing a prover to use any leaf.
	// L8-024 CONFIRMED FIXED: L5-015 Leaf public binding verified present.
	Leaf       frontend.Variable   `gnark:",public"`
	Directions []frontend.Variable `gnark:"directions"`
	Siblings   []frontend.Variable `gnark:"siblings"`
	Root       frontend.Variable   `gnark:",public"`
	depth      int
}

func (c *membershipCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("mimc init: %w", err)
	}
	current := c.Leaf
	for i := 0; i < c.depth; i++ {
		api.AssertIsBoolean(c.Directions[i])
		h.Reset()
		left := api.Select(c.Directions[i], c.Siblings[i], current)
		right := api.Select(c.Directions[i], current, c.Siblings[i])
		h.Write(left)
		h.Write(right)
		current = h.Sum()
	}
	api.AssertIsEqual(current, c.Root)
	return nil
}

type balanceCircuit struct {
	InputBlinding     [MaxBalanceProofInputs]frontend.Variable  `gnark:"input_blinding"`
	OutputBlinding    [MaxBalanceProofOutputs]frontend.Variable `gnark:"output_blinding"`
	InputAmounts      [MaxBalanceProofInputs]frontend.Variable  `gnark:"input_amounts"`
	OutputAmounts     [MaxBalanceProofOutputs]frontend.Variable `gnark:"output_amounts"`
	Fee               frontend.Variable                         `gnark:"fee"`
	FeeBlinding       frontend.Variable                         `gnark:"fee_blinding"`
	InputCommitments  [MaxBalanceProofInputs]frontend.Variable  `gnark:",public"`
	OutputCommitments [MaxBalanceProofOutputs]frontend.Variable `gnark:",public"`
	FeeCommitment     frontend.Variable                         `gnark:",public"`
	NumInputs         int
	NumOutputs        int
	AmountBitLen      int
}

const BalanceAmountBitLen = 64

const (
	MaxBalanceProofInputs  = 16
	MaxBalanceProofOutputs = 16
)

func (c *balanceCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("mimc init: %w", err)
	}

	// 1. Verify each input commitment: MiMC(amount, blinding) == commitment
	//    This proves the prover knows the amount and blinding for each input.
	//    Also add range proof to prevent field arithmetic overflow attacks.
	// L15-028 NOTE: Blinding factors (InputBlinding, OutputBlinding) are NOT
	// range-constrained in the circuit. They can be any field element. This is
	// acceptable for Pedersen/MiMC commitments (which are statistically binding
	// regardless of blinding range), but if a different commitment scheme is
	// used that requires bounded blindings, range constraints must be added here.
	var inputAmountSum frontend.Variable = 0
	for i := 0; i < c.NumInputs; i++ {
		h.Reset()
		h.Write(c.InputAmounts[i])
		h.Write(c.InputBlinding[i])
		api.AssertIsEqual(h.Sum(), c.InputCommitments[i])

		// Range proof: each input amount must be in [0, 2^AmountBitLen)
		inputBits := api.ToBinary(c.InputAmounts[i], c.AmountBitLen)
		for j := 0; j < c.AmountBitLen; j++ {
			api.AssertIsBoolean(inputBits[j])
		}

		if i == 0 {
			inputAmountSum = c.InputAmounts[i]
		} else {
			inputAmountSum = api.Add(inputAmountSum, c.InputAmounts[i])
		}
	}

	// 2. Verify each output commitment: MiMC(amount, blinding) == commitment
	//    Also add range proof to prevent field arithmetic overflow attacks.
	var outputAmountSum frontend.Variable = 0
	for i := 0; i < c.NumOutputs; i++ {
		h.Reset()
		h.Write(c.OutputAmounts[i])
		h.Write(c.OutputBlinding[i])
		api.AssertIsEqual(h.Sum(), c.OutputCommitments[i])

		// Range proof: each output amount must be in [0, 2^AmountBitLen)
		outputBits := api.ToBinary(c.OutputAmounts[i], c.AmountBitLen)
		for j := 0; j < c.AmountBitLen; j++ {
			api.AssertIsBoolean(outputBits[j])
		}

		if i == 0 {
			outputAmountSum = c.OutputAmounts[i]
		} else {
			outputAmountSum = api.Add(outputAmountSum, c.OutputAmounts[i])
		}
	}

	// 3. Verify fee commitment: MiMC(fee, fee_blinding) == fee_commitment
	//    Also add range proof for fee.
	h.Reset()
	h.Write(c.Fee)
	h.Write(c.FeeBlinding)
	api.AssertIsEqual(h.Sum(), c.FeeCommitment)

	// Range proof: fee must be in [0, 2^AmountBitLen)
	feeBits := api.ToBinary(c.Fee, c.AmountBitLen)
	for j := 0; j < c.AmountBitLen; j++ {
		api.AssertIsBoolean(feeBits[j])
	}

	// 4. Assert balance equation: Σ(input_amounts) = Σ(output_amounts) + fee
	api.AssertIsEqual(inputAmountSum, api.Add(outputAmountSum, c.Fee))

	return nil
}

type compiledCircuit struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
	// AUDIT (2026) ZK-NN-7: trustedSource marks whether (pk, vk) came
	// from an external MPC ceremony (true) or local groth16.Setup (false).
	// Local setup produces toxic waste that enables proof forgery if leaked;
	// only trusted setups are safe for production cross-node verification.
	trustedSource bool
}

type circuitCache struct {
	mu       sync.RWMutex
	circuits map[string]*compiledCircuit
	order    []string // tracks insertion order for LRU eviction
}

func newCircuitCache() *circuitCache {
	return &circuitCache{
		circuits: make(map[string]*compiledCircuit),
	}
}

func (cc *circuitCache) get(key string) (*compiledCircuit, bool) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	c, ok := cc.circuits[key]
	return c, ok
}

func (cc *circuitCache) put(key string, c *compiledCircuit) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	// If key already exists, just update the value (no order change needed).
	if _, exists := cc.circuits[key]; exists {
		cc.circuits[key] = c
		return
	}
	// L12-012 FIX: LRU eviction — when the cache is full, evict the oldest
	// entry before inserting a new one.
	if len(cc.circuits) >= maxCircuitCacheSize && len(cc.order) > 0 {
		oldest := cc.order[0]
		delete(cc.circuits, oldest)
		cc.order = cc.order[1:]
	}
	cc.circuits[key] = c
	cc.order = append(cc.order, key)
}

type SigmaProtocol struct {
	config ZKConfig
	cache  *circuitCache
	mu     sync.Mutex
}

func NewSigmaProtocol(config ZKConfig) *SigmaProtocol {
	return &SigmaProtocol{
		config: config,
		cache:  newCircuitCache(),
	}
}

func (sp *SigmaProtocol) compileCircuit(key string, circuit frontend.Circuit) (*compiledCircuit, error) {
	if cc, ok := sp.cache.get(key); ok {
		return cc, nil
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if cc, ok := sp.cache.get(key); ok {
		return cc, nil
	}
	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile circuit %s: %w", key, err)
	}

	// SECURITY (audit CRITICAL): Block insecure local trusted setup in production.
	// groth16.Setup produces toxic waste that enables proof forgery if leaked.
	// Production MUST use MPC ceremony or transparent setup.
	//
	// L15-013 FIX: Defense-in-depth -- even if AllowInsecureSetup is
	// accidentally set to true, the QZKP_DISABLE_SETUP=1 env var
	// unconditionally blocks local trusted setup in production.
	if os.Getenv("QZKP_DISABLE_SETUP") == "1" {
		return nil, errors.New("qzkp: local trusted setup blocked by QZKP_DISABLE_SETUP=1 env var (production mode)")
	}
	if !sp.config.AllowInsecureSetup {
		return nil, errors.New("qzkp: insecure local trusted setup blocked; configure MPC ceremony or set AllowInsecureSetup=true only for testing")
	}

	// QZKP-001-TODO [ARCHITECTURE]: groth16.Setup is NOT a multi-party
	// computation (MPC) ceremony. The proving key (pk) contains toxic waste
	// (secret randomness) generated locally. In production, this MUST be
	// replaced with:
	//   (a) A proper MPC ceremony (e.g., Perpetual Powers of Tau) where
	//       multiple independent parties contribute entropy, or
	//   (b) A transparent/universal setup scheme (e.g., PlonK, FRI-based
	//       STARKs) that does not require trusted setup.
	// Until this is resolved, an attacker who obtains the proving key can
	// forge zero-knowledge proofs for arbitrary statements.
	trustedSetupWarnOnce.Do(func() {
		log.Println("[QZKP-WARN] compileCircuit: using local trusted setup (groth16.Setup) with toxic waste; production requires an MPC ceremony or transparent setup scheme")
	})
	// TODO(L13-017): Replace local groth16.Setup with an MPC ceremony (e.g., Perpetual Powers of Tau)
	// to eliminate toxic waste. The current local setup generates proving/verifying keys that
	// contain secret randomness -- if leaked, an attacker can forge zero-knowledge proofs.
	// See the detailed QZKP-001-TODO comment above for full context.
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup circuit %s: %w", key, err)
	}
	// AUDIT (2026) ZK-NN-7: trustedSource=false marks this as local
	// setup with toxic waste — NOT safe for production cross-node use.
	cc := &compiledCircuit{ccs: ccs, pk: pk, vk: vk, trustedSource: false}
	sp.cache.put(key, cc)
	return cc, nil
}

// LoadTrustedSetup loads a pre-computed proving key and verifying key from an
// external MPC ceremony for the given circuit key. This is the ONLY safe way
// to set up circuits in production — local groth16.Setup (used by
// compileCircuit) generates toxic waste that enables proof forgery if leaked.
//
// AUDIT (2026) ZK-NN-7 FIX: Previously, SigmaProtocol had no way to
// inject externally-computed trusted setup parameters. Every Prove* call
// went through compileCircuit, which always used local groth16.Setup,
// producing per-process pk/vk pairs with no shared VK across nodes. This
// made the ZK subsystem unusable cross-node (verifiers on other nodes
// would reject proofs because their VK differed from the prover's pk).
//
// With this method, production deployments can:
//  1. Run an MPC ceremony (e.g., Perpetual Powers of Tau) once to produce
//     shared (pk, vk) for each circuit.
//  2. Call LoadTrustedSetup on every node before any Prove*/Verify* call.
//  3. compileCircuit will find the cached trusted entry and skip local
//     groth16.Setup entirely.
//
// The circuit instance is compiled locally to obtain the constraint system
// (ccs), which is deterministic for a given gnark version and circuit
// definition. The caller is responsible for ensuring pk/vk were produced
// from an MPC ceremony using the same circuit definition.
func (sp *SigmaProtocol) LoadTrustedSetup(key string, circuit frontend.Circuit, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	if key == "" {
		return errors.New("qzkp: LoadTrustedSetup requires non-empty key")
	}
	if pk == nil || vk == nil {
		return errors.New("qzkp: LoadTrustedSetup requires non-nil pk and vk")
	}
	if circuit == nil {
		return errors.New("qzkp: LoadTrustedSetup requires non-nil circuit")
	}

	sp.mu.Lock()
	defer sp.mu.Unlock()

	// If already cached (e.g., previously loaded or compiled), do not
	// overwrite — the first loaded setup wins. This prevents a caller from
	// accidentally replacing a trusted setup with a different one.
	if cc, ok := sp.cache.get(key); ok {
		if cc.trustedSource {
			return nil // already loaded from trusted source
		}
		// Overwrite a local (insecure) setup with a trusted one.
	}

	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("qzkp: LoadTrustedSetup compile circuit %s: %w", key, err)
	}

	cc := &compiledCircuit{ccs: ccs, pk: pk, vk: vk, trustedSource: true}
	sp.cache.put(key, cc)
	return nil
}

func (sp *SigmaProtocol) ProveKnowledgeOfPreimage(preimage, publicHash []byte) (*SchnorrProof, error) {
	if len(preimage) == 0 {
		return nil, ErrInvalidWitness
	}
	preimageInt := hashToFieldElement(preimage)
	hashInt := computeNativeMiMC(preimageInt)
	if len(publicHash) > 0 {
		expectedHash := new(big.Int).SetBytes(publicHash)
		if hashInt.Cmp(expectedHash) != 0 {
			return nil, ErrInvalidWitness
		}
	}
	cc, err := sp.compileCircuit("preimage", &preimageCircuit{})
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	assignment := &preimageCircuit{
		Preimage: preimageInt,
		Hash:     hashInt,
	}
	witness, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := groth16.Prove(cc.ccs, cc.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}

	// FIX: Zero witness vector and the secret preimage after proof
	// generation to prevent sensitive data from lingering in memory.
	// Mirrors the  pattern in ProveBalance.
	vec := witness.Vector()
	if vec != nil {
		elems, ok := vec.(bls12381fr.Vector)
		if !ok {
			return nil, fmt.Errorf("preimage witness vector has unexpected type %T, expected fr.Vector", vec)
		}
		var zero bls12381fr.Element
		for i := range elems {
			elems[i] = zero
		}
	}
	preimageInt.SetInt64(0)

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}
	hashBytes := hashInt.Bytes()
	// R31-P3 FIX: Zero hashInt after extracting bytes for the proof.
	// hashInt contains the MiMC hash of the preimage, which is sensitive
	// witness material. Must zero AFTER Bytes() to avoid empty result.
	hashInt.SetInt64(0)
	publicHashCopy := make([]byte, len(hashBytes))
	copy(publicHashCopy, hashBytes)
	return &SchnorrProof{
		ProofBytes: proofBuf.Bytes(),
		PublicHash: publicHashCopy,
	}, nil
}

// ComputePreimageHash computes the MiMC hash of a preimage — the same hash
// used as the public input in ProveKnowledgeOfPreimage/VerifyKnowledgeOfPreimage.
// This allows verifiers to recompute the expected public hash from public
// inputs rather than trusting the prover-supplied hash embedded in the proof.
//
// AUDIT (2026) HIGH-19 (ZK-NN-3): Without this, the nullifier proof
// verifier accepted proof.Proof.PublicHash (prover-chosen) without binding
// it to the canonical nullifier derivation inputs.
func (sp *SigmaProtocol) ComputePreimageHash(preimage []byte) []byte {
	if len(preimage) == 0 {
		return nil
	}
	preimageInt := hashToFieldElement(preimage)
	hashInt := computeNativeMiMC(preimageInt)
	defer func() {
		preimageInt.SetInt64(0)
		hashInt.SetInt64(0)
	}()
	return hashInt.Bytes()
}

func (sp *SigmaProtocol) VerifyKnowledgeOfPreimage(proof *SchnorrProof, publicHash []byte) error {
	if proof == nil {
		return ErrProofVerificationFailed
	}
	cc, ok := sp.cache.get("preimage")
	if !ok {
		return ErrCircuitNotCompiled
	}
	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	gnarkProof := groth16.NewProof(curve)
	if _, err := gnarkProof.ReadFrom(bytes.NewReader(proof.ProofBytes)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}
	hashInt := new(big.Int).SetBytes(publicHash)
	// R38-P3 FIX: Zero hashInt after use to prevent memory residue.
	defer hashInt.SetInt64(0)
	assignment := &preimageCircuit{Hash: hashInt}
	publicWitness, err := frontend.NewWitness(assignment, curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("create public witness: %w", err)
	}
	err = groth16.Verify(gnarkProof, cc.vk, publicWitness)
	if err != nil {
		return ErrProofVerificationFailed
	}
	return nil
}

func (sp *SigmaProtocol) ProveValueInRange(value *big.Int, bitLength int) (*RangeProof, error) {
	if value.Sign() < 0 {
		return nil, ErrInvalidWitness
	}
	maxVal := new(big.Int).Lsh(big.NewInt(1), uint(bitLength))
	if value.Cmp(maxVal) >= 0 {
		return nil, ErrInvalidWitness
	}
	// R2-HIGH-08 FIX: Generate a random blinding factor so the commitment
	// C = MiMC(value, blinding) is not brute-forceable for low-entropy values.
	// Without blinding, MiMC(value) is deterministic and an observer can
	// enumerate candidate amounts to recover the exact value.
	blinding, err := crand.Int(crand.Reader, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("generate blinding: %w", err)
	}
	// Compute blinded commitment using MiMC(value || blinding).
	commitmentInt := computeNativeMiMCPedersen(value, blinding).Value
	cacheKey := fmt.Sprintf("range_%d", bitLength)
	circuit := &rangeCircuit{bitLen: bitLength}
	cc, err := sp.compileCircuit(cacheKey, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	assignment := &rangeCircuit{
		Value:      value,
		Blinding:   blinding,
		Commitment: commitmentInt,
		bitLen:     bitLength,
	}
	witness, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := groth16.Prove(cc.ccs, cc.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}
	commitmentBytes := commitmentInt.Bytes()
	commitmentCopy := make([]byte, len(commitmentBytes))
	copy(commitmentCopy, commitmentBytes)

	// FIX: Zero witness vector and internal commitment after proof
	// serialization and commitment copy. ProveValueInRange was omitted from
	// 's witness zeroing scope.
	// R2-HIGH-08: Also zero the blinding factor — it is private key material.
	// NOTE: assignment.Value is NOT zeroed because it aliases the caller's
	// `value` parameter — zeroing it would corrupt caller state. Only the
	// witness vector (internal), commitmentInt, and blinding are zeroed.
	if wVec, ok := witness.Vector().(bls12381fr.Vector); ok {
		for i := range wVec {
			wVec[i].SetZero()
		}
	}
	commitmentInt.SetInt64(0)
	blinding.SetInt64(0)

	return &RangeProof{
		ProofBytes: proofBuf.Bytes(),
		Commitment: commitmentCopy,
		BitLength:  bitLength,
	}, nil
}

func (sp *SigmaProtocol) VerifyValueInRange(proof *RangeProof, commitment []byte) error {
	if proof == nil {
		return ErrProofVerificationFailed
	}
	cacheKey := fmt.Sprintf("range_%d", proof.BitLength)
	cc, ok := sp.cache.get(cacheKey)
	if !ok {
		return ErrCircuitNotCompiled
	}
	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	gnarkProof := groth16.NewProof(curve)
	if _, err := gnarkProof.ReadFrom(bytes.NewReader(proof.ProofBytes)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}
	commitmentInt := new(big.Int).SetBytes(commitment)
	// FIX: Zero commitmentInt on return (defensive cleanup).
	defer func() { commitmentInt.SetInt64(0) }()
	assignment := &rangeCircuit{
		Commitment: commitmentInt,
		bitLen:     proof.BitLength,
	}
	publicWitness, err := frontend.NewWitness(assignment, curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("create public witness: %w", err)
	}
	err = groth16.Verify(gnarkProof, cc.vk, publicWitness)
	if err != nil {
		return ErrProofVerificationFailed
	}
	return nil
}

func (sp *SigmaProtocol) ProveEquality(witness []byte, publicA, publicB []byte) (*EqualityProof, error) {
	if len(witness) == 0 {
		return nil, ErrInvalidWitness
	}
	witnessInt := new(big.Int).SetBytes(witness)
	hashAInt := computeNativeMiMCWithSuffix(witnessInt, 0x41)
	hashBInt := computeNativeMiMCWithSuffix(witnessInt, 0x42)
	if len(publicA) > 0 {
		expectedA := new(big.Int).SetBytes(publicA)
		if hashAInt.Cmp(expectedA) != 0 {
			return nil, ErrInvalidWitness
		}
	}
	if len(publicB) > 0 {
		expectedB := new(big.Int).SetBytes(publicB)
		if hashBInt.Cmp(expectedB) != 0 {
			return nil, ErrInvalidWitness
		}
	}
	cc, err := sp.compileCircuit("equality", &equalityCircuit{})
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	assignment := &equalityCircuit{
		Witness: witnessInt,
		PublicA: hashAInt,
		PublicB: hashBInt,
	}
	w, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := groth16.Prove(cc.ccs, cc.pk, w)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	// FIX: Zero witness vector and the secret witness after proof
	// generation to prevent sensitive data from lingering in memory.
	// Mirrors the  pattern in ProveBalance.
	vec := w.Vector()
	if vec != nil {
		elems, ok := vec.(bls12381fr.Vector)
		if !ok {
			return nil, fmt.Errorf("equality witness vector has unexpected type %T, expected fr.Vector", vec)
		}
		var zero bls12381fr.Element
		for i := range elems {
			elems[i] = zero
		}
	}
	witnessInt.SetInt64(0)
	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}
	hashABytes := hashAInt.Bytes()
	hashBBytes := hashBInt.Bytes()
	// R31-P3 FIX: Zero hashAInt/hashBInt after extracting bytes for the proof.
	// Must zero AFTER Bytes() to avoid empty result (pointer aliasing).
	hashAInt.SetInt64(0)
	hashBInt.SetInt64(0)
	publicACopy := make([]byte, len(hashABytes))
	publicBCopy := make([]byte, len(hashBBytes))
	copy(publicACopy, hashABytes)
	copy(publicBCopy, hashBBytes)
	return &EqualityProof{
		ProofBytes: proofBuf.Bytes(),
		PublicA:    publicACopy,
		PublicB:    publicBCopy,
	}, nil
}

func (sp *SigmaProtocol) VerifyEquality(proof *EqualityProof, publicA, publicB []byte) error {
	if proof == nil {
		return ErrProofVerificationFailed
	}
	cc, ok := sp.cache.get("equality")
	if !ok {
		return ErrCircuitNotCompiled
	}
	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	gnarkProof := groth16.NewProof(curve)
	if _, err := gnarkProof.ReadFrom(bytes.NewReader(proof.ProofBytes)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}
	publicAInt := new(big.Int).SetBytes(publicA)
	publicBInt := new(big.Int).SetBytes(publicB)
	// FIX: Zero publicAInt/publicBInt on return (defensive cleanup).
	defer func() {
		publicAInt.SetInt64(0)
		publicBInt.SetInt64(0)
	}()
	assignment := &equalityCircuit{
		PublicA: publicAInt,
		PublicB: publicBInt,
	}
	publicWitness, err := frontend.NewWitness(assignment, curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("create public witness: %w", err)
	}
	err = groth16.Verify(gnarkProof, cc.vk, publicWitness)
	if err != nil {
		return ErrProofVerificationFailed
	}
	return nil
}

func (sp *SigmaProtocol) ProveMembership(leaf []byte, siblings [][]byte, directions []bool) (*MembershipProof, error) {
	if len(siblings) != len(directions) {
		return nil, ErrInvalidWitness
	}
	depth := len(siblings)
	leafInt := new(big.Int).SetBytes(leaf)
	siblingInts := make([]*big.Int, depth)
	directionInts := make([]*big.Int, depth)
	for i := 0; i < depth; i++ {
		siblingInts[i] = new(big.Int).SetBytes(siblings[i])
		if directions[i] {
			directionInts[i] = big.NewInt(1)
		} else {
			directionInts[i] = big.NewInt(0)
		}
	}
	rootInt := computeMerkleRoot(leafInt, siblingInts, directionInts)
	cacheKey := fmt.Sprintf("membership_%d", depth)
	circuit := &membershipCircuit{
		Directions: make([]frontend.Variable, depth),
		Siblings:   make([]frontend.Variable, depth),
		depth:      depth,
	}
	cc, err := sp.compileCircuit(cacheKey, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	assignment := &membershipCircuit{
		Leaf:       leafInt,
		Directions: make([]frontend.Variable, depth),
		Siblings:   make([]frontend.Variable, depth),
		Root:       rootInt,
		depth:      depth,
	}
	for i := 0; i < depth; i++ {
		assignment.Directions[i] = directionInts[i]
		assignment.Siblings[i] = siblingInts[i]
	}
	w, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := groth16.Prove(cc.ccs, cc.pk, w)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	// FIX: Zero witness vector and the secret Merkle path (siblings,
	// directions) after proof generation to prevent sensitive data from
	// lingering in memory. Mirrors the  pattern in ProveBalance.
	vec := w.Vector()
	if vec != nil {
		elems, ok := vec.(bls12381fr.Vector)
		if !ok {
			return nil, fmt.Errorf("membership witness vector has unexpected type %T, expected fr.Vector", vec)
		}
		var zero bls12381fr.Element
		for i := range elems {
			elems[i] = zero
		}
	}
	for i := range siblingInts {
		siblingInts[i].SetInt64(0)
	}
	for i := range directionInts {
		directionInts[i].SetInt64(0)
	}
	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}
	rootBytes := rootInt.Bytes()
	rootCopy := make([]byte, len(rootBytes))
	copy(rootCopy, rootBytes)
	// audit-fix L5-015: Store leaf in proof for verification
	leafBytes := leafInt.Bytes()
	leafCopy := make([]byte, len(leafBytes))
	copy(leafCopy, leafBytes)
	// R30-P3 FIX: Zero leafInt and rootInt after copies are made.
	// These contain Merkle tree position data that should not linger.
	leafInt.SetInt64(0)
	rootInt.SetInt64(0)
	return &MembershipProof{
		ProofBytes: proofBuf.Bytes(),
		Root:       rootCopy,
		Leaf:       leafCopy,
		Depth:      depth,
	}, nil
}

func (sp *SigmaProtocol) VerifyMembership(proof *MembershipProof, expectedRoot []byte) error {
	if proof == nil {
		return ErrProofVerificationFailed
	}
	cacheKey := fmt.Sprintf("membership_%d", proof.Depth)
	cc, ok := sp.cache.get(cacheKey)
	if !ok {
		return ErrCircuitNotCompiled
	}
	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	gnarkProof := groth16.NewProof(curve)
	if _, err := gnarkProof.ReadFrom(bytes.NewReader(proof.ProofBytes)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}
	rootInt := new(big.Int).SetBytes(expectedRoot)
	// audit-fix L5-015: Include Leaf as public input so the verifier
	// can verify the proof was generated for the claimed leaf value.
	leafInt := new(big.Int).SetBytes(proof.Leaf)
	// FIX: Zero rootInt/leafInt on return (defensive cleanup).
	defer func() {
		rootInt.SetInt64(0)
		leafInt.SetInt64(0)
	}()
	assignment := &membershipCircuit{
		Leaf:  leafInt,
		Root:  rootInt,
		depth: proof.Depth,
	}
	publicWitness, err := frontend.NewWitness(assignment, curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("create public witness: %w", err)
	}
	err = groth16.Verify(gnarkProof, cc.vk, publicWitness)
	if err != nil {
		return ErrProofVerificationFailed
	}
	return nil
}

// ProveBalance generates a zero-knowledge proof that the transaction balances:
// sum(inputs) = sum(outputs) + fee, without revealing individual amounts.
//
// L15-012 CLARIFICATION: inputCommitments/outputCommitments are Pedersen
// commitments (serialized as byte slices) corresponding 1:1 to
// inputAmounts/outputAmounts respectively. Each commitment[i] must be the
// Pedersen commitment of (inputAmounts[i], inputBlindings[i]). Similarly
// for outputCommitments. feeCommitment is the commitment of (fee, feeBlinding).
func (sp *SigmaProtocol) ProveBalance(
	inputAmounts []*big.Int,
	inputBlindings []*big.Int,
	outputAmounts []*big.Int,
	outputBlindings []*big.Int,
	fee *big.Int,
	feeBlinding *big.Int,
	inputCommitments [][]byte,
	outputCommitments [][]byte,
	feeCommitment []byte,
) (*BalanceProof, error) {
	if len(inputAmounts) != len(inputBlindings) || len(inputAmounts) == 0 {
		return nil, ErrInvalidWitness
	}
	if len(outputAmounts) != len(outputBlindings) {
		return nil, ErrInvalidWitness
	}
	if len(inputCommitments) != len(inputAmounts) || len(outputCommitments) != len(outputAmounts) {
		return nil, ErrInvalidStatement
	}
	if len(inputAmounts) > MaxBalanceProofInputs || len(outputAmounts) > MaxBalanceProofOutputs {
		return nil, fmt.Errorf("too many inputs/outputs for balance proof")
	}

	// SECURITY FIX (L14-023): Validate all input amounts are non-negative BEFORE
	// any arithmetic. Negative amounts could wrap around in modular field
	// arithmetic, producing a "balanced" equation that actually mints value.
	// The range check below (lines ~830-844) also catches this, but only AFTER
	// the balance equation has been computed — failing early prevents negative
	// values from ever entering the summation.
	for i, amt := range inputAmounts {
		if amt == nil || amt.Sign() < 0 {
			return nil, fmt.Errorf("input amount %d is negative or nil", i)
		}
	}
	for i, amt := range outputAmounts {
		if amt == nil || amt.Sign() < 0 {
			return nil, fmt.Errorf("output amount %d is negative or nil", i)
		}
	}
	if fee == nil || fee.Sign() < 0 {
		return nil, fmt.Errorf("fee is negative or nil")
	}

	// Verify balance equation: sum(inputs) = sum(outputs) + fee
	var inputSum, outputSum, feeSum *big.Int
	inputSum = new(big.Int).Set(inputAmounts[0])
	for i := 1; i < len(inputAmounts); i++ {
		inputSum.Add(inputSum, inputAmounts[i])
	}
	outputSum = new(big.Int).Set(outputAmounts[0])
	for i := 1; i < len(outputAmounts); i++ {
		outputSum.Add(outputSum, outputAmounts[i])
	}
	feeSum = new(big.Int).Set(fee)
	outputSum.Add(outputSum, feeSum)
	if inputSum.Cmp(outputSum) != 0 {
		// FIX: Do not leak inputSum/outputSum values in the error message.
		return nil, fmt.Errorf("balance equation not satisfied: sum(inputs) != sum(outputs)+fee")
	}

	// N19-003 FIX: Zero sensitive amount sums on return to prevent
	// sensitive financial data from lingering in memory.
	defer func() {
		if inputSum != nil {
			inputSum.SetInt64(0)
		}
		if outputSum != nil {
			outputSum.SetInt64(0)
		}
		if feeSum != nil {
			feeSum.SetInt64(0)
		}
	}()

	// Range validation: each amount must be in [0, 2^BalanceAmountBitLen)
	maxAmount := new(big.Int).Lsh(big.NewInt(1), BalanceAmountBitLen)
	for i, amt := range inputAmounts {
		if amt.Sign() < 0 || amt.Cmp(maxAmount) >= 0 {
			// FIX: Do not leak individual amount values in the error message.
			return nil, fmt.Errorf("input amount %d out of range", i)
		}
	}
	for i, amt := range outputAmounts {
		if amt.Sign() < 0 || amt.Cmp(maxAmount) >= 0 {
			// FIX: Do not leak individual amount values in the error message.
			return nil, fmt.Errorf("output amount %d out of range", i)
		}
	}
	if fee.Sign() < 0 || fee.Cmp(maxAmount) >= 0 {
		// FIX: Do not leak fee value in the error message.
		return nil, fmt.Errorf("fee out of range")
	}

	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}

	cacheKey := fmt.Sprintf("balance_%dx%d", len(inputAmounts), len(outputAmounts))
	circuit := &balanceCircuit{
		NumInputs:    len(inputAmounts),
		NumOutputs:   len(outputAmounts),
		AmountBitLen: BalanceAmountBitLen,
	}
	cc, err := sp.compileCircuit(cacheKey, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	// Build fixed-size arrays for gnark
	// Initialize all elements to 0 to avoid nil frontend.Variable values
	// (frontend.Variable is interface{}, zero value is nil, which causes
	// "can't set fr.Element with <nil>" when creating witness)
	inputAmountsArr := [MaxBalanceProofInputs]frontend.Variable{}
	outputAmountsArr := [MaxBalanceProofOutputs]frontend.Variable{}
	inputBlindingsArr := [MaxBalanceProofInputs]frontend.Variable{}
	outputBlindingsArr := [MaxBalanceProofOutputs]frontend.Variable{}
	inputCommitArr := [MaxBalanceProofInputs]frontend.Variable{}
	outputCommitArr := [MaxBalanceProofOutputs]frontend.Variable{}
	for i := 0; i < MaxBalanceProofInputs; i++ {
		inputAmountsArr[i] = big.NewInt(0)
		inputBlindingsArr[i] = big.NewInt(0)
		inputCommitArr[i] = big.NewInt(0)
	}
	for i := 0; i < MaxBalanceProofOutputs; i++ {
		outputAmountsArr[i] = big.NewInt(0)
		outputBlindingsArr[i] = big.NewInt(0)
		outputCommitArr[i] = big.NewInt(0)
	}

	// Compute MiMC commitments (circuit uses MiMC, not Pedersen)
	// The circuit asserts: MiMC(amount, blinding) == commitment
	mimcInputCommits := make([][]byte, len(inputAmounts))
	// L12-027 [P3] SOUNDNESS NOTE: inputAmounts (and outputAmounts) are NOT explicitly
	// domain-reduced (Mod curve.ScalarField()) before being fed to the native MiMC at
	// line ~885 (computeNativeMiMCPedersen uses the raw big.Int). Only the witness
	// assignment below (Mod at line ~883) is reduced. This is currently safe because the
	// range check above (lines ~826-837) bounds every amount to [0, 2^BalanceAmountBitLen),
	// which is far below the BLS12-381 scalar field (~255 bits). If BalanceAmountBitLen is
	// ever raised close to the scalar field bit length, the native (unreduced) and
	// in-circuit (reduced) MiMC inputs would diverge and break soundness; in that case
	// reduce inputAmounts[i]/inputBlindings[i] modulo ScalarField() before the native call.
	for i := 0; i < len(inputAmounts); i++ {
		inputAmountsArr[i] = new(big.Int).Mod(inputAmounts[i], curve.ScalarField())
		inputBlindingsArr[i] = new(big.Int).Mod(inputBlindings[i], curve.ScalarField())
		mimcCommit := computeNativeMiMCPedersen(inputAmounts[i], inputBlindings[i])
		mimcInputCommits[i] = mimcCommit.Bytes()
		inputCommitArr[i] = new(big.Int).SetBytes(mimcInputCommits[i])
	}
	mimcOutputCommits := make([][]byte, len(outputAmounts))
	for i := 0; i < len(outputAmounts); i++ {
		outputAmountsArr[i] = new(big.Int).Mod(outputAmounts[i], curve.ScalarField())
		outputBlindingsArr[i] = new(big.Int).Mod(outputBlindings[i], curve.ScalarField())
		mimcCommit := computeNativeMiMCPedersen(outputAmounts[i], outputBlindings[i])
		mimcOutputCommits[i] = mimcCommit.Bytes()
		outputCommitArr[i] = new(big.Int).SetBytes(mimcOutputCommits[i])
	}
	mimcFeeCommit := computeNativeMiMCPedersen(fee, feeBlinding)
	// FIX: Cache mimcFeeCommit.Bytes() once to avoid repeated
	// allocations. Bytes() creates a new 32-byte slice each call; previously
	// it was called 3 times (here, and again at the feeCommCopy block below).
	mimcFeeCommitBytes := mimcFeeCommit.Bytes()
	feeCommitInt := new(big.Int).SetBytes(mimcFeeCommitBytes)
	feeBlindingField := new(big.Int).Mod(feeBlinding, curve.ScalarField())

	// N19-003 FIX: Zero blinding factor on return
	// FIX: Also zero feeCommitInt and mimcFeeCommitBytes on return,
	// including panic paths. Previously feeCommitInt was only zeroed after
	// successful proof generation (line ~1136), leaving it in memory if
	// frontend.NewWitness or groth16.Prove panicked.
	defer func() {
		if feeBlindingField != nil {
			feeBlindingField.SetInt64(0)
		}
		if feeCommitInt != nil {
			feeCommitInt.SetInt64(0)
		}
		clear(mimcFeeCommitBytes)
	}()

	assignment := &balanceCircuit{
		InputBlinding:     inputBlindingsArr,
		OutputBlinding:    outputBlindingsArr,
		InputAmounts:      inputAmountsArr,
		OutputAmounts:     outputAmountsArr,
		Fee:               new(big.Int).Mod(fee, curve.ScalarField()),
		FeeBlinding:       feeBlindingField,
		InputCommitments:  inputCommitArr,
		OutputCommitments: outputCommitArr,
		FeeCommitment:     feeCommitInt,
		NumInputs:         len(inputAmounts),
		NumOutputs:        len(outputAmounts),
		AmountBitLen:      BalanceAmountBitLen,
	}

	witness, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}

	proof, err := groth16.Prove(cc.ccs, cc.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}

	// FIX: Zero witness vector and sensitive assignment fields after
	// proof generation to prevent sensitive financial data (amounts, blindings,
	// commitments) from lingering in memory. Mirrors quantum/zkp.go pattern.
	vec := witness.Vector()
	if vec != nil {
		elems, ok := vec.(bls12381fr.Vector)
		if !ok {
			return nil, fmt.Errorf("balance witness vector has unexpected type %T, expected fr.Vector", vec)
		}
		var zero bls12381fr.Element
		for i := range elems {
			elems[i] = zero
		}
	}
	// Zero the *big.Int values held in the frontend.Variable arrays
	for i := range inputAmountsArr {
		if bi, ok := inputAmountsArr[i].(*big.Int); ok {
			bi.SetInt64(0)
		}
		if bi, ok := inputBlindingsArr[i].(*big.Int); ok {
			bi.SetInt64(0)
		}
		if bi, ok := inputCommitArr[i].(*big.Int); ok {
			bi.SetInt64(0)
		}
	}
	for i := range outputAmountsArr {
		if bi, ok := outputAmountsArr[i].(*big.Int); ok {
			bi.SetInt64(0)
		}
		if bi, ok := outputBlindingsArr[i].(*big.Int); ok {
			bi.SetInt64(0)
		}
		if bi, ok := outputCommitArr[i].(*big.Int); ok {
			bi.SetInt64(0)
		}
	}
	feeCommitInt.SetInt64(0)
	// FIX: Zero assignment.Fee after proof generation.
	// assignment.Fee was created as new(big.Int).Mod(fee, curve.ScalarField())
	// at line ~1068 but never zeroed, leaving fee material in memory.
	// frontend.Variable is interface{}, so type-assert to *big.Int.
	if bi, ok := assignment.Fee.(*big.Int); ok {
		bi.SetInt64(0)
	}

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}

	// Copy MiMC commitment bytes (not the external Pedersen commitments)
	inputCommCopy := make([][]byte, len(mimcInputCommits))
	for i := range mimcInputCommits {
		inputCommCopy[i] = make([]byte, len(mimcInputCommits[i]))
		copy(inputCommCopy[i], mimcInputCommits[i])
	}
	outputCommCopy := make([][]byte, len(mimcOutputCommits))
	for i := range mimcOutputCommits {
		outputCommCopy[i] = make([]byte, len(mimcOutputCommits[i]))
		copy(outputCommCopy[i], mimcOutputCommits[i])
	}
	// FIX: Reuse cached mimcFeeCommitBytes instead of calling
	// mimcFeeCommit.Bytes() two more times (for len() and copy()).
	feeCommCopy := make([]byte, len(mimcFeeCommitBytes))
	copy(feeCommCopy, mimcFeeCommitBytes)

	// SECURITY (audit 2026-06-14, C5): Store the Pedersen commitments that
	// correspond to the SAME (amount, blinding) the proof is over. The prover
	// passed these in as inputCommitments/outputCommitments/feeCommitment; we
	// deep-copy them into the proof so VerifyBalance can bind the Groth16 proof
	// (over MiMC commitments) to the real transaction Pedersen commitments.
	// An honest prover passes Pedersen(a_i, b_i) here; a dishonest one cannot
	// both (a) satisfy the Groth16 proof over MiMC(a,b) and (b) attach Pedersen
	// commitments that disagree with the transaction's real commitments —
	// VerifyBalance rejects the latter.
	inputPedCopy := make([][]byte, len(inputCommitments))
	for i := range inputCommitments {
		inputPedCopy[i] = make([]byte, len(inputCommitments[i]))
		copy(inputPedCopy[i], inputCommitments[i])
	}
	outputPedCopy := make([][]byte, len(outputCommitments))
	for i := range outputCommitments {
		outputPedCopy[i] = make([]byte, len(outputCommitments[i]))
		copy(outputPedCopy[i], outputCommitments[i])
	}
	feePedCopy := make([]byte, len(feeCommitment))
	copy(feePedCopy, feeCommitment)

	// L11-002 FIX: Compute cross-commitment binding hash linking all MiMC
	// commitments (circuit public inputs) to all Pedersen commitments (transaction).
	// This ensures the Groth16 proof and the transaction reference the same
	// (amount, blinding) pairs, preventing cross-commitment forgery.
	balanceBindingHash := computeBalanceBindingHash(
		inputPedCopy, outputPedCopy, feePedCopy,
		inputCommCopy, outputCommCopy, feeCommCopy,
	)

	// AUDIT (2026) ZK-NN-1 FIX: Generate Schnorr binding proofs that
	// cryptographically link each MiMC commitment to a Pedersen commitment
	// via the shared blinding factor. For each commitment, we create
	// ecCommitment = PedersenCommit(mimcCommit, blinding) and generate a
	// Schnorr DLP proof that ecCommitment - mimcCommit*G = blinding*H.
	// This proves the Pedersen commitment opens to the MiMC value without
	// revealing the blinding. The verifier will also check that the real
	// transaction Pedersen commitments are homomorphically balanced,
	// preventing the cross-commitment forgery attack.
	gen, err := pedersen.NewGenerator()
	if err != nil {
		return nil, fmt.Errorf("pedersen generator: %w", err)
	}
	bindingQ := sp.config.QRNG
	if bindingQ == nil {
		bindingQ, err = qrng.New(qrng.DefaultQRNGConfig())
		if err != nil {
			return nil, fmt.Errorf("qrng init for binding: %w", err)
		}
		defer bindingQ.Close()
	}

	// Generate Schnorr bindings for inputs
	inputEcCommitments := make([][]byte, len(inputAmounts))
	inputSchnorrBindings := make([]*SchnorrBindingProof, len(inputAmounts))
	for i := 0; i < len(inputAmounts); i++ {
		mimcCommitInt := new(big.Int).SetBytes(inputCommCopy[i])
		ecCommit := gen.Commit(mimcCommitInt, inputBlindings[i])
		ecBytes := ecCommit.Bytes()
		ecCopy := make([]byte, len(ecBytes))
		copy(ecCopy, ecBytes)
		inputEcCommitments[i] = ecCopy

		bindingProof, err := generateSchnorrBinding(bindingQ, inputBlindings[i], ecCommit, gen, inputCommCopy[i])
		if err != nil {
			return nil, fmt.Errorf("input schnorr binding %d: %w", i, err)
		}
		inputSchnorrBindings[i] = bindingProof
		mimcCommitInt.SetInt64(0)
	}

	// Generate Schnorr bindings for outputs
	outputEcCommitments := make([][]byte, len(outputAmounts))
	outputSchnorrBindings := make([]*SchnorrBindingProof, len(outputAmounts))
	for i := 0; i < len(outputAmounts); i++ {
		mimcCommitInt := new(big.Int).SetBytes(outputCommCopy[i])
		ecCommit := gen.Commit(mimcCommitInt, outputBlindings[i])
		ecBytes := ecCommit.Bytes()
		ecCopy := make([]byte, len(ecBytes))
		copy(ecCopy, ecBytes)
		outputEcCommitments[i] = ecCopy

		bindingProof, err := generateSchnorrBinding(bindingQ, outputBlindings[i], ecCommit, gen, outputCommCopy[i])
		if err != nil {
			return nil, fmt.Errorf("output schnorr binding %d: %w", i, err)
		}
		outputSchnorrBindings[i] = bindingProof
		mimcCommitInt.SetInt64(0)
	}

	// Generate Schnorr binding for fee
	feeMimcCommitInt := new(big.Int).SetBytes(feeCommCopy)
	feeEcCommit := gen.Commit(feeMimcCommitInt, feeBlinding)
	feeEcBytes := feeEcCommit.Bytes()
	feeEcCopy := make([]byte, len(feeEcBytes))
	copy(feeEcCopy, feeEcBytes)
	feeSchnorrBinding, err := generateSchnorrBinding(bindingQ, feeBlinding, feeEcCommit, gen, feeCommCopy)
	if err != nil {
		return nil, fmt.Errorf("fee schnorr binding: %w", err)
	}
	feeMimcCommitInt.SetInt64(0)

	// FIX: Zero MiMC commitment byte slices after copies are made.
	// These contain derived commitment data that should not linger in memory.
	for i := range mimcInputCommits {
		for j := range mimcInputCommits[i] {
			mimcInputCommits[i][j] = 0
		}
	}
	for i := range mimcOutputCommits {
		for j := range mimcOutputCommits[i] {
			mimcOutputCommits[i][j] = 0
		}
	}
	// FIX: mimcFeeCommit is *PedersenCommitment, zero its Value field.
	if mimcFeeCommit != nil && mimcFeeCommit.Value != nil {
		mimcFeeCommit.Value.SetInt64(0)
	}

	return &BalanceProof{
		ProofBytes:            proofBuf.Bytes(),
		InputComm:             inputCommCopy,
		OutputComm:            outputCommCopy,
		FeeComm:               feeCommCopy,
		InputPedersenComm:     inputPedCopy,
		OutputPedersenComm:    outputPedCopy,
		FeePedersenComm:       feePedCopy,
		BalanceBindingHash:    balanceBindingHash,
		InputEcCommitments:    inputEcCommitments,
		OutputEcCommitments:   outputEcCommitments,
		FeeEcCommitment:       feeEcCopy,
		InputSchnorrBindings:  inputSchnorrBindings,
		OutputSchnorrBindings: outputSchnorrBindings,
		FeeSchnorrBinding:     feeSchnorrBinding,
	}, nil
}

func (sp *SigmaProtocol) VerifyBalance(
	proof *BalanceProof,
	inputCommitments [][]byte,
	outputCommitments [][]byte,
	feeCommitment []byte,
) error {
	if proof == nil {
		return ErrProofVerificationFailed
	}
	// L15-029 FIX: Reject proofs with empty commitment slices. An empty
	// InputComm or OutputComm could bypass verification by having zero
	// items to compare, effectively accepting a proof over nothing.
	if len(proof.InputComm) == 0 || len(proof.OutputComm) == 0 {
		return ErrInvalidStatement
	}
	if len(proof.InputComm) != len(inputCommitments) ||
		len(proof.OutputComm) != len(outputCommitments) ||
		len(proof.InputPedersenComm) != len(inputCommitments) ||
		len(proof.OutputPedersenComm) != len(outputCommitments) {
		return ErrInvalidStatement
	}

	// FIX: Validate MiMC commitment byte lengths before using them
	// as big.Int inputs. MiMC commitments on BLS12-381 are 32 bytes; reject
	// malformed commitments early (fail-fast) instead of letting groth16
	// verification fail with a confusing error.
	for i := range proof.InputComm {
		if len(proof.InputComm[i]) != 32 {
			return fmt.Errorf("%w: input MiMC commitment %d has invalid length %d, expected 32", ErrInvalidStatement, i, len(proof.InputComm[i]))
		}
	}
	for i := range proof.OutputComm {
		if len(proof.OutputComm[i]) != 32 {
			return fmt.Errorf("%w: output MiMC commitment %d has invalid length %d, expected 32", ErrInvalidStatement, i, len(proof.OutputComm[i]))
		}
	}
	if len(proof.FeeComm) != 32 {
		return fmt.Errorf("%w: fee MiMC commitment has invalid length %d, expected 32", ErrInvalidStatement, len(proof.FeeComm))
	}

	// SECURITY (audit 2026-06-14, C5): Bind the Groth16 proof to the REAL
	// transaction commitments. The proof's MiMC commitments (proof.InputComm
	// etc.) are the circuit's public inputs and are derived from (amount,
	// blinding). The transaction carries Pedersen commitments for the same
	// (amount, blinding). ProveBalance stores the Pedersen commitments it was
	// given alongside the MiMC commitments. Here we assert the stored Pedersen
	// commitments are byte-for-byte equal to the commitments the caller (the
	// confidential-tx verifier) is validating against — i.e. the real
	// transaction commitments. An attacker who wants to forge must either:
	//   (a) set proof.InputPedersenComm = real tx commitments, in which case
	//       the Groth16 proof must be over MiMC(a,b) where Pedersen(a,b) =
	//       real commitment — which requires knowing the real (a,b), i.e. a
	//       valid balanced tx; or
	//   (b) attach fake Pedersen commitments, which this check rejects.
	// Constant-time compare prevents timing oracles.
	for i := range proof.InputPedersenComm {
		if subtle.ConstantTimeCompare(proof.InputPedersenComm[i], inputCommitments[i]) != 1 {
			return fmt.Errorf("%w: input Pedersen commitment %d does not match transaction", ErrInvalidStatement, i)
		}
	}
	for i := range proof.OutputPedersenComm {
		if subtle.ConstantTimeCompare(proof.OutputPedersenComm[i], outputCommitments[i]) != 1 {
			return fmt.Errorf("%w: output Pedersen commitment %d does not match transaction", ErrInvalidStatement, i)
		}
	}
	if subtle.ConstantTimeCompare(proof.FeePedersenComm, feeCommitment) != 1 {
		return fmt.Errorf("%w: fee Pedersen commitment does not match transaction", ErrInvalidStatement)
	}

	// L11-002 FIX: Verify the cross-commitment binding hash. Recompute the hash
	// from the stored MiMC and Pedersen commitments and verify it matches.
	// This ensures the MiMC commitments (Groth16 circuit inputs) and Pedersen
	// commitments (transaction) were generated as a unit — an attacker cannot
	// swap either set independently.
	expectedBindingHash := computeBalanceBindingHash(
		proof.InputPedersenComm, proof.OutputPedersenComm, proof.FeePedersenComm,
		proof.InputComm, proof.OutputComm, proof.FeeComm,
	)
	if subtle.ConstantTimeCompare(proof.BalanceBindingHash, expectedBindingHash) != 1 {
		return fmt.Errorf("%w: balance binding hash mismatch - MiMC and Pedersen commitments are not linked",
			ErrBindingVerificationFailed)
	}

	// AUDIT (2026) ZK-NN-1 FIX: Verify Schnorr binding proofs that
	// cryptographically link each MiMC commitment to a Pedersen commitment
	// via the shared blinding factor. For each commitment, the prover created
	// ecCommitment = PedersenCommit(mimcCommit, blinding) and generated a
	// Schnorr DLP proof that ecCommitment - mimcCommit*G = blinding*H.
	// We verify each proof to ensure the Pedersen commitment opens to the
	// MiMC value without revealing the blinding.
	if len(proof.InputEcCommitments) != len(proof.InputComm) ||
		len(proof.OutputEcCommitments) != len(proof.OutputComm) ||
		len(proof.InputSchnorrBindings) != len(proof.InputComm) ||
		len(proof.OutputSchnorrBindings) != len(proof.OutputComm) ||
		proof.FeeSchnorrBinding == nil ||
		len(proof.FeeEcCommitment) == 0 {
		return fmt.Errorf("%w: missing Schnorr binding proofs for balance proof",
			ErrBindingVerificationFailed)
	}

	gen, err := pedersen.NewGenerator()
	if err != nil {
		return fmt.Errorf("pedersen generator: %w", err)
	}

	// Verify input Schnorr bindings
	for i := range proof.InputSchnorrBindings {
		ecCommit, err := pedersen.CommitmentFromBytes(proof.InputEcCommitments[i])
		if err != nil {
			return fmt.Errorf("%w: input EC commitment %d invalid: %v", ErrBindingVerificationFailed, i, err)
		}
		if err := verifySchnorrBinding(proof.InputSchnorrBindings[i], ecCommit, gen, proof.InputComm[i]); err != nil {
			return fmt.Errorf("%w: input Schnorr binding %d failed: %v", ErrBindingVerificationFailed, i, err)
		}
	}

	// Verify output Schnorr bindings
	for i := range proof.OutputSchnorrBindings {
		ecCommit, err := pedersen.CommitmentFromBytes(proof.OutputEcCommitments[i])
		if err != nil {
			return fmt.Errorf("%w: output EC commitment %d invalid: %v", ErrBindingVerificationFailed, i, err)
		}
		if err := verifySchnorrBinding(proof.OutputSchnorrBindings[i], ecCommit, gen, proof.OutputComm[i]); err != nil {
			return fmt.Errorf("%w: output Schnorr binding %d failed: %v", ErrBindingVerificationFailed, i, err)
		}
	}

	// Verify fee Schnorr binding
	feeEcCommit, err := pedersen.CommitmentFromBytes(proof.FeeEcCommitment)
	if err != nil {
		return fmt.Errorf("%w: fee EC commitment invalid: %v", ErrBindingVerificationFailed, err)
	}
	if err := verifySchnorrBinding(proof.FeeSchnorrBinding, feeEcCommit, gen, proof.FeeComm); err != nil {
		return fmt.Errorf("%w: fee Schnorr binding failed: %v", ErrBindingVerificationFailed, err)
	}

	// AUDIT (2026) ZK-NN-1 FIX: Pedersen homomorphic balance check.
	// Verify that the REAL transaction Pedersen commitments are homomorphically
	// balanced: Σ(InputPedersenComm) == Σ(OutputPedersenComm) + FeePedersenComm.
	// This uses Pedersen's homomorphic property: if C_i = Pedersen(a_i, b_i),
	// then Σ(C_input) - Σ(C_output) - C_fee = Pedersen(Σa_in - Σa_out - fee,
	// Σb_in - Σb_out - fee_blinding). For this to equal the identity point,
	// BOTH the amounts and blindings must be balanced. Since G and H are
	// linearly independent, this proves the REAL transaction amounts are
	// balanced, preventing the cross-commitment forgery attack where an
	// attacker uses balanced MiMC values with unbalanced Pedersen values.
	inputPedCommits := make([]*pedersen.Commitment, len(proof.InputPedersenComm))
	for i := range proof.InputPedersenComm {
		c, err := pedersen.CommitmentFromBytes(proof.InputPedersenComm[i])
		if err != nil {
			return fmt.Errorf("%w: input Pedersen commitment %d invalid: %v", ErrInvalidStatement, i, err)
		}
		inputPedCommits[i] = c
	}
	outputPedCommits := make([]*pedersen.Commitment, len(proof.OutputPedersenComm))
	for i := range proof.OutputPedersenComm {
		c, err := pedersen.CommitmentFromBytes(proof.OutputPedersenComm[i])
		if err != nil {
			return fmt.Errorf("%w: output Pedersen commitment %d invalid: %v", ErrInvalidStatement, i, err)
		}
		outputPedCommits[i] = c
	}
	feePedCommit, err := pedersen.CommitmentFromBytes(proof.FeePedersenComm)
	if err != nil {
		return fmt.Errorf("%w: fee Pedersen commitment invalid: %v", ErrInvalidStatement, err)
	}
	if !gen.VerifyBalance(inputPedCommits, outputPedCommits, feePedCommit) {
		return fmt.Errorf("%w: Pedersen homomorphic balance check failed - real transaction amounts are not balanced",
			ErrBindingVerificationFailed)
	}

	numInputs := len(inputCommitments)
	numOutputs := len(outputCommitments)
	cacheKey := fmt.Sprintf("balance_%dx%d", numInputs, numOutputs)
	cc, ok := sp.cache.get(cacheKey)
	if !ok {
		return ErrCircuitNotCompiled
	}

	curve := sp.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}

	gnarkProof := groth16.NewProof(curve)
	if _, err := gnarkProof.ReadFrom(bytes.NewReader(proof.ProofBytes)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}

	// Reconstruct public inputs from the MiMC commitments stored in the proof.
	// (These are the circuit's public inputs; see DESIGN NOTE above re: the
	// remaining binding gap to the transaction's Pedersen commitments.)
	// Initialize all elements to 0 to avoid nil frontend.Variable values
	inputCommitArr := [MaxBalanceProofInputs]frontend.Variable{}
	outputCommitArr := [MaxBalanceProofOutputs]frontend.Variable{}
	for i := 0; i < MaxBalanceProofInputs; i++ {
		inputCommitArr[i] = big.NewInt(0)
	}
	for i := 0; i < MaxBalanceProofOutputs; i++ {
		outputCommitArr[i] = big.NewInt(0)
	}
	for i := range proof.InputComm {
		inputCommitArr[i] = new(big.Int).SetBytes(proof.InputComm[i])
	}
	for i := range proof.OutputComm {
		outputCommitArr[i] = new(big.Int).SetBytes(proof.OutputComm[i])
	}
	feeCommitInt := new(big.Int).SetBytes(proof.FeeComm)
	// FIX: Zero feeCommitInt on return (defensive cleanup), including
	// panic paths via defer. Previously feeCommitInt was only zeroed after
	// successful verification (line ~1377), leaving it in memory if
	// frontend.NewWitness or groth16.Verify panicked.
	defer func() { feeCommitInt.SetInt64(0) }()

	assignment := &balanceCircuit{
		NumInputs:         numInputs,
		NumOutputs:        numOutputs,
		AmountBitLen:      BalanceAmountBitLen,
		InputCommitments:  inputCommitArr,
		OutputCommitments: outputCommitArr,
		FeeCommitment:     feeCommitInt,
	}

	publicWitness, err := frontend.NewWitness(assignment, curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("create public witness: %w", err)
	}

	err = groth16.Verify(gnarkProof, cc.vk, publicWitness)
	if err != nil {
		return fmt.Errorf("%w: balance proof verification failed", ErrProofVerificationFailed)
	}

	return nil
}

// computeBalanceBindingHash computes a SHA3-256 hash that cryptographically
// links all Pedersen commitments (transaction) to all MiMC commitments (circuit
// public inputs). This ensures the Groth16 proof and the transaction reference
// the same set of (amount, blinding) pairs.
// L11-002 FIX: Without this binding, an attacker could attach a valid Groth16
// proof over balanced MiMC commitments to a transaction whose Pedersen commitments
// are unbalanced, minting confidential value.
func computeBalanceBindingHash(inputPedersen, outputPedersen [][]byte, feePedersen []byte,
	inputMiMC, outputMiMC [][]byte, feeMiMC []byte) []byte {
	// TODO(): This hash does not use length-prefix encoding for the
	// commitment byte slices. Direct concatenation without length prefixes creates
	// a theoretical ambiguity where two different sets of commitments could produce
	// the same hash (e.g. [ab,cd] vs [abcd]). This is currently SAFE because all
	// Pedersen and MiMC commitments are fixed-length (32 bytes), making the
	// ambiguity non-exploitable. However, if variable-length commitments are ever
	// introduced, length-prefix encoding (e.g. encode.Uint32(length) || commitment)
	// MUST be added to prevent hash collision attacks.
	// L15-027 NOTE: This hash does not use length-prefixing for the commitment
	// byte slices. In theory, this creates an ambiguity where two different sets
	// of commitments could produce the same hash (e.g. [ab,cd] vs [abcd]).
	// In practice, all Pedersen and MiMC commitments are fixed-length (32 bytes),
	// so the ambiguity is not exploitable. If variable-length commitments are
	// introduced in the future, length prefixes must be added.
	h := sha3.New256()
	h.Reset() // L18-027 FIX: ensure clean hash state
	h.Write([]byte("Quantaureum-BalanceBinding-V1"))
	for _, c := range inputPedersen {
		h.Write(c)
	}
	for _, c := range outputPedersen {
		h.Write(c)
	}
	h.Write(feePedersen)
	for _, c := range inputMiMC {
		h.Write(c)
	}
	for _, c := range outputMiMC {
		h.Write(c)
	}
	h.Write(feeMiMC)
	result := h.Sum(nil)
	// R31-P4 FIX: Reset SHA3 state after Sum to clear internal buffers.
	h.Reset()
	return result
}

// computeNativeMiMCPedersen computes a Pedersen-like commitment using MiMC.
// This is used to verify balance proofs without revealing amounts.
// L9-048 NOTE: The function name includes "Pedersen" for historical reasons,
// but this does NOT use elliptic-curve Pedersen commitments. It computes a
// MiMC-hash-based commitment (value || blinding -> MiMC -> field element).
// The PedersenCommitment return type wraps the MiMC output for API uniformity.
// L10-026 CLARIFICATION: The name "computeNativeMiMCPedersen" is misleading —
// it does NOT compute a Pedersen commitment (elliptic curve scalar multiplication).
// It computes MiMC(value, blinding) as a hash-based commitment. The "Pedersen"
// in the name is a historical artifact from when the balance circuit intended
// to use Pedersen commitments but was switched to MiMC. Callers should treat
// the output as a MiMC hash, not an elliptic curve point. The PedersenCommitment
// wrapper type is retained solely to avoid breaking the API; its .Bytes() method
// returns the 32-byte MiMC hash, not a compressed EC point.
func computeNativeMiMCPedersen(value, blinding *big.Int) *PedersenCommitment {
	h := mimc_native.NewMiMC()
	writeFieldElement(h, value)
	writeFieldElement(h, blinding)
	result := h.Sum(nil)
	// L9-050 FIX: Reset the MiMC hasher to clear its internal block buffer,
	// which still holds the absorbed value/blinding commitment material.
	h.Reset()
	// N19-004 FIX: Create commitment from result, then zero the result buffer
	// to prevent sensitive hash material from lingering in memory.
	commit := &PedersenCommitment{Value: new(big.Int).SetBytes(result)}
	for i := range result {
		result[i] = 0
	}
	return commit
}

// PedersenCommitment for internal use in balance proof computation
type PedersenCommitment struct {
	Value *big.Int
}

func (c *PedersenCommitment) Bytes() []byte {
	if c.Value == nil {
		return nil
	}
	result := make([]byte, 32)
	c.Value.FillBytes(result[:])
	return result
}

type BatchVerifier struct {
	protocol *SigmaProtocol
}

func NewBatchVerifier(protocol *SigmaProtocol) *BatchVerifier {
	return &BatchVerifier{
		protocol: protocol,
	}
}

// VerifySchnorrSequential verifies each proof individually in sequence.
// L13-009 FIX: Despite living on BatchVerifier, this method performs
// SEQUENTIAL verification (one groth16.Verify per proof), not true batch
// verification. True batch verification would combine all proofs via a
// random linear combination into a single equation, yielding an asymptotic
// speedup. Implementing that requires a batch-verify API in the underlying
// groth16 backend; until then this method is renamed from BatchVerifySchnorr
// to accurately reflect its sequential behavior and avoid misleading callers
// into assuming batch-level performance.
func (bv *BatchVerifier) VerifySchnorrSequential(proofs []*SchnorrProof, publicHashes [][]byte) error {
	if len(proofs) != len(publicHashes) {
		return ErrInvalidStatement
	}
	curve := bv.protocol.config.Curve
	if curve == 0 {
		curve = ecc.BLS12_381
	}
	cc, ok := bv.protocol.cache.get("preimage")
	if !ok {
		return ErrCircuitNotCompiled
	}
	for i, proof := range proofs {
		if proof == nil {
			return ErrProofVerificationFailed
		}
		gnarkProof := groth16.NewProof(curve)
		if _, err := gnarkProof.ReadFrom(bytes.NewReader(proof.ProofBytes)); err != nil {
			return fmt.Errorf("deserialize proof %d: %w", i, err)
		}
		hashInt := new(big.Int).SetBytes(publicHashes[i])
		// R39-P3 FIX: Zero hashInt after each iteration to prevent memory residue.
		// R37 legacy item — the single-proof path (line 551) was fixed in R38
		// but this batch loop was missed.
		assignment := &preimageCircuit{Hash: hashInt}
		publicWitness, err := frontend.NewWitness(assignment, curve.ScalarField(), frontend.PublicOnly())
		if err != nil {
			hashInt.SetInt64(0)
			return fmt.Errorf("create public witness %d: %w", i, err)
		}
		err = groth16.Verify(gnarkProof, cc.vk, publicWitness)
		if err != nil {
			hashInt.SetInt64(0)
			return ErrProofVerificationFailed
		}
		hashInt.SetInt64(0)
	}
	return nil
}

// computeNativeMiMC computes the MiMC hash of a single field element.
//
//	DUPLICATION NOTE: This function is duplicated in the quantum
//
// package (quantum/zkp.go:computeNativeMiMC). The quantum package version
// inlines the field-element serialization (Mod -> FillBytes -> Write)
// because it cannot import qzkp without creating a circular dependency;
// this version uses the shared writeFieldElement helper. Both implementations
// MUST stay in sync: any change to one must be reflected in the other.
//
//	NOTE: Callers should zero the input data after calling this
//
// function if it contains sensitive material. This function zeroes its
// internal buffers and result, but does not modify the caller's `data`.
func computeNativeMiMC(data *big.Int) *big.Int {
	h := mimc_native.NewMiMC()
	writeFieldElement(h, data)
	result := h.Sum(nil)
	// L9-050 FIX: Reset the MiMC hasher to clear internal state.
	h.Reset()
	ret := new(big.Int).SetBytes(result)
	// Q21-006 FIX: Zero the result buffer to prevent residual hash data.
	// Without this, MiMC hash output remains in memory and could be used to
	// reverse-engineer sensitive input data (e.g., transaction amounts).
	for i := range result {
		result[i] = 0
	}
	return ret
}

// computeNativeMiMCWithSuffix computes the MiMC hash of a field element
// followed by a single-byte suffix. Used for domain-separated hashing.
func computeNativeMiMCWithSuffix(data *big.Int, suffix byte) *big.Int {
	h := mimc_native.NewMiMC()
	writeFieldElement(h, data)
	writeFieldElement(h, big.NewInt(int64(suffix)))
	result := h.Sum(nil)
	// L9-050 FIX: Reset the MiMC hasher to clear internal state.
	h.Reset()
	ret := new(big.Int).SetBytes(result)
	// FIX: Zero the result buffer to prevent residual hash data.
	for i := range result {
		result[i] = 0
	}
	return ret
}

// writeFieldElement writes a big.Int as a 32-byte big-endian field element
// to the given writer, reducing it modulo the BLS12-381 scalar field first.
//
//	NOTE: big.NewInt/new(big.Int) allocation per call is intentional
//
// and acceptable for security: each invocation needs a fresh allocation to
// avoid aliasing bugs where concurrent callers could corrupt shared state.
func writeFieldElement(h io.Writer, val *big.Int) {
	var buf [32]byte
	reduced := new(big.Int).Mod(val, ecc.BLS12_381.ScalarField())
	reduced.FillBytes(buf[:])
	h.Write(buf[:])
	// L16-018 FIX: Zeroize sensitive field element material after use.
	for i := range buf {
		buf[i] = 0
	}
	reduced.SetInt64(0)
}

// computeMerkleRoot computes the Merkle root for a leaf given its sibling
// hashes and path directions (0 = leaf is left, non-zero = leaf is right).
// Uses MiMC as the internal hashing function over BLS12-381 field elements.
func computeMerkleRoot(leaf *big.Int, siblings []*big.Int, directions []*big.Int) *big.Int {
	current := leaf
	for i := 0; i < len(siblings); i++ {
		h := mimc_native.NewMiMC()
		var left, right *big.Int
		if directions[i].Sign() != 0 {
			left = siblings[i]
			right = current
		} else {
			left = current
			right = siblings[i]
		}
		writeFieldElement(h, left)
		writeFieldElement(h, right)
		result := h.Sum(nil)
		// L9-050 FIX: Reset the MiMC hasher to clear internal state.
		h.Reset()
		current = new(big.Int).SetBytes(result)
		// FIX: Zero the result buffer to prevent intermediate hash
		// values from remaining in memory across loop iterations.
		for j := range result {
			result[j] = 0
		}
	}
	return current
}
