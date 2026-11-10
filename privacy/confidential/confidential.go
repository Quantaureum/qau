// Quantaureum Node source, version 1.0.0.
package confidential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/quantaureum/qau/pedersen"
	"github.com/quantaureum/qau/qrng"
	"github.com/quantaureum/qau/qzkp"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/hkdf"
)

var (
	ErrInvalidCommitment     = errors.New("confidential: invalid commitment")
	ErrCommitmentMismatch    = errors.New("confidential: commitment mismatch")
	ErrEncryptionFailed      = errors.New("confidential: encryption failed")
	ErrDecryptionFailed      = errors.New("confidential: decryption failed")
	ErrRangeProofFailed      = errors.New("confidential: range proof verification failed")
	ErrBalanceProofFailed    = errors.New("confidential: balance proof verification failed")
	ErrInvalidAmount         = errors.New("confidential: invalid amount")
	ErrNegativeAmount        = errors.New("confidential: negative amount")
	ErrMissingPubKey         = errors.New("confidential: missing recipient public key")
	ErrDuplicateNullifier    = errors.New("confidential: duplicate nullifier detected")
	ErrInvalidNullifierProof = errors.New("confidential: invalid nullifier proof")

	// ErrRangeProofBindingUnaudited is returned only while the kill-switch
	// rangeProofBindingAudited is closed (false). It is no longer the guard
	// against run-8: the circuit-level root fix (TxProof, a Groth16 proof
	// whose public input is the real transaction commitment) replaced the
	// self-referential Schnorr binding, and legacy-format proofs are
	// structurally rejected with ErrLegacyRangeProofFormat.
	ErrRangeProofBindingUnaudited = errors.New("confidential: range proof is not bound to the external Pedersen commitment (circuit-level binding pending)")

	// ErrLegacyRangeProofFormat is returned for range proofs that do not
	// carry the circuit-bound TxProof (audit run-8: node/qzkp-range-proof-
	// self-reference). Such proofs prove a range statement about a
	// prover-chosen MiMC commitment and never constrain the real
	// transaction commitment; they are rejected unconditionally.
	ErrLegacyRangeProofFormat = errors.New("confidential: legacy range proof format rejected (not bound to the transaction commitment)")
)

// Domain separator constants for nullifier derivation
const (
	DomainNullifierV1     = "quantaureum-nullifier-v1"
	DomainNullifierCommit = "quantaureum-nullifier-commit-v1"
)

// PolicyTxValueBitLength is the fixed range-proof bit width for confidential
// transaction amounts: the proven AND verified statement is
// "amount < 2^PolicyTxValueBitLength". Prover and verifier MUST share this
// single source of truth — a prover-chosen wider bit width (up to the
// structural qzkp.MaxTxRangeBitLength of 254) would weaken the range
// statement the verifier accepts (e.g., to a near-vacuous [0, 2^254)), so
// VerifyRangeProof rejects any TxProof whose BitLength differs from this
// policy constant (fail-closed).
const PolicyTxValueBitLength = 128

type ConfidentialAmount struct {
	Commitment      []byte
	EncryptedAmount []byte
	RangeProof      *qzkp.RangeProof
	Blinding        []byte
	EphemeralPubKey []byte
}

type ConfidentialTransaction struct {
	TxHash         types.Hash
	Inputs         []*ConfidentialAmount
	Outputs        []*ConfidentialAmount
	Fee            *big.Int
	FeeCommitment  []byte
	FeeBlinding    []byte
	BalanceProof   *qzkp.BalanceProof
	NullifierProof *NullifierProof
}

type NullifierProof struct {
	Nullifier         types.Hash
	PreviousNullifier types.Hash
	TxHash            types.Hash
	DomainSeparator   []byte
	ChainPath         []byte
	// CRITICAL FIX: Store actual ZK proof - was being discarded causing verification bypass
	Proof *qzkp.SchnorrProof
	// AUDIT (2026) HIGH-19 (ZK-NN-3): Bind the nullifier to its derivation
	// inputs so the verifier can recompute the canonical nullifier and MiMC
	// public hash instead of trusting prover-supplied values. Without this,
	// an attacker could attach a valid ZK proof over arbitrary inputs to a
	// fake nullifier and double-spend.
	Commitment      []byte
	EphemeralPubKey []byte
}

type ConfidentialManager struct {
	mu       sync.RWMutex
	config   qzkp.ZKConfig
	protocol *qzkp.SigmaProtocol
}

func NewConfidentialManager() *ConfidentialManager {
	q, _ := qrng.New(qrng.DefaultQRNGConfig())
	config := qzkp.DefaultZKConfig(q)
	return &ConfidentialManager{
		config:   config,
		protocol: qzkp.NewSigmaProtocol(config),
	}
}

// NewConfidentialManagerWithConfig creates a ConfidentialManager with a custom ZKConfig.
// This is intended for testing (e.g., to enable AllowInsecureSetup for local trusted
// setup) or for advanced deployments that need to tune ZK parameters. Production code
// should typically use NewConfidentialManager() which applies production-safe defaults.
func NewConfidentialManagerWithConfig(config qzkp.ZKConfig) *ConfidentialManager {
	return &ConfidentialManager{
		config:   config,
		protocol: qzkp.NewSigmaProtocol(config),
	}
}

type PedersenGenerator struct {
	gen *pedersen.Generator
}

// NewPedersenGenerator creates a Pedersen commitment generator.
// Returns an error instead of panicking so a failure during transaction
// construction cannot crash the node (R7-R2 fix). Callers that need a
// panic-on-init behavior can do `if err != nil { panic(err) }` themselves.
//
// AUDIT (2026) ZK-NN-1 FIX: Uses BLS12-381 Pedersen commitments
// (pedersen.Generator) instead of trie.PedersenBasis (Z_p* commitments).
// The ZK proof system (qzkp) and the Schnorr binding proofs operate on
// BLS12-381 G1 points. Using a different commitment group for the
// transaction commitments made the ZK-NN-1 homomorphic balance check
// fail because the 256-byte Z_p* commitments are not valid BLS12-381
// G1 points. Unifying on BLS12-381 ensures all components share the
// same group and the homomorphic balance check succeeds.
func NewPedersenGenerator() (*PedersenGenerator, error) {
	gen, err := pedersen.NewGenerator()
	if err != nil {
		return nil, fmt.Errorf("confidential: failed to create Pedersen generator: %w", err)
	}
	return &PedersenGenerator{gen: gen}, nil
}

// NewPedersenGeneratorOrPanic is the legacy constructor retained for callers
// (init paths, tests) that prefer fail-fast behavior. New code should use
// NewPedersenGenerator and handle the error.
func NewPedersenGeneratorOrPanic() *PedersenGenerator {
	pg, err := NewPedersenGenerator()
	if err != nil {
		panic(err)
	}
	return pg
}

func (pg *PedersenGenerator) Commit(amount *big.Int, blinding []byte) []byte {
	// R11-PRIV-003 FIX: Return nil on CommitWithBlinding failure instead of
	// falling back to SHA256. The SHA256 fallback does not have Pedersen's
	// homomorphic properties, causing balance proof verification to fail or
	// produce incorrect results. Callers should check for nil return.
	if amount == nil {
		return nil
	}
	blindingInt := new(big.Int).SetBytes(blinding)
	commitment := pg.gen.Commit(amount, blindingInt)
	// Zero the blinding big.Int to prevent sensitive material from lingering.
	blindingInt.SetInt64(0)
	return commitment.Bytes()
}

func (pg *PedersenGenerator) Verify(commitment []byte, amount *big.Int, blinding []byte) bool {
	expected := pg.Commit(amount, blinding)
	if len(commitment) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare(commitment, expected) == 1
}

func (cm *ConfidentialManager) EncryptAmount(amount *big.Int, receiverKemPubKey []byte, senderKey []byte) ([]byte, error) {
	sharedKey, kemCt, err := kemEncapsulate(receiverKemPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: KEM encapsulation failed: %v", ErrEncryptionFailed, err)
	}

	encrypted, err := encryptWithKey(amount, sharedKey)
	for i := range sharedKey {
		sharedKey[i] = 0
	}
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, len(kemCt)+len(encrypted))
	result = append(result, kemCt...)
	result = append(result, encrypted...)
	return result, nil
}

func (cm *ConfidentialManager) DecryptAmount(encrypted []byte, receiverKemPrivKey []byte, senderPubKey []byte) (*big.Int, error) {
	kemCtSize := kyber768.CiphertextSize
	if len(encrypted) < kemCtSize {
		return nil, ErrDecryptionFailed
	}

	kemCt := encrypted[:kemCtSize]
	encAmount := encrypted[kemCtSize:]

	sharedKey, err := kemDecapsulate(receiverKemPrivKey, kemCt)
	if err != nil {
		return nil, fmt.Errorf("%w: KEM decapsulation failed: %v", ErrDecryptionFailed, err)
	}
	defer func() {
		for i := range sharedKey {
			sharedKey[i] = 0
		}
	}()

	return decryptWithKey(encAmount, sharedKey)
}

func encryptWithKey(amount *big.Int, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrEncryptionFailed
	}

	amountBytes := amount.Bytes()
	ciphertext := gcm.Seal(nonce, nonce, amountBytes, nil)

	return ciphertext, nil
}

func decryptWithKey(encrypted []byte, key []byte) (*big.Int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, ErrDecryptionFailed
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	amount := new(big.Int).SetBytes(plaintext)

	return amount, nil
}

// GenerateRangeProof produces the LEGACY (unbound) range proof format.
//
// DEPRECATED (run-8 root fix): the returned proof states the range condition
// about a prover-chosen MiMC commitment and is NOT bound to the transaction's
// Pedersen commitment; VerifyRangeProof rejects it with
// ErrLegacyRangeProofFormat. Retained only for input-validation tests and API
// compatibility. Production code MUST use GenerateRangeProofWithBlinding.
func (cm *ConfidentialManager) GenerateRangeProof(amount *big.Int, bitLength int, commitment []byte) (*qzkp.RangeProof, error) {
	// PRIV-RP-01 FIX (deep-audit 2026-07-12): validate bitLength and amount
	// before the shift. bitLength==0 makes uint(bitLength-1) wrap to ~2^64, so
	// Lsh below attempts a ~2^64-bit allocation (OOM); a nil amount panics in
	// Cmp.
	if bitLength < 1 || bitLength > 256 {
		return nil, ErrInvalidAmount
	}
	if amount == nil {
		return nil, ErrInvalidAmount
	}
	maxVal := new(big.Int).Lsh(big.NewInt(1), uint(bitLength-1))
	if amount.Cmp(maxVal) >= 0 {
		return nil, ErrInvalidAmount
	}

	proof, err := cm.protocol.ProveValueInRange(amount, bitLength)
	if err != nil {
		return nil, err
	}
	// Store the external (e.g., Pedersen) commitment for binding verification
	if len(commitment) > 0 {
		proof.ExternalCommitment = make([]byte, len(commitment))
		copy(proof.ExternalCommitment, commitment)
	}
	return proof, nil
}

// GenerateRangeProofWithBlinding generates a range proof cryptographically
// bound to the REAL transaction Pedersen commitment.
//
// AUDIT run-8 ROOT FIX (node/qzkp-range-proof-self-reference): the previous
// implementation produced a MiMC-circuit proof plus a self-referential
// Schnorr binding (ecCommitment = Pedersen(MiMC(amount), blinding) was
// prover-chosen, never the transaction commitment), so the proven range
// statement did not constrain the committed amount. The new implementation
// calls ProveTxValueInRange, whose Groth16 circuit takes C_tx as a public
// input and constrains C_tx == amount*G + blinding*H with amount < 2^bitLen.
// Since the Pedersen opening is unique (G, H independent), the proven range
// statement applies to the transaction's committed amount.
func (cm *ConfidentialManager) GenerateRangeProofWithBlinding(amount *big.Int, bitLength int, commitment []byte, blinding []byte) (*qzkp.RangeProof, error) {
	// Validate bitLength and amount before any arithmetic. bitLength==0
	// would make uint(bitLength-1) wrap; a nil or negative amount panics in
	// Cmp (PRIV-RP-01 fix).
	if bitLength < 1 || bitLength > 256 {
		return nil, ErrInvalidAmount
	}
	if amount == nil || amount.Sign() < 0 {
		return nil, ErrInvalidAmount
	}
	// Match the circuit's proven bound exactly: amount < 2^bitLength.
	maxVal := new(big.Int).Lsh(big.NewInt(1), uint(bitLength))
	if amount.Cmp(maxVal) >= 0 {
		return nil, ErrInvalidAmount
	}
	if len(blinding) == 0 {
		return nil, ErrInvalidCommitment
	}
	if len(commitment) != qzkp.G1PointSize {
		return nil, ErrInvalidCommitment
	}

	gen, err := pedersen.NewGenerator()
	if err != nil {
		return nil, fmt.Errorf("pedersen generator: %w", err)
	}

	blindingInt := new(big.Int).SetBytes(blinding)
	defer blindingInt.SetInt64(0)

	txProof, err := cm.protocol.ProveTxValueInRange(amount, blindingInt, bitLength, commitment, gen)
	if err != nil {
		return nil, fmt.Errorf("tx range proof: %w", err)
	}
	return &qzkp.RangeProof{
		BitLength: bitLength,
		TxProof:   txProof,
	}, nil
}

// rangeProofBindingAudited gates the confidential range-proof acceptance
// path. It stays in the code as a kill-switch: flipping it back to false
// re-closes the path without a code rollback.
//
// It was flipped to TRUE for the run-8 root fix
// (node/qzkp-range-proof-self-reference): VerifyRangeProof now verifies
// TxProof, a Groth16 proof whose PUBLIC input is the real transaction
// Pedersen commitment C_tx, constraining C_tx == amount*G + blinding*H with
// amount < 2^BitLength in-circuit (emulated BLS12-381 G1 arithmetic; Pedersen
// opening uniqueness gives the soundness argument). The legacy
// self-referential format (MiMC circuit + Schnorr binding to a
// prover-chosen commitment) is structurally rejected. Justification for the
// flip: algebraic soundness argument in qzkp/bound_tx_range.go plus negative
// tests (wrong commitment, replay, tampered commitment, legacy format) and
// positive end-to-end tests all pass. Pre-existing deployment prerequisite
// (unchanged, orthogonal to this fix): production cross-node verification
// still requires an MPC-ceremony trusted setup via LoadTrustedSetup
// (ZK-NN-7); with per-process local setup, cross-node proofs fail closed.
const rangeProofBindingAudited = true

// VerifyRangeProof verifies the range proof for a confidential amount
// against the commitment extracted from the transaction. Only the
// circuit-bound format at the fixed policy bit width (PolicyTxValueBitLength)
// is accepted; anything else fails closed.
func (cm *ConfidentialManager) VerifyRangeProof(proof *qzkp.RangeProof, commitment []byte) error {
	if !rangeProofBindingAudited {
		return ErrRangeProofBindingUnaudited
	}
	if proof == nil {
		return ErrRangeProofFailed
	}
	if commitment == nil || len(commitment) == 0 {
		return ErrRangeProofFailed
	}
	// run-8 root fix: only the circuit-bound format is accepted. Proofs
	// without TxProof prove a range statement about a prover-chosen MiMC
	// commitment (self-referential) and are rejected unconditionally.
	if proof.TxProof == nil {
		return ErrLegacyRangeProofFormat
	}
	// Policy bit width: the range statement is only meaningful at the
	// fixed policy width shared with the prover. A wider (attacker-
	// chosen) BitLength would weaken the verified range up to
	// [0, 2^MaxTxRangeBitLength), so reject before any cryptographic
	// work. Collapsed to ErrRangeProofFailed like every other
	// verification failure (no verification internals leaked).
	if proof.TxProof.BitLength != PolicyTxValueBitLength {
		return ErrRangeProofFailed
	}
	if err := cm.protocol.VerifyTxValueInRange(proof.TxProof, commitment); err != nil {
		// Do not leak verification internals to callers.
		return ErrRangeProofFailed
	}
	return nil
}

func (cm *ConfidentialManager) GeneratePedersenBalanceProof(
	inputAmounts []*big.Int,
	inputBlindings [][]byte,
	outputAmounts []*big.Int,
	outputBlindings [][]byte,
	fee *big.Int,
	feeBlinding []byte,
	inputCommitments [][]byte,
	outputCommitments [][]byte,
	feeCommitment []byte,
) (*qzkp.BalanceProof, error) {
	// Convert blindings to big.Int
	inputBlindingBigints := make([]*big.Int, len(inputBlindings))
	for i, b := range inputBlindings {
		inputBlindingBigints[i] = new(big.Int).SetBytes(b)
	}
	outputBlindingBigints := make([]*big.Int, len(outputBlindings))
	for i, b := range outputBlindings {
		outputBlindingBigints[i] = new(big.Int).SetBytes(b)
	}
	feeBlindingBigint := new(big.Int).SetBytes(feeBlinding)

	return cm.protocol.ProveBalance(
		inputAmounts,
		inputBlindingBigints,
		outputAmounts,
		outputBlindingBigints,
		fee,
		feeBlindingBigint,
		inputCommitments,
		outputCommitments,
		feeCommitment,
	)
}

func (cm *ConfidentialManager) VerifyPedersenBalanceProof(
	proof *qzkp.BalanceProof,
	inputCommitments [][]byte,
	outputCommitments [][]byte,
	feeCommitment []byte,
) error {
	return cm.protocol.VerifyBalance(proof, inputCommitments, outputCommitments, feeCommitment)
}

func (cm *ConfidentialManager) GenerateBalanceProof(inputCommitments, outputCommitments [][]byte, fee *big.Int) (*qzkp.SchnorrProof, error) {
	// DEPRECATED: This method only proves knowledge of preimage of hash(commitments),
	// NOT that Σ(inputs) = Σ(outputs) + fee in Pedersen-homomorphic sense.
	// Use GeneratePedersenBalanceProof for proper balance proofs.
	allData := make([]byte, 0)
	for _, c := range inputCommitments {
		allData = append(allData, c...)
	}
	for _, c := range outputCommitments {
		allData = append(allData, c...)
	}
	allData = append(allData, fee.Bytes()...)

	witness := make([]byte, len(allData))
	copy(witness, allData)

	publicHash := cm.config.HashFunc(witness)

	return cm.protocol.ProveKnowledgeOfPreimage(witness, publicHash)
}

func (cm *ConfidentialManager) VerifyBalanceProof(proof *qzkp.SchnorrProof, inputCommitments, outputCommitments [][]byte, fee *big.Int) error {
	// DEPRECATED: See GenerateBalanceProof
	if proof == nil {
		return ErrBalanceProofFailed
	}
	allData := make([]byte, 0)
	for _, c := range inputCommitments {
		allData = append(allData, c...)
	}
	for _, c := range outputCommitments {
		allData = append(allData, c...)
	}
	allData = append(allData, fee.Bytes()...)
	publicHash := cm.config.HashFunc(allData)
	return cm.protocol.VerifyKnowledgeOfPreimage(proof, publicHash)
}

func (cm *ConfidentialManager) CreateConfidentialTx(inputAmounts []*big.Int, outputAmounts []*big.Int, outputPubKeys [][]byte, senderPubKey []byte, fee *big.Int) (*ConfidentialTransaction, error) {
	pg, err := NewPedersenGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to create Pedersen generator: %w", err)
	}

	inputs := make([]*ConfidentialAmount, len(inputAmounts))
	for i, amt := range inputAmounts {
		blinding := make([]byte, 32)
		if _, err := rand.Read(blinding); err != nil {
			return nil, err
		}

		commitment := pg.Commit(amt, blinding)

		ephemeralKey := make([]byte, 32)
		if _, err := rand.Read(ephemeralKey); err != nil {
			return nil, err
		}

		encAmount, err := cm.EncryptAmount(amt, senderPubKey, ephemeralKey)
		if err != nil {
			return nil, err
		}

		rangeProof, err := cm.GenerateRangeProofWithBlinding(amt, PolicyTxValueBitLength, commitment, blinding)
		if err != nil {
			return nil, err
		}

		inputs[i] = &ConfidentialAmount{
			Commitment:      commitment,
			EncryptedAmount: encAmount,
			RangeProof:      rangeProof,
			Blinding:        blinding,
			EphemeralPubKey: ephemeralKey,
		}
	}

	outputs := make([]*ConfidentialAmount, len(outputAmounts))
	for i, amt := range outputAmounts {
		blinding := make([]byte, 32)
		if _, err := rand.Read(blinding); err != nil {
			return nil, err
		}

		commitment := pg.Commit(amt, blinding)

		if i >= len(outputPubKeys) {
			return nil, ErrMissingPubKey
		}
		pubKey := outputPubKeys[i]

		ephemeralKey := make([]byte, 32)
		if _, err := rand.Read(ephemeralKey); err != nil {
			return nil, err
		}

		encAmount, err := cm.EncryptAmount(amt, pubKey, ephemeralKey)
		if err != nil {
			return nil, err
		}

		rangeProof, err := cm.GenerateRangeProofWithBlinding(amt, PolicyTxValueBitLength, commitment, blinding)
		if err != nil {
			return nil, err
		}

		outputs[i] = &ConfidentialAmount{
			Commitment:      commitment,
			EncryptedAmount: encAmount,
			RangeProof:      rangeProof,
			Blinding:        blinding,
			EphemeralPubKey: ephemeralKey,
		}
	}

	inputComms := make([][]byte, len(inputs))
	for i, inp := range inputs {
		inputComms[i] = inp.Commitment
	}
	outputComms := make([][]byte, len(outputs))
	for i, out := range outputs {
		outputComms[i] = out.Commitment
	}

	// Collect all blindings for the proper Pedersen balance proof
	inputBlindings := make([][]byte, len(inputs))
	for i, inp := range inputs {
		inputBlindings[i] = inp.Blinding
	}
	outputBlindings := make([][]byte, len(outputs))
	for i, out := range outputs {
		outputBlindings[i] = out.Blinding
	}

	// AUDIT (2026) ZK-NN-1 FIX: Compute the fee blinding to satisfy the
	// Pedersen homomorphic balance equation:
	//   Σ(b_input) == Σ(b_output) + b_fee  (mod curveOrder)
	//   => b_fee = Σ(b_input) - Σ(b_output)  (mod curveOrder)
	// This is REQUIRED for the Pedersen homomorphic balance check in
	// VerifyBalance to pass. The check verifies:
	//   Σ(InputPedersenComm) - Σ(OutputPedersenComm) - FeePedersenComm == Identity
	// which expands (since G,H are linearly independent) to BOTH:
	//   (1) Σ(amount_in)  == Σ(amount_out) + fee        (amount balance)
	//   (2) Σ(b_in)        == Σ(b_out) + b_fee           (blinding balance)
	// The amount balance is enforced by the Groth16 circuit; the blinding
	// balance is enforced by choosing b_fee here. Using a random b_fee would
	// make (2) fail almost certainly, causing every legitimate transaction
	// to be rejected.
	feeBlindingInt := new(big.Int)
	for _, b := range inputBlindings {
		feeBlindingInt.Add(feeBlindingInt, new(big.Int).SetBytes(b))
	}
	for _, b := range outputBlindings {
		feeBlindingInt.Sub(feeBlindingInt, new(big.Int).SetBytes(b))
	}
	feeBlindingInt.Mod(feeBlindingInt, pedersen.CurveOrder())
	// FillBytes panics if the value doesn't fit in 32 bytes; after Mod the
	// value is in [0, curveOrder) which is 255 bits, so 32 bytes always suffices.
	feeBlinding := feeBlindingInt.FillBytes(make([]byte, 32))
	feeBlindingInt.SetInt64(0) // zero temp to avoid lingering sensitive material
	feeCommitment := pg.Commit(fee, feeBlinding)

	// Generate proper Pedersen balance proof that proves:
	// Σ(committed inputs) = Σ(committed outputs) + fee in homomorphic sense
	balanceProof, err := cm.GeneratePedersenBalanceProof(
		inputAmounts, inputBlindings,
		outputAmounts, outputBlindings,
		fee, feeBlinding,
		inputComms, outputComms,
		feeCommitment,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Pedersen balance proof: %w", err)
	}

	txHashData := make([]byte, 0)
	for _, inp := range inputs {
		txHashData = append(txHashData, inp.Commitment...)
	}
	for _, out := range outputs {
		txHashData = append(txHashData, out.Commitment...)
	}
	txHashData = append(txHashData, fee.Bytes()...)
	txHashData = append(txHashData, feeCommitment...)
	txHash := sha256.Sum256(txHashData)

	var nullifierProof *NullifierProof
	if len(outputs) > 0 {
		output := outputs[0]
		nullifierProof, err = cm.GenerateNullifierProof(txHash, output.Commitment, output.EphemeralPubKey, types.Hash{})
		if err != nil {
			return nil, fmt.Errorf("failed to generate nullifier proof: %w", err)
		}
	}

	return &ConfidentialTransaction{
		TxHash:         txHash,
		Inputs:         inputs,
		Outputs:        outputs,
		Fee:            fee,
		FeeCommitment:  feeCommitment,
		FeeBlinding:    feeBlinding,
		BalanceProof:   balanceProof,
		NullifierProof: nullifierProof,
	}, nil
}

func (cm *ConfidentialManager) VerifyConfidentialTx(tx *ConfidentialTransaction) error {
	if tx == nil {
		return ErrInvalidCommitment
	}

	// QZKP-001 FIX: Verify range proofs for INPUTS as well.
	// Previously only outputs were verified, allowing attackers to inject
	// inputs with out-of-range or negative amounts while still passing
	// the Schnorr balance proof (which only proves preimage knowledge,
	// not actual Pedersen balance equality).
	for _, inp := range tx.Inputs {
		if err := cm.VerifyRangeProof(inp.RangeProof, inp.Commitment); err != nil {
			return err
		}
	}

	for _, out := range tx.Outputs {
		if err := cm.VerifyRangeProof(out.RangeProof, out.Commitment); err != nil {
			return err
		}
	}

	inputComms := make([][]byte, len(tx.Inputs))
	for i, inp := range tx.Inputs {
		inputComms[i] = inp.Commitment
	}
	outputComms := make([][]byte, len(tx.Outputs))
	for i, out := range tx.Outputs {
		outputComms[i] = out.Commitment
	}

	// Verify the Pedersen balance proof that Σ(inputs) = Σ(outputs) + fee
	if err := cm.VerifyPedersenBalanceProof(tx.BalanceProof, inputComms, outputComms, tx.FeeCommitment); err != nil {
		return fmt.Errorf("balance proof verification failed: %w", err)
	}

	if tx.NullifierProof != nil {
		if err := cm.VerifyNullifierProof(tx.NullifierProof); err != nil {
			return fmt.Errorf("nullifier proof verification failed: %w", err)
		}
		// AUDIT (2026) ZK-NN-3 FIX: Bind the nullifier proof to the actual
		// transaction outputs. VerifyNullifierProof recomputes the canonical
		// nullifier from (txHash, commitment, ephemeralPubKey) and verifies the
		// ZK proof, but previously did not check that these inputs correspond to
		// a REAL output in this transaction. An attacker could attach a valid
		// nullifier proof over a fake commitment/ephemeralPubKey, allowing
		// double-spending with arbitrary nullifiers.
		if tx.NullifierProof.TxHash != tx.TxHash {
			return fmt.Errorf("%w: nullifier proof txHash does not match transaction", ErrInvalidNullifierProof)
		}
		matchedOutput := false
		for _, out := range tx.Outputs {
			if subtle.ConstantTimeCompare(tx.NullifierProof.Commitment, out.Commitment) == 1 &&
				subtle.ConstantTimeCompare(tx.NullifierProof.EphemeralPubKey, out.EphemeralPubKey) == 1 {
				matchedOutput = true
				break
			}
		}
		if !matchedOutput {
			return fmt.Errorf("%w: nullifier proof commitment does not match any transaction output", ErrInvalidNullifierProof)
		}
	}

	return nil
}

// deriveSharedKey derives a shared encryption key from sender and receiver key
// material using HKDF with domain separation.
//
// SECURITY NOTE: This is a transitional implementation. In production, this MUST
// be replaced with Kyber768 key encapsulation (KEM) where:
//   - Sender encapsulates a shared secret using the receiver's Kyber public key
//   - Receiver decapsulates using their Kyber private key
//   - Both parties derive the same shared secret through the KEM
//
// The current HKDF-based approach requires both parties to contribute key material
// but does not provide proper asymmetric key agreement. The senderKey parameter
// prepares the API for Kyber KEM integration where the sender's ephemeral key
// will be used for encapsulation.
func kemEncapsulate(kemPubKeyBytes []byte) (sharedKey []byte, ciphertext []byte, err error) {
	if len(kemPubKeyBytes) != kyber768.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid KEM public key size: expected %d, got %d", kyber768.PublicKeySize, len(kemPubKeyBytes))
	}

	kemPub := &kyber768.PublicKey{}
	kemPub.Unpack(kemPubKeyBytes)

	ct := make([]byte, kyber768.CiphertextSize)
	ss := make([]byte, kyber768.SharedKeySize)
	kemPub.EncapsulateTo(ct, ss, nil)

	hkdfReader := hkdf.New(sha256.New, ss, nil, []byte("quantaureum-confidential-kem-v2"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		for i := range ss {
			ss[i] = 0
		}
		return nil, nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	for i := range ss {
		ss[i] = 0
	}

	return derivedKey, ct, nil
}

func kemDecapsulate(kemPrivKeyBytes []byte, ciphertext []byte) ([]byte, error) {
	if len(kemPrivKeyBytes) != kyber768.PrivateKeySize {
		return nil, fmt.Errorf("invalid KEM private key size: expected %d, got %d", kyber768.PrivateKeySize, len(kemPrivKeyBytes))
	}

	if len(ciphertext) != kyber768.CiphertextSize {
		return nil, fmt.Errorf("invalid ciphertext size: expected %d, got %d", kyber768.CiphertextSize, len(ciphertext))
	}

	kemPriv := &kyber768.PrivateKey{}
	kemPriv.Unpack(kemPrivKeyBytes)

	ss := make([]byte, kyber768.SharedKeySize)
	kemPriv.DecapsulateTo(ss, ciphertext)

	hkdfReader := hkdf.New(sha256.New, ss, nil, []byte("quantaureum-confidential-kem-v2"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		for i := range ss {
			ss[i] = 0
		}
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	for i := range ss {
		ss[i] = 0
	}

	return derivedKey, nil
}

// DeriveNullifier computes a domain-separated nullifier from commitment and tx context.
// The nullifier is derived as:
//
//	H(domain || txHash || commitment || ephemeralPubKey)
//
// This ensures:
//   - Each transaction has a unique nullifier (domain + txHash)
//   - Each output has a unique nullifier (commitment)
//   - Replay protection (ephemeralPubKey includes per-output randomness)
//   - Domain separation prevents cross-protocol attacks
func DeriveNullifier(txHash types.Hash, commitment []byte, ephemeralPubKey []byte) types.Hash {
	h := sha256.New()
	h.Write([]byte(DomainNullifierV1))
	h.Write(txHash[:])
	h.Write(commitment)
	h.Write(ephemeralPubKey)

	digest := h.Sum(nil)
	var nullifier types.Hash
	copy(nullifier[:], digest[:32])
	return nullifier
}

// DeriveNullifierWithPrevious extends nullifier derivation to include previous nullifier
// in the chain, creating a linked list of nullifiers for additional replay protection.
// This forms a hash chain: nullifier[n] = H(domain || nullifier[n-1] || txHash[n])
func DeriveNullifierWithPrevious(txHash types.Hash, commitment []byte, ephemeralPubKey []byte, previousNullifier types.Hash) types.Hash {
	h := sha256.New()
	h.Write([]byte(DomainNullifierCommit))
	h.Write(previousNullifier[:])
	h.Write(txHash[:])
	h.Write(commitment)
	h.Write(ephemeralPubKey)

	digest := h.Sum(nil)
	var nullifier types.Hash
	copy(nullifier[:], digest[:32])
	return nullifier
}

// GenerateNullifierProof creates a proof that the nullifier is correctly derived
// from the transaction data and includes membership in the nullifier chain.
// This allows verifiers to check that the nullifier hasn't been used before
// without revealing which specific output it corresponds to.
func (cm *ConfidentialManager) GenerateNullifierProof(txHash types.Hash, commitment []byte, ephemeralPubKey []byte, previousNullifier types.Hash) (*NullifierProof, error) {
	nullifier := DeriveNullifier(txHash, commitment, ephemeralPubKey)

	var chainPath []byte
	if previousNullifier != (types.Hash{}) {
		nullifier = DeriveNullifierWithPrevious(txHash, commitment, ephemeralPubKey, previousNullifier)
		h := sha256.New()
		h.Write(previousNullifier[:])
		h.Write(nullifier[:])
		chainPath = h.Sum(nil)
	} else {
		h := sha256.New()
		h.Write(nullifier[:])
		h.Write(txHash[:])
		chainPath = h.Sum(nil)
	}

	domainSep := []byte(DomainNullifierV1)
	witness := make([]byte, 0, len(domainSep)+len(txHash[:])+len(commitment)+len(ephemeralPubKey))
	witness = append(witness, domainSep...)
	witness = append(witness, txHash[:]...)
	witness = append(witness, commitment...)
	witness = append(witness, ephemeralPubKey...)

	// Pass nil as publicHash - ProveKnowledgeOfPreimage computes MiMC hash internally
	// and stores it in SchnorrProof.PublicHash. The nullifier is SHA-256 based,
	// which is different from MiMC, so we cannot pass it as the expected MiMC hash.
	proof, err := cm.protocol.ProveKnowledgeOfPreimage(witness, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to generate nullifier proof: %v", ErrInvalidNullifierProof, err)
	}

	// CRITICAL FIX: Store proof instead of discarding - proof is essential for verification
	// AUDIT (2026) HIGH-19 (ZK-NN-3): also store Commitment/EphemeralPubKey
	// so the verifier can recompute the canonical nullifier and MiMC public hash.
	return &NullifierProof{
		Nullifier:         nullifier,
		PreviousNullifier: previousNullifier,
		TxHash:            txHash,
		DomainSeparator:   domainSep,
		ChainPath:         chainPath,
		Proof:             proof,
		Commitment:        append([]byte(nil), commitment...),
		EphemeralPubKey:   append([]byte(nil), ephemeralPubKey...),
	}, nil
}

// VerifyNullifierProof verifies that a nullifier proof is valid.
// It checks:
//  1. The ZK proof is present and valid (proves knowledge of nullifier preimage)
//  2. The domain separator is correct (domain separation)
//  3. The chain path correctly links to previous nullifier (if any)
func (cm *ConfidentialManager) VerifyNullifierProof(proof *NullifierProof) error {
	if proof == nil {
		return ErrInvalidNullifierProof
	}

	if len(proof.DomainSeparator) == 0 {
		return fmt.Errorf("%w: missing domain separator", ErrInvalidNullifierProof)
	}

	// CRITICAL FIX: Verify the actual ZK proof - was completely bypassed before
	if proof.Proof == nil {
		return fmt.Errorf("%w: missing ZK proof", ErrInvalidNullifierProof)
	}

	// AUDIT (2026) HIGH-19 (ZK-NN-3): Bind the nullifier to its canonical
	// derivation inputs. Previously the verifier accepted proof.Nullifier and
	// proof.Proof.PublicHash as prover-supplied values without recomputing
	// them, allowing an attacker to attach a valid ZK proof over arbitrary
	// inputs to a fake nullifier. We now:
	//   1. Recompute the canonical nullifier from (txHash, commitment, ephemeralPubKey)
	//      and reject if it doesn't match proof.Nullifier.
	//   2. Recompute the canonical MiMC public hash from the same witness and
	//      reject if it doesn't match proof.Proof.PublicHash.
	//   3. Only then verify the ZK proof against the recomputed hash.
	if len(proof.Commitment) == 0 || len(proof.EphemeralPubKey) == 0 {
		return fmt.Errorf("%w: missing nullifier binding inputs", ErrInvalidNullifierProof)
	}

	// 1. Recompute canonical nullifier (handles both single and chained cases).
	var expectedNullifier types.Hash
	if proof.PreviousNullifier != (types.Hash{}) {
		expectedNullifier = DeriveNullifierWithPrevious(
			proof.TxHash, proof.Commitment, proof.EphemeralPubKey, proof.PreviousNullifier,
		)
	} else {
		expectedNullifier = DeriveNullifier(
			proof.TxHash, proof.Commitment, proof.EphemeralPubKey,
		)
	}
	if subtle.ConstantTimeCompare(expectedNullifier[:], proof.Nullifier[:]) != 1 {
		return fmt.Errorf("%w: nullifier does not match canonical derivation", ErrInvalidNullifierProof)
	}

	// 2. Recompute the canonical MiMC public hash from the witness that the
	//    prover should have used. This MUST match the hash embedded in the
	//    SchnorrProof — otherwise the proof was generated over different inputs.
	witness := make([]byte, 0, len(proof.DomainSeparator)+len(proof.TxHash[:])+len(proof.Commitment)+len(proof.EphemeralPubKey))
	witness = append(witness, proof.DomainSeparator...)
	witness = append(witness, proof.TxHash[:]...)
	witness = append(witness, proof.Commitment...)
	witness = append(witness, proof.EphemeralPubKey...)
	expectedPublicHash := cm.protocol.ComputePreimageHash(witness)
	if len(expectedPublicHash) == 0 {
		return fmt.Errorf("%w: failed to recompute public hash", ErrInvalidNullifierProof)
	}
	if subtle.ConstantTimeCompare(expectedPublicHash, proof.Proof.PublicHash) != 1 {
		return fmt.Errorf("%w: public hash does not match canonical derivation", ErrInvalidNullifierProof)
	}

	// 3. Verify the ZK proof against the recomputed (canonical) public hash.
	if err := cm.protocol.VerifyKnowledgeOfPreimage(proof.Proof, expectedPublicHash); err != nil {
		return fmt.Errorf("%w: ZK proof verification failed: %v", ErrInvalidNullifierProof, err)
	}

	h := sha256.New()
	if proof.PreviousNullifier != (types.Hash{}) {
		h.Write(proof.PreviousNullifier[:])
	} else {
		h.Write(proof.Nullifier[:])
	}
	h.Write(proof.TxHash[:])
	// R11-PRIV-001 FIX: Compare expectedPath with proof.ChainPath using
	// constant-time comparison. Previously the computed hash was discarded,
	// allowing any non-empty ChainPath to pass verification.
	expectedPath := h.Sum(nil)

	if len(proof.ChainPath) == 0 {
		return fmt.Errorf("%w: missing chain path", ErrInvalidNullifierProof)
	}

	if subtle.ConstantTimeCompare(expectedPath, proof.ChainPath) != 1 {
		return fmt.Errorf("%w: chain path mismatch", ErrInvalidNullifierProof)
	}

	return nil
}

// NullifierMembershipProof represents a Merkle proof for nullifier set membership
type NullifierMembershipProof struct {
	Nullifier   types.Hash
	MerkleRoot  types.Hash
	MerkleProof []types.Hash
	Position    uint32
}

// GenerateNullifierMembershipProof creates a Merkle proof that a nullifier
// is a member of the committed nullifier set. This allows efficient verification
// that the nullifier hasn't been spent without requiring the entire nullifier set.
func GenerateNullifierMembershipProof(nullifier types.Hash, merkleRoot types.Hash, merklePath []types.Hash, position uint32) *NullifierMembershipProof {
	return &NullifierMembershipProof{
		Nullifier:   nullifier,
		MerkleRoot:  merkleRoot,
		MerkleProof: merklePath,
		Position:    position,
	}
}

// VerifyNullifierMembershipProof verifies a Merkle proof of nullifier membership.
// The verifier recomputes the Merkle root from the nullifier and proof path,
// then compares against the claimed root using constant-time comparison.
func VerifyNullifierMembershipProof(proof *NullifierMembershipProof) bool {
	if proof == nil || proof.Nullifier == (types.Hash{}) {
		return false
	}
	// audit-fix CRITICAL-2: validate proof structure before recomputing.
	if len(proof.MerkleProof) == 0 {
		return false
	}
	// audit-fix CRITICAL-2: use constant-time comparison to prevent timing attacks.
	currentHash := proof.Nullifier
	for i, sibling := range proof.MerkleProof {
		if sibling == (types.Hash{}) {
			return false
		}
		if proof.Position&(1<<uint(i)) != 0 {
			h := sha256.New()
			h.Write(sibling[:])
			h.Write(currentHash[:])
			currentHash = types.Hash{}
			copy(currentHash[:], h.Sum(nil)[:32])
		} else {
			h := sha256.New()
			h.Write(currentHash[:])
			h.Write(sibling[:])
			currentHash = types.Hash{}
			copy(currentHash[:], h.Sum(nil)[:32])
		}
	}
	// Constant-time comparison to prevent timing-based branch detection
	return constTimeCompare(currentHash[:], proof.MerkleRoot[:]) == 1
}

// constTimeCompare performs constant-time comparison of two byte slices.
// Returns 1 if equal, 0 if not equal. Prevents timing attacks on sensitive comparisons.
func constTimeCompare(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	if result == 0 {
		return 1
	}
	return 0
}
