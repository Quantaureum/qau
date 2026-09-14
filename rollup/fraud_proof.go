// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"crypto/sha3"
	"encoding/binary"
	"log"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/types"
)

// BatchLookup provides access to batch data for fraud proof verification.
type BatchLookup interface {
	GetBatch(index uint64) (*Batch, error)
}

// SignatureVerifier verifies challenger signatures against their addresses.
// ROLLUP-001 FIX: Added to enable real cryptographic signature verification
// instead of just checking that the signature is non-empty.
//
// W-P1-1 FIX (2026-07-13): The interface now includes pubKey so the verifier
// can validate that pubKey derives to `challenger` AND that the signature
// matches. L2 challengers' pubkeys are not stored on L1, so the proof carries
// the pubkey inline (ChallengerPubKey field).
type SignatureVerifier interface {
	// VerifyFraudProofSignature verifies that the signature was produced by
	// the challenger's private key over the given message.
	VerifyFraudProofSignature(challenger types.Address, pubKey []byte, msg []byte, sig []byte) bool
}

type FraudProofType uint8

const (
	FraudProofTypeStateTransition FraudProofType = 0
	FraudProofTypeInvalidBatch    FraudProofType = 1
	FraudProofTypeDoubleSpend     FraudProofType = 2
)

type FraudProof struct {
	Type          FraudProofType
	BatchIndex    uint64
	Challenger    types.Address
	PreStateRoot  types.Hash
	PostStateRoot types.Hash
	InvalidTx     *RollupTransaction
	ProofData     []byte
	Timestamp     int64
	// ROLLUP-001 FIX: Challenger signature over the fraud proof to prevent
	// impersonation. The signature covers Type || BatchIndex || PreStateRoot ||
	// PostStateRoot || Timestamp, signed by the Challenger's Dilithium3 key.
	ChallengerSig []byte
	// W-P1-1 FIX (2026-07-13): Challenger's Dilithium3 public key (1952 bytes).
	// L2 challengers' pubkeys are not stored on L1, so the proof carries the
	// pubkey inline. The verifier checks pubkey derives to Challenger address
	// AND signature verifies. NOT included in the signed message — it is
	// verification metadata, like ChallengerSig.
	ChallengerPubKey []byte
}

type FraudProver struct {
	mu           sync.RWMutex
	config       *RollupConfig
	stateManager *StateManager
	batchLookup  BatchLookup
	sigVerifier  SignatureVerifier // ROLLUP-001: for challenger signature verification
	// R6-RP-002 FIX: When true, fraud proofs are rejected if no SignatureVerifier
	// is configured.
	// R3-C1 FIX (2026-07-06): Default changed to true (fail-closed).
	// Previously defaulted to false for backward compatibility with tests,
	// but this allowed unauthenticated fraud proofs in production.
	// Tests that need to bypass verification should call
	// SetRequireSignatureVerifier(false) explicitly.
	requireSigVerifier bool
	// RLLP-R5-07 (2026-07-17): Production lock. Once LockProductionMode()
	// is called, SetRequireSignatureVerifier(false) is rejected — the
	// fail-closed behavior cannot be disabled at runtime. This prevents
	// an operator or compromised code path from disabling signature
	// verification in production. Mainnet deployments MUST call
	// LockProductionMode() after initialization.
	productionLocked bool
	proofs           map[uint64]*FraudProof
	// W-P1-3 (2026-07-13): Optional persistence layer for fraud proofs.
	persistence Persistence
	// W-P3-1 (2026-07-14): Prometheus metrics for fraud proof monitoring.
	// Nil when not configured; all helper methods are nil-safe.
	metrics *RollupMetrics
}

func NewFraudProver(config *RollupConfig, stateManager *StateManager) *FraudProver {
	return &FraudProver{
		config:             config,
		stateManager:       stateManager,
		proofs:             make(map[uint64]*FraudProof),
		requireSigVerifier: true, // R3-C1 FIX: fail-closed by default
	}
}

func (fp *FraudProver) SetBatchLookup(lookup BatchLookup) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.batchLookup = lookup
}

// SetSignatureVerifier sets the signature verifier for challenger signature
// verification. ROLLUP-001 FIX: Required for full cryptographic verification.
func (fp *FraudProver) SetSignatureVerifier(sv SignatureVerifier) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.sigVerifier = sv
}

// SetRequireSignatureVerifier enables strict mode where fraud proofs are
// rejected if no SignatureVerifier is configured. Production deployments
// should call this with true to prevent accepting unauthenticated proofs.
//
// RLLP-R5-07 (2026-07-17): Once LockProductionMode() is called, attempts to
// disable requireSigVerifier (passing false) are rejected. This prevents
// runtime downgrade of the fail-closed behavior in production.
func (fp *FraudProver) SetRequireSignatureVerifier(require bool) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if !require && fp.productionLocked {
		log.Printf("[ERROR] rollup: RLLP-R5-07: refusing SetRequireSignatureVerifier(false) — production mode is locked, cannot disable fail-closed signature verification")
		return
	}
	fp.requireSigVerifier = require
}

// LockProductionMode enables the RLLP-R5-07 production lock. Once called:
//   - SetRequireSignatureVerifier(false) is rejected (fail-closed cannot
//     be disabled at runtime).
//
// This is a one-way operation: once locked, the FraudProver cannot be
// unlocked. Mainnet deployments MUST call this after initialization.
// Testnet/devnet may skip this to allow SetRequireSignatureVerifier(false)
// for testing.
//
// RLLP-R5-07 (2026-07-17)
func (fp *FraudProver) LockProductionMode() {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.productionLocked = true
	// Also force requireSigVerifier=true in case it was disabled before
	// locking. This ensures the production lock always starts from a
	// fail-closed state.
	fp.requireSigVerifier = true
}

// SetMetrics injects Prometheus metrics for fraud proof monitoring.
// W-P3-1 FIX (2026-07-14)
func (fp *FraudProver) SetMetrics(m *RollupMetrics) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.metrics = m
}

func (fp *FraudProver) SubmitFraudProof(proof *FraudProof) error {
	fp.mu.Lock()

	// W-P3-1 (2026-07-14): Count every submission attempt (before verification).
	fp.metrics.IncFraudProofSubmitted()

	if _, exists := fp.proofs[proof.BatchIndex]; exists {
		fp.mu.Unlock()
		return ErrFraudProofInvalid
	}

	if err := fp.verifyFraudProof(proof); err != nil {
		fp.mu.Unlock()
		return err
	}

	// W-P3-1 (2026-07-14): Count proofs that passed verification.
	fp.metrics.IncFraudProofVerified()

	fp.proofs[proof.BatchIndex] = proof

	// W-P1-3 (2026-07-13): Persist the fraud proof. Done under lock for
	// consistency; unlock before returning.
	var persistErr error
	if fp.persistence != nil {
		if err := fp.persistence.SaveFraudProof(proof); err != nil {
			persistErr = err
		}
	}
	fp.mu.Unlock()

	if persistErr != nil {
		log.Printf("[rollup] WARN: persist fraud proof (batch %d) failed: %v", proof.BatchIndex, persistErr)
	}
	return nil
}

// SetPersistence injects the persistence layer for fraud proofs.
// W-P1-3 FIX (2026-07-13)
func (fp *FraudProver) SetPersistence(p Persistence) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.persistence = p
}

// RestoreFraudProofs loads persisted fraud proofs into memory. Called once
// on engine startup.
// W-P1-3 FIX (2026-07-13)
func (fp *FraudProver) RestoreFraudProofs(proofs []*FraudProof) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	for _, p := range proofs {
		fp.proofs[p.BatchIndex] = p
	}
}

func (fp *FraudProver) verifyFraudProof(proof *FraudProof) error {
	if proof.BatchIndex == 0 && proof.PreStateRoot == (types.Hash{}) {
		return ErrFraudProofInvalid
	}

	if proof.Challenger == (types.Address{}) {
		return ErrFraudProofInvalid
	}

	// ROLLUP-001 FIX: Verify challenger signature to prevent impersonation.
	// The signature must cover the core fraud proof fields.
	if len(proof.ChallengerSig) == 0 {
		return ErrFraudProofInvalid
	}

	// ROLLUP-001 FIX: If a SignatureVerifier is configured, perform full
	// cryptographic verification. If no verifier is configured (e.g. in
	// unit tests without a validator set), fall back to the non-empty check
	// with a warning log. This is a defense-in-depth approach: production
	// ROLLUP2-001 FIX: Warn when no SignatureVerifier is configured.
	// Production deployments MUST call SetSignatureVerifier() to enable
	// full cryptographic verification of challenger signatures.
	if fp.sigVerifier != nil {
		// W-P1-1 FIX: Require inline ChallengerPubKey for L2 fraud proofs.
		// L2 challengers' pubkeys are not stored on L1, so the verifier
		// cannot look them up by address. The proof MUST carry the pubkey.
		if len(proof.ChallengerPubKey) == 0 {
			return ErrFraudProofInvalid
		}
		msg := buildFraudProofSignMessage(proof)
		if !fp.sigVerifier.VerifyFraudProofSignature(proof.Challenger, proof.ChallengerPubKey, msg, proof.ChallengerSig) {
			return ErrFraudProofInvalid
		}
	} else if fp.requireSigVerifier {
		// R6-RP-002 FIX: In production mode, reject fraud proofs when no
		// SignatureVerifier is configured instead of silently accepting them.
		return ErrFraudProofInvalid
	} else {
		// ROLLUP2-001 FIX: Log a warning every time a proof is accepted
		// without full signature verification.
		log.Printf("[WARN] rollup: fraud proof accepted from %x without SignatureVerifier — "+
			"production deployments MUST call SetSignatureVerifier()", proof.Challenger[:8])
	}

	// R6-RP-001 FIX: Use proof.Timestamp validation without time.Now() to
	// ensure determinism across nodes. The fraud proof must have a valid
	// positive timestamp. The actual freshness check (whether the proof is
	// too far in the future) should be done by the caller using block time,
	// not wall-clock time which varies per node.
	if proof.Timestamp <= 0 {
		return ErrFraudProofInvalid
	}

	switch proof.Type {
	case FraudProofTypeStateTransition:
		return fp.verifyStateTransitionFraud(proof)
	case FraudProofTypeInvalidBatch:
		return fp.verifyInvalidBatchFraud(proof)
	case FraudProofTypeDoubleSpend:
		return fp.verifyDoubleSpendFraud(proof)
	default:
		return ErrFraudProofInvalid
	}
}

// buildFraudProofSignMessage constructs the message that the challenger must
// sign. ROLLUP-001 FIX: Used by both the verifier and the prover to ensure
// consistent message construction.
// ROLLUP3-002 FIX: Include ProofData hash in the signature message for
// complete end-to-end integrity protection.
func buildFraudProofSignMessage(proof *FraudProof) []byte {
	// Message = Type(1) || BatchIndex(8) || PreStateRoot(32) || PostStateRoot(32) || Timestamp(8) || ProofDataHash(32)
	msg := make([]byte, 1+8+types.HashLength+types.HashLength+8+types.HashLength)
	msg[0] = byte(proof.Type)
	binary.BigEndian.PutUint64(msg[1:9], proof.BatchIndex)
	copy(msg[9:9+types.HashLength], proof.PreStateRoot[:])
	copy(msg[9+types.HashLength:9+2*types.HashLength], proof.PostStateRoot[:])
	binary.BigEndian.PutUint64(msg[9+2*types.HashLength:9+2*types.HashLength+8], uint64(proof.Timestamp))
	// ROLLUP3-002 FIX: Append ProofData hash for complete integrity.
	proofDataHash := sha3.Sum256(proof.ProofData)
	copy(msg[9+2*types.HashLength+8:], proofDataHash[:])

	// Hash the message for signature verification
	h := sha3.New256()
	h.Write(msg)
	return h.Sum(nil)
}

func (fp *FraudProver) verifyStateTransitionFraud(proof *FraudProof) error {
	if proof.InvalidTx == nil {
		return ErrFraudProofInvalid
	}

	// R36-P0-03 FIX (2026-07-30): Bind the proof to the actual on-chain
	// batch. Previously proof.PreStateRoot / proof.PostStateRoot were
	// challenger-supplied and NEVER compared to the batch's recorded roots.
	// A challenger could attach a garbage PostStateRoot to an honest batch
	// and the proof would verify (expectedRoot != garbage → "fraud found"),
	// permanently blocking finalization with zero cost.
	//
	// Now we require the FraudProver to have a BatchLookup (same as
	// verifyInvalidBatchFraud) and verify:
	//   1. proof.PreStateRoot == batch.PrevStateRoot
	//   2. proof.PostStateRoot == batch.PostStateRoot
	//   3. proof.InvalidTx actually belongs to batch.Transactions
	// Only then do we SimulateBatch and check expectedRoot != batch.PostStateRoot.
	if fp.batchLookup == nil {
		return ErrFraudProofInvalid
	}
	batch, err := fp.batchLookup.GetBatch(proof.BatchIndex)
	if err != nil {
		return ErrFraudProofInvalid
	}
	if proof.PreStateRoot != batch.PrevStateRoot {
		return ErrFraudProofInvalid
	}
	if proof.PostStateRoot != batch.PostStateRoot {
		return ErrFraudProofInvalid
	}
	// Verify InvalidTx belongs to the batch.
	txFound := false
	for _, btx := range batch.Transactions {
		if btx == proof.InvalidTx {
			txFound = true
			break
		}
	}
	if !txFound {
		return ErrFraudProofInvalid
	}

	expectedRoot, _, err := fp.stateManager.SimulateBatch(proof.PreStateRoot, []*RollupTransaction{proof.InvalidTx})
	if err != nil {
		return ErrFraudProofInvalid
	}

	// Fraud is confirmed only when the re-simulated root differs from the
	// batch's ACTUAL recorded PostStateRoot (not the challenger's claim).
	if expectedRoot != batch.PostStateRoot {
		return nil // fraud confirmed
	}
	// expectedRoot == batch.PostStateRoot → batch is honest, proof is invalid.
	return ErrFraudProofInvalid
}

func (fp *FraudProver) verifyInvalidBatchFraud(proof *FraudProof) error {
	if fp.batchLookup == nil {
		return ErrFraudProofInvalid
	}

	batch, err := fp.batchLookup.GetBatch(proof.BatchIndex)
	if err != nil {
		return ErrFraudProofInvalid
	}

	// R36-P0-03 FIX (2026-07-30): Bind proof roots to the batch's recorded
	// roots. Previously proof.PostStateRoot was challenger-supplied and never
	// compared to batch.PostStateRoot — a challenger could set it to garbage
	// to frame an honest batch.
	if proof.PreStateRoot != batch.PrevStateRoot {
		return ErrFraudProofInvalid
	}
	if proof.PostStateRoot != batch.PostStateRoot {
		return ErrFraudProofInvalid
	}

	expectedRoot, _, err := fp.stateManager.SimulateBatch(proof.PreStateRoot, batch.Transactions)
	if err != nil {
		return ErrFraudProofInvalid
	}

	// Fraud confirmed only when re-simulation diverges from the batch's
	// ACTUAL recorded PostStateRoot.
	if expectedRoot != batch.PostStateRoot {
		return nil // fraud confirmed
	}
	return ErrFraudProofInvalid
}

func (fp *FraudProver) verifyDoubleSpendFraud(proof *FraudProof) error {
	// ROLLUP-003 FIX: Use exact length check (60 bytes needed: 8+20+4+8+20)
	// instead of < 64, which allowed 60-63 byte data with ignored bytes 28-31.
	const requiredProofDataLen = 60
	if len(proof.ProofData) < requiredProofDataLen {
		return ErrFraudProofInvalid
	}

	if fp.batchLookup == nil {
		return ErrFraudProofInvalid
	}

	nonce1 := binary.BigEndian.Uint64(proof.ProofData[0:8])
	var from1 types.Address
	copy(from1[:], proof.ProofData[8:28])

	nonce2 := binary.BigEndian.Uint64(proof.ProofData[32:40])
	var from2 types.Address
	copy(from2[:], proof.ProofData[40:60])

	if nonce1 != nonce2 || from1 != from2 {
		return ErrFraudProofInvalid
	}

	batch, err := fp.batchLookup.GetBatch(proof.BatchIndex)
	if err != nil {
		return ErrFraudProofInvalid
	}

	matchCount := 0
	for _, tx := range batch.Transactions {
		if tx.Nonce == nonce1 && tx.From == from1 {
			matchCount++
		}
	}

	if matchCount < 2 {
		return ErrFraudProofInvalid
	}

	return nil
}

func (fp *FraudProver) GetFraudProof(batchIndex uint64) (*FraudProof, bool) {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	proof, exists := fp.proofs[batchIndex]
	if !exists || proof == nil {
		return nil, false
	}
	// ROLLUP3-001 FIX: Return a deep copy to prevent callers from modifying
	// the internal proof state via the returned pointer.
	copied := &FraudProof{
		Type:             proof.Type,
		BatchIndex:       proof.BatchIndex,
		Challenger:       proof.Challenger,
		PreStateRoot:     proof.PreStateRoot,
		PostStateRoot:    proof.PostStateRoot,
		Timestamp:        proof.Timestamp,
		ChallengerSig:    append([]byte(nil), proof.ChallengerSig...),
		ChallengerPubKey: append([]byte(nil), proof.ChallengerPubKey...),
		ProofData:        append([]byte(nil), proof.ProofData...),
	}
	if proof.InvalidTx != nil {
		// R7-RP-001 FIX: Deep copy the To pointer, not just copy the pointer
		// value. The original code copied proof.InvalidTx.To directly, so the
		// caller could modify the original proof's To field through the copy.
		var toCopy *types.Address
		if proof.InvalidTx.To != nil {
			toCopy = &types.Address{}
			copy(toCopy[:], proof.InvalidTx.To[:])
		}
		copied.InvalidTx = &RollupTransaction{
			Nonce:    proof.InvalidTx.Nonce,
			GasPrice: proof.InvalidTx.GasPrice,
			GasLimit: proof.InvalidTx.GasLimit,
			To:       toCopy,
			Value:    new(big.Int).Set(proof.InvalidTx.Value),
			Data:     append([]byte(nil), proof.InvalidTx.Data...),
			From:     proof.InvalidTx.From,
			Hash:     proof.InvalidTx.Hash,
		}
	}
	return copied, true
}

func (fp *FraudProver) HasFraudProof(batchIndex uint64) bool {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	_, exists := fp.proofs[batchIndex]
	return exists
}
