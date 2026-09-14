// Quantaureum Node source, version 1.0.0.
package rollup

// AUDIT (2026) RLLP-R5-01 regression tests.
//
// These tests verify the fix for the critical vulnerability where:
//   - FinalizeBatch only checked the challenge deadline, NEVER checking
//     whether a fraud proof had been submitted. This made the challenge
//     period meaningless — a malicious sequencer could submit an invalid
//     batch, wait out the challenge period, and have it auto-finalized
//     regardless of any fraud proof submitted by an honest challenger.
//   - SubmitFraudProof stored the proof but did NOT trigger ChallengeBatch,
//     so the batch stayed in Submitted status and remained eligible for
//     finalization.
//   - There was NO production RPC endpoint for challengers to submit
//     fraud proofs — the entire challenge mechanism was dead code.
//
// Fix verification:
//   1. FinalizeBatch checks HasFraudProof and auto-transitions to Challenged
//   2. RollupEngine.SubmitFraudProof coordinates proof storage + ChallengeBatch
//   3. Failed verification does NOT trigger ChallengeBatch (fail-closed)
//   4. ErrBatchChallenged is returned so callers can distinguish from
//      ErrChallengePeriodNotOver (transient) vs ErrBatchChallenged (permanent)

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// r5RllpSetup builds a minimal engine + funded account + submitted batch 0
// whose challenge period has ELAPSED, so the only thing that can block
// finalization is a fraud proof. Returns the engine, batch manager, fraud
// prover, the funded account, and batch 0's pre-root + post-root + tx.
func r5RllpSetup(t *testing.T) (*RollupEngine, *BatchManager, *FraudProver, types.Address, types.Hash, types.Hash, *RollupTransaction) {
	t.Helper()
	cfg := DefaultRollupConfig()
	// Challenge period = 1ns so it has already elapsed by the time we call
	// FinalizeBatch. This isolates the fraud-proof check from the deadline
	// check.
	cfg.ChallengePeriod = 1 * time.Nanosecond
	cfg.FinalizeCheckInterval = 10 * time.Millisecond
	cfg.MinTxPerBatch = 1

	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}
	// Bypass challenger signature verification — these tests focus on the
	// finalization gate, not on signature verification (covered elsewhere).
	engine.fraudProver.SetRequireSignatureVerifier(false)
	engine.fraudProver.SetBatchLookup(engine.batchManager)
	engine.batchManager.SetFraudProver(engine.fraudProver)

	from := types.Address{10}
	to := types.Address{20}
	engine.stateManager.getOrCreateAccount(from)
	engine.stateManager.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)
	pre0 := engine.stateManager.computeStateRoot()
	// R36-P0-03: Sync BatchManager's lastStateRoot to the funded state so
	// batch0.PrevStateRoot matches pre0 (required by root-binding verification).
	engine.batchManager.RestoreMeta(0, pre0)

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		From:     from,
		To:       &to,
	}
	if err := engine.batchManager.AddTransaction(tx); err != nil {
		t.Fatalf("AddTransaction: %v", err)
	}
	batch0, err := engine.batchManager.BuildBatch()
	if err != nil {
		t.Fatalf("BuildBatch: %v", err)
	}
	post0, _, err := engine.stateManager.ProcessBatch(batch0.Index, pre0, []*RollupTransaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	// R36-P0-03: Submit with TAMPERED PostStateRoot so the batch is actually
	// fraudulent. Fraud proofs in the tests below use the same tampered root
	// value (types.Hash{0xAA, 0xBB, 0xCC}) as proof.PostStateRoot.
	tamperedRoot := types.Hash{0xAA, 0xBB, 0xCC}
	if err := engine.batchManager.SubmitBatch(batch0.Index, tamperedRoot, types.Hash{}); err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}
	// Sleep so wall-clock deadline elapses (ChallengeDeadline = SubmittedAt + 1ns).
	time.Sleep(2 * time.Millisecond)

	return engine, engine.batchManager, engine.fraudProver, from, pre0, post0, tx
}

// TestR5_RLLP_R5_01_FinalizeBatchBlockedByFraudProof verifies that
// FinalizeBatch returns ErrBatchChallenged and auto-transitions the batch
// to Challenged when a fraud proof exists — even when the challenge deadline
// has elapsed. This is the core defense-in-depth gate.
func TestR5_RLLP_R5_01_FinalizeBatchBlockedByFraudProof(t *testing.T) {
	engine, bm, fp, _, pre0, _, tx := r5RllpSetup(t)

	// Sanity: without a fraud proof, FinalizeBatch should succeed (deadline elapsed).
	// We verify this on a SEPARATE engine to avoid mutating the test's batch.
	{
		sanityEngine, sanityBM, _, _, _, _, sanityTx := r5RllpSetup(t)
		_ = sanityEngine
		if err := sanityBM.FinalizeBatch(0); err != nil {
			t.Fatalf("sanity: FinalizeBatch without fraud proof should succeed (deadline elapsed), got: %v", err)
		}
		batch, _ := sanityBM.GetBatch(0)
		if batch.Status != BatchStatusFinalized {
			t.Fatalf("sanity: expected Finalized, got %d", batch.Status)
		}
		_ = sanityTx
	}

	// Submit a fraud proof directly via FraudProver (NOT via Engine.SubmitFraudProof,
	// to verify FinalizeBatch's OWN HasFraudProof check works independently).
	tamperedRoot := types.Hash{0xAA, 0xBB, 0xCC}
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    0,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: tamperedRoot,
		InvalidTx:     tx,
		ChallengerSig: []byte{0x01}, // bypass sig (requireSigVerifier=false)
		Timestamp:     time.Now().Unix(),
	}
	if err := fp.SubmitFraudProof(proof); err != nil {
		t.Fatalf("FraudProver.SubmitFraudProof: %v", err)
	}
	if !fp.HasFraudProof(0) {
		t.Fatal("HasFraudProof should return true after SubmitFraudProof")
	}

	// FinalizeBatch MUST return ErrBatchChallenged (NOT succeed, NOT
	// ErrChallengePeriodNotOver). This is the RLLP-R5-01 fix.
	err := bm.FinalizeBatch(0)
	if !errors.Is(err, ErrBatchChallenged) {
		t.Fatalf("expected ErrBatchChallenged, got: %v", err)
	}

	// The batch MUST have been auto-transitioned to Challenged so subsequent
	// finalizeLoop ticks skip it.
	batch, _ := bm.GetBatch(0)
	if batch.Status != BatchStatusChallenged {
		t.Fatalf("expected batch auto-transitioned to Challenged, got status %d", batch.Status)
	}

	// Defense-in-depth: a second FinalizeBatch call must STILL fail (batch is
	// now Challenged, not Submitted). It should return ErrBatchNotSubmitted
	// because the status check runs before the fraud-proof check.
	err = bm.FinalizeBatch(0)
	if !errors.Is(err, ErrBatchNotSubmitted) {
		t.Fatalf("second FinalizeBatch should return ErrBatchNotSubmitted (already Challenged), got: %v", err)
	}
	_ = engine
}

// TestR5_RLLP_R5_01_EngineSubmitFraudProofCoordinated verifies the engine's
// coordinated SubmitFraudProof method: it stores the proof AND immediately
// transitions the batch to Challenged (without waiting for a FinalizeBatch
// tick). This closes the race window where a fraud proof is stored but the
// batch remains eligible for finalization until the next finalize tick.
func TestR5_RLLP_R5_01_EngineSubmitFraudProofCoordinated(t *testing.T) {
	engine, bm, fp, _, pre0, _, tx := r5RllpSetup(t)
	_ = bm

	tamperedRoot := types.Hash{0xAA, 0xBB, 0xCC}
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    0,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: tamperedRoot,
		InvalidTx:     tx,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}

	// Engine.SubmitFraudProof must verify + store AND transition the batch.
	if err := engine.SubmitFraudProof(proof); err != nil {
		t.Fatalf("Engine.SubmitFraudProof: %v", err)
	}

	// Proof must be stored.
	if !fp.HasFraudProof(0) {
		t.Fatal("HasFraudProof should return true after Engine.SubmitFraudProof")
	}

	// Batch must be IMMEDIATELY Challenged (not still Submitted).
	batch, _ := bm.GetBatch(0)
	if batch.Status != BatchStatusChallenged {
		t.Fatalf("expected batch immediately Challenged after Engine.SubmitFraudProof, got status %d", batch.Status)
	}

	// FinalizeBatch must fail (batch is Challenged).
	err := bm.FinalizeBatch(0)
	if err == nil {
		t.Fatal("FinalizeBatch should fail after Engine.SubmitFraudProof (batch is Challenged)")
	}
}

// TestR5_RLLP_R5_01_EngineSubmitFraudProofRejectedDoesNotChallenge verifies
// that a REJECTED fraud proof (verification failure) does NOT trigger
// ChallengeBatch. This is the fail-closed guarantee: only verified proofs
// can challenge a batch.
func TestR5_RLLP_R5_01_EngineSubmitFraudProofRejectedDoesNotChallenge(t *testing.T) {
	engine, bm, fp, _, pre0, post0, tx := r5RllpSetup(t)
	_ = post0

	// Construct a fraud proof that will FAIL verification: PostStateRoot
	// matches the real post-state, so verifyStateTransitionFraud rejects it
	// (no fraud detected).
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    0,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: post0, // CORRECT root → no fraud → verification fails
		InvalidTx:     tx,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}

	err := engine.SubmitFraudProof(proof)
	if err == nil {
		t.Fatal("Engine.SubmitFraudProof should reject proof with correct PostStateRoot (no fraud)")
	}
	if !errors.Is(err, ErrFraudProofInvalid) {
		t.Fatalf("expected ErrFraudProofInvalid, got: %v", err)
	}

	// Proof must NOT be stored.
	if fp.HasFraudProof(0) {
		t.Fatal("HasFraudProof should return false after rejected proof")
	}

	// Batch must still be Submitted (NOT Challenged).
	batch, _ := bm.GetBatch(0)
	if batch.Status != BatchStatusSubmitted {
		t.Fatalf("expected batch still Submitted after rejected proof, got status %d", batch.Status)
	}

	// FinalizeBatch should succeed (deadline elapsed, no fraud proof).
	if err := bm.FinalizeBatch(0); err != nil {
		t.Fatalf("FinalizeBatch should succeed (no fraud proof, deadline elapsed), got: %v", err)
	}
	batch, _ = bm.GetBatch(0)
	if batch.Status != BatchStatusFinalized {
		t.Fatalf("expected batch Finalized, got status %d", batch.Status)
	}
}

// TestR5_RLLP_R5_01_NilProofRejected verifies the engine's SubmitFraudProof
// rejects nil proofs without panicking. Defense-in-depth.
func TestR5_RLLP_R5_01_NilProofRejected(t *testing.T) {
	engine, _, _, _, _, _, _ := r5RllpSetup(t)

	if err := engine.SubmitFraudProof(nil); err == nil {
		t.Fatal("Engine.SubmitFraudProof(nil) should return an error")
	}
}

// TestR5_RLLP_R5_01_NilFraudProverOnEngine verifies that Engine.SubmitFraudProof
// fails safely when the fraud prover is nil (defense-in-depth — should never
// happen in production because NewRollupEngine always creates one, but the
// guard must exist).
func TestR5_RLLP_R5_01_NilFraudProverOnEngine(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.ChallengePeriod = 1 * time.Nanosecond
	cfg.MinTxPerBatch = 1
	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}
	// Force nil fraud prover (simulates a misconfigured engine).
	engine.fraudProver = nil

	proof := &FraudProof{BatchIndex: 0}
	submitErr := engine.SubmitFraudProof(proof)
	if submitErr == nil {
		t.Fatal("Engine.SubmitFraudProof with nil fraudProver should return an error")
	}
	if !errors.Is(submitErr, ErrFraudProofInvalid) {
		t.Fatalf("expected ErrFraudProofInvalid, got: %v", submitErr)
	}
}

// TestR5_RLLP_R5_01_FinalizeLoopSkipsChallenged verifies that
// tryFinalizeBatches (the engine's auto-finalize loop) skips batches in
// Challenged status. GetSubmittedBatchIndices only returns Submitted batches,
// so a Challenged batch is naturally excluded. This test confirms that
// contract holds.
func TestR5_RLLP_R5_01_FinalizeLoopSkipsChallenged(t *testing.T) {
	engine, bm, _, _, pre0, _, tx := r5RllpSetup(t)
	_ = pre0
	_ = tx

	// Transition batch 0 to Challenged via Engine.SubmitFraudProof.
	tamperedRoot := types.Hash{0xAA, 0xBB, 0xCC}
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    0,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: tamperedRoot,
		InvalidTx:     tx,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}
	if err := engine.SubmitFraudProof(proof); err != nil {
		t.Fatalf("Engine.SubmitFraudProof: %v", err)
	}

	// GetSubmittedBatchIndices must NOT include the Challenged batch.
	indices := bm.GetSubmittedBatchIndices()
	for _, idx := range indices {
		if idx == 0 {
			t.Fatal("GetSubmittedBatchIndices must not return Challenged batch 0")
		}
	}

	// Calling tryFinalizeBatches directly must NOT finalize batch 0.
	// We invoke it manually to avoid timing flakes from the loop ticker.
	// tryFinalizeBatches reads engine.status, so we must start the engine.
	cfg := engine.config
	cfg.BlockTime = 100 * time.Millisecond
	_ = engine.Start()
	defer engine.Stop()

	// Give the finalize loop a couple of ticks to attempt finalization.
	time.Sleep(150 * time.Millisecond)

	// Batch 0 must still be Challenged (NOT Finalized).
	batch, _ := bm.GetBatch(0)
	if batch.Status != BatchStatusChallenged {
		t.Fatalf("expected batch 0 still Challenged after finalizeLoop ticks, got status %d", batch.Status)
	}
}

// TestR5_RLLP_R5_01_ErrBatchChallengedIsDistinct verifies that
// ErrBatchChallenged is a distinct sentinel error so callers can
// differentiate "permanent block" from "transient wait" (challenge period
// not over). This is critical for the finalizeLoop's error handling logic.
func TestR5_RLLP_R5_01_ErrBatchChallengedIsDistinct(t *testing.T) {
	if errors.Is(ErrBatchChallenged, ErrChallengePeriodNotOver) {
		t.Fatal("ErrBatchChallenged must NOT be ErrChallengePeriodNotOver")
	}
	if errors.Is(ErrBatchChallenged, ErrBatchNotSubmitted) {
		t.Fatal("ErrBatchChallenged must NOT be ErrBatchNotSubmitted")
	}
	if errors.Is(ErrBatchChallenged, ErrBatchNotFound) {
		t.Fatal("ErrBatchChallenged must NOT be ErrBatchNotFound")
	}
	if errors.Is(ErrBatchChallenged, ErrFraudProofInvalid) {
		t.Fatal("ErrBatchChallenged must NOT be ErrFraudProofInvalid")
	}
}
