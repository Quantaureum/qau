// Quantaureum Node source, version 1.0.0.
package rollup

// W-P2-2: Fraud proof end-to-end tests.
//
// Goal (per the rollup production-readiness plan):
//   Verify that fraud proofs can be correctly validated against HISTORICAL
//   state, even after the state has advanced past the disputed batch.
//
// Scenario:
//   1. Submit batch N (containing tx T1) → stateRoot: pre0 → post0
//   2. Submit batch N+1 (advancing state) → stateRoot: post0 → post1
//   3. Construct a fraud proof against batch N (tampered PostStateRoot)
//   4. Verify FraudProver.SubmitFraudProof correctly identifies fraud using
//      the HISTORICAL pre-state (pre0) that was archived by W-P0-1.
//
// DoD: Fraud proofs can be correctly validated after state has advanced.
//
// These tests complement the W-P2-1 real-signature tests by focusing on the
// STATE-ADVANCEMENT aspect: SimulateBatch must load the correct historical
// snapshot, not the current live state.

import (
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// helper: submitBatchWithTx processes a batch through the StateManager and
// submits it to the BatchManager. Returns the post-state root.
func submitBatchWithTx(t *testing.T, bm *BatchManager, sm *StateManager, batchIndex uint64, preRoot types.Hash, tx *RollupTransaction) types.Hash {
	t.Helper()
	postRoot, _, err := sm.ProcessBatch(batchIndex, preRoot, []*RollupTransaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch(%d): %v", batchIndex, err)
	}
	if err := bm.SubmitBatch(batchIndex, postRoot, types.Hash{}); err != nil {
		t.Fatalf("SubmitBatch(%d): %v", batchIndex, err)
	}
	return postRoot
}

// --- W-P2-2 Test 1: State-transition fraud proof verified after state advanced ---

// TestFraudProofE2E_StateTransitionAfterStateAdvanced is the canonical W-P2-2
// scenario: commit batch N, advance state with batch N+1, then submit a fraud
// proof against batch N with a tampered PostStateRoot. SimulateBatch must load
// the HISTORICAL pre-state (archived by W-P0-1) and detect the fraud.
func TestFraudProofE2E_StateTransitionAfterStateAdvanced(t *testing.T) {
	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	// Set up funded account + capture genesis pre-root.
	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetRequireSignatureVerifier(false) // bypass sig verification — focus on state
	bm.SetFraudProver(fp)

	// Batch 0: T1 transfers 500 from `from` to `to`.
	// R36-P0-03: Submit with a TAMPERED PostStateRoot so the batch is
	// actually fraudulent. The fraud proof below carries the same tampered
	// root (must match batch.PostStateRoot under the new verification).
	t1 := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t1)
	batch0, err := bm.BuildBatch()
	if err != nil {
		t.Fatalf("BuildBatch(0): %v", err)
	}
	post0, _, err := sm.ProcessBatch(batch0.Index, pre0, []*RollupTransaction{t1})
	if err != nil {
		t.Fatalf("ProcessBatch(0): %v", err)
	}
	tamperedRoot := types.Hash{0xAA, 0xBB, 0xCC}
	if tamperedRoot == post0 {
		tamperedRoot[0] = 0xDD
	}
	if err := bm.SubmitBatch(batch0.Index, tamperedRoot, types.Hash{}); err != nil {
		t.Fatalf("SubmitBatch(0): %v", err)
	}

	// Batch 1: T2 transfers 300 from `from` to `to`. This advances the state
	// past batch 0 — the live state no longer matches pre0.
	t2 := &RollupTransaction{
		Nonce:    1,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(300),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t2)
	batch1, err := bm.BuildBatch()
	if err != nil {
		t.Fatalf("BuildBatch(1): %v", err)
	}
	submitBatchWithTx(t, bm, sm, batch1.Index, post0, t2)

	// Sanity: state has advanced past pre0.
	currentRoot := sm.GetCurrentRoot()
	if currentRoot == pre0 {
		t.Fatal("setup invariant violated: state did not advance past pre0")
	}

	// Construct fraud proof against batch 0. proof roots must match the
	// batch's recorded roots (R36-P0-03). SimulateBatch(pre0, [t1]) computes
	// post0, which differs from batch0.PostStateRoot (tamperedRoot) → fraud.
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    batch0.Index,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: tamperedRoot,
		InvalidTx:     t1,
		ChallengerSig: []byte{0x01}, // bypass sig (requireSigVerifier=false)
		Timestamp:     time.Now().Unix(),
	}

	if err := fp.SubmitFraudProof(proof); err != nil {
		t.Fatalf("SubmitFraudProof rejected valid fraud proof after state advanced: %v", err)
	}

	if !fp.HasFraudProof(batch0.Index) {
		t.Fatal("fraud proof not registered for batch 0")
	}
	t.Log("✅ Fraud proof correctly detected tampered PostStateRoot using historical pre-state")
}

// --- W-P2-2 Test 2: Valid PostStateRoot NOT flagged as fraud ---

// TestFraudProofE2E_ValidPostRootNotFlaggedAsFraud verifies the inverse: when
// the proof's PostStateRoot MATCHES what SimulateBatch computes, the proof is
// rejected (no fraud occurred). This prevents false positives.
func TestFraudProofE2E_ValidPostRootNotFlaggedAsFraud(t *testing.T) {
	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetRequireSignatureVerifier(false)

	t1 := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t1)
	batch0, _ := bm.BuildBatch()
	post0 := submitBatchWithTx(t, bm, sm, batch0.Index, pre0, t1)

	// Submit batch 1 to advance state.
	t2 := &RollupTransaction{
		Nonce:    1,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(300),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t2)
	batch1, _ := bm.BuildBatch()
	submitBatchWithTx(t, bm, sm, batch1.Index, post0, t2)

	// Construct proof with CORRECT PostStateRoot — should be REJECTED.
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    batch0.Index,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: post0, // correct — no fraud
		InvalidTx:     t1,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}

	err := fp.SubmitFraudProof(proof)
	if err == nil {
		t.Fatal("SubmitFraudProof accepted proof with valid PostStateRoot — should reject (no fraud)")
	}
	if err != ErrFraudProofInvalid {
		t.Fatalf("expected ErrFraudProofInvalid, got: %v", err)
	}
	t.Log("✅ Valid PostStateRoot correctly rejected — no false-positive fraud detection")
}

// --- W-P2-2 Test 3: Multiple batches — earliest batch still provable ---

// TestFraudProofE2E_MultipleBatchesEarliestProvable verifies that after
// submitting MANY batches, a fraud proof against the EARLIEST batch can still
// be verified. This tests that stateHistory correctly retains old snapshots
// (FIFO eviction only kicks in after maxStateHistoryEntries).
func TestFraudProofE2E_MultipleBatchesEarliestProvable(t *testing.T) {
	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(100_000_000) // plenty
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetRequireSignatureVerifier(false)

	// Submit 5 batches, each transferring 100. Batch 0 is submitted with a
	// TAMPERED PostStateRoot (fraud); subsequent batches are honest.
	var preRoot = pre0
	var firstBatchIndex uint64
	var firstTx *RollupTransaction
	var firstTamperedRoot types.Hash
	for i := 0; i < 5; i++ {
		tx := &RollupTransaction{
			Nonce:    uint64(i),
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     from,
			To:       &to,
		}
		bm.AddTransaction(tx)
		batch, err := bm.BuildBatch()
		if err != nil {
			t.Fatalf("BuildBatch(%d): %v", i, err)
		}
		postRoot, _, err := sm.ProcessBatch(batch.Index, preRoot, []*RollupTransaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch(%d): %v", i, err)
		}
		if i == 0 {
			// Batch 0: submit with TAMPERED root — simulates malicious sequencer.
			firstBatchIndex = batch.Index
			firstTx = tx
			firstTamperedRoot = types.Hash{0xEE, 0xFF}
			if firstTamperedRoot == postRoot {
				firstTamperedRoot[0] = 0xDD
			}
			if err := bm.SubmitBatch(batch.Index, firstTamperedRoot, types.Hash{}); err != nil {
				t.Fatalf("SubmitBatch(%d): %v", i, err)
			}
		} else {
			if err := bm.SubmitBatch(batch.Index, postRoot, types.Hash{}); err != nil {
				t.Fatalf("SubmitBatch(%d): %v", i, err)
			}
		}
		preRoot = postRoot
	}

	// Fraud proof against the FIRST batch (index 0) — state has advanced 5
	// batches since then. SimulateBatch must load pre0 snapshot. proof roots
	// must match batch 0's recorded roots (R36-P0-03).
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    firstBatchIndex,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: firstTamperedRoot,
		InvalidTx:     firstTx,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}

	if err := fp.SubmitFraudProof(proof); err != nil {
		t.Fatalf("SubmitFraudProof rejected fraud proof against earliest batch: %v", err)
	}
	t.Log("✅ Fraud proof against earliest batch (5 batches ago) correctly detected")
}

// --- W-P2-2 Test 4: Real challenger signature E2E ---

// TestFraudProofE2E_RealChallengerSignature exercises the full path: real
// Dilithium3 signature verification for the challenger, AND historical state
// verification. Combines W-P2-1 (real sigs) with W-P2-2 (historical state).
func TestFraudProofE2E_RealChallengerSignature(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetSignatureVerifier(&testFraudProofSigVerifier{sv: sv})
	// requireSigVerifier stays true (production default).

	// Batch 0. R36-P0-03: Submit with TAMPERED PostStateRoot (fraud).
	t1 := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t1)
	batch0, _ := bm.BuildBatch()
	post0, _, err := sm.ProcessBatch(batch0.Index, pre0, []*RollupTransaction{t1})
	if err != nil {
		t.Fatalf("ProcessBatch(0): %v", err)
	}
	tamperedRoot := types.Hash{0xAA, 0xBB}
	if tamperedRoot == post0 {
		tamperedRoot[0] = 0xDD
	}
	if err := bm.SubmitBatch(batch0.Index, tamperedRoot, types.Hash{}); err != nil {
		t.Fatalf("SubmitBatch(0): %v", err)
	}

	// Batch 1 advances state.
	t2 := &RollupTransaction{
		Nonce:    1,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(300),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t2)
	batch1, _ := bm.BuildBatch()
	submitBatchWithTx(t, bm, sm, batch1.Index, post0, t2)

	// Generate challenger keypair + sign the proof.
	challengerKp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (challenger): %v", err)
	}
	challengerAddr := crypto.PublicKeyAddressFromBytes(challengerKp.Public.Bytes())

	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    batch0.Index,
		Challenger:    challengerAddr,
		PreStateRoot:  pre0,
		PostStateRoot: tamperedRoot,
		InvalidTx:     t1,
		Timestamp:     time.Now().Unix(),
	}
	signTestFraudProof(t, proof, challengerKp)

	if err := fp.SubmitFraudProof(proof); err != nil {
		t.Fatalf("SubmitFraudProof rejected real-signed fraud proof: %v", err)
	}
	t.Log("✅ Real Dilithium3 challenger signature + historical state E2E passed")
}

// --- W-P2-2 Test 5: Real challenger signature with wrong key rejected ---

// TestFraudProofE2E_RealChallengerWrongKeyRejected verifies that a fraud proof
// signed by a DIFFERENT key than the claimed challenger is rejected, even when
// the historical state would otherwise indicate fraud.
func TestFraudProofE2E_RealChallengerWrongKeyRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetSignatureVerifier(&testFraudProofSigVerifier{sv: sv})

	t1 := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t1)
	batch0, _ := bm.BuildBatch()
	post0 := submitBatchWithTx(t, bm, sm, batch0.Index, pre0, t1)

	// Advance state.
	t2 := &RollupTransaction{
		Nonce:    1,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(300),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t2)
	batch1, _ := bm.BuildBatch()
	submitBatchWithTx(t, bm, sm, batch1.Index, post0, t2)

	// Challenger claims address A but signs with key for address B.
	challengerKp, _ := crypto.GenerateKeyPair()
	challengerAddr := crypto.PublicKeyAddressFromBytes(challengerKp.Public.Bytes())
	wrongKp, _ := crypto.GenerateKeyPair()

	tamperedRoot := types.Hash{0xAA, 0xBB}
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    batch0.Index,
		Challenger:    challengerAddr,
		PreStateRoot:  pre0,
		PostStateRoot: tamperedRoot,
		InvalidTx:     t1,
		Timestamp:     time.Now().Unix(),
	}
	// Sign with WRONG key — pubkey won't derive to challengerAddr.
	signTestFraudProof(t, proof, wrongKp)

	err := fp.SubmitFraudProof(proof)
	if err == nil {
		t.Fatal("SubmitFraudProof accepted proof signed by wrong key — must reject")
	}
	if err != ErrFraudProofInvalid {
		t.Fatalf("expected ErrFraudProofInvalid, got: %v", err)
	}
	t.Log("✅ Wrong-key challenger signature correctly rejected")
}

// --- W-P2-2 Test 6: ChallengeBatch marks batch as challenged ---

// TestFraudProofE2E_ChallengeBatchFlow verifies the full flow: submit batch →
// advance state → submit fraud proof → ChallengeBatch transitions batch status
// to Challenged.
func TestFraudProofE2E_ChallengeBatchFlow(t *testing.T) {
	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetRequireSignatureVerifier(false)
	bm.SetFraudProver(fp)

	// Batch 0. R36-P0-03: Submit with TAMPERED PostStateRoot (fraud).
	t1 := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t1)
	batch0, _ := bm.BuildBatch()
	post0, _, err := sm.ProcessBatch(batch0.Index, pre0, []*RollupTransaction{t1})
	if err != nil {
		t.Fatalf("ProcessBatch(0): %v", err)
	}
	tamperedRoot := types.Hash{0xAA, 0xBB}
	if tamperedRoot == post0 {
		tamperedRoot[0] = 0xDD
	}
	if err := bm.SubmitBatch(batch0.Index, tamperedRoot, types.Hash{}); err != nil {
		t.Fatalf("SubmitBatch(0): %v", err)
	}

	// Advance state with batch 1.
	t2 := &RollupTransaction{
		Nonce:    1,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(300),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t2)
	batch1, _ := bm.BuildBatch()
	submitBatchWithTx(t, bm, sm, batch1.Index, post0, t2)

	// Submit fraud proof against batch 0.
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    batch0.Index,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: tamperedRoot,
		InvalidTx:     t1,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}
	if err := fp.SubmitFraudProof(proof); err != nil {
		t.Fatalf("SubmitFraudProof: %v", err)
	}

	// ChallengeBatch should transition batch 0 to Challenged status.
	if err := bm.ChallengeBatch(batch0.Index); err != nil {
		t.Fatalf("ChallengeBatch: %v", err)
	}
	got, _ := bm.GetBatch(batch0.Index)
	if got.Status != BatchStatusChallenged {
		t.Fatalf("expected Challenged, got %d", got.Status)
	}

	// Batch 1 should NOT be challenged.
	got1, _ := bm.GetBatch(batch1.Index)
	if got1.Status == BatchStatusChallenged {
		t.Fatal("batch 1 should not be challenged")
	}
	t.Log("✅ ChallengeBatch correctly transitioned disputed batch to Challenged")
}

// --- W-P2-2 Test 7: InvalidBatch fraud proof E2E ---

// TestFraudProofE2E_InvalidBatchType verifies the InvalidBatch fraud proof
// type: the batch's actual transactions, when replayed from the pre-state,
// produce a DIFFERENT root than the batch claims. This catches sequencers
// that post a fake PostStateRoot without bothering to actually run the txs.
func TestFraudProofE2E_InvalidBatchType(t *testing.T) {
	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetRequireSignatureVerifier(false)

	// Build batch 0 with T1, but SUBMIT it with a TAMPERED PostStateRoot
	// that doesn't match what ProcessBatch would compute.
	t1 := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		From:     from,
		To:       &to,
	}
	bm.AddTransaction(t1)
	batch0, err := bm.BuildBatch()
	if err != nil {
		t.Fatalf("BuildBatch: %v", err)
	}

	// Compute the CORRECT post-root by actually running the batch.
	correctPostRoot, _, err := sm.ProcessBatch(batch0.Index, pre0, []*RollupTransaction{t1})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	// Submit the batch with a TAMPERED root — simulates a malicious sequencer.
	tamperedRoot := types.Hash{0xAB, 0xCD, 0xEF}
	if tamperedRoot == correctPostRoot {
		tamperedRoot[0] = 0x99
	}
	if err := bm.SubmitBatch(batch0.Index, tamperedRoot, types.Hash{}); err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}

	// Fraud proof: replay the batch's REAL transactions from pre0 → get
	// correctPostRoot, which != tamperedRoot → fraud detected.
	proof := &FraudProof{
		Type:          FraudProofTypeInvalidBatch,
		BatchIndex:    batch0.Index,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: tamperedRoot, // what the sequencer claimed
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}

	if err := fp.SubmitFraudProof(proof); err != nil {
		t.Fatalf("SubmitFraudProof (InvalidBatch): %v", err)
	}
	t.Log("✅ InvalidBatch fraud proof correctly detected tampered PostStateRoot")
}

// --- W-P2-2 Test 8: DoubleSpend fraud proof E2E ---

// TestFraudProofE2E_DoubleSpendType verifies the DoubleSpend fraud proof type:
// two transactions in the SAME batch with the SAME (from, nonce) — a sequencer
// bug or collusion that lets a user spend the same nonce twice.
func TestFraudProofE2E_DoubleSpendType(t *testing.T) {
	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	// Fund account so both txs would individually succeed.
	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetRequireSignatureVerifier(false)

	// Build a batch with TWO transactions sharing (from=10, nonce=0).
	// This is the double-spend: the sequencer should have rejected the 2nd.
	t1 := &RollupTransaction{
		Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(100),
		From: from, To: &to,
	}
	t2 := &RollupTransaction{
		Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(200),
		From: from, To: &to,
	}
	bm.AddTransaction(t1)
	bm.AddTransaction(t2)
	batch0, err := bm.BuildBatch()
	if err != nil {
		t.Fatalf("BuildBatch: %v", err)
	}
	// Submit the batch (with any post-root — double-spend proof doesn't
	// validate the root, only the batch's tx list).
	bm.SubmitBatch(batch0.Index, types.Hash{0x12, 0x34}, types.Hash{})

	// Construct ProofData: two (nonce, from) pairs showing the same (from, nonce).
	proofData := make([]byte, 60)
	binary.BigEndian.PutUint64(proofData[0:8], 0)   // nonce1
	copy(proofData[8:28], from[:])                  // from1
	binary.BigEndian.PutUint64(proofData[32:40], 0) // nonce2
	copy(proofData[40:60], from[:])                 // from2

	proof := &FraudProof{
		Type:          FraudProofTypeDoubleSpend,
		BatchIndex:    batch0.Index,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: types.Hash{0x12, 0x34},
		ProofData:     proofData,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}

	if err := fp.SubmitFraudProof(proof); err != nil {
		t.Fatalf("SubmitFraudProof (DoubleSpend): %v", err)
	}
	t.Log("✅ DoubleSpend fraud proof correctly detected duplicate (from, nonce) in batch")
}

// --- W-P2-2 Test 9: DoubleSpend proof rejected when no duplicate ---

// TestFraudProofE2E_DoubleSpendNoDuplicateRejected verifies that a DoubleSpend
// proof is REJECTED when the batch doesn't actually contain a double-spend.
// This prevents false accusations.
func TestFraudProofE2E_DoubleSpendNoDuplicateRejected(t *testing.T) {
	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetRequireSignatureVerifier(false)

	// Batch with two LEGITIMATE transactions (different nonces).
	t1 := &RollupTransaction{
		Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(100),
		From: from, To: &to,
	}
	t2 := &RollupTransaction{
		Nonce: 1, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(200),
		From: from, To: &to,
	}
	bm.AddTransaction(t1)
	bm.AddTransaction(t2)
	batch0, _ := bm.BuildBatch()
	bm.SubmitBatch(batch0.Index, types.Hash{0x12, 0x34}, types.Hash{})

	// ProofData falsely claims (nonce=0, from=10) appears twice — but it
	// doesn't (nonce 0 appears once, nonce 1 appears once).
	proofData := make([]byte, 60)
	binary.BigEndian.PutUint64(proofData[0:8], 0)
	copy(proofData[8:28], from[:])
	binary.BigEndian.PutUint64(proofData[32:40], 0)
	copy(proofData[40:60], from[:])

	proof := &FraudProof{
		Type:          FraudProofTypeDoubleSpend,
		BatchIndex:    batch0.Index,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: types.Hash{0x12, 0x34},
		ProofData:     proofData,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}

	err := fp.SubmitFraudProof(proof)
	if err == nil {
		t.Fatal("SubmitFraudProof accepted DoubleSpend proof with no actual duplicate — must reject")
	}
	if err != ErrFraudProofInvalid {
		t.Fatalf("expected ErrFraudProofInvalid, got: %v", err)
	}
	t.Log("✅ DoubleSpend proof with no actual duplicate correctly rejected")
}

// --- W-P2-2 Test 10: Duplicate fraud proof rejected ---

// TestFraudProofE2E_DuplicateProofRejected verifies that submitting a second
// fraud proof for the SAME batch index is rejected (one challenge per batch).
func TestFraudProofE2E_DuplicateProofRejected(t *testing.T) {
	cfg := DefaultRollupConfig()
	from := types.Address{10}
	to := types.Address{20}

	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetRequireSignatureVerifier(false)

	t1 := &RollupTransaction{
		Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(500),
		From: from, To: &to,
	}
	bm.AddTransaction(t1)
	batch0, _ := bm.BuildBatch()
	// R36-P0-03: Submit with TAMPERED PostStateRoot so the batch is fraudulent.
	post0, _, err := sm.ProcessBatch(batch0.Index, pre0, []*RollupTransaction{t1})
	if err != nil {
		t.Fatalf("ProcessBatch(0): %v", err)
	}
	tamperedRoot := types.Hash{0xAA}
	if tamperedRoot == post0 {
		tamperedRoot[0] = 0xBB
	}
	if err := bm.SubmitBatch(batch0.Index, tamperedRoot, types.Hash{}); err != nil {
		t.Fatalf("SubmitBatch(0): %v", err)
	}

	// First proof — accepted.
	proof1 := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    batch0.Index,
		Challenger:    types.Address{99},
		PreStateRoot:  pre0,
		PostStateRoot: tamperedRoot,
		InvalidTx:     t1,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}
	if err := fp.SubmitFraudProof(proof1); err != nil {
		t.Fatalf("first SubmitFraudProof: %v", err)
	}

	// Second proof for the same batch — must be rejected.
	proof2 := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    batch0.Index,
		Challenger:    types.Address{88}, // different challenger
		PreStateRoot:  pre0,
		PostStateRoot: types.Hash{0xBB},
		InvalidTx:     t1,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}
	err = fp.SubmitFraudProof(proof2)
	if err == nil {
		t.Fatal("second SubmitFraudProof for same batch accepted — must reject")
	}
	if err != ErrFraudProofInvalid {
		t.Fatalf("expected ErrFraudProofInvalid, got: %v", err)
	}
	t.Log("✅ Duplicate fraud proof for same batch correctly rejected")
}

// TestRLLP_R5_07_ProductionLock_PreventsDisablingFailClosed verifies the
// RLLP-R5-07 production lock: once LockProductionMode() is called,
// SetRequireSignatureVerifier(false) is rejected and requireSigVerifier
// stays true, preventing runtime downgrade of the fail-closed behavior.
//
// RLLP-R5-07 (2026-07-17)
func TestRLLP_R5_07_ProductionLock_PreventsDisablingFailClosed(t *testing.T) {
	fp := NewFraudProver(nil, nil)

	// Before locking: SetRequireSignatureVerifier(false) works (test mode).
	fp.SetRequireSignatureVerifier(false)
	if fp.requireSigVerifier != false {
		t.Fatal("pre-lock: SetRequireSignatureVerifier(false) should disable requireSigVerifier")
	}

	// Lock production mode. This must force requireSigVerifier=true.
	fp.LockProductionMode()
	if fp.requireSigVerifier != true {
		t.Fatal("LockProductionMode must force requireSigVerifier=true")
	}

	// After locking: SetRequireSignatureVerifier(false) must be rejected.
	fp.SetRequireSignatureVerifier(false)
	if fp.requireSigVerifier != true {
		t.Fatal("RLLP-R5-07: post-lock SetRequireSignatureVerifier(false) must be rejected; requireSigVerifier should remain true")
	}

	// SetRequireSignatureVerifier(true) should still work (no-op effectively).
	fp.SetRequireSignatureVerifier(true)
	if fp.requireSigVerifier != true {
		t.Fatal("post-lock SetRequireSignatureVerifier(true) should still work")
	}

	t.Log("✅ RLLP-R5-07: production lock prevents disabling fail-closed signature verification")
}

// TestRLLP_R5_07_ProductionLock_RejectsUnauthenticatedProof verifies that
// after LockProductionMode(), the FraudProver rejects fraud proofs when
// no SignatureVerifier is configured (fail-closed enforced).
//
// RLLP-R5-07 (2026-07-17)
func TestRLLP_R5_07_ProductionLock_RejectsUnauthenticatedProof(t *testing.T) {
	fp := NewFraudProver(nil, nil)
	fp.LockProductionMode()

	// No SignatureVerifier configured. Production lock enforces fail-closed.
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    1,
		Challenger:    types.Address{0x42},
		PreStateRoot:  types.Hash{0x01},
		PostStateRoot: types.Hash{0x02},
		ChallengerSig: []byte{0x01}, // non-empty but unauthenticated
		Timestamp:     time.Now().Unix(),
	}

	err := fp.SubmitFraudProof(proof)
	if err != ErrFraudProofInvalid {
		t.Fatalf("RLLP-R5-07: production-locked FraudProver must reject unauthenticated proof; got err=%v, want ErrFraudProofInvalid", err)
	}

	t.Log("✅ RLLP-R5-07: production-locked FraudProver rejects unauthenticated fraud proof")
}
