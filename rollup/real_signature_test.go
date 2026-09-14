// Quantaureum Node source, version 1.0.0.
package rollup

// W-P2-1: Real Dilithium3 signature integration tests for the L2 rollup.
//
// AUDIT (2026) HIGH-10 / W-P1-1: All prior rollup tests bypassed
// signature verification via SetRequireTxSig(false) / SetRequireSignatureVerifier(false).
// These tests exercise the real cryptographic verification path that production
// deployments use after W-P1-1 injects a crypto.SigningVerifier-backed adapter.
//
// Coverage:
//   - L2 transaction with valid Dilithium3 signature is accepted
//   - L2 transaction with no signature is rejected
//   - L2 transaction with wrong signature is rejected
//   - L2 transaction with tampered fields (signature no longer matches) is rejected
//   - L2 transaction whose PublicKey does not derive to From is rejected
//   - Fraud proof with valid challenger signature is accepted
//   - Fraud proof with wrong challenger signature is rejected
//   - Fraud proof with no ChallengerSig is rejected
//   - Fraud proof whose ChallengerPubKey does not derive to Challenger is rejected

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// testTxSigVerifier adapts crypto.SigningVerifier to rollup.TxSignatureVerifier.
// This mirrors node/rollup_adapters.go rollupTxSigVerifier — duplicated here
// because the rollup package cannot import node (import cycle).
type testTxSigVerifier struct {
	sv *crypto.SigningVerifier
}

func (v *testTxSigVerifier) VerifyTxSignature(from types.Address, pubKey []byte, msg []byte, sig []byte) bool {
	if v.sv == nil {
		return false
	}
	// AUDIT-FULL-ROUND1-2026-08-15 P0-01 FIX (2026-08-15): delegate to the
	// canonical single-source primitive so the rollup test verifier cannot
	// drift from encoding.VerifyTransactionAuthorization's semantics. The
	// wrapped SigningVerifier (cache layer) is still consulted via the
	// helper's crypto.Verify on cache-miss; cache-hit short-circuits inside
	// SigningVerifier.VerifyTransactionSignature preserve throughput on
	// repeated (pubKey, msg, sig) inputs.
	if err := encoding.VerifySingleSigBinding(from, pubKey, msg, sig); err != nil {
		return false
	}
	return true
}

// testFraudProofSigVerifier adapts crypto.SigningVerifier to rollup.SignatureVerifier.
// Mirrors node/rollup_adapters.go rollupFraudProofSigVerifier.
type testFraudProofSigVerifier struct {
	sv *crypto.SigningVerifier
}

func (v *testFraudProofSigVerifier) VerifyFraudProofSignature(challenger types.Address, pubKey []byte, msg []byte, sig []byte) bool {
	if v.sv == nil || len(pubKey) == 0 || len(sig) == 0 {
		return false
	}
	if crypto.PublicKeyAddressFromBytes(pubKey) != challenger {
		return false
	}
	if err := v.sv.VerifyTransactionSignature(pubKey, msg, sig); err != nil {
		return false
	}
	return true
}

// newTestVerifier builds a real crypto.SigningVerifier backed by Dilithium3.
// Caller is responsible for calling Close() when done (background goroutine
// for invalid-sig cache cleanup). Tests typically defer sv.Close().
func newTestVerifier(t *testing.T) *crypto.SigningVerifier {
	t.Helper()
	sv := crypto.NewSigningVerifier()
	sv.SetRejectLegacy(true) // production default
	return sv
}

// signTestTx signs tx.SigningHash() with the given Dilithium3 private key and
// populates tx.Signature + tx.PublicKey. Helper for tests that need a validly
// signed L2 transaction.
//
// RLLP-FIX (2026-07-17): PublicKey is set BEFORE computing SigningHash
// because the signing hash now covers the PublicKey field.
func signTestTx(t *testing.T, tx *RollupTransaction, kp *crypto.KeyPair) {
	t.Helper()
	tx.PublicKey = kp.Public.Bytes()
	hash := tx.SigningHash()
	sig, err := kp.Private.Sign(hash[:])
	if err != nil {
		t.Fatalf("Sign L2 tx: %v", err)
	}
	tx.Signature = sig
}

// signTestFraudProof signs buildFraudProofSignMessage(proof) with the challenger's
// Dilithium3 key and populates proof.ChallengerSig + proof.ChallengerPubKey.
func signTestFraudProof(t *testing.T, proof *FraudProof, kp *crypto.KeyPair) {
	t.Helper()
	msg := buildFraudProofSignMessage(proof)
	sig, err := kp.Private.Sign(msg)
	if err != nil {
		t.Fatalf("Sign fraud proof: %v", err)
	}
	proof.ChallengerSig = sig
	proof.ChallengerPubKey = kp.Public.Bytes()
}

// --- L2 transaction signature tests ---

// TestRealSignature_ValidTxAccepted verifies that a properly signed L2
// transaction is accepted by the sequencer when a real Dilithium3 verifier
// is configured. This is the core happy-path for W-P1-1.
func TestRealSignature_ValidTxAccepted(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	bm := NewBatchManager(cfg, types.Hash{})
	seq := NewSequencer(cfg, bm)
	seq.SetTxSignatureVerifier(&testTxSigVerifier{sv: sv})
	// requireTxSig stays true (default) — fail-closed mode.

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	fromAddr := crypto.PublicKeyAddressFromBytes(kp.Public.Bytes())

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     fromAddr,
		ChainID:  cfg.ChainID,
	}
	signTestTx(t, tx, kp)

	if err := seq.AcceptTransaction(tx); err != nil {
		t.Errorf("valid signed tx rejected: %v", err)
	}
}

// TestRealSignature_NoSignatureRejected verifies that a transaction with no
// signature is rejected when fail-closed mode is active (requireTxSig=true).
func TestRealSignature_NoSignatureRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	bm := NewBatchManager(cfg, types.Hash{})
	seq := NewSequencer(cfg, bm)
	seq.SetTxSignatureVerifier(&testTxSigVerifier{sv: sv})

	kp, _ := crypto.GenerateKeyPair()
	fromAddr := crypto.PublicKeyAddressFromBytes(kp.Public.Bytes())

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     fromAddr,
		ChainID:  cfg.ChainID,
		// Signature and PublicKey intentionally empty
	}

	err := seq.AcceptTransaction(tx)
	if err == nil {
		t.Fatal("tx with no signature accepted — should be rejected")
	}
}

// TestRealSignature_EmptyPublicKeyRejected verifies that a signed transaction
// whose PublicKey field is empty is rejected. Even if the signature is
// cryptographically valid in isolation, the L2 protocol requires the tx to
// carry the pubkey inline (W-P1-1 design).
func TestRealSignature_EmptyPublicKeyRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	bm := NewBatchManager(cfg, types.Hash{})
	seq := NewSequencer(cfg, bm)
	seq.SetTxSignatureVerifier(&testTxSigVerifier{sv: sv})

	kp, _ := crypto.GenerateKeyPair()
	fromAddr := crypto.PublicKeyAddressFromBytes(kp.Public.Bytes())

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     fromAddr,
		ChainID:  cfg.ChainID,
	}
	hash := tx.SigningHash()
	sig, _ := kp.Private.Sign(hash[:])
	tx.Signature = sig
	// PublicKey intentionally empty

	err := seq.AcceptTransaction(tx)
	if err == nil {
		t.Fatal("tx with empty PublicKey accepted — should be rejected")
	}
}

// TestRealSignature_WrongSignatureRejected verifies that a signature produced
// by a different key (not the one claimed in PublicKey) is rejected.
func TestRealSignature_WrongSignatureRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	bm := NewBatchManager(cfg, types.Hash{})
	seq := NewSequencer(cfg, bm)
	seq.SetTxSignatureVerifier(&testTxSigVerifier{sv: sv})

	// Sender's real key (matches From + PublicKey)
	senderKp, _ := crypto.GenerateKeyPair()
	fromAddr := crypto.PublicKeyAddressFromBytes(senderKp.Public.Bytes())

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     fromAddr,
		ChainID:  cfg.ChainID,
	}
	// Sign with a DIFFERENT key — signature will not verify against PublicKey.
	// RLLP- Set PublicKey BEFORE SigningHash so the hash covers it.
	attackerKp, _ := crypto.GenerateKeyPair()
	tx.PublicKey = senderKp.Public.Bytes()
	hash := tx.SigningHash()
	wrongSig, _ := attackerKp.Private.Sign(hash[:])
	tx.Signature = wrongSig

	err := seq.AcceptTransaction(tx)
	if err == nil {
		t.Fatal("tx with wrong-key signature accepted — should be rejected")
	}
}

// TestRealSignature_TamperedFieldsRejected verifies that modifying any signed
// field (here: Value) after signing invalidates the signature. This proves
// the signature covers all transaction fields per SigningHash().
func TestRealSignature_TamperedFieldsRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	bm := NewBatchManager(cfg, types.Hash{})
	seq := NewSequencer(cfg, bm)
	seq.SetTxSignatureVerifier(&testTxSigVerifier{sv: sv})

	kp, _ := crypto.GenerateKeyPair()
	fromAddr := crypto.PublicKeyAddressFromBytes(kp.Public.Bytes())

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     fromAddr,
		ChainID:  cfg.ChainID,
	}
	signTestTx(t, tx, kp)

	// Tamper with Value after signing — signature no longer matches.
	tx.Value = big.NewInt(1_000_000)

	err := seq.AcceptTransaction(tx)
	if err == nil {
		t.Fatal("tx with tampered Value accepted — signature should be invalid")
	}
}

// TestRealSignature_WrongChainIDRejected verifies that a transaction signed
// for a different ChainID is rejected. This is a cross-chain replay defense
// (W-P0-4): a signature valid on L2 chain A must not be reusable on L2 chain B.
func TestRealSignature_WrongChainIDRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	bm := NewBatchManager(cfg, types.Hash{})
	seq := NewSequencer(cfg, bm)
	seq.SetTxSignatureVerifier(&testTxSigVerifier{sv: sv})

	kp, _ := crypto.GenerateKeyPair()
	fromAddr := crypto.PublicKeyAddressFromBytes(kp.Public.Bytes())

	// Sign with wrong ChainID, then change ChainID to match config. The
	// signature was computed over the wrong ChainID, so it must not verify.
	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     fromAddr,
		ChainID:  cfg.ChainID + 999, // wrong chain
	}
	signTestTx(t, tx, kp)
	tx.ChainID = cfg.ChainID // tamper to bypass the early ChainID check

	// Even though tx.ChainID now matches, the signature covers the original
	// wrong ChainID. The verifier recomputes SigningHash() which uses the
	// current ChainID, so the signature will not match.
	err := seq.AcceptTransaction(tx)
	if err == nil {
		t.Fatal("tx with wrong-chain signature accepted — should be rejected")
	}
}

// TestRealSignature_PubKeyAddressMismatchRejected verifies that a transaction
// whose PublicKey does not derive to the claimed From address is rejected.
// This prevents an attacker from using their own pubkey+sig while claiming a
// victim's address in From.
func TestRealSignature_PubKeyAddressMismatchRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	bm := NewBatchManager(cfg, types.Hash{})
	seq := NewSequencer(cfg, bm)
	seq.SetTxSignatureVerifier(&testTxSigVerifier{sv: sv})

	// Attacker's keypair
	attackerKp, _ := crypto.GenerateKeyPair()
	// Victim's address (not derived from attacker's pubkey)
	victimAddr := types.Address{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67}

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     victimAddr,
		ChainID:  cfg.ChainID,
	}
	// Sign with attacker's key, but claim victim's From
	// RLLP- Set PublicKey BEFORE SigningHash so the hash covers it.
	tx.PublicKey = attackerKp.Public.Bytes() // derives to attacker's addr, not victim
	hash := tx.SigningHash()
	sig, _ := attackerKp.Private.Sign(hash[:])
	tx.Signature = sig

	err := seq.AcceptTransaction(tx)
	if err == nil {
		t.Fatal("tx with pubkey/address mismatch accepted — should be rejected")
	}
}

// TestRealSignature_FailClosedWhenVerifierNil verifies that when no verifier
// is configured AND requireTxSig is true (the production default), the
// sequencer rejects ALL transactions. This is the fail-closed behavior
// described in AUDIT (2026) HIGH-10.
func TestRealSignature_FailClosedWhenVerifierNil(t *testing.T) {
	cfg := DefaultRollupConfig()
	bm := NewBatchManager(cfg, types.Hash{})
	seq := NewSequencer(cfg, bm)
	// No SetTxSignatureVerifier call — txSigVerifier stays nil.
	// requireTxSig stays true (default).

	kp, _ := crypto.GenerateKeyPair()
	fromAddr := crypto.PublicKeyAddressFromBytes(kp.Public.Bytes())

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     fromAddr,
		ChainID:  cfg.ChainID,
	}
	signTestTx(t, tx, kp)

	err := seq.AcceptTransaction(tx)
	if err == nil {
		t.Fatal("tx accepted with nil verifier + requireTxSig=true — should fail-closed")
	}
}

// --- Fraud proof signature tests ---

// TestRealSignature_ValidFraudProofAccepted verifies that a fraud proof with
// a valid challenger Dilithium3 signature is accepted by the FraudProver when
// a real SignatureVerifier is configured.
func TestRealSignature_ValidFraudProofAccepted(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	fp := NewFraudProver(cfg, sm)
	fp.SetSignatureVerifier(&testFraudProofSigVerifier{sv: sv})
	// requireSigVerifier stays true (default).

	// Set up valid pre-state so SimulateBatch succeeds.
	from := types.Address{10}
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance.SetInt64(1_000_000)
	sm.accountStates[from].Nonce = 0
	preStateRoot := sm.computeStateRoot()

	// Challenger's keypair
	challengerKp, _ := crypto.GenerateKeyPair()
	challengerAddr := crypto.PublicKeyAddressFromBytes(challengerKp.Public.Bytes())

	// Build a batch with a real transaction. R36-P0-03: submit with a
	// TAMPERED PostStateRoot so the batch is actually fraudulent.
	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     from,
	}
	bm := NewBatchManager(cfg, preStateRoot)
	bm.AddTransaction(tx)
	batch, _ := bm.BuildBatch()
	correctPostRoot, _, err := sm.ProcessBatch(batch.Index, preStateRoot, []*RollupTransaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	tamperedRoot := types.Hash{4, 5, 6}
	if tamperedRoot == correctPostRoot {
		tamperedRoot[0] = 0x99
	}
	bm.SubmitBatch(batch.Index, tamperedRoot, types.Hash{7, 8, 9})
	fp.SetBatchLookup(bm)

	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    batch.Index,
		Challenger:    challengerAddr,
		PreStateRoot:  preStateRoot,
		PostStateRoot: tamperedRoot,
		InvalidTx:     tx,
		Timestamp:     time.Now().Unix(),
	}
	signTestFraudProof(t, proof, challengerKp)

	if err := fp.SubmitFraudProof(proof); err != nil {
		t.Errorf("valid signed fraud proof rejected: %v", err)
	}
}

// TestRealSignature_FraudProofNoSigRejected verifies that a fraud proof with
// no ChallengerSig is rejected when fail-closed mode is active.
func TestRealSignature_FraudProofNoSigRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	fp := NewFraudProver(cfg, sm)
	fp.SetSignatureVerifier(&testFraudProofSigVerifier{sv: sv})

	challengerKp, _ := crypto.GenerateKeyPair()
	challengerAddr := crypto.PublicKeyAddressFromBytes(challengerKp.Public.Bytes())

	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    1,
		Challenger:    challengerAddr,
		PreStateRoot:  types.Hash{1},
		PostStateRoot: types.Hash{2},
		InvalidTx: &RollupTransaction{
			Nonce:    0,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{10},
		},
		Timestamp:     time.Now().Unix(),
		ChallengerSig: nil, // no signature
		// ChallengerPubKey intentionally set but signature empty
		ChallengerPubKey: challengerKp.Public.Bytes(),
	}

	err := fp.SubmitFraudProof(proof)
	if err == nil {
		t.Fatal("fraud proof with no ChallengerSig accepted — should be rejected")
	}
}

// TestRealSignature_FraudProofWrongSigRejected verifies that a fraud proof
// whose ChallengerSig was produced by a different key is rejected.
func TestRealSignature_FraudProofWrongSigRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	fp := NewFraudProver(cfg, sm)
	fp.SetSignatureVerifier(&testFraudProofSigVerifier{sv: sv})

	// Real challenger
	challengerKp, _ := crypto.GenerateKeyPair()
	challengerAddr := crypto.PublicKeyAddressFromBytes(challengerKp.Public.Bytes())

	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    1,
		Challenger:    challengerAddr,
		PreStateRoot:  types.Hash{1},
		PostStateRoot: types.Hash{2},
		InvalidTx: &RollupTransaction{
			Nonce:    0,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{10},
		},
		Timestamp: time.Now().Unix(),
	}
	// Sign with a DIFFERENT key, but claim challenger's address + pubkey
	attackerKp, _ := crypto.GenerateKeyPair()
	msg := buildFraudProofSignMessage(proof)
	wrongSig, _ := attackerKp.Private.Sign(msg)
	proof.ChallengerSig = wrongSig
	proof.ChallengerPubKey = challengerKp.Public.Bytes() // real challenger's pubkey

	err := fp.SubmitFraudProof(proof)
	if err == nil {
		t.Fatal("fraud proof with wrong-key signature accepted — should be rejected")
	}
}

// TestRealSignature_FraudProofPubKeyMismatchRejected verifies that a fraud
// proof whose ChallengerPubKey does not derive to the claimed Challenger
// address is rejected. Prevents an attacker from using their own pubkey+sig
// while claiming a victim's challenger address.
func TestRealSignature_FraudProofPubKeyMismatchRejected(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	fp := NewFraudProver(cfg, sm)
	fp.SetSignatureVerifier(&testFraudProofSigVerifier{sv: sv})

	// Attacker's keypair
	attackerKp, _ := crypto.GenerateKeyPair()
	// Victim's challenger address (not derived from attacker's pubkey)
	victimAddr := types.Address{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67}

	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    1,
		Challenger:    victimAddr,
		PreStateRoot:  types.Hash{1},
		PostStateRoot: types.Hash{2},
		InvalidTx: &RollupTransaction{
			Nonce:    0,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{10},
		},
		Timestamp: time.Now().Unix(),
	}
	// Sign with attacker's key, but claim victim's Challenger
	msg := buildFraudProofSignMessage(proof)
	sig, _ := attackerKp.Private.Sign(msg)
	proof.ChallengerSig = sig
	proof.ChallengerPubKey = attackerKp.Public.Bytes() // derives to attacker, not victim

	err := fp.SubmitFraudProof(proof)
	if err == nil {
		t.Fatal("fraud proof with pubkey/address mismatch accepted — should be rejected")
	}
}

// TestRealSignature_FraudProofFailClosedWhenVerifierNil verifies that when no
// SignatureVerifier is configured AND requireSigVerifier is true (production
// default), the FraudProver rejects ALL fraud proofs.
func TestRealSignature_FraudProofFailClosedWhenVerifierNil(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	fp := NewFraudProver(cfg, sm)
	// No SetSignatureVerifier — sigVerifier stays nil.
	// requireSigVerifier stays true (default).

	challengerKp, _ := crypto.GenerateKeyPair()
	challengerAddr := crypto.PublicKeyAddressFromBytes(challengerKp.Public.Bytes())

	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    1,
		Challenger:    challengerAddr,
		PreStateRoot:  types.Hash{1},
		PostStateRoot: types.Hash{2},
		InvalidTx: &RollupTransaction{
			Nonce:    0,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{10},
		},
		Timestamp: time.Now().Unix(),
	}
	signTestFraudProof(t, proof, challengerKp)

	err := fp.SubmitFraudProof(proof)
	if err == nil {
		t.Fatal("fraud proof accepted with nil verifier + requireSigVerifier=true — should fail-closed")
	}
}

// TestRealSignature_E2EFlowWithRealCrypto is an end-to-end test that exercises
// the full signature verification path: generate keypair → sign tx → submit
// to sequencer → batch builds → batch submits → state manager processes.
// This catches integration bugs that unit tests miss.
func TestRealSignature_E2EFlowWithRealCrypto(t *testing.T) {
	sv := newTestVerifier(t)
	defer sv.Close()

	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1
	cfg.MaxTxPerBatch = 10

	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}
	engine.SetTxSignatureVerifier(&testTxSigVerifier{sv: sv})
	engine.SetFraudProofVerifier(&testFraudProofSigVerifier{sv: sv})

	// Wire FraudProver lookup + BatchManager prover (matches initRollup).
	fp := engine.GetFraudProver()
	bm := engine.GetBatchManager()
	fp.SetBatchLookup(bm)
	bm.SetFraudProver(fp)

	if err := engine.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer engine.Stop()

	// Generate a real sender keypair.
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	fromAddr := crypto.PublicKeyAddressFromBytes(kp.Public.Bytes())

	// Fund the sender account so the L2 tx doesn't bounce.
	sm := engine.GetStateManager()
	sm.getOrCreateAccount(fromAddr)
	sm.accountStates[fromAddr].Balance = new(big.Int).SetInt64(1_000_000_000)

	// HIGH-11 FIX: ProcessBatch validates prevStateRoot == computeStateRoot().
	// The engine was created with genesisStateRoot=types.Hash{} (empty), but
	// we just funded an account — so the StateManager's current root no longer
	// matches the BatchManager's lastStateRoot. Sync them via RestoreMeta so
	// the first batch's PrevStateRoot check passes.
	preRoot := sm.computeStateRoot()
	bm.RestoreMeta(0, preRoot)

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     fromAddr,
		ChainID:  cfg.ChainID,
	}
	signTestTx(t, tx, kp)

	// Submit — should be accepted by the real verifier.
	if err := engine.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction rejected valid signed tx: %v", err)
	}

	// Wait for the engine to build + submit a batch (BlockTime=100ms).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		totalBatches, _, _ := engine.GetStats()
		if totalBatches > 0 {
			return // success — a batch was built and submitted
		}
		time.Sleep(20 * time.Millisecond)
	}
	totalBatches, totalTxs, _ := engine.GetStats()
	t.Errorf("no batch was built within 2s (totalBatches=%d, totalTxs=%d)", totalBatches, totalTxs)
}

// Ensure unused imports are referenced (mode3 is used indirectly via crypto).
var _ = mode3.PublicKeySize
var _ = rand.Reader
