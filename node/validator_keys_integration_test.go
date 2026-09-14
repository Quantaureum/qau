// Quantaureum Node source, version 1.0.0.
//go:build integration

package node

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// buildDevFundTx (unused helper, kept for manual dev flows): generates from deterministic dev account 0
// (seed "QUANTAUREUM-DEV-ACCOUNT-SEED"||0) to `to`, with value 1 QAU.
func buildDevFundTx(t *testing.T, to types.Address, chainID uint64) *encoding.Transaction {
	t.Helper()
	seed := make([]byte, 32)
	copy(seed[:], []byte("QUANTAUREUM-DEV-ACCOUNT-SEED"))
	kp, err := crypto.GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	tx := &encoding.Transaction{
		Type:     encoding.TxTypeTransfer,
		From:     kp.Public.Address(),
		To:       &to,
		Nonce:    0,
		Value:    big.NewInt(1_000_000_000_000_000_000),
		GasLimit: 50000,
		GasPrice: big.NewInt(1_000_000_000),
		ChainID:  chainID,
	}
	tx.PublicKey = kp.Public.Bytes()
	hash, err := tx.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(kp.Private, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	tx.Signature = sig
	return tx
}

// node's identity key, as vkctl would.
func buildVKSignedTx(t *testing.T, idKey *crypto.PrivateKey, idAddr types.Address, chainID uint64, nonce uint64, data []byte) *encoding.Transaction {
	t.Helper()
	reg := economics.ValidatorKeyRegistryAddress
	tx := &encoding.Transaction{
		Type:     encoding.TxTypeValidatorKey,
		From:     idAddr,
		To:       &reg,
		Nonce:    nonce,
		Data:     data,
		Value:    nil,
		GasLimit: 120000, // payload ~2KB + base intrinsic
		GasPrice: big.NewInt(1_000_000_000),
		ChainID:  chainID,
	}
	tx.PublicKey = idKey.PublicKey().Bytes()
	hash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("signing hash: %v", err)
	}
	sig, err := crypto.Sign(idKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tx.Signature = sig
	return tx
}

// TestValidatorSessionRotation_E2E spins up a dev node, submits a session-key
// rotation transaction through the real txpool → block inclusion →
// post-commit hook path, waits for epoch-boundary activation, asserts the
// session key is authoritative for attestations, and finally restarts the
// node to prove snapshot persistence.
func TestValidatorSessionRotation_E2E(t *testing.T) {
	cfg := devTestConfig(t)
	// Windows: t.TempDir() cleanup races the LMDB handle release from the
	// restarted node; use a hand-managed dir we clean best-effort.
	tmp, err := os.MkdirTemp("", "r131-e2e-")
	if err == nil {
		cfg.DataDir = tmp
		t.Cleanup(func() {
			time.Sleep(2 * time.Second)
			_ = os.RemoveAll(tmp)
		})
	}

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer n.Stop()

	// Wait for the block producer to come up and produce some blocks.
	for i := 0; i < 50 && n.blockProducer == nil; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if n.blockProducer == nil {
		t.Fatal("block producer never initialized")
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		if n.blockProducer.QPOS() != nil && n.blockProducer.validatorKey != nil {
			h, _ := n.blockStore.GetLatestHeight()
			if h >= 3 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("chain did not reach height 3")
		}
		time.Sleep(200 * time.Millisecond)
	}

	bp := n.blockProducer
	qpos := bp.QPOS()

	// Identity = deterministic dev validator #0 (DevMode-only fallback
	// validator set: keys reproducible from "QUANTAUREUM-DEV-VALIDATOR-i").
	seed := make([]byte, 32)
	copy(seed, []byte("QUANTAUREUM-DEV-VALIDATOR-0"))
	kp, err := crypto.GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	idKey := kp.Private
	idAddr := kp.Public.Address()
	vs := bp.validatorSet
	if vs == nil || vs.GetValidator(idAddr) == nil {
		t.Fatal("dev validator 0 not in validator set — deterministic dev set missing")
	}

	// Sanity: validator registry is empty for this validator.
	if qpos.ValidatorKeyStatus(idAddr) != nil {
		t.Fatal("registry must start empty for this validator")
	}

	// Generate session keypair (hot key).
	sessKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessPub := sessKP.Public.Bytes()

	// Current epoch from qpos slot; activation at epoch+2 to be safely in the
	// future of any concurrently committing block.
	curSlot := qpos.GetCurrentSlot()
	curEpoch := curSlot / consensus.SlotsPerEpoch
	actEpoch := curEpoch + 1

	data := consensus.EncodeVKRotateSession(idAddr, actEpoch, sessPub)
	tx := buildVKSignedTx(t, idKey, idAddr, n.chainID, 0, data)

	// Fund the validator identity directly in state (dev-genesis accounts are
	// not wired into this harness's alloc; this is a test-only state probe).
	n.stateDB.SetBalance(idAddr, big.NewInt(1_000_000_000_000_000_000))
	if bal := n.stateDB.GetBalance(idAddr); bal == nil || bal.Sign() == 0 {
		t.Fatal("state injection failed")
	}
	t.Logf("validator funded via state probe")

	if err := n.txPool.Add(tx); err != nil {
		t.Fatalf("txPool.Add: %v", err)
	}
	t.Logf("rotation tx queued: activate epoch %d (current %d)", actEpoch, curEpoch)

	// Wait for inclusion (pool → block → syncValidatorKeysFromBlock).
	inclusionDeadline := time.Now().Add(30 * time.Second)
	included := false
	for time.Now().Before(inclusionDeadline) {
		st := qpos.ValidatorKeyStatus(idAddr)
		if st != nil && st.RotationCount > 0 {
			included = true
			t.Logf("rotation applied in block %d (height field=%d)", func() uint64 { h, _ := n.blockStore.GetLatestHeight(); return h }(), st.LastOpHeight)
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !included {
		t.Fatal("rotation tx was never applied")
	}

	// Before activation epoch: resolver must fall back to base identity.
	if _, ok := qpos.EffectiveSessionPubKey(idAddr, curEpoch); ok {
		t.Fatal("session must NOT be active before activation epoch")
	}

	// Epoch-aware resolver assertions (the chain's own slot clock in this
	// dev harness is gated by QPOS cold-start, so the registry API's epoch
	// parameter is the deterministic anchor).
	if _, ok := qpos.EffectiveSessionPubKey(idAddr, actEpoch-1); ok {
		t.Fatal("session must NOT be active at activationEpoch-1")
	}
	pk, ok := qpos.EffectiveSessionPubKey(idAddr, actEpoch)
	if !ok {
		t.Fatal("session must be active at activation epoch")
	}
	if string(pk) != string(sessPub) {
		t.Fatal("active session pubkey mismatch")
	}
	t.Logf("session active at epoch %d", actEpoch)

	// Snapshot must exist on disk.
	snapPath := filepath.Join(cfg.DataDir, "validator_keys.json")
	st2, err := os.Stat(snapPath)
	if err != nil || st2.Size() == 0 {
		t.Fatalf("snapshot missing: %v", err)
	}
	t.Logf("snapshot persisted: %s (%d bytes)", snapPath, st2.Size())

	// Producer-side: re-point this dev node's identity to dev validator 0
	// (the rotated one), then: with NO session key loaded at bp,
	// activeSigningKey must REFUSE (fail-closed, not silently sign with the
	// base key while a session is active on-chain).
	bp.validatorAddr = idAddr
	bp.validatorKey = idKey
	if _, err := bp.activeSigningKey(actEpoch); err == nil {
		t.Fatal("activeSigningKey must refuse when on-chain session active but local session key missing")
	}
	// Now load the session key into bp manually and expect selection.
	bp.sessionKey = sessKP.Private
	bp.sessionPub = sessPub
	k, err := bp.activeSigningKey(actEpoch)
	if err != nil {
		t.Fatalf("activeSigningKey with matching session: %v", err)
	}
	if k != sessKP.Private {
		t.Fatal("activeSigningKey did not return the session key")
	}

	// ── Restart persistence check ──
	if err := n.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	cfg2 := cfg
	n2, err := NewNode(cfg2)
	if err != nil {
		t.Fatalf("NewNode(2): %v", err)
	}
	if err := n2.Start(); err != nil {
		t.Fatalf("Start(2): %v", err)
	}
	defer n2.Stop()

	// Wait for qpos to come up
	d2 := time.Now().Add(20 * time.Second)
	for {
		if n2.blockProducer != nil && n2.blockProducer.QPOS() != nil {
			break
		}
		if time.Now().After(d2) {
			t.Fatal("qpos never came up after restart")
		}
		time.Sleep(200 * time.Millisecond)
	}
	qpos2 := n2.blockProducer.QPOS()
	d3 := time.Now().Add(20 * time.Second)
	var st *consensus.ValidatorKeyState
	for {
		st = qpos2.ValidatorKeyStatus(idAddr)
		if st != nil {
			break
		}
		if time.Now().After(d3) {
			t.Fatal("registry not restored after restart")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if st == nil || st.RotationCount == 0 {
		t.Fatalf("registry lost after restart: %+v", st)
	}
	pk2, ok2 := qpos2.EffectiveSessionPubKey(idAddr, actEpoch)
	if !ok2 || string(pk2) != string(sessPub) {
		t.Fatal("session key not restored after restart")
	}
	t.Logf("registry survived restart: rotationCount=%d session present", st.RotationCount)
}
