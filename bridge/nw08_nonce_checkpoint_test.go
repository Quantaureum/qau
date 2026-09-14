// Quantaureum Node source, version 1.0.0.
// AUDIT-FULL NW-08 (2026-08-14) regression tests: memory-mode nonce
// checkpoint.
//
// When the bridge runs without a persistent message store (store == nil),
// usedNonces/highestUsedNonce were memory-only, so a process restart forgot
// every recorded nonce and pre-restart messages could be replayed
// (double-spend). With SetNonceCheckpointPath configured, the nonce state
// must be snapshotted on every mutation and reloaded on (re)start.
//
// These tests reuse the signH01Message / trackingAdapter /
// failingSubmitOnlyAdapter helpers from sibling test files (same package).
package bridge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// nw08NewBridge builds a memory-mode bridge (no store) with the common
// test wiring: initialized status maps, a trusted validator key pair and
// a working source-chain adapter.
func nw08NewBridge(t *testing.T, cfg *BridgeConfig) (*QuantumBridge, *crypto.KeyPair) {
	t.Helper()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	if err := b.Initialize(context.Background()); err != nil {
		b.Stop(context.Background())
		t.Fatalf("Initialize failed: %v", err)
	}
	b.adapters["source-chain"] = &trackingAdapter{chainID: "source-chain"}
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		b.Stop(context.Background())
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	b.SetTrustedValidatorKeys([][]byte{keyPair.Public.Bytes()})
	return b, keyPair
}

// nw08NewMessage builds a valid, signed BridgeMessage. SourceAddress is
// derived from the key pair (verifyQuantumSignature enforces this).
func nw08NewMessage(t *testing.T, b *QuantumBridge, keyPair *crypto.KeyPair, id string, nonce uint64) *BridgeMessage {
	t.Helper()
	msg := &BridgeMessage{
		ID:            id,
		SourceChain:   "source-chain",
		TargetChain:   "target-chain",
		SourceAddress: keyPair.Public.Address().ToHexAddress(),
		TargetAddress: "0xRecipientNW08",
		AssetType:     AssetTypeNative,
		AssetID:       "QAU",
		Amount:        "1000000000000000000",
		MessageType:   MessageTypeAssetTransfer,
		Nonce:         nonce,
		Timestamp:     time.Now().Unix(),
		BlockNumber:   100,
		Status:        MessageStatusPending,
	}
	signH01Message(t, b, msg, keyPair)
	return msg
}

// TestNW08_MemoryModeNonceCheckpoint_SurvivesRestart is the core NW-08
// regression: a nonce consumed before a restart must still be rejected
// after the bridge is recreated (memory mode, checkpoint file only).
func TestNW08_MemoryModeNonceCheckpoint_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	// Nested, not-yet-existing parent directory exercises MkdirAll.
	path := filepath.Join(dir, "bridge", "nonce_checkpoint.json")

	b1, keyPair := nw08NewBridge(t, DefaultBridgeConfig())
	defer b1.Stop(context.Background())
	if err := b1.SetNonceCheckpointPath(path); err != nil {
		t.Fatalf("SetNonceCheckpointPath: %v", err)
	}

	if err := b1.SubmitMessage(context.Background(), nw08NewMessage(t, b1, keyPair, "nw08-msg-1", 7)); err != nil {
		t.Fatalf("initial SubmitMessage failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("NW-08 regression: nonce checkpoint file not written: %v", err)
	}

	// Simulated restart: brand-new bridge over the same checkpoint file.
	// The SAME key pair is reused so the replay targets the SAME
	// (sourceChain, sourceAddress) nonce namespace as the original submit.
	b2, _ := nw08NewBridge(t, DefaultBridgeConfig())
	defer b2.Stop(context.Background())
	// R31-MED-4: swapping b2's bootstrap key for b1's persistent key set is
	// a trust-anchor change — go through the explicit operator mutation
	// window, then re-seal.
	b2.UnlockValidatorTrustMutation("nw08 restart simulation: restore persistent validator key")
	b2.SetTrustedValidatorKeys([][]byte{keyPair.Public.Bytes()})
	b2.LockValidatorTrustMutation()
	if err := b2.SetNonceCheckpointPath(path); err != nil {
		t.Fatalf("NW-08 regression: loading checkpoint on restart failed: %v", err)
	}

	// Replaying the SAME (chain, addr, nonce) under a fresh message ID
	// must be rejected after the restart.
	replay := nw08NewMessage(t, b2, keyPair, "nw08-replay", 7)
	err := b2.SubmitMessage(context.Background(), replay)
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("NW-08 NOT FIXED: nonce replay accepted after restart (err=%v)", err)
	}

	// A distinct nonce must still be accepted (no over-blocking).
	if err := b2.SubmitMessage(context.Background(), nw08NewMessage(t, b2, keyPair, "nw08-fresh", 8)); err != nil {
		t.Fatalf("distinct nonce wrongly rejected after restart: %v", err)
	}
}

// TestNW08_CheckpointRollbackFreesNonceAcrossRestart verifies the rollback
// checkpoint sites: when SubmitMessage fails on the adapter, the nonce is
// removed from memory AND from the on-disk checkpoint, so a restart between
// rollback and retry does not permanently burn a nonce that was never used.
func TestNW08_CheckpointRollbackFreesNonceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonce_checkpoint.json")

	b1, keyPair := nw08NewBridge(t, DefaultBridgeConfig())
	defer b1.Stop(context.Background())
	if err := b1.SetNonceCheckpointPath(path); err != nil {
		t.Fatalf("SetNonceCheckpointPath: %v", err)
	}
	// Replace the working adapter with one whose SubmitMessage always fails
	// to force the BRIDGE-H01 rollback path (which re-checkpoints).
	b1.adapters["source-chain"] = &failingSubmitOnlyAdapter{chainID: "source-chain"}

	msg := nw08NewMessage(t, b1, keyPair, "nw08-rollback", 21)
	if err := b1.SubmitMessage(context.Background(), msg); err == nil {
		t.Fatal("SubmitMessage unexpectedly succeeded with failingSubmitOnlyAdapter")
	}

	// Same key pair as b1 so the retry targets the SAME nonce namespace —
	// a stale checkpoint entry would burn the nonce across the restart.
	b2, _ := nw08NewBridge(t, DefaultBridgeConfig())
	defer b2.Stop(context.Background())
	// R31-MED-4: explicit operator mutation window (restart rotation).
	b2.UnlockValidatorTrustMutation("nw08 rollback-restart simulation: restore persistent validator key")
	b2.SetTrustedValidatorKeys([][]byte{keyPair.Public.Bytes()})
	b2.LockValidatorTrustMutation()
	if err := b2.SetNonceCheckpointPath(path); err != nil {
		t.Fatalf("load checkpoint after rollback: %v", err)
	}
	// The rolled-back nonce was never used — it must be submittable again.
	if err := b2.SubmitMessage(context.Background(), nw08NewMessage(t, b2, keyPair, "nw08-rollback-retry", 21)); err != nil {
		t.Fatalf("NW-08 regression: rolled-back nonce burned across restart: %v", err)
	}
}

// TestNW08_HighWaterMarkAndIndividuallyTrackedNoncesPersist verifies the
// checkpoint round-trip of the high-water mark and individually tracked
// nonces: nonces <= highest are covered by the mark (skipped on load to
// keep memory lean), nonces > highest are restored individually.
func TestNW08_HighWaterMarkAndIndividuallyTrackedNoncesPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonce_checkpoint.json")

	b1, _ := nw08NewBridge(t, DefaultBridgeConfig())
	defer b1.Stop(context.Background())
	if err := b1.SetNonceCheckpointPath(path); err != nil {
		t.Fatalf("SetNonceCheckpointPath: %v", err)
	}
	nk := nonceKey{chain: "source-chain", addr: "0xNW08HighWater"}
	b1.mu.Lock()
	b1.highestUsedNonce[nk] = 100
	b1.usedNonces[nk] = map[uint64]time.Time{
		50:  time.Now(),
		120: time.Now(),
	}
	b1.totalUsedNonces = 2
	b1.checkpointNoncesLocked()
	b1.mu.Unlock()

	b2, _ := nw08NewBridge(t, DefaultBridgeConfig())
	defer b2.Stop(context.Background())
	if err := b2.SetNonceCheckpointPath(path); err != nil {
		t.Fatalf("SetNonceCheckpointPath: %v", err)
	}

	b2.mu.RLock()
	highest := b2.highestUsedNonce[nk]
	_, has50 := b2.usedNonces[nk][50]
	_, has120 := b2.usedNonces[nk][120]
	total := b2.totalUsedNonces
	b2.mu.RUnlock()

	if highest != 100 {
		t.Fatalf("NW-08 NOT FIXED: high-water mark lost across restart (got %d, want 100)", highest)
	}
	if has50 {
		t.Fatal("nonce 50 (<= high-water mark) should be skipped on load — it is covered by the mark")
	}
	if !has120 {
		t.Fatal("NW-08 NOT FIXED: individually tracked nonce 120 lost across restart")
	}
	if total != 1 {
		t.Fatalf("totalUsedNonces = %d after load, want 1 (only the uncovered nonce counts)", total)
	}
}

// TestNW08_CorruptOrWrongVersionCheckpointFailsClosed verifies the
// fail-closed load contract: a corrupt or version-mismatched checkpoint
// returns an error instead of silently starting with an empty anti-replay
// set (which would re-open the replay window the checkpoint closes).
func TestNW08_CorruptOrWrongVersionCheckpointFailsClosed(t *testing.T) {
	dir := t.TempDir()

	corruptPath := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt checkpoint: %v", err)
	}
	b1, _ := nw08NewBridge(t, DefaultBridgeConfig())
	defer b1.Stop(context.Background())
	if err := b1.SetNonceCheckpointPath(corruptPath); err == nil {
		t.Fatal("NW-08 regression: corrupt checkpoint silently accepted (fail-open)")
	}

	badVersionPath := filepath.Join(dir, "badversion.json")
	if err := os.WriteFile(badVersionPath, []byte(`{"version":99,"saved_at":1,"entries":[]}`), 0o600); err != nil {
		t.Fatalf("write bad-version checkpoint: %v", err)
	}
	b2, _ := nw08NewBridge(t, DefaultBridgeConfig())
	defer b2.Stop(context.Background())
	if err := b2.SetNonceCheckpointPath(badVersionPath); err == nil {
		t.Fatal("NW-08 regression: wrong-version checkpoint silently accepted (fail-open)")
	}
}
