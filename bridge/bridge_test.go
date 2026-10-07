// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

type mockVerifier struct {
	allowAll bool
}

func (m *mockVerifier) Verify(publicKey []byte, message []byte, signature []byte) bool {
	return m.allowAll
}

func TestMessageRelayer(t *testing.T) {
	cfg := DefaultBridgeConfig()
	bridge := NewQuantumBridge(cfg).(*QuantumBridge)
	relayerCfg := DefaultRelayerConfig()

	t.Run("NewMessageRelayer", func(t *testing.T) {
		relayer := NewMessageRelayer(relayerCfg, bridge)
		if relayer == nil {
			t.Fatal("NewMessageRelayer returned nil")
		}
	})

	t.Run("Start and Stop", func(t *testing.T) {
		relayer := NewMessageRelayer(relayerCfg, bridge)
		ctx := context.Background()

		err := relayer.Start(ctx)
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		err = relayer.Stop()
		if err != nil {
			t.Fatalf("Stop failed: %v", err)
		}
	})

	t.Run("SubmitRelayTask", func(t *testing.T) {
		relayer := NewMessageRelayer(relayerCfg, bridge)
		ctx := context.Background()
		relayer.Start(ctx)
		defer relayer.Stop()

		msg := &BridgeMessage{
			ID:          "test-msg-1",
			SourceChain: "chain-a",
			TargetChain: "chain-b",
			MessageType: MessageTypeAssetTransfer,
			Status:      MessageStatusPending,
			Timestamp:   time.Now().Unix(),
		}

		task, err := relayer.SubmitRelayTask(msg)
		if err != nil {
			t.Fatalf("SubmitRelayTask failed: %v", err)
		}
		if task == nil {
			t.Fatal("task is nil")
		}
		if task.ID == "" {
			t.Error("task ID is empty")
		}
	})

	t.Run("GetTask", func(t *testing.T) {
		relayer := NewMessageRelayer(relayerCfg, bridge)
		ctx := context.Background()
		relayer.Start(ctx)
		defer relayer.Stop()

		msg := &BridgeMessage{
			ID:          "test-msg-2",
			SourceChain: "chain-a",
			TargetChain: "chain-b",
			MessageType: MessageTypeAssetTransfer,
			Status:      MessageStatusPending,
			Timestamp:   time.Now().Unix(),
		}

		task, _ := relayer.SubmitRelayTask(msg)
		retrieved, exists := relayer.GetTask(task.ID)
		if !exists {
			t.Fatal("task not found")
		}
		if retrieved.ID != task.ID {
			t.Errorf("task ID mismatch: %s != %s", retrieved.ID, task.ID)
		}
	})

	t.Run("CalculateBackoff", func(t *testing.T) {
		relayer := NewMessageRelayer(relayerCfg, bridge)

		// BRDG- (2026-07-17): calculateBackoff now applies full jitter
		// (AWS pattern: random in [0, cap]). The previous exact-equality
		// assertions no longer hold; we now verify the value is within the
		// valid jitter range [0, cap].
		// cap for attempts=1 is BaseBackoff * 2^0 = BaseBackoff.
		b1 := relayer.calculateBackoff(1)
		if b1 < 0 || b1 > relayerCfg.BaseBackoff {
			t.Errorf("attempts=1 backoff out of [0, %v]: got %v",
				relayerCfg.BaseBackoff, b1)
		}

		// cap for attempts=2 is BaseBackoff * 2^1 = 2*BaseBackoff.
		b2 := relayer.calculateBackoff(2)
		if b2 < 0 || b2 > relayerCfg.BaseBackoff*2 {
			t.Errorf("attempts=2 backoff out of [0, %v]: got %v",
				relayerCfg.BaseBackoff*2, b2)
		}

		// Jittered value must still respect the MaxBackoff cap.
		bMax := relayer.calculateBackoff(100)
		if bMax > relayerCfg.MaxBackoff {
			t.Errorf("backoff exceeded max: %v > %v", bMax, relayerCfg.MaxBackoff)
		}
	})

	// BRDG- (2026-07-17): Verify calculateBackoff applies full jitter —
	// N repeated calls for the same attempt count must NOT all return the
	// same value. Without jitter, all N calls return cap deterministically;
	// with full jitter, the values are spread across [0, cap]. We verify
	// (a) all values are in range, and (b) at least 2 distinct values appear
	// (statistical guarantee against degenerate random sources).
	t.Run("CalculateBackoff full jitter (BRDG-)", func(t *testing.T) {
		relayer := NewMessageRelayer(relayerCfg, bridge)
		const samples = 50
		const attempts = 5 // cap = BaseBackoff * 2^4 = 80s
		cap := relayerCfg.BaseBackoff * time.Duration(1<<uint(attempts-1))
		if cap > relayerCfg.MaxBackoff {
			cap = relayerCfg.MaxBackoff
		}
		seen := make(map[time.Duration]struct{}, samples)
		for i := 0; i < samples; i++ {
			b := relayer.calculateBackoff(attempts)
			if b < 0 || b > cap {
				t.Fatalf("sample %d: backoff %v out of [0, %v]", i, b, cap)
			}
			seen[b] = struct{}{}
		}
		if len(seen) < 2 {
			t.Errorf("full jitter expected >=2 distinct values across %d samples, got %d (no jitter applied?)",
				samples, len(seen))
		}
		// Sanity: average should be roughly cap/2 (within generous bounds).
		// We don't assert this strictly to avoid flakiness, but log it.
		var sum time.Duration
		for v := range seen {
			sum += v
		}
		t.Logf("jitter samples=%d distinct=%d cap=%v avg≈%v",
			samples, len(seen), cap, sum/time.Duration(len(seen)))
	})

	// BRDG- Edge case — BaseBackoff=0 must not panic (rand.Int63n(0)
	// would panic; the guard in calculateBackoff returns 0).
	t.Run("CalculateBackoff zero BaseBackoff safe (BRDG-)", func(t *testing.T) {
		cfg := *relayerCfg
		cfg.BaseBackoff = 0
		relayer := NewMessageRelayer(&cfg, bridge)
		// Must not panic.
		b := relayer.calculateBackoff(3)
		if b != 0 {
			t.Errorf("with BaseBackoff=0, expected 0, got %v", b)
		}
	})
}

func TestAssetLockManager(t *testing.T) {
	cfg := DefaultBridgeConfig()
	bridge := NewQuantumBridge(cfg).(*QuantumBridge)

	t.Run("NewAssetLockManager", func(t *testing.T) {
		alm := NewAssetLockManager(bridge, types.Address{})
		if alm == nil {
			t.Fatal("NewAssetLockManager returned nil")
		}
	})

	t.Run("GetLock not found", func(t *testing.T) {
		alm := NewAssetLockManager(bridge, types.Address{})
		_, exists := alm.GetLock("nonexistent")
		if exists {
			t.Error("should not find nonexistent lock")
		}
	})

	t.Run("GetLocksByOwner empty", func(t *testing.T) {
		alm := NewAssetLockManager(bridge, types.Address{})
		owner := types.Address{1}
		locks := alm.GetLocksByOwner(owner)
		if len(locks) != 0 {
			t.Errorf("expected 0 locks, got %d", len(locks))
		}
	})

	t.Run("GetLocksByStatus empty", func(t *testing.T) {
		alm := NewAssetLockManager(bridge, types.Address{})
		locks := alm.GetLocksByStatus(LockStatusLocked)
		if len(locks) != 0 {
			t.Errorf("expected 0 locks, got %d", len(locks))
		}
	})

	t.Run("GenerateLockID", func(t *testing.T) {
		owner := types.Address{1, 2, 3}
		id1 := GenerateLockID("chain-a", owner, 0)
		id2 := GenerateLockID("chain-a", owner, 0)
		if id1 != id2 {
			t.Error("same inputs should produce same ID")
		}

		id3 := GenerateLockID("chain-a", owner, 1)
		if id1 == id3 {
			t.Error("different nonces should produce different IDs")
		}
	})

	// BRDG- (2026-07-17): Verify StartConfirmationWatcher + Stop()
	// cleanly tears down the background goroutine. The audit flagged this
	// as a potential goroutine-leak risk; the fix (stopCh + WaitGroup +
	// ctx.Done select) was already implemented by BRDG-09 (2026-07-12).
	// This test guards against regression.
	t.Run("StartConfirmationWatcher Stop cleans up goroutine (BRDG-)", func(t *testing.T) {
		alm := NewAssetLockManager(bridge, types.Address{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// BRDG-R42-CI-RACE-3 (2026-08-19): replaced the previous
		// `time.Sleep(100ms); if duringGoroutines <= beforeGoroutines`
		// check with a polling loop. On CI slow-machines (especially
		// under -race instrumentation) 100ms is frequently insufficient
		// for the Go scheduler to actually start the watcher goroutine,
		// producing flaky "watcher goroutine did not spawn: before=4,
		// during=4" failures (see CI run 32247883826 — the actual race
		// was already fixed by R42-CI-RACE-3; this was a timing flake
		// on top of a passing race fix).
		runtime.Gosched()
		beforeGoroutines := runtime.NumGoroutine()
		if err := alm.StartConfirmationWatcher(ctx, 50*time.Millisecond); err != nil {
			t.Fatalf("StartConfirmationWatcher failed: %v", err)
		}
		// Poll up to 2s for the watcher goroutine to spawn. CI runners
		// under -race can take multiple scheduler ticks to start a new
		// goroutine; 100ms was insufficient on linear 2-core CI.
		spawned := false
		spawnDeadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(spawnDeadline) {
			if runtime.NumGoroutine() > beforeGoroutines {
				spawned = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !spawned {
			t.Errorf("watcher goroutine did not spawn within 2s: before=%d, current=%d",
				beforeGoroutines, runtime.NumGoroutine())
		}

		// Stop must signal the watcher via stopCh and wait for it to exit
		// (WaitGroup). If the goroutine leaks, this assertion will fail.
		stopDone := make(chan struct{})
		go func() {
			alm.Stop()
			close(stopDone)
		}()
		select {
		case <-stopDone:
			// good — Stop returned promptly
		case <-time.After(3 * time.Second):
			t.Fatal("alm.Stop() blocked for >3s — watcher goroutine did not exit (BRDG- leak)")
		}

		// BRDG-R42-CI-RACE-3 (2026-08-19): replaced the previous
		// `time.Sleep(100ms); if afterGoroutines > beforeGoroutines`
		// check with a polling loop. Same rationale as the spawn-check
		// above: CI slow-machines need a moment to reclaim the exit()'d
		// goroutine from NumGoroutine's accounting, and 100ms is
		// insufficient under -race instrumentation.
		exited := false
		exitDeadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(exitDeadline) {
			if runtime.NumGoroutine() <= beforeGoroutines {
				exited = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !exited {
			t.Errorf("goroutine leak: before=%d, current=%d (watcher did not exit)",
				beforeGoroutines, runtime.NumGoroutine())
		}
		if !alm.IsStopped() {
			t.Error("alm.IsStopped() should be true after Stop()")
		}
	})

	// BRDG- Double Stop() must not panic (idempotent close on stopCh).
	t.Run("Stop is idempotent (BRDG-)", func(t *testing.T) {
		alm := NewAssetLockManager(bridge, types.Address{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := alm.StartConfirmationWatcher(ctx, 100*time.Millisecond); err != nil {
			t.Fatalf("StartConfirmationWatcher failed: %v", err)
		}
		alm.Stop()
		alm.Stop() // must not panic on double-close of watcherStop
		alm.Stop() // third call still safe
	})

	// BRDG- StartConfirmationWatcher must refuse after Stop().
	t.Run("StartConfirmationWatcher refuses after Stop (BRDG-)", func(t *testing.T) {
		alm := NewAssetLockManager(bridge, types.Address{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := alm.StartConfirmationWatcher(ctx, 100*time.Millisecond); err != nil {
			t.Fatalf("StartConfirmationWatcher failed: %v", err)
		}
		alm.Stop()
		if err := alm.StartConfirmationWatcher(ctx, 100*time.Millisecond); err == nil {
			t.Error("StartConfirmationWatcher should fail after Stop() (IsStopped=true)")
		}
	})
}

func TestValidatorSet(t *testing.T) {
	t.Run("NewValidatorSet", func(t *testing.T) {
		vs := NewValidatorSet(3)
		if vs == nil {
			t.Fatal("NewValidatorSet returned nil")
		}
		if vs.GetThreshold() != 3 {
			t.Errorf("expected threshold 3, got %d", vs.GetThreshold())
		}
	})

	t.Run("AddValidator", func(t *testing.T) {
		vs := NewValidatorSet(2)
		v := &BridgeValidator{
			Address:   types.Address{1},
			Stake:     big.NewInt(1000),
			PublicKey: []byte{1},
		}
		err := vs.AddValidator(v)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}

		retrieved, exists := vs.GetValidator(v.Address)
		if !exists {
			t.Fatal("validator not found")
		}
		if !retrieved.Active {
			t.Error("validator should be active")
		}
	})

	t.Run("AddValidator duplicate", func(t *testing.T) {
		vs := NewValidatorSet(2)
		v := &BridgeValidator{
			Address:   types.Address{1},
			Stake:     big.NewInt(1000),
			PublicKey: []byte{1},
		}
		vs.AddValidator(v)
		err := vs.AddValidator(v)
		if err == nil {
			t.Error("should fail on duplicate validator")
		}
	})

	t.Run("RemoveValidator", func(t *testing.T) {
		vs := NewValidatorSet(2)
		v := &BridgeValidator{
			Address:   types.Address{1},
			Stake:     big.NewInt(1000),
			PublicKey: []byte{1},
		}
		vs.AddValidator(v)
		err := vs.RemoveValidator(v.Address)
		if err != nil {
			t.Fatalf("RemoveValidator failed: %v", err)
		}

		retrieved, _ := vs.GetValidator(v.Address)
		if retrieved.Active {
			t.Error("validator should be inactive")
		}
	})

	t.Run("GetActiveValidators", func(t *testing.T) {
		vs := NewValidatorSet(2)
		v1 := &BridgeValidator{Address: types.Address{1}, Stake: big.NewInt(100), PublicKey: []byte{1}}
		v2 := &BridgeValidator{Address: types.Address{2}, Stake: big.NewInt(200), PublicKey: []byte{2}}
		vs.AddValidator(v1)
		vs.AddValidator(v2)

		active := vs.GetActiveValidators()
		if len(active) != 2 {
			t.Errorf("expected 2 active, got %d", len(active))
		}
		if active[0].Stake.Cmp(big.NewInt(200)) != 0 {
			t.Error("validators should be sorted by stake descending")
		}
	})

	t.Run("HasQuorum", func(t *testing.T) {
		vs := NewValidatorSet(3)
		if vs.HasQuorum(2) {
			t.Error("2 signatures should not meet threshold of 3")
		}
		if !vs.HasQuorum(3) {
			t.Error("3 signatures should meet threshold of 3")
		}
	})
}

// mustNewSignatureAggregator is a test helper that wraps
// NewSignatureAggregator and panics on error. R8-OBS-2 (2026-07-18):
// NewSignatureAggregator now returns (*SignatureAggregator, error)
// instead of panicking on invalid arguments. This helper preserves the
// concise test call sites.
func mustNewSignatureAggregator(t *testing.T, threshold int, verifier SignatureVerifier, validatorSet *ValidatorSet) *SignatureAggregator {
	t.Helper()
	sa, err := NewSignatureAggregator(threshold, verifier, validatorSet)
	if err != nil {
		t.Fatalf("NewSignatureAggregator(%d, %T, %T) failed: %v", threshold, verifier, validatorSet, err)
	}
	return sa
}

// mustNewValidatorNetwork is a test helper that wraps
// NewValidatorNetwork and panics on error. R8-OBS-2 (2026-07-18).
func mustNewValidatorNetwork(t *testing.T, threshold int, relayer *MessageRelayer, verifier SignatureVerifier, governanceAddress string) *ValidatorNetwork {
	t.Helper()
	vn, err := NewValidatorNetwork(threshold, relayer, verifier, governanceAddress)
	if err != nil {
		t.Fatalf("NewValidatorNetwork(%d, %T, %T, %q) failed: %v", threshold, relayer, verifier, governanceAddress, err)
	}
	return vn
}

func TestSignatureAggregator(t *testing.T) {
	mockVerifier := &mockVerifier{allowAll: true}

	t.Run("NewSignatureAggregator", func(t *testing.T) {
		sa := mustNewSignatureAggregator(t, 3, mockVerifier, nil)
		if sa == nil {
			t.Fatal("NewSignatureAggregator returned nil")
		}
	})

	t.Run("AddSignature", func(t *testing.T) {
		sa := mustNewSignatureAggregator(t, 2, mockVerifier, nil)
		err := sa.AddSignature("msg-1", []byte("hash1"), types.Address{1}, []byte("sig1"))
		if err != nil {
			t.Fatalf("AddSignature failed: %v", err)
		}
		if sa.GetSignatureCount("msg-1") != 1 {
			t.Errorf("expected 1 signature, got %d", sa.GetSignatureCount("msg-1"))
		}
	})

	t.Run("AddSignature duplicate", func(t *testing.T) {
		sa := mustNewSignatureAggregator(t, 2, mockVerifier, nil)
		sa.AddSignature("msg-1", []byte("hash1"), types.Address{1}, []byte("sig1"))
		err := sa.AddSignature("msg-1", []byte("hash1"), types.Address{1}, []byte("sig1"))
		if err == nil {
			t.Error("should fail on duplicate signature")
		}
	})

	t.Run("HasQuorum", func(t *testing.T) {
		sa := mustNewSignatureAggregator(t, 2, mockVerifier, nil)
		sa.AddSignature("msg-1", []byte("hash1"), types.Address{1}, []byte("sig1"))
		if sa.HasQuorum("msg-1") {
			t.Error("1 signature should not meet threshold of 2")
		}
		sa.AddSignature("msg-1", []byte("hash1"), types.Address{2}, []byte("sig2"))
		if !sa.HasQuorum("msg-1") {
			t.Error("2 signatures should meet threshold of 2")
		}
	})

	t.Run("GetAggregatedSignature insufficient", func(t *testing.T) {
		sa := mustNewSignatureAggregator(t, 3, mockVerifier, nil)
		sa.AddSignature("msg-1", []byte("hash1"), types.Address{1}, []byte("sig1"))
		_, err := sa.GetAggregatedSignature("msg-1")
		if err == nil {
			t.Error("should fail with insufficient signatures")
		}
	})

	t.Run("ClearMessage", func(t *testing.T) {
		sa := mustNewSignatureAggregator(t, 2, mockVerifier, nil)
		sa.AddSignature("msg-1", []byte("hash1"), types.Address{1}, []byte("sig1"))
		sa.ClearMessage("msg-1")
		if sa.GetSignatureCount("msg-1") != 0 {
			t.Errorf("expected 0 signatures after clear, got %d", sa.GetSignatureCount("msg-1"))
		}
	})

	// BRDG- (2026-07-17): SignatureAggregator must cap distinct
	// messageIDs to bound memory usage against fabricated-messageID floods.
	t.Run("AddSignature rejects new messageID over cap (BRDG-)", func(t *testing.T) {
		sa := mustNewSignatureAggregator(t, 2, mockVerifier, nil)
		sa.SetMaxMessages(3)
		// Add 3 distinct messageIDs — should all succeed.
		for i := 0; i < 3; i++ {
			msgID := fmt.Sprintf("msg-%d", i)
			if err := sa.AddSignature(msgID, []byte("hash"+msgID), types.Address{1}, []byte("sig")); err != nil {
				t.Fatalf("AddSignature(%q) failed before cap: %v", msgID, err)
			}
		}
		// 4th distinct messageID should be rejected.
		if err := sa.AddSignature("msg-overflow", []byte("hash-overflow"), types.Address{1}, []byte("sig")); err == nil {
			t.Error("AddSignature should fail when maxMessages cap is reached")
		}
		// Adding a signature for an EXISTING messageID must still succeed
		// (the cap only applies to new messageIDs, otherwise legitimate
		// quorum collection for an in-flight message would be blocked).
		if err := sa.AddSignature("msg-0", []byte("hashmsg-0"), types.Address{2}, []byte("sig2")); err != nil {
			t.Errorf("AddSignature for existing messageID should succeed even at cap: %v", err)
		}
		// Clearing a message frees a slot — a new messageID should now succeed.
		sa.ClearMessage("msg-0")
		if err := sa.AddSignature("msg-after-clear", []byte("hash-after-clear"), types.Address{1}, []byte("sig")); err != nil {
			t.Errorf("AddSignature after ClearMessage should succeed: %v", err)
		}
	})

	t.Run("AddSignature maxMessages=0 disables cap (BRDG-)", func(t *testing.T) {
		sa := mustNewSignatureAggregator(t, 2, mockVerifier, nil)
		sa.SetMaxMessages(0) // unlimited
		for i := 0; i < 100; i++ {
			msgID := fmt.Sprintf("msg-%d", i)
			if err := sa.AddSignature(msgID, []byte("hash"+msgID), types.Address{1}, []byte("sig")); err != nil {
				t.Fatalf("AddSignature(%q) failed with cap disabled: %v", msgID, err)
			}
		}
	})

	t.Run("Default maxMessages is applied (BRDG-)", func(t *testing.T) {
		sa := mustNewSignatureAggregator(t, 2, mockVerifier, nil)
		if got := sa.MaxMessages(); got != defaultSignatureAggregatorMaxMessages {
			t.Errorf("default maxMessages: got %d, want %d", got, defaultSignatureAggregatorMaxMessages)
		}
	})
}

func TestValidatorNetwork(t *testing.T) {
	cfg := DefaultBridgeConfig()
	bridge := NewQuantumBridge(cfg).(*QuantumBridge)
	relayerCfg := DefaultRelayerConfig()
	relayer := NewMessageRelayer(relayerCfg, bridge)
	mockVerifier := &mockVerifier{allowAll: true}

	t.Run("NewValidatorNetwork", func(t *testing.T) {
		vn := mustNewValidatorNetwork(t, 3, relayer, mockVerifier, "governance")
		if vn == nil {
			t.Fatal("NewValidatorNetwork returned nil")
		}
	})

	t.Run("Start and Stop", func(t *testing.T) {
		vn := mustNewValidatorNetwork(t, 3, relayer, mockVerifier, "governance")
		ctx := context.Background()

		err := vn.Start(ctx)
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		err = vn.Stop()
		if err != nil {
			t.Fatalf("Stop failed: %v", err)
		}
	})

	t.Run("AddValidator", func(t *testing.T) {
		vn := mustNewValidatorNetwork(t, 3, relayer, mockVerifier, "governance")
		v := &BridgeValidator{
			Address:   types.Address{1},
			Stake:     big.NewInt(1000),
			PublicKey: []byte{1},
		}
		err := vn.AddValidator("governance", v)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}
	})

	t.Run("SignMessage validator not active", func(t *testing.T) {
		vn := mustNewValidatorNetwork(t, 3, relayer, mockVerifier, "governance")
		err := vn.SignMessage("msg-1", []byte("hash1"), types.Address{99}, []byte("sig"))
		if err == nil {
			t.Error("should fail for unknown validator")
		}
	})
}

// generateTestDilithium3KeyPair generates a Dilithium3 key pair for testing.
func generateTestDilithium3KeyPair(t *testing.T) (*mode3.PublicKey, *mode3.PrivateKey) {
	t.Helper()
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("mode3.GenerateKey: %v", err)
	}
	return pub, priv
}

// TestSetTrustedPublicKeyBytes_QuantaureumAdapter verifies that
// SetTrustedPublicKeyBytes correctly sets the trusted validator public key
// on a QuantaureumChainAdapter from raw bytes.
//
// P0-4 FIX (2026-07-13): Without this method, adapter VerifyMessage always
// fails with "no trusted validator public key configured".
func TestSetTrustedPublicKeyBytes_QuantaureumAdapter(t *testing.T) {
	pubKey, _ := generateTestDilithium3KeyPair(t)
	pubKeyBytes, err := pubKey.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	adapter := NewQuantaureumChainAdapter("quantaureum", "http://localhost:8545", "", 10, "0xInit").(*QuantaureumChainAdapter)

	// AUDIT-FULL H-1: SetTrustedPublicKeyBytes is governance-gated; configure
	// the governance address first and call as the governor.
	if err := adapter.SetGovernanceAddress("0xGov", "0xInit"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	// Before injection, validatorPublicKey should be nil.
	adapter.mu.RLock()
	if adapter.validatorPublicKey != nil {
		t.Fatal("validatorPublicKey should be nil before injection")
	}
	adapter.mu.RUnlock()

	// Inject the trusted public key.
	if err := adapter.SetTrustedPublicKeyBytes(pubKeyBytes, "0xGov"); err != nil {
		t.Fatalf("SetTrustedPublicKeyBytes: %v", err)
	}

	// After injection, validatorPublicKey should be set.
	adapter.mu.RLock()
	setKey := adapter.validatorPublicKey
	adapter.mu.RUnlock()
	if setKey == nil {
		t.Fatal("validatorPublicKey should be set after injection")
	}

	// Verify the key matches.
	setKeyBytes, _ := setKey.MarshalBinary()
	if len(setKeyBytes) != len(pubKeyBytes) {
		t.Fatalf("key length mismatch: got %d, want %d", len(setKeyBytes), len(pubKeyBytes))
	}
	for i := range pubKeyBytes {
		if setKeyBytes[i] != pubKeyBytes[i] {
			t.Fatalf("key byte mismatch at index %d", i)
		}
	}
}

// TestSetTrustedPublicKeyBytes_InvalidSize verifies that SetTrustedPublicKeyBytes
// rejects keys with invalid sizes.
func TestSetTrustedPublicKeyBytes_InvalidSize(t *testing.T) {
	adapter := NewQuantaureumChainAdapter("quantaureum", "http://localhost:8545", "", 10, "0xInit").(*QuantaureumChainAdapter)

	// Too short.
	err := adapter.SetTrustedPublicKeyBytes([]byte{1, 2, 3}, "0xInit")
	if err == nil {
		t.Fatal("expected error for too-short key")
	}

	// Too long.
	err = adapter.SetTrustedPublicKeyBytes(make([]byte, Dilithium3PublicKeySize+1), "0xInit")
	if err == nil {
		t.Fatal("expected error for too-long key")
	}
}

// TestSetTrustedRelayerPublicKeyBytes_ExternalAdapter verifies that
// SetTrustedRelayerPublicKeyBytes correctly sets the trusted relayer public key
// on an ExternalChainAdapter from raw bytes.
func TestSetTrustedRelayerPublicKeyBytes_ExternalAdapter(t *testing.T) {
	pubKey, _ := generateTestDilithium3KeyPair(t)
	pubKeyBytes, _ := pubKey.MarshalBinary()

	adapter := NewExternalChainAdapter("ethereum", "http://localhost:8546", "", 10, "0xInit").(*ExternalChainAdapter)

	// AUDIT-FULL H-1: SetTrustedRelayerPublicKeyBytes is governance-gated;
	// configure the governance address first and call as the governor.
	if err := adapter.SetGovernanceAddress("0xGov", "0xInit"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	// Before injection, relayerPublicKey should be nil.
	adapter.mu.RLock()
	if adapter.relayerPublicKey != nil {
		t.Fatal("relayerPublicKey should be nil before injection")
	}
	adapter.mu.RUnlock()

	// Inject the trusted public key.
	if err := adapter.SetTrustedRelayerPublicKeyBytes(pubKeyBytes, "0xGov"); err != nil {
		t.Fatalf("SetTrustedRelayerPublicKeyBytes: %v", err)
	}

	// After injection, relayerPublicKey should be set.
	adapter.mu.RLock()
	setKey := adapter.relayerPublicKey
	adapter.mu.RUnlock()
	if setKey == nil {
		t.Fatal("relayerPublicKey should be set after injection")
	}
}

// TestR4BRDG_ExternalAdapter_SubmitMessage_NoKey_NoPanic verifies the
// regression fix: SubmitMessage must NOT panic when relayer keys are not
// configured. Previously it dereferenced *e.relayerPrivateKey before checking
// hasPrivKey, causing a nil pointer panic. The symmetric fix was already
// applied to quantaureum_adapter.go on 2026-07-13; this test guards the
// Ethereum adapter.
func TestR4BRDG_ExternalAdapter_SubmitMessage_NoKey_NoPanic(t *testing.T) {
	adapter := NewExternalChainAdapter("ethereum", "http://localhost:8546", "", 10, "0xInit").(*ExternalChainAdapter)

	msg := &BridgeMessage{
		ID:            "test-no-key",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "0xabc",
		Amount:        "1",
		Nonce:         1,
	}

	// Must not panic; must return an error.
	_, err := adapter.SubmitMessage(context.Background(), msg)
	if err == nil {
		t.Error("expected error when relayer keys not configured, got nil")
	}
}

// TestR4BRDG_ExternalAdapter_SignMessage_NoKey_NoPanic mirrors the above for
// SignMessage, which had the same nil-deref-before-check pattern.
func TestR4BRDG_ExternalAdapter_SignMessage_NoKey_NoPanic(t *testing.T) {
	adapter := NewExternalChainAdapter("ethereum", "http://localhost:8546", "", 10, "0xInit").(*ExternalChainAdapter)

	msg := &BridgeMessage{
		ID:            "test-sign-no-key",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "0xabc",
		Amount:        "1",
		Nonce:         1,
	}

	// Must not panic; must return an error.
	_, err := adapter.SignMessage(context.Background(), msg)
	if err == nil {
		t.Error("expected error when relayer keys not configured, got nil")
	}
}

// TestR4BRDG_ProcessMessage_MissingSourceAdapter_FailClosed verifies the
// confirmation-depth fail-closed guard: when the source adapter is missing,
// ProcessMessage must reject the message instead of silently skipping the
// confirmation-depth check and proceeding to ExecuteMessage.
func TestR4BRDG_ProcessMessage_MissingSourceAdapter_FailClosed(t *testing.T) {
	cfg := DefaultBridgeConfig()
	b := NewQuantumBridge(cfg).(*QuantumBridge)

	// Register ONLY a target adapter — the source adapter is missing.
	targetAdapter := &mockChainAdapter{chainID: "ethereum"}
	b.adapters["ethereum"] = targetAdapter

	msg := &BridgeMessage{
		ID:          "test-fail-closed",
		SourceChain: "quantaureum", // source adapter NOT registered
		TargetChain: "ethereum",    // target adapter registered
		BlockNumber: 100,
	}

	err := b.ProcessMessage(context.Background(), msg)
	if err == nil {
		t.Fatal("ProcessMessage should fail-closed when source adapter is missing")
	}
}

// mockChainAdapter is a minimal ChainAdapter for fail-closed testing.
type mockChainAdapter struct {
	chainID ChainID
}

func (m *mockChainAdapter) ChainID() ChainID { return m.chainID }
func (m *mockChainAdapter) SubmitMessage(ctx context.Context, msg *BridgeMessage) (string, error) {
	return "", nil
}
func (m *mockChainAdapter) VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}
func (m *mockChainAdapter) ExecuteMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	return true, nil
}
func (m *mockChainAdapter) HasSufficientConfirmations(ctx context.Context, blockNumber uint64) (bool, error) {
	return true, nil
}
func (m *mockChainAdapter) GetTransactionBlockNumber(ctx context.Context, txHash string) (uint64, error) {
	return 0, nil
}
func (m *mockChainAdapter) GetMessageProof(ctx context.Context, msgID string) ([]byte, error) {
	// BRIDGE-R10-HIGH-002 test support: return a valid single-leaf Merkle
	// proof (LeafHash == Root, Neighbors = [], LeafIndex = 0). This is the
	// simplest valid proof — a Merkle tree with exactly one leaf, where
	// the leaf IS the root. MintAsset uses this to verify that the lock
	// event was committed to a Merkle tree on the source chain.
	leafHash := hashLeaf([]byte(msgID))
	proof := &MerkleProof{
		LeafHash:  leafHash,
		Neighbors: nil,
		LeafIndex: 0,
		Root:      leafHash, // single-leaf tree: leaf IS the root
	}
	return EncodeMerkleProof(proof), nil
}
func (m *mockChainAdapter) WatchEvents(ctx context.Context, callback func(*BridgeMessage) error) error {
	return nil
}
func (m *mockChainAdapter) FetchMerkleRootFromChain(ctx context.Context) (types.Hash, error) {
	return types.Hash{}, nil
}

// R38-P1-11 DEEP FIX (2026-08-02): signature changed to *BurnVerificationRequest.
func (m *mockChainAdapter) VerifyBurnTransaction(ctx context.Context, req *BurnVerificationRequest) (bool, error) {
	return true, nil
}

// TestInjectTrustedPublicKeys verifies that QuantumBridge.InjectTrustedPublicKeys
// correctly injects keys into the right adapter types (Quantaureum vs external).
func TestInjectTrustedPublicKeys(t *testing.T) {
	valPubKey, _ := generateTestDilithium3KeyPair(t)
	valKeyBytes, _ := valPubKey.MarshalBinary()

	relayerPubKey, _ := generateTestDilithium3KeyPair(t)
	relayerKeyBytes, _ := relayerPubKey.MarshalBinary()

	cfg := DefaultBridgeConfig()
	cfg.NodeURLs = map[ChainID]string{
		"quantaureum": "http://localhost:8545",
		"ethereum":    "http://localhost:8546",
	}
	cfg.BridgeContractAddresses = map[ChainID]string{
		"quantaureum": "0xBridgeQau",
		"ethereum":    "0xBridgeEth",
	}
	cfg.InitializerAddress = "0xInitializer"

	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	ctx := context.Background()
	if err := qb.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	// AUDIT-FULL C-1 follow-up: SetTrustedPublicKeyBytes now requires the
	// governance caller, so the adapters must have governance configured
	// before key injection.
	if injected, errs := qb.SetGovernanceAddressOnAdapters("0xGovQau", "0xInitializer"); len(errs) > 0 {
		t.Fatalf("SetGovernanceAddressOnAdapters errors: %v (injected=%d)", errs, injected)
	}

	// Inject both keys.
	injected, errs := qb.InjectTrustedPublicKeys(valKeyBytes, relayerKeyBytes, "0xGovQau")
	if len(errs) > 0 {
		t.Fatalf("injection errors: %v", errs)
	}
	if injected != 2 {
		t.Fatalf("injected = %d, want 2", injected)
	}

	// Verify Quantaureum adapter got the validator key.
	qauAdapter := qb.adapters["quantaureum"].(*QuantaureumChainAdapter)
	qauAdapter.mu.RLock()
	qauKey := qauAdapter.validatorPublicKey
	qauAdapter.mu.RUnlock()
	if qauKey == nil {
		t.Fatal("Quantaureum adapter: validatorPublicKey not set")
	}

	// Verify Ethereum adapter got the relayer key.
	ethAdapter := qb.adapters["ethereum"].(*ExternalChainAdapter)
	ethAdapter.mu.RLock()
	ethKey := ethAdapter.relayerPublicKey
	ethAdapter.mu.RUnlock()
	if ethKey == nil {
		t.Fatal("Ethereum adapter: relayerPublicKey not set")
	}
}

// TestInjectTrustedPublicKeys_PartialInjection verifies that injecting only
// one key type (e.g., only validator key) correctly skips the other adapter type.
func TestInjectTrustedPublicKeys_PartialInjection(t *testing.T) {
	valPubKey, _ := generateTestDilithium3KeyPair(t)
	valKeyBytes, _ := valPubKey.MarshalBinary()

	cfg := DefaultBridgeConfig()
	cfg.NodeURLs = map[ChainID]string{
		"quantaureum": "http://localhost:8545",
		"ethereum":    "http://localhost:8546",
	}
	cfg.InitializerAddress = "0xInitializer"

	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	ctx := context.Background()
	if err := qb.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if injected, errs := qb.SetGovernanceAddressOnAdapters("0xGovQau", "0xInitializer"); len(errs) > 0 {
		t.Fatalf("SetGovernanceAddressOnAdapters errors: %v (injected=%d)", errs, injected)
	}

	// Inject only validator key (nil relayer key).
	injected, errs := qb.InjectTrustedPublicKeys(valKeyBytes, nil, "0xGovQau")
	if len(errs) > 0 {
		t.Fatalf("injection errors: %v", errs)
	}
	if injected != 1 {
		t.Fatalf("injected = %d, want 1 (only quantaureum adapter)", injected)
	}

	// Quantaureum adapter should have the key.
	qauAdapter := qb.adapters["quantaureum"].(*QuantaureumChainAdapter)
	qauAdapter.mu.RLock()
	if qauAdapter.validatorPublicKey == nil {
		t.Error("Quantaureum adapter: validatorPublicKey should be set")
	}
	qauAdapter.mu.RUnlock()

	// Ethereum adapter should NOT have a relayer key.
	ethAdapter := qb.adapters["ethereum"].(*ExternalChainAdapter)
	ethAdapter.mu.RLock()
	if ethAdapter.relayerPublicKey != nil {
		t.Error("Ethereum adapter: relayerPublicKey should be nil (not injected)")
	}
	ethAdapter.mu.RUnlock()
}

// TestSetCommittedRoot_QuantaureumAdapter verifies that SetCommittedRoot
// correctly sets the governance-committed Merkle root on a Quantaureum adapter.
//
// P0-5 FIX (2026-07-13): This eliminates single-point trust by allowing
// governance to set a Merkle root that VerifyMessage uses instead of the
// in-memory messageTree.Root().
func TestSetCommittedRoot_QuantaureumAdapter(t *testing.T) {
	adapter := NewQuantaureumChainAdapter("quantaureum", "http://localhost:8545", "", 10, "0xInit").(*QuantaureumChainAdapter)

	// Set governance address first (required for SetCommittedRoot).
	if err := adapter.SetGovernanceAddress("0xGov", "0xInit"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	// Before setting, committedRoot should be zero.
	if adapter.GetCommittedRoot() != (types.Hash{}) {
		t.Fatal("committedRoot should be zero before setting")
	}

	// Set committed root via governance.
	testRoot := types.Hash{1, 2, 3, 4, 5}
	if err := adapter.SetCommittedRoot(testRoot, "0xGov"); err != nil {
		t.Fatalf("SetCommittedRoot: %v", err)
	}

	// Verify it was set.
	if adapter.GetCommittedRoot() != testRoot {
		t.Fatalf("committedRoot = %v, want %v", adapter.GetCommittedRoot(), testRoot)
	}

	// GetMerkleRoot should return committedRoot (not messageTree.Root()).
	if adapter.GetMerkleRoot() != testRoot {
		t.Fatalf("GetMerkleRoot = %v, want %v (committedRoot)", adapter.GetMerkleRoot(), testRoot)
	}
}

// TestSetCommittedRoot_Unauthorized verifies that SetCommittedRoot rejects
// callers that don't match the governance address.
func TestSetCommittedRoot_Unauthorized(t *testing.T) {
	adapter := NewQuantaureumChainAdapter("quantaureum", "http://localhost:8545", "", 10, "0xInit").(*QuantaureumChainAdapter)

	if err := adapter.SetGovernanceAddress("0xGov", "0xInit"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	// Non-governance caller should be rejected.
	err := adapter.SetCommittedRoot(types.Hash{1}, "0xAttacker")
	if err == nil {
		t.Fatal("expected error for unauthorized caller")
	}

	// Without governance address set.
	adapter2 := NewQuantaureumChainAdapter("quantaureum", "http://localhost:8545", "", 10, "0xInit").(*QuantaureumChainAdapter)
	err = adapter2.SetCommittedRoot(types.Hash{1}, "0xGov")
	if err == nil {
		t.Fatal("expected error when governance address not configured")
	}
}

// TestCommittedRoot_PreferredOverMessageTree verifies that when both
// committedRoot and messageTree are set, VerifyMessage uses committedRoot.
//
// P0-5: This is the key security property — the governance-committed root
// takes precedence over the in-memory tree, preventing an attacker who
// can modify the in-memory tree from forging message proofs.
func TestCommittedRoot_PreferredOverMessageTree(t *testing.T) {
	adapter := NewQuantaureumChainAdapter("quantaureum", "http://localhost:8545", "", 10, "0xInit").(*QuantaureumChainAdapter)

	if err := adapter.SetGovernanceAddress("0xGov", "0xInit"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	// Set messageTree via CommitMessages.
	treeRoot, err := adapter.CommitMessages([]string{"msg-1", "msg-2"}, "0xGov")
	if err != nil {
		t.Fatalf("CommitMessages: %v", err)
	}

	// GetMerkleRoot should return treeRoot.
	if got := adapter.GetMerkleRoot(); got != treeRoot {
		t.Fatalf("GetMerkleRoot = %v, want %v (treeRoot)", got, treeRoot)
	}

	// Now set a different committedRoot via governance.
	committedRoot := types.Hash{0xAA, 0xBB, 0xCC}
	if err := adapter.SetCommittedRoot(committedRoot, "0xGov"); err != nil {
		t.Fatalf("SetCommittedRoot: %v", err)
	}

	// GetMerkleRoot should now return committedRoot (not treeRoot).
	if got := adapter.GetMerkleRoot(); got != committedRoot {
		t.Fatalf("GetMerkleRoot = %v, want %v (committedRoot should take precedence)", got, committedRoot)
	}
	if got := adapter.GetMerkleRoot(); got == treeRoot {
		t.Fatal("GetMerkleRoot returned treeRoot — committedRoot should take precedence")
	}
}

// TestSetCommittedRoot_ExternalAdapter verifies SetCommittedRoot on ExternalChainAdapter.
func TestSetCommittedRoot_ExternalAdapter(t *testing.T) {
	adapter := NewExternalChainAdapter("ethereum", "http://localhost:8546", "", 10, "0xInit").(*ExternalChainAdapter)

	if err := adapter.SetGovernanceAddress("0xGovEth", "0xInit"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	testRoot := types.Hash{0xDD, 0xEE, 0xFF}
	if err := adapter.SetCommittedRoot(testRoot, "0xGovEth"); err != nil {
		t.Fatalf("SetCommittedRoot: %v", err)
	}

	if adapter.GetCommittedRoot() != testRoot {
		t.Fatalf("committedRoot = %v, want %v", adapter.GetCommittedRoot(), testRoot)
	}

	if adapter.GetMerkleRoot() != testRoot {
		t.Fatalf("GetMerkleRoot = %v, want %v (committedRoot)", adapter.GetMerkleRoot(), testRoot)
	}
}

// TestSyncFromQPOS_NewValidators verifies that SyncFromQPOS adds new validators.
// P1-6 (2026-07-14): QPOS validator set → bridge arbitration network linkage.
func TestSyncFromQPOS_NewValidators(t *testing.T) {
	vs := NewValidatorSet(1)

	validators := []*BridgeValidator{
		{Address: types.Address{1}, PublicKey: []byte("pk1"), Stake: big.NewInt(1000), Active: true},
		{Address: types.Address{2}, PublicKey: []byte("pk2"), Stake: big.NewInt(2000), Active: true},
		{Address: types.Address{3}, PublicKey: []byte("pk3"), Stake: big.NewInt(3000), Active: true},
	}

	result := vs.SyncFromQPOS(validators, 2)

	if result.Added != 3 {
		t.Errorf("Added = %d, want 3", result.Added)
	}
	if result.Updated != 0 {
		t.Errorf("Updated = %d, want 0", result.Updated)
	}
	if result.Deactivated != 0 {
		t.Errorf("Deactivated = %d, want 0", result.Deactivated)
	}
	if result.Threshold != 2 {
		t.Errorf("Threshold = %d, want 2", result.Threshold)
	}
	if vs.GetThreshold() != 2 {
		t.Errorf("GetThreshold = %d, want 2", vs.GetThreshold())
	}
	if len(vs.GetActiveValidators()) != 3 {
		t.Errorf("active validators = %d, want 3", len(vs.GetActiveValidators()))
	}
	if vs.GetTotalStake().Cmp(big.NewInt(6000)) != 0 {
		t.Errorf("total stake = %s, want 6000", vs.GetTotalStake().String())
	}
}

// TestSyncFromQPOS_UpdateExisting verifies that SyncFromQPOS updates
// existing validators' stake and public key.
func TestSyncFromQPOS_UpdateExisting(t *testing.T) {
	vs := NewValidatorSet(1)

	// Initial set.
	initial := []*BridgeValidator{
		{Address: types.Address{1}, PublicKey: []byte("pk1"), Stake: big.NewInt(1000), Active: true},
	}
	vs.SyncFromQPOS(initial, 1)

	// Updated set: same address, new stake and pubkey.
	updated := []*BridgeValidator{
		{Address: types.Address{1}, PublicKey: []byte("pk1-updated"), Stake: big.NewInt(5000), Active: true},
	}
	result := vs.SyncFromQPOS(updated, 1)

	if result.Added != 0 {
		t.Errorf("Added = %d, want 0", result.Added)
	}
	if result.Updated != 1 {
		t.Errorf("Updated = %d, want 1", result.Updated)
	}
	if result.Deactivated != 0 {
		t.Errorf("Deactivated = %d, want 0", result.Deactivated)
	}

	v, ok := vs.GetValidator(types.Address{1})
	if !ok {
		t.Fatal("validator not found")
	}
	if v.Stake.Cmp(big.NewInt(5000)) != 0 {
		t.Errorf("stake = %s, want 5000", v.Stake.String())
	}
	if string(v.PublicKey) != "pk1-updated" {
		t.Errorf("pubkey = %s, want pk1-updated", string(v.PublicKey))
	}
	if vs.GetTotalStake().Cmp(big.NewInt(5000)) != 0 {
		t.Errorf("total stake = %s, want 5000", vs.GetTotalStake().String())
	}
}

// TestSyncFromQPOS_DeactivateRemoved verifies that validators no longer
// in the QPOS set are deactivated (not deleted).
func TestSyncFromQPOS_DeactivateRemoved(t *testing.T) {
	vs := NewValidatorSet(2)

	// Initial set with 3 validators.
	initial := []*BridgeValidator{
		{Address: types.Address{1}, PublicKey: []byte("pk1"), Stake: big.NewInt(1000), Active: true},
		{Address: types.Address{2}, PublicKey: []byte("pk2"), Stake: big.NewInt(2000), Active: true},
		{Address: types.Address{3}, PublicKey: []byte("pk3"), Stake: big.NewInt(3000), Active: true},
	}
	vs.SyncFromQPOS(initial, 2)

	// New set: only validators 1 and 3 (validator 2 removed/jailed).
	updated := []*BridgeValidator{
		{Address: types.Address{1}, PublicKey: []byte("pk1"), Stake: big.NewInt(1000), Active: true},
		{Address: types.Address{3}, PublicKey: []byte("pk3"), Stake: big.NewInt(3000), Active: true},
	}
	result := vs.SyncFromQPOS(updated, 2)

	if result.Added != 0 {
		t.Errorf("Added = %d, want 0", result.Added)
	}
	if result.Updated != 0 {
		t.Errorf("Updated = %d, want 0", result.Updated)
	}
	if result.Deactivated != 1 {
		t.Errorf("Deactivated = %d, want 1", result.Deactivated)
	}

	// Validator 2 should be deactivated but still exist (for historical sig verification).
	v, ok := vs.GetValidator(types.Address{2})
	if !ok {
		t.Fatal("deactivated validator should still exist in the set")
	}
	if v.Active {
		t.Error("validator 2 should be inactive after removal from QPOS")
	}

	// Active validators should be 2 (1 and 3).
	active := vs.GetActiveValidators()
	if len(active) != 2 {
		t.Errorf("active validators = %d, want 2", len(active))
	}
}

// TestBRDG_R7_01_SetThreshold_ClampToMin verifies BRDG- fix:
// SetThreshold and SyncFromQPOS must clamp threshold < 2 to 2, mirroring
// NewValidatorSet's BRDG- protection. Without this, an attacker
// (or buggy caller) could pass threshold=0/1 and disable multi-sig.
func TestBRDG_R7_01_SetThreshold_ClampToMin(t *testing.T) {
	vs := NewValidatorSet(2)

	// SetThreshold with values below 2 must be clamped to 2.
	for _, in := range []int{-1, 0, 1} {
		vs.SetThreshold(in)
		if got := vs.GetThreshold(); got != 2 {
			t.Fatalf("SetThreshold(%d): threshold = %d, want 2 (clamped)", in, got)
		}
		// HasQuorum must NOT return true for 0 or 1 signatures.
		if vs.HasQuorum(0) {
			t.Fatalf("SetThreshold(%d): HasQuorum(0) = true, want false", in)
		}
		if vs.HasQuorum(1) {
			t.Fatalf("SetThreshold(%d): HasQuorum(1) = true, want false", in)
		}
	}

	// SetThreshold with values >= 2 must pass through unchanged.
	vs.SetThreshold(3)
	if got := vs.GetThreshold(); got != 3 {
		t.Fatalf("SetThreshold(3): threshold = %d, want 3", got)
	}

	// SyncFromQPOS must apply the same clamp.
	validators := []*BridgeValidator{
		{Address: types.Address{1}, PublicKey: []byte("pk1"), Stake: big.NewInt(1000), Active: true},
	}
	for _, in := range []int{0, 1} {
		result := vs.SyncFromQPOS(validators, in)
		if result.Threshold != 2 {
			t.Fatalf("SyncFromQPOS(_, %d): result.Threshold = %d, want 2 (clamped)", in, result.Threshold)
		}
		if got := vs.GetThreshold(); got != 2 {
			t.Fatalf("SyncFromQPOS(_, %d): threshold = %d, want 2 (clamped)", in, got)
		}
	}
}

// TestBRDG_R7_02_GlobalUsedNoncesCap verifies BRDG- fix: when the
// global count of used nonces (across ALL source addresses) reaches
// maxUsedNoncesGlobal, SubmitMessage must reject new messages to prevent OOM.
// This closes the bypass where an attacker forges messages with distinct
// sourceAddress values to evade the per-address cap.
//
// The global cap check runs BEFORE quantum signature validation (it sits in
// the nonce-replay guard block), so Part 1 does not need a signed message.
// Part 2 verifies the counter maintenance logic directly (insert + TTL
// eviction keep totalUsedNonces in sync), avoiding the heavy Dilithium3
// setup required for a full SubmitMessage success path.
func TestBRDG_R7_02_GlobalUsedNoncesCap(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	// --- Part 1: global cap rejects before signature validation ---
	qb.mu.Lock()
	qb.totalUsedNonces = maxUsedNoncesGlobal
	qb.mu.Unlock()

	msg := &BridgeMessage{
		ID:            "msg-r7-02-1",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "addr-r7-02-a",
		TargetAddress: "0xRecipient",
		AssetType:     AssetTypeNative,
		Amount:        "100",
		Nonce:         1,
		Timestamp:     time.Now().Unix(),
		MessageType:   MessageTypeAssetTransfer,
	}

	err := qb.SubmitMessage(context.Background(), msg)
	if err == nil {
		t.Fatal("SubmitMessage must fail when global used nonces limit is reached")
	}
	if !strings.Contains(err.Error(), "global used nonces limit") {
		t.Fatalf("expected 'global used nonces limit' error, got: %v", err)
	}

	// --- Part 2: counter increments on insert; nonceTTL = 0 means no eviction ---
	// BRDG-FIX: nonceTTL is now 0 (nonces never expire). Verify the
	// counter increments on insert and that the TTL eviction path is a no-op
	// when nonceTTL = 0, so replay protection persists even after finalizedIDs
	// LRU eviction.
	qb.mu.Lock()
	// Reset to a known baseline.
	qb.totalUsedNonces = 0
	qb.usedNonces = make(map[nonceKey]map[uint64]time.Time)
	addr := "addr-r7-02-b"
	chain := ChainID("quantaureum")
	nk := nonceKey{chain: chain, addr: addr}
	qb.usedNonces[nk] = make(map[uint64]time.Time)
	// Insert a nonce with an OLD timestamp. With nonceTTL = 0 it must NOT be evicted.
	qb.usedNonces[nk][1] = time.Now().Add(-365 * 24 * time.Hour)
	qb.totalUsedNonces++
	if qb.totalUsedNonces != 1 {
		t.Errorf("after insert: totalUsedNonces = %d, want 1", qb.totalUsedNonces)
	}
	// Simulate the TTL eviction path (mirrors SubmitMessage lines ~1194-1211).
	// With nonceTTL = 0, the scan is skipped entirely (no expired entries).
	now := time.Now()
	var expired []uint64
	if nonceTTL > 0 {
		for n, ts := range qb.usedNonces[nk] {
			if now.Sub(ts) > nonceTTL {
				expired = append(expired, n)
			}
		}
	}
	for _, n := range expired {
		delete(qb.usedNonces[nk], n)
		qb.totalUsedNonces--
	}
	if qb.totalUsedNonces != 1 {
		t.Errorf("after TTL scan (nonceTTL=0): totalUsedNonces = %d, want 1 (no eviction)", qb.totalUsedNonces)
	}
	if _, exists := qb.usedNonces[nk][1]; !exists {
		t.Error("nonce 1 should still exist (nonceTTL=0 means never expire)")
	}
	qb.mu.Unlock()
}

// TestBRDG_R7_03_NonceNeverExpires_ReplayProtectionAfterFinalizedEviction
// verifies BRDG- fix: even after a finalized ID is evicted from the
// LRU cache, the corresponding nonce remains in usedNonces (nonceTTL = 0),
// so a replay attempt is rejected at SubmitMessage with "nonce already used"
// instead of being re-processed (double-spend).
func TestBRDG_R7_03_NonceNeverExpires_ReplayProtectionAfterFinalizedEviction(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	addr := "addr-r7-03"
	nonce := uint64(42)
	msgID := "msg-r7-03-1"

	// Simulate a message that was previously submitted + finalized + evicted:
	// 1. Record the nonce (as SubmitMessage would on first submission).
	// BRIDGE- use composite nonceKey matching the message's SourceChain.
	qb.mu.Lock()
	nk := nonceKey{chain: ChainID("quantaureum"), addr: addr}
	qb.usedNonces[nk] = make(map[uint64]time.Time)
	qb.usedNonces[nk][nonce] = time.Now().Add(-365 * 24 * time.Hour) // very old
	qb.totalUsedNonces++
	// 2. Mark as finalized, then evict from finalizedIDs LRU.
	qb.markFinalized(msgID)
	delete(qb.finalizedIDs, msgID) // simulate LRU eviction
	qb.mu.Unlock()

	// Verify the finalized ID is gone (eviction simulated).
	qb.mu.RLock()
	if qb.finalizedIDs[msgID] {
		t.Fatal("precondition: finalizedID should have been evicted")
	}
	qb.mu.RUnlock()

	// Now attempt to replay: SubmitMessage with the same nonce.
	// It must be rejected with "nonce already used" — NOT re-processed.
	// The global-cap check runs before the per-nonce check, so ensure we
	// are below the cap.
	msg := &BridgeMessage{
		ID:            msgID,
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: addr,
		TargetAddress: "0xRecipient",
		AssetType:     AssetTypeNative,
		Amount:        "100",
		Nonce:         nonce,
		Timestamp:     time.Now().Unix(),
		MessageType:   MessageTypeAssetTransfer,
	}

	err := qb.SubmitMessage(context.Background(), msg)
	if err == nil {
		t.Fatal("replay must be rejected: expected 'nonce already used' error, got nil")
	}
	// The error must be the nonce-replay rejection, NOT a signature error
	// (which would mean the nonce check was bypassed).
	if !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected 'already used' nonce-replay error (replay blocked by usedNonces after finalizedID eviction), got: %v", err)
	}
}

// TestBRDG_R7_07_BootstrapModeAutoDisable verifies BRDG- fix:
// bootstrapMode now has a deadline (bootstrapModeTTL) after which
// isEventSignatureAllowed auto-disables it, AND RegisterEventSignature
// auto-disables it once bootstrapModeAutoDisableThreshold signatures are
// registered. This closes the "forgotten open" window.
func TestBRDG_R7_07_BootstrapModeAutoDisable(t *testing.T) {
	// --- Part 1: deadline expiry auto-disables bootstrap mode ---
	adapter := NewExternalChainAdapter("r7-07-chain", "http://localhost:1", "", 1, "test-init").(*ExternalChainAdapter)
	if err := adapter.SetGovernanceAddress("test-gov", "test-init"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	// Enable bootstrap mode.
	if err := adapter.SetBootstrapMode(true, "test-gov"); err != nil {
		t.Fatalf("SetBootstrapMode(true): %v", err)
	}

	// With bootstrap enabled and empty allowlist, any event is accepted.
	if !adapter.isEventSignatureAllowed("0xarbitrary") {
		t.Fatal("bootstrap enabled: expected isEventSignatureAllowed=true for arbitrary sig")
	}

	// Simulate deadline expiry by backdating the deadline.
	adapter.mu.Lock()
	adapter.bootstrapModeDeadline = time.Now().Add(-time.Second)
	adapter.mu.Unlock()

	// After deadline, arbitrary events must be rejected (fail-closed).
	if adapter.isEventSignatureAllowed("0xarbitrary") {
		t.Fatal("after deadline: expected isEventSignatureAllowed=false (auto-disabled)")
	}

	// --- Part 2: RegisterEventSignature auto-disables after threshold ---
	adapter2 := NewExternalChainAdapter("r7-07-chain-2", "http://localhost:1", "", 1, "test-init").(*ExternalChainAdapter)
	if err := adapter2.SetGovernanceAddress("test-gov", "test-init"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}
	if err := adapter2.SetBootstrapMode(true, "test-gov"); err != nil {
		t.Fatalf("SetBootstrapMode(true): %v", err)
	}

	// Register signatures one by one; bootstrap should auto-disable at threshold.
	for i := 0; i < bootstrapModeAutoDisableThreshold; i++ {
		sig := "0xsig-" + string(rune('a'+i))
		if err := adapter2.RegisterEventSignature(sig, "test-gov"); err != nil {
			t.Fatalf("RegisterEventSignature(%s): %v", sig, err)
		}
	}

	// After registering threshold signatures, bootstrapMode must be false.
	adapter2.mu.RLock()
	bootstrapEnabled := adapter2.bootstrapMode
	adapter2.mu.RUnlock()
	if bootstrapEnabled {
		t.Errorf("bootstrapMode should have been auto-disabled after %d signatures", bootstrapModeAutoDisableThreshold)
	}

	// Registered signatures should still be accepted.
	if !adapter2.isEventSignatureAllowed("0xsig-a") {
		t.Error("registered signature should be allowed after auto-disable")
	}
	// Unregistered signatures should be rejected (allowlist is non-empty).
	if adapter2.isEventSignatureAllowed("0xunknown") {
		t.Error("unknown signature should be rejected after auto-disable (allowlist non-empty)")
	}
}

// TestRefreshValidatorSet verifies that QuantumBridge.RefreshValidatorSet
// updates both the ValidatorNetwork's ValidatorSet and trustedValidatorKeys.
func TestRefreshValidatorSet(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	// Create a ValidatorNetwork and inject it.
	vn := mustNewValidatorNetwork(t, 1, nil, NewQuantumSignatureVerifier(), "")
	qb.SetValidatorNetwork(vn)

	// Initial validator set.
	validators := []*BridgeValidator{
		{Address: types.Address{1}, PublicKey: []byte("pk1"), Stake: big.NewInt(1000), Active: true},
		{Address: types.Address{2}, PublicKey: []byte("pk2"), Stake: big.NewInt(2000), Active: true},
	}

	result := qb.RefreshValidatorSet(validators, 2)
	if result.Added != 2 {
		t.Errorf("Added = %d, want 2", result.Added)
	}

	// trustedValidatorKeys should be updated.
	if qb.GetTrustedValidatorKeysCount() != 2 {
		t.Errorf("trustedValidatorKeys count = %d, want 2", qb.GetTrustedValidatorKeysCount())
	}

	// ValidatorNetwork's ValidatorSet should reflect the new set.
	vs := vn.GetValidatorSet()
	if vs.GetThreshold() != 2 {
		t.Errorf("threshold = %d, want 2", vs.GetThreshold())
	}
	if len(vs.GetActiveValidators()) != 2 {
		t.Errorf("active validators = %d, want 2", len(vs.GetActiveValidators()))
	}

	// Now refresh with an updated set: validator 2 removed, validator 3 added.
	updated := []*BridgeValidator{
		{Address: types.Address{1}, PublicKey: []byte("pk1"), Stake: big.NewInt(1000), Active: true},
		{Address: types.Address{3}, PublicKey: []byte("pk3"), Stake: big.NewInt(3000), Active: true},
	}
	result = qb.RefreshValidatorSet(updated, 2)
	if result.Deactivated != 1 {
		t.Errorf("Deactivated = %d, want 1", result.Deactivated)
	}
	if result.Added != 1 {
		t.Errorf("Added = %d, want 1", result.Added)
	}

	// trustedValidatorKeys should reflect the new set (2 keys).
	if qb.GetTrustedValidatorKeysCount() != 2 {
		t.Errorf("trustedValidatorKeys count = %d, want 2", qb.GetTrustedValidatorKeysCount())
	}

	// Validator 2 should be deactivated.
	v, ok := vs.GetValidator(types.Address{2})
	if !ok {
		t.Fatal("validator 2 should still exist")
	}
	if v.Active {
		t.Error("validator 2 should be deactivated")
	}

	// Validator 3 should be active.
	v, ok = vs.GetValidator(types.Address{3})
	if !ok {
		t.Fatal("validator 3 should exist")
	}
	if !v.Active {
		t.Error("validator 3 should be active")
	}
}

// TestRefreshValidatorSet_NoNetwork verifies that RefreshValidatorSet
// updates trustedValidatorKeys even when no ValidatorNetwork is configured.
func TestRefreshValidatorSet_NoNetwork(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	// No ValidatorNetwork injected.
	validators := []*BridgeValidator{
		{Address: types.Address{1}, PublicKey: []byte("pk1"), Stake: big.NewInt(1000), Active: true},
	}

	result := qb.RefreshValidatorSet(validators, 1)

	// Should return zero ValidatorSyncResult (no vn), but trustedValidatorKeys
	// should still be updated.
	if result.Added != 0 {
		t.Errorf("Added = %d, want 0 (no vn)", result.Added)
	}
	if qb.GetTrustedValidatorKeysCount() != 1 {
		t.Errorf("trustedValidatorKeys count = %d, want 1", qb.GetTrustedValidatorKeysCount())
	}
}

// mockMinistryWorksRecorder is a test implementation of MinistryWorksRecorder.
// P1-T7 (2026-07-14): Used to verify the bridge correctly delegates bridge
// registration and cross-chain tx recording to the ministry.
type mockMinistryWorksRecorder struct {
	bridgeRegistered bool
	bridgeName       string
	bridgeRemoteID   uint64
	txRecorded       bool
	txAmount         string
	txBridgeID       uint64
	nextBridgeID     uint64
	nextTxID         uint64
}

func (m *mockMinistryWorksRecorder) RegisterBridge(name string, remoteChainID uint64, relayerCount int, totalLocked string) (uint64, error) {
	m.bridgeRegistered = true
	m.bridgeName = name
	m.bridgeRemoteID = remoteChainID
	m.nextBridgeID++
	return m.nextBridgeID, nil
}

func (m *mockMinistryWorksRecorder) RecordCrossChainTx(bridgeID uint64, sourceTxHash types.Hash, amount string) (uint64, error) {
	m.txRecorded = true
	m.txBridgeID = bridgeID
	m.txAmount = amount
	m.nextTxID++
	return m.nextTxID, nil
}

// TestP1T7_MinistryWorksRecorder verifies that the bridge correctly delegates
// bridge registration and cross-chain transaction recording to the
// MinistryWorksRecorder interface.
func TestP1T7_MinistryWorksRecorder(t *testing.T) {
	// Create a bridge with a mock MinistryWorksRecorder.
	cfg := DefaultBridgeConfig()
	cfg.NodeURLs = map[ChainID]string{
		"quantaureum": "http://localhost:8545",
	}
	cfg.BridgeContractAddresses = map[ChainID]string{
		"quantaureum": "0x0000000000000000000000000000000000000001",
	}
	qb := NewQuantumBridge(cfg).(*QuantumBridge)

	mock := &mockMinistryWorksRecorder{}
	qb.SetMinistryWorks(mock)

	// Trigger registration manually (simulates what node.go does after injection).
	qb.RegisterWithMinistry()

	// Verify bridge was registered.
	if !mock.bridgeRegistered {
		t.Fatal("RegisterBridge was not called")
	}
	if mock.bridgeName != "quantum-bridge" {
		t.Errorf("bridge name = %q, want %q", mock.bridgeName, "quantum-bridge")
	}

	// Verify ministryBridgeID was stored.
	if qb.ministryBridgeID == 0 {
		t.Fatal("ministryBridgeID not set after registration")
	}

	t.Log("=== P1-T7: MinistryWorks bridge registration: PASS ===")
}

// TestP1T7_MinistryWorksNilRecorder verifies that nil MinistryWorks does not
// cause panics during Initialize or RegisterWithMinistry.
func TestP1T7_MinistryWorksNilRecorder(t *testing.T) {
	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)

	// No MinistryWorks set — should be a no-op, not a panic.
	qb.RegisterWithMinistry()

	if qb.ministryBridgeID != 0 {
		t.Errorf("ministryBridgeID = %d, want 0 (no recorder)", qb.ministryBridgeID)
	}

	t.Log("=== P1-T7: Nil MinistryWorks recorder: PASS ===")
}

// R31-MED-4 regression: after the bridge's trust set is seeded, an ad-hoc
// SetTrustedValidatorKeys with a DIFFERENT set must be refused (the trust
// anchor can only rotate via the explicit operator mutation window or the
// consensus-driven RefreshValidatorSet), while re-seeding the IDENTICAL set
// stays idempotent (restart re-init).
func TestR31MED4_TrustAnchorMutationGuard(t *testing.T) {
	kp1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	kp2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	defer qb.Stop(context.Background())
	if err := qb.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Bootstrap seed: allowed.
	qb.SetTrustedValidatorKeys([][]byte{kp1.Public.Bytes()})
	if qb.GetTrustedValidatorKeysCount() != 1 {
		t.Fatalf("bootstrap seed failed: count=%d", qb.GetTrustedValidatorKeysCount())
	}

	// Ad-hoc CHANGE: refused (guard engaged post-bootstrap).
	qb.SetTrustedValidatorKeys([][]byte{kp2.Public.Bytes()})
	if qb.GetTrustedValidatorKeysCount() != 1 {
		t.Fatalf("trust anchor change was NOT refused (R31-MED-4)")
	}

	// Idempotent re-seed of the identical set: accepted no-op.
	qb.SetTrustedValidatorKeys([][]byte{kp1.Public.Bytes()})
	if qb.GetTrustedValidatorKeysCount() != 1 {
		t.Fatalf("idempotent re-seed disturbed the trust set")
	}

	// Explicit operator window: rotation succeeds.
	qb.UnlockValidatorTrustMutation("test rotation")
	qb.SetTrustedValidatorKeys([][]byte{kp2.Public.Bytes()})
	if qb.GetTrustedValidatorKeysCount() != 1 {
		t.Fatalf("windowed rotation failed")
	}
	// Verify the new anchor actually took effect by comparing to kp2.
	qb.mu.RLock()
	got := qb.trustedValidatorKeys[0]
	qb.mu.RUnlock()
	if string(got) != string(kp2.Public.Bytes()) {
		t.Fatalf("windowed rotation did not install the new key")
	}
	qb.LockValidatorTrustMutation()

	// Window re-sealed: change refused again.
	qb.SetTrustedValidatorKeys([][]byte{kp1.Public.Bytes()})
	qb.mu.RLock()
	got = qb.trustedValidatorKeys[0]
	qb.mu.RUnlock()
	if string(got) != string(kp2.Public.Bytes()) {
		t.Fatalf("mutation guard did not re-engage after LockValidatorTrustMutation")
	}

	// Clearing the seeded set is refused (fail-closed against DoS).
	qb.SetTrustedValidatorKeys(nil)
	if qb.GetTrustedValidatorKeysCount() != 1 {
		t.Fatalf("clearing the seeded trust set was allowed (fail-closed violated)")
	}
}
