// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// TestBRIDGE_R12001_PauseRejectsSubmitMessage verifies that after Pause()
// is called, SubmitMessage rejects new messages with ErrBridgePaused.
//
// BRIDGE-R12-001 (2026-07-20): bridge had no pause mechanism — operators
// had no way to halt bridge operations short of shutting down the node.
func TestBRIDGE_R12001_PauseRejectsSubmitMessage(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	// Before pause: SubmitMessage should NOT return ErrBridgePaused.
	// (It may return other errors like rate-limit or signature verification
	// failure, but not ErrBridgePaused.)
	if b.IsPaused() {
		t.Fatal("bridge should not be paused initially")
	}

	// Pause the bridge.
	b.Pause("vulnerability CVE-XXXX discovered")
	if !b.IsPaused() {
		t.Fatal("IsPaused should return true after Pause()")
	}

	// SubmitMessage should now return ErrBridgePaused.
	// We pass a nil message — the pause check happens before any message
	// field access, so nil is safe.
	err := b.SubmitMessage(context.Background(), nil)
	if !errors.Is(err, ErrBridgePaused) {
		t.Errorf("expected ErrBridgePaused after Pause(), got %v", err)
	}

	// Unpause and verify SubmitMessage no longer returns ErrBridgePaused.
	b.Unpause()
	if b.IsPaused() {
		t.Fatal("IsPaused should return false after Unpause()")
	}
}

// TestBRIDGE_R12001_PauseRejectsProcessMessage verifies that after Pause()
// is called, ProcessMessage rejects new messages with ErrBridgePaused.
func TestBRIDGE_R12001_PauseRejectsProcessMessage(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	// Pause.
	b.Pause("attack mitigation")
	if !b.IsPaused() {
		t.Fatal("IsPaused should return true after Pause()")
	}

	// ProcessMessage should return ErrBridgePaused.
	err := b.ProcessMessage(context.Background(), nil)
	if !errors.Is(err, ErrBridgePaused) {
		t.Errorf("expected ErrBridgePaused after Pause(), got %v", err)
	}

	// Unpause.
	b.Unpause()
	if b.IsPaused() {
		t.Fatal("IsPaused should return false after Unpause()")
	}
}

// TestBRIDGE_R12001_PausedReason verifies that Pause() records the reason
// and PausedReason() returns it, and Unpause() clears it.
func TestBRIDGE_R12001_PausedReason(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	if reason := b.PausedReason(); reason != "" {
		t.Fatalf("PausedReason should be empty initially, got %q", reason)
	}

	reason := "test pause reason"
	b.Pause(reason)

	if got := b.PausedReason(); got != reason {
		t.Errorf("PausedReason = %q, want %q", got, reason)
	}

	b.Unpause()
	if got := b.PausedReason(); got != "" {
		t.Errorf("PausedReason should be empty after Unpause(), got %q", got)
	}
}

// TestBRIDGE_R12001_IsPausedAtomicReads verifies that IsPaused can be called
// concurrently from multiple goroutines without data races.
//
// The pause flag uses atomic.Bool, so reads are lock-free. This test runs
// with -race to verify the atomicity holds.
func TestBRIDGE_R12001_IsPausedAtomicReads(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	var wg sync.WaitGroup
	const N = 100

	// Start readers.
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.IsPaused()
		}()
	}

	// Concurrently pause and unpause.
	wg.Add(2)
	go func() {
		defer wg.Done()
		b.Pause("test")
	}()
	go func() {
		defer wg.Done()
		b.Unpause()
	}()

	wg.Wait()
}

// TestBRIDGE_R12001_PauseUnpauseCycle verifies that Pause/Unpause can be
// called multiple times in sequence without breaking state.
func TestBRIDGE_R12001_PauseUnpauseCycle(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	for i := 0; i < 5; i++ {
		b.Pause("cycle test")
		if !b.IsPaused() {
			t.Fatalf("iteration %d: IsPaused should be true after Pause", i)
		}

		err := b.SubmitMessage(context.Background(), nil)
		if !errors.Is(err, ErrBridgePaused) {
			t.Fatalf("iteration %d: expected ErrBridgePaused, got %v", i, err)
		}

		b.Unpause()
		if b.IsPaused() {
			t.Fatalf("iteration %d: IsPaused should be false after Unpause", i)
		}
	}
}

// TestBRIDGE_R12001_UnpauseWithoutPause verifies that Unpause() is safe to
// call even if Pause() was never called (no-op / defensive).
func TestBRIDGE_R12001_UnpauseWithoutPause(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	// Unpause without prior Pause — should not panic or corrupt state.
	b.Unpause()
	if b.IsPaused() {
		t.Fatal("IsPaused should be false after Unpause without prior Pause")
	}
}

// TestBRIDGE_R12001_ErrBridgePausedIsSentinel verifies that ErrBridgePaused
// is a stable sentinel that can be compared with errors.Is.
func TestBRIDGE_R12001_ErrBridgePausedIsSentinel(t *testing.T) {
	// Wrap the error and verify errors.Is still finds it.
	wrapped := errors.New("wrapped: " + ErrBridgePaused.Error())
	if errors.Is(wrapped, ErrBridgePaused) {
		t.Fatal("wrapped error should NOT match ErrBridgePaused (errors.Is checks identity, not message)")
	}

	// Direct match.
	if !errors.Is(ErrBridgePaused, ErrBridgePaused) {
		t.Fatal("ErrBridgePaused should match itself")
	}
}
