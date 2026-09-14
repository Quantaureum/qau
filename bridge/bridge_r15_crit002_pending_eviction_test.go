// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
//
// BRIDGE-R15-CRIT-002 (2026-07-22) regression tests: PENDING message
// eviction must mark the corresponding AssetLock as Failed and trigger
// the refund flow. Previously, evicting a PENDING message silently
// dropped it from memory while the user's locked assets remained
// permanently stuck on the source chain.
//
// These tests verify:
//  1. HandlePendingMessageEviction marks a Pending lock as Failed
//  2. HandlePendingMessageEviction is a no-op for non-existent locks
//  3. HandlePendingMessageEviction does not disturb non-Pending locks
//  4. QuantumBridge.evictOldMessages calls the registered hook
//  5. SetPendingEvictionHook registers the callback
package bridge

import (
	"context"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestBRIDGE_R15_CRIT_002_HandleEviction_MarksPendingLockFailed verifies
// that HandlePendingMessageEviction transitions a Pending lock to Failed.
func TestBRIDGE_R15_CRIT_002_HandleEviction_MarksPendingLockFailed(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	// Insert a lock in Pending status (simulating a just-created lock
	// whose bridge message hasn't been confirmed yet).
	lock := &AssetLock{
		ID:           "lock-evict-1",
		SourceChain:  "source-chain",
		TargetChain:  "target-chain",
		AssetType:    AssetTypeQRC20,
		TokenAddress: types.Address{0x11},
		Amount:       bigNewInt(1000),
		Owner:        types.Address{0xAA},
		Recipient:    types.Address{0xBB},
		Status:       LockStatusPending,
		CreatedAt:    time.Now().Unix(),
	}
	alm.mu.Lock()
	alm.locks[lock.ID] = lock
	alm.locksByOwner[lock.Owner] = append(alm.locksByOwner[lock.Owner], lock.ID)
	if alm.locksByStatus[LockStatusPending] == nil {
		alm.locksByStatus[LockStatusPending] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusPending][lock.ID] = true
	alm.mu.Unlock()

	alm.HandlePendingMessageEviction("lock-evict-1")

	// The lock must now be Failed.
	got, ok := alm.GetLock("lock-evict-1")
	if !ok {
		t.Fatal("lock should still exist after eviction handling")
	}
	if got.Status != LockStatusFailed {
		t.Errorf("expected Failed, got %d", got.Status)
	}
	if got.FailedReason == "" {
		t.Error("expected non-empty FailedReason")
	}
}

// TestBRIDGE_R15_CRIT_002_HandleEviction_NoopForNonExistentLock verifies
// that HandlePendingMessageEviction is a no-op when no lock exists for
// the given message ID (e.g., a manual bridge message without a lock).
func TestBRIDGE_R15_CRIT_002_HandleEviction_NoopForNonExistentLock(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	// Should not panic or create any state.
	alm.HandlePendingMessageEviction("nonexistent-lock-id")

	if _, ok := alm.GetLock("nonexistent-lock-id"); ok {
		t.Error("expected no lock to be created")
	}
}

// TestBRIDGE_R15_CRIT_002_HandleEviction_DoesNotDisturbNonPendingLock
// verifies that HandlePendingMessageEviction leaves locks in non-Pending
// statuses untouched (the timeout watcher handles those).
func TestBRIDGE_R15_CRIT_002_HandleEviction_DoesNotDisturbNonPendingLock(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	// Insert a lock in Locked status (already confirmed).
	lock := &AssetLock{
		ID:        "lock-locked-1",
		Status:    LockStatusLocked,
		CreatedAt: time.Now().Unix(),
		LockedAt:  time.Now().Unix(),
		Owner:     types.Address{0xAA},
		Amount:    bigNewInt(1000),
	}
	alm.mu.Lock()
	alm.locks[lock.ID] = lock
	if alm.locksByStatus[LockStatusLocked] == nil {
		alm.locksByStatus[LockStatusLocked] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusLocked][lock.ID] = true
	alm.mu.Unlock()

	alm.HandlePendingMessageEviction("lock-locked-1")

	got, ok := alm.GetLock("lock-locked-1")
	if !ok {
		t.Fatal("lock should still exist")
	}
	if got.Status != LockStatusLocked {
		t.Errorf("Locked lock should not be disturbed, got status=%d", got.Status)
	}
}

// TestBRIDGE_R15_CRIT_002_SetPendingEvictionHook verifies that
// SetPendingEvictionHook registers a callback that is invoked during
// PENDING message eviction.
func TestBRIDGE_R15_CRIT_002_SetPendingEvictionHook(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	called := make(chan string, 1)
	b.SetPendingEvictionHook(func(id string) {
		called <- id
	})

	// Manually inject a stale PENDING message and trigger eviction.
	b.mu.Lock()
	msg := &BridgeMessage{
		ID:        "msg-stale-1",
		Status:    MessageStatusPending,
		Timestamp: time.Now().Add(-2 * time.Hour).Unix(), // 2h ago — stale
	}
	b.messages[msg.ID] = msg
	if b.messagesByStatus[MessageStatusPending] == nil {
		b.messagesByStatus[MessageStatusPending] = make(map[string]bool)
	}
	b.messagesByStatus[MessageStatusPending][msg.ID] = true
	b.maxMessages = 0 // force eviction
	b.mu.Unlock()

	b.evictOldMessages()

	select {
	case id := <-called:
		if id != "msg-stale-1" {
			t.Errorf("expected hook called with msg-stale-1, got %s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pendingEvictionHook was not called during eviction")
	}

	// Verify the message was actually evicted.
	b.mu.RLock()
	_, exists := b.messages["msg-stale-1"]
	b.mu.RUnlock()
	if exists {
		t.Error("stale PENDING message should have been evicted")
	}
}

// TestBRIDGE_R15_CRIT_002_EvictionWithoutHookDoesNotPanic verifies that
// evictOldMessages is safe when no hook is registered (nil hook).
func TestBRIDGE_R15_CRIT_002_EvictionWithoutHookDoesNotPanic(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	// No SetPendingEvictionHook call — hook is nil.

	b.mu.Lock()
	msg := &BridgeMessage{
		ID:        "msg-stale-2",
		Status:    MessageStatusPending,
		Timestamp: time.Now().Add(-2 * time.Hour).Unix(),
	}
	b.messages[msg.ID] = msg
	if b.messagesByStatus[MessageStatusPending] == nil {
		b.messagesByStatus[MessageStatusPending] = make(map[string]bool)
	}
	b.messagesByStatus[MessageStatusPending][msg.ID] = true
	b.maxMessages = 0
	b.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("evictOldMessages panicked with nil hook: %v", r)
		}
	}()
	b.evictOldMessages()

	b.mu.RLock()
	_, exists := b.messages["msg-stale-2"]
	b.mu.RUnlock()
	if exists {
		t.Error("stale PENDING message should have been evicted even without hook")
	}
}
