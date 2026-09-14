// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"testing"
	"time"
)

// ── DefaultSnapSyncConfig ──

func TestDefaultSnapSyncConfig(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	if cfg.MaxAccountsPerBatch != 1000 {
		t.Errorf("expected MaxAccountsPerBatch 1000, got %d", cfg.MaxAccountsPerBatch)
	}
	if cfg.MaxStoragePerBatch != 5000 {
		t.Errorf("expected MaxStoragePerBatch 5000, got %d", cfg.MaxStoragePerBatch)
	}
	if cfg.RecentBlocksCount != 128 {
		t.Errorf("expected RecentBlocksCount 128, got %d", cfg.RecentBlocksCount)
	}
	if cfg.RequestTimeout != 5*time.Second {
		t.Errorf("expected RequestTimeout 5s, got %v", cfg.RequestTimeout)
	}
	if cfg.MaxConcurrentRequests != 16 {
		t.Errorf("expected MaxConcurrentRequests 16, got %d", cfg.MaxConcurrentRequests)
	}
}

// ── SyncPhase.String() ──

func TestSyncPhase_String(t *testing.T) {
	tests := []struct {
		phase    SyncPhase
		expected string
	}{
		{SyncPhaseIdle, "Idle"},
		{SyncPhaseStateRoot, "StateRoot"},
		{SyncPhaseAccounts, "Accounts"},
		{SyncPhaseStorage, "Storage"},
		{SyncPhaseRecentBlocks, "RecentBlocks"},
		{SyncPhaseVerification, "Verification"},
		{SyncPhaseComplete, "Complete"},
		{SyncPhaseFailed, "Failed"},
		{SyncPhase(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		result := tt.phase.String()
		if result != tt.expected {
			t.Errorf("SyncPhase(%d).String() = %q, want %q", tt.phase, result, tt.expected)
		}
	}
}

// ── NewSnapSyncState ──

func TestNewSnapSyncState(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)
	if state == nil {
		t.Fatal("expected non-nil SnapSyncState")
	}
	if state.phase != SyncPhaseIdle {
		t.Errorf("expected Idle phase, got %s", state.phase.String())
	}
	if state.progress != 0 {
		t.Errorf("expected 0 progress, got %f", state.progress)
	}
}

// ── StartPhase ──

func TestSnapSyncState_StartPhase(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.StartPhase(SyncPhaseAccounts)
	status := state.GetStatus()
	if status.Phase != SyncPhaseAccounts {
		t.Errorf("expected Accounts phase, got %s", status.Phase.String())
	}
}

func TestSnapSyncState_StartPhase_SetsStartTime(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.StartPhase(SyncPhaseStateRoot)
	// After starting StateRoot phase, startTime should be set
	// ElapsedTime should be very small but non-negative
	status := state.GetStatus()
	if status.ElapsedTime < 0 {
		t.Error("expected non-negative elapsed time after starting StateRoot phase")
	}
}

// ── UpdateProgress ──

func TestSnapSyncState_UpdateProgress(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.UpdateProgress(0.5)
	status := state.GetStatus()
	if status.Progress != 0.5 {
		t.Errorf("expected 0.5 progress, got %f", status.Progress)
	}
}

func TestSnapSyncState_UpdateProgress_ClampsNegative(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.UpdateProgress(-0.5)
	status := state.GetStatus()
	if status.Progress != 0 {
		t.Errorf("expected 0 progress for negative input, got %f", status.Progress)
	}
}

func TestSnapSyncState_UpdateProgress_ClampsAboveOne(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.UpdateProgress(1.5)
	status := state.GetStatus()
	if status.Progress != 1.0 {
		t.Errorf("expected 1.0 progress for >1 input, got %f", status.Progress)
	}
}

// ── RecordAccountSync ──

func TestSnapSyncState_RecordAccountSync(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.RecordAccountSync(100, 4096)
	status := state.GetStatus()
	if status.SyncedAccounts != 100 {
		t.Errorf("expected 100 synced accounts, got %d", status.SyncedAccounts)
	}
	if status.TotalBytesSynced != 4096 {
		t.Errorf("expected 4096 bytes, got %d", status.TotalBytesSynced)
	}
}

// ── RecordStorageSync ──

func TestSnapSyncState_RecordStorageSync(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.RecordStorageSync(50, 8192)
	status := state.GetStatus()
	if status.SyncedStorageSlots != 50 {
		t.Errorf("expected 50 synced storage slots, got %d", status.SyncedStorageSlots)
	}
}

// ── RecordBlockSync ──

func TestSnapSyncState_RecordBlockSync(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.RecordBlockSync(10, 2048)
	status := state.GetStatus()
	if status.SyncedRecentBlocks != 10 {
		t.Errorf("expected 10 synced blocks, got %d", status.SyncedRecentBlocks)
	}
}

// ── RecordError ──

func TestSnapSyncState_RecordError(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.RecordError(fmt.Errorf("test error"))
	status := state.GetStatus()
	if status.ErrorCount != 1 {
		t.Errorf("expected 1 error, got %d", status.ErrorCount)
	}
}

func TestSnapSyncState_RecordError_MaxErrors(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	// Record more than 100 errors
	for i := 0; i < 150; i++ {
		state.RecordError(fmt.Errorf("error %d", i))
	}
	status := state.GetStatus()
	if status.ErrorCount != 100 {
		t.Errorf("expected max 100 errors, got %d", status.ErrorCount)
	}
}

// ── MarkFailed ──

func TestSnapSyncState_MarkFailed(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.MarkFailed()
	status := state.GetStatus()
	if status.Phase != SyncPhaseFailed {
		t.Errorf("expected Failed phase, got %s", status.Phase.String())
	}
}

// ── MarkComplete ──

func TestSnapSyncState_MarkComplete(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.MarkComplete()
	status := state.GetStatus()
	if status.Phase != SyncPhaseComplete {
		t.Errorf("expected Complete phase, got %s", status.Phase.String())
	}
	if status.Progress != 1.0 {
		t.Errorf("expected 1.0 progress after complete, got %f", status.Progress)
	}
}

// ── Cancel ──

func TestSnapSyncState_Cancel(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	// Should not panic
	state.Cancel()
}

// ── GetStatus ──

func TestSnapSyncState_GetStatus_Initial(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	status := state.GetStatus()
	if status.Phase != SyncPhaseIdle {
		t.Errorf("expected Idle phase, got %s", status.Phase.String())
	}
	if status.Progress != 0 {
		t.Errorf("expected 0 progress, got %f", status.Progress)
	}
	if status.SyncedAccounts != 0 {
		t.Errorf("expected 0 synced accounts, got %d", status.SyncedAccounts)
	}
	if status.ErrorCount != 0 {
		t.Errorf("expected 0 errors, got %d", status.ErrorCount)
	}
}

// ── SnapSyncManager ──

func TestNewSnapSyncManager_NilSyncer(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	mgr := NewSnapSyncManager(nil, cfg)
	if mgr == nil {
		t.Fatal("expected non-nil SnapSyncManager")
	}
}

func TestSnapSyncManager_StartSnapSync(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	mgr := NewSnapSyncManager(nil, cfg)

	err := mgr.StartSnapSync(1000)
	if err != nil {
		t.Fatalf("StartSnapSync failed: %v", err)
	}

	status := mgr.GetSnapSyncStatus()
	if status.Phase != SyncPhaseComplete {
		t.Errorf("expected Complete phase after StartSnapSync, got %s", status.Phase.String())
	}
}

func TestSnapSyncManager_IsSnapSyncComplete(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	mgr := NewSnapSyncManager(nil, cfg)

	if mgr.IsSnapSyncComplete() {
		t.Error("expected snap sync not complete initially")
	}

	mgr.StartSnapSync(1000)

	if !mgr.IsSnapSyncComplete() {
		t.Error("expected snap sync complete after StartSnapSync")
	}
}

func TestSnapSyncManager_CancelSnapSync(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	mgr := NewSnapSyncManager(nil, cfg)

	// Should not panic
	mgr.CancelSnapSync()
}

// ── SnapSyncStatus fields ──

func TestSnapSyncStatus_TotalBytesSynced(t *testing.T) {
	cfg := DefaultSnapSyncConfig()
	state := NewSnapSyncState(cfg)

	state.RecordAccountSync(10, 1000)
	state.RecordStorageSync(5, 2000)
	state.RecordBlockSync(2, 500)

	status := state.GetStatus()
	if status.TotalBytesSynced != 3500 {
		t.Errorf("expected 3500 total bytes, got %d", status.TotalBytesSynced)
	}
}
